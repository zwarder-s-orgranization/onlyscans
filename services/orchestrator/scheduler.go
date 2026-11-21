package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"strconv"
	"strings"
	"time"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
)

func (s *Server) startScheduler(ctx context.Context) {
	go func() {
		// Check every 15s; each workflow fires at most once per matching minute via lastFired + idempotency key.
		tick := time.NewTicker(15 * time.Second)
		defer tick.Stop()
		lastFired := map[string]string{}
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-tick.C:
				s.tickSchedules(ctx, now, lastFired)
			}
		}
	}()
}

func (s *Server) tickSchedules(ctx context.Context, now time.Time, lastFired map[string]string) {
	s.wfMu.RLock()
	wfs := make([]*secflowv1.Workflow, 0, len(s.workflows))
	for _, wf := range s.workflows {
		wfs = append(wfs, cloneWorkflow(wf))
	}
	s.wfMu.RUnlock()

	for _, wf := range wfs {
		exprStr, loc, enabled, ok := scheduleConfig(wf)
		if !ok || !enabled {
			continue
		}
		localNow := now.In(loc)
		if !cronMatches(exprStr, localNow) {
			continue
		}
		bucket := localNow.UTC().Format("200601021504")
		if lastFired[wf.GetId()] == bucket {
			continue
		}
		lastFired[wf.GetId()] = bucket
		s.fireScheduledWorkflow(ctx, wf.GetId(), bucket)
	}
}

func (s *Server) fireScheduledWorkflow(ctx context.Context, workflowID, bucket string) {
	idemKey := "cron:" + workflowID + ":" + bucket
	if s.pool != nil {
		lockCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		tx, err := s.pool.Begin(lockCtx)
		if err != nil {
			slog.Warn("cron begin advisory lock tx", "workflow_id", workflowID, "bucket", bucket, "err", err)
			return
		}
		defer func() {
			_ = tx.Rollback(lockCtx)
		}()

		lockKey := "secflow:cron:" + workflowID + ":" + bucket
		var acquired bool
		if err := tx.QueryRow(lockCtx, `SELECT pg_try_advisory_xact_lock(hashtext($1))`, lockKey).Scan(&acquired); err != nil {
			slog.Warn("cron advisory lock failed", "workflow_id", workflowID, "bucket", bucket, "err", err)
			return
		}
		if !acquired {
			return
		}
		var alreadyFired bool
		if err := tx.QueryRow(lockCtx, `SELECT EXISTS(SELECT 1 FROM runs WHERE idempotency_key = $1)`, idemKey).Scan(&alreadyFired); err != nil {
			slog.Warn("cron idempotency check failed", "workflow_id", workflowID, "bucket", bucket, "err", err)
			return
		}
		if alreadyFired {
			return
		}
		if _, err := s.StartRun(ctx, &secflowv1.StartRunRequest{
			WorkflowId:     workflowID,
			TriggerType:    secflowv1.TriggerType_TRIGGER_TYPE_SCHEDULE,
			IdempotencyKey: idemKey,
		}); err != nil {
			slog.Warn("scheduled run skipped", "workflow_id", workflowID, "err", err)
			return
		}
		if err := tx.Commit(lockCtx); err != nil {
			slog.Warn("cron commit advisory lock tx", "workflow_id", workflowID, "bucket", bucket, "err", err)
		}
		return
	}

	if _, err := s.StartRun(ctx, &secflowv1.StartRunRequest{
		WorkflowId:     workflowID,
		TriggerType:    secflowv1.TriggerType_TRIGGER_TYPE_SCHEDULE,
		IdempotencyKey: idemKey,
	}); err != nil {
		slog.Warn("scheduled run skipped", "workflow_id", workflowID, "err", err)
	}
}

// applyTriggerMetadata populates ScheduleEnabled, CronExpression, and WebhookEnabled
// on wf from its trigger node definition.
func applyTriggerMetadata(wf *secflowv1.Workflow) {
	if wf == nil {
		return
	}
	wf.ScheduleEnabled = false
	wf.CronExpression = ""
	wf.WebhookEnabled = false
	if wf.GetGraph() == nil {
		return
	}
	for _, n := range wf.GetGraph().GetNodes() {
		switch n.GetPluginId() {
		case "trigger.schedule":
			params := map[string]any{}
			if len(n.GetParamsJson()) > 0 {
				_ = json.Unmarshal(n.GetParamsJson(), &params)
			}
			cronStr, _ := params["cron"].(string)
			cronStr = strings.TrimSpace(cronStr)
			enabled := true
			if b, ok := params["enabled"].(bool); ok {
				enabled = b
			}
			wf.CronExpression = cronStr
			wf.ScheduleEnabled = enabled && cronStr != ""
		case "trigger.webhook":
			wf.WebhookEnabled = true
			if wf.WebhookPath == "" && wf.GetId() != "" {
				wf.WebhookPath = "/webhooks/git/" + wf.GetId()
			}
		}
	}
}

func scheduleConfig(wf *secflowv1.Workflow) (string, *time.Location, bool, bool) {
	if wf == nil || wf.GetGraph() == nil {
		return "", time.UTC, false, false
	}
	for _, n := range wf.GetGraph().GetNodes() {
		if n.GetPluginId() != "trigger.schedule" {
			continue
		}
		params := map[string]any{}
		if len(n.GetParamsJson()) > 0 {
			_ = json.Unmarshal(n.GetParamsJson(), &params)
		}
		exprStr, _ := params["cron"].(string)
		exprStr = strings.TrimSpace(exprStr)
		if exprStr == "" {
			return "", time.UTC, false, false
		}
		enabled := true
		if b, ok := params["enabled"].(bool); ok {
			enabled = b
		}
		loc := time.UTC
		if tz, ok := params["timezone"].(string); ok && strings.TrimSpace(tz) != "" {
			if loaded, err := time.LoadLocation(strings.TrimSpace(tz)); err == nil {
				loc = loaded
			}
		}
		return exprStr, loc, enabled, true
	}
	return "", time.UTC, false, false
}

// cronMatches evaluates a standard 5-field cron expression:
// minute (0-59) hour (0-23) day-of-month (1-31) month (1-12) day-of-week (0-6, 7=Sunday).
func cronMatches(exprStr string, t time.Time) bool {
	fields := strings.Fields(exprStr)
	if len(fields) != 5 {
		return false
	}
	return cronFieldMatches(fields[0], t.Minute(), 0, 59, false) &&
		cronFieldMatches(fields[1], t.Hour(), 0, 23, false) &&
		cronFieldMatches(fields[2], t.Day(), 1, 31, false) &&
		cronFieldMatches(fields[3], int(t.Month()), 1, 12, false) &&
		cronFieldMatches(fields[4], int(t.Weekday()), 0, 6, true)
}

func cronFieldMatches(spec string, value, minVal, maxVal int, allowSevenAsZero bool) bool {
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		step := 1
		rangeSpec := part
		if idx := strings.IndexByte(part, '/'); idx >= 0 {
			rangeSpec = part[:idx]
			s, err := strconv.Atoi(part[idx+1:])
			if err != nil || s <= 0 {
				return false
			}
			step = s
		}
		if rangeSpec == "*" {
			if (value-minVal)%step == 0 {
				return true
			}
			continue
		}
		start, end := 0, 0
		if idx := strings.IndexByte(rangeSpec, '-'); idx >= 0 {
			a, err1 := strconv.Atoi(rangeSpec[:idx])
			b, err2 := strconv.Atoi(rangeSpec[idx+1:])
			if err1 != nil || err2 != nil {
				return false
			}
			start, end = a, b
		} else {
			a, err := strconv.Atoi(rangeSpec)
			if err != nil {
				return false
			}
			start, end = a, a
			if strings.Contains(part, "/") {
				end = maxVal
			}
		}
		if allowSevenAsZero {
			if start == 7 {
				start = 0
			}
			if end == 7 {
				end = 0
			}
		}
		if start < minVal || end > maxVal || start > end {
			return false
		}
		if value >= start && value <= end && (value-start)%step == 0 {
			return true
		}
	}
	return false
}
