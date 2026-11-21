package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/auth"
	"github.com/secflow/secflow/services/internal/blobstore"
	"github.com/secflow/secflow/services/internal/obs"
	"github.com/secflow/secflow/services/internal/urlguard"
)

const (
	maxInspectorChannels             = 50
	maxInspectorDeliveriesPerChannel = 100
	defaultInspectorTTL              = time.Hour
)

type inspectorEntry struct {
	item     map[string]any
	storedAt time.Time
}

func (g *gateway) inspectorTTL() time.Duration {
	if g.inspTTL > 0 {
		return g.inspTTL
	}
	return defaultInspectorTTL
}

// evictInspectorLocked removes expired entries and enforces channel & per-channel bounds.
// Caller must hold g.mu.
func (g *gateway) evictInspectorLocked(now time.Time) {
	ttl := g.inspectorTTL()
	for ch, entries := range g.insp {
		kept := entries[:0]
		for _, e := range entries {
			if now.Sub(e.storedAt) <= ttl {
				kept = append(kept, e)
			}
		}
		if len(kept) == 0 {
			delete(g.insp, ch)
			delete(g.inspUpdated, ch)
		} else {
			g.insp[ch] = kept
		}
	}
	for len(g.insp) > maxInspectorChannels {
		var oldestKey string
		var oldestTime time.Time
		first := true
		for ch := range g.insp {
			t := g.inspUpdated[ch]
			if first || t.Before(oldestTime) {
				oldestKey = ch
				oldestTime = t
				first = false
			}
		}
		if oldestKey == "" {
			break
		}
		delete(g.insp, oldestKey)
		delete(g.inspUpdated, oldestKey)
	}
}

func (g *gateway) recordInspectorDelivery(key string, item map[string]any) {
	now := time.Now().UTC()
	g.mu.Lock()
	if g.insp == nil {
		g.insp = map[string][]inspectorEntry{}
	}
	if g.inspUpdated == nil {
		g.inspUpdated = map[string]time.Time{}
	}
	g.evictInspectorLocked(now)
	entries := append(g.insp[key], inspectorEntry{item: item, storedAt: now})
	if len(entries) > maxInspectorDeliveriesPerChannel {
		entries = entries[len(entries)-maxInspectorDeliveriesPerChannel:]
	}
	g.insp[key] = entries
	g.inspUpdated[key] = now
	g.evictInspectorLocked(now)
	waiters := append([]chan map[string]any(nil), g.subs[key]...)
	g.mu.Unlock()

	for _, ch := range waiters {
		select {
		case ch <- item:
		default:
		}
	}
}

func (g *gateway) listInspectorDeliveries(key string, limit int) []any {
	if limit <= 0 {
		limit = 25
	}
	now := time.Now().UTC()
	g.mu.Lock()
	if g.insp != nil {
		g.evictInspectorLocked(now)
	}
	entries := append([]inspectorEntry(nil), g.insp[key]...)
	g.mu.Unlock()

	if len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}
	out := make([]any, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.item)
	}
	return out
}

func (g *gateway) subscribeInspector(key string) ([]map[string]any, <-chan map[string]any, func()) {
	now := time.Now().UTC()
	ch := make(chan map[string]any, 64)

	g.mu.Lock()
	if g.insp == nil {
		g.insp = map[string][]inspectorEntry{}
	}
	if g.subs == nil {
		g.subs = map[string][]chan map[string]any{}
	}
	g.evictInspectorLocked(now)
	initial := make([]map[string]any, 0, len(g.insp[key]))
	for _, e := range g.insp[key] {
		initial = append(initial, e.item)
	}
	g.subs[key] = append(g.subs[key], ch)
	g.mu.Unlock()

	var once sync.Once
	unsubscribe := func() {
		once.Do(func() {
			g.mu.Lock()
			list := g.subs[key]
			for i, candidate := range list {
				if candidate == ch {
					list = append(list[:i], list[i+1:]...)
					break
				}
			}
			if len(list) == 0 {
				delete(g.subs, key)
			} else {
				g.subs[key] = list
			}
			g.mu.Unlock()
		})
	}
	return initial, ch, unsubscribe
}

func (g *gateway) healthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeProblem(w, r, http.StatusMethodNotAllowed, "VALIDATION_FAILED", "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (g *gateway) readyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeProblem(w, r, http.StatusMethodNotAllowed, "VALIDATION_FAILED", "method not allowed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	checks := map[string]any{
		"postgres":            "skipped",
		"orchestratorGrpc":    "error",
		"garage":              "skipped",
		"activeWorkerStreams": 0,
	}
	ready := true

	if g.pgPing != nil {
		if err := g.pgPing(ctx); err != nil {
			slog.Warn("readyz postgres check failed", "err", err)
			checks["postgres"] = "error"
			ready = false
		} else {
			checks["postgres"] = "ok"
		}
	} else if g.pool != nil {
		if err := g.pool.Ping(ctx); err != nil {
			slog.Warn("readyz postgres ping failed", "err", err)
			checks["postgres"] = "error"
			ready = false
		} else {
			checks["postgres"] = "ok"
		}
	}

	if g.plugs != nil {
		resp, err := g.plugs.ListPlugins(ctx, &secflowv1.ListPluginsRequest{})
		if err != nil {
			slog.Warn("readyz orchestrator probe failed", "err", err)
			checks["orchestratorGrpc"] = "error"
			ready = false
		} else {
			checks["orchestratorGrpc"] = "ok"
			workers := 0
			for _, p := range resp.GetPlugins() {
				workers += int(p.GetActiveWorkers())
			}
			checks["activeWorkerStreams"] = workers
		}
	} else {
		checks["orchestratorGrpc"] = "unconfigured"
		ready = false
	}

	if g.garageCheck != nil {
		if err := g.garageCheck(ctx); err != nil {
			slog.Warn("readyz garage check failed", "err", err)
			checks["garage"] = "error"
			ready = false
		} else {
			checks["garage"] = "ok"
		}
	} else if blobstore.Configured() {
		if err := blobstore.Ensure(ctx); err != nil {
			slog.Warn("readyz garage ensure failed", "err", err)
			checks["garage"] = "error"
			ready = false
		} else {
			checks["garage"] = "ok"
		}
	}

	if ready {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "checks": checks})
		return
	}
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready", "checks": checks})
}

func (g *gateway) requireRank(w http.ResponseWriter, r *http.Request, rank int) (*auth.Claims, bool) {
	claims, err := g.bearer(r)
	if err != nil || claims == nil {
		writeProblem(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "authentication required")
		return nil, false
	}
	if roleRank(claims.Role) < rank {
		writeProblem(w, r, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
		return nil, false
	}
	return claims, true
}

func (g *gateway) upload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "VALIDATION_FAILED", "method not allowed")
		return
	}
	claims, ok := g.requireRank(w, r, 2)
	if !ok {
		return
	}
	raw, filename, fields, err := readUploadForm(r, 52<<20)
	if err != nil || len(raw) == 0 {
		writeProblem(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "invalid or empty upload payload")
		return
	}
	if filename == "" {
		filename = "upload.zip"
	}
	repoName := first(strings.TrimSpace(fields["repoName"]), filename)
	if g.ingest == nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "INTERNAL", "source ingester unavailable")
		return
	}
	ctx := withTraceparent(r.Context(), r)
	resp, err := g.ingest.IngestUpload(ctx, &secflowv1.IngestUploadRequest{
		Actor:      g.actorOf(claims),
		Filename:   filename,
		RepoName:   repoName,
		ArchiveZip: raw,
	})
	if err != nil {
		writeProblemFromGRPC(w, r, err)
		return
	}
	ref := resp.GetSourceRef()
	writeJSON(w, http.StatusCreated, map[string]any{
		"sourceId":        ref.GetSourceId(),
		"bucket":          first(ref.GetBucket(), "secflow-sources"),
		"key":             ref.GetKey(),
		"sha256":          ref.GetSha256(),
		"repoName":        first(ref.GetRepoName(), repoName),
		"sizeBytes":       ref.GetSizeBytes(),
		"fileCount":       ref.GetFileCount(),
		"deduplicatedHit": resp.GetDeduplicatedHit(),
		"ingestedAt":      stamp(resp.GetIngestedAt()),
	})
}

func (g *gateway) catalogUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "VALIDATION_FAILED", "method not allowed")
		return
	}
	claims, ok := g.requireRank(w, r, 2)
	if !ok {
		return
	}
	raw, _, fields, err := readUploadForm(r, 20<<20)
	if err != nil || len(raw) == 0 {
		writeProblem(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "invalid or empty catalog payload")
		return
	}
	advisoryCount, docSnapshotDate, schemaErr := validateCatalogJSON(raw, fields["snapshotDate"])
	if schemaErr != nil {
		writeProblem(w, r, http.StatusUnprocessableEntity, "VALIDATION_FAILED", schemaErr.Error())
		return
	}
	name := first(strings.TrimSpace(fields["name"]), "uploaded")
	snapshotDate := first(strings.TrimSpace(fields["snapshotDate"]), docSnapshotDate)
	if snapshotDate == "" {
		snapshotDate = time.Now().UTC().Format("2006-01-02")
	}
	setAsDefault := parseBoolForm(fields["setAsDefault"])

	sum := sha256.Sum256(raw)
	shaHex := hex.EncodeToString(sum[:])
	key := shaHex + ".json"
	ctx := withTraceparent(r.Context(), r)
	if blobstore.Configured() {
		if err := blobstore.Put(ctx, "secflow-catalogs", key, raw); err != nil {
			slog.Error("garage catalog put failed", "key", key, "err", err)
			writeProblem(w, r, http.StatusServiceUnavailable, "INTERNAL", "catalog storage unavailable")
			return
		}
	}
	if g.cats == nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "INTERNAL", "catalog service unavailable")
		return
	}
	resp, err := g.cats.RegisterCatalog(ctx, &secflowv1.RegisterCatalogRequest{
		Actor:         g.actorOf(claims),
		Name:          name,
		Bucket:        "secflow-catalogs",
		S3Key:         key,
		Sha256:        shaHex,
		SnapshotDate:  snapshotDate,
		AdvisoryCount: int32(advisoryCount),
		SetAsDefault:  setAsDefault,
	})
	if err != nil {
		writeProblemFromGRPC(w, r, err)
		return
	}
	out := catalogMap(resp.GetCatalog())
	if strings.TrimSpace(asString(out["snapshotDate"])) == "" {
		out["snapshotDate"] = snapshotDate
	}
	writeJSON(w, http.StatusCreated, out)
}

var (
	catalogDateRe   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	catalogSHA256Re = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

func validCatalogSeverity(s string) bool {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "LOW", "MEDIUM", "HIGH", "CRITICAL":
		return true
	default:
		return false
	}
}

func validateCatalogJSON(raw []byte, formSnapshotDate string) (int, string, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil || len(top) == 0 {
		return 0, "", errors.New("catalog must be a non-empty JSON object")
	}

	_, hasAdvisories := top["advisories"]
	_, hasSchemaVer := top["schemaVersion"]
	_, hasSnapDate := top["snapshotDate"]
	if hasAdvisories || hasSchemaVer || hasSnapDate {
		var doc struct {
			SchemaVersion any    `json:"schemaVersion"`
			SnapshotDate  string `json:"snapshotDate"`
			Advisories    []struct {
				ID             string            `json:"id"`
				Group          string            `json:"group"`
				Artifact       string            `json:"artifact"`
				Severity       string            `json:"severity"`
				AffectedRanges []json.RawMessage `json:"affectedRanges"`
			} `json:"advisories"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			return 0, "", errors.New("catalog failed advisories schema validation")
		}
		switch v := doc.SchemaVersion.(type) {
		case string:
			if strings.TrimSpace(v) == "" {
				return 0, "", errors.New("catalog missing required field schemaVersion")
			}
		case float64:
			if v <= 0 {
				return 0, "", errors.New("catalog invalid schemaVersion")
			}
		default:
			return 0, "", errors.New("catalog missing required field schemaVersion")
		}
		snap := strings.TrimSpace(doc.SnapshotDate)
		if snap == "" {
			return 0, "", errors.New("catalog missing required field snapshotDate")
		}
		if len(doc.Advisories) == 0 {
			return 0, "", errors.New("catalog advisories array must be non-empty")
		}
		for i, adv := range doc.Advisories {
			if strings.TrimSpace(adv.ID) == "" || strings.TrimSpace(adv.Group) == "" || strings.TrimSpace(adv.Artifact) == "" {
				return 0, "", fmt.Errorf("catalog advisory[%d] missing id, group, or artifact", i)
			}
			if !validCatalogSeverity(adv.Severity) {
				return 0, "", fmt.Errorf("catalog advisory[%d] has invalid severity", i)
			}
			if len(adv.AffectedRanges) == 0 {
				return 0, "", fmt.Errorf("catalog advisory[%d] missing affectedRanges", i)
			}
		}
		return len(doc.Advisories), snap, nil
	}

	if _, hasVulns := top["vulnerabilities"]; !hasVulns {
		return 0, "", errors.New("catalog failed schema validation: missing vulnerabilities or advisories")
	}

	_, hasFmt := top["formatVersion"]
	_, hasEco := top["ecosystem"]
	_, hasVerFmt := top["versionFormat"]
	_, hasSnap := top["snapshot"]
	strictMentor := hasFmt || hasEco || hasVerFmt || hasSnap

	var mentor struct {
		FormatVersion int    `json:"formatVersion"`
		Ecosystem     string `json:"ecosystem"`
		VersionFormat string `json:"versionFormat"`
		Snapshot      struct {
			Date       string `json:"date"`
			URL        string `json:"url"`
			SHA256     string `json:"sha256"`
			Advisories string `json:"advisories"`
		} `json:"snapshot"`
		Vulnerabilities []struct {
			ID       string `json:"id"`
			Group    string `json:"group"`
			Artifact string `json:"artifact"`
			Severity string `json:"severity"`
			Ranges   []struct {
				Upper string `json:"upper"`
			} `json:"ranges"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &mentor); err != nil || len(mentor.Vulnerabilities) == 0 {
		return 0, "", errors.New("catalog vulnerabilities array must be non-empty")
	}
	if strictMentor {
		if mentor.FormatVersion != 1 || mentor.Ecosystem != "Maven" || mentor.VersionFormat != "numeric-dot-separated" {
			return 0, "", errors.New("catalog header does not match Maven vulnerability schema")
		}
		if !catalogDateRe.MatchString(strings.TrimSpace(mentor.Snapshot.Date)) ||
			strings.TrimSpace(mentor.Snapshot.URL) == "" ||
			!catalogSHA256Re.MatchString(strings.TrimSpace(mentor.Snapshot.SHA256)) ||
			strings.TrimSpace(mentor.Snapshot.Advisories) == "" {
			return 0, "", errors.New("catalog snapshot metadata failed schema validation")
		}
		for i, v := range mentor.Vulnerabilities {
			if strings.TrimSpace(v.ID) == "" || strings.TrimSpace(v.Group) == "" || strings.TrimSpace(v.Artifact) == "" {
				return 0, "", fmt.Errorf("catalog vulnerability[%d] missing id, group, or artifact", i)
			}
			if !validCatalogSeverity(v.Severity) {
				return 0, "", fmt.Errorf("catalog vulnerability[%d] has invalid severity", i)
			}
			if len(v.Ranges) == 0 {
				return 0, "", fmt.Errorf("catalog vulnerability[%d] missing ranges", i)
			}
			for j, rng := range v.Ranges {
				if strings.TrimSpace(rng.Upper) == "" {
					return 0, "", fmt.Errorf("catalog vulnerability[%d].ranges[%d] missing upper bound", i, j)
				}
			}
		}
		return len(mentor.Vulnerabilities), strings.TrimSpace(mentor.Snapshot.Date), nil
	}

	// Minimal vulnerabilities payload requires snapshotDate form field and valid advisory IDs.
	snap := strings.TrimSpace(formSnapshotDate)
	if snap == "" {
		return 0, "", errors.New("catalog missing required schema headers or snapshotDate")
	}
	for i, v := range mentor.Vulnerabilities {
		if strings.TrimSpace(v.ID) == "" {
			return 0, "", fmt.Errorf("catalog vulnerability[%d] missing id", i)
		}
		if v.Severity != "" && !validCatalogSeverity(v.Severity) {
			return 0, "", fmt.Errorf("catalog vulnerability[%d] has invalid severity", i)
		}
		if v.Group != "" || v.Artifact != "" || len(v.Ranges) > 0 {
			if strings.TrimSpace(v.Group) == "" || strings.TrimSpace(v.Artifact) == "" || !validCatalogSeverity(v.Severity) || len(v.Ranges) == 0 {
				return 0, "", fmt.Errorf("catalog vulnerability[%d] incomplete schema fields", i)
			}
		}
	}
	return len(mentor.Vulnerabilities), snap, nil
}

func readUploadForm(r *http.Request, limit int64) ([]byte, string, map[string]string, error) {
	fields := map[string]string{}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err == nil && strings.HasPrefix(media, "multipart/") {
		if err := r.ParseMultipartForm(limit); err != nil {
			return nil, "", fields, err
		}
		if r.MultipartForm != nil {
			for k, vals := range r.MultipartForm.Value {
				if len(vals) > 0 {
					fields[k] = vals[0]
				}
			}
		}
		file, hdr, err := r.FormFile("file")
		if err != nil {
			return nil, "", fields, err
		}
		defer file.Close()
		raw, err := io.ReadAll(io.LimitReader(file, limit))
		name := ""
		if hdr != nil {
			name = hdr.Filename
		}
		return raw, name, fields, err
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, limit))
	return raw, "", fields, err
}

func parseBoolForm(raw string) bool {
	v := strings.ToLower(strings.TrimSpace(raw))
	return v == "true" || v == "1" || v == "yes"
}

type webhookMeta struct {
	EventType       string
	RepoURL         string
	Branch          string
	CommitSHA       string
	PRNumber        *int32
	DeliveryID      string
	CommitStatusURL string
	Sender          string
}

func (g *gateway) checkWebhookRepoAllowlist(ctx context.Context, repoURL string) (bool, string) {
	if g.ingest != nil {
		checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		resp, err := g.ingest.CheckRepoAllowlist(checkCtx, &secflowv1.CheckRepoAllowlistRequest{RepoUrl: repoURL})
		if err == nil {
			return resp.GetAllowed(), resp.GetReason()
		}
		slog.Warn("webhook CheckRepoAllowlist failed, falling back to local urlguard", "err", err)
	}
	ok, _, reason := urlguard.RepoAllowed(repoURL, os.Getenv("REPO_ALLOWLIST"))
	return ok, reason
}

func (g *gateway) webhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "VALIDATION_FAILED", "method not allowed")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeProblem(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "invalid request body")
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/webhooks/git/"), "/")
	if id == "" || strings.Contains(id, "/") {
		writeProblem(w, r, http.StatusNotFound, "NOT_FOUND", "workflow not found")
		return
	}
	ctx := withTraceparent(r.Context(), r)
	wf, err := g.wf.GetWorkflow(ctx, &secflowv1.GetWorkflowRequest{WorkflowId: id})
	if err != nil {
		writeProblemFromGRPC(w, r, err)
		return
	}
	var secretRef, nodeID, branchFilter string
	var allowedEvents []string
	gitProvider := secflowv1.GitProvider_GIT_PROVIDER_GITHUB
	for _, n := range wf.GetWorkflow().GetGraph().GetNodes() {
		if n.GetPluginId() != "trigger.webhook" {
			continue
		}
		nodeID = n.GetId()
		params := map[string]any{}
		if len(n.GetParamsJson()) > 0 {
			_ = json.Unmarshal(n.GetParamsJson(), &params)
		}
		if strings.EqualFold(asString(params["gitProvider"]), "GITLAB") {
			gitProvider = secflowv1.GitProvider_GIT_PROVIDER_GITLAB
		}
		allowedEvents = asStringSlice(params["events"])
		branchFilter = strings.TrimSpace(asString(params["branchFilter"]))
		for _, b := range n.GetSecretBindings() {
			if b.GetParamKey() == "webhookSecret" {
				secretRef = b.GetSecretRef()
			}
		}
		break
	}
	if secretRef == "" {
		writeProblem(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "webhook secret is not bound")
		return
	}
	resolved, err := g.secs.ResolveScopedSecret(ctx, &secflowv1.ResolveScopedSecretRequest{
		SecretRef:    secretRef,
		ServiceToken: g.serviceToken,
		Scope: &secflowv1.ResolveScopedSecretRequest_WorkflowWebhook{
			WorkflowWebhook: &secflowv1.WorkflowWebhookSecretScope{WorkflowId: id, TriggerNodeId: nodeID},
		},
	})
	if err != nil || !hmacOK(body, resolved.GetPlaintextValue(), r, gitProvider) {
		writeProblem(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "invalid webhook signature")
		return
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("X-GitHub-Event")), "ping") {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}

	meta := extractWebhookMeta(body, r, gitProvider)
	if meta.RepoURL != "" {
		if ok, reason := g.checkWebhookRepoAllowlist(ctx, meta.RepoURL); !ok {
			writeProblem(w, r, http.StatusForbidden, "ALLOWLIST_DENIED", first(reason, "repository URL is not allowlisted"))
			return
		}
	}
	if len(allowedEvents) > 0 && meta.EventType != "" && !eventMatches(allowedEvents, meta.EventType) {
		writeJSON(w, http.StatusOK, map[string]any{"ignored": true, "reason": "event not subscribed"})
		return
	}
	if branchFilter != "" && (meta.Branch == "" || !matchBranch(branchFilter, meta.Branch)) {
		writeJSON(w, http.StatusOK, map[string]any{"ignored": true, "reason": "branch filtered"})
		return
	}

	trig := &secflowv1.TriggerMetadata{
		Type:            secflowv1.TriggerType_TRIGGER_TYPE_WEBHOOK,
		RepoUrl:         meta.RepoURL,
		Branch:          meta.Branch,
		CommitSha:       meta.CommitSHA,
		PrNumber:        meta.PRNumber,
		GitProvider:     gitProvider,
		DeliveryId:      meta.DeliveryID,
		TriggeredBy:     meta.Sender,
		CommitStatusUrl: meta.CommitStatusURL,
		TriggeredAt:     timestamppb.Now(),
	}
	resp, err := g.runs.StartRunFromWebhook(ctx, &secflowv1.StartRunFromWebhookRequest{
		WorkflowId:     id,
		Trigger:        trig,
		IdempotencyKey: meta.DeliveryID,
	})
	if err != nil {
		writeProblemFromGRPC(w, r, err)
		return
	}
	run := resp.GetRun()
	writeJSON(w, http.StatusAccepted, map[string]any{
		"runId":      run.GetId(),
		"workflowId": id,
		"status":     first(trimEnum(run.GetStatus().String(), "RUN_STATUS_"), "QUEUED"),
		"deliveryId": meta.DeliveryID,
		"traceId":    first(run.GetTraceId(), traceIDFromRequest(r)),
	})
}

func extractWebhookMeta(body []byte, r *http.Request, provider secflowv1.GitProvider) webhookMeta {
	var payload map[string]any
	_ = json.Unmarshal(body, &payload)
	if payload == nil {
		payload = map[string]any{}
	}

	var meta webhookMeta
	if provider == secflowv1.GitProvider_GIT_PROVIDER_GITLAB {
		meta.EventType = normalizeGitLabEvent(first(strings.TrimSpace(r.Header.Get("X-Gitlab-Event")), asString(payload["object_kind"])))
		meta.DeliveryID = first(
			strings.TrimSpace(r.Header.Get("X-Gitlab-Event-UUID")),
			first(strings.TrimSpace(r.Header.Get("X-Gitlab-Delivery")), strings.TrimSpace(r.Header.Get("X-GitHub-Delivery"))),
		)
		meta.CommitSHA = first(asString(payload["checkout_sha"]), asString(payload["after"]))
		meta.Branch = stripGitRefPrefix(asString(payload["ref"]))
		meta.Sender = first(asString(payload["user_username"]), asString(payload["user_name"]))
		if user, ok := payload["user"].(map[string]any); ok && meta.Sender == "" {
			meta.Sender = first(asString(user["username"]), asString(user["name"]))
		}
		if oa, ok := payload["object_attributes"].(map[string]any); ok {
			if meta.CommitSHA == "" {
				if lc, ok := oa["last_commit"].(map[string]any); ok {
					meta.CommitSHA = asString(lc["id"])
				}
			}
			if meta.Branch == "" {
				meta.Branch = first(asString(oa["source_branch"]), asString(oa["target_branch"]))
			}
			if iid := asInt(oa["iid"], 0); iid > 0 {
				v := int32(iid)
				meta.PRNumber = &v
			}
		}
		if proj, ok := payload["project"].(map[string]any); ok {
			meta.RepoURL = first(
				asString(proj["git_http_url"]),
				first(asString(proj["web_url"]), asString(proj["http_url"])),
			)
			if pid := asInt64(proj["id"], 0); pid > 0 && meta.CommitSHA != "" {
				base := "https://gitlab.com"
				if webURL := asString(proj["web_url"]); webURL != "" {
					if u, err := url.Parse(webURL); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" {
						base = u.Scheme + "://" + u.Host
					}
				}
				meta.CommitStatusURL = fmt.Sprintf("%s/api/v4/projects/%d/statuses/%s", base, pid, meta.CommitSHA)
			}
		}
		return meta
	}

	// GitHub
	meta.EventType = strings.ToLower(strings.TrimSpace(r.Header.Get("X-GitHub-Event")))
	meta.DeliveryID = strings.TrimSpace(r.Header.Get("X-GitHub-Delivery"))
	meta.CommitSHA = asString(payload["after"])
	meta.Branch = stripGitRefPrefix(asString(payload["ref"]))
	if sender, ok := payload["sender"].(map[string]any); ok {
		meta.Sender = asString(sender["login"])
	}
	if meta.Sender == "" {
		if pusher, ok := payload["pusher"].(map[string]any); ok {
			meta.Sender = asString(pusher["name"])
		}
	}
	if pr, ok := payload["pull_request"].(map[string]any); ok {
		if head, ok := pr["head"].(map[string]any); ok {
			if meta.CommitSHA == "" {
				meta.CommitSHA = asString(head["sha"])
			}
			if meta.Branch == "" {
				meta.Branch = asString(head["ref"])
			}
		}
		if baseObj, ok := pr["base"].(map[string]any); ok && meta.Branch == "" {
			meta.Branch = asString(baseObj["ref"])
		}
		if num := asInt(pr["number"], 0); num > 0 {
			v := int32(num)
			meta.PRNumber = &v
		}
	}
	if meta.PRNumber == nil {
		if num := asInt(payload["number"], 0); num > 0 {
			v := int32(num)
			meta.PRNumber = &v
		}
	}
	if repo, ok := payload["repository"].(map[string]any); ok {
		meta.RepoURL = first(asString(repo["html_url"]), asString(repo["clone_url"]))
		fullName := asString(repo["full_name"])
		if meta.RepoURL == "" && fullName != "" {
			meta.RepoURL = "https://github.com/" + fullName
		}
		if statusesURL := strings.TrimSpace(asString(repo["statuses_url"])); statusesURL != "" && meta.CommitSHA != "" {
			meta.CommitStatusURL = strings.ReplaceAll(statusesURL, "{sha}", meta.CommitSHA)
		} else if fullName != "" && meta.CommitSHA != "" {
			meta.CommitStatusURL = fmt.Sprintf("https://api.github.com/repos/%s/statuses/%s", fullName, meta.CommitSHA)
		}
	}
	return meta
}

func normalizeGitLabEvent(raw string) string {
	low := strings.ToLower(strings.TrimSpace(raw))
	switch low {
	case "push hook", "push":
		return "push"
	case "merge request hook", "merge_request":
		return "merge_request"
	case "tag push hook", "tag_push":
		return "tag_push"
	default:
		return low
	}
}

func stripGitRefPrefix(ref string) string {
	ref = strings.TrimSpace(ref)
	ref = strings.TrimPrefix(ref, "refs/heads/")
	ref = strings.TrimPrefix(ref, "refs/tags/")
	return ref
}

func eventMatches(allowed []string, got string) bool {
	for _, ev := range allowed {
		if strings.EqualFold(strings.TrimSpace(ev), strings.TrimSpace(got)) {
			return true
		}
	}
	return false
}

func matchBranch(pattern, branch string) bool {
	pattern = strings.TrimSpace(pattern)
	branch = strings.TrimSpace(branch)
	if pattern == "" || pattern == "*" {
		return true
	}
	if branch == "" {
		return false
	}
	for _, part := range strings.Split(pattern, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		if p == "*" || p == branch {
			return true
		}
		if strings.HasSuffix(p, "/**") {
			prefix := strings.TrimSuffix(p, "/**")
			if prefix != "" && (branch == prefix || strings.HasPrefix(branch, prefix+"/")) {
				return true
			}
		}
		if strings.HasSuffix(p, "/*") {
			prefix := strings.TrimSuffix(p, "*")
			if strings.HasPrefix(branch, prefix) {
				return true
			}
		}
		if matched, err := path.Match(p, branch); err == nil && matched {
			return true
		}
	}
	return false
}

func hmacOK(body []byte, secret string, r *http.Request, provider secflowv1.GitProvider) bool {
	if secret == "" {
		return false
	}
	if provider == secflowv1.GitProvider_GIT_PROVIDER_GITLAB {
		token := r.Header.Get("X-Gitlab-Token")
		return token != "" && hmac.Equal([]byte(token), []byte(secret))
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	got := r.Header.Get("X-Hub-Signature-256")
	return got != "" && hmac.Equal([]byte(got), []byte(want))
}

func isValidChannelKey(key string) bool {
	if len(key) < 4 || len(key) > 64 {
		return false
	}
	for _, r := range key {
		isAlphaNum := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !isAlphaNum && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

func randomHexID(nBytes int) string {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return sha(time.Now().UTC().String())[:nBytes*2]
	}
	return hex.EncodeToString(buf)
}

func (g *gateway) inspector(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "VALIDATION_FAILED", "method not allowed")
		return
	}
	key := strings.Trim(strings.TrimPrefix(r.URL.Path, "/webhooks/inspector/"), "/")
	if !isValidChannelKey(key) {
		writeProblem(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "invalid channelKey")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeProblem(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "invalid request body")
		return
	}
	var parsed any
	if json.Unmarshal(body, &parsed) != nil {
		parsed = string(body)
	}
	headers := map[string]any{}
	for k, v := range r.Header {
		if strings.EqualFold(k, "X-SecFlow-Test-Secret") {
			continue
		}
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}
	hmacSecret := os.Getenv("INSPECTOR_HMAC_SECRET")
	if hmacSecret == "" {
		hmacSecret = r.Header.Get("X-SecFlow-Test-Secret")
	}
	hmacValid := verifyInspectorHMAC(body, hmacSecret, r.Header.Get("X-SecFlow-Signature-256"))
	deliveryID := randomHexID(8)
	receivedAt := timeNow()
	item := map[string]any{
		"id":         deliveryID,
		"channelKey": key,
		"method":     r.Method,
		"headers":    headers,
		"body":       parsed,
		"hmacValid":  hmacValid,
		"receivedAt": receivedAt,
	}
	g.recordInspectorDelivery(key, item)
	writeJSON(w, http.StatusOK, map[string]any{
		"deliveryId": deliveryID,
		"receivedAt": receivedAt,
	})
}

func verifyInspectorHMAC(body []byte, secret, signature string) bool {
	sig := strings.TrimSpace(signature)
	if sig == "" || secret == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(sig), []byte(want))
}

func sanitizeFilenameSegment(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "run"
	}
	return b.String()
}

func contentSHA256Hex(raw []byte, preferred string) string {
	if len(preferred) == 64 {
		if _, err := hex.DecodeString(preferred); err == nil {
			return strings.ToLower(preferred)
		}
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (g *gateway) runFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeProblem(w, r, http.StatusMethodNotAllowed, "VALIDATION_FAILED", "method not allowed")
		return
	}
	claims, err := g.bearer(r)
	if err != nil || claims == nil {
		writeProblem(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "authentication required")
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 {
		writeProblem(w, r, http.StatusNotFound, "NOT_FOUND", "run not found")
		return
	}
	runID, name := parts[1], parts[2]
	var permField string
	switch name {
	case "submission.json":
		permField = "submission"
	case "sbom.cdx.json":
		permField = "sbom"
	case "report.md", "report.html":
		permField = "readableReport"
	default:
		writeProblem(w, r, http.StatusNotFound, "NOT_FOUND", "artifact not found")
		return
	}
	if !allowed(permField, claims) {
		writeProblem(w, r, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
		return
	}
	ctx := withTraceparent(r.Context(), r)
	actor := g.actorOf(claims)
	if _, err := g.checkScopedRun(ctx, claims, actor, runID); err != nil {
		writeProblemFromGRPC(w, r, err)
		return
	}

	safeID := sanitizeFilenameSegment(runID)
	switch name {
	case "submission.json":
		resp, err := g.runs.GetSubmissionReport(ctx, &secflowv1.GetSubmissionReportRequest{Actor: actor, RunId: runID})
		if err != nil {
			writeProblemFromGRPC(w, r, err)
			return
		}
		payload := resp.GetSubmissionJson()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="submission-%s.json"`, safeID))
		w.Header().Set("X-SecFlow-Sha256", contentSHA256Hex(payload, resp.GetSha256()))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	case "sbom.cdx.json":
		resp, err := g.runs.GetSbom(ctx, &secflowv1.GetSbomRequest{Actor: actor, RunId: runID, IncludeContent: true})
		if err != nil {
			writeProblemFromGRPC(w, r, err)
			return
		}
		payload := resp.GetCyclonedxJson()
		w.Header().Set("Content-Type", "application/vnd.cyclonedx+json; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="sbom-%s.cdx.json"`, safeID))
		w.Header().Set("X-SecFlow-Sha256", contentSHA256Hex(payload, ""))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	case "report.md", "report.html":
		format := secflowv1.ReportFormat_REPORT_FORMAT_MARKDOWN
		ctype := "text/markdown; charset=utf-8"
		ext := "md"
		if name == "report.html" {
			format = secflowv1.ReportFormat_REPORT_FORMAT_HTML
			ctype = "text/html; charset=utf-8"
			ext = "html"
		}
		resp, err := g.runs.GetReadableReport(ctx, &secflowv1.GetReadableReportRequest{Actor: actor, RunId: runID, Format: format})
		if err != nil {
			writeProblemFromGRPC(w, r, err)
			return
		}
		payload := resp.GetContent()
		w.Header().Set("Content-Type", ctype)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="report-%s.%s"`, safeID, ext))
		w.Header().Set("X-SecFlow-Sha256", contentSHA256Hex(payload, ""))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}
}

func (g *gateway) mcpHTTP(w http.ResponseWriter, r *http.Request) {
	g.mcpServerHTTP(w, r)
}

func timeNow() string {
	return stamp(nil)
}

func withTraceparent(ctx context.Context, r *http.Request) context.Context {
	if r == nil {
		return ctx
	}
	if tp := strings.TrimSpace(r.Header.Get("traceparent")); tp != "" {
		ctx = context.WithValue(ctx, traceKey{}, tp)
		if obs.TraceIDFromContext(ctx) == "" {
			ctx = obs.ExtractTraceparent(ctx, tp)
		}
	}
	return ctx
}

func traceIDFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	if tid := obs.TraceIDFromContext(r.Context()); tid != "" {
		return tid
	}
	tp := strings.TrimSpace(r.Header.Get("traceparent"))
	if tp == "" {
		return ""
	}
	parts := strings.Split(tp, "-")
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}

func writeJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeProblem(w http.ResponseWriter, r *http.Request, statusCode int, code, detail string) {
	title := http.StatusText(statusCode)
	if title == "" {
		title = "Error"
	}
	body := map[string]any{
		"type":    "about:blank",
		"title":   title,
		"status":  statusCode,
		"code":    code,
		"detail":  detail,
		"message": detail,
		"traceId": traceIDFromRequest(r),
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(body)
}

func writeProblemFromGRPC(w http.ResponseWriter, r *http.Request, err error) {
	st, ok := status.FromError(err)
	if !ok {
		slog.Error("http backend internal error", "path", r.URL.Path, "trace_id", traceIDFromRequest(r), "err", err)
		writeProblem(w, r, http.StatusInternalServerError, "INTERNAL", "internal server error")
		return
	}
	msg := st.Message()
	switch {
	case strings.Contains(msg, "ZIP_BOMB_DETECTED"):
		writeProblem(w, r, http.StatusRequestEntityTooLarge, "ZIP_BOMB_DETECTED", "archive exceeds compressed or uncompressed size limits")
		return
	case strings.Contains(msg, "ZIP_SLIP_DETECTED"):
		writeProblem(w, r, http.StatusUnprocessableEntity, "ZIP_SLIP_DETECTED", "archive contains unsafe file paths or symlinks")
		return
	}
	switch st.Code() {
	case codes.Unauthenticated:
		writeProblem(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "authentication required")
	case codes.PermissionDenied:
		if strings.Contains(msg, "SECRET_SCOPE_DENIED") {
			writeProblem(w, r, http.StatusForbidden, "SECRET_SCOPE_DENIED", "secret scope denied")
			return
		}
		if strings.Contains(msg, "ALLOWLIST") {
			writeProblem(w, r, http.StatusForbidden, "ALLOWLIST_DENIED", "repository URL is not allowlisted")
			return
		}
		writeProblem(w, r, http.StatusForbidden, "FORBIDDEN", "forbidden")
	case codes.NotFound:
		writeProblem(w, r, http.StatusNotFound, "NOT_FOUND", "resource not found")
	case codes.Aborted:
		writeProblem(w, r, http.StatusConflict, "CONFLICT", "conflict")
	case codes.AlreadyExists:
		detail := "conflict"
		if strings.Contains(msg, "DUPLICATE_DELIVERY") {
			detail = "duplicate delivery"
		}
		writeProblem(w, r, http.StatusConflict, "CONFLICT", detail)
	case codes.InvalidArgument:
		writeProblem(w, r, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "request failed validation")
	case codes.FailedPrecondition:
		if strings.Contains(msg, "DENYLIST") {
			writeProblem(w, r, http.StatusUnprocessableEntity, "DENYLIST_BLOCKED", "operation blocked by security policy")
			return
		}
		writeProblem(w, r, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "precondition failed")
	case codes.ResourceExhausted:
		writeProblem(w, r, http.StatusTooManyRequests, "RATE_LIMITED", "rate limit or queue capacity exceeded")
	default:
		slog.Error("http backend grpc error", "path", r.URL.Path, "grpc_code", st.Code().String(), "trace_id", traceIDFromRequest(r), "err", err)
		writeProblem(w, r, http.StatusInternalServerError, "INTERNAL", "internal server error")
	}
}
