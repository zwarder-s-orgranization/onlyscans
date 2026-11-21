package main

import (
	"testing"
	"time"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
)

func TestCronMatches(t *testing.T) {
	ref := time.Date(2026, 11, 21, 3, 15, 0, 0, time.UTC) // Saturday (Weekday=6)
	tests := []struct {
		name string
		expr string
		want bool
	}{
		{name: "exact minute and hour", expr: "15 3 * * *", want: true},
		{name: "step every 15 minutes", expr: "*/15 * * * *", want: true},
		{name: "range and weekday match", expr: "10-20 3 * * 6", want: true},
		{name: "comma list match", expr: "0,15,30 1,3 * * *", want: true},
		{name: "wrong hour", expr: "15 4 * * *", want: false},
		{name: "wrong weekday", expr: "15 3 * * 1-5", want: false},
		{name: "invalid field count", expr: "15 3 * *", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cronMatches(tt.expr, ref); got != tt.want {
				t.Fatalf("cronMatches(%q) = %v, want %v", tt.expr, got, tt.want)
			}
		})
	}
}

func TestTickSchedules_StartsRunOncePerMinute(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	s := newServer()
	_, err := s.CreateWorkflow(ctx, &secflowv1.CreateWorkflowRequest{
		Name: "Nightly Watch",
		Graph: &secflowv1.WorkflowGraph{
			SchemaVersion: 1,
			Nodes: []*secflowv1.WorkflowNode{
				{Id: "t1", PluginId: "trigger.schedule", ParamsJson: []byte(`{"cron":"0 3 * * *","timezone":"UTC","enabled":true}`)},
				{Id: "s1", PluginId: "source.upload", ParamsJson: []byte(`{"sourceId":"pending-upload"}`)},
			},
			Edges: []*secflowv1.WorkflowEdge{
				{Id: "e1", SourceNodeId: "t1", SourceHandle: "default", TargetNodeId: "s1", TargetHandle: "default"},
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}

	lastFired := map[string]string{}
	matchTime := time.Date(2026, 11, 21, 3, 0, 10, 0, time.UTC)
	s.tickSchedules(ctx, matchTime, lastFired)
	s.tickSchedules(ctx, matchTime.Add(20*time.Second), lastFired)

	s.runMu.Lock()
	runCount := len(s.runs)
	var gotTrig secflowv1.TriggerType
	for _, st := range s.runs {
		gotTrig = st.run.GetTrigger().GetType()
	}
	s.runMu.Unlock()
	if runCount != 1 {
		t.Fatalf("expected exactly 1 scheduled run in same minute, got %d", runCount)
	}
	if gotTrig != secflowv1.TriggerType_TRIGGER_TYPE_SCHEDULE {
		t.Fatalf("trigger type = %v, want TRIGGER_TYPE_SCHEDULE", gotTrig)
	}
}

func TestApplyTriggerMetadata(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		wf           *secflowv1.Workflow
		wantSchedule bool
		wantCron     string
		wantWebhook  bool
	}{
		{
			name: "schedule enabled by default",
			wf: &secflowv1.Workflow{
				Id: "wf_1",
				Graph: &secflowv1.WorkflowGraph{
					Nodes: []*secflowv1.WorkflowNode{
						{Id: "t1", PluginId: "trigger.schedule", ParamsJson: []byte(`{"cron":"0 14 * * *"}`)},
					},
				},
			},
			wantSchedule: true,
			wantCron:     "0 14 * * *",
			wantWebhook:  false,
		},
		{
			name: "schedule explicitly disabled",
			wf: &secflowv1.Workflow{
				Id: "wf_2",
				Graph: &secflowv1.WorkflowGraph{
					Nodes: []*secflowv1.WorkflowNode{
						{Id: "t1", PluginId: "trigger.schedule", ParamsJson: []byte(`{"cron":"0 14 * * *","enabled":false}`)},
					},
				},
			},
			wantSchedule: false,
			wantCron:     "0 14 * * *",
			wantWebhook:  false,
		},
		{
			name: "webhook trigger sets webhookEnabled and path",
			wf: &secflowv1.Workflow{
				Id: "wf_3",
				Graph: &secflowv1.WorkflowGraph{
					Nodes: []*secflowv1.WorkflowNode{
						{Id: "t1", PluginId: "trigger.webhook", ParamsJson: []byte(`{"gitProvider":"GITHUB"}`)},
					},
				},
			},
			wantSchedule: false,
			wantCron:     "",
			wantWebhook:  true,
		},
		{
			name: "manual trigger clears schedule and webhook flags",
			wf: &secflowv1.Workflow{
				Id:              "wf_4",
				ScheduleEnabled: true,
				CronExpression:  "0 1 * * *",
				WebhookEnabled:  true,
				Graph: &secflowv1.WorkflowGraph{
					Nodes: []*secflowv1.WorkflowNode{
						{Id: "t1", PluginId: "trigger.manual", ParamsJson: []byte(`{}`)},
					},
				},
			},
			wantSchedule: false,
			wantCron:     "",
			wantWebhook:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			applyTriggerMetadata(tt.wf)
			if tt.wf.GetScheduleEnabled() != tt.wantSchedule {
				t.Fatalf("ScheduleEnabled = %v, want %v", tt.wf.GetScheduleEnabled(), tt.wantSchedule)
			}
			if tt.wf.GetCronExpression() != tt.wantCron {
				t.Fatalf("CronExpression = %q, want %q", tt.wf.GetCronExpression(), tt.wantCron)
			}
			if tt.wf.GetWebhookEnabled() != tt.wantWebhook {
				t.Fatalf("WebhookEnabled = %v, want %v", tt.wf.GetWebhookEnabled(), tt.wantWebhook)
			}
		})
	}
}
