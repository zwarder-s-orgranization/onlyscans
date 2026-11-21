package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/auth"
)

func (g *gateway) actorOf(c *auth.Claims) *secflowv1.ActorContext {
	if c == nil {
		return nil
	}
	mode := secflowv1.AuthMode_AUTH_MODE_LOCAL
	if c.Role == "" && len(c.Scopes) > 0 {
		mode = secflowv1.AuthMode_AUTH_MODE_SCOPED_TOKEN
	} else if strings.EqualFold(os.Getenv("AUTH_MODE"), "oidc") {
		mode = secflowv1.AuthMode_AUTH_MODE_OIDC
	}
	return &secflowv1.ActorContext{
		Subject:          c.Subject,
		Email:            c.Email,
		Role:             roleProto(c.Role),
		Scopes:           c.Scopes,
		ScopedWorkflowId: c.Wf,
		AuthMode:         mode,
	}
}

func roleNameFromProto(role secflowv1.Role) string {
	switch role {
	case secflowv1.Role_ROLE_OWNER:
		return "owner"
	case secflowv1.Role_ROLE_EDITOR:
		return "editor"
	case secflowv1.Role_ROLE_VIEWER:
		return "viewer"
	default:
		return ""
	}
}

func roleProto(role string) secflowv1.Role {
	switch strings.ToLower(role) {
	case "owner":
		return secflowv1.Role_ROLE_OWNER
	case "editor":
		return secflowv1.Role_ROLE_EDITOR
	case "viewer":
		return secflowv1.Role_ROLE_VIEWER
	default:
		return secflowv1.Role_ROLE_UNSPECIFIED
	}
}

func trimEnum(v, prefix string) string {
	s := strings.TrimPrefix(v, prefix)
	if s == "UNSPECIFIED" || s == "" {
		return ""
	}
	return s
}

func stamp(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return time.Now().UTC().Format(time.RFC3339)
	}
	return ts.AsTime().UTC().Format(time.RFC3339)
}

func optStamp(ts *timestamppb.Timestamp) any {
	if ts == nil {
		return nil
	}
	return ts.AsTime().UTC().Format(time.RFC3339)
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func asInt(v any, def int) int {
	switch n := v.(type) {
	case int:
		return n
	case int32:
		return int(n)
	case int64:
		return int(n)
	case float64:
		return int(n)
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return int(i)
		}
		return def
	case string:
		if i, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
			return i
		}
		return def
	default:
		return def
	}
}

func asInt64(v any, def int64) int64 {
	switch n := v.(type) {
	case int:
		return int64(n)
	case int32:
		return int64(n)
	case int64:
		return n
	case float64:
		return int64(n)
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i
		}
		return def
	case string:
		if i, err := strconv.ParseInt(strings.TrimSpace(n), 10, 64); err == nil {
			return i
		}
		return def
	default:
		return def
	}
}

func asFloat(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case float32:
		return float64(n)
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case json.Number:
		f, _ := n.Float64()
		return f
	default:
		return 0
	}
}

func asBool(v any) bool {
	b, _ := v.(bool)
	return b
}

func asBoolDefault(v any, def bool) bool {
	if v == nil {
		return def
	}
	if b, ok := v.(bool); ok {
		return b
	}
	return def
}

func asList(v any) []any {
	switch items := v.(type) {
	case []any:
		return items
	case []string:
		out := make([]any, 0, len(items))
		for _, item := range items {
			out = append(out, item)
		}
		return out
	case []map[string]any:
		out := make([]any, 0, len(items))
		for _, item := range items {
			out = append(out, item)
		}
		return out
	default:
		return nil
	}
}

func asStringSlice(v any) []string {
	switch items := v.(type) {
	case []string:
		return append([]string(nil), items...)
	case []any:
		out := make([]string, 0, len(items))
		for _, item := range items {
			if s := asString(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}

func secretBindingsFromAny(v any) []*secflowv1.SecretBinding {
	items := asList(v)
	if len(items) == 0 {
		return nil
	}
	out := make([]*secflowv1.SecretBinding, 0, len(items))
	for _, raw := range items {
		b := asMap(raw)
		out = append(out, &secflowv1.SecretBinding{
			ParamKey:  asString(b["paramKey"]),
			SecretRef: asString(b["secretRef"]),
		})
	}
	return out
}

func graphFromAny(v any) *secflowv1.WorkflowGraph {
	m := asMap(v)
	g := &secflowv1.WorkflowGraph{SchemaVersion: int32(asInt(m["schemaVersion"], 1))}
	for _, item := range asList(m["nodes"]) {
		n := asMap(item)
		params, _ := json.Marshal(n["params"])
		if string(params) == "null" || n["params"] == nil {
			params = []byte(`{}`)
		}
		node := &secflowv1.WorkflowNode{
			Id:             asString(n["id"]),
			PluginId:       asString(n["pluginId"]),
			Label:          asString(n["label"]),
			ParamsJson:     params,
			Position:       &secflowv1.Position{X: asFloat(asMap(n["position"])["x"]), Y: asFloat(asMap(n["position"])["y"])},
			SecretBindings: secretBindingsFromAny(n["secretBindings"]),
		}
		g.Nodes = append(g.Nodes, node)
	}
	for _, item := range asList(m["edges"]) {
		e := asMap(item)
		sh, th := asString(e["sourceHandle"]), asString(e["targetHandle"])
		if sh == "" {
			sh = "default"
		}
		if th == "" {
			th = "default"
		}
		g.Edges = append(g.Edges, &secflowv1.WorkflowEdge{
			Id:           asString(e["id"]),
			SourceNodeId: asString(e["sourceNodeId"]),
			SourceHandle: sh,
			TargetNodeId: asString(e["targetNodeId"]),
			TargetHandle: th,
		})
	}
	return g
}

func graphMap(gph *secflowv1.WorkflowGraph) map[string]any {
	if gph == nil {
		return map[string]any{"schemaVersion": 1, "nodes": []any{}, "edges": []any{}}
	}
	nodes := make([]any, 0, len(gph.GetNodes()))
	for _, n := range gph.GetNodes() {
		var params any = map[string]any{}
		if len(n.GetParamsJson()) > 0 {
			_ = json.Unmarshal(n.GetParamsJson(), &params)
		}
		bindings := make([]any, 0, len(n.GetSecretBindings()))
		for _, b := range n.GetSecretBindings() {
			bindings = append(bindings, map[string]any{"paramKey": b.GetParamKey(), "secretRef": b.GetSecretRef()})
		}
		x, y := 0.0, 0.0
		if n.GetPosition() != nil {
			x, y = n.GetPosition().GetX(), n.GetPosition().GetY()
		}
		nodes = append(nodes, map[string]any{
			"id":             n.GetId(),
			"pluginId":       n.GetPluginId(),
			"label":          n.GetLabel(),
			"position":       map[string]any{"x": x, "y": y},
			"params":         params,
			"secretBindings": bindings,
		})
	}
	edges := make([]any, 0, len(gph.GetEdges()))
	for _, e := range gph.GetEdges() {
		edges = append(edges, map[string]any{
			"id":           e.GetId(),
			"sourceNodeId": e.GetSourceNodeId(),
			"sourceHandle": e.GetSourceHandle(),
			"targetNodeId": e.GetTargetNodeId(),
			"targetHandle": e.GetTargetHandle(),
		})
	}
	schemaVersion := gph.GetSchemaVersion()
	if schemaVersion == 0 {
		schemaVersion = 1
	}
	return map[string]any{"schemaVersion": schemaVersion, "nodes": nodes, "edges": edges}
}

func issuesMap(items []*secflowv1.ValidationIssue) []any {
	out := make([]any, 0, len(items))
	for _, issue := range items {
		sev := trimEnum(issue.GetSeverity().String(), "VALIDATION_SEVERITY_")
		if sev == "" {
			sev = "ERROR"
		}
		out = append(out, map[string]any{
			"code":      issue.GetCode(),
			"severity":  sev,
			"message":   issue.GetMessage(),
			"nodeId":    emptyNil(issue.GetNodeId()),
			"edgeId":    emptyNil(issue.GetEdgeId()),
			"fieldPath": emptyNil(issue.GetFieldPath()),
		})
	}
	return out
}

func workflowMap(wf *secflowv1.Workflow) map[string]any {
	if wf == nil {
		wf = &secflowv1.Workflow{}
	}
	created := stamp(wf.GetCreatedAt())
	updated := created
	if wf.GetUpdatedAt() != nil {
		updated = stamp(wf.GetUpdatedAt())
	}
	return map[string]any{
		"id":               wf.GetId(),
		"name":             wf.GetName(),
		"description":      wf.GetDescription(),
		"version":          wf.GetVersion(),
		"graph":            graphMap(wf.GetGraph()),
		"ownerSubject":     wf.GetOwnerSubject(),
		"scheduleEnabled":  wf.GetScheduleEnabled(),
		"cronExpression":   emptyNil(wf.GetCronExpression()),
		"webhookEnabled":   wf.GetWebhookEnabled(),
		"webhookPath":      wf.GetWebhookPath(),
		"sourceTemplateId": emptyNil(wf.GetSourceTemplateId()),
		"validationIssues": issuesMap(wf.GetValidationIssues()),
		"createdAt":        created,
		"updatedAt":        updated,
	}
}

func emptyNil(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func pageReq(limit int, cursor string) *secflowv1.PageRequest {
	if limit <= 0 {
		limit = 25
	}
	if limit > 100 {
		limit = 100
	}
	return &secflowv1.PageRequest{Limit: int32(limit), Cursor: cursor}
}

func encodeOffsetCursor(offset int) string {
	return base64.RawURLEncoding.EncodeToString([]byte("offset:" + strconv.Itoa(offset)))
}

func decodeOffsetCursor(cursor string) (int, bool) {
	if strings.TrimSpace(cursor) == "" {
		return 0, true
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, false
	}
	rest, ok := strings.CutPrefix(string(raw), "offset:")
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(rest)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func page(items []any, total int) map[string]any {
	if items == nil {
		items = []any{}
	}
	return map[string]any{"items": items, "nextCursor": nil, "hasMore": false, "totalCount": total}
}

func paginate(items []any, limit int, cursor string, backend *secflowv1.PageInfo) map[string]any {
	if items == nil {
		items = []any{}
	}
	if limit <= 0 {
		limit = 25
	}
	if limit > 100 {
		limit = 100
	}
	// If backend already handled cursor pagination, preserve its page info.
	if backend != nil && (backend.GetHasMore() || backend.GetNextCursor() != "" || (cursor != "" && int(backend.GetTotalCount()) > len(items) && len(items) <= limit)) {
		total := int(backend.GetTotalCount())
		if total < len(items) {
			total = len(items)
		}
		return map[string]any{
			"items":      items,
			"nextCursor": emptyNil(backend.GetNextCursor()),
			"hasMore":    backend.GetHasMore(),
			"totalCount": total,
		}
	}
	total := len(items)
	if backend != nil && int(backend.GetTotalCount()) > total {
		total = int(backend.GetTotalCount())
	}
	start := 0
	if cursor != "" {
		if off, ok := decodeOffsetCursor(cursor); ok {
			start = off
		} else {
			return map[string]any{"items": []any{}, "nextCursor": nil, "hasMore": false, "totalCount": total}
		}
	}
	if start >= len(items) {
		return map[string]any{"items": []any{}, "nextCursor": nil, "hasMore": false, "totalCount": total}
	}
	end := start + limit
	hasMore := false
	var nextCursor any
	if end < len(items) {
		hasMore = true
		nextCursor = encodeOffsetCursor(end)
	} else {
		end = len(items)
	}
	return map[string]any{
		"items":      items[start:end],
		"nextCursor": nextCursor,
		"hasMore":    hasMore,
		"totalCount": total,
	}
}

func emptyStats() map[string]any {
	return map[string]any{
		"total":       0,
		"newCount":    0,
		"critical":    0,
		"high":        0,
		"medium":      0,
		"low":         0,
		"secretCount": 0,
		"sastCount":   0,
		"scaCount":    0,
		"maxSeverity": nil,
	}
}
