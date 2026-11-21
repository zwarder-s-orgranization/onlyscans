package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/auth"
)

func (g *gateway) checkScopedWorkflow(claims *auth.Claims, workflowID string) error {
	if claims == nil || claims.Wf == "" {
		return nil
	}
	if workflowID == "" || workflowID != claims.Wf {
		return status.Error(codes.PermissionDenied, "FORBIDDEN")
	}
	return nil
}

func (g *gateway) checkScopedRun(ctx context.Context, claims *auth.Claims, actor *secflowv1.ActorContext, runID string) (*secflowv1.Run, error) {
	if claims == nil || claims.Wf == "" {
		return nil, nil
	}
	if runID == "" || g.runs == nil {
		return nil, status.Error(codes.PermissionDenied, "FORBIDDEN")
	}
	resp, err := g.runs.GetRun(ctx, &secflowv1.GetRunRequest{Actor: actor, RunId: runID})
	if err != nil {
		return nil, err
	}
	if err := g.checkScopedWorkflow(claims, resp.GetRun().GetWorkflowId()); err != nil {
		return nil, err
	}
	return resp.GetRun(), nil
}

func (g *gateway) resolve(ctx context.Context, claims *auth.Claims, fieldName string, args map[string]any) (any, error) {
	actor := g.actorOf(claims)
	switch fieldName {
	case "login":
		return g.login(ctx, args["input"])
	case "me":
		return actorMap(claims), nil
	case "workflow":
		wfID := asString(args["id"])
		if err := g.checkScopedWorkflow(claims, wfID); err != nil {
			return nil, err
		}
		resp, err := g.wf.GetWorkflow(ctx, &secflowv1.GetWorkflowRequest{Actor: actor, WorkflowId: wfID})
		if err != nil {
			return nil, err
		}
		return workflowMap(resp.GetWorkflow()), nil
	case "workflows":
		limit := asInt(args["limit"], 25)
		cursor := asString(args["cursor"])
		search := asString(args["search"])
		resp, err := g.wf.ListWorkflows(ctx, &secflowv1.ListWorkflowsRequest{
			Actor:  actor,
			Search: search,
			Page:   pageReq(limit, cursor),
		})
		if err != nil {
			return nil, err
		}
		searchLower := strings.ToLower(strings.TrimSpace(search))
		items := make([]any, 0, len(resp.GetWorkflows()))
		for _, wf := range resp.GetWorkflows() {
			if claims != nil && claims.Wf != "" && wf.GetId() != claims.Wf {
				continue
			}
			if searchLower != "" && !strings.Contains(strings.ToLower(wf.GetName()), searchLower) {
				continue
			}
			items = append(items, workflowMap(wf))
		}
		return paginate(items, limit, cursor, resp.GetPageInfo()), nil
	case "validateWorkflow":
		resp, err := g.wf.ValidateWorkflow(ctx, &secflowv1.ValidateWorkflowRequest{
			Actor: actor,
			Graph: graphFromAny(args["graph"]),
		})
		if err != nil {
			return nil, err
		}
		valid := true
		for _, issue := range resp.GetIssues() {
			if issue.GetSeverity() == secflowv1.ValidationSeverity_VALIDATION_SEVERITY_ERROR {
				valid = false
				break
			}
		}
		return map[string]any{"valid": valid, "issues": issuesMap(resp.GetIssues())}, nil
	case "saveWorkflow":
		return g.saveWorkflow(ctx, actor, asMap(args["input"]))
	case "deleteWorkflow":
		resp, err := g.wf.DeleteWorkflow(ctx, &secflowv1.DeleteWorkflowRequest{
			Actor:      actor,
			WorkflowId: asString(args["id"]),
		})
		if err != nil {
			return nil, err
		}
		return resp.GetDeleted(), nil
	case "startRun":
		in := asMap(args["input"])
		wfID := asString(in["workflowId"])
		if err := g.checkScopedWorkflow(claims, wfID); err != nil {
			return nil, err
		}
		triggerType := secflowv1.TriggerType_TRIGGER_TYPE_MANUAL
		if claims != nil && claims.Role == "" {
			if hasScope(claims, "ci:startRun") {
				triggerType = secflowv1.TriggerType_TRIGGER_TYPE_CI_API
			} else if hasScope(claims, "mcp:run") {
				triggerType = secflowv1.TriggerType_TRIGGER_TYPE_MCP
			}
		}
		resp, err := g.runs.StartRun(ctx, &secflowv1.StartRunRequest{
			Actor:             actor,
			WorkflowId:        wfID,
			TriggerType:       triggerType,
			SourceIdOverride:  asString(in["sourceIdOverride"]),
			RepoUrlOverride:   asString(in["repoUrlOverride"]),
			GitRefOverride:    asString(in["gitRefOverride"]),
			CommitShaOverride: asString(in["commitShaOverride"]),
			IdempotencyKey:    asString(in["idempotencyKey"]),
		})
		if err != nil {
			return nil, err
		}
		return g.decorateRun(ctx, actor, resp.GetRun())
	case "rerunFromNode":
		in := asMap(args["input"])
		var rawParams []byte
		if in["updatedParams"] != nil {
			rawParams, _ = json.Marshal(in["updatedParams"])
		}
		resp, err := g.runs.RerunFromNode(ctx, &secflowv1.RerunFromNodeRequest{
			Actor:                  actor,
			SourceRunId:            asString(in["sourceRunId"]),
			NodeId:                 asString(in["nodeId"]),
			UpdatedParamsJson:      rawParams,
			UpdatedSecretBindings:  secretBindingsFromAny(in["updatedSecretBindings"]),
			PersistWorkflowChanges: asBool(in["persistWorkflowChanges"]),
		})
		if err != nil {
			return nil, err
		}
		return g.decorateRun(ctx, actor, resp.GetRun())
	case "cancelRun":
		resp, err := g.runs.CancelRun(ctx, &secflowv1.CancelRunRequest{
			Actor:  actor,
			RunId:  asString(args["runId"]),
			Reason: asString(args["reason"]),
		})
		if err != nil {
			return nil, err
		}
		return g.decorateRun(ctx, actor, resp.GetRun())
	case "run":
		resp, err := g.runs.GetRun(ctx, &secflowv1.GetRunRequest{
			Actor: actor,
			RunId: asString(args["id"]),
		})
		if err != nil {
			return nil, err
		}
		if err := g.checkScopedWorkflow(claims, resp.GetRun().GetWorkflowId()); err != nil {
			return nil, err
		}
		return g.decorateRun(ctx, actor, resp.GetRun())
	case "runs":
		wfID := asString(args["workflowId"])
		if claims != nil && claims.Wf != "" {
			if wfID != "" && wfID != claims.Wf {
				return nil, status.Error(codes.PermissionDenied, "FORBIDDEN")
			}
			wfID = claims.Wf
		}
		limit := asInt(args["limit"], 25)
		cursor := asString(args["cursor"])
		wantStatus := runStatusProto(asString(args["status"]))
		resp, err := g.runs.ListRuns(ctx, &secflowv1.ListRunsRequest{
			Actor:      actor,
			WorkflowId: wfID,
			Status:     wantStatus,
			Page:       pageReq(limit, cursor),
		})
		if err != nil {
			return nil, err
		}
		wfNameCache := map[string]string{}
		items := make([]any, 0, len(resp.GetRuns()))
		for _, run := range resp.GetRuns() {
			if claims != nil && claims.Wf != "" && run.GetWorkflowId() != claims.Wf {
				continue
			}
			if wantStatus != secflowv1.RunStatus_RUN_STATUS_UNSPECIFIED && run.GetStatus() != wantStatus {
				continue
			}
			item := runMap(run)
			if run.GetWorkflowName() == "" && run.GetWorkflowId() != "" {
				item["workflowName"] = g.lookupWorkflowNameCached(ctx, actor, run.GetWorkflowId(), wfNameCache)
			}
			items = append(items, item)
		}
		return paginate(items, limit, cursor, resp.GetPageInfo()), nil
	case "findings":
		if _, err := g.checkScopedRun(ctx, claims, actor, asString(args["runId"])); err != nil {
			return nil, err
		}
		return g.findings(ctx, actor, args)
	case "nodeRunPayload":
		runID := asString(args["runId"])
		if _, err := g.checkScopedRun(ctx, claims, actor, runID); err != nil {
			return nil, err
		}
		resp, err := g.runs.GetNodePayload(ctx, &secflowv1.GetNodePayloadRequest{
			Actor:        actor,
			RunId:        runID,
			NodeId:       asString(args["nodeId"]),
			SourceHandle: asString(args["sourceHandle"]),
		})
		if err != nil {
			return nil, err
		}
		var in any
		var out any
		if len(resp.GetInputEnvelopeJson()) > 0 {
			_ = json.Unmarshal(resp.GetInputEnvelopeJson(), &in)
		}
		if len(resp.GetOutputEnvelopeJson()) > 0 {
			_ = json.Unmarshal(resp.GetOutputEnvelopeJson(), &out)
		}
		ports := make([]any, 0, len(resp.GetActiveOutputPorts()))
		for _, p := range resp.GetActiveOutputPorts() {
			ports = append(ports, p)
		}
		portOutputs := make([]any, 0, len(resp.GetPortOutputs()))
		for _, p := range resp.GetPortOutputs() {
			var env any = map[string]any{}
			if len(p.GetOutputEnvelopeJson()) > 0 {
				_ = json.Unmarshal(p.GetOutputEnvelopeJson(), &env)
			}
			portOutputs = append(portOutputs, map[string]any{
				"sourceHandle":   p.GetSourceHandle(),
				"outputEnvelope": env,
			})
		}
		nodeStatus := first(trimEnum(resp.GetStatus().String(), "NODE_RUN_STATUS_"), "PENDING")
		return map[string]any{
			"runId":             resp.GetRunId(),
			"nodeId":            resp.GetNodeId(),
			"pluginId":          resp.GetPluginId(),
			"status":            nodeStatus,
			"inputEnvelope":     in,
			"outputEnvelope":    out,
			"activeOutputPorts": ports,
			"portOutputs":       portOutputs,
		}, nil
	case "sbom":
		runID := asString(args["runId"])
		if _, err := g.checkScopedRun(ctx, claims, actor, runID); err != nil {
			return nil, err
		}
		resp, err := g.runs.GetSbom(ctx, &secflowv1.GetSbomRequest{
			Actor:          actor,
			RunId:          runID,
			IncludeContent: true,
		})
		if err != nil {
			return nil, err
		}
		return sbomMap(resp.GetSbom(), runID), nil
	case "readableReport":
		runID := asString(args["runId"])
		if _, err := g.checkScopedRun(ctx, claims, actor, runID); err != nil {
			return nil, err
		}
		format := secflowv1.ReportFormat_REPORT_FORMAT_MARKDOWN
		if asString(args["format"]) == "HTML" {
			format = secflowv1.ReportFormat_REPORT_FORMAT_HTML
		}
		resp, err := g.runs.GetReadableReport(ctx, &secflowv1.GetReadableReportRequest{
			Actor:  actor,
			RunId:  runID,
			Format: format,
		})
		if err != nil {
			return nil, err
		}
		name := "MARKDOWN"
		ext := "md"
		if format == secflowv1.ReportFormat_REPORT_FORMAT_HTML {
			name = "HTML"
			ext = "html"
		}
		return map[string]any{
			"format":       name,
			"content":      string(resp.GetContent()),
			"findingCount": resp.GetFindingCount(),
			"downloadUrl":  "/runs/" + runID + "/report." + ext,
		}, nil
	case "plugins":
		wantCat := pluginCategoryProto(asString(args["category"]))
		includeOffline := asBool(args["includeOffline"])
		resp, err := g.plugs.ListPlugins(ctx, &secflowv1.ListPluginsRequest{
			Actor:          actor,
			Category:       wantCat,
			IncludeOffline: includeOffline,
		})
		if err != nil {
			return nil, err
		}
		items := make([]any, 0, len(resp.GetPlugins()))
		for _, p := range resp.GetPlugins() {
			if wantCat != secflowv1.PluginCategory_PLUGIN_CATEGORY_UNSPECIFIED && p.GetManifest().GetCategory() != wantCat {
				continue
			}
			if !includeOffline && p.GetStatus() == secflowv1.PluginStatus_PLUGIN_STATUS_OFFLINE {
				continue
			}
			items = append(items, pluginMap(p))
		}
		return items, nil
	case "plugin":
		resp, err := g.plugs.GetPlugin(ctx, &secflowv1.GetPluginRequest{
			Actor:    actor,
			PluginId: asString(args["pluginId"]),
		})
		if err != nil {
			return nil, err
		}
		return pluginMap(resp.GetPlugin()), nil
	case "templates":
		limit := asInt(args["limit"], 25)
		cursor := asString(args["cursor"])
		search := asString(args["search"])
		tags := asStringSlice(args["tags"])
		resp, err := g.wf.ListTemplates(ctx, &secflowv1.ListTemplatesRequest{
			Actor:  actor,
			Search: search,
			Tags:   tags,
			Page:   pageReq(limit, cursor),
		})
		if err != nil {
			return nil, err
		}
		searchLower := strings.ToLower(strings.TrimSpace(search))
		items := make([]any, 0, len(resp.GetTemplates()))
		for _, tpl := range resp.GetTemplates() {
			if searchLower != "" {
				hay := strings.ToLower(tpl.GetName() + " " + tpl.GetDescription() + " " + tpl.GetProblemSolved())
				if !strings.Contains(hay, searchLower) {
					continue
				}
			}
			if len(tags) > 0 && !templateHasAllTags(tpl.GetTags(), tags) {
				continue
			}
			items = append(items, templateMap(tpl))
		}
		return paginate(items, limit, cursor, resp.GetPageInfo()), nil
	case "template":
		resp, err := g.wf.GetTemplate(ctx, &secflowv1.GetTemplateRequest{
			Actor:      actor,
			TemplateId: asString(args["id"]),
		})
		if err != nil {
			return nil, err
		}
		return templateMap(resp.GetTemplate()), nil
	case "publishTemplate":
		in := asMap(args["input"])
		resp, err := g.wf.PublishTemplate(ctx, &secflowv1.PublishTemplateRequest{
			Actor:         actor,
			WorkflowId:    asString(in["workflowId"]),
			Name:          asString(in["name"]),
			Description:   asString(in["description"]),
			ProblemSolved: asString(in["problemSolved"]),
			Tags:          asStringSlice(in["tags"]),
		})
		if err != nil {
			return nil, err
		}
		return templateMap(resp.GetTemplate()), nil
	case "cloneTemplate":
		in := asMap(args["input"])
		resp, err := g.wf.CloneTemplate(ctx, &secflowv1.CloneTemplateRequest{
			Actor:           actor,
			TemplateId:      asString(in["templateId"]),
			NewWorkflowName: asString(in["newWorkflowName"]),
		})
		if err != nil {
			return nil, err
		}
		return workflowMap(resp.GetWorkflow()), nil
	case "generateCiConfig":
		in := asMap(args["input"])
		provider := secflowv1.CiProvider_CI_PROVIDER_GITHUB_ACTIONS
		if asString(in["provider"]) == "GITLAB_CI" {
			provider = secflowv1.CiProvider_CI_PROVIDER_GITLAB_CI
		}
		failOnSev := severityProto(asString(in["failOnSeverity"]))
		if failOnSev == secflowv1.Severity_SEVERITY_UNSPECIFIED {
			failOnSev = secflowv1.Severity_SEVERITY_HIGH
		}
		resp, err := g.wf.GenerateCiConfig(ctx, &secflowv1.GenerateCiConfigRequest{
			Actor:            actor,
			WorkflowId:       asString(in["workflowId"]),
			Provider:         provider,
			SecflowBaseUrl:   asString(in["secflowBaseUrl"]),
			FailOnSeverity:   failOnSev,
			FailOnPolicyGate: asBoolDefault(in["failOnPolicyGate"], true),
		})
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"provider":          first(trimEnum(resp.GetProvider().String(), "CI_PROVIDER_"), "GITHUB_ACTIONS"),
			"filename":          resp.GetFilename(),
			"yamlContent":       resp.GetYamlContent(),
			"requiredCiSecrets": stringList(resp.GetRequiredCiSecrets()),
		}, nil
	case "generateWorkflowFromText":
		in := asMap(args["input"])
		resp, err := g.ai.GenerateWorkflow(ctx, &secflowv1.GenerateWorkflowRequest{
			Actor:  actor,
			Prompt: asString(in["prompt"]),
			Locale: first(asString(in["locale"]), "ru"),
		})
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"suggestedName":        resp.GetSuggestedName(),
			"suggestedDescription": resp.GetSuggestedDescription(),
			"rationale":            resp.GetRationale(),
			"graph":                graphMap(resp.GetGraph()),
			"missingFields":        issuesMap(resp.GetMissingFields()),
			"modelId":              resp.GetModelId(),
			"providerMode":         first(trimEnum(resp.GetProviderMode().String(), "AI_PROVIDER_MODE_"), "TEMPLATE_FALLBACK"),
		}, nil
	case "catalogs":
		resp, err := g.cats.ListCatalogs(ctx, &secflowv1.ListCatalogsRequest{Actor: actor})
		if err != nil {
			return nil, err
		}
		items := make([]any, 0, len(resp.GetCatalogs()))
		for _, c := range resp.GetCatalogs() {
			items = append(items, catalogMap(c))
		}
		return items, nil
	case "aiProviderStatus":
		resp, err := g.ai.GetProviderStatus(ctx, &secflowv1.GetProviderStatusRequest{Actor: actor})
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"providerMode":       first(trimEnum(resp.GetProviderMode().String(), "AI_PROVIDER_MODE_"), "TEMPLATE_FALLBACK"),
			"modelId":            resp.GetModelId(),
			"endpointHost":       resp.GetEndpointHost(),
			"closedLoop":         resp.GetClosedLoop(),
			"defaultPrivacyMode": first(trimEnum(resp.GetDefaultPrivacyMode().String(), "PRIVACY_MODE_"), "REDACTED_SNIPPET"),
			"healthy":            resp.GetHealthy(),
		}, nil
	case "aiAuditLogs":
		limit := asInt(args["limit"], 25)
		cursor := asString(args["cursor"])
		resp, err := g.ai.ListAuditLogs(ctx, &secflowv1.ListAuditLogsRequest{
			Actor: actor,
			RunId: asString(args["runId"]),
			Page:  pageReq(limit, cursor),
		})
		if err != nil {
			return nil, err
		}
		items := make([]any, 0, len(resp.GetEntries()))
		for _, entry := range resp.GetEntries() {
			items = append(items, auditMap(entry))
		}
		return paginate(items, limit, cursor, resp.GetPageInfo()), nil
	case "secrets":
		wantKind := secretKindOpt(asString(args["kind"]))
		resp, err := g.secs.ListMaskedSecrets(ctx, &secflowv1.ListMaskedSecretsRequest{
			Actor: actor,
			Kind:  wantKind,
		})
		if err != nil {
			return nil, err
		}
		items := make([]any, 0, len(resp.GetSecrets()))
		for _, sec := range resp.GetSecrets() {
			if wantKind != secflowv1.SecretKind_SECRET_KIND_UNSPECIFIED && sec.GetKind() != wantKind {
				continue
			}
			items = append(items, secretMap(sec))
		}
		return items, nil
	case "createSecret":
		in := asMap(args["input"])
		resp, err := g.secs.CreateSecret(ctx, &secflowv1.CreateSecretRequest{
			Actor:          actor,
			Name:           asString(in["name"]),
			Kind:           secretKind(asString(in["kind"])),
			PlaintextValue: asString(in["plaintextValue"]),
		})
		if err != nil {
			return nil, err
		}
		return secretMap(resp.GetSecret()), nil
	case "deleteSecret":
		resp, err := g.secs.DeleteSecret(ctx, &secflowv1.DeleteSecretRequest{
			Actor:     actor,
			SecretRef: asString(args["secretRef"]),
		})
		if err != nil {
			return nil, err
		}
		return resp.GetDeleted(), nil
	case "scopedTokens":
		resp, err := g.secs.ListScopedTokens(ctx, &secflowv1.ListScopedTokensRequest{Actor: actor})
		if err != nil {
			return nil, err
		}
		items := make([]any, 0, len(resp.GetTokens()))
		for _, tok := range resp.GetTokens() {
			items = append(items, tokenMap(tok))
		}
		return items, nil
	case "createScopedToken":
		in := asMap(args["input"])
		scopes := asStringSlice(in["scopes"])
		var expiresAt *timestamppb.Timestamp
		if rawExp := strings.TrimSpace(asString(in["expiresAt"])); rawExp != "" {
			parsed, err := time.Parse(time.RFC3339, rawExp)
			if err != nil {
				return nil, status.Error(codes.InvalidArgument, "invalid expiresAt")
			}
			expiresAt = timestamppb.New(parsed)
		}
		resp, err := g.secs.IssueScopedToken(ctx, &secflowv1.IssueScopedTokenRequest{
			Actor:      actor,
			Name:       asString(in["name"]),
			Scopes:     scopes,
			WorkflowId: asString(in["workflowId"]),
			ExpiresAt:  expiresAt,
		})
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"metadata":       tokenMap(resp.GetMetadata()),
			"plaintextToken": resp.GetPlaintextToken(),
		}, nil
	case "revokeScopedToken":
		resp, err := g.secs.RevokeScopedToken(ctx, &secflowv1.RevokeScopedTokenRequest{
			Actor:   actor,
			TokenId: asString(args["tokenId"]),
		})
		if err != nil {
			return nil, err
		}
		return resp.GetRevoked(), nil
	case "mcpConnections":
		resp, err := g.mcp.ListConnections(ctx, &secflowv1.ListConnectionsRequest{Actor: actor})
		if err != nil {
			return nil, err
		}
		items := make([]any, 0, len(resp.GetConnections()))
		for _, c := range resp.GetConnections() {
			items = append(items, mcpMap(c))
		}
		return items, nil
	case "mcpConnectionTools":
		resp, err := g.mcp.ListConnectionTools(ctx, &secflowv1.ListConnectionToolsRequest{
			Actor:        actor,
			ConnectionId: asString(args["connectionId"]),
			ForceRefresh: asBool(args["forceRefresh"]),
		})
		if err != nil {
			return nil, err
		}
		tools := make([]any, 0, len(resp.GetTools()))
		for _, tool := range resp.GetTools() {
			var schema any = map[string]any{}
			if len(tool.GetInputSchemaJson()) > 0 {
				_ = json.Unmarshal(tool.GetInputSchemaJson(), &schema)
			}
			tools = append(tools, map[string]any{
				"name":        tool.GetName(),
				"description": tool.GetDescription(),
				"inputSchema": schema,
			})
		}
		return map[string]any{
			"connectionId":     resp.GetConnectionId(),
			"tools":            tools,
			"blockedToolCount": resp.GetBlockedToolCount(),
			"fetchedAt":        stamp(resp.GetFetchedAt()),
		}, nil
	case "registerMcpConnection":
		resp, err := g.mcp.RegisterConnection(ctx, &secflowv1.RegisterConnectionRequest{
			Actor:  actor,
			Config: mcpConfig(asMap(asMap(args["input"])["config"])),
		})
		if err != nil {
			return nil, err
		}
		return mcpMap(resp.GetConnection()), nil
	case "updateMcpConnection":
		in := asMap(args["input"])
		resp, err := g.mcp.UpdateConnection(ctx, &secflowv1.UpdateConnectionRequest{
			Actor:        actor,
			ConnectionId: asString(in["id"]),
			Config:       mcpConfig(asMap(in["config"])),
			Enabled:      asBool(in["enabled"]),
		})
		if err != nil {
			return nil, err
		}
		return mcpMap(resp.GetConnection()), nil
	case "deleteMcpConnection":
		resp, err := g.mcp.DeleteConnection(ctx, &secflowv1.DeleteConnectionRequest{
			Actor:        actor,
			ConnectionId: asString(args["id"]),
		})
		if err != nil {
			return nil, err
		}
		return resp.GetDeleted(), nil
	case "testMcpConnection":
		resp, err := g.mcp.TestConnection(ctx, &secflowv1.TestConnectionRequest{
			Actor:        actor,
			ConnectionId: asString(args["id"]),
		})
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"ok":                 resp.GetOk(),
			"serverName":         emptyNil(resp.GetServerName()),
			"serverVersion":      emptyNil(resp.GetServerVersion()),
			"availableToolCount": resp.GetAvailableToolCount(),
			"blockedToolCount":   resp.GetBlockedToolCount(),
			"errorMessage":       emptyNil(resp.GetErrorMessage()),
		}, nil
	case "webhookInspectorDeliveries":
		key := asString(args["channelKey"])
		limit := asInt(args["limit"], 25)
		return g.listInspectorDeliveries(key, limit), nil
	default:
		return nil, status.Error(codes.InvalidArgument, "unknown field "+fieldName)
	}
}

func (g *gateway) login(ctx context.Context, raw any) (any, error) {
	if strings.EqualFold(os.Getenv("AUTH_MODE"), "oidc") {
		return nil, status.Error(codes.FailedPrecondition, "local login disabled")
	}
	in := asMap(raw)
	email, password := asString(in["email"]), asString(in["password"])
	role, ok := g.checkUser(ctx, email, password)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "UNAUTHENTICATED")
	}
	exp := time.Now().Add(12 * time.Hour)
	token, err := auth.Sign(g.secret, auth.Claims{Subject: email, Email: email, Role: role, Exp: exp.Unix()})
	if err != nil {
		return nil, err
	}
	claims := &auth.Claims{Subject: email, Email: email, Role: role}
	return map[string]any{
		"accessToken": token,
		"tokenType":   "Bearer",
		"expiresAt":   exp.UTC().Format(time.RFC3339),
		"actor":       actorMap(claims),
	}, nil
}

type localUserSpec struct {
	email    string
	password string
	role     string
}

func isLocalAuthMode() bool {
	return !strings.EqualFold(strings.TrimSpace(os.Getenv("AUTH_MODE")), "oidc")
}

func isProductionEnv() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("SECFLOW_ENV")), "production") ||
		strings.EqualFold(strings.TrimSpace(os.Getenv("ENV")), "production")
}

func configuredLocalUsers(rawUsers string, production bool) []localUserSpec {
	raw := strings.TrimSpace(rawUsers)
	if raw == "" {
		if production {
			return nil
		}
		raw = "owner@secflow.local:secflow:owner"
	}
	var out []localUserSpec
	for _, item := range strings.Split(raw, ",") {
		parts := strings.Split(strings.TrimSpace(item), ":")
		if len(parts) != 3 {
			continue
		}
		email, pass, role := strings.TrimSpace(parts[0]), parts[1], strings.TrimSpace(parts[2])
		if email == "" || pass == "" || role == "" {
			continue
		}
		out = append(out, localUserSpec{email: email, password: pass, role: role})
	}
	return out
}

func hashPasswordSalted(password string) (string, error) {
	saltBytes := make([]byte, 16)
	if _, err := rand.Read(saltBytes); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	salt := hex.EncodeToString(saltBytes)
	sum := sha256.Sum256([]byte(salt + ":" + password))
	return "sha256:" + salt + ":" + hex.EncodeToString(sum[:]), nil
}

func ensureLocalUsersTable(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return nil
	}
	dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := pool.Exec(dbCtx, `CREATE TABLE IF NOT EXISTS users (
		email text PRIMARY KEY,
		password_hash text NOT NULL,
		role text NOT NULL,
		created_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return fmt.Errorf("create users table: %w", err)
	}
	for _, u := range configuredLocalUsers(os.Getenv("AUTH_USERS"), isProductionEnv()) {
		hashed, err := hashPasswordSalted(u.password)
		if err != nil {
			return fmt.Errorf("hash seed user %s: %w", u.email, err)
		}
		if _, err := pool.Exec(
			dbCtx,
			`INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) ON CONFLICT (email) DO NOTHING`,
			u.email, hashed, u.role,
		); err != nil {
			return fmt.Errorf("seed local user %s: %w", u.email, err)
		}
	}
	return nil
}

func isMissingUsersTableErr(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "42P01" {
		return true
	}
	low := strings.ToLower(err.Error())
	return strings.Contains(low, "does not exist") && strings.Contains(low, "users")
}

func (g *gateway) checkUser(ctx context.Context, email, password string) (string, bool) {
	if email == "" || password == "" {
		return "", false
	}
	if g.userLookup != nil {
		storedHash, role, found, err := g.userLookup(ctx, email)
		if err == nil && found {
			if verifyPasswordHash(storedHash, password) {
				return role, true
			}
			return "", false
		}
		if isLocalAuthMode() && ((err == nil && !found) || (!isProductionEnv() && isMissingUsersTableErr(err))) {
			return checkEnvUser(email, password)
		}
		return "", false
	}
	if g.pool != nil {
		dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		var storedHash, role string
		err := g.pool.QueryRow(dbCtx, `SELECT password_hash, role FROM users WHERE email = $1`, email).Scan(&storedHash, &role)
		if err == nil {
			if verifyPasswordHash(storedHash, password) {
				return role, true
			}
			return "", false
		}
		if isLocalAuthMode() && (errors.Is(err, pgx.ErrNoRows) || (!isProductionEnv() && isMissingUsersTableErr(err))) {
			if !errors.Is(err, pgx.ErrNoRows) {
				slog.Warn("users table query failed in non-production, falling back to configured local users", "err", err)
			}
			return checkEnvUser(email, password)
		}
		return "", false
	}
	return checkEnvUser(email, password)
}

func checkEnvUser(email, password string) (string, bool) {
	for _, u := range configuredLocalUsers(os.Getenv("AUTH_USERS"), isProductionEnv()) {
		emailMatch := subtle.ConstantTimeCompare([]byte(u.email), []byte(email)) == 1
		passMatch := subtle.ConstantTimeCompare([]byte(u.password), []byte(password)) == 1
		if emailMatch && passMatch {
			return u.role, true
		}
	}
	return "", false
}

func verifyPasswordHash(storedHash, password string) bool {
	if storedHash == "" {
		return false
	}
	if rest, ok := strings.CutPrefix(storedHash, "sha256:"); ok {
		if salt, wantHex, hasSalt := strings.Cut(rest, ":"); hasSalt {
			sum := sha256.Sum256([]byte(salt + ":" + password))
			gotHex := hex.EncodeToString(sum[:])
			return subtle.ConstantTimeCompare([]byte(gotHex), []byte(strings.ToLower(wantHex))) == 1
		}
		sum := sha256.Sum256([]byte(password))
		gotHex := hex.EncodeToString(sum[:])
		return subtle.ConstantTimeCompare([]byte(gotHex), []byte(strings.ToLower(rest))) == 1
	}
	if len(storedHash) == 64 {
		if _, err := hex.DecodeString(storedHash); err == nil {
			sum := sha256.Sum256([]byte(password))
			gotHex := hex.EncodeToString(sum[:])
			return subtle.ConstantTimeCompare([]byte(gotHex), []byte(strings.ToLower(storedHash))) == 1
		}
	}
	return subtle.ConstantTimeCompare([]byte(storedHash), []byte(password)) == 1
}

func actorMap(c *auth.Claims) map[string]any {
	if c == nil {
		c = &auth.Claims{}
	}
	role := strings.ToUpper(c.Role)
	var roleVal any
	if role != "" {
		roleVal = role
	}
	scopes := make([]any, 0, len(c.Scopes))
	for _, s := range c.Scopes {
		scopes = append(scopes, s)
	}
	mode := "LOCAL"
	if c.Role == "" && len(c.Scopes) > 0 {
		mode = "SCOPED_TOKEN"
	} else if strings.EqualFold(os.Getenv("AUTH_MODE"), "oidc") {
		mode = "OIDC"
	}
	return map[string]any{
		"subject":          c.Subject,
		"email":            emptyNil(c.Email),
		"role":             roleVal,
		"scopes":           scopes,
		"scopedWorkflowId": emptyNil(c.Wf),
		"authMode":         mode,
	}
}

func (g *gateway) saveWorkflow(ctx context.Context, actor *secflowv1.ActorContext, in map[string]any) (any, error) {
	graph := graphFromAny(in["graph"])
	if asString(in["id"]) == "" {
		resp, err := g.wf.CreateWorkflow(ctx, &secflowv1.CreateWorkflowRequest{
			Actor:       actor,
			Name:        asString(in["name"]),
			Description: asString(in["description"]),
			Graph:       graph,
		})
		if err != nil {
			return nil, err
		}
		return workflowMap(resp.GetWorkflow()), nil
	}
	var expected *int32
	if in["expectedVersion"] != nil {
		v := int32(asInt(in["expectedVersion"], 0))
		expected = &v
	}
	resp, err := g.wf.UpdateWorkflow(ctx, &secflowv1.UpdateWorkflowRequest{
		Actor:           actor,
		WorkflowId:      asString(in["id"]),
		ExpectedVersion: expected,
		Name:            asString(in["name"]),
		Description:     asString(in["description"]),
		Graph:           graph,
	})
	if err != nil {
		return nil, err
	}
	return workflowMap(resp.GetWorkflow()), nil
}

func (g *gateway) findings(ctx context.Context, actor *secflowv1.ActorContext, args map[string]any) (any, error) {
	limit := asInt(args["limit"], 100)
	cursor := asString(args["cursor"])
	resp, err := g.runs.ListFindings(ctx, &secflowv1.ListFindingsRequest{
		Actor:       actor,
		RunId:       asString(args["runId"]),
		Category:    findingCategory(asString(args["category"])),
		MinSeverity: severityProto(asString(args["minSeverity"])),
		Page:        pageReq(limit, cursor),
	})
	if err != nil {
		return nil, err
	}
	items := make([]any, 0, len(resp.GetFindings()))
	for _, f := range resp.GetFindings() {
		items = append(items, findingMap(f))
	}
	stats := statsFrom(resp.GetFindings())
	if resp.GetStats() != nil {
		stats = envelopeStatsMap(resp.GetStats())
	}
	res := paginate(items, limit, cursor, resp.GetPageInfo())
	res["stats"] = stats
	return res, nil
}

func (g *gateway) lookupWorkflowNameCached(ctx context.Context, actor *secflowv1.ActorContext, workflowID string, cache map[string]string) string {
	if workflowID == "" {
		return ""
	}
	if name, ok := cache[workflowID]; ok {
		return name
	}
	name := workflowID
	if g.wf != nil {
		wfCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if resp, err := g.wf.GetWorkflow(wfCtx, &secflowv1.GetWorkflowRequest{Actor: actor, WorkflowId: workflowID}); err == nil && resp.GetWorkflow().GetName() != "" {
			name = resp.GetWorkflow().GetName()
		}
	}
	cache[workflowID] = name
	return name
}

func hasSucceededPlugin(run *secflowv1.Run, pluginID string) bool {
	if run == nil {
		return false
	}
	for _, nr := range run.GetNodeRuns() {
		if nr.GetPluginId() == pluginID && nr.GetStatus() == secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED {
			return true
		}
	}
	return false
}

func (g *gateway) decorateRun(ctx context.Context, actor *secflowv1.ActorContext, run *secflowv1.Run) (map[string]any, error) {
	item := runMap(run)
	if run == nil {
		return item, nil
	}
	if run.GetWorkflowName() == "" && run.GetWorkflowId() != "" {
		item["workflowName"] = g.lookupWorkflowNameCached(ctx, actor, run.GetWorkflowId(), map[string]string{})
	}
	if g.runs != nil && run.GetId() != "" {
		if run.GetFindingsStats() == nil {
			if resp, err := g.runs.ListFindings(ctx, &secflowv1.ListFindingsRequest{Actor: actor, RunId: run.GetId()}); err == nil {
				if resp.GetStats() != nil {
					item["findingsStats"] = envelopeStatsMap(resp.GetStats())
				} else {
					item["findingsStats"] = statsFrom(resp.GetFindings())
				}
			}
		}
		if run.GetAiReport() == nil && hasSucceededPlugin(run, "ai.explain") {
			if resp, err := g.runs.GetAIReport(ctx, &secflowv1.GetAIReportRequest{Actor: actor, RunId: run.GetId()}); err == nil && resp.GetReport() != nil {
				item["aiReport"] = aiReportMap(resp.GetReport())
			}
		}
		if run.GetSbom() == nil && hasSucceededPlugin(run, "sbom.generate") {
			if resp, err := g.runs.GetSbom(ctx, &secflowv1.GetSbomRequest{Actor: actor, RunId: run.GetId(), IncludeContent: false}); err == nil && resp.GetSbom() != nil {
				item["sbom"] = sbomMap(resp.GetSbom(), run.GetId())
			}
		}
	}
	return item, nil
}

func runMap(run *secflowv1.Run) map[string]any {
	if run == nil {
		run = &secflowv1.Run{}
	}
	created := stamp(run.GetCreatedAt())
	statusName := first(trimEnum(run.GetStatus().String(), "RUN_STATUS_"), "QUEUED")
	id := run.GetId()

	stats := emptyStats()
	if run.GetFindingsStats() != nil {
		stats = envelopeStatsMap(run.GetFindingsStats())
	}

	var srcRef any
	if run.GetSourceRef() != nil {
		srcRef = sourceRefMap(run.GetSourceRef())
	}
	var gateRes any
	if run.GetGateResult() != nil {
		gateRes = gateResultMap(run.GetGateResult())
	}
	var sbom any
	if run.GetSbom() != nil {
		sbom = sbomMap(run.GetSbom(), id)
	}
	var aiRep any
	if run.GetAiReport() != nil {
		aiRep = aiReportMap(run.GetAiReport())
	}
	nodeRuns := make([]any, 0, len(run.GetNodeRuns()))
	for _, nr := range run.GetNodeRuns() {
		nodeRuns = append(nodeRuns, nodeRunMap(nr))
	}

	return map[string]any{
		"id":                        id,
		"workflowId":                run.GetWorkflowId(),
		"workflowVersion":           run.GetWorkflowVersion(),
		"workflowName":              first(run.GetWorkflowName(), run.GetWorkflowId()),
		"status":                    statusName,
		"trigger":                   triggerMap(run.GetTrigger(), created),
		"sourceRef":                 srcRef,
		"gateResult":                gateRes,
		"findingsStats":             stats,
		"sbom":                      sbom,
		"aiReport":                  aiRep,
		"nodeRuns":                  nodeRuns,
		"parentRunId":               emptyNil(run.GetParentRunId()),
		"rerunFromNodeId":           emptyNil(run.GetRerunFromNodeId()),
		"traceId":                   first(run.GetTraceId(), id),
		"errorMessage":              emptyNil(run.GetErrorMessage()),
		"lastSeqId":                 run.GetLastSeqId(),
		"submissionDownloadUrl":     "/runs/" + id + "/submission.json",
		"markdownReportDownloadUrl": "/runs/" + id + "/report.md",
		"htmlReportDownloadUrl":     "/runs/" + id + "/report.html",
		"createdAt":                 created,
		"startedAt":                 optStamp(run.GetStartedAt()),
		"finishedAt":                optStamp(run.GetFinishedAt()),
	}
}

func triggerMap(t *secflowv1.TriggerMetadata, fallbackAt string) map[string]any {
	if t == nil {
		return map[string]any{
			"type":            "MANUAL",
			"repoUrl":         nil,
			"branch":          nil,
			"commitSha":       nil,
			"prNumber":        nil,
			"gitProvider":     nil,
			"deliveryId":      nil,
			"triggeredBy":     nil,
			"commitStatusUrl": nil,
			"triggeredAt":     fallbackAt,
		}
	}
	at := fallbackAt
	if t.GetTriggeredAt() != nil {
		at = stamp(t.GetTriggeredAt())
	}
	var prNum any
	if t.PrNumber != nil {
		prNum = int(t.GetPrNumber())
	}
	return map[string]any{
		"type":            first(trimEnum(t.GetType().String(), "TRIGGER_TYPE_"), "MANUAL"),
		"repoUrl":         emptyNil(t.GetRepoUrl()),
		"branch":          emptyNil(t.GetBranch()),
		"commitSha":       emptyNil(t.GetCommitSha()),
		"prNumber":        prNum,
		"gitProvider":     emptyNil(trimEnum(t.GetGitProvider().String(), "GIT_PROVIDER_")),
		"deliveryId":      emptyNil(t.GetDeliveryId()),
		"triggeredBy":     emptyNil(t.GetTriggeredBy()),
		"commitStatusUrl": emptyNil(t.GetCommitStatusUrl()),
		"triggeredAt":     at,
	}
}

func sourceRefMap(ref *secflowv1.SourceRef) map[string]any {
	if ref == nil {
		return nil
	}
	return map[string]any{
		"sourceId":  ref.GetSourceId(),
		"sha256":    ref.GetSha256(),
		"repoName":  ref.GetRepoName(),
		"repoUrl":   emptyNil(ref.GetRepoUrl()),
		"gitRef":    emptyNil(ref.GetGitRef()),
		"commitSha": emptyNil(ref.GetCommitSha()),
		"sizeBytes": ref.GetSizeBytes(),
		"fileCount": ref.GetFileCount(),
	}
}

func gateResultMap(gr *secflowv1.GateResult) map[string]any {
	if gr == nil {
		return nil
	}
	return map[string]any{
		"status": first(trimEnum(gr.GetStatus().String(), "GATE_STATUS_"), "PASS"),
		"reason": gr.GetReason(),
		"nodeId": gr.GetNodeId(),
	}
}

func envelopeStatsMap(s *secflowv1.EnvelopeStats) map[string]any {
	if s == nil {
		return nil
	}
	return map[string]any{
		"total":       s.GetTotal(),
		"newCount":    s.GetNewCount(),
		"critical":    s.GetCritical(),
		"high":        s.GetHigh(),
		"medium":      s.GetMedium(),
		"low":         s.GetLow(),
		"secretCount": s.GetSecretCount(),
		"sastCount":   s.GetSastCount(),
		"scaCount":    s.GetScaCount(),
		"maxSeverity": emptyNil(trimEnum(s.GetMaxSeverity().String(), "SEVERITY_")),
	}
}

func nodeRunMap(nr *secflowv1.NodeRun) map[string]any {
	if nr == nil {
		return map[string]any{}
	}
	var preview any
	if len(nr.GetRedactedPreviewJson()) > 0 {
		_ = json.Unmarshal(nr.GetRedactedPreviewJson(), &preview)
	}
	return map[string]any{
		"nodeRunId":         nr.GetNodeRunId(),
		"runId":             nr.GetRunId(),
		"nodeId":            nr.GetNodeId(),
		"pluginId":          nr.GetPluginId(),
		"status":            first(trimEnum(nr.GetStatus().String(), "NODE_RUN_STATUS_"), "PENDING"),
		"attempt":           nr.GetAttempt(),
		"workerId":          emptyNil(nr.GetWorkerId()),
		"activeOutputPorts": stringList(nr.GetActiveOutputPorts()),
		"redactedPreview":   preview,
		"findingsEmitted":   nr.GetFindingsEmitted(),
		"errorMessage":      emptyNil(nr.GetErrorMessage()),
		"durationMs":        nr.GetDurationMs(),
		"startedAt":         optStamp(nr.GetStartedAt()),
		"finishedAt":        optStamp(nr.GetFinishedAt()),
	}
}

func aiReportMap(rep *secflowv1.AIReport) map[string]any {
	if rep == nil {
		return nil
	}
	groups := make([]any, 0, len(rep.GetGroups()))
	for _, grp := range rep.GetGroups() {
		groups = append(groups, map[string]any{
			"title":       grp.GetTitle(),
			"maxSeverity": first(trimEnum(grp.GetMaxSeverity().String(), "SEVERITY_"), "LOW"),
			"findingIds":  stringList(grp.GetFindingIds()),
			"summary":     grp.GetSummary(),
		})
	}
	items := make([]any, 0, len(rep.GetItems()))
	for _, it := range rep.GetItems() {
		items = append(items, map[string]any{
			"findingId":            it.GetFindingId(),
			"priorityRank":         it.GetPriorityRank(),
			"plainLanguageRisk":    it.GetPlainLanguageRisk(),
			"businessImpact":       it.GetBusinessImpact(),
			"remediationSteps":     stringList(it.GetRemediationSteps()),
			"referencedAdvisories": stringList(it.GetReferencedAdvisories()),
			"finding":              groundedFindingMap(it.GetFinding()),
		})
	}
	return map[string]any{
		"quality":                        first(trimEnum(rep.GetQuality().String(), "AI_QUALITY_"), "FALLBACK"),
		"releaseDecision":                first(trimEnum(rep.GetReleaseDecision().String(), "RELEASE_DECISION_"), "WARN"),
		"executiveSummary":               rep.GetExecutiveSummary(),
		"groups":                         groups,
		"items":                          items,
		"modelId":                        rep.GetModelId(),
		"providerMode":                   first(trimEnum(rep.GetProviderMode().String(), "AI_PROVIDER_MODE_"), "TEMPLATE_FALLBACK"),
		"privacyMode":                    first(trimEnum(rep.GetPrivacyMode().String(), "PRIVACY_MODE_"), "REDACTED_SNIPPET"),
		"strippedHallucinatedAdvisories": rep.GetStrippedHallucinatedAdvisories(),
		"cached":                         rep.GetCached(),
		"promptHash":                     rep.GetPromptHash(),
		"tokensIn":                       rep.GetTokensIn(),
		"tokensOut":                      rep.GetTokensOut(),
		"latencyMs":                      rep.GetLatencyMs(),
		"createdAt":                      stamp(rep.GetCreatedAt()),
	}
}

func groundedFindingMap(f *secflowv1.GroundedFindingSummary) map[string]any {
	if f == nil {
		return map[string]any{
			"category":     "SAST",
			"path":         "",
			"line":         nil,
			"endLine":      nil,
			"findingClass": nil,
			"group":        nil,
			"artifact":     nil,
			"version":      nil,
			"advisoryId":   nil,
			"severity":     nil,
		}
	}
	var lineVal, endLineVal any
	if f.Line != nil {
		lineVal = int(f.GetLine())
	}
	if f.EndLine != nil {
		endLineVal = int(f.GetEndLine())
	}
	return map[string]any{
		"category":     first(trimEnum(f.GetCategory().String(), "FINDING_CATEGORY_"), "SAST"),
		"path":         f.GetPath(),
		"line":         lineVal,
		"endLine":      endLineVal,
		"findingClass": emptyNil(f.GetFindingClass()),
		"group":        emptyNil(f.GetGroup()),
		"artifact":     emptyNil(f.GetArtifact()),
		"version":      emptyNil(f.GetVersion()),
		"advisoryId":   emptyNil(f.GetAdvisoryId()),
		"severity":     emptyNil(trimEnum(f.GetSeverity().String(), "SEVERITY_")),
	}
}

func findingMap(f *secflowv1.Finding) map[string]any {
	id := f.GetFindingId()
	if id == "" {
		id = f.GetPath() + ":" + f.GetFindingClass() + ":" + f.GetAdvisoryId()
	}
	var lineVal, endLineVal any
	if f.Line != nil {
		lineVal = int(f.GetLine())
	}
	if f.EndLine != nil {
		endLineVal = int(f.GetEndLine())
	}
	return map[string]any{
		"findingId":       id,
		"fingerprint":     first(f.GetFingerprint(), sha(id)),
		"sourceNodeId":    f.GetSourceNodeId(),
		"pluginId":        f.GetPluginId(),
		"category":        first(trimEnum(f.GetCategory().String(), "FINDING_CATEGORY_"), "SAST"),
		"path":            f.GetPath(),
		"findingClass":    emptyNil(f.GetFindingClass()),
		"line":            lineVal,
		"endLine":         endLineVal,
		"group":           emptyNil(f.GetGroup()),
		"artifact":        emptyNil(f.GetArtifact()),
		"version":         emptyNil(f.GetVersion()),
		"advisoryId":      emptyNil(f.GetAdvisoryId()),
		"severity":        emptyNil(trimEnum(f.GetSeverity().String(), "SEVERITY_")),
		"description":     emptyNil(f.GetDescription()),
		"remediation":     emptyNil(f.GetRemediation()),
		"maskedSnippet":   emptyNil(f.GetMaskedSnippet()),
		"isNewVsBaseline": f.GetIsNewVsBaseline(),
	}
}

func statsFrom(items []*secflowv1.Finding) map[string]any {
	stats := emptyStats()
	stats["total"] = len(items)
	var newCount, critical, high, medium, low, secretCount, sastCount, scaCount int
	maxRank := 0
	maxName := ""
	for _, f := range items {
		if f.GetIsNewVsBaseline() {
			newCount++
		}
		sev := trimEnum(f.GetSeverity().String(), "SEVERITY_")
		switch sev {
		case "CRITICAL":
			critical++
		case "HIGH":
			high++
		case "MEDIUM":
			medium++
		case "LOW":
			low++
		}
		switch trimEnum(f.GetCategory().String(), "FINDING_CATEGORY_") {
		case "SECRET":
			secretCount++
		case "SAST":
			sastCount++
		case "SCA":
			scaCount++
		}
		rank := map[string]int{"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[sev]
		if rank > maxRank {
			maxRank = rank
			maxName = sev
		}
	}
	stats["newCount"] = newCount
	stats["critical"] = critical
	stats["high"] = high
	stats["medium"] = medium
	stats["low"] = low
	stats["secretCount"] = secretCount
	stats["sastCount"] = sastCount
	stats["scaCount"] = scaCount
	if maxName != "" {
		stats["maxSeverity"] = maxName
	}
	return stats
}

func pluginMap(p *secflowv1.RegisteredPlugin) map[string]any {
	m := p.GetManifest()
	if m == nil {
		m = &secflowv1.PluginManifest{}
	}
	ports := func(list []*secflowv1.PortDefinition) []any {
		out := make([]any, 0, len(list))
		for _, port := range list {
			out = append(out, map[string]any{
				"id":          port.GetId(),
				"label":       port.GetLabel(),
				"description": emptyNil(port.GetDescription()),
			})
		}
		return out
	}
	var schema any = map[string]any{}
	if len(m.GetParamsJsonSchema()) > 0 {
		_ = json.Unmarshal(m.GetParamsJsonSchema(), &schema)
	}
	profile := first(trimEnum(m.GetSandboxProfile().String(), "SANDBOX_PROFILE_"), "ORCHESTRATOR_BUILTIN")
	category := first(trimEnum(m.GetCategory().String(), "PLUGIN_CATEGORY_"), "LOGIC")
	statusName := first(trimEnum(p.GetStatus().String(), "PLUGIN_STATUS_"), "ONLINE")
	return map[string]any{
		"pluginId":           m.GetPluginId(),
		"version":            first(m.GetVersion(), "1.0.0"),
		"displayName":        first(m.GetDisplayName(), m.GetPluginId()),
		"description":        m.GetDescription(),
		"category":           category,
		"capabilities":       stringList(m.GetCapabilities()),
		"paramsJsonSchema":   schema,
		"inputPorts":         ports(m.GetInputPorts()),
		"outputPorts":        ports(m.GetOutputPorts()),
		"runtimeLanguage":    m.GetRuntimeLanguage(),
		"sandboxProfile":     profile,
		"isExternal":         m.GetIsExternal(),
		"requiredSecretKeys": stringList(m.GetRequiredSecretKeys()),
		"status":             statusName,
		"activeWorkers":      p.GetActiveWorkers(),
		"queueDepth":         p.GetQueueDepth(),
		"registeredAt":       stamp(p.GetRegisteredAt()),
		"lastSeenAt":         stamp(p.GetLastSeenAt()),
	}
}

func templateMap(tpl *secflowv1.WorkflowTemplate) map[string]any {
	if tpl == nil {
		tpl = &secflowv1.WorkflowTemplate{}
	}
	created := stamp(tpl.GetCreatedAt())
	updated := created
	if tpl.GetUpdatedAt() != nil {
		updated = stamp(tpl.GetUpdatedAt())
	}
	return map[string]any{
		"id":             tpl.GetId(),
		"slug":           tpl.GetSlug(),
		"name":           tpl.GetName(),
		"description":    tpl.GetDescription(),
		"problemSolved":  tpl.GetProblemSolved(),
		"tags":           stringList(tpl.GetTags()),
		"isBuiltin":      tpl.GetIsBuiltin(),
		"sanitizedGraph": graphMap(tpl.GetSanitizedGraph()),
		"authorSubject":  tpl.GetAuthorSubject(),
		"cloneCount":     tpl.GetCloneCount(),
		"createdAt":      created,
		"updatedAt":      updated,
	}
}

func secretMap(sec *secflowv1.SecretMetadata) map[string]any {
	created := stamp(sec.GetCreatedAt())
	updated := created
	if sec.GetUpdatedAt() != nil {
		updated = stamp(sec.GetUpdatedAt())
	}
	kind := first(trimEnum(sec.GetKind().String(), "SECRET_KIND_"), "GENERIC")
	backend := first(trimEnum(sec.GetBackend().String(), "SECRET_STORE_BACKEND_"), "PG_AES")
	return map[string]any{
		"secretRef":     sec.GetSecretRef(),
		"name":          sec.GetName(),
		"kind":          kind,
		"maskedPreview": sec.GetMaskedPreview(),
		"backend":       backend,
		"createdBy":     sec.GetCreatedBy(),
		"createdAt":     created,
		"updatedAt":     updated,
	}
}

func tokenMap(tok *secflowv1.ScopedTokenMetadata) map[string]any {
	return map[string]any{
		"tokenId":     tok.GetTokenId(),
		"name":        tok.GetName(),
		"tokenPrefix": tok.GetTokenPrefix(),
		"scopes":      stringList(tok.GetScopes()),
		"workflowId":  emptyNil(tok.GetWorkflowId()),
		"createdBy":   tok.GetCreatedBy(),
		"expiresAt":   optStamp(tok.GetExpiresAt()),
		"lastUsedAt":  optStamp(tok.GetLastUsedAt()),
		"revokedAt":   optStamp(tok.GetRevokedAt()),
		"createdAt":   stamp(tok.GetCreatedAt()),
	}
}

func catalogMap(c *secflowv1.VulnerabilityCatalog) map[string]any {
	if c == nil {
		c = &secflowv1.VulnerabilityCatalog{}
	}
	return map[string]any{
		"id":            c.GetId(),
		"name":          c.GetName(),
		"ecosystem":     first(c.GetEcosystem(), "Maven"),
		"versionFormat": first(c.GetVersionFormat(), "numeric-dot-separated"),
		"s3Key":         c.GetS3Key(),
		"sha256":        c.GetSha256(),
		"snapshotDate":  c.GetSnapshotDate(),
		"advisoryCount": c.GetAdvisoryCount(),
		"isDefault":     c.GetIsDefault(),
		"uploadedBy":    c.GetUploadedBy(),
		"createdAt":     stamp(c.GetCreatedAt()),
	}
}

func mcpMap(c *secflowv1.MCPConnection) map[string]any {
	cfg := c.GetConfig()
	if cfg == nil {
		cfg = &secflowv1.MCPConnectionConfig{}
	}
	created := stamp(c.GetCreatedAt())
	updated := created
	if c.GetUpdatedAt() != nil {
		updated = stamp(c.GetUpdatedAt())
	}
	return map[string]any{
		"id": c.GetId(),
		"config": map[string]any{
			"name":           cfg.GetName(),
			"description":    cfg.GetDescription(),
			"endpointUrl":    cfg.GetEndpointUrl(),
			"authSecretRef":  emptyNil(cfg.GetAuthSecretRef()),
			"authHeaderName": first(cfg.GetAuthHeaderName(), "Authorization"),
			"allowedTools":   stringList(cfg.GetAllowedTools()),
			"deniedTools":    stringList(cfg.GetDeniedTools()),
		},
		"enabled":   c.GetEnabled(),
		"createdBy": c.GetCreatedBy(),
		"createdAt": created,
		"updatedAt": updated,
	}
}

func mcpConfig(m map[string]any) *secflowv1.MCPConnectionConfig {
	return &secflowv1.MCPConnectionConfig{
		Name:           asString(m["name"]),
		Description:    asString(m["description"]),
		EndpointUrl:    asString(m["endpointUrl"]),
		AuthSecretRef:  asString(m["authSecretRef"]),
		AuthHeaderName: first(asString(m["authHeaderName"]), "Authorization"),
		AllowedTools:   asStringSlice(m["allowedTools"]),
		DeniedTools:    asStringSlice(m["deniedTools"]),
	}
}

func auditMap(e *secflowv1.AIAuditLogEntry) map[string]any {
	return map[string]any{
		"id":                             e.GetId(),
		"runId":                          emptyNil(e.GetRunId()),
		"nodeRunId":                      emptyNil(e.GetNodeRunId()),
		"operation":                      first(trimEnum(e.GetOperation().String(), "AI_OPERATION_"), "AI_EXPLAIN"),
		"modelId":                        e.GetModelId(),
		"providerMode":                   first(trimEnum(e.GetProviderMode().String(), "AI_PROVIDER_MODE_"), "TEMPLATE_FALLBACK"),
		"privacyMode":                    first(trimEnum(e.GetPrivacyMode().String(), "PRIVACY_MODE_"), "REDACTED_SNIPPET"),
		"promptHash":                     e.GetPromptHash(),
		"tokensIn":                       e.GetTokensIn(),
		"tokensOut":                      e.GetTokensOut(),
		"latencyMs":                      e.GetLatencyMs(),
		"quality":                        first(trimEnum(e.GetQuality().String(), "AI_QUALITY_"), "FALLBACK"),
		"strippedHallucinatedAdvisories": e.GetStrippedHallucinatedAdvisories(),
		"cacheHit":                       e.GetCacheHit(),
		"createdAt":                      stamp(e.GetCreatedAt()),
	}
}

func eventMap(ev *secflowv1.RunEvent) map[string]any {
	if ev == nil {
		return nil
	}
	var preview any
	if len(ev.GetRedactedPreviewJson()) > 0 {
		_ = json.Unmarshal(ev.GetRedactedPreviewJson(), &preview)
	}
	var stats any
	if ev.GetStats() != nil {
		stats = envelopeStatsMap(ev.GetStats())
	}
	var gate any
	if ev.GetGateResult() != nil {
		gate = gateResultMap(ev.GetGateResult())
	}
	return map[string]any{
		"seqId":           ev.GetSeqId(),
		"runId":           ev.GetRunId(),
		"eventType":       first(trimEnum(ev.GetEventType().String(), "RUN_EVENT_TYPE_"), "RUN_STARTED"),
		"runStatus":       first(trimEnum(ev.GetRunStatus().String(), "RUN_STATUS_"), "QUEUED"),
		"nodeId":          emptyNil(ev.GetNodeId()),
		"nodeRunId":       emptyNil(ev.GetNodeRunId()),
		"nodeStatus":      emptyNil(trimEnum(ev.GetNodeStatus().String(), "NODE_RUN_STATUS_")),
		"edgeId":          emptyNil(ev.GetEdgeId()),
		"sourceHandle":    emptyNil(ev.GetSourceHandle()),
		"stats":           stats,
		"gateResult":      gate,
		"redactedPreview": preview,
		"message":         emptyNil(ev.GetMessage()),
		"createdAt":       stamp(ev.GetCreatedAt()),
	}
}

func sbomMap(ref *secflowv1.SbomRef, runID string) map[string]any {
	if ref == nil {
		ref = &secflowv1.SbomRef{SpecVersion: "1.6"}
	}
	return map[string]any{
		"digest":             ref.GetDigest(),
		"specVersion":        first(ref.GetSpecVersion(), "1.6"),
		"componentCount":     ref.GetComponentCount(),
		"vulnerabilityCount": ref.GetVulnerabilityCount(),
		"downloadUrl":        "/runs/" + runID + "/sbom.cdx.json",
		"generatedAt":        stamp(ref.GetGeneratedAt()),
	}
}

func templateHasAllTags(have, want []string) bool {
	if len(want) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(have))
	for _, t := range have {
		set[strings.ToLower(strings.TrimSpace(t))] = struct{}{}
	}
	for _, t := range want {
		if _, ok := set[strings.ToLower(strings.TrimSpace(t))]; !ok {
			return false
		}
	}
	return true
}

func runStatusProto(v string) secflowv1.RunStatus {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "QUEUED":
		return secflowv1.RunStatus_RUN_STATUS_QUEUED
	case "RUNNING":
		return secflowv1.RunStatus_RUN_STATUS_RUNNING
	case "SUCCEEDED":
		return secflowv1.RunStatus_RUN_STATUS_SUCCEEDED
	case "FAILED":
		return secflowv1.RunStatus_RUN_STATUS_FAILED
	case "CANCELLED":
		return secflowv1.RunStatus_RUN_STATUS_CANCELLED
	default:
		return secflowv1.RunStatus_RUN_STATUS_UNSPECIFIED
	}
}

func pluginCategoryProto(v string) secflowv1.PluginCategory {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "TRIGGER":
		return secflowv1.PluginCategory_PLUGIN_CATEGORY_TRIGGER
	case "SOURCE":
		return secflowv1.PluginCategory_PLUGIN_CATEGORY_SOURCE
	case "ANALYZER":
		return secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER
	case "LOGIC":
		return secflowv1.PluginCategory_PLUGIN_CATEGORY_LOGIC
	case "AI_REPORT":
		return secflowv1.PluginCategory_PLUGIN_CATEGORY_AI_REPORT
	case "ACTION":
		return secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION
	default:
		return secflowv1.PluginCategory_PLUGIN_CATEGORY_UNSPECIFIED
	}
}

func findingCategory(v string) secflowv1.FindingCategory {
	switch v {
	case "SECRET":
		return secflowv1.FindingCategory_FINDING_CATEGORY_SECRET
	case "SAST":
		return secflowv1.FindingCategory_FINDING_CATEGORY_SAST
	case "SCA":
		return secflowv1.FindingCategory_FINDING_CATEGORY_SCA
	default:
		return secflowv1.FindingCategory_FINDING_CATEGORY_UNSPECIFIED
	}
}

func severityProto(v string) secflowv1.Severity {
	switch v {
	case "LOW":
		return secflowv1.Severity_SEVERITY_LOW
	case "MEDIUM":
		return secflowv1.Severity_SEVERITY_MEDIUM
	case "HIGH":
		return secflowv1.Severity_SEVERITY_HIGH
	case "CRITICAL":
		return secflowv1.Severity_SEVERITY_CRITICAL
	default:
		return secflowv1.Severity_SEVERITY_UNSPECIFIED
	}
}

func secretKindOpt(v string) secflowv1.SecretKind {
	if strings.TrimSpace(v) == "" {
		return secflowv1.SecretKind_SECRET_KIND_UNSPECIFIED
	}
	return secretKind(v)
}

func secretKind(v string) secflowv1.SecretKind {
	switch v {
	case "TELEGRAM_BOT_TOKEN":
		return secflowv1.SecretKind_SECRET_KIND_TELEGRAM_BOT_TOKEN
	case "WEBHOOK_HMAC_SECRET":
		return secflowv1.SecretKind_SECRET_KIND_WEBHOOK_HMAC_SECRET
	case "SMTP_PASSWORD":
		return secflowv1.SecretKind_SECRET_KIND_SMTP_PASSWORD
	case "GIT_TOKEN":
		return secflowv1.SecretKind_SECRET_KIND_GIT_TOKEN
	case "GIT_WEBHOOK_SECRET":
		return secflowv1.SecretKind_SECRET_KIND_GIT_WEBHOOK_SECRET
	case "LLM_API_KEY":
		return secflowv1.SecretKind_SECRET_KIND_LLM_API_KEY
	case "MCP_AUTH_HEADER":
		return secflowv1.SecretKind_SECRET_KIND_MCP_AUTH_HEADER
	default:
		return secflowv1.SecretKind_SECRET_KIND_GENERIC
	}
}

func stringList(items []string) []any {
	out := make([]any, 0, len(items))
	for _, item := range items {
		out = append(out, item)
	}
	return out
}

func first(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func sha(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}
