package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/envutil"
	"github.com/secflow/secflow/services/internal/httpserver"
	"github.com/secflow/secflow/services/internal/manifest"
	"github.com/secflow/secflow/services/internal/obs"
	"github.com/secflow/secflow/services/internal/paramschema"
	"github.com/secflow/secflow/services/internal/secretclient"
	"github.com/secflow/secflow/services/internal/urlguard"
	"github.com/secflow/secflow/services/internal/workerclient"
)

var resolveCommitSecretFn = secretclient.ResolveCommitSecret

func main() {
	obs.SetupLogger("notify-service")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	shutdownObs, err := obs.Init(ctx, "notify-service")
	if err != nil {
		slog.Warn("telemetry init", "err", err)
	} else {
		defer obs.Shutdown(shutdownObs)
	}
	lis, err := net.Listen("tcp", envutil.Get("GRPC_ADDR", ":50054"))
	if err != nil {
		slog.Error("listen", "err", err)
		os.Exit(1)
	}
	gs := grpc.NewServer(obs.GRPCServerOptions("notify-service")...)
	secflowv1.RegisterNotifyServiceServer(gs, &notify{})
	httpserver.Start(ctx, envutil.Get("HTTP_ADDR", ":8087"))
	go func() {
		if err := gs.Serve(lis); err != nil {
			slog.Error("grpc", "err", err)
			os.Exit(1)
		}
	}()
	go func() {
		manifests := notifyManifests()
		workerID := envutil.Get("WORKER_INSTANCE_ID", "")
		if workerID == "" {
			if host, hErr := os.Hostname(); hErr == nil && host != "" {
				workerID = "notify-service-" + host
			} else {
				workerID = "notify-service"
			}
		}
		if err := workerclient.Run(ctx, envutil.Get("ORCHESTRATOR_ADDR", "orchestrator:50051"), workerID, manifests, deliver); err != nil && ctx.Err() == nil {
			slog.Error("notify worker stopped", "err", err)
		}
	}()
	<-ctx.Done()
	gs.GracefulStop()
}

func notifyManifests() []*secflowv1.PluginManifest {
	defs := []struct {
		id              string
		display         string
		description     string
		requiredSecrets []string
	}{
		{
			id:              "notify.telegram",
			display:         "Telegram Notification",
			description:     "Sends MarkdownV2 security report notifications to Telegram.",
			requiredSecrets: []string{"botToken"},
		},
		{
			id:          "notify.webhook",
			display:     "Signed Webhook",
			description: "Delivers HMAC-signed JSON notifications to an allowlisted webhook URL.",
		},
		{
			id:              "notify.smtp",
			display:         "Email (SMTP)",
			description:     "Sends email notifications over SMTP.",
			requiredSecrets: []string{"smtpPassword"},
		},
	}
	out := make([]*secflowv1.PluginManifest, 0, len(defs))
	for _, d := range defs {
		if spec, ok := manifest.LookupBuiltin(d.id); ok {
			rawSchema, _ := paramschema.RawDef(d.id)
			out = append(out, spec.ToProto(string(rawSchema)))
			continue
		}
		m := manifest.One(d.id, d.display, secflowv1.PluginCategory_PLUGIN_CATEGORY_ACTION, []string{"notify"}, false)
		m.Description = d.description
		m.SandboxProfile = secflowv1.SandboxProfile_SANDBOX_PROFILE_EGRESS_EXTERNAL
		m.RequiredSecretKeys = d.requiredSecrets
		out = append(out, m)
	}
	return out
}

type notify struct {
	secflowv1.UnimplementedNotifyServiceServer
}

func (notify) SendCommitStatus(ctx context.Context, req *secflowv1.SendCommitStatusRequest) (*secflowv1.SendCommitStatusResponse, error) {
	target := strings.TrimSpace(req.GetCommitStatusUrl())
	if target == "" {
		return &secflowv1.SendCommitStatusResponse{
			Delivered:    false,
			ErrorMessage: "commit status url is required",
			SentAt:       timestamppb.Now(),
		}, nil
	}
	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if err := validateCommitStatusURL(reqCtx, target); err != nil {
		return &secflowv1.SendCommitStatusResponse{
			Delivered:    false,
			ErrorMessage: err.Error(),
			SentAt:       timestamppb.Now(),
		}, nil
	}

	isGitLab := req.GetGitProvider() == secflowv1.GitProvider_GIT_PROVIDER_GITLAB || strings.Contains(target, "/api/v4/projects/")
	state := commitStatusStateString(req.GetState(), isGitLab)
	statusCtx := strings.TrimSpace(req.GetContext())
	if statusCtx == "" {
		statusCtx = "secflow/security-gate"
	}
	payload := map[string]string{
		"state":       state,
		"context":     statusCtx,
		"description": req.GetDescription(),
	}
	if targetURL := strings.TrimSpace(req.GetTargetUrl()); targetURL != "" {
		payload["target_url"] = targetURL
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return &secflowv1.SendCommitStatusResponse{Delivered: false, ErrorMessage: "marshal payload", SentAt: timestamppb.Now()}, nil
	}
	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return &secflowv1.SendCommitStatusResponse{Delivered: false, ErrorMessage: "bad url", SentAt: timestamppb.Now()}, nil
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if !isGitLab {
		httpReq.Header.Set("Accept", "application/vnd.github+json")
	}
	if ref := strings.TrimSpace(req.GetGitStatusSecretRef()); ref != "" {
		token, err := resolveCommitSecretFn(reqCtx, envutil.Get("ORCHESTRATOR_ADDR", "orchestrator:50051"), envutil.Get("SERVICE_TOKEN", "dev-service-token"), req, ref)
		if err != nil || strings.TrimSpace(token) == "" {
			return &secflowv1.SendCommitStatusResponse{
				Delivered:    false,
				ErrorMessage: "SECRET_SCOPE_DENIED: commit status secret unavailable",
				SentAt:       timestamppb.Now(),
			}, nil
		}
		if isGitLab {
			httpReq.Header.Set("PRIVATE-TOKEN", token)
		} else {
			httpReq.Header.Set("Authorization", "Bearer "+token)
		}
	}
	resp, err := notifyHTTP.Do(httpReq)
	if err != nil {
		return &secflowv1.SendCommitStatusResponse{Delivered: false, ErrorMessage: "delivery failed", SentAt: timestamppb.Now()}, nil
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDiscardBodyBytes))
	delivered := resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices
	errMsg := ""
	if !delivered {
		errMsg = fmt.Sprintf("commit status upstream returned HTTP %d", resp.StatusCode)
	}
	return &secflowv1.SendCommitStatusResponse{
		Delivered:    delivered,
		HttpStatus:   int32(resp.StatusCode),
		ErrorMessage: errMsg,
		SentAt:       timestamppb.Now(),
	}, nil
}

func validateCommitStatusURL(ctx context.Context, raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return urlguard.ErrAllowlistDenied
	}
	if urlguard.Denied(raw) {
		return urlguard.ErrDenylistBlocked
	}
	allowInsecure := os.Getenv("NOTIFY_ALLOW_INSECURE_COMMIT_STATUS") == "1" || os.Getenv("MCP_ALLOW_PRIVATE") == "1"
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && (!allowInsecure || scheme != "http") {
		return urlguard.ErrAllowlistDenied
	}
	if !commitStatusHostAllowed(u.Hostname()) {
		return urlguard.ErrAllowlistDenied
	}
	return urlguard.CheckCtx(ctx, raw)
}

func commitStatusHostAllowed(rawHost string) bool {
	host := strings.ToLower(strings.TrimSpace(rawHost))
	if host == "" {
		return false
	}
	if host == "api.github.com" || host == "gitlab.com" {
		return true
	}
	if os.Getenv("MCP_ALLOW_PRIVATE") == "1" {
		if host == "localhost" {
			return true
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return true
		}
	}
	for _, entry := range parseAllowlistHosts(os.Getenv("COMMIT_STATUS_ALLOWLIST")) {
		if host == entry {
			return true
		}
	}
	for _, entry := range parseAllowlistHosts(os.Getenv("REPO_ALLOWLIST")) {
		if host == entry || host == "api."+entry {
			return true
		}
	}
	return false
}

func parseAllowlistHosts(csv string) []string {
	if strings.TrimSpace(csv) == "" {
		return nil
	}
	var hosts []string
	for _, raw := range strings.Split(csv, ",") {
		entry := strings.TrimSpace(strings.ToLower(raw))
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "://") {
			entry = "https://" + entry
		}
		u, err := url.Parse(entry)
		if err != nil {
			continue
		}
		h := strings.ToLower(strings.TrimSpace(u.Hostname()))
		if h != "" && !strings.Contains(h, "*") {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

func commitStatusStateString(state secflowv1.CommitStatusState, isGitLab bool) string {
	switch state {
	case secflowv1.CommitStatusState_COMMIT_STATUS_STATE_PENDING:
		return "pending"
	case secflowv1.CommitStatusState_COMMIT_STATUS_STATE_SUCCESS:
		return "success"
	case secflowv1.CommitStatusState_COMMIT_STATUS_STATE_FAILURE:
		if isGitLab {
			return "failed"
		}
		return "failure"
	case secflowv1.CommitStatusState_COMMIT_STATUS_STATE_ERROR:
		if isGitLab {
			return "failed"
		}
		return "error"
	default:
		return "pending"
	}
}
