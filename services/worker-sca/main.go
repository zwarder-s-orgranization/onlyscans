package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/blobstore"
	"github.com/secflow/secflow/services/internal/envutil"
	"github.com/secflow/secflow/services/internal/gradleparser"
	"github.com/secflow/secflow/services/internal/manifest"
	"github.com/secflow/secflow/services/internal/obs"
	"github.com/secflow/secflow/services/internal/protoconv"
	"github.com/secflow/secflow/services/internal/sourcetree"
	"github.com/secflow/secflow/services/internal/workerclient"
)

type scaParams struct {
	CatalogID string `json:"catalogId"`
	LiveOSV   bool   `json:"liveOsv"`
}

type catalogResolver struct {
	orchestratorAddr string
	catalogPath      string
	osvAPIBaseURL    string
	preferLiveOSV    bool
	fetchCatalogMeta func(ctx context.Context, addr, catalogID string) (*secflowv1.VulnerabilityCatalog, error)
	blobConfigured   func() bool
	blobGet          func(ctx context.Context, bucket, key string) ([]byte, error)
	liveQueryOSV     func(ctx context.Context, deps []gradleparser.Dependency, apiBaseURL string) ([]gradleparser.Finding, error)
	fallbackFiles    []string
}

func defaultCatalogResolver(orchAddr, catalogPath string) *catalogResolver {
	osvURL := strings.TrimSpace(os.Getenv("OSV_API_URL"))
	if osvURL == "" {
		osvURL = gradleparser.DefaultOSVAPIBaseURL
	}
	preferLive := strings.EqualFold(strings.TrimSpace(os.Getenv("OSV_LIVE_QUERY")), "1") ||
		strings.EqualFold(strings.TrimSpace(os.Getenv("OSV_LIVE_QUERY")), "true")
	return &catalogResolver{
		orchestratorAddr: orchAddr,
		catalogPath:      catalogPath,
		osvAPIBaseURL:    osvURL,
		preferLiveOSV:    preferLive,
		fetchCatalogMeta: fetchCatalogMetadataGRPC,
		blobConfigured:   blobstore.Configured,
		blobGet:          blobstore.Get,
		liveQueryOSV:     gradleparser.QueryOSVLive,
	}
}

func main() {
	obs.SetupLogger("worker-sca")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	shutdownObs, err := obs.Init(ctx, "worker-sca")
	if err != nil {
		slog.Warn("telemetry init", "err", err)
	} else {
		defer obs.Shutdown(shutdownObs)
	}

	orchAddr := envutil.Get("ORCHESTRATOR_ADDR", "orchestrator:50051")
	m := manifest.One("scan.sca", "SCA", secflowv1.PluginCategory_PLUGIN_CATEGORY_ANALYZER, []string{"analyzer"}, false)
	m.RuntimeLanguage = "go"
	m.SandboxProfile = secflowv1.SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY

	if err := blobstore.WaitReachable(ctx, 15*time.Second); err != nil && ctx.Err() == nil {
		slog.Warn("garage reachability wait timed out", "err", err)
	}

	resolver := defaultCatalogResolver(orchAddr, envutil.Get("CATALOG_PATH", ""))

	if err := workerclient.Run(ctx, orchAddr, envutil.Get("WORKER_INSTANCE_ID", "worker-sca"), []*secflowv1.PluginManifest{m}, func(taskCtx context.Context, task *secflowv1.NodeTask) *secflowv1.NodeResult {
		_ = workerclient.ReportProgress(taskCtx, 10, "resolving source tree")
		root, done := sourcetree.Resolve(taskCtx, task.GetEnvelopeJson())
		defer done()
		if root == "" {
			root = envutil.Get("SOURCE_ROOT", "")
		}
		if err := taskCtx.Err(); err != nil {
			return failResult(task, "TASK_CANCELLED", err.Error())
		}
		params := parseSCAParams(task.GetParamsJson())
		_ = workerclient.ReportProgress(taskCtx, 40, "parsing dependencies and matching vulnerability catalog")
		findings, err := matchWithParams(taskCtx, root, params, resolver)
		if err != nil {
			slog.Error("sca scan failed", "run_id", task.GetRunId(), "node_id", task.GetNodeId(), "err", err)
			return failResult(task, "SCA_SCAN_FAILED", err.Error())
		}
		_ = workerclient.ReportProgress(taskCtx, 100, "sca scan completed")
		return &secflowv1.NodeResult{
			NodeRunId:         task.GetNodeRunId(),
			RunId:             task.GetRunId(),
			NodeId:            task.GetNodeId(),
			PluginId:          task.GetPluginId(),
			Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_SUCCEEDED,
			Findings:          findings,
			ActiveOutputPorts: []string{"default"},
		}
	}); err != nil && ctx.Err() == nil {
		slog.Error("worker", "err", err)
		os.Exit(1)
	}
}

func parseSCAParams(raw []byte) scaParams {
	if len(raw) == 0 {
		return scaParams{}
	}
	var p scaParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return scaParams{}
	}
	p.CatalogID = strings.TrimSpace(p.CatalogID)
	return p
}

func failResult(task *secflowv1.NodeTask, code, msg string) *secflowv1.NodeResult {
	return &secflowv1.NodeResult{
		NodeRunId:         task.GetNodeRunId(),
		RunId:             task.GetRunId(),
		NodeId:            task.GetNodeId(),
		PluginId:          task.GetPluginId(),
		Status:            secflowv1.NodeRunStatus_NODE_RUN_STATUS_FAILED,
		ErrorCode:         code,
		ErrorMessage:      msg,
		ActiveOutputPorts: []string{"default"},
	}
}

func matchWithResolver(ctx context.Context, root, catalogID string, resolver *catalogResolver) ([]*secflowv1.Finding, error) {
	return matchWithParams(ctx, root, scaParams{CatalogID: catalogID}, resolver)
}

func matchWithParams(ctx context.Context, root string, params scaParams, resolver *catalogResolver) ([]*secflowv1.Finding, error) {
	if root == "" {
		return nil, fmt.Errorf("source root is empty")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deps, err := gradleparser.ParseProject(root)
	if err != nil {
		return nil, fmt.Errorf("parse project dependencies: %w", err)
	}

	var matched []gradleparser.Finding
	useLive := (params.LiveOSV || resolver.preferLiveOSV) && params.CatalogID == ""
	if useLive && resolver.liveQueryOSV != nil && !strings.EqualFold(resolver.osvAPIBaseURL, "off") {
		liveFindings, lerr := resolver.liveQueryOSV(ctx, deps, resolver.osvAPIBaseURL)
		if lerr == nil {
			return toProtoSCAFindings(liveFindings), nil
		}
		slog.Warn("live OSV query failed, falling back to stored catalog", "err", lerr)
	}

	advisories, err := resolver.load(ctx, params.CatalogID)
	if err != nil {
		// When no explicit custom catalogId was requested, fall back to live OSV.dev API.
		if (params.CatalogID == "" || params.CatalogID == "default") &&
			resolver.liveQueryOSV != nil &&
			!strings.EqualFold(resolver.osvAPIBaseURL, "off") {
			slog.Warn("stored vulnerability catalog unavailable, querying live OSV API", "err", err)
			liveFindings, lerr := resolver.liveQueryOSV(ctx, deps, resolver.osvAPIBaseURL)
			if lerr == nil {
				return toProtoSCAFindings(liveFindings), nil
			}
			return nil, fmt.Errorf("%w; live OSV fallback failed: %w", err, lerr)
		}
		return nil, err
	}
	matched = gradleparser.Match(deps, advisories)
	return toProtoSCAFindings(matched), nil
}

func toProtoSCAFindings(matched []gradleparser.Finding) []*secflowv1.Finding {
	out := make([]*secflowv1.Finding, 0, len(matched))
	for _, f := range matched {
		// Per submission-report.schema.json, SCA findings MUST NOT set line, endLine, or class.
		out = append(out, &secflowv1.Finding{
			Category:   secflowv1.FindingCategory_FINDING_CATEGORY_SCA,
			Path:       f.Path,
			Group:      f.Group,
			Artifact:   f.Artifact,
			Version:    f.Version,
			AdvisoryId: f.AdvisoryID,
			Severity:   protoconv.SeverityProto(f.Severity),
			PluginId:   "scan.sca",
		})
	}
	return out
}

func (r *catalogResolver) load(ctx context.Context, catalogID string) ([]gradleparser.Advisory, error) {
	id := strings.TrimSpace(catalogID)

	// 1. CatalogService metadata + Garage object when catalogId is set and orchestrator addr is available.
	if id != "" && r.orchestratorAddr != "" && r.fetchCatalogMeta != nil {
		cat, err := r.fetchCatalogMeta(ctx, r.orchestratorAddr, id)
		if err != nil {
			if id != "default" {
				return nil, fmt.Errorf("resolve catalog %q via CatalogService: %w", id, err)
			}
			slog.Warn("CatalogService default lookup failed, falling back to Garage default.json", "err", err)
		} else if cat != nil && cat.GetBucket() != "" && cat.GetS3Key() != "" {
			if r.blobConfigured != nil && r.blobConfigured() && r.blobGet != nil {
				raw, gerr := r.blobGet(ctx, cat.GetBucket(), cat.GetS3Key())
				if gerr != nil {
					return nil, fmt.Errorf("download catalog %s/%s from garage: %w", cat.GetBucket(), cat.GetS3Key(), gerr)
				}
				advisories, perr := gradleparser.LoadCatalogBytes(raw)
				if perr != nil {
					return nil, fmt.Errorf("parse garage catalog %s/%s: %w", cat.GetBucket(), cat.GetS3Key(), perr)
				}
				return advisories, nil
			}
			if id != "default" {
				return nil, fmt.Errorf("catalog %q requires Garage storage but blobstore is not configured", id)
			}
		}
	}

	// 2. Default catalog directly from Garage secflow-catalogs/default.json (seeded from live OSV by garage-init).
	if r.blobConfigured != nil && r.blobConfigured() && r.blobGet != nil {
		raw, err := r.blobGet(ctx, "secflow-catalogs", "default.json")
		if err == nil && len(raw) > 0 {
			advisories, perr := gradleparser.LoadCatalogBytes(raw)
			if perr != nil {
				return nil, fmt.Errorf("parse garage default catalog: %w", perr)
			}
			return advisories, nil
		}
		if err != nil {
			slog.Warn("fetch default catalog from garage failed", "err", err)
		}
	}

	// 3. Explicit local file override (CATALOG_PATH env or custom fallbackFiles).
	if r.catalogPath != "" {
		advisories, err := gradleparser.LoadCatalog(r.catalogPath)
		if err == nil {
			return advisories, nil
		}
		return nil, fmt.Errorf("load catalog %s: %w", r.catalogPath, err)
	}
	for _, candidate := range r.fallbackFiles {
		if candidate == "" {
			continue
		}
		if advisories, err := gradleparser.LoadCatalog(candidate); err == nil {
			return advisories, nil
		}
	}

	// 4. No stored catalog found (caller may fall back to live OSV API).
	return nil, fmt.Errorf("no vulnerability catalog could be loaded (catalogId=%q)", id)
}

func fetchCatalogMetadataGRPC(ctx context.Context, addr, catalogID string) (*secflowv1.VulnerabilityCatalog, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()), obs.GRPCDialOption())
	if err != nil {
		return nil, fmt.Errorf("dial orchestrator %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()

	client := secflowv1.NewCatalogServiceClient(conn)
	if catalogID != "" && catalogID != "default" {
		resp, err := client.GetCatalog(dialCtx, &secflowv1.GetCatalogRequest{CatalogId: catalogID})
		if err != nil {
			return nil, fmt.Errorf("GetCatalog(%q): %w", catalogID, err)
		}
		return resp.GetCatalog(), nil
	}

	if resp, err := client.GetCatalog(dialCtx, &secflowv1.GetCatalogRequest{CatalogId: "default"}); err == nil && resp.GetCatalog() != nil {
		return resp.GetCatalog(), nil
	}
	listResp, err := client.ListCatalogs(dialCtx, &secflowv1.ListCatalogsRequest{})
	if err != nil {
		return nil, fmt.Errorf("ListCatalogs: %w", err)
	}
	for _, c := range listResp.GetCatalogs() {
		if c.GetIsDefault() {
			return c, nil
		}
	}
	return nil, fmt.Errorf("default catalog not registered in CatalogService")
}
