package main

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/urlguard"
)

const defaultCatalogBucket = "secflow-catalogs"

func cloneCatalog(cat *secflowv1.VulnerabilityCatalog) *secflowv1.VulnerabilityCatalog {
	if cat == nil {
		return nil
	}
	cloned, _ := proto.Clone(cat).(*secflowv1.VulnerabilityCatalog)
	return cloned
}

func (s *Server) ListCatalogs(_ context.Context, _ *secflowv1.ListCatalogsRequest) (*secflowv1.ListCatalogsResponse, error) {
	s.catMu.Lock()
	defer s.catMu.Unlock()
	items := make([]*secflowv1.VulnerabilityCatalog, 0, len(s.catalogs))
	for _, c := range s.catalogs {
		items = append(items, cloneCatalog(c))
	}
	return &secflowv1.ListCatalogsResponse{Catalogs: items}, nil
}

func (s *Server) GetCatalog(_ context.Context, req *secflowv1.GetCatalogRequest) (*secflowv1.GetCatalogResponse, error) {
	s.catMu.Lock()
	defer s.catMu.Unlock()
	c, ok := s.catalogs[req.GetCatalogId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "catalog not found")
	}
	return &secflowv1.GetCatalogResponse{Catalog: cloneCatalog(c)}, nil
}

func (s *Server) RegisterCatalog(ctx context.Context, req *secflowv1.RegisterCatalogRequest) (*secflowv1.RegisterCatalogResponse, error) {
	bucket := strings.TrimSpace(req.GetBucket())
	if bucket == "" {
		bucket = defaultCatalogBucket
	}
	cat := &secflowv1.VulnerabilityCatalog{
		Id:            id("cat"),
		Name:          req.GetName(),
		Ecosystem:     "Maven",
		VersionFormat: "numeric-dot-separated",
		Bucket:        bucket,
		S3Key:         req.GetS3Key(),
		Sha256:        req.GetSha256(),
		SnapshotDate:  req.GetSnapshotDate(),
		AdvisoryCount: req.GetAdvisoryCount(),
		IsDefault:     req.GetSetAsDefault(),
		UploadedBy:    subject(req.GetActor()),
		CreatedAt:     timestamppb.Now(),
	}
	s.catMu.Lock()
	if cat.GetIsDefault() {
		for _, existing := range s.catalogs {
			existing.IsDefault = false
		}
	}
	s.catalogs[cat.GetId()] = cat
	snapshot := cloneCatalog(cat)
	s.catMu.Unlock()
	s.persistCatalog(ctx, snapshot)
	return &secflowv1.RegisterCatalogResponse{Catalog: cloneCatalog(snapshot)}, nil
}

func validateMCPConnectionConfig(ctx context.Context, cfg *secflowv1.MCPConnectionConfig) error {
	if cfg == nil {
		return status.Error(codes.InvalidArgument, "missing mcp connection config")
	}
	if urlguard.Denied(cfg.GetName() + " " + cfg.GetDescription() + " " + cfg.GetEndpointUrl()) {
		return status.Error(codes.FailedPrecondition, "DENYLIST_BLOCKED")
	}
	for _, tool := range cfg.GetAllowedTools() {
		if urlguard.Denied(tool) {
			return status.Error(codes.FailedPrecondition, "DENYLIST_BLOCKED")
		}
	}
	if err := urlguard.CheckCtx(ctx, cfg.GetEndpointUrl()); err != nil {
		if errors.Is(err, urlguard.ErrDenylistBlocked) {
			return status.Error(codes.FailedPrecondition, "DENYLIST_BLOCKED")
		}
		return status.Error(codes.PermissionDenied, "ALLOWLIST_DENIED")
	}
	return nil
}

func cloneMCPConnection(conn *secflowv1.MCPConnection) *secflowv1.MCPConnection {
	if conn == nil {
		return nil
	}
	cloned, _ := proto.Clone(conn).(*secflowv1.MCPConnection)
	return cloned
}

func cloneMCPConfig(cfg *secflowv1.MCPConnectionConfig) *secflowv1.MCPConnectionConfig {
	if cfg == nil {
		return nil
	}
	cloned, _ := proto.Clone(cfg).(*secflowv1.MCPConnectionConfig)
	return cloned
}

func (s *Server) RegisterConnection(ctx context.Context, req *secflowv1.RegisterConnectionRequest) (*secflowv1.RegisterConnectionResponse, error) {
	if err := validateMCPConnectionConfig(ctx, req.GetConfig()); err != nil {
		return nil, err
	}
	now := timestamppb.Now()
	conn := &secflowv1.MCPConnection{
		Id:        id("mcp"),
		Config:    cloneMCPConfig(req.GetConfig()),
		Enabled:   true,
		CreatedBy: subject(req.GetActor()),
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.mcpMu.Lock()
	s.mcps[conn.GetId()] = conn
	snapshot := cloneMCPConnection(conn)
	s.mcpMu.Unlock()
	s.persistMCP(ctx, snapshot)
	return &secflowv1.RegisterConnectionResponse{Connection: snapshot}, nil
}

func (s *Server) UpdateConnection(ctx context.Context, req *secflowv1.UpdateConnectionRequest) (*secflowv1.UpdateConnectionResponse, error) {
	if err := validateMCPConnectionConfig(ctx, req.GetConfig()); err != nil {
		return nil, err
	}
	s.mcpMu.Lock()
	conn, ok := s.mcps[req.GetConnectionId()]
	if !ok {
		s.mcpMu.Unlock()
		return nil, status.Error(codes.NotFound, "connection not found")
	}
	conn.Config = cloneMCPConfig(req.GetConfig())
	conn.Enabled = req.GetEnabled()
	conn.UpdatedAt = timestamppb.Now()
	snapshot := cloneMCPConnection(conn)
	s.mcpMu.Unlock()
	s.persistMCP(ctx, snapshot)
	return &secflowv1.UpdateConnectionResponse{Connection: snapshot}, nil
}

func (s *Server) DeleteConnection(ctx context.Context, req *secflowv1.DeleteConnectionRequest) (*secflowv1.DeleteConnectionResponse, error) {
	s.mcpMu.Lock()
	delete(s.mcps, req.GetConnectionId())
	s.mcpMu.Unlock()
	if s.pool != nil {
		dbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if _, err := s.pool.Exec(dbCtx, `DELETE FROM mcp_connections WHERE id = $1`, req.GetConnectionId()); err != nil {
			slog.Warn("delete mcp connection from db", "connection_id", req.GetConnectionId(), "err", err)
		}
	}
	return &secflowv1.DeleteConnectionResponse{Deleted: true}, nil
}

func (s *Server) ListConnections(_ context.Context, _ *secflowv1.ListConnectionsRequest) (*secflowv1.ListConnectionsResponse, error) {
	s.mcpMu.Lock()
	defer s.mcpMu.Unlock()
	items := make([]*secflowv1.MCPConnection, 0, len(s.mcps))
	for _, c := range s.mcps {
		items = append(items, cloneMCPConnection(c))
	}
	return &secflowv1.ListConnectionsResponse{Connections: items}, nil
}

func (s *Server) GetConnection(_ context.Context, req *secflowv1.GetConnectionRequest) (*secflowv1.GetConnectionResponse, error) {
	s.mcpMu.Lock()
	defer s.mcpMu.Unlock()
	c, ok := s.mcps[req.GetConnectionId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "connection not found")
	}
	return &secflowv1.GetConnectionResponse{Connection: cloneMCPConnection(c)}, nil
}

func (s *Server) ListConnectionTools(ctx context.Context, req *secflowv1.ListConnectionToolsRequest) (*secflowv1.ListConnectionToolsResponse, error) {
	s.mcpMu.Lock()
	conn, ok := s.mcps[req.GetConnectionId()]
	snapshot := cloneMCPConnection(conn)
	s.mcpMu.Unlock()
	if !ok {
		return nil, status.Error(codes.NotFound, "connection not found")
	}
	tools, blocked, _, _, err := s.discoverTools(ctx, snapshot)
	if err != nil {
		if _, isStatus := status.FromError(err); isStatus {
			return nil, err
		}
		if errors.Is(err, urlguard.ErrDenylistBlocked) {
			return nil, status.Error(codes.FailedPrecondition, "DENYLIST_BLOCKED")
		}
		if errors.Is(err, urlguard.ErrAllowlistDenied) {
			return nil, status.Error(codes.PermissionDenied, "ALLOWLIST_DENIED")
		}
		slog.WarnContext(ctx, "discover mcp connection tools failed", "connection_id", req.GetConnectionId(), "err", err)
		return nil, status.Error(codes.InvalidArgument, "failed to discover MCP connection tools")
	}
	return &secflowv1.ListConnectionToolsResponse{
		ConnectionId:     req.GetConnectionId(),
		Tools:            tools,
		BlockedToolCount: int32(blocked),
		FetchedAt:        timestamppb.Now(),
	}, nil
}

func (s *Server) TestConnection(ctx context.Context, req *secflowv1.TestConnectionRequest) (*secflowv1.TestConnectionResponse, error) {
	s.mcpMu.Lock()
	conn, ok := s.mcps[req.GetConnectionId()]
	snapshot := cloneMCPConnection(conn)
	s.mcpMu.Unlock()
	if !ok {
		return nil, status.Error(codes.NotFound, "connection not found")
	}
	tools, blocked, srvName, srvVer, err := s.discoverTools(ctx, snapshot)
	if err != nil {
		return &secflowv1.TestConnectionResponse{
			Ok:               false,
			ErrorMessage:     err.Error(),
			BlockedToolCount: int32(blocked),
		}, nil
	}
	if srvName == "" {
		srvName = snapshot.GetConfig().GetName()
	}
	return &secflowv1.TestConnectionResponse{
		Ok:                 true,
		ServerName:         srvName,
		ServerVersion:      srvVer,
		AvailableToolCount: int32(len(tools)),
		BlockedToolCount:   int32(blocked),
	}, nil
}

func (s *Server) persistCatalog(ctx context.Context, cat *secflowv1.VulnerabilityCatalog) {
	if s.pool == nil || cat == nil {
		return
	}
	bucket := strings.TrimSpace(cat.GetBucket())
	if bucket == "" {
		bucket = defaultCatalogBucket
	}
	dbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if cat.GetIsDefault() {
		if _, err := s.pool.Exec(dbCtx, `UPDATE catalogs SET is_default = false WHERE id <> $1`, cat.GetId()); err != nil {
			slog.Warn("clear default catalogs", "catalog_id", cat.GetId(), "err", err)
		}
	}
	if _, err := s.pool.Exec(dbCtx, `
		INSERT INTO catalogs (id, name, sha256, bucket, s3_key, snapshot_date, advisory_count, is_default, uploaded_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			sha256 = EXCLUDED.sha256,
			bucket = EXCLUDED.bucket,
			s3_key = EXCLUDED.s3_key,
			snapshot_date = EXCLUDED.snapshot_date,
			advisory_count = EXCLUDED.advisory_count,
			is_default = EXCLUDED.is_default,
			uploaded_by = EXCLUDED.uploaded_by`,
		cat.GetId(), cat.GetName(), cat.GetSha256(), bucket, cat.GetS3Key(),
		cat.GetSnapshotDate(), cat.GetAdvisoryCount(), cat.GetIsDefault(), cat.GetUploadedBy(),
	); err != nil {
		if strings.Contains(err.Error(), "snapshot_date") || strings.Contains(err.Error(), "uploaded_by") || strings.Contains(err.Error(), "advisory_count") {
			if _, fbErr := s.pool.Exec(dbCtx, `
				INSERT INTO catalogs (id, name, sha256, bucket, s3_key, is_default)
				VALUES ($1,$2,$3,$4,$5,$6)
				ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, sha256 = EXCLUDED.sha256, bucket = EXCLUDED.bucket, s3_key = EXCLUDED.s3_key, is_default = EXCLUDED.is_default`,
				cat.GetId(), cat.GetName(), cat.GetSha256(), bucket, cat.GetS3Key(), cat.GetIsDefault(),
			); fbErr != nil {
				slog.Warn("persist catalog", "catalog_id", cat.GetId(), "err", fbErr)
			}
			return
		}
		slog.Warn("persist catalog", "catalog_id", cat.GetId(), "err", err)
	}
}

func (s *Server) persistMCP(ctx context.Context, conn *secflowv1.MCPConnection) {
	if s.pool == nil || conn == nil {
		return
	}
	raw, err := protojson.Marshal(conn)
	if err != nil {
		slog.Warn("marshal mcp connection", "connection_id", conn.GetId(), "err", err)
		return
	}
	dbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if _, err := s.pool.Exec(dbCtx, `INSERT INTO mcp_connections (id, config_json, enabled) VALUES ($1,$2::jsonb,$3) ON CONFLICT (id) DO UPDATE SET config_json = EXCLUDED.config_json, enabled = EXCLUDED.enabled`, conn.GetId(), string(raw), conn.GetEnabled()); err != nil {
		slog.Warn("persist mcp connection", "connection_id", conn.GetId(), "err", err)
	}
}

func (s *Server) loadCatalogs(ctx context.Context) {
	if s.pool == nil {
		return
	}
	fullCols := true
	rows, err := s.pool.Query(ctx, `SELECT id, name, sha256, COALESCE(NULLIF(bucket, ''), 'secflow-catalogs'), s3_key, COALESCE(snapshot_date, ''), COALESCE(advisory_count, 0), is_default, COALESCE(uploaded_by, ''), created_at FROM catalogs`)
	if err != nil && (strings.Contains(err.Error(), "snapshot_date") || strings.Contains(err.Error(), "advisory_count") || strings.Contains(err.Error(), "uploaded_by")) {
		fullCols = false
		rows, err = s.pool.Query(ctx, `SELECT id, name, sha256, COALESCE(NULLIF(bucket, ''), 'secflow-catalogs'), s3_key, is_default, created_at FROM catalogs`)
	}
	if err != nil {
		slog.Warn("load catalogs", "err", err)
		return
	}
	defer rows.Close()
	loaded := map[string]*secflowv1.VulnerabilityCatalog{}
	for rows.Next() {
		cat := &secflowv1.VulnerabilityCatalog{
			Ecosystem:     "Maven",
			VersionFormat: "numeric-dot-separated",
		}
		var createdAt time.Time
		var scanErr error
		if fullCols {
			scanErr = rows.Scan(&cat.Id, &cat.Name, &cat.Sha256, &cat.Bucket, &cat.S3Key, &cat.SnapshotDate, &cat.AdvisoryCount, &cat.IsDefault, &cat.UploadedBy, &createdAt)
		} else {
			scanErr = rows.Scan(&cat.Id, &cat.Name, &cat.Sha256, &cat.Bucket, &cat.S3Key, &cat.IsDefault, &createdAt)
		}
		if scanErr != nil {
			slog.Warn("scan catalog", "err", scanErr)
			continue
		}
		if strings.TrimSpace(cat.Bucket) == "" {
			cat.Bucket = defaultCatalogBucket
		}
		if !createdAt.IsZero() {
			cat.CreatedAt = timestamppb.New(createdAt)
		}
		loaded[cat.GetId()] = cat
	}
	if err := rows.Err(); err != nil {
		slog.Warn("iterate catalogs", "err", err)
	}
	s.catMu.Lock()
	for catID, cat := range loaded {
		s.catalogs[catID] = cat
	}
	s.catMu.Unlock()
}

func (s *Server) loadMCPs(ctx context.Context) {
	if s.pool == nil {
		return
	}
	rows, err := s.pool.Query(ctx, `SELECT config_json FROM mcp_connections`)
	if err != nil {
		slog.Warn("load mcp connections", "err", err)
		return
	}
	defer rows.Close()
	loaded := map[string]*secflowv1.MCPConnection{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			slog.Warn("scan mcp connection", "err", err)
			continue
		}
		conn := &secflowv1.MCPConnection{}
		if err := protojson.Unmarshal(raw, conn); err == nil && conn.GetId() != "" {
			loaded[conn.GetId()] = conn
		}
	}
	if err := rows.Err(); err != nil {
		slog.Warn("iterate mcp connections", "err", err)
	}
	s.mcpMu.Lock()
	for connID, conn := range loaded {
		s.mcps[connID] = conn
	}
	s.mcpMu.Unlock()
}

func (s *Server) loadState(ctx context.Context) {
	s.loadWorkflows(ctx)
	s.loadTemplates(ctx)
	s.loadSecrets(ctx)
	s.loadCatalogs(ctx)
	s.loadMCPs(ctx)
	s.loadRuns(ctx)
	s.loadTokens(ctx)
	s.loadPluginInstallations(ctx)
	s.loadPlugins(ctx)
	s.loadSavedNodes(ctx)
}
