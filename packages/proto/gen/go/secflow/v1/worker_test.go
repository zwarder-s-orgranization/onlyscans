package secflowv1

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestWorkerDescriptorAndServiceDescParity(t *testing.T) {
	t.Parallel()

	tsFDP := protodesc.ToFileDescriptorProto(timestamppb.File_google_protobuf_timestamp_proto)
	commonFDP := protodesc.ToFileDescriptorProto(File_secflow_v1_common_proto)
	workerFDP := protodesc.ToFileDescriptorProto(File_secflow_v1_worker_proto)

	files, err := protodesc.NewFiles(&descriptorpb.FileDescriptorSet{
		File: []*descriptorpb.FileDescriptorProto{tsFDP, commonFDP, workerFDP},
	})
	if err != nil {
		t.Fatalf("protodesc.NewFiles failed: %v", err)
	}
	fd, err := files.FindFileByPath("secflow/v1/worker.proto")
	if err != nil {
		t.Fatalf("FindFileByPath: %v", err)
	}

	svc := fd.Services().ByName("PluginRegistryService")
	if svc == nil {
		t.Fatal("PluginRegistryService missing from descriptor")
	}

	wantMethods := []string{
		"ListPlugins",
		"GetPlugin",
		"WatchPlugins",
		"ListPluginInstallations",
		"GetPluginInstallation",
		"ListPluginPresets",
		"InstallPlugin",
		"ApprovePluginInstallation",
		"UpdatePluginInstallation",
		"SetPluginInstallationEnabled",
		"DeletePluginInstallation",
		"WatchPluginInstallations",
		"TestDeclarativePlugin",
		"ListDeclarativeSpecs",
		"ListSavedNodes",
		"SaveNode",
		"UpdateSavedNode",
		"DeleteSavedNode",
	}
	for _, name := range wantMethods {
		if svc.Methods().ByName(protoreflect.Name(name)) == nil {
			t.Fatalf("PluginRegistryService method %q missing from descriptor", name)
		}
	}

	if got := len(PluginRegistryService_ServiceDesc.Methods); got != 16 {
		t.Fatalf("ServiceDesc.Methods count = %d, want 16", got)
	}
	if got := len(PluginRegistryService_ServiceDesc.Streams); got != 2 {
		t.Fatalf("ServiceDesc.Streams count = %d, want 2", got)
	}
	if PluginRegistryService_ServiceDesc.Streams[0].StreamName != "WatchPlugins" {
		t.Fatalf("Streams[0] = %q, want WatchPlugins", PluginRegistryService_ServiceDesc.Streams[0].StreamName)
	}
	if PluginRegistryService_ServiceDesc.Streams[1].StreamName != "WatchPluginInstallations" {
		t.Fatalf("Streams[1] = %q, want WatchPluginInstallations", PluginRegistryService_ServiceDesc.Streams[1].StreamName)
	}
}

func TestWorkerProtoAndProtoJSONRoundTrips(t *testing.T) {
	t.Parallel()

	now := timestamppb.Now()
	inst := &PluginInstallation{
		Id:                     "inst_1",
		Name:                   "spring-config",
		SourceMode:             PluginSourceMode_PLUGIN_SOURCE_MODE_PRESET,
		PresetId:               "spring-config-hardening",
		ImageRef:               "secflow/demo-spring-config:1.0.0",
		SandboxProfile:         SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
		EgressAllowlist:        []string{},
		ResourceLimits:         &PluginResourceLimits{CpuRequest: "100m", CpuLimit: "500m", MemoryRequest: "64Mi", MemoryLimit: "256Mi", MinReplicas: 1, MaxReplicas: 2},
		DesiredReplicas:        1,
		Status:                 PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ACTIVE,
		AutoApprove:            true,
		ApprovedManifestDigest: "sha256:abc",
		Manifests: []*PluginManifest{{
			PluginId:       "scan.spring-config",
			Version:        "1.0.0",
			DisplayName:    "Spring Config Hardening",
			Category:       PluginCategory_PLUGIN_CATEGORY_ANALYZER,
			SandboxProfile: SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
			IsExternal:     true,
		}},
		PluginIds: []string{"scan.spring-config"},
		RuntimeDiagnostics: &PluginRuntimeDiagnostics{
			Phase:           "Ready",
			DesiredReplicas: 1,
			ReadyReplicas:   1,
			Message:         "running",
			UpdatedAt:       now,
		},
		CreatedBy:  "owner@secflow.local",
		ApprovedBy: "owner@secflow.local",
		CreatedAt:  now,
		UpdatedAt:  now,
		ApprovedAt: now,
	}

	msgs := []proto.Message{
		&RegisteredPlugin{
			Manifest:        inst.GetManifests()[0],
			Status:          PluginStatus_PLUGIN_STATUS_ONLINE,
			ActiveWorkers:   1,
			InstallationId:  "inst_1",
			Enabled:         true,
			ApprovalPending: false,
			RegisteredAt:    now,
			LastSeenAt:      now,
		},
		inst,
		&PluginPreset{
			Id:                   "spring-config-hardening",
			Name:                 "Spring Config Hardening",
			ImageRef:             "secflow/demo-spring-config:1.0.0",
			Category:             PluginCategory_PLUGIN_CATEGORY_ANALYZER,
			SandboxProfile:       SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
			PluginIds:            []string{"scan.spring-config"},
			OutputPorts:          []*PortDefinition{{Id: "default", Label: "default"}},
			AutoApproveSupported: true,
		},
		&InstallPluginRequest{
			Name:            "spring-config",
			SourceMode:      PluginSourceMode_PLUGIN_SOURCE_MODE_PRESET,
			PresetId:        "spring-config-hardening",
			SandboxProfile:  SandboxProfile_SANDBOX_PROFILE_INTERNAL_ONLY,
			DesiredReplicas: 1,
			AutoApprove:     true,
		},
		&InstallPluginResponse{
			Installation:         inst,
			PlaintextPluginToken: "sf_plg_secret",
		},
		&PluginInstallationEvent{
			EventType:    PluginInstallationEventType_PLUGIN_INSTALLATION_EVENT_TYPE_CREATED,
			Installation: inst,
			OccurredAt:   now,
		},
	}

	for _, msg := range msgs {
		wire, err := proto.Marshal(msg)
		if err != nil {
			t.Fatalf("proto.Marshal(%T): %v", msg, err)
		}
		gotWire := msg.ProtoReflect().New().Interface()
		if err := proto.Unmarshal(wire, gotWire); err != nil {
			t.Fatalf("proto.Unmarshal(%T): %v", msg, err)
		}
		if !proto.Equal(msg, gotWire) {
			t.Fatalf("proto roundtrip mismatch for %T", msg)
		}

		j, err := protojson.Marshal(msg)
		if err != nil {
			t.Fatalf("protojson.Marshal(%T): %v", msg, err)
		}
		gotJSON := msg.ProtoReflect().New().Interface()
		if err := protojson.Unmarshal(j, gotJSON); err != nil {
			t.Fatalf("protojson.Unmarshal(%T): %v", msg, err)
		}
		if !proto.Equal(msg, gotJSON) {
			t.Fatalf("protojson roundtrip mismatch for %T", msg)
		}
	}
}

type bufconnRegistryTestServer struct {
	UnimplementedPluginRegistryServiceServer
	inst *PluginInstallation
}

func (s *bufconnRegistryTestServer) InstallPlugin(_ context.Context, req *InstallPluginRequest) (*InstallPluginResponse, error) {
	return &InstallPluginResponse{
		Installation: &PluginInstallation{
			Id:         "inst_test",
			Name:       req.GetName(),
			SourceMode: req.GetSourceMode(),
			Status:     PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ACTIVE,
		},
		PlaintextPluginToken: "sf_plg_testtoken",
	}, nil
}

func (s *bufconnRegistryTestServer) ListPluginInstallations(_ context.Context, _ *ListPluginInstallationsRequest) (*ListPluginInstallationsResponse, error) {
	return &ListPluginInstallationsResponse{Installations: []*PluginInstallation{s.inst}}, nil
}

func (s *bufconnRegistryTestServer) WatchPluginInstallations(_ *WatchPluginInstallationsRequest, stream PluginRegistryService_WatchPluginInstallationsServer) error {
	return stream.Send(&WatchPluginInstallationsResponse{
		Event: &PluginInstallationEvent{
			EventType:    PluginInstallationEventType_PLUGIN_INSTALLATION_EVENT_TYPE_CREATED,
			Installation: s.inst,
			OccurredAt:   timestamppb.Now(),
		},
	})
}

func TestWorkerGRPCBufconnUnaryAndStream(t *testing.T) {
	t.Parallel()

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	RegisterPluginRegistryServiceServer(gs, &bufconnRegistryTestServer{
		inst: &PluginInstallation{
			Id:     "inst_test",
			Name:   "spring-config",
			Status: PluginInstallationStatus_PLUGIN_INSTALLATION_STATUS_ACTIVE,
		},
	})
	go func() {
		_ = gs.Serve(lis)
	}()
	defer func() {
		gs.Stop()
		_ = lis.Close()
	}()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer func() { _ = conn.Close() }()

	cli := NewPluginRegistryServiceClient(conn)
	instResp, err := cli.InstallPlugin(t.Context(), &InstallPluginRequest{
		Name:       "spring-config",
		SourceMode: PluginSourceMode_PLUGIN_SOURCE_MODE_EXTERNAL_PULL,
	})
	if err != nil {
		t.Fatalf("InstallPlugin: %v", err)
	}
	if instResp.GetInstallation().GetId() != "inst_test" || instResp.GetPlaintextPluginToken() != "sf_plg_testtoken" {
		t.Fatalf("unexpected InstallPluginResponse: %+v", instResp)
	}

	listResp, err := cli.ListPluginInstallations(t.Context(), &ListPluginInstallationsRequest{})
	if err != nil || len(listResp.GetInstallations()) != 1 {
		t.Fatalf("ListPluginInstallations: resp=%+v err=%v", listResp, err)
	}

	stream, err := cli.WatchPluginInstallations(t.Context(), &WatchPluginInstallationsRequest{})
	if err != nil {
		t.Fatalf("WatchPluginInstallations: %v", err)
	}
	evResp, err := stream.Recv()
	if err != nil {
		t.Fatalf("WatchPluginInstallations.Recv: %v", err)
	}
	if evResp.GetEvent().GetEventType() != PluginInstallationEventType_PLUGIN_INSTALLATION_EVENT_TYPE_CREATED {
		t.Fatalf("unexpected WatchPluginInstallations event: %+v", evResp)
	}
}
