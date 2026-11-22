// Command genworker regenerates gen/go/secflow/v1/worker.pb.go and
// gen/go/secflow/v1/worker_grpc.pb.go without requiring protoc or buf.
package main

import (
	"bytes"
	"context"
	"fmt"
	"go/format"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/pluginpb"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
)

const (
	protoPkgPrefix = ".secflow.v1."
	timestampType  = ".google.protobuf.Timestamp"
	workerOutRel   = "gen/go/secflow/v1/worker.pb.go"
	grpcOutRel     = "gen/go/secflow/v1/worker_grpc.pb.go"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "genworker: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	tsFDP := protodesc.ToFileDescriptorProto(timestamppb.File_google_protobuf_timestamp_proto)
	commonFDP := protodesc.ToFileDescriptorProto(secflowv1.File_secflow_v1_common_proto)
	workerFDP, ok := proto.Clone(protodesc.ToFileDescriptorProto(secflowv1.File_secflow_v1_worker_proto)).(*descriptorpb.FileDescriptorProto)
	if !ok || workerFDP == nil {
		return fmt.Errorf("clone worker file descriptor proto")
	}

	applyWorkerUpdates(workerFDP)

	fds := &descriptorpb.FileDescriptorSet{
		File: []*descriptorpb.FileDescriptorProto{tsFDP, commonFDP, workerFDP},
	}
	if _, err := protodesc.NewFiles(fds); err != nil {
		return fmt.Errorf("validate file descriptors: %w", err)
	}

	reqBytes, err := proto.Marshal(&pluginpb.CodeGeneratorRequest{
		FileToGenerate: []string{"secflow/v1/worker.proto"},
		Parameter:      proto.String("paths=source_relative"),
		ProtoFile:      fds.GetFile(),
	})
	if err != nil {
		return fmt.Errorf("marshal CodeGeneratorRequest: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "run", "google.golang.org/protobuf/cmd/protoc-gen-go")
	cmd.Stdin = bytes.NewReader(reqBytes)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run protoc-gen-go: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}

	var resp pluginpb.CodeGeneratorResponse
	if err := proto.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return fmt.Errorf("unmarshal CodeGeneratorResponse: %w", err)
	}
	if resp.GetError() != "" {
		return fmt.Errorf("protoc-gen-go error: %s", resp.GetError())
	}

	if err := writeGeneratedFiles(resp.GetFile(), workerFDP); err != nil {
		return err
	}
	return nil
}

func writeGeneratedFiles(files []*pluginpb.CodeGeneratorResponse_File, workerFDP *descriptorpb.FileDescriptorProto) error {
	var workerPBContent string
	for _, f := range files {
		if f.GetName() == "secflow/v1/worker.pb.go" {
			workerPBContent = f.GetContent()
			break
		}
	}
	if workerPBContent == "" {
		return fmt.Errorf("protoc-gen-go did not emit secflow/v1/worker.pb.go")
	}
	formattedPB, err := format.Source([]byte(workerPBContent))
	if err != nil {
		return fmt.Errorf("format worker.pb.go: %w", err)
	}
	if err := os.WriteFile(filepath.FromSlash(workerOutRel), formattedPB, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", workerOutRel, err)
	}

	grpcSrc, err := renderWorkerGRPC(workerFDP)
	if err != nil {
		return fmt.Errorf("render worker_grpc.pb.go: %w", err)
	}
	formattedGRPC, err := format.Source(grpcSrc)
	if err != nil {
		return fmt.Errorf("format worker_grpc.pb.go: %w", err)
	}
	if err := os.WriteFile(filepath.FromSlash(grpcOutRel), formattedGRPC, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", grpcOutRel, err)
	}
	return nil
}

func applyWorkerUpdates(fdp *descriptorpb.FileDescriptorProto) {
	ensureEnumValues(fdp, "ManifestRejectionCode",
		enumVal("MANIFEST_REJECTION_CODE_UNAUTHENTICATED", 5),
		enumVal("MANIFEST_REJECTION_CODE_BUILTIN_OVERRIDE_FORBIDDEN", 6),
		enumVal("MANIFEST_REJECTION_CODE_UNSUPPORTED_CATEGORY", 7),
		enumVal("MANIFEST_REJECTION_CODE_SANDBOX_PROFILE_MISMATCH", 8),
	)

	ensureMessageFields(fdp, "RegisteredPlugin",
		strField("installation_id", "installationId", 7),
		boolField("enabled", "enabled", 8),
		boolField("approval_pending", "approvalPending", 9),
	)
	ensureMessageFields(fdp, "ListPluginsRequest",
		boolField("include_disabled", "includeDisabled", 4),
	)

	ensureEnums(fdp,
		newEnum("PluginInstallationStatus",
			enumVal("PLUGIN_INSTALLATION_STATUS_UNSPECIFIED", 0),
			enumVal("PLUGIN_INSTALLATION_STATUS_PROVISIONING", 1),
			enumVal("PLUGIN_INSTALLATION_STATUS_PENDING_APPROVAL", 2),
			enumVal("PLUGIN_INSTALLATION_STATUS_ACTIVE", 3),
			enumVal("PLUGIN_INSTALLATION_STATUS_DISABLED", 4),
			enumVal("PLUGIN_INSTALLATION_STATUS_ERROR", 5),
			enumVal("PLUGIN_INSTALLATION_STATUS_DELETING", 6),
			enumVal("PLUGIN_INSTALLATION_STATUS_DRAFT", 7),
		),
		newEnum("PluginSourceMode",
			enumVal("PLUGIN_SOURCE_MODE_UNSPECIFIED", 0),
			enumVal("PLUGIN_SOURCE_MODE_PRESET", 1),
			enumVal("PLUGIN_SOURCE_MODE_OCI_IMAGE", 2),
			enumVal("PLUGIN_SOURCE_MODE_EXTERNAL_PULL", 3),
			enumVal("PLUGIN_SOURCE_MODE_DECLARATIVE", 4),
		),
		newEnum("PluginInstallationEventType",
			enumVal("PLUGIN_INSTALLATION_EVENT_TYPE_UNSPECIFIED", 0),
			enumVal("PLUGIN_INSTALLATION_EVENT_TYPE_CREATED", 1),
			enumVal("PLUGIN_INSTALLATION_EVENT_TYPE_UPDATED", 2),
			enumVal("PLUGIN_INSTALLATION_EVENT_TYPE_APPROVED", 3),
			enumVal("PLUGIN_INSTALLATION_EVENT_TYPE_STATUS_CHANGED", 4),
			enumVal("PLUGIN_INSTALLATION_EVENT_TYPE_DELETED", 5),
		),
	)

	ensureEnumValues(fdp, "PluginInstallationStatus",
		enumVal("PLUGIN_INSTALLATION_STATUS_DRAFT", 7),
	)
	ensureEnumValues(fdp, "PluginSourceMode",
		enumVal("PLUGIN_SOURCE_MODE_DECLARATIVE", 4),
	)

	ensureMessages(fdp, installationMessages()...)
	ensureMessages(fdp, declarativeAndSavedNodeMessages()...)

	ensureMessageFields(fdp, "PluginInstallation",
		bytesField("declarative_spec_json", "declarativeSpecJson", 23),
		bytesField("pending_declarative_spec_json", "pendingDeclarativeSpecJson", 24),
		strField("plugin_version", "pluginVersion", 25),
	)
	ensureMessageFields(fdp, "InstallPluginRequest",
		bytesField("declarative_spec_json", "declarativeSpecJson", 11),
		boolField("save_as_draft", "saveAsDraft", 12),
	)
	ensureMessageFields(fdp, "UpdatePluginInstallationRequest",
		bytesField("declarative_spec_json", "declarativeSpecJson", 12),
		boolField("submit_for_approval", "submitForApproval", 13),
		boolField("approve_immediately", "approveImmediately", 14),
	)

	ensureServiceMethods(fdp, "PluginRegistryService",
		unaryMethod("ListPluginInstallations", "ListPluginInstallationsRequest", "ListPluginInstallationsResponse"),
		unaryMethod("GetPluginInstallation", "GetPluginInstallationRequest", "GetPluginInstallationResponse"),
		unaryMethod("ListPluginPresets", "ListPluginPresetsRequest", "ListPluginPresetsResponse"),
		unaryMethod("InstallPlugin", "InstallPluginRequest", "InstallPluginResponse"),
		unaryMethod("ApprovePluginInstallation", "ApprovePluginInstallationRequest", "ApprovePluginInstallationResponse"),
		unaryMethod("UpdatePluginInstallation", "UpdatePluginInstallationRequest", "UpdatePluginInstallationResponse"),
		unaryMethod("SetPluginInstallationEnabled", "SetPluginInstallationEnabledRequest", "SetPluginInstallationEnabledResponse"),
		unaryMethod("DeletePluginInstallation", "DeletePluginInstallationRequest", "DeletePluginInstallationResponse"),
		serverStreamMethod("WatchPluginInstallations", "WatchPluginInstallationsRequest", "WatchPluginInstallationsResponse"),
		unaryMethod("TestDeclarativePlugin", "TestDeclarativePluginRequest", "TestDeclarativePluginResponse"),
		unaryMethod("ListDeclarativeSpecs", "ListDeclarativeSpecsRequest", "ListDeclarativeSpecsResponse"),
		unaryMethod("ListSavedNodes", "ListSavedNodesRequest", "ListSavedNodesResponse"),
		unaryMethod("SaveNode", "SaveNodeRequest", "SaveNodeResponse"),
		unaryMethod("UpdateSavedNode", "UpdateSavedNodeRequest", "UpdateSavedNodeResponse"),
		unaryMethod("DeleteSavedNode", "DeleteSavedNodeRequest", "DeleteSavedNodeResponse"),
	)
}

func installationMessages() []*descriptorpb.DescriptorProto {
	return []*descriptorpb.DescriptorProto{
		newMessage("PluginResourceLimits",
			strField("cpu_request", "cpuRequest", 1),
			strField("cpu_limit", "cpuLimit", 2),
			strField("memory_request", "memoryRequest", 3),
			strField("memory_limit", "memoryLimit", 4),
			int32Field("min_replicas", "minReplicas", 5),
			int32Field("max_replicas", "maxReplicas", 6),
		),
		newMessage("PluginRuntimeDiagnostics",
			strField("phase", "phase", 1),
			int32Field("desired_replicas", "desiredReplicas", 2),
			int32Field("ready_replicas", "readyReplicas", 3),
			strField("message", "message", 4),
			strField("last_error", "lastError", 5),
			msgField("updated_at", "updatedAt", 6, timestampType),
		),
		newMessage("PluginInstallation",
			strField("id", "id", 1),
			strField("name", "name", 2),
			enumField("source_mode", "sourceMode", 3, protoPkgPrefix+"PluginSourceMode"),
			strField("preset_id", "presetId", 4),
			strField("image_ref", "imageRef", 5),
			enumField("sandbox_profile", "sandboxProfile", 6, protoPkgPrefix+"SandboxProfile"),
			repStrField("egress_allowlist", "egressAllowlist", 7),
			msgField("resource_limits", "resourceLimits", 8, protoPkgPrefix+"PluginResourceLimits"),
			int32Field("desired_replicas", "desiredReplicas", 9),
			enumField("status", "status", 10, protoPkgPrefix+"PluginInstallationStatus"),
			boolField("auto_approve", "autoApprove", 11),
			strField("approved_manifest_digest", "approvedManifestDigest", 12),
			repMsgField("manifests", "manifests", 13, protoPkgPrefix+"PluginManifest"),
			repMsgField("pending_manifests", "pendingManifests", 14, protoPkgPrefix+"PluginManifest"),
			repStrField("plugin_ids", "pluginIds", 15),
			msgField("runtime_diagnostics", "runtimeDiagnostics", 16, protoPkgPrefix+"PluginRuntimeDiagnostics"),
			strField("created_by", "createdBy", 17),
			strField("approved_by", "approvedBy", 18),
			msgField("created_at", "createdAt", 19, timestampType),
			msgField("updated_at", "updatedAt", 20, timestampType),
			msgField("approved_at", "approvedAt", 21, timestampType),
			strField("status_reason", "statusReason", 22),
		),
		newMessage("PluginPreset",
			strField("id", "id", 1),
			strField("name", "name", 2),
			strField("description", "description", 3),
			strField("image_ref", "imageRef", 4),
			enumField("category", "category", 5, protoPkgPrefix+"PluginCategory"),
			enumField("sandbox_profile", "sandboxProfile", 6, protoPkgPrefix+"SandboxProfile"),
			repStrField("plugin_ids", "pluginIds", 7),
			repMsgField("output_ports", "outputPorts", 8, protoPkgPrefix+"PortDefinition"),
			repStrField("required_secret_keys", "requiredSecretKeys", 9),
			repStrField("default_egress_allowlist", "defaultEgressAllowlist", 10),
			msgField("default_resource_limits", "defaultResourceLimits", 11, protoPkgPrefix+"PluginResourceLimits"),
			boolField("auto_approve_supported", "autoApproveSupported", 12),
		),
		newMessage("ListPluginInstallationsRequest",
			msgField("actor", "actor", 1, protoPkgPrefix+"ActorContext"),
		),
		newMessage("ListPluginInstallationsResponse",
			repMsgField("installations", "installations", 1, protoPkgPrefix+"PluginInstallation"),
		),
		newMessage("GetPluginInstallationRequest",
			msgField("actor", "actor", 1, protoPkgPrefix+"ActorContext"),
			strField("installation_id", "installationId", 2),
		),
		newMessage("GetPluginInstallationResponse",
			msgField("installation", "installation", 1, protoPkgPrefix+"PluginInstallation"),
		),
		newMessage("ListPluginPresetsRequest",
			msgField("actor", "actor", 1, protoPkgPrefix+"ActorContext"),
		),
		newMessage("ListPluginPresetsResponse",
			repMsgField("presets", "presets", 1, protoPkgPrefix+"PluginPreset"),
		),
		newMessage("InstallPluginRequest",
			msgField("actor", "actor", 1, protoPkgPrefix+"ActorContext"),
			strField("name", "name", 2),
			enumField("source_mode", "sourceMode", 3, protoPkgPrefix+"PluginSourceMode"),
			strField("preset_id", "presetId", 4),
			strField("image_ref", "imageRef", 5),
			enumField("sandbox_profile", "sandboxProfile", 6, protoPkgPrefix+"SandboxProfile"),
			repStrField("egress_allowlist", "egressAllowlist", 7),
			msgField("resource_limits", "resourceLimits", 8, protoPkgPrefix+"PluginResourceLimits"),
			int32Field("desired_replicas", "desiredReplicas", 9),
			boolField("auto_approve", "autoApprove", 10),
		),
		newMessage("InstallPluginResponse",
			msgField("installation", "installation", 1, protoPkgPrefix+"PluginInstallation"),
			strField("plaintext_plugin_token", "plaintextPluginToken", 2),
		),
		newMessage("ApprovePluginInstallationRequest",
			msgField("actor", "actor", 1, protoPkgPrefix+"ActorContext"),
			strField("installation_id", "installationId", 2),
			strField("expected_manifest_digest", "expectedManifestDigest", 3),
		),
		newMessage("ApprovePluginInstallationResponse",
			msgField("installation", "installation", 1, protoPkgPrefix+"PluginInstallation"),
		),
		newMessage("UpdatePluginInstallationRequest",
			msgField("actor", "actor", 1, protoPkgPrefix+"ActorContext"),
			strField("installation_id", "installationId", 2),
			strField("image_ref", "imageRef", 3),
			enumField("sandbox_profile", "sandboxProfile", 4, protoPkgPrefix+"SandboxProfile"),
			repStrField("egress_allowlist", "egressAllowlist", 5),
			msgField("resource_limits", "resourceLimits", 6, protoPkgPrefix+"PluginResourceLimits"),
			int32Field("desired_replicas", "desiredReplicas", 7),
			boolField("rotate_token", "rotateToken", 8),
			msgField("runtime_diagnostics", "runtimeDiagnostics", 9, protoPkgPrefix+"PluginRuntimeDiagnostics"),
			enumField("status", "status", 10, protoPkgPrefix+"PluginInstallationStatus"),
			strField("status_reason", "statusReason", 11),
		),
		newMessage("UpdatePluginInstallationResponse",
			msgField("installation", "installation", 1, protoPkgPrefix+"PluginInstallation"),
			strField("plaintext_plugin_token", "plaintextPluginToken", 2),
		),
		newMessage("SetPluginInstallationEnabledRequest",
			msgField("actor", "actor", 1, protoPkgPrefix+"ActorContext"),
			strField("installation_id", "installationId", 2),
			boolField("enabled", "enabled", 3),
			strField("reason", "reason", 4),
		),
		newMessage("SetPluginInstallationEnabledResponse",
			msgField("installation", "installation", 1, protoPkgPrefix+"PluginInstallation"),
		),
		newMessage("DeletePluginInstallationRequest",
			msgField("actor", "actor", 1, protoPkgPrefix+"ActorContext"),
			strField("installation_id", "installationId", 2),
			strField("reason", "reason", 3),
		),
		newMessage("DeletePluginInstallationResponse",
			boolField("deleted", "deleted", 1),
		),
		newMessage("WatchPluginInstallationsRequest",
			msgField("actor", "actor", 1, protoPkgPrefix+"ActorContext"),
			strField("installation_id", "installationId", 2),
		),
		newMessage("WatchPluginInstallationsResponse",
			msgField("event", "event", 1, protoPkgPrefix+"PluginInstallationEvent"),
		),
		newMessage("PluginInstallationEvent",
			enumField("event_type", "eventType", 1, protoPkgPrefix+"PluginInstallationEventType"),
			msgField("installation", "installation", 2, protoPkgPrefix+"PluginInstallation"),
			msgField("occurred_at", "occurredAt", 3, timestampType),
		),
	}
}

func declarativeAndSavedNodeMessages() []*descriptorpb.DescriptorProto {
	return []*descriptorpb.DescriptorProto{
		newMessage("VirtualFile",
			strField("path", "path", 1),
			strField("content", "content", 2),
		),
		newMessage("TestDeclarativePluginRequest",
			msgField("actor", "actor", 1, protoPkgPrefix+"ActorContext"),
			bytesField("declarative_spec_json", "declarativeSpecJson", 2),
			bytesField("params_json", "paramsJson", 3),
			repMsgField("files", "files", 4, protoPkgPrefix+"VirtualFile"),
			bytesField("envelope_json", "envelopeJson", 5),
		),
		newMessage("TestDeclarativePluginResponse",
			boolField("ok", "ok", 1),
			repStrField("validation_errors", "validationErrors", 2),
			repMsgField("findings", "findings", 3, protoPkgPrefix+"Finding"),
			repStrField("active_output_ports", "activeOutputPorts", 4),
			bytesField("envelope_patch_json", "envelopePatchJson", 5),
			bytesField("dry_run_http_json", "dryRunHttpJson", 6),
			int64Field("duration_ms", "durationMs", 7),
			strField("summary", "summary", 8),
		),
		newMessage("DeclarativeSpecRecord",
			strField("installation_id", "installationId", 1),
			strField("plugin_id", "pluginId", 2),
			strField("version", "version", 3),
			enumField("sandbox_profile", "sandboxProfile", 4, protoPkgPrefix+"SandboxProfile"),
			repStrField("egress_allowlist", "egressAllowlist", 5),
			bytesField("declarative_spec_json", "declarativeSpecJson", 6),
			msgField("manifest", "manifest", 7, protoPkgPrefix+"PluginManifest"),
		),
		newMessage("ListDeclarativeSpecsRequest",
			enumField("sandbox_profile", "sandboxProfile", 1, protoPkgPrefix+"SandboxProfile"),
		),
		newMessage("ListDeclarativeSpecsResponse",
			repMsgField("specs", "specs", 1, protoPkgPrefix+"DeclarativeSpecRecord"),
		),
		newMessage("SavedNode",
			strField("id", "id", 1),
			strField("name", "name", 2),
			strField("description", "description", 3),
			strField("plugin_id", "pluginId", 4),
			bytesField("params_json", "paramsJson", 5),
			strField("canonical_params_hash", "canonicalParamsHash", 6),
			strField("created_by", "createdBy", 7),
			msgField("created_at", "createdAt", 8, timestampType),
			msgField("updated_at", "updatedAt", 9, timestampType),
		),
		newMessage("ListSavedNodesRequest",
			msgField("actor", "actor", 1, protoPkgPrefix+"ActorContext"),
		),
		newMessage("ListSavedNodesResponse",
			repMsgField("saved_nodes", "savedNodes", 1, protoPkgPrefix+"SavedNode"),
		),
		newMessage("SaveNodeRequest",
			msgField("actor", "actor", 1, protoPkgPrefix+"ActorContext"),
			strField("name", "name", 2),
			strField("description", "description", 3),
			strField("plugin_id", "pluginId", 4),
			bytesField("params_json", "paramsJson", 5),
		),
		newMessage("SaveNodeResponse",
			msgField("saved_node", "savedNode", 1, protoPkgPrefix+"SavedNode"),
		),
		newMessage("UpdateSavedNodeRequest",
			msgField("actor", "actor", 1, protoPkgPrefix+"ActorContext"),
			strField("id", "id", 2),
			strField("name", "name", 3),
			strField("description", "description", 4),
			bytesField("params_json", "paramsJson", 5),
		),
		newMessage("UpdateSavedNodeResponse",
			msgField("saved_node", "savedNode", 1, protoPkgPrefix+"SavedNode"),
		),
		newMessage("DeleteSavedNodeRequest",
			msgField("actor", "actor", 1, protoPkgPrefix+"ActorContext"),
			strField("id", "id", 2),
		),
		newMessage("DeleteSavedNodeResponse",
			boolField("deleted", "deleted", 1),
		),
	}
}

func ensureEnumValues(fdp *descriptorpb.FileDescriptorProto, enumName string, vals ...*descriptorpb.EnumValueDescriptorProto) {
	for _, e := range fdp.GetEnumType() {
		if e.GetName() != enumName {
			continue
		}
		existing := map[string]bool{}
		for _, v := range e.GetValue() {
			existing[v.GetName()] = true
		}
		for _, v := range vals {
			if !existing[v.GetName()] {
				e.Value = append(e.Value, v)
				existing[v.GetName()] = true
			}
		}
		return
	}
}

func ensureEnums(fdp *descriptorpb.FileDescriptorProto, enums ...*descriptorpb.EnumDescriptorProto) {
	existing := map[string]bool{}
	for _, e := range fdp.GetEnumType() {
		existing[e.GetName()] = true
	}
	for _, e := range enums {
		if !existing[e.GetName()] {
			fdp.EnumType = append(fdp.EnumType, e)
			existing[e.GetName()] = true
		}
	}
}

func ensureMessageFields(fdp *descriptorpb.FileDescriptorProto, msgName string, fields ...*descriptorpb.FieldDescriptorProto) {
	for _, m := range fdp.GetMessageType() {
		if m.GetName() != msgName {
			continue
		}
		existing := map[string]bool{}
		for _, f := range m.GetField() {
			existing[f.GetName()] = true
		}
		for _, f := range fields {
			if !existing[f.GetName()] {
				m.Field = append(m.Field, f)
				existing[f.GetName()] = true
			}
		}
		return
	}
}

func ensureMessages(fdp *descriptorpb.FileDescriptorProto, msgs ...*descriptorpb.DescriptorProto) {
	existing := map[string]bool{}
	for _, m := range fdp.GetMessageType() {
		existing[m.GetName()] = true
	}
	for _, m := range msgs {
		if !existing[m.GetName()] {
			fdp.MessageType = append(fdp.MessageType, m)
			existing[m.GetName()] = true
		}
	}
}

func ensureServiceMethods(fdp *descriptorpb.FileDescriptorProto, svcName string, methods ...*descriptorpb.MethodDescriptorProto) {
	for _, svc := range fdp.GetService() {
		if svc.GetName() != svcName {
			continue
		}
		existing := map[string]bool{}
		for _, m := range svc.GetMethod() {
			existing[m.GetName()] = true
		}
		for _, m := range methods {
			if !existing[m.GetName()] {
				svc.Method = append(svc.Method, m)
				existing[m.GetName()] = true
			}
		}
		return
	}
}

func newEnum(name string, vals ...*descriptorpb.EnumValueDescriptorProto) *descriptorpb.EnumDescriptorProto {
	return &descriptorpb.EnumDescriptorProto{Name: proto.String(name), Value: vals}
}

func enumVal(name string, num int32) *descriptorpb.EnumValueDescriptorProto {
	return &descriptorpb.EnumValueDescriptorProto{Name: proto.String(name), Number: proto.Int32(num)}
}

func newMessage(name string, fields ...*descriptorpb.FieldDescriptorProto) *descriptorpb.DescriptorProto {
	return &descriptorpb.DescriptorProto{Name: proto.String(name), Field: fields}
}

func strField(name, jsonName string, num int32) *descriptorpb.FieldDescriptorProto {
	return scalarField(name, jsonName, num, descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL, descriptorpb.FieldDescriptorProto_TYPE_STRING)
}

func boolField(name, jsonName string, num int32) *descriptorpb.FieldDescriptorProto {
	return scalarField(name, jsonName, num, descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL, descriptorpb.FieldDescriptorProto_TYPE_BOOL)
}

func int32Field(name, jsonName string, num int32) *descriptorpb.FieldDescriptorProto {
	return scalarField(name, jsonName, num, descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL, descriptorpb.FieldDescriptorProto_TYPE_INT32)
}

func int64Field(name, jsonName string, num int32) *descriptorpb.FieldDescriptorProto {
	return scalarField(name, jsonName, num, descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL, descriptorpb.FieldDescriptorProto_TYPE_INT64)
}

func bytesField(name, jsonName string, num int32) *descriptorpb.FieldDescriptorProto {
	return scalarField(name, jsonName, num, descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL, descriptorpb.FieldDescriptorProto_TYPE_BYTES)
}

func repStrField(name, jsonName string, num int32) *descriptorpb.FieldDescriptorProto {
	return scalarField(name, jsonName, num, descriptorpb.FieldDescriptorProto_LABEL_REPEATED, descriptorpb.FieldDescriptorProto_TYPE_STRING)
}

func scalarField(name, jsonName string, num int32, label descriptorpb.FieldDescriptorProto_Label, typ descriptorpb.FieldDescriptorProto_Type) *descriptorpb.FieldDescriptorProto {
	return &descriptorpb.FieldDescriptorProto{
		Name:     proto.String(name),
		Number:   proto.Int32(num),
		Label:    label.Enum(),
		Type:     typ.Enum(),
		JsonName: proto.String(jsonName),
	}
}

func msgField(name, jsonName string, num int32, typeName string) *descriptorpb.FieldDescriptorProto {
	return complexField(name, jsonName, num, descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, typeName)
}

func repMsgField(name, jsonName string, num int32, typeName string) *descriptorpb.FieldDescriptorProto {
	return complexField(name, jsonName, num, descriptorpb.FieldDescriptorProto_LABEL_REPEATED, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, typeName)
}

func enumField(name, jsonName string, num int32, typeName string) *descriptorpb.FieldDescriptorProto {
	return complexField(name, jsonName, num, descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL, descriptorpb.FieldDescriptorProto_TYPE_ENUM, typeName)
}

func complexField(name, jsonName string, num int32, label descriptorpb.FieldDescriptorProto_Label, typ descriptorpb.FieldDescriptorProto_Type, typeName string) *descriptorpb.FieldDescriptorProto {
	return &descriptorpb.FieldDescriptorProto{
		Name:     proto.String(name),
		Number:   proto.Int32(num),
		Label:    label.Enum(),
		Type:     typ.Enum(),
		TypeName: proto.String(typeName),
		JsonName: proto.String(jsonName),
	}
}

func unaryMethod(name, inMsg, outMsg string) *descriptorpb.MethodDescriptorProto {
	return &descriptorpb.MethodDescriptorProto{
		Name:       proto.String(name),
		InputType:  proto.String(protoPkgPrefix + inMsg),
		OutputType: proto.String(protoPkgPrefix + outMsg),
	}
}

func serverStreamMethod(name, inMsg, outMsg string) *descriptorpb.MethodDescriptorProto {
	return &descriptorpb.MethodDescriptorProto{
		Name:            proto.String(name),
		InputType:       proto.String(protoPkgPrefix + inMsg),
		OutputType:      proto.String(protoPkgPrefix + outMsg),
		ServerStreaming: proto.Bool(true),
	}
}

func renderWorkerGRPC(fdp *descriptorpb.FileDescriptorProto) ([]byte, error) {
	var b strings.Builder
	b.WriteString(`// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             (unknown)
// source: secflow/v1/worker.proto

package secflowv1

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9
`)

	for _, svc := range fdp.GetService() {
		renderServiceGRPC(&b, fdp.GetPackage(), fdp.GetName(), svc)
	}
	return []byte(b.String()), nil
}

func renderServiceGRPC(b *strings.Builder, pkg, source string, svc *descriptorpb.ServiceDescriptorProto) {
	svcName := svc.GetName()
	lowerSvc := strings.ToLower(svcName[:1]) + svcName[1:]

	b.WriteString("\nconst (\n")
	for _, m := range svc.GetMethod() {
		fmt.Fprintf(b, "\t%s_%s_FullMethodName = \"/%s.%s/%s\"\n", svcName, m.GetName(), pkg, svcName, m.GetName())
	}
	b.WriteString(")\n\n")

	fmt.Fprintf(b, "// %sClient is the client API for %s service.\n", svcName, svcName)
	fmt.Fprintf(b, "type %sClient interface {\n", svcName)
	for _, m := range svc.GetMethod() {
		in := shortType(m.GetInputType())
		out := shortType(m.GetOutputType())
		switch {
		case m.GetClientStreaming() && m.GetServerStreaming():
			fmt.Fprintf(b, "\t%s(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[%s, %s], error)\n", m.GetName(), in, out)
		case m.GetServerStreaming():
			fmt.Fprintf(b, "\t%s(ctx context.Context, in *%s, opts ...grpc.CallOption) (grpc.ServerStreamingClient[%s], error)\n", m.GetName(), in, out)
		default:
			fmt.Fprintf(b, "\t%s(ctx context.Context, in *%s, opts ...grpc.CallOption) (*%s, error)\n", m.GetName(), in, out)
		}
	}
	b.WriteString("}\n\n")

	fmt.Fprintf(b, "type %sClient struct {\n\tcc grpc.ClientConnInterface\n}\n\n", lowerSvc)
	fmt.Fprintf(b, "func New%sClient(cc grpc.ClientConnInterface) %sClient {\n\treturn &%sClient{cc}\n}\n\n", svcName, svcName, lowerSvc)

	streamIdx := 0
	for _, m := range svc.GetMethod() {
		in := shortType(m.GetInputType())
		out := shortType(m.GetOutputType())
		switch {
		case m.GetClientStreaming() && m.GetServerStreaming():
			fmt.Fprintf(b, "func (c *%sClient) %s(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[%s, %s], error) {\n", lowerSvc, m.GetName(), in, out)
			fmt.Fprintf(b, "\tcOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)\n")
			fmt.Fprintf(b, "\tstream, err := c.cc.NewStream(ctx, &%s_ServiceDesc.Streams[%d], %s_%s_FullMethodName, cOpts...)\n", svcName, streamIdx, svcName, m.GetName())
			fmt.Fprintf(b, "\tif err != nil {\n\t\treturn nil, err\n\t}\n")
			fmt.Fprintf(b, "\tx := &grpc.GenericClientStream[%s, %s]{ClientStream: stream}\n\treturn x, nil\n}\n\n", in, out)
			fmt.Fprintf(b, "type %s_%sClient = grpc.BidiStreamingClient[%s, %s]\n\n", svcName, m.GetName(), in, out)
			streamIdx++
		case m.GetServerStreaming():
			fmt.Fprintf(b, "func (c *%sClient) %s(ctx context.Context, in *%s, opts ...grpc.CallOption) (grpc.ServerStreamingClient[%s], error) {\n", lowerSvc, m.GetName(), in, out)
			fmt.Fprintf(b, "\tcOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)\n")
			fmt.Fprintf(b, "\tstream, err := c.cc.NewStream(ctx, &%s_ServiceDesc.Streams[%d], %s_%s_FullMethodName, cOpts...)\n", svcName, streamIdx, svcName, m.GetName())
			fmt.Fprintf(b, "\tif err != nil {\n\t\treturn nil, err\n\t}\n")
			fmt.Fprintf(b, "\tx := &grpc.GenericClientStream[%s, %s]{ClientStream: stream}\n", in, out)
			fmt.Fprintf(b, "\tif err := x.ClientStream.SendMsg(in); err != nil {\n\t\treturn nil, err\n\t}\n")
			fmt.Fprintf(b, "\tif err := x.ClientStream.CloseSend(); err != nil {\n\t\treturn nil, err\n\t}\n")
			fmt.Fprintf(b, "\treturn x, nil\n}\n\n")
			fmt.Fprintf(b, "type %s_%sClient = grpc.ServerStreamingClient[%s]\n\n", svcName, m.GetName(), out)
			streamIdx++
		default:
			fmt.Fprintf(b, "func (c *%sClient) %s(ctx context.Context, in *%s, opts ...grpc.CallOption) (*%s, error) {\n", lowerSvc, m.GetName(), in, out)
			fmt.Fprintf(b, "\tcOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)\n")
			fmt.Fprintf(b, "\tout := new(%s)\n", out)
			fmt.Fprintf(b, "\terr := c.cc.Invoke(ctx, %s_%s_FullMethodName, in, out, cOpts...)\n", svcName, m.GetName())
			fmt.Fprintf(b, "\tif err != nil {\n\t\treturn nil, err\n\t}\n\treturn out, nil\n}\n\n")
		}
	}

	fmt.Fprintf(b, "// %sServer is the server API for %s service.\n", svcName, svcName)
	fmt.Fprintf(b, "type %sServer interface {\n", svcName)
	for _, m := range svc.GetMethod() {
		in := shortType(m.GetInputType())
		out := shortType(m.GetOutputType())
		switch {
		case m.GetClientStreaming() && m.GetServerStreaming():
			fmt.Fprintf(b, "\t%s(grpc.BidiStreamingServer[%s, %s]) error\n", m.GetName(), in, out)
		case m.GetServerStreaming():
			fmt.Fprintf(b, "\t%s(*%s, grpc.ServerStreamingServer[%s]) error\n", m.GetName(), in, out)
		default:
			fmt.Fprintf(b, "\t%s(context.Context, *%s) (*%s, error)\n", m.GetName(), in, out)
		}
	}
	fmt.Fprintf(b, "\tmustEmbedUnimplemented%sServer()\n}\n\n", svcName)

	fmt.Fprintf(b, "type Unimplemented%sServer struct{}\n\n", svcName)
	for _, m := range svc.GetMethod() {
		in := shortType(m.GetInputType())
		out := shortType(m.GetOutputType())
		switch {
		case m.GetClientStreaming() && m.GetServerStreaming():
			fmt.Fprintf(b, "func (Unimplemented%sServer) %s(grpc.BidiStreamingServer[%s, %s]) error {\n", svcName, m.GetName(), in, out)
			fmt.Fprintf(b, "\treturn status.Errorf(codes.Unimplemented, \"method %s not implemented\")\n}\n", m.GetName())
		case m.GetServerStreaming():
			fmt.Fprintf(b, "func (Unimplemented%sServer) %s(*%s, grpc.ServerStreamingServer[%s]) error {\n", svcName, m.GetName(), in, out)
			fmt.Fprintf(b, "\treturn status.Errorf(codes.Unimplemented, \"method %s not implemented\")\n}\n", m.GetName())
		default:
			fmt.Fprintf(b, "func (Unimplemented%sServer) %s(context.Context, *%s) (*%s, error) {\n", svcName, m.GetName(), in, out)
			fmt.Fprintf(b, "\treturn nil, status.Errorf(codes.Unimplemented, \"method %s not implemented\")\n}\n", m.GetName())
		}
	}
	fmt.Fprintf(b, "func (Unimplemented%sServer) mustEmbedUnimplemented%sServer() {}\n", svcName, svcName)
	fmt.Fprintf(b, "func (Unimplemented%sServer) testEmbeddedByValue() {}\n\n", svcName)

	fmt.Fprintf(b, "type Unsafe%sServer interface {\n\tmustEmbedUnimplemented%sServer()\n}\n\n", svcName, svcName)

	fmt.Fprintf(b, "func Register%sServer(s grpc.ServiceRegistrar, srv %sServer) {\n", svcName, svcName)
	fmt.Fprintf(b, "\tif t, ok := srv.(interface{ testEmbeddedByValue() }); ok {\n\t\tt.testEmbeddedByValue()\n\t}\n")
	fmt.Fprintf(b, "\ts.RegisterService(&%s_ServiceDesc, srv)\n}\n\n", svcName)

	var unaryDescs, streamDescs []string
	for _, m := range svc.GetMethod() {
		in := shortType(m.GetInputType())
		out := shortType(m.GetOutputType())
		hName := fmt.Sprintf("_%s_%s_Handler", svcName, m.GetName())
		switch {
		case m.GetClientStreaming() && m.GetServerStreaming():
			fmt.Fprintf(b, "func %s(srv interface{}, stream grpc.ServerStream) error {\n", hName)
			fmt.Fprintf(b, "\treturn srv.(%sServer).%s(&grpc.GenericServerStream[%s, %s]{ServerStream: stream})\n}\n\n", svcName, m.GetName(), in, out)
			fmt.Fprintf(b, "type %s_%sServer = grpc.BidiStreamingServer[%s, %s]\n\n", svcName, m.GetName(), in, out)
			streamDescs = append(streamDescs, fmt.Sprintf("\t\t{\n\t\t\tStreamName: \"%s\",\n\t\t\tHandler: %s,\n\t\t\tServerStreams: true,\n\t\t\tClientStreams: true,\n\t\t},\n", m.GetName(), hName))
		case m.GetServerStreaming():
			fmt.Fprintf(b, "func %s(srv interface{}, stream grpc.ServerStream) error {\n", hName)
			fmt.Fprintf(b, "\tm := new(%s)\n\tif err := stream.RecvMsg(m); err != nil {\n\t\treturn err\n\t}\n", in)
			fmt.Fprintf(b, "\treturn srv.(%sServer).%s(m, &grpc.GenericServerStream[%s, %s]{ServerStream: stream})\n}\n\n", svcName, m.GetName(), in, out)
			fmt.Fprintf(b, "type %s_%sServer = grpc.ServerStreamingServer[%s]\n\n", svcName, m.GetName(), out)
			streamDescs = append(streamDescs, fmt.Sprintf("\t\t{\n\t\t\tStreamName: \"%s\",\n\t\t\tHandler: %s,\n\t\t\tServerStreams: true,\n\t\t},\n", m.GetName(), hName))
		default:
			fmt.Fprintf(b, "func %s(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {\n", hName)
			fmt.Fprintf(b, "\tin := new(%s)\n\tif err := dec(in); err != nil {\n\t\treturn nil, err\n\t}\n", in)
			fmt.Fprintf(b, "\tif interceptor == nil {\n\t\treturn srv.(%sServer).%s(ctx, in)\n\t}\n", svcName, m.GetName())
			fmt.Fprintf(b, "\tinfo := &grpc.UnaryServerInfo{\n\t\tServer: srv,\n\t\tFullMethod: %s_%s_FullMethodName,\n\t}\n", svcName, m.GetName())
			fmt.Fprintf(b, "\thandler := func(ctx context.Context, req interface{}) (interface{}, error) {\n\t\treturn srv.(%sServer).%s(ctx, req.(*%s))\n\t}\n", svcName, m.GetName(), in)
			fmt.Fprintf(b, "\treturn interceptor(ctx, in, info, handler)\n}\n\n")
			unaryDescs = append(unaryDescs, fmt.Sprintf("\t\t{\n\t\t\tMethodName: \"%s\",\n\t\t\tHandler: %s,\n\t\t},\n", m.GetName(), hName))
		}
	}

	fmt.Fprintf(b, "var %s_ServiceDesc = grpc.ServiceDesc{\n", svcName)
	fmt.Fprintf(b, "\tServiceName: \"%s.%s\",\n", pkg, svcName)
	fmt.Fprintf(b, "\tHandlerType: (*%sServer)(nil),\n", svcName)
	b.WriteString("\tMethods: []grpc.MethodDesc{\n")
	for _, u := range unaryDescs {
		b.WriteString(u)
	}
	b.WriteString("\t},\n\tStreams: []grpc.StreamDesc{\n")
	for _, st := range streamDescs {
		b.WriteString(st)
	}
	b.WriteString("\t},\n")
	fmt.Fprintf(b, "\tMetadata: \"%s\",\n}\n", source)
}

func shortType(fqn string) string {
	return strings.TrimPrefix(fqn, protoPkgPrefix)
}
