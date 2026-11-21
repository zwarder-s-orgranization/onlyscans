// Package secretclient resolves least-privilege scoped secrets from orchestrator SecretService.
package secretclient

import (
	"context"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/obs"
)

var (
	connsMu sync.Mutex
	conns   = map[string]*grpc.ClientConn{}
)

func getConn(addr string) (*grpc.ClientConn, error) {
	connsMu.Lock()
	defer connsMu.Unlock()
	if c, ok := conns[addr]; ok && c != nil {
		return c, nil
	}
	c, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()), obs.GRPCDialOption())
	if err != nil {
		return nil, fmt.Errorf("dial secret service %s: %w", addr, err)
	}
	conns[addr] = c
	return c, nil
}

// ResolveNodeSecret fetches a plaintext secret bound to the leased NodeTask.
func ResolveNodeSecret(ctx context.Context, addr string, task *secflowv1.NodeTask, secretRef string) (string, error) {
	if secretRef == "" {
		return "", nil
	}
	if task == nil {
		return "", fmt.Errorf("resolve node secret: missing task")
	}
	req := &secflowv1.ResolveScopedSecretRequest{
		SecretRef: secretRef,
		Scope: &secflowv1.ResolveScopedSecretRequest_NodeTask{
			NodeTask: &secflowv1.NodeTaskSecretScope{
				RunId:          task.GetRunId(),
				NodeRunId:      task.GetNodeRunId(),
				NodeId:         task.GetNodeId(),
				PluginId:       task.GetPluginId(),
				TaskLeaseToken: task.GetTaskLeaseToken(),
			},
		},
	}
	return resolve(ctx, addr, req)
}

// ResolveCommitSecret fetches a plaintext git commit status token scoped to a webhook Run.
func ResolveCommitSecret(ctx context.Context, addr, serviceToken string, req *secflowv1.SendCommitStatusRequest, secretRef string) (string, error) {
	if secretRef == "" {
		return "", nil
	}
	if req == nil {
		return "", fmt.Errorf("resolve commit secret: missing request")
	}
	resolveReq := &secflowv1.ResolveScopedSecretRequest{
		SecretRef:    secretRef,
		ServiceToken: serviceToken,
		Scope: &secflowv1.ResolveScopedSecretRequest_CommitStatus{
			CommitStatus: &secflowv1.CommitStatusSecretScope{
				RunId:         req.GetRunId(),
				WorkflowId:    req.GetWorkflowId(),
				TriggerNodeId: req.GetTriggerNodeId(),
			},
		},
	}
	return resolve(ctx, addr, resolveReq)
}

// ResolveMCPDiscoverySecret fetches an outbound MCP connection auth secret for tool discovery.
func ResolveMCPDiscoverySecret(ctx context.Context, addr, serviceToken, connectionID, secretRef string) (string, error) {
	if secretRef == "" {
		return "", nil
	}
	resolveReq := &secflowv1.ResolveScopedSecretRequest{
		SecretRef:    secretRef,
		ServiceToken: serviceToken,
		Scope: &secflowv1.ResolveScopedSecretRequest_McpDiscovery{
			McpDiscovery: &secflowv1.MCPDiscoverySecretScope{
				McpConnectionId: connectionID,
			},
		},
	}
	return resolve(ctx, addr, resolveReq)
}

func resolve(ctx context.Context, addr string, req *secflowv1.ResolveScopedSecretRequest) (string, error) {
	conn, err := getConn(addr)
	if err != nil {
		return "", err
	}
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	resp, err := secflowv1.NewSecretServiceClient(conn).ResolveScopedSecret(reqCtx, req)
	if err != nil {
		return "", fmt.Errorf("resolve scoped secret: %w", err)
	}
	return resp.GetPlaintextValue(), nil
}
