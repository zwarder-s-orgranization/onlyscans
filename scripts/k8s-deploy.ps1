<#
.SYNOPSIS
    Build and deploy OnlyScans to Kubernetes (Docker Desktop K8s / kind / k3s) with dynamic orchestrator worker scaling.
.EXAMPLE
    .\scripts\k8s-deploy.ps1 -Target k8s -Method kustomize
    .\scripts\k8s-deploy.ps1 -Target k3s -Method helm -Registry ghcr.io/zwarder-s-orgranization/onlyscans -Tag 1.0.0 -Push
#>
[CmdletBinding()]
param(
    [ValidateSet("k3s", "k8s", "kind")]
    [string]$Target = "k8s",
    [ValidateSet("auto", "helm", "kustomize")]
    [string]$Method = "auto",
    [string]$Registry = "onlyscans",
    [string]$Tag = "local",
    [string]$PublicUrl = "http://onlyscans.local",
    [string]$KindCluster = "kind",
    [switch]$NoBuild,
    [switch]$Push
)

$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent $PSScriptRoot
Push-Location $RootDir

try {
    $services = @(
        @{ Name = "orchestrator";       Dockerfile = "services/orchestrator/Dockerfile" },
        @{ Name = "source-ingester";    Dockerfile = "services/source-ingester/Dockerfile" },
        @{ Name = "edge-gateway";       Dockerfile = "services/edge-gateway/Dockerfile" },
        @{ Name = "web";                Dockerfile = "services/web/Dockerfile" },
        @{ Name = "plugin-provisioner";      Dockerfile = "services/plugin-provisioner/Dockerfile" },
        @{ Name = "plugin-runtime-internal"; Dockerfile = "services/plugin-runtime-internal/Dockerfile" },
        @{ Name = "plugin-runtime-action";   Dockerfile = "services/plugin-runtime-action/Dockerfile" },
        @{ Name = "garage-init";             Dockerfile = "services/garage-init/Dockerfile" },
        @{ Name = "worker-kotlin";      Dockerfile = "services/worker-kotlin/Dockerfile" },
        @{ Name = "worker-sca";         Dockerfile = "services/worker-sca/Dockerfile" },
        @{ Name = "sbom-service";       Dockerfile = "services/sbom-service/Dockerfile" },
        @{ Name = "ai-service";         Dockerfile = "services/ai-service/Dockerfile" },
        @{ Name = "notify-service";     Dockerfile = "services/notify-service/Dockerfile" },
        @{ Name = "mcp-bridge";         Dockerfile = "services/mcp-bridge/Dockerfile" }
    )

    if (-not $NoBuild) {
        Write-Host "==> Building OnlyScans container images ($Registry/*:$Tag)..."
        foreach ($svc in $services) {
            $image = "$Registry/$($svc.Name):$Tag"
            Write-Host " -> Building $image from $($svc.Dockerfile)"
            if ($svc.Name -eq "web") {
                docker build -f $svc.Dockerfile --build-arg "NEXT_PUBLIC_API_URL=$PublicUrl" -t $image .
            } else {
                docker build -f $svc.Dockerfile -t $image .
            }
            if ($LASTEXITCODE -ne 0) { throw "docker build failed for $image" }

            if ($Push) {
                docker push $image
                if ($LASTEXITCODE -ne 0) { throw "docker push failed for $image" }
            } elseif ($Target -eq "kind") {
                kind load docker-image $image --name $KindCluster
                if ($LASTEXITCODE -ne 0) { throw "kind load failed for $image" }
            }
        }
    }

    if ($Method -eq "auto") {
        if (Get-Command helm -ErrorAction SilentlyContinue) {
            $Method = "helm"
        } else {
            $Method = "kustomize"
        }
    }

    Write-Host "==> Deploying OnlyScans (Target=$Target, Method=$Method)..."
    if ($Method -eq "helm") {
        $valuesFile = switch ($Target) {
            "k3s"  { "deploy/charts/onlyscans/values-k3s.yaml" }
            "kind" { "deploy/charts/onlyscans/values-local-k8s.yaml" }
            default { "deploy/charts/onlyscans/values-local-k8s.yaml" }
        }
        helm upgrade --install onlyscans deploy/charts/onlyscans `
            -f $valuesFile `
            --set "global.imageRegistry=$Registry" `
            --set "global.imageTag=$Tag" `
            --set "global.publicUrl=$PublicUrl"
        if ($LASTEXITCODE -ne 0) { throw "helm upgrade --install failed" }
    } else {
        $overlay = if ($Target -eq "k3s") { "deploy/k8s/overlays/k3s" } else { "deploy/k8s/overlays/k8s" }
        kubectl apply -k $overlay
        if ($LASTEXITCODE -ne 0) { throw "kubectl apply -k failed" }
    }

    Write-Host "==> Waiting for data plane & garage-init bootstrap..."
    kubectl -n secflow-system rollout status statefulset/postgres --timeout=180s
    kubectl -n secflow-system rollout status statefulset/garage --timeout=180s
    kubectl -n secflow-system wait --for=condition=complete job/garage-init --timeout=180s

    Write-Host "==> Waiting for app plane & base workers..."
    kubectl -n secflow-app rollout status deployment/orchestrator --timeout=180s
    kubectl -n secflow-app rollout status deployment/edge-gateway --timeout=180s
    kubectl -n secflow-app rollout status deployment/web --timeout=180s
    kubectl -n secflow-workers rollout status deployment/ai-service --timeout=180s
    kubectl -n secflow-workers rollout status deployment/notify-service --timeout=180s

    Write-Host ""
    Write-Host "OnlyScans deployed successfully!" -ForegroundColor Green
    Write-Host "Pure pull workers (worker-kotlin, worker-sca, sbom-service) are created and scaled on demand"
    Write-Host "by orchestrator in namespace 'secflow-workers' when scans run."
} finally {
    Pop-Location
}
