#!/usr/bin/env bash
set -euo pipefail

# Build and deploy OnlyScans to Kubernetes (k8s) or k3s with dynamic orchestrator worker scaling.
#
# Usage:
#   ./scripts/k8s-deploy.sh --target k3s --method kustomize
#   ./scripts/k8s-deploy.sh --target k3s --method helm
#   ./scripts/k8s-deploy.sh --target k8s --method helm --registry ghcr.io/zwarder-s-orgranization/onlyscans --tag 1.0.0 --push
#   ./scripts/k8s-deploy.sh --target kind --kind-cluster onlyscans --method kustomize

TARGET="k3s"          # k3s | k8s | kind
METHOD="auto"         # auto | helm | kustomize
REGISTRY="onlyscans"
TAG="local"
BUILD=true
PUSH=false
KIND_CLUSTER="kind"
PUBLIC_URL="http://onlyscans.local"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --method) METHOD="$2"; shift 2 ;;
    --registry) REGISTRY="$2"; shift 2 ;;
    --tag) TAG="$2"; shift 2 ;;
    --public-url) PUBLIC_URL="$2"; shift 2 ;;
    --kind-cluster) KIND_CLUSTER="$2"; shift 2 ;;
    --no-build) BUILD=false; shift ;;
    --push) PUSH=true; shift ;;
    -h|--help)
      sed -n '3,12p' "$0"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SERVICES=(
  "orchestrator:services/orchestrator/Dockerfile"
  "source-ingester:services/source-ingester/Dockerfile"
  "edge-gateway:services/edge-gateway/Dockerfile"
  "web:services/web/Dockerfile"
  "plugin-provisioner:services/plugin-provisioner/Dockerfile"
  "plugin-runtime-internal:services/plugin-runtime-internal/Dockerfile"
  "plugin-runtime-action:services/plugin-runtime-action/Dockerfile"
  "garage-init:services/garage-init/Dockerfile"
  "worker-kotlin:services/worker-kotlin/Dockerfile"
  "worker-sca:services/worker-sca/Dockerfile"
  "sbom-service:services/sbom-service/Dockerfile"
  "ai-service:services/ai-service/Dockerfile"
  "notify-service:services/notify-service/Dockerfile"
  "mcp-bridge:services/mcp-bridge/Dockerfile"
)

if [[ "$BUILD" == "true" ]]; then
  echo "==> Building OnlyScans container images (${REGISTRY}/*:${TAG})..."
  for entry in "${SERVICES[@]}"; do
    name="${entry%%:*}"
    dockerfile="${entry#*:}"
    image="${REGISTRY}/${name}:${TAG}"
    echo " -> Building ${image} from ${dockerfile}"
    if [[ "$name" == "web" ]]; then
      docker build -f "$dockerfile" --build-arg "NEXT_PUBLIC_API_URL=${PUBLIC_URL}" -t "$image" .
    else
      docker build -f "$dockerfile" -t "$image" .
    fi

    if [[ "$PUSH" == "true" ]]; then
      echo " -> Pushing ${image}"
      docker push "$image"
    elif [[ "$TARGET" == "k3s" ]]; then
      if command -v k3s >/dev/null 2>&1; then
        echo " -> Importing ${image} into k3s containerd"
        docker save "$image" | sudo k3s ctr images import -
      else
        echo " !! k3s binary not found locally; skipping direct ctr import (use --push for remote k3s)"
      fi
    elif [[ "$TARGET" == "kind" ]]; then
      echo " -> Loading ${image} into kind cluster '${KIND_CLUSTER}'"
      kind load docker-image "$image" --name "$KIND_CLUSTER"
    fi
  done
fi

if [[ "$METHOD" == "auto" ]]; then
  if command -v helm >/dev/null 2>&1; then
    METHOD="helm"
  else
    METHOD="kustomize"
  fi
fi

echo "==> Deploying OnlyScans (target=${TARGET}, method=${METHOD})..."
if [[ "$METHOD" == "helm" ]]; then
  VALUES_FILE="deploy/charts/onlyscans/values-local-k8s.yaml"
  if [[ "$TARGET" == "k3s" ]]; then
    VALUES_FILE="deploy/charts/onlyscans/values-k3s.yaml"
  elif [[ "$TARGET" == "k8s" ]]; then
    VALUES_FILE="deploy/charts/onlyscans/values-prod.yaml"
  fi
  helm upgrade --install onlyscans deploy/charts/onlyscans \
    -f "$VALUES_FILE" \
    --set "global.imageRegistry=${REGISTRY}" \
    --set "global.imageTag=${TAG}" \
    --set "global.publicUrl=${PUBLIC_URL}"
else
  OVERLAY="deploy/k8s/overlays/k8s"
  if [[ "$TARGET" == "k3s" ]]; then
    OVERLAY="deploy/k8s/overlays/k3s"
  fi
  kubectl apply -k "$OVERLAY"
fi

echo "==> Waiting for data plane & garage-init bootstrap..."
kubectl -n secflow-system rollout status statefulset/postgres --timeout=180s
kubectl -n secflow-system rollout status statefulset/garage --timeout=180s
kubectl -n secflow-system wait --for=condition=complete job/garage-init --timeout=180s

echo "==> Waiting for app plane & base workers..."
kubectl -n secflow-app rollout status deployment/orchestrator --timeout=180s
kubectl -n secflow-app rollout status deployment/edge-gateway --timeout=180s
kubectl -n secflow-app rollout status deployment/web --timeout=180s
kubectl -n secflow-workers rollout status deployment/ai-service --timeout=180s
kubectl -n secflow-workers rollout status deployment/notify-service --timeout=180s

echo ""
echo "OnlyScans deployed successfully!"
echo "Pure pull workers (worker-kotlin, worker-sca, sbom-service) will be created and scaled"
echo "automatically in namespace 'secflow-workers' by the orchestrator when scans run."
echo ""
echo "Inspect status:"
echo "  kubectl -n secflow-app get pods,ingress"
echo "  kubectl -n secflow-workers get deployments,pods"
