#!/usr/bin/env bash
# Installs the platform layer onto a fresh k3s cluster:
#   Kyverno (admission policy), Argo CD (GitOps), kube-prometheus-stack
#   (metrics/alerts), Falco (runtime detection), then hands the app to Argo CD.
#
# Run from the repo root on a machine with kubectl + helm pointed at the cluster:
#   ./scripts/bootstrap-cluster.sh
set -euo pipefail

need() { command -v "$1" >/dev/null || { echo "missing: $1" >&2; exit 1; }; }
need kubectl
need helm

if grep -rq "YourGitHubName\|yourgithubname" k8s/; then
  echo "Replace YourGitHubName / yourgithubname in k8s/ first (see docs/HOMELAB.md step 7)." >&2
  exit 1
fi

if [[ -z "${GRAFANA_PASSWORD:-}" ]]; then
  read -rsp "Grafana admin password to set: " GRAFANA_PASSWORD; echo
fi

echo "==> Helm repositories"
helm repo add kyverno https://kyverno.github.io/kyverno/ >/dev/null
helm repo add argo https://argoproj.github.io/argo-helm >/dev/null
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts >/dev/null
helm repo add falcosecurity https://falcosecurity.github.io/charts >/dev/null
helm repo update >/dev/null

echo "==> Kyverno (admission control)"
helm upgrade --install kyverno kyverno/kyverno -n kyverno --create-namespace --wait

echo "==> Monitoring (Prometheus, Alertmanager, Grafana)"
kubectl create namespace monitoring --dry-run=client -o yaml | kubectl apply -f -
kubectl -n monitoring create secret generic grafana-admin \
  --from-literal=admin-user=admin \
  --from-literal=admin-password="$GRAFANA_PASSWORD" \
  --dry-run=client -o yaml | kubectl apply -f -
helm upgrade --install monitoring prometheus-community/kube-prometheus-stack \
  -n monitoring -f k8s/monitoring/kube-prometheus-stack-values.yaml --wait --timeout 10m

echo "==> Falco (runtime threat detection)"
helm upgrade --install falco falcosecurity/falco -n falco --create-namespace \
  -f k8s/runtime/falco-values.yaml --wait --timeout 10m

echo "==> Argo CD (GitOps)"
helm upgrade --install argocd argo/argo-cd -n argocd --create-namespace --wait

echo "==> Hand the policies and the app to Argo CD"
kubectl apply -f k8s/argocd/secure-app.yaml

echo "==> Waiting for the app namespace, then adding its ServiceMonitor and alerts"
for _ in $(seq 1 30); do
  kubectl get namespace secure-app >/dev/null 2>&1 && break
  sleep 10
done
kubectl apply -f k8s/monitoring/secure-app-monitoring.yaml

cat <<EOF

Done.
  Argo CD admin password:
    kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d; echo
  Argo CD UI:   kubectl -n argocd port-forward svc/argocd-server 8443:443   -> https://localhost:8443
  Grafana:      http://grafana.lab   (user: admin)
  Falco UI:     kubectl -n falco port-forward svc/falco-falcosidekick-ui 2802:2802 -> http://localhost:2802
EOF
