#!/usr/bin/env bash
# Sets up the AI-ops module after scripts/bootstrap-cluster.sh has run.
# Run on mgmt01 from the repo root:  ./scripts/bootstrap-ai-ops.sh
#
# 1. Generates three tokens (ingest, approver, EDA webhook).
# 2. Stores them in a Kubernetes Secret and in /etc/ai-ops.env (root-only).
# 3. Points Falcosidekick at the triage service.
# 4. Adds monitoring for the AI components.
set -euo pipefail

need() { command -v "$1" >/dev/null || { echo "missing: $1" >&2; exit 1; }; }
need kubectl
need helm
need openssl

ENV_FILE=/etc/ai-ops.env

if sudo test -f "$ENV_FILE"; then
  echo "==> Reusing tokens from $ENV_FILE"
  # shellcheck disable=SC1090
  source <(sudo cat "$ENV_FILE")
else
  echo "==> Generating tokens"
  INGEST_TOKEN=$(openssl rand -hex 32)
  APPROVER_TOKEN=$(openssl rand -hex 32)
  EDA_WEBHOOK_TOKEN=$(openssl rand -hex 32)
  sudo install -m 0600 -o "$USER" /dev/null "$ENV_FILE"
  cat <<EOF | sudo tee "$ENV_FILE" >/dev/null
INGEST_TOKEN=$INGEST_TOKEN
APPROVER_TOKEN=$APPROVER_TOKEN
EDA_WEBHOOK_TOKEN=$EDA_WEBHOOK_TOKEN
TRIAGE_URL=http://triage.lab
EOF
fi

echo "==> Kubernetes Secret ai-ops/ai-ops-tokens"
kubectl create namespace ai-ops --dry-run=client -o yaml | kubectl apply -f -
kubectl -n ai-ops create secret generic ai-ops-tokens \
  --from-literal=ingest-token="$INGEST_TOKEN" \
  --from-literal=approver-token="$APPROVER_TOKEN" \
  --from-literal=eda-token="$EDA_WEBHOOK_TOKEN" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n ai-ops rollout restart deployment/ai-triage 2>/dev/null || true

echo "==> Falcosidekick -> triage webhook"
helm upgrade falco falcosecurity/falco -n falco --reuse-values \
  --set falcosidekick.config.webhook.address=http://ai-triage.ai-ops.svc.cluster.local/events/falco \
  --set falcosidekick.config.webhook.minimumpriority=warning \
  --set-string "falcosidekick.config.webhook.customHeaders=Authorization:Bearer ${INGEST_TOKEN}" \
  --wait

echo "==> Monitoring for AI components"
kubectl apply -f k8s/monitoring/ai-ops-monitoring.yaml

cat <<EOF

Done. Next steps on mgmt01 (see docs/AI-OPS.md section 3):
  - Install and start the EDA rulebook and Zeek shipper services.
  - Add "192.168.10.21  triage.lab" to your hosts file.
  - Your approver token is in $ENV_FILE (APPROVER_TOKEN). Treat it like a password.
EOF
