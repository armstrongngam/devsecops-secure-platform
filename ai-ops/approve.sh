#!/usr/bin/env bash
# Tiny CLI for the on-call engineer.
#   ./approve.sh list
#   ./approve.sh show <id>
#   ./approve.sh approve <id>
#   ./approve.sh reject <id>
set -euo pipefail
: "${TRIAGE_URL:=http://triage.lab}"
: "${APPROVER_TOKEN:?export APPROVER_TOKEN (from /etc/ai-ops.env)}"

auth=(-H "Authorization: Bearer ${APPROVER_TOKEN}" -H "Content-Type: application/json")
id="${2:-}"

case "${1:-list}" in
  list)    curl -fsS "${auth[@]}" "$TRIAGE_URL/incidents" | jq -r '.[] | [.id, .status, .severity, .runbook, .summary[0:80]] | @tsv' ;;
  show)    curl -fsS "${auth[@]}" "$TRIAGE_URL/incidents/$id" | jq . ;;
  approve) curl -fsS "${auth[@]}" -X POST -d "{\"approver\":\"$USER\"}" "$TRIAGE_URL/incidents/$id/approve" | jq '{id, status, runbook: .decision.runbook, target}' ;;
  reject)  curl -fsS "${auth[@]}" -X POST -d "{\"approver\":\"$USER\"}" "$TRIAGE_URL/incidents/$id/reject" | jq '{id, status}' ;;
  *)       echo "usage: $0 list|show|approve|reject [id]" >&2; exit 1 ;;
esac
