#!/usr/bin/env bash
# Forwards new Zeek notices from the OT host to the triage service.
#
# Runs on mgmt01 and PULLS over SSH, because the firewall lets LAB reach OT
# but never lets OT initiate a connection into LAB. The OT side stays
# one-way, like a data diode in a real plant.
set -euo pipefail

: "${OT_HOST:=192.168.20.30}"
: "${OT_USER:=labadmin}"
: "${NOTICE_LOG:=ot-lab/zeek-logs/notice.log}"
: "${TRIAGE_URL:=http://triage.lab}"
: "${INGEST_TOKEN:?set INGEST_TOKEN}"

while true; do
  ssh -o BatchMode=yes -o ServerAliveInterval=30 -i "${HOME}/.ssh/lab_ed25519" \
      "${OT_USER}@${OT_HOST}" "tail -n0 -F ${NOTICE_LOG}" |
  while IFS= read -r line; do
    [[ "$line" == \{* ]] || continue   # JSON records only
    curl -fsS -m 10 -X POST "${TRIAGE_URL}/events/zeek" \
      -H "Authorization: Bearer ${INGEST_TOKEN}" \
      -H "Content-Type: application/json" \
      --data-binary "$line" >/dev/null \
      || echo "$(date -Is) forward failed" >&2
  done
  echo "$(date -Is) SSH stream ended; reconnecting in 10s" >&2
  sleep 10
done
