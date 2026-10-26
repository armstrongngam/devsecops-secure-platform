"""AI-assisted alert triage service.

Flow:
  Falco (via Falcosidekick) / Zeek (via shipper) -> POST /events/{falco,zeek}
    -> guardrails clean the alert -> local LLM (Ollama) proposes a runbook
    -> guardrails validate the proposal
    -> read-only runbooks run automatically through Event-Driven Ansible
    -> disruptive runbooks wait for POST /incidents/<id>/approve
"""

from __future__ import annotations

import hmac
import os
import threading
import time
import uuid
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

from flask import Flask, Response, abort, jsonify, request
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

from .dispatch import DispatchError, EdaDispatcher
from .guardrails import (
    RESPONSE_SCHEMA,
    RUNBOOKS,
    GuardrailError,
    build_messages,
    extract_target,
    fallback_decision,
    normalize_falco,
    normalize_zeek,
    validate_decision,
)
from .llm import LLMError, OllamaClient

INCIDENTS = Counter("triage_incidents_total", "Incidents created", ["source", "severity", "runbook"])
GUARDRAIL_REJECTIONS = Counter("triage_guardrail_rejections_total", "Model outputs rejected by guardrails")
LLM_FAILURES = Counter("triage_llm_failures_total", "Model calls that failed")
LLM_SECONDS = Histogram("triage_llm_seconds", "Model latency", buckets=(1, 2, 5, 10, 20, 40, 60, 120))
ACTIONS = Counter("triage_actions_total", "Actions sent to EDA", ["runbook", "mode"])


class IncidentStore:
    """In-memory, newest-first, capped. One replica only; use a DB beyond the lab."""

    def __init__(self, limit: int = 500):
        self._items: OrderedDict[str, dict] = OrderedDict()
        self._lock = threading.Lock()
        self._limit = limit

    def add(self, incident: dict) -> None:
        with self._lock:
            self._items[incident["id"]] = incident
            while len(self._items) > self._limit:
                self._items.popitem(last=False)

    def get(self, incident_id: str) -> dict | None:
        with self._lock:
            return self._items.get(incident_id)

    def list(self) -> list[dict]:
        with self._lock:
            return list(reversed(self._items.values()))


def _secret(name: str) -> str:
    """Read a secret from its mounted file, falling back to the environment.

    Kubernetes mounts the ai-ops-tokens Secret as files under SECRETS_DIR, so
    tokens never appear in the process environment (CKV_K8S_35). The env
    fallback keeps local runs and tests simple.
    """
    path = os.path.join(os.environ.get("SECRETS_DIR", "/var/run/secrets/ai-ops"), name)
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return os.environ.get(name.upper().replace("-", "_"), "")


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def create_app(
    llm=None, dispatcher=None, store=None, ingest_token=None, approver_token=None, async_triage=True
) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024

    llm = llm or OllamaClient(
        os.environ.get("OLLAMA_URL", "http://ollama:11434"),
        os.environ.get("OLLAMA_MODEL", "qwen2.5:3b"),
        float(os.environ.get("OLLAMA_TIMEOUT", "90")),
    )
    dispatcher = dispatcher or EdaDispatcher(
        os.environ.get("EDA_URL", "http://192.168.10.10:5000/endpoint"),
        _secret("eda-token"),
    )
    store = store or IncidentStore()
    # One worker: a CPU-only model handles one alert at a time.
    executor = ThreadPoolExecutor(max_workers=1)
    ingest_token = ingest_token if ingest_token is not None else _secret("ingest-token")
    approver_token = approver_token if approver_token is not None else _secret("approver-token")

    def require_token(expected: str) -> None:
        sent = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        if not expected or not hmac.compare_digest(sent.encode(), expected.encode()):
            abort(401)

    def dispatch(incident: dict, approved_by: str, mode: str) -> None:
        action = {
            "type": "approved_action",
            "incident_id": incident["id"],
            "runbook": incident["decision"]["runbook"],
            "severity": incident["decision"]["severity"],
            "target": incident["target"],
            "approved_by": approved_by,
        }
        try:
            dispatcher.send(action)
            incident["status"] = "dispatched"
            ACTIONS.labels(action["runbook"], mode).inc()
        except DispatchError as exc:
            incident["status"] = "dispatch_failed"
            incident["error"] = str(exc)
        incident["history"].append({"at": _now(), "event": f"{mode} dispatch by {approved_by}: {incident['status']}"})

    def receive(alert: dict):
        """Record the alert immediately; analyze it in the background.

        A small CPU-only model can take tens of seconds, and webhook senders
        time out long before that, so the HTTP reply never waits for the model.
        """
        incident = {
            "id": uuid.uuid4().hex[:12],
            "created": _now(),
            "alert": alert,
            "target": extract_target(alert),
            "decision": fallback_decision(alert, "analysis in progress"),
            "status": "triaging",
            "history": [{"at": _now(), "event": "received"}],
        }
        store.add(incident)
        if async_triage:
            executor.submit(analyze, incident)
            return jsonify(id=incident["id"], status="triaging"), 202
        analyze(incident)
        return jsonify(incident), 201

    def analyze(incident: dict) -> None:
        alert, target = incident["alert"], incident["target"]
        start = time.perf_counter()
        try:
            raw = llm.decide(build_messages(alert), RESPONSE_SCHEMA)
            decision = validate_decision(raw, alert)
        except LLMError as exc:
            LLM_FAILURES.inc()
            decision = fallback_decision(alert, f"model unavailable: {exc}")
        except GuardrailError as exc:
            GUARDRAIL_REJECTIONS.inc()
            decision = fallback_decision(alert, f"guardrail rejected model output: {exc}")
        except Exception as exc:  # noqa: BLE001 - a triage bug must never drop an alert
            LLM_FAILURES.inc()
            decision = fallback_decision(alert, f"unexpected error: {type(exc).__name__}")
        finally:
            LLM_SECONDS.observe(time.perf_counter() - start)

        # A disruptive runbook needs a safe, concrete target. Without one,
        # fall back to evidence collection and flag for a human.
        if not RUNBOOKS[decision["runbook"]]["auto"] and target is None:
            decision = fallback_decision(alert, "no safe target for the recommended action")

        incident["decision"] = decision
        incident["history"].append({"at": _now(), "event": f"triaged: {decision['runbook']} ({decision['severity']})"})
        INCIDENTS.labels(alert["source"], decision["severity"], decision["runbook"]).inc()

        runbook = decision["runbook"]
        if runbook == "no_action":
            incident["status"] = "closed_no_action"
        elif RUNBOOKS[runbook]["auto"]:
            dispatch(incident, "auto-policy", "auto")
        else:
            incident["status"] = "pending_approval"

    @app.post("/events/falco")
    def falco_event():
        require_token(ingest_token)
        try:
            alert = normalize_falco(request.get_json(silent=True))
        except GuardrailError as exc:
            return jsonify(error=str(exc)), 400
        return receive(alert)

    @app.post("/events/zeek")
    def zeek_event():
        require_token(ingest_token)
        try:
            alert = normalize_zeek(request.get_json(silent=True))
        except GuardrailError as exc:
            return jsonify(error=str(exc)), 400
        return receive(alert)

    @app.get("/incidents")
    def list_incidents():
        require_token(approver_token)
        return jsonify(
            [
                {
                    "id": i["id"],
                    "created": i["created"],
                    "source": i["alert"]["source"],
                    "severity": i["decision"]["severity"],
                    "runbook": i["decision"]["runbook"],
                    "status": i["status"],
                    "summary": i["decision"]["summary"],
                }
                for i in store.list()
            ]
        )

    @app.get("/incidents/<incident_id>")
    def get_incident(incident_id: str):
        require_token(approver_token)
        incident = store.get(incident_id)
        if not incident:
            abort(404)
        return jsonify(incident)

    @app.post("/incidents/<incident_id>/approve")
    def approve(incident_id: str):
        require_token(approver_token)
        incident = store.get(incident_id)
        if not incident:
            abort(404)
        if incident["status"] != "pending_approval":
            return jsonify(error=f"incident is {incident['status']}"), 409
        approver = str((request.get_json(silent=True) or {}).get("approver", "unknown"))[:60]
        dispatch(incident, approver, "approved")
        return jsonify(incident)

    @app.post("/incidents/<incident_id>/reject")
    def reject(incident_id: str):
        require_token(approver_token)
        incident = store.get(incident_id)
        if not incident:
            abort(404)
        if incident["status"] != "pending_approval":
            return jsonify(error=f"incident is {incident['status']}"), 409
        approver = str((request.get_json(silent=True) or {}).get("approver", "unknown"))[:60]
        incident["status"] = "rejected"
        incident["history"].append({"at": _now(), "event": f"rejected by {approver}"})
        return jsonify(incident)

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok")

    @app.get("/metrics")
    def metrics():
        return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

    return app
