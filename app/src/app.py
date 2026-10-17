"""Small API used to exercise the secure delivery pipeline.

Endpoints:
  GET /healthz   liveness/readiness probe
  GET /api/info  build metadata (version, git commit)
  GET /metrics   Prometheus metrics
"""

import os
import time

from flask import Flask, Response, jsonify, request
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

REQUESTS = Counter(
    "app_requests_total", "HTTP requests", ["method", "endpoint", "status"]
)
LATENCY = Histogram("app_request_seconds", "Request latency", ["endpoint"])


def create_app() -> Flask:
    app = Flask(__name__)

    @app.before_request
    def _start_timer():
        request.environ["start_time"] = time.perf_counter()

    @app.after_request
    def _record(response):
        endpoint = request.url_rule.rule if request.url_rule else "unknown"
        elapsed = time.perf_counter() - request.environ.get("start_time", time.perf_counter())
        LATENCY.labels(endpoint).observe(elapsed)
        REQUESTS.labels(request.method, endpoint, response.status_code).inc()
        # Basic security headers on every response.
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok")

    @app.get("/api/info")
    def info():
        return jsonify(
            service="secure-app",
            version=os.environ.get("APP_VERSION", "dev"),
            commit=os.environ.get("GIT_SHA", "unknown"),
        )

    @app.get("/metrics")
    def metrics():
        return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

    return app


app = create_app()
