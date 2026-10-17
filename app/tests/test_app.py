import pytest

from src.app import create_app


@pytest.fixture()
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_healthz(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


def test_info_reports_build_metadata(client, monkeypatch):
    monkeypatch.setenv("APP_VERSION", "1.2.3")
    monkeypatch.setenv("GIT_SHA", "abc123")
    data = client.get("/api/info").get_json()
    assert data["version"] == "1.2.3"
    assert data["commit"] == "abc123"


def test_security_headers_present(client):
    resp = client.get("/healthz")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in resp.headers["Content-Security-Policy"]


def test_metrics_exposed(client):
    client.get("/healthz")
    body = client.get("/metrics").get_data(as_text=True)
    assert "app_requests_total" in body


def test_unknown_route_is_404(client):
    assert client.get("/admin").status_code == 404
