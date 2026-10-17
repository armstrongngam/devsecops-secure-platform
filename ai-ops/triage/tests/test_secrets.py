"""Tokens are read from mounted Secret files, with the environment as a fallback."""

from src.app import _secret


def test_secret_is_read_from_mounted_file(tmp_path, monkeypatch):
    (tmp_path / "ingest-token").write_text("from-file\n", encoding="utf-8")
    monkeypatch.setenv("SECRETS_DIR", str(tmp_path))
    monkeypatch.setenv("INGEST_TOKEN", "from-env")
    assert _secret("ingest-token") == "from-file"


def test_secret_falls_back_to_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("SECRETS_DIR", str(tmp_path))
    monkeypatch.setenv("INGEST_TOKEN", "from-env")
    assert _secret("ingest-token") == "from-env"


def test_missing_secret_is_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("SECRETS_DIR", str(tmp_path))
    monkeypatch.delenv("APPROVER_TOKEN", raising=False)
    assert _secret("approver-token") == ""
