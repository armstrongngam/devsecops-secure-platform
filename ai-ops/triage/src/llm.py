"""Minimal Ollama client using structured (JSON schema) output."""

from __future__ import annotations

import json
import urllib.error
import urllib.request


class LLMError(RuntimeError):
    """The model could not be reached or returned an unusable response."""


class OllamaClient:
    def __init__(self, base_url: str, model: str, timeout: float = 60.0):
        self.url = base_url.rstrip("/") + "/api/chat"
        self.model = model
        self.timeout = timeout

    def decide(self, messages: list[dict], schema: dict) -> str:
        body = json.dumps(
            {
                "model": self.model,
                "messages": messages,
                "stream": False,
                "format": schema,  # Ollama constrains decoding to this schema
                "options": {"temperature": 0},
            }
        ).encode()
        req = urllib.request.Request(
            self.url, data=body, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 - fixed internal URL
                payload = json.load(resp)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise LLMError(f"ollama request failed: {exc}") from exc
        try:
            return payload["message"]["content"]
        except (KeyError, TypeError) as exc:
            raise LLMError("unexpected ollama response shape") from exc
