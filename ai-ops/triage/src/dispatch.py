"""Sends approved actions to the Event-Driven Ansible webhook."""

from __future__ import annotations

import json
import urllib.error
import urllib.request


class DispatchError(RuntimeError):
    pass


class EdaDispatcher:
    def __init__(self, url: str, token: str, timeout: float = 10.0):
        self.url = url
        self.token = token
        self.timeout = timeout

    def send(self, action: dict) -> None:
        req = urllib.request.Request(
            self.url,
            data=json.dumps(action).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.token}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 - fixed internal URL
                if resp.status >= 300:
                    raise DispatchError(f"EDA returned HTTP {resp.status}")
        except urllib.error.URLError as exc:
            raise DispatchError(f"EDA unreachable: {exc}") from exc
