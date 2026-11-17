"""Test helpers for the WP2 probe tests (fake engagement session + context)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from fastapi.testclient import TestClient

from tests.automated_vapt.fixtures.mock_waf_challenge_app import create_waf_challenge_app
from tests.automated_vapt.fixtures.probes.mock_probe_app import SECOND_TOKEN, SESSION_TOKEN, create_probe_app

BASE = "http://testserver/"


@dataclass
class FakeAuth:
    token: str = SESSION_TOKEN
    status: str = "ready"
    redact_values: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        self.redact_values = (self.token, self.token.split(" ", 1)[-1])

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": self.token}

    def headers_for(self, url: str, root: str) -> dict[str, str]:
        if (urlsplit(url).hostname or "") != (urlsplit(root).hostname or ""):
            return {}
        return dict(self.headers)

    def scrub(self, text: str) -> str:
        out = text or ""
        for v in self.redact_values:
            out = out.replace(v, "[REDACTED]")
        return out


@dataclass
class Ctx:
    extra: dict[str, Any] = field(default_factory=dict)
    profile: str = "baseline"


def ctx(*, auth: bool = False, second: bool = False, **extra: Any) -> Ctx:
    e: dict[str, Any] = dict(extra)
    if auth:
        e["_session_auth"] = FakeAuth()
    if second:
        e["_secondary_session_auth"] = FakeAuth(token=SECOND_TOKEN)
    return Ctx(extra=e)


def probe_client(**kw: Any) -> TestClient:
    return TestClient(create_probe_app(**kw))


def waf_client() -> TestClient:
    return TestClient(create_waf_challenge_app())


def seen(client: TestClient) -> list[dict[str, Any]]:
    return list(client.app.state.seen)
