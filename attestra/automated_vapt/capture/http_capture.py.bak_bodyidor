"""Capture HTTP requests and responses with HTTPX into Attestra HttpPair form."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin

import httpx

from attestra.automated_vapt.core import scope_validator
from attestra.auth_web.scope import CrawlScope
from attestra.proof.pair import HttpPair
from attestra.services import ServiceError

# @lat: [[architecture#Elite automated security testing#HTTP capture]]

_DEFAULT_TIMEOUT_S = 15.0
_UA = "attestra-automated-vapt/0.1 (security testing; authorized engagement)"


@dataclass
class CapturedTransaction:
    """One captured HTTP exchange with timing and sanitized report pair."""

    pair: HttpPair
    elapsed_ms: float
    captured_at: str
    raw_request_headers: dict[str, str] = field(default_factory=dict)
    # Sanitized pair for reports/logs (secrets redacted).
    report_pair: HttpPair | None = None

    def to_dict(self) -> dict[str, Any]:
        report = self.report_pair or self.pair.redacted()
        return {
            "method": report.method,
            "url": report.url,
            "status": report.status,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "captured_at": self.captured_at,
            "request_headers": report.request_headers,
            "request_body": report.request_body,
            "response_headers": report.response_headers,
            "response_body": report.response_body[:200_000],
            "source": report.source,
        }


def capture_request(
    method: str,
    url: str,
    *,
    scope: CrawlScope | None = None,
    profile: str = "baseline",
    headers: dict[str, str] | None = None,
    content: str | bytes | None = None,
    cookies: dict[str, str] | None = None,
    client: httpx.Client | None = None,
    follow_redirects: bool = False,
    timeout_s: float = _DEFAULT_TIMEOUT_S,
    check_dns: bool = True,
) -> CapturedTransaction:
    """Perform one in-scope HTTP request and return a captured transaction.

    Never logs bearer tokens or cookies. The ``report_pair`` is always redacted.
    """
    method_u = (method or "GET").upper()
    scope_validator.validate_method(method_u, profile)
    absolute = url.strip()
    if scope is not None:
        scope_validator.validate_target_url(absolute, scope, check_dns=check_dns)

    req_headers = {"user-agent": _UA, **(headers or {})}
    owns_client = client is None
    http = client or httpx.Client(timeout=timeout_s, follow_redirects=follow_redirects)
    started = time.perf_counter()
    captured_at = datetime.now(UTC).isoformat()
    resp: httpx.Response | None = None
    try:
        resp = http.request(
            method_u,
            absolute,
            headers=req_headers,
            content=content,
            cookies=cookies,
        )
        if scope is not None and resp.headers.get("location") and not follow_redirects:
            loc = resp.headers.get("location") or ""
            if loc:
                nxt = urljoin(str(resp.request.url), loc)
                scope_validator.validate_redirect(absolute, nxt, scope)
    finally:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        if owns_client:
            http.close()

    if resp is None:
        raise ServiceError("HTTP capture failed before a response was received")

    req = resp.request
    pair = HttpPair(
        method=method_u,
        url=str(req.url),
        request_headers={k: v for k, v in req.headers.items()},
        request_body=_body_text(content if content is not None else req.content),
        status=resp.status_code,
        response_headers={k: v for k, v in resp.headers.items()},
        response_body=resp.text[:200_000],
        source="automated_vapt_httpx",
    )
    return CapturedTransaction(
        pair=pair,
        elapsed_ms=elapsed_ms,
        captured_at=captured_at,
        raw_request_headers=dict(pair.request_headers),
        report_pair=pair.redacted(),
    )


def _body_text(content: str | bytes | None) -> str:
    if content is None:
        return ""
    if isinstance(content, bytes):
        return content.decode("utf-8", "replace")[:200_000]
    return str(content)[:200_000]
