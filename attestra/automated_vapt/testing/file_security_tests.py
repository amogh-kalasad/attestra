"""SAFE path-traversal / file probes (World-Class Phase 3).

Uses a clearly fake traversal segment (``....//attestra-probe-not-a-file``) and
expects 404/deny. Sets ``finding_candidate`` only when the response body contains
sensitive-file **content markers** (proof). Status alone or a bare ``/etc/passwd``
path string without content is not enough.

Catalogue mapping: not wired into the orchestrator — no deferred catalogue IDs for
file security. Catalogue ``T21`` includes a path-traversal input replay via
[[attestra/automated_vapt/core/replay_checks.py]]. Call [[run]] directly or from a
future catalogue handler.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

from attestra.automated_vapt.testing._http import absolute, request_pair
from attestra.automated_vapt.testing._session import (
    SKIP_NO_AUTH_SESSION,
    probe_urls,
    request_auth,
    resolve_mode,
    skip_result,
)

# @lat: [[architecture#Elite automated security testing#Safe non-destructive probes]]

FAKE_TRAVERSAL = "....//attestra-probe-not-a-file"

# Content proof only — path strings alone do not count.
_SENSITIVE_MARKERS: tuple[str, ...] = (
    "root:x:0:0:",
    "daemon:x:1:1:",
    "[boot loader]",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "<?php",
)

_DEFAULT_PROBES: tuple[tuple[str, str | None], ...] = (
    (f"/{FAKE_TRAVERSAL}", None),
    ("/static/", FAKE_TRAVERSAL),  # path suffix
    ("/", "file"),  # query param
)
_MAX_PROBES = 3


def detect_sensitive_content(body: str) -> list[str]:
    """Return which sensitive content markers appear in ``body`` (pure helper)."""
    text = body or ""
    return [m for m in _SENSITIVE_MARKERS if m in text]


def _engagement_probes(base_url: str, kwargs: dict[str, Any]) -> list[tuple[str, str | None]]:
    urls = probe_urls(base_url, kwargs, api=False, limit=_MAX_PROBES)
    out: list[tuple[str, str | None]] = []
    for u in urls:
        out.append((u, "file"))
    return out or list(_DEFAULT_PROBES)[:_MAX_PROBES]


def _full_url(base_url: str, path: str, param: str | None) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        url = path
        if param is None:
            # append traversal as a path segment
            parts = urlsplit(url)
            new_path = (parts.path or "/").rstrip("/") + "/" + FAKE_TRAVERSAL
            return urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, ""))
        if path.endswith("/") and param == FAKE_TRAVERSAL:
            return url.rstrip("/") + "/" + param.lstrip("/")
        qs = urlencode({param: FAKE_TRAVERSAL})
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}{qs}"
    if param is None:
        return absolute(base_url, path)
    if path.endswith("/") and param == FAKE_TRAVERSAL:
        return absolute(base_url, path + param.lstrip("/"))
    url = absolute(base_url, path)
    qs = urlencode({param: FAKE_TRAVERSAL})
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{qs}"


def run(client, base_url: str, **kwargs) -> dict[str, Any]:
    """Probe fake traversal paths; find only with sensitive content proof."""
    mode, auth = resolve_mode(client, kwargs)
    if mode == "skip":
        return skip_result(
            "FILE",
            "file",
            SKIP_NO_AUTH_SESSION,
            "engagement login profile not ready; skipped default lab traversal probes",
        )
    if kwargs.get("probes"):
        probes = list(kwargs.get("probes") or _DEFAULT_PROBES)[:_MAX_PROBES]
    elif mode == "engagement":
        probes = _engagement_probes(base_url, kwargs)[:_MAX_PROBES]
    else:
        probes = list(_DEFAULT_PROBES)[:_MAX_PROBES]
    observations: list[dict[str, Any]] = []
    evidence = []
    finding = False
    finding_detail = ""

    def _get(full: str):
        if auth is not None:
            return request_auth(client, "GET", full, auth, base_url, follow_redirects=False)
        return request_pair(client, "GET", full, follow_redirects=False)

    for path, param in probes:
        full = _full_url(base_url, path, param)
        pair = _get(full)
        body = pair.response_body or ""
        markers = detect_sensitive_content(body)
        denied = int(pair.status or 0) in (401, 403, 404)
        row = {
            "url": full,
            "status": pair.status,
            "denied_or_missing": denied,
            "sensitive_markers": markers,
        }
        observations.append(row)
        if markers and not finding:
            finding = True
            finding_detail = f"sensitive content markers in response for {full}: {markers}"
            evidence.append(pair)

    return {
        "test_id": "FILE",
        "category": "file",
        "observations": {
            "traversal": FAKE_TRAVERSAL,
            "probes": observations,
            "probe_count": len(observations),
        },
        "finding_candidate": finding,
        "detail": finding_detail or "no sensitive content returned for fake traversal",
        "evidence_hints": [f"GET …{FAKE_TRAVERSAL}"],
        "evidence_pairs": evidence,
    }
