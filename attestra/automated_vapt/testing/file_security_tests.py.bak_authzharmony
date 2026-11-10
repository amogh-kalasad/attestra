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
from urllib.parse import urlencode

from attestra.automated_vapt.testing._http import absolute, request_pair

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


def run(client, base_url: str, **kwargs) -> dict[str, Any]:
    """Probe fake traversal paths; find only with sensitive content proof."""
    probes = list(kwargs.get("probes") or _DEFAULT_PROBES)[:_MAX_PROBES]
    observations: list[dict[str, Any]] = []
    evidence = []
    finding = False
    finding_detail = ""

    for path, param in probes:
        if param is None:
            full = absolute(base_url, path)
        elif path.endswith("/") and param == FAKE_TRAVERSAL:
            full = absolute(base_url, path + param.lstrip("/"))
        else:
            url = absolute(base_url, path)
            qs = urlencode({param: FAKE_TRAVERSAL})
            sep = "&" if "?" in url else "?"
            full = f"{url}{sep}{qs}"

        pair = request_pair(client, "GET", full, follow_redirects=False)
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
