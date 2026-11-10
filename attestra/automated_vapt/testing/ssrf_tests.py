"""Scoped SSRF canary (catalogue SSRF).

Probes in-scope URL-fetcher parameters with an Attestra-controlled canary marker.
Never targets cloud metadata / link-local by default as the *payload destination*
for production APP_ENV. Lab fixtures may reflect a canary when they fetch the
supplied URL; findings require canary reflection or a clear fetch-error proof.
"""

from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from attestra.automated_vapt.testing._http import absolute, request_pair
from attestra.automated_vapt.testing._session import (
    SKIP_NO_AUTH_SESSION,
    request_auth,
    resolve_mode,
    skip_result,
)

# @lat: [[architecture#Remaining gaps plan (auth depth)]]

CANARY_TOKEN = "attestra-ssrf-canary-7f3a"
_DEFAULT_CANARY_URL = f"https://canary.attestra.invalid/probe?token={CANARY_TOKEN}"

# Destinations we never ask the target to fetch in production (metadata / link-local).
_BLOCKED_HOST_RE = re.compile(
    r"(?i)^(169\.254\.|127\.|0\.0\.0\.0|\[?::1\]?|metadata\.google|"
    r"metadata\.azure|instance-data|localhost)$"
)

_URL_PARAM_NAMES = ("url", "uri", "target", "src", "source", "webhook", "callback", "fetch", "link")
_MAX_PROBES = 6

SKIP_DISABLED = "ssrf_probe_disabled"
SKIP_NO_FETCHER = "no_ssrf_fetcher_param"


def probe_enabled() -> bool:
    """Active SSRF probes require allowlisted APP_ENV or explicit ATTESTRA_AUTOMATED_VAPT_SSRF=1."""
    raw = (os.environ.get("ATTESTRA_AUTOMATED_VAPT_SSRF") or "").strip().lower()
    if raw in ("0", "false", "no", "off"):
        return False
    if raw in ("1", "true", "yes", "on"):
        return True
    from attestra import config

    env = config.parse_app_env() if hasattr(config, "parse_app_env") else getattr(config, "APP_ENV", None)
    allow = getattr(config, "_APP_ENV_BYPASS_ALLOWLIST", frozenset({"local", "test", "development"}))
    return env in allow


def is_blocked_ssrf_destination(url: str) -> bool:
    host = (urlsplit(url or "").hostname or "").strip().lower()
    if not host:
        return True
    if host in {"localhost", "metadata.google.internal", "metadata"}:
        return True
    if host.startswith("169.254.") or host.startswith("127.") or host == "::1":
        return True
    return bool(_BLOCKED_HOST_RE.match(host))


def canary_url() -> str:
    return (os.environ.get("ATTESTRA_SSRF_CANARY_URL") or _DEFAULT_CANARY_URL).strip()


def _with_param(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != name]
    pairs.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), ""))


def _candidate_urls(base_url: str, ctx: Any | None, *, include_lab_default: bool = True) -> list[tuple[str, str]]:
    """Return (url, param_name) pairs that look like URL fetchers."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    if include_lab_default:
        for name in ("url",):
            u = absolute(base_url, "/api/fetch")
            key = f"{u}?{name}"
            if key not in seen:
                seen.add(key)
                out.append((u, name))
    extra = []
    if ctx is not None:
        extra = list((getattr(ctx, "extra", {}) or {}).get("_capture_api_urls") or [])
        for ep in ((getattr(ctx, "extra", {}) or {}).get("_js_api") or {}).get("endpoints_list") or []:
            path = ep.get("path") if isinstance(ep, dict) else getattr(ep, "path", "")
            qkeys = ep.get("query_keys") if isinstance(ep, dict) else getattr(ep, "query_keys", ()) or ()
            for q in qkeys:
                if str(q).lower() in _URL_PARAM_NAMES and path:
                    extra.append(absolute(base_url, str(path)))
    for u in extra:
        low = u.lower()
        if "fetch" in low or "proxy" in low or "webhook" in low or "url=" in low:
            param = "url"
            for name in _URL_PARAM_NAMES:
                if f"{name}=" in low:
                    param = name
                    break
            key = f"{u}|{param}"
            if key not in seen:
                seen.add(key)
                out.append((u.split("?", 1)[0], param))
    return out[:_MAX_PROBES]


def run(client, base_url: str, **kwargs) -> dict[str, Any]:
    ctx = kwargs.get("ctx")
    if not probe_enabled() and not kwargs.get("force"):
        return {
            "test_id": "SSRF",
            "category": "injection",
            "status_hint": "SKIPPED",
            "skip_reason": SKIP_DISABLED,
            "observations": {"detail": "SSRF canary disabled outside local/test/development (set ATTESTRA_AUTOMATED_VAPT_SSRF=1)"},
            "finding_candidate": False,
            "evidence_hints": [],
        }

    mode, auth = resolve_mode(client, kwargs)
    if mode == "skip":
        return skip_result(
            "SSRF",
            "injection",
            SKIP_NO_AUTH_SESSION,
            "engagement login profile not ready; skipped lab /api/fetch SSRF probes",
        )

    canary = canary_url()
    if is_blocked_ssrf_destination(canary):
        # Misconfigured canary — refuse rather than point at metadata.
        return {
            "test_id": "SSRF",
            "category": "injection",
            "status_hint": "SKIPPED",
            "skip_reason": SKIP_DISABLED,
            "observations": {"detail": "canary URL host is blocked (metadata/loopback)"},
            "finding_candidate": False,
            "evidence_hints": [],
        }

    candidates = _candidate_urls(base_url, ctx, include_lab_default=(mode != "engagement"))
    if not candidates:
        return {
            "test_id": "SSRF",
            "category": "injection",
            "status_hint": "SKIPPED",
            "skip_reason": SKIP_NO_FETCHER,
            "observations": {"detail": "no URL-fetcher parameters discovered"},
            "finding_candidate": False,
            "evidence_hints": [],
        }

    observations: list[dict[str, Any]] = []
    evidence = []
    finding = False
    for endpoint, param in candidates:
        probe = _with_param(endpoint, param, canary)
        if auth is not None:
            pair = request_auth(client, "GET", probe, auth, base_url, follow_redirects=False)
        else:
            pair = request_pair(client, "GET", probe, follow_redirects=False)
        body = pair.response_body or ""
        reflected = CANARY_TOKEN in body or "attestra-ssrf-canary" in body.lower()
        # Lab vulnerable fetcher echoes body with canary= from our token query.
        lab_proof = "canary=" in body and CANARY_TOKEN.split("-")[-1] in body
        # Also accept lab's internal-service-banner when it fetched a blocked host *if* the
        # caller forced a metadata URL in tests — production path never sends those.
        row = {
            "url": probe,
            "status": pair.status,
            "canary_reflected": reflected or lab_proof,
            "param": param,
        }
        observations.append(row)
        if reflected or lab_proof:
            finding = True
            evidence.append(pair)
            break

    return {
        "test_id": "SSRF",
        "category": "injection",
        "observations": {
            "probes": observations,
            "canary": canary,
            "finding": finding,
        },
        "finding_candidate": finding,
        "evidence_pairs": evidence,
        "evidence_hints": [f"SSRF canary via {p}" for _, p in candidates[:3]],
    }
