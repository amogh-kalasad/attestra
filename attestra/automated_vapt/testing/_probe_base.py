"""Shared plumbing for the WP2 safe web/API probe pack (B-01..B-07, C-05, C-06).

Every probe module exports ``META`` ([[ProbeMeta]]) and ``run(client, base_url, *, ctx)``
returning the standard module dict plus ``status_hint`` and ``validity_samples``
(PHASE2 §3.6). This module only provides the common pieces:

- [[ProbeMeta]]: tier, request budget, WSTG refs; ``mutating`` is always False.
- [[ProbeSession]]: bounded, rate-limited GET/HEAD/OPTIONS sender. It never follows
  redirects, sends session headers only to the target origin, classifies each response
  through the FND-01 response classifier and stops early on WAF / challenge / 429.
- Flag helpers ([[probes_web_safe_enabled]], [[api_import_enabled]], [[graphql_probe_enabled]])
  that read ``attestra.config`` when INT has added the attribute, else the env var.
  All default to off.

The response classifier is WP1's ``core/response_classifier.py`` (FND-01). It is imported
lazily; when it is not importable (WP1 not landed yet) [[_fallback_classify]] applies the
same contract conservatively so blocked/challenge pages are never read as app content.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from attestra.automated_vapt.testing._http import request_pair
from attestra.automated_vapt.testing._session import ctx_extra, ready_auth, same_origin, scrub_pair

# @lat: [[web-api-probes#Probe contract]]

SAFE_PROBE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# Classes that mean "the target's edge, not the application, answered": the case is BLOCKED.
BLOCKING_CLASSES = frozenset({"waf_block", "challenge", "rate_limited"})
EVIDENCE_BODY_CAP = 8_000
SKIP_DISABLED_BY_FLAG = "disabled_by_flag"
SKIP_NO_AUTH = "no_auth_session"
SKIP_NO_SECOND_ROLE = "no_second_role"


@dataclass(frozen=True)
class ProbeMeta:
    test_id: str
    category: str
    safety_tier: str  # T0 passive | T1 safe-active read-only
    request_budget: int
    mutating: bool = False
    auth_required: bool = False
    wstg_refs: tuple[str, ...] = ()
    pe_refs: tuple[str, ...] = ()
    cwe_refs: tuple[str, ...] = ()

    def public(self) -> dict[str, Any]:
        return {
            "test_id": self.test_id,
            "safety_tier": self.safety_tier,
            "request_budget": self.request_budget,
            "mutating": self.mutating,
            "auth_required": self.auth_required,
            "wstg_refs": list(self.wstg_refs),
            "cwe_refs": list(self.cwe_refs),
        }


# ---------------------------------------------------------------- flags (off by default)


def _flag(attr: str, env: str) -> bool:
    """Env var when set (live override, also used by tests), else ``config.<attr>``, else off."""
    raw = os.environ.get(env)
    if raw is not None and raw.strip() != "":
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    try:
        from attestra import config

        if hasattr(config, attr):
            return bool(getattr(config, attr))
    except Exception:  # noqa: BLE001 - config import problems must not enable probes
        pass
    return False


def probes_web_safe_enabled() -> bool:
    """``ATTESTRA_PROBES_WEB_SAFE`` (default 0): CORS, HOSTHDR, OREDIR, CACHE, SSIND."""
    return _flag("PROBES_WEB_SAFE", "ATTESTRA_PROBES_WEB_SAFE")


def api_import_enabled() -> bool:
    """``ATTESTRA_API_IMPORT_ENABLED`` (default 0): OpenAPI/Postman/HAR import (C-01..C-04)."""
    return _flag("API_IMPORT_ENABLED", "ATTESTRA_API_IMPORT_ENABLED")


def graphql_probe_enabled() -> bool:
    """``ATTESTRA_GRAPHQL_PROBE`` (default 0): GraphQL detection/introspection (C-05)."""
    return _flag("GRAPHQL_PROBE", "ATTESTRA_GRAPHQL_PROBE")


def probe_delay_s() -> float:
    """Pause between probe requests (``ATTESTRA_PROBE_DELAY_MS``, default 250 ms, max 5 s)."""
    raw = (os.environ.get("ATTESTRA_PROBE_DELAY_MS") or "").strip()
    try:
        ms = int(raw) if raw else 250
    except ValueError:
        ms = 250
    return max(0, min(ms, 5000)) / 1000.0


# ---------------------------------------------------------------- classification


@dataclass(frozen=True)
class _FallbackClassification:
    cls: str
    reasons: tuple[str, ...]
    confidence: float


def _hdr(headers: Any, name: str) -> str:
    low = name.lower()
    try:
        for k, v in (headers or {}).items():
            if str(k).lower() == low:
                return str(v)
    except Exception:  # noqa: BLE001
        return ""
    return ""


def _fallback_classify(status: int | None, headers: Any, body: str = "", *, error: str | None = None) -> Any:
    """Conservative stand-in for FND-01 used only when WP1's classifier is not importable."""
    text = (body or "")[:20_000]
    if status is None or error:
        return _FallbackClassification("network_failed", ("fallback", "no_status"), 0.9)
    try:
        from attestra.auth_web.session_guard import _CHALLENGE_BODY_RE as chal
    except Exception:  # noqa: BLE001
        chal = None
    if _hdr(headers, "cf-mitigated").lower() == "challenge" or (chal is not None and chal.search(text)):
        return _FallbackClassification("challenge", ("fallback", "challenge_marker"), 0.9)
    if status == 429 or _hdr(headers, "ratelimit-remaining").strip() == "0":
        return _FallbackClassification("rate_limited", ("fallback", "429_or_remaining_0"), 0.9)
    waf_hdr = bool(_hdr(headers, "x-sucuri-id") or _hdr(headers, "x-sucuri-block"))
    cf = bool(_hdr(headers, "cf-ray")) or _hdr(headers, "server").lower() == "cloudflare"
    lower = text.lower()
    block_body = any(s in lower for s in ("attention required", "access denied", "reference #", "request blocked", "web application firewall"))
    if status in (403, 406) or status >= 500:
        if waf_hdr or (cf and block_body) or ("reference #" in lower and "akamai" in lower):
            return _FallbackClassification("waf_block", ("fallback", "waf_marker"), 0.8)
    if 520 <= status <= 526:
        return _FallbackClassification("origin_error", ("fallback", "cf_52x"), 0.7)
    if 200 <= status < 300:
        return _FallbackClassification("app_ok", ("fallback",), 0.6)
    if 300 <= status < 400:
        loc = _hdr(headers, "location").lower()
        if any(p in loc for p in ("/login", "/signin", "/sign-in", "/auth")):
            return _FallbackClassification("auth_redirect", ("fallback",), 0.6)
        return _FallbackClassification("app_ok", ("fallback", "redirect"), 0.5)
    if status in (401, 403):
        return _FallbackClassification("app_auth_denied", ("fallback",), 0.5)
    if status in (404, 410):
        return _FallbackClassification("not_found", ("fallback",), 0.7)
    if status >= 500:
        return _FallbackClassification("origin_error", ("fallback",), 0.6)
    return _FallbackClassification("unknown", ("fallback",), 0.3)


class ValiditySample(dict):
    """JSON-safe view of one FND-01 ``Classification`` (``cls`` / ``reasons`` / ``confidence``).

    Module results are persisted with plain ``json.dumps`` (orchestrator ``result_json``),
    so samples must serialise even before INT strips them. Attribute access matches the
    ``Classification`` contract; ``cls`` is the class *value* string, which compares and
    hashes equal to the ``ResponseClass`` StrEnum member.
    """

    @property
    def cls(self) -> str:
        return str(self.get("cls") or "unknown")

    @property
    def reasons(self) -> tuple[str, ...]:
        return tuple(self.get("reasons") or ())

    @property
    def confidence(self) -> float:
        return float(self.get("confidence") or 0.0)

    @classmethod
    def of(klass, c: Any) -> ValiditySample:
        if isinstance(c, ValiditySample):
            return c
        cls = getattr(c, "cls", c)
        return klass(
            cls=str(getattr(cls, "value", cls) or "unknown"),
            reasons=[str(r)[:80] for r in (getattr(c, "reasons", ()) or ())][:6],
            confidence=float(getattr(c, "confidence", 0.0) or 0.0),
        )


def classify(
    status: int | None, headers: Any, body: str = "", *, authed: bool = False, error: str | None = None
) -> ValiditySample:
    """Classify one response through FND-01 (lazy import), else the conservative fallback."""
    try:
        from attestra.automated_vapt.core.response_classifier import classify_response
    except ImportError:
        return ValiditySample.of(_fallback_classify(status, headers, body, error=error))
    hdrs = {str(k): str(v) for k, v in (headers or {}).items()} if headers else {}
    return ValiditySample.of(classify_response(status, hdrs, body or "", authed=authed, error=error))


def class_name(c: Any) -> str:
    if isinstance(c, dict):
        return str(c.get("cls") or "unknown")
    cls = getattr(c, "cls", c)
    return str(getattr(cls, "value", cls) or "unknown")


def status_from_samples(
    samples: list[Any], *, finding: bool, statuses: list[int | None] | None = None
) -> str | None:
    """Case status hint from classified samples (FND-06 vocabulary); None = default mapping.

    A finding keeps the default mapping. Otherwise any WAF/challenge/429 sample makes the
    case BLOCKED, and a case with no usable application response is INCONCLUSIVE (never
    PASSED). ``unknown`` counts as usable only when an HTTP status < 500 was received
    (for example a plain 3xx the classifier has no class for).
    """
    if finding:
        return None
    if not samples:
        return "INCONCLUSIVE"
    names = [class_name(s) for s in samples]
    if any(n in BLOCKING_CLASSES for n in names):
        return "BLOCKED"
    sts = list(statuses or [])
    usable = 0
    for i, n in enumerate(names):
        if n in {"network_failed", "origin_error"}:
            continue
        if n == "unknown":
            st = sts[i] if i < len(sts) else None
            if st is None or int(st) >= 500:
                continue
        usable += 1
    if not usable:
        return "INCONCLUSIVE"
    return None


# ---------------------------------------------------------------- bounded sender


class BudgetExceeded(RuntimeError):
    pass


@dataclass
class ProbeSession:
    """Bounded, rate-limited, redirect-free request helper for one probe run."""

    client: Any
    base_url: str
    meta: ProbeMeta
    auth: Any = None
    delay_s: float | None = None
    sent: int = 0
    samples: list[Any] = field(default_factory=list)
    requests_log: list[dict[str, Any]] = field(default_factory=list)
    halted_reason: str = ""
    _last: float = 0.0

    @property
    def remaining(self) -> int:
        return max(0, self.meta.request_budget - self.sent)

    @property
    def halted(self) -> bool:
        return bool(self.halted_reason)

    def can_send(self) -> bool:
        return not self.halted and self.remaining > 0

    def send(self, method: str, url: str, *, headers: dict[str, str] | None = None, authed: bool = True) -> Any:
        """Send one request (GET/HEAD/OPTIONS only). Returns the HttpPair, or None on failure."""
        m = (method or "GET").upper()
        if m not in SAFE_PROBE_METHODS:
            raise ValueError(f"probe method {m} not allowed (read-only probes only)")
        if self.halted:
            return None
        if self.sent >= self.meta.request_budget:
            raise BudgetExceeded(f"{self.meta.test_id} request budget {self.meta.request_budget} exhausted")
        delay = probe_delay_s() if self.delay_s is None else self.delay_s
        if delay and self._last:
            wait = delay - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
        hdrs = {str(k): str(v) for k, v in (headers or {}).items()}
        use_auth = authed and self.auth is not None
        if use_auth and hasattr(self.auth, "headers_for"):
            for k, v in (self.auth.headers_for(url, self.base_url) or {}).items():
                hdrs.setdefault(k, v)
        self.sent += 1
        self._last = time.monotonic()
        try:
            pair = request_pair(self.client, m, url, headers=hdrs or None, follow_redirects=False)
        except Exception as exc:  # noqa: BLE001 - network failures become samples
            c = classify(None, {}, "", authed=use_auth, error=type(exc).__name__)
            self.samples.append(c)
            self.requests_log.append({"method": m, "url": _safe_url(url), "status": None, "class": class_name(c)})
            return None
        c = classify(pair.status, pair.response_headers, pair.response_body or "", authed=use_auth)
        self.samples.append(c)
        self.requests_log.append({"method": m, "url": _safe_url(url), "status": pair.status, "class": class_name(c)})
        if class_name(c) in BLOCKING_CLASSES:
            # Never retry or evade: stop sending for this probe.
            self.halted_reason = class_name(c)
        return pair

    def last_class(self) -> str:
        return class_name(self.samples[-1]) if self.samples else "unknown"

    def evidence(self, pair: Any, *, body_cap: int = EVIDENCE_BODY_CAP) -> Any:
        """Scrub session values, redact sensitive headers/body, cap the body size."""
        if pair is None:
            return None
        scrub_pair(pair, self.auth)
        try:
            red = pair.redacted()
        except Exception:  # noqa: BLE001
            red = pair
        red.response_body = (red.response_body or "")[:body_cap]
        red.source = "automated_vapt"
        return red


def _safe_url(url: str) -> str:
    try:
        from attestra.proof.redact import redact_url

        return redact_url(url)
    except Exception:  # noqa: BLE001
        return url.split("?", 1)[0]


# ---------------------------------------------------------------- result helpers


def body_sha256(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", "replace")).hexdigest()


def header(headers: Any, name: str) -> str:
    return _hdr(headers, name)


def host_of(url: str) -> str:
    return (urlsplit(url or "").hostname or "").lower()


def engagement_auth(kwargs: dict[str, Any]) -> Any:
    return ready_auth(kwargs)


def secondary_auth(kwargs: dict[str, Any]) -> Any:
    return ready_auth(kwargs, "_secondary_session_auth")


def scope_ok(url: str, base_url: str, kwargs: dict[str, Any]) -> bool:
    """Same origin as the target or the resolved API base; never another host."""
    extra = ctx_extra(kwargs)
    api_root = str(extra.get("_api_base_url") or "")
    return same_origin(url, base_url) or bool(api_root and same_origin(url, api_root))


def not_tested(meta: ProbeMeta, reason: str, detail: str) -> dict[str, Any]:
    return {
        "test_id": meta.test_id,
        "category": meta.category,
        "status_hint": "NOT_TESTED",
        "skip_reason": reason,
        "probe": meta.public(),
        "observations": {"detail": detail},
        "finding_candidate": False,
        "evidence_hints": [],
        "validity_samples": [],
    }


def finish(
    meta: ProbeMeta,
    ps: ProbeSession | None,
    *,
    observations: dict[str, Any],
    finding: bool,
    detail: str,
    confidence: str = "",
    severity: str = "",
    evidence: list[Any] | None = None,
    hints: list[str] | None = None,
    status_hint: str | None = None,
) -> dict[str, Any]:
    """Build the standard module dict (+ status_hint, validity_samples, probe meta)."""
    samples = list(ps.samples) if ps is not None else []
    statuses = [r.get("status") for r in ps.requests_log] if ps is not None else []
    hint = status_hint if status_hint is not None else status_from_samples(samples, finding=finding, statuses=statuses)
    obs = dict(observations)
    obs["detail"] = detail
    if ps is not None:
        obs["requests_sent"] = ps.sent
        obs["request_budget"] = meta.request_budget
        obs["requests"] = ps.requests_log[: meta.request_budget]
        if ps.halted_reason:
            obs["halted_reason"] = ps.halted_reason
        obs["response_classes"] = [class_name(s) for s in samples]
    out: dict[str, Any] = {
        "test_id": meta.test_id,
        "category": meta.category,
        "probe": meta.public(),
        "observations": obs,
        "finding_candidate": bool(finding),
        "detail": detail,
        "evidence_hints": list(hints or []),
        "evidence_pairs": [e for e in (evidence or []) if e is not None],
        "validity_samples": samples,
    }
    if finding:
        out["finding_confidence"] = confidence or "suspected"
        if severity:
            out["severity_hint"] = severity
    if hint:
        out["status_hint"] = hint
    return out
