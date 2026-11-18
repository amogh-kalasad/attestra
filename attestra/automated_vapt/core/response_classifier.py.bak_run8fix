"""Shared HTTP response classifier (FND-01).

Pure module: no network I/O, no database, no logging. Every automated test module
uses :func:`classify_response` to tell a genuine application control (401/403 from
the app, redirect to the login page) apart from infrastructure noise (WAF block
pages, CDN challenges, rate limiting, network failures, expired sessions).

Rule: a 401/403 is ``APP_AUTH_DENIED`` only when no WAF/challenge marker is present
and the body is not a known block page. Even then a module must also prove that the
authenticated request to the same URL returned application content (``APP_OK``)
before it records "auth enforced" (see :func:`proves_enforcement`).

``reasons`` only ever carry status codes, header *names* and marker labels, never
header values, cookies, tokens or body text.
"""

# @lat: [[run-validity-and-policy#Response classifier]]

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any
from urllib.parse import urlsplit

try:  # Reuse the session guard's challenge regex (import only, read-only).
    from attestra.auth_web.session_guard import _CHALLENGE_BODY_RE as _GUARD_CHALLENGE_RE
except Exception:  # pragma: no cover - optional dependency chain
    _GUARD_CHALLENGE_RE = None


class ResponseClass(str, Enum):
    """Contract §3.1 (string values are persisted; never rename)."""

    APP_OK = "app_ok"
    APP_AUTH_DENIED = "app_auth_denied"
    AUTH_REDIRECT = "auth_redirect"
    WAF_BLOCK = "waf_block"
    CHALLENGE = "challenge"
    RATE_LIMITED = "rate_limited"
    AUTH_EXPIRED = "auth_expired"
    ORIGIN_ERROR = "origin_error"
    NETWORK_FAILED = "network_failed"
    NOT_FOUND = "not_found"
    UNKNOWN = "unknown"

    def __str__(self) -> str:  # StrEnum behaviour on 3.11+ and older
        return self.value


@dataclass(frozen=True)
class Classification:
    cls: ResponseClass
    reasons: tuple[str, ...] = ()
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {"cls": self.cls.value, "reasons": list(self.reasons), "confidence": round(float(self.confidence), 2)}


#: Classes that mean "the infrastructure, not the application, answered".
BLOCKING_CLASSES = frozenset({ResponseClass.WAF_BLOCK, ResponseClass.CHALLENGE, ResponseClass.RATE_LIMITED})
#: Classes that are application answers usable for a verdict.
USABLE_CLASSES = frozenset(
    {
        ResponseClass.APP_OK,
        ResponseClass.APP_AUTH_DENIED,
        ResponseClass.AUTH_REDIRECT,
        ResponseClass.NOT_FOUND,
        ResponseClass.ORIGIN_ERROR,
        ResponseClass.UNKNOWN,
    }
)

# ------------------------------------------------------------------ markers

# Strong interstitial markers: a challenge at any status code.
_CHALLENGE_BODY_RE = re.compile(
    r"(?i)just\s+a\s+moment\.\.\.|cdn-cgi/challenge-platform|cf-browser-verification|__cf_chl_|"
    r"_cf_chl_opt|verifying\s+you\s+are\s+human|checking\s+your\s+browser\s+before|"
    r"enable\s+javascript\s+and\s+cookies\s+to\s+continue|ddos-guard|"
    r"awswaf-captcha|/_Incapsula_Resource\?.*?captcha|px-captcha"
)
# Weak markers (a login page may legitimately embed a CAPTCHA widget): only on >= 400.
_WEAK_CHALLENGE_BODY_RE = re.compile(
    r"(?i)challenges\.cloudflare\.com/turnstile|cf-turnstile|g-recaptcha|recaptcha/api\.js|"
    r"hcaptcha\.com|h-captcha|captcha-delivery\.com"
)

# (label, regex) block-page body markers; label goes into reasons.
_BLOCK_BODY_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("cloudflare_block", re.compile(r"(?i)attention\s+required!?\s*\|\s*cloudflare|sorry,\s+you\s+have\s+been\s+blocked|"
                                    r"cf-error-code|error\s+code:?\s*10(?:0\d|1\d|20)\b|cloudflare\s+ray\s+id")),
    ("akamai_block", re.compile(r"(?i)access\s+denied[\s\S]{0,400}reference\s*#\s*\d+\.[0-9a-f]+|errors\.edgesuite\.net")),
    ("sucuri_block", re.compile(r"(?i)sucuri\s+website\s+firewall|access\s+denied\s*-\s*sucuri|cloudproxy@sucuri")),
    ("imperva_block", re.compile(r"(?i)incapsula\s+incident\s+id|_incapsula_resource|powered\s+by\s+imperva")),
    ("aws_waf_block", re.compile(r"(?i)request\s+blocked\.?[\s\S]{0,300}cloudfront|generated\s+by\s+cloudfront|"
                                 r"the\s+request\s+could\s+not\s+be\s+satisfied")),
    ("f5_asm_block", re.compile(r"(?i)the\s+requested\s+url\s+was\s+rejected\.\s+please\s+consult\s+with\s+your\s+administrator|"
                                r"your\s+support\s+id\s+is")),
    ("modsecurity_block", re.compile(r"(?i)mod_security|modsecurity|this\s+error\s+was\s+generated\s+by\s+mod_security")),
    ("barracuda_block", re.compile(r"(?i)barracuda\s+(?:networks|web\s+application\s+firewall)|barra_counter_session")),
    ("generic_waf_block", re.compile(r"(?i)web\s+application\s+firewall|request\s+rejected\s+by\s+(?:the\s+)?(?:waf|firewall)|"
                                     r"blocked\s+by\s+(?:the\s+)?(?:waf|web\s+application\s+firewall|security\s+polic)")),
)

# Header names (lower) that on their own mark a WAF block response (with status >= 400).
_WAF_BLOCK_HEADERS: tuple[tuple[str, str], ...] = (
    ("x-sucuri-block", "sucuri"),
    ("x-amzn-waf-action", "aws_waf"),
    ("x-datadome", "datadome"),
    ("x-px-block", "perimeterx"),
)
# Header names that identify a CDN/WAF in path but are not a block on their own.
_CDN_HEADERS = ("cf-ray", "x-sucuri-id", "x-iinfo", "x-cdn", "x-akamai-transformed", "akamai-grn", "x-amz-cf-id")

_RATE_HEADERS = ("ratelimit-remaining", "x-ratelimit-remaining", "x-rate-limit-remaining")

DEFAULT_LOGIN_PATH_RE = re.compile(
    r"(?i)/(?:log-?in|sign-?in|signin|auth(?:enticate|orize)?|sso|saml|oauth2?|openid-connect|"
    r"account/login|users/sign_in|session/new|sessions/new|logon|cas/login)(?:[/?#.]|$)"
)
_EXPIRED_BODY_RE = re.compile(
    r"(?i)session[_\s-]*(?:has\s+)?expired|token[_\s-]*(?:has\s+)?expired|jwt\s+expired|"
    r"invalid[_\s-]*session|not\s+authenticated|please\s+(?:log|sign)\s*in\s+again"
)
_HTML_LOGIN_FORM_RE = re.compile(r"(?is)<form[^>]+(?:login|signin|sign-in)[^>]*>.*?type=[\"']?password")


def _lower_headers(headers: Mapping[str, Any] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in (headers or {}).items():
        out[str(k).lower()] = str(v)
    return out


def _is_login_location(location: str, login_paths: Sequence[str]) -> bool:
    path = urlsplit(location or "").path or (location or "").split("?", 1)[0]
    if not path:
        return False
    low = path.lower()
    for p in login_paths or ():
        lp = str(p or "").strip().lower()
        if lp and (low == lp or low.startswith(lp.rstrip("/") + "/") or low.rstrip("/") == lp.rstrip("/")):
            return True
    return bool(DEFAULT_LOGIN_PATH_RE.search(low))


def _same_site(location: str, request_url: str | None) -> bool | None:
    """True/False when decidable, None when unknown (relative Location or no request URL)."""
    loc_host = (urlsplit(location or "").hostname or "").lower()
    if not loc_host:
        return True  # relative redirect stays on the same origin
    if not request_url:
        return None
    req_host = (urlsplit(request_url).hostname or "").lower()
    if not req_host:
        return None
    if loc_host == req_host:
        return True
    # Same registrable-ish suffix (app.example.com -> login.example.com).
    a, b = loc_host.split("."), req_host.split(".")
    return len(a) >= 2 and len(b) >= 2 and a[-2:] == b[-2:]


def _block_marker(text: str) -> str | None:
    sample = text[:30_000]
    for label, rx in _BLOCK_BODY_MARKERS:
        if rx.search(sample):
            return label
    return None


def _challenge_marker(hdrs: dict[str, str], text: str, code: int) -> str | None:
    if "cf-mitigated" in hdrs:
        return "header:cf-mitigated"
    if "cf-chl-bypass" in hdrs:
        return "header:cf-chl-bypass"
    if hdrs.get("x-amzn-waf-action", "").strip().lower() in ("captcha", "challenge"):
        return "header:x-amzn-waf-action"
    sample = text[:30_000]
    if _CHALLENGE_BODY_RE.search(sample):
        return "body:challenge_marker"
    if code >= 400 and _WEAK_CHALLENGE_BODY_RE.search(sample):
        return "body:captcha_marker"
    if code >= 400 and _GUARD_CHALLENGE_RE is not None and _GUARD_CHALLENGE_RE.search(sample):
        # The guard's regex also matches some block pages; block markers win later.
        if _block_marker(sample) is None:
            return "body:challenge_marker"
    return None


def classify_response(
    status: int | None,
    headers: Mapping[str, str] | None = None,
    body: str = "",
    *,
    authed: bool = False,
    login_paths: Sequence[str] = (),
    error: str | None = None,
    request_url: str | None = None,
) -> Classification:
    """Classify one HTTP response. Pure and deterministic.

    ``authed`` means the request carried the engagement session; a 401 or
    redirect-to-login then reads as ``AUTH_EXPIRED`` instead of a control.
    ``request_url`` (optional, additive to the frozen contract) lets the classifier
    tell same-site login redirects from off-site ones.
    """
    if status is None or int(status or 0) <= 0:
        why = "network_error" if error else "no_status"
        return Classification(ResponseClass.NETWORK_FAILED, (why,), 1.0)
    code = int(status)
    hdrs = _lower_headers(headers)
    text = body or ""
    cdn = tuple(f"header:{h}" for h in _CDN_HEADERS if h in hdrs)

    # 1. challenge (any status; a 200 challenge interstitial is still a challenge)
    chal = _challenge_marker(hdrs, text, code)
    if chal:
        return Classification(ResponseClass.CHALLENGE, (f"status:{code}", chal, *cdn), 0.95)

    # 2. rate limiting
    if code == 429:
        return Classification(ResponseClass.RATE_LIMITED, ("status:429", *cdn), 1.0)
    if code >= 400:
        if "retry-after" in hdrs and code in (503, 509):
            return Classification(ResponseClass.RATE_LIMITED, (f"status:{code}", "header:retry-after"), 0.85)
        for h in _RATE_HEADERS:
            if hdrs.get(h, "").strip() == "0":
                return Classification(ResponseClass.RATE_LIMITED, (f"status:{code}", f"header:{h}=0"), 0.85)

    # 3. WAF / CDN block pages
    if code >= 400:
        for h, label in _WAF_BLOCK_HEADERS:
            if h in hdrs:
                return Classification(ResponseClass.WAF_BLOCK, (f"status:{code}", f"header:{h}", f"waf:{label}"), 0.95)
        marker = _block_marker(text)
        if marker:
            return Classification(ResponseClass.WAF_BLOCK, (f"status:{code}", f"body:{marker}", *cdn), 0.95)
        server = hdrs.get("server", "").lower()
        if code in (403, 406, 409, 419, 999) and "akamaighost" in server:
            return Classification(ResponseClass.WAF_BLOCK, (f"status:{code}", "server:akamaighost"), 0.85)
        if code == 403 and "cloudflare" in server and not text.strip():
            return Classification(ResponseClass.WAF_BLOCK, (f"status:{code}", "server:cloudflare", "body:empty"), 0.75)

    # 4. network-ish origin errors
    if 520 <= code <= 527 or code == 530:
        return Classification(ResponseClass.ORIGIN_ERROR, (f"status:{code}", "cdn_origin_error", *cdn), 0.95)
    if code >= 500:
        return Classification(ResponseClass.ORIGIN_ERROR, (f"status:{code}",), 0.9)

    # 5. redirects
    if 300 <= code < 400:
        loc = hdrs.get("location", "")
        if loc and _is_login_location(loc, login_paths):
            if authed:
                return Classification(ResponseClass.AUTH_EXPIRED, (f"status:{code}", "redirect:login"), 0.9)
            same = _same_site(loc, request_url)
            if same is False:
                return Classification(ResponseClass.AUTH_REDIRECT, (f"status:{code}", "redirect:login", "offsite_sso"), 0.6)
            return Classification(ResponseClass.AUTH_REDIRECT, (f"status:{code}", "redirect:login"), 0.9)
        return Classification(ResponseClass.UNKNOWN, (f"status:{code}", "redirect:non_login"), 0.5)

    # 6. app 401/403
    if code == 401:
        if authed:
            return Classification(ResponseClass.AUTH_EXPIRED, ("status:401", "authed_request"), 0.85)
        return Classification(ResponseClass.APP_AUTH_DENIED, ("status:401", *cdn), 0.9 if not cdn else 0.8)
    if code == 403:
        if authed and _EXPIRED_BODY_RE.search(text[:20_000]):
            return Classification(ResponseClass.AUTH_EXPIRED, ("status:403", "body:expired_marker"), 0.8)
        return Classification(ResponseClass.APP_AUTH_DENIED, ("status:403", *cdn), 0.85 if not cdn else 0.7)
    if code in (404, 410):
        return Classification(ResponseClass.NOT_FOUND, (f"status:{code}",), 1.0)

    # 7. success
    if 200 <= code < 300:
        if authed and (_EXPIRED_BODY_RE.search(text[:4000]) and len(text) < 4000):
            return Classification(ResponseClass.AUTH_EXPIRED, (f"status:{code}", "body:expired_marker"), 0.7)
        if authed and _HTML_LOGIN_FORM_RE.search(text[:20_000]):
            return Classification(ResponseClass.AUTH_EXPIRED, (f"status:{code}", "body:login_form"), 0.6)
        return Classification(ResponseClass.APP_OK, (f"status:{code}",), 0.9)

    return Classification(ResponseClass.UNKNOWN, (f"status:{code}",), 0.5)


def classify_pair(pair: Any, *, authed: bool = False, login_paths: Sequence[str] = ()) -> Classification:
    """Classify an ``HttpPair``-like object (``status``, ``response_headers``, ``response_body``, ``url``)."""
    if pair is None:
        return Classification(ResponseClass.NETWORK_FAILED, ("no_response",), 1.0)
    return classify_response(
        getattr(pair, "status", None),
        getattr(pair, "response_headers", None) or {},
        getattr(pair, "response_body", "") or "",
        authed=authed,
        login_paths=login_paths,
        error=getattr(pair, "error", None),
        request_url=getattr(pair, "url", None),
    )


def classify_httpx(resp: Any, *, authed: bool = False, login_paths: Sequence[str] = (), error: str | None = None) -> Classification:
    """Classify an httpx/Starlette ``Response`` (or ``None`` on transport errors)."""
    if resp is None:
        return Classification(ResponseClass.NETWORK_FAILED, ("network_error" if error else "no_response",), 1.0)
    url = None
    try:
        url = str(resp.request.url)
    except Exception:
        url = None
    return classify_response(
        int(getattr(resp, "status_code", 0) or 0) or None,
        dict(getattr(resp, "headers", {}) or {}),
        getattr(resp, "text", "") or "",
        authed=authed,
        login_paths=login_paths,
        error=error,
        request_url=url,
    )


def is_security_control_evidence(c: Classification) -> bool:
    """True only for application denials and same-site login redirects."""
    return c.cls in (ResponseClass.APP_AUTH_DENIED, ResponseClass.AUTH_REDIRECT)


def is_blocking(c: Classification) -> bool:
    return c.cls in BLOCKING_CLASSES


def is_usable(c: Classification) -> bool:
    return c.cls in USABLE_CLASSES


def proves_enforcement(unauth: Classification, authed: Classification) -> bool:
    """FND-04: enforcement needs an app denial/login redirect AND authed ``APP_OK`` on the same URL."""
    return is_security_control_evidence(unauth) and authed.cls is ResponseClass.APP_OK


def blocking_hint(samples: Sequence[Classification]) -> str | None:
    """Status hint for a case whose decisive samples were infrastructure answers."""
    classes = {s.cls for s in samples}
    if classes & BLOCKING_CLASSES:
        return "BLOCKED"
    if ResponseClass.AUTH_EXPIRED in classes:
        return "BLOCKED"
    if classes and classes <= {ResponseClass.NETWORK_FAILED}:
        return "INCONCLUSIVE"
    return None


def skip_reason_for(samples: Sequence[Classification]) -> str:
    """Value-free skip reason code for a non-pass result (pre-FND-06 orchestrators map it to SKIPPED)."""
    classes = {s.cls for s in samples}
    if ResponseClass.CHALLENGE in classes:
        return "challenge_detected"
    if ResponseClass.WAF_BLOCK in classes:
        return "waf_blocked"
    if ResponseClass.RATE_LIMITED in classes:
        return "rate_limited"
    if ResponseClass.AUTH_EXPIRED in classes:
        return "auth_expired"
    if ResponseClass.NETWORK_FAILED in classes:
        return "network_failed"
    return "inconclusive"


def samples_to_json(samples: Sequence[Classification]) -> list[dict[str, Any]]:
    return [s.to_dict() for s in samples]


def mark_blocked_if_needed(result: dict[str, Any], samples: Sequence[Classification]) -> dict[str, Any]:
    """When a module found nothing but its samples were infrastructure answers, mark it
    ``BLOCKED``/``INCONCLUSIVE`` (with a ``skip_reason`` so pre-FND-06 orchestrators map it
    to SKIPPED rather than PASSED). Findings are left untouched.
    """
    if result.get("finding_candidate") or result.get("status_hint"):
        return result
    hint = blocking_hint(samples)
    if hint:
        result["status_hint"] = hint
        result["skip_reason"] = skip_reason_for(samples)
    return result
