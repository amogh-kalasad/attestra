"""Passive web hygiene checks (headers, security.txt, HSTS) over http_safe only."""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen

from attestra.runner.authorization import AuthorizationError, AuthorizedScope, authorize_target
from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.http_safe import SafeResponse, safe_get
from attestra.runner.scanners.base import ScannerAdapter, ScannerResult

# Referrer-Policy: no finding for the strongest values; Info for strict-origin*; Low otherwise.
_REFERRER_OK = frozenset({"no-referrer", "same-origin"})
_REFERRER_INFO = frozenset({"strict-origin", "strict-origin-when-cross-origin"})
_REFERRER_LOW = frozenset(
    {"no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "unsafe-url"}
)
_WAF_HEADERS = frozenset({"cf-ray", "x-sucuri-id", "x-amz-cf-id", "x-azure-ref"})
# hstspreload.org /api/v2/status values that mean the domain is clearly not on the preload list.
# unknown = not submitted; pending = submitted but not yet shipped; rejected/removed = off the list.
# preloaded / pending-removal / pending-automated-removal mean it is (still) on the list → no finding.
_HSTS_NOT_PRELOADED_STATUSES = frozenset({"unknown", "pending", "rejected", "removed"})
_HSTS_PRELOADED_STATUSES = frozenset({"preloaded", "pending-removal", "pending-automated-removal"})
_VERSION_RE = re.compile(r"\d+\.\d+")
_CSP_DIR_RE = re.compile(r"(?:^|;)\s*([a-z0-9-]+)\b", re.IGNORECASE)

# Cookie names treated as session-like even when Max-Age/Expires is set.
_SESSION_COOKIE_NAMES = frozenset(
    {
        "session",
        "sessionid",
        "sess",
        "sessid",
        "sid",
        "jsessionid",
        "phpsessid",
        "aspxauth",
        "auth",
        "authorization",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "jwt",
        "connect.sid",
        "csrf",
        "csrftoken",
        "xsrf",
        "xsrftoken",
        "_session",
        "rack.session",
    }
)
_COOKIE_FLAGS = ("Secure", "HttpOnly", "SameSite")


def _finding(
    fid: str,
    title: str,
    severity: str,
    cwe: int,
    description: str,
    location: str,
    recommendation: str = "",
    param: str = "",
    variant: str = "",
) -> dict:
    out = {
        "id": fid,
        "title": title,
        "severity": severity,
        "cwe": cwe,
        "description": description,
        "location": location,
    }
    if recommendation:
        out["recommendation"] = recommendation
    if param:
        out["param"] = param
    if variant:
        out["variant"] = variant
    return out


def parent_domain(host: str) -> str | None:
    labels = [p for p in host.lower().strip(".").split(".") if p]
    if len(labels) < 3:
        return None
    return ".".join(labels[1:])


def build_url(pin: PinnedTarget, path: str = "/", *, scheme: str | None = None) -> str:
    scheme = (scheme or pin.scheme).lower()
    path = path if path.startswith("/") else f"/{path}"
    default = 443 if scheme == "https" else 80
    # Keep pin.port only when the scheme matches the pin (custom test ports).
    if scheme == pin.scheme and pin.port != default:
        return f"{scheme}://{pin.host}:{pin.port}{path}"
    return f"{scheme}://{pin.host}{path}"


def _header(headers: dict[str, str], name: str) -> str:
    return (headers.get(name.lower()) or "").strip()


def _csp_directives(csp: str) -> set[str]:
    return {m.group(1).lower() for m in _CSP_DIR_RE.finditer(csp)}


def set_cookie_values(headers: dict[str, str]) -> list[str]:
    """Return every Set-Cookie value. Multiple headers are joined with newlines by http_safe."""
    raw = headers.get("set-cookie")
    if raw is None:
        for key, val in headers.items():
            if key.lower() == "set-cookie":
                raw = val
                break
    if raw is None:
        return []
    if isinstance(raw, (list, tuple)):
        return [str(x).strip() for x in raw if str(x).strip()]
    text = str(raw).strip()
    if not text:
        return []
    # Prefer newline-separated values (http_safe). Also accept a rare single-line list
    # only when there is no Expires= date comma ambiguity — keep split on newlines only.
    return [line.strip() for line in text.split("\n") if line.strip()]


def parse_set_cookie(raw: str) -> dict[str, str] | None:
    """Parse ``name=value; Attr; Attr=val`` into name + lowercase attribute map."""
    text = (raw or "").strip()
    if not text or "=" not in text.split(";", 1)[0]:
        return None
    first, *rest = text.split(";")
    name, _, value = first.strip().partition("=")
    name = name.strip()
    if not name:
        return None
    attrs: dict[str, str] = {"_name": name, "_value": value.strip()}
    for part in rest:
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            ak, _, av = part.partition("=")
            attrs[ak.strip().lower()] = av.strip()
        else:
            attrs[part.lower()] = ""
    return attrs


def is_session_cookie(attrs: dict[str, str]) -> bool:
    """Session cookie: no Max-Age/Expires, or a session-like name.

    Non-session cookies (tracking, prefs, consent) get Info severity for missing flags.
    Session cookies get Low. Documented in lat.md under webcheck cookie flags.
    """
    name = (attrs.get("_name") or "").strip().lower()
    if name in _SESSION_COOKIE_NAMES:
        return True
    # Common prefixes/suffixes: session_*, *_session, *sess*
    if "session" in name or name.endswith("sess") or name.startswith("sess"):
        return True
    has_max_age = "max-age" in attrs
    has_expires = "expires" in attrs
    return not (has_max_age or has_expires)


def _cookie_flag_id(cookie_name: str, flag: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_.-]+", "_", cookie_name.strip())[:80] or "unnamed"
    return f"cookie:{safe}:{flag.lower()}"


def check_cookies(headers: dict[str, str], location: str) -> tuple[list[dict], list[dict]]:
    """One finding per cookie per missing Secure / HttpOnly / SameSite flag.

    Returns ``(findings, check_rows)``. Fully flagged cookies become C5 passed rows.
    No Set-Cookie → one skipped check row (not tested).
    """
    from attestra.checks import FAILED, PASSED, SKIPPED, check_row

    values = set_cookie_values(headers)
    if not values:
        return [], [
            check_row(
                check_id="cookie-flags",
                name="Cookie Secure / HttpOnly / SameSite flags",
                status=SKIPPED,
                source="webcheck",
                evidence="no Set-Cookie header",
            )
        ]

    findings: list[dict] = []
    checks: list[dict] = []
    cwe_for = {"Secure": 614, "HttpOnly": 1004, "SameSite": 1275}
    for raw in values:
        attrs = parse_set_cookie(raw)
        if not attrs:
            continue
        name = attrs["_name"]
        session = is_session_cookie(attrs)
        severity = "low" if session else "info"
        kind = "session" if session else "non-session"
        missing: list[str] = []
        if "secure" not in attrs:
            missing.append("Secure")
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        if "samesite" not in attrs:
            missing.append("SameSite")

        if not missing:
            checks.append(
                check_row(
                    check_id=f"cookie:{re.sub(r'[^a-zA-Z0-9_.-]+', '_', name)[:80]}",
                    name=f"Cookie {name} Secure+HttpOnly+SameSite",
                    status=PASSED,
                    source="webcheck",
                    evidence=raw[:200],
                )
            )
            continue

        for flag in missing:
            fid = _cookie_flag_id(name, flag)
            findings.append(
                _finding(
                    fid,
                    f"Cookie {name} missing {flag} flag",
                    severity,
                    cwe_for[flag],
                    f"{kind} cookie {name!r} is missing the {flag} attribute. Evidence: {raw[:300]}",
                    location,
                    f"Set the {flag} attribute on the {name} cookie"
                    + (" (SameSite=Lax or Strict)." if flag == "SameSite" else "."),
                )
            )
            checks.append(
                check_row(
                    check_id=fid,
                    name=f"Cookie {name} {flag}",
                    status=FAILED,
                    source="webcheck",
                    evidence=raw[:200],
                )
            )
    return findings, checks


# ---------------------------------------------------------------- HTML body: SRI + mixed content
# Parse the already-fetched primary HTML only. Never fetch discovered URLs.

_SRI_KINDS = frozenset({"script", "stylesheet"})
_ACTIVE_MIXED_KINDS = frozenset({"script", "stylesheet", "iframe", "object", "form"})
_PASSIVE_MIXED_KINDS = frozenset({"img", "audio", "video", "source"})
_EVIDENCE_URL_CAP = 20


class _PageResourceParser(HTMLParser):
    """Collect script/link/img/iframe/media/object/form URLs from HTML tags."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.resources: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_l = tag.lower()
        ad = {str(k).lower(): ("" if v is None else str(v)) for k, v in attrs}
        if tag_l == "script":
            src = ad.get("src", "").strip()
            if src:
                self.resources.append(
                    {
                        "kind": "script",
                        "url": src,
                        "integrity": ad.get("integrity", "").strip(),
                    }
                )
            return
        if tag_l == "link":
            rel_tokens = ad.get("rel", "").lower().split()
            if "stylesheet" not in rel_tokens:
                return
            href = ad.get("href", "").strip()
            if href:
                self.resources.append(
                    {
                        "kind": "stylesheet",
                        "url": href,
                        "integrity": ad.get("integrity", "").strip(),
                    }
                )
            return
        if tag_l in {"img", "iframe", "audio", "video", "source"}:
            src = ad.get("src", "").strip()
            if src:
                self.resources.append({"kind": tag_l, "url": src, "integrity": ""})
            return
        if tag_l == "object":
            data = ad.get("data", "").strip()
            if data:
                self.resources.append({"kind": "object", "url": data, "integrity": ""})
            return
        if tag_l == "form":
            action = ad.get("action", "").strip()
            if action:
                self.resources.append({"kind": "form", "url": action, "integrity": ""})


def parse_page_resources(html: str) -> list[dict[str, str]]:
    """Parse HTML into resource dicts with kind, url, and optional integrity."""
    parser = _PageResourceParser()
    try:
        parser.feed(html or "")
        parser.close()
    except Exception:  # noqa: BLE001 - malformed HTML still yields what was collected
        pass
    return parser.resources


def _page_origin(location: str) -> tuple[str, str, int] | None:
    parts = urlsplit(location or "")
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return (parts.scheme.lower(), parts.hostname.lower(), int(port))


def resolve_resource_url(page_url: str, ref: str) -> str:
    """Resolve a resource URL against the page. Protocol-relative uses the page scheme."""
    ref = (ref or "").strip()
    if not ref:
        return ""
    if ref.startswith("//"):
        scheme = urlsplit(page_url).scheme or "https"
        ref = f"{scheme}:{ref}"
    return urljoin(page_url, ref)


def is_same_origin(page_url: str, resource_url: str) -> bool:
    """True when both URLs share scheme, host, and port (defaults applied)."""
    left = _page_origin(page_url)
    right = _page_origin(resource_url)
    if left is None or right is None:
        return False
    return left == right


def _format_url_evidence(urls: list[str], *, cap: int = _EVIDENCE_URL_CAP) -> str:
    unique: list[str] = []
    seen: set[str] = set()
    for u in urls:
        if u in seen:
            continue
        seen.add(u)
        unique.append(u)
    if len(unique) <= cap:
        return "; ".join(unique)
    shown = "; ".join(unique[:cap])
    return f"{shown}; ... and {len(unique) - cap} more"


def _decode_html_body(body: bytes | str | None) -> str | None:
    if body is None:
        return None
    if isinstance(body, bytes):
        return body.decode("utf-8", errors="replace")
    return str(body)


def check_sri(html: str, location: str) -> tuple[list[dict], list[dict]]:
    """Cross-origin script/stylesheet tags missing integrity → one finding.

    Same-origin resources do not need SRI. Severity is Medium when any listed
    URL is a script; otherwise Low. Fingerprint variant is ``sri`` (stable per target).
    """
    from attestra.checks import FAILED, PASSED, check_row

    missing: list[tuple[str, str]] = []  # (kind, absolute url)
    for res in parse_page_resources(html):
        if res["kind"] not in _SRI_KINDS:
            continue
        if res.get("integrity"):
            continue
        abs_url = resolve_resource_url(location, res["url"])
        if not abs_url:
            continue
        origin = _page_origin(abs_url)
        if origin is None:
            continue  # data:, javascript:, blob:, etc.
        if is_same_origin(location, abs_url):
            continue
        missing.append((res["kind"], abs_url))

    if not missing:
        return [], [
            check_row(
                check_id="sri",
                name="Subresource Integrity on cross-origin scripts/styles",
                status=PASSED,
                source="webcheck",
                evidence="no cross-origin script/style without integrity",
            )
        ]

    has_script = any(kind == "script" for kind, _ in missing)
    severity = "medium" if has_script else "low"
    urls = [u for _, u in missing]
    evidence = (
        "Cross-origin script or stylesheet tags have no integrity attribute. "
        f"URLs: {_format_url_evidence(urls)}"
    )
    finding = _finding(
        "sri",
        "External scripts or styles without Subresource Integrity",
        severity,
        353,
        evidence,
        location,
        "Add integrity (and crossorigin) attributes on third-party script and stylesheet tags.",
        variant="sri",
    )
    return [finding], [
        check_row(
            check_id="sri",
            name="Subresource Integrity on cross-origin scripts/styles",
            status=FAILED,
            source="webcheck",
            evidence=evidence[:200],
        )
    ]


def check_mixed_content(
    html: str, location: str, *, scheme: str = "https"
) -> tuple[list[dict], list[dict]]:
    """On https pages, flag http:// subresources as active or passive mixed content.

    Active (script/style/iframe/object/form) → Medium. Passive (img/audio/video/source) → Low.
    Stable variants: ``mixed-content-active`` / ``mixed-content-passive``. Skipped on http.
    """
    from attestra.checks import FAILED, PASSED, SKIPPED, check_row

    if (scheme or "").lower() != "https" and not (location or "").lower().startswith("https://"):
        return [], [
            check_row(
                check_id="mixed-content",
                name="No mixed content on HTTPS pages",
                status=SKIPPED,
                source="webcheck",
                evidence="page is not https",
            )
        ]

    active: list[str] = []
    passive: list[str] = []
    for res in parse_page_resources(html):
        raw = (res.get("url") or "").strip()
        if not raw.lower().startswith("http://"):
            # Relative and protocol-relative URLs are not cleartext http on https pages.
            continue
        kind = res["kind"]
        abs_url = resolve_resource_url(location, raw)
        if kind in _ACTIVE_MIXED_KINDS:
            active.append(abs_url or raw)
        elif kind in _PASSIVE_MIXED_KINDS:
            passive.append(abs_url or raw)

    findings: list[dict] = []
    checks: list[dict] = []
    if active:
        evidence = f"Active mixed content (http://) on an HTTPS page. URLs: {_format_url_evidence(active)}"
        findings.append(
            _finding(
                "mixed-content-active",
                "Active mixed content",
                "medium",
                311,
                evidence,
                location,
                "Load scripts, stylesheets, frames, and form actions over https:// only.",
                variant="mixed-content-active",
            )
        )
        checks.append(
            check_row(
                check_id="mixed-content-active",
                name="No active mixed content",
                status=FAILED,
                source="webcheck",
                evidence=evidence[:200],
            )
        )
    if passive:
        evidence = f"Passive mixed content (http://) on an HTTPS page. URLs: {_format_url_evidence(passive)}"
        findings.append(
            _finding(
                "mixed-content-passive",
                "Passive mixed content",
                "low",
                311,
                evidence,
                location,
                "Load images and media over https:// only (change http:// to https://).",
                variant="mixed-content-passive",
            )
        )
        checks.append(
            check_row(
                check_id="mixed-content-passive",
                name="No passive mixed content",
                status=FAILED,
                source="webcheck",
                evidence=evidence[:200],
            )
        )
    if not findings:
        checks.append(
            check_row(
                check_id="mixed-content",
                name="No mixed content on HTTPS pages",
                status=PASSED,
                source="webcheck",
                evidence="no http:// subresources on https page",
            )
        )
    return findings, checks


def check_html_body(
    body: bytes | str | None, location: str, *, scheme: str = "https"
) -> tuple[list[dict], list[dict]]:
    """Run SRI and mixed-content checks on an already-fetched HTML body."""
    from attestra.checks import SKIPPED, check_row

    text = _decode_html_body(body)
    if text is None:
        return [], []
    if not text.strip():
        return [], [
            check_row(
                check_id="sri",
                name="Subresource Integrity on cross-origin scripts/styles",
                status=SKIPPED,
                source="webcheck",
                evidence="empty response body",
            ),
            check_row(
                check_id="mixed-content",
                name="No mixed content on HTTPS pages",
                status=SKIPPED,
                source="webcheck",
                evidence="empty response body",
            ),
        ]
    findings: list[dict] = []
    checks: list[dict] = []
    sri_f, sri_c = check_sri(text, location)
    findings.extend(sri_f)
    checks.extend(sri_c)
    mix_f, mix_c = check_mixed_content(text, location, scheme=scheme)
    findings.extend(mix_f)
    checks.extend(mix_c)
    return findings, checks


_CSP_PARAM = "Content-Security-Policy"
_CSP_REQUIRED = ("default-src", "object-src", "base-uri", "frame-ancestors")
# Map known issues onto ZAP Baseline alertRef so webcheck and ZAP share a fingerprint.
_CSP_ZAP_VARIANT = {
    ("script-src", "unsafe-inline"): "10055-5",
    ("style-src", "unsafe-inline"): "10055-6",
    ("script-src", "unsafe-eval"): "10055-10",
}


def parse_csp(policy: str) -> dict[str, list[str]]:
    """Parse a Content-Security-Policy header into directive → source tokens."""
    out: dict[str, list[str]] = {}
    for part in (policy or "").split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if not tokens:
            continue
        directive = tokens[0].lower()
        out[directive] = tokens[1:]
    return out


def _csp_source_key(token: str) -> str:
    t = token.strip().lower()
    if t in {"'unsafe-inline'", "unsafe-inline"}:
        return "unsafe-inline"
    if t in {"'unsafe-eval'", "unsafe-eval"}:
        return "unsafe-eval"
    if t == "*":
        return "wildcard"
    if t.startswith("http:"):
        return "http-source"
    return ""


def check_csp_policy(headers: dict[str, str], location: str) -> tuple[list[dict], list[dict]]:
    """C10: one finding per CSP issue (unsafe-*, wildcard, http:, missing directives).

    Variants use ``csp:{directive}:{issue}`` so they merge with ZAP 10055 alerts that
    use the same semantic variant. ``param`` is Content-Security-Policy (ZAP style).
    """
    from attestra.checks import FAILED, PASSED, SKIPPED, check_row

    csp = _header(headers, "content-security-policy")
    if not csp:
        return [], [
            check_row(
                check_id="csp-policy",
                name="Content-Security-Policy analysis",
                status=SKIPPED,
                source="webcheck",
                evidence="no Content-Security-Policy header",
            )
        ]

    directives = parse_csp(csp)
    findings: list[dict] = []
    checks: list[dict] = []
    seen: set[str] = set()

    def _emit(
        fid: str,
        title: str,
        severity: str,
        evidence: str,
        recommendation: str,
        *,
        variant: str = "",
    ) -> None:
        if fid in seen:
            return
        seen.add(fid)
        findings.append(
            _finding(
                fid,
                title,
                severity,
                693,
                evidence,
                location,
                recommendation,
                param=_CSP_PARAM,
                variant=variant or fid,
            )
        )
        checks.append(
            check_row(
                check_id=fid,
                name=title,
                status=FAILED,
                source="webcheck",
                evidence=evidence[:200],
            )
        )

    for req in _CSP_REQUIRED:
        if req in directives:
            continue
        _emit(
            f"csp:missing:{req}",
            f"CSP: {req} directive missing",
            "low",
            f"Content-Security-Policy has no {req} directive. Evidence: {csp[:300]}",
            f"Add {req} with a tight value (for example 'self' or 'none').",
        )

    for directive, sources in directives.items():
        for src in sources:
            kind = _csp_source_key(src)
            if not kind:
                continue
            zap_variant = _CSP_ZAP_VARIANT.get((directive, kind), "")
            if kind == "unsafe-inline":
                _emit(
                    f"csp:{directive}:unsafe-inline",
                    f"CSP: {directive} unsafe-inline",
                    "medium",
                    f"{directive} includes 'unsafe-inline'. Evidence: {directive} {' '.join(sources)}"[:500],
                    f"Remove 'unsafe-inline' from {directive}; use nonces or hashes instead.",
                    variant=zap_variant,
                )
            elif kind == "unsafe-eval":
                _emit(
                    f"csp:{directive}:unsafe-eval",
                    f"CSP: {directive} unsafe-eval",
                    "medium",
                    f"{directive} includes 'unsafe-eval'. Evidence: {directive} {' '.join(sources)}"[:500],
                    f"Remove 'unsafe-eval' from {directive}.",
                    variant=zap_variant,
                )
            elif kind == "wildcard":
                _emit(
                    f"csp:{directive}:wildcard",
                    f"CSP: {directive} wildcard source",
                    "medium",
                    f"{directive} allows wildcard source *. Evidence: {directive} {' '.join(sources)}"[:500],
                    f"Replace * in {directive} with an explicit allow-list.",
                )
            elif kind == "http-source":
                _emit(
                    f"csp:{directive}:http-source",
                    f"CSP: {directive} http: source",
                    "medium",
                    f"{directive} allows http: source {src}. Evidence: {directive} {' '.join(sources)}"[:500],
                    f"Use https: sources only in {directive}; remove {src}.",
                )
    if not findings:
        checks.append(
            check_row(
                check_id="csp-policy",
                name="Content-Security-Policy analysis",
                status=PASSED,
                source="webcheck",
                evidence=csp[:200],
            )
        )
    return findings, checks


def check_csp_base_uri(headers: dict[str, str], location: str) -> dict | None:
    """Compatibility wrapper: missing base-uri finding from [[check_csp_policy]]."""
    findings, _checks = check_csp_policy(headers, location)
    for f in findings:
        if f.get("id") == "csp:missing:base-uri":
            return f
    return None


def check_x_content_type_options(headers: dict[str, str], location: str) -> dict | None:
    """Fail when X-Content-Type-Options is missing or not nosniff."""
    val = _header(headers, "x-content-type-options")
    if val.lower() == "nosniff":
        return None
    evidence = val or "(missing)"
    return _finding(
        "x-content-type-options",
        "X-Content-Type-Options is missing or not nosniff",
        "low",
        693,
        f"X-Content-Type-Options should be nosniff. Evidence: {evidence}",
        location,
        "Set X-Content-Type-Options: nosniff on all responses.",
    )


def check_hsts_present(headers: dict[str, str], location: str, *, scheme: str) -> dict | None:
    """On HTTPS, fail when Strict-Transport-Security is missing or has no max-age."""
    if scheme.lower() != "https":
        return None
    sts = _header(headers, "strict-transport-security")
    if sts and re.search(r"max-age\s*=\s*\d+", sts, re.IGNORECASE):
        return None
    return _finding(
        "hsts-present",
        "HSTS header missing on HTTPS",
        "medium",
        319,
        f"HTTPS response has no usable Strict-Transport-Security header. Evidence: {sts or '(missing)'}",
        location,
        "Send Strict-Transport-Security with a positive max-age on HTTPS responses.",
    )


def check_server_disclosure(headers: dict[str, str], location: str) -> dict | None:
    server = _header(headers, "server")
    if not server:
        return None
    # Bare CDN tokens like "cloudflare" are treated as WAF signatures, not product disclosure.
    if server.lower() in ("cloudflare", "amazons3", "awselb/2.0"):
        return None
    severity = "low" if _VERSION_RE.search(server) else "info"
    return _finding(
        "server-disclosure",
        "Server header discloses software",
        severity,
        200,
        f"Server header discloses software identity. Evidence: Server: {server}",
        location,
        "Remove or genericize the Server header so it does not reveal product or version.",
    )


def check_x_xss_protection(headers: dict[str, str], location: str) -> dict | None:
    val = _header(headers, "x-xss-protection")
    if not val:
        return None
    return _finding(
        "x-xss-protection",
        "X-XSS-Protection legacy value set",
        "info",
        693,
        f"X-XSS-Protection is a legacy header. Evidence: {val}",
        location,
        "Remove X-XSS-Protection; rely on a strong Content-Security-Policy instead.",
    )


def check_referrer_policy(headers: dict[str, str], location: str) -> dict | None:
    val = _header(headers, "referrer-policy")
    if not val:
        return _finding(
            "referrer-policy",
            "Referrer-Policy is not a strict value",
            "low",
            200,
            "Referrer-Policy header is missing.",
            location,
            "Set Referrer-Policy to no-referrer or same-origin.",
        )
    # Take the first token if multiple policies are listed.
    primary = val.split(",")[0].strip().lower()
    if primary in _REFERRER_OK:
        return None
    if primary in _REFERRER_INFO:
        severity = "info"
    else:
        # Known weak values and any other unrecognized value → Low.
        severity = "low"
    return _finding(
        "referrer-policy",
        "Referrer-Policy is not a strict value",
        severity,
        200,
        f"Referrer-Policy is set but not strict. Evidence: {val}",
        location,
        "Set Referrer-Policy to no-referrer or same-origin.",
    )


def check_security_txt(resp: SafeResponse | None, location: str) -> dict | None:
    if resp is None:
        return _finding(
            "security-txt",
            "security.txt missing or invalid",
            "info",
            16,
            "Could not fetch /.well-known/security.txt.",
            location,
        )
    ctype = _header(resp.headers, "content-type").lower()
    body = resp.body.decode("utf-8", errors="replace")
    if resp.status == 404:
        return _finding(
            "security-txt",
            "security.txt missing or invalid",
            "info",
            16,
            "security.txt returned HTTP 404.",
            location,
            "Publish a security.txt at /.well-known/security.txt (RFC 9116).",
        )
    if "text/html" in ctype:
        return _finding(
            "security-txt",
            "security.txt missing or invalid",
            "info",
            16,
            f"security.txt Content-Type is HTML, not text/plain. Evidence: {ctype}",
            location,
        )
    if resp.status >= 400:
        return _finding(
            "security-txt",
            "security.txt missing or invalid",
            "info",
            16,
            f"security.txt returned HTTP {resp.status}.",
            location,
        )
    # Clearly not security.txt: HTML body or no Contact field.
    lowered = body.lower()
    if "<html" in lowered or not re.search(r"(?m)^\s*contact\s*:", body, re.IGNORECASE):
        return _finding(
            "security-txt",
            "security.txt missing or invalid",
            "info",
            16,
            "security.txt body is not a valid security.txt (missing Contact: or looks like HTML).",
            location,
            "Publish RFC 9116 security.txt with at least a Contact field.",
        )
    return None


def check_hsts_on_http(resp: SafeResponse | None, location: str) -> dict | None:
    if resp is None:
        return None
    sts = _header(resp.headers, "strict-transport-security")
    if not sts:
        return None
    return _finding(
        "hsts-on-http",
        "HSTS header sent over plain HTTP",
        "low",
        319,
        f"Strict-Transport-Security was sent on a plain HTTP response. Evidence: {sts[:200]}",
        location,
        "Send HSTS only over HTTPS responses.",
    )


def _hosts_equal(a: str, b: str) -> bool:
    """Compare hostnames ignoring case and a trailing dot."""
    return (a or "").strip().lower().rstrip(".") == (b or "").strip().lower().rstrip(".")


def check_http_no_redirect(
    resp: SafeResponse | None,
    location: str,
    *,
    expected_host: str = "",
) -> tuple[dict | None, str | None]:
    """Classify the first plain-HTTP answer (redirects not followed).

    Returns ``(finding, note)``. Pass with no finding for 301/308 to
    ``https://`` on the same host, or when HTTP is not served (``resp`` is
    None → note ``HTTP not served``).
    """
    if resp is None:
        return None, "HTTP not served"

    expected = (expected_host or "").strip() or (urlsplit(location).hostname or "")
    status = int(resp.status)
    loc_hdr = _header(resp.headers, "location")

    if status in (301, 302, 307, 308):
        if not loc_hdr:
            return (
                _finding(
                    "http-no-redirect",
                    "HTTP does not redirect to HTTPS",
                    "medium",
                    319,
                    f"HTTP {status} redirect has no Location header.",
                    location,
                    "Respond to HTTP with 301 or 308 Location: https://<same-host>/...",
                    variant="http-no-redirect",
                ),
                None,
            )
        absolute = urljoin(location, loc_hdr)
        parts = urlsplit(absolute)
        scheme = (parts.scheme or "").lower()
        host = (parts.hostname or "").lower()

        if scheme == "https":
            if expected and host and _hosts_equal(host, expected):
                if status in (301, 308):
                    return None, None
                return (
                    _finding(
                        "http-redirect-temporary",
                        "Temporary redirect to HTTPS",
                        "low",
                        319,
                        f"HTTP {status} redirects to HTTPS on the same host; prefer 301 or 308. "
                        f"Evidence: Location: {loc_hdr[:200]}",
                        location,
                        "Use a permanent redirect (301 or 308) to https:// on the same host.",
                        variant="http-redirect-temporary",
                    ),
                    None,
                )
            return (
                _finding(
                    "http-redirect-other-host",
                    "HTTP redirects to another host before HTTPS on the same host",
                    "low",
                    319,
                    f"HTTP {status} redirects to https:// on a different host first "
                    f"({host or loc_hdr[:80]}). HSTS cannot be set for this host this way. "
                    f"Evidence: Location: {loc_hdr[:200]}",
                    location,
                    "Redirect http://<host>/ to https://<same-host>/ with 301 or 308 before any other host.",
                    variant="http-redirect-other-host",
                ),
                None,
            )

        return (
            _finding(
                "http-no-redirect",
                "HTTP redirects to http (not HTTPS)",
                "medium",
                319,
                f"HTTP {status} redirects to http:// (not https). Evidence: Location: {loc_hdr[:200]}",
                location,
                "Redirect HTTP to https:// on the same host with 301 or 308.",
                variant="http-redirect-to-http",
            ),
            None,
        )

    return (
        _finding(
            "http-no-redirect",
            "HTTP does not redirect to HTTPS",
            "medium",
            319,
            f"HTTP does not redirect to HTTPS (status {status}).",
            location,
            "Respond to HTTP with 301 or 308 Location: https://<same-host>/...",
            variant="http-no-redirect",
        ),
        None,
    )


def check_expect_ct(headers: dict[str, str], location: str) -> dict | None:
    if _header(headers, "expect-ct"):
        return None
    return _finding(
        "expect-ct",
        "Expect-CT header not set",
        "info",
        693,
        "Expect-CT header is not set on the primary response.",
        location,
    )


def check_waf_none_seen(headers: dict[str, str], location: str) -> dict | None:
    server = _header(headers, "server").lower()
    if server == "cloudflare":
        return None
    for name in _WAF_HEADERS:
        if _header(headers, name):
            return None
    return _finding(
        "waf-none-seen",
        "No WAF or CDN signature seen",
        "info",
        693,
        "No common WAF/CDN response headers were observed (cf-ray, x-sucuri-id, x-amz-cf-id, "
        "server: cloudflare, x-azure-ref). This cannot prove there is no firewall.",
        location,
    )


def _hsts_requests_preload(sts: str) -> bool:
    return bool(re.search(r"(?:^|;)\s*preload\s*(?:;|$)", sts, re.IGNORECASE))


def _hsts_include_subdomains(sts: str) -> bool:
    return bool(re.search(r"(?:^|;)\s*includesubdomains\s*(?:;|$)", sts, re.IGNORECASE))


def check_hsts_not_preloaded(
    domain: str, headers: dict[str, str], location: str
) -> tuple[dict | None, str | None]:
    """Return (finding, note). Lookup only when ATTESTRA_HSTS_PRELOAD_LOOKUP=1.

    Not-preloaded statuses (finding): unknown, pending, rejected, removed.
    On-list statuses (no finding): preloaded, pending-removal, pending-automated-removal.
    Anything else or a failed lookup → no finding, note "preload lookup failed".
    """
    if os.environ.get("ATTESTRA_HSTS_PRELOAD_LOOKUP", "").strip() != "1":
        return None, None
    sts = _header(headers, "strict-transport-security")
    if not sts or not _hsts_requests_preload(sts):
        return None, None
    try:
        api = f"https://hstspreload.org/api/v2/status?domain={domain}"
        req = Request(api, headers={"User-Agent": "attestra-webcheck/0.1"})
        with urlopen(req, timeout=10) as resp:  # noqa: S310 - public status API, not engagement target
            raw = resp.read(64_000)
        data = json.loads(raw.decode("utf-8", errors="replace"))
        status = str(data.get("status") or "").lower().strip()
        if status in _HSTS_PRELOADED_STATUSES:
            return None, None
        if status in _HSTS_NOT_PRELOADED_STATUSES:
            return (
                _finding(
                    "hsts-not-preloaded",
                    "HSTS preload requested but not on preload list",
                    "info",
                    693,
                    f"HSTS header requests preload but hstspreload.org status is {status} for {domain}.",
                    location,
                ),
                None,
            )
        return None, "preload lookup failed"
    except Exception:
        return None, "preload lookup failed"


def check_hsts_parent_missing(
    parent_headers: dict[str, str] | None,
    parent_url: str,
    *,
    skipped_note: str | None = None,
) -> tuple[dict | None, str | None]:
    if skipped_note:
        return None, skipped_note
    if parent_headers is None:
        return None, "skipped: parent HSTS check failed"
    sts = _header(parent_headers, "strict-transport-security")
    if sts and _hsts_include_subdomains(sts):
        return None, None
    return (
        _finding(
            "hsts-parent-missing",
            "Parent domain has no HSTS includeSubDomains",
            "info",
            693,
            f"Parent {parent_url} has no HSTS includeSubDomains. Evidence: {sts or '(missing)'}",
            parent_url,
            "Set Strict-Transport-Security with includeSubDomains on the parent domain.",
        ),
        None,
    )


def _check_status(check_id: str, name: str, finding: dict | None, *, source: str = "webcheck") -> dict:
    from attestra.checks import FAILED, PASSED, check_row

    if finding is None:
        return check_row(check_id=check_id, name=name, status=PASSED, source=source)
    return check_row(
        check_id=check_id,
        name=name,
        status=FAILED,
        source=source,
        evidence=(finding.get("description") or "")[:200],
    )


def evaluate_primary(
    headers: dict[str, str],
    location: str,
    host: str,
    *,
    scheme: str = "https",
    body: bytes | str | None = None,
) -> tuple[list[dict], list[str], list[dict]]:
    """Return findings, notes, and pass/fail check rows for the primary response.

    Optional ``body`` runs SRI and mixed-content checks on the already-fetched HTML
    (no extra requests). When ``body`` is omitted, those checks are skipped so
    header-only unit tests stay unchanged.
    """
    findings: list[dict] = []
    notes: list[str] = []
    checks: list[dict] = []

    # Always-evaluated header checks (C5 passed rows when clean).
    hsts_f = check_hsts_present(headers, location, scheme=scheme)
    if hsts_f:
        findings.append(hsts_f)
    if scheme.lower() == "https":
        checks.append(_check_status("hsts-present", "HSTS header present", hsts_f))

    xcto_f = check_x_content_type_options(headers, location)
    if xcto_f:
        findings.append(xcto_f)
    checks.append(_check_status("x-content-type-options", "X-Content-Type-Options nosniff", xcto_f))

    ref_f = check_referrer_policy(headers, location)
    if ref_f:
        findings.append(ref_f)
    checks.append(_check_status("referrer-policy", "Referrer-Policy strict value", ref_f))

    # C10: full CSP analysis (includes missing base-uri and unsafe/wildcard/http sources).
    csp_findings, csp_checks = check_csp_policy(headers, location)
    findings.extend(csp_findings)
    checks.extend(csp_checks)

    named = (
        (check_server_disclosure, "server-disclosure", "Server header not disclosing software", False),
        (check_x_xss_protection, "x-xss-protection", "X-XSS-Protection not set (legacy)", False),
        (check_expect_ct, "expect-ct", "Expect-CT header", False),
        (check_waf_none_seen, "waf-none-seen", "WAF or CDN signature seen", False),
    )
    for fn, cid, name, _only_when_csp in named:
        got = fn(headers, location)
        if got:
            findings.append(got)
        # server-disclosure / x-xss / waf: "passed" means the bad signal was absent.
        checks.append(_check_status(cid, name, got))
    pre, pre_note = check_hsts_not_preloaded(host, headers, location)
    if pre:
        findings.append(pre)
    if pre_note:
        notes.append(pre_note)
    if os.environ.get("ATTESTRA_HSTS_PRELOAD_LOOKUP", "").strip() == "1":
        checks.append(_check_status("hsts-not-preloaded", "HSTS preload list membership", pre))

    # C9: one finding per cookie per missing Secure / HttpOnly / SameSite.
    cookie_findings, cookie_checks = check_cookies(headers, location)
    findings.extend(cookie_findings)
    checks.extend(cookie_checks)

    # SRI + mixed content from the already-fetched HTML body (no extra requests).
    if body is not None:
        html_findings, html_checks = check_html_body(body, location, scheme=scheme)
        findings.extend(html_findings)
        checks.extend(html_checks)
    return findings, notes, checks


class WebcheckAdapter(ScannerAdapter):
    name = "webcheck"
    import_tool = "webcheck"
    out_name = "webcheck.json"
    image_key = ""

    def available(self) -> bool:
        return True

    def version(self) -> str:
        return "webcheck"

    def build_argv(self, target: PinnedTarget | str, *, out_file: Path, profile: str = "baseline") -> list[str]:
        raise NotImplementedError("webcheck is pure Python; use scan()")

    def scan(
        self,
        pin: PinnedTarget | str,
        *,
        out_dir: Path,
        cancel: threading.Event | None = None,
        profile: str = "baseline",
        scope: AuthorizedScope | None = None,
        **opts,
    ) -> ScannerResult:
        if not isinstance(pin, PinnedTarget):
            return ScannerResult(tool=self.name, tool_version=self.version(), error="webcheck needs a PinnedTarget")
        if scope is None:
            return ScannerResult(
                tool=self.name,
                tool_version=self.version(),
                error="webcheck requires an AuthorizedScope (scope=...)",
            )

        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / self.out_name
        if out_file.exists():
            out_file.unlink()

        from attestra.checks import PASSED, SKIPPED, check_row, write_checks_sidecar

        requests_log: list[dict] = []
        findings: list[dict] = []
        notes: list[str] = []
        checks: list[dict] = []

        primary_url = build_url(pin, "/")
        security_url = build_url(pin, "/.well-known/security.txt")

        primary: SafeResponse | None = None
        try:
            primary = safe_get(primary_url, scope=scope, pin=pin)
            requests_log.append({"method": "GET", "url": primary_url, "status": primary.status})
        except AuthorizationError as exc:
            notes.append(f"primary request refused: {exc}")
        except Exception as exc:  # noqa: BLE001 - record and continue other checks
            notes.append(f"primary request failed: {exc}")

        certificate: dict[str, str] = {}
        if primary is not None:
            primary_findings, primary_notes, primary_checks = evaluate_primary(
                primary.headers,
                primary_url,
                pin.host,
                scheme=pin.scheme,
                body=primary.body,
            )
            findings.extend(primary_findings)
            notes.extend(primary_notes)
            checks.extend(primary_checks)
            # Saved peer cert end date (no extra request) for expiry bands / daily job.
            if primary.peer_cert_not_after:
                certificate = {"not_after": primary.peer_cert_not_after}
                try:
                    from attestra.cert_expiry import finding_for_end_date, parse_not_after

                    end = parse_not_after(primary.peer_cert_not_after)
                    if end is not None:
                        nf = finding_for_end_date(
                            end=end,
                            location=primary_url,
                            tool="webcheck",
                            rule_id="webcheck/cert-expiry",
                        )
                        if nf is not None:
                            findings.append(
                                _finding(
                                    "cert-expiry",
                                    nf.title,
                                    nf.severity,
                                    nf.cwe or 298,
                                    nf.description,
                                    primary_url,
                                    recommendation=nf.recommendation,
                                    variant=nf.variant or "cert_expirationStatus",
                                )
                            )
                except Exception as exc:  # noqa: BLE001 - never block the scan
                    notes.append(f"cert expiry check skipped: {exc}")

        sec_resp: SafeResponse | None = None
        try:
            # Reuse pin IP/port/scheme for the same host.
            sec_resp = safe_get(security_url, scope=scope, pin=pin)
            requests_log.append({"method": "GET", "url": security_url, "status": sec_resp.status})
        except AuthorizationError as exc:
            notes.append(f"security.txt request refused: {exc}")
        except Exception as exc:  # noqa: BLE001
            notes.append(f"security.txt request failed: {exc}")
        sec_finding = check_security_txt(sec_resp, security_url)
        if sec_finding:
            findings.append(sec_finding)
        checks.append(_check_status("security-txt", "security.txt present and valid", sec_finding))

        # Plain HTTP probe (no redirect follow). Skip when HTTP is out of scope.
        # One request only; reuse this answer for HSTS-on-HTTP and HTTPS-upgrade checks.
        http_url = build_url(pin, "/", scheme="http")
        http_resp: SafeResponse | None = None
        http_in_scope = False
        try:
            authorize_target(scope, http_url, "url")
            http_in_scope = True
        except AuthorizationError:
            notes.append("skipped: http not in scope")
            checks.append(
                check_row(
                    check_id="http-no-redirect",
                    name="HTTP redirects to HTTPS",
                    status=SKIPPED,
                    source="webcheck",
                    evidence="http not in scope",
                )
            )
            checks.append(
                check_row(
                    check_id="hsts-on-http",
                    name="HSTS not sent over HTTP",
                    status=SKIPPED,
                    source="webcheck",
                    evidence="http not in scope",
                )
            )
        else:
            http_pin = pin if pin.scheme == "http" else PinnedTarget(host=pin.host, ip=pin.ip, port=80, scheme="http")
            try:
                http_resp = safe_get(http_url, scope=scope, pin=http_pin, follow_redirects=False)
                entry: dict = {"method": "GET", "url": http_url, "status": http_resp.status}
                if http_resp.status in (301, 302, 307, 308):
                    loc = _header(http_resp.headers, "location")
                    if loc:
                        entry["location"] = loc
                requests_log.append(entry)
            except Exception as exc:  # noqa: BLE001
                notes.append(f"http probe failed: {exc}")

        if http_resp is not None:
            hsts_http = check_hsts_on_http(http_resp, http_url)
            if hsts_http:
                findings.append(hsts_http)
            checks.append(_check_status("hsts-on-http", "HSTS not sent over HTTP", hsts_http))
            # HTTPS-upgrade check only when the pin is https (separate http:// listener).
            # On an http pin the primary URL is already plain HTTP, so a self-redirect
            # would break the header checks that need a 200 body.
            if pin.scheme == "https":
                no_redir, redir_note = check_http_no_redirect(
                    http_resp, http_url, expected_host=pin.host
                )
                if no_redir:
                    findings.append(no_redir)
                if redir_note:
                    notes.append(redir_note)
                checks.append(_check_status("http-no-redirect", "HTTP redirects to HTTPS", no_redir))
            else:
                notes.append("skipped: http-no-redirect requires https pin")
                checks.append(
                    check_row(
                        check_id="http-no-redirect",
                        name="HTTP redirects to HTTPS",
                        status=SKIPPED,
                        source="webcheck",
                        evidence="requires https pin",
                    )
                )
        elif http_in_scope and pin.scheme == "https":
            # Port 80 closed / no answer → pass with note (do not fail the upgrade check).
            _, redir_note = check_http_no_redirect(None, http_url, expected_host=pin.host)
            if redir_note:
                notes.append(redir_note)
            checks.append(
                check_row(
                    check_id="http-no-redirect",
                    name="HTTP redirects to HTTPS",
                    status=PASSED,
                    source="webcheck",
                    evidence=redir_note or "HTTP not served",
                )
            )
            checks.append(
                check_row(
                    check_id="hsts-on-http",
                    name="HSTS not sent over HTTP",
                    status=SKIPPED,
                    source="webcheck",
                    evidence=redir_note or "HTTP not served",
                )
            )

        # Parent HSTS includeSubDomains — only when parent is in scope (+1 request).
        parent = parent_domain(pin.host)
        if parent is None:
            notes.append("skipped: no parent domain")
            checks.append(
                check_row(
                    check_id="hsts-parent-missing",
                    name="Parent HSTS includeSubDomains",
                    status=SKIPPED,
                    source="webcheck",
                    evidence="no parent domain",
                )
            )
        elif parent not in scope.allowed_hosts:
            notes.append("skipped: parent not in scope")
            checks.append(
                check_row(
                    check_id="hsts-parent-missing",
                    name="Parent HSTS includeSubDomains",
                    status=SKIPPED,
                    source="webcheck",
                    evidence="parent not in scope",
                )
            )
        else:
            parent_url = f"https://{parent}/"
            parent_headers: dict[str, str] | None = None
            skipped: str | None = None
            try:
                authorize_target(scope, parent_url, "url")
                parent_resp = safe_get(parent_url, scope=scope)
                requests_log.append({"method": "GET", "url": parent_url, "status": parent_resp.status})
                parent_headers = parent_resp.headers
            except AuthorizationError:
                skipped = "skipped: parent not in scope"
                notes.append(skipped)
            except Exception as exc:  # noqa: BLE001
                skipped = f"skipped: parent request failed: {exc}"
                notes.append(skipped)
            finding, note = check_hsts_parent_missing(parent_headers, parent_url, skipped_note=skipped)
            if note and note not in notes:
                notes.append(note)
            if finding:
                findings.append(finding)
            if skipped:
                checks.append(
                    check_row(
                        check_id="hsts-parent-missing",
                        name="Parent HSTS includeSubDomains",
                        status=SKIPPED,
                        source="webcheck",
                        evidence=skipped,
                    )
                )
            else:
                checks.append(_check_status("hsts-parent-missing", "Parent HSTS includeSubDomains", finding))

        # Google Safe Browsing reputation (off by default; lookup to Google, not the target).
        from attestra.runner.scanners.safe_browsing import check_safe_browsing

        gsb_urls: list[str] = []
        for candidate in (primary_url,):
            try:
                authorize_target(scope, candidate, "url")
                gsb_urls.append(candidate)
            except AuthorizationError:
                pass
        gsb = check_safe_browsing(gsb_urls)
        findings.extend(gsb.findings)
        for note in gsb.notes:
            if note and note not in notes:
                notes.append(note)
        checks.extend(gsb.checks)

        # Passive DNS posture checks (CAA, AAAA, SPF, TLSA, email, DNSSEC).
        # Skip for IP-literal pins (no useful parent/CAA walk on 127.0.0.1).
        from attestra.runner.scanners.base import is_ip_literal
        from attestra.runner.scanners.webcheck_dns import dns_posture

        dns_ids = (
            ("dns-caa", "DNS CAA record"),
            ("dns-aaaa", "DNS AAAA (IPv6) address"),
            ("dns-spf", "DNS SPF when host has no MX"),
            ("dns-tlsa", "DNS TLSA (DANE) record"),
            ("dns-dmarc", "DNS DMARC policy"),
            ("dns-dkim", "DNS DKIM on common selectors"),
            ("dns-mta-sts", "DNS MTA-STS policy"),
            ("dns-tls-rpt", "DNS TLS-RPT record"),
            ("dns-dnssec", "DNSSEC DS and RRSIG"),
        )
        if is_ip_literal(pin.host):
            notes.append("skipped: DNS checks require a hostname, not an IP literal")
            for cid, name in dns_ids:
                checks.append(
                    check_row(
                        check_id=cid,
                        name=name,
                        status=SKIPPED,
                        source="webcheck",
                        evidence="host is an IP literal",
                    )
                )
        else:
            dns_result = dns_posture(pin.host, scope=scope)
            for item in dns_result.findings:
                if item.get("skipped"):
                    notes.append(item.get("description") or item.get("title") or "DNS checks skipped")
                else:
                    findings.append(item)
            for note in dns_result.notes:
                if note and note not in notes:
                    notes.append(note)
            # Prefer rows built by dns_posture (includes N/A and SKIPPED).
            if dns_result.checks:
                checks.extend(dns_result.checks)
            else:
                dns_findings = {str(f.get("id") or ""): f for f in dns_result.findings if not f.get("skipped")}
                for cid, name in dns_ids:
                    checks.append(_check_status(cid, name, dns_findings.get(cid)))

        # Snapshot of tracked security headers for change alerts (compare saved results only).
        headers_snap: dict[str, str] = {}
        if primary is not None:
            from attestra.alerts.headers import SECURITY_HEADERS, snapshot_from_headers

            headers_snap = snapshot_from_headers(
                {name: _header(primary.headers, name) for name in SECURITY_HEADERS}
            )
        report = {
            "requests": requests_log,
            "findings": findings,
            "notes": notes,
            "checks": checks,
            "certificate": certificate,
            "headers": headers_snap,
        }
        payload = json.dumps(report, indent=2, sort_keys=True).encode("utf-8")
        out_file.write_bytes(payload)
        write_checks_sidecar(out_file, checks)
        digest = hashlib.sha256(payload).hexdigest()
        return ScannerResult(
            tool=self.name,
            tool_version=self.version(),
            import_tool=self.import_tool,
            raw_path=out_file,
            raw_sha256=digest,
            extra={"checks": checks},
        )
