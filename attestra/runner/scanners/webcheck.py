"""Passive web hygiene checks (headers, security.txt, HSTS) over http_safe only."""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from pathlib import Path
from urllib.request import Request, urlopen

from attestra.runner.authorization import AuthorizationError, AuthorizedScope, authorize_target
from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.http_safe import SafeResponse, safe_get
from attestra.runner.scanners.base import ScannerAdapter, ScannerResult

_STRICT_REFERRER = frozenset({"no-referrer", "same-origin", "strict-origin"})
_WAF_HEADERS = frozenset({"cf-ray", "x-sucuri-id", "x-amz-cf-id", "x-azure-ref"})
_VERSION_RE = re.compile(r"\d+\.\d+")
_CSP_DIR_RE = re.compile(r"(?:^|;)\s*([a-z0-9-]+)\b", re.IGNORECASE)


def _finding(
    fid: str,
    title: str,
    severity: str,
    cwe: int,
    description: str,
    location: str,
    recommendation: str = "",
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


def check_csp_base_uri(headers: dict[str, str], location: str) -> dict | None:
    csp = _header(headers, "content-security-policy")
    if not csp:
        return None
    if "base-uri" in _csp_directives(csp):
        return None
    return _finding(
        "csp-base-uri",
        "CSP: base-uri directive missing",
        "low",
        693,
        f"Content-Security-Policy is set but has no base-uri directive. Evidence: {csp[:300]}",
        location,
        "Add base-uri 'self' (or a tight allow-list) to the Content-Security-Policy header.",
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
            "info",
            200,
            "Referrer-Policy header is missing.",
            location,
            "Set Referrer-Policy to no-referrer, same-origin, or strict-origin.",
        )
    # Take the first token if multiple policies are listed.
    primary = val.split(",")[0].strip().lower()
    if primary in _STRICT_REFERRER:
        return None
    return _finding(
        "referrer-policy",
        "Referrer-Policy is not a strict value",
        "low",
        200,
        f"Referrer-Policy is set but not strict. Evidence: {val}",
        location,
        "Set Referrer-Policy to no-referrer, same-origin, or strict-origin.",
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


def check_http_no_redirect(resp: SafeResponse | None, location: str) -> dict | None:
    if resp is None:
        return None
    if resp.status in (301, 302, 307, 308):
        loc = _header(resp.headers, "location")
        if loc.lower().startswith("https://"):
            return None
    return _finding(
        "http-no-redirect",
        "Plain HTTP does not redirect to HTTPS",
        "medium",
        319,
        f"HTTP response did not redirect to HTTPS (status {resp.status}).",
        location,
        "Respond to HTTP with 301/302/307/308 Location: https://...",
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


def check_hsts_not_preloaded(domain: str, headers: dict[str, str], location: str) -> dict | None:
    if os.environ.get("ATTESTRA_HSTS_PRELOAD_LOOKUP", "").strip() != "1":
        return None
    sts = _header(headers, "strict-transport-security")
    if not sts or not _hsts_requests_preload(sts):
        return None
    try:
        api = f"https://hstspreload.org/api/v2/status?domain={domain}"
        req = Request(api, headers={"User-Agent": "attestra-webcheck/0.1"})
        with urlopen(req, timeout=10) as resp:  # noqa: S310 - public status API, not engagement target
            raw = resp.read(64_000)
        data = json.loads(raw.decode("utf-8", errors="replace"))
        status = str(data.get("status") or "").lower()
        if status == "preloaded":
            return None
        return _finding(
            "hsts-not-preloaded",
            "HSTS preload requested but not on preload list",
            "info",
            693,
            f"HSTS header requests preload but hstspreload.org status is {status or 'unknown'} for {domain}.",
            location,
        )
    except Exception:
        return None


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


def evaluate_primary(headers: dict[str, str], location: str, host: str) -> list[dict]:
    findings: list[dict] = []
    for fn in (
        check_csp_base_uri,
        check_server_disclosure,
        check_x_xss_protection,
        check_referrer_policy,
        check_expect_ct,
        check_waf_none_seen,
    ):
        got = fn(headers, location)
        if got:
            findings.append(got)
    pre = check_hsts_not_preloaded(host, headers, location)
    if pre:
        findings.append(pre)
    return findings


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

        requests_log: list[dict] = []
        findings: list[dict] = []
        notes: list[str] = []

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

        if primary is not None:
            findings.extend(evaluate_primary(primary.headers, primary_url, pin.host))

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

        # Plain HTTP probe (no redirect follow). Skip when HTTP is out of scope.
        http_url = build_url(pin, "/", scheme="http")
        http_resp: SafeResponse | None = None
        try:
            authorize_target(scope, http_url, "url")
        except AuthorizationError:
            notes.append("skipped: http not in scope")
        else:
            http_pin = pin if pin.scheme == "http" else PinnedTarget(host=pin.host, ip=pin.ip, port=80, scheme="http")
            try:
                http_resp = safe_get(http_url, scope=scope, pin=http_pin, follow_redirects=False)
                requests_log.append({"method": "GET", "url": http_url, "status": http_resp.status})
            except Exception as exc:  # noqa: BLE001
                notes.append(f"http probe failed: {exc}")

        if http_resp is not None:
            hsts_http = check_hsts_on_http(http_resp, http_url)
            if hsts_http:
                findings.append(hsts_http)
            # HTTPS-upgrade check only when the pin is https (separate http:// listener).
            # On an http pin the primary URL is already plain HTTP, so a self-redirect
            # would break the header checks that need a 200 body.
            if pin.scheme == "https":
                no_redir = check_http_no_redirect(http_resp, http_url)
                if no_redir:
                    findings.append(no_redir)
            else:
                notes.append("skipped: http-no-redirect requires https pin")

        # Parent HSTS includeSubDomains — only when parent is in scope (+1 request).
        parent = parent_domain(pin.host)
        if parent is None:
            notes.append("skipped: no parent domain")
        elif parent not in scope.allowed_hosts:
            notes.append("skipped: parent not in scope")
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

        # Passive DNS posture checks (CAA, AAAA, SPF, TLSA) — same report file.
        # Skip for IP-literal pins (no useful parent/CAA walk on 127.0.0.1).
        from attestra.runner.scanners.base import is_ip_literal
        from attestra.runner.scanners.webcheck_dns import dns_checks

        if is_ip_literal(pin.host):
            notes.append("skipped: DNS checks require a hostname, not an IP literal")
        else:
            for item in dns_checks(pin.host):
                if item.get("skipped"):
                    notes.append(item.get("description") or item.get("title") or "DNS checks skipped")
                else:
                    findings.append(item)

        report = {"requests": requests_log, "findings": findings, "notes": notes}
        payload = json.dumps(report, indent=2, sort_keys=True).encode("utf-8")
        out_file.write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        return ScannerResult(
            tool=self.name,
            tool_version=self.version(),
            import_tool=self.import_tool,
            raw_path=out_file,
            raw_sha256=digest,
        )
