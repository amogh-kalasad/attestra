"""Login-profile session headers for automated VAPT HTTP capture (T01).

Same material the ZAP/Nuclei scans inject (``attestra.auth_web.scan_auth``): the profile's
auth header/cookie, its non-secret Extra Headers and its encrypted Extra Cookies. Values are
kept in memory only, never written to disk or logged; callers get ``redact_values`` to scrub
any echo from captured evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit


@dataclass
class SessionAuth:
    profile_id: int | None = None
    status: str = "none"  # none | ready | failed
    note: str = ""
    headers: dict[str, str] = field(default_factory=dict, repr=False)
    redact_values: tuple[str, ...] = field(default=(), repr=False)

    @property
    def injected_names(self) -> list[str]:
        return sorted(self.headers.keys())

    def public(self) -> dict[str, Any]:
        """Value-free summary safe for result_json / reports."""
        return {
            "profile_id": self.profile_id,
            "status": self.status,
            "note": self.note[:300],
            "injected": self.injected_names,
        }

    def headers_for(self, url: str, root: str) -> dict[str, str]:
        """Session headers only for the target origin (never another host)."""
        if self.status != "ready" or not self.headers:
            return {}
        if _origin(url) != _origin(root):
            return {}
        return dict(self.headers)

    def scrub(self, text: str) -> str:
        out = text or ""
        for v in self.redact_values:
            if v and v in out:
                out = out.replace(v, "[REDACTED]")
        return out


def _origin(url: str) -> tuple[str, str, int]:
    p = urlsplit(url)
    scheme = (p.scheme or "").lower()
    try:
        port = p.port or (443 if scheme == "https" else 80)
    except ValueError:
        port = -1
    return scheme, (p.hostname or "").lower(), port


def load_session_auth(
    s: Any,
    *,
    profile_id: int | None,
    engagement_id: int,
    target_url: str,
    verify: bool = True,
    login_probe: Any | None = None,
    http_post: Any | None = None,
) -> SessionAuth:
    """Build session headers from an AuthCredentialProfile. Never raises; failures -> status=failed."""
    if not profile_id:
        return SessionAuth(status="none", note="no login profile; unauthenticated capture")
    from attestra.auth_web import extra_cookies as xc
    from attestra.auth_web import extra_headers as xh
    from attestra.auth_web import scan_auth as sa

    out = SessionAuth(profile_id=int(profile_id), status="failed")
    try:
        profile = sa.load_profile_for_run(s, SimpleNamespace(auth_profile_id=profile_id, engagement_id=engagement_id))
        if profile is None:
            out.note = "login profile not found"
            return out
        method = (profile.method or "").strip().lower()
        if method in ("", "none"):
            out.status, out.note = "none", "profile method=none; unauthenticated capture"
            return out
        if method == "sso_bootstrap":
            out.note = "sso_bootstrap cannot be automated"
            return out
        from attestra import credentials

        ref = (profile.secret_ref or "").strip()
        if not ref:
            out.note = "login profile has no stored secret"
            return out
        secret = credentials.get_secret(ref)
        cfg = sa._profile_cfg(profile)
        extra = xh.parse_extra_headers(
            getattr(profile, "extra_headers", "") or "", own_header_name=xh.own_header_name(method, cfg)
        )
        extra_cookies = sa._load_extra_cookies(profile, method, cfg)
        allowed = sa._allowed_hosts(profile, target_url)
        if http_post is None:
            http_post = sa.live_http_post(allowed, extra_headers=extra, extra_cookies=extra_cookies)
        if login_probe is None:
            login_probe = sa.live_login_probe(allowed)
        headers, cookies, note = sa.session_material(method, cfg, secret, http_post=http_post)
        if not headers and not cookies:
            out.note = "no session header or cookie could be prepared"
            return out
        cookies = xc.merge_cookies(cookies, extra_cookies)
        out.redact_values = sa._redaction_values(secret, headers, cookies, extra_values=[v for _, v in extra_cookies])
        headers = xh.merge_extra_headers(headers, extra)
        if verify:
            ok, vnote = sa.verify_logged_in(cfg, headers, cookies, login_probe=login_probe)
            if not ok:
                out.note = vnote
                return out
            note = f"{note}; {vnote}"
        out.headers = sa.all_request_headers(headers, cookies)
        out.status = "ready"
        out.note = note
        return out
    except Exception as exc:  # noqa: BLE001 - value-free reason only
        out.status = "failed"
        out.note = f"login profile could not be loaded: {type(exc).__name__}"
        msg = str(exc)
        if isinstance(exc, sa.ScanAuthError) and msg and not any(v and v in msg for v in out.redact_values):
            out.note = msg[:200]
        out.headers = {}
        return out
