"""ZAP authenticated scan contexts from Phase 6 credential profiles.

Builds mounted auth config for zap-baseline/full without putting secrets on the
docker argv, in ScanRun rows, or in diagnostic dumps. Secrets are read only via
``attestra.credentials.get_secret`` at the call site and written into restrictive
temp files under the scanner ``out_dir`` (mounted at ``/zap/wrk``).

Supported methods: ``form``, ``header``, ``cookie``. ``sso_bootstrap`` returns
blocked status (never bypass MFA/SSO). ``none`` skips auth wiring.

Baseline scripts accept ``-n <context>`` and optional ``-U <user>``. Full ZAP
auth via packaged scripts is awkward, so this module always prepares JSON/YAML
auth files on the work mount; ``-n`` is wired only when a ``.context`` file is
supplied. Never pass passwords through ``-z`` (visible in process lists / argv
logging).
"""
# @lat: [[architecture#Authenticated website testing]]
# @lat: [[runner#ZAP authentication]]

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

import yaml
from sqlalchemy.orm import Session

from attestra import credentials, services
from attestra.models import AUTH_METHODS, AuthCredentialProfile
from attestra.secret_store import SecretsError

AUTH_JSON_NAME = "attestra-zap-auth.json"
AUTH_YAML_NAME = "attestra-zap-auth.yaml"
CONTEXT_NAME = "attestra-auth.context"
PUBLIC_META_NAME = "attestra-zap-auth.public.json"

_FILE_MODE = 0o600
_REDACTED = "[REDACTED]"

_SSO_REASON = (
    "SSO/MFA bootstrap is blocked for ZAP auth contexts: complete interactive SSO "
    "outside Attestra, then use a session cookie or header profile. Never bypass MFA or SSO."
)


class ZapAuthError(Exception):
    """Auth context could not be built or loaded."""


@dataclass
class ZapAuthContext:
    """Public auth-context descriptor; secret-bearing bodies stay out of repr/str."""

    status: str  # ready | blocked | skipped
    method: str
    reason: str = ""
    format: str = "attestra-zap-auth-v1"
    auth_json_name: str = AUTH_JSON_NAME
    auth_yaml_name: str = AUTH_YAML_NAME
    context_name: str = CONTEXT_NAME
    zap_user: str = ""
    use_n_flag: bool = False
    public: dict[str, Any] = field(default_factory=dict)
    _bodies: dict[str, str] = field(default_factory=dict, repr=False, compare=False)

    def __str__(self) -> str:  # noqa: D105 - keep secrets out of str/repr paths
        return (
            f"ZapAuthContext(status={self.status!r}, method={self.method!r}, "
            f"reason={self.reason!r}, use_n_flag={self.use_n_flag!r}, "
            f"zap_user={self.zap_user!r}, public={self.public!r})"
        )

    def redacted_dict(self) -> dict[str, Any]:
        """Safe diagnostic dump (never includes file bodies or secrets)."""
        return {
            "status": self.status,
            "method": self.method,
            "reason": self.reason,
            "format": self.format,
            "auth_json_name": self.auth_json_name,
            "auth_yaml_name": self.auth_yaml_name,
            "context_name": self.context_name if self.use_n_flag else "",
            "zap_user": self.zap_user,
            "use_n_flag": self.use_n_flag,
            "public": redact_auth_diagnostics(dict(self.public)),
        }


def _as_meta(profile: AuthCredentialProfile | dict[str, Any]) -> dict[str, Any]:
    if isinstance(profile, AuthCredentialProfile):
        cfg = dict(profile.config_json or {})
        return {
            "id": profile.id,
            "tenant_id": profile.tenant_id,
            "engagement_id": profile.engagement_id,
            "label": profile.label or "",
            "role_name": profile.role_name or "",
            "method": (profile.method or "").strip().lower(),
            "login_url": profile.login_url or "",
            "username_selector": profile.username_selector or "",
            "password_selector": profile.password_selector or "",
            "submit_selector": profile.submit_selector or "",
            "success_url_contains": profile.success_url_contains or "",
            "status": profile.status or "",
            "config": cfg,
        }
    if not isinstance(profile, dict):
        raise ZapAuthError("profile must be AuthCredentialProfile or dict")
    cfg = dict(profile.get("config") or profile.get("config_json") or {})
    return {
        "id": profile.get("id"),
        "tenant_id": profile.get("tenant_id"),
        "engagement_id": profile.get("engagement_id"),
        "label": str(profile.get("label") or ""),
        "role_name": str(profile.get("role_name") or ""),
        "method": str(profile.get("method") or "").strip().lower(),
        "login_url": str(profile.get("login_url") or ""),
        "username_selector": str(profile.get("username_selector") or ""),
        "password_selector": str(profile.get("password_selector") or ""),
        "submit_selector": str(profile.get("submit_selector") or ""),
        "success_url_contains": str(profile.get("success_url_contains") or ""),
        "status": str(profile.get("status") or ""),
        "config": cfg,
    }


def _username_from_meta(meta: dict[str, Any]) -> str:
    cfg = meta.get("config") or {}
    for key in ("username", "user", "login", "user_name"):
        val = cfg.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    label = (meta.get("label") or "").strip()
    return label


def _field_names(meta: dict[str, Any]) -> tuple[str, str]:
    cfg = meta.get("config") or {}
    user_field = str(cfg.get("username_field") or cfg.get("user_field") or "username").strip() or "username"
    pass_field = str(cfg.get("password_field") or cfg.get("pass_field") or "password").strip() or "password"
    return user_field, pass_field


def _target_urls(meta: dict[str, Any]) -> list[str]:
    login = (meta.get("login_url") or "").strip()
    urls: list[str] = []
    if login:
        urls.append(login)
        try:
            parts = urlparse(login)
            if parts.scheme and parts.netloc:
                urls.append(f"{parts.scheme}://{parts.netloc}/")
        except Exception:
            pass
    # de-dupe preserve order
    seen: set[str] = set()
    out: list[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out or ["https://example.invalid/"]


def _restrictive_chmod(path: Path) -> None:
    try:
        path.chmod(_FILE_MODE)
    except OSError:
        pass


def redact_auth_diagnostics(obj: Any, secret_hints: list[str] | None = None) -> Any:
    """Return a deep copy with secret-looking values replaced by ``[REDACTED]``."""
    hints = [h for h in (secret_hints or []) if h]
    secret_keys = {
        "password",
        "passwd",
        "pwd",
        "secret",
        "secret_value",
        "token",
        "access_token",
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "cookie_value",
        "credentials",
        "loginrequestbody",
        "replacement",
    }

    def _walk(value: Any, key: str | None = None) -> Any:
        if isinstance(value, dict):
            return {k: _walk(v, str(k)) for k, v in value.items()}
        if isinstance(value, list):
            return [_walk(v, key) for v in value]
        if isinstance(value, str):
            low = (key or "").lower().replace("-", "_")
            if low in secret_keys or any(part in low for part in ("password", "secret", "token", "cookie")):
                return _REDACTED if value else value
            for hint in hints:
                if hint and hint in value:
                    return value.replace(hint, _REDACTED)
            return value
        return value

    return _walk(obj)


def _form_bodies(meta: dict[str, Any], secret_value: str) -> tuple[dict[str, str], str, bool]:
    username = _username_from_meta(meta)
    user_field, pass_field = _field_names(meta)
    login_url = (meta.get("login_url") or "").strip()
    success = (meta.get("success_url_contains") or "").strip()
    urls = _target_urls(meta)
    login_body = f"{quote(user_field)}={{%username%}}&{quote(pass_field)}={{%password%}}"

    payload = {
        "version": 1,
        "format": "attestra-zap-auth-v1",
        "method": "form",
        "zap_auth": "formBasedAuthentication",
        "login_url": login_url,
        "username": username,
        "username_field": user_field,
        "password_field": pass_field,
        "success_url_contains": success,
        "password": secret_value,
        "urls": urls,
    }
    af_yaml = {
        "env": {
            "contexts": [
                {
                    "name": "attestra-auth",
                    "urls": urls,
                    "authentication": {
                        "method": "form",
                        "parameters": {
                            "loginPageUrl": login_url,
                            "loginRequestUrl": login_url,
                            "loginRequestBody": login_body,
                        },
                        "verification": {
                            "method": "response",
                            "loggedInRegex": re.escape(success) if success else "\\Q\\E",
                        },
                    },
                    "sessionManagement": {"method": "cookie"},
                    "users": [
                        {
                            "name": username or "attestra-user",
                            "credentials": {
                                "username": username,
                                "password": secret_value,
                            },
                        }
                    ],
                }
            ]
        }
    }
    # Classic context snippet for -n (properties-style export ZAP still imports).
    context_lines = [
        "# Attestra-generated ZAP context (formBasedAuthentication)",
        "ctx.name=attestra-auth",
        f"ctx.desc=Attestra form auth for profile {meta.get('id') or meta.get('label') or ''}",
    ]
    for i, u in enumerate(urls):
        context_lines.append(f"ctx.url.regex.include.{i}={re.escape(u).replace(chr(92), chr(92) * 2)}.*")
    context_lines += [
        "ctx.auth.type=1",  # formBasedAuthentication
        f"ctx.auth.loginurl={login_url}",
        f"ctx.auth.loginpostdata={user_field}={{%username%}}&{pass_field}={{%password%}}",
        f"ctx.users.0.name={username or 'attestra-user'}",
        f"ctx.users.0.username={username}",
        f"ctx.users.0.password={secret_value}",
        "ctx.session.type=0",  # cookie-based
    ]
    if success:
        context_lines.append(f"ctx.auth.loggedinindicator={re.escape(success)}")

    bodies = {
        AUTH_JSON_NAME: json.dumps(payload, indent=2, separators=(",", ": ")),
        AUTH_YAML_NAME: yaml.safe_dump(af_yaml, sort_keys=False),
        CONTEXT_NAME: "\n".join(context_lines) + "\n",
    }
    return bodies, username or "attestra-user", True


def _header_bodies(meta: dict[str, Any], secret_value: str) -> tuple[dict[str, str], str, bool]:
    cfg = meta.get("config") or {}
    header_name = str(cfg.get("header_name") or cfg.get("header") or "Authorization").strip() or "Authorization"
    prefix = cfg.get("header_prefix")
    if prefix is None:
        prefix = "Bearer " if header_name.lower() == "authorization" and not secret_value.lower().startswith(
            "bearer "
        ) else ""
    prefix = str(prefix)
    header_value = f"{prefix}{secret_value}" if prefix and not secret_value.startswith(prefix) else secret_value
    urls = _target_urls(meta)
    username = _username_from_meta(meta) or "attestra-user"

    payload = {
        "version": 1,
        "format": "attestra-zap-auth-v1",
        "method": "header",
        "zap_auth": "headers",
        "header_name": header_name,
        "header_value": header_value,
        "urls": urls,
    }
    af_yaml = {
        "env": {
            "contexts": [
                {
                    "name": "attestra-auth",
                    "urls": urls,
                    "authentication": {"method": "manual"},
                    "sessionManagement": {
                        "method": "headers",
                        "parameters": {header_name: header_value},
                    },
                    "users": [{"name": username}],
                }
            ]
        }
    }
    context_lines = [
        "# Attestra-generated ZAP context (header session)",
        "ctx.name=attestra-auth",
        "ctx.auth.type=0",  # manual
        "ctx.session.type=3",  # headers-based session management (ZAP)
        f"ctx.session.headers.0={header_name}:{header_value}",
        f"ctx.users.0.name={username}",
    ]
    for i, u in enumerate(urls):
        context_lines.append(f"ctx.url.regex.include.{i}={re.escape(u)}.*")

    bodies = {
        AUTH_JSON_NAME: json.dumps(payload, indent=2, separators=(",", ": ")),
        AUTH_YAML_NAME: yaml.safe_dump(af_yaml, sort_keys=False),
        CONTEXT_NAME: "\n".join(context_lines) + "\n",
    }
    return bodies, username, True


def _cookie_bodies(meta: dict[str, Any], secret_value: str) -> tuple[dict[str, str], str, bool]:
    cfg = meta.get("config") or {}
    cookie_name = str(cfg.get("cookie_name") or cfg.get("cookie") or "session").strip() or "session"
    urls = _target_urls(meta)
    username = _username_from_meta(meta) or "attestra-user"
    cookie_header = f"{cookie_name}={secret_value}"

    payload = {
        "version": 1,
        "format": "attestra-zap-auth-v1",
        "method": "cookie",
        "zap_auth": "httpSessions",
        "cookie_name": cookie_name,
        "cookie_value": secret_value,
        "urls": urls,
    }
    af_yaml = {
        "env": {
            "contexts": [
                {
                    "name": "attestra-auth",
                    "urls": urls,
                    "authentication": {"method": "manual"},
                    "sessionManagement": {"method": "cookie"},
                    "users": [{"name": username}],
                }
            ]
        },
        "attestra_http_sessions": {
            "cookies": {cookie_name: secret_value},
            "cookie_header": cookie_header,
        },
    }
    context_lines = [
        "# Attestra-generated ZAP context (cookie / httpSessions)",
        "ctx.name=attestra-auth",
        "ctx.auth.type=0",
        "ctx.session.type=0",
        f"ctx.session.tokens.0={cookie_name}",
        f"ctx.users.0.name={username}",
        f"# cookie_header={cookie_header}",
    ]
    for i, u in enumerate(urls):
        context_lines.append(f"ctx.url.regex.include.{i}={re.escape(u)}.*")

    bodies = {
        AUTH_JSON_NAME: json.dumps(payload, indent=2, separators=(",", ": ")),
        AUTH_YAML_NAME: yaml.safe_dump(af_yaml, sort_keys=False),
        CONTEXT_NAME: "\n".join(context_lines) + "\n",
    }
    return bodies, username, True


def build_zap_auth_context(
    profile: AuthCredentialProfile | dict[str, Any],
    secret_value: str,
) -> ZapAuthContext:
    """Build a ZAP auth context descriptor for form/header/cookie profiles.

    Secret-bearing file bodies are held on ``ZapAuthContext._bodies`` (excluded
    from ``repr``/``str``). Call :func:`write_zap_auth_files` to persist them.
    Public metadata never embeds the secret.
    """
    meta = _as_meta(profile)
    method = (meta.get("method") or "").strip().lower()
    public = {
        "profile_id": meta.get("id"),
        "label": meta.get("label") or "",
        "role_name": meta.get("role_name") or "",
        "method": method,
        "login_url": meta.get("login_url") or "",
        "success_url_contains": meta.get("success_url_contains") or "",
        "has_selectors": bool(meta.get("username_selector") or meta.get("password_selector")),
        "config_keys": sorted(str(k) for k in (meta.get("config") or {})),
    }

    if method not in AUTH_METHODS and method:
        raise ZapAuthError(f"unsupported auth method: {method}")

    if method == "sso_bootstrap":
        return ZapAuthContext(
            status="blocked",
            method=method,
            reason=_SSO_REASON,
            public=public,
        )

    if method in ("", "none"):
        return ZapAuthContext(
            status="skipped",
            method=method or "none",
            reason="method=none: unauthenticated ZAP baseline",
            public=public,
        )

    if not isinstance(secret_value, str) or secret_value == "":
        raise ZapAuthError("secret_value is required for this auth method")

    if method == "form":
        bodies, zap_user, use_n = _form_bodies(meta, secret_value)
    elif method == "header":
        bodies, zap_user, use_n = _header_bodies(meta, secret_value)
    elif method == "cookie":
        bodies, zap_user, use_n = _cookie_bodies(meta, secret_value)
    else:
        raise ZapAuthError(f"unsupported auth method: {method}")

    # Ensure secret never lands in public metadata.
    public = redact_auth_diagnostics(public, secret_hints=[secret_value])
    return ZapAuthContext(
        status="ready",
        method=method,
        public=public,
        zap_user=zap_user,
        use_n_flag=use_n,
        _bodies=bodies,
    )


def write_zap_auth_files(out_dir: Path | str, ctx: ZapAuthContext) -> dict[str, Any]:
    """Write auth files under ``out_dir`` with restrictive permissions.

    Returns public metadata including paths. File bodies that contain secrets are
    never included in the return value.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: dict[str, str] = {}
    for name, body in (ctx._bodies or {}).items():
        path = out / name
        path.write_text(body, encoding="utf-8")
        _restrictive_chmod(path)
        written[name] = str(path)

    public_path = out / PUBLIC_META_NAME
    meta = ctx.redacted_dict()
    meta["written"] = {k: Path(v).name for k, v in written.items()}
    public_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    _restrictive_chmod(public_path)

    result = {
        "status": ctx.status,
        "method": ctx.method,
        "reason": ctx.reason,
        "zap_user": ctx.zap_user,
        "use_n_flag": ctx.use_n_flag,
        "auth_context_path": written.get(CONTEXT_NAME, ""),
        "auth_json_path": written.get(AUTH_JSON_NAME, ""),
        "auth_yaml_path": written.get(AUTH_YAML_NAME, ""),
        "public_meta_path": str(public_path),
        "public": ctx.public,
    }
    return redact_auth_diagnostics(result)


def load_profile_secret(
    session: Session,
    profile_id: int,
    *,
    engagement_id: int | None = None,
    principal=None,
) -> tuple[AuthCredentialProfile, str]:
    """Load a profile and its secret with engagement/tenant checks.

    Uses :func:`attestra.credentials.get_secret`. The secret must not be logged;
    callers should treat the return value as sensitive and never put it on
    ScanRun, argv, or quarantine notes.
    """
    if not isinstance(profile_id, int) or profile_id < 1:
        raise ZapAuthError("profile_id must be a positive int")

    row = session.get(AuthCredentialProfile, profile_id)
    if row is None:
        raise LookupError(f"auth profile {profile_id} not found")

    eng = services.get_engagement(session, row.engagement_id, principal)
    if row.tenant_id != eng.tenant_id or row.engagement_id != eng.id:
        raise LookupError(f"auth profile {profile_id} not found")
    if engagement_id is not None and eng.id != engagement_id:
        raise LookupError(f"auth profile {profile_id} not found")

    ref = (row.secret_ref or "").strip()
    if not ref:
        raise ZapAuthError("auth profile has no secret_ref")

    try:
        from attestra.credentials.store import parse_secret_ref

        tid, eid, _ = parse_secret_ref(ref)
    except SecretsError as exc:
        raise ZapAuthError("invalid secret_ref on auth profile") from exc
    if tid != row.tenant_id or eid != row.engagement_id:
        raise ZapAuthError("secret_ref does not belong to this engagement")

    try:
        secret = credentials.get_secret(ref)
    except SecretsError as exc:
        raise ZapAuthError("secret not found for auth profile") from exc
    return row, secret


def prepare_zap_auth(
    out_dir: Path | str,
    profile: AuthCredentialProfile | dict[str, Any],
    secret_value: str,
) -> dict[str, Any]:
    """Build + write ZAP auth files; return public metadata for scanner wiring."""
    ctx = build_zap_auth_context(profile, secret_value)
    if ctx.status != "ready":
        return ctx.redacted_dict()
    return write_zap_auth_files(out_dir, ctx)
