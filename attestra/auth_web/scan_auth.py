"""Wire per-target authentication profiles into the scanners (ZAP, Nuclei).

This is the glue that turns an :class:`AuthCredentialProfile` + its stored secret
into concrete session material (request headers / cookies) and the per-tool
artifacts the adapters consume:

* **ZAP** — a mounted *hook* file (``--hook``) that installs a Replacer rule on
  ``zap_started`` so every request (baseline spider, passive and active scan)
  carries the session header/cookie. For ``form`` profiles we additionally keep
  the native ZAP form-auth context as a fallback.
* **Nuclei** — a mounted *secret file* (``-sf``, authx ``static`` headers) so the
  session header/cookie rides on every probe without ever hitting ``argv``.

Secrets never touch ``argv``, ScanRun rows, audit details, or logs. They live
only inside restrictive (0600) files in a per-scan *secret directory* created with
:func:`new_secret_dir` OUTSIDE ``data/raw`` (default: the OS temp dir under
``attestra-auth-secrets``; override with ``ATTESTRA_AUTH_SECRET_DIR``). The scanner
container gets that directory as a separate read-only mount, and
:meth:`ScanAuthPlan.cleanup` deletes it when the scan ends (success, failure,
timeout, cancel, Stop Worker). :func:`sweep_leftover_secrets` removes anything a
crashed worker left behind (run on worker start).

Supported methods (``AuthCredentialProfile.method``):

* ``header``  — paste an ``Authorization`` (or named) header value. Works for
  bearer tokens, SSO, 2FA — anything that yields a long-lived header.
* ``cookie``  — paste a session cookie value (or a full ``Cookie:`` string).
* ``form``    — username + password form login; we POST the form, capture the
  session cookie, and inject it (falls back to ZAP's native form context).
* ``otp``     — email one-time-passcode login via a test IMAP inbox
  (see :mod:`attestra.auth_web.otp`).
* ``none`` / ``sso_bootstrap`` — no injection (sso_bootstrap is reported blocked).
"""
# @lat: [[architecture#Authenticated website testing]]
# @lat: [[runner#Authenticated scan wiring]]

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from attestra.auth_web import extra_cookies as xc
from attestra.auth_web import extra_headers as xh
from attestra.auth_web import otp as otp_mod

_FILE_MODE = 0o600
_DIR_MODE = 0o700
# Legacy (pre-fix) name of the separate ZAP auth hook; ZAP accepts only ONE --hook, so the
# auth injection now lives in the crawl hook (attestra/runner/scanners/zap_crawl.py).
_HOOK_NAME = "attestra-zap-hooks.py"
_HOOK_DATA_NAME = "attestra-zap-hook-data.json"
_NUCLEI_SECRET_NAME = "attestra-nuclei-auth.yaml"
SECRET_DIR_ENV = "ATTESTRA_AUTH_SECRET_DIR"
_SECRET_DIR_DEFAULT = "attestra-auth-secrets"
# Every file name that has ever carried auth material inside data/raw/scan-*/ (swept on start).
LEGACY_SECRET_FILE_NAMES = (
    _HOOK_DATA_NAME,
    _NUCLEI_SECRET_NAME,
    _HOOK_NAME,
    "attestra-zap-hooks.cpython-311.pyc",
    "attestra-zap-auth.json",
    "attestra-zap-auth.yaml",
    "attestra-auth.context",
)
_USER_AGENT = "attestra-auth-web/0.1 (security testing)"
_FETCH_TIMEOUT_S = 10.0


class ScanAuthError(Exception):
    """Authentication material could not be prepared."""


@dataclass
class ScanAuthPlan:
    """Per-tool wiring + status for one authenticated scan.

    ``status`` is one of ``ready`` (inject + authenticated), ``skipped`` (no
    profile / method=none), ``blocked`` (sso_bootstrap), or ``error``.
    Secret-bearing material stays in mounted files, never on these fields.
    """

    status: str = "skipped"
    method: str = "none"
    profile_id: int | None = None
    profile_label: str = ""
    role_name: str = ""
    note: str = ""
    authenticated: bool = False
    # ZAP
    zap_auth_context_path: str | None = None
    zap_auth_opts: dict[str, Any] = field(default_factory=dict)
    # Nuclei
    nuclei_secret_file: str | None = None
    # non-secret diagnostic: header/cookie names only, never values
    injected_names: list[str] = field(default_factory=list)
    # Per-scan secret directory (outside data/raw); removed by cleanup().
    secret_dir: str | None = None
    # Secret values to mask in any scanner log we keep. Never rendered (repr=False).
    redact_values: tuple[str, ...] = field(default=(), repr=False)

    def zap_kwargs(self) -> dict[str, Any]:
        if not self.authenticated:
            return {}
        return {
            "auth_context_path": self.zap_auth_context_path,
            "auth_opts": dict(self.zap_auth_opts),
            "redact_values": tuple(self.redact_values),
        }

    def nuclei_kwargs(self) -> dict[str, Any]:
        if not self.authenticated or not self.nuclei_secret_file:
            return {}
        return {"auth_secret_file": self.nuclei_secret_file, "redact_values": tuple(self.redact_values)}

    def cleanup(self) -> bool:
        """Delete the per-scan secret directory. Idempotent; never raises."""
        path, self.secret_dir = self.secret_dir, None
        self.redact_values = ()
        if not path:
            return False
        return remove_secret_dir(path)


# ------------------------------------------------------------- secret directory


def secret_root() -> Path:
    """Parent of all per-scan secret dirs (outside data/raw)."""
    raw = (os.environ.get(SECRET_DIR_ENV) or "").strip()
    return Path(raw) if raw else Path(tempfile.gettempdir()) / _SECRET_DIR_DEFAULT


def _ensure_not_under_raw(path: Path) -> None:
    try:
        from attestra import config

        raw = (config.DATA_DIR / "raw").resolve()
        path.resolve().relative_to(raw)
    except ValueError:
        return  # not under data/raw: good
    except Exception:  # noqa: BLE001 - config unavailable in odd test setups
        return
    raise ScanAuthError(f"{SECRET_DIR_ENV} must not point inside data/raw (scan artifacts)")


def new_secret_dir(run_id: int | str | None) -> Path:
    """Create a fresh 0700 directory for one scan's secret files."""
    root = secret_root()
    _ensure_not_under_raw(root)
    root.mkdir(parents=True, exist_ok=True)
    _chmod(root, _DIR_MODE)
    path = Path(tempfile.mkdtemp(prefix=f"scan-{run_id or 'x'}-", dir=str(root)))
    _chmod(path, _DIR_MODE)
    return path


def remove_secret_dir(path: Path | str, *, attempts: int = 5) -> bool:
    """Best-effort delete of a secret dir (retries: Docker may release the mount late on Windows)."""
    p = Path(path)
    for i in range(attempts):
        if not p.exists():
            return True
        # Truncate files first so nothing readable survives a partial rmtree.
        for f in p.rglob("*"):
            try:
                if f.is_file():
                    f.write_bytes(b"")
            except OSError:
                pass
        shutil.rmtree(p, ignore_errors=True)
        if not p.exists():
            return True
        time.sleep(0.2 * (i + 1))
    return not p.exists()


def purge_legacy_secret_files(out_dir: Path | str) -> list[str]:
    """Remove auth files older code wrote into a scan's raw dir. Returns removed names."""
    out = Path(out_dir)
    removed: list[str] = []
    for name in LEGACY_SECRET_FILE_NAMES:
        candidates = [out / name]
        if name.endswith(".pyc"):
            candidates.append(out / "__pycache__" / name)
        for f in candidates:
            try:
                if f.is_file():
                    f.write_bytes(b"")
                    f.unlink()
                    removed.append(str(f.relative_to(out)))
            except OSError:
                pass
    return removed


_SCAN_DIR_RE = re.compile(r"^scan-(\d+)(?:-|$)")


def sweep_leftover_secrets(
    raw_root: Path | str | None = None,
    *,
    active_run_ids: set[int] | frozenset[int] = frozenset(),
) -> list[str]:
    """Delete leaked auth files for scans that are NOT running.

    * ``data/raw/scan-<id>/`` — legacy secret file names (pre-fix leaks).
    * ``<secret_root>/scan-<id>-*`` — temp secret dirs a killed worker left behind.

    Returns the removed paths (relative names only; never file contents).
    """
    removed: list[str] = []
    if raw_root is None:
        from attestra import config

        raw_root = config.DATA_DIR / "raw"
    raw = Path(raw_root)
    if raw.is_dir():
        for d in raw.iterdir():
            m = _SCAN_DIR_RE.match(d.name)
            if not d.is_dir() or not m or int(m.group(1)) in active_run_ids:
                continue
            removed += [f"{d.name}/{n}" for n in purge_legacy_secret_files(d)]
    root = secret_root()
    if root.is_dir():
        for d in root.iterdir():
            m = _SCAN_DIR_RE.match(d.name)
            if not d.is_dir() or (m and int(m.group(1)) in active_run_ids):
                continue
            if remove_secret_dir(d):
                removed.append(f"{root.name}/{d.name}")
    return removed


# --------------------------------------------------------------- session material


def _mask_header_prefix(secret: str, cfg: dict[str, Any]) -> str:
    name = str(cfg.get("header_name") or cfg.get("name") or "Authorization").strip() or "Authorization"
    prefix = cfg.get("header_prefix")
    if prefix is None:
        prefix = "Bearer " if name.lower() == "authorization" and not secret.lower().startswith("bearer ") else ""
    prefix = str(prefix)
    value = f"{prefix}{secret}" if prefix and not secret.startswith(prefix) else secret
    return value


def session_material(
    method: str,
    cfg: dict[str, Any],
    secret: str,
    *,
    http_post: "otp_mod.HttpPost | None" = None,
    imap_search: "otp_mod.ImapSearch | None" = None,
) -> tuple[dict[str, str], dict[str, str], str]:
    """Return ``(headers, cookies, note)`` for the given auth method.

    ``headers`` are plain ``name: value`` request headers; ``cookies`` is a
    ``name: value`` map. For ``form``/``otp`` a live login is performed via the
    injected ``http_post`` (and ``imap_search`` for otp).
    """
    method = (method or "").strip().lower()
    secrets = otp_mod.parse_profile_secret(secret)

    if method == "header":
        name = str(cfg.get("header_name") or cfg.get("name") or "Authorization").strip() or "Authorization"
        value = _mask_header_prefix(secret, cfg)
        return {name: value}, {}, "header injected"

    if method == "cookie":
        raw = secret.strip()
        if "=" in raw and (";" in raw or cfg.get("cookie_is_header")):
            # A full "name=value; name2=value2" cookie string.
            cookies = _parse_cookie_string(raw)
            return {}, cookies, "cookie string injected"
        name = str(cfg.get("cookie_name") or cfg.get("name") or "session").strip() or "session"
        return {}, {name: raw}, "cookie injected"

    if method == "form":
        if http_post is None:
            raise ScanAuthError("form login requires an http transport")
        cookies = _form_login(cfg, secrets, http_post=http_post)
        return {}, cookies, "form login ok"

    if method == "otp":
        if http_post is None:
            raise ScanAuthError("otp login requires an http transport")
        result = otp_mod.login_with_otp(cfg, secrets, http_post=http_post, imap_search=imap_search)
        return {}, dict(result.cookies), result.note

    if method in ("", "none"):
        return {}, {}, "no authentication"
    if method == "sso_bootstrap":
        raise ScanAuthError("sso_bootstrap cannot be automated; use a cookie or header profile")
    raise ScanAuthError(f"unsupported auth method: {method}")


def _parse_cookie_string(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in raw.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        if k.strip():
            out[k.strip()] = v.strip()
    return out


def _form_login(cfg: dict[str, Any], secrets: dict[str, str], *, http_post: "otp_mod.HttpPost") -> dict[str, str]:
    login_url = str(cfg.get("login_url") or "").strip()
    if not login_url:
        raise ScanAuthError("login_url is required for form login")
    username = str(cfg.get("username") or "").strip()
    password = secrets.get("password") or ""
    if not username or not password:
        raise ScanAuthError("username and password are required for form login")
    user_field = str(cfg.get("username_field") or "username")
    pass_field = str(cfg.get("password_field") or "password")
    reply = http_post(login_url, {user_field: username, pass_field: password}, {})
    if reply.status >= 400:
        raise ScanAuthError(f"form login failed (HTTP {reply.status})")
    cookies = dict(reply.cookies or {})
    if not cookies:
        raise ScanAuthError("form login completed but no session cookie was set")
    return cookies


def cookie_header(cookies: dict[str, str]) -> str:
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


def all_request_headers(headers: dict[str, str], cookies: dict[str, str]) -> dict[str, str]:
    out = dict(headers)
    if cookies:
        existing = out.get("Cookie")
        ch = cookie_header(cookies)
        out["Cookie"] = f"{existing}; {ch}" if existing else ch
    return out


# -------------------------------------------------------------------- ZAP auth data


def target_url_regex(target_url: str) -> str:
    """Java-compatible regex matching only the target host (scheme/port tolerant)."""
    host = (urlsplit(target_url).hostname or "").lower()
    if not host:
        return ""
    esc = "".join(c if c.isalnum() else "\\" + c for c in host)
    return "^https?://" + esc + "(?::[0-9]+)?(?:[/?#].*)?$"


def write_zap_hook(
    out_dir: Path | str,
    headers: dict[str, str],
    cookies: dict[str, str],
    *,
    target_url: str = "",
) -> str:
    """Write the ZAP auth-header data file into ``out_dir`` (a per-scan SECRET dir).

    Returns the data file path. The single Attestra ZAP hook
    (:mod:`attestra.runner.scanners.zap_crawl`) reads it from the read-only secrets
    mount at ``zap_started`` and installs one Replacer rule per header, limited to
    the target host so the session never rides to CDNs / identity providers the
    AJAX spider's browser loads. ``out_dir`` must not be the raw artifact dir.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    data = {"headers": all_request_headers(headers, cookies), "url_regex": target_url_regex(target_url)}
    data_path = out / _HOOK_DATA_NAME
    _write_secret(data_path, json.dumps(data))
    return str(data_path)


# ------------------------------------------------------------------- Nuclei file


def write_nuclei_secret_file(
    out_dir: Path | str,
    target_url: str,
    headers: dict[str, str],
    cookies: dict[str, str],
) -> str:
    """Write a Nuclei authx secret file (``-sf``) with the session headers.

    Returns the file path. Secret values stay in this 0600 file, never on argv.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    all_headers = all_request_headers(headers, cookies)
    host = urlsplit(target_url).hostname or ""
    # nuclei authx schema (v3): ``headers`` is a LIST of {key, value} objects. A mapping
    # makes nuclei v3.11 exit with "[FTL] ... cannot unmarshal !!map into []authx.KV".
    entry: dict[str, Any] = {"type": "header"}
    if host:
        entry["domains"] = [host]
    entry["headers"] = [{"key": k, "value": v} for k, v in all_headers.items()]
    doc = {"static": [entry]}
    import yaml

    path = out / _NUCLEI_SECRET_NAME
    _write_secret(path, yaml.safe_dump(doc, sort_keys=False))
    return str(path)


def _write_secret(path: Path, text: str) -> None:
    """Create the file 0600 from the start (no world-readable window on POSIX)."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(str(path), flags, _FILE_MODE)
    with os.fdopen(fd, "wb") as fh:
        fh.write(text.encode("utf-8"))
    _chmod(path)


def _chmod(path: Path, mode: int = _FILE_MODE) -> None:
    try:
        path.chmod(mode)
    except OSError:
        pass


# ------------------------------------------------------------- pre-scan check

# login_probe(url, headers) -> (status_code|None, body_text). ``headers`` include the
# profile's extra headers (see prepare_for_run).
LoginProbe = Callable[[str, dict[str, str]], tuple[int | None, str]]


def verify_logged_in(
    cfg: dict[str, Any],
    headers: dict[str, str],
    cookies: dict[str, str],
    *,
    login_probe: LoginProbe,
) -> tuple[bool, str]:
    """Confirm the session is authenticated by probing a protected URL.

    Checks (in order): a ``logged_in_indicator`` regex must appear, a
    ``logged_out_indicator`` regex must NOT appear, and the response must not be
    an auth redirect/401/403. Returns ``(ok, note)`` with a redacted note.
    """
    url = str(cfg.get("verify_url") or cfg.get("success_url") or cfg.get("login_url") or "").strip()
    if not url:
        return True, "no verify_url configured; skipped pre-scan login check"
    req_headers = all_request_headers(headers, cookies)
    req_headers.setdefault("User-Agent", _USER_AGENT)
    try:
        status, body = login_probe(url, req_headers)
    except Exception as exc:  # noqa: BLE001 - redact
        return False, f"login check request failed: {type(exc).__name__}"

    if status in (401, 403):
        detail = server_error_detail(body)
        return False, f"login check got HTTP {status} ({detail or 'not authenticated'})"

    logged_out = str(cfg.get("logged_out_indicator") or "").strip()
    if logged_out:
        try:
            if re.search(logged_out, body):
                return False, "login check saw the logged-out indicator (session not active)"
        except re.error:
            return False, "invalid logged_out_indicator regex"

    logged_in = str(cfg.get("logged_in_indicator") or "").strip()
    if logged_in:
        try:
            if not re.search(logged_in, body):
                return False, "login check did not find the logged-in indicator"
        except re.error:
            return False, "invalid logged_in_indicator regex"
        return True, "login check passed (logged-in indicator present)"

    success = str(cfg.get("success_url_contains") or "").strip()
    if success and success not in body and status and status >= 400:
        detail = server_error_detail(body)
        return False, f"login check got HTTP {status}" + (f" ({detail})" if detail else "")
    return True, "login check passed (no explicit indicator; response ok)"


_TOKENISH_RES = (
    re.compile(r"eyJ[A-Za-z0-9_-]{5,}(?:\.[A-Za-z0-9_-]*){0,2}"),  # JWT / JWS
    re.compile(r"(?i)\bbearer\s+\S+"),
    re.compile(r"[A-Za-z0-9+/_=.-]{24,}"),  # long opaque token / hex / base64 run
)
_DETAIL_MAX = 80
_CODE_KEYS = ("code", "error_code", "errorCode", "errorcode")
_MSG_KEYS = ("message", "error_description", "error", "detail", "msg")


def _redact_detail(text: str) -> str:
    out = " ".join(str(text).split())
    for rx in _TOKENISH_RES:
        out = rx.sub("[redacted]", out)
    if len(out) > _DETAIL_MAX:
        out = out[: _DETAIL_MAX - 3].rstrip() + "..."
    return out


def server_error_detail(body: str | None) -> str:
    """Short, non-secret reason from a JSON error body: its ``code`` or ``message``.

    Token-like strings are redacted and the result is capped at 80 characters.
    Returns "" when the body is not JSON or carries no usable field.
    """
    if not body or not isinstance(body, str):
        return ""
    try:
        doc = json.loads(body[:20_000])
    except Exception:  # noqa: BLE001 - HTML / text bodies: say nothing
        return ""
    candidates: list[Any] = []
    if isinstance(doc, dict):
        nested = doc.get("error") if isinstance(doc.get("error"), dict) else None
        for src in (doc, nested or {}):
            candidates += [src.get(k) for k in _CODE_KEYS]
        for src in (doc, nested or {}):
            candidates += [src.get(k) for k in _MSG_KEYS]
    for c in candidates:
        if isinstance(c, (str, int)) and not isinstance(c, bool) and str(c).strip():
            return _redact_detail(str(c))
    return ""


# ------------------------------------------------------------ run orchestration


def _profile_cfg(profile) -> dict[str, Any]:
    """Build the effective config dict from the profile columns + config_json."""
    cfg = dict(getattr(profile, "config_json", None) or {})
    for col in (
        "login_url",
        "username_selector",
        "password_selector",
        "submit_selector",
        "success_url_contains",
        "role_name",
    ):
        val = getattr(profile, col, "")
        if val and col not in cfg:
            cfg[col] = val
    return cfg


def _allowed_hosts(profile, target_url: str) -> set[str]:
    hosts: set[str] = set()
    for u in (target_url, getattr(profile, "login_url", "") or "", (profile.config_json or {}).get("verify_url", "")):
        try:
            host = urlsplit(u).hostname
        except Exception:
            host = None
        if host:
            hosts.add(host.lower())
    return hosts


def _host_ok(url: str, allowed: set[str]) -> bool:
    try:
        host = (urlsplit(url).hostname or "").lower()
    except Exception:
        return False
    return bool(host) and host in allowed


def live_http_post(
    allowed_hosts: set[str],
    *,
    timeout_s: float = _FETCH_TIMEOUT_S,
    extra_headers: list[tuple[str, str]] | None = None,
    extra_cookies: list[tuple[str, str]] | None = None,
) -> "otp_mod.HttpPost":
    """A urllib-based form POST restricted to the allowlisted hosts (for login).

    ``extra_headers`` (profile's non-secret extras) are added; they never override
    the client's own User-Agent / Content-Type / Cookie. ``extra_cookies`` (profile's
    encrypted extras) join the request cookies; the login flow's own cookies win.
    """
    import urllib.parse
    import urllib.request
    from http.cookiejar import CookieJar

    def _post(url: str, data: dict[str, str], cookies: dict[str, str]) -> "otp_mod.HttpReply":
        if not _host_ok(url, allowed_hosts):
            raise ScanAuthError("login URL host is not in scope for this target")
        jar = CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        body = urllib.parse.urlencode(data).encode("utf-8")
        headers = {"User-Agent": _USER_AGENT, "Content-Type": "application/x-www-form-urlencoded"}
        cookies = xc.merge_cookies(dict(cookies or {}), list(extra_cookies or []))
        if cookies:
            headers["Cookie"] = cookie_header(cookies)
        headers = xh.merge_extra_headers(headers, list(extra_headers or []))
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        got: dict[str, str] = {}
        status = 200
        final = url
        try:
            with opener.open(req, timeout=timeout_s) as resp:  # noqa: S310 - host allowlisted
                status = int(getattr(resp, "status", 200) or 200)
                final = getattr(resp, "geturl", lambda: url)() or url
                text = resp.read(200_000).decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "code", None)
            status = int(code) if isinstance(code, int) else 599
            text = ""
        for ck in jar:
            got[ck.name] = ck.value or ""
        return otp_mod.HttpReply(status=status, body=text, cookies=got, final_url=final)

    return _post


def live_login_probe(allowed_hosts: set[str], *, timeout_s: float = _FETCH_TIMEOUT_S) -> LoginProbe:
    """A urllib GET restricted to allowlisted hosts (for the pre-scan login check)."""
    import urllib.request

    def _probe(url: str, headers: dict[str, str]) -> tuple[int | None, str]:
        if not _host_ok(url, allowed_hosts):
            raise ScanAuthError("verify URL host is not in scope for this target")
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310 - host allowlisted
                status = int(getattr(resp, "status", 200) or 200)
                text = resp.read(500_000).decode("utf-8", "replace")
                return status, text
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "code", None)
            if isinstance(code, int):
                body = ""
                try:
                    body = exc.read(200_000).decode("utf-8", "replace")  # type: ignore[attr-defined]
                except Exception:
                    pass
                return code, body
            raise

    return _probe


def _redaction_values(
    secret: str,
    headers: dict[str, str],
    cookies: dict[str, str],
    *,
    extra_values: list[str] | tuple[str, ...] = (),
) -> tuple[str, ...]:
    vals = {secret or ""}
    vals.update(str(v) for v in extra_values or ())
    vals.update(headers.values())
    vals.update(cookies.values())
    for v in list(vals):
        if v.lower().startswith("bearer "):
            vals.add(v[7:].strip())
    try:
        vals.update(otp_mod.parse_profile_secret(secret).values())
    except Exception:  # noqa: BLE001
        pass
    return tuple(sorted((v for v in vals if isinstance(v, str) and len(v) >= 4), key=len, reverse=True))



def _load_extra_cookies(profile, method: str, cfg: dict[str, Any]) -> list[tuple[str, str]]:
    """Decrypt + parse the profile's extra cookies (``[]`` when none). Value-free errors."""
    ref = (getattr(profile, "extra_cookies_ref", "") or "").strip()
    if not ref:
        return []
    from attestra import credentials

    try:
        text = credentials.get_secret(ref)
    except Exception as exc:  # noqa: BLE001 - never surface store internals
        raise ScanAuthError("auth profile extra cookies could not be decrypted; set them again") from exc
    try:
        pairs = xc.parse_extra_cookies(text)
    except xc.ExtraCookiesError as exc:
        raise ScanAuthError(f"auth profile extra cookies are invalid: {exc}") from exc
    own = xc.own_cookie_name(method, cfg)
    return [(k, v) for k, v in pairs if k != own]


def load_profile_for_run(s, run) -> Any | None:
    """Load the AuthCredentialProfile referenced by ``run.auth_profile_id`` (or None)."""
    pid = getattr(run, "auth_profile_id", None)
    if not pid:
        return None
    from attestra.models import AuthCredentialProfile

    row = s.get(AuthCredentialProfile, pid)
    if row is None:
        raise ScanAuthError(f"auth profile {pid} not found")
    if row.engagement_id != run.engagement_id:
        raise ScanAuthError("auth profile does not belong to this engagement")
    if (row.status or "") == "revoked":
        raise ScanAuthError("auth profile is revoked")
    return row


def prepare_for_run(
    s,
    run,
    out_dir: Path | str,
    *,
    tool: str,
    target_url: str,
    http_post: "otp_mod.HttpPost | None" = None,
    imap_search: "otp_mod.ImapSearch | None" = None,
    login_probe: LoginProbe | None = None,
    verify: bool = True,
    secret_dir: Path | str | None = None,
) -> ScanAuthPlan:
    """Prepare authenticated-scan artifacts for one ScanRun + tool.

    ``out_dir`` is the scan's raw artifact dir: NO secret is written there (legacy
    leaked files in it are purged). Secret files go to ``secret_dir`` (default: a
    fresh :func:`new_secret_dir`), which the caller MUST release with
    :meth:`ScanAuthPlan.cleanup` in a ``finally`` block.

    Returns a :class:`ScanAuthPlan`. Raises :class:`ScanAuthError` when a profile
    was requested but authentication could not be established (the caller fails
    the scan with the returned message); no secret dir survives that case.
    """
    try:
        purge_legacy_secret_files(out_dir)
    except Exception:  # noqa: BLE001 - housekeeping only
        pass
    profile = load_profile_for_run(s, run)
    if profile is None:
        return ScanAuthPlan(status="skipped", note="unauthenticated scan")

    method = (profile.method or "").strip().lower()
    plan = ScanAuthPlan(
        status="skipped",
        method=method,
        profile_id=profile.id,
        profile_label=profile.label or "",
        role_name=profile.role_name or "",
    )
    if method in ("", "none"):
        plan.note = "profile method=none; unauthenticated scan"
        return plan
    if method == "sso_bootstrap":
        plan.status = "blocked"
        plan.note = "sso_bootstrap cannot be automated; use a cookie or header profile"
        raise ScanAuthError(plan.note)

    from attestra import credentials

    ref = (profile.secret_ref or "").strip()
    if not ref:
        raise ScanAuthError("auth profile has no stored secret")
    secret = credentials.get_secret(ref)

    cfg = _profile_cfg(profile)
    try:
        extra = xh.parse_extra_headers(
            getattr(profile, "extra_headers", "") or "", own_header_name=xh.own_header_name(method, cfg)
        )
    except xh.ExtraHeadersError as exc:
        raise ScanAuthError(f"auth profile extra headers are invalid: {exc}") from exc
    extra_cookies = _load_extra_cookies(profile, method, cfg)
    allowed = _allowed_hosts(profile, target_url)
    if http_post is None:
        http_post = live_http_post(allowed, extra_headers=extra, extra_cookies=extra_cookies)
    if login_probe is None:
        login_probe = live_login_probe(allowed)

    headers, cookies, note = session_material(
        method, cfg, secret, http_post=http_post, imap_search=imap_search
    )
    if not headers and not cookies:
        raise ScanAuthError("no session header or cookie could be prepared")
    # Encrypted extra cookies join the session cookies in ONE Cookie header (session wins).
    cookies = xc.merge_cookies(cookies, extra_cookies)
    # Redact the session material incl. every extra cookie value; extra headers are
    # non-secret by contract.
    redact = _redaction_values(secret, headers, cookies, extra_values=[v for _, v in extra_cookies])
    # Extra headers ride with the session everywhere it is injected (verify, ZAP, Nuclei);
    # session headers always win on a name clash.
    headers = xh.merge_extra_headers(headers, extra)

    if verify:
        ok, vnote = verify_logged_in(cfg, headers, cookies, login_probe=login_probe)
        if not ok:
            raise ScanAuthError(vnote)
        note = f"{note}; {vnote}"

    created = secret_dir is None
    sdir = new_secret_dir(getattr(run, "id", None)) if created else Path(secret_dir)
    plan.secret_dir = str(sdir)
    plan.redact_values = redact
    try:
        if tool == "zap":
            plan.zap_auth_opts = {
                "headers_file": write_zap_hook(sdir, headers, cookies, target_url=target_url),
                "secret_dir": str(sdir),
            }
            # Keep a native ZAP form context as a fallback for full (active) scans.
            if method == "form":
                try:
                    from attestra.auth_web.zap_auth import prepare_zap_auth

                    res = prepare_zap_auth(sdir, profile, secret)
                    if res.get("status") == "ready" and res.get("auth_context_path"):
                        plan.zap_auth_context_path = res["auth_context_path"]
                        plan.zap_auth_opts["context_path"] = res["auth_context_path"]
                        if res.get("zap_user"):
                            plan.zap_auth_opts["user"] = res["zap_user"]
                except Exception:
                    pass
        elif tool == "nuclei":
            plan.nuclei_secret_file = write_nuclei_secret_file(sdir, target_url, headers, cookies)
    except BaseException:
        if created:
            plan.cleanup()
        raise

    plan.injected_names = sorted(list(headers.keys()) + (["Cookie"] if cookies else []))
    plan.authenticated = True
    plan.status = "ready"
    plan.note = note[:480]
    return plan
