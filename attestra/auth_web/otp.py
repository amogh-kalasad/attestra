"""Email-OTP login helper for authenticated website testing.

Minimal, well-tested pieces for logging into a web app that gates sign-in behind
an emailed one-time passcode (OTP), then capturing the resulting session so the
scanners (ZAP / Nuclei) can run authenticated.

Design
------
* Everything that touches the network or an IMAP inbox takes an injectable
  callable so the orchestration is unit-testable without live services.
* No secret value is ever logged. Passwords and app-passwords live only in the
  encrypted credential store and are passed in as plain strings at call time.
* This is a best-effort HTTP form login. JavaScript-only single-page logins may
  still need a pasted session cookie/token (``method=cookie``/``header``); the
  caller falls back to a clear error in that case.

Config keys (``AuthCredentialProfile.config_json``) used here::

    login_url            full URL of the login form POST target (or page)
    username             the account's username / email
    username_field       form field name for the username (default "username")
    password_field       form field name for the password (default "password")
    otp_request_url      optional URL that triggers the OTP email (default login_url)
    otp_field            form field name for the OTP code (default "otp")
    otp_submit_url       optional URL the OTP is POSTed to (default login_url)
    logged_in_indicator  regex that must appear in the post-login response
    imap_host            IMAP server host
    imap_port            IMAP port (default 993, SSL)
    imap_user            mailbox login (often the test account email)
    imap_mailbox         folder to search (default "INBOX")
    sender_filter        substring the From header must contain (optional)
    subject_filter       substring the Subject must contain (optional)
    otp_regex            regex with one capture group for the code
                         (default r"\\b(\\d{4,8})\\b")

The profile secret (``credentials.get_secret``) is either the plain login
password, or a JSON object carrying several secrets, e.g.::

    {"password": "...", "imap_app_password": "..."}
"""
# @lat: [[architecture#Authenticated website testing]]
# @lat: [[runner#Email OTP login]]

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable

DEFAULT_OTP_REGEX = r"\b(\d{4,8})\b"
_DEFAULT_IMAP_PORT = 993


class OtpLoginError(Exception):
    """OTP login could not be completed (reported to the user without secrets)."""


def parse_profile_secret(secret: str | None) -> dict[str, str]:
    """Return a dict of named secrets from the stored secret blob.

    Accepts either a JSON object of ``{name: value}`` or a bare string, which is
    treated as the login ``password``.
    """
    raw = (secret or "").strip()
    if not raw:
        return {}
    if raw.startswith("{"):
        try:
            data = json.loads(raw)
        except ValueError:
            return {"password": raw}
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items() if v is not None}
    return {"password": raw}


def extract_otp(text: str, regex: str = DEFAULT_OTP_REGEX) -> str | None:
    """Return the first OTP found in ``text`` using ``regex`` (first capture group)."""
    if not text:
        return None
    try:
        pat = re.compile(regex)
    except re.error as exc:
        raise OtpLoginError(f"invalid otp_regex: {exc}") from exc
    m = pat.search(text)
    if not m:
        return None
    return (m.group(1) if m.groups() else m.group(0)).strip()


# --------------------------------------------------------------------------- IMAP

# A mailbox message is modelled as a simple dict so tests need no real IMAP.
Message = dict[str, Any]
# imap_search(cfg, app_password) -> list[Message]; newest last or any order.
ImapSearch = Callable[[dict[str, Any], str], list[Message]]


def _imap_search_live(cfg: dict[str, Any], app_password: str) -> list[Message]:  # pragma: no cover - needs a server
    """Fetch recent messages from an IMAP mailbox over SSL.

    Returns a list of ``{"from","subject","body","date"}`` dicts. Never logs the
    password. Imported lazily so the module stays import-safe without imaplib use.
    """
    import email
    import imaplib
    from email.header import decode_header, make_header

    host = str(cfg.get("imap_host") or "").strip()
    if not host:
        raise OtpLoginError("imap_host is required for email OTP")
    port = int(cfg.get("imap_port") or _DEFAULT_IMAP_PORT)
    user = str(cfg.get("imap_user") or "").strip()
    mailbox = str(cfg.get("imap_mailbox") or "INBOX").strip() or "INBOX"
    if not user:
        raise OtpLoginError("imap_user is required for email OTP")

    out: list[Message] = []
    conn = imaplib.IMAP4_SSL(host, port)
    try:
        conn.login(user, app_password)
        conn.select(mailbox, readonly=True)
        typ, data = conn.search(None, "ALL")
        if typ != "OK":
            return out
        ids = data[0].split()[-15:]  # only the most recent handful
        for mid in reversed(ids):
            typ, msg_data = conn.fetch(mid, "(RFC822)")
            if typ != "OK" or not msg_data or not msg_data[0]:
                continue
            msg = email.message_from_bytes(msg_data[0][1])
            body = _message_body(msg)
            out.append(
                {
                    "from": str(make_header(decode_header(msg.get("From", "")))),
                    "subject": str(make_header(decode_header(msg.get("Subject", "")))),
                    "date": msg.get("Date", ""),
                    "body": body,
                }
            )
    finally:
        try:
            conn.logout()
        except Exception:
            pass
    return out


def _message_body(msg) -> str:  # pragma: no cover - exercised via live path
    import email

    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html"):
                payload = part.get_payload(decode=True)
                if payload:
                    parts.append(payload.decode(part.get_content_charset() or "utf-8", "replace"))
        return "\n".join(parts)
    payload = msg.get_payload(decode=True)
    if payload:
        return payload.decode(msg.get_content_charset() or "utf-8", "replace")
    return str(msg.get_payload() or "")


def _message_matches(msg: Message, sender_filter: str, subject_filter: str) -> bool:
    if sender_filter and sender_filter.lower() not in str(msg.get("from", "")).lower():
        return False
    if subject_filter and subject_filter.lower() not in str(msg.get("subject", "")).lower():
        return False
    return True


def poll_for_otp(
    cfg: dict[str, Any],
    app_password: str,
    *,
    imap_search: ImapSearch | None = None,
    attempts: int = 10,
    delay_s: float = 3.0,
    sleep: Callable[[float], None] = time.sleep,
) -> str:
    """Poll the inbox until a matching OTP arrives; raise on timeout.

    ``imap_search`` is injectable for tests. Matching messages are filtered by
    ``sender_filter``/``subject_filter`` and scanned newest-first.
    """
    search = imap_search or _imap_search_live
    regex = str(cfg.get("otp_regex") or DEFAULT_OTP_REGEX)
    sender_filter = str(cfg.get("sender_filter") or "")
    subject_filter = str(cfg.get("subject_filter") or "")
    last_err = "no OTP email found"
    for i in range(max(1, attempts)):
        try:
            messages = search(cfg, app_password) or []
        except OtpLoginError:
            raise
        except Exception as exc:  # noqa: BLE001 - surface a redacted reason only
            raise OtpLoginError(f"IMAP read failed: {type(exc).__name__}") from exc
        for msg in messages:
            if not _message_matches(msg, sender_filter, subject_filter):
                continue
            code = extract_otp(str(msg.get("body", "")), regex) or extract_otp(
                str(msg.get("subject", "")), regex
            )
            if code:
                return code
        if i < attempts - 1:
            sleep(delay_s)
    raise OtpLoginError(last_err)


# --------------------------------------------------------------------------- login

# http_post(url, data: dict, cookies: dict) -> HttpReply
HttpPost = Callable[[str, dict[str, str], dict[str, str]], "HttpReply"]


@dataclass
class HttpReply:
    status: int = 200
    body: str = ""
    cookies: dict[str, str] = field(default_factory=dict)
    final_url: str = ""


@dataclass
class OtpLoginResult:
    cookies: dict[str, str]
    final_url: str
    note: str = ""


def login_with_otp(
    cfg: dict[str, Any],
    secrets: dict[str, str],
    *,
    http_post: HttpPost,
    imap_search: ImapSearch | None = None,
    attempts: int = 10,
    delay_s: float = 3.0,
    sleep: Callable[[float], None] = time.sleep,
) -> OtpLoginResult:
    """Drive an email-OTP login and return the captured session cookies.

    Steps: POST username (+password) to the login/OTP-request URL, poll the test
    inbox for the code, POST the code, then return accumulated cookies. All
    network/IMAP work is injected so this is fully unit-testable.
    """
    login_url = str(cfg.get("login_url") or "").strip()
    if not login_url:
        raise OtpLoginError("login_url is required for email OTP")
    username = str(cfg.get("username") or cfg.get("imap_user") or "").strip()
    if not username:
        raise OtpLoginError("username is required for email OTP")
    app_password = secrets.get("imap_app_password") or secrets.get("app_password") or ""
    if not app_password:
        raise OtpLoginError("imap_app_password is required for email OTP")

    user_field = str(cfg.get("username_field") or "username")
    pass_field = str(cfg.get("password_field") or "password")
    otp_field = str(cfg.get("otp_field") or "otp")
    request_url = str(cfg.get("otp_request_url") or login_url)
    submit_url = str(cfg.get("otp_submit_url") or login_url)

    cookies: dict[str, str] = {}

    # Step 1: trigger the OTP email (send username, and password when present).
    form1: dict[str, str] = {user_field: username}
    if secrets.get("password"):
        form1[pass_field] = secrets["password"]
    reply1 = http_post(request_url, form1, cookies)
    cookies.update(reply1.cookies or {})
    if reply1.status >= 400:
        raise OtpLoginError(f"OTP request failed (HTTP {reply1.status})")

    # Step 2: read the code from the inbox.
    code = poll_for_otp(
        cfg, app_password, imap_search=imap_search, attempts=attempts, delay_s=delay_s, sleep=sleep
    )

    # Step 3: submit the code.
    form2: dict[str, str] = {otp_field: code}
    if cfg.get("carry_username_on_otp"):
        form2[user_field] = username
    reply2 = http_post(submit_url, form2, cookies)
    cookies.update(reply2.cookies or {})
    if reply2.status >= 400:
        raise OtpLoginError(f"OTP submit failed (HTTP {reply2.status})")

    if not cookies:
        raise OtpLoginError("login completed but no session cookie was set")
    return OtpLoginResult(cookies=cookies, final_url=reply2.final_url or submit_url, note="email-otp login ok")
