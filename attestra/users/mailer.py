"""Optional SMTP email. Off unless ATTESTRA_SMTP_HOST is set; never logs the password."""

from __future__ import annotations

import logging
import os
import smtplib
from collections.abc import Callable
from email.message import EmailMessage

log = logging.getLogger(__name__)

# Tests replace this with a fake that records messages (no real network).
DeliverFn = Callable[[EmailMessage], None]
_deliver_override: DeliverFn | None = None


def smtp_configured() -> bool:
    return bool(os.environ.get("ATTESTRA_SMTP_HOST", "").strip())


def set_deliver(fn: DeliverFn | None) -> None:
    """Install or clear a deliver function (tests use an in-memory fake)."""
    global _deliver_override
    _deliver_override = fn


def can_send() -> bool:
    """True when SMTP is configured or a test deliver function is installed."""
    return smtp_configured() or _deliver_override is not None


def _truthy(name: str, default: str = "true") -> bool:
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes")


def _smtp_deliver(msg: EmailMessage) -> None:
    """Connect and send. Reads password from env; never logs it."""
    host = os.environ["ATTESTRA_SMTP_HOST"].strip()
    port = int(os.environ.get("ATTESTRA_SMTP_PORT", "587"))
    user = os.environ.get("ATTESTRA_SMTP_USER", "")
    password = os.environ.get("ATTESTRA_SMTP_PASSWORD", "")
    # Prefer explicit TLS flag; fall back to STARTTLS (invite-era name).
    use_tls = _truthy("ATTESTRA_SMTP_TLS", os.environ.get("ATTESTRA_SMTP_STARTTLS", "true"))
    with smtplib.SMTP(host, port, timeout=15) as smtp:
        if use_tls:
            smtp.starttls()
        if user:
            smtp.login(user, password)
        smtp.send_message(msg)


def send_email(
    to: str | list[str],
    subject: str,
    text: str,
    *,
    html: str = "",
    sender: str | None = None,
) -> bool:
    """Send a plain + optional HTML email. Returns True when handed to SMTP/fake.

    Quietly skips (one info log, no error) when SMTP is not configured.
    """
    recipients = [t.strip() for t in ([to] if isinstance(to, str) else list(to)) if t and t.strip()]
    if not recipients:
        return False
    if not smtp_configured() and _deliver_override is None:
        log.info("email skipped: ATTESTRA_SMTP_HOST not set")
        return False
    from_addr = sender or os.environ.get("ATTESTRA_SMTP_FROM", "") or os.environ.get("ATTESTRA_SMTP_USER", "") or "attestra@localhost"
    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    deliver = _deliver_override or _smtp_deliver
    deliver(msg)
    return True


def send_link(to: str, link: str, *, purpose: str = "invite") -> bool:
    """Send the invite/reset link if SMTP is configured. Returns True when sent."""
    if not to:
        return False
    if purpose == "reset":
        subject = "Reset your Attestra password"
        text = f"Use this one-time link to set a new password:\n\n{link}\n"
    else:
        subject = "You are invited to Attestra"
        text = f"Use this one-time link to create your account:\n\n{link}\n"
    return send_email(to, subject, text)


def send_welcome(
    to: str,
    *,
    username: str,
    organization_name: str,
    display_name: str = "",
    login_url: str | None = None,
) -> bool:
    """Welcome acknowledgement after customer self-service registration.

    Includes username and organization name only — never the password. Uses the
    existing SMTP / test deliver path. Returns True when handed to the deliverer.
    """
    if not to:
        return False
    base = (login_url or os.environ.get("ATTESTRA_PUBLIC_URL", "") or "").rstrip("/")
    sign_in = f"{base}/login" if base else "/login"
    who = (display_name or username or "").strip() or username
    subject = "Welcome to Attestra"
    text = (
        f"Hello {who},\n\n"
        f"Your Attestra account was created successfully.\n\n"
        f"Organization: {organization_name}\n"
        f"Username: {username}\n\n"
        f"Sign in here:\n{sign_in}\n\n"
        f"If you did not register for Attestra, contact your administrator.\n"
    )
    html = (
        f"<p>Hello {who},</p>"
        f"<p>Your Attestra account was created successfully.</p>"
        f"<ul>"
        f"<li><strong>Organization:</strong> {organization_name}</li>"
        f"<li><strong>Username:</strong> {username}</li>"
        f"</ul>"
        f'<p><a href="{sign_in}">Sign in to Attestra</a></p>'
        f"<p>If you did not register for Attestra, contact your administrator.</p>"
    )
    return send_email(to, subject, text, html=html)
