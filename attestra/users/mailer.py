"""Optional invite email. Off unless ATTESTRA_SMTP_HOST is set; never used in tests."""

from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage


def smtp_configured() -> bool:
    return bool(os.environ.get("ATTESTRA_SMTP_HOST", "").strip())


def send_link(to: str, link: str, *, purpose: str = "invite") -> bool:
    """Send the link if SMTP is configured. Returns True when sent."""
    if not smtp_configured() or not to:
        return False
    host = os.environ["ATTESTRA_SMTP_HOST"].strip()
    port = int(os.environ.get("ATTESTRA_SMTP_PORT", "587"))
    user = os.environ.get("ATTESTRA_SMTP_USER", "")
    password = os.environ.get("ATTESTRA_SMTP_PASSWORD", "")
    sender = os.environ.get("ATTESTRA_SMTP_FROM", user or "attestra@localhost")
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to
    if purpose == "reset":
        msg["Subject"] = "Reset your Attestra password"
        msg.set_content(f"Use this one-time link to set a new password:\n\n{link}\n")
    else:
        msg["Subject"] = "You are invited to Attestra"
        msg.set_content(f"Use this one-time link to create your account:\n\n{link}\n")
    with smtplib.SMTP(host, port, timeout=15) as smtp:
        if os.environ.get("ATTESTRA_SMTP_STARTTLS", "true").lower() in ("1", "true", "yes"):
            smtp.starttls()
        if user:
            smtp.login(user, password)
        smtp.send_message(msg)
    return True
