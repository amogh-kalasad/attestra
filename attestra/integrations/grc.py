"""Optional GRC evidence push (Vanta / Drata / Sprinto / generic webhook).

Off by default. When ``ATTESTRA_GRC_BACKEND`` is set to ``vanta``, ``drata``,
``sprinto``, or ``webhook`` and a HTTPS webhook URL (plus secret) is configured,
signed report metadata can be POSTed to that endpoint. Real vendor APIs are not
called directly; connectors are webhook-style so operators can point at their
own bridge or the vendor's inbound webhook.

    ATTESTRA_GRC_BACKEND=vanta | drata | sprinto | webhook
    ATTESTRA_GRC_WEBHOOK_URL=https://...
    ATTESTRA_GRC_WEBHOOK_SECRET  (or secret store key ``grc_webhook_secret``)

Secrets are never logged. Prefer :func:`safe_push_grc_report` from callers so a
failed push never breaks report signing.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import urllib.request
from collections.abc import Callable
from typing import Any, Protocol

from sqlalchemy.orm import Session

from attestra import audit
from attestra.models import Report

log = logging.getLogger("attestra.integrations.grc")

BACKENDS = ("vanta", "drata", "sprinto", "webhook")
HttpPost = Callable[[str, dict[str, str], dict[str, Any]], dict[str, Any]]


class GrcError(RuntimeError):
    """GRC connector misconfiguration or push failure."""


class GrcConnector(Protocol):
    name: str

    def push_signed_report(self, report_meta: dict[str, Any]) -> dict[str, Any]: ...


def _http_post(url: str, headers: dict[str, str], body: dict[str, Any], *, timeout: float = 15.0) -> dict[str, Any]:
    if not url.lower().startswith("https://"):
        raise GrcError("GRC webhook URL must use https")
    data = json.dumps(body, separators=(",", ":"), default=str).encode()
    req = urllib.request.Request(
        url, data=data, method="POST", headers={"Content-Type": "application/json", **headers}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - https enforced above
        raw = resp.read(1_000_000)
    return json.loads(raw) if raw else {}


def _sign_body(secret: str, body: dict[str, Any]) -> str:
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()


class WebhookGrcConnector:
    """POST signed report metadata to a configured HTTPS webhook URL."""

    def __init__(
        self,
        name: str,
        url: str,
        secret: str,
        *,
        http_post: HttpPost | None = None,
    ):
        if name not in BACKENDS and name != "webhook":
            # Allow the four backends; name is informational in the payload.
            pass
        if not url or not url.lower().startswith("https://"):
            raise GrcError("ATTESTRA_GRC_WEBHOOK_URL must be an https URL")
        if not secret:
            raise GrcError("GRC webhook secret missing (secret 'grc_webhook_secret' or ATTESTRA_GRC_WEBHOOK_SECRET)")
        self.name = name
        self.url = url.rstrip("/")
        self._secret = secret
        self._post = http_post or _http_post

    def __repr__(self) -> str:
        return f"WebhookGrcConnector(name={self.name!r}, url={self.url!r})"

    def push_signed_report(self, report_meta: dict[str, Any]) -> dict[str, Any]:
        payload = {
            "source": "attestra",
            "backend": self.name,
            "event": "report.signed",
            "report": dict(report_meta),
        }
        sig = _sign_body(self._secret, payload)
        headers = {
            "X-Attestra-Signature": f"sha256={sig}",
            "X-Attestra-Backend": self.name,
        }
        try:
            return self._post(self.url, headers, payload)
        except GrcError:
            raise
        except Exception as exc:  # noqa: BLE001 - never echo secret in messages
            text = str(exc).replace(self._secret, "[redacted]")
            raise GrcError(f"GRC push failed: {text[:200]}") from None


def VantaConnector(url: str, secret: str, *, http_post: HttpPost | None = None) -> WebhookGrcConnector:
    return WebhookGrcConnector("vanta", url, secret, http_post=http_post)


def DrataConnector(url: str, secret: str, *, http_post: HttpPost | None = None) -> WebhookGrcConnector:
    return WebhookGrcConnector("drata", url, secret, http_post=http_post)


def SprintoConnector(url: str, secret: str, *, http_post: HttpPost | None = None) -> WebhookGrcConnector:
    return WebhookGrcConnector("sprinto", url, secret, http_post=http_post)


def connector_from_env(
    env: dict[str, str] | None = None, *, http_post: HttpPost | None = None
) -> GrcConnector | None:
    """Return a connector when backend + URL + secret are set; otherwise ``None`` (feature off)."""
    env = dict(os.environ) if env is None else env
    backend = env.get("ATTESTRA_GRC_BACKEND", "").strip().lower()
    if not backend:
        return None
    if backend not in BACKENDS:
        raise GrcError(f"unknown ATTESTRA_GRC_BACKEND {backend!r}; supported: {', '.join(BACKENDS)}")
    url = env.get("ATTESTRA_GRC_WEBHOOK_URL", "").strip()
    from attestra.secret_store import get_secret

    secret = get_secret("grc_webhook_secret", env.get("ATTESTRA_GRC_WEBHOOK_SECRET", ""))
    if not url or not secret:
        raise GrcError(
            "GRC push needs ATTESTRA_GRC_WEBHOOK_URL and ATTESTRA_GRC_WEBHOOK_SECRET "
            "(or secret 'grc_webhook_secret')"
        )
    name = "webhook" if backend == "webhook" else backend
    return WebhookGrcConnector(name, url, secret, http_post=http_post)


def report_meta(report: Report) -> dict[str, Any]:
    """Signed-report fields sent to GRC — no file bytes, no secrets."""
    signed = report.signed_at.isoformat() if report.signed_at else ""
    return {
        "report_id": report.id,
        "engagement_id": report.engagement_id,
        "kind": report.kind,
        "version": report.version,
        "sha256": report.sha256,
        "signed_at": signed,
        "signed_by": report.approved_by or "",
        "download_hint": f"/reports/{report.id}/sealed",
    }


def push_signed_report(
    s: Session,
    report_id: int,
    *,
    actor: str,
    connector: GrcConnector | None = None,
) -> dict[str, Any]:
    """Push metadata for a signed report. Raises when disabled or report is not signed."""
    r = s.get(Report, report_id)
    if not r:
        raise LookupError(f"report {report_id} not found")
    if r.status != "signed":
        raise GrcError(f"report {report_id} is not signed (status={r.status!r})")
    client = connector if connector is not None else connector_from_env()
    if client is None:
        raise GrcError("GRC push is disabled; set ATTESTRA_GRC_BACKEND")
    meta = report_meta(r)
    result = client.push_signed_report(meta)
    audit.record(
        s,
        actor,
        "report.grc_pushed",
        "report",
        r.id,
        engagement_id=r.engagement_id,
        backend=client.name,
        sha256=r.sha256,
        kind=r.kind,
    )
    return result if isinstance(result, dict) else {"ok": True}


def safe_push_grc_report(
    s: Session,
    report_id: int,
    *,
    actor: str = "system",
    connector: GrcConnector | None = None,
) -> dict[str, Any] | None:
    """Best-effort GRC push; never raises into the caller. No-op when disabled."""
    try:
        env_backend = os.environ.get("ATTESTRA_GRC_BACKEND", "").strip()
        if connector is None and not env_backend:
            return None
        return push_signed_report(s, report_id, actor=actor, connector=connector)
    except GrcError as exc:
        log.warning("grc push skipped: %s", str(exc)[:200])
        return None
    except Exception:  # noqa: BLE001
        log.exception("grc push failed for report %s", report_id)
        return None
