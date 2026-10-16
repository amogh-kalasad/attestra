"""Payload shapes: generic signed JSON, Slack and Microsoft Teams incoming webhooks."""

from __future__ import annotations

import hashlib
import hmac
import json
import time

FORMATS = ("json", "slack", "teams")
EVENTS = (
    "finding.created",
    "finding.status_changed",
    "finding.commented",
    "report.signed",
    "retest.completed",
    "scan.finished",
    "cert.expiring",
)
SIG_HEADER = "X-Attestra-Signature"
TS_HEADER = "X-Attestra-Timestamp"


def summary(event: str, data: dict) -> str:
    if event.startswith("finding."):
        if event == "finding.commented":
            return (
                f"[{str(data.get('severity', '')).upper()}] {data.get('title', '')} "
                f"- comment on finding #{data.get('finding_id')}"
            )
        extra = f" ({data.get('from')} -> {data.get('status')})" if event == "finding.status_changed" else ""
        return f"[{str(data.get('severity', '')).upper()}] {data.get('title', '')} - finding #{data.get('finding_id')}{extra}"
    if event == "report.signed":
        return f"Report #{data.get('report_id')} ({data.get('kind')}) signed by {data.get('signed_by')}"
    if event == "retest.completed":
        return f"Retest #{data.get('retest_id')} of finding #{data.get('finding_id')}: {data.get('result')}"
    if event == "scan.finished":
        return f"Scan #{data.get('scan_id')} ({data.get('tool')}) finished with status {data.get('status')}"
    if event == "cert.expiring":
        return (
            f"Certificate for {data.get('target', '')} expires in {data.get('days_left')} day(s) "
            f"(band {data.get('band')}, end {data.get('end_date')})"
        )
    return event


def render(fmt: str, event: str, data: dict, delivery_id: int) -> dict:
    text = f"Attestra: {summary(event, data)}"
    if fmt == "slack":
        return {"text": text, "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]}
    if fmt == "teams":
        facts = [{"title": str(k), "value": str(v)} for k, v in data.items() if not isinstance(v, (dict, list))]
        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {"type": "TextBlock", "text": text, "wrap": True, "weight": "Bolder"},
                            {"type": "FactSet", "facts": facts},
                        ],
                    },
                }
            ],
        }
    return {"id": delivery_id, "event": event, "data": data}


def sign(secret: str, body: bytes, ts: str | None = None) -> tuple[str, str]:
    """HMAC-SHA256 over ``<timestamp>.<body>``. Returns (timestamp, 'sha256=<hex>')."""
    ts = ts or str(int(time.time()))
    mac = hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return ts, f"sha256={mac}"


def verify(secret: str, body: bytes, ts: str, signature: str, *, tolerance: int = 300, now: float | None = None) -> bool:
    if not ts.isdigit() or abs((now or time.time()) - int(ts)) > tolerance:
        return False
    return hmac.compare_digest(sign(secret, body, ts)[1], signature)


def encode(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True, default=str).encode()
