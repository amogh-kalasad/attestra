"""naabu importer (`-json`): one informational finding per open port."""

from __future__ import annotations

from attestra.importers._jsonutil import load_json_or_lines
from attestra.importers.base import NormalizedFinding


def parse(raw: bytes) -> list[NormalizedFinding]:
    doc = load_json_or_lines(raw)
    items = doc if isinstance(doc, list) else [doc]
    out: list[NormalizedFinding] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        port = item.get("port")
        if isinstance(port, dict):
            proto = port.get("Protocol") or port.get("protocol") or "tcp"
            port = port.get("Port") or port.get("port")
        else:
            proto = item.get("protocol") or "tcp"
        if port in (None, ""):
            continue
        host = item.get("host") or item.get("ip") or ""
        out.append(
            NormalizedFinding(
                tool="naabu",
                rule_id=f"open-port-{port}",
                title=f"Open port {port}/{proto}",
                severity="info",
                location=f"{host}:{port}",
                description=f"Port {port}/{proto} answered on {item.get('ip') or host}.",
                recommendation="Confirm the service is required and restricted to authorized networks.",
                param=f"{port}/{proto}",
            )
        )
    return out
