"""OWASP ZAP JSON report importer (the 'traditional-json' report format)."""

from __future__ import annotations

import html
import json
import re

from attestra.importers.base import NormalizedFinding, parse_cwe

RISKCODE = {"3": "high", "2": "medium", "1": "low", "0": "info"}
_TAGS = re.compile(r"<[^>]+>")


def _text(s: str | None) -> str:
    return html.unescape(_TAGS.sub(" ", s or "")).strip()


def parse(raw: bytes) -> list[NormalizedFinding]:
    doc = json.loads(raw)
    sites = doc.get("site", [])
    if isinstance(sites, dict):
        sites = [sites]
    out: list[NormalizedFinding] = []
    for site in sites:
        for alert in site.get("alerts", []) or []:
            severity = RISKCODE.get(str(alert.get("riskcode", "0")), "info")
            # ZAP flags confidence 0 as "false positive" in its own triage.
            if str(alert.get("confidence", "")) == "0":
                continue
            instances = alert.get("instances") or [{"uri": site.get("@name", "")}]
            for inst in instances:
                out.append(
                    NormalizedFinding(
                        tool="zap",
                        rule_id=str(alert.get("pluginid", "")),
                        title=alert.get("alert") or alert.get("name") or "ZAP alert",
                        severity=severity,
                        location=inst.get("uri", ""),
                        param=inst.get("param", "") or "",
                        description=_text(alert.get("desc")),
                        recommendation=_text(alert.get("solution")),
                        cwe=parse_cwe(alert.get("cweid")),
                    )
                )
    return out
