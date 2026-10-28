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
            pluginid = str(alert.get("pluginid", ""))
            alert_ref = alert.get("alertRef")
            # Distinct alertRef (e.g. 10055-5) keeps CSP subtypes from collapsing.
            # webcheck C10 uses the same alertRef values as variant for known CSP issues.
            variant = str(alert_ref) if alert_ref is not None and str(alert_ref) != pluginid else ""
            instances = alert.get("instances") or [{"uri": site.get("@name", "")}]
            for inst in instances:
                out.append(
                    NormalizedFinding(
                        tool="zap",
                        rule_id=pluginid,
                        original_id=str(alert_ref or pluginid),
                        confidence=str(alert.get("confidence", "") or ""),
                        title=alert.get("alert") or alert.get("name") or "ZAP alert",
                        severity=severity,
                        location=inst.get("uri", ""),
                        param=inst.get("param", "") or "",
                        description=_text(alert.get("desc")),
                        recommendation=_text(alert.get("solution")),
                        cwe=parse_cwe(alert.get("cweid")),
                        variant=variant,
                    )
                )
    return out
