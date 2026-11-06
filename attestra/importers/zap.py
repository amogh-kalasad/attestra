"""OWASP ZAP JSON report importer (the 'traditional-json' report format)."""

from __future__ import annotations

import html
import json
import re

from attestra.importers.base import NormalizedFinding, parse_cwe

RISKCODE = {"3": "high", "2": "medium", "1": "low", "0": "info"}
_TAGS = re.compile(r"<[^>]+>")
# traditional-json-plus uses kebab-case; some exports use camelCase or lowercase.
_REQ_HEADER_KEYS = ("request-header", "requestHeader", "requestheader")
_RESP_HEADER_KEYS = ("response-header", "responseHeader", "responseheader")
_STATUS_KEYS = ("statusCode", "statuscode", "status")


def _text(s: str | None) -> str:
    return html.unescape(_TAGS.sub(" ", s or "")).strip()


def _inst_field(inst: dict, keys: tuple[str, ...]) -> str:
    for key in keys:
        val = inst.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    return ""


def _message_evidence_refs(inst: dict) -> list[str]:
    """Truncated request/response header snippets when the report includes messages."""
    refs: list[str] = []
    req_h = _inst_field(inst, _REQ_HEADER_KEYS)
    if req_h:
        refs.append(f"requestHeader: {req_h[:500]}")
    resp_h = _inst_field(inst, _RESP_HEADER_KEYS)
    if resp_h:
        refs.append(f"responseHeader: {resp_h[:500]}")
    status = _inst_field(inst, _STATUS_KEYS)
    if status:
        refs.append(f"statusCode: {status[:32]}")
    return refs


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
            # alertRef (e.g. 10055-5) is kept on the observation; import canonicalize
            # collapses CSP 10055 subtypes into one csp:weak-or-incomplete fingerprint.
            variant = str(alert_ref) if alert_ref is not None and str(alert_ref) != pluginid else ""
            instances = alert.get("instances") or [{"uri": site.get("@name", "")}]
            for inst in instances:
                # Per-URL evidence is kept on that URL's observation (grouping keeps all of them).
                refs: list[str] = []
                for key in ("attack", "evidence", "otherinfo"):
                    val = str(inst.get(key) or "").strip()
                    if val:
                        refs.append(f"{key}: {val[:500]}")
                refs.extend(_message_evidence_refs(inst))
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
                        evidence_refs=refs,
                    )
                )
    return out
