"""OWASP ZAP JSON report importer (the 'traditional-json' report format)."""

from __future__ import annotations

import html
import json
import re

from attestra.finding_validation.infrastructure import (
    is_cache_related_finding,
    is_cdn_challenge_url,
    is_static_asset_url,
)
from attestra.importers.base import NormalizedFinding, parse_cwe

RISKCODE = {"3": "high", "2": "medium", "1": "low", "0": "info"}
# Scanner notices / debug hooks — never elevate above informational.
INFORMATIONAL_PLUGIN_IDS = frozenset({"10109", "10112"})
_CACHE_PLUGIN_IDS = frozenset({"10015", "10049", "10050"})
_TAGS = re.compile(r"<[^>]+>")
# traditional-json-plus uses kebab-case; some exports use camelCase or lowercase.
_REQ_HEADER_KEYS = ("request-header", "requestHeader", "requestheader")
_RESP_HEADER_KEYS = ("response-header", "responseHeader", "responseheader")
_STATUS_KEYS = ("statusCode", "statuscode", "status")


def _plugin_base(pluginid: str) -> str:
    """Strip ZAP alertRef subtype suffix (e.g. 10049-1 → 10049)."""
    raw = (pluginid or "").strip()
    if "-" in raw:
        head, _, tail = raw.partition("-")
        if head.isdigit() and tail.isdigit():
            return head
    return raw


def _force_informational_severity(
    *,
    pluginid: str,
    title: str,
    description: str,
    location: str,
    severity: str,
) -> str:
    """Cap ZAP notices and static/CDN cache alerts to info severity."""
    base = _plugin_base(pluginid)
    if base in INFORMATIONAL_PLUGIN_IDS:
        return "info"
    if base in _CACHE_PLUGIN_IDS or is_cache_related_finding(
        title, [pluginid, base], description
    ):
        if is_static_asset_url(location) or is_cdn_challenge_url(location):
            return "info"
    return severity


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
            title = alert.get("alert") or alert.get("name") or "ZAP alert"
            description = _text(alert.get("desc"))
            instances = alert.get("instances") or [{"uri": site.get("@name", "")}]
            for inst in instances:
                # Per-URL evidence is kept on that URL's observation (grouping keeps all of them).
                refs: list[str] = []
                for key in ("attack", "evidence", "otherinfo"):
                    val = str(inst.get(key) or "").strip()
                    if val:
                        refs.append(f"{key}: {val[:500]}")
                refs.extend(_message_evidence_refs(inst))
                location = inst.get("uri", "") or ""
                sev = _force_informational_severity(
                    pluginid=str(alert_ref or pluginid),
                    title=str(title),
                    description=description,
                    location=location,
                    severity=severity,
                )
                out.append(
                    NormalizedFinding(
                        tool="zap",
                        rule_id=pluginid,
                        original_id=str(alert_ref or pluginid),
                        confidence=str(alert.get("confidence", "") or ""),
                        title=title,
                        severity=sev,
                        location=location,
                        param=inst.get("param", "") or "",
                        description=description,
                        recommendation=_text(alert.get("solution")),
                        cwe=parse_cwe(alert.get("cweid")),
                        variant=variant,
                        evidence_refs=refs,
                    )
                )
    return out
