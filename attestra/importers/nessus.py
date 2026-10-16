"""Nessus .nessus (v2 XML) importer (upload only)."""
# @lat: [[import-pipeline#Supported formats]]

from __future__ import annotations

from xml.etree.ElementTree import Element

from attestra.importers._xmlutil import child_text, parse_xml
from attestra.importers.base import NormalizedFinding

# Nessus severity attribute 0–4 → Attestra severity.
_SEV = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}

# Scan-info / settings plugins: store as import notes, never as findings.
_NOTE_PLUGIN_IDS = {"19506"}
_NOTE_NAME_HINTS = ("nessus scan information",)


def _host_label(report_host: Element) -> str:
    name = (report_host.get("name") or "").strip()
    props = report_host.find("HostProperties")
    if props is None:
        return name
    tags: dict[str, str] = {}
    for tag in props.findall("tag"):
        key = (tag.get("name") or "").strip().lower()
        if key and tag.text:
            tags[key] = tag.text.strip()
    return tags.get("host-fqdn") or tags.get("hostname") or tags.get("host-ip") or name


def _is_scan_note(plugin_id: str, plugin_name: str) -> bool:
    if plugin_id in _NOTE_PLUGIN_IDS:
        return True
    lower = (plugin_name or "").strip().lower()
    return any(h in lower for h in _NOTE_NAME_HINTS)


def _cves(item: Element) -> list[str]:
    out: list[str] = []
    for el in item.findall("cve"):
        text = (el.text or "").strip().upper()
        if text and text not in out:
            out.append(text)
    return out


def _cvss(item: Element) -> tuple[float | None, str]:
    for key in ("cvss3_base_score", "cvss_base_score"):
        raw = child_text(item, key)
        if not raw:
            continue
        try:
            return float(raw), ""
        except ValueError:
            continue
    return None, ""


def _location(host: str, port: str, protocol: str) -> str:
    host = (host or "").strip()
    port = (port or "").strip()
    protocol = (protocol or "tcp").strip() or "tcp"
    if not host:
        return f"{port}/{protocol}" if port else ""
    if port and port not in ("0", ""):
        return f"{host}:{port}"
    return host


def parse(raw: bytes) -> list[NormalizedFinding]:
    root = parse_xml(raw)
    out: list[NormalizedFinding] = []
    for report in root.findall("Report"):
        for rh in report.findall("ReportHost"):
            host = _host_label(rh)
            for item in rh.findall("ReportItem"):
                plugin_id = (item.get("pluginID") or "").strip()
                plugin_name = (item.get("pluginName") or child_text(item, "plugin_name") or "").strip()
                if _is_scan_note(plugin_id, plugin_name):
                    continue
                severity = _SEV.get(str(item.get("severity", "0")), "info")
                port = (item.get("port") or "").strip()
                protocol = (item.get("protocol") or "tcp").strip()
                description = child_text(item, "description") or child_text(item, "synopsis")
                output = child_text(item, "plugin_output")
                if output:
                    description = (description + "\n\nPlugin output:\n" + output).strip()
                solution = child_text(item, "solution")
                cves = _cves(item)
                cvss_score, cvss_vector = _cvss(item)
                out.append(
                    NormalizedFinding(
                        tool="nessus",
                        rule_id=plugin_id or plugin_name,
                        variant=plugin_id,
                        title=plugin_name or f"Nessus plugin {plugin_id}",
                        severity=severity,
                        location=_location(host, port, protocol),
                        description=description,
                        recommendation=solution if solution.lower() not in ("", "n/a") else "",
                        cves=cves,
                        cvss_score=cvss_score,
                        cvss_vector=cvss_vector,
                        param=f"{port}/{protocol}" if port and port != "0" else "",
                    )
                )
    return out


def extract_notes(raw: bytes) -> list[str]:
    """Scan-info plugins (e.g. 19506) as import notes, not findings."""
    root = parse_xml(raw)
    notes: list[str] = []
    seen: set[str] = set()
    for report in root.findall("Report"):
        for rh in report.findall("ReportHost"):
            host = _host_label(rh)
            for item in rh.findall("ReportItem"):
                plugin_id = (item.get("pluginID") or "").strip()
                plugin_name = (item.get("pluginName") or child_text(item, "plugin_name") or "").strip()
                if not _is_scan_note(plugin_id, plugin_name):
                    continue
                output = child_text(item, "plugin_output") or child_text(item, "description") or plugin_name
                text = f"[{host}] {plugin_name or plugin_id}: {output}".strip()
                if text and text not in seen:
                    seen.add(text)
                    notes.append(text)
    return notes
