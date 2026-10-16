"""Burp Suite Issues XML export importer (upload only)."""
# @lat: [[import-pipeline#Supported formats]]

from __future__ import annotations

import base64
import html
import re
from urllib.parse import urlsplit, urlunsplit
from xml.etree.ElementTree import Element

from attestra.importers._xmlutil import child_text, parse_xml
from attestra.importers.base import NormalizedFinding, norm_severity

_TAGS = re.compile(r"<[^>]+>")
_PARAM_RE = re.compile(r"\[([^\]]+)\]")


def _text(s: str | None) -> str:
    return html.unescape(_TAGS.sub(" ", s or "")).strip()


def _decode_body(el: Element | None) -> str:
    if el is None or el.text is None:
        return ""
    raw = el.text
    if (el.get("base64") or "").lower() in ("true", "1", "yes"):
        try:
            return base64.b64decode(raw.strip()).decode("utf-8", errors="replace")
        except (ValueError, TypeError):
            return raw.strip()
    return raw.strip()


def _location(host: str, path: str) -> str:
    host = (host or "").strip()
    path = (path or "").strip() or "/"
    if not path.startswith("/"):
        path = "/" + path
    if not host:
        return path
    if "://" in host:
        parts = urlsplit(host)
        return urlunsplit((parts.scheme, parts.netloc, path, "", ""))
    return f"https://{host}{path}"


def _param_from_location(location_el: str) -> str:
    m = _PARAM_RE.search(location_el or "")
    if not m:
        return ""
    return m.group(1).strip()


def parse(raw: bytes) -> list[NormalizedFinding]:
    root = parse_xml(raw)
    issues = root.findall("issue") if root.tag.endswith("issues") or root.tag == "issues" else []
    if not issues and root.tag.endswith("issue"):
        issues = [root]
    out: list[NormalizedFinding] = []
    for issue in issues:
        name = child_text(issue, "name") or "Burp issue"
        type_id = child_text(issue, "type")
        host_el = issue.find("host")
        host = (host_el.text or "").strip() if host_el is not None else ""
        path = child_text(issue, "path")
        loc_hint = child_text(issue, "location")
        severity = norm_severity(child_text(issue, "severity") or "Information")
        confidence = child_text(issue, "confidence")
        background = _text(child_text(issue, "issueBackground"))
        detail = _text(child_text(issue, "issueDetail"))
        remediation = _text(
            child_text(issue, "remediationBackground") or child_text(issue, "remediationDetail")
        )
        desc_parts = [p for p in (detail, background) if p]
        if confidence:
            desc_parts.append(f"Confidence: {confidence}")
        # Evidence snippets from first request/response pair.
        rr = issue.find("requestresponse")
        if rr is not None:
            req = _decode_body(rr.find("request"))
            resp = _decode_body(rr.find("response"))
            if req:
                desc_parts.append("Request:\n" + req[:2000])
            if resp:
                desc_parts.append("Response:\n" + resp[:2000])
        location = _location(host, path)
        out.append(
            NormalizedFinding(
                tool="burp",
                rule_id=type_id or name,
                variant=type_id,
                title=name,
                severity=severity,
                location=location,
                param=_param_from_location(loc_hint),
                description="\n\n".join(desc_parts),
                recommendation=remediation,
            )
        )
    return out


def extract_pairs(raw: bytes) -> list[tuple[str, str, str]]:
    """Yield (url, request, response) triples for proof capture."""
    root = parse_xml(raw)
    issues = root.findall("issue") if root.tag.endswith("issues") or root.tag == "issues" else []
    pairs: list[tuple[str, str, str]] = []
    for issue in issues:
        host_el = issue.find("host")
        host = (host_el.text or "").strip() if host_el is not None else ""
        path = child_text(issue, "path")
        url = _location(host, path)
        for rr in issue.findall("requestresponse"):
            req = _decode_body(rr.find("request"))
            resp = _decode_body(rr.find("response"))
            if req and resp:
                pairs.append((url, req, resp))
    return pairs
