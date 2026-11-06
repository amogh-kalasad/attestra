"""Importer for attestra webcheck JSON reports."""

from __future__ import annotations

import json

from attestra.fingerprint import CAA_VARIANT, is_caa_variant
from attestra.finding_normalize import (
    is_expect_ct_deprecated,
    normalize_cwe_for_import,
    normalize_severity_for_import,
)
from attestra.importers.base import NormalizedFinding, norm_severity, parse_cwe


def parse(raw: bytes) -> list[NormalizedFinding]:
    doc = json.loads(raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw)
    items = doc.get("findings") if isinstance(doc, dict) else None
    if not isinstance(items, list):
        return []
    out: list[NormalizedFinding] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        fid = str(item.get("id") or "").strip()
        if not fid:
            continue
        variant = str(item.get("variant") or fid)
        # Align with testssl DNS_CAArecord via shared CAA_VARIANT (R15 merge).
        if fid == "dns-caa" or is_caa_variant(variant):
            variant = CAA_VARIANT
        title = str(item.get("title") or fid)
        description = str(item.get("description") or "")
        rule_id = f"webcheck/{fid}"
        cwe = parse_cwe(item.get("cwe"))
        severity = norm_severity(str(item.get("severity") or "info"))
        # Obsolete Expect-CT must stay informational/low and never keep CWE-79.
        if is_expect_ct_deprecated(title=title, rule_id=rule_id, description=description) or fid == "expect-ct":
            cwe = normalize_cwe_for_import(
                title=title, rule_id=rule_id, description=description, cwe=cwe
            )
            severity = normalize_severity_for_import(
                title=title,
                rule_id=rule_id,
                description=description,
                severity=severity,
            ) or "info"
        out.append(
            NormalizedFinding(
                tool="webcheck",
                rule_id=rule_id,
                variant=variant,
                title=title,
                severity=severity,
                location=str(item.get("location") or ""),
                description=description,
                recommendation=str(item.get("recommendation") or ""),
                cwe=cwe,
                param=str(item.get("param") or ""),
            )
        )
    return out
