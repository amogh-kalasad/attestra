"""Nuclei JSON Lines importer (output of `-jsonl`)."""

from __future__ import annotations

import json

from attestra.importers.base import NormalizedFinding, norm_severity, parse_cwe


# Templates whose matchers/extractors are separate issues (one per missing header or
# per deprecated protocol). The sub-check name becomes the variant so they do not
# collapse into one finding, and "template:sub" is kept as the observation id.
SUBCHECK_TEMPLATES = frozenset({"http-missing-security-headers", "deprecated-tls"})


def _subcheck(rec: dict) -> str:
    if str(rec.get("template-id") or "") not in SUBCHECK_TEMPLATES:
        return ""
    return str(rec.get("matcher-name") or rec.get("extractor-name") or "").strip()


def _as_list(v) -> list[str]:
    if not v:
        return []
    return [v] if isinstance(v, str) else list(v)


def parse(raw: bytes) -> list[NormalizedFinding]:
    out: list[NormalizedFinding] = []
    text = raw.decode("utf-8", errors="replace").strip()
    records = json.loads(text) if text.startswith("[") else [json.loads(line) for line in text.splitlines() if line.strip()]
    for rec in records:
        info = rec.get("info", {}) or {}
        cls = info.get("classification", {}) or {}
        cvss = cls.get("cvss-score")
        sub = _subcheck(rec)
        out.append(
            NormalizedFinding(
                tool="nuclei",
                rule_id=rec.get("template-id", ""),
                original_id=(
                    f"{rec.get('template-id')}:{sub}" if sub
                    else str(rec.get("template-id") or rec.get("template-path") or "")
                ),
                variant=sub,
                tool_version=str(info.get("version") or rec.get("template-version") or ""),
                title=info.get("name") or rec.get("template-id", "nuclei finding"),
                severity=norm_severity(info.get("severity")),
                location=rec.get("matched-at") or rec.get("host", ""),
                description=info.get("description", "") or "",
                recommendation=info.get("remediation", "") or "",
                cwe=parse_cwe(_as_list(cls.get("cwe-id"))),
                cves=[c.upper() for c in _as_list(cls.get("cve-id"))],
                cvss_score=float(cvss) if cvss not in (None, "") else None,
                cvss_vector=cls.get("cvss-metrics", "") or "",
            )
        )
    return out
