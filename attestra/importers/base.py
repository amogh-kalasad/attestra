"""Common shape every importer produces."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class NormalizedFinding:
    tool: str
    rule_id: str
    title: str
    severity: str  # critical | high | medium | low | info
    location: str  # URL, host:port, file:line, image@package
    description: str = ""
    recommendation: str = ""
    cwe: int | None = None
    cves: list[str] = field(default_factory=list)
    cvss_score: float | None = None
    cvss_vector: str = ""
    param: str = ""
    package: str = ""


_CWE_RE = re.compile(r"cwe[-_/ ]?(\d+)", re.IGNORECASE)


def parse_cwe(value) -> int | None:
    """Accept 79, '79', 'CWE-79', 'external/cwe/cwe-79', or a list of those (first wins)."""
    if value is None or value == "":
        return None
    if isinstance(value, (list, tuple)):
        for v in value:
            got = parse_cwe(v)
            if got:
                return got
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    text = str(value).strip()
    if text.isdigit():
        n = int(text)
        return n if n > 0 else None
    m = _CWE_RE.search(text)
    return int(m.group(1)) if m else None


def norm_severity(value: str | None) -> str:
    v = (value or "").strip().lower()
    aliases = {"informational": "info", "information": "info", "unknown": "info", "moderate": "medium", "negligible": "info"}
    v = aliases.get(v, v)
    return v if v in ("critical", "high", "medium", "low", "info") else "info"
