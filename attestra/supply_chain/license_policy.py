"""Licence policy over CycloneDX components (F-04).

Classifies each component's declared licences against a policy (``deny`` / ``review``
/ ``allow`` SPDX ids) and returns violations. Unknown or missing licences are reported
as ``unknown`` (needs review), never assumed to be permissive.

The policy is data, not legal advice: the default below only flags strong and network
copyleft licences for review and is meant to be overridden per tenant/engagement with
a YAML/JSON file (``ATTESTRA_LICENSE_POLICY=/path/policy.yaml``).
"""
# @lat: [[intel-and-reporting#Licence policy]]

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

POLICY_VERSION = "lp1"

DEFAULT_POLICY: dict = {
    "name": "attestra-default",
    "version": POLICY_VERSION,
    # Network copyleft: source-disclosure duty can trigger on SaaS use.
    "deny": ["AGPL-1.0", "AGPL-1.0-only", "AGPL-1.0-or-later", "AGPL-3.0", "AGPL-3.0-only",
             "AGPL-3.0-or-later", "SSPL-1.0", "RPL-1.5", "OSL-3.0"],
    # Strong / weak copyleft: allowed only after legal review of how it is linked/distributed.
    "review": ["GPL-1.0", "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0", "GPL-3.0-only",
               "GPL-3.0-or-later", "LGPL-2.0", "LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later",
               "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later", "MPL-2.0", "EPL-1.0", "EPL-2.0",
               "CDDL-1.0", "CDDL-1.1", "EUPL-1.2", "CC-BY-SA-4.0", "BUSL-1.1", "Commons-Clause"],
    "allow": ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD", "Unlicense",
              "Zlib", "Python-2.0", "PSF-2.0", "CC0-1.0", "BSL-1.0", "MIT-0", "BlueOak-1.0.0"],
    # How to treat components with no declared licence.
    "unknown": "review",
}
DECISION_RANK = {"deny": 3, "review": 2, "unknown": 2, "allow": 0}
SEVERITY = {"deny": "medium", "review": "low", "unknown": "info"}


@dataclass
class LicenseDecision:
    component: str
    version: str
    purl: str
    licenses: list[str] = field(default_factory=list)
    decision: str = "unknown"  # allow | review | deny | unknown
    reason: str = ""
    ref: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def load_policy(path: str | os.PathLike | None = None) -> dict:
    """Load a policy file (YAML or JSON); fall back to :data:`DEFAULT_POLICY`."""
    path = path or os.environ.get("ATTESTRA_LICENSE_POLICY", "").strip() or None
    if not path or str(path).lower() in ("default", "1", "true", "on"):
        return dict(DEFAULT_POLICY)
    text = Path(path).read_text(encoding="utf-8")
    if str(path).lower().endswith(".json"):
        doc = json.loads(text)
    else:
        import yaml

        doc = yaml.safe_load(text)
    if not isinstance(doc, dict):
        raise ValueError("licence policy must be a mapping")
    merged = dict(DEFAULT_POLICY)
    merged.update({k: v for k, v in doc.items() if k in ("name", "version", "deny", "review", "allow", "unknown")})
    if merged["unknown"] not in ("allow", "review", "deny"):
        raise ValueError("licence policy 'unknown' must be allow | review | deny")
    return merged


def enabled() -> bool:
    """Licence findings are opt-in (``ATTESTRA_LICENSE_POLICY`` set)."""
    return bool(os.environ.get("ATTESTRA_LICENSE_POLICY", "").strip()) and os.environ.get(
        "ATTESTRA_LICENSE_POLICY", ""
    ).strip().lower() not in ("0", "false", "off", "no")


_SPLIT_RE = re.compile(r"\s+(?:AND|OR|WITH)\s+|[()]", re.IGNORECASE)


def component_licenses(comp: dict) -> tuple[list[str], str]:
    """SPDX ids / names declared on a CycloneDX component and the expression operator."""
    ids: list[str] = []
    op = ""
    for entry in comp.get("licenses") or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("expression"):
            expr = str(entry["expression"])
            if re.search(r"\sOR\s", expr, re.IGNORECASE):
                op = "OR"
            elif re.search(r"\sAND\s", expr, re.IGNORECASE):
                op = op or "AND"
            ids.extend(t.strip() for t in _SPLIT_RE.split(expr) if t and t.strip())
            continue
        lic = entry.get("license") or {}
        val = lic.get("id") or lic.get("name")
        if val:
            ids.append(str(val).strip())
    # drop WITH-exception identifiers (e.g. Classpath-exception-2.0)
    ids = [i for i in ids if not i.lower().endswith("-exception") and "exception" not in i.lower()]
    return list(dict.fromkeys(ids)), op


def _norm(lid: str) -> str:
    return lid.strip().removesuffix("+")


def decide(licenses: list[str], op: str, policy: dict) -> tuple[str, str]:
    if not licenses:
        d = policy.get("unknown", "review")
        return ("unknown" if d == "review" else d), "no licence declared"
    sets = {k: {x.lower() for x in policy.get(k) or []} for k in ("deny", "review", "allow")}

    def one(lid: str) -> str:
        low = _norm(lid).lower()
        for k in ("deny", "review", "allow"):
            if low in sets[k]:
                return k
        return "unknown"

    per = {lid: one(lid) for lid in licenses}
    if op == "OR":
        # Dual licence: the licensee may pick the most permissive option.
        best = min(per.values(), key=lambda d: DECISION_RANK.get(d, 2))
        return best, f"dual-licensed ({' OR '.join(licenses)}); most permissive option: {best}"
    worst = max(per.values(), key=lambda d: DECISION_RANK.get(d, 2))
    hits = [lid for lid, d in per.items() if d == worst]
    return worst, f"{worst}: {', '.join(hits)}"


def evaluate_bom(raw: bytes | dict, policy: dict | None = None) -> list[LicenseDecision]:
    """Decisions for every component (nested included) in a CycloneDX document."""
    doc = json.loads(raw) if isinstance(raw, (bytes, str)) else raw
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        raise ValueError("not a CycloneDX document (bomFormat != CycloneDX)")
    policy = policy or dict(DEFAULT_POLICY)
    out: list[LicenseDecision] = []

    def walk(items):
        for c in items or []:
            if not isinstance(c, dict):
                continue
            lic, op = component_licenses(c)
            decision, reason = decide(lic, op, policy)
            out.append(LicenseDecision(component=str(c.get("name") or c.get("bom-ref") or "?"),
                                       version=str(c.get("version") or ""), purl=str(c.get("purl") or ""),
                                       licenses=lic, decision=decision, reason=reason,
                                       ref=str(c.get("bom-ref") or "")))
            walk(c.get("components"))

    walk(doc.get("components"))
    return out


def violations(decisions: list[LicenseDecision]) -> list[LicenseDecision]:
    """Decisions that need action (deny / review / unknown)."""
    return [d for d in decisions if d.decision != "allow"]
