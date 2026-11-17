"""B-05: Injection coverage catalogue and safety tiers.

One declared entry per injection check: payload class, injection location, safety tier,
WSTG reference and the exact payloads. [[validate_catalog]] proves that no entry carries
a destructive or time-based payload, and [[classify_outcome]] separates **reflected /
error** (signal) from **filtered** (the app encoded or stripped the canary), **blocked**
(WAF / challenge / 429 answered, not the app) and **inconclusive** (network / origin
error / unknown) so a blocked probe is never read as "not vulnerable".

Entries with ``implemented=False`` are listed for coverage reporting only (status
``not_assessed``); nothing sends them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# @lat: [[web-api-probes#Injection catalogue]]

CATALOG_VERSION = "inj-catalog/1"

TIERS = ("T0", "T1", "T2", "T3")
LOCATIONS = ("query", "path", "header", "json_body", "form_body", "cookie")


@dataclass(frozen=True)
class InjectionCheck:
    check_id: str
    test_id: str  # catalogue case that runs it (INJ / XSS / ...)
    payload_class: str
    location: str
    tier: str
    wstg_ref: str
    description: str
    payloads: tuple[str, ...] = field(default_factory=tuple)
    implemented: bool = True

    def public(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "test_id": self.test_id,
            "payload_class": self.payload_class,
            "location": self.location,
            "tier": self.tier,
            "wstg_ref": self.wstg_ref,
            "implemented": self.implemented,
            "payload_count": len(self.payloads),
        }


CHECKS: tuple[InjectionCheck, ...] = (
    InjectionCheck(
        "INJ-REFLECT-QUERY",
        "INJ",
        "reflection_canary",
        "query",
        "T1",
        "WSTG-INPV-01",
        "benign ATTSTRA_CANARY_* value; flags unencoded HTML reflection only",
        ("ATTSTRA_CANARY_<random>'",),
    ),
    InjectionCheck(
        "INJ-SQLERR-QUERY",
        "INJ",
        "sql_error_boolean",
        "query",
        "T1",
        "WSTG-INPV-05",
        "quote / boolean tautology; flags database error signatures only (never time-based)",
        ("'", '"'),
    ),
    InjectionCheck(
        "INJ-SQLBOOL-QUERY",
        "INJ",
        "sql_error_boolean",
        "query",
        "T1",
        "WSTG-INPV-05",
        "boolean pair sent only after a clean first probe; error signature only",
        ("' OR '1'='1", "1' AND '1'='2"),
    ),
    InjectionCheck(
        "INJ-REFLECT-HEADER",
        "INJ",
        "reflection_canary",
        "header",
        "T1",
        "WSTG-INPV-01",
        "canary reflected from request headers (observed on the query probes' responses)",
        (),
    ),
    InjectionCheck(
        "INJ-SSTI-QUERY",
        "SSIND",
        "template_error_signature",
        "query",
        "T0",
        "WSTG-INPV-18",
        "passive template-engine error signatures in captured responses (no expression payloads)",
        (),
    ),
    InjectionCheck(
        "INJ-JSON-BODY",
        "T21",
        "type_confusion",
        "json_body",
        "T2",
        "WSTG-INPV-05",
        "JSON body type confusion lives in replay check T21 (intrusive policy gated)",
        (),
        implemented=False,
    ),
    InjectionCheck(
        "INJ-PATH",
        "INJ",
        "reflection_canary",
        "path",
        "T1",
        "WSTG-INPV-01",
        "path-segment canary (not implemented; listed for coverage)",
        (),
        implemented=False,
    ),
    InjectionCheck(
        "INJ-CMD",
        "INJ",
        "os_command",
        "query",
        "T3",
        "WSTG-INPV-12",
        "OS command injection is lab-only and not sent by the safe pack",
        (),
        implemented=False,
    ),
)

# Destructive, time-based, out-of-band or execution payload markers: never allowed.
_FORBIDDEN_RE = re.compile(
    r"(?i)(\bdrop\s+table\b|\bdelete\s+from\b|\btruncate\b|\bupdate\s+\w+\s+set\b|\binsert\s+into\b|"
    r"\bsleep\s*\(|\bwaitfor\s+delay\b|\bbenchmark\s*\(|pg_sleep|\bshutdown\b|xp_cmdshell|"
    r";\s*(rm|del|shutdown|curl|wget)\b|\|\s*(nc|bash|sh)\b|\$\(|`|load_file|into\s+outfile|"
    r"169\.254\.169\.254|file://|gopher://|dict://)"
)


def checks(*, test_id: str | None = None, implemented_only: bool = False) -> list[InjectionCheck]:
    out = [c for c in CHECKS if (test_id is None or c.test_id == test_id)]
    if implemented_only:
        out = [c for c in out if c.implemented]
    return out


def get(check_id: str) -> InjectionCheck | None:
    for c in CHECKS:
        if c.check_id == check_id:
            return c
    return None


def validate_catalog(entries: tuple[InjectionCheck, ...] | list[InjectionCheck] = CHECKS) -> list[str]:
    """Return problems (empty list = OK): duplicates, bad tier/location, destructive payloads."""
    problems: list[str] = []
    seen: set[str] = set()
    for c in entries:
        if c.check_id in seen:
            problems.append(f"duplicate check_id {c.check_id}")
        seen.add(c.check_id)
        if c.tier not in TIERS:
            problems.append(f"{c.check_id}: unknown tier {c.tier}")
        if c.location not in LOCATIONS:
            problems.append(f"{c.check_id}: unknown location {c.location}")
        if not c.payload_class:
            problems.append(f"{c.check_id}: missing payload_class")
        if not c.wstg_ref.startswith("WSTG-"):
            problems.append(f"{c.check_id}: missing WSTG reference")
        if c.implemented and c.tier in ("T2", "T3") and c.test_id == "INJ":
            problems.append(f"{c.check_id}: INJ safe pack may not run tier {c.tier}")
        for p in c.payloads:
            if _FORBIDDEN_RE.search(p):
                problems.append(f"{c.check_id}: forbidden payload content")
    return problems


def coverage_rows() -> list[dict[str, Any]]:
    """Value-free coverage rows: implemented checks are ``assessed``, others ``not_assessed``."""
    return [{**c.public(), "status": "assessed" if c.implemented else "not_assessed"} for c in CHECKS]


OUTCOMES = (
    "reflected",
    "reflected_non_html",
    "error_signature",
    "filtered",
    "not_reflected",
    "blocked",
    "inconclusive",
)


def classify_outcome(
    response_class: str,
    *,
    reflected_unencoded: bool,
    error_signature: bool,
    marker_present_encoded: bool,
    reflected_non_html: bool = False,
) -> str:
    """Map one probe response to an outcome. Edge answers are never read as app behaviour."""
    rc = str(getattr(response_class, "value", response_class) or "unknown")
    if rc in ("waf_block", "challenge", "rate_limited"):
        return "blocked"
    if rc in ("network_failed", "origin_error", "unknown", "auth_expired"):
        # An origin 500 with a DB error signature is still a signal.
        if rc == "origin_error" and error_signature:
            return "error_signature"
        return "inconclusive"
    if reflected_unencoded:
        return "reflected"
    if error_signature:
        return "error_signature"
    if reflected_non_html:
        return "reflected_non_html"
    if marker_present_encoded:
        return "filtered"
    return "not_reflected"
