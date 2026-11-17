"""Explainable test-case planner (I-05).

Pure functions: given the requested case ids and value-free run facts, return an
ordered plan where each case is ``run``, ``skip`` (with the NOT_TESTED / SKIPPED
reason it will be recorded with) or ``defer``, plus a human explanation. Also picks a
request-rate profile: a conservative low-rate profile when a CDN/WAF was seen or a
previous run was challenged or rate-limited.

Nothing here sends traffic or changes defaults; the orchestrator keeps its current
order until the INT wiring in ``WIRING_WP1.md`` opts in.
"""

# @lat: [[run-validity-and-policy#Planner]]

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from typing import Any

from attestra.automated_vapt.core.intrusive_policy import INTRUSIVE_TEST_IDS

PLANNER_VERSION = "plan1"

# Lower tier runs first: passive / read-only before authz comparisons before writes.
_TIER: dict[str, int] = {
    "OIDCMETA": 0, "SESSION": 0, "SESSLIFE": 1, "T03": 1, "T07": 1, "T19": 1,
    "XSS": 2, "XSSDOM": 2, "INJ": 2, "FILE": 2, "T21": 2,
    "T04": 3, "T05": 3, "T06": 3, "ROLEDIFF": 3, "BIZ": 3, "T20": 3,
    "SSRF": 4, "UPLOAD": 5, "XSSSTORE": 5, "T22": 5,
}
_DEFAULT_TIER = 2
NEEDS_SESSION = frozenset({"T04", "T05", "T06", "ROLEDIFF", "BIZ", "T20", "T22", "SESSLIFE"})
NEEDS_SECONDARY = frozenset({"T04", "T06", "ROLEDIFF", "T20"})
NON_EXECUTABLE = frozenset({"T01", "T02"} | {f"T{n:02d}" for n in range(8, 19)} | {"SCOPE_SMOKE"})

RATE_DEFAULT = {"name": "default", "max_rps": 5.0, "concurrency": 2, "jitter_ms": [0, 100], "max_requests_per_case": 60, "stop_on": ["challenge"]}
RATE_LOW = {"name": "low_rate_cdn", "max_rps": 1.0, "concurrency": 1, "jitter_ms": [250, 750], "max_requests_per_case": 20, "stop_on": ["challenge", "rate_limited", "auth_expired"]}


@dataclass(frozen=True)
class PlanFacts:
    has_session: bool = False
    has_secondary_session: bool = False
    cdn_detected: bool = False
    previous_validity: str | None = None  # run_validity state of the last run, if any
    intrusive_decisions: Mapping[str, Mapping[str, Any]] | None = None


@dataclass(frozen=True)
class PlannedCase:
    test_id: str
    action: str  # run | skip | defer
    order: int
    reason: str
    explanation: str

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


def rate_profile(facts: PlanFacts) -> dict[str, Any]:
    low = facts.cdn_detected or (facts.previous_validity or "") in {"CHALLENGE_DETECTED", "RATE_LIMITED", "PARTIALLY_BLOCKED"}
    prof = dict(RATE_LOW if low else RATE_DEFAULT)
    prof["why"] = (
        "CDN/WAF detected or previous run blocked; using conservative low-rate profile"
        if low else "no CDN/WAF signal; default rate profile"
    )
    return prof


def _decide(tid: str, facts: PlanFacts) -> tuple[str, str, str]:
    if tid in NON_EXECUTABLE:
        return "skip", "not_executable", "verified by the platform/test suite, not a live probe"
    if tid in INTRUSIVE_TEST_IDS:
        dec = (facts.intrusive_decisions or {}).get(tid)
        if not dec:
            return "skip", "no_policy_decision", "intrusive case without an FND-02 policy decision is refused"
        if not dec.get("allow"):
            return "skip", str(dec.get("reason") or "policy_denied"), "intrusive policy denied this case"
    if tid in NEEDS_SESSION and not facts.has_session:
        return "skip", "no_auth_session", "needs a ready engagement login profile"
    if tid in NEEDS_SECONDARY and not facts.has_secondary_session:
        return "skip", "no_second_role", "needs a second authorized identity to compare"
    if facts.previous_validity == "AUTH_EXPIRED" and tid in NEEDS_SESSION:
        return "defer", "session_recheck", "previous run lost its session; re-verify login before authz cases"
    return "run", "planned", "eligible"


def plan_cases(case_ids: Iterable[str], facts: PlanFacts | None = None) -> dict[str, Any]:
    facts = facts or PlanFacts()
    ids = list(dict.fromkeys(str(c).upper() for c in case_ids if str(c).strip()))
    ordered = sorted(ids, key=lambda t: (_TIER.get(t, _DEFAULT_TIER), ids.index(t)))
    cases: list[PlannedCase] = []
    for i, tid in enumerate(ordered):
        action, reason, why = _decide(tid, facts)
        tier = _TIER.get(tid, _DEFAULT_TIER)
        cases.append(PlannedCase(tid, action, i, reason, f"tier {tier}: {why}"))
    return {
        "version": PLANNER_VERSION,
        "rate_profile": rate_profile(facts),
        "cases": [c.to_json() for c in cases],
        "run": [c.test_id for c in cases if c.action == "run"],
        "skipped": {c.test_id: c.reason for c in cases if c.action == "skip"},
        "deferred": [c.test_id for c in cases if c.action == "defer"],
    }


#: Name used in WORK_PARTITION.md for the INT call site.
plan = plan_cases
