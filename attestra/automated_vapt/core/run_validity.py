"""Run-validity state machine (FND-03).

Pure and deterministic. Each case collects the :class:`Classification` of the
responses it relied on (``validity_samples``); :class:`CaseValidity` turns them into
a case state, and :func:`aggregate_run` folds every case into the run state persisted
as ``result_json.run_validity`` (contract PHASE2 §3.2, ``version: "rv1"``).

Precedence (first match wins):

1. ``NETWORK_FAILED``      >= 80 % of samples are network failures
2. ``AUTH_EXPIRED``        a session-dependent case lost auth (guard event or AUTH_EXPIRED sample)
3. ``CHALLENGE_DETECTED``  any challenge sample
4. ``RATE_LIMITED``        any rate-limited sample
5. ``PARTIALLY_BLOCKED``   any WAF block sample (``fully_blocked`` is set when >= 80 %)
6. ``INCONCLUSIVE``        fewer than ``min_usable`` usable samples
7. ``VALID``

Legacy rows without ``run_validity`` read as "not computed" and are never VALID.
"""

# @lat: [[run-validity-and-policy#Run validity]]

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from attestra.automated_vapt.core.response_classifier import (
    Classification,
    ResponseClass,
    USABLE_CLASSES,
)

VERSION = "rv1"

VALID = "VALID"
PARTIALLY_BLOCKED = "PARTIALLY_BLOCKED"
CHALLENGE_DETECTED = "CHALLENGE_DETECTED"
RATE_LIMITED = "RATE_LIMITED"
AUTH_EXPIRED = "AUTH_EXPIRED"
NETWORK_FAILED = "NETWORK_FAILED"
INCONCLUSIVE = "INCONCLUSIVE"
STATES = (VALID, PARTIALLY_BLOCKED, CHALLENGE_DETECTED, RATE_LIMITED, AUTH_EXPIRED, NETWORK_FAILED, INCONCLUSIVE)
NOT_COMPUTED = "NOT_COMPUTED"  # legacy / pre-upgrade rows (display only, never persisted as a state)

NETWORK_FAILED_RATIO = 0.8
FULLY_BLOCKED_RATIO = 0.8
CASE_MIN_USABLE = 1
RUN_MIN_USABLE = 2

MODE_ENFORCE = "enforce"
MODE_OBSERVE = "observe"


def _coerce(sample: Any) -> Classification | None:
    """Accept a Classification, its ``to_dict`` form, or a bare class string."""
    if isinstance(sample, Classification):
        return sample
    if isinstance(sample, ResponseClass):
        return Classification(sample, (), 1.0)
    if isinstance(sample, str):
        try:
            return Classification(ResponseClass(sample), (), 1.0)
        except ValueError:
            return Classification(ResponseClass.UNKNOWN, ("unparsed",), 0.0)
    if isinstance(sample, Mapping):
        raw = sample.get("cls")
        try:
            cls = ResponseClass(str(raw))
        except ValueError:
            cls = ResponseClass.UNKNOWN
        reasons = tuple(str(r) for r in (sample.get("reasons") or ()))
        return Classification(cls, reasons, float(sample.get("confidence") or 0.0))
    return None


def _counts(samples: Sequence[Classification]) -> dict[str, int]:
    out: dict[str, int] = {}
    for s in samples:
        out[s.cls.value] = out.get(s.cls.value, 0) + 1
    return dict(sorted(out.items()))


def evaluate(
    samples: Sequence[Classification],
    *,
    auth_lost: bool = False,
    min_usable: int = CASE_MIN_USABLE,
) -> tuple[str, list[str]]:
    """Apply the §3.2 precedence table. Returns ``(state, reasons)``."""
    total = len(samples)
    by = _counts(samples)
    net = by.get(ResponseClass.NETWORK_FAILED.value, 0)
    usable = sum(1 for s in samples if s.cls in USABLE_CLASSES)
    if total and net / total >= NETWORK_FAILED_RATIO:
        return NETWORK_FAILED, [f"network_failed {net}/{total} samples"]
    expired = by.get(ResponseClass.AUTH_EXPIRED.value, 0)
    if auth_lost or expired:
        why = ["session lost during the run (session guard)"] if auth_lost else []
        if expired:
            why.append(f"auth_expired responses {expired}/{total}")
        return AUTH_EXPIRED, why
    chal = by.get(ResponseClass.CHALLENGE.value, 0)
    if chal:
        return CHALLENGE_DETECTED, [f"challenge pages {chal}/{total} samples"]
    rate = by.get(ResponseClass.RATE_LIMITED.value, 0)
    if rate:
        return RATE_LIMITED, [f"rate-limited responses {rate}/{total} samples"]
    waf = by.get(ResponseClass.WAF_BLOCK.value, 0)
    if waf:
        ratio = waf / total if total else 0.0
        tag = "fully blocked" if ratio >= FULLY_BLOCKED_RATIO else "partially blocked"
        return PARTIALLY_BLOCKED, [f"WAF block pages {waf}/{total} samples ({tag})"]
    if usable < max(1, int(min_usable)):
        return INCONCLUSIVE, [f"only {usable} usable sample(s); need {max(1, int(min_usable))}"]
    return VALID, []


@dataclass
class CaseValidity:
    """Accumulates one case's samples; ``state`` is recomputed on demand."""

    test_id: str
    samples: list[Classification] = field(default_factory=list)
    auth_lost: bool = False
    session_dependent: bool = False
    notes: list[str] = field(default_factory=list)

    def add(self, sample: Any) -> None:
        c = _coerce(sample)
        if c is not None:
            self.samples.append(c)

    def extend(self, samples: Iterable[Any] | None) -> None:
        for s in samples or ():
            self.add(s)

    def mark_auth_lost(self, note: str = "") -> None:
        self.auth_lost = True
        if note:
            self.notes.append(str(note)[:200])

    @property
    def state(self) -> str:
        return evaluate(self.samples, auth_lost=self.auth_lost, min_usable=CASE_MIN_USABLE)[0]

    def to_json(self) -> dict[str, Any]:
        state, reasons = evaluate(self.samples, auth_lost=self.auth_lost, min_usable=CASE_MIN_USABLE)
        return {
            "state": state,
            "reasons": reasons + list(self.notes),
            "sample_count": len(self.samples),
            "by_class": _counts(self.samples),
            "version": VERSION,
        }

    @classmethod
    def from_result(cls, test_id: str, result: Mapping[str, Any] | None, *, auth_lost: bool = False) -> "CaseValidity":
        """Build from a module result dict carrying ``validity_samples``."""
        cv = cls(test_id=test_id)
        cv.extend((result or {}).get("validity_samples") or ())
        if auth_lost:
            cv.mark_auth_lost("session guard reported auth loss")
        return cv


@dataclass(frozen=True)
class RunValidity:
    state: str
    reasons: tuple[str, ...]
    sample_count: int
    by_class: dict[str, int]
    affected_cases: tuple[str, ...]
    computed_at: str
    fully_blocked: bool = False
    version: str = VERSION

    @property
    def is_valid(self) -> bool:
        return self.state == VALID

    def to_json(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "reasons": list(self.reasons),
            "sample_count": self.sample_count,
            "by_class": dict(sorted(self.by_class.items())),
            "affected_cases": list(self.affected_cases),
            "computed_at": self.computed_at,
            "fully_blocked": self.fully_blocked,
            "version": self.version,
        }


def _iso(now: datetime | None) -> str:
    ts = now or datetime.now(timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def aggregate_run(
    cases: Iterable[CaseValidity],
    *,
    auth_lost: bool = False,
    min_usable: int = RUN_MIN_USABLE,
    now: datetime | None = None,
) -> RunValidity:
    """Fold every case into the run state (deterministic for a fixed ``now``)."""
    case_list = sorted(cases, key=lambda c: c.test_id)
    samples: list[Classification] = [s for c in case_list for s in c.samples]
    lost = auth_lost or any(c.auth_lost for c in case_list)
    state, reasons = evaluate(samples, auth_lost=lost, min_usable=min_usable)
    affected = tuple(c.test_id for c in case_list if c.state != VALID)
    waf = sum(1 for s in samples if s.cls is ResponseClass.WAF_BLOCK)
    fully = bool(samples) and waf / len(samples) >= FULLY_BLOCKED_RATIO
    return RunValidity(
        state=state,
        reasons=tuple(reasons),
        sample_count=len(samples),
        by_class=_counts(samples),
        affected_cases=affected,
        computed_at=_iso(now),
        fully_blocked=fully,
    )


def guard_lost(session_auth: Any) -> bool:
    """True when an engagement ``SessionAuth`` / ``SessionGuard`` reports a lost session."""
    if session_auth is None:
        return False
    guard = getattr(session_auth, "guard", session_auth)
    if getattr(guard, "lost", False) is True:
        return True
    events = getattr(guard, "events", None) or []
    return any(isinstance(e, Mapping) and e.get("kind") == "lost" for e in events)


def read_run_validity(result_json: Mapping[str, Any] | None) -> dict[str, Any]:
    """Display helper: legacy rows (no ``run_validity``) read as not computed, never VALID."""
    rv = (result_json or {}).get("run_validity") if isinstance(result_json, Mapping) else None
    if not isinstance(rv, Mapping) or rv.get("state") not in STATES:
        return {"state": NOT_COMPUTED, "reasons": ["validity not computed (pre-upgrade run)"], "version": ""}
    return dict(rv)


# ------------------------------------------------------------------ status gating (used by INT / FND-06)

_NON_PASS_HINTS = frozenset({"BLOCKED", "INCONCLUSIVE", "NOT_TESTED", "SKIPPED", "DEFERRED"})


def gate_case_status(
    *,
    status_hint: str | None,
    finding_candidate: bool,
    case_state: str | None,
    mode: str = MODE_ENFORCE,
    has_samples: bool = True,
) -> str:
    """Map a module result to the §3.3 status vocabulary.

    ``PASSED`` only when the module gave no non-pass hint, there is no finding, and
    (in ``enforce`` mode) the case validity is VALID. A finding stays a FINDING (its
    confidence is capped elsewhere when the case is not VALID).

    ``has_samples=False`` marks a legacy module that does not emit
    ``validity_samples`` yet (T04/T05/ROLEDIFF/INJ/FILE at the time of WP1); it keeps
    its old PASSED behaviour, but the run-level validity still applies to it.
    """
    hint = (status_hint or "").upper()
    if hint in _NON_PASS_HINTS:
        return hint
    if finding_candidate:
        return "FINDING"
    if mode == MODE_OBSERVE or not has_samples:
        return "PASSED"
    if case_state == VALID:
        return "PASSED"
    if case_state in (PARTIALLY_BLOCKED, CHALLENGE_DETECTED, RATE_LIMITED, AUTH_EXPIRED):
        return "BLOCKED"
    return "INCONCLUSIVE"


def cap_validation_status(validation_status: str, case_state: str | None) -> tuple[str, str]:
    """Never ``CONFIRMED`` unless the case is VALID. Returns ``(status, reason)``."""
    if (validation_status or "").upper() == "CONFIRMED" and case_state != VALID:
        return "POTENTIAL", f"capped: case validity {case_state or NOT_COMPUTED}"
    return validation_status, ""
