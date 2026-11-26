"""Target-environment intrusive gate that fails closed (FND-02).

Intrusive automated cases (SSRF canary, UPLOAD marker, stored XSS, T22 body
mutation) may send requests only when :func:`decide_intrusive` allowed them for
this execution. ``APP_ENV`` (Attestra's own environment) plays **no** part here; it
only governs Attestra's own bypass flags.

``allow`` is true only when all of these hold (contract PHASE2 §3.4):

1. the per-test env flag is on (``ATTESTRA_AUTOMATED_VAPT_{SSRF,UPLOAD,STORED_XSS,MUTATION}``);
2. the execution profile is ``active`` or ``intrusive``;
3. the scope policy (``runner/gate.policy_input`` + ``runner/policy.decide`` with
   ``profile="active"``) allows it: intrusive_allowed, authorization covering the
   asset environment, window, not halted, ownership, rate limit;
4. ``asset.environment`` is in ``ATTESTRA_INTRUSIVE_ALLOWED_ENVIRONMENTS`` (default
   ``dev,demo``). ``production`` can never be allowed;
5. UPLOAD and XSSSTORE also need a ``cleanup_plan`` acknowledgement.

When anything is missing or unclear, the answer is deny. There is deliberately no
rollback flag.
"""

# @lat: [[run-validity-and-policy#Intrusive policy]]

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

INTRUSIVE_TEST_IDS: frozenset[str] = frozenset({"SSRF", "UPLOAD", "XSSSTORE", "T22"})
CLEANUP_REQUIRED: frozenset[str] = frozenset({"UPLOAD", "XSSSTORE"})
ACTIVE_PROFILES: frozenset[str] = frozenset({"active", "intrusive"})

FLAG_ENV: dict[str, str] = {
    "SSRF": "ATTESTRA_AUTOMATED_VAPT_SSRF",
    "UPLOAD": "ATTESTRA_AUTOMATED_VAPT_UPLOAD",
    "XSSSTORE": "ATTESTRA_AUTOMATED_VAPT_STORED_XSS",
    "T22": "ATTESTRA_AUTOMATED_VAPT_MUTATION",
}

ALLOWLIST_ENV = "ATTESTRA_INTRUSIVE_ALLOWED_ENVIRONMENTS"
DEFAULT_ALLOWED_ENVIRONMENTS: frozenset[str] = frozenset({"dev", "demo"})
#: Never allowed, whatever the allowlist says.
FORBIDDEN_ENVIRONMENTS: frozenset[str] = frozenset({"production", "prod", "live", "prd"})

CTX_KEY = "_intrusive_policy"

# Reason codes (value-free; persisted in result_json.policy_decisions).
R_ALLOWED = "allowed"
R_NOT_INTRUSIVE = "not_an_intrusive_test"
R_FLAG_OFF = "env_flag_off"
R_PROFILE = "profile_not_active"
R_POLICY = "policy_denied"
R_POLICY_ERROR = "policy_error"
R_ENV = "env_not_allowed"
R_ENV_FORBIDDEN = "env_production_forbidden"
R_ENV_UNKNOWN = "env_unknown"
R_ALLOWLIST_INVALID = "allowlist_invalid"
R_CLEANUP = "cleanup_plan_missing"
R_NO_DECISION = "no_policy_decision"
R_PROD_SAFE_ALLOWED = "production_safe_mutation_allowed"
R_PROD_SAFE_DENIED = "production_safe_mutation_denied"


@dataclass(frozen=True)
class IntrusiveDecision:
    allow: bool
    reason: str
    facts: dict[str, Any] = field(default_factory=dict)  # value-free: no secrets, no URLs

    def to_json(self) -> dict[str, Any]:
        return {"allow": bool(self.allow), "reason": self.reason, "facts": dict(sorted(self.facts.items()))}


def deny(reason: str, **facts: Any) -> IntrusiveDecision:
    return IntrusiveDecision(False, reason, dict(facts))


# ------------------------------------------------------------------ allowlist


class AllowlistError(ValueError):
    """The intrusive environment allowlist names a forbidden environment."""


def parse_allowed_environments(raw: str | None) -> frozenset[str]:
    """Parse ``dev,demo``-style text. Raises :class:`AllowlistError` if production is listed.

    ``config.validate_runtime_config`` (INT) calls this so a bad value fails startup.
    Empty/unset means the default ``{dev, demo}``.
    """
    if raw is None or not str(raw).strip():
        return DEFAULT_ALLOWED_ENVIRONMENTS
    envs = frozenset(p.strip().lower() for p in str(raw).split(",") if p.strip())
    bad = sorted(envs & FORBIDDEN_ENVIRONMENTS)
    if bad:
        raise AllowlistError(
            f"{ALLOWLIST_ENV} must never include {', '.join(bad)}; intrusive tests are refused on production"
        )
    return envs


def allowed_environments() -> frozenset[str]:
    """Current allowlist; an invalid value fails closed (empty set = deny everything)."""
    try:
        from attestra import config

        configured = getattr(config, "INTRUSIVE_ALLOWED_ENVIRONMENTS", None)
    except Exception:  # pragma: no cover
        configured = None
    try:
        if configured is not None:
            envs = frozenset(str(e).strip().lower() for e in configured if str(e).strip())
            if envs & FORBIDDEN_ENVIRONMENTS:
                return frozenset()
            return envs
        return parse_allowed_environments(os.environ.get(ALLOWLIST_ENV))
    except AllowlistError:
        return frozenset()


# ------------------------------------------------------------------ flags


def _truthy(raw: str | None) -> bool:
    return (raw or "").strip().lower() in ("1", "true", "yes", "on")


def env_flag_enabled(test_id: str) -> bool:
    """Per-test opt-in flag. Default off. T22 also honours ``config.AUTOMATED_VAPT_MUTATION``."""
    tid = (test_id or "").upper()
    name = FLAG_ENV.get(tid)
    if not name:
        return False
    if _truthy(os.environ.get(name)):
        return True
    if tid == "T22":
        try:
            from attestra import config

            return bool(getattr(config, "AUTOMATED_VAPT_MUTATION", False))
        except Exception:  # pragma: no cover
            return False
    return False


# ------------------------------------------------------------------ decision


def decide_from_policy_input(
    inp: Mapping[str, Any] | None,
    *,
    test_id: str,
    profile: str,
    env_flag_enabled: bool,
    cleanup_plan_ack: bool = False,
    policy_decide: Callable[[dict[str, Any]], Any] | None = None,
    allowed: frozenset[str] | None = None,
    production_grant: Mapping[str, Any] | None = None,
) -> IntrusiveDecision:
    """Pure core of :func:`decide_intrusive` (no DB). ``inp`` is a ``gate.policy_input`` document.

    ``production_grant`` is an optional pre-validated grant facts dict from
    [[attestra.automated_vapt.core.mutation_approval]] (Gap #3). Ordinary intrusive
    tests remain forbidden on production when no valid grant is present.
    """
    tid = (test_id or "").upper()
    prof = (profile or "").strip().lower()
    envs = allowed_environments() if allowed is None else allowed
    inp = dict(inp or {})
    asset_env = str(inp.get("asset_environment") or "").strip().lower()
    facts: dict[str, Any] = {
        "test_id": tid,
        "profile": prof,
        "env_flag": bool(env_flag_enabled),
        "asset_environment": asset_env,
        "allowed_environments": sorted(envs),
        "intrusive_allowed": bool(inp.get("intrusive_allowed")),
        "engagement_status": str(inp.get("engagement_status") or ""),
        "authorized_for_environment": asset_env in [str(e).lower() for e in (inp.get("authorized_environments") or [])],
        "cleanup_plan_ack": bool(cleanup_plan_ack),
        "production_safe_grant": bool(production_grant),
    }
    if tid not in INTRUSIVE_TEST_IDS:
        return deny(R_NOT_INTRUSIVE, **facts)
    if not env_flag_enabled:
        return deny(R_FLAG_OFF, **facts)
    if prof not in ACTIVE_PROFILES:
        return deny(R_PROFILE, **facts)
    if not inp:
        return deny(R_POLICY_ERROR, **facts, policy_reason="no policy input")
    # Policy input is evaluated as an active profile so intrusive_allowed is enforced.
    inp["profile"] = "active"
    if policy_decide is None:
        from attestra.runner import policy as _policy

        policy_decide = _policy.decide
    try:
        decision = policy_decide(inp)
    except Exception as exc:  # noqa: BLE001 - fail closed, value-free
        return deny(R_POLICY_ERROR, **facts, policy_reason=type(exc).__name__)
    facts["policy_reason"] = str(getattr(decision, "reason", "") or "")
    if getattr(decision, "allow", False) is not True:
        return deny(R_POLICY, **facts)
    if not asset_env:
        return deny(R_ENV_UNKNOWN, **facts)
    if asset_env in FORBIDDEN_ENVIRONMENTS:
        # Gap #3: supervised production safe-mutation for T22 only.
        if tid == "T22" and production_grant:
            from attestra.automated_vapt.core import mutation_approval as ma

            if not ma.production_safe_mutation_enabled():
                return deny(R_PROD_SAFE_DENIED, **facts, grant_reason="flag_off")
            ok = bool(production_grant.get("ok"))
            reason = str(production_grant.get("reason") or "")
            facts["grant_reason"] = reason
            facts["grant_id"] = str(production_grant.get("approval_id") or "")[:32]
            if not ok:
                return deny(R_PROD_SAFE_DENIED, **facts)
            if tid in CLEANUP_REQUIRED and not cleanup_plan_ack:
                return deny(R_CLEANUP, **facts)
            # T22 production path always requires an explicit cleanup_plan on the grant.
            if not str(production_grant.get("cleanup_plan") or "").strip():
                return deny(R_CLEANUP, **facts, grant_reason="cleanup_plan_missing")
            return IntrusiveDecision(True, R_PROD_SAFE_ALLOWED, facts)
        return deny(R_ENV_FORBIDDEN, **facts)
    if not envs:
        return deny(R_ALLOWLIST_INVALID, **facts)
    if asset_env not in envs:
        return deny(R_ENV, **facts)
    if tid in CLEANUP_REQUIRED and not cleanup_plan_ack:
        return deny(R_CLEANUP, **facts)
    return IntrusiveDecision(True, R_ALLOWED, facts)


def _grant_facts_from_extra(extra: Mapping[str, Any] | None) -> Mapping[str, Any] | None:
    """Build production_grant facts from ctx.extra when a validated approval is attached."""
    extra = extra or {}
    raw = extra.get("production_safe_mutation") or extra.get("_production_safe_mutation")
    if not isinstance(raw, Mapping):
        return None
    # Expected keys set by orchestrator after validate_grant_for_execution
    return {
        "ok": bool(raw.get("ok")),
        "reason": str(raw.get("reason") or ""),
        "approval_id": str(raw.get("approval_id") or "")[:64],
        "cleanup_plan": str(raw.get("cleanup_plan") or ""),
        "test_record_id": str(raw.get("test_record_id") or ""),
        "approved_fields": list(raw.get("approved_fields") or []),
    }


def decide_intrusive(
    session: Any,
    *,
    engagement_id: int,
    asset_id: int,
    test_id: str,
    profile: str,
    env_flag_enabled: bool,
    cleanup_plan_ack: bool = False,
    production_grant: Mapping[str, Any] | None = None,
) -> IntrusiveDecision:
    """Contract §3.4: gather policy facts from the DB and decide. Never raises."""
    tid = (test_id or "").upper()
    prof = (profile or "").strip().lower()
    if tid not in INTRUSIVE_TEST_IDS:
        return deny(R_NOT_INTRUSIVE, test_id=tid, profile=prof)
    if not env_flag_enabled:
        return deny(R_FLAG_OFF, test_id=tid, profile=prof, env_flag=False)
    if prof not in ACTIVE_PROFILES:
        return deny(R_PROFILE, test_id=tid, profile=prof, env_flag=True)
    try:
        from attestra.runner import gate

        inp = gate.policy_input(session, engagement_id, asset_id, tool="zap", profile="active")
    except Exception as exc:  # noqa: BLE001 - fail closed, value-free
        return deny(R_POLICY_ERROR, test_id=tid, profile=prof, env_flag=True, policy_reason=type(exc).__name__)
    return decide_from_policy_input(
        inp,
        test_id=tid,
        profile=profile,
        env_flag_enabled=env_flag_enabled,
        cleanup_plan_ack=cleanup_plan_ack,
        production_grant=production_grant,
    )


def decide_all(
    session: Any,
    *,
    engagement_id: int,
    asset_id: int,
    test_ids: list[str] | tuple[str, ...],
    profile: str,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, IntrusiveDecision]:
    """Convenience for INT: one decision per intrusive id present in ``test_ids``."""
    ack = bool((extra or {}).get("cleanup_plan") or (extra or {}).get("cleanup_plan_ack"))
    grant = _grant_facts_from_extra(extra)
    out: dict[str, IntrusiveDecision] = {}
    for tid in sorted({str(t).upper() for t in test_ids} & INTRUSIVE_TEST_IDS):
        # Production grant applies only to T22; other intrusive ids stay hard-forbidden on prod.
        out[tid] = decide_intrusive(
            session,
            engagement_id=engagement_id,
            asset_id=asset_id,
            test_id=tid,
            profile=profile,
            env_flag_enabled=env_flag_enabled(tid),
            cleanup_plan_ack=ack,
            production_grant=grant if tid == "T22" else None,
        )
    return out


def _from_any(value: Any) -> IntrusiveDecision | None:
    if isinstance(value, IntrusiveDecision):
        return value
    if isinstance(value, Mapping) and isinstance(value.get("allow"), bool):
        return IntrusiveDecision(bool(value["allow"]), str(value.get("reason") or ""), dict(value.get("facts") or {}))
    return None


def decision_from_ctx(ctx: Any, test_id: str) -> IntrusiveDecision:
    """Read the decision INT stored in ``ctx.extra["_intrusive_policy"][test_id]``. Absent => deny.

    Defence in depth: re-checks the env flag and refuses forbidden environments even
    when a stored decision says allow.
    """
    tid = (test_id or "").upper()
    extra = getattr(ctx, "extra", None) if ctx is not None else None
    if isinstance(ctx, Mapping):
        extra = ctx.get("extra", ctx)
    store = (extra or {}).get(CTX_KEY) if isinstance(extra, Mapping) else None
    dec = _from_any(store.get(tid)) if isinstance(store, Mapping) else None
    if tid in INTRUSIVE_TEST_IDS and not env_flag_enabled(tid):
        return deny(R_FLAG_OFF, **{**(dec.facts if dec else {"test_id": tid}), "env_flag": False})
    if dec is None:
        return deny(R_NO_DECISION, test_id=tid)
    if not dec.allow:
        return dec
    if not env_flag_enabled(tid):
        return deny(R_FLAG_OFF, **{**dec.facts, "env_flag": False})
    env = str(dec.facts.get("asset_environment") or "").lower()
    if not env:
        return deny(R_ENV_UNKNOWN, **dec.facts)
    if env in FORBIDDEN_ENVIRONMENTS:
        return deny(R_ENV_FORBIDDEN, **dec.facts)
    return dec


def public_decisions(decisions: Mapping[str, IntrusiveDecision]) -> list[dict[str, Any]]:
    """Value-free list for ``result_json.policy_decisions``."""
    return [{"test_id": tid, **d.to_json()} for tid, d in sorted(decisions.items())]


def skip_payload(test_id: str, category: str, decision: IntrusiveDecision, *, disabled_reason: str) -> dict[str, Any]:
    """Standard module result for a denied intrusive case: SKIPPED with ``policy_denied`` or the flag-off code."""
    reason = disabled_reason if decision.reason == R_FLAG_OFF else "policy_denied"
    return {
        "test_id": test_id,
        "category": category,
        "status_hint": "SKIPPED",
        "skip_reason": reason,
        "policy_decision": decision.to_json(),
        "observations": {
            "detail": f"intrusive {test_id} not run: {decision.reason} (target-environment policy; APP_ENV is not used)",
        },
        "finding_candidate": False,
        "evidence_hints": [],
        "validity_samples": [],
    }
