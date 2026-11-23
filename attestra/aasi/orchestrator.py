"""AASI Phase 3 recommend-only orchestrator.

Runs logical roles on one runtime, validates recommendations against registered
test IDs / AI adapters, gates intrusive items on human ``approve()``, and
returns planner-ready payloads without calling scanners.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import asdict, dataclass, field, replace
from typing import Any, Callable, Mapping, MutableMapping, Protocol, Sequence

from attestra import aasi
from attestra.aasi.evidence_gate import (
    CitationLookup,
    EvidenceGateError,
    assert_citations_valid,
    lookup_from_records,
)
from attestra.aasi.prioritize import prioritize_recommendations
from attestra.aasi.roles import (
    AI_ADAPTER_TEST_IDS,
    AssessmentPlan,
    ContextPacket,
    EvidenceNotes,
    Hypothesis,
    JsonProvider,
    QualityReport,
    ROLE_SEQUENCE,
    TestRecommendation,
    run_ai_security,
    run_evidence_reviewer,
    run_hypothesis,
    run_quality_reviewer,
    run_strategist,
)
from attestra.aasi.task_tree import (
    add_task,
    ensure_task_tree,
    new_task,
    propagate_completion,
    role_task_id,
    set_task_status,
)

try:
    from attestra.aasi.contracts import Conclusion
except ImportError:  # pragma: no cover - contracts always present in-tree
    Conclusion = None  # type: ignore[misc, assignment]

try:
    from attestra.automated_vapt.core.intrusive_policy import INTRUSIVE_TEST_IDS
except ImportError:  # pragma: no cover - defensive
    INTRUSIVE_TEST_IDS = frozenset({"SSRF", "UPLOAD", "XSSSTORE", "T22"})

try:
    from attestra.automated_vapt.core import test_registry
except ImportError:  # pragma: no cover
    test_registry = None  # type: ignore[assignment]

try:
    from attestra.runner.scanners import registry as scanner_registry
except ImportError:  # pragma: no cover
    scanner_registry = None  # type: ignore[assignment]


class AasiDisabledError(RuntimeError):
    """Raised when ``aasi.enabled()`` is false and ``run`` is invoked strictly."""


class AasiCancelledError(RuntimeError):
    """Raised when a cancel Event is set during orchestration."""


class AasiBudgetExhausted(RuntimeError):
    """Raised or recorded when the call/role budget is exhausted."""


class DecisionStore(Protocol):
    """Injectable persistence for runs and append-only decisions."""

    def save_run(self, run: Mapping[str, Any]) -> None: ...

    def record_decision(self, decision: Mapping[str, Any]) -> None: ...


class BudgetGate(Protocol):
    """Injectable budget: role slots and provider-call ceiling."""

    def allow_role(self, role: str) -> bool: ...

    def record_role(self, role: str) -> None: ...

    def exhausted(self) -> bool: ...

    def reason(self) -> str: ...


@dataclass
class SimpleBudget:
    """In-process budget used when ``attestra.aasi.budget`` is not injected."""

    max_roles: int = 5
    max_calls: int = 30
    max_wall_s: float = 900.0
    roles_used: int = 0
    calls_used: int = 0
    started_at: float = field(default_factory=time.monotonic)
    _reason: str = ""

    def allow_role(self, role: str) -> bool:
        if self.exhausted():
            return False
        if self.roles_used >= self.max_roles:
            self._reason = "max_roles"
            return False
        return True

    def record_role(self, role: str) -> None:
        self.roles_used += 1
        self.calls_used += 1

    def exhausted(self) -> bool:
        if self.roles_used >= self.max_roles:
            self._reason = self._reason or "max_roles"
            return True
        if self.calls_used >= self.max_calls:
            self._reason = "max_calls"
            return True
        if (time.monotonic() - self.started_at) >= self.max_wall_s:
            self._reason = "max_wall_s"
            return True
        return False

    def reason(self) -> str:
        return self._reason or ("exhausted" if self.exhausted() else "")


@dataclass
class MemoryStore:
    """Test-friendly in-memory DecisionStore."""

    runs: list[dict[str, Any]] = field(default_factory=list)
    decisions: list[dict[str, Any]] = field(default_factory=list)

    def save_run(self, run: Mapping[str, Any]) -> None:
        self.runs.append(dict(run))

    def record_decision(self, decision: Mapping[str, Any]) -> None:
        self.decisions.append(dict(decision))


ContextBuilder = Callable[[Mapping[str, Any]], ContextPacket]


def default_context_builder(seed: Mapping[str, Any]) -> ContextPacket:
    """Shallow context construction hook — copies seed into a mutable packet."""
    packet: dict[str, Any] = dict(seed)
    packet.setdefault("authorized_assets", [])
    packet.setdefault("authorized_test_types", ["ai_llm", "ai_agent"])
    packet.setdefault("coverage_gaps", [])
    packet.setdefault("observations", [])
    packet.setdefault("findings_meta", [])
    packet.setdefault("evidence_meta", [])
    packet.setdefault("plan_skips", [])
    if "run_id" not in packet:
        packet["run_id"] = f"run-{uuid.uuid4().hex[:12]}"
    return packet


def registered_test_ids() -> set[str]:
    """Union of Elite test_registry IDs and AI adapter capability names."""
    ids: set[str] = set(AI_ADAPTER_TEST_IDS)
    if test_registry is not None:
        for case in test_registry.list_test_cases():
            ids.add(case.id)
            ids.add(case.id.upper())
            ids.add(case.id.lower())
    if scanner_registry is not None:
        for name in scanner_registry.list_adapters():
            if name.lower() in AI_ADAPTER_TEST_IDS or name.lower() in {"garak", "promptfoo", "safelabs", "pyrit"}:
                ids.add(name)
                ids.add(name.lower())
    # Always allow the four AI capability names even if pyrit adapter is not registered yet.
    ids.update(AI_ADAPTER_TEST_IDS)
    return ids


def _normalize_test_id(test_id: str) -> str:
    return (test_id or "").strip()


def is_registered_test_id(test_id: str, *, allowlist: set[str] | None = None) -> bool:
    tid = _normalize_test_id(test_id)
    if not tid:
        return False
    allowed = allowlist if allowlist is not None else registered_test_ids()
    return tid in allowed or tid.upper() in allowed or tid.lower() in allowed


def compute_intrusive(test_id: str) -> bool:
    """Intrusive flag from policy / AI adapter tier — never from model claims."""
    tid = _normalize_test_id(test_id)
    if tid.upper() in INTRUSIVE_TEST_IDS:
        return True
    if tid.lower() in AI_ADAPTER_TEST_IDS:
        # AI probes are T2 (target egress); require approval before planner handoff.
        return True
    return False


@dataclass
class OrchestratorResult:
    """Outcome of one recommend-only AASI run."""

    status: str
    run_id: str
    plan: AssessmentPlan | None = None
    hypotheses: list[Hypothesis] = field(default_factory=list)
    recommendations: list[TestRecommendation] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)
    pending_approval: list[TestRecommendation] = field(default_factory=list)
    approved: list[TestRecommendation] = field(default_factory=list)
    evidence: EvidenceNotes | None = None
    quality: QualityReport | None = None
    conclusions: list[Any] = field(default_factory=list)
    tasks: list[dict[str, Any]] = field(default_factory=list)
    reason: str = ""
    planner_payload: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        def _ser(obj: Any) -> Any:
            if hasattr(obj, "__dataclass_fields__"):
                return asdict(obj)
            return obj

        return {
            "status": self.status,
            "run_id": self.run_id,
            "plan": _ser(self.plan) if self.plan else None,
            "hypotheses": [_ser(h) for h in self.hypotheses],
            "recommendations": [_ser(r) for r in self.recommendations],
            "rejected": list(self.rejected),
            "pending_approval": [_ser(r) for r in self.pending_approval],
            "approved": [_ser(r) for r in self.approved],
            "evidence": _ser(self.evidence) if self.evidence else None,
            "quality": _ser(self.quality) if self.quality else None,
            "conclusions": [_ser(c) for c in self.conclusions],
            "tasks": list(self.tasks),
            "reason": self.reason,
            "planner_payload": list(self.planner_payload),
        }


class AasiOrchestrator:
    """Bounded role loop: context → roles → validate → approval → planner payloads."""

    def __init__(
        self,
        *,
        provider: JsonProvider | None = None,
        store: DecisionStore | None = None,
        budget: BudgetGate | None = None,
        context_builder: ContextBuilder | None = None,
        cancel_event: threading.Event | None = None,
        require_enabled: bool = True,
        registered_ids: set[str] | None = None,
    ) -> None:
        self.provider = provider
        self.store: DecisionStore = store or MemoryStore()
        self.budget: BudgetGate = budget or SimpleBudget()
        self.context_builder = context_builder or default_context_builder
        self.cancel_event = cancel_event if cancel_event is not None else threading.Event()
        self.require_enabled = require_enabled
        self._registered_ids = registered_ids
        self._pending: MutableMapping[str, TestRecommendation] = {}
        self._approved: MutableMapping[str, TestRecommendation] = {}
        self._last_result: OrchestratorResult | None = None
        self._run_state: dict[str, Any] = {}

    # -------------------------------------------------------------- helpers

    def _check_cancel(self) -> None:
        if self.cancel_event.is_set():
            raise AasiCancelledError("AASI run cancelled")

    def _persist(self, *, run_id: str, role: str, kind: str, payload: Mapping[str, Any], ctx: ContextPacket) -> None:
        decision = {
            "id": f"dec-{uuid.uuid4().hex[:12]}",
            "run_id": run_id,
            "tenant_id": ctx.get("tenant_id"),
            "engagement_id": ctx.get("engagement_id"),
            "role": role,
            "kind": kind,
            "payload": dict(payload),
            "cites": list(payload.get("cites") or payload.get("evidence_citations") or []),
        }
        self.store.record_decision(decision)

    def _default_citation_lookup(self, ctx: ContextPacket) -> CitationLookup:
        """Build a lookup from context evidence/finding/observation metadata."""
        records: list[Mapping[str, Any]] = []
        tenant_id = ctx.get("tenant_id")
        engagement_id = ctx.get("engagement_id")
        for key, kind in (
            ("evidence_meta", "evidence"),
            ("findings_meta", "finding"),
            ("observations", "observation"),
            ("proof_meta", "proof"),
        ):
            for item in ctx.get(key) or []:
                if not isinstance(item, Mapping):
                    continue
                row = dict(item)
                row.setdefault("kind", kind)
                row.setdefault("tenant_id", tenant_id)
                row.setdefault("engagement_id", engagement_id)
                records.append(row)
        return lookup_from_records(records)

    def _sync_tasks_to_result(self, result: OrchestratorResult) -> None:
        result.tasks = [dict(t) for t in (self._run_state.get("tasks") or []) if isinstance(t, Mapping)]

    def _begin_role_task(self, run_id: str, role: str) -> str:
        tid = role_task_id(run_id, role)
        ensure_task_tree(self._run_state)
        if not any(str(t.get("id")) == tid for t in self._run_state.get("tasks") or [] if isinstance(t, Mapping)):
            add_task(
                self._run_state,
                new_task(
                    tid,
                    parent_id=role_task_id(run_id, "run"),
                    status="in_progress",
                    role=role,
                    kind="role",
                ),
            )
        else:
            set_task_status(self._run_state, tid, "in_progress")
        return tid

    def _complete_role_task(self, run_id: str, role: str, *, summary: str = "", ok: bool = True) -> None:
        tid = role_task_id(run_id, role)
        set_task_status(
            self._run_state,
            tid,
            "completed" if ok else "failed",
            summary=summary,
        )
        propagate_completion(self._run_state, tid)

    def persist_conclusion(
        self,
        conclusion: Any,
        *,
        ctx: ContextPacket,
        lookup_fn: CitationLookup | None = None,
        role: str = "quality_reviewer",
    ) -> Any:
        """Validate citations via the evidence gate, then append a conclusion decision.

        Accepts a ``Conclusion`` contract instance or a mapping. Forged / unknown /
        cross-tenant citations raise ``EvidenceGateError`` and are recorded as a
        rejection decision before re-raising.
        """
        run_id = str(ctx.get("run_id") or getattr(self._last_result, "run_id", "") or "")
        tenant_id = int(ctx.get("tenant_id") or 0)
        engagement_id = int(ctx.get("engagement_id") or 0)

        if isinstance(conclusion, Mapping):
            if Conclusion is None:
                raise TypeError("Conclusion contract unavailable")
            conc = Conclusion.from_mapping(conclusion)
        else:
            conc = conclusion
            if hasattr(conc, "validate"):
                conc.validate()

        cites = tuple(
            getattr(conc, "evidence_citations", None)
            or (conc.get("evidence_citations") if isinstance(conc, Mapping) else ())
            or ()
        )
        lookup = lookup_fn or self._default_citation_lookup(ctx)
        try:
            assert_citations_valid(tenant_id, engagement_id, cites, lookup)
        except EvidenceGateError as exc:
            rejection = {
                "id": getattr(conc, "id", None),
                "reason": exc.reason,
                "citation_id": exc.citation_id,
                "message": str(exc),
            }
            self._persist(
                run_id=run_id,
                role=role,
                kind="conclusion_rejected",
                payload=rejection,
                ctx=ctx,
            )
            if self._last_result is not None:
                self._last_result.rejected.append(rejection)
            raise

        payload = asdict(conc) if hasattr(conc, "__dataclass_fields__") else dict(conc)
        self._persist(run_id=run_id, role=role, kind="conclusion", payload=payload, ctx=ctx)
        if self._last_result is not None:
            self._last_result.conclusions.append(conc)
        return conc

    def _authorized_assets(self, ctx: ContextPacket) -> set[int]:
        out: set[int] = set()
        for asset in ctx.get("authorized_assets") or []:
            if isinstance(asset, Mapping) and "id" in asset:
                try:
                    out.add(int(asset["id"]))
                except (TypeError, ValueError):
                    continue
            elif isinstance(asset, int):
                out.add(asset)
        return out

    def _authorized_types(self, ctx: ContextPacket) -> set[str]:
        return {str(t) for t in (ctx.get("authorized_test_types") or [])}

    def validate_recommendation(
        self,
        rec: TestRecommendation,
        ctx: ContextPacket,
    ) -> tuple[TestRecommendation | None, dict[str, Any] | None]:
        """Return (accepted, None) or (None, rejection_record)."""
        allowlist = self._registered_ids if self._registered_ids is not None else registered_test_ids()
        tid = _normalize_test_id(rec.test_id)
        if not is_registered_test_id(tid, allowlist=allowlist):
            return None, {
                "id": rec.id,
                "reason": "unregistered_test_id",
                "test_id": tid,
            }

        allowed_assets = self._authorized_assets(ctx)
        if allowed_assets and rec.asset_id not in allowed_assets:
            return None, {
                "id": rec.id,
                "reason": "unauthorized_asset",
                "asset_id": rec.asset_id,
            }

        # Scope escalation: reject recommendations that introduce host/url fields.
        raw = asdict(rec) if hasattr(rec, "__dataclass_fields__") else dict(rec)  # type: ignore[arg-type]
        for banned in ("host", "hostname", "url", "target_url", "new_asset"):
            if raw.get(banned):
                return None, {"id": rec.id, "reason": "scope_escalation", "field": banned}

        authorized_types = self._authorized_types(ctx)
        test_type = str(rec.test_type or "")
        if authorized_types and test_type and test_type not in authorized_types:
            return None, {
                "id": rec.id,
                "reason": "unauthorized_test_type",
                "test_type": test_type,
            }

        intrusive = compute_intrusive(tid)
        # Model-claimed approval / intrusive flags have no effect — recompute.
        updated = replace(
            rec,
            test_id=tid,
            intrusive=intrusive,
            needs_approval=intrusive,
            status="pending" if intrusive else "approved",
        )
        return updated, None

    def approve(self, recommendation_id: str, *, actor: str = "human") -> TestRecommendation | None:
        """Human/policy approval — the only path that clears the approval gate."""
        rec = self._pending.pop(recommendation_id, None)
        if rec is None:
            return None
        approved = replace(rec, status="approved", needs_approval=False)
        self._approved[recommendation_id] = approved
        self.store.record_decision(
            {
                "id": f"dec-{uuid.uuid4().hex[:12]}",
                "run_id": getattr(self._last_result, "run_id", ""),
                "role": "approval",
                "kind": "approval",
                "payload": {"recommendation_id": recommendation_id, "actor": actor, "model_claim_ignored": True},
                "cites": [],
            }
        )
        if self._last_result is not None:
            self._last_result.pending_approval = [r for r in self._last_result.pending_approval if r.id != recommendation_id]
            self._last_result.approved.append(approved)
            self._last_result.planner_payload = self.planner_payloads()
            if not self._last_result.pending_approval and self._last_result.status == "AWAITING_APPROVAL":
                self._last_result.status = "COMPLETED"
        return approved

    def planner_payloads(self) -> list[dict[str, Any]]:
        """Recommendation dicts ready for Attestra planner — no scanner calls."""
        payloads: list[dict[str, Any]] = []
        for rec in self._approved.values():
            payloads.append(
                {
                    "recommendation_id": rec.id,
                    "test_id": rec.test_id,
                    "test_type": rec.test_type,
                    "asset_id": rec.asset_id,
                    "hypothesis_id": rec.hypothesis_id,
                    "intrusive": rec.intrusive,
                    "expected_evidence": list(rec.expected_evidence),
                    "rationale": rec.rationale,
                    "origin": "aasi",
                }
            )
        return payloads

    # ------------------------------------------------------------------ run

    def run(
        self,
        seed: Mapping[str, Any] | None = None,
        *,
        raise_if_disabled: bool = False,
    ) -> OrchestratorResult:
        """Execute the role sequence with budget / cancel / validation gates."""
        if self.require_enabled and not aasi.enabled():
            if raise_if_disabled:
                raise AasiDisabledError("AASI is disabled (ATTESTRA_AASI=off)")
            return OrchestratorResult(status="DISABLED", run_id="", reason="aasi_disabled")

        ctx = self.context_builder(dict(seed or {}))
        run_id = str(ctx.get("run_id") or f"run-{uuid.uuid4().hex[:12]}")
        ctx = dict(ctx)
        ctx["run_id"] = run_id

        result = OrchestratorResult(status="PLANNING", run_id=run_id)
        self._last_result = result
        self._pending.clear()
        # Keep previously approved items only within this run object.
        self._approved.clear()
        self._run_state = {
            "id": run_id,
            "tenant_id": ctx.get("tenant_id"),
            "engagement_id": ctx.get("engagement_id"),
            "status": "PLANNING",
            "schema_version": 1,
            "tasks": [],
        }
        ensure_task_tree(self._run_state)
        add_task(
            self._run_state,
            new_task(
                role_task_id(run_id, "run"),
                status="in_progress",
                role="orchestrator",
                kind="run",
                summary="AASI recommend-only run",
            ),
        )
        self.store.save_run(dict(self._run_state))

        plan: AssessmentPlan | None = None
        hypotheses: list[Hypothesis] = []
        recommendations: list[TestRecommendation] = []
        evidence: EvidenceNotes | None = None
        quality: QualityReport | None = None

        try:
            self._check_cancel()

            # --- strategist
            if not self.budget.allow_role("strategist"):
                result.status = "BLOCKED"
                result.reason = self.budget.reason() or "budget_exhausted"
                self._persist(run_id=run_id, role="orchestrator", kind="budget", payload={"reason": result.reason}, ctx=ctx)
                self._sync_tasks_to_result(result)
                return result
            self.budget.record_role("strategist")
            self._begin_role_task(run_id, "strategist")
            plan = run_strategist(ctx, provider=self.provider)
            result.plan = plan
            self._persist(run_id=run_id, role="strategist", kind="plan", payload=asdict(plan), ctx=ctx)
            self._complete_role_task(run_id, "strategist", summary=f"objectives={len(plan.objectives)}")
            self._check_cancel()

            # --- hypothesis
            if not self.budget.allow_role("hypothesis"):
                result.status = "BLOCKED"
                result.reason = self.budget.reason() or "budget_exhausted"
                self._persist(run_id=run_id, role="orchestrator", kind="budget", payload={"reason": result.reason}, ctx=ctx)
                self._sync_tasks_to_result(result)
                return result
            self.budget.record_role("hypothesis")
            self._begin_role_task(run_id, "hypothesis")
            hypotheses = run_hypothesis(ctx, provider=self.provider, plan=plan)
            result.hypotheses = hypotheses
            for hyp in hypotheses:
                self._persist(run_id=run_id, role="hypothesis", kind="hypothesis", payload=asdict(hyp), ctx=ctx)
            self._complete_role_task(run_id, "hypothesis", summary=f"hypotheses={len(hypotheses)}")
            self._check_cancel()

            # --- ai_security
            if not self.budget.allow_role("ai_security"):
                result.status = "BLOCKED"
                result.reason = self.budget.reason() or "budget_exhausted"
                self._persist(run_id=run_id, role="orchestrator", kind="budget", payload={"reason": result.reason}, ctx=ctx)
                self._sync_tasks_to_result(result)
                return result
            self.budget.record_role("ai_security")
            self._begin_role_task(run_id, "ai_security")
            raw_recs = run_ai_security(ctx, provider=self.provider, hypotheses=hypotheses)
            accepted: list[TestRecommendation] = []
            for rec in raw_recs:
                # Strip any model-claimed approval before validation.
                scrubbed = replace(rec, status="pending")
                ok, rejection = self.validate_recommendation(scrubbed, ctx)
                if rejection is not None:
                    result.rejected.append(rejection)
                    self._persist(
                        run_id=run_id,
                        role="ai_security",
                        kind="rejection",
                        payload=rejection,
                        ctx=ctx,
                    )
                    continue
                assert ok is not None
                accepted.append(ok)
                self._persist(run_id=run_id, role="ai_security", kind="recommendation", payload=asdict(ok), ctx=ctx)
            # Rank for planner handoff; planner still decides final order.
            recommendations = prioritize_recommendations(
                accepted,
                coverage_gaps=ctx.get("coverage_gaps") or [],
                findings_meta=ctx.get("findings_meta") or [],
            )
            result.recommendations = recommendations
            self._complete_role_task(run_id, "ai_security", summary=f"recommendations={len(recommendations)}")

            for rec in recommendations:
                if rec.needs_approval or rec.intrusive:
                    self._pending[rec.id] = rec
                    result.pending_approval.append(rec)
                else:
                    self._approved[rec.id] = replace(rec, status="approved")
                    result.approved.append(self._approved[rec.id])
            self._check_cancel()

            # --- evidence_reviewer
            if not self.budget.allow_role("evidence_reviewer"):
                result.status = "BLOCKED"
                result.reason = self.budget.reason() or "budget_exhausted"
                self._persist(run_id=run_id, role="orchestrator", kind="budget", payload={"reason": result.reason}, ctx=ctx)
                result.planner_payload = self.planner_payloads()
                self._sync_tasks_to_result(result)
                return result
            self.budget.record_role("evidence_reviewer")
            self._begin_role_task(run_id, "evidence_reviewer")
            evidence = run_evidence_reviewer(ctx, provider=self.provider, recommendations=recommendations)
            result.evidence = evidence
            self._persist(run_id=run_id, role="evidence_reviewer", kind="evidence_notes", payload=asdict(evidence), ctx=ctx)
            self._complete_role_task(
                run_id,
                "evidence_reviewer",
                summary=f"missing={len(evidence.missing)} contradictory={len(evidence.contradictory)}",
            )
            self._check_cancel()

            # --- quality_reviewer
            if not self.budget.allow_role("quality_reviewer"):
                result.status = "BLOCKED"
                result.reason = self.budget.reason() or "budget_exhausted"
                self._persist(run_id=run_id, role="orchestrator", kind="budget", payload={"reason": result.reason}, ctx=ctx)
                result.planner_payload = self.planner_payloads()
                self._sync_tasks_to_result(result)
                return result
            self.budget.record_role("quality_reviewer")
            self._begin_role_task(run_id, "quality_reviewer")
            quality = run_quality_reviewer(
                ctx,
                provider=self.provider,
                plan=plan,
                recommendations=recommendations,
                evidence=evidence,
                prior={"hypotheses": [asdict(h) for h in hypotheses]},
            )
            result.quality = quality
            self._persist(run_id=run_id, role="quality_reviewer", kind="quality", payload=asdict(quality), ctx=ctx)
            self._complete_role_task(run_id, "quality_reviewer", summary=quality.completeness or "quality")

            result.planner_payload = self.planner_payloads()
            if result.pending_approval:
                result.status = "AWAITING_APPROVAL"
            else:
                result.status = "COMPLETED"
            set_task_status(
                self._run_state,
                role_task_id(run_id, "run"),
                "completed" if result.status == "COMPLETED" else "in_progress",
                summary=result.status,
            )
            self._run_state["status"] = result.status
            self._sync_tasks_to_result(result)
            self.store.save_run(dict(self._run_state))
            return result

        except AasiCancelledError as exc:
            result.status = "CANCELLED"
            result.reason = str(exc)
            self._persist(
                run_id=run_id,
                role="orchestrator",
                kind="cancellation",
                payload={"reason": result.reason},
                ctx=ctx,
            )
            set_task_status(self._run_state, role_task_id(run_id, "run"), "cancelled", summary=result.reason)
            self._run_state["status"] = "CANCELLED"
            self._sync_tasks_to_result(result)
            self.store.save_run(dict(self._run_state))
            return result
        except Exception as exc:  # noqa: BLE001 - record and stop cleanly
            result.status = "FAILED"
            result.reason = f"{type(exc).__name__}: {exc}"
            self._persist(
                run_id=run_id,
                role="orchestrator",
                kind="failure",
                payload={"reason": result.reason},
                ctx=ctx,
            )
            set_task_status(self._run_state, role_task_id(run_id, "run"), "failed", summary=result.reason)
            self._run_state["status"] = "FAILED"
            self._run_state["reason"] = result.reason
            self._sync_tasks_to_result(result)
            self.store.save_run(dict(self._run_state))
            return result


__all__ = [
    "AasiBudgetExhausted",
    "AasiCancelledError",
    "AasiDisabledError",
    "AasiOrchestrator",
    "BudgetGate",
    "DecisionStore",
    "EvidenceGateError",
    "MemoryStore",
    "OrchestratorResult",
    "ROLE_SEQUENCE",
    "SimpleBudget",
    "compute_intrusive",
    "default_context_builder",
    "is_registered_test_id",
    "registered_test_ids",
]
