"""AASI Phase 3 logical roles — one runtime, five role stages (not five agents).

Each role takes a ContextPacket-like dict plus optional prior outputs and returns
typed dataclasses. When a provider with ``complete_json`` is available it is
used; otherwise deterministic stub heuristics keep tests offline.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass
from typing import Any, Mapping, Protocol, Sequence

# Prefer shared contracts when the parent module lands; keep local shapes compatible.
try:
    from attestra.aasi.contracts import (  # type: ignore[attr-defined]
        AssessmentPlan,
        EvidenceNotes,
        Hypothesis,
        QualityReport,
        TestRecommendation,
    )
except ImportError:  # contracts.py not ready yet — parent will unify

    @dataclass(frozen=True)
    class Hypothesis:
        """Validated hypothesis contract (local Phase 3 shape)."""

        id: str
        run_id: str
        tenant_id: int
        engagement_id: int
        asset_id: int
        statement: str
        basis: str  # observed | inferred
        cites: tuple[str, ...] = ()
        uncertainty: str = ""

    @dataclass(frozen=True)
    class TestRecommendation:
        """Recommend-only test payload; ``test_id`` must be registered."""

        __test__ = False  # not a pytest test class

        id: str
        hypothesis_id: str
        asset_id: int
        test_id: str
        test_type: str
        intrusive: bool
        expected_evidence: tuple[str, ...] = ()
        rationale: str = ""
        needs_approval: bool = False
        status: str = "pending"  # pending | approved | rejected

    @dataclass(frozen=True)
    class AssessmentPlan:
        """Strategist outline of ordered assessment objectives."""

        objectives: tuple[str, ...] = ()
        notes: str = ""
        asset_ids: tuple[int, ...] = ()

    @dataclass(frozen=True)
    class EvidenceNotes:
        """Evidence-reviewer gaps and contradictions (metadata only)."""

        missing: tuple[str, ...] = ()
        contradictory: tuple[str, ...] = ()
        suggested_retests: tuple[str, ...] = ()

    @dataclass(frozen=True)
    class QualityReport:
        """Quality-reviewer completeness / skip / unsupported-claim notes."""

        completeness: str = ""
        skipped: tuple[str, ...] = ()
        unsupported_claims: tuple[str, ...] = ()
        notes: str = ""


ContextPacket = Mapping[str, Any]


class JsonProvider(Protocol):
    """Minimal provider surface used by roles (``complete_json`` preferred)."""

    def complete_json(
        self,
        system: str,
        prompt: str,
        *,
        schema: dict[str, Any] | None = None,
    ) -> dict[str, Any]: ...


# AI adapter capability IDs agents may recommend (plus test_registry cases).
AI_ADAPTER_TEST_IDS: frozenset[str] = frozenset({"garak", "promptfoo", "safelabs", "pyrit"})

_ROLE_SYSTEM = (
    "You are an Attestra AASI role. Return JSON only matching the schema. "
    "Never invent hosts, assets, or unregistered test IDs. Never claim approval."
)


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _ctx_int(ctx: ContextPacket, key: str, default: int = 0) -> int:
    try:
        return int(ctx.get(key, default) or default)
    except (TypeError, ValueError):
        return default


def _authorized_asset_ids(ctx: ContextPacket) -> set[int]:
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


def _coverage_gaps(ctx: ContextPacket) -> list[str]:
    gaps = ctx.get("coverage_gaps") or []
    return [str(g) for g in gaps]


def _call_provider(
    provider: JsonProvider | None,
    *,
    role: str,
    prompt: str,
    schema: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    if provider is None:
        return None
    complete = getattr(provider, "complete_json", None)
    if not callable(complete):
        return None
    try:
        result = complete(_ROLE_SYSTEM + f" Role={role}.", prompt, schema=schema)
    except TypeError:
        result = complete(_ROLE_SYSTEM + f" Role={role}.", prompt)
    return result if isinstance(result, dict) else None


def _to_dict(obj: Any) -> dict[str, Any]:
    if hasattr(obj, "__dataclass_fields__"):
        return asdict(obj)
    if isinstance(obj, Mapping):
        return dict(obj)
    return {"value": obj}


# ------------------------------------------------------------------ Strategist


def run_strategist(
    ctx: ContextPacket,
    *,
    provider: JsonProvider | None = None,
    prior: Mapping[str, Any] | None = None,
) -> AssessmentPlan:
    """Build an ordered assessment-plan outline from engagement context."""
    raw = _call_provider(
        provider,
        role="strategist",
        prompt=(
            f"Context keys: {sorted(ctx.keys())}. "
            f"Prior: {_to_dict(prior) if prior else {}}. "
            "Return JSON: {objectives: string[], notes: string, asset_ids: int[]}."
        ),
        schema={"type": "object", "required": ["objectives"]},
    )
    if raw is not None:
        objectives = tuple(str(o) for o in (raw.get("objectives") or []) if o)
        asset_ids = tuple(int(a) for a in (raw.get("asset_ids") or []) if str(a).isdigit() or isinstance(a, int))
        return AssessmentPlan(
            objectives=objectives,
            notes=str(raw.get("notes") or ""),
            asset_ids=asset_ids,
        )

    # Stub: deterministic outline from authorized assets + coverage gaps.
    assets = list(_authorized_asset_ids(ctx))
    gaps = _coverage_gaps(ctx)
    objectives: list[str] = []
    if ctx.get("objective"):
        objectives.append(str(ctx["objective"]))
    for gap in gaps[:5]:
        objectives.append(f"Close coverage gap: {gap}")
    if not objectives:
        objectives.append("Assess authorized AI assets with registered catalogue tests")
    return AssessmentPlan(
        objectives=tuple(objectives),
        notes="stub-strategist",
        asset_ids=tuple(assets),
    )


# ------------------------------------------------------------------ Hypothesis


def run_hypothesis(
    ctx: ContextPacket,
    *,
    provider: JsonProvider | None = None,
    prior: Mapping[str, Any] | None = None,
    plan: AssessmentPlan | None = None,
) -> list[Hypothesis]:
    """Generate Hypothesis list citing observation IDs when available."""
    raw = _call_provider(
        provider,
        role="hypothesis",
        prompt=(
            f"Plan: {_to_dict(plan) if plan else {}}. "
            f"Observations: {ctx.get('observations') or []}. "
            "Return JSON: {hypotheses: [{statement, basis, asset_id, cites, uncertainty}]}."
        ),
    )
    run_id = str(ctx.get("run_id") or "")
    tenant_id = _ctx_int(ctx, "tenant_id")
    engagement_id = _ctx_int(ctx, "engagement_id")
    allowed = _authorized_asset_ids(ctx)

    if raw is not None:
        out: list[Hypothesis] = []
        for item in raw.get("hypotheses") or []:
            if not isinstance(item, Mapping):
                continue
            try:
                asset_id = int(item.get("asset_id") or 0)
            except (TypeError, ValueError):
                continue
            if allowed and asset_id not in allowed:
                continue
            basis = str(item.get("basis") or "inferred")
            if basis not in ("observed", "inferred"):
                basis = "inferred"
            cites = tuple(str(c) for c in (item.get("cites") or []) if c)
            out.append(
                Hypothesis(
                    id=_new_id("hyp"),
                    run_id=run_id,
                    tenant_id=tenant_id,
                    engagement_id=engagement_id,
                    asset_id=asset_id,
                    statement=str(item.get("statement") or "")[:500],
                    basis=basis,
                    cites=cites,
                    uncertainty=str(item.get("uncertainty") or ""),
                )
            )
        return out

    # Stub: empty hypotheses offline (no invented claims without provider).
    observations = ctx.get("observations") or []
    if not observations:
        return []
    # If observations exist, emit one inferred stub per first observation cite.
    first = observations[0] if isinstance(observations[0], Mapping) else {}
    cite = str(first.get("id") or first.get("observation_id") or "")
    asset_id = 0
    try:
        asset_id = int(first.get("asset_id") or next(iter(allowed), 0))
    except (TypeError, ValueError, StopIteration):
        asset_id = next(iter(allowed), 0)
    if allowed and asset_id not in allowed:
        return []
    return [
        Hypothesis(
            id=_new_id("hyp"),
            run_id=run_id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            asset_id=asset_id,
            statement="Observation suggests further AI-security probing",
            basis="observed" if cite else "inferred",
            cites=(cite,) if cite else (),
            uncertainty="stub-hypothesis",
        )
    ]


# -------------------------------------------------------- AI-security specialist


def run_ai_security(
    ctx: ContextPacket,
    *,
    provider: JsonProvider | None = None,
    prior: Mapping[str, Any] | None = None,
    hypotheses: Sequence[Hypothesis] | None = None,
) -> list[TestRecommendation]:
    """Produce TestRecommendation list for registered tests / AI adapters only."""
    raw = _call_provider(
        provider,
        role="ai_security",
        prompt=(
            f"Hypotheses: {[ _to_dict(h) for h in (hypotheses or []) ]}. "
            f"Gaps: {_coverage_gaps(ctx)}. "
            "Return JSON: {recommendations: [{hypothesis_id, asset_id, test_id, test_type, "
            "expected_evidence, rationale}]}."
        ),
    )
    allowed_assets = _authorized_asset_ids(ctx)
    authorized_types = {str(t) for t in (ctx.get("authorized_test_types") or ["ai_llm", "ai_agent"])}

    def _build(
        *,
        hypothesis_id: str,
        asset_id: int,
        test_id: str,
        test_type: str,
        rationale: str,
        expected_evidence: Sequence[str] = (),
        enforce_asset_scope: bool = False,
    ) -> TestRecommendation | None:
        tid = str(test_id).strip()
        if not tid:
            return None
        # Stubs stay in scope; provider output is left for orchestrator validation.
        if enforce_asset_scope and allowed_assets and asset_id not in allowed_assets:
            return None
        tt = str(test_type or "ai_llm")
        # Intrusive is recomputed by the orchestrator; adapters default to needs_approval.
        needs = tid.lower() in AI_ADAPTER_TEST_IDS or tid.upper() in {"SSRF", "UPLOAD", "XSSSTORE", "T22"}
        return TestRecommendation(
            id=_new_id("rec"),
            hypothesis_id=hypothesis_id or "",
            asset_id=asset_id,
            test_id=tid,
            test_type=tt if tt in authorized_types or not authorized_types else tt,
            intrusive=needs,
            expected_evidence=tuple(str(e) for e in expected_evidence),
            rationale=str(rationale or "")[:500],
            needs_approval=needs,
            status="pending",
        )

    if raw is not None:
        out: list[TestRecommendation] = []
        for item in raw.get("recommendations") or []:
            if not isinstance(item, Mapping):
                continue
            try:
                asset_id = int(item.get("asset_id") or 0)
            except (TypeError, ValueError):
                continue
            rec = _build(
                hypothesis_id=str(item.get("hypothesis_id") or ""),
                asset_id=asset_id,
                test_id=str(item.get("test_id") or ""),
                test_type=str(item.get("test_type") or "ai_llm"),
                rationale=str(item.get("rationale") or ""),
                expected_evidence=item.get("expected_evidence") or (),
            )
            if rec is not None:
                out.append(rec)
        return out

    # Stub: catalogue-gap recommendations for AI adapters when gaps exist.
    gaps = [g.lower() for g in _coverage_gaps(ctx)]
    if not gaps:
        return []
    hyps = list(hypotheses or [])
    default_asset = next(iter(allowed_assets), 0)
    hyp_id = hyps[0].id if hyps else ""
    asset_id = hyps[0].asset_id if hyps else default_asset
    out: list[TestRecommendation] = []
    preferred = ("garak", "promptfoo", "safelabs")
    for name in preferred:
        if not any(name in g or "llm" in g or "agent" in g or "ai" in g for g in gaps):
            continue
        rec = _build(
            hypothesis_id=hyp_id,
            asset_id=asset_id,
            test_id=name,
            test_type="ai_llm" if name != "safelabs" else "ai_agent",
            rationale=f"stub catalogue-gap recommendation for {name}",
            expected_evidence=(f"{name}-report",),
            enforce_asset_scope=True,
        )
        if rec is not None:
            out.append(rec)
        if len(out) >= 2:
            break
    if not out:
        rec = _build(
            hypothesis_id=hyp_id,
            asset_id=asset_id,
            test_id="garak",
            test_type="ai_llm",
            rationale="stub default AI probe for coverage gap",
            enforce_asset_scope=True,
        )
        if rec is not None:
            out.append(rec)
    return out


# ----------------------------------------------------------- Evidence reviewer


def run_evidence_reviewer(
    ctx: ContextPacket,
    *,
    provider: JsonProvider | None = None,
    prior: Mapping[str, Any] | None = None,
    recommendations: Sequence[TestRecommendation] | None = None,
) -> EvidenceNotes:
    """Note missing or contradictory evidence from finding/evidence metadata."""
    raw = _call_provider(
        provider,
        role="evidence_reviewer",
        prompt=(
            f"Findings meta: {ctx.get('findings_meta') or []}. "
            f"Evidence meta: {ctx.get('evidence_meta') or []}. "
            f"Recommendations: {[ _to_dict(r) for r in (recommendations or []) ]}. "
            "Return JSON: {missing: string[], contradictory: string[], suggested_retests: string[]}."
        ),
    )
    if raw is not None:
        return EvidenceNotes(
            missing=tuple(str(x) for x in (raw.get("missing") or []) if x),
            contradictory=tuple(str(x) for x in (raw.get("contradictory") or []) if x),
            suggested_retests=tuple(str(x) for x in (raw.get("suggested_retests") or []) if x),
        )

    missing: list[str] = []
    contradictory: list[str] = []
    retests: list[str] = []
    known_evidence: set[str] = set()
    for ev in ctx.get("evidence_meta") or []:
        if not isinstance(ev, Mapping):
            continue
        eid = str(ev.get("id") or ev.get("evidence_id") or "").strip()
        if eid:
            known_evidence.add(eid)
        if ev.get("contradicts"):
            contradictory.append(str(ev.get("id") or ev.get("contradicts")))
        if ev.get("deleted") or ev.get("is_deleted") or ev.get("expired") or ev.get("is_expired"):
            missing.append(f"evidence:{eid or '?'}:unavailable")
    for finding in ctx.get("findings_meta") or []:
        if not isinstance(finding, Mapping):
            continue
        fid = str(finding.get("id") or finding.get("finding_id") or "?")
        cites = finding.get("evidence_ids") or finding.get("cites") or []
        if not cites:
            missing.append(f"finding:{fid}:no_evidence")
        else:
            for cite in cites:
                cid = str(cite).strip()
                if cid and known_evidence and cid not in known_evidence:
                    missing.append(f"finding:{fid}:unknown_cite:{cid}")
                    retests.append(fid)
        status = str(finding.get("validation") or finding.get("status") or "").lower()
        if status in ("needs_manual_validation", "potential") and cites:
            retests.append(fid)
    if not missing and not contradictory and not (ctx.get("findings_meta") or []):
        missing.append("no_findings_meta")
    # Deduplicate while preserving order.
    retests = list(dict.fromkeys(retests))
    return EvidenceNotes(
        missing=tuple(missing),
        contradictory=tuple(contradictory),
        suggested_retests=tuple(retests),
    )


# ------------------------------------------------------------ Quality reviewer


def run_quality_reviewer(
    ctx: ContextPacket,
    *,
    provider: JsonProvider | None = None,
    prior: Mapping[str, Any] | None = None,
    plan: AssessmentPlan | None = None,
    recommendations: Sequence[TestRecommendation] | None = None,
    evidence: EvidenceNotes | None = None,
) -> QualityReport:
    """Assess completeness, skipped work, and unsupported claims."""
    raw = _call_provider(
        provider,
        role="quality_reviewer",
        prompt=(
            f"Plan: {_to_dict(plan) if plan else {}}. "
            f"Skips: {ctx.get('plan_skips') or []}. "
            f"Recommendations: {len(recommendations or [])}. "
            f"Evidence: {_to_dict(evidence) if evidence else {}}. "
            "Return JSON: {completeness: string, skipped: string[], "
            "unsupported_claims: string[], notes: string}."
        ),
    )
    if raw is not None:
        return QualityReport(
            completeness=str(raw.get("completeness") or ""),
            skipped=tuple(str(x) for x in (raw.get("skipped") or []) if x),
            unsupported_claims=tuple(str(x) for x in (raw.get("unsupported_claims") or []) if x),
            notes=str(raw.get("notes") or ""),
        )

    skipped = tuple(str(s) for s in (ctx.get("plan_skips") or []))
    unsupported: list[str] = []
    for hyp in (prior or {}).get("hypotheses") or []:
        if isinstance(hyp, Mapping) and not (hyp.get("cites") or hyp.get("evidence_ids") or []):
            unsupported.append(str(hyp.get("id") or "hypothesis_without_cites"))
    for claim in (prior or {}).get("conclusions") or []:
        if not isinstance(claim, Mapping):
            continue
        cites = claim.get("evidence_citations") or claim.get("cites") or []
        if not cites:
            unsupported.append(str(claim.get("id") or "conclusion_without_cites"))
    missing_n = len(evidence.missing) if evidence else 0
    rec_n = len(recommendations or [])
    if rec_n == 0 and _coverage_gaps(ctx):
        completeness = "incomplete: gaps remain without recommendations"
    elif missing_n:
        completeness = f"partial: {missing_n} evidence gaps"
    else:
        completeness = "adequate for recommend-only handoff"
    notes = "stub-quality"
    if unsupported:
        notes = f"stub-quality; unsupported_claims={len(unsupported)}"
    return QualityReport(
        completeness=completeness,
        skipped=skipped,
        unsupported_claims=tuple(unsupported),
        notes=notes,
    )


ROLE_SEQUENCE: tuple[str, ...] = (
    "strategist",
    "hypothesis",
    "ai_security",
    "evidence_reviewer",
    "quality_reviewer",
)

__all__ = [
    "AI_ADAPTER_TEST_IDS",
    "AssessmentPlan",
    "ContextPacket",
    "EvidenceNotes",
    "Hypothesis",
    "JsonProvider",
    "QualityReport",
    "ROLE_SEQUENCE",
    "TestRecommendation",
    "run_ai_security",
    "run_evidence_reviewer",
    "run_hypothesis",
    "run_quality_reviewer",
    "run_strategist",
]
