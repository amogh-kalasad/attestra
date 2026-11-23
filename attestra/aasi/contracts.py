"""Typed AASI decision contracts (hypothesis, recommendation, conclusion).

Model output is untrusted: every field is validated in code. Intrusive status is
never taken from the model — it is computed from the registered-test catalogue
([[attestra/automated_vapt/core/intrusive_policy.py#INTRUSIVE_TEST_IDS]]).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any, Literal

BASIS_VALUES: frozenset[str] = frozenset({"observed", "inferred"})

CONCLUSION_TYPES: frozenset[str] = frozenset(
    {
        "observed_fact",
        "hypothesis",
        "scanner_result",
        "correlated",
        "potential_finding",
        "manually_reviewed",
        "validated",
        "rejected",
        "inconclusive",
    }
)

# Conclusion kinds that claim a finding-like outcome and must cite evidence.
CLAIMING_FINDING_TYPES: frozenset[str] = frozenset(
    {
        "scanner_result",
        "potential_finding",
        "manually_reviewed",
        "validated",
    }
)


class ContractError(ValueError):
    """Raised when an AASI contract fails structural or catalogue validation."""


def _require_nonempty_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{name} must be a non-empty string")
    return value.strip()


def _require_positive_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ContractError(f"{name} must be a positive int")
    return value


def _as_str_tuple(value: Any, name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        raise ContractError(f"{name} must be a sequence of strings, not a bare string")
    if not isinstance(value, Sequence):
        raise ContractError(f"{name} must be a sequence of strings")
    out: list[str] = []
    for i, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise ContractError(f"{name}[{i}] must be a non-empty string")
        out.append(item.strip())
    return tuple(out)


def _normalize_uncertainty(value: Any) -> float | str:
    if isinstance(value, bool):
        raise ContractError("uncertainty must be a float in [0, 1] or a non-empty label")
    if isinstance(value, (int, float)):
        u = float(value)
        if u < 0.0 or u > 1.0:
            raise ContractError("uncertainty float must be in [0, 1]")
        return u
    if isinstance(value, str) and value.strip():
        return value.strip()
    raise ContractError("uncertainty must be a float in [0, 1] or a non-empty label")


def _normalize_confidence(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractError("confidence must be a float in [0, 1] or None")
    c = float(value)
    if c < 0.0 or c > 1.0:
        raise ContractError("confidence must be in [0, 1]")
    return c


def _require_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ContractError(f"{name} must be a bool")
    return value

def compute_intrusive(registered_test_id: str) -> bool:
    """True when ``registered_test_id`` is in the intrusive catalogue (never from the model)."""
    from attestra.automated_vapt.core.intrusive_policy import INTRUSIVE_TEST_IDS

    tid = (registered_test_id or "").strip().upper()
    return tid in INTRUSIVE_TEST_IDS


def is_registered_test(test_id: str) -> bool:
    """True when ``test_id`` is a catalogue case or a registered scanner adapter name."""
    from attestra.automated_vapt.core.test_registry import get_test_case

    tid = (test_id or "").strip()
    if not tid:
        return False
    if get_test_case(tid) is not None:
        return True
    try:
        from attestra.runner.scanners.registry import get_adapter

        get_adapter(tid)
        return True
    except KeyError:
        return False


def is_authorized_test_type(test_type: str) -> bool:
    """True when ``test_type`` is a key of [[attestra/models.py#TEST_TYPES]]."""
    from attestra.models import TEST_TYPES

    return (test_type or "").strip() in TEST_TYPES


def _unknown_ids(cited: Iterable[str], known: set[str]) -> list[str]:
    return sorted({c for c in cited if c not in known})


@dataclass(frozen=True)
class Hypothesis:
    """Structured hypothesis produced by an AASI role (not a finding)."""

    id: str
    run_id: str
    tenant_id: int
    engagement_id: int
    asset_id: int
    statement: str
    basis: Literal["observed", "inferred"]
    evidence_ids: tuple[str, ...] = ()
    #: Alias list accepted on input; normalized into ``evidence_ids`` by ``from_mapping``.
    observation_ids: tuple[str, ...] = field(default=(), compare=False)
    uncertainty: float | str = "unknown"

    def validate(self) -> Hypothesis:
        """Validate structural rules; return ``self`` (frozen) for chaining."""
        _require_nonempty_str(self.id, "id")
        _require_nonempty_str(self.run_id, "run_id")
        _require_positive_int(self.tenant_id, "tenant_id")
        _require_positive_int(self.engagement_id, "engagement_id")
        _require_positive_int(self.asset_id, "asset_id")
        _require_nonempty_str(self.statement, "statement")
        if self.basis not in BASIS_VALUES:
            raise ContractError(f"basis must be one of {sorted(BASIS_VALUES)}")
        _as_str_tuple(self.evidence_ids, "evidence_ids")
        _normalize_uncertainty(self.uncertainty)
        return self

    def validate_against_known(self, evidence_ids: set[str]) -> None:
        """Reject citations that are not in the known evidence/observation ID set."""
        unknown = _unknown_ids(self.evidence_ids, evidence_ids)
        if unknown:
            raise ContractError(f"unknown evidence_ids: {unknown}")

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> Hypothesis:
        """Build from untrusted mapping; merges ``observation_ids`` into ``evidence_ids``."""
        if not isinstance(data, Mapping):
            raise ContractError("hypothesis payload must be a mapping")
        ev = list(_as_str_tuple(data.get("evidence_ids"), "evidence_ids"))
        obs = list(_as_str_tuple(data.get("observation_ids"), "observation_ids"))
        merged = tuple(dict.fromkeys([*ev, *obs]))
        hyp = cls(
            id=_require_nonempty_str(data.get("id"), "id"),
            run_id=_require_nonempty_str(data.get("run_id"), "run_id"),
            tenant_id=_require_positive_int(data.get("tenant_id"), "tenant_id"),
            engagement_id=_require_positive_int(data.get("engagement_id"), "engagement_id"),
            asset_id=_require_positive_int(data.get("asset_id"), "asset_id"),
            statement=_require_nonempty_str(data.get("statement"), "statement"),
            basis=_require_nonempty_str(data.get("basis"), "basis"),  # type: ignore[arg-type]
            evidence_ids=merged,
            observation_ids=tuple(obs),
            uncertainty=_normalize_uncertainty(data.get("uncertainty", "unknown")),
        )
        return hyp.validate()


@dataclass(frozen=True)
class TestRecommendation:
    """Recommend-only test proposal; execution still requires Attestra authorization."""

    __test__ = False  # not a pytest test class

    id: str
    hypothesis_id: str
    asset_id: int
    registered_test_id: str
    authorized_test_type: str
    expected_evidence: tuple[str, ...]
    rationale: str
    approval_required: bool
    #: Computed from the intrusive catalogue only; never trusted from model output.
    intrusive: bool | None = None

    def validate(self, *, against_catalogue: bool = False) -> TestRecommendation:
        """Validate structure; optionally check registries and compute ``intrusive``.

        When ``against_catalogue`` is true, ``registered_test_id`` must resolve via
        [[attestra/aasi/contracts.py#is_registered_test]] and ``authorized_test_type``
        via [[attestra/aasi/contracts.py#is_authorized_test_type]]. ``intrusive`` is
        always recomputed from the catalogue (model-supplied values are ignored).
        """
        _require_nonempty_str(self.id, "id")
        _require_nonempty_str(self.hypothesis_id, "hypothesis_id")
        _require_positive_int(self.asset_id, "asset_id")
        tid = _require_nonempty_str(self.registered_test_id, "registered_test_id")
        ttype = _require_nonempty_str(self.authorized_test_type, "authorized_test_type")
        _as_str_tuple(self.expected_evidence, "expected_evidence")
        _require_nonempty_str(self.rationale, "rationale")
        if not isinstance(self.approval_required, bool):
            raise ContractError("approval_required must be a bool")

        if against_catalogue:
            if not is_registered_test(tid):
                raise ContractError(f"unregistered test id: {tid!r}")
            if not is_authorized_test_type(ttype):
                raise ContractError(f"unauthorized test type: {ttype!r}")

        computed = compute_intrusive(tid)
        if self.intrusive is not None and self.intrusive is not computed:
            # Model claimed a different intrusive flag — replace with catalogue truth.
            pass
        return replace(self, registered_test_id=tid, authorized_test_type=ttype, intrusive=computed)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any], *, against_catalogue: bool = False) -> TestRecommendation:
        """Build from untrusted mapping; strips any model-supplied ``intrusive`` value."""
        if not isinstance(data, Mapping):
            raise ContractError("recommendation payload must be a mapping")
        # Explicitly ignore data.get("intrusive") — catalogue computes it.
        rec = cls(
            id=_require_nonempty_str(data.get("id"), "id"),
            hypothesis_id=_require_nonempty_str(data.get("hypothesis_id"), "hypothesis_id"),
            asset_id=_require_positive_int(data.get("asset_id"), "asset_id"),
            registered_test_id=_require_nonempty_str(data.get("registered_test_id"), "registered_test_id"),
            authorized_test_type=_require_nonempty_str(
                data.get("authorized_test_type"), "authorized_test_type"
            ),
            expected_evidence=_as_str_tuple(data.get("expected_evidence"), "expected_evidence"),
            rationale=_require_nonempty_str(data.get("rationale"), "rationale"),
            approval_required=_require_bool(
                data["approval_required"] if "approval_required" in data else False,
                "approval_required",
            ),
            intrusive=None,
        )
        return rec.validate(against_catalogue=against_catalogue)

@dataclass(frozen=True)
class Conclusion:
    """Structured conclusion; finding-like kinds require non-empty evidence citations."""

    id: str
    run_id: str
    subject_ids: tuple[str, ...]
    conclusion_type: str
    evidence_citations: tuple[str, ...]
    recommended_action: str
    confidence: float | None
    confidence_basis: str

    def validate(self) -> Conclusion:
        """Validate structural rules including non-empty cites for claiming findings."""
        _require_nonempty_str(self.id, "id")
        _require_nonempty_str(self.run_id, "run_id")
        subjects = _as_str_tuple(self.subject_ids, "subject_ids")
        if not subjects:
            raise ContractError("subject_ids must be non-empty")
        ctype = _require_nonempty_str(self.conclusion_type, "conclusion_type")
        if ctype not in CONCLUSION_TYPES:
            raise ContractError(f"conclusion_type must be one of {sorted(CONCLUSION_TYPES)}")
        cites = _as_str_tuple(self.evidence_citations, "evidence_citations")
        if ctype in CLAIMING_FINDING_TYPES and not cites:
            raise ContractError(
                f"evidence_citations must be non-empty for claiming conclusion_type {ctype!r}"
            )
        _require_nonempty_str(self.recommended_action, "recommended_action")
        _normalize_confidence(self.confidence)
        _require_nonempty_str(self.confidence_basis, "confidence_basis")
        return self

    def validate_against_known(self, evidence_ids: set[str]) -> None:
        """Reject evidence citation IDs that are not in the known set."""
        unknown = _unknown_ids(self.evidence_citations, evidence_ids)
        if unknown:
            raise ContractError(f"unknown evidence citations: {unknown}")

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> Conclusion:
        """Build from untrusted mapping and run structural validation."""
        if not isinstance(data, Mapping):
            raise ContractError("conclusion payload must be a mapping")
        conc = cls(
            id=_require_nonempty_str(data.get("id"), "id"),
            run_id=_require_nonempty_str(data.get("run_id"), "run_id"),
            subject_ids=_as_str_tuple(data.get("subject_ids"), "subject_ids"),
            conclusion_type=_require_nonempty_str(data.get("conclusion_type"), "conclusion_type"),
            evidence_citations=_as_str_tuple(data.get("evidence_citations"), "evidence_citations"),
            recommended_action=_require_nonempty_str(
                data.get("recommended_action"), "recommended_action"
            ),
            confidence=_normalize_confidence(data.get("confidence")),
            confidence_basis=_require_nonempty_str(data.get("confidence_basis"), "confidence_basis"),
        )
        return conc.validate()
