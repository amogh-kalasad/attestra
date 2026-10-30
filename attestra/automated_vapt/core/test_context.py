"""Execution context passed between orchestrator steps."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TestContext:
    engagement_id: int
    tenant_id: int
    asset_id: int | None
    target_base_url: str
    test_case_ids: list[str]
    profile: str = "baseline"
    actor: str = "system"
    allow_private: bool = False
    extra: dict[str, Any] = field(default_factory=dict)
