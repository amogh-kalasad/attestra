"""Attestra Agentic Security Intelligence (AASI) — recommend-only orchestration.

Agents recommend registered tests. Attestra authorizes, plans, executes, records
evidence, and validates. Disabled by default via ``ATTESTRA_AASI=off``.
"""

from __future__ import annotations

__all__ = ["enabled"]


def enabled() -> bool:
    """True when the AASI feature flag is on (still subject to tenant AI kill-switch)."""
    from attestra import config

    return bool(getattr(config, "AASI_ENABLED", False))
