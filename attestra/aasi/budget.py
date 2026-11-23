"""AASI run budgets — iterations, tasks, model calls, tokens, wall clock.

Limits default to [[attestra/config.py#AASI_MAX_ITERATIONS]] and sibling
``AASI_MAX_*`` constants. Exhaustion raises [[BudgetExceeded]] so the orchestrator
can mark the run ``BLOCKED``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any


class BudgetExceeded(Exception):
    """Raised when a consume/check would exceed a configured AASI budget dimension."""

    def __init__(self, dimension: str, used: float, limit: float, *, message: str | None = None):
        self.dimension = dimension
        self.used = used
        self.limit = limit
        super().__init__(message or f"AASI budget exceeded: {dimension} used={used} limit={limit}")


@dataclass(frozen=True)
class BudgetSnapshot:
    """Immutable view of usage, limits, and remaining capacity."""

    iterations: int
    tasks: int
    model_calls: int
    tokens: int
    wall_clock_s: float
    max_iterations: int
    max_tasks: int
    max_model_calls: int
    max_tokens: int
    max_wall_clock_s: int
    remaining_iterations: int
    remaining_tasks: int
    remaining_model_calls: int
    remaining_tokens: int
    remaining_wall_clock_s: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "usage": {
                "iterations": self.iterations,
                "tasks": self.tasks,
                "model_calls": self.model_calls,
                "tokens": self.tokens,
                "wall_clock_s": self.wall_clock_s,
            },
            "limits": {
                "iterations": self.max_iterations,
                "tasks": self.max_tasks,
                "model_calls": self.max_model_calls,
                "tokens": self.max_tokens,
                "wall_clock_s": self.max_wall_clock_s,
            },
            "remaining": {
                "iterations": self.remaining_iterations,
                "tasks": self.remaining_tasks,
                "model_calls": self.remaining_model_calls,
                "tokens": self.remaining_tokens,
                "wall_clock_s": self.remaining_wall_clock_s,
            },
        }


def _limits_from_config() -> dict[str, int]:
    from attestra import config

    return {
        "max_iterations": int(config.AASI_MAX_ITERATIONS),
        "max_tasks": int(config.AASI_MAX_TASKS),
        "max_model_calls": int(config.AASI_MAX_MODEL_CALLS),
        "max_tokens": int(config.AASI_MAX_TOKENS),
        "max_wall_clock_s": int(config.AASI_MAX_WALL_CLOCK_S),
    }


class Budget:
    """Mutable usage counters with hard ceilings from config (or explicit overrides)."""

    __slots__ = (
        "iterations",
        "tasks",
        "model_calls",
        "tokens",
        "wall_clock_s",
        "max_iterations",
        "max_tasks",
        "max_model_calls",
        "max_tokens",
        "max_wall_clock_s",
        "_started_at",
        "_track_wall_clock",
    )

    def __init__(
        self,
        *,
        max_iterations: int | None = None,
        max_tasks: int | None = None,
        max_model_calls: int | None = None,
        max_tokens: int | None = None,
        max_wall_clock_s: int | None = None,
        track_wall_clock: bool = True,
    ) -> None:
        defaults = _limits_from_config()
        self.max_iterations = int(defaults["max_iterations"] if max_iterations is None else max_iterations)
        self.max_tasks = int(defaults["max_tasks"] if max_tasks is None else max_tasks)
        self.max_model_calls = int(
            defaults["max_model_calls"] if max_model_calls is None else max_model_calls
        )
        self.max_tokens = int(defaults["max_tokens"] if max_tokens is None else max_tokens)
        self.max_wall_clock_s = int(
            defaults["max_wall_clock_s"] if max_wall_clock_s is None else max_wall_clock_s
        )
        for name, value in (
            ("max_iterations", self.max_iterations),
            ("max_tasks", self.max_tasks),
            ("max_model_calls", self.max_model_calls),
            ("max_tokens", self.max_tokens),
            ("max_wall_clock_s", self.max_wall_clock_s),
        ):
            if value < 0:
                raise ValueError(f"{name} must be >= 0")

        self.iterations = 0
        self.tasks = 0
        self.model_calls = 0
        self.tokens = 0
        self.wall_clock_s = 0.0
        self._track_wall_clock = bool(track_wall_clock)
        self._started_at = time.monotonic()

    def _refresh_wall_clock(self) -> None:
        if self._track_wall_clock:
            self.wall_clock_s = max(self.wall_clock_s, time.monotonic() - self._started_at)

    def check(self) -> None:
        """Raise [[BudgetExceeded]] when usage has already reached a limit (no headroom)."""
        self._refresh_wall_clock()
        checks: tuple[tuple[str, float, float], ...] = (
            ("iterations", float(self.iterations), float(self.max_iterations)),
            ("tasks", float(self.tasks), float(self.max_tasks)),
            ("model_calls", float(self.model_calls), float(self.max_model_calls)),
            ("tokens", float(self.tokens), float(self.max_tokens)),
            ("wall_clock", float(self.wall_clock_s), float(self.max_wall_clock_s)),
        )
        for dimension, used, limit in checks:
            if used >= limit:
                raise BudgetExceeded(dimension, used, limit)

    def consume(
        self,
        *,
        iterations: int = 0,
        tasks: int = 0,
        model_calls: int = 0,
        tokens: int = 0,
        wall_clock_s: float = 0.0,
    ) -> None:
        """Add usage if the projected totals stay within limits (exactly ``max_*`` allowed)."""
        for name, value in (
            ("iterations", iterations),
            ("tasks", tasks),
            ("model_calls", model_calls),
            ("tokens", tokens),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} delta must be a non-negative int")
        if isinstance(wall_clock_s, bool) or not isinstance(wall_clock_s, (int, float)) or wall_clock_s < 0:
            raise ValueError("wall_clock_s delta must be a non-negative number")

        self._refresh_wall_clock()
        projected: tuple[tuple[str, float, float], ...] = (
            ("iterations", float(self.iterations + iterations), float(self.max_iterations)),
            ("tasks", float(self.tasks + tasks), float(self.max_tasks)),
            ("model_calls", float(self.model_calls + model_calls), float(self.max_model_calls)),
            ("tokens", float(self.tokens + tokens), float(self.max_tokens)),
            (
                "wall_clock",
                float(self.wall_clock_s + float(wall_clock_s)),
                float(self.max_wall_clock_s),
            ),
        )
        for dimension, used, limit in projected:
            if used > limit:
                raise BudgetExceeded(dimension, used, limit)

        self.iterations += iterations
        self.tasks += tasks
        self.model_calls += model_calls
        self.tokens += tokens
        if wall_clock_s:
            self.wall_clock_s += float(wall_clock_s)
    def remaining(self) -> BudgetSnapshot:
        """Snapshot of usage, limits, and remaining capacity (wall clock refreshed)."""
        self._refresh_wall_clock()

        def _rem(used: float, limit: float) -> float:
            return max(0.0, float(limit) - float(used))

        return BudgetSnapshot(
            iterations=self.iterations,
            tasks=self.tasks,
            model_calls=self.model_calls,
            tokens=self.tokens,
            wall_clock_s=float(self.wall_clock_s),
            max_iterations=self.max_iterations,
            max_tasks=self.max_tasks,
            max_model_calls=self.max_model_calls,
            max_tokens=self.max_tokens,
            max_wall_clock_s=self.max_wall_clock_s,
            remaining_iterations=int(_rem(self.iterations, self.max_iterations)),
            remaining_tasks=int(_rem(self.tasks, self.max_tasks)),
            remaining_model_calls=int(_rem(self.model_calls, self.max_model_calls)),
            remaining_tokens=int(_rem(self.tokens, self.max_tokens)),
            remaining_wall_clock_s=float(_rem(self.wall_clock_s, self.max_wall_clock_s)),
        )
