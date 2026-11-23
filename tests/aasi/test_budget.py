"""AASI Phase 3 budget limits (iterations, tasks, model calls, tokens, wall clock)."""

from __future__ import annotations

import pytest

from attestra.aasi.budget import Budget, BudgetExceeded
from attestra import config


def test_budget_defaults_match_config():
    b = Budget(track_wall_clock=False)
    assert b.max_iterations == config.AASI_MAX_ITERATIONS
    assert b.max_tasks == config.AASI_MAX_TASKS
    assert b.max_model_calls == config.AASI_MAX_MODEL_CALLS
    assert b.max_tokens == config.AASI_MAX_TOKENS
    assert b.max_wall_clock_s == config.AASI_MAX_WALL_CLOCK_S
    snap = b.remaining()
    assert snap.remaining_iterations == config.AASI_MAX_ITERATIONS
    assert snap.remaining_tokens == config.AASI_MAX_TOKENS


def test_consume_allows_exact_limit_then_check_blocks():
    b = Budget(max_iterations=3, max_tasks=100, max_model_calls=100, max_tokens=1000, max_wall_clock_s=10_000, track_wall_clock=False)
    b.consume(iterations=1)
    b.consume(iterations=2)
    assert b.iterations == 3
    with pytest.raises(BudgetExceeded) as ei:
        b.check()
    assert ei.value.dimension == "iterations"
    with pytest.raises(BudgetExceeded):
        b.consume(iterations=1)


def test_consume_rejects_overshoot_without_partial_apply():
    b = Budget(max_tasks=5, max_iterations=100, max_model_calls=100, max_tokens=1000, max_wall_clock_s=10_000, track_wall_clock=False)
    b.consume(tasks=4)
    with pytest.raises(BudgetExceeded) as ei:
        b.consume(tasks=2)
    assert ei.value.dimension == "tasks"
    assert b.tasks == 4


def test_model_calls_and_tokens_limits():
    b = Budget(
        max_iterations=100,
        max_tasks=100,
        max_model_calls=2,
        max_tokens=50,
        max_wall_clock_s=10_000,
        track_wall_clock=False,
    )
    b.consume(model_calls=1, tokens=40)
    with pytest.raises(BudgetExceeded) as ei:
        b.consume(tokens=20)
    assert ei.value.dimension == "tokens"
    b2 = Budget(
        max_iterations=100,
        max_tasks=100,
        max_model_calls=2,
        max_tokens=500,
        max_wall_clock_s=10_000,
        track_wall_clock=False,
    )
    b2.consume(model_calls=2)
    with pytest.raises(BudgetExceeded):
        b2.consume(model_calls=1)


def test_wall_clock_consume_limit():
    b = Budget(
        max_iterations=100,
        max_tasks=100,
        max_model_calls=100,
        max_tokens=1000,
        max_wall_clock_s=10,
        track_wall_clock=False,
    )
    b.consume(wall_clock_s=10)
    assert b.wall_clock_s == 10
    with pytest.raises(BudgetExceeded) as ei:
        b.consume(wall_clock_s=0.1)
    assert ei.value.dimension == "wall_clock"


def test_remaining_snapshot_decrements():
    b = Budget(
        max_iterations=8,
        max_tasks=32,
        max_model_calls=40,
        max_tokens=500,
        max_wall_clock_s=100,
        track_wall_clock=False,
    )
    b.consume(iterations=2, tasks=3, model_calls=1, tokens=25, wall_clock_s=5)
    snap = b.remaining()
    assert snap.remaining_iterations == 6
    assert snap.remaining_tasks == 29
    assert snap.remaining_model_calls == 39
    assert snap.remaining_tokens == 475
    assert snap.remaining_wall_clock_s == 95
    assert snap.as_dict()["usage"]["iterations"] == 2


def test_consume_rejects_negative_deltas():
    b = Budget(track_wall_clock=False)
    with pytest.raises(ValueError, match="iterations"):
        b.consume(iterations=-1)
    with pytest.raises(ValueError, match="wall_clock"):
        b.consume(wall_clock_s=-0.5)
