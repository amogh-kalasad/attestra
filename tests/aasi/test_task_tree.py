"""Offline unit tests for AASI Phase 4 task-tree helpers."""

from __future__ import annotations

import pytest

# @lat: [[tests#AASI Phase 4 task tree]]

from attestra.aasi.orchestrator import AasiOrchestrator, MemoryStore, SimpleBudget
from attestra.aasi.task_tree import (
    add_task,
    dependencies_satisfied,
    ensure_task_tree,
    get_children,
    get_task,
    new_task,
    propagate_completion,
    set_task_status,
)


# @lat: [[tests#AASI Phase 4 task tree#Ensure and add tasks]]
def test_ensure_and_add_tasks():
    run: dict = {"id": "run-1"}
    tasks = ensure_task_tree(run)
    assert tasks == []
    add_task(run, new_task("t-root", status="pending", summary="root"))
    add_task(run, new_task("t-child", parent_id="t-root", dependencies=["t-dep"], role="hypothesis"))
    with pytest.raises(ValueError, match="duplicate"):
        add_task(run, new_task("t-root"))
    assert len(run["tasks"]) == 2
    assert get_task(run, "t-child")["parent_id"] == "t-root"
    assert get_children(run, "t-root")[0]["id"] == "t-child"


# @lat: [[tests#AASI Phase 4 task tree#Dependencies and retries]]
def test_dependencies_and_retries():
    run: dict = {"id": "run-1", "tasks": []}
    add_task(run, new_task("dep", status="pending"))
    add_task(run, new_task("work", dependencies=["dep"], status="pending"))
    assert dependencies_satisfied(run, "work") is False
    set_task_status(run, "dep", "completed", summary="done")
    assert dependencies_satisfied(run, "work") is True
    set_task_status(run, "work", "failed", increment_retry=True)
    assert get_task(run, "work")["retry_count"] == 1
    set_task_status(run, "work", "in_progress", result_refs=["ev-1"], increment_retry=True)
    work = get_task(run, "work")
    assert work["retry_count"] == 2
    assert work["result_refs"] == ["ev-1"]


# @lat: [[tests#AASI Phase 4 task tree#Completion summary propagation]]
def test_completion_summary_propagation():
    run: dict = {"id": "run-1", "tasks": []}
    add_task(run, new_task("root", status="in_progress", summary="run"))
    add_task(run, new_task("a", parent_id="root", status="in_progress"))
    add_task(run, new_task("b", parent_id="root", status="in_progress"))
    set_task_status(run, "a", "completed", summary="strategist ok")
    changed = propagate_completion(run, "a")
    assert changed == []  # sibling still running
    assert get_task(run, "root")["children_complete"] is False

    set_task_status(run, "b", "completed", summary="hypothesis ok")
    changed = propagate_completion(run, "b")
    assert "root" in changed
    root = get_task(run, "root")
    assert root["status"] == "completed"
    assert root["children_complete"] is True
    assert "strategist ok" in root["summary"]
    assert "hypothesis ok" in root["summary"]


# @lat: [[tests#AASI Phase 4 task tree#Failed child rolls up]]
def test_failed_child_rolls_up():
    run: dict = {"id": "run-1", "tasks": []}
    add_task(run, new_task("root", status="in_progress"))
    add_task(run, new_task("a", parent_id="root", status="completed", summary="ok"))
    add_task(run, new_task("b", parent_id="root", status="failed", summary="boom"))
    changed = propagate_completion(run, "b")
    assert "root" in changed
    assert get_task(run, "root")["status"] == "failed"


# @lat: [[tests#AASI Phase 4 task tree#Orchestrator attaches tasks]]
def test_orchestrator_attaches_tasks(monkeypatch):
    monkeypatch.setattr("attestra.aasi.enabled", lambda: True)
    store = MemoryStore()
    orch = AasiOrchestrator(
        provider=None,
        store=store,
        budget=SimpleBudget(max_roles=5),
        require_enabled=True,
    )
    seed = {
        "tenant_id": 1,
        "engagement_id": 99,
        "authorized_assets": [{"id": 7, "kind": "ai_app"}],
        "authorized_test_types": ["ai_llm", "ai_agent"],
        "coverage_gaps": ["garak"],
        "observations": [],
        "findings_meta": [],
        "plan_skips": [],
    }
    result = orch.run(seed)
    assert result.tasks
    ids = {t["id"] for t in result.tasks}
    assert any(i.endswith("-run") for i in ids)
    assert any("strategist" in i for i in ids)
    assert any("ai_security" in i for i in ids)
    saved = store.runs[-1]
    assert isinstance(saved.get("tasks"), list)
    assert saved["tasks"]
