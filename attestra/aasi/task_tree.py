"""AASI Phase 4 task-tree helpers for run-state dicts.

Parent/child task ids, status, dependencies, result refs, retry count, and
completion-summary propagation. Attach to an AASI run structure — this is
**not** an independent graph execution engine.
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from typing import Any

TASK_STATUSES: frozenset[str] = frozenset(
    {
        "pending",
        "ready",
        "in_progress",
        "completed",
        "failed",
        "blocked",
        "cancelled",
        "skipped",
    }
)

# Statuses that count as finished for parent rollup.
_TERMINAL: frozenset[str] = frozenset(
    {"completed", "failed", "cancelled", "skipped"}
)
_SUCCESS: frozenset[str] = frozenset({"completed", "skipped"})


def ensure_task_tree(run: MutableMapping[str, Any]) -> list[dict[str, Any]]:
    """Ensure ``run["tasks"]`` exists as a list; return it."""
    tasks = run.get("tasks")
    if not isinstance(tasks, list):
        tasks = []
        run["tasks"] = tasks
    return tasks  # type: ignore[return-value]


def new_task(
    task_id: str,
    *,
    parent_id: str | None = None,
    status: str = "pending",
    dependencies: Sequence[str] = (),
    result_refs: Sequence[str] = (),
    retry_count: int = 0,
    summary: str = "",
    role: str = "",
    kind: str = "",
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a task dict suitable for ``run["tasks"]``."""
    tid = (task_id or "").strip()
    if not tid:
        raise ValueError("task_id must be a non-empty string")
    st = (status or "pending").strip().lower()
    if st not in TASK_STATUSES:
        raise ValueError(f"unknown task status: {st!r}")
    if retry_count < 0:
        raise ValueError("retry_count must be >= 0")

    task: dict[str, Any] = {
        "id": tid,
        "parent_id": (parent_id.strip() if isinstance(parent_id, str) and parent_id.strip() else None),
        "status": st,
        "dependencies": [str(d).strip() for d in dependencies if str(d).strip()],
        "result_refs": [str(r).strip() for r in result_refs if str(r).strip()],
        "retry_count": int(retry_count),
        "summary": str(summary or ""),
        "role": str(role or ""),
        "kind": str(kind or ""),
        "children_complete": False,
    }
    if extra:
        for k, v in extra.items():
            if k not in task:
                task[k] = v
    return task


def add_task(run: MutableMapping[str, Any], task: Mapping[str, Any]) -> dict[str, Any]:
    """Append a task (copy) to the run task tree; reject duplicate ids."""
    tasks = ensure_task_tree(run)
    tid = str(task.get("id") or "").strip()
    if not tid:
        raise ValueError("task must have a non-empty id")
    if any(str(t.get("id")) == tid for t in tasks if isinstance(t, Mapping)):
        raise ValueError(f"duplicate task id: {tid!r}")
    stored = dict(task)
    stored["id"] = tid
    tasks.append(stored)
    return stored


def get_task(run: Mapping[str, Any], task_id: str) -> dict[str, Any] | None:
    """Return the task dict with ``task_id``, or None."""
    tid = (task_id or "").strip()
    for task in run.get("tasks") or []:
        if isinstance(task, Mapping) and str(task.get("id")) == tid:
            return dict(task) if not isinstance(task, dict) else task  # type: ignore[return-value]
    return None


def get_children(run: Mapping[str, Any], parent_id: str) -> list[dict[str, Any]]:
    """Return direct children of ``parent_id``."""
    pid = (parent_id or "").strip()
    out: list[dict[str, Any]] = []
    for task in run.get("tasks") or []:
        if isinstance(task, Mapping) and str(task.get("parent_id") or "") == pid:
            out.append(task if isinstance(task, dict) else dict(task))
    return out


def dependencies_satisfied(run: Mapping[str, Any], task_id: str) -> bool:
    """True when every dependency of ``task_id`` is in a success terminal state."""
    task = get_task(run, task_id)
    if task is None:
        return False
    deps = task.get("dependencies") or []
    for dep_id in deps:
        dep = get_task(run, str(dep_id))
        if dep is None:
            return False
        if str(dep.get("status") or "") not in _SUCCESS:
            return False
    return True


def set_task_status(
    run: MutableMapping[str, Any],
    task_id: str,
    status: str,
    *,
    summary: str | None = None,
    result_refs: Sequence[str] | None = None,
    increment_retry: bool = False,
) -> dict[str, Any] | None:
    """Update status (and optional summary / result_refs / retry) on a task in place."""
    st = (status or "").strip().lower()
    if st not in TASK_STATUSES:
        raise ValueError(f"unknown task status: {st!r}")
    tasks = ensure_task_tree(run)
    tid = (task_id or "").strip()
    for task in tasks:
        if not isinstance(task, dict):
            continue
        if str(task.get("id")) != tid:
            continue
        task["status"] = st
        if summary is not None:
            task["summary"] = str(summary)
        if result_refs is not None:
            task["result_refs"] = [str(r).strip() for r in result_refs if str(r).strip()]
        if increment_retry:
            task["retry_count"] = int(task.get("retry_count") or 0) + 1
        return task
    return None


def _child_rollup_status(children: Sequence[Mapping[str, Any]]) -> str | None:
    """Derive a parent status from children, or None if not all terminal."""
    if not children:
        return "completed"
    statuses = [str(c.get("status") or "") for c in children]
    if not all(s in _TERMINAL for s in statuses):
        return None
    if any(s == "failed" for s in statuses):
        return "failed"
    if any(s == "cancelled" for s in statuses):
        return "cancelled"
    if all(s in _SUCCESS for s in statuses):
        return "completed"
    return "failed"


def propagate_completion(
    run: MutableMapping[str, Any],
    task_id: str,
) -> list[str]:
    """Propagate completion upward from ``task_id``.

    When all children of a parent are terminal, set the parent's status from
    the rollup, mark ``children_complete``, and concatenate child summaries.
    Walks ancestors. Returns ids whose status changed.
    """
    changed: list[str] = []
    current = get_task(run, task_id)
    if current is None:
        return changed

    parent_id = current.get("parent_id")
    while parent_id:
        children = get_children(run, str(parent_id))
        rollup = _child_rollup_status(children)
        parent = None
        for t in ensure_task_tree(run):
            if isinstance(t, dict) and str(t.get("id")) == str(parent_id):
                parent = t
                break
        if parent is None:
            break
        if rollup is None:
            parent["children_complete"] = False
            break
        parent["children_complete"] = True
        summaries = [str(c.get("summary") or "").strip() for c in children]
        summaries = [s for s in summaries if s]
        if summaries:
            joined = "; ".join(summaries)
            existing = str(parent.get("summary") or "").strip()
            parent["summary"] = f"{existing} | {joined}".strip(" |") if existing else joined
        if parent.get("status") != rollup:
            parent["status"] = rollup
            changed.append(str(parent_id))
        parent_id = parent.get("parent_id")
    return changed


def role_task_id(run_id: str, role: str) -> str:
    """Stable task id for a role stage within a run."""
    return f"task-{run_id}-{role}"


__all__ = [
    "TASK_STATUSES",
    "add_task",
    "dependencies_satisfied",
    "ensure_task_tree",
    "get_children",
    "get_task",
    "new_task",
    "propagate_completion",
    "role_task_id",
    "set_task_status",
]
