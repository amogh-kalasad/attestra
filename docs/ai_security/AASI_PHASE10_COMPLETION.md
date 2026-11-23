# AASI Phase 10 completion report

Branch: `attestra-asi-bundle`. Date: 2026-11-23.

## Summary

Dependency-management documentation only. Recorded that **`pyproject.toml` is authoritative**, `requirements.txt` is a sync mirror, the Attestra core Python environment must stay minimal, and AI frameworks (Garak, Promptfoo, SafeLabs, PyRIT) run in **isolated digest-pinned images** — not as core `pyproject` / uncommented `requirements.txt` dependencies. No packages were added to core dependencies. No commit or push in this phase.

## Deliverables

| File | Purpose |
|---|---|
| [`AASI_DEPENDENCY_AND_LICENSE_INVENTORY.md`](./AASI_DEPENDENCY_AND_LICENSE_INVENTORY.md) | Authoritative-source rule, core floors, exact `.venv` versions for core packages (2026-11-23), AI isolation / licence pointers |
| [`AASI_WORKER_IMAGES.md`](./AASI_WORKER_IMAGES.md) | Short isolated-worker dependency policy |

## Verified checks

- `pyproject.toml` / `requirements.txt`: no `garak`, `pyrit`, `promptfoo`, or `safelabs` package entries.
- Local `.venv` `pip list` / `pip show` used for **exact installed versions** of core packages only; no invented “latest” claims.
- Several installed versions remain below declared floors (pre-existing; documented; refresh with `pip install -e ".[dev]"` when aligning).

## Explicitly not done (by design)

- Editing `pyproject.toml` or `requirements.txt` floors.
- Adding PyRIT / Garak / Promptfoo (or SafeLabs) to core dependencies.
- Building or pinning production AI worker digests (Phase 9 / adapter digests).
- Git commit or push.

## Next

Phase 11 — README / install docs (when scheduled), keeping the isolated-image rule visible to operators.
