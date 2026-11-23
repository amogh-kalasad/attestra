# AASI production readiness report (Phase 13)

Branch: `attestra-asi-bundle`. Date: **2026-11-23**. Based on tree inspection only.

## Classification

| Field | Value |
|---|---|
| **Classification** | **READY FOR STAGING** |
| Also acceptable framing | READY FOR PRODUCTION REVIEW (code + docs reviewable; ops gates incomplete) |
| **Not** | PRODUCTION READY |
| Production deploy claimed? | **No** — none performed or verified in this session |

Reasons it is **not** production-ready:

1. AI scanner digests are still placeholders (`REPLACE_AFTER_INSPECT` / all-zero defaults) and are refused at runtime.
2. No staging deploy was verified against this branch in this session.
3. No full e2e against a live vulnerable AI lab was run in this session.
4. Local core `.venv` floors may lag `pyproject.toml` (pre-existing; see Phase 10 inventory).

---

## Readiness gates

| Gate | Status | Evidence / gap |
|---|---|---|
| Feature flag default off | **Pass** | `ATTESTRA_AASI=off` in `.env.example` / `.env.production.example`; `config.AASI_ENABLED` |
| Recommend-only agents (no scanner invoke from LLM) | **Pass** (design) | Orchestrator emits planner payloads; adapters are separate runner path |
| Human approval default on | **Pass** | `ATTESTRA_AASI_REQUIRE_APPROVAL=on` |
| Placeholder digests refused | **Pass** | `image_is_placeholder`; `validate_aasi_env.py` |
| Real AI digests pinned in ops env | **Fail** | Only commented stubs in `docker/scanner-digests.env` |
| Compose default stack unchanged | **Pass** | `aasi-scanner-pull` commented; web `scanner-pull` only |
| Mongo migrations present | **Pass** | `0005_aasi_collections`, `0006_aasi_graph` |
| Unit tests for core paths | **Pass** (offline) | `tests/aasi/`, importers, adapters, reporting, graph, GitHub PR |
| Live AI lab e2e | **Fail / not done** | Not executed this session |
| Shannon AGPL reuse | **Pass** (policy) | Prohibited in licence review / blueprint |
| AI frameworks out of core pyproject | **Pass** | Inventory Phase 10; no garak/promptfoo/safelabs/pyrit in core deps |
| Production secrets / APP_ENV | **Operator** | Templates only; real secrets never committed |
| Staging smoke (`/api/health`, `/api/aasi/status`) | **Not verified** | Commands documented; no deploy run here |

---

## Production-configured column (honesty)

For the master matrix in [`AASI_IMPLEMENTATION_STATUS.md`](AASI_IMPLEMENTATION_STATUS.md), **Production configured** means: real digests, secrets, and flags set in a deployed staging/production environment. On this branch as inspected, that column is **No** for AI scanners and AASI enablement. Templates and refuse-placeholder behaviour are ready for operators to configure staging.

---

## Recommended next gates (external / ops)

1. Pin real `@sha256:` digests for Garak, Promptfoo, SafeLabs, and PyRIT after `docker inspect`; put them in the **deployment** env (not necessarily the git tree).
2. Align `.env.example` / `.env.production.example` with a commented `ATTESTRA_IMAGE_PYRIT` line (present in digests file, missing from env examples).
3. Refresh core venv: `pip install -e ".[dev]"` so installed versions meet `pyproject.toml` floors.
4. Deploy to **staging** with `ATTESTRA_AASI=off`, run `python scripts/aasi/validate_aasi_env.py`, then enable on a lab tenant only.
5. Run a controlled e2e against an authorized vulnerable AI lab; record evidence separately.
6. Only then promote classification toward production after security/ops sign-off.

---

## Related runbooks

- Deploy: [`AASI_DEPLOYMENT_RUNBOOK.md`](AASI_DEPLOYMENT_RUNBOOK.md)
- Rollback: [`AASI_ROLLBACK_RUNBOOK.md`](AASI_ROLLBACK_RUNBOOK.md)
- Docker detail: [`AASI_DOCKER_DEPLOYMENT.md`](AASI_DOCKER_DEPLOYMENT.md)
