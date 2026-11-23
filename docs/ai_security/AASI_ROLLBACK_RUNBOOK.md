# AASI rollback runbook (Phase 13)

How to disable or unwind Attestra Agentic Security Intelligence without claiming a prior production deploy. Companion: [`AASI_DEPLOYMENT_RUNBOOK.md`](AASI_DEPLOYMENT_RUNBOOK.md), [`AASI_DOCKER_DEPLOYMENT.md`](AASI_DOCKER_DEPLOYMENT.md).

**Goal:** restore the pre-AASI-enablement posture (flag off, no AI scanner pulls required) while leaving core Attestra VAPT intact.

---

## 1. Immediate disable (preferred first step)

1. Set `ATTESTRA_AASI=off` in the active environment (Compose `.env`, Helm values/secret, systemd, etc.).
2. Restart API processes (and workers if they cache config at startup).
3. Verify `GET /api/aasi/status` reports disabled; mutate routes under `/api/aasi/*` return **404**.
4. Leave `ATTESTRA_AI_NARRATIVES` unchanged unless narratives themselves are the incident — AASI and narratives are related but separately flagged.

With AASI off, recommend-only runs do not proceed; registered AI adapters remain in the registry but will not be required for default web scans.

---

## 2. Stop AI scanner activity

| Action | Detail |
|---|---|
| Cancel in-flight AASI runs | Use API cancel (when enabled) or wait for budget/wall-clock; after disable, new runs refuse |
| Halt worker jobs | Use existing kill-switch / job cancel for scanner runs targeting `garak` / `promptfoo` / `safelabs` / `pyrit` |
| Compose optional pull | Ensure `aasi-scanner-pull` stays commented or removed from active override files |
| Bad digests | Unset `ATTESTRA_IMAGE_GARAK` / `PROMPTFOO` / `SAFELABS` / `PYRIT` or restore last known-good pins; placeholders are refused (safe fail-closed) |

Do **not** run scanner containers `--privileged` during recovery.

---

## 3. Config and image rollback

1. Revert deployment env to the last known-good revision (previous ConfigMap/Secret/`.env`).
2. If a new app image introduced AASI regressions unrelated to the flag, roll the Deployment/Compose tag back to the previous Attestra image **and** keep `ATTESTRA_AASI=off` until investigated.
3. Web scanner digests (`ZAP` / `NUCLEI` / `TESTSSL` / `NAABU`) are independent — do not wipe them when rolling back AI pins.

Validate after rollback:

```bash
python scripts/aasi/validate_aasi_env.py
curl -fsS "$BASE/api/health"
curl -fsS "$BASE/api/aasi/status"
```

---

## 4. Data plane notes

| Store | Rollback behaviour |
|---|---|
| `aasi_runs` / `aasi_decisions` | Left in place (append-oriented). Disabling the flag stops new writes from the API path; do not drop collections in panic unless directed by retention policy |
| `aasi_graph_nodes` / `aasi_graph_edges` | Same — retention / soft `retain_until` as designed; inferred edges must not inflate risk alone |
| Findings from AI importers | Normal finding lifecycle; suppress or status-update via existing product flows — not by deleting Mongo wholesale |
| Draft GitHub PR proposals | Local draft state / audit history; do not force-merge. Close or leave drafts; Issues client is separate |

Migrations `0005_aasi_collections` and `0006_aasi_graph` are additive. Rolling back **code** does not automatically remove collections; treat schema down-migration as a planned DBA task, not an incident toggle.

---

## 5. Licence / supply-chain incident

If an AGPL or prohibited artifact (e.g. Shannon-derived code or an unapproved AI image) entered the environment:

1. Disable AASI and stop pulling that image.
2. Remove the image from node caches / registries used by Attestra.
3. Follow `docs/ai_security/AASI_LICENSE_REVIEW.md` — Shannon AGPL-3.0 remains **no code reuse**.
4. Rebuild app images from a clean tree if source contamination is suspected.

---

## 6. Verification checklist

- [ ] `ATTESTRA_AASI=off`
- [ ] `/api/aasi/status` disabled; mutate routes 404
- [ ] `/api/health` OK
- [ ] Default web scans still dispatch
- [ ] No privileged AI containers running
- [ ] Incident ticket notes digests, flag state, and time window
