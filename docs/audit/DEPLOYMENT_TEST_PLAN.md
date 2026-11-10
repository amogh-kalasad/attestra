# Deployment / Integration Test Plan (Phase 10 gate)

Evidence-based plan for validating one-command Docker deploy (`docker compose up -d --build`) and related acceptance.  
**Status of this document:** inventory and planned gates only. Nothing below is marked passing unless evidence already exists in-repo.

Inspected: `tests/`, `tests/conftest.py`, `pyproject.toml` `[tool.pytest.ini_options]`, `Dockerfile`, `deploy/README.md`, `deploy/helm/attestra/`, `.github/workflows/ci.yml`, `docs/RELEASE.md`, `README.md`, `.env.example`, `lat.md/tests.md` (via `lat search "deployment integration tests docker"`).

---

## 1. Current test inventory relevant to deploy

### 1.1 Pytest configuration

| Item | Evidence | Deploy relevance |
| --- | --- | --- |
| `testpaths = ["tests"]` | `pyproject.toml` | Suite root |
| Marker `integration` | `pyproject.toml` — “live scanner or docker runs; skipped when tools are missing” | Intended for live tools; almost unused |
| Marker `mongo` | Registered in `tests/conftest.py` `pytest_configure` | Throwaway Mongo replica-set DB |
| Shared fixtures | `fresh_db`, `mongo_test_db`, `engagement`, `loaded`, `client`, `auth_headers` | In-process API + Mongo; **not** Compose |

Default Mongo test URI: `ATTESTRA_TEST_MONGODB_URI` or `mongodb://127.0.0.1:27017/?replicaSet=rs0`. Tests skip when the replica set is unreachable.

Rough inventory (`.py` test modules, excluding `*.bak*`): **~129** `test_*.py` files; **18** under `tests/persistence/`; **4** under `tests/jobs/`; **4** under `tests/auth/`; **1** under `tests/e2e/`; **23** under `tests/automated_vapt/`.

`@pytest.mark.integration`: **2** uses (`tests/e2e/test_runner_e2e.py` trivy/nuclei).  
`pytest.mark.mongo` / module `pytestmark`: persistence suite (tenant isolation, reports, web routes, identity/webhooks, exports, audit chain, settings emit, etc.).

### 1.2 Areas with in-process coverage (useful building blocks, not Compose proof)

| Area | Primary evidence | What it proves today | What it does **not** prove |
| --- | --- | --- | --- |
| App / API health shape | `tests/test_api.py::test_health`; health body in `attestra/api.py` (`/api/health` → status, version, pdf_*, persistence, mongo ping) | Health JSON contract under `TestClient` | Container HEALTHCHECK, Compose `depends_on`, port publish |
| API authn (Bearer) | `tests/test_api.py` (401 without token); `tests/auth/*` | Route-level auth with fixtures | Secrets/env wiring in containers |
| API authz / roles | `tests/auth/test_tenant_matrix.py`, `tests/auth/test_api_security.py`, security/scope tests | Cross-tenant 404, role matrix | Network-separated multi-tenant deploy |
| Tenant isolation (Mongo repos) | `tests/persistence/test_mongo_tenant_isolation.py`, `test_mongo_foundation.py` | Repo-level tenant filters | Same checks through published Compose API |
| DB init / schema | `mongo_test_db` → `init_mongo(..., apply_migrations=True)`; foundation tests | Migrations on throwaway DB | `attestra init` as Compose/Helm init container against durable volume |
| Worker / queue | `tests/jobs/test_durable.py`, `test_worker_pool.py`, `test_kill_switch.py` | Enqueue, claim, complete, stale heartbeat recover, concurrency | Separate `attestra worker` process in Compose, InstanceLock across containers |
| Temporal (optional) | `tests/jobs/test_temporal_orchestration.py` | Workflow semantics with test env | Temporal sidecar in Compose (optional product path) |
| Scanner adapters | `tests/runner/*`, `tests/e2e/test_runner_e2e.py` (skip if binary missing) | Argv/adapters; optional live trivy/nuclei | Digest-pinned images in Compose/K8s Jobs; worker→Docker socket |
| Compliance load / reports | `tests/test_compliance_reports.py`, phase3/phase8 report tests | Framework rollups, report generate/sign | Framework YAML present and loadable inside image |
| Evidence / GridFS | `tests/test_phase5_evidence.py`, foundation GridFS tests | Masking, purge, download audit, write-once | Volume/GridFS survival across `compose down` (without `-v`) |
| Observability | `tests/test_observability.py` | `/api/health` + metrics under TestClient | Prometheus scrape of Compose stack |
| Automated VAPT | `tests/automated_vapt/*` | Feature matrix against mocks | Full stack deploy |

### 1.3 Docker / deploy artifacts (present vs missing)

| Artifact | State | Notes |
| --- | --- | --- |
| `Dockerfile` | Present | One image; default `attestra serve`; worker via `attestra worker`. Env defaults Mongo. `HEALTHCHECK` curls `http://127.0.0.1:8000/` (root), **not** `/api/health`. |
| `compose.yaml` / `docker-compose*.yml` | **Absent** | One-command Compose deploy is a target of the master Docker workstream, not current tree state. |
| `.dockerignore` | Present | Build context hygiene |
| `.env.example` | Present | Documents Mongo URI, replica set, test URI, worker concurrency, etc. |
| `deploy/helm/attestra/` | Present | API Deployment with `attestra init` initContainer; TCP readiness/liveness on API port; worker Deployment `attestra worker --poll …` |
| `deploy/k8s/` | Present | Scanner Job + NetworkPolicy templates |
| `deploy/README.md` | Present | `docker build`, `helm lint` / `helm install` — no Compose |

### 1.4 CI (`.github/workflows/ci.yml`) — deploy-relevant findings

Current CI:

- Service: **Postgres 16** (`ATTESTRA_TEST_POSTGRES_URL`)
- Install: `pip install -e ".[dev,postgres]"`
- Step: `db.upgrade('postgresql+psycopg://…')`
- Then: `ruff check .` and `pytest -q`

Runtime product defaults and `tests/conftest.py` are **Mongo-only**. `pyproject.toml` optional-deps as inspected do **not** define a `postgres` extra.  
**Conclusion:** CI is not evidence of Mongo or Docker Compose readiness. Treat CI green (if any) as non-authoritative for Phase 10 until the workflow matches Mongo + optional Compose smoke.

### 1.5 Docs that mention release checks (stale relative to Mongo)

`docs/RELEASE.md` still instructs Postgres URL for pytest and Alembic head `0027_…` on Postgres. Product README / `.env.example` require Mongo replica set. Do not use RELEASE.md Postgres steps as Phase 10 pass criteria without reconciliation.

### 1.6 Lat knowledge

`lat search "deployment integration tests docker"` surfaces `lat.md/tests.md`: suite is pytest for importers/API/compliance; scan/ownership tests explicitly “Nothing here touches the network or starts Docker”. No lat section documents a passing Compose acceptance suite.

---

## 2. Gaps in coverage (TEST-G01…)

| ID | Gap | Risk | Current state | Required for Phase 10 |
| --- | --- | --- | --- | --- |
| **TEST-G01** | No `compose.yaml` / one-command stack under test | Cannot run Phase 10 commands as specified | Compose files absent | Add Compose (owned by Docker architecture work) + lock tests to that file |
| **TEST-G02** | No automated Compose smoke (build/up/ps/health) | Regressions only found manually | No `tests/docker_*` or CI Compose job | Script or pytest+subprocess smoke gated on Docker |
| **TEST-G03** | CI still Postgres-shaped | False confidence; install may fail | `ci.yml` Postgres + `.[dev,postgres]` | CI: Mongo replica-set service (or Testcontainers), drop Postgres path |
| **TEST-G04** | Dockerfile HEALTHCHECK ≠ `/api/health` | Container “healthy” while API/mongo degraded | HEALTHCHECK hits `/` | Align HEALTHCHECK / Compose healthcheck with `/api/health` and assert `mongo.ok` |
| **TEST-G05** | Helm probes are TCP-only | Port open ≠ app+DB ready | `tcpSocket` on API | Prefer HTTP GET `/api/health` (and document Compose equivalent) |
| **TEST-G06** | No containerized worker process test | Queue works in-process only | `tests/jobs/*` use fixtures | Compose: API + worker + Mongo; enqueue via API; assert job completes |
| **TEST-G07** | No deploy-time scanner availability matrix | Worker may start with all tools unavailable | E2E skips if binaries missing; scanners not in app image (by design) | Document which tools are optional; smoke `unavailable_reason` / version flags inside worker or sidecar policy |
| **TEST-G08** | No Compose restart/recovery test | Durable volume + job recover unproven in containers | `recover_stale_heartbeat` unit-tested only | Restart API/worker/mongo; assert data + reclaim semantics |
| **TEST-G09** | No post-`compose down` (without `-v`) data survival test | Operators may confuse `down` vs `down -v` | Undocumented in automated tests | Explicit smoke + docs warning |
| **TEST-G10** | Compliance catalogue not asserted inside image | Missing package-data in image would fail late | Unit tests on host install | After image build: `attestra` CLI or API frameworks/compliance smoke in container |
| **TEST-G11** | Authz/tenant isolation not re-run against published port | Proxy/env misconfig could weaken isolation | Strong unit/API fixture coverage | Thin smoke: two API keys, cross-tenant 404 over `localhost:published` |
| **TEST-G12** | Evidence/report persistence across restart unproven in Compose | GridFS/volume loss | Host/Mongo unit tests | Create evidence/report; restart; re-fetch by id/hash |
| **TEST-G13** | No unauthorized external scan guard in deploy smoke | Accidental internet scans | Gate/scope unit tests exist | Smoke must use fixtures / mock apps / loopback only |
| **TEST-G14** | RELEASE.md / MASTER Phase10 migration docs vs Mongo | Wrong gate commands | Postgres-centric release notes | Align release checklist with Mongo + Compose (separate doc fix) |
| **TEST-G15** | `integration` marker underused | Live Docker/tool runs not systematized | 2 tests | Expand or add `deploy` marker for Compose acceptance |

---

## 3. Phase 10 acceptance test plan (mapped to commands)

**Preconditions (must be true before claiming any step passed):**

1. `compose.yaml` (or agreed Compose file) exists and is the single source of one-command deploy.
2. `.env` derived from `.env.example` with non-default secrets for any shared environment.
3. Docker Engine available; no scans aimed at unauthorized external targets.
4. Record: commit SHA, image digests, Compose project name, timestamp.

Mark each step **PASS / FAIL / BLOCKED** with command output excerpts. Untested = not PASS.

### 3.1 Clean build

```bash
docker compose build --no-cache
```

**Pass:** all services defined in Compose build without error; app image includes package data (templates, compliance YAML).  
**Fail examples:** missing wheel deps, `postgres` extra referenced, copy path errors.  
**Blocked if:** no Compose file (TEST-G01).

### 3.2 Full startup

```bash
docker compose up -d --build
```

**Pass:** every **required** service (at minimum: Mongo replica-set capable, API, worker — exact names from final Compose) reaches running state.  
**Evidence:** `docker compose ps` + logs for API/worker/mongo without crash loops.

### 3.3 Container health

```bash
docker compose ps
docker compose logs --no-color --tail=200
```

**Pass:** no required service `unhealthy` or restarting; API healthcheck uses application readiness (prefer `/api/health`).  
**Assert JSON (from host):**

```bash
curl -fsS http://127.0.0.1:<API_PORT>/api/health
```

Expect: HTTP 200; `status` is `ok` (not `degraded`); `persistence` is `mongo`; `mongo.ok` is true; `mongo.replica_set` set when transactions required; `version` matches image/pyproject.

### 3.4 MongoDB validation

Inside Mongo service or via `mongosh` against Compose network URI:

- `hello` / replica set name present if product requires transactions (`attestra.persistence.mongo.health.require_transactions_capable`).
- Application DB exists after API/`attestra init`.
- Schema migration marker / indexes present (same path as `init_mongo(apply_migrations=True)`).
- Persistent volume still present after restart (see 3.10).

Optional host parallel (not a substitute for Compose):

```bash
pytest -q -m mongo tests/persistence/test_mongo_foundation.py
```

Requires reachable test replica set; proves library init, not Compose wiring.

### 3.5 Worker validation

```bash
docker compose logs worker --no-color --tail=200
# or service name from Compose
```

**Pass:** worker process stays up; connects to same Mongo; claims jobs (log or DB `jobs` documents show `worker_id`).  
**Functional:** create authorized engagement + enqueue a **safe** job (fixture tool / dry adapter / known-local mock — not random internet). Wait until status `done` or documented terminal failure with clear reason.

Reuse semantics already tested in-process (`claim_job`, `recover_interrupted_jobs`, pool concurrency) but **re-verify** across process boundary.

### 3.6 Scanner availability

Safe checks only (version / help / `unavailable_reason`), for each tool the deployment claims to support:

- Confirm policy: scanners **not** bundled in app image (Dockerfile comment / deploy README) → either host Docker socket + digest-pinned `ATTESTRA_IMAGE_*`, or separate jobs.
- For each enabled tool: image digest non-placeholder **or** local binary; otherwise expect refused scan with explicit reason (existing gate/adapter behavior).

```bash
# Example pattern only — exact service/exec names follow final Compose
docker compose exec api python -c "from attestra.runner.scanners import ...; print(...)"
```

Do **not** mark PASS based solely on `tests/e2e/test_runner_e2e.py` skipping on developer laptops.

### 3.7 Compliance loading

```bash
curl -fsS -H "Authorization: Bearer <key>" http://127.0.0.1:<API_PORT>/api/frameworks
# plus engagement compliance for a known framework id, e.g. pci_dss_4
```

**Pass:** catalogue returns expected framework ids shipped in image package-data; compliance endpoint returns control list for fixture engagement (create via API with auth).  
Complementary host suite (not Compose substitute): `tests/test_compliance_reports.py`.

### 3.8 API authn / authz smoke (published port)

1. Unauthenticated write → 401.
2. Lead/admin key can create engagement in window with authorization.
3. Second tenant key cannot read first tenant engagement (404, not 200/403 with body).  
   Mirror `tests/auth/test_tenant_matrix.py` over HTTP to Compose.

### 3.9 End-to-end workflow (controlled)

Where product supports it, against Compose stack only:

1. Create tenant/user/API key (or bootstrap documented in deploy guide).
2. Create engagement + signed authorization + in-scope asset (loopback/mock only).
3. Import fixture findings **or** run one allowed local scanner.
4. List findings; run compliance for one framework.
5. Generate a report; verify hash/verify endpoint if exposed.
6. Attach or import evidence; download and confirm integrity (sha256 / GridFS id).

Do not disable authz to force green.

### 3.10 Restart and recovery

```bash
docker compose restart
# or restart api worker individually; avoid destroying volumes
docker compose ps
curl -fsS http://127.0.0.1:<API_PORT>/api/health
```

**Pass:** prior engagement/findings/evidence/report still readable; worker reconnects; interrupted jobs follow implemented recover semantics (`recover_interrupted_jobs` / stale heartbeat).  
**Fail if:** empty DB after restart without `-v`, or API `mongo.ok` false.

### 3.11 Shutdown

```bash
docker compose down
# Confirm volumes still present (inspect volume list)
docker compose up -d
# Re-check health + prior data
```

Document separately:

```bash
docker compose down -v   # DESTRUCTIVE — data loss; not part of happy-path acceptance
```

**Pass:** graceful stop; data preserved without `-v`; clean restart.

---

## 4. Smoke test ideas that can be automated

Prefer a small `scripts/deploy_smoke.*` or `tests/deploy/` module marked `@pytest.mark.deploy` (new) / reuse `integration`, skipped unless `ATTESTRA_DEPLOY_SMOKE=1` and Docker are present.

| Smoke ID | Idea | Automation sketch | Depends on |
| --- | --- | --- | --- |
| SMK-01 | Compose config validate | `docker compose config -q` | Compose file |
| SMK-02 | Build once | `docker compose build` | SMK-01 |
| SMK-03 | Up + wait healthy | `up -d` + poll `/api/health` until `status==ok` and `mongo.ok` | SMK-02 |
| SMK-04 | Health contract | Assert keys: `version`, `persistence`, `mongo`, `pdf_engine` | SMK-03 |
| SMK-05 | Auth gate | POST `/api/engagements` without Bearer → 401 | SMK-03 |
| SMK-06 | Happy create | Authenticated create engagement + list | Bootstrap secrets |
| SMK-07 | Tenant isolation | Two keys; cross GET → 404 | Seed script |
| SMK-08 | Worker ping | Enqueue noop/fixture job; poll until terminal | Worker service |
| SMK-09 | Frameworks | GET `/api/frameworks` non-empty known ids | Package data in image |
| SMK-10 | Report roundtrip | Generate markdown/json report; optional verify | Findings present |
| SMK-11 | Evidence roundtrip | Upload small blob; download; hash match | Storage backend |
| SMK-12 | Restart survival | `compose restart`; re-run SMK-04/06 ids | Named volumes |
| SMK-13 | Down without `-v` | `down` then `up`; data intact | Volumes |
| SMK-14 | Image healthcheck | `docker inspect` Healthcheck matches `/api/health` policy | Dockerfile fix |
| SMK-15 | CI job | GitHub Actions service: Mongo RS + Docker Compose smoke on PR/main | TEST-G03 |

**Host regression pack** (already largely exists; run when Mongo RS available — still not Compose proof):

```bash
pytest -q
pytest -q -m mongo
pytest -q tests/auth tests/jobs tests/test_api.py tests/test_compliance_reports.py
pytest -q -m integration   # expect skips without tools
```

---

## 5. What must pass before claiming production readiness

Do **not** claim production readiness from unit/API fixture greens alone.

### 5.1 Hard gates (all required)

1. **One-command deploy works on clean machine path:** `docker compose up -d --build` documented and executed successfully (Windows PowerShell and macOS/Linux Bash as product commits to support).
2. **Phase 10 steps 3.1–3.11** recorded PASS with artifacts (logs, health JSON, digests).
3. **Mongo:** replica set (or documented transactional equivalent); `/api/health` reports `mongo.ok: true`; no standalone-only deploy for default product.
4. **API + worker** both required in default Compose profile; worker processes at least one controlled job end-to-end.
5. **Authn/authz + tenant isolation** smoke over the published API (TEST-G11 closed).
6. **Data durability:** restart + `down`/`up` without `-v` preserve engagements, findings, evidence, reports.
7. **Secrets:** no default pepper/session secrets in production values; `.env.example` has placeholders only.
8. **CI matches reality:** lint + pytest against Mongo; optional Compose smoke; Postgres-only workflow retired or quarantined.
9. **Scanner policy explicit:** which tools are required vs optional; refused scans are clear; no unauthorized external targets in automated tests.
10. **Compliance:** frameworks load from image; at least one compliance + report path verified in Compose.
11. **Release checklist** (`docs/RELEASE.md`) updated to Mongo/Compose commands (TEST-G14) before release sign-off.
12. **Security baseline:** existing threat/release expectations (no open critical/high from agreed pentest; license review) remain outside this file but still block “production ready.”

### 5.2 Explicit non-gates (useful but insufficient alone)

- Green `pytest -q` on a developer Mongo without Docker.
- Helm `helm lint` / `helm template` without a live cluster exercise.
- Skipped `@pytest.mark.integration` tests.
- TCP port open without `/api/health` mongo ok.
- Dockerfile build without Compose stack (image-only).

### 5.3 Evidence to archive per release candidate

- Compose file hash + `docker compose images` digests  
- `/api/health` JSON  
- `docker compose ps`  
- Smoke script exit codes  
- Job id that completed in worker  
- Confirmation volumes retained after `down`  
- CI run URL aligned with Mongo/Compose  

---

## 6. Prioritized test sequence

Execute in order; stop on hard failure unless investigating isolation.

| Order | Action | Closes / informs | Blocking? |
| --- | --- | --- | --- |
| 1 | Confirm Compose file exists and `docker compose config` is valid | TEST-G01 | Yes |
| 2 | Align HEALTHCHECK / Compose healthcheck with `/api/health` (+ mongo) | TEST-G04, TEST-G05 | Yes for honest health |
| 3 | `docker compose build --no-cache` | Phase 10.1 | Yes |
| 4 | `docker compose up -d --build` + wait | Phase 10.2–10.3 | Yes |
| 5 | Assert `/api/health` contract | Phase 10.4, Mongo slice | Yes |
| 6 | Mongo replica-set / collections / migrations spot-check | Phase 10.5 | Yes |
| 7 | Auth 401 + tenant isolation smoke on published port | TEST-G11, Phase 10.8 | Yes |
| 8 | Compliance/frameworks smoke in container | TEST-G10, Phase 10.7 | Yes |
| 9 | Worker job E2E (fixture/safe target only) | TEST-G06, Phase 10.6/10.9 | Yes |
| 10 | Evidence + report persistence check | TEST-G12 | Yes |
| 11 | Scanner availability matrix (declared tools only) | TEST-G07, Phase 10.7 | Yes for claimed tools; optional tools must be documented |
| 12 | `compose restart` recovery | Phase 10.10, TEST-G08 | Yes |
| 13 | `compose down` then `up` (no `-v`) | Phase 10.11, TEST-G09 | Yes |
| 14 | Automate SMK-01…SMK-13 under flag | TEST-G02, TEST-G15 | Yes before claiming repeatable gate |
| 15 | Fix CI to Mongo (+ optional deploy smoke) | TEST-G03 | Yes before “CI proves deploy” |
| 16 | Reconcile RELEASE.md / migration docs | TEST-G14 | Yes before production release claim |
| 17 | Full host `pytest -q` / `-m mongo` as regression pack | Breadth | Required regression; not a Compose substitute |
| 18 | Helm path (lint + staging install) if K8s is a supported prod target | Parallel track | Required for K8s prod; not a substitute for Compose gate if Compose is the one-command promise |

---

## 7. Traceability summary

| Mission topic | In-process evidence today | Compose / deploy evidence today |
| --- | --- | --- |
| App startup | TestClient lifespan + CLI patterns | Dockerfile CMD; **no Compose** |
| DB connectivity / init | `mongo_test_db`, foundation tests | Image env defaults; Helm `attestra init`; **unproven via Compose** |
| Worker startup / tasks | `tests/jobs/*` | Helm worker command; **no Compose worker test** |
| Scanner availability | adapter + skip-if-missing e2e | Documented external images; **no deploy matrix** |
| Compliance loading | `test_compliance_reports.py` | Package-data in setuptools; **not image-asserted** |
| API authz | auth + security tests | **Not against published Compose port** |
| Tenant isolation | auth matrix + mongo tenant tests | **Same** |
| Job execution / persistence | durable/pool + mongo suites | **Missing cross-container** |
| Reports / evidence | phase report + evidence tests | **Missing restart survival in Compose** |
| Restart / recovery / E2E deploy | unit recover only | **Not implemented as automated gate** |

**Bottom line:** Attestra has a substantial Mongo-backed pytest suite and a single multi-role `Dockerfile` plus Helm chart, but **does not yet have an in-repo one-command Compose stack or an executed Phase 10 acceptance record**. Until the prioritized sequence above is run and evidenced, production readiness for one-command Docker deploy must remain **unclaimed**.
