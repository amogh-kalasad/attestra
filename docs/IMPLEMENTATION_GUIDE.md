# Attestra – Step-by-Step Implementation Guide (Phase 0 → Phase 8)

This guide turns `PHASES.md` and `ROADMAP.md` into concrete, ordered steps. It is based on the real code in `E:\attestra` (v0.1.0). Every step is a **new implementation inside the attestra package** – no code is copied from other projects.

## How to use this guide

- Do the phases **in order**. Do the steps inside a phase in order unless a step says it can run in parallel.
- Each step has: **What**, **Files**, **Key code / schema**, **Commands**, **Tests**, **Done when**.
- `VERIFY` marks a command or path I could not confirm from the project. Check it before relying on it.
- Effort figures are estimates.
- **Commits:** you commit yourself, in GitHub Desktop, at each **Commit point**. Work in `E:\attestra`, then copy the changed files into `E:\GitHub\attestra` (or switch to working directly in the clone), review the **Changes** tab, write a summary, click **Commit to main**, then **Push origin**.
- **Keep everything on E:**: the virtual env is `E:\attestra\.venv`; temp, caches and scanner output go under `E:\attestra\data` or `E:\attestra\.cache`. Never commit `.venv`, `data/`, `*.db`, or `.cache`.
- **No microservices rewrite early.** Phases 0–5 stay inside the single `attestra` Python package (FastAPI + SQLAlchemy + Jinja). Infrastructure changes (Postgres default, Temporal, OPA, Vault, Kubernetes) wait for Phase 6.
- **No LLM / paid AI** anywhere unless the architecture owner requires it. It is an optional, last item in Phase 8.

### Standard commands (PowerShell, from `E:\attestra`)

```powershell
cd E:\attestra
.\.venv\Scripts\Activate.ps1                       # turn on the venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"   # install / refresh deps
.\.venv\Scripts\python.exe -m pytest -q            # run all tests (34 today)
.\.venv\Scripts\python.exe -m pytest tests\test_scope.py -q   # one file
attestra demo                                      # load the synthetic engagement
attestra serve --host 127.0.0.1 --port 8000        # UI http://127.0.0.1:8000, API docs /docs
attestra verify-audit                              # check the hash chain
```
Optional: set `$env:TEMP="E:\attestra\.cache\tmp"` and `$env:ATTESTRA_DATA_DIR="E:\attestra\data"` in the session so temp files stay on E:.

### Where things are today (map of the real code)

| Area | File(s) | Notes |
|---|---|---|
| DB engine | `attestra/db.py` | `init()` calls `create_all` + `_add_missing_columns()` (ad-hoc migration) |
| Settings | `attestra/config.py` | `DATA_DIR`, `DATABASE_URL`, `SLA_DAYS`, `ensure_dirs()` |
| Models | `attestra/models.py` | `Tenant, Engagement, Authorization, Asset, ImportRun, Finding, Evidence, ControlAssessment, Report, AuditEvent` |
| Business logic | `attestra/services.py` | `create_engagement, add_authorization, add_asset, import_results, enrich, transition, add_evidence, confirm_control, _store` |
| Audit | `attestra/audit.py` | `record()`, `verify()` hash chain |
| Scoring | `attestra/scoring.py` | `risk_score()`, `sla_due()` |
| Importers | `attestra/importers/{base,zap,nuclei,trivy,sarif}.py` | parse files only – nothing runs scanners |
| Compliance | `attestra/compliance/engine.py`, `compliance/data/{controls,cwe_map}.yaml` | `load_library()`, `evaluate()` |
| Reports | `attestra/reports/render.py`, `signing.py`, `templates/*.j2` | HTML only, HMAC signing, two-person approve |
| API | `attestra/api.py` | identity = `X-Attestra-Actor` header (`actor()` dependency) |
| Web UI | `attestra/web/ui.py`, `web/templates/*.html` | Jinja |
| CLI | `attestra/cli.py` | `attestra` entry point |
| Tests | `tests/conftest.py` (`fresh_db`, `engagement`, `loaded` fixtures), `test_api, test_compliance_reports, test_importers, test_scope, test_services` | in `E:\attestra` only, removed from the GitHub copy |

---

## Phase 0 – Foundations and a safe baseline (2–3 days)

**Prerequisites:** venv works and `.\.venv\Scripts\python.exe -m pytest -q` shows 34 passed. GitHub Desktop has `E:\GitHub\attestra` cloned.

### Step 0.1 – Record the baseline
- **What:** run the suite and save the result so later phases can compare.
- **Commands:** `.\.venv\Scripts\python.exe -m pytest -q -W default > E:\attestra\.cache\baseline.txt` (create `.cache` first).
- **Done when:** 34 passed, and the warnings list (e.g. the Starlette TestClient deprecation) is written down.

### Step 0.2 – Add Alembic and an initial migration
- **What:** replace `_add_missing_columns()` with real migrations.
- **Files:** `pyproject.toml` (add `"alembic>=1.13"` to `dependencies`), new `alembic.ini`, new `migrations/env.py`, `migrations/script.py.mako`, `migrations/versions/0001_baseline.py`; modify `attestra/db.py`.
- **Key code:** `migrations/env.py` imports `attestra.db.Base` and `attestra.models` and uses `target_metadata = Base.metadata`, URL from `attestra.config.DATABASE_URL`. In `db.py` add:
  ```python
  def upgrade(url: str | None = None) -> None:
      from alembic import command
      from alembic.config import Config
      cfg = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
      cfg.set_main_option("sqlalchemy.url", url or config.DATABASE_URL)
      command.upgrade(cfg, "head")
  ```
  Keep `create_all` in `init()` for tests (fast), but mark `_add_missing_columns` deprecated; production start-up (`attestra init`, `attestra serve`) calls `upgrade()`.
- **Commands:**
  ```powershell
  .\.venv\Scripts\python.exe -m pip install -e ".[dev]"
  .\.venv\Scripts\alembic.exe init migrations            # VERIFY (then edit env.py as above)
  .\.venv\Scripts\alembic.exe revision --autogenerate -m "baseline"   # VERIFY
  .\.venv\Scripts\alembic.exe upgrade head               # VERIFY
  ```
- **Tests:** new `tests/test_migrations.py`: upgrade an empty SQLite file in `tmp_path` to head, compare table names with `Base.metadata.tables`, then `downgrade base`.
- **Done when:** a fresh DB built only with `alembic upgrade head` passes the full suite.

### Step 0.3 – Add ruff and CI
- **What:** lint + test on every push.
- **Files:** `pyproject.toml` (add `"ruff>=0.5"` to `dev`, add `[tool.ruff]` with `line-length = 120`, `target-version = "py311"`); new `.github/workflows/ci.yml`.
- **Key code (ci.yml):** `runs-on: ubuntu-latest`, `actions/setup-python` with `3.11`, `pip install -e ".[dev]"`, `ruff check .`, `pytest -q`.
- **Commands:** `.\.venv\Scripts\python.exe -m ruff check .` then `.\.venv\Scripts\python.exe -m ruff check . --fix` for safe fixes.
- **Done when:** ruff clean locally; CI is green after your push.

### Step 0.4 – Put the tests back into the repo
- **What:** CI needs `tests/`. Copy `E:\attestra\tests\` to `E:\GitHub\attestra\tests\` (exclude `__pycache__`, `.DS_Store`). Also delete stray `.DS_Store` files from `attestra/` and add `.DS_Store` to `.gitignore`.
- **Files:** `tests/**`, `.gitignore`.
- **Done when:** GitHub Desktop Changes tab shows `tests/` (14 files) and no `.DS_Store`.

### Step 0.5 – Fix the TestClient deprecation warning
- **What:** update how `tests/test_api.py` builds the client (use `with TestClient(app) as client:` / the transport the installed Starlette version expects), or pin `httpx` to the version Starlette supports.
- **Files:** `tests/test_api.py`, possibly `pyproject.toml`.
- **Commands:** `.\.venv\Scripts\python.exe -m pytest -q -W error::DeprecationWarning`.
- **Done when:** that command passes.

### Step 0.6 – SECURITY.md and threat-model note
- **Files:** new `SECURITY.md`, new `docs/THREAT_MODEL.md`.
- **Content:** reporting contact; assets to protect (authorization docs, signing key in `data/keys`, audit chain, evidence); main threats (out-of-scope scanning, SSRF, tampering with audit/evidence, identity spoofing via `X-Attestra-Actor` until Phase 2, cross-tenant leaks).
- **Done when:** both files exist and are linked from `README.md`.

**Phase 0 checklist**
- [ ] Baseline recorded (34 passed)
- [ ] `alembic upgrade head` builds a fresh DB; migration test passes
- [ ] ruff clean, CI green
- [ ] `tests/` in the GitHub copy
- [ ] No deprecation warnings
- [ ] SECURITY.md + THREAT_MODEL.md

**Commit point:** copy changes into `E:\GitHub\attestra`, commit in GitHub Desktop as `Phase 0: migrations, CI, tests, security docs`, push, and check the CI run on GitHub.

---

## Phase 1 – Runner plane: Attestra runs scanners safely (3–4 weeks)

**Prerequisites:** Phase 0 committed. Docker Desktop installed if you will run containerised scanners (VERIFY). Never point a scan at an external target during development – use loopback fixtures only.

New package layout created in this phase:
```
attestra/runner/__init__.py
attestra/runner/authorization.py   (new: scope model + target checks)
attestra/runner/dns_pin.py         (new: resolve once, pin IP)
attestra/runner/http_safe.py       (new: pinned HTTP client)
attestra/runner/gate.py            (new: window / intrusive / rate limit)
attestra/runner/ownership.py       (new: DNS TXT / well-known token)
attestra/runner/scanners/{base,trivy,semgrep,nuclei,nuclei_policy,zap,registry}.py
attestra/jobs/{__init__,durable,queue,instance_lock}.py
tests/security/...
```

### Step 1.1 – Build the scope authorization module
- **What:** create `attestra/runner/authorization.py` with an `AuthorizedScope` built from Attestra's own `Authorization`, `Asset` and `Engagement` records (no scope files).
- **Key code:**
  ```python
  @dataclass(frozen=True)
  class AuthorizedScope:
      name: str
      allowed_hosts: frozenset[str]
      allowed_urls: tuple[str, ...]
      allowed_paths: tuple[str, ...]
      allowed_images: tuple[str, ...]
      allow_private: bool = False

  def scope_for_engagement(s: Session, engagement_id: int, on: date | None = None) -> AuthorizedScope:
      eng = services.get_engagement(s, engagement_id)
      envs = services.authorized_environments(eng, on)   # existing helper
      if not envs: raise AuthorizationError("no valid authorization")
      assets = [a for a in eng.assets if a.environment in envs]
      ...  # split assets by kind (url/web_app/api -> urls+hosts, repo/path -> paths, image -> images)
  ```
  Add `authorize_target(scope, target, kind)`, `validate_url_target()`, `validate_path_target()`, `validate_image_target()`, `validate_resolved_ips()`, `assert_safe_cli_arg()` (rejects `; | & ` $( \n`), and `AuthorizationError`.
- **Tests:** new `tests/security/test_authorization.py` using the `engagement` fixture in `tests/conftest.py`: off-list host, wrong scheme/port, path outside the allowed prefix, unsafe chars, expired authorization → all raise.
- **Done when:** every target outside the engagement's assets raises `AuthorizationError`.

### Step 1.2 – Exact image matching (no prefix bug)
- **What:** image scope must be an exact match unless the entry ends in `*`; a naive `startswith` check would let `nginx` allow `nginx-evil`.
- **File:** `attestra/runner/authorization.py`.
- **Key code:**
  ```python
  def _image_allowed(image: str, allowed: str) -> bool:
      if allowed.endswith("*"):
          return image.startswith(allowed[:-1])
      return image == allowed
  ```
- **Tests:** `nginx:1.25` allowed only by `nginx:1.25` or `nginx:*`; `nginx-evil` rejected by `nginx`.
- **Done when:** test passes.

### Step 1.3 – SSRF block list
- **What:** write `is_blocked_ip` / `is_private_ip` / `validate_resolved_ips`: deny unless `ip.is_global` (unless the asset explicitly allows private ranges), unwrap `ip.ipv4_mapped`, and add `100.64.0.0/10`, `0.0.0.0/8`, `fd00:ec2::254/128`, `169.254.0.0/16` to `BLOCKED_CIDRS`.
- **File:** `attestra/runner/authorization.py`.
- **Tests:** parametrized `tests/security/test_ssrf_policy.py` with `::ffff:127.0.0.1`, `100.64.1.1`, `0.0.0.1`, `169.254.169.254`, `fd00:ec2::254` → blocked; a public IP → allowed.
- **Done when:** all cases pass.

### Step 1.4 – DNS pinning and the safe HTTP client
- **What:** new `attestra/runner/dns_pin.py`: resolve the host once, validate every IP with `validate_resolved_ips()`, choose one stable IP, and return a `PinnedTarget(host, ip, port, scheme)` with `connect_url`, `host_header`, `sni_hostname`. New `attestra/runner/http_safe.py`: `safe_request()` / `safe_get()` that connect only to the pinned IP, re-authorize **every redirect** (`resolve_redirect_url()` + `authorize_target()`), cap redirects and body size, and write an `audit.record(...)` entry for each refusal.
- **Tests:** new `tests/security/test_dns_pinning.py` and `test_redirect_reauth.py`. Use a loopback `http.server` fixture; a redirect to an out-of-scope host must be refused.
- **Done when:** a DNS-rebind test and a 302-to-out-of-scope test make zero requests to the forbidden address.

### Step 1.5 – Scanner base and adapters
- **What:** new `attestra/runner/scanners/base.py` with `run_process(argv, timeout, cancel)` (no shell, own process group, kill tree on timeout/cancel), `ProcessResult`, `ScannerResult`, abstract `ScannerAdapter` (`available()`, `version()`, `scan()`), plus `which()` / `docker_available()`. Then one adapter each: `trivy.py`, `semgrep.py`, `nuclei.py` (+ `nuclei_policy.py` deciding which templates are allowed), `zap.py`, and `registry.py` (name → adapter). Adapters must **write raw output to a file** under `config.DATA_DIR / "raw"` and then call the existing `services.import_results(..., tool=..., data=raw_bytes)` so parsing stays in `attestra/importers/*`. Semgrep output goes through the `sarif` importer.
- **Signature:** `scan(pin: PinnedTarget | str, *, out_dir: Path, cancel: threading.Event) -> ScannerResult`.
- **Config:** add `RAW_DIR`, `SCANNER_TIMEOUT_S`, and `"raw"` to `ensure_dirs()` in `attestra/config.py`.
- **Tests:** `tests/runner/test_adapters_argv.py` – build argv for each adapter with a fake pin and assert no shell metacharacters and the correct flags; mark real runs `@pytest.mark.integration` and skip if the binary/docker is missing (`which()` / `docker_available()`).
- **Done when:** argv tests pass; with Trivy installed, `trivy fs` on `tests/fixtures` produces findings in the DB.

### Step 1.6 – Confine ZAP egress
- **What:** ZAP must only reach the pinned IP. In `attestra/runner/scanners/zap.py`: always pass `--add-host <host>:<pinned_ip>`; run in a dedicated docker network (or behind an egress proxy) that only allows that IP:port; after the run, read every site URL from the ZAP report and **quarantine** the run (status `quarantined`, audit entry) if any is out of scope.
- **Tests:** new `tests/security/test_zap_pin_egress.py`: argv always contains the pin; a fake report with an extra site triggers quarantine.
- **Done when:** both tests pass.

### Step 1.7 – Pin scanner images by digest
- **What:** in `attestra/config.py` add `SCANNER_IMAGES = {"zap": "ghcr.io/zaproxy/zaproxy@sha256:...", "trivy": "...@sha256:...", ...}` (fill real digests – VERIFY with `docker pull` then `docker inspect --format "{{index .RepoDigests 0}}"`). Adapters refuse an image reference without `@sha256:`.
- **Tests:** an adapter given `zaproxy:latest` raises.
- **Done when:** every run records tool name, version and digest (Step 1.8).

### Step 1.8 – `ScanRun` model (extend `ImportRun`)
- **What:** keep `ImportRun` for manual uploads; add `ScanRun` for runs Attestra dispatches, and link imports to it.
- **Files:** `attestra/models.py`, new migration `migrations/versions/0002_scan_runs.py`.
- **Schema:**
  ```python
  class ScanRun(Base):
      __tablename__ = "scan_runs"
      id: Mapped[int] = mapped_column(primary_key=True)
      engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
      asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"))
      tool: Mapped[str] = mapped_column(String(50))
      tool_version: Mapped[str] = mapped_column(String(100), default="")
      image_digest: Mapped[str] = mapped_column(String(100), default="")
      profile: Mapped[str] = mapped_column(String(50), default="baseline")   # baseline | active
      status: Mapped[str] = mapped_column(String(20), default="queued")     # queued|running|done|failed|cancelled|quarantined|refused
      requested_by: Mapped[str] = mapped_column(String(200))
      started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
      ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
      raw_artifact_uri: Mapped[str] = mapped_column(String(500), default="")
      raw_sha256: Mapped[str] = mapped_column(String(64), default="")
      import_run_id: Mapped[int | None] = mapped_column(ForeignKey("import_runs.id"))
  ```
  Hash the **full** raw file (stream in chunks), never a truncated copy.
- **Tests:** `tests/runner/test_scan_run.py` – sha256 of a >1 MB raw file equals `hashlib.sha256(file).hexdigest()`.
- **Done when:** migration applies; test passes.

### Step 1.9 – Dispatch gate: window, intrusive flag, rate limit
- **What:** one function every scan passes **at dispatch and again at resume**.
- **File:** new `attestra/runner/gate.py`.
- **Key code:**
  ```python
  def check(s, engagement_id: int, asset_id: int, *, tool: str, profile: str, actor: str, now=None) -> PinnedTarget | str:
      eng = services.get_engagement(s, engagement_id)
      # 1 valid authorization covering the asset environment
      # 2 eng.window_start <= today <= eng.window_end
      # 3 profile == "active" or nuclei active templates -> asset.intrusive_allowed
      # 4 per-asset rate limit (max runs / hour, config.SCAN_RATE_PER_ASSET)
      # 5 authorize_target(...) + pin
      # on any failure: audit.record(s, actor, "scan.refused", "asset", asset_id, reason=...) and raise GateError
  ```
- **Tests:** `tests/runner/test_gate.py` – outside window, expired authorization, off-list target, intrusive without flag, rate exceeded → refused with one audit entry each. Add `test_nuclei_active_gate`: active templates refused unless `intrusive_allowed`.
- **Done when:** refusals are 100% and audited.

### Step 1.10 – ScopeRule deny rules
- **What:** explicit deny/allow patterns per engagement (e.g. deny `/admin/*`, deny `payments.example.com`).
- **Files:** `attestra/models.py` (`ScopeRule`: `id, engagement_id, action allow|deny, kind host|url|path|image|cidr, pattern, note, created_by`), migration `0003_scope_rules.py`, `services.add_scope_rule()/remove_scope_rule()` with audit, `runner/authorization.py` applies deny **before** allow.
- **Tests:** deny beats allow; removing a rule is audited.
- **Done when:** tests pass.

### Step 1.11 – Durable jobs
- **What:** new `attestra/jobs/` (`durable.py`, `queue.py`, `instance_lock.py`) on a SQLAlchemy `Job` model (`id, scan_run_id, status, attempts, worker_id, heartbeat_at, cancel_requested, error`) in `models.py` + migration `0004_jobs.py`. Functions: `enqueue`, `claim_job` (atomic UPDATE ... WHERE status='queued'), `mark_job_running`, `complete_job`, `fail_job` (retry with backoff up to N), `request_cancel`, `recover_interrupted_jobs` (stale heartbeat → requeue), `resume_queued_jobs`; `instance_lock.py` stops two workers claiming the same job. On resume, call `gate.check()` again.
- **CLI:** add `attestra worker` to `attestra/cli.py` (loop: claim → run adapter → import → complete).
- **Tests:** `tests/jobs/test_durable.py` – enqueue/claim/complete; a job left `running` with a stale heartbeat is recovered; resume outside the window is refused.
- **Done when:** tests pass; killing the worker and restarting resumes queued jobs.

### Step 1.12 – Kill switch
- **What:** engagement-level halt. Sets `Engagement.status = "halted"`, sets `cancel_requested` on all its jobs, kills the scanner **process group** (`_kill_process_tree`) within 5 s, writes `engagement.halt` audit entry. Gate refuses new scans while halted; resuming needs a lead.
- **Files:** `attestra/jobs/durable.py`, `attestra/runner/scanners/base.py` (poll the cancel event every 0.5 s in `run_process`), `attestra/services.py` (`halt_engagement`, `resume_engagement`), `attestra/api.py`.
- **Tests:** `tests/jobs/test_kill_switch.py` – start a dummy long process (`python -c "import time; time.sleep(60)"`), halt, assert it exits < 5 s.
- **Done when:** test passes on Windows and in CI (Linux).

### Step 1.13 – API and UI for scans
- **Files:** `attestra/api.py`, `attestra/web/ui.py`, `attestra/web/templates/engagement.html`.
- **Routes:** `POST /engagements/{eid}/scans` (body: `asset_id, tool, profile`), `GET /engagements/{eid}/scans`, `GET /scans/{sid}`, `POST /engagements/{eid}/halt`, `POST /engagements/{eid}/resume`.
- **Tests:** extend `tests/test_api.py`: refused scan returns 403 with reason; halt returns 200 and stops jobs.
- **Done when:** a scan can be started and halted from the UI.

### Step 1.14 – Target ownership verification
- **What:** before the **first** scan of an asset, prove control: DNS TXT `attestra-verify=<token>` or `https://host/.well-known/attestra-verify.txt` containing the token (fetched with `http_safe.safe_get`).
- **Files:** new `attestra/runner/ownership.py` (`issue_token(asset)`, `verify(asset) -> bool`), `Asset` gets `ownership_token`, `ownership_verified_at` (migration `0005_asset_ownership.py`), gate checks it.
- **Tests:** mocked DNS resolver and loopback HTTP server.
- **Done when:** an unverified asset is refused; a verified one passes.

### Step 1.15 – End-to-end loopback test
- **What:** `tests/e2e/test_runner_e2e.py` (`@pytest.mark.integration`): start a tiny local web app on 127.0.0.1 (asset with `allow_private`), run Trivy fs + Semgrep on `tests/fixtures`, Nuclei and ZAP baseline against loopback, check findings appear.
- **Commands:** `.\.venv\Scripts\python.exe -m pytest -m integration -q` (register the marker in `pyproject.toml` `[tool.pytest.ini_options] markers`).
- **Done when:** passes locally where tools exist; skipped cleanly in CI otherwise.

**Phase 1 checklist**
- [ ] Scope gate built; exact image match and SSRF list in place
- [ ] DNS pin + safe HTTP; rebind and redirect tests green
- [ ] Adapters write raw output; importers parse it
- [ ] ZAP egress confined; images pinned by digest
- [ ] `ScanRun` with full-output sha256
- [ ] Window / intrusive / rate limit at dispatch and resume; all refusals audited
- [ ] ScopeRule deny rules
- [ ] Durable jobs + `attestra worker`
- [ ] Kill switch < 5 s
- [ ] Scan API/UI; ownership verification
- [ ] Loopback E2E

**Commit point:** suggested commits in GitHub Desktop: (a) `runner: scope gate, ssrf, dns pin`, (b) `runner: scanners, ScanRun, gate`, (c) `jobs: durable queue, kill switch, API`. Push after each and check CI.

---

## Phase 2 – Identity, roles and tenant isolation (2–3 weeks)

**Prerequisites:** Phase 0 done (can overlap end of Phase 1).

### Step 2.1 – User and API-key models
- **Files:** new `attestra/auth/__init__.py`, `attestra/auth/keys.py` (`hash_api_key` – sha256 with a server pepper, `generate_api_key` – `secrets.token_urlsafe(32)`, `create_api_key`, `revoke_api_key`, `authenticate_api_key`, `Principal` dataclass), `attestra/models.py`, migration `0006_users.py`.
- **Schema:** `User(id, tenant_id nullable for staff, username unique, display_name, password_hash, role, active, created_at)`, `ApiKey(id, user_id, key_hash, prefix, created_at, revoked_at, last_used_at)`. 
- **Passwords:** `hashlib.scrypt` from the standard library (no new dependency), or `argon2-cffi` (VERIFY choice).
- **CLI:** `attestra user add <name> --role lead`, `attestra key create <user>` in `cli.py`.
- **Tests:** `tests/auth/test_keys.py` – hash never equals raw key; revoked key fails.

### Step 2.2 – Roles from the spec
- **What:** define roles `admin, lead, tester, reviewer, client_viewer, auditor`.
- **File:** `attestra/auth/roles.py` with a permission map, e.g. `{"scan.start": {"lead","tester"}, "report.approve": {"reviewer","lead"}, "report.sign": {"lead"}, "finding.read": {...all}}`.
- **Key code:** a `require(permission: str)` FastAPI dependency that checks the current principal's role against the map.

### Step 2.3 – Replace `X-Attestra-Actor`
- **Files:** `attestra/api.py` (delete `actor()` header dependency; add `get_principal()` reading `Authorization: Bearer <api key>` or a session cookie), `attestra/web/ui.py` (login form + signed session cookie), `attestra/cli.py` (`--actor` becomes `--api-key` / env `ATTESTRA_API_KEY` for remote, or local admin for offline CLI).
- **Four-eyes:** `approve_report` compares **user ids**, not free-text names.
- **Tests:** anonymous → 401 on every write route; sending a different name can no longer bypass four-eyes.

### Step 2.4 – Tenant scoping helper
- **What:** every query filtered by tenant through one helper.
- **Files:** `attestra/services.py` (`def scoped(s, model, principal)` adds `Engagement.tenant_id == principal.tenant_id` joins for client users; staff see tenants they are assigned to), `models.py` (`Tenant.data_region`, `Tenant.plan`, `TenantMembership(user_id, tenant_id, role)`), migration `0007_tenancy.py`.
- **Rule:** no route may call `s.get(...)` / `select(...)` on tenant data directly – grep check in CI: `rg "s\.get\(" attestra/api.py` should return nothing.
- **Tests:** `tests/auth/test_tenant_matrix.py` – parametrized over route × role × tenant; cross-tenant get/list returns 404.

### Step 2.5 – Per-tenant storage prefixes
- **File:** `services._store(sub, sha, filename, data)` → `_store(tenant_id, sub, sha, filename, data)` writing under `DATA_DIR/tenants/<tenant_id>/<sub>/`. Migration script to move existing files (`attestra migrate-storage`, new CLI command).
- **Tests:** evidence for tenant A is not readable via tenant B's download route.

### Step 2.6 – Rate limit and security headers
- **What:** new `attestra/api_security.py` with an in-memory `RateLimiter` (per key + per IP), a `SecurityHeadersMiddleware` (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy) and `enforce_scan_rate()`; register in `api.py`.
- **Tests:** headers present (CSP, X-Frame-Options, etc.); 429 after the limit.

### Step 2.7 – OIDC (Keycloak) behind a flag
- **What:** `ATTESTRA_OIDC_ENABLED`, issuer, client id. Auth code + PKCE, `state` and `nonce`, issuer and audience checks, map Keycloak roles/groups to Attestra roles.
- **Files:** `attestra/auth/oidc.py`, `pyproject.toml` optional extra `oidc = ["authlib>=1.3"]` (VERIFY library choice).
- **Tests:** mocked IdP (JWKS + token endpoint) – bad nonce, wrong audience, expired token all rejected.

**Phase 2 checklist**
- [ ] Users, API keys, hashed passwords
- [ ] Six roles; every route has a permission check
- [ ] Header identity removed; four-eyes by user id
- [ ] Tenant scoping helper used everywhere; matrix test green
- [ ] Per-tenant storage
- [ ] Rate limit + security headers
- [ ] OIDC behind a flag

**Commit point:** `Phase 2: auth, roles, tenancy` (consider splitting into auth / tenancy commits). Push and check CI.

---

## Phase 3 – Compliance completeness (2–3 weeks + external review)

**Prerequisites:** Phase 2 (real assessor identity). Step 3.6 needs Phase 1 jobs.

### Step 3.1 – Missing PCI DSS v4 controls
- **File:** `attestra/compliance/data/controls.yaml`.
- **Add:** 11.3.1.1, 11.3.1.2, 11.3.2 (ASV), 11.4.2, 11.4.3, 11.4.5, 11.4.6, 6.4.2, 12.3.1, each with title, `rule` (finding-driven or a process rule understood by `engine._process_status`), and evidence expectations.
- **Code:** add any new process rules to `_process_status()` in `compliance/engine.py` (e.g. `asv_passing_scan`, `segmentation_tested`, `internal_scan_quarterly`).
- **Tests:** roll-up case per new control in `tests/test_compliance_reports.py`.

### Step 3.2 – Missing ISO 27001 and SOC 2 controls
- **Add:** ISO A.8.22, Clause 6.1.2, Clause 8.2, A.5.21; SOC 2 CC7.4, CC6.8, CC3.2. Same file and tests.

### Step 3.3 – Strength and rationale on every mapping
- **Files:** `controls.yaml`, `cwe_map.yaml`, `compliance/engine.py` (`Library` dataclass gains strength/rationale; reports show them).
- **Tests:** new `tests/test_library_integrity.py` – fails if any mapping lacks `strength in {full, partial}` or a non-empty `rationale`, or references an unknown control.

### Step 3.4 – Risk acceptance
- **Files:** `models.py` (`RiskAcceptance(id, finding_id, owner_user_id, rationale, accepted_at, expires_on, revoked_at)`), migration `0008_risk_acceptance.py`, `services.accept_risk()`, `services.expire_risk_acceptances()` (sets finding back to `open`, audits), CLI `attestra expire-risk` and a daily job.
- **Tests:** expired acceptance reopens the finding with an audit entry.

### Step 3.5 – ASV import and segmentation records
- **Files:** `models.py` (`AsvScan(id, engagement_id, vendor, scan_date, passing, attestation_path, sha256)`, `SegmentationTest(id, engagement_id, boundary, method, result, tested_on, evidence_id)`), migration `0009_pci_records.py`, `services`, API routes, UI section.
- **Tests:** 11.3.2 becomes `met` only with a passing ASV record in the quarter.

### Step 3.6 – PCI quarterly scan calendar
- **What:** a `ScanSchedule(id, engagement_id, asset_id, tool, cadence quarterly|monthly, next_due)` table; the worker enqueues due scans through `gate.check()`; "rescan until clean" keeps the quarter open until no high/critical remains.
- **Tests:** freeze time; schedule enqueues; quarter marked clean only after a clean run.

### Step 3.7 – OWASP references on findings
- **What:** new `attestra/compliance/owasp.py` (`map_finding_to_owasp(finding)`, `get_asvs()`, `get_wstg()`) driven by a new YAML catalog `attestra/compliance/data/owasp.yaml` mapping CWE → OWASP Top 10 2021 category, ASVS and WSTG ids (add it to `package-data`).
- **Schema:** `Finding.owasp_top10`, `asvs_ref`, `wstg_ref` (migration `0010_owasp_refs.py`); set during `import_results`.
- **Tests:** a CWE-89 finding maps to A03 Injection.

### Step 3.8 – ISO SoA view and nonconformities
- **Files:** `models.py` (`Nonconformity(id, engagement_id, control_ref, finding_id, corrective_action, owner, due, closed_at, retest_id)`), new template `reports/templates/iso_soa.html.j2`, UI tab.

### Step 3.9 – Ageing and SLA breach report
- **Files:** `services.sla_breaches(s, engagement_id)`, template `reports/templates/ageing.html.j2`, API `GET /engagements/{eid}/sla`.
- **Tests:** a critical finding older than 30 days is listed.

### Step 3.10 – External library review (process)
- Export the library (`attestra compliance-export` – new CLI command writing CSV) and send to a QSA / ISO lead auditor. Record reviewer, date and version in `compliance/data/REVIEW.md`.

**Phase 3 checklist**
- [ ] PCI 19/19, ISO 12/12, SOC 2 11/11 controls from the requirements document
- [ ] Integrity test green (strength + rationale 100%)
- [ ] Risk acceptance auto-expiry
- [ ] ASV + segmentation records
- [ ] Quarterly calendar
- [ ] OWASP refs, ISO SoA, nonconformities, SLA report
- [ ] External review recorded

**Commit point:** `Phase 3: compliance library and records`. Push; re-run the gap analysis.

---

## Phase 4 – Reports, letters and signing (3–4 weeks)

**Prerequisites:** Phases 2 and 3; retest steps need Phase 1.

### Step 4.1 – Three-step report workflow
- **File:** `attestra/reports/render.py`; `Report.status` values `draft → submitted → qa_approved → signed` plus `rejected` (back to draft); `Report.qa_by`, `Report.rejection_note` (migration `0011_report_workflow.py`).
- **Functions:** `submit_report`, `qa_approve`, `qa_reject`, `sign_report` (replaces `approve_report`). Tester ≠ QA ≠ signer (by user id), lead role required to sign.
- **Tests:** reject loop; same user cannot do two steps.

### Step 4.2 – Retests with false-fix guards
- **What:** new `attestra/retest.py` (`request_retest`, `finalize_retest`, `cancel_retest`) with a `Retest(id, finding_id, scan_run_id, result fixed|still_open|inconclusive, ...)` model. Mark **fixed** only if the retest ScanRun actually reached the affected asset/URL; otherwise `inconclusive`. Use asset-aware correlation keys for DAST (fingerprint includes asset id + normalised URL path).
- **Files:** `attestra/retest.py`, `attestra/fingerprint.py`, `models.py`, migration `0012_retests.py`.
- **Tests:** `tests/test_retest_false_fix.py` – retest that never fetched the asset is never `fixed`.

### Step 4.3 – Closure letter and attestation letter
- **Files:** new `reports/templates/closure_letter.html.j2`, `attestation_letter.html.j2` (no vulnerability details), add kinds to `generate_report`.
- **Tests:** golden-file render test under `tests/golden/`.

### Step 4.4 – DOCX and PDF output
- **What:** DOCX via `docxtpl`; PDF via WeasyPrint locally (Windows needs GTK runtime – VERIFY) or Gotenberg container later. Decide with the architecture owner.
- **Files:** `attestra/reports/export.py` (`to_docx(report)`, `to_pdf(report)`), templates under `reports/templates/docx/`, `pyproject.toml` optional extra `docs = ["docxtpl>=0.16", "weasyprint>=61"]` (VERIFY versions).
- **Tests:** files are produced and their sha256 is stored like HTML reports.

### Step 4.5 – Verifiable signatures
- **What:** replace HMAC in `reports/signing.py` (`ALGORITHM = "hmac-sha256"`) with X.509/Ed25519 (`cryptography`) or cosign so customers can verify outside Attestra. Keep `verify()` able to read old HMAC signatures (`algorithm` column on `Report`).
- **Tests:** verify with `openssl` (CI step) or the `cryptography` public key only.

### Step 4.6 – Framework packs
- PCI binder indexed by requirement, ISO Annex A evidence register, SOC 2 period population + sample CSV. New templates + `attestra/reports/packs.py` building a zip with a sha256 manifest.

### Step 4.7 – Executive trend
- Compare open findings by severity with the previous engagement of the same tenant; chart in `executive.html.j2` (inline SVG, no JS dependency).

### Step 4.8 – Exports
- New `attestra/reports/sarif.py` (`findings_to_sarif()` producing SARIF 2.1.0, plus a structure check), CSV export, and OSCAL Assessment Results / POA&M JSON in `attestra/reports/oscal.py`.
- **Tests:** SARIF structure check; OSCAL validated against the NIST JSON schema (store the schema file under `tests/schemas/`, VERIFY version).

**Phase 4 checklist**
- [ ] Submit → QA → sign workflow with reject loop
- [ ] Retests never false-fix
- [ ] Closure + attestation letters
- [ ] DOCX + PDF
- [ ] Signatures verifiable outside Attestra
- [ ] Framework packs, trend, SARIF/CSV/OSCAL

**Commit point:** `Phase 4: report workflow, letters, formats, signing`. Push.

---

## Phase 5 – Evidence hardening (2–3 weeks)

**Prerequisites:** Phase 2 (tenants), Phase 1 (raw artifacts).

### Step 5.1 – Masking at capture
- **File:** new `attestra/evidence/mask.py` (`mask_bytes(data, content_type) -> (masked, report)`): Luhn-checked PANs (keep first 6 / last 4), passwords in forms/headers, `Authorization`/`Cookie` headers, JWTs, API keys, emails/phone numbers.
- **Wire in:** `services.add_evidence` and raw artifact storage mask **before** hashing and `_store`; `Evidence.masking_applied` (JSON summary) column, migration `0013_masking.py`.
- **Tests:** `tests/evidence/test_mask_corpus.py` – a generated corpus of 1,000 PAN/credential strings leaves 0 unmasked; non-Luhn digit strings untouched.

### Step 5.2 – Storage backend interface
- **Files:** new `attestra/storage/__init__.py` (`class Storage(Protocol): put(key, data) -> uri; get(uri); exists(uri)`), `storage/local.py` (current `_store` logic, write-once, read-only perms), `storage/s3.py` (S3 Object Lock / SeaweedFS, `boto3` optional extra – VERIFY).
- **Config:** `ATTESTRA_STORAGE=local|s3`.
- **Tests:** local overwrite refused; S3 test against MinIO/SeaweedFS container marked `integration`.

### Step 5.3 – Retention policies and purge
- **Files:** `models.py` (`RetentionPolicy(tenant_id, framework, days)`; PCI default ≥ 365), `attestra/ops/retention.py` (new: `purge_expired(dry_run)`), CLI `attestra purge --dry-run`.
- **Tests:** purge deletes only expired items and audits each deletion; signed reports under legal hold are kept.

### Step 5.4 – Audit completeness and append-only DB
- **What:** audit every evidence/report download (`api.download_report` etc.), add `GET /audit/export?format=json|csv` with chain proof, and enforce append-only: SQLite trigger `BEFORE UPDATE/DELETE ON audit_events → RAISE(ABORT)`; Postgres: revoke UPDATE/DELETE (in a migration).
- **Tests:** download creates an event; UPDATE on `audit_events` fails.

### Step 5.5 – Backup and restore with manifest
- **What:** new `attestra/ops/backup.py` with `backup()` / `restore()` covering the DB (SQLite online backup API or `pg_dump`), evidence and reports; write `manifest.json` (sha256 per file); restore refuses on any mismatch – no silent fallback.
- **CLI:** `attestra backup E:\attestra-backups\<date>` and `attestra restore <dir>`.
- **Tests:** backup → tamper one file → restore fails; clean restore passes.

### Step 5.6 – KEV/EPSS refresh
- **What:** `attestra enrich --refresh` downloads the CISA KEV JSON and FIRST EPSS CSV (VERIFY URLs) into `DATA_DIR/feeds/`, then calls existing `services.enrich()`. Store catalog date; print it in reports.
- **Tests:** offline test with fixture files (`tests/fixtures/kev.json`, `epss.csv`).

**Phase 5 checklist**
- [ ] 0 unmasked in corpus test
- [ ] Storage interface; immutability test
- [ ] Retention + purge audited
- [ ] Download events, audit export, append-only enforcement
- [ ] Backup/restore with manifest
- [ ] Feed refresh with dates in reports

**Commit point:** `Phase 5: evidence masking, storage, retention, backup`. Push.

---

## Phase 6 – Production infrastructure (6–10 weeks)

**Prerequisites:** Phases 1–5. This is the first phase that adds services; keep the Python package as the core and add infrastructure around it.

### Step 6.1 – PostgreSQL 16 by default
- `ATTESTRA_DATABASE_URL=postgresql+psycopg://...` (existing `postgres` extra). Run all migrations on Postgres in CI (service container). Add row-level security policies per tenant in a migration (`SET app.tenant_id` per request in `db.session()`).
- **Tests:** cross-tenant raw SQL returns 0 rows under RLS.

### Step 6.2 – Temporal workflows
- Model scope → scan → triage → validate → map → report → retest as a Temporal workflow (`temporalio` SDK – VERIFY); activities call existing `services`/`runner` functions. Keep `attestra/jobs` as the fallback for single-node installs.
- **Tests:** workflow resumes after a worker kill (Temporal test server).

### Step 6.3 – OPA/Rego scope policy
- Move `runner/gate.py` decisions into `policy/scope.rego`; Python calls OPA. Reuse all Phase 1 gate tests as policy tests (`opa test policy/` – VERIFY).

### Step 6.4 – Keycloak default + Vault/OpenBao keys
- Keycloak with MFA as the default IdP (Phase 2 OIDC flag on). Per-tenant data keys from Vault/OpenBao Transit to encrypt raw evidence at rest (envelope encryption in `attestra/storage`).

### Step 6.5 – Containers and Helm
- `Dockerfile` (API + worker), `deploy/helm/attestra/` chart; scanners as Kubernetes Jobs with NetworkPolicy allowing only the pinned IP and a per-runner egress IP. Go on-prem runner agent (outbound mTLS) later.
- **Commands:** `docker build -t attestra:dev .`, `helm install attestra deploy/helm/attestra` (VERIFY).

### Step 6.6 – Observability
- OpenTelemetry instrumentation for FastAPI and SQLAlchemy, Prometheus metrics endpoint, Grafana dashboards, Loki logs. OpenSearch optional.

### Step 6.7 – Scheduled scans and CI/CD gates
- Scheduler UI on top of Step 3.6; GitHub Actions and GitLab templates in `integrations/ci/` that upload SARIF/Trivy results to `POST /engagements/{eid}/imports` and fail the pipeline on policy.

**Phase 6 checklist**
- [ ] Postgres + RLS
- [ ] Temporal workflow resumes after pod kill
- [ ] OPA policy suite green
- [ ] Keycloak MFA, Vault keys
- [ ] Helm smoke E2E on a clean cluster
- [ ] Observability, schedules, CI gates

**Commit point:** one commit per sub-step (`infra: postgres rls`, `infra: temporal`, ...). Push and check CI each time.

---

## Phase 7 – Product polish and integrations (4–6 weeks)

**Prerequisites:** Phase 6.

### Step 7.1 – Client portal and auditor view
- Read-only routes for `client_viewer` and `auditor` roles in `web/ui.py` + new templates. Keep Jinja; move to React/TypeScript only if a real need appears.

### Step 7.2 – Ticket sync and SBOM
- Jira and GitHub Issues sync for `Finding.ticket_ref` (`attestra/integrations/{jira,github}.py`, webhook for status back-sync). CycloneDX SBOM import and Dependency-Track import as new importers in `attestra/importers/`.

### Step 7.3 – More scanners
- Adapters for Prowler, kube-bench, testssl.sh, Gitleaks, Checkov, naabu in `attestra/runner/scanners/` + importers. GPL/AGPL tools (OpenVAS, MobSF) only as separate services called over HTTP.

### Step 7.4 – Tuning
- Per-tenant risk weights (override `scoring.asset_weight`/`exposure_weight`), suppression rules with expiry and audit, false-positive rate per tool on the dashboard.

### Step 7.5 – Legal pack and licence review
- RoE and authorization templates under `docs/legal/`; licence review of all bundled/called tools (AGPL/GPL/NPSL) recorded in `docs/LICENSES.md`.

**Phase 7 checklist**
- [ ] Portal + auditor view
- [ ] Jira/GitHub sync, SBOM import
- [ ] New scanners
- [ ] Tuning and suppression
- [ ] Legal pack + licence review

**Commit point:** `Phase 7: portal, integrations, scanners`. Push.

---

## Phase 8 – GA, then optional extras

**Prerequisites:** Phases 0–7.

### Step 8.1 – Third-party pentest of Attestra
- Engage an external tester; fix every critical/high; retest; store the letter as evidence.

### Step 8.2 – Load test
- Script with `locust` or `k6` (VERIFY tool) against a staging Helm install: N concurrent engagements, imports and report generations; record p95 latencies.

### Step 8.3 – GA release
- Bump `version` in `pyproject.toml` and `attestra/__init__.py`, write `CHANGELOG.md`, tag the release in GitHub Desktop / on GitHub.

### Step 8.4 – v2.1 framework packs
- CERT-In, RBI, SEBI CSCRF, DORA, NIST CSF 2.0 as YAML libraries under `compliance/data/` only (no code forks); each passes the Step 3.3 integrity test.

### Step 8.5 – AI (optional, last)
- Default: **do not build**. Use template-based narratives. Only if the architecture owner requires it: draft narratives labelled "AI-generated" until a reviewer edits them, a per-tenant off switch, no client data used for training, prefer a local model over paid APIs.

**Phase 8 checklist**
- [ ] External pentest closed (no open critical/high)
- [ ] Load test results recorded
- [ ] GA tagged
- [ ] v2.1 packs (as needed)
- [ ] AI decision recorded (built or explicitly skipped)

**Commit point:** `Release 1.0.0` and a tag. Push.

---

## Appendix A – Migration numbering (planned)

`0001_baseline` · `0002_scan_runs` · `0003_scope_rules` · `0004_jobs` · `0005_asset_ownership` · `0006_users` · `0007_tenancy` · `0008_risk_acceptance` · `0009_pci_records` · `0010_owasp_refs` · `0011_report_workflow` · `0012_retests` · `0013_masking` (later phases continue the sequence).

## Appendix B – Rules for every step
1. Write the test first or together with the code; `.\.venv\Scripts\python.exe -m pytest -q` must stay green.
2. Every state change goes through `services` and writes an `audit.record(...)` entry.
3. Never scan anything outside loopback fixtures during development.
4. Keep `.venv`, data and temp on `E:`; never commit `data/`, `*.db`, `.venv`, `.cache`.
5. You commit and push yourself in GitHub Desktop at each commit point.
