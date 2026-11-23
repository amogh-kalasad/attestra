# AASI Phase 8 — Environment variable inventory

Early Phase 8 documentation (docs only) on branch `attestra-asi-bundle`. Sources scanned: `.env.example`, `attestra/config.py`, `docs/AI_NARRATIVES.md`, `docker/scanner-digests.env`, `compose.yaml`. Product Python was **not** modified for this inventory. `.env.example` updates land when the Phase 8 code pass lands — see [`AASI_PHASE8_ENV_DRAFT.md`](AASI_PHASE8_ENV_DRAFT.md).

**Count:** **118** named variables documented below (bare prefixes such as `ATTESTRA_IMAGE_` / `ATTESTRA_SCANNER_TIMEOUT_` counted as their concrete keys; `BYPASS_STATUS` is a module constant, not an env var, and is omitted).

**Legend**

| Field | Meaning |
|---|---|
| Default | Value when unset (code / compose / docs). |
| Req | Required at runtime for the related feature to work. |
| Secret | Treat as secret material (never commit real values). |
| Sources | Which of the five inventory sources mention the name. |
| Status | `existing` = already used; `AASI-in-config` = already wired in `config.py` for AASI; `proposed` = V4 §15.2 gap, name not invented when an existing var covers it. |

Production recommendations assume `APP_ENV=staging` or `production` unless noted.

---

## 1. Application / APP_ENV

| Name | Purpose | Default | Req | Secret | Production recommendation | Related service | Sources | Status |
|---|---|---|---|---|---|---|---|---|
| `APP_ENV` | Deployment environment; gates bypass allowlist and K-04 secret defaults | unset → `None` (compose default `local`) | Optional; required if any `BYPASS_*` is true | No | `staging` or `production`; never enable bypasses | API, worker, CLI | `.env.example`, `config.py`, `compose.yaml` | existing |

---

## 2. Persistence / MongoDB / storage

| Name | Purpose | Default | Req | Secret | Production recommendation | Related service | Sources | Status |
|---|---|---|---|---|---|---|---|---|
| `ATTESTRA_DATA_DIR` | Root data directory (evidence, drafts, caches) | `./data` (cwd-relative) | Optional | No | Durable volume; compose uses `/data` | API, worker, AI drafts | `.env.example`, `config.py`, `AI_NARRATIVES.md`, `compose.yaml` | existing |
| `ATTESTRA_PERSISTENCE` | Legacy persistence selector (runtime is Mongo only) | `mongo` | Optional | No | Leave `mongo` | API, worker | `.env.example`, `config.py`, `compose.yaml` | existing |
| `ATTESTRA_STORAGE` | Artifact backend: `mongo` (GridFS) \| `local` \| `s3` | `mongo` when persistence is mongo | Optional | No | `mongo` or `s3` with Object Lock as needed | API, worker, reports | `.env.example`, `config.py`, `compose.yaml` | existing |
| `ATTESTRA_MONGODB_URI` | Mongo connection string (replica set required for transactions) | `mongodb://127.0.0.1:27017/?replicaSet=rs0` | **Yes** for runtime | **Yes** (credentials) | Authenticated URI; TLS in prod; never commit passwords | MongoDB | `.env.example`, `config.py`, `compose.yaml` | existing |
| `ATTESTRA_MONGODB_DB` | Database name | `attestra` | Optional | No | Dedicated DB name | MongoDB | `.env.example`, `config.py`, `compose.yaml` | existing |
| `ATTESTRA_TEST_MONGODB_URI` | Separate URI for tests (`attestra_test_*` DBs) | same host RS URI | Optional (tests) | **Yes** if credentials | Throwaway test DB only | pytest | `.env.example` | existing |
| `ATTESTRA_MONGODB_GRIDFS_BUCKET` | GridFS bucket for artifacts | `attestra_artifacts` | Optional | No | Stable bucket name | GridFS | `.env.example` | existing |
| `ATTESTRA_MONGODB_TLS` | Enable TLS to Mongo | unset/false | Optional | No | `true` for remote/prod clusters | MongoDB | `.env.example` | existing |
| `ATTESTRA_MONGODB_TLS_CA_FILE` | CA bundle path for Mongo TLS | empty | Optional | No | Set when using private CA | MongoDB | `.env.example` | existing |
| `ATTESTRA_MONGODB_SERVER_SELECTION_TIMEOUT_MS` | Server selection timeout | `5000` | Optional | No | Tune for network latency | MongoDB | `.env.example` | existing |
| `ATTESTRA_MONGODB_CONNECT_TIMEOUT_MS` | Connect timeout | `5000` | Optional | No | Tune for network latency | MongoDB | `.env.example` | existing |
| `ATTESTRA_MONGODB_SOCKET_TIMEOUT_MS` | Socket timeout | `30000` | Optional | No | Raise for large GridFS reads if needed | MongoDB | `.env.example` | existing |
| `ATTESTRA_MONGODB_MAX_POOL_SIZE` | Client pool size | `50` | Optional | No | Size to API+worker concurrency | MongoDB | `.env.example` | existing |
| `ATTESTRA_S3_BUCKET` | S3 bucket when `ATTESTRA_STORAGE=s3` | empty | Required if s3 | No | Set real bucket | S3 / MinIO | `.env.example`, `config.py` | existing |
| `ATTESTRA_S3_ENDPOINT` | Custom S3 endpoint | empty | Optional | No | Set for MinIO / private endpoints | S3 / MinIO | `.env.example`, `config.py` | existing |
| `ATTESTRA_S3_OBJECT_LOCK` | Object Lock for immutability | false | Optional | No | Enable for evidence WORM where required | S3 | `.env.example`, `config.py` | existing |

---

## 3. Auth secrets / sessions / credentials

| Name | Purpose | Default | Req | Secret | Production recommendation | Related service | Sources | Status |
|---|---|---|---|---|---|---|---|---|
| `ATTESTRA_SESSION_SECRET` | Cookie/session signing | `attestra-dev-session-change-me` | **Yes** | **Yes** | Unique strong secret; startup refuses default in staging/production (K-04) | API sessions | `.env.example`, `config.py`, `compose.yaml` | existing |
| `ATTESTRA_API_KEY_PEPPER` | Pepper for API key hashes | `attestra-dev-pepper-change-me` | **Yes** | **Yes** | Unique strong secret; refused default in staging/production | API keys | `.env.example`, `config.py`, `compose.yaml` | existing |
| `ATTESTRA_CREDENTIAL_FERNET_KEY` | Fernet key for auth-web credential profiles | empty | Required when auth-web stores credentials | **Yes** | Fill via `scripts/ensure_env_secrets.py`; never commit | auth-web | `.env.example`, `config.py`, `compose.yaml` | existing |
| `ATTESTRA_CREDENTIAL_ALLOW_EPHEMERAL` | Allow ephemeral credential material in local testing | unset | Optional | No | **Off** in shared/prod | auth-web | `.env.example` | existing |
| `ATTESTRA_AUTH_SECRET_DIR` | Directory for auth secret files inside container | `/data/auth-secrets` (compose) | Optional | No (path) | Persist on volume; restrict perms | auth-web / compose | `.env.example`, `compose.yaml` | existing |
| `ATTESTRA_SECRETS_BACKEND` | `env` or `vault` (Vault/OpenBao KV v2) | `env` | Optional | No | Prefer `vault` in production for AI/API secrets | secret_store | `config.py` | existing |
| `ATTESTRA_API_RATE_LIMIT` | API requests per window | `120` | Optional | No | Size to threat model / WAF | API middleware | `config.py` | existing |

---

## 4. OIDC / SSO

| Name | Purpose | Default | Req | Secret | Production recommendation | Related service | Sources | Status |
|---|---|---|---|---|---|---|---|---|
| `ATTESTRA_OIDC_ENABLED` | Enable OIDC login / JWT validation | off | Optional | No | Enable only when IdP is ready | OIDC / Keycloak | `config.py` | existing |
| `ATTESTRA_OIDC_ISSUER` | Issuer URL | empty | Required if OIDC on | No | HTTPS issuer | OIDC | `config.py` | existing |
| `ATTESTRA_OIDC_CLIENT_ID` | Client id | empty | Required if OIDC on | No | Dedicated client | OIDC | `config.py` | existing |
| `ATTESTRA_OIDC_CLIENT_SECRET` | Client secret | empty | Often required | **Yes** | Secret store / compose secrets | OIDC | `config.py` | existing |
| `ATTESTRA_OIDC_AUDIENCE` | JWT audience (empty → client id) | empty | Optional | No | Match IdP access-token aud | OIDC JWT | `config.py` | existing |
| `ATTESTRA_OIDC_JWKS_URL` | JWKS URL (empty → issuer certs path) | empty | Optional | No | Explicit JWKS when non-Keycloak | OIDC JWT | `config.py` | existing |
| `ATTESTRA_OIDC_ALGORITHMS` | Allowed JWT algs | `RS256,ES256` | Optional | No | Keep asymmetric only | OIDC JWT | `config.py` | existing |
| `ATTESTRA_OIDC_USERNAME_CLAIM` | Username claim | `preferred_username` | Optional | No | Match IdP | OIDC | `config.py` | existing |
| `ATTESTRA_OIDC_TENANT_CLAIM` | Tenant claim | `attestra_tenant_id` | Optional | No | Match IdP mapping | OIDC | `config.py` | existing |
| `ATTESTRA_OIDC_AUTO_PROVISION` | Auto-create users from token | `true` | Optional | No | Review for prod; may prefer invite-only | OIDC | `config.py` | existing |

---

## 5. Bypass flags (local / test / development only)

| Name | Purpose | Default | Req | Secret | Production recommendation | Related service | Sources | Status |
|---|---|---|---|---|---|---|---|---|
| `BYPASS_TARGET_OWNERSHIP_VERIFICATION` | Skip ownership gate when `APP_ENV` allowlisted | `false` | Optional | No | **Must be false** in staging/production (startup fails otherwise) | scans / imports | `.env.example`, `config.py` | existing |
| `BYPASS_SIGNED_AUTHORIZATION_VERIFICATION` | Skip signed-auth gate when `APP_ENV` allowlisted | `false` | Optional | No | **Must be false** in staging/production | scans / imports | `.env.example`, `config.py` | existing |

---

## 6. Workers / jobs / orchestrator / Temporal

| Name | Purpose | Default | Req | Secret | Production recommendation | Related service | Sources | Status |
|---|---|---|---|---|---|---|---|---|
| `ATTESTRA_ORCHESTRATOR` | `inline` durable poller or `temporal` | `inline` | Optional | No | Keep `inline` unless Temporal is operated | worker | `.env.example`, `config.py` | existing |
| `ATTESTRA_TEMPORAL_ADDRESS` | Temporal frontend address | `localhost:7233` | Required if temporal | No | Internal address only | Temporal | `.env.example`, `config.py` | existing |
| `ATTESTRA_TEMPORAL_NAMESPACE` | Temporal namespace | `default` | Optional | No | Dedicated namespace | Temporal | `.env.example`, `config.py` | existing |
| `ATTESTRA_TEMPORAL_TASK_QUEUE` | Task queue name | `attestra-scans` | Optional | No | Stable queue name | Temporal | `.env.example`, `config.py` | existing |
| `ATTESTRA_WORKER_CONCURRENCY` | Parallel scan jobs per worker (1–8) | `2` | Optional | No | Size to CPU / Docker capacity | worker | `.env.example` | existing |
| `ATTESTRA_WORKER_INSTANCE` | Distinguishes compose workers | `"1"` / `"2"` | Optional | No | Unique per replica | worker lock | `compose.yaml` | existing |
| `ATTESTRA_JOB_MAX_ATTEMPTS` | Max job attempts | `3` | Optional | No | Keep bounded | jobs | `.env.example`, `config.py` | existing |
| `ATTESTRA_JOB_STALE_HEARTBEAT_S` | Stale heartbeat threshold | `120` | Optional | No | Align with scanner timeouts | jobs | `.env.example`, `config.py` | existing |
| `ATTESTRA_SCAN_RATE_PER_ASSET` | Scan scheduling rate per asset | `10` | Optional | No | Lower under WAF pressure | scheduler | `.env.example`, `config.py` | existing |
| `ATTESTRA_DOCKER_HOST_DATA_DIR` | Host path for nested `docker run -v` | empty / `./data` | Required for nested Docker scanners on Windows/Linux Docker Desktop | No | Absolute host path matching bind mount | Docker-in-Docker scanners | `.env.example`, `compose.yaml` | existing |

---

## 7. Scanner images (digest pins) and scanner runtime

Placeholder digests (all-zero style) are **refused** at runtime by `image_is_placeholder`. Compose currently pins ZAP/NUCLEI/TESTSSL/NAABU; AASI AI images are commented placeholders until inspect.

| Name | Purpose | Default | Req | Secret | Production recommendation | Related service | Sources | Status |
|---|---|---|---|---|---|---|---|---|
| `ATTESTRA_IMAGE_ZAP` | Digest-pinned ZAP image | compose/digests real pin; config placeholder otherwise | Required to run ZAP | No | Real `@sha256:` pin only | ZAP adapter | all four image sources | existing |
| `ATTESTRA_IMAGE_NUCLEI` | Digest-pinned Nuclei image | compose/digests real pin | Required to run Nuclei | No | Real pin | Nuclei | all four | existing |
| `ATTESTRA_IMAGE_TESTSSL` | Digest-pinned testssl image | compose/digests real pin | Required to run testssl | No | Real pin | testssl | all four | existing |
| `ATTESTRA_IMAGE_NAABU` | Digest-pinned naabu image | compose/digests real pin | Required to run naabu | No | Real pin | naabu | all four | existing |
| `ATTESTRA_IMAGE_TRIVY` | Digest-pinned Trivy | config placeholder | Required to run Trivy | No | Replace after `docker inspect` | Trivy | `.env.example`, `config.py` | existing |
| `ATTESTRA_IMAGE_SEMGREP` | Digest-pinned Semgrep | config placeholder | Required to run Semgrep | No | Replace after inspect | Semgrep | `.env.example`, `config.py` | existing |
| `ATTESTRA_IMAGE_GITLEAKS` | Digest-pinned Gitleaks | config placeholder | Required to run Gitleaks | No | Replace after inspect | Gitleaks | `.env.example`, `config.py` | existing |
| `ATTESTRA_IMAGE_CHECKOV` | Digest-pinned Checkov | config placeholder | Required to run Checkov | No | Replace after inspect | Checkov | `.env.example`, `config.py` | existing |
| `ATTESTRA_IMAGE_SUBFINDER` | Digest-pinned subfinder | config placeholder | Required if discovery | No | Replace after inspect | discovery | `.env.example`, `config.py` | existing |
| `ATTESTRA_IMAGE_DNSX` | Digest-pinned dnsx | config placeholder | Required if discovery | No | Replace after inspect | discovery | `.env.example`, `config.py` | existing |
| `ATTESTRA_IMAGE_HTTPX` | Digest-pinned httpx probe image | config placeholder | Required if discovery | No | Replace after inspect | discovery | `.env.example`, `config.py` | existing |
| `ATTESTRA_IMAGE_GARAK` | Digest-pinned Garak AI scanner | config placeholder `nvidia/garak@sha256:…000c`; digests file commented | Required to run Garak adapter | No | Real pin after inspect; refuse placeholders | AASI / Garak | `config.py`, `scanner-digests.env` | **AASI-in-config** |
| `ATTESTRA_IMAGE_PROMPTFOO` | Digest-pinned Promptfoo | config placeholder; digests commented (`ghcr.io/…` comment vs `docker.io/…` placeholder — reconcile at Phase 9) | Required to run Promptfoo | No | Real pin after inspect | AASI / Promptfoo | `config.py`, `scanner-digests.env` | **AASI-in-config** |
| `ATTESTRA_IMAGE_SAFELABS` | Digest-pinned safelabs-eval | config placeholder; digests commented | Required to run SafeLabs | No | Real pin after inspect | AASI / SafeLabs | `config.py`, `scanner-digests.env` | **AASI-in-config** |
| `ATTESTRA_SCANNER_TIMEOUT_S` | Global scanner timeout (seconds) | `600` | Optional | No | Raise carefully; prefer per-tool overrides | scanners | `.env.example`, `config.py` | existing |
| `ATTESTRA_SCANNER_TIMEOUT_NUCLEI` | Nuclei timeout | `7200` | Optional | No | Keep high for full baselines | Nuclei | `.env.example`, `compose.yaml` | existing |
| `ATTESTRA_NUCLEI_RATE_LIMIT` | Nuclei requests/sec (1–150) | `30` | Optional | No | Lower (e.g. 15) behind WAF | Nuclei | `.env.example`, `compose.yaml` | existing |
| `ATTESTRA_SCANNER_CACHE_DIR` | Persistent nuclei/trivy cache | `$ATTESTRA_DATA_DIR/scanner-cache` | Optional | No | Persist across restarts | scanners | `.env.example`, `config.py` | existing |
| `ATTESTRA_HTTPX_BIN` | Host httpx binary name (not Python httpx) | `httpx-toolkit` | Optional | No | Never point at Python package | httpx probe | `.env.example` | existing |
| `ATTESTRA_EVIDENCE_MAX_BYTES` | Evidence upload size cap | `20971520` (20 MiB) | Optional | No | Keep bounded; portal has stricter 5 MiB | evidence API | `.env.example`, `config.py` | existing |
| `ATTESTRA_KEV_URL` | CISA KEV feed URL | CISA JSON URL | Optional | No | Official URL unless mirrored | threat intel | `config.py` | existing |
| `ATTESTRA_EPSS_URL` | FIRST EPSS feed URL | empiricalsecurity CSV.gz | Optional | No | Official URL unless mirrored | threat intel | `config.py` | existing |
| `ATTESTRA_LICENSE_POLICY` | SBOM licence policy path or `default` | empty (opt-in) | Optional | No | Enable for supply-chain gates | supply_chain | `.env.example`, `compose.yaml` | existing |
| `ATTESTRA_GSB_ENABLED` | Google Safe Browsing webcheck | off | Optional | No | Off unless key provisioned | webcheck | `config.py` | existing |
| `ATTESTRA_GSB_API_KEY` | GSB API key | empty | Required if GSB on | **Yes** | Secret store; never log | webcheck | `config.py` | existing |

Pattern (documented in `.env.example`, not a single var): `ATTESTRA_SCANNER_TIMEOUT_<TOOL>` for per-tool overrides beyond Nuclei.

---

## 8. Feature flags — automated VAPT / auth-web / probes / ops

| Name | Purpose | Default | Req | Secret | Production recommendation | Related service | Sources | Status |
|---|---|---|---|---|---|---|---|---|
| `ATTESTRA_AUTOMATED_VAPT_ENABLED` | Elite automated VAPT orchestrator | off / `false` | Optional | No | Enable only when authorized; keep fail-closed | automated_vapt | `.env.example`, `config.py`, `compose.yaml` | existing |
| `ATTESTRA_AUTH_WEB_ENABLED` | Authenticated website testing | off | Optional | No | Enable with Fernet key + profiles | auth-web | `.env.example`, `config.py`, `compose.yaml` | existing |
| `ATTESTRA_AUTH_WEB_MAX_ROUTES` | Max crawled routes | `100` | Optional | No | Bound crawl cost | auth-web | `config.py` | existing |
| `ATTESTRA_AUTH_WEB_MAX_DEPTH` | Max crawl depth | `5` | Optional | No | Bound crawl cost | auth-web | `config.py` | existing |
| `ATTESTRA_AUTH_WEB_MAX_DURATION_S` | Max auth-web duration | `600` | Optional | No | Bound wall time | auth-web | `config.py` | existing |
| `ATTESTRA_AUTH_WEB_RATE_PER_HOST` | Requests per host rate | `2` | Optional | No | Stay WAF-safe | auth-web | `config.py` | existing |
| `ATTESTRA_AUTH_WEB_CONCURRENCY` | Concurrent auth-web workers | `2` | Optional | No | Bound load | auth-web | `config.py` | existing |
| `ATTESTRA_AUTOMATED_VAPT_MUTATION` | Body-level write mutation (T22) | `0` | Optional | No | Off unless local allowlisted env + policy | automated_vapt | `.env.example`, `config.py`, `compose.yaml` | existing |
| `ATTESTRA_INTRUSIVE_ALLOWED_ENVIRONMENTS` | Asset environments that may receive intrusive tests | `dev,demo` | Optional | No | Never include `production` (startup rejects) | intrusive_policy | `.env.example`, `config.py`, `compose.yaml` | existing |
| `ATTESTRA_AUTOMATED_VAPT_SSRF` | Intrusive SSRF tests | `0` | Optional | No | Off unless authorized | intrusive | `.env.example`, `config.py`, `compose.yaml` | existing |
| `ATTESTRA_AUTOMATED_VAPT_UPLOAD` | Intrusive upload tests | `0` | Optional | No | Off unless authorized + cleanup | intrusive | `.env.example`, `config.py`, `compose.yaml` | existing |
| `ATTESTRA_AUTOMATED_VAPT_STORED_XSS` | Intrusive stored XSS tests | `0` | Optional | No | Off unless authorized + cleanup | intrusive | `.env.example`, `config.py`, `compose.yaml` | existing |
| `ATTESTRA_RUN_VALIDITY_MODE` | `enforce` \| `observe` for WAF/auth-loss aware results | `enforce` | Optional | No | Keep `enforce` in prod | run_validity | `.env.example`, `config.py`, `compose.yaml` | existing |
| `ATTESTRA_RUN_VALIDITY` | Alias for `ATTESTRA_RUN_VALIDITY_MODE` | — | Optional | No | Prefer the `_MODE` name | run_validity | `config.py` | existing |
| `ATTESTRA_AUTOMATED_VAPT_PLANNER` | Tiered case planner | `0` | Optional | No | Opt-in | planner | `.env.example`, `config.py`, `compose.yaml` | existing |
| `ATTESTRA_GUIDED_PLANS` | Guided manual business-logic plans | `0` | Optional | No | Opt-in | guided plans | `.env.example`, `config.py`, `compose.yaml` | existing |
| `ATTESTRA_PROBES_WEB_SAFE` | Safe web probes (CORS, Host, redirect, …) | `0` | Optional | No | Opt-in | probes | `.env.example`, `config.py`, `compose.yaml` | existing |
| `ATTESTRA_GRAPHQL_PROBE` | GraphQL detect + bounded introspection | `0` | Optional | No | Opt-in | probes | `.env.example`, `config.py`, `compose.yaml` | existing |
| `ATTESTRA_API_IMPORT_ENABLED` | OpenAPI / Swagger / Postman / HAR import | `0` | Optional | No | Opt-in | API inventory | `.env.example`, `config.py`, `compose.yaml` | existing |
| `ATTESTRA_PROBE_DELAY_MS` | Delay between probes | `250` | Optional | No | Raise under rate limits | probes | `.env.example` | existing |
| `ATTESTRA_API_SPEC_MAX_BYTES` | Max API spec upload size | `5242880` | Optional | No | Keep bounded | API import | `.env.example` | existing |
| `ATTESTRA_DISCOVERY_ENABLED` | Passive subdomain discovery | off | Optional | No | Opt-in; verify digests | discovery | `.env.example`, `config.py`, `compose.yaml` | existing |
| `ATTESTRA_TENANT_STRICT` | Unscoped repos fail closed | off | Optional | No | Enable after admin views verified | multi-tenant | `.env.example`, `config.py`, `compose.yaml` | existing |
| `ATTESTRA_MAINTENANCE_ENABLED` | Worker maintenance tick | off | Optional | No | Enable for scheduled ops | maintenance | `.env.example`, `config.py`, `compose.yaml` | existing |
| `ATTESTRA_INTEL_AUTO_REFRESH` | KEV/EPSS refresh task | off | Optional | No | Needs maintenance enabled | intel | `.env.example`, `config.py`, `compose.yaml` | existing |
| `ATTESTRA_INTEL_REFRESH_INTERVAL_S` | Intel refresh interval | `21600` | Optional | No | Align with feed freshness | intel | `.env.example` | existing |
| `ATTESTRA_INTEL_MAX_AGE_HOURS_KEV` | KEV freshness threshold | empty | Optional | No | Set if enforcing freshness | intel | `.env.example` | existing |
| `ATTESTRA_INTEL_MAX_AGE_HOURS_EPSS` | EPSS freshness threshold | empty | Optional | No | Set if enforcing freshness | intel | `.env.example` | existing |

---

## 9. Subscription / credits / public URL

| Name | Purpose | Default | Req | Secret | Production recommendation | Related service | Sources | Status |
|---|---|---|---|---|---|---|---|---|
| `SUBSCRIPTION_SERVICE` | Enforce org test-run credits (`ON`/`OFF`) | `ON` | Optional | No | Keep `ON` unless deliberately bypassing credits only | credits | `.env.example`, `config.py` | existing |
| `ATTESTRA_INITIAL_TEST_RUN_CREDITS` | Initial credits for new orgs | `3` (compose often `10`) | Optional | No | Business policy | credits | `.env.example`, `config.py`, `compose.yaml` | existing |
| `ATTESTRA_CREDIT_REFUND_ON_PRE_START_FAILURE` | Refund if admission fails before start | `ON` | Optional | No | Keep ON | credits | `.env.example`, `config.py` | existing |
| `ATTESTRA_CREDIT_REFUND_ON_POST_START_FAILURE` | Refund after started scan fails | `OFF` | Optional | No | Keep OFF | credits | `.env.example`, `config.py` | existing |
| `ATTESTRA_PUBLIC_URL` | Public base URL for links / emails | `http://127.0.0.1:8000` | Optional | No | HTTPS public origin | alerts, UI | `.env.example`, `compose.yaml` | existing |

---

## 10. AI narratives (existing — reused by AASI; not in `.env.example` yet)

Documented in `docs/AI_NARRATIVES.md`. Phase 8 code pass should add commented placeholders to `.env.example` (see draft).

| Name | Purpose | Default | Req | Secret | Production recommendation | Related service | Sources | Status |
|---|---|---|---|---|---|---|---|---|
| `ATTESTRA_AI_NARRATIVES` | Enable AI narrative drafts | `off` | Optional | No | Keep off unless operator enables; drafts still need tester approval | ai_narratives | `AI_NARRATIVES.md` | existing |
| `ATTESTRA_AI_PROVIDER` | `ollama` or `openai` (OpenAI-compatible) | `ollama` | Optional | No | Prefer local Ollama | ai_narratives / AASI provider | `AI_NARRATIVES.md` | existing |
| `ATTESTRA_AI_BASE_URL` | Provider base URL | `http://localhost:11434` (ollama) | Required when narratives/AASI provider on | No | Internal URL; HTTPS for remote | provider | `AI_NARRATIVES.md` | existing |
| `ATTESTRA_AI_MODEL` | Model name | `llama3.1` | Optional | No | Pin a known model | provider | `AI_NARRATIVES.md` | existing |
| `ATTESTRA_AI_API_KEY` | Fallback API key if secret `ai_api_key` unset | empty | Required for openai provider | **Yes** | Prefer Vault/`secret_store`; never log | provider | `AI_NARRATIVES.md` | existing |
| `ATTESTRA_AI_TENANTS_OFF` | Comma-separated tenant ids with AI off | empty | Optional | No | Use for kill-switch tenants; AASI must honour | narratives / AASI | `AI_NARRATIVES.md` | existing |

Do **not** invent `ATTESTRA_AASI_PROVIDER` / `ATTESTRA_AASI_MODEL` — reuse the `ATTESTRA_AI_*` names above (blueprint §8 / V4 “do not invent”).

---

## 11. AASI knobs already in `attestra/config.py`

| Name | Purpose | Default | Req | Secret | Production recommendation | Related service | Sources | Status |
|---|---|---|---|---|---|---|---|---|
| `ATTESTRA_AASI` | Master AASI feature flag | `off` | Optional | No | **Keep off** until Phase 8+ production readiness; when off, AASI routes must not expose reasoning | AASI | `config.py` | **AASI-in-config** |
| `ATTESTRA_AASI_MAX_ITERATIONS` | Max orchestrator iterations per run | `8` | Optional | No | Keep bounded (V4: bounded execution) | AASI budget | `config.py` | **AASI-in-config** |
| `ATTESTRA_AASI_MAX_TASKS` | Max tasks per run | `32` | Optional | No | Keep bounded | AASI budget | `config.py` | **AASI-in-config** |
| `ATTESTRA_AASI_MAX_MODEL_CALLS` | Max provider calls per run | `40` | Optional | No | Keep bounded | AASI budget | `config.py` | **AASI-in-config** |
| `ATTESTRA_AASI_MAX_TOKENS` | Max tokens budget per run | `50000` | Optional | No | Keep bounded | AASI budget | `config.py` | **AASI-in-config** |
| `ATTESTRA_AASI_MAX_WALL_CLOCK_S` | Max wall-clock seconds | `1800` (30 min) | Optional | No | Keep bounded | AASI budget | `config.py` | **AASI-in-config** |
| `ATTESTRA_AASI_RETRY_LIMIT` | Provider/task retry limit | `2` | Optional | No | Keep small | AASI budget | `config.py` | **AASI-in-config** |
| `ATTESTRA_AASI_REQUIRE_APPROVAL` | Require human approval before intrusive / execution path | `on` | Optional | No | **Keep on** in all shared environments | AASI approval | `config.py` | **AASI-in-config** |

---

## 12. Proposed AASI variables (V4 §15.2 gaps — not yet in config)

Mark clearly as **proposed**. Prefer existing names when they already cover the concern.

| Proposed name | Purpose | Suggested default | Req | Secret | Production recommendation | Related service | Maps to existing? | Status |
|---|---|---|---|---|---|---|---|---|
| `ATTESTRA_AASI_THIRD_PARTY_DATA` | Allow sending redacted-beyond-metadata customer fields to third-party models | `off` | Optional | No | **Off**; local Ollama preferred | AASI provider / redaction | New — blueprint “data-processing flag” | **proposed** |
| `ATTESTRA_AASI_EXTERNAL_JUDGE` | Authorize third-party judge / adversarial model egress (Promptfoo graders, PyRIT scorers) | `off` | Optional | No | **Off**; use local judge when needed | AI adapters egress | New — V4 §15.2 “external judge authorization” | **proposed** |
| *(none — reuse)* | Evidence retention / size | — | — | — | Use `ATTESTRA_EVIDENCE_MAX_BYTES` + storage backend retention policy | evidence | **Reuse** `ATTESTRA_EVIDENCE_MAX_BYTES` | covered by existing |
| *(none — reuse)* | AI asset testing enablement | — | — | — | Catalogue + signed authorization (`ai_app` / `ai_llm` / `ai_agent`); no separate kill-switch beyond `ATTESTRA_AASI` and image digests | assets / RoE | **Reuse** auth catalogues + `ATTESTRA_AASI` | covered by existing |
| *(none — reuse)* | Provider / model selection | — | — | — | `ATTESTRA_AI_PROVIDER` / `ATTESTRA_AI_MODEL` / `ATTESTRA_AI_BASE_URL` | provider | **Reuse** `ATTESTRA_AI_*` | covered by existing |

Final names for the two proposed flags may be adjusted in the Phase 8 code pass; do not ship them in `.env.example` until implemented.

---

## 13. Source coverage summary

| Source | Role in inventory |
|---|---|
| `.env.example` | Operator-facing template (incomplete for `ATTESTRA_AI*` / `ATTESTRA_AASI*` until Phase 8 code) |
| `attestra/config.py` | Canonical defaults including AASI + image placeholders |
| `docs/AI_NARRATIVES.md` | AI narrative / provider vars |
| `docker/scanner-digests.env` | Digest pins; AASI images commented |
| `compose.yaml` | Runtime injection for API/workers + web scanner pins |

**Variables documented: 118** (including 8 AASI-in-config knobs, 3 AASI image pins, 6 AI narrative vars, and 2 proposed flags called out separately in §12 without inventing duplicates for provider/model/evidence/AI-asset testing).
