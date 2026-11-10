# Attestra

**From findings to signed attestation.**

Attestra turns security testing results into audit-ready evidence. It runs scans against approved targets, or imports results from the scanners your testers already use. It deduplicates and validates findings, ranks them by risk, records human review, maps them to **PCI DSS v4.0.1, ISO/IEC 27001:2022 and SOC 2** (and other frameworks), and produces reports that are hashed, reviewed by a second person and signed.

Attestra only tests a target when the engagement has a valid signed permission letter and the target owner has proved control of the domain.

Runtime storage is **MongoDB only**. SQLAlchemy is used as a schema/query builder over a Mongo session — there is no SQLite, PostgreSQL or Alembic path.

More detail: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [SECURITY.md](SECURITY.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), [docs/USER_MANAGEMENT.md](docs/USER_MANAGEMENT.md), [SETUP_GUIDE.md](SETUP_GUIDE.md), [docs/AUTH_WEB_TESTING.md](docs/AUTH_WEB_TESTING.md), [docs/mongodb_migration/SECURE_LOCAL_MONGO.md](docs/mongodb_migration/SECURE_LOCAL_MONGO.md).

## What Attestra does

| Area | What it does |
| --- | --- |
| Engagements | Tenants, engagements (VA, PT, VA + PT, retest, continuous), test window and target frameworks |
| Permission gate | A signed permission letter is stored hashed and write-once. Scans and imports are blocked without a valid one |
| Domain ownership | The owner proves control with a DNS TXT record or `/attestra-verify.txt` at the website root. Proof stays valid for a Super Admin-configured per-tenant period (default 30 days), then must be re-checked |
| Targets | Assets with criticality 1–5, internet or internal exposure, and a PCI CDE flag |
| In-app scans | Background worker runs ZAP, webcheck, testssl, Nuclei, Trivy, Semgrep, Gitleaks, Checkov, naabu, Prowler, kube-bench. Scans can be cancelled. Same path from the CLI: `attestra scan` |
| Auth website testing | Optional authenticated crawl and WSTG/ASVS checklist (off by default). Mid-scan session expiry detection and bounded re-login. See [docs/AUTH_WEB_TESTING.md](docs/AUTH_WEB_TESTING.md) |
| Automated VAPT | Optional catalogue (T01–T22 plus SESSION, INJ, XSS, XSSDOM, XSSSTORE, FILE, BIZ, ROLEDIFF, SSRF, UPLOAD). Off by default; some probes are extra-gated. Skip/blocked reasons stay visible in reports |
| Imports | ZAP, Nuclei, Trivy, SARIF, testssl, SSL Labs, Observatory, Burp, Nessus, Prowler, kube-bench, Checkov, Gitleaks, naabu, CycloneDX, Dependency-Track, webcheck and more |
| Findings | One format keyed on CWE, CVE and location, with observations kept under canonical findings. Import-time classification downgrades scanner noise (for example ZAP 10109/10112, CDN/challenge, Expect-CT). Finding-specific remediation packs |
| Risk | Risk is based on CVSS (vector + score) plus FIRST EPSS, CISA KEV, asset criticality and exposure. Each site also gets a separate A–F observatory-style grade |
| Lifecycle | new, triaged, validated, fixed, retest passed, plus false positive and risk accepted (a reason is required). A fixed finding that comes back reopens. SLA due dates are set per severity |
| Evidence | Files are hashed with SHA-256, stored by content and never changed |
| Compliance | Findings map to control objectives and framework requirements (PCI DSS, ISO 27001, SOC 2, ASVS, SEBI CSCRF, CERT-In and others). An assessor can confirm or change each result with a reason |
| Reports | Technical, executive, compliance pack, OWASP Top 10, attestation letter and others. Draft watermark until signed. Submit for QA → QA approve or reject → lead signs. Technical reports include an automated coverage and limitations section |
| Dashboards | Staff metrics at `/dashboard`; per-target grades at `/sites`. Client and auditor roles use the portal |
| Sharing | Read-only share links, a client portal and an auditor view |
| Public verify | Signed reports verify at `/verify/reports/{id}?sig=…` without login |
| Library | Per-tenant writeups; seed or import via `POST /api/library/import` or `attestra library-import` |
| Alerts | Email alerts, certificate expiry warnings and SLA alerts |
| Users | Local users with roles, invites, API keys and optional OIDC |
| Audit | Append-only, hash-chained audit log with a tamper check |
| Interfaces | Web UI, REST API (OpenAPI at `/docs`) and CLI |

### Control statuses

| Status | Meaning |
| --- | --- |
| `met` | Engagement records show the control, or an assessor confirmed it |
| `no_exceptions` | Testing found nothing against the control. This alone does not prove the control is in place |
| `partial` | Open medium findings, or a process is only partly shown |
| `not_met` | Open critical or high findings, or required evidence is missing |
| `not_assessed` | Outside what this engagement tested |

## Requirements

### One-command Docker (recommended)

- Docker Desktop with Compose v2
- Windows 10/11 + WSL2, or macOS (Apple Silicon or Intel)
- Free localhost ports `8000` and `27017`

### Host Python (optional alternative)

- Python 3.11 or newer (3.12 matches the container image)
- A MongoDB replica set (`rs0`), or use the Compose `mongo` service alone
- Docker still required for containerized scanners (ZAP, Nuclei, Trivy, …)

## One-command deployment

From the repository root:

```bash
docker compose up -d --build
```

That starts MongoDB (replica set `rs0`), the API/UI, and the durable job worker.

| Check | URL / command |
| --- | --- |
| UI | http://127.0.0.1:8000 |
| Health | http://127.0.0.1:8000/api/health |
| OpenAPI | http://127.0.0.1:8000/docs |
| Status | `docker compose ps` |

Optional: copy `.env.example` to `.env` and set `ATTESTRA_SESSION_SECRET` / `ATTESTRA_API_KEY_PEPPER` before shared use. Create an admin user:

```bash
docker compose exec api attestra user add admin --role admin --password "YourStrongPass1"
```

Stop without deleting data: `docker compose down`.  
**Destroy volumes (data loss):** `docker compose down -v`.

Full Windows/macOS ops, scanner pins, and troubleshooting: [docs/DOCKER_DEPLOYMENT_GUIDE.md](docs/DOCKER_DEPLOYMENT_GUIDE.md). Infrastructure baseline: [docs/DOCKER_INFRASTRUCTURE_AUDIT.md](docs/DOCKER_INFRASTRUCTURE_AUDIT.md).

## MongoDB setup (host install)

Attestra talks to MongoDB using `ATTESTRA_MONGODB_URI` (default `mongodb://127.0.0.1:27017/?replicaSet=rs0`) and `ATTESTRA_MONGODB_DB` (default `attestra`). Multi-document transactions need a **replica set**. Prefer Compose for local stacks; for a host `mongod`, initialise `rs0` once and harden before non-local use: [docs/mongodb_migration/SECURE_LOCAL_MONGO.md](docs/mongodb_migration/SECURE_LOCAL_MONGO.md).

Example credentialed URI (do not commit passwords):

```
ATTESTRA_MONGODB_URI=mongodb://USER:PASSWORD@127.0.0.1:27017/attestra?replicaSet=rs0&authSource=admin
ATTESTRA_MONGODB_DB=attestra
```

### Copy data between machines

- **Logical Attestra backup** (Mongo export + `ATTESTRA_DATA_DIR` evidence, SHA-256 manifest):

```bash
python -m attestra.cli backup DEST_DIR
python -m attestra.cli restore BACKUP_DIR
```

Restore refuses a backup if the manifest hashes do not match.

- **Point-in-time / replica-set copy:** also use official `mongodump` / `mongorestore` against the same URI (do not put the password on a shared command history if you can avoid it).

### Connection problems

| Symptom | Typical cause |
| --- | --- |
| `ServerSelectionTimeoutError` or `WinError 10061` (connection refused) | `mongod` is not running, or it is listening on another host/port than the URI |
| Timeout only when the URI has `replicaSet=rs0` | The process is up but the replica set was never initiated, or the set name does not match |
| `Command … requires authentication` / Unauthorized | The URI has no user, the user is wrong, or `authSource` is not where the user was created (often `admin`) |
| Startup error that standalone is not supported | URI works, but the deployment is not a replica set |

## Quick start (host venv)

Prefer [One-command deployment](#one-command-deployment) unless you need an editable install.

Windows (PowerShell), with MongoDB reachable (`replicaSet=rs0`):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
# Copy .env.example to .env and set ATTESTRA_MONGODB_URI / secrets.
python -m attestra.cli init
python -m attestra.cli serve --host 127.0.0.1 --port 8000
```

Second window for scans:

```powershell
.\.venv\Scripts\Activate.ps1
python -m attestra.cli worker
```

macOS / Linux:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
python -m attestra.cli init
python -m attestra.cli serve
python -m attestra.cli worker   # second terminal
```

Open http://127.0.0.1:8000. Prefer `python -m attestra.cli` over a stale `attestra` entrypoint.

## Users and passwords

```bash
python -m attestra.cli user add <username> --role lead --password <password>
python -m attestra.cli user set-password <username>         # asks for the new password
python -m attestra.cli user disable <username>
python -m attestra.cli key list                             # also: key create, key revoke <id>
```

Roles are `admin`, `lead`, `tester`, `reviewer`, `client_viewer` and `auditor`. Passwords must be at least 12 characters long and use at least 4 different characters.

The CLI uses `ATTESTRA_DATA_DIR` (default `./data` in the folder you run it from) for evidence, reports and keys, and MongoDB for records. Run it from the same folder as the app, or set `ATTESTRA_DATA_DIR` and the same Mongo URI the server uses.

## Scans and imports

Queue a scan (same permission, ownership and audit path as the UI). `--tool` is one of: `zap`, `nuclei`, `webcheck`, `testssl`, `trivy`, `semgrep`, `gitleaks`, `checkov`, `naabu`, `prowler`, `kube_bench`. Optional `--profile baseline|active|intrusive`.

```bash
python -m attestra.cli --user alice scan 1 2 --tool zap --profile baseline
python -m attestra.cli --user alice import 1 zap zap-report.json
```

The worker must be running. Refused scans print `status=refused` and a reason. Pin scanner images with `ATTESTRA_IMAGE_<TOOL>` (for example `ATTESTRA_IMAGE_ZAP`) before that tool can run in Docker.

## Authenticated testing and mid-scan sessions

Set `ATTESTRA_AUTH_WEB_ENABLED=1` (and `ATTESTRA_CREDENTIAL_FERNET_KEY` for stored test-account secrets). Caps such as `ATTESTRA_AUTH_WEB_MAX_ROUTES` are listed below.

Mid-scan expiry handling is **on unless** you set `ATTESTRA_AUTH_MIDSCAN_ENABLED=0`. ZAP reloads hook headers/cookies, Nuclei re-checks between URL chunks (`ATTESTRA_AUTH_NUCLEI_CHUNK`, default 25), and automated cases are marked **BLOCKED** if the session cannot be recovered. Checklist items are never auto-marked `passed` after auth loss.

Re-login behaviour depends on the profile method:

| Method | Mid-scan recovery |
| --- | --- |
| `form` / `otp` | Existing login in `scan_auth` is run again (bounded by `ATTESTRA_AUTH_RELOGIN_MAX`, default 2) |
| `header` / `cookie` | Static tokens are **not** refreshed unless the profile sets `config_json.refresh_url`. Legacy behaviour (no JSON path) is an empty form POST; only new `Set-Cookie` values are applied. Optional JSON refresh keys (below) can renew a bearer/access token from a refresh endpoint |
| `sso_bootstrap` / `none` | Not automatable |

Optional `config_json` keys for header/cookie JSON refresh (all backward compatible; omit them to keep the legacy empty-POST + `Set-Cookie` path):

| Key | Meaning |
| --- | --- |
| `refresh_url` | Absolute refresh endpoint |
| `refresh_method` | `GET`, `POST` (default), `PUT`, or `PATCH` |
| `refresh_body` | JSON object sent as the body (default `{}`) |
| `refresh_content_type` | `json` or `form`. Defaults to `json` when `refresh_token_json_path` is set |
| `refresh_cookies` | List of cookie **names** to send (for example `["refreshToken"]`). Values come from the profile's encrypted extra-cookie store, never from `config_json` |
| `refresh_headers` | Extra non-secret request headers (`Origin`, `Referer`, `User-Agent`, `x-portal-host`) |
| `refresh_token_json_path` | Dotted JSON path for the new access token (for example `accessToken`) |
| `refresh_apply_as` | `bearer` (replace `Authorization` with `Bearer <token>`), `header:<Name>`, or `cookie:<Name>` |

On success the new access token **replaces** the previous `Authorization` header (it is not duplicated), any `Set-Cookie` values (including a rotated refresh cookie) are merged into the in-memory session for the next refresh, and `on_renew` still rewrites the ZAP hook and Nuclei secret file. The refresh response body is treated as secret and is never logged or stored. A Cloudflare / WAF challenge (`cf-mitigated`, "Just a moment", challenge HTML) records the value-free note `refresh blocked by WAF/challenge`; after bounded retries the scan is **BLOCKED** with a value-free `auth_note`. Browser-only cookies such as `cf_clearance` are not solved automatically.

Example (placeholders only — put the real refresh cookie in the encrypted Extra Cookies / Refresh Cookie Value field, not in config):

```json
{
  "verify_url": "https://app.example.com/api/me",
  "header_name": "Authorization",
  "refresh_url": "https://api.example.com/api/auth/refresh-token",
  "refresh_method": "POST",
  "refresh_body": {},
  "refresh_content_type": "json",
  "refresh_cookies": ["refreshToken"],
  "refresh_headers": {
    "Origin": "https://app.example.com",
    "Referer": "https://app.example.com/",
    "User-Agent": "Mozilla/5.0",
    "x-portal-host": "app.example.com"
  },
  "refresh_token_json_path": "accessToken",
  "refresh_apply_as": "bearer"
}
```

Configure the same fields on the asset Authentication Profile form (Token Refresh). See the UI: method Session Token, paste the current access token as Secret, set Verify URL, then Token Refresh as above with cookie name `refreshToken` and its value in the masked Refresh Cookie Value input.

## Automated security-testing catalogue

Enable the orchestrator with `ATTESTRA_AUTOMATED_VAPT_ENABLED=1`. Catalogue IDs (see `attestra/automated_vapt/core/test_registry.py`) include:

| IDs | Role |
| --- | --- |
| T01, T02 | HTTP and browser capture (Playwright write-body capture feeds T22) |
| T03–T07 | Auth gates, BOLA/IDOR, role enforcement, tenant isolation, disclosure |
| SESSION | Cookie flags and JWT structure (no token forging) |
| INJ, XSS, XSSDOM, XSSSTORE | Safe canaries; stored XSS is extra-gated (see flags) |
| FILE | Path-traversal content-proof probe |
| T08–T18 | Validation, evidence, Burp import, scope, subscription checks |
| T19–T22 | API auth bypass, IDOR (harvested IDs), input replay, BOLA write mutation |
| BIZ, ROLEDIFF | Business-logic catalogue case; read-only two-role compare |
| SSRF, UPLOAD | Scoped SSRF canary; safe upload probe (both extra-gated) |
| SCOPE_SMOKE | Scope/authorization smoke |

If T20/T22 cannot run, they are **SKIPPED** with an explicit reason (`no_auth_session`, `no_object_ids`, `no_write_templates`, `mutation_disabled`, `app_env_blocked`, and similar) — never a silent pass. T22 never sends DELETE; mutation sends only when `ATTESTRA_AUTOMATED_VAPT_MUTATION=1` **and** `APP_ENV` is `local`, `test` or `development`.

Checklist rows (WSTG/ASVS) can be updated from completed scans and automated runs:

```bash
python -m attestra.cli checklist-sync --engagement ENGAGEMENT_ID
python -m attestra.cli checklist-sync --engagement ENGAGEMENT_ID --dry-run
```

## Reports

Generate drafts, then Submit for QA, QA approve or reject, and a lead signs.

```bash
python -m attestra.cli --user alice report 1 technical
python -m attestra.cli --user alice report 1 executive
python -m attestra.cli --user alice report 1 compliance --framework soc2
python -m attestra.cli --user alice report 1 owasp_top10
python -m attestra.cli --user bob submit 7
python -m attestra.cli --user carol qa-approve 7
python -m attestra.cli --user lead sign 7
python -m attestra.cli verify-report 7
```

Other `report` kinds: `iso_soa`, `ageing`, `closure_letter`, `attestation_letter`.

The technical PDF cover leads with the **client name** and scope. Authenticated checklist tables show only executed statuses (`passed`, `failed`, `blocked`); `not_started` stays in the database. A coverage and limitations section lists deferred catalogue capabilities, skip/block reasons (including T20/T22) and mid-scan auth-loss notes. Drafts carry a DRAFT watermark until signed. Reports can be signed with Ed25519 (public key under `data/keys/signing.pub`) or an HMAC fallback.

## Settings

Settings are read from environment variables (typically a `.env` file; copy `.env.example`). Restart the API and workers after changes. **Never put secret values in this README or in git.** The table lists **names**, defaults and purpose only.

### Core and MongoDB

| Variable | Default (when unset) | Purpose |
| --- | --- | --- |
| `APP_ENV` | unset allowed if both bypasses are false | `local`, `test`, `development`, `staging`, or `production`. Bypass and some probes only in local/test/development |
| `ATTESTRA_MONGODB_URI` | `mongodb://127.0.0.1:27017/?replicaSet=rs0` | Mongo connection URI (use credentials once auth is on) |
| `ATTESTRA_MONGODB_DB` | `attestra` | Database name |
| `ATTESTRA_TEST_MONGODB_URI` | unset | Tests only; throwaway DBs must be named `attestra_test_*` |
| `ATTESTRA_MONGODB_GRIDFS_BUCKET` | `attestra_artifacts` | GridFS bucket for artifacts |
| `ATTESTRA_MONGODB_TLS` | off | Enable TLS |
| `ATTESTRA_MONGODB_TLS_CA_FILE` | unset | CA file when TLS is on |
| `ATTESTRA_MONGODB_SERVER_SELECTION_TIMEOUT_MS` | `5000` | Server selection timeout |
| `ATTESTRA_MONGODB_CONNECT_TIMEOUT_MS` | `5000` | Connect timeout |
| `ATTESTRA_MONGODB_SOCKET_TIMEOUT_MS` | `30000` | Socket timeout |
| `ATTESTRA_MONGODB_MAX_POOL_SIZE` | `50` | Pool size |
| `ATTESTRA_PERSISTENCE` | `mongo` | Retained for old env files; runtime is Mongo-only |
| `ATTESTRA_DATA_DIR` | `./data` | Evidence, reports, keys, scanner cache |
| `ATTESTRA_STORAGE` | `mongo` | Artifact store: `mongo` (GridFS), `local`, or `s3` |
| `ATTESTRA_PUBLIC_URL` | — | Address users open (links, emails, verify QR) |
| `ATTESTRA_SESSION_SECRET` | dev placeholder | Session + public verify HMAC; set a long random value outside development |
| `ATTESTRA_API_KEY_PEPPER` | dev placeholder | API key hashing; set outside development |
| `ATTESTRA_API_RATE_LIMIT` | `120` | API rate limit |
| `ATTESTRA_DISPLAY_TZ` | — | Display time zone label |

### Credits and gates

| Variable | Default | Purpose |
| --- | --- | --- |
| `SUBSCRIPTION_SERVICE` | `ON` | `ON` enforces org test-run credits; `OFF` bypasses only those checks |
| `ATTESTRA_INITIAL_TEST_RUN_CREDITS` | `3` | Starting credits for a new tenant |
| `ATTESTRA_CREDIT_REFUND_ON_PRE_START_FAILURE` | `ON` | Refund if queue/dispatch fails before the run starts |
| `ATTESTRA_CREDIT_REFUND_ON_POST_START_FAILURE` | `OFF` | Auto-refund when a started scan later fails |
| `BYPASS_SIGNED_AUTHORIZATION_VERIFICATION` | `false` | Skip signed-authorization gates only in allowlisted `APP_ENV` |
| `BYPASS_TARGET_OWNERSHIP_VERIFICATION` | `false` | Skip ownership policy gate only in allowlisted `APP_ENV` |

Staging/production (or missing `APP_ENV`) with a bypass set to true fails startup.

### Authenticated scans and mid-scan auth

| Variable | Default | Purpose |
| --- | --- | --- |
| `ATTESTRA_AUTH_WEB_ENABLED` | off | Enable authenticated website testing |
| `ATTESTRA_AUTH_WEB_MAX_ROUTES` | `100` | Crawl route cap |
| `ATTESTRA_AUTH_WEB_MAX_DEPTH` | `5` | Crawl depth |
| `ATTESTRA_AUTH_WEB_MAX_DURATION_S` | `600` | Crawl duration |
| `ATTESTRA_AUTH_WEB_RATE_PER_HOST` | `2` | Requests per host |
| `ATTESTRA_AUTH_WEB_CONCURRENCY` | `2` | Crawl concurrency |
| `ATTESTRA_CREDENTIAL_FERNET_KEY` | — | Fernet key for test-account secrets |
| `ATTESTRA_CREDENTIAL_ALLOW_EPHEMERAL` | — | Dev/tests only: process-local key if Fernet key is unset |
| `ATTESTRA_AUTH_MIDSCAN_ENABLED` | on (unset = on) | Mid-scan expiry checks; set `0`/`false`/`no` for preflight only |
| `ATTESTRA_AUTH_RELOGIN_MAX` | `2` | Re-login attempts per scan (0–10) |
| `ATTESTRA_AUTH_RELOGIN_MIN_INTERVAL_S` | `5` | Minimum spacing between re-login attempts |
| `ATTESTRA_AUTH_HEARTBEAT_S` | `120` | Liveness poll interval (minimum 10) |
| `ATTESTRA_AUTH_NUCLEI_CHUNK` | `25` | Nuclei URLs per chunk between session checks |

### Automated VAPT safety flags

| Variable | Default | Purpose |
| --- | --- | --- |
| `ATTESTRA_AUTOMATED_VAPT_ENABLED` | off | Enable the automated catalogue orchestrator |
| `ATTESTRA_AUTOMATED_VAPT_MUTATION` | off | Allow T22 write-body sends (still requires allowlisted `APP_ENV`; never DELETE) |
| `ATTESTRA_AUTOMATED_VAPT_SSRF` | off | Allow active SSRF canaries outside local/test/development |
| `ATTESTRA_AUTOMATED_VAPT_UPLOAD` | off | Allow safe upload probes outside local/test/development |
| `ATTESTRA_AUTOMATED_VAPT_STORED_XSS` | off | Allow stored XSS canaries outside local/test/development |
| `ATTESTRA_SSRF_CANARY_URL` | built-in invalid canary host | Callback URL for SSRF probes |
| `ATTESTRA_AUTOMATED_VAPT_MAX_URLS` | built-in cap | Capture URL cap |
| `ATTESTRA_AUTOMATED_VAPT_JS_API` | — | JS API discovery toggle |
| `ATTESTRA_AUTOMATED_VAPT_JS_FILES` | built-in | Max JS files to fetch for API discovery |
| `ATTESTRA_AUTOMATED_VAPT_JS_SECONDS` | built-in | Time budget for JS discovery |

### Worker, scanners, mail, SSO, storage

| Variable | Default | Purpose |
| --- | --- | --- |
| `ATTESTRA_WORKER_CONCURRENCY` | `2` (max 8) | Parallel scan jobs; Nuclei stays serial |
| `ATTESTRA_JOB_MAX_ATTEMPTS` | `3` | Job retries |
| `ATTESTRA_JOB_STALE_HEARTBEAT_S` | `120` | Stale job heartbeat |
| `ATTESTRA_SCANNER_TIMEOUT_S` | `600` | Default scanner timeout; per-tool `ATTESTRA_SCANNER_TIMEOUT_<TOOL>` also exists |
| `ATTESTRA_SCAN_RATE_PER_ASSET` | `10` | Scan rate per asset |
| `ATTESTRA_IMAGE_<TOOL>` | placeholders | Docker image pin (digest) per tool |
| `ATTESTRA_HSTS_PRELOAD_LOOKUP` | off | Check the HSTS preload list |
| `ATTESTRA_DNS_RESOLVERS` | — | Resolvers for ownership checks |
| `ATTESTRA_NUCLEI_MAX_URLS`, `ATTESTRA_NUCLEI_CRAWL`, `ATTESTRA_NUCLEI_MAX_HOST_ERRORS` | — | Nuclei crawl/limits |
| `ATTESTRA_SMTP_HOST`, `ATTESTRA_SMTP_PORT`, `ATTESTRA_SMTP_USER`, `ATTESTRA_SMTP_PASSWORD`, `ATTESTRA_SMTP_FROM`, `ATTESTRA_SMTP_TLS` | unset / mail off unless host set | Invites and alerts |
| `ATTESTRA_OIDC_*` | disabled unless `ATTESTRA_OIDC_ENABLED` | SSO (`ISSUER`, `CLIENT_ID`, `CLIENT_SECRET`, `AUDIENCE`, `JWKS_URL`, `ALGORITHMS`, `USERNAME_CLAIM`, `TENANT_CLAIM`, `AUTO_PROVISION`) |
| `ATTESTRA_S3_BUCKET`, `ATTESTRA_S3_ENDPOINT`, `ATTESTRA_S3_OBJECT_LOCK` | — | S3 evidence (`pip install -e ".[s3]"`) |
| `ATTESTRA_SECRETS_BACKEND` | `env` | Secrets backend (`env` or Vault-related `ATTESTRA_VAULT_*`) |
| `ATTESTRA_AI_*` | off | Optional AI draft text (`PROVIDER`, `MODEL`, `BASE_URL`, `API_KEY`, `NARRATIVES`, `TENANTS_OFF`) — keep keys in the environment, never in the repo |
| `ATTESTRA_METRICS_TOKEN`, `ATTESTRA_METRICS_ENABLED`, `ATTESTRA_METRICS_ALLOW_ANON` | — | `/metrics` |
| `ATTESTRA_LOG_JSON`, `ATTESTRA_LOG_LEVEL` | — | Logging |
| `ATTESTRA_EVIDENCE_MAX_BYTES` | `20971520` | Evidence size cap |
| `ATTESTRA_ORCHESTRATOR` | `inline` | `inline` worker or `temporal` (`ATTESTRA_TEMPORAL_*`) |
| `ATTESTRA_TICKETS_*`, `ATTESTRA_JIRA_*`, `ATTESTRA_GITHUB_*`, `ATTESTRA_AZDO_*`, `ATTESTRA_SERVICENOW_*`, `ATTESTRA_GRC_*` | — | Optional ticketing / GRC integrations |
| `ATTESTRA_GSB_ENABLED`, `ATTESTRA_GSB_API_KEY` | off | Optional Google Safe Browsing in webcheck |

Authenticated website testing notes: [docs/AUTH_WEB_TESTING.md](docs/AUTH_WEB_TESTING.md).

## CLI command reference

Run `python -m attestra.cli --help` for flags. Global options include `--user`, `--api-key` (or `ATTESTRA_API_KEY`) and `--actor`.

| Command | Purpose |
| --- | --- |
| `init` | Connect to MongoDB and apply schema |
| `demo` | Load a synthetic demo engagement |
| `serve [--host] [--port]` | API and dashboard (default 127.0.0.1:8000) |
| `worker [--poll] [--concurrency]` | Durable scan worker |
| `user add` / `user set-password` / `user disable` | Local users |
| `key create` / `key list` / `key revoke` | API keys |
| `scan` | Queue a scan |
| `import` | Import a scanner result file |
| `findings` | List findings by risk |
| `transition` | Move a finding through its lifecycle |
| `accept-risk` / `expire-risk` | Residual risk records |
| `enrich [--kev] [--epss] [--refresh]` | CISA KEV / FIRST EPSS feeds |
| `checklist-sync` | Auto-update WSTG/ASVS checklist from completed work |
| `compliance` / `compliance-export` / `library-import` / `soc2-sample` | Framework status and libraries |
| `report` / `submit` / `qa-approve` / `qa-reject` / `sign` / `approve` | Draft, QA and sign-off (`approve` is the legacy four-eyes path) |
| `verify-report` / `verify-audit` | Check report hash/signature and the audit chain |
| `backup` / `restore` | Mongo + data-dir backup with manifest |
| `purge` | Retention purge (default dry-run; `--execute` to delete) |
| `cert-expiry-check` / `sla-alert-check` | Daily cert and SLA jobs |
| `migrate-storage` | Move legacy files under `tenants/<id>/` |
| `mongo-migrate validate` / `mongo-migrate status` | Audit-chain / checkpoint helpers (SQL import subcommands are archived) |

KEV JSON comes from CISA (`known_exploited_vulnerabilities.json`). EPSS CSV comes from FIRST (`epss_scores-current.csv.gz`, unzipped).

## Tests

```bash
python -m pytest -q
ruff check .
```

Targeted suites used while building recent validation, auth-guard, catalogue and report work (optional):

```bash
python -m pytest -q --tb=line ^
  tests/test_finding_validation_classify.py ^
  tests/test_finding_validation_headers.py ^
  tests/test_remediation_match.py ^
  tests/test_session_guard.py ^
  tests/automated_vapt/test_e19_replay_checks.py ^
  tests/automated_vapt/test_e20_body_mutation.py ^
  tests/automated_vapt/test_phase3a_biz_rolediff.py ^
  tests/automated_vapt/test_phase3b_ssrf_upload.py ^
  tests/automated_vapt/test_phase3c_xss_injection.py ^
  tests/automated_vapt/test_lab_regression.py ^
  tests/test_phase5_report_coverage_limitations.py
```

Lab fixtures (WAF/challenge, conflicting headers, session expiry, vulnerable and secure mocks) live under `tests/automated_vapt/fixtures/`. Some report tests need a working authenticated `ATTESTRA_MONGODB_URI` (or `ATTESTRA_TEST_MONGODB_URI`).

## Project layout

```
attestra/
  importers/          result file parsers
  runner/             permission/ownership checks and in-app scanners (ZAP, Nuclei, …)
  auth_web/           authenticated testing: profiles, crawl, checklist, session_guard
  automated_vapt/     catalogue, orchestrator, capture, test modules, coverage_matrix
  finding_validation/ import-time classify / evidence contradiction / reconcile
  remediation/        finding-specific fix packs (not generic CSP fallback)
  credentials/        Fernet-backed engagement secret store
  jobs/               durable scan queue used by the worker
  persistence/mongo/  Mongo client, GridFS, schema migrations, MongoSession
  compliance/         control mapping engine and data
  library/            findings library
  reports/            templates, PDF/DOCX, QA, signing, coverage limitations
  verify/             public signed-report verification
  users/, auth/       users, roles, sessions, API keys, OIDC
  share/, alerts/     share links, email alerts, expiry checks
  ops/                backup / restore
  services.py         business rules shared by the API and CLI (writes are audited)
  models.py           data model (SQLAlchemy mapped onto Mongo)
  audit.py            hash-chained audit log
  grade.py            observatory-style site grade (separate from CVSS)
  api.py, web/        REST API and UI
  cli.py              command line
docs/                 design, security and guides
lat.md/               short notes on how each part works
tests/                unit, importer, lab and sample data
```

## Before production

- **Control library review.** Control references and titles in `attestra/compliance/data/` are paraphrased. Check them against licensed PCI SSC, ISO and AICPA texts.
- **Signing.** Reports can be signed with Ed25519 (`data/keys/signing.pub` for external verify) or HMAC over `ATTESTRA_SESSION_SECRET`. Prefer a dedicated signing key in production.
- **MongoDB.** Use a replica set, authentication, network binding you intend, and regular `mongodump` plus `attestra backup`.
- **Storage.** For evidence at scale, GridFS or S3 Object Lock (compliance mode), and a separate encryption key per tenant.
- **Secrets.** Set `ATTESTRA_SESSION_SECRET` and `ATTESTRA_API_KEY_PEPPER`. If auth-web is enabled, set `ATTESTRA_CREDENTIAL_FERNET_KEY` (do not use ephemeral keys outside local/dev).
- **Licensing.** Scanners run from their own Docker images and are not bundled. Review AGPL, GPL and NPSL terms before bundling any tool.
