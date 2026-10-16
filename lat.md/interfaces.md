# Interfaces

Three surfaces share [[attestra/services.py]] so business rules stay in one place.

## REST API

FastAPI routes and actor header for write operations.

[[attestra/api.py]] — FastAPI app with OpenAPI at `/docs`.

Notable routes:

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Liveness |
| GET | `/api/catalog` | Asset kinds + test types |
| POST/GET | `/api/engagements` | Create / list |
| POST | `/api/engagements/{eid}/authorizations` | Upload signed auth |
| POST | `/api/engagements/{eid}/assets` | Add target |
| POST | `/api/engagements/{eid}/imports` | Import scanner file |
| GET | `/api/engagements/{eid}/findings` | List findings |
| POST | `/api/findings/{fid}/transition` | Lifecycle change |
| GET | `/api/engagements/{eid}/compliance` | Control roll-up |
| POST | `/api/engagements/{eid}/reports` | Generate report |
| POST | `/api/reports/{rid}/submit` | Submit for QA |
| POST | `/api/reports/{rid}/qa-approve` | QA approve |
| POST | `/api/reports/{rid}/qa-reject` | QA reject with a note |
| POST | `/api/reports/{rid}/sign` | Approve and sign |
| POST | `/api/reports/{rid}/approve` | Four-eyes approve |
| GET | `/reports/{rid}` | View report with sign-off record on top |
| GET | `/reports/{rid}/sealed` | Download the sealed file unchanged |
| GET | `/api/audit/verify` | Audit chain check |
| GET | `/api/audit/export` | Audit export JSON/CSV + chain proof |
| GET | `/api/evidence/{eid}/download` | Download evidence (audited) |

Writes require [[attestra/api.py#get_principal]] (Bearer or session) and [[attestra/api.py#require]] for the route permission. Service errors map via [[attestra/api.py#_run]].

## CLI

Command-line entrypoint sharing the same services layer.

[[attestra/cli.py]] — `attestra` entrypoint: init, demo, user add, user set-password, key create, migrate-storage, serve, worker, import, enrich (`--refresh`), purge, backup, restore, transition, compliance, report, approve, verify-report, verify-audit, findings. Identity via `--api-key` / `ATTESTRA_API_KEY` or `--user`.

`attestra user set-password <username>` ([[attestra/cli.py#cmd_user_set_password]]) sets a local user's password. Without `--password` it asks twice at a hidden prompt and stops if the two do not match. [[attestra/users/service.py#set_password]] finds the user by name (exact, then case-insensitive), refuses SSO users, applies the same rules as [[attestra/users/service.py#validate_password]] (at least 12 characters, not the username, not too simple), revokes open reset links, and writes a `user.password_set` audit event with the CLI login name as actor. If the account is disabled, the command says it cannot sign in until an admin enables it.

## Web dashboard

Server-rendered UI served alongside the API. Login at `/login` ([[attestra/web/ui.py#login]]); session cookie replaces the old free-text actor bar.

[[attestra/web/ui.py]] — server-rendered UI mounted with the API.

Report lifecycle buttons post to `/engagements/{eid}/reports/{rid}/submit`, `/qa-approve`, `/qa-reject` and `/sign`; see [[reports#Workflow]]. Report links open `/reports/{rid}` in a new tab with the sign-off record on top ([[reports#Sign-off record]]).

### Target history (C11)

Per-target page at `/engagements/{eid}/targets/{aid}` ([[attestra/web/ui.py#target_page]], template `asset.html`).

[[attestra/history.py#asset_scan_history]] lists finished scans for that target with date, tool, A–F grade ([[attestra/history.py#scan_letter_grade]]), severity counts, and new/fixed/still-open vs the previous scan of the **same tool** ([[attestra/history.py#diff_fingerprints]]). Snapshots come from each scan’s saved raw/import file. The page shows a small trend chart via [[attestra/history.py#trend_svg]] (same chart the technical report uses). Engagement target rows link to this page.

Shared look-and-feel lives in `attestra/web/templates/_layout.html` (staff/portal) and `attestra/web/templates/_public.html` (Trust Center). Authenticated pages use a light app shell: white sidebar (Work / Library / Ops), sticky top bar, and content workspace. `attestra/web/templates/login.html` is a standalone split-screen sign-in (brand panel + form) matching the product login sample; it still posts username/password to [[attestra/web/ui.py#login]]. Visual system uses Geist + Geist Mono and indigo `#4338CA`. Page templates (engagements home, engagement detail, new engagement, PCI calendar, users, report templates, library, portal) follow that shell with KPI strips, status pills, breadcrumbs, and stepped progress where the product UI samples define them. Routes, forms, and permissions are unchanged.

## Scheduled scans and CI gates

Recurring scan schedules and a pass/fail check that CI pipelines can call.

- Schedules: `GET/POST /api/engagements/{eid}/schedules`, `PATCH/DELETE /api/engagements/{eid}/schedules/{sid}`, and `POST /api/engagements/{eid}/schedules/run-due` ([[attestra/api.py#run_due_schedules]]). Cadence is `quarterly` or `monthly` ([[attestra/services.py#update_scan_schedule]]); due schedules are queued by [[attestra/services.py#enqueue_due_schedules]] through the normal scan gate. Managing them needs `scan.start`; listing needs `scan.read`.
- CI gate: `GET /api/engagements/{eid}/gate` runs [[attestra/services.py#ci_gate]]. It fails when open findings at or above `fail_on` (default `high`) are more than `max_findings` (default 0). `tool` limits the check to one importer. Accepted-risk, fixed and false-positive findings never block. The answer lists counts by severity and up to 50 blocking findings.

[[attestra/services.py#list_scan_schedules]], [[attestra/services.py#update_scan_schedule]], and [[attestra/services.py#remove_scan_schedule]] manage cadence and due dates. [[attestra/services.py#ci_gate]] fails a pipeline when open findings at or above `fail_on` exceed `max_findings` (accepted-risk / fixed / false-positive do not block).

## Configuration

Environment variables and on-disk data layout.

[[attestra/config.py]]:

- `ATTESTRA_DATA_DIR` — evidence/imports/reports/keys/feeds (default `./data`)
- `ATTESTRA_DATABASE_URL` — SQLite by default; PostgreSQL via `postgresql+psycopg://…`
- `ATTESTRA_STORAGE` — `local` (default) or `s3` ([[attestra/storage/__init__.py#get_storage]])
- `ATTESTRA_S3_BUCKET` / `ATTESTRA_S3_ENDPOINT` / `ATTESTRA_S3_OBJECT_LOCK` — S3 backend
- `ATTESTRA_KEV_URL` / `ATTESTRA_EPSS_URL` — feed URLs for `enrich --refresh`

## Product marketing page

Standalone AntHive-branded HTML describing implemented Attestra capabilities for the public website.

`docs/marketing/attestra.html` is a self-contained product page (hero, problem, solution workflow, features, advantages, report deliverables, audiences, CTA). Claims track `README.md`, [[architecture]], [[reports]], and report templates under `attestra/reports/templates`. It is not served by the app; drop it into anthive.tech when integrating.
