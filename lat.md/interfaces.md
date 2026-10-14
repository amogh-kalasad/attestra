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
| POST | `/api/reports/{rid}/approve` | Four-eyes approve |
| GET | `/api/audit/verify` | Audit chain check |
| GET | `/api/audit/export` | Audit export JSON/CSV + chain proof |
| GET | `/api/evidence/{eid}/download` | Download evidence (audited) |

Writes require [[attestra/api.py#get_principal]] (Bearer or session) and [[attestra/api.py#require]] for the route permission. Service errors map via [[attestra/api.py#_run]].

## CLI

Command-line entrypoint sharing the same services layer.

[[attestra/cli.py]] — `attestra` entrypoint: init, demo, user add, key create, migrate-storage, serve, worker, import, enrich (`--refresh`), purge, backup, restore, transition, compliance, report, approve, verify-report, verify-audit, findings. Identity via `--api-key` / `ATTESTRA_API_KEY` or `--user`.

## Web dashboard

Server-rendered UI served alongside the API. Login at `/login` ([[attestra/web/ui.py#login]]); session cookie replaces the old free-text actor bar.

[[attestra/web/ui.py]] — server-rendered UI mounted with the API.

## Configuration

Environment variables and on-disk data layout.

[[attestra/config.py]]:

- `ATTESTRA_DATA_DIR` — evidence/imports/reports/keys/feeds (default `./data`)
- `ATTESTRA_DATABASE_URL` — SQLite by default; PostgreSQL via `postgresql+psycopg://…`
- `ATTESTRA_STORAGE` — `local` (default) or `s3` ([[attestra/storage/__init__.py#get_storage]])
- `ATTESTRA_S3_BUCKET` / `ATTESTRA_S3_ENDPOINT` / `ATTESTRA_S3_OBJECT_LOCK` — S3 backend
- `ATTESTRA_KEV_URL` / `ATTESTRA_EPSS_URL` — feed URLs for `enrich --refresh`
