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

Writes require [[attestra/api.py#actor]] (`X-Attestra-Actor`). Service errors map via [[attestra/api.py#_run]].

## CLI

Command-line entrypoint sharing the same services layer.

[[attestra/cli.py]] — `attestra` entrypoint: demo, serve, import, enrich, transition, compliance, report, approve, verify-report, verify-audit, findings.

## Web dashboard

Server-rendered UI served alongside the API.

[[attestra/web/ui.py]] — server-rendered UI mounted with the API.

## Configuration

Environment variables and on-disk data layout.

[[attestra/config.py]]:

- `ATTESTRA_DATA_DIR` — evidence/imports/reports/keys (default `./data`)
- `ATTESTRA_DATABASE_URL` — SQLite by default; PostgreSQL via `postgresql+psycopg://…`
