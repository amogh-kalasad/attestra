# Attestra Docker deployment guide

How to run the full Attestra stack with one Compose command on Windows or macOS. Reflects the verified root `compose.yaml` layout.

## One-command start

From the repository root, with Docker Desktop running:

```bash
docker compose up -d --build
```

This builds the app image, starts MongoDB with replica set `rs0`, initializes the set, starts the API (after `attestra init`), runs one-shot `scanner-pull` (validates + pulls digest-pinned ZAP/Nuclei/testssl/Naabu), and starts the durable job worker.

- UI / API: http://127.0.0.1:8000  
- OpenAPI: http://127.0.0.1:8000/docs  
- Health: http://127.0.0.1:8000/api/health  
- Mongo (loopback only): `mongodb://127.0.0.1:27017/?replicaSet=rs0`

Copy `.env.example` to `.env` and set secrets before any shared or production use. Compose loads `.env` when present.

## Services

| Service | Role | Ports |
| --- | --- | --- |
| `mongo` | MongoDB 7, `--replSet rs0`, named volume | `127.0.0.1:27017` |
| `mongo-init` | One-shot idempotent `rs.initiate` | none |
| `api` | FastAPI + UI; runs `attestra init` then `serve` | `127.0.0.1:8000` |
| `scanner-pull` | One-shot: refuse placeholder digests and `docker pull` ZAP/Nuclei/testssl/Naabu | none |
| `worker` | Durable scan job worker (waits for `scanner-pull`) | none (Docker socket mounted for scanner `docker run`) |

Scanner digest defaults live in `compose.yaml` and `docker/scanner-digests.env` (`ATTESTRA_IMAGE_ZAP` / `NUCLEI` / `TESTSSL` / `NAABU`). Override in root `.env` when you need newer pins. `webcheck` needs no image.

Automated VAPT stays **disabled** (`ATTESTRA_AUTOMATED_VAPT_ENABLED=false`).

## Prerequisites

### Windows

- Windows 10/11 with Docker Desktop and WSL2 backend  
- Enough disk for images and Mongo/app volumes  
- Ports `8000` and `27017` free on localhost  

### macOS

- Docker Desktop (Apple Silicon or Intel)  
- Same port requirements  

## Common commands

```bash
docker compose up -d --build    # build and start
docker compose ps               # status / health
docker compose logs -f api      # API logs
docker compose logs -f worker   # worker logs
docker compose restart worker   # restart one service
docker compose down             # stop; keep volumes (data preserved)
docker compose down -v          # stop AND delete volumes (DESTROYS Mongo/app data)
```

Create an admin user (password ≥12 chars, ≥4 distinct) **inside the API container**:

```bash
docker compose exec api attestra user add admin --role admin --password "YourStrongPass1"
```

Do not run `attestra user add` on the Windows/macOS host against Compose Mongo unless
`ATTESTRA_MONGODB_URI` includes `directConnection=true` (see root `.env`). The Compose
replica set advertises hostname `mongo`, which only resolves on the Docker network; a
host CLI without `directConnection=true` times out and the user is never written.

## Environment

See `.env.example` for the full list. Compose overrides Mongo to `mongodb://mongo:27017/?replicaSet=rs0` on the internal network.

Scanner containers need real digest pins:

```text
ATTESTRA_IMAGE_ZAP=ghcr.io/zaproxy/zaproxy@sha256:…
ATTESTRA_IMAGE_NUCLEI=…
# … TRIVY SEMGREP TESTSSL NAABU GITLEAKS CHECKOV
```

Placeholder all-zero digests refuse to run (by design).

## Health checks

- API / image: HTTP `GET /api/health` (includes Mongo ping)  
- Mongo: `mongosh` ping  
- Worker: Python import of `attestra` (no HTTP port)  

Worker instance locks survive container restart (PID-namespace-aware steal in `InstanceLock`).

## Security notes

- Mongo is published on loopback only, without auth in the default local Compose profile. Harden before any non-local use (`docs/mongodb_migration/SECURE_LOCAL_MONGO.md`).  
- Worker mounts the host Docker socket for scanner runs. That is a **dev/compose tradeoff**; do not copy it blindly into production. Production path is digest-pinned Kubernetes Jobs (Helm chart under `deploy/helm/attestra`).  
- Do not enable ownership/authorization bypasses outside `APP_ENV=local|test|development`.  
- Keep `ATTESTRA_AUTOMATED_VAPT_ENABLED` false unless you intentionally enable it.

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Build fails on `.[postgres]` | Stale Dockerfile | Use current root `Dockerfile` (`pip wheel "."`) |
| API unhealthy, mongo.ok false | Replica set not primary | Check `docker compose logs mongo-init`; recreate mongo volume only if empty/dev |
| Worker exits “another worker holds the instance lock” | Stale lock (pre-fix images) | Rebuild images; or `docker compose exec api rm -f /data/.lock-worker` then restart worker |
| Scans stay Queued | Worker down | `docker compose ps` / `logs worker` |
| Scanner refuses image | Placeholder digest | Set `ATTESTRA_IMAGE_<TOOL>` to a real `@sha256:` pin |
| `docker was not found` from worker | Image lacked Docker CLI, or socket not usable | Rebuild so [[Dockerfile]] includes the Docker client; worker needs socket mount + `group_add: ["0"]`; set `ATTESTRA_DOCKER_HOST_DATA_DIR` to the absolute host path of `./data` |
| Nuclei `secrets file '/attestra-secrets/...' does not exist` | Auth secrets written under container `/tmp`, invisible to host Docker | Set `ATTESTRA_AUTH_SECRET_DIR=/data/auth-secrets` on the worker (compose default) and recreate worker |
| Port in use | Local process or old container | Stop the other listener; `docker ps` |

## Related docs

- Baseline audit: `docs/DOCKER_INFRASTRUCTURE_AUDIT.md`  
- Specialist audits: `docs/audit/`  
- Helm / k8s: `deploy/README.md`  
- Secure Mongo: `docs/mongodb_migration/SECURE_LOCAL_MONGO.md`  
