# AASI Phase 9 — Docker / deployment guide

How to run Attestra with optional AASI (Attestra Agentic Security Intelligence) scanners
on branch `attestra-asi-bundle` without changing the default Compose stack. Companion
completion note: [`AASI_PHASE9_COMPLETION.md`](AASI_PHASE9_COMPLETION.md). General
Compose ops: [`../DOCKER_DEPLOYMENT_GUIDE.md`](../DOCKER_DEPLOYMENT_GUIDE.md). Helm:
[`../../deploy/README.md`](../../deploy/README.md).

**Default posture:** `ATTESTRA_AASI=off`. AI scanner images stay **out** of the app
image and are **not** pulled by the required `scanner-pull` service. Enable AASI and
pull AI images only after real digest pins replace placeholders.

---

## 1. Main app image (already present)

Root `Dockerfile` is multi-stage (`python:3.12-slim` build → runtime):

| Practice | Behaviour |
|---|---|
| One image, two roles | Default `CMD` → `attestra serve`; override → `attestra worker` |
| Non-root | `USER 10001:10001` (`attestra`) |
| Scanners not baked in | Only Docker **CLI** for compose/dev docker-out-of-Docker; tools run as separate images |
| Healthcheck | `GET http://127.0.0.1:8000/api/health` |
| Data volume | `/data` (`ATTESTRA_DATA_DIR`) |
| Mongo defaults | Compose-friendly URI; production **must** override with credentials/TLS |

Build:

```bash
docker build -t attestra:dev .
```

Do **not** add Garak / Promptfoo / SafeLabs / PyRIT packages to the app image (licence
isolation and supply-chain boundary — see `AASI_LICENSE_REVIEW.md`).

---

## 2. Scanner isolation

| Plane | What runs | Isolation |
|---|---|---|
| API / worker containers | Attestra package only | Non-root; no scanner binaries |
| Web scanners (default Compose) | ZAP / Nuclei / testssl / Naabu via worker `docker run` | Digest-pinned; `--security-opt no-new-privileges` (`attestra/runner/scanners/base.py#docker_run_argv`); DNS pin via `--add-host` |
| AASI AI scanners | Garak / Promptfoo / SafeLabs / PyRIT adapters | Same pattern; placeholders refused by `image_is_placeholder` |
| Production (Helm) | Ephemeral Jobs (`deploy/helm/attestra/templates/scanner-job.yaml`) | `allowPrivilegeEscalation: false`, drop `ALL` caps, NetworkPolicy egress to pinned IP `/32`, resource requests/limits |

**Never** run scanner containers `--privileged`. Compose workers mount the Docker socket
for local DooD only — that is a **dev tradeoff**; production uses Jobs, not a socket
mount (`deploy/README.md`).

---

## 3. Digest pins (Garak / Promptfoo / SafeLabs / PyRIT)

Env keys (also listed in `AASI_ENV_INVENTORY.md` / `docker/scanner-digests.env`):

| Variable | Tool | Status in repo |
|---|---|---|
| `ATTESTRA_IMAGE_GARAK` | Garak | Placeholder in `config._PLACEHOLDER_IMAGES`; commented stub in `docker/scanner-digests.env` |
| `ATTESTRA_IMAGE_PROMPTFOO` | Promptfoo | Same |
| `ATTESTRA_IMAGE_SAFELABS` | safelabs-eval | Same |
| `ATTESTRA_IMAGE_PYRIT` | PyRIT multi-turn worker | Placeholder in config (`attestra/pyrit-worker@sha256:…000f`); commented stub in digests file — pin after inspect |

Placeholders (all-zero-style digests) are **refused** at runtime. After you pull a
candidate tag once, pin the digest:

```bash
# Example workflow (operator machine; replace repo:tag with the approved release)
docker pull docker.io/nvidia/garak:latest
docker image inspect --format '{{index .RepoDigests 0}}' docker.io/nvidia/garak:latest

# Put the repo@sha256:… value in root .env (never commit real production secrets)
# ATTESTRA_IMAGE_GARAK=docker.io/nvidia/garak@sha256:<real>
# ATTESTRA_IMAGE_PROMPTFOO=…@sha256:<real>
# ATTESTRA_IMAGE_SAFELABS=…@sha256:<real>
# ATTESTRA_IMAGE_PYRIT=…@sha256:<real>
```

Reconcile Promptfoo registry naming (`ghcr.io/promptfoo/…` vs `docker.io/promptfoo/…`)
at pin time so `.env`, digests file comments, and `config` defaults agree.

Web-tool pins remain required for default Compose (`ATTESTRA_IMAGE_ZAP` / `NUCLEI` /
`TESTSSL` / `NAABU`) and are pulled by the existing `scanner-pull` one-shot.

---

## 4. Resource limits and no-privileged policy

### Compose (local)

Default `compose.yaml` does not set CPU/memory limits on `api` / `worker` (lab
convenience). For a constrained host, add under each service (example only):

```yaml
    deploy:
      resources:
        limits:
          cpus: "2.0"
          memory: 2G
        reservations:
          cpus: "0.25"
          memory: 256M
```

(`deploy.resources` applies when the Compose engine supports it; Docker Compose v2 /
Swarm semantics vary — prefer Docker Desktop resource caps for pure local lab.)

Scanner `docker run` always includes `--security-opt no-new-privileges`. Do not add
`--privileged` or broad `--cap-add`. Optional per-run caps can be passed via adapter
`extra_flags` only when reviewed.

### Helm (production pattern)

From `deploy/helm/attestra/values.yaml`:

- API / worker: requests `100m` / `256Mi`, limits `1` CPU / `1Gi`
- Example scanner Job: requests `250m` / `512Mi`, limits `2` CPU / `2Gi`
- Pod: `runAsNonRoot`, uid/gid `10001`, `RuntimeDefault` seccomp
- Container: `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`,
  `readOnlyRootFilesystem: true` (API/worker)

Keep `scanner.exampleJob.enabled: false` until an image is digest-pinned and the
egress IP is set.

---

## 5. Feature flag and safe defaults

| Knob | Safe default | Notes |
|---|---|---|
| `ATTESTRA_AASI` | `off` | Master flag; when off, `/api/aasi/status` → `{enabled: false}`, other AASI routes 404 |
| `ATTESTRA_AASI_REQUIRE_APPROVAL` | `on` | Human approval before intrusive / execution path |
| Budget `ATTESTRA_AASI_MAX_*` | Bounded (see inventory) | Iterations / tasks / tokens / wall clock |
| AI narratives | Existing `ATTESTRA_AI_*` | Do not invent `ATTESTRA_AASI_PROVIDER` |
| Bypass flags | `false` | Staging/production refuse ownership/auth bypasses |

Env inventory: [`AASI_ENV_INVENTORY.md`](AASI_ENV_INVENTORY.md). Draft defaults:
[`AASI_PHASE8_ENV_DRAFT.md`](AASI_PHASE8_ENV_DRAFT.md).

---

## 6. Validate env and health (example commands)

Prefer the stub script (prints **names and pass/fail only**, never secret values):

```bash
# From repo root, with the same env the API/worker will see
python scripts/aasi/validate_aasi_env.py
python scripts/aasi/validate_aasi_env.py --require-aasi-on   # fail if ATTESTRA_AASI is off
python scripts/aasi/validate_aasi_env.py --require-ai-images # fail if GARAK/PROMPTFOO/SAFELABS still placeholders
```

Compose / CLI health (existing Attestra surface — no new CLI subcommand required):

```bash
docker compose up -d --build
docker compose ps
docker compose exec api python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).read().decode())"
# Optional helper already in-tree:
# docker compose exec api sh /path/not-mounted — prefer inline python above or image HEALTHCHECK

# AASI advertising status (works when flag is off)
docker compose exec api python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/api/aasi/status', timeout=4).read().decode())"
```

Host CLI against Compose Mongo needs `directConnection=true` in `ATTESTRA_MONGODB_URI`
(see `DOCKER_DEPLOYMENT_GUIDE.md`). Inside the API container, hostname `mongo` resolves.

Admin bootstrap (unchanged):

```bash
docker compose exec api attestra user add admin --role admin --password "YourStrongPass1"
docker compose exec api attestra init
```

---

## 7. Optional Compose AI scanner pull (commented only)

Root `compose.yaml` may include a **fully commented** `aasi-scanner-pull` example that
mirrors `scanner-pull` for Garak / Promptfoo / SafeLabs. It is **not** a required
service. Uncomment only after `.env` holds real digests; do not wire `worker`
`depends_on` to it unless you intentionally want AI images before workers start.

Default `docker compose up -d --build` behaviour is unchanged: mongo → mongo-init →
api → scanner-pull (web) → worker / worker-2.

---

## 8. Rollback notes

| Scenario | Action |
|---|---|
| Disable AASI immediately | Set `ATTESTRA_AASI=off` in `.env` / Secret; restart API (and worker if it reads the flag at process start). Recommend-only routes stop advertising; deterministic VA/PT unchanged |
| Bad AI scanner digest | Revert `ATTESTRA_IMAGE_*` to the previous known-good pin (keep pins in change control). Placeholders refuse runs instead of floating tags |
| Bad app image | Redeploy previous `attestra:<tag>` / digest; Helm: `helm rollback attestra` |
| Compose lab reset (keep data) | `docker compose down` (omit `-v`) |
| Compose wipe | `docker compose down -v` — **destroys** Mongo/app volumes |
| Helm scanner Job | Leave `exampleJob.enabled: false`; delete any manual Job; NetworkPolicy remains deny-by-default |
| Evidence / Mongo | Additive AASI collections (`aasi_runs` / `aasi_decisions`); disabling the flag does not drop data — drop only with an explicit maintenance procedure |

Always prefer digest pins over mutable tags so rollback targets are bit-for-bit known.

---

## 9. Production checklist (short)

1. `APP_ENV=staging` or `production`; unique `ATTESTRA_SESSION_SECRET` / `ATTESTRA_API_KEY_PEPPER`
2. Authenticated Mongo URI + TLS; no Docker socket on workers
3. `ATTESTRA_AASI=off` until digests, RoE, and approval path are ready
4. Real `@sha256:` pins for every AI tool you enable; run `validate_aasi_env.py --require-ai-images`
5. Helm resource limits + NetworkPolicy CNI that enforces egress
6. Confirm `/api/health` and `/api/aasi/status` from the load balancer health checks you already use for the API
)
