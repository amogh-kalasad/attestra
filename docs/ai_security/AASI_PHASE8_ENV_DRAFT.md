# AASI Phase 8 — Environment draft (docs only)

Early draft for Phase 8 (production configuration / environment management) on branch `attestra-asi-bundle`. **No product Python changes** in this pass. **`.env.example` updates come when the Phase 8 code pass lands** — this file only records intended content and safe defaults.

Companion inventory: [`AASI_ENV_INVENTORY.md`](AASI_ENV_INVENTORY.md) (118 variables from `.env.example`, `attestra/config.py`, `docs/AI_NARRATIVES.md`, `docker/scanner-digests.env`, `compose.yaml`).

V4 references: CLI Prompt 4.0 §15.1–15.3 (inventory + required AASI config + secrets) and §21 (production safety defaults).

---

## Status

| Item | State |
|---|---|
| Environment inventory doc | **Drafted** (`AASI_ENV_INVENTORY.md`) |
| This Phase 8 env draft | **Drafted** (docs only) |
| `.env.example` AASI / AI blocks | **Deferred** to Phase 8 code pass |
| `.env.production.example` | **Deferred** (file does not exist yet; create in code pass) |
| `compose.yaml` AASI / AI image injection | **Deferred** to Phase 8/9 |
| Real digests for Garak / Promptfoo / SafeLabs | **Deferred** to Phase 9 (after `docker inspect`) |
| Commit / push | **Do not** (operator instruction for this early docs pass) |

---

## Safe defaults table (V4 §15.2 + §21)

Where operator decisions are not supplied, use these defaults. Mapped to **existing** env names when present; proposed names marked.

| Decision (V4) | Safe default | Env / mechanism | Notes |
|---|---|---|---|
| AASI enabled/disabled | **Disabled** | `ATTESTRA_AASI=off` | Already in `config.py` |
| Provider selection | Local Ollama when AI is used | `ATTESTRA_AI_PROVIDER=ollama` | Reuse narratives vars; do not invent `ATTESTRA_AASI_PROVIDER` |
| Model selection | Documented local model | `ATTESTRA_AI_MODEL=llama3.1` | Override only with operator-approved model |
| Maximum iterations | Bounded | `ATTESTRA_AASI_MAX_ITERATIONS=8` | In config |
| Maximum tasks | Bounded | `ATTESTRA_AASI_MAX_TASKS=32` | In config |
| Maximum model calls | Bounded | `ATTESTRA_AASI_MAX_MODEL_CALLS=40` | In config |
| Maximum tokens | Bounded | `ATTESTRA_AASI_MAX_TOKENS=50000` | In config |
| Maximum wall-clock time | Bounded | `ATTESTRA_AASI_MAX_WALL_CLOCK_S=1800` | In config (30 min) |
| Retry limit | Small | `ATTESTRA_AASI_RETRY_LIMIT=2` | In config |
| Approval requirement | **Required** | `ATTESTRA_AASI_REQUIRE_APPROVAL=on` | In config; human approval for intrusive path |
| External judge authorization | **Disabled** | **proposed** `ATTESTRA_AASI_EXTERNAL_JUDGE=off` | Until implemented, adapters must not enable third-party judge egress |
| Third-party customer data processing | **Disabled** | **proposed** `ATTESTRA_AASI_THIRD_PARTY_DATA=off` | Redacted metadata only by default |
| Evidence retention | Bounded uploads | `ATTESTRA_EVIDENCE_MAX_BYTES` (+ storage policy) | Reuse existing; no new name |
| AI asset testing | Catalogue + RoE only | `ai_app` / `ai_llm` / `ai_agent` + signed authorization; gated by `ATTESTRA_AASI` for agentic loop | No separate invented kill-switch |
| Adapter image digests | Digest-pinned; placeholders refused | `ATTESTRA_IMAGE_GARAK`, `ATTESTRA_IMAGE_PROMPTFOO`, `ATTESTRA_IMAGE_SAFELABS` | In config + commented in `docker/scanner-digests.env` |
| Intrusive testing | **Disabled** unless existing policy authorizes | `ATTESTRA_AUTOMATED_VAPT_SSRF/UPLOAD/STORED_XSS=0`, allowlist without `production`, `ATTESTRA_AASI_REQUIRE_APPROVAL=on` | Existing intrusive_policy |
| Production exploitation | **Forbidden** | Allowlist rejects `production`; APP_ENV staging/production refuse bypasses | Existing |
| High-impact tests | Explicit human approval | `ATTESTRA_AASI_REQUIRE_APPROVAL=on` + RBAC approval | Existing knob |
| External agent runtimes | No execution rights | AASI agents recommend only; adapters via `run_process` | Architecture |
| Local judge | Allowed when configured | `ATTESTRA_AI_PROVIDER=ollama` + local base URL | Prefer over external |
| Shannon / PentAGI / RedAmon tools | Not adopted | Licence / adoption matrix | See `AASI_LICENSE_REVIEW.md` |
| AI findings validation | Potential / manual validation | Importers + validation pipeline | Existing |
| Confirmed findings | Human-reviewed proof only | Finding validation workflow | Existing |
| Docker images | Digest-pinned | `ATTESTRA_IMAGE_*` | Placeholders refused |
| Secrets | Existing secret store | `ATTESTRA_SECRETS_BACKEND`, Fernet, peppers | Never commit real values |
| Tenant AI restrictions | Honour kill list | `ATTESTRA_AI_TENANTS_OFF` | AASI must honour when enabled |

---

## Intended `.env.example` additions (code pass — do not apply yet)

When Phase 8 code lands, append a commented block similar to:

```bash
# =============================================================================
# AI narratives (optional Step 8.5) — see docs/AI_NARRATIVES.md
# =============================================================================
# ATTESTRA_AI_NARRATIVES=off
# ATTESTRA_AI_PROVIDER=ollama
# ATTESTRA_AI_BASE_URL=http://localhost:11434
# ATTESTRA_AI_MODEL=llama3.1
# ATTESTRA_AI_API_KEY=          # prefer secret_store key ai_api_key; placeholder only
# ATTESTRA_AI_TENANTS_OFF=

# =============================================================================
# AASI (Attestra Agentic Security Intelligence) — off by default
# =============================================================================
# ATTESTRA_AASI=off
# ATTESTRA_AASI_MAX_ITERATIONS=8
# ATTESTRA_AASI_MAX_TASKS=32
# ATTESTRA_AASI_MAX_MODEL_CALLS=40
# ATTESTRA_AASI_MAX_TOKENS=50000
# ATTESTRA_AASI_MAX_WALL_CLOCK_S=1800
# ATTESTRA_AASI_RETRY_LIMIT=2
# ATTESTRA_AASI_REQUIRE_APPROVAL=on
# Proposed (implement before uncommenting in example):
# ATTESTRA_AASI_THIRD_PARTY_DATA=off
# ATTESTRA_AASI_EXTERNAL_JUDGE=off

# AASI scanner images (digest pins required; placeholders refused at runtime)
# ATTESTRA_IMAGE_GARAK=docker.io/nvidia/garak@sha256:REPLACE_AFTER_INSPECT
# ATTESTRA_IMAGE_PROMPTFOO=ghcr.io/promptfoo/promptfoo@sha256:REPLACE_AFTER_INSPECT
# ATTESTRA_IMAGE_SAFELABS=docker.io/agentsafelabs/safelabs-eval@sha256:REPLACE_AFTER_INSPECT
```

Also create `.env.production.example` with the same keys, production-oriented comments (`APP_ENV=production`, bypasses false, AASI off, strong secret placeholders, no real keys).

---

## Secret handling (V4 §15.3)

- `.env.example` / `.env.production.example`: **placeholders only**.
- Never commit real API keys, Mongo passwords, signing keys, GitHub tokens, or customer secrets.
- Do not print secret values during startup validation; do not log them.
- Prefer `secret_store` / Vault for `ai_api_key` over `ATTESTRA_AI_API_KEY` in shared environments.
- K-04: staging/production refuse default `ATTESTRA_API_KEY_PEPPER` / `ATTESTRA_SESSION_SECRET`.

---

## Follow-ups for the Phase 8 code pass

1. Wire any **proposed** flags into `config.py` only if still missing; keep defaults off.
2. Update `.env.example` and add `.env.production.example`.
3. Optionally surface AASI flags in `compose.yaml` (default off) without enabling scanners until digests are real.
4. Reconcile Promptfoo image registry string (`docker.io/…` placeholder in config vs `ghcr.io/…` comment in digests).
5. Environment validation script / health checks as required by V4 §15 deliverables (separate from this early draft).
6. Refresh [`AASI_IMPLEMENTATION_STATUS.md`](AASI_IMPLEMENTATION_STATUS.md) Phase 8 row when code lands.
