# Attestra: Multi-AI provider + admin/lead UI settings

Copy everything below the line into your coding agent / CLI session as the implementation prompt.

---

## Goal

Extend Attestra’s existing AI stack so operators can:

1. Select among multiple LLM providers, each with the **correct default base URL and request endpoint/auth**.
2. Configure all AI settings in the **web portal UI**, gated to **admin and lead** only.
3. **Paste an API key in the UI** and save it **encrypted for that tenant in MongoDB**.
4. Ensure **Compose `api` and `worker` containers both observe UI setting changes** immediately (shared Mongo is the source of truth; no manual `.env` / compose rewrite, no required container restart for AI settings).
5. Keep AASI and AI narratives working through the same `Provider` protocol without a second provider stack.

Do **not** invent a parallel AASI provider system. Reuse `attestra/ai_narratives.py` `Provider.complete` and `attestra/aasi/provider.py` `build_provider` / `AasiProvider`.

## Non-goals

- Do not send evidence, descriptions, raw tool output, or secrets to any provider (keep existing redaction).
- Do not show API keys in UI responses, logs, `repr()`, drafts, or audit detail payloads.
- Do not grant tester / reviewer / client_viewer / auditor rights to change AI provider settings.
- Do not require a new SQL/Alembic path; runtime persistence is Mongo only.
- Do not pile new routes into `attestra/web/ui.py`; follow the feature-module pattern (`alerts`, `certification`).
- Do **not** rewrite `compose.yaml`, container env, or host `.env` from the UI when AI settings change. Docker stays in sync because **api and worker already share Mongo** (`ATTESTRA_MONGODB_URI`) and the same `ATTESTRA_CREDENTIAL_FERNET_KEY` in `compose.yaml`.

## Current baseline (read before coding)

### Provider stack today

- `attestra/ai_narratives.py`
  - `Provider` protocol: `name`, `complete(system, prompt) -> str`
  - `OllamaProvider` → `{base}/api/chat`, no API key
  - `OpenAICompatProvider` → `{base}/chat/completions`, `Authorization: Bearer <key>`
  - `provider_from_env()` accepts only `ollama` | `openai` | `openai-compatible`
  - `is_enabled()` / `ATTESTRA_AI_NARRATIVES` off-by-default; `ATTESTRA_AI_TENANTS_OFF`
  - Key: `secret_store.get_secret("ai_api_key", ATTESTRA_AI_API_KEY)`
- `attestra/aasi/provider.py` wraps the same narratives provider; docs forbid inventing `ATTESTRA_AASI_PROVIDER`
- UI drafts: `attestra/web/ai_routes.py` via `ai.get_provider(eng.tenant_id)`
- Docs: `docs/AI_NARRATIVES.md`, `.env.example` AI block

### Settings UI pattern to copy (best analogue)

**Email alerts** (admin + lead, per-tenant):

| Piece | Path |
|---|---|
| Routes | `attestra/alerts/routes.py` (`api_router` + `ui_router`) |
| Service | `attestra/alerts/service.py` (`get_settings`, `update_settings`, `settings_dict`, audit) |
| Store helpers | `attestra/web/settings_store.py` |
| Mongo repo | `attestra/persistence/mongo/repositories/settings.py` `EmailAlertSettingsRepository` |
| Template | `attestra/web/templates/alerts_settings.html` |
| Nav | `attestra/web/templates/_layout.html` More → Ops, `{% if role in ("admin", "lead") %}` |
| Mount | `attestra/api.py` `include_router` |
| Permission | `webhook.manage` → admin, lead in `attestra/auth/roles.py` |

**Secrets UI pattern to copy:** auth-web `has_secret` / write-only password field (`attestra/auth_web/profiles.py` `profile_dict`). Empty API-key field on save = leave existing key unchanged; optional clear/rotate.

**CA settings** are admin-only singleton; do **not** use that gate for AI (requirement is admin **and** lead).

## Required product behavior

### A. Multi-provider registry

Add a first-class provider catalog (constant or small module, e.g. `attestra/ai_providers.py` or section inside `ai_narratives.py`) with at least:

| Provider id | Label | Default base URL | Endpoint builder | Auth |
|---|---|---|---|---|
| `ollama` | Ollama (local) | `http://localhost:11434` | `{base}/api/chat` | none |
| `openai` | OpenAI | `https://api.openai.com/v1` | `{base}/chat/completions` | Bearer |
| `anthropic` | Anthropic (Claude) | `https://api.anthropic.com` | `{base}/v1/messages` **native Messages API** | `x-api-key` + `anthropic-version` |
| `xai` | xAI (Grok) | `https://api.x.ai/v1` | `{base}/chat/completions` | Bearer |
| `openrouter` | OpenRouter | `https://openrouter.ai/api/v1` | `{base}/chat/completions` | Bearer |
| `openai-compatible` | Custom OpenAI-compatible | (operator-supplied, required) | `{base}/chat/completions` | Bearer |

Rules:

1. Selecting a known provider **auto-fills default base URL** when the stored base URL is empty or still the previous provider’s default.
2. Operator may override base URL (self-hosted / proxies). Validate `http://` or `https://` via existing `_check_url`.
3. Implement **`AnthropicProvider`** (or equivalent) that speaks Anthropic Messages API:
   - POST body shape: `model`, `system` (or system in messages per Anthropic docs), `messages`, `max_tokens`, `temperature`
   - Headers: `x-api-key`, `anthropic-version` (pin a documented stable version), `content-type: application/json`
   - Parse `content[].text` from the response
   - Scrub key from errors/`repr` like `OpenAICompatProvider._scrub`
4. Keep OpenAI-wire providers on `OpenAICompatProvider` (or thin subclasses) with **provider-specific default bases**, not copy-pasted HTTP clients.
5. Unknown provider id → clear validation error (same spirit as today’s `unknown ATTESTRA_AI_PROVIDER`).
6. Suggested default models (overridable): ollama `llama3.1`; openai `gpt-4o-mini` (or current stable small model); anthropic `claude-sonnet-4-5`; xai a current Grok chat model; openrouter a Claude or GPT id string.

### B. Configuration resolution (UI primary, env bootstrap)

Introduce a single resolver used by `get_provider` / `provider_from_env` (rename carefully or add `resolve_provider` called by both):

**Precedence (document in code + docs):**

1. If narratives master switch is off → return `None`, build nothing, no network.
2. **Per-tenant Mongo AI settings** when present for that tenant (UI-saved).
3. Else **env** `ATTESTRA_AI_*` (local/dev/CI bootstrap and emergency override).
4. Tenant kill switch: UI per-tenant `enabled=false` **or** legacy `ATTESTRA_AI_TENANTS_OFF` still honored.

“Configured in UI portal only” for operators means: production path expects admins/leads to use `/settings/ai`; env remains supported for bootstrap and tests. Do not break existing tests that set env.

### C. Mongo persistence (per-tenant, like alerts)

Add collection e.g. `ai_settings` (name consistently in `collections.py`):

Suggested document shape:

```text
tenant_id (unique)
enabled: bool                 # narratives on for this tenant
provider: str                 # catalog id
base_url: str                 # may be "" → use provider default
model: str
api_key_enc: str | null       # Fernet ciphertext ONLY — never plaintext in Mongo
# OR api_key_ref pointing at encrypted blob; same rule: no plaintext
# Reuse ATTESTRA_CREDENTIAL_FERNET_KEY (already passed to Compose api + worker).
# Prefer encrypting with cryptography.fernet via attestra.credentials.store.resolve_fernet_key
# (or a small dedicated helper). Do NOT store raw API keys in Mongo.
aasi_enabled: bool | optional # only if you can do so without inventing AASI_PROVIDER; otherwise leave AASI_ENABLED env as-is and document
updated_by, updated_at
```

Also:

- Collection constant + index `tenant_id` unique in `indexes.py` / migrations path (`ensure_indexes`).
- Repository beside `EmailAlertSettingsRepository` (or sibling file) with `get` / `ensure` / `update`, field allow-list, `as_row` compatibility.
- `settings_dict` returns: `tenant_id`, `enabled`, `provider`, `base_url`, `model`, `has_api_key: bool`, `providers: [{id,label,default_base_url,default_model,needs_api_key}]`, `updated_by`, `updated_at`. **Never** `api_key`, `api_key_enc`, or decrypted material.
- Decrypt only inside provider construction on the server (api or worker process), never in templates or API JSON.

### D. Permission + routes + UI

1. Add permission in `attestra/auth/roles.py`:

```python
"ai.configure": frozenset({"admin", "lead"}),
```

2. New module `attestra/ai_settings/` (recommended) with:

| Method | Path | Behavior |
|---|---|---|
| GET | `/api/ai/settings?tenant_id=` | settings_dict; require `ai.configure` + tenant scope |
| PUT | `/api/ai/settings?tenant_id=` | partial update; empty `api_key` leaves existing; explicit clear flag if needed |
| GET | `/settings/ai?tenant_id=` | HTML page |
| POST | `/settings/ai` | form save + `_back` flash |

3. Template `attestra/web/templates/ai_settings.html` extending `_layout.html`:
   - Tenant select (copy alerts)
   - Enable toggle
   - Provider `<select>` from catalog
   - Base URL input (placeholder = provider default; hint that blank uses default)
   - Model input
   - **API key paste field** (see section H): `type="password"` (or text+password toggle for paste UX), `autocomplete="off"`, placeholder like “Paste API key, then Save”; show “Key saved” / `has_api_key` when ciphertext exists; **never** echo the value after save
   - Optional “Clear API key” control
   - Optional “Test connection” button **only if** you can implement it safely (redacted probe, timeout, no key in response). Nice-to-have; not required for MVP if time-boxed.
4. Nav: in `_layout.html` More → Ops, next to Email alerts, under `{% if role in ("admin", "lead") %}` or `can(role, "ai.configure")`:
   - `<a href="/settings/ai">AI provider</a>`
5. Mount routers in `attestra/api.py` like alerts.
6. Thin helpers in `settings_store.py` or `ai_settings` service; audit event e.g. `ai.settings.update` with provider/model/enabled/`has_api_key` only (no key material).

### E. Wire construction call sites

- `get_provider(tenant_id=…)` must load **that tenant’s Mongo AI settings + decrypt key** when `tenant_id` is known (ai_routes, AASI paths that have tenant context). Today `get_provider` largely ignores tenant for construction; fix that.
- Resolve **on each use** (or with a very short TTL + explicit invalidate-on-save). Do **not** cache a process-global provider built from env forever, or Compose worker will keep stale settings after a UI save.
- Preserve `set_provider` / `http_post` injection for tests.
- Preserve off-means-off: disabled → `None`, no sockets.
- AASI continues to call `build_provider` / narratives provider; update only construction inputs.

### H. Paste API key in UI → encrypted per-tenant Mongo → Docker api/worker pick it up

**UI paste + save**

1. Admin/lead opens `/settings/ai`, selects tenant, pastes provider API key into the key field, clicks Save.
2. POST/PUT handler:
   - Trims the pasted value.
   - If non-empty: Fernet-encrypt with `resolve_fernet_key()` / shared `ATTESTRA_CREDENTIAL_FERNET_KEY`, write ciphertext into that tenant’s `ai_settings` Mongo doc (`api_key_enc` or equivalent). Never log the pasted value.
   - If empty: leave existing ciphertext unchanged (rotate/clear only via explicit clear action).
3. Re-render / API response shows `has_api_key=true` only; input stays blank.
4. Form must accept long pasted keys (`sk-…`, `sk-ant-…`, etc.) without truncation; disable browser autocomplete.

**Mongo is the cross-container sync bus (this is how Docker “gets updated”)**

Facts in this repo today:

- Root `compose.yaml` does **not** currently inject `ATTESTRA_AI_*` into services.
- Both `api` and `worker` already receive `ATTESTRA_MONGODB_URI=mongodb://mongo:27017/?replicaSet=rs0` and `ATTESTRA_CREDENTIAL_FERNET_KEY`.
- Therefore: **saving AI settings in Mongo is sufficient for Docker.** The next AI call in either container must read Mongo + decrypt with the shared Fernet key.

Hard requirements:

1. **Do not** attempt to mutate running container env, rewrite `compose.yaml`, or write host `.env` from the settings UI.
2. **Do** make `get_provider(tenant_id)` / resolver read the tenant Mongo document at call time so:
   - UI save in the `api` container is visible to the `worker` container without restart.
   - Host-venv worker against the same Mongo also sees the same settings.
3. If any in-process cache of AI settings/provider exists, **invalidate it in the save path** (and keep TTL ≤ a few seconds if you keep a cache at all). Prefer no cache for MVP.
4. Document for operators: Compose stack must share one Mongo and one Fernet key (already true in `compose.yaml`); ephemeral Fernet (`ATTESTRA_CREDENTIAL_ALLOW_EPHEMERAL`) must **not** be used across api/worker or ciphertext won’t decrypt in the other process.
5. Add a short note on the AI settings page: “Saved for this tenant in the database. API and worker use these settings automatically; no Docker restart needed.”
6. Tests:
   - Save key via service → second “process”/fresh resolver with same Fernet key reads and decrypts successfully.
   - `settings_dict` / HTML never contain plaintext or `api_key_enc`.
   - Worker-path construction (`get_provider(tenant_id)`) uses Mongo key, not stale env, when Mongo settings exist.

### F. Docs + lat.md + env examples

Update:

- `docs/AI_NARRATIVES.md` — provider table, UI path, precedence, secret handling
- `.env.example` / `.env.production.example` — note UI primary; env bootstrap; list new provider ids
- `lat.md/architecture.md` (AI drafts), `lat.md/interfaces.md` if settings routes belong there, `lat.md/tests.md` for new specs
- Run `lat check` and fix until clean
- Add `@lat:` comments on new tests per project rules

### G. Tests (required)

Extend / add coverage in:

- `tests/test_ai_narratives.py` — each catalog provider builds correct URL/headers; anthropic parses Messages response; unknown provider errors; key scrubbing for anthropic too
- `tests/test_phase5_ai.py` — defaults / key never in drafts/errors
- New `tests/test_ai_settings.py` (or similar):
  - admin/lead can GET/PUT; tester gets 403
  - tenant scope enforced
  - settings_dict never contains api_key
  - empty key on update preserves previous
  - enabled=false → `get_provider` returns None
  - provider switch applies default base URL when appropriate
- Keep AASI provider tests green (`tests/aasi/test_provider.py`)

Use fake `http_post`; no live network.

## Implementation order (suggested PR-sized steps)

1. Provider catalog + `AnthropicProvider` + extend `provider_from_env` / resolver (env-only still works).
2. Mongo collection/repo + Fernet encrypt/decrypt for per-tenant API key + `settings_dict` / update.
3. API + UI routes + paste-friendly key field + template + nav + permission.
4. Point `get_provider(tenant_id)` at live Mongo settings (no sticky process cache); env fallback only when no tenant doc.
5. Verify Compose path: save via api → worker resolves same tenant settings/key without restart (integration or documented manual check).
6. Docs + lat.md + tests + `lat check`.

## Acceptance checklist

- [ ] Admin and lead can open `/settings/ai`, pick tenant, paste API key, save provider/model/base URL/enable.
- [ ] Pasted key is stored **encrypted** on the tenant’s Mongo `ai_settings` document; plaintext never written.
- [ ] After Save, Compose `api` and `worker` both use the new settings/key on the next AI call **without** Docker restart or `.env` edits.
- [ ] Tester (and lower) cannot open or mutate AI settings (403 / redirect).
- [ ] Selecting Anthropic hits Messages API with correct headers; OpenAI/xAI/OpenRouter hit `/chat/completions`; Ollama hits `/api/chat`.
- [ ] API key never appears in HTML, JSON settings, logs, audit details, or exception text.
- [ ] AI drafts + AASI still work when enabled; off stays off with zero network.
- [ ] Existing env-based tests still pass; new UI/settings tests pass.
- [ ] `lat.md/` updated for implemented behavior; `lat check` passes.

## Constraints / coding conventions

- Follow surrounding Attestra style; short comments only for non-obvious constraints.
- Prefer narrow wiki links / `@lat:` on new test leaf sections.
- Prefer `python -m attestra.cli` in any manual verification notes.
- Windows-friendly paths; project root `C:\Github\attestra`.
- Before claiming UI done: exercise `/settings/ai` in the browser as admin and as tester (deny path).

## Out of scope unless trivial

- Streaming responses
- Per-user (non-tenant) API keys
- Embedding / image providers
- Replacing draft approval workflow
- Moving SMTP or other unrelated settings

## Hypothesis (non-binding)

Per-tenant Mongo AI settings + `ai.configure` for admin/lead, modeled on email alerts, is the right shape. Native Anthropic Messages support avoids relying on Anthropic’s OpenAI-compat layer. Paste-to-Mongo with Fernet (`ATTESTRA_CREDENTIAL_FERNET_KEY`, already on Compose api/worker) plus live `get_provider(tenant_id)` reads is how Docker stays updated without rewriting container env. Verify against the files above and adjust if a cleaner existing secret encryption helper fits better than inventing a new crypto path.
