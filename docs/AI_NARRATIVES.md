# AI narratives (Step 8.5, optional)

Status: **built, OFF by default**. Template-based report narratives stay the default until a tester (or lead/admin) **approves** an AI draft. This feature is **distinct from AASI** (Garak/Promptfoo/SafeLabs/PyRIT / `/api/aasi`).

Full operator walkthrough also lives in the root [README → AI Narratives](../README.md#ai-narratives-optional).

## What it does

When enabled, Attestra can draft:

- an **executive summary** for the engagement, and
- **finding writeups** with VAPT headings **Description / Impact / Likelihood / Recommendation**, either:
  - **one draft per finding**, or
  - **one combined writeup** covering several selected findings (`finding_combined`).

Every output is stored with the label **"AI draft"** and status `draft`. A draft appears in a report only after approval (optional edit). Client and auditor roles cannot approve. Rejected or unapproved drafts never appear; reports fall back to template text. Report accessors: `approved_for_report()` / `approved_text()`.

Drafts are **not** created automatically when a scan finishes. Create them on the engagement **AI drafts** page after findings exist.

## How to use (UI steps)

### 1. Prerequisites

1. Stack running (Compose or host serve + Mongo replica set).
2. `ATTESTRA_CREDENTIAL_FERNET_KEY` set (Compose install scripts fill an empty key). Needed to store pasted API keys in Mongo.
3. Findings on the engagement (scan or import). False positives are omitted from the finding picker.
4. Role: **admin** or **lead** to configure the provider; **tester**, **lead**, or **admin** to create and approve drafts.

### 2. Enable and configure the provider

**Preferred:** sign in as admin/lead → **More → AI provider** (`/settings/ai`).

1. Turn **enabled** on for the tenant.
2. Choose provider: `ollama`, `openai`, `anthropic`, `xai`, `openrouter`, or `openai-compatible`.
3. Set **model** and optional **base URL** (blank = catalog default).
4. Paste an **API key** when the provider needs one (write-only; never shown again after save — UI shows `has_api_key` only). Empty paste keeps the existing key; use clear to remove it.
5. Save. Compose `api` / `worker` read live Mongo settings — **no Docker restart** for a UI-only change.

**Anthropic tip:** base URL may be `https://api.anthropic.com` or `…/v1` (Attestra normalizes to `/v1/messages`). Newer Claude models omit `temperature` in the request body.

**Env bootstrap** (when no Mongo UI row exists for the tenant): set `ATTESTRA_AI_NARRATIVES=on` plus `ATTESTRA_AI_PROVIDER` / `BASE_URL` / `MODEL` / `API_KEY` in `.env`, then recreate API/worker so they pick up env changes:

```bash
docker compose up -d --force-recreate api worker worker-2
```

Prefer UI paste over committing keys. Prefer secret store key `ai_api_key` over `ATTESTRA_AI_API_KEY` in shared environments.

### 3. Create drafts

Open the engagement → **AI drafts** (`/engagements/{id}/ai-drafts`).

1. Choose **Executive summary** or **Finding narrative**.
2. For findings:
   - Use the checkbox list (Select all / Clear / **Select needing writeup**).
   - Rows already **approved for reports** are highlighted (green) with an **In report** badge; you can still re-draft them (new draft needs approval again).
   - Mode: **One draft per finding** or **One combined writeup**.
3. Submit. Large combined selections can take several minutes (timeout and max tokens scale with finding count; HTTP default read timeout is 120s, up to 600s for big combined jobs).
4. Provider or settings errors flash on redirect (or HTTP 502 on the JSON API) instead of a silent success.

CSP blocks inline scripts on this page; picker UX lives in `/static/attestra.js` (`initAiDraftsPage`). Hard-refresh after static cache-bust bumps (`attestra.js?v=…` in `_layout.html`).

### 4. Review and approve

1. Open each draft below the create form.
2. Edit text if needed (keep the four VAPT headings for finding writeups).
3. **Approve (with edits)** or **Reject**.
4. Only approved text enters the next **executive** (summary) or **technical** (finding / combined) report generation, marked AI-assisted with the approver.

### 5. Generate reports as usual

Use the engagement Reports flow (draft → Submit for QA → QA → sign). Unapproved AI drafts never enter signed reports.

## UI configuration details

Admins and leads: **More → AI provider** (`/settings/ai`), permission `ai.configure`.

Per tenant: enable/disable, provider, model, base URL, Fernet-encrypted `api_key_enc` on Mongo `ai_settings`.

API: `GET/PUT /api/ai/settings?tenant_id=`

## Env bootstrap (local / CI)

Used when no Mongo UI document exists for the tenant (or as emergency override).

| Variable | Default | Meaning |
|---|---|---|
| `ATTESTRA_AI_NARRATIVES` | `off` | Bootstrap enable when no per-tenant UI settings |
| `ATTESTRA_AI_PROVIDER` | `ollama` | `ollama`, `openai`, `anthropic`, `xai`, `openrouter`, or `openai-compatible` |
| `ATTESTRA_AI_BASE_URL` | catalog default | Override base URL |
| `ATTESTRA_AI_MODEL` | catalog default | Model name |
| `ATTESTRA_AI_API_KEY` | empty | Fallback key (prefer UI paste or secret store `ai_api_key`) |
| `ATTESTRA_AI_TENANTS_OFF` | empty | Comma-separated tenant ids always off |

### Provider endpoints

| Provider | Default base | Request path | Auth |
|---|---|---|---|
| `ollama` | `http://localhost:11434` | `/api/chat` | none |
| `openai` | `https://api.openai.com/v1` | `/chat/completions` | Bearer |
| `anthropic` | `https://api.anthropic.com` | `/v1/messages` | `x-api-key` + `anthropic-version` |
| `xai` | `https://api.x.ai/v1` | `/chat/completions` | Bearer |
| `openrouter` | `https://openrouter.ai/api/v1` | `/chat/completions` | Bearer |
| `openai-compatible` | (required) | `/chat/completions` | Bearer |

Catalog: `attestra/ai_providers.py`. Resolution: `get_provider(tenant_id)` → live Mongo when present, else env.

### Compose / Docker notes

- Root `compose.yaml` loads optional `.env` via `env_file` for `api` / `worker` / `worker-2`.
- `ATTESTRA_AI_NARRATIVES` is passed through with default `off`; other `ATTESTRA_AI_*` values come from `.env` when present.
- UI-saved keys need a shared `ATTESTRA_CREDENTIAL_FERNET_KEY` on api and workers (Compose already wires this).
- Template/JS/Python changes require image rebuild: `docker compose up -d --build api` (workers only if worker code changed).
- Ollama on the host is not reachable as `localhost` from inside containers; use a reachable host URL or run Ollama on the Docker network.

## Data protection

- **Sent:** redacted title, severity, CWE, CVE ids, OWASP/ASVS refs, KEV flag, EPSS, CVSS score, status. For summaries, also severity counts.
- **Never sent:** evidence, descriptions, recommendations, locations, raw tool output, assets, client names.
- Titles are redacted: URLs, hostnames, IPs, emails, paths, tokens, keys and long random strings become placeholders such as `[host]` and `[secret]`.
- Prefer a provider whose terms exclude training on submitted data; local Ollama keeps traffic on-premises.

## Off means off

When the tenant is disabled in UI (or env bootstrap is off and no UI doc), `get_provider` returns `None`, no provider object is built, and no network connection is made.

## Storage

- Drafts: JSON files in `<ATTESTRA_DATA_DIR>/ai_drafts/engagement_<id>.json`
- Settings: Mongo collection `ai_settings` (per `tenant_id`, Fernet `api_key_enc`)

## Dependencies

AI narratives use **stock** Attestra runtime packages (`cryptography` for Fernet, stdlib/`urllib` HTTP in `ai_providers.py`). No `openai` / `anthropic` Python SDKs are required for drafts. Those optional pins in `requirements.txt` are for **AASI shared-env scanners**, not this feature.

## Tests

`tests/test_ai_narratives.py`, `tests/test_ai_routes.py`, and `tests/test_ai_settings.py` use fakes / injected HTTP; no real model is called.

## Draft routes (404 when the feature is off for the engagement’s tenant)

| Method | Path | Roles |
|---|---|---|
| GET | `/api/engagements/{id}/ai-drafts` | admin, lead, tester |
| POST | `/api/engagements/{id}/ai-drafts` | admin, lead, tester |
| | JSON body: `kind` (`executive_summary` or `finding`), optional `finding_id`, or `finding_ids` + `mode` (`per_finding` \| `combined`) | |
| POST | `/api/engagements/{id}/ai-drafts/{draft}/approve` `{"text": "optional edited text"}` | admin, lead, tester |
| POST | `/api/engagements/{id}/ai-drafts/{draft}/reject` | admin, lead, tester |
| GET/POST | `/engagements/{id}/ai-drafts` (dashboard create, edit-approve, reject) | admin, lead, tester |
| GET/PUT | `/api/ai/settings?tenant_id=` | admin, lead (`ai.configure`) |

Reports: executive report shows the approved summary; technical report shows approved per-finding and combined writeups, each marked "AI-assisted, approved by …". Unapproved or rejected drafts never appear.
