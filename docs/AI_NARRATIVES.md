# AI narratives (Step 8.5, optional)

Status: **built, OFF by default** unless enabled per tenant in the UI. Template-based narratives remain the default and are unchanged.

## What it does
When enabled, Attestra can draft:
- an **executive summary** per engagement, and
- a **narrative per finding** (impact and fix direction).

Every output is stored with the label **"AI draft"** and status `draft`. A draft can only appear in a
report after a user with role `tester` (or `lead`/`admin`) approves it, optionally editing the text.
Client and auditor roles cannot approve. Rejected or unapproved drafts are never used; the report
falls back to the template narrative. The only report-facing accessor is
`attestra.ai_narratives.approved_text()`.

## UI configuration (preferred)

Admins and leads manage AI under **More → AI provider** (`/settings/ai`), permission `ai.configure`.

Per tenant you can:
- enable/disable AI
- select provider (`ollama`, `openai`, `anthropic`, `xai`, `openrouter`, `openai-compatible`)
- set model and optional base URL (blank = catalog default)
- **paste an API key** — stored as Fernet `api_key_enc` on the tenant’s Mongo `ai_settings` document

The key is never echoed after save (`has_api_key` only). Compose `api` and `worker` already share
Mongo and `ATTESTRA_CREDENTIAL_FERNET_KEY`, so a UI save is visible to both **without** rewriting
container env or restarting Docker. Implementation prompt: `docs/MULTI_AI_PROVIDER_CLI_PROMPT.md`.

API: `GET/PUT /api/ai/settings?tenant_id=`

## Env bootstrap (local / CI)

Used when no Mongo UI document exists for the tenant.

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

Catalog and adapters live in `attestra/ai_providers.py`. Resolution:
`get_provider(tenant_id)` → live Mongo settings when present, else env.

## Data protection
- **Sent:** redacted title, severity, CWE, CVE ids, OWASP/ASVS refs, KEV flag, EPSS, CVSS score, status.
  For summaries, also severity counts.
- **Never sent:** evidence, descriptions, recommendations, locations, raw tool output, assets, client names.
- Titles are redacted: URLs, hostnames, IPs, emails, paths, tokens, keys and long random strings are replaced
  with placeholders such as `[host]` and `[secret]`.
- Use a provider whose terms exclude training on submitted data; a local Ollama keeps everything on-premises.

## Off means off
When the tenant is disabled in UI (or env bootstrap is off and no UI doc), `get_provider` returns
`None`, no provider object is built, and no network connection is made.

## Storage
- Drafts: JSON files in `<ATTESTRA_DATA_DIR>/ai_drafts/engagement_<id>.json`
- Settings: Mongo collection `ai_settings` (per `tenant_id`, Fernet `api_key_enc`)

## Tests
`tests/test_ai_narratives.py` and `tests/test_ai_settings.py` use fakes / injected HTTP; no real model is called.

## Draft routes (404 when the feature is off for the engagement’s tenant)
| Method | Path | Roles |
|---|---|---|
| GET | `/api/engagements/{id}/ai-drafts` | admin, lead, tester |
| POST | `/api/engagements/{id}/ai-drafts` `{"kind": "executive_summary" or "finding", "finding_id": n}` | admin, lead, tester |
| POST | `/api/engagements/{id}/ai-drafts/{draft}/approve` `{"text": "optional edited text"}` | admin, lead, tester |
| POST | `/api/engagements/{id}/ai-drafts/{draft}/reject` | admin, lead, tester |
| GET/POST | `/engagements/{id}/ai-drafts` (dashboard page with create, edit-approve and reject) | admin, lead, tester |

Reports: the executive report shows the approved summary and the technical report shows approved finding
narratives, each marked "AI-assisted, approved by <tester>". Unapproved or rejected drafts never appear.
