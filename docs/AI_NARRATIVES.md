# AI narratives (Step 8.5, optional)

Status: **built, OFF by default.** Template-based narratives remain the default and are unchanged.

## What it does
When enabled, Attestra can draft:
- an **executive summary** per engagement, and
- a **narrative per finding** (impact and fix direction).

Every output is stored with the label **"AI draft"** and status `draft`. A draft can only appear in a
report after a user with role `tester` (or `lead`/`admin`) approves it, optionally editing the text.
Client and auditor roles cannot approve. Rejected or unapproved drafts are never used; the report
falls back to the template narrative. The only report-facing accessor is
`attestra.ai_narratives.approved_text()`.

## Configuration
| Variable | Default | Meaning |
|---|---|---|
| `ATTESTRA_AI_NARRATIVES` | `off` | `on` enables the feature |
| `ATTESTRA_AI_PROVIDER` | `ollama` | `ollama` (local) or `openai` (any OpenAI-compatible API) |
| `ATTESTRA_AI_BASE_URL` | `http://localhost:11434` | Ollama URL, or the API base such as `https://host/v1` |
| `ATTESTRA_AI_MODEL` | `llama3.1` | Model name |
| `ATTESTRA_AI_TENANTS_OFF` | empty | Comma-separated tenant ids for which the feature is off |

The API key for the `openai` provider comes from the secret store (`attestra/secret_store.py`, key
`ai_api_key` in Vault/OpenBao), falling back to `ATTESTRA_AI_API_KEY`. The key is never logged or
shown in `repr()`. Prefer a local model (Ollama) over a paid API.

## Data protection
- **Sent:** redacted title, severity, CWE, CVE ids, OWASP/ASVS refs, KEV flag, EPSS, CVSS score, status.
  For summaries, also severity counts.
- **Never sent:** evidence, descriptions, recommendations, locations, raw tool output, assets, client names.
- Titles are redacted: URLs, hostnames, IPs, emails, paths, tokens, keys and long random strings are replaced
  with placeholders such as `[host]` and `[secret]`.
- Use a provider whose terms exclude training on submitted data; a local Ollama keeps everything on-premises.

## Off means off
With `ATTESTRA_AI_NARRATIVES=off`, `provider_from_env()` returns `None`, no provider object is built
and no network connection is made. Tests assert this by failing any socket use.

## Storage
Drafts are JSON files in `<ATTESTRA_DATA_DIR>/ai_drafts/engagement_<id>.json` (no DB migration).

## Tests
`tests/test_ai_narratives.py` uses a fake provider and an injected HTTP transport; no real model is called.

## Routes (404 when the feature is off)
| Method | Path | Roles |
|---|---|---|
| GET | `/api/engagements/{id}/ai-drafts` | admin, lead, tester |
| POST | `/api/engagements/{id}/ai-drafts` `{"kind": "executive_summary" or "finding", "finding_id": n}` | admin, lead, tester |
| POST | `/api/engagements/{id}/ai-drafts/{draft}/approve` `{"text": "optional edited text"}` | admin, lead, tester |
| POST | `/api/engagements/{id}/ai-drafts/{draft}/reject` | admin, lead, tester |
| GET/POST | `/engagements/{id}/ai-drafts` (dashboard page with create, edit-approve and reject) | admin, lead, tester |

Reports: the executive report shows the approved summary and the technical report shows approved finding
narratives, each marked "AI-assisted, approved by <tester>". Unapproved or rejected drafts never appear.
