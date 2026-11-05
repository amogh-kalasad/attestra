# World-Class VA + PT — Phase 6 Normalize / Dedup (merge context guards)

**Source:** `Downloads/# MASTER PROMPT WORLD-CLASS VAPT PL.txt`  
**Prior:** `docs/WORLDCLASS_VAPT_PHASE5_RISK_SCORING.md`  
**Date:** 2026-11-05

Product wording: **security testing** / **VA + PT**. Do not equate scan completion with coverage.

---

## Goals

- Avoid merging findings from **different security contexts** on the same host (e.g. CORS on `/cdn-cgi/` vs CORS on `/api`).
- Preserve affected endpoint / location on each linked row (rows are linked, never deleted).
- Retain scanner-specific severity and metadata on each observation/source.
- Record **why** findings were consolidated (`merge_rationale`).
- Distinguish exact/concept duplicates from **related-not-merged** near misses (same host+concept, different context).
- Do not discard useful evidence.

---

## Security context key

`attestra/finding_normalize.py#security_context_key(location, title="")` → `{host}@{bucket}`.

| Bucket | When |
| --- | --- |
| `challenge` | `challenge-platform`, Cloudflare challenge hosts, `cf-chl-` markers |
| `cdn-cgi` | `/cdn-cgi/` (non-challenge) |
| `static` | `/_next/`, `/__nextjs`, `/_vercel/`, `/static/`, `/assets/` |
| `app` | Default (application endpoints) |

Host comes from the same URL/`host[:port]` rules as cross-merge `site_key` / `caa_host`.

---

## Cross-merge guards (`attestra/crossmerge.py`)

| Match type | Host | Security context | Rationale shape |
| --- | --- | --- | --- |
| Shared CVE | Same host (or exact location if no host) | **Not required** (host-level) | `cve:{ID}` |
| Concept map (`CONCEPT_RULES`) | Same host | **Required** same `security_context_key` | `map:{concept}@{bucket}` |
| Specific CWE + overlapping path | Same host | **Required** same context | `cwe:CWE-N+path@{bucket}` |

Ambiguity (more than one candidate per tool for a concept) is scoped per `(site, bucket, concept, tool)` so a cdn-cgi row does not block an app merge.

Sibling CONCEPT_RULES expansions (CORS / Permissions-Policy / SameSite / weak-cipher) may land in `finding_normalize.EXTRA_CONCEPT_RULES`; `concepts_for` merges them via getattr/try so either side can ship first.

---

## Related-not-merged

`crossmerge.explain_near_misses(session, engagement_id)` returns compact pairs that share host + single concept but differ in security context. Intended for API/debug; does not change rows.

---

## Expanded CONCEPT_RULES (Phase 6)

New / improved concept keys (COEP/COOP/CORP and CSP-missing vs CSP-weak stay distinct):

| Key | Intent |
| --- | --- |
| `header:permissions-policy-missing` | Permissions-Policy not set |
| `header:referrer-policy-missing` | Referrer-Policy missing |
| `header:xss-protection-deprecated` | Deprecated X-XSS-Protection (not reflected XSS) |
| `cors:misconfiguration` | Cross-domain / CORS misconfiguration |
| `cors:acao-wildcard` | Wildcard ACAO nuclei patterns |
| `cookie:samesite-none` | SameSite=None cookie |
| `cookie:samesite` | Cookie without SameSite |
| `tls:weak-cipher` | Weak cipher suites |

`list_concept_keys()` enumerates the registry. Observations remain on each linked row; cross-merge never deletes evidence.

## API / exports

- Finding API: `merged_into_id`, `merge_rationale`, `dedup_*`, `validation_status`, `tools_count` (+ `observations_count` when loaded).
- JSON export includes merge/validation honesty fields.
- Markdown export folds member observations onto the primary and prints Merge rationale.

## Tests

- `tests/test_cross_tool_merge.py` — context guards + near-misses
- `tests/test_finding_normalize_phase6.py` — concept matching + observation/API honesty

---

## Files

- `attestra/finding_normalize.py` — `security_context_key`, `path_context_bucket`, `EXTRA_CONCEPT_RULES`
- `attestra/crossmerge.py` — CONCEPT_RULES expansion, context on `_Info`, `explain_near_misses`, `list_concept_keys`
- `attestra/api.py`, `reports/engagement_export.py`, `reports/markdown_export.py`
- Tests (local): `tests/test_cross_tool_merge.py`, `tests/test_finding_normalize_phase6.py`

---

## Stop

Phase 6 complete for review. Next on request: **Phase 7 — Remediation Intelligence**.
