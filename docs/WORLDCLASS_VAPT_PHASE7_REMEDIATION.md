# World-Class VA + PT — Phase 7 Remediation Intelligence

**Source:** `Downloads/# MASTER PROMPT WORLD-CLASS VAPT PL.txt`  
**Prior:** `docs/WORLDCLASS_VAPT_PHASE6_NORMALIZE_DEDUP.md`  
**Date:** 2026-11-05

Product wording: **security testing** / **VA + PT**. Remediation text must match the finding concept (no CSP snippets on Permissions-Policy findings).

---

## Goals

- Attach accurate, safe remediation packs to findings by **concept key** (aligned with `crossmerge.CONCEPT_RULES` / title patterns).
- Include root cause, recommended fix, server/app config examples, compatibility notes, verification, and retest steps.
- Reject known mismatches (especially Permissions-Policy ↔ CSP; deprecated X-XSS-Protection ≠ reflected XSS).
- Expose a legacy `recommendation_text` string for existing recommendation fields.
- Wire packs into library guidance, import recommendation fill, API finding payloads, and technical report cards.

---

## Package

| Module | Role |
| --- | --- |
| `attestra/remediation/packs.py` | `REMEDIATION_PACKS`, `pack_for_concept` |
| `attestra/remediation/match.py` | `resolve_concepts`, `pack_for_finding`, `format_remediation_markdown`, `remediation_for_finding` |
| `attestra/remediation/__init__.py` | Exports `REMEDIATION_PACKS`, `pack_for_concept`, `remediation_for_finding` |

---

## Concept keys (initial)

| Key | Notes |
| --- | --- |
| `header:hsts-missing` | HSTS on HTTPS only |
| `header:csp-missing` | CSP / Report-Only rollout |
| `header:csp-weak` | Remove unsafe-inline / unsafe-eval |
| `header:coep-missing` | Cross-Origin-Embedder-Policy |
| `header:coop-missing` | Cross-Origin-Opener-Policy |
| `header:corp-missing` | Cross-Origin-Resource-Policy |
| `header:permissions-policy-missing` | **Permissions-Policy only** (no CSP header text) |
| `header:xss-protection-deprecated` | Remove or set `0`; not an XSS fix |
| `cors:misconfiguration` | Origin allow-list; no `*` + credentials |
| `cors:acao-wildcard` | Replace ACAO `*` on sensitive responses |
| `cookie:samesite-none` | Prefer Lax/Strict unless deliberate |
| `cookie:samesite` | Set explicit SameSite |
| `tls:weak-cipher` | Modern AEAD suites; TLS 1.2+ |
| `authz:idor` | Server-side object authorization |
| `injection:sqli` | Parameterized queries |
| `xss:reflected` | Context encoding + CSP defense in depth |

---

## Matching rules

1. Prefer `crossmerge.concepts_for(finding, obs)` when tools/rule ids are present.
2. Fall back to pack `title_match` substrings (longest match wins among title hits).
3. **Never** return a CSP pack for Permissions-Policy / Feature-Policy titles.
4. `format_remediation_markdown` always emits the seven sections (code example may be `_None_`).

---

## Tests

- `tests/test_remediation_phase7.py` — Permissions-Policy excludes CSP; COEP names header; IDOR authorization; concept mismatch rejected; SQLi parameterized; XSS-Protection deprecated guidance.

---

## Files

- `attestra/remediation/` (new)
- `tests/test_remediation_phase7.py`
- `lat.md/findings.md` — Remediation packs (Phase 7)
- `lat.md/architecture.md` — World-class remediation packs (Phase 7)
- `docs/WORLDCLASS_VAPT_PHASE7_REMEDIATION.md` (this file)

---

## Wiring (library / API / reports)

| Path | Behavior |
| --- | --- |
| `library/service.guidance_for_finding` | Prefer pack when library/seed missing or CSP/wrong-header mismatch |
| `library/fix_snippets` | `header_concept_for_text` / `guidance_looks_csp_only`; BY_TITLE + SEED for PP/COEP/COOP/CORP/CORS |
| `services._apply_remediation_recommendation` | Fill empty recommendation on import; replace CSP-on-wrong-header text |
| `finding_api_fix_fields` | Adds structured `remediation` object when pack resolves |
| `reports/render._attach_remediation_packs` | Sets `finding.remediation_pack` for technical cards |
| `technical.html.j2` | Root cause / Recommended fix / Verification / Retest sections |

## Stop

Phase 7 complete for review. Next on request: **Phase 8 — Professional VAPT Report Engine**.
