# World-Class VAPT — review corrections

Corrections from Gemini / report-quality review that are not covered by a single ENG1 Phase 10 anchor alone. Fix upstream in classify, normalize, remediation, and importers — never in `pdf.py` or report templates.

## Expect-CT (obsolete header; not CSP)

**Problem.** Expect-CT missing/present was treated like a normal Medium header finding. Remediation could attach Content-Security-Policy / CSP-Report-Only or Cloudflare CSP transforms (shared CWE-693 / library mismatch). Some templates also shipped CWE-79 (XSS/Injection path).

**Expected behaviour.**

| Layer | Behaviour |
| --- | --- |
| Validation | `validation_status=informational`; reasons cite deprecation / Chrome 107+ retirement; **never** Confirmed |
| Severity | Cap to `info` on import when templates inflate to medium/high |
| CWE | Clear wrong CWE-79 → 693 (misconfiguration hardening) |
| Concept | `header:expect-ct-deprecated` — distinct from `header:csp-missing` / CSP Injection |
| Remediation | Pack says header is obsolete; no action for absence; remove leftovers; **no** CSP guidance |
| Library | `rejects_csp_guidance_for_finding` treats Expect-CT like Permissions-Policy for CSP-only seeds |
| Webcheck | Only emit when Expect-CT is **present** (leftover); absence is correct and passes the check |

**Code.**

- `attestra/finding_validation/classify.py` — Expect-CT → informational
- `attestra/finding_normalize.py` — `is_expect_ct_deprecated`, CWE/severity normalize
- `attestra/crossmerge.py` — `CONCEPT_RULES["header:expect-ct-deprecated"]`
- `attestra/remediation/packs.py` / `match.py` — obsolete pack; never CSP pack for Expect-CT titles
- `attestra/library/fix_snippets.py` — `expect-ct` in `NON_CSP_HEADER_CONCEPTS`
- `attestra/importers/webcheck.py` / `runner/scanners/webcheck.py` — severity/CWE normalize; presence-only finding
- Tests: `tests/test_review_corrections.py`

**Lat.** [[findings#Review corrections]], [[tests#Review corrections (Expect-CT CSP HSTS)]].

## CSP directive consolidation (Weak or Incomplete CSP)

**Problem.** Scanners emit one Medium/Low finding per CSP directive (script-src unsafe-eval, style-src unsafe-inline, form-action http:, missing object-src, missing frame-ancestors). Reports inflate risk posture, and each card repeats the same Cloudflare `default-src 'self'` Transform Rules block — omitting hosts the app actually needs (e.g. Turnstile `challenges.cloudflare.com`).

**Expected behaviour.**

| Layer | Behaviour |
| --- | --- |
| Concept | All CSP directive / incomplete-policy alerts map to `csp:weak-or-incomplete` (distinct from `header:csp-missing` when no CSP header exists) |
| Fingerprint | `canonicalize_for_merge` forces shared variant `csp:weak-or-incomplete` + origin so subtypes collide intentionally |
| Soft-match | Same concept + same `security_context_key` reaches merge threshold |
| Import | Subsequent hits merge into one finding titled **Weak or Incomplete Content Security Policy (CSP)**; distinct titles append under `CSP observations:` |
| Remediation | Single pack with directive checklist; Cloudflare/app notes call out Turnstile/CDN script hosts when required — not a paste-only default-src block |
| Validation | Do **not** invent Confirmed |

**Code.**

- `attestra/finding_normalize.py` — `CSP_WEAK_OR_INCOMPLETE`, `is_csp_weak_or_incomplete`, `csp_fingerprint_kwargs`, `append_csp_observation`, `EXTRA_CONCEPT_RULES`
- `attestra/fingerprint.py` — CSP branch in `canonicalize_for_merge`
- `attestra/crossmerge.py` — `CONCEPT_RULES["csp:weak-or-incomplete"]`; unified `concepts_for`
- `attestra/dedup.py` — `csp_concept_context` soft-match boost
- `attestra/services.py#import_results` — canonical title + observation bullets
- `attestra/remediation/packs.py` — unified pack (+ `header:csp-weak` alias)
- `attestra/reports/consolidate.py` — report title; same-tool CSP fold
- Tests: `tests/test_review_corrections.py`, `tests/test_zap_grouping.py`

**Lat.** [[findings#Review corrections#CSP directive consolidation]], [[tests#Review corrections (Expect-CT CSP HSTS)#CSP concepts unify]].
