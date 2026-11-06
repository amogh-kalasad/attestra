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

## COEP / COOP / CORP / Permissions-Policy / X-Permitted-Cross-Domain (not CSP)

**Problem.** ENG1 / v21 reviews still saw identical Content-Security-Policy Nginx/Apache snippets attached to COEP, COOP, CORP, Permissions-Policy, and X-Permitted-Cross-Domain-Policies findings (shared CWE-693 / generic “cross-domain” concept collision). XPCD had no pack or seed and was misclassified as CORS because markers matched `cross-domain`.

**Expected behaviour.**

| Layer | Behaviour |
| --- | --- |
| Concept | Each header has its own key (`header:coep-missing`, `header:coop-missing`, `header:corp-missing`, `header:permissions-policy-missing`, `header:x-permitted-cross-domain-missing`) |
| Pack / seed | Nginx/Apache/IIS/Cloudflare examples set **that** header only — never `Content-Security-Policy` |
| Library | `rejects_csp_guidance_for_finding` / `guidance_for_finding` refuse CSP-only seeds for these titles; XPCD is in `NON_CSP_HEADER_CONCEPTS` |
| Match | `pack_for_finding` forces the own-header pack and strips CSP concepts for these titles |
| CORS | XPCD is **not** `cors:misconfiguration`; CDN CORS classifier excludes XPCD titles |

**Code.**

- `attestra/remediation/packs.py` — `header:x-permitted-cross-domain-missing` pack; existing COEP/COOP/CORP/PP packs kept header-specific
- `attestra/remediation/match.py` — `_own_header_pack_for_title` forces PP/Expect-CT/COEP/COOP/CORP/XPCD packs
- `attestra/library/fix_snippets.py` — XPCD in `NON_CSP_HEADER_CONCEPTS` / `BY_TITLE`; CORS markers no longer swallow XPCD
- `attestra/library/seed.py` — XPCD seed writeup
- `attestra/crossmerge.py` — `CONCEPT_RULES["header:x-permitted-cross-domain-missing"]`
- Tests: `tests/test_v21_review_gaps.py`

**Lat.** [[findings#Review corrections#Own-header remediation not CSP]], [[tests#v21 review gaps (header remediation)]].

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

## v21 HSTS / clickjacking evidence honesty

**Problem.** Live engagements still showed open HSTS-missing and anti-clickjacking findings (and site-grade −20 each) when other HTTP evidence on the engagement already proved the headers present — including cross-finding description text and evidence notes, not only the claiming finding’s own `http_pair`.

**Expected behaviour.**

| Layer | Behaviour |
| --- | --- |
| Classify | HSTS-not-set + evidence with `Strict-Transport-Security: … max-age=` → `not_reproducible` |
| Classify | Missing anti-clickjacking / XFO-not-set + evidence with `X-Frame-Options: SAMEORIGIN\|DENY` **or** CSP `frame-ancestors` with a non-empty / `'self'` / `'none'` value → `not_reproducible` |
| Reconcile | `reconcile_validation_from_evidence` / `reconcile_engagement_validation` reclassifies existing ORM findings using engagement `http_pair` bodies, evidence notes, and cross-finding description/recommendation text (not only same-finding pairs) |
| Grade | HSTS-missing (−20) and clickjacking (−20) skipped when claiming finding is `not_reproducible` / informational / validation FP / accepted_risk, **or** when any in-scope finding evidence shows the header present; pass reasons stay honest (evidence cite vs validation skip) |

**Code.**

- `attestra/finding_validation/headers.py` — `clickjacking_protection_present_in_evidence`; claim key `clickjacking`
- `attestra/finding_validation/classify.py` — clickjacking contradiction → `not_reproducible`
- `attestra/finding_validation/reconcile.py` — cross-finding descriptions + evidence notes; alias `reconcile_engagement_validation`
- `attestra/grade.py` — clickjacking skip mirrors HSTS (`_clickjacking_pass_reason`)
- Tests: `tests/test_v21_hsts_clickjack.py`

**Lat.** [[tests#v21 review gaps]], [[findings#Site grade]].

## ZAP notices and static-cache noise (Gemini v21)

**Problem.** ZAP rule **10109** (Modern Web Application / SPA notice) and **10112** (Session Management Response Identified — scanner debug hook) were imported as open findings and could inflate Medium/open-vuln KPIs. Cache-family alerts (Non-Storable / Cache-Control / Retrieved from Cache / Storable and Cacheable — ZAP 10015 / 10049 / 10050) on **static** Next.js assets (`/_next/static`, `.js`, `.css`, webpack chunks, `robots.txt`) and on CDN/`cdn-cgi` paths likewise appeared as reportable open vulns.

**Expected behaviour.**

| Layer | Behaviour |
| --- | --- |
| Validation | 10109 / 10112 → `validation_status=informational`, severity `info`; **never** Confirmed / open Medium |
| Validation | Cache-family titles/rules on static or CDN/challenge URLs → informational with static/CDN reason |
| Import (ZAP) | Force severity `info` for plugins 10109 / 10112; force `info` for 10015 / 10049 / 10050 when URI is static or cdn-cgi |
| Normalize | `normalize_severity_for_import` caps the same cases to `info` |
| CDN harden | Existing cf_clearance / CORS-on-cdn-cgi / header-on-cdn-cgi stay informational; cache-on-cdn-cgi fills the remaining gap |
| Report KPIs | `_NON_VULN_VALIDATION` / `_counts_as_open_vuln` already exclude informational — notices never count as open vulns |
| App HTML cache | Cache-control on non-static app pages stays `unvalidated` (still triageable) |

**Code.**

- `attestra/finding_validation/infrastructure.py` — `is_static_asset_url`, `is_cache_related_finding`
- `attestra/finding_validation/classify.py` — ZAP notice + static/CDN cache → informational
- `attestra/importers/zap.py` — `INFORMATIONAL_PLUGIN_IDS`, `_force_informational_severity`
- `attestra/finding_normalize.py` — severity cap for notices and static/CDN cache
- `attestra/reports/render.py` — `_NON_VULN_VALIDATION` KPI exclusion (unchanged contract)
- Tests: `tests/test_review_corrections_zap_noise.py`

**Lat.** [[findings#Review corrections#ZAP notices and static cache]], [[tests#Review corrections (ZAP notices and static cache)]].
