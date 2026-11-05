# World-Class VAPT Platform — Phase 1 Audit

**Source prompt:** `Downloads/# MASTER PROMPT WORLD-CLASS VAPT PL.txt`  
**ENG1 case:** `Downloads/eng1-technical-v21.pdf` (Coworked Harmony AI Project Manager, engagement #1, report v21, DRAFT)  
**Audit date:** 2026-11-05  
**Repo branch at audit:** `restore-old-template`  
**Method:** Five parallel code audits (scanners, findings, scoring, evidence/QA, reports) plus ENG1 V21 PDF inspection. No product code changed in this phase.

Product wording: use **security testing** / **VA + PT** in readable text; engagement type key `vapt` stays.

This document is the Phase 1 deliverable: architecture assessment, gap analysis, ENG1 V21 issue register, and prioritized engineering backlog for Phases 2–10. Implementation starts only after owner review.

---

## 1. Architecture assessment (current implemented state)

Attestra is a FastAPI + Jinja evidence platform with Mongo persistence. Testers authorize engagements, run or import scanners, normalize findings, map compliance, and produce signed reports.

| Layer | Role | Primary anchors |
| --- | --- | --- |
| Interfaces | REST, CLI, dashboard, portal | `attestra/api.py`, `cli.py`, `web/ui.py` |
| Services | Shared write path + audit | `attestra/services.py` |
| Runner plane | Scoped live scanners (ZAP, Nuclei, testssl, naabu, webcheck, …) | `attestra/runner/` |
| Auth-web | Authenticated crawl, ZAP/Nuclei auth, IDOR/role scan | `attestra/auth_web/` |
| Automated security testing | Orchestrator, capture, validation façade | `attestra/automated_vapt/` |
| Importers | ZAP, Nuclei, Burp, Nessus, SARIF, … | `attestra/importers/` |
| Findings | Fingerprint, soft dedup, cross-merge, lifecycle | `fingerprint.py`, `dedup.py`, `crossmerge.py`, `models.py` |
| Scoring | CVSS fields, EPSS/KEV enrich, risk_score | `scoring.py`, `services.enrich` |
| Evidence / proof | Masked store, HttpPair, screenshots, gallery | `evidence/`, `proof/` |
| Reports | HTML → PDF/DOCX/MD/JSON; four-eyes; sign | `reports/render.py`, `export.py`, `pdf.py` |
| Compliance | CWE → objectives → frameworks | `compliance/engine.py` |

**Design intent that still holds:** every claim should be traceable to evidence; scanner alerts should not become “validated” without a named tester (or Elite validation path with evidence). Import-only language in older lat sections is stale where the runner plane executes scanners.

**Two validation models today (not unified):**

1. **Finding.status** workflow: `new` → `triaged` → `validated` → `fixed` → `retest_passed`, plus `false_positive` and `risk_accepted`.
2. **Elite validation class:** `CONFIRMED` / `POTENTIAL` / `NOT_VULNERABLE` / `INCONCLUSIVE` / `NEEDS_MANUAL_REVIEW` — creates findings still as `status="new"`.

Prompt states (Needs Manual Validation, Not Reproducible, Informational-as-status) are only partially covered.

---

## 2. Component scorecard

| Component | Status | Summary |
| --- | --- | --- |
| Nuclei runner + importer | Present / Extend | Docker/local, auth file, shallow URL discovery; weak evidence when templates omit req/resp |
| ZAP runner + importer | Present / Extend | Baseline/full scripts; often **no message bodies** → empty proof pairs; no OpenAPI/AF YAML path |
| Authenticated scanning | Present / Extend | Header/cookie/form/OTP; SPA/SSO thin; flag-gated |
| Crawling | Present / Extend | ZAP spider + auth-web BFS + Nuclei heuristics; no unified crawl inventory |
| API discovery | Thin | JS regex discovery only; no OpenAPI/Swagger/GraphQL introspection import |
| Endpoint / port discovery | Partial | Naabu (pinned IP); Nmap intentionally absent (license) |
| Req/resp capture | Present / Extend | Import proof + Elite HTTPX/Playwright; ZAP body gap is critical |
| Finding normalization | Present | `NormalizedFinding`; Elite path bypasses it |
| Dedup / cross-tool | Present / Extend | Exact + soft + CONCEPT_RULES; CORS/Permissions-Policy/SameSite/weak-cipher concepts thin |
| False-positive management | Partial | Manual FP + suppressions; Elite FP checker does **not** gate create |
| Validation states | Partial | Workflow ≠ Elite classes; no `not_reproducible` |
| Severity / CVSS | Partial | CVSS 3.x only; v4 cleared; severity↔score can diverge |
| EPSS / KEV | Present / Extend | Offline enrich; no percentile/dates; manual refresh |
| OWASP / CWE | Present / Extend | Sparse YAML; single CWE; many Unmapped |
| Technical vs business risk | Blurred | Single `risk_score`; no separate business-risk field |
| Evidence storage | Present / Extend | Hashed write-once; download often skips re-verify; Elite raw folder parallel |
| Remediation | Weak | Library/CWE templates; **wrong header remediations** (ENG1 F-7) |
| Retest | Present / Extend | Request/finalize + optional replay; weak fingerprint binding |
| Audit log | Present | Hash chain; global, not per-tenant |
| Report QA / approval | Present / Extend | Report-level SoD; no finding evidence checklist gate |
| Technical report chrome | Strong | Cover through appendix largely present |
| Coverage chapter | Weak | Checks/checklist exist; not distinct “% tested vs vulns” |
| Finding narrative depth | Weak | No first-class root cause / reproduction steps on Finding |
| PDF quality | Adequate | xhtml2pdf limits on Windows; keep-together relaxed |

---

## 3. ENG1 V21 issue register (regression anchors)

Inspected `eng1-technical-v21.pdf` (35 pages, DRAFT). Do **not** “fix” these by editing the PDF; fix detection, validation, grading, remediation mapping, then regenerate.

| ID | Observed in V21 | Expected enterprise behaviour | Likely root cause | Phase to fix |
| --- | --- | --- | --- | --- |
| **F-2 CORS** | Medium finding on `/cdn-cgi/challenge-platform/.../main.js` with `Access-Control-Allow-Origin: *` | Classify CDN/challenge resources separately; require app-owned CORS + credentialed read proof before Confirmed | No CDN/challenge FP / ownership validator; ZAP 10098 imported as `new` | Phase 2 |
| **F-3 SameSite** | Low on `cf_clearance` cookie, SameSite=None | Distinguish Cloudflare cookies from app session cookies; impact only if auth/session cookie | Cookie checks treat all Set-Cookie equally | Phase 2 |
| **F-7 Permissions-Policy** | Low “header not set” on **cdn-cgi** URL; remediation text is **CSP** Nginx/Apache | Validate against application responses; remediation must match Permissions-Policy | Wrong affected resource + library/guidance mismatch | Phase 2 + 7 |
| **F-8 HSTS** | Finding “HSTS not set”; site grade **HSTS missing Failed −20**; same report’s F-18 evidence shows `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` | Finding and grade must match response evidence; contradicting Pass/Fail reconciled | Grade/check vs Nuclei/ZAP observation mismatch; evidence not used to invalidate alert | Phase 2 + 5 |
| **F-10 Weak ciphers** | Low; Nuclei `weak-cipher-suites`; **no cipher names / protocol versions / handshake** | Exact suite names, TLS versions, handshake evidence | Importer/template evidence incomplete | Phase 2 + 3 |
| **F-18 XSS-Protection** | Info titled like XSS; CWE-79, OWASP Injection, WSTG reflected XSS | Deprecated-header hardening observation; do not imply active XSS | Mapping from Nuclei template → CWE/OWASP too aggressive | Phase 2 + 6 |
| **Site grade** | C (55); HSTS missing Failed while HSTS short Passed; weak cipher Failed | Consistent modifiers from verified evidence | `grade.py` / webcheck vs imported findings disagree | Phase 5 |
| **Coverage** | XSS/SQLi checklist “Passed” with notes that HTML forms/DOM and blind SQLi **not covered** | Passed ≠ skipped/limited; coverage chapter separate from vuln counts | Checklist language vs coverage engine | Phase 3 + 4 |
| **CDN noise** | F-11 loosely scoped `cf_clearance`; multiple cdn-cgi URLs | Infrastructure cookie noise filtered or Informational with clear ownership | No CF cookie allowlist | Phase 2 |
| **Validation status** | All listed findings still **New** | Scanner alerts stay New/Needs Manual until evidence-backed validation | By design today; product still reads as “open vulns” | Phase 2 |
| **Remediation quality** | F-7 CSP guidance for Permissions-Policy | Header-specific remediation blocks | Library seed / guidance match | Phase 7 |
| **QA metadata** | Document control QA/Approved `—`; DRAFT watermark | Seal QA/signer into approved PDFs | Report lifecycle vs sealed HTML | Phase 8 + 9 |

---

## 4. Prioritized engineering backlog (maps to prompt Phases 2–10)

### P0 — Accuracy and honesty (start Phase 2)

1. **Finding validation engine (unify models)**  
   Persist validation class on findings/observations; gate Elite create on FP checker + real evidence flags; add `needs_manual_review` / `not_reproducible` (or equivalent); never treat HTTP 200 alone as Confirmed.
2. **CDN / challenge / Cloudflare classifiers**  
   General rules (path prefixes, `cf_*` cookies, `Server: cloudflare` challenge bodies) that mark Needs Manual / Informational / FP candidates — not hardcoded ENG1 IDs.
3. **Evidence-contradiction invalidation**  
   If stored HTTP evidence shows HSTS/Permissions-Policy present on the **application** URL, do not keep “header not set” as an open vulnerability without analyst override.
4. **ZAP/Nuclei message bodies**  
   Ensure imports produce HttpPairs so validation and reports can challenge scanner claims.

### P1 — Coverage and scoring

5. **Coverage execution engine** — endpoints/methods/params/roles tested vs discovered; blocked/skipped/failed tracked; never equate scan completion with testing coverage (Phase 4).
6. **Expand PT modules** within authorization — authn, authz, session, injection, XSS, API, business logic, file, infra — with safe non-destructive probes (Phase 3).
7. **CVSS v3.1 + v4 store/validate; sync severity↔score; preserve vectors** (Phase 5).
8. **Split technical severity vs priority/business risk** in API and reports (Phase 5).
9. **Concept registry** for CORS, Permissions-Policy, SameSite, weak-cipher across fingerprint / crossmerge / report consolidate (Phase 6).

### P2 — Remediation, reports, QA

10. **Finding-specific remediation packs** (COEP/COOP/CORP/CORS/CSP/HSTS/IDOR/SQLi …) with root cause, examples, verification, retest steps (Phase 7).
11. **Report narrative depth** — reproduction steps, root cause, validation status, tool versions, out-of-scope, coverage chapter (Phase 8).
12. **Automated report QA gates** before final approval (Phase 9).
13. **ENG1 V21 regression suite** asserting the register above (Phase 10).

---

## 5. What already works (reuse; do not rewrite)

- Runner adapters + importers registry; SSRF/DNS pin/scope gates.
- Auth-web profiles, ZAP auth contexts, role scan, gated IDOR tamper.
- Fingerprint + soft dedup + observation history + cross-merge (conservative).
- Evidence mask, SHA-256 store, HttpPair, screenshot redact, gallery provenance.
- EPSS/KEV enrich hooks; asset criticality / exposure weights.
- Technical report structure (cover, control, scope, methodology, findings cards, appendix).
- Four-eyes report submit → QA → sign; audit hash chain.
- Elite façade (`automated_vapt`) over capture/validation/evidence — extend, do not fork a second platform.

---

## 6. Phase 1 exit criteria

| Deliverable | Status |
| --- | --- |
| Architecture assessment | Done (this doc §1) |
| Complete gap analysis | Done (§2–§3) |
| Prioritized engineering task list | Done (§4) |
| ENG1 V21 issue register | Done (§3) |
| Code changes | None (audit-only) |
| Tests | None required for Phase 1 |

**Stop for review.** Next step on request: Phase 2 — Finding Validation Engine (P0 items 1–4), then commit.

---

## 7. Related docs

- `docs/ELITE_VAPT_GAP_ANALYSIS.md` — automated testing façade mapping (2026-10-30)
- `docs/GAP_ANALYSIS_CURRENT.md` — older implementation-guide progress
- `lat.md/architecture.md`, `lat.md/findings.md`, `lat.md/reports.md`, `lat.md/runner.md`
