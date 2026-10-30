# Elite Engineering Master Prompt — Gap Analysis

Source prompt: `Downloads/# ELITE ENGINEERING MASTER PROMPT.txt`  
Analysis date: 2026-10-30  
Repo: `E:\GitHub\attestra` on `main` (master-impl Phases 0–12 already delivered for the prior master plan).

This document maps the Elite prompt’s requested automated VA + PT evidence/validation framework against **what Attestra already implements**. It is a discovery artifact only. No Elite phases were coded in this pass.

Product wording: use **security testing** / **VA + PT** in readable text; engagement type key `vapt` stays.

---

## Executive summary

The Elite prompt describes a large `automated_vapt/` package (orchestrator, HTTP/browser capture, authz test modules, validation engine, evidence pipeline, Burp import, frontend, subscription, mocks, T01–T18). **Much of the capability already exists under different module names.** Building a parallel `backend/automated_vapt/` tree would duplicate services the prompt itself forbids duplicating.

| Verdict | Meaning |
| --- | --- |
| **Reuse** | Production-equivalent already exists; wire/extend, do not rewrite |
| **Extend** | Exists but thinner than the Elite script (gaps listed) |
| **Build** | Missing as a first-class Elite capability |
| **Reject / adapt** | Prompt path or shape conflicts with Attestra architecture |

**Recommended shape:** extend `attestra.auth_web`, `attestra.proof`, `attestra.evidence`, `attestra.runner`, `attestra.importers`, `attestra.credits`, and engagement UI — do **not** create a separate `backend/automated_vapt/` package unless a thin façade package re-exports existing modules.

---

## Architecture fit (Part 1 / Part 9 Phase 1)

| Prompt assumption | Attestra reality |
| --- | --- |
| `backend/automated_vapt/` | Package root is `attestra/` (FastAPI + Jinja + SQLAlchemy/Alembic) |
| New findings / reporting services | `attestra.services`, `attestra.reports`, `attestra.dedup` |
| New subscription adapter | `attestra.credits` + `SUBSCRIPTION_SERVICE` ON/OFF |
| New Burp importer | `attestra.importers.burp` (+ `proof.capture.extract_pairs`) |
| New scope / SSRF | `attestra.auth_web.scope`, `attestra.runner.authorization`, `runner.gate` / `policy` |
| New Playwright browser layer | `attestra.auth_web.crawl` (Playwright optional), `proof.screenshot_redact`, `proof.screenshots` |
| New IDOR / privilege tests | `auth_web.tamper` (gated IDOR), `auth_web.role_scan` (multi-role compare) |
| Mock apps under `tests/automated_vapt/` | Documented `tests/fixtures/auth_web_mock_app.py` — **source currently missing** (only `.pyc` residue); no intentional vulnerable twin |

---

## Component matrix (prompt Scripts 1–20 + Parts 3–8)

| Elite component | Status | Existing Attestra anchors | Gap vs Elite prompt |
| --- | --- | --- | --- |
| **orchestrator.py** (QUEUED→CANCELLED) | Extend | `jobs/`, `orchestration/`, `runner/`, scan admit via `services.request_scan`, auth-web routes | No single “approved engagement → test profile → evidence → finding” orchestrator for Elite test cases; status model exists for scans/jobs, not for Elite test-run entities |
| **scope_validator.py** | Reuse / Extend | `auth_web.scope.CrawlScope`, `runner.authorization`, DNS pin, redirect/SSRF guards, engagement auth window via gate/policy | Elite wants ports/methods/excluded endpoints as first-class engagement fields; crawl scope is origin/path-prefix oriented today |
| **http_capture.py** (HTTPX) | Extend | `proof.pair.HttpPair`, `proof.capture`, `proof.redact`, evidence kind `http_pair` | No dedicated live HTTPX capture runner that records timed transactions into storage as a test-run artifact stream |
| **browser_capture.py** (Playwright) | Extend | `auth_web.crawl` Playwright fetch, credential store, screenshot redact/attach | Workflow scripting (forms, before/after, network events) is crawl/role-scan oriented, not a general Playwright test runner |
| **request_parser.py / response_parser.py** | Build / Extend | Partial parsing in importers, tamper URL ID swap, HttpPair fields | No shared normalizer for query/JSON/form/path IDs + role/tenant markers used by validation |
| **idor_bola_tests.py** | Extend | `auth_web.tamper.plan_and_maybe_execute_probes` (plan-only default; GET ID swaps; gated) | Two-account Project A/B fixture workflow + response comparison + CONFIRMED classification pipeline not packaged as Elite T04 |
| **privilege_escalation_tests.py** | Extend | `auth_web.role_scan.run_role_comparison`, role profiles | Vertical/horizontal suite with named roles (tester→org admin) incomplete; no Super Admin product role string |
| **authentication_tests.py** | Build / Extend | Profiles, OTP helpers (`auth_web.otp`), session/credential store | No systematic invalid-creds / expired-session / reset-authorization test module |
| **api_security_tests.py** | Build | Partial signals via tamper, role scan, scanner imports | No configurable BFLA / mass-assignment / rate-limit validation suite |
| **vulnerability_validator.py** | Build | Finding confidence fields, dedup confidence, tamper status labels | No CONFIRMED / POTENTIAL / NOT_VULNERABLE / INCONCLUSIVE / NEEDS_MANUAL_REVIEW engine as specified |
| **false_positive_checker.py** | Build / Extend | Finding status `false_positive` + note; `tuning` FP rates | No pre-finding automated FP checker for Elite validation results |
| **screenshot_manager.py** | Reuse / Extend | `proof.screenshots`, gallery provenance, engagement/finding linkage | Stable filenames / test-case ID association for Elite runs needs a run-id model |
| **request_response_renderer.py** (two-panel image) | Build | Reports pretty-print `http_pair` as HTML `<pre>`; no Burp-like two-panel PNG | Visual request/response evidence images with syntax highlighting + field highlight are missing |
| **screenshot_annotator.py** | Reuse / Extend | `evidence.annotate.annotate_png`, `services.attach_annotated_screenshot` | Markers/borders/captions exist; arrows / param-specific highlight may need extension |
| **evidence_redactor.py** | Reuse | `evidence.mask`, `proof.redact`, `proof.screenshot_redact` | Meets intent; keep original restricted + sanitized report copy (already the pattern) |
| **evidence_hasher.py / manifest** | Reuse / Extend | SHA-256 on evidence store; backup manifests; provenance columns | Per test-execution Elite manifest (test case + engagement + capture method) may need a new table or JSON artifact |
| **burp_importer.py** | Reuse | `importers.burp`, `proof.capture.extract_pairs` | Already present; extend only if Elite XML/attachment cases fail |
| **attestra_findings.py** | Reuse | `services` findings + evidence + CWE/OWASP via library/importers + dedup | Integration layer should call existing APIs, not a parallel findings store |
| **run_tests.py CLI** | Extend | `attestra.cli`, scan/auth-web entrypoints | No Elite “list categories / run profile / export evidence” CLI façade |
| **Secure + vulnerable mock apps** | Build | Docs reference `tests/fixtures/auth_web_mock_app.py`; **file not present** (pyc only); smoke test file also absent from tree | Need secure mock + intentional vulnerable twin with BOLA/role/exposure/auth failures; isolated local-only |
| **T01–T18 pytest matrix** | Build | Many phase6/7 tests cover pieces; no Elite IDs | Map T-IDs onto new/extended tests; ≥85% cov target for **new** logic only |
| **E2E demo (BOLA on mocks → report)** | Build | Pieces exist separately | End-to-end scripted demo against both mocks not packaged |
| **Frontend: Evidence Collection / Automated Testing / History / Viewer / Validation** | Extend | Engagement + finding gallery, proof routes, auth-web UI surfaces | Elite-named engagement panels with start/monitor/confirm-reject proposed findings not present as specified |
| **Subscription ON/OFF + one credit per test run** | Reuse | `credits.service`, admit-on-scan, `SUBSCRIPTION_SERVICE` | Wire Elite orchestrator to **one credit per authorized test run**, not per screenshot/HTTP call (already the credit design for scans) |

---

## Test-case coverage foresight (Part 4)

| ID | Elite intent | Likely approach |
| --- | --- | --- |
| T01 HTTP capture | Extend HttpPair + live capture | New integration against mocks |
| T02 Browser screenshot | Reuse proof/auth-web capture | Wire to Elite run id |
| T03 Auth enforcement | Build auth test module | Secure pass / vulnerable detect |
| T04 BOLA/IDOR | Extend tamper + two-account fixture | Core demo path |
| T05 Role enforcement | Extend role_scan | Add vertical cases |
| T06 Tenant isolation | Extend + platform RLS patterns | Mock multi-tenant |
| T07 Sensitive exposure | Extend markers + validator | Vulnerable mock leak |
| T08 Response validation | **Build validator** | Central classification |
| T09 False-positive handling | Build FP checker + secure mock | No false CONFIRMED on secure |
| T10 Annotation | Reuse annotate_png | Extend if arrows required |
| T11 Redaction | Reuse mask/redact | Regression tests |
| T12 Integrity | Reuse hash verify | Manifest if added |
| T13 Finding mapping | Reuse services + dedup | Adapter tests |
| T14 Report integration | Reuse reports | Ensure Elite evidence kinds render |
| T15 Burp import | Reuse importer | Fixture regression |
| T16 Scope enforcement | Reuse/extend scope | Out-of-scope reject |
| T17 Tenant evidence isolation | Reuse Phase 9 path/tenant checks | Cross-tenant deny |
| T18 Subscription | Reuse credits | One debit per Elite run |

---

## Prompt risks and adaptations

1. **Do not scaffold a second architecture.** Prefer `attestra/automated_vapt/` only as a thin orchestration façade that imports existing modules, or skip the package name and extend auth_web/proof/evidence directly.
2. **Naming:** readable UI/docs say “security testing” / “VA + PT”, never “VAPT”; keep engagement key `vapt`.
3. **Safety:** intrusive execution must keep `assert_intrusive_allowed`, ownership, signed authorization, window, and rate limits. Elite “execute tests” must stay fail-closed outside approved scope.
4. **No OTP brute force / no production privilege mutation** — already aligned with Attestra design; keep explicit in new modules.
5. **Missing mock source:** restore or recreate auth-web mock, then add vulnerable twin before claiming T03–T09.
6. **Master-impl pacing (Section 0):** finish agreed Elite phase(s), stop for review; do not push; leave `tests/` uncommitted by habit unless asked otherwise.
7. **Prior master plan is complete** (Phases 0–12). Elite work is a **new program**, not a continuation of those phase numbers without renaming (suggest `Elite Phase 1…` or `AVP Phase 1…`).

---

## Suggested Elite implementation order (adapted)

Reuse the prompt’s sequence, but collapse duplicates:

| Elite Phase | Work | Depends on |
| --- | --- | --- |
| **E1** | This discovery map (done in this doc) | — |
| **E2** | Secure + vulnerable local mocks + fixtures | E1 |
| **E3** | Thin orchestrator + scope reuse/extend + status model | E2 |
| **E4** | Live HTTP capture → HttpPair storage | E3 |
| **E5** | Playwright workflow capture (extend crawl/screenshots) | E3 |
| **E6** | Auth + authz modules (wrap/extend tamper + role_scan) | E4–E5 |
| **E7** | Validator + FP checker (new) | E6 |
| **E8** | Two-panel HTTP renderer + annotate extensions | E4–E5 |
| **E9** | Manifest if needed; redaction/hash already mostly done | E8 |
| **E10** | Burp import regression only | — |
| **E11** | Findings/report wiring (existing services) | E7–E9 |
| **E12** | Engagement UI panels | E11 |
| **E13** | Credits: one debit per Elite test run | E3 |
| **E14–E15** | T01–T18 + demo + regression | All above |

---

## Deliverables checklist (Part 10) — current honesty

| Deliverable | Now |
| --- | --- |
| Working Python scripts (Elite package) | Not started (reuse candidates exist) |
| Frontend Elite panels | Not started |
| DB migrations for Elite runs | Not started (may need `test_executions` / manifest) |
| API endpoints for Elite runs | Not started (auth-web/proof APIs exist) |
| Secure + vulnerable mocks | Missing / incomplete |
| Unit / integration / security / e2e for Elite IDs | Not started |
| Sample annotated screenshots / HTTP files / report | Partial via existing proof/report paths |
| Coverage ≥85% on **new** Elite logic | N/A until built |
| Deployment / developer docs for Elite | This gap analysis only |

---

## Decision needed

Choose next step:

1. **E1 sign-off** — treat this doc as Phase 1 complete; stop.
2. **E2 mocks** — restore/create secure + vulnerable local apps and fixtures only.
3. **E2 + E3** — mocks plus thin orchestrator/status/scope wiring; stop before capture modules.
4. **Rewrite plan** — if you want a literal `automated_vapt/` tree despite reuse guidance, say so explicitly.

## Implementation progress

| Elite phase | Status | Notes |
| --- | --- | --- |
| E1 Discovery map | Done | This document |
| E2 Secure + vulnerable mocks | Done (2026-10-30) | Restored `tests/fixtures/auth_web_mock_app.py`; added `tests/automated_vapt/fixtures/` + `test_e2_mock_apps.py` |
| E3 Orchestrator + scope | Done (2026-10-30) | `attestra/automated_vapt/core/*`, model + migration 0034, API routes, `SCOPE_SMOKE`; other cases DEFERRED |
| E4 HTTP capture | Done (2026-10-30) | `capture/http_capture.py`, parsers, orchestrator `T01` |
| E5 Browser capture | Done (2026-10-30) | `capture/browser_capture.py`, orchestrator `T02` (Playwright optional; injectable capture_fn) |
| E6 Authz modules | Done (2026-10-30) | `testing/*` modules + orchestrator `T03`–`T07` |
| E7 Validation engine | Done (2026-10-30) | `validation/*` + wired into authz orchestrator results |
| E8 Evidence visuals | Done (2026-10-30) | two-panel renderer, annotate wrapper, screenshot manager |
| E9+ | Not started | Next: redaction/hash/manifest |
