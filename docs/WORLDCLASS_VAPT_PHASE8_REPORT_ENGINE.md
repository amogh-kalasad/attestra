# World-Class VA + PT — Phase 8 Professional VAPT Report Engine

**Source:** `Downloads/# MASTER PROMPT WORLD-CLASS VAPT PL.txt`  
**Prior:** `docs/WORLDCLASS_VAPT_PHASE7_REMEDIATION.md`  
**Date:** 2026-11-05

Product wording: **security testing** / **VA + PT**. Technical reports must not invent tool versions or equate scan completion with coverage.

---

## Goals

- Complete the technical report section map (TOC + body) for professional VAPT deliverables.
- Add a **Tools and versions** table from recorded observation / scan `tool_version` only.
- Enrich assumptions / limitations with Phase 3–4 honesty rules.
- Surface engagement retest requests (or a standard how-to when none exist).
- Make DRAFT QA / approval placeholders explicit in document control and sign-off.
- Leave sealed-HTML QA polish and ENG1 V21 regression for **Phase 9**.

---

## Technical section map

| # | Required topic | Technical report surface | Notes |
| --- | --- | --- | --- |
| 1 | Cover | `_base.html.j2` cover band | Unchanged |
| 2 | Document control | `#document-control` | DRAFT row uses Pending QA / Pending approval; history shows `qa_by` / `approved_by` when set |
| 3 | Executive / summary | `#summary` (Summary) | KPI strip; not a separate Executive Summary h2 |
| 4 | Scope | `#scope` | Assets + authorizations |
| 5 | Methodology | `#methodology` | Phases + imports + scan history |
| 6 | Tools and versions | `#tools-and-versions` | **New** — Tool \| Version \| Notes |
| 7 | Standards and frameworks | `#standards` | Test types + standards list |
| 8 | Risk-rating methodology | `#risk-legend` | CVSS technical severity vs Priority / business risk (Phase 5) |
| 9 | Vulnerability summary | `#summary` | Same Summary unit |
| 10 | Findings overview | `#findings-overview` | Compact sev strip + overview table |
| 11 | Security testing coverage | `#security-testing-coverage` | Phase 4; TOC + body when context set |
| 12 | Detailed findings | `#findings` | Finding cards (sibling ownership for card chrome) |
| 13 | Evidence / repro | Cards `.finding-evidence` | Screenshots, HTTP pairs, register |
| 14 | Business impact | Cards Impact section | When `f.impact` set |
| 15 | Remediation | Cards Recommendation / pack blocks | Phase 7 packs |
| 16 | Testing limitations | `#disclaimer` / `#testing-limitations` | Honesty bullets |
| 17 | Assumptions | `#disclaimer` / `#assumptions` | Scope / access assumptions |
| 18 | Retesting information | `#retesting` | **New** — table or standard request paragraph |
| 19 | Conclusion | `#conclusion` | Unchanged intent |
| 20 | QA and approval / sign-off | `#sign-off` | Explicit DRAFT placeholders; live banner still outside sealed file |
| 21 | Appendix | `#appendix` | Imports + scan runs |

Distribution list, list of figures, status checks, auth checklist, site grades, TLS, and automated testing evidence remain optional TOC entries when data exists.

---

## Tools and versions

Context key `tools_and_versions` from `attestra/reports/render.py#_tools_and_versions`:

1. Collect distinct tools from `FindingObservation`, `ScanRun`, import runs, and `Finding.tools`.
2. Prefer non-empty `tool_version` from observations and scan runs.
3. If no version was recorded → display **`version not recorded`** (never invent).
4. Multiple recorded versions for one tool → join with `; ` and note “Multiple versions recorded”.

Template: `#tools-and-versions` table Tool | Version | Notes.

---

## Honesty copy (limitations)

Under `#disclaimer`, fixed bullets (independent of tenant disclaimer override):

- Skipped / blocked checklist ≠ passed.
- Scan completion ≠ security testing coverage.
- Unvalidated scanner alerts are not confirmed vulnerabilities.
- Failed / incomplete scans are not evidence of absence.

Assumptions paragraph covers out-of-scope systems, missing credentials, WAF / rate limits, and environment gaps.

---

## Retesting

Context key `retest_requests` from `attestra/reports/render.py#_retest_request_rows` (flat list from `retests_by_finding`).

- When rows exist: table of finding label, result, requester, dates, note.
- When empty: short standard paragraph on requesting via engagement UI / client portal and finalize-only-when-asset-reached.

---

## Primary files

- `attestra/reports/render.py` — `_tools_and_versions`, `_retest_request_rows`, `_context` keys
- `attestra/reports/templates/technical.html.j2` — TOC + body sections (`#tools-and-versions`, `#retesting`, enriched `#disclaimer` / `#sign-off` / `#document-control`)
- `attestra/reports/data/template_config.yaml` — technical `sections` list
- `docs/WORLDCLASS_VAPT_PHASE8_REPORT_ENGINE.md` (this file)
- `lat.md/reports.md`, `lat.md/architecture.md`

---

## Finding-card narrative depth

`attestra/reports/render.py#_attach_finding_narrative_fields` attaches getattr-safe view fields before Jinja render:

| Field | Source | Rules |
| --- | --- | --- |
| `validation_status_label` | `VALIDATION_STATUS_LABELS` / status labels | Never invents Confirmed for empty / unvalidated |
| `reproduction_steps` | Stored column, else location + tool default | Prefer stored text; list/tuple joined as lines |
| `cvss_version` | Column or vector-derived | Empty when neither available |
| `remediation_pack` | Phase 7 attach path | Root cause / recommended fix when pack matches |

Technical card order (when data exists): header (severity, workflow status, **Validation**, priority / business risk) → affected asset / endpoint / URLs → description → **reproduction steps** → impact → **root cause** → remediation (+ pack blocks) → references → **validation status** (+ reasons) → evidence / technical details (CWE, OWASP, CVSS, tools).

---

## Gaps left for Phase 9 QA

- Seal QA / signer identity into approved PDF chrome beyond the separate sign-off banner (Phase 1 audit note).
- ENG1 V21 regression pass against `Downloads/eng1-technical-v21.pdf` (CORS/SameSite/HSTS/cipher/XSS-Protection/checklist honesty).
- Optional: always-on Security testing coverage stub when snapshot is empty (today the section is omitted when context is null).
- Optional: executive-kind section parity for Tools and versions.
- Broader PDF/DOCX visual QA for new h2 anchors and long retest tables.

---

## Stop

Phase 8 report-section completeness and finding-card narrative depth ready for review. Next on request: **Phase 9 — QA**.
