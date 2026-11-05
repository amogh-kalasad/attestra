# Report presentation — standard VAPT template

This pass **FINALIZES** the **one standard reusable VAPT PDF template** for **all** Attestra engagements (small and large). Visual polish and print chrome follow this single baseline for every future Attestra VAPT (VA + PT) technical report; assessment scores, finding IDs, sealed HTML content, Pass/Fail outcomes, remediation text, environment labels, and timestamps are not rewritten here.

**Deliverables (sample PDFs):** ENG #1 sealed baseline + ENG #3 layout-stress fixture — see Validation below (`eng1-technical-standard-template.pdf`, `eng3-technical-standard-template-fixture.pdf`).

## Presentation-only surface

Chrome and layout live only in:

| Path | Role |
|------|------|
| `attestra/reports/presentation_tokens.py` | Shared enterprise palette and CSS builders (HTML / PDF / DOCX) |
| `attestra/reports/pdf.py` | PDF copy path: `prepare_html`, running header/footer, severity accents, DRAFT watermark |
| `attestra/reports/templates/_base.html.j2` | Shared cover, screen DRAFT mark, print CSS, finding-card chrome |
| `attestra/reports/templates/technical.html.j2` | Technical VAPT body structure and finding cards |
| `attestra/reports/templates/executive.html.j2` | Executive summary chrome aligned to the same tokens |

Sealed HTML is never mutated; PDF export works on a copy via `prepare_html`.

## Goals of this finalized standard template

One reusable presentation chrome for every engagement size. Layout stress is validated on the ENG #3 fixture; live sealed parity remains ENG #1 until ENG #3 sealed HTML exists.

| Area | Intent |
|------|--------|
| **Cover identity** | Clear Attestra / engagement identity, title hierarchy, navy rule, compact meta |
| **Integrated severity chart** | KPIs + caption + chart in one `.summary-posture` unit; prefer existing `trend_svg`; otherwise inject KPI-derived bars with caption (wrap sealed HTML that lacks the wrapper) |
| **Tables** | Body ~9.25pt / cells 8.5pt / headers 8pt, ~5–6pt padding, navy-on-surface headers, PDF zebra via `_zebra_tables` (not CSS `nth-child`); `_size_columns` boosts title/file/check columns and soft-caps hash columns (~16%); denser `.status-checks-table` / `.site-grades` / `.overview-table` |
| **Findings overview** | Compact `.overview-sev-summary` (open Critical–Info counts via `by_sev` / sev chips) above denser `.overview-table` (ID / Title truncated 90 chars display-only / Severity / Status / Retest / Asset; 3–4pt / 8pt PDF); meta line when 25+ findings |
| **Finding cards** | Severity left-border accents; `.finding-head` keep-together; severity chip/badge once (no duplicate capitalized word); `.finding-meta`; narrative `.finding-section`; quieter “Technical details” `.finding-refs`; denser spacing; long bodies may split; LayoutError retry retained |
| **Pagination** | Quieter running engagement header, `Page X of Y` footer, keep-with-next on headings and evidence images |
| **Watermark** | Lifecycle-correct DRAFT stamp (see below); subtle under-content mark via `pdf._watermark` (~0.12× page min dim, fill ~0.95/0.96/0.97) — not PDF CSS |
| **Appendix hashes** | `.appendix-table` quieter/denser (tighter pad, ~6pt mono); sha256 wraps; hash columns soft-capped so titles are not crushed |
| **Running header** | Quieter `#pdf-header` (~6.5pt engagement · Confidential, truncated); not a second title block |
| **Page consistency** | Uniform margins, chrome, and section rhythm across technical (and aligned executive) pages; tighter KPI/chart margins; Title Case via `title_case` / `_display_case` (e.g. Risk Rating Legend) |

## Document control and DRAFT watermark (preserve)

- **Document control** stays the existing approach: version / change history table (Change column), distribution, and related front-matter from report context — presentation must not invent or rewrite control rows.
- **Report lifecycle watermark**:
  - **Draft** (unsigned): DRAFT is stamped (HTML screen mark and/or PDF under-content watermark via `pdf._watermark`).
  - **Signed**: DRAFT is **not** stamped.

Do not change these rules for visual polish.

## Data inconsistencies — document, do not “fix” in presentation

Product / data inconsistencies discovered during visual validation must be **documented separately** (investigation items). Presentation code must **never** silently correct Pass/Fail, remediation copy, environment labels, clocks, or other assessment content to make the PDF look consistent.

### Known data inconsistencies (investigation)

Copied from the ENG #1 baseline recorded in `docs/REPORT_PRESENTATION_SECOND_REFINEMENT.md`:

1. **Page 8 — checklist Pass vs weakness narrative**  
   `hsts_short`, `tls_legacy`, and `tls_weak_cipher` show **Pass** while the accompanying explanations describe weaknesses (short HSTS / legacy TLS / weak ciphers). Status vs narrative mismatch needs data/rules review, not CSS.

2. **Page 7 vs page 15 — clock skew**  
   Authenticated checklist event time around **21:05 IST** vs report generation around **15:36 IST** on page 15. Investigate source clocks / display TZ / event ordering; do not paper over in the PDF layer.

3. **Page 3 — Production vs demo target**  
   Scope / document control shows a **Production** environment label against what appears to be a demo target / engagement configuration. Correct labeling belongs in engagement configuration or report context builders, not presentation tokens.

4. **Page 13 — Expect-CT remediation**  
   Remediation text associated with an Expect-CT finding appears **unrelated** to that finding. Fix finding content / remediation mapping upstream; do not substitute copy in `pdf.py` or templates for polish.

### ENG #3 severity-count inconsistency (investigation)

Investigate separately in **data / report-generation** — do **not** hide or silently correct in presentation (CSS, PDF chrome, or template polish).

- The Downloads/live ENG #3 baseline PDF and/or the presentation fixture may show **severity KPI / chart totals that disagree** with the findings overview and/or detailed finding severities (count mismatch across summary KPIs, severity chart, and finding list).
- Document and fix upstream (aggregates, `by_sev` / sealed HTML builders, fixture construction). Presentation must not recompute or patch counts to make the PDF look consistent.
- The ENG #3 presentation fixture is **layout stress testing only** (page volume, finding-card density, appendix chrome). It is not a claim of Anthive Q4 data integrity.
- When actual ENG #3 sealed source is available, **re-validate** severity KPIs, chart totals, overview, and detailed finding severities against that sealed HTML — still without presentation-layer count fixes.

## Validation notes (ENG #3 Anthive Q4)

**ENG #3 Anthive Q4:** if sealed HTML is unavailable in the live DB, validation uses available large-engagement HTML and/or a stress fixture. Downloads eng3 PDF is a **baseline reference only** — not a sealed-HTML parity check. Prefer sealed HTML from ENG #1 (or another available large engagement) for presentation validation until ENG #3 sealed HTML exists. See **ENG #3 severity-count inconsistency** above.

Related prior notes: `docs/REPORT_PRESENTATION_SECOND_REFINEMENT.md`. Knowledge-graph section: `lat.md/reports.md` → Exports → PDF presentation.

## Validation (2026-11-04 standard-template PDF QA)

Fast visual QA of the **finalized** standard-template PDFs (xhtml2pdf). Assessment data and the known-inconsistencies lists (ENG #1 + ENG #3 severity-count) were left unchanged.

**Sample deliverables:** eng1 + eng3 fixture PDFs below.

| Artifact | Path | Pages |
|----------|------|-------|
| ENG #1 PDF | `C:\Users\t480s\Downloads\eng1-technical-standard-template.pdf` (Temp: `attestra-eng1-standard.pdf`) | **16** |
| ENG #1 rasters | `%TEMP%\attestra-eng1-standard-pages\page-N.png` (all pages @ ~100 dpi) | 16 |
| ENG #3 PDF | `C:\Users\t480s\Downloads\eng3-technical-standard-template-fixture.pdf` (Temp: `attestra-eng3-standard-template.pdf`) | **39** |
| ENG #3 rasters | `%TEMP%\attestra-eng3-standard-pages\` (pages 1, 2, 3, mid=20, last=39; plus 6–7 for summary) | 39 total |

**ENG #3** is a **presentation stress fixture** (55 findings, F-62…F-116), not live Anthive Q4 sealed HTML — Mongo / `data/tenants` still lacks that sealed report. Severity KPI/chart vs findings count mismatches on ENG #3 are investigation items only (see above).

| Check | ENG #1 | ENG #3 fixture |
|-------|--------|----------------|
| Navy cover identity (band / Confidential / ATTESTRA / meta / foot) | Pass (p1) | Pass (p1; fixture banner on cover) |
| Summary KPIs + severity chart | Pass (KPIs p4 → chart p5) | Pass layout (KPIs + chart p6); counts may disagree with findings — investigate upstream |
| Subtler DRAFT watermark | Pass (under-content diagonal) | Pass |
| Finding cards readable | Pass (e.g. p9 F-1) | Pass (e.g. mid p20) |
| Appendix / import SHA-256 readable | Pass (Import Log p4; Appendix A p16) | Pass (conclusion p39 notes 55 findings; same chrome) |

Verdict: **PASS** for finalized standard-template presentation chrome (all engagement sizes). Do not treat ENG #3 as sealed-HTML parity; re-check severity counts when sealed ENG #3 source is available.

### Finalization QA (2026-11-04)

Final visual QA of the same Downloads PDFs, rasterized with pypdfium2 (~150 dpi) to `%TEMP%\attestra-eng1-final-qa\` (pages 1, 2, 4, 5, 8, 9, 16) and `%TEMP%\attestra-eng3-final-qa\` (pages 1, 2, 6, 7, 20, 37). Assessment content and known-inconsistency lists were not changed. **ENG #3 fixture is layout stress only** (not Anthive Q4 sealed parity); the ENG #3 severity-count inconsistency remains **investigation-only** and must not be patched in presentation chrome.

| Artifact | Path | Pages |
|----------|------|-------|
| ENG #1 PDF | `C:\Users\t480s\Downloads\eng1-technical-standard-template.pdf` | **16** |
| ENG #1 rasters | `%TEMP%\attestra-eng1-final-qa\page-NN.png` | 7 sampled |
| ENG #3 fixture PDF | `C:\Users\t480s\Downloads\eng3-technical-standard-template-fixture.pdf` | **37** |
| ENG #3 rasters | `%TEMP%\attestra-eng3-final-qa\page-NN.png` | 6 sampled |

Finding IDs confirmed in PDF text: ENG #1 **F-1…F-11** (11/11); ENG #3 fixture **F-62…F-116** (55/55 contiguous).

| Check | ENG #1 | ENG #3 fixture |
|-------|--------|----------------|
| Cover navy band / meta / foot | **PASS** (p1) | **PASS** (p1; fixture banner above band) |
| Summary KPIs + chart together | **PASS** (both on p5 in `.summary-posture`) | **PASS** layout (both on p6); severity-count vs findings remains investigation-only |
| Overview severity strip + dense table | **PASS** dense `.overview-table` (p5); strip **absent** on sealed HTML path (Jinja `overview-sev-summary` is for fresh renders; `prepare_html` does not inject it) | **PASS** dense table (p7+); same sealed/fixture strip absence; 25+ meta line present |
| Finding cards | **PASS** (p9 F-1 / F-2; head keep-together, sev chip once) | **PASS** (p20 F-80…; fixture synthetic cards under load) |
| Appendix / import SHA-256 | **PASS** (p16 Appendix A; hashes wrap, readable) | **PASS** (p37 Appendix A; same chrome) |
| Subtle DRAFT watermark | **PASS** (under-content diagonal ~RGB 0.95; all pages) | **PASS** (all 37 pages) |

**Verdict: PASS** for finalized standard-template presentation chrome on ENG #1 sealed baseline and ENG #3 layout-stress fixture. Overview severity-strip absence on sealed/fixture HTML is a known sealed-path gap (template-ready for new Jinja renders), not a data rewrite. Do not treat ENG #3 as sealed-HTML parity; leave ENG #3 severity-count mismatch as investigation-only.
