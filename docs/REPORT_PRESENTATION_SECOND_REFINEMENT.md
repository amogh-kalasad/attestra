# Report presentation — second refinement

This document records **presentation-only** refinement of the enterprise PDF redesign. It does not change assessment scores, finding IDs, sealed HTML content, Pass/Fail outcomes, remediation text, environment labels, or timestamps. Chrome, palette, layout hierarchy, and print styling may change; product data must not be “corrected” in presentation code.

Presentation surface:

- `attestra/reports/presentation_tokens.py` — shared enterprise palette and CSS builders for HTML / PDF / DOCX chrome
- `attestra/reports/pdf.py` — PDF copy path (`prepare_html`, running header, severity accents, subtler DRAFT watermark, Contents / legend injection)

## Intended presentation improvements

Second refinement targets visual polish of the enterprise redesign only:

| Area | Intent |
|------|--------|
| **Cover** | Tighter cover (`padding-top` ~2.2cm), stronger title hierarchy, 3pt navy bottom rule, compact meta spacing |
| **Tables** | Body ~9pt / cells 8.5pt, navy-on-surface headers, 5–6pt padding, softened rules; **no** `tr:nth-child` zebra in `pdf_css` (xhtml2pdf CSS 2.1); screen CSS may zebra (excluding `.finding-meta` / `.kpis`); DOCX zebra where already implemented |
| **Findings hierarchy** | Severity left-border accents kept; more card padding / softer border; `.finding-meta` as compact surface key-facts strip; clearer `.finding-section` / `.finding-evidence` separators |
| **Evidence** | Images capped ~14.5cm with `-pdf-keep-with-next`; `pre.http-pair` on `SURFACE_ALT`; grouped `.finding-evidence` spacing/borders only |
| **Watermark** | Opacity remains in `pdf._watermark` (ReportLab navy-tint under content) — not encoded in PDF CSS |
| **Pagination** | Running engagement header, Page X of Y footer, keep-with-next on headings / evidence images |
| **Charts** | Clearer navy `.kpi-num`, balanced tile padding; severity trend / KPI chrome aligned to presentation tokens |

No change to finding text, checklist status values, environment fields, or generation clocks is in scope for this workstream.

## Data inconsistencies (baseline ENG #1) — do not “fix” in presentation

The following inconsistencies were observed in the **baseline ENG #1** technical report used for visual validation. They are **product / engineering investigation items**. Presentation code must not rewrite Pass/Fail, swap remediation copy, change environment labels, or alter timestamps to make the PDF look consistent.

1. **Page 8 — checklist Pass vs weakness narrative**  
   `hsts_short`, `tls_legacy`, and `tls_weak_cipher` show **Pass** while the accompanying explanations describe weaknesses (short HSTS / legacy TLS / weak ciphers). Status vs narrative mismatch needs data/rules review, not CSS.

2. **Page 7 vs page 15 — clock skew**  
   Authenticated checklist event time around **21:05 IST** vs report generation around **15:36 IST** on page 15. Investigate source clocks / display TZ / event ordering; do not paper over in the PDF layer.

3. **Page 3 — Production vs demo target**  
   Scope / document control shows a **Production** environment label against what appears to be a demo target / engagement configuration. Correct labeling belongs in engagement configuration or report context builders, not presentation tokens.

4. **Page 13 — Expect-CT remediation**  
   Remediation text associated with an Expect-CT finding appears **unrelated** to that finding. Fix finding content / remediation mapping upstream; do not substitute copy in `pdf.py` or templates for polish.

## Implemented in this pass

| Area | Status |
|------|--------|
| Cover tighter (`~2.2cm` top pad), navy rule | Done (`presentation_tokens.pdf_css` / `_base`) |
| Table padding, headers, PDF zebra via `_zebra_tables` | Done |
| Finding hierarchy (`.finding-facts` / `.finding-refs` / sections) | Done (templates; sealed HTML keeps prior card shape + PDF accents) |
| Evidence width / keep-with-next / captions | Done |
| Subtler DRAFT watermark (`~0.15×`, lighter fill) | Done (`pdf._watermark`) |
| Severity chart caption + prefer existing `trend_svg` | Done (`_inject_severity_bars`) |
| Summary KPI clarity + `.chart-block` | Done (technical / executive templates) |
| Data inconsistency “fixes” | **Not done** (flagged below only) |

Sample PDF: `eng1-technical-enterprise-second-refinement.pdf` (Downloads). `tests/test_pdf_export.py`: 18 passed.

## Validation baseline

- **ENG #3 (Anthive Q4) sealed HTML is still missing.** Do not treat ENG #3 Downloads PDFs alone as a sealed-HTML parity check for this refinement.
- Validation for this presentation pass uses **ENG #1 sealed HTML** plus the prior **Downloads** baseline PDF (e.g. `eng1-technical-enterprise-redesign.pdf` / related ENG1 exports).

When ENG #3 sealed HTML becomes available, re-run visual comparison against that engagement without changing assessment data in the presentation path.
