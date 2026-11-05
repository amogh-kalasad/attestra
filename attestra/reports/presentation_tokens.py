"""Shared presentation tokens for HTML, PDF, and DOCX report styling.

Presentation layer only. Assessment scores, finding IDs, and data contracts
are unchanged — these values drive colours, type, and chrome.
"""
# @lat: [[reports#Exports]]

from __future__ import annotations

# Ink and surfaces (enterprise consulting: white page, navy headings, grey panels).
INK = "#16181d"
NAVY = "#0f2744"
QUIET = "#5b6170"
RULE = "#d8dce3"
RULE_STRONG = "#c9ccd4"
ACCENT = "#1b3a6b"  # dark navy brand (replaces bright blue)
SURFACE = "#f4f6f9"
SURFACE_ALT = "#eef1f6"
WHITE = "#ffffff"
NOTE_BG = "#f4f6f9"

# Severity: Critical red, High orange, Medium amber, Low blue, Info grey.
# Written severity labels always accompany colour in templates/PDF badges.
SEV = {
    "critical": "#a1161b",
    "high": "#d0461b",
    "medium": "#b7791f",
    "low": "#1d5f8a",
    "info": "#6b7280",
}

# Compliance control status colours (aligned with severity semantics where useful).
STATUS = {
    "met": "#1d5f8a",
    "no_exceptions": "#2f7f8a",
    "partial": "#b7791f",
    "not_met": "#a1161b",
    "not_assessed": "#6b7280",
    "not_applicable": "#6b7280",
}

PASSED = "#1d5f8a"
FAILED = "#a1161b"
CHIP_INTERNET_BG = "#e8f1f8"
CHIP_INTERNET_FG = "#0f2744"

# Hex without '#' for ReportLab / DOCX / SVG badge builders.
SEV_HEX = {k: v.lstrip("#") for k, v in SEV.items()}
SEV_HEX_DOCX = {k: v.lstrip("#").upper() for k, v in SEV.items()}


def pdf_css(*, font: str = "Inter", mono: str = "AttestraMono") -> str:
    """xhtml2pdf CSS 2.1 stylesheet (no custom properties, flex, or transforms).

    Zebra via ``tr:nth-child`` is unreliable in xhtml2pdf; ``pdf._zebra_tables``
    applies ``row-alt`` / bgcolor with [[SURFACE]]. DRAFT opacity is owned by
    ``pdf._watermark`` (subtle grey-blue under content), not this stylesheet.
    """
    c, h, m, lo, info = SEV["critical"], SEV["high"], SEV["medium"], SEV["low"], SEV["info"]
    st = STATUS
    return f"""
@page {{
  size: a4 portrait;
  margin: 1.6cm 1.4cm 2.0cm 1.4cm;
  @frame header {{ -pdf-frame-content: pdf-header; left: 1.4cm; width: 18.2cm; top: 0.55cm; height: 0.7cm; }}
  @frame footer {{ -pdf-frame-content: pdf-footer; left: 1.4cm; width: 18.2cm; bottom: 0.55cm; height: 0.85cm; }}
}}
body {{ font-family: {font}, Helvetica; font-size: 9.25pt; line-height: 1.48; color: {INK}; }}
h1 {{ font-size: 18pt; margin: 4pt 0 8pt 0; color: {NAVY}; -pdf-outline: false; }}
h2 {{ font-size: 12.5pt; margin-top: 15pt; margin-bottom: 6pt; padding-bottom: 3pt;
     color: {NAVY}; border-bottom: 0.75pt solid {NAVY}; -pdf-keep-with-next: true; }}
h3 {{ font-size: 10.5pt; margin-top: 10pt; margin-bottom: 4pt; color: {NAVY}; -pdf-keep-with-next: true; }}
.finding h3 {{ margin-top: 0; margin-bottom: 3pt; -pdf-keep-with-next: true; }}
p {{ margin: 0 0 5pt 0; }}
.meta {{ color: {QUIET}; font-size: 8.5pt; }}
.brand {{ font-weight: bold; color: {ACCENT}; letter-spacing: 0.04em; }}
table {{ width: 100%; margin: 5pt 0 10pt 0; }}
th, td {{ text-align: left; padding: 5pt 6pt; border-bottom: 0.4pt solid {RULE}; vertical-align: top; font-size: 8.5pt; }}
th {{ color: {NAVY}; font-weight: bold; font-size: 8pt; background-color: {SURFACE}; }}
tr.row-alt td {{ background-color: {SURFACE}; }}
.sev {{ color: #ffffff; font-weight: bold; padding: 1pt 4pt; }}
.sev-critical {{ background-color: {c}; }} .sev-high {{ background-color: {h}; }}
.sev-medium {{ background-color: {m}; }} .sev-low {{ background-color: {lo}; }} .sev-info {{ background-color: {info}; }}
.st {{ font-weight: bold; }}
.st-met {{ color: {st["met"]}; }} .st-partial {{ color: {st["partial"]}; }} .st-not_met {{ color: {st["not_met"]}; }}
.st-not_assessed, .st-not_applicable {{ color: {st["not_assessed"]}; }} .st-no_exceptions {{ color: {st["no_exceptions"]}; }}
.status-passed {{ color: {PASSED}; font-weight: bold; }}
.status-failed {{ color: {FAILED}; font-weight: bold; }}
.chip-internet {{ background-color: {CHIP_INTERNET_BG}; color: {CHIP_INTERNET_FG}; }}
.finding {{ border: 0.4pt solid {RULE}; border-left: 3pt solid {ACCENT}; padding: 5pt 7pt; margin: 5pt 0;
            background-color: {WHITE}; }}
.finding-critical {{ border-left-color: {c}; }}
.finding-high {{ border-left-color: {h}; }}
.finding-medium {{ border-left-color: {m}; }}
.finding-low {{ border-left-color: {lo}; }}
.finding-info {{ border-left-color: {info}; }}
.finding-head {{ margin: 0 0 2pt 0; page-break-inside: avoid; page-break-after: avoid; -pdf-keep-with-next: true; }}
.finding-header {{ margin: 0 0 2pt 0; font-size: 8.25pt; line-height: 1.3; color: {INK}; }}
.finding-facts {{ margin: 2pt 0 3pt 0; border: 0.4pt solid {RULE}; background-color: {SURFACE}; }}
.finding-facts th {{ width: 25%; background-color: {SURFACE}; color: {QUIET}; font-size: 7.5pt; font-weight: bold; border-bottom: none; }}
.finding-facts td {{ width: 25%; background-color: {SURFACE}; border-bottom: none; font-size: 8pt; }}
.finding-meta {{ margin: 1pt 0 2pt 0; }}
.finding-meta th, .finding-meta td {{ padding: 1pt 3pt; border-bottom: none; font-size: 7.5pt; }}
.finding-meta th {{ width: 26%; background-color: {SURFACE}; color: {QUIET}; font-size: 7pt; font-weight: bold; }}
.finding-meta td {{ background-color: {SURFACE}; color: {INK}; }}
.finding-refs-label {{ margin: 3pt 0 1pt 0; color: {QUIET}; font-size: 7.5pt; font-weight: bold; }}
.finding-refs {{ margin: 1pt 0 3pt 0; }}
.finding-refs th {{ width: 26%; background-color: {SURFACE}; color: {QUIET}; font-size: 7pt; font-weight: bold; }}
.finding-refs td {{ font-size: 7.5pt; }}
.finding-section {{ margin: 2pt 0 1pt 0; }}
.finding-section p {{ margin: 0 0 2pt 0; }}
.finding-evidence {{ margin-top: 3pt; padding-top: 3pt; border-top: 0.5pt solid {RULE_STRONG}; }}
.evidence-figure {{ margin: 2pt 0 4pt 0; }}
.mono {{ font-family: {mono}, Courier; font-size: 7pt; word-wrap: break-word; }}
pre {{ font-family: {mono}, Courier; font-size: 7.5pt; }}
pre.http-pair {{ background-color: {SURFACE_ALT}; border: 0.4pt solid {RULE}; padding: 6pt 8pt; }}
.note {{ background-color: {NOTE_BG}; border-left: 2.5pt solid {ACCENT}; padding: 7pt 9pt; font-size: 9pt; }}
.cover {{ padding-top: 6pt; padding-bottom: 0; border-bottom: none; }}
.cover-band {{ width: 100%; margin: 0 0 12pt 0; }}
.cover-band td, .cover-band-cell {{ border: none; background-color: {NAVY}; color: #ffffff; padding: 9pt 12pt; vertical-align: middle; }}
.cover-band-brand {{ font-size: 9pt; font-weight: bold; letter-spacing: 0.06em; color: #ffffff; }}
.cover-band-end {{ text-align: right; font-size: 8pt; color: #ffffff; }}
.cover-logo {{ height: 1.1cm; margin: 0 8pt 0 0; }}
.cover-brand {{ margin: 0 0 8pt 0; font-size: 8.5pt; }}
.cover h1 {{ font-size: 9pt; color: {ACCENT}; margin: 0 0 5pt 0; line-height: 1.3; font-weight: bold;
            text-transform: uppercase; letter-spacing: 0.1em; border-bottom: none; padding-bottom: 0; }}
.cover p {{ font-size: 19pt; font-weight: bold; color: {NAVY}; margin: 0 0 10pt 0; line-height: 1.2; }}
.cover p.meta, .cover .meta {{ font-size: 8.5pt; font-weight: normal; color: {QUIET}; line-height: 1.4; margin: 0 0 2pt 0; }}
.cover-meta {{ width: 100%; margin: 2pt 0 8pt 0; }}
.cover-meta th, .cover-meta td {{ border-bottom: 0.4pt solid {RULE}; padding: 7pt 8pt; vertical-align: top; font-size: 8.5pt; }}
.cover-meta th {{ width: 14%; color: {QUIET}; font-weight: bold; font-size: 7.5pt; background-color: {SURFACE}; }}
.cover-meta td {{ width: 36%; color: {INK}; background-color: {WHITE}; }}
.cover-prepared {{ margin: 2pt 0 0 0; }}
.cover-spacer {{ width: 100%; margin: 6pt 0 0 0; border: none; }}
.cover-spacer td, .cover-spacer-cell {{ border: none; background-color: {WHITE}; padding: 0; font-size: 1pt; color: {WHITE}; }}
.cover-spacer img {{ border: none; }}
.cover-foot {{ width: 100%; margin: 0; }}
.cover-foot td, .cover-foot-cell {{ border: none; background-color: {NAVY}; color: #ffffff; padding: 8pt 12pt; font-size: 8pt; }}
.toc-title {{ font-size: 13pt; font-weight: bold; color: {NAVY}; margin-bottom: 10pt; -pdf-outline: false; }}
.evidence-img {{ width: 14.5cm; border: 0.4pt solid {RULE}; margin: 6pt 0 2pt 0; -pdf-keep-with-next: true; }}
.fig-caption {{ color: {QUIET}; font-size: 8pt; margin: 0 0 10pt 0; }}
footer {{ margin-top: 18pt; color: {QUIET}; font-size: 8pt; line-height: 1.5; border-top: 0.4pt solid {RULE}; padding-top: 6pt; }}
#pdf-header {{ color: {QUIET}; font-size: 6.5pt; font-weight: normal; text-align: left;
              border-bottom: 0.3pt solid {RULE}; padding-bottom: 1pt; letter-spacing: 0; }}
#pdf-footer {{ color: {QUIET}; font-size: 7pt; text-align: center; }}
.summary-posture {{ margin: 2pt 0 6pt 0; page-break-inside: avoid; }}
.overview-sev-summary {{ width: 100%; margin: 4pt 0 8pt 0; }}
.overview-sev-summary th, .overview-sev-summary td {{ text-align: center; padding: 4pt 3pt; font-size: 8pt; border-bottom: 0.4pt solid {RULE}; }}
.overview-sev-summary th {{ background-color: {SURFACE}; }}
.overview-table {{ margin: 4pt 0 10pt 0; }}
.overview-table th, .overview-table td {{ padding: 3pt 4pt; font-size: 8pt; }}
.overview-table th {{ font-size: 7.5pt; }}
.overview-table .mono {{ font-size: 7pt; }}
.status-checks-table {{ margin: 4pt 0 10pt 0; }}
.status-checks-table th, .status-checks-table td {{ padding: 3pt 5pt; font-size: 8pt; }}
.status-checks-table th {{ font-size: 7.5pt; }}
.status-checks-table .mono {{ font-size: 7pt; word-wrap: break-word; }}
.site-grades {{ margin: 3pt 0 8pt 0; }}
.site-grades th, .site-grades td {{ padding: 3pt 5pt; font-size: 8pt; }}
.site-grades th {{ font-size: 7.5pt; }}
.site-grades .mono {{ font-size: 7pt; word-wrap: break-word; }}
table.kpis {{ width: 100%; margin: 2pt 0 3pt 0; -pdf-keep-with-next: true; }}
table.kpis td {{ border: 0.4pt solid {RULE}; background-color: {SURFACE}; padding: 9pt 6pt 8pt 6pt; text-align: center;
                vertical-align: middle; font-size: 8pt; color: {QUIET}; }}
.kpi-label {{ margin: 0 0 5pt 0; font-size: 8pt; line-height: 1.2; text-align: center; color: {QUIET}; }}
.kpi-sub {{ margin: 4pt 0 0 0; font-size: 7.5pt; color: {QUIET}; line-height: 1.2; text-align: center; }}
table.kpis td.gap {{ border: none; background-color: {WHITE}; padding: 0; width: 6pt; }}
.kpi-num {{ font-size: 18pt; font-weight: bold; color: {NAVY}; margin: 0; line-height: 1.1; text-align: center; }}
.chart-block {{ margin: 0 0 6pt 0; }}
.chart-caption {{ margin: 1pt 0 3pt 0; color: {QUIET}; font-size: 8pt; -pdf-keep-with-next: true; }}
.appendix-table {{ margin: 3pt 0 8pt 0; }}
.appendix-table th, .appendix-table td {{ padding: 3pt 4pt; font-size: 7.5pt; }}
.appendix-table th {{ font-size: 7pt; }}
.appendix-table .mono {{ font-size: 6pt; word-wrap: break-word; }}
img.badge {{ vertical-align: middle; }}
pdftoc {{ color: {INK}; }}
pdftoc.pdftoclevel0 {{ font-weight: bold; margin-top: 5pt; color: {NAVY}; }}
pdftoc.pdftoclevel1 {{ margin-left: 1em; }}
"""

def base_html_css() -> str:
    """Screen/HTML stylesheet for ``_base.html.j2`` (supports CSS variables).

    Keep in sync with the ``<style>`` block in ``templates/_base.html.j2``.
    """
    return f"""
  :root {{ --ink:{INK}; --navy:{NAVY}; --quiet:{QUIET}; --rule:{RULE}; --rule-strong:{RULE_STRONG}; --accent:{ACCENT};
          --surface:{SURFACE}; --surface-alt:{SURFACE_ALT};
          --crit:{SEV["critical"]}; --high:{SEV["high"]}; --med:{SEV["medium"]};
          --low:{SEV["low"]}; --info:{SEV["info"]}; }}
  * {{ box-sizing: border-box; }}
  body {{ font: 14px/1.55 -apple-system, "Segoe UI", Inter, Roboto, sans-serif; color: var(--ink); background:#fff;
         max-width: 960px; margin: 0 auto; padding: 40px 28px 80px; counter-reset: page; }}
  h1 {{ font-size: 26px; margin: 0 0 8px; color: var(--navy); }}
  h2 {{ font-size: 18px; margin: 36px 0 10px; border-bottom: 1.5px solid var(--navy); padding-bottom: 5px; color: var(--navy); }}
  h3 {{ font-size: 15px; margin: 22px 0 8px; color: var(--navy); }}
  p {{ margin: 0 0 10px; }}
  .meta {{ color: var(--quiet); font-size: 13px; }}
  .brand {{ font-weight: 700; letter-spacing: .04em; color: var(--accent); }}
  table {{ width: 100%; border-collapse: collapse; margin: 10px 0 18px; font-size: 13px; }}
  th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--rule); vertical-align: top; }}
  th {{ color: var(--navy); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: .04em;
       background: var(--surface); }}
  table:not(.finding-meta):not(.finding-facts):not(.finding-refs):not(.kpis):not(.cover-band):not(.cover-meta):not(.cover-foot):not(.cover-spacer):not(.overview-sev-summary) tbody tr:nth-child(even) td {{ background: var(--surface-alt); }}
  .sev {{ display:inline-block; padding: 2px 10px; border-radius: 4px; color:#fff; font-size: 12px; font-weight:600; text-transform: capitalize; }}
  .sev-critical{{background:var(--crit)}} .sev-high{{background:var(--high)}} .sev-medium{{background:var(--med)}}
  .sev-low{{background:var(--low)}} .sev-info{{background:var(--info)}}
  .chip-internet {{ background: {CHIP_INTERNET_BG}; color: {CHIP_INTERNET_FG}; }}
  .status-passed {{ color: {PASSED}; font-weight: 600; }}
  .status-failed {{ color: {FAILED}; font-weight: 600; }}
  .st {{ font-weight: 600; text-transform: capitalize; }}
  .st-met{{color:{STATUS["met"]}}} .st-no_exceptions{{color:{STATUS["no_exceptions"]}}}
  .st-partial{{color:{STATUS["partial"]}}} .st-not_met{{color:{STATUS["not_met"]}}}
  .st-not_assessed,.st-not_applicable{{color:{STATUS["not_assessed"]}}}
  .kpis {{ display:flex; gap:16px; flex-wrap: wrap; margin: 12px 0 6px; }}
  .kpi {{ border:1px solid var(--rule); border-radius: 6px; padding: 14px 18px; min-width: 118px; background: var(--surface); }}
  .kpi b {{ display:block; font-size: 24px; color: var(--navy); }}
  .summary-posture {{ margin: 8px 0 14px; }}
  .overview-sev-summary {{ width: 100%; margin: 8px 0 12px; }}
  .overview-sev-summary th, .overview-sev-summary td {{ text-align: center; padding: 6px 4px; font-size: 12px; }}
  .overview-table th, .overview-table td {{ padding: 5px 6px; font-size: 12px; }}
  .overview-table .mono {{ font-size: 11px; }}
  .status-checks-table th, .status-checks-table td {{ padding: 5px 8px; font-size: 12px; }}
  .status-checks-table .mono {{ font-size: 11px; word-break: break-all; }}
  .site-grades th, .site-grades td {{ padding: 5px 8px; font-size: 12px; }}
  .site-grades .mono {{ font-size: 11px; word-break: break-all; }}
  .chart-block {{ margin: 4px 0 12px; }}
  .chart-caption, .chart-block > .meta {{ margin: 0 0 6px; color: var(--quiet); font-size: 12px; }}
  .appendix-table {{ font-size: 12px; }}
  .appendix-table th, .appendix-table td {{ padding: 5px 6px; }}
  .appendix-table .mono {{ font-size: 10px; word-break: break-all; }}
  .finding {{ border:1px solid var(--rule); border-left: 4px solid var(--accent); border-radius: 4px;
              padding: 8px 10px; margin: 8px 0; background: #fff; }}
  .finding-critical {{ border-left-color: var(--crit); }}
  .finding-high {{ border-left-color: var(--high); }}
  .finding-medium {{ border-left-color: var(--med); }}
  .finding-low {{ border-left-color: var(--low); }}
  .finding-info {{ border-left-color: var(--info); }}
  .finding h3 {{ margin-top: 0; margin-bottom: 4px; }}
  .finding-head {{ margin: 0 0 4px; page-break-inside: avoid; page-break-after: avoid; }}
  .finding-header {{ margin: 0 0 3px; font-size: 13px; line-height: 1.35; color: var(--ink); }}
  .finding-facts {{ margin: 4px 0 8px; border: 1px solid var(--rule); background: var(--surface); }}
  .finding-facts th {{ width: 25%; background: transparent; color: var(--quiet); text-transform: none; letter-spacing: 0;
                      font-size: 11px; font-weight: 600; border-bottom: none; padding: 4px 8px 2px; }}
  .finding-facts td {{ width: 25%; background: transparent; border-bottom: none; padding: 2px 8px 6px; font-size: 12.5px; }}
  .finding-meta {{ margin: 2px 0 4px; }}
  .finding-meta th, .finding-meta td {{ padding: 2px 6px; border-bottom: none; font-size: 12px; background: var(--surface); }}
  .finding-meta th {{ width: 26%; color: var(--quiet); text-transform: none; letter-spacing: 0; font-weight: 600; }}
  .finding-refs-label {{ margin: 4px 0 2px; font-size: 12px; color: var(--quiet); font-weight: 600; }}
  .finding-refs {{ margin: 2px 0 6px; }}
  .finding-refs th {{ width: 26%; background: var(--surface); color: var(--quiet); text-transform: none; letter-spacing: 0;
                     font-weight: 600; font-size: 11px; }}
  .finding-section {{ margin: 4px 0 2px; }}
  .finding-section p {{ margin: 0 0 3px; }}
  .finding-evidence {{ margin-top: 6px; padding-top: 6px; border-top: 1px solid var(--rule-strong); }}
  .evidence-figure {{ margin: 4px 0 8px; }}
  .mono {{ font-family: ui-monospace, Menlo, monospace; font-size: 12px; word-break: break-all; }}
  .note {{ background: var(--surface); border-left: 4px solid var(--accent); padding: 12px 16px; font-size: 13px; }}
  .cover {{ min-height: 72vh; display:flex; flex-direction:column; justify-content:flex-start;
           border-bottom: none; margin: 0 0 28px; padding: 0; page-break-after: always; }}
  .cover-band {{ width: 100%; border-collapse: collapse; margin: 0 0 20px; background: var(--navy); }}
  .cover-band td {{ border: none; padding: 14px 18px; vertical-align: middle; background: var(--navy); color: #fff; }}
  .cover-band-brand {{ font-size: 13px; font-weight: 700; letter-spacing: .06em; text-transform: uppercase; color: #fff; }}
  .cover-band-end {{ text-align: right; font-size: 12px; color: rgba(255,255,255,.85); letter-spacing: .04em; }}
  .cover-logo {{ max-height: 48px; max-width: 180px; margin: 0 14px 0 0; vertical-align: middle; background: #fff; padding: 4px 8px; }}
  .cover-brand {{ margin: 0 0 14px; font-size: 13px; }}
  .cover h1 {{ font-size: 13px; margin: 0 0 6px; line-height: 1.3; color: var(--accent); font-weight: 700;
              text-transform: uppercase; letter-spacing: .1em; border: none; padding: 0; }}
  .cover > p {{ font-size: 28px; font-weight: 700; margin: 0 0 16px; line-height: 1.2; color: var(--navy); }}
  .cover p.meta {{ font-size: 13px; font-weight: 400; margin: 0 0 3px; color: var(--quiet); }}
  .cover-meta {{ width: 100%; border-collapse: collapse; margin: 6px 0 14px; font-size: 13px; }}
  .cover-meta th, .cover-meta td {{ border-bottom: 1px solid var(--rule); padding: 10px 12px; vertical-align: top; background: #fff; }}
  .cover-meta th {{ width: 14%; color: var(--quiet); font-weight: 600; font-size: 11px; text-transform: uppercase;
                   letter-spacing: .04em; background: var(--surface); }}
  .cover-meta td {{ width: 36%; color: var(--ink); background: #fff; }}
  .cover-prepared {{ margin: 4px 0 0; }}
  .cover-spacer {{ width: 100%; border-collapse: collapse; flex: 1 1 auto; margin: 0; }}
  .cover-spacer td {{ border: none; background: transparent; height: 48px; padding: 0; font-size: 1px; color: transparent; }}
  .cover-foot {{ width: 100%; border-collapse: collapse; margin: 0; background: var(--navy); }}
  .cover-foot td {{ border: none; padding: 12px 18px; background: var(--navy); color: rgba(255,255,255,.9);
                   font-size: 12px; letter-spacing: .03em; }}
  .toc a {{ color: var(--ink); text-decoration: none; }}
  .toc li {{ margin: 5px 0; }}
  .evidence-img {{ max-width: 100%; max-height: 360px; height: auto; width: auto; object-fit: contain;
                   border: 1px solid var(--rule); margin: 8px 0 4px; }}
  .fig-caption {{ color: var(--quiet); font-size: 12px; margin: 0 0 14px; }}
  pre.http-pair {{ background: var(--surface-alt); border:1px solid var(--rule); border-radius:4px; padding:12px 14px;
                  white-space:pre-wrap; word-break:break-word; max-height:420px; overflow:auto; font-size:11px; }}
  .draft-mark {{ position: fixed; top: 40%; left: 10%; font-size: 64px; color: rgba(15,39,68,.06);
                transform: rotate(-28deg); pointer-events: none; z-index: 0; font-weight: 800; letter-spacing: .08em; }}
  footer {{ margin-top: 48px; color: var(--quiet); font-size: 12px; border-top:1px solid var(--rule); padding-top: 12px; }}
  @media print {{
    body {{ padding: 0; }}
    h2 {{ page-break-after: avoid; }}
    .finding-head {{ page-break-inside: avoid; page-break-after: avoid; }}
    .draft-mark {{ position: fixed; }}
    @page {{ margin: 16mm 14mm 18mm; @bottom-center {{ content: "Page " counter(page) " of " counter(pages); font-size: 9px; color: {QUIET}; }}
            @top-left {{ content: ""; }} }}
  }}
"""
