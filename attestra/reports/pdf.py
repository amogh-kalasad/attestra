"""Styled PDF rendering for frozen HTML reports.

The sealed HTML report is never changed. For the PDF we take a copy of it and
add print-only parts: a cover page break, a contents page with page numbers,
a severity legend and a disclaimer when the report kind has none, a
"Page X of Y" footer, and a DRAFT watermark while the report is not signed.

Engines, in order:
1. WeasyPrint, when it is installed and its native libraries load (Linux / Docker).
2. xhtml2pdf (pure Python, declared as a core dependency, works on Windows).
The caller falls back to a plain-text PDF when both are missing.
"""
# @lat: [[reports#Exports]]

from __future__ import annotations

import base64
import re
from datetime import UTC
from html import escape
from io import BytesIO
from pathlib import Path

LETTER_KINDS = ("closure_letter", "attestation_letter")

FONT_DIR = Path(__file__).parent / "fonts"
FONT = "Inter"  # bundled, SIL Open Font Licence; see fonts/LICENSES.md
MONO = "AttestraMono"  # DejaVu Sans Mono, bundled


def _font_css() -> str:
    """@font-face rules for the bundled fonts (forward slashes keep Windows paths valid in CSS)."""
    faces = [
        (FONT, "Inter-Regular.ttf", "normal", "normal"),
        (FONT, "Inter-Bold.ttf", "bold", "normal"),
        (FONT, "Inter-Italic.ttf", "normal", "italic"),
        (FONT, "Inter-BoldItalic.ttf", "bold", "italic"),
        (MONO, "DejaVuSansMono.ttf", "normal", "normal"),
        (MONO, "DejaVuSansMono.ttf", "bold", "normal"),
    ]
    out = []
    for fam, file, weight, style in faces:
        path = (FONT_DIR / file).as_posix()
        if (FONT_DIR / file).exists():
            out.append(f'@font-face {{ font-family: {fam}; src: url("{path}"); font-weight: {weight}; font-style: {style}; }}')
    return "\n".join(out)


def _register_badge_font() -> str:
    """Register Inter Bold with ReportLab for SVG badges and the watermark; fall back to Helvetica."""
    try:
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont

        if "Inter-Bold" not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont("Inter-Bold", str(FONT_DIR / "Inter-Bold.ttf")))
        try:  # svglib keeps its own font map; without this SVG text falls back to Helvetica
            from svglib.fonts import register_font

            register_font("Inter-Bold", str(FONT_DIR / "Inter-Bold.ttf"), rlgFontName="Inter-Bold")
        except Exception:
            pass
        return "Inter-Bold"
    except Exception:
        return "Helvetica-Bold"


SEV_HEX = {"critical": "a1161b", "high": "d0461b", "medium": "b7791f", "low": "3b7d4f", "info": "6b7280"}

SEVERITY_LEGEND = (
    ("critical", "9.0 – 10.0", "Exploitable now with severe impact. Fix immediately."),
    ("high", "7.0 – 8.9", "Serious weakness likely to be exploited. Fix within days."),
    ("medium", "4.0 – 6.9", "Exploitable under some conditions. Fix in the next release cycle."),
    ("low", "0.1 – 3.9", "Limited impact. Fix as part of normal hardening."),
    ("info", "0.0", "Observation or best-practice note; no direct risk."),
)

DISCLAIMER = (
    "This report reflects the state of the in-scope assets during the testing window only. "
    "Security testing is a point-in-time exercise and cannot prove the absence of vulnerabilities; "
    "assets, configurations and threats change after the window closes. Findings rely on the tools, "
    "evidence and access available to the testers. Compliance statuses are proposals until a named "
    "assessor confirms them. This document is confidential and intended only for the named client."
)

# xhtml2pdf understands CSS 2.1 only (no custom properties, flexbox or transforms).
PDF_CSS = """
@page {
  size: a4 portrait;
  margin: 1.8cm 1.5cm 2.2cm 1.5cm;
  @frame footer { -pdf-frame-content: pdf-footer; left: 1.5cm; width: 18cm; bottom: 0.7cm; height: 1cm; }
}
body { font-family: Inter, Helvetica; font-size: 9pt; line-height: 1.4; color: #16181d; }
h1 { font-size: 22pt; margin: 6pt 0; -pdf-outline: false; }
h2 { font-size: 14pt; margin-top: 14pt; margin-bottom: 6pt; padding-bottom: 3pt;
     border-bottom: 0.5pt solid #c9ccd4; -pdf-keep-with-next: true; }
h3 { font-size: 11pt; margin-top: 10pt; margin-bottom: 4pt; -pdf-keep-with-next: true; }
p { margin: 0 0 5pt 0; }
.meta { color: #5b6170; font-size: 8.5pt; }
.brand { font-weight: bold; color: #2457d6; }
table { width: 100%; margin: 4pt 0 10pt 0; }
th, td { text-align: left; padding: 3pt 4pt; border-bottom: 0.5pt solid #e3e5ea; vertical-align: top; font-size: 8.5pt; }
th { color: #5b6170; font-weight: bold; font-size: 8pt; }
.sev { color: #ffffff; font-weight: bold; padding: 1pt 4pt; }
.sev-critical { background-color: #a1161b; } .sev-high { background-color: #d0461b; }
.sev-medium { background-color: #b7791f; } .sev-low { background-color: #3b7d4f; } .sev-info { background-color: #6b7280; }
.st { font-weight: bold; }
.st-met { color: #3b7d4f; } .st-partial { color: #b7791f; } .st-not_met { color: #a1161b; }
.st-not_assessed, .st-not_applicable { color: #6b7280; } .st-no_exceptions { color: #2f7f8a; }
.finding { border: 0.5pt solid #e3e5ea; padding: 6pt 8pt; margin: 8pt 0; }
.mono { font-family: AttestraMono, Courier; font-size: 7.5pt; }
pre { font-family: AttestraMono, Courier; font-size: 7.5pt; }
.note { background-color: #f5f7fb; border-left: 2pt solid #2457d6; padding: 6pt 8pt; font-size: 9pt; }
.cover { padding-top: 6cm; }
.toc-title { font-size: 14pt; font-weight: bold; margin-bottom: 8pt; }
.cover h1 { font-size: 26pt; }
.cover img { height: 2cm; }
.evidence-img { width: 15cm; border: 0.5pt solid #e3e5ea; margin: 4pt 0; }
.fig-caption { color: #5b6170; font-size: 8pt; }
footer { margin-top: 18pt; color: #5b6170; font-size: 8pt; line-height: 1.5; border-top: 0.5pt solid #e3e5ea; padding-top: 6pt; }
#pdf-footer { color: #5b6170; font-size: 8pt; text-align: center; }
table.kpis { width: 100%; margin: 6pt 0 12pt 0; }
table.kpis td { border: 0.5pt solid #d5d8de; background-color: #fafbfc; padding: 8pt 4pt 7pt 4pt; text-align: center;
                vertical-align: middle; font-size: 8pt; color: #5b6170; }
.kpi-label { margin: 0 0 5pt 0; font-size: 8pt; line-height: 1.2; text-align: center; }
.kpi-sub { margin: 4pt 0 0 0; font-size: 7.5pt; color: #5b6170; line-height: 1.2; text-align: center; }
table.kpis td.gap { border: none; background-color: #ffffff; padding: 0; }
.kpi-num { font-size: 18pt; font-weight: bold; color: #16181d; margin: 0; line-height: 1.1; text-align: center; }
img.badge { vertical-align: middle; }
pdftoc { color: #16181d; }
pdftoc.pdftoclevel0 { font-weight: bold; margin-top: 4pt; }
pdftoc.pdftoclevel1 { margin-left: 1em; }
"""


def _legend_html() -> str:
    rows = "".join(
        f'<tr><td><span class="sev sev-{k}">{k.capitalize()}</span></td><td>{rng}</td><td>{escape(desc)}</td></tr>'
        for k, rng, desc in SEVERITY_LEGEND
    )
    return (
        '<h2 id="pdf-severity-legend">Severity Legend</h2>'
        "<table><tr><th>Severity</th><th>CVSS v3 Range</th><th>Meaning</th></tr>"
        f"{rows}</table>"
    )


_PRE = re.compile(r"(?is)(<pre[^>]*>)(.*?)(</pre>)")


def _wrap_pre(html: str, width: int = 90) -> str:
    """Code snippets keep their lines but wrap at the page width instead of running off the page."""
    import textwrap
    from html import unescape

    def wrap(m: re.Match) -> str:
        lines = []
        for line in unescape(m.group(2)).splitlines() or [""]:
            lines.extend(textwrap.wrap(line, width, break_long_words=True, break_on_hyphens=False,
                                       drop_whitespace=False, replace_whitespace=False) or [""])
        return m.group(1) + escape("\n".join(lines)) + m.group(3)

    return _PRE.sub(wrap, html)


_TAG_OR_TEXT = re.compile(r"(<[^>]*>)|([^<]+)")
_LONG = re.compile(r"[^\s<>&]{40,}")


def _breakable(html: str) -> str:
    """Let long unbroken strings (hashes, URLs, vectors) wrap instead of being clipped in table cells."""

    def chunk(m: re.Match) -> str:
        w = m.group(0)
        if re.fullmatch(r"[0-9a-fA-F]+", w):  # hashes: groups of 16
            return " ".join(w[i : i + 16] for i in range(0, len(w), 16))
        # URLs, paths, CVSS vectors: break after separators, keeping lines up to ~28 characters.
        parts = re.findall(r"[^/?&=:,;]*[/?&=:,;]?", w)
        lines, cur = [], ""
        for part in filter(None, parts):
            while len(part) > 28:
                if cur:
                    lines.append(cur)
                    cur = ""
                lines.append(part[:28])
                part = part[28:]
            if len(cur) + len(part) > 28 and cur:
                lines.append(cur)
                cur = ""
            cur += part
        if cur:
            lines.append(cur)
        return " ".join(lines)

    def fix(m: re.Match) -> str:
        if m.group(1):
            return m.group(1)
        return _LONG.sub(chunk, m.group(2))

    head, sep, body = html.partition("<body")
    return head + sep + _TAG_OR_TEXT.sub(fix, body) if sep else html


_KPIS = re.compile(r'(?is)<div class="kpis">\s*((?:<div class="kpi">.*?</div>\s*)+)</div>')
_KPI = re.compile(r'(?is)<div class="kpi">(.*?)<b>(.*?)</b>(.*?)</div>')


def _kpis_to_table(html: str) -> str:
    """Summary tiles use flexbox in the HTML; xhtml2pdf needs a one-row table instead."""

    def tiles(m: re.Match) -> str:
        cells = []
        for label, num, suffix in _KPI.findall(m.group(1)):
            cells.append(
                f'<td><p class="kpi-label">{label.strip()}</p><p class="kpi-num">{num.strip()}</p>'
                f'<p class="kpi-sub">{suffix.strip()}</p></td>'
            )
        spaced = '<td class="gap" width="6"></td>'.join(cells)
        return f'<table class="kpis" cellspacing="0"><tr>{spaced}</tr></table>'

    return _KPIS.sub(tiles, html)


_TABLE = re.compile(r"(?is)<table(?![^>]*class=\"kpis\")([^>]*)>(.*?)</table>")
_ROW = re.compile(r"(?is)<tr[^>]*>(.*?)</tr>")
_CELL = re.compile(r"(?is)<t([dh])([^>]*)>(.*?)</t[dh]>")


def _size_columns(html: str) -> str:
    """xhtml2pdf splits columns evenly; size them by content so long text gets room and short codes don't."""

    def size(m: re.Match) -> str:
        attrs, body = m.group(1), m.group(2)
        rows = [_CELL.findall(r) for r in _ROW.findall(body)]
        if not rows or any("colspan" in c[1] for r in rows for c in r):
            return m.group(0)
        n = max(len(r) for r in rows)
        if n < 2:
            return m.group(0)
        weight = [0.0] * n
        for r in rows:
            for i, (_, _, cell) in enumerate(r):
                text = re.sub(r"<[^>]+>|&[#\w]+;", " ", cell)
                longest = max((len(w) for w in text.split()), default=0)
                img_w = sum(int(x) for x in re.findall(r'<img[^>]*width="(\d+)"', cell))
                weight[i] = max(weight[i], min(len(text.strip()), 120) ** 0.7, longest * 1.1, img_w / 5)
        total = sum(weight) or 1.0
        pct = [max(7.0, 100.0 * w / total) for w in weight]
        scale = 100.0 / sum(pct)
        pct = [round(p * scale, 1) for p in pct]
        first = _ROW.search(body)
        cells = iter(pct)

        def add_width(c: re.Match) -> str:
            w = next(cells, None)
            if w is None or "width" in c.group(2):
                return c.group(0)
            return f'<t{c.group(1)}{c.group(2)} width="{w}%">{c.group(3)}</t{c.group(1)}>'

        row = first.group(0)
        new_row = _CELL.sub(add_width, row)
        body = body[: first.start()] + new_row + body[first.end():]
        return f"<table{attrs}>{body}</table>"

    return _TABLE.sub(size, html)


_BADGE = re.compile(r'(?is)<span class="sev(?: sev-(\w+))?"(?: style="([^"]*)")?>(.*?)</span>')


def _badges(html: str) -> str:
    """Severity / exposure pills as fixed-size SVG badges: text centred both ways (xhtml2pdf can't pad spans)."""

    def badge(m: re.Match) -> str:
        from html import unescape

        sev, style, inner = m.group(1), m.group(2) or "", m.group(3)
        label = unescape(re.sub(r"<[^>]+>", "", inner)).strip()
        if not label:
            return m.group(0)
        if sev:
            fill, ink, label = "#" + SEV_HEX.get(sev.lower(), "6b7280"), "#ffffff", label.capitalize()
        else:
            bg = re.search(r"background:\s*(#[0-9a-fA-F]{3,6})", style)
            fg = re.search(r"(?<!-)color:\s*(#[0-9a-fA-F]{3,6})", style)
            fill, ink = (bg.group(1) if bg else "#6b7280"), (fg.group(1) if fg else "#ffffff")
        width = max(52, int(len(label) * 4.9) + 12)  # one size for all severities; longer pills grow
        svg = (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="14" viewBox="0 0 {width} 14">'
            f'<rect width="{width}" height="14" rx="3" fill="{fill}"/>'
            f'<text x="{width / 2}" y="10" font-family="{_register_badge_font()}" font-size="8" fill="{ink}" '
            f'text-anchor="middle">{escape(label)}</text></svg>'
        )
        uri = "data:image/svg+xml;base64," + base64.b64encode(svg.encode()).decode()
        return f'<img class="badge" src="{uri}" width="{width}" height="14" alt="{escape(label)}"/>'

    return _BADGE.sub(badge, html)


def _watermark(pdf: bytes) -> bytes:
    """Stamp a light, centred, diagonal DRAFT on every page (xhtml2pdf cannot rotate text)."""
    from pypdf import PdfReader, PdfWriter
    from reportlab.pdfgen import canvas

    reader = PdfReader(BytesIO(pdf))
    writer = PdfWriter()
    stamps: dict[tuple[float, float], bytes] = {}
    for page in reader.pages:
        w, h = float(page.mediabox.width), float(page.mediabox.height)
        if (w, h) not in stamps:
            buf = BytesIO()
            c = canvas.Canvas(buf, pagesize=(w, h))
            c.setFillColorRGB(0.97, 0.86, 0.86)  # light tint, opaque: drawn under the text
            size = min(w, h) * 0.22
            c.setFont(_register_badge_font(), size)
            c.translate(w / 2, h / 2)
            c.rotate(45)
            c.drawCentredString(0, -size * 0.35, "DRAFT")
            c.save()
            stamps[(w, h)] = buf.getvalue()
        # Draw the report on top of a fresh stamp page: the stamp sits underneath the text, and the
        # report's own graphics state (clips, transforms) cannot hide or skew it.
        base = PdfReader(BytesIO(stamps[(w, h)])).pages[0]
        base.merge_page(page)
        writer.add_page(base)
    out = BytesIO()
    writer.write(out)
    return out.getvalue()


_SMALL = {"a", "an", "and", "as", "at", "by", "for", "in", "of", "on", "or", "per", "the", "to", "vs", "via", "with"}
# Exact cell / label values that are enum keys rendered as text; shown in Title Case.
_ENUM_TEXT = {
    "proposed", "confirmed", "process control", "new", "triaged", "validated", "fixed", "verified", "reopened",
    "accepted", "risk accepted", "false positive", "not tested", "passed", "failed", "pass", "fail", "draft",
    "submitted", "signed", "rejected", "met", "no exceptions", "partial", "not met", "not assessed",
    "not applicable", "full", "partial mapping", "requested", "open", "closed", "yes", "no", "internet",
    "internal", "production", "staging", "development", "controls", "open findings", "excluded",
    "warn", "warning", "error", "skipped", "info", "not scanned", "in progress", "web app", "repo", "image",
}


def title_case(text: str) -> str:
    """Display Title Case that keeps acronyms, versions, identifiers and code-like tokens unchanged."""
    words = text.split(" ")
    out = []
    for i, w in enumerate(words):
        core = w.strip("()[]:,.;\"'")
        if not core or any(c.isdigit() for c in core) or any(c.isupper() for c in core) or "_" in core \
                or "/" in core or "." in core or "@" in core:
            out.append(w)
        elif i and core.lower() in _SMALL and not (out and out[-1].endswith(":")):
            out.append(w.lower())
        else:
            j = w.index(core[0])
            out.append(w[:j] + w[j].upper() + w[j + 1 :])
    return " ".join(out)


def _display_case(html: str) -> str:
    """Title Case for headings, table headers, status/severity labels and enum-valued cells (display only)."""
    from html import unescape

    def text_only(fn):
        def sub(m: re.Match) -> str:
            parts = re.split(r"(<[^>]+>)", m.group(2))
            return m.group(1) + "".join(p if p.startswith("<") else escape(fn(unescape(p))) for p in parts) + m.group(3)

        return sub

    out = re.sub(r"(?is)(<h[12][^>]*>)(.*?)(</h[12]>)", text_only(title_case), html)
    out = re.sub(r"(?is)(<th[^>]*>)(.*?)(</th>)", text_only(title_case), out)
    out = re.sub(r'(?is)(<span class="(?:st|sev)[^"]*"[^>]*>)(.*?)(</span>)', text_only(title_case), out)

    def enum_cell(m: re.Match) -> str:
        inner = m.group(2)
        plain = re.sub(r"\s+", " ", unescape(inner)).strip()
        if plain.lower().replace("_", " ") in _ENUM_TEXT and "_" in plain:
            return m.group(1) + inner.replace(plain, escape(title_case(plain.replace("_", " ")))) + m.group(3)
        if plain.lower() in _ENUM_TEXT or re.fullmatch(r"(?:not )?tested|[a-z]+ \(this generation\)", plain):
            return m.group(1) + inner.replace(plain, escape(title_case(plain))) + m.group(3)
        return m.group(0)

    out = re.sub(r"(?is)(<(?:td|span class=\"meta\"|div class=\"meta\")[^>]*>|<td[^>]*>\s*<b>)([^<]{1,40})(</(?:td|b|span|div)>)", enum_cell, out)
    # KPI tile captions ("controls", "open", "excluded") follow the number.
    out = re.sub(r"(?is)(</b>)([a-z ]{2,20})(</div>)", lambda m: m.group(1) + title_case(m.group(2)) + m.group(3), out)
    return out


def _title_of(html: str) -> str:
    m = re.search(r"(?is)<title>(.*?)</title>", html)
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else "Attestra report"


def _framework_display_names() -> dict[str, str]:
    try:
        from attestra.compliance.engine import load_library

        fws = load_library().frameworks
        return {k: str(v.get("name") or k) for k, v in fws.items()}
    except Exception:
        return {}


def _framework_names(html: str) -> str:
    """Show framework display names instead of raw ids in visible text (display only)."""
    names = _framework_display_names()
    if not names:
        return html
    pat = re.compile(r"(?<![\w/=\-\"'])(" + "|".join(map(re.escape, sorted(names, key=len, reverse=True))) + r")(?![\w\-\"'])")
    parts = re.split(r"(<[^>]+>)", html)
    in_skip = False
    for i, part in enumerate(parts):
        if part.startswith("<"):
            low = part[:8].lower()
            if low.startswith(("<style", "<script", "<title")):
                in_skip = True
            elif low.startswith(("</style", "</script", "</title")):
                in_skip = False
            continue
        if not in_skip and part:
            parts[i] = pat.sub(lambda m: names[m.group(1)], part)
    return "".join(parts)


_TS = re.compile(r"\b(\d{4}-\d{2}-\d{2})[ T](\d{2}):(\d{2})(?::\d{2}(?:\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?(?:\s*UTC)?")


def _human_times(html: str) -> str:
    """Render ISO timestamps as '21 Oct 2026, 11:06 IST' (Asia/Kolkata)."""
    from datetime import datetime, timedelta, timezone

    ist = timezone(timedelta(hours=5, minutes=30))

    def fix(m: re.Match) -> str:
        try:
            dt = datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}:{m.group(3)}")
            tz = m.group(4)
            if tz in (None, "Z") or tz.replace(":", "") in ("+0000", "-0000"):
                dt = dt.replace(tzinfo=UTC)
            else:
                dt = datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}:{m.group(3)}{tz}")
            return dt.astimezone(ist).strftime("%d %b %Y, %H:%M IST").lstrip("0")
        except Exception:
            return m.group(0)

    head, sep, body = html.partition("<body")
    return head + sep + _TS.sub(fix, body) if sep else html


def _svg_to_img(m: re.Match) -> str:
    import base64

    svg = m.group(0)
    if "xmlns=" not in svg[:200]:
        svg = svg.replace("<svg", '<svg xmlns="http://www.w3.org/2000/svg"', 1)
    w = re.search(r'(?i)<svg[^>]*\swidth="([\d.]+)', svg)
    h = re.search(r'(?i)<svg[^>]*\sheight="([\d.]+)', svg)
    vb = re.search(r'(?i)viewBox="[\d.\s-]+?\s([\d.]+)\s+([\d.]+)"', svg)
    width = float(w.group(1)) if w else float(vb.group(1)) if vb else 480
    height = float(h.group(1)) if h else float(vb.group(2)) if vb else 160
    if not w:
        svg = svg.replace("<svg", f'<svg width="{width}" height="{height}"', 1)
    scale = min(1.0, 480 / width)
    data = base64.b64encode(svg.encode("utf-8")).decode()
    return f'<img src="data:image/svg+xml;base64,{data}" width="{int(width * scale)}" height="{int(height * scale)}">'


def prepare_html(html: str, *, kind: str, draft: bool, for_engine: str = "xhtml2pdf") -> str:
    """Return a print-ready copy of the sealed report HTML (the input is not modified)."""
    title = title_case(_title_of(html))
    out = _human_times(_framework_names(html))
    # Drop the screen-only watermark and hint; the PDF adds its own.
    out = re.sub(r'(?is)<div class="draft-mark"[^>]*>.*?</div>', "", out)
    out = re.sub(r"(?is)<br>\s*Page numbers appear when printed[^<]*", "", out)
    head, sep, body = out.partition("<body")
    out = head + sep + _display_case(body) if sep else out
    if for_engine == "xhtml2pdf":
        out = re.sub(r"(?is)<style.*?</style>", f"<style>{_font_css()}{PDF_CSS}</style>", out, count=1)
        # xhtml2pdf cannot draw inline SVG, but it renders SVG <img> data URIs via svglib.
        out = re.sub(r"(?is)<svg.*?</svg>", _svg_to_img, out)
        out = _wrap_pre(out)
        out = _breakable(out)
        out = _kpis_to_table(out)
    letter = kind in LETTER_KINDS
    extras = []
    if not letter:
        # Contents with real page numbers replaces the HTML link list.
        out = re.sub(r'(?is)<nav class="toc"[^>]*>.*?</nav>', "", out)
        if for_engine == "xhtml2pdf":
            extras.append(
                '<pdf:nextpage /><p class="toc-title">Contents</p><div><pdf:toc /></div><pdf:nextpage />'
                if len(re.findall(r"(?i)<h2", out)) >= 3
                else "<pdf:nextpage />"  # short reports: cover, then straight to the content
            )
        if 'id="risk-legend"' not in out:
            extras.append(_legend_html())
    if extras:
        block = "".join(extras)
        m = re.search(r"(?is)</section>", out)  # end of the cover section
        if m and 'id="cover"' in out[: m.end()]:
            out = out[: m.end()] + block + out[m.end():]
        else:
            out = re.sub(r"(?is)(<body[^>]*>)", r"\1" + block.replace("\\", r"\\"), out, count=1)
    if 'id="disclaimer"' not in out:
        disc = f'<h2 id="pdf-disclaimer">Disclaimer</h2><p>{escape(DISCLAIMER)}</p>'
        out = re.sub(r"(?is)<footer>", disc + "<footer>", out, count=1) if "<footer>" in out else out.replace(
            "</body>", disc + "</body>"
        )
    if for_engine == "xhtml2pdf":
        static = (
            f'<div id="pdf-footer">{escape(title)} &#183; Confidential &#183; '
            'Page <pdf:pagenumber> of <pdf:pagecount></div>'
        )
        out = re.sub(r"(?is)(<body[^>]*>)", r"\1" + static, out, count=1)
        # Last, so injected legend / disclaimer tables get the same badges and column sizing.
        out = _badges(out)
        out = _size_columns(out)
    elif for_engine == "weasyprint":
        extra_css = (
            "@page { size: A4; margin: 18mm 14mm 20mm; "
            "@bottom-center { content: 'Page ' counter(page) ' of ' counter(pages); font-size: 9px; color: #5b6170; } }"
            ".cover { page-break-after: always; }"
        )
        if draft:
            extra_css += (
                ".pdf-draft { position: fixed; top: 40%; left: 12%; font-size: 96px; font-weight: 800;"
                " color: rgba(161,22,27,.12); transform: rotate(-30deg); }"
            )
            out = re.sub(r"(?is)(<body[^>]*>)", r'\1<div class="pdf-draft">DRAFT</div>', out, count=1)
        out = out.replace("</head>", f"<style>{extra_css}</style></head>", 1)
    return out


def _weasyprint(html: str, base_url: str) -> bytes | None:
    try:
        from weasyprint import HTML
    except Exception:  # not installed, or GTK/Pango missing (typical on Windows)
        return None
    try:
        return HTML(string=html, base_url=base_url).write_pdf()
    except Exception:
        return None


def _xhtml2pdf(html: str) -> bytes | None:
    try:
        from xhtml2pdf import pisa
    except Exception:
        return None
    buf = BytesIO()
    result = pisa.CreatePDF(html, dest=buf, encoding="utf-8")
    if result.err:
        return None
    return buf.getvalue() or None


def render_pdf(html: str, *, kind: str, draft: bool, base_url: str = "") -> tuple[bytes | None, str]:
    """Render the report HTML to PDF bytes. Returns (data, engine) or (None, "")."""
    data = _weasyprint(prepare_html(html, kind=kind, draft=draft, for_engine="weasyprint"), base_url)
    if data:
        return data, "weasyprint"
    data = _xhtml2pdf(prepare_html(html, kind=kind, draft=draft, for_engine="xhtml2pdf"))
    if data:
        if draft:
            try:
                data = _watermark(data)
            except Exception:  # never lose the export over the watermark
                pass
        return data, "xhtml2pdf"
    return None, ""
