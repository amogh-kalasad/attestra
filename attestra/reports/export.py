"""DOCX and PDF export for frozen HTML reports."""
# @lat: [[reports#Exports]]

from __future__ import annotations

import hashlib
import re
import zipfile
from html import unescape
from io import BytesIO
from pathlib import Path
from xml.sax.saxutils import escape

from attestra import config
from attestra.models import Report
from attestra.services import ServiceError


def _html_to_text(html: str) -> str:
    text = re.sub(r"(?is)<script.*?>.*?</script>", " ", html)
    text = re.sub(r"(?is)<style.*?>.*?</style>", " ", text)
    text = re.sub(r"(?is)<svg.*?>.*?</svg>", " ", text)
    text = re.sub(r"(?is)<br\s*/?>", "\n", text)
    text = re.sub(r"(?is)</(p|div|tr|li|h[1-6]|section|table|ul|ol|header|footer)>", "\n", text)
    text = re.sub(r"(?is)</t[dh]>", " | ", text)
    text = re.sub(r"(?is)<[^>]+>", " ", text)
    text = unescape(text)
    text = re.sub(r"[ \t\xa0]+", " ", text)
    text = re.sub(r" *\n *", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _minimal_docx(text: str) -> bytes:
    """Build a minimal OOXML docx without docxtpl."""
    paragraphs = "".join(f"<w:p><w:r><w:t xml:space=\"preserve\">{escape(line)}</w:t></w:r></w:p>" for line in text.splitlines() or [""])
    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body>{paragraphs}<w:sectPr/></w:body></w:document>"
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        "</Types>"
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/>'
        "</Relationships>"
    )
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("word/document.xml", document_xml)
    return buf.getvalue()


def _wrap_lines(text: str, width: int = 95) -> list[str]:
    """Word-wrap text so no word is cut or dropped (fallback PDF only)."""
    import textwrap

    out: list[str] = []
    for line in text.splitlines():
        line = line.rstrip()
        if not line:
            out.append("")
            continue
        out.extend(textwrap.wrap(line, width=width, break_long_words=True, break_on_hyphens=False) or [""])
    return out or [""]


def _minimal_pdf(text: str) -> bytes:
    """Multi-page plain-text PDF (Helvetica, latin-1) used only when no PDF engine is installed.

    Every line is wrapped and paginated, so no text is dropped (the old single-page
    version kept only the first 60 lines and cut each at 100 characters).
    """
    lines = _wrap_lines(text)
    per_page = 58
    pages = [lines[i : i + per_page] for i in range(0, len(lines), per_page)] or [[""]]
    n = len(pages)
    font_id = 3
    objects: dict[int, bytes] = {}
    kids = []
    for idx, page_lines in enumerate(pages):
        page_id = 4 + idx * 2
        content_id = page_id + 1
        kids.append(f"{page_id} 0 R")
        body = ["BT", "/F1 10 Tf", "50 780 Td", "12.5 TL"]
        for i, line in enumerate(page_lines):
            safe = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            body.append(("" if i == 0 else "T* ") + f"({safe}) Tj")
        body.append("ET")
        body.append(f"BT /F1 9 Tf 270 30 Td (Page {idx + 1} of {n}) Tj ET")
        stream = "\n".join(body).encode("cp1252", errors="replace")
        objects[page_id] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Contents {content_id} 0 R /Resources << /Font << /F1 {font_id} 0 R >> >> >>"
        ).encode()
        objects[content_id] = f"<< /Length {len(stream)} >>stream\n".encode() + stream + b"\nendstream"
    objects[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objects[2] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {n} >>".encode()
    objects[font_id] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
    out = bytearray(b"%PDF-1.4\n")
    offsets = {}
    for oid in sorted(objects):
        offsets[oid] = len(out)
        out.extend(f"{oid} 0 obj".encode() + objects[oid] + b"endobj\n")
    size = max(objects) + 1
    xref_pos = len(out)
    out.extend(f"xref\n0 {size}\n".encode())
    out.extend(b"0000000000 65535 f \n")
    for oid in range(1, size):
        out.extend(f"{offsets[oid]:010d} 00000 n \n".encode())
    out.extend(f"trailer<< /Size {size} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode())
    return bytes(out)


def _atomic_write_readonly(path: Path, data: bytes) -> None:
    """Write export bytes atomically, replacing a prior read-only file (P1-1)."""
    import os

    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    if path.exists():
        try:
            path.chmod(0o666)
        except OSError:
            pass
        try:
            path.unlink()
        except OSError:
            # Windows may still hold a handle; fall through to replace.
            pass
    os.replace(tmp, path)
    path.chmod(0o444)


def to_docx(report: Report, html_path: Path | None = None) -> tuple[Path, str]:
    src = Path(html_path or report.path)
    html = src.read_text(encoding="utf-8", errors="replace")
    kind, draft = report.kind or "", (report.status or "draft") != "signed"
    try:  # styled python-docx export (docx_export.py)
        from attestra.reports.docx_export import render_docx as render_styled

        data = render_styled(html, kind=kind, draft=draft, base_url=str(src.parent))
    except Exception:
        try:  # dependency-free OOXML writer
            from attestra.reports.docx import render_docx

            data = render_docx(html, kind=kind, draft=draft)
        except Exception:  # never fail the export: fall back to the plain-text document
            data = _minimal_docx(_html_to_text(html))
    sha = hashlib.sha256(data).hexdigest()
    out = src.with_suffix(".docx")
    _atomic_write_readonly(out, data)
    report.docx_path, report.docx_sha256 = str(out), sha
    return out, sha


def to_pdf(report: Report, html_path: Path | None = None) -> tuple[Path, str]:
    from attestra.reports.pdf import prepare_html, render_pdf

    src = Path(html_path or report.path)
    html = src.read_text(encoding="utf-8", errors="replace")
    kind, draft = report.kind or "", (report.status or "draft") != "signed"
    data, _engine = render_pdf(
        html,
        kind=kind,
        draft=draft,
        base_url=str(src.parent),
    )
    if not data:
        # Same display normalisation / legend / disclaimer as the styled engines, without pdf: tags.
        data = _minimal_pdf(_html_to_text(prepare_html(html, kind=kind, draft=draft, for_engine="minimal")))
    sha = hashlib.sha256(data).hexdigest()
    out = src.with_suffix(".pdf")
    _atomic_write_readonly(out, data)
    report.pdf_path, report.pdf_sha256 = str(out), sha
    return out, sha


def export_report_formats(report: Report, html_path: Path | None = None) -> dict:
    """Produce DOCX + PDF and return paths/hashes.

    ``html_path`` overrides ``report.path`` when the data folder moved (see api._report_file).
    Safe to call repeatedly: earlier read-only exports are replaced.
    """
    src = Path(html_path) if html_path else (Path(report.path) if report.path else None)
    if src is None or not src.exists():
        raise ServiceError("report HTML path missing")
    config.ensure_dirs()
    docx_path, docx_sha = to_docx(report, src)
    pdf_path, pdf_sha = to_pdf(report, src)
    return {
        "docx_path": str(docx_path),
        "docx_sha256": docx_sha,
        "pdf_path": str(pdf_path),
        "pdf_sha256": pdf_sha,
    }
