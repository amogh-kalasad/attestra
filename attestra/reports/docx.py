"""Styled Word (.docx) export for frozen HTML reports, with no third-party dependency.

The sealed HTML is parsed and rebuilt as real Word content: heading styles, tables with
sized columns and a shaded header row, summary tiles, coloured severity/status labels,
embedded evidence images, a cover page, a contents list, a DRAFT header until the report is
signed, and a "Page X of Y" footer.
"""
# @lat: [[reports#Exports]]

from __future__ import annotations

import base64
import re
import zipfile
from html.parser import HTMLParser
from io import BytesIO
from xml.sax.saxutils import escape

from attestra.reports.pdf import LETTER_KINDS, _title_of, prepare_html

PAGE_W = 9638  # A4 text width in twips with 2 cm margins

SEV_COLOURS = {"critical": "A1161B", "high": "D0461B", "medium": "B7791F", "low": "3B7D4F", "info": "6B7280"}
ST_COLOURS = {"met": "3B7D4F", "no_exceptions": "2F7F8A", "partial": "B7791F", "not_met": "A1161B",
              "not_assessed": "6B7280", "not_applicable": "6B7280"}

BLOCK = {"p", "div", "section", "h1", "h2", "h3", "h4", "h5", "h6", "table", "ul", "ol", "li", "nav",
         "footer", "header", "figure", "pre", "blockquote", "hr", "tr", "td", "th", "thead", "tbody", "main", "article"}
VOID = {"br", "img", "meta", "link", "hr", "input", "col", "source", "wbr"}
SKIP = {"head", "style", "script", "svg", "title", "button", "form", "select", "noscript"}


class Node:
    __slots__ = ("tag", "attrs", "children")

    def __init__(self, tag: str, attrs: dict | None = None):
        self.tag, self.attrs, self.children = tag, attrs or {}, []

    @property
    def classes(self) -> set[str]:
        return set((self.attrs.get("class") or "").split())


class _Tree(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = Node("root")
        self.stack = [self.root]

    def handle_starttag(self, tag, attrs):
        node = Node(tag, {k: (v or "") for k, v in attrs})
        self.stack[-1].children.append(node)
        if tag not in VOID:
            self.stack.append(node)

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i].tag == tag:
                del self.stack[i:]
                return

    def handle_data(self, data):
        self.stack[-1].children.append(data)


def _text(node) -> str:
    if isinstance(node, str):
        return node
    if node.tag in SKIP:
        return ""
    return "".join(_text(c) for c in node.children)


def _is_block(node) -> bool:
    return not isinstance(node, str) and (node.tag in BLOCK or "kpis" in node.classes)


class _Writer:
    def __init__(self, draft: bool):
        self.draft = draft
        self.images: list[tuple[str, bytes]] = []
        self.out: list[str] = []

    # ---------------------------------------------------------------- runs
    def runs(self, node, fmt: dict | None = None) -> str:
        fmt = dict(fmt or {})
        if isinstance(node, str):
            if fmt.get("pre"):  # code: keep line breaks
                lines = node.strip("\n").split("\n")
                return "<w:r><w:br/></w:r>".join(self._run(line, fmt) for line in lines)
            text = re.sub(r"\s+", " ", node)
            if not text:
                return ""
            return self._run(text, fmt)
        if node.tag in SKIP or "draft-mark" in node.classes:
            return ""
        if node.tag == "br":
            return "<w:r><w:br/></w:r>"
        if node.tag == "img":
            return self._image(node)
        cls = node.classes
        if node.tag in ("b", "strong"):
            fmt["b"] = True
        if node.tag in ("i", "em"):
            fmt["i"] = True
        if node.tag in ("code", "kbd") or "mono" in cls:
            fmt["mono"] = True
        if node.tag == "pre":
            fmt.update(pre=True, mono=True)
        if "meta" in cls or "fig-caption" in cls:
            fmt.update(color="5B6170", size=15)
        if "brand" in cls:
            fmt.update(color="2457D6", b=True)
        for c in cls:
            if c.startswith("sev-") and c[4:] in SEV_COLOURS:
                fmt.update(shade=SEV_COLOURS[c[4:]], color="FFFFFF", b=True)
            if c.startswith("st-") and c[3:] in ST_COLOURS:
                fmt.update(color=ST_COLOURS[c[3:]], b=True)
        body = "".join(self.runs(c, fmt) for c in node.children)
        if "sev" in cls and body:
            body = self._run(" ", fmt) + body + self._run(" ", fmt)
        return body

    @staticmethod
    def _run(text: str, fmt: dict) -> str:
        rpr = []
        if fmt.get("mono"):
            rpr.append('<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/>')
        if fmt.get("b"):
            rpr.append("<w:b/>")
        if fmt.get("i"):
            rpr.append("<w:i/>")
        if fmt.get("color"):
            rpr.append(f'<w:color w:val="{fmt["color"]}"/>')
        size = fmt.get("size") or (15 if fmt.get("mono") else None)
        if size:
            rpr.append(f'<w:sz w:val="{size}"/>')
        if fmt.get("shade"):
            rpr.append(f'<w:shd w:val="clear" w:color="auto" w:fill="{fmt["shade"]}"/>')
        props = f"<w:rPr>{''.join(rpr)}</w:rPr>" if rpr else ""
        return f'<w:r>{props}<w:t xml:space="preserve">{escape(text)}</w:t></w:r>'

    def _image(self, node) -> str:
        src = node.attrs.get("src", "")
        m = re.match(r"data:image/(png|jpe?g|gif);base64,(.+)", src, re.S)
        if not m:
            return ""
        try:
            data = base64.b64decode(m.group(2))
        except Exception:
            return ""
        ext = "jpeg" if m.group(1).startswith("jp") else m.group(1)
        w_px, h_px = _image_size(data)
        if not w_px:
            return ""
        max_w = 6.0 * 914400 if "evidence-img" in node.classes else 2.2 * 914400
        cx = min(max_w, w_px * 9525)
        cy = int(cx * h_px / w_px)
        if cy > 4.5 * 914400:
            cy = int(4.5 * 914400)
            cx = int(cy * w_px / h_px)
        n = len(self.images) + 1
        rid = f"rIdImg{n}"
        self.images.append((f"image{n}.{ext}", data))
        name = escape(node.attrs.get("alt", f"image{n}"), {'"': "&quot;"})
        return (
            f'<w:r><w:drawing><wp:inline><wp:extent cx="{int(cx)}" cy="{int(cy)}"/><wp:docPr id="{n}" name="{name}"/>'
            '<a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
            '<a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
            '<pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">'
            f'<pic:nvPicPr><pic:cNvPr id="{n}" name="{name}"/><pic:cNvPicPr/></pic:nvPicPr>'
            f'<pic:blipFill><a:blip r:embed="{rid}"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
            f'<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="{int(cx)}" cy="{int(cy)}"/></a:xfrm>'
            '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic></a:graphicData></a:graphic>'
            "</wp:inline></w:drawing></w:r>"
        )

    # ---------------------------------------------------------------- blocks
    @staticmethod
    def para(runs: str, style: str = "", extra: str = "") -> str:
        ppr = (f'<w:pStyle w:val="{style}"/>' if style else "") + extra
        return f"<w:p>{f'<w:pPr>{ppr}</w:pPr>' if ppr else ''}{runs}</w:p>"

    def blocks(self, node, style: str = "") -> list[str]:
        """Block-level OOXML for a node's children, grouping loose inline content into paragraphs."""
        out: list[str] = []
        pending: list = []

        def flush():
            runs = "".join(self.runs(c) for c in pending).strip()
            pending.clear()
            if runs and re.search(r"<w:t[^>]*>[^<]*\S|<w:drawing|<w:br", runs):
                out.append(self.para(runs, style))

        for child in node.children:
            if _is_block(child):
                flush()
                out.extend(self.block(child))
            elif isinstance(child, str) or child.tag not in SKIP:
                pending.append(child)
        flush()
        return out

    def block(self, node) -> list[str]:
        tag, cls = node.tag, node.classes
        if tag in SKIP or "draft-mark" in cls or ("toc" in cls and tag == "nav"):
            return []
        if "kpis" in cls:
            return [self.tiles(node)]
        if tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
            level = min(int(tag[1]), 3)
            return [self.para("".join(self.runs(c) for c in node.children), f"Heading{level}")]
        if tag == "table":
            return [self.table(node), self.para("", "Spacer")]
        if tag in ("ul", "ol"):
            items = [c for c in node.children if not isinstance(c, str) and c.tag == "li"]
            res = []
            for i, li in enumerate(items, 1):
                marker = f"{i}." if tag == "ol" else "\u2022"
                body = self.blocks(li, "ListPara")
                first = self._run(marker + "\t", {})
                if body:
                    body[0] = body[0].replace("<w:pPr>", "<w:pPr>", 1).replace("</w:pPr>", "</w:pPr>" + first, 1)
                res.extend(body or [self.para(first, "ListPara")])
            return res
        if tag == "hr":
            return [self.para("", "Rule")]
        if tag == "pre":
            return [self.para(self.runs(node), "Code")]
        if tag == "p" and "white-space:pre" in node.attrs.get("style", "").replace(" ", ""):
            return [self.para(self.runs(node, {"pre": True}))]  # multi-line text such as fix steps
        if tag == "footer":
            return self.blocks(node, "Small")
        style = "Note" if "note" in cls else ("Small" if "meta" in cls else "")
        if "finding" in cls:
            return [self.para("", "Rule")] + self.blocks(node) + []
        res = self.blocks(node, style)
        if node.attrs.get("id") == "cover":
            res.append('<w:p><w:r><w:br w:type="page"/></w:r></w:p>')
        return res

    def tiles(self, node) -> str:
        tiles = [c for c in node.children if not isinstance(c, str) and "kpi" in c.classes]
        if not tiles:
            return ""
        w = PAGE_W // len(tiles)
        cells = []
        for t in tiles:
            label, num, suffix = [], "", []
            seen_b = False
            for c in t.children:
                if not isinstance(c, str) and c.tag == "b":
                    num, seen_b = _text(c).strip(), True
                elif seen_b:
                    suffix.append(c)
                else:
                    label.append(c)
            centre = '<w:spacing w:before="40" w:after="40"/><w:jc w:val="center"/>'
            paras = (
                self.para("".join(self.runs(c, {"size": 16}) for c in label), "", centre)
                + self.para(self._run(num, {"b": True, "size": 36}), "", centre)
                + self.para("".join(self.runs(c, {"color": "5B6170", "size": 15}) for c in suffix), "", centre)
            )
            cells.append(
                f'<w:tc><w:tcPr><w:tcW w:w="{w}" w:type="dxa"/><w:shd w:val="clear" w:color="auto" w:fill="FAFBFC"/>'
                f'<w:vAlign w:val="center"/></w:tcPr>{paras}</w:tc>'
            )
        grid = "".join(f'<w:gridCol w:w="{w}"/>' for _ in tiles)
        return (
            '<w:tbl><w:tblPr><w:tblW w:w="5000" w:type="pct"/>'
            '<w:tblBorders><w:top w:val="single" w:sz="4" w:color="D5D8DE"/><w:left w:val="single" w:sz="4" w:color="D5D8DE"/>'
            '<w:bottom w:val="single" w:sz="4" w:color="D5D8DE"/><w:right w:val="single" w:sz="4" w:color="D5D8DE"/>'
            '<w:insideV w:val="single" w:sz="4" w:color="D5D8DE"/></w:tblBorders><w:tblLayout w:type="fixed"/>'
            '<w:tblCellMar><w:left w:w="60" w:type="dxa"/><w:right w:w="60" w:type="dxa"/></w:tblCellMar></w:tblPr>'
            f"<w:tblGrid>{grid}</w:tblGrid><w:tr>{''.join(cells)}</w:tr></w:tbl>"
            + self.para("", "Spacer")
        )

    def table(self, node) -> str:
        rows = []

        def collect(n):
            for c in n.children:
                if isinstance(c, str):
                    continue
                if c.tag == "tr":
                    rows.append(c)
                elif c.tag in ("thead", "tbody", "tfoot"):
                    collect(c)

        collect(node)
        grid_rows = [[c for c in r.children if not isinstance(c, str) and c.tag in ("td", "th")] for r in rows]
        grid_rows = [r for r in grid_rows if r]
        if not grid_rows:
            return ""
        ncol = max(sum(int(c.attrs.get("colspan") or 1) for c in r) for r in grid_rows)
        weight = [1.0] * ncol
        floor = [500] * ncol  # twips; never narrower than the longest word in the column
        for r in grid_rows:
            if any(c.attrs.get("colspan") for c in r):
                continue
            for i, c in enumerate(r):
                text = re.sub(r"\s+", " ", _text(c)).strip()
                longest = max((len(w) for w in text.split()), default=0)
                weight[i] = max(weight[i], min(len(text), 120) ** 0.7)
                floor[i] = max(floor[i], min(longest, 22) * 95 + 200)
        if sum(floor) > PAGE_W:
            floor = [int(f * PAGE_W / sum(floor)) for f in floor]
        spare = PAGE_W - sum(floor)
        total = sum(weight)
        widths = [int(f + spare * w / total) for f, w in zip(floor, weight)]
        grid = "".join(f'<w:gridCol w:w="{w}"/>' for w in widths)
        out_rows = []
        for ri, r in enumerate(grid_rows):
            header = all(c.tag == "th" for c in r)
            cells, col = [], 0
            for c in r:
                span = int(c.attrs.get("colspan") or 1)
                w = sum(widths[col : col + span])
                col += span
                fmt = {"b": True, "color": "5B6170", "size": 15} if c.tag == "th" else {"size": 17}
                body = self._cell_blocks(c, fmt)
                tcpr = f'<w:tcW w:w="{w}" w:type="dxa"/>' + (f'<w:gridSpan w:val="{span}"/>' if span > 1 else "")
                if header:
                    tcpr += '<w:shd w:val="clear" w:color="auto" w:fill="F1F3F6"/>'
                cells.append(f"<w:tc><w:tcPr>{tcpr}</w:tcPr>{body}</w:tc>")
            if col < ncol:  # ragged row: pad so Word keeps the grid aligned
                cells.append(f'<w:tc><w:tcPr><w:tcW w:w="{sum(widths[col:])}" w:type="dxa"/>'
                             f'<w:gridSpan w:val="{ncol - col}"/></w:tcPr><w:p/></w:tc>')
            trpr = "<w:trPr><w:tblHeader/><w:cantSplit/></w:trPr>" if header and ri == 0 else "<w:trPr><w:cantSplit/></w:trPr>"
            out_rows.append(f"<w:tr>{trpr}{''.join(cells)}</w:tr>")
        return (
            '<w:tbl><w:tblPr><w:tblStyle w:val="ReportTable"/><w:tblW w:w="5000" w:type="pct"/>'
            '<w:tblLayout w:type="fixed"/></w:tblPr>'
            f"<w:tblGrid>{grid}</w:tblGrid>{''.join(out_rows)}</w:tbl>"
        )

    def _cell_blocks(self, cell, fmt: dict) -> str:
        paras, pending = [], []

        def flush():
            runs = "".join(self.runs(c, fmt) for c in pending).strip()
            pending.clear()
            if runs:
                paras.append(self.para(runs, "Cell"))

        for c in cell.children:
            if _is_block(c) and c.tag not in ("td", "th"):
                flush()
                if c.tag == "table":
                    paras.append(self.table(c))
                    paras.append(self.para("", "Cell"))
                else:
                    sub = self.blocks(c, "Cell")
                    paras.extend(sub)
            else:
                pending.append(c)
        flush()
        return "".join(paras) or self.para("", "Cell")


def _image_size(data: bytes) -> tuple[int, int]:
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return int.from_bytes(data[6:8], "little"), int.from_bytes(data[8:10], "little")
    if data[:2] == b"\xff\xd8":
        i = 2
        while i < len(data) - 9:
            if data[i] != 0xFF:
                i += 1
                continue
            marker = data[i + 1]
            length = int.from_bytes(data[i + 2 : i + 4], "big")
            if marker in (0xC0, 0xC1, 0xC2):
                return int.from_bytes(data[i + 7 : i + 9], "big"), int.from_bytes(data[i + 5 : i + 7], "big")
            i += 2 + length
    return 0, 0


STYLES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/><w:sz w:val="20"/>
<w:color w:val="16181D"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="100" w:line="264" w:lineRule="auto"/>
</w:pPr></w:pPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/>
<w:pPr><w:keepNext/><w:spacing w:before="240" w:after="120"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:sz w:val="40"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/>
<w:pPr><w:keepNext/><w:pBdr><w:bottom w:val="single" w:sz="4" w:space="3" w:color="C9CCD4"/></w:pBdr><w:spacing w:before="300" w:after="120"/>
<w:outlineLvl w:val="1"/></w:pPr><w:rPr><w:b/><w:sz w:val="28"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/>
<w:pPr><w:keepNext/><w:spacing w:before="200" w:after="80"/><w:outlineLvl w:val="2"/></w:pPr><w:rPr><w:b/><w:sz w:val="22"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Cell"><w:name w:val="Table Cell"/><w:basedOn w:val="Normal"/>
<w:pPr><w:spacing w:after="20" w:line="240" w:lineRule="auto"/></w:pPr><w:rPr><w:sz w:val="17"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Small"><w:name w:val="Small"/><w:basedOn w:val="Normal"/><w:rPr><w:color w:val="5B6170"/><w:sz w:val="16"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Note"><w:name w:val="Note"/><w:basedOn w:val="Normal"/>
<w:pPr><w:pBdr><w:left w:val="single" w:sz="18" w:space="6" w:color="2457D6"/></w:pBdr><w:shd w:val="clear" w:color="auto" w:fill="F5F7FB"/>
<w:ind w:left="120"/></w:pPr></w:style>
<w:style w:type="paragraph" w:styleId="ListPara"><w:name w:val="List Paragraph"/><w:basedOn w:val="Normal"/>
<w:pPr><w:tabs><w:tab w:val="left" w:pos="360"/></w:tabs><w:spacing w:after="40"/><w:ind w:left="360" w:hanging="360"/></w:pPr></w:style>
<w:style w:type="paragraph" w:styleId="Code"><w:name w:val="Code"/><w:basedOn w:val="Normal"/>
<w:pPr><w:shd w:val="clear" w:color="auto" w:fill="F5F7FB"/><w:spacing w:after="120" w:line="240" w:lineRule="auto"/></w:pPr>
<w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/><w:sz w:val="15"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Spacer"><w:name w:val="Spacer"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="60"/></w:pPr><w:rPr><w:sz w:val="8"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Rule"><w:name w:val="Rule"/><w:basedOn w:val="Normal"/>
<w:pPr><w:pBdr><w:top w:val="single" w:sz="4" w:space="1" w:color="E3E5EA"/></w:pBdr><w:spacing w:before="160" w:after="0"/></w:pPr><w:rPr><w:sz w:val="4"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:rPr><w:b/><w:sz w:val="52"/></w:rPr></w:style>
<w:style w:type="table" w:styleId="ReportTable"><w:name w:val="Report Table"/><w:tblPr>
<w:tblBorders><w:top w:val="single" w:sz="4" w:color="E3E5EA"/><w:bottom w:val="single" w:sz="4" w:color="E3E5EA"/>
<w:insideH w:val="single" w:sz="4" w:color="E3E5EA"/></w:tblBorders>
<w:tblCellMar><w:top w:w="40" w:type="dxa"/><w:left w:w="80" w:type="dxa"/><w:bottom w:w="40" w:type="dxa"/><w:right w:w="80" w:type="dxa"/></w:tblCellMar>
</w:tblPr></w:style>
</w:styles>"""

NS = (
    'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
    'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" '
    'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
    'xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"'
)


def _field(code: str) -> str:
    return (
        '<w:r><w:fldChar w:fldCharType="begin"/></w:r>'
        f'<w:r><w:instrText xml:space="preserve"> {code} </w:instrText></w:r>'
        '<w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>1</w:t></w:r>'
        '<w:r><w:fldChar w:fldCharType="end"/></w:r>'
    )


def render_docx(html: str, *, kind: str, draft: bool) -> bytes:
    """Build a styled .docx from the sealed report HTML."""
    title = _title_of(html)
    prepared = prepare_html(html, kind=kind, draft=draft, for_engine="docx")
    tree = _Tree()
    tree.feed(prepared)
    body_node = next((n for n in _walk(tree.root) if n.tag == "body"), tree.root)
    w = _Writer(draft)
    blocks = w.blocks(body_node)
    # Contents list after the cover for longer reports (Word users can swap in a TOC field).
    heads = [re.sub(r"\s+", " ", _text(n)).strip() for n in _walk(body_node) if n.tag == "h2"]
    own = [n for n in _walk(body_node) if n.tag == "h2" and not n.attrs.get("id", "").startswith("pdf-")]
    if kind not in LETTER_KINDS and len(own) >= 3:
        toc = [w.para(w._run("Contents", {"b": True, "size": 28}))] + [
            w.para(w._run(h, {}), "ListPara") for h in heads
        ] + ['<w:p><w:r><w:br w:type="page"/></w:r></w:p>']
        cut = next((i + 1 for i, b in enumerate(blocks) if 'w:type="page"' in b), 0)
        blocks[cut:cut] = toc
    sect = (
        '<w:sectPr><w:headerReference w:type="default" r:id="rIdHdr"/><w:footerReference w:type="default" r:id="rIdFtr"/>'
        '<w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" '
        'w:header="567" w:footer="567" w:gutter="0"/></w:sectPr>'
    )
    document = (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document {NS}><w:body>'
        + "".join(blocks)
        + sect
        + "</w:body></w:document>"
    )
    hdr_runs = (
        w._run("DRAFT \u2014 not signed. ", {"b": True, "color": "A1161B", "size": 16})
        + w._run("Not for distribution until approved and signed in Attestra.", {"color": "A1161B", "size": 16})
        if draft
        else w._run(title, {"color": "5B6170", "size": 16})
    )
    header = (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:hdr {NS}>'
        f'<w:p><w:pPr><w:jc w:val="center"/></w:pPr>{hdr_runs}</w:p></w:hdr>'
    )
    small = {"color": "5B6170", "size": 16}
    footer = (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:ftr {NS}><w:p><w:pPr><w:jc w:val="center"/></w:pPr>'
        + w._run(f"{title} \u00b7 Confidential \u00b7 Page ", small)
        + _field("PAGE")
        + w._run(" of ", small)
        + _field("NUMPAGES")
        + "</w:p></w:ftr>"
    )
    img_types = "".join(
        f'<Default Extension="{e}" ContentType="image/{e}"/>' for e in sorted({n.rsplit(".", 1)[1] for n, _ in w.images})
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>' + img_types +
        '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
        '<Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/>'
        '<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>'
        "</Types>"
    )
    rel = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    doc_rels = (
        '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f'<Relationship Id="rIdStyles" Type="{rel}/styles" Target="styles.xml"/>'
        f'<Relationship Id="rIdHdr" Type="{rel}/header" Target="header1.xml"/>'
        f'<Relationship Id="rIdFtr" Type="{rel}/footer" Target="footer1.xml"/>'
        + "".join(
            f'<Relationship Id="rIdImg{i}" Type="{rel}/image" Target="media/{n}"/>' for i, (n, _) in enumerate(w.images, 1)
        )
        + "</Relationships>"
    )
    root_rels = (
        '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f'<Relationship Id="rId1" Type="{rel}/officeDocument" Target="word/document.xml"/></Relationships>'
    )
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", root_rels)
        zf.writestr("word/document.xml", document)
        zf.writestr("word/styles.xml", STYLES)
        zf.writestr("word/header1.xml", header)
        zf.writestr("word/footer1.xml", footer)
        zf.writestr("word/_rels/document.xml.rels", doc_rels)
        for name, data in w.images:
            zf.writestr(f"word/media/{name}", data)
    return buf.getvalue()


def _walk(node):
    if isinstance(node, str):
        return
    yield node
    for c in node.children:
        yield from _walk(c)
