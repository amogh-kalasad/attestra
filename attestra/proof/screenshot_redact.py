"""Screenshot evidence redaction helpers for authenticated web capture.

Pixel region redaction prefers Pillow when installed; it is an optional import
and never a hard dependency. DOM prep ([[prepare_page_for_capture]]) and PNG
metadata/ASCII scans work with the stdlib alone. Callers should run the JS
prep in the page before capture, then [[attach_redacted_screenshot]] to store.
"""
# @lat: [[architecture#Authenticated website testing]]

from __future__ import annotations

import json
import struct
import zlib
from collections.abc import Sequence
from io import BytesIO
from typing import TYPE_CHECKING

from attestra.proof.store import attach_screenshot

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from attestra.models import Evidence

try:
    from PIL import Image, ImageDraw
except ImportError:  # pragma: no cover - exercised when Pillow absent
    Image = None  # type: ignore[assignment,misc]
    ImageDraw = None  # type: ignore[assignment,misc]

_PNG_SIG = b"\x89PNG\r\n\x1a\n"
_TEXT_CHUNKS = frozenset({b"tEXt", b"zTXt", b"iTXt"})
Region = tuple[int, int, int, int]


class RedactionError(RuntimeError):
    """Raised when pixel redaction cannot run (typically Pillow missing)."""


def pillow_available() -> bool:
    """Return True when Pillow can be used for pixel-region redaction."""
    return Image is not None and ImageDraw is not None


def prepare_page_for_capture(sensitive_selectors: list[str] | None = None) -> str:
    """Return a JS snippet that masks password fields and matching selectors.

    Sets ``input[type=password]`` and each selector to password-style masking,
    replaces visible values with bullets, and marks nodes with
    ``data-attestra-redact`` for the crawler to screenshot afterward.
    """
    selectors = [str(s) for s in (sensitive_selectors or []) if str(s).strip()]
    # JSON list is safe to embed inside a single-quoted JS string assignment.
    sel_json = json.dumps(selectors, ensure_ascii=True)
    return (
        "(function(){"
        f"var sels={sel_json};"
        "function mark(el){"
        "try{"
        "el.setAttribute('data-attestra-redact','1');"
        "var t=(el.tagName||'').toUpperCase();"
        "if(t==='INPUT'||t==='TEXTAREA'){"
        "try{if(el.type!=='password')el.type='password';}catch(e){}"
        "try{el.value='••••••••';}catch(e){}"
        "}else{"
        "try{el.textContent='••••••••';}catch(e){}"
        "}"
        "}catch(e){}"
        "}"
        "try{document.querySelectorAll('input[type=password]').forEach(mark);}catch(e){}"
        "for(var i=0;i<sels.length;i++){"
        "try{document.querySelectorAll(sels[i]).forEach(mark);}catch(e){}"
        "}"
        "})();"
    )


def _iter_png_chunks(png_bytes: bytes):
    if not png_bytes.startswith(_PNG_SIG):
        raise RedactionError("not a PNG image")
    pos = len(_PNG_SIG)
    end = len(png_bytes)
    while pos + 8 <= end:
        length = struct.unpack(">I", png_bytes[pos : pos + 4])[0]
        ctype = png_bytes[pos + 4 : pos + 8]
        data_start = pos + 8
        data_end = data_start + length
        crc_end = data_end + 4
        if crc_end > end:
            raise RedactionError("truncated PNG chunk")
        data = png_bytes[data_start:data_end]
        yield ctype, data, png_bytes[pos:crc_end]
        pos = crc_end
        if ctype == b"IEND":
            break


def _decode_text_chunk(ctype: bytes, data: bytes) -> str:
    if ctype == b"tEXt":
        return data.decode("latin-1", "replace")
    if ctype == b"zTXt":
        nul = data.find(b"\x00")
        if nul < 0 or nul + 2 > len(data):
            return data.decode("latin-1", "replace")
        # byte after keyword NUL is compression method (0 = zlib)
        try:
            return data[:nul].decode("latin-1", "replace") + "\x00" + zlib.decompress(data[nul + 2 :]).decode(
                "latin-1", "replace"
            )
        except zlib.error:
            return data.decode("latin-1", "replace")
    if ctype == b"iTXt":
        # keyword\0 compression_flag compression_method language\0 translated\0 text
        parts = data.split(b"\x00", 3)
        if len(parts) < 4:
            return data.decode("utf-8", "replace")
        keyword, _rest = parts[0], parts[3] if len(parts) == 4 else b""
        # After first NUL: comp_flag (1) + comp_method (1) then language\0 translated\0 text
        if len(data) > len(keyword) + 1:
            body = data[len(keyword) + 1 :]
            if len(body) >= 2:
                comp_flag = body[0]
                # skip comp_method, then language\0 translated\0 text
                rem = body[2:]
                lang_end = rem.find(b"\x00")
                if lang_end >= 0:
                    rem = rem[lang_end + 1 :]
                    tr_end = rem.find(b"\x00")
                    if tr_end >= 0:
                        text = rem[tr_end + 1 :]
                        if comp_flag == 1:
                            try:
                                text = zlib.decompress(text)
                            except zlib.error:
                                pass
                        return keyword.decode("latin-1", "replace") + "\x00" + text.decode("utf-8", "replace")
        return data.decode("utf-8", "replace")
    return ""


def strip_png_text_chunks(png_bytes: bytes) -> bytes:
    """Return PNG bytes with tEXt/zTXt/iTXt chunks removed (stdlib only)."""
    out = bytearray(_PNG_SIG)
    for ctype, _data, raw in _iter_png_chunks(png_bytes):
        if ctype in _TEXT_CHUNKS:
            continue
        out.extend(raw)
    return bytes(out)


def scan_png_for_plaintext_ascii(png_bytes: bytes, forbidden_substrings: Sequence[str]) -> list[str]:
    """Return which forbidden substrings appear as literal ASCII/UTF-8 in PNG bytes.

    Intended for tests and pre-store checks. Does not log or echo secret values.
    """
    hits: list[str] = []
    if not png_bytes:
        return hits
    for item in forbidden_substrings:
        if not item:
            continue
        needle = item.encode("utf-8") if isinstance(item, str) else bytes(item)
        if needle and needle in png_bytes:
            hits.append(item if isinstance(item, str) else item.decode("utf-8", "replace"))
    return hits


def assert_no_secret_in_png_metadata(png_bytes: bytes, forbidden_substrings: Sequence[str]) -> None:
    """Raise ``AssertionError`` if any forbidden string appears in PNG text chunks.

    Error messages never include the forbidden values.
    """
    if not png_bytes.startswith(_PNG_SIG):
        raise RedactionError("not a PNG image")
    found = 0
    needles = [s for s in forbidden_substrings if s]
    for ctype, data, _raw in _iter_png_chunks(png_bytes):
        if ctype not in _TEXT_CHUNKS:
            continue
        text = _decode_text_chunk(ctype, data)
        for needle in needles:
            if needle in text:
                found += 1
                break
    # Also treat literal plaintext anywhere in the file as a metadata/leak hit for tests.
    if scan_png_for_plaintext_ascii(png_bytes, needles):
        found += 1
    if found:
        raise AssertionError("forbidden material present in PNG metadata or plaintext bytes")


def redact_png_regions(png_bytes: bytes, regions: list[Region]) -> bytes:
    """Black out rectangular regions in a PNG and strip text metadata chunks.

    Requires Pillow for pixel painting. Raises [[RedactionError]] when Pillow is
    unavailable or the input is not a PNG. Empty ``regions`` still strips text
    chunks via the stdlib path.
    """
    if not png_bytes.startswith(_PNG_SIG):
        raise RedactionError("not a PNG image")
    if not regions:
        return strip_png_text_chunks(png_bytes)
    if not pillow_available():
        raise RedactionError(
            "Pillow is required for pixel-region screenshot redaction; "
            "install pillow or rely on prepare_page_for_capture DOM masking"
        )
    assert Image is not None and ImageDraw is not None
    with Image.open(BytesIO(png_bytes)) as img:
        work = img.convert("RGBA")
        draw = ImageDraw.Draw(work)
        width, height = work.size
        for x, y, w, h in regions:
            if w <= 0 or h <= 0:
                continue
            x0 = max(0, int(x))
            y0 = max(0, int(y))
            x1 = min(width, x0 + int(w))
            y1 = min(height, y0 + int(h))
            if x1 > x0 and y1 > y0:
                draw.rectangle([x0, y0, x1 - 1, y1 - 1], fill=(0, 0, 0, 255))
        buf = BytesIO()
        work.save(buf, format="PNG", optimize=True)
        return strip_png_text_chunks(buf.getvalue())


def _note_with_status(note: str, status: str) -> str:
    marker = f"redaction_status={status}"
    base = (note or "").rstrip()
    if not base:
        return marker
    if marker in base:
        return base
    return f"{base}\n{marker}"


def attach_redacted_screenshot(
    s: Session,
    finding_id: int,
    *,
    filename: str,
    data: bytes,
    actor: str,
    note: str = "",
    regions: list[Region] | None = None,
) -> Evidence:
    """Redact PNG regions when possible, then store via [[attach_screenshot]].

    Callers should have already applied [[prepare_page_for_capture]] in the page
    before capturing ``data``. Note always records ``redaction_status=redacted``
    or ``redaction_status=skipped``. Pixel redaction skips (does not raise) when
    Pillow is missing so crawl pipelines can still store DOM-masked shots.
    """
    regions = list(regions or [])
    payload = data
    status = "skipped"
    if regions:
        try:
            payload = redact_png_regions(data, regions)
            status = "redacted"
        except RedactionError:
            # DOM prep may already have masked secrets; store without pixel paint.
            try:
                payload = strip_png_text_chunks(data) if data.startswith(_PNG_SIG) else data
            except RedactionError:
                payload = data
            status = "skipped"
    elif data.startswith(_PNG_SIG):
        try:
            payload = strip_png_text_chunks(data)
        except RedactionError:
            payload = data
    return attach_screenshot(
        s,
        finding_id,
        filename=filename or "screenshot.png",
        data=payload,
        actor=actor,
        note=_note_with_status(note, status),
    )
