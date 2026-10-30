"""Two-panel HTTP request/response PNG evidence (Attestra-generated visuals)."""

from __future__ import annotations

import json
import re
from io import BytesIO
from typing import Any

from attestra.proof.pair import HttpPair
from attestra.services import ServiceError

# @lat: [[architecture#Elite automated security testing#Evidence visuals]]

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:  # pragma: no cover
    Image = None  # type: ignore[assignment,misc]
    ImageDraw = None  # type: ignore[assignment,misc]
    ImageFont = None  # type: ignore[assignment,misc]

_HIGHLIGHT_FIELDS = (
    "projectid",
    "userid",
    "role",
    "platform_role",
    "tenantid",
    "organizationid",
    "permissions",
    "secret_note",
    "api_token",
)
_BANNER = "Attestra-generated visual representation (not a Burp Suite screenshot)"


def render_http_pair_png(pair: HttpPair | dict[str, Any], *, width: int = 1200, height: int = 800) -> bytes:
    """Render a left-request / right-response PNG with basic field highlighting."""
    if Image is None or ImageDraw is None:
        raise ServiceError("Pillow is required to render HTTP pair evidence images")
    if isinstance(pair, HttpPair):
        data = pair.redacted()
        method, url, status = data.method, data.url, data.status
        req_h, req_b = data.request_headers, data.request_body
        resp_h, resp_b = data.response_headers, data.response_body
    else:
        method = str(pair.get("method") or "GET")
        url = str(pair.get("url") or "")
        status = pair.get("status")
        req_h = pair.get("request_headers") or {}
        req_b = str(pair.get("request_body") or "")
        resp_h = pair.get("response_headers") or {}
        resp_b = str(pair.get("response_body") or "")

    left = _panel_text("HTTP REQUEST", method, url, req_h, req_b)
    right = _panel_text("HTTP RESPONSE", str(status or ""), url, resp_h, resp_b)

    img = Image.new("RGB", (width, height), (248, 249, 251))
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.load_default()
    except Exception:  # pragma: no cover
        font = None

    mid = width // 2
    draw.rectangle([0, 0, width, 28], fill=(30, 64, 110))
    draw.text((8, 8), _BANNER, fill=(255, 255, 255), font=font)
    draw.line([(mid, 28), (mid, height)], fill=(180, 180, 180), width=2)
    _draw_wrapped(draw, left, 8, 36, mid - 16, font)
    _draw_wrapped(draw, right, mid + 8, 36, width - mid - 16, font)

    # Highlight security-relevant field names present in either panel.
    hay = (left + "\n" + right).lower()
    y = height - 22
    for field in _HIGHLIGHT_FIELDS:
        if field in hay:
            draw.rectangle([8, y - 2, 8 + 7 * len(field), y + 12], outline=(200, 40, 40), width=1)
            draw.text((10, y), field, fill=(180, 0, 0), font=font)
            y -= 14
            if y < height - 120:
                break

    buf = BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _panel_text(title: str, line1: str, url: str, headers: dict, body: str) -> str:
    lines = [title, f"{line1} {url}".strip(), ""]
    for k, v in list(headers.items())[:20]:
        lines.append(f"{k}: {v}")
    lines.append("")
    body_s = body if isinstance(body, str) else json.dumps(body, indent=2)
    # Light "syntax" markers for JSON braces.
    body_s = re.sub(r"([{}[\],])", r"\1", body_s[:4000])
    lines.extend(body_s.splitlines()[:80])
    return "\n".join(lines)


def _draw_wrapped(draw, text: str, x: int, y: int, max_width: int, font) -> None:
    # Default bitmap font is ~6px wide; approximate wrap by characters.
    max_chars = max(20, max_width // 6)
    cy = y
    for raw in text.splitlines():
        while raw:
            chunk, raw = raw[:max_chars], raw[max_chars:]
            draw.text((x, cy), chunk, fill=(20, 20, 20), font=font)
            cy += 12
            if cy > 10000:
                return
