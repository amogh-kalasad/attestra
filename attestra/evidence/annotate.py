"""Create annotated screenshot derivatives without altering originals.

Annotations use visible borders and numbered markers. Caption text sits in a
margin strip so it does not cover the captured application content.
"""
# @lat: [[authorization#Evidence gallery#Annotated derivatives]]

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from typing import Any

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:  # pragma: no cover
    Image = None  # type: ignore[assignment,misc]
    ImageDraw = None  # type: ignore[assignment,misc]
    ImageFont = None  # type: ignore[assignment,misc]


class AnnotateError(RuntimeError):
    """Raised when annotation cannot run (bad image or missing Pillow)."""


@dataclass(frozen=True)
class Highlight:
    x: int
    y: int
    w: int
    h: int
    label: str = ""


def pillow_available() -> bool:
    return Image is not None and ImageDraw is not None


def annotate_png(
    png_bytes: bytes,
    highlights: list[Highlight] | list[dict[str, Any]],
    *,
    caption: str = "",
) -> tuple[bytes, dict[str, Any]]:
    """Return annotated PNG bytes plus annotation metadata.

    The original ``png_bytes`` are never modified in place. Requires Pillow.
    """
    if not pillow_available():
        raise AnnotateError("Pillow is required to create annotated screenshot derivatives")
    if not png_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        raise AnnotateError("annotated derivatives require a PNG original")
    assert Image is not None and ImageDraw is not None

    parsed: list[Highlight] = []
    for item in highlights or []:
        if isinstance(item, Highlight):
            parsed.append(item)
        else:
            parsed.append(
                Highlight(
                    x=int(item.get("x", 0)),
                    y=int(item.get("y", 0)),
                    w=int(item.get("w", 0)),
                    h=int(item.get("h", 0)),
                    label=str(item.get("label") or ""),
                )
            )

    with Image.open(BytesIO(png_bytes)) as img:
        base = img.convert("RGBA")
        width, height = base.size
        caption_h = 36 if (caption or "").strip() else 0
        canvas = Image.new("RGBA", (width, height + caption_h), (255, 255, 255, 255))
        canvas.paste(base, (0, 0))
        draw = ImageDraw.Draw(canvas)
        try:
            font = ImageFont.load_default()
        except Exception:  # pragma: no cover
            font = None

        meta_highlights: list[dict[str, Any]] = []
        for idx, hl in enumerate(parsed, start=1):
            if hl.w <= 0 or hl.h <= 0:
                continue
            x0 = max(0, hl.x)
            y0 = max(0, hl.y)
            x1 = min(width - 1, x0 + hl.w)
            y1 = min(height - 1, y0 + hl.h)
            if x1 <= x0 or y1 <= y0:
                continue
            # Non-obstructive border + numbered marker outside the content box.
            draw.rectangle([x0, y0, x1, y1], outline=(220, 38, 38, 255), width=3)
            marker = str(idx)
            mx = min(width - 18, max(0, x0))
            my = max(0, y0 - 16)
            draw.ellipse([mx, my, mx + 16, my + 16], fill=(220, 38, 38, 255))
            draw.text((mx + 4, my + 2), marker, fill=(255, 255, 255, 255), font=font)
            meta_highlights.append(
                {"x": x0, "y": y0, "w": x1 - x0, "h": y1 - y0, "label": hl.label or marker, "marker": idx}
            )

        if caption_h:
            draw.rectangle([0, height, width, height + caption_h], fill=(248, 250, 252, 255))
            draw.text((8, height + 10), (caption or "").strip()[:200], fill=(15, 23, 42, 255), font=font)

        out = BytesIO()
        canvas.convert("RGB").save(out, format="PNG", optimize=True)
        meta = {
            "highlights": meta_highlights,
            "caption": (caption or "").strip()[:500],
            "original_width": width,
            "original_height": height,
            "annotated": True,
        }
        return out.getvalue(), meta
