"""Annotate Elite screenshots via existing evidence.annotate helpers."""

from __future__ import annotations

from typing import Any

from attestra.evidence.annotate import AnnotateError, Highlight, annotate_png, pillow_available

# @lat: [[architecture#Elite automated security testing#Evidence visuals]]


def annotate_screenshot(
    png_bytes: bytes,
    highlights: list[dict[str, Any]] | list[Highlight],
    *,
    caption: str = "",
) -> tuple[bytes, dict[str, Any]]:
    """Return annotated PNG bytes; original bytes are unchanged."""
    return annotate_png(png_bytes, highlights, caption=caption)


__all__ = ["AnnotateError", "Highlight", "annotate_screenshot", "pillow_available"]
