"""Small helpers shared by the Phase 7 importers."""

from __future__ import annotations

import json


def load_json_or_lines(raw: bytes):
    """Parse a JSON document, or JSON Lines when the whole file is not one document."""
    text = raw.decode("utf-8-sig", errors="replace").strip()
    if not text:
        return []
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]
