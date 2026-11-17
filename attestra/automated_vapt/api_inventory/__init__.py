"""API inventory import (C-01..C-04): OpenAPI 3.x / Swagger 2.0, Postman v2.1 and HAR 1.2.

[[parse_spec]] detects the format, validates it and returns a normalised
[[attestra/automated_vapt/api_inventory/model.py#ApiInventory]] with a SHA-256 of the
uploaded bytes. Unsupported constructs are listed explicitly (never silently dropped).
Imported operations are **inventory only**: nothing here sends a request, and only
GET/HEAD operations without path templates are ever merged into capture
([[attestra/automated_vapt/core/capture_urls.py#build_capture_urls]]). Mutating
operations are never replayed.

Behind ``ATTESTRA_API_IMPORT_ENABLED`` (default off).
"""

from __future__ import annotations

import json
from typing import Any

from attestra.automated_vapt.api_inventory.model import (
    ApiInventory,
    ApiOperation,
    ApiParam,
    SpecError,
    compute_coverage,
    max_spec_bytes,
    sha256_bytes,
)

# @lat: [[web-api-probes#API inventory import]]

__all__ = [
    "ApiInventory",
    "ApiOperation",
    "ApiParam",
    "SpecError",
    "compute_coverage",
    "detect_kind",
    "load_document",
    "parse_spec",
]


def load_document(data: bytes, filename: str = "") -> Any:
    """Decode JSON (or YAML for OpenAPI/Swagger) after the size check."""
    if len(data) > max_spec_bytes():
        raise SpecError(f"spec larger than {max_spec_bytes()} bytes")
    if not data.strip():
        raise SpecError("empty file")
    text = data.decode("utf-8-sig", "replace")
    try:
        return json.loads(text)
    except ValueError:
        pass
    try:
        import yaml

        doc = yaml.safe_load(text)
    except Exception as exc:  # noqa: BLE001
        raise SpecError(f"not valid JSON or YAML ({type(exc).__name__})") from None
    if not isinstance(doc, dict):
        raise SpecError("spec root must be an object")
    return doc


def detect_kind(doc: Any) -> str:
    if not isinstance(doc, dict):
        raise SpecError("spec root must be an object")
    if "openapi" in doc:
        return "openapi3"
    if str(doc.get("swagger") or "") == "2.0":
        return "swagger2"
    info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
    if "postman" in str(info.get("schema") or "").lower() or ("item" in doc and "info" in doc):
        return "postman"
    log = doc.get("log")
    if isinstance(log, dict) and "entries" in log:
        return "har"
    raise SpecError("unrecognised format (expected OpenAPI 3.x, Swagger 2.0, Postman v2.1 or HAR 1.2)")


def parse_spec(data: bytes, filename: str = "", *, allowed_origins: list[str] | tuple[str, ...] = ()) -> ApiInventory:
    """Parse + validate one uploaded file. ``allowed_origins`` marks out-of-scope servers."""
    doc = load_document(data, filename)
    kind = detect_kind(doc)
    if kind in ("openapi3", "swagger2"):
        from attestra.automated_vapt.api_inventory.openapi import parse_openapi

        inv = parse_openapi(doc)
    elif kind == "postman":
        from attestra.automated_vapt.api_inventory.postman import parse_postman

        inv = parse_postman(doc)
    else:
        from attestra.automated_vapt.api_inventory.har import parse_har

        inv = parse_har(doc)
    inv.sha256 = sha256_bytes(data)
    inv.size_bytes = len(data)
    inv.filename = (filename or "")[-200:]
    inv.dedupe()
    if allowed_origins:
        inv.apply_scope(list(allowed_origins))
    return inv
