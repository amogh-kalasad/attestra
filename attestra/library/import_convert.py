"""Convert onboarding findings-library templates (JSON/CSV) into entry dicts.

Used during tenant setup so a simple list of writeups can be imported without
hand-entering each row. Field names match common export shapes; they are mapped
onto LibraryEntry columns before validation.
"""

from __future__ import annotations

import csv
import io
import json

from attestra.library.service import LibraryError, _validate

# Cap upload size and row count so a bad file cannot flood the tenant library.
MAX_TEMPLATE_BYTES = 1_000_000
MAX_ENTRIES = 500

_JSON_KEYS = frozenset({"entries", "items", "writeups", "library"})


def convert_library_template(data: bytes, fmt: str | None = None) -> list[dict]:
    """Parse JSON or CSV bytes into validated library entry dicts.

    Accepted fields per row: ``title`` (required), ``severity``, ``description``,
    ``recommendation``, optional ``owasp_top10``. Oversized payloads and empty
    files raise ``LibraryError``.
    """
    if data is None:
        raise LibraryError("template is empty")
    if len(data) > MAX_TEMPLATE_BYTES:
        raise LibraryError(f"template exceeds {MAX_TEMPLATE_BYTES} byte limit")
    if not data.strip():
        raise LibraryError("template is empty")

    kind = (fmt or "").strip().lower() or _detect_fmt(data)
    if kind in ("json", "application/json"):
        rows = _parse_json(data)
    elif kind in ("csv", "text/csv"):
        rows = _parse_csv(data)
    else:
        raise LibraryError("fmt must be json or csv")

    if not rows:
        raise LibraryError("template has no entries")
    if len(rows) > MAX_ENTRIES:
        raise LibraryError(f"template exceeds {MAX_ENTRIES} entry limit")

    out: list[dict] = []
    seen: set[str] = set()
    for i, raw in enumerate(rows, start=1):
        if not isinstance(raw, dict):
            raise LibraryError(f"entry {i} must be an object")
        mapped = _map_row(raw)
        clean = _validate({"default_severity": "medium", **mapped})
        if "title" not in clean or not clean["title"]:
            raise LibraryError(f"entry {i} needs a title")
        title = clean["title"]
        if title in seen:
            raise LibraryError(f"duplicate title in template: {title}")
        seen.add(title)
        out.append(clean)
    return out


def _detect_fmt(data: bytes) -> str:
    head = data.lstrip()[:1]
    if head in (b"{", b"["):
        return "json"
    return "csv"


def _parse_json(data: bytes) -> list:
    try:
        doc = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise LibraryError(f"invalid JSON template: {e}") from e
    if isinstance(doc, list):
        return doc
    if isinstance(doc, dict):
        for key in _JSON_KEYS:
            if key in doc and isinstance(doc[key], list):
                return doc[key]
        raise LibraryError("JSON template must be a list or an object with an entries array")
    raise LibraryError("JSON template must be a list or an object with an entries array")


def _parse_csv(data: bytes) -> list[dict]:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as e:
        raise LibraryError(f"invalid CSV encoding: {e}") from e
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise LibraryError("CSV template needs a header row")
    return [dict(row) for row in reader]


def _map_row(raw: dict) -> dict:
    """Map onboarding field names onto LibraryEntry columns."""
    def g(*names: str) -> str:
        for n in names:
            if n in raw and raw[n] is not None:
                return str(raw[n]).strip()
        return ""

    title = g("title")
    severity = g("severity", "default_severity") or "medium"
    description = g("description")
    remediation = g("recommendation", "remediation")
    tags = _clean_list(raw.get("tags"))
    owasp = raw.get("owasp_top10")
    if owasp is None:
        owasp = raw.get("owasp")
    for tag in _owasp_tags(owasp):
        if tag not in tags:
            tags.append(tag)

    out: dict = {
        "title": title,
        "default_severity": severity.lower() if severity else "medium",
        "description": description,
        "remediation": remediation,
    }
    if tags:
        out["tags"] = tags
    cwe = raw.get("cwe")
    if cwe not in (None, ""):
        out["cwe"] = cwe
    impact = g("impact")
    if impact:
        out["impact"] = impact
    refs = raw.get("references")
    if refs not in (None, ""):
        out["references"] = refs
    return out


def _owasp_tags(value) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, (list, tuple)):
        items = value
    else:
        items = str(value).replace(";", ",").split(",")
    out: list[str] = []
    for item in items:
        t = str(item).strip()
        if not t:
            continue
        low = t.lower()
        if low.startswith("owasp"):
            out.append(t if " " not in t else low.replace(" ", "-"))
        else:
            # A03:2021-Injection → owasp-a03; bare A03 → owasp-a03
            code = low.split(":")[0].split("-")[0].strip()
            out.append(f"owasp-{code}" if code else f"owasp-{low}")
    return out


def _clean_list(value) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, str):
        value = value.replace("\n", ",").split(",")
    out: list[str] = []
    for v in value:
        v = str(v).strip()
        if v and v not in out:
            out.append(v[:200])
    return out
