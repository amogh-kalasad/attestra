"""Capture and persist same-host POST/PUT/PATCH JSON bodies for T22 body mutation.

Bodies are redacted (no Authorization/Cookie) and truncated. Cap applies per run.
Never logs secret header/cookie values.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from attestra.automated_vapt.evidence.run_evidence import run_dir

WRITE_METHODS = frozenset({"POST", "PUT", "PATCH"})
DEFAULT_BODY_CAP = 50
DEFAULT_BODY_MAX_BYTES = 32_768
WRITE_BODIES_FILENAME = "captured-write-bodies.json"

_SENSITIVE_HEADER = re.compile(r"(?i)^(authorization|cookie|set-cookie|x-api-key|proxy-authorization)$")
_SENSITIVE_JSON_KEY = re.compile(
    r"(?i)(password|passwd|secret|token|access_token|refresh_token|id_token|api[_-]?key|authorization|cookie)"
)


def is_write_method(method: str | None) -> bool:
    return (method or "").upper() in WRITE_METHODS


def same_host(url: str, root: str) -> bool:
    try:
        a, b = urlsplit(url), urlsplit(root)
        return bool(a.hostname) and (a.hostname or "").lower() == (b.hostname or "").lower()
    except Exception:  # noqa: BLE001
        return False


def looks_json_body(body: str, content_type: str = "") -> bool:
    ct = (content_type or "").lower()
    if "json" in ct:
        return True
    s = (body or "").lstrip()
    return s.startswith("{") or s.startswith("[")


def redact_headers(headers: dict[str, str] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in (headers or {}).items():
        if _SENSITIVE_HEADER.match(str(k)):
            out[str(k)] = "[REDACTED]"
        else:
            out[str(k)] = str(v)[:200]
    return out


def redact_json_body(body: str, *, max_bytes: int = DEFAULT_BODY_MAX_BYTES) -> str:
    """Redact sensitive JSON string fields; truncate to max_bytes."""
    text = body or ""
    try:
        data = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        return text[:max_bytes]

    def walk(obj: Any) -> Any:
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if _SENSITIVE_JSON_KEY.search(str(k)) and isinstance(v, str):
                    out[k] = "[REDACTED]"
                else:
                    out[k] = walk(v)
            return out
        if isinstance(obj, list):
            return [walk(x) for x in obj[:100]]
        if isinstance(obj, str) and len(obj) > 500:
            return obj[:500] + "…"
        return obj

    try:
        dumped = json.dumps(walk(data), ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError):
        dumped = text
    return dumped[:max_bytes]


def normalize_write_capture(
    *,
    method: str,
    url: str,
    body: str,
    content_type: str = "",
    headers: dict[str, str] | None = None,
    root: str = "",
    max_bytes: int = DEFAULT_BODY_MAX_BYTES,
) -> dict[str, Any] | None:
    """Return a redacted capture dict, or None if not a usable write JSON body."""
    method_u = (method or "").upper()
    if not is_write_method(method_u):
        return None
    if not url:
        return None
    if root and not same_host(url, root):
        return None
    if not looks_json_body(body, content_type):
        return None
    body_r = redact_json_body(body, max_bytes=max_bytes)
    if not body_r.strip():
        return None
    return {
        "method": method_u,
        "url": url[:2000],
        "body": body_r,
        "request_body": body_r,
        "content_type": (content_type or "application/json")[:120],
        "headers": redact_headers(headers),
        "captured_at": datetime.now(UTC).isoformat(),
    }


def from_playwright_request(req: Any, *, root: str, max_bytes: int = DEFAULT_BODY_MAX_BYTES) -> dict[str, Any] | None:
    """Build a write capture from a Playwright Request object (no secrets logged)."""
    try:
        method = getattr(req, "method", "") or ""
        url = getattr(req, "url", "") or ""
        if not is_write_method(method):
            return None
        # Prefer XHR/fetch; still allow other same-host writes with JSON bodies.
        try:
            rtype = (req.resource_type or "").lower()
        except Exception:  # noqa: BLE001
            rtype = ""
        headers = {}
        try:
            headers = {str(k): str(v) for k, v in dict(req.headers).items()}
        except Exception:  # noqa: BLE001
            headers = {}
        lower = {k.lower(): v for k, v in headers.items()}
        ct = str(lower.get("content-type") or "")
        body = ""
        try:
            body = req.post_data or ""
        except Exception:  # noqa: BLE001
            body = ""
        if not body:
            try:
                buf = req.post_data_buffer
                if buf:
                    body = bytes(buf).decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                body = ""
        # Some Playwright builds expose JSON via post_data already; nothing else to try.
        if rtype and rtype not in {"xhr", "fetch", "other"} and not looks_json_body(body, ct):
            return None
        return normalize_write_capture(
            method=method,
            url=url,
            body=body,
            content_type=ct,
            headers=headers,
            root=root,
            max_bytes=max_bytes,
        )
    except Exception:  # noqa: BLE001
        return None


def dedupe_key(item: dict[str, Any]) -> tuple[str, str]:
    path = urlsplit(str(item.get("url") or "")).path or ""
    return ((item.get("method") or "").upper(), path)


def merge_write_captures(
    existing: list[dict[str, Any]] | None,
    new_items: list[dict[str, Any]] | None,
    *,
    cap: int = DEFAULT_BODY_CAP,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in list(existing or []) + list(new_items or []):
        if not isinstance(item, dict):
            continue
        key = dedupe_key(item)
        if key in seen:
            continue
        if not is_write_method(str(item.get("method") or "")):
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= cap:
            break
    return out


def write_bodies_path(execution_id: int) -> Path:
    return run_dir(int(execution_id)) / WRITE_BODIES_FILENAME


def save_write_bodies(execution_id: int, bodies: list[dict[str, Any]], *, cap: int = DEFAULT_BODY_CAP) -> Path:
    folder = run_dir(int(execution_id))
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / WRITE_BODIES_FILENAME
    trimmed = merge_write_captures([], bodies, cap=cap)
    # Public summary never includes bodies in sibling file — bodies stay in this JSON only.
    doc = {
        "execution_id": int(execution_id),
        "count": len(trimmed),
        "bodies": trimmed,
        "saved_at": datetime.now(UTC).isoformat(),
    }
    path.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    # Tiny summary for UI/logs (paths+methods only)
    summary = {
        "execution_id": int(execution_id),
        "count": len(trimmed),
        "entries": [
            {"method": b.get("method"), "path": urlsplit(str(b.get("url") or "")).path}
            for b in trimmed
        ],
        "saved_at": doc["saved_at"],
    }
    (folder / "captured-write-bodies.summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return path


def load_write_bodies(execution_id: int) -> list[dict[str, Any]]:
    path = write_bodies_path(int(execution_id))
    if not path.is_file():
        return []
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    bodies = doc.get("bodies") if isinstance(doc, dict) else doc
    if not isinstance(bodies, list):
        return []
    return [b for b in bodies if isinstance(b, dict)]


def load_newest_write_bodies_for_host(
    host: str,
    *,
    prefer_execution_id: int | None = None,
    raw_root: Path | None = None,
) -> list[dict[str, Any]]:
    """Load write bodies for ``host``, preferring ``prefer_execution_id`` then newest mtime."""
    host_l = (host or "").lower()
    if prefer_execution_id:
        bodies = load_write_bodies(int(prefer_execution_id))
        if bodies:
            return bodies

    from attestra import config

    root = raw_root or (config.DATA_DIR / "raw")
    if not root.is_dir():
        return []
    candidates: list[tuple[float, Path]] = []
    for p in root.glob("automated-*/" + WRITE_BODIES_FILENAME):
        try:
            candidates.append((p.stat().st_mtime, p))
        except OSError:
            continue
    candidates.sort(reverse=True)
    for _mtime, path in candidates:
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        bodies = doc.get("bodies") if isinstance(doc, dict) else None
        if not isinstance(bodies, list) or not bodies:
            continue
        # filter same host if possible
        matched = []
        for b in bodies:
            if not isinstance(b, dict):
                continue
            u = str(b.get("url") or "")
            try:
                if (urlsplit(u).hostname or "").lower() == host_l or not host_l:
                    matched.append(b)
            except Exception:  # noqa: BLE001
                continue
        if matched:
            return matched
    return []


def public_summary(bodies: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Paths + methods only (safe to log / put in result_json)."""
    out = []
    for b in bodies:
        out.append(
            {
                "method": str(b.get("method") or ""),
                "path": urlsplit(str(b.get("url") or "")).path or "",
            }
        )
    return out
