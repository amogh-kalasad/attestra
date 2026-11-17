"""Normalised API inventory model shared by the OpenAPI / Postman / HAR importers."""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

# @lat: [[web-api-probes#API inventory import]]

INVENTORY_VERSION = "api-inv/1"
DEFAULT_MAX_SPEC_BYTES = 5 * 1024 * 1024
HTTP_METHODS = ("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE")
SAFE_METHODS = frozenset({"GET", "HEAD"})
MAX_OPERATIONS = 5_000


class SpecError(ValueError):
    """The uploaded file is not a valid / supported API description."""


def max_spec_bytes() -> int:
    raw = (os.environ.get("ATTESTRA_API_SPEC_MAX_BYTES") or "").strip()
    if raw.isdigit():
        return max(1024, min(int(raw), 50 * 1024 * 1024))
    return DEFAULT_MAX_SPEC_BYTES


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data or b"").hexdigest()


_TEMPLATE_RE = re.compile(r"\{[^}/]+\}")


def normalize_path(raw: str) -> str:
    """``/users/:id`` / ``/users/<id>`` / ``/users/{{id}}`` -> ``/users/{id}``; no query."""
    p = (raw or "").strip()
    if "://" in p:
        p = urlsplit(p).path or "/"
    p = p.split("?", 1)[0].split("#", 1)[0]
    if not p.startswith("/"):
        p = "/" + p
    p = re.sub(r"/{2,}", "/", p)
    p = re.sub(r"\{\{\s*([^}]+?)\s*\}\}", r"{\1}", p)
    p = re.sub(r"/:([A-Za-z_][A-Za-z0-9_]*)", r"/{\1}", p)
    p = re.sub(r"/<([A-Za-z_][A-Za-z0-9_:]*)>", lambda m: "/{" + m.group(1).split(":")[-1] + "}", p)
    if len(p) > 1 and p.endswith("/"):
        p = p[:-1]
    return p


def origin_of(url: str) -> str:
    p = urlsplit(url or "")
    if not p.scheme or not p.hostname:
        return ""
    scheme = p.scheme.lower()
    try:
        port = p.port
    except ValueError:
        port = None
    host = p.hostname.lower()
    if port and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
        host = f"{host}:{port}"
    return f"{scheme}://{host}"


@dataclass
class ApiParam:
    name: str
    location: str  # query | path | header | cookie | body
    required: bool = False
    format: str = ""
    type: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ApiOperation:
    method: str
    path: str
    server: str = ""  # origin + base path, "" = relative to the target / API base
    operation_id: str = ""
    params: list[ApiParam] = field(default_factory=list)
    request_content_types: list[str] = field(default_factory=list)
    response_codes: list[str] = field(default_factory=list)
    security: list[str] = field(default_factory=list)  # scheme names only, never values
    tags: list[str] = field(default_factory=list)
    deprecated: bool = False
    source: str = ""  # openapi3 | swagger2 | postman | har
    in_scope: bool = True

    @property
    def key(self) -> tuple[str, str]:
        return (self.method.upper(), self.path)

    @property
    def templated(self) -> bool:
        return bool(_TEMPLATE_RE.search(self.path))

    @property
    def mutating(self) -> bool:
        return self.method.upper() not in SAFE_METHODS and self.method.upper() != "OPTIONS"

    @property
    def replay_safe(self) -> bool:
        """Only GET/HEAD, no path templates, in scope and no state-changing words."""
        if self.method.upper() not in SAFE_METHODS or self.templated or not self.in_scope:
            return False
        from attestra.automated_vapt.core.js_api_discovery import is_unsafe_path

        return not is_unsafe_path(self.path)

    def url_for(self, root: str) -> str:
        base = self.server or root
        if not base.endswith("/"):
            base += "/"
        return urljoin(base, self.path.lstrip("/"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method.upper(),
            "path": self.path,
            "server": self.server,
            "operation_id": self.operation_id,
            "params": [p.to_dict() for p in self.params],
            "request_content_types": list(self.request_content_types),
            "response_codes": list(self.response_codes),
            "security": list(self.security),
            "tags": list(self.tags),
            "deprecated": self.deprecated,
            "source": self.source,
            "in_scope": self.in_scope,
            "templated": self.templated,
            "mutating": self.mutating,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ApiOperation:
        return cls(
            method=str(d.get("method") or "GET").upper(),
            path=str(d.get("path") or "/"),
            server=str(d.get("server") or ""),
            operation_id=str(d.get("operation_id") or ""),
            params=[ApiParam(**{k: p.get(k) for k in ("name", "location", "required", "format", "type") if k in p}) for p in d.get("params") or []],
            request_content_types=list(d.get("request_content_types") or []),
            response_codes=[str(c) for c in d.get("response_codes") or []],
            security=list(d.get("security") or []),
            tags=list(d.get("tags") or []),
            deprecated=bool(d.get("deprecated")),
            source=str(d.get("source") or ""),
            in_scope=bool(d.get("in_scope", True)),
        )


@dataclass
class ApiInventory:
    kind: str
    spec_version: str = ""
    title: str = ""
    servers: list[str] = field(default_factory=list)
    operations: list[ApiOperation] = field(default_factory=list)
    unsupported: list[dict[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    sha256: str = ""
    size_bytes: int = 0
    filename: str = ""
    duplicates_merged: int = 0

    def add_unsupported(self, construct: str, where: str = "", detail: str = "") -> None:
        if len(self.unsupported) < 500:
            self.unsupported.append({"construct": construct, "location": where[:200], "detail": detail[:200]})

    def add_operation(self, op: ApiOperation) -> None:
        if len(self.operations) >= MAX_OPERATIONS:
            if not any(u["construct"] == "operation_limit" for u in self.unsupported):
                self.add_unsupported("operation_limit", "", f"only the first {MAX_OPERATIONS} operations are kept")
            return
        op.method = op.method.upper()
        op.path = normalize_path(op.path)
        self.operations.append(op)

    def dedupe(self) -> None:
        merged: dict[tuple[str, str, str], ApiOperation] = {}
        dup = 0
        for op in self.operations:
            k = (op.method, op.path, op.server)
            cur = merged.get(k)
            if cur is None:
                merged[k] = op
                continue
            dup += 1
            names = {(p.name, p.location) for p in cur.params}
            cur.params += [p for p in op.params if (p.name, p.location) not in names]
            cur.request_content_types = sorted(set(cur.request_content_types) | set(op.request_content_types))
            cur.response_codes = sorted(set(cur.response_codes) | set(op.response_codes))
            cur.security = sorted(set(cur.security) | set(op.security))
        self.operations = list(merged.values())
        self.duplicates_merged += dup

    def apply_scope(self, allowed_origins: list[str]) -> None:
        allowed = {origin_of(o) or o for o in allowed_origins if o}
        for op in self.operations:
            if op.server:
                op.in_scope = origin_of(op.server) in allowed
        bad = sorted({origin_of(op.server) for op in self.operations if not op.in_scope})
        for o in bad:
            self.warnings.append(f"server {o} is outside the target scope; its operations are inventory-only")

    def summary(self) -> dict[str, Any]:
        ops = self.operations
        return {
            "kind": self.kind,
            "spec_version": self.spec_version,
            "title": self.title[:200],
            "operations": len(ops),
            "safe_get_ops": sum(1 for o in ops if o.method in SAFE_METHODS),
            "mutating_ops": sum(1 for o in ops if o.mutating),
            "templated_ops": sum(1 for o in ops if o.templated),
            "out_of_scope_ops": sum(1 for o in ops if not o.in_scope),
            "replay_safe_ops": sum(1 for o in ops if o.replay_safe),
            "unsupported": len(self.unsupported),
            "duplicates_merged": self.duplicates_merged,
            "servers": self.servers[:20],
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }

    def to_doc(self) -> dict[str, Any]:
        return {
            "format_version": INVENTORY_VERSION,
            "kind": self.kind,
            "spec_version": self.spec_version,
            "title": self.title[:200],
            "servers": self.servers[:50],
            "operations": [o.to_dict() for o in self.operations],
            "unsupported": list(self.unsupported),
            "warnings": list(self.warnings)[:100],
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "filename": self.filename,
            "duplicates_merged": self.duplicates_merged,
            "summary": self.summary(),
        }

    @classmethod
    def from_doc(cls, d: dict[str, Any]) -> ApiInventory:
        return cls(
            kind=str(d.get("kind") or ""),
            spec_version=str(d.get("spec_version") or ""),
            title=str(d.get("title") or ""),
            servers=list(d.get("servers") or []),
            operations=[ApiOperation.from_dict(o) for o in d.get("operations") or []],
            unsupported=list(d.get("unsupported") or []),
            warnings=list(d.get("warnings") or []),
            sha256=str(d.get("sha256") or ""),
            size_bytes=int(d.get("size_bytes") or 0),
            filename=str(d.get("filename") or ""),
            duplicates_merged=int(d.get("duplicates_merged") or 0),
        )


def compute_coverage(inventory: ApiInventory | None, tested_urls: list[str], *, root: str = "") -> dict[str, Any]:
    """Spec endpoint coverage for ``result_json.api_coverage`` (rendered by WP3 reports).

    Each operation is ``tested`` (its URL was requested by this run), ``untested``,
    ``excluded_mutating`` (never replayed), ``excluded_templated`` (needs a path value)
    or ``out_of_scope``.
    """
    if inventory is None:
        return {"present": False}
    tested_paths = {(urlsplit(u).path or "/").rstrip("/") or "/" for u in tested_urls or []}
    rows: list[dict[str, Any]] = []
    counts = {"tested": 0, "untested": 0, "excluded_mutating": 0, "excluded_templated": 0, "out_of_scope": 0}
    for op in inventory.operations:
        if not op.in_scope:
            st = "out_of_scope"
        elif op.mutating:
            st = "excluded_mutating"
        elif op.templated:
            st = "excluded_templated"
        else:
            full = urlsplit(op.url_for(root or "https://target.invalid/")).path.rstrip("/") or "/"
            st = "tested" if (full in tested_paths or op.path.rstrip("/") in tested_paths) else "untested"
        counts[st] += 1
        if len(rows) < 500:
            rows.append({"method": op.method, "path": op.path, "status": st})
    total = len(inventory.operations)
    assessable = counts["tested"] + counts["untested"]
    return {
        "present": True,
        "version": INVENTORY_VERSION,
        "sha256": inventory.sha256,
        "kind": inventory.kind,
        "total": total,
        **counts,
        "tested_pct": round(100.0 * counts["tested"] / assessable, 1) if assessable else 0.0,
        "unsupported_constructs": len(inventory.unsupported),
        "operations": rows,
    }
