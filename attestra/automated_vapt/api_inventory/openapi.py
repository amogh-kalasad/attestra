"""C-01: OpenAPI 3.x and Swagger 2.0 importer (validation + normalisation, no network)."""

from __future__ import annotations

import re
from typing import Any

from attestra.automated_vapt.api_inventory.model import ApiInventory, ApiOperation, ApiParam, SpecError

# @lat: [[web-api-probes#API inventory import]]

_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
_SUPPORTED_OAS = re.compile(r"^3\.(0|1)\.\d+$")


def _resolve(doc: dict[str, Any], node: Any, inv: ApiInventory, where: str, depth: int = 0) -> Any:
    """Resolve local ``#/...`` refs (bounded). External refs are reported as unsupported."""
    if not isinstance(node, dict) or "$ref" not in node:
        return node
    ref = str(node.get("$ref") or "")
    if not ref.startswith("#/"):
        inv.add_unsupported("external_ref", where, ref[:120])
        return {}
    if depth > 10:
        inv.add_unsupported("ref_depth", where, ref[:120])
        return {}
    cur: Any = doc
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(cur, dict) or part not in cur:
            inv.add_unsupported("unresolved_ref", where, ref[:120])
            return {}
        cur = cur[part]
    return _resolve(doc, cur, inv, where, depth + 1)


def _param(doc: dict[str, Any], raw: Any, inv: ApiInventory, where: str) -> ApiParam | None:
    p = _resolve(doc, raw, inv, where)
    if not isinstance(p, dict) or not p.get("name"):
        return None
    loc = str(p.get("in") or "query")
    schema = _resolve(doc, p.get("schema") or {}, inv, where) if isinstance(p.get("schema"), dict) else {}
    fmt = str(p.get("format") or (schema or {}).get("format") or "")
    typ = str(p.get("type") or (schema or {}).get("type") or "")
    if loc == "formData":
        loc = "body"
    return ApiParam(name=str(p["name"])[:100], location=loc, required=bool(p.get("required")), format=fmt, type=typ)


def _servers_oas3(doc: dict[str, Any], inv: ApiInventory, where: str, servers: Any) -> list[str]:
    out: list[str] = []
    for s in servers or []:
        if not isinstance(s, dict) or not s.get("url"):
            continue
        url = str(s["url"])
        for name, var in (s.get("variables") or {}).items():
            default = (var or {}).get("default") if isinstance(var, dict) else None
            if default is None:
                inv.add_unsupported("server_variable_without_default", where, name)
                continue
            url = url.replace("{" + name + "}", str(default))
        if "{" in url:
            inv.add_unsupported("unresolved_server_variable", where, url[:120])
            continue
        out.append(url.rstrip("/"))
    return out


def parse_openapi(doc: dict[str, Any]) -> ApiInventory:
    if "openapi" in doc:
        ver = str(doc.get("openapi") or "")
        kind = "openapi3"
        if not _SUPPORTED_OAS.match(ver):
            raise SpecError(f"unsupported OpenAPI version {ver[:20]!r} (3.0.x / 3.1.x only)")
    else:
        ver = str(doc.get("swagger") or "")
        kind = "swagger2"
        if ver != "2.0":
            raise SpecError("unsupported Swagger version (2.0 only)")
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        if kind == "openapi3" and isinstance(doc.get("webhooks"), dict):
            paths = {}
        else:
            raise SpecError("spec has no 'paths' object")
    info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
    if not info.get("title"):
        raise SpecError("spec 'info.title' is required")
    inv = ApiInventory(kind=kind, spec_version=ver, title=str(info.get("title"))[:200])

    if kind == "openapi3":
        servers = _servers_oas3(doc, inv, "servers", doc.get("servers"))
        if isinstance(doc.get("webhooks"), dict) and doc["webhooks"]:
            inv.add_unsupported("webhooks", "webhooks", f"{len(doc['webhooks'])} webhook(s) not imported")
    else:
        host = str(doc.get("host") or "")
        base = str(doc.get("basePath") or "").rstrip("/")
        schemes = [s for s in (doc.get("schemes") or ["https"]) if s in ("http", "https")] or ["https"]
        servers = [f"{schemes[0]}://{host}{base}"] if host else ([base] if base else [])
    inv.servers = servers
    default_server = servers[0] if servers and "://" in servers[0] else ""
    base_prefix = servers[0] if servers and "://" not in servers[0] else ""
    global_security = [list(s.keys())[0] for s in (doc.get("security") or []) if isinstance(s, dict) and s]
    global_consumes = list(doc.get("consumes") or []) if kind == "swagger2" else []

    for raw_path, item in paths.items():
        where = f"paths.{raw_path}"
        item = _resolve(doc, item, inv, where)
        if not isinstance(item, dict):
            inv.add_unsupported("invalid_path_item", where)
            continue
        path_params = [p for p in (_param(doc, r, inv, where) for r in item.get("parameters") or []) if p]
        item_servers = _servers_oas3(doc, inv, where, item.get("servers")) if kind == "openapi3" else []
        for key in item:
            if key in _METHODS or key in ("parameters", "servers", "summary", "description", "$ref") or key.startswith("x-"):
                continue
            inv.add_unsupported("unknown_path_item_field", where, key)
        for m in _METHODS:
            op = item.get(m)
            if not isinstance(op, dict):
                continue
            ow = f"{where}.{m}"
            params = list(path_params)
            names = {(p.name, p.location) for p in params}
            for r in op.get("parameters") or []:
                p = _param(doc, r, inv, ow)
                if p and (p.name, p.location) not in names:
                    params = [q for q in params if (q.name, q.location) != (p.name, p.location)] + [p]
            cts: list[str] = []
            if kind == "openapi3":
                rb = _resolve(doc, op.get("requestBody") or {}, inv, ow)
                if isinstance(rb, dict):
                    cts = [str(c) for c in (rb.get("content") or {}).keys()]
                if op.get("callbacks"):
                    inv.add_unsupported("callbacks", ow, "callback operations not imported")
                for code, resp in (op.get("responses") or {}).items():
                    resp = _resolve(doc, resp, inv, ow) if isinstance(resp, dict) else resp
                    if isinstance(resp, dict) and resp.get("links"):
                        inv.add_unsupported("links", f"{ow}.responses.{code}", "response links not followed")
                op_servers = _servers_oas3(doc, inv, ow, op.get("servers"))
            else:
                cts = list(op.get("consumes") or global_consumes)
                if any(p.location == "body" for p in params) and not cts:
                    cts = ["application/json"]
                op_servers = []
            server = (op_servers or item_servers or [default_server])[0] if (op_servers or item_servers or default_server) else ""
            security = op.get("security")
            sec_names = [list(s.keys())[0] for s in security if isinstance(s, dict) and s] if isinstance(security, list) else global_security
            path = f"{base_prefix}{raw_path}" if base_prefix else raw_path
            inv.add_operation(
                ApiOperation(
                    method=m.upper(),
                    path=str(path),
                    server=server if "://" in server else "",
                    operation_id=str(op.get("operationId") or "")[:120],
                    params=params,
                    request_content_types=cts,
                    response_codes=[str(c) for c in (op.get("responses") or {}).keys()],
                    security=sec_names,
                    tags=[str(t) for t in (op.get("tags") or [])][:10],
                    deprecated=bool(op.get("deprecated")),
                    source=kind,
                )
            )
    if not inv.operations and not inv.unsupported:
        inv.warnings.append("spec defines no operations")
    return inv
