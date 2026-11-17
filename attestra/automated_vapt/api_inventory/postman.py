"""C-02: Postman Collection v2.1 importer (no scripts executed, no requests sent)."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from attestra.automated_vapt.api_inventory.model import ApiInventory, ApiOperation, ApiParam, SpecError, origin_of

# @lat: [[web-api-probes#API inventory import]]

_VAR_RE = re.compile(r"\{\{\s*([^}]+?)\s*\}\}")
MAX_DEPTH = 12


def _vars(doc: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for v in doc.get("variable") or []:
        if isinstance(v, dict) and v.get("key") and isinstance(v.get("value"), (str, int, float)):
            out[str(v["key"])] = str(v["value"])
    return out


def _subst(text: str, variables: dict[str, str]) -> str:
    return _VAR_RE.sub(lambda m: variables.get(m.group(1), m.group(0)), text or "")


def _url_parts(url: Any, variables: dict[str, str]) -> tuple[str, str, list[str]]:
    """Return (server origin or "", path, query keys) from a Postman URL (string or object)."""
    if isinstance(url, dict):
        raw = str(url.get("raw") or "")
        if not raw:
            host = url.get("host") or []
            host_s = ".".join(host) if isinstance(host, list) else str(host)
            path = url.get("path") or []
            path_s = "/" + "/".join(str(p) for p in path) if isinstance(path, list) else str(path)
            proto = str(url.get("protocol") or "https")
            raw = f"{proto}://{host_s}{path_s}"
        keys = [str(q.get("key")) for q in (url.get("query") or []) if isinstance(q, dict) and q.get("key")]
    else:
        raw = str(url or "")
        keys = []
    raw = _subst(raw, variables)
    q = raw.split("?", 1)[1] if "?" in raw else ""
    if not keys and q:
        keys = [kv.split("=", 1)[0] for kv in q.split("&") if kv]
    base = raw.split("?", 1)[0]
    server = ""
    if base.startswith("{{"):
        # Unresolved {{baseUrl}} prefix: keep only the path part.
        base = _VAR_RE.sub("", base, count=1)
    if "://" in base:
        sp = urlsplit(base)
        if not _VAR_RE.search(sp.netloc):
            server = origin_of(base)
        path = sp.path or "/"
    else:
        path = base if base.startswith("/") else "/" + base
    return server, path, keys


def parse_postman(doc: dict[str, Any]) -> ApiInventory:
    info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
    schema = str(info.get("schema") or "")
    if "v2.1" not in schema and "v2.0" not in schema:
        raise SpecError("unsupported Postman collection schema (v2.1 expected)")
    if not isinstance(doc.get("item"), list):
        raise SpecError("Postman collection has no 'item' list")
    inv = ApiInventory(kind="postman", spec_version="2.1" if "v2.1" in schema else "2.0", title=str(info.get("name") or "")[:200])
    if "v2.0" in schema:
        inv.warnings.append("Postman v2.0 collection parsed with the v2.1 rules")
    variables = _vars(doc)
    if doc.get("event"):
        inv.add_unsupported("collection_scripts", "event", "pre-request/test scripts are never executed")
    servers: set[str] = set()

    def walk(items: list[Any], where: str, depth: int, folder_auth: str) -> None:
        if depth > MAX_DEPTH:
            inv.add_unsupported("folder_depth", where)
            return
        for idx, it in enumerate(items):
            if not isinstance(it, dict):
                continue
            w = f"{where}[{idx}]"
            auth = str(((it.get("auth") or {}).get("type")) or folder_auth)
            if it.get("event"):
                inv.add_unsupported("item_scripts", w, "scripts not executed")
            if isinstance(it.get("item"), list):
                walk(it["item"], f"{w}.item", depth + 1, auth)
                continue
            req = it.get("request")
            if req is None:
                inv.add_unsupported("item_without_request", w)
                continue
            if isinstance(req, str):
                req = {"method": "GET", "url": req}
            method = str(req.get("method") or "GET").upper()
            server, path, qkeys = _url_parts(req.get("url"), variables)
            if _VAR_RE.search(path):
                inv.add_unsupported("unresolved_variable", w, "path variable kept as template")
            if server:
                servers.add(server)
            body = req.get("body") or {}
            cts: list[str] = []
            mode = str(body.get("mode") or "") if isinstance(body, dict) else ""
            if mode == "raw":
                lang = str(((body.get("options") or {}).get("raw") or {}).get("language") or "text")
                cts = [{"json": "application/json", "xml": "application/xml"}.get(lang, "text/plain")]
            elif mode == "urlencoded":
                cts = ["application/x-www-form-urlencoded"]
            elif mode == "formdata":
                cts = ["multipart/form-data"]
            elif mode == "graphql":
                cts = ["application/json"]
            elif mode == "file":
                inv.add_unsupported("binary_file_body", w)
            for h in req.get("header") or []:
                if isinstance(h, dict) and str(h.get("key") or "").lower() == "content-type" and h.get("value"):
                    cts = [str(h["value"]).split(";")[0].strip()]
            params = [ApiParam(name=k[:100], location="query") for k in qkeys]
            inv.add_operation(
                ApiOperation(
                    method=method,
                    path=path,
                    server=server,
                    operation_id=str(it.get("name") or "")[:120],
                    params=params,
                    request_content_types=cts,
                    security=[auth] if auth and auth != "noauth" else [],
                    tags=["graphql"] if mode == "graphql" else [],
                    source="postman",
                )
            )

    walk(doc["item"], "item", 0, str(((doc.get("auth") or {}).get("type")) or ""))
    inv.servers = sorted(servers)
    return inv
