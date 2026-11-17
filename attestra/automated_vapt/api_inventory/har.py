"""C-03: HAR 1.2 importer. Keeps methods, paths, parameter *names* and content types only.

Header, cookie, query and body *values* are never stored (a HAR export usually carries
live session tokens). Only the presence of ``Authorization`` / ``Cookie`` headers is
recorded as the security scheme name.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qsl, urlsplit

from attestra.automated_vapt.api_inventory.model import ApiInventory, ApiOperation, ApiParam, SpecError, origin_of

# @lat: [[web-api-probes#API inventory import]]

_SKIP_MIME = ("image/", "font/", "text/css", "javascript", "video/", "audio/")


def parse_har(doc: dict[str, Any]) -> ApiInventory:
    log = doc.get("log")
    if not isinstance(log, dict) or not isinstance(log.get("entries"), list):
        raise SpecError("HAR file has no log.entries list")
    ver = str(log.get("version") or "")
    if ver and not ver.startswith("1."):
        raise SpecError(f"unsupported HAR version {ver[:10]!r} (1.2 expected)")
    inv = ApiInventory(kind="har", spec_version=ver or "1.2", title=str((log.get("creator") or {}).get("name") or "HAR")[:200])
    servers: set[str] = set()
    skipped_static = 0
    for idx, e in enumerate(log["entries"]):
        req = (e or {}).get("request") if isinstance(e, dict) else None
        if not isinstance(req, dict) or not req.get("url"):
            inv.add_unsupported("entry_without_request", f"entries[{idx}]")
            continue
        url = str(req["url"])
        p = urlsplit(url)
        if p.scheme not in ("http", "https"):
            inv.add_unsupported("non_http_entry", f"entries[{idx}]", p.scheme[:20])
            continue
        mime = str((((e.get("response") or {}).get("content") or {}).get("mimeType")) or "").lower()
        if any(s in mime for s in _SKIP_MIME):
            skipped_static += 1
            continue
        server = origin_of(url)
        servers.add(server)
        params = [ApiParam(name=k[:100], location="query") for k, _ in parse_qsl(p.query, keep_blank_values=True)]
        post = req.get("postData") or {}
        cts = [str(post.get("mimeType")).split(";")[0].strip()] if isinstance(post, dict) and post.get("mimeType") else []
        names = {str(h.get("name") or "").lower() for h in req.get("headers") or [] if isinstance(h, dict)}
        security = [n for n in ("authorization", "cookie") if n in names]
        status = (e.get("response") or {}).get("status")
        inv.add_operation(
            ApiOperation(
                method=str(req.get("method") or "GET").upper(),
                path=p.path or "/",
                server=server,
                params=params,
                request_content_types=cts,
                response_codes=[str(status)] if status else [],
                security=security,
                source="har",
            )
        )
    if skipped_static:
        inv.warnings.append(f"{skipped_static} static asset entries skipped")
    if e_ws := [i for i, en in enumerate(log["entries"]) if isinstance(en, dict) and en.get("_webSocketMessages")]:
        inv.add_unsupported("websocket_messages", "entries", f"{len(e_ws)} websocket entries not imported")
    inv.servers = sorted(servers)
    return inv
