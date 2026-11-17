"""Page list for automated VAPT HTTP/browser capture (T01/T02).

Same idea as Nuclei's URL list: target base URL, Extra Start URLs, then pages
from the newest finished ZAP scan of that host. Capped so a run stays bounded.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import urljoin, urlsplit

DEFAULT_MAX_URLS = 20


def max_urls() -> int:
    raw = os.environ.get("ATTESTRA_AUTOMATED_VAPT_MAX_URLS", "").strip()
    if raw.isdigit():
        return max(1, min(int(raw), 100))
    return DEFAULT_MAX_URLS


def _normalize_root(url: str) -> str:
    u = (url or "").strip()
    if not u:
        return ""
    p = urlsplit(u if "://" in u else f"https://{u}")
    scheme = (p.scheme or "https").lower()
    host = (p.hostname or "").lower()
    if not host:
        return u
    try:
        port = p.port
    except ValueError:
        port = None
    netloc = host
    if port and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
        netloc = f"{host}:{port}"
    path = p.path or "/"
    return f"{scheme}://{netloc}{path}" + (f"?{p.query}" if p.query else "")


def _pin_for_zap(url: str) -> Any:
    """Duck-typed pin for nuclei_urls.zap_urls_for (needs scheme + host_header only)."""
    p = urlsplit((url or "").strip() if "://" in (url or "") else f"https://{(url or '').strip()}")
    scheme = (p.scheme or "https").lower()
    host = (p.hostname or "").lower()
    try:
        port = p.port
    except ValueError:
        port = None
    if not host:
        raise ValueError("url has no host")
    default = 443 if scheme == "https" else 80
    host_header = host if not port or port == default else f"{host}:{port}"
    return SimpleNamespace(scheme=scheme, host_header=host_header)


def build_capture_urls(
    *,
    session: Any | None,
    asset: Any | None,
    target_base_url: str,
    scope: Any | None = None,
    info: dict[str, Any] | None = None,
    check_dns: bool = True,
) -> tuple[list[str], str]:
    """Return (urls, source_label). Always includes the target base URL first when valid.

    When a ZAP scan is reused, same-origin JS bundles from it are scanned for API calls
    (``js_api_discovery``); capture-safe GET endpoints go right after the base URL and the
    source label gets a ``+js`` suffix. ``info`` (optional dict) receives ``zap_scan_id``,
    ``api_urls`` and a value-free ``js_api`` summary.
    """
    from attestra.automated_vapt.core import js_api_discovery as jsd
    from attestra.runner import nuclei_urls

    if info is None:
        info = {}
    info.setdefault("zap_scan_id", None)
    info.setdefault("api_urls", [])
    info.setdefault("js_api", None)

    root = _normalize_root(target_base_url) or (target_base_url or "").strip()
    if not root:
        return [], "empty"

    seeds: list[str] = []
    if asset is not None:
        seeds = [ln.strip() for ln in (getattr(asset, "crawl_seed_urls", None) or "").splitlines() if ln.strip()]

    zap_lines: list[str] = []
    zap_id: int | None = None
    if session is not None and asset is not None:
        try:
            pin = _pin_for_zap(root)
            zap_lines, zap_id = nuclei_urls.zap_urls_for(session, None, pin, asset)
        except Exception:  # noqa: BLE001 - fall back to seeds/root
            zap_lines, zap_id = [], None

    extras = nuclei_urls.rank(nuclei_urls.filter_urls([*seeds, *zap_lines], root, None))  # same-origin only; CrawlScope != AuthorizedScope
    # Never auto-GET state-changing endpoints (logout, refresh-token, delete, ...).
    extras = [u for u in extras if not jsd.is_unsafe_path(u)]

    api_urls: list[str] = []
    if zap_lines and jsd.enabled():
        try:
            from attestra import config

            cache = Path(config.DATA_DIR) / "raw" / f"scan-{zap_id}" / jsd.CACHE_NAME if zap_id else None
            res = jsd.discover_from_js(zap_lines, root, scope=scope, check_dns=check_dns, cache_path=cache)
            api_urls = [urljoin(root, p) for p in res.safe_get_paths]
            info["js_api"] = {
                **res.summary(),
                "endpoints_list": [e.to_dict() for e in res.endpoints],
            }
        except Exception as exc:  # noqa: BLE001 - discovery is best effort
            info["js_api"] = {"error": type(exc).__name__}

    seen: set[str] = set()
    urls: list[str] = []
    for u in [root, *api_urls, *extras]:
        key = (u or "").rstrip("/") or u
        if not key or key in seen:
            continue
        seen.add(key)
        urls.append(u)
        if len(urls) >= max_urls():
            break

    api_set = {a.rstrip("/") for a in api_urls}
    info["zap_scan_id"] = zap_id
    info["api_urls"] = [u for u in urls if u.rstrip("/") in api_set]
    if zap_id is not None and zap_lines:
        source = f"zap-scan-{zap_id}" + ("+js" if info["api_urls"] else "")
    elif seeds:
        source = "extra-start"
    else:
        source = "root-only"
    return urls, source


def page_label(index: int, url: str) -> str:
    """Short safe label for screenshot filenames (one page per capture)."""
    path = urlsplit(url).path or "/"
    stem = re.sub(r"[^a-zA-Z0-9]+", "_", path.strip("/"))[:40].strip("_") or "root"
    return f"p{index}_{stem}"
