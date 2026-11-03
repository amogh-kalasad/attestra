from pathlib import Path
import shutil
from datetime import datetime

root = Path(r"D:\VAPT attestra\attestra")
orch = root / "attestra" / "automated_vapt" / "core" / "orchestrator.py"
helper = root / "attestra" / "automated_vapt" / "core" / "capture_urls.py"
test_new = root / "tests" / "automated_vapt" / "test_e17_multi_url_capture.py"

tag = "multiurl"
ts = datetime.now().strftime("%Y%m%d_%H%M%S")
bak = orch.with_suffix(orch.suffix + f".bak_{tag}")
if not bak.exists():
    shutil.copy2(orch, bak)
    print("backed up", bak.name)
else:
    print("backup exists", bak.name)

helper.write_text(r'''"""Page list for automated VAPT HTTP/browser capture (T01/T02).

Same idea as Nuclei's URL list: target base URL, Extra Start URLs, then pages
from the newest finished ZAP scan of that host. Capped so a run stays bounded.
"""

from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import urlsplit

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


def build_capture_urls(
    *,
    session: Any | None,
    asset: Any | None,
    target_base_url: str,
    scope: Any | None = None,
) -> tuple[list[str], str]:
    """Return (urls, source_label). Always includes the target base URL first when valid."""
    from attestra.runner import nuclei_urls

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
            zap_lines, zap_id = nuclei_urls.zap_urls_for(session, None, root, asset)
        except Exception:  # noqa: BLE001 - fall back to seeds/root
            zap_lines, zap_id = [], None

    extras = nuclei_urls.rank(nuclei_urls.filter_urls([*seeds, *zap_lines], root, scope))
    seen: set[str] = set()
    urls: list[str] = []
    for u in [root, *extras]:
        key = (u or "").rstrip("/") or u
        if not key or key in seen:
            continue
        seen.add(key)
        urls.append(u)
        if len(urls) >= max_urls():
            break

    if zap_id is not None and zap_lines:
        source = f"zap-scan-{zap_id}"
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
''', encoding="utf-8")
print("wrote", helper)

text = orch.read_text(encoding="utf-8")

# Inject session+asset URL list into run_execution after execution_id setdefault
needle = '        # Real run id so screenshot names and the evidence folder match this row.\n        ctx.extra.setdefault("execution_id", ex.id)\n'
insert = needle + '''        # Same page list Nuclei uses: base URL + Extra Start URLs + latest ZAP pages.
        from attestra.automated_vapt.core.capture_urls import build_capture_urls

        capture_urls, capture_source = build_capture_urls(
            session=s,
            asset=asset,
            target_base_url=ex.target_base_url,
            scope=scope,
        )
        ctx.extra["_capture_urls"] = capture_urls or [ex.target_base_url]
        ctx.extra["_capture_url_source"] = capture_source
'''
if 'build_capture_urls' not in text:
    if needle not in text:
        raise SystemExit("needle for run_execution not found")
    text = text.replace(needle, insert, 1)
    print("patched run_execution")
else:
    print("run_execution already patched")

old_t01 = '''def _run_t01_http_capture(ctx: TestContext, category: str) -> dict[str, Any]:
    """T01: capture one GET against the approved target base URL."""
    from attestra.automated_vapt.capture.http_capture import capture_request
    from attestra.automated_vapt.capture.request_parser import parse_request
    from attestra.automated_vapt.capture.response_parser import parse_response

    seeds = []
    scope = scope_validator.build_scope_from_asset(
        ctx.target_base_url,
        extra_seeds=seeds,
        allow_private=ctx.allow_private,
    )
    client = ctx.extra.get("httpx_client")
    try:
        tx = capture_request(
            "GET",
            ctx.target_base_url,
            scope=scope,
            profile=ctx.profile,
            client=client,
            check_dns=not ctx.allow_private,
        )
    except Exception as exc:  # noqa: BLE001 — surface capture failures in case result
        return {
            "test_id": "T01",
            "status": "FAILED",
            "detail": f"HTTP capture failed: {exc}",
            "category": category,
        }
    report = tx.report_pair or tx.pair.redacted()
    ctx.extra.setdefault("_http_pairs", []).append(report)
    req_n = parse_request(report)
    resp_n = parse_response(report)
    return {
        "test_id": "T01",
        "status": "PASSED",
        "detail": "HTTP transaction captured",
        "category": category,
        "capture": tx.to_dict(),
        "request_normalized": {k: v for k, v in req_n.items() if k != "original"},
        "response_normalized": resp_n,
    }
'''

# Allow either em-dash or ASCII dash in comment
import re as _re
pat_t01 = _re.compile(
    r'def _run_t01_http_capture\(ctx: TestContext, category: str\) -> dict\[str, Any\]:.*?(?=\ndef _run_t02_browser_capture)',
    _re.S,
)
new_t01 = '''def _run_t01_http_capture(ctx: TestContext, category: str) -> dict[str, Any]:
    """T01: capture GET against each approved page (base + Extra Start + ZAP URLs)."""
    from attestra.automated_vapt.capture.http_capture import capture_request
    from attestra.automated_vapt.capture.request_parser import parse_request
    from attestra.automated_vapt.capture.response_parser import parse_response

    urls = list(ctx.extra.get("_capture_urls") or [ctx.target_base_url])
    source = str(ctx.extra.get("_capture_url_source") or "root-only")
    seeds = [u for u in urls[1:] if u]
    scope = scope_validator.build_scope_from_asset(
        ctx.target_base_url,
        extra_seeds=seeds,
        allow_private=ctx.allow_private,
    )
    client = ctx.extra.get("httpx_client")
    pages: list[dict[str, Any]] = []
    last_tx = None
    last_req: dict[str, Any] = {}
    last_resp: dict[str, Any] = {}
    for url in urls:
        try:
            tx = capture_request(
                "GET",
                url,
                scope=scope,
                profile=ctx.profile,
                client=client,
                check_dns=not ctx.allow_private,
            )
        except Exception as exc:  # noqa: BLE001 — surface capture failures in case result
            pages.append({"url": url, "status": "FAILED", "detail": str(exc)})
            continue
        report = tx.report_pair or tx.pair.redacted()
        ctx.extra.setdefault("_http_pairs", []).append(report)
        req_n = parse_request(report)
        resp_n = parse_response(report)
        last_tx, last_req, last_resp = tx, req_n, resp_n
        pages.append({"url": url, "status": "PASSED", "detail": "HTTP transaction captured"})
    ok = [p for p in pages if p["status"] == "PASSED"]
    if not ok:
        first = pages[0]["detail"] if pages else "no URLs"
        return {
            "test_id": "T01",
            "status": "FAILED",
            "detail": f"HTTP capture failed on {len(pages)} page(s) ({source}): {first}",
            "category": category,
            "pages": pages,
            "url_source": source,
        }
    out: dict[str, Any] = {
        "test_id": "T01",
        "status": "PASSED" if len(ok) == len(pages) else "PASSED",
        "detail": f"HTTP captured for {len(ok)}/{len(pages)} page(s) ({source})",
        "category": category,
        "pages": pages,
        "url_source": source,
    }
    if last_tx is not None:
        out["capture"] = last_tx.to_dict()
        out["request_normalized"] = {k: v for k, v in last_req.items() if k != "original"}
        out["response_normalized"] = last_resp
    return out


'''
m = pat_t01.search(text)
if not m:
    raise SystemExit("T01 function not found")
text = text[: m.start()] + new_t01 + text[m.end() :]
print("replaced T01")

pat_t02 = _re.compile(
    r'def _run_t02_browser_capture\(ctx: TestContext, category: str\) -> dict\[str, Any\]:.*?(?=\ndef _run_authz_module)',
    _re.S,
)
new_t02 = '''def _run_t02_browser_capture(ctx: TestContext, category: str) -> dict[str, Any]:
    """T02: browser screenshot of each approved page (base + Extra Start + ZAP URLs)."""
    from attestra.automated_vapt.capture.browser_capture import (
        capture_screenshot,
        stable_screenshot_name,
    )
    from attestra.automated_vapt.core.capture_urls import page_label

    urls = list(ctx.extra.get("_capture_urls") or [ctx.target_base_url])
    source = str(ctx.extra.get("_capture_url_source") or "root-only")
    seeds = [u for u in urls[1:] if u]
    scope = scope_validator.build_scope_from_asset(
        ctx.target_base_url,
        extra_seeds=seeds,
        allow_private=ctx.allow_private,
    )
    capture_fn = ctx.extra.get("browser_capture_fn")
    pages: list[dict[str, Any]] = []
    last_shot: dict[str, Any] | None = None
    for i, url in enumerate(urls, 1):
        try:
            result = capture_screenshot(
                url,
                scope=scope,
                allow_private=ctx.allow_private,
                capture_fn=capture_fn,
                check_dns=not ctx.allow_private,
                username=ctx.extra.get("browser_username"),
                password=ctx.extra.get("browser_password"),
                login_url=ctx.extra.get("browser_login_url"),
            )
        except Exception as exc:  # noqa: BLE001
            pages.append({"url": url, "status": "FAILED", "detail": str(exc)})
            continue
        name = stable_screenshot_name(
            engagement_id=ctx.engagement_id,
            execution_id=int(ctx.extra.get("execution_id") or 0),
            test_case_id="T02",
            label=page_label(i, url),
        )
        ctx.extra.setdefault("_screenshots", {})[name] = result.screenshot_png
        meta = {**result.to_dict(), "filename": name, "url": url}
        pages.append({"url": url, "status": "PASSED", "detail": "browser screenshot captured", "screenshot": meta})
        last_shot = meta
    ok = [p for p in pages if p["status"] == "PASSED"]
    if not ok:
        first = pages[0]["detail"] if pages else "no URLs"
        return {
            "test_id": "T02",
            "status": "FAILED",
            "detail": f"browser capture failed on {len(pages)} page(s) ({source}): {first}",
            "category": category,
            "pages": pages,
            "url_source": source,
        }
    out: dict[str, Any] = {
        "test_id": "T02",
        "status": "PASSED",
        "detail": f"browser screenshots for {len(ok)}/{len(pages)} page(s) ({source})",
        "category": category,
        "pages": pages,
        "url_source": source,
    }
    if last_shot is not None:
        out["screenshot"] = last_shot
    return out


'''
m2 = pat_t02.search(text)
if not m2:
    raise SystemExit("T02 function not found")
text = text[: m2.start()] + new_t02 + text[m2.end() :]
print("replaced T02")

orch.write_text(text, encoding="utf-8")
print("wrote orchestrator")

test_new.write_text(r'''"""E17: T01/T02 capture Extra Start URLs and ZAP-discovered pages."""

from __future__ import annotations

from attestra.automated_vapt.core.capture_urls import build_capture_urls, max_urls, page_label


def test_page_label_stable():
    assert page_label(1, "https://demo.example/").startswith("p1_")
    assert "projects" in page_label(2, "https://demo.example/projects")


def test_build_capture_urls_root_and_seeds():
    class _Asset:
        crawl_seed_urls = "https://demo.example/projects\nhttps://demo.example/login"
        id = 1
        identifier = "https://demo.example/"

    urls, source = build_capture_urls(
        session=None,
        asset=_Asset(),
        target_base_url="https://demo.example/",
        scope=None,
    )
    assert urls[0].rstrip("/") == "https://demo.example"
    assert any(u.rstrip("/").endswith("/projects") for u in urls)
    assert source == "extra-start"
    assert len(urls) <= max_urls()


def test_build_capture_urls_respects_cap(monkeypatch):
    monkeypatch.setenv("ATTESTRA_AUTOMATED_VAPT_MAX_URLS", "2")

    class _Asset:
        crawl_seed_urls = "\n".join(f"https://demo.example/p{i}" for i in range(10))
        id = 1
        identifier = "https://demo.example/"

    urls, _ = build_capture_urls(
        session=None,
        asset=_Asset(),
        target_base_url="https://demo.example/",
        scope=None,
    )
    assert len(urls) == 2
''', encoding="utf-8")
print("wrote test", test_new.name)
print("done")