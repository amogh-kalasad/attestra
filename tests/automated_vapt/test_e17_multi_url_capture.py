"""E17: T01/T02 capture Extra Start URLs and ZAP-discovered pages."""

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


def test_build_capture_urls_merges_safe_inventory_ops_only(monkeypatch):
    """C-04 (WP2): GET/HEAD inventory ops join capture; mutating ops never do."""
    from attestra.automated_vapt.api_inventory.model import ApiInventory, ApiOperation

    monkeypatch.setenv("ATTESTRA_API_IMPORT_ENABLED", "1")
    inv = ApiInventory(kind="openapi3")
    inv.add_operation(ApiOperation(method="GET", path="/api/list"))
    inv.add_operation(ApiOperation(method="POST", path="/api/list"))
    inv.add_operation(ApiOperation(method="GET", path="/api/items/{id}"))
    inv.add_operation(ApiOperation(method="GET", path="/api/logout"))
    info: dict = {}
    urls, source = build_capture_urls(
        session=None, asset=None, target_base_url="https://demo.example/", scope=None, info=info, api_inventory=inv
    )
    assert "https://demo.example/api/list" in urls
    assert source == "root-only+spec"
    assert info["api_inventory"]["excluded_mutating"] == 1
    assert info["api_inventory"]["excluded_templated"] == 1
    assert info["api_inventory"]["excluded_unsafe_words"] == 1
