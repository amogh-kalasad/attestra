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
