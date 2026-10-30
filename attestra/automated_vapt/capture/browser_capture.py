"""Playwright-based browser workflow capture for Elite automated testing.

Reuses auth-web Playwright availability checks and proof screenshot DOM prep.
Secrets must be injected by the caller; never hardcode passwords or OTPs.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin

from attestra.auth_web.crawl import playwright_available
from attestra.auth_web.scope import CrawlScope
from attestra.automated_vapt.core import scope_validator
from attestra.proof.screenshot_redact import prepare_page_for_capture
from attestra.services import ServiceError

# @lat: [[architecture#Elite automated security testing#Browser capture]]

CaptureFn = Callable[[str], bytes]  # url -> PNG bytes
_PNG_SIG = b"\x89PNG\r\n\x1a\n"


@dataclass
class BrowserCaptureResult:
    url: str
    screenshot_png: bytes
    full_page: bool
    captured_at: str
    network_events: list[dict[str, Any]] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "full_page": self.full_page,
            "captured_at": self.captured_at,
            "png_bytes": len(self.screenshot_png),
            "png_magic_ok": self.screenshot_png.startswith(_PNG_SIG),
            "network_events": list(self.network_events),
            "notes": self.notes,
        }


def capture_screenshot(
    url: str,
    *,
    scope: CrawlScope | None = None,
    allow_private: bool = False,
    full_page: bool = True,
    username: str | None = None,
    password: str | None = None,
    login_url: str | None = None,
    sensitive_selectors: Sequence[str] | None = None,
    capture_fn: CaptureFn | None = None,
    check_dns: bool = True,
) -> BrowserCaptureResult:
    """Open an approved URL, optionally log in, and capture a screenshot.

    When ``capture_fn`` is provided (tests), Playwright is not required.
    """
    absolute = (url or "").strip()
    if not absolute:
        raise ServiceError("browser capture requires a URL")
    if scope is not None:
        scope_validator.validate_target_url(absolute, scope, check_dns=check_dns)
    captured_at = datetime.now(UTC).isoformat()

    if capture_fn is not None:
        png = capture_fn(absolute)
        if not png.startswith(_PNG_SIG):
            raise ServiceError("capture_fn did not return a PNG")
        return BrowserCaptureResult(
            url=absolute,
            screenshot_png=png,
            full_page=full_page,
            captured_at=captured_at,
            notes="injected capture_fn",
        )

    if not playwright_available():
        raise ServiceError("Playwright is not installed; cannot capture browser screenshots")

    return _playwright_capture(
        absolute,
        scope=scope,
        full_page=full_page,
        username=username,
        password=password,
        login_url=login_url,
        sensitive_selectors=list(sensitive_selectors or []),
        captured_at=captured_at,
        check_dns=check_dns,
        allow_private=allow_private,
    )


def _playwright_capture(
    url: str,
    *,
    scope: CrawlScope | None,
    full_page: bool,
    username: str | None,
    password: str | None,
    login_url: str | None,
    sensitive_selectors: list[str],
    captured_at: str,
    check_dns: bool,
    allow_private: bool,
) -> BrowserCaptureResult:
    from playwright.sync_api import sync_playwright

    network: list[dict[str, Any]] = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            page.on(
                "request",
                lambda req: network.append(
                    {"type": "request", "method": req.method, "url": req.url[:500]}
                ),
            )
            page.on(
                "response",
                lambda res: network.append(
                    {"type": "response", "status": res.status, "url": res.url[:500]}
                ),
            )
            if username and password and login_url:
                if scope is not None:
                    scope_validator.validate_target_url(login_url, scope, check_dns=check_dns)
                page.goto(login_url, wait_until="domcontentloaded", timeout=20000)
                page.fill('input[name="username"], input[type="text"]', username)
                page.fill('input[name="password"], input[type="password"]', password)
                page.click('button[type="submit"], input[type="submit"]')
                page.wait_for_load_state("domcontentloaded")
                # Refuse navigation that left scope.
                if scope is not None:
                    scope_validator.validate_target_url(page.url, scope, check_dns=check_dns)
            page.goto(url, wait_until="domcontentloaded", timeout=20000)
            if scope is not None:
                scope_validator.validate_target_url(page.url, scope, check_dns=check_dns)
            page.evaluate(prepare_page_for_capture(sensitive_selectors))
            png = page.screenshot(full_page=full_page, type="png")
        finally:
            browser.close()

    if not png.startswith(_PNG_SIG):
        raise ServiceError("Playwright screenshot was not a PNG")
    # Drop any accidental secret echo from network event URLs (userinfo).
    cleaned = []
    for ev in network[:50]:
        u = str(ev.get("url") or "")
        if "://" in u and "@" in u.split("://", 1)[1].split("/", 1)[0]:
            ev = {**ev, "url": "[REDACTED_USERINFO_URL]"}
        cleaned.append(ev)
    return BrowserCaptureResult(
        url=url,
        screenshot_png=png,
        full_page=full_page,
        captured_at=captured_at,
        network_events=cleaned,
        notes="playwright",
    )


def stable_screenshot_name(
    *,
    engagement_id: int,
    execution_id: int,
    test_case_id: str,
    label: str = "viewport",
) -> str:
    """Stable filename association for Elite evidence storage."""
    safe_case = "".join(c if c.isalnum() or c in "-_" else "_" for c in test_case_id.upper())
    safe_label = "".join(c if c.isalnum() or c in "-_" else "_" for c in label.lower()) or "shot"
    return f"e{engagement_id}_x{execution_id}_{safe_case}_{safe_label}.png"


def resolve_login_url(base: str, login_path: str = "/login") -> str:
    return urljoin(base if base.endswith("/") else base + "/", login_path.lstrip("/"))
