"""Playwright-backed capture_fn for classic finding auto-screenshots.

Registers with [[attestra.proof.screenshots.register_screenshot_capture]] when
``ATTESTRA_AUTO_SCREENSHOT`` is on. Reuses Elite
[[attestra.automated_vapt.capture.browser_capture.capture_screenshot]]; never
fabricates PNG bytes.
"""
# @lat: [[architecture#Authenticated website testing]]

from __future__ import annotations

import logging
from collections.abc import Callable

log = logging.getLogger(__name__)

CaptureFn = Callable[[str], bytes | None]


def playwright_ready() -> bool:
    """True when Playwright sync API can be imported (browser install is separate)."""
    try:
        from attestra.auth_web.crawl import playwright_available

        return bool(playwright_available())
    except Exception:  # noqa: BLE001
        return False


def make_playwright_capture_fn(*, full_page: bool = True, allow_private: bool = False) -> CaptureFn:
    """Return ``url -> PNG bytes | None`` using real browser capture.

    Returns ``None`` on any failure so callers can record ``capture_failure``
    without aborting the security finding.
    """

    def _capture(url: str) -> bytes | None:
        raw = (url or "").strip()
        if not raw:
            return None
        try:
            from attestra.automated_vapt.capture.browser_capture import capture_screenshot
            from attestra.services import ServiceError

            result = capture_screenshot(
                raw,
                full_page=full_page,
                allow_private=allow_private,
                check_dns=not allow_private,
            )
            png = getattr(result, "screenshot_png", None) or b""
            if not png.startswith(b"\x89PNG\r\n\x1a\n"):
                return None
            return png
        except ServiceError as exc:
            log.info("auto-screenshot skipped for %s: %s", raw[:120], exc)
            return None
        except Exception:  # noqa: BLE001 — never fail imports / findings
            log.exception("auto-screenshot capture failed for %s", raw[:120])
            return None

    return _capture


def try_register_auto_screenshot() -> bool:
    """Register Playwright capture_fn when env is on and Playwright is available.

    Returns True when a capture_fn was registered. Safe to call multiple times.
    """
    from attestra import config
    from attestra.proof.screenshots import register_screenshot_capture

    if not getattr(config, "AUTO_SCREENSHOT_ENABLED", False):
        return False
    if not playwright_ready():
        log.warning(
            "ATTESTRA_AUTO_SCREENSHOT is on but Playwright is not available; "
            "classic findings will not get automatic screenshots"
        )
        return False
    allow_private = bool(getattr(config, "AUTO_SCREENSHOT_ALLOW_PRIVATE", False))
    register_screenshot_capture(make_playwright_capture_fn(full_page=True, allow_private=allow_private))
    log.info("registered Playwright auto-screenshot capture_fn (allow_private=%s)", allow_private)
    return True
