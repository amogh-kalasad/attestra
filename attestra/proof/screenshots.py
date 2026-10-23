"""Automatic screenshot evidence for findings with http(s) locations.

Orchestrates capture (injected or registered ``capture_fn``) then stores via
[[attestra.proof.screenshot_redact.attach_redacted_screenshot]]. Default
registry is empty so imports stay network-free. Browser-based ``capture_fn``
implementations should evaluate [[dom_prep_js]] (password selectors) before
taking the PNG.
"""
# @lat: [[architecture#Authenticated website testing]]

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from sqlalchemy import select

from attestra.models import Evidence
from attestra.proof.screenshot_redact import attach_redacted_screenshot, prepare_page_for_capture

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from attestra.models import Finding

log = logging.getLogger(__name__)

CaptureFn = Callable[[str], bytes | None]

_registered_capture: CaptureFn | None = None

# Default selectors for DOM masking when a browser capture_fn uses [[dom_prep_js]].
PASSWORD_SELECTORS = [
    "input[type=password]",
    "input[name*=password i]",
    "input[name*=secret i]",
    "input[name*=token i]",
    "input[autocomplete=current-password]",
    "input[autocomplete=new-password]",
]


def register_screenshot_capture(fn: CaptureFn | None) -> None:
    """Register the process-wide auto-capture callable (``url -> png bytes``)."""
    global _registered_capture
    _registered_capture = fn


def clear_screenshot_capture() -> None:
    """Clear the process-wide auto-capture callable (tests use this in teardown)."""
    global _registered_capture
    _registered_capture = None


def registered_screenshot_capture() -> CaptureFn | None:
    """Return the currently registered capture callable, if any."""
    return _registered_capture


def dom_prep_js(sensitive_selectors: list[str] | None = None) -> str:
    """JS snippet that masks password fields before a browser screenshot.

    Browser ``capture_fn`` implementations should ``page.evaluate`` this (or
    equivalent) before ``page.screenshot``. Defaults include [[PASSWORD_SELECTORS]].
    """
    sels = list(PASSWORD_SELECTORS if sensitive_selectors is None else sensitive_selectors)
    return prepare_page_for_capture(sels)


def has_screenshot(s: Session, finding_id: int) -> bool:
    """True when the finding already has screenshot evidence."""
    return (
        s.scalar(
            select(Evidence.id).where(Evidence.finding_id == finding_id, Evidence.kind == "screenshot").limit(1)
        )
        is not None
    )


def _http_url(location: str) -> str:
    """Return a bare http(s) URL from a finding location, or empty if not usable."""
    raw = (location or "").split(" [param:", 1)[0].strip()
    if not raw:
        return ""
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return ""
    return raw


def capture_finding_screenshot(
    session: Session,
    finding: Finding,
    *,
    page_png_bytes: bytes | None = None,
    capture_fn: CaptureFn | None = None,
    actor: str,
    note: str = "",
) -> Evidence | None:
    """Attach a redacted screenshot for ``finding`` when possible.

    Prefer ``page_png_bytes`` when provided (always-on attach path; auth-web flag
    does not block). Otherwise call ``capture_fn`` or the registered capture with
    the finding's http(s) URL. Skips empty/non-http locations and findings that
    already have screenshot evidence. Notes never include secrets.
    """
    url = _http_url(getattr(finding, "location", "") or "")
    if not url:
        return None
    if has_screenshot(session, finding.id):
        return None

    png = page_png_bytes
    if png is None:
        fn = capture_fn if capture_fn is not None else _registered_capture
        if fn is None:
            return None
        try:
            png = fn(url)
        except Exception:  # noqa: BLE001 — never fail callers / imports
            log.exception("screenshot capture_fn failed for finding %s", getattr(finding, "id", "?"))
            return None
    if not png:
        return None

    safe_note = (note or "auto-captured screenshot").strip()
    return attach_redacted_screenshot(
        session,
        finding.id,
        filename="screenshot.png",
        data=png,
        actor=actor,
        note=safe_note,
        regions=None,
    )


def capture_screenshots_for_findings(
    session: Session,
    findings: Iterable[Finding],
    *,
    actor: str,
    capture_fn: CaptureFn | None = None,
) -> int:
    """Attach screenshots for findings with http(s) locations when a capture_fn is available.

    Uses ``capture_fn`` when passed, otherwise the registered callable. Returns 0
    immediately when neither is set (imports stay network-free by default).
    """
    fn = capture_fn if capture_fn is not None else _registered_capture
    if fn is None:
        return 0
    attached = 0
    for finding in findings:
        ev = capture_finding_screenshot(session, finding, capture_fn=fn, actor=actor)
        if ev is not None:
            attached += 1
    return attached
