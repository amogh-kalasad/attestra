"""Derivative plain (unbranded) views of sealed report HTML.

The sealed file on disk is never modified. Plain views strip logos, issuer /
Attestra brand chrome, and powered-by footers so clients can open content-only
pages from the portal. Hashes and verify still refer to the sealed original.
"""
# @lat: [[interfaces#Client remediation portal]]

from __future__ import annotations

import re

# Cover / header logos (tenant or CA).
_COVER_LOGO = re.compile(
    rb'(?is)<img\b[^>]*\bclass\s*=\s*["\'][^"\']*cover-logo[^"\']*["\'][^>]*>'
)
_ANY_LOGO_IMG = re.compile(
    rb'(?is)<img\b[^>]*(?:alt\s*=\s*["\'][^"\']*logo[^"\']*["\']|src\s*=\s*["\']data:image/)[^>]*>'
)
# Explicit brand wordmarks in cover / meta lines.
_BRAND_SPAN = re.compile(
    rb'(?is)<span\b[^>]*\bclass\s*=\s*["\'][^"\']*\bbrand\b[^"\']*["\'][^>]*>.*?</span>'
)
_COVER_BAND_BRAND = re.compile(
    rb'(?is)<span\b[^>]*\bclass\s*=\s*["\'][^"\']*cover-band-brand[^"\']*["\'][^>]*>.*?</span>'
)
# Full report footer (Attestra / CA powered-by + verify prose).
_FOOTER = re.compile(rb"(?is)<footer\b[^>]*>.*?</footer>")
# Common "ATTESTRA" wordmarks left in plain text nodes of the cover meta strip.
_ATTESTRA_WORD = re.compile(rb"(?i)\bATTESTRA\b")
_POWERED_BY = re.compile(rb"(?is)[Gg]enerated\s+[^.<]{0,120}\bwith\s+[Aa]ttestra[^.<]{0,80}\.")


def strip_report_branding(html: bytes) -> bytes:
    """Return a content-focused copy of sealed report HTML with brand chrome removed.

    Removes cover logos, brand wordmarks, and the Attestra/CA footer. Leaves
    findings, tables, and body content intact. Does not touch the file on disk.
    """
    if not html:
        return html
    out = html
    out = _COVER_LOGO.sub(b"", out)
    out = _COVER_BAND_BRAND.sub(b"", out)
    out = _BRAND_SPAN.sub(b"", out)
    # Drop remaining data:image logos that were not class=cover-logo.
    out = _ANY_LOGO_IMG.sub(b"", out)
    plain_footer = (
        b"<footer>Confidential. Plain content view - issuer branding and "
        b"platform marks are omitted. The sealed original remains unchanged for verify.</footer>"
    )
    if _FOOTER.search(out):
        out = _FOOTER.sub(plain_footer, out, count=1)
    else:
        # Ensure a closing note before </body>
        out = re.sub(rb"(?is)</body>", plain_footer + b"</body>", out, count=1)
    out = _POWERED_BY.sub(b"", out)
    # Soften leftover ATTESTRA tokens in chrome (keep body finding text if any mention).
    # Only replace outside <pre> / finding evidence blocks is hard; limit to header meta lines.
    out = re.sub(
        rb'(?is)(<div class="meta">)(.*?)(</div>)',
        lambda m: m.group(1) + _ATTESTRA_WORD.sub(b"", m.group(2)) + m.group(3),
        out,
        count=1,
    )
    return out


def plain_banner_html(*, sealed_url: str, branded_url: str) -> str:
    """Minimal view banner for plain mode (no Attestra marketing chrome)."""
    from html import escape

    return (
        '<div id="attestra-plain-view-banner" role="status" '
        'style="font:13px/1.45 -apple-system,\'Segoe UI\',sans-serif;color:#16181d;'
        'border:1px solid #d1d5db;background:#f9fafb;border-radius:8px;padding:10px 14px;margin:0 0 16px">'
        "<div style=\"font-weight:600;margin-bottom:4px\">Plain content view</div>"
        "<div>Issuer logos, platform branding, and powered-by marks are hidden. "
        "Findings and report body content are unchanged.</div>"
        f'<div style="margin-top:8px">'
        f'<a href="{escape(branded_url)}">Open with branding</a>'
        f' · <a href="{escape(sealed_url)}">Download sealed original</a>'
        f"</div></div>"
    )
