"""Sign-off record shown on top of a report when it is viewed in Attestra.

The sealed report file is never changed: its SHA-256 is what QA approved and the lead signed, and
``verify-report`` re-hashes the file on disk. The banner is built at view time from the database and
the existing verify logic, and injected only into the response. The sealed bytes stay downloadable
unchanged from ``/reports/{rid}/sealed``.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from html import escape

from attestra.models import Report

BANNER_ID = "attestra-signoff-record"
_BODY_OPEN = re.compile(rb"<body\b[^>]*>", re.IGNORECASE)

_STATUS_TEXT = {
    "draft": "Draft. Not submitted for QA, not approved and not signed.",
    "submitted": "In QA. Waiting for a different person to QA it. Not approved or signed yet.",
    "rejected": "Rejected by QA. Sent back to the author. Not approved or signed.",
    "qa_approved": "QA approved. Waiting for a lead to approve and sign it. Not signed yet.",
    "signed": "Signed.",
}

_COLOURS = {  # border, background
    "signed": ("#3b7d4f", "#eef7f0"),
    "qa_approved": ("#2457d6", "#eef3fc"),
    "submitted": ("#b7791f", "#fdf6ea"),
    "rejected": ("#a1161b", "#fcefef"),
    "draft": ("#6b7280", "#f3f4f6"),
}


def _default_fmt(value) -> str:
    from attestra.web.ui import format_dt

    return format_dt(value)


def banner_html(r: Report, check: dict, *, sealed_url: str, fmt: Callable[[object], str] | None = None) -> str:
    """One block of HTML describing the report's current sign-off state."""
    fmt = fmt or _default_fmt
    status = r.status or "draft"
    border, bg = _COLOURS.get(status, _COLOURS["draft"])
    hash_ok = bool(check.get("hash_matches"))
    sig_ok = bool(check.get("signature_valid"))
    if not hash_ok:
        border, bg = "#a1161b", "#fcefef"

    lines: list[str] = []
    if status == "signed":
        head = (f"Signed by {escape(r.approved_by or '-')} on {escape(fmt(r.signed_at))}"
                f", QA by {escape(r.qa_by or '-')}.")
    else:
        head = escape(_STATUS_TEXT.get(status, f"Status: {status}."))
        if status in ("qa_approved", "rejected") and r.qa_by:
            head += f" QA by {escape(r.qa_by)}."
    lines.append(f'<div style="font-size:15px;font-weight:700;margin-bottom:4px">{head}</div>')
    if status == "rejected" and r.rejection_note:
        lines.append(f"<div>QA note: {escape(r.rejection_note)}</div>")
    lines.append(f"<div>Made by {escape(r.generated_by or '-')} on {escape(fmt(r.generated_at))}.</div>")

    if hash_ok:
        file_state = "File unchanged since it was made (SHA-256 matches)."
    else:
        file_state = "WARNING: the file on disk no longer matches its recorded SHA-256. Do not rely on it."
    if status == "signed":
        algo = escape(check.get("algorithm") or r.algorithm or "")
        sig_state = f"Signature valid ({algo})." if sig_ok and hash_ok else "Signature INVALID."
    else:
        sig_state = "Not signed yet."
    lines.append(f"<div>{file_state} {sig_state}</div>")
    lines.append(
        '<div style="font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-all">'
        f"SHA-256 {escape(r.sha256 or '')}</div>"
    )
    lines.append(
        '<div style="color:#5b6170;font-size:12px;margin-top:4px">This sign-off record is added by Attestra when you '
        "view the report. It is not part of the sealed file, so the SHA-256 above still matches. "
        f'<a href="{escape(sealed_url)}">Download the sealed file</a> or check it with '
        f'<span style="font-family:ui-monospace,Menlo,monospace">attestra verify-report {int(r.id)}</span>.</div>'
    )
    return (
        f'<div id="{BANNER_ID}" data-status="{escape(status)}" role="status" '
        f'style="font:14px/1.5 -apple-system,\'Segoe UI\',Inter,Roboto,sans-serif;color:#16181d;'
        f'border:2px solid {border};background:{bg};border-radius:8px;padding:10px 14px;margin:0 0 20px">'
        + "".join(lines)
        + "</div>"
    )


def inject(sealed: bytes, banner: str) -> bytes:
    """Return a copy of the sealed HTML with the banner right after <body>. The input is not modified."""
    data = banner.encode("utf-8")
    m = _BODY_OPEN.search(sealed)
    if not m:
        return data + sealed
    return sealed[: m.end()] + data + sealed[m.end():]