"""Pure helpers for safe reflection / canary detection (no network I/O)."""

from __future__ import annotations

import html
import re
import secrets
from typing import Any

CANARY_PREFIX = "ATTSTRA_CANARY_"

_HTML_HINT = re.compile(
    r"(?i)<(!doctype\s+html|html\b|head\b|body\b|div\b|span\b|p\b|script\b|form\b|title\b)"
)


def new_canary(*, tag: str = "") -> str:
    """Return a unique ``ATTSTRA_CANARY_*`` marker (alphanumeric + underscores)."""
    mid = f"{tag}_" if tag else ""
    return f"{CANARY_PREFIX}{mid}{secrets.token_hex(4).upper()}"


def xss_canary_payload(canary: str | None = None) -> str:
    """Benign reflected-XSS shape: quote-break + unique marker (no script execution)."""
    marker = canary or new_canary(tag="XSS")
    return f"'\"><{marker}>"


def injection_canary_payload(canary: str | None = None) -> str:
    """Benign injection-surface canary with a quote (no time-based or destructive payload)."""
    marker = canary or new_canary(tag="INJ")
    return f"{marker}'"


def is_html_body(body: str, content_type: str | None = None) -> bool:
    """True when Content-Type is HTML or the body looks like HTML markup."""
    if content_type and "html" in content_type.lower():
        return True
    sample = (body or "")[:4000]
    return bool(_HTML_HINT.search(sample))


def detect_unencoded_reflection(needle: str, body: str) -> bool:
    """True when ``needle`` appears literally in ``body`` (not HTML-entity-only)."""
    if not needle or not body:
        return False
    if needle in body:
        return True
    return False


def detect_encoded_only_reflection(needle: str, body: str) -> bool:
    """True when only an HTML-escaped form of ``needle`` appears (proper encoding)."""
    if not needle or not body or needle in body:
        return False
    escaped = html.escape(needle, quote=True)
    return escaped != needle and escaped in body


def reflection_in_headers(needle: str, headers: dict[str, Any] | None) -> list[str]:
    """Return header names whose values contain the literal needle."""
    if not needle or not headers:
        return []
    hit: list[str] = []
    for key, value in headers.items():
        if needle in str(value):
            hit.append(str(key))
    return hit


def reflected_unencoded_in_html(
    needle: str,
    body: str,
    *,
    content_type: str | None = None,
) -> bool:
    """Finding gate: literal reflection inside an HTML response context."""
    return detect_unencoded_reflection(needle, body) and is_html_body(body, content_type)


# ------------------------------------------------------------------ B-06 reflection context

# @lat: [[run-validity-and-policy#XSS reflection context]]

CTX_HTML_TEXT = "html_text"
CTX_ATTR_QUOTED = "attribute_quoted"
CTX_ATTR_UNQUOTED = "attribute_unquoted"
CTX_URL_ATTR = "url_attribute"
CTX_SCRIPT = "script_block"
CTX_EVENT_HANDLER = "event_handler"
CTX_STYLE = "style_block"
CTX_COMMENT = "html_comment"
CTX_TAG_NAME = "tag_name"

_URL_ATTRS = frozenset({"href", "src", "action", "formaction", "data", "poster", "srcset", "xlink:href", "background"})
_TAG_OPEN_RE = re.compile(r"<\s*([A-Za-z][A-Za-z0-9:-]*)\b")
_ATTR_RE = re.compile(r"""([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*("[^"]*"|'[^']*'|[^\s"'=<>`]+)""")


def _enclosing_block(body: str, idx: int, open_tag: str) -> bool:
    low = body.lower()
    start = low.rfind(f"<{open_tag}", 0, idx)
    if start < 0:
        return False
    end = low.rfind(f"</{open_tag}", 0, idx)
    return end < start


def _tag_context(body: str, idx: int, needle: str) -> str | None:
    """Context when ``idx`` sits inside an open tag ``<tag ... needle ...>``."""
    lt = body.rfind("<", 0, idx)
    gt = body.rfind(">", 0, idx)
    if lt < 0 or gt > lt:
        return None
    tag_text = body[lt: idx + len(needle)]
    m = _TAG_OPEN_RE.match(tag_text)
    if m and m.end() > idx - lt:
        return CTX_TAG_NAME
    for am in _ATTR_RE.finditer(body[lt: body.find(">", idx) if body.find(">", idx) > 0 else len(body)]):
        a_start = lt + am.start(2)
        a_end = lt + am.end(2)
        if a_start <= idx < a_end:
            name = am.group(1).lower()
            value = am.group(2)
            if name.startswith("on"):
                return CTX_EVENT_HANDLER
            if name in _URL_ATTRS:
                return CTX_URL_ATTR
            if name == "style":
                return CTX_STYLE
            return CTX_ATTR_QUOTED if value[:1] in ("'", '"') else CTX_ATTR_UNQUOTED
    return CTX_ATTR_UNQUOTED


def classify_reflection_context(needle: str, body: str, *, limit: int = 5) -> list[str]:
    """B-06: where does ``needle`` land in an HTML page? Pure, read-only.

    Returns up to ``limit`` context labels (one per occurrence, de-duplicated, in
    order): ``html_text``, ``attribute_quoted``, ``attribute_unquoted``,
    ``url_attribute``, ``event_handler``, ``script_block``, ``style_block``,
    ``html_comment``, ``tag_name``.
    """
    if not needle or not body:
        return []
    out: list[str] = []
    start = 0
    while len(out) < limit:
        idx = body.find(needle, start)
        if idx < 0:
            break
        start = idx + len(needle)
        if body.rfind("<!--", 0, idx) > body.rfind("-->", 0, idx):
            ctx = CTX_COMMENT
        elif _enclosing_block(body, idx, "script"):
            ctx = CTX_SCRIPT
        elif _enclosing_block(body, idx, "style"):
            ctx = CTX_STYLE
        else:
            ctx = _tag_context(body, idx, needle) or CTX_HTML_TEXT
        if ctx not in out:
            out.append(ctx)
    return out


def context_breakout_possible(context: str, payload: str, body: str, marker: str) -> bool:
    """Does the raw reflection let the canary escape its context? (Indicator, not exploitation.)

    * html_text / tag_name: the literal ``<MARKER>`` tag survived.
    * attribute_quoted / event_handler / url_attribute / style: the quote preceding the
      marker in the payload survived unencoded next to the marker.
    * script_block: a quote or ``</script`` adjacent to the marker survived.
    * html_comment: ``-->`` would be needed; never claimed from a canary alone.
    """
    if not marker or not body:
        return False
    if context in (CTX_HTML_TEXT, CTX_TAG_NAME):
        return f"<{marker}>" in body
    if context in (CTX_ATTR_QUOTED, CTX_EVENT_HANDLER, CTX_URL_ATTR, CTX_STYLE, CTX_ATTR_UNQUOTED):
        return f'"><{marker}>' in body or f"'><{marker}>" in body or (
            context == CTX_ATTR_UNQUOTED and f"><{marker}>" in body
        )
    if context == CTX_SCRIPT:
        return f"'\"><{marker}" in body or f"</script><{marker}" in body.lower()
    return False


def url_attribute_starts_with(needle: str, body: str) -> bool:
    """True when a URL attribute value *starts* with the needle (``javascript:`` style risk)."""
    for m in re.finditer(r"""(?i)\b(?:href|src|action|formaction)\s*=\s*["']?""", body or ""):
        if body.startswith(needle, m.end()):
            return True
    return False
