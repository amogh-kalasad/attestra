"""Safe XML helpers for Burp / Nessus importers (defusedxml, size limit)."""

from __future__ import annotations

from xml.etree.ElementTree import Element

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

# Cap upload size so entity bombs and huge exports cannot fill memory.
MAX_XML_BYTES = 32 * 1024 * 1024


def parse_xml(raw: bytes) -> Element:
    """Parse XML bytes with defusedxml. Refuse oversized or hostile documents."""
    if not isinstance(raw, (bytes, bytearray)):
        raise ValueError("XML input must be bytes")
    if len(raw) > MAX_XML_BYTES:
        raise ValueError(f"XML file exceeds {MAX_XML_BYTES} byte limit")
    try:
        return ET.fromstring(raw)
    except DefusedXmlException as exc:
        raise ValueError(f"refused unsafe XML: {exc}") from exc
    except ET.ParseError as exc:
        raise ValueError(f"invalid XML: {exc}") from exc


def child_text(el: Element | None, tag: str, default: str = "") -> str:
    """Return stripped text of the first direct child with the given tag."""
    if el is None:
        return default
    child = el.find(tag)
    if child is None or child.text is None:
        return default
    return str(child.text).strip()
