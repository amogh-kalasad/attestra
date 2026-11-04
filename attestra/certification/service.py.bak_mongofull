"""Persist and retrieve the platform Certification Authority singleton.

Super Admin (`admin` / ``certification.manage``) configures issuer identity,
logo, address and contact used on reports. Distinct from per-engagement client
[[attestra/models.py#Authorization]] rows and per-tenant ReportTemplate logos.
"""
# @lat: [[reports#Certification Authority branding]]

from __future__ import annotations

import re
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra import audit
from attestra.auth.roles import has_permission
from attestra.models import CertificationAuthority, utcnow

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PHONE_RE = re.compile(r"^[\d\s\-()+.]{5,40}$")
_SINGLETON_ID = 1


class CertificationError(ValueError):
    """Invalid Certification Authority input or unauthorized mutation."""


def _require_admin(principal) -> None:
    if principal is None or not has_permission(getattr(principal, "role", ""), "certification.manage"):
        raise CertificationError("only a Super Admin can manage Certification Authority settings")


def get_settings(s: Session) -> CertificationAuthority | None:
    return s.get(CertificationAuthority, _SINGLETON_ID)


def ensure_settings(s: Session) -> CertificationAuthority:
    row = get_settings(s)
    if row is not None:
        return row
    row = CertificationAuthority(id=_SINGLETON_ID)
    s.add(row)
    s.flush()
    return row


def format_address(row: CertificationAuthority | None) -> str:
    """Single-line address omitting empty components."""
    if row is None:
        return ""
    line1 = (row.address_line1 or "").strip()
    line2 = (row.address_line2 or "").strip()
    city = (row.city or "").strip()
    state = (row.state or "").strip()
    postal = (row.postal_code or "").strip()
    country = (row.country or "").strip()
    locality = ", ".join(p for p in (city, state) if p)
    if postal:
        locality = f"{locality} {postal}".strip() if locality else postal
    parts = [p for p in (line1, line2, locality, country) if p]
    return ", ".join(parts)


def settings_dict(row: CertificationAuthority | None) -> dict:
    empty = {
        "legal_name": "",
        "signer_name": "",
        "signer_title": "",
        "authorization_statement": "",
        "logo": "",
        "has_logo": False,
        "address_line1": "",
        "address_line2": "",
        "city": "",
        "state": "",
        "postal_code": "",
        "country": "",
        "address_formatted": "",
        "contact_name": "",
        "contact_email": "",
        "contact_phone": "",
        "website": "",
        "updated_by": "",
        "updated_at": None,
    }
    if row is None:
        return empty
    return {
        "legal_name": row.legal_name or "",
        "signer_name": row.signer_name or "",
        "signer_title": row.signer_title or "",
        "authorization_statement": row.authorization_statement or "",
        "logo": row.logo or "",
        "has_logo": bool(row.logo),
        "address_line1": row.address_line1 or "",
        "address_line2": row.address_line2 or "",
        "city": row.city or "",
        "state": row.state or "",
        "postal_code": row.postal_code or "",
        "country": row.country or "",
        "address_formatted": format_address(row),
        "contact_name": row.contact_name or "",
        "contact_email": row.contact_email or "",
        "contact_phone": row.contact_phone or "",
        "website": row.website or "",
        "updated_by": row.updated_by or "",
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def report_branding(s: Session) -> dict:
    """Safe report-context fields; empty strings when unset (never raises)."""
    try:
        return settings_dict(get_settings(s))
    except Exception:
        return settings_dict(None)


def _clean_str(value: str | None, *, max_len: int, field: str) -> str:
    text = (value or "").strip()
    if len(text) > max_len:
        raise CertificationError(f"{field} must be at most {max_len} characters")
    return text


def _validate_email(email: str) -> str:
    email = email.strip()
    if not email:
        return ""
    if not _EMAIL_RE.match(email):
        raise CertificationError("official email address is not valid")
    return email.lower()


def _validate_phone(phone: str) -> str:
    phone = phone.strip()
    if not phone:
        return ""
    if not _PHONE_RE.match(phone):
        raise CertificationError("contact phone number is not valid")
    return phone


def _validate_website(url: str) -> str:
    url = url.strip()
    if not url:
        return ""
    if len(url) > 300:
        raise CertificationError("company website must be at most 300 characters")
    parsed = urlparse(url if "://" in url else f"https://{url}")
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise CertificationError("company website must be an http(s) URL")
    # Normalize to include scheme for stable report rendering.
    if "://" not in url:
        return f"https://{url}"
    return url


def update_settings(
    s: Session,
    principal,
    *,
    legal_name: str | None = None,
    signer_name: str | None = None,
    signer_title: str | None = None,
    authorization_statement: str | None = None,
    logo: bytes | None = None,
    clear_logo: bool = False,
    address_line1: str | None = None,
    address_line2: str | None = None,
    city: str | None = None,
    state: str | None = None,
    postal_code: str | None = None,
    country: str | None = None,
    contact_name: str | None = None,
    contact_email: str | None = None,
    contact_phone: str | None = None,
    website: str | None = None,
) -> CertificationAuthority:
    """Partial update of the singleton; unset kwargs leave existing values."""
    _require_admin(principal)
    row = ensure_settings(s)

    if legal_name is not None:
        row.legal_name = _clean_str(legal_name, max_len=200, field="legal name")
    if signer_name is not None:
        row.signer_name = _clean_str(signer_name, max_len=200, field="signer name")
    if signer_title is not None:
        row.signer_title = _clean_str(signer_title, max_len=200, field="signer title")
    if authorization_statement is not None:
        row.authorization_statement = _clean_str(
            authorization_statement, max_len=4000, field="authorization statement"
        )

    if logo:
        from attestra.library.templates import TemplateErrorOut, logo_data_uri

        try:
            row.logo = logo_data_uri(logo)
        except TemplateErrorOut as e:
            raise CertificationError(str(e)) from e
    elif clear_logo:
        row.logo = ""

    if address_line1 is not None:
        row.address_line1 = _clean_str(address_line1, max_len=300, field="address line 1")
    if address_line2 is not None:
        row.address_line2 = _clean_str(address_line2, max_len=300, field="address line 2")
    if city is not None:
        row.city = _clean_str(city, max_len=120, field="city")
    if state is not None:
        row.state = _clean_str(state, max_len=120, field="state or province")
    if postal_code is not None:
        row.postal_code = _clean_str(postal_code, max_len=40, field="postal code")
    if country is not None:
        row.country = _clean_str(country, max_len=120, field="country")

    if contact_name is not None:
        row.contact_name = _clean_str(contact_name, max_len=200, field="company contact name")
    if contact_email is not None:
        row.contact_email = _validate_email(contact_email)
    if contact_phone is not None:
        row.contact_phone = _validate_phone(contact_phone)
    if website is not None:
        row.website = _validate_website(website)

    row.updated_by = getattr(principal, "actor", "") or ""
    row.updated_at = utcnow()
    s.flush()
    audit.record(
        s,
        row.updated_by,
        "certification_authority.update",
        "certification_authority",
        row.id,
        legal_name=row.legal_name,
        has_logo=bool(row.logo),
        has_address=bool(format_address(row)),
        has_contact=bool(row.contact_email or row.contact_phone or row.contact_name),
    )
    return row
