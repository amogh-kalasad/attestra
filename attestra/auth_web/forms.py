"""Form/element inventory and safe synthetic test-data for authenticated website testing.

Non-destructive by default: state-changing forms are never submitted unless
``authorize_submit=True``. Generated values never echo real-looking secrets from
placeholders, values, or autocomplete hints found in the page markup.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin

from attestra.proof.redact import is_sensitive_name

STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Patterns that look like live secrets / credentials — never copy into synthetic data.
_SECRET_LOOKING = re.compile(
    r"(?i)("
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|"  # JWT-ish
    r"sk-[A-Za-z0-9]{16,}|"
    r"ghp_[A-Za-z0-9]{20,}|"
    r"AKIA[0-9A-Z]{16}|"
    r"(?:password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*\S+|"
    r"[A-Za-z0-9+/]{32,}={0,2}"  # long base64-ish blobs
    r")"
)

_EMAIL_NAME = re.compile(r"(?i)e-?mail|user(name)?|login")
_PHONE_NAME = re.compile(r"(?i)phone|mobile|tel")
_NAME_NAME = re.compile(r"(?i)(?:first|last|full)?_?name|given|family")
_SEARCH_NAME = re.compile(r"(?i)search|query|q$")
_URL_NAME = re.compile(r"(?i)url|website|homepage")
_NUMBER_NAME = re.compile(r"(?i)amount|qty|quantity|count|age|zip|postal")


@dataclass
class FormField:
    name: str
    input_type: str = "text"
    required: bool = False
    value: str = ""
    placeholder: str = ""
    autocomplete: str = ""
    element_type: str = "textbox"  # textbox|checkbox|radio|select|hidden|button|…
    options: list[str] = field(default_factory=list)
    selector: str = ""


@dataclass
class FormInventory:
    action: str
    method: str = "GET"
    fields: list[FormField] = field(default_factory=list)
    name: str = ""
    id: str = ""

    @property
    def is_state_changing(self) -> bool:
        return self.method.upper() in STATE_CHANGING_METHODS


@dataclass
class ElementInventoryItem:
    selector: str
    accessible_name: str
    element_type: str
    input_type: str = ""
    required: bool = False


def looks_like_secret(text: str) -> bool:
    """True when text resembles a credential or token (must not be reused as test data)."""
    t = (text or "").strip()
    if not t:
        return False
    if is_sensitive_name(t):
        return True
    return bool(_SECRET_LOOKING.search(t))


def synthetic_value(field: FormField, *, seed: str = "attestra") -> str:
    """Return safe fake input for ``field``; never copies secret-looking source values."""
    # Never copy field.value / placeholder / autocomplete into output (may hold secrets).
    name = field.name or ""
    itype = (field.input_type or "text").lower()
    digest = hashlib.sha256(f"{seed}:{name}:{itype}".encode()).hexdigest()[:10]

    if itype in ("checkbox", "radio"):
        return "on"
    if itype == "hidden":
        # Do not reuse hidden token values from page content.
        return f"synth-{digest}"
    if itype == "password" or is_sensitive_name(name):
        return f"SynthPass-{digest}"
    if itype == "email" or _EMAIL_NAME.search(name):
        return f"tester-{digest}@example.test"
    if itype == "tel" or _PHONE_NAME.search(name):
        return "+15550100"
    if itype == "url" or _URL_NAME.search(name):
        return "https://example.test/synth"
    if itype in ("number", "range") or _NUMBER_NAME.search(name):
        return "1"
    if itype == "search" or _SEARCH_NAME.search(name):
        return f"synth-search-{digest}"
    if itype == "date":
        return "2020-01-02"
    if itype == "file":
        return ""
    if field.options:
        for opt in field.options:
            if opt and not looks_like_secret(opt):
                return opt
        return f"synth-{digest}"
    if _NAME_NAME.search(name):
        return f"Synth User {digest[:4]}"
    return f"synth-{digest}"


def may_submit(form: FormInventory, *, authorize_submit: bool = False) -> bool:
    """State-changing forms require an explicit authorize_submit flag."""
    if form.is_state_changing and not authorize_submit:
        return False
    return True


def fill_form_values(
    form: FormInventory,
    *,
    seed: str = "attestra",
    authorize_submit: bool = False,
) -> dict[str, str]:
    """Map field names to synthetic values. Does not submit.

    When the form is state-changing and ``authorize_submit`` is false, values are
    still generated for inventory/preview but callers must not POST them.
    """
    _ = authorize_submit  # documented gate for callers; generation itself is safe
    out: dict[str, str] = {}
    for f in form.fields:
        if not f.name:
            continue
        if f.input_type.lower() in ("submit", "button", "image", "reset"):
            continue
        out[f.name] = synthetic_value(f, seed=seed)
    return out


class _FormParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.forms: list[FormInventory] = []
        self.elements: list[ElementInventoryItem] = []
        self._form: FormInventory | None = None
        self._select: FormField | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        ad = {k.lower(): (v if v is not None else "") for k, v in attrs}
        if tag == "form":
            action = ad.get("action") or self.base_url or ""
            if self.base_url:
                action = urljoin(self.base_url, action)
            method = (ad.get("method") or "GET").upper()
            self._form = FormInventory(
                action=action,
                method=method,
                name=ad.get("name") or "",
                id=ad.get("id") or "",
            )
            return
        if tag == "input":
            itype = (ad.get("type") or "text").lower()
            name = ad.get("name") or ""
            field = FormField(
                name=name,
                input_type=itype,
                required="required" in ad,
                value=ad.get("value") or "",
                placeholder=ad.get("placeholder") or "",
                autocomplete=ad.get("autocomplete") or "",
                element_type=_element_type_for_input(itype),
                selector=_rough_selector("input", ad),
            )
            if self._form is not None:
                self._form.fields.append(field)
            if name or ad.get("id"):
                self.elements.append(
                    ElementInventoryItem(
                        selector=field.selector,
                        accessible_name=ad.get("aria-label") or name or ad.get("id") or "",
                        element_type=field.element_type,
                        input_type=itype,
                        required=field.required,
                    )
                )
            return
        if tag == "textarea":
            name = ad.get("name") or ""
            field = FormField(
                name=name,
                input_type="textarea",
                required="required" in ad,
                placeholder=ad.get("placeholder") or "",
                element_type="textbox",
                selector=_rough_selector("textarea", ad),
            )
            if self._form is not None:
                self._form.fields.append(field)
            self.elements.append(
                ElementInventoryItem(
                    selector=field.selector,
                    accessible_name=ad.get("aria-label") or name or "",
                    element_type="textbox",
                    input_type="textarea",
                    required=field.required,
                )
            )
            return
        if tag == "select":
            name = ad.get("name") or ""
            self._select = FormField(
                name=name,
                input_type="select",
                required="required" in ad,
                element_type="select",
                selector=_rough_selector("select", ad),
            )
            if self._form is not None:
                self._form.fields.append(self._select)
            self.elements.append(
                ElementInventoryItem(
                    selector=self._select.selector,
                    accessible_name=ad.get("aria-label") or name or "",
                    element_type="select",
                    input_type="select",
                    required=self._select.required,
                )
            )
            return
        if tag == "option" and self._select is not None:
            val = ad.get("value")
            # Value may arrive in handle_data; stash empty and fill later if needed.
            if val:
                self._select.options.append(val)
            else:
                self._select.options.append("")
            return
        if tag in ("button", "a"):
            name = ad.get("aria-label") or ad.get("name") or ad.get("id") or ""
            self.elements.append(
                ElementInventoryItem(
                    selector=_rough_selector(tag, ad),
                    accessible_name=name,
                    element_type="button" if tag == "button" else "link",
                    input_type=ad.get("type") or "",
                )
            )

    def handle_data(self, data: str) -> None:
        if self._select is not None and self._select.options and self._select.options[-1] == "":
            text = (data or "").strip()
            if text:
                self._select.options[-1] = text

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None
        if tag == "select":
            self._select = None


def _element_type_for_input(itype: str) -> str:
    if itype in ("checkbox",):
        return "checkbox"
    if itype in ("radio",):
        return "radio"
    if itype in ("submit", "button", "reset", "image"):
        return "button"
    if itype == "hidden":
        return "hidden"
    if itype == "file":
        return "file"
    return "textbox"


def _rough_selector(tag: str, ad: dict[str, str]) -> str:
    if ad.get("id"):
        return f"#{ad['id']}"
    if ad.get("name"):
        return f"{tag}[name={ad['name']!r}]"
    if ad.get("aria-label"):
        return f"{tag}[aria-label={ad['aria-label']!r}]"
    return tag


def inventory_forms(html: str, base_url: str = "") -> list[FormInventory]:
    """Parse HTML forms into inventories (no network, no submit)."""
    parser = _FormParser(base_url)
    try:
        parser.feed(html or "")
    except Exception:
        return []
    return parser.forms


def inventory_elements(html: str, base_url: str = "") -> list[ElementInventoryItem]:
    """Parse interactive elements (inputs, selects, buttons, links) for coverage."""
    parser = _FormParser(base_url)
    try:
        parser.feed(html or "")
    except Exception:
        return []
    return parser.elements
