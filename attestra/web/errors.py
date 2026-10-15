"""Friendly HTML error handling for the server-rendered UI (UI audit #5, #6, #12, #39, #40).

Browsers (``Accept: text/html``) on non-API paths get:

* form validation errors (FastAPI's 422) as a redirect back to the form with a readable ``?error=`` message;
* 401 on a GET as a redirect to ``/login?next=...``;
* 403 / 404 / other HTTP errors as an HTML page with navigation, keeping the status code.

API clients and anything not asking for HTML keep the JSON responses unchanged.
"""

from __future__ import annotations

from urllib.parse import quote, urlsplit

from fastapi import FastAPI, Request
from fastapi.exception_handlers import http_exception_handler, request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import RedirectResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

API_PREFIXES = ("/api", "/docs", "/redoc", "/openapi.json", "/metrics")

FIELD_LABELS = {
    "asset_id": "Target",
    "signed_on": "Signed on",
    "expires_on": "Valid until",
    "document": "Signed document",
    "signer": "Signed by",
    "criticality": "Business criticality",
    "identifier": "URL / address / identifier",
    "next_due": "Next due date",
    "scan_date": "Scan date",
    "tested_on": "Tested on",
    "control_ref": "Control",
    "finding_id": "Finding",
    "tenant": "Client / company name",
    "file": "File",
    "tool": "Tool",
}

# Which card to scroll back to, by the last part of the form's action path.
ANCHORS = (
    ("/scans", "#scans"),
    ("/authorizations", "#scope"),
    ("/targets", "#targets"),
    ("/imports", "#import"),
    ("/schedules", "#schedules"),
    ("/run-due", "#schedules"),
    ("/update", "#schedules"),
    ("/pci/segmentation", "#segmentation"),
    ("/asv/import", "#asv"),
    ("/asv", "#pci-records"),
    ("/segmentation", "#pci-records"),
    ("/iso/sample", "#sampling"),
    ("/iso/soa", "#soa"),
    ("/iso/nc", "#nc"),
)

STATUS_TEXT = {
    401: ("Sign in required", "Sign in to see this page."),
    403: ("You don't have access to this page", "Your role doesn't allow this action. If you need it, ask your lead or an admin."),
    404: ("Page not found", "We couldn't find that page or record. It may have been removed, or the link is wrong."),
    405: ("Action not allowed", "This page can't be used that way. Go back and use the buttons on the page."),
    409: ("That change conflicts with the current state", "Reload the page and try again."),
    429: ("Too many requests", "Wait a minute and try again."),
}


def wants_html(request: Request) -> bool:
    path = request.url.path
    if any(path == p or path.startswith(p + "/") for p in API_PREFIXES):
        return False
    return "text/html" in (request.headers.get("accept") or "").lower()


def _field_name(loc) -> str:
    parts = [str(p) for p in loc if p not in ("body", "query", "path", "header", "cookie")]
    return parts[-1] if parts else "field"


def friendly_validation_message(exc: RequestValidationError) -> str:
    problems = []
    for err in exc.errors():
        name = _field_name(err.get("loc", ()))
        pretty = FIELD_LABELS.get(name, name.replace("_", " ").capitalize())
        kind = str(err.get("type", ""))
        if kind == "missing":
            why = "is required"
        elif "date" in kind:
            why = "must be a valid date"
        elif "int" in kind or "float" in kind or "decimal" in kind:
            why = "must be a number"
        elif "bool" in kind:
            why = "must be yes or no"
        else:
            why = "isn't valid"
        problems.append(f"{pretty} {why}")
    return "Please check the form: " + "; ".join(dict.fromkeys(problems)) + "." if problems else "Please check the form."


def back_url(request: Request) -> str:
    """Same-site page the form came from (the Referer), else the parent page of the form action."""
    ref = request.headers.get("referer") or ""
    if ref:
        parts = urlsplit(ref)
        same_host = not parts.netloc or parts.netloc == request.url.netloc
        if same_host and parts.path.startswith("/") and not parts.path.startswith("//"):
            return parts.path
    path = request.url.path
    segs = [s for s in path.split("/") if s]
    if len(segs) >= 2 and segs[0] == "engagements" and segs[1].isdigit():
        if len(segs) >= 3 and segs[2] in ("pci", "iso"):
            return f"/engagements/{segs[1]}/{segs[2]}"
        return f"/engagements/{segs[1]}"
    return "/" + "/".join(segs[:-1]) if len(segs) > 1 else "/"


def anchor_for(path: str) -> str:
    for suffix, anchor in ANCHORS:
        if suffix in path:
            return anchor
    return ""


def error_page(request: Request, status_code: int, detail: str | None = None):
    from attestra.web.ui import _render

    title, message = STATUS_TEXT.get(status_code, ("Something went wrong", "The request couldn't be completed."))
    shown = detail if detail and detail.lower() not in (title.lower(), "not found", "forbidden") else None
    return _render(request, "error.html", {"status_code": status_code, "title": title, "message": message,
                                           "detail": shown}, status_code=status_code)


def install(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError):
        if wants_html(request):
            url = back_url(request)
            anchor = anchor_for(request.url.path)
            return RedirectResponse(f"{url}?error={quote(friendly_validation_message(exc))}{anchor}", status_code=303)
        return await request_validation_exception_handler(request, exc)

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException):
        if wants_html(request) and exc.status_code >= 400:
            if exc.status_code == 401 and request.method == "GET":
                from attestra.web.ui import _login_redirect

                nxt = request.url.path + (f"?{request.url.query}" if request.url.query else "")
                return _login_redirect(nxt)
            resp = error_page(request, exc.status_code, str(exc.detail) if exc.detail else None)
            for k, v in (getattr(exc, "headers", None) or {}).items():
                resp.headers[k] = v
            return resp
        return await http_exception_handler(request, exc)
