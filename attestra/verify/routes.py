"""Public HTTP routes for signed-report verification."""
# @lat: [[interfaces#Public report verification]]

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from attestra import db
from attestra.verify import service as verify

public_router = APIRouter(include_in_schema=False)

_NO_CACHE = {
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "X-Robots-Tag": "noindex, nofollow",
}


def _not_found() -> HTMLResponse:
    return HTMLResponse(
        (
            "<!doctype html><html lang=\"en\"><head>"
            "<meta charset=\"utf-8\">"
            "<meta name=\"robots\" content=\"noindex,nofollow\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            "<title>Not found</title></head>"
            "<body><p>Report verification link is not valid.</p></body></html>"
        ),
        status_code=404,
        headers=_NO_CACHE,
    )


@public_router.get("/verify/reports/{rid}", response_class=HTMLResponse)
def public_verify_report(request: Request, rid: int, sig: str = ""):
    """Unauthenticated page: hash, signer, date, and QR for a signed report."""
    from attestra.web.ui import templates

    base = str(request.base_url).rstrip("/")
    with db.session() as s:
        view = verify.public_view(s, rid, sig, base_url=base)
    if view is None:
        return _not_found()
    resp = templates.TemplateResponse(
        request,
        "verify_public.html",
        {"v": view},
    )
    for k, val in _NO_CACHE.items():
        resp.headers[k] = val
    return resp
