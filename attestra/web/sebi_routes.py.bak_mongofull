"""Staff UI routes for SEBI CSCRF security-testing timeline (Phase 8 P6-6).

Parent app must ``include_router`` this module's ``ui_router`` (see ``attestra/api.py``).
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from attestra import db, services
from attestra.compliance import sebi_timeline as sebi

ui_router = APIRouter(include_in_schema=False)


@ui_router.get("/engagements/{eid}/sebi-timeline", response_class=HTMLResponse)
def ui_sebi_timeline(request: Request, eid: int):
    """Staff page: SEBI CSCRF periodic security-testing milestones for an engagement."""
    from attestra.web.ui import READ_ONLY_ROLES, _back, _login_redirect, _render, _require_login

    principal, redirect = _require_login(request)
    if redirect:
        return redirect
    if principal is None:
        return _login_redirect(f"/engagements/{eid}/sebi-timeline")
    if principal.role in READ_ONLY_ROLES:
        return _back("/portal", error="That page is for the test team. Here is your read-only portal instead.")

    try:
        with db.session() as s:
            eng = services.get_engagement(s, eid, principal)
            timeline = sebi.build_timeline(s, eng)
            return _render(
                request,
                "sebi_timeline.html",
                {
                    "e": eng,
                    "timeline": timeline,
                    "milestones": timeline.get("milestones") or [],
                },
            )
    except LookupError as e:
        raise HTTPException(404, str(e).strip("'\"")) from e
