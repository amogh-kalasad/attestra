"""API routes: attach proof, list it, replay on retest, confirm the verdict."""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

from attestra import db, services
from attestra.models import Finding, ProofReplay
from attestra.proof import replay as replay_mod
from attestra.proof.pair import HttpPair, pair_from_raw
from attestra.proof.store import attach_http_pair, attach_screenshot, proof_items

router = APIRouter()


def _require(permission: str):
    from attestra.api import require

    return require(permission)


def _call(fn):
    try:
        with db.session() as s:
            return fn(s)
    except LookupError as e:
        raise HTTPException(404, str(e)) from e
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    except services.ServiceError as e:
        msg = str(e)
        raise HTTPException(403 if "not in scope" in msg or "not allowed" in msg or "only lead" in msg else 409, msg) from e


def _finding(s, fid: int, principal) -> Finding:
    f = s.get(Finding, fid)
    if not f:
        raise LookupError(f"finding {fid} not found")
    services.assert_engagement_access(s, f.engagement_id, principal)
    return f


class HttpPairIn(BaseModel):
    method: str = "GET"
    url: str = ""
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: str = ""
    status: int | None = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body: str = ""
    raw_request: str = Field("", description="alternative: raw HTTP request text")
    raw_response: str = Field("", description="alternative: raw HTTP response text")
    match: str = Field("", description="text whose presence in the response proves the issue")
    note: str = ""


class ReplayIn(BaseModel):
    evidence_id: int
    retest_id: int | None = None
    allow_unsafe_methods: bool = Field(False, description="lead/admin only: allow non GET/HEAD/OPTIONS replay")


class ConfirmIn(BaseModel):
    result: str = Field(description="fixed | still_open | inconclusive")
    note: str = ""


def _replay_out(r: ProofReplay) -> dict:
    return {
        "id": r.id, "finding_id": r.finding_id, "evidence_id": r.evidence_id, "response_evidence_id": r.response_evidence_id,
        "retest_id": r.retest_id, "method": r.method, "url": r.url, "status_code": r.status_code, "error": r.error,
        "suggested": r.suggested, "reason": r.reason, "confirmed_result": r.confirmed_result, "confirmed_by": r.confirmed_by,
    }


@router.post("/api/findings/{fid}/proof/http", status_code=201)
def add_http_proof(fid: int, body: HttpPairIn, principal=Depends(_require("finding.write"))):
    def fn(s):
        _finding(s, fid, principal)
        if body.raw_request:
            pair = pair_from_raw(body.raw_request, body.raw_response, url=body.url, match=body.match)
            HttpPair.from_dict({"method": pair.method, "url": pair.url})  # validates absolute URL
        else:
            pair = HttpPair.from_dict(body.model_dump())
        ev = attach_http_pair(s, fid, pair, actor=principal.actor, note=body.note)
        return {"id": ev.id, "sha256": ev.sha256}

    return _call(fn)


@router.post("/api/findings/{fid}/proof/screenshot", status_code=201)
async def add_screenshot(fid: int, note: str = Form(""), file: UploadFile = File(...), principal=Depends(_require("finding.write"))):
    data = await file.read()

    def fn(s):
        _finding(s, fid, principal)
        ev = attach_screenshot(s, fid, filename=file.filename or "screenshot.png", data=data, note=note, actor=principal.actor)
        return {"id": ev.id, "sha256": ev.sha256}

    return _call(fn)


@router.get("/api/findings/{fid}/proof")
def list_proof(fid: int, principal=Depends(_require("finding.read"))):
    from sqlalchemy import select

    def fn(s):
        _finding(s, fid, principal)
        items = [{"id": e.id, "kind": e.kind, "filename": e.filename, "sha256": e.sha256, "note": e.note, "captured_by": e.captured_by}
                 for e in proof_items(s, fid)]
        replays = [_replay_out(r) for r in s.scalars(select(ProofReplay).where(ProofReplay.finding_id == fid).order_by(ProofReplay.id))]
        return {"evidence": items, "replays": replays}

    return _call(fn)


@router.post("/api/findings/{fid}/proof/replay", status_code=201)
def replay_proof(fid: int, body: ReplayIn, principal=Depends(_require("retest.manage"))):
    def fn(s):
        _finding(s, fid, principal)
        r = replay_mod.replay(
            s, fid, body.evidence_id, actor=principal.actor, role=principal.role,
            allow_unsafe=body.allow_unsafe_methods, retest_id=body.retest_id,
        )
        return _replay_out(r)

    return _call(fn)


@router.post("/api/proof/replays/{rid}/confirm")
def confirm_replay(rid: int, body: ConfirmIn, principal=Depends(_require("retest.manage"))):
    def fn(s):
        r = s.get(ProofReplay, rid)
        if not r:
            raise LookupError(f"replay {rid} not found")
        _finding(s, r.finding_id, principal)
        return _replay_out(replay_mod.confirm(s, rid, result=body.result, actor=principal.actor, user_id=principal.user_id, note=body.note))

    return _call(fn)
