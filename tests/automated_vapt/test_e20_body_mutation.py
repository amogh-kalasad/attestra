"""E20 body mutation (T22): guarded write-method object-id swaps (mocked HTTP)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from attestra.automated_vapt.core import body_mutation as bm
from attestra.automated_vapt.core import js_api_discovery as jsd
from attestra.automated_vapt.core.session_auth import SessionAuth
from attestra.automated_vapt.core.test_registry import get_test_case
from attestra.proof.pair import HttpPair

ROOT = "https://demo.example/"


def _pair(method: str, url: str, status: int, body: str, *, req_body: str = "", auth_header: str | None = None) -> HttpPair:
    req = {"user-agent": "test", "content-type": "application/json"}
    if auth_header:
        req["authorization"] = auth_header
    return HttpPair(
        method=method,
        url=url,
        request_headers=req,
        request_body=req_body,
        status=status,
        response_headers={"content-type": "application/json"},
        response_body=body,
        source="test",
    )


class FakeTx:
    def __init__(self, pair: HttpPair):
        self.pair = pair
        self.report_pair = pair.redacted()


def _auth(ready: bool = True) -> SessionAuth:
    return SessionAuth(
        profile_id=2,
        status="ready" if ready else "failed",
        note="login check passed" if ready else "failed",
        headers={"Authorization": "Bearer SECRETtokenXYZ"} if ready else {},
        redact_values=("SECRETtokenXYZ",),
    )


def _ctx(*, write_captures=None, responses=None, secondary=None, auth_ready=True):
    extra = {
        "_session_auth": _auth(auth_ready),
        "_write_captures": list(write_captures or []),
        "_http_pairs": [],
        "_js_api": {"endpoints_list": []},
        "_fake_responses": dict(responses or {}),
    }
    if secondary is not None:
        extra["_secondary_session_auth"] = secondary
    return SimpleNamespace(
        target_base_url=ROOT,
        profile="baseline",
        allow_private=True,
        engagement_id=1,
        extra=extra,
    )


@pytest.fixture
def patch_capture(monkeypatch):
    def install(ctx):
        queues = {u: list(v) for u, v in ctx.extra["_fake_responses"].items()}
        calls: list[dict] = []

        def fake_capture(method, url, **kwargs):
            calls.append({"method": method, "url": url, "content": kwargs.get("content")})
            hdrs = kwargs.get("headers") or {}
            q = queues.setdefault(url, [])
            if not q:
                status, body = 404, '{"status":"error"}'
            else:
                status, body = q.pop(0)
            auth_h = hdrs.get("Authorization") or hdrs.get("authorization")
            req_body = kwargs.get("content") or ""
            if isinstance(req_body, bytes):
                req_body = req_body.decode("utf-8", errors="replace")
            return FakeTx(
                _pair(method, url, status, body, req_body=str(req_body), auth_header=auth_h)
            )

        monkeypatch.setattr(
            "attestra.automated_vapt.capture.http_capture.capture_request",
            fake_capture,
        )
        return calls

    return install


def test_registry_lists_t22():
    c = get_test_case("T22")
    assert c is not None
    assert c.category == "authorization"
    assert "MUTATION" in c.description or "mutation" in c.description.lower()


def test_swap_body_ids_and_find_fields():
    body = '{"projectId": 42, "name": "x", "stakeholderId": "abc"}'
    fields = bm.find_body_id_fields(body)
    keys = {k for _, k, _ in fields}
    assert "project_id" in keys
    assert "stakeholder_id" in keys
    new, changed = bm.swap_body_ids(body, "99")
    assert "99" in new
    assert "projectId" in changed
    assert "stakeholderId" in changed


def test_t22_skipped_when_mutation_disabled(monkeypatch, patch_capture):
    monkeypatch.setattr(bm, "mutation_flag_enabled", lambda: False)
    monkeypatch.setattr(bm, "mutation_sends_allowed", lambda: False)
    captures = [
        {
            "method": "POST",
            "url": ROOT + "api/projects/update",
            "body": '{"projectId": 10, "title": "a"}',
        }
    ]
    ctx = _ctx(write_captures=captures)
    calls = patch_capture(ctx)
    result = bm.run_object_mutation(ctx, clock_sleep=lambda _s: None)
    assert result["status"] == "SKIPPED"
    assert "disabled" in result["detail"].lower() or "dry-run" in result["detail"].lower()
    assert result["mutation"]["dry_run"] is True
    assert result["mutation"]["planned"]
    assert calls == []  # no HTTP


def test_t22_detects_when_mutation_enabled(monkeypatch, patch_capture):
    monkeypatch.setattr(bm, "mutation_flag_enabled", lambda: True)
    monkeypatch.setattr(bm, "mutation_sends_allowed", lambda: True)
    url = ROOT + "api/projects/update-meta"
    captures = [
        {
            "method": "PUT",
            "url": url,
            "body": '{"projectId": 10, "title": "mine"}',
        }
    ]
    # orig then probe
    responses = {
        url: [
            (200, '{"projectId": 10, "title": "mine", "ok": true}'),
            (200, '{"projectId": 11, "title": "mine", "ok": true}'),
        ]
    }
    ctx = _ctx(write_captures=captures, responses=responses)
    calls = patch_capture(ctx)
    result = bm.run_object_mutation(ctx, clock_sleep=lambda _s: None, dry_run=False)
    assert result["status"] == "FINDING"
    assert result["finding_count"] == 1
    assert len(calls) == 2
    assert calls[0]["method"] == "PUT"
    assert calls[1]["method"] == "PUT"
    # foreign neighbour of 10 should appear in second body
    content1 = calls[1]["content"]
    if isinstance(content1, bytes):
        content1 = content1.decode()
    assert "11" in content1 or "9" in content1 or "12" in content1 or "13" in content1
    assert result.get("finding_evidence_pairs")


def test_t22_passed_when_server_rejects(monkeypatch, patch_capture):
    monkeypatch.setattr(bm, "mutation_flag_enabled", lambda: True)
    monkeypatch.setattr(bm, "mutation_sends_allowed", lambda: True)
    url = ROOT + "api/projects/update-meta"
    captures = [
        {
            "method": "PATCH",
            "url": url,
            "body": '{"projectId": 10, "title": "mine"}',
        }
    ]
    responses = {
        url: [
            (200, '{"projectId": 10, "title": "mine", "ok": true}'),
            (403, '{"status":"error","message":"forbidden"}'),
        ]
    }
    ctx = _ctx(write_captures=captures, responses=responses)
    patch_capture(ctx)
    result = bm.run_object_mutation(ctx, clock_sleep=lambda _s: None, dry_run=False)
    assert result["status"] == "PASSED"
    assert result["finding_count"] == 0


def test_t22_skips_delete_and_unsafe_paths(monkeypatch, patch_capture):
    monkeypatch.setattr(bm, "mutation_flag_enabled", lambda: True)
    monkeypatch.setattr(bm, "mutation_sends_allowed", lambda: True)
    captures = [
        {"method": "DELETE", "url": ROOT + "api/projects/1", "body": '{"id": 1}'},
        {"method": "POST", "url": ROOT + "api/projects/delete", "body": '{"projectId": 1}'},
        {"method": "POST", "url": ROOT + "api/transfer/ownership", "body": '{"projectId": 1}'},
    ]
    ctx = _ctx(write_captures=captures)
    calls = patch_capture(ctx)
    result = bm.run_object_mutation(ctx, clock_sleep=lambda _s: None, dry_run=False)
    assert result["status"] == "SKIPPED"
    assert result["mutation"]["templates"] == 0
    assert calls == []


def test_t22_skips_without_auth(monkeypatch, patch_capture):
    monkeypatch.setattr(bm, "mutation_flag_enabled", lambda: True)
    monkeypatch.setattr(bm, "mutation_sends_allowed", lambda: True)
    ctx = _ctx(
        auth_ready=False,
        write_captures=[{"method": "POST", "url": ROOT + "api/x", "body": '{"id": 1}'}],
    )
    patch_capture(ctx)
    result = bm.run_object_mutation(ctx, clock_sleep=lambda _s: None)
    assert result["status"] == "SKIPPED"
    assert "not ready" in result["detail"].lower()


def test_find_body_id_fields_project_name():
    body = '{"date": "2024-01-01", "projectName": "Alpha", "endDate": "2024-01-02"}'
    fields = bm.find_body_id_fields(body)
    keys = {k for _, k, _ in fields}
    assert "project_name" in keys
    new, changed = bm.swap_body_ids(body, "OtherProj")
    assert "OtherProj" in new
    assert "projectName" in changed


def test_find_body_id_fields_null_project_name():
    body = '{"date":"2026-11-02T05:48:07.797Z","projectName":null,"endDate":"2026-11-02T05:48:07.797Z"}'
    fields = bm.find_body_id_fields(body)
    assert any(r == "projectName" and v == "null" for r, _, v in fields)
    new, changed = bm.swap_body_ids(body, "OtherProj")
    assert '"projectName": "OtherProj"' in new
    assert "projectName" in changed
