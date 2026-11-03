"""E21: write-body capture for T22 (parser, persist, T22 load)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from attestra.automated_vapt.capture import write_body_capture as wbc
from attestra.automated_vapt.core import body_mutation as bm
from attestra.automated_vapt.core.session_auth import SessionAuth


def test_normalize_write_capture_redacts_and_keeps_json():
    cap = wbc.normalize_write_capture(
        method="POST",
        url="https://demo.example/api/projects/update",
        body='{"projectId": 10, "token": "SUPERSECRET", "title": "x"}',
        content_type="application/json",
        headers={"Authorization": "Bearer SUPERSECRET", "Content-Type": "application/json"},
        root="https://demo.example/",
    )
    assert cap is not None
    assert cap["method"] == "POST"
    assert "SUPERSECRET" not in cap["body"]
    assert "[REDACTED]" in cap["body"]
    assert cap["headers"]["Authorization"] == "[REDACTED]"
    assert "projectId" in cap["body"]


def test_normalize_skips_get_and_cross_host_and_non_json():
    assert (
        wbc.normalize_write_capture(
            method="GET",
            url="https://demo.example/api/x",
            body='{"id":1}',
            root="https://demo.example/",
        )
        is None
    )
    assert (
        wbc.normalize_write_capture(
            method="POST",
            url="https://other.example/api/x",
            body='{"id":1}',
            root="https://demo.example/",
        )
        is None
    )
    assert (
        wbc.normalize_write_capture(
            method="POST",
            url="https://demo.example/api/x",
            body="not-json",
            content_type="text/plain",
            root="https://demo.example/",
        )
        is None
    )


def test_save_and_load_write_bodies(tmp_path, monkeypatch):
    monkeypatch.setattr(wbc, "run_dir", lambda eid: tmp_path / f"automated-{eid}")
    bodies = [
        wbc.normalize_write_capture(
            method="PUT",
            url="https://demo.example/api/projects/1",
            body='{"projectId": 1, "name": "a"}',
            root="https://demo.example/",
        ),
        wbc.normalize_write_capture(
            method="PATCH",
            url="https://demo.example/api/clients/2",
            body='{"clientId": 2, "name": "b"}',
            root="https://demo.example/",
        ),
    ]
    path = wbc.save_write_bodies(99, [b for b in bodies if b])
    assert path.is_file()
    loaded = wbc.load_write_bodies(99)
    assert len(loaded) == 2
    summary = json.loads((tmp_path / "automated-99" / "captured-write-bodies.summary.json").read_text(encoding="utf-8"))
    assert summary["count"] == 2
    assert all("body" not in e for e in summary["entries"])
    assert {e["method"] for e in summary["entries"]} == {"PUT", "PATCH"}


def test_t22_loads_disk_bodies_in_dry_run(tmp_path, monkeypatch):
    monkeypatch.setattr(wbc, "run_dir", lambda eid: tmp_path / f"automated-{eid}")
    monkeypatch.setattr(bm, "mutation_flag_enabled", lambda: False)
    monkeypatch.setattr(bm, "mutation_sends_allowed", lambda: False)
    bodies = [
        {
            "method": "POST",
            "url": "https://demo.example/api/projects/update-meta",
            "body": '{"projectId": 10, "title": "mine"}',
            "headers": {},
        }
    ]
    wbc.save_write_bodies(42, bodies)
    auth = SessionAuth(profile_id=2, status="ready", note="ok", headers={}, redact_values=())
    ctx = SimpleNamespace(
        target_base_url="https://demo.example/",
        profile="baseline",
        allow_private=True,
        engagement_id=1,
        extra={"_session_auth": auth, "_write_captures": [], "execution_id": 42},
    )
    # Prefer disk via prefer_execution_id; also stub newest loader host scan root
    monkeypatch.setattr(
        wbc,
        "load_newest_write_bodies_for_host",
        lambda host, prefer_execution_id=None, raw_root=None: wbc.load_write_bodies(prefer_execution_id or 0),
    )
    result = bm.run_object_mutation(ctx, clock_sleep=lambda _s: None)
    assert result["status"] == "SKIPPED"
    assert result["mutation"]["templates"] >= 1 or result["mutation"]["planned"]
    # planned should mention the path without sending
    planned = result["mutation"].get("planned") or []
    assert planned
    assert planned[0]["method"] == "POST"


def test_public_summary_paths_only():
    s = wbc.public_summary(
        [{"method": "POST", "url": "https://x/api/a", "body": '{"password":"no"}'}]
    )
    assert s == [{"method": "POST", "path": "/api/a"}]


def test_collect_templates_includes_project_name_body(tmp_path, monkeypatch):
    monkeypatch.setattr(wbc, "run_dir", lambda eid: tmp_path / f"automated-{eid}")
    body = '{"date": "2024-01-01", "projectName": "Alpha", "endDate": "2024-01-02"}'
    cap = wbc.normalize_write_capture(
        method="POST",
        url="https://demo.example/api/projects/get-meeting-notes",
        body=body,
        root="https://demo.example/",
    )
    assert cap is not None
    wbc.save_write_bodies(42, [cap])
    ctx = SimpleNamespace(
        target_base_url="https://demo.example/",
        extra={"execution_id": 42, "_write_captures": [], "_http_pairs": []},
    )
    templates = bm.collect_write_templates(ctx)
    assert any(t["method"] == "POST" and "get-meeting-notes" in t["url"] for t in templates)
