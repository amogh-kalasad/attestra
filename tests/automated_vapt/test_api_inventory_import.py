"""C-01/02/03 importers: valid, malformed, unsupported constructs, dedup, scope, size, storage."""

from __future__ import annotations

from pathlib import Path

import pytest

from attestra.automated_vapt.api_inventory import SpecError, detect_kind, parse_spec
from attestra.automated_vapt.api_inventory import store as inv_store
from attestra.automated_vapt.api_inventory.model import normalize_path

SPECS = Path(__file__).parent / "fixtures" / "api_specs"
SCOPE = ["https://app.example.test"]


def _load(name: str, **kw):
    return parse_spec((SPECS / name).read_bytes(), name, **kw)


def test_openapi3_operations_refs_servers_and_unsupported():
    inv = _load("openapi3.json", allowed_origins=SCOPE)
    assert inv.kind == "openapi3" and inv.spec_version == "3.0.3"
    keys = {(o.method, o.path) for o in inv.operations}
    assert ("GET", "/api/users") not in keys  # server path is kept in server, not path
    assert ("GET", "/users") in keys and ("DELETE", "/users/{id}") in keys
    users = next(o for o in inv.operations if o.key == ("GET", "/users"))
    assert users.server == "https://app.example.test/api"
    assert [p.name for p in users.params] == ["page"]
    assert users.security == ["bearerAuth"]
    constructs = {u["construct"] for u in inv.unsupported}
    assert {"external_ref", "callbacks", "links"} <= constructs
    assert len(inv.sha256) == 64
    s = inv.summary()
    assert s["mutating_ops"] == 3 and s["templated_ops"] == 2


def test_swagger2_yaml():
    inv = _load("swagger2.yaml", allowed_origins=SCOPE)
    assert inv.kind == "swagger2"
    put = next(o for o in inv.operations if o.method == "PUT")
    assert put.request_content_types == ["application/json"]
    assert all(o.server == "https://app.example.test/v1" for o in inv.operations)


def test_postman_folders_variables_dedup_scope_and_scripts():
    inv = _load("postman.json", allowed_origins=SCOPE)
    keys = [(o.method, o.path) for o in inv.operations]
    assert keys.count(("GET", "/api/projects")) == 1 and inv.duplicates_merged == 1
    assert ("GET", "/api/projects/{projectId}") in keys
    other = next(o for o in inv.operations if o.path == "/api/x")
    assert other.in_scope is False
    gql = next(o for o in inv.operations if o.path == "/graphql")
    assert "graphql" in gql.tags
    assert "collection_scripts" in {u["construct"] for u in inv.unsupported}
    assert any("outside the target scope" in w for w in inv.warnings)


def test_har_keeps_names_never_values():
    inv = _load("sample.har", allowed_origins=SCOPE)
    doc = str(inv.to_doc())
    for secret in ("SECRET-QUERY-VALUE", "SECRET-HAR-TOKEN", "SECRET-COOKIE", "SECRET-BODY"):
        assert secret not in doc
    me = next(o for o in inv.operations if o.method == "GET")
    assert [p.name for p in me.params] == ["token"]
    assert me.security == ["authorization", "cookie"]
    assert {u["construct"] for u in inv.unsupported} == {"non_http_entry"}
    assert len(inv.operations) == 2  # static JS skipped


@pytest.mark.parametrize("name", ["malformed.json", "unsupported_version.json"])
def test_malformed_and_unsupported_versions_rejected(name):
    with pytest.raises(SpecError):
        _load(name)


def test_unknown_format_and_size_limit(monkeypatch):
    with pytest.raises(SpecError):
        detect_kind({"hello": 1})
    monkeypatch.setenv("ATTESTRA_API_SPEC_MAX_BYTES", "1024")
    with pytest.raises(SpecError):
        parse_spec(b"{" + b" " * 2048 + b"}", "big.json")


def test_normalize_path():
    assert normalize_path("/a/:id/b") == "/a/{id}/b"
    assert normalize_path("/a/<int:id>") == "/a/{id}"
    assert normalize_path("https://h/x//y/?q=1") == "/x/y"


def test_store_versions_and_sha_dedup_per_tenant():
    be = inv_store.MemoryBackend()
    a = _load("openapi3.json")
    s1 = inv_store.save(a, tenant_id=1, engagement_id=2, asset_id=3, actor="t", backend=be)
    s2 = inv_store.save(_load("openapi3.json"), tenant_id=1, engagement_id=2, asset_id=3, backend=be)
    s3 = inv_store.save(_load("swagger2.yaml"), tenant_id=1, engagement_id=2, asset_id=3, backend=be)
    other = inv_store.save(_load("openapi3.json"), tenant_id=9, engagement_id=2, asset_id=3, backend=be)
    assert (s1.version, s2.duplicate, s3.version, other.version) == (1, True, 2, 1)
    latest = inv_store.latest(tenant_id=1, engagement_id=2, asset_id=3, backend=be)
    assert latest is not None and latest.kind == "swagger2"
    assert inv_store.latest(tenant_id=5, engagement_id=2, asset_id=3, backend=be) is None
    assert [v.version for v in inv_store.list_versions(tenant_id=1, engagement_id=2, asset_id=3, backend=be)] == [2, 1]
    with pytest.raises(ValueError):
        inv_store.save(a, tenant_id=None, engagement_id=2, asset_id=3, backend=be)  # type: ignore[arg-type]


def test_upload_helper_flag_scope_versioning_and_errors(monkeypatch):
    """C-04 route helper without a database: flag gate, asset check, dedup, bad input."""
    from types import SimpleNamespace

    from attestra import services
    from attestra.automated_vapt import routes

    be = inv_store.MemoryBackend()
    monkeypatch.setattr(inv_store, "MongoBackend", lambda: be)
    eng = SimpleNamespace(id=2, tenant_id=1)
    asset = SimpleNamespace(id=3, engagement_id=2, kind="api", identifier="https://app.example.test/", api_base_url="")
    monkeypatch.setattr(services, "get_engagement", lambda s, eid, principal=None: eng)
    monkeypatch.setattr(services, "get_asset", lambda s, aid, principal=None: asset)
    who = SimpleNamespace(username="tester", role="tester")
    data = (SPECS / "openapi3.json").read_bytes()

    def call(body=data):
        return routes._api_spec_import(None, eid=2, aid=3, principal=who, filename="spec.json", data=body)

    monkeypatch.setenv("ATTESTRA_API_IMPORT_ENABLED", "0")
    with pytest.raises(services.ServiceError, match="disabled"):
        call()
    monkeypatch.setenv("ATTESTRA_API_IMPORT_ENABLED", "1")
    first = call()
    assert first["version"] == 1 and first["duplicate"] is False and first["summary"]["operations"] == 7
    assert call()["duplicate"] is True
    with pytest.raises(services.ServiceError, match="invalid API spec"):
        call(b"{not json")
    asset.engagement_id = 99
    with pytest.raises(LookupError):
        call()
