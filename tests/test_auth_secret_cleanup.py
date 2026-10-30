"""Auth secret files never land in data/raw, are deleted when the scan ends (success,
failure, exception, cancel, Ctrl+C), and leftovers are swept on worker start."""
from __future__ import annotations

from pathlib import Path

import pytest

from attestra.auth_web import scan_auth
from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import ProcessResult, ScannerResult, redact_text

PIN = PinnedTarget(host="shop.example.com", ip="93.184.216.34", port=443, scheme="https")
TOKEN = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0LXVzZXIifQ.c2lnbmF0dXJlLXZhbHVl"


@pytest.fixture
def secret_root(tmp_path, monkeypatch):
    root = tmp_path / "secret-root"
    monkeypatch.setenv(scan_auth.SECRET_DIR_ENV, str(root))
    return root


# ------------------------------------------------------------------ run_one_job cleanup


class _FakeNuclei:
    name = "nuclei"

    def __init__(self, behavior, raw):
        self.behavior = behavior
        self.raw = raw
        self.seen_secret_file = None
        self.seen_exists = None

    def scan(self, target, *, out_dir, cancel=None, intrusive_allowed=False, **kw):
        sf = kw.get("auth_secret_file")
        self.seen_secret_file = sf
        self.seen_exists = bool(sf) and Path(sf).is_file()
        assert kw.get("redact_values"), "secret values for log redaction are passed"
        if self.behavior == "raise":
            raise RuntimeError("scanner crashed")
        if self.behavior == "ctrl_c":
            raise KeyboardInterrupt
        if self.behavior == "cancel":
            return ScannerResult(tool="nuclei", extra={"cancelled": True})
        if self.behavior == "timeout":
            return ScannerResult(tool="nuclei", error="nuclei timed out after 1s", extra={"timed_out": True})
        return ScannerResult(tool="nuclei", raw_path=self.raw, import_tool="nuclei", extra={"returncode": 0})


def _queued_nuclei_job(s, engagement):
    from attestra.jobs.durable import enqueue
    from attestra.models import Asset, ScanRun

    asset = s.query(Asset).filter(Asset.engagement_id == engagement, Asset.kind == "web_app").first()
    run = ScanRun(
        engagement_id=engagement, asset_id=asset.id, tool="nuclei", profile="baseline",
        status="queued", requested_by="lead", auth_profile_id=1,
    )
    s.add(run)
    s.flush()
    job = enqueue(s, run.id)
    job.status = "running"
    s.flush()
    return run, job


@pytest.mark.parametrize("behavior", ["success", "raise", "cancel", "timeout", "ctrl_c"])
def test_secret_dir_removed_whatever_the_scan_outcome(engagement, secret_root, monkeypatch, tmp_path, behavior):
    import attestra.config as cfg
    from attestra import db
    from attestra.jobs import durable
    from attestra.runner import crawl as crawl_mod

    monkeypatch.setattr(cfg, "AUTH_WEB_ENABLED", True)
    monkeypatch.setattr(durable, "check", lambda *a, **k: PIN)
    monkeypatch.setattr(crawl_mod, "scan_kwargs", lambda *a, **k: {})

    created: dict = {}

    def fake_prepare(s, run, out_dir, *, tool, target_url, **kw):
        sdir = scan_auth.new_secret_dir(run.id)
        created["dir"] = sdir
        plan = scan_auth.ScanAuthPlan(status="ready", method="header", authenticated=True, note="ok")
        plan.secret_dir = str(sdir)
        plan.redact_values = (TOKEN,)
        plan.nuclei_secret_file = scan_auth.write_nuclei_secret_file(
            sdir, target_url, {"Authorization": TOKEN}, {}
        )
        return plan

    monkeypatch.setattr(scan_auth, "prepare_for_run", fake_prepare)
    raw = tmp_path / "nuclei-out.jsonl"
    raw.write_bytes(b"")
    fake = _FakeNuclei(behavior, raw)
    monkeypatch.setattr(durable, "get_adapter", lambda tool: fake)

    with db.session() as s:
        run, job = _queued_nuclei_job(s, engagement)
        if behavior == "ctrl_c":
            with pytest.raises(KeyboardInterrupt):
                durable.run_one_job(s, job)
        else:
            durable.run_one_job(s, job)
        out_dir = cfg.DATA_DIR / "raw" / f"scan-{run.id}"

    assert fake.seen_exists is True  # the scanner did get the file while it ran
    sdir = created["dir"]
    assert sdir.parent == secret_root  # outside data/raw
    assert not sdir.exists(), f"secret dir left behind after {behavior}"
    # nothing secret was ever written into the raw artifact dir
    if out_dir.exists():
        for f in out_dir.rglob("*"):
            if f.is_file():
                assert "eyJ" not in f.read_text(errors="replace")


def test_prepare_failure_leaves_no_secret_dir(engagement, secret_root, monkeypatch):
    """A failed write after the dir was created must not leave the dir behind."""
    from types import SimpleNamespace

    monkeypatch.setattr(scan_auth, "load_profile_for_run", lambda s, run: SimpleNamespace(
        id=1, method="header", label="x", role_name="", secret_ref="ref", config_json={},
        login_url="", status="active",
    ))
    import attestra.credentials as creds

    monkeypatch.setattr(creds, "get_secret", lambda ref: "tok-value-123")

    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(scan_auth, "write_nuclei_secret_file", boom)
    run = SimpleNamespace(id=77, auth_profile_id=1, engagement_id=1)
    with pytest.raises(OSError):
        scan_auth.prepare_for_run(None, run, secret_root.parent / "raw-out", tool="nuclei",
                                  target_url="https://shop.example.com/", verify=False)
    assert not any(secret_root.glob("scan-77-*"))


def test_secret_dir_refuses_raw_artifact_dir(tmp_path, monkeypatch):
    import attestra.config as cfg

    monkeypatch.setattr(cfg, "DATA_DIR", tmp_path / "data")
    monkeypatch.setenv(scan_auth.SECRET_DIR_ENV, str(tmp_path / "data" / "raw" / "x"))
    with pytest.raises(scan_auth.ScanAuthError):
        scan_auth.new_secret_dir(1)


# ------------------------------------------------------------------ startup sweep


def test_sweep_removes_leaked_files_except_running_scans(tmp_path, secret_root):
    raw = tmp_path / "raw"
    for n in (11, 12, 13):
        d = raw / f"scan-{n}"
        d.mkdir(parents=True)
        (d / "attestra-nuclei-auth.yaml").write_text("static: []")
        (d / "attestra-zap-hook-data.json").write_text("{}")
        (d / "attestra-zap-hooks.py").write_text("# hook")
        (d / "nuclei-out.jsonl").write_text("{}")  # a real artifact: must stay
    (raw / "scan-12" / "__pycache__").mkdir()
    (raw / "scan-12" / "__pycache__" / "attestra-zap-hooks.cpython-311.pyc").write_bytes(b"x")
    secret_root.mkdir()
    (secret_root / "scan-12-abc").mkdir()
    (secret_root / "scan-12-abc" / "attestra-nuclei-auth.yaml").write_text("x")
    (secret_root / "scan-13-def").mkdir()

    removed = scan_auth.sweep_leftover_secrets(raw, active_run_ids={13})

    for n in (11, 12):
        d = raw / f"scan-{n}"
        assert not (d / "attestra-nuclei-auth.yaml").exists()
        assert not (d / "attestra-zap-hook-data.json").exists()
        assert not (d / "attestra-zap-hooks.py").exists()
        assert (d / "nuclei-out.jsonl").exists()
    assert not (raw / "scan-12" / "__pycache__" / "attestra-zap-hooks.cpython-311.pyc").exists()
    assert not (secret_root / "scan-12-abc").exists()
    # running scan untouched
    assert (raw / "scan-13" / "attestra-nuclei-auth.yaml").exists()
    assert (secret_root / "scan-13-def").exists()
    assert "scan-11/attestra-nuclei-auth.yaml" in removed
    assert all("static" not in r for r in removed)  # names only, never content


def test_sweep_auth_secrets_uses_live_jobs(engagement, secret_root, monkeypatch):
    import attestra.config as cfg
    from attestra import db
    from attestra.jobs import durable
    from attestra.models import utcnow

    with db.session() as s:
        run, job = _queued_nuclei_job(s, engagement)
        job.heartbeat_at = utcnow()
        s.flush()
        live = cfg.DATA_DIR / "raw" / f"scan-{run.id}"
        dead = cfg.DATA_DIR / "raw" / "scan-99999"
        for d in (live, dead):
            d.mkdir(parents=True, exist_ok=True)
            (d / "attestra-nuclei-auth.yaml").write_text("x")
        durable.sweep_auth_secrets(s)
    assert (live / "attestra-nuclei-auth.yaml").exists()
    assert not (dead / "attestra-nuclei-auth.yaml").exists()


# ------------------------------------------------------------------ adapters


def test_nuclei_docker_argv_mounts_secret_dir_readonly(tmp_path, monkeypatch):
    import attestra.config as cfg
    from attestra.runner.scanners.nuclei import CONTAINER_SECRETS, NucleiAdapter

    monkeypatch.setitem(cfg.SCANNER_IMAGES, "nuclei", "projectdiscovery/nuclei@sha256:" + "a" * 64)
    monkeypatch.setattr(cfg, "SCANNER_CACHE_DIR", tmp_path / "cache")
    out = tmp_path / "raw" / "scan-1"
    out.mkdir(parents=True)
    sdir = tmp_path / "secrets" / "scan-1-x"
    sdir.mkdir(parents=True)
    sf = sdir / "attestra-nuclei-auth.yaml"
    sf.write_text("static: []")
    argv = NucleiAdapter().build_docker_argv(PIN, out_file=out / "nuclei-out.jsonl", auth_secret_file=str(sf))
    assert f"{Path(sdir).resolve()}:{CONTAINER_SECRETS}:ro" in argv
    assert argv[argv.index("-sf") + 1] == f"{CONTAINER_SECRETS}/attestra-nuclei-auth.yaml"
    assert "-silent" not in argv and "-stats" in argv
    with pytest.raises(ValueError):
        NucleiAdapter().build_docker_argv(PIN, out_file=out / "nuclei-out.jsonl", auth_secret_file=str(out / "a.yaml"))


def test_nuclei_fatal_with_empty_output_is_a_failure(tmp_path):
    from attestra.runner.scanners.nuclei import _fail_on_fatal_empty

    raw = tmp_path / "nuclei-out.jsonl"
    raw.write_bytes(b"")
    sr = ScannerResult(tool="nuclei", raw_path=raw, extra={
        "returncode": 1,
        "stderr": "[FTL] Could not run nuclei: failed to load dynamic auth templates",
    })
    _fail_on_fatal_empty(sr)
    assert sr.raw_path is None and "failed to load dynamic auth" in sr.error
    ok = ScannerResult(tool="nuclei", raw_path=raw, extra={"returncode": 0, "stderr": "[INF] Scan completed"})
    _fail_on_fatal_empty(ok)
    assert ok.raw_path == raw and not ok.error


def test_tool_log_is_redacted(tmp_path):
    from attestra.runner.scanners.nuclei import STDERR_LOG_NAME, NucleiAdapter

    res = ProcessResult(returncode=1, stdout=b"", stderr=(
        f"[DBG] Authorization: {TOKEN}\nraw token {TOKEN[7:]}\nCookie: sid=abcdef123\n[FTL] boom\n"
    ).encode())
    NucleiAdapter()._write_tool_log(tmp_path, res, (TOKEN, TOKEN[7:]))
    text = (tmp_path / STDERR_LOG_NAME).read_text()
    assert "eyJ" not in text and "abcdef123" not in text
    assert "[FTL] boom" in text and "exit code 1" in text
    assert "c2lnbmF0dXJl" not in redact_text("x eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl y")


def test_zap_argv_single_hook_and_readonly_secret_mount(tmp_path, monkeypatch):
    import attestra.config as cfg
    from attestra.runner.scanners.zap import ZAP_SECRETS, ZapAdapter

    monkeypatch.setattr(cfg, "AUTH_WEB_ENABLED", True)
    monkeypatch.setitem(cfg.SCANNER_IMAGES, "zap", "ghcr.io/zaproxy/zaproxy@sha256:" + "b" * 64)
    out = tmp_path / "raw" / "scan-2"
    out.mkdir(parents=True)
    sdir = tmp_path / "secrets" / "scan-2-x"
    path = scan_auth.write_zap_hook(sdir, {"Authorization": TOKEN}, {}, target_url="https://shop.example.com/")
    argv = ZapAdapter().build_argv(
        PIN, out_file=out / "zap-report.json", auth_opts={"headers_file": path, "secret_dir": str(sdir)}
    )
    assert argv.count("--hook") == 1
    assert f"{sdir.resolve()}:{ZAP_SECRETS}:ro" in argv
    assert TOKEN not in " ".join(argv)
    assert not (out / "attestra-zap-hook-data.json").exists()
    # auth flag off => no secret mount
    monkeypatch.setattr(cfg, "AUTH_WEB_ENABLED", False)
    argv2 = ZapAdapter().build_argv(PIN, out_file=out / "zap-report.json", auth_opts={"headers_file": path})
    assert not any(ZAP_SECRETS in a for a in argv2)
