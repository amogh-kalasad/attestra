"""G-01 hardened KEV/EPSS feed store + G-02 NVD parsing (offline fixtures only)."""
# @lat: [[intel-and-reporting#Feed store and freshness]]

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from attestra.intel import feed_store, freshness, nvd

FIXTURES = Path(__file__).parent / "fixtures"
KEV = (FIXTURES / "kev.json").read_bytes()
EPSS = (FIXTURES / "epss.csv").read_bytes()


def test_valid_feeds_store_and_load(tmp_path):
    e1 = feed_store.store_feed("kev", KEV, source="fixture", directory=tmp_path)
    e2 = feed_store.store_feed("epss", EPSS, source="fixture", directory=tmp_path)
    assert e1["status"] == "ok" and e1["records"] == 2 and e1["schema"] == feed_store.SCHEMAS["kev"]
    assert e2["status"] == "ok" and e2["records"] >= 3
    snap = feed_store.load_validated(tmp_path)
    assert "CVE-2024-9999" in snap.kev
    assert snap.epss["CVE-2024-9999"] == pytest.approx(0.9743)
    assert snap.kev_known and snap.epss_known
    assert snap.source_version.startswith("fs1;kev=2026.10.01@")


@pytest.mark.parametrize(
    "bad",
    [b"", b"{not json", b'{"vulnerabilities": []}', b'{"count": 5, "vulnerabilities": [{"cveID": "CVE-2024-0001"}]}',
     b'{"vulnerabilities": [{"cveID": "nope"}, {"cveID": "bad"}]}'],
)
def test_corrupt_kev_keeps_previous_file(tmp_path, bad):
    feed_store.store_feed("kev", KEV, directory=tmp_path)
    before = (tmp_path / "kev.json").read_bytes()
    with pytest.raises(feed_store.FeedValidationError):
        feed_store.store_feed("kev", bad, directory=tmp_path)
    assert (tmp_path / "kev.json").read_bytes() == before
    st = feed_store.load_state(tmp_path)["kev"]
    assert st["status"] == "error" and st["last_error"]
    # enrichment input is still the last good copy
    assert "CVE-2024-9999" in feed_store.load_validated(tmp_path).kev


def test_corrupt_epss_rows_rejected(tmp_path):
    feed_store.store_feed("epss", EPSS, directory=tmp_path)
    with pytest.raises(feed_store.FeedValidationError):
        feed_store.store_feed("epss", b"cve,epss\nCVE-2024-1,abc\nCVE-2024-2,7\n", directory=tmp_path)
    with pytest.raises(feed_store.FeedValidationError):
        feed_store.store_feed("epss", b"id,score\nCVE-2024-1111,0.1\n", directory=tmp_path)
    assert (tmp_path / "epss.csv").read_bytes() == EPSS


def test_epss_gzip_and_comment_header(tmp_path):
    raw = b"#model_version:v2025.03.14,score_date:2026-11-16T00:00:00+0000\ncve,epss,percentile\nCVE-2024-1111,0.5,0.9\n"
    entry = feed_store.store_feed("epss", gzip.compress(raw), directory=tmp_path)
    assert entry["meta"]["score_date"].startswith("2026-11-16")
    assert (tmp_path / "epss.csv").read_bytes() == raw


def test_idempotent_rerun(tmp_path):
    feed_store.store_feed("kev", KEV, directory=tmp_path, now="2026-11-17T00:00:00+00:00")
    again = feed_store.store_feed("kev", KEV, directory=tmp_path, now="2026-11-17T06:00:00+00:00")
    assert again["unchanged"] is True
    assert again["fetched_at"] == "2026-11-17T00:00:00+00:00"
    assert again["checked_at"] == "2026-11-17T06:00:00+00:00"
    assert not (tmp_path / "kev.json.prev").exists()


def test_corrupt_live_file_falls_back_to_prev(tmp_path):
    feed_store.store_feed("kev", KEV, directory=tmp_path)
    doc = json.loads(KEV)
    doc["vulnerabilities"].append({"cveID": "CVE-2025-0002"})
    doc["count"] = 3
    feed_store.store_feed("kev", json.dumps(doc).encode(), directory=tmp_path)
    (tmp_path / "kev.json").write_bytes(b"\x00garbage")  # simulated disk corruption
    snap = feed_store.load_validated(tmp_path)
    assert snap.used_fallback == ["kev"]
    assert snap.kev == {"CVE-2024-9999", "CVE-2023-0001"}


def test_stale_detection():
    now = datetime(2026, 11, 17, tzinfo=UTC)
    fresh = freshness.feed_freshness("kev", (now - timedelta(hours=10)).isoformat(), now=now)
    old = freshness.feed_freshness("kev", (now - timedelta(days=5)).isoformat(), now=now)
    missing = freshness.feed_freshness("epss", None, now=now)
    assert fresh["stale"] is False and fresh["known"] is True
    assert old["stale"] is True
    assert missing["stale"] is True and missing["known"] is False
    rep = freshness.freshness_report({"kev": {"last_good_at": (now - timedelta(days=5)).isoformat()}}, now=now)
    assert rep["stale_inputs"] == ["kev", "epss"]


def test_missing_feeds_are_unknown_not_empty(tmp_path):
    snap = feed_store.load_validated(tmp_path)
    assert not snap.kev_known and not snap.epss_known
    assert set(snap.freshness["stale_inputs"]) == {"kev", "epss"}
    assert snap.freshness["feeds"]["kev"]["status"] == "missing"


def test_refresh_feeds_validates_before_write(tmp_path, monkeypatch):
    from attestra import config
    from attestra.ops import feeds

    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "ensure_dirs", lambda: None)
    payload = {"kev": KEV, "epss": EPSS}

    class _Resp:
        def __init__(self, data):
            self._data = data

        def read(self):
            return self._data

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(feeds, "urlopen", lambda url, timeout=60: _Resp(payload["kev" if "kev" in url else "epss"]))
    meta = feeds.refresh_feeds(kev_url="https://x/kev.json", epss_url="https://x/epss.csv")
    assert meta["kev_date"].startswith("2026-10-01")
    good_kev = (tmp_path / "feeds" / "kev.json").read_bytes()

    payload["kev"] = b'{"truncated": '
    with pytest.raises(feeds.FeedError, match="KEV feed rejected"):
        feeds.refresh_feeds(kev_url="https://x/kev.json", epss_url="https://x/epss.csv")
    assert (tmp_path / "feeds" / "kev.json").read_bytes() == good_kev
    kev, epss = feeds.load_cached_feeds()
    assert kev == good_kev and epss == EPSS

    def boom(url, timeout=60):
        raise OSError("network down")

    monkeypatch.setattr(feeds, "urlopen", boom)
    with pytest.raises(feeds.FeedError, match="download failed"):
        feeds.refresh_feeds(kev_url="https://x/kev.json", epss_url="https://x/epss.csv")
    assert (tmp_path / "feeds" / "kev.json").read_bytes() == good_kev
    assert feed_store.load_state(tmp_path / "feeds")["epss"]["status"] == "error"


# ------------------------------------------------------------------ G-02 NVD

NVD_PAGE = {
    "resultsPerPage": 2, "startIndex": 0, "totalResults": 2, "format": "NVD_CVE", "version": "2.0",
    "timestamp": "2026-11-17T00:00:00.000",
    "vulnerabilities": [
        {"cve": {"id": "CVE-2024-9999", "published": "2024-11-01T00:00:00.000", "lastModified": "2026-11-01T00:00:00.000",
                 "vulnStatus": "Analyzed", "descriptions": [{"lang": "en", "value": "Example RCE"}],
                 "weaknesses": [{"description": [{"lang": "en", "value": "CWE-502"}]}],
                 "metrics": {"cvssMetricV40": [{"type": "Primary", "cvssData": {
                     "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "baseScore": 9.3}}],
                     "cvssMetricV31": [{"type": "Primary", "cvssData": {
                         "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseScore": 9.8}}]}}},
        {"cve": {"id": "CVE-2023-0001", "weaknesses": [{"description": [{"value": "NVD-CWE-noinfo"}]}],
                 "metrics": {"cvssMetricV40": [{"cvssData": {
                     "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "baseScore": 5.0}}]}}},
    ],
}


def test_nvd_parse_and_rescore():
    recs, meta = nvd.parse_response(json.dumps(NVD_PAGE).encode())
    assert meta["records"] == 2 and meta["schema"] == nvd.SCHEMA
    r = recs["CVE-2024-9999"]
    assert r.cwes == [502] and r.cvss40_local_score == 9.3 and r.cvss40_mismatch is False
    assert r.cvss31_score == 9.8
    assert recs["CVE-2023-0001"].cvss40_mismatch is True  # NVD 5.0 vs computed 9.3 is surfaced
    assert nvd.loads(nvd.dumps(recs))["CVE-2024-9999"]["cvss40_score"] == 9.3


def test_nvd_rejects_malformed_and_refresh_pages():
    with pytest.raises(nvd.NvdError):
        nvd.parse_response(b"{}")
    with pytest.raises(nvd.NvdError):
        nvd.parse_response(b'{"vulnerabilities": [{"cve": {"id": "bad"}}]}')
    urls = []

    def fetch(url):
        urls.append(url)
        return json.dumps(NVD_PAGE).encode()

    recs, meta = nvd.refresh(fetch, last_mod_start="2026-11-16T00:00:00.000", last_mod_end="2026-11-17T00:00:00.000")
    assert meta["complete"] is True and meta["pages"] == 1 and len(recs) == 2
    assert "lastModStartDate" in urls[0] and "apiKey" not in urls[0]
