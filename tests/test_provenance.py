"""H-02 evidence provenance: never certainty, evidence bytes/hash untouched. No DB."""
# @lat: [[intel-and-reporting#Evidence provenance]]

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from attestra.finding_validation import provenance


def test_provenance_fields_and_age():
    now = datetime(2026, 11, 17, 12, tzinfo=UTC)
    prov = provenance.build(confidence=0.9, captured_at=now - timedelta(minutes=5), now=now, tool="automated_vapt",
                            rule_id="T05", rule_version="2", template_version="t1", run_validity={"state": "VALID"},
                            identity_label="tenant-a:standard-user", asset_snapshot_id=42, execution_id=9)
    assert prov["version"] == "prov1"
    assert prov["evidence_age_seconds"] == 300
    assert prov["run_validity"] == "VALID" and prov["identity_label"] == "tenant-a:standard-user"
    assert prov["asset_snapshot_id"] == "42" and prov["confidence_label"] == "high"
    assert provenance.loads(provenance.dumps(prov)) == prov


def test_confidence_never_certain():
    prov = provenance.build(confidence=1.0, run_validity="VALID")
    assert prov["confidence"] <= provenance.MAX_CONFIDENCE < 1.0
    assert prov["confidence_label"] in provenance.CONFIDENCE_LABELS
    assert "not certainty" in " ".join(prov["notes"])


def test_degraded_run_lowers_confidence():
    good = provenance.build(confidence=0.9, run_validity="VALID")["confidence"]
    bad = provenance.build(confidence=0.9, run_validity="CHALLENGE_DETECTED")
    assert bad["confidence"] < good and bad["run_validity"] == "CHALLENGE_DETECTED"
    assert provenance.build(run_validity=None)["run_validity"] == "NOT_COMPUTED"
    assert provenance.build(confidence=None)["confidence_label"] == "unknown"


def test_secret_like_identity_dropped():
    assert provenance.build(identity_label="Bearer eyJabc")["identity_label"] == "[redacted-identity-label]"


def test_evidence_bytes_and_hash_unchanged():
    body = b"HTTP/1.1 200 OK\r\n\r\n{\"id\": 2}"
    digest = hashlib.sha256(body).hexdigest()
    prov = provenance.build(confidence=0.5, evidence_sha256=digest)
    assert body == b"HTTP/1.1 200 OK\r\n\r\n{\"id\": 2}" and hashlib.sha256(body).hexdigest() == digest
    assert prov["evidence_sha256"] == digest
