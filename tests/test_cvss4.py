"""G-03 CVSS 4.0 calculator: FIRST reference vectors, malformed vectors, scoring.py hook."""
# @lat: [[intel-and-reporting#CVSS 4.0 calculator]]

from __future__ import annotations

import json
from pathlib import Path

import pytest

from attestra import scoring
from attestra.intel import cvss4

VECTORS = json.loads((Path(__file__).parent / "fixtures" / "cvss4" / "first_vectors.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", VECTORS["vectors"], ids=lambda c: c["vector"][9:40])
def test_reference_vectors(case):
    res = cvss4.score(case["vector"])
    assert res.score == case["score"]
    assert res.severity == ("info" if case["severity"] == "none" else case["severity"])
    assert res.calculator_version == cvss4.CALCULATOR_VERSION


def test_spec_headline_examples():
    assert cvss4.score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H").score == 10.0
    assert cvss4.score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N").score == 9.3
    assert cvss4.score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N").score == 0.0


def test_reproducible():
    v = "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:P/VC:H/VI:L/VA:L/SC:L/SI:L/SA:N/E:A/MAV:N"
    assert cvss4.score(v) == cvss4.score(v)
    assert cvss4.score(v).as_dict()["macro_vector"] == cvss4.macro_vector(cvss4.parse_vector(v))


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N",  # SA missing
        "CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",  # bad value
        "CVSS:4.0/AV:N/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",  # duplicate
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/ZZ:1",  # unknown
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/",  # trailing slash
    ],
)
def test_malformed_vectors(bad):
    with pytest.raises(cvss4.Cvss4Error):
        cvss4.score(bad)
    assert cvss4.try_score(bad) is None


def test_scoring_hook_scores_v4_and_keeps_v3():
    v4 = scoring.cvss_score_for_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.0)
    assert v4["score"] == 9.3 and v4["source"] == "cvss4_calculator" and v4["version"] == "4.0"
    v3 = scoring.cvss_score_for_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8)
    assert v3["score"] == 9.8 and v3["source"] == "provided" and v3["calculator_version"] == ""
    broken = scoring.cvss_score_for_vector("CVSS:4.0/AV:N", 6.1)
    assert broken["score"] == 6.1 and broken["source"] == "provided_invalid_vector"
