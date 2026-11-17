"""D-02 offline JWT posture: claims/header review, value-free output."""

from __future__ import annotations

import base64
import json

from attestra.automated_vapt.testing.jwt_posture import assess_token, assess_tokens

NOW = 1_800_000_000


def _enc(d) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


def _jwt(header: dict, claims: dict, sig: str = "c2ln") -> str:
    return f"{_enc(header)}.{_enc(claims)}.{sig}"


GOOD = _jwt({"alg": "RS256", "typ": "JWT"}, {"iss": "https://idp", "aud": "app", "sub": "u", "iat": NOW - 60, "exp": NOW + 900})


# @lat: [[run-validity-and-policy#JWT posture]]
def test_good_token_has_no_high_issue():
    r = assess_token(GOOD, now=NOW)
    assert r["assessed"] and r["max_severity"] in ("", "info", "low")
    assert r["lifetime_s"] == 960


def test_alg_none_and_missing_exp_are_high():
    r = assess_tokens([_jwt({"alg": "none"}, {"sub": "u"}, sig="")], now=NOW)
    assert {"alg_none_or_weak", "missing_exp"} <= set(r["high_issues"])
    assert r["finding"] is True


def test_header_key_injection_and_long_lifetime():
    r = assess_token(_jwt({"alg": "RS256", "jku": "https://x", "kid": "../../k"}, {"iss": "i", "aud": "a", "iat": NOW, "exp": NOW + 7 * 86400}), now=NOW)
    codes = {i["code"] for i in r["issues"]}
    assert {"jku_header", "kid_suspicious_chars", "long_lifetime"} <= codes


def test_sensitive_claim_names_reported_without_values():
    tok = _jwt({"alg": "RS256"}, {"iss": "i", "aud": "a", "exp": NOW + 60, "password": "hunter2-secret"})
    r = assess_tokens([tok], now=NOW)
    blob = json.dumps(r)
    assert "sensitive_claim_names" in r["medium_issues"]
    assert "hunter2-secret" not in blob and tok not in blob


def test_non_jwt_and_jwe_are_not_assessed():
    r = assess_tokens(["opaque-session-token", "a.b.c.d.e"], now=NOW)
    assert r["tokens_assessed"] == 0 and r["status"] == "not_assessed"
    assert {x["reason"] for x in r["not_assessed"]} == {"unsupported_format", "jwe_encrypted_not_assessed"}
