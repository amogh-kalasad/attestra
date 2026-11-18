"""FND-01: response classifier contract (§3.1) on synthetic WAF / app fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from attestra.automated_vapt.core.response_classifier import (
    ResponseClass as RC,
    classify_response,
    is_blocking,
    is_security_control_evidence,
    mark_blocked_if_needed,
    proves_enforcement,
    skip_reason_for,
)

FIX = Path(__file__).parent / "fixtures" / "waf"


def _body(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


# @lat: [[run-validity-and-policy#Response classifier]]
@pytest.mark.parametrize(
    "status,headers,body,expected",
    [
        (403, {"server": "cloudflare", "cf-mitigated": "challenge"}, "cf_challenge.html", RC.CHALLENGE),
        (503, {"server": "cloudflare"}, "cf_challenge.html", RC.CHALLENGE),
        (403, {"server": "cloudflare", "cf-ray": "x"}, "cf_block_403.html", RC.WAF_BLOCK),
        (403, {"server": "AkamaiGHost"}, "akamai_ref.html", RC.WAF_BLOCK),
        (403, {"x-sucuri-block": "1"}, "sucuri_block.html", RC.WAF_BLOCK),
        (403, {"content-type": "application/json"}, "app_403.json", RC.APP_AUTH_DENIED),
        (401, {}, "app_401_login.html", RC.APP_AUTH_DENIED),
        (429, {"retry-after": "30"}, "rate_429.txt", RC.RATE_LIMITED),
    ],
)
def test_fixture_classes(status, headers, body, expected):
    c = classify_response(status, headers, _body(body))
    assert c.cls is expected, c.reasons


def test_waf_and_challenge_are_never_security_control_evidence():
    for status, headers, body in (
        (403, {"cf-mitigated": "challenge"}, "cf_challenge.html"),
        (403, {"server": "cloudflare"}, "cf_block_403.html"),
        (403, {"server": "AkamaiGHost"}, "akamai_ref.html"),
        (429, {}, "rate_429.txt"),
    ):
        c = classify_response(status, headers, _body(body))
        assert not is_security_control_evidence(c)
        assert is_blocking(c)


def test_app_denials_are_security_control_evidence():
    assert is_security_control_evidence(classify_response(401, {}, "{}"))
    assert is_security_control_evidence(classify_response(403, {}, _body("app_403.json")))
    redirect = classify_response(302, {"location": "/login?next=/app"}, "")
    assert redirect.cls is RC.AUTH_REDIRECT and is_security_control_evidence(redirect)


def test_authed_denial_means_session_expired():
    assert classify_response(401, {}, "{}", authed=True).cls is RC.AUTH_EXPIRED
    assert classify_response(302, {"location": "/login"}, "", authed=True).cls is RC.AUTH_EXPIRED
    assert classify_response(200, {}, _body("app_401_login.html"), authed=True).cls is RC.AUTH_EXPIRED


def test_misc_classes():
    assert classify_response(0, {}, "", error="ConnectError").cls is RC.NETWORK_FAILED
    assert classify_response(404, {}, "nope").cls is RC.NOT_FOUND
    assert classify_response(502, {}, "bad gateway").cls is RC.ORIGIN_ERROR
    # cf-ray alone on a normal page is not a block.
    assert classify_response(200, {"cf-ray": "abc", "server": "cloudflare"}, "<h1>ok</h1>").cls is RC.APP_OK
    # A login page that embeds a captcha widget (200) is not a challenge.
    assert classify_response(200, {}, '<form><div class="g-recaptcha"></div></form>').cls is RC.APP_OK
    # Plain 404 behind Cloudflare (cf-ray / server only, or a captcha widget) is not a challenge.
    cf = {"server": "cloudflare", "cf-ray": "abc123"}
    assert classify_response(404, cf, '{"message":"not found"}').cls is RC.NOT_FOUND
    assert classify_response(404, cf, "<html><title>Not Found</title></html>").cls is RC.NOT_FOUND
    assert classify_response(404, cf, '<div class="g-recaptcha"></div>not found').cls is RC.NOT_FOUND
    # Real challenge markers still win at 404.
    assert classify_response(
        404, {"cf-mitigated": "challenge", "server": "cloudflare"}, "Just a moment..."
    ).cls is RC.CHALLENGE


def test_proves_enforcement_needs_app_denial_and_authed_ok():
    ok = classify_response(200, {}, "{}", authed=True)
    assert proves_enforcement(classify_response(401, {}, ""), ok)
    assert not proves_enforcement(classify_response(403, {"server": "cloudflare"}, _body("cf_block_403.html")), ok)
    assert not proves_enforcement(classify_response(401, {}, ""), classify_response(401, {}, "", authed=True))


def test_mark_blocked_if_needed_sets_skip_reason():
    samples = [classify_response(403, {"cf-mitigated": "challenge"}, _body("cf_challenge.html"))]
    out = mark_blocked_if_needed({"finding_candidate": False}, samples)
    assert out["status_hint"] == "BLOCKED" and out["skip_reason"] == "challenge_detected"
    assert skip_reason_for(samples) == "challenge_detected"
    # Findings are never downgraded.
    assert "status_hint" not in mark_blocked_if_needed({"finding_candidate": True}, samples)


def test_to_dict_is_value_free():
    c = classify_response(403, {"set-cookie": "sid=SECRETVALUE"}, "SECRETBODY")
    blob = str(c.to_dict())
    assert "SECRETVALUE" not in blob and "SECRETBODY" not in blob


def test_large_html_200_is_not_challenge_without_real_markers():
    buried = "<!doctype html><html><head><title>App</title></head><body>" + ("n" * 5000) + "Just a moment..."
    assert classify_response(200, {"cf-ray": "abc", "server": "cloudflare"}, buried).cls is RC.APP_OK
    # A real interstitial has the marker in the early document.
    interstitial = "<html><head><title>Just a moment...</title></head><body>Checking your browser before you continue</body></html>"
    assert classify_response(200, {"server": "cloudflare"}, interstitial).cls is RC.CHALLENGE
    # Challenge headers still win on a large 200, even without an early body marker.
    assert classify_response(200, {"cf-mitigated": "challenge"}, buried).cls is RC.CHALLENGE

