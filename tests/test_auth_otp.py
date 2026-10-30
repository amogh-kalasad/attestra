"""Email-OTP login helper: extraction, inbox polling, and full login orchestration."""
from __future__ import annotations

import pytest

from attestra.auth_web import otp


def test_extract_otp_default_regex():
    assert otp.extract_otp("Your code is 482913 now") == "482913"
    assert otp.extract_otp("no digits here") is None
    assert otp.extract_otp("") is None


def test_extract_otp_custom_regex():
    assert otp.extract_otp("code: AB-9921", regex=r"AB-(\d{4})") == "9921"


def test_extract_otp_invalid_regex_raises():
    with pytest.raises(otp.OtpLoginError):
        otp.extract_otp("x", regex="(")


def test_parse_profile_secret_bare_and_json():
    assert otp.parse_profile_secret("hunter2") == {"password": "hunter2"}
    blob = '{"password": "pw", "imap_app_password": "app"}'
    assert otp.parse_profile_secret(blob) == {"password": "pw", "imap_app_password": "app"}
    assert otp.parse_profile_secret("") == {}


def test_poll_for_otp_filters_sender_and_subject():
    cfg = {"sender_filter": "no-reply@app", "subject_filter": "Login code"}
    inbox = [
        {"from": "spam@x", "subject": "Login code", "body": "111111"},
        {"from": "no-reply@app", "subject": "newsletter", "body": "222222"},
        {"from": "no-reply@app", "subject": "Your Login code", "body": "Use 345678 to sign in"},
    ]
    code = otp.poll_for_otp(cfg, "app-pw", imap_search=lambda c, p: inbox, attempts=1, sleep=lambda s: None)
    assert code == "345678"


def test_poll_for_otp_retries_until_mail_arrives():
    calls = {"n": 0}

    def search(cfg, pw):
        calls["n"] += 1
        return [{"from": "a", "subject": "s", "body": "999000"}] if calls["n"] >= 3 else []

    code = otp.poll_for_otp({}, "pw", imap_search=search, attempts=5, delay_s=0, sleep=lambda s: None)
    assert code == "999000"
    assert calls["n"] == 3


def test_poll_for_otp_times_out():
    with pytest.raises(otp.OtpLoginError):
        otp.poll_for_otp({}, "pw", imap_search=lambda c, p: [], attempts=2, delay_s=0, sleep=lambda s: None)


def test_login_with_otp_end_to_end():
    cfg = {
        "login_url": "https://app.example.com/login",
        "username": "tester@example.com",
        "otp_field": "code",
        "sender_filter": "no-reply@app.example.com",
    }
    secrets = {"password": "pw", "imap_app_password": "app-pw"}
    posts = []

    def http_post(url, data, cookies):
        posts.append((url, dict(data), dict(cookies)))
        if "code" in data:
            return otp.HttpReply(status=200, cookies={"session": "SECRET-SESSION"}, final_url=url)
        return otp.HttpReply(status=200, cookies={"csrf": "abc"}, final_url=url)

    inbox = [{"from": "no-reply@app.example.com", "subject": "code", "body": "Your code: 778899"}]
    result = otp.login_with_otp(
        cfg, secrets, http_post=http_post, imap_search=lambda c, p: inbox, attempts=1, sleep=lambda s: None
    )
    assert result.cookies["session"] == "SECRET-SESSION"
    # Step 1 sent username; step 2 sent the OTP code pulled from the inbox.
    assert posts[0][1]["username"] == "tester@example.com"
    assert posts[1][1]["code"] == "778899"


def test_login_with_otp_requires_app_password():
    with pytest.raises(otp.OtpLoginError):
        otp.login_with_otp(
            {"login_url": "https://a/login", "username": "u"},
            {"password": "pw"},
            http_post=lambda u, d, c: otp.HttpReply(),
            imap_search=lambda c, p: [],
        )


def test_login_with_otp_fails_on_bad_status():
    with pytest.raises(otp.OtpLoginError):
        otp.login_with_otp(
            {"login_url": "https://a/login", "username": "u"},
            {"imap_app_password": "app"},
            http_post=lambda u, d, c: otp.HttpReply(status=500),
            imap_search=lambda c, p: [],
        )
