"""Portal / engagement report plain (unbranded) derivative views."""
# @lat: [[interfaces#Client remediation portal]]

from __future__ import annotations

from attestra.reports.plain import strip_report_branding


SAMPLE = """<!doctype html><html><body>
<section class="cover" id="cover">
  <table class="cover-band"><tr>
    <td><img class="cover-logo" src="data:image/png;base64,aaa" alt=""></td>
    <td><span class="cover-band-brand">ATTESTRA</span></td>
  </tr></table>
  <h1>Technical report</h1>
  <p class="finding">Missing HSTS on app.example.com</p>
</section>
<div class="meta"><span class="brand">ATTESTRA</span> | Acme | Engagement #1</div>
<main><h2>Findings</h2><p>SQL injection in /api/search</p></main>
<footer>
  Generated 2026-01-01 by lead with Attestra 1.2.3.
  Acme Security Ltd. qa@example.com
  QA, approval and signature are not part of this file. They are recorded separately in the Attestra sign-off record.
</footer>
</body></html>""".encode("utf-8")


def test_strip_removes_logo_brand_and_powered_by_keeps_findings():
    out = strip_report_branding(SAMPLE)
    assert b"cover-logo" not in out
    assert b"cover-band-brand" not in out
    assert b"data:image/png;base64,aaa" not in out
    assert b"with Attestra" not in out
    assert b"Plain content view" in out or b"plain" in out.lower()
    assert b"Missing HSTS on app.example.com" in out
    assert b"SQL injection in /api/search" in out
    assert b"Technical report" in out


def test_strip_empty_and_idempotent_ish():
    assert strip_report_branding(b"") == b""
    once = strip_report_branding(SAMPLE)
    twice = strip_report_branding(once)
    assert b"SQL injection" in twice
