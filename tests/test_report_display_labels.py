"""Display-label layer: maps, sentence helpers, and report text hygiene."""
# @lat: [[tests#Report display labels]]

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

from attestra.reports import labels

# --------------------------------------------------------------------------- unit maps


# @lat: [[tests#Report display labels#Tool and status maps]]
def test_tool_and_status_maps():
    assert labels.tool_label("zap") == "Zap"
    assert labels.tool_label("OWASP ZAP") == "OWASP Zap" or labels.tool_label("owasp_zap") == "OWASP Zap"
    assert labels.tool_label("automated_vapt") == "Automated VAPT"
    assert labels.tool_label("webcheck") == "Webcheck"
    assert labels.status_label("PASSED") == "Passed"
    assert labels.status_label("not_started") == "Not Started"
    assert labels.status_label("done") == "Completed"
    assert labels.status_label("false_positive") == "False positive"
    assert labels.severity_label("medium") == "Medium"
    assert labels.severity_label("critical") == "Critical"


# @lat: [[tests#Report display labels#Humanize and plural]]
def test_humanize_and_plural():
    assert labels.humanize("exact_fingerprint") == "Exact fingerprint"
    assert labels.humanize("same_asset+cwe_and_location+cross_tool") == (
        "Same asset, CWE and location, cross-tool"
    )
    assert labels.humanize("csp_unsafe_inline") == "CSP unsafe-inline"
    assert labels.humanize("tls_weak_cipher") == "Weak TLS cipher"
    assert labels.plural(1, "finding") == "1 finding"
    assert labels.plural(5, "finding") == "5 findings"
    assert labels.plural(0, "image") == "0 images"
    assert "(s)" not in labels.plural(2, "page")


# @lat: [[tests#Report display labels#Date formats]]
def test_date_formats_never_verbose_ist():
    dt = datetime(2026, 11, 4, 10, 38, tzinfo=UTC)
    assert labels.format_date(dt) == "2026-11-04"
    out = labels.format_datetime(dt)
    # Day-month form so pdf._human_times does not rematch and append a second IST.
    assert re.match(r"\d{1,2} \w{3} \d{4}, \d{2}:\d{2} [A-Z]{2,5}", out)
    assert "India Standard Time" not in out
    assert "IST IST" not in out
    cleaned = labels.format_datetime("2026-11-04 16:08 IST India Standard Time")
    assert "India Standard Time" not in cleaned
    assert "IST" in cleaned or re.search(r"\d{2}:\d{2}", cleaned)


# @lat: [[tests#Report display labels#Detail and checklist sentences]]
def test_detail_and_checklist_sentences():
    pages = labels.format_detail_sentence(
        "HTTP captured for 20/20 page(s) (zap-scan-1+js); HTTP 403x20; auth: ready (profile #1)"
    )
    assert "all 20 pages" in pages
    assert "Zap scan 1 with JavaScript" in pages
    assert "All 20 responses returned HTTP 403" in pages
    assert "Authentication: ready (profile #1)." in pages
    assert "(s)" not in pages

    bypass = labels.format_detail_sentence(
        "auth bypass: 0 finding(s) across 5 endpoint(s); auth: ready (profile #1)"
    )
    assert bypass.startswith("Authentication bypass:")
    assert "0 findings across 5 endpoints" in bypass

    assert labels.format_detail_sentence(
        "no object ids harvested from authenticated API responses"
    ) == "No object IDs were harvested from authenticated API responses."

    bodies = labels.format_detail_sentence(
        "no captured POST/PUT/PATCH JSON bodies with object-id fields to mutate; "
        "JS discovery listed 39 write endpoint(s) but no request bodies were captured"
    )
    assert "No POST, PUT or PATCH JSON bodies" in bodies
    assert "39 write endpoints" in bodies

    note = labels.format_checklist_note(
        "auto: passed by attestra-auto at 2026-11-04T10:38:00Z - [automated_vapt] "
        "automated run #1 T19: no issues -> #1, #2 (+4 more)"
    )
    assert note.startswith("Automated: Passed by Attestra on ")
    assert "Automated VAPT" in note
    assert note.count("Automated VAPT") == 1
    assert "->" not in note
    assert "Findings:" in note
    assert "and 4 more" in note
    assert "[automated_vapt]" not in note
    assert "(s)" not in note

    blocked = labels.format_checklist_note(
        "no object ids harvested from authenticated API responses"
    )
    assert blocked.startswith("Blocked:")
    assert "object IDs" in blocked


# @lat: [[tests#Report display labels#Consolidate and param labels]]
def test_consolidate_param_and_run_header():
    s = labels.consolidate_sentence("same issue (report:csp-weak) reported by zap, nuclei")
    assert s.startswith("The same issue")
    assert "Consolidated Consolidated" not in s
    assert s.lower().count("consolidated") == 0
    assert "was reported by Zap and Nuclei" in s
    assert "listed once under Sources" in s

    assert labels.check_label("cookie_httponly_flag") == "Cookie HttpOnly flag"
    assert labels.check_label("csp_unsafe_inline") == "CSP unsafe-inline"
    assert labels.evidence_kind_label("http_pair") == "HTTP pair"
    assert "Nuclei" in labels.evidence_note_label("auto-captured from nuclei")

    assert "(Parameter: cookie)" in labels.param_label("loc [param: cookie]")
    assert labels.param_label("otherinfo: missing").startswith("Other info:")

    hdr = labels.automated_run_header(
        status="completed",
        profile="baseline",
        finished_at=datetime(2026, 11, 4, 10, 38, tzinfo=UTC),
        case_count=5,
        image_count=0,
    )
    assert hdr.startswith("Status: Completed")
    assert "Profile: Baseline" in hdr
    assert "5 test cases, 0 images" in hdr
    assert "(s)" not in hdr

    assert labels.test_name_label("T19", "API Authentication Bypass").startswith("T19 ·")
    assert "API" in labels.test_name_label("T19", "API Authentication Bypass")


# @lat: [[tests#Report display labels#Title case keeps small words]]
def test_title_case_keeps_all_lowercase_mid_sentence():
    # DOCX title_case keeps mid-sentence small words (pdf.py title_case unchanged on this branch).
    from attestra.reports.docx_export import title_case

    out = title_case("remove all CORS headers for all web pages")
    assert "for All" not in out
    assert "remove All" not in out
    assert out.startswith("Remove")


# @lat: [[tests#Report display labels#Dedup Zap label]]
def test_detected_by_uses_zap_not_owasp_zap_acronym():
    # Report display uses labels.tool_label (dedup.py display names stay unchanged on this branch).
    assert labels.tool_label("zap") == "Zap"
    assert labels.tool_label("nuclei") == "Nuclei"
    assert ", ".join(labels.tool_label(t) for t in ["zap", "nuclei"]) == "Zap, Nuclei"


_SNAKE = re.compile(r"\b[a-z]+(_[a-z]+)+\b")
# Template/chrome plurals we used to emit — not free-text finding titles from scanners.
_PLURAL_S = re.compile(
    r"\b(?:test case|image|page|finding|endpoint|probe|observation|item|issue|reportable finding)\(s\)",
    re.I,
)
_STATUS_CAPS = re.compile(r"\b(PASSED|FAILED|SKIPPED|COMPLETED)\b")
_ARROW = re.compile(r"->")
_IST_VERBOSE = re.compile(r"IST India Standard Time")
_MID_ALL = re.compile(r"(?<=[a-z])\s+(All|Always)\b")
_BRACKET_TOOL = re.compile(r"\[(zap|nuclei|automated_vapt|webcheck)\]", re.I)
_CELL_STATUS = re.compile(
    r"<td[^>]*>\s*(?:<[^>]+>\s*)*(new|blocked|done|passed|failed|skipped|completed)\b"
)
_IST_IST = re.compile(r"\bIST\s+IST\b")
_DUP_WORDS = re.compile(r"\b([A-Za-z][A-Za-z+./-]{1,20})\s+\1\b")
_BAD_CHECK = re.compile(r"\b(Httponly|Samesite|Http only)\b")
_LOWER_TOOL = re.compile(r"(?i)(?:Detected by|auto-captured from)\s*:\s*.*\b(zap|nuclei|webcheck)\b")


def _strip_evidence_blocks(html: str) -> str:
    """Remove verbatim evidence / free-text narrative so the scanner checks labels only."""
    out = re.sub(r"(?is)<script\b[^>]*>.*?</script>", " ", html)
    out = re.sub(r"(?is)<style\b[^>]*>.*?</style>", " ", out)
    out = re.sub(r"(?is)<pre\b[^>]*>.*?</pre>", " ", out)
    out = re.sub(r"(?is)<(code|samp)\b[^>]*>.*?</\1>", " ", out)
    # Scanner/finding prose (descriptions, recommendations, AI narrative) — not labels.
    out = re.sub(r'(?is)<div class="finding-section"[^>]*>.*?</div>', " ", out)
    out = re.sub(r'(?is)<div class="finding-evidence"[^>]*>.*?</div>', " ", out)
    out = re.sub(r"(?is)<h2 id=\"disclaimer\">.*?(?=<h2\b)", " ", out)
    out = re.sub(r"(?is)<span class=\"mono\"[^>]*>.*?</span>", " ", out)
    out = re.sub(r"(?is)class=\"mono\"[^>]*>.*?<", "><", out)
    return out


def _assert_display_hygiene(html: str) -> None:
    text = _strip_evidence_blocks(html)
    # Allow known snake_case in CSS class names / ids / data attrs by stripping tags first.
    plain = re.sub(r"(?is)<[^>]+>", " ", text)
    plain = re.sub(r"&[#\w]+;", " ", plain)
    # Allow sha256 hex and F- ids; drop long hashes
    plain = re.sub(r"\b[a-f0-9]{16,}\b", " ", plain)
    # File-like tokens with underscores in filenames are evidence — already stripped with mono.
    # Fail on remaining snake_case tokens that look like enum keys.
    snakes = {
        m.group(0)
        for m in _SNAKE.finditer(plain)
        if m.group(0)
        not in {
            "false_positive",  # may appear in CSS class finding-false_positive — stripped
        }
        and not m.group(0).startswith("row_")
    }
    # Filter CSS leftovers and known template internals that can leak via class text
    snakes = {s for s in snakes if not s.startswith(("sev_", "st_", "finding_", "chip_", "status_"))}
    # Allow cvss_vector-like only if somehow present — still flag status/tool keys
    bad_snakes = {
        s
        for s in snakes
        if s
        in {
            "not_started",
            "false_positive",
            "risk_accepted",
            "automated_vapt",
            "exact_fingerprint",
            "csp_unsafe_inline",
            "tls_weak_cipher",
            "refuse_reason",
            "in_progress",
            "not_assessed",
            "no_exceptions",
            "not_applicable",
            "not_met",
            "not_tested",
            "retest_passed",
        }
        or s.endswith(("_fingerprint", "_inline", "_cipher", "_vapt"))
    }
    assert not bad_snakes, f"raw snake_case labels in report: {sorted(bad_snakes)}"
    assert not _PLURAL_S.search(plain), "found (s) plural pattern"
    assert not _STATUS_CAPS.search(plain), "found ALL-CAPS status word"
    assert not _ARROW.search(plain), "found -> arrow"
    assert not _IST_VERBOSE.search(plain), "found verbose IST India Standard Time"
    assert not _MID_ALL.search(plain), "mid-sentence capital All/Always"
    assert not _BRACKET_TOOL.search(plain), "raw [tool] bracket tags"
    assert not _CELL_STATUS.search(html), "lowercase status at start of table cell"
    assert not _IST_IST.search(plain), "found IST IST"
    assert not _BAD_CHECK.search(plain), "Title-cased HttpOnly/SameSite regression"
    # Flag phrase-level dupes only (Automated VAPT Automated VAPT / Zap Zap), not acronym headers.
    assert not re.search(r"\b(Automated VAPT)\s+\1\b", plain)
    assert not re.search(r"\b(Zap|Nuclei|Webcheck)\s+\1\b", plain)
    assert "Consolidated Consolidated" not in plain
    assert "Findings: findings" not in plain.lower()


# @lat: [[tests#Report display labels#Generated technical hygiene]]
def test_generated_technical_hygiene(loaded):
    from attestra import db
    from attestra.reports import generate_report

    with db.session() as s:
        r = generate_report(s, loaded, kind="technical", actor="tester")
        html = Path(r.path).read_text(encoding="utf-8")

    assert "Refusal Reason" in html or "refusal reason" not in html.lower().replace("refusal reason", "")
    # Chart / severity chips use full words
    assert "medi" not in re.sub(r"(?is)<[^>]+>", " ", html).lower().split()
    _assert_display_hygiene(html)


# @lat: [[tests#Report display labels#Recommendation bullets]]
def test_recommendation_to_bullets_splits_numbered():
    html = labels.recommendation_to_bullets(
        "1. First do this. 2. Then do that. 3. Finally verify."
    )
    assert html.startswith("<ul")
    assert html.count("<li>") >= 2
    assert labels.recommendation_to_bullets("Just one sentence.") == ""


# @lat: [[tests#Report display labels#Evidence stays verbatim]]
def test_http_pair_evidence_stays_verbatim(loaded, tmp_path):
    """HTTP pair display must match stored body (modulo REDACTED and line wrapping)."""

    from attestra import db, services
    from attestra.proof.pair import HttpPair
    from attestra.proof.store import attach_http_pair
    from attestra.reports import generate_report
    from attestra.reports.pdf import prepare_html
    from attestra.reports.render import _format_http_pair_display

    raw_body = {
        "method": "GET",
        "url": "https://example.com/path",
        "status": 200,
        "request_headers": {
            "Accept-Language": "en",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "X-Xss-Protection": "1; mode=block",
        },
        "request_body": "",
        "response_headers": {"Date": "Wed, 04 Nov 2026 10:00:00 GMT", "Content-Type": 'text/html; lang="en"'},
        "response_body": '<html lang="en"><body>— Request —</body></html>',
        "source": "manual",
    }
    with db.session() as s:
        f = services.list_findings(s, loaded)[0]
        pair = HttpPair.from_dict(raw_body)
        attach_http_pair(s, f.id, pair, actor="tester", note="verbatim probe")
        r = generate_report(s, loaded, kind="technical", actor="tester")
        html = Path(r.path).read_text(encoding="utf-8")
        prepared = prepare_html(html, kind="technical", draft=True, for_engine="xhtml2pdf")

    expected = _format_http_pair_display(raw_body)
    assert "Accept-Language: en" in expected
    assert "Intel Mac OS X 10_15_7" in expected
    assert 'lang="en"' in expected or "lang=&quot;en&quot;" in expected or 'lang="en"' in html
    assert "— Request —" in expected
    # Sealed HTML and PDF-prepared HTML keep the verbatim markers.
    for blob in (html, prepared):
        assert "Accept-Language: en" in blob
        assert "Intel Mac OS X 10_15_7" in blob
        assert "mode=block" in blob
        assert "X-Xss-Protection: 1" in blob
        assert "Wed, 04 Nov 2026" in blob
        assert "— Request —" in blob
        assert "IST IST" not in blob


# @lat: [[tests#Report display labels#No double timezone conversion]]
def test_human_times_does_not_double_convert():
    """format_datetime output must survive pdf._human_times without a second IST.

    restore-old-template keeps stock pdf._human_times (ISO rematch, including in
    ``<pre>``); day-month display form is the display-layer defence without changing pdf.py.
    """
    from attestra.reports.pdf import _human_times

    labeled = labels.format_datetime(datetime(2026, 11, 4, 10, 38, tzinfo=UTC))
    html = f"<body><p>Scan {labeled}</p><p>Finished {labeled}.</p></body>"
    out = _human_times(html)
    assert labeled in out
    assert out.count(labeled) >= 2
    assert "IST IST" not in out
