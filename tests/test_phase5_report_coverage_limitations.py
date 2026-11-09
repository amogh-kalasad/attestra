"""Phase 5: automated coverage/limitations section for technical reports."""

from __future__ import annotations

from types import SimpleNamespace

from attestra.reports.render import (
    _automated_coverage_limitations_context,
    _redact_auth_note,
)


# @lat: [[tests#Phase 5 report coverage limitations#Auth note redaction]]
def test_auth_note_redaction():
    note = "form login ok; auth-loss: Cookie=SUPERSECRETVALUE1234567890ABCD mid-scan"
    out = _redact_auth_note(note)
    assert "auth-loss:" in out
    assert "SUPERSECRETVALUE1234567890ABCD" not in out
    assert "[REDACTED]" in out


# @lat: [[tests#Phase 5 report coverage limitations#Deferred list always available]]
def test_limitations_include_deferred_without_runs(fresh_db, engagement):
    from attestra import db
    from attestra.models import Engagement

    with db.session() as s:
        eng = s.get(Engagement, engagement)
        ctx = _automated_coverage_limitations_context(s, eng)
    block = ctx.get("automated_coverage_limitations")
    assert block is not None
    assert block["section"] is True
    assert any(d.get("status") == "deferred" for d in block["deferred"])


# @lat: [[tests#Phase 5 report coverage limitations#Skip reasons surface from execution]]
def test_limitations_surface_skip_reasons(fresh_db, engagement):
    from sqlalchemy import select

    from attestra import db
    from attestra.models import Asset, AutomatedTestExecution, Engagement

    with db.session() as s:
        eng = s.get(Engagement, engagement)
        asset = s.scalars(select(Asset).where(Asset.engagement_id == eng.id)).first()
        ex = AutomatedTestExecution(
            engagement_id=eng.id,
            tenant_id=eng.tenant_id,
            asset_id=asset.id if asset else None,
            target_base_url="https://lab.example.test/",
            status="COMPLETED",
            profile="baseline",
            test_case_ids=["T20", "T22"],
            result_json=(
                '{"cases":['
                '{"test_id":"T20","status":"SKIPPED","skip_reason":"no_object_ids","detail":"no ids"},'
                '{"test_id":"T22","status":"BLOCKED","skip_reason":"auth_lost","detail":"blocked: session lost"}'
                '],"auth":{"note":"auth-loss: Cookie=SECRETtokenXYZ","status":"lost"}}'
            ),
            requested_by="tester",
        )
        s.add(ex)
        s.commit()
        ctx = _automated_coverage_limitations_context(s, eng)
        block = ctx["automated_coverage_limitations"]
        reasons = {c["skip_reason"] for c in block["cases"]}
        assert "no_object_ids" in reasons
        assert "auth_lost" in reasons
        assert any("auth-loss:" in n for n in block["auth_notes"])
        assert "SECRETtokenXYZ" not in str(block)


# @lat: [[tests#Phase 5 report coverage limitations#Technical template renders section]]
def test_technical_template_renders_limitations_section():
    from jinja2 import Environment

    from attestra.reports import labels as report_labels

    env = Environment(autoescape=True)
    report_labels.register_jinja_filters(env)
    tmpl = env.from_string(
        """
        {% if automated_coverage_limitations and automated_coverage_limitations.section %}
        <h2 id="automated-coverage-limitations">Automated coverage and limitations</h2>
        {% for note in automated_coverage_limitations.auth_notes %}<p>{{ note }}</p>{% endfor %}
        {% for c in automated_coverage_limitations.cases %}
        <span>{{ c.test_id }} {{ c.skip_reason }}</span>
        {% endfor %}
        <p>Deferred catalogue capabilities</p>
        {% for d in automated_coverage_limitations.deferred %}<span>{{ d.capability }}</span>{% endfor %}
        {% endif %}
        """
    )
    html = tmpl.render(
        automated_coverage_limitations={
            "section": True,
            "deferred": [{"category": "xss", "capability": "demo", "notes": "n", "status": "deferred"}],
            "cases": [
                {
                    "execution_id": 9,
                    "test_id": "T20",
                    "status": "SKIPPED",
                    "skip_reason": "no_object_ids",
                    "detail": "no ids",
                }
            ],
            "auth_notes": ["automated run #9: auth-loss: [REDACTED]"],
        }
    )
    assert 'id="automated-coverage-limitations"' in html
    assert "no_object_ids" in html
    assert "Deferred catalogue capabilities" in html
