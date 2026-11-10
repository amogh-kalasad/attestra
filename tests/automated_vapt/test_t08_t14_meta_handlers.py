"""Unit tests for Elite meta-case handlers T08-T14."""

from __future__ import annotations

from attestra.automated_vapt.core.meta_handlers import run_meta_case
from attestra.automated_vapt.core.orchestrator import _run_case
from attestra.automated_vapt.core.test_context import TestContext as VaptContext
from attestra.automated_vapt.evidence.request_response_renderer import render_http_pair_png
from attestra.automated_vapt.evidence.screenshot_annotator import pillow_available
from attestra.automated_vapt.validation.vulnerability_validator import NOT_VULNERABLE
from attestra.proof.pair import HttpPair


def _ctx(**extra):
    return VaptContext(
        engagement_id=1,
        tenant_id=1,
        asset_id=1,
        target_base_url='https://example.test/',
        test_case_ids=['T08'],
        extra=dict(extra),
    )


def _pair(status=200, body='ok', url='https://example.test/app', headers=None):
    return HttpPair(
        method='GET',
        url=url,
        request_headers=headers or {},
        status=status,
        response_body=body,
    )


def test_t08_skipped_without_evidence():
    out = run_meta_case('T08', _ctx(), 'validation')
    assert out['status'] == 'SKIPPED'
    assert 'not implemented' not in (out.get('detail') or '').lower()


def test_t08_classifies_http_200_as_not_vulnerable():
    out = run_meta_case('T08', _ctx(_http_pairs=[_pair()]), 'validation')
    assert out['status'] == 'PASSED'
    assert out['classifications'][0]['status'] == NOT_VULNERABLE
    assert (out.get('validation') or {}).get('status') not in {'CONFIRMED', 'POTENTIAL'}
    assert all(row['status'] != 'CONFIRMED' for row in out['classifications'])


def test_t09_flags_deny_response_as_likely_fp():
    out = run_meta_case('T09', _ctx(_http_pairs=[_pair(status=403, body='')]), 'validation')
    assert out['status'] == 'PASSED'
    assert out['reviews'][0]['is_likely_fp'] is True
    assert out['reviews'][0]['allow_manual_review'] is True
    assert (out.get('validation') or {}).get('status') not in {'CONFIRMED', 'POTENTIAL'}


def test_t09_does_not_suppress_confirmed_exposure():
    prior = [{
        'test_id': 'T04',
        'status': 'FINDING',
        'validation': {'status': 'CONFIRMED', 'reasons': ['bypass'], 'confidence': 'high'},
        'false_positive': {
            'is_likely_fp': False,
            'reasons': ['protected exposure or bypass present; not suppressed'],
            'allow_manual_review': True,
        },
    }]
    out = run_meta_case('T09', _ctx(_case_results=prior), 'validation')
    assert out['status'] == 'PASSED'
    assert out['reviews'][0]['is_likely_fp'] is False
    assert out['reviews'][0]['not_suppressed'] is True


def test_t10_skipped_without_screenshots():
    out = run_meta_case('T10', _ctx(), 'evidence')
    assert out['status'] == 'SKIPPED'


def test_t10_annotates_screenshot_when_pillow_available():
    png = render_http_pair_png(_pair())
    ctx = _ctx(_screenshots={'page1.png': png})
    out = run_meta_case('T10', ctx, 'evidence')
    if not pillow_available():
        assert out['status'] == 'SKIPPED'
        return
    assert out['status'] == 'PASSED'
    assert out['annotated']
    stored = ctx.extra['_screenshots']
    assert 'page1.png' in stored
    assert stored['page1.png'] == png
    assert stored[out['annotated'][0]].startswith(b'\x89PNG')
    assert stored[out['annotated'][0]] != png


def test_t11_redacts_authorization_header():
    secret = 'Bearer test-token-value'
    pair = _pair(headers={'Authorization': secret})
    out = run_meta_case('T11', _ctx(_http_pairs=[pair]), 'evidence')
    assert out['status'] == 'PASSED'
    assert out['masked_headers'] >= 1
    assert secret not in (out.get('detail') or '')


def test_t11_skipped_without_pairs():
    out = run_meta_case('T11', _ctx(), 'evidence')
    assert out['status'] == 'SKIPPED'


def test_t12_hashes_and_verifies_evidence():
    png = render_http_pair_png(_pair())
    out = run_meta_case(
        'T12',
        _ctx(_http_pairs=[_pair()], _screenshots={'page1.png': png}),
        'evidence',
    )
    assert out['status'] == 'PASSED'
    assert out['verified'] == 2
    assert out['failed'] == 0
    assert all(row['verified'] for row in out['manifest_entries'])
    assert all(len(row['hash']) == 64 for row in out['manifest_entries'])


def test_t13_skipped_without_prior_cases():
    out = run_meta_case('T13', _ctx(), 'integration')
    assert out['status'] == 'SKIPPED'


def test_t13_maps_prior_confirmed_without_duplicate_validation():
    prior = [{
        'test_id': 'T04',
        'status': 'FINDING',
        'detail': 'authz module completed',
        'finding_id': 42,
        'finding_title': 'BOLA on project',
        'finding_cwe': 639,
        'finding_location': 'https://example.test/api/projects/1',
        'validation': {'status': 'CONFIRMED', 'reasons': ['bypass'], 'confidence': 'high'},
        'false_positive': {'is_likely_fp': False, 'allow_manual_review': True},
    }]
    out = run_meta_case('T13', _ctx(_case_results=prior), 'integration')
    assert out['status'] == 'PASSED'
    assert out['finding_map'][0]['finding_id'] == 42
    assert out['finding_map'][0]['already_created'] is True
    assert out['finding_map'][0]['would_create_finding'] is True
    assert (out.get('validation') or {}).get('status') not in {'CONFIRMED', 'POTENTIAL'}


def test_t13_passed_when_prior_cases_have_no_findings():
    prior = [{'test_id': 'T01', 'status': 'PASSED', 'detail': 'captured'}]
    out = run_meta_case('T13', _ctx(_case_results=prior), 'integration')
    assert out['status'] == 'PASSED'
    assert out['finding_map'] == []


def test_t14_skipped_without_evidence():
    out = run_meta_case('T14', _ctx(), 'integration')
    assert out['status'] == 'SKIPPED'


def test_t14_passes_with_listed_and_in_memory_evidence():
    prior = [{
        'test_id': 'T02',
        'status': 'PASSED',
        'evidence_files': ['T02_screenshot_1.png'],
        'report_evidence_files': [],
    }]
    out = run_meta_case(
        'T14',
        _ctx(_case_results=prior, _http_pairs=[_pair()], _screenshots={'page1.png': b'\x89PNG'}),
        'integration',
    )
    assert out['status'] == 'PASSED'
    assert 'T02_screenshot_1.png' in out['evidence_files']
    assert out['in_memory_pairs'] == 1
    assert (out.get('validation') or {}).get('status') not in {'CONFIRMED', 'POTENTIAL'}


def test_orchestrator_dispatches_t08_not_deferred():
    out = _run_case('T08', _ctx())
    assert out['status'] == 'SKIPPED'
    assert out['status'] != 'DEFERRED'
    assert 'not implemented' not in (out.get('detail') or '').lower()


def test_orchestrator_still_defers_t15():
    out = _run_case('T15', _ctx())
    assert out['status'] == 'DEFERRED'
    assert out['detail'] == 'handler not implemented yet'
