"""Handlers for Elite meta-cases T08-T14 (validation, evidence, report mapping).

These operate on evidence already captured earlier in the same run
(_http_pairs, _screenshots, _case_results). They classify and package that
evidence; they do not probe the target and must not invent vulnerabilities.
A case result from these handlers never sets validation.status to CONFIRMED
or POTENTIAL, so the orchestrator will not open a duplicate finding.
"""

from __future__ import annotations

from typing import Any

from attestra.automated_vapt.core.test_context import TestContext
from attestra.automated_vapt.evidence.evidence_hasher import EvidenceManifest, sha256_hex
from attestra.automated_vapt.evidence.evidence_redactor import redact_http_pair
from attestra.automated_vapt.validation.false_positive_checker import check_false_positive
from attestra.automated_vapt.validation.severity_calculator import severity_for
from attestra.automated_vapt.validation.vulnerability_validator import validate_result
from attestra.proof.pair import HttpPair

# Headers whose values must not appear in redacted evidence.
_SENSITIVE_HEADERS = frozenset({
    'authorization',
    'cookie',
    'set-cookie',
    'proxy-authorization',
    'x-api-key',
    'x-auth-token',
    'x-access-token',
})

_META_IDS = ('T08', 'T09', 'T10', 'T11', 'T12', 'T13', 'T14')


def run_meta_case(test_id: str, ctx: TestContext, category: str) -> dict[str, Any]:
    """Dispatch one T08-T14 case against evidence already on ctx.extra."""
    tid = (test_id or '').strip().upper()
    runners = {
        'T08': _run_t08_response_validation,
        'T09': _run_t09_false_positive,
        'T10': _run_t10_screenshot_annotation,
        'T11': _run_t11_evidence_redaction,
        'T12': _run_t12_evidence_integrity,
        'T13': _run_t13_finding_mapping,
        'T14': _run_t14_report_integration,
    }
    fn = runners.get(tid)
    if fn is None:
        return {
            'test_id': test_id,
            'status': 'FAILED',
            'detail': 'unknown meta test case',
            'category': category,
        }
    try:
        return fn(ctx, category)
    except Exception as exc:  # noqa: BLE001 - surface handler bugs, never crash the run
        return {
            'test_id': tid,
            'status': 'FAILED',
            'detail': 'meta handler error: %s' % type(exc).__name__,
            'category': category,
        }


def _skipped(test_id: str, category: str, reason: str) -> dict[str, Any]:
    return {
        'test_id': test_id,
        'status': 'SKIPPED',
        'detail': reason,
        'skip_reason': reason,
        'category': category,
    }


def _passed(test_id: str, category: str, detail: str, **extra: Any) -> dict[str, Any]:
    out: dict[str, Any] = {
        'test_id': test_id,
        'status': 'PASSED',
        'detail': detail,
        'category': category,
    }
    out.update(extra)
    return out


def _prior_cases(ctx: TestContext) -> list[dict[str, Any]]:
    raw = ctx.extra.get('_case_results') or []
    return [c for c in raw if isinstance(c, dict)]


def _pairs(ctx: TestContext) -> list[Any]:
    return list(ctx.extra.get('_http_pairs') or [])


def _shots(ctx: TestContext) -> dict[str, bytes]:
    pending = ctx.extra.get('_screenshots') or {}
    if not isinstance(pending, dict):
        return {}
    out: dict[str, bytes] = {}
    for name, data in pending.items():
        if data:
            out[str(name)] = bytes(data)
    return out


def _as_pair(item: Any) -> HttpPair | None:
    if isinstance(item, HttpPair):
        return item
    if isinstance(item, dict):
        try:
            return HttpPair.from_dict(item)
        except (TypeError, ValueError):
            return None
    return None


def _pair_url(pair: HttpPair) -> str:
    return str(getattr(pair, 'url', '') or '')


def _classify_pair(pair: HttpPair) -> dict[str, Any]:
    """Classify a captured response. HTTP 200 alone is never a confirmed finding."""
    vctx = {
        'executed': True,
        'in_scope': True,
        'auth_valid': True,
        'identity_ok': True,
        'expected_control_defined': True,
        'status_code': pair.status,
        'response_body': pair.response_body or '',
        'protected_data_exposed': False,
        'authorization_bypass': False,
        'finding_candidate': False,
    }
    result = validate_result(vctx)
    return {
        'url': _pair_url(pair),
        'http_status': pair.status,
        'status': result.get('status'),
        'reasons': list(result.get('reasons') or []),
        'confidence': result.get('confidence'),
    }


def _run_t08_response_validation(ctx: TestContext, category: str) -> dict[str, Any]:
    classifications: list[dict[str, Any]] = []
    for raw in _pairs(ctx):
        pair = _as_pair(raw)
        if pair is None:
            continue
        classifications.append(_classify_pair(pair))

    prior_validations: list[dict[str, Any]] = []
    for case in _prior_cases(ctx):
        validation = case.get('validation') or {}
        if not isinstance(validation, dict) or not validation.get('status'):
            continue
        prior_validations.append({
            'test_id': case.get('test_id'),
            'case_status': case.get('status'),
            'status': validation.get('status'),
            'reasons': list(validation.get('reasons') or []),
            'confidence': validation.get('confidence'),
        })

    if not classifications and not prior_validations:
        return _skipped(
            'T08',
            category,
            'no HTTP captures or prior case validations to classify (run T01 or earlier test cases first)',
        )

    counts: dict[str, int] = {}
    for row in classifications + prior_validations:
        key = str(row.get('status') or 'UNKNOWN')
        counts[key] = counts.get(key, 0) + 1
    detail = (
        'classified %s HTTP capture(s) and %s prior case validation(s): %s'
        % (len(classifications), len(prior_validations), counts)
    )
    return _passed(
        'T08',
        category,
        detail,
        classifications=classifications,
        prior_validations=prior_validations,
        validation_counts=counts,
    )


def _fp_ctx_from_pair(pair: HttpPair) -> dict[str, Any]:
    return {
        'status_code': pair.status,
        'response_body': pair.response_body or '',
        'protected_data_exposed': False,
        'authorization_bypass': False,
    }


def _run_t09_false_positive(ctx: TestContext, category: str) -> dict[str, Any]:
    reviews: list[dict[str, Any]] = []
    for raw in _pairs(ctx):
        pair = _as_pair(raw)
        if pair is None:
            continue
        fp = check_false_positive(_fp_ctx_from_pair(pair))
        reviews.append({
            'source': 'http_pair',
            'url': _pair_url(pair),
            'http_status': pair.status,
            'is_likely_fp': bool(fp.get('is_likely_fp')),
            'reasons': list(fp.get('reasons') or []),
            'allow_manual_review': bool(fp.get('allow_manual_review', True)),
        })

    for case in _prior_cases(ctx):
        validation = case.get('validation') or {}
        if not isinstance(validation, dict) or not validation.get('status'):
            continue
        existing = case.get('false_positive') if isinstance(case.get('false_positive'), dict) else {}
        vstatus = str(validation.get('status') or '').upper()
        exposed = vstatus == 'CONFIRMED'
        fp = existing or check_false_positive({
            'status_code': None,
            'protected_data_exposed': exposed,
            'authorization_bypass': vstatus in {'CONFIRMED', 'POTENTIAL'},
        })
        reviews.append({
            'source': 'prior_case',
            'test_id': case.get('test_id'),
            'validation_status': vstatus,
            'is_likely_fp': bool(fp.get('is_likely_fp')),
            'reasons': list(fp.get('reasons') or []),
            'allow_manual_review': bool(fp.get('allow_manual_review', True)),
            'not_suppressed': exposed and not bool(fp.get('is_likely_fp')),
        })

    if not reviews:
        return _skipped(
            'T09',
            category,
            'no HTTP captures or prior validations to review for false positives',
        )

    likely = sum(1 for r in reviews if r.get('is_likely_fp'))
    detail = (
        'false-positive review of %s observation(s); %s likely-FP, manual review still allowed'
        % (len(reviews), likely)
    )
    return _passed('T09', category, detail, reviews=reviews, likely_fp_count=likely)


def _run_t10_screenshot_annotation(ctx: TestContext, category: str) -> dict[str, Any]:
    from attestra.automated_vapt.evidence.screenshot_annotator import (
        AnnotateError,
        annotate_screenshot,
        pillow_available,
    )

    shots = _shots(ctx)
    originals = {
        name: data
        for name, data in shots.items()
        if 'annotated' not in name.lower()
    }
    if not originals:
        return _skipped('T10', category, 'no screenshots to annotate (run T02 first)')
    if not pillow_available():
        return _skipped('T10', category, 'Pillow is not available for screenshot annotation')

    annotated_names: list[str] = []
    errors: list[str] = []
    store = ctx.extra.setdefault('_screenshots', {})
    for name, data in originals.items():
        try:
            marked, _meta = annotate_screenshot(
                data,
                [{'x': 8, 'y': 8, 'w': 48, 'h': 24, 'label': 'T10'}],
                caption='T10 annotated evidence - %s' % name,
            )
        except (AnnotateError, Exception) as exc:  # noqa: BLE001
            errors.append('%s: %s' % (name, type(exc).__name__))
            continue
        if not marked or not marked.startswith(b'\x89PNG'):
            errors.append('%s: annotator returned non-PNG' % name)
            continue
        stem = name.rsplit('.', 1)[0] if '.' in name else name
        new_name = '%s_annotated.png' % stem
        store[new_name] = marked
        annotated_names.append(new_name)

    if not annotated_names:
        return _skipped(
            'T10',
            category,
            'annotation failed on all screenshots (%s)' % ('; '.join(errors) or 'unknown error'),
        )
    detail = 'annotated %s of %s screenshot(s)' % (len(annotated_names), len(originals))
    if errors:
        detail += '; %s failed' % len(errors)
    return _passed(
        'T10',
        category,
        detail,
        annotated=annotated_names,
        annotation_errors=errors,
    )


def _header_map(headers: Any) -> dict[str, str]:
    if not isinstance(headers, dict):
        return {}
    return {str(k): str(v) for k, v in headers.items()}


def _run_t11_evidence_redaction(ctx: TestContext, category: str) -> dict[str, Any]:
    pairs = [p for p in (_as_pair(raw) for raw in _pairs(ctx)) if p is not None]
    if not pairs:
        return _skipped('T11', category, 'no HTTP captures to redact (run T01 first)')

    redacted_pairs: list[HttpPair] = []
    masked_headers = 0
    leftover_sensitive = 0
    for pair in pairs:
        red = redact_http_pair(pair)
        redacted_pairs.append(red)
        original = {k.lower(): v for k, v in _header_map(pair.request_headers).items()}
        original.update({k.lower(): v for k, v in _header_map(pair.response_headers).items()})
        cleaned = {k.lower(): v for k, v in _header_map(red.request_headers).items()}
        cleaned.update({k.lower(): v for k, v in _header_map(red.response_headers).items()})
        for name in _SENSITIVE_HEADERS:
            raw_val = original.get(name) or ''
            new_val = cleaned.get(name) or ''
            if not raw_val:
                continue
            if new_val != raw_val or new_val.lower() in {'[redacted]', 'redacted'}:
                masked_headers += 1
            elif raw_val.strip():
                leftover_sensitive += 1

    ctx.extra['_redacted_pairs'] = redacted_pairs
    if leftover_sensitive:
        return {
            'test_id': 'T11',
            'status': 'FAILED',
            'detail': 'redaction left %s sensitive header value(s) unmasked' % leftover_sensitive,
            'category': category,
            'pairs_redacted': len(redacted_pairs),
            'masked_headers': masked_headers,
            'unmasked_sensitive_headers': leftover_sensitive,
        }
    detail = 'redacted %s HTTP pair(s); masked %s sensitive header(s)' % (
        len(redacted_pairs),
        masked_headers,
    )
    return _passed(
        'T11',
        category,
        detail,
        pairs_redacted=len(redacted_pairs),
        masked_headers=masked_headers,
    )


def _pair_bytes(pair: HttpPair) -> bytes:
    try:
        return pair.to_bytes()
    except Exception:  # noqa: BLE001
        blob = '%s %s %s' % (pair.method, pair.url, pair.status)
        return blob.encode('utf-8', errors='replace')


def _run_t12_evidence_integrity(ctx: TestContext, category: str) -> dict[str, Any]:
    pairs = [p for p in (_as_pair(raw) for raw in _pairs(ctx)) if p is not None]
    shots = _shots(ctx)
    if not pairs and not shots:
        return _skipped('T12', category, 'no HTTP captures or screenshots to hash (run T01/T02 first)')

    manifest = EvidenceManifest(
        engagement_id=int(ctx.engagement_id or 0),
        test_execution_id=int(ctx.extra.get('execution_id') or 0),
    )
    entries: list[dict[str, str]] = []
    verified = 0
    failed = 0
    for idx, pair in enumerate(pairs, 1):
        data = _pair_bytes(pair)
        eid = 'http-%s' % idx
        entry = manifest.add(
            evidence_id=eid,
            file_name='http_pair_%s.bin' % idx,
            data=data,
            capture_method='http_capture',
        )
        ok = manifest.verify(eid, data)
        verified += int(ok)
        failed += int(not ok)
        entries.append({'evidence_id': eid, 'hash': entry.hash, 'verified': ok})
    for name, data in shots.items():
        eid = 'shot-%s' % name
        entry = manifest.add(
            evidence_id=eid,
            file_name=str(name),
            data=data,
            capture_method='screenshot',
        )
        ok = manifest.verify(eid, data) and entry.hash == sha256_hex(data)
        verified += int(ok)
        failed += int(not ok)
        entries.append({'evidence_id': eid, 'hash': entry.hash, 'verified': ok})

    if failed:
        return {
            'test_id': 'T12',
            'status': 'FAILED',
            'detail': 'evidence integrity failed for %s of %s item(s)' % (failed, len(entries)),
            'category': category,
            'verified': verified,
            'failed': failed,
            'manifest_entries': entries,
        }
    detail = 'SHA-256 verified for %s evidence item(s)' % verified
    return _passed(
        'T12',
        category,
        detail,
        verified=verified,
        failed=0,
        manifest_entries=entries,
    )


def _run_t13_finding_mapping(ctx: TestContext, category: str) -> dict[str, Any]:
    prior = _prior_cases(ctx)
    if not prior:
        return _skipped(
            'T13',
            category,
            'no prior case results to map (run other test cases first)',
        )

    try:
        from attestra.finding_validation.classify import should_create_elite_finding
    except Exception:  # noqa: BLE001
        def should_create_elite_finding(validation: dict[str, Any], fp_check: dict[str, Any]) -> bool:
            status = str((validation or {}).get('status') or '').upper()
            if status not in {'CONFIRMED', 'POTENTIAL'}:
                return False
            return not bool((fp_check or {}).get('is_likely_fp'))

    finding_map: list[dict[str, Any]] = []
    for case in prior:
        validation = case.get('validation') if isinstance(case.get('validation'), dict) else {}
        vstatus = str((validation or {}).get('status') or '').upper()
        if vstatus not in {'CONFIRMED', 'POTENTIAL'}:
            continue
        fp = case.get('false_positive') if isinstance(case.get('false_positive'), dict) else {}
        cwe = case.get('finding_cwe') or validation.get('cwe') or 639
        try:
            cwe_i = int(cwe) if cwe is not None else None
        except (TypeError, ValueError):
            cwe_i = 639
        title = case.get('finding_title') or (
            'Automated test %s: %s' % (case.get('test_id'), validation.get('title_suffix') or 'authorization issue')
        )
        location = str(case.get('finding_location') or ctx.target_base_url or '')
        finding_map.append({
            'source_test_id': case.get('test_id'),
            'validation_status': vstatus,
            'finding_id': case.get('finding_id'),
            'title': str(title)[:500],
            'cwe': cwe_i,
            'severity': severity_for(
                cwe=cwe_i,
                hints={'protected_data_exposed': vstatus == 'CONFIRMED'},
            ),
            'location': location[:1000],
            'would_create_finding': bool(should_create_elite_finding(validation, fp)),
            'already_created': case.get('finding_id') is not None,
        })

    if not finding_map:
        return _passed(
            'T13',
            category,
            'no confirmed or potential results to map to findings',
            finding_map=[],
        )
    already = sum(1 for row in finding_map if row.get('already_created'))
    would = sum(1 for row in finding_map if row.get('would_create_finding'))
    detail = (
        'mapped %s confirmed/potential result(s); %s already created, %s eligible'
        % (len(finding_map), already, would)
    )
    return _passed('T13', category, detail, finding_map=finding_map)


def _run_t14_report_integration(ctx: TestContext, category: str) -> dict[str, Any]:
    prior = _prior_cases(ctx)
    pairs = [p for p in (_as_pair(raw) for raw in _pairs(ctx)) if p is not None]
    shots = _shots(ctx)
    in_memory = bool(pairs or shots)

    listed: list[str] = []
    report_listed: list[str] = []
    subset_issues = 0
    for case in prior:
        files = [str(f) for f in (case.get('evidence_files') or []) if f]
        report = [str(f) for f in (case.get('report_evidence_files') or []) if f]
        listed.extend(files)
        report_listed.extend(report)
        if report and files and not set(report).issubset(set(files)):
            subset_issues += 1

    if not prior and not in_memory:
        return _skipped(
            'T14',
            category,
            'no prior case evidence or in-memory captures to include in a report',
        )
    if not listed and not in_memory:
        return _passed(
            'T14',
            category,
            'prior cases produced no evidence files; nothing to embed in the report',
            evidence_files=[],
            report_evidence_files=[],
            on_disk=0,
            in_memory_pairs=0,
            in_memory_screenshots=0,
        )

    on_disk = 0
    missing = 0
    execution_id = int(ctx.extra.get('execution_id') or 0)
    if execution_id and listed:
        try:
            from attestra.automated_vapt.evidence.run_evidence import run_dir, safe_evidence_path

            folder_exists = run_dir(execution_id).is_dir()
        except Exception:  # noqa: BLE001
            folder_exists = False
            safe_evidence_path = None  # type: ignore[assignment]
        if folder_exists and safe_evidence_path is not None:
            for fname in listed:
                path = safe_evidence_path(execution_id, fname)
                if path is not None:
                    on_disk += 1
                else:
                    missing += 1

    reportable = 0
    try:
        from attestra.automated_vapt.evidence.run_evidence import report_image_files

        for case in prior:
            reportable += len(report_image_files(case) or [])
    except Exception:  # noqa: BLE001
        reportable = len(report_listed)

    detail = (
        'report integration ready: %s listed file(s), %s on disk, %s in-memory pair(s), '
        '%s in-memory screenshot(s), %s report-embed image(s)'
        % (len(listed), on_disk, len(pairs), len(shots), reportable)
    )
    if subset_issues:
        detail += '; %s case(s) have report_evidence_files outside evidence_files' % subset_issues
    if missing:
        detail += '; %s listed file(s) not found on disk' % missing
    return _passed(
        'T14',
        category,
        detail,
        evidence_files=listed,
        report_evidence_files=report_listed,
        on_disk=on_disk,
        missing_on_disk=missing,
        in_memory_pairs=len(pairs),
        in_memory_screenshots=len(shots),
        report_embed_count=reportable,
        subset_issues=subset_issues,
    )
