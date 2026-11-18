from copy import deepcopy
import json
import pytest
import peaso.image_findings as module
from peaso.image_findings import build_report

D = 'sha256:' + 'a' * 64
BASE = {'provider': 'gcp', 'scope': 'projects/example-project',
    'asset_id': 'projects/example-project/locations/us-central1/jobs/example',
    'asset_kind': 'cloud_run_job', 'scan': {
        'image': {'provider': 'gcp', 'scope': 'projects/example-project',
            'immutable_reference': 'us-docker.pkg.dev/example-project/repo/image@' + D,
            'manifest_digest': D, 'config_digest': 'sha256:' + 'b' * 64},
        'status': 'FAIL', 'complete': True, 'scan_complete': True,
        'coverage_status': 'COMPLETE', 'database': {'fresh': True},
        'findings': [{'vulnerability_id': 'CVE-2026-12345', 'severity': 'HIGH',
            'package_types': ['alpine'], 'package': 'busybox', 'version': '1.0',
            'fixed_in': ['1.1'], 'fix_status': 'fixed', 'classes': ['os-pkgs'],
            'image_digest': D}]}}


def test_one_immutable_leak_row_and_multiple_asset_locations():
    second = deepcopy(BASE)
    second['asset_id'] += '-other'
    rows = build_report([BASE, BASE, second], selected=True)
    assert rows['complete'] and rows['coverage'] == 'COMPLETE'
    assert len(rows['rows']) == 1
    assert len(rows['rows'][0]['affected_assets']) == 2
    assert rows['rows'][0]['fixed_versions'] == ['1.1']


def test_deterministic_identity_and_order():
    second = deepcopy(BASE)
    second['scan']['findings'][0]['severity'] = 'CRITICAL'
    second['asset_id'] += '-other'
    left, right = build_report([BASE, second], selected=True), build_report([second, BASE], selected=True)
    assert left == right
    assert left['rows'][0]['severity'] == 'CRITICAL'


@pytest.mark.parametrize('provider', ['aws', 'gcp', 'azure', 'k8s'])
def test_all_provider_shapes_supported(provider):
    row = deepcopy(BASE)
    row['provider'] = row['scan']['image']['provider'] = provider
    assert len(build_report([row], selected=True)['rows']) == 1


def test_scope_and_provider_never_merged():
    other = deepcopy(BASE)
    other['scope'] = other['scan']['image']['scope'] = 'projects/another-project'
    assert len(build_report([BASE, other], selected=True)['rows']) == 2
    other['provider'] = other['scan']['image']['provider'] = 'k8s'
    assert len(build_report([BASE, other], selected=True)['rows']) == 2


def test_unselected_and_empty_are_not_clean():
    assert build_report([BASE])['coverage'] == 'NOT_SCANNED'
    result = build_report([], selected=True)
    assert not result['complete'] and result['coverage'] == 'UNKNOWN'


def test_supported_complete_clean_is_distinct():
    row = deepcopy(BASE)
    row['scan'].update(status='PASS', findings=[])
    result = build_report([row], selected=True)
    assert result['complete'] and result['coverage'] == 'COMPLETE' and result['rows'] == []


def test_partial_positive_preserved_without_clean_claim():
    row = deepcopy(BASE)
    row['scan'].update(complete=False, scan_complete=False, coverage_status='UNKNOWN', database={'fresh': False})
    result = build_report([row], selected=True)
    assert len(result['rows']) == 1 and result['rows'][0]['coverage'] == 'UNKNOWN'
    assert result['coverage'] == 'UNKNOWN' and not result['complete']


@pytest.mark.parametrize('mutation', [
    lambda r: r['scan']['image'].update(provider='azure'),
    lambda r: r['scan']['image'].update(scope='projects/foreign'),
    lambda r: r['scan']['image'].update(immutable_reference='user:pass@evil.example/image'),
    lambda r: r['scan']['image'].update(manifest_digest='sha256:' + 'c' * 64),
    lambda r: r['scan'].update(status='PASS'),
    lambda r: r['scan'].update(complete='true'),
    lambda r: r['scan'].update(database={'fresh': False}),
])
def test_unbound_or_contradictory_scan_never_claims_clean(mutation):
    row = deepcopy(BASE)
    mutation(row)
    result = build_report([row], selected=True)
    assert result['coverage'] == 'UNKNOWN' and not result['rows']


@pytest.mark.parametrize('mutation', [
    lambda v: v.update(image_digest='sha256:' + 'c' * 64),
    lambda v: v.update(vulnerability_id='<script>'),
    lambda v: v.update(severity='LOW'),
    lambda v: v.update(package='not\na\tpackage'),
    lambda v: v.update(fixed_in=['https://untrusted.example']),
    lambda v: v.update(fix_status='unreviewed'),
])
def test_malformed_vulnerability_discarded_and_coverage_incomplete(mutation):
    row = deepcopy(BASE)
    mutation(row['scan']['findings'][0])
    result = build_report([row], selected=True)
    assert result['coverage'] == 'UNKNOWN' and not result['rows']
    assert result['invalid_vulnerabilities'] == 1


def test_unknown_fields_and_sensitive_diagnostics_not_forwarded():
    row = deepcopy(BASE)
    row['credentials'] = row['scan']['stderr'] = 'synthetic-sensitive-canary'
    result = build_report([row], selected=True)
    assert result['complete']
    assert 'synthetic-sensitive-canary' not in json.dumps(result)


def test_bounds_never_silently_report_complete(monkeypatch):
    monkeypatch.setattr(module, 'MAX_OBSERVATIONS', 1)
    result = build_report([BASE, BASE], selected=True)
    assert result['truncated'] and not result['complete']
    monkeypatch.setattr(module, 'MAX_TOTAL_VULNERABILITIES', 0)
    result = build_report([BASE], selected=True)
    assert result['truncated'] and not result['rows']


def test_affected_assets_bound_explicit(monkeypatch):
    monkeypatch.setattr(module, 'MAX_ASSETS_PER_ROW', 1)
    second = deepcopy(BASE)
    second['asset_id'] += '-other'
    result = build_report([BASE, second], selected=True)
    assert result['truncated'] and not result['complete']
    assert result['rows'][0]['coverage'] == 'UNKNOWN'
    assert len(result['rows'][0]['affected_assets']) == 1


def _aws(repository, digest_char, *, findings=True, complete=True):
    """Shape emitted by the AWS selected-image collector for an ECR digest."""
    digest = 'sha256:' + digest_char * 64
    scope = '244541190879/us-east-1'
    row = deepcopy(BASE)
    row.update(provider='aws', scope=scope, asset_kind='ecr_image',
               asset_id=f'arn:aws:ecr:us-east-1:244541190879:repository/{repository}@{digest}')
    row['scan']['image'] = {'provider': 'aws', 'scope': scope,
        'immutable_reference': f'244541190879.dkr.ecr.us-east-1.amazonaws.com/{repository}@{digest}',
        'manifest_digest': digest, 'config_digest': 'sha256:' + 'c' * 64}
    row['scan']['findings'] = [dict(row['scan']['findings'][0], image_digest=digest)] if findings else []
    row['scan'].update(status='FAIL' if findings else 'PASS' if complete else 'UNKNOWN',
                       complete=complete, scan_complete=complete,
                       coverage_status='COMPLETE' if complete else 'UNKNOWN')
    return row


def test_incomplete_positive_and_unknown_clean_are_accepted_not_invalid():
    observations = [_aws('cade/gateway', 'd'), _aws('cade/scheduling-subscribe', 'e', complete=False),
                    _aws('cade/migrate', 'f', findings=False),
                    _aws('cade/catalog-subscribe', '1', findings=False, complete=False)]
    report = build_report(observations, selected=True)
    assert (report['observations'], report['invalid_observations'], report['invalid_reasons']) == (4, 0, {})
    assert report['coverage'] == 'UNKNOWN' and not report['complete']
    assert {row['image_reference'].split('/', 1)[1].split('@')[0]: row['coverage'] for row in report['rows']} == {
        'cade/gateway': 'COMPLETE', 'cade/scheduling-subscribe': 'UNKNOWN'}


def test_rejections_are_counted_by_reason():
    unknown_with_findings = _aws('cade/a', '2')
    unknown_with_findings['scan']['status'] = 'UNKNOWN'
    foreign = _aws('cade/b', '3')
    foreign['scan']['image']['scope'] = '999999999999/us-east-1'
    bad_vulnerability = _aws('cade/c', '4')
    bad_vulnerability['scan']['findings'][0]['severity'] = 'LOW'
    report = build_report([None, None, 'x', {}, unknown_with_findings, foreign,
                           {'rejected': 'foreign_image'}, bad_vulnerability], selected=True)
    assert report['invalid_reasons'] == {'missing_observation': 2, 'invalid_observation': 1,
        'missing_field': 1, 'contradictory_scan_status': 1, 'foreign_image': 2}
    assert report['invalid_observations'] == 7
    assert report['invalid_vulnerability_reasons'] == {'invalid_vulnerability_status': 1}
    assert report['invalid_vulnerabilities'] == 1 and report['coverage'] == 'UNKNOWN'


def test_rejected_marker_never_echoes_untrusted_reason_text():
    report = build_report([{'rejected': 'Secret Value!'}], selected=True)
    assert report['invalid_reasons'] == {'invalid_observation': 1}
