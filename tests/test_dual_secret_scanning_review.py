"""Independent dual-scanner review: synthetic GitHub tokens, detection only.

Real integration cases require the pinned optional Kingfisher distribution and
TruffleHog binary. No cloud calls, validation/revocation or real credentials.
"""
import copy
from importlib.metadata import version
import io
import json
from types import SimpleNamespace
import zipfile

import pytest
from peaso import secret_scanning as scanning
from peaso.secret_findings import deduplicate_secret_findings

# Deliberately synthetic, high entropy, correctly shaped PATs. Never validated.
TOKEN_A = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
TOKEN_B = 'ghp_' + '2Yt9Ec5Zp0Ru6Wq1Aa8Kd3Vx7Mn4Bs5Hj9Lf'
SCOPE = '123456789012/us-east-1'


@pytest.fixture(autouse=True)
def isolated_cache():
    # Engine monkeypatches must never reuse an earlier engine's cached verdict.
    if hasattr(scanning, '_RESULTS'):
        scanning._RESULTS.clear()
    yield
    if hasattr(scanning, '_RESULTS'):
        scanning._RESULTS.clear()


@pytest.fixture(scope='module')
def real_scans():
    pytest.importorskip('kingfisher_sdk', reason='requires optional pinned scanner SDK')
    assert version('kingfisher-secret-scanner') == '1.4.0'
    executable = scanning._trufflehog()
    assert executable
    # SDK ScanInput does detection only; TH adapter supplies explicit offline flags.
    first = scanning.scan_content((f'github_token={TOKEN_A}\ncopy={TOKEN_A}\nother={TOKEN_B}\n').encode(), 'src/config.py')
    second = scanning.scan_content((f'token={TOKEN_A}\n').encode(), 'logs/synthetic.log')
    assert first['complete'] and second['complete']
    return first, second


def finding(leaks, *, check='synthetic.code', asset='asset-a', scope=SCOPE, status='FAIL'):
    return {'id': check+'-'+asset, 'provider': 'aws', 'check_id': check, 'scope': scope,
            'resource_id': asset, 'native_resource_id': 'arn:synthetic:'+asset,
            'resource_type': 'lambda_function', 'category': 'exposure', 'title': 'Synthetic scan',
            'status': status, 'severity': 'high', 'frameworks': ['Synthetic'],
            'evidence': {'secret_leaks': copy.deepcopy(leaks)}}


def test_real_installed_engines_agree_without_exposing_values(real_scans, capsys):
    first, second = real_scans
    assert len(first['leaks']) == 2
    assert len(second['leaks']) == 1
    assert {r['engine'] for r in first['engines']} == {'kingfisher', 'trufflehog'}
    assert all({d['engine'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'} for leak in first['leaks'])
    encoded = json.dumps([first, second]) + str(capsys.readouterr())
    assert TOKEN_A not in encoded and TOKEN_B not in encoded
    assert all(len(leak['fingerprint']) == 64 for leak in first['leaks'])


def test_real_repeated_multiline_locations_and_distinct_secrets(real_scans):
    first, second = real_scans
    shared = second['leaks'][0]['fingerprint']
    matches = next(leak for leak in first['leaks'] if leak['fingerprint'] == shared)
    assert {loc.get('line') for loc in matches['locations']} == {1, 2}
    assert len({leak['fingerprint'] for leak in first['leaks']}) == 2


def test_one_finding_per_real_leak_across_checks_assets_and_scopes(real_scans):
    first, second = real_scans
    original = [finding(first['leaks']), finding(second['leaks'], check='synthetic.logs', asset='asset-b',
                    scope='123456789012/eu-west-1')]
    before = copy.deepcopy(original)
    rows = deduplicate_secret_findings(original)
    assert original == before
    assert len(rows) == 2
    shared = next(r for r in rows if r['secret_fingerprint'] == second['leaks'][0]['fingerprint'])
    assert shared['linked_check_ids'] == ['synthetic.code', 'synthetic.logs']
    locs = shared['evidence']['secret_leaks'][0]['locations']
    assert {loc['resource_id'] for loc in locs} == {'arn:synthetic:asset-a', 'arn:synthetic:asset-b'}
    assert {loc['scope'] for loc in locs} == {SCOPE, '123456789012/eu-west-1'}
    assert len(locs) == 3
    from peaso.finding_groups import group_findings
    assert len(group_findings(rows)) == 2
    assert TOKEN_A not in json.dumps(rows) and TOKEN_B not in json.dumps(rows)


def test_real_detected_value_in_filename_keeps_exact_path_but_not_cache():
    pytest.importorskip('kingfisher_sdk')
    outcome = scanning.scan_content((f'token={TOKEN_A}\n').encode(), f'src/{TOKEN_A}.py')
    assert outcome['complete'] and outcome['leaks']
    # The owner sees the exact detector path; the process-wide cache never holds it.
    assert {loc['path'] for leak in outcome['leaks'] for loc in leak['locations']} == {f'src/{TOKEN_A}.py'}
    assert TOKEN_A not in repr(scanning._RESULTS)


@pytest.mark.parametrize('failed_engine', ['kingfisher', 'trufflehog'])
@pytest.mark.parametrize('error_type', [ImportError, RuntimeError, TimeoutError])
@pytest.mark.parametrize('positive', [False, True])
def test_missing_or_failed_engine_never_proves_complete_absence(monkeypatch, failed_engine, error_type, positive, capsys):
    def failed(*args):
        raise error_type('sensitive exception '+TOKEN_A)
    def available(*args):
        return [(TOKEN_A, 'synthetic-github', 2)] if positive else []
    monkeypatch.setattr(scanning, '_scan_'+failed_engine, failed)
    other = 'trufflehog' if failed_engine == 'kingfisher' else 'kingfisher'
    monkeypatch.setattr(scanning, '_scan_'+other, available)
    result = scanning.scan_content(b'synthetic payload', 'file.py')
    assert result['complete'] is False
    assert {r['engine']: r['status'] for r in result['engines']} == {failed_engine: 'unavailable', other: 'complete'}
    assert len(result['leaks']) == int(positive)
    assert TOKEN_A not in json.dumps(result) + str(capsys.readouterr())


def test_error_is_not_cached_as_clean_and_cached_results_are_redacted(monkeypatch):
    count = {'calls': 0}
    def transient(*args):
        count['calls'] += 1
        if count['calls'] == 1:
            raise RuntimeError(TOKEN_A)
        return [(TOKEN_A, 'synthetic-github', 1)]
    monkeypatch.setattr(scanning, '_scan_kingfisher', transient)
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *args: [])
    first = scanning.scan_content(b'payload', 'file.py')
    second = scanning.scan_content(b'payload', 'file.py')
    third = scanning.scan_content(b'payload', 'file.py')
    assert not first['complete'] and second['complete'] and third == second
    # Positive outcomes are never cached, so the found value stays out of the
    # process-wide cache and the third scan runs the engine again.
    assert count['calls'] == 3
    assert third['leaks'] and third['leaks'][0]['fingerprint'] == scanning._fingerprint(TOKEN_A)
    assert TOKEN_A not in repr(scanning._RESULTS)
    assert b'payload' not in repr(scanning._RESULTS).encode()


@pytest.mark.parametrize('raw_output', [b'not-json', b'{"Raw":"value","Verified":true}', b'[]'])
def test_malformed_trufflehog_result_is_incomplete_without_raw_output(monkeypatch, raw_output):
    monkeypatch.setattr(scanning, '_trufflehog', lambda: '/synthetic/trufflehog')
    monkeypatch.setattr(scanning, '_run', lambda *args: raw_output)
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *args: [])
    result = scanning.scan_content(b'payload')
    assert result['complete'] is False and not result['leaks']
    assert {r['engine']:r['status'] for r in result['engines']}['trufflehog'] == 'unavailable'


def test_trufflehog_adapter_always_disables_verification_updates_and_archives(monkeypatch):
    calls = []
    monkeypatch.setattr(scanning, '_trufflehog', lambda: '/synthetic/trufflehog')
    def run(argv, payload, timeout):
        calls.append(argv)
        return b''
    monkeypatch.setattr(scanning, '_run', run)
    assert scanning._scan_trufflehog(b'payload', 'file', 1) == []
    assert len(calls) == 1
    assert {'stdin', '--json', '--no-verification', '--no-update', '--no-verification-cache',
            '--force-skip-archives', '--fail-on-scan-errors'} <= set(calls[0])


def test_package_negative_with_missing_engine_stays_partial(monkeypatch):
    from peaso.collectors import aws_package_content_indicators as packages
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *args: [])
    def absent(*args): raise ImportError('not installed')
    monkeypatch.setattr(scanning, '_scan_trufflehog', absent)
    zipped = io.BytesIO()
    with zipfile.ZipFile(zipped, 'w') as z:
        z.writestr('file.txt', 'ready=true')
    with pytest.raises(packages.PartialArchive) as caught:
        packages.scan_zip(zipped.getvalue(), SimpleNamespace(check_deadline=lambda: None))
    assert caught.value.refs == []


def test_malformed_external_leak_cannot_abort_unrelated_findings():
    from peaso.checks import aws_package_content_review_20261019 as checks
    item, index = checks._fixture('lambda_function', True)
    item['PackageContentSource']['PackageSecretIndicators']['References'][0]['Leaks'] = [
        {'fingerprint': 'invalid', 'detectors': [], 'locations': []}]
    status, evidence = checks.function_code(item, index)
    safe = finding([], status='UNKNOWN', check='unrelated')
    suspect = finding([], check='malformed')
    suspect.update(status=status, evidence=evidence)
    rows = deduplicate_secret_findings([safe, suspect])
    assert any(r['check_id'] == 'unrelated' and r['status'] == 'UNKNOWN' for r in rows)
    assert all(r['check_id'] != 'malformed' or r['status'] == 'UNKNOWN' for r in rows)


def test_engine_report_retains_one_row_per_real_leak_across_native_kinds(real_scans):
    from peaso import engine
    from peaso.snapshot import make_snapshot
    from peaso.checks import aws_package_content_review_20261019 as checks
    collections = []
    selected = []
    for kind, result in zip(('lambda_function', 'lambda_layer_version'), real_scans):
        item, _ = checks._fixture(kind, True)
        refs = item['PackageContentSource']['PackageSecretIndicators']['References']
        refs[0].update(Categories=['secret'], Leaks=result['leaks'])
        collections.append({'type': kind, 'scope': SCOPE, 'status': 'collected', 'items': [item]})
        selected.append(next(d['id'] for d in checks.DECLARATIONS if d['kind'] == kind))
    snapshot = make_snapshot('aws', [SCOPE], collections)
    report = engine.evaluate_snapshot(snapshot, checks=selected)
    failed = [r for r in report['findings'] if r['status'] == 'FAIL']
    assert len(failed) == 2
    assert report['stats']['by_status']['FAIL'] == 2
    assert len({r['secret_fingerprint'] for r in failed}) == 2
    shared = next(r for r in failed if len(r['linked_check_ids']) == 2)
    assert len(shared['evidence']['secret_leaks'][0]['locations']) == 3
    assert TOKEN_A not in json.dumps(report) and TOKEN_B not in json.dumps(report)
    from peaso.finding_groups import group_findings
    from peaso.storage.reports import finding_summary, publish_report
    compact = [finding_summary(row) for row in failed]
    assert len(group_findings(compact)) == 2
    assert all(row['secret_fingerprint'] and row['linked_check_ids'] for row in compact)
    class MemoryArtifacts:
        def __init__(self): self.rows = {}
        def put(self, tenant, ident, kind, value):
            key = kind+'-'+str(len(self.rows))
            self.rows[key] = copy.deepcopy(value)
            return key
        def put_text(self, tenant, ident, kind, value): return self.put(tenant, ident, kind, value)
    artifacts = MemoryArtifacts()
    manifest = artifacts.rows[publish_report(artifacts, 'synthetic-tenant', 'd' * 32, report)]
    persisted = [row for chunk in manifest['finding_index_chunks']
                 for row in artifacts.rows[chunk['reference']]['items']]
    assert len(group_findings(persisted)) == 2
    assert len({row['secret_fingerprint'] for row in persisted}) == 2
    assert TOKEN_A not in json.dumps(artifacts.rows) and TOKEN_B not in json.dumps(artifacts.rows)


def test_full_engine_report_handles_malformed_external_leak():
    from peaso import engine
    from peaso.snapshot import make_snapshot
    from peaso.checks import aws_package_content_review_20261019 as checks
    item, _ = checks._fixture('lambda_function', True)
    item['PackageContentSource']['PackageSecretIndicators']['References'][0]['Leaks'] = [
        {'fingerprint': 'invalid', 'detectors': [], 'locations': []}]
    snapshot = make_snapshot('aws', [SCOPE], [
        {'type': 'lambda_function', 'scope': SCOPE, 'status': 'collected', 'items': [item]}])
    cid = next(d['id'] for d in checks.DECLARATIONS if d['kind'] == 'lambda_function')
    report = engine.evaluate_snapshot(snapshot, checks=[cid])
    assert any(row['status'] == 'UNKNOWN' for row in report['findings'])


def test_path_redaction_unions_values_detected_by_different_engines(monkeypatch):
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *args: [(TOKEN_A, 'synthetic-github', 1)])
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *args: [(TOKEN_B, 'synthetic-github', 1)])
    result = scanning.scan_content((TOKEN_A+' '+TOKEN_B).encode(), f'{TOKEN_A}/{TOKEN_B}.txt')
    assert result['complete'] and len(result['leaks']) == 2
    # Found values stay visible in the exact detector path.
    assert {loc['path'] for leak in result['leaks'] for loc in leak['locations']} == {f'{TOKEN_A}/{TOKEN_B}.txt'}
    assert TOKEN_A not in repr(scanning._RESULTS) and TOKEN_B not in repr(scanning._RESULTS)


def test_subprocess_timeout_kills_and_reaps_child(monkeypatch):
    import sys
    children = []
    popen = scanning.subprocess.Popen
    def tracked(*args, **kwargs):
        process = popen(*args, **kwargs)
        children.append(process)
        return process
    monkeypatch.setattr(scanning.subprocess, 'Popen', tracked)
    with pytest.raises(TimeoutError):
        scanning._run([sys.executable, '-c', 'import time; time.sleep(10)'], b'', .05)
    assert len(children) == 1 and children[0].returncode is not None
    assert children[0].stdout.closed and children[0].stdin.closed


def test_subprocess_output_bound_kills_and_reaps_child(monkeypatch):
    import sys
    children = []
    popen = scanning.subprocess.Popen
    def tracked(*args, **kwargs):
        process = popen(*args, **kwargs)
        children.append(process)
        return process
    monkeypatch.setattr(scanning.subprocess, 'Popen', tracked)
    monkeypatch.setattr(scanning, 'MAX_OUTPUT', 1024)
    with pytest.raises(ValueError, match='output bound'):
        scanning._run([sys.executable, '-c', 'import sys,time; sys.stdout.write("x"*2048); sys.stdout.flush(); time.sleep(10)'], b'', 1)
    assert len(children) == 1 and children[0].returncode is not None
    assert children[0].stdout.closed and children[0].stdin.closed


def test_subprocess_stderr_is_private_and_credentials_are_not_inherited(monkeypatch, capfd):
    import sys
    monkeypatch.setenv('AWS_ACCESS_KEY_ID', 'synthetic-inert')
    monkeypatch.setenv('AWS_SECRET_ACCESS_KEY', 'synthetic-inert')
    monkeypatch.setenv('GITHUB_TOKEN', TOKEN_A)
    script = 'import os,json; print(json.dumps({k:k in os.environ for k in ("AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY","GITHUB_TOKEN")}))'
    assert scanning._run([sys.executable, '-c', script], b'', 2).strip() == b'{"AWS_ACCESS_KEY_ID": false, "AWS_SECRET_ACCESS_KEY": false, "GITHUB_TOKEN": false}'
    with pytest.raises(RuntimeError, match='scanner failed') as caught:
        scanning._run([sys.executable, '-c', 'import sys; sys.stderr.write('+repr(TOKEN_A)+'); sys.exit(9)'], b'', 2)
    assert TOKEN_A not in str(caught.value) + str(capfd.readouterr())


def test_metadata_redaction_marks_altered_facts_unavailable():
    from peaso.checks.facts import get, Unavailable
    source = {'serviceConfig': {'environmentVariableNames': ['secret-canary']},
              'description': 'secret-canary', 'safe': True}
    safe = scanning.redact_matches(source, {'secret-canary'})
    # Found values stay visible, so the native facts remain available as collected.
    assert safe == source and safe is not source and safe['serviceConfig'] is not source['serviceConfig']
    assert get(safe, 'serviceConfig.environmentVariableNames', list) == ['secret-canary']


def test_clean_metadata_callback_can_reuse_redacted_negative_cache(monkeypatch):
    calls, callbacks = [], []
    scanning._RESULTS.clear()
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *a: calls.append('kingfisher') or [])
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *a: calls.append('trufflehog') or [])
    for _ in range(2):
        assert scanning.scan_content(b'plain', _redact_values=callbacks.append)['complete']
    assert sorted(calls) == ['kingfisher', 'trufflehog']
    assert callbacks == [frozenset(), frozenset()]
