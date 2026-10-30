"""Normal native/registry/engine/dedup/persistence closure of Functions pairing."""
from copy import deepcopy
import gzip
import hashlib
import inspect
import json
from pathlib import Path

import pytest

from peaso.checks import CHECKS, evaluate_check
from peaso.checks import gcp_function_secret_page_admission_20261020 as admission
from peaso.checks import gcp_function_secret_paired_review_20261020 as consumer
from peaso.checks import gcp_function_secret_review_20261019 as original
from peaso.collectors import gcp_function_secret_pairs_20261020 as producer
from peaso.engine import evaluate_snapshot
from peaso.gcp_function_secret_page_persistence_20261020 import retain_function_secret_pairs, FIELD
from peaso.gcp_function_secret_page_source_20261020 import reviewed_inputs
from peaso.secret_findings import deduplicate_secret_findings
from tests.gcp_function_secret_paired_native_20261020 import collect, OTHER
from tests.gcp_function_partial_positive_native_20261020 import TOKEN, index_for
from tests.test_gcp_function_secret_partial_positive_20261020 import MALFORMED, corrupt

ROOT = Path(__file__).resolve().parents[1]


def check_adopted():
    check, = [row for row in CHECKS if row.id == original.CHECK_ID]
    from peaso.checks import gcp_function_secret_partial_page_20261020 as current
    assert inspect.unwrap(check.evaluate) is current.evaluate
    return check


def pre_finding(row, envelope):
    status, evidence = evaluate_check(original.CHECK_ID, row, index_for(row, envelope))
    return {'provider': 'gcp', 'check_id': original.CHECK_ID, 'scope': envelope['scope'],
        'resource_id': row['name'], 'native_resource_id': row['name'],
        'resource_type': 'function', 'status': status, 'frameworks': [], 'evidence': evidence}


@pytest.fixture(scope='module')
def native_partial():
    with pytest.MonkeyPatch.context() as patch:
        snapshot, receipt = collect(patch, 'partial_positive')
    return snapshot, receipt


@pytest.fixture(scope='module')
def native_asymmetric():
    with pytest.MonkeyPatch.context() as patch:
        snapshot, receipt = collect(patch, 'asymmetric')
    return snapshot, receipt


@pytest.mark.parametrize('scenario,expected', [
    ('full_positive', 'FAIL'), ('full_clean', 'PASS'), ('partial_positive', 'FAIL'),
    ('partial_clean', 'UNKNOWN'), ('asymmetric', 'FAIL'), ('denied', 'DENIED'),
    ('unreachable', 'UNKNOWN'), ('malformed', 'UNKNOWN'), ('missing', 'UNKNOWN'),
    ('source_incomplete', 'UNKNOWN'), ('spoof', 'PASS'), ('managed_reference', 'PASS'),
])
def test_normal_native_engine_and_saved_json_roundtrip(monkeypatch, tmp_path, scenario, expected):
    check_adopted()
    snapshot, receipt = collect(monkeypatch, scenario)
    snapshot_file = tmp_path / 'snapshot.json'
    snapshot_file.write_text(json.dumps(snapshot))
    saved = json.loads(snapshot_file.read_text())
    before = deepcopy(saved)
    result = evaluate_snapshot(saved, checks=[original.CHECK_ID])
    assert saved == before
    findings = result['findings']
    assert len(findings) == (2 if scenario == 'unreachable' else 1), findings
    assert all(finding['status'] == expected for finding in findings)
    finding = findings[0]
    assert finding['status'] == expected, finding
    # 75087001 added one Functions locations listing before the list and getIamPolicy reads.
    locations = ['GET', 'https://cloudfunctions.googleapis.com/v2/projects/review/locations']
    assert receipt['calls'].count(locations) == 1
    assert len(receipt['calls']) == (2 if scenario == 'denied' else 3)
    if expected == 'FAIL':
        assert finding['linked_check_ids'] == [original.CHECK_ID]
        assert len(finding['evidence']['secret_leaks']) == 1
        assert finding['evidence'][FIELD]
        fingerprint = finding['secret_fingerprint']
        assert all(pair['secret_leaks'][0]['fingerprint'] == fingerprint
                   for pair in finding['evidence'][FIELD])
        if scenario in ('partial_positive', 'asymmetric'):
            assert finding['evidence']['complete'] is False
            assert finding['evidence']['coverage'] == 'incomplete'
    if scenario in ('denied', 'unreachable', 'malformed', 'missing', 'source_incomplete'):
        assert receipt['detector_runs'] == []
    for argv in receipt['commands']:
        if 'stdin' in argv:
            assert {'--no-verification', '--no-update', '--no-verification-cache', '--force-skip-archives'} <= set(argv)
    output_file = tmp_path / 'report.json'
    output_file.write_text(json.dumps(result))
    assert json.loads(output_file.read_text())['findings'] == findings
    assert TOKEN not in snapshot_file.read_text() + output_file.read_text()


def test_default_off_policy_and_safe_native_cache(monkeypatch):
    snapshot, receipt = collect(monkeypatch, enabled=False)
    assert receipt['detector_runs'] == []
    row, = receipt['native_envelope']['items']
    assert producer.MARKER not in row
    assert row['serviceConfig']['environmentVariableNames'] == ['SETTING']
    assert evaluate_snapshot(snapshot, checks=[original.CHECK_ID])['findings'][0]['status'] == 'UNKNOWN'


@pytest.mark.parametrize('masked', [False, True])
def test_native_named_get_keeps_the_existing_binding_and_fieldmask_policy(monkeypatch, masked):
    from types import SimpleNamespace
    from peaso.collectors import gcp
    from tests.gcp_function_partial_positive_native_20261020 import NAME, SCOPE, raw
    source = raw({'SETTING': TOKEN}, {'BUILD': TOKEN})
    calls = []
    class Response:
        status_code = 200
        def json(self): return deepcopy(source)
    def request(method, url, **kwargs):
        calls.append([method, url])
        assert method == 'GET' and url == 'https://cloudfunctions.googleapis.com/v2/' + NAME
        return Response()
    transport = gcp.Transport(SimpleNamespace(headers=lambda: {}, close=lambda: None),
        {'content_secret_scans': True, '_content_secret_scan_kinds': ['function'], 'retries': 0})
    monkeypatch.setattr(transport, '_session', lambda: SimpleNamespace(request=request, close=lambda: None))
    row, request_id = transport.request('GET', 'https://cloudfunctions.googleapis.com/v2/' + NAME,
        scope=SCOPE, params={'fields': 'name'} if masked else None)
    repeated, repeated_id = transport.request('GET', 'https://cloudfunctions.googleapis.com/v2/' + NAME,
        scope=SCOPE, params={'fields': 'name'} if masked else None)
    assert row == repeated and request_id == repeated_id and len(calls) == 1
    assert evaluate_check(original.CHECK_ID, row, index_for(row))[0] == ('UNKNOWN' if masked else 'FAIL')
    assert TOKEN not in json.dumps([row, transport.evidence, [entry.get('data') for entry in transport.cache.values()]])


def test_native_asymmetric_attribution_survives_engine_and_persistence(native_asymmetric):
    snapshot, receipt = native_asymmetric
    row, = receipt['native_envelope']['items']
    marker = row[producer.MARKER]
    assert marker['schema'] == producer.SCHEMA
    assert len(receipt['detector_runs']) == 4
    result = evaluate_snapshot(snapshot, checks=[original.CHECK_ID])
    finding, = result['findings']
    assert finding['status'] == 'FAIL' and finding['evidence']['complete'] is False
    pairs = finding['evidence'][FIELD]
    assert len(pairs) == 2
    supported = {'serviceConfig': 'kingfisher', 'buildConfig': 'trufflehog'}
    for pair in pairs:
        completed = {engine['engine'] for engine in pair['engines'] if engine['status'] == 'complete'}
        assert completed == {supported[pair['surface']]}
        assert {detector['engine'] for leak in pair['secret_leaks'] for detector in leak['detectors']} == completed
        assert {location['path'] for leak in pair['secret_leaks'] for location in leak['locations']} == {
            pair['surface'] + '.environmentVariables'}
    assert json.loads(json.dumps(finding)) == finding


@pytest.mark.parametrize('case', MALFORMED)
def test_every_previous_malformed_counterexample_still_rejected(native_partial, case):
    row = deepcopy(native_partial[1]['native_envelope']['items'][0])
    corrupt(row, case)
    assert evaluate_check(original.CHECK_ID, row, index_for(row))[0] == 'UNKNOWN', case


@pytest.mark.parametrize('case', [
    'foreign_provider', 'foreign_scope', 'foreign_name', 'missing_inventory',
    'denied_inventory', 'partial_inventory', 'missing_item', 'duplicate_item',
    'duplicate_envelope', 'foreign_envelope_scope', 'different_native_item', 'malformed_items',
])
def test_scoped_native_inventory_rejection_preserved(native_partial, case):
    row = deepcopy(native_partial[1]['native_envelope']['items'][0])
    index = index_for(row)
    envelope = index['collections']['function'][0]
    if case == 'foreign_provider': index['context']['provider'] = 'aws'
    elif case == 'foreign_scope': index['context']['scope'] = 'projects/foreign'
    elif case == 'foreign_name': row['name'] = row['name'].replace('/review/', '/foreign/')
    elif case == 'missing_inventory': index['collections'] = {}
    elif case == 'denied_inventory': envelope['status'] = 'denied'
    elif case == 'partial_inventory': envelope['status'] = 'partial'
    elif case == 'missing_item': envelope['items'] = []
    elif case == 'duplicate_item': envelope['items'].append(deepcopy(row))
    elif case == 'duplicate_envelope': index['collections']['function'].append(deepcopy(envelope))
    elif case == 'foreign_envelope_scope': envelope['scope'] = 'projects/foreign'
    elif case == 'different_native_item': envelope['items'] = [{**row, 'state': 'OTHER'}]
    elif case == 'malformed_items': envelope['items'] = None
    assert evaluate_check(original.CHECK_ID, row, index)[0] == 'UNKNOWN', case


@pytest.mark.parametrize('surface,engine', [('serviceConfig', 'trufflehog'), ('buildConfig', 'kingfisher')])
def test_crosssurface_unavailable_engine_hit_rejected(native_asymmetric, surface, engine):
    row = deepcopy(native_asymmetric[1]['native_envelope']['items'][0])
    marker = row[producer.MARKER]
    local = next(item for item in marker['surfaces'] if item['surface'] == surface)
    local['leaks'][0]['detectors'][0]['engine'] = engine
    # Even a consistent global union cannot authorize this detector on a
    # different surface. Keep union canonical to isolate local attribution.
    from peaso.secret_scanning import merge_leaks
    marker['leaks'] = merge_leaks([leak for item in marker['surfaces'] for leak in item['leaks']])
    assert evaluate_check(original.CHECK_ID, row, index_for(row))[0] == 'UNKNOWN'


@pytest.mark.parametrize('case', [
    'missing_pairs', 'pairs_not_list', 'fabricated_runtime_hit', 'fabricated_build_hit',
    'foreign_surface_location', 'missing_global_hit', 'missing_local_hit',
    'fabricated_global_hit', 'foreign_local_metadata', 'mismatched_fingerprint',
    'zero_pairs_with_hit', 'too_many_local_hits', 'too_many_local_locations',
])
def test_archived_paired_counterexamples_apply_to_live_consumer(native_asymmetric, case):
    row = deepcopy(native_asymmetric[1]['native_envelope']['items'][0])
    assert evaluate_check(original.CHECK_ID, row, index_for(row))[0] == 'FAIL'
    marker = row[producer.MARKER]
    runtime, build = marker['surfaces']
    if case == 'missing_pairs': del runtime['leaks']
    elif case == 'pairs_not_list': runtime['leaks'] = {}
    elif case == 'fabricated_runtime_hit': runtime['leaks'][0]['detectors'][0]['engine'] = 'trufflehog'
    elif case == 'fabricated_build_hit': build['leaks'][0]['detectors'][0]['engine'] = 'kingfisher'
    elif case == 'foreign_surface_location': runtime['leaks'][0]['locations'][0]['path'] = 'buildConfig.environmentVariables'
    elif case == 'missing_global_hit': marker['leaks'] = []
    elif case == 'missing_local_hit': runtime['leaks'] = []
    elif case == 'fabricated_global_hit': marker['leaks'][0]['detectors'].append({'engine': 'trufflehog', 'rule': 'fabricated'})
    elif case == 'foreign_local_metadata': runtime['leaks'][0]['locations'][0]['scope'] = 'projects/foreign'
    elif case == 'mismatched_fingerprint': runtime['leaks'][0]['fingerprint'] = 'a' * 64
    elif case == 'zero_pairs_with_hit': runtime['pairs'] = 0
    elif case == 'too_many_local_hits': runtime['leaks'] *= producer.MAX_LEAKS + 1
    elif case == 'too_many_local_locations':
        runtime['leaks'][0]['locations'] = [
            {'path': 'serviceConfig.environmentVariables', 'line': i + 1}
            for i in range(producer.MAX_LOCATIONS + 1)]
    assert evaluate_check(original.CHECK_ID, row, index_for(row))[0] == 'UNKNOWN', case


def test_only_matching_fingerprint_pairs_survive_one_finding_per_value(monkeypatch):
    snapshot, receipt = collect(monkeypatch, 'partial_positive', functions=2, two_secrets=True)
    result = evaluate_snapshot(snapshot, checks=[original.CHECK_ID])
    assert len(result['findings']) == 2
    assert len(result['resources']) == 2
    for finding in result['findings']:
        fingerprint = finding['secret_fingerprint']
        assert len(finding['evidence']['secret_leaks']) == 1
        assert finding['linked_check_ids'] == [original.CHECK_ID]
        pairs = finding['evidence'][FIELD]
        assert {pair['resource_id'] for pair in pairs} == {row['name'] for row in receipt['native_envelope']['items']}
        assert {pair['scope'] for pair in pairs} == {'projects/review'}
        assert all(leak['fingerprint'] == fingerprint for pair in pairs for leak in pair['secret_leaks'])
    assert TOKEN not in json.dumps(result) and OTHER not in json.dumps(result)


def test_postdedup_helper_rejects_transplanted_and_tampered_pair_evidence(native_asymmetric):
    _, receipt = native_asymmetric
    row, = receipt['native_envelope']['items']
    source = pre_finding(row, receipt['native_envelope'])
    final = deduplicate_secret_findings([source])
    before = deepcopy((source, final))
    good = retain_function_secret_pairs([source], final)
    assert good[0]['evidence'][FIELD]
    assert {key: value for key, value in good[0].items() if key != 'evidence'} == {
        key: value for key, value in final[0].items() if key != 'evidence'}
    assert (source, final) == before
    for case in ('foreign_scope', 'foreign_asset', 'unavailable_detector', 'other_fingerprint', 'private_field'):
        bad = deepcopy(source)
        if case == 'foreign_scope': bad['scope'] = 'projects/foreign'
        elif case == 'foreign_asset': bad['native_resource_id'] += '-foreign'
        elif case == 'unavailable_detector':
            bad['evidence']['surfaces'][0]['leaks'][0]['detectors'][0]['engine'] = 'trufflehog'
        elif case == 'other_fingerprint': bad['evidence']['surfaces'][0]['leaks'][0]['fingerprint'] = 'a' * 64
        elif case == 'private_field': bad['evidence']['surfaces'][0]['leaks'][0]['raw'] = 'PRIVATE_MUST_NOT_SURVIVE'
        output = retain_function_secret_pairs([bad], final)
        assert FIELD not in output[0]['evidence'], case
        assert 'PRIVATE_MUST_NOT_SURVIVE' not in json.dumps(output)


def test_same_secret_across_native_project_scopes_keeps_all_occurrences(monkeypatch):
    from peaso.snapshot import make_snapshot
    scopes = ['projects/review', 'projects/secondary']
    native = [collect(monkeypatch, 'partial_positive', scope=scope)[0] for scope in scopes]
    combined = make_snapshot('gcp', scopes,
        [deepcopy(collection) for snapshot in native for collection in snapshot['collections']])
    result = evaluate_snapshot(json.loads(json.dumps(combined)), checks=[original.CHECK_ID])
    finding, = result['findings']
    assert finding['status'] == 'FAIL' and finding['evidence']['complete'] is False
    assert len(result['resources']) == 2
    assert finding['linked_check_ids'] == [original.CHECK_ID]
    pairs = finding['evidence'][FIELD]
    assert {pair['scope'] for pair in pairs} == set(scopes)
    assert {pair['resource_id'] for pair in pairs} == {
        scope + '/locations/us-central1/functions/worker' for scope in scopes}
    assert {location['scope'] for location in finding['evidence']['secret_leaks'][0]['locations']} == set(scopes)
    assert len(pairs) == 4


@pytest.mark.parametrize('provider', ['aws', 'azure', 'k8s'])
def test_other_provider_dedup_is_unchanged(provider):
    source = {'provider': provider, 'check_id': 'unrelated', 'scope': 'native-scope',
        'resource_id': 'asset', 'native_resource_id': 'native-asset', 'status': 'FAIL',
        'frameworks': [], 'evidence': {'secret_leaks': [{
            'fingerprint': 'b' * 64, 'detectors': [{'engine': 'kingfisher', 'rule': 'fixture'}],
            'locations': [{'path': 'native.literal', 'line': 1}]}]}}
    original_final = deduplicate_secret_findings([source, deepcopy(source)])
    assert len(original_final) == 1
    assert retain_function_secret_pairs([source], original_final) == original_final


@pytest.mark.parametrize('scenario', ['full_positive', 'full_clean', 'partial_positive', 'asymmetric'])
def test_real_old_new_native_compatibility_is_nonvacuous(monkeypatch, scenario):
    snapshot, receipt = collect(monkeypatch, scenario, legacy_projection=True)
    legacy, = receipt['legacy_rows']
    current, = receipt['native_envelope']['items']
    before_status, before_evidence = original.evaluate(legacy, index_for(legacy))
    current_status, current_evidence = evaluate_check(original.CHECK_ID, current, index_for(current))
    if scenario == 'full_clean':
        assert not legacy[producer.MARKER]['leaks'] and not current[producer.MARKER]['leaks']
    else:
        assert legacy[producer.MARKER]['leaks'] and current[producer.MARKER]['leaks']
    if scenario.startswith('full_'):
        assert before_status == current_status == ('PASS' if scenario == 'full_clean' else 'FAIL')
        assert before_evidence['secret_leaks'] == current_evidence['secret_leaks']
        assert before_evidence['observed'] == current_evidence['observed']
    else:
        assert before_status == 'UNKNOWN' and current_status == 'FAIL'
        assert current_evidence['complete'] is False
    assert evaluate_snapshot(snapshot, checks=[original.CHECK_ID])['findings'][0]['status'] == current_status


def test_source_substitution_rejected_then_restored(native_partial, monkeypatch):
    row = native_partial[1]['native_envelope']['items'][0]
    assert evaluate_check(original.CHECK_ID, row, index_for(row))[0] == 'FAIL'
    with monkeypatch.context() as patch:
        patch.setattr(producer, 'project_response', lambda *args, **kwargs: {})
        assert evaluate_check(original.CHECK_ID, row, index_for(row))[0] == 'UNKNOWN'
        with pytest.raises(RuntimeError): admission.install()
    assert evaluate_check(original.CHECK_ID, row, index_for(row))[0] == 'FAIL'
    path = Path(consumer.__file__)
    read_bytes = Path.read_bytes
    with monkeypatch.context() as patch:
        patch.setattr(Path, 'read_bytes', lambda self: read_bytes(self) + b'\n# substituted source\n'
                      if self.resolve() == path.resolve() else read_bytes(self))
        assert evaluate_check(original.CHECK_ID, row, index_for(row))[0] == 'UNKNOWN'
        with pytest.raises(RuntimeError): admission.install()
    assert evaluate_check(original.CHECK_ID, row, index_for(row))[0] == 'FAIL'
    admission.install()


def test_exact_predecessors_and_native_case_replacement_are_preserved():
    reviewed_inputs()  # Validate the installed additive source epoch first.
    receipt = json.loads((ROOT / 'peaso/checks/gcp_function_secret_paired_admission_20261020.json').read_bytes())
    archive = json.loads(gzip.decompress((ROOT / receipt['predecessors']['path']).read_bytes()))
    for name, row in archive['files'].items():
        old = bytes.fromhex(row['hex'])
        assert hashlib.sha256(old).hexdigest() == row['sha256']
        if name.startswith('peaso/') and name not in ('peaso/collectors/gcp.py', 'peaso/checks/__init__.py'):
            from peaso.rawv2_private_source_successor_20261021 import source_bytes
            current = (ROOT / name).read_bytes()
            # The finite source attestor revalidates current private bytes and
            # returns only their pinned predecessor; old bytes/hashes stay exact.
            assert source_bytes(name, current, row['sha256'], ROOT) == old, name
        else:
            from tests.gcp_wave2_historical_native_20261020 import historical_bytes
            assert historical_bytes(name, row['sha256']) == old
    impossible = archive['legacy_cases'][original.CHECK_ID]['fail']
    assert original.evaluate(impossible, index_for(impossible))[0] == 'FAIL'
    assert consumer._evaluate(impossible, index_for(impossible))[0] == 'UNKNOWN'
    _, cases = admission.reviewed_inputs()
    for branch in ('fail', 'partial', 'asymmetric'):
        row = cases[original.CHECK_ID][branch]
        assert any(surface['pairs'] > 0 and surface['leaks'] for surface in row[producer.MARKER]['surfaces'])
    current = check_adopted()
    assert admission._signature(current) == archive['legacy_registration']
