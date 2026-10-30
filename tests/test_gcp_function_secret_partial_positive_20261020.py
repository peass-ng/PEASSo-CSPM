"""Source-bound native red/green proof; production evaluator remains untouched."""
from copy import deepcopy
import json


import pytest

from peaso.checks import gcp_function_secret_review_20261019 as original
from peaso.collectors import gcp_function_secret_indicators as projection
from tests.gcp_function_partial_positive_native_20261020 import (
    NAME, SCOPE, TOKEN, collect_native, index_for, raw,
)

from tests.gcp_wave2_historical_native_20261020 import collect_historical_native as collect_native


@pytest.fixture(scope='module')
def native_partial():
    with pytest.MonkeyPatch.context() as patch:
        envelope, receipt, _ = collect_native(patch, raw({'SETTING': TOKEN}, {'STAGE': 'release'}))
    assert envelope['status'] == 'collected' and len(envelope['items']) == 1
    row, = envelope['items']
    marker = row[projection.MARKER]
    assert marker['leaks'] and marker['complete'] is False
    assert marker['status'] == 'incomplete'
    assert all(s['engines'][0]['status'] == 'complete' and
               s['engines'][1]['status'] == 'unavailable' for s in marker['surfaces'])
    assert {d['engine'] for leak in marker['leaks'] for d in leak['detectors']} == {'kingfisher'}
    assert receipt['detector_runs'] == [[engine, surface + '.environmentVariables']
        for surface in projection.SURFACES for engine in ('kingfisher', 'trufflehog')]
    assert len(receipt['http_calls']) == 2
    return row, index_for(row, envelope), receipt


@pytest.mark.xfail(strict=True, reason='Original discards a real completed Kingfisher positive when TruffleHog is unavailable')
def test_original_native_positive_required(native_partial):
    row, index, _ = native_partial
    # --runxfail makes this the intentional, actual red reproduction.
    assert original.evaluate(row, index)[0] == 'FAIL'


def candidate():
    from peaso.checks.gcp_function_secret_partial_positive_candidate_20261020 import evaluate
    return evaluate


def test_native_positive_is_lost_original_and_preserved_candidate(native_partial, capsys):
    row, index, receipt = deepcopy(native_partial)
    before = deepcopy((row, index))
    assert original.evaluate(row, index)[0] == 'UNKNOWN'
    status, evidence = candidate()(row, index)
    assert status == 'FAIL' and evidence['complete'] is False
    assert evidence['credential_validation'] == 'not_attempted'
    assert evidence['secret_leaks'] == row[projection.MARKER]['leaks']
    assert evidence['surfaces'] == row[projection.MARKER]['surfaces']
    assert 'Coverage is incomplete' in evidence['observed']
    assert (row, index) == before
    assert TOKEN not in json.dumps([row, index, evidence, receipt]) + str(capsys.readouterr())
    evidence['secret_leaks'].clear()
    evidence['surfaces'].clear()
    assert (row, index) == before


@pytest.mark.parametrize('surface', [*projection.SURFACES, 'both'])
def test_real_partial_positive_on_each_actual_surface(monkeypatch, surface):
    source = raw()
    selected = projection.SURFACES if surface == 'both' else [surface]
    for actual_surface in selected:
        source[actual_surface]['environmentVariables'] = {'SETTING': TOKEN}
    envelope, _, _ = collect_native(monkeypatch, source)
    row, = envelope['items']
    status, evidence = candidate()(row, index_for(row, envelope))
    assert status == 'FAIL' and evidence['complete'] is False
    assert {loc['path'] for leak in evidence['secret_leaks'] for loc in leak['locations']} == {
        actual_surface + '.environmentVariables' for actual_surface in selected}


def test_partial_clean_remains_unknown(monkeypatch):
    envelope, _, _ = collect_native(monkeypatch, raw({'PUBLIC': 'production'}, {'BUILD': 'release'}))
    row, = envelope['items']
    assert row[projection.MARKER]['leaks'] == []
    assert original.evaluate(row, index_for(row, envelope))[0] == 'UNKNOWN'
    assert candidate()(row, index_for(row, envelope))[0] == 'UNKNOWN'


@pytest.mark.parametrize('positive', [False, True])
def test_real_full_native_results_are_identical(monkeypatch, positive):
    envelope, receipt, _ = collect_native(monkeypatch,
        raw({'SETTING': TOKEN if positive else 'production'}, {'BUILD': TOKEN if positive else 'release'}),
        unavailable_second=False)
    row, = envelope['items']
    expected = original.evaluate(row, index_for(row, envelope))
    assert expected[0] == ('FAIL' if positive else 'PASS')
    assert expected[1]['complete'] is True
    assert candidate()(row, index_for(row, envelope)) == expected
    assert receipt['secret_absent_from_retained_output']


@pytest.mark.parametrize('partial', [True, False])
def test_declared_managed_secret_references_are_not_literals(monkeypatch, partial):
    source = raw({'PUBLIC': 'production'})
    source['serviceConfig']['secretEnvironmentVariables'] = [
        {'key': 'CREDENTIAL', 'projectId': 'review', 'secret': 'managed-token', 'version': 'latest'}]
    source['serviceConfig']['secretVolumes'] = [
        {'mountPath': '/secrets', 'projectId': 'review', 'secret': 'managed-volume',
         'versions': [{'version': 'latest', 'path': 'token'}]}]
    envelope, _, payloads = collect_native(monkeypatch, source, unavailable_second=partial)
    row, = envelope['items']
    assert row[projection.MARKER]['leaks'] == []
    assert all(b'managed-token' not in payload and b'managed-volume' not in payload for payload in payloads)
    assert candidate()(row, index_for(row, envelope))[0] == ('UNKNOWN' if partial else 'PASS')


MALFORMED = [
    'missing_marker', 'extra_marker_field', 'schema', 'marker_identity', 'marker_scope',
    'verification', 'status_contradiction', 'complete_contradiction', 'complete_not_bool',
    'surface_missing', 'surface_extra', 'surface_reordered', 'surface_not_object',
    'surface_complete_contradiction', 'surface_extra_field', 'pairs_not_int', 'pairs_bound',
    'bytes_not_int', 'bytes_bound', 'engines_missing', 'engine_duplicate', 'engine_foreign',
    'engine_version', 'engine_status', 'engine_extra_field', 'leaks_not_list',
    'leak_extra_field', 'bad_fingerprint', 'bad_detector', 'missing_detector',
    'missing_location', 'foreign_location', 'foreign_location_scope', 'foreign_location_identity',
    'unexpected_location_metadata', 'bad_line', 'unavailable_engine_hit',
    'detector_completed_only_elsewhere', 'mixed_valid_and_fabricated_detector',
    'mixed_valid_and_foreign_location', 'empty_source_hit', 'all_engines_unavailable',
    'leak_bound', 'location_bound',
]


def corrupt(row, case):
    marker = row[projection.MARKER]
    surface = marker['surfaces'][0]
    engine = surface['engines'][0]
    leak = marker['leaks'][0]
    if case == 'missing_marker': del row[projection.MARKER]
    elif case == 'extra_marker_field': marker['raw'] = 'unexpected'
    elif case == 'schema': marker['schema'] = 'foreign'
    elif case == 'marker_identity': marker['identity'] = NAME + '-foreign'
    elif case == 'marker_scope': marker['scope'] = 'projects/foreign'
    elif case == 'verification': marker['verification'] = 'validated'
    elif case == 'status_contradiction': marker['status'] = 'collected'
    elif case == 'complete_contradiction': marker['complete'] = True
    elif case == 'complete_not_bool': marker['complete'] = 0
    elif case == 'surface_missing': marker['surfaces'].pop()
    elif case == 'surface_extra': marker['surfaces'].append(deepcopy(surface))
    elif case == 'surface_reordered': marker['surfaces'].reverse()
    elif case == 'surface_not_object': marker['surfaces'][1] = None
    elif case == 'surface_complete_contradiction': surface['complete'] = True
    elif case == 'surface_extra_field': surface['raw'] = 'unexpected'
    elif case == 'pairs_not_int': surface['pairs'] = True
    elif case == 'pairs_bound': surface['pairs'] = projection.MAX_PAIRS + 1
    elif case == 'bytes_not_int': surface['bytes'] = True
    elif case == 'bytes_bound': surface['bytes'] = projection.MAX_FUNCTION_BYTES + 1
    elif case == 'engines_missing': surface['engines'] = []
    elif case == 'engine_duplicate': surface['engines'][1] = deepcopy(engine)
    elif case == 'engine_foreign': engine['engine'] = 'other'
    elif case == 'engine_version': engine['version'] = 'unsupported'
    elif case == 'engine_status': engine['status'] = 'timeout'
    elif case == 'engine_extra_field': engine['raw'] = 'unexpected'
    elif case == 'leaks_not_list': marker['leaks'] = {}
    elif case == 'leak_extra_field': leak['raw'] = 'unexpected'
    elif case == 'bad_fingerprint': leak['fingerprint'] = 'invalid'
    elif case == 'bad_detector': leak['detectors'][0]['engine'] = 'other'
    elif case == 'missing_detector': leak['detectors'] = []
    elif case == 'missing_location': leak['locations'] = []
    elif case == 'foreign_location': leak['locations'][0]['path'] = 'foreign.environmentVariables'
    elif case == 'foreign_location_scope': leak['locations'][0]['scope'] = 'projects/foreign'
    elif case == 'foreign_location_identity': leak['locations'][0]['resource_id'] = NAME + '-foreign'
    elif case == 'unexpected_location_metadata': leak['locations'][0]['layer'] = 'foreign-layer'
    elif case == 'bad_line': leak['locations'][0]['line'] = 0
    elif case == 'unavailable_engine_hit': leak['detectors'][0]['engine'] = 'trufflehog'
    elif case == 'detector_completed_only_elsewhere':
        leak['detectors'][0]['engine'] = 'trufflehog'
        marker['surfaces'][1]['engines'][1]['status'] = 'complete'
        marker['surfaces'][1]['complete'] = True
    elif case == 'mixed_valid_and_fabricated_detector':
        leak['detectors'].append({'engine': 'trufflehog', 'rule': 'fabricated'})
    elif case == 'mixed_valid_and_foreign_location':
        leak['locations'].append({'path': 'foreign.environmentVariables'})
    elif case == 'empty_source_hit': surface['pairs'] = 0
    elif case == 'all_engines_unavailable':
        for s in marker['surfaces']:
            s['engines'][0]['status'] = 'unavailable'
    elif case == 'leak_bound': marker['leaks'] = [deepcopy(leak)] * (projection.MAX_LEAKS + 1)
    elif case == 'location_bound':
        leak['locations'] = [{'path': 'serviceConfig.environmentVariables', 'line': i + 1}
                             for i in range(projection.MAX_LOCATIONS + 1)]
    else: raise AssertionError(case)


@pytest.mark.parametrize('case', MALFORMED)
def test_positive_never_overrides_invalid_projection(native_partial, case):
    row = deepcopy(native_partial[0])
    corrupt(row, case)
    assert candidate()(row, index_for(row))[0] == 'UNKNOWN', case


@pytest.mark.parametrize('case', [
    'foreign_provider', 'foreign_scope', 'foreign_name', 'missing_inventory',
    'denied_inventory', 'partial_inventory', 'missing_item', 'duplicate_item',
    'duplicate_envelope', 'foreign_envelope_scope', 'different_native_item', 'malformed_items',
])
def test_positive_never_overrides_scoped_native_inventory(native_partial, case):
    row = deepcopy(native_partial[0])
    evidence = index_for(row)
    envelope = evidence['collections']['function'][0]
    if case == 'foreign_provider': evidence['context']['provider'] = 'aws'
    elif case == 'foreign_scope': evidence['context']['scope'] = 'projects/foreign'
    elif case == 'foreign_name': row['name'] = NAME.replace('/review/', '/foreign/')
    elif case == 'missing_inventory': evidence['collections'] = {}
    elif case == 'denied_inventory': envelope['status'] = 'denied'
    elif case == 'partial_inventory': envelope['status'] = 'partial'
    elif case == 'missing_item': envelope['items'] = []
    elif case == 'duplicate_item': envelope['items'].append(deepcopy(row))
    elif case == 'duplicate_envelope': evidence['collections']['function'].append(deepcopy(envelope))
    elif case == 'foreign_envelope_scope': envelope['scope'] = 'projects/foreign'
    elif case == 'different_native_item': envelope['items'] = [{**row, 'state': 'OTHER'}]
    elif case == 'malformed_items': envelope['items'] = None
    assert candidate()(row, evidence)[0] == 'UNKNOWN', case


@pytest.mark.parametrize('case', [
    'missing_config', 'malformed_config', 'malformed_map', 'already_sanitized',
    'incomplete_coverage', 'foreign_identity', 'unreachable', 'denied', 'disabled', 'oversized',
])
def test_native_invalid_or_incomplete_source_cannot_supply_a_positive(monkeypatch, case):
    source = raw({'SETTING': TOKEN})
    options = {}
    if case == 'missing_config': del source['buildConfig']
    elif case == 'malformed_config': source['buildConfig'] = []
    elif case == 'malformed_map': source['buildConfig']['environmentVariables'] = []
    elif case == 'already_sanitized': source['serviceConfig'] = {'environmentVariableNames': ['SETTING']}
    elif case == 'incomplete_coverage': source['serviceConfig']['_coverage'] = {'environmentVariables': {'status': 'unknown'}}
    elif case == 'foreign_identity': source['name'] = NAME.replace('/review/', '/foreign/')
    elif case == 'unreachable': options['response_changes'] = {'unreachable': ['us-central1']}
    elif case == 'denied': options['http_status'] = 403
    elif case == 'disabled': options['enabled'] = False
    elif case == 'oversized': source['buildConfig']['environmentVariables'] = {'BIG': 'x' * (projection.MAX_VALUE_BYTES + 1)}
    envelope, receipt, _ = collect_native(monkeypatch, source, **options)
    assert receipt['detector_runs'] == []
    if not envelope['items']:
        assert envelope['status'] != 'collected'
        return
    row, = envelope['items']
    assert candidate()(row, index_for(row, envelope))[0] == 'UNKNOWN'


def test_merged_surface_claims_are_conservative(native_partial):
    row = deepcopy(native_partial[0])
    marker = row[projection.MARKER]
    # There is no engine/location matrix in the v1 union schema. A detector
    # completed elsewhere cannot support a location where it was unavailable.
    marker['surfaces'][1]['engines'][0]['status'] = 'unavailable'
    marker['surfaces'][1]['engines'][1]['status'] = 'complete'
    marker['leaks'][0]['detectors'].append({'engine': 'trufflehog', 'rule': 'fixture'})
    marker['leaks'][0]['locations'].append({'path': 'buildConfig.environmentVariables', 'line': 1})
    assert candidate()(row, index_for(row))[0] == 'UNKNOWN'


def test_candidate_import_leaves_original_registry_binding(native_partial):
    from peaso.checks import CHECKS, evaluate_check
    from peaso.checks import gcp_function_secret_partial_page_20261020 as current
    before = tuple(CHECKS)
    candidate()
    assert tuple(CHECKS) == before
    entries = [check for check in CHECKS if check.id == original.CHECK_ID]
    assert len(entries) == 1
    import inspect
    assert inspect.unwrap(entries[0].evaluate) is current.evaluate
    row, index, _ = native_partial
    assert original.evaluate(row, index)[0] == 'UNKNOWN'
    assert evaluate_check(original.CHECK_ID, row, index)[0] == 'FAIL'


def test_duplicate_fingerprint_rows_cannot_launder_unavailable_detector(native_partial):
    row = deepcopy(native_partial[0])
    fabricated = deepcopy(row[projection.MARKER]['leaks'][0])
    fabricated['detectors'][0]['engine'] = 'trufflehog'
    row[projection.MARKER]['leaks'].append(fabricated)
    assert candidate()(row, index_for(row))[0] == 'UNKNOWN'


def test_existing_value_grouping_retains_candidate_coverage(native_partial):
    from peaso.secret_findings import deduplicate_secret_findings
    row, index, _ = native_partial
    status, evidence = candidate()(row, index)
    grouped = deduplicate_secret_findings([{
        'provider': 'gcp', 'check_id': original.CHECK_ID, 'scope': SCOPE,
        'resource_id': NAME, 'native_resource_id': NAME, 'resource_type': 'function',
        'finding_type': 'secrets', 'frameworks': [], 'status': status, 'evidence': evidence}])
    assert len(grouped) == len(evidence['secret_leaks'])
    assert all(finding['status'] == 'FAIL' and finding['evidence']['complete'] is False
               and finding['evidence']['coverage'] == 'incomplete' for finding in grouped)
    assert TOKEN not in json.dumps(grouped)
