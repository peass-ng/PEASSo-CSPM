"""Normal engine -> native GET/OCI -> saved JSON -> pure registered consumer."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from peaso import engine, secret_scanning as scanning
from peaso.collectors import gcp
from peaso.collectors import gcp_cloudrun_job_image_runtime_20261020 as runtime
from peaso.checks import gcp_cloudrun_job_image_secret_review_20261020 as consumer
from peaso.snapshot import seal
from tests.test_gcp_cloudrun_v2_job_declared_images_20261020 import (
    fixtures, MetadataSession, SCOPE, JOB, UID,
)
from tests.test_gcp_image_secret_review_20261019 import (
    Session, TOKEN, real, clean, isolate,  # noqa: F401
)


def request(selectors=None):
    selectors = fixtures()[0] if selectors is None else selectors
    return {'connector': {'provider': 'gcp', 'scopes': [SCOPE],
        'auth': {'method': 'access-token', 'token': 'fixture-access-token'},
        'options': {'content_secret_scans': True, runtime.OPTION: selectors}},
        'checks': [runtime.CHECK_ID]}


def setup_wire(monkeypatch, value='production', *, second=None, alter=None, fault=None,
               byte_options=None, cancelled=False, max_calls=None, close_failure=False):
    selectors, bodies, blobs = fixtures(value, second=second)
    metadata = MetadataSession(bodies, alter=alter, fault=fault)
    binary = Session(blobs, **(byte_options or {}))
    sessions, events = iter([metadata, binary]), []
    transport_type = gcp.Transport
    wire = transport_type(SimpleNamespace(close=lambda: None), {'timeout': 10})
    wire.closed = False
    def close():
        transport_type.close(wire)
        wire.closed = True
    wire.close = close
    class Credentials:
        method = 'access-token'
        def __init__(self, *args, **kwargs):
            events.append('credentials')
            assert events[0] == 'grant'
        def headers(self):
            return {'Authorization': 'Bearer fixture-access-token'}
        def close(self):
            self.closed = True
    def native_transport(credentials, options):
        events.append('transport')
        bounded = {**options, 'timeout': 10, '_cancel_check': lambda: cancelled}
        if max_calls is not None:
            bounded['max_calls'] = max_calls
        transport_type.__init__(wire, credentials, bounded)
        return wire
    original_authorize = runtime.authorize_collector
    def authorize(options, scopes):
        result = original_authorize(options, scopes)
        if result:
            events.append('grant')
        return result
    monkeypatch.setattr(runtime, 'authorize_collector', authorize)
    monkeypatch.setattr(gcp, 'Credentials', Credentials)
    monkeypatch.setattr(gcp, 'Transport', native_transport)
    monkeypatch.setattr(runtime.source, '_session', lambda: next(sessions))
    if close_failure:
        def failed_close():
            binary.closed = True
            raise RuntimeError('cleanup failed')
        binary.close = failed_close
    return selectors, metadata, binary, wire, events


def roundtrip(monkeypatch, tmp_path, value='production', **kwargs):
    selected, metadata, binary, wire, events = setup_wire(monkeypatch, value, **kwargs)
    body = request(selected)
    assert engine.plan_collection(body) == [runtime.KIND]
    snapshot = engine.collect_snapshot(body)
    path = tmp_path / 'native-job.json'
    path.write_text(json.dumps(snapshot))
    saved = json.loads(path.read_text())
    # Once native capture is saved, evaluation must neither authenticate nor read HTTP.
    def offline(*args, **kwargs):
        raise AssertionError('pure consumer attempted live operation')
    monkeypatch.setattr(runtime, 'collect_native', offline)
    monkeypatch.setattr(gcp, 'Credentials', offline)
    report = engine.evaluate_snapshot(saved, checks=[runtime.CHECK_ID])
    return saved, report, metadata, binary, wire, events


@pytest.mark.parametrize('value,status', [('production', 'PASS'), (TOKEN, 'FAIL')])
def test_normal_native_saved_json_public_roundtrip(real, monkeypatch, tmp_path, value, status, record_property):
    snapshot, report, metadata, binary, wire, events = roundtrip(monkeypatch, tmp_path, value)
    finding, = report['findings']
    assert finding['status'] == status, finding
    assert events == ['grant', 'credentials', 'transport']
    assert len(metadata.calls) == 8 and len(binary.calls) == 4 and wire.calls == 12
    assert metadata.closed and metadata.responses_closed == 8 and binary.closed and wire.closed
    assert TOKEN not in json.dumps([snapshot, report]) and 'fixture-access-token' not in json.dumps([snapshot, report])
    if status == 'FAIL':
        leak, = finding['evidence']['secret_leaks']
        assert {d['engine'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
        assert {loc['path'] for loc in leak['locations']} == {'member-1', 'image-config.json'}
        assert all(loc['layer'].startswith('sha256:') and loc['scope'] == SCOPE for loc in leak['locations'])
        assert finding['linked_check_ids'] == [runtime.CHECK_ID]
    item, = snapshot['collections'][0]['items']
    proof = item[runtime.MARKER]
    assert proof['observed_runtime_digest'] is None and proof['deployed_bytes_proven'] is False
    assert proof['row']['declaration']['selected_artifact_image_hint']['source']['uid'] == UID
    record_property('native_runtime_witness', json.dumps({'snapshot': snapshot, 'finding': finding}, sort_keys=True))


def test_multicontainer_same_secret_one_public_finding(real, monkeypatch, tmp_path):
    snapshot, report, metadata, binary, _, _ = roundtrip(monkeypatch, tmp_path, TOKEN, second=TOKEN)
    finding, = report['findings']
    assert finding['status'] == 'FAIL'
    assert len(snapshot['collections'][0]['items']) == 2
    assert len(metadata.calls) == 16 and len(binary.calls) == 8
    leaks, = finding['evidence']['secret_leaks']
    assert {loc['resource_id'].rsplit('=', 1)[-1] for loc in leaks['locations']} == {'worker', 'sidecar'}


def test_partial_detector_positive_survives_public_consumer(real, monkeypatch, tmp_path):
    def unavailable(*args, **kwargs):
        raise RuntimeError('offline detector unavailable')
    monkeypatch.setattr(scanning, '_scan_trufflehog', unavailable)
    snapshot, report, _, _, _, _ = roundtrip(monkeypatch, tmp_path, TOKEN)
    finding, = report['findings']
    assert finding['status'] == 'FAIL' and finding['evidence']['complete'] is False
    leak, = finding['evidence']['secret_leaks']
    assert {d['engine'] for d in leak['detectors']} == {'kingfisher'}
    assert snapshot['collections'][0]['items'][0][runtime.MARKER]['row']['complete'] is False


@pytest.mark.parametrize('state,status', [('omitted', 'PASS'), (None, 'UNKNOWN'),
    (True, 'UNKNOWN'), ('false', 'UNKNOWN'), (0, 'UNKNOWN')])
def test_native_protojson_false_default_keeps_raw_capture(real, monkeypatch, tmp_path, state, status):
    def alter(url, body, count):
        if '/jobs/' in url:
            if state == 'omitted':
                body.pop('reconciling')
            else:
                body['reconciling'] = state
    snapshot, report, metadata, binary, _, _ = roundtrip(monkeypatch, tmp_path, alter=alter)
    assert {finding['status'] for finding in report['findings']} == {status}
    if state == 'omitted':
        captures = snapshot['collections'][0]['items'][0][runtime.MARKER]['metadata_captures']
        assert all('reconciling' not in captures[i]['body'] for i in (0, 4))
        assert len(metadata.calls) == 8 and len(binary.calls) == 4


def test_incomplete_first_container_does_not_hide_later_positive(real, monkeypatch, tmp_path):
    failed_once = set()
    def fault(url, count):
        if '/dockerImages/' in url and not failed_once:
            failed_once.add(url)
            return 'denied'
    snapshot, report, _, binary, _, _ = roundtrip(monkeypatch, tmp_path, second=TOKEN, fault=fault)
    assert any(finding['status'] == 'FAIL' for finding in report['findings'])
    rows = {item[runtime.MARKER]['row']['selection']['container_name']: item[runtime.MARKER]['row']
            for item in snapshot['collections'][0]['items']}
    assert rows['worker']['status'] == 'UNKNOWN'
    assert rows['sidecar']['status'] == 'FAIL'
    assert len(binary.calls) == 4


@pytest.mark.parametrize('case', ['metadata_denied', 'image_denied', 'partial_bytes', 'cancelled', 'call_budget', 'changed'])
def test_native_denied_partial_cancellation_unknown_and_cleanup(clean, monkeypatch, tmp_path, case):
    def alter(url, body, count):
        if count == 2 and '/jobs/' in url:
            body['etag'] = 'changed'
    opts = {'metadata_denied': {'fault': lambda *_: 'denied'},
        'image_denied': {'byte_options': {'status': 403}},
        'partial_bytes': {'byte_options': {'truncated': True}},
        'cancelled': {'cancelled': True}, 'call_budget': {'max_calls': 2},
        'changed': {'alter': alter}}[case]
    snapshot, report, metadata, binary, wire, _ = roundtrip(monkeypatch, tmp_path, **opts)
    assert {f['status'] for f in report['findings']} == {'UNKNOWN'}
    assert metadata.closed and binary.closed and wire.closed
    assert metadata.responses_closed == len(metadata.calls)


@pytest.mark.parametrize('value,status', [('production', 'UNKNOWN'), (TOKEN, 'FAIL')])
def test_cleanup_failure_prevents_clean_pass(real, monkeypatch, tmp_path, value, status):
    snapshot, report, _, _, _, _ = roundtrip(monkeypatch, tmp_path, value, close_failure=True)
    finding, = report['findings']
    assert finding['status'] == status
    if status == 'FAIL':
        assert finding['evidence']['complete'] is False


@pytest.mark.parametrize('mode', ['default', 'category', 'framework', 'disabled', 'forged_grant'])
def test_default_and_unnamed_selections_never_read_job_content(clean, monkeypatch, mode):
    body = request()
    if mode != 'disabled':
        body.pop('checks')
    if mode == 'category':
        body['categories'] = ['hardening']
    if mode == 'framework':
        body['frameworks'] = ['hacktricks']
    if mode == 'disabled':
        body['connector']['options']['content_secret_scans'] = False
    if mode == 'forged_grant':
        body['connector']['options'][runtime.GRANT] = {'seal': True}
    _, selected = engine._selection('gcp', body.get('categories'), body.get('checks'), body.get('frameworks'))
    assert mode == 'disabled' or runtime.CHECK_ID not in {c.id for c in selected}
    # Narrow to this inventory to prove pre-auth gating without unrelated metadata auth.
    body['connector']['options']['inventories'] = [runtime.KIND]
    def forbidden(*args, **kwargs):
        raise AssertionError('unselected Job requested credentials or HTTP')
    monkeypatch.setattr(gcp, 'Credentials', forbidden)
    monkeypatch.setattr(runtime.source, '_session', forbidden)
    snapshot = engine.collect_snapshot(body)
    assert all(not c['items'] for c in snapshot['collections'])


@pytest.mark.parametrize('case', ['missing', 'cross_project', 'tag', 'extra', 'multi_scope', 'discovery', 'foreign_provider'])
def test_selector_preflight_rejects_before_auth(clean, monkeypatch, case):
    body = request()
    options = body['connector']['options']
    selector = options[runtime.OPTION][0]
    if case == 'missing':
        options.pop(runtime.OPTION)
    elif case == 'cross_project':
        selector['project_id'] = 'foreign'
    elif case == 'tag':
        selector['immutable_reference'] = 'us-central1-docker.pkg.dev/review/images/app:latest'
    elif case == 'extra':
        selector['custom_content'] = 'forbidden'
    elif case == 'multi_scope':
        body['connector']['scopes'].append('projects/foreign')
    elif case == 'discovery':
        options['all_projects'] = True
    elif case == 'foreign_provider':
        body['connector']['provider'] = 'aws'
        body.pop('checks')
    def forbidden(*args, **kwargs):
        raise AssertionError('invalid selector reached credentials')
    monkeypatch.setattr(gcp, 'Credentials', forbidden)
    with pytest.raises(ValueError):
        engine.collect_snapshot(body)


@pytest.mark.parametrize('case', ['scope', 'uid', 'capture_body', 'missing_request', 'request_url', 'foreign_layer', 'runtime_claim', 'duplicate', 'fake_detector'])
def test_pure_consumer_rejects_foreign_or_unbound_saved_sources(real, monkeypatch, tmp_path, case):
    snapshot, report, _, _, _, _ = roundtrip(monkeypatch, tmp_path, TOKEN)
    item = snapshot['collections'][0]['items'][0]
    proof = item[runtime.MARKER]
    if case == 'scope':
        proof['scope'] = 'projects/foreign'
    elif case == 'uid':
        proof['row']['selection']['resource_uid'] = '00000000-0000-4000-8000-000000000000'
    elif case == 'capture_body':
        proof['metadata_captures'][-4]['body']['etag'] = 'foreign'
    elif case == 'missing_request':
        snapshot['metadata']['source_requests'].pop()
    elif case == 'request_url':
        snapshot['metadata']['source_requests'][0]['url'] = 'https://foreign.invalid/'
    elif case == 'foreign_layer':
        proof['row']['content']['leaks'][0]['locations'][0]['layer'] = 'sha256:' + '0' * 64
    elif case == 'runtime_claim':
        proof['deployed_bytes_proven'] = True
    elif case == 'duplicate':
        snapshot['metadata']['source_requests'].append(deepcopy(snapshot['metadata']['source_requests'][0]))
    elif case == 'fake_detector':
        proof['row']['content']['leaks'][0]['detectors'][0]['engine'] = 'invented'
    result = engine.evaluate_snapshot(seal(snapshot), checks=[runtime.CHECK_ID])
    assert {f['status'] for f in result['findings']} == {'UNKNOWN'}




def test_collector_strings_cannot_grant_image_reads(clean, monkeypatch):
    body = request()
    body['connector']['options']['_content_secret_scan_kinds'] = [runtime.KIND]
    body['connector']['options'][runtime.GRANT] = {'seal': 'claimed'}
    def forbidden(*args, **kwargs):
        raise AssertionError('forged internal strings requested auth')
    monkeypatch.setattr(gcp, 'Credentials', forbidden)
    snapshot = runtime.collect_connector(body['connector'], [runtime.KIND])
    assert not snapshot['collections']


@pytest.mark.parametrize('case', ['valid', 'foreign_provider', 'malformed', 'private_grant'])
def test_hosted_intake_accepts_only_public_exact_job_selectors(case):
    from fastapi import HTTPException
    from peaso.server.validation import OPTIONS, validate_connector
    body = request()
    connector = body['connector']
    assert runtime.OPTION in OPTIONS
    if case == 'foreign_provider':
        connector['provider'] = 'aws'
    elif case == 'malformed':
        connector['options'][runtime.OPTION][0]['resource_uid'] = 'wrong'
    elif case == 'private_grant':
        connector['options'][runtime.GRANT] = 'claimed'
    def validate():
        validate_connector(connector['provider'], {'method': 'token', 'token': 'fixture-access-token'},
            connector['options'], SimpleNamespace(auth_mode='cognito'), scopes=connector['scopes'])
    if case == 'valid':
        validate()
    else:
        with pytest.raises(HTTPException) as error:
            validate()
        assert error.value.status_code == 422


def test_engine_grant_is_bound_to_exact_selector_and_scope(clean):
    body = request()
    options = body['connector']['options']
    options['_content_secret_scan_kinds'] = [runtime.KIND]
    runtime.issue_engine_grant(options, [SCOPE], [runtime.CHECK_ID])
    options[runtime.OPTION][0]['container_name'] = 'other'
    assert runtime.authorize_collector(options, [SCOPE]) is False
    assert runtime.GRANT not in options and runtime.KIND not in options['_content_secret_scan_kinds']


def test_existing_service_image_path_with_complete_native_http_fixture(clean, monkeypatch):
    # The historical fixture predates CRM duplicate-key parsing and omits HTTP
    # response.content. Supply those actual native JSON bytes in this new test.
    from tests import test_gcp_cloudrun_image_inspection_review as legacy
    def native_namespace(**kwargs):
        if 'json' in kwargs:
            kwargs['content'] = json.dumps(kwargs['json']()).encode()
        return SimpleNamespace(**kwargs)
    monkeypatch.setattr(legacy, 'SimpleNamespace', native_namespace)
    snapshot, binary, _ = legacy.observed(monkeypatch)
    findings = engine.evaluate_snapshot(snapshot, checks=[legacy.projection.CHECK_ID])['findings']
    finding, = findings
    assert finding['status'] == 'PASS', finding
    assert len(binary.calls) == 4 and binary.closed
    assert {path['revision'].rsplit('/', 1)[-1] for path in finding['evidence']['cloudrun_deployment_paths']} == {
        'api-old', 'api-new', 'api-preview'}
