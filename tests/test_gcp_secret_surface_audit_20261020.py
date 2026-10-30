"""Independent optional-secret admission and missing-evidence safety matrix.

Positive content and streaming proofs are attributed to the freshly executed
directed adapter suites; these cases add no manufactured clean scan markers.
"""
from copy import deepcopy
import json
from pathlib import Path
import socket
import threading
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from peaso import collectors, engine
from peaso.checks import CHECKS
from peaso.checks.native_only import exclusions
from peaso.collectors.gcp_image_secret_indicators import Reader
from peaso.snapshot import make_snapshot
from tests.test_gcp_secret_integration_acceptance_review import selected_options as prior_selected_options


ROOT = Path(__file__).resolve().parents[1]
SURFACES = json.loads((ROOT / 'docs/gcp-review/secret-surfaces.json').read_text())['surfaces']
BASELINE_IDS = {cid for surface in SURFACES for cid in surface.get('implementation', {}).get('check_ids', [])}
NEW_SELECTED_IDS = {'gcp.review.cloudtasks.selected_payload_secret_indicators',
                    'gcp.review.bigquery.selected_routine_secret_indicators'}
ADMITTED_SOURCE_IDS = {
    'gcp.review.batch.selected_mounted_script_source_secret_indicators',
    'gcp.review.cloudrun_job.declared_image_secret_indicators',
    'gcp.review.dataflow.selected_package_referenced_source_secret_indicators',
    'gcp.review.dataproc.selected_initialization_referenced_source_secret_indicators',
    'gcp.review.dataproc.selected_job_referenced_source_secret_indicators',
    'gcp.review.workbench.selected_referenced_source_secret_indicators_20261020',
}
IDS = sorted(BASELINE_IDS | NEW_SELECTED_IDS | ADMITTED_SOURCE_IDS)
REGISTRY = {c.id: c for c in CHECKS if c.id in IDS and c.id not in exclusions()}
SCOPE = 'projects/review'


def selected_options():
    raw = (ROOT / 'tests/fixtures/gcp-wave2-admitted-selectors-20261020.json').read_bytes()
    return {**prior_selected_options(), **json.loads(raw),
            'selected_cloudtasks_tasks': [SCOPE + '/locations/us-central1/queues/review/tasks/review'],
            'selected_bigquery_routines': [SCOPE + '/datasets/review/routines/review']}


@pytest.fixture(autouse=True)
def forbid_live_reads(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Secret-surface audit forbids live network and auth')
    for name in ('create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex'):
        monkeypatch.setattr(socket, name, forbidden)
    monkeypatch.setattr(socket.socket, 'connect', forbidden)
    monkeypatch.setattr(socket.socket, 'connect_ex', forbidden)
    monkeypatch.setattr('peaso.collectors.gcp.Credentials', forbidden)


@pytest.mark.parametrize('cid', IDS)
@pytest.mark.parametrize('mode', ['omitted', 'denied', 'partial'])
def test_every_secret_check_requires_collected_scanner_evidence(cid, mode):
    check = REGISTRY[cid]
    # A native subject identifier alone must not be construed as a scan result.
    row = {'name': SCOPE if check.kind == 'project' else SCOPE + '/unscanned-subject'}
    collection = {'type': check.kind, 'scope': SCOPE, 'status': 'collected', 'items': [row]}
    if mode == 'denied': collection.update(status='denied', items=[])
    if mode == 'partial': collection.update(status='partial', coverage_status='partial')
    native = make_snapshot('gcp', [SCOPE], [collection], metadata={})
    before = deepcopy(native)
    findings = engine.evaluate_snapshot(native, checks=[cid], include_not_applicable=True)['findings']
    assert native == before and findings
    assert {f['status'] for f in findings} == {'DENIED' if mode == 'denied' else 'UNKNOWN'}


@pytest.mark.parametrize('cid', IDS)
@pytest.mark.parametrize('enabled', [False, True])
def test_named_kind_preserves_the_separate_boolean_optin(monkeypatch, cid, enabled):
    calls = []
    def fake_collect(connector, requirements):
        calls.append((deepcopy(connector), list(requirements)))
        return make_snapshot('gcp', [SCOPE], [], metadata={})
    monkeypatch.setattr(collectors, 'collect_live', fake_collect)
    options = selected_options()
    options['content_secret_scans'] = enabled
    request = {'connector': {'provider': 'gcp', 'scopes': [SCOPE], 'options': options}, 'checks': [cid]}
    before = deepcopy(request)
    engine.collect_snapshot(request)
    assert request == before and len(calls) == 1
    bound = calls[0][0]['options'].get('_content_secret_scan_kinds', [])
    # Naming a check binds a kind even when disabled; readers must independently
    # require the public boolean, as the directed transport gate suites prove.
    assert bound == [REGISTRY[cid].kind]
    assert calls[0][0]['options']['content_secret_scans'] is enabled


@pytest.mark.parametrize('host,image', [
    ('us-central1-docker.pkg.dev', 'review/images/app'),
    ('gcr.io', 'review/app'), ('eu.gcr.io', 'review/app'), ('asia.gcr.io', 'review/app'),
])
@pytest.mark.parametrize('status', [401, 403])
def test_private_registry_denial_has_exact_route_closed_response_and_safe_receipt(host, image, status):
    digest = 'sha256:' + 'a' * 64
    expected = 'https://' + host + '/v2/' + image + '/manifests/' + digest
    calls = []
    class Denied:
        status_code = status
        url = expected
        history = []
        headers = {}
        closed = False
        def iter_content(self, **kwargs):
            raise AssertionError('Denied registry body must not be parsed')
        def close(self): self.closed = True
    response = Denied()
    class Session:
        closed = False
        def request(self, method, url, **kwargs):
            parsed = urlsplit(url)
            assert method == 'GET' and parsed.scheme == 'https'
            assert parsed.netloc == host and parsed.path == '/v2/' + image + '/manifests/' + digest
            assert not parsed.query and kwargs['allow_redirects'] is False and kwargs['stream'] is True
            assert kwargs['headers']['Accept-Encoding'] == 'identity'
            calls.append((method, url))
            return response
        def close(self): self.closed = True
    session = Session()
    transport = SimpleNamespace(lock=threading.Lock(), calls=0, max_calls=2, timeout=5,
        check_cancelled=lambda: None, evidence=[],
        credentials=SimpleNamespace(headers=lambda: {'Authorization': 'Bearer offline-test-token'}))
    reader = Reader(transport, session=session)
    try:
        with pytest.raises(ValueError):
            reader.get(host + '/' + image + '@' + digest, 'manifests', digest, 1024)
    finally:
        reader.close()
    assert calls == [('GET', expected)] and response.closed and session.closed
    receipt, = transport.evidence
    assert receipt['status'] == 'denied' and receipt['http_status'] == status
    assert receipt['scope'] == SCOPE and receipt['http_attempts'] == 1
    assert 'Authorization' not in json.dumps(receipt) and 'offline-test-token' not in json.dumps(receipt)
