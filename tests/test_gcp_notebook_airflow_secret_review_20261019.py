"""Native JSON -> pre-cache projection -> offline tools -> pure callbacks.

All Python sockets/DNS fail closed. The collector integration test requires root's
actual installed transport hook; no fake scheduling or sanitized fixture input.
"""
from copy import deepcopy
import json
import socket
from types import SimpleNamespace

import pytest
from peaso.collectors import gcp
from peaso.collectors import gcp_notebook_airflow_secret_indicators as a
from peaso.checks import gcp_notebook_airflow_secret_review_20261019 as c
from peaso import secret_scanning as scanning
from peaso.secret_findings import deduplicate_secret_findings

SCOPE = 'projects/review'
TOKEN = 'ghp_' + '7mq2zr9wl4cv8nk1sf6ah3jp5ud0xb2ye9rt'


def native(kind, positive=False):
    value = TOKEN if positive else 'production'
    name = SCOPE + '/locations/' + ('us-central1' if kind == a.COMPOSER else 'us-central1-a') + '/' + a.SPEC[kind][2] + '/worker'
    common = {'name': name, 'labels': {'stage': value}}
    if kind == a.COMPOSER:
        return {**common, 'state': 'RUNNING', 'config': {'softwareConfig': {
            'envVariables': {'API_TOKEN': value}, 'airflowConfigOverrides': {'smtp-smtp_password': value},
            'pypiPackages': {'numpy': '==1.12.0'}}, 'encryptionConfig': {'kmsKeyName': 'projects/review/locations/us-central1/keyRings/r/cryptoKeys/k'},
            'privateEnvironmentConfig': {'enablePrivateEnvironment': True}, 'dagGcsPrefix': 'gs://dag-bucket/dags'}}
    return {**common, 'state': 'ACTIVE', 'gceSetup': {
        'metadata': {'startup-script': 'export API_TOKEN=' + value, 'post-startup-script': 'export OTHER=' + value,
                     'post-startup-script-url': 'gs://scripts/boot.sh', 'notebook-disable-root': 'true'},
        'systemMetadata': {'post-startup-script': 'export OTHER=' + value, 'notebook-disable-root': 'true'},
        'shieldedInstanceConfig': {'enableSecureBoot': True}, 'disablePublicIp': True}}


def kwargs(kind, **overrides):
    host, version, plural = a.SPEC[kind]
    location = 'us-central1' if kind == a.COMPOSER else '-'
    return {'method': 'GET', 'url': f'https://{host}/{version}/{SCOPE}/locations/{location}/{plural}',
            'scope': SCOPE, 'enabled': True, 'selected_kinds': [kind], **overrides}


def context(row, kind, status='collected'):
    return {'context': {'provider': 'gcp', 'scope': SCOPE}, 'collections': {
        kind: [{'type': kind, 'scope': SCOPE, 'status': status, 'items': [row]}]}}


def project(kind, row=None, **options):
    row = native(kind) if row is None else row
    page = a.project_response({a.SPEC[kind][2]: [row]}, **kwargs(kind, **options))
    item, = page[a.SPEC[kind][2]]
    return item, context(item, kind), page


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    def forbidden(*args, **kw): raise AssertionError('Unmocked socket/DNS forbidden')
    for name in ('connect', 'connect_ex'): monkeypatch.setattr(socket.socket, name, forbidden)
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


@pytest.fixture
def clean(monkeypatch):
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *args: [])
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *args: [])


@pytest.mark.parametrize('kind', a.KINDS)
@pytest.mark.parametrize('options', [{'enabled': False}, {'enabled': 'true'}, {'selected_kinds': []}, {'selected_kinds': ['function']}])
def test_default_off_scrub_and_exact_activation_without_tools(monkeypatch, kind, options):
    def forbidden(*args, **kw): raise AssertionError('scanner must not run')
    monkeypatch.setattr(a, 'scan_content', forbidden)
    row, index, safe = project(kind, native(kind, True), **options)
    assert TOKEN not in json.dumps(safe)
    assert a.MARKER not in row and c.evaluate(row, index, kind)[0] == 'UNKNOWN'
    if kind == a.WORKBENCH:
        assert row['gceSetup']['metadata']['notebook-disable-root'] == 'true'
        assert row['gceSetup']['metadata']['post-startup-script'] is None
        assert row['gceSetup']['shieldedInstanceConfig']['enableSecureBoot'] is True
    else:
        assert row['config']['privateEnvironmentConfig']['enablePrivateEnvironment'] is True
        assert row['config']['encryptionConfig']['kmsKeyName'].endswith('/cryptoKeys/k')
    if kind == a.COMPOSER:
        assert row['config']['softwareConfig']['_coverage']['envVariables']['status'] == 'unavailable'
    else:
        assert row['gceSetup']['metadata']['_coverage']['post-startup-script']['status'] == 'unavailable'


@pytest.mark.parametrize('kind', a.KINDS)
def test_native_omitted_optional_maps_and_full_get(clean, kind):
    row = native(kind)
    if kind == a.COMPOSER:
        for key in ('envVariables', 'airflowConfigOverrides', 'pypiPackages'): row['config']['softwareConfig'].pop(key)
    else: row['gceSetup'].pop('metadata')
    out, index, _ = project(kind, row, url=kwargs(kind)['url'].replace('/locations/-/', '/locations/us-central1-a/') + '/worker')
    assert c.evaluate(out, index, kind)[0] == 'PASS'


@pytest.mark.parametrize('kind', a.KINDS)
@pytest.mark.parametrize('mutation', ['missing_parent', 'wrong_map', 'oversize', 'foreign', 'masked', 'partial', 'invalid_method', 'invalid_host', 'invalid_scope', 'field_mask'])
def test_unavailable_native_contracts_are_unknown_and_literals_removed(clean, kind, mutation):
    row = native(kind, True); options = {}
    if mutation == 'missing_parent': row.pop('config' if kind == a.COMPOSER else 'gceSetup')
    if mutation == 'wrong_map':
        if kind == a.COMPOSER: row['config']['softwareConfig']['envVariables'] = TOKEN
        else: row['gceSetup']['metadata'] = TOKEN
    if mutation == 'oversize':
        if kind == a.COMPOSER: row['config']['softwareConfig']['envVariables']['LARGE'] = 'a' * (a.MAX_VALUE_BYTES + 1)
        else: row['gceSetup']['metadata']['LARGE'] = 'a' * (a.MAX_VALUE_BYTES + 1)
    if mutation == 'foreign': row['name'] = row['name'].replace('projects/review/', 'projects/foreign/')
    if mutation == 'masked': row['_field_mask'] = 'name'
    if mutation == 'partial': options['response_complete'] = False
    if mutation == 'invalid_method': options['method'] = 'POST'
    if mutation == 'invalid_host': options['url'] = kwargs(kind)['url'].replace('https://', 'https://user@')
    if mutation == 'invalid_scope': options['scope'] = 'projects/elsewhere'
    if mutation == 'field_mask': options['params'] = {'fields': 'name'}
    out, index, safe = project(kind, row, **options)
    assert c.evaluate(out, index, kind)[0] == 'UNKNOWN'
    assert TOKEN not in json.dumps(safe)


def test_run_budgets_partial_pages_cancel_and_freeform_pages(clean):
    budget = a.new_budget(); budget['pages'] = a.MAX_PAGES
    row, index, _ = project(a.COMPOSER, budget=budget)
    assert c.evaluate(row, index, a.COMPOSER)[0] == 'UNKNOWN'
    budget = a.new_budget(); budget['bytes'] = a.MAX_TOTAL_BYTES
    row, index, _ = project(a.WORKBENCH, budget=budget)
    assert c.evaluate(row, index, a.WORKBENCH)[0] == 'UNKNOWN'
    budget = a.new_budget(); budget['deadline'] = 0
    row, index, _ = project(a.WORKBENCH, budget=budget)
    assert c.evaluate(row, index, a.WORKBENCH)[0] == 'UNKNOWN'
    def cancel(): raise RuntimeError(TOKEN)
    row, index, safe = project(a.WORKBENCH, check_cancelled=cancel)
    assert c.evaluate(row, index, a.WORKBENCH)[0] == 'UNKNOWN' and TOKEN not in json.dumps(safe)
    for kind in a.KINDS:
        raw = {a.SPEC[kind][2]: [native(kind)], 'unreachable': ['us-other']}
        safe = a.project_response(raw, **kwargs(kind))
        row, = safe[a.SPEC[kind][2]]
        assert c.evaluate(row, context(row, kind), kind)[0] == 'UNKNOWN'
        # Free-form duplicates on an earlier clean page must never persist,
        # even when the revealing literal occurs on a later page.
        raw = native(kind); raw['labels'] = {'reflection': TOKEN}; raw['annotations'] = {'copy': TOKEN}; raw['description'] = TOKEN
        out, _, _ = project(kind, raw)
        assert TOKEN not in json.dumps(out)
        assert out['_coverage']['labels']['status'] == 'unavailable'
        assert out['_coverage']['description']['status'] == 'unavailable'


def test_malformed_parents_default_scrub_and_retained_security_unknown():
    for kind in a.KINDS:
        row = native(kind, True)
        if kind == a.COMPOSER: row['config']['softwareConfig'] = TOKEN
        else: row['gceSetup'] = TOKEN
        out, _, safe = project(kind, row, enabled=False)
        assert TOKEN not in json.dumps(safe)
    row = native(a.WORKBENCH); row['gceSetup']['metadata']['notebook-disable-root'] = TOKEN
    out, _, _ = project(a.WORKBENCH, row, enabled=False)
    assert out['gceSetup']['metadata']['notebook-disable-root'] is None


@pytest.mark.parametrize('kind', a.KINDS)
@pytest.mark.parametrize('positive', [False, True])
def test_real_dual_tools_hidden_values_and_no_reference_download(kind, positive, capsys):
    out, index, safe = project(kind, native(kind, positive))
    status, evidence = c.evaluate(out, index, kind)
    assert status == ('FAIL' if positive else 'PASS')
    if positive:
        leak, = evidence['secret_leaks']
        assert {d['engine'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
    assert TOKEN not in json.dumps([safe, evidence]) + repr(scanning._RESULTS) + str(capsys.readouterr())


def test_real_cross_owner_exact_value_dedup():
    findings = []
    for kind in a.KINDS:
        row, index, _ = project(kind, native(kind, True)); status, evidence = c.evaluate(row, index, kind)
        assert status == 'FAIL'
        findings.append({'provider': 'gcp', 'check_id': c.DECLARATIONS[kind]['id'], 'scope': SCOPE,
            'resource_id': row['name'], 'native_resource_id': row['name'], 'resource_type': kind,
            'status': status, 'finding_type': 'secrets', 'frameworks': [], 'evidence': evidence})
    merged = deduplicate_secret_findings(findings)
    assert len(merged) == 1 and len(merged[0]['linked_check_ids']) == 2
    assert TOKEN not in json.dumps(merged)


def test_one_engine_failure_and_forged_marker_unknown(monkeypatch):
    def absent(*args): raise OSError(TOKEN)
    monkeypatch.setattr(scanning, '_scan_trufflehog', absent)
    row, index, safe = project(a.COMPOSER, native(a.COMPOSER, True))
    assert c.evaluate(row, index, a.COMPOSER)[0] == 'UNKNOWN' and TOKEN not in json.dumps(safe)
    row[a.MARKER]['complete'] = True
    assert c.evaluate(row, index, a.COMPOSER)[0] == 'UNKNOWN'


def collect_native_pipeline(monkeypatch, kind, row=None, options=None, denied=False):
    """Actual collector, installed pre-cache hook and existing service jobs."""
    opts = {'inventories': [kind], 'include_inherited': False, 'metrics_scopes': False,
            'concurrency': 1, 'retries': 0, 'content_secret_scans': True, '_content_secret_scan_kinds': [kind],
            'composer_locations': ['us-central1'], **(options or {})}
    row = deepcopy(row if row is not None else native(kind))
    calls = []
    class Response:
        status_code = 200
        headers = {}
        def __init__(self, data, status=200): self.data = data; self.status_code = status
        def json(self): return deepcopy(self.data)
    def request(method, url, **kw):
        calls.append((method, url, kw))
        assert method == 'GET'
        if url == 'https://cloudresourcemanager.googleapis.com/v3/' + SCOPE:
            return Response({'name': 'projects/10001', 'projectId': 'review', 'state': 'ACTIVE'})
        if url == 'https://compute.googleapis.com/compute/v1/' + SCOPE: return Response({'name': 'review', 'id': '10001'})
        if kind == a.WORKBENCH and url == 'https://' + a.SPEC[kind][0] + '/v2/' + row['name'] + ':getIamPolicy':
            # 75087001 hydrates each Workbench instance's IAM policy.
            return Response({'bindings': []})
        assert url == kwargs(kind)['url']
        return Response({a.SPEC[kind][2]: [row]}, 403 if denied else 200)
    transport = gcp.Transport(SimpleNamespace(headers=lambda: {'Authorization': 'Bearer fake-token'}, close=lambda: None), opts)
    monkeypatch.setattr(transport, '_session', lambda: SimpleNamespace(request=request))
    collector = gcp.GCPCollector({'provider': 'gcp', 'scopes': [SCOPE], 'options': opts}, requirements=[kind], transport=transport)
    snapshot = collector.collect(); collections = {}
    for e in snapshot['collections']: collections.setdefault(e['type'], []).append(e)
    envelope, = collections[kind]
    return envelope, {'context': {'provider': 'gcp', 'scope': SCOPE}, 'collections': collections}, snapshot, calls, transport


@pytest.mark.parametrize('kind', a.KINDS)
def test_actual_collector_installed_precache_hook_real_offline_tools(monkeypatch, kind):
    e, index, snapshot, calls, transport = collect_native_pipeline(monkeypatch, kind, native(kind, True))
    row, = e['items']
    assert c.evaluate(row, index, kind)[0] == 'FAIL'
    assert a.MARKER in row
    assert len([url for _, url, _ in calls if a.SPEC[kind][0] in url and not url.endswith(':getIamPolicy')]) == 1
    assert TOKEN not in json.dumps([snapshot, transport.evidence]) + repr(transport.cache)
    with pytest.raises(AssertionError, match='forbidden'): socket.create_connection(('example.invalid', 443))


def test_install_native_fixtures_idempotent():
    from peaso.checks import CHECKS
    from peaso.checks.fixtures import CASES
    c.install(); c.install()
    for kind, d in c.DECLARATIONS.items():
        assert sum(x.id == d['id'] for x in CHECKS) == 1
        f = CASES[d['id']]
        for label in ('pass', 'fail', 'unknown'):
            assert c.CALLBACKS[kind](f[label], f[label + '_index'])[0] == label.upper()
        for label in ('missing', 'malformed'): assert c.CALLBACKS[kind](f[label], {})[0] == 'UNKNOWN'


def test_nested_coverage_and_existing_workbench_security_compatibility():
    from peaso.checks.facts import get, Unavailable
    from peaso.checks import gcp_workbench_review_20261019 as existing
    out, index, _ = project(a.WORKBENCH, enabled=False)
    out['_provenance'] = {'representation': 'full', 'scope': SCOPE, 'source_requests': ['request-1']}
    assert existing.root_access(out, index)[0] == 'PASS'
    assert existing.public_ip(out, index)[0] == 'PASS'
    with pytest.raises(Unavailable): get(out, 'gceSetup.metadata.startup-script', str)
    raw = native(a.WORKBENCH); raw['gceSetup']['metadata'].pop('notebook-disable-root')
    out, index, _ = project(a.WORKBENCH, raw, enabled=False)
    out['_provenance'] = {'representation': 'full', 'scope': SCOPE, 'source_requests': ['request-1']}
    assert existing.root_access(out, index)[0] == 'FAIL'
    raw['gceSetup']['metadata']['notebook-disable-root'] = TOKEN
    out, index, _ = project(a.WORKBENCH, raw, enabled=False)
    with pytest.raises(Unavailable): existing.root_access(out, index)
    out, _, _ = project(a.COMPOSER, enabled=False)
    for field in a.FIELDS[a.COMPOSER]:
        with pytest.raises(Unavailable): get(out, field, dict)


def test_real_pypi_literal_and_clean_external_reference_only():
    row = native(a.COMPOSER)
    row['config']['softwareConfig']['pypiPackages']['private-package'] = TOKEN
    out, index, _ = project(a.COMPOSER, row)
    assert c.evaluate(out, index, a.COMPOSER)[0] == 'FAIL'
    assert TOKEN not in json.dumps(out)
    row = native(a.WORKBENCH)
    row['gceSetup']['metadata'] = {'post-startup-script-url': 'gs://scripts/boot.sh'}
    out, index, _ = project(a.WORKBENCH, row)
    assert c.evaluate(out, index, a.WORKBENCH)[0] == 'PASS'
    assert out[a.MARKER]['fields'] == ['gceSetup.metadata', 'gceSetup.systemMetadata']
    # Output-only system metadata can be the sole reflected literal source.
    row = native(a.WORKBENCH, True); row['gceSetup']['metadata'] = {}
    out, index, _ = project(a.WORKBENCH, row)
    assert c.evaluate(out, index, a.WORKBENCH)[0] == 'FAIL'
    assert TOKEN not in json.dumps(out)


@pytest.mark.parametrize('kind', a.KINDS)
def test_actual_default_scrub_same_existing_call_count_no_tools(monkeypatch, kind):
    def forbidden(*args, **kw): raise AssertionError('scanner must not run')
    monkeypatch.setattr(a, 'scan_content', forbidden)
    e, index, snapshot, calls, transport = collect_native_pipeline(monkeypatch, kind, native(kind, True),
        options={'content_secret_scans': False, '_content_secret_scan_kinds': []})
    row, = e['items']
    assert c.evaluate(row, index, kind)[0] == 'UNKNOWN'
    assert len([url for _, url, _ in calls if a.SPEC[kind][0] in url and not url.endswith(':getIamPolicy')]) == 1
    assert TOKEN not in json.dumps(snapshot) + repr(transport.cache)


def test_native_denied_reads_never_scan_or_cache_error_configuration(monkeypatch):
    def forbidden(*args, **kw): raise AssertionError('denied response must not scan')
    monkeypatch.setattr(a, 'scan_content', forbidden)
    for kind in a.KINDS:
        e, index, snapshot, calls, transport = collect_native_pipeline(monkeypatch, kind, native(kind, True), denied=True)
        assert e['status'] != 'collected' and not e['items']
        assert c.evaluate({}, index, kind)[0] == 'UNKNOWN'
        assert TOKEN not in json.dumps([snapshot, transport.evidence]) + repr(transport.cache)
