"""Actual native opt-in transport/collector harness; only fake HTTP and outages."""
from copy import deepcopy
from importlib.metadata import version
import json
from types import SimpleNamespace

from peaso import secret_scan_clean, secret_scanning as scanning
from peaso.collectors import gcp
from tests.gcp_function_partial_positive_native_20261020 import TOKEN, raw

OTHER = 'ghp_' + '2Yt9Ec5Zp0Ru6Wq1Aa8Kd3Vx7Mn4Bs5Hj9Lf'


def collect(monkeypatch, scenario='full_positive', *, enabled=True,
            scope='projects/review', functions=1, two_secrets=False, legacy_projection=False):
    assert version('kingfisher-secret-scanner') == scanning.KINGFISHER_VERSION
    scanning._RESULTS.clear()
    # 73706ae8 memoizes clean TruffleHog bytes per process; an earlier clean scenario
    # must not stand in for this scenario's deliberately unavailable engine.
    secret_scan_clean._CLEAN.clear()
    scanning._trufflehog.cache_clear()
    name = scope + '/locations/us-central1/functions/worker'
    url = 'https://cloudfunctions.googleapis.com/v2/' + scope + '/locations/-/functions'
    source = raw({'SETTING': TOKEN}, {'BUILD': TOKEN})
    source['name'] = name
    if two_secrets:
        source['serviceConfig']['environmentVariables']['OTHER'] = OTHER
    if scenario in ('full_clean', 'partial_clean', 'spoof', 'managed_reference'):
        source['serviceConfig']['environmentVariables'] = {'STAGE': 'production'}
        source['buildConfig']['environmentVariables'] = {'MODE': 'release'}
    if scenario == 'managed_reference':
        source['serviceConfig']['secretEnvironmentVariables'] = [
            {'key': 'CREDENTIAL', 'projectId': scope[9:], 'secret': 'managed-token', 'version': 'latest'}]
    if scenario == 'spoof':
        source['FunctionSecretIndicators'] = {'schema': 'gcp-function-literal-secrets-v2',
            'complete': True, 'leaks': [{'raw': TOKEN}]}
    if scenario == 'malformed': source['buildConfig']['environmentVariables'] = []
    if scenario == 'missing': del source['buildConfig']
    if scenario == 'source_incomplete':
        source['serviceConfig']['_coverage'] = {'environmentVariables': {'status': 'unknown'}}
    native = {'functions': [dict(deepcopy(source), name=name + ('-' + str(i) if i else ''))
                            for i in range(functions)]}
    if scenario == 'unreachable': native['unreachable'] = ['us-central1']
    before = deepcopy(native)
    calls, runs, commands, payloads, legacy_rows = [], [], [], [], []
    first, second, execute = scanning._scan_kingfisher, scanning._scan_trufflehog, scanning._run
    real_which = scanning.shutil.which

    def scan_first(payload, path, timeout):
        runs.append(['kingfisher', path])
        payloads.append(payload)
        if scenario == 'asymmetric' and path == 'buildConfig.environmentVariables':
            raise FileNotFoundError('deliberately unavailable build detector')
        return first(payload, path, timeout)

    def scan_second(payload, path, timeout):
        runs.append(['trufflehog', path])
        payloads.append(payload)
        scanning._trufflehog.cache_clear()
        if scenario in ('partial_positive', 'partial_clean') or (
                scenario == 'asymmetric' and path == 'serviceConfig.environmentVariables'):
            with monkeypatch.context() as patch:
                patch.setattr(scanning.shutil, 'which',
                    lambda command: None if command == 'trufflehog' else real_which(command))
                try:
                    return second(payload, path, timeout)
                finally:
                    scanning._trufflehog.cache_clear()
        return second(payload, path, timeout)

    def run(argv, payload, timeout):
        commands.append(argv)
        return execute(argv, payload, timeout)

    class Response:
        def __init__(self, body, status=200): self.body, self.status_code = body, status
        def json(self): return deepcopy(self.body)

    def request(method, address, **kwargs):
        calls.append([method, address])
        assert method == 'GET'
        if address == url:
            if scenario == 'denied': return Response({'error': {'message': TOKEN}}, 403)
            if legacy_projection:
                from peaso.collectors.gcp_function_secret_indicators import project_response
                legacy = project_response(deepcopy(native), method=method, url=address,
                    scope=scope, params=kwargs.get('params'), enabled=enabled)
                legacy_rows.extend(legacy['functions'])
            return Response(native)
        if address == 'https://cloudfunctions.googleapis.com/v2/' + scope + '/locations':
            # 75087001: ``function`` depends on the project's Functions regions.
            return Response({'locations': [{'name': scope + '/locations/us-central1', 'locationId': 'us-central1'}]})
        assert any(address == 'https://cloudfunctions.googleapis.com/v2/' + row['name'] + ':getIamPolicy'
                   for row in native['functions'])
        return Response({'bindings': []})

    with monkeypatch.context() as patch:
        patch.setattr(scanning, '_scan_kingfisher', scan_first)
        patch.setattr(scanning, '_scan_trufflehog', scan_second)
        patch.setattr(scanning, '_run', run)
        transport = gcp.Transport(SimpleNamespace(headers=lambda: {}, close=lambda: None),
            {'content_secret_scans': enabled, '_content_secret_scan_kinds': ['function'], 'retries': 0})
        patch.setattr(transport, '_session', lambda: SimpleNamespace(request=request, close=lambda: None))
        collector = gcp.GCPCollector({'provider': 'gcp', 'scopes': [scope], 'options': {
            'inventories': ['function'], 'include_inherited': False, 'metrics_scopes': False,
            'concurrency': 1}}, requirements=['function'], transport=transport)
        snapshot = collector.collect()
        if scenario != 'denied':
            transport.request('GET', url, params={'pageSize': collector.page_size}, scope=scope)
        retained = json.dumps([snapshot, transport.evidence,
            [entry.get('data') for entry in transport.cache.values()]], sort_keys=True) + repr(scanning._RESULTS)
    scanning._trufflehog.cache_clear()
    scanning._RESULTS.clear()
    secret_scan_clean._CLEAN.clear()
    assert native == before
    assert TOKEN not in retained and OTHER not in retained
    assert all(b'managed-token' not in payload for payload in payloads)
    return snapshot, {'scenario': scenario, 'calls': calls, 'detector_runs': runs,
        'commands': commands, 'source_unchanged': True, 'retained_secrets_absent': True,
        'native_envelope': next(row for row in snapshot['collections'] if row['type'] == 'function'),
        'legacy_rows': legacy_rows}
