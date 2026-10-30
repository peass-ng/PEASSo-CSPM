"""Complete native configuration can prove a missing individual log operation."""
from copy import deepcopy
from urllib.parse import urlsplit
import pytest

from peaso.collectors import azure, collect_live
from tests.test_peaso_azure_audit_storage_history import requirements as historical_requirements, evaluate as historical_evaluate
from tests.test_peaso_azure_audit_storage_native import API, ACCOUNT, SERVICE, SCOPE, options, native


class GapAPI(API):
    def __init__(self, mode):
        super().__init__('absent')
        self.gap_mode = mode

    def request_xml(self, url):
        result = super().request_xml(url)
        if self.gap_mode == 'legacy-read-diagnostic-write':
            result['read'] = True
        return result

    def request(self, url, *, body=None, audience=azure.ARM):
        if urlsplit(url).path != SERVICE + '/providers/Microsoft.Insights/diagnosticSettings':
            return super().request(url, body=body, audience=audience)
        self.calls.append((url, deepcopy(body)))
        mode = self.gap_mode
        logs = [{'category': 'StorageRead', 'enabled': True}]
        if mode == 'all-disabled':
            logs = [{'category': c, 'enabled': False} for c in sorted(native.CATEGORIES)]
        elif mode == 'legacy-read-diagnostic-write':
            logs = [{'category': 'StorageWrite', 'enabled': True}]
        elif mode == 'all-configured':
            logs = [{'category': c, 'enabled': True} for c in sorted(native.CATEGORIES)]
        elif mode in ('all-group', 'unknown-group'):
            logs = [{'categoryGroup': 'allLogs' if mode == 'all-group' else 'futureGroup', 'enabled': True}]
        elif mode == 'malformed-flag':
            logs[0]['enabled'] = 'false'
        rid = SERVICE + '/providers/Microsoft.Insights/diagnosticSettings/logs'
        if mode == 'foreign-setting':
            rid = rid.replace('/default/', '/foreign/')
        return {'value': [{'id': rid, 'name': 'logs', 'properties': {'logs': logs}}]}


@pytest.mark.parametrize('mode,missing', [
    ('read-only', ['write', 'delete']),
    ('all-disabled', ['read', 'write', 'delete']),
    ('legacy-read-diagnostic-write', ['delete']),
    ('all-configured', None), ('all-group', None), ('unknown-group', None),
    ('malformed-flag', None), ('foreign-setting', None),
])
def test_native_operation_gaps_without_delivery_claim(monkeypatch, mode, missing):
    api = GapAPI(mode)
    monkeypatch.setattr(azure, 'AzureTransport', lambda auth: api)
    # collect() builds AzureTransportExposure for owned native reads.
    monkeypatch.setattr(azure, 'AzureTransportExposure', lambda auth: api)
    connector = {'provider': 'azure', 'scopes': [SCOPE], 'auth': {
        'method': 'token', 'arm_token': 'inert', 'storage_token': 'inert'}, 'options': options('absent')}
    snapshot = collect_live(connector, historical_requirements())
    findings = historical_evaluate(snapshot)
    assert {f['status'] for f in findings} == {'FAIL' if missing else 'UNKNOWN'}, findings
    if missing:
        assert all(f['evidence']['missing_blob_access_log_operations'] == missing for f in findings)
    assert api.closed
    assert all(body is None or urlsplit(url).path == '/providers/Microsoft.ResourceGraph/resources'
               for url, body in api.calls)
