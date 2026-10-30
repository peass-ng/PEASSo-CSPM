"""Hosted approval intake for bounded, non-PCI native installation evidence."""
from copy import deepcopy
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from peaso.server.validation import validate_connector

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
CHECK = 'azure.gap.compute_vm_system_updates_installed'


def options():
    return {'concurrency': 1, 'retries': 1, 'compliance_policy': {
        'status': 'collected', 'scope': SCOPE, 'checks': {
            CHECK: {'requireActualInstallation': True, 'requirePciCompliance': False,
                    'maxReportAgeSeconds': 86400}}}}


def validate(config):
    validate_connector('azure', {'method': 'token', 'arm_token': 'inert'},
                       config, SimpleNamespace(auth_mode='cognito'))


@pytest.mark.parametrize('value', [True, False, 'absent'])
def test_hosted_accepts_optional_typed_installation_requirement(value):
    config = options()
    review = config['compliance_policy']['checks'][CHECK]
    if value == 'absent':
        review.pop('requireActualInstallation')
    else:
        review['requireActualInstallation'] = value
    before = deepcopy(config)
    validate(config)
    assert config == before


@pytest.mark.parametrize('flag', ['requireActualInstallation', 'requirePciCompliance'])
@pytest.mark.parametrize('value', [None, 0, 1, 'true', [], {}])
def test_hosted_rejects_untyped_patch_requirement(flag, value):
    config = options()
    config['compliance_policy']['checks'][CHECK][flag] = value
    with pytest.raises(HTTPException) as error:
        validate(config)
    assert error.value.status_code == 422


VM = SCOPE + '/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm'
OPERATION = '33333333-3333-3333-3333-333333333333'


class NativeAPI:
    tenant = verified_tenant = '22222222-2222-2222-2222-222222222222'

    def __init__(self, mode):
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        self.times = [(now-timedelta(hours=n)).isoformat() for n in (4, 3, 2)]
        self.mode, self.calls, self.closed = mode, [], False

    def close(self):
        self.closed = True

    def request(self, url, *, body=None, audience=None):
        from urllib.parse import urlsplit
        from peaso.collectors import azure
        self.calls.append((url, deepcopy(body)))
        path = urlsplit(url).path
        assert audience == azure.ARM
        if body is not None:
            assert path == '/providers/Microsoft.ResourceGraph/resources'
            if 'patchinstallationresources' not in body['query']:
                return {'data': [], 'resultTruncated': False}
            if self.mode == 'denied':
                raise azure.AzureReadError('fixture_denied', 403)
            props = {'installationActivityId': OPERATION, 'status': 'Succeeded',
                'lastModifiedDateTime': self.times[1], 'installedPatchCount': 2,
                'failedPatchCount': 0, 'pendingPatchCount': 0,
                'maintenanceWindowExceeded': False, 'rebootStatus': 'NotNeeded'}
            rows = [] if self.mode == 'missing_result' else [{
                'id': VM + '/patchInstallationResults/' + OPERATION,
                'type': 'patchinstallationresults', 'properties': props}]
            return {'data': rows, 'resultTruncated': self.mode == 'truncated'}
        machine = {'id': VM, 'type': 'Microsoft.Compute/virtualMachines',
                   'properties': {'storageProfile': {'osDisk': {'osType': 'Linux'}}}}
        if path == SCOPE + '/providers/Microsoft.Compute/virtualMachines':
            return {'value': [machine]}
        if path == VM:
            return machine
        if path == VM + '/instanceView':
            return {'patchStatus': {
                'availablePatchSummary': {'status': 'Succeeded',
                    'lastModifiedTime': self.times[2],
                    'criticalAndSecurityPatchCount': int(self.mode == 'missing_patches')},
                'lastPatchInstallationSummary': {'status': 'Succeeded',
                    'installationActivityId': OPERATION,
                    'lastModifiedTime': self.times[0], 'installedPatchCount': 2,
                    'failedPatchCount': 0, 'pendingPatchCount': 0,
                    'maintenanceWindowExceeded': False}}}
        return {'value': []}


@pytest.mark.parametrize('mode,expected', [
    ('complete', 'PASS'), ('missing_result', 'UNKNOWN'), ('denied', 'UNKNOWN'),
    ('truncated', 'UNKNOWN'), ('missing_patches', 'FAIL'),
    ('unapproved', 'UNKNOWN'), ('pci', 'UNKNOWN')])
def test_normal_hosted_native_compute_pipeline(monkeypatch, mode, expected):
    from peaso.collectors import azure, collect_live
    from tests.archived_check_contract import evaluate_snapshot, plan_collection
    api = NativeAPI(mode)
    monkeypatch.setattr(azure, 'AzureTransportExposure', lambda auth: api)
    config = options()
    if mode == 'unapproved':
        config.pop('compliance_policy')
    elif mode == 'pci':
        config['compliance_policy']['checks'][CHECK]['requirePciCompliance'] = True
    validate(config)
    connector = {'provider': 'azure', 'scopes': [SCOPE],
                 'auth': {'method': 'token', 'arm_token': 'inert'}, 'options': config}
    planned = plan_collection({'connector': connector, 'checks': [CHECK]})
    assert 'vm_patch_installation_result' in planned
    snapshot = collect_live(connector, planned)
    report = evaluate_snapshot(snapshot, checks=[CHECK], include_not_applicable=True)
    findings = [row for row in report['findings'] if row['check_id'] == CHECK]
    assert len(findings) == 1 and findings[0]['status'] == expected, findings
    arg = [(url, body) for url, body in api.calls
           if body is not None and 'patchinstallationresources' in body['query']]
    assert bool(arg) == (mode != 'unapproved')
    result = next(c for c in snapshot['collections'] if c['type'] == 'vm_patch_installation_result')
    if mode == 'unapproved':
        assert result['status'] == 'unknown'
        assert result['error']['code'] == 'actual_installation_policy_not_approved'
    elif mode == 'complete':
        assert result['status'] == 'collected'
    assert sum('/instanceView?' in url for url, body in api.calls) == 1
    assert api.closed
    if mode == 'complete':
        assert findings[0]['evidence']['native_installation']['installed_patch_count'] == 2
        assert findings[0]['evidence']['require_pci_compliance'] is False
    if mode in ('missing_result', 'denied', 'truncated'):
        assert 'completed Update Manager installation result unavailable' in findings[0]['evidence']['reason']
    if mode == 'pci':
        assert 'native_installation' not in findings[0]['evidence']
