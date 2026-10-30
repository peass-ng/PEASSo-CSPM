"""Stubbed Resource Graph collector boundaries for one approved VM operation."""
import pytest

from peaso.collectors.azure_wave_compute_native import KIND, collect, required_types


SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
VM = SCOPE + '/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm'


def _vm():
    return {'id': VM, '_coverage': {'instanceView': {'status': 'collected'}},
            'instanceView': {'patchStatus': {'lastPatchInstallationSummary': {
                'installationActivityId': 'operation-1'}}}}


def _policy(approved=True):
    return {'compliance_policy': {'status': 'collected', 'scope': SCOPE,
            'checks': {'azure.gap.compute_vm_system_updates_installed': {
                'requireActualInstallation': approved, 'requirePciCompliance': False}}}}


def _result(vm=VM, operation='operation-1'):
    return {'id': vm + '/patchInstallationResults/' + operation,
            'type': 'patchinstallationresults',
            'properties': {'installationActivityId': operation,
                           'lastModifiedDateTime': '2026-10-16T09:20:00Z',
                           'status': 'Succeeded', 'installedPatchCount': 3,
                           'failedPatchCount': 0, 'pendingPatchCount': 0,
                           'maintenanceWindowExceeded': False, 'rebootStatus': 'NotNeeded'}}


class Reader:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []
        self.collections = [{'type': 'vm', 'scope': SCOPE, 'status': 'collected', 'items': [_vm()]}]

    def pages(self, request, url, *, body, key, next_key):
        self.calls.append((url, body, key, next_key))
        yield self.rows

    def run(self, jobs):
        for kind, scope, service, fetch in jobs:
            items = [item for page in fetch() for item in page]
            self.collections.append({'type': kind, 'scope': scope, 'service': service,
                                     'status': 'collected' if items else 'empty', 'items': items})

    def unavailable(self, kind, scope, service, exc):
        self.collections.append({'type': kind, 'scope': scope, 'service': service,
                                 'status': 'unavailable', 'items': [], 'error': str(exc)})

    def progress(self, phase=None, scope='', settled=None):
        # Real Azure readers only report an envelope the collector already appended.
        assert settled is None or settled is self.collections[-1]


def test_approved_scope_collects_only_exact_operation_with_bounded_arg_query():
    reader = Reader([_result()])
    assert required_types({KIND}) == {'vm'}
    collect(reader, None, [SCOPE], {KIND}, _policy())
    rows = reader.collections[-1]['items']
    assert len(rows) == 1
    assert rows[0]['vm_id'] == VM
    assert rows[0]['properties']['installationActivityId'] == 'operation-1'
    assert rows[0]['_provenance']['source_operation'] == 'ResourceGraph:patchinstallationresources'
    url, body, key, next_key = reader.calls[0]
    assert url.endswith('/providers/Microsoft.ResourceGraph/resources?api-version=2024-04-01')
    assert body['subscriptions'] == [SCOPE.rsplit('/', 1)[-1]]
    assert "type =~ 'patchinstallationresults'" in body['query']
    assert body['options']['$top'] == 1000
    assert (key, next_key) == ('data', '$skipToken')


def test_unapproved_scope_does_not_make_arg_call():
    reader = Reader([_result()])
    collect(reader, None, [SCOPE], {KIND}, _policy(approved=False))
    assert reader.calls == []
    assert reader.collections[-1]['status'] == 'unknown'
    assert reader.collections[-1]['error'] == {'code': 'actual_installation_policy_not_approved'}


def test_foreign_result_rejected_before_snapshot_fact():
    reader = Reader([_result(vm='/subscriptions/other/resourceGroups/r/providers/Microsoft.Compute/virtualMachines/v')])
    with pytest.raises(ValueError, match='foreign Update Manager'):
        collect(reader, None, [SCOPE], {KIND}, _policy())


def test_mismatched_operation_result_is_not_projected():
    reader = Reader([_result(operation='older')])
    with pytest.raises(ValueError, match='outside requested operation set'):
        collect(reader, None, [SCOPE], {KIND}, _policy())
