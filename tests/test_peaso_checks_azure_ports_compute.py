"""Literal scope differences, guest assertions, and exact source compute truth fixtures."""
import copy
import json
from pathlib import Path
import re

import pytest

from peaso.checks import CHECKS, azure_ports_compute as ports
from peaso.checks.fixtures import CASES

ROOT = Path(__file__).resolve().parent.parent
REVIEWS = json.loads((ROOT / 'peaso/rulepacks/reviewed_azure_ports_compute.json').read_text())
REGISTRY = {c.id: c for c in CHECKS}
PROOFS = {r['source_review']['query_id']: r['source_review'] for r in REVIEWS.values()}


@pytest.mark.parametrize('cid', ports.CHECK_IDS)
def test_compute_pass_fail_denied_partial_missing_malformed_and_purity(cid):
    for label, expected in (('pass', 'PASS'), ('fail', 'FAIL')):
        item = copy.deepcopy(CASES[cid][label]); original = copy.deepcopy(item)
        assert REGISTRY[cid].evaluate(item, {})[0] == expected
        assert item == original
    for item in ({}, None, [], {'collection_status': 'denied'}, {'collection_status': 'partial'}):
        assert REGISTRY[cid].evaluate(item, {})[0] == 'UNKNOWN'


@pytest.mark.parametrize('query', PROOFS)
def test_inspected_source_sql_case_truth(query):
    duckdb = pytest.importorskip('duckdb')
    for case in PROOFS[query]['status_case_sql']:
        case = case.replace('b.vm_id', 'matching_vm_id')
        case = re.sub(r'\b[a-z_]+\.(\w+)\b', r'\1', case)
        case = re.sub(r"(\([^\n]+?\))::bool", r'CAST(\1 AS BOOLEAN)', case)
        case = re.sub(r"(\w+(?:\s*->>?\s*'[^']+')+)\s*(=|<>|is\s+null)", r'(\1) \2', case, flags=re.I)
        for good in (True, False):
            if query in ('compute_os_and_data_disk_encrypted_with_cmk', 'compute_unattached_disk_encrypted_with_cmk'): cols = {'encryption_type': 'EncryptionAtRestWithCustomerKey' if good else 'EncryptionAtRestWithPlatformKey'}
            elif query == 'compute_vm_utilizing_managed_disk': cols = {'managed_disk_id': '/disk' if good else None}
            elif query == 'compute_vm_trust_launch_enabled': cols = {'security_profile': {'securityType': 'TrustedLaunch', 'uefiSettings': {'secureBootEnabled': good, 'vTpmEnabled': True}}}
            elif query == 'compute_vm_ssh_key_authentication_linux': cols = {'os_type': 'Linux', 'matching_vm_id': '/vm' if good else None}
            elif query == 'compute_vm_and_sacle_set_encryption_at_host_enabled': cols = {'security_profile': {'encryptionAtHost': good}, 'virtual_machine_security_profile': {'encryptionAtHost': good}}
            elif query == 'compute_disk_public_access_disabled': cols = {'network_access_policy': 'AllowPrivate' if good else 'AllowAll', 'public_network_access': 'Disabled' if good else 'Enabled'}
            else: cols = {'data_access_auth_mode': 'AzureActiveDirectory' if good else 'None'}
            defs, values = [], []
            for name, value in cols.items():
                defs.append('?' + ('::JSON' if isinstance(value, dict) else '') + ' AS ' + name)
                values.append(json.dumps(value) if isinstance(value, dict) else value)
            with duckdb.connect(':memory:') as db:
                assert db.execute('SELECT ' + case + ' FROM (SELECT ' + ','.join(defs) + ')', values).fetchone()[0] == ('ok' if good else 'alarm')


def test_reserved_and_double_encryption_are_not_broadly_merged_with_source_filters():
    attached = REGISTRY[ports.SOURCE_QUERIES['compute_os_and_data_disk_encrypted_with_cmk']]
    not_attached = REGISTRY[ports.SOURCE_QUERIES['compute_unattached_disk_encrypted_with_cmk']]
    item = {'properties': {'diskState': 'Reserved', 'encryption': {'type': 'EncryptionAtRestWithCustomerKey'}}}
    assert attached.evaluate(item, {})[0] == 'NOT_APPLICABLE'
    assert not_attached.evaluate(item, {})[0] == 'PASS'
    item['properties']['encryption']['type'] = 'EncryptionAtRestWithPlatformAndCustomerKeys'
    assert not_attached.evaluate(item, {})[0] == 'FAIL'
    item['properties']['diskState'] = 'FutureState'
    assert not_attached.evaluate(item, {})[0] == 'UNKNOWN'


def test_managed_identifier_source_does_not_silently_skip_ephemeral_os_disks():
    check = REGISTRY[ports.SOURCE_QUERIES['compute_vm_utilizing_managed_disk']]
    assert check.evaluate({'properties': {'storageProfile': {'osDisk': {'diffDiskSettings': {'option': 'Local'}}}}}, {})[0] == 'FAIL'
    item = {'properties': {'storageProfile': {'osDisk': {'_coverage': {'managedDisk': {'status': 'denied'}}}}}}
    assert check.evaluate(item, {})[0] == 'UNKNOWN'


def test_trusted_launch_source_only_scope_and_missing_uefi_flags_unknown():
    check = REGISTRY[ports.SOURCE_QUERIES['compute_vm_trust_launch_enabled']]
    for kind in ('Standard', 'ConfidentialVM', None):
        assert check.evaluate({'properties': {'securityProfile': {'securityType': kind}}}, {})[0] == 'NOT_APPLICABLE'
    assert check.evaluate({'properties': {}}, {})[0] == 'NOT_APPLICABLE'
    assert check.evaluate({'properties': {'_coverage': {'securityProfile': {'status': 'denied'}}}}, {})[0] == 'UNKNOWN'
    assert check.evaluate({'properties': {'securityProfile': {'securityType': 'TrustedLaunch'}}}, {})[0] == 'UNKNOWN'


def test_guest_report_applicability_identity_status_and_denial_without_guest_execution():
    check = REGISTRY[ports.SOURCE_QUERIES['compute_vm_ssh_key_authentication_linux']]
    item = copy.deepcopy(CASES[check.id]['pass'])
    item['properties']['storageProfile']['osDisk']['osType'] = 'Windows'
    assert check.evaluate(item, {})[0] == 'NOT_APPLICABLE'
    item['properties']['storageProfile']['osDisk']['osType'] = 'Linux'
    row = item['guestConfigurationAssignments'][0]
    row['id'] = row['id'].replace('/g/', '/other/')
    assert check.evaluate(item, {})[0] == 'UNKNOWN'
    row['id'] = row['id'].replace('/other/', '/g/')
    row['properties']['complianceStatus'] = 'NonCompliant'
    assert check.evaluate(item, {})[0] == 'FAIL'
    row['properties']['complianceStatus'] = 'NewStatus'
    assert check.evaluate(item, {})[0] == 'UNKNOWN'
    item['_coverage'] = {'guestConfigurationAssignments': {'status': 'denied'}}
    assert check.evaluate(item, {})[0] == 'UNKNOWN'
