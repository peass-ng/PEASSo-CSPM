"""Finite native HTTP -> Azure collector -> public engine proposal proofs.

The two proposals are installed only in a reversible test-local registry overlay.
Production registration/admission/catalog files and frozen predecessors are untouched.
"""
import io
import json
import os
import socket
import sys
from copy import deepcopy
from pathlib import Path
from urllib.parse import urlsplit, parse_qs
import hashlib
import pytest

from peaso import checks, engine
from peaso.collectors import azure
from peaso.checks import Check
from peaso.snapshot import thaw
from tests import archived_check_contract as archived
import inspect
from peaso.checks import azure_native_contract_closure_20261020 as proposed

BASE = json.loads(Path(__file__).with_name('fixtures').joinpath('azure_native_contract_closure_20261020.json').read_text())
SUB = BASE['subscription']['subscriptionId']; TENANT = BASE['subscription']['tenantId']; SCOPE = '/subscriptions/' + SUB
OTHER = '99999999-9999-9999-9999-999999999999'; USER = '55555555-5555-5555-5555-555555555555'; CLIENT = '88888888-8888-8888-8888-888888888888'
RG = SCOPE + '/resourceGroups/review'
UAI = RG + '/providers/Microsoft.ManagedIdentity/userAssignedIdentities/encryption'
REAL_TRANSPORT = azure.AzureTransport
RECEIPTS = []


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail('sockets, DNS and credential discovery are forbidden')
    for name in ('connect', 'connect_ex'):
        monkeypatch.setattr(socket.socket, name, blocked)
    for name in ('getaddrinfo', 'gethostbyname', 'gethostbyname_ex', 'create_connection'):
        monkeypatch.setattr(socket, name, blocked)
    monkeypatch.setattr(azure, 'credential_for', blocked)
    monkeypatch.setattr(azure, 'urlopen', blocked)
    # The real public engine still selects and evaluates ordinary Check objects.
    # No production registration, engine function replacement or CASES mutation.
    additions = [Check(p['id'], 'azure', p['category'], p['kind'], p['title'], p['severity'], '',
                       '\n'.join(p['remediation']), p['evaluate'], declared_dependencies=p['dependencies'])
                 for p in proposed.PROPOSALS]
    current = {c.id: c for c in checks.CHECKS}
    for c in additions:
        if c.id in current:
            assert inspect.unwrap(current[c.id].evaluate) is inspect.unwrap(c.evaluate)
            assert getattr(current[c.id].evaluate, '_native_final_admission_20261020', None) == c.id
    monkeypatch.setattr(checks, 'CHECKS', [*checks.CHECKS, *(c for c in additions if c.id not in current)])


@pytest.fixture(scope='session', autouse=True)
def receipts():
    yield
    if folder := os.environ.get('AZURE_CONTRACT_CLOSURE_RECEIPTS'):
        Path(folder).mkdir(parents=True, exist_ok=True)
        Path(folder, 'native-cases.json').write_text(json.dumps(RECEIPTS, indent=2) + '\n')


class Wire:
    def __init__(self, rows, fault=None):
        self.rows, self.fault, self.calls = rows, fault, []
        self.responses = {}
        self.suffixes = {}
        for kind, resource in rows.items():
            typ, version = ('Microsoft.Authorization/roleDefinitions','2022-04-01') if kind=='role_definition' else azure.ENDPOINTS[kind]
            self.responses[SCOPE + '/providers/' + typ] = {'value': [resource]}
            self.responses[resource['id']] = resource
            self.suffixes[kind] = (SCOPE + '/providers/' + typ, resource['id'])
        self.responses['/providers/Microsoft.Authorization/roleDefinitions']={'value':[]}
        self.responses['/providers/Microsoft.Management/managementGroups']={'value':[]}
        self.responses[SCOPE] = BASE['subscription']
        self.responses[RG] = {'id': RG, 'name': 'review', 'type': 'Microsoft.Resources/resourceGroups', 'location': 'eastus', 'properties': {}}
        self.denied = {SCOPE + '/providers/Microsoft.Authorization/locks', RG + '/providers/Microsoft.Authorization/locks'}
        # Current read-only Stream Analytics output inventory (metadata child
        # list); the reviewed job declares no outputs.
        self.child_lists = {row['id'] + '/outputs': '2020-03-01' for kind, row in rows.items() if kind == 'stream_analytics_job'}
        self.responses.update({path: {'value': []} for path in self.child_lists})
        for row in rows.values():
            rid = row['id']
            self.denied.add(rid + '/providers/Microsoft.Insights/diagnosticSettings')
            self.denied.add(rid + '/providers/Microsoft.Authorization/locks')
            for child in ('blobServices/default/containers', 'encryptionScopes', 'localUsers', 'providers/Microsoft.EventGrid/eventSubscriptions'):
                self.denied.add(rid + '/' + child)
            for service in ('blobServices', 'fileServices', 'queueServices', 'tableServices'):
                self.denied.add(rid + '/' + service + '/default')
                self.denied.add(rid + '/' + service + '/default/providers/Microsoft.Insights/diagnosticSettings')

    def open(self, request, timeout):
        u = urlsplit(request.full_url); query = parse_qs(u.query)
        assert u.scheme == 'https' and u.netloc == 'management.azure.com' and timeout == 20
        assert request.get_header('Authorization') == 'Bearer offline-contract'
        if u.path == '/providers/Microsoft.ResourceGraph/resources':
            assert request.get_method() == 'POST'
            body = json.loads(request.data)
            assert set(body) == {'subscriptions', 'query', 'options'} and body['subscriptions'] == [SUB]
            assert body['query'] in ('Resources | project id, type, name, location, tags, identity, properties, subscriptionId, resourceGroup | order by id asc',
                "resourcecontainers | where type =~ 'microsoft.resources/subscriptions' | project id, properties | order by id asc")
            assert query['api-version'] in (['2022-10-01'], ['2024-04-01'])
            self.calls.append({'method': 'POST', 'host': u.netloc, 'path': u.path, 'query': query, 'body': body})
            raise azure.AzureReadError('optional_discovery_denied', 403)
        assert request.get_method() == 'GET' and request.data is None
        self.calls.append({'method': 'GET', 'host': u.netloc, 'path': u.path, 'query': query, 'body': None})
        if u.path in self.denied:
            raise azure.AzureReadError('unrelated_metadata_denied', 403)
        if u.path not in self.responses:
            pytest.fail('Unexpected native HTTP path: ' + u.path)
        versions = {('2022-04-01' if k=='role_definition' else azure.ENDPOINTS[k.removesuffix('_alternate')][1]) for k, pair in self.suffixes.items() if u.path in pair}
        if u.path=='/providers/Microsoft.Authorization/roleDefinitions':versions={'2022-04-01'}
        if u.path=='/providers/Microsoft.Management/managementGroups':versions={'2020-05-01'}
        if u.path==SCOPE+'/providers/Microsoft.Authorization/roleDefinitions':assert query.get('$filter')==["type eq 'CustomRole'"]
        if u.path == SCOPE: versions = {'2022-12-01'}
        if u.path in self.child_lists: versions = {self.child_lists[u.path]}
        if u.path in (RG, SCOPE + '/resourceGroups/another'): versions = {'2021-04-01'}
        assert query.get('api-version', [None])[0] in versions
        value = deepcopy(self.responses[u.path])
        if self.fault:
            target_kind, action = self.fault
            listing, detail = self.suffixes[target_kind]
            if action == 'denied' and u.path == listing or action == 'detail_denied' and u.path == detail:
                raise azure.AzureReadError('selected_metadata_denied', 403)
            if u.path == listing:
                if action == 'empty': value['value'] = []
                if action == 'bad_list': value['value'] = {}
                if action == 'partial':
                    if '$skiptoken' in query: raise azure.AzureReadError('continuation_denied', 403)
                    value['nextLink'] = request.full_url + '&$skiptoken=next'
                if action == 'duplicate': value['value'].append(deepcopy(value['value'][0]))
                if action == 'ambiguous_name':
                    duplicate = deepcopy(value['value'][0]); duplicate['id'] = duplicate['id'].replace('/resourceGroups/review/', '/resourceGroups/another/')
                    value['value'].append(duplicate); self.responses[duplicate['id']] = deepcopy(duplicate)
                    self.suffixes[target_kind + '_alternate'] = (listing, duplicate['id'])
                    alt = duplicate['id']
                    group = SCOPE + '/resourceGroups/another'
                    self.responses[group] = {'id': group, 'name': 'another', 'type': 'Microsoft.Resources/resourceGroups', 'location': 'eastus', 'properties': {}}
                    self.denied.add(group + '/providers/Microsoft.Authorization/locks')
                    self.denied.update({alt + '/providers/Microsoft.Authorization/locks', alt + '/providers/Microsoft.Insights/diagnosticSettings',
                        alt + '/blobServices/default/containers', alt + '/encryptionScopes', alt + '/localUsers', alt + '/providers/Microsoft.EventGrid/eventSubscriptions'})
                    for service in ('blobServices', 'fileServices', 'queueServices', 'tableServices'):
                        self.denied.update({alt + '/' + service + '/default', alt + '/' + service + '/default/providers/Microsoft.Insights/diagnosticSettings'})
                if action == 'foreign_list': value['value'][0]['id'] = value['value'][0]['id'].replace(SUB, OTHER)
                if action == 'wrong_list_type': value['value'][0]['type'] = 'Microsoft.Unrelated/resources'
            if u.path == detail:
                if action == 'foreign_get': value['id'] = value['id'].replace(SUB, OTHER)
                if action == 'wrong_get_type': value['type'] = 'Microsoft.Unrelated/resources'
                if action == 'wrong_get_name': value['name'] = 'different'
                if action == 'bad_properties': value['properties'] = []
        response = io.BytesIO(json.dumps(value).encode())
        response.status = 200
        return response


def capture(monkeypatch, cid, branch, mutate=None, fault=None):
    rows = {kind: deepcopy(BASE[kind]) for kind in ('log_analytics_cluster', 'stream_analytics_job', 'storage_account', 'security_pricing', 'role_definition')}
    if mutate: mutate(rows)
    wire = Wire(rows, fault)
    monkeypatch.setattr(azure, 'build_opener', lambda *a: wire)
    transport = object.__new__(REAL_TRANSPORT)
    transport.tenant = transport.verified_tenant = TENANT
    transport.owned = False; transport.credential = None
    transport.token = lambda audience: 'offline-contract' if audience == azure.ARM else pytest.fail('unexpected auth audience')
    monkeypatch.setattr(azure, 'AzureTransport', lambda auth: transport)
    # azure.collect builds its scan transport through the exposure subclass.
    monkeypatch.setattr(azure, 'AzureTransportExposure', lambda auth: transport)
    snapshot = archived.collect_snapshot({'connector': {'provider': 'azure', 'scopes': [SUB], 'auth': {'tenant_id': TENANT},
        'options': {'retries': 0, 'concurrency': 1}}, 'checks': [cid]})
    arguments = []
    selected = next(c for c in checks.CHECKS if c.id == cid)
    def observe(frame, event, arg):
        if event == 'call' and frame.f_code is selected.evaluate.__code__ and 'item' in frame.f_locals and 'index' in frame.f_locals:
            arguments.append({'item': thaw(frame.f_locals['item']), 'index': thaw(frame.f_locals['index'])})
    export = os.environ.get('AZURE_CONTRACT_CLOSURE_RECEIPTS') and branch in ('good', 'microsoft_key', 'no_key', 'system_account', 'standard', 'free') or (os.environ.get('AZURE_CONTRACT_CLOSURE_RECEIPTS') and cid=='azure.claude.iam_custom_role_administers_locks' and branch.startswith('permissions-'))
    if export: sys.setprofile(observe)
    try:
        findings = archived.evaluate_snapshot(snapshot, checks=[cid])['findings']
    finally:
        if export: sys.setprofile(None)
    for pair in arguments:
        assert selected.evaluate(deepcopy(pair['item']), deepcopy(pair['index']))[0] in {f['status'] for f in findings}
    assert wire.calls
    digest = hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()
    entry = {'id': cid, 'branch': branch, 'node': os.environ.get('PYTEST_CURRENT_TEST', '').split(' (')[0],
        'native_sha256': digest, 'fault': fault, 'requests': wire.calls,
        'statuses': sorted({f['status'] for f in findings}), 'findings': findings, 'evaluator_arguments': arguments}
    if folder := os.environ.get('AZURE_CONTRACT_CLOSURE_RECEIPTS'):
        Path(folder).mkdir(parents=True, exist_ok=True)
        p = Path(folder, cid + '.' + branch + '.' + digest[:12] + '.json')
        p.write_text(json.dumps(snapshot, separators=(',', ':')) + '\n'); entry['snapshot'] = str(p)
    RECEIPTS.append(entry)
    return snapshot, findings


def states(findings): return {f['status'] for f in findings}


def mutate_cluster(case):
    def change(rows):
        row = rows['log_analytics_cluster']; p = row['properties']; identity = row['identity']; key = p['keyVaultProperties']
        if case == 'no_key': p['keyVaultProperties'] = {}
        elif case == 'omitted_key': p.pop('keyVaultProperties')
        elif case == 'no_identity': row['identity'] = None
        elif case == 'disabled_identity': row['identity'] = {'type': 'None'}
        elif case == 'missing_principal': identity.pop('principalId')
        elif case == 'nil_principal': identity['principalId'] = '00000000-0000-0000-0000-000000000000'
        elif case == 'foreign_tenant': identity['tenantId'] = OTHER
        elif case == 'bad_uri': key['keyVaultUri'] = 'https://unrelated.example/keys/key'
        elif case == 'bad_key': key['keyName'] = ''
        elif case == 'bad_version': key['keyVersion'] = '../another'
        elif case == 'null_version': key['keyVersion'] = None
        elif case == 'short_version': key['keyVersion'] = 'abc'
        elif case == 'double_hyphen_vault': key['keyVaultUri'] = 'https://review--vault.vault.azure.net'
        elif case == 'uri_query': key['keyVaultUri'] = 'https://reviewvault.vault.azure.net?key=other'
        elif case == 'omitted_version': key.pop('keyVersion')
        elif case == 'uppercase_vault': key['keyVaultUri'] = 'https://REVIEWVAULT.vault.azure.net/'
        elif case == 'hsm_reference': key['keyVaultUri'] = 'https://reviewhsm.managedhsm.azure.net'
        elif case == 'pending': p['provisioningState'] = 'Updating'
        elif case.startswith('user_') or case == 'combined_identity':
            row['identity'] = {'type': 'UserAssigned', 'userAssignedIdentities': {UAI: {'principalId': USER, 'clientId': CLIENT}}}
            if case == 'user_ambiguous': row['identity']['userAssignedIdentities'][UAI + '2'] = {'principalId': CLIENT}
            if case == 'user_foreign_kind': row['identity']['userAssignedIdentities'] = {UAI.replace('Microsoft.ManagedIdentity/userAssignedIdentities', 'Microsoft.Unrelated/resources'): {'principalId': USER}}
            if case == 'user_duplicate_case': row['identity']['userAssignedIdentities'][UAI.upper()] = {'principalId': CLIENT}
            if case == 'combined_identity': row['identity'].update(type='SystemAssigned,UserAssigned', principalId=BASE['log_analytics_cluster']['identity']['principalId'], tenantId=TENANT)
    return change


@pytest.mark.parametrize('case,expected', [
    ('good', 'PASS'), ('no_key', 'FAIL'), ('omitted_key', 'FAIL'), ('no_identity', 'FAIL'), ('disabled_identity', 'FAIL'),
    ('missing_principal', 'UNKNOWN'), ('nil_principal', 'UNKNOWN'), ('foreign_tenant', 'UNKNOWN'),
    ('bad_uri', 'UNKNOWN'), ('bad_key', 'UNKNOWN'), ('bad_version', 'UNKNOWN'), ('null_version', 'UNKNOWN'),
    ('short_version', 'UNKNOWN'), ('double_hyphen_vault', 'UNKNOWN'), ('uri_query', 'UNKNOWN'),
    ('omitted_version', 'PASS'), ('uppercase_vault', 'PASS'), ('hsm_reference', 'PASS'), ('pending', 'UNKNOWN'),
    ('user_good', 'PASS'), ('user_ambiguous', 'UNKNOWN'), ('user_foreign_kind', 'UNKNOWN'),
    ('user_duplicate_case', 'UNKNOWN'), ('combined_identity', 'UNKNOWN')])
def test_cluster_native_configuration(monkeypatch, case, expected):
    _, findings = capture(monkeypatch, proposed.CLUSTER, case, mutate_cluster(case))
    assert states(findings) == {expected}, findings


def mutate_stream(case):
    def change(rows):
        p = rows['stream_analytics_job']['properties']; account = rows['storage_account']; enc = account['properties']['encryption']
        if case == 'microsoft_key': enc['keySource'] = 'Microsoft.Storage'
        elif case == 'omitted_source_default': enc.pop('keySource')
        elif case == 'uppercase_source': enc['keySource'] = 'MICROSOFT.KEYVAULT'
        elif case == 'unknown_source': enc['keySource'] = 'CustomUnknown'
        elif case == 'system_account': p['contentStoragePolicy'] = 'SystemAccount'; p.pop('jobStorageAccount')
        elif case == 'omitted_policy': p.pop('contentStoragePolicy')
        elif case == 'unknown_policy': p['contentStoragePolicy'] = 'Unknown'
        elif case == 'omitted_storage': p.pop('jobStorageAccount')
        elif case == 'invalid_name': p['jobStorageAccount']['accountName'] = 'invalid/account'
        elif case == 'unresolved_account': p['jobStorageAccount']['accountName'] = 'notcaptured123'
        elif case == 'unknown_auth_mode': p['jobStorageAccount']['authenticationMode'] = 'Unsupported'
        elif case == 'omitted_auth_default': p['jobStorageAccount'].pop('authenticationMode')
        elif case == 'edge_job': p['jobType'] = 'Edge'
        elif case == 'job_pending': p['provisioningState'] = 'Updating'
        elif case == 'storage_pending': account['properties']['provisioningState'] = 'Updating'
        elif case == 'missing_encryption': account['properties'].pop('encryption')
        elif case == 'sdk_camel_shape':
            enc['keyVaultProperties'] = enc.pop('keyvaultproperties')
        elif case == 'missing_key': enc['keyvaultproperties'].pop('keyname')
        elif case == 'user_selected' or case == 'user_unassigned' or case == 'user_cross_subscription' or case == 'user_no_selection':
            rid = UAI.replace(SUB, OTHER) if case == 'user_cross_subscription' else UAI
            account['identity'] = {'type': 'UserAssigned', 'userAssignedIdentities': {rid: {'principalId': USER, 'clientId': CLIENT}}}
            enc['identity'] = {'userAssignedIdentity': rid + 'other' if case == 'user_unassigned' else rid}
            if case == 'user_no_selection': enc.pop('identity')
        elif case == 'mixed_user_selected':
            account['identity'].update(type='SystemAssigned, UserAssigned', userAssignedIdentities={UAI: {'principalId': USER, 'clientId': CLIENT}})
            enc['identity'] = {'userAssignedIdentity': UAI}
        elif case == 'cross_tenant_federation': enc['identity'] = {'userAssignedIdentity': UAI, 'federatedIdentityClientId': CLIENT}
        elif case == 'foreign_identity_tenant': account['identity']['tenantId'] = OTHER
        elif case == 'missing_system_principal': account['identity'].pop('principalId')
    return change


@pytest.mark.parametrize('case,expected', [
    ('good', 'PASS'), ('microsoft_key', 'FAIL'), ('omitted_source_default', 'FAIL'), ('uppercase_source', 'PASS'),
    ('unknown_source', 'UNKNOWN'), ('system_account', 'NOT_APPLICABLE'), ('omitted_policy', 'UNKNOWN'),
    ('unknown_policy', 'UNKNOWN'), ('omitted_storage', 'UNKNOWN'), ('invalid_name', 'UNKNOWN'),
    ('unresolved_account', 'UNKNOWN'), ('unknown_auth_mode', 'UNKNOWN'), ('omitted_auth_default', 'PASS'),
    ('edge_job', 'UNKNOWN'), ('job_pending', 'UNKNOWN'), ('storage_pending', 'UNKNOWN'),
    ('missing_encryption', 'UNKNOWN'), ('sdk_camel_shape', 'UNKNOWN'), ('missing_key', 'UNKNOWN'),
    ('user_selected', 'PASS'), ('user_unassigned', 'UNKNOWN'), ('user_cross_subscription', 'PASS'),
    ('user_no_selection', 'UNKNOWN'), ('mixed_user_selected', 'PASS'), ('cross_tenant_federation', 'UNKNOWN'),
    ('foreign_identity_tenant', 'UNKNOWN'), ('missing_system_principal', 'UNKNOWN')])
def test_stream_job_native_configuration(monkeypatch, case, expected):
    _, findings = capture(monkeypatch, proposed.STREAM, case, mutate_stream(case))
    assert states(findings) == {expected}, findings


@pytest.mark.parametrize('cid,kind', [(proposed.CLUSTER, 'log_analytics_cluster'),
    (proposed.STREAM, 'stream_analytics_job'), (proposed.STREAM, 'storage_account')])
@pytest.mark.parametrize('fault', ['denied', 'detail_denied', 'empty', 'bad_list', 'partial',
    'foreign_list', 'wrong_list_type', 'foreign_get', 'wrong_get_type', 'wrong_get_name', 'bad_properties'])
def test_native_collection_boundaries(monkeypatch, cid, kind, fault):
    _, findings = capture(monkeypatch, cid, kind + '-' + fault, fault=(kind, fault))
    status = states(findings)
    if fault == 'empty' and kind != 'storage_account': assert status == {'EMPTY'}, findings
    else: assert status <= {'DENIED', 'UNKNOWN'}, findings


def test_builtin_storage_does_not_require_an_external_account(monkeypatch):
    _, findings = capture(monkeypatch, proposed.STREAM, 'system-storage-account-denied',
        mutate_stream('system_account'), ('storage_account', 'denied'))
    assert states(findings) == {'NOT_APPLICABLE'}, findings


def test_ambiguous_native_storage_names_do_not_select_a_match(monkeypatch):
    _, findings = capture(monkeypatch, proposed.STREAM, 'ambiguous-native-storage', fault=('storage_account', 'ambiguous_name'))
    assert states(findings) == {'UNKNOWN'}, findings


def test_no_content_or_key_material_is_persisted(monkeypatch):
    def mutate(rows):
        p = rows['stream_analytics_job']['properties']
        p['jobStorageAccount']['accountKey'] = 'discarded-fixture-content'
        p['transformation'] = {'properties': {'query': 'discarded-fixture-content'}}
        p['inputs'] = [{'properties': {'datasource': {'properties': {'connectionString': 'discarded-fixture-content'}}}}]
    snapshot, findings = capture(monkeypatch, proposed.STREAM, 'metadata-projection', mutate)
    assert states(findings) == {'PASS'}, findings
    assert 'discarded-fixture-content' not in json.dumps(snapshot)
    assert not any('listKeys' in call['path'] or '/keys/' in call['path'] for call in RECEIPTS[-1]['requests'])


def test_proposal_module_does_not_register_or_invent_requirement_edges():
    import importlib.util
    before = tuple(checks.CHECKS)
    spec = importlib.util.spec_from_file_location('peaso.checks._contract_closure_inert_import', proposed.__file__)
    probe = importlib.util.module_from_spec(spec); spec.loader.exec_module(probe)
    assert tuple(checks.CHECKS) == before
    assert {p['id'] for p in probe.PROPOSALS} == {p['id'] for p in proposed.PROPOSALS}
    assert all(p['category'] == 'encryption' and not p.get('control') and not p.get('framework_ids') for p in proposed.PROPOSALS)


@pytest.mark.parametrize('branch,expected', [('standard','PASS'),('free','FAIL'),('omitted_tier','UNKNOWN'),
    ('unknown_tier','UNKNOWN'),('denied','DENIED'),('empty','UNKNOWN'),('partial','UNKNOWN'),
    ('foreign_get','UNKNOWN'),('wrong_get_type','UNKNOWN')])
def test_existing_cloudposture_is_configuration_only(monkeypatch,branch,expected):
    def mutate(rows):
        p=rows['security_pricing']['properties']
        if branch=='free':p['pricingTier']='Free'
        elif branch=='omitted_tier':p.pop('pricingTier')
        elif branch=='unknown_tier':p['pricingTier']='Unknown'
    fault=('security_pricing',branch) if branch in ('denied','empty','partial','foreign_get','wrong_get_type') else None
    _,findings=capture(monkeypatch,'azure.port.security_center_defender_for_cloudposture_enabled',branch,mutate,fault)
    assert states(findings)=={expected},findings
    if expected=='PASS':assert findings[0]['evidence'].get('pricing_tier')=='Standard'


@pytest.mark.parametrize('permissions,expected',[
 ([{'actions':['Microsoft.Authorization/locks/read'],'notActions':[]}],'FAIL'),
 ([{'actions':['Microsoft.Authorization/locks/*'],'notActions':['Microsoft.Authorization/locks/*']}],'FAIL'),
 ([{'actions':['Microsoft.Authorization/locks/write','Microsoft.Authorization/locks/delete'],'notActions':[]}],'PASS'),
 ([{'actions':['microsoft.authorization/locks/*'],'notActions':[]}],'PASS'),
 ([{'actions':['Microsoft.Authorization/*'],'notActions':[]}],'PASS'),
 ([{'actions':['*'],'notActions':['MICROSOFT.AUTHORIZATION/LOCKS/DELETE']}],'FAIL'),
 ([{'actions':['Microsoft.Authorization/locks/*'],'notActions':['Microsoft.Authorization/locks/delete']},
  {'actions':['Microsoft.Authorization/locks/delete'],'notActions':[]}],'PASS'),
 ([{'actions':['Microsoft.Authorization/locks/write'],'notActions':[]},
  {'actions':['Microsoft.Authorization/locks/delete'],'notActions':[]}],'PASS'),
 ([{'actions':['Microsoft.Authorization/locks/rea?'],'notActions':[]}],'UNKNOWN'),
 ([{'actions':['Microsoft.Authorization/locks/[wd]*'],'notActions':[]}],'UNKNOWN'),
 ([{'actions':None,'notActions':[]}],'UNKNOWN'),
 ([{'actions':['Microsoft.Authorization/locks/*']}],'UNKNOWN'),
 ([{'actions':['Microsoft.Authorization/locks/*'],'notActions':[42]}],'UNKNOWN'),
 ([{'actions':[],'notActions':[],'dataActions':['Microsoft.Authorization/locks/write','Microsoft.Authorization/locks/delete']}],'FAIL'),
])
def test_lock_administration_native_permission_algebra(monkeypatch,permissions,expected):
    def mutate(rows):rows['role_definition']['properties']['permissions']=deepcopy(permissions)
    _,findings=capture(monkeypatch,'azure.claude.iam_custom_role_administers_locks','permissions-'+hashlib.sha256(str(permissions).encode()).hexdigest()[:10],mutate)
    assert states(findings)=={expected},findings

@pytest.mark.parametrize('fault',['denied','partial','foreign_list','wrong_list_type','bad_list','empty'])
def test_lock_native_scope_and_collection(monkeypatch,fault):
    _,findings=capture(monkeypatch,'azure.claude.iam_custom_role_administers_locks','lock-'+fault,fault=('role_definition',fault))
    if fault=='empty':assert states(findings)=={'FAIL'},findings
    elif fault=='foreign_list':assert states(findings)=={'PASS'},findings # a cross-home CustomRole can explicitly apply here
    else:assert states(findings)<={'UNKNOWN','DENIED'},findings


def test_lock_native_foreign_assignable_scope_is_unresolved(monkeypatch):
    def mutate(rows):rows['role_definition']['properties']['assignableScopes']=[SCOPE.replace(SUB,OTHER)]
    _,findings=capture(monkeypatch,'azure.claude.iam_custom_role_administers_locks','foreign-assignable-scope',mutate)
    assert states(findings)=={'UNKNOWN'},findings
