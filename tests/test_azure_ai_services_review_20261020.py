"""Independent native ARM responses -> Azure collector -> registered engine.

No fixture/CASES input, customer policy, mocked evaluator, network or credentials.
"""
from copy import deepcopy
import json
from pathlib import Path
import socket
from urllib.parse import urlsplit, parse_qs
import pytest
from peaso.collectors import azure
from peaso.collectors import azure_ai_services_native as native
from peaso.checks import azure_ai_services_review_20261020 as checks
from peaso import engine

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
OTHER = '/subscriptions/33333333-3333-3333-3333-333333333333'
ACCOUNT = SCOPE + '/resourceGroups/review/providers/Microsoft.CognitiveServices/accounts/review-ai'
ACCOUNT2 = ACCOUNT + '-two'
WORKSPACE = SCOPE + '/resourceGroups/review/providers/Microsoft.OperationalInsights/workspaces/audit'
DEPLOYMENT = ACCOUNT + '/deployments/chat'
POLICY = ACCOUNT + '/raiPolicies/explicit-shield'
CANARY = 'inert-sensitive-field-must-never-be-retained'


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail('socket/DNS/auth discovery forbidden')
    for attr in ('connect', 'connect_ex'):
        monkeypatch.setattr(socket.socket, attr, blocked)
    for attr in ('create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex'):
        monkeypatch.setattr(socket, attr, blocked)
    monkeypatch.setattr(azure, 'credential_for', blocked)
    monkeypatch.setattr(azure.AzureTransport, '__init__', blocked)
    monkeypatch.setattr(azure, 'urlopen', blocked)
    monkeypatch.setattr(azure.time, 'sleep', lambda seconds: None)


def account():
    return {'id': ACCOUNT, 'name': 'review-ai', 'type': native.TYPE, 'kind': 'OpenAI',
        'identity': {'type': 'SystemAssigned', 'principalId': '22222222-2222-2222-2222-222222222222', 'tenantId': '44444444-4444-4444-4444-444444444444'},
        'properties': {'provisioningState': 'Succeeded', 'restrictOutboundNetworkAccess': True,
            'allowedFqdnList': ['required.example.test'], 'disableLocalAuth': True, 'publicNetworkAccess': 'Disabled',
            'capabilities': [{'name': 'VirtualNetworks'}, {'name': 'CustomerManagedKey'}],
            'networkAcls': {'defaultAction': 'Deny'}, 'encryption': {'keySource': 'Microsoft.KeyVault'},
            'privateEndpointConnections': [{'id': ACCOUNT + '/privateEndpointConnections/approved',
                'properties': {'privateLinkServiceConnectionState': {'status': 'Approved'}}}],
            'apiProperties': {'storageAccountConnectionString': CANARY}}}


def child(path, name, properties):
    return {'id': ACCOUNT + '/' + path + '/' + name, 'name': name,
        'type': (native.TYPE + '/' + path if not path.startswith('providers/') else path[len('providers/'):]), 'properties': properties}


def pages():
    return {
        SCOPE + '/providers/' + native.TYPE: {'value': [{'id': ACCOUNT, 'name': 'review-ai', 'type': native.TYPE}]},
        ACCOUNT: account(),
        ACCOUNT + '/providers/Microsoft.Insights/diagnosticSettings': {'value': [child('providers/Microsoft.Insights/diagnosticSettings', 'audit-export', {
            'logs': [{'category': 'Audit', 'enabled': True}], 'workspaceId': WORKSPACE})]},
        ACCOUNT + '/providers/Microsoft.Insights/diagnosticSettingsCategories': {'value': [child('providers/Microsoft.Insights/diagnosticSettingsCategories', 'Audit', {
            'categoryType': 'Logs', 'categoryGroups': ['audit', 'allLogs']})]},
        ACCOUNT + '/deployments': {'value': [child('deployments', 'chat', {'provisioningState': 'Succeeded', 'capabilities': {'chatCompletion': 'true'}, 'raiPolicyName': 'explicit-shield'})]},
        ACCOUNT + '/raiPolicies': {'value': [child('raiPolicies', 'explicit-shield', {'contentFilters': [{'name': 'Jailbreak', 'source': 'Prompt', 'enabled': True, 'blocking': True}]})]},
        ACCOUNT + '/privateEndpointConnections': {'value': []},
    }


class NativeAPI:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []
    def request(self, url, *, body=None, audience=azure.ARM):
        parsed = urlsplit(url)
        method = 'POST' if body is not None else 'GET'
        assert method == 'GET' and body is None
        assert audience == azure.ARM and parsed.scheme == 'https' and parsed.hostname == 'management.azure.com'
        assert parsed.port is None and not parsed.fragment and not parsed.username and not parsed.password
        assert parsed.path in self.responses, (parsed.path, self.responses.keys())
        query = parse_qs(parsed.query)
        assert query['api-version'] == [native.MONITOR_VERSION if '/Microsoft.Insights/' in parsed.path else native.VERSION]
        assert set(query) <= {'api-version', '$skiptoken'}
        self.calls.append((method, parsed.hostname, parsed.path, query))
        value = self.responses[(parsed.path, query['$skiptoken'][0])] if '$skiptoken' in query else self.responses[parsed.path]
        if isinstance(value, BaseException):
            raise value
        return deepcopy(value)


def capture(name, responses=None, **options):
    api = NativeAPI(pages() if responses is None else responses)
    snapshot = azure.collect({'scopes': [SCOPE], 'auth': {}, 'options': {'retries': 0, 'concurrency': 1, **options}},
        [native.KINDS[name]], transport=api)
    findings = engine.evaluate_snapshot(snapshot, checks=[checks.PREFIX + name])['findings']
    return snapshot, findings, api


def outcome(name, responses=None, **options):
    snapshot, findings, api = capture(name, responses, **options)
    assert findings, (name, snapshot)
    assert CANARY not in json.dumps([snapshot, findings])
    return {f['status'] for f in findings}


@pytest.mark.parametrize('name', list(native.KINDS))
def test_native_supported_positive(name):
    snapshot, findings, api = capture(name)
    assert {f['status'] for f in findings} == {'PASS'}, findings
    assert len(api.calls) == (4 if name in ('audit_logging', 'prompt_shield') else 2)
    assert CANARY not in json.dumps([snapshot, findings])


@pytest.mark.parametrize('name', list(native.KINDS))
@pytest.mark.parametrize('where', ['inventory', 'account'])
@pytest.mark.parametrize('status', [403, 429])
def test_native_denied_and_unavailable(name, where, status):
    data = pages(); data[SCOPE + '/providers/' + native.TYPE if where == 'inventory' else ACCOUNT] = azure.AzureReadError('permission_denied' if status == 403 else 'throttled', status)
    assert outcome(name, data) == ({'DENIED'} if status == 403 else {'UNKNOWN'})


@pytest.mark.parametrize('name', list(native.KINDS))
@pytest.mark.parametrize('mutate', ['foreign_inventory', 'foreign_get', 'wrong_type', 'wrong_name', 'duplicate', 'not_ready', 'missing_properties'])
def test_native_identity_and_account_completeness(name, mutate):
    data = pages()
    if mutate == 'foreign_inventory': data[SCOPE + '/providers/' + native.TYPE]['value'][0]['id'] = ACCOUNT.replace(SCOPE, OTHER)
    if mutate == 'foreign_get': data[ACCOUNT]['id'] = ACCOUNT.replace(SCOPE, OTHER)
    if mutate == 'wrong_type': data[ACCOUNT]['type'] = 'Microsoft.Storage/storageAccounts'
    if mutate == 'wrong_name': data[ACCOUNT]['name'] = 'foreign'
    if mutate == 'duplicate': data[SCOPE + '/providers/' + native.TYPE]['value'] *= 2
    if mutate == 'not_ready': data[ACCOUNT]['properties']['provisioningState'] = 'Creating'
    if mutate == 'missing_properties': data[ACCOUNT].pop('properties')
    assert outcome(name, data) == {'UNKNOWN'}


@pytest.mark.parametrize('name', list(native.KINDS))
def test_native_partial_inventory_retains_explicit_coverage_gap(name):
    data = pages(); path = SCOPE + '/providers/' + native.TYPE
    data[path]['nextLink'] = azure.ARM + path + '?api-version=' + native.VERSION + '&$skiptoken=next'
    data[(path, 'next')] = azure.AzureReadError('permission_denied', 403)
    assert outcome(name, data) == {'PASS', 'UNKNOWN'}


@pytest.mark.parametrize('name', list(native.KINDS))
def test_native_empty_inventory(name):
    data = pages(); data[SCOPE + '/providers/' + native.TYPE] = {'value': []}
    snapshot, findings, _ = capture(name, data)
    assert {f['status'] for f in findings} == {'EMPTY'}, findings


@pytest.mark.parametrize('mode,expected', [('None','FAIL'), ('SystemAssigned','PASS'), ('UserAssigned','PASS'), ('SystemAssigned, UserAssigned','PASS'), ('Anything','UNKNOWN'), (None,'UNKNOWN'), (1,'UNKNOWN')])
def test_native_identity_enum(mode, expected):
    data = pages(); data[ACCOUNT]['identity']['type'] = mode
    assert outcome('managed_identity', data) == {expected}


@pytest.mark.parametrize('value,expected', [('omitted','FAIL'), (None,'FAIL'), ({},'UNKNOWN'), ('SystemAssigned','UNKNOWN')])
def test_native_identity_optional_block(value, expected):
    data = pages()
    if value == 'omitted': data[ACCOUNT].pop('identity')
    else: data[ACCOUNT]['identity'] = value
    assert outcome('managed_identity', data) == {expected}


@pytest.mark.parametrize('value,expected', [(True,'PASS'), (False,'FAIL'), (None,'UNKNOWN'), ('true','UNKNOWN'), (1,'UNKNOWN'), ('omitted','UNKNOWN')])
def test_native_outbound_boolean(value, expected):
    data = pages()
    if value == 'omitted': data[ACCOUNT]['properties'].pop('restrictOutboundNetworkAccess')
    else: data[ACCOUNT]['properties']['restrictOutboundNetworkAccess'] = value
    assert outcome('outbound_restriction', data) == {expected}


@pytest.mark.parametrize('field', ['diagnosticSettings','diagnosticSettingsCategories','deployments','raiPolicies'])
@pytest.mark.parametrize('mutation', ['denied','foreign_account','foreign_subscription','wrong_type','wrong_name','duplicate','partial','omitted_value','foreign_next'])
def test_native_children_are_complete_and_bound(field, mutation):
    name = 'audit_logging' if field.startswith('diagnostic') else 'prompt_shield'
    path = ACCOUNT + ('/providers/Microsoft.Insights/' if field.startswith('diagnostic') else '/') + field
    data = pages(); value = data[path]
    if mutation == 'denied': data[path] = azure.AzureReadError('permission_denied', 403)
    if mutation in ('foreign_account','foreign_subscription'):
        value['value'][0]['id'] = value['value'][0]['id'].replace(ACCOUNT, ACCOUNT2 if mutation == 'foreign_account' else ACCOUNT.replace(SCOPE,OTHER))
    if mutation == 'wrong_type': value['value'][0]['type'] = 'Microsoft.Other/resources'
    if mutation == 'wrong_name': value['value'][0]['name'] = 'other'
    if mutation == 'duplicate': value['value'] *= 2
    if mutation == 'partial':
        value['nextLink'] = azure.ARM + path + '?api-version=' + (native.MONITOR_VERSION if field.startswith('diagnostic') else native.VERSION) + '&$skiptoken=next'
        data[(path,'next')] = azure.AzureReadError('permission_denied',403)
    if mutation == 'omitted_value': value.pop('value')
    if mutation == 'foreign_next': value['nextLink'] = 'https://untrusted.example.test' + path
    assert outcome(name, data) == {'UNKNOWN'}


@pytest.mark.parametrize('mutation,expected', [('empty_settings','FAIL'),('disabled','FAIL'),('other_category','FAIL'),('alllogs','PASS'),('audit_group','PASS'),('no_sink','FAIL'),('bad_sink','UNKNOWN'),('bad_enabled','UNKNOWN'),('empty_categories','UNKNOWN'),('group_unavailable','FAIL'),('both_selectors','UNKNOWN'),('metrics_only','FAIL')])
def test_native_audit_log_contract(mutation, expected):
    data = pages(); props = data[ACCOUNT + '/providers/Microsoft.Insights/diagnosticSettings']['value'][0]['properties']; log = props['logs'][0]
    if mutation == 'empty_settings': data[ACCOUNT + '/providers/Microsoft.Insights/diagnosticSettings']['value'] = []
    if mutation == 'disabled': log['enabled'] = False
    if mutation == 'other_category': log['category'] = 'RequestResponse'
    if mutation in ('alllogs','audit_group'):
        log.pop('category'); log['categoryGroup'] = 'allLogs' if mutation == 'alllogs' else 'audit'
    if mutation == 'no_sink': props.pop('workspaceId')
    if mutation == 'bad_sink': props['workspaceId'] = 'https://example.test/'
    if mutation == 'bad_enabled': log['enabled'] = 'true'
    if mutation == 'empty_categories': data[ACCOUNT + '/providers/Microsoft.Insights/diagnosticSettingsCategories']['value'] = []
    if mutation == 'group_unavailable': log.pop('category'); log['categoryGroup'] = 'security'
    if mutation == 'both_selectors': log['categoryGroup'] = 'allLogs'
    if mutation == 'metrics_only': props['logs'] = []; props['metrics'] = [{'category':'AllMetrics','enabled':True}]
    assert outcome('audit_logging', data) == {expected}


@pytest.mark.parametrize('mutation,expected', [('disabled','FAIL'),('not_blocking','FAIL'),('completion_only','FAIL'),('no_jailbreak','FAIL'),('empty_filters','FAIL'),('missing_filters','UNKNOWN'),('bad_enabled','UNKNOWN'),('bad_blocking','UNKNOWN'),('duplicate_filter','UNKNOWN'),('default_omitted','UNKNOWN'),('default_empty','UNKNOWN'),('missing_policy','UNKNOWN'),('policy_case','PASS'),('bad_reference','UNKNOWN'),('empty_policies','UNKNOWN'),('empty_deployments','NOT_APPLICABLE'),('embedding','NOT_APPLICABLE'),('image','NOT_APPLICABLE'),('mixed_text','PASS'),('unknown_capability','UNKNOWN'),('omitted_capabilities','UNKNOWN'),('bool_capability','UNKNOWN'),('not_ready','UNKNOWN'),('mixed_unknown_nontext','UNKNOWN')])
def test_native_prompt_shield_contract(mutation, expected):
    data = pages(); dep = data[ACCOUNT + '/deployments']['value'][0]['properties']; policy = data[ACCOUNT + '/raiPolicies']['value'][0]['properties']; filt = policy['contentFilters'][0]
    if mutation == 'disabled': filt['enabled'] = False
    if mutation == 'not_blocking': filt['blocking'] = False
    if mutation == 'completion_only': filt['source'] = 'Completion'
    if mutation == 'no_jailbreak': filt['name'] = 'Hate'
    if mutation == 'empty_filters': policy['contentFilters'] = []
    if mutation == 'missing_filters': policy.pop('contentFilters')
    if mutation == 'bad_enabled': filt['enabled'] = 'true'
    if mutation == 'bad_blocking': filt['blocking'] = 1
    if mutation == 'duplicate_filter': policy['contentFilters'] *= 2
    if mutation == 'default_omitted': dep.pop('raiPolicyName')
    if mutation == 'default_empty': dep['raiPolicyName'] = ''
    if mutation == 'missing_policy': dep['raiPolicyName'] = 'Microsoft.Default'
    if mutation == 'policy_case': dep['raiPolicyName'] = 'EXPLICIT-SHIELD'
    if mutation == 'bad_reference': dep['raiPolicyName'] = POLICY
    if mutation == 'empty_policies': data[ACCOUNT + '/raiPolicies']['value'] = []
    if mutation == 'empty_deployments': data[ACCOUNT + '/deployments']['value'] = []
    if mutation == 'embedding': dep['capabilities'] = {'embeddings':'true'}
    if mutation == 'image': dep['capabilities'] = {'imageGenerations':'true'}
    if mutation == 'mixed_text': dep['capabilities'] = {'embeddings':'true','chatCompletion':'true'}
    if mutation == 'unknown_capability': dep['capabilities'] = {'newModel':'true'}
    if mutation == 'omitted_capabilities': dep.pop('capabilities')
    if mutation == 'bool_capability': dep['capabilities'] = {'chatCompletion':True}
    if mutation == 'not_ready': dep['provisioningState'] = 'Failed'
    if mutation == 'mixed_unknown_nontext': dep['capabilities'] = {'embeddings':'true','newModel':'true'}
    assert outcome('prompt_shield', data) == {expected}


@pytest.mark.parametrize('name', list(native.KINDS))
def test_native_inventory_second_page(name):
    data = pages(); path = SCOPE + '/providers/' + native.TYPE
    data[path] = {'value': [], 'nextLink': azure.ARM + path + '?api-version=' + native.VERSION + '&$skiptoken=next'}
    data[(path,'next')] = {'value':[{'id':ACCOUNT, 'name':'review-ai','type':native.TYPE}]}
    assert outcome(name, data) == {'PASS'}


@pytest.mark.parametrize('field', ['diagnosticSettings','diagnosticSettingsCategories','deployments','raiPolicies'])
def test_native_child_second_page(field):
    name = 'audit_logging' if field.startswith('diagnostic') else 'prompt_shield'
    data = pages(); path = ACCOUNT + ('/providers/Microsoft.Insights/' if field.startswith('diagnostic') else '/') + field
    actual = deepcopy(data[path]); version = native.MONITOR_VERSION if field.startswith('diagnostic') else native.VERSION
    data[path] = {'value': [], 'nextLink': azure.ARM + path + '?api-version=' + version + '&$skiptoken=next'}
    data[(path,'next')] = actual
    assert outcome(name, data) == {'PASS'}

EXISTING = {
    'local_auth_disabled': 'cognitive_service_local_auth_disabled',
    'public_disabled': 'cognitive_account_public_network_access_disabled',
    'acl_deny': 'cognitive_account_restrict_public_access',
    'cmk': 'cognitive_account_encrypted_with_cmk',
    'private_endpoint': 'cognitive_account_private_link_used',
}


def existing_outcome(name, data=None):
    api = NativeAPI(pages() if data is None else data)
    snapshot = azure.collect({'scopes':[SCOPE], 'options':{'retries':0, 'concurrency':1}}, ['cognitive_account'], transport=api)
    cid = 'azure.port.' + EXISTING[name]
    findings = engine.evaluate_snapshot(snapshot, checks=[cid])['findings']
    assert findings
    assert CANARY not in json.dumps([snapshot,findings])
    return {f['status'] for f in findings}


@pytest.mark.parametrize('name', list(EXISTING))
@pytest.mark.parametrize('branch', ['pass', 'fail', 'omitted', 'denied', 'foreign'])
def test_existing_five_native_contracts(name, branch):
    data = pages(); props = data[ACCOUNT]['properties']
    if branch == 'fail':
        if name == 'local_auth_disabled': props['disableLocalAuth'] = False
        if name == 'public_disabled': props['publicNetworkAccess'] = 'Enabled'
        if name == 'acl_deny': props['networkAcls']['defaultAction'] = 'Allow'
        if name == 'cmk': props['encryption']['keySource'] = 'Microsoft.CognitiveServices'
        if name == 'private_endpoint': props['privateEndpointConnections'][0]['properties']['privateLinkServiceConnectionState']['status'] = 'Pending'
    if branch == 'omitted':
        props.pop({'local_auth_disabled':'disableLocalAuth','public_disabled':'publicNetworkAccess','acl_deny':'networkAcls','cmk':'encryption','private_endpoint':'privateEndpointConnections'}[name])
    if branch == 'denied': data[SCOPE + '/providers/' + native.TYPE] = azure.AzureReadError('permission_denied',403)
    if branch == 'foreign': data[SCOPE + '/providers/' + native.TYPE]['value'][0]['id'] = ACCOUNT.replace(SCOPE,OTHER)
    expected = {'pass':'PASS','fail':'FAIL','omitted':'UNKNOWN','denied':'DENIED','foreign':'UNKNOWN'}[branch]
    assert existing_outcome(name,data) == {expected}


@pytest.mark.parametrize('name,branch,expected', [('cmk','capability_absent','PASS'),('acl_deny','capability_absent','PASS'),
    ('private_endpoint','capability_absent','FAIL'),('private_endpoint','no_connections','MANUAL'),
    ('acl_deny','public_disabled_acl_allow','FAIL')])
def test_existing_semantic_differences_are_explicit(name,branch,expected):
    data = pages(); props=data[ACCOUNT]['properties']
    if branch=='capability_absent':
        props['capabilities']=[]
        props['encryption']['keySource']='Microsoft.CognitiveServices'
        props['networkAcls']['defaultAction']='Allow'
    if branch=='no_connections': props['privateEndpointConnections']=[]
    if branch=='public_disabled_acl_allow': props['networkAcls']['defaultAction']='Allow'
    assert existing_outcome(name,data)=={expected}


@pytest.mark.parametrize('branch,expected', [('negative','FAIL'),('default','UNKNOWN'),('nontext','PASS')])
def test_native_multiple_deployments_account_aggregation(branch,expected):
    data=pages(); second=child('deployments','second',{'provisioningState':'Succeeded','capabilities':{'chatCompletion':'true'},'raiPolicyName':'explicit-shield'})
    if branch=='negative':
        second['properties']['raiPolicyName']='disabled'
        data[ACCOUNT+'/raiPolicies']['value'].append(child('raiPolicies','disabled',{'contentFilters':[{'name':'Jailbreak','source':'Prompt','enabled':False,'blocking':True}]}))
    if branch=='default':second['properties'].pop('raiPolicyName')
    if branch=='nontext':second['properties']['capabilities']={'embeddings':'true'}
    data[ACCOUNT+'/deployments']['value'].append(second)
    assert outcome('prompt_shield',data)=={expected}


def test_native_four_controls_share_account_get_without_hidden_calls():
    api=NativeAPI(pages());snapshot=azure.collect({'scopes':[SCOPE],'options':{'retries':0,'concurrency':1}},list(native.NATIVE_TYPES),transport=api)
    findings=engine.evaluate_snapshot(snapshot,checks=checks.CHECK_IDS)['findings']
    assert len(findings)==4 and {f['status'] for f in findings}=={'PASS'}
    assert len(api.calls)==6
    assert {c[2] for c in api.calls}=={SCOPE+'/providers/'+native.TYPE,ACCOUNT,ACCOUNT+'/deployments',ACCOUNT+'/raiPolicies',
        ACCOUNT+'/providers/Microsoft.Insights/diagnosticSettings',ACCOUNT+'/providers/Microsoft.Insights/diagnosticSettingsCategories'}

@pytest.mark.parametrize('field,value,expected', [('workspaceId','','FAIL'),('storageAccountId',SCOPE+'/resourceGroups/review/providers/Microsoft.Storage/storageAccounts/audit','PASS'),
    ('eventHubAuthorizationRuleId',OTHER+'/resourceGroups/review/providers/Microsoft.EventHub/namespaces/audit/authorizationRules/export','PASS'),
    ('marketplacePartnerId',SCOPE+'/resourceGroups/review/providers/Microsoft.Datadog/monitors/audit','PASS')])
def test_native_diagnostic_destination_shapes(field,value,expected):
    data=pages();props=data[ACCOUNT+'/providers/Microsoft.Insights/diagnosticSettings']['value'][0]['properties']
    props['workspaceId']='';props[field]=value
    assert outcome('audit_logging',data)=={expected}


def test_native_child_metadata_projection_discards_noncontract_bodies():
    data=pages()
    data[ACCOUNT+'/raiPolicies']['value'][0]['properties']['contentFilters'][0]['requestBody']=CANARY
    data[ACCOUNT+'/providers/Microsoft.Insights/diagnosticSettings']['value'][0]['properties']['logs'][0]['body']=CANARY
    for name in ('prompt_shield','audit_logging'):
        assert outcome(name,data)=={'PASS'}

@pytest.mark.parametrize('field', ['accounts','deployments','raiPolicies','diagnosticSettings','diagnosticSettingsCategories'])
@pytest.mark.parametrize('query',['api-version=1900-01-01','api-version=2024-10-01&$filter=enabled%20eq%20true','api-version=2024-10-01&$top=1','api-version=2024-10-01&api-version=2024-10-01'])
def test_native_narrowed_or_changed_version_continuation_unresolved(field,query):
    data=pages();name='prompt_shield' if field in ('deployments','raiPolicies') else 'audit_logging'
    path=SCOPE+'/providers/'+native.TYPE if field=='accounts' else ACCOUNT+('/providers/Microsoft.Insights/' if field.startswith('diagnostic') else '/')+field
    data[path]['nextLink']=azure.ARM+path+'?'+query
    states=outcome(name,data)
    # An observed full account may remain decisive alongside an explicit inventory gap.
    assert states==({'UNKNOWN','PASS'} if field=='accounts' else {'UNKNOWN'})

@pytest.mark.parametrize('name',list(native.KINDS)+list(EXISTING))
@pytest.mark.parametrize('branch',['positive','negative','denied','foreign'])
def test_native_http_request_object_through_real_arm_transport(monkeypatch,name,branch):
    import io
    from urllib.error import HTTPError
    data=pages();props=data[ACCOUNT]['properties']
    if branch=='negative':
        if name=='managed_identity':data[ACCOUNT]['identity']['type']='None'
        if name=='outbound_restriction':props['restrictOutboundNetworkAccess']=False
        if name=='audit_logging':data[ACCOUNT+'/providers/Microsoft.Insights/diagnosticSettings']['value']=[]
        if name=='prompt_shield':data[ACCOUNT+'/raiPolicies']['value'][0]['properties']['contentFilters'][0]['blocking']=False
        if name=='local_auth_disabled':props['disableLocalAuth']=False
        if name=='public_disabled':props['publicNetworkAccess']='Enabled'
        if name=='acl_deny':props['networkAcls']['defaultAction']='Allow'
        if name=='cmk':props['encryption']['keySource']='Microsoft.CognitiveServices'
        if name=='private_endpoint':props['privateEndpointConnections'][0]['properties']['privateLinkServiceConnectionState']['status']='Rejected'
    if branch=='foreign':data[SCOPE+'/providers/'+native.TYPE]['value'][0]['id']=ACCOUNT.replace(SCOPE,OTHER)
    api=NativeAPI(data);wire=[]
    class Opener:
        def open(self,request,timeout):
            assert request.get_method()=='GET' and request.data is None and timeout==20
            assert request.get_header('Authorization')=='Bearer inert-offline-token'
            wire.append(request.full_url)
            if branch=='denied':raise HTTPError(request.full_url,403,'Forbidden',{},io.BytesIO(b'{"error":{}}'))
            value=api.request(request.full_url,body=request.data,audience=azure.ARM)
            response=io.BytesIO(json.dumps(value).encode())
            response.status=200
            return response
    monkeypatch.setattr(azure,'build_opener',lambda *args:Opener())
    transport=object.__new__(azure.AzureTransport)
    transport.token=lambda audience:'inert-offline-token' if audience==azure.ARM else pytest.fail('foreign auth audience')
    transport.owned=False;transport.credential=None
    kind=native.KINDS[name] if name in native.KINDS else 'cognitive_account'
    cid=checks.PREFIX+name if name in native.KINDS else 'azure.port.'+EXISTING[name]
    snapshot=azure.collect({'scopes':[SCOPE],'options':{'retries':0,'concurrency':1}},[kind],transport=transport)
    findings=engine.evaluate_snapshot(snapshot,checks=[cid])['findings']
    assert {f['status'] for f in findings}=={{'positive':'PASS','negative':'FAIL','denied':'DENIED','foreign':'UNKNOWN'}[branch]}
    assert wire and CANARY not in json.dumps([snapshot,findings])

@pytest.mark.parametrize('sink',[WORKSPACE.replace('Microsoft.OperationalInsights','MicrosoftXOperationalInsights'),WORKSPACE.replace('11111111-1111-1111-1111-111111111111','-'*36)])
def test_native_invalid_diagnostic_destination_identity_unknown(sink):
    data=pages();data[ACCOUNT+'/providers/Microsoft.Insights/diagnosticSettings']['value'][0]['properties']['workspaceId']=sink
    assert outcome('audit_logging',data)=={'UNKNOWN'}



@pytest.mark.parametrize('name',list(EXISTING))
def test_existing_five_partial_inventory_keeps_unknown_coverage(name):
    data=pages();path=SCOPE+'/providers/'+native.TYPE
    data[path]['nextLink']=azure.ARM+path+'?api-version='+native.VERSION+'&$skiptoken=next'
    data[(path,'next')]=azure.AzureReadError('permission_denied',403)
    assert existing_outcome(name,data)=={'PASS','UNKNOWN'}


def test_review_declarations_use_existing_finding_types_without_numbered_mappings():
    from peaso.finding_types import type_ids
    admission=json.loads(Path(checks.__file__).with_name('azure_ai_services_review_20261020_admission.json').read_text())
    descriptions=json.loads(Path(checks.__file__).with_name('azure_ai_services_review_20261020_descriptions.json').read_text())
    for declaration in admission['declarations']:
        assert declaration['finding_type'] in type_ids()
        assert descriptions[declaration['id']]['finding_type']==declaration['finding_type']
        assert declaration['requirements']==[] and descriptions[declaration['id']]['requirement_controls']==[]
