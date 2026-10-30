"""Explicit review + current Graph universal block; no simulated principals."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit
import pytest
from fastapi import HTTPException
from peaso.collectors import azure, collect_live, azure_ca_consideration_native as native
from tests.archived_check_contract import evaluate_snapshot, plan_collection
from peaso.server.validation import validate_connector

TENANT = '22222222-2222-2222-2222-222222222222'
SCOPE = '/tenants/' + TENANT
SUB = '11111111-1111-1111-1111-111111111111'
ID = 'a3333333-b333-c333-d333-e33333333333'
OTHER = '44444444-4444-4444-4444-444444444444'
GEO = 'azure.cis.exclusionary_geographic_access_policy_considered'
MFA = 'azure|cis|multifactor_authentication_policy_exists_users'


def rule(mode='complete'):
    value = {'id': ID, 'state': 'enabled', 'conditions': {
        'users': {'includeUsers': ['All'], 'excludeUsers': [], 'includeGroups': [], 'excludeGroups': [], 'includeRoles': [], 'excludeRoles': []},
        'applications': {'includeApplications': ['All'], 'excludeApplications': []},
        'clientAppTypes': ['all'], 'authenticationFlows': {'transferMethods': 'deviceCodeFlow'},
        'locations': None, 'platforms': None, 'devices': None, 'signInRiskLevels': [], 'userRiskLevels': []},
        'grantControls': {'operator': 'OR', 'builtInControls': ['block'], 'authenticationStrength': None,
                          'customAuthenticationFactors': [], 'termsOfUse': []}, 'sessionControls': None}
    if mode == 'disabled': value['state'] = 'disabled'
    if mode == 'reportonly': value['state'] = 'enabledForReportingButNotEnforced'
    if mode == 'unknown_state': value['state'] = 'futureEnforcement'
    if mode == 'exclude_user': value['conditions']['users']['excludeUsers'] = [OTHER]
    if mode == 'exclude_group': value['conditions']['users']['excludeGroups'] = [OTHER]
    if mode == 'include_group': value['conditions']['users']['includeGroups'] = [OTHER]
    if mode == 'exclude_role': value['conditions']['users']['excludeRoles'] = [OTHER]
    if mode == 'guest': value['conditions']['users']['includeGuestsOrExternalUsers'] = {'guestOrExternalUserTypes': 'b2bCollaborationGuest'}
    if mode == 'exclude_app': value['conditions']['applications']['excludeApplications'] = [OTHER]
    if mode == 'limited_app': value['conditions']['applications']['includeApplications'] = [OTHER]
    if mode == 'app_filter': value['conditions']['applications']['applicationFilter'] = {'mode': 'include', 'rule': 'x'}
    if mode == 'client_subset': value['conditions']['clientAppTypes'] = ['browser']
    if mode == 'location': value['conditions']['locations'] = {'includeLocations': ['All'], 'excludeLocations': [OTHER]}
    if mode == 'device': value['conditions']['devices'] = {'deviceFilter': {'mode': 'exclude', 'rule': 'x'}}
    if mode == 'risk': value['conditions']['signInRiskLevels'] = ['high']
    if mode == 'future_condition': value['conditions']['futureCondition'] = {'limited': True}
    if mode == 'other_flow': value['conditions']['authenticationFlows']['transferMethods'] = 'authenticationTransfer'
    if mode == 'combined_flow': value['conditions']['authenticationFlows']['transferMethods'] = 'deviceCodeFlow,authenticationTransfer'
    if mode == 'future_flow': value['conditions']['authenticationFlows']['futureRestriction'] = True
    if mode == 'mfa_only': value['grantControls']['builtInControls'] = ['mfa']
    if mode == 'conflicting_grant': value['grantControls']['builtInControls'] = ['block', 'mfa']
    if mode == 'strength': value['grantControls']['authenticationStrength'] = {'id': OTHER}
    if mode == 'custom_grant': value['grantControls']['customAuthenticationFactors'] = ['x']
    if mode == 'terms': value['grantControls']['termsOfUse'] = [OTHER]
    if mode == 'session': value['sessionControls'] = {'signInFrequency': {'isEnabled': True, 'value': 1, 'type': 'hours'}}
    if mode == 'future_root': value['partialEnablementStrategy'] = {'percentage': 50}
    if mode == 'field_partial': value['conditions']['_coverage'] = {'users': {'status': 'partial'}}
    return value


def options(raw, mode='complete'):
    now = datetime.now(timezone.utc)
    value = {'concurrency': 1, 'retries': 1, 'compliance_policy': {'sw13': {
        'status': 'collected', 'scope': SCOPE, 'authorized_by': 'security-owner', 'document_id': 'device-flow-consideration',
        'observed_at': (now-timedelta(hours=1)).isoformat(), 'expires_at': (now+timedelta(hours=1)).isoformat(),
        'checks': {native.KEY: {'userScope': 'all', 'requiredApplications': ['All'], 'requiredClientAppTypes': ['all'],
            'consideration': {'decision': 'block', 'reviewedPolicies': [{'policyId': ID, 'configurationSha256': native.digest(raw)}]}}}}}}
    review = value['compliance_policy']['sw13']
    if mode == 'expired': review['expires_at'] = (now-timedelta(minutes=1)).isoformat()
    if mode == 'future': review['observed_at'] = (now+timedelta(minutes=1)).isoformat()
    if mode == 'foreign_review': review['scope'] = '/tenants/' + OTHER
    if mode == 'bad_digest': review['checks'][native.KEY]['consideration']['reviewedPolicies'][0]['configurationSha256'] = '0'*64
    if mode == 'missing_policy': review['checks'][native.KEY]['consideration']['reviewedPolicies'][0]['policyId'] = OTHER
    if mode == 'no_approval': value.pop('compliance_policy')
    if mode == 'mixed_mfa': review['checks'][MFA] = {'userScope':'all', 'requiredApplications':['app-1'], 'requiredClientAppTypes':['browser']}
    if mode == 'subset_approved':
        review['checks'][native.KEY]['requiredApplications'] = [OTHER]
        review['checks'][native.KEY]['requiredClientAppTypes'] = ['browser']
    return value


class API:
    tenant = verified_tenant = TENANT
    def __init__(self, mode): self.mode = mode; self.raw = rule(mode); self.calls = []; self.closed = False
    def close(self): self.closed = True
    def request(self, url, *, body=None, audience=azure.ARM):
        self.calls.append((url, body, audience)); path = urlsplit(url).path
        if body is not None:
            assert path == '/providers/Microsoft.ResourceGraph/resources' and audience == azure.ARM
            return {'data': [], 'resultTruncated': False}
        assert audience == azure.GRAPH
        if path == native.ENDPOINT:
            if self.mode == 'denied': raise azure.AzureReadError('fixture_denied',403)
            if self.mode == 'partial' and '$skiptoken' in parse_qs(urlsplit(url).query): raise azure.AzureReadError('fixture_denied',403)
            values = [deepcopy(self.raw)]
            if self.mode == 'duplicate': values.append(deepcopy(self.raw))
            if self.mode == 'duplicate_case': values.append({**deepcopy(self.raw), 'id': ID.upper()})
            result = {'value': values}
            if self.mode == 'partial': result['@odata.nextLink'] = azure.GRAPH + native.ENDPOINT + '?$skiptoken=next'
            return result
        if path == '/v1.0/users': return {'value':[{'id': OTHER, 'accountEnabled': True, 'userType': 'Member'}]}
        if path == '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy': return {'id':'defaults','isEnabled':False}
        return {'value': []}


@pytest.mark.parametrize('mode,expected', [('complete','PASS'), ('mixed_mfa','PASS'), ('subset_approved','PASS'),
    *[(mode,'UNKNOWN') for mode in ('disabled','reportonly','unknown_state','exclude_user','exclude_group','include_group',
    'exclude_role','guest','exclude_app','limited_app','app_filter','client_subset','location','device','risk','future_condition',
    'other_flow','combined_flow','future_flow','mfa_only','conflicting_grant','strength','custom_grant','terms','session',
    'future_root','field_partial','expired','future','foreign_review','bad_digest','missing_policy','no_approval',
    'partial','duplicate','duplicate_case','unverified','foreign_tenant')], ('denied','DENIED')])
def test_normal_hosted_native_device_consideration(monkeypatch, mode, expected):
    api = API(mode)
    if mode == 'unverified': api.verified_tenant = None
    if mode == 'foreign_tenant': api.tenant = api.verified_tenant = OTHER
    monkeypatch.setattr(azure,'AzureTransport',lambda auth:api)
    monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:api)
    configured = options(api.raw, mode)
    auth = {'method':'token','arm_token':'inert','graph_token':'inert'}
    validate_connector('azure',auth,configured,SimpleNamespace(auth_mode='cognito'))
    connector = {'provider':'azure','scopes':[SUB],'auth':auth,'options':configured}
    required = plan_collection({'connector':connector,'checks':[native.CID]})
    snapshot = collect_live(connector,required)
    report = evaluate_snapshot(snapshot,checks=[native.CID],include_not_applicable=True)
    assert report['findings'] and {f['status'] for f in report['findings']} == {expected}, report['findings']
    assert api.closed
    assert all('signIns' not in url and 'runCommand' not in url for url,body,audience in api.calls)
    assert all(not c['items'] for c in snapshot['collections'] if c['type'] in ('conditional_access_principal','conditional_access_partition','azure_compliance_review'))
    if mode in ('partial','duplicate','duplicate_case'):
        assert next(c for c in snapshot['collections'] if c['type']=='conditional_access_policy')['status'] == 'partial'


@pytest.mark.parametrize('mutation', ['observed','considered','enforced','wrong_user','missing_decision','no_bindings',
    'duplicate_policy','bad_hash','foreign_field','numeric_client','empty_apps'])
def test_hosted_intake_rejects_observed_claims_and_unbound_approval(mutation):
    config = options(rule()); target = config['compliance_policy']['sw13']['checks'][native.KEY]
    if mutation in ('observed','considered','enforced'): target[mutation] = True
    if mutation == 'wrong_user': target['userScope'] = 'designated'
    if mutation == 'missing_decision': target['consideration'].pop('decision')
    if mutation == 'no_bindings': target['consideration']['reviewedPolicies'] = []
    if mutation == 'duplicate_policy': target['consideration']['reviewedPolicies'] *= 2
    if mutation == 'bad_hash': target['consideration']['reviewedPolicies'][0]['configurationSha256'] = 'z'*64
    if mutation == 'foreign_field': target['consideration']['ingestionConfirmed'] = True
    if mutation == 'numeric_client': target['requiredClientAppTypes'] = [True]
    if mutation == 'empty_apps': target['requiredApplications'] = []
    with pytest.raises(HTTPException):
        validate_connector('azure',{'method':'token','arm_token':'inert','graph_token':'inert'},config,SimpleNamespace(auth_mode='cognito'))


def test_native_device_review_does_not_create_geographic_review_inventory(monkeypatch):
    api = API('complete'); monkeypatch.setattr(azure,'AzureTransport',lambda auth:api);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:api)
    connector = {'provider':'azure','scopes':[SUB],'options':options(api.raw)}
    snapshot = collect_live(connector,plan_collection({'connector':connector,'checks':[native.CID,GEO]}))
    result = evaluate_snapshot(snapshot,checks=[native.CID,GEO],include_not_applicable=True)['findings']
    assert {f['status'] for f in result if f['check_id']==native.CID} == {'PASS'}
    assert {f['status'] for f in result if f['check_id']==GEO} == {'UNKNOWN'}
