"""Independent Graph/ARM wire data -> actual collect_live planning -> engine.

No historical CASES, collector-output input, effective-access markers or live auth.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import socket
from urllib.parse import urlsplit, parse_qs
import pytest
from peaso import engine
from peaso.checks import CHECKS
from peaso.collectors import azure

SUB='11111111-1111-1111-1111-111111111111'
TENANT='22222222-2222-2222-2222-222222222222'
OTHER='99999999-9999-9999-9999-999999999999'
SCOPE='/subscriptions/'+SUB
TSCOPE='/tenants/'+TENANT
USER='33333333-3333-3333-3333-333333333333'
GROUP='44444444-4444-4444-4444-444444444444'
APP='55555555-5555-5555-5555-555555555555'
SP='66666666-6666-6666-6666-666666666666'
POLICY='77777777-7777-7777-7777-777777777777'
KEY='88888888-8888-8888-8888-888888888888'
GLOBAL='62e90394-69f5-4237-9190-012177145e10'
OWNER='8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
READER='acdd72a7-3385-48ef-bd42-f606fba81ae7'
CONTRIBUTOR='b24988ac-6180-42a0-ab88-20f7382dd24c'
UAA='18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'
RESTRICTED='2af84b1e-32c8-42b7-82bc-daa82404023b'
GRAPH_APP='00000003-0000-0000-c000-000000000000'
LOW='managePermissionGrantsForSelf.microsoft-user-default-low'
LEGACY='managePermissionGrantsForSelf.microsoft-user-default-legacy'
CANARY='inert-no-native-secret-may-be-retained'
MI=SCOPE+'/resourceGroups/review/providers/Microsoft.ManagedIdentity/userAssignedIdentities/review'
REGISTRY={c.id:c for c in CHECKS}
REAL_TRANSPORT=azure.AzureTransport

ROSTER=['azure.cis.multifactor_auth_status_non_privileged_users', 'azure.cis.multifactor_auth_status_privileged_users', 'azure.cis.multifactor_authentication_policy_exists_administrative_groups', 'azure.cis.multifactor_authentication_policy_exists_users', 'azure.cis.multifactor_authentication_risky_sign_ins', 'azure.claude.entra_app_credential_not_expiring', 'azure.claude.entra_ca_mfa_admin_portals', 'azure.claude.entra_ca_mfa_management_api', 'azure.claude.entra_ca_policy_requires_mfa', 'azure.claude.entra_global_admin_fewer_than_five', 'azure.claude.entra_guest_access_restricted', 'azure.claude.entra_guest_invites_admins_only', 'azure.claude.entra_m365_group_creation_restricted', 'azure.claude.entra_non_privileged_user_mfa', 'azure.claude.entra_privileged_user_mfa', 'azure.claude.entra_security_defaults_enabled', 'azure.claude.entra_trusted_named_location_exists', 'azure.claude.entra_user_consent_disabled', 'azure.claude.entra_user_consent_not_legacy', 'azure.claude.entra_user_recent_sign_in', 'azure.claude.entra_users_cannot_create_apps', 'azure.claude.entra_users_cannot_create_security_groups', 'azure.claude.entra_users_cannot_create_tenants', 'azure.claude.entra_vm_access_user_mfa', 'azure.claude.iam_custom_role_no_wildcard_actions', 'azure.claude.iam_no_user_access_administrator_assignment', 'azure.claude.iam_root_custom_role_no_wildcard', 'azure.claude.iam_subscription_tenant_transfer_restricted', 'azure.claude.iam_user_no_contributor_assignment', 'azure.claude2.entra_ca_mfa_all_users_or_roles', 'azure.claude2.entra_custom_banned_password_enforced', 'azure.claude2.entra_device_join_requires_mfa', 'azure.claude2.entra_global_admin_between_2_and_4', 'azure.claude2.entra_lockout_duration_min_60', 'azure.claude2.entra_lockout_threshold_max_10', 'azure.claude2.iam_no_custom_owner_roles', 'azure.htbp.entra.app_fic_github_not_pull_request', 'azure.htbp.entra.app_no_tier0_graph_application_permissions', 'azure.htbp.entra.service_principal_no_password_credentials', 'azure.htbp.managed_identity.fic_github_not_pull_request', 'azure.iam.no_full_custom_role', 'azure.iam.review_owner_assignment', 'azure.port.ad_authorization_policy_guest_invite_restricted', 'azure.port.ad_authorization_policy_guest_user_access_restricted', 'azure.port.ad_authorization_policy_user_consent_disallowed', 'azure.port.ad_authorization_policy_user_consent_verified_publishers_selected_permissions', 'azure.port.ad_security_defaults_policy_enabled', 'azure.port.iam_user_not_allowed_to_create_security_group', 'azure.port.iam_user_not_allowed_to_register_application', 'azure_directory_user_10_6_3_21_d013932', 'azure_directory_user_7_2_1_19_28e2aa7', 'azure_directory_user_entra_non_privileged_user_has_mfa_b242ca9', 'azure_directory_user_entra_privileged_user_has_mfa_6f6d584', 'azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28']


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args,**kwargs):pytest.fail('socket/DNS/credential discovery prohibited')
    for attr in ('connect','connect_ex'):monkeypatch.setattr(socket.socket,attr,blocked)
    for attr in ('create_connection','getaddrinfo','gethostbyname','gethostbyname_ex'):monkeypatch.setattr(socket,attr,blocked)
    monkeypatch.setattr(azure,'credential_for',blocked)
    monkeypatch.setattr(azure,'urlopen',blocked)
    monkeypatch.setattr(azure.time,'sleep',lambda seconds:None)


def policy():
    return {'id':POLICY,'displayName':'Native review policy','state':'enabled',
        'conditions':{'users':{'includeUsers':['All'],'excludeUsers':[],'includeGroups':[],'excludeGroups':[],'includeRoles':[],'excludeRoles':[]},
            'applications':{'includeApplications':['All'],'excludeApplications':[]},
            'clientAppTypes':['all'],'locations':None,'platforms':None,'devices':None,'signInRiskLevels':[],'userRiskLevels':[],'authenticationFlows':None},
        'grantControls':{'operator':'AND','builtInControls':['mfa'],'customAuthenticationFactors':[],'termsOfUse':[],'authenticationStrength':None}}


def native_data():
    now=datetime.now(timezone.utc)
    password={'keyId':KEY,'startDateTime':(now-timedelta(days=5)).isoformat(),'endDateTime':(now+timedelta(days=120)).isoformat(),'secretText':None}
    user={'id':USER,'displayName':'Native user','userPrincipalName':'review@example.test','accountEnabled':True,'userType':'Member',
        'signInActivity':{'lastSuccessfulSignInDateTime':(now-timedelta(days=5)).isoformat(),'lastSignInDateTime':now.isoformat()}}
    definition={'id':SCOPE+'/providers/Microsoft.Authorization/roleDefinitions/'+KEY,'name':KEY,'type':'Microsoft.Authorization/roleDefinitions',
        'properties':{'roleName':'Limited review role','type':'CustomRole','assignableScopes':[SCOPE],
            'permissions':[{'actions':['Microsoft.Resources/subscriptions/resourceGroups/read'],'notActions':[],'dataActions':[],'notDataActions':[]}]}}
    assignment={'id':SCOPE+'/providers/Microsoft.Authorization/roleAssignments/'+KEY,'name':KEY,'type':'Microsoft.Authorization/roleAssignments',
        'properties':{'principalId':USER,'principalType':'User','roleDefinitionId':SCOPE+'/providers/Microsoft.Authorization/roleDefinitions/'+READER,'scope':SCOPE,'condition':None,'conditionVersion':None}}
    app={'id':APP,'appId':KEY,'displayName':'Native app','requiredResourceAccess':[],'signInAudience':'AzureADMyOrg','passwordCredentials':[password],'keyCredentials':[]}
    sp={'id':SP,'appId':KEY,'appOwnerOrganizationId':TENANT,'servicePrincipalType':'Application','accountEnabled':True,'preferredSingleSignOnMode':None,'passwordCredentials':[],'keyCredentials':[],'appRoles':[]}
    return {
        '/tenants':{'value':[{'id':TSCOPE,'tenantId':TENANT,'displayName':'Native tenant','tenantCategory':'Home'}]},
        SCOPE:{'id':SCOPE,'subscriptionId':SUB,'tenantId':TENANT,'state':'Enabled'},
        '/providers/Microsoft.Management/managementGroups':{'value':[]},
        '/providers/Microsoft.Authorization/roleAssignments':{'value':[]},
        '/providers/Microsoft.Authorization/roleDefinitions':{'value':[{'id':'/providers/Microsoft.Authorization/roleDefinitions/'+READER,'name':READER,'type':'Microsoft.Authorization/roleDefinitions','properties':{'type':'BuiltInRole','roleName':'Reader','assignableScopes':['/'],'permissions':[{'actions':['*/read'],'notActions':[],'dataActions':[],'notDataActions':[]}]}}]},
        SCOPE+'/providers/Microsoft.Authorization/roleAssignments':{'value':[assignment]},
        SCOPE+'/providers/Microsoft.Authorization/roleDefinitions':{'value':[definition]},
        '/providers/Microsoft.Subscription/policies/default':{'id':'/providers/Microsoft.Subscription/policies/default','type':'Microsoft.Subscription/policies',
            'properties':{'blockSubscriptionsIntoTenant':True,'blockSubscriptionsLeavingTenant':True,'exemptedPrincipals':[]}},
        '/v1.0/policies/authorizationPolicy':{'id':'authorizationPolicy','allowInvitesFrom':'adminsAndGuestInviters','guestUserRoleId':RESTRICTED,
            'defaultUserRolePermissions':{'allowedToCreateApps':False,'allowedToCreateSecurityGroups':False,'allowedToCreateTenants':False,'permissionGrantPoliciesAssigned':[]}},
        '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy':{'id':'00000000-0000-0000-0000-000000000005','isEnabled':True},
        '/v1.0/policies/deviceRegistrationPolicy':{'id':'deviceRegistrationPolicy','multiFactorAuthConfiguration':'required'},
        '/v1.0/identity/conditionalAccess/policies':{'value':[policy()]},
        '/v1.0/identity/conditionalAccess/namedLocations':{'value':[{'id':GROUP,'@odata.type':'#microsoft.graph.ipNamedLocation','displayName':'Office',
            'isTrusted':True,'ipRanges':[{'@odata.type':'#microsoft.graph.iPv4CidrRange','cidrAddress':'203.0.113.0/24'}]}]},
        '/v1.0/policies/authenticationStrengthPolicies':{'value':[]},
        '/v1.0/subscribedSkus':{'value':[{'id':TENANT+'_'+KEY,'skuId':KEY,'capabilityStatus':'Enabled','appliesTo':'User','servicePlans':[{'servicePlanId':'eec0eb4f-6444-4f95-aba0-50c24d67f998','servicePlanName':'AAD_PREMIUM_P2','provisioningStatus':'Success'}]}]},
        '/v1.0/users':{'value':[user]},
        '/v1.0/groups':{'value':[]},
        '/v1.0/users/'+USER+'/transitiveMemberOf':{'value':[{'id':GROUP,'@odata.type':'#microsoft.graph.group'}]},
        '/v1.0/groupSettings':{'value':[{'id':KEY,'displayName':'Group.Unified','templateId':'62375ab9-6b52-47ed-826b-58e47e0e304b','values':[{'name':'EnableGroupCreation','value':'false'}]},
            {'id':GROUP,'displayName':'Password Rule Settings','templateId':'5cf42378-d67d-4f36-ba46-e8b86229381d','values':[
                {'name':'LockoutDurationInSeconds','value':'60'},{'name':'LockoutThreshold','value':'10'},{'name':'EnableBannedPasswordCheck','value':'true'}]}]},
        '/v1.0/reports/authenticationMethods/userRegistrationDetails':{'value':[{'id':USER,'userPrincipalName':'review@example.test','isMfaCapable':True,'isMfaRegistered':True}]},
        '/v1.0/directoryRoles':{'value':[{'id':KEY,'roleTemplateId':GLOBAL,'displayName':'Global Administrator'}]},
        '/v1.0/roleManagement/directory/roleAssignments':{'value':[]},
        '/v1.0/roleManagement/directory/roleDefinitions':{'value':[]},
        '/v1.0/roleManagement/directory/roleEligibilitySchedules':{'value':[]},
        '/v1.0/roleManagement/directory/roleEligibilityScheduleInstances':{'value':[]},
        '/v1.0/roleManagement/directory/roleAssignmentScheduleInstances':{'value':[]},
        '/beta/roleManagement/directory/roleDefinitions':{'value':[]},
        '/beta/users/'+USER+'/authentication/requirements':{'perUserMfaState':'enforced'},
        '/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances':{'value':[]},
        '/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances':{'value':[]},
        '/v1.0/applications':{'value':[app]},
        '/v1.0/servicePrincipals':{'value':[sp]},
        '/beta/applications/'+APP+'/federatedIdentityCredentials':{'value':[{'id':GROUP,'name':'protected-environment','issuer':'https://token.actions.githubusercontent.com','subject':'repo:review/repo:environment:production','audiences':['api://AzureADTokenExchange']}]},
        SCOPE+'/providers/Microsoft.ManagedIdentity/userAssignedIdentities':{'value':[{'id':MI,'name':'review','type':'Microsoft.ManagedIdentity/userAssignedIdentities','properties':{'principalId':SP,'tenantId':TENANT,'clientId':APP}}]},
        MI:{'id':MI,'name':'review','type':'Microsoft.ManagedIdentity/userAssignedIdentities','properties':{'principalId':SP,'tenantId':TENANT,'clientId':APP}},
        MI+'/federatedIdentityCredentials':{'value':[{'id':MI+'/federatedIdentityCredentials/protected-environment','name':'protected-environment','type':'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials',
            'properties':{'issuer':'https://token.actions.githubusercontent.com','subject':'repo:review/repo:environment:production','audiences':['api://AzureADTokenExchange']}}]},
        MI+'/providers/Microsoft.Insights/diagnosticSettings':{'value':[]},
    }


class NativeAPI:
    tenant=verified_tenant=TENANT
    def __init__(self,data,*,deny=False,partial=False,omit=False):
        self.data=data;self.calls=[];self.deny=deny;self.partial=partial;self.omit=omit
    def close(self):pass
    def request(self,url,*,body=None,audience=azure.ARM):
        parts=urlsplit(url);query=parse_qs(parts.query)
        assert body is None, 'no native write or hidden body'
        assert parts.scheme=='https' and parts.netloc in ('graph.microsoft.com','management.azure.com')
        assert audience==(azure.GRAPH if parts.netloc=='graph.microsoft.com' else azure.ARM)
        if parts.path not in self.data:pytest.fail('unexpected native route: '+parts.path)
        if parts.netloc=='management.azure.com':assert 'api-version' in query
        self.calls.append(('GET',parts.netloc,parts.path,query))
        if self.deny:raise azure.AzureReadError('forbidden',403)
        row=self.data[parts.path]
        if isinstance(row,BaseException):raise row
        if self.omit:return {} if 'value' not in row else {'value':[{'id':i['id']} for i in row['value']]}
        if self.partial and 'value' in row:
            if '$skiptoken' in query:raise azure.AzureReadError('forbidden',403)
            row={**deepcopy(row),'@odata.nextLink' if parts.netloc=='graph.microsoft.com' else 'nextLink':url+('&' if parts.query else '?')+'$skiptoken=next'}
        row=deepcopy(row)
        if parts.netloc=='graph.microsoft.com' and '$select' in query and isinstance(row.get('value'),list):
            selected=set(query['$select'][0].split(','))
            row['value']=[{key:value for key,value in item.items() if key in selected or key.startswith('@odata.')} for item in row['value']]
        return row


def prepare(cid,opposite=False):
    d=native_data();a=d['/v1.0/policies/authorizationPolicy'];perm=a['defaultUserRolePermissions'];ca=d['/v1.0/identity/conditionalAccess/policies']['value'][0]
    # Each fixture starts with independent documented provider fields, never CASES.
    if cid.endswith('entra_ca_mfa_admin_portals'):ca['conditions']['applications']['includeApplications']=['MicrosoftAdminPortals']
    if cid.endswith('entra_ca_mfa_management_api'):ca['conditions']['applications']['includeApplications']=['797f4846-ba00-4fd7-ba43-dac1f8f63013']
    if cid.endswith('.entra_privileged_user_mfa'):
        d['/v1.0/roleManagement/directory/roleAssignments']['value']=[{'id':KEY,'principalId':USER,'roleDefinitionId':GLOBAL,'directoryScopeId':'/','appScopeId':None}]
    if 'global_admin_' in cid:
        count=5 if opposite else 3
        d['/v1.0/roleManagement/directory/roleAssignments']['value']=[{'id':f'10000000-0000-0000-0000-{i:012d}','principalId':f'20000000-0000-0000-0000-{i:012d}','roleDefinitionId':GLOBAL,'directoryScopeId':'/','appScopeId':None} for i in range(count)]
    if cid.endswith('user_consent_not_legacy') or cid.endswith('user_consent_verified_publishers_selected_permissions'):perm['permissionGrantPoliciesAssigned']=[LOW]
    if 'app_no_tier0' in cid:
        graph={'id':GROUP,'appId':GRAPH_APP,'appRoles':[{'id':KEY,'value':'RoleManagement.ReadWrite.Directory','isEnabled':True,'allowedMemberTypes':['Application']}], 'passwordCredentials':[],'keyCredentials':[]}
        d['/v1.0/servicePrincipals']['value']=[graph]
        d['/v1.0/applications']['value'][0]['requiredResourceAccess']=[{'resourceAppId':GRAPH_APP,'resourceAccess':[{'id':KEY,'type':'Role' if opposite else 'Scope'}]}]
    if cid.endswith('keyvault_rbac_secret_expiration_set_e2e0e28'):
        now=datetime.now(timezone.utc)
        d['/v1.0/servicePrincipals']['value'][0]['passwordCredentials']=[{'keyId':KEY,'startDateTime':(now-timedelta(days=100 if opposite else 5)).isoformat(),'endDateTime':(now+timedelta(days=100)).isoformat()}]
    if cid=='azure.cis.multifactor_auth_status_non_privileged_users':d['/v1.0/users/'+USER+'/transitiveMemberOf']['value']=[]
    if cid in ('azure.cis.multifactor_authentication_policy_exists_administrative_groups','azure.cis.multifactor_authentication_policy_exists_users','azure.cis.multifactor_authentication_risky_sign_ins'):
        d['/v1.0/policies/identitySecurityDefaultsEnforcementPolicy']['isEnabled']=False
    if cid.endswith('entra_vm_access_user_mfa'):d[SCOPE+'/providers/Microsoft.Authorization/roleAssignments']['value'][0]['properties']['roleDefinitionId']=SCOPE+'/providers/Microsoft.Authorization/roleDefinitions/'+OWNER
    if cid=='azure.cis.multifactor_authentication_risky_sign_ins':
        ca['conditions']['signInRiskLevels']=['medium','high']
        d['/v1.0/users']['value'][0]['assignedPlans']=[{'servicePlanId':'eec0eb4f-6444-4f95-aba0-50c24d67f998','capabilityStatus':'Enabled'}]
    if not opposite:return d
    if cid.startswith('azure.cis.multifactor_authentication_'):ca['state']='disabled'
    if 'guest_invite' in cid:a['allowInvitesFrom']='everyone'
    if 'guest_access' in cid or 'guest_user_access' in cid:a['guestUserRoleId']='10dae51f-b6af-4016-8d66-8c2a99b929b3'
    if 'cannot_create_apps' in cid or 'not_allowed_to_register_application' in cid:perm['allowedToCreateApps']=True
    if 'create_security_group' in cid:perm['allowedToCreateSecurityGroups']=True
    if 'create_tenants' in cid:perm['allowedToCreateTenants']=True
    if cid.endswith('user_consent_disabled') or cid.endswith('user_consent_disallowed'):perm['permissionGrantPoliciesAssigned']=[LOW]
    if cid.endswith('user_consent_not_legacy'):perm['permissionGrantPoliciesAssigned']=[LEGACY]
    if cid.endswith('user_consent_verified_publishers_selected_permissions'):perm['permissionGrantPoliciesAssigned']=[]
    if cid.endswith('security_defaults_enabled') or cid.endswith('security_defaults_policy_enabled'):
        d['/v1.0/policies/identitySecurityDefaultsEnforcementPolicy']['isEnabled']=False
        d['/v1.0/identity/conditionalAccess/policies']['value']=[]
    if 'ca_mfa_' in cid:ca['state']='disabled'
    if cid.endswith('entra_ca_policy_requires_mfa'):ca['grantControls'].update(operator='OR',builtInControls=['mfa','compliantDevice'])
    if 'trusted_named_location' in cid:d['/v1.0/identity/conditionalAccess/namedLocations']['value'][0]['isTrusted']=False
    if 'm365_group_creation' in cid:d['/v1.0/groupSettings']['value'][0]['values'][0]['value']='true'
    if 'lockout_duration' in cid:d['/v1.0/groupSettings']['value'][1]['values'][0]['value']='30'
    if 'lockout_threshold' in cid:d['/v1.0/groupSettings']['value'][1]['values'][1]['value']='11'
    if 'banned_password' in cid:d['/v1.0/groupSettings']['value'][1]['values'][2]['value']='false'
    if 'device_join' in cid:d['/v1.0/policies/deviceRegistrationPolicy']['multiFactorAuthConfiguration']='notRequired'
    if cid.endswith('user_recent_sign_in'):d['/v1.0/users']['value'][0]['signInActivity']['lastSuccessfulSignInDateTime']=(datetime.now(timezone.utc)-timedelta(days=120)).isoformat()
    if cid.endswith('app_credential_not_expiring'):d['/v1.0/applications']['value'][0]['passwordCredentials'][0]['endDateTime']=(datetime.now(timezone.utc)+timedelta(days=1)).isoformat()
    if cid.endswith('service_principal_no_password_credentials'):d['/v1.0/servicePrincipals']['value'][0]['passwordCredentials']=[{'keyId':KEY,'endDateTime':(datetime.now(timezone.utc)+timedelta(days=120)).isoformat()}]
    if 'fic_github_not_pull_request' in cid:
        if '.managed_identity.' in cid:d[MI+'/federatedIdentityCredentials']['value'][0]['properties']['subject']='repo:review/repo:pull_request'
        else:d['/beta/applications/'+APP+'/federatedIdentityCredentials']['value'][0]['subject']='repo:review/repo:pull_request'
    if cid.endswith('iam_subscription_tenant_transfer_restricted'):d['/providers/Microsoft.Subscription/policies/default']['properties']['blockSubscriptionsLeavingTenant']=False
    if 'custom_role' in cid or cid.endswith('iam_no_custom_owner_roles'):d[SCOPE+'/providers/Microsoft.Authorization/roleDefinitions']['value'][0]['properties']['permissions'][0]['actions']=['*']
    if cid.endswith('iam_no_user_access_administrator_assignment'):d[SCOPE+'/providers/Microsoft.Authorization/roleAssignments']['value'][0]['properties']['roleDefinitionId']=SCOPE+'/providers/Microsoft.Authorization/roleDefinitions/'+UAA
    if cid.endswith('iam_user_no_contributor_assignment'):d[SCOPE+'/providers/Microsoft.Authorization/roleAssignments']['value'][0]['properties']['roleDefinitionId']=SCOPE+'/providers/Microsoft.Authorization/roleDefinitions/'+CONTRIBUTOR
    if cid.endswith('review_owner_assignment'):d[SCOPE+'/providers/Microsoft.Authorization/roleAssignments']['value'][0]['properties']['roleDefinitionId']=SCOPE+'/providers/Microsoft.Authorization/roleDefinitions/'+OWNER
    if cid.endswith('user_mfa'):d['/v1.0/reports/authenticationMethods/userRegistrationDetails']['value'][0]['isMfaCapable']=False
    if cid=='azure.cis.multifactor_auth_status_non_privileged_users':d['/v1.0/reports/authenticationMethods/userRegistrationDetails']['value'][0]['isMfaCapable']=False
    if cid=='azure_directory_user_10_6_3_21_d013932':d['/v1.0/users/'+USER+'/transitiveMemberOf']['value']=[]
    return d


def _with_prior_native_source_gaps(cid,d):
    if cid in PRIOR_CAPTURE_WITHOUT_ENFORCEMENT_SOURCES:
        # Preserve this earlier finite capture as incomplete; do not fabricate
        # empty grants or per-user enforcement. Complete native witnesses are
        # separately tested in test_azure_identity_enforcement_native_20261020.
        unavailable = azure.AzureReadError('New native source not readable in prior capture', 403)
        for path in ('/providers/Microsoft.Authorization/roleAssignmentScheduleInstances',
                     '/providers/Microsoft.Authorization/roleEligibilityScheduleInstances',
                     '/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances',
                     '/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances'):
            d.setdefault(path, unavailable)
        for user in d['/v1.0/users']['value']:
            d.setdefault('/beta/users/'+user['id']+'/authentication/requirements', unavailable)
        for group in d['/v1.0/groups']['value']:
            d.setdefault('/v1.0/groups/'+group['id']+'/owners', unavailable)
    return d


def capture(monkeypatch,cid,branch='positive',data=None,**options):
    supplied = prepare(cid,branch=='opposite') if data is None else data
    api=NativeAPI(_with_prior_native_source_gaps(cid,supplied),deny=branch=='denied',partial=branch=='partial',omit=branch=='omitted')
    monkeypatch.setattr(azure,'AzureTransport',lambda auth:api)
    monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:api)
    request={'connector':{'provider':'azure','scopes':[SUB],'auth':{'tenant_id':TENANT},'options':{'retries':0,'concurrency':1,**options}},'checks':[cid]}
    snapshot=engine.collect_snapshot(request)
    findings=engine.evaluate_snapshot(snapshot,checks=[cid])['findings']
    assert findings,(cid,snapshot)
    assert CANARY not in json.dumps([snapshot,findings])
    if REGISTRY[cid].kind in ('role_definition','role_assignment'):
        findings=[f for f in findings if f['scope']==SCOPE or f['status'] in ('UNKNOWN','DENIED')]
    return snapshot,findings,api


PRIOR_CAPTURE_WITHOUT_ENFORCEMENT_SOURCES={
    'azure.cis.multifactor_auth_status_privileged_users',
    'azure_directory_user_7_2_1_19_28e2aa7',
    'azure_directory_user_entra_non_privileged_user_has_mfa_b242ca9',
    'azure_directory_user_entra_privileged_user_has_mfa_6f6d584',
}


def expected(cid,branch):
    if branch=='denied':return {'DENIED','UNKNOWN'}
    if branch=='omitted':return {'UNKNOWN','EMPTY','NOT_APPLICABLE'}
    if branch=='partial':return {'PASS','FAIL','UNKNOWN','DENIED','NOT_APPLICABLE','EMPTY'}
    if cid in PRIOR_CAPTURE_WITHOUT_ENFORCEMENT_SOURCES:return {'UNKNOWN'}
    if branch=='opposite' and cid in ('azure.cis.multifactor_authentication_policy_exists_administrative_groups','azure.cis.multifactor_authentication_risky_sign_ins'):return {'UNKNOWN'}
    if cid.endswith('iam_root_custom_role_no_wildcard'):return {'NOT_APPLICABLE'}
    if cid.endswith('entra_ca_policy_requires_mfa') and branch=='opposite':return {'FAIL'}
    return {'FAIL' if branch=='opposite' else 'PASS'}


@pytest.mark.parametrize('cid',ROSTER)
@pytest.mark.parametrize('branch',['positive','opposite','omitted','denied','partial'])
def test_assigned_native_contracts(monkeypatch,cid,branch):
    if cid == 'azure.claude.iam_root_custom_role_no_wildcard':
        # Provider-impossible root applicability is archived; the useful native
        # custom-role successor remains covered by its own real native matrix.
        with pytest.raises(ValueError, match='not available for automated scans'):
            capture(monkeypatch,cid,branch)
        return
    _,findings,api=capture(monkeypatch,cid,branch)
    states={f['status'] for f in findings}
    assert states <= expected(cid,branch),(cid,branch,findings)
    if branch=='partial' and REGISTRY[cid].kind not in ('directory_authorization_policy','directory_security_defaults','subscription_tenant_policy'):
        assert 'UNKNOWN' in states or 'DENIED' in states,(cid,findings)
    assert api.calls

CA_TARGETS=['azure.claude.entra_ca_mfa_admin_portals','azure.claude.entra_ca_mfa_management_api','azure.claude2.entra_ca_mfa_all_users_or_roles']

@pytest.mark.parametrize('cid',CA_TARGETS)
def test_regression_native_or_grant_does_not_require_mfa(monkeypatch,cid):
    data=prepare(cid);data['/v1.0/identity/conditionalAccess/policies']['value'][0]['grantControls'].update(operator='OR',builtInControls=['mfa','compliantDevice'])
    _,findings,_=capture(monkeypatch,cid,data=data)
    assert {f['status'] for f in findings}=={'FAIL'},findings


@pytest.mark.parametrize('cid',CA_TARGETS[:2])
def test_regression_native_target_resource_excluded(monkeypatch,cid):
    data=prepare(cid);apps=data['/v1.0/identity/conditionalAccess/policies']['value'][0]['conditions']['applications']
    apps['excludeApplications']=['MicrosoftAdminPortals' if cid.endswith('admin_portals') else '797f4846-ba00-4fd7-ba43-dac1f8f63013']
    _,findings,_=capture(monkeypatch,cid,data=data)
    assert {f['status'] for f in findings}=={'FAIL'},findings

@pytest.mark.parametrize('cid',CA_TARGETS)
@pytest.mark.parametrize('mode,expected_state',[
    ('mfa_only_or','PASS'),('mfa_and_device','PASS'),('mfa_or_device','FAIL'),('mfa_or_terms','FAIL'),
    ('mfa_or_custom','UNKNOWN'),('mfa_and_custom','PASS'),('strength_only','UNKNOWN'),
    ('malformed_strength','UNKNOWN'),('unknown_control','UNKNOWN'),('unknown_operator','UNKNOWN'),
    ('report_only','FAIL'),('denied_policies','UNKNOWN')])
def test_native_mfa_grant_relationships(monkeypatch,cid,mode,expected_state):
    data=prepare(cid);row=data['/v1.0/identity/conditionalAccess/policies']['value'][0];g=row['grantControls']
    if mode=='mfa_only_or':g['operator']='OR'
    if mode=='mfa_and_device':g['builtInControls']=['mfa','compliantDevice']
    if mode=='mfa_or_device':g.update(operator='OR',builtInControls=['mfa','compliantDevice'])
    if mode=='mfa_or_terms':g.update(operator='OR',termsOfUse=[GROUP])
    if mode in ('mfa_or_custom','mfa_and_custom'):g.update(operator='OR' if mode=='mfa_or_custom' else 'AND',customAuthenticationFactors=[GROUP])
    if mode=='strength_only':g.update(builtInControls=[],authenticationStrength={'id':GROUP})
    if mode=='malformed_strength':g['authenticationStrength']='mfa'
    if mode=='unknown_control':g['builtInControls']=['unknownFutureValue']
    if mode=='unknown_operator':g['operator']='XOR'
    if mode=='report_only':row['state']='enabledForReportingButNotEnforced'
    if mode=='denied_policies':data['/v1.0/identity/conditionalAccess/policies']=azure.AzureReadError('forbidden',403)
    _,findings,_=capture(monkeypatch,cid,data=data)
    assert {f['status'] for f in findings}=={expected_state},findings


@pytest.mark.parametrize('cid',['azure.claude.entra_non_privileged_user_mfa','azure.claude.entra_privileged_user_mfa','azure.claude.entra_vm_access_user_mfa'])
@pytest.mark.parametrize('mode',['foreign_user','duplicate_user','omitted_capable','denied_report'])
def test_native_registration_join_requires_exact_subject(monkeypatch,cid,mode):
    data=prepare(cid);path='/v1.0/reports/authenticationMethods/userRegistrationDetails';row=data[path]['value'][0]
    if mode=='foreign_user':row['id']=OTHER
    if mode=='duplicate_user':data[path]['value'].append(deepcopy(row))
    if mode=='omitted_capable':row.pop('isMfaCapable')
    if mode=='denied_report':data[path]=azure.AzureReadError('forbidden',403)
    _,findings,_=capture(monkeypatch,cid,data=data)
    assert {f['status'] for f in findings}<={'UNKNOWN','DENIED'},findings


@pytest.mark.parametrize('mode,expected_state',[('current','PASS'),('stale','FAIL'),('attempt_only','UNKNOWN'),('null_success','UNKNOWN'),('future_success','UNKNOWN'),('disabled','NOT_APPLICABLE')])
def test_native_successful_signin_is_not_recent_attempt(monkeypatch,mode,expected_state):
    cid='azure.claude.entra_user_recent_sign_in';data=prepare(cid);row=data['/v1.0/users']['value'][0]
    if mode=='stale':row['signInActivity']['lastSuccessfulSignInDateTime']=(datetime.now(timezone.utc)-timedelta(days=91)).isoformat()
    if mode=='attempt_only':row['signInActivity'].pop('lastSuccessfulSignInDateTime')
    if mode=='null_success':row['signInActivity']['lastSuccessfulSignInDateTime']=None
    if mode=='future_success':row['signInActivity']['lastSuccessfulSignInDateTime']=(datetime.now(timezone.utc)+timedelta(days=1)).isoformat()
    if mode=='disabled':row['accountEnabled']=False
    _,findings,_=capture(monkeypatch,cid,data=data)
    assert {f['status'] for f in findings}=={expected_state}


@pytest.mark.parametrize('cid',['azure.claude2.entra_lockout_duration_min_60','azure.claude2.entra_lockout_threshold_max_10','azure.claude2.entra_custom_banned_password_enforced'])
@pytest.mark.parametrize('mode',['absent','malformed','duplicate'])
def test_native_directory_setting_absence_is_not_default_compliance(monkeypatch,cid,mode):
    data=prepare(cid);path='/v1.0/groupSettings';selected={'azure.claude2.entra_lockout_duration_min_60':0,'azure.claude2.entra_lockout_threshold_max_10':1,'azure.claude2.entra_custom_banned_password_enforced':2}[cid]
    row=data[path]['value'][1]['values'][selected]
    if mode=='absent':data[path]['value']=[data[path]['value'][0]]
    if mode=='malformed':row['value']='not-a-value'
    if mode=='duplicate':data[path]['value'][1]['values'].append(deepcopy(row)|{'value':'not-a-value'})
    _,findings,_=capture(monkeypatch,cid,data=data)
    assert {f['status'] for f in findings}==({'NOT_APPLICABLE'} if mode=='absent' else {'UNKNOWN'})

@pytest.mark.parametrize('cid',['azure.claude.entra_vm_access_user_mfa','azure_directory_user_10_6_3_21_d013932'])
def test_native_subscription_tenant_binding_blocks_foreign_graph_join(monkeypatch,cid):
    data=prepare(cid);data[SCOPE]['tenantId']=OTHER
    _,findings,_=capture(monkeypatch,cid,data=data)
    assert {f['status'] for f in findings}<={'UNKNOWN','DENIED'},findings


@pytest.mark.parametrize('cid',['azure.claude.entra_vm_access_user_mfa','azure.claude.entra_non_privileged_user_mfa','azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28'])
@pytest.mark.parametrize('field',['credential_context_id','customer_context_id','tenant_id'])
def test_post_native_capture_tampering_cannot_authorize_foreign_join(monkeypatch,cid,field):
    # These are corruption guards after native capture, not positive API fixtures.
    snapshot,_,_=capture(monkeypatch,cid)
    snapshot['metadata'][field]='foreign-capture'
    snapshot.pop('snapshot_id',None)
    findings=engine.evaluate_snapshot(snapshot,checks=[cid])['findings']
    if cid.endswith('entra_vm_access_user_mfa'):findings=[f for f in findings if f['scope']==SCOPE]
    assert findings and {f['status'] for f in findings}<={'UNKNOWN','DENIED'},findings


@pytest.mark.parametrize('cid',['azure.claude.entra_app_credential_not_expiring','azure.htbp.entra.service_principal_no_password_credentials','azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28'])
@pytest.mark.parametrize('mode',['empty','malformed','duplicate'])
def test_native_credential_inventory_boundaries(monkeypatch,cid,mode):
    data=prepare(cid);path='/v1.0/applications' if 'app_credential_not_expiring' in cid else '/v1.0/servicePrincipals';row=data[path]['value'][0]
    if mode=='empty':row['passwordCredentials']=[];row['keyCredentials']=[]
    if mode=='malformed':row['passwordCredentials']=['malformed']
    if mode=='duplicate':data[path]['value'].append(deepcopy(row))
    _,findings,_=capture(monkeypatch,cid,data=data)
    states={f['status'] for f in findings}
    assert states==({'NOT_APPLICABLE'} if mode=='empty' and cid.endswith('app_credential_not_expiring') else {'PASS'} if mode=='empty' else {'UNKNOWN'}),findings


@pytest.mark.parametrize('cid',['azure.htbp.entra.app_fic_github_not_pull_request','azure.htbp.managed_identity.fic_github_not_pull_request'])
@pytest.mark.parametrize('mode,expected_state',[('other_issuer','NOT_APPLICABLE'),('missing_subject','UNKNOWN'),('denied','DENIED')])
def test_native_federated_credential_subject_and_availability(monkeypatch,cid,mode,expected_state):
    data=prepare(cid);managed='.managed_identity.' in cid
    path=MI+'/federatedIdentityCredentials' if managed else '/beta/applications/'+APP+'/federatedIdentityCredentials'
    row=data[path]['value'][0]['properties'] if managed else data[path]['value'][0]
    if mode=='other_issuer':row['issuer']='https://issuer.example.test/'
    if mode=='missing_subject':row.pop('subject')
    if mode=='denied':data[path]=azure.AzureReadError('forbidden',403)
    _,findings,_=capture(monkeypatch,cid,data=data)
    assert {f['status'] for f in findings}=={expected_state}

WIRE_IDS=['azure.port.ad_authorization_policy_guest_invite_restricted','azure.claude.entra_ca_mfa_admin_portals',
    'azure.claude.entra_non_privileged_user_mfa','azure.claude.entra_app_credential_not_expiring',
    'azure.htbp.entra.app_fic_github_not_pull_request','azure.iam.review_owner_assignment',
    'azure_directory_user_10_6_3_21_d013932','azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28']

@pytest.mark.parametrize('cid',WIRE_IDS)
@pytest.mark.parametrize('branch',['positive','opposite'])
def test_real_readonly_request_objects_and_json_decoder(monkeypatch,cid,branch):
    data=prepare(cid,branch=='opposite');api=NativeAPI(data);wire=[]
    class Opener:
        def open(self,request,timeout):
            assert request.get_method()=='GET' and request.data is None and timeout==20
            assert request.get_header('Authorization')=='Bearer inert-offline-token'
            parts=urlsplit(request.full_url);audience=azure.GRAPH if parts.netloc=='graph.microsoft.com' else azure.ARM
            wire.append((request.get_method(),parts.netloc,parts.path))
            response=io.BytesIO(json.dumps(api.request(request.full_url,body=request.data,audience=audience)).encode())
            response.status=200
            return response
    monkeypatch.setattr(azure,'build_opener',lambda *args:Opener())
    transport=object.__new__(REAL_TRANSPORT);transport.tenant=transport.verified_tenant=TENANT
    transport.owned=False;transport.credential=None
    transport.token=lambda audience:'inert-offline-token' if audience in (azure.GRAPH,azure.ARM) else pytest.fail('unexpected auth audience')
    monkeypatch.setattr(azure,'AzureTransport',lambda auth:transport)
    monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:transport)
    request={'connector':{'provider':'azure','scopes':[SUB],'auth':{'tenant_id':TENANT},'options':{'retries':0,'concurrency':1}},'checks':[cid]}
    snapshot=engine.collect_snapshot(request);findings=engine.evaluate_snapshot(snapshot,checks=[cid])['findings']
    selected=[f for f in findings if f['scope'] in (SCOPE,TSCOPE) or '/applications/' in f['scope']]
    assert selected and {f['status'] for f in selected}=={'PASS' if branch=='positive' else 'FAIL'},findings
    assert wire and CANARY not in json.dumps([snapshot,findings])

@pytest.mark.parametrize('cid',CA_TARGETS[:2])
@pytest.mark.parametrize('control',['passwordChange','riskRemediation'])
def test_native_standalone_remediation_grant_is_unresolved(monkeypatch,cid,control):
    data=prepare(cid);data['/v1.0/identity/conditionalAccess/policies']['value'][0]['grantControls']['builtInControls']=[control]
    _,findings,_=capture(monkeypatch,cid,data=data)
    assert {f['status'] for f in findings}=={'UNKNOWN'}
