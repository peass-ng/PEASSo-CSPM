"""Native snapshot→analysis proof for every supported provider/check variant."""
from copy import deepcopy
import pytest
from peaso.snapshot import make_snapshot
from peaso.analysis import analyze_findings
from peaso.finding_observation import evidence_summary

def provider_snapshot(provider):
 scope={'aws':'111122223333/us-east-1','gcp':'projects/demo','azure':'/subscriptions/11111111-1111-1111-1111-111111111111','k8s':'cluster-a'}[provider]
 usage={'activity_count':0,'window':{'start':'2025-12-01','end':'2026-01-01'},'completeness':'partial'}
 metadata={}
 if provider=='aws':
  facts={'iam_policy':[{'Arn':'arn:aws:iam::111122223333:policy/demo','PolicyDocument':{'Statement':[{'Effect':'Allow','Action':'*','Resource':'*'}]},'Usage':usage}],
   'iam_role':[{'Arn':'arn:aws:iam::111122223333:role/r','AssumeRolePolicyDocument':{'Statement':[{'Effect':'Allow','Principal':'*','Action':'sts:AssumeRole'},{'Effect':'Allow','Principal':{'Federated':'arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com'},'Action':'sts:AssumeRoleWithWebIdentity','Condition':{'StringEquals':{'token.actions.githubusercontent.com:aud':'sts.amazonaws.com'}}}]}}],
   'iam_oidc_provider':[{'Arn':'arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com','Provider':{'collection_status':'collected','Url':'token.actions.githubusercontent.com','ClientIDList':['sts.amazonaws.com']}}],
   'security_group':[{'GroupId':'sg-a','IpPermissions':[{'IpProtocol':'tcp','FromPort':443,'ToPort':443,'IpRanges':[{'CidrIp':'0.0.0.0/0'}]}]}],
   'http_api':[{'ApiId':'a','ApiEndpoint':'https://a.execute-api.us-east-1.amazonaws.com','ProtocolType':'HTTP','Routes':[{'RouteKey':'GET /','AuthorizationType':'NONE'}]}]}
 elif provider=='gcp':
  facts={'iam_policy':[{'name':'projects/demo','bindings':[{'role':'roles/editor','members':['allUsers']}],'Usage':usage}],
   'firewall':[{'name':'web','direction':'INGRESS','sourceRanges':['0.0.0.0/0'],'allowed':[{'IPProtocol':'tcp','ports':['443']}]}],
   'workload_identity_provider':[{'name':'projects/1/locations/global/workloadIdentityPools/p/providers/gh','oidc':{'issuerUri':'https://token.actions.githubusercontent.com'}}],
   'cloudrun_service':[{'name':'projects/demo/locations/us-east1/services/web','uri':'https://web.run.app','ingress':'INGRESS_TRAFFIC_ALL','iamPolicy':{'bindings':[{'role':'roles/run.invoker','members':['allUsers']}]}}]}
 elif provider=='azure':
  metadata={'tenant_id':'22222222-2222-2222-2222-222222222222'}
  app=scope+'/resourceGroups/demo/providers/Microsoft.Web/sites/demo'
  role='33333333-3333-3333-3333-333333333333'
  facts={'role_definition':[{'id':'/providers/Microsoft.Authorization/roleDefinitions/'+role,'name':role,'properties':{'roleName':'Demo','permissions':[{'actions':['*'],'dataActions':[]}]}}],
   'role_assignment':[{'id':scope+'/providers/Microsoft.Authorization/roleAssignments/demo','properties':{'principalId':'44444444-4444-4444-4444-444444444444','principalType':'ServicePrincipal','tenantId':'55555555-5555-5555-5555-555555555555','roleDefinitionId':'/providers/Microsoft.Authorization/roleDefinitions/'+role,'scope':scope},'Usage':usage}],
   'nsg':[{'id':scope+'/providers/Microsoft.Network/networkSecurityGroups/demo','properties':{'securityRules':[{'name':'web','properties':{'access':'Allow','direction':'Inbound','protocol':'Tcp','sourceAddressPrefix':'Internet','destinationPortRange':'443'}}]}}],
   'managed_identity_federated_credential':[{'id':scope+'/providers/Microsoft.ManagedIdentity/userAssignedIdentities/demo/federatedIdentityCredentials/gh','properties':{'issuer':'https://token.actions.githubusercontent.com','subject':'repo:acme/app:ref:refs/heads/main','audiences':['api://AzureADTokenExchange']}}],
   'app_service':[{'id':app,'properties':{'defaultHostName':'demo.azurewebsites.net','publicNetworkAccess':'Enabled','httpsOnly':True}}],
   'app_service_config':[{'id':app+'/config/web','parent_id':app,'properties':{'ipSecurityRestrictions':[],'ipSecurityRestrictionsDefaultAction':'Allow'}}]}
 else:
  facts={'clusterrole':[{'metadata':{'name':'demo'},'rules':[{'apiGroups':['*'],'resources':['*'],'verbs':['*']}],'Usage':usage}],
   'clusterrolebinding':[{'metadata':{'name':'demo'},'roleRef':{'kind':'ClusterRole','name':'demo'},'subjects':[{'kind':'Group','name':'system:unauthenticated'}]}],
   'networkpolicy':[{'metadata':{'name':'web','namespace':'apps'},'spec':{'policyTypes':['Ingress'],'ingress':[{'from':[{'ipBlock':{'cidr':'0.0.0.0/0'}}],'ports':[{'protocol':'TCP','port':443}]}]}}],
   'service':[{'metadata':{'name':'web','namespace':'apps'},'spec':{'type':'LoadBalancer','ports':[{'protocol':'TCP','port':443}]},'status':{'loadBalancer':{'ingress':[{'ip':'8.8.8.8'}]}}}]}
 collections=[{'type':kind,'scope':scope,'service':kind,'status':'collected','items':items}for kind,items in facts.items()]
 return make_snapshot(provider,[scope],collections,metadata=metadata,created_at='2026-10-19T00:00:00+00:00')


@pytest.mark.parametrize('provider',['aws','gcp','azure','k8s'])
def test_every_supported_analysis_variant_uses_actual_producer_evidence(provider):
    snapshot=provider_snapshot(provider);before=deepcopy(snapshot)
    findings=analyze_findings(snapshot)
    expected={'analysis.grant_review','analysis.principal_exposure','analysis.network_review','analysis.inactive_identity','analysis.coverage','analysis.internet_exposure'}
    if provider!='k8s':expected.add('analysis.federated_trust')
    if provider=='gcp':expected.add('analysis.gcp_public_iam')
    assert {f['check_id'] for f in findings}==expected
    for finding in findings:
        original=deepcopy(finding)
        text=evidence_summary(finding) or finding['evidence'].get('observed')
        assert text and len(text)<=360, finding
        assert 'supplied records' not in text and 'More recorded details' not in text
        assert finding==original
    assert snapshot==before


@pytest.mark.parametrize('provider',['gcp','azure','k8s'])
def test_provider_identity_observations_reject_missing_or_wrong_native_witness(provider):
    from peaso.analysis.provider_observed_evidence import evidence_summary as provider_summary
    for cid in ('analysis.principal_exposure','analysis.federated_trust'):
        for malformed in ({},None,[],False):
            assert provider_summary({'provider':provider,'check_id':cid,'status':'FAIL','evidence':malformed}) is None
    for f in analyze_findings(provider_snapshot(provider)):
        if f['check_id'] not in ('analysis.principal_exposure','analysis.federated_trust'):continue
        malformed={**f,'evidence':{k:([None] if isinstance(v,dict) else {}) for k,v in f['evidence'].items()}}
        assert provider_summary(malformed) is None


def test_no_condition_is_not_claimed_as_a_validated_cel_restriction():
    snap=deepcopy(provider_snapshot('gcp'))
    collection=next(c for c in snap['collections'] if c['type']=='workload_identity_provider')
    collection['items'][0]['attributeCondition']="assertion.repository_owner == 'acme'"
    found=next(f for f in analyze_findings(snap) if f['check_id']=='analysis.federated_trust')
    assert found['status']=='MANUAL'
    assert evidence_summary(found)=='The workload identity provider declares an attribute condition to limit token exchange; its CEL logic and effective IAM access still need review.'


def test_public_gcp_binding_requires_matching_native_member_not_only_classification():
    from peaso.analysis.provider_observed_evidence import evidence_summary as provider_summary
    f=deepcopy(next(f for f in analyze_findings(provider_snapshot('gcp')) if f['check_id']=='analysis.principal_exposure'))
    f['evidence']['principals'][0]['native_grant']['members']=['user:private@example.test']
    assert provider_summary(f) is None


def test_external_azure_principal_requires_actual_matching_tenant():
    from peaso.analysis.provider_observed_evidence import evidence_summary as provider_summary
    f=deepcopy(next(f for f in analyze_findings(provider_snapshot('azure')) if f['check_id']=='analysis.principal_exposure'))
    f['evidence']['principals'][0]['native_grant'].pop('tenantId')
    assert provider_summary(f) is None


@pytest.mark.parametrize('identity,expected_status,phrase',[
    ('arn:aws:iam::444455556666:root','FAIL','outside the trusted account scope'),
    ('AROAEXAMPLEUNATTRIBUTED','UNKNOWN','ownership could not be resolved'),
])
def test_aws_native_role_external_and_unattributed_principals_have_concrete_explanations(identity,expected_status,phrase):
    snapshot=provider_snapshot('aws')
    role=next(c for c in snapshot['collections'] if c['type']=='iam_role')['items'][0]
    role['AssumeRolePolicyDocument']['Statement']=[{'Effect':'Allow','Principal':{'AWS':identity},'Action':'sts:AssumeRole'}]
    finding=next(f for f in analyze_findings(snapshot) if f['check_id']=='analysis.principal_exposure')
    assert finding['status']==expected_status
    explanation=evidence_summary(finding)
    assert identity in explanation and 'sts:AssumeRole' in explanation and phrase in explanation
    finding=deepcopy(finding)
    finding['evidence']['principals'][0]['native_grant']['Effect']='Deny'
    assert evidence_summary(finding) is None


@pytest.mark.parametrize('provider',['aws','gcp','azure','k8s'])
def test_high_impact_summary_names_actual_permissions_and_rejects_malformed_grant(provider):
    from peaso.analysis.finding_clarity import evidence_summary as explain
    finding=next(f for f in analyze_findings(provider_snapshot(provider)) if f['check_id']=='analysis.grant_review')
    text=explain(finding)
    assert {'aws':'all actions','gcp':'the Editor role','azure':'all management actions','k8s':'every action'}[provider] in text
    assert 'policies' in text and 'usable access' in text
    finding['evidence']['grants'][0]['native_grant']={'Effect':'Deny','Action':'*','Resource':'*'}
    assert explain(finding) is None


def test_conditional_grant_explains_restrictions_without_claiming_effective_access():
    snapshot=provider_snapshot('aws')
    policy=next(c for c in snapshot['collections'] if c['type']=='iam_policy')['items'][0]
    policy['PolicyDocument']['Statement'][0]['Condition']={'StringEquals':{'aws:RequestedRegion':'us-east-1'}}
    finding=next(f for f in analyze_findings(snapshot) if f['check_id']=='analysis.grant_review')
    assert 'recorded restrictions' in evidence_summary(finding)


def test_aws_federation_does_not_repeat_a_problem_contradicted_by_native_conditions():
    from peaso.analysis.finding_clarity import evidence_summary as explain
    finding=next(f for f in analyze_findings(provider_snapshot('aws')) if f['check_id']=='analysis.federated_trust')
    trust=finding['evidence']['federated_trusts'][0]
    trust['conditions']['StringEquals'][trust['issuer']+':sub']='repo:approved/app:ref:refs/heads/main'
    assert explain(finding) is None


def test_raw_observed_code_cannot_create_an_internet_path_claim():
    from peaso.finding_observation import evidence_summary as dispatch
    assert dispatch({'check_id':'analysis.internet_exposure','provider':'aws','status':'FAIL','evidence':{'observed':'000000'}}) is None
    from peaso.analysis.finding_clarity import evidence_summary as explain
    assert explain({'check_id':'analysis.internet_exposure','provider':'aws','status':'FAIL','evidence':{'observed':'000000'}}) is None
    finding=next(f for f in analyze_findings(provider_snapshot('aws'))
                 if f['check_id']=='analysis.internet_exposure' and f['evidence'].get('exposure_kind')=='api')
    finding['evidence']['path']=[{'layer':'authorization','decision':'block'}]
    explanation = explain(finding)
    assert explanation is not None and 'cannot be resolved' in explanation
    assert 'configured to accept internet traffic' not in explanation


def test_gcp_aws_federation_names_the_native_account_and_keeps_exchange_limits():
    snapshot=provider_snapshot('gcp')
    row=next(c for c in snapshot['collections'] if c['type']=='workload_identity_provider')['items'][0]
    row.pop('oidc');row['aws']={'accountId':'444455556666'}
    finding=next(f for f in analyze_findings(snapshot) if f['check_id']=='analysis.federated_trust')
    text=evidence_summary(finding)
    assert 'AWS account 444455556666' in text
    assert 'no attribute condition' in text and 'IAM bindings still govern access' in text


@pytest.mark.parametrize('provider,expected',[
    ('gcp','the Editor role to anyone, including anonymous users'),
    ('azure','all management actions'),
    ('k8s','every action on every Kubernetes resource'),
])
def test_wildcard_and_public_grants_are_explained_in_words(provider,expected):
    finding=next(f for f in analyze_findings(provider_snapshot(provider)) if f['check_id']=='analysis.grant_review')
    text=evidence_summary(finding)
    assert expected in text
    assert 'permits *' not in text and '* on *' not in text
    assert 'policies' in text


def test_inventory_gaps_explain_missing_and_denied_reads_as_sentences():
    from peaso.analysis.finding_clarity import evidence_summary as explain
    finding={'check_id':'analysis.coverage','status':'UNKNOWN','provider':'aws','evidence':{'gaps':[{'type':'iam_user','status':'not_collected'},{'type':'iam_role','status':'denied'}]}}
    text=explain(finding)
    assert 'lacks complete inventory for IAM users' in text
    assert 'reads were denied for IAM roles' in text
    assert '(not collected)' not in text and '(read denied)' not in text


def test_azure_action_exclusions_are_explained_without_claiming_unrestricted_access():
    snapshot=provider_snapshot('azure')
    definition=next(c for c in snapshot['collections'] if c['type']=='role_definition')['items'][0]
    definition['properties']['permissions'][0]['notActions']=['Microsoft.Authorization/*']
    finding=next(f for f in analyze_findings(snapshot) if f['check_id']=='analysis.grant_review')
    text=evidence_summary(finding)
    assert 'all management actions, subject to the recorded exclusions' in text
    assert 'recorded restrictions' in text
    assert 'and subject' not in text
