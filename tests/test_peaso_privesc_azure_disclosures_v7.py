"""Exact metadata-only disclosure proofs never become principal control."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path

import pytest

from peaso import privesc
from peaso.privesc.effective_permissions.azure_disclosure_effects import CONTRACT, _ACTION_TYPES, UNSUPPORTED_DISCLOSURES
from peaso.privesc.schema import expand_requires, validate_entry
from peaso.privesc import versioned_catalog as vc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import az, SUB, RG, ROLE_ID

# These terminal disclosure rules are historical fixtures, not active escalations.
_PRIOR_ENTRIES, _PRIOR_HASHES = vc._verified_prior()
ENTRIES = [_PRIOR_ENTRIES[ident] for ident in CONTRACT]
CASES = [(entry,index) for entry in ENTRIES for index,_ in enumerate(expand_requires(entry['requires']))]
NOW='2026-10-15T01:00:00+00:00'
SOURCE='u-alice'


def _col(kind,scope,rows,status=None):
    return {'type':kind,'scope':scope,'service':'reviewed_metadata','status':status or ('collected' if rows else 'empty'),'items':rows,'error':None}


def case(entry,index=0):
    path=expand_requires(entry['requires'])[index]
    types=_ACTION_TYPES[path[0]['action'].casefold()].split('/')
    resource=RG+'/providers/'+types[0]+'/'+ '/'.join(part+'/test' for part in types[1:])
    if entry['service']=='app_services':resource='/providers/Microsoft.Web/sourcecontrols/GitHub'
    scope='/' if entry['service']=='app_services' else resource
    actions=[r['action'] for r in path if not r.get('data_action')]
    data=[r['action'] for r in path if r.get('data_action')]
    rows=[{'id':resource,'type':'/'.join(types)}]
    metadata={'TechniqueId':entry['id'],'ResourceId':resource,'ResourceType':'/'.join(types),
              'SecretConfigured':True,'CredentialReferenceId':'opaque-configured-credential-1',
              'CustomerTenantId':'t','EvidenceRef':'reviewed-safe-reference-1',
              '_provenance':{'source':'reviewed_metadata_only','read_only':True,'values_omitted':True,'observed_at':NOW}}
    extra=[]
    if entry['service']=='app_services':
        metadata.update(ProviderGlobal=True,NativeResource={'id':resource,'type':'Microsoft.Web/sourcecontrols','name':'GitHub'})
        metadata['_provenance']['source_operation']='SourceControls_Get'
        rows=[]
    if entry['service']=='service_fabric':
        vault=RG+'/providers/Microsoft.KeyVault/vaults/test';cluster=RG+'/providers/Microsoft.ServiceFabric/clusters/test'
        resource=vault+'/secrets/client-cert';scope=resource;metadata['ResourceId']=resource
        thumb='ab'*20;cert='https://test.vault.azure.net/certificates/client-cert/version1'
        secret='https://test.vault.azure.net/secrets/client-cert/version2'
        rows=[{'id':vault,'type':'Microsoft.KeyVault/vaults','properties':{'vaultUri':'https://test.vault.azure.net/','enableRbacAuthorization':True}},
              {'id':cluster,'type':'Microsoft.ServiceFabric/clusters','properties':{'certificate':{'thumbprint':thumb}}}]
        metadata['CertificateLink']={'ClusterId':cluster,'VaultId':vault,'SecretVersionId':secret,
                                     'CertificateVersionId':cert,'CertificateThumbprint':thumb}
        extra.append(_col('azure_disclosure_certificate_metadata',vault,[{'id':cert,'sid':secret,'parent_id':vault,
              'x5t':base64.urlsafe_b64encode(bytes.fromhex(thumb)).decode().rstrip('='),
              'policy':{'key_props':{'exportable':True}},'_provenance':{'source_operation':'Certificates_Get',
              'request_uri':cert,'read_only':True,'values_omitted':True,'observed_at':NOW}}]))
    snap=az(assignments=[(SOURCE,'User',scope,ROLE_ID)],roles={ROLE_ID:(actions,data)},graph=rows)
    snap['created_at']=NOW
    fact={'TechniqueId':entry['id'],'SourceId':SOURCE,'TargetKind':'azure_verified_authority','TargetId':resource,
          'TargetScope':scope,'Status':'verified','VerifiedPreconditions':True,'EffectType':'terminal_configuration_disclosure',
          'EvidenceRef':metadata['EvidenceRef'],'VerifiedConditionIds':CONTRACT[entry['id']]['conditions'],
          'EvidenceObservedAt':NOW,'CredentialReferenceId':metadata['CredentialReferenceId'],'CustomerTenantId':'t',
          'ActionResources':{r['action']:[scope] for r in path}}
    snap['collections'] += extra+[_col('azure_disclosure_source_metadata',scope,[metadata]),
                                 _col('azure_privesc_challenge_evidence',scope,[fact])]
    return snap,fact,metadata


def run(snap,entry):
    return privesc.analyze(snap,entries=[entry])


def conditional(snap,entry):
    return {target:confidence for target,confidence in reached(run(snap,entry),SOURCE,entry['id']).items() if confidence=='conditional'}


@pytest.mark.parametrize('entry,index',[(e,i) for e,i in CASES if e['id'] not in UNSUPPORTED_DISCLOSURES and e['service']!='app_services'])
def test_every_exact_action_path_is_terminal_and_snapshot_immutable(entry,index):
    snap,_,_=case(entry,index);before=copy.deepcopy(snap)
    assert validate_entry({k:v for k,v in entry.items() if k!='_file'})[0]==[]
    result=run(snap,entry);targets={k:v for k,v in reached(result,SOURCE,entry['id']).items() if v=='conditional'}
    assert len(targets)==1 and set(targets.values())=={'conditional'},result
    assert snap==before
    assert all(f['status']!='FAIL' for f in result['findings'])
    assert not any(edge['source'] in targets for edge in result['graph']['edges'])
    assert not any(target in ('u-admin','u-alice') for target in targets)
    assert entry['target']['outcome']=='bounded_authority'


@pytest.mark.parametrize('entry',ENTRIES,ids=lambda e:e['id'])
@pytest.mark.parametrize('mutation',[
 {'EvidenceRef':''},{'VerifiedConditionIds':[]},{'VerifiedConditionIds':[{}]},
 {'VerifiedPreconditions':False},{'EffectType':'principal_control'},{'Status':'disproven'},
 {'CustomerTenantId':'foreign'},{'CredentialReferenceId':'other'},
 {'EvidenceObservedAt':'2020-01-01T00:00:00Z'},{'EvidenceObservedAt':'2026-10-15T01:00:01Z'},
 {'ActionResources':{}},{'TargetId':'/subscriptions/00000000-0000-0000-0000-00000000bbbb/resourceGroups/rg/providers/Microsoft.App/agents/foreign'},
 {'details':{'private_key':'forbidden-fixture-value'}}])
def test_unbound_foreign_stale_wrong_effect_and_value_inputs_do_not_authorize(entry,mutation):
    snap,fact,_=case(entry);fact.update(mutation)
    assert not conditional(snap,entry)


@pytest.mark.parametrize('entry',ENTRIES,ids=lambda e:e['id'])
@pytest.mark.parametrize('mutation',[
 {'SecretConfigured':False},{'ResourceType':None},{'CustomerTenantId':'other'},{'CredentialReferenceId':'other'},
 {'_provenance':{}},{'EvidenceRef':'different'},{'nested':{'access_key':'forbidden-fixture-value'}}])
def test_missing_or_wrong_source_metadata_cannot_authorize(entry,mutation):
    snap,_,metadata=case(entry);metadata.update(mutation)
    assert not conditional(snap,entry)


@pytest.mark.parametrize('entry',ENTRIES,ids=lambda e:e['id'])
def test_effective_permission_is_independent_of_reviewed_metadata(entry):
    for grant_scope in (SUB+'/resourceGroups/other','/subscriptions/00000000-0000-0000-0000-00000000bbbb'):
        snap,_,_=case(entry)
        col=next(c for c in snap['collections'] if c['type']=='role_assignment')
        col['items'][0]['properties']['scope']=grant_scope
        assert not conditional(snap,entry)
    snap,_,_=case(entry)
    next(c for c in snap['collections'] if c['type']=='role_assignment')['items']=[]
    assert not conditional(snap,entry)


@pytest.mark.parametrize('entry',ENTRIES,ids=lambda e:e['id'])
@pytest.mark.parametrize('kind',['azure_privesc_challenge_evidence','azure_disclosure_source_metadata'])
def test_partial_duplicate_or_missing_evidence_stays_unknown(entry,kind):
    for mode in ('partial','denied','duplicate','missing'):
        snap,_,_=case(entry);col=next(c for c in snap['collections'] if c['type']==kind)
        if mode=='duplicate':col['items']*=2
        elif mode=='missing':snap['collections'].remove(col)
        else:col['status']=mode
        assert not conditional(snap,entry)


@pytest.mark.parametrize('entry',[e for e in ENTRIES if e['service'] not in ('app_services','service_fabric')],ids=lambda e:e['id'])
def test_wrong_or_uncollected_native_resource_type_stays_unknown(entry):
    for mode in ('wrong_type','foreign','duplicate','partial','missing'):
        snap,_,_=case(entry);col=next(c for c in snap['collections'] if c['type']=='resource_graph')
        if mode=='wrong_type':col['items'][0]['type']='Microsoft.Compute/virtualMachines'
        elif mode=='foreign':col['items'][0]['id']+='-foreign'
        elif mode=='duplicate':col['items']*=2
        elif mode=='partial':col['status']='partial'
        else:snap['collections'].remove(col)
        assert not conditional(snap,entry)


def test_provider_global_source_control_is_not_covered_by_subscription_role():
    entry=next(e for e in ENTRIES if e['service']=='app_services')
    snap,_,metadata=case(entry)
    next(c for c in snap['collections'] if c['type']=='role_assignment')['items'][0]['properties']['scope']=SUB
    assert not conditional(snap,entry)
    snap,_,metadata=case(entry);metadata['NativeResource']['id']+='/other'
    assert not conditional(snap,entry)


@pytest.mark.parametrize('field,value',[
 ('sid','https://test.vault.azure.net/secrets/other/version2'),('id','https://other.vault.azure.net/certificates/client-cert/version1'),
 ('x5t','different'),('policy',{'key_props':{'exportable':False}}),('parent_id',RG+'/providers/Microsoft.KeyVault/vaults/other'),
 ('_provenance',{}),('secret_value','forbidden-fixture-value')])
def test_service_fabric_requires_real_exact_exportable_certificate_secret_link(field,value):
    entry=next(e for e in ENTRIES if e['service']=='service_fabric');snap,_,_=case(entry)
    next(c for c in snap['collections'] if c['type']=='azure_disclosure_certificate_metadata')['items'][0][field]=value
    assert not conditional(snap,entry)


def test_service_fabric_cannot_substitute_cluster_or_vault_identity():
    entry=next(e for e in ENTRIES if e['service']=='service_fabric')
    for mode in ('cluster_thumbprint','vault_uri','no_certificate_metadata'):
        snap,_,_=case(entry)
        rows=next(c for c in snap['collections'] if c['type']=='resource_graph')['items']
        if mode=='cluster_thumbprint':rows[1]['properties']['certificate']['thumbprint']='cd'*20
        elif mode=='vault_uri':rows[0]['properties']['vaultUri']='https://other.vault.azure.net/'
        else:snap['collections']=[c for c in snap['collections'] if c['type']!='azure_disclosure_certificate_metadata']
        assert not conditional(snap,entry)


def test_historical_disclosure_binding_preserves_archived_meanings():
    current={e['id']:e for e in privesc.load_catalog()['entries']}
    assert current and len(_PRIOR_ENTRIES)==1234
    assert len(ENTRIES)==len(CONTRACT)==7
    assert not set(CONTRACT)&set(current)
    prior=json.loads(vc.PRIOR_DISCLOSURE_HISTORY.read_text())
    assert len(prior['sha256'])==253
    assert hashlib.sha256(vc.PRIOR_DISCLOSURE_HISTORY.read_bytes()).hexdigest()==vc.PRIOR_DISCLOSURE_MANIFEST
    for name,digest in prior['sha256'].items():
        assert _PRIOR_HASHES[name]==digest
    binding={'schema':vc.BINDING_SCHEMA,'manifest_sha256':vc.PRIOR_DISCLOSURE_MANIFEST,
             'effective_tree_sha256':vc.PRIOR_DISCLOSURE_TREE,'source_revision':vc.V4_REVISION}
    retained,status=vc.lookup_entries(list(_PRIOR_ENTRIES),binding)
    assert status=='exact_bounded_v5' and len(retained)==1227
    assert not set(CONTRACT)&set(retained)
    assert all(retained[key]==_PRIOR_ENTRIES[key] for key in retained)
    got,status=vc.lookup_entries(list(current),vc.current_binding())
    assert set(got)==set(current) and status=='exact_strict_privesc'
    assert vc.lookup_entries(list(CONTRACT),dict(binding,manifest_sha256='wrong'))==({},'unknown_catalog_manifest')


def test_no_claim_of_standard_native_disclosure_collection():
    assert all(spec['normal_collector_status']=='not_collected' for spec in CONTRACT.values())
    for entry in ENTRIES:
        snap,_,_=case(entry)
        snap['collections']=[c for c in snap['collections'] if c['type'] not in ('azure_disclosure_source_metadata','azure_disclosure_certificate_metadata')]
        assert not conditional(snap,entry)


@pytest.mark.parametrize('entry,index',CASES,ids=[e['id']+':'+str(i) for e,i in CASES])
def test_control_and_data_permissions_are_not_interchangeable(entry,index):
    snap,_,_=case(entry,index)
    permissions=next(c for c in snap['collections'] if c['type']=='role_definition')['items'][0]['properties']['permissions'][0]
    permissions['actions'],permissions['dataActions']=permissions['dataActions'],permissions['actions']
    assert not conditional(snap,entry)


@pytest.mark.parametrize('entry',[e for e in ENTRIES if e['service']!='app_services'],ids=lambda e:e['id'])
def test_native_resource_does_not_join_an_unlisted_or_foreign_tenant_subscription(entry):
    for mutation in ('missing','foreign_tenant','duplicate','partial'):
        snap,_,_=case(entry)
        col=next(c for c in snap['collections'] if c['type']=='subscription')
        if mutation=='missing':snap['collections'].remove(col)
        elif mutation=='foreign_tenant':col['items'][0]['tenantId']='foreign'
        elif mutation=='duplicate':col['items']*=2
        else:col['status']='partial'
        assert not conditional(snap,entry)


def test_provider_global_native_projection_rejects_malformed_type_and_scope():
    entry=next(e for e in ENTRIES if e['service']=='app_services')
    for mutation in ({'type':None},{'name':'other'},{'id':'/providers/Microsoft.Web/sourcecontrols/Other'}):
        snap,_,metadata=case(entry);metadata['NativeResource'].update(mutation)
        assert not conditional(snap,entry)


def test_service_fabric_rejects_stale_native_certificate_projection():
    entry=next(e for e in ENTRIES if e['service']=='service_fabric');snap,_,_=case(entry)
    next(c for c in snap['collections'] if c['type']=='azure_disclosure_certificate_metadata')['items'][0]['_provenance']['observed_at']='2020-01-01T00:00:00Z'
    assert not conditional(snap,entry)


def test_every_uncollected_adapter_is_explicit_in_normal_scan_coverage():
    for entry in ENTRIES:
        snap,_,_=case(entry)
        snap['collections']=[c for c in snap['collections'] if c['type'] not in ('azure_privesc_challenge_evidence','azure_disclosure_source_metadata','azure_disclosure_certificate_metadata')]
        result=run(snap,entry)
        rows=[r for r in result['coverage'] if r['kind']=='adapter' and entry['id'] in r['reason']]
        assert len(rows)==1 and rows[0]['status']=='not_collected'
        assert not any(f['status']=='FAIL' for f in result['findings'])


def test_apm_property_names_never_establish_secret_value_disclosure():
    from peaso.privesc.effective_permissions.azure import AzureModel
    from peaso.privesc.effective_permissions.azure_disclosure_effects import valid, UNSUPPORTED_DISCLOSURES
    technique='azure-spring-apps-microsoftappplatformspringapmslistsecretkeysaction'
    entry=next(e for e in ENTRIES if e['id']==technique)
    snap,fact,metadata=case(entry)
    # This formerly passed: exact native resource/type, fresh reviewed customer
    # and credential joins, configured-secret assertion, and effective action.
    assert metadata['SecretConfigured'] is True and fact['VerifiedPreconditions'] is True
    assert fact['Status']=='verified' and fact['CustomerTenantId']=='t'
    model=AzureModel(snap)
    action=CONTRACT[technique]['requires']['all_of'][0]['action']
    grant=model.check(model.principals[SOURCE],{'action':action},fact['TargetScope'])
    assert grant is not None and grant.confidence!='unknown'
    assert not valid(model,technique,fact,SOURCE,fact['TargetId'],fact['TargetScope'])
    result=run(snap,entry)
    assert not reached(result,SOURCE,technique), result
    assert not model.exact_source_matches(technique,model.principals[SOURCE])
    assert model.exact_targets_for('azure_verified_authority',{'azure_challenge_fact':technique})==[]
    rows=[r for r in result['coverage'] if r['kind']=='adapter' and technique in r['reason']]
    assert len(rows)==1 and rows[0]['status']=='not_collected'
    assert 'sensitive_property_names_only' in rows[0]['reason']
    assert 'not their values' in UNSUPPORTED_DISCLOSURES[technique]


@pytest.mark.parametrize('technique,path_index',[
    ('azure-spring-apps-config-server-bindings-secret-exposure',0),
    ('azure-spring-apps-config-server-bindings-secret-exposure',1),
    ('azure-spring-apps-config-server-bindings-secret-exposure',2),
    ('azure-service-linker-read-connection-configuration-to-exfiltrate-the-backing-secret',0),
    ('azure-service-linker-read-connection-configuration-to-exfiltrate-the-backing-secret',1),
    ('azure-sre-agent-microsoftappagentsdataconnectorslistsecretsaction',0),
    ('azure-sre-agent-microsoftappagentslistsecretsaction',0),
])
def test_redacted_reference_or_cross_plane_metadata_never_establishes_disclosure(technique,path_index):
    from peaso.privesc.effective_permissions.azure import AzureModel
    from peaso.privesc.effective_permissions.azure_disclosure_effects import valid
    entry=next(e for e in ENTRIES if e['id']==technique)
    snap,fact,metadata=case(entry,path_index)
    assert metadata['SecretConfigured'] is True and fact['VerifiedPreconditions'] is True
    assert fact['Status']=='verified' and fact['CustomerTenantId']=='t'
    model=AzureModel(snap)
    # Every action in the formerly accepted path really is granted on the exact
    # typed resource, including the separate Spring data-action branch.
    for requirement in expand_requires(entry['requires'])[path_index]:
        grant=model.check(model.principals[SOURCE],{'action':requirement['action'],
                          'data_action':bool(requirement.get('data_action'))},fact['TargetScope'])
        assert grant is not None and grant.confidence!='unknown'
    assert not valid(model,technique,fact,SOURCE,fact['TargetId'],fact['TargetScope'])
    result=run(snap,entry)
    assert not reached(result,SOURCE,technique),result
    assert not model.exact_source_matches(technique,model.principals[SOURCE])
    assert model.exact_targets_for('azure_verified_authority',{'azure_challenge_fact':technique})==[]
    rows=[r for r in result['coverage'] if r['kind']=='adapter' and technique in r['reason']]
    assert len(rows)==1 and rows[0]['status']=='not_collected'
    assert UNSUPPORTED_DISCLOSURES[technique].split(':',1)[0] in rows[0]['reason']


def test_unsupported_value_disclosure_guards_are_exact_not_family_wide():
    assert set(UNSUPPORTED_DISCLOSURES)=={
        'azure-spring-apps-microsoftappplatformspringapmslistsecretkeysaction',
        'azure-spring-apps-config-server-bindings-secret-exposure',
        'azure-service-linker-read-connection-configuration-to-exfiltrate-the-backing-secret',
        'azure-sre-agent-microsoftappagentsdataconnectorslistsecretsaction',
        'azure-sre-agent-microsoftappagentslistsecretsaction'}
    retained={'app_services','service_fabric'}
    assert all(e['id']not in UNSUPPORTED_DISCLOSURES for e in ENTRIES if e['service']in retained)


@pytest.mark.parametrize('mode',[None,False])
def test_fabric_rbac_data_action_cannot_authorize_access_policy_or_unknown_vault_mode(mode):
    from peaso.privesc.effective_permissions.azure import AzureModel
    from peaso.privesc.effective_permissions.azure_disclosure_effects import valid
    entry=next(e for e in ENTRIES if e['service']=='service_fabric')
    snap,fact,metadata=case(entry)
    vault=metadata['CertificateLink']['VaultId']
    for env in snap['collections']:
        if env['type']=='resource_graph':
            for row in env['items']:
                if row['id']==vault:
                    if mode is None:row['properties'].pop('enableRbacAuthorization')
                    else:row['properties']['enableRbacAuthorization']=mode
    model=AzureModel(snap)
    grant=model.check(model.principals[SOURCE],{'action':'Microsoft.KeyVault/vaults/secrets/getSecret/action','data_action':True},fact['TargetScope'])
    assert grant is not None and grant.confidence!='unknown'
    assert metadata['SecretConfigured'] is True and fact['Status']=='verified'
    assert not valid(model,entry['id'],fact,SOURCE,fact['TargetId'],fact['TargetScope'])
    result=run(snap,entry)
    assert not {target:confidence for target,confidence in reached(result,SOURCE,entry['id']).items() if confidence!='unknown'}
    assert any(row['status']=='not_collected'for row in result['coverage']if row['kind']=='adapter')
