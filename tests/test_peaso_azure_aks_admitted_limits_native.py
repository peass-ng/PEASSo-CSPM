# Historical fixture contracts; current native admission is tested separately.
"""Directed native admitted resource-limit projection acceptance."""
import copy,json
from types import SimpleNamespace
import pytest
from peaso.collectors import azure,k8s,azure_aks_workloads_native as native
from peaso.collectors.azure_aks_admitted_limits_native import project
from tests.archived_check_contract import collect_snapshot, evaluate_snapshot
from peaso.server.validation import validate_connector
from peaso.checks.compliance_new_sw25_facts import APPARMOR_ID
from tests.test_peaso_azure_aks_workloads_native import ca,fixture,RID,TOKEN
from tests.test_peaso_azure_bulk_native import Transport,SUB,envelope


def capture(monkeypatch,ca,mode='good'):
    base_mode=mode if mode in {'denied','partial','uid_changed','foreign_namespace','resource_cap','call_cap','duplicate_pod'} else 'good'
    routes,responses,options,auth,Api=fixture(ca,base_mode)
    owner=options['compliance_parameters'][native.OPTION]['subscriptions'][0]
    owner['limits']={'maxCpu':'2','maxMemory':'2Gi','containerKinds':['containers','initContainers','ephemeralContainers']}
    pod=responses['/api/v1/pods'][0]
    pod['spec']['containers'][0]['resources']={'limits':{'cpu':'1','memory':'1Gi'}}
    limits=pod['spec']['containers'][0]['resources']['limits']
    if mode=='exceeds':limits['cpu']='3'
    if mode=='missing':limits.pop('memory')
    if mode=='malformed':limits['cpu']='invalid'
    if mode=='init_missing':pod['spec']['initContainers']=[{'name':'setup','resources':{'limits':{'cpu':'1'}}}]
    if mode=='ephemeral_missing':pod['spec']['ephemeralContainers']=[{'name':'debug'}]
    if mode=='no_policy':owner.pop('limits')
    if mode=='range_present':responses['/api/v1/limitranges']=[{'apiVersion':'v1','kind':'LimitRange','metadata':{'name':'defaults','namespace':'default','uid':'range-1','resourceVersion':'7'},'spec':{'limits':[{'type':'Container','default':{'cpu':'4','memory':'4Gi'}}]}}]
    arm=Transport(routes);arm.close=lambda:None;apis=[]
    def factory(context):
        api=Api();apis.append(api);return api
    monkeypatch.setattr(azure,'AzureTransport',lambda auth:arm)
    monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:arm)
    monkeypatch.setattr(k8s,'_new_api',factory)
    snap=collect_snapshot({'connector':{'provider':'azure','scopes':[SUB],'auth':auth,'options':options},'checks':[native.LIMITS]})
    status=evaluate_snapshot(snap,checks=[native.LIMITS])['findings'][0]['status']
    assert TOKEN not in json.dumps(snap) and 'private-workload-literal' not in json.dumps(snap)
    assert all(api.closed for api in apis)
    return snap,status,apis


@pytest.mark.parametrize('mode,expected',[
 ('good','PASS'),('exceeds','FAIL'),('range_present','PASS'),('missing','UNKNOWN'),('malformed','UNKNOWN'),
 ('init_missing','UNKNOWN'),('ephemeral_missing','UNKNOWN'),('no_policy','UNKNOWN'),('denied','DENIED'),
 ('partial','UNKNOWN'),('uid_changed','UNKNOWN'),('foreign_namespace','UNKNOWN'),('resource_cap','UNKNOWN'),
 ('call_cap','UNKNOWN'),('duplicate_pod','UNKNOWN')])
def test_public_capture_signed_limits(monkeypatch,ca,mode,expected):
    snap,status,apis=capture(monkeypatch,ca,mode)
    assert status==expected
    assert all(path in {'/api/v1/namespaces/kube-system','/api/v1/namespaces','/api/v1/pods','/api/v1/limitranges'} for api in apis for path,_ in api.calls)
    if mode in {'good','exceeds','range_present'}:
        row=envelope(snap,'pod_runtime')['items'][0]
        assert row['admissionEffectsResolved'] is True and row['limitRangeBindings']==[]
        assert not {'nodeOs','appArmorEnabled','runtimeDefaultSupported','kubernetesVersion'} & row.keys()
        assert sum(path=='/api/v1/pods' for api in apis for path,_ in api.calls)==1


@pytest.mark.parametrize('mode',['good','missing'])
def test_cannot_close_apparmor(monkeypatch,ca,mode):
    snap,_,_=capture(monkeypatch,ca,mode)
    snap['metadata']['sw25_policy'][APPARMOR_ID]={'scope':'/subscriptions/'+SUB,'allowedProfiles':[{'type':'RuntimeDefault'}],'nonLinuxApplies':False,'containerKinds':['containers']}
    snap.pop('snapshot_id',None)  # Re-seal this explicit normative-policy fixture change.
    assert evaluate_snapshot(snap,checks=[APPARMOR_ID])['findings'][0]['status']=='UNKNOWN'


@pytest.mark.parametrize('field,value',[('cluster_uid','foreign'),('cluster_id',RID+'foreign'),('source_operation','owner'),('representation','partial'),('read_only',False)])
def test_foreign_or_partial_provenance(monkeypatch,ca,field,value):
    snap,_,_=capture(monkeypatch,ca)
    pod=copy.deepcopy(envelope(snap,'pod')['items'][0]);uid=pod['_provenance']['cluster_uid'];pod['_provenance'][field]=value
    with pytest.raises(ValueError):project(pod,RID,uid)


@pytest.mark.parametrize('auth_mode',['local','cognito'])
def test_normative_only_owner_policy(ca,auth_mode):
    _,_,options,auth,_=fixture(ca);options['retries']=1
    options['compliance_parameters'][native.OPTION]['subscriptions'][0]['limits']={'maxCpu':'2','maxMemory':'2Gi','containerKinds':['containers']}
    validate_connector('azure',auth,options,SimpleNamespace(auth_mode=auth_mode))
    for key,value in [('admissionEffectsResolved',True),('pod_runtime',[]),('maxCpu','bad'),('containerKinds',['initContainers'])]:
        bad=copy.deepcopy(options);bad['compliance_parameters'][native.OPTION]['subscriptions'][0]['limits'][key]=value
        with pytest.raises(Exception):validate_connector('azure',auth,bad,SimpleNamespace(auth_mode=auth_mode))
