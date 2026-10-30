"""Actual public dispatch and intake with inert HTTP/native-shape unit responses."""
from collections import Counter
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from urllib.parse import urlsplit
import json

import pytest
from fastapi import HTTPException

from peaso.collectors import azure
from peaso.collectors import azure_nsg_ingress_native as native
from tests.archived_check_contract import collect_snapshot, evaluate_snapshot
from peaso.server.validation import validate_connector
from tests.test_peaso_azure_nsg_ingress_native import S, N, NIC, VNET, OPTIONS, topology, InertTransport, InertHTTPResponse


def options(age=30):
    out=deepcopy(OPTIONS)
    out['retries']=1
    out['concurrency']=1
    out['compliance_parameters'][native.NAMESPACE]['observed_at']=(datetime.now(timezone.utc)-timedelta(seconds=age)).isoformat()
    return out


def request(owner_options=None,scope=S):
    return {'connector':{'provider':'azure','scopes':[scope],
        'auth':{'method':'token','arm_token':'INERT-NOT-A-CREDENTIAL'},
        'options':options()if owner_options is None else owner_options},'checks':[native.CHECK]}


@pytest.mark.parametrize('freshness,age,expected',[('fresh',30,'PASS'),('stale',601,'UNKNOWN'),('future',-601,'UNKNOWN')])
def test_public_collect_dispatch_query_flow_and_real_engine(monkeypatch,freshness,age,expected):
    objects,groups,routes=topology()
    http=[];tokens=[];constructed=[]
    class Transport(InertTransport):
        def __init__(self,auth):
            constructed.append(deepcopy(auth));super().__init__(objects);self.closed=False
        def token(self,audience):
            assert not self.closed;tokens.append(audience);return 'INERT-NOT-A-CREDENTIAL'
        def close(self):self.closed=True
        def request(self,url,**kwargs):
            path=urlsplit(url).path.casefold()
            if path=='/providers/microsoft.resourcegraph/resources':
                assert kwargs.get('body',{}).get('subscriptions')==[S.rsplit('/',1)[1]]
                self.calls.append(url)
                return {'data':[deepcopy(v)for v in objects.values()if v.get('type')]}
            try:return super().request(url,**kwargs)
            except AssertionError:
                # Known unrelated metadata enrichments remain denied, not fabricated empty.
                from peaso.collectors.azure import AzureReadError
                raise AzureReadError('unit_unrelated_metadata_denied',403)from None
    class Opener:
        def open(self,req,timeout):
            http.append(req)
            path=urlsplit(req.full_url).path.casefold()
            if req.method=='GET':
                for kind,typ in native.TYPES.items():
                    if path==(S+'/providers/'+typ).casefold():
                        return InertHTTPResponse(200,{'value':[deepcopy(row)for row in objects.values()if row.get('type')==typ]})
                for rid,row in objects.items():
                    if rid.casefold()==path:return InertHTTPResponse(200,deepcopy(row))
                raise AssertionError('Unexpected bounded native GET '+req.full_url)
            assert req.method=='POST'
            if path==(NIC+'/effectiveNetworkSecurityGroups').casefold():return InertHTTPResponse(200,{'value':deepcopy(groups)})
            if path==(NIC+'/effectiveRouteTable').casefold():return InertHTTPResponse(200,{'value':deepcopy(routes)})
            if path==(VNET+'/listNetworkManagerEffectiveSecurityAdminRules').casefold():
                assert json.loads(req.data)=={}
                return InertHTTPResponse(200,{'value':[]})
            raise AssertionError('Unexpected query '+req.full_url)
    monkeypatch.setattr(azure,'AzureTransport',Transport);monkeypatch.setattr(azure,'AzureTransportExposure',Transport)
    monkeypatch.setattr(native,'build_opener',lambda *args:Opener())
    raw=options(age);before=deepcopy(raw)
    for mode in('local','cognito'):
        validate_connector('azure',request(raw)['connector']['auth'],raw,SimpleNamespace(auth_mode=mode))
    snapshot=collect_snapshot(request(raw))
    assert raw==before
    assert len(constructed)==1
    assert len(http)==len(tokens)
    assert Counter(urlsplit(req.full_url).path.casefold().rsplit('/',1)[-1] for req in http if req.method=='POST') == {
        'effectivenetworksecuritygroups':1, 'effectiveroutetable':2,
        'listnetworkmanagereffectivesecurityadminrules':3}
    assert len([req for req in http if req.method=='GET'])>=14 # Seven complete inventory universes before/after.
    paths=[c for c in snapshot['collections']if c['type']=='nsg_effective_internet_path']
    assert len(paths)==1 and paths[0]['status']=='collected',paths
    assert len(paths[0]['items'])==1
    assert snapshot['metadata']['collection_plan']['mode']=='dependencies'
    approval=snapshot['metadata'].get('compliance_policy',{}).get('sw31')
    if freshness=='fresh':assert approval=={'approvedInternetPorts':[443]}
    else:assert approval is None
    result=evaluate_snapshot(snapshot,checks=[native.CHECK])
    assert result['findings'] and {f['status']for f in result['findings']}=={expected}
    assert snapshot['metadata']['bulk_evidence']['unavailable_projections']==[]


@pytest.mark.parametrize('mode',['local','cognito'])
@pytest.mark.parametrize('kind',['null','observation','priority_payload','wrong_scope','bad_age','bad_time','flat_sw31'])
def test_public_intake_invalid_policy_precredential(mode,kind):
    raw=options();row=raw['compliance_parameters'][native.NAMESPACE]
    if kind=='null':raw['compliance_parameters'][native.NAMESPACE]=None
    elif kind=='observation':row['observed_paths']=[]
    elif kind=='priority_payload':row['nsg']={'defaultSecurityRules':[]}
    elif kind=='wrong_scope':row['scope']='https://evil.invalid'
    elif kind=='bad_age':row['max_age_seconds']=True
    elif kind=='bad_time':row['observed_at']='yesterday'
    elif kind=='flat_sw31':raw['compliance_policy']={'sw31':{'approvedInternetPorts':[22]}}
    with pytest.raises(HTTPException)as error:
        validate_connector('azure',{},raw,SimpleNamespace(auth_mode=mode))
    assert error.value.status_code==422


@pytest.mark.parametrize('mode',['local','cognito'])
@pytest.mark.parametrize('provider',['aws','gcp','k8s'])
def test_public_intake_namespace_provider_boundary(mode,provider):
    with pytest.raises(HTTPException)as error:
        validate_connector(provider,{},options(),SimpleNamespace(auth_mode=mode))
    assert error.value.status_code==422


@pytest.mark.parametrize('kind',['null','observation','flat_sw31','foreign','wildcard'])
def test_public_dispatch_invalid_or_mismatched_owner_before_transport(monkeypatch,kind):
    attempts=[]
    def forbidden(*args,**kwargs):attempts.append(True);raise AssertionError('Credential construction must not run')
    monkeypatch.setattr(azure,'AzureTransport',forbidden);monkeypatch.setattr(azure,'AzureTransportExposure',forbidden)
    raw=options();scope=S
    if kind=='null':raw['compliance_parameters'][native.NAMESPACE]=None
    elif kind=='observation':raw['compliance_parameters'][native.NAMESPACE]['paths']=[]
    elif kind=='flat_sw31':raw['compliance_policy']={'sw31':{'approvedInternetPorts':[22]}}
    elif kind=='foreign':scope='/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    elif kind=='wildcard':scope='*'
    with pytest.raises(ValueError):collect_snapshot(request(raw,scope))
    assert attempts==[]


def test_early_nsg_refresh_retains_real_later_diagnostics_and_flow_logs(monkeypatch):
    """One combined public collection: generation refresh must precede enrichers."""
    objects,groups,routes=topology()
    watcher=S+'/resourceGroups/rg/providers/Microsoft.Network/networkWatchers/w'
    flow=watcher+'/flowLogs/fresh'
    diagnostic=N+'/providers/Microsoft.Insights/diagnosticSettings/fresh'
    objects[watcher]={'id':watcher,'type':'Microsoft.Network/networkWatchers',
        'etag':'"watcher"','properties':{}}
    generic=deepcopy(objects)
    generic[N]['etag']='"initial-before-refresh"'
    objects[N]['etag']='"native-refreshed"'
    logrow={'id':flow,'name':'fresh','type':'Microsoft.Network/networkWatchers/flowLogs','properties':{'enabled':True,'targetResourceId':N,
        'format':{'type':'JSON','version':2}}}
    diagrow={'id':diagnostic,'name':'fresh','properties':{
        'workspaceId':S+'/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/logs',
        'logs':[{'category':'NetworkSecurityGroupEvent','enabled':True}], 'metrics':[]}}
    generic_nsg_get=[];bounded_nsg_get=[];query_calls=[]
    class Transport(InertTransport):
        def __init__(self,auth):super().__init__(generic)
        def token(self,audience):return 'INERT-NOT-A-CREDENTIAL'
        def close(self):pass
        def request(self,url,**kwargs):
            path=urlsplit(url).path.casefold();self.calls.append(url)
            if path=='/providers/microsoft.resourcegraph/resources':
                return {'data':[deepcopy(row)for row in generic.values()if row.get('type')]}
            if path==(S+'/resources').casefold():
                return {'value':[deepcopy(row)for row in generic.values()if row.get('type')]}
            if path==(S+'/providers/Microsoft.Network/networkSecurityGroups').casefold():
                return {'value':[{'id':N,'type':native.TYPES['nsg'],'etag':generic[N]['etag']}]}
            if path==N.casefold():
                generic_nsg_get.append(generic[N]['etag']);return deepcopy(generic[N])
            if path==(S+'/providers/Microsoft.Network/networkWatchers').casefold():return {'value':[deepcopy(generic[watcher])]}
            if path==(watcher+'/flowLogs').casefold():return {'value':[deepcopy(logrow)]}
            if path==(N+'/providers/Microsoft.Insights/diagnosticSettings').casefold():return {'value':[deepcopy(diagrow)]}
            try:return super().request(url,**kwargs)
            except AssertionError:
                from peaso.collectors.azure import AzureReadError
                raise AzureReadError('unit_unrelated_metadata_denied',403)from None
    class Opener:
        def open(self,req,timeout):
            path=urlsplit(req.full_url).path.casefold()
            if req.method=='GET':
                for kind,typ in native.TYPES.items():
                    if path==(S+'/providers/'+typ).casefold():
                        return InertHTTPResponse(200,{'value':[deepcopy(row)for row in objects.values()if row.get('type')==typ]})
                for rid,row in objects.items():
                    if path==rid.casefold():
                        if path==N.casefold():bounded_nsg_get.append(row['etag'])
                        return InertHTTPResponse(200,deepcopy(row))
            if req.method=='POST':
                query_calls.append(path)
                if path==(NIC+'/effectiveNetworkSecurityGroups').casefold():return InertHTTPResponse(200,{'value':deepcopy(groups)})
                if path==(NIC+'/effectiveRouteTable').casefold():return InertHTTPResponse(200,{'value':deepcopy(routes)})
                if path==(VNET+'/listNetworkManagerEffectiveSecurityAdminRules').casefold():return InertHTTPResponse(200,{'value':[]})
            raise AssertionError('Unexpected bounded metadata request')
    monkeypatch.setattr(azure,'AzureTransport',Transport);monkeypatch.setattr(azure,'AzureTransportExposure',Transport)
    monkeypatch.setattr(native,'build_opener',lambda *args:Opener())
    raw=options()
    raw['inventories']=['nsg_effective_internet_path','diagnostic_setting','flow_log']
    snapshot=collect_snapshot(request(raw))
    assert generic_nsg_get==['"initial-before-refresh"']
    assert bounded_nsg_get==['"native-refreshed"','"native-refreshed"']
    nsg=next(c['items'][0]for c in snapshot['collections']if c['type']=='nsg')
    assert nsg['etag']=='"native-refreshed"'
    assert nsg['_coverage']['diagnosticSettings']['status']=='collected'
    assert nsg['diagnosticSettings'][0]['id']==diagnostic
    assert nsg['diagnosticSettings'][0]['properties']['logs'][0]['enabled']is True
    parent=next(c['items'][0]for c in snapshot['collections']if c['type']=='network_watcher')
    assert parent['_coverage']['flowLogs']['status']=='collected'
    assert parent['flowLogs'][0]['id']==flow
    assert parent['flowLogs'][0]['properties']['targetResourceId']==N
    flow_collection=next(c for c in snapshot['collections']if c['type']=='flow_log')
    assert flow_collection['status']=='collected'and len(flow_collection['items'])==1
    assert flow_collection['items'][0]['parent_id']==watcher
    assert flow_collection['items'][0]['id']==flow
    assert flow_collection['items'][0]['properties']['enabled']is True
    diag_collection=next(c for c in snapshot['collections']if c['type']=='diagnostic_setting'and c['scope']==N)
    assert diag_collection['status']=='collected'
    assert diag_collection['items'][0]['id']==diagnostic
    assert diag_collection['items'][0]['properties']['logs'][0]['enabled']is True
    assert len(query_calls)==4
    assert {finding['status']for finding in evaluate_snapshot(snapshot,checks=[native.CHECK])['findings']}=={'PASS'}


def test_combined_public_edge_nsg_diagnostics_and_flow_logs(monkeypatch):
    """One new inert native collection boundary across both early producers."""
    from peaso.collectors import azure_public_edge_native as edge
    sw22='azure_application_gateway_11_5_1_1_1_f56bdc2'
    service='azure.other.nsg_port_protocol_assignment' 
    objects,groups,routes=topology()
    # Native public-edge identity requires the actual resource name, not an
    # injected binding. Protection mode is a documented PublicIP GET property.
    for rid,row in objects.items():
        if row.get('type'):row['name']=rid.rsplit('/',1)[-1]
    from tests.test_peaso_azure_nsg_ingress_native import PIP
    objects[PIP]['etag']='W/"public-ip-current"'
    objects[PIP]['properties']['ddosSettings']={'protectionMode':'Enabled'}
    watcher=S+'/resourceGroups/rg/providers/Microsoft.Network/networkWatchers/w'
    flow=watcher+'/flowLogs/fresh'
    diagnostic=N+'/providers/Microsoft.Insights/diagnosticSettings/fresh'
    objects[watcher]={'id':watcher,'type':'Microsoft.Network/networkWatchers',
        'etag':'"watcher"','properties':{}}
    generic=deepcopy(objects)
    generic[N]['etag']='"initial-before-refresh"'
    generic[PIP]['etag']='W/"public-ip-list-prior"'
    objects[N]['etag']='"native-refreshed"'
    logrow={'id':flow,'name':'fresh','type':'Microsoft.Network/networkWatchers/flowLogs','properties':{'enabled':True,'targetResourceId':N,
        'format':{'type':'JSON','version':2}}}
    diagrow={'id':diagnostic,'name':'fresh','properties':{
        'workspaceId':S+'/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/logs',
        'logs':[{'category':'NetworkSecurityGroupEvent','enabled':True}], 'metrics':[]}}
    generic_nsg_get=[];bounded_nsg_get=[];query_calls=[];public_ip_get=[]
    class Transport(InertTransport):
        def __init__(self,auth):super().__init__(generic)
        def token(self,audience):return 'INERT-NOT-A-CREDENTIAL'
        def close(self):pass
        def request(self,url,**kwargs):
            path=urlsplit(url).path.casefold();self.calls.append(url)
            if path=='/providers/microsoft.resourcegraph/resources':
                return {'data':[deepcopy(row)for row in generic.values()if row.get('type')]}
            if path==(S+'/resources').casefold():
                return {'value':[deepcopy(row)for row in generic.values()if row.get('type')]}
            if path==(S+'/providers/Microsoft.Network/networkSecurityGroups').casefold():
                return {'value':[{'id':N,'type':native.TYPES['nsg'],'etag':generic[N]['etag']}]}
            if path==(S+'/providers/'+edge.TYPES['frontdoor']).casefold():return {'value':[]}
            if path==(S+'/providers/'+edge.TYPES['frontdoor_profile']).casefold():return {'value':[]}
            if path==PIP.casefold():
                public_ip_get.append(objects[PIP]['etag']);return deepcopy(objects[PIP])
            if path==N.casefold():
                generic_nsg_get.append(generic[N]['etag']);return deepcopy(generic[N])
            if path==(S+'/providers/Microsoft.Network/networkWatchers').casefold():return {'value':[deepcopy(generic[watcher])]}
            if path==(watcher+'/flowLogs').casefold():return {'value':[deepcopy(logrow)]}
            if path==(N+'/providers/Microsoft.Insights/diagnosticSettings').casefold():return {'value':[deepcopy(diagrow)]}
            try:return super().request(url,**kwargs)
            except AssertionError:
                from peaso.collectors.azure import AzureReadError
                raise AzureReadError('unit_unrelated_metadata_denied',403)from None
    class Opener:
        def open(self,req,timeout):
            path=urlsplit(req.full_url).path.casefold()
            if req.method=='GET':
                for kind,typ in native.TYPES.items():
                    if path==(S+'/providers/'+typ).casefold():
                        return InertHTTPResponse(200,{'value':[deepcopy(row)for row in objects.values()if row.get('type')==typ]})
                for rid,row in objects.items():
                    if path==rid.casefold():
                        if path==N.casefold():bounded_nsg_get.append(row['etag'])
                        return InertHTTPResponse(200,deepcopy(row))
            if req.method=='POST':
                query_calls.append(path)
                if path==(NIC+'/effectiveNetworkSecurityGroups').casefold():return InertHTTPResponse(200,{'value':deepcopy(groups)})
                if path==(NIC+'/effectiveRouteTable').casefold():return InertHTTPResponse(200,{'value':deepcopy(routes)})
                if path==(VNET+'/listNetworkManagerEffectiveSecurityAdminRules').casefold():return InertHTTPResponse(200,{'value':[]})
            raise AssertionError('Unexpected bounded metadata request')
    monkeypatch.setattr(azure,'AzureTransport',Transport);monkeypatch.setattr(azure,'AzureTransportExposure',Transport)
    monkeypatch.setattr(native,'build_opener',lambda *args:Opener())
    raw=options()
    raw['inventories']=['nsg_effective_internet_path','diagnostic_setting','flow_log',*edge.NATIVE_TYPES]
    selected=request(raw);selected['checks']=[native.CHECK,sw22,service]
    snapshot=collect_snapshot(selected)
    assert generic_nsg_get==['"initial-before-refresh"']
    assert bounded_nsg_get==['"native-refreshed"','"native-refreshed"']
    nsg=next(c['items'][0]for c in snapshot['collections']if c['type']=='nsg')
    assert nsg['etag']=='"native-refreshed"'
    assert nsg['_coverage']['diagnosticSettings']['status']=='collected'
    assert nsg['diagnosticSettings'][0]['id']==diagnostic
    assert nsg['diagnosticSettings'][0]['properties']['logs'][0]['enabled']is True
    parent=next(c['items'][0]for c in snapshot['collections']if c['type']=='network_watcher')
    assert parent['_coverage']['flowLogs']['status']=='collected'
    assert parent['flowLogs'][0]['id']==flow
    assert parent['flowLogs'][0]['properties']['targetResourceId']==N
    flow_collection=next(c for c in snapshot['collections']if c['type']=='flow_log')
    assert flow_collection['status']=='collected'and len(flow_collection['items'])==1
    assert flow_collection['items'][0]['parent_id']==watcher
    assert flow_collection['items'][0]['id']==flow
    assert flow_collection['items'][0]['properties']['enabled']is True
    diag_collection=next(c for c in snapshot['collections']if c['type']=='diagnostic_setting'and c['scope']==N)
    assert diag_collection['status']=='collected'
    assert diag_collection['items'][0]['id']==diagnostic
    assert diag_collection['items'][0]['properties']['logs'][0]['enabled']is True
    assert len(query_calls)==4
    pip=next(collection['items'][0]for collection in snapshot['collections']if collection['type']=='public_ip')
    binding_collection=next(collection for collection in snapshot['collections']if collection['type']=='public_edge_binding')
    assert binding_collection['status']=='collected',binding_collection
    assert len(binding_collection['items'])==1
    binding=binding_collection['items'][0]
    assert binding['resource_id']==PIP and binding['resource_kind']=='public_ip'
    assert binding['resource_etag']==pip['etag']=='W/"public-ip-current"'
    assert binding['public_frontend_ids']==[PIP]and binding['public']is True
    assert pip['_provenance']['source_operation']=='Microsoft.Network/publicIPAddresses:GET'
    assert binding['_provenance']['source_operation']=='Azure.publicEdgeProtection:resolve'
    assert public_ip_get==['W/"public-ip-current"']
    assert pip['properties']['ddosSettings']['protectionMode']=='Enabled'
    for kind in('application_gateway','load_balancer','frontdoor','frontdoor_profile'):
        collection=next(collection for collection in snapshot['collections']if collection['type']==kind)
        assert collection['status']=='empty'and collection['items']==[]
    measured=[collection for collection in snapshot['collections']if collection['type']=='nsg_service_measurement']
    # Explicit inventory planning can omit unavailable dependencies entirely.
    # Absence must remain UNKNOWN; never insert a fabricated measurement.
    assert all(collection['status']not in('collected','empty')and collection['items']==[]for collection in measured)
    report=evaluate_snapshot(snapshot,checks=[native.CHECK,sw22,service])
    statuses={check:{finding['status']for finding in report['findings']if finding['check_id']==check}
              for check in(native.CHECK,sw22,service)}
    assert statuses=={native.CHECK:{'PASS'},sw22:{'PASS'},service:{'UNKNOWN'}},statuses
