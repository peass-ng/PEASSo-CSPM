"""Portable predicate fixtures; place beside module for staging or under tests."""
import copy
import importlib.util
import json
from pathlib import Path
import pytest

HERE = Path(__file__).resolve().parent
MODULE = HERE / 'post_dfaf_azure.py'
if not MODULE.exists():
    MODULE = HERE.parent / 'peaso/checks/post_dfaf_azure.py'
spec = importlib.util.spec_from_file_location('private_post_dfaf_azure', MODULE)
batch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(batch)
SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
PROVENANCE = {'representation':'full','source_operation':'get','read_only':True}


def resource(kind, name='one'):
    provider = {'web_pubsub':'Microsoft.SignalRService/webPubSub','firewall_policy':'Microsoft.Network/firewallPolicies'}[kind]
    return {'id':SCOPE+'/resourceGroups/example/providers/'+provider+'/'+name,
            'properties':{}, '_provenance':copy.deepcopy(PROVENANCE),
            '_coverage':{}}


def index(kind, rows, status='collected'):
    return {'context':{'provider':'azure','scope':SCOPE},
            'collections':{kind:[{'type':kind,'scope':SCOPE,'status':status,'items':copy.deepcopy(rows)}]},
            kind:[{'provider':'azure','type':kind,'scope':SCOPE,'data':copy.deepcopy(row)} for row in rows]}


def connection(parent, status='Approved'):
    return {'id':parent['id']+'/privateEndpointConnections/one','properties':{
        'privateLinkServiceConnectionState':{'status':status},
        'privateEndpoint':{'id':SCOPE+'/resourceGroups/example/providers/Microsoft.Network/privateEndpoints/one'}}}


def group(parent, rules=True, collection_type='FirewallPolicyFilterRuleCollection', rule_type='NetworkRule'):
    return {'id':parent['id']+'/ruleCollectionGroups/one','parent_id':parent['id'],
            '_provenance':{'representation':'full','source_operation':'get_rule_collection_group',
                           'read_only':True,'parent_policy_id':parent['id']},
            'properties':{'ruleCollections':[{'ruleCollectionType':collection_type,
                'rules':[{'name':'rule','ruleType':rule_type,'sourceAddresses':['10.0.0.0/24'],
                          'destinationAddresses':['10.1.0.0/24'],'destinationPorts':['443'],
                          'ipProtocols':['TCP']}] if rules else []}]}}


def observed(kind, field, children):
    row=resource(kind);row[field]=children(row);row['_coverage'][field]={'status':'collected'}
    return row,index(kind,[row])


CASES=[]
def add(name,cid,row,idx,expected):
    CASES.append({'name':name,'id':cid,'item':copy.deepcopy(row),'index':copy.deepcopy(idx),'expected':expected})

for cid,kind,field,children in [
    (batch.WEBPUBSUB,'web_pubsub','privateEndpointConnections',lambda row:[connection(row)]),
    (batch.FIREWALL,'firewall_policy','ruleCollectionGroups',lambda row:[group(row)])]:
    row,idx=observed(kind,field,children);add('pass',cid,row,idx,'PASS')
    bad=copy.deepcopy(row);bad[field]=[];bad['_coverage'][field]={'status':'empty'};add('fail_empty',cid,bad,index(kind,[bad]),'FAIL')
    for status in ['denied','partial','not_collected','error']:
        add('inventory_'+status,cid,row,index(kind,[row],status),'UNKNOWN')
        bad=copy.deepcopy(row);bad['_coverage'][field]={'status':status}
        add('child_'+status,cid,bad,index(kind,[bad]),'UNKNOWN')
    for name,mutate in [
        ('missing',lambda r:r.pop(field)),
        ('malformed',lambda r:r.__setitem__(field,{})),
        ('foreign_child',lambda r:r[field][0].__setitem__('id',SCOPE.replace('11111111','22222222')+'/other')),
        ('duplicate_child',lambda r:r[field].append(copy.deepcopy(r[field][0]))),
        ('missing_coverage',lambda r:r.pop('_coverage')),
    ]:
        bad=copy.deepcopy(row);mutate(bad);add(name,cid,bad,index(kind,[bad]),'UNKNOWN')
    bad=copy.deepcopy(row);bad['_coverage'][field]={'status':'empty'};add('contradictory_child',cid,bad,index(kind,[bad]),'UNKNOWN')
    badidx=copy.deepcopy(idx);badidx['collections'][kind][0]['status']='empty';add('contradictory_inventory',cid,row,badidx,'UNKNOWN')
    badidx=copy.deepcopy(idx);badidx['collections'][kind][0]['scope']=17;add('malformed_scope',cid,row,badidx,'UNKNOWN')
    badidx=copy.deepcopy(idx);badidx['context']['provider']='aws';add('foreign_provider',cid,row,badidx,'UNKNOWN')
    badidx=copy.deepcopy(idx);badidx[kind][0]['scope']='/subscriptions/foreign';add('foreign_projection',cid,row,badidx,'UNKNOWN')
    badidx=copy.deepcopy(idx);badidx['collections'][kind][0]['scope']='/subscriptions/foreign';add('foreign_envelope',cid,row,badidx,'UNKNOWN')
    badidx=copy.deepcopy(idx);badidx[kind][0]['data']['properties']['changed']=True;add('projection_mismatch',cid,row,badidx,'UNKNOWN')
    add('missing_inventory',cid,row,{'context':idx['context'],'collections':{}},'UNKNOWN')

for status in ['Pending','Rejected','Disconnected','Removed','unknown']:
    row,idx=observed('web_pubsub','privateEndpointConnections',lambda row:[connection(row,status)])
    add('status_'+status,batch.WEBPUBSUB,row,idx,'FAIL' if status in ['Pending','Rejected','Disconnected'] else 'UNKNOWN')
row,idx=observed('web_pubsub','privateEndpointConnections',lambda row:[connection(row)])
row['privateEndpointConnections'][0]['properties']['privateEndpoint']['id']=''
add('missing_endpoint',batch.WEBPUBSUB,row,index('web_pubsub',[row]),'UNKNOWN')
for ctype,rtype,expected in [('FirewallPolicyNatRuleCollection','NatRule','PASS'),
                            ('FirewallPolicyFilterRuleCollection','ApplicationRule','PASS'),
                            ('FirewallPolicyNatRuleCollection','NetworkRule','UNKNOWN'),
                            ('future','NetworkRule','UNKNOWN')]:
    row,idx=observed('firewall_policy','ruleCollectionGroups',lambda row:[group(row,True,ctype,rtype)])
    add('type_'+ctype+'_'+rtype,batch.FIREWALL,row,idx,expected)
row,idx=observed('firewall_policy','ruleCollectionGroups',lambda row:[group(row,False)])
add('empty_rules',batch.FIREWALL,row,idx,'FAIL')
base=resource('firewall_policy','base');base['ruleCollectionGroups']=[group(base)];base['_coverage']['ruleCollectionGroups']={'status':'collected'}
child=resource('firewall_policy','child');child['properties']['basePolicy']={'id':base['id']};child['ruleCollectionGroups']=[];child['_coverage']['ruleCollectionGroups']={'status':'empty'}
add('inherited',batch.FIREWALL,child,index('firewall_policy',[child,base]),'PASS')
add('missing_base',batch.FIREWALL,child,index('firewall_policy',[child]),'UNKNOWN')
base['properties']['basePolicy']={'id':child['id']}
add('cyclic_base',batch.FIREWALL,child,index('firewall_policy',[child,base]),'UNKNOWN')
row,idx=observed('firewall_policy','ruleCollectionGroups',lambda row:[group(row)])
row['_provenance']['representation']='partial';add('partial_parent',batch.FIREWALL,row,index('firewall_policy',[row]),'UNKNOWN')
row,idx=observed('firewall_policy','ruleCollectionGroups',lambda row:[group(row)])
row['ruleCollectionGroups'][0]['_provenance']['representation']='partial';add('partial_group',batch.FIREWALL,row,index('firewall_policy',[row]),'UNKNOWN')

@pytest.mark.parametrize('case',CASES,ids=lambda c:c['id']+':'+c['name'])
def test_predicate(case):
    before=copy.deepcopy(case)
    assert batch.evaluate(case['id'],case['item'],case['index'])[0]==case['expected']
    assert case==before


def test_portability():
    assert '.cache' not in MODULE.read_text()
    assert set(batch.EVALUATORS)=={batch.WEBPUBSUB,batch.FIREWALL}

class CountedList(list):
    iterations=0
    def __iter__(self):
        self.iterations+=1
        return super().__iter__()

@pytest.mark.parametrize('cid,kind,field,children',[
    (batch.WEBPUBSUB,'web_pubsub','privateEndpointConnections',lambda row:[connection(row)]),
    (batch.FIREWALL,'firewall_policy','ruleCollectionGroups',lambda row:[group(row)])])
def test_scoped_inventory_is_traversed_once(cid,kind,field,children):
    from peaso.checks.facts import MemoIndex
    rows=[]
    for number in range(20):
        row=resource(kind,str(number));row[field]=children(row);row['_coverage'][field]={'status':'collected'};rows.append(row)
    idx=MemoIndex(index(kind,rows))
    native=CountedList(idx['collections'][kind][0]['items']);wrapped=CountedList(idx[kind])
    idx['collections'][kind][0]['items']=native;idx[kind]=wrapped
    assert batch.evaluate(cid,rows[0],idx)[0]=='PASS'
    baseline=(native.iterations,wrapped.iterations)
    for row in rows:
        assert batch.evaluate(cid,row,idx)[0]=='PASS'
    assert (native.iterations,wrapped.iterations)==baseline
    idx['context']['scope']='/subscriptions/other'
    assert batch.evaluate(cid,rows[0],idx)[0]=='UNKNOWN'

class OfflineReader:
    workers=1
    def __init__(self,children):self.children=children;self.urls=[];self.collections=[]
    def pages(self,request,url):
        self.urls.append(url)
        if 'privateEndpointConnections?' in url or 'ruleCollectionGroups?' in url:yield copy.deepcopy(self.children)
        else:yield []
    def call(self,request,url):
        self.urls.append(url)
        identity=url.split('?')[0].removeprefix('https://management.azure.com')
        return copy.deepcopy(next(r for r in self.children if r['id'].casefold()==identity.casefold()))
    def _read(self,job):
        rows=[]
        for page in job[3]():rows.extend(page)
        return {'status':'collected' if rows else 'empty','items':rows}


def test_real_webpubsub_collector_embed():
    from peaso.collectors.azure import _embed
    parent=resource('web_pubsub');reader=OfflineReader([connection(parent)])
    _embed(reader,None,[('web_pubsub',parent)])
    assert batch.evaluate(batch.WEBPUBSUB,parent,index('web_pubsub',[parent]))[0]=='PASS'
    assert any('privateEndpointConnections?api-version=2024-03-01' in u for u in reader.urls)


def test_real_firewall_collector_helper():
    from peaso.collectors.azure_swc import _firewall_groups
    parent=resource('firewall_policy');child=group(parent);child.pop('_provenance');child.pop('parent_id')
    reader=OfflineReader([child])
    _firewall_groups(reader,None,[{'type':'firewall_policy','items':[parent]}])
    assert batch.evaluate(batch.FIREWALL,parent,index('firewall_policy',[parent]))[0]=='PASS'
    assert parent['ruleCollectionGroups'][0]['_provenance']['source_operation']=='get_rule_collection_group'
    assert any('ruleCollectionGroups?api-version=2023-09-01' in u for u in reader.urls)
