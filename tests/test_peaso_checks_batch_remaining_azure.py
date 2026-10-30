"""Portable real-registry behavior cases for the reviewed Azure batch."""
from __future__ import annotations
import copy
import pytest
from peaso.checks import CHECKS
from peaso.checks import batch_remaining_azure as batch

SCOPE='/subscriptions/11111111-1111-1111-1111-111111111111'
PROVENANCE={'representation':'full','source_operation':'get','read_only':True}
BY_ID={c.id:c for c in CHECKS}

def item(kind,name='one',**fields):
    types={'web_application_firewall_policy':'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies',
           'postgresql_single_server':'Microsoft.DBforPostgreSQL/servers',
           'mysql_single_server':'Microsoft.DBforMySQL/servers',
           'mariadb_server':'Microsoft.DBforMariaDB/servers',
           'log_analytics_cluster':'Microsoft.OperationalInsights/clusters',
           'firewall_policy':'Microsoft.Network/firewallPolicies'}
    return {'id':SCOPE+'/resourceGroups/example/providers/'+types[kind]+'/'+name,
            'name':name,'properties':{},'_provenance':copy.deepcopy(PROVENANCE),**fields}

def index(kind,rows,status=None):
    return {'context':{'provider':'azure','scope':SCOPE},
            'collections':{kind:[{'type':kind,'scope':SCOPE,'status':status or ('collected' if rows else 'empty'),'items':copy.deepcopy(rows)}]},
            kind:[{'provider':'azure','type':kind,'scope':SCOPE,'data':copy.deepcopy(row)} for row in rows]}

def config(server,name,value):
    row=copy.deepcopy(server)
    row['configurations']=[{'id':row['id']+'/configurations/'+name,'name':name,'properties':{'value':value}}]
    row['_coverage']={'configurations':{'status':'collected'}}
    return row

def cases():
    out={}
    good=item('web_application_firewall_policy',properties={'customRules':[{'name':'allow-health'}],'managedRules':{'managedRuleSets':[]}})
    bad=item('web_application_firewall_policy',properties={'customRules':[],'managedRules':{'managedRuleSets':[]}})
    out['azure_firewall_policy_1_2_8_42_cacbd9e']=(good,index('web_application_firewall_policy',[good]),bad,index('web_application_firewall_policy',[bad]))
    for cid,kind,field,good_value,bad_value in [
        ('azure.cis.enforce_ssl_connection_mysql_server','mysql_single_server','sslEnforcement','Enabled','Disabled'),
        ('azure.cis.postgresql_single_ssl_enforcement','postgresql_single_server','sslEnforcement','Enabled','Disabled'),
        ('azure.cis.public_network_access_should_mariadb_servers','mariadb_server','publicNetworkAccess','Disabled','Enabled'),
        ('azure.cis.legacy_infrastructure_double_encryption_postgresql_single_server','postgresql_single_server','infrastructureEncryption','Enabled','Disabled')]:
        good=item(kind,properties={field:good_value});bad=item(kind,properties={field:bad_value})
        out[cid]=(good,index(kind,[good]),bad,index(kind,[bad]))
    for cid,kind,name,good_value,bad_value in [
        ('azure.cis.postgresql_single_connection_throttling','postgresql_single_server','connection_throttling','ON','OFF'),
        ('azure.cis.postgresql_single_log_checkpoints','postgresql_single_server','log_checkpoints','ON','OFF'),
        ('azure.cis.postgresql_single_log_connections','postgresql_single_server','log_connections','on','off'),
        ('azure.cis.postgresql_single_log_disconnections','postgresql_single_server','log_disconnections','on','off'),
        ('azure.cis.postgresql_single_log_retention_days','postgresql_single_server','log_retention_days','4','3'),
        ('azure.cis.mysql_single_audit_log_enabled','mysql_single_server','audit_log_enabled','ON','OFF')]:
        base=item(kind);good=config(base,name,good_value);bad=config(base,name,bad_value)
        out[cid]=(good,index(kind,[good]),bad,index(kind,[bad]))
    base=item('mysql_single_server')
    good=config(base,'audit_log_enabled','ON')
    event={'id':good['id']+'/configurations/audit_log_events','name':'audit_log_events',
           'properties':{'value':'CONNECTION,GENERAL'}}
    good['configurations'].append(event)
    bad=copy.deepcopy(good);bad['configurations'][1]['properties']['value']='GENERAL'
    out['azure.cis.mysql_single_audit_log_events_connection']=(good,index('mysql_single_server',[good]),
        bad,index('mysql_single_server',[bad]))
    good=item('postgresql_single_server',_coverage={'firewallRules':{'status':'empty'}},firewallRules=[])
    bad=copy.deepcopy(good);bad['_coverage']['firewallRules']['status']='collected'
    bad['firewallRules']=[{'id':bad['id']+'/firewallRules/AzureServices',
        'properties':{'startIpAddress':'0.0.0.0','endIpAddress':'0.0.0.0'}}]
    out['azure.cis.postgresql_single_no_azure_services_rule']=(good,index('postgresql_single_server',[good]),
        bad,index('postgresql_single_server',[bad]))
    good=item('log_analytics_cluster',properties={'isDoubleEncryptionEnabled':True})
    bad=item('log_analytics_cluster',properties={'isDoubleEncryptionEnabled':False})
    out['azure.gap.monitor_log_cluster_infrastructure_encryption_enabled']=(good,index('log_analytics_cluster',[good]),bad,index('log_analytics_cluster',[bad]))
    good=item('firewall_policy',_coverage={'ruleCollectionGroups':{'status':'collected'}})
    gid=good['id']+'/ruleCollectionGroups/rules'
    group={'id':gid,'parent_id':good['id'],'properties':{'ruleCollections':[{'rules':[{'name':'rule-one'}]}]},'_provenance':{'representation':'full','read_only':True,'source_operation':'get_rule_collection_group'}}
    good['ruleCollectionGroups']=[group]
    bad=copy.deepcopy(good);bad['ruleCollectionGroups'][0]['properties']['ruleCollections'][0]['rules']=[]
    out['azure_firewall_policy_1_2_8_24_cc7cb8a']=(good,index('firewall_policy',[good]),bad,index('firewall_policy',[bad]))
    return out
CASES=cases()

@pytest.mark.parametrize('cid',sorted(batch.SPECS))
def test_registry_pass_fail_unknown_and_immutable(cid):
    check=BY_ID[cid]
    good,good_index,bad,bad_index=copy.deepcopy(CASES[cid])
    before_good,before_bad=copy.deepcopy((good,good_index)),copy.deepcopy((bad,bad_index))
    assert check.evaluate(good,good_index)[0]=='PASS'
    assert check.evaluate(bad,bad_index)[0]=='FAIL'
    assert (good,good_index)==before_good and (bad,bad_index)==before_bad
    bad_index=copy.deepcopy(good_index)
    bad_index['collections'][batch.SPECS[cid][0]][0]['status']='partial'
    assert check.evaluate(good,bad_index)[0]=='UNKNOWN'
    assert check.evaluate(None,good_index)[0]=='UNKNOWN'
    assert check.evaluate(good,{})[0]=='UNKNOWN'


def test_foreign_waf_and_unreadable_config_are_unknown():
    cid='azure_firewall_policy_1_2_8_42_cacbd9e';good,good_index=copy.deepcopy(CASES[cid][:2])
    good['id']=good['id'].replace('11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222')
    assert BY_ID[cid].evaluate(good,good_index)[0]=='UNKNOWN'


def test_postgres_azure_services_sentinel_fails_even_with_partial_child_list():
    cid='azure.cis.postgresql_single_no_azure_services_rule'
    bad,bad_index=copy.deepcopy(CASES[cid][2:])
    bad['_coverage']['firewallRules']['status']='partial'
    bad['firewallRules'].insert(0,{'id':'malformed-child-without-addresses'})
    bad_index['collections']['postgresql_single_server'][0]['items'][0]=copy.deepcopy(bad)
    bad_index['postgresql_single_server'][0]['data']=copy.deepcopy(bad)
    assert BY_ID[cid].evaluate(bad,bad_index)[0]=='FAIL'
    good,good_index=copy.deepcopy(CASES[cid][:2])
    good['_coverage']['firewallRules']['status']='partial'
    good_index['collections']['postgresql_single_server'][0]['items'][0]=copy.deepcopy(good)
    good_index['postgresql_single_server'][0]['data']=copy.deepcopy(good)
    assert BY_ID[cid].evaluate(good,good_index)[0]=='UNKNOWN'
    cid='azure.cis.postgresql_single_log_checkpoints';good,good_index=copy.deepcopy(CASES[cid][:2])
    good['_coverage']['configurations']['status']='denied'
    good_index['collections']['postgresql_single_server'][0]['items'][0]=copy.deepcopy(good)
    good_index['postgresql_single_server'][0]['data']=copy.deepcopy(good)
    assert BY_ID[cid].evaluate(good,good_index)[0]=='UNKNOWN'


def test_firewall_child_get_to_snapshot_to_registry():
    from peaso.collectors import azure_swc
    policy=item('firewall_policy')
    group_id=policy['id']+'/ruleCollectionGroups/rules'
    class ReadOnlyReader:
        workers=1
        def pages(self,_request,url):
            assert '/ruleCollectionGroups?' in url
            yield [{'id':group_id}]
        def call(self,_request,url):
            assert group_id+'?' in url
            return {'id':group_id,'properties':{'ruleCollections':[{'rules':[{'name':'one'}]}]}}
        def _read(self,job):
            rows=[item for page in job[3]() for item in page]
            return {'items':rows,'status':'collected' if rows else 'empty'}
    collections=[{'type':'firewall_policy','scope':SCOPE,'status':'collected','items':[policy]}]
    azure_swc._firewall_groups(ReadOnlyReader(),object(),collections)
    assert policy['_coverage']['ruleCollectionGroups']['status']=='collected'
    assert BY_ID['azure_firewall_policy_1_2_8_24_cc7cb8a'].evaluate(policy,index('firewall_policy',[policy]))[0]=='PASS'
