"""Tail native-only fixtures: complete joins, kind/SKU branches, no cloud calls."""
import copy,json,re
from pathlib import Path
import pytest
from peaso.checks import CHECKS,azure_ports_tail as ports
from peaso.checks.fixtures import CASES
ROOT=Path(__file__).resolve().parent.parent
REVIEWS=json.loads((ROOT/'peaso/rulepacks/reviewed_azure_ports_tail.json').read_text())
REGISTRY={c.id:c for c in CHECKS}


@pytest.mark.parametrize('cid',ports.CHECK_IDS)
def test_tail_pass_fail_unavailable_and_purity(cid):
    case=CASES[cid]
    for label,want in [('pass','PASS'),('fail','FAIL')]:
        item,index=copy.deepcopy(case[label]),copy.deepcopy(case.get(label+'_index',{}));before=copy.deepcopy((item,index))
        assert REGISTRY[cid].evaluate(item,index)[0]==want
        assert (item,index)==before
    for item in ({},None,[],{'collection_status':'denied'},{'collection_status':'partial'}):assert REGISTRY[cid].evaluate(item,{})[0]=='UNKNOWN'


@pytest.mark.parametrize('query,kind',[('network_interface_ip_forwarding_disabled','nic'),('databricks_workspace_subnet_with_nsg_configured','subnet'),('monitor_log_alert_service_health','activity_log_alert')])
def test_dependency_denied_partial_foreign_and_ambiguous_are_unknown(query,kind):
    check=REGISTRY[ports.SOURCE_QUERIES[query]];case=CASES[check.id]
    for status in ('denied','partial','malformed'):
        index=copy.deepcopy(case['pass_index']);index['collections'][kind][0]['status']=status
        assert check.evaluate(case['pass'],index)[0]=='UNKNOWN'
    index=copy.deepcopy(case['pass_index']);index[kind][0]['data']['id']=index[kind][0]['data']['id'].replace('/sub/','/foreign/')
    assert check.evaluate(case['pass'],index)[0]=='UNKNOWN'
    if kind!='activity_log_alert':
        index=copy.deepcopy(case['pass_index']);index[kind].append(copy.deepcopy(index[kind][0]))
        assert check.evaluate(case['pass'],index)[0]=='UNKNOWN'


def test_aks_all_pools_metrics_provider_and_uncertain_enforcement():
    nodes=REGISTRY[ports.SOURCE_QUERIES['aks_clusters_created_with_private_nodes']]
    assert nodes.evaluate({'properties':{'kubernetesVersion':'1.31','agentPoolProfiles':[]}},{})[0]=='UNKNOWN'
    assert nodes.evaluate({'properties':{'kubernetesVersion':'1.31','agentPoolProfiles':[{}]}},{})[0]=='UNKNOWN'
    policy=REGISTRY[ports.SOURCE_QUERIES['aks_network_policy_enabled']]
    assert policy.evaluate({'properties':{'kubernetesVersion':'1.31','networkProfile':{'networkPolicy':'future'}}},{})[0]=='UNKNOWN'
    assert 'unverified' in policy.evaluate(CASES[policy.id]['pass'],{})[1]['semantics']


def test_databricks_sku_exact_categories_and_declared_subnet_applicability():
    logs=REGISTRY[ports.SOURCE_QUERIES['databricks_workspace_diagnostic_log_delivery_configured']]
    assert logs.evaluate({'sku':{'name':'standard'}},{})[0]=='NOT_APPLICABLE'
    assert logs.evaluate({'sku':{'name':'unknown'}},{})[0]=='UNKNOWN'
    case=copy.deepcopy(CASES[logs.id]['pass']);case['diagnosticSettings'][0]['properties']['logs']=[{'categoryGroup':'allLogs','enabled':True}]
    assert logs.evaluate(case,{})[0]=='FAIL'
    subnets=REGISTRY[ports.SOURCE_QUERIES['databricks_workspace_subnet_with_nsg_configured']]
    assert subnets.evaluate({'properties':{'parameters':{}}},{})[0]=='NOT_APPLICABLE'


def test_exact_vpn_array_and_health_category_or_do_not_broadmerge():
    vpn=REGISTRY[ports.SOURCE_QUERIES['network_virtual_network_gateway_aad_only']]
    assert vpn.evaluate({'properties':{'vpnClientConfiguration':{'vpnAuthenticationTypes':[]}}},{})[0]=='NOT_APPLICABLE'
    assert vpn.evaluate({'properties':{'vpnClientConfiguration':{'vpnAuthenticationTypes':['unknown']}}},{})[0]=='UNKNOWN'
    health=REGISTRY[ports.SOURCE_QUERIES['monitor_log_alert_service_health']]
    index=copy.deepcopy(CASES[health.id]['pass_index']);index['activity_log_alert'][0]['data']['properties']['condition']['allOf'][0]['equals']='ResourceHealth'
    assert health.evaluate({'scope':'/subscriptions/sub'},index)[0]=='PASS'


def test_pinned_python_checks_are_replayed_without_prowler_imports():
    # Execute only source check class text against in-memory inert data. Its
    # runtime imports are removed; no service client or upstream runtime runs.
    from types import SimpleNamespace as NS
    proof=REVIEWS['prowler.azure.aks_clusters_created_with_private_nodes']['source_review']
    source=proof['pinned_python'];source=source[source.index('class aks_clusters_created_with_private_nodes'):]
    for public,want in [(False,'PASS'),(True,'FAIL')]:
        class Report:
            def __init__(self,**kwargs):pass
        client=NS(clusters={'sub':{'cluster':NS(name='cluster',agent_pool_profiles=[NS(enable_node_public_ip=public)])}},subscriptions={})
        env={'Check':type('Check',(),{'metadata':lambda self:{}}),'Check_Report_Azure':Report,'aks_client':client}
        exec(source,env)
        assert env['aks_clusters_created_with_private_nodes']().execute()[0].status==want


@pytest.mark.parametrize('cid',[c for c in ports.CHECK_IDS if any('pinned_python' in r['source_review'] and c in r['native_checks'] for r in REVIEWS.values())])
def test_every_pinned_python_tail_predicate_differential_truth(cid):
    from types import SimpleNamespace as NS
    row=next(r for r in REVIEWS.values() if cid in r['native_checks']);proof=row['source_review'];query=proof['query_id']
    class Report:
        def __init__(self,*args,**kwargs):pass
    for label,want in [('pass','PASS'),('fail','FAIL')]:
        item=CASES[cid][label];props=item.get('properties',{});config=item.get('configuration',{}).get('properties',{})
        if query.startswith('aks_'):
            pools=[NS(enable_node_public_ip=p['enableNodePublicIP']) for p in props.get('agentPoolProfiles',[])]
            resource=NS(name='cluster',azure_monitor_enabled=props.get('azureMonitorProfile',{}).get('metrics',{}).get('enabled'),agent_pool_profiles=pools,network_policy=props.get('networkProfile',{}).get('networkPolicy'))
            client=NS(clusters={'sub':{'c':resource}},subscriptions={});client_name='aks_client'
        else:
            logs=[NS(category=l.get('category'),category_group=l.get('categoryGroup'),enabled=l['enabled']) for s in item.get('diagnosticSettings',[]) for l in s['properties']['logs']]
            resource=NS(name='function',kind=item['kind'],https_only=props.get('httpsOnly'),ftps_state=config.get('ftpsState'),public_access=props.get('publicNetworkAccess')!='Disabled',vnet_subnet_id=props.get('virtualNetworkSubnetId'),monitor_diagnostic_settings=[NS(name='log',logs=logs)] if logs else [])
            client=NS(functions={'sub':{'f':resource}},apps={'sub':{'a':resource}},subscriptions={});client_name='app_client'
        env={'Check':type('Check',(),{'metadata':lambda self:{}}),'Check_Report_Azure':Report,client_name:client}
        source=proof['pinned_python'];exec(source[source.index('class '+query):],env)
        assert env[query]().execute()[0].status==want
        assert REGISTRY[cid].evaluate(item,{})[0]==want


@pytest.mark.parametrize('query',['automation_account_variable_encryption_enabled','app_service_environment_internal_encryption_enabled','databricks_workspace_cmk_configured','databricks_workspace_diagnostic_log_delivery_configured','databricks_workspace_subnet_with_nsg_configured','network_virtual_network_gateway_aad_only','network_interface_ip_forwarding_disabled','monitor_log_alert_service_health'])
def test_pinned_sql_tail_status_cases_differential_with_authoritative_join_truth(query):
    duckdb=pytest.importorskip('duckdb');cid=ports.SOURCE_QUERIES[query];proof=next(r['source_review'] for r in REVIEWS.values() if cid in r['native_checks'])
    expression=re.search(r'(case\b(?:(?!\bcase\b).)*?\bend)\s+as\s+status',proof['pinned_sql'],re.I|re.S).group(1)
    expression=expression.replace('b.id','matched_id').replace('nsg.id','bad_subnet_id').replace('a.subscription_id','alert_subscription_id').replace('i.enable_ip_forwarding','enable_ip_forwarding')
    expression=re.sub(r'\b(?:a|w|g)\.', '',expression).replace('::jsonb','::JSON').replace('::bool','::BOOLEAN').replace('jsonb_array_length(','json_array_length(')
    expression=re.sub(r"\b(?:parameters|sku|vpn_client_configuration)(?:\s*->>?\s*'[^']*')+",lambda m:'('+m[0]+')',expression)
    expression=re.sub(r"\(([^()]*)\)\s*@>\s*('[^']*')(?:::JSON)?",r'json_contains(\1,\2::JSON)',expression)
    expression=expression.replace('count(alert_subscription_id)','matching_alert_count')
    for label,want in [('pass','ok'),('fail','alarm')]:
        item=CASES[cid][label];props=item.get('properties',{});good=label=='pass'
        # CTE facts use the independently established source full-ID joins;
        # all status CASE selectors/thresholds above are the actual pinned text.
        parameters=props.get('parameters',{});vpn=props.get('vpnClientConfiguration',{})
        expression_case=expression
        for alias in ('dsa.clusters_logs_enabled','dsa.accounts_logs_enabled','dsa.jobs_logs_enabled','dsa.notebook_logs_enabled','dsa.workspace_logs_enabled','dsa.sqlpermissions_logs_enabled'):expression_case=expression_case.replace(alias,str(1 if good else 0))
        with duckdb.connect(':memory:') as db:
            actual=db.execute('SELECT '+expression_case+' FROM (SELECT ? AS is_encrypted,? AS matched_id,? AS bad_subnet_id,? AS enable_ip_forwarding,? AS matching_alert_count,?::JSON AS parameters,?::JSON AS sku,?::JSON AS diagnostic_settings,?::JSON AS vpn_client_configuration)',[props.get('isEncrypted'), 'matched' if good else None,None if good else 'bad',not good,1 if good else 0,json.dumps(parameters),json.dumps(item.get('sku',{})),json.dumps(item.get('diagnosticSettings',[])),json.dumps(vpn)]).fetchone()[0]
        assert actual==want
        assert REGISTRY[cid].evaluate(item,CASES[cid].get(label+'_index',{}))[0]=={'ok':'PASS','alarm':'FAIL'}[want]
