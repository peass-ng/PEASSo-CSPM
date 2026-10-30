"""Real context-sensitive predicates and captured-only facts never become safe defaults."""
import copy, json
from pathlib import Path
import pytest
from peaso.checks import CHECKS,azure_ports_tail_context as ports
from peaso.checks.fixtures import CASES
from peaso.collectors import azure
import copy,json,re
ROOT=Path(__file__).resolve().parent.parent
REVIEWS=json.loads((ROOT/'peaso/rulepacks/reviewed_azure_ports_tail_context.json').read_text())
REGISTRY={c.id:c for c in CHECKS}


@pytest.mark.parametrize('cid',ports.CHECK_IDS)
def test_context_pass_fail_unavailable_and_purity(cid):
    case=CASES[cid]
    for label,want in [('pass','PASS'),('fail','FAIL')]:
        item,index=copy.deepcopy(case[label]),copy.deepcopy(case.get(label+'_index',{}));before=copy.deepcopy((item,index))
        assert REGISTRY[cid].evaluate(item,index)[0]==want
        assert (item,index)==before
    for item in ({},None,[],{'collection_status':'denied'},{'collection_status':'partial'}):assert REGISTRY[cid].evaluate(item,{})[0]=='UNKNOWN'


@pytest.mark.parametrize('query',['sql_server_va_setting_periodic_scan_enabled','sql_server_va_setting_reports_notify_admins','sql_server_va_setting_scan_reports_configured'])
def test_classic_va_exact_parent_state_conditional_source_and_unknown_mode(query):
    check=REGISTRY[ports.SOURCE_QUERIES[query]];case=copy.deepcopy(CASES[check.id]['pass'])
    case['securityAlertPolicies'][0]['properties']['state']='Disabled'
    assert check.evaluate(case,{})[0]=='FAIL'
    case['securityAlertPolicies']=[]
    assert check.evaluate(case,{})[0]=='UNKNOWN'
    case=copy.deepcopy(CASES[check.id]['pass']);case['vulnerabilityAssessment']['id']=case['vulnerabilityAssessment']['id'].replace('/sub/','/foreign/')
    assert check.evaluate(case,{})[0]=='UNKNOWN'
    case=copy.deepcopy(CASES[check.id]['pass']);case['vulnerabilityAssessment']['properties']['storageContainerPath']=None
    assert check.evaluate(case,{})[0]=='UNKNOWN'
    case['expressVulnerabilityAssessment']={'properties':{'state':'Enabled'}}
    assert check.evaluate(case,{})[0]=='PASS'
    case['_coverage']={'vulnerabilityAssessment':{'status':'denied'}}
    assert check.evaluate(case,{})[0]=='UNKNOWN'


def test_disabled_user_enabled_skip_foreign_tenant_assignment_denial_and_purity():
    check=REGISTRY[ports.SOURCE_QUERIES['ad_disabled_user_no_role_assignments']];case=CASES[check.id]
    user=copy.deepcopy(case['pass']);user['accountEnabled']=True
    assert check.evaluate(user,{})[0]=='NOT_APPLICABLE'
    for status in ('denied','partial','not_collected'):
        index=copy.deepcopy(case['fail_index']);index['collections']['role_assignment'][0]['status']=status
        assert check.evaluate(case['fail'],index)[0]=='UNKNOWN'
    index=copy.deepcopy(case['fail_index']);index['role_assignment'][0]['data']['_provenance']['tenant_id']='foreign'
    assert check.evaluate(case['fail'],index)[0]=='UNKNOWN'


def test_exact_plan_join_and_vnet_connection_completeness():
    workers=REGISTRY[ports.SOURCE_QUERIES['appservice_web_app_worker_more_than_one']];case=CASES[workers.id]
    index=copy.deepcopy(case['pass_index']);index['app_service_plan'][0]['data']['id']=index['app_service_plan'][0]['data']['id'].replace('/sub/','/foreign/')
    assert workers.evaluate(case['pass'],index)[0]=='UNKNOWN'
    vnet=REGISTRY[ports.SOURCE_QUERIES['appservice_web_app_use_virtual_service_endpoint']]
    assert vnet.evaluate({'kind':'functionapp'},{})[0]=='NOT_APPLICABLE'
    item=copy.deepcopy(CASES[vnet.id]['pass']);item['_coverage']={'vnetConnections':{'status':'partial'}}
    assert vnet.evaluate(item,{})[0]=='UNKNOWN'


@pytest.mark.parametrize('language',['java','php','python'])
def test_pinned_runtime_defaults_configured_argument_and_not_latest_claim(language):
    check=REGISTRY[ports.SOURCE_QUERIES['app_ensure_'+language+'_version_is_latest']]
    item=copy.deepcopy(CASES[check.id]['pass'])
    assert check.evaluate(item,{'context':{'metadata':{'audit_config':{language+'_latest_version':'99'}}}})[0]=='FAIL'
    assert check.evaluate(item,{'context':{'metadata':{'audit_config':{language+'_latest_version':{}}}}})[0]=='UNKNOWN'
    item['configuration']['properties']['linuxFxVersion']='other|1';item['configuration']['properties'][language+'Version']=None
    assert check.evaluate(item,{})[0]=='NOT_APPLICABLE'


def test_app_settings_are_captured_only_and_no_missing_safe_default():
    for query in ('app_function_latest_runtime_version','app_function_application_insights_enabled'):
        check=REGISTRY[ports.SOURCE_QUERIES[query]]
        assert check.evaluate({'kind':'functionapp'},{})[0]=='UNKNOWN'
        review=REVIEWS['prowler.azure.'+query]
        assert review['runtime_provider_supported'] is False and review['fact_requirements']['captured_only'] is True


def test_required_legacy_attack_setting_empty_denied_or_nonmatching_inventory_is_unknown():
    check=REGISTRY[ports.SOURCE_QUERIES['security_center_attack_path_alerts_enabled']]
    for status in ('empty','denied','partial'):
        index=ports._attack(True);index['security_setting']=[];index['collections']['security_setting'][0]['status']=status
        assert check.evaluate({'scope':'/subscriptions/sub'},index)[0]=='UNKNOWN'
    index=ports._attack(True);index['security_setting'][0]['data']['name']='WDATP'
    assert check.evaluate({'scope':'/subscriptions/sub'},index)[0]=='UNKNOWN'


def test_collector_vnet_connections_drop_certificate_and_key_material():
    parent='/subscriptions/sub/resourceGroups/g/providers/Microsoft.Web/sites/site'
    rows=azure._child_rows([{'id':parent+'/virtualNetworkConnections/vnet','name':'vnet','properties':{'vnetResourceId':ports._VNET,'certBlob':'INERT_CERT','certificate':'INERT_PRIVATE','routes':[]}}],parent,'vnetConnections')
    assert rows[0]['properties']=={'vnetResourceId':ports._VNET}
    assert 'INERT' not in json.dumps(rows)
    with pytest.raises(ValueError):azure._child_rows([{'id':parent.replace('/sub/','/foreign/')+'/virtualNetworkConnections/vnet'}],parent,'vnetConnections')


@pytest.mark.parametrize('query',['app_ensure_java_version_is_latest','app_ensure_php_version_is_latest','app_ensure_python_version_is_latest','app_function_application_insights_enabled','app_function_latest_runtime_version'])
def test_pinned_python_context_predicates_differential_truth(query):
    from types import SimpleNamespace as NS
    class Report:
        def __init__(self,*args,**kwargs):pass
    proof=REVIEWS['prowler.azure.'+query]['source_review'];check=REGISTRY[ports.SOURCE_QUERIES[query]]
    for label,want in [('pass','PASS'),('fail','FAIL')]:
        item=CASES[check.id][label];config=item.get('configuration',{}).get('properties',{});settings=item.get('appSettingsMetadata',{})
        resource=NS(name='app',configurations=NS(linux_fx_version=config.get('linuxFxVersion',''),java_version=config.get('javaVersion'),php_version=config.get('phpVersion'),python_version=config.get('pythonVersion')),environment_variables={'APPINSIGHTS_INSTRUMENTATIONKEY':settings.get('APPINSIGHTS_INSTRUMENTATIONKEY_nonempty'), 'APPLICATIONINSIGHTS_CONNECTION_STRING':settings.get('APPLICATIONINSIGHTS_CONNECTION_STRING_nonempty'),'FUNCTIONS_EXTENSION_VERSION':settings.get('FUNCTIONS_EXTENSION_VERSION')})
        client=NS(apps={'sub':{'a':resource}},functions={'sub':{'f':resource}},subscriptions={},audit_config={})
        env={'Check':type('Check',(),{'metadata':lambda self:{}}),'Check_Report_Azure':Report,'app_client':client}
        source=proof['pinned_python'];exec(source[source.index('class '+query):],env)
        assert env[query]().execute()[0].status==want and check.evaluate(item,{})[0]==want
