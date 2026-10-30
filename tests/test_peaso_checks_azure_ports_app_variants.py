"""Literal App Service scopes, declaration truth and unavailable legacy facts."""
import copy,json,re
from pathlib import Path
import pytest
from peaso.checks import CHECKS,azure_ports_app_variants as ports
from peaso.checks.fixtures import CASES
ROOT=Path(__file__).resolve().parent.parent
REVIEWS=json.loads((ROOT/'peaso/rulepacks/reviewed_azure_ports_app_variants.json').read_text())
REGISTRY={c.id:c for c in CHECKS}


@pytest.mark.parametrize('cid',ports.CHECK_IDS)
def test_all_app_variants_pass_fail_unknown_denied_malformed_and_purity(cid):
    for label,want in [('pass','PASS'),('fail','FAIL')]:
        item=copy.deepcopy(CASES[cid][label]);before=copy.deepcopy(item)
        assert REGISTRY[cid].evaluate(item,{})[0]==want
        assert item==before
    for item in ({},None,[],{'collection_status':'denied'},{'collection_status':'partial'}):assert REGISTRY[cid].evaluate(item,{})[0]=='UNKNOWN'


def test_api_suffix_exact_api_and_function_substring_have_distinct_source_scopes():
    https=REGISTRY[ports.SOURCE_QUERIES['appservice_api_app_use_https']]
    debug=REGISTRY[ports.SOURCE_QUERIES['appservice_api_app_remote_debugging_disabled']]
    item={'kind':'app,customapi','properties':{'httpsOnly':False},'configuration':{'properties':{'remoteDebuggingEnabled':True}}}
    assert https.evaluate(item,{})[0]=='FAIL' and debug.evaluate(item,{})[0]=='NOT_APPLICABLE'
    f=REGISTRY[ports.SOURCE_QUERIES['appservice_function_app_latest_http_version']]
    assert f.evaluate({'kind':'functionapp'},{})[0]=='NOT_APPLICABLE'
    assert f.evaluate({'kind':'app'},{})[0]=='NOT_APPLICABLE'


def test_tls13_and_ftps_disabled_preserve_source_ordering_and_ftp_selector():
    for query,field,value in [('appservice_api_app_latest_tls_version','minTlsVersion','1.3'),('appservice_api_app_ftps_enabled','ftpsState','Disabled')]:
        check=REGISTRY[ports.SOURCE_QUERIES[query]]
        assert check.evaluate({'kind':'api','configuration':{'properties':{field:value}}},{})[0]=='PASS'
        assert check.evaluate({'kind':'api','configuration':{'properties':{field:{}}}},{})[0]=='UNKNOWN'


def test_v2_flag_never_fabricates_legacy_v1_success_or_failure():
    check=REGISTRY[ports.SOURCE_QUERIES['appservice_authentication_enabled']]
    assert check.evaluate({'kind':'app','authSettingsV2':{'properties':{'platform':{'enabled':True}}}},{})[0]=='UNKNOWN'
    assert check.evaluate({'kind':'app','authSettingsV1':{'properties':{'enabled':True}},'_coverage':{'authSettingsV1':{'status':'denied'}}},{})[0]=='UNKNOWN'
    assert all(not r['runtime_provider_supported'] for r in REVIEWS.values() if 'authentication' in r['source_review']['query_id'])


@pytest.mark.parametrize('query',ports.RUNTIMES)
def test_actual_pinned_runtime_case_literal_parameters_and_scope(query):
    check=REGISTRY[ports.SOURCE_QUERIES[query]];spec=ports.RUNTIMES[query]
    item=copy.deepcopy(CASES[check.id]['pass']);item['configuration']['properties']['linuxFxVersion']={}
    assert check.evaluate(item,{})[0]=='UNKNOWN'
    if spec[0].endswith('linux'):
        assert check.evaluate({'kind':'app' if spec[0].startswith('app') else 'functionapp'},{})[0]=='NOT_APPLICABLE'
    source=next(r['source_review'] for r in REVIEWS.values() if r['source_review']['query_id']==query)
    assert source['resolved_default_baseline']==spec[-1] and '$1' in source['pinned_sql']
    assert source['parameter_semantics'].startswith('Pinned query default')


@pytest.mark.parametrize('query',ports.RUNTIMES)
def test_captured_source_variable_binding_is_preserved_and_native_context_is_required(query):
    check=REGISTRY[ports.SOURCE_QUERIES[query]];selector,language,prefix,default=ports.RUNTIMES[query]
    item=copy.deepcopy(CASES[check.id]['pass']);wanted='99' if language=='java' else prefix+'|99'
    index={'context':{'metadata':{'source_parameters':{query:wanted}}}}
    assert check.evaluate(item,index)[0]=='FAIL'
    item['configuration']['properties']['linuxFxVersion']=prefix+'|99'
    assert check.evaluate(item,index)[0]=='PASS'
    index['context']['metadata']['source_parameters'][query]={}
    assert check.evaluate(item,index)[0]=='UNKNOWN'
    item['configuration']['properties']['linuxFxVersion']=None
    assert check.evaluate(item,{})[0]=='UNKNOWN'


@pytest.mark.parametrize('cid',ports.CHECK_IDS)
def test_pinned_status_case_differential_truth_for_every_app_predicate(cid):
    duckdb=pytest.importorskip('duckdb')
    proof=next(r['source_review'] for r in REVIEWS.values() if cid in r['native_checks'])
    expression=re.search(r'(case\b(?:(?!\bcase\b).)*?\bend)\s+as\s+status',proof['pinned_sql'],re.I|re.S).group(1)
    expression=expression.replace('b.id','joined_id')
    expression=re.sub(r'\b(?:a|app|s|fa)\.', '',expression)
    expression=re.sub(r"\b(?:configuration|auth_settings|diagnostic_logs_configuration)(?:\s*->>?\s*'[^']*')+",lambda m:'('+m[0]+')',expression)
    expression=re.sub(r"\(([^()]*)\)\s*@>\s*('[^']*')",r'json_contains(\1,\2::JSON)',expression)
    expression=expression.replace('::bool','::BOOLEAN')
    baseline=proof.get('resolved_default_baseline')
    expression=expression.replace('$1',"'"+baseline+"'") if baseline else expression
    for label,want in [('pass','ok'),('fail','alarm')]:
        item=CASES[cid][label];props=item.get('properties',{})
        with duckdb.connect(':memory:') as db:
            actual=db.execute('SELECT '+expression+' FROM (SELECT ?::JSON AS configuration,?::JSON AS auth_settings,?::JSON AS diagnostic_logs_configuration,? AS https_only,? AS client_cert_enabled,? AS kind,? AS sku_name,? AS joined_id)',[json.dumps(item.get('configuration',{})),json.dumps(item.get('authSettingsV1',{})),json.dumps(item.get('logsConfiguration',{})),props.get('httpsOnly'),props.get('clientCertEnabled'),item.get('kind'),item.get('sku',{}).get('name'),'selected-native-row']).fetchone()[0]
        assert actual==want
        assert REGISTRY[cid].evaluate(item,{})[0]=={'ok':'PASS','alarm':'FAIL'}[want]
