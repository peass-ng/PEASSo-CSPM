"""Source exact parameter selectors are distinct from broader safe settings."""
import copy,json
from pathlib import Path
import pytest
from peaso.checks import CHECKS,azure_ports_flexible as ports
from peaso.checks.fixtures import CASES
ROOT=Path(__file__).resolve().parent.parent
REVIEWS=json.loads((ROOT/'peaso/rulepacks/reviewed_azure_ports_flexible.json').read_text())
REGISTRY={c.id:c for c in CHECKS}


@pytest.mark.parametrize('cid',ports.CHECK_IDS)
def test_flexible_source_pass_fail_missing_denied_malformed_and_purity(cid):
    for label,want in (('pass','PASS'),('fail','FAIL')):
        item=copy.deepcopy(CASES[cid][label]);before=copy.deepcopy(item)
        assert REGISTRY[cid].evaluate(item,{})[0]==want
        assert item==before
    for item in ({},None,[],{'collection_status':'denied'},{'collection_status':'partial'}):assert REGISTRY[cid].evaluate(item,{})[0]=='UNKNOWN'


@pytest.mark.parametrize('query',ports.PARAMETERS)
def test_parameter_exact_scope_absent_version_context_duplicate_denied_and_pinned_selector(query):
    check=REGISTRY[ports.SOURCE_QUERIES[query]];item=copy.deepcopy(CASES[check.id]['pass'])
    row=item['configurations'][0]
    assert check.evaluate({'configurations':[]},{})[0]=='UNKNOWN'
    item['configurations'].append(copy.deepcopy(row))
    assert check.evaluate(item,{})[0]=='UNKNOWN'
    item['configurations']=[row];item['_coverage']={'configurations':{'status':'denied'}}
    assert check.evaluate(item,{})[0]=='UNKNOWN'
    proof=next(r['source_review'] for r in REVIEWS.values() if r['source_review']['query_id']==query)
    assert ports.PARAMETERS[query][1] in proof['pinned_sql']
    assert ports.PARAMETERS[query][2] in proof['pinned_sql'] or ports.PARAMETERS[query][1]=='logfiles.retention_days'


def test_tls_pair_and_exact_connection_event_do_not_broadmerge_safe_variant_lists():
    tls=REGISTRY[ports.SOURCE_QUERIES['mysql_flexible_server_min_tls_1_2']]
    audit=REGISTRY[ports.SOURCE_QUERIES['mysql_flexible_server_audit_logging_events_connection_set']]
    assert tls.evaluate({'configurations':[{'name':'tls_version','properties':{'value':'TLSv1.2'}}]},{})[0]=='FAIL'
    assert audit.evaluate({'configurations':[{'name':'audit_log_events','properties':{'value':'CONNECTION,DDL'}}]},{})[0]=='FAIL'


def test_zero_endpoint_source_declaration_does_not_merge_effective_network_disabled_skip():
    check=REGISTRY[ports.SOURCE_QUERIES['postgres_flexible_server_allow_access_to_azure_services_disabled']]
    item=copy.deepcopy(CASES[check.id]['fail']);item['properties']={'network':{'publicNetworkAccess':'Disabled'}}
    assert check.evaluate(item,{})[0]=='FAIL'
    item['_coverage']={'firewallRules':{'status':'partial'}}
    assert check.evaluate(item,{})[0]=='UNKNOWN'


@pytest.mark.parametrize('start,end',[('not-an-ip','10.0.0.1'),('::','::1'),('10.0.0.2','10.0.0.1')])
def test_firewall_malformed_or_reversed_interval_is_unknown(start,end):
    check=REGISTRY[ports.SOURCE_QUERIES['postgres_flexible_server_allow_access_to_azure_services_disabled']]
    assert check.evaluate({'firewallRules':[{'properties':{'startIpAddress':start,'endIpAddress':end}}]},{})[0]=='UNKNOWN'
