"""Tenant administrative values require real unique policy context; no missing defaults."""
import copy
import pytest
from peaso.checks import CHECKS,azure_ports_directory_extra as ports
from peaso.checks.fixtures import CASES

REGISTRY={c.id:c for c in CHECKS}


@pytest.mark.parametrize('cid',ports.CHECK_IDS)
def test_known_policy_pass_fail_missing_denied_partial_malformed_and_purity(cid):
    f=CASES[cid]
    for label,want in (('pass','PASS'),('fail','FAIL')):
        item,index=copy.deepcopy(f[label]),copy.deepcopy(f.get(label+'_index',{}));before=copy.deepcopy((item,index))
        assert REGISTRY[cid].evaluate(item,index)[0]==want
        assert (item,index)==before
    for item in ({},None,[],{'collection_status':'denied'},{'collection_status':'partial'}):assert REGISTRY[cid].evaluate(item,{})[0]=='UNKNOWN'


@pytest.mark.parametrize('query',list(ports.SOURCE_QUERIES)[:4])
def test_admin_setting_scope_empty_denied_duplicate_foreign_and_native_constraints_unknown(query):
    check=REGISTRY[ports.SOURCE_QUERIES[query]];f=CASES[check.id]
    index=copy.deepcopy(f['pass_index']);row=index['directory_setting'][0]['data'];entry=row['values'][0]
    assert check.evaluate({'scope':'/subscriptions/sub'},index)[0]=='NOT_APPLICABLE'
    row['values']=[]
    assert check.evaluate(f['pass'],index)[0]=='UNKNOWN'
    row['values']=[entry,copy.deepcopy(entry)]
    assert check.evaluate(f['pass'],index)[0]=='UNKNOWN'
    row['values']=[entry];row['_provenance']['tenant_id']='foreign'
    assert check.evaluate(f['pass'],index)[0]=='UNKNOWN'
    row['_provenance']['tenant_id']='tenant'
    for value in ('',None,'bad'):
        entry['value']=value
        assert check.evaluate(f['pass'],index)[0]=='UNKNOWN'
    for state in ('denied','partial','malformed','empty'):
        broken=copy.deepcopy(f['pass_index']);broken['collections']['directory_setting'][0]['status']=state
        if state=='empty':broken['directory_setting']=[]
        assert check.evaluate(f['pass'],broken)[0]=='UNKNOWN'


def test_registration_upn_scope_and_capability_does_not_substitute_registration():
    check=REGISTRY[ports.SOURCE_QUERIES['ad_user_mfa_enabled']]
    item=copy.deepcopy(CASES[check.id]['pass']);item['userPrincipalName']=None
    assert check.evaluate(item,{})[0]=='NOT_APPLICABLE'
    item=copy.deepcopy(CASES[check.id]['pass']);item.pop('isMfaRegistered');item['isMfaCapable']=True
    assert check.evaluate(item,{})[0]=='UNKNOWN'
    item['_provenance']['tenant_id']='foreign'
    assert check.evaluate(item,{'context':{'metadata':{'tenant_id':'tenant'}}})[0]=='UNKNOWN'
