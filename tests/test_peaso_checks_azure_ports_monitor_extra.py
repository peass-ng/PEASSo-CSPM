"""Monitor literal category/count and named container selection have exact truth fixtures."""
import copy
import pytest
from peaso.checks import CHECKS,azure_ports_monitor_extra as ports
from peaso.checks.fixtures import CASES
import copy,json
REGISTRY={c.id:c for c in CHECKS}


@pytest.mark.parametrize('cid',ports.CHECK_IDS)
def test_monitor_exact_pass_fail_missing_denied_partial_malformed_and_purity(cid):
    f=CASES[cid]
    for label,want in (('pass','PASS'),('fail','FAIL')):
        item,index=copy.deepcopy(f[label]),copy.deepcopy(f.get(label+'_index',{}));before=copy.deepcopy((item,index))
        assert REGISTRY[cid].evaluate(item,index)[0]==want
        assert (item,index)==before
    for item in ({},None,[],{'collection_status':'denied'},{'collection_status':'partial'}):assert REGISTRY[cid].evaluate(item,{})[0]=='UNKNOWN'


def test_required_scope_presence_complete_empty_fails_and_foreign_or_denied_unknown():
    for q,k in [('monitor_application_insights_configured','application_insights'),('monitor_diagnostic_settings_exists_for_subscription','subscription_diagnostic_setting')]:
        check=REGISTRY[ports.SOURCE_QUERIES[q]];f=CASES[check.id]
        assert check.evaluate({'scope':'/tenants/t'},f['pass_index'])[0]=='NOT_APPLICABLE'
        index=copy.deepcopy(f['pass_index']);index[k][0]['data']['id']=index[k][0]['data']['id'].replace('/sub/','/foreign/')
        assert check.evaluate(f['pass'],index)[0]=='UNKNOWN'
        for state in ('denied','partial','malformed'):
            index=copy.deepcopy(f['pass_index']);index['collections'][k][0]['status']=state
            assert check.evaluate(f['pass'],index)[0]=='UNKNOWN'


def test_literal_four_categories_and_duplicate_shape_not_alllogs_broad_merge():
    check=REGISTRY[ports.SOURCE_QUERIES['monitor_diagnostic_settings_captures_proper_categories']]
    assert check.evaluate({'properties':{'logs':[{'categoryGroup':'allLogs','enabled':True}]}},{})[0]=='FAIL'
    duplicate={'properties':{'logs':[{'category':'Administrative','enabled':True}]*4}}
    assert check.evaluate(duplicate,{})[0]=='UNKNOWN'
    duckdb=pytest.importorskip('duckdb')
    with duckdb.connect(':memory:') as db:
        db.execute('CREATE TABLE logs(category VARCHAR,enabled BOOLEAN)')
        db.executemany('INSERT INTO logs VALUES (?,?)',[(x,True) for x in ('Administrative','Security','Alert','Policy')])
        assert db.execute("SELECT count(*) FILTER (WHERE enabled AND category IN ('Administrative','Security','Alert','Policy')) FROM logs").fetchone()[0]==4


def test_named_container_applicability_full_parent_identity_and_denied_absence_context():
    for prefix in ('activity','operational'):
        public=REGISTRY[ports.SOURCE_QUERIES['monitor_logs_storage_container_insights_'+prefix+'_logs_not_public_accessible']]
        assert public.evaluate({'name':'other'},{})[0]=='NOT_APPLICABLE'
        cmk=REGISTRY[ports.SOURCE_QUERIES['monitor_logs_storage_container_insights_'+prefix+'_logs_encrypted_with_byok']]
        item=copy.deepcopy(CASES[cmk.id]['pass']);item['blobContainers']=[]
        assert cmk.evaluate(item,{})[0]=='NOT_APPLICABLE'
        item['_coverage']={'blobContainers':{'status':'denied'}}
        assert cmk.evaluate(item,{})[0]=='UNKNOWN'
        item=copy.deepcopy(CASES[cmk.id]['pass']);item['blobContainers'][0]['id']=item['blobContainers'][0]['id'].replace('/g/','/other/')
        assert cmk.evaluate(item,{})[0]=='UNKNOWN'
