"""Exact edge source admission and public-engine native snapshot witnesses."""
from copy import deepcopy
import gzip,json
from pathlib import Path
import pytest
from peaso.checks import CHECKS
from peaso.checks import azure_edge_native_admission_20261020 as admission
from peaso.engine import evaluate_snapshot
from peaso.checks.azure_review_observed_20261020 import observation
ROOT=Path(__file__).resolve().parents[1]
CAPTURES=json.loads(gzip.decompress((ROOT/'tests/fixtures/azure_edge_native_current_inputs_20261020.json.gz').read_bytes()))['cases']
CANDIDATES=[r for r in CAPTURES if r['evaluated_callable']['qualname']=='evaluate' and 'candidate' in r['case']]

@pytest.mark.parametrize('row',CANDIDATES,ids=lambda r:r['case'])
def test_registered_callback_evaluates_actual_native_snapshot(row):
    cid='azure.review.devops.visible_clone_urls_without_userinfo' if row['case'].startswith('visible_') else row['check_id']
    snapshot=deepcopy(row['snapshot']);before=deepcopy(snapshot)
    out=evaluate_snapshot(snapshot,checks=[cid],include_not_applicable=True)
    assert {f['status']for f in out['findings']}=={f['status']for f in row['findings']}
    assert snapshot==before
    for f in out['findings']:
        if f['status']in('PASS','FAIL'):
            assert observation(f) and len(observation(f))<190
            assert observation({**f,'status':'FAIL'if f['status']=='PASS'else'PASS'}) is None
            assert observation({**f,'evidence':{**f['evidence'],'native_review_id':'unreviewed','observed':'Everything is protected.'}}) is None

def test_current_admission_is_idempotent_and_narrow_applicability_remains_scoped():
    before=tuple(CHECKS);admission.install();assert tuple(CHECKS)==before
    logs=next(c for c in CHECKS if c.id=='azure_application_gateway_app_http_logs_enabled_2de0361')
    assert logs.target=='scope' and logs.kind=='application_gateway'
    assert logs.empty_applicability_dependencies==('application_gateway',)
    assert 'load_balancer'not in logs.dependencies
    assert set(logs.dependencies)=={'application_gateway','diagnostic_setting','diagnostic_category','log_analytics_workspace','storage_account'}
