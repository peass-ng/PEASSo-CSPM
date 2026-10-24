"""Full scans retain explicitly named content inputs without implicit streams."""
import pytest
from peaso import engine

CASES=[
 ('aws','aws.review.lambda.selected_environment_secret_indicators','lambda_selected_environment'),
 ('azure','azure.review.acr.selected_image_secret_indicators','acr_selected_image'),
 ('gcp','gcp.review.artifact_image.selected_image_vulnerabilities','artifact_selected_image_vulnerabilities'),
 ('k8s','k8s.review.selected_registry_image_high_vulnerabilities','k8s_selected_registry_image_vulnerabilities'),
]

def full_request(provider,extra=()):
 categories,ordinary=engine._selection(provider,None,None,None)
 checks={check.id for check in ordinary}|set(extra)
 checks.update(check['id'] for check in engine._analysis_selection(provider,categories,None,None))
 checks.add(engine.PRIVESC_CHECK_ID)
 request={'connector':{'provider':provider},'categories':categories,'checks':sorted(checks)}
 _,selected=engine._selection(provider,categories,request['checks'],None)
 assert engine._full_selection(provider,categories,selected)
 return request

@pytest.mark.parametrize('provider,check,kind',CASES)
def test_full_scan_retains_explicit_named_bulk_dependency(provider,check,kind,monkeypatch):
 from types import SimpleNamespace
 # One declared native consumer isolates full-plan authority from unrelated
 # optional readers that need their own separately selected source targets.
 native=SimpleNamespace(id=check,provider=provider,category='hardening',kind=kind,dependencies=[kind],frameworks=[])
 monkeypatch.setattr(engine,'_registry',lambda:[native])
 request=full_request(provider,[check])
 assert kind in engine.BULK_STREAM_TYPES[provider]
 assert kind in engine.plan_collection(request)

@pytest.mark.parametrize('provider', ['aws','azure','gcp','k8s'])
def test_implicit_default_streams_are_unchanged(provider):
 from peaso.collectors import supported_types
 from peaso.checks.native_only import automated_inventory_types
 available=set(automated_inventory_types(provider,supported_types(provider)))
 expected=available-engine.BULK_STREAM_TYPES[provider]-({'iam_managed_policy'} if provider=='aws' else set())
 assert set(engine.plan_collection({'connector':{'provider':provider}}))==expected
 assert set(engine.plan_collection({'connector':{'provider':provider},'categories':list(engine.CATEGORIES),'checks':[]}))==expected


def test_full_azure_named_acr_both_inputs_are_retained():
 request=full_request('azure',['azure.review.acr.selected_image_secret_indicators','azure.review.acr.selected_image_high_critical_vulnerabilities'])
 assert {'acr_selected_image','acr_selected_image_vulnerabilities'} <= set(engine.plan_collection(request))


def test_aws_managed_library_remains_explicit():
 assert 'iam_managed_policy' not in engine.plan_collection({'connector':{'provider':'aws'}})
 assert 'iam_managed_policy' not in engine.plan_collection(full_request('aws'))
 assert 'iam_managed_policy' in engine.plan_collection({'connector':{'provider':'aws','options':{'inventories':['iam_managed_policy']}}})
 assert 'iam_managed_policy' in engine.plan_collection({'connector':{'provider':'aws','options':{'collect_all':True}}})
