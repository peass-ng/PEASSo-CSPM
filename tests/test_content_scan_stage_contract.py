"""Independent configured content stages never widen ordinary H&C selectors."""
from copy import deepcopy
import json
import pytest
from peaso import engine, content_scan_selection as selection
from peaso.snapshot import make_snapshot

AZURE='/subscriptions/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
AZURE2='/subscriptions/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
TARGET=dict(registry_id=AZURE+'/resourceGroups/qualification/providers/Microsoft.ContainerRegistry/registries/registry1',repository='qualification/positive',digest='sha256:'+'a'*64)
LEAK='azure.review.acr.selected_image_secret_indicators'
IMAGE='azure.review.acr.selected_image_high_critical_vulnerabilities'
AUTO={'azure.review.app_service.selected_app_settings_secret_indicators','azure.review.configuration.selected_content_secret_indicators'}

def request(**extra):
 value={'connector':{'provider':'azure','scopes':[AZURE,AZURE2], 'options':dict(content_secret_scans=True,image_vulnerability_scans=True,selected_azure_acr_images=[TARGET],selected_azure_acr_image_vulnerabilities=[TARGET])},'categories':list(engine.CATEGORIES),'checks':[],'frameworks':[]}
 value.update(extra);return value

@pytest.mark.parametrize('provider,option,check,stage',[
 ('aws','selected_aws_lambda_functions','aws.review.lambda.selected_environment_secret_indicators','leaks'),
 ('azure','selected_azure_acr_images',LEAK,'leaks'),
 ('gcp','selected_gcp_registry_image_vulnerabilities','gcp.review.artifact_image.selected_image_vulnerabilities','images'),
 ('k8s','selected_k8s_literal_resources','k8s.review.selected_literals.secret_indicators','leaks'),
 ('k8s','selected_k8s_registry_images','k8s.review.selected_registry_image_high_vulnerabilities','images'),
])
def test_configured_capability_requires_exact_opt_in(provider,option,check,stage):
 flag='content_secret_scans' if stage=='leaks' else 'image_vulnerability_scans'
 assert check not in selection.configured_checks(provider,{option:[{}]})[stage]
 assert check not in selection.configured_checks(provider,{flag:True,option:[]})[stage]
 assert check in selection.configured_checks(provider,{flag:True,option:[{}]})[stage]
 assert check not in selection.configured_checks('wrong-provider',{flag:True,option:[{}]})[stage]

@pytest.mark.parametrize('leaks,images',[(False,False),(True,False),(False,True),(True,True)])
def test_feature_flags_derive_only_configured_exact_checks(leaks,images):
 raw=request(leaks_enabled=leaks,images_enabled=images);before=deepcopy(raw)
 effective=selection.normalize_request(raw)
 assert set(effective['content_checks'])==({LEAK}|AUTO if leaks else set())|({IMAGE} if images else set())
 assert raw==before
 assert effective['categories']==raw['categories'] and effective['checks']==[]
 assert effective['frameworks']==[]


def test_disabled_flags_mask_runtime_copy_without_changing_saved_connector():
 raw=request(leaks_enabled=False,images_enabled=False);before=deepcopy(raw)
 actual=engine._request(raw)
 assert actual['options']['content_secret_scans'] is False
 assert actual['options']['image_vulnerability_scans'] is False
 assert raw==before


def test_unknown_unconfigured_and_cross_provider_content_checks_rejected():
 for checks in ([IMAGE+'unknown'],['gcp.review.artifact_image.selected_image_vulnerabilities']):
  with pytest.raises(ValueError):engine.plan_collection(request(content_checks=checks))
 raw=request(content_checks=[IMAGE]);raw['connector']['options']['selected_azure_acr_image_vulnerabilities']=[]
 with pytest.raises(ValueError):engine.plan_collection(raw)


def test_full_standard_feature_request_keeps_both_content_dependencies():
 raw=request(leaks_enabled=True,images_enabled=True)
 plan=set(engine.plan_collection(raw))
 assert {'acr_selected_image','acr_selected_image_vulnerabilities'}<=plan
 # Selecting image tools does not implicitly authorize unrelated legacy streams.
 assert 'activity_log' not in plan and 'directory_audit' not in plan


def test_content_only_ignores_hardening_framework_category_filters():
 raw=request(categories=[],frameworks=['CIS'],leaks_enabled=True,images_enabled=True)
 effective=selection.normalize_request(raw)
 categories,native=engine._selection('azure',effective['categories'],[],effective['frameworks'],content_checks=effective['content_checks'])
 assert categories==[] and {c.id for c in native}=={LEAK,IMAGE}|AUTO
 assert {'acr_selected_image','acr_selected_image_vulnerabilities'}<=set(engine.plan_collection(raw))
 assert selection.capture_checks(effective)=={LEAK,IMAGE}|AUTO


def test_content_only_reaches_real_evaluator_without_hardening_selection():
 snapshot=make_snapshot('azure',[AZURE],[],created_at='2026-10-24T00:00:00+00:00')
 report=engine.evaluate_snapshot(snapshot,categories=[],checks=[],frameworks=['CIS'],content_checks=[LEAK])
 ids={row.get('id',row.get('check_id')) for row in report['coverage']}
 assert LEAK in ids
 assert {row['check_id'] for row in report['findings']} <= {LEAK}


@pytest.mark.parametrize('mode,expected',[('leaks',True),('images',False),('disabled',False)])
def test_real_encrypted_private_witness_preserves_exact_content_authority(mode,expected):
 from peaso import secret_evidence as evidence,secret_scanning as scanning
 raw=request(categories=[],frameworks=['CIS'],leaks_enabled=(mode=='leaks'),images_enabled=(mode=='images'))
 effective=selection.normalize_request(raw)
 selected=selection.capture_checks(effective)
 cipher=evidence.EphemeralCipher();value='synthetic-offline-witness-never-used-Q8x7!';fp=scanning._fingerprint(value)
 resource=TARGET['registry_id']+'/repositories/'+TARGET['repository']+'@'+TARGET['digest']
 with evidence.capture(cipher,tenant='alice',scan_id='fixture',options=selection.effective_options(effective),selected_checks=selected) as sink:
  with evidence.source_context(resource_id=resource,scope=AZURE,image_digest=TARGET['digest'],check_ids={LEAK}):
   evidence.remember(value,fp,path='/app/private.conf',line=3,engine='trufflehog',rule='synthetic-offline')
 document=sink.document()
 assert value not in json.dumps(document)
 if not expected:
  assert not sink.records
  return
 assert set(sink.records)=={fp}
 row=cipher.decrypt(sink.records[fp])
 assert row['value']==value and row['locations'][0]['path']=='/app/private.conf'
 assert row['locations'][0]['line']==3
 assert row['locations'][0]['resource_id']==resource
 assert LEAK in row['check_ids']
 finding={'id':'fixture','provider':'azure','check_id':LEAK,'status':'FAIL','finding_type':'secrets','scope':AZURE,'resource_id':resource,'native_resource_id':resource,'evidence':{},'secret_fingerprint':fp}
 detail=evidence.details(finding,document,cipher,tenant='alice',scan_id='fixture')
 assert detail['matches'][0]['value']==value and detail['matches'][0]['locations'][0]['path']=='/app/private.conf'


def test_api_models_retain_new_stage_selection_and_strict_booleans():
 from peaso.server.models import ScanCreate,SchedulePatch
 payload=ScanCreate.model_validate(dict(connector_id='fixture',categories=[],content_checks=[IMAGE],images_enabled=True,leaks_enabled=False,ai_enabled=False))
 assert payload.model_dump()['content_checks']==[IMAGE]
 assert SchedulePatch.model_validate({'images_enabled':False}).images_enabled is False
 with pytest.raises(ValueError):ScanCreate.model_validate({'connector_id':'fixture','images_enabled':'yes'})


def test_shared_selector_profiles_do_not_enable_unconfigured_readers():
 options={'content_secret_scans':True,'selected_dataproc_referenced_sources':[{'profile':'job'}]}
 known=selection.configured_checks('gcp',options)['leaks']
 assert 'gcp.review.dataproc.selected_job_referenced_source_secret_indicators' in known
 assert 'gcp.review.dataproc.selected_initialization_referenced_source_secret_indicators' not in known
 for option in ('selected_azure_databricks_files','selected_azure_databricks_task_outputs'):
  assert 'azure.review.databricks.selected_notebook_source_secret_indicators' in selection.configured_checks('azure',{'content_secret_scans':True,option:[{}]})['leaks']


def test_native_reference_and_environment_capabilities_need_opt_in_not_extra_selectors():
 options={'content_secret_scans':True}
 gcp=set(selection.configured_checks('gcp',options)['leaks'])
 assert {'gcp.review.function.literal_environment_secret_indicators','gcp.review.function.resolved_source_archive_secret_indicators','gcp.review.composer.dag_source_secret_indicators'} <= gcp
 assert 'gcp.review.gke_workload.literal_configuration_secret_indicators' not in gcp
 assert not selection.configured_checks('gcp',{'content_secret_scans':False})['leaks']
 aws=set(selection.configured_checks('aws',options)['leaks'])
 assert 'aws.review.lambda_function.package_content_secret_indicators' in aws
 assert 'aws_cis_ec2_userdata_embedded_secrets' in aws
 assert 'aws.review.ecs_task_definition.configuration_secret_indicators' not in aws
 assert {'aws.review.lambda.selected_environment_secret_indicators',
         'aws.review.configuration.selected_content_secret_indicators'} <= aws
 assert not selection.configured_checks('aws',{'content_secret_scans':False})['leaks']
 assert not selection.configured_checks('azure',{'image_vulnerability_scans':True})['images']


def test_native_environment_disabled_preserves_zero_detector_io(monkeypatch):
 from peaso.collectors import gcp_function_secret_indicators as native
 calls=[]
 monkeypatch.setattr(native,'scan_content',lambda *a,**k:calls.append((a,k)))
 native.project_response({'name':'projects/fixture-project/locations/us-central1/functions/function1','serviceConfig':{'environmentVariables':{'EXAMPLE':'synthetic-offline'}}},method='GET',url='https://cloudfunctions.googleapis.com/v2/projects/fixture-project/locations/us-central1/functions/function1',scope='projects/fixture-project',enabled=False)
 assert calls==[]
