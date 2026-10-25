"""Candidate pure capability table through real model/API/planner authority."""
import importlib.util,json
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from peaso import engine,collectors,content_scan_selection as selection
from peaso.auth import CredentialCipher,Identity
from peaso.server import create_app
from peaso.server.config import Settings
from peaso.server.models import ConnectorCreate,ScanCreate
from peaso.server.validation import validate_connector
from peaso.storage import SQLiteStore,FileArtifacts
from peaso.snapshot import make_snapshot

candidate=selection
CASES={
 'aws':(['123456789012/us-east-1'],{'method':'access_keys','aws_access_key_id':'synthetic-only','aws_secret_access_key':'synthetic-only'},
  {'aws.review.lambda.selected_environment_secret_indicators':'lambda_selected_environment','aws.review.configuration.selected_content_secret_indicators':'configuration_selected_content'}),
 'azure':(['/subscriptions/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'],{'method':'client-secret','tenant_id':'fixture','client_id':'fixture','client_secret':'synthetic-only'},
  {'azure.review.app_service.selected_app_settings_secret_indicators':'app_service_selected_settings','azure.review.configuration.selected_content_secret_indicators':'azure_configuration_selected_content'}),
 'k8s':(['default'],{'method':'token','server':'https://8.8.8.8','token':'synthetic-only'},
  {'k8s.review.selected_literals.secret_indicators':'k8s_selected_literals'}),
}
@pytest.mark.parametrize('provider',CASES)
@pytest.mark.parametrize('enabled',[True,False])
def test_standard_api_model_and_real_engine_derive_only_authorized_automatic_kinds(tmp_path,monkeypatch,provider,enabled):
 scopes,auth,expected=CASES[provider];options={'content_secret_scans':True};before=deepcopy((auth,options,scopes))
 settings=Settings(state_dir=tmp_path/'state',identity_dir=tmp_path/'identity')
 model=ConnectorCreate(name='automatic-fixture',provider=provider,auth=auth,scopes=scopes,options=options)
 validate_connector(provider,model.auth,model.options,settings,scopes=model.scopes)
 store=SQLiteStore(settings.state_dir);artifacts=FileArtifacts(tmp_path/'artifacts');cipher=CredentialCipher(settings.identity_dir)
 connector=store.add_connector('alice',{'name':model.name,'provider':provider,'scopes':scopes},cipher.encrypt({'auth':auth,'options':options}))
 class Auth:
  def authenticate(self,_):return Identity('alice')
  def is_paid(self,_):return False
 payload=ScanCreate(connector_id=connector['id'],categories=list(engine.CATEGORIES),checks=[],frameworks=[],leaks_enabled=enabled,images_enabled=False,ai_enabled=False).model_dump(exclude_none=True)
 with patch('peaso.storage.runtime.WorkflowDispatcher.dispatch',return_value=None),TestClient(create_app(settings,store=store,artifacts=artifacts,authenticator=Auth()),base_url='http://127.0.0.1') as client:
  public=client.get('/api/connectors').json()['items'][0]
  assert set(expected)<=set(public['content_scan_checks']['leaks'])
  response=client.post('/api/scans',json=payload);assert response.status_code==201,response.text
 saved=json.loads(store.job('alice',response.json()['id'])['data']);selected=set(saved['content_checks'])
 assert (set(expected)<=selected) if enabled else not (set(expected)&selected)
 request={'connector':model.model_dump(),**saved};prior=deepcopy(request)
 native=engine._request(request);plan=set(engine.plan_collection(request))
 if enabled:
  assert set(expected.values())<=plan
 else:
  # Ordinary H&C dependencies may retain an envelope kind; only a content
  # grant authorizes its reader, and false must mask the effective switch.
  assert native['options']['content_secret_scans'] is False
 assert not any(k.startswith('selected_') for k in native['options'])
 assert native['scopes']==scopes and native['auth']==auth
 observed=[]
 def collect(bound,required):
  observed.append((deepcopy(bound),required));return make_snapshot(provider,scopes,[])
 monkeypatch.setattr(collectors,'collect_live',collect)
 engine.collect_snapshot(request)
 grants=set(observed[0][0]['options'].get('_content_secret_scan_kinds',()))
 assert (set(expected.values())<=grants) if enabled else not(set(expected.values())&grants)
 assert request==prior and (auth,options,scopes)==before

@pytest.mark.parametrize('provider,option,check',[(provider,option,check) for provider,option,stage,check in candidate.ROWS if check in candidate._AUTOMATIC_NATIVE_CHECKS])
def test_explicit_empty_selection_is_not_replaced_by_automatic_targets(provider,option,check):
 assert check in candidate.configured_checks(provider,{'content_secret_scans':True})['leaks']
 assert check not in candidate.configured_checks(provider,{'content_secret_scans':True,option:[]})['leaks']
 assert check in candidate.configured_checks(provider,{'content_secret_scans':True,option:[{}]})['leaks']
 assert check not in candidate.configured_checks(provider,{'content_secret_scans':False})['leaks']

def test_unsupported_source_image_and_cluster_readers_stay_selector_gated_and_gcp_unchanged():
 for provider,option,stage,check in candidate.ROWS:
  if option is not None and check not in candidate._AUTOMATIC_NATIVE_CHECKS:
   flags={'content_secret_scans':True,'image_vulnerability_scans':True}
   assert check not in candidate.configured_checks(provider,flags)[stage]
 expected={check for owner,option,stage,check in candidate.ROWS if owner=='gcp' and option is None and stage=='leaks'}
 assert len(expected)==20
 assert set(candidate.configured_checks('gcp',{'content_secret_scans':True})['leaks'])==expected
