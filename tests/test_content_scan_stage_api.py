"""Standard public scan API derives content authority from its owned connector."""
import json
from unittest.mock import patch
from fastapi.testclient import TestClient
from peaso.auth import CredentialCipher, Identity
from peaso.server import create_app
from peaso.server.config import Settings
from peaso.storage import SQLiteStore, FileArtifacts

SCOPE='/subscriptions/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
LEAK='azure.review.acr.selected_image_secret_indicators'
IMAGE='azure.review.acr.selected_image_high_critical_vulnerabilities'
AUTO={'azure.review.app_service.selected_app_settings_secret_indicators','azure.review.configuration.selected_content_secret_indicators'}

def test_normal_api_feature_flags_publish_capabilities_and_freeze_native_ids(tmp_path):
 settings=Settings(state_dir=tmp_path/'state',identity_dir=tmp_path/'identity')
 store=SQLiteStore(settings.state_dir);artifacts=FileArtifacts(tmp_path/'artifacts')
 cipher=CredentialCipher(settings.identity_dir)
 target=dict(registry_id=SCOPE+'/resourceGroups/qualification/providers/Microsoft.ContainerRegistry/registries/registry1',repository='qualification/image',digest='sha256:'+'a'*64)
 options=dict(content_secret_scans=True,image_vulnerability_scans=True,selected_azure_acr_images=[target],selected_azure_acr_image_vulnerabilities=[target])
 connector=store.add_connector('alice',{'name':'fixture','provider':'azure','scopes':[SCOPE]},cipher.encrypt({'auth':{'method':'client-secret','client_id':'fixture','client_secret':'private-fixture','tenant_id':'fixture'},'options':options}))
 class Auth:
  def authenticate(self,_):return Identity('alice')
  def is_paid(self,_):return False
 with patch('peaso.storage.runtime.WorkflowDispatcher.dispatch',return_value=None), TestClient(create_app(settings,store=store,artifacts=artifacts,authenticator=Auth()),base_url='http://127.0.0.1') as client:
  response=client.get('/api/connectors');assert response.status_code==200
  public=next(row for row in response.json()['items'] if row['id']==connector['id'])
  assert set(public['content_scan_checks']['leaks'])=={LEAK}|AUTO
  assert set(public['content_scan_checks']['images'])=={IMAGE}
  assert 'private-fixture' not in response.text and target['registry_id'] not in json.dumps(public['content_scan_checks'])
  response=client.post('/api/scans',json={'connector_id':connector['id'],'categories':[],'checks':[],'frameworks':['CIS'],'leaks_enabled':True,'images_enabled':True,'ai_enabled':False})
  assert response.status_code==201,response.text
  saved=json.loads(store.job('alice',response.json()['id'])['data'])
  assert saved['checks']==[] and saved['categories']==[] and saved['frameworks']==['CIS']
  assert set(saved['content_checks'])=={LEAK,IMAGE}|AUTO
  assert saved['leaks_enabled'] and saved['images_enabled']
  wrong=store.add_connector('alice',{'name':'unconfigured','provider':'azure','scopes':[SCOPE]},cipher.encrypt({'auth':{},'options':{}}))
  rejected=client.post('/api/scans',json={'connector_id':wrong['id'],'images_enabled':True,'ai_enabled':False})
  assert rejected.status_code==422
  assert 'Configure enabled images targets' in rejected.text
