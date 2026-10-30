"""Finite native security contacts, settings, assessments and workspace declarations."""
from copy import deepcopy
import socket
from urllib.parse import urlsplit
import pytest
from peaso.collectors import azure
from peaso.engine import evaluate_snapshot
from tests.test_peaso_azure_bulk_native import SUB,SCOPE,BASE,Transport,parent

# Independent provider-shaped declarations; no runtime CASES or closures imported.
ASSESSMENTS = {
 'azure.claude.defender_assessment_endpoint_protection':['Install endpoint protection solution on virtual machines'],
 'azure.claude.defender_assessment_vulnerability_solution':['Machines should have a vulnerability assessment solution'],
 'azure.claude.defender_assessment_running_images_vulnerabilities':['Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management)'],
 'azure.claude.defender_assessment_system_updates':['Log Analytics agent should be installed on virtual machines','Machines should be configured to periodically check for missing system updates','System updates should be installed on your machines'],
}
SPECS = [(cid,'security_assessment') for cid in ASSESSMENTS] + [
 ('azure.claude.defender_alert_notifications_high','security_contact'),
 ('azure.claude.defender_alerts_to_owner','security_contact'),
 ('azure.claude.defender_attack_path_notifications','security_contact'),
 ('azure.claude.defender_contact_has_email','security_contact'),
 ('azure.claude.defender_security_contact_email_configured','security_contact'),
 ('azure.port.defender_alert_severity_contact','security_contact'),
 ('azure.port.defender_notify_owner_contact','security_contact'),
 ('azure.port.defender_required_mcas','security_setting'),
 ('azure.port.defender_required_wdatp','security_setting'),
 ('azure.port.securitycenter_mcas_integration','security_setting'),
 ('azure.port.securitycenter_wdatp_integration','security_setting'),
 ('azure.claude2.defender_attack_path_setting_and_alert_contacts','security_setting'),
 ('azure.claude.log_analytics_local_auth_disabled','log_analytics_workspace'),
 ('azure.claude.log_analytics_public_ingestion_query_disabled','log_analytics_workspace'),
 ('azure_log_analytics_workspace_10_5_1_4_8c74ccb','log_analytics_workspace'),
]
TYPES={'security_assessment':'Microsoft.Security/assessments','security_contact':'Microsoft.Security/securityContacts',
       'security_setting':'Microsoft.Security/settings','log_analytics_workspace':'Microsoft.OperationalInsights/workspaces'}
MODES=('good','bad','empty','denied','partial','foreign','malformed','wrong-type')


@pytest.fixture(autouse=True)
def offline(monkeypatch):
 def blocked(*a,**k):pytest.fail('Native monitoring review forbids sockets, DNS and auth')
 for obj,name in ((socket,'create_connection'),(socket,'getaddrinfo'),(socket.socket,'connect'),(socket.socket,'connect_ex'),(azure,'AzureTransport'),(azure,'AzureTransportExposure')):monkeypatch.setattr(obj,name,blocked)


def capture(spec,mode):
 cid,kind=spec;native_type=TYPES[kind];endpoint=SCOPE+'/providers/'+native_type;bad=mode=='bad'
 if kind=='security_assessment':
  rows=[parent(BASE+'Microsoft.Compute/virtualMachines/review-vm/providers/'+native_type+'/assessment'+str(i),native_type,{'displayName':name,'status':{'code':'Unhealthy' if bad else 'Healthy'}}) for i,name in enumerate(ASSESSMENTS[cid])]
 elif kind=='security_contact':
  props={'emails':'' if bad else 'security@example.com','isEnabled':True,'notificationsByRole':{'state':'Off' if bad else 'On','roles':[] if bad else ['Owner']},'notificationsSources':[{'sourceType':'Alert','minimalSeverity':'Critical' if bad else 'High'},{'sourceType':'AttackPath','minimalRiskLevel':'Critical' if bad else 'High'}]}
  rows=[parent(endpoint+'/default',native_type,props)]
 elif kind=='security_setting':
  name='AttackPath' if 'attack_path' in cid else 'MCAS' if 'mcas' in cid else 'WDATP'
  rows=[parent(endpoint+'/'+name,native_type,{'enabled':not bad})]
 else:
  props={'features':{'disableLocalAuth':not bad},'publicNetworkAccessForIngestion':'Enabled' if bad else 'Disabled','publicNetworkAccessForQuery':'Enabled' if bad else 'Disabled','retentionInDays':30 if bad else 365}
  rows=[parent(BASE+native_type+'/review-workspace',native_type,props)]
 if mode=='malformed':
  for row in rows:row['properties']={'unrelated':True}
 if mode=='foreign':
  for row in rows:row['id']=row['id'].replace(SUB,'99999999-9999-9999-9999-999999999999')
 if mode=='wrong-type':
  for row in rows:row['type']='Microsoft.Compute/virtualMachines'
 routes={endpoint:{'value':deepcopy(rows)}}
 for row in rows:routes[row['id']]=deepcopy(row)
 if mode=='empty':routes[endpoint]={'value':[]}
 if mode=='denied':routes[endpoint]=azure.AzureReadError('Forbidden',403)
 if mode=='partial':
  def pages(query):
   if 'page' in query:raise azure.AzureReadError('Forbidden',403)
   return {'value':deepcopy(rows),'nextLink':azure.ARM+endpoint+'?page=2'}
  routes[endpoint]=pages
 wanted=[kind]
 if 'attack_path_setting' in cid:
  contact_type=TYPES['security_contact'];c=parent(SCOPE+'/providers/'+contact_type+'/default',contact_type,{'notificationsSources':[] if bad else [{'sourceType':'Alert','minimalSeverity':'High'}]})
  routes[SCOPE+'/providers/'+contact_type]={'value':[c]};wanted+=['security_contact']
 api=Transport(routes);snapshot=azure.collect({'provider':'azure','scopes':[SUB],'options':{'retries':0}},wanted,transport=api)
 return snapshot,api,evaluate_snapshot(snapshot,checks=[cid],include_not_applicable=True)['findings']


@pytest.mark.parametrize('spec',SPECS,ids=lambda s:s[0])
@pytest.mark.parametrize('mode',MODES)
def test_native_monitoring_deciding_fields_and_collection_boundaries(spec,mode):
 snapshot,api,findings=capture(spec,mode);cid,kind=spec
 if mode=='good':expected={'PASS'}
 elif mode=='bad':expected={'FAIL'}
 elif mode=='denied':expected={'DENIED'}
 elif mode=='empty':
  # Empty assessment inventory supplies no health or applicability result.
  if kind=='security_assessment':expected={'UNKNOWN'}
  elif 'attack_path_setting' in cid:expected={'NOT_APPLICABLE'}
  elif kind=='log_analytics_workspace' or cid in ('azure.claude.defender_attack_path_notifications','azure.claude.defender_contact_has_email','azure.port.defender_alert_severity_contact','azure.port.defender_notify_owner_contact'):expected={'EMPTY'}
  elif cid in ('azure.port.securitycenter_mcas_integration','azure.port.securitycenter_wdatp_integration'):expected={'UNKNOWN'}
  else:expected={'FAIL'}
 elif mode=='partial' and cid=='azure_log_analytics_workspace_10_5_1_4_8c74ccb':expected={'UNKNOWN'}
 elif mode=='partial' and kind in ('log_analytics_workspace','security_contact') and cid in ('azure.claude.defender_attack_path_notifications','azure.claude.defender_contact_has_email','azure.port.defender_alert_severity_contact','azure.port.defender_notify_owner_contact','azure.claude.log_analytics_local_auth_disabled','azure.claude.log_analytics_public_ingestion_query_disabled','azure_log_analytics_workspace_10_5_1_4_8c74ccb'):expected={'PASS','UNKNOWN'}
 else:expected={'UNKNOWN'}
 assert {f['status'] for f in findings}==expected,(spec,mode,findings)
 # Selected security contacts also read the tenant's Entra domain list so
 # recipient domains can be classified; every other read stays on ARM.
 domains=[u for u in api.calls if urlsplit(u).hostname=='graph.microsoft.com']
 assert domains==([azure.GRAPH+'/v1.0/'+azure.DIRECTORY['directory_domain']] if kind=='security_contact' or 'attack_path_setting' in cid else [])
 assert api.calls and all(urlsplit(u).hostname=='management.azure.com' for u in api.calls if u not in domains)
