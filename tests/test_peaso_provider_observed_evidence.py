"""Actual source facts produce brief observations, never a guessed verdict."""
from copy import deepcopy
import gzip,json
from pathlib import Path
import pytest
from tests.generic_k8s_behavior_successors_20261020 import current_cases
from tests.provider_observation_residual_successors_20261020 import AZURE_BINDINGS, azure_case, gcp_case
from tests.azure_native_successor_inputs_20261020 import native_row
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks.gcp_observed_evidence import evidence_summary as gcp
from peaso.finding_observation import evidence_summary as current_observation
from peaso.checks.facts import MemoIndex
from peaso.checks.azure_bulk_observed_evidence import evidence_summary as azure

CHECK={c.id:c for c in CHECKS}
GCP_IDS=tuple('''gcp.ports.compute_instance_ip_forwarding_disabled
gcp.ports.compute_instance_block_project_wide_ssh_enabled
gcp.ports.function_logging_mutation_declarations
gcp.ports.function_legacy_deployment_role_declarations
gcp.ports.compute_ssl_policy_strict_declaration
gcp.ports.cloud_run_service_policy_prohibit_public_access
gcp.ports.api_key_meaningful_restrictions
gcp.claude.instance.sa_no_data_destruction_permission
gcp.claude.instance.sa_no_database_write_permission
gcp.claude.instance.sa_no_deployments_manager_permission
gcp.claude.instance.sa_no_disrupt_logging_permission
gcp.claude.instance.sa_no_iam_write_permission
gcp.claude.instance.sa_no_service_account_impersonate_permission
gcp.claude.instance.sa_no_deny_policy_write_permission
gcp.claude2.logging.sink_all_log_entries
gcp.ports.compute_network_dns_logging_scoped
gcp.ports.dns_managed_zone_key_signing_not_using_rsasha1
gcp.ports.dns_managed_zone_zone_signing_not_using_rsasha1
gcp.ports.storage_bucket_not_publicly_accessible
gcp.ports.cloudfunction_function_restrict_public_access
gcp.ports.function_active_public_binding
gcp.ports.cloudrun_service_restrict_public_access
gcp.ports.bigquery_dataset_not_publicly_accessible
gcp.ports.sql_private_ip_assignments
gcp_certificate_validity
gcp_pci_bucket_157fb0c69361
gcp_backend_service_checks_armor_security_policy_contains_f48cc81ccae3
gcp.identity.super_admin_recovery_group
gcp_cloud_armor_waf_enabled
gcp_kms_key_destroy_alert
gcp_logging_enumeration_alert
gcp_certificate_renewal_30_days'''.splitlines())
BULK=json.loads(gzip.decompress((Path(__file__).parent/'fixtures/azure_bulk_clarity_reviewed.json.gz').read_bytes()))
AZURE_IDS=tuple(cid for cid in BULK if cid in {c.id for c in __import__('peaso.checks.native_only',fromlist=['automated_checks']).automated_checks(CHECKS)})

# These reviewed successors require native hierarchy/customer/Directory joins.
# Keep historical CENTRAL unchanged; use their separately captured native cases.
NATIVE_CASES=json.loads((Path(__file__).parent/'fixtures/gcp-native-review-behavior.json').read_text())['cases']
NATIVE_SUCCESSORS={'gcp_pci_bucket_157fb0c69361',
                   'gcp.identity.non_service_account_mfa',
                   'gcp.identity.super_admin_recovery_group'}


def current_case(cid, branch):
 native=gcp_case(cid,branch,CASES.get(cid))
 if native is not None:return native
 if cid in NATIVE_SUCCESSORS:
  row=next(row for row in NATIVE_CASES
           if row['check_id']==cid and row['expected_status']==branch.upper())
  return deepcopy(row['item']),MemoIndex(deepcopy(row['index']))
 # Current successors bind authority the historical fixtures omitted.
 fx=current_cases(CHECK[cid],CASES[cid])
 return deepcopy(fx[branch]),MemoIndex(deepcopy(fx.get(branch+'_index',fx.get('index',{}))))

@pytest.mark.parametrize('cid',GCP_IDS)
@pytest.mark.parametrize('branch',['pass','fail'])
def test_gcp_actual_callbacks_have_brief_typed_observations(cid,branch):
 item,index=current_case(cid,branch)
 status,evidence=CHECK[cid].evaluate(item,index)
 assert status==branch.upper()
 finding={'provider':'gcp','check_id':cid,'status':status,'evidence':evidence};before=deepcopy(finding)
 summary=(current_observation if cid in NATIVE_SUCCESSORS or cid=='gcp_kms_key_destroy_alert' else gcp)(finding)
 assert summary and len(summary)<=350
 assert 'semantics:'not in summary and 'supplied records'not in summary and 'More recorded details'not in summary
 assert finding==before

# Fresh collector witnesses that supersede stale generic BULK shapes.
CURRENT_GENERIC_WITNESSES={'azure_storage_account_10_3_4_7_02943e9'}

@pytest.mark.parametrize('cid',AZURE_IDS)
def test_azure_actual_bulk_success_shapes_have_direct_observations(cid):
 case,_=azure_case(cid,'PASS',BULK[cid]['PASS'])
 if cid in CURRENT_GENERIC_WITNESSES:
  # Keep the historical BULK case; the current evaluator needs the
  # source-bound collector witness that superseded it.
  case=native_row(cid,'pass');assert case is not None
 status,evidence=CHECK[cid].evaluate(deepcopy(case['item']),deepcopy(case['index']))
 assert status=='PASS'
 finding={'provider':'azure','check_id':cid,'status':status,'evidence':evidence};before=deepcopy(finding)
 text=(current_observation if cid in AZURE_BINDINGS else azure)(finding)
 assert text and len(text)<250
 assert 'semantics:'not in text and 'supplied records'not in text
 assert finding==before

@pytest.mark.parametrize('status',['UNKNOWN','DENIED','MANUAL','EMPTY','NOT_APPLICABLE'])
def test_uncertain_statuses_do_not_get_current_interpretations(status):
 for provider,cid,fn in [('gcp',GCP_IDS[0],gcp),('azure',AZURE_IDS[0],azure)]:
  assert fn({'provider':provider,'check_id':cid,'status':status,'evidence':{}})is None

@pytest.mark.parametrize('value',[None,0,'true',[],{}])
def test_malformed_decisive_boolean_does_not_become_an_observation(value):
 assert gcp({'provider':'gcp','status':'FAIL','check_id':GCP_IDS[0],'evidence':{'can_ip_forward':value}})is None


def test_incoming_sql_address_and_outgoing_source_are_distinct():
 base={'provider':'gcp','status':'PASS','check_id':'gcp.ports.sql_private_ip_assignments'}
 outgoing=gcp({**base,'evidence':{'address_types':['OUTGOING'],'public_incoming_types':[]}})
 assert 'outbound source'in outgoing and 'private incoming'in outgoing
 public=gcp({**base,'status':'FAIL','evidence':{'address_types':['PRIMARY'],'public_incoming_types':['PRIMARY']}})
 assert public=='The Cloud SQL address list includes a public incoming IP.'


def test_legacy_empty_producer_payloads_state_the_specific_missing_observation():
 text=gcp({'provider':'gcp','status':'FAIL','check_id':'gcp.ports.compute_instance_block_project_wide_ssh_enabled','evidence':{}})
 assert text=='The recorded SSH-key assessment omits the project-key blocking setting.'

GCP_SUCCESS_IDS=tuple(c.id for c in __import__('peaso.checks.native_only',fromlist=['automated_checks']).automated_checks(CHECKS) if c.provider=='gcp' and c.id in CASES and 'pass'in CASES[c.id])

@pytest.mark.parametrize('cid',GCP_SUCCESS_IDS)
def test_every_available_active_gcp_success_callback_has_typed_observation(cid):
 item,index=current_case(cid,'pass')
 status,evidence=CHECK[cid].evaluate(item,index)
 assert status=='PASS'
 finding={'provider':'gcp','check_id':cid,'status':status,'evidence':evidence};before=deepcopy(finding)
 # Exercise the renderer used by production, including newly admitted checks.
 text=current_observation(finding)
 assert text and len(text)<400
 assert 'supplied records'not in text and 'More recorded details'not in text
 assert finding==before

@pytest.mark.parametrize('cid',GCP_SUCCESS_IDS)
def test_empty_or_uncertain_success_records_do_not_invent_settings(cid):
 for status in ('UNKNOWN','DENIED','NOT_APPLICABLE'):
  assert gcp({'provider':'gcp','check_id':cid,'status':status,'evidence':{}})is None


def test_configuration_is_not_confused_with_explicit_declaration_or_sql_default():
 assert gcp({'provider':'gcp','status':'PASS','check_id':'gcp.ports.app_engine_application_iap_enabled','evidence':{'field':'iap.enabled','configured':True,'declared':False}})=='App Engine Identity-Aware Proxy is enabled.'
 assert gcp({'provider':'gcp','status':'PASS','check_id':'gcp.ports.sql_instance_sql_user_options_database_flag_not_configured','evidence':{'flag':'user options','configured':None}})=='No explicit Cloud SQL user options flag is recorded.'
 assert gcp({'provider':'gcp','status':'PASS','check_id':'gcp.ports.reference_sqlserver_user_options','evidence':{'field':'user options','declared':''}})=='No explicit user options setting was recorded.'

CORE_CASES={
 'gcp.iam.restrict_public_members':({'bindings':[]},{'bindings':[{'role':'roles/viewer','members':['allUsers']}]}),
 'gcp.iam.avoid_basic_roles':({'bindings':[]},{'bindings':[{'role':'roles/editor','members':['user:a@example.test']}]}),
 'gcp.storage.uniform_access':({'iamConfiguration':{'uniformBucketLevelAccess':{'enabled':True}}},{'iamConfiguration':{'uniformBucketLevelAccess':{'enabled':False}}}),
 'gcp.storage.public_access_prevention':({'iamConfiguration':{'publicAccessPrevention':'enforced'}},None),
 'gcp.compute.restrict_internet_ingress':({'sourceRanges':['10.0.0.0/8'],'allowed':[{'IPProtocol':'tcp','ports':['443']}]},{'sourceRanges':['0.0.0.0/0'],'allowed':[{'IPProtocol':'tcp','ports':['22']}]}),
 'gcp.compute.no_external_ip':({'networkInterfaces':[{'accessConfigs':[]}]},{'networkInterfaces':[{'accessConfigs':[{'natIP':'203.0.113.10'}]}]}),
}
@pytest.mark.parametrize('cid',CORE_CASES)
@pytest.mark.parametrize('branch',[0,1])
def test_core_registered_gcp_observation_shapes(cid,branch):
 item=CORE_CASES[cid][branch]
 if item is None:
  item={'iamConfiguration':{'publicAccessPrevention':'inherited'}}
  assert CHECK[cid].evaluate(item,{})[0]=='UNKNOWN'
  return
 status,evidence=CHECK[cid].evaluate(item,{})
 assert status==('FAIL'if branch else 'PASS')
 text=gcp({'provider':'gcp','check_id':cid,'status':status,'evidence':evidence})
 assert text and len(text)<350

@pytest.mark.parametrize('branch',['pass','fail'])
def test_signed_native_gcp_observations_use_real_scope_joined_records(branch):
 scope='projects/demo'
 def index(groups):
  return {'context':{'provider':'gcp','scope':scope,'metadata':{}},
   'collections':{kind:[{'type':kind,'scope':scope,'status':'collected'if rows else 'empty','items':rows}]for kind,rows in groups.items()},
   **{kind:[{'type':kind,'scope':scope,'data':row}for row in rows]for kind,rows in groups.items()}}
 bucket={'name':'b','_provenance':{'scope':scope},'_representation':'full','iamPolicy':{'bindings':[]},'iamConfiguration':{'uniformBucketLevelAccess':{'enabled':True}}}
 if branch=='fail':bucket['iamPolicy']['bindings']=[{'role':'roles/storage.objectCreator','members':['allUsers']}]
 effective={'name':'b','_provenance':{'scope':scope},'resolutionComplete':True,'publicAccess':False,'publicWrite':False}
 inputs=[('gcp_pci_bucket_56c6b1b7f813',bucket,index({'bucket':[bucket],'bucket_effective_iam':[effective]}))]
 key={'name':scope+'/locations/global/keyRings/r/cryptoKeys/k','_provenance':{'scope':scope}}
 principals=['user:a','user:b','user:c']+(['user:d']if branch=='fail'else [])
 inputs.append(('gcp_pci_kms_key_a3927a5f3b84',key,index({'kms_key':[key],'kms_effective_use':[{**key,'principals':principals,'resolutionComplete':True}]})))
 record={'resource':{'type':'gce_instance'},'logName':scope+'/logs/cloudaudit.googleapis.com%2Factivity','timestamp':'invalid'if branch=='fail'else '2026-01-01T00:00:00Z','eventClass':'authenticated_audit','protoPayload':{'methodName':'read','authenticationInfo':{'principalEmail':'user@example.com'}}}
 inputs.append(('gcp_c5_log_event_fields',record,index({'log_entry':[record]})))
 for cid,subject,facts in inputs:
  status,evidence=CHECK[cid].evaluate(subject,facts)
  assert status==branch.upper(),(cid,status,evidence)
  text=gcp({'provider':'gcp','check_id':cid,'status':status,'evidence':evidence})
  assert text and len(text)<350,(cid,evidence)

@pytest.mark.parametrize('branch',['pass','fail'])
def test_brute_force_native_audit_observations(branch):
 from datetime import datetime,timedelta,timezone
 scope='projects/demo';now=datetime(2026,10,12,tzinfo=timezone.utc)
 stamp=lambda seconds:(now+timedelta(seconds=seconds)).isoformat()
 rows=[]
 for n in range(10 if branch=='fail'else 1):
  rows.append({'insertId':str(n),'logName':scope+'/logs/cloudaudit.googleapis.com%2Factivity','resource':{'type':'audited_resource','labels':{'project_id':'demo'}},'timestamp':stamp(n*20),'authenticationEvent':True,'protoPayload':{'methodName':'authentication.login','authenticationInfo':{'principalEmail':'user@example.com'},'status':{'code':7},'requestMetadata':{'callerIp':'192.0.2.4'}}})
 envelope={'type':'audit_log','scope':scope,'status':'collected','items':rows,'audit_coverage':{'complete':True,'all_pages':True,'start':stamp(-3600),'end':stamp(3600),'authentication_events':True}}
 facts={'context':{'provider':'gcp','scope':scope,'created_at':stamp(0),'metadata':{}},'collections':{'audit_log':[envelope]},'audit_log':[{'type':'audit_log','scope':scope,'data':row}for row in rows]}
 cid='gcp_logging_detect_t1110';status,evidence=CHECK[cid].evaluate(rows[0],facts)
 assert status==branch.upper(),evidence
 text=gcp({'provider':'gcp','check_id':cid,'status':status,'evidence':evidence})
 assert text and len(text)<350,evidence


def test_specific_gke_and_key_policy_observations_name_the_deciding_setting():
 cases={
  'gcp.ports.kubernetes_cluster_legacy_endpoints_disabled':'legacy metadata endpoints',
  'gcp.ports.kubernetes_cluster_node_config_image_cos_containerd':'COS_CONTAINERD',
  'gcp.ports.kubernetes_cluster_shielded_node_secure_boot_enabled':'Secure Boot',
  'gcp.ports.kubernetes_cluster_auto_repair_enabled':'automatic repair',
  'gcp.ports.kubernetes_cluster_auto_upgrade_enabled':'automatic upgrade',
  'gcp.claude.kms_key.users_limited_to_3':'more than three members'}
 for cid,words in cases.items():
  fx=CASES[cid];status,evidence=CHECK[cid].evaluate(deepcopy(fx['pass']),deepcopy(fx.get('pass_index',fx.get('index',{}))))
  text=gcp({'provider':'gcp','check_id':cid,'status':status,'evidence':evidence})
  assert words in text
