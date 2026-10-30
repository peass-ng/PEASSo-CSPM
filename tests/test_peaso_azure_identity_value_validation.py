"""Malformed Graph values must not establish a successful identity baseline."""
from copy import deepcopy
import pytest
from peaso.checks import CHECKS, resolve_check_id
from peaso.checks.fixtures import CASES

@pytest.mark.parametrize('slug', ['entra_ca_mfa_admin_portals','entra_ca_mfa_management_api'])
@pytest.mark.parametrize('control,status', [('notmfa','UNKNOWN'),('MFA','UNKNOWN'),('unknownFutureValue','UNKNOWN'),('mfa','PASS'),('compliantDevice','FAIL'),('block','FAIL'),('domainJoinedDevice','FAIL'),('approvedApplication','FAIL'),('compliantApplication','FAIL'),('passwordChange','UNKNOWN'),('riskRemediation','UNKNOWN')])
def test_declared_mfa_control_matches_only_documented_exact_member(slug,control,status):
    cid='azure.claude.'+slug
    c=next(c for c in CHECKS if c.id==cid)
    case=CASES[cid]; index=deepcopy(case['pass_index'])
    policy=index['conditional_access_policy'][0]['data']
    policy['grantControls']['builtInControls']=[control]
    assert c.evaluate(deepcopy(case['pass']),index)[0]==status

@pytest.mark.parametrize('value,status',[('garbage','UNKNOWN'),('','UNKNOWN'),(' false ','UNKNOWN'),('FALSE','PASS'),('false','PASS'),('true','FAIL'),('TRUE','FAIL')])
def test_group_creation_requires_a_recognized_boolean_string(value,status):
    cid='azure.claude.entra_m365_group_creation_restricted'
    c=next(c for c in CHECKS if c.id==cid);case=CASES[cid];index=deepcopy(case['pass_index'])
    index['directory_setting'][0]['data']['values'][0]['value']=value
    assert c.evaluate(deepcopy(case['pass']),index)[0]==status

@pytest.mark.parametrize('value,status',[({},'UNKNOWN'),(0,'UNKNOWN'),('P0D','UNKNOWN'),('P6D','UNKNOWN'),('P7D','PASS'),('P1M','PASS'),('P90D','PASS')])
def test_after_create_rotation_requires_supported_interval(value,status):
    cid='azure.claude.keyvault_key_automatic_rotation_after_create';c=next(c for c in CHECKS if c.id==cid)
    item=deepcopy(CASES[cid]['pass']);item['properties']['rotationPolicy']['lifetimeActions'][0]['trigger']['timeAfterCreate']=value
    assert c.evaluate(item,{})[0]==status

@pytest.mark.parametrize('value,status',[({},'UNKNOWN'),(True,'UNKNOWN'),({'logAnalyticsWorkspaceResourceID':''},'UNKNOWN'),({'logAnalyticsWorkspaceResourceID':'/w'},'UNKNOWN'),({'logAnalyticsWorkspaceResourceID':'/subscriptions/s/resourceGroups/r/providers/Microsoft.OperationalInsights/workspaces/w'},'PASS')])
def test_container_insights_requires_a_real_workspace_declaration(value,status):
    cid='azure.claude.aks_container_insights_logging';c=next(c for c in CHECKS if c.id==cid)
    item=deepcopy(CASES[cid]['pass']);item['properties']['addonProfiles']['omsagent']['config']=value
    assert c.evaluate(item,{})[0]==status

@pytest.mark.parametrize('days',[-1,'365',True,0,365])
def test_retired_diagnostic_retention_field_cannot_prove_current_hsm_retention(days):
    cid='azure.claude.managed_hsm_audit_logging';c=next(c for c in CHECKS if c.id==cid)
    item=deepcopy(CASES[cid]['pass']);item['diagnosticSettings'][0]['properties']['logs'][0]['retentionPolicy']['days']=days
    status,evidence=c.evaluate(item,{})
    assert status=='UNKNOWN'
    assert evidence['diagnostic_retention_retired_on']=='2025-09-30'

@pytest.mark.parametrize('slug,key',[('eventhub_namespace_logging','diagnostic_logging_enabled'),('iot_hub_logging','diagnostic_logging_enabled'),('keyvault_key_rotation_policy','rotate_action_present')])
@pytest.mark.parametrize('state,expected',[('pass',True),('fail',False)])
def test_evidence_retains_decisive_boolean_not_ambiguous_item_count(slug,key,state,expected):
    cid='azure.claude.'+slug;c=next(c for c in CHECKS if c.id==cid)
    status,evidence=c.evaluate(deepcopy(CASES[cid][state]),{})
    assert status==state.upper()
    assert evidence[key] is expected

@pytest.mark.parametrize('ranges,status',[([''],'UNKNOWN'),(['garbage'],'UNKNOWN'),([' 203.0.113.0/24'],'UNKNOWN'),(['999.0.0.0/24'],'UNKNOWN'),(['203.0.113.0/24'],'PASS'),(['0.0.0.0/0'],'FAIL'),([],'FAIL')])
def test_authorized_sources_reject_malformed_and_unrestricted_ranges(ranges,status):
    # The retired Claude AKS check is an alias of the native exposure check.
    cid=resolve_check_id('azure.claude.aks_authorized_ip_ranges');assert cid=='azure.aks.api_server_restricted'
    c=next(c for c in CHECKS if c.id==cid)
    item=deepcopy(CASES[cid]['pass']);item['properties']['apiServerAccessProfile']['authorizedIPRanges']=ranges
    assert c.evaluate(item,{})[0]==status

@pytest.mark.parametrize('value,status',[({},'UNKNOWN'),(True,'UNKNOWN'),('','UNKNOWN'),(' fqdn ','UNKNOWN'),('x.privatelink.eastus.azmk8s.io','PASS')])
def test_private_api_fqdn_must_be_a_nonempty_string(value,status):
    cid='azure.claude2.aks_private_cluster_nodes_without_public_ip';c=next(c for c in CHECKS if c.id==cid)
    item=deepcopy(CASES[cid]['pass']);item['properties']['privateFQDN']=value
    assert c.evaluate(item,{})[0]==status

@pytest.mark.parametrize('state,expected',[('pass',True),('fail',False)])
def test_batch_logs_include_matching_boolean_even_without_setting_name(state,expected):
    cid='azure.claude2.batch_account_resource_logs';c=next(c for c in CHECKS if c.id==cid)
    item=deepcopy(CASES[cid][state]);before=deepcopy(item)
    status,evidence=c.evaluate(item,{})
    assert status==state.upper()
    assert evidence['matching_enabled_logs'] is expected
    assert item==before

@pytest.mark.parametrize('slug',['entra_lockout_duration_min_60','entra_lockout_threshold_max_10'])
@pytest.mark.parametrize('value',['0','-1','--1','garbage'])
def test_lockout_numeric_settings_cannot_prove_compliance_with_nonpositive_or_malformed_values(slug,value):
    cid='azure.claude2.'+slug;c=next(c for c in CHECKS if c.id==cid);case=CASES[cid]
    index=deepcopy(case['pass_index']);index['directory_setting'][0]['data']['values'][0]['value']=value
    assert c.evaluate(deepcopy(case['pass']),index)[0]=='UNKNOWN'

@pytest.mark.parametrize('value,status',[(-1,'UNKNOWN'),(0,'PASS'),(1,'FAIL')])
def test_vulnerability_scan_counts_cannot_be_negative(value,status):
    cid='azure.claude.sql_database_va_findings_resolved';c=next(c for c in CHECKS if c.id==cid)
    item=deepcopy(CASES[cid]['pass'])
    for scan in item['vulnerabilityAssessmentScans']:
        scan['properties']['numberOfFailedSecurityChecks']=value
        # Count alone cannot prove that the scan ran. Keep this regression
        # about negative counts within an explicitly completed native state.
        scan['properties']['state']='Failed' if value>0 else 'Passed'
    assert c.evaluate(item,{})[0]==status

@pytest.mark.parametrize('source,status',[('garbage','UNKNOWN'),('Microsoft.Storage','FAIL'),('Microsoft.KeyVault','PASS')])
def test_legacy_vhd_key_source_requires_recognized_native_metadata(source,status):
    from tests.azure_native_successor_inputs_20261020 import current_cases
    cid='azure.claude.storage_vhd_accounts_cmk';c=next(c for c in CHECKS if c.id==cid);case=current_cases(cid, CASES[cid])
    index=deepcopy(case['pass_index']);index['storage_account'][0]['data']['properties']['encryption']['keySource']=source
    for envelope in index['collections']['storage_account']:
        for row in envelope['items']:
            row['properties']['encryption']['keySource']=source
    result,evidence=c.evaluate(deepcopy(case['pass']),index)
    assert result==status
    if status=='PASS':assert evidence['platform_key_vhd_accounts']==[]
