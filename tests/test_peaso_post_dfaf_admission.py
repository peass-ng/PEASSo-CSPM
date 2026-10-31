"""Exact ten-ID successor, signed mapping and historical conservation gates."""
from peaso.checks.hacktricks_scope import includes
from tests.release_successor_history import historical_release as read_historical_release
import hashlib,json
from pathlib import Path
from copy import deepcopy
from peaso.checks import CHECKS,HACKTRICKS,evaluate_check,post_dfaf_aws
from peaso.checks.fixtures import CASES
from peaso.checks.catalog import proposal_provenance_for,requirement_tags_for
from scripts.peaso_compliance_compile import spec_digest

from tests.release_successor_history import (ancestor_json, ancestor_bytes, ancestor_sha, registered_before_bulk, registry_source_before_bulk)

CHECKS = registered_before_bulk(CHECKS)

ROOT=Path(__file__).resolve().parents[1]
FIXTURE=ROOT/'tests/fixtures/post_dfaf_integration'
CONTRACT=json.loads((FIXTURE/'contract.json').read_text())
BASELINE=json.loads((FIXTURE/'conservation.json').read_text())
IDS=set(CONTRACT)
NEXT20={'aws_backup_plan_rule_required_frequency','aws_cis_elbv2_only_tls_listeners'}
APIM='azure_api_management_appinsights_ensure_is_configured_42aac6a'
GCP_AUDIT={'gcp_logging_detect_t1136','gcp_logging_detect_t1546'}
PSC={'gcp.network.private_service_connect_google_apis'}
APIM_EDGES = {
    'pci_4.0_azure|10.2.1.1.3',
    'pci_4.0_azure|10.2.1.2.3',
    'pci_4.0_azure|10.2.1.3',
    'pci_4.0_azure|10.2.1.3.3',
    'pci_4.0_azure|10.2.1.4.3',
    'pci_4.0_azure|10.2.1.5.3',
    'pci_4.0_azure|10.2.1.6.3',
    'pci_4.0_azure|10.2.1.7.3',
    'pci_4.0_azure|10.2.2.3',
    'pci_4.0_azure|10.4.1.1',
    'pci_4.0_azure|10.4.1.1.1',
    'pci_4.0_azure|10.4.2.1',
    'pci_4.0_azure|10.6.3.3',
    'pci_4.0_azure|10.7.1.1',
    'pci_4.0_azure|10.7.2.1',
    'pci_4.0_azure|5.3.4.3',
    'pci_4.0_azure|A1.2.1.3',
    'pci_4.0_azure|A3.3.1.1',
    'pci_4.0_azure|A3.5.1.1',
}
GCP_AUDIT_EDGES = {'mitre_attack_gcp|T1136', 'mitre_attack_gcp|T1546'}
PACK=ROOT/'peaso/rulepacks'

def canonical(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
def masked(value):
    value=deepcopy(value);value.get('proposal_provenance',{}).pop('source_manifest_sha256',None);return value

NEXT_GROUP_IDS = {'azure.cis.defender_external_attack_surface_monitoring_easm', 'azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28', 'azure.other.entra_app_secret_age_90', 'aws.pci.secretsmanager.kms_encryption_any', 'aws.nist.rds_cluster_member_enhanced_monitoring', 'azure.gap.monitor_log_profile_retention_365_days', 'azure.cis.app_service_entra_registration_enabled', 'aws_ecs_task_definition_credential_environment_names'}
NEXT_GROUP_EDGES = {'azure-compliance.benchmark.cis_v200|azure-compliance.benchmark.cis_v200_2_3', 'azure-compliance.benchmark.cis_v140|azure-compliance.control.cis_v140_9_5', 'azure-compliance.benchmark.nist_csf_v2|azure-compliance.control.monitor_log_profile_retention_365_days', 'pci_4.0_aws|3.5.1.34', 'azure-compliance.benchmark.cis_v300|azure-compliance.control.cis_v300_9_5', 'pci_4.0_azure|8.3.10.1.1', 'azure-compliance.benchmark.cis_v200|azure-compliance.control.cis_v200_9_5', 'azure-compliance.benchmark.cis_v500|azure-compliance.control.cis_v500_8_1_16', 'cis_3.0_azure|9.5', 'azure-compliance.benchmark.cis_v150|azure-compliance.control.cis_v150_9_5', 'azure-compliance.benchmark.cis_v130|azure-compliance.control.cis_v130_9_5', 'cis_3.0_azure|3.1.15', 'pci_4.0_azure|8.3.5.1', 'cis_2.0_azure|9.5', 'azure-compliance.benchmark.rbi_itf_nbfc_v2017|azure-compliance.control.monitor_log_profile_retention_365_days', 'azure-compliance.benchmark.cis_v300|azure-compliance.control.cis_v300_3_1_15', 'aws-compliance.benchmark.nist_800_171_rev_2|aws-compliance.control.rds_db_instance_and_cluster_enhanced_monitoring_enabled', 'aws-compliance.benchmark.fedramp_low_rev_4|aws-compliance.control.rds_db_instance_and_cluster_enhanced_monitoring_enabled', 'cis_5.0_azure|8.1.16', 'aws-compliance.benchmark.nist_800_172|aws-compliance.control.rds_db_instance_and_cluster_enhanced_monitoring_enabled', 'pci_4.0_aws|8.3.2.53', 'azure-compliance.benchmark.cis_v210|azure-compliance.control.cis_v210_2_1_22', 'aws-compliance.benchmark.fedramp_moderate_rev_4|aws-compliance.control.rds_db_instance_and_cluster_enhanced_monitoring_enabled', 'aws_foundational_security_best_practices_aws|ECS.8', 'aws-compliance.benchmark.ffiec|aws-compliance.control.rds_db_instance_and_cluster_enhanced_monitoring_enabled', 'cis_4.0_azure|9.1.16', 'cis_2.1_azure|9.4', 'pci_4.0_azure|8.3.9.1', 'cis_2.1_azure|2.1.22', 'pci_4.0_azure|8.3.7.1', 'cis_6.0_azure|8.1.16', 'pci_4.0_azure|8.6.3.1', 'azure-compliance.benchmark.cis_v210|azure-compliance.control.cis_v210_9_4', 'ccc_azure|CCC.IAM.CN06.AR01', 'azure-compliance.benchmark.cis_v400|azure-compliance.control.cis_v400_9_1_16'}

COHORT=json.loads((FIXTURE/'two_hour_native_cohort.json').read_text())
COHORT_IDS=set(COHORT['ids'])
COHORT_SLICES=set(COHORT['changed_slices'])

def test_exact_ten_registered_without_held_or_duplicate_predicates():
    ordered=[c.id for c in CHECKS]
    assert len(ordered)==len(set(ordered))==3434
    assert set(ordered[-14:])==COHORT_IDS
    ordered=ordered[:-14]
    assert set(ordered[-1:])==PSC
    ordered=ordered[:-1]
    assert set(ordered[-8:])==NEXT_GROUP_IDS
    ordered=ordered[:-8]
    assert ordered[:-15]==BASELINE['old_native_ids']
    assert set(ordered[-15:-5])==IDS
    assert set(ordered[-5:-3])==NEXT20 and ordered[-3]==APIM and set(ordered[-2:])==GCP_AUDIT
    assert set(post_dfaf_aws.READY_IDS)=={cid for cid in IDS if cid.startswith('aws')}
    assert not {'aws_nist_efs_access_point_enforce_root_directory','aws_fedramp_rds_cluster_members_enhanced_monitoring'}&set(ordered)


def test_finalized_central_cases_are_exact_and_decisive():
    expected=json.loads((ROOT/'peaso/checks/central_batch_fixtures.json').read_text())
    from tests.release_successor_history import assert_reviewed_central_fixture_successor
    assert len(expected)==204
    assert_reviewed_central_fixture_successor({cid:CASES[cid] for cid in expected},expected)
    for cid in IDS:
        case=CASES[cid]
        for name,status in [('pass','PASS'),('fail','FAIL'),('missing','UNKNOWN'),('malformed','UNKNOWN')]:
            subject=deepcopy(case[name]);index=deepcopy(case.get(name+'_index',case.get('index',{})))
            before=deepcopy((subject,index))
            assert evaluate_check(cid,subject,index)[0]==status,(cid,name)
            assert (subject,index)==before


def test_pending_remediation_does_not_promote_approval():
    for provider in ('aws','azure'):
        rows=json.loads((PACK/f'remediation_compliance_batch_remaining_{provider}.json').read_text())
        for cid in IDS:
            if CONTRACT[cid]['provider']==provider:
                assert rows[cid]['review_status']=='source_bound_pending_review'
                assert rows[cid]['summary']==CONTRACT[cid]['signed_spec']['remediation_hint']
                assert rows[cid]['proposed_spec_sha256']==CONTRACT[cid]['canonical_signed_spec_sha256']




def test_measured_guard_roster_and_byte_budgets_are_exact():
    from scripts import peaso_deploy_artifact_update as guard
    assert (guard.MAX_SOURCE_MEMBERS,guard.MAX_SOURCE_MEMBER_BYTES,guard.MAX_SOURCE_UNCOMPRESSED_BYTES,guard.MAX_SOURCE_ARCHIVE_BYTES)==(1866,40_000_000,250_000_000,32_000_000)
    assert (guard.MAX_API_MEMBERS,guard.MAX_API_MEMBER_BYTES,guard.MAX_API_UNCOMPRESSED_BYTES,guard.MAX_API_ARCHIVE_BYTES)==(4600,40_000_000,240_000_000,55_000_000)
    assert guard.BASELINE_RUNTIME_MEMBERS==751
    old=guard.APPROVED_BATCH_RUNTIME_ADDITIONS
    historical=guard.APPROVED_POST_DFAF_RUNTIME_ADDITIONS
    current=guard.APPROVED_NEXT20_RUNTIME_ADDITIONS
    assert len(old)==35 and len(historical)==38 and len(current)==39
    assert guard.approved_runtime_additions(old) and guard.approved_runtime_additions(historical) and guard.approved_runtime_additions(current)
    for exact in (old,historical,current):
        first=next(iter(exact))
        assert not guard.approved_runtime_additions({k:v for k,v in exact.items() if k!=first})
        assert not guard.approved_runtime_additions({**exact,first:'0'*64})
        assert not guard.approved_runtime_additions({**exact,'peaso/checks/extra_unreviewed.py':'0'*64})
