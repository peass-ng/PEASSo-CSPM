"""Combined defensive CSPM release gate: registry, signed sources, and generated packs."""
from __future__ import annotations

import hashlib
import ast
import gzip
import json
import os
import subprocess
import sys
from pathlib import Path

import peaso.checks as checks_pkg
from peaso.checks import (CHECKS, aws_backup_plan_frequency, aws_config_recording,
                          claude_aws_a_network, compliance_new_aws,
                          gcp_data_access, k8s_namespace_policy_presence, compliance_next_k8s)

from tests.release_successor_history import (ancestor_json, ancestor_bytes, ancestor_sha, registered_before_bulk, registry_source_before_bulk)

CHECKS = registered_before_bulk(CHECKS)

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "peaso/rulepacks"
LEDGER = ROOT / "docs/compliance-ledgers"
POST_DFAF_IDS = set(json.loads((ROOT / "tests/fixtures/post_dfaf_integration/contract.json").read_text()))
NEXT20_IDS = {"aws_backup_plan_rule_required_frequency", "aws_cis_elbv2_only_tls_listeners"}
APIM_ID = "azure_api_management_appinsights_ensure_is_configured_42aac6a"
GCP_AUDIT_IDS = {"gcp_logging_detect_t1136", "gcp_logging_detect_t1546"}
PSC_IDS = {"gcp.network.private_service_connect_google_apis"}
PSC_PINS = json.loads((ROOT / "tests/fixtures/post_dfaf_integration/psc_materialization.json").read_text())["files"]
PSC_PREIMAGE = json.loads((ROOT / "tests/fixtures/post_dfaf_integration/psc_requirement_preimage.json").read_text())
SSH = "aws.claude_a.vpc.sg_world_v4_ssh"
OLD_CFG = "aws_config_recorder_all_supported_resources"
NEW_CFG = "aws_config_all_resources_recorded"
BACKUP = "aws_nist_backup_plan_min_retention_35_days"
K8S = "k8s.cis.namespace_has_networkpolicy"
GCP = ("gcp_pci_iam_policy_ca1281da7ab2", "gcp_pci_iam_policy_9a8ce875703d")
K8S_COMPONENT = ("k8s.cis.a_limit_is_set_on_pod_pids", "k8s.cis.the_seccomp_default_parameter_is_set_to_true")
WAF = ("aws.pci.wafv2.rule_group_metrics", "aws.pci.wafv2.rule_group_nonempty")
NEXT_K8S = compliance_next_k8s.IDS
NEXT_GROUP_ROW_PREIMAGES = {'aws-compliance.benchmark.fedramp_low_rev_4::aws-compliance.control.rds_db_instance_and_cluster_enhanced_monitoring_enabled': {'requirement_id': 'aws-compliance.control.rds_db_instance_and_cluster_enhanced_monitoring_enabled', 'name': 'RDS DB instance and cluster enhanced monitoring should be enabled', 'decision': 'PARTIAL', 'runtime_status': 'partial', 'native_checks': ['aws.cb.rds.instance_enhanced_monitoring_except_m1_small'], 'declared_check_ids': ['aws.cb.rds.instance_enhanced_monitoring_except_m1_small', 'aws_fedramp_rds_cluster_members_enhanced_monitoring'], 'pending_checks': ['aws_fedramp_rds_cluster_members_enhanced_monitoring'], 'removed_checks': ['aws.cb.rds.cluster_log_exports_declared'], 'reason': 'The native instance check covers instance MonitoringInterval; the purported cluster check reads log exports, which do not establish Enhanced Monitoring for cluster members.', 'evidence': ['peaso/checks/claude_aws_b_db.py:286']}, 'aws-compliance.benchmark.fedramp_moderate_rev_4::aws-compliance.control.rds_db_instance_and_cluster_enhanced_monitoring_enabled': {'requirement_id': 'aws-compliance.control.rds_db_instance_and_cluster_enhanced_monitoring_enabled', 'name': 'RDS DB instance and cluster enhanced monitoring should be enabled', 'decision': 'PARTIAL', 'runtime_status': 'partial', 'native_checks': ['aws.cb.rds.instance_enhanced_monitoring_except_m1_small'], 'declared_check_ids': ['aws.cb.rds.instance_enhanced_monitoring_except_m1_small', 'aws_fedramp_rds_cluster_members_enhanced_monitoring'], 'pending_checks': ['aws_fedramp_rds_cluster_members_enhanced_monitoring'], 'removed_checks': ['aws.cb.rds.cluster_log_exports_declared'], 'reason': 'The native instance check covers instance MonitoringInterval; the purported cluster check reads log exports, which do not establish Enhanced Monitoring for cluster members.', 'evidence': ['peaso/checks/claude_aws_b_db.py:286']}, 'aws-compliance.benchmark.ffiec::aws-compliance.control.rds_db_instance_and_cluster_enhanced_monitoring_enabled': {'requirement_id': 'aws-compliance.control.rds_db_instance_and_cluster_enhanced_monitoring_enabled', 'name': 'RDS DB instance and cluster enhanced monitoring should be enabled', 'decision': 'PARTIAL', 'runtime_status': 'partial', 'native_checks': ['aws.cb.rds.instance_enhanced_monitoring_except_m1_small'], 'declared_check_ids': ['aws.cb.rds.instance_enhanced_monitoring_except_m1_small', 'aws.nist.rds_cluster_member_enhanced_monitoring'], 'pending_checks': ['aws.nist.rds_cluster_member_enhanced_monitoring'], 'removed_checks': ['aws.cb.rds.cluster_log_exports_declared'], 'reason': 'The rds_cluster evaluator tests EnabledCloudwatchLogsExports, which is log export rather than Enhanced Monitoring. The RDS instance evaluator covers only instances; cluster coverage is unresolved; proposed aws.nist.rds_cluster_member_enhanced_monitoring covers the remaining scope.', 'evidence': ['peaso/checks/claude_aws_b_db.py:286']}, 'aws-compliance.benchmark.nist_800_171_rev_2::aws-compliance.control.rds_db_instance_and_cluster_enhanced_monitoring_enabled': {'requirement_id': 'aws-compliance.control.rds_db_instance_and_cluster_enhanced_monitoring_enabled', 'name': 'RDS DB instance and cluster enhanced monitoring should be enabled', 'decision': 'PARTIAL', 'runtime_status': 'partial', 'native_checks': ['aws.cb.rds.instance_enhanced_monitoring_except_m1_small'], 'declared_check_ids': ['aws.cb.rds.instance_enhanced_monitoring_except_m1_small', 'aws.nist.rds_cluster_member_enhanced_monitoring'], 'pending_checks': ['aws.nist.rds_cluster_member_enhanced_monitoring'], 'removed_checks': ['aws.cb.rds.cluster_log_exports_declared'], 'reason': 'The rds_cluster evaluator tests EnabledCloudwatchLogsExports, which is log export rather than Enhanced Monitoring. The RDS instance evaluator covers only instances; cluster coverage is unresolved; proposed aws.nist.rds_cluster_member_enhanced_monitoring covers the remaining scope.', 'evidence': ['peaso/checks/claude_aws_b_db.py:286']}, 'aws-compliance.benchmark.nist_800_172::aws-compliance.control.rds_db_instance_and_cluster_enhanced_monitoring_enabled': {'requirement_id': 'aws-compliance.control.rds_db_instance_and_cluster_enhanced_monitoring_enabled', 'name': 'RDS DB instance and cluster enhanced monitoring should be enabled', 'decision': 'PARTIAL', 'runtime_status': 'partial', 'native_checks': ['aws.cb.rds.instance_enhanced_monitoring_except_m1_small'], 'declared_check_ids': ['aws.cb.rds.instance_enhanced_monitoring_except_m1_small', 'aws.nist.rds_cluster_member_enhanced_monitoring'], 'pending_checks': ['aws.nist.rds_cluster_member_enhanced_monitoring'], 'removed_checks': ['aws.cb.rds.cluster_log_exports_declared'], 'reason': 'The rds_cluster evaluator tests EnabledCloudwatchLogsExports, which is log export rather than Enhanced Monitoring. The RDS instance evaluator covers only instances; cluster coverage is unresolved; proposed aws.nist.rds_cluster_member_enhanced_monitoring covers the remaining scope.', 'evidence': ['peaso/checks/claude_aws_b_db.py:286']}, 'aws_foundational_security_best_practices_aws::ECS.8': {'requirement_id': 'ECS.8', 'name': 'Secrets should not be passed as container environment variables', 'decision': 'PARTIAL', 'runtime_status': 'partial', 'native_checks': ['aws.c2b.ecs.no_credential_named_env_vars'], 'declared_check_ids': ['aws.c2b.ecs.no_credential_named_env_vars', 'aws_ecs_task_definition_credential_environment_names'], 'pending_checks': ['aws_ecs_task_definition_credential_environment_names'], 'removed_checks': [], 'reason': 'Credential-name detector covers named AWS credentials only; requirement prohibits all secrets in plaintext environment values.', 'evidence': ['peaso/checks/claude2_aws_b_compute.py:333']}, 'azure-compliance.benchmark.cis_v130::azure-compliance.control.cis_v130_9_5': {'requirement_id': 'azure-compliance.control.cis_v130_9_5', 'name': '9.5 Ensure that Register with Azure Active Directory is enabled on App Service', 'decision': 'NEW_CHECK', 'runtime_status': 'not_assessed', 'native_checks': [], 'declared_check_ids': ['azure.cis.app_service_entra_registration_enabled'], 'pending_checks': ['azure.cis.app_service_entra_registration_enabled'], 'removed_checks': ['azure.claude2.web_app_register_with_entra'], 'reason': 'App Service managed identity does not test user authentication registration. The proposed read-only check inspects authSettingsV2 platform and Entra provider settings and joins its clientId to a Graph application; runtime coverage begins only after implementation.', 'evidence': ['peaso/checks/claude2_azure_app.py:225']}, 'azure-compliance.benchmark.cis_v140::azure-compliance.control.cis_v140_9_5': {'requirement_id': 'azure-compliance.control.cis_v140_9_5', 'name': '9.5 Ensure that Register with Azure Active Directory is enabled on App Service', 'decision': 'NEW_CHECK', 'runtime_status': 'not_assessed', 'native_checks': [], 'declared_check_ids': ['azure.cis.app_service_entra_registration_enabled'], 'pending_checks': ['azure.cis.app_service_entra_registration_enabled'], 'removed_checks': ['azure.claude2.web_app_register_with_entra'], 'reason': 'App Service managed identity does not test user authentication registration. The proposed read-only check inspects authSettingsV2 platform and Entra provider settings and joins its clientId to a Graph application; runtime coverage begins only after implementation.', 'evidence': ['peaso/checks/claude2_azure_app.py:225']}, 'azure-compliance.benchmark.cis_v150::azure-compliance.control.cis_v150_9_5': {'requirement_id': 'azure-compliance.control.cis_v150_9_5', 'name': '9.5 Ensure that Register with Azure Active Directory is enabled on App Service', 'decision': 'NEW_CHECK', 'runtime_status': 'not_assessed', 'native_checks': [], 'declared_check_ids': ['azure.cis.app_service_entra_registration_enabled'], 'pending_checks': ['azure.cis.app_service_entra_registration_enabled'], 'removed_checks': ['azure.claude2.web_app_register_with_entra'], 'reason': 'App Service managed identity does not test user authentication registration. The proposed read-only check inspects authSettingsV2 platform and Entra provider settings and joins its clientId to a Graph application; runtime coverage begins only after implementation.', 'evidence': ['peaso/checks/claude2_azure_app.py:225']}, 'azure-compliance.benchmark.cis_v200::azure-compliance.benchmark.cis_v200_2_3': {'requirement_id': 'azure-compliance.benchmark.cis_v200_2_3', 'name': '2.3 Microsoft Defender for External Attack Surface Monitoring', 'decision': 'NEW_CHECK', 'runtime_status': 'not_assessed', 'native_checks': [], 'declared_check_ids': ['azure.cis.defender_external_attack_surface_monitoring_easm'], 'pending_checks': ['azure.cis.defender_external_attack_surface_monitoring_easm'], 'removed_checks': [], 'reason': 'Microsoft Defender for External Attack Surface Monitoring is an Azure configuration signal available from the stated read-only source; no existing evaluator tests its required fields.', 'evidence': ['cis_v200/section_2.pp#L404']}, 'azure-compliance.benchmark.cis_v200::azure-compliance.control.cis_v200_9_5': {'requirement_id': 'azure-compliance.control.cis_v200_9_5', 'name': '9.5 Ensure that Register with Azure Active Directory is enabled on App Service', 'decision': 'NEW_CHECK', 'runtime_status': 'not_assessed', 'native_checks': [], 'declared_check_ids': ['azure.cis.app_service_entra_registration_enabled'], 'pending_checks': ['azure.cis.app_service_entra_registration_enabled'], 'removed_checks': ['azure.claude2.web_app_register_with_entra'], 'reason': 'App Service managed identity does not test user authentication registration. The proposed read-only check inspects authSettingsV2 platform and Entra provider settings and joins its clientId to a Graph application; runtime coverage begins only after implementation.', 'evidence': ['peaso/checks/claude2_azure_app.py:225']}, 'azure-compliance.benchmark.cis_v210::azure-compliance.control.cis_v210_2_1_22': {'requirement_id': 'azure-compliance.control.cis_v210_2_1_22', 'name': '2.1.22 Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is enabled', 'decision': 'NEW_CHECK', 'runtime_status': 'not_assessed', 'native_checks': [], 'declared_check_ids': ['azure.cis.defender_external_attack_surface_monitoring_easm'], 'pending_checks': ['azure.cis.defender_external_attack_surface_monitoring_easm'], 'removed_checks': [], 'reason': 'Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is enabled is an Azure configuration signal available from the stated read-only source; no existing evaluator tests its required fields.', 'evidence': ['cis_v210/section_2.pp#L358']}, 'azure-compliance.benchmark.cis_v210::azure-compliance.control.cis_v210_9_4': {'requirement_id': 'azure-compliance.control.cis_v210_9_4', 'name': '9.4 Ensure that Register with Entra ID is enabled on App Service', 'decision': 'NEW_CHECK', 'runtime_status': 'not_assessed', 'native_checks': [], 'declared_check_ids': ['azure.cis.app_service_entra_registration_enabled'], 'pending_checks': ['azure.cis.app_service_entra_registration_enabled'], 'removed_checks': ['azure.claude2.web_app_register_with_entra'], 'reason': 'App Service managed identity does not test user authentication registration. The proposed read-only check inspects authSettingsV2 platform and Entra provider settings and joins its clientId to a Graph application; runtime coverage begins only after implementation.', 'evidence': ['peaso/checks/claude2_azure_app.py:225']}, 'azure-compliance.benchmark.cis_v300::azure-compliance.control.cis_v300_3_1_15': {'requirement_id': 'azure-compliance.control.cis_v300_3_1_15', 'name': '3.1.15 Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is enabled', 'decision': 'NEW_CHECK', 'runtime_status': 'not_assessed', 'native_checks': [], 'declared_check_ids': ['azure.cis.defender_external_attack_surface_monitoring_easm'], 'pending_checks': ['azure.cis.defender_external_attack_surface_monitoring_easm'], 'removed_checks': [], 'reason': 'Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is enabled is an Azure configuration signal available from the stated read-only source; no existing evaluator tests its required fields.', 'evidence': ['cis_v300/section_3.pp#L497']}, 'azure-compliance.benchmark.cis_v300::azure-compliance.control.cis_v300_9_5': {'requirement_id': 'azure-compliance.control.cis_v300_9_5', 'name': '9.5 Ensure that Register with Entra ID is enabled on App Service', 'decision': 'NEW_CHECK', 'runtime_status': 'not_assessed', 'native_checks': [], 'declared_check_ids': ['azure.cis.app_service_entra_registration_enabled'], 'pending_checks': ['azure.cis.app_service_entra_registration_enabled'], 'removed_checks': ['azure.claude2.web_app_register_with_entra'], 'reason': 'App Service managed identity does not test user authentication registration. The proposed read-only check inspects authSettingsV2 platform and Entra provider settings and joins its clientId to a Graph application; runtime coverage begins only after implementation.', 'evidence': ['peaso/checks/claude2_azure_app.py:225']}, 'azure-compliance.benchmark.cis_v400::azure-compliance.control.cis_v400_9_1_16': {'requirement_id': 'azure-compliance.control.cis_v400_9_1_16', 'name': '9.1.16 Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is enabled', 'decision': 'NEW_CHECK', 'runtime_status': 'not_assessed', 'native_checks': [], 'declared_check_ids': ['azure.cis.defender_external_attack_surface_monitoring_easm'], 'pending_checks': ['azure.cis.defender_external_attack_surface_monitoring_easm'], 'removed_checks': [], 'reason': 'Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is enabled is an Azure configuration signal available from the stated read-only source; no existing evaluator tests its required fields.', 'evidence': ['cis_v400/section_9.pp#L463']}, 'azure-compliance.benchmark.cis_v500::azure-compliance.control.cis_v500_8_1_16': {'requirement_id': 'azure-compliance.control.cis_v500_8_1_16', 'name': '8.1.16 Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is enabled', 'decision': 'NEW_CHECK', 'runtime_status': 'not_assessed', 'native_checks': [], 'declared_check_ids': ['azure.cis.defender_external_attack_surface_monitoring_easm'], 'pending_checks': ['azure.cis.defender_external_attack_surface_monitoring_easm'], 'removed_checks': [], 'reason': 'Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is enabled is an Azure configuration signal available from the stated read-only source; no existing evaluator tests its required fields.', 'evidence': ['cis_v500/section_8.pp#L537']}, 'azure-compliance.benchmark.nist_csf_v2::azure-compliance.control.monitor_log_profile_retention_365_days': {'requirement_id': 'azure-compliance.control.monitor_log_profile_retention_365_days', 'name': 'Monitor log profiles should have retention set to 365 days or greater', 'decision': 'PARTIAL', 'runtime_status': 'partial', 'native_checks': ['azure.sql.audit_retention'], 'declared_check_ids': ['azure.gap.monitor_log_profile_retention_365_days', 'azure.sql.audit_retention'], 'pending_checks': ['azure.gap.monitor_log_profile_retention_365_days'], 'removed_checks': [], 'reason': 'Monitor log profiles should have retention set to 365 days or greater. Existing evaluators inspect properties.retentionDays. It does not prove the exact resource scope, enforcement, or retention requested.', 'evidence': ['peaso/checks/azure_extended.py:146']}, 'azure-compliance.benchmark.rbi_itf_nbfc_v2017::azure-compliance.control.monitor_log_profile_retention_365_days': {'requirement_id': 'azure-compliance.control.monitor_log_profile_retention_365_days', 'name': 'Monitor log profiles should have retention set to 365 days or greater', 'decision': 'PARTIAL', 'runtime_status': 'partial', 'native_checks': ['azure.sql.audit_retention'], 'declared_check_ids': ['azure.gap.monitor_log_profile_retention_365_days', 'azure.sql.audit_retention'], 'pending_checks': ['azure.gap.monitor_log_profile_retention_365_days'], 'removed_checks': [], 'reason': 'Monitor log profiles should have retention set to 365 days or greater. Existing evaluators inspect properties.retentionDays. It does not prove the exact resource scope, enforcement, or retention requested.', 'evidence': ['peaso/checks/azure_extended.py:146']}, 'ccc_azure::CCC.IAM.CN06.AR01': {'requirement_id': 'CCC.IAM.CN06.AR01', 'name': '', 'decision': 'PARTIAL', 'runtime_status': 'partial', 'native_checks': ['azure.claude.storage_key_expiration_policy_max_90'], 'declared_check_ids': ['azure.claude.storage_key_expiration_policy_max_90', 'azure.other.entra_app_secret_age_90'], 'pending_checks': ['azure.other.entra_app_secret_age_90'], 'removed_checks': ['azure.aks.rbac', 'azure.claude.iam_custom_role_no_wildcard_actions'], 'reason': 'When a static credential such as an access key has existed for 90 days or more, it MUST be rotated. azure.claude.storage_key_expiration_policy_max_90 reads Storage key expiration policy is at most 90 days. Storage keys are covered; other static Entra application credentials need age checks.', 'evidence': ['peaso/checks/claude_azure_data.py:678']}, 'cis_2.0_azure::9.5': {'requirement_id': '9.5', 'name': 'Ensure that Register with Azure Active Directory is enabled on App Service', 'decision': 'NEW_CHECK', 'runtime_status': 'not_assessed', 'native_checks': [], 'declared_check_ids': ['azure.cis.app_service_entra_registration_enabled'], 'pending_checks': ['azure.cis.app_service_entra_registration_enabled'], 'removed_checks': ['azure.claude2.prowler_app_identity'], 'reason': 'App Service managed identity does not test user authentication registration. The proposed read-only check inspects authSettingsV2 platform and Entra provider settings and joins its clientId to a Graph application; runtime coverage begins only after implementation.', 'evidence': ['peaso/checks/claude2_azure_app.py:379']}, 'cis_2.1_azure::2.1.22': {'requirement_id': '2.1.22', 'name': 'Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is enabled', 'decision': 'NEW_CHECK', 'runtime_status': 'not_assessed', 'native_checks': [], 'declared_check_ids': ['azure.cis.defender_external_attack_surface_monitoring_easm'], 'pending_checks': ['azure.cis.defender_external_attack_surface_monitoring_easm'], 'removed_checks': [], 'reason': 'Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is enabled is an Azure configuration signal available from the stated read-only source; no existing evaluator tests its required fields.', 'evidence': ['prowler/compliance/azure/cis_2.1_azure.json']}, 'cis_2.1_azure::9.4': {'requirement_id': '9.4', 'name': 'Ensure that Register with Entra ID is enabled on App Service', 'decision': 'NEW_CHECK', 'runtime_status': 'not_assessed', 'native_checks': [], 'declared_check_ids': ['azure.cis.app_service_entra_registration_enabled'], 'pending_checks': ['azure.cis.app_service_entra_registration_enabled'], 'removed_checks': ['azure.claude2.prowler_app_identity'], 'reason': 'App Service managed identity does not test user authentication registration. The proposed read-only check inspects authSettingsV2 platform and Entra provider settings and joins its clientId to a Graph application; runtime coverage begins only after implementation.', 'evidence': ['peaso/checks/claude2_azure_app.py:379']}, 'cis_3.0_azure::3.1.15': {'requirement_id': '3.1.15', 'name': 'Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is enabled', 'decision': 'NEW_CHECK', 'runtime_status': 'not_assessed', 'native_checks': [], 'declared_check_ids': ['azure.cis.defender_external_attack_surface_monitoring_easm'], 'pending_checks': ['azure.cis.defender_external_attack_surface_monitoring_easm'], 'removed_checks': [], 'reason': 'Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is enabled is an Azure configuration signal available from the stated read-only source; no existing evaluator tests its required fields.', 'evidence': ['prowler/compliance/azure/cis_3.0_azure.json']}, 'cis_3.0_azure::9.5': {'requirement_id': '9.5', 'name': 'Ensure that Register with Entra ID is enabled on App Service', 'decision': 'NEW_CHECK', 'runtime_status': 'not_assessed', 'native_checks': [], 'declared_check_ids': ['azure.cis.app_service_entra_registration_enabled'], 'pending_checks': ['azure.cis.app_service_entra_registration_enabled'], 'removed_checks': ['azure.claude2.prowler_app_identity'], 'reason': 'App Service managed identity does not test user authentication registration. The proposed read-only check inspects authSettingsV2 platform and Entra provider settings and joins its clientId to a Graph application; runtime coverage begins only after implementation.', 'evidence': ['peaso/checks/claude2_azure_app.py:379']}, 'cis_4.0_azure::9.1.16': {'requirement_id': '9.1.16', 'name': 'Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is enabled', 'decision': 'NEW_CHECK', 'runtime_status': 'not_assessed', 'native_checks': [], 'declared_check_ids': ['azure.cis.defender_external_attack_surface_monitoring_easm'], 'pending_checks': ['azure.cis.defender_external_attack_surface_monitoring_easm'], 'removed_checks': [], 'reason': 'Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is enabled is an Azure configuration signal available from the stated read-only source; no existing evaluator tests its required fields.', 'evidence': ['prowler/compliance/azure/cis_4.0_azure.json']}, 'cis_5.0_azure::8.1.16': {'requirement_id': '8.1.16', 'name': 'Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is enabled', 'decision': 'NEW_CHECK', 'runtime_status': 'not_assessed', 'native_checks': [], 'declared_check_ids': ['azure.cis.defender_external_attack_surface_monitoring_easm'], 'pending_checks': ['azure.cis.defender_external_attack_surface_monitoring_easm'], 'removed_checks': [], 'reason': 'Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is enabled is an Azure configuration signal available from the stated read-only source; no existing evaluator tests its required fields.', 'evidence': ['prowler/compliance/azure/cis_5.0_azure.json']}, 'cis_6.0_azure::8.1.16': {'requirement_id': '8.1.16', 'name': 'Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is Enabled', 'decision': 'NEW_CHECK', 'runtime_status': 'not_assessed', 'native_checks': [], 'declared_check_ids': ['azure.cis.defender_external_attack_surface_monitoring_easm'], 'pending_checks': ['azure.cis.defender_external_attack_surface_monitoring_easm'], 'removed_checks': [], 'reason': 'Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is Enabled is an Azure configuration signal available from the stated read-only source; no existing evaluator tests its required fields.', 'evidence': ['prowler/compliance/azure/cis_6.0_azure.json']}, 'pci_4.0_aws::3.5.1.34': {'requirement_id': '3.5.1.34', 'name': 'secretsmanager', 'decision': 'NEW_CHECK', 'runtime_status': 'not_assessed', 'native_checks': [], 'declared_check_ids': ['aws.pci.secretsmanager.kms_encryption_any'], 'pending_checks': ['aws.pci.secretsmanager.kms_encryption_any'], 'removed_checks': ['aws.cb.secretsmanager.cmk_encryption', 'aws.secretsmanager.rotation'], 'reason': 'The CMK-only check rejects the explicitly allowed AWS managed key.', 'evidence': ['prowler/compliance/aws/pci_4.0_aws.json']}, 'pci_4.0_aws::8.3.2.53': {'requirement_id': '8.3.2.53', 'name': 'secretsmanager', 'decision': 'NEW_CHECK', 'runtime_status': 'not_assessed', 'native_checks': [], 'declared_check_ids': ['aws.pci.secretsmanager.kms_encryption_any'], 'pending_checks': ['aws.pci.secretsmanager.kms_encryption_any'], 'removed_checks': ['aws.cb.secretsmanager.cmk_encryption', 'aws.secretsmanager.rotation'], 'reason': 'The CMK-only check rejects the explicitly allowed AWS managed key.', 'evidence': ['prowler/compliance/aws/pci_4.0_aws.json']}, 'pci_4.0_azure::8.3.10.1.1': {'requirement_id': '8.3.10.1.1', 'name': 'Azure AD', 'decision': 'NEW_CHECK', 'runtime_status': 'not_assessed', 'native_checks': [], 'declared_check_ids': ['azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28'], 'pending_checks': ['azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28'], 'removed_checks': ['azure.claude.keyvault_rbac_secret_expiration_set'], 'reason': 'The requirement asks for active Azure AD service principal credentials (client secrets or certificates) are rotated within the number of days specified in maxCredentialAge. No reviewed native Azure evaluator tests this exact resource setting; the proposed read-only predicate covers it.', 'evidence': ['peaso/checks/claude_azure_identity.py:944']}, 'pci_4.0_azure::8.3.5.1': {'requirement_id': '8.3.5.1', 'name': 'Azure AD', 'decision': 'NEW_CHECK', 'runtime_status': 'not_assessed', 'native_checks': [], 'declared_check_ids': ['azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28'], 'pending_checks': ['azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28'], 'removed_checks': ['azure.claude.keyvault_rbac_secret_expiration_set'], 'reason': 'The requirement asks for active Azure AD service principal credentials (client secrets or certificates) are rotated within the number of days specified in maxCredentialAge. No reviewed native Azure evaluator tests this exact resource setting; the proposed read-only predicate covers it.', 'evidence': ['peaso/checks/claude_azure_identity.py:944']}, 'pci_4.0_azure::8.3.7.1': {'requirement_id': '8.3.7.1', 'name': 'Azure AD', 'decision': 'NEW_CHECK', 'runtime_status': 'not_assessed', 'native_checks': [], 'declared_check_ids': ['azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28'], 'pending_checks': ['azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28'], 'removed_checks': ['azure.claude.keyvault_rbac_secret_expiration_set'], 'reason': 'The requirement asks for active Azure AD service principal credentials (client secrets or certificates) are rotated within the number of days specified in maxCredentialAge. No reviewed native Azure evaluator tests this exact resource setting; the proposed read-only predicate covers it.', 'evidence': ['peaso/checks/claude_azure_identity.py:944']}, 'pci_4.0_azure::8.3.9.1': {'requirement_id': '8.3.9.1', 'name': 'Azure AD', 'decision': 'NEW_CHECK', 'runtime_status': 'not_assessed', 'native_checks': [], 'declared_check_ids': ['azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28'], 'pending_checks': ['azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28'], 'removed_checks': ['azure.claude.keyvault_rbac_secret_expiration_set'], 'reason': 'The requirement asks for active Azure AD service principal credentials (client secrets or certificates) are rotated within the number of days specified in maxCredentialAge. No reviewed native Azure evaluator tests this exact resource setting; the proposed read-only predicate covers it.', 'evidence': ['peaso/checks/claude_azure_identity.py:944']}, 'pci_4.0_azure::8.6.3.1': {'requirement_id': '8.6.3.1', 'name': 'Azure AD', 'decision': 'NEW_CHECK', 'runtime_status': 'not_assessed', 'native_checks': [], 'declared_check_ids': ['azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28'], 'pending_checks': ['azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28'], 'removed_checks': ['azure.claude.keyvault_rbac_secret_expiration_set'], 'reason': 'The requirement asks for active Azure AD service principal credentials (client secrets or certificates) are rotated within the number of days specified in maxCredentialAge. No reviewed native Azure evaluator tests this exact resource setting; the proposed read-only predicate covers it.', 'evidence': ['peaso/checks/claude_azure_identity.py:944']}}
NEXT_GROUP_IDS = {'azure.cis.defender_external_attack_surface_monitoring_easm', 'azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28', 'azure.other.entra_app_secret_age_90', 'aws.pci.secretsmanager.kms_encryption_any', 'aws.nist.rds_cluster_member_enhanced_monitoring', 'azure.gap.monitor_log_profile_retention_365_days', 'azure.cis.app_service_entra_registration_enabled', 'aws_ecs_task_definition_credential_environment_names'}
SOURCES = {
    "peaso/checks/claude_aws_a_network.py": '41ce907b579719381c307421475500e9eac0b4f885e61e91567bb35811062e56',
    "peaso/checks/compliance_new_aws.py": '631a322dcfbd561bfbf4ec5cda53949c1030328b42462255e045e9c8cf0a5bce',
    "peaso/checks/aws_config_recording.py": '50800c1a5c30aa407d0791d4416cc473ea19c3d03f584a2a4a2cfa694d2eabec',
    "peaso/checks/__init__.py": 'caef27171667da9fd23216591ec2bb2e406a47e4ff2dcf47a45a490a0c6121c0',
    "peaso/checks/compliance_next_k8s.py": 'd0184f0934601aaa4682c07d1f0dbfa1b40fa2e9090ce2ca53ca413471b96dfc',
    "peaso/checks/compliance_new_sw07.py": '6858c0bb33ca188313103d098953a1b601563d76fa7a41a3a27ac6f5c0fabdcb',
    "peaso/checks/aws_backup_plan_frequency.py": '0f40ddcace19dded128369f32efad6d72e36a8a95590073beb8cada2d4cff08d',
    "peaso/checks/k8s_namespace_policy_presence.py": '47f64b995e1f5ca9b6db72ff62a7a4594521448f2a1fbba174d453251698a2b2',
    "peaso/checks/gcp_data_access.py": 'ce997648d524475e848aff41353b99f3add7075eca451146a89a7998da9f51c5',
    "peaso/gcp_data_access_policy.py": '03167a5cf56583a9ae4efb08aba2beb24fa0e62fcafded1b6f7f47181cb5d4c7',
    "peaso/collectors/gcp.py": '9325aad599a5929050c2add8f743882638741912811a5b54a3d41d703f76cb41',
    "peaso/collectors/aws.py": '90a237628b2a45012e07adff78d3c9e9e92c3d855fa5237d1b11fdd3945df7f4',
    "peaso/collectors/aws_policy.py": 'a3003f6c3930bd5f23523cc6128192ee6a22891a47035df922e34498ada0429d',
    "scripts/peaso_compliance_compile.py": '8211f8f4e9db7d439afac6db7d7219a7234d5fdac15bc31cb313353de9a4ee5e',
    "peaso/checks/compliance_new_k8s_component.py": '7a1f4ed724924f3c3bde79f2f095627ce8560b4ad64eea94a88d877a77187a25',
    "peaso/checks/wafv2_basic.py": 'b300d867db2803793f56b23dbd2c51751435236428267e12e23c398c99316437',
    "peaso/checks/claude_aws_b_security.py": 'cace583fa69c669d649e8d881934aa3fe1a1a1cfb52b6edef3e138bf91175f98',
    "peaso/collectors/aws_facts_compute_edge.py": '7457cb0db2aabf2a01a6ac18fed0a0a9cebf587f8bf86bdf863fe1b277379782',
}
MANIFEST_SHA256 = 'd5bcf2525ad2a4b0dc974d2bb2269e5486201f229d6f4a1833c7052460d4ec32'
PACKS = {
    "compliance_requirements.json": '7eacec75a219e90a59578613f30ebe367f4b7d97b47b6dee3a5883dc35545a26',
    "compliance_lookup.json": 'a8406177d03a050ed0f057e39d050a871a3823a519357751829a4423f56bab62',
    "check_descriptions.json": 'b45c3a13ea0fe6ef085f52fd03078561cbebe477ba398d941f255d74315d80a2',
    "native_catalog.json": 'c383dad30bc5da4429bddd25103487dc17593df70eee548f586e81cbb7c2380b',
    "framework_catalog.json": 'b991f8f65b92298da941b4761188e8a6c66bc4d9b2afd43553aa6ce6a6dd6e4a',
    "runtime_metadata.json": 'da3623f3e9c2f3e39fb5375ba7835be29fdfa00d750f28beab2f699b7c3e53ed',
    "catalog_summary.json": 'b90f7860fb08b076e933c8469993888255dbb4963a5540422fd82067d4912439',
}
# Baseline digests (pointer-masked) that the combined release must preserve.
COGNITO_21_SHA256 = "558d3e713ff7d770df93bdab07b6850acd5b48995fb5f1500e68e7234e2e08ab"
OTHER_3202_NATIVE_SHA256 = "4b8616595db85713d610c527ab31dc799e58afcefadbd321eb5d9e0ee56a4c91"
SSH_TAGS_SHA256 = "0fa2b8c9f6ec8578a6cf7a5df1d07542f7c40106714e7069282ba3f2e8f1181e"
OLD_CFG_TAGS_SHA256 = "66a90c6dc2e9128e2c48f6e11a3bd4a254ff3b812e4a4262cc6741c5c050087b"
OTHER_BY_CHECK_SHA256 = "0ad4d63feb3b3559270a56865308128d808d65b83ff7f5441ba26bb145dc8502"
# The prior Source2d requirements have the same 22,212 signed keys. The
# private admission comparison proves all 21,488 rows outside this batch equal
# that baseline; these pins preserve the exact post-admission boundary.
BATCH_CHANGED_KEYS_SHA256 = "9649d21ea3cd717a9fa32cf346d2b1ed7a3595727288812ae386dc1dda21151e"
BATCH_UNRELATED_ROWS_SHA256 = "4c134baf2ec7497ae5dae2841a2d2adb287f0e78174663f8c8a06fbb13584f52"
BATCH_MODULES = {"peaso.checks.batch_remaining_aws", "peaso.checks.batch_remaining_azure",
                 "peaso.checks.batch_remaining_gcp", "peaso.checks.batch_remaining_k8s",
                 "peaso.checks.batch_remaining_azure_vm_storage"}
ALIAS_ROWS = {("aws-compliance.benchmark.nist_csf_v2",
               "aws-compliance.control.redshift_cluster_automatic_upgrade_major_versions_enabled"),
              ("pci_3.2.1_aws", "10.2.5"), ("pci_3.2.1_aws", "10.2.5.a"),
              ("fedramp_low_revision_4_aws", "au-2"),
              ("fedramp_moderate_revision_4_aws", "au-2-a-d"),
              ("nist_800_53_revision_4_aws", "au_2"),
              ("nist_800_53_revision_5_aws", "au_12_a"),
              ("nist_800_53_revision_5_aws", "au_12_c")}
WAF_REQUIREMENTS = {
    WAF[0]: {"10.2.1.1.36", "10.4.1.1.7", "10.4.1.6", "10.4.2.7", "10.6.3.41",
             "10.7.1.8", "10.7.2.8", "A3.3.1.11", "A3.5.1.11"},
    WAF[1]: {"6.4.1.7", "6.4.2.7"},
}
K8S_REQUIREMENTS = {
    ("cis_1.10_kubernetes", "4.2.13"),
    ("cis_1.11_kubernetes", "4.2.13"), ("cis_1.11_kubernetes", "4.2.14"),
    ("cis_1.12_kubernetes", "4.2.13"), ("cis_1.12_kubernetes", "4.2.14"),
    ("cis_1.8_kubernetes", "4.2.13"),
    ("cis_2.0.1_kubernetes", "4.2.13"), ("cis_2.0.1_kubernetes", "4.2.14"),
}
NEXT_K8S_REQUIREMENTS = {
    ("cis_1.10_kubernetes", "5.1.7"): NEXT_K8S[0],
    ("cis_1.11_kubernetes", "5.1.7"): NEXT_K8S[0],
    ("cis_1.12_kubernetes", "5.1.7"): NEXT_K8S[0],
    ("cis_1.8_kubernetes", "5.1.7"): NEXT_K8S[0],
    ("cis_2.0.1_kubernetes", "5.1.7"): NEXT_K8S[0],
    ("pci_4.0_kubernetes", "7.2.2.29"): NEXT_K8S[1],
    ("pci_4.0_kubernetes", "1.5.1.36"): NEXT_K8S[2],
    ("pci_4.0_kubernetes", "A1.1.3.36"): NEXT_K8S[2],
}


COHORT = json.loads((ROOT / 'tests/fixtures/post_dfaf_integration/two_hour_native_cohort.json').read_text())
COHORT_IDS = set(COHORT['ids'])


def sha(path):
    return ancestor_sha(path)


def canon(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def masked(entry):
    entry = json.loads(json.dumps(entry))
    provenance = entry.get("proposal_provenance")
    if isinstance(provenance, dict):
        provenance.pop("source_manifest_sha256", None)
    return entry


def check(check_id):
    matches = [item for item in CHECKS if item.id == check_id]
    assert len(matches) == 1, check_id
    return matches[0]


def test_registered_sources_are_the_private_combined_candidates():
    assert Path(checks_pkg.__file__).resolve() == ROOT / "peaso/checks/__init__.py"
    from scripts import peaso_deploy_artifact_update as guard
    for rel, digest in SOURCES.items():
        if rel in {"peaso/collectors/gcp.py", "peaso/collectors/azure.py"}:
            assert digest == guard.APPROVED_NEXT_GROUP_RUNTIME_ADDITIONS[rel]
            digest = guard.APPROVED_PSC_RUNTIME_ADDITIONS[rel]
        if rel == "peaso/checks/__init__.py":
            delta = json.loads((ROOT / "tests/fixtures/post_dfaf_integration/psc_native_source_changes.json").read_text())["changes"][rel]
            assert delta["baseline_sha256"] == digest
            digest = delta["sha256"]
        digest = COHORT["source_changes"].get(rel, {}).get("sha256", digest)
        if rel == "peaso/checks/compliance_new_aws.py":
            # The private candidate was followed by the published 414e source.
            assert digest == "631a322dcfbd561bfbf4ec5cda53949c1030328b42462255e045e9c8cf0a5bce"
            digest = "d09421b5e91cf1449f6b398c2dea46a2d38fba9cbe6b2cd4b3ed5a6175a2c600"
        assert sha(ROOT / rel) == digest, rel
    for module, rel in ((claude_aws_a_network, "claude_aws_a_network.py"), (compliance_new_aws, "compliance_new_aws.py"),
                        (aws_config_recording, "aws_config_recording.py"),
                        (aws_backup_plan_frequency, "aws_backup_plan_frequency.py"),
                        (k8s_namespace_policy_presence, "k8s_namespace_policy_presence.py"),
                        (gcp_data_access, "gcp_data_access.py"),
                        (compliance_next_k8s, "compliance_next_k8s.py")):
        assert Path(module.__file__).resolve() == ROOT / "peaso/checks" / rel
    for check_id, module in ((SSH, claude_aws_a_network), (OLD_CFG, compliance_new_aws),
                             (NEW_CFG, aws_config_recording), (BACKUP, aws_backup_plan_frequency),
                             (K8S, k8s_namespace_policy_presence),
                             *((check_id, gcp_data_access) for check_id in GCP),
                             *((check_id, compliance_next_k8s) for check_id in NEXT_K8S)):
        assert check(check_id).evaluate.__wrapped__.__module__ == module.__name__
    assert "optional(group, \"recordingStrategy\", None, dict)" in Path(compliance_new_aws.__file__).read_text()
    # Anchor-preserving import: appended last, every baseline line unchanged.
    lines = registry_source_before_bulk().splitlines()
    assert len(lines) == 796
    assert lines[790:] == ["", "from . import aws_all_policies  # Full managed and inline IAM configuration inventory.", "", "from . import gcp_audit_rates  # Native RPC read rates; observed events only.", "", "from . import native_storage_compute  # Complete native EFS/EMR/SQL joins."]
    lines = lines[:790]
    assert len(lines) == 790
    assert lines[-3:] == ['', 'from . import gcp_psc_dns  # noqa: E402,F401 (scoped PSC/DNS declaration evidence)', 'gcp_psc_dns.install()']
    lines = lines[:-3]
    assert len(lines) == 787
    assert lines[-4:] == ['', '', '# Root-reviewed next grouped native admissions; keep all earlier hooks.', 'from . import azure_appservice_identity_followup, azure_easm_native, azure_graph_credential_age, azure_log_profile_retention, remaining_aws_gcp_native  # noqa: E402,F401']
    lines = lines[:-4]
    assert len(lines) == 783
    lines = lines[:-9]  # Preserve historical registry anchor proof.
    assert len(lines) == 774
    assert lines[-4].startswith("from . import next20_aws")
    lines = lines[:-5]
    assert len(lines) == 769
    assert lines[-6].startswith("from . import post_dfaf_aws, post_dfaf_azure")
    lines = lines[:-6]
    assert len(lines) == 763
    assert lines[-13].startswith("from . import aws_config_recording  ")
    assert lines[-12].startswith("from . import aws_backup_plan_frequency  ")
    assert lines[-11].startswith("from . import k8s_namespace_policy_presence  ")
    assert lines[-10].startswith("from . import compliance_new_k8s_component  ")
    assert lines[-9].startswith("from . import gcp_data_access  ")
    assert lines[-8].startswith("from . import wafv2_basic  ")
    assert lines[-7].startswith("from . import compliance_next_k8s  ")
    assert lines[-6].startswith("from . import batch_remaining_aws, batch_remaining_azure, ")
    assert lines[-5].startswith("from .fixtures import restore_remaining_batch_cases as ")
    assert lines[-4] == "_restore_remaining_batch_cases()"
    assert lines[-3] == "del _restore_remaining_batch_cases"
    assert lines[-2].startswith("alias_check('aws_g6_redshift_automatic_version_upgrade', ")
    assert lines[-1].startswith("alias_check('aws.pci.cloudtrail.authentication_events', ")


def test_registry_identity_controls_and_targets():
    ids = [item.id for item in CHECKS]
    assert len(ids) == len(set(ids)) == 3434
    assert set(ids[-14:]) == COHORT_IDS
    ids = ids[:-14]
    assert set(ids[-1:]) == PSC_IDS
    ssh, old, new = check(SSH), check(OLD_CFG), check(NEW_CFG)
    assert (ssh.provider, ssh.category, ssh.kind, ssh.severity, ssh.control, ssh.target) == (
        "aws", "exposure", "security_group", "high", "SC-7", "resource")
    assert (old.provider, old.category, old.kind, old.severity, old.control, old.target, old.title) == (
        "aws", "hardening", "config_recorder", "medium", "AU-12", "resource", "AWS Config recorder includes all supported resource types")
    assert (new.provider, new.category, new.kind, new.control, new.target) == ("aws", "hardening", "config_recorder", "CM-8", "scope")
    backup = check(BACKUP)
    assert (backup.provider, backup.category, backup.kind, backup.control, backup.target) == (
        "aws", "hardening", "backup_plan", "CP-9", "resource")
    k8s = check(K8S)
    assert (k8s.provider, k8s.category, k8s.kind, k8s.control, k8s.target) == (
        "k8s", "network", "namespace", "SC-7", "resource")
    for check_id in GCP:
        gcp = check(check_id)
        assert (gcp.provider, gcp.category, gcp.kind, gcp.control, gcp.target) == (
            "gcp", "hardening", "iam_policy", "AU-2", "resource")
    assert [(check(cid).provider, check(cid).target, check(cid).dependencies) for cid in NEXT_K8S] == [
        ("k8s", "scope", ["clusterrolebinding", "rolebinding"]),
        ("k8s", "scope", ["rolebinding", "clusterrolebinding"]),
        ("k8s", "resource", ["pod"]),
    ]


def test_signed_manifest_digests_and_rows():
    manifest_path = LEDGER / "manifest.json"
    assert PSC_PINS["docs/compliance-ledgers/manifest.json"]["baseline_sha256"] == MANIFEST_SHA256
    assert sha(manifest_path) == COHORT["source_changes"]["docs/compliance-ledgers/manifest.json"]["sha256"]
    manifest = ancestor_json(manifest_path)
    assert manifest["check_index_sha256"] == sha(LEDGER / "inputs/check-index.json")
    for section in ("slices", "descriptions"):
        for row in manifest[section].values():
            assert row["sha256"] == sha(LEDGER / row["path"])
    assert manifest["new_descriptions"]["sha256"] == sha(LEDGER / manifest["new_descriptions"]["path"])
    assert manifest["new_descriptions"]["checks"] == 329
    index = json.loads((LEDGER / "inputs/check-index.json").read_text())
    rows = index if isinstance(index, list) else index["checks"]
    by_id = {row["id"]: row for row in rows}
    assert NEW_CFG not in by_id
    assert (by_id[SSH]["source"], by_id[SSH]["line"]) == ("peaso/checks/claude_aws_a_network.py", 283)
    # The signed ledger records the original source location. Evidence-only
    # enrichment shifted current lines; verify the actual hash-bound baseline.
    source = gzip.decompress((ROOT / "tests/fixtures/post_dfaf_integration/network-pre-clarity.py.gz").read_bytes())
    assert hashlib.sha256(source).hexdigest() == SOURCES[by_id[SSH]["source"]]
    assert source.decode().splitlines()[by_id[SSH]["line"] - 1].startswith("def _turbot_check(")
    supplement = ancestor_json(LEDGER / "descriptions/implemented-new-checks.json")
    assert len(supplement) == 329 and supplement[NEW_CFG]["proposed_spec_sha256"] == aws_config_recording.PROPOSED_SPEC_SHA256
    assert supplement[BACKUP]["proposed_spec_sha256"] == aws_backup_plan_frequency.PROPOSED_SPEC_SHA256
    assert all(supplement[check_id]["proposed_spec_sha256"] for check_id in (K8S, *GCP))
    from scripts.peaso_compliance_merge_new import signed_proposals
    from scripts.peaso_compliance_compile import spec_digest
    _, proposed = signed_proposals(LEDGER)
    assert all(supplement[cid]["proposed_spec_sha256"] == spec_digest(proposed[cid]) for cid in NEXT_K8S)


def test_generated_packs_counts_and_preservation():
    for name, digest in PACKS.items():
        delta = PSC_PINS["peaso/rulepacks/" + name]
        assert delta["baseline_sha256"] == digest
        assert sha(PACK / name) == COHORT["source_changes"]["peaso/rulepacks/" + name]["sha256"], name
    assert PSC_PINS["frontend/src/frameworkCatalog.json"]["baseline_sha256"] == "a4f89b9c3321d2c7c99b702677c00eabf848fe4c1696e604d27a2882a61ecb89"
    assert sha(ROOT / "frontend/src/frameworkCatalog.json") == COHORT["source_changes"]["frontend/src/frameworkCatalog.json"]["sha256"]
    requirements = ancestor_json(PACK / "compliance_requirements.json")
    assert requirements["source_manifest_sha256"] == COHORT["source_changes"]["docs/compliance-ledgers/manifest.json"]["sha256"]
    assert requirements["counts"] == {"automated": 9566, "manual": 5957, "not_applicable": 651, "not_assessed": 1387, "partial": 4651}
    by_check = requirements["by_check"]
    assert len(by_check[NEW_CFG]) == 10
    assert canon(by_check[SSH]) == SSH_TAGS_SHA256 and canon(by_check[OLD_CFG]) == OLD_CFG_TAGS_SHA256
    assert len(by_check[BACKUP]) == 17
    assert canon({k: v for k, v in by_check.items() if k not in (NEW_CFG, BACKUP, K8S, *K8S_COMPONENT, *GCP, *WAF, *NEXT_K8S) and k not in POST_DFAF_IDS and k not in NEXT20_IDS and k != APIM_ID and k not in GCP_AUDIT_IDS and k not in NEXT_GROUP_IDS and k not in PSC_IDS and k not in COHORT_IDS}) == OTHER_BY_CHECK_SHA256
    native = ancestor_json(PACK / "native_catalog.json")["checks"]
    assert len(native) == 3434 and {entry["id"] for entry in native[-14:]} == COHORT_IDS
    native = native[:-15]
    assert len(native) == 3419 and {entry["id"] for entry in native[-8:]} == NEXT_GROUP_IDS
    native = native[:-8]
    assert len(native) == 3411 and [entry["id"] for entry in native[-3:]] == [APIM_ID, *sorted(GCP_AUDIT_IDS)] and [entry["id"] for entry in native[:-15][-193:-181]] == [NEW_CFG, BACKUP, K8S, *K8S_COMPONENT, *GCP, *WAF, *NEXT_K8S]
    batch_ids = {check.id for check in CHECKS if check.evaluate.__module__ in BATCH_MODULES}
    assert len(batch_ids) == 181 and {entry["id"] for entry in native[:-15][-181:]} == batch_ids
    assert canon({c["id"]: masked(c) for c in native if "cognito" in c["id"].lower()}) == COGNITO_21_SHA256
    assert canon({c["id"]: masked(c) for c in native if c["id"] not in set((NEW_CFG, SSH, BACKUP, K8S, *K8S_COMPONENT, *GCP, *WAF, *NEXT_K8S)) | batch_ids | POST_DFAF_IDS | NEXT20_IDS | {APIM_ID} | GCP_AUDIT_IDS}) == OTHER_3202_NATIVE_SHA256
    descriptions = ancestor_json(PACK / "check_descriptions.json")["checks"]
    signed = json.loads((LEDGER / "descriptions/desc-aws-4.json").read_text())[SSH]
    assert len(descriptions) == 3441
    assert all(descriptions[SSH][field] == signed[field] for field in descriptions[SSH])


def test_historical_waf_k8s_rows_and_exact_remaining_native_batch_scope():
    requirements = ancestor_json(PACK / "compliance_requirements.json")
    rows = {(framework["id"], row["requirement_id"]): row
            for framework in requirements["frameworks"] for row in framework["requirements"]}
    assert len(rows) == 22212
    waf_keys = {("pci_4.0_aws", rid) for controls in WAF_REQUIREMENTS.values() for rid in controls}
    assert len(waf_keys) == 11 and len(K8S_REQUIREMENTS) == 8
    assert all(rows[key]["runtime_status"] == "automated" and rows[key]["decision"] == "NEW_CHECK"
               for key in waf_keys)
    assert all(rows[key]["runtime_status"] == "partial" and rows[key]["decision"] == "PARTIAL"
               for key in K8S_REQUIREMENTS)
    for check_id, controls in WAF_REQUIREMENTS.items():
        assert {row["requirement_id"] for row in requirements["by_check"][check_id]} == controls
        assert all(row["runtime_status"] == "automated" for row in requirements["by_check"][check_id])
    assert {row["framework_id"] for cid in K8S_COMPONENT for row in requirements["by_check"][cid]} == \
        {framework for framework, _ in K8S_REQUIREMENTS}
    assert sum(len(requirements["by_check"][cid]) for cid in K8S_COMPONENT) == 8
    assert len(NEXT_K8S_REQUIREMENTS) == 8
    assert all(rows[key]["native_checks"] == [cid] and rows[key]["pending_checks"] == [] and
               rows[key]["runtime_status"] == ("partial" if key[0].startswith("cis_") else "automated")
               for key, cid in NEXT_K8S_REQUIREMENTS.items())
    batch_ids = {check.id for check in CHECKS if check.evaluate.__module__ in BATCH_MODULES}
    assert len(batch_ids) == 181
    changed = {key for key, row in rows.items() if batch_ids & set(row["native_checks"])} | ALIAS_ROWS
    assert len(changed) == 724
    assert canon(sorted(f"{framework}::{rid}" for framework, rid in changed)) == BATCH_CHANGED_KEYS_SHA256
    unrelated = {f"{framework}::{rid}": row for (framework, rid), row in rows.items()
                 if (framework, rid) not in changed}
    assert len(unrelated) == 21488
    delta = json.loads((ROOT / "tests/fixtures/post_dfaf_integration/derived-row-preimages.json").read_text())
    historical_unrelated = {**unrelated, **{k: v for k, v in delta.items() if k in unrelated}}
    for key, change in COHORT['changed_requirements'].items():
        historical_key = key.replace('|', '::', 1)
        if historical_key != 'cis_5.0_gcp::3.9' and historical_key in historical_unrelated:
            historical_unrelated[historical_key] = change['baseline']
    # Reconstruct the exact previously pending signed associations before
    # comparing the historical batch digest; keep that digest normative.
    for key, row in list(historical_unrelated.items()):
        if key in NEXT_GROUP_ROW_PREIMAGES:
            row = NEXT_GROUP_ROW_PREIMAGES[key]
            historical_unrelated[key] = row
        admitted = (NEXT20_IDS | {APIM_ID} | GCP_AUDIT_IDS) & set(row["native_checks"])
        if admitted:
            previous = {**row, "native_checks": sorted(set(row["native_checks"]) - admitted),
                        "pending_checks": sorted(set(row["pending_checks"]) | admitted)}
            if admitted & ({APIM_ID} | GCP_AUDIT_IDS):
                previous["runtime_status"] = "not_assessed"
            historical_unrelated[key] = previous
    assert historical_unrelated["cis_5.0_gcp::3.9"]["native_checks"] == sorted(PSC_IDS)
    historical_unrelated["cis_5.0_gcp::3.9"] = PSC_PREIMAGE
    assert canon(historical_unrelated) == BATCH_UNRELATED_ROWS_SHA256


def test_materializer_check_mode_is_current_and_writes_nothing():
    from scripts.peaso_compliance_materialize import render_documents
    watched = list(render_documents())
    assert len(watched) == 8
    before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in watched}
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    run = subprocess.run([sys.executable, "scripts/peaso_compliance_materialize.py"], cwd=ROOT, env=env,
                         capture_output=True, text=True, timeout=600)
    assert run.returncode == 0, run.stdout + run.stderr
    assert json.loads(run.stdout) == {"stale": [], "checked": len(watched)}
    assert {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in watched} == before


def test_finding_detail_presentation_sources_match_reviewed_native_source():
    from peaso.server.materialized_catalog import _presentation_sources_valid, template_for
    from peaso.server.evidence_static import verify_closure

    _presentation_sources_valid.cache_clear()
    _presentation_sources_valid()
    verify_closure.cache_clear()
    verify_closure()
    native = ast.parse((ROOT / "peaso/remediation.py").read_text())
    static = ast.parse((ROOT / "peaso/server/remediation_presentation_static_20261020.py").read_text())
    for name in ("_bounded", "identity_bindings", "bind_command", "exposure_action", "exposure_details"):
        left = next(node for node in native.body if isinstance(node, ast.FunctionDef) and node.name == name)
        right = next(node for node in static.body if isinstance(node, ast.FunctionDef) and node.name == name)
        assert ast.dump(left, include_attributes=False) == ast.dump(right, include_attributes=False), name
    assert template_for("aws.a.cloudwatch.cross_account_role_absent", "aws") is not None
