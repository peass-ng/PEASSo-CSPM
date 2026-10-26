"""Evaluate catalog techniques against a provider model.

Pipeline per technique (entry):
  1. compile: expand requires into alternatives (all_of + one any_of group),
     classify each requirement as static (source-only), pivot or per-target,
     and turn *_covered_by / resource_permission_covers_target selectors into
     extra per-target requirements;
  2. candidates: the target inventory filtered by static selectors (cached per
     (kind, selector) and shared between techniques);
  3. sources: an inverted index (requirement key -> principals that may hold it)
     intersected over the requirements of an alternative, so a 10k-principal
     snapshot only evaluates the few principals that can possibly match;
  4. exact checks per source (cached by permission-equivalence key), then the
     source-dependent selectors and the target scope rule.

The result is a list of Reach objects consumed by graph.py.
"""
from __future__ import annotations

import functools
import hashlib
import re

from .effective_permissions import ANY, CONF_RANK, AllTargets, Grant, UniformVerdict, as_list, best, combine, downgrade, glob_match, permission_match as _tag_permission
from .schema import (BLOCKER_ALIASES, CHAIN_SOURCE_SELECTORS, EVALUATED_BLOCKERS, FACTS_NEEDED, GENERIC_SELECTORS,
                     GENERIC_SOURCE_SELECTORS, MODEL_BLOCKERS, PRECONDITIONS, expand_requires)

_PH = re.compile(r"(?<!\$)\{([^{}]+)\}")
# Selectors that depend on the source (or the pivot) and are evaluated per source.
DYNAMIC_SELECTORS = {
    "cognito_developer_authenticated_role", "cognito_developer_classic_role",
    "cognito_developer_settable_authenticated_role",
    "cognito_developer_enable_classic_role",
    "cognito_guest_update_classic_role",
    "aws_challenge_fact", "aws_scheduler_iam_self_grant", "aws_scheduler_iam_self_grant_update", "aws_s3_policy_self_grant", "aws_sqs_policy_self_grant", "aws_sns_policy_self_grant", "aws_dynamodb_policy_self_grant", "aws_s3_access_grants_self_grant",
    "aws_secretsmanager_policy_self_grant", "aws_efs_policy_self_grant",
    "aws_cases_tag_self_grant", "aws_sitewise_portal_self_grant",
    "gcp_challenge_fact", "gcp_resource_self_grant", "gcp_external_principal_evidence", "gcp_agentregistry_skill_evidence",
    "gcp_appengine_deploy_path", "gcp_appengine_legacy_actas_unenforced",
    "gcp_appintegration_run_as_path",
    "gcp_gcr_namespace_path",
    "gcp_artifact_policy_consumer_path",
    "gcp_agentidentity_retrieve_path",
    "gcp_agentidentity_update_path",
    "gcp_bounded_access_gain", "gcp_wif_active_path", "gcp_wif_restorable_path", "gcp_workforce_control_path", "gcp_clouddeploy_custom_render_path", "gcp_clouddeploy_existing_custom_render_path", "gcp_clouddeploy_pipeline_policy_custom_render_path", "gcp_clouddeploy_configurable_custom_render_path", "gcp_cloudbuild_writable_trigger_token_path", "gcp_cloudbuild_writable_trigger_policy_path", "gcp_vertex_batch_prediction_path", "gcp_vertex_new_model_endpoint_path", "gcp_workbench_existing_takeover_path", "gcp_run_job_override_path", "gcp_run_job_policy_override_path", "gcp_run_service_update_path", "gcp_run_job_update_execute_path", "gcp_run_instance_create_or_update_path", "gcp_run_instance_ssh_path", "gcp_run_service_ssh_path", "gcp_appengine_instance_ssh_path", "gcp_batch_agent_reporter_on_target", "gcp_run_worker_pool_create_or_update_path", "gcp_cross_project_run_service", "gcp_cross_project_run_job", "gcp_cross_project_cloudbuild",
    "gcp_cross_project_workflows", "gcp_workflows_update_execute_same_workflow", "gcp_workflows_update_attach_path", "gcp_workflows_observed_external_execution", "gcp_cloudscheduler_update_job_path", "gcp_cloudscheduler_authenticated_delivery", "gcp_cloudtasks_enqueue_path", "gcp_cloudtasks_authenticated_delivery", "gcp_cloudtasks_queue_policy_path", "gcp_cloudfunctions_create_path", "gcp_cloudfunctions_existing_source_update_path", "gcp_cloudfunctions_env_startup_path", "gcp_cloudfunctions_source_deploy_build_path",
    "azure_challenge_fact", "azure_external_principal_evidence", "azure_static_site_deployment_token", "azure_apim_restorable_backup", "azure_automation_assignable_uami", "azure_automation_runbook_identity_path", "azure_automation_hybrid_worker_path", "azure_batch_job_pool_identity", "azure_batch_pool_starttask_identity", "azure_batch_shared_key_pool_identity", "azure_batch_pool_assignable_uami", "azure_confidential_ledger_admin_path", "azure_containerapp_assignable_uami", "azure_containerapp_create_uami_path", "azure_containerapp_exec_identity", "azure_containerapp_job_assignable_uami", "azure_appservice_assignable_uami", "azure_appservice_backup_restore_code_path", "azure_appservice_config_code_path", "azure_appservice_enable_publishing_credentials_code_path", "azure_appservice_kudu_code_path", "azure_appservice_onedeploy_code_path", "azure_appservice_publishing_credentials_code_path", "azure_appservice_sitecontainers_code_path", "azure_appservice_siteextensions_code_path", "azure_appservice_slot_code_path", "azure_appservice_slot_swap_code_path", "azure_appservice_sourcecontrol_code_path", "azure_arc_entra_admin_ssh_path", "azure_arc_custom_script_code_path", "azure_arc_run_command_code_path", "azure_deployment_script_uami_path", "azure_appservice_slot_publishing_credentials_code_path", "azure_acr_assignable_uami", "azure_acr_existing_task_identity", "azure_aks_rbac_group_impersonation", "azure_aks_rbac_cluster_binding", "azure_flux_cluster_path", "azure_vmss_instance_identity", "azure_aci_assignable_uami", "azure_aci_exec_running_identity", "azure_aci_existing_write_identity", "k8s_challenge_fact", "k8s_helm_values_rbac", "k8s_verified_pivot", "k8s_bound_role_gain", "k8s_clusterrolebinding_gain", "k8s_existing_clusterrolebinding_gain", "k8s_aggregated_rolebinding_namespace",
    "openshift_source_host_scc_path",
    "openshift_unlabeled_existing_namespace",
    "k8s_node_schedulable",
    "k8s_sa_used_by_pending_pod",
    "k8s_pod_access_path",
    "k8s_websocket_exec_get_usable",
    "k8s_mutating_admission_policy_served",
    "openshift_namespace_without_scc",
    "k8s_constrained_impersonation_gain",
    "k8s_dangling_sa_permission_gain",
    "k8s_sa_namespace_absent",
    "gcp_sourcerepo_trigger_path",
    "k8s_existing_rolebinding_gain",
    "k8s_aggregation_new_role_path",
    "k8s_csr_same_name_path",
    "gcp_privatecatalog_dm_iam_path",
    "gcp_eventarc_oauth_pipeline_path",
    "k8s_kcc_service_account_key_path",
    "k8s_kcc_project_policy_grant",
    "azure_vmss_instance_runcommand_action_path",
    "azure_vmss_instance_runcommand_path",
    "azure_vmss_model_rollout_path",
    "azure_vm_runcommand_action_path",
    "azure_vm_os_disk_swap_path",
    "azure_vm_managed_runcommand_path",
    "azure_vm_gallery_application_path",
    "azure_vm_extension_execution_path",
    "azure_vm_reimage_customdata_path",
    "azure_vm_create_uami_path",
    "azure_vm_assign_indirect_uami_path",
    "azure_vm_assign_existing_uami_path",
    "azure_synapse_entra_admin_path",
    "azure_spring_deployment_identity_path",
    "azure_spring_app_uami_path",
    "azure_servicefabric_application_uami_path",
    "azure_policy_assignment_identity_path",
    "azure_sql_server_admin_password_reset",
    "azure_sql_server_entra_admin_write",
    "azure_sqlmi_admin_password_reset",
    "azure_sqlmi_entra_admin_write",
    "azure_mysql_flexible_admin_password_reset",
    "azure_mysql_flexible_entra_admin_write",
    "azure_postgresql_flexible_admin_password_reset",
    "azure_postgresql_flexible_entra_admin_write",
    "azure_ml_online_endpoint_create_uami_path",
    "azure_ml_existing_online_deployment_identity_path",
    "azure_ml_compute_create_uami_path",
    "azure_ml_compute_application_identity_path",
    "azure_uami_fic_write_path",
    "azure_managedapp_listtokens_path",
    "azure_logicapp_existing_identity_path",
    "azure_logicapp_assign_uami_path",
    "entra_sp_credential_takeover_target",
    "entra_sp_owner_update_target",
    "azure_function_definition_code_path",
    "azure_function_host_vfs_code_path",
    "azure_function_remote_debug_path",
    "azure_arc_guest_configuration_path",
    "azure_hybrid_k8s_admin_credential_path",
    "azure_imagebuilder_new_template_identity_path",
    "azure_kusto_cluster_principal_assignment_path",
    "azure_kusto_database_principal_assignment_path",
    "azure_loadtesting_assign_uami_path",
    "azure_loadtesting_existing_engine_identity_path",
    "entra_agent_blueprint_principal_or_child_identity",
    "aws_challenge_fact", "aws_s3_policy_self_grant", "aws_s3_access_grants_self_grant",
    "aws_secretsmanager_policy_self_grant", "aws_efs_policy_self_grant",
    "aws_cases_tag_self_grant", "aws_sitewise_portal_self_grant",
    "gcp_challenge_fact", "gcp_resource_self_grant", "gcp_project_iam_sa_token_grant", "gcp_kcc_project_policy_grant", "gcp_gke_clusterrole_bind", "gcp_gke_clusterrole_escalate", "gcp_gke_system_impersonation", "gcp_gke_node_sa_actas", "gcp_gke_webhook_ksa_path", "gcp_gke_namespaced_rbac_ksa_path", "gcp_gke_node_proxy_sa", "gcp_gke_node_proxy_ksa", "gcp_gke_pod_template_ksa", "gcp_gke_pod_template_node_sa", "gcp_gke_pod_exec_node_sa", "gcp_gke_pod_exec_ksa", "gcp_gke_pod_update_ksa", "gcp_gke_secret_ksa", "gcp_gke_token_request_ksa", "gcp_gke_nodepool_metadata_downgrade", "gcp_kcc_generated_key_secret", "gcp_configdelivery_fleet_target", "gcp_fleet_config_management_target", "gcp_fleet_rbac_admin_target", "gcp_external_principal_evidence", "gcp_agentregistry_skill_evidence", "gcp_firebase_apphosting_retarget",
    "gcp_appengine_deploy_path", "gcp_appengine_legacy_actas_unenforced",
    "gcp_appintegration_run_as_path",
    "gcp_bigquery_spark_connection_path",
    "gcp_mig_existing_template_path",
    "gcp_vm_create_path",
    "gcp_osadminlogin_vm_path",
    "gcp_osconfig_guest_policy_path",
    "gcp_osconfig_os_policy_assignment_path",
    "gcp_osconfig_patch_job_path",
    "gcp_osconfig_policy_orchestrator_path",
    "gcp_oslogin_vm_path",
    "gcp_metadata_vm_path",
    "gcp_project_metadata_vm_path",
    "gcp_sa_swap_vm_path",
    "gcp_mig_create_path",
    "gcp_bounded_service_execution",
    "gcp_gcr_namespace_path",
    "gcp_artifact_policy_consumer_path",
    "gcp_artifact_upload_consumer_path",
    "gcp_agentidentity_retrieve_path",
    "gcp_agentidentity_update_path",
    "gcp_apigee_proxy_deploy_path",
    "gcp_apigee_sharedflow_hook_path",
    "gcp_vmmigration_metadata_clone_path",
    "gcp_composer_storage_policy_path",
    "gcp_bounded_access_gain", "gcp_wif_active_path", "gcp_wif_restorable_path", "gcp_workforce_control_path", "gcp_clouddeploy_custom_render_path", "gcp_clouddeploy_existing_custom_render_path", "gcp_clouddeploy_pipeline_policy_custom_render_path", "gcp_clouddeploy_configurable_custom_render_path", "gcp_cloudbuild_writable_trigger_token_path", "gcp_cloudbuild_writable_trigger_policy_path", "gcp_vertex_batch_prediction_path", "gcp_vertex_new_model_endpoint_path", "gcp_workbench_existing_takeover_path", "gcp_run_job_override_path", "gcp_run_job_policy_override_path", "gcp_run_service_update_path", "gcp_run_job_update_execute_path", "gcp_run_job_create_execute_path", "gcp_run_service_create_path", "gcp_run_service_policy_update_path", "gcp_run_worker_pool_policy_update_path", "gcp_run_instance_create_or_update_path", "gcp_run_instance_ssh_path", "gcp_run_service_ssh_path", "gcp_appengine_instance_ssh_path", "gcp_batch_agent_reporter_on_target", "gcp_run_worker_pool_create_or_update_path", "gcp_cross_project_run_service", "gcp_cross_project_run_instance", "gcp_cross_project_run_job", "gcp_cross_project_cloudbuild",
    "gcp_cross_project_workflows", "gcp_cloudbuild_api_enabled", "gcp_datapipelines_scheduled_template_path", "gcp_dataflow_flex_launch_path", "gcp_dataflow_artifact_overwrite_path", "gcp_datafusion_pipeline_path", "gcp_datafusion_selfgrant_path", "gcp_datafusion_artifact_poison_path", "gcp_dataplex_task_path", "gcp_dataproc_create_path", "gcp_dataproc_session_path", "gcp_dataproc_cluster_selfgrant_path", "gcp_dataproc_gateway_path", "gcp_dataproc_job_path", "gcp_dataproc_init_replace_path", "gcp_dataproc_workflow_path", "gcp_deploymentmanager_create_path", "gcp_deploymentmanager_update_path", "gcp_developerconnect_pipeline_path", "gcp_deploymentmanager_selfgrant_path", "gcp_workflows_update_execute_same_workflow", "gcp_workflows_update_attach_path", "gcp_workflows_observed_external_execution", "gcp_workstations_create_config_path", "gcp_workstations_use_existing_path", "gcp_workstations_create_from_config_path", "gcp_cloudscheduler_update_job_path", "gcp_cloudscheduler_authenticated_delivery", "gcp_cloudtasks_enqueue_path", "gcp_cloudtasks_authenticated_delivery", "gcp_cloudtasks_queue_policy_path", "gcp_cloudfunctions_create_path", "gcp_cloudfunctions_existing_source_update_path", "gcp_cloudfunctions_env_startup_path", "gcp_cloudfunctions_source_deploy_build_path", "gcp_composer_dag_upload_path", "gcp_composer_create_with_dag_path", "gcp_composer_pypi_update_path",
    "azure_challenge_fact", "azure_external_principal_evidence", "azure_apim_restorable_backup", "azure_automation_assignable_uami", "azure_automation_runbook_identity_path", "azure_automation_hybrid_worker_path", "azure_batch_job_pool_identity", "azure_batch_pool_starttask_identity", "azure_batch_shared_key_pool_identity", "azure_batch_pool_assignable_uami", "azure_confidential_ledger_admin_path", "azure_mongo_cluster_admin_password", "azure_mongo_cluster_self_root", "azure_cosmos_mongo_user_write", "azure_cosmos_other_api_role_grant", "azure_cosmos_sql_role_grant", "azure_databricks_workspace_admin", "azure_devtestlab_artifact_identity", "azure_containerapp_assignable_uami", "azure_containerapp_create_uami_path", "azure_containerapp_exec_identity", "azure_containerapp_write_existing_identity", "azure_containerapp_job_assignable_uami", "azure_containerapp_job_execution_identity", "azure_appservice_assignable_uami", "azure_appservice_backup_restore_code_path", "azure_appservice_config_code_path", "azure_appservice_enable_publishing_credentials_code_path", "azure_appservice_kudu_code_path", "azure_appservice_onedeploy_code_path", "azure_appservice_publishing_credentials_code_path", "azure_appservice_sitecontainers_code_path", "azure_appservice_siteextensions_code_path", "azure_appservice_slot_code_path", "azure_appservice_slot_swap_code_path", "azure_appservice_sourcecontrol_code_path", "azure_arc_entra_admin_ssh_path", "azure_arc_custom_script_code_path", "azure_arc_run_command_code_path", "azure_deployment_script_uami_path", "azure_appservice_slot_publishing_credentials_code_path", "azure_acr_assignable_uami", "azure_acr_existing_task_identity", "azure_aks_rbac_group_impersonation", "azure_aks_rbac_cluster_binding", "azure_flux_cluster_path", "azure_vmss_instance_identity", "azure_aci_assignable_uami", "azure_aci_exec_running_identity", "azure_aci_existing_write_identity", "k8s_challenge_fact", "k8s_helm_values_rbac", "k8s_verified_pivot", "k8s_bound_role_gain", "k8s_clusterrolebinding_gain", "k8s_existing_clusterrolebinding_gain", "k8s_aggregated_rolebinding_namespace",
    "same_as_source", "trust_allows_principal_of_source", "source_kind", "source_group_covered_by",
    "source_attached_policy_covered_by", "via_assumable_role_covered_by",
    "via_assumable_role_attached_policy_covered_by", "custom_role_assigned_to_source",
    "entra_source_is_owner_of_application", "entra_source_is_owner_of_service_principal", "entra_source_is_owner_of_group",
    "entra_group_source_self_membership",
    "entra_custom_role_assigned_to_source", "entra_pim_eligible_for_source", "entra_dynamic_rule_attributes_writable_by_source",
    "entra_group_new_self_membership",
    "entra_group_owner_new_self_membership",
    "entra_group_source_not_owner",
    "entra_auth_admin_user_takeover",
    "entra_helpdesk_password_reset",
    "entra_password_admin_reset",
    "entra_user_admin_password_reset",
    "entra_nonadmin_password_reset",
    "entra_privileged_auth_user_takeover",
    "entra_custom_role_assigned_to_source", "entra_user_upn_on_federatable_custom_domain", "entra_auto_assignment_package_group", "entra_catalog_self_grant_group", "entra_catalog_self_grant_role", "entra_graph_application_credential_target", "entra_graph_self_grant_directory_role", "entra_graph_directory_role_self_grant", "entra_role_assignment_self_grant", "entra_graph_tap_user_target", "entra_graph_group_sp_membership", "entra_graph_group_user_membership", "entra_pim_active_sp_membership", "entra_pim_controlled_user_eligibility", "entra_pim_eligible_for_source", "entra_dynamic_rule_attributes_writable_by_source",
    "entra_role_assignment_scope_covers_target", "entra_reset_matrix_column", "ml_compute_assigned_to_source",
    "k8s_sa_cloud_binding", "trust_allows_k8s_sa_oidc_subject", "gcp_workload_identity_user_granted_to_k8s_sa",
    "azure_fic_matches_k8s_sa", "k8s_node_cloud_identity", "k8s_nodes_mapped_to_cloud_identity",
    "gcp_custom_role_bound_to_source", "azure_deployer_of_pivot", "azure_host_linked_to_pivot",
    "k8s_node_hosting_pods_with_sa", "k8s_node_hosting_pods_in_namespace", "k8s_node_hosting_privileged_pod_in_namespace",
    "k8s_node_hosting_host_mount_pod_in_namespace", "k8s_node_hosting_pod_of_source",
    "gcp_group_join_open_to_source",
    "credential_stored_in_scope", "kube2iam_namespace_permits_role", "gcp_implicit_delegation_chain",
    "assumable_by_pivot_role",
    # Azure extensions: depend on the source or on {pivot}.
    "azure_consumer_of_pivot", "azure_assignable_via_identity_holding", "azure_users_assigned_to_pivot",
    "azure_assignment_condition_uses_principal_attribute", "entra_pim_group_eligible_for_source",
}
# Multi-valued target placeholders: when several requirements reference the same one, they must all hold
# on the SAME resolved resource (intersection), not each on some resource.
SHARED_PLACEHOLDERS = {"target.resource_arn", "target.attached_resource_arn", "target.host_resource",
                       "target.artifact_arn", "target.consumer_input_arn"}
# Selectors that are an extra "the source holds <action> on <resource>" requirement.
COVERED_BY = {
    "resource_permission_covers_target": None,
    "gcp_actas_granted_on_target": "{target.email}",
    "attached_resource_covered_by": "{target.attached_resource_arn}",
    "source_group_covered_by": "{source.group_arn}",
    "source_attached_policy_covered_by": "{source.attached_policy_arn}",
    "trust_allows_saml_provider_covered_by": "{target.saml_provider_arn}",
}
LOCALIZING_SELECTORS = {"gcp_sa_in_scope_of_permission", "azure_identity_assignable_in_scope"}
LOCALIZING_SCOPES = {"same_namespace", "same_project"}


def _tag_result(result, raw):
    if isinstance(result, AllTargets):
        return AllTargets(_tag_permission(result.grant, raw))
    if isinstance(result, dict):
        seen = {}
        for target, grant in result.items():
            key = id(grant)
            if key not in seen:
                seen[key] = _tag_permission(grant, raw)
            result[target] = seen[key]
        return result
    return _tag_permission(result, raw)


class CReq:
    __slots__ = ("raw", "key", "template", "mode", "localized")

    def __init__(self, raw, key, template, mode, localized=False):
        self.raw, self.key, self.template, self.mode, self.localized = raw, key, template, mode, localized


UNRESOLVED_PREFIX = "unresolved:"
_PLACEHOLDER_PREFIXES = ("unknown:", UNRESOLVED_PREFIX)
PRECONDITION_PREFIX = "precondition:"


class CandidateSet:
    """Static candidates of one (kind, static selector) combination.

    members only holds targets proven by collected facts. When a selector cannot be evaluated (facts missing) or
    only yields unknown-confidence matches, those targets are NOT members: `unresolved` maps each scope where they
    would live to the reason, and reaches point to one "Unresolved: <label>" placeholder per scope instead."""
    __slots__ = ("id", "kind", "members", "floor", "by_scope", "label", "unknown_scopes", "unresolved", "excluded")

    def __init__(self, ident, kind, members, floor, label, unknown_scopes, unresolved=None, excluded=0):
        self.id, self.kind, self.members, self.floor, self.label = ident, kind, members, floor, label
        self.unknown_scopes = unknown_scopes
        self.unresolved = unresolved or {}
        self.excluded = excluded
        self.by_scope = {}
        for node in members.values():
            self.by_scope.setdefault(node.scope, set()).add(node.id)


class AllOf:
    """Every static candidate (optionally only in `scopes`) is reached with `grant`."""
    __slots__ = ("grant", "scopes", "unknown")

    def __init__(self, grant, scopes, unknown):
        self.grant, self.scopes, self.unknown = grant, scopes, unknown

    def __bool__(self):
        return True

    def expand(self, cset, exclude=None):
        """Materialise {target id: grant} (only used for small sets and tests)."""
        out = {}
        for scope, ids in cset.by_scope.items():
            if self.scopes is not None and scope not in self.scopes:
                continue
            for tid in ids:
                if tid == exclude:
                    continue
                floor = cset.floor.get(tid)
                out[tid] = downgrade(self.grant, floor[0], floor[1]) if floor else self.grant
        out.update(self.unknown)
        return out


class Reach:
    """One technique reaching a set of targets from one source."""
    __slots__ = ("entry", "source", "targets", "cset", "source_group")

    def __init__(self, entry, source, targets, cset, source_group=None):
        self.entry, self.source, self.targets, self.cset = entry, source, targets, cset
        self.source_group = source_group  # list of source nodes when sources are aggregated (unknown facts)


def _template_kind(template):
    names = _PH.findall(template) if isinstance(template, str) else []
    if any(name in names for name in ("source_rolebound_clusterrole", "source_bound_clusterrole", "source_bound_role")):
        return "target"  # the RoleBinding namespace must equal each target SA namespace
    if any(n == "pivot" or n.startswith("pivot.") for n in names):
        return "pivot"
    if any(n.startswith("target.") or n in ("target",) for n in names):
        return "target"
    return "static"


# These remaining legacy claims need exact consumer/target joins or a bounded portal outcome.
# Preserve their catalog IDs for historical lookup while withholding graph edges.
# A reviewed v4 correction may replace a hold only after its fact importer and
# wrong-target validation are admitted together. See shared-suppression.json.
_SHARED_SEMANTIC_HOLDS = frozenset({
    "aws-codecommit-gitpush-pipeline-source",
    "aws-ec2-passrole-associate-instance-profile",
    "aws-v3-05-add-or-replace-a-workspaces-web-portal-saml-oidc-identi",
})


class Evaluator:
    def __init__(self, model, entries, *, include_unknown=True, admin_scopes=None):
        """admin_scopes: {source id: [scopes it already administers]}; a source is skipped for a technique when every
        scope the technique's targets live in is within one of them (its edges would be suppressed anyway)."""
        self.model = model
        self.admin_scopes = admin_scopes or {}
        self.skipped_admin = 0
        self.memo_hits = 0
        self.skipped_service_managed = 0
        # Reaches removed by a definitive model blocker, kept until the lift pass (target.removes_blockers along a
        # chain) and then reported in `blocked` (never silently dropped).
        self._blocked_pending = []
        self.blocked = []
        self._last_pivots = None
        self.entries = [e for e in entries if e["provider"] == model.provider or (
            model.provider == "azure" and e["provider"] == "azure")]
        self.include_unknown = include_unknown
        self._csets = {}
        self._noted = set()
        self.compiled = [self._compile(e) for e in self.entries]
        # Every requirement key must be known before possible() is computed (prefilter index).
        model.catalog_keys.update(r.key for c in self.compiled for alt in c["alternatives"] for r in alt)
        self._index()

    # ---------------------------------------------------------------- compile
    def _compile(self, entry):
        model = self.model
        target = entry.get("target") or {}
        selector = dict(target.get("selector") or {})
        scope_rule = target.get("scope", "any")
        localize = bool(LOCALIZING_SELECTORS & set(selector)) or scope_rule in LOCALIZING_SCOPES
        requires = entry.get("requires") or {}
        groups = expand_requires(requires)  # DNF: v1 all_of + one any_of group, nested {any_of}/{all_of} multiplied out
        extra = []
        for key, template in COVERED_BY.items():
            if key not in selector:
                continue
            action = selector[key]
            req = model.covered_by_requirement(key, action, template, target.get("kind"))
            if req is not None:
                extra.append(req)
        alternatives = []
        for group in groups:
            reqs, seen = [], set()
            for raw in list(group) + extra:
                key = model.requirement_key(raw)
                template = model.requirement_template(raw)
                ident = (key, template, raw.get("bind"), repr(raw.get("request_context")))
                if ident in seen:
                    continue
                seen.add(ident)
                mode = _template_kind(template) if template is not None else "static"
                localized = False
                if mode == "static" and localize and model.localizable(raw):
                    mode, localized = "target", True
                reqs.append(CReq(raw, key, template, mode, localized))
            alternatives.append(reqs)
        if (target.get("kind") in ("azure_dataplane_admin", "k8s_cluster_admin")
                and model.provider == "azure" and "azure_flux_cluster_path" not in selector
                and "azure_resource_type" not in selector
                and "azure_hybrid_k8s_admin_credential_path" not in selector
                and "azure_kusto_cluster_principal_assignment_path" not in selector
                and "azure_kusto_database_principal_assignment_path" not in selector
                and "azure_mysql_flexible_entra_admin_write" not in selector
                and "azure_sql_server_entra_admin_write" not in selector
                and "azure_sqlmi_entra_admin_write" not in selector
                and "azure_postgresql_flexible_entra_admin_write" not in selector):
            first = next((r.raw for alt in alternatives for r in alt if "action" in r.raw), None)
            if first is not None:
                selector["_resource_type_from_action"] = first["action"]
        static_sel, dynamic_sel = {}, {}
        for pre in entry.get("preconditions") or []:
            pid = pre if isinstance(pre, str) else (pre or {}).get("id")
            if pid:
                selector[PRECONDITION_PREFIX + pid] = True
        for key, value in selector.items():
            if key in COVERED_BY and key != "trust_allows_saml_provider_covered_by":
                continue
            if key in LOCALIZING_SELECTORS:
                continue
            text = repr(value)
            if key.startswith(PRECONDITION_PREFIX):
                (dynamic_sel if PRECONDITIONS.get(key[len(PRECONDITION_PREFIX):], ((), "target"))[1] == "source"
                 else static_sel)[key] = value
            elif key in DYNAMIC_SELECTORS or "{source" in text or "{pivot" in text or "{target" in text:
                dynamic_sel[key] = value
            else:
                static_sel[key] = value
        blockers = [b if isinstance(b, str) else b.get("id") for b in entry.get("blockers") or []]
        model_blockers = [b for b in blockers if b in MODEL_BLOCKERS.get(model.provider, ())]
        if model.provider == "gcp" and target.get("kind") == "gcp_service_account":
            model_blockers.append("disabled_service_account")
        if model.provider == "azure" and target.get("kind") in (
                "azure_user", "azure_service_principal", "azure_managed_identity"):
            model_blockers.append("disabled_azure_identity")
        return {"entry": entry, "alternatives": alternatives, "static": static_sel, "dynamic": dynamic_sel,
                "kind": target.get("kind"), "scope": scope_rule, "selector": selector,
                "floor": entry.get("confidence", "derived"),
                "blockers_not_evaluated": [b for b in blockers if b and b not in EVALUATED_BLOCKERS and b not in model_blockers],
                "model_blockers": model_blockers,
                "source_kind": entry.get("source_kind"),
                "source_selector": {k: v for k, v in (entry.get("source_selector") or {}).items()
                                    if k not in GENERIC_SOURCE_SELECTORS and k not in CHAIN_SOURCE_SELECTORS},
                "source_reaches": (entry.get("source_selector") or {}).get("source_reaches_kind"),
                "source_globs": {k: v for k, v in (entry.get("source_selector") or {}).items() if k in GENERIC_SOURCE_SELECTORS},
                "source_service_managed": bool((entry.get("source_selector") or {}).get("include_service_managed"))}

    # ------------------------------------------------------------ candidates
    def note(self, kind, scope, status, reason, impact):
        key = (kind, scope, reason)
        if key not in self._noted:
            self._noted.add(key)
            self.model.add_coverage(kind, scope, status, reason, impact)

    def candidates(self, compiled):
        kind = compiled["kind"]
        model = self.model
        model.current_entry = compiled["entry"]
        variant = model.target_variant(kind, compiled["selector"])
        managed = model.include_service_managed(compiled)
        # GCP challenge evidence creates a technique-specific exact candidate set. It
        # must never share the ordinary kind-only cache entry or another technique's.
        challenge = next((compiled["selector"].get(p + "_challenge_fact")
                          for p in ("aws", "gcp", "azure", "k8s")
                          if compiled["selector"].get(p + "_challenge_fact")), None)
        if compiled["selector"].get("gcp_resource_self_grant"):
            challenge = compiled["entry"]["id"]
        if compiled["selector"].get("gcp_privatecatalog_dm_iam_path"):
            challenge = compiled["entry"]["id"]
        if compiled["selector"].get("gcp_project_iam_sa_token_grant"):
            challenge = compiled["entry"]["id"]
        if compiled["selector"].get("gcp_kcc_project_policy_grant"):
            challenge = compiled["entry"]["id"]
        if compiled["selector"].get("gcp_kcc_generated_key_secret"):
            challenge = compiled["entry"]["id"]
        if compiled["selector"].get("gcp_configdelivery_fleet_target"):
            challenge = compiled["entry"]["id"]
        if compiled["selector"].get("gcp_fleet_config_management_target"):
            challenge = compiled["entry"]["id"]
        if compiled["selector"].get("gcp_fleet_rbac_admin_target"):
            challenge = compiled["entry"]["id"]
        if compiled["selector"].get("gcp_external_principal_evidence"):
            challenge = compiled["entry"]["id"]
        if compiled["selector"].get("gcp_agentregistry_skill_evidence"):
            challenge = compiled["entry"]["id"]
        if compiled["selector"].get("gcp_bounded_access_gain"):
            challenge = compiled["entry"]["id"]
        if compiled["selector"].get("k8s_verified_pivot"):
            challenge = compiled["entry"]["id"]
        key = (kind, tuple(sorted((k, repr(v)) for k, v in compiled["static"].items())), variant, managed, challenge)
        if key in self._csets:
            return self._csets[key]
        # Static selectors may consult their siblings (all of them are part of the cache key).
        model.current_selector = compiled["selector"]
        members = {n.id: n for n in model.targets_for(kind, compiled["selector"])}
        excluded = 0
        if not managed:
            # Service-managed identities (AWS service-linked roles, Google-managed service agents, Microsoft
            # first-party service principals) cannot be passed, assumed or edited by customers.
            kept = {tid: n for tid, n in members.items() if not model.service_managed(n)}
            excluded, members = len(members) - len(kept), kept
        floor, unresolved_why = {}, {}
        for sel_key, value in sorted(compiled["static"].items()):
            if not members:
                break
            verdict = self._select(sel_key, value, members, None)
            if verdict is None:
                # Facts missing: never expand to every target. The remaining candidates become one unresolved
                # placeholder per scope (computed after the other selectors had a chance to rule them out).
                self.note("selector", "*", "not_evaluated", f"selector {sel_key} not evaluated",
                          "Matching targets reported as one unresolved placeholder per scope (no members); needs "
                          + FACTS_NEEDED.get(sel_key, "facts not in snapshot"))
                for tid in members:
                    unresolved_why.setdefault(tid, f"selector_{sel_key}_not_evaluated")
                continue
            members = {tid: n for tid, n in members.items() if tid in verdict}
            for tid, why in verdict.items():
                if not why:
                    continue
                if why[0] == "unknown":
                    # A match that rests on missing facts is not proven: placeholder, not member.
                    unresolved_why.setdefault(tid, why[1] or f"selector_{sel_key}_unknown")
                    self.note("selector", "*", "unresolved", f"selector {sel_key} unresolved ({why[1]})",
                              "Targets matching only on missing facts reported as one unresolved placeholder per scope; needs "
                              + FACTS_NEEDED.get(sel_key, "facts not in snapshot"))
                else:
                    floor[tid] = _worse(floor.get(tid), why)
        unresolved = {}
        for tid in [t for t in members if t in unresolved_why]:
            node = members.pop(tid)
            floor.pop(tid, None)
            unresolved.setdefault(node.scope, unresolved_why[tid])
        unknown_scopes = model.unknown_target_scopes(kind)
        for scope, status in unknown_scopes.items():
            if status.startswith("review_evidence_"):
                reason = f"{kind} reviewed evidence {status[len('review_evidence_'):]}"
                detail = "Exact target evidence is unavailable; no target identity has been established"
            else:
                reason = f"{kind} inventory {status}"
                detail = "Targets of this kind in this scope are unknown; techniques reaching them are reported with unknown confidence"
            self.note("targets", scope, status, reason, detail)
        digest = hashlib.sha1(repr(key).encode()).hexdigest()[:10]
        label = compiled["entry"]["target"].get("aggregate_as") or kind
        cset = CandidateSet(f"{kind}:{digest}", kind, members, floor, label, unknown_scopes, unresolved, excluded)
        self._csets[key] = cset
        return cset

    # ----------------------------------------------------------------- index
    def _select(self, key, value, candidates, source, pivot=None):
        if key in GENERIC_SELECTORS:
            return _generic_selector(key, value, candidates)
        if key.startswith(PRECONDITION_PREFIX):
            return self.model.precondition(key[len(PRECONDITION_PREFIX):], candidates, source)
        return self.model.selector(key, value, candidates, source, pivot=pivot)

    def _admin_covers(self, source, cset, compiled=None):
        """True when the source already administers every scope the technique's targets can live in for it."""
        # The scope of a Secret is its origin cluster/namespace. Administrative
        # control there establishes no authority in the separately authenticated
        # remote cluster whose credential is stored in that Secret.
        if cset.kind == "k8s_remote_cluster":
            return False
        scopes = self.admin_scopes.get(source.id)
        if not scopes:
            return False
        within = self.model.scope_within
        wanted = set(cset.by_scope) | set(cset.unknown_scopes) | set(cset.unresolved)
        allowed = self.model.allowed_scopes(compiled["scope"], source) if compiled is not None else None
        if allowed is not None:
            wanted = {s for s in wanted if s in allowed}
        return all(any(within(s, a) for a in scopes) for s in wanted)

    def _index(self):
        model = self.model
        self.by_key, self.universal = {}, set()
        # Only requirement keys of compiled alternatives are ever looked up (_alt_sources). Models return one
        # shared key set per equal permission key, so index each distinct set once for all of its sources.
        wanted = {r.key for c in self.compiled for alt in c["alternatives"] for r in alt}
        groups = {}
        for node in model.sources():
            keys, universal = model.possible(node)
            if universal:
                self.universal.add(node.id)
            if not isinstance(keys, (set, frozenset)):
                keys = frozenset(keys)
            group = groups.get(id(keys))
            if group is None:
                groups[id(keys)] = group = (keys, [])
            group[1].append(node.id)
        for keys, ids in groups.values():
            hits = wanted.intersection(keys) if len(keys) > len(wanted) else [k for k in keys if k in wanted]
            for key in hits:
                self.by_key.setdefault(key, set()).update(ids)
        self.all_sources = {n.id: n for n in model.sources()}
        self.service_managed_sources = {sid for sid, n in self.all_sources.items() if model.managed_source(n)}

    def _alt_sources(self, reqs):
        sets, unknown = [], []
        for req in reqs:
            reason = self.model.global_unknown(req.raw)
            if reason:
                if self.model.provider == "azure" and "entra_owner_of" in req.raw:
                    # Owner lists are per object. A missing list must not downgrade
                    # a different object's recorded owner to unknown.
                    sets.append(self.model.unknown_holders(req.raw))
                    continue
                unknown.append((req, reason))
                sets.append(self.model.unknown_holders(req.raw))
                continue
            sets.append(self.by_key.get(req.key, set()) | self.universal)
        if not sets:
            return set(self.all_sources), unknown
        sets.sort(key=len)
        result = set(sets[0])
        for other in sets[1:]:
            result &= other
            if not result:
                break
        return result, unknown

    # --------------------------------------------------------------- evaluate
    def run(self):
        reaches, gated = [], []
        for compiled in self.compiled:
            technique_id = compiled["entry"]["id"]
            if self.model.provider == 'aws' and technique_id == 'aws-ec2-passrole-associate-instance-profile':
                from .effective_permissions.ec2_profile_association import evaluate as evaluate_profile_association
                reaches.extend(evaluate_profile_association(self, compiled))
                continue
            if (technique_id in _SHARED_SEMANTIC_HOLDS or
                    (technique_id == "gcp-privatecatalog-product-version-poison" and
                     compiled["selector"].get("gcp_privatecatalog_dm_iam_path") is not True) or
                    (technique_id == "gcp-appengine-versions-create-actas" and
                     compiled["selector"].get("gcp_appengine_deploy_path") is not True) or
                    (technique_id == "gcp-appintegration-runas-sa-actas" and
                     compiled["selector"].get("gcp_appintegration_run_as_path") is not True) or
                    (technique_id == "gcp-artifactregistry-gcrio-namespace-squat" and
                     compiled["selector"].get("gcp_gcr_namespace_path") is not True) or
                    (technique_id == "gcp-artifactregistry-repositories-setiampolicy" and
                     compiled["selector"].get("gcp_artifact_policy_consumer_path") is not True) or
                    (technique_id == "gcp-artifactregistry-upload-artifacts" and
                     compiled["selector"].get("gcp_artifact_upload_consumer_path") is not True) or
                    (technique_id == "gcp-agentidentity-retrieve-credentials" and
                     compiled["selector"].get("gcp_agentidentity_retrieve_path") is not True) or
                    (technique_id == "gcp-agentidentity-update-token-url" and
                     compiled["selector"].get("gcp_agentidentity_update_path") is not True)):
                self.note("technique", "*", "unresolved", f"{technique_id} exact semantic join held",
                          "No principal edge until the exact source, target, scope and execution facts are collected "
                          "and the corrected technique semantics are admitted")
                continue
            (gated if compiled.get("source_reaches") else reaches).extend(self.evaluate(compiled))
        if self._blocked_pending:
            for reach in self._lift_blockers(reaches + gated):
                (gated if reach.entry.get("source_reaches") else reaches).append(reach)
        if gated:
            reaches.extend(self._chain_gate(reaches, gated))
        return reaches

    def _chain_gate(self, reaches, gated):
        """source_selector.source_reaches_kind: keep a gated reach only when its source is of the wanted kind or reaches
        a node of that kind through the other reaches (iterated to a fixpoint: kept gated reaches add edges). The reach
        is downgraded to the weakest confidence of the best chain, with condition source_reaches_<kind>_via_chain."""
        adjacency = {}   # source id -> {target id: (confidence rank, target kind)}
        add_edges = functools.partial(_add_edges, adjacency)
        for reach in reaches:
            add_edges(reach)
        levels = sorted(CONF_RANK, key=CONF_RANK.__getitem__)
        pending, kept = list(gated), []
        while pending:
            cache, still, progress = {}, [], False
            for reach in pending:
                wanted = reach.entry["source_reaches"]
                source = reach.source
                if reach.source_group or source is None:
                    continue  # aggregated "may reach" sources: the chain cannot be attributed
                if reach.entry["source_selector"].get("source_reaches_user_outside_target_group"):
                    targets = (reach.targets.expand(reach.cset, source.id)
                               if isinstance(reach.targets, AllOf) else reach.targets)
                    matched = {}
                    for tid, grant in (targets or {}).items():
                        group = reach.cset.members.get(tid)
                        if group is None:
                            continue
                        def eligible_user(user_id, group_id=group.id):
                            user = self.model.principals.get(user_id)
                            return (user is not None and user.kind == "azure_user"
                                    and user.attrs.get("account_enabled") is True
                                    and group_id not in self.model._groups(user_id))
                        if source.kind == wanted:
                            level = grant.confidence if eligible_user(source.id) else None
                        else:
                            key = (source.id, wanted, tid)
                            if key not in cache:
                                cache[key] = self._chain_level(adjacency, source.id, wanted, levels, eligible_user)
                            level = cache[key]
                        if level is not None:
                            matched[tid] = downgrade(grant, level, "source_reaches_nonmember_user_via_chain")
                    if matched:
                        kept.append(Reach(reach.entry, source, matched, reach.cset, source_group=reach.source_group))
                        add_edges(kept[-1])
                        progress = True
                    else:
                        still.append(reach)
                    continue
                if source.kind == wanted:
                    kept.append(reach)
                    add_edges(reach)
                    progress = True
                    continue
                key = (source.id, wanted)
                if key not in cache:
                    cache[key] = self._chain_level(adjacency, source.id, wanted, levels)
                level = cache[key]
                if level is None:
                    still.append(reach)
                    continue
                why = f"source_reaches_{wanted}_via_chain"
                kept.append(Reach(reach.entry, source, _map_grants(reach.targets, lambda g: downgrade(g, level, why)),
                                  reach.cset, source_group=reach.source_group))
                add_edges(kept[-1])
                progress = True
            if not progress or len(still) == len(pending):
                break
            pending = still
        return kept

    @staticmethod
    def _chain_level(adjacency, start, wanted, levels, accept_target=None):
        """Best (strongest) confidence level at which `start` reaches a node of kind `wanted`, or None."""
        for level in levels:
            limit = CONF_RANK[level]
            seen, frontier = {start}, [start]
            while frontier:
                nxt = []
                for nid in frontier:
                    for tid, (rank, kind) in adjacency.get(nid, {}).items():
                        if rank > limit or tid in seen:
                            continue
                        if kind == wanted and (accept_target is None or accept_target(tid)):
                            return level
                        seen.add(tid)
                        nxt.append(tid)
                frontier = nxt
        return None

    def evaluate(self, compiled):
        model = self.model
        cset = self.candidates(compiled)
        if not cset.members and not cset.unknown_scopes and not cset.unresolved:
            return []
        model.current_selector = compiled["selector"]
        model.current_cset = cset
        model.current_entry = compiled["entry"]
        results = {}
        grouped_unknown = {}
        for index, reqs in enumerate(compiled["alternatives"]):
            sources, unknown_reqs = self._alt_sources(reqs)
            if unknown_reqs:
                for req, reason in unknown_reqs:
                    self.note("requirement", "*", "not_collected", f"{req.key} facts not collected",
                              "Techniques requiring it are reported with unknown confidence for aggregated sources; needs " + reason)
                if not self.include_unknown:
                    continue
            known = [r for r in reqs if not any(r is u for u, _ in unknown_reqs)]
            # Sources with equal model memo keys (same effective policies and account) reach the same targets when
            # nothing in the technique names the source: evaluate once per key (avoids sources x targets work).
            memo_ok = all(k in model.memo_safe_selectors and "{source" not in repr(v) and "{pivot" not in repr(v)
                          for k, v in compiled["dynamic"].items()) \
                and not compiled["selector"].get("same_as_source") and not any(
                r.mode == "pivot" or "{source." in (r.template or "") for r in known)
            memo = {}
            for sid in sorted(sources):  # sets iterate in hash-seed order; keep output deterministic
                source = self.all_sources[sid]
                if sid in self.service_managed_sources and not compiled["source_service_managed"]:
                    # Service-linked roles / Google-managed agents / Microsoft first-party apps: only the owning
                    # service holds their credentials, so customers cannot act as them.
                    self.skipped_service_managed += 1
                    continue
                if not model.source_matches(source, compiled["source_kind"], compiled["source_selector"]):
                    continue
                # "source_id_glob" is enforced by _source_glob_ok for generic source selectors.
                if compiled["source_globs"] and not _source_glob_ok(source, compiled["source_globs"]):
                    continue
                if self._admin_covers(source, cset, compiled):
                    self.skipped_admin += 1
                    continue
                memo_key = model.source_memo_key(source) if memo_ok else None
                if memo_key is None:
                    reached = self._evaluate_source(compiled, known, source, cset)
                else:
                    if memo_key in memo:
                        self.memo_hits += 1
                    else:
                        memo[memo_key] = self._evaluate_source(compiled, known, source, cset, skip_self=False)
                    reached = _without(memo[memo_key], sid)
                if reached and compiled["model_blockers"]:
                    reached = self._apply_blockers(compiled, source, reached, cset,
                                                   self._last_pivots if memo_key is None else None)
                if not reached:
                    continue
                if unknown_reqs:
                    # Group "may reach" sources by what they would reach, without materialising targets.
                    if isinstance(reached, AllOf):
                        sig = ("all", None if reached.scopes is None else frozenset(reached.scopes), frozenset(reached.unknown))
                    else:
                        sig = ("set", frozenset(reached))
                    group = grouped_unknown.setdefault((index, sig), {"sources": [], "reached": reached,
                                                                       "why": unknown_reqs})
                    group["sources"].append(source)
                    continue
                previous = results.get(sid)
                if previous is None:
                    results[sid] = reached
                    continue
                if isinstance(previous, AllOf) and isinstance(reached, AllOf) and previous.scopes == reached.scopes:
                    results[sid] = AllOf(best(previous.grant, reached.grant), previous.scopes, {**reached.unknown, **previous.unknown})
                    continue
                previous = previous.expand(cset, sid) if isinstance(previous, AllOf) else previous
                reached = reached.expand(cset, sid) if isinstance(reached, AllOf) else reached
                merged = dict(previous)
                for tid, grant in reached.items():
                    merged[tid] = best(merged.get(tid), grant)
                results[sid] = merged
        out = self._share_placeholders(compiled, cset, results)
        for group in grouped_unknown.values():
            why = "requirement_facts_not_collected:" + ",".join(r.key for r, _ in group["why"])
            # Sources that already reach this technique with known facts are not repeated as "may reach".
            sources = [src for src in group["sources"] if src.id not in results]
            if not sources:
                continue
            reached = group["reached"]
            if isinstance(reached, AllOf):
                targets = AllOf(downgrade(reached.grant, "unknown", why), reached.scopes,
                                {tid: downgrade(g, "unknown", why) for tid, g in reached.unknown.items()})
            else:
                targets = {tid: downgrade(g, "unknown", why) for tid, g in reached.items()}
            out.append(Reach(compiled, sources[0], targets, cset, source_group=sources if len(sources) > 1 else None))
        model.current_selector = None
        model.current_cset = None
        return out

    def _share_placeholders(self, compiled, cset, results):
        """Reaches per source, with memberless placeholders (unresolved targets, unknown inventories) shared.

        A placeholder stands for targets whose facts were not collected; every source holding the technique's
        permissions reaches it the same way, so sources x placeholders edges carry no information. Each placeholder
        is reached once per technique by the group of its holders (sources with the same placeholders share one
        group). A source drops placeholders in scopes it already administers and, for scope-entity targets, in
        scopes under another scope it reaches (control of an organization implies control of its projects)."""
        within = self.model.scope_within
        # Optional model hook: scope_containers(inner) is exactly {outer : scope_within(inner, outer)}.
        containers = getattr(self.model, "scope_containers", None)
        prefix = len(cset.id) + 1
        entity = self._entity_kind(cset.kind)
        rest, holders = {}, {}
        for sid, targets in results.items():
            if not targets:
                continue
            if isinstance(targets, AllOf):
                placeholders, rest[sid] = targets.unknown, AllOf(targets.grant, targets.scopes, {})
                reached_scopes = list(cset.by_scope) if targets.scopes is None else list(targets.scopes)
            else:
                placeholders = {t: g for t, g in targets.items() if t.startswith(_PLACEHOLDER_PREFIXES)}
                kept = {t: g for t, g in targets.items() if t not in placeholders}
                if kept:
                    rest[sid] = kept
                reached_scopes = list({cset.members[t].scope for t in kept if t in cset.members}) if entity else []
            if not placeholders:
                continue
            scopes = {t: t.split(":", 1)[1][prefix:] or "*" for t in placeholders}
            admin = self.admin_scopes.get(sid) or ()
            # The skip test depends only on the placeholder's scope (and is order-free), so it is decided once per
            # distinct scope against the de-duplicated dominating scopes instead of once per placeholder.
            dominating = set(admin)
            dominating.update(reached_scopes)
            if entity:
                dominating.update(scopes.values())
            admin_set = set(admin)
            skip = {}
            for tid, grant in placeholders.items():
                scope = scopes[tid]
                dropped = skip.get(scope)
                if dropped is None:
                    if containers is not None:
                        # Same test from the other side: the (few) scopes containing this one vs the dominating set.
                        outer = containers(scope)
                        dropped = any(other != scope for other in outer if other in dominating) or \
                            not outer.isdisjoint(admin_set)
                    else:
                        dropped = any(other != scope and within(scope, other) for other in dominating) or \
                            any(within(scope, a) for a in admin)
                    skip[scope] = dropped
                if dropped:
                    continue
                holder = holders.setdefault(tid, {})
                holder[sid] = grant
        groups = {}
        for tid, by_source in holders.items():
            groups.setdefault(frozenset(by_source), {})[tid] = by_source
        for sids, placeholders in groups.items():
            merged = {}
            for tid, by_source in placeholders.items():
                grant = None
                for g in by_source.values():
                    grant = best(grant, g)
                merged[tid] = grant
            if len(sids) == 1:
                (sid,) = sids
                own = rest.get(sid)
                if own is None:
                    rest[sid] = merged
                elif isinstance(own, AllOf):
                    own.unknown.update(merged)
                else:
                    own.update(merged)
                continue
            sources = sorted((self.all_sources[sid] for sid in sids), key=lambda n: n.id)
            rest[("group",) + tuple(n.id for n in sources)] = (sources, merged)
        out = []
        for key, targets in rest.items():
            if isinstance(key, tuple):
                sources, merged = targets
                out.append(Reach(compiled, sources[0], merged, cset, source_group=sources))
            elif targets:
                out.append(Reach(compiled, self.all_sources[key], targets, cset))
        return out

    def _entity_kind(self, kind):
        """Targets of this kind are scope entities (control of a scope covers the scopes below it)."""
        cache = self.__dict__.setdefault("_entity_kinds", {})
        if kind not in cache:
            first = next(iter(self.model.targets(kind)), None)
            cache[kind] = bool(first is not None and first.entity)
        return cache[kind]

    def _apply_blockers(self, compiled, source, reached, cset=None, pivots=None):
        """Model-evaluated blockers. Verdicts (Model.blocker_verdict): 'clear' (evaluated, does not apply);
        None (facts missing: edge kept, annotated blocker_<b>_not_evaluated); ('possibly_blocked', evidence) (an
        enforcing control may reject the technique: edge kept, downgraded to conditional with the evidence);
        ('blocked', evidence) (definitive: the reach is held back for the lift pass and, unless a reachable
        target.removes_blockers technique lifts the blocker, reported in Evaluator.blocked). A dict verdict is per
        target id (targets missing from it are not affected)."""
        blocked = {}   # target id (or None: the whole reach) -> [(blocker, evidence)]
        owned = False  # per-target downgrades update one private copy of `reached` (keys keep their order)
        for blocker in compiled["model_blockers"]:
            verdict = self.model.blocker_verdict(blocker, source, compiled, pivots=pivots, reached=reached, cset=cset)
            per_target = verdict if isinstance(verdict, dict) else None
            if per_target is not None and isinstance(reached, AllOf):
                reached = reached.expand(cset, source.id) if cset is not None else reached
            for tid, raw in (per_target.items() if per_target is not None else ((None, verdict),)):
                if per_target is not None and tid not in reached:
                    continue
                state, evidence = _verdict(raw)
                if state == "clear":
                    continue
                if state == "blocked":
                    blocked.setdefault(tid, []).append((blocker, evidence))
                    continue
                if state == "possibly_blocked":
                    why = f"blocker_{blocker}_possibly_enforced" + (f": {evidence}" if evidence else "")
                    self.note("blocker", source.scope, "possibly_blocked", f"blocker {blocker} possibly enforced",
                              "Edges kept as conditional with the enforcing control as evidence")
                    fn = lambda g, why=why: downgrade(g, "conditional", why)
                else:
                    why = f"blocker_{blocker}_not_evaluated"
                    self.note("blocker", "*", "not_evaluated", f"blocker {blocker} not evaluated",
                              "Edges kept; needs " + FACTS_NEEDED.get(blocker, "facts not in snapshot"))
                    # An uncollected admission control can reject the workload.
                    # Preserve the route, but do not call it definite.
                    level = "conditional" if self.model.provider == "k8s" else None
                    fn = lambda g, why=why, level=level: downgrade(g, level or g.confidence, why)
                if tid is None:
                    reached, owned = _map_grants(reached, fn), False
                else:
                    if not owned:
                        reached, owned = dict(reached), True
                    reached[tid] = fn(reached[tid])
        if not blocked:
            return reached
        if None in blocked:
            self._blocked_pending.append((compiled, source, reached, cset, blocked[None]))
            return None
        groups = {}
        for tid, why in blocked.items():
            groups.setdefault(tuple(why), {})[tid] = reached[tid]
        for why, targets in groups.items():
            self._blocked_pending.append((compiled, source, targets, cset, list(why)))
        rest = {tid: g for tid, g in reached.items() if tid not in blocked}
        return rest or None

    def _lift_blockers(self, reaches):
        """Restore held-back (blocked) reaches whose source - or a node it reaches through the other reaches - reaches
        a scope entity (k8s_admission_control) of a scope containing the source's with a technique whose target.removes_blockers
        covers every blocker of the reach. The restored reach is downgraded to the weakest confidence of the chain,
        with condition blocker_<b>_lifted_via_<technique>. Iterated to a fixpoint; what stays blocked is reported in
        self.blocked and as coverage."""
        adjacency, lifters = {}, {}   # node id -> [(entity scope, frozenset(blockers), rank, technique id)]

        def index(reach):
            _add_edges(adjacency, reach)
            removes = (reach.entry["entry"].get("target") or {}).get("removes_blockers")
            if not removes or reach.source_group or reach.source is None:
                return
            lifted = set(removes)
            for b in removes:
                lifted |= BLOCKER_ALIASES.get(b, set())
            targets = reach.targets.expand(reach.cset, reach.source.id) if isinstance(reach.targets, AllOf) else reach.targets
            for tid, grant in (targets or {}).items():
                node = reach.cset.members.get(tid)
                if node is not None and node.entity:
                    lifters.setdefault(reach.source.id, []).append(
                        (node.scope, frozenset(lifted), CONF_RANK[grant.confidence], reach.entry["entry"]["id"]))

        for reach in reaches:
            index(reach)
        levels = sorted(CONF_RANK, key=CONF_RANK.__getitem__)
        pending, restored = list(self._blocked_pending), []
        while pending:
            still = []
            for item in pending:
                compiled, source, targets, cset, why = item
                found = self._lift_level(adjacency, lifters, source, {b for b, _ in why}, levels)
                if found is None:
                    still.append(item)
                    continue
                level, techniques = found
                conds = [f"blocker_{b}_lifted_via_{techniques[b]}" + (f" (was: {ev})" if ev else "") for b, ev in why]

                def lift(g, conds=conds, level=level):
                    for cond in conds:
                        g = downgrade(g, level, cond)
                    return g
                reach = Reach(compiled, source, _map_grants(targets, lift), cset)
                restored.append(reach)
                index(reach)
            if len(still) == len(pending):
                break
            pending = still
        self._blocked_pending = []
        for compiled, source, targets, cset, why in pending:
            expanded = targets.expand(cset, source.id) if isinstance(targets, AllOf) else targets
            for b, ev in why:
                self.note("blocker", source.scope, "blocked", f"blocker {b} enforced",
                          "Edges removed from the attack graph; listed in stats['blocked'] with the evidence")
            self.blocked.append({
                "technique": compiled["entry"]["id"], "source": source.id, "source_label": source.label,
                "blockers": [{"id": b, "evidence": ev} for b, ev in why],
                "target_count": len(expanded), "targets": sorted(expanded)[:20],
                "confidence": min((g.confidence for g in expanded.values()), key=CONF_RANK.__getitem__, default="unknown")})
        return restored

    def _lift_level(self, adjacency, lifters, source, needed, levels):
        """(level, {blocker: technique id}) for the strongest level at which every needed blocker is lifted from
        nodes reachable from `source` (the source itself included), or None."""
        for level in levels:
            limit = CONF_RANK[level]
            seen, frontier, got = {source.id}, [source.id], {}
            while frontier:
                nxt = []
                for nid in frontier:
                    for scope, lifted, rank, technique in lifters.get(nid, ()):
                        if rank <= limit and (scope == source.scope or self.model.scope_within(source.scope, scope)):
                            for b in needed & lifted:
                                got.setdefault(b, technique)
                    for tid, (rank, _) in adjacency.get(nid, {}).items():
                        if rank <= limit and tid not in seen:
                            seen.add(tid)
                            nxt.append(tid)
                frontier = nxt
            if needed <= set(got):
                return level, got
        return None

    @staticmethod
    def _steps(per_target):
        """Per-target requirements in evaluation order; requirements sharing a multi-valued placeholder are joined."""
        groups, steps = {}, []
        for req in sorted(per_target, key=lambda r: 0 if not r.localized else 1):
            shared = sorted(set(_PH.findall(req.template or "")) & SHARED_PLACEHOLDERS) if not req.localized else []
            if shared:
                groups.setdefault(shared[0], []).append(req)
            else:
                steps.append(req)
        for name, reqs in sorted(groups.items()):
            if len(reqs) == 1:
                steps.insert(0, reqs[0])
            else:
                steps.insert(0, (name, reqs))
        return steps

    def _evaluate_source(self, compiled, reqs, source, cset, skip_self=True):
        model = self.model
        self._last_pivots = None
        if (model.provider == "k8s" and any("source_rolebound_clusterrole" in (r.template or "") for r in reqs)
                and not all(model._complete(k) for k in ("rolebinding", "clusterrole", "clusterrolebinding"))):
            if not self.include_unknown:
                return None
            reason = "rolebound_clusterrole_rbac_not_collected"
            scopes = {target.scope for target in cset.members.values() if model.scope_allows(compiled["scope"], source, target)}
            scopes.update(cset.unknown_scopes)
            return {f"{UNRESOLVED_PREFIX}{cset.id}:{scope}": Grant("unknown", [], [reason])
                    for scope in sorted(scopes)} or None
        static = [r for r in reqs if r.mode == "static"]
        pivot = [r for r in reqs if r.mode == "pivot"]
        per_target = [r for r in reqs if r.mode == "target"]
        grant = Grant(compiled["floor"] if compiled["floor"] in CONF_RANK else "derived")
        grants = [grant]
        bound = {}
        for req in static:
            if req.raw.get("bind"):
                bound.setdefault(req.raw["bind"], []).append(req)
        for name, group in sorted(bound.items()):
            if len(group) < 2:
                continue  # a bind name used once in this alternative is an ordinary requirement
            got = model.check_bound(source, [r.raw for r in group], [r.template for r in group])
            if got is None:
                return None
            for requirement in group:
                got = _tag_permission(got, requirement.raw)
            grants.append(got)
        for req in static:
            if req.raw.get("bind") and len(bound.get(req.raw["bind"], ())) >= 2:
                continue
            refs, floor = model.resolve(req.template, source, None)
            got = None
            for ref in refs:
                got = best(got, model.cached_check(source, req.raw, ref))
            if got is None:
                return None
            got = downgrade(got, floor[0], floor[1]) if floor else got
            grants.append(_tag_permission(got, req.raw))
        pivot_values = None
        if pivot:
            got, pivot_values = self._pivot(source, pivot)
            if got is None:
                return None
            self._last_pivots = pivot_values
            grants.append(got)
        base = combine(*grants)
        members = cset.members
        placeholders = {}
        if self.include_unknown and (cset.unknown_scopes or cset.unresolved):
            # Per-target requirements cannot be checked on a placeholder: the source must at least hold them
            # on some resource.
            for req in per_target:
                got = model.cached_check(source, req.raw, ANY)
                if got is None:
                    placeholders = None
                    break
            if placeholders is not None:
                allowed = model.allowed_scopes(compiled["scope"], source)
                if not compiled["selector"].get("same_as_source"):
                    placeholders.update({f"unknown:{cset.id}:{s}": downgrade(base, "unknown", f"target_inventory_{st}")
                                         for s, st in cset.unknown_scopes.items()
                                         if allowed is None or s in allowed})
                placeholders.update({f"{UNRESOLVED_PREFIX}{cset.id}:{s}": downgrade(base, "unknown", why)
                                     for s, why in cset.unresolved.items() if allowed is None or s in allowed})
        placeholders = placeholders or {}
        if not members:
            # Inventory unavailable or selector facts missing: placeholder reaches only.
            return placeholders or None
        current = AllTargets(base)
        for req in self._steps(per_target):
            if isinstance(req, tuple):
                name, joined = req
                candidates = members.values() if isinstance(current, AllTargets) else [members[t] for t in current]
                got = model.check_targets_shared(source, [r.raw for r in joined], [r.template for r in joined], name, candidates)
            elif isinstance(current, AllTargets) and model.scope_only(req.raw, req.template, req.localized):
                # The requirement depends on the target only through its scope: check one target per scope.
                reps = {next(iter(ids)): scope for scope, ids in cset.by_scope.items() if ids}
                got = model.check_targets(source, req.raw, req.template, [members[t] for t in reps], localized=req.localized)
                if not isinstance(got, AllTargets):
                    held = {reps[t]: g for t, g in got.items()}
                    if len(held) < len(reps):
                        got = {tid: g for scope, g in held.items() for tid in cset.by_scope[scope]}
                    elif len({id(g) for g in held.values()}) == 1:
                        got = AllTargets(next(iter(held.values())))
                    else:
                        got = {tid: g for scope, g in held.items() for tid in cset.by_scope[scope]}
            elif not isinstance(current, AllTargets) and model.scope_only(req.raw, req.template, req.localized):
                # Already narrowed: still one check per scope of the remaining targets.
                reps = {}
                for tid in current:
                    reps.setdefault(members[tid].scope, tid)
                held = model.check_targets(source, req.raw, req.template, [members[t] for t in reps.values()], localized=req.localized)
                held = held.grant if isinstance(held, AllTargets) else held
                got = {}
                for tid in current:
                    rep = reps[members[tid].scope]
                    g = held if isinstance(held, Grant) else held.get(rep)
                    if g is not None:
                        got[tid] = g
            else:
                candidates = members.values() if isinstance(current, AllTargets) else [members[t] for t in current]
                if not candidates:
                    return placeholders or None
                got = model.check_targets(source, req.raw, req.template, candidates, localized=req.localized)
            if not isinstance(req, tuple):
                got = _tag_result(got, req.raw)
            if isinstance(got, AllTargets):
                if isinstance(current, AllTargets):
                    current = AllTargets(combine(current.grant, got.grant))
                else:
                    current = _combine_each(current, got.grant, left=True)
            else:
                if isinstance(current, AllTargets):
                    current = _combine_each(got, current.grant, left=False)
                else:
                    current = {t: combine(g, got[t]) for t, g in current.items() if t in got}
            if not current:
                return placeholders or None
        scope_rule = compiled["scope"]
        unknown = dict(placeholders)
        if isinstance(current, AllTargets) and not compiled["dynamic"] and not model.target_gain_required():
            allowed = model.allowed_scopes(scope_rule, source)
            if current.grant.confidence == "unknown":
                # Every candidate reached only through missing facts (e.g. an unresolvable target placeholder).
                if self.include_unknown:
                    why = _unknown_reason(current.grant)
                    for scope in cset.by_scope:
                        if allowed is None or scope in allowed:
                            unknown.setdefault(f"{UNRESOLVED_PREFIX}{cset.id}:{scope}", downgrade(current.grant, "unknown", why))
                return unknown or None
            # Symbolic "every candidate" result: graph.py aggregates without materialising members.
            return AllOf(current.grant, allowed, unknown)
        first_dynamic_verdict = None
        if (isinstance(current, AllTargets) and len(compiled["dynamic"]) == 1
                and not cset.floor and not model.target_gain_required()):
            # An unevaluable selector leaves only one unresolved target per scope. When
            # every member has the same grant, materialising and downgrading every
            # target for every source adds no information (notably 10k Azure users).
            key, value = next(iter(compiled["dynamic"].items()))
            first_dynamic_verdict = self._select(key, value, members, source, pivot=pivot_values)
            if (isinstance(first_dynamic_verdict, UniformVerdict)
                    and first_dynamic_verdict.verdict[0] == "unknown" and not self.include_unknown):
                # Every selected target depends on missing facts. No concrete
                # edge can be produced, including when the selector chose a
                # subset of the candidate set.
                return placeholders or None
            if first_dynamic_verdict is None:
                self.note("selector", "*", "not_evaluated", f"selector {key} not evaluated",
                          "Matching targets reported as one unresolved placeholder per scope (no members); needs "
                          + FACTS_NEEDED.get(key, "facts not in snapshot"))
                grant = downgrade(current.grant, "unknown", f"selector_{key}_not_evaluated")
            elif (isinstance(first_dynamic_verdict, UniformVerdict)
                  and first_dynamic_verdict.candidates is members
                  and first_dynamic_verdict.exclude in (None, source.id)) or first_dynamic_verdict.keys() == members.keys():
                first = (first_dynamic_verdict.verdict if isinstance(first_dynamic_verdict, UniformVerdict)
                         else next(iter(first_dynamic_verdict.values()), None))
                if first and first[0] == "unknown" and (isinstance(first_dynamic_verdict, UniformVerdict)
                                                       or all(v == first for v in first_dynamic_verdict.values())):
                    reason = first[1] or f"selector_{key}_unknown"
                    self.note("selector", "*", "unresolved", f"selector {key} unresolved ({first[1]})",
                              "Targets matching only on missing facts reported as one unresolved placeholder per scope; needs "
                              + FACTS_NEEDED.get(key, "facts not in snapshot"))
                    grant = downgrade(downgrade(current.grant, *first), "unknown", reason)
                else:
                    grant = None
            else:
                grant = None
            if grant is not None:
                result = {}
                if self.include_unknown:
                    allowed = model.allowed_scopes(scope_rule, source)
                    for scope, ids in cset.by_scope.items():
                        if (allowed is None or scope in allowed) and (not skip_self or len(ids) > 1 or source.id not in ids):
                            result[f"{UNRESOLVED_PREFIX}{cset.id}:{scope}"] = grant
                result.update(unknown)
                return result or None
        if isinstance(current, AllTargets):
            current = {tid: current.grant for tid in members}
        unresolved = {}
        for key, value in compiled["dynamic"].items():
            subset = {tid: members[tid] for tid in current}
            verdict = first_dynamic_verdict if first_dynamic_verdict is not None else self._select(
                key, value, subset, source, pivot=pivot_values)
            if verdict is None:
                self.note("selector", "*", "not_evaluated", f"selector {key} not evaluated",
                          "Matching targets reported as one unresolved placeholder per scope (no members); needs "
                          + FACTS_NEEDED.get(key, "facts not in snapshot"))
                for tid in current:
                    unresolved.setdefault(tid, f"selector_{key}_not_evaluated")
                continue
            for tid, why in verdict.items():
                if why and why[0] == "unknown" and tid in current:
                    unresolved.setdefault(tid, why[1] or f"selector_{key}_unknown")
                    self.note("selector", "*", "unresolved", f"selector {key} unresolved ({why[1]})",
                              "Targets matching only on missing facts reported as one unresolved placeholder per scope; needs "
                              + FACTS_NEEDED.get(key, "facts not in snapshot"))
            current = _downgrade_each(current, verdict)
            if not current:
                return unknown or None
        result = {}
        for tid, g in current.items():
            target = members[tid]
            if not model.scope_allows(scope_rule, source, target):
                continue
            if skip_self and tid == source.id and not compiled["selector"].get("same_as_source"):
                continue
            gain = model.target_gain(source, target)
            if gain is False:
                continue
            if gain:
                g = downgrade(g, *gain)
            if tid in unresolved:
                if self.include_unknown:
                    pid = f"{UNRESOLVED_PREFIX}{cset.id}:{target.scope}"
                    result[pid] = best(result.get(pid), downgrade(g, "unknown", unresolved[tid]))
                continue
            floor = cset.floor.get(tid)
            g = downgrade(g, floor[0], floor[1]) if floor else g
            if g.confidence == "unknown":
                # A target reached only through missing facts is not proven: placeholder, not member.
                if self.include_unknown:
                    pid = f"{UNRESOLVED_PREFIX}{cset.id}:{target.scope}"
                    result[pid] = best(result.get(pid), g)
                continue
            result[tid] = g
        result.update(unknown)
        return result or None

    def _pivot(self, source, reqs):
        """Find a pivot (resource / namespace) on which every pivot requirement holds."""
        model = self.model
        candidates = model.pivot_candidates(source)
        if candidates is None:
            grants = []
            for req in reqs:
                got = model.cached_check(source, req.raw, ANY)
                if got is None:
                    return None, None
                grants.append(_tag_permission(got, req.raw))
            return downgrade(combine(*grants), "conditional", "pivot_resource_not_verified"), None
        winner, values = None, []
        for pivot in candidates:
            grants = []
            for req in reqs:
                refs, floor = model.resolve(req.template, source, None, pivot=pivot)
                got = None
                for ref in refs:
                    got = best(got, model.cached_check(source, req.raw, ref))
                if got is None:
                    break
                got = downgrade(got, floor[0], floor[1]) if floor else got
                grants.append(_tag_permission(got, req.raw))
            else:
                values.append(pivot)
                winner = best(winner, combine(*grants))
        if winner is None:
            return None, None
        return downgrade(winner, "conditional", "pivot_resource_may_need_creation") if model.pivot_is_conditional else winner, values


def _generic_selector(key, value, candidates):
    """Evaluator-implemented selectors that only read the node id / label (every provider, always evaluable)."""
    globs = as_list(value)
    out = {}
    for tid, node in (candidates.items() if isinstance(candidates, dict) else ((n.id, n) for n in candidates)):
        if key == "target_id_glob":
            keep = any(glob_match(g, tid) for g in globs)
        elif key == "target_name_glob":
            keep = any(glob_match(g, str(node.label or "")) or glob_match(g, str(node.attrs.get("name") or "")) for g in globs)
        else:  # exclude_target_id_glob
            keep = not any(glob_match(g, tid) for g in globs)
        if keep:
            out[tid] = None
    return out

def _source_glob_ok(source, globs):
    return all(any(glob_match(g, source.id) for g in as_list(value)) for value in globs.values())

def _unknown_reason(grant):
    return next((c for c in reversed(grant.conditions) if "not_in_snapshot" in c or "not_collected" in c or "not_evaluated" in c),
                grant.conditions[-1] if grant.conditions else "facts_missing")


def _verdict(raw):
    """Normalise a blocker verdict: 'clear' | 'blocked' | 'possibly_blocked' | None, optionally (state, evidence)."""
    if isinstance(raw, (tuple, list)):
        state, evidence = (tuple(raw) + (None,))[:2]
    else:
        state, evidence = raw, None
    if state not in ("clear", "blocked", "possibly_blocked"):
        state = None
    return state, (str(evidence)[:300] if evidence else None)


def _add_edges(adjacency, reach):
    """Adjacency {source id: {target id: (best confidence rank, target kind)}} of a reach (attributed sources only)."""
    if reach.source_group or reach.source is None:
        return
    out = adjacency.setdefault(reach.source.id, {})
    targets = reach.targets.expand(reach.cset, reach.source.id) if isinstance(reach.targets, AllOf) else reach.targets
    for tid, grant in (targets or {}).items():
        node = reach.cset.members.get(tid)
        kind = node.kind if node is not None else reach.cset.kind
        rank = CONF_RANK[grant.confidence]
        if tid not in out or rank < out[tid][0]:
            out[tid] = (rank, kind)


def _map_grants(reached, fn):
    if isinstance(reached, AllOf):
        return AllOf(fn(reached.grant), reached.scopes, {k: fn(v) for k, v in reached.unknown.items()})
    return {k: fn(v) for k, v in reached.items()}

def _worse(current, new):
    if current is None:
        return new
    return new if CONF_RANK[new[0]] > CONF_RANK[current[0]] else current


def _combine_each(grants, other, left):
    """{t: combine(g, other)} (or combine(other, g)) with one combine per distinct grant object: targets reached
    through the same statement share their Grant, so a per-target combine is mostly repeated work."""
    out, seen = {}, {}
    for t, g in grants.items():
        key = id(g)
        got = seen.get(key)
        if got is None:
            got = seen[key] = (combine(g, other) if left else combine(other, g), g)
        out[t] = got[0]
    return out


def _downgrade_each(current, verdict):
    """{t: downgrade(g, *verdict[t]) or g} for the targets the verdict keeps, with one downgrade per distinct
    (grant object, verdict): Grants are immutable, so equal inputs share one result like _combine_each."""
    out, seen = {}, {}
    for tid, g in current.items():
        if tid not in verdict:
            continue
        why = verdict[tid]
        if not why:
            out[tid] = g
            continue
        try:
            key = (id(g), why)
            got = seen.get(key)
        except TypeError:  # unhashable verdict
            out[tid] = downgrade(g, *why)
            continue
        if got is None:
            got = seen[key] = (downgrade(g, *why), g)
        out[tid] = got[0]
    return out


def _without(reached, source_id):
    """A memoized reach for one source: drop the source itself (AllOf excludes it when the graph is built)."""
    if not reached or isinstance(reached, AllOf) or source_id not in reached:
        return reached
    return {tid: g for tid, g in reached.items() if tid != source_id} or None
