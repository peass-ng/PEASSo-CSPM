#!/usr/bin/env python3
"""Build CSPM artifacts and apply only a coordinator-reviewed, dedicated plan."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import zipfile

# Direct script execution must use this checkout, including its build helpers.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from peaso import deployment

try:
    import peaso_deploy_current_update as current_update
except ModuleNotFoundError:
    from scripts import peaso_deploy_current_update as current_update
try:
    import peaso_deploy_successor_update as successor_update
except ModuleNotFoundError:
    from scripts import peaso_deploy_successor_update as successor_update
try:
    import peaso_deploy_artifact_update as artifact_update
except ModuleNotFoundError:
    from scripts import peaso_deploy_artifact_update as artifact_update

INFRA = ROOT / "infra" / "aws"
BUILD = INFRA / "build"
TF = os.environ.get("PEASO_TERRAFORM", "terraform")
ACCOUNT = deployment.value("account_id")
REPOSITORY = f"{ACCOUNT}.dkr.ecr.us-east-1.amazonaws.com/hacktricks-cspm-worker"
ZERO_IMAGE = REPOSITORY + "@sha256:" + "0" * 64
CUSTOMER_ROLE_DOWNLOAD_KEY = "aws/customer-role.json"
API_PACKAGE_PREFIX = "runtime-packages/"
WORKER_SIZING_CURRENT_SHA256 = '40e2987f2bad20d53f9e8898225fbaf4abcf9f3a009fb472e3f2c34702fe5ca6'
# The 4 vCPU collector / 1 vCPU analyzer successor reverses first, then the 2 vCPU extension.
WORKER_SIZING_REVERSE = ((b'    collector = { cpu = 4096, memory = 16384 }\n    analyzer  = { cpu = 1024, memory = 8192 }', b'    collector = { cpu = 1024, memory = 6144 }\n    analyzer  = { cpu = 512, memory = 4096 }'), (b'  description = "Prospective Linux/x86 Fargate CPU units and MiB: collector 4 vCPU/16 GiB, analyzer 1 vCPU/8 GiB. A 1 vCPU collector was CPU-bound on offline content detection and AWS TLS reads; four content lanes need four vCPUs. Not an all-estates capacity guarantee."', b'  description = "Prospective Linux/x86 Fargate CPU units and MiB: collector 1 vCPU/6 GiB, analyzer 0.5 vCPU/4 GiB. Reported split peaks support these starting sizes, not an all-estates capacity guarantee."'), (b' resource.memory % 1024 == 0) ||\n      (resource.cpu == 4096 && resource.memory >= 8192 && resource.memory <= 30720 && resource.memory % 1024 == 0)\n', b' resource.memory % 1024 == 0)\n'), (b'supported 0.5/1/2/4 vCPU Fargate sizes', b'supported 0.5/1/2 vCPU Fargate sizes'), (b'(resource.cpu == 1024 && contains([2048, 3072, 4096, 5120, 6144, 7168, 8192], resource.memory)) ||\n      (resource.cpu == 2048 && resource.memory >= 4096 && resource.memory <= 16384 && resource.memory % 1024 == 0)', b'(resource.cpu == 1024 && contains([2048, 3072, 4096, 5120, 6144, 7168, 8192], resource.memory))'), (b'supported 0.5/1/2 vCPU Fargate sizes', b'supported 0.5/1 vCPU Fargate sizes'))
# Immutable data consumed by the source-bound native registry at import time.
RUNTIME_ADMISSION_INPUTS = {
    "tests/fixtures/azure_nsp_query_cmk_metadata_proposal_20261020.json.gz":
        "a478816f3f9d0a6a732d1ff80b61cd80779e01e36172bda3a36f4fac16417fac",
    "tests/fixtures/azure_nsp_query_cmk_runtime_native_20261020.json.gz":
        "2d7c24828dbc5d22de6a68c96668e87db1c9fdaec01419eaf5b25219b5ef50a5",
    "tests/fixtures/azure_nsp_query_cmk_production_native_20261020.json.gz":
        "be06f6b6fc2ebe96a8c9da2138eaaea941e9a2e266432e45a9e253bc24f2558a",
    "tests/fixtures/azure_sql_tde_parent_identity_predecessor_20261020.json.gz":
        "ea4125608adcffd7ef148a40620dd1130afab7fb4ff27e5d08a6215834ef6af7",
}
# Exact public inputs needed to reproduce the shipped compiler, provenance and
# tests. Explicit paths/globs only: no .work drafts, caches or private files.
REPRODUCTION_INPUT_PATTERNS = (
    'tests/test_azure_refresh_capture_closure_20261025.py',
    'tests/test_ai_collection_coverage.py',
    'tests/test_aws_worker_metrics_integration.py',
    'tests/test_annotation_engine_plan_successor.py',
    'tests/test_runtime_metrics_portable.py',
    'tests/test_detector_call_metrics.py',
    'tests/test_rawv2_package512_bootstrap_20261025.py',
    'tests/test_snapshot_public_identity.py',
    'tests/test_k8s_clock_checkpoint_scope_20261025.py',
    'tests/test_peaso_trivy_database_diagnostics.py',
    'tests/test_peaso_trivy_database_source_admission.py',
    'tests/test_ai_secret_positive_conservation_20261025.py',
    'tests/fixtures/ai-secret-positive-redacted.json',
    'tests/test_azure_acr_prepared_batch_20261025.py',
    'tests/test_reconcile_related_snapshots_20261025.py',
    'tests/test_api_secret_positive_conservation_20261025.py',
    'tests/test_completed_section_refresh_20261025.py',
    'tests/test_automatic_content_capabilities.py',
    'tests/test_aws_call_metrics.py',
    'tests/test_peaso_publication_runtime_metrics.py',

    'tests/test_markdown_json_fastpath.py',
    'tests/test_content_explicit_bulk_planner.py',
    'tests/test_content_scan_stage_api.py',
    'tests/test_content_scan_stage_closure.py',
    'tests/test_content_scan_stage_contract.py',

    'tests/test_gcp_explicit_multiproject_images.py',
    'tests/test_secret_scanning_batch_metrics.py',
    'tests/test_federation_identity_conflicts.py',
    'tests/test_selected_image_contradictory_cves.py',
    'tests/test_native_pod_cve_positive_pipeline.py',
    'tests/test_checkpoint_copy_privacy.py',
    'tests/test_analyzer_disabled_publication.py',
    'tests/test_bulk_evidence_single_copy.py',
    'tests/test_iam_early_overlap.py',
    'tests/test_worker_native_iam_expiry.py',
    'tests/test_snapshot_builder_single_validation.py',
    'tests/test_publication_inventory_single_pass.py',
    'docs/native-publication-performance.md',
    'tests/test_missing_control_evidence_boundaries.py',
    'tests/test_secret_batch_tmpfs_capacity.py',
    'docs/secret-batch-capacity-and-native-qualification.md',
    'tests/test_current_generic_native_witnesses_20261024.py',
    'tests/fixtures/azure_current_generic_native_witnesses_20261024.json.gz',
    'tests/test_iam_policy_free_native_records.py',
    'docs/iam-policy-free-inventory-performance.md',
    'docs/registry-image-evidence-review-20261024.md',
    'tests/test_azure_acr_frozen_engine_20261024.py',
    'tests/test_gcp_image_stream_redirect_20261024.py',
    'tests/test_iam_usage_extensions.py',
    'tests/test_report_artifact_batch_reuse.py',
    'tests/test_gcp_discoveryengine_collection_projection.py',
    'docs/api-lambda-s3-delivery.md',
    'examples/benchmark_peaso_final_collector_release.py',
    'examples/benchmark_peaso_checkpoint_copy.py',
    'docs/multicloud-worker-sizing.md',
    'tests/test_k8s_literal_scanner_deadline_successor_20261023.py',
    'tests/test_k8s_calico_alias_current_20261023.py',
    'tests/test_k8s_blob_redirect_current_20261023.py',
    'docs/api-sdk-source-review-20261023.json',
    'tests/test_peaso_k8s_access_transport.py',
    'tests/test_k8s_image_source_association_current_20261023.py',
    'docs/gcp-iam-pagination-source-review-20261023.json',
    'scripts/benchmark_engine_finding_materialization.py',
    'scripts/benchmark_engine_sw46_joins.py',
    'examples/benchmark_peaso_network_facts.py',
    'examples/benchmark_peaso_network_node_ids.py',
    'examples/benchmark_peaso_network_workflows.py',
    'examples/reference_peaso_network_node_ids.py',
    'tests/test_content_cohort_source_admission_20261023.py',
    'examples/benchmark_peaso_ecr_layer_pipeline.py',
    'scripts/replay_native_lambda_cohort.py',
    'scripts/peaso_api_service_model_sources.json',
    'docs/api-sdk-model-prune.md',
    'scripts/peaso_api_service_model_gate.py',
    'scripts/peaso_api_service_model_sources.json',
    'tests/test_peaso_api_service_model_gate.py',
    'tests/test_peaso_api_credential_models.py',
    'docs/api-sdk-model-prune.md',
    'tests/test_automatic_environment_33_scope_candidate.py',
    'tests/test_peaso_gcp_scoped_resume_candidate.py',
    'tests/test_private_shared_finite_batch_20261023.py',
    'tests/test_peaso_k8s_evidence_explanations_current_20261023.py',
    'scripts/verify_workload_environment_discovery_candidate.py',
    'scripts/verify_automatic_batch_consumer_candidate.py',
    'docs/scan-execution.md',
    'tests/test_ai_selected_stages.py',
    'tests/test_aws_ecs_configuration_literals.py',
    'tests/test_batch_content_reuse.py',
    'examples/benchmark_peaso_batch_content_reuse.py',
    'docs/secret-scanning.md',
    'tests/test_ecr_clean_digest_failure.py',
    'tests/test_ecr_layer_resume.py',
    'tests/test_gcp_log_page_batch.py',
    'tests/test_log_page_batch.py',
    'tests/test_scan_section_single_pass.py',
    'examples/benchmark_peaso_ecr_resume.py',
    'examples/benchmark_peaso_gcp_log_page_batch.py',
    'examples/benchmark_peaso_log_page_batch.py',
    'examples/benchmark_peaso_section_readiness.py',
    'tests/test_api_privesc_display_20261022.py',
    'tests/test_aws*.py',
    'work_aws_privesc_review/*.md',
    'work_aws_privesc_review/*.tsv',
    'work_aws_privesc_review/*.py',
    'tests/test_progressive_owned_tasks.py',
    'examples/benchmark_peaso_checkpoint_cadence.py',
    'examples/benchmark_peaso_progressive_poll.py',
    'examples/benchmark_peaso_publication_reuse.py',
    'examples/benchmark_peaso_redaction.py',
    'tests/test_aws_index_result_reuse_20261022.py',
    'tests/test_document_redaction_performance.py',
    'tests/test_incremental_report_cadence.py',
    'tests/test_incremental_scope_plan_20261022.py',
    'tests/test_progressive_poll_cost.py',
    'tests/test_report_artifact_reuse.py',
    'tests/connector_access_receipts.py',
    'scripts/pytest_shard.py',
    'docs/ci-runtime-optimization-20261022.md',
    'tests/test_combined_catalog_history_successor_20261022.py',
    'tests/fixtures/combined_iam_network_provider_catalog_successor_20261022.json.gz',
    'tests/test_attack_detection_aws_devicefarm_batch140.py',
    'tests/test_attack_detection_aws_devicefarm_sessions_batch141.py',
    'tests/test_attack_detection_aws_keyspaces_data_batch143.py',
    'tests/test_attack_detection_aws_keyspaces_management_batch142.py',
    'tests/test_attack_detection_aws_lex_analytics_batch135.py',
    'tests/test_attack_detection_aws_lex_hook_batch137.py',
    'tests/test_attack_detection_aws_lex_hook_batch138.py',
    'tests/test_attack_detection_aws_lex_runtime_batch136.py',
    'tests/test_attack_detection_aws_lex_testset_batch136.py',
    'tests/test_attack_detection_aws_license_ami_batch132.py',
    'tests/test_attack_detection_aws_license_hardlimit_batch133.py',
    'tests/test_attack_detection_aws_license_instance_batch134.py',
    'tests/test_attack_detection_aws_route53_profiles_batch139.py',
    'tests/fixtures/shared_metadata_catalog_3496_20261020.json.gz',
    'tests/fixtures/shared_metadata_catalog_3496_20261020.provenance.json',
    'tests/test_snapshot_resource_identity_finite_source.py',
    'tests/test_compliance_reviewed_native_aliases.py',
    'tests/test_release_history_alias_projection.py',
    'tests/test_unused_iam_network_cli_json.py',
    'tests/test_private_receipt_fast_path_20261021.py',
    'tests/test_peaso_batch_remaining_admission.py',
    'tests/test_unused_iam_access_analyzer_hardening.py',
    'tests/test_unused_network_aws_target_group.py',
    'tests/test_unused_network_gcp_native_completion.py',
    'tests/test_unused_network_azure_completion.py',
    'tests/test_unused_network_public_ip_native.py',
    'docs/network-unused/*',
    'docs/network-audit/*',
    'tests/test_unused_network_aws.py',
    'tests/test_unused_network_gcp.py',
    'tests/test_unused_network_providers_20261021.py',
    'docs/unused-network/*',
    'tests/test_unused_iam_aws_federation_consumers.py',
    'tests/test_unused_iam_azure_user_completion.py',
    'tests/test_unused_iam_aws_completion.py',
    'tests/test_unused_iam_azure_completion.py',
    'tests/test_unused_iam_provider_completion_20261021.py',
    'tests/test_unused_iam_gcp.py',
    'tests/test_unused_iam_gcp_authorization.py',
    'tests/test_unused_iam_gcp_directory.py',
    'tests/test_unused_iam_gcp_keys.py',
    'tests/test_unused_iam_gcp_roles.py',
    'tests/test_unused_iam_aws_activity.py',
    'tests/test_unused_iam_aws_inline.py',
    'tests/test_unused_iam_azure.py',
    'tests/test_unused_iam_azure_roles.py',
    'tests/test_unused_iam_azure_arm_roles.py',
    'tests/test_unused_iam_coverage_audit.py',
    'tests/test_iam_usage_evidence.py',
    'tests/test_unused_iam_k8s.py',
    'scripts/audit_unused_iam_coverage.py',
    'docs/iam-unused/*',
    'tests/test_azure_acr_partial_positive_20261021.py',
    'tests/test_peaso_finding_priority.py',
    'tests/test_peaso_checks_k8s_ports_components.py',
    'tests/fixtures/aws_codeartifact_npm_batch80_events.json',
    'tests/fixtures/aws_sfn_role_routes_batch85_events.json',
    'tests/fixtures/aws_sns_public_policy_batch83_events.json',
    'tests/fixtures/aws_sns_service_scope_batch84_events.json',
    'tests/fixtures/aws_sns_subscription_batch81_events.json',
    'tests/fixtures/aws_sqs_public_policy_batch82_events.json',
    'docs/exposure-candidate-decisions.json',
    'docs/exposure-check-dedup-audit.md',
    'docs/exposure-check-inventory.json',
    'tests/test_exposed_privileged_workload.py',
    'docs/aws-selected-image-vulnerabilities.md',
    'docs/container-practical-images-20261021.md',
    'docs/azure-acr-image-vulnerabilities-registration-20261021.json',
    'docs/compliance-ledgers/native-extensions/provider-images-runtime-20261021.json',
    'docs/compliance-ledgers/native-extensions/provider-content-images-followup-20261021.json',
    'docs/compliance-ledgers/native-extensions/provider-final-selected-content-20261021.json',
    # Exact provider review records and regression fixtures for this integration.
    'tests/test_provider_content_native_cases_20261021.py',
    'docs/aws-build-deployment-referenced-source-setup.md',
    'docs/aws-ecs-selected-environment-file-setup.md',
    'docs/aws-selected-ecr-public-images.md',
    'docs/aws-workload-referenced-source-setup.md',
    'docs/azure-aks-selected-image-setup.md',
    'docs/azure-flex-configured-deployment-archives-setup.md',
    'docs/azure-ml-job-variants-setup.md',
    'docs/azure-review/source-recheck-20261021.jsonl',
    'docs/azure-selected-image-slot-setup-20261021.md',
    'docs/collectors/aws-user-data-content.md',
    'docs/collectors/k8s-selected-content-20261021.md',
    'docs/gcp-portable-test-setup.md',
    'docs/gcp-review/source-recheck-20261021.jsonl',
    'docs/gcp_developerconnect_selected_file_setup.md',
    'docs/gcp_workerpool_selected_image_setup.md',
    'docs/k8s-review/source-recheck-20261021.jsonl',
    'docs/peaso-azure-databricks-notebook-secrets.md',
    'docs/peaso-azure-selected-ml-assets-secrets.md',
    'docs/peaso-azure-synapse-notebook-secrets.md',
    'docs/peaso-gcp-selected-dataproc-sources.md',
    'docs/provider-content-review-20261021.md',
    'docs/provider-source-corrections-20261021.json',
    'docs/provider-source-review-20261021.md',
    'docs/provider-upstream-review-20261021.json',
    'docs/selected-image-content-coverage-20261021.md',
    'tests/fixtures/aws_sagemaker_training_native_20261021.json',
    'tests/fixtures/aws_workload_image_secret_native_20261021.json',
    'tests/fixtures/azure_flex_archive_native_extended_20261021.json',
    'tests/fixtures/azure_ml_job_code_native_20261021.json',
    'tests/gcp_cloudrun_portable_fixtures.py',
    'tests/test_acr_index_functional.py',
    'tests/test_attack_detection_dynamic_catalog.py',
    'tests/test_attack_detection_raw_cloudtrail_catalog.py',
    'tests/test_attack_detection_lambda_public_layer.py',
    'tests/test_current_azure_proposal_proof_20261022.py',
    'tests/test_gcp_k8s_current_evidence_cohort_20261022.py',
    'tests/fixtures/evidence_static_privesc_successor_20261022.json.gz',
    'tests/fixtures/current_privesc_catalog_successor_20261022.json.gz',
    'tests/test_peaso_privesc_current_runtime_binding.py',
    'tests/current_runtime_admission_inputs_20261022.py',
    'tests/retired_privesc_catalog_20261022.py',
    'tests/fixtures/aws_retired_sns_perimeter_source_20261022.py.txt',
    'tests/test_aws_batch_selected_variants_20261021.py',
    'tests/test_aws_build_deployment_referenced_source_20261021.py',
    'tests/test_aws_ecs_environment_file_native_20261021.py',
    'tests/test_aws_reference_api_preflight_20261021.py',
    'tests/test_aws_reference_partial_positive_20261021.py',
    'tests/test_aws_reference_private_source_association_20261021.py',
    'tests/test_aws_selected_templates_pipelines_20261021.py',
    'tests/test_aws_user_data_payload_20261021.py',
    'tests/test_aws_user_data_payload_native_20261021.py',
    'tests/test_aws_workload_image_binding_20261021.py',
    'tests/test_aws_workload_image_private_binding_20261021.py',
    'tests/test_aws_workload_image_secret_dedup_20261021.py',
    'tests/test_azure_acr_image_vulnerabilities_20261021.py',
    'tests/test_azure_acr_server_selection_20261021.py',
    'tests/test_azure_acr_streaming_20261021.py',
    'tests/test_azure_activity_alert_coverage_20261021.py',
    'tests/test_azure_aks_image_api_preflight_20261021.py',
    'tests/test_azure_databricks_selected_file_20261021.py',
    'tests/test_azure_databricks_selected_task_output_20261021.py',
    'tests/test_azure_flex_configured_archives.py',
    'tests/test_azure_flex_private_source_layer_20261021.py',
    'tests/test_azure_function_package_slots_20261021.py',
    'tests/test_azure_ml_environment_dockerfile_20261021.py',
    'tests/test_azure_ml_job_code_binding_20261021.py',
    'tests/test_azure_ml_job_variants_20261021.py',
    'tests/test_azure_selected_aks_image_20261021.py',
    'tests/test_azure_selected_private_source_association_20261021.py',
    'tests/test_azure_synapse_selected_notebook_20261021.py',
    'tests/test_cli_selected_content_routing_20261021.py',
    'tests/test_codebuild_codecommit_source.py',
    'tests/test_content_api_preflight_20261021.py',
    'tests/test_ecr_public_image.py',
    'tests/test_gcp_appengine_flex_image_native_20261021.py',
    'tests/test_gcp_cloudbuild_logging_portable.py',
    'tests/test_gcp_dataflow_jvm_constants_20261021.py',
    'tests/test_gcp_dataproc_dependency_archives_native_20261021.py',
    'tests/test_gcp_dataproc_dependency_selected_20261021.py',
    'tests/test_gcp_dataset_firewall_native_semantics_20261021.py',
    'tests/test_gcp_developerconnect_native_content_20261021.py',
    'tests/test_gcp_gke_network_native_semantics_20261021.py',
    'tests/test_gcp_image_decoded_config_native_20261021.py',
    'tests/test_gcp_image_stream_inspection.py',
    'tests/test_gcp_image_stream_reader.py',
    'tests/test_gcp_image_stream_real_detectors.py',
    'tests/test_gcp_job_trivy_stream.py',
    'tests/test_gcp_job_trivy_stream_real_cli.py',
    'tests/test_gcp_registry_cve_index_functional_20261021.py',
    'tests/test_gcp_registry_trivy_portable.py',
    'tests/test_gcp_sdk_authorization_headers_20261025.py',
    'tests/test_gcp_selected_private_source_association_20261021.py',
    'tests/test_gcp_image_scan_batch_20261024.py',
    'tests/test_gcp_stream_file_continuation_20261021.py',
    'tests/test_gcp_stream_index_functional_20261021.py',
    'tests/test_gcp_workerpool_native_content_20261021.py',
    'tests/test_k8s_component_partial_rate_native_20261021.py',
    'tests/test_k8s_configmap_association_portable.py',
    'tests/test_k8s_content_terminal_cancellation_20261021.py',
    'tests/test_k8s_flux_artifact.py',
    'tests/test_k8s_literal_fields_portable.py',
    'tests/test_k8s_pinned_reference_native_20261021.py',
    'tests/test_k8s_registry_consumer_boundaries_20261021.py',
    'tests/test_k8s_registry_image.py',
    'tests/test_k8s_gar_blob_redirect_20261025.py',
    'tests/test_k8s_selected_image_batch_20261024.py',
    'tests/test_k8s_seccomp_ephemeral_native_20261021.py',
    'tests/test_k8s_selected_artifact_redaction_20261021.py',
    'tests/test_k8s_selected_text_content_portable.py',
    'tests/test_multicontainer_declared_images.py',
    'tests/test_multicontainer_source_proof.py',
    'tests/test_oci_index_ecr_public.py',
    'tests/test_oci_index_resolver.py',
    'tests/test_peaso_checks_claude_azure_network.py',
    'tests/test_pod_oci_index_20261021.py',
    'tests/test_private_ecr_index.py',
    'tests/test_private_ecr_selection_final.py',
    'tests/test_sagemaker_training_script_source.py',
    'tests/test_selected_codecommit_api_routing_20261021.py',
    'tests/test_selected_image_api_routing_20261021.py',
    'tests/test_selected_image_database.py',
    'tests/test_selected_image_observations_20261021.py',
    'tests/test_selected_image_partial_file_coverage_20261021.py',
    'tests/test_access_analyzer_unused_hardening.py',
    'tests/test_peaso_least_privilege.py',
    'tests/test_peaso_aws_access_analyzer_lifecycle.py',
    'tests/test_peaso_finding_group_api.py',
    'tests/test_peaso_detected_leaks_filter.py',
    'tests/test_worker_progress_20261022.py',
    'tests/test_peaso_image_scan_throughput_20261022.py',
    'tests/test_peaso_scan_queue.py',
    'tests/test_incremental_checkpoint.py',
    'tests/test_incremental_storage_20261022.py',
    'tests/test_incremental_parallel_20261022.py',
    'tests/test_incremental_ready_reads_20261022.py',
    'tests/test_scan_section_batches_20261022.py',
    'tests/test_progressive_analyzer_20261022.py',
    'tests/test_ai_section_concurrency_20261022.py',
    'tests/test_private_receipt_compaction_20261022.py',
    'tests/test_operator_scan_quota.py',
    'tests/test_partial_evaluation_scheduling_20261022.py',
    'tests/test_secret_scanning_performance.py',
    'tests/test_secret_batch_capacity_128.py',
    'tests/test_aws_image_capture_20261022.py',
    'tests/test_aws_image_capture_store_20261022.py',
    'tests/test_least_privilege_permissions.py',
    'tests/provider_group_catalog_history_20261021.py',
    'tests/fixtures/provider_group_catalog_history_20261021.json.gz',
    'tests/fixtures/aws_image_vulnerability_native_cases_20261021.json',
    'tests/fixtures/trivy/trivy-0.68.1-manifest.json',
    'tests/gcp_job_image_vulnerability_fixture_20261021.py',
    'tests/test_aws_image_vulnerability_runtime_20261021.py',
    'tests/test_azure_app_runtime_pipeline_20261021.py',
    'tests/test_container_practical_archive_20261021.py',
    'tests/test_ecr_secret_streaming_20261021.py',
    'tests/test_peaso_secret_scanning_batch.py',
    'tests/test_aws_package_content_batch_20261022.py',
    'tests/test_gcp_job_image_vulnerability_lifecycle_20261021.py',
    'tests/test_gcp_job_image_vulnerability_product_20261021.py',
    'tests/test_peaso_cloudrun_selector_static_20261021.py',
    'tests/test_peaso_full_scope_content_selection_20261021.py',
    'tests/test_peaso_image_api_app_20261021.py',
    'tests/test_peaso_image_options_api_20261021.py',
    'tests/test_peaso_image_report_publisher_20261021.py',
    'tests/test_peaso_image_routes_20261021.py',
    'tests/test_peaso_image_storage_20261021.py',
    'tests/test_peaso_provider_followup_observations_20261021.py',
    'tests/test_peaso_trivy_database_lease_20261021.py',
    'tests/test_peaso_trivy_download_monitor_20261021.py',
    'tests/test_peaso_trivy_packaging_20261021.py',
    'tests/test_provider_group_fixture_closure_20261021.py',
    'tests/test_provider_group_finite_source_epoch_20261021.py',
    'tests/test_peaso_reference_titles.py',
    'tests/fixtures/remediation_reference_title_overlay.json',
    'tests/test_ai_device_flow_and_policy.py',
    'tests/test_peaso_image_findings_20261021.py',
    'tests/test_private_source_unrelated_leaf_freshness_20261021.py',
    'tests/test_private_source_cpu_margin_20261021.py',
    'tests/test_private_secret_evidence.py',
    'tests/test_private_secret_evidence_integration.py',
    'tests/test_gcp_current_function_validator_20261021.py',
    'tests/test_aws_sg_any_port_criteria_20261021.py',
    'tests/test_api_evidence_source_generation_20261021.py',
    'tests/test_api_finding_groups_static_20261021.py',
    'tests/test_rawv2_native_startup_margin_20261021.py',
    'tests/fixtures/gcp_native_cpu_margin_pre_rawv2_20261021.json.gz',
    'tests/test_rawv2_public_redaction.py',
    'tests/test_rawv2_public_source_successor_20261021.py',
    'tests/test_rawv2_public_source_runtime_20261021.py',
    'tests/test_gcp_native_cpu_margin_artifacts_20261021.py',
    'tests/gcp_native_cpu_margin_epoch_20261021.py',
    'tests/fixtures/gcp_native_cpu_margin_predecessor_20261021.json.gz',
    'tests/test_azure_defender_unassessed_status_20261020.py',
    'docs/check-review/azure-defender-assessment-four-current-binding-20261021.json',
    'tests/test_gcp_positive_native_cpu_cache_20261020.py',
    'tests/fixtures/gcp_positive_native_cpu_predecessor_20261020.json.gz',
    'tests/gcp_positive_conservation_epoch_20261020.py',
    'tests/fixtures/gcp_positive_conservation_predecessors_20261020.json.gz',
    'tests/fixtures/aws_chime_batch64_events.json',
    'tests/fixtures/aws_chime_batch65_events.json',
    'tests/fixtures/aws_chime_insights_batch69_events.json',
    'tests/fixtures/aws_chime_media_batch68_events.json',
    'tests/fixtures/aws_chime_voice_batch66_events.json',
    'tests/fixtures/aws_chime_voice_sip_batch67_events.json',
    'tests/fixtures/aws_codeartifact_batch79_events.json',
    'tests/fixtures/aws_cognito_directory_batch77_events.json',
    'tests/fixtures/aws_cognito_m2m_batch78_events.json',
    'tests/fixtures/aws_dynamodb_backup_stream_batch75_events.json',
    'tests/fixtures/aws_kvs_channel_ttl_batch71_event.json',
    'tests/fixtures/aws_kvs_endpoint_batch70_events.json',
    'tests/fixtures/aws_kvs_fragment_media_batch73_event.json',
    'tests/fixtures/aws_kvs_more_endpoints_batch72_events.json',
    'tests/fixtures/aws_s3_access_point_lock_batch63_events.json',
    'tests/fixtures/aws_s3_acl_grants_batch62_events.json',
    'tests/composer_task_positive_helper.py',
    'tests/image_positive_helper.py',
    'tests/portable_fixture.py',
    'tests/test_gcp_artifact_archive_partial_positive_portable.py',
    'tests/test_gcp_composer_task_partial_positive_portable.py',
    'tests/test_gcp_image_partial_positive_portable.py',
    'tests/test_gcp_sourcerepo_partial_positive_portable.py',
    'tests/test_api_native_free_finding_detail_20261020.py',
    'tests/test_api_remediation_presentation_static_20261020.py',
    'tests/test_api_evidence_static_20261020.py',
    'tests/fixtures/evidence_static_parity_all_20261020.jsonl.gz',
    'tests/fixtures/evidence_static_skipped_20261020.json',

    "tests/test_api_service_labels_static_20261020.py",
    "tests/test_azure_metadata_only_admission_successor_20261020.py",
    "tests/case_state_contract_20261020.py",
    "tests/test_case_state_contract_20261020.py",
    "tests/test_collector_noop_authorization_successor_20261020.py",
    'tests/aws_k8s_current_native_inputs_20261020.py',
    'tests/fixtures/aws_k8s_residual_test_predecessors_20261020.json.gz',
    'tests/fixtures/aws_s3_historical_policy_before_20261020.json.gz',
    'tests/fixtures/gcp-wave2-admitted-selectors-20261020.json',
    'tests/fixtures/gcp-wave2-final-services-history-20261020/before-compliance_new_sw52.py',
    'tests/fixtures/gcp-wave2-final-services-history-20261020/before-native_only.json',
    'tests/fixtures/gcp-wave2-final-services-history-20261020/predecessor-hashes.json',
    'tests/fixtures/gcp-wave2-proposal-boundary-predecessor-20261020.py.gz',
    'tests/fixtures/gcp-wave2-test-predecessors-20261020.json.gz',
    'tests/fixtures/shared_admission_original_tests_20261020.json.gz',
    'tests/gcp_wave2_historical_native_20261020.py',
    'tests/shared_admission_epoch_compatibility_20261020.py',
    'tests/test_aws_k8s_current_native_inputs_20261020.py',
    'tests/test_gcp_wave2_native_successor_20261020.py',
    'tests/test_peaso_checks_claude_gcp_k8s_behavior.py',
    'tests/test_peaso_checks_gcp_ports_services.py',
    'tests/test_peaso_collector_swc2_gcp_core.py',
    'tests/test_peaso_collector_swc_gcp_wave.py',
    'tests/test_peaso_gcp_project_alias_pipeline.py',
    'tests/test_shared_admission_epoch_compatibility_20261020.py',
    "tests/azure_windows_scope_history_20261020.py",
    "tests/fixtures/azure-windows-scope-predecessor-20261020.json",
    'tests/fixtures/gcp-final-residual-predecessors-20261020.json.gz',
    'tests/fixtures/gcp-final-residual-source-closure-20261020.json',
    'tests/test_gcp_final_residual_source_closure_20261020.py',
    'tests/test_peaso_gcp_observation_source_parity.py',
    "tests/retained_upstream_manifest_20261020.py",
    "tests/fixtures/native_admission_upstream_predecessor_20261020.json.gz",
    "tests/test_provider_combined_source_bridge_20261020.py",
    "tests/test_azure_admitted_alias_draft_isolation_20261020.py",
    "tests/test_peaso_network_ai_purpose.py",
    "tests/fixtures/provider_combined_bridge_baseline_20261020.json.gz",
    "tests/test_provider_bridge_compiler_portability_20261020.py",
    "tests/test_provider_bridge_prepared_ast_portability_20261020.py",
    "tests/gcp_clarity_combined_successor_20261020.py",
    "tests/azure_native_inventory_routes_20261020.py",
    "tests/fixtures/azure_archived_aks_scope_predecessor_20261020.json.gz",
    "tests/test_azure_jit_parent_type_successor_20261020.py",
    "tests/provider_observation_residual_successors_20261020.py",
    "tests/aws_late_native_contracts_20261020.py",
    "tests/test_peaso_api_materialized_catalog_20261020.py",
    "scripts/peaso_api_catalog_cold_probe_20261020.py",
    "docs/peaso-api-materialized-catalog-20261020.md",
    "tests/generic_k8s_behavior_successors_20261020.py",
    # Frozen provider/network review inputs and portable reproduction fixtures.
    'docs/aws-codebuild-buildspec-source-setup-20261020.md',
    'docs/aws-review/current-roster-reconciliation-20261020.json',
    'docs/aws-selected-s3-source-secret-permissions-20261020.md',
    'docs/aws-selected-s3-source-setup-20261020.md',
    'docs/aws-workload-command-source-setup-20261020.md',
    'docs/azure-apim-operation-window-research-permissions-20261020.md',
    'docs/azure-devops-selected-content-secret-permissions.md',
    'docs/azure-function-settings-declaration-permissions-20261020.md',
    'docs/check-review/README.md',
    'docs/check-review/aws-codebuild-buildspec-primary-contract-20261020.json.gz',
    'docs/check-review/aws-codebuild-buildspec-runtime-integration-20261020.json',
    'docs/check-review/aws-codebuild-buildspec-runtime-node-logs-20261020.json.gz',
    'docs/check-review/aws-codebuild-buildspec-runtime-public-native-20261020.json',
    'docs/check-review/aws-codebuild-buildspec-runtime-setup-20261020.md',
    'docs/check-review/aws-codebuild-buildspec-source-20261020.json',
    'docs/check-review/aws-codebuild-current-acceptance-20261020.json',
    'docs/check-review/aws-codebuild-historical-current-admission-20261020.json',
    'docs/check-review/aws-codebuild-inline-observation-acceptance-20261020.json',
    'docs/check-review/aws-codebuild-master-admission-20261020.json',
    'docs/check-review/aws-codebuild-package-root-gates-20261020.json.gz',
    'docs/check-review/aws-codecommit-path-redaction-fix-20261020.json',
    'docs/check-review/aws-lambda-environment-secret-implementation-20261020.json',
    'docs/check-review/aws-pr33-local-preservation-20261020.json',
    'docs/check-review/aws-s3-current-acceptance-20261020.json',
    'docs/check-review/aws-s3-selected-source-integration-20261020.json',
    'docs/check-review/aws-s3-selected-source-secret-review-20261020.json',
    'docs/check-review/aws-selected-configuration-integration-acceptance-20261020.json',
    'docs/check-review/aws-selected-configuration-secret-implementation-20261020.json',
    'docs/check-review/aws-userdata-lambda-real-followup-20261020.json',
    'docs/check-review/aws-workload-command-brief-acceptance-20261020.json',
    'docs/check-review/aws-workload-command-runtime-20261020.json',
    'docs/check-review/aws-workload-command-source-20261020.json',
    'docs/check-review/aws-workload-commands-current-acceptance-20261020.json',
    'docs/check-review/aws-workload-commands-current-native-witnesses-20261020.json.gz',
    'docs/check-review/aws-workload-commands-master-pending-20261020.json',
    'docs/check-review/aws-workload-commands-primary-contract-20261020.json.gz',
    'docs/check-review/azure-acr-image-secret-implementation-20261020.json',
    'docs/check-review/azure-acr-public-ip-review-20261020.json',
    'docs/check-review/azure-activity-alert-native-review-20261020.json',
    'docs/check-review/azure-ai-five-tracking-reconciliation-20261020.json',
    'docs/check-review/azure-ai-services-source-review-20261020.json',
    'docs/check-review/azure-aks-hsm-final-native-review-20261020.json',
    'docs/check-review/azure-apim-operation-window-source-native-review-20261020.json',
    'docs/check-review/azure-app-settings-secret-implementation-20261020.json',
    'docs/check-review/azure-application-compute-1-native-review-20261020.json',
    'docs/check-review/azure-application-compute-2-native-review-20261020.json',
    'docs/check-review/azure-application-native-title-successors-20261020.json',
    'docs/check-review/azure-archived-legacy-fixture-closure-20261020.json',
    'docs/check-review/azure-automation-aci-metadata-review-20261020.json',
    'docs/check-review/azure-automation-aci-native-admission-20261020.json',
    'docs/check-review/azure-backup-source-successor-20261020.json',
    'docs/check-review/azure-compute-network-native-review-20261020.json',
    'docs/check-review/azure-configured-package-observation-root-proof-20261020.json',
    'docs/check-review/azure-current-attestation-nine-native-recheck-20261020.json',
    'docs/check-review/azure-current-integration-acceptance-20261020.json',
    'docs/check-review/azure-current-source-inventory-20261020.json',
    'docs/check-review/azure-database-crypto-backup-1-native-review-20261020.json',
    'docs/check-review/azure-database-crypto-backup-2-native-review-20261020.json',
    'docs/check-review/azure-databricks-notebook-proposed-tests-20261020.py.gz',
    'docs/check-review/azure-databricks-notebook-secret-implementation-20261020.json',
    'docs/check-review/azure-databricks-notebook-secret-integration-20261020.json',
    'docs/check-review/azure-declaration-current-acceptance-20261020.json',
    'docs/check-review/azure-declaration-secret-integration-20261020.json',
    'docs/check-review/azure-defender-pricing-native-review-20261020.json',
    'docs/check-review/azure-devops-selected-content-secret-review-20261020.json',
    'docs/check-review/azure-final-edge-native-closure-20261020.json',
    'docs/check-review/azure-final-services-integration-20261020.json',
    'docs/check-review/azure-four-cohort-integration-20261020.json',
    'docs/check-review/azure-function-package-final-acceptance-20261020.json',
    'docs/check-review/azure-function-package-final-ledger-20261020.json',
    'docs/check-review/azure-function-package-head3-current-acceptance-20261020.json',
    'docs/check-review/azure-function-package-head3-current-node-logs-20261020.json.gz',
    'docs/check-review/azure-function-package-integrated-public-native-20261020.json',
    'docs/check-review/azure-function-package-integrated-two-secret-native-20261020.json',
    'docs/check-review/azure-function-package-integration-acceptance-20261020.json',
    'docs/check-review/azure-function-package-integration-node-logs-20261020.json.gz',
    'docs/check-review/azure-function-package-integration-setup-20261020.md',
    'docs/check-review/azure-function-package-portable-proof-20261020.json',
    'docs/check-review/azure-function-package-portable-setup-20261020.md',
    'docs/check-review/azure-function-package-primary-contract-20261020.json.gz',
    'docs/check-review/azure-function-package-runtime-proof-20261020.json',
    'docs/check-review/azure-function-package-runtime-setup-20261020.md',
    'docs/check-review/azure-function-package-source-current-proof-20261020.json',
    'docs/check-review/azure-function-package-source-evidence-20261020.json',
    'docs/check-review/azure-function-package-source-review-20261020.md',
    'docs/check-review/azure-function-package-source-setup-20261020.md',
    'docs/check-review/azure-function-settings-current-native-captures-20261020.json.gz',
    'docs/check-review/azure-function-settings-declarations-native-review-20261020.json',
    'docs/check-review/azure-function-settings-pre-integration-20261020.json.gz',
    'docs/check-review/azure-function-settings-production-integration-20261020.json',
    'docs/check-review/azure-function-settings-production-proof-20261020.json.gz',
    'docs/check-review/azure-function-source-parity-successor-20261020.json',
    'docs/check-review/azure-function-transport-current-acceptance-20261020.json',
    'docs/check-review/azure-hsm-audit-review-20261020-proposal.json',
    'docs/check-review/azure-hsm-native-fixture-admission-20261020.json',
    'docs/check-review/azure-http-status-fixture-compatibility-review-20261020.json',
    'docs/check-review/azure-identity-enforcement-native-20261020.json',
    'docs/check-review/azure-identity-integration-20261020.json',
    'docs/check-review/azure-identity-native-review-20261020.json',
    'docs/check-review/azure-incomplete-native-evidence-followup-20261020.json',
    'docs/check-review/azure-k8s-archived-selection-review-20261020.json',
    'docs/check-review/azure-k8s-current-predicate-bindings-20261020.json',
    'docs/check-review/azure-log-sample-secret-integration-20261020.json',
    'docs/check-review/azure-mariadb-hpc-retirement-20261020.json',
    'docs/check-review/azure-master-predicate-attestation-errata-20261020.json',
    'docs/check-review/azure-metadata-transport-fix-review-20261020.json',
    'docs/check-review/azure-metadata-transport-inherited-risk-20261020.json',
    'docs/check-review/azure-metadata-transport-source-successor-20261020.json',
    'docs/check-review/azure-ml-assets-current-acceptance-20261020.json',
    'docs/check-review/azure-ml-command-job-proposed-tests-20261020.py.gz',
    'docs/check-review/azure-ml-command-job-secret-integration-20261020.json',
    'docs/check-review/azure-ml-current-acceptance-20261020.json',
    'docs/check-review/azure-ml-databricks-secret-surface-audit-20261020.json',
    'docs/check-review/azure-ml-databricks-secret-surface-audit-20261020.md',
    'docs/check-review/azure-ml-selected-asset-proposed-tests-20261020.py.gz',
    'docs/check-review/azure-ml-selected-asset-secret-implementation-20261020.json',
    'docs/check-review/azure-ml-selected-asset-secret-integration-20261020.json',
    'docs/check-review/azure-ml-selected-asset-secret-native-proof-20261020.json.gz',
    'docs/check-review/azure-ml-selected-asset-secret-production-proof-20261020.json.gz',
    'docs/check-review/azure-monitoring-native-review-20261020.json',
    'docs/check-review/azure-native-contract-closure-20261020.json',
    'docs/check-review/azure-native-source-path-reconciliation-20261020.json',
    'docs/check-review/azure-network-audit-admission-20261020.json',
    'docs/check-review/azure-network-database-guidance-successors-20261020.json',
    'docs/check-review/azure-network-native-integration-20261020.json',
    'docs/check-review/azure-network-platform-1-native-review-20261020.json',
    'docs/check-review/azure-nsp-query-cmk-metadata-admission-20261020.json',
    'docs/check-review/azure-nsp-query-cmk-metadata-admission-receipts-20261020.json.gz',
    'docs/check-review/azure-nsp-query-cmk-metadata-proposals-20261020.json',
    'docs/check-review/azure-nsp-query-cmk-metadata-receipts-20261020.json.gz',
    'docs/check-review/azure-nsp-query-cmk-metadata-setup-proposal-20261020.md',
    'docs/check-review/azure-nsp-query-cmk-production-predecessors-20261020.json.gz',
    'docs/check-review/azure-nsp-query-cmk-production-receipts-20261020.json.gz',
    'docs/check-review/azure-nsp-query-cmk-production-review-20261020.json',
    'docs/check-review/azure-nsp-query-cmk-production-source-successor-20261020.json.gz',
    'docs/check-review/azure-nsp-query-cmk-runtime-receipts-20261020.json.gz',
    'docs/check-review/azure-nsp-query-cmk-runtime-review-20261020.json',
    'docs/check-review/azure-nsp-query-cmk-setup-20261020.md',
    'docs/check-review/azure-nsp-query-current-acceptance-20261020.json',
    'docs/check-review/azure-nsp-tde-admission-test-compatibility-20261020.json',
    'docs/check-review/azure-package-master-admission-20261020.json',
    'docs/check-review/azure-package-master-finalization-20261020.json',
    'docs/check-review/azure-provider-integration-acceptance-20261020.json',
    'docs/check-review/azure-rejected-source-original-reason-errata-20261020.json',
    'docs/check-review/azure-rejected-source-recheck-20261020.json',
    'docs/check-review/azure-rejected-source-recheck-queue-20261020.json',
    'docs/check-review/azure-remaining-services-1-native-review-20261020.json',
    'docs/check-review/azure-remaining-services-2-native-review-20261020.json',
    'docs/check-review/azure-remaining-services-3-native-review-20261020.json',
    'docs/check-review/azure-review-queue-20261020.json',
    'docs/check-review/azure-root-custom-role-archive-20261020.json',
    'docs/check-review/azure-sas-expiry-policy-native-proposal-20261020.json',
    'docs/check-review/azure-selected-configuration-secret-implementation-20261020.json',
    'docs/check-review/azure-selected-declaration-secret-implementation-20261020.json',
    'docs/check-review/azure-selected-log-sample-secret-implementation-20261020.json',
    'docs/check-review/azure-selected-secret-integration-20261020.json',
    'docs/check-review/azure-selected-secret-union-source-successor-20261020.json',
    'docs/check-review/azure-selected-storage-secret-implementation-20261020.json',
    'docs/check-review/azure-servicebus-devops-native-compatibility-20261020.json',
    'docs/check-review/azure-services-native-input-retention-20261020.json',
    'docs/check-review/azure-single-server-retirement-20261020.json',
    'docs/check-review/azure-storage-compute-integration-20261020.json',
    'docs/check-review/azure-storage-native-fixes-20261020.json',
    'docs/check-review/azure-storage-native-review-20261020.json',
    'docs/check-review/azure-sw19-native-source-successor-20261020.json',
    'docs/check-review/azure-upstream-parity-20261020.csv',
    'docs/check-review/azure-upstream-parity-20261020.json',
    'docs/check-review/azure-upstream-parity-pre-apim-disposition-20261020.csv.gz',
    'docs/check-review/azure-upstream-parity-pre-rejection-reassessment-20261020.csv.gz',
    'docs/check-review/batch-current-acceptance-20261020.json',
    'docs/check-review/checks.csv',
    'docs/check-review/commands-job-current-ledger-20261020-tests.xml',
    'docs/check-review/commands-job-current-ledger-source-conservation-20261020.json',
    'docs/check-review/commands-job-current-ledger-source-validation-20261020.json',
    'docs/check-review/cross-cloud-secret-surface-audit-20261020.json',
    'docs/check-review/current-kubelet-azure-log-acceptance-20261020.json',
    'docs/check-review/current-native-wave-final-acceptance-20261020.json',
    'docs/check-review/current-source-package-acceptance-20261020.json',
    'docs/check-review/dataflow-current-acceptance-20261020.json',
    'docs/check-review/dataproc-tde-current-acceptance-20261020.json',
    'docs/check-review/four-excluded-receipt-tracking-reconciliation-20261020.json',
    'docs/check-review/gcp-cloudrun-job-image-current-acceptance-20261020.json',
    'docs/check-review/gcp-cloudrun-job-image-current-native-witnesses-20261020.json.gz',
    'docs/check-review/gcp-current-ledger-source-conservation-20261020-master-retest.xml',
    'docs/check-review/gcp-current-ledger-source-conservation-20261020-tests.xml',
    'docs/check-review/gcp-current-ledger-source-conservation-20261020.json',
    'docs/check-review/gcp-current-ledger-source-validation-20261020.json',
    'docs/check-review/gcp-function-current-ledger-erratum-20261020.json',
    'docs/check-review/gcp-function-paired-native-current-dtos-20261020.json',
    'docs/check-review/gcp-function-paired-native-dtos-20261020.json',
    'docs/check-review/gcp-function-paired-native-integration-20261020.json',
    'docs/check-review/gcp-function-partial-page-20261020-tests.xml',
    'docs/check-review/gcp-function-partial-positive-candidate-20261020.json',
    'docs/check-review/gcp-function-shared-page-budget-diagnostic-20261020.json',
    'docs/check-review/gcp-job-declared-image-primary-contract-20261020.json.gz',
    'docs/check-review/gcp-job-image-native-root-acceptance-20261020.json',
    'docs/check-review/gcp-three-referenced-sources-final-acceptance-20261020.json',
    'docs/check-review/gcp-workbench-head3-20261020-ccc-drafts.json',
    'docs/check-review/gcp-workbench-head3-20261020-collector-proposal.json',
    'docs/check-review/gcp-workbench-head3-20261020-collector-successor-proof.json',
    'docs/check-review/gcp-workbench-head3-20261020-collector.patch',
    'docs/check-review/gcp-workbench-head3-20261020-final-native-tests.xml',
    'docs/check-review/gcp-workbench-head3-20261020-native-proof.json',
    'docs/check-review/gcp-workbench-head3-20261020-native-tests.xml',
    'docs/check-review/gcp-workbench-head3-20261020-ordinary-edge-tests.xml',
    'docs/check-review/gcp-workbench-head3-20261020-projection-tests.xml',
    'docs/check-review/gcp-workbench-head3-20261020-proposal-bindings.json',
    'docs/check-review/gcp-workbench-head3-20261020-pure-native-results.json',
    'docs/check-review/gcp-workbench-head3-compliance-association-review-20261020.json',
    'docs/check-review/gcp-workbench-head3-primary-contract-20261020.json.gz',
    'docs/check-review/gcp-workbench-head3-proposal-test-successor-20261020.json',
    'docs/check-review/gcp-workbench-head3-runtime-20261020-admission.json',
    'docs/check-review/gcp-workbench-head3-runtime-20261020-current-epoch-tests.xml',
    'docs/check-review/gcp-workbench-head3-runtime-20261020-prehook-tests.xml',
    'docs/check-review/gcp-workbench-head3-runtime-20261020-source-accounting.json',
    'docs/check-review/goal-completion-audit-20261020.json',
    'docs/check-review/k8s-annotation-admission-lineage-20261020/k8s-annotation-native-admission-20261020.json.pre-portable.gz',
    'docs/check-review/k8s-annotation-admission-lineage-20261020/k8s_annotation_native_admission_20261020.json.pre-portable.gz',
    'docs/check-review/k8s-annotation-admission-lineage-20261020/k8s_annotation_native_admission_20261020.py.pre-portable.gz',
    'docs/check-review/k8s-annotation-admission-scoped-lineage-20261020/k8s-annotation-native-admission-portability-20261020.json.pre-scoped.gz',
    'docs/check-review/k8s-annotation-admission-scoped-lineage-20261020/k8s_annotation_native_admission_20261020.py.pre-scoped.gz',
    'docs/check-review/k8s-annotation-admission-scoped-lineage-20261020/k8s_annotation_native_admission_portable_20261020.json.pre-scoped.gz',
    'docs/check-review/k8s-annotation-admission-scoped-lineage-20261020/k8s_annotation_portable_probe_20261020.py.pre-scoped.gz',
    'docs/check-review/k8s-annotation-admission-scoped-lineage-20261020/test_k8s_annotation_native_admission_20261020.py.pre-scoped.gz',
    'docs/check-review/k8s-annotation-native-admission-20261020.json',
    'docs/check-review/k8s-annotation-native-admission-portability-20261020.json',
    'docs/check-review/k8s-annotation-psp-native-closure-20261020.json',
    'docs/check-review/k8s-annotation-scoped-admission-20261020.json',
    'docs/check-review/k8s-cluster-native-retention-20261020.json',
    'docs/check-review/k8s-cluster-native-review-20261020.json',
    'docs/check-review/k8s-components-1-native-review-20261020.json',
    'docs/check-review/k8s-components-2-native-review-20261020.json',
    'docs/check-review/k8s-components-3-native-review-20261020.json',
    'docs/check-review/k8s-components-4-native-review-20261020.json',
    'docs/check-review/k8s-components-5-native-review-20261020.json',
    'docs/check-review/k8s-components-6-native-review-20261020.json',
    'docs/check-review/k8s-components-native-review-20261020.json',
    'docs/check-review/k8s-controller-literal-secret-implementation-20261020.json',
    'docs/check-review/k8s-controller-literal-source-successor-20261020.json',
    'docs/check-review/k8s-current-cipher-source-disposition-20261020.json',
    'docs/check-review/k8s-current-integration-proposals-20261020.json',
    'docs/check-review/k8s-current-integration-review-20261020.json',
    'docs/check-review/k8s-current-native-integration-acceptance-20261020.json',
    'docs/check-review/k8s-current-source-inventory-20261020.json',
    'docs/check-review/k8s-image-association-review-20261020.json',
    'docs/check-review/k8s-image-association-setup-20261020.md',
    'docs/check-review/k8s-image-policy-source-successor-20261020.json',
    'docs/check-review/k8s-kubelet-configmap-integration-20261020.json',
    'docs/check-review/k8s-kubelet-configmap-integration-lineage-20261020/k8s.py.pre-configmap.gz',
    'docs/check-review/k8s-kubelet-configmap-integration-lineage-20261020/k8s_annotation_native_admission_20261020.py.pre-configmap.gz',
    'docs/check-review/k8s-kubelet-configmap-integration-lineage-20261020/k8s_annotation_native_admission_scoped_20261020.json.pre-configmap.gz',
    'docs/check-review/k8s-kubelet-configmap-integration-lineage-20261020/test_k8s_kubelet_configmap_native_review_20261020.py.pre-production.gz',
    'docs/check-review/k8s-kubelet-configmap-native-review-20261020.json',
    'docs/check-review/k8s-literal-current-metadata-admission-20261020.json',
    'docs/check-review/k8s-literal-secret-implementation-20261020.json',
    'docs/check-review/k8s-native-observation-closure-20261020.json',
    'docs/check-review/k8s-network-inventory-successor-20261020.json',
    'docs/check-review/k8s-network-inventory-successor-20261020.md',
    'docs/check-review/k8s-public-observation-compatibility-20261020.json',
    'docs/check-review/k8s-public-secret-observation-fix-20261020.json',
    'docs/check-review/k8s-readonly-content-boundaries-20261020.json',
    'docs/check-review/k8s-readonly-content-boundaries-primary-20261020.json.gz',
    'docs/check-review/k8s-review-queue-20261020.json',
    'docs/check-review/k8s-selected-content-all-namespace-successor-20261020.json',
    'docs/check-review/k8s-selected-log-production-integration-20261020.json',
    'docs/check-review/k8s-selected-log-production-lineage-20261020/k8s.py.pre-literal-sdk.gz',
    'docs/check-review/k8s-selected-log-production-lineage-20261020/k8s.py.pre-log-production.gz',
    'docs/check-review/k8s-selected-log-production-lineage-20261020/k8s_annotation_native_admission_20261020.py.pre-literal-sdk.gz',
    'docs/check-review/k8s-selected-log-production-lineage-20261020/k8s_annotation_native_admission_20261020.py.pre-log-production.gz',
    'docs/check-review/k8s-selected-log-production-lineage-20261020/k8s_annotation_native_admission_configmap_successor_20261020.json.pre-log-production.gz',
    'docs/check-review/k8s-selected-log-production-lineage-20261020/k8s_annotation_native_admission_log_successor_20261020.json.pre-literal-sdk.gz',
    'docs/check-review/k8s-selected-log-production-lineage-20261020/k8s_kubelet_configmap_admission_20261020.json.pre-log-production.gz',
    'docs/check-review/k8s-selected-log-production-lineage-20261020/k8s_kubelet_configmap_admission_20261020.py.pre-log-production.gz',
    'docs/check-review/k8s-selected-log-production-lineage-20261020/k8s_selected_log_sample_admission_20261020.json.pre-binding-guard.gz',
    'docs/check-review/k8s-selected-log-production-lineage-20261020/k8s_selected_log_sample_admission_20261020.py.pre-binding-guard.gz',
    'docs/check-review/k8s-selected-log-production-lineage-20261020/test_k8s_selected_log_sample_secret_review_20261020.py.pre-log-production.gz',
    'docs/check-review/k8s-selected-log-sample-secret-implementation-20261020.json',
    'docs/check-review/k8s-selected-log-sample-secrets-setup-20261020.md',
    'docs/check-review/k8s-selected-metadata-current-acceptance-20261020.json',
    'docs/check-review/k8s-selected-metadata-production-partial-native-20261020.json.gz',
    'docs/check-review/k8s-selected-metadata-production-predecessors-20261020.json.gz',
    'docs/check-review/k8s-selected-metadata-production-receipts-20261020.json.gz',
    'docs/check-review/k8s-selected-metadata-production-review-20261020.json',
    'docs/check-review/k8s-selected-metadata-production-source-successor-20261020.json.gz',
    'docs/check-review/k8s-selected-metadata-secret-predecessors-20261020.json.gz',
    'docs/check-review/k8s-selected-metadata-secret-receipts-20261020.json.gz',
    'docs/check-review/k8s-selected-metadata-secret-review-20261020.json',
    'docs/check-review/k8s-selected-metadata-secret-source-successor-20261020.json.gz',
    'docs/check-review/k8s-upstream-parity-20261020.csv',
    'docs/check-review/k8s-upstream-parity-20261020.json',
    'docs/check-review/k8s-upstream-parity-pre-kubelet-20261020.csv.gz',
    'docs/check-review/k8s-upstream-parity-pre-kubelet-20261020.json.gz',
    'docs/check-review/k8s-upstream-source-retention-20261020/apiserver_request_timeout_set.py.gz',
    'docs/check-review/k8s-upstream-source-retention-20261020/etcd_unique_ca.py.gz',
    'docs/check-review/k8s-upstream-source-retention-20261020/kubelet_authorization_mode.py.gz',
    'docs/check-review/k8s-upstream-source-retention-20261020/kubelet_client_ca_file_set.py.gz',
    'docs/check-review/k8s-upstream-source-retention-20261020/kubelet_conf_file_ownership.py.gz',
    'docs/check-review/k8s-upstream-source-retention-20261020/kubelet_conf_file_permissions.py.gz',
    'docs/check-review/k8s-upstream-source-retention-20261020/kubelet_config_yaml_ownership.py.gz',
    'docs/check-review/k8s-upstream-source-retention-20261020/kubelet_config_yaml_permissions.py.gz',
    'docs/check-review/k8s-upstream-source-retention-20261020/kubelet_disable_anonymous_auth.py.gz',
    'docs/check-review/k8s-upstream-source-retention-20261020/kubelet_disable_read_only_port.py.gz',
    'docs/check-review/k8s-upstream-source-retention-20261020/kubelet_event_record_qps.py.gz',
    'docs/check-review/k8s-upstream-source-retention-20261020/kubelet_manage_iptables.py.gz',
    'docs/check-review/k8s-upstream-source-retention-20261020/kubelet_rotate_certificates.py.gz',
    'docs/check-review/k8s-upstream-source-retention-20261020/kubelet_service.py.gz',
    'docs/check-review/k8s-upstream-source-retention-20261020/kubelet_service_file_ownership_root.py.gz',
    'docs/check-review/k8s-upstream-source-retention-20261020/kubelet_service_file_permissions.py.gz',
    'docs/check-review/k8s-upstream-source-retention-20261020/kubelet_streaming_connection_timeout.py.gz',
    'docs/check-review/k8s-upstream-source-retention-20261020/kubelet_strong_ciphers_only.py.gz',
    'docs/check-review/k8s-upstream-source-retention-20261020/kubelet_tls_cert_and_key.py.gz',
    'docs/check-review/k8s-upstream-source-retention-20261020/rbac_cluster_admin_usage.py.gz',
    'docs/check-review/k8s-workload-native-retention-20261020.json',
    'docs/check-review/k8s-workloads-native-review-20261020.json',
    'docs/check-review/local-admission-wave-source-package-20261020.json.gz',
    'docs/check-review/log-databricks-sas-current-acceptance-20261020.json',
    'docs/check-review/metadata-public-observation-package-acceptance-20261020.json',
    'docs/check-review/nsp-runtime-wheel-portability-20261020.json',
    'docs/check-review/progress.json',
    'docs/check-review/secret-coverage.json',
    'docs/check-review/secret-grouping-incomplete-source-successor-20261020.json',
    'docs/check-review/secret-surface-current-successors-20261020.json',
    'docs/check-review/tests/test_azure_function_package_final_20261020.py',
    'docs/check-review/upstream-head-delta-20261020-evidence.json',
    'docs/check-review/upstream-head-delta-20261020-queue.csv',
    'docs/check-review/upstream-head-delta-20261020-report.json',
    'docs/check-review/workbench-current-acceptance-20261020.json',
    'docs/check-review/workload-content-canonical-admission-20261020.json',
    'docs/compliance-ledgers/native-extensions/aws-codebuild-inline-buildspec-20261020.json',
    'docs/compliance-ledgers/native-extensions/aws-selected-configuration-content-20261020.json',
    'docs/compliance-ledgers/native-extensions/aws-selected-s3-source-20261020.json',
    'docs/compliance-ledgers/native-extensions/azure-ai-services-20261020.json',
    'docs/compliance-ledgers/native-extensions/azure-automation-aci-20261020.json',
    'docs/compliance-ledgers/native-extensions/azure-blocking-sas-policy-20261020.json',
    'docs/compliance-ledgers/native-extensions/azure-devops-visible-urls-20261020.json',
    'docs/compliance-ledgers/native-extensions/azure-final-native-20261020.json',
    'docs/compliance-ledgers/native-extensions/azure-functions-declarations-20261020.json',
    'docs/compliance-ledgers/native-extensions/azure-network-audit-20261020.json',
    'docs/compliance-ledgers/native-extensions/azure-nsp-query-declarations-20261020.json',
    'docs/compliance-ledgers/native-extensions/azure-selected-configured-package-20261020.json',
    'docs/compliance-ledgers/native-extensions/azure-selected-databricks-notebooks-20261020.json',
    'docs/compliance-ledgers/native-extensions/azure-selected-declarations-20261020.json',
    'docs/compliance-ledgers/native-extensions/azure-selected-log-samples-20261020.json',
    'docs/compliance-ledgers/native-extensions/azure-selected-ml-assets-20261020.json',
    'docs/compliance-ledgers/native-extensions/azure-selected-ml-jobs-20261020.json',
    'docs/compliance-ledgers/native-extensions/azure-selected-secrets-20261020.json',
    'docs/compliance-ledgers/native-extensions/gcp-20261019.json',
    'docs/compliance-ledgers/native-extensions/gcp-batch-referenced-source-20261020.json',
    'docs/compliance-ledgers/native-extensions/gcp-dataflow-referenced-source-20261020.json',
    'docs/compliance-ledgers/native-extensions/gcp-dataproc-referenced-source-20261020.json',
    'docs/compliance-ledgers/native-extensions/gcp-selected-content-20261020.json',
    'docs/compliance-ledgers/native-extensions/gcp-workbench-head3-20261020.json',
    'docs/compliance-ledgers/native-extensions/gcp-workbench-referenced-source-20261020.json',
    'docs/compliance-ledgers/native-extensions/k8s-kubelet-configmap-declarations-20261020.json',
    'docs/compliance-ledgers/native-extensions/k8s-selected-log-samples-20261020.json',
    'docs/compliance-ledgers/native-extensions/k8s-selected-object-metadata-20261020.json',
    'docs/compliance-ledgers/native-extensions/selected-content-20261020.json',
    'docs/compliance-ledgers/native-extensions/workload-content-20261020.json',
    'docs/gcp-review/README.md',
    'docs/gcp-review/dataflow-batch-source-runtime-setup-20261020.md',
    'docs/gcp-review/dataproc-referenced-source-secret-setup-20261020.md',
    'docs/gcp-review/gcp_batch_referenced_source_20261020_setup.md',
    'docs/gcp-review/gcp_workbench_referenced_source_20261020_setup.md',
    'docs/gcp-review/recheck-20261020/access-transparency-alias-correction.json',
    'docs/gcp-review/recheck-20261020/alert-predicate-successors.json',
    'docs/gcp-review/recheck-20261020/alert-qualification-fixes.json',
    'docs/gcp-review/recheck-20261020/api-caller-prefix-fix.json',
    'docs/gcp-review/recheck-20261020/appengine-handler-projection-correction.json',
    'docs/gcp-review/recheck-20261020/archive-selection-review.json',
    'docs/gcp-review/recheck-20261020/bigquery-historical-native-closure.json',
    'docs/gcp-review/recheck-20261020/checks.csv',
    'docs/gcp-review/recheck-20261020/compute-batch-review.json',
    'docs/gcp-review/recheck-20261020/compute-conflict-fixes.json',
    'docs/gcp-review/recheck-20261020/compute-predicate-successors.json',
    'docs/gcp-review/recheck-20261020/compute-second-batch-review.json',
    'docs/gcp-review/recheck-20261020/compute-second-fixes.json',
    'docs/gcp-review/recheck-20261020/core-compute-review.json',
    'docs/gcp-review/recheck-20261020/core-gke-review.json',
    'docs/gcp-review/recheck-20261020/crm-native-response-body-compatibility-20261020.json',
    'docs/gcp-review/recheck-20261020/current-source-extension-accounting-20261020.json',
    'docs/gcp-review/recheck-20261020/current-source-reconciliation-20261020.json',
    'docs/gcp-review/recheck-20261020/dataflow-batch-source-runtime-admission-review-20261020.json',
    'docs/gcp-review/recheck-20261020/dataflow-batch-source-runtime-directed-tests-20261020.json.gz',
    'docs/gcp-review/recheck-20261020/dataflow-batch-source-runtime-native-proof-20261020.json.gz',
    'docs/gcp-review/recheck-20261020/dataflow-batch-source-runtime-public-findings-20261020.json',
    'docs/gcp-review/recheck-20261020/dataproc-referenced-source-proof-20261020.json.gz',
    'docs/gcp-review/recheck-20261020/dataproc-referenced-source-secret-review-20261020.json',
    'docs/gcp-review/recheck-20261020/dataproc-source-finalizer-predecessor-20261020.json.gz',
    'docs/gcp-review/recheck-20261020/dataproc-source-pre-integration-20261020.json.gz',
    'docs/gcp-review/recheck-20261020/dataproc-source-production-integration-20261020.json',
    'docs/gcp-review/recheck-20261020/dataproc-source-production-proof-20261020.json.gz',
    'docs/gcp-review/recheck-20261020/dns-ports-key-correction.json',
    'docs/gcp-review/recheck-20261020/dnssec-review.json',
    'docs/gcp-review/recheck-20261020/final-services-fixes.json',
    'docs/gcp-review/recheck-20261020/final-services-predicate-successors.json',
    'docs/gcp-review/recheck-20261020/final-services-review.json',
    'docs/gcp-review/recheck-20261020/gcp_batch_independent_review_20261020_initial_blocker.txt',
    'docs/gcp-review/recheck-20261020/gcp_batch_independent_review_20261020_junit.xml',
    'docs/gcp-review/recheck-20261020/gcp_batch_independent_review_20261020_proof.json.gz',
    'docs/gcp-review/recheck-20261020/gcp_batch_independent_review_20261020_pytest.txt',
    'docs/gcp-review/recheck-20261020/gcp_batch_independent_review_20261020_report.json',
    'docs/gcp-review/recheck-20261020/gcp_batch_referenced_source_20261020_primary.json.gz',
    'docs/gcp-review/recheck-20261020/gcp_batch_referenced_source_20261020_proof.json.gz',
    'docs/gcp-review/recheck-20261020/gcp_batch_referenced_source_20261020_pytest.txt',
    'docs/gcp-review/recheck-20261020/gcp_batch_referenced_source_20261020_report.json',
    'docs/gcp-review/recheck-20261020/gcp_cloudrun_job_image_observed_20261020_proof.txt',
    'docs/gcp-review/recheck-20261020/gcp_cloudrun_job_image_observed_20261020_receipt.json',
    'docs/gcp-review/recheck-20261020/gcp_cloudrun_job_image_runtime_20261020_proof.txt',
    'docs/gcp-review/recheck-20261020/gcp_cloudrun_job_image_runtime_20261020_receipt.json',
    'docs/gcp-review/recheck-20261020/gcp_cloudrun_job_image_runtime_20261020_setup.md',
    'docs/gcp-review/recheck-20261020/gcp_cloudrun_v2_job_declared_images_20261020_proof.txt',
    'docs/gcp-review/recheck-20261020/gcp_cloudrun_v2_job_declared_images_20261020_receipt.json',
    'docs/gcp-review/recheck-20261020/gcp_cloudrun_v2_job_declared_images_20261020_setup.md',
    'docs/gcp-review/recheck-20261020/gcp_dataflow_referenced_source_20261020_primary_contract.json',
    'docs/gcp-review/recheck-20261020/gcp_dataflow_referenced_source_20261020_report.json',
    'docs/gcp-review/recheck-20261020/gcp_dataflow_referenced_source_20261020_setup.md',
    'docs/gcp-review/recheck-20261020/gcp_dataflow_referenced_source_request_binding_20261020_report.json',
    'docs/gcp-review/recheck-20261020/gcp_source_historical_compatibility_20261020_report.json',
    'docs/gcp-review/recheck-20261020/gcp_workbench_referenced_source_20261020_attestation_tests.xml',
    'docs/gcp-review/recheck-20261020/gcp_workbench_referenced_source_20261020_native_proof.json.gz',
    'docs/gcp-review/recheck-20261020/gcp_workbench_referenced_source_20261020_official_sources.json',
    'docs/gcp-review/recheck-20261020/gcp_workbench_referenced_source_20261020_report.json',
    'docs/gcp-review/recheck-20261020/gcp_workbench_referenced_source_20261020_tests.xml',
    'docs/gcp-review/recheck-20261020/gcp_workload_image_source_association_20261020_report.json',
    'docs/gcp-review/recheck-20261020/gcp_workload_image_source_association_20261020_setup.md',
    'docs/gcp-review/recheck-20261020/gke-pool-review.json',
    'docs/gcp-review/recheck-20261020/htbp-precedence-correction.json',
    'docs/gcp-review/recheck-20261020/identity-api-backup-fixes.json',
    'docs/gcp-review/recheck-20261020/identity_data-batch-review.json',
    'docs/gcp-review/recheck-20261020/logging-batch-review.json',
    'docs/gcp-review/recheck-20261020/metadata-final-batch-review.json',
    'docs/gcp-review/recheck-20261020/metadata-fixes.json',
    'docs/gcp-review/recheck-20261020/metadata-predicate-successors.json',
    'docs/gcp-review/recheck-20261020/native57-data-fixes.json',
    'docs/gcp-review/recheck-20261020/native57-data-review.json',
    'docs/gcp-review/recheck-20261020/native57-iam-kms-fixes.json',
    'docs/gcp-review/recheck-20261020/native57-iam-kms-review.json',
    'docs/gcp-review/recheck-20261020/native57-integration-acceptance.json',
    'docs/gcp-review/recheck-20261020/native57-legacy-iam-fixtures.json',
    'docs/gcp-review/recheck-20261020/native57-predicate-successors.json',
    'docs/gcp-review/recheck-20261020/oslogin2fa-plan-correction.json',
    'docs/gcp-review/recheck-20261020/prior-bounded-corrections.json',
    'docs/gcp-review/recheck-20261020/prior-bounded-predicate-successors.json',
    'docs/gcp-review/recheck-20261020/prior-bounded-recheck.json',
    'docs/gcp-review/recheck-20261020/progress.json',
    'docs/gcp-review/recheck-20261020/secret-surface-audit.json',
    'docs/gcp-review/recheck-20261020/serverless-parent-correction.json',
    'docs/gcp-review/recheck-20261020/serverless-parent-defect.json',
    'docs/gcp-review/recheck-20261020/source-parity.json',
    'docs/gcp-review/recheck-20261020/task-routine-secret-implementation.json',
    'docs/gcp-review/recheck-20261020/three-source-final-root-gates-20261020.json.gz',
    'docs/gcp-review/recheck-20261020/vm-role-permissions-review.json',
    'docs/gcp-review/recheck-20261020/vm-role-producer-review.json',
    'docs/gcp-review/recheck-20261020/workbench-source-runtime-admission-review-20261020.json',
    'docs/gcp-review/recheck-20261020/workbench-source-runtime-directed-tests-20261020.json.gz',
    'docs/gcp-review/recheck-20261020/workbench-source-runtime-native-proof-20261020.json.gz',
    'docs/gcp-review/recheck-20261020/workbench-source-runtime-public-findings-20261020.json',
    'docs/gcp-review/workbench-source-runtime-setup-20261020.md',
    'docs/network-audit/STATUS.md',
    'docs/network-audit/aws-api-network-candidates.json',
    'docs/network-audit/azure-private-link-candidates.json',
    'docs/network-audit/gcp-api-network-candidates.json',
    'docs/network-audit/service-dispositions.json',
    'docs/secret-content-permissions.md',
    'tests/aws_codebuild_historical_admission_compatibility_20261020.py',
    'tests/aws_workload_command_source_20261020_test.py',
    'tests/azure_native_successor_inputs_20261020.py',
    'tests/fixtures/aws-codebuild-inline-evidence-review-20261020.json',
    'tests/fixtures/aws-codebuild-inline-public-summaries-20261020.json',
    'tests/fixtures/aws-selected-configuration-evidence-review-20261020.json',
    'tests/fixtures/aws-selected-s3-source-evidence-review-20261020.json',
    'tests/fixtures/aws-workload-command-brief-native-20261020.json',
    'tests/fixtures/aws_s3_selected_source_pre_integration_20261020.py.gz',
    'tests/fixtures/azure-ai-evidence-review-20261020.json',
    'tests/fixtures/azure-automation-aci-evidence-review-20261020.json',
    'tests/fixtures/azure-configured-package-evidence-review-20261020.json',
    'tests/fixtures/azure-edge-native-evidence-review-20261020.json',
    'tests/fixtures/azure-final-native-evidence-review-20261020.json',
    'tests/fixtures/azure-functions-declaration-evidence-review-20261020.json',
    'tests/fixtures/azure-key-age-evidence-review-20261020.json',
    'tests/fixtures/azure-network-audit-evidence-review-20261020.json',
    'tests/fixtures/azure-nsp-query-declaration-evidence-review-20261020.json',
    'tests/fixtures/azure-sas-policy-evidence-review-20261020.json',
    'tests/fixtures/azure-selected-databricks-evidence-review-20261020.json',
    'tests/fixtures/azure-selected-declaration-evidence-review-20261020.json',
    'tests/fixtures/azure-selected-log-sample-evidence-review-20261020.json',
    'tests/fixtures/azure-selected-ml-assets-evidence-review-20261020.json',
    'tests/fixtures/azure-selected-ml-job-evidence-review-20261020.json',
    'tests/fixtures/azure-selected-secrets-evidence-review-20261020.json',
    'tests/fixtures/azure_acr_image_secret_indicators_pre_union_20261020.py.gz',
    'tests/fixtures/azure_apim_operation_source_assessment_20261020.json.gz',
    'tests/fixtures/azure_apim_operation_window_gate_20261020.log.gz',
    'tests/fixtures/azure_apim_operation_window_gate_20261020.xml.gz',
    'tests/fixtures/azure_app_settings_secret_indicators_pre_union_20261020.py.gz',
    'tests/fixtures/azure_application_compute_2_native_successors_20261020.json',
    'tests/fixtures/azure_application_compute_native_successors_20261020.json',
    'tests/fixtures/azure_archived_legacy_fixture_closure_predecessors_20261020.json.gz',
    'tests/fixtures/azure_archived_legacy_fixture_closure_receipts_20261020.json.gz',
    'tests/fixtures/azure_database_crypto_backup_1_native_current_20261020.json',
    'tests/fixtures/azure_database_crypto_backup_2_evaluator_inputs_20261020.json',
    'tests/fixtures/azure_database_crypto_backup_2_native_current_20261020.json',
    'tests/fixtures/azure_database_crypto_backup_2_public_certificates_20261020.json',
    'tests/fixtures/azure_database_native_evaluator_inputs_20261020.json',
    'tests/fixtures/azure_devops_visible_native_pre_current_bridge_20261020.json.gz',
    'tests/fixtures/azure_edge_native_current_inputs_20261020.json.gz',
    'tests/fixtures/azure_function_role_native_successors_20261020.json',
    'tests/fixtures/azure_function_source_parity_pre_admission_reconciliation_20261020.json.gz',
    'tests/fixtures/azure_hsm_audit_review_20261020_native.json',
    'tests/fixtures/azure_http_status_fixture_compatibility_predecessor_20261020.json.gz',
    'tests/fixtures/azure_identity_enforcement_native_successors_20261020.json',
    'tests/fixtures/azure_identity_native_successors_20261020.json',
    'tests/fixtures/azure_lock_native_successors_20261020.json.gz',
    'tests/fixtures/azure_metadata_transport_predecessor_20261020.json.gz',
    'tests/fixtures/azure_metadata_transport_receipts_20261020.json.gz',
    'tests/fixtures/azure_metadata_transport_successor_native_cases_20261020.json.gz',
    'tests/fixtures/azure_native_contract_closure_20261020.json',
    'tests/fixtures/azure_network_native_evaluator_inputs_20261020.json',
    'tests/fixtures/azure_nsp_tde_admission_compatibility_receipts_20261020.json.gz',
    'tests/fixtures/azure_nsp_tde_admission_test_predecessor_20261020.json.gz',
    'tests/fixtures/azure_package_canonical_pre_admission_20261020.json.gz',
    'tests/fixtures/azure_package_master_pending_predecessor_20261020.json.gz',
    'tests/fixtures/azure_package_review_accounting_pre_admission_20261020.json.gz',
    'tests/fixtures/azure_rejected_source_predicates_20261020.json.gz',
    'tests/fixtures/azure_servicebus_native_capture_pre_inventory_isolation_20261020.py.gz',
    'tests/fixtures/azure_services1_native_evaluator_inputs_20261020.json.gz',
    'tests/fixtures/azure_services2_native_evaluator_inputs_20261020.json.gz',
    'tests/fixtures/azure_services3_native_evaluator_inputs_20261020.json.gz',
    'tests/fixtures/azure_storage_native_fixes_20261020.json',
    'tests/fixtures/commands_job_current_acceptance_predecessors_20261020.json.gz',
    'tests/fixtures/commands_job_master_full_before_after_20261020.json.gz',
    'tests/fixtures/gcp-alert-native-successor-20261020.json',
    'tests/fixtures/gcp-cloudrun-job-image-observed-20261020.json',
    'tests/fixtures/gcp-compute-native-successor-20261020.json',
    'tests/fixtures/gcp-dataflow-batch-source-evidence-review-20261020.json',
    'tests/fixtures/gcp-dataproc-source-evidence-review-20261020.json',
    'tests/fixtures/gcp-final-services-native-successor-20261020.json',
    'tests/fixtures/gcp-native57-native-successor-20261020.json',
    'tests/fixtures/gcp-prior-bounded-native-successor-20261020.json',
    'tests/fixtures/gcp-workbench-head3-brief-native-20261020.json',
    'tests/fixtures/gcp-workbench-source-evidence-review-20261020.json',
    'tests/fixtures/gcp-workbench-source-partial-evidence-review-20261020.json',
    'tests/fixtures/gcp_canonical_conservation_pre_codebuild_20261020.json.gz',
    'tests/fixtures/gcp_cloudrun_image_inspection_review_pre_job_runtime_20261020.py.gz',
    'tests/fixtures/gcp_crm_response_body_compatibility_predecessor_20261020.json.gz',
    'tests/fixtures/gcp_current_ledger_head3_predecessors_20261020.json.gz',
    'tests/fixtures/gcp_head3_canonical_pre_admission_20261020.json.gz',
    'tests/fixtures/gcp_head3_proposal_test_pre_admission_20261020.json.gz',
    'tests/fixtures/gcp_master_azure_package_compatibility_predecessor_20261020.json.gz',
    'tests/fixtures/gcp_source_acceptance_accounting_pre_dataflow_batch_20261020.json.gz',
    'tests/fixtures/gcp_source_reconciliation_test_pre_workbench_20261020.json.gz',
    'tests/fixtures/gcp_workbench_shared_hook_test_pre_combined_20261020.json.gz',
    'tests/fixtures/k8s-kubelet-unknown-native-observations-20261020.json',
    'tests/fixtures/k8s-selected-log-sample-evidence-review-20261020.json',
    'tests/fixtures/k8s-selected-metadata-consolidated-evidence-review-20261020.json',
    'tests/fixtures/k8s-selected-metadata-evidence-review-20261020.json',
    'tests/fixtures/k8s-selected-metadata-partial-evidence-review-20261020.json',
    'tests/fixtures/k8s-selected-metadata-partial-predicate-evidence-review-20261020.json',
    'tests/fixtures/k8s_cluster_native_inputs_20261020.tar.gz',
    'tests/fixtures/k8s_controller_literal_secret_review_20261020.json',
    'tests/fixtures/k8s_current_literal_observations_20261020.json',
    'tests/fixtures/k8s_literal_before_all_namespace_20261020.py.gz',
    'tests/fixtures/k8s_literal_pre_controller_consumer_20261020.py.gz',
    'tests/fixtures/k8s_literal_pre_controller_producer_20261020.py.gz',
    'tests/fixtures/k8s_public_observation_compatibility_predecessors_20261020.json.gz',
    'tests/fixtures/k8s_public_secret_observation_predecessor_20261020.json.gz',
    'tests/fixtures/k8s_selected_metadata_secret_native_20261020.json.gz',
    'tests/fixtures/k8s_workload_native_current_inputs_20261020.json.gz',
    'tests/fixtures/kubelet_unknown_observation_predecessor_20261020.json.gz',
    'tests/fixtures/secret_findings_pre_incomplete_20261020.py.gz',
    'tests/fixtures/selected-content-evidence-review-20261020.json',
    'tests/fixtures/selected_content_extension_pre_k8s_workloads_20261020.json.gz',
    'tests/fixtures/workbench_canonical_description_predecessor_20261020.json.gz',
    'tests/fixtures/workload_content_canonical_pre_admission_20261020.json.gz',
    'tests/gcp_batch_independent_review_20261020_test.py',
    'tests/gcp_batch_referenced_source_20261020_native.json',
    'tests/gcp_batch_referenced_source_20261020_test.py',
    'tests/gcp_dataflow_referenced_source_20261020_native_fixtures.json',
    'tests/gcp_dataflow_referenced_source_20261020_receipt_fixtures.json',
    'tests/gcp_dataflow_referenced_source_20261020_test.py',
    'tests/gcp_dataflow_referenced_source_request_binding_20261020_test.py',
    'tests/gcp_function_partial_positive_native_20261020.py',
    'tests/gcp_function_secret_paired_native_20261020.py',
    'tests/gcp_native_iam_test_inputs_20261020.py',
    'tests/gcp_referenced_source_historical_compatibility_20261020.py',
    'tests/gcp_referenced_source_independent_review_20261020_test.py',
    'tests/gcp_workbench_referenced_source_20261020_test.py',
    'tests/k8s_annotation_portable_probe_20261020.py',
    'tests/k8s_cluster_retained_inputs_20261020.py',
    'tests/selected_secret_source_successors_20261020.py',
    'tests/test_aws_code_log_content_review_20261019.py',
    'tests/test_aws_codebuild_buildspec_runtime_20261020.py',
    'tests/test_aws_codebuild_buildspec_shared_runtime_20261020.py',
    'tests/test_aws_codebuild_buildspec_source_20261020.py',
    'tests/test_aws_codebuild_historical_admission_compatibility_20261020.py',
    'tests/test_aws_codebuild_inline_observed_20261020.py',
    'tests/test_aws_codecommit_path_redaction_fix_20261020.py',
    'tests/test_aws_content_scan_selection_review.py',
    'tests/test_aws_lambda_environment_hosted_options_20261020.py',
    'tests/test_aws_lambda_environment_secret_review_20261020.py',
    'tests/test_aws_pr33_local_preservation_20261020.py',
    'tests/test_aws_s3_runtime_admission_20261020.py',
    'tests/test_aws_s3_selected_source_integration_20261020.py',
    'tests/test_aws_s3_selected_source_secret_review_20261020.py',
    'tests/test_aws_selected_configuration_admission_20261020.py',
    'tests/test_aws_selected_configuration_permission_boundary_20261020.py',
    'tests/test_aws_selected_configuration_secret_review_20261020.py',
    'tests/test_aws_workload_command_observed_20261020.py',
    'tests/test_aws_workload_command_runtime_20261020.py',
    'tests/test_azure_acr_hosted_options_20261020.py',
    'tests/test_azure_acr_image_secret_review_20261020.py',
    'tests/test_azure_acr_public_ip_review_20261020.py',
    'tests/test_azure_activity_alert_native_review_20261020.py',
    'tests/test_azure_ai_services_copy_20261020.py',
    'tests/test_azure_ai_services_review_20261020.py',
    'tests/test_azure_aks_legacy_projection_review_20261020.py',
    'tests/test_azure_apim_operation_window_20261020.py',
    'tests/test_azure_app_settings_hosted_options_20261020.py',
    'tests/test_azure_app_settings_secret_review_20261020.py',
    'tests/test_azure_application_compute_1_native_review_20261020.py',
    'tests/test_azure_application_compute_2_native_review_20261020.py',
    'tests/test_azure_attack_logs.py',
    'tests/test_azure_automation_aci_admission_20261020.py',
    'tests/test_azure_automation_aci_metadata_review_20261020.py',
    'tests/test_azure_automation_aci_observation_20261020.py',
    'tests/test_azure_backup_native_source_successor_20261020.py',
    'tests/test_azure_compute_network_native_review_20261020.py',
    'tests/test_azure_configured_package_observed_20261020.py',
    'tests/test_azure_database_crypto_backup_1_native_review_20261020.py',
    'tests/test_azure_database_crypto_backup_2_native_review_20261020.py',
    'tests/test_azure_databricks_notebook_secret_integration_20261020.py',
    'tests/test_azure_databricks_notebook_secret_review_20261020.py',
    'tests/test_azure_declaration_secret_integration_20261020.py',
    'tests/test_azure_defender_pricing_native_review_20261020.py',
    'tests/test_azure_devops_selected_content_secret_review_20261020.py',
    'tests/test_azure_edge_native_admission_20261020.py',
    'tests/test_azure_final_edge_native_closure_20261020.py',
    'tests/test_azure_final_native_admission_boundary_20261020.py',
    'tests/test_azure_final_native_observations_20261020.py',
    'tests/test_azure_function_package_integrated_20261020.py',
    'tests/test_azure_function_package_portable_20261020.py',
    'tests/test_azure_function_package_runtime_20261020.py',
    'tests/test_azure_function_package_source_20261020.py',
    'tests/test_azure_function_package_source_successor_20261020.py',
    'tests/test_azure_function_settings_declarations_20261020.py',
    'tests/test_azure_function_settings_production_integration_20261020.py',
    'tests/test_azure_function_settings_runtime_admission_20261020.py',
    'tests/test_azure_function_upstream_successor_20261020.py',
    'tests/test_azure_hsm_audit_review_20261020.py',
    'tests/test_azure_identity_enforcement_native_20261020.py',
    'tests/test_azure_identity_native_review_20261020.py',
    'tests/test_azure_k8s_archived_selection_review_20261020.py',
    'tests/test_azure_k8s_current_review_bindings_20261020.py',
    'tests/test_azure_key_age_observation_20261020.py',
    'tests/test_azure_log_sample_secret_integration_20261020.py',
    'tests/test_azure_metadata_transport_fix_20261020.py',
    'tests/test_azure_metadata_transport_inherited_risk_20261020.py',
    'tests/test_azure_ml_job_secret_integration_20261020.py',
    'tests/test_azure_ml_selected_asset_secret_integration_20261020.py',
    'tests/test_azure_ml_selected_asset_secret_review_20261020.py',
    'tests/test_azure_ml_selected_job_secret_review_20261020.py',
    'tests/test_azure_monitoring_contacts_native_review_20261020.py',
    'tests/test_azure_native_contract_closure_20261020.py',
    'tests/test_azure_native_current_fixture_preservation_20261020.py',
    'tests/test_azure_native_review_copy_successors_20261020.py',
    'tests/test_azure_network_audit_observation_20261020.py',
    'tests/test_azure_network_platform_1_native_review_20261020.py',
    'tests/test_azure_nsp_query_cmk_metadata_admission_20261020.py',
    'tests/test_azure_nsp_query_cmk_metadata_proposal_20261020.py',
    'tests/test_azure_nsp_query_cmk_production_20261020.py',
    'tests/test_azure_nsp_query_cmk_production_admission_20261020.py',
    'tests/test_azure_nsp_query_cmk_runtime_20261020.py',
    'tests/test_azure_nsp_query_cmk_runtime_admission_20261020.py',
    'tests/test_azure_nsp_tde_admission_compatibility_20261020.py',
    'tests/test_azure_rejected_source_recheck_20261020.py',
    'tests/test_azure_remaining_services_1_native_review_20261020.py',
    'tests/test_azure_remaining_services_2_native_review_20261020.py',
    'tests/test_azure_remaining_services_3_native_review_20261020.py',
    'tests/test_azure_sas_expiry_policy_declaration_20261020.py',
    'tests/test_azure_sas_policy_admission_20261020.py',
    'tests/test_azure_selected_configuration_secret_review_20261020.py',
    'tests/test_azure_selected_declaration_secret_review_20261020.py',
    'tests/test_azure_selected_log_sample_secret_review_20261020.py',
    'tests/test_azure_selected_secret_integration_20261020.py',
    'tests/test_azure_union_redaction_batches_20261025.py',
    'tests/test_azure_selected_storage_secret_review_20261020.py',
    'tests/test_azure_sql_tde_parent_identity_fix_20261020.py',
    'tests/test_azure_storage_native_fixes_20261020.py',
    'tests/test_azure_storage_native_review_20261020.py',
    'tests/test_azure_sw19_native_source_successor_20261020.py',
    'tests/test_azure_synapse_dependency_successor_20261020.py',
    'tests/test_cross_cloud_secret_surface_audit_20261020.py',
    'tests/test_gcp_alert_qualification_fix_review_20261020.py',
    'tests/test_gcp_api_caller_prefix_fix_review_20261020.py',
    'tests/test_gcp_appengine_handler_projection_review_20261020.py',
    'tests/test_gcp_archived_selection_review_20261020.py',
    'tests/test_gcp_cloudrun_image_inspection_review.py',
    'tests/test_gcp_cloudrun_job_image_observed_20261020.py',
    'tests/test_gcp_cloudrun_job_image_runtime_20261020.py',
    'tests/test_gcp_cloudrun_v2_job_declared_images_20261020.py',
    'tests/test_gcp_compute_audit_batch_review_20261020.py',
    'tests/test_gcp_compute_second_batch_review_20261020.py',
    'tests/test_gcp_compute_second_fix_review_20261020.py',
    'tests/test_gcp_consolidated_secret_observed_20261020.py',
    'tests/test_gcp_core_compute_native_review_20261020.py',
    'tests/test_gcp_core_gke_native_review_20261020.py',
    'tests/test_gcp_current_native_fixture_preservation_20261020.py',
    'tests/test_gcp_current_source_reconciliation_20261020.py',
    'tests/test_gcp_dataflow_batch_source_runtime_20261020.py',
    'tests/test_gcp_dataproc_referenced_source_secret_review_20261020.py',
    'tests/test_gcp_dataproc_source_production_integration_20261020.py',
    'tests/test_gcp_dnssec_native_matrix_review_20261020.py',
    'tests/test_gcp_final_services_fix_review_20261020.py',
    'tests/test_gcp_final_services_review_20261020.py',
    'tests/test_gcp_firewall_port_native_matrix_review_20261020.py',
    'tests/test_gcp_function_backing_parent_native_review_20261020.py',
    'tests/test_gcp_function_secret_paired_candidate_20261020.py',
    'tests/test_gcp_function_secret_paired_integration_20261020.py',
    'tests/test_gcp_function_secret_partial_page_20261020.py',
    'tests/test_gcp_function_secret_partial_positive_20261020.py',
    'tests/test_gcp_gke_native_matrix_review_20261020.py',
    'tests/test_gcp_htbp_precedence_native_review_20261020.py',
    'tests/test_gcp_identity_data_audit_batch_review_20261020.py',
    'tests/test_gcp_job_literal_secret_review_20261019.py',
    'tests/test_gcp_logging_audit_batch_review_20261020.py',
    'tests/test_gcp_metadata_final_batch_review_20261020.py',
    'tests/test_gcp_metadata_fixes_review_20261020.py',
    'tests/test_gcp_native57_data_fix_20261020.py',
    'tests/test_gcp_native57_data_review_20261020.py',
    'tests/test_gcp_native57_iam_kms_fix_20261020.py',
    'tests/test_gcp_native57_iam_kms_review_20261020.py',
    'tests/test_gcp_native57_source_copy_acceptance_20261020.py',
    'tests/test_gcp_prior_bounded_corrections_20261020.py',
    'tests/test_gcp_prior_bounded_recheck_20261020.py',
    'tests/test_gcp_referenced_source_current_compatibility_20261020.py',
    'tests/test_gcp_secret_surface_audit_20261020.py',
    'tests/test_gcp_selected_archive_secret_review_20261019.py',
    'tests/test_gcp_selected_object_secret_review_20261019.py',
    'tests/test_gcp_task_routine_hosted_options_20261020.py',
    'tests/test_gcp_task_routine_secret_review_20261020.py',
    'tests/test_gcp_vm_role_permissions_native_review_20261020.py',
    'tests/test_gcp_workbench_current_acceptance_20261020.py',
    'tests/test_gcp_workbench_head3_observed_20261020.py',
    'tests/test_gcp_workbench_head3_ordinary_edges_20261020.py',
    'tests/test_gcp_workbench_head3_projection_20261020.py',
    'tests/test_gcp_workbench_head3_proposal_20261020.py',
    'tests/test_gcp_workbench_head3_runtime_admission_20261020.py',
    'tests/test_gcp_workbench_source_runtime_20261020.py',
    'tests/test_gcp_workload_image_source_association_20261020.py',
    'tests/test_k8s_admission_configmap_secret_surface_20261020.py',
    'tests/test_k8s_annotation_native_admission_20261020.py',
    'tests/test_k8s_annotation_native_admission_portable_20261020.py',
    'tests/test_k8s_annotation_psp_closure_20261020.py',
    'tests/test_k8s_annotation_scoped_admission_20261020.py',
    'tests/test_k8s_cluster_native_review_20261020.py',
    'tests/test_k8s_components_native_review_20261020.py',
    'tests/test_k8s_controller_literal_secret_review_20261020.py',
    'tests/test_k8s_current_integration_review_20261020.py',
    'tests/test_k8s_image_policy_source_successor_20261020.py',
    'tests/test_k8s_image_source_association_20261020.py',
    'tests/test_k8s_kubelet_configmap_native_review_20261020.py',
    'tests/test_k8s_kubelet_configmap_production_20261020.py',
    'tests/test_k8s_kubelet_declaration_observed_20261020.py',
    'tests/test_k8s_literal_hosted_options_20261020.py',
    'tests/test_k8s_literal_secret_review_20261020.py',
    'tests/test_k8s_native_review_copy_20261020.py',
    'tests/test_k8s_network_inventory_successor_20261020.py',
    'tests/test_k8s_secret_public_observation_20261020.py',
    'tests/test_k8s_selected_content_all_namespaces_20261020.py',
    'tests/test_k8s_selected_log_sample_production_20261020.py',
    'tests/test_k8s_selected_log_sample_secret_review_20261020.py',
    'tests/test_k8s_selected_metadata_production_20261020.py',
    'tests/test_k8s_selected_metadata_runtime_gates_20261020.py',
    'tests/test_k8s_selected_metadata_secret_admission_20261020.py',
    'tests/test_k8s_selected_metadata_secret_review_20261020.py',
    'tests/test_k8s_workloads_native_review_20261020.py',
    'tests/test_provider_recorded_review_conservation_20261020.py',
    'tests/test_provider_source_inventory_audit.py',
    'tests/test_public_source_secret_observed_20261020.py',
    'tests/test_secret_findings_incomplete_positive_20261020.py',
    'tests/test_selected_configuration_content_observed_20261020.py',
    'tests/test_selected_content_observed_20261020.py',
    'tests/test_selected_secret_source_successors_20261020.py',

    *RUNTIME_ADMISSION_INPUTS,
    "tests/test_provider_container_admission_inputs_20261020.py",
    "docs/evidence-reviews/*.json", "docs/finding-groups.md", "docs/check-scope-review.csv",
    "scripts/audit_observed_evidence.py", "scripts/sync_evidence_explanation_copy.py",
    "tests/test_gcp_evidence_explanations_review.py",
    "tests/test_attack_detection*.py",
    "tests/test_attack_history_worker_s3.py",
    "tests/test_peaso_ai_review.py", "tests/test_peaso_aws_priority_tags_native.py",
    "tests/test_peaso_aws_bulk_inventory.py", "tests/test_peaso_workflow_failures.py",
    "tests/test_aws_identity_sdk_closure_review.py", "docs/aws-review/identity-closure-review.json",
    "docs/aws-review/identity-sdk-closure-review.json",
    "tests/test_gcp_source_parity_review.py", "scripts/audit_gcp_source_parity.py",
    "docs/gcp-review/source-parity.json", "tests/fixtures/gcp-workbench-source-parity.json.gz",
    "tests/test_principal_exposure.py", "tests/test_privesc_grant_evidence.py",
    "docs/ai-review/*.md", "docs/security-review-2026-10-19.md",
    "tests/fixtures/aws_evidence_review.json.gz", "tests/fixtures/azure_evidence_review.json.gz",
    "tests/fixtures/gcp-reviewed-evidence.json", "tests/fixtures/shared_evidence_review.json",
    "docs/compliance-ledgers/*.json", "docs/compliance-ledgers/*.md",
    "docs/compliance-ledgers/descriptions/*.json", "docs/compliance-ledgers/descriptions/*.md",
    "docs/compliance-ledgers/inputs/*.json", "docs/compliance-ledgers/provenance/*.json",
    "docs/compliance-ledgers/inputs/compliance-requirements-matrix.json.gz", "docs/compliance-ledgers/inputs/compliance-requirements-summary.json",
    "docs/compliance-ledgers/inputs/compliance-runtime-coverage.json",
    "docs/collectors/azure-certificate-issuance-native.md",
    "docs/cli-iam.md", "docs/permission-severity-policy.md", "docs/permission-categorization-sync.md",
    "tests/fixtures/native-kind-network-v27.json",
    "tests/fixtures/aws-region-customer-policy-history.json",
    "tests/customer_policy_history.py",
    "tests/fixtures/aws-customer-policy-history-synthetic.json.gz",
    "tests/fixtures/aws_bulk_clarity_reviewed.json.gz",
    "tests/fixtures/aws_final_clarity_reviewed.json.gz",
    "tests/fixtures/azure_bulk_clarity_reviewed.json.gz",
    "tests/fixtures/aws_compute_storage_signed_cases.json",
    "tests/fixtures/post_dfaf_integration/source414-native-catalog-baseline.json.gz",
    "tests/fixtures/azure_core6.json",
    "tests/conftest.py", "tests/compliance_draft_isolation.py", "tests/compliance_source_conservation.py",
    "tests/test_combined_release_gate.py", "tests/fixtures/remediation_aws_reviewed_overlay.json",
    "tests/fixtures/markdown_anchor_expected.json",
    "tests/test_next20_aws.py",
    "tests/fixtures/next20_aws.json",
    "tests/test_secret_rotation_collector.py",
    "tests/test_azure_apim_native.py",
    "tests/test_gcp_audit_native.py",
    'tests/test_post_dfaf_aws.py',
    'tests/test_post_dfaf_azure.py',
    'tests/fixtures/post_dfaf_aws.json',
    'tests/fixtures/post_dfaf_azure/cases.json',
    'tests/fixtures/post_dfaf_integration/conservation.json',
    'tests/fixtures/post_dfaf_integration/contract.json',
    'tests/fixtures/post_dfaf_integration/derived-row-preimages.json',
    "tests/fixtures/batch_remaining_gcp_k8s/central-fixture-fragment.json",
    "tests/fixtures/batch_remaining_gcp_k8s/full-id-disposition.json",
    "tests/fixtures/batch_remaining_azure_vm_storage/central-fixture-fragment.json",
    "tests/fixtures/batch_remaining_azure_vm_storage/full-id-disposition.json",
    "Blue-AWSPEAS.py", "tests/test_blue_awspeas_access_analyzer_read_only.py",
    "tests/fixtures/privesc/synthetic_aws.py", "tests/fixtures/privesc/catalog/*/fixture.yaml",
    "tests/release_successor_history.py", "tests/aws_tag_policy_fixture.py",
    "tests/archived_check_contract.py", "tests/backup_c5_fixture_data.py",
    "tests/gcp_archived_native_contract.py", "tests/reviewed_guidance_presentation.py",
    "tests/elb_native_policy_fixture.py", "tests/nsg_service_observation_fixture.py",
    "tests/release_test_inputs.py", "tests/fixtures/release-test-inputs.json.xz",
    "tests/fixtures/hacktricks-source-revisions.json",
    "tests/fixtures/post_dfaf_integration/pre_bulk_views.json.gz",
    "tests/fixtures/post_dfaf_integration/sprint_source_changes.json",
    "tests/fixtures/post_dfaf_integration/*",
    "tests/fixtures/privesc_scoped/*.yaml",
    "docs/privesc-ledgers/source-validation-*.json.gz",
    "docs/privesc-ledgers/scoped-live-validation-20261014.json",
    "scripts/__init__.py", "scripts/check_test_skips.py",
    # Exact retained source epoch inputs needed for standalone reproduction.
    '.gitignore',
    'Blue-AzurePEAS.py',
    'Blue-GCPPEAS.py',
    'Blue-K8sPEAS.py',
    'aws_permissions_cat.yaml',
    'azure_permissions_cat.yaml',
    'bluepeass/finding_blacklist.yaml',
    'bluepeass/finding_filters.py',
    'bluepeass/hardening.py',
    'bluepeass/hardening_catalog.json',
    'bluepeass/hardening_report.py',
    'bluepeass/normalize.py',
    'bluepeass/progress.py',
    'bluepeass/progress_pool.py',
    'bluepeass/report.py',
    'docs/ai-review/example-priorities-input.json',
    'docs/ai-review/example-result.json',
    'docs/attack-analysis.md',
    'docs/aws-resource-policy-coverage.json',
    'docs/aws-resource-policy-review.md',
    'docs/aws-review/README.md',
    'docs/aws-review/absent-useful-controls.json',
    'docs/aws-review/checklist.csv',
    'docs/aws-review/checklist.inputs.json',
    'docs/aws-review/core-semantic-review.json',
    'docs/aws-review/core-semantic-review.md',
    'docs/aws-review/current-upstream-comparison.json',
    'docs/aws-review/data-sdk-closure-review.json',
    'docs/aws-review/data-sdk-closure-review.md',
    'docs/aws-review/dual-scanner-review.md',
    'docs/aws-review/ec2-public-reachability-review.json',
    'docs/aws-review/ec2-public-reachability-review.md',
    'docs/aws-review/field-producers.json',
    'docs/aws-review/field-producers.md',
    'docs/aws-review/framework-mappings.json',
    'docs/aws-review/framework-mappings.md',
    'docs/aws-review/iam-hcl-contract-recheck.json',
    'docs/aws-review/iam-report-role-acceptance.json',
    'docs/aws-review/identity-closure-review.md',
    'docs/aws-review/identity-sdk-closure-review.md',
    'docs/aws-review/identity-semantic-review.json',
    'docs/aws-review/identity-semantic-review.md',
    'docs/aws-review/latest-acceptance.json',
    'docs/aws-review/live-metadata-smoke.json',
    'docs/aws-review/native-contract-review.md',
    'docs/aws-review/native-contracts.json',
    'docs/aws-review/network-closure-review.json',
    'docs/aws-review/network-closure-review.md',
    'docs/aws-review/network-cross-service-sdk-review.json',
    'docs/aws-review/network-cross-service-sdk-review.md',
    'docs/aws-review/network-sdk-closure-review.json',
    'docs/aws-review/network-sdk-closure-review.md',
    'docs/aws-review/network-semantic-review.json',
    'docs/aws-review/network-semantic-review.md',
    'docs/aws-review/optional-lambda-public-pipeline-review.json',
    'docs/aws-review/optional-lambda-public-pipeline-review.md',
    'docs/aws-review/proposed-mapping-corrections.json',
    'docs/aws-review/proposed-partial-signal-additions.json',
    'docs/aws-review/prowler-parity.json',
    'docs/aws-review/prowler-parity.md',
    'docs/aws-review/prowler-predicate-delta.json',
    'docs/aws-review/remaining-source-exclusions.json',
    'docs/aws-review/remaining-source-exclusions.md',
    'docs/aws-review/remaining-source-review.json',
    'docs/aws-review/remaining-source-review.md',
    'docs/aws-review/requirement-associations.json',
    'docs/aws-review/requirement-decisions.json',
    'docs/aws-review/service-family-review.json',
    'docs/aws-review/service-family-review.md',
    'docs/aws-review/services-closure-review.json',
    'docs/aws-review/services-closure-review.md',
    'docs/aws-review/source-conservation-decisions.json',
    'docs/aws-review/steampipe-parity.json',
    'docs/aws-review/steampipe-parity.md',
    'docs/aws-review/trail-kms-sdk-closure-review.json',
    'docs/aws-review/trail-kms-sdk-closure-review.md',
    'docs/aws-review/userdata-dual-acceptance.json',
    'docs/aws-review/userdata-live-smoke.json',
    'docs/aws-review/workload-resource-followup-review.json',
    'docs/aws-review/workload-resource-followup-review.md',
    'docs/aws-review/workload-sdk-closure-review.json',
    'docs/aws-review/workload-sdk-closure-review.md',
    'docs/azure-native-per-user-mfa.md',
    'docs/compliance-ledgers/native-extensions/aws-20261019.json',
    'docs/finding-type-review.csv',
    'docs/finding-types.md',
    'docs/gcp-review/additional-literal-secret-review.json',
    'docs/gcp-review/additional-literal-secret-review.md',
    'docs/gcp-review/appengine-source-integration.json',
    'docs/gcp-review/appengine-source-integration.md',
    'docs/gcp-review/appengine-source-secret-review.json',
    'docs/gcp-review/artifact-file-secret-review.json',
    'docs/gcp-review/artifact-file-secret-review.md',
    'docs/gcp-review/authentication-contract-review.json',
    'docs/gcp-review/authentication-contract-review.md',
    'docs/gcp-review/backup-alert-native-review.json',
    'docs/gcp-review/backup-alert-native-review.md',
    'docs/gcp-review/checklist.csv',
    'docs/gcp-review/checklist.inputs.json',
    'docs/gcp-review/clarity-reconciliation.json',
    'docs/gcp-review/clarity-reconciliation.md',
    'docs/gcp-review/cloudbuild-artifact-secret-review.json',
    'docs/gcp-review/cloudbuild-log-integration.json',
    'docs/gcp-review/cloudbuild-log-integration.md',
    'docs/gcp-review/cloudbuild-log-secret-review.json',
    'docs/gcp-review/clouddeploy-source-secret-review.json',
    'docs/gcp-review/cloudrun-image-integration.json',
    'docs/gcp-review/cloudrun-image-integration.md',
    'docs/gcp-review/composer-source-secret-review.json',
    'docs/gcp-review/composer-source-secret-review.md',
    'docs/gcp-review/compute-network-review.json',
    'docs/gcp-review/compute-network-review.md',
    'docs/gcp-review/configuration-secret-review.json',
    'docs/gcp-review/configuration-secret-review.md',
    'docs/gcp-review/content-source-planners-review.json',
    'docs/gcp-review/content-source-planners-review.md',
    'docs/gcp-review/dataform-secret-review.json',
    'docs/gcp-review/dataform-secret-review.md',
    'docs/gcp-review/final-detector-fix.json',
    'docs/gcp-review/final-parity-collector-fix.json',
    'docs/gcp-review/final-release-acceptance.json',
    'docs/gcp-review/followup-content-integration.json',
    'docs/gcp-review/followup-content-integration.md',
    'docs/gcp-review/function-secret-review.json',
    'docs/gcp-review/function-secret-review.md',
    'docs/gcp-review/function-source-secret-review.json',
    'docs/gcp-review/function-source-secret-review.md',
    'docs/gcp-review/gcr-image-review.json',
    'docs/gcp-review/gcr-image-review.md',
    'docs/gcp-review/git-content-primitives-review.json',
    'docs/gcp-review/gke-literal-secret-review.json',
    'docs/gcp-review/gke-literal-secret-review.md',
    'docs/gcp-review/identity-data-review.json',
    'docs/gcp-review/identity-data-review.md',
    'docs/gcp-review/image-secret-review.json',
    'docs/gcp-review/image-secret-review.md',
    'docs/gcp-review/intake-fixture-reconciliation.json',
    'docs/gcp-review/intake-fixture-reconciliation.md',
    'docs/gcp-review/job-literal-secret-review.json',
    'docs/gcp-review/job-literal-secret-review.md',
    'docs/gcp-review/log-secret-review.json',
    'docs/gcp-review/log-secret-review.md',
    'docs/gcp-review/metric-alert-semantic-followup.json',
    'docs/gcp-review/metric-alert-semantic-followup.md',
    'docs/gcp-review/native-contracts.json',
    'docs/gcp-review/native-extension-integration.json',
    'docs/gcp-review/native-extension-integration.md',
    'docs/gcp-review/notebook-airflow-secret-review.json',
    'docs/gcp-review/notebook-airflow-secret-review.md',
    'docs/gcp-review/os-security-update-review.json',
    'docs/gcp-review/os-security-update-review.md',
    'docs/gcp-review/project-logging-review.json',
    'docs/gcp-review/project-logging-review.md',
    'docs/gcp-review/secret-integration-acceptance.json',
    'docs/gcp-review/secret-integration-acceptance.md',
    'docs/gcp-review/secret-surfaces.json',
    'docs/gcp-review/secret-surfaces.md',
    'docs/gcp-review/selected-archive-secret-review.json',
    'docs/gcp-review/selected-archive-secret-review.md',
    'docs/gcp-review/selected-object-secret-review.json',
    'docs/gcp-review/selected-object-secret-review.md',
    'docs/gcp-review/source-parity.md',
    'docs/gcp-review/source-repositories-native-contract-review.json',
    'docs/gcp-review/source-repositories-native-contract-review.md',
    'docs/gcp-review/sourcerepo-secret-review.json',
    'docs/gcp-review/sql-transport-semantic-followup.json',
    'docs/gcp-review/sql-transport-semantic-followup.md',
    'docs/gcp-review/upstream-head-recheck.json',
    'docs/gcp-review/workbench-requirement-decisions.json',
    'docs/gcp-review/workbench-review.json',
    'docs/hacktricks-checklist-review.csv',
    'docs/hacktricks-checklist-review.md',
    'docs/hacktricks-permission-inventory.csv',
    'docs/hardening-catalog-review.csv',
    'docs/hardening-catalog-review.md',
    'docs/permission-identifier-corrections.csv',
    'docs/permission-severity-audit.csv',
    'docs/principal-exposure.md',
    'examples/aws-demo-report.json',
    'examples/aws-demo-report.md',
    'examples/aws-demo-snapshot.json',
    'examples/aws-live-minimal-request.json',
    'examples/benchmark_peaso.py',
    'examples/benchmark_peaso_k8s.py',
    'examples/benchmark_peaso_saved_snapshot.py',
    'examples/benchmark_peaso_iam.py',
    'examples/benchmark_peaso_leaks.py',
    'examples/benchmark_peaso_secret_batch_capacity.py',
    'examples/benchmark_peaso_network.py',
    'examples/benchmark_peaso_network_paging.py',
    'scripts/benchmark_api_grouped_selection.py',
    'scripts/benchmark_api_principal_hydration.py',
    'scripts/benchmark_api_summary_rendering.py',
    'scripts/benchmark_report_publication_summary.py',
    'tests/test_peaso_finding_summary_shared_constants.py',
    'tests/test_peaso_principal_finding_hydration.py',
    'tests/test_peaso_network_page_index.py',
    'tests/test_peaso_grouped_selection_paging_regression.py',
    'tests/fixtures/gcp_evidence_explanations_predecessor_b775.py.gz',
    'examples/verify_installed_peaso.py',
    'frontend/.gitignore',
    'frontend/tests/fixtures/aws-batch-evidence.json',
    'frontend/tests/fixtures/aws-core-evidence.json',
    'frontend/tests/fixtures/aws-devtools-evidence.json',
    'frontend/tests/fixtures/aws-iam-evidence.json',
    'frontend/tests/fixtures/aws-identity-b-evidence.json',
    'frontend/tests/fixtures/aws-identity-evidence.json',
    'frontend/tests/fixtures/aws-initial-evidence.json',
    'frontend/tests/fixtures/aws-network-evidence.json',
    'frontend/tests/fixtures/aws-network-rest-evidence.json',
    'frontend/tests/fixtures/aws-policy-evidence.json',
    'frontend/tests/fixtures/aws-scalar-evidence.json',
    'frontend/tests/fixtures/aws-security-b-evidence.json',
    'frontend/tests/fixtures/aws-security-b-rest-evidence.json',
    'frontend/tests/fixtures/aws-security-evidence.json',
    'frontend/tests/fixtures/aws-tooling-evidence.json',
    'frontend/tests/fixtures/azure-reviewed-evidence.json',
    'gcp_permissions_cat.yaml',
    'infra/aws/.gitignore',
    'infra/aws/customer-role-d43535005ba3ccf7c3179253d2dadb4ff6c521eb26884c571bc1f01c780995b8.json',
    'peaso/rulepacks/upstream_manifest.json.gz',
    'requirements.txt',
    'scripts/attack_detection_coverage.py',
    'scripts/attack_detection_rule_source_ledger.py',
    'scripts/attack_detection_technique_inventory.py',
    'scripts/audit_aws_field_producers.py',
    'scripts/audit_aws_framework_mappings.py',
    'scripts/audit_aws_native_contracts.py',
    'scripts/audit_aws_prowler_parity.py',
    'scripts/audit_aws_requirement_associations.py',
    'scripts/audit_aws_resource_policy_coverage.py',
    'scripts/audit_aws_review_checklist.py',
    'scripts/audit_aws_steampipe_parity.py',
    'scripts/audit_finding_types.py',
    'scripts/audit_gcp_native_contracts.py',
    'scripts/audit_gcp_review_checklist.py',
    'scripts/audit_hacktricks_scope.py',
    'scripts/audit_network_service_dispositions.py',
    'scripts/audit_network_service_inventory.py',
    'scripts/audit_provider_source_inventory.py',
    'scripts/azure_function_package_runtime_proof_20261020.py',
    'scripts/check_cloudpeass_risk_parity.py',
    'scripts/classify_permissions.py',
    'scripts/hardening_catalog_context.py',
    'scripts/peaso_test_resources/README.md',
    'scripts/permission_risk_classifier.py',
    'scripts/refresh_risk_catalogs.py',
    'scripts/review_hardening_catalog.py',
    'scripts/sync_cloudpeass_risks.py',
    'scripts/update_permission_categories.py',
    'scripts/verify_gcp_cloudrun_v2_job_declared_images_20261020.py',
    'tests/connector_owner_fixture_20261020.json',
    'tests/e2e/test_api_lifecycle.py',
    'tests/e2e/test_azure_eventual_inventory.py',
    'tests/e2e/test_cli_stdout_acceptance.py',
    'tests/e2e/test_credential_fact_preservation.py',
    'tests/e2e/test_engine_contract.py',
    'tests/e2e/test_fixture_ownership.py',
    'tests/e2e/test_gcp_auth_acceptance_transport.py',
    'tests/e2e/test_gcp_live_acceptance_runner.py',
    'tests/e2e/test_gcp_live_fixture_guards.py',
    'tests/e2e/test_metadata_credential_redaction.py',
    'tests/fixtures/aws_cloudtrail_historical_object_lab_events.json',
    'tests/fixtures/aws_cloudtrail_log_destination_lab_events.json',
    'tests/fixtures/aws_cognito_federation_lab_events.json',
    'tests/fixtures/aws_cognito_identity_lab_events.json',
    'tests/fixtures/aws_cognito_import_lab_events.json',
    'tests/fixtures/aws_cognito_mfa_lab_events.json',
    'tests/fixtures/aws_cognito_update_lab_events.json',
    'tests/fixtures/aws_ecs_lab_events.json',
    'tests/fixtures/aws_emr_serverless_lab_events.json',
    'tests/fixtures/aws_emr_serverless_session_lab_events.json',
    'tests/fixtures/aws_iam_federation_deletion_lab_events.json',
    'tests/fixtures/aws_iam_federation_provider_lab_events.json',
    'tests/fixtures/aws_iam_saml_provider_lab_events.json',
    'tests/fixtures/aws_iot_core_batch_lab_events.json',
    'tests/fixtures/aws_iot_provision_jobs_lab_events.json',
    'tests/fixtures/aws_kinesis_capacity_lab_events.json',
    'tests/fixtures/aws_kinesis_channel_lab_event.json',
    'tests/fixtures/aws_kinesis_controls_extended_lab_events.json',
    'tests/fixtures/aws_kinesis_lab_events.json',
    'tests/fixtures/aws_kinesis_video_lab_events.json',
    'tests/fixtures/aws_lambda_access_mapping_lab_events.json',
    'tests/fixtures/aws_lambda_privesc_batch_events.json',
    'tests/fixtures/aws_observed_evidence_successors.json',
    'tests/fixtures/aws_rds_mysql_replica_lab_events.json',
    'tests/fixtures/aws_rds_parameter_replica_lab_events.json',
    'tests/fixtures/aws_rds_proxy_master_secret_lab_events.json',
    'tests/fixtures/aws_rds_restore_chain_lab_events.json',
    'tests/fixtures/aws_rds_snapshot_controls_lab_events.json',
    'tests/fixtures/aws_resource_explorer_lab_events.json',
    'tests/fixtures/aws_resource_policy_pre_scope_review.json',
    'tests/fixtures/aws_rolesanywhere_lab_events.json',
    'tests/fixtures/aws_s3_ssec_ransomware_lab_events.json',
    'tests/fixtures/aws_secretsmanager_followup_lab_events.json',
    'tests/fixtures/aws_ses_receipt_lab_events.json',
    'tests/fixtures/aws_sfn_activity_alias_lab_events.json',
    'tests/fixtures/aws_sfn_redrive_lab_events.json',
    'tests/fixtures/aws_sqs_fifo_collision_lab_events.json',
    'tests/fixtures/aws_sqs_followup_management_events.json',
    'tests/fixtures/aws_sqs_message_visibility_lab_events.json',
    'tests/fixtures/aws_ssm_association_command_lab_events.json',
    'tests/fixtures/aws_ssm_automation_activation_window_lab_events.json',
    'tests/fixtures/aws_ssm_managed_node_lab_events.json',
    'tests/fixtures/aws_ssm_parameter_read_lab_events.json',
    'tests/fixtures/aws_stepfunctions_controls_lab_events.json',
    'tests/fixtures/aws_sts_role_cycle_lab_events.json',
    'tests/fixtures/aws_sts_web_token_lab_events.json',
    'tests/fixtures/aws_supportauthz_lab_events.json',
    'tests/fixtures/aws_vpc_network_lab_events.json',
    'tests/fixtures/bulk_pending_behavior.json',
    'tests/fixtures/gcp-native-review-behavior.json',
    'tests/fixtures/gcp-natural-evidence-golden.json',
    'tests/fixtures/gcp-psc-admission-history.json.gz',
    'tests/fixtures/native_admission_cpu_predecessor_epoch_20261020.json.gz',
    'tests/fixtures/privesc_bounded/aws.yaml',
    'tests/fixtures/privesc_bounded/azure.yaml',
    'tests/fixtures/privesc_bounded/gcp.yaml',
    'tests/integration/kubernetes-auditor.yaml',
    'tests/integration/kubernetes-hardening.yaml',
    'tests/observed_evidence_successors.py',
    'tests/probe_connector_static_20261020.py',
    'tests/test_api_finding_types_static_20261020.py',
    'tests/test_api_report_projection_static_20261020.py',
    'tests/test_archived_check_contract.py',
    'tests/test_attack_history_ledger.py',
    'tests/test_attack_history_sqlite.py',
    'tests/test_attack_log_source.py',
    'tests/test_attack_rule_source_selection.py',
    'tests/test_aws_additional_secret_review_20261019.py',
    'tests/test_aws_alb_waf_association_metadata.py',
    'tests/test_aws_beanstalk_runtime_metadata_review.py',
    'tests/test_aws_cloudtrail_s3_delivery_metadata_review.py',
    'tests/test_aws_cognito_rotation_review_20261019.py',
    'tests/test_aws_configuration_payload_secret_review_20261019.py',
    'tests/test_aws_configuration_secret_review_20261019.py',
    'tests/test_aws_core_semantic_review_20261019.py',
    'tests/test_aws_current_source_parity_review.py',
    'tests/test_aws_data_sdk_closure_review.py',
    'tests/test_aws_ec2_clock_metadata_review.py',
    'tests/test_aws_ec2_public_reachability_review.py',
    'tests/test_aws_enclave_debug_review_20261019.py',
    'tests/test_aws_field_producer_review.py',
    'tests/test_aws_framework_mapping_review.py',
    'tests/test_aws_global_subject_binding_review.py',
    'tests/test_aws_iam_read_report_selection_review.py',
    'tests/test_aws_identity_closure_review.py',
    'tests/test_aws_identity_semantic_review.py',
    'tests/test_aws_kms_enclave_inventory.py',
    'tests/test_aws_kms_enclave_review_20261019.py',
    'tests/test_aws_lambda_role_policy_review_20261019.py',
    'tests/test_aws_launch_template_instance_metadata_review.py',
    'tests/test_aws_native_contract_review.py',
    'tests/test_aws_network_closure_review.py',
    'tests/test_aws_network_cross_service_sdk_review.py',
    'tests/test_aws_network_sdk_closure_review.py',
    'tests/test_aws_network_semantic_review.py',
    'tests/test_aws_optional_lambda_public_pipeline_review.py',
    'tests/test_aws_package_content_review_20261019.py',
    'tests/test_aws_policy_constraints_review_20261019.py',
    'tests/test_aws_prowler_parity_review.py',
    'tests/test_aws_requirement_association_review.py',
    'tests/test_aws_requirement_decision_acceptance.py',
    'tests/test_aws_resource_policy_coverage.py',
    'tests/test_aws_s3_object_acl_review_20261019.py',
    'tests/test_aws_service_family_semantic_review.py',
    'tests/test_aws_service_status_review_20261019.py',
    'tests/test_aws_services_closure_review.py',
    'tests/test_aws_steampipe_parity_review.py',
    'tests/test_aws_trail_kms_sdk_closure_review.py',
    'tests/test_aws_user_data_secret_projection_review.py',
    'tests/test_aws_userdata_dual_secret_scan_review.py',
    'tests/test_aws_workload_resource_followup_review.py',
    'tests/test_aws_workload_sdk_closure_review.py',
    'tests/test_azure_auth.py',
    'tests/test_azure_self_grant_detector.py',
    'tests/test_catalog_review.py',
    'tests/test_cloudpeass_criticality.py',
    'tests/test_compose_api_receipt.py',
    'tests/test_dual_secret_scanning_review.py',
    'tests/test_ecs_volume_native_provenance.py',
    'tests/test_entra_attack_logs.py',
    'tests/test_finding_filters.py',
    'tests/test_gcp_additional_literal_secret_review_20261019.py',
    'tests/test_gcp_appengine_source_integration_review.py',
    'tests/test_gcp_appengine_source_secret_review_20261019.py',
    'tests/test_gcp_artifact_file_secret_review_20261019.py',
    'tests/test_gcp_attack_logs.py',
    'tests/test_gcp_authentication_contract_review.py',
    'tests/test_gcp_cloudbuild_artifact_integration_review.py',
    'tests/test_gcp_cloudbuild_artifact_secret_review_20261019.py',
    'tests/test_gcp_cloudbuild_content_sources_review.py',
    'tests/test_gcp_cloudbuild_log_integration_review.py',
    'tests/test_gcp_cloudbuild_log_secret_review_20261019.py',
    'tests/test_gcp_clouddeploy_source_integration_review.py',
    'tests/test_gcp_clouddeploy_source_secret_review_20261019.py',
    'tests/test_gcp_cloudrun_content_sources_review.py',
    'tests/test_gcp_cloudsql_backup_alert_native_review.py',
    'tests/test_gcp_composer_source_secret_review_20261019.py',
    'tests/test_gcp_compute_network_review_20261019.py',
    'tests/test_gcp_configuration_secret_review_20261019.py',
    'tests/test_gcp_content_scan_selection_review.py',
    'tests/test_gcp_cross_surface_secret_dedup.py',
    'tests/test_gcp_dataform_secret_review_20261019.py',
    'tests/test_gcp_function_secret_review_20261019.py',
    'tests/test_gcp_function_source_secret_review_20261019.py',
    'tests/test_gcp_gcr_secret_images_review.py',
    'tests/test_gcp_git_content_review.py',
    'tests/test_gcp_git_transport_review.py',
    'tests/test_gcp_gke_literal_secret_review_20261019.py',
    'tests/test_gcp_identity_data_review_20261019.py',
    'tests/test_gcp_image_secret_review_20261019.py',
    'tests/test_gcp_log_secret_review_20261019.py',
    'tests/test_gcp_metric_alert_semantic_followup.py',
    'tests/test_gcp_natural_evidence_review.py',
    'tests/test_gcp_notebook_airflow_secret_review_20261019.py',
    'tests/test_gcp_optional_default_transport_contract.py',
    'tests/test_gcp_os_security_update_review_20261019.py',
    'tests/test_gcp_project_logging_review_20261019.py',
    'tests/test_gcp_secret_integration_acceptance_review.py',
    'tests/test_gcp_secret_surface_inventory.py',
    'tests/test_gcp_sourcerepo_integration_review.py',
    'tests/test_gcp_sourcerepo_secret_review_20261019.py',
    'tests/test_gcp_sql_transport_semantic_followup.py',
    'tests/test_gcp_workbench_review_20261019.py',
    'tests/test_hacktricks_checklist_scope.py',
    'tests/test_hardening.py',
    'tests/test_hardening_grouping.py',
    'tests/test_k8s.py',
    'tests/test_native_admission_cpu_successor_20261020.py',
    'tests/test_native_policy_validation_static_20261020.py',
    'tests/test_permission_identifiers.py',
    'tests/test_permission_severity_policy.py',
    'tests/test_query_context.py',
)
# This opt-in contract is only for the reviewed, failed initial CSPM deployment.
RECOVERY_FAILED_PLAN_SHA256 = "6abd03527bca42c00cb9ea2ebf8b0c43e912270f9e317c9a04fb0a2f2d0ad409"
RECOVERY_FAILED_JSON_SHA256 = "f9f99e434927dae2683cc286af761d2e507874e1bd343ad8f194264db7ea6141"
RECOVERY_ENRICHMENT_SHA256 = "15c0fb3193c6ac22299802c6866ff689a85f7af374a483d169dcc4a00cfb9c71"
RECOVERY_ENRICHMENT_APPROVAL = "msg_89daa0d2fb65"
RECOVERY_BACKEND = deployment.backend()
RECOVERY_MISSING = {"aws_cloudfront_distribution.cspm", "aws_s3_bucket_policy.frontend",
                    'aws_route53_record.cspm["A"]', 'aws_route53_record.cspm["AAAA"]'}
RECOVERY_ACTIONS = {
    "aws_lambda_function.api": (["update"], "source-runtime-lambda"),
    "aws_lambda_function.scheduler": (["update"], "source-runtime-lambda"),
    'aws_ecs_task_definition.tasks["collector"]': (["delete", "create"], "immutable-task-revision"),
    'aws_ecs_task_definition.tasks["analyzer"]': (["delete", "create"], "immutable-task-revision"),
    "aws_sfn_state_machine.scan": (["update"], "workflow-task-references"),
    "aws_iam_role_policy.workflow": (["update"], "workflow-iam-task-references"),
}
# Reviewed expressions used by deployment_expectations; changing these inputs
# requires reviewing that contract, not silently deferring additional values.
RUNTIME_CONFIG_SHA256 = {
    "outputs.tf": "e83fb597d6cb6f4b42e57b44480a1bd7eb7acfce961102c4504640ab0ac8b54d",
    "storage.tf": "40033ed25c5ac8bfae9a99016f959a25f5d431b6e202ffb602c2a78a0f223b22",
    "iam.tf": "119086927a14a48dc52f0180eb10a75f0d6355a848de200b8028a1325d268e39",
    "api.tf": "7f247794ef85ce194f099334548b10a7dbfa94ffd85875f1fe29533b67197eda",
    "workflow.tf": "de9c466b4f91cf3490e21ba48bdf5d721527bd2d75a5fc48493f160e911514fe",
    "variables.tf": "2824bc1ff26a1cb2bdc97109bd911d301ee1df29688253d5c2cd22236b928a58",
    "versions.tf": "2b3b22273e0f514fd6b66be276cc47d20598f68e45ccd8537ee17e2cdbd2efff",
    "network.tf": "9b9b839d185551282d2e771bd779c069678099690740b7ef0b4d26acb6cee34e",
    "ai_runtime.tf": "3a1e98be34ff47397d6fb83f5a7f6fdddaaf51f7b8dc4a2c3cdad676e6d017ab",
    "ai_network.tf": "e180dee4032309d52455d23a59062a536dd231caa874a78b17057b7115308eab",
}
# Explicitly reviewed two-hour runtime successor; retain the historical source pin.
RUNTIME_LIMITS_PREDECESSOR_SHA256 = "2c9bdcfc7e08edb02c36dc1640692e1d00a412b326053c8120eff70257870554"
RUNTIME_LIMITS_CURRENT_SHA256 = "12845ef9a58c6d1064d21054b2f54577c594e30e4773fa36bda1988e593bcd4d"
RUNTIME_LIMITS_EXACT_REPLACEMENTS = (
    (b"workflow_seconds = 3600", b"workflow_seconds = 7200"),
    (b"stage_seconds    = 1800", b"stage_seconds    = 7200"),
    (b"lease_seconds    = 3900", b"lease_seconds    = 7500"),
    (b"var.scan_runtime_limits.workflow_seconds <= 3600", b"var.scan_runtime_limits.workflow_seconds <= 7200"),
    (b"var.scan_runtime_limits.stage_seconds <= 3600", b"var.scan_runtime_limits.stage_seconds <= 7200"),
    (b"var.scan_runtime_limits.lease_seconds <= 3900", b"var.scan_runtime_limits.lease_seconds <= 7500"),
    ("900–3600s, stages 300–3600s".encode(), "900–7200s, stages 300–7200s".encode()),
    (b"(at most3900s)", b"(at most7500s)"),
)
# Reviewed 39ff93f IAM successor: the API role may read only the configured
# Codex token secret ARN. The original runtime contract hashes stay intact.
IAM_RUNTIME_CURRENT_SHA256 = "319e90d9f2f377be919c815ed27f433ae4f45868bbf3bb984f36c9fddfc213a2"
IAM_RUNTIME_EXACT_ADDITION = (
    b'    ], var.codex_token_secret_arn == "" ? [] : [\n'
    b'    { Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = var.codex_token_secret_arn }\n'
)
# Reviewed durable queue and parallel-stage successors in f51b813d and
# 804ee202. The complete file digests bind the runtime contract after those
# changes while the earlier pins above remain available for historical review.
CURRENT_IAM_RUNTIME_SHA256 = "a20b4d6d6fa5698cb55ab0fc0bed420859fe12163373c9358955a97a377285bc"
CURRENT_INDEXED_IAM_SHA256 = "8db82f1355308602a2c6f6216e8aba42ebd23ba889e7af3ea76ca0b3f7a4aea6"
INDEXED_IAM_QUERY_ADDITION = b'    { Effect = "Allow", Action = ["dynamodb:Query"], Resource = ["${aws_dynamodb_table.metadata.arn}/index/work-state", "${aws_dynamodb_table.metadata.arn}/index/schedule-time"] },\n'
PREVIOUS_WORKFLOW_RUNTIME_SHA256 = "caed9a12c8d11c12e14d87cb74d1fdef83567648287c1d654f926114cd227d64"
CURRENT_WORKFLOW_RUNTIME_SHA256 = "ecfaa71f9c9668d02e59571efa7a7b9e5daf6af1da9a22501a23611cf9e565a3"
CURRENT_INDEXED_WORKFLOW_SHA256 = "361fef2318aef55d01ba351501cc79a4fa06884d368d380b714f2f42814e57ad"
INDEXED_WORKFLOW_ADDITION = b'    PEASO_WORK_STATE_INDEX         = "work-state"\n    PEASO_SCHEDULE_TIME_INDEX      = "schedule-time"\n'
CURRENT_AI_RUNTIME_SHA256 = "0948bda88c41ea79fd25dc9c2faa656b7d71c9d29012024156017921122834a6"
API_DELIVERY_SOURCE = {
    "api.tf": ("0ad8ba2e7e2a7868c7366c84a6693e8e5c3420382cfb2946e641dab878b35efe",
               "cc8046cd30d96ead3cf0b1c9d3713a83f8a01fc81114bd31ad667852dbab1229",
               "ab8336af2ce98102c92abe6dfb6df9f4346cc8cee404e469c180c2aa4eb02787"),
    "storage.tf": ("44dd9865f0e59364e1f4d0f65e384de44efbab1ec94acb8ca393a06e78b037cc",
                   "79101ef40b01f86ddf6d6d2653f57176366b32bd5b336c0d8f40381444754774",
                   "82643965a855769dec22e34c065fc1fba2f1486b9576032e23dd6f5396c8c0b2"),
}
API_DELIVERY_CONTENT_REVERSE = {
    "api.tf": (
        (b'  function_name    = "${local.name}-api"\n  role             = aws_iam_role.api.arn\n'
         b'  runtime          = "python3.12"\n  architectures    = ["x86_64"]\n'
         b'  handler          = "peaso.server.lambda_handler.handler"\n  filename         = null\n'
         b'  s3_bucket        = aws_s3_object.api_zip.bucket\n  s3_key           = aws_s3_object.api_zip.key\n'
         b'  source_code_hash = filebase64sha256(var.api_zip)\n',
         b'  function_name     = "${local.name}-api"\n  role              = aws_iam_role.api.arn\n'
         b'  runtime           = "python3.12"\n  architectures     = ["x86_64"]\n'
         b'  handler           = "peaso.server.lambda_handler.handler"\n  filename          = null\n'
         b'  s3_bucket         = aws_s3_object.api_zip.bucket\n  s3_key            = aws_s3_object.api_zip.key\n'
         b'  s3_object_version = aws_s3_object.api_zip.version_id\n'
         b'  source_code_hash  = filebase64sha256(var.api_zip)\n'),
        (b'  s3_key                         = aws_s3_object.api_zip.key\n'
         b'  source_code_hash               = filebase64sha256(var.api_zip)\n',
         b'  s3_key                         = aws_s3_object.api_zip.key\n'
         b'  s3_object_version              = aws_s3_object.api_zip.version_id\n'
         b'  source_code_hash               = filebase64sha256(var.api_zip)\n'),
    ),
    "storage.tf": ((
        b'resource "aws_s3_object" "api_zip" {\n'
        b'  bucket                 = aws_s3_bucket.artifacts.id\n'
        b'  key                    = "runtime-packages/${filesha256(var.api_zip)}.zip"\n'
        b'  source                 = var.api_zip\n'
        b'  source_hash            = filebase64sha256(var.api_zip)\n'
        b'  server_side_encryption = "aws:kms"\n'
        b'  kms_key_id             = aws_kms_key.connectors.arn\n'
        b'  metadata               = { sha256 = filesha256(var.api_zip) }\n'
        b'}\n',
        b'resource "aws_s3_bucket_versioning" "artifacts" {\n'
        b'  bucket = aws_s3_bucket.artifacts.id\n'
        b'  versioning_configuration { status = "Enabled" }\n'
        b'}\nresource "aws_s3_object" "api_zip" {\n'
        b'  bucket                 = aws_s3_bucket.artifacts.id\n'
        b'  key                    = "runtime-packages/api.zip"\n'
        b'  source                 = var.api_zip\n'
        b'  source_hash            = filebase64sha256(var.api_zip)\n'
        b'  server_side_encryption = "aws:kms"\n'
        b'  kms_key_id             = aws_kms_key.connectors.arn\n'
        b'  metadata               = { sha256 = filesha256(var.api_zip) }\n'
        b'  depends_on             = [aws_s3_bucket_versioning.artifacts]\n'
        b'}\n'),),
}
API_DELIVERY_REVERSE = {
    "api.tf": (
        (b'  function_name     = "${local.name}-api"\n  role              = aws_iam_role.api.arn\n'
         b'  runtime           = "python3.12"\n  architectures     = ["x86_64"]\n'
         b'  handler           = "peaso.server.lambda_handler.handler"\n  filename          = null\n'
         b'  s3_bucket         = aws_s3_object.api_zip.bucket\n  s3_key            = aws_s3_object.api_zip.key\n'
         b'  s3_object_version = aws_s3_object.api_zip.version_id\n'
         b'  source_code_hash  = filebase64sha256(var.api_zip)\n',
         b'  function_name    = "${local.name}-api"\n  role             = aws_iam_role.api.arn\n'
         b'  runtime          = "python3.12"\n  architectures    = ["x86_64"]\n'
         b'  handler          = "peaso.server.lambda_handler.handler"\n  filename         = var.api_zip\n'
         b'  source_code_hash = filebase64sha256(var.api_zip)\n'),
        (b'  filename                       = null\n  s3_bucket                      = aws_s3_object.api_zip.bucket\n'
         b'  s3_key                         = aws_s3_object.api_zip.key\n'
         b'  s3_object_version              = aws_s3_object.api_zip.version_id\n',
         b'  filename                       = var.api_zip\n'),
    ),
    "storage.tf": ((
        b'resource "aws_s3_bucket_versioning" "artifacts" {\n'
        b'  bucket = aws_s3_bucket.artifacts.id\n'
        b'  versioning_configuration { status = "Enabled" }\n'
        b'}\nresource "aws_s3_object" "api_zip" {\n'
        b'  bucket                 = aws_s3_bucket.artifacts.id\n'
        b'  key                    = "runtime-packages/api.zip"\n'
        b'  source                 = var.api_zip\n'
        b'  source_hash            = filebase64sha256(var.api_zip)\n'
        b'  server_side_encryption = "aws:kms"\n'
        b'  kms_key_id             = aws_kms_key.connectors.arn\n'
        b'  metadata               = { sha256 = filesha256(var.api_zip) }\n'
        b'  depends_on             = [aws_s3_bucket_versioning.artifacts]\n'
        b'}\n', b''),),
}
ALLOWED_RESOURCES = set("""
aws_cloudwatch_log_group.api aws_cloudwatch_log_group.scheduler aws_apigatewayv2_stage.api
aws_budgets_budget.cspm aws_route53_record.cspm aws_ecs_task_definition.tasks
aws_cloudfront_distribution.cspm aws_iam_role_policy.analyzer aws_iam_role.workflow
aws_cloudfront_function.spa aws_vpc_endpoint.dynamodb aws_apigatewayv2_api.cspm
aws_cloudwatch_event_target.schedules aws_s3_bucket_policy.frontend
aws_cloudfront_origin_access_control.frontend aws_s3_bucket_public_access_block.private
aws_route_table.tasks aws_s3_bucket.artifacts aws_internet_gateway.cspm
aws_kms_alias.connectors aws_lambda_function.scheduler aws_cloudfront_response_headers_policy.security
aws_ecs_cluster.cspm aws_s3_bucket_policy.tls aws_iam_role.execution
aws_cloudwatch_metric_alarm.api_errors aws_vpc.cspm aws_sfn_state_machine.scan
aws_s3_bucket.frontend aws_lambda_permission.api aws_s3_bucket_lifecycle_configuration.artifacts
aws_s3_bucket.templates aws_s3_bucket_ownership_controls.templates aws_s3_bucket_versioning.templates
aws_s3_object.api_zip
aws_s3_bucket_server_side_encryption_configuration.templates aws_s3_bucket_public_access_block.templates
aws_s3_bucket_policy.templates aws_s3_object.customer_role_template aws_s3_object.customer_role_download
aws_s3_bucket_ownership_controls.private aws_apigatewayv2_integration.api aws_iam_role_policy.api
aws_secretsmanager_secret.credentials aws_security_group.tasks aws_iam_role.collector
aws_lambda_function.api aws_kms_key.connectors aws_iam_role_policy.workflow
aws_iam_role.analyzer aws_iam_role_policy.execution aws_dynamodb_table.metadata
aws_cloudwatch_event_rule.schedules aws_s3_bucket_server_side_encryption_configuration.private
aws_s3_bucket_cors_configuration.artifacts
random_bytes.credential_key aws_cloudwatch_log_group.tasks aws_subnet.tasks
aws_secretsmanager_secret_version.credentials aws_vpc_endpoint.s3 aws_ecr_repository.worker
aws_route_table_association.tasks aws_apigatewayv2_route.api aws_lambda_permission.schedules
aws_iam_role_policy.collector aws_ecr_lifecycle_policy.worker aws_iam_role.api
aws_iam_role.customer_trust aws_iam_role_policy.customer_trust
random_bytes.ai_key aws_kms_key.ai aws_secretsmanager_secret.ai aws_secretsmanager_secret_version.ai
aws_s3_bucket.ai_transport aws_s3_bucket_public_access_block.ai_transport
aws_s3_bucket_server_side_encryption_configuration.ai_transport aws_s3_bucket_lifecycle_configuration.ai_transport
aws_s3_bucket_policy.ai_transport aws_ecs_task_definition.ai aws_iam_role_policy.ai_dispatch
aws_subnet.ai aws_route_table_association.ai aws_security_group.ai aws_network_acl.ai
aws_ecs_cluster.ai aws_cloudwatch_log_group.ai_tasks
aws_iam_role.ai_execution aws_iam_role_policy.ai_execution
""".split())

# Keep dependency bytecode out of this cross-platform package. The API retains
# complete reviewed SDK service models; workers retain the full provider SDK.
CURRENT_API_MEMBER_LIMIT = 6000
CURRENT_API_ARCHIVE_LIMIT = 52_428_800  # Preserve the verified zipped Lambda package bound.
# Enforce a cap below Lambda's 250 MiB uncompressed limit, including
# layers (these functions declare none).
# Historical artifact-update approvals retain their original byte limits.
# https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html
CURRENT_API_UNCOMPRESSED_LIMIT = 260_000_000
# Current corresponding source has grown beyond the historical artifact-update
# contract. Keep these bounds aligned with the GitHub Actions release reviewer;
# historical artifact-update approvals retain their original measured limits.
CURRENT_SOURCE_MEMBER_LIMIT = 7000  # Current complete source inventory: 6,423 members before the final bounded performance additions.
CURRENT_SOURCE_UNCOMPRESSED_LIMIT = 600_000_000
CURRENT_SOURCE_ARCHIVE_LIMIT = 100_000_000  # Measured complete epoch: 73.8 MB ZIP / 539 MB expanded; historical caps stay fixed.


def checked_member(root, name):
    """Resolve no symlinks and permit only portable relative member names."""
    relative = Path(name)
    if not name or "\\" in name or relative.is_absolute() or any(
            part in {"", ".", ".."} for part in name.split("/")):
        raise RuntimeError(f"Unsafe generated member path: {name}")
    path = root
    for part in (None, *relative.parts):
        if part is not None:
            path = path / part
        if path.is_symlink():
            raise RuntimeError(f"Cannot use symlinks or external paths: {path}")
    return path


def generated_path(name):
    """Validate helper outputs without changing enclosing build/cache modes."""
    build = BUILD.absolute()
    root = ROOT.absolute()
    if build == root or root.is_relative_to(build):
        raise RuntimeError("Generated build directory must not enclose authored ROOT")
    if build.is_relative_to(root):
        checked_member(root, build.relative_to(root).as_posix())
    path = checked_member(build, name)
    if path.exists():
        metadata = path.stat()
        if metadata.st_uid != os.getuid() or not (stat.S_ISDIR(metadata.st_mode) or (
                stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1)):
            raise RuntimeError(f"Generated output must be owned and unlinked: {path}")
    return path


def public_tree_entries(tree):
    """Preflight every API-stage entry before any chmod or ZIP write."""
    if tree != generated_path("api-package"):
        raise RuntimeError("Public permissions apply only to generated code trees")
    if not tree.is_dir():
        raise RuntimeError(f"Missing generated public code tree: {tree}")
    entries = [tree, *sorted(tree.rglob("*"))]
    for path in entries:
        if path != tree:
            checked_member(tree, path.relative_to(tree).as_posix())
        metadata = path.stat()
        if metadata.st_uid != os.getuid() or not (stat.S_ISDIR(metadata.st_mode) or (
                stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1)):
            raise RuntimeError(f"Public code must contain owned directories or unlinked regular files: {path}")
    return entries


def public_mode(path):
    return 0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644


def normalize_public_tree(tree):
    # Validate every entry first: a late symlink/hardlink must not chmod its target.
    for path in public_tree_entries(tree):
        path.chmod(public_mode(path))


def verify_public_tree(tree):
    entries = public_tree_entries(tree)
    for path in entries:
        if stat.S_IMODE(path.stat().st_mode) != public_mode(path):
            raise RuntimeError(f"Generated public code has nonportable permissions: {path}")
    return entries


def frozen_source_entries(snapshot, names):
    # Frontend builds add node_modules/dist to this context; only the frozen
    # members and their traversal directories are public corresponding source.
    if snapshot != generated_path("source-snapshot"):
        raise RuntimeError("Frozen permissions apply only to the generated source snapshot")
    paths = {snapshot}
    for name in names:
        path = checked_member(snapshot, name)
        paths.add(path)
        paths.update(parent for parent in path.parents if parent == snapshot or parent.is_relative_to(snapshot))
    for path in paths:
        if not path.exists():
            raise RuntimeError(f"Frozen source changed: {path}; freeze and rebuild")
        metadata = path.stat()
        if metadata.st_uid != os.getuid() or not (stat.S_ISDIR(metadata.st_mode) or (
                stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1)):
            raise RuntimeError(f"Frozen public source must be owned and unlinked: {path}")
    return sorted(paths)


def normalize_frozen_permissions(snapshot, names):
    for path in frozen_source_entries(snapshot, names):
        path.chmod(public_mode(path))


def verify_frozen_permissions(snapshot, names):
    for path in frozen_source_entries(snapshot, names):
        if stat.S_IMODE(path.stat().st_mode) != public_mode(path):
            raise RuntimeError(f"Frozen public source has nonportable permissions: {path}")


def runtime_admission_data(files):
    """Require the immutable data whenever its native registry consumer ships."""
    present = {name: files[name] for name in RUNTIME_ADMISSION_INPUTS if name in files}
    consumer = "peaso/checks/azure_nsp_query_cmk_production_tde_successor_20261020.py"
    if consumer in files and set(present) != set(RUNTIME_ADMISSION_INPUTS):
        raise RuntimeError("Frozen source omits required runtime admission inputs")
    if any(digest != RUNTIME_ADMISSION_INPUTS[name] for name, digest in present.items()):
        raise RuntimeError("Frozen runtime admission input hash changed")
    return present


def source_root():
    snapshot = generated_path("source-snapshot")
    manifest_path = checked_member(snapshot, "release.json")
    manifest = generated_path("release.json")
    if not manifest_path.is_file() or not manifest.is_file():
        raise RuntimeError("Freeze the complete current working source before building")
    release = json.loads(manifest_path.read_text())
    if release != json.loads(manifest.read_text()):
        raise RuntimeError("Release manifest and source snapshot differ; freeze again")
    if not any(name.startswith("peaso/privesc/") for name in release["files"]):
        raise RuntimeError("Release must include the complete supplied peaso/privesc package")
    runtime_admission_data(release["files"])
    verify_frozen_permissions(snapshot, ["release.json", *release["files"]])
    for name, expected in release["files"].items():
        path = checked_member(snapshot, name)
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise RuntimeError(f"Frozen source changed: {name}; freeze and rebuild")
    return snapshot


def _omit_verified_duplicate_manifest(source, root=None):
    """Keep the complete canonical manifest; omit only its byte-identical gzip copy.

    Neither inputs nor history are removed from the working repository. A
    mismatched compressed companion is an integrity error, never discarded.
    """
    plain = "peaso/rulepacks/upstream_manifest.json"
    compressed = plain + ".gz"
    if plain not in source or compressed not in source:
        return
    if root is not None:
        for name in (plain, compressed):
            path = checked_member(root, name)
            if path.is_symlink() or path.stat().st_nlink != 1 or path.read_bytes() != source[name]:
                raise RuntimeError("Upstream manifest changed during freeze")
    import gzip
    import io
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(source[compressed])) as stream:
            identical = stream.read(len(source[plain]) + 1) == source[plain]
    except (OSError, EOFError, ValueError) as error:
        raise RuntimeError("Invalid redundant upstream manifest gzip") from error
    if not identical:
        raise RuntimeError("Redundant upstream manifest gzip differs from canonical JSON")
    del source[compressed]


def _omit_verified_reconstructible_privesc_history(source, root):
    """Omit only originals exactly represented by the pinned history block pack."""
    import ast
    import base64
    import gzip
    import io
    import struct
    code_name = 'peaso/privesc/versioned_catalog.py'
    pack_name = 'peaso/privesc/catalog_versions/runtime-history-v1.zip'
    if code_name not in source and pack_name not in source:
        return set()
    code, packed = source[code_name], source[pack_name]
    pinned = {node.targets[0].id: ast.literal_eval(node.value)
              for node in ast.parse(code).body if isinstance(node, ast.Assign)
              and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
              and node.targets[0].id == 'RUNTIME_HISTORY_SHA256'}
    if hashlib.sha256(packed).hexdigest() != pinned.get('RUNTIME_HISTORY_SHA256'):
        raise RuntimeError('Privesc history pack differs from runtime pin')
    if (checked_member(root, code_name).read_bytes() != code
            or checked_member(root, pack_name).read_bytes() != packed):
        raise RuntimeError('Privesc history pack changed during freeze')
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise RuntimeError('Duplicate privesc history index key')
            result[key] = value
        return result
    with zipfile.ZipFile(io.BytesIO(packed)) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or set(names) != {
                'index.json', 'blocks.bin', 'references.bin', 'manifests.bin'}:
            raise RuntimeError('Privesc history pack members changed')
        index = json.loads(archive.read('index.json'), object_pairs_hook=unique_pairs)
        blocks = archive.read('blocks.bin')
        refs = archive.read('references.bin')
        manifests = archive.read('manifests.bin')
    if (index.get('schema') != 'privesc-exact-history-v1'
            or not isinstance(index.get('versions'), dict)
            or len(index['versions']) != 137
            or not isinstance(index.get('block_sha256'), list)
            or len(blocks) != 512 * len(index['block_sha256'])
            or len(index['block_sha256']) > 65536):
        raise RuntimeError('Privesc history pack shape changed')
    for n, digest in enumerate(index['block_sha256']):
        if hashlib.sha256(blocks[n*512:(n+1)*512]).hexdigest() != digest:
            raise RuntimeError('Privesc history block changed')
    from scripts.peaso_build_privesc_history_pack import declarations
    expected = {archive.name: (manifest.name, manifest_sha, archive_sha)
                for manifest, archive, manifest_sha, archive_sha, *_ in declarations()}
    if set(index['versions']) != set(expected):
        raise RuntimeError('Privesc history roster changed')
    prefix = 'peaso/privesc/catalog_versions/'
    omitted = set()
    for archive_name, row in index['versions'].items():
        if (not isinstance(archive_name, str) or '/' in archive_name or '\\' in archive_name
                or not archive_name.endswith('.tar.gz')
                or (row['manifest_name'], row['manifest_sha256'], row['archive_sha256'])
                   != expected[archive_name]):
            raise RuntimeError('Privesc history identity changed')
        archive_key, manifest_key = prefix + archive_name, prefix + row['manifest_name']
        for key, digest in ((archive_key, row['archive_sha256']),
                            (manifest_key, row['manifest_sha256'])):
            if (hashlib.sha256(source[key]).hexdigest() != digest
                    or checked_member(root, key).read_bytes() != source[key]):
                raise RuntimeError('Privesc original changed during freeze: ' + key)
        offset, count = row['reference_offset'], row['reference_count']
        moffset, msize = row['manifest_offset'], row['manifest_size']
        if (not all(type(value) is int for value in (offset, count, moffset, msize))
                or offset < 0 or count < 1 or offset + count * 2 > len(refs)
                or moffset < 0 or msize < 1 or moffset + msize > len(manifests)
                or row['tar_size'] != count * 512):
            raise RuntimeError('Privesc history references changed')
        ids = struct.unpack_from('<' + 'H' * count, refs, offset)
        if any(n >= len(index['block_sha256']) for n in ids):
            raise RuntimeError('Privesc history block reference changed')
        tar_bytes = b''.join(blocks[n*512:(n+1)*512] for n in ids)
        original = source[archive_key]
        if (tar_bytes != gzip.decompress(original)
                or not original.startswith(base64.b64decode(row['header'], validate=True))
                or not original.endswith(base64.b64decode(row['trailer'], validate=True))
                or manifests[moffset:moffset+msize] != source[manifest_key]):
            raise RuntimeError('Privesc history cannot be reconstructed exactly')
        omitted.update((archive_key, manifest_key))
    for name in omitted:
        del source[name]
    return omitted


def freeze_release(release_source=None):
    """Freeze exact corresponding source without Git, credentials, or caches."""
    import shutil
    release_root = Path(release_source).resolve() if release_source else ROOT
    if release_root != ROOT.resolve():
        raise RuntimeError("Hosted releases must freeze the complete current working source")
    files = set()
    for folder in ["peaso", "risk_rules", "frontend/src", "frontend/public", "frontend/tests", "frontend/e2e"]:
        directory = checked_member(release_root, folder)
        for path in directory.rglob("*"):
            if path.is_symlink() and not any(part.startswith(".") for part in path.relative_to(release_root).parts):
                raise RuntimeError("Source archive cannot include symlinks or external files")
            if path.is_file():
                files.add(path)
    for pattern in ["infra/aws/*.tf", "infra/aws/Dockerfile.worker", "infra/aws/customer-role.json", "infra/aws/customer-policy-allocation.json",
                    "infra/aws/.terraform.lock.hcl", "infra/aws/sdk-constraints.txt", "scripts/peaso*.py", "scripts/peaso_test_resources/*.py",
                    "docs/peaso*.md", "docs/checks/*.md", "docs/privesc-ledgers/*.md", "tests/test_peaso*.py", "frontend/package*.json", "frontend/*config*",
                    "frontend/index.html", "scripts/sync_hacktricks_permissions.py",
                    "scripts/fetch_hacktricks_permissions.py", ".github/workflows/sync-permission-categorizations.yml", ".github/workflows/tests.yml",
                    "tests/test_permission_sync_supplement.py", "tests/test_canonical_permissions.py",
                    "tests/test_permission_source_fetch.py", "scripts/sync_hacktricks_privesc.py",
                    "scripts/export_privesc_catalog.py", "tests/test_privesc_sync.py",
                    # Public compliance research ledgers and pinned inputs the
                    # shipped compiler/tests read; .work drafts stay excluded.
                    *REPRODUCTION_INPUT_PATTERNS]:
        files.update(release_root.glob(pattern))
    # Only the current generic template may accompany its immutable filename.
    # Older operator-bound templates live outside public source.
    template = release_root / "infra/aws/customer-role.json"
    if template.is_file():
        content = template.read_bytes()
        current_template = release_root / ("infra/aws/customer-role-" + hashlib.sha256(content).hexdigest() + ".json")
        if current_template.is_file():
            if current_template.read_bytes() != content:
                raise RuntimeError("Current customer template archive differs from its content hash")
            files.add(current_template)
    files.update(release_root / name for name in ["bluepeass/__init__.py", "bluepeass/k8s.py", "bluepeass/k8s_risks.py", "scripts/cloud_permission_risks.py"])
    files.update(release_root / f for f in ["LICENSE", "README.md", "pyproject.toml", "Dockerfile.peaso",
                                         "docker-compose.yml", ".dockerignore", ".env.example"])
    paths = {str(path.relative_to(release_root)): path for path in files}
    for pattern in ["infra/aws/*.tf", "infra/aws/Dockerfile.worker", "infra/aws/customer-role.json", "infra/aws/customer-policy-allocation.json",
                    "infra/aws/.terraform.lock.hcl", "infra/aws/sdk-constraints.txt", "scripts/peaso_deploy*.py", "docs/peaso-aws.md"]:
        for path in ROOT.glob(pattern):
            paths[str(path.relative_to(ROOT))] = path
    source = {}
    for relative_name, path in sorted(paths.items()):
        relative = Path(relative_name)
        if not path.is_file() or "__pycache__" in path.parts or path.suffix in {".pyc", ".tsbuildinfo", ".db", ".sqlite", ".sqlite3", ".key", ".pem", ".log"}:
            continue
        if relative.name.lower().startswith("untitled"):
            continue
        if relative_name not in {".github/workflows/sync-permission-categorizations.yml", ".github/workflows/tests.yml", ".dockerignore", ".env.example", ".gitignore", "frontend/.gitignore", "infra/aws/.gitignore"} and any(
                part.startswith(".") and part != ".terraform.lock.hcl" for part in relative.parts):
            continue
        if str(relative).startswith(("tests/", "frontend/tests/", "frontend/e2e/")) and path.suffix not in {
                ".py", ".ts", ".tsx", ".js", ".mjs"} and not str(relative).startswith(("tests/fixtures/", "frontend/tests/fixtures/", "frontend/e2e/fixtures/")) and relative_name not in {
                "tests/connector_owner_fixture_20261020.json",
                "tests/gcp_batch_referenced_source_20261020_native.json",
                "tests/gcp_dataflow_referenced_source_20261020_native_fixtures.json",
                "tests/gcp_dataflow_referenced_source_20261020_receipt_fixtures.json",
                "tests/integration/kubernetes-auditor.yaml", "tests/integration/kubernetes-hardening.yaml"}:
            continue
        checked_member(release_root, relative_name)
        if path.is_symlink() or not any(path.resolve().is_relative_to(base.resolve()) for base in (ROOT, release_root)):
            raise RuntimeError("Source archive cannot include symlinks or external files")
        if path.stat().st_nlink != 1:
            raise RuntimeError("Source archive cannot include hardlinked files")
        content = path.read_bytes()
        if path.suffix == ".json":
            try:
                json.loads(content)
            except (ValueError, UnicodeDecodeError) as error:
                raise RuntimeError(f"Source JSON changing or invalid: {relative}; retry after its owner finishes") from error
        if path.suffix == ".py":
            try:
                compile(content, str(relative), "exec")
            except SyntaxError as error:
                raise RuntimeError(f"Source Python changing or invalid: {relative}; retry after its owner finishes") from error
        source[str(relative)] = content
    _omit_verified_duplicate_manifest(source, release_root)
    _omit_verified_reconstructible_privesc_history(source, release_root)
    identifier_file = deployment.value("private_identifiers_file")
    if deployment.configuration() and not identifier_file:
        raise RuntimeError("Private deployment configuration requires private_identifiers_file for release auditing")
    if identifier_file:
        from peaso.public_audit import check_sources
        if Path(identifier_file).resolve().is_relative_to(release_root):
            raise RuntimeError("The private identifier list must remain outside public source")
        check_sources(source, identifier_file)
    manifest = {name: hashlib.sha256(value).hexdigest() for name, value in source.items()}
    runtime_admission_data(manifest)
    version = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    release = {"source_version": version, "source_url": f"https://cspm.hacktricks.wiki/source/peaso-source-{version}.zip",
               "license": "AGPL-3.0", "files": manifest}
    snapshot = generated_path("source-snapshot")
    release_path = generated_path("release.json")
    archive_path = generated_path(f"peaso-source-{version}.zip")
    BUILD.mkdir(parents=True, exist_ok=True)
    if snapshot.exists():
        # The owned snapshot may contain npm symlinks/hardlinks after a frontend
        # build. Unlink them with fd-based rmtree; never chmod or follow them.
        if not shutil.rmtree.avoids_symlink_attacks:
            raise RuntimeError("Refreeze requires symlink-safe generated snapshot removal")
        shutil.rmtree(snapshot)
    for name, value in source.items():
        destination = snapshot / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(value)
        if paths[name].stat().st_mode & 0o111:
            destination.chmod(0o755)
    (snapshot / "release.json").write_text(json.dumps(release, indent=2) + "\n")
    normalize_frozen_permissions(snapshot, ["release.json", *source])
    release_path.write_text(json.dumps(release, indent=2) + "\n")
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, value in sorted(source.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, value, compresslevel=9)
        info = zipfile.ZipInfo("release.json", date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        archive.writestr(info, json.dumps(release, indent=2), compresslevel=9)
    if archive_path.stat().st_size > CURRENT_SOURCE_ARCHIVE_LIMIT:
        try:
            from peaso_source_archive import optimize_source_archive
        except ModuleNotFoundError:
            from scripts.peaso_source_archive import optimize_source_archive
        compression = optimize_source_archive(
            archive_path, max_members=CURRENT_SOURCE_MEMBER_LIMIT,
            max_member_bytes=artifact_update.MAX_SOURCE_MEMBER_BYTES,
            max_uncompressed_bytes=CURRENT_SOURCE_UNCOMPRESSED_LIMIT)
        (BUILD / "source-compression.json").write_text(json.dumps(compression, indent=2) + "\n")
        if archive_path.stat().st_size > CURRENT_SOURCE_ARCHIVE_LIMIT:
            raise RuntimeError("Frozen source ZIP exceeds the current archive byte limit")
    print(f"Frozen source {version}: {len(source)} files; {archive_path}")
    return release


API_ENGINE_CATALOG_PREFIXES = ("peaso/privesc/catalog/", "peaso/privesc/catalog_versions/")
API_DISPLAY_INPUTS = frozenset({"peaso/server/privesc_display_catalog.py",
    "peaso/rulepacks/api_privesc_display.json.gz", "peaso/rulepacks/api_privesc_display_manifest.json"})


def api_runtime_files(files):
    """Package API presentation metadata; full privilege catalogs belong to workers."""
    present = API_DISPLAY_INPUTS.intersection(files)
    if present and present != API_DISPLAY_INPUTS:
        raise RuntimeError("Incomplete API privilege display generation")
    admission = runtime_admission_data(files)
    return {name: digest for name, digest in files.items()
            if (name.startswith(("peaso/", "risk_rules/")) or name in {
                "bluepeass/__init__.py", "bluepeass/k8s.py", "bluepeass/k8s_risks.py",
                "scripts/cloud_permission_risks.py"} or name in admission)
            and not (present and name.startswith(API_ENGINE_CATALOG_PREFIXES))}


def verify_api_source():
    """Verify portable ZIP/staging permissions and complete frozen runtime source."""
    source_root()
    release = json.loads((BUILD / "release.json").read_text())
    admission_data = runtime_admission_data(release["files"])
    runtime_files = api_runtime_files(release["files"])
    target = generated_path("api-package")
    entries = verify_public_tree(target)
    staged = {path.relative_to(target).as_posix(): path for path in entries if path.is_file()}
    with zipfile.ZipFile(generated_path("api.zip")) as package:
        for name, expected in runtime_files.items():
            try:
                content = package.read(name)
            except KeyError:
                raise RuntimeError(f"API ZIP omits supplied source: {name}") from None
            if hashlib.sha256(content).hexdigest() != expected:
                raise RuntimeError(f"API ZIP source differs from frozen release: {name}")
        members = package.infolist()
        if (API_DISPLAY_INPUTS <= release["files"].keys()
                and any(info.filename.startswith(API_ENGINE_CATALOG_PREFIXES) for info in members)):
            raise RuntimeError("Engine privilege catalogs entered API package")
        if len(members) != len({info.filename for info in members}):
            raise RuntimeError("API ZIP has duplicate members")
        for info in members:
            path = checked_member(target, info.filename)
            if info.create_system != 3 or info.external_attr >> 16 not in {
                    stat.S_IFREG | 0o644, stat.S_IFREG | 0o755}:
                raise RuntimeError(f"API ZIP has nonportable member permissions: {info.filename}")
            if not path.is_file() or stat.S_IMODE(info.external_attr >> 16) != public_mode(path):
                raise RuntimeError(f"API ZIP member differs from verification directory: {info.filename}")
            if hashlib.sha256(package.read(info)).digest() != hashlib.sha256(path.read_bytes()).digest():
                raise RuntimeError(f"API verification directory differs from ZIP: {info.filename}")
        if set(staged) != {info.filename for info in members}:
            raise RuntimeError("API ZIP members differ from verification directory")
    for name, expected in runtime_files.items():
        path = BUILD / "api-package" / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise RuntimeError(f"API verification directory differs from ZIP: {name}")
    print(f"Verified {len(runtime_files)} frozen runtime source files in API ZIP and directory")


def run(args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, **kwargs)


def verify_backend():
    """Fail closed if this checkout was initialized against another state key."""
    metadata = INFRA / ".terraform" / "terraform.tfstate"
    if not metadata.is_file():
        raise RuntimeError("Initialize the dedicated CSPM backend before deployment")
    backend = json.loads(metadata.read_text()).get("backend", {})
    config = backend.get("config", {})
    expected = deployment.backend()
    if not expected or not re.fullmatch(r"[0-9]{12}", ACCOUNT):
        raise RuntimeError("Set PEASO_DEPLOY_CONFIG to the private deployment configuration")
    if backend.get("type") != "s3" or any(config.get(k) != v for k, v in expected.items()):
        raise RuntimeError("Deployment requires the encrypted, locked cspm/terraform.tfstate backend")


def terraform(*args, capture=False):
    verify_backend()
    return run([TF, f"-chdir={INFRA}", *args], capture_output=capture, text=True)


def aws_identity():
    import boto3
    session = boto3.Session(region_name="us-east-1")
    identity = session.client("sts").get_caller_identity()
    if identity["Account"] != ACCOUNT:
        raise RuntimeError("Deployment requires the configured deployment account")
    print(f"Verified wiki account {identity['Account']}; caller {identity['Arn']}")
    return session


def omit_empty_api_installation_markers(target):
    """Omit optional pip request markers; preserve dependency code and metadata."""
    # Preflight the entire installer tree before deleting anything, including
    # a marker that sorts before an unsafe symlink or hardlink.
    entries = public_tree_entries(target)
    removed = []
    for path in entries:
        relative = path.relative_to(target)
        if (len(relative.parts) == 2 and relative.parts[0].endswith(".dist-info")
                and relative.parts[0] != ".dist-info" and relative.name == "REQUESTED"
                and path.is_file() and path.stat().st_size == 0):
            path.unlink()
            removed.append(relative.as_posix())
    return sorted(removed)


def package_api():
    import shutil
    source = source_root()
    release_path = BUILD / "release.json"
    admission_data = runtime_admission_data(json.loads(release_path.read_text())["files"]) if release_path.is_file() else {}
    target = generated_path("api-package")
    package = generated_path("api.zip")
    BUILD.mkdir(parents=True, exist_ok=True)
    if target.exists():
        public_tree_entries(target)
        shutil.rmtree(target)
    target.mkdir()
    run([sys.executable, "-m", "pip", "install", "--target", target,
         "--constraint", source / "infra/aws/sdk-constraints.txt",
         "--no-compile", "--platform", "manylinux2014_x86_64", "--implementation", "cp",
         "--python-version", "3.12", "--abi", "cp312", "--only-binary=:all:",
         "fastapi>=0.115", "uvicorn>=0.30", "cryptography>=43", "PyYAML>=6",
         "PyJWT[crypto]>=2.10", "mangum>=0.19", "boto3==1.43.38", "requests>=2", "tzdata>=2024.1",
         "google-auth==2.62.0", "azure-identity==1.26.0"])
    # Reject installer-created links before copying any source into its tree.
    omitted = omit_empty_api_installation_markers(target)
    if omitted:
        print(f"Omitted {len(omitted)} optional empty API installation markers")
    shutil.copytree(source / "peaso", target / "peaso", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copytree(source / "risk_rules", target / "risk_rules", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for name in ["bluepeass/__init__.py", "bluepeass/k8s.py", "bluepeass/k8s_risks.py", "scripts/cloud_permission_risks.py", *admission_data]:
        destination = target / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / name, destination)
    if (BUILD / "release.json").is_file():
        release = json.loads((BUILD / "release.json").read_text())
        api_runtime_files(release["files"])  # Validate the complete presentation generation.
        if API_DISPLAY_INPUTS <= release["files"].keys():
            for prefix in API_ENGINE_CATALOG_PREFIXES:
                directory = target / prefix
                if directory.exists():
                    shutil.rmtree(directory)
        shutil.copyfile(BUILD / "release.json", target / "peaso_release.json")
    normalize_public_tree(target)
    try:
        from scripts.peaso_api_service_model_gate import prune_api_service_models
    except ModuleNotFoundError:
        from peaso_api_service_model_gate import prune_api_service_models
    sdk_models = prune_api_service_models(target)
    print(f"Reviewed API SDK services: {len(sdk_models['allowed_services'])}; "
          f"removed model files: {sdk_models['removed_models']}")
    members = [path for path in sorted(target.rglob("*")) if path.is_file()]
    if len(members) > CURRENT_API_MEMBER_LIMIT:
        raise RuntimeError("API member limit exceeded after optional metadata omission: "
                           f"{len(members)} > {CURRENT_API_MEMBER_LIMIT}")
    expanded_bytes = sum(path.stat().st_size for path in members)
    if expanded_bytes > CURRENT_API_UNCOMPRESSED_LIMIT:
        raise RuntimeError("API uncompressed byte limit exceeded: "
                           f"{expanded_bytes} > {CURRENT_API_UNCOMPRESSED_LIMIT}")
    with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in members:
            info = zipfile.ZipInfo(path.relative_to(target).as_posix(), date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | public_mode(path)) << 16
            archive.writestr(info, path.read_bytes(), compresslevel=9)
    if package.stat().st_size > CURRENT_API_ARCHIVE_LIMIT:
        try:
            from peaso_source_archive import optimize_source_archive
        except ModuleNotFoundError:
            from scripts.peaso_source_archive import optimize_source_archive
        compression = optimize_source_archive(
            package, max_members=CURRENT_API_MEMBER_LIMIT,
            max_member_bytes=CURRENT_API_UNCOMPRESSED_LIMIT,
            max_uncompressed_bytes=CURRENT_API_UNCOMPRESSED_LIMIT, preserve_modes=True)
        (BUILD / "api-compression.json").write_text(json.dumps(compression, indent=2) + "\n")
    if package.stat().st_size > CURRENT_API_ARCHIVE_LIMIT:
        raise RuntimeError("API archive byte limit exceeded: "
                           f"{package.stat().st_size} > {CURRENT_API_ARCHIVE_LIMIT}")
    verify_api_source()
    print(f"API package: {package}; {package.stat().st_size} bytes")
    return package


def build_worker(tag):
    context = source_root()
    release = json.loads((BUILD / "release.json").read_text())
    run(["docker", "build", "--platform", "linux/amd64", "-f", context / "infra/aws/Dockerfile.worker",
         "--label", f"org.opencontainers.image.revision={release['source_version']}",
         "-t", f"peaso-worker:{tag}", context])
    code = "RUNTIME_ADMISSION_INPUTS = " + repr(RUNTIME_ADMISSION_INPUTS) + "\n" + """
import hashlib,json,os
from pathlib import Path
from peaso.engine import get_catalog
import peaso.privesc
assert os.getuid()==10001 and os.getgid()==10001
release=json.loads(Path('/release.json').read_text())
count=0
for name,digest in release['files'].items():
    if name.startswith(('peaso/','risk_rules/')) or name in {'bluepeass/__init__.py','bluepeass/k8s.py','bluepeass/k8s_risks.py','scripts/cloud_permission_risks.py'} or name in RUNTIME_ADMISSION_INPUTS:
        path=Path('/app')/name
        assert path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest()==digest,name
        count+=1
constraints=Path('/app/infra/aws/sdk-constraints.txt')
assert constraints.is_file() and hashlib.sha256(constraints.read_bytes()).hexdigest()==release['files']['infra/aws/sdk-constraints.txt']
print('Worker frozen runtime files:',count)
print('Worker native catalog checks:',len(get_catalog()['checks']))
"""
    run(["docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none", "--read-only",
         "--tmpfs", "/tmp", "--entrypoint", "python", "-v", f"{context / 'release.json'}:/release.json:ro",
         f"peaso-worker:{tag}", "-c", code])


def build_frontend():
    frontend = source_root() / "frontend"
    run(["npm", "ci"], cwd=frontend)
    run(["npm", "run", "build"], cwd=frontend)
    release = json.loads((BUILD / "release.json").read_text())
    manifest = {str(path.relative_to(frontend / "dist")): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in (frontend / "dist").rglob("*") if path.is_file()}
    (BUILD / "frontend-build.json").write_text(json.dumps({"source_version": release["source_version"], "files": manifest}, indent=2) + "\n")
    print(f"Built frontend from {release['source_version']}: {len(manifest)} files")


def frontend_sync_command(frontend, bucket):
    """Keep the frozen source and Terraform-owned download during --delete."""
    return ["aws", "s3", "sync", frontend / "dist", f"s3://{bucket}/", "--delete",
            "--exclude", "source/*", "--exclude", CUSTOMER_ROLE_DOWNLOAD_KEY,
            "--cache-control", "public,max-age=300"]


def write_vars(image, api_zip):
    if not api_zip.is_file():
        raise RuntimeError("Build the API ZIP before planning")
    variables = {"api_zip": str(api_zip.resolve()), "worker_image": image}
    if (BUILD / "release.json").is_file():
        variables["source_version"] = json.loads((BUILD / "release.json").read_text())["source_version"]
    # Preserve reviewed sizing and budget overrides between builds.
    existing = INFRA / "deployment.auto.tfvars.json"
    if existing.exists():
        variables.update({k: v for k, v in json.loads(existing.read_text()).items()
                          if k in {"enable_public_customer_role_template", "gcp_platform_sa_secret_arn", "worker_resources", "scan_runtime_limits", "budget_email", "monthly_budget_usd"}})
    integration_keys = ("account_id", "cognito_pool_id", "cognito_client_id", "stripe_secret_arn", "stripe_price_id",
                        "codex_token_secret_arn", "codex_token_kms_key_arn", "gcp_platform_project", "gcp_platform_email", "platform_account_ids", "budget_email", "archived_customer_role_templates", "gcp_platform_sa_secret_arn",
                        "enable_public_customer_role_template", "worker_resources", "scan_runtime_limits", "monthly_budget_usd")
    for key in integration_keys:
        configured = deployment.value(key)
        if configured != "":
            variables[key] = ({digest: os.path.relpath(filename, INFRA) for digest, filename in configured.items()}
                              if key == "archived_customer_role_templates" else configured)
    if "worker_resources" in variables:
        verify_worker_resources(variables["worker_resources"])
    existing.write_text(json.dumps(variables, indent=2) + "\n")
    existing.chmod(0o600)


def verify_worker_resources(resources):
    """Reject stale deployment overrides before writing variables or reviewing plans."""
    supported = {512: {1024, 2048, 3072, 4096}, 1024: {2048, 3072, 4096, 5120, 6144, 7168, 8192},
                 2048: set(range(4096, 16385, 1024)), 4096: set(range(8192, 30721, 1024))}
    if set(resources) != {"collector", "analyzer"}:
        raise RuntimeError("Worker sizing requires collector and analyzer only")
    for stage, minimum in [("collector", 6144), ("analyzer", 4096)]:
        try:
            cpu, memory = resources[stage]["cpu"], resources[stage]["memory"]
            valid = memory in supported.get(cpu, set()) and memory >= minimum
        except (KeyError, TypeError):
            valid = False
        if not valid:
            raise RuntimeError(f"Invalid {stage} sizing: use supported Fargate CPU/memory with at least {minimum} MiB")


def deployment_expectations(data, plan):
    """Bind deferred runtime fields to reviewed configuration and built source."""
    import base64
    variables = {key: value.get("value") for key, value in data.get("variables", {}).items()}
    image = variables.get("worker_image")
    if image == ZERO_IMAGE:
        raise RuntimeError("Placeholder worker image cannot be reviewed/applied")
    if not isinstance(image, str) or not re.fullmatch(re.escape(REPOSITORY) + r"@sha256:[a-f0-9]{64}", image):
        raise RuntimeError("Saved worker image variable must be a dedicated immutable digest")
    sizes = variables.get("worker_resources") or {}
    verify_worker_resources(sizes)
    verify_api_source()
    snapshot = source_root()
    release = json.loads((BUILD / "release.json").read_text())
    source = hashlib.sha256(json.dumps(release["files"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if variables.get("source_version") != source or release["source_version"] != source:
        raise RuntimeError("Saved source variable differs from frozen release")
    current = json.loads((INFRA / "deployment.auto.tfvars.json").read_text())
    for key in ("worker_image", "source_version", "api_zip"):
        if current.get(key) != variables.get(key):
            raise RuntimeError(f"Saved {key} variable differs from reviewed deployment variables")
    for key in ("enable_public_customer_role_template", "worker_resources", "scan_runtime_limits", "codex_token_secret_arn", "codex_token_kms_key_arn", "account_id", "cognito_pool_id", "cognito_client_id", "stripe_secret_arn", "stripe_price_id", "archived_customer_role_templates"):
        if key in current and current[key] != variables.get(key):
            raise RuntimeError(f"Saved {key} variable differs from reviewed deployment variables")
    tf_files = {Path(name).name: digest for name, digest in release["files"].items()
                if name.startswith("infra/aws/") and name.endswith(".tf")}
    try:
        with zipfile.ZipFile(plan) as archive:
            members = [name for name in archive.namelist() if name.startswith("tfconfig/") and name != "tfconfig/modules.json"]
            if len(members) != len(set(members)) or set(members) != {f"tfconfig/m-/{name}" for name in tf_files}:
                raise RuntimeError("Saved plan configuration differs from frozen dedicated root")
            for name, digest in tf_files.items():
                if (hashlib.sha256(archive.read(f"tfconfig/m-/{name}")).hexdigest() != digest or
                        hashlib.sha256((INFRA / name).read_bytes()).hexdigest() != digest or
                        hashlib.sha256((snapshot / "infra/aws" / name).read_bytes()).hexdigest() != digest):
                    raise RuntimeError("Saved plan configuration differs from frozen source")
    except zipfile.BadZipFile:
        raise RuntimeError("Cannot verify configuration embedded in saved plan") from None
    for name, historical_digest in RUNTIME_CONFIG_SHA256.items():
        current_digest = tf_files.get(name)
        if current_digest == historical_digest:
            continue
        if name in API_DELIVERY_SOURCE and current_digest in API_DELIVERY_SOURCE[name][1:]:
            predecessor = (INFRA / name).read_bytes()
            if current_digest == API_DELIVERY_SOURCE[name][2]:
                for replacement, original in API_DELIVERY_CONTENT_REVERSE[name]:
                    if predecessor.count(replacement) != 1:
                        raise RuntimeError("Content-addressed API delivery differs from its reviewed predecessor")
                    predecessor = predecessor.replace(replacement, original, 1)
                if hashlib.sha256(predecessor).hexdigest() != API_DELIVERY_SOURCE[name][1]:
                    raise RuntimeError("Content-addressed API delivery predecessor mismatch")
            for replacement, original in API_DELIVERY_REVERSE[name]:
                if predecessor.count(replacement) != 1:
                    raise RuntimeError("API S3 delivery successor differs from its reviewed change")
                predecessor = predecessor.replace(replacement, original, 1)
            if hashlib.sha256(predecessor).hexdigest() != API_DELIVERY_SOURCE[name][0]:
                raise RuntimeError("API S3 delivery successor does not reconstruct its predecessor")
            continue
        if name == "workflow.tf" and current_digest == CURRENT_INDEXED_WORKFLOW_SHA256:
            restored = (INFRA / name).read_bytes()
            if restored.count(INDEXED_WORKFLOW_ADDITION) != 1:
                raise RuntimeError("Indexed workflow differs from reviewed index environment")
            restored = restored.replace(INDEXED_WORKFLOW_ADDITION, b'', 1)
            if hashlib.sha256(restored).hexdigest() != CURRENT_WORKFLOW_RUNTIME_SHA256:
                raise RuntimeError("Indexed workflow does not reconstruct reviewed source")
            continue
        if name == "iam.tf" and current_digest == CURRENT_INDEXED_IAM_SHA256:
            restored = (INFRA / name).read_bytes()
            batch_addition = b'"dynamodb:GetItem", "dynamodb:BatchGetItem", '
            if restored.count(batch_addition) != 3 or restored.count(INDEXED_IAM_QUERY_ADDITION) != 3:
                raise RuntimeError("Indexed IAM successor differs from reviewed permissions")
            restored = restored.replace(batch_addition, b'"dynamodb:GetItem", ')
            restored = restored.replace(INDEXED_IAM_QUERY_ADDITION, b'')
            if hashlib.sha256(restored).hexdigest() != CURRENT_IAM_RUNTIME_SHA256:
                raise RuntimeError("Indexed IAM successor does not reconstruct reviewed source")
            continue
        if (name == "iam.tf" and current_digest == CURRENT_IAM_RUNTIME_SHA256
                    or name == "workflow.tf" and current_digest in {
                        PREVIOUS_WORKFLOW_RUNTIME_SHA256, CURRENT_WORKFLOW_RUNTIME_SHA256}
                    or name == "ai_runtime.tf" and current_digest == CURRENT_AI_RUNTIME_SHA256):
            continue
        if name == "variables.tf" and current_digest in {RUNTIME_LIMITS_CURRENT_SHA256, WORKER_SIZING_CURRENT_SHA256}:
            restored = (INFRA / name).read_bytes()
            if current_digest == WORKER_SIZING_CURRENT_SHA256:
                for successor, predecessor in WORKER_SIZING_REVERSE:
                    if restored.count(successor) != 1:
                        raise RuntimeError("Worker sizing differs from its reviewed extension")
                    restored = restored.replace(successor, predecessor, 1)
                if hashlib.sha256(restored).hexdigest() != RUNTIME_LIMITS_CURRENT_SHA256:
                    raise RuntimeError("Worker sizing does not reconstruct reviewed runtime limits")
            for before, after in RUNTIME_LIMITS_EXACT_REPLACEMENTS:
                if restored.count(after) != 1:
                    raise RuntimeError("Runtime limit successor differs from its exact reviewed change")
                restored = restored.replace(after, before, 1)
            if hashlib.sha256(restored).hexdigest() != RUNTIME_LIMITS_PREDECESSOR_SHA256:
                raise RuntimeError("Runtime limit successor does not reconstruct its historical source")
            continue
        if name != "iam.tf" or current_digest != IAM_RUNTIME_CURRENT_SHA256:
            raise RuntimeError("Runtime configuration requires a new explicit contract review")
        current_bytes = (INFRA / name).read_bytes()
        if (current_bytes.count(IAM_RUNTIME_EXACT_ADDITION) != 2
                or hashlib.sha256(current_bytes.replace(IAM_RUNTIME_EXACT_ADDITION, b"", 1)).hexdigest()
                != historical_digest):
            raise RuntimeError("Runtime configuration requires a new explicit contract review")
    if variables.get("api_zip") != str((BUILD / "api.zip").resolve()):
        raise RuntimeError("Saved API ZIP variable differs from verified package")
    if variables.get("region") != "us-east-1":
        raise RuntimeError("Saved deployment region differs from dedicated account region")
    limits = variables.get("scan_runtime_limits") or {}
    if not isinstance(limits.get("workflow_seconds"), int) or not 900 <= limits["workflow_seconds"] <= 7200:
        raise RuntimeError("Saved scan runtime limit is missing or unsupported")
    public_template_enabled = variables.get("enable_public_customer_role_template", False)
    if not isinstance(public_template_enabled, bool):
        raise RuntimeError("Public customer-role template opt-in must be a boolean")
    template_sha256 = hashlib.sha256((INFRA / "customer-role.json").read_bytes()).hexdigest()
    public_template_url = (f"https://hacktricks-cspm-templates-{ACCOUNT}.s3.us-east-1.amazonaws.com/customer-role-{template_sha256}.json"
                           if public_template_enabled else "")
    if variables.get("account_id") != ACCOUNT:
        raise RuntimeError("Saved deployment account differs from private configuration")
    for key in ("cognito_pool_id", "cognito_client_id", "stripe_secret_arn", "stripe_price_id", "codex_token_secret_arn"):
        if variables.get(key, "") != deployment.value(key):
            raise RuntimeError("Saved integration inputs differ from private configuration")
    expected_archives = {digest: os.path.relpath(filename, INFRA) for digest, filename in (deployment.value("archived_customer_role_templates") or {}).items()}
    if variables.get("archived_customer_role_templates", {}) != expected_archives:
        raise RuntimeError("Saved template archives differ from private configuration")
    common = {
        "PEASO_AI_CREDENTIAL_SECRET_ARN": {"arn_pattern": f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:hacktricks-cspm-ai-key-[A-Za-z0-9]{{6}}"},
        "CODEX_TOKEN_SECRET_ARN": variables.get("codex_token_secret_arn", ""),
        "PEASO_AWS_COLLECTOR_ROLE_ARN": f"arn:aws:iam::{ACCOUNT}:role/HackTricks-CSPM",
        "PEASO_PLATFORM_ACCOUNT_IDS": ",".join(dict.fromkeys([ACCOUNT] + variables.get("platform_account_ids", []))),
        "PEASO_GCP_PLATFORM_PROJECT": variables.get("gcp_platform_project", ""),
        "PEASO_GCP_PLATFORM_EMAIL": variables.get("gcp_platform_email", ""),
        "PEASO_AUTH_MODE": "cognito", "PEASO_COGNITO_ISSUER": f"https://cognito-idp.us-east-1.amazonaws.com/{variables['cognito_pool_id']}",
        "PEASO_COGNITO_CLIENT_ID": variables["cognito_client_id"], "PEASO_STORAGE": "dynamodb",
        "PEASO_DYNAMODB_TABLE": "hacktricks-cspm", "PEASO_ARTIFACT_BUCKET": f"hacktricks-cspm-artifacts-{ACCOUNT}",
        "PEASO_SCAN_TIMEOUT_SECONDS": str(limits["workflow_seconds"]),
        "PEASO_STATE_DIR": "/tmp/peaso/state", "PEASO_IDENTITY_DIR": "/tmp/peaso/identity",
        "PEASO_SOURCE_VERSION": source,
    }
    if tf_files.get("workflow.tf") == CURRENT_INDEXED_WORKFLOW_SHA256:
        common.update(PEASO_WORK_STATE_INDEX="work-state", PEASO_SCHEDULE_TIME_INDEX="schedule-time")
    for stage, size in sizes.items():
        common[f"PEASO_{stage.upper()}_VCPU"] = str(size["cpu"] / 1024)
        common[f"PEASO_{stage.upper()}_MEMORY_GIB"] = str(size["memory"] / 1024)
    secret = {"arn_pattern": f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:hacktricks-cspm-credential-key-[A-Za-z0-9]{{6}}"}
    api = dict(common, PEASO_CREDENTIAL_SECRET_ARN=secret,
               PEASO_PUBLIC_CUSTOMER_ROLE_TEMPLATE_URL=public_template_url,
               PEASO_WORKFLOW_ARN=f"arn:aws:states:us-east-1:{ACCOUNT}:stateMachine:hacktricks-cspm",
               PEASO_STRIPE_SECRET_ARN=variables["stripe_secret_arn"],
               PEASO_STRIPE_PRICE_ID=variables["stripe_price_id"], PEASO_ALLOWED_ORIGINS="https://cspm.hacktricks.wiki",
               PEASO_SOURCE_URL=f"https://cspm.hacktricks.wiki/source/peaso-source-{source}.zip")
    workers = {stage: dict(common, AWS_DEFAULT_REGION="us-east-1", PEASO_TASK_VCPU=str(size["cpu"] / 1024),
                           PEASO_TASK_MEMORY_GIB=str(size["memory"] / 1024)) for stage, size in sizes.items()}
    workers["collector"]["PEASO_CREDENTIAL_SECRET_ARN"] = secret
    return {"worker_image": image, "worker_resources": sizes, "source_version": source, "api_zip": variables["api_zip"],
            "api_s3_delivery": tf_files.get("api.tf") == API_DELIVERY_SOURCE["api.tf"][2],
            "api_code_sha256": base64.b64encode(hashlib.sha256((BUILD / "api.zip").read_bytes()).digest()).decode(),
            "api_environment": api, "worker_environments": workers}


def api_package_key(code_sha256):
    import base64
    return API_PACKAGE_PREFIX + base64.b64decode(code_sha256, validate=True).hex() + ".zip"


def check_api_delivery_plan(data, expected):
    """Bind both Lambdas to one private content-addressed S3 object."""
    import base64
    rows = {row.get("address"): row for row in data.get("resource_changes", [])}
    obj = rows.get("aws_s3_object.api_zip")
    if (not obj or obj.get("mode") != "managed" or
            rows.get("aws_s3_bucket_versioning.artifacts")):
        raise RuntimeError("Private content-addressed API package object is absent or bucket versioning changed")
    change = obj.get("change") or {}
    value = change.get("after") or {}
    bucket = f"hacktricks-cspm-artifacts-{ACCOUNT}"
    digest = base64.b64decode(expected["api_code_sha256"], validate=True).hex()
    key = api_package_key(expected["api_code_sha256"])
    if (value.get("bucket") != bucket or value.get("key") != key or
            value.get("source") != expected["api_zip"] or
            value.get("source_hash") != expected["api_code_sha256"] or
            value.get("metadata") != {"sha256": digest} or
            value.get("server_side_encryption") != "aws:kms" or
            not re.fullmatch(rf"arn:aws:kms:us-east-1:{ACCOUNT}:key/[a-f0-9-]+", value.get("kms_key_id") or "")):
        raise RuntimeError("Saved API package object differs from reviewed private source")
    for name in ("api", "scheduler"):
        row = rows.get(f"aws_lambda_function.{name}")
        if not row:
            raise RuntimeError("Saved API Lambda is absent")
        values = (row.get("change") or {}).get("after") or {}
        markers = (row.get("change") or {}).get("after_unknown") or {}
        if (values.get("filename") is not None or values.get("s3_bucket") != bucket or
                values.get("s3_key") != key or
                values.get("source_code_hash") != expected["api_code_sha256"] or
                values.get("s3_object_version") is not None or markers.get("s3_object_version") is True):
            raise RuntimeError(f"Saved {name} Lambda is not bound to the reviewed content-addressed object")


def check_environment(environment, expected, unknown=None):
    if not isinstance(environment, dict):
        raise RuntimeError("Runtime environment is missing or malformed")
    for key, value in expected.items():
        if key not in environment and (unknown is True or isinstance(unknown, dict) and unknown.get(key) is True):
            continue
        actual = environment.get(key)
        try:
            matches = (isinstance(actual, str) and re.fullmatch(value["arn_pattern"], actual) is not None if isinstance(value, dict) else
                       float(actual) == float(value) if key.endswith(("_VCPU", "_MEMORY_GIB")) else
                       actual == value)
        except (ValueError, TypeError):
            matches = False
        if not matches:
            raise RuntimeError(f"Runtime telemetry differs or configured value missing: {key}")


def container_environment(container):
    items = container.get("environment", [])
    if (not isinstance(items, list) or any(not isinstance(item, dict) or not isinstance(item.get("name"), str) or
                                          not isinstance(item.get("value"), str) for item in items) or
            len({item["name"] for item in items}) != len(items)):
        raise RuntimeError("Worker environment is malformed or contains duplicate keys")
    return {item["name"]: item["value"] for item in items}


def recovery_artifact(entry):
    path = Path(entry.get("path", ""))
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise RuntimeError("Recovery artifact must be an absolute regular file")
    content = path.read_bytes()
    if hashlib.sha256(content).hexdigest() != entry.get("sha256"):
        raise RuntimeError("Recovery artifact digest changed")
    return content


def recovery_state_resources(state):
    resources = {}
    if not state.get("lineage") or not isinstance(state.get("serial"), int):
        raise RuntimeError("Recovery state lineage/serial missing")
    for resource in state.get("resources", []):
        if resource.get("mode") != "managed":
            continue
        if resource.get("module"):
            raise RuntimeError("Recovery state contains a child module")
        for instance in resource.get("instances", []):
            address = resource["type"] + "." + resource["name"]
            if "index_key" in instance:
                address += "[" + json.dumps(instance["index_key"], separators=(",", ":")) + "]"
            attributes = instance.get("attributes")
            if (address in resources or instance.get("deposed") or instance.get("status") == "tainted" or
                    not isinstance(attributes, dict) or not recovery_identity(address, attributes)):
                raise RuntimeError("Recovery state identity is unknown, tainted, deposed or duplicated")
            resources[address] = attributes
    return resources


def recovery_identity(address, attributes):
    if address == "random_bytes.credential_key":
        # random_bytes has no provider id attribute; its complete, immutable
        # secret bytes remain private and bound by the state/artifact hashes.
        import base64
        try:
            return (attributes.get("length") == 32 and len(bytes.fromhex(attributes["hex"])) == 32 and
                    base64.b64decode(attributes["base64"], validate=True) == bytes.fromhex(attributes["hex"]))
        except (KeyError, ValueError, TypeError):
            return False
    return isinstance(attributes.get("id"), str) and bool(attributes["id"])


def recovery_refreshed_resources(document, raw_resources):
    prior = document.get("prior_state", {}).get("values", {}).get("root_module", {})
    rows = [r for r in prior.get("resources", []) if r.get("mode") == "managed"]
    refreshed = {r["address"]: r["values"] for r in rows}
    if prior.get("child_modules") or len(rows) != len(refreshed) or set(refreshed) != set(raw_resources):
        raise RuntimeError("Recovery refresh inventory differs from the raw baseline")
    changes = document.get("resource_drift", [])
    if len(changes) != len({r["address"] for r in changes}):
        raise RuntimeError("Recovery refresh contains duplicate drift identities")
    for row in changes:
        address, change = row["address"], row["change"]
        if (address not in raw_resources or change.get("actions") != ["update"] or
                change.get("before") != raw_resources[address] or change.get("after") != refreshed[address] or
                change["before"].get("id") != change["after"].get("id")):
            raise RuntimeError("Recovery recorded read enrichment changed an exact before/identity")
    changed = {address for address in refreshed if refreshed[address] != raw_resources[address]}
    if changed != {r["address"] for r in changes}:
        raise RuntimeError("Recovery refresh contains unrecorded value changes")
    return refreshed


def recovery_context(path, reviewed_sha256):
    """Read only content-addressed supervisor evidence; never infer ownership by name."""
    verify_backend()
    content = recovery_artifact({"path": str(path), "sha256": reviewed_sha256})
    baseline = json.loads(content)
    if (baseline.get("schema") != "peaso-cloudfront-recovery-v1" or baseline.get("account") != ACCOUNT or
            baseline.get("backend") != RECOVERY_BACKEND):
        raise RuntimeError("Recovery baseline account/backend/schema differs")
    failed = recovery_artifact(baseline["failed_plan"])
    initial_raw = recovery_artifact(baseline["failed_plan_json"])
    if (hashlib.sha256(failed).hexdigest() != RECOVERY_FAILED_PLAN_SHA256 or
            hashlib.sha256(initial_raw).hexdigest() != RECOVERY_FAILED_JSON_SHA256):
        raise RuntimeError("Recovery requires the exact approved failed initial plan")
    initial = json.loads(initial_raw)
    owned, bootstrap = set(), set()
    for resource in initial["resource_changes"]:
        if resource.get("mode") != "managed":
            continue
        address, change = resource["address"], resource["change"]
        if change["actions"] == ["create"] and change.get("before") is None:
            owned.add(address)
        elif address in {"aws_ecr_repository.worker", "aws_ecr_lifecycle_policy.worker"} and change["actions"] == ["no-op"]:
            bootstrap.add(address)
        else:
            raise RuntimeError("Recovery initial plan has an unexpected action")
    state = json.loads(recovery_artifact(baseline["state"]))
    resources = recovery_state_resources(state)
    if set(resources) != (owned - RECOVERY_MISSING) | bootstrap or owned - set(resources) != RECOVERY_MISSING:
        raise RuntimeError("Recovery state does not contain exactly the initial creates minus missing four")
    drift = json.loads(recovery_artifact(baseline["drift"]))
    if any(r["change"]["actions"] != ["no-op"]
            for r in drift.get("resource_changes", []) if r.get("mode") == "managed"):
        raise RuntimeError("Recovery preflight contains drift")
    enrichment = baseline.get("read_enrichment_approval")
    if drift.get("resource_drift"):
        if baseline["drift"]["sha256"] != RECOVERY_ENRICHMENT_SHA256 or enrichment != {
                "message_id": RECOVERY_ENRICHMENT_APPROVAL, "document_sha256": RECOVERY_ENRICHMENT_SHA256}:
            raise RuntimeError("Recovery drift requires the exact supervisor-approved read-enrichment document")
    elif enrichment:
        raise RuntimeError("Recovery enrichment approval does not match recorded rows")
    raw_resources = resources
    resources = recovery_refreshed_resources(drift, raw_resources)
    preflight = json.loads(recovery_artifact(baseline["orphans_and_jobs"]))
    if (preflight.get("account") != ACCOUNT or preflight.get("backend") != RECOVERY_BACKEND or
            preflight.get("orphan_resources") != [] or preflight.get("active_hosted_jobs") != []):
        raise RuntimeError("Recovery orphan/job preflight is missing or not clear")
    approved = baseline.get("approved_actions", {})
    for address, approval in approved.items():
        if (address not in RECOVERY_ACTIONS or address not in owned or address not in resources or
                (approval.get("actions"), approval.get("reason")) != RECOVERY_ACTIONS[address]):
            raise RuntimeError("Recovery approval contains an unrelated address/action/reason")
    return {"path": str(path), "sha256": reviewed_sha256, "baseline": baseline, "state": state,
            "resources": resources, "raw_resources": raw_resources, "drift_rows": drift.get("resource_drift", []),
            "owned": owned, "bootstrap": bootstrap, "approved": approved}


def recovery_terraform_delta(plan, recovery):
    """Only the named CloudFront lookup repair may differ from the failed TF."""
    import io
    original = recovery_artifact(recovery["baseline"]["failed_plan"])
    try:
        with zipfile.ZipFile(io.BytesIO(original)) as old, zipfile.ZipFile(plan) as new:
            old_names = [n for n in old.namelist() if n.startswith("tfconfig/") and n != "tfconfig/modules.json"]
            new_names = [n for n in new.namelist() if n.startswith("tfconfig/") and n != "tfconfig/modules.json"]
            if (set(old_names) != set(new_names) or len(old_names) != len(set(old_names)) or
                    len(new_names) != len(set(new_names))):
                raise RuntimeError("Recovery embedded Terraform inventory differs")
            if any(old.read(name) != new.read(name) for name in old_names if name != "tfconfig/m-/frontend.tf"):
                raise RuntimeError("Recovery Terraform delta may change only frontend.tf")
    except zipfile.BadZipFile:
        raise RuntimeError("Recovery failed/new binary must embed exact Terraform source") from None


def recovery_plan_inventory(data, recovery):
    if data.get("resource_drift", []) != recovery["drift_rows"]:
        raise RuntimeError("Recovery plan drift differs from the exact recorded read enrichments")
    prior = data.get("prior_state", {}).get("values", {}).get("root_module", {})
    if prior.get("child_modules"):
        raise RuntimeError("Recovery plan contains unrelated prior modules")
    prior_resources = {r["address"]: r["values"] for r in prior.get("resources", []) if r.get("mode") == "managed"}
    if prior_resources != recovery["resources"]:
        raise RuntimeError("Recovery plan before state differs from the exact baseline")
    managed = [r for r in data.get("resource_changes", []) if r.get("mode") == "managed"]
    if len(managed) != len({r["address"] for r in managed}) or {r["address"] for r in managed} != recovery["owned"] | recovery["bootstrap"]:
        raise RuntimeError("Recovery plan inventory differs from original initial plan")
    used = {r["address"] for r in managed if r["change"]["actions"] not in (["no-op"], ["create"])}
    if used != set(recovery["approved"]):
        raise RuntimeError("Recovery actions differ from the exact approved action inventory")


def recovery_unknown(marker):
    """Terraform unknown trees contain only literal booleans and containers."""
    if type(marker) is bool:
        return marker
    if isinstance(marker, dict) and all(isinstance(key, str) for key in marker):
        return any([recovery_unknown(value) for value in marker.values()])
    if isinstance(marker, list):
        return any([recovery_unknown(value) for value in marker])
    raise RuntimeError("Malformed recovery unknown marker")


def recovery_scratch_volume(volume):
    return volume == [{"name": "scratch", "configure_at_launch": False, "host_path": "",
        "docker_volume_configuration": [], "efs_volume_configuration": [],
        "fsx_windows_file_server_volume_configuration": [], "s3files_volume_configuration": []}] and (
            volume[0]["configure_at_launch"] is False)


def recovery_ecs_default_settings(before):
    return (before.get("enable_fault_injection") is False and
            recovery_scratch_volume(before.get("volume")) and
            before.get("ipc_mode") == "" and before.get("pid_mode") == "")


def recovery_container_settings_match(before, after):
    old, new = json.loads(json.dumps(before)), json.loads(json.dumps(after))
    # ECS returns container-level cpu=0 when Terraform omits that setting.
    # Limit this equivalence to an absent key and a literal integer zero.
    for absent, present in ((old, new), (new, old)):
        if "cpu" not in absent and type(present.get("cpu")) is int and present["cpu"] == 0:
            present.pop("cpu")
    for key in ("portMappings", "volumesFrom", "systemControls"):
        if (type(old.get(key)) is list and old[key] == [] and
                (key not in new or type(new[key]) is list and new[key] == [])):
            old.pop(key)
            new.pop(key, None)
    old_caps = old.get("linuxParameters", {}).get("capabilities", {})
    new_caps = new.get("linuxParameters", {}).get("capabilities", {})
    if (type(old_caps.get("add")) is list and old_caps["add"] == [] and
            ("add" not in new_caps or type(new_caps["add"]) is list and new_caps["add"] == [])):
        old_caps.pop("add")
        new_caps.pop("add", None)
    for container in (old, new):
        container.pop("image", None)
        container["environment"] = sorted((e for e in container.get("environment", [])
            if e.get("name") != "PEASO_SOURCE_VERSION"), key=lambda e: e["name"])
    return old == new


def recovery_action(resource, recovery):
    address, change = resource["address"], resource["change"]
    actions, before, after = change["actions"], change.get("before"), change.get("after")
    unknown = change.get("after_unknown", {})
    if not isinstance(unknown, dict):
        raise RuntimeError("Malformed recovery unknown marker root")
    has_unknown = recovery_unknown(unknown)
    if resource.get("module_address") or resource["type"] + "." + resource["name"] not in ALLOWED_RESOURCES:
        raise RuntimeError("Recovery resource is outside the dedicated root")
    if actions == ["create"]:
        if address not in RECOVERY_MISSING or before is not None:
            raise RuntimeError("Recovery create is outside the original missing four")
        return "original-missing-create"
    if before != recovery["resources"].get(address) or not isinstance(before, dict) or not recovery_identity(address, before):
        raise RuntimeError("Recovery before identity/values differ from baseline")
    if actions == ["no-op"]:
        if before != after or has_unknown:
            raise RuntimeError("Recovery no-op must be completely known and unchanged")
        return "bootstrap-no-op" if address in recovery["bootstrap"] else "baseline-no-op"
    approval = recovery["approved"].get(address)
    if not approval or actions != approval["actions"]:
        raise RuntimeError("Recovery action is not approved for this exact owned identity")
    allowed_fields = {
        "source-runtime-lambda": {"filename", "source_code_hash", "source_code_size", "environment", "last_modified",
                                  "version", "qualified_arn", "qualified_invoke_arn"},
        "immutable-task-revision": {"container_definitions", "arn", "arn_without_revision", "id", "revision"},
        "workflow-task-references": {"definition"},
        "workflow-iam-task-references": {"policy"},
    }[approval["reason"]]
    if not isinstance(after, dict):
        raise RuntimeError("Recovery after values must be known objects")
    after, unknown = dict(after), dict(unknown)
    if approval["reason"] == "immutable-task-revision":
        # The exact baseline and byte-identical workflow.tf are checked first.
        # Normalize only the provider's observed empty/default consequences.
        for key, empty in (("ipc_mode", ""), ("pid_mode", ""), ("tags", {})):
            if key in before and before[key] == empty and key in after and after[key] is None:
                after[key] = before[key]
        if (recovery_ecs_default_settings(before) and
                after.get("enable_fault_injection") is None and
                unknown.get("enable_fault_injection") is True):
            after["enable_fault_injection"] = False
            unknown.pop("enable_fault_injection")
        volumes, markers = before.get("volume"), unknown.get("volume")
        if (recovery_ecs_default_settings(before) and
                after.get("volume") == [{k: v for k, v in volumes[0].items() if k != "configure_at_launch"}] and
                isinstance(markers, list) and len(markers) == 1 and isinstance(markers[0], dict) and
                markers[0].get("configure_at_launch") is True):
            after["volume"] = volumes
            unknown["volume"] = [{k: v for k, v in markers[0].items() if k != "configure_at_launch"}]
    if any(before.get(key) != after.get(key) or recovery_unknown(unknown.get(key, False))
            for key in (set(before) | set(after) | set(unknown)) - allowed_fields):
        raise RuntimeError("Recovery changes fields outside the approved source/reference consequence")
    if approval["reason"] == "source-runtime-lambda":
        old_env = before.get("environment", [{}])[0].get("variables", {})
        new_env = after.get("environment", [{}])[0].get("variables", {})
        if recovery_unknown(unknown.get("environment", False)) or any(old_env.get(k) != new_env.get(k)
                for k in (set(old_env) | set(new_env)) - {"PEASO_SOURCE_VERSION", "PEASO_SOURCE_URL"}):
            raise RuntimeError("Recovery Lambda environment changes unrelated keys or defers known values")
    if approval["reason"] == "immutable-task-revision":
        if recovery_unknown(unknown.get("container_definitions", False)):
            raise RuntimeError("Recovery task container definitions must be known")
        old = json.loads(before.get("container_definitions", "[]"))
        new = json.loads(after.get("container_definitions", "[]"))
        if len(old) != 1 or len(new) != 1:
            raise RuntimeError("Recovery task container definitions missing")
        if not recovery_container_settings_match(old[0], new[0]):
            raise RuntimeError("Recovery task changes unrelated container settings")
    if approval["reason"] in {"workflow-task-references", "workflow-iam-task-references"}:
        field = "definition" if approval["reason"] == "workflow-task-references" else "policy"
        # Exact pinned workflow.tf governs unknown revision ARNs. Known values may
        # change only revision suffixes on the two owned CSPM task families.
        pattern = rf"arn:aws:ecs:us-east-1:{ACCOUNT}:task-definition/hacktricks-cspm-(collector|analyzer):[1-9][0-9]*"
        if field in unknown and type(unknown[field]) is not bool:
            raise RuntimeError("Malformed recovery reference unknown marker")
        if not unknown.get(field, False) and json.loads(re.sub(pattern, r"owned-task-\1", before.get(field, ""))) != json.loads(re.sub(pattern, r"owned-task-\1", after.get(field, ""))):
            raise RuntimeError("Recovery workflow/policy changes unrelated references")
    return approval["reason"]


def recovery_live_state_matches(current, baseline):
    """Allow only top-level validation-row ordering in native state pull."""
    from collections import Counter
    if not isinstance(current, dict) or not isinstance(baseline, dict):
        return False
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    try:
        if canonical(current) == canonical(baseline):
            return True
        if canonical({k: v for k, v in current.items() if k != "check_results"}) != canonical(
                {k: v for k, v in baseline.items() if k != "check_results"}):
            return False
        current_rows, baseline_rows = current.get("check_results"), baseline.get("check_results")
        if not isinstance(current_rows, list) or not isinstance(baseline_rows, list):
            return False
        return Counter(canonical(row) for row in current_rows) == Counter(canonical(row) for row in baseline_rows)
    except (TypeError, ValueError):
        return False


def successor_live_state_matches(current, baseline):
    """Preserve full state and validation rows; accept one proven two-object order."""
    if recovery_live_state_matches(current, baseline):
        return True
    if not isinstance(current, dict) or not isinstance(baseline, dict):
        return False
    target = ("resource", "aws_s3_object.customer_role_template")
    def normalized(state):
        rows = state.get("check_results")
        if not isinstance(rows, list) or len(rows) != 7:
            return None
        matches = [row for row in rows if isinstance(row, dict) and
                   (row.get("object_kind"), row.get("config_addr")) == target]
        if len(matches) != 1 or not isinstance(matches[0].get("objects"), list) or len(matches[0]["objects"]) != 2:
            return None
        from copy import deepcopy
        value = deepcopy(state)
        for row in value["check_results"]:
            if (row.get("object_kind"), row.get("config_addr")) == target:
                row["objects"] = sorted(row["objects"], key=current_update.canonical)
        return value
    left, right = normalized(current), normalized(baseline)
    return left is not None and right is not None and recovery_live_state_matches(left, right)


def verify_recovery_live(recovery, session):
    """Host-only read checks immediately before apply; no state write here."""
    if session.client("sts").get_caller_identity().get("Account") != ACCOUNT:
        raise RuntimeError("Recovery live account differs")
    current = json.loads(terraform("state", "pull", capture=True).stdout)
    if not recovery_live_state_matches(current, recovery["state"]):
        raise RuntimeError("Recovery live baseline changed; apply refused")
    workflow = f"arn:aws:states:us-east-1:{ACCOUNT}:stateMachine:hacktricks-cspm"
    if session.client("stepfunctions").list_executions(stateMachineArn=workflow, statusFilter="RUNNING", maxResults=1).get("executions"):
        raise RuntimeError("Recovery has active hosted workflow jobs")
    cluster = f"arn:aws:ecs:us-east-1:{ACCOUNT}:cluster/hacktricks-cspm"
    if session.client("ecs").list_tasks(cluster=cluster, desiredStatus="RUNNING", maxResults=1).get("taskArns"):
        raise RuntimeError("Recovery has active hosted ECS jobs")
    # A fresh read-only refresh catches provider-side drift that has not changed
    # the backend serial. Never apply this temporary refresh-only plan.
    import tempfile
    with tempfile.TemporaryDirectory(prefix="peaso-recovery-preapply-", dir=BUILD) as folder:
        refresh = Path(folder) / "never-apply-refresh.tfplan"
        terraform("plan", "-refresh-only", "-input=false", f"-out={refresh}")
        fresh = json.loads(terraform("show", "-json", refresh, capture=True).stdout)
        prior = fresh.get("prior_state", {}).get("values", {}).get("root_module", {})
        if fresh.get("resource_drift", []) != recovery["drift_rows"] or prior.get("child_modules") or {
                r["address"]: r["values"] for r in prior.get("resources", []) if r.get("mode") == "managed"} != recovery["resources"]:
            raise RuntimeError("Recovery fresh provider drift/before values differ from baseline")
    current = json.loads(terraform("state", "pull", capture=True).stdout)
    if not recovery_live_state_matches(current, recovery["state"]):
        raise RuntimeError("Recovery live baseline changed during preflight")


def verify_current_update_live(plan, contract_path, approved_sha256, session, *, successor=False, artifact=False):
    """Read-only account, state, drift and active-work guard before one saved apply."""
    import tempfile
    if session.client("sts").get_caller_identity().get("Account") != ACCOUNT:
        raise RuntimeError("Current-update live AWS account differs")
    verify_backend()
    raw = terraform("show", "-json", plan, capture=True).stdout
    if successor and artifact:
        raise RuntimeError("Artifact and successor live guards are mutually exclusive")
    update = artifact_update if artifact else (successor_update if successor else current_update)
    context = update.load_context(plan, raw.encode(), json.loads(raw),
                                  Path(contract_path), approved_sha256, INFRA, BUILD)
    current = json.loads(terraform("state", "pull", capture=True).stdout)
    state_matches = (artifact_update.state_pull_matches if artifact else
                     successor_live_state_matches if successor else recovery_live_state_matches)
    if not state_matches(current, context["state"]):
        raise RuntimeError("Current-update live state changed after plan review")
    workflow = f"arn:aws:states:us-east-1:{ACCOUNT}:stateMachine:hacktricks-cspm"
    if session.client("stepfunctions").list_executions(
            stateMachineArn=workflow, statusFilter="RUNNING", maxResults=1).get("executions"):
        raise RuntimeError("Current-update has an active owned workflow")
    cluster = f"arn:aws:ecs:us-east-1:{ACCOUNT}:cluster/hacktricks-cspm"
    ecs = session.client("ecs")
    for status in ("RUNNING", "PENDING"):
        if ecs.list_tasks(cluster=cluster, desiredStatus=status, maxResults=1).get("taskArns"):
            raise RuntimeError("Current-update has an active owned ECS task")
    table = "hacktricks-cspm"
    dynamodb = session.client("dynamodb")
    lock = dynamodb.get_item(TableName=table, Key={"PK": {"S": "GLOBAL"}, "SK": {"S": "SCAN_LOCK"}},
                             ConsistentRead=True).get("Item")
    if lock:
        if "expires_at" not in lock or int(lock["expires_at"]["N"]) > time.time():
            raise RuntimeError("Current-update has an active or malformed global scan lock")
    arguments = current_update.active_owned_jobs_query(table, int(time.time()))
    for _ in range(100):
        page = dynamodb.scan(**arguments)
        if page.get("Count", 0):
            raise RuntimeError("Current-update has an unexpired owned scan job")
        if not page.get("LastEvaluatedKey"):
            break
        arguments["ExclusiveStartKey"] = page["LastEvaluatedKey"]
    else:
        raise RuntimeError("Current-update owned job page bound exceeded")
    with tempfile.TemporaryDirectory(prefix="peaso-current-update-refresh-", dir=BUILD) as folder:
        refresh = Path(folder) / "never-apply-refresh.tfplan"
        terraform("plan", "-refresh-only", "-lock=false", "-input=false", f"-out={refresh}")
        fresh = json.loads(terraform("show", "-json", refresh, capture=True).stdout)
        prior = fresh.get("prior_state", {}).get("values", {}).get("root_module", {})
        before = {row["address"]: row.get("values") for row in prior.get("resources", [])
                  if row.get("mode") == "managed"}
        if (fresh.get("resource_drift", []) != context["drift_rows"] or
                prior.get("child_modules") or before != context["resources"]):
            raise RuntimeError("Current-update fresh provider values or exact reviewed drift changed")
    current = json.loads(terraform("state", "pull", capture=True).stdout)
    if not state_matches(current, context["state"]):
        raise RuntimeError("Current-update live state changed during preapply guard")
    contract = json.loads(current_update.private_artifact(Path(contract_path), approved_sha256))
    approved_plan = contract["review"]["plan"] if artifact else contract["plan"]
    if hashlib.sha256(plan.read_bytes()).hexdigest() != approved_plan["sha256"]:
        raise RuntimeError("Current-update saved plan changed during preapply guard")


def verify_current_update_resolved(session, plan, contract_path, approved_sha256, definition, revisions,
                                   *, successor=False, artifact=False):
    """Read exact resolved owned policies and immutable role bytes after apply."""
    raw = terraform("show", "-json", plan, capture=True).stdout
    data = json.loads(raw)
    if successor and artifact:
        raise RuntimeError("Artifact and successor resolved guards are mutually exclusive")
    update = artifact_update if artifact else (successor_update if successor else current_update)
    context = update.load_context(plan, raw.encode(), data, Path(contract_path),
                                  approved_sha256, INFRA, BUILD)
    resources = context["resources"]
    planned = {row["address"]: row for row in data["resource_changes"] if row.get("mode") == "managed"}
    iam = session.client("iam")
    def role_policy(address):
        before = resources[address]
        value = iam.get_role_policy(RoleName=before["role"], PolicyName=before["name"])["PolicyDocument"]
        if not isinstance(value, dict):
            raise RuntimeError("Resolved owned IAM policy is malformed")
        return value
    workflow_policy = role_policy("aws_iam_role_policy.workflow")
    api_policy = role_policy("aws_iam_role_policy.api")
    s3 = session.client("s3")
    template_bucket = resources["aws_s3_bucket.templates[0]"]["id"]
    policy = json.loads(s3.get_bucket_policy(Bucket=template_bucket)["Policy"])
    update.check_resolved_documents(resources, planned, definition, workflow_policy,
                                    api_policy, policy, revisions)
    def exact_object(bucket, key, expected_sha256, *, template, new_object=False):
        response = s3.get_object(Bucket=bucket, Key=key, **(
            {"ChecksumMode": "ENABLED"} if new_object else {}))
        body = response["Body"]
        try:
            if not isinstance(response.get("ContentLength"), int) or response["ContentLength"] > 1_000_000:
                raise RuntimeError("Resolved customer-role object exceeds the reviewed read bound")
            content = body.read(1_000_001)
        finally:
            body.close()
        if len(content) != response["ContentLength"] or hashlib.sha256(content).hexdigest() != expected_sha256:
            raise RuntimeError("Resolved customer-role object bytes differ from signed content")
        if (response.get("ContentType") != "application/json" or
                response.get("ContentDisposition") != 'attachment; filename="customer-role.json"'):
            raise RuntimeError("Resolved customer-role object headers differ")
        if template and (response.get("Metadata") != {"sha256": expected_sha256} or
                         response.get("CacheControl") != "public,max-age=31536000,immutable"):
            raise RuntimeError("Resolved immutable customer-role metadata differs")
        if new_object:
            current_update.check_reviewed_object_checksum(response, content, expected_sha256)
            acl = s3.get_object_acl(Bucket=bucket, Key=key)
            owner = (acl.get("Owner") or {}).get("ID")
            grants = acl.get("Grants")
            grantee = grants[0].get("Grantee") if isinstance(grants, list) and len(grants) == 1 else None
            if (not isinstance(owner, str) or not owner or not isinstance(grantee, dict) or
                    grantee.get("ID") != owner or grantee.get("Type") != "CanonicalUser" or
                    set(grantee) - {"ID", "Type", "DisplayName"} or
                    grants[0].get("Permission") != "FULL_CONTROL"):
                raise RuntimeError("Resolved immutable object ACL differs from bucket-owner-only access")
    old_templates = (
        "d7f7b815628bb270f4bd40f985d70de7ba1bbd50cefa4f429031ea0a74e08bcd",
        "7e6fc610eee9021025ffd498c8dc924d740975a34c56f291bc7317a7db182dbe",
    )
    for item in (*old_templates, *current_update.TEMPLATE_HASHES):
        exact_object(template_bucket, f"customer-role-{item}.json", item, template=True,
                     new_object=item in current_update.TEMPLATE_HASHES)
    frontend_bucket = resources["aws_s3_bucket.frontend"]["id"]
    exact_object(frontend_bucket, CUSTOMER_ROLE_DOWNLOAD_KEY,
                 current_update.TEMPLATE_HASHES[-1], template=False)


def check_current_api_policy_identity(before, after):
    """Allow only the existing generated API inline-policy identity on update."""
    role = "hacktricks-cspm-api"
    name = before.get("name") if isinstance(before, dict) else None
    if (not isinstance(name, str) or not re.fullmatch(r"terraform-[a-f0-9]{26}", name) or
            before.get("role") != role or before.get("id") != f"{role}:{name}" or
            not isinstance(after, dict) or after.get("name") != name or
            after.get("role") != role or after.get("id") != before["id"]):
        raise RuntimeError("Current-update API inline-policy name/role/id binding differs")


def plan_summary(plan, bootstrap=False, recovery_baseline=None, recovery_sha256=None,
                 current_update_contract=None, current_update_sha256=None,
                 successor_update_contract=None, successor_update_sha256=None,
                 artifact_update_contract=None, artifact_update_sha256=None):
    digest = hashlib.sha256(plan.read_bytes()).hexdigest()
    raw = terraform("show", "-json", plan, capture=True).stdout
    data = json.loads(raw)
    if bool(recovery_baseline) != bool(recovery_sha256) or bootstrap and recovery_baseline:
        raise RuntimeError("Recovery requires baseline plus approved digest and cannot bootstrap ECR")
    if (bool(current_update_contract) != bool(current_update_sha256) or
            current_update_contract and (bootstrap or recovery_baseline or successor_update_contract or
                                         artifact_update_contract)):
        raise RuntimeError("Current update requires its own paired approval and cannot use bootstrap or recovery")
    if (bool(successor_update_contract) != bool(successor_update_sha256) or
            successor_update_contract and (bootstrap or recovery_baseline or current_update_contract or
                                           artifact_update_contract)):
        raise RuntimeError("Successor update requires its own paired approval and cannot use another update mode")
    if (bool(artifact_update_contract) != bool(artifact_update_sha256) or
            artifact_update_contract and (bootstrap or recovery_baseline or current_update_contract or
                                          successor_update_contract)):
        raise RuntimeError("Artifact update requires its own paired approval and cannot use another update mode")
    recovery = recovery_context(recovery_baseline, recovery_sha256) if recovery_baseline else None
    approved_update = current_update.load_context(
        plan, raw.encode(), data, Path(current_update_contract), current_update_sha256, INFRA, BUILD
    ) if current_update_contract else None
    if successor_update_contract:
        approved_update = successor_update.load_context(
            plan, raw.encode(), data, Path(successor_update_contract), successor_update_sha256, INFRA, BUILD)
    if artifact_update_contract:
        approved_update = artifact_update.load_context(
            plan, raw.encode(), data, Path(artifact_update_contract), artifact_update_sha256, INFRA, BUILD)
    if recovery:
        recovery_terraform_delta(plan, recovery)
        recovery_plan_inventory(data, recovery)
    changes, task_sizes, api_environments, required_checks = [], {}, [], []
    runtime = any(r.get("mode") == "managed" and r.get("type") in {"aws_ecs_task_definition", "aws_lambda_function"}
                  for r in data.get("resource_changes", []))
    expected = deployment_expectations(data, plan) if runtime and not bootstrap else None
    if expected and expected.get("api_s3_delivery", False):
        check_api_delivery_plan(data, expected)
    bootstrap_allowed = {"aws_ecr_repository.worker", "aws_ecr_lifecycle_policy.worker"}
    for resource in data.get("resource_changes", []):
        if resource.get("mode") != "managed":
            continue
        actions = resource["change"]["actions"]
        reason = recovery_action(resource, recovery) if recovery else None
        if actions == ["no-op"]:
            if resource["type"] in {"aws_ecs_task_definition", "aws_lambda_function"} and not (recovery or approved_update):
                raise RuntimeError("Runtime review requires create actions; unknowns cannot be deferred on no-op")
            if not (recovery or approved_update) or resource["type"] not in {"aws_ecs_task_definition", "aws_lambda_function"}:
                continue
        if "delete" in actions and not (recovery or approved_update):
            raise RuntimeError(f"Destructive plan refused: {resource['address']}")
        if resource.get("module_address"):
            raise RuntimeError("Unexpected child module in the dedicated CSPM root")
        if resource["type"] + "." + resource["name"] not in ALLOWED_RESOURCES:
            raise RuntimeError(f"Resource outside the dedicated CSPM inventory: {resource['address']}")
        if not (recovery or approved_update) and (actions != ["create"] or resource["change"].get("before") is not None):
            raise RuntimeError(f"Non-additive plan refused: {resource['address']} ({','.join(actions)})")
        if bootstrap and resource["address"] not in bootstrap_allowed:
            raise RuntimeError("Bootstrap plan contains a resource outside dedicated ECR")
        # Every managed before/after must belong to CSPM. IAM policies, route
        # associations, and secret versions inherit that scope through references.
        values = resource["change"].get("after") or {}
        owned_workflow_policy_name = False
        owned_api_policy_name = False
        if (resource["address"] == "aws_iam_role_policy.workflow" and
                (recovery and reason == "workflow-iam-task-references" or approved_update)):
            before = resource["change"]["before"]
            policy_name = before.get("name")
            role_name = before.get("role")
            if (not isinstance(policy_name, str) or not policy_name or
                    values.get("name") != policy_name or
                    role_name != "hacktricks-cspm-workflow" or values.get("role") != role_name or
                    before.get("id") != f"{role_name}:{policy_name}" or values.get("id") != before["id"]):
                raise RuntimeError("Recovery workflow inline-policy name/role/id binding differs from baseline")
            # The approved action already proved the exact owned before values
            # and reference-only delta. Its provider-generated name is unchanged.
            owned_workflow_policy_name = True
        if resource["address"] == "aws_iam_role_policy.api" and approved_update:
            check_current_api_policy_identity(resource["change"]["before"], values)
            owned_api_policy_name = True
        for name in ("name", "bucket", "function_name", "family", "alarm_name", "repository"):
            value = values.get(name)
            if resource["type"] == "aws_apigatewayv2_stage" and name == "name" and value == "$default":
                continue
            if name == "name" and (owned_workflow_policy_name or owned_api_policy_name):
                continue
            if value and not (str(value).startswith("hacktricks-cspm") or
                              str(value).startswith("/ecs/hacktricks-cspm") or
                              str(value).startswith("/aws/lambda/hacktricks-cspm") or
                              str(value).startswith("alias/hacktricks-cspm") or
                              str(value) == "cspm.hacktricks.wiki"):
                # S3 bucket policies contain generated bucket IDs, not wiki IDs.
                raise RuntimeError(f"Unrelated named resource refused: {resource['address']}")
        if resource["type"] == "aws_route53_record" and values.get("name") != "cspm.hacktricks.wiki":
            raise RuntimeError("DNS plan must address only cspm.hacktricks.wiki")
        if resource["type"] == "aws_ecs_task_definition":
            stage = resource.get("index")
            if stage not in {"collector", "analyzer"}:
                raise RuntimeError("Unexpected worker stage in saved plan")
            task_sizes[stage] = {key: int(values[key]) for key in ["cpu", "memory"]}
            if task_sizes[stage] != expected["worker_resources"][stage]:
                raise RuntimeError("Saved task sizing differs from reviewed worker_resources variable")
            definitions = values.get("container_definitions")
            declared_unknown = resource["change"].get("after_unknown", {}).get("container_definitions") is True
            if definitions is None and declared_unknown:
                required_checks.append({"address": resource["address"], "field": "container_definitions", "stage": stage})
                containers = []
            else:
                containers = json.loads(definitions or "[]")
                if not isinstance(containers, list) or len(containers) != 1:
                    raise RuntimeError("Saved worker container definitions missing without apply-time unknown marker")
            for container in containers:
                if container.get("image") != expected["worker_image"]:
                    raise RuntimeError("Saved worker image differs from immutable image variable")
                environment = container_environment(container)
                check_environment(environment, expected["worker_environments"][stage])
                for key, value in {"PEASO_TASK_VCPU": task_sizes[stage]["cpu"] / 1024,
                                   "PEASO_TASK_MEMORY_GIB": task_sizes[stage]["memory"] / 1024}.items():
                    if float(environment.get(key, -1)) != value:
                        raise RuntimeError("Worker cost telemetry differs from saved task sizing")
                api_environments.append(environment)
        if resource["type"] == "aws_lambda_function":
            if resource["name"] not in {"api", "scheduler"}:
                raise RuntimeError("Unexpected Lambda in runtime review")
            if not expected.get("api_s3_delivery", False) and values.get("filename") != expected["api_zip"]:
                raise RuntimeError("Saved Lambda filename differs from verified API ZIP variable")
            blocks = values.get("environment")
            markers = resource["change"].get("after_unknown", {}).get("environment")
            if not isinstance(blocks, list) or len(blocks) != 1 or not isinstance(blocks[0], dict):
                raise RuntimeError("Saved Lambda environment block missing or malformed")
            marker = markers[0].get("variables") if isinstance(markers, list) and len(markers) == 1 and isinstance(markers[0], dict) else None
            environment = blocks[0].get("variables", {})
            check_environment(environment, expected["api_environment"], marker)
            if marker is True or isinstance(marker, dict) and any(v is True for v in marker.values()):
                required_checks.append({"address": resource["address"], "field": "environment.variables", "function": resource["name"]})
            else:
                api_environments.append(environment)
        if resource["type"] == "aws_lambda_function" and not expected.get("api_s3_delivery", False) and values.get("filename"):
            import base64
            package = Path(values["filename"])
            current_hash = base64.b64encode(hashlib.sha256(package.read_bytes()).digest()).decode()
            if current_hash != values.get("source_code_hash"):
                raise RuntimeError("API ZIP changed after planning; recreate the plan and obtain review")
        changes.append(dict({"address": resource["address"], "actions": actions}, **({"reason": reason} if recovery else {})))
    if task_sizes:
        verify_worker_resources(task_sizes)
        for environment in api_environments:
            for stage, size in task_sizes.items():
                for suffix, value in {"VCPU": size["cpu"] / 1024, "MEMORY_GIB": size["memory"] / 1024}.items():
                    if float(environment.get(f"PEASO_{stage.upper()}_{suffix}", -1)) != value:
                        raise RuntimeError("API/worker cost telemetry differs from saved task sizing")
    if bootstrap and any(c["actions"] != ["create"] for c in changes):
        raise RuntimeError("ECR bootstrap must be create-only")
    if hashlib.sha256(plan.read_bytes()).hexdigest() != digest:
        raise RuntimeError("Saved plan changed during review")
    summary = {"plan": str(plan), "sha256": digest, "resources": changes,
               "json_sha256": hashlib.sha256(raw.encode()).hexdigest(),
               "required_resolved_checks": required_checks,
               "counts": {action: sum(action in c["actions"] for c in changes)
                          for action in ["create", "update", "delete"]}}
    report = plan.with_suffix(".review.json")
    if recovery:
        summary["recovery"] = {"baseline_path": str(recovery_baseline), "baseline_sha256": recovery_sha256,
            "failed_plan_sha256": RECOVERY_FAILED_PLAN_SHA256, "failed_plan_json_sha256": RECOVERY_FAILED_JSON_SHA256,
            "state_sha256": recovery["baseline"]["state"]["sha256"], "lineage": recovery["state"]["lineage"],
            "serial": recovery["state"]["serial"], "approved_actions": recovery["approved"]}
        if recovery["baseline"].get("read_enrichment_approval"):
            summary["recovery"]["read_enrichment_approval"] = recovery["baseline"]["read_enrichment_approval"]
    if approved_update:
        summary["artifact_update" if artifact_update_contract else
                "successor_update" if successor_update_contract else "current_update"] = {
            "contract_path": approved_update["contract_path"],
            "contract_sha256": approved_update["contract_sha256"],
            "state_sha256": approved_update["state_sha256"],
            "lineage": approved_update["lineage"], "serial": approved_update["serial"],
            "approved_addresses": sorted(approved_update["approved_changes"]),
            "release": approved_update["release"],
        }
    if expected:
        if recovery:
            expected["recovery_ecs_defaults"] = [r["index"] for r in data["resource_changes"]
                if r.get("type") == "aws_ecs_task_definition" and
                recovery_ecs_default_settings(r["change"].get("before") or {})]
            expected["recovery_ecs_containers"] = {r["index"]: json.loads(r["change"]["before"]["container_definitions"])[0]
                for r in data["resource_changes"] if r.get("type") == "aws_ecs_task_definition"}
            required_checks.extend({"stage": stage, "field": "ecs_recovery_defaults"}
                                   for stage in expected["recovery_ecs_defaults"])
        if approved_update:
            expected["current_ecs_containers"] = {
                r["index"]: json.loads(r["change"]["before"]["container_definitions"])[0]
                for r in data["resource_changes"] if r.get("type") == "aws_ecs_task_definition"
                and r.get("address") in approved_update["approved_changes"]}
            expected["current_ecs_defaults"] = [
                r["index"] for r in data["resource_changes"]
                if r.get("type") == "aws_ecs_task_definition"
                and r.get("address") in approved_update["approved_changes"]]
        summary["resolved_contract"] = expected
        summary["resolved_validation_required"] = True
        summary["lambda_configuration"] = {
            r["name"]: {key: r["change"]["after"].get(key) for key in
                        ("function_name", "source_code_hash", "memory_size", "timeout", "runtime", "handler", "architectures")}
            for r in data["resource_changes"] if r.get("type") == "aws_lambda_function" and r.get("mode") == "managed"}
    private_json(report, summary)
    print(json.dumps({key: value for key, value in summary.items() if key != "resolved_contract"}, indent=2))
    return digest


def private_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        metadata = os.fstat(stream.fileno())
        if metadata.st_uid != os.getuid() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RuntimeError("Private receipt must be owned and unlinked")
        os.fchmod(stream.fileno(), 0o600)
        os.ftruncate(stream.fileno(), 0)
        json.dump(value, stream, indent=2)
        stream.write("\n")


def private_bytes_once(path, content):
    """Preserve the exact Terraform JSON bytes as a new private review input."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        metadata = os.fstat(stream.fileno())
        if (metadata.st_uid != os.getuid() or not stat.S_ISREG(metadata.st_mode) or
                metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600):
            raise RuntimeError("Saved plan JSON must be a new owned mode-0600 file")
        stream.write(content)


def verify_resolved_api_delivery(session, contract):
    """Read back the exact content-addressed object wired to both Lambdas."""
    state = json.loads(terraform("show", "-json", capture=True).stdout)
    rows = {item.get("address"): item.get("values") or {} for item in
            ((state.get("values") or {}).get("root_module") or {}).get("resources", [])}
    package = rows.get("aws_s3_object.api_zip") or {}
    bucket = f"hacktricks-cspm-artifacts-{ACCOUNT}"
    key = api_package_key(contract["api_code_sha256"])
    if (package.get("bucket") != bucket or package.get("key") != key or
            package.get("source_hash") != contract["api_code_sha256"] or
            rows.get("aws_s3_bucket_versioning.artifacts")):
        raise RuntimeError("Resolved API package key or bucket differs from reviewed delivery")
    for name in ("api", "scheduler"):
        values = rows.get(f"aws_lambda_function.{name}") or {}
        if (values.get("filename") is not None or values.get("s3_bucket") != bucket or
                values.get("s3_key") != key or values.get("s3_object_version") is not None):
            raise RuntimeError(f"Resolved {name} Lambda references a different S3 package")
    import base64
    digest = base64.b64decode(contract["api_code_sha256"], validate=True).hex()
    response = session.client("s3").head_object(Bucket=bucket, Key=key, ExpectedBucketOwner=ACCOUNT)
    if (response.get("Metadata", {}).get("sha256") != digest or
            response.get("ServerSideEncryption") != "aws:kms" or
            response.get("SSEKMSKeyId") != package.get("kms_key_id") or
            response.get("ContentLength") != Path(contract["api_zip"]).stat().st_size):
        raise RuntimeError("Resolved API package object metadata differs from reviewed ZIP")


def verify_resolved_deployment(session, plan, reviewed_sha256, recovery_baseline=None, recovery_sha256=None,
                               current_update_contract=None, current_update_sha256=None,
                               successor_update_contract=None, successor_update_sha256=None,
                               artifact_update_contract=None, artifact_update_sha256=None):
    """Read actual workflow-selected revisions and functions; disclose no environments."""
    if hashlib.sha256(plan.read_bytes()).hexdigest() != reviewed_sha256:
        raise RuntimeError("Plan changed after coordinator review; resolved validation refused")
    verify_backend()
    if session.client("sts").get_caller_identity().get("Account") != ACCOUNT:
        raise RuntimeError("Resolved validation requires the dedicated wiki account")
    previous_review = json.loads(plan.with_suffix(".review.json").read_text()) if (
        recovery_baseline or current_update_contract or successor_update_contract or artifact_update_contract) else None
    if plan_summary(plan, recovery_baseline=recovery_baseline, recovery_sha256=recovery_sha256,
                    current_update_contract=current_update_contract,
                    current_update_sha256=current_update_sha256,
                    successor_update_contract=successor_update_contract,
                    successor_update_sha256=successor_update_sha256,
                    artifact_update_contract=artifact_update_contract,
                    artifact_update_sha256=artifact_update_sha256) != reviewed_sha256:
        raise RuntimeError("Saved plan changed during resolved validation")
    review = json.loads(plan.with_suffix(".review.json").read_text())
    if previous_review is not None and previous_review != review:
        raise RuntimeError("Approved review changed during resolved validation")
    required = {'aws_ecs_task_definition.tasks["collector"]', 'aws_ecs_task_definition.tasks["analyzer"]',
                "aws_lambda_function.api", "aws_lambda_function.scheduler"}
    if not required.issubset({r["address"] for r in review["resources"]}) or not review.get("resolved_validation_required"):
        raise RuntimeError("Resolved validation requires the complete reviewed runtime deployment")
    contract = review["resolved_contract"]
    output = json.loads(terraform("output", "-json", capture=True).stdout)
    def value(key):
        result = output.get(key, {}).get("value")
        if not isinstance(result, str) or not result:
            raise RuntimeError(f"Missing resolved deployment output: {key}")
        return result
    workflow = value("workflow_arn")
    if workflow != f"arn:aws:states:us-east-1:{ACCOUNT}:stateMachine:hacktricks-cspm":
        raise RuntimeError("Resolved workflow is outside the dedicated deployment")
    secret = value("credential_secret_arn")
    if not re.fullmatch(contract["api_environment"]["PEASO_CREDENTIAL_SECRET_ARN"]["arn_pattern"], secret):
        raise RuntimeError("Resolved credential secret is outside the dedicated deployment")
    bucket, table = value("artifact_bucket"), value("metadata_table")
    if bucket != contract["api_environment"]["PEASO_ARTIFACT_BUCKET"] or table != "hacktricks-cspm":
        raise RuntimeError("Resolved storage is outside the dedicated deployment")
    if value("api_function") != "hacktricks-cspm-api":
        raise RuntimeError("Resolved API function is outside the dedicated deployment")
    if contract.get("api_s3_delivery"):
        verify_resolved_api_delivery(session, contract)
    definition = json.loads(session.client("stepfunctions").describe_state_machine(stateMachineArn=workflow)["definition"])
    ecs = session.client("ecs")
    revisions = {}
    for stage, state in (("collector", "Collect"), ("analyzer", "Analyze")):
        parameters = definition.get("States", {}).get(state, {}).get("Parameters", {})
        arn = parameters.get("TaskDefinition")
        if not isinstance(arn, str) or not re.fullmatch(f"arn:aws:ecs:us-east-1:{ACCOUNT}:task-definition/hacktricks-cspm-{stage}:[1-9][0-9]*", arn):
            raise RuntimeError(f"Workflow has no dedicated resolved {stage} task revision")
        expected_overrides = {"ContainerOverrides": [{"Name": stage,
            "Command.$": f"States.Array('{stage}', '--once', '--tenant-id', $.tenant_id, '--scan-id', $.scan_id)"}]}
        if parameters.get("Overrides") != expected_overrides:
            raise RuntimeError("Workflow overrides differ from reviewed commands or override sizing/environment")
        task_response = ecs.describe_task_definition(taskDefinition=arn, **(
            {"include": ["TAGS"]} if (current_update_contract or successor_update_contract or artifact_update_contract) else {}))
        task = task_response["taskDefinition"]
        if stage in contract.get("recovery_ecs_defaults", []) or stage in contract.get("current_ecs_defaults", []):
            volumes = task.get("volumes")
            # ECS documents fault injection as opt-in, default false. The
            # recovery contract already proves the baseline and pinned source.
            if (task.get("enableFaultInjection", False) is not False or
                    task.get("ipcMode") not in (None, "") or task.get("pidMode") not in (None, "") or
                    not isinstance(volumes, list) or len(volumes) != 1 or not isinstance(volumes[0], dict) or
                    volumes[0].get("name") != "scratch" or
                    volumes[0].get("configureAtLaunch", False) is not False or
                    volumes[0].get("host", {}) != {} or
                    set(volumes[0]) - {"name", "host", "configureAtLaunch"}):
                raise RuntimeError(f"Resolved {stage} ECS default-false/scratch/IPC/PID settings differ")
        if stage in contract.get("current_ecs_defaults", []):
            actual_tags = task_response.get("tags")
            expected_tags = {"Application": "hacktricks-cspm", "ManagedBy": "Terraform"}
            if (not isinstance(actual_tags, list) or len(actual_tags) != 2 or
                    any(not isinstance(item, dict) or set(item) != {"key", "value"}
                        for item in actual_tags) or
                    {item["key"]: item["value"] for item in actual_tags} != expected_tags):
                raise RuntimeError(f"Resolved {stage} ECS tags differ from the reviewed defaults")
        size = contract["worker_resources"][stage]
        if (task.get("taskDefinitionArn") != arn or task.get("status") != "ACTIVE" or
                task.get("family") != f"hacktricks-cspm-{stage}" or
                any(str(task.get(key)) != str(size[key]) for key in ("cpu", "memory"))):
            raise RuntimeError(f"Resolved {stage} task sizing/revision differs from reviewed plan")
        containers = task.get("containerDefinitions")
        if not isinstance(containers, list) or len(containers) != 1:
            raise RuntimeError(f"Resolved {stage} task containers missing or ambiguous")
        container = containers[0]
        baseline_container = (contract.get("recovery_ecs_containers", {}).get(stage) or
                              contract.get("current_ecs_containers", {}).get(stage))
        if baseline_container is not None and not recovery_container_settings_match(baseline_container, container):
            raise RuntimeError(f"Resolved {stage} container security/settings differ from the owned baseline")
        if container.get("name") != stage or container.get("image") != contract["worker_image"]:
            raise RuntimeError(f"Resolved {stage} image differs from reviewed immutable image")
        environment = container_environment(container)
        expected = dict(contract["worker_environments"][stage], PEASO_ARTIFACT_BUCKET=bucket, PEASO_DYNAMODB_TABLE=table)
        if stage == "collector":
            expected["PEASO_CREDENTIAL_SECRET_ARN"] = secret
        check_environment(environment, expected)
        if set(environment) != set(expected):
            raise RuntimeError(f"Resolved {stage} environment has unreviewed keys")
        revisions[stage] = arn
    lambdas = session.client("lambda")
    for function in ("api", "scheduler"):
        actual = lambdas.get_function_configuration(FunctionName=f"hacktricks-cspm-{function}")
        planned = review["lambda_configuration"][function]
        for saved_key, actual_key in (("function_name", "FunctionName"), ("source_code_hash", "CodeSha256"),
                                      ("memory_size", "MemorySize"), ("timeout", "Timeout"), ("runtime", "Runtime"),
                                      ("handler", "Handler"), ("architectures", "Architectures")):
            if planned.get(saved_key) is None or actual.get(actual_key) != planned[saved_key]:
                raise RuntimeError(f"Resolved {function} configuration differs: {actual_key}")
        if (actual.get("CodeSha256") != contract["api_code_sha256"] or actual.get("State") != "Active" or
                actual.get("LastUpdateStatus") != "Successful" or actual.get("Environment", {}).get("Error")):
            raise RuntimeError(f"Resolved {function} source/state/environment is not verified")
        environment = actual.get("Environment", {}).get("Variables")
        expected = dict(contract["api_environment"], PEASO_ARTIFACT_BUCKET=bucket, PEASO_DYNAMODB_TABLE=table,
                        PEASO_CREDENTIAL_SECRET_ARN=secret, PEASO_WORKFLOW_ARN=workflow)
        check_environment(environment, expected)
        if set(environment) != set(expected):
            raise RuntimeError(f"Resolved {function} environment has unreviewed keys")
    if current_update_contract:
        verify_current_update_resolved(session, plan, current_update_contract,
                                       current_update_sha256, definition, revisions)
    if successor_update_contract:
        verify_current_update_resolved(session, plan, successor_update_contract,
                                       successor_update_sha256, definition, revisions, successor=True)
    if artifact_update_contract:
        verify_current_update_resolved(session, plan, artifact_update_contract,
                                       artifact_update_sha256, definition, revisions, artifact=True)
    receipt = {"status": "passed", "plan_sha256": reviewed_sha256, "plan_json_sha256": review["json_sha256"],
               "source_version": contract["source_version"], "task_revisions": revisions,
               "functions": ["hacktricks-cspm-api", "hacktricks-cspm-scheduler"]}
    if hashlib.sha256(plan.read_bytes()).hexdigest() != reviewed_sha256:
        raise RuntimeError("Saved plan changed during resolved validation")
    private_json(plan.with_suffix(".resolved.json"), receipt)
    print(json.dumps(receipt, indent=2))
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("package-api")
    sub.add_parser("build-frontend")
    sub.add_parser("verify-package")
    sub.add_parser("validate-workflow")
    freeze = sub.add_parser("freeze-release")
    freeze.add_argument("--source-root", type=Path,
                        help="Optional current repository path; alternate exports are refused")
    build = sub.add_parser("build-worker")
    build.add_argument("--tag", default=f"release-{int(time.time())}")
    push = sub.add_parser("push-worker")
    push.add_argument("--tag", required=True)
    plan = sub.add_parser("plan")
    plan.add_argument("--image")
    plan.add_argument("--bootstrap-ecr", action="store_true")
    plan.add_argument("--output", type=Path, default=BUILD / "cspm.tfplan")
    plan.add_argument("--save-for-review", action="store_true",
                      help="Save exact full plan and private JSON without authorizing an update")
    current_review = sub.add_parser("review-current-plan")
    current_review.add_argument("--plan", type=Path, required=True)
    successor_review = sub.add_parser("review-successor-plan")
    successor_review.add_argument("--plan", type=Path, required=True)
    artifact_review = sub.add_parser("review-artifact-plan")
    artifact_review.add_argument("--plan", type=Path, required=True)
    apply = sub.add_parser("apply")
    apply.add_argument("--plan", type=Path, required=True)
    apply.add_argument("--reviewed-sha256", required=True,
                       help="Exact plan digest approved by the coordinator")
    apply.add_argument("--bootstrap-ecr", action="store_true")
    recovery_commands = [plan, apply]
    for command in ("verify-resolved", "publish-frontend"):
        resolved = sub.add_parser(command)
        resolved.add_argument("--plan", type=Path, required=True)
        resolved.add_argument("--reviewed-sha256", required=True)
        recovery_commands.append(resolved)
    for command in recovery_commands:
        command.add_argument("--recovery-baseline", type=Path,
                             help="Private approved baseline for the exact failed initial CSPM plan")
        command.add_argument("--recovery-sha256",
                             help="Exact supervisor-reviewed baseline bytes SHA256; never a general update exception")
    for command in (current_review, apply, *recovery_commands[2:]):
        command.add_argument("--current-update-contract", type=Path)
        command.add_argument("--current-update-sha256")
    for command in (successor_review, apply, *recovery_commands[2:]):
        command.add_argument("--successor-update-contract", type=Path)
        command.add_argument("--successor-update-sha256")
    for command in (artifact_review, apply, *recovery_commands[2:]):
        command.add_argument("--artifact-update-contract", type=Path)
        command.add_argument("--artifact-update-sha256")
    verify = sub.add_parser("verify-host")
    verify.add_argument("--url", default="https://cspm.hacktricks.wiki")
    args = parser.parse_args()
    if hasattr(args, "recovery_baseline") and (bool(args.recovery_baseline) != bool(args.recovery_sha256) or
            getattr(args, "bootstrap_ecr", False) and args.recovery_baseline):
        parser.error("Recovery requires both baseline flags and cannot be combined with ECR bootstrap")
    if hasattr(args, "current_update_contract") and (
            bool(args.current_update_contract) != bool(args.current_update_sha256) or
            args.current_update_contract and (getattr(args, "recovery_baseline", None) or
                                              getattr(args, "bootstrap_ecr", False) or
                                              getattr(args, "successor_update_contract", None) or
                                              getattr(args, "artifact_update_contract", None))):
        parser.error("Current-update approval requires both exact flags and cannot use recovery or bootstrap")
    if hasattr(args, "successor_update_contract") and (
            bool(args.successor_update_contract) != bool(args.successor_update_sha256) or
            args.successor_update_contract and (getattr(args, "recovery_baseline", None) or
                                                getattr(args, "bootstrap_ecr", False) or
                                                getattr(args, "current_update_contract", None) or
                                                getattr(args, "artifact_update_contract", None))):
        parser.error("Successor-update approval requires both exact flags and its own update mode")
    if hasattr(args, "artifact_update_contract") and (
            bool(args.artifact_update_contract) != bool(args.artifact_update_sha256) or
            args.artifact_update_contract and (getattr(args, "recovery_baseline", None) or
                                               getattr(args, "bootstrap_ecr", False) or
                                               getattr(args, "current_update_contract", None) or
                                               getattr(args, "successor_update_contract", None))):
        parser.error("Artifact-update approval requires both exact flags and its own update mode")
    if args.command == "package-api":
        package_api()
        return
    if args.command == "build-frontend":
        build_frontend()
        return
    if args.command == "freeze-release":
        freeze_release(args.source_root)
        return
    if args.command == "verify-package":
        verify_api_source()
        code = """
import json
import importlib.util
from bluepeass.k8s import KubernetesApi
from bluepeass.k8s_risks import PermissionKey
from scripts.cloud_permission_risks import classify_permission
import sys
from peaso.server.materialized_catalog import summary
from peaso.server.privesc_display_catalog import _load as privilege_display
from peaso.server.lambda_handler import handler
assert importlib.util.find_spec('peaso.privesc') is not None
print('API catalog checks:',len(summary()['checks']))
assert privilege_display()['bindings']
for name in ('peaso.engine', 'peaso.privesc.evaluator', 'peaso.privesc.versioned_catalog'):
    assert name not in sys.modules, name
for path, expected in [('/api/health',200),('/api/me',401),('/api/connectors',401)]:
    event={'version':'2.0','routeKey':'$default','rawPath':path,'rawQueryString':'',
           'headers':{'host':'localhost'},'requestContext':{'stage':'$default',
           'domainName':'localhost','http':{'method':'GET','path':path,
           'sourceIp':'127.0.0.1','protocol':'HTTP/1.1'}},'isBase64Encoded':False}
    result=handler(event,None)
    assert result['statusCode']==expected,(path,result['statusCode'])
    print(path,result['statusCode'])
"""
        run(["docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none",
             "-v", f"{BUILD / 'api-package'}:/opt:ro", "-e", "PYTHONPATH=/opt",
             "-e", "PEASO_STATE_DIR=/tmp/state", "-e", "PEASO_IDENTITY_DIR=/tmp/identity",
             "python:3.12-slim", "python", "-c", code])
        return
    if args.command == "build-worker":
        build_worker(args.tag)
        return
    if args.command == "verify-host":
        import urllib.request
        import urllib.error
        results = []
        for path, expected in [("/", 200), ("/api/health", 200), ("/api/me", 401),
                               ("/api/connectors", 401), ("/api/scans", 401), ("/api/schedules", 401)]:
            request = urllib.request.Request(args.url.rstrip("/") + path)
            try:
                response = urllib.request.urlopen(request, timeout=30)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                actual = response.status
                body = response.read()
                if actual != expected:
                    raise RuntimeError(f"Hosted check {path}: expected HTTP {expected}, got {actual}")
                if path == "/api/health":
                    payload = json.loads(body)
                    if not isinstance(payload, dict):
                        raise RuntimeError("Hosted health must be a JSON object")
                results.append({"path": path, "status": actual})
        print(json.dumps({"url": args.url, "https_checks": results}, indent=2))
        return
    if args.command == "review-current-plan":
        if not args.current_update_contract:
            parser.error("Current-update saved-plan review requires the exact approved contract")
        verify_backend()
        plan_summary(args.plan.resolve(), current_update_contract=args.current_update_contract,
                     current_update_sha256=args.current_update_sha256)
        return
    if args.command == "review-successor-plan":
        if not args.successor_update_contract:
            parser.error("Successor saved-plan review requires the exact approved contract")
        verify_backend()
        plan_summary(args.plan.resolve(), successor_update_contract=args.successor_update_contract,
                     successor_update_sha256=args.successor_update_sha256)
        return
    if args.command == "review-artifact-plan":
        if not args.artifact_update_contract:
            parser.error("Artifact saved-plan review requires the exact approved contract")
        verify_backend()
        plan_summary(args.plan.resolve(), artifact_update_contract=args.artifact_update_contract,
                     artifact_update_sha256=args.artifact_update_sha256)
        return
    session = aws_identity()
    if args.command == "validate-workflow":
        from peaso_deploy_validate_workflow import validate
        validate(ROOT, TF, session)
    elif args.command == "push-worker":
        ecr = session.client("ecr")
        auth = ecr.get_authorization_token()["authorizationData"][0]
        import base64
        username, password = base64.b64decode(auth["authorizationToken"]).decode().split(":", 1)
        run(["docker", "login", "--username", username, "--password-stdin", auth["proxyEndpoint"]],
            input=password, text=True)
        run(["docker", "tag", f"peaso-worker:{args.tag}", f"{REPOSITORY}:{args.tag}"])
        run(["docker", "push", f"{REPOSITORY}:{args.tag}"])
        digest = ecr.describe_images(repositoryName="hacktricks-cspm-worker",
                                     imageIds=[{"imageTag": args.tag}])["imageDetails"][0]["imageDigest"]
        image = f"{REPOSITORY}@{digest}"
        write_vars(image, BUILD / "api.zip")
        print(f"Published immutable image: {image}")
    elif args.command == "plan":
        BUILD.mkdir(parents=True, exist_ok=True)
        if args.save_for_review and (args.bootstrap_ecr or args.recovery_baseline):
            parser.error("Save-for-review requires a full, untargeted plan without historical recovery")
        if args.save_for_review and args.output.exists():
            raise RuntimeError("Saved plan path exists; choose a new unique output path")
        if args.bootstrap_ecr:
            write_vars(ZERO_IMAGE, BUILD / "api.zip")
        elif args.image:
            write_vars(args.image, BUILD / "api.zip")
        elif not (INFRA / "deployment.auto.tfvars.json").exists():
            raise RuntimeError("Publish an image or provide its digest before the full plan")
        if not args.bootstrap_ecr and json.loads((INFRA / "deployment.auto.tfvars.json").read_text())["worker_image"] == ZERO_IMAGE:
            raise RuntimeError("Publish the built native worker before the full plan")
        command = ["plan", "-input=false", f"-out={args.output.resolve()}"]
        if args.bootstrap_ecr:
            command += ["-target=aws_ecr_repository.worker", "-target=aws_ecr_lifecycle_policy.worker"]
        terraform(*command)
        args.output.chmod(0o600)
        if args.save_for_review:
            raw = terraform("show", "-json", args.output.resolve(), capture=True).stdout
            json.loads(raw)
            private_bytes_once(args.output.with_suffix(".unreviewed.json"), raw.encode())
            print(json.dumps({"status": "unreviewed_saved_plan", "plan": str(args.output.resolve()),
                              "sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
                              "json_path": str(args.output.with_suffix(".unreviewed.json").resolve()),
                              "json_sha256": hashlib.sha256(raw.encode()).hexdigest()}, indent=2))
            return
        plan_summary(args.output.resolve(), args.bootstrap_ecr, args.recovery_baseline, args.recovery_sha256)
    elif args.command == "apply":
        actual = hashlib.sha256(args.plan.read_bytes()).hexdigest()
        if actual != args.reviewed_sha256:
            raise RuntimeError("Plan changed after coordinator review; apply refused")
        previous_review = json.loads(args.plan.with_suffix(".review.json").read_text()) if (
            args.recovery_baseline or args.current_update_contract or args.successor_update_contract or
            args.artifact_update_contract) else None
        if plan_summary(args.plan.resolve(), args.bootstrap_ecr, args.recovery_baseline, args.recovery_sha256,
                        args.current_update_contract, args.current_update_sha256,
                        args.successor_update_contract, args.successor_update_sha256,
                        args.artifact_update_contract, args.artifact_update_sha256) != args.reviewed_sha256:
            raise RuntimeError("Plan changed during review; apply refused")
        if args.recovery_baseline or args.current_update_contract or args.successor_update_contract or args.artifact_update_contract:
            if previous_review != json.loads(args.plan.with_suffix(".review.json").read_text()):
                raise RuntimeError("Approved binary/JSON/action/source review changed; apply refused")
        if args.recovery_baseline:
            recovery = recovery_context(args.recovery_baseline, args.recovery_sha256)
            verify_recovery_live(recovery, session)
            # Recheck every content-addressed evidence file immediately before the write.
            recovery_context(args.recovery_baseline, args.recovery_sha256)
            if hashlib.sha256(args.plan.read_bytes()).hexdigest() != args.reviewed_sha256:
                raise RuntimeError("Recovery plan changed before apply")
        if args.current_update_contract:
            verify_current_update_live(args.plan.resolve(), args.current_update_contract,
                                       args.current_update_sha256, session)
        if args.successor_update_contract:
            verify_current_update_live(args.plan.resolve(), args.successor_update_contract,
                                       args.successor_update_sha256, session, successor=True)
        if args.artifact_update_contract:
            verify_current_update_live(args.plan.resolve(), args.artifact_update_contract,
                                       args.artifact_update_sha256, session, artifact=True)
        terraform("apply", "-input=false", args.plan.resolve())
    elif args.command in {"verify-resolved", "publish-frontend"}:
        verify_resolved_deployment(session, args.plan.resolve(), args.reviewed_sha256,
                                   args.recovery_baseline, args.recovery_sha256,
                                   args.current_update_contract, args.current_update_sha256,
                                   args.successor_update_contract, args.successor_update_sha256,
                                   args.artifact_update_contract, args.artifact_update_sha256)
        if args.command == "verify-resolved":
            return
        frontend = source_root() / "frontend"
        manifest_path = BUILD / "frontend-build.json"
        if not manifest_path.is_file():
            raise RuntimeError("Build the frozen frontend before publication")
        manifest = json.loads(manifest_path.read_text())
        release = json.loads((BUILD / "release.json").read_text())
        if manifest["source_version"] != release["source_version"]:
            raise RuntimeError("Frontend was built from another source release")
        files = {str(path.relative_to(frontend / "dist")): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in (frontend / "dist").rglob("*") if path.is_file()}
        if files != manifest["files"] or "index.html" not in files:
            raise RuntimeError("Built frontend changed; rebuild before publication")
        output = json.loads(terraform("output", "-json", capture=True).stdout)
        if args.artifact_update_contract:
            artifact_update.check_publish_target(output)
        bucket = output["frontend_bucket"]["value"]
        run(frontend_sync_command(frontend, bucket))
        run(["aws", "s3", "cp", frontend / "dist" / "index.html", f"s3://{bucket}/index.html",
             "--cache-control", "no-cache", "--content-type", "text/html"])
        filename = f"peaso-source-{release['source_version']}.zip"
        run(["aws", "s3", "cp", BUILD / filename, f"s3://{bucket}/source/{filename}",
             "--cache-control", "public,max-age=31536000,immutable", "--content-type", "application/zip"])
        run(["aws", "s3", "cp", BUILD / "release.json", f"s3://{bucket}/source/release.json",
             "--cache-control", "no-cache", "--content-type", "application/json"])
        session.client("cloudfront").create_invalidation(
            DistributionId=output["cloudfront_distribution_id"]["value"],
            InvalidationBatch={"Paths": {"Quantity": 1, "Items": ["/*"]}, "CallerReference": str(time.time_ns())})


if __name__ == "__main__":
    main()
