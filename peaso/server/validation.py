"""Hosted connectors cannot select service filesystem, helper commands or task identity."""
from datetime import datetime, timezone
import json
import os
from functools import lru_cache
import secrets
import re
from fastapi import HTTPException
from . import content_selection_preflight_20261021 as pure_selection

OPTIONS = {
    "content_secret_scans",
    "image_vulnerability_scans",
    "selected_gcs_objects",
    "selected_gcs_archives",
    "selected_dataform_files",
    "selected_cloudtasks_tasks", "selected_bigquery_routines",
    "selected_dataflow_referenced_sources", "selected_batch_referenced_sources",
    "selected_workbench_referenced_sources",
    "selected_dataproc_referenced_sources",
    "selected_azure_app_settings",
    "selected_azure_acr_images",
    "selected_azure_acr_image_vulnerabilities",
    "selected_azure_ml_command_jobs",
    "selected_azure_ml_environment_versions", "selected_azure_ml_code_files",
    "selected_azure_function_settings",
    "selected_azure_function_package_sources",
    "selected_azure_databricks_notebooks",
    "selected_azure_databricks_files",
    "selected_azure_databricks_task_outputs",
    "selected_azure_log_workspaces", "selected_azure_application_insights",
    "selected_azure_app_configuration_values", "selected_azure_data_factory_declarations", "selected_azure_synapse_pipelines",
    "selected_azure_configuration_content", "selected_azure_storage_sources", "selected_azure_devops_content",
    "selected_azure_flex_deployment_containers",
    "selected_aws_lambda_functions",
    "selected_aws_configuration_content",
    "selected_aws_s3_sources",
    "selected_k8s_literal_resources",
    "selected_k8s_log_samples",
    "selected_k8s_metadata_resources",
    "selected_k8s_text_resources",
    "selected_gke_clusters", "selected_gke_namespaces",
    "selected_artifact_images", "selected_artifact_files",
    "selected_cloudrun_services",
    "selected_cloudbuild_builds",
    "selected_source_repository_files",
    "selected_clouddeploy_releases",
    "selected_cloudbuild_artifact_builds",
    "selected_appengine_versions",
    "dataflow_regions", "batch_regions", "dataproc_regions",
    "node_clock_evidence",
    "native_disclosure_metadata", "inventories", "audit_window", "audit_detection_policy", "max_pages", "max_resources", "max_calls", "regions", "organization_role_name",
    "all_projects", "discover_projects", "project_restrictions", "allowed_projects", "quota_project",
    "sw51_policy", "sw55_policy", "sw52",
    "resource_iam", "include_inherited", "asset_types", "recommender_locations", "kms_locations", "cloudbuild_locations", "include_source_account",
    "trusted_scope_ids", "trusted_domains", "gcp_data_access_required_principals", "gcp_psc_dns_policy", "concurrency", "retries", "page_size", "activity_days", "log_entry_minutes", "scope_concurrency", "region_concurrency", "service_concurrency", "collect_all", "compliance_policy", "compliance_parameters",
}
OPTIONS.add('selected_aws_codebuild_inline_buildspecs')
OPTIONS.add('selected_aws_workload_commands')
OPTIONS.add('selected_cloudrun_job_declared_images')
OPTIONS.add('selected_gcp_registry_image_vulnerabilities')
OPTIONS.add('selected_aws_image_vulnerabilities')
OPTIONS.add('selected_aws_ecr_public_images')
OPTIONS.update({'selected_k8s_registry_images', 'selected_registry_hosts'})
OPTIONS.add('selected_k8s_flux_artifacts')
OPTIONS.add('selected_appengine_flex_version_images')
OPTIONS.add('selected_gke_pod_images')
OPTIONS.add('selected_aws_workload_image_secrets')
OPTIONS.add('selected_azure_aks_pod_images')
OPTIONS.add('selected_registry_hosts')
OPTIONS.update({'selected_azure_synapse_notebooks', 'selected_aws_ecs_environment_files'})
OPTIONS.update({'selected_cloudrun_worker_pool_revision_images', 'selected_developerconnect_files'})
OPTIONS.update({'selected_aws_workload_sources', 'selected_aws_build_deployment_sources'})
AUTH = {
    "aws": {"method", "aws_access_key_id", "aws_secret_access_key", "aws_session_token", "role_arn", "external_id", "role_chain", "assume_roles", "region_name", "role_session_name"},
    "gcp": {"gke_image_kubernetes", "registry_auth", "method", "token", "sa_json", "quota_project", "external_account_json", "subject_token", "project_proof_label"},
    "azure": {"devops_credentials", "aks_workloads", "registry_auth", "method", "token", "arm_token", "graph_token", "vault_token", "storage_token", "logs_token", "databricks_account_token", "tenant_id", "client_id", "client_secret", "certificate_data", "client_certificate", "certificate_password", "federated_token"},
    "k8s": {"method", "server", "token", "kubeconfig_data", "context", "cluster_id", "ca_cert_data", "client_cert_data", "client_key_data", "registry_auth"},
}
AWS_ROLE_ARN = re.compile(r"arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]{1,512}\Z")
COLLECTOR_ROLE_ARN = os.getenv("PEASO_AWS_COLLECTOR_ROLE_ARN", "")
PLATFORM_ACCOUNT_IDS = frozenset(filter(None, os.getenv("PEASO_PLATFORM_ACCOUNT_IDS", "").split(","))) | frozenset(
    [COLLECTOR_ROLE_ARN.split(":")[4]] if re.fullmatch(r"arn:aws:iam::[0-9]{12}:role/.+", COLLECTOR_ROLE_ARN) else []
)
CUSTOMER_ROLE_TEMPLATE_URL = "https://cspm.hacktricks.wiki/aws/customer-role.json"
EXTERNAL_ID_PREFIX = "hacktricks-cspm-"
LEGACY_EXTERNAL_ID_PREFIX = "peaso-"


def validate_connector(provider, auth, options, settings, *, server_external_id=False, scopes=None):
    if 'selected_gke_pod_images' in options or provider == 'gcp' and any(k in auth for k in ('gke_image_kubernetes', 'registry_auth')):
        try:
            if provider != 'gcp':
                raise ValueError('GKE image selection requires GCP')
            from peaso.gcp_gke_image_selection_20261021 import selected, kubernetes_auth, registry_auth
            targets = selected(options, scopes or [], [])
            kubernetes_auth(auth, targets)
            registry_auth(auth, targets, options.get('selected_registry_hosts', []))
        except (ValueError, TypeError, KeyError, AttributeError):
            raise HTTPException(422, 'Selected GKE images require exact project, cluster, Pod, digest, registry and separately authorized Kubernetes access') from None
    if 'selected_aws_workload_image_secrets' in options:
        try:
            if provider != 'aws' or ('content_secret_scans' in options and type(options['content_secret_scans']) is not bool):
                raise ValueError('AWS workload image selection requires AWS')
            selector=pure_selection.aws_workload_image
            selector.selected({**options, selector.ENABLE: True}, scopes or [], [selector.CHECK])
        except (ValueError, TypeError, KeyError, AttributeError):
            raise HTTPException(422, 'Selected workload image secrets require exact Lambda, ECS or Batch declarations and immutable ECR digests in the selected account and Region') from None
    if 'selected_aws_ecr_public_images' in options:
        try:
            if provider != 'aws':
                raise ValueError('AWS-only ECR Public selection')
            from peaso.aws_ecr_public_selection_20261021 import selected_targets as selected_public_images
            selected_public_images(options, scopes or [])
        except (ValueError, TypeError, KeyError, AttributeError):
            raise HTTPException(422, 'Selected ECR Public images require exact account/us-east-1 scopes, active alias names, repository names and immutable SHA-256 digests') from None
    if 'selected_azure_aks_pod_images' in options or provider == 'azure' and 'registry_auth' in auth:
        try:
            if provider != 'azure':
                raise ValueError('Azure-only AKS image selection')
            selected = pure_selection.aks_image.selected_targets(options, scopes or [], [])
            pure_selection.registry.registry_credentials(auth, selected, options.get('selected_registry_hosts', []))
        except (ValueError, TypeError, KeyError, AttributeError):
            raise HTTPException(422, 'Selected AKS images require exact ARM cluster, Pod UID, immutable digest, and separately authorized registry') from None
    if 'selected_k8s_flux_artifacts' in options:
        try:
            if provider != 'k8s':
                raise ValueError('Kubernetes-only Flux source selection')
            pure_selection.flux.selected_targets(options, scopes or [], [])
        except (ValueError, TypeError, KeyError, AttributeError):
            raise HTTPException(422, 'Selected Flux artifacts require exact scoped source, digest and source-controller Service selectors') from None
    if 'selected_k8s_registry_images' in options or provider == 'k8s' and ('selected_registry_hosts' in options or 'registry_auth' in auth):
        try:
            if provider != 'k8s':
                raise ValueError('Kubernetes-only registry selection')
            selected = pure_selection.registry.selected_targets(options, scopes or [], [])
            pure_selection.registry.registry_credentials(auth, selected, options.get(pure_selection.registry.ALLOWLIST, []))
        except (ValueError, TypeError, KeyError, AttributeError):
            raise HTTPException(422, 'Selected Kubernetes registry images require exact scoped Pod digests, public registry hosts, and separately bound registry authentication') from None
    if ('image_vulnerability_scans' in options or 'selected_aws_image_vulnerabilities' in options
            or 'selected_gcp_registry_image_vulnerabilities' in options
            or 'selected_azure_acr_image_vulnerabilities' in options):
        try:
            from .image_selection_options_20261021 import validate_image_options
            validate_image_options(provider, options, scopes or [])
        except (ValueError, TypeError, KeyError, AttributeError):
            raise HTTPException(422, 'Image vulnerability scans require a boolean and exact AWS image targets, GCP Job image selectors, or Azure ACR digests in selected scopes') from None
    if 'selected_cloudrun_job_declared_images' in options:
        try:
            if provider != 'gcp':
                raise ValueError('Selected Job declared images require GCP')
            from .cloudrun_job_selection_static_20261021 import validate_options as validate_cloudrun_job_images
            validate_cloudrun_job_images(options, scopes or [])
        except (ValueError, TypeError, KeyError, AttributeError):
            raise HTTPException(422, 'Selected Cloud Run Job declared images require exact supported selectors in one explicit project') from None
    for option, validator, description in (
        ('selected_cloudrun_worker_pool_revision_images', pure_selection.workerpool.selections,
         'Selected worker pool images require one explicit GCP project, exact revision/container, and immutable image digest'),
        ('selected_developerconnect_files', pure_selection.developerconnect.selections,
         'Selected Developer Connect files require one explicit GCP project and exact link, origin, commit, path and blob')):
        if option not in options:
            continue
        try:
            if (provider != 'gcp' or not isinstance(scopes, list) or len(scopes) != 1
                    or any(options.get(key) for key in ('all_projects', 'discover_projects', 'all_hierarchy'))):
                raise ValueError('one selected GCP project required')
            validator(options[option], scopes[0])
        except (ValueError, TypeError, KeyError, AttributeError):
            raise HTTPException(422, description) from None
    if 'selected_aws_workload_commands' in options:
        try:
            pure_selection.workload.targets(options, scopes or [], [], provider)
        except (ValueError, TypeError, KeyError, AttributeError):
            raise HTTPException(422, 'Selected AWS commands require exact ECS/classic Batch definition ARN revisions in selected account/Region scopes; images, environment files and EKS Batch are unsupported') from None
    if 'selected_aws_codebuild_inline_buildspecs' in options:
        try:
            from peaso.collectors.aws_codebuild_buildspec_runtime_20261020 import targets as codebuild_inline_targets
            codebuild_inline_targets(options, scopes or [], [], provider)
        except Exception:
            raise HTTPException(422, 'Selected CodeBuild buildspecs require exact project ARNs in selected AWS account/region scopes') from None
    if 'selected_azure_function_package_sources' in options:
        try:
            from peaso.collectors.azure_function_package_integration_20261020 import preflight as package_preflight
            package_preflight(options, scopes or [], [], provider=provider)
        except (ValueError, TypeError, KeyError, AttributeError):
            raise HTTPException(422, 'Selected Azure packages require 1–2 exact owned site and Blob ZIP selections') from None
    if 'selected_azure_flex_deployment_containers' in options:
        try:
            if provider!='azure':raise ValueError('Azure-only Flex selection')
            pure_selection.azure_flex_archives.selected_targets(options,scopes or [])
        except (ValueError,TypeError,KeyError,AttributeError):
            raise HTTPException(422,'Selected Flex deployment containers require exact same-subscription Function and storage-account ARM IDs plus a container name') from None
    if 'selected_azure_function_settings' in options:
        try:
            if provider != 'azure':
                raise ValueError('Azure-only selected Function settings')
            from peaso.collectors.azure_function_settings_declarations_20261020 import preflight
            preflight(options, scopes or [], [])
        except Exception:
            raise HTTPException(422, 'Selected Function settings require 1–4 exact native site ARM IDs in selected subscription scopes; slots and URLs are unsupported') from None
    if any(option in options for option in ('selected_azure_ml_environment_versions', 'selected_azure_ml_code_files')):
        try:
            if provider != 'azure':
                raise ValueError('Azure-only ML asset selection')
            pure_selection.ml_asset.selected_targets(options, scopes or [])
        except Exception:
            raise HTTPException(422, 'Selected Azure ML assets require 1–4 exact scoped environment-version IDs, environment-version/datastore/selected Blob Dockerfiles, or code-version/datastore/selected storage-file targets') from None
    if any(key in options for key in ('selected_azure_databricks_notebooks','selected_azure_databricks_files','selected_azure_databricks_task_outputs')):
        try:
            if provider != 'azure':
                raise ValueError('Azure-only Databricks content selection')
            pure_selection.databricks.selected_targets(options, scopes or [])
        except Exception:
            raise HTTPException(422, 'Selected Azure Databricks content requires 1–4 exact scoped notebook, workspace FILE, or job/task-run output targets') from None
    if 'selected_azure_synapse_notebooks' in options:
        try:
            if provider != 'azure':
                raise ValueError('Azure-only Synapse notebook selection')
            pure_selection.synapse.selected_targets(options, scopes or [])
        except (ValueError, TypeError, KeyError, AttributeError):
            raise HTTPException(422, 'Selected Synapse notebooks require 1–4 exact workspace IDs and notebook names in selected subscription scopes') from None
    if 'selected_azure_ml_command_jobs' in options:
        try:
            if provider != 'azure':
                raise ValueError('Azure-only ML job selection')
            pure_selection.ml_job.selected_targets(options, scopes or [])
        except Exception:
            raise HTTPException(422, 'Selected Azure ML jobs require 1–4 exact case-sensitive native job ARM IDs in selected subscriptions') from None
    log_sample_options = ('selected_azure_log_workspaces', 'selected_azure_application_insights')
    if any(option in options for option in log_sample_options):
        try:
            if provider != 'azure':
                raise ValueError('Azure-only log sample selection')
            from peaso.collectors.azure_selected_log_sample_secret_indicators import selected_targets
            selected_targets(options, scopes or [])
        except Exception:
            raise HTTPException(422, 'Selected Azure log samples require 1–4 total exact scoped workspace/table or Application Insights component targets') from None
    declaration_options = ('selected_azure_app_configuration_values', 'selected_azure_data_factory_declarations', 'selected_azure_synapse_pipelines')
    if any(option in options for option in declaration_options):
        try:
            if provider != 'azure':
                raise ValueError('Azure-only declaration selection')
            pure_selection.declaration.selected_targets(options, scopes or [])
        except Exception:
            raise HTTPException(422, 'Selected Azure declarations require 1–8 total exact scoped App Configuration key/label, Data Factory pipeline/dataflow or Synapse pipeline targets') from None
    for option, module, needs_auth, detail in (
        ('selected_azure_configuration_content', 'azure_selected_configuration_secret_indicators', False, 'Selected Azure configuration requires 1–8 exact supported surface/resource_id targets in selected subscriptions'),
        ('selected_azure_storage_sources', 'azure_selected_storage_secret_indicators', False, 'Selected Azure storage requires 1–4 exact native Blob/File account, container/share, path and format targets; version is optional'),
        ('selected_azure_devops_content', 'azure_devops_selected_content_secret_indicators', True, 'Selected DevOps content requires 1–8 exact scoped immutable Git files or pipeline definition revisions with configured organization/project bindings')):
        if option not in options:
            continue
        try:
            if provider != 'azure':
                raise ValueError('Azure-only content selection')
            if option == 'selected_azure_storage_sources':
                validator = pure_selection.storage.selected_targets
            else:
                from importlib import import_module
                validator = import_module('peaso.collectors.' + module).selected_targets
            args = (options, scopes or [], auth) if needs_auth else (options, scopes or [])
            validator(*args)
        except Exception:
            raise HTTPException(422, detail) from None

    if 'selected_aws_s3_sources' in options:
        try:
            if provider != 'aws':
                raise ValueError('AWS-only S3 source selection')
            pure_selection.s3.selected_targets(options, scopes or [])
        except Exception:
            raise HTTPException(422, 'Selected S3 sources require 1–4 exact bucket, key, format and optional existing version targets in matching account/Region scopes') from None
    if 'selected_aws_configuration_content' in options:
        try:
            if provider != 'aws':
                raise ValueError('AWS-only content selection')
            pure_selection.aws_config.selected_targets(options, scopes or [])
        except Exception:
            raise HTTPException(422, 'Selected AWS configuration requires 1–16 exact surface, scope and resource_id targets in matching account/Region scopes; SSM documents and launch templates require numeric versions') from None
    if 'selected_aws_ecs_environment_files' in options:
        try:
            if provider != 'aws':
                raise ValueError('AWS-only ECS environment file selection')
            pure_selection.ecs_env.selected_targets(options, scopes or [])
        except (ValueError, TypeError, KeyError, AttributeError):
            raise HTTPException(422, 'Selected ECS environment files require exact task revision, container, S3 ARN, and matching selected S3 source') from None
    if 'selected_aws_workload_sources' in options:
        try:
            if provider != 'aws':
                raise ValueError('AWS-only workload source selection')
            pure_selection.workload_ref.selected_targets(options, scopes or [])
        except (ValueError, TypeError, KeyError, AttributeError):
            raise HTTPException(422, 'Selected AWS workload sources require exact Glue, EMR, or SageMaker references and matching selected S3 sources') from None
    if 'selected_aws_build_deployment_sources' in options:
        try:
            if provider != 'aws':
                raise ValueError('AWS-only build or deployment source selection')
            pure_selection.build_ref.selected_targets(options, scopes or [])
        except (ValueError, TypeError, KeyError, AttributeError):
            raise HTTPException(422, 'Selected AWS build and deployment sources require exact CodeBuild, Elastic Beanstalk, or Amplify references and matching selected S3 sources') from None
    if 'selected_aws_lambda_functions' in options:
        try:
            if provider != 'aws':
                raise ValueError('AWS-only content selection')
            pure_selection.lambda_environment.selected_targets(options, scopes or [])
        except Exception:
            raise HTTPException(422, 'Selected Lambda environments require 1–8 unique unqualified function ARNs in explicit matching account/Region scopes') from None
    if 'selected_azure_acr_images' in options:
        try:
            if provider != 'azure':
                raise ValueError('Azure-only content selection')
            from peaso.collectors.azure_acr_image_secret_indicators import selected_targets
            selected_targets(options, scopes or [])
        except Exception:
            raise HTTPException(422, 'Selected ACR images require 1–4 exact registry ARM IDs, repositories and immutable SHA256 digests in selected subscriptions') from None
    if 'selected_k8s_literal_resources' in options:
        try:
            if provider != 'k8s':
                raise ValueError('Kubernetes-only content selection')
            from peaso.collectors.k8s_literal_secret_indicators import selected_targets
            selected_targets(options, scopes or [])
        except Exception:
            raise HTTPException(422, 'Selected literals require 1–8 exact supported workload or ConfigMap targets with exact namespaces of one cluster, including an overall all-namespace scan') from None
    if 'selected_k8s_metadata_resources' in options:
        try:
            if provider != 'k8s':
                raise ValueError('Kubernetes-only metadata selection')
            from peaso.collectors.k8s_selected_metadata_runtime_20261020 import preflight
            preflight(options, scopes or [], [])
        except Exception:
            raise HTTPException(422, 'Selected metadata requires 1–8 exact supported namespaced object targets of one configured Kubernetes cluster') from None
    if 'selected_k8s_text_resources' in options:
        try:
            if provider != 'k8s':
                raise ValueError('Kubernetes-only text selection')
            from peaso.collectors.k8s_selected_text_content import selected_targets
            selected_targets(options, scopes or [])
        except Exception:
            raise HTTPException(422, 'Selected text requires 1–8 exact Event, Ingress, Gateway or CRD objects of one cluster') from None
    if 'selected_k8s_log_samples' in options:
        try:
            if provider != 'k8s':
                raise ValueError('Kubernetes-only log selection')
            from peaso.collectors.k8s_selected_log_sample_secret_indicators import selected_targets
            selected_targets(options, scopes or [])
        except Exception:
            raise HTTPException(422, 'Selected log samples require 1–4 unique exact cluster_id/namespace/pod/container targets in explicit namespace scopes of one cluster') from None
    if 'selected_azure_app_settings' in options:
        try:
            if provider != 'azure':
                raise ValueError('Azure-only content selection')
            from peaso.collectors.azure_app_settings_secret_indicators import selected_targets
            selected_targets(options, scopes or [])
        except Exception:
            raise HTTPException(422, 'Selected app settings require 1–8 unique exact site or slot ARM IDs in explicitly selected subscriptions') from None
    if 'selected_dataflow_referenced_sources' in options or 'selected_batch_referenced_sources' in options:
        try:
            from peaso.collectors.gcp_dataflow_batch_source_runtime_20261020 import preflight as selected_job_preflight
            selected_job_preflight(options, scopes or [], [], provider)
        except Exception:
            raise HTTPException(422, 'Selected Dataflow/Batch sources require 1-4 exact owned native resource/reference/bucket/object/generation targets') from None
    if 'selected_workbench_referenced_sources' in options:
        try:
            if provider != 'gcp':
                raise ValueError('GCP-only selected Workbench sources')
            from peaso.collectors.gcp_workbench_source_runtime_20261020 import preflight
            preflight(options, scopes or [], [])
        except Exception:
            raise HTTPException(422, 'Selected Workbench sources require 1-4 exact owned instance/metadata-field/bucket/object/generation targets') from None
    if 'selected_dataproc_referenced_sources' in options:
        try:
            if provider != 'gcp':
                raise ValueError('GCP-only source selection')
            from peaso.dataproc_source_selection import selected_targets
            selected_targets(options, scopes or [])
        except Exception:
            raise HTTPException(422, 'Selected Dataproc sources require 1–4 exact native job/cluster references and same-project GCS source generations') from None
    for option, kind in (('selected_cloudtasks_tasks', 'cloudtasks_selected_task'),
                         ('selected_bigquery_routines', 'bigquery_selected_routine')):
        if option not in options:
            continue
        try:
            if provider != 'gcp':
                raise ValueError('GCP-only content selection')
            from peaso.collectors.gcp_selected_task_routine_secret_indicators import selected_targets
            selected_targets({**options, 'content_secret_scans': True,
                              '_content_secret_scan_kinds': [kind]}, scopes or [], kind)
        except Exception:
            raise HTTPException(422, option + ' requires 1–8 unique exact native names in one explicit GCP project') from None
    if 'selected_cloudbuild_builds' in options:
        try:
            if provider != 'gcp':
                raise ValueError('GCP-only selection')
            from peaso.collectors.gcp_cloudbuild_log_secret_indicators import selected_builds, KIND
            selected_builds({**options, 'content_secret_scans': True,
                '_content_secret_scan_kinds': [KIND]}, scopes or [])
        except Exception:
            raise HTTPException(422, 'Cloud Build log inspection requires 1–4 exact same-project Build names and one explicit project') from None
    if 'selected_source_repository_files' in options:
        try:
            if provider != 'gcp':
                raise ValueError('GCP-only selection')
            from peaso.collectors.gcp_sourcerepo_secret_indicators import selected_targets, KIND
            selected_targets({**options, 'content_secret_scans': True,
                '_content_secret_scan_kinds': [KIND]}, scopes or [])
        except Exception:
            raise HTTPException(422, 'Source Repository inspection requires one exact project, repository, 40-character commit and 1–8 file paths') from None
    if 'selected_clouddeploy_releases' in options:
        try:
            if provider != 'gcp':
                raise ValueError('GCP-only selection')
            from peaso.collectors.gcp_clouddeploy_source_secret_indicators import selected_releases, KIND
            selected_releases({**options, 'content_secret_scans': True,
                '_content_secret_scan_kinds': [KIND]}, scopes or [])
        except Exception:
            raise HTTPException(422, 'Cloud Deploy source inspection requires 1–4 exact same-project Release names and one explicit project') from None
    if 'selected_cloudbuild_artifact_builds' in options:
        try:
            if provider != 'gcp':
                raise ValueError('GCP-only selection')
            from peaso.collectors.gcp_cloudbuild_artifact_secret_indicators import selected_builds, KIND
            selected_builds({**options, 'content_secret_scans': True,
                '_content_secret_scan_kinds': [KIND]}, scopes or [])
        except Exception:
            raise HTTPException(422, 'Cloud Build artifact inspection requires 1–2 exact same-project Build names and one explicit project') from None
    if 'selected_appengine_flex_version_images' in options:
        try:
            if provider != 'gcp':
                raise ValueError('GCP-only selection')
            from peaso.gcp_appengine_flex_image_selection_20261021 import selected
            selected(options, scopes or [], [])
        except (ValueError, TypeError, KeyError, AttributeError):
            raise HTTPException(422, 'Selected Flex version images require one project, exact Version names, and same-project immutable digests') from None
    if 'selected_appengine_versions' in options:
        try:
            if provider != 'gcp':
                raise ValueError('GCP-only selection')
            from peaso.collectors.gcp_appengine_source_secret_indicators import selected_versions, KIND
            selected_versions({**options, 'content_secret_scans': True,
                '_content_secret_scan_kinds': [KIND]}, scopes or [])
        except Exception:
            raise HTTPException(422, 'App Engine source inspection requires 1–4 exact same-project Version names and one explicit project') from None
    if 'selected_cloudrun_services' in options:
        try:
            if provider != 'gcp':
                raise ValueError('GCP-only selection')
            from peaso.collectors.gcp_cloudrun_image_inspection import validate_selection
            validate_selection(options['selected_cloudrun_services'], scopes or [])
        except Exception:
            raise HTTPException(422, 'Cloud Run image selection requires 1–4 exact same-project service names and one explicit project') from None
    if 'selected_artifact_files' in options:
        try:
            if provider != 'gcp':
                raise ValueError('GCP-only selection')
            from peaso.collectors.gcp_artifact_file_secret_indicators import normalize_selection, KIND
            normalize_selection({**options, 'content_secret_scans': True, '_content_secret_scan_kinds': [KIND]}, scopes or [])
        except Exception:
            raise HTTPException(422, 'Artifact file selections require exact scoped file names, SHA256 and supported formats') from None
    if 'selected_gke_clusters' in options or 'selected_gke_namespaces' in options:
        try:
            if provider != 'gcp':
                raise ValueError('GCP-only selection')
            from types import SimpleNamespace
            from peaso.collectors.gcp_gke_literal_secret_indicators import selected, KIND
            candidate = SimpleNamespace(options={**options, 'content_secret_scans': True,
                '_content_secret_scan_kinds': [KIND]}, requested_scopes=scopes or [])
            selected(candidate, (scopes or [''])[0])
        except Exception:
            raise HTTPException(422, 'GKE scans require exact selected cluster scopes and an optional complete cluster-to-namespace mapping') from None
    if 'selected_dataform_files' in options:
        try:
            if provider != 'gcp':
                raise ValueError('GCP-only content selection')
            from peaso.collectors.gcp_dataform_secret_indicators import selected_targets as dataform_targets, KIND
            dataform_targets({**options, 'content_secret_scans': True, '_content_secret_scan_kinds': [KIND]}, scopes or [])
        except Exception:
            raise HTTPException(422, 'Selected Dataform files require exact scoped repository/file and commit SHA or explicit workspace targets') from None
    if 'selected_gcs_archives' in options:
        try:
            if provider != 'gcp':
                raise ValueError('GCP-only content selection')
            from peaso.collectors.gcp_selected_archive_secret_indicators import normalize_selection, KIND
            normalize_selection({**options, 'content_secret_scans': True, '_content_secret_scan_kinds': [KIND]}, scopes or [])
            if len(options.get('selected_gcs_objects', [])) + len(options['selected_gcs_archives']) > 10:
                raise ValueError('combined target limit')
        except Exception:
            raise HTTPException(422, 'Selected GCS archives require scoped immutable targets, supported formats and at most 10 combined object/archive targets') from None
    if 'selected_artifact_images' in options:
        try:
            if provider != 'gcp':
                raise ValueError('GCP project scopes are required')
            from peaso.gcp_image_selection_20261021 import OPTION, grouped_selections
            grouped_selections({**options, OPTION: options['selected_artifact_images']}, scopes or [])
        except Exception:
            raise HTTPException(422, 'Selected images require explicit project scopes and 1–4 immutable Artifact Registry image references belonging to those projects') from None
    if 'selected_gcs_objects' in options:
        try:
            if provider != 'gcp':
                raise ValueError('GCP-only content selection')
            from peaso.collectors.gcp_selected_object_secret_indicators import selected_targets, KIND
            selected_targets({**options, 'content_secret_scans': True, '_content_secret_scan_kinds': [KIND]}, scopes or [])
        except Exception:
            raise HTTPException(422, 'Selected GCS objects require exact project, bucket, object and generation targets in the requested project scopes') from None
    for key in ('dataflow_regions', 'batch_regions', 'dataproc_regions'):
        if key in options:
            value = options[key]
            if (provider != 'gcp' or not isinstance(value, list) or not 1 <= len(value) <= 5
                    or any(not isinstance(region, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', region)
                           or region == 'global' for region in value) or len(set(value)) != len(value)):
                raise HTTPException(422, 'GCP job scan regions must contain 1–5 distinct explicit non-global regions')
    if 'content_secret_scans' in options and (provider not in {'aws', 'gcp', 'azure', 'k8s'} or type(options['content_secret_scans']) is not bool):
        raise HTTPException(422, 'content_secret_scans must be a supported provider boolean option')
    if 'node_clock_evidence' in options:
        try:
            if provider != 'k8s':raise ValueError('Node clock observations are Kubernetes-only')
            from peaso.collectors.k8s_node_clock_evidence import normalize
            normalize(options)
        except (ValueError, TypeError):
            raise HTTPException(422, 'Invalid Kubernetes node clock observations') from None
    if isinstance(options.get('compliance_policy'), dict) and 'eks_image_integrity' in options['compliance_policy']:
        try:
            if provider != 'aws':raise ValueError('EKS image integrity criteria are AWS-only')
            from peaso.collectors.aws_eks_admission_native import normalize
            normalize(options)
        except (ValueError, TypeError):
            raise HTTPException(422, 'Invalid AWS EKS image integrity criteria') from None
    if 'devops_credentials' in auth or isinstance(options.get('compliance_parameters'),dict) and 'azure_devops_git' in options['compliance_parameters']:
        try:
            if provider != 'azure':raise ValueError('DevOps Git bridge is Azure-only')
            from peaso.azure_devops_git_policy import normalize as normalize_devops_git
            normalize_devops_git(options, auth)
        except (ValueError, TypeError):
            raise HTTPException(422, 'Invalid Azure DevOps explicit credentials or owner applicability') from None
    if isinstance(options.get('compliance_parameters'), dict) and 'azure_devops_pipelines' in options['compliance_parameters']:
        try:
            if provider != 'azure':raise ValueError('DevOps pipeline metadata is Azure-only')
            from peaso.collectors.azure_devops_pipeline_native import normalize as normalize_devops_pipelines
            normalize_devops_pipelines(options, auth)
        except (ValueError, TypeError, OverflowError, RecursionError):
            raise HTTPException(422, 'Invalid Azure DevOps pipeline applicability or normative variable policy') from None
    if 'aks_workloads' in auth or isinstance(options.get('compliance_parameters'),dict) and 'azure_aks_workloads' in options['compliance_parameters']:
        try:
            if provider != 'azure':raise ValueError('AKS bridge is Azure-only')
            if isinstance(options.get('compliance_parameters'), dict) and 'azure_aks_workloads' in options['compliance_parameters']:
                from peaso.collectors.azure_aks_workloads_native import normalize
                normalize(options, auth)
            else:
                pure_selection.aks_image.normalize_contexts(auth)
        except (ValueError, TypeError):
            raise HTTPException(422, 'Invalid Azure AKS explicit workload context or owner policy') from None
    if "databricks_account_token" in auth:
        try:
            if provider != "azure":
                raise ValueError("Databricks account credentials are Azure-only")
            from peaso.collectors.azure_databricks_native import validate_auth
            validate_auth(auth)
        except ValueError:
            raise HTTPException(422, "Invalid Databricks account credential") from None
    if "native_disclosure_metadata" in options:
        if provider != "azure" or type(options["native_disclosure_metadata"]) is not bool:
            raise HTTPException(422, "Invalid Azure native disclosure metadata selection")
    if 'log_entry_minutes' in options:
        minutes = options['log_entry_minutes']
        if provider != 'gcp' or type(minutes) is not int or not 1 <= minutes <= 1440:
            raise HTTPException(422, 'Invalid GCP log metadata window')
    from peaso.gcp_psc_policy import OPTION as PSC_OPTION, normalize as normalize_psc_policy
    if PSC_OPTION in options:
        try:
            if provider != "gcp":
                raise ValueError("PSC policy is GCP-only")
            normalize_psc_policy(options[PSC_OPTION])
        except ValueError:
            raise HTTPException(422, "Invalid GCP PSC owner scope") from None
    if "cloudbuild_locations" in options:
        locations = options["cloudbuild_locations"]
        if (provider != "gcp" or not isinstance(locations, list) or len(locations) > 100 or
                any(not isinstance(x, str) or not re.fullmatch(r"[a-z0-9-]+", x) for x in locations) or
                len(locations) != len(set(locations))):
            raise HTTPException(422, "Invalid Cloud Build location selection")
    from peaso.gcp_data_access_policy import OPTION, normalize_owner_policy
    if OPTION in options:
        if provider != "gcp":
            raise HTTPException(422, "GCP Data Access owner policy is GCP-only")
        try:
            normalize_owner_policy(options[OPTION])
        except ValueError:
            raise HTTPException(422, "Invalid GCP Data Access owner policy") from None
    # Audit declarations are validated before the local-auth return as owner policies are.
    from .gcp_audit_options_static_20261021 import validate_audit_options
    try:
        validate_audit_options(provider, options)
    except ValueError:
        raise HTTPException(422, "Invalid GCP audit selection or policy") from None
    if 'compliance_parameters' in options:
        value = options['compliance_parameters']
        try:
            valid = isinstance(value, dict) and len(json.dumps(value, allow_nan=False)) <= 50000
        except (TypeError, ValueError):
            valid = False
        if not valid:
            raise HTTPException(422, 'Invalid compliance parameters')
        if 'aws_environment_separation' in value:
            from peaso.collectors.aws_environment_boundaries_native import normalize
            try:
                if provider != 'aws':raise ValueError('Environment separation criteria are AWS-only')
                normalize(options)
            except (ValueError,TypeError):
                raise HTTPException(422, 'Invalid AWS environment separation criteria') from None
        if 'azure_subnet_firewall' in value:
            try:
                if provider != 'azure': raise ValueError('Subnet applicability is Azure-only')
                from peaso.collectors.azure_subnet_firewall_policy import normalize
                normalize(options)
            except (ValueError, TypeError, OverflowError, RecursionError):
                raise HTTPException(422, 'Invalid Azure subnet firewall applicability') from None
        if 'azure_audit_storage' in value:
            try:
                if provider != 'azure': raise ValueError('Audit account classification is Azure-only')
                from peaso.collectors.azure_audit_storage_native import normalize
                normalize(options)
            except (ValueError, TypeError, OverflowError, RecursionError):
                raise HTTPException(422, 'Invalid Azure audit account classification') from None
        if 'azure_nsg_ingress' in value:
            try:
                if provider != 'azure':
                    raise ValueError('NSG criteria are Azure-only')
                from peaso.collectors.azure_nsg_ingress_native import normalize
                normalize(options)
            except (ValueError, TypeError, OverflowError, RecursionError):
                raise HTTPException(422, 'Invalid Azure NSG owner criteria') from None
        if 'aws_lightsail_bucket_iam' in value:
            try:
                if provider != 'aws':
                    raise ValueError('Lightsail criteria are AWS-only')
                from peaso.aws_lightsail_owner_policy import normalize
                normalize(options)
            except (ValueError, TypeError, OverflowError, RecursionError):
                raise HTTPException(422, 'Invalid Lightsail IAM owner criteria') from None
        if 'azure_tls_certificates' in value:
            try:
                if provider != 'azure':
                    raise ValueError('TLS certificate criteria are Azure-only')
                from peaso.azure_tls_owner_policy import normalize
                normalize(options)
            except (ValueError, TypeError, OverflowError, RecursionError):
                raise HTTPException(422, 'Invalid Azure TLS certificate owner criteria') from None
        if 'aws_controltower' in value:
            from peaso.collectors.aws_controltower_native import normalize
            try:
                if provider != 'aws':raise ValueError('Control Tower policy is AWS-only')
                normalize(options)
            except (ValueError, TypeError):
                raise HTTPException(422, 'Invalid Control Tower owner AI scope') from None
        if 'approved_inventory_reader_arns' in value:
            from peaso.collectors.aws_ssm_inventory_events_native import approved_readers
            try:
                if provider != 'aws':raise ValueError('Inventory readers are AWS-only')
                approved_readers(options)
            except (ValueError,TypeError):
                raise HTTPException(422, 'Invalid AWS inventory reader owner policy') from None
        if 'aws_resolver_firewall' in value:
            from peaso.collectors.aws_resolver_firewall_native import normalize
            try:
                if provider != 'aws':raise ValueError('Resolver policy is AWS-only')
                normalize(options)
            except (ValueError,TypeError):
                raise HTTPException(422, 'Invalid AWS Resolver owner policy') from None
        if 'aws_ecr_artifacts' in value:
            from peaso.collectors.aws_ecr_artifacts_native import normalize
            try:
                if provider != 'aws':raise ValueError('ECR policy is AWS-only')
                normalize(options)
            except (ValueError,TypeError):
                raise HTTPException(422, 'Invalid AWS ECR content-reading policy') from None
        if 'aws_budget_stop' in value:
            from peaso.aws_budget_policy import normalize
            try:
                if provider != 'aws':raise ValueError('Budget stop policy is AWS-only')
                normalize(options)
            except (ValueError,TypeError):
                raise HTTPException(422, 'Invalid AWS budget stop owner policy') from None
        if 'cost_anomaly_alerts' in value:
            from peaso.collectors.aws_cost_policy import normalize
            try:
                if provider != 'aws':raise ValueError('cost alert policy is AWS-only')
                normalize(options)
            except ValueError:
                raise HTTPException(422, 'Invalid cost anomaly owner policy') from None
        if 'operational_groups' in value:
            from peaso.collectors.aws_operational_groups_native import normalize
            try:
                if provider != 'aws':raise ValueError('operational grouping is AWS-only')
                normalize(options)
            except (ValueError, TypeError):
                raise HTTPException(422, 'Invalid AWS operational group owner policy') from None
        if 'azure_resource_logging' in value:
            from peaso.collectors.azure_resource_logging_policy import normalize
            try:
                if provider != 'azure':raise ValueError('Resource logging requirements are Azure-only')
                normalize(options)
            except (ValueError,TypeError):
                raise HTTPException(422, 'Invalid Azure resource logging owner requirements') from None
        if 'azure_iot_policy' in value:
            from peaso.collectors.azure_iot_policy_native import normalize
            try:
                if provider != 'azure':raise ValueError('DPS policy is Azure-only')
                normalize(options)
            except (ValueError,TypeError):
                raise HTTPException(422, 'Invalid Azure DPS owner policy') from None
        if 'azure_storage_recovery' in value:
            from peaso.collectors.azure_storage_recovery_metadata_native import normalize
            try:
                if provider != 'azure':raise ValueError('Storage retention review is Azure-only')
                normalize(options)
            except (ValueError,TypeError):
                raise HTTPException(422, 'Invalid Azure storage/recovery owner policy') from None
        if 'azure_storage_lifecycle' in value:
            from peaso.collectors.azure_storage_lifecycle_native import normalize
            try:
                if provider != 'azure':raise ValueError('Storage lifecycle review is Azure-only')
                normalize(options)
            except (ValueError,TypeError):
                raise HTTPException(422, 'Invalid Azure storage lifecycle owner policy') from None
        if 'azure_guest_configuration' in value:
            from peaso.collectors.azure_guest_policy import normalize
            try:
                if provider != 'azure':raise ValueError('guest baseline policy is Azure-only')
                normalize(options)
            except (ValueError,TypeError):
                raise HTTPException(422, 'Invalid Azure guest baseline owner policy') from None
    if "sw52" in options:
        try:
            from peaso.gcp_sbom_policy import normalize
            if provider != "gcp":
                raise ValueError("SBOM workload scope is GCP-only")
            # Actual selected scopes are unavailable here; collection binds them.
            normalize(options["sw52"])
        except (ValueError, TypeError, OverflowError, RecursionError):
            raise HTTPException(422, "Invalid GCP SBOM workload scope") from None
    if isinstance(options.get("compliance_policy"), dict) and "security_reviewer_arns" in options["compliance_policy"]:
        try:
            from peaso.collectors.aws_codecommit_review_native import review_policy
            if provider != "aws":
                raise ValueError("CodeCommit reviewers are AWS-only")
            review_policy(options)
        except (ValueError, TypeError):
            raise HTTPException(422, "Invalid CodeCommit reviewer policy") from None
    # These namespaces select normative rules, never captured observations.
    # Validate them in local mode too, before accepting provider-specific input.
    parent_policy = options.get("compliance_policy")
    sw13 = parent_policy.get('sw13') if isinstance(parent_policy, dict) else None
    consideration_keys = {'azure|cis|exclusionary_device_code_flow_policy_considered',
                          'azure|cis|exclusionary_geographic_access_policy_considered'}
    selected_considerations = ({cid: config for cid, config in sw13['checks'].items()
        if cid in consideration_keys and isinstance(config, dict) and 'consideration' in config}
        if isinstance(sw13, dict) and isinstance(sw13.get('checks'), dict) else {})
    if selected_considerations:
        try:
            if provider != 'azure': raise ValueError('Consideration requirements are Azure-only')
            from .native_policy_validation import azure_mfa_review
            # Preserve existing local legacy criteria in other checks. Only
            # this explicit native consideration input adds new validation.
            azure_mfa_review({**sw13, 'checks': selected_considerations})
        except (ValueError, TypeError, OverflowError, RecursionError):
            raise HTTPException(422, 'Invalid Azure Conditional Access consideration requirements') from None
    correlation_key = 'azure|other|security_event_correlation'
    if isinstance(sw13, dict) and isinstance(sw13.get('checks'), dict) and correlation_key in sw13['checks']:
        try:
            if provider != 'azure': raise ValueError('Correlation requirements are Azure-only')
            from peaso.collectors.azure_security_correlation_native import normalize
            normalize(sw13)
        except (ValueError, TypeError, OverflowError, RecursionError):
            raise HTTPException(422, 'Invalid Azure security correlation requirements') from None
    sw27 = parent_policy.get('sw27') if isinstance(parent_policy, dict) else None
    if isinstance(sw27, dict) and 'incidentTriage' in sw27:
        try:
            if provider != 'azure':
                raise ValueError('Incident triage requirements are Azure-only')
            from .native_policy_validation import azure_incident_triage_review
            legacy_sw27_criteria = {'approvedRecipientIds', 'dscNodes', 'targetPrivateEndpointServiceType',
                'approvedLogAnalyticsWorkspaceIds', 'minimumSnapshotSpanDays', 'expectedDiskVmIds',
                'storageEventSubscriptions', 'vmBaselineAssessmentKeys', 'assessmentMaxAgeHours', 'siem'}
            if set(sw27) - {'status', 'scope', 'incidentTriage'} - legacy_sw27_criteria:
                raise ValueError('Incident triage policy cannot supply observations')
            # Preserve unrelated legacy local SW27 baselines; validate this new
            # procedure before accepting it in either authentication mode.
            azure_incident_triage_review({key: sw27[key] for key in
                ('status', 'scope', 'incidentTriage') if key in sw27})
        except (ValueError, TypeError, OverflowError, RecursionError):
            raise HTTPException(422, 'Invalid Azure incident triage requirements') from None
    sw25 = parent_policy.get('sw25') if isinstance(parent_policy, dict) else None
    sw25_checks = sw25.get('checks') if isinstance(sw25, dict) else None
    native_alert_checks = {'azure.other.gateway_backend_health_alert', 'azure_pci_10_2_1_1_8',
                           'azure_diagnostic_setting_11_5_2_3_7959930',
                           'azure_storage_account_monitor_alert_create_update_sqlserver_fr_7a7ddfa'}
    selected_alert_checks = {cid: value for cid, value in sw25_checks.items() if cid in native_alert_checks} if isinstance(sw25_checks, dict) else {}
    if selected_alert_checks:
        try:
            if provider != 'azure':raise ValueError('Alert requirements are Azure-only')
            from .native_policy_validation import azure_guest_review_policy
            # Validate this new criterion in local mode too, preserving existing
            # local policies for other SW25 controls.
            azure_guest_review_policy({**{key: sw25[key] for key in ('status', 'scope') if key in sw25},
                                       'checks': selected_alert_checks})
        except (ValueError, TypeError, OverflowError, RecursionError):
            raise HTTPException(422, 'Invalid Azure alert requirements') from None
    if isinstance(parent_policy, dict):
        for namespace in ("sw15", "sw31", "sw32"):
            if namespace not in parent_policy:
                continue
            try:
                if provider != "azure":
                    raise ValueError("Azure owner policy is provider-specific")
                from .native_policy_validation import azure_detection
                azure_detection({namespace: parent_policy[namespace]})
            except (ValueError, TypeError, OverflowError, RecursionError):
                raise HTTPException(422, "Invalid Azure native owner policy") from None
    if settings.auth_mode != "cognito":
        return
    if set(auth) - AUTH[provider] or set(options) - OPTIONS:
        raise HTTPException(422, "Unsupported hosted connector field or authentication method")
    from . import native_policy_validation as native_review
    for name in ("sw51_policy", "sw55_policy"):
        if name in options:
            try:
                if provider != "gcp":
                    raise ValueError("GCP review is provider-specific")
                native_review.gcp_review(name, options[name])
            except (ValueError, TypeError, OverflowError, RecursionError):
                raise HTTPException(422, "Invalid hosted GCP review policy") from None
    if "compliance_policy" in options:
        policy = options["compliance_policy"]
        if provider == "aws":
            if not isinstance(policy, dict) or not policy or set(policy) - {"aws_backup_plan", "aws_organizations", "sw38_policy", "status", "scope", "security_reviewer_arns", "eks_image_integrity"}:
                raise HTTPException(422, "Unsupported hosted compliance policy")
            from peaso.collectors.aws_policy import backup_plan_policy
            try:
                from peaso.collectors.aws_codecommit_review_native import review_policy
                review_policy(options, strict=True)
                backup_plan_policy(options)
                if "aws_organizations" in policy:
                    native_review.organizations(policy["aws_organizations"])
                if "sw38_policy" in policy:
                    native_review.aws_transport(policy["sw38_policy"])
            except (ValueError, TypeError, OverflowError, RecursionError):
                raise HTTPException(422, "Invalid AWS backup plan policy") from None
        elif provider in ("azure", "gcp"):
            try:
                (native_review.azure_detection if provider == "azure" else native_review.gcp_backup)(policy)
            except (ValueError, TypeError, OverflowError, RecursionError):
                raise HTTPException(422, "Invalid hosted native review policy") from None
        elif provider == "k8s":
            required = {"cluster_id", "max_policy_items", "system_namespaces"}
            expiry = {"observed_at", "max_age_seconds"}
            optional = {"approved_clock_skew"}
            cluster = auth.get("cluster_id")
            if (not isinstance(policy, dict) or set(policy) - optional not in (required, required | expiry) or
                    not isinstance(cluster, str) or not 0 < len(cluster) <= 512 or
                    cluster != cluster.strip() or any(ord(char) < 32 for char in cluster) or
                    cluster != policy.get("cluster_id")):
                raise HTTPException(422, "Unsupported hosted Kubernetes owner policy")
            if expiry <= set(policy) and (not isinstance(policy["observed_at"], str) or
                    type(policy["max_age_seconds"]) is not int or
                    not 0 < policy["max_age_seconds"] <= 31536000):
                raise HTTPException(422, "Invalid hosted Kubernetes owner policy expiry")
            from peaso.collectors.k8s import _owner_policy_metadata
            # Validate declaration shape and bounds at intake. Collection checks
            # actual age, so an expired saved policy yields UNKNOWN rather than
            # preventing the whole hosted scan from running.
            captured_at = policy.get("observed_at") or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            result = _owner_policy_metadata(options, cluster, captured_at)
            if result.get("status") != "collected" or result.get("system_namespaces") != policy["system_namespaces"]:
                raise HTTPException(422, "Invalid hosted Kubernetes owner policy")
        else:
            raise HTTPException(422, "Unsupported hosted compliance policy")
    structured = {"registry_auth", "gke_image_kubernetes", "devops_credentials", "aks_workloads", "sa_json", "external_account_json", "kubeconfig_data", "role_chain", "assume_roles"}
    if any(key not in structured and (not isinstance(value, str) or len(value) > 1_000_000) for key, value in auth.items()):
        raise HTTPException(422, "Hosted authentication fields must contain strings or supported inline configuration")
    for key in ("max_resources", "max_calls", "max_pages"):
        if key in options and (isinstance(options[key], bool) or not isinstance(options[key], int) or options[key] < 1):
            raise HTTPException(422, "Explicit inventory caps must be positive integers")
    limits = {"concurrency": 4, "service_concurrency": 16, "scope_concurrency": 2, "region_concurrency": 2, "retries": 5, "page_size": 1000, "activity_days": 90, "log_entry_minutes": 1440}
    for key, maximum in limits.items():
        if key in options and (isinstance(options[key], bool) or not isinstance(options[key], int) or not 0 < options[key] <= maximum):
            raise HTTPException(422, "Hosted collector limit exceeds the supported budget")
    if provider == "aws":
        if "include_source_account" in options and not isinstance(options["include_source_account"], bool):
            raise HTTPException(422, "include_source_account must be a boolean")
        has_keys = any(auth.get(key) for key in ("aws_access_key_id", "aws_secret_access_key", "aws_session_token"))
        if has_keys and (not auth.get("aws_access_key_id") or not auth.get("aws_secret_access_key") or auth.get("method", "access_keys") not in {"access_keys", "assume_role"}):
            raise HTTPException(422, "Explicit customer AWS authentication requires access key and secret key")
        role_entries = []
        if auth.get("role_arn"):
            role_entries.append({"role_arn": auth["role_arn"]})
        for field in ("role_chain", "assume_roles"):
            entries = auth.get(field, [])
            if not isinstance(entries, list) or any(not isinstance(entry, dict) or set(entry) - {"role_arn", "role_session_name", "external_id"} for entry in entries):
                raise HTTPException(422, "Invalid role configuration")
            role_entries.extend(entries)
        if len(role_entries) > 50 or len(auth.get("role_chain", [])) > 10:
            raise HTTPException(422, "At most 50 distinct role targets and 10 chain roles are supported")
        seen = set()
        for entry in role_entries:
            if not isinstance(entry.get("role_arn"), str) or not AWS_ROLE_ARN.fullmatch(entry["role_arn"]):
                raise HTTPException(422, "Invalid role configuration")
            if entry["role_arn"] in seen:
                raise HTTPException(422, "Duplicate role target")
            seen.add(entry["role_arn"])
            for field in ("external_id", "role_session_name"):
                value = entry.get(field, auth.get(field))
                if value is not None and (not isinstance(value, str) or not 2 <= len(value) <= (1224 if field == "external_id" else 64)):
                    raise HTTPException(422, "Invalid role configuration")
        if any(AWS_ROLE_ARN.fullmatch(entry["role_arn"]).group(1) in PLATFORM_ACCOUNT_IDS for entry in role_entries):
            raise HTTPException(422, "Platform-owned AWS accounts cannot be role targets")
        if has_keys:
            # Their source identity authorizes these targets; never substitute our role.
            return
        if auth.get("method") not in {"assume_role", "task_role"} or not role_entries:
            raise HTTPException(422, "Hosted AWS role access requires target roles")
        if auth.get("role_chain") or options.get("organization_role_name"):
            raise HTTPException(422, "Hosted platform role access requires explicit fanout targets")
        if any(entry.get("external_id") for entry in role_entries if entry in auth.get("assume_roles", [])):
            raise HTTPException(422, "Hosted platform role targets use the server-generated ExternalID")
        if auth.get("external_id") and not server_external_id:
            raise HTTPException(422, "Hosted platform ExternalID is generated by the server")
        if not server_external_id:
            auth["external_id"] = EXTERNAL_ID_PREFIX + secrets.token_urlsafe(24)
        elif not isinstance(auth.get("external_id"), str) or not auth["external_id"].startswith((EXTERNAL_ID_PREFIX, LEGACY_EXTERNAL_ID_PREFIX)):
            raise HTTPException(422, "Missing server-generated ExternalID")
        return
    elif provider == "gcp":
        if auth.get("method") == "platform-service-account":
            from peaso.gcp_platform import PLATFORM_PROJECT, PROOF_LABEL, enabled, new_proof_label, project_id
            if not enabled(settings) or set(auth) - {"method", "project_proof_label"}:
                raise HTTPException(422, "Hosted GCP platform service account is unavailable")
            if "project_proof_label" in auth and not server_external_id:
                raise HTTPException(422, "GCP project proof label is generated by the server")
            if server_external_id:
                if not isinstance(auth.get("project_proof_label"), str) or not PROOF_LABEL.fullmatch(auth["project_proof_label"]):
                    raise HTTPException(422, "Missing server-generated GCP project proof label")
            else:
                auth["project_proof_label"] = new_proof_label()
            if not scopes or any(options.get(key) for key in ("all_projects", "discover_projects", "all_hierarchy")):
                raise HTTPException(422, "The shared HackTricks GCP account requires exact project IDs; project discovery is unavailable")
            try:
                selected = [project_id(scope) for scope in scopes]
                if PLATFORM_PROJECT in selected:
                    raise ValueError("platform project selected")
            except (ValueError, TypeError):
                raise HTTPException(422, "Enter exact customer project IDs for the shared HackTricks GCP account") from None
        elif auth.get("method") == "external-account":
            try:
                from peaso.collectors.gcp import validate_external_config
                info = auth.get("external_account_json")
                info = json.loads(info) if isinstance(info, str) else info
                validate_external_config(info, inline=True)
                if not isinstance(auth.get("subject_token"), str) or not auth["subject_token"]:
                    raise ValueError("Inline subject token required")
            except Exception:
                raise HTTPException(422, "Hosted GCP federation requires safe inline config and subject token") from None
        elif auth.get("token"):
            if auth.get("method", "token") != "token":
                raise HTTPException(422, "Hosted GCP token authentication requires token method")
        elif auth.get("sa_json"):
            try:
                value = auth["sa_json"] if isinstance(auth["sa_json"], dict) else json.loads(auth["sa_json"])
                if value.get("type") != "service_account" or value.get("token_uri") != "https://oauth2.googleapis.com/token":
                    raise ValueError("Unsafe credential source")
            except Exception:
                raise HTTPException(422, "Hosted GCP requires inline service-account JSON") from None
            from peaso.gcp_platform import PLATFORM_EMAIL
            if value.get("client_email") == PLATFORM_EMAIL:
                raise HTTPException(422, "Use the hosted GCP platform service account connector")
            if auth.get("method", "service-account") not in {"service-account", "service_account"}:
                raise HTTPException(422, "Unsupported hosted GCP authentication")
        else:
            raise HTTPException(422, "Hosted GCP requires explicit customer credentials")
    elif provider == "azure":
        if not (auth.get("token") or auth.get("arm_token")):
            certificate = auth.get("certificate_data") or auth.get("client_certificate")
            if auth.get("method") == "workload-identity":
                if not all(isinstance(auth.get(field), str) and auth[field] for field in ("tenant_id", "client_id", "federated_token")):
                    raise HTTPException(422, "Hosted Azure federation requires inline assertion")
            elif certificate:
                if not isinstance(certificate, str) or "-----BEGIN" not in certificate or not auth.get("tenant_id") or not auth.get("client_id") or auth.get("method", "client-cert") not in {"client-cert", "certificate"}:
                    raise HTTPException(422, "Hosted Azure requires inline PEM certificate authentication")
            elif not all(auth.get(field) for field in ("tenant_id", "client_id", "client_secret")) or auth.get("method", "client-secret") != "client-secret":
                raise HTTPException(422, "Hosted Azure requires explicit customer credentials")
        elif auth.get("method", "token") not in {"token", "auto"}:
            raise HTTPException(422, "Unsupported hosted Azure authentication")
    elif provider == "k8s":
        try:
            from peaso.collectors.k8s import hosted_auth, _public_server
            resolved = hosted_auth(auth)
            _public_server(resolved["server"])
        except Exception:
            raise HTTPException(422, "Hosted Kubernetes requires safe inline credentials and a public HTTPS API server") from None


def auth_capabilities(settings):
    if settings.auth_mode == "cognito":
        from peaso.gcp_platform import enabled
        gcp = ["token", "service-account", "external-account"]
        if enabled(settings):
            gcp.append("platform-service-account")
        return {"aws": ["access_keys", "assume_role"], "gcp": gcp, "azure": ["token", "client-secret", "client-cert", "workload-identity"], "k8s": ["inline", "token", "client-cert"]}
    return {"aws": ["default", "profile", "sso", "access_keys", "assume_role", "web_identity", "container", "instance"], "gcp": ["adc", "gcloud", "service-account", "external-account", "metadata", "impersonation", "token"], "azure": ["auto", "az-cli", "client-secret", "client-cert", "managed-identity", "workload-identity", "device-code", "token"], "k8s": ["kubeconfig", "context", "in-cluster", "token", "client-cert", "inline"]}


@lru_cache(maxsize=8)
def _selector_index(provider):
    """Valid selector values per provider, without building the full public catalog."""
    from peaso.analysis import ANALYSIS_CHECKS
    from peaso.checks import CHECKS
    from peaso.checks.catalog import _framework_rows, framework_selector_index
    from peaso.engine import CATEGORIES, FRAMEWORK_ALIASES
    from peaso.checks.native_only import automated_checks
    checks = {c.id for c in automated_checks(CHECKS) if c.provider in {provider, "all"}} | {c["id"] for c in ANALYSIS_CHECKS if c.get("provider") in {provider, "all"}}
    from peaso.checks import CHECK_ALIASES
    checks |= {retired for retired, survivor in CHECK_ALIASES.items() if survivor in checks}  # retired duplicate ids
    provider_ids = frozenset(row["id"] for row in _framework_rows() if row["provider"] in {provider, "all"})
    labels = {name for c in CHECKS for name in c.frameworks} | {name for c in ANALYSIS_CHECKS for name in c["frameworks"]}
    frameworks = labels | provider_ids | set(FRAMEWORK_ALIASES) | {"nist", "hacktricks_cloud_best_practices"}
    # Family labels ("CIS", "NIST 800-53", "AWS-Foundational-Security-Best-Practices") remain filter aliases.
    frameworks |= {key for key, ids in framework_selector_index().items() if provider_ids.intersection(ids)}
    return frozenset(CATEGORIES), frozenset(checks), frozenset(frameworks)


def validate_selectors(request, provider):
    categories, checks, frameworks = _selector_index(provider)
    if any(value not in categories for value in request.get("categories", [])):
        raise HTTPException(422, "Unsupported scan category")
    if any(value not in checks for value in request.get("checks", [])):
        raise HTTPException(422, "Unknown check for selected provider")
    if any(value not in frameworks and str(value).lower() not in frameworks for value in request.get("frameworks", [])):
        raise HTTPException(422, "Unsupported framework")
