"""Explicit configured content stages, independent of compliance selectors."""

# (provider, exact selected-target option, stage, named native consumer)
ROWS = (('aws', None, 'leaks', 'aws_cis_ec2_userdata_embedded_secrets'),
 ('aws',
  'selected_aws_build_deployment_sources',
  'leaks',
  'aws.review.build_deployment.referenced_source_secret_indicators'),
 ('aws', None, 'leaks', 'aws.review.cloudwatch.sampled_log_secret_indicators'),
 ('aws',
  'selected_aws_codebuild_inline_buildspecs',
  'leaks',
  'aws.review.codebuild.selected_inline_buildspec_secret_indicators'),
 ('aws', None, 'leaks', 'aws.review.codecommit.default_commit_secret_indicators'),
 ('aws',
  'selected_aws_configuration_content',
  'leaks',
  'aws.review.configuration.selected_content_secret_indicators'),
 ('aws', 'selected_aws_image_vulnerabilities', 'images', 'aws.review.ecr.selected_image_vulnerabilities'),
 ('aws',
  'selected_aws_ecr_public_images',
  'images',
  'aws.review.ecr_public.selected_image_high_vulnerabilities'),
 ('aws', 'selected_aws_ecr_public_images', 'leaks', 'aws.review.ecr_public.selected_image_secret_indicators'),
 ('aws', None, 'leaks', 'aws.review.ecr_repository.package_content_secret_indicators'),
 ('aws',
  'selected_aws_ecs_environment_files',
  'leaks',
  'aws.review.ecs.selected_environment_file_secret_indicators'),
 ('aws',
  'selected_aws_lambda_functions',
  'leaks',
  'aws.review.lambda.selected_environment_secret_indicators'),
 ('aws', None, 'leaks', 'aws.review.lambda_function.package_content_secret_indicators'),
 ('aws', None, 'leaks', 'aws.review.lambda_layer_version.package_content_secret_indicators'),
 ('aws', 'selected_aws_s3_sources', 'leaks', 'aws.review.s3.selected_source_secret_indicators'),
 ('aws', 'selected_aws_workload_sources', 'leaks', 'aws.review.workload.referenced_source_secret_indicators'),
 ('aws',
  'selected_aws_workload_commands',
  'leaks',
  'aws.review.workload.selected_command_literal_secret_indicators'),
 ('aws',
  'selected_aws_workload_image_secrets',
  'leaks',
  'aws.review.workload.selected_image_secret_indicators'),
 ('azure',
  'selected_azure_acr_image_vulnerabilities',
  'images',
  'azure.review.acr.selected_image_high_critical_vulnerabilities'),
 ('azure', 'selected_azure_acr_images', 'leaks', 'azure.review.acr.selected_image_secret_indicators'),
 ('azure',
  'selected_azure_aks_pod_images',
  'images',
  'azure.review.aks.selected_pod_image_high_vulnerabilities'),
 ('azure', 'selected_azure_aks_pod_images', 'leaks', 'azure.review.aks.selected_pod_image_secret_indicators'),
 ('azure',
  'selected_azure_app_configuration_values',
  'leaks',
  'azure.review.app_configuration.selected_value_secret_indicators'),
 ('azure',
  'selected_azure_app_settings',
  'leaks',
  'azure.review.app_service.selected_app_settings_secret_indicators'),
 ('azure',
  'selected_azure_application_insights',
  'leaks',
  'azure.review.application_insights.selected_trace_sample_secret_indicators'),
 ('azure',
  'selected_azure_configuration_content',
  'leaks',
  'azure.review.configuration.selected_content_secret_indicators'),
 ('azure',
  'selected_azure_data_factory_declarations',
  'leaks',
  'azure.review.data_factory.selected_declaration_secret_indicators'),
 ('azure',
  'selected_azure_databricks_files',
  'leaks',
  'azure.review.databricks.selected_notebook_source_secret_indicators'),
 ('azure',
  'selected_azure_databricks_notebooks',
  'leaks',
  'azure.review.databricks.selected_notebook_source_secret_indicators'),
 ('azure',
  'selected_azure_databricks_task_outputs',
  'leaks',
  'azure.review.databricks.selected_notebook_source_secret_indicators'),
 ('azure',
  'selected_azure_devops_content',
  'leaks',
  'azure.review.devops.selected_content_secret_indicators'),
 ('azure',
  'selected_azure_flex_deployment_containers',
  'leaks',
  'azure.review.function.configured_deployment_container_archives_secret_indicators'),
 ('azure',
  'selected_azure_function_package_sources',
  'leaks',
  'azure.review.function.selected_package_source_secret_indicators'),
 ('azure',
  'selected_azure_log_workspaces',
  'leaks',
  'azure.review.log_analytics.selected_message_sample_secret_indicators'),
 ('azure',
  'selected_azure_ml_code_files',
  'leaks',
  'azure.review.machine_learning.selected_code_file_secret_indicators'),
 ('azure',
  'selected_azure_ml_command_jobs',
  'leaks',
  'azure.review.machine_learning.selected_command_job_secret_indicators'),
 ('azure',
  'selected_azure_ml_environment_versions',
  'leaks',
  'azure.review.machine_learning.selected_environment_conda_secret_indicators'),
 ('azure',
  'selected_azure_storage_sources',
  'leaks',
  'azure.review.storage.selected_source_secret_indicators'),
 ('azure',
  'selected_azure_synapse_notebooks',
  'leaks',
  'azure.review.synapse.selected_notebook_source_secret_indicators'),
 ('azure',
  'selected_azure_synapse_pipelines',
  'leaks',
  'azure.review.synapse.selected_pipeline_secret_indicators'),
 ('gcp',
  'selected_appengine_flex_version_images',
  'images',
  'gcp.review.app_engine_flex.selected_version_image_high_vulnerabilities'),
 ('gcp',
  'selected_appengine_flex_version_images',
  'leaks',
  'gcp.review.app_engine_flex.selected_version_image_secret_indicators'),
 ('gcp', None, 'leaks', 'gcp.review.app_engine_version.literal_environment_secret_indicators'),
 ('gcp', 'selected_appengine_versions', 'leaks', 'gcp.review.appengine.deployment_source_secret_indicators'),
 ('gcp', 'selected_artifact_images', 'leaks', 'gcp.review.artifact_image.content_secret_indicators'),
 ('gcp',
  'selected_gcp_registry_image_vulnerabilities',
  'images',
  'gcp.review.artifact_image.selected_image_vulnerabilities'),
 ('gcp', 'selected_artifact_files', 'leaks', 'gcp.review.artifactregistry.selected_file_secret_indicators'),
 ('gcp',
  'selected_batch_referenced_sources',
  'leaks',
  'gcp.review.batch.selected_mounted_script_source_secret_indicators'),
 ('gcp', None, 'leaks', 'gcp.review.batch_job.literal_configuration_secret_indicators'),
 ('gcp', 'selected_bigquery_routines', 'leaks', 'gcp.review.bigquery.selected_routine_secret_indicators'),
 ('gcp',
  'selected_cloudrun_job_declared_images',
  'images',
  'gcp.review.cloud_run.selected_job_image_vulnerabilities'),
 ('gcp', 'selected_cloudbuild_artifact_builds', 'leaks', 'gcp.review.cloudbuild.artifact_secret_indicators'),
 ('gcp', 'selected_cloudbuild_builds', 'leaks', 'gcp.review.cloudbuild.stored_log_secret_indicators'),
 ('gcp', None, 'leaks', 'gcp.review.cloudbuild_build.literal_configuration_secret_indicators'),
 ('gcp', None, 'leaks', 'gcp.review.cloudbuild_trigger.literal_configuration_secret_indicators'),
 ('gcp', 'selected_clouddeploy_releases', 'leaks', 'gcp.review.clouddeploy.release_source_secret_indicators'),
 ('gcp',
  'selected_cloudrun_job_declared_images',
  'leaks',
  'gcp.review.cloudrun_job.declared_image_secret_indicators'),
 ('gcp', None, 'leaks', 'gcp.review.cloudrun_job.literal_configuration_secret_indicators'),
 ('gcp', None, 'leaks', 'gcp.review.cloudrun_service.literal_configuration_secret_indicators'),
 ('gcp',
  'selected_cloudrun_worker_pool_revision_images',
  'leaks',
  'gcp.review.cloudrun_worker_pool.selected_revision_image_secret_indicators'),
 ('gcp', 'selected_cloudtasks_tasks', 'leaks', 'gcp.review.cloudtasks.selected_payload_secret_indicators'),
 ('gcp', None, 'leaks', 'gcp.review.composer.dag_source_secret_indicators'),
 ('gcp', None, 'leaks', 'gcp.review.composer_environment.literal_configuration_secret_indicators'),
 ('gcp',
  'selected_dataflow_referenced_sources',
  'leaks',
  'gcp.review.dataflow.selected_package_referenced_source_secret_indicators'),
 ('gcp', None, 'leaks', 'gcp.review.dataflow_job.literal_configuration_secret_indicators'),
 ('gcp', 'selected_dataform_files', 'leaks', 'gcp.review.dataform.selected_file_secret_indicators'),
 ('gcp',
  'selected_dataproc_referenced_sources',
  'leaks',
  'gcp.review.dataproc.selected_initialization_referenced_source_secret_indicators'),
 ('gcp',
  'selected_dataproc_referenced_sources',
  'leaks',
  'gcp.review.dataproc.selected_job_referenced_source_secret_indicators'),
 ('gcp', None, 'leaks', 'gcp.review.dataproc_cluster.literal_configuration_secret_indicators'),
 ('gcp', None, 'leaks', 'gcp.review.dataproc_job.literal_configuration_secret_indicators'),
 ('gcp',
  'selected_developerconnect_files',
  'leaks',
  'gcp.review.developerconnect.selected_repository_file_secret_indicators'),
 ('gcp', None, 'leaks', 'gcp.review.function.literal_environment_secret_indicators'),
 ('gcp', None, 'leaks', 'gcp.review.function.resolved_source_archive_secret_indicators'),
 ('gcp', 'selected_gke_pod_images', 'images', 'gcp.review.gke.selected_pod_image_high_vulnerabilities'),
 ('gcp', 'selected_gke_pod_images', 'leaks', 'gcp.review.gke.selected_pod_image_secret_indicators'),
 ('gcp', None, 'leaks', 'gcp.review.instance.literal_configuration_secret_indicators'),
 ('gcp', None, 'leaks', 'gcp.review.instance_template.literal_configuration_secret_indicators'),
 ('gcp', None, 'leaks', 'gcp.review.logging.application_log_secret_indicators'),
 ('gcp', None, 'leaks', 'gcp.review.project.literal_configuration_secret_indicators'),
 ('gcp', None, 'leaks', 'gcp.review.scheduler_job.literal_target_secret_indicators'),
 ('gcp',
  'selected_source_repository_files',
  'leaks',
  'gcp.review.sourcerepo.selected_file_secret_indicators'),
 ('gcp', 'selected_gcs_archives', 'leaks', 'gcp.review.storage.selected_archive_secret_indicators'),
 ('gcp', 'selected_gcs_objects', 'leaks', 'gcp.review.storage.selected_object_secret_indicators'),
 ('gcp',
  'selected_workbench_referenced_sources',
  'leaks',
  'gcp.review.workbench.selected_referenced_source_secret_indicators_20261020'),
 ('gcp', None, 'leaks', 'gcp.review.workbench_instance.literal_configuration_secret_indicators'),
 ('gcp', None, 'leaks', 'gcp.review.workflow.deployed_source_secret_indicators'),
 ('k8s', 'selected_k8s_log_samples', 'leaks', 'k8s.review.selected_container_logs.secret_indicators'),
 ('k8s', 'selected_k8s_flux_artifacts', 'leaks', 'k8s.review.selected_flux_artifact_secret_indicators'),
 ('k8s', 'selected_k8s_literal_resources', 'leaks', 'k8s.review.selected_literals.secret_indicators'),
 ('k8s', 'selected_k8s_metadata_resources', 'leaks', 'k8s.review.selected_metadata.secret_indicators'),
 ('k8s', 'selected_k8s_registry_images', 'images', 'k8s.review.selected_registry_image_high_vulnerabilities'),
 ('k8s', 'selected_k8s_registry_images', 'leaks', 'k8s.review.selected_registry_image_secret_indicators'),
 ('k8s', 'selected_k8s_text_resources', 'leaks', 'k8s.review.selected_text_content.secret_indicators'))


_PROFILE_FILTERS = {
    'gcp.review.dataproc.selected_job_referenced_source_secret_indicators': 'job',
    'gcp.review.dataproc.selected_initialization_referenced_source_secret_indicators': 'cluster',
}


def configured_checks(provider, options):
    result = {'leaks': [], 'images': []}
    for owner, option, stage, check in ROWS:
        flag = 'content_secret_scans' if stage == 'leaks' else 'image_vulnerability_scans'
        if (owner == provider and options.get(flag) is True
                and (option is None or type(options.get(option)) is list and options[option])):
            profile = _PROFILE_FILTERS.get(check)
            if profile and not any(type(row) is dict and row.get('profile') == profile for row in options[option]):
                continue
            result[stage].append(check)
    return {stage: sorted(set(checks)) for stage, checks in result.items()}


def validate_content_checks(provider, options, selected):
    if type(selected) is not list or any(type(value) is not str for value in selected):
        raise ValueError('content_checks must be a string list')
    allowed = set().union(*configured_checks(provider, options).values())
    if set(selected) - allowed:
        raise ValueError('Content checks require enabled scanning and configured exact targets in this connector')
    return sorted(set(selected))


def known_content_checks(provider):
    return {check for owner, _, _, check in ROWS if owner == provider}


def named_checks(request):
    return list(dict.fromkeys([*(request.get('checks') or []), *(request.get('content_checks') or [])]))



def prepare_request(provider, options, request):
    result = dict(request)
    selected = list(request.get('content_checks') or [])
    configured = configured_checks(provider, options)
    for stage, field, option in (('leaks', 'leaks_enabled', 'content_secret_scans'),
                                 ('images', 'images_enabled', 'image_vulnerability_scans')):
        value = request.get(field)
        if value is not None and type(value) is not bool:
            raise ValueError(field + ' must be a boolean')
        if value is True:
            if options.get(option) is not True or not configured[stage]:
                raise ValueError('Configure enabled ' + stage + ' targets in the connector first')
            selected.extend(configured[stage])
        elif value is False:
            blocked = {check for owner, _, group, check in ROWS if owner == provider and group == stage}
            selected = [check for check in selected if check not in blocked]
    result['content_checks'] = validate_content_checks(provider, options, selected)
    return result


def normalize_request(request):
    if type(request) is not dict:
        return request
    connector = request.get('connector', request)
    if type(connector) is not dict or type(connector.get('options', {})) is not dict:
        return request
    return prepare_request(connector.get('provider'), connector.get('options', {}), request)



def effective_options(request):
    options = dict(request.get('connector', request).get('options', {}))
    if request.get('leaks_enabled') is False:
        options['content_secret_scans'] = False
    if request.get('images_enabled') is False:
        options['image_vulnerability_scans'] = False
    return options


def capture_checks(request):
    from peaso.engine import _selection
    from peaso.finding_types import type_for
    request = normalize_request(request)
    provider = request.get('connector', request).get('provider')
    checks = _selection(provider, request.get('categories'), request.get('checks'),
        request.get('frameworks'), content_checks=request.get('content_checks'))[1]
    return {check.id for check in checks if not (request.get('leaks_enabled') is False
        and (check.id in {cid for owner, _, stage, cid in ROWS if owner == provider and stage == 'leaks'}
             or type_for(check.id) in {'secrets', 'detected_leaks'}))}
