"""Current reports resolve, while earlier strict cards retain their exact catalog."""

from peaso.privesc import versioned_catalog as catalog
from peaso.privesc.finding_explanation import evidence_summary
from tests.test_peaso_privesc_finding_explanations_review import admin_projected


def test_current_catalog_binding_resolves_new_technique():
    binding = catalog.current_binding()
    entries, status = catalog.lookup_entries(["aws-flink-studio-presigned-url"], binding)
    assert status == "exact_strict_privesc"
    assert set(entries) == {"aws-flink-studio-presigned-url"}


def test_apim_anchor_correction_preserves_original_report_binding():
    ident = "azure-apim-developer-portal-sso-external-principal"
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.APIM_ANCHOR_685_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.APIM_ANCHOR_685_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current"
    assert previous[ident]["source"].endswith("#microsoftapimanagementserviceuserstokenaction")
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc"
    assert current[ident]["source"].endswith("#microsoftapimanagementserviceusersgeneratessourlaction")
    assert len(catalog._verified_apim_anchor_685_previous()) == 685


def test_beanstalk_prefilter_change_preserves_previous_report_binding():
    ident = "aws-elasticbeanstalk-passrole-create-environment"
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.BEANSTALK_685_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.BEANSTALK_685_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current"
    assert previous[ident]["requires"]["all_of"] == [
        {"action": "elasticbeanstalk:CreateEnvironment"}]
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc"
    assert current[ident]["requires"]["any_of"] == [
        [{"action": "elasticbeanstalk:CreateEnvironment"}],
        [{"action": "elasticbeanstalk:UpdateEnvironment"}]]




def test_reviewed_685_binding_retains_original_source_for_stored_reports():
    ident = "azure-apim-developer-portal-sso-external-principal"
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.REVIEWED_685_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.REVIEWED_685_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current"
    assert previous[ident]["source"].endswith("#microsoftapimanagementserviceusersgeneratessourlaction")
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc"
    assert current[ident]["source"].endswith("#microsoftapimanagementserviceuserstokenaction")
    assert len(catalog._verified_reviewed_685_previous()) == 685


def test_reviewed_691_binding_retains_retired_techniques_without_reviving_them():
    ident = "gcp-artifactregistry-repositories-update-dependency-confusion"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc" and current == {}
    previous_binding = {
        "schema": catalog.BINDING_SCHEMA,
        "manifest_sha256": catalog.REVIEWED_691_PREVIOUS_MANIFEST,
        "effective_tree_sha256": catalog.REVIEWED_691_PREVIOUS_TREE,
        "source_revision": catalog.V4_REVISION,
    }
    previous, status = catalog.lookup_entries([ident], previous_binding)
    assert status == "exact_previous_current" and ident in previous
    assert len(catalog._verified_reviewed_691_previous()) == 691


def test_previous_aws_audit_binding_keeps_its_original_entries():
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.FINAL_AWS_AUDIT_691_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.FINAL_AWS_AUDIT_691_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    entries, status = catalog.lookup_entries(["aws-flink-studio-presigned-url"], old)
    assert status == "exact_previous_current"
    assert set(entries) == {"aws-flink-studio-presigned-url"}
    assert len(catalog._verified_final_aws_audit_691_previous()) == 691


def test_source_repin_keeps_previous_700_entry_meanings():
    ident = "aws-cloudcontrol-passrole-createresource"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc"
    assert current[ident]["source_revision"] == "9e5d46375b53cbd2d0cdce63771f3e36f0c30bae"
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.SOURCE_REPIN_700_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.SOURCE_REPIN_700_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current"
    assert previous[ident]["source_revision"] == "171e422299"
    assert len(catalog._verified_source_repin_700_previous()) == 700


def test_appstream_resource_requirements_keep_previous_report_meanings():
    ident = "aws-appstream-createimagebuilderstreamingurl"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc"
    assert current[ident]["requires"]["all_of"][0]["action"] == "appstream:CreateImageBuilderStreamingURL"
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.APPSTREAM_RESOURCE_700_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.APPSTREAM_RESOURCE_700_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current"
    assert previous[ident]["requires"]["all_of"] == []
    assert len(catalog._verified_appstream_resource_700_previous()) == 700


def test_revisionless_organizations_binding_retains_original_catalog_tree():
    ident = "aws-appstream-createimagebuilderstreamingurl"
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.ORGANIZATIONS_RCP_691_REVISIONLESS_MANIFEST,
           "effective_tree_sha256": catalog.ORGANIZATIONS_RCP_691_REVISIONLESS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current"
    assert previous[ident]["requires"]["all_of"] == []
    assert catalog.ORGANIZATIONS_RCP_691_REVISIONLESS_TREE != catalog.CURRENT_TREE


def test_stepfunctions_passrole_service_binding_preserves_previous_catalog():
    ids = ["aws-stepfunctions-createstatemachine-passrole-start",
           "aws-stepfunctions-updatestatemachine-passrole"]
    current, status = catalog.lookup_entries(ids, catalog.current_binding())
    assert status == "exact_strict_privesc"
    for ident in ids:
        passrole = next(req for req in current[ident]["requires"]["all_of"]
                        if req["action"] == "iam:PassRole")
        assert passrole["request_context"] == {"iam:PassedToService": "states.amazonaws.com"}
        assert "sfn_role_sdk_effect_reviewed" in current[ident]["preconditions"]

    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.STEPFUNCTIONS_PASSROLE_689_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.STEPFUNCTIONS_PASSROLE_689_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries(ids, old)
    assert status == "exact_previous_current"
    assert set(previous) == set(ids)
    for ident in ids:
        passrole = next(req for req in previous[ident]["requires"]["all_of"]
                        if req["action"] == "iam:PassRole")
        assert "request_context" not in passrole
    assert len(catalog._verified_stepfunctions_passrole_689_previous()) == 689


def test_organizations_generated_access_role_binding_preserves_previous_catalog():
    ident = "aws-organizations-createaccount-principalorgid-trust"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc"
    assert current[ident]["requires"]["all_of"] == [
        {"action": "organizations:CreateAccount", "resource": "*"}]
    assert "created_org_access_role_assumable" in current[ident]["preconditions"]
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.ORG_ACCESS_ROLE_689_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.ORG_ACCESS_ROLE_689_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current"
    assert any(req["action"] == "sts:AssumeRole"
               for req in previous[ident]["requires"]["all_of"])
    assert len(catalog._verified_org_access_role_689_previous()) == 689


def test_servicecatalog_artifact_effect_binding_preserves_previous_catalog():
    ids = ("aws-servicecatalog-createprovisioningartifact-provisionproduct",
           "aws-servicecatalog-associateprincipal-createartifact-provision")
    current, status = catalog.lookup_entries(ids, catalog.current_binding())
    assert status == "exact_strict_privesc"
    assert all("servicecatalog_new_artifact_effect_unverified" in current[ident]["preconditions"]
               for ident in ids)
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.SERVICECATALOG_EFFECT_689_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.SERVICECATALOG_EFFECT_689_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries(ids, old)
    assert status == "exact_previous_current" and set(previous) == set(ids)
    assert all("preconditions" not in previous[ident] for ident in ids)
    assert len(catalog._verified_servicecatalog_effect_689_previous()) == 689


def test_config_remediation_binding_preserves_previous_catalog():
    ident = "aws-config-passrole-automatic-remediation"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc"
    entry = current[ident]
    assert "config_automatic_remediation_effect_unverified" in entry["preconditions"]
    requirements = {req["action"]: req for req in entry["requires"]["all_of"]}
    assert requirements["iam:PassRole"]["request_context"] == {
        "iam:PassedToService": "ssm.amazonaws.com"}
    assert set(requirements) == {"iam:PassRole"}
    assert any(condition["id"] == "document_reuse" for condition in entry["conditions"])
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.CONFIG_REMEDIATION_689_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.CONFIG_REMEDIATION_689_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current"
    assert "preconditions" not in previous[ident]
    assert previous[ident]["severity"] == "critical"
    assert len(catalog._verified_deadline_fleet_684_previous()) == 684
    assert len(catalog._verified_config_remediation_689_previous()) == 689


def test_elasticbeanstalk_role_execution_binding_preserves_previous_catalog():
    ident = "aws-elasticbeanstalk-passrole-create-environment"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc"
    entry = current[ident]
    assert "elasticbeanstalk_environment_role_effect_reviewed" in entry["preconditions"]
    assert entry["requires"]["any_of"] == [
        [{"action": "elasticbeanstalk:CreateEnvironment"}],
        [{"action": "elasticbeanstalk:UpdateEnvironment"}],
    ]
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.ELASTICBEANSTALK_EFFECT_689_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.ELASTICBEANSTALK_EFFECT_689_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current"
    assert "preconditions" not in previous[ident]
    assert len(catalog._verified_elasticbeanstalk_effect_689_previous()) == 689


def test_emr_runtime_role_binding_preserves_previous_catalog():
    ids = ("aws-emr-passrole-runjobflow",
           "aws-emr-getclustersessioncredentials-runtime-role",
           "aws-emr-addjobflowsteps-runtime-role")
    current, status = catalog.lookup_entries(ids, catalog.current_binding())
    assert status == "exact_strict_privesc" and set(current) == set(ids)
    assert current[ids[0]]["requires"]["all_of"] == [
        {"action": "elasticmapreduce:RunJobFlow"}]
    assert "emr_new_cluster_instance_role_effect_reviewed" in current[ids[0]]["preconditions"]
    assert current[ids[1]]["preconditions"] == ["emr_cluster_session_runtime_role"]
    assert current[ids[1]]["requires"]["all_of"] == [
        {"action": "elasticmapreduce:GetClusterSessionCredentials"}]
    assert "emr_existing_cluster_runtime_step_role" in current[ids[2]]["preconditions"]
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.EMR_RUNTIME_689_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.EMR_RUNTIME_689_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries(ids, old)
    assert status == "exact_previous_current" and set(previous) == set(ids[:2])
    assert "preconditions" not in previous[ids[0]]
    assert len(catalog._verified_emr_runtime_689_previous()) == 689


def test_amplify_role_binding_preserves_previous_catalog():
    ids = ("aws-amplify-updateapp-passrole", "aws-amplify-updateapp-passrole-ssr")
    current, status = catalog.lookup_entries(ids, catalog.current_binding())
    assert status == "exact_strict_privesc"
    assert "amplify_service_role_build_effect_unverified" in current[ids[0]]["preconditions"]
    assert "amplify_compute_role_ssr_effect_unverified" in current[ids[1]]["preconditions"]
    assert all(len(current[ident]["requires"]["all_of"]) == 1 for ident in ids)
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.AMPLIFY_ROLE_690_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.AMPLIFY_ROLE_690_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries(ids, old)
    assert status == "exact_previous_current" and set(previous) == set(ids)
    assert all("preconditions" not in previous[ident] for ident in ids)
    assert len(catalog._verified_amplify_role_690_previous()) == 690


def test_sts_federation_candidate_binding_preserves_previous_catalog():
    ident = "aws-sts-assumerole-trusted"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc" and ident in current
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.STS_FEDERATION_690_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.STS_FEDERATION_690_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current" and previous[ident] == current[ident]
    assert len(catalog._verified_sts_federation_690_previous()) == 690


def test_agentcore_bounds_binding_preserves_previous_catalog():
    ident = "aws-bedrock-agentcore-createcodeinterpreter-passrole"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc" and ident in current
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.AGENTCORE_BOUNDS_690_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.AGENTCORE_BOUNDS_690_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current" and ident in previous
    assert len(catalog._verified_agentcore_bounds_690_previous()) == 690


def test_agentcore_existing_binding_preserves_previous_catalog():
    ident = "aws-bedrock-agentcore-createcodeinterpreter-passrole"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc" and ident in current
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.AGENTCORE_EXISTING_690_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.AGENTCORE_EXISTING_690_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current"
    assert previous[ident]["source_revision"] == "6fb9ac51fd"
    assert current[ident]["source_revision"] == "9e5d46375b53cbd2d0cdce63771f3e36f0c30bae"
    assert {key: value for key, value in previous[ident].items() if key != "source_revision"} == {
        key: value for key, value in current[ident].items() if key != "source_revision"}
    assert len(catalog._verified_agentcore_existing_690_previous()) == 690


def test_agentcore_runtime_binding_preserves_previous_catalog():
    ident = "aws-bedrock-agentcore-updateagentruntime-passrole"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc" and ident in current
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.AGENTCORE_RUNTIME_691_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.AGENTCORE_RUNTIME_691_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current" and ident in previous
    assert len(catalog._verified_agentcore_runtime_691_previous()) == 691


def test_agentcore_create_binding_preserves_previous_catalog():
    ident = "aws-bedrock-agentcore-createagentruntime-passrole"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc" and ident in current
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.AGENTCORE_CREATE_691_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.AGENTCORE_CREATE_691_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current" and ident in previous
    assert len(catalog._verified_agentcore_create_691_previous()) == 691


def test_agentcore_harness_binding_preserves_previous_catalog():
    ident = "aws-bedrock-agentcore-createharness-passrole"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc" and ident in current
    current_actions = {req["action"] for req in current[ident]["requires"]["all_of"]}
    assert "bedrock-agentcore:CreateMemory" in current_actions
    assert "bedrock-agentcore:CreateAgentRuntimeEndpoint" not in current_actions
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.AGENTCORE_HARNESS_691_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.AGENTCORE_HARNESS_691_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current" and ident in previous
    previous_actions = {req["action"] for req in previous[ident]["requires"]["all_of"]}
    assert "bedrock-agentcore:CreateAgentRuntimeEndpoint" in previous_actions
    assert len(catalog._verified_agentcore_harness_691_previous()) == 691


def test_sagemaker_jobs_binding_preserves_previous_catalog():
    ids = ("aws-sagemaker-passrole-createprocessingjob",
           "aws-sagemaker-passrole-createtrainingjob",
           "aws-sagemaker-passrole-createhyperparametertuningjob")
    current, status = catalog.lookup_entries(ids, catalog.current_binding())
    assert status == "exact_strict_privesc" and set(current) == set(ids)
    for ident in ids:
        requirements = current[ident]["requires"]["all_of"]
        assert next(req for req in requirements if req["action"] == "iam:PassRole")[
            "request_context"] == {"iam:PassedToService": "sagemaker.amazonaws.com"}
        assert next(req for req in requirements if req["action"].startswith("sagemaker:Create"))[
            "resource"].startswith("arn:{source.partition}:sagemaker:")
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.SAGEMAKER_JOBS_691_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.SAGEMAKER_JOBS_691_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries(ids, old)
    assert status == "exact_previous_current" and set(previous) == set(ids)
    assert all(next(req for req in previous[ident]["requires"]["all_of"]
                    if req["action"].startswith("sagemaker:Create"))["resource"] == "*"
               for ident in ids)
    assert len(catalog._verified_sagemaker_jobs_691_previous()) == 691


def test_sagemaker_processing_binding_preserves_previous_route():
    ident = "aws-sagemaker-passrole-createprocessingjob"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc"
    assert current[ident]["preconditions"] == ["sagemaker_processing_inline_entrypoint_route"]
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.SAGEMAKER_PROCESSING_691_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.SAGEMAKER_PROCESSING_691_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current"
    assert previous[ident]["preconditions"] == ["sagemaker_job_execution_route_unverified"]
    assert len(catalog._verified_sagemaker_processing_691_previous()) == 691


def test_sagemaker_training_binding_preserves_previous_route():
    ident = "aws-sagemaker-passrole-createtrainingjob"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc"
    assert current[ident]["preconditions"] == ["sagemaker_training_inline_entrypoint_route"]
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.SAGEMAKER_TRAINING_691_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.SAGEMAKER_TRAINING_691_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current"
    assert previous[ident]["preconditions"] == ["sagemaker_job_execution_route_unverified"]
    assert len(catalog._verified_sagemaker_training_691_previous()) == 691


def test_sagemaker_hpo_binding_preserves_previous_route():
    ident = "aws-sagemaker-passrole-createhyperparametertuningjob"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc"
    assert current[ident]["preconditions"] == ["sagemaker_hpo_script_mode_route"]
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.SAGEMAKER_HPO_691_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.SAGEMAKER_HPO_691_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current"
    assert previous[ident]["preconditions"] == ["sagemaker_job_execution_route_unverified"]
    assert len(catalog._verified_sagemaker_hpo_691_previous()) == 691


def test_deadline_queue_binding_preserves_previous_catalog():
    ident = "aws-deadline-existing-queue-role-vend"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc" and set(current) == {ident}
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.DEADLINE_QUEUE_683_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.DEADLINE_QUEUE_683_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current" and previous == {}
    assert len(catalog._verified_deadline_queue_683_previous()) == 683


def test_deadline_fleet_scope_correction_preserves_previous_catalog():
    ident = "aws-deadline-passrole-fleet-createworker"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc"
    assert current[ident]["preconditions"] == ["deadline_fleet_worker_bounded_authority_reviewed"]
    assert current[ident]["target"]["kind"] == "aws_verified_authority"
    assert current[ident]["severity"] == "high"
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.DEADLINE_FLEET_684_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.DEADLINE_FLEET_684_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current"
    assert "preconditions" not in previous[ident]


def test_deadline_worker_authority_correction_preserves_previous_catalog():
    ident = "aws-deadline-passrole-fleet-createworker"
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.DEADLINE_FLEET_WORKER_691_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.DEADLINE_FLEET_WORKER_691_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current"
    assert previous[ident]["target"]["kind"] == "aws_role"
    assert previous[ident]["preconditions"] == ["deadline_fleet_worker_binding_unverified"]


def test_devicefarm_existing_spec_correction_preserves_previous_catalog():
    ident = "aws-devicefarm-schedulerun-existing-test-spec-passrole"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc"
    assert current[ident]["preconditions"] == ["devicefarm_existing_test_spec_role_effect_reviewed"]
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.DEVICEFARM_EXISTING_SPEC_691_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.DEVICEFARM_EXISTING_SPEC_691_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current"
    assert previous[ident]["requires"]["all_of"][0]["resource"] == "*"


def test_asg_role_execution_correction_preserves_previous_catalog():
    ident = "aws-ec2-autoscaling-create-update-asg-passrole"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc"
    assert current[ident]["preconditions"] == ["autoscaling_created_launch_input_role_effect_reviewed"]
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.ASG_ROLE_EXECUTION_691_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.ASG_ROLE_EXECUTION_691_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current"
    assert previous[ident]["requires"]["all_of"][0]["action"] == "iam:PassRole"


def test_spot_fleet_role_execution_correction_preserves_previous_catalog():
    ident = "aws-ec2-passrole-requestspotfleet"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc"
    assert current[ident]["preconditions"] == ["ec2_spot_fleet_instance_role_effect_reviewed"]
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.SPOT_FLEET_ROLE_EXECUTION_691_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.SPOT_FLEET_ROLE_EXECUTION_691_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current"
    assert previous[ident]["preconditions"] == ["ec2_spot_fleet_roles_ready"]


def test_deadline_existing_worker_binding_preserves_previous_catalog():
    ident = "aws-deadline-existing-worker-role-vend"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc" and set(current) == {ident}
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.DEADLINE_WORKER_684_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.DEADLINE_WORKER_684_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current" and previous == {}
    assert len(catalog._verified_deadline_worker_684_previous()) == 684


def test_deadline_new_worker_binding_preserves_previous_catalog():
    ident = "aws-deadline-new-worker-existing-fleet-role-vend"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc" and set(current) == {ident}
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.DEADLINE_NEW_WORKER_685_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.DEADLINE_NEW_WORKER_685_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current" and previous == {}
    assert len(catalog._verified_deadline_new_worker_685_previous()) == 685


def test_deadline_worker_dependency_binding_preserves_previous_catalog():
    ident = "aws-deadline-new-worker-existing-fleet-role-vend"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc"
    assert "dependent permissions" in current[ident]["summary"]
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.DEADLINE_DEPENDENCIES_686_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.DEADLINE_DEPENDENCIES_686_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current"
    assert "dependent permissions" not in previous[ident]["summary"]
    assert len(catalog._verified_deadline_dependencies_686_previous()) == 686


def test_cloudfront_creation_binding_retains_previous_update_only_catalog():
    ident = "aws-cloudfront-lambda-edge-passrole"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc"
    assert "new or existing distribution" in current[ident]["title"]
    previous_binding = {"schema": catalog.BINDING_SCHEMA,
                        "manifest_sha256": catalog.CLOUDFRONT_CREATE_683_PREVIOUS_MANIFEST,
                        "effective_tree_sha256": catalog.CLOUDFRONT_CREATE_683_PREVIOUS_TREE,
                        "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], previous_binding)
    assert status == "exact_previous_current"
    assert previous[ident]["title"] == "Associate a new Lambda@Edge function with a passed role to a distribution"
    assert len(catalog._verified_cloudfront_create_683_previous()) == 683


def test_intermediate_strict_binding_uses_retained_660_entry_catalog():
    binding = {"schema": catalog.BINDING_SCHEMA,
               "manifest_sha256": catalog.INTERMEDIATE_CURRENT_MANIFEST,
               "effective_tree_sha256": catalog.INTERMEDIATE_CURRENT_TREE,
               "source_revision": catalog.V4_REVISION}
    entries, status = catalog.lookup_entries(
        ["aws-emr-addjobflowsteps", "aws-flink-studio-presigned-url"], binding)
    assert status == "exact_previous_current"
    assert set(entries) == {"aws-emr-addjobflowsteps"}
    assert len(catalog._verified_intermediate_current()) == 660


def test_previous_strict_binding_uses_retained_633_entry_catalog():
    binding = {"schema": catalog.BINDING_SCHEMA,
               "manifest_sha256": catalog.PREVIOUS_CURRENT_MANIFEST,
               "effective_tree_sha256": catalog.PREVIOUS_CURRENT_TREE,
               "source_revision": catalog.V4_REVISION}
    entries, status = catalog.lookup_entries(
        ["aws-emr-passrole-runjobflow", "aws-emr-addjobflowsteps"], binding)
    assert status == "exact_previous_current"
    assert set(entries) == {"aws-emr-passrole-runjobflow"}
    assert len(catalog._verified_previous_current()) == 633


def test_quicksight_self_promotion_binding_preserves_scheduler_catalog():
    ident = "aws-quicksight-updateuser-admin"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc" and set(current) == {ident}
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.SCHEDULER_UPDATE_687_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.SCHEDULER_UPDATE_687_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident, "aws-scheduler-passrole-updateschedule-self-grant"], old)
    assert status == "exact_previous_current"
    assert set(previous) == {"aws-scheduler-passrole-updateschedule-self-grant"}
    assert len(catalog._verified_scheduler_update_687_previous()) == 687


def test_azure_and_kubernetes_finding_explanations_load():
    for provider in ("azure", "k8s"):
        for confidence in ("derived", "conditional", "unknown"):
            text = evidence_summary(admin_projected(provider, confidence))
            assert text and len(text.splitlines()) == 3
