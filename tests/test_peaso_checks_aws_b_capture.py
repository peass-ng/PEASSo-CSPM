"""Regressions for native API spellings and proven optional-field omissions."""
import copy
import pytest
from peaso.checks import CHECKS
from peaso.checks import aws_b_core, aws_b_loadbalancing, aws_b_compute


def check(cid):
    return next(c for c in CHECKS if c.id == cid)


@pytest.mark.parametrize("algorithm,status", [("RSA-1024", "FAIL"), ("RSA_1024", "FAIL"),
    ("RSA-2048", "PASS"), ("RSA_2048", "PASS"), ("RSA-3072", "PASS"), ("RSA_3072", "PASS"),
    ("RSA-4096", "PASS"), ("RSA_4096", "PASS"), ("RSA-8192", "UNKNOWN"),
    ("EC_prime256v1", "NOT_APPLICABLE"), ("invented", "UNKNOWN")])
def test_acm_native_cli_spelling_and_enum_reference_without_fact_rewriting(algorithm, status):
    data = {"Certificate": {"collection_status": "collected", "Certificate": {"KeyAlgorithm": algorithm}}}
    before = copy.deepcopy(data)
    verdict, evidence = check("aws.b.acm.rsa_minimum_2048").evaluate(data, {})
    assert verdict == status
    assert data == before
    assert evidence["key_algorithm"] == algorithm


def test_lambda_missing_layers_requires_successful_detail_and_function_identity():
    c = check("aws.b.lambda.insights_layer")
    assert c.evaluate({"Configuration": {"collection_status": "collected", "FunctionName": "fixture"}}, {})[0] == "FAIL"
    for configuration in ({}, {"FunctionName": "fixture"}, {"collection_status": "collected"},
                          {"collection_status": "denied", "FunctionName": "fixture"},
                          {"collection_status": "collected", "FunctionName": "fixture", "_coverage": {"Layers": {"status": "denied"}}},
                          {"collection_status": "collected", "FunctionName": "fixture", "Layers": None}):
        assert c.evaluate({"Configuration": configuration}, {})[0] == "UNKNOWN"


def test_ecs_inherited_image_user_remains_unknown_and_explicit_root_fails():
    c = check("aws.b.ecs.declared_nonroot_users")
    base = {"Definition": {"collection_status": "collected", "taskDefinition": {"runtimePlatform": {"operatingSystemFamily": "LINUX"}, "containerDefinitions": [{"name": "fixture"}]}}}
    assert c.evaluate(base, {})[0] == "UNKNOWN"
    base["Definition"]["taskDefinition"]["containerDefinitions"][0]["user"] = "0"
    assert c.evaluate(base, {})[0] == "FAIL"
    base["Definition"]["taskDefinition"]["containerDefinitions"][0]["user"] = "1000"
    assert c.evaluate(base, {})[0] == "PASS"


@pytest.mark.parametrize("field,cid,value", [
    ("privileged", "aws.b.ecs.no_privileged_containers", False),
    ("readonlyRootFilesystem", "aws.b.ecs.all_readonly_roots", True),
    ("user", "aws.b.ecs.declared_nonroot_users", "1000"),
    ("logConfiguration", "aws.b.ecs.some_logging_configuration", {"logDriver": "awslogs"}),
])
def test_explicit_container_field_denial_cannot_be_ignored_by_optional_defaults(field, cid, value):
    row = {"name": "fixture", field: value, "_coverage": {field: {"status": "denied"}}}
    data = {"Definition": {"taskDefinition": {"runtimePlatform": {"operatingSystemFamily": "LINUX"}, "containerDefinitions": [row]}}}
    assert check(cid).evaluate(data, {})[0] == "UNKNOWN"


@pytest.mark.parametrize("user,expected", [("00", "FAIL"), ("0000:1000", "FAIL"), (":1000", "UNKNOWN"), ("1000:1000:1000", "UNKNOWN")])
def test_declared_numeric_uid_zero_and_malformed_user_formats(user, expected):
    data = {"Definition": {"taskDefinition": {"runtimePlatform": {"operatingSystemFamily": "LINUX"}, "containerDefinitions": [{"name": "fixture", "user": user}]}}}
    assert check("aws.b.ecs.declared_nonroot_users").evaluate(data, {})[0] == expected


@pytest.mark.parametrize("user,expected", [
    (None, "UNKNOWN"), ("root", "FAIL"), ("root:1000", "FAIL"),
    ("0", "FAIL"), ("00:1000", "FAIL"), ("root:2147483648", "FAIL"), ("1000", "PASS"),
    ("1000:root", "PASS"), ("2147483647", "PASS"),
    ("appuser", "UNKNOWN"), ("appuser:1000", "UNKNOWN"),
    (":1000", "UNKNOWN"), ("1000:", "UNKNOWN"),
    ("1000:1000:1000", "UNKNOWN"), ("2147483648", "UNKNOWN"),
    ("999999999999999999999999999999", "UNKNOWN"),
    ("1000:2147483648", "UNKNOWN"), ("1000:-1", "UNKNOWN"),
])
def test_ecs_user_uid_proof_registered_callback(user, expected):
    # An image may map appuser to UID 0; a declared name cannot prove non-root.
    row = {"name": "fixture"}
    if user is not None:
        row["user"] = user
    data = {"Definition": {"collection_status": "collected",
                           "taskDefinition": {"runtimePlatform": {"operatingSystemFamily": "LINUX"}, "containerDefinitions": [row]}}}
    status, evidence = check("aws.b.ecs.declared_nonroot_users").evaluate(data, {})
    assert status == expected
    if user == "appuser":
        assert evidence["unresolved_named_users"] == ["fixture"]


def test_ecs_explicit_root_still_fails_with_unresolved_sibling():
    data = {"Definition": {"collection_status": "collected",
                           "taskDefinition": {"runtimePlatform": {"operatingSystemFamily": "LINUX"}, "containerDefinitions": [
                               {"name": "unknown", "user": "appuser"},
                               {"name": "root", "user": "0"}]}}}
    assert check("aws.b.ecs.declared_nonroot_users").evaluate(data, {})[0] == "FAIL"


@pytest.mark.parametrize("user,os_family,expected", [
    ("appuser", None, "UNKNOWN"), ("1000:root", None, "PASS"), ("0", None, "FAIL"),
    ("1000", "LINUX", "PASS"), ("0", "LINUX", "FAIL"),
    ("1000", "WINDOWS_SERVER_2022_CORE", "UNKNOWN"),
    ("0", "WINDOWS_SERVER_2022_CORE", "UNKNOWN")])
def test_ecs_uid_proof_through_aws_collector_and_engine(monkeypatch, user, os_family, expected):
    import boto3
    from botocore.stub import Stubber
    from peaso.collectors import aws
    from peaso.engine import evaluate_snapshot

    account, region = "123456789012", "us-east-1"
    arn = f"arn:aws:ecs:{region}:{account}:task-definition/uid-proof:1"
    session = boto3.Session(aws_access_key_id="fixture", aws_secret_access_key="fixture",
                           region_name=region)
    sts, ecs = session.client("sts"), session.client("ecs")
    with Stubber(sts) as sts_stub, Stubber(ecs) as ecs_stub:
        sts_stub.add_response("get_caller_identity", {"Account": account,
            "Arn": f"arn:aws:iam::{account}:user/reviewer", "UserId": "AIDAREVIEWER"}, {})
        ecs_stub.add_response("list_task_definitions", {"taskDefinitionArns": [arn]}, {})
        definition = {"taskDefinitionArn": arn, "status": "ACTIVE", "networkMode": "host",
                      "containerDefinitions": [{"name": "app", "privileged": False, "user": user}]}
        if os_family is not None:
            definition["runtimePlatform"] = {"operatingSystemFamily": os_family}
        ecs_stub.add_response("describe_task_definition", {"taskDefinition": definition},
                              {"taskDefinition": arn})
        clients = {("sts", region): sts, ("ecs", region): ecs}
        monkeypatch.setattr(aws.Requests, "client",
                            lambda self, _session, service, requested_region: clients[(service, requested_region)])
        monkeypatch.setattr(aws, "_session", lambda auth, requested_region: (session, "fixture"))
        snapshot = aws.collect({"provider": "aws", "scopes": [account],
            "auth": {"profile": "fixture"}, "options": {"regions": [region],
            "service_concurrency": 1, "scope_concurrency": 1}}, ["ecs_task_definition"])
        sts_stub.assert_no_pending_responses()
        ecs_stub.assert_no_pending_responses()
    ids = ["aws.b.ecs.declared_nonroot_users", "aws.b.ecs.host_network_nonprivileged"]
    report = evaluate_snapshot(snapshot, checks=ids)
    findings = {row["check_id"]: row["status"] for row in report["findings"]
                if row["resource_id"] != "inventory:ecs_task_definition"}
    assert findings == dict.fromkeys(ids, expected)


@pytest.mark.parametrize("privileged,user,expected", [
    (False, "appuser", "UNKNOWN"), (False, "1000:root", "PASS"),
    (False, "0", "FAIL"), (True, "appuser", "FAIL"),
    ("unresolved", "0", "FAIL")])
def test_host_network_uid_and_privilege_failure_precedence(privileged, user, expected):
    data = {"Definition": {"collection_status": "collected", "taskDefinition": {
        "runtimePlatform": {"operatingSystemFamily": "LINUX"}, "networkMode": "host", "containerDefinitions": [
            {"name": "fixture", "privileged": privileged, "user": user}]}}}
    assert check("aws.b.ecs.host_network_nonprivileged").evaluate(data, {})[0] == expected


@pytest.mark.parametrize("os_family,user,expected", [
    ("LINUX", "1000", "PASS"), ("LINUX", "0", "FAIL"),
    ("WINDOWS_SERVER_2022_CORE", "1000", "UNKNOWN"),
    ("WINDOWS_SERVER_2022_CORE", "0", "UNKNOWN"),
    ("INVALID_OS", "1000", "UNKNOWN")])
def test_ecs_registered_uid_os_scope(os_family, user, expected):
    definition = {"runtimePlatform": {"operatingSystemFamily": os_family},
                  "networkMode": "host", "containerDefinitions": [
                      {"name": "fixture", "privileged": False, "user": user}]}
    data = {"Definition": {"collection_status": "collected", "taskDefinition": definition}}
    for check_id in ("aws.b.ecs.declared_nonroot_users", "aws.b.ecs.host_network_nonprivileged"):
        assert check(check_id).evaluate(data, {})[0] == expected


def test_ecs_linux_default_needs_successful_matching_native_identity():
    arn = "arn:aws:ecs:us-east-1:123456789012:task-definition/uid-proof:1"
    definition = {"taskDefinitionArn": arn, "networkMode": "host",
                  "containerDefinitions": [{"name": "fixture", "privileged": False, "user": "1000"}]}
    item = {"taskDefinitionArn": arn, "Definition": {"collection_status": "collected",
            "taskDefinition": definition}}
    for check_id in ("aws.b.ecs.declared_nonroot_users", "aws.b.ecs.host_network_nonprivileged"):
        status, evidence = check(check_id).evaluate(item, {})
        assert status == "PASS"
        assert evidence["operating_system_evidence"] == "documented default on successful ARN-bound DescribeTaskDefinition"
        for altered in ({"Definition": item["Definition"]},
                        {"taskDefinitionArn": arn + "-mismatch", "Definition": item["Definition"]},
                        {"taskDefinitionArn": "arn:aws:s3:::fake", "Definition": {"collection_status": "collected",
                            "taskDefinition": {**definition, "taskDefinitionArn": "arn:aws:s3:::fake"}}},
                        {"taskDefinitionArn": arn, "Definition": {"taskDefinition": definition}}):
            assert check(check_id).evaluate(altered, {})[0] == "UNKNOWN"


def test_ecs_description_overlay_requires_numeric_nonzero_uid():
    from peaso.checks.catalog import description_for
    corrected = description_for("aws.b.ecs.declared_nonroot_users")
    assert "valid nonzero numeric UID" in corrected["pass_when"]


def test_codebuild_identity_denial_cannot_prove_optional_encryption_defaults():
    data = {"Configuration": {"collection_status": "collected", "projects": [{"name": "fixture", "_coverage": {"name": {"status": "denied"}}, "artifacts": {"type": "S3"}}]}}
    assert check("aws.b.codebuild.s3_artifact_encryption").evaluate(data, {})[0] == "UNKNOWN"


@pytest.mark.parametrize("kind", ["NO_ARTIFACTS", "CODEPIPELINE"])
def test_codebuild_non_s3_type_is_na_only_in_separate_defensive_variant(kind):
    data = {"Configuration": {"collection_status": "collected", "projects": [{"name": "fixture", "artifacts": {"type": kind}}]}}
    assert check("aws.b.codebuild.s3_artifact_encryption").evaluate(data, {})[0] == "NOT_APPLICABLE"
    assert check("aws.b.codebuild.artifact_encryption").evaluate(data, {})[0] == "FAIL"


def test_codebuild_s3_default_requires_positive_native_success_and_identity():
    c = check("aws.b.codebuild.s3_artifact_encryption")
    project = {"name": "fixture", "artifacts": {"type": "S3"}}
    data = {"Configuration": {"collection_status": "collected", "projects": [project]}}
    assert c.evaluate(data, {})[0] == "PASS"
    data["Configuration"].pop("collection_status")
    assert c.evaluate(data, {})[0] == "UNKNOWN"
    data["Configuration"]["collection_status"] = "denied"
    assert c.evaluate(data, {})[0] == "UNKNOWN"


def test_codebuild_secondary_s3_failure_survives_non_s3_primary_and_missing_fields():
    c = check("aws.b.codebuild.s3_artifact_encryption")
    project = {"name": "fixture", "artifacts": {"type": "NO_ARTIFACTS"}, "secondaryArtifacts": [{"type": "S3", "encryptionDisabled": True}]}
    data = {"Configuration": {"collection_status": "collected", "projects": [project]}}
    assert c.evaluate(data, {})[0] == "FAIL"
    project["secondaryArtifacts"][0]["encryptionDisabled"] = "false"
    assert c.evaluate(data, {})[0] == "UNKNOWN"
    project["secondaryArtifacts"] = [{"type": "S3", "_coverage": {"encryptionDisabled": {"status": "denied"}}}]
    assert c.evaluate(data, {})[0] == "UNKNOWN"


def test_codebuild_literal_secondary_absence_matches_source_true_only_condition():
    data = {"Configuration": {"collection_status": "collected", "projects": [{"name": "fixture", "artifacts": {"type": "S3", "encryptionDisabled": False}, "secondaryArtifacts": [{"type": "S3"}]}]}}
    assert check("aws.b.codebuild.artifact_encryption").evaluate(data, {})[0] == "PASS"
    data["Configuration"]["projects"][0]["secondaryArtifacts"][0]["encryptionDisabled"] = True
    assert check("aws.b.codebuild.artifact_encryption").evaluate(data, {})[0] == "FAIL"


@pytest.mark.parametrize("cid", ["aws.b.ecs.no_privileged_containers", "aws.b.ecs.host_network_nonprivileged"])
@pytest.mark.parametrize("unreadable", [{"privileged": "true"}, {"privileged": None},
                                      {"_coverage": {"privileged": {"status": "denied"}}}])
@pytest.mark.parametrize("reverse", [False, True])
def test_ecs_privileged_witness_survives_unreadable_peer(cid, unreadable, reverse):
    peer = {"name": "unreadable", "user": "1000", **copy.deepcopy(unreadable)}
    rows = [peer, {"name": "unsafe", "user": "1000", "privileged": True}]
    definition = {"runtimePlatform": {"operatingSystemFamily": "LINUX"}, "networkMode": "host",
                  "containerDefinitions": list(reversed(rows)) if reverse else rows}
    assert check(cid).evaluate({"Definition": {"taskDefinition": definition}}, {})[0] == "FAIL"
    definition["containerDefinitions"] = [peer]
    assert check(cid).evaluate({"Definition": {"taskDefinition": definition}}, {})[0] == "UNKNOWN"
