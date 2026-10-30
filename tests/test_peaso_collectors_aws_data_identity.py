"""Data, analytics, identity and devtools collector facts: read-only, secret-free, never empty on failure."""
import datetime
import json

import pytest

boto3 = pytest.importorskip("boto3")
from botocore.stub import Stubber

from peaso.checks import evaluate_check
from peaso.collectors import aws
from peaso.collectors import aws_facts_data_identity as facts

REGION = "us-east-1"
ACCOUNT = "123456789012"
NOW = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
VAULT_ARN = f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-vault:v1"
PUBLIC = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "backup:*", "Resource": "*"}]})


@pytest.fixture
def sdk(monkeypatch):
    session = boto3.Session(aws_access_key_id="inert", aws_secret_access_key="inert", region_name=REGION)
    clients, stubs = {}, {}
    def add(service):
        if service not in clients:
            clients[service] = session.client(service, region_name=REGION)
            stubs[service] = Stubber(clients[service])
            stubs[service].activate()
        return stubs[service]
    monkeypatch.setattr(aws.Requests, "client", lambda requests, context, service, region: clients[service])
    yield session, add
    for stub in stubs.values():
        stub.assert_no_pending_responses()
        stub.deactivate()


def status(check_id, item, index=None):
    return evaluate_check(check_id, item, index)[0]


def test_extension_is_loaded_read_only_and_does_not_replace_specs():
    for kind, spec in facts.SPECS.items():
        assert aws.SPECS[kind] == spec
    assert "iam_service_specific_credential" in aws.GLOBAL_TYPES
    assert all(op.startswith(("get_", "list_", "describe_", "batch_get_")) for _, op in facts.READ_ACTIONS)
    assert ("docdb", "describe_db_cluster_parameters") in aws.READ_ACTIONS
    assert aws.SPECS["dlm_lifecycle_policy"] == aws.SPECS["dlm_policy"]


def test_backup_vault_policy_absent_public_and_denied(sdk):
    session, add = sdk
    backup = add("backup")
    backup.add_response("get_backup_vault_access_policy", {"BackupVaultName": "v1", "BackupVaultArn": VAULT_ARN, "Policy": PUBLIC}, {"BackupVaultName": "v1"})
    backup.add_client_error("get_backup_vault_access_policy", "ResourceNotFoundException", expected_params={"BackupVaultName": "v2"})
    backup.add_client_error("get_backup_vault_access_policy", "AccessDeniedException", expected_params={"BackupVaultName": "v3"})
    items = [{"BackupVaultName": name, "BackupVaultArn": VAULT_ARN} for name in ("v1", "v2", "v3")]
    public, missing, denied = facts.ENRICHERS["backup_vault"](aws.Requests({}), session, REGION, items)
    assert missing["Policy"] == {"collection_status": "empty", "absent": True, "error": {"code": "ResourceNotFoundException"}}
    assert denied["Policy"]["collection_status"] == "denied"
    unknown = dict(public, Policy={"collection_status": "denied", "error": {"code": "AccessDenied"}})
    assert status("aws.c2b.backup.vault_policy_not_public", unknown) == "UNKNOWN"
    assert status("aws.c2b.backup.vault_policy_not_public", public) == "FAIL"
    assert status("aws.c2b.backup.vault_policy_not_public", missing) == "PASS"
    assert status("aws.c2b.backup.vault_policy_not_public", denied) == "UNKNOWN"


def test_chained_backup_enricher_reuses_cached_failure(sdk):
    session, add = sdk
    backup = add("backup")
    backup.add_response("describe_backup_vault", {"BackupVaultName": "v1", "BackupVaultArn": VAULT_ARN}, {"BackupVaultName": "v1"})
    backup.add_client_error("get_backup_vault_access_policy", "ResourceNotFoundException", expected_params={"BackupVaultName": "v1"})
    backup.add_client_error("get_backup_vault_notifications", "ResourceNotFoundException", expected_params={"BackupVaultName": "v1"})
    requests = aws.Requests({})
    [item] = aws.ENRICHERS["backup_vault"](requests, session, REGION, [{"BackupVaultName": "v1", "BackupVaultArn": VAULT_ARN}])
    assert item["Policy"]["absent"] is True
    assert item["Notifications"]["absent"] is True
    assert requests.calls == 3


def test_recovery_points_paginate_every_vault(sdk):
    session, add = sdk
    backup = add("backup")
    backup.add_response("list_backup_vaults", {"BackupVaultList": [{"BackupVaultName": "v1", "BackupVaultArn": VAULT_ARN}]}, {})
    rp = {"RecoveryPointArn": "arn:rp1", "BackupVaultName": "v1", "IsEncrypted": False, "Lifecycle": {"DeleteAfterDays": 7}}
    backup.add_response("list_recovery_points_by_backup_vault", {"RecoveryPoints": [rp], "NextToken": "n"}, {"BackupVaultName": "v1"})
    backup.add_response("list_recovery_points_by_backup_vault", {"RecoveryPoints": [dict(rp, RecoveryPointArn="arn:rp2", IsEncrypted=True)]},
        {"BackupVaultName": "v1", "NextToken": "n"})
    read = facts.FETCHERS["backup_recovery_point"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "collected" and [i["RecoveryPointArn"] for i in read.items] == ["arn:rp1", "arn:rp2"]
    assert status("aws.c2b.backup.recovery_point_encrypted", read.items[0]) == "FAIL"
    assert status("aws.c2b.backup.recovery_point_encrypted", read.items[1]) == "PASS"


def test_recovery_points_denied_vault_list_is_denied_not_empty(sdk):
    session, add = sdk
    add("backup").add_client_error("list_backup_vaults", "AccessDeniedException")
    read = facts.FETCHERS["backup_recovery_point"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "denied" and read.items == []


def test_efs_backup_policy_absent_marker(sdk):
    session, add = sdk
    efs = add("efs")
    efs.add_client_error("describe_backup_policy", "PolicyNotFound", expected_params={"FileSystemId": "fs-1"})
    efs.add_client_error("describe_file_system_policy", "PolicyNotFound", expected_params={"FileSystemId": "fs-1"})
    efs.add_response("describe_backup_policy", {"BackupPolicy": {"Status": "ENABLED"}}, {"FileSystemId": "fs-2"})
    efs.add_client_error("describe_file_system_policy", "AccessDeniedException", expected_params={"FileSystemId": "fs-2"})
    missing, enabled = facts.ENRICHERS["efs_file_system"](aws.Requests({}), session, REGION, [{"FileSystemId": "fs-1"}, {"FileSystemId": "fs-2"}])
    assert missing["BackupPolicy"]["absent"] is True and missing["Policy"]["absent"] is True
    assert enabled["Policy"]["collection_status"] == "denied"
    assert status("aws.c2b.efs.backup_not_disabled", dict(missing, BackupPolicy={"collection_status": "unknown"})) == "UNKNOWN"
    assert status("aws.c2b.efs.backup_not_disabled", missing) == "FAIL"
    assert status("aws.c2b.efs.backup_not_disabled", enabled) == "PASS"


def test_efs_mount_targets_per_file_system(sdk):
    session, add = sdk
    efs = add("efs")
    efs.add_response("describe_file_systems", {"FileSystems": [{"FileSystemId": "fs-1", "CreationToken": "t", "OwnerId": ACCOUNT, "CreationTime": NOW,
        "LifeCycleState": "available", "NumberOfMountTargets": 1, "SizeInBytes": {"Value": 1}, "PerformanceMode": "generalPurpose", "Tags": []}]}, {})
    efs.add_response("describe_mount_targets", {"MountTargets": [{"MountTargetId": "fsmt-0123456789", "FileSystemId": "fs-1", "SubnetId": "subnet-0123456789", "LifeCycleState": "available"}]},
        {"FileSystemId": "fs-1"})
    efs.add_response("describe_mount_target_security_groups", {"SecurityGroups": ["sg-0123456789"]}, {"MountTargetId": "fsmt-0123456789"})
    read = facts.FETCHERS["efs_mount_target"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "collected" and read.items == [{"MountTargetId": "fsmt-0123456789", "FileSystemId": "fs-1", "SubnetId": "subnet-0123456789", "LifeCycleState": "available", "SecurityGroups": ["sg-0123456789"]}]


def test_dynamodb_resource_policy_absent_and_tags(sdk):
    session, add = sdk
    arn = f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/t"
    dynamodb = add("dynamodb")
    dynamodb.add_client_error("get_resource_policy", "PolicyNotFoundException", expected_params={"ResourceArn": arn})
    dynamodb.add_response("list_tags_of_resource", {"Tags": [{"Key": "backup", "Value": "daily"}], "NextToken": "n"}, {"ResourceArn": arn})
    dynamodb.add_response("list_tags_of_resource", {"Tags": [{"Key": "env", "Value": "prod"}]}, {"ResourceArn": arn, "NextToken": "n"})
    [item] = facts.ENRICHERS["dynamodb_table"](aws.Requests({}), session, REGION, [{"TableName": "t", "Table": {"collection_status": "collected", "Table": {"TableArn": arn}}}])
    assert item["ResourcePolicy"]["absent"] is True
    assert item["Tags"]["collection_status"] == "collected" and len(item["Tags"]["items"]) == 2
    [bad] = facts.ENRICHERS["dynamodb_table"](aws.Requests({}), session, REGION, [{"TableName": "t", "Table": {"collection_status": "denied"}}])
    assert bad["ResourcePolicy"]["collection_status"] == bad["Tags"]["collection_status"] == "not_collected"


def test_firehose_manual_pagination_strips_destinations(sdk):
    session, add = sdk
    firehose = add("firehose")
    firehose.add_response("list_delivery_streams", {"DeliveryStreamNames": ["a"], "HasMoreDeliveryStreams": True}, {"Limit": 100})
    firehose.add_response("list_delivery_streams", {"DeliveryStreamNames": ["b"], "HasMoreDeliveryStreams": False}, {"Limit": 100, "ExclusiveStartDeliveryStreamName": "a"})
    def description(name, enc):
        return {"DeliveryStreamDescription": {"DeliveryStreamName": name, "DeliveryStreamARN": "arn:" + name, "DeliveryStreamStatus": "ACTIVE",
            "DeliveryStreamType": "DirectPut", "VersionId": "1", "HasMoreDestinations": False, "DeliveryStreamEncryptionConfiguration": {"Status": enc},
            "Destinations": [{"DestinationId": "d", "SplunkDestinationDescription": {"HECToken": "secret-token"}}]}}
    firehose.add_response("describe_delivery_stream", description("a", "ENABLED"), {"DeliveryStreamName": "a"})
    firehose.add_response("describe_delivery_stream", description("b", "DISABLED"), {"DeliveryStreamName": "b"})
    read = facts.FETCHERS["firehose_delivery_stream"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "collected" and "secret-token" not in json.dumps(read.items)
    # Destinations keep routing facts only (type, ids, hosts/ARNs); HEC tokens,
    # keys and users from the native description are never persisted.
    for item in read.items:
        assert item["DestinationsComplete"] is True
        assert item["Destinations"] == [{"DestinationId": "d", "Type": "SplunkDestinationDescription", "BucketARNs": [],
                                         "EndpointHosts": [], "TargetARNs": [], "LambdaProcessing": False}]
    assert status("aws.cb.firehose.server_side_encryption", read.items[0]) == "PASS"
    assert status("aws.cb.firehose.server_side_encryption", read.items[1]) == "FAIL"
    assert status("aws.c2b.firehose.encrypted_at_rest_or_msk_source", read.items[1]) == "FAIL"


def test_firehose_denied_and_describe_failure(sdk):
    session, add = sdk
    firehose = add("firehose")
    firehose.add_client_error("list_delivery_streams", "AccessDeniedException")
    assert facts.FETCHERS["firehose_delivery_stream"](aws.Requests({}), session, REGION, ACCOUNT).status == "denied"
    firehose.add_response("list_delivery_streams", {"DeliveryStreamNames": ["a"], "HasMoreDeliveryStreams": False}, {"Limit": 100})
    firehose.add_client_error("describe_delivery_stream", "AccessDeniedException", expected_params={"DeliveryStreamName": "a"})
    read = facts.FETCHERS["firehose_delivery_stream"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "partial" and read.items[0]["collection_status"] == "denied"
    assert status("aws.cb.firehose.server_side_encryption", read.items[0]) == "UNKNOWN"


def test_firehose_empty(sdk):
    session, add = sdk
    add("firehose").add_response("list_delivery_streams", {"DeliveryStreamNames": [], "HasMoreDeliveryStreams": False}, {"Limit": 100})
    assert facts.FETCHERS["firehose_delivery_stream"](aws.Requests({}), session, REGION, ACCOUNT).status == "empty"


def test_codebuild_env_names_types_only_and_latest_builds(sdk):
    session, add = sdk
    codebuild = add("codebuild")
    project = {"name": "proj", "arn": "arn:p", "environment": {"type": "LINUX_CONTAINER", "image": "i", "computeType": "BUILD_GENERAL1_SMALL",
        "environmentVariables": [{"name": "AWS_SECRET_ACCESS_KEY", "value": "super-secret", "type": "PLAINTEXT"}]}}
    codebuild.add_response("batch_get_projects", {"projects": [project]}, {"names": ["proj"]})
    codebuild.add_response("list_builds_for_project", {"ids": ["proj:2", "proj:1"]}, {"projectName": "proj", "sortOrder": "DESCENDING"})
    codebuild.add_response("batch_get_builds", {"builds": [{"id": "proj:1", "buildStatus": "SUCCEEDED"}, {"id": "proj:2", "buildStatus": "FAILED"}]}, {"ids": ["proj:2", "proj:1"]})
    requests = aws.Requests({})
    [item] = aws.ENRICHERS["codebuild_project"](requests, session, REGION, [{"name": "proj"}])
    assert "super-secret" not in json.dumps(item, default=str)
    assert item["Configuration"]["projects"][0]["environment"]["environmentVariables"] == [{"name": "AWS_SECRET_ACCESS_KEY", "type": "PLAINTEXT"}]
    assert [b["id"] for b in item["Builds"]["items"]] == ["proj:2", "proj:1"]
    assert status("aws.c2b.codebuild.no_plaintext_sensitive_env_names", item) == "FAIL"
    assert status("aws.c2b.codebuild.no_plaintext_sensitive_env_names", dict(item, Configuration={"collection_status": "denied"})) == "UNKNOWN"


def test_codebuild_builds_denied_is_not_empty(sdk):
    session, add = sdk
    add("codebuild").add_client_error("list_builds_for_project", "AccessDeniedException", expected_params={"projectName": "p", "sortOrder": "DESCENDING"})
    [item] = facts.ENRICHERS["codebuild_project"](aws.Requests({}), session, REGION, [{"name": "p", "Configuration": {"collection_status": "denied"}}])
    assert item["Builds"]["collection_status"] == "denied"


def test_iam_service_specific_credentials_marker_pagination(sdk):
    session, add = sdk
    iam = add("iam")
    cred = {"UserName": "u", "Status": "Active", "ServiceUserName": "u-at-1", "CreateDate": NOW, "ServiceSpecificCredentialId": "ACCA1234567890123456",
        "ServiceName": "bedrock.amazonaws.com"}
    base = {"AllUsers": True}
    iam.add_response("list_service_specific_credentials", {"ServiceSpecificCredentials": [cred], "IsTruncated": True, "Marker": "m"}, base)
    iam.add_response("list_service_specific_credentials", {"ServiceSpecificCredentials": [dict(cred, ServiceSpecificCredentialId="ACCA1234567890123457")], "IsTruncated": False},
        dict(base, Marker="m"))
    read = facts.FETCHERS["iam_service_specific_credential"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "collected" and len(read.items) == 2 and "ServiceUserName" not in read.items[0]


@pytest.mark.parametrize("service", ["bedrock.amazonaws.com", "codecommit.amazonaws.com", "cassandra.amazonaws.com", "logs.amazonaws.com"])
def test_service_specific_inventory_keeps_other_services_without_inventing_activity(sdk, service):
    session, add = sdk
    credential = {"UserName": "u", "Status": "Active", "ServiceUserName": "u-at-1", "CreateDate": NOW,
        "ServiceSpecificCredentialId": "ACCA1234567890123456", "ServiceName": service}
    add("iam").add_response("list_service_specific_credentials", {"ServiceSpecificCredentials": [credential], "IsTruncated": False}, {"AllUsers": True})
    read = facts.FETCHERS["iam_service_specific_credential"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "collected"
    assert read.items == [{key: credential[key] for key in ("ServiceSpecificCredentialId", "UserName", "ServiceName", "Status", "CreateDate")}]
    if service != "bedrock.amazonaws.com":
        assert status("aws.c2b.bedrock.api_key_long_term_expired", read.items[0]) == "NOT_APPLICABLE"


@pytest.mark.parametrize("mode", ["denied", "second_page_denied", "resource_limit", "page_limit", "repeated_token"])
def test_service_specific_incomplete_inventory_is_never_empty_success(sdk, mode):
    session, add = sdk
    iam = add("iam")
    credential = {"UserName": "u", "Status": "Active", "CreateDate": NOW,
        "ServiceSpecificCredentialId": "ACCA1234567890123456", "ServiceName": "codecommit.amazonaws.com"}
    options = {}
    if mode == "denied":
        iam.add_client_error("list_service_specific_credentials", "AccessDenied", expected_params={"AllUsers": True})
    else:
        iam.add_response("list_service_specific_credentials", {"ServiceSpecificCredentials": [credential], "IsTruncated": True, "Marker": "next"}, {"AllUsers": True})
        if mode == "second_page_denied":
            iam.add_client_error("list_service_specific_credentials", "AccessDenied", expected_params={"AllUsers": True, "Marker": "next"})
        elif mode == "resource_limit": options["max_resources"] = 1
        elif mode == "page_limit": options["max_pages"] = 1
        else:
            iam.add_response("list_service_specific_credentials", {"ServiceSpecificCredentials": [], "IsTruncated": True, "Marker": "next"}, {"AllUsers": True, "Marker": "next"})
    read = facts.FETCHERS["iam_service_specific_credential"](aws.Requests(options), session, REGION, ACCOUNT)
    assert read.status == ("denied" if mode == "denied" else "partial"), read
    if mode != "denied":
        assert read.items[0]["ServiceName"] == "codecommit.amazonaws.com"
        assert read.error["cause_status"] in ("denied", "not_collected", "malformed")


@pytest.mark.parametrize("bound,partial,expected", [(False, False, "FAIL"), (True, False, "PASS"), (False, True, "DENIED"), (True, True, "PASS")])
def test_native_authorization_details_feed_inline_policy_consumers(sdk, bound, partial, expected):
    from peaso import unused_iam_aws_inline
    session, add = sdk
    iam = add("iam")
    group = {"GroupName": "synthetic", "GroupId": "AGPA0123456789ABCDE", "Arn": f"arn:aws:iam::{ACCOUNT}:group/synthetic",
        "GroupPolicyList": [{"PolicyName": "StorageReader", "PolicyDocument": json.dumps({"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]})}]}
    user = {"UserName": "synthetic-user", "UserId": "AIDA0123456789ABCDE", "Arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-user",
        "GroupList": ["synthetic"] if bound else []}
    payload = {"UserDetailList": [user], "GroupDetailList": [group], "IsTruncated": partial}
    if partial: payload["Marker"] = "next"
    iam.add_response("get_account_authorization_details", payload, {})
    if partial:
        iam.add_client_error("get_account_authorization_details", "AccessDenied", expected_params={"Marker": "next"})
    iam.add_response("list_access_keys", {"AccessKeyMetadata": [], "IsTruncated": False}, {"UserName": user["UserName"]})
    iam.add_client_error("get_login_profile", "NoSuchEntity", expected_params={"UserName": user["UserName"]})
    iam.add_response("list_mfa_devices", {"MFADevices": [], "IsTruncated": False}, {"UserName": user["UserName"]})
    native = aws._iam(aws.Requests({}), session, REGION, {"iam_group", "iam_user"})
    scope = ACCOUNT + "/global"
    index = {"context": {"provider": "aws", "scope": scope}, "collections": {}}
    for kind, read in native.items():
        index[kind] = [{"type": kind, "scope": scope, "data": row} for row in read.items]
        index["collections"][kind] = [{"type": kind, "scope": scope, "service": "iam", "status": read.status,
            "items": read.items, **({"error": read.error} if read.error else {})}]
    item = native["iam_group"].items[0]
    result, evidence = unused_iam_aws_inline.evaluate(item, index)
    assert result == expected, evidence
    if result in ("PASS", "FAIL"):
        assert evidence["inline_policies"][0]["PolicyDocument"]["Statement"][0]["Action"] == "s3:GetObject"


def test_drs_uninitialized_is_empty_but_denied_is_denied(sdk):
    session, add = sdk
    drs = add("drs")
    drs.add_client_error("describe_jobs", "UninitializedAccountException")
    assert facts.FETCHERS["drs_job"](aws.Requests({}), session, REGION, ACCOUNT).status == "empty"
    drs.add_client_error("describe_jobs", "AccessDeniedException")
    assert facts.FETCHERS["drs_job"](aws.Requests({}), session, REGION, ACCOUNT).status == "denied"


def test_athena_workgroups_token_pagination_and_detail(sdk):
    session, add = sdk
    athena = add("athena")
    athena.add_response("list_work_groups", {"WorkGroups": [{"Name": "a", "State": "ENABLED"}], "NextToken": "n"}, {})
    athena.add_response("list_work_groups", {"WorkGroups": [{"Name": "b", "State": "ENABLED"}]}, {"NextToken": "n"})
    read = facts.FETCHERS["athena_workgroup"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "collected" and [w["Name"] for w in read.items] == ["a", "b"]
    athena.add_response("get_work_group", {"WorkGroup": {"Name": "a", "State": "ENABLED", "Configuration": {"PublishCloudWatchMetricsEnabled": True}}}, {"WorkGroup": "a"})
    athena.add_client_error("get_work_group", "AccessDeniedException", expected_params={"WorkGroup": "b"})
    good, denied = facts.ENRICHERS["athena_workgroup"](aws.Requests({}), session, REGION, read.items)
    assert status("aws.c2b.athena.cloudwatch_metrics", good) == "PASS"
    assert status("aws.c2b.athena.cloudwatch_metrics", denied) == "UNKNOWN"


def test_eventbridge_bus_describe_failure_is_unknown(sdk):
    session, add = sdk
    events = add("events")
    events.add_response("describe_event_bus", {"Name": "custom", "Arn": "arn:custom", "Policy": json.dumps({"Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "events:PutEvents", "Resource": "*"}]})}, {"Name": "custom"})
    events.add_client_error("describe_event_bus", "AccessDeniedException", expected_params={"Name": "other"})
    public, denied = facts.ENRICHERS["eventbridge_bus"](aws.Requests({}), session, REGION, [{"Name": "custom", "Arn": "arn:custom"}, {"Name": "other", "Arn": "arn:other"}])
    index = {"scope": {"provider": "aws", "account": ACCOUNT}}
    assert status("aws.c2b.eventbridge.custom_bus_policy_attached", public, index) == "PASS"
    assert status("aws.c2b.eventbridge.custom_bus_policy_attached", denied, index) == "UNKNOWN"
    assert status("aws.c2b.eventbridge.bus_policy_not_public", denied, index) == "UNKNOWN"


def test_dms_and_directory_secrets_are_dropped(sdk):
    session, add = sdk
    endpoint = {"EndpointArn": "arn:e", "EngineName": "redis", "SslMode": "none", "Username": "admin", "Password": "pw", "ExtraConnectionAttributes": "secret=1",
        "RedisSettings": {"ServerName": "r", "SslSecurityProtocol": "plaintext", "AuthPassword": "pw2", "AuthUserName": "u"}}
    [kept] = facts.ENRICHERS["dms_endpoint"](aws.Requests({}), session, REGION, [endpoint])
    assert kept == {"EndpointArn": "arn:e", "EngineName": "redis", "SslMode": "none", "RedisSettings": {"ServerName": "r", "SslSecurityProtocol": "plaintext"}}
    ds = add("ds")
    directory = {"DirectoryId": "d-1", "Type": "SimpleAD", "RadiusStatus": "Completed", "RadiusSettings": {"AuthenticationProtocol": "PAP", "SharedSecret": "radius"}}
    ds.add_response("describe_event_topics", {"EventTopics": []}, {"DirectoryId": "d-1"})
    ds.add_response("describe_shared_directories", {"SharedDirectories": []}, {"OwnerDirectoryId": "d-1"})
    ds.add_response("list_log_subscriptions", {"LogSubscriptions": []}, {"DirectoryId": "d-1"})
    ds.add_client_error("get_snapshot_limits", "UnsupportedOperationException", expected_params={"DirectoryId": "d-1"})
    [item] = facts.ENRICHERS["directory_service_directory"](aws.Requests({}), session, REGION, [directory])
    assert "radius" not in json.dumps(item) and item["RadiusSettings"] == {"AuthenticationProtocol": "PAP"}
    assert item["EventTopics"]["collection_status"] == item["LogSubscriptions"]["collection_status"] == "empty"
    assert item["SnapshotLimits"]["absent"] is True and "Certificates" not in item


def test_acmpca_projection_supports_both_check_families():
    ca = {"Arn": "arn:ca", "Type": "ROOT", "Status": "ACTIVE", "CertificateAuthorityConfiguration": {"KeyAlgorithm": "RSA_2048", "SigningAlgorithm": "SHA256WITHRSA",
        "Subject": {"CommonName": "x"}, "CsrExtensions": {}}, "RevocationConfiguration": {}}
    [kept] = facts.ENRICHERS["acmpca_certificate_authority"](aws.Requests({}), None, REGION, [ca])
    assert kept["CertificateAuthorityConfiguration"] == {"KeyAlgorithm": "RSA_2048", "SigningAlgorithm": "SHA256WITHRSA"}
    assert status("aws.c2b.acmpca.root_ca_disabled", kept) == "FAIL"
    assert status("aws.c2b.acmpca.root_ca_disabled", dict(kept, Status="DISABLED")) == "PASS"
    assert status("aws.c2b.acmpca.root_ca_disabled", dict(kept, collection_status="denied")) == "UNKNOWN"
