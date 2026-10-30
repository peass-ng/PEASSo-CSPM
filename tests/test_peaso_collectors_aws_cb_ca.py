"""Read-only collector facts for the claude AWS-B / AWS-A predicate families."""
import json

import pytest

boto3 = pytest.importorskip("boto3")
from botocore.stub import ANY, Stubber

from peaso.collectors import aws
from peaso.collectors import aws_facts_cb_ca as facts
from peaso.checks import CHECKS

REGION = "us-east-1"
ACCOUNT = "123456789012"


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


def check(check_id):
    return next(c for c in CHECKS if c.id == check_id)


def evaluate(check_id, item, index=None):
    return check(check_id).evaluate(aws._safe(item), index or {})[0]


def denied(stub, operation, code="AccessDeniedException"):
    stub.add_client_error(operation, service_error_code=code, service_message="denied", http_status_code=403)


def test_module_is_loaded_into_the_collector_registry():
    for kind, spec in facts.SPECS.items():
        assert aws.SPECS[kind] == spec
    assert facts.GLOBAL_TYPES <= aws.GLOBAL_TYPES
    assert {"organization", "shield_subscription", "route53_domain", "trustedadvisor_check"} <= aws.GLOBAL_TYPES
    for service, operation in facts.READ_ACTIONS:
        assert operation.startswith(("get_", "list_", "describe_", "batch_get_", "search_")), (service, operation)


def test_kinesis_streams_paginate_merge_summary_and_drive_encryption_predicate(sdk):
    session, add = sdk
    kinesis = add("kinesis")
    kinesis.add_response("list_streams", {"StreamNames": ["a"], "HasMoreStreams": True, "NextToken": "n"}, {})
    kinesis.add_response("list_streams", {"StreamNames": ["b"], "HasMoreStreams": False}, {"NextToken": "n"})
    requests = aws.Requests({})
    read = facts.FETCHERS["kinesis_stream"](requests, session, REGION, ACCOUNT)
    assert read.status == "collected"
    assert [item["StreamARN"] for item in read.items] == [f"arn:aws:kinesis:{REGION}:{ACCOUNT}:stream/a", f"arn:aws:kinesis:{REGION}:{ACCOUNT}:stream/b"]

    def summary(name, encryption):
        return {"StreamDescriptionSummary": {"StreamName": name, "StreamARN": f"arn:aws:kinesis:{REGION}:{ACCOUNT}:stream/{name}", "StreamStatus": "ACTIVE",
                "RetentionPeriodHours": 24, "StreamCreationTimestamp": "2024-01-01T00:00:00Z", "EnhancedMonitoring": [], "OpenShardCount": 1,
                "EncryptionType": encryption}}
    kinesis.add_response("describe_stream_summary", summary("a", "KMS"), {"StreamName": "a"})
    denied(kinesis, "describe_stream_summary")
    items = facts.ENRICHERS["kinesis_stream"](requests, session, REGION, read.items)
    assert items[0]["EncryptionType"] == "KMS" and "collection_status" not in items[0]
    assert items[1]["collection_status"] == "denied" and "EncryptionType" not in items[1]
    assert evaluate("aws.cb.kinesis.kms_encryption", items[0]) == "PASS"
    assert evaluate("aws.cb.kinesis.kms_encryption", items[1]) == "UNKNOWN"
    assert evaluate("aws.cb.kinesis.kms_encryption", {**items[0], "EncryptionType": "NONE"}) == "FAIL"


def test_listing_denied_is_never_an_empty_inventory(sdk):
    session, add = sdk
    denied(add("kinesis"), "list_streams")
    read = facts.FETCHERS["kinesis_stream"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "denied" and read.items == []


def test_glue_job_arguments_are_reduced_to_allowlisted_flags(sdk):
    session, _ = sdk
    job = {"Name": "etl", "Role": "arn:aws:iam::123456789012:role/glue",
           "DefaultArguments": {"--enable-continuous-cloudwatch-log": "true", "--db-password": "hunter2", "--conn": "jdbc:postgresql://u:p@h/db"},
           "NonOverridableArguments": {"--job-bookmark-option": "job-bookmark-enable"}}
    before = evaluate("aws.cb.glue.job_continuous_cloudwatch_logging", {"Name": "etl", "Role": job["Role"]})
    [item] = facts.ENRICHERS["glue_job"](aws.Requests({}), session, REGION, [job])
    assert before == "UNKNOWN"
    assert "DefaultArguments" not in item and "NonOverridableArguments" not in item
    assert item["DefaultArgumentFlags"] == {"--enable-continuous-cloudwatch-log": "true", "--job-bookmark-option": "job-bookmark-enable"}
    assert "hunter2" not in json.dumps(item) and "jdbc" not in json.dumps(item)
    assert evaluate("aws.cb.glue.job_continuous_cloudwatch_logging", item) == "PASS"
    [off] = facts.ENRICHERS["glue_job"](aws.Requests({}), session, REGION, [{"Name": "x", "Role": job["Role"]}])
    assert evaluate("aws.cb.glue.job_continuous_cloudwatch_logging", off) == "FAIL"


def test_bucket_website_collected_absent_and_denied(sdk):
    session, add = sdk
    s3 = add("s3")
    s3.add_response("get_bucket_website", {"IndexDocument": {"Suffix": "index.html"}}, {"Bucket": "site"})
    s3.add_client_error("get_bucket_website", service_error_code="NoSuchWebsiteConfiguration", http_status_code=404, expected_params={"Bucket": "plain"})
    s3.add_client_error("get_bucket_website", service_error_code="AccessDenied", http_status_code=403, expected_params={"Bucket": "locked"})
    buckets = [{"Name": name, "Location": {"collection_status": "collected", "LocationConstraint": None}} for name in ("site", "plain", "locked")]
    site, plain, locked = facts.ENRICHERS["bucket"](aws.Requests({}), session, REGION, buckets)
    assert site["Website"]["IndexDocument"] == {"Suffix": "index.html"}
    assert plain["Website"]["absent"] is True and plain["Website"]["collection_status"] == "empty"
    assert locked["Website"]["collection_status"] == "denied"
    assert evaluate("aws.claude_a.s3.static_website_disabled", buckets[0]) == "UNKNOWN"
    assert evaluate("aws.claude_a.s3.static_website_disabled", site) == "FAIL"
    assert evaluate("aws.claude_a.s3.static_website_disabled", plain) == "PASS"
    assert evaluate("aws.claude_a.s3.static_website_disabled", locked) == "UNKNOWN"


def test_guardduty_detector_facts_and_high_severity_predicate(sdk):
    session, add = sdk
    gd = add("guardduty")
    detector = "d" * 32
    gd.add_response("get_administrator_account", {"Administrator": {"AccountId": "999999999999", "InvitationId": "i", "RelationshipStatus": "Enabled", "InvitedAt": "t"}}, {"DetectorId": detector})
    gd.add_response("list_members", {"Members": [{"AccountId": "111111111111", "MasterId": "m", "Email": "secret@example.com", "RelationshipStatus": "Enabled", "UpdatedAt": "t"}]}, {"DetectorId": detector})
    gd.add_response("list_findings", {"FindingIds": ["f1", "f2"], "NextToken": "n"}, {"DetectorId": detector})
    gd.add_response("list_findings", {"FindingIds": ["f3"]}, {"DetectorId": detector, "NextToken": "n"})
    denied(gd, "list_findings", "AccessDeniedException")
    gd.add_response("describe_organization_configuration", {"AutoEnable": True, "MemberAccountLimitReached": False, "AutoEnableOrganizationMembers": "ALL"}, {"DetectorId": detector})
    [item] = facts.ENRICHERS["guardduty_detector"](aws.Requests({}), session, REGION, [{"DetectorId": detector}])
    assert item["Administrator"]["Administrator"]["AccountId"] == "999999999999"
    assert "secret@example.com" not in json.dumps(item)
    assert item["FindingIds"] == {"collection_status": "collected", "items": ["f1", "f2", "f3"]}
    assert item["HighSeverityFindingIds"]["collection_status"] == "denied"
    assert item["OrganizationConfiguration"]["AutoEnableOrganizationMembers"] == "ALL"
    assert evaluate("aws.claude_a.guardduty.prowler_no_high_severity_findings", item) == "UNKNOWN"
    assert evaluate("aws.claude_a.guardduty.prowler_no_high_severity_findings", {**item, "HighSeverityFindingIds": {"collection_status": "collected", "items": []}}) == "PASS"
    assert evaluate("aws.claude_a.guardduty.prowler_no_high_severity_findings", {**item, "HighSeverityFindingIds": item["FindingIds"]}) == "FAIL"


def test_route53_query_logging_grouped_by_zone_with_one_listing(sdk):
    session, add = sdk
    route53 = add("route53")
    group = "arn:aws:logs:us-east-1:123456789012:log-group:/aws/route53/example.com"
    route53.add_response("list_query_logging_configs", {"QueryLoggingConfigs": [{"Id": "q", "HostedZoneId": "Z1", "CloudWatchLogsLogGroupArn": group}], "NextToken": "n"}, {})
    route53.add_response("list_query_logging_configs", {"QueryLoggingConfigs": []}, {"NextToken": "n"})
    zones = [{"Id": "/hostedzone/Z1", "Name": "example.com.", "Config": {"PrivateZone": False}},
             {"Id": "/hostedzone/Z2", "Name": "other.com.", "Config": {"PrivateZone": False}}]
    logged, unlogged = facts.ENRICHERS["route53_zone"](aws.Requests({}), session, REGION, zones)
    assert logged["QueryLoggingConfigs"]["QueryLoggingConfigs"][0]["CloudWatchLogsLogGroupArn"] == group
    assert evaluate("aws.cb.route53.public_zone_query_logging", zones[0]) == "UNKNOWN"
    assert evaluate("aws.cb.route53.public_zone_query_logging", logged) == "PASS"
    assert evaluate("aws.cb.route53.public_zone_query_logging", unlogged) == "FAIL"


def test_route53_query_logging_denied_is_unknown(sdk):
    session, add = sdk
    denied(add("route53"), "list_query_logging_configs", "AccessDenied")
    [zone] = facts.ENRICHERS["route53_zone"](aws.Requests({}), session, REGION, [{"Id": "/hostedzone/Z1", "Config": {"PrivateZone": False}}])
    assert zone["QueryLoggingConfigs"]["collection_status"] == "denied"
    assert evaluate("aws.cb.route53.public_zone_query_logging", zone) == "UNKNOWN"


def test_sns_subscription_endpoint_is_never_stored(sdk):
    session, add = sdk
    topic = f"arn:aws:sns:{REGION}:{ACCOUNT}:t"
    add("sns").add_response("list_subscriptions", {"Subscriptions": [
        {"SubscriptionArn": topic + ":1", "Owner": ACCOUNT, "Protocol": "http", "Endpoint": "http://hook.example/?token=abc", "TopicArn": topic},
        {"SubscriptionArn": "PendingConfirmation", "Owner": ACCOUNT, "Protocol": "https", "Endpoint": "https://x.example/?token=def", "TopicArn": topic}]}, {})
    read = facts.FETCHERS["sns_subscription"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "collected"
    assert "token" not in json.dumps(read.items)
    assert read.items[0]["id"] == topic + ":1" and read.items[1]["id"].startswith(topic + "/pending/")
    assert evaluate("aws.cb.sns.subscription_not_http", read.items[0]) == "FAIL"
    assert evaluate("aws.cb.sns.subscription_not_http", read.items[1]) == "NOT_APPLICABLE"


def test_glue_connection_properties_allowlist_drops_credentials(sdk):
    session, add = sdk
    add("glue").add_response("get_connections", {"ConnectionList": [{"Name": "db", "ConnectionType": "JDBC", "ConnectionProperties": {
        "JDBC_CONNECTION_URL": "jdbc:mysql://h/db", "USERNAME": "admin", "PASSWORD": "pw", "SECRET_ID": "s", "JDBC_ENFORCE_SSL": "true"}}]}, {"HidePassword": True})
    read = facts.FETCHERS["glue_connection"](aws.Requests({}), session, REGION, ACCOUNT)
    assert [{key: value for key, value in item.items() if key != "AdditionalSecretIndicators"} for item in read.items] == [
        {"Name": "db", "ConnectionType": "JDBC", "ConnectionProperties": {"JDBC_ENFORCE_SSL": "true"}}]
    marker = read.items[0]["AdditionalSecretIndicators"]
    assert marker["Coverage"] == "visible_nonpassword_properties"
    assert marker["HighConfidenceSecretPresent"] is False
    assert marker["NativeResponseComplete"] is True and marker["collection_status"] == "collected"
    assert marker["SourceOperation"] == "glue:GetConnections" and marker["ResourceId"] == "db"
    assert marker["Kind"] == "glue_connection" and marker["Region"] == REGION
    assert marker["AccountId"] is None  # native CatalogId omission: account authority is the scoped collection


def test_glue_data_catalog_encryption_and_absent_policy(sdk):
    session, add = sdk
    glue = add("glue")
    glue.add_response("get_data_catalog_encryption_settings", {"DataCatalogEncryptionSettings": {"EncryptionAtRest": {"CatalogEncryptionMode": "DISABLED"},
        "ConnectionPasswordEncryption": {"ReturnConnectionPasswordEncrypted": False}}}, {})
    glue.add_client_error("get_resource_policy", service_error_code="EntityNotFoundException", http_status_code=400)
    read = facts.FETCHERS["glue_data_catalog"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "collected"
    [catalog] = read.items
    assert catalog["id"] == f"arn:aws:glue:{REGION}:{ACCOUNT}:catalog"
    assert catalog["ResourcePolicy"]["absent"] is True
    assert evaluate("aws.cb.glue.catalog_metadata_encryption", catalog) == "FAIL"


def test_securityhub_permission_error_is_unknown_but_missing_hub_is_empty(sdk):
    session, add = sdk
    hub = add("securityhub")
    hub.add_client_error("describe_hub", service_error_code="InvalidAccessException", http_status_code=401)
    read = facts.FETCHERS["securityhub_hub"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "unknown" and read.items == []
    assert read.error == {"code": "InvalidAccessException", "operation": "describe_hub"}
    hub.add_client_error("describe_hub", service_error_code="ResourceNotFoundException", http_status_code=404)
    read = facts.FETCHERS["securityhub_hub"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "empty" and read.items == []
    assert read.error == {"code": "ResourceNotFoundException"}
    denied(hub, "describe_hub", "AccessDeniedException")
    read = facts.FETCHERS["securityhub_hub"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "denied" and read.items == []


def test_organization_not_in_use_is_documented_empty(sdk):
    session, add = sdk
    orgs = add("organizations")
    orgs.add_client_error("describe_organization", service_error_code="AWSOrganizationsNotInUseException", http_status_code=400)
    assert facts.FETCHERS["organization"](aws.Requests({}), session, REGION, ACCOUNT).status == "empty"
    orgs.add_response("describe_organization", {"Organization": {"Id": "o-abcdefghij", "Arn": "arn:aws:organizations::1:organization/o-abcdefghij",
        "MasterAccountEmail": "root@example.com", "MasterAccountId": "111111111111", "FeatureSet": "ALL"}}, {})
    read = facts.FETCHERS["organization"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.items[0]["Organization"]["Id"] == "o-abcdefghij"
    assert "root@example.com" not in json.dumps(read.items)


def test_shield_protections_not_found_is_empty(sdk):
    session, add = sdk
    add("shield").add_client_error("list_protections", service_error_code="ResourceNotFoundException", http_status_code=400)
    assert facts.FETCHERS["shield_protection"](aws.Requests({}), session, REGION, ACCOUNT).status == "empty"


def test_s3_access_points_follow_unpaginated_tokens(sdk):
    session, add = sdk
    control = add("s3control")
    point = lambda name: {"Name": name, "NetworkOrigin": "Internet", "Bucket": "b"}
    control.add_response("list_access_points", {"AccessPointList": [point("apa")], "NextToken": "n"}, {"AccountId": ACCOUNT})
    control.add_response("list_access_points", {"AccessPointList": [point("apb")]}, {"AccountId": ACCOUNT, "NextToken": "n"})
    control.add_response("get_access_point", {"Name": "apa", "Bucket": "b", "NetworkOrigin": "Internet",
        "PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}, {"AccountId": ACCOUNT, "Name": "apa"})
    denied(control, "get_access_point", "AccessDenied")
    read = facts.FETCHERS["s3_access_point"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "collected"
    assert read.items[0]["PublicAccessBlockConfiguration"]["BlockPublicPolicy"] is True
    assert read.items[1]["collection_status"] == "denied"


def test_inspector_findings_batch_details_and_per_finding_errors(sdk):
    session, add = sdk
    inspector = add("inspector2")
    arns = [f"arn:aws:inspector2:{REGION}:{ACCOUNT}:finding/{index}" for index in range(12)]
    def finding(arn):
        return {"findingArn": arn, "awsAccountId": ACCOUNT, "type": "PACKAGE_VULNERABILITY", "description": "d", "severity": "HIGH", "status": "ACTIVE",
                "firstObservedAt": "2024-01-01T00:00:00Z", "lastObservedAt": "2024-01-01T00:00:00Z", "updatedAt": "2024-01-01T00:00:00Z",
                "remediation": {}, "resources": [{"type": "AWS_EC2_INSTANCE", "id": "i-1"}]}
    inspector.add_response("list_findings", {"findings": [finding(arn) for arn in arns[:7]], "nextToken": "n"}, {"filterCriteria": ANY})
    inspector.add_response("list_findings", {"findings": [finding(arn) for arn in arns[7:]]}, {"filterCriteria": ANY, "nextToken": "n"})
    ordered = sorted(arns)
    inspector.add_response("batch_get_finding_details", {"findingDetails": [{"findingArn": arn} for arn in ordered[:9]],
        "errors": [{"findingArn": ordered[9], "errorCode": "INTERNAL_ERROR", "errorMessage": "x"}]}, {"findingArns": ordered[:10]})
    denied(inspector, "batch_get_finding_details")
    read = facts.FETCHERS["inspector2_finding"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "collected" and len(read.items) == 12
    details = {item["findingArn"]: item["Details"]["collection_status"] for item in read.items}
    assert [details[arn] for arn in ordered] == ["collected"] * 9 + ["unknown", "denied", "denied"]


def test_redshift_subnet_group_spec_paginates(sdk):
    session, add = sdk
    redshift = add("redshift")
    group = lambda name: {"ClusterSubnetGroupName": name, "VpcId": "vpc-1", "Subnets": [{"SubnetIdentifier": "subnet-1"}]}
    redshift.add_response("describe_cluster_subnet_groups", {"ClusterSubnetGroups": [group("a")], "Marker": "m"}, {})
    redshift.add_response("describe_cluster_subnet_groups", {"ClusterSubnetGroups": [group("b")]}, {"Marker": "m"})
    service, operation, expression = facts.SPECS["redshift_subnet_group"]
    read = aws.Requests({}).pages(session, service, REGION, operation, expression)
    assert read.status == "collected" and [item["ClusterSubnetGroupName"] for item in read.items] == ["a", "b"]

