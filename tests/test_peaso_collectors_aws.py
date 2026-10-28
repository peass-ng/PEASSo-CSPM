"""Native AWS response contracts tested with botocore's validating Stubber."""
import concurrent.futures
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

boto3 = pytest.importorskip("boto3")
from botocore.exceptions import ReadTimeoutError
from botocore.stub import Stubber, ANY

from peaso.collectors import aws
from peaso.snapshot import validate
from peaso.snapshot import nothing_readable

ACCOUNT = "123456789012"
REGION = "us-east-1"
IDENTITY = {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/reviewer", "UserId": "AIDAREVIEWER"}
NOW = datetime(2026, 10, 10, tzinfo=timezone.utc)


@pytest.mark.parametrize('mode', ['success', 'denied', 'malformed', 'partial'])
def test_private_auto_scope_plan_requires_complete_region_discovery(sdk, monkeypatch, mode):
    from peaso.collection_events import scope_plan_callback
    _, add, _ = sdk
    add('sts').add_response('get_caller_identity', IDENTITY, {})
    ec2 = add('ec2')
    if mode == 'denied':
        ec2.add_client_error('describe_regions', 'UnauthorizedOperation', expected_params={'AllRegions': True})
    else:
        rows = [{'RegionName': REGION, 'OptInStatus': 'opt-in-not-required'},
                {'RegionName': 'eu-west-1', 'OptInStatus': 'not-opted-in'}]
        if mode == 'malformed':
            rows.append(dict(rows[0]))
        response = {'Regions': rows}
        ec2.add_response('describe_regions', response, {'AllRegions': True})
        if mode == 'partial':
            pages = aws.Requests.pages
            def partial_pages(requests, *args, **kwargs):
                result = pages(requests, *args, **kwargs)
                if args[3] == 'describe_regions':
                    return aws.ReadResult(result.items, 'partial', {'code': 'page_limit'})
                return result
            monkeypatch.setattr(aws.Requests, 'pages', partial_pages)
    if mode == 'success':
        ec2.add_response('describe_vpcs', {'Vpcs': []}, {})
    events = []
    with scope_plan_callback(lambda scopes: events.append(('plan', scopes))):
        snapshot = aws.collect({'provider': 'aws', 'scopes': [], 'options': {
            'max_pages': 1, '_collection_callback': lambda row: events.append(('read', row['type']))}}, ['vpc'])
    plans = [value for kind, value in events if kind == 'plan']
    assert plans == [(f'{ACCOUNT}/{REGION}',)] if mode == 'success' else plans == []
    if mode == 'success':
        assert events[0][0] == 'plan'
    assert '_scope_plan' not in json.dumps(snapshot)


@pytest.mark.parametrize('explicit', [False, True])
def test_private_scope_plan_preserves_per_account_enabled_regions(sdk, monkeypatch, explicit):
    from peaso.collection_events import scope_plan_callback
    session, add, _ = sdk
    other_account = '999999999999'
    other = SimpleNamespace(get_partition_for_region=session.get_partition_for_region)
    monkeypatch.setattr(aws, '_assume', lambda *args: other)
    identity = {**IDENTITY, 'Account': other_account, 'Arn': f'arn:aws:iam::{other_account}:user/reviewer'}
    sts = add('sts')
    sts.add_response('get_caller_identity', IDENTITY, {})
    sts.add_response('get_caller_identity', identity, {})
    pages = aws.Requests.pages
    def regional_pages(requests, current, service, region, operation, *args, **kwargs):
        if operation == 'describe_regions':
            selected = [REGION, 'eu-west-1'] if current is session else ['ap-south-1']
            return aws.ReadResult([{'RegionName': value, 'OptInStatus': 'opt-in-not-required'} for value in selected], 'collected')
        return pages(requests, current, service, region, operation, *args, **kwargs)
    monkeypatch.setattr(aws.Requests, 'pages', regional_pages)
    selected_regions = [REGION, 'ap-south-1'] if explicit else [REGION, 'eu-west-1', 'ap-south-1']
    for region in selected_regions:
        add('ec2', region).add_response('describe_vpcs', {'Vpcs': []}, {})
    plans = []
    with scope_plan_callback(plans.append):
        aws.collect({'provider': 'aws', 'scopes': [f'{ACCOUNT}/{REGION}', f'{other_account}/ap-south-1'] if explicit else [], 'auth': {'assume_roles': [
            f'arn:aws:iam::{other_account}:role/reviewer']}}, ['vpc'])
    expected = [f'{ACCOUNT}/{REGION}', f'{other_account}/ap-south-1']
    if not explicit:
        expected.append(f'{ACCOUNT}/eu-west-1')
    assert plans == [tuple(sorted(expected))]


@pytest.mark.parametrize('mode', ['identity_denied', 'role_denied', 'organization_denied'])
def test_private_scope_plan_never_closes_incomplete_target_discovery(sdk, mode):
    from peaso.collection_events import scope_plan_callback
    _, add, _ = sdk
    sts = add('sts')
    options, auth = {}, {}
    if mode == 'identity_denied':
        sts.add_client_error('get_caller_identity', 'AccessDenied', expected_params={})
    else:
        sts.add_response('get_caller_identity', IDENTITY, {})
        if mode == 'role_denied':
            arn = 'arn:aws:iam::999999999999:role/reviewer'
            auth['assume_roles'] = [arn]
            sts.add_client_error('assume_role', 'AccessDenied', expected_params={'RoleArn': arn, 'RoleSessionName': ANY})
        else:
            options['organization_role_name'] = 'reviewer'
            add('organizations').add_client_error('list_accounts', 'AccessDeniedException', expected_params={})
        ec2 = add('ec2')
        ec2.add_response('describe_regions', {'Regions': [{'RegionName': REGION, 'OptInStatus': 'opt-in-not-required'}]}, {'AllRegions': True})
        ec2.add_response('describe_vpcs', {'Vpcs': []}, {})
    plans = []
    with scope_plan_callback(plans.append):
        aws.collect({'provider': 'aws', 'scopes': [], 'auth': auth, 'options': options}, ['vpc'])
    assert plans == []


@pytest.fixture
def sdk(monkeypatch):
    session = boto3.Session(aws_access_key_id="selected-key-must-not-leak",
        aws_secret_access_key="selected-secret-must-not-leak", aws_session_token="selected-token-must-not-leak", region_name=REGION)
    clients, stubs = {}, {}

    def add(service, region=REGION):
        key = (service, region)
        if key not in clients:
            clients[key] = session.client(service, region_name=region)
            stubs[key] = Stubber(clients[key])
            stubs[key].activate()
        return stubs[key]

    monkeypatch.setattr(aws.Requests, "client", lambda self, _session, service, region: clients[(service, region)])
    monkeypatch.setattr(aws, "_session", lambda auth, region: (session, "test-pinned"))
    original_assume = aws._assume
    def assume_with_fixture_broker(requests, source, region, target, defaults):
        from peaso.server.validation import COLLECTOR_ROLE_ARN
        if isinstance(target, dict) and target.get("role_arn") == COLLECTOR_ROLE_ARN:
            return session
        return original_assume(requests, source, region, target, defaults)
    monkeypatch.setattr(aws, "_assume", assume_with_fixture_broker)
    yield session, add, clients
    for stub in stubs.values():
        stub.assert_no_pending_responses()
        stub.deactivate()


def envelope(snapshot, kind, region=REGION):
    # Account-global inventories are collected once, under <account>/global.
    if kind in aws.GLOBAL_TYPES and region == REGION:
        region = aws.GLOBAL_SCOPE
    return next(c for c in snapshot["collections"] if c["type"] == kind and c["scope"] == f"{ACCOUNT}/{region}")


def test_identity_scopes_required_facts_empty_and_omitted(sdk):
    session, add, _ = sdk
    add("sts").add_response("get_caller_identity", IDENTITY, {})
    add("ec2").add_response("describe_vpcs", {"Vpcs": []}, {})
    snapshot = aws.collect({"provider": "aws", "scopes": [ACCOUNT], "auth": {"profile": "chosen"}, "options": {"regions": [REGION]}}, ["vpc"])
    assert validate(snapshot) == snapshot
    assert snapshot["scopes"] == [f"{ACCOUNT}/{REGION}"]
    assert snapshot["metadata"]["calls"] == 2
    assert snapshot["metadata"]["caller_identities"] == [IDENTITY]
    assert envelope(snapshot, "vpc")["status"] == "empty"
    assert envelope(snapshot, "bucket")["status"] == "not_collected"
    assert envelope(snapshot, "aws_account")["items"][0]["Account"] == ACCOUNT
    assert "selected-key-must-not-leak" not in json.dumps(snapshot)


def test_network_pagination_native_ids_and_relationships(sdk):
    session, add, _ = sdk
    add("sts").add_response("get_caller_identity", IDENTITY, {})
    ec2 = add("ec2")
    ec2.add_response("describe_subnets", {"Subnets": [{"SubnetId": "subnet-1", "VpcId": "vpc-shared"}], "NextToken": "next"}, {})
    ec2.add_response("describe_subnets", {"Subnets": [{"SubnetId": "subnet-2", "VpcId": "vpc-shared"}]}, {"NextToken": "next"})
    snapshot = aws.collect({"provider": "aws", "scopes": [REGION], "options": {"service_concurrency": 1}}, ["subnet"])
    subnets = envelope(snapshot, "subnet")
    assert subnets["status"] == "collected"
    assert {x["id"] for x in subnets["items"]} == {"subnet-1", "subnet-2"}
    assert len(snapshot["metadata"]["network_relationships"]) == 2
    assert all(x["reachability"] == "unknown" for x in snapshot["metadata"]["network_relationships"])


def test_transit_gateway_route_table_captures_both_route_types_and_associations(sdk):
    _, add, _ = sdk
    add("sts").add_response("get_caller_identity", IDENTITY, {})
    ec2 = add("ec2")
    table_id = "tgw-rtb-0123456789abcdef0"
    ec2.add_response("describe_transit_gateway_route_tables", {"TransitGatewayRouteTables": [
        {"TransitGatewayRouteTableId": table_id, "TransitGatewayId": "tgw-0123456789abcdef0", "State": "available"}]}, {})
    ec2.add_response("search_transit_gateway_routes", {"Routes": [{
        "DestinationCidrBlock": "10.1.0.0/16", "Type": "static", "State": "active",
        "TransitGatewayAttachments": [{"TransitGatewayAttachmentId": "tgw-attach-111", "ResourceId": "vpc-1", "ResourceType": "vpc"}]}],
        "AdditionalRoutesAvailable": False}, {"TransitGatewayRouteTableId": table_id,
        "Filters": [{"Name": "type", "Values": ["static"]}]})
    ec2.add_response("search_transit_gateway_routes", {"Routes": [{
        "DestinationCidrBlock": "10.2.0.0/16", "Type": "propagated", "State": "active",
        "TransitGatewayAttachments": [{"TransitGatewayAttachmentId": "tgw-attach-222", "ResourceId": "vpc-2", "ResourceType": "vpc"}]}],
        "AdditionalRoutesAvailable": False}, {"TransitGatewayRouteTableId": table_id,
        "Filters": [{"Name": "type", "Values": ["propagated"]}]})
    ec2.add_response("get_transit_gateway_route_table_associations", {"Associations": [{
        "TransitGatewayAttachmentId": "tgw-attach-111", "ResourceId": "vpc-1", "ResourceType": "vpc", "State": "associated"}]},
        {"TransitGatewayRouteTableId": table_id})
    snapshot = aws.collect({"provider": "aws", "scopes": [REGION], "options": {"service_concurrency": 1}},
        ["transit_gateway_route_table"])
    table = envelope(snapshot, "transit_gateway_route_table")["items"][0]
    assert table["RouteInventory"]["collection_status"] == "collected", table["RouteInventory"]
    assert {route["Type"] for route in table["RouteInventory"]["items"]} == {"static", "propagated"}
    assert table["AssociationInventory"]["collection_status"] == "collected"
    assert table["AssociationInventory"]["items"][0]["TransitGatewayAttachmentId"] == "tgw-attach-111"


def test_transit_gateway_route_table_does_not_hide_truncated_route_search(sdk):
    _, add, _ = sdk
    add("sts").add_response("get_caller_identity", IDENTITY, {})
    ec2 = add("ec2")
    table_id = "tgw-rtb-0123456789abcdef0"
    ec2.add_response("describe_transit_gateway_route_tables", {"TransitGatewayRouteTables": [
        {"TransitGatewayRouteTableId": table_id, "TransitGatewayId": "tgw-0123456789abcdef0", "State": "available"}]}, {})
    ec2.add_response("search_transit_gateway_routes", {"Routes": [], "AdditionalRoutesAvailable": True},
        {"TransitGatewayRouteTableId": table_id, "Filters": [{"Name": "type", "Values": ["static"]}]})
    ec2.add_response("search_transit_gateway_routes", {"Routes": [], "AdditionalRoutesAvailable": False},
        {"TransitGatewayRouteTableId": table_id, "Filters": [{"Name": "type", "Values": ["propagated"]}]})
    ec2.add_response("get_transit_gateway_route_table_associations", {"Associations": []},
        {"TransitGatewayRouteTableId": table_id})
    snapshot = aws.collect({"provider": "aws", "scopes": [REGION], "options": {"service_concurrency": 1}},
        ["transit_gateway_route_table"])
    table = envelope(snapshot, "transit_gateway_route_table")["items"][0]
    assert table["RouteInventory"]["collection_status"] == "partial"
    assert {source["code"] for source in table["RouteInventory"]["error"]["sources"]} == {"missing_pagination_token"}


def test_transit_gateway_vpc_attachment_keeps_native_subnet_and_option_facts(sdk):
    _, add, _ = sdk
    add("sts").add_response("get_caller_identity", IDENTITY, {})
    add("ec2").add_response("describe_transit_gateway_vpc_attachments", {"TransitGatewayVpcAttachments": [{
        "TransitGatewayAttachmentId": "tgw-attach-0123456789abcdef0",
        "TransitGatewayId": "tgw-0123456789abcdef0", "VpcId": "vpc-0123456789abcdef0",
        "VpcOwnerId": ACCOUNT, "State": "available", "SubnetIds": ["subnet-0123456789abcdef0"],
        "Options": {"Ipv6Support": "enable", "SecurityGroupReferencingSupport": "disable"}}]}, {})
    snapshot = aws.collect({"provider": "aws", "scopes": [REGION], "options": {"service_concurrency": 1}},
        ["transit_gateway_vpc_attachment"])
    row = envelope(snapshot, "transit_gateway_vpc_attachment")["items"][0]
    assert row["SubnetIds"] == ["subnet-0123456789abcdef0"]
    assert row["Options"]["Ipv6Support"] == "enable"
    assert row["State"] == "available"


def test_iam_marker_pagination_shared_request_cache(sdk):
    session, add, _ = sdk
    iam = add("iam")
    iam.add_response("get_account_authorization_details", {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": [], "IsTruncated": True, "Marker": "next"}, {})
    iam.add_response("get_account_authorization_details", {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [{"RoleName": "review", "RoleId": "AROAREVIEWROLE1234567", "Arn": f"arn:aws:iam::{ACCOUNT}:role/review", "Path": "/", "CreateDate": NOW, "AssumeRolePolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": []}),
        "RolePolicyList": [{"PolicyName": "models", "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "bedrock:InvokeModel", "Resource": "*"}]})}]}], "Policies": [], "IsTruncated": False}, {"Marker": "next"})
    role_arn = f"arn:aws:iam::{ACCOUNT}:role/review"
    requests = aws.Requests({})
    results = aws._iam(requests, session, REGION, {"iam_user", "iam_group", "iam_role", "iam_policy"})
    assert results["iam_role"].status == "collected"
    assert results["iam_user"].status == "empty"
    assert requests.calls == 2
    assert requests.cache_hits == 8  # role report scoping re-reads the cached Policies pages
    role = results["iam_role"].items[0]
    assert "ServicesLastAccessed" not in role
    assert role["ServicesLastAccessedStatus"]["collection_status"] == "not_collected"
    assert requests.service_last_accessed_generations == 0


def test_service_last_accessed_partial_failure_marks_only_affected_principal(sdk):
    session, add, _ = sdk
    add("iam")  # No SDK operations queued: report creation must never happen.
    requests = aws.Requests({})
    arns = [f"arn:aws:iam::{ACCOUNT}:role/{name}" for name in ("alpha", "beta", "gamma")]
    results = aws._sla_reports(requests, session, REGION, arns)
    assert set(results) == set(arns)
    assert all(rows is None and status["collection_status"] == "not_collected"
        and status["error"]["code"] == "service_last_accessed_generation_disabled"
        for rows, status in results.values())
    assert requests.calls == 0 and requests.service_last_accessed_generations == 0


def test_service_last_accessed_deadline_and_gate(sdk):
    session, add, _ = sdk
    add("iam")
    arn = f"arn:aws:iam::{ACCOUNT}:user/review"
    requests = aws.Requests({"service_last_accessed_wait_seconds": 5})
    item = {"Arn": arn}
    aws._services_last_accessed(requests, session, REGION, [item])
    assert "ServicesLastAccessed" not in item
    assert item["ServicesLastAccessedStatus"]["collection_status"] == "not_collected"
    assert requests.calls == 0
    for operation in ("generate_credential_report", "generate_service_last_accessed_details"):
        with pytest.raises(aws.ReadFailure):
            requests.call(session, "iam", REGION, operation)
    assert requests.calls == 0


def test_throttle_retry_denial_cached_and_message_redacted(sdk):
    session, add, _ = sdk
    iam = add("iam")
    iam.add_client_error("get_account_summary", "Throttling", "secret-value-must-not-leak", expected_params={})
    iam.add_response("get_account_summary", {"SummaryMap": {"Users": 1}}, {})
    iam.add_client_error("get_account_password_policy", "AccessDenied", "selected-token-must-not-leak", expected_params={})
    waits = []
    requests = aws.Requests({}, sleep=waits.append)
    assert requests.call(session, "iam", REGION, "get_account_summary")["SummaryMap"]["Users"] == 1
    assert waits == [0.2]
    first = requests.detail(session, "iam", REGION, "get_account_password_policy")
    second = requests.detail(session, "iam", REGION, "get_account_password_policy")
    assert first == second == {"collection_status": "denied", "error": {"code": "AccessDenied"}}
    assert requests.calls == 3
    assert "secret" not in json.dumps(first)


def test_throttle_exhaustion_preserves_unknown(sdk):
    session, add, _ = sdk
    iam = add("iam")
    for _ in range(2):
        iam.add_client_error("get_account_summary", "ThrottlingException", expected_params={})
    requests = aws.Requests({"retry_attempts": 2}, sleep=lambda _: None)
    result = requests.detail(session, "iam", REGION, "get_account_summary")
    assert result["collection_status"] == "unknown"
    assert result["error"]["code"] == "ThrottlingException"
    assert requests.calls == 2


def test_singleflight_concurrent_identical_reads(sdk):
    session, add, _ = sdk
    add("iam").add_response("get_account_summary", {"SummaryMap": {"Users": 2}}, {})
    requests = aws.Requests({})
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: requests.call(session, "iam", REGION, "get_account_summary"), range(8)))
    assert requests.calls == 1
    assert requests.cache_hits == 7
    results[0]["SummaryMap"]["Users"] = 99
    assert results[1]["SummaryMap"]["Users"] == 2


@pytest.mark.parametrize("fault", ["page_limit", "repeated_pagination_token", "malformed_response", "missing_pagination_token", "resource_limit"])
def test_pagination_limit_and_malformed_are_partial(sdk, fault, monkeypatch):
    session, add, _ = sdk
    iam = add("iam")
    options = {"max_pages": 1} if fault == "page_limit" else {"max_resources": 1} if fault == "resource_limit" else {}
    if fault == "malformed_response":
        iam.add_response("list_users", {"Users": [], "IsTruncated": True, "Marker": "next"}, {})
        # An output accepted by Stubber's optional schema, but missing native list.
        iam.add_response("list_users", {"Users": [], "IsTruncated": False}, {"Marker": "next"})
        client = sdk[2][("iam", REGION)]
        native = client.list_users
        def malformed(**kwargs):
            response = native(**kwargs)
            if kwargs:
                response.pop("Users")
            return response
        monkeypatch.setattr(client, "list_users", malformed)
    else:
        user = {"Path": "/", "UserName": "review", "UserId": "AIDAREVIEWUSER1234567", "Arn": f"arn:aws:iam::{ACCOUNT}:user/review", "CreateDate": NOW}
        first = {"Users": [user], "IsTruncated": True}
        if fault != "missing_pagination_token":
            first["Marker"] = "next"
        iam.add_response("list_users", first, {})
        if fault == "repeated_pagination_token":
            iam.add_response("list_users", first, {"Marker": "next"})
    read = aws.Requests(options).pages(session, "iam", REGION, "list_users", "Users")
    assert read.status == ("malformed" if fault == "malformed_response" else "partial")
    assert read.error["code"] == fault


def test_timeout_explicit_and_non_read_operation_blocked(sdk, monkeypatch):
    session, add, clients = sdk
    add("iam")
    monkeypatch.setattr(clients[("iam", REGION)], "get_account_summary", lambda **kwargs: (_ for _ in ()).throw(ReadTimeoutError(endpoint_url="https://iam.amazonaws.com")))
    requests = aws.Requests({"retry_attempts": 1})
    assert requests.detail(session, "iam", REGION, "get_account_summary")["collection_status"] == "timeout"
    with pytest.raises(aws.ReadFailure, match="non_read_operation"):
        requests.call(session, "iam", REGION, "create_user", UserName="forbidden")
    assert requests.calls == 1


def test_denial_after_success_retains_partial_evidence(sdk):
    session, add, _ = sdk
    ec2 = add("ec2")
    ec2.add_response("describe_vpcs", {"Vpcs": [{"VpcId": "vpc-1"}], "NextToken": "next"}, {})
    ec2.add_client_error("describe_vpcs", "UnauthorizedOperation", expected_params={"NextToken": "next"})
    read = aws.Requests({}).pages(session, "ec2", REGION, "describe_vpcs", "Vpcs")
    assert read.status == "partial"
    assert read.items == [{"VpcId": "vpc-1"}]
    assert read.error == {"code": "UnauthorizedOperation", "cause_status": "denied"}


def test_identity_failure_never_reads_service_or_default(sdk):
    session, add, _ = sdk
    add("sts").add_client_error("get_caller_identity", "InvalidClientTokenId", "do not leak token", expected_params={})
    snapshot = aws.collect({"provider": "aws", "scopes": [ACCOUNT], "auth": {"profile": "bad"}}, ["vpc"])
    assert envelope(snapshot, "aws_account")["status"] == "denied"
    assert envelope(snapshot, "vpc")["status"] == "denied"
    assert snapshot["metadata"]["calls"] == 1
    assert snapshot["metadata"]["caller_identities"] == []
    assert "do not leak" not in json.dumps(snapshot)


def test_access_keys_usage_redacted_and_missing_profile_explicit(sdk):
    session, add, _ = sdk
    add("sts").add_response("get_caller_identity", IDENTITY, {})
    iam = add("iam")
    iam.add_response("get_account_authorization_details", {"UserDetailList": [{"Path": "/", "UserName": "review", "UserId": "AIDAREVIEWUSER1234567", "Arn": f"arn:aws:iam::{ACCOUNT}:user/review", "CreateDate": NOW, "UserPolicyList": [{"PolicyName": "audit", "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": []})}]}], "IsTruncated": False}, {})
    key = "AKIAMETADATAKEYONLY"
    iam.add_response("list_access_keys", {"AccessKeyMetadata": [{"UserName": "review", "AccessKeyId": key, "Status": "Active", "CreateDate": NOW}]}, {"UserName": "review"})
    iam.add_response("get_access_key_last_used", {"UserName": "review", "AccessKeyLastUsed": {"LastUsedDate": NOW, "ServiceName": "s3", "Region": REGION}}, {"AccessKeyId": key})
    iam.add_client_error("get_login_profile", "NoSuchEntity", expected_params={"UserName": "review"})
    iam.add_response("list_mfa_devices", {"MFADevices": []}, {"UserName": "review"})
    snapshot = aws.collect({"provider": "aws", "scopes": [REGION], "options": {"service_concurrency": 1}}, ["iam_user"])
    user = envelope(snapshot, "iam_user")["items"][0]
    assert user["PolicySources"][0]["source_type"] == "inline_policy"
    assert user["AccessKeys"]["items"][0]["LastUsed"]["AccessKeyLastUsed"]["ServiceName"] == "s3"
    assert len(user["AccessKeys"]["items"][0]["AccessKeyFingerprint"]) == 64
    assert key not in json.dumps(snapshot)
    assert user["LoginProfile"]["absent"] is True


def test_secret_metadata_only_and_lambda_environment_redaction(sdk):
    session, add, _ = sdk
    secret_arn = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:metadata-only-123456"
    sm = add("secretsmanager")
    sm.add_response("list_secrets", {"SecretList": [{"ARN": secret_arn, "Name": "metadata-only", "KmsKeyId": "key-1"}]}, {})
    sm.add_response("describe_secret", {"ARN": secret_arn, "Name": "metadata-only"}, {"SecretId": secret_arn})
    sm.add_response("get_resource_policy", {"ARN": secret_arn, "Name": "metadata-only", "ResourcePolicy": '{"Version":"2012-10-17","Statement":[]}'}, {"SecretId": secret_arn})
    requests = aws.Requests({})
    read = requests.pages(session, "secretsmanager", REGION, "list_secrets", "SecretList")
    enriched = aws._enrich(requests, session, REGION, "secret", read.items, account=ACCOUNT, partition="aws")
    assert enriched[0]["RotationEnabled"] is False
    assert enriched[0]["_coverage"]["RotationEnabled"]["interpretation"] == "documented_never_configured_rotation"
    assert enriched[0]["Policy"]["ResourcePolicy"]["Statement"] == []
    safe = aws._safe({"Environment": {"Variables": {"PASSWORD": "env-secret"}}, "Code": {"Location": "signed-download-url"}, "SecretString": "stored-secret", "FunctionName": "audit"})
    assert safe == {"FunctionName": "audit"}
    assert requests.calls == 3


def test_elbv2_state_code_is_narrowly_projected_through_privacy_filter(monkeypatch):
    from peaso.collectors import aws_request_pool

    monkeypatch.setattr(aws_request_pool, 'ordered_map',
                        lambda requests, items, enrich: [enrich(item) for item in items])

    class ReadOnlyRequests:
        def detail(self, *args, **kwargs):
            return {'collection_status': 'empty'}

        def pages(self, *args, **kwargs):
            return aws.ReadResult([], 'empty')

    arn = f'arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/web/1'
    raw = {'LoadBalancerArn': arn, 'State': {'Code': 'active', 'Reason': 'Serving'},
           'Code': {'Location': 'private-download-url'}}
    item = aws._enrich(ReadOnlyRequests(), object(), REGION, 'load_balancer', [raw],
                       account=ACCOUNT, partition='aws')[0]
    safe = aws._safe(item)
    assert safe['LoadBalancerStateCode'] == 'active'
    assert safe['State'] == {'Reason': 'Serving'}
    assert 'Code' not in safe
    assert 'Code' not in safe['State']


def test_existing_credential_report_no_generation(sdk):
    session, add, _ = sdk
    add("iam").add_response("get_credential_report", {"Content": b"user,arn,password_enabled,mfa_active\nreview,arn:aws:iam::123456789012:user/review,true,false\n", "ReportFormat": "text/csv", "GeneratedTime": NOW}, {})
    requests = aws.Requests({})
    read = aws._credentials_report(requests, session, REGION)
    assert read.status == "collected"
    assert read.items[0]["mfa_active"] == "false"
    assert requests.calls == 1


def test_credential_report_missing_generation_denial_is_explicit(sdk):
    session, add, _ = sdk
    add("iam").add_client_error("get_credential_report", "ReportNotPresent", expected_params={})
    requests = aws.Requests({})
    read = aws._credentials_report(requests, session, REGION)
    assert read.status == "not_collected" and read.items == []
    assert read.error["code"] == "credential_report_generation_disabled"
    assert requests.calls == 1 and requests.evidence_generations == 0


def test_call_and_total_resource_budgets(sdk):
    session, add, _ = sdk
    add("sts").add_response("get_caller_identity", IDENTITY, {})
    snapshot = aws.collect({"provider": "aws", "scopes": [REGION], "options": {"max_calls": 1, "service_concurrency": 1}}, ["aws_account", "vpc"])
    assert snapshot["metadata"]["calls"] == 1
    assert envelope(snapshot, "vpc")["status"] == "not_collected"
    assert envelope(snapshot, "vpc")["error"]["code"] == "call_limit"


def test_missing_explicit_account_target_cannot_use_base_account(sdk):
    session, add, _ = sdk
    add("sts").add_response("get_caller_identity", IDENTITY, {})
    target = "999999999999"
    snapshot = aws.collect({"provider": "aws", "scopes": [target]}, ["vpc"])
    assert snapshot["scopes"] == [f"{target}/{REGION}"]
    assert all(c["items"] == [] for c in snapshot["collections"])
    assert snapshot["metadata"]["calls"] == 1


def test_invalid_selected_profile_does_not_fallback(monkeypatch):
    calls = []
    def session(**kwargs):
        calls.append(kwargs)
        raise RuntimeError("private credential message")
    monkeypatch.setattr(boto3, "Session", session)
    snapshot = aws.collect({"provider": "aws", "scopes": [ACCOUNT], "auth": {"profile": "absent"}}, ["vpc"])
    assert calls == [{"region_name": None, "profile_name": "absent"}]
    assert envelope(snapshot, "vpc")["status"] == "unknown"
    assert "private credential" not in json.dumps(snapshot)


@pytest.mark.parametrize("options", [{"max_calls": True}, {"service_concurrency": 33}, {"region_concurrency": 0}, {"scope_concurrency": 9}, {"regions": ["not-a-region"]}, {"inventories": ["secret_values"]}])
def test_invalid_bounds_rejected_before_network(options):
    with pytest.raises(ValueError):
        aws.collect({"provider": "aws", "options": options})


def assumed_credentials():
    return {"Credentials": {"AccessKeyId": "ASIAASSUMED123456789", "SecretAccessKey": "assumed-secret-do-not-leak", "SessionToken": "assumed-token-do-not-leak", "Expiration": NOW}}


def test_role_chain_external_id_session_name_and_identity(sdk):
    session, add, _ = sdk
    sts = add("sts")
    intermediate = f"arn:aws:iam::{ACCOUNT}:role/platform-scanner"
    target = f"arn:aws:iam::{ACCOUNT}:role/audit"
    sts.add_response("assume_role", assumed_credentials(), {"RoleArn": intermediate, "RoleSessionName": "peaso-scan", "ExternalId": "first-external"})
    sts.add_response("assume_role", assumed_credentials(), {"RoleArn": target, "RoleSessionName": "target-session", "ExternalId": "second-external"})
    sts.add_response("get_caller_identity", {**IDENTITY, "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/audit/target-session"}, {})
    snapshot = aws.collect({"provider": "aws", "scopes": [ACCOUNT], "auth": {"role_session_name": "peaso-scan", "role_chain": [{"role_arn": intermediate, "external_id": "first-external"}, {"role_arn": target, "external_id": "second-external", "role_session_name": "target-session"}]}}, [])
    assert snapshot["metadata"]["calls"] == 3
    assert "assumed-role/audit/target-session" in snapshot["metadata"]["caller_identities"][0]["Arn"]
    serialized = json.dumps(snapshot)
    assert "assumed-secret-do-not-leak" not in serialized
    assert "assumed-token-do-not-leak" not in serialized
    assert "ASIAASSUMED123456789" not in serialized


def test_assume_role_failure_no_base_credential_fallback(sdk):
    session, add, _ = sdk
    target = f"arn:aws:iam::{ACCOUNT}:role/audit"
    add("sts").add_client_error("assume_role", "AccessDenied", "private-external-id", expected_params={"RoleArn": target, "RoleSessionName": "peaso-read-only", "ExternalId": "private-external-id"})
    snapshot = aws.collect({"provider": "aws", "scopes": [ACCOUNT], "auth": {"role_arn": target, "external_id": "private-external-id"}}, ["vpc"])
    assert envelope(snapshot, "vpc")["status"] == "denied"
    assert snapshot["metadata"]["caller_identities"] == []
    assert snapshot["metadata"]["calls"] == 1
    assert "private-external-id" not in json.dumps(snapshot)


def test_hosted_fanout_refuses_unprotected_trust_and_continues(sdk, monkeypatch):
    captured = []
    original_init = aws.Requests.__init__
    def capture_requests(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        captured.append(self)
    monkeypatch.setattr(aws.Requests, "__init__", capture_requests)
    original_session = boto3.Session
    assumed_keys = []
    def capture_session(*args, **kwargs):
        assumed_keys.append(kwargs.get("aws_access_key_id"))
        return original_session(*args, **kwargs)
    monkeypatch.setattr(boto3, "Session", capture_session)
    _, add, _ = sdk
    unsafe, safe = (f"arn:aws:iam::{account}:role/Audit" for account in ("222222222222", "333333333333"))
    sts = add("sts")
    sts.add_response("get_caller_identity", {"Account": "111122223333",
        "Arn": "arn:aws:sts::111122223333:assumed-role/collector/scan",
        "UserId": "AROACOLLECTOR123456789:scan"}, {})
    unsafe_credentials = assumed_credentials()
    unsafe_credentials["Credentials"]["AccessKeyId"] = "ASIAUNSAFE123456789"
    sts.add_response("assume_role", unsafe_credentials, {"RoleArn": unsafe, "RoleSessionName": "peaso-read-only"})
    sts.add_client_error("assume_role", "AccessDenied", "External ID required", expected_params={"RoleArn": safe, "RoleSessionName": "peaso-read-only"})
    sts.add_client_error("assume_role", "AccessDenied", expected_params={"RoleArn": safe, "RoleSessionName": "peaso-read-only", "ExternalId": ANY})
    sts.add_response("assume_role", assumed_credentials(), {"RoleArn": safe, "RoleSessionName": "peaso-read-only", "ExternalId": "peaso-server-only"})
    sts.add_response("get_caller_identity", {"Account": "333333333333", "Arn": "arn:aws:sts::333333333333:assumed-role/Audit/peaso-read-only", "UserId": "AROASAFEROLE123456789:peaso-read-only"}, {})
    add("ec2").add_response("describe_vpcs", {"Vpcs": []}, {})
    snapshot = aws.collect({"provider": "aws", "scopes": ["222222222222", "333333333333"],
        "auth": {"method": "task_role", "external_id": "peaso-server-only", "assume_roles": [unsafe, safe]},
        "options": {"hosted": True, "include_source_account": True, "regions": [REGION]}}, ["vpc"])
    assert snapshot["metadata"]["authentication_errors"] == [{"account": "222222222222", "role_arn": unsafe,
        "error": {"code": "external_id_not_required_by_trust"}, "status": "denied"}]
    assert next(c for c in snapshot["collections"] if c["type"] == "vpc" and c["scope"].startswith("222222222222/"))["status"] == "denied"
    assert next(c for c in snapshot["collections"] if c["type"] == "vpc" and c["scope"].startswith("333333333333/"))["status"] == "empty"
    assert "111122223333" not in {identity["Account"] for identity in snapshot["metadata"]["caller_identities"]}
    assert "peaso-server-only" not in json.dumps(snapshot)
    assert "ASIAUNSAFE123456789" not in repr(captured[0]._cache)
    assert not any("222222222222" in key[-1] for key in captured[0]._cache)
    assert assumed_keys == ["ASIAASSUMED123456789"]


def test_hosted_all_targets_refused_has_no_resource_reads(sdk):
    _, add, clients = sdk
    role = "arn:aws:iam::222222222222:role/Audit"
    sts = add("sts")
    sts.add_response("get_caller_identity", {"Account": "111122223333",
        "Arn": "arn:aws:sts::111122223333:assumed-role/collector/scan",
        "UserId": "AROACOLLECTOR123456789:scan"}, {})
    sts.add_response("assume_role", assumed_credentials(),
        {"RoleArn": role, "RoleSessionName": "peaso-read-only"})
    snapshot = aws.collect({"provider": "aws", "scopes": ["222222222222"],
        "auth": {"method": "task_role", "external_id": "peaso-server-only", "assume_roles": [role]},
        "options": {"hosted": True, "include_source_account": False, "regions": [REGION]}}, ["vpc"])
    assert nothing_readable(snapshot)
    assert snapshot["metadata"]["calls"] == 2
    assert set(clients) == {("sts", REGION)}
    assert snapshot["metadata"]["authentication_errors"] == [{"account": "222222222222", "role_arn": role,
        "error": {"code": "external_id_not_required_by_trust"}, "status": "denied"}]


def test_hosted_second_role_same_account_skips_before_any_sts(sdk):
    _, add, _ = sdk
    account = "222233334444"
    first = f"arn:aws:iam::{account}:role/RoleA"
    second = f"arn:aws:iam::{account}:role/RoleB"
    sts = add("sts")
    sts.add_response("get_caller_identity", IDENTITY, {})
    sts.add_client_error("assume_role", "AccessDenied", expected_params={
        "RoleArn": first, "RoleSessionName": "peaso-read-only"})
    sts.add_client_error("assume_role", "AccessDenied", expected_params={"RoleArn": first, "RoleSessionName": "peaso-read-only", "ExternalId": ANY})
    sts.add_response("assume_role", assumed_credentials(), {
        "RoleArn": first, "RoleSessionName": "peaso-read-only", "ExternalId": "peaso-server-only"})
    sts.add_response("get_caller_identity", {"Account": account,
        "Arn": f"arn:aws:sts::{account}:assumed-role/RoleA/peaso-read-only",
        "UserId": "AROASAFEROLE12345678A:peaso-read-only"}, {})
    add("ec2").add_response("describe_vpcs", {"Vpcs": [{"VpcId": "vpc-role-a"}]}, {})
    add("ec2").add_response("describe_vpc_attribute", {"VpcId": "vpc-role-a", "EnableDnsSupport": {"Value": True}},
        {"VpcId": "vpc-role-a", "Attribute": "enableDnsSupport"})
    add("ec2").add_response("describe_vpc_attribute", {"VpcId": "vpc-role-a", "EnableDnsHostnames": {"Value": True}},
        {"VpcId": "vpc-role-a", "Attribute": "enableDnsHostnames"})
    snapshot = aws.collect({"provider": "aws", "scopes": [account],
        "auth": {"method": "task_role", "external_id": "peaso-server-only", "assume_roles": [first, second]},
        "options": {"hosted": True, "include_source_account": True, "regions": [REGION], "service_concurrency": 1}}, ["vpc"])
    assert validate(snapshot) == snapshot
    vpc = next(c for c in snapshot["collections"] if c["type"] == "vpc")
    assert vpc["status"] == "collected" and [row["VpcId"] for row in vpc["items"]] == ["vpc-role-a"]
    assert "authority_reads" not in vpc
    assert snapshot["metadata"]["role_target_selection"]["duplicate_account_targets"] == [
        {"account": account, "role_arn": second, "status": "not_collected", "code": "duplicate_account_target"}]
    assert snapshot["metadata"]["scan_coverage"] == [{"level": "credential_target", "scope": account,
        "account": account, "role_arn": second, "status": "not_collected", "code": "duplicate_account_target",
        "error_code": "duplicate_account_target"}]
    assert len(snapshot["metadata"]["caller_identities"]) == 1
    assert snapshot["metadata"]["calls"] == 8


def test_hosted_failed_first_role_allows_second_role_same_account(sdk):
    _, add, _ = sdk
    account = "222233334444"
    first = f"arn:aws:iam::{account}:role/RoleA"
    second = f"arn:aws:iam::{account}:role/RoleB"
    sts = add("sts")
    sts.add_response("get_caller_identity", IDENTITY, {})
    sts.add_client_error("assume_role", "AccessDenied", expected_params={
        "RoleArn": first, "RoleSessionName": "peaso-read-only"})
    sts.add_client_error("assume_role", "AccessDenied", expected_params={"RoleArn": first, "RoleSessionName": "peaso-read-only", "ExternalId": ANY})
    sts.add_client_error("assume_role", "AccessDenied", expected_params={
        "RoleArn": first, "RoleSessionName": "peaso-read-only", "ExternalId": "peaso-server-only"})
    sts.add_client_error("assume_role", "AccessDenied", expected_params={
        "RoleArn": second, "RoleSessionName": "peaso-read-only"})
    sts.add_client_error("assume_role", "AccessDenied", expected_params={"RoleArn": second, "RoleSessionName": "peaso-read-only", "ExternalId": ANY})
    sts.add_response("assume_role", assumed_credentials(), {
        "RoleArn": second, "RoleSessionName": "peaso-read-only", "ExternalId": "peaso-server-only"})
    sts.add_response("get_caller_identity", {"Account": account,
        "Arn": f"arn:aws:sts::{account}:assumed-role/RoleB/peaso-read-only",
        "UserId": "AROASAFEROLE12345678B:peaso-read-only"}, {})
    add("ec2").add_response("describe_vpcs", {"Vpcs": [{"VpcId": "vpc-role-b"}]}, {})
    snapshot = aws.collect({"provider": "aws", "scopes": [account],
        "auth": {"method": "task_role", "external_id": "peaso-server-only", "assume_roles": [first, second]},
        "options": {"hosted": True, "regions": [REGION], "service_concurrency": 1}}, ["vpc"])
    vpc = next(c for c in snapshot["collections"] if c["type"] == "vpc")
    assert vpc["status"] == "collected" and [row["VpcId"] for row in vpc["items"]] == ["vpc-role-b"]
    assert snapshot["metadata"]["role_target_selection"]["duplicate_account_targets"] == []
    assert snapshot["metadata"]["authentication_errors"] == [{"account": account,
        "role_arn": first, "error": {"code": "AccessDenied"}, "status": "denied"}]


def test_checked_source_account_skips_assumed_role_in_same_account(sdk):
    _, add, _ = sdk
    role = f"arn:aws:iam::{ACCOUNT}:role/OtherAudit"
    add("sts").add_response("get_caller_identity", IDENTITY, {})
    add("ec2").add_response("describe_vpcs", {"Vpcs": []}, {})
    snapshot = aws.collect({"provider": "aws", "scopes": [ACCOUNT],
        "auth": {"assume_roles": [role]}, "options": {"regions": [REGION], "include_source_account": True}}, ["vpc"])
    assert snapshot["metadata"]["role_target_selection"]["duplicate_account_targets"][0]["role_arn"] == role
    assert snapshot["metadata"]["caller_identities"] == [IDENTITY]


def test_uncached_trust_probe_obeys_budget_and_read_guard(sdk):
    session, add, _ = sdk
    role = "arn:aws:iam::222222222222:role/Audit"
    requests = aws.Requests({"max_calls": 1})
    add("sts").add_response("assume_role", assumed_credentials(), {"RoleArn": role, "RoleSessionName": "peaso-read-only", "DurationSeconds": 900})
    assert requests.call(session, "sts", REGION, "assume_role", _uncached_credential_exchange=True,
        RoleArn=role, RoleSessionName="peaso-read-only", DurationSeconds=900)["Credentials"]["AccessKeyId"]
    assert requests.calls == 1
    assert requests._cache == {}
    with pytest.raises(aws.ReadFailure, match="call_limit"):
        requests.call(session, "sts", REGION, "assume_role", _uncached_credential_exchange=True,
            RoleArn=role, RoleSessionName="peaso-read-only", DurationSeconds=900)
    with pytest.raises(aws.ReadFailure, match="uncached_exchange_requires_assume_role"):
        requests.call(session, "sts", REGION, "get_caller_identity", _uncached_credential_exchange=True)


def test_hosted_owned_target_never_reaches_sts_assume_role(sdk, monkeypatch):
    from peaso.server.validation import COLLECTOR_ROLE_ARN
    assumed = []
    original_assume = aws._assume
    def record_assume(requests, source, region, target, defaults):
        assumed.append(target["role_arn"])
        return original_assume(requests, source, region, target, defaults)
    monkeypatch.setattr(aws, "_assume", record_assume)
    _, add, _ = sdk
    add("sts").add_response("get_caller_identity", IDENTITY, {})
    snapshot = aws.collect({"provider": "aws", "scopes": ["111122223333"],
        "auth": {"method": "task_role", "external_id": "peaso-server-only",
                 "assume_roles": ["arn:aws:iam::111122223333:role/Internal"]},
        "options": {"hosted": True, "regions": [REGION]}}, ["vpc"])
    assert snapshot["metadata"]["calls"] == 1
    assert assumed == [COLLECTOR_ROLE_ARN]
    assert snapshot["metadata"]["authentication_errors"][0]["error"]["code"] == "platform_owned_account"


def test_customer_key_fanout_uses_per_target_external_id_and_excludes_source(sdk):
    _, add, _ = sdk
    target = "arn:aws:iam::333333333333:role/Audit"
    sts = add("sts")
    sts.add_response("get_caller_identity", IDENTITY, {})
    sts.add_response("assume_role", assumed_credentials(), {"RoleArn": target, "RoleSessionName": "peaso-read-only", "ExternalId": "customer-id"})
    sts.add_response("get_caller_identity", {"Account": "333333333333", "Arn": "arn:aws:sts::333333333333:assumed-role/Audit/peaso-read-only", "UserId": "AROASAFEROLE123456789:peaso-read-only"}, {})
    add("ec2").add_response("describe_vpcs", {"Vpcs": []}, {})
    snapshot = aws.collect({"provider": "aws", "auth": {"assume_roles": [{"role_arn": target, "external_id": "customer-id"}]},
        "options": {"include_source_account": False, "regions": [REGION]}}, ["vpc"])
    assert snapshot["scopes"] == ["333333333333/us-east-1"]


def test_explicit_account_region_pairs_not_broadened(sdk):
    session, add, _ = sdk
    add("sts", "eu-west-1").add_response("get_caller_identity", IDENTITY, {})
    add("ec2", "us-east-1").add_response("describe_vpcs", {"Vpcs": []}, {})
    options = {"regions": ["eu-west-1"]}
    snapshot = aws.collect({"provider": "aws", "scopes": [f"{ACCOUNT}/us-east-1"], "options": options}, ["vpc"])
    assert snapshot["scopes"] == [f"{ACCOUNT}/us-east-1"]
    assert options == {"regions": ["eu-west-1"]}
    assert snapshot["metadata"]["calls"] == 2


def test_total_resources_cap_includes_identity(sdk):
    session, add, _ = sdk
    add("sts").add_response("get_caller_identity", IDENTITY, {})
    add("ec2").add_response("describe_vpcs", {"Vpcs": [{"VpcId": "vpc-1"}, {"VpcId": "vpc-2"}]}, {})
    snapshot = aws.collect({"provider": "aws", "scopes": [REGION], "options": {"max_resources": 2}}, ["vpc"])
    assert snapshot["metadata"]["resource_count"] == 2
    assert envelope(snapshot, "vpc")["status"] == "partial"
    assert envelope(snapshot, "vpc")["error"]["code"] == "resource_limit"
    assert len(envelope(snapshot, "vpc")["items"]) == 1


def test_s3_native_security_detail_and_absent_policy(sdk):
    session, add, _ = sdk
    s3 = add("s3")
    s3.add_response("list_buckets", {"Buckets": [{"Name": "audit-bucket", "CreationDate": NOW}]}, {})
    s3.add_response("get_bucket_location", {"LocationConstraint": ""}, {"Bucket": "audit-bucket"})
    s3.add_response("get_public_access_block", {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}, {"Bucket": "audit-bucket"})
    s3.add_client_error("get_bucket_policy_status", "NoSuchBucketPolicy", expected_params={"Bucket": "audit-bucket"})
    s3.add_client_error("get_bucket_policy", "NoSuchBucketPolicy", expected_params={"Bucket": "audit-bucket"})
    s3.add_response("get_bucket_encryption", {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}, {"Bucket": "audit-bucket"})
    s3.add_response("get_bucket_versioning", {"Status": "Enabled"}, {"Bucket": "audit-bucket"})
    s3.add_response("get_bucket_acl", {"Grants": []}, {"Bucket": "audit-bucket"})
    s3.add_response("get_bucket_ownership_controls", {"OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}}, {"Bucket": "audit-bucket"})
    s3.add_response("get_bucket_logging", {}, {"Bucket": "audit-bucket"})
    s3.add_client_error("get_bucket_lifecycle_configuration", "NoSuchLifecycleConfiguration", expected_params={"Bucket": "audit-bucket"})
    s3.add_response("get_bucket_notification_configuration", {}, {"Bucket": "audit-bucket"})
    s3.add_client_error("get_bucket_replication", "ReplicationConfigurationNotFoundError", expected_params={"Bucket": "audit-bucket"})
    s3.add_client_error("get_object_lock_configuration", "ObjectLockConfigurationNotFoundError", expected_params={"Bucket": "audit-bucket"})
    s3.add_client_error("get_bucket_tagging", "NoSuchTagSet", expected_params={"Bucket": "audit-bucket"})
    result = aws._buckets(aws.Requests({}), session, REGION)
    assert result.status == "collected"
    assert result.items[0]["Policy"]["collection_status"] == "empty"
    assert result.items[0]["Policy"]["absent"] is True
    assert result.items[0]["Encryption"]["ServerSideEncryptionConfiguration"]["Rules"][0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] == "AES256"


def test_session_pins_selected_profile_credentials(monkeypatch):
    calls = []
    credentials = SimpleNamespace(method="sso", get_frozen_credentials=lambda: SimpleNamespace(access_key="sso-key", secret_key="sso-secret", token="sso-token"))
    selected = SimpleNamespace(get_credentials=lambda: credentials)
    pinned = SimpleNamespace()
    def new_session(**kwargs):
        calls.append(kwargs)
        return selected if "profile_name" in kwargs else pinned
    monkeypatch.setattr(boto3, "Session", new_session)
    resolved, method = aws._session({"method": "sso", "profile": "chosen-sso"}, REGION)
    assert resolved is pinned
    assert method == "sso"
    assert calls == [{"region_name": REGION, "profile_name": "chosen-sso"}, {"aws_access_key_id": "sso-key", "aws_secret_access_key": "sso-secret", "aws_session_token": "sso-token", "region_name": REGION}]


@pytest.mark.parametrize("auth", [{"method": "profile"}, {"method": "access_keys"}, {"aws_access_key_id": "only-key"}, {"aws_access_key_id": "key", "aws_secret_access_key": "secret", "profile": "ambiguous"}])
def test_incomplete_or_ambiguous_auth_does_not_resolve_default(auth, monkeypatch):
    monkeypatch.setattr(boto3, "Session", lambda **kwargs: pytest.fail("default resolution forbidden"))
    with pytest.raises(ValueError):
        aws._session(auth, REGION)


def test_sensitive_value_and_mutation_apis_blocked(sdk):
    session, add, _ = sdk
    requests = aws.Requests({})
    for service, operation in [("secretsmanager", "get_secret_value"), ("s3", "get_object"), ("logs", "get_log_events"), ("accessanalyzer", "create_analyzer"), ("ec2", "create_network_insights_path")]:
        with pytest.raises(aws.ReadFailure, match="non_read_operation"):
            requests.call(session, service, REGION, operation)
    assert requests.calls == 0


@pytest.mark.parametrize("operation", ["create_user", "delete_user", "attach_role_policy", "put_user_policy", "update_assume_role_policy"])
def test_mutation_rejected_before_client_side_effects_even_if_allowlist_accidentally_contains_it(monkeypatch, operation):
    monkeypatch.setattr(aws, "READ_ACTIONS", aws.READ_ACTIONS | {("iam", operation)})
    requests = aws.Requests({})
    monkeypatch.setattr(requests, "client", lambda *args: pytest.fail("dangerous SDK client was constructed"))
    with pytest.raises(aws.ReadFailure, match="non_read_operation"):
        requests.call(object(), "iam", REGION, operation)
    assert requests.calls == 0
    assert requests._cache == {}


@pytest.mark.parametrize("service,operation", [("secretsmanager", "get_secret_value"), ("ssm", "get_parameters"), ("s3", "get_object"), ("logs", "get_log_events"), ("ecr", "get_authorization_token")])
def test_value_api_rejected_before_client_side_effects_even_with_accidental_allowlist_entry(monkeypatch, service, operation):
    monkeypatch.setattr(aws, "READ_ACTIONS", aws.READ_ACTIONS | {(service, operation)})
    requests = aws.Requests({})
    monkeypatch.setattr(requests, "client", lambda *args: pytest.fail("secret/content SDK client was constructed"))
    with pytest.raises(aws.ReadFailure, match="non_read_operation"):
        requests.call(object(), service, REGION, operation)
    assert requests.calls == 0


def test_organization_accessible_role_requires_explicit_name_and_verifies_account(sdk):
    session, add, _ = sdk
    target = "999999999999"
    sts = add("sts")
    sts.add_response("get_caller_identity", IDENTITY, {})
    sts.add_response("assume_role", assumed_credentials(), {"RoleArn": f"arn:aws:iam::{target}:role/explicit-audit", "RoleSessionName": "peaso-read-only"})
    sts.add_response("get_caller_identity", {"Account": target, "Arn": f"arn:aws:sts::{target}:assumed-role/explicit-audit/peaso-read-only", "UserId": "AROAREVIEWUSER1234567:peaso-read-only"}, {})
    add("organizations").add_response("list_accounts", {"Accounts": [{"Id": ACCOUNT, "State": "ACTIVE"}, {"Id": target, "State": "ACTIVE"}, {"Id": "888888888888", "State": "SUSPENDED"}]}, {})
    add("ec2").add_response("describe_regions", {"Regions": [{"RegionName": REGION, "OptInStatus": "opt-in-not-required"}]}, {"AllRegions": True})
    add("ec2").add_response("describe_vpcs", {"Vpcs": []}, {})
    snapshot = aws.collect({"provider": "aws", "scopes": [target], "options": {"organization_role_name": "explicit-audit"}}, ["vpc"])
    assert snapshot["scopes"] == [f"{target}/{REGION}"]
    assert snapshot["metadata"]["caller_identities"][0]["Account"] == target
    assert snapshot["metadata"]["calls"] == 6
    assert snapshot["metadata"]["organization_discovery"]["accounts_seen"] == 3


@pytest.mark.parametrize("hosted,scheduled_count", [(False, 51), (True, 50)])
def test_organization_discovery_51_distinct_targets_respects_hosted_limit(sdk, hosted, scheduled_count):
    _, add, _ = sdk
    accounts = [f"{200000000000 + n:012d}" for n in range(51)]
    roles = [f"arn:aws:iam::{account}:role/audit" for account in accounts]
    sts = add("sts")
    sts.add_response("get_caller_identity", IDENTITY, {})
    for role in roles[:scheduled_count]:
        sts.add_client_error("assume_role", "AccessDenied", expected_params={"RoleArn": role, "RoleSessionName": "peaso-read-only"})
    add("organizations").add_response("list_accounts", {"Accounts": [{"Id": account, "State": "ACTIVE"} for account in accounts]}, {})
    snapshot = aws.collect({"provider": "aws", "auth": {"aws_access_key_id": "customer-key", "aws_secret_access_key": "customer-secret"},
        "options": {"organization_role_name": "audit", "include_source_account": False,
        "regions": [REGION], "hosted": hosted}}, [])
    selection = snapshot["metadata"]["role_target_selection"]
    assert selection == {"requested": 51, "scheduled_limit": 50 if hosted else None,
        "scheduled": scheduled_count, "omitted": 51 - scheduled_count,
        "omitted_role_arns": roles[scheduled_count:], "status": "partial" if hosted else "collected",
        "duplicate_account_targets": []}
    assert snapshot["metadata"]["calls"] == scheduled_count + 2
    assert {error["account"] for error in snapshot["metadata"]["authentication_errors"]} == set(accounts)
    last = next(c for c in snapshot["collections"] if c["type"] == "aws_account" and c["scope"] == f"{accounts[50]}/global")
    assert last["error"]["code"] == ("role_target_limit" if hosted else "AccessDenied")


def test_local_explicit_60_role_targets_have_no_implicit_fanout_cap(sdk):
    _, add, _ = sdk
    accounts = [f"{300000000000 + n:012d}" for n in range(60)]
    roles = [f"arn:aws:iam::{account}:role/audit" for account in accounts]
    sts = add("sts")
    sts.add_response("get_caller_identity", IDENTITY, {})
    for role in roles:
        sts.add_client_error("assume_role", "AccessDenied", expected_params={"RoleArn": role,
            "RoleSessionName": "peaso-read-only"})
    snapshot = aws.collect({"provider": "aws", "auth": {"assume_roles": roles},
        "options": {"include_source_account": False, "regions": [REGION]}}, [])
    assert snapshot["metadata"]["role_target_selection"] == {"requested": 60, "scheduled_limit": None,
        "scheduled": 60, "omitted": 0, "omitted_role_arns": [], "status": "collected",
        "duplicate_account_targets": []}
    assert snapshot["metadata"]["calls"] == 61
    assert {error["account"] for error in snapshot["metadata"]["authentication_errors"]} == set(accounts)
    assert all(error["error"]["code"] == "AccessDenied" for error in snapshot["metadata"]["authentication_errors"])


def test_hosted_worker_injects_trusted_scan_flag_after_validation(monkeypatch, tmp_path):
    import threading
    import time
    from peaso.worker import Worker

    auth = {"method": "access_keys", "aws_access_key_id": "customer-key", "aws_secret_access_key": "customer-secret"}
    private = {"auth": auth, "options": {"organization_role_name": "audit"}}
    captured, finished = [], []
    job = {"id": "scan", "tenant": "tenant", "owner": "owner", "deadline": time.time() + 60,
        "data": json.dumps({"ai_enabled": False}), "connector": json.dumps({"data": {"provider": "aws"}, "auth": "encrypted"})}

    class Store:
        def claim(self, *args, **kwargs):
            return job
        def public_job(self, row):
            return {"timeline": []}
        def checkpoint_collections(self, tenant, ident):
            return []
        def heartbeat(self, *args):
            return True
        def job(self, *args):
            return {"status": "collecting"}
        def finish(self, *args, **kwargs):
            finished.append((args, kwargs))

    class Connection:
        def close(self):
            pass
        def poll(self, timeout):
            return True
        def recv(self):
            return True, "artifact"

    class Process:
        def __init__(self, **kwargs):
            captured.append(kwargs["args"][1]["connector"])
            self.alive = False
        def start(self):
            self.alive = True
        def is_alive(self):
            return self.alive
        def terminate(self):
            self.alive = False
        def join(self, timeout):
            pass

    class Context:
        @staticmethod
        def Pipe(duplex):
            return Connection(), Connection()

    Context.Process = Process
    monkeypatch.setattr("peaso.worker.multiprocessing.get_context", lambda _: Context())
    worker = Worker.__new__(Worker)
    worker.role = "collector"
    worker.settings = SimpleNamespace(auth_mode="cognito", lease_seconds=30,
                                     state_dir=tmp_path, identity_dir=tmp_path / "identities")
    worker.store = Store()
    worker.artifacts = SimpleNamespace(bucket="unused", kms_key=None)
    worker.cipher = SimpleNamespace(decrypt=lambda _: private)
    worker.stopping = threading.Event()
    assert worker.run_once("tenant", "scan")
    assert len(captured) == len(finished) == 1
    assert captured[0]["options"] == {"organization_role_name": "audit", "hosted": True}
    assert captured[0]["auth"] == auth
    assert private["options"] == {"organization_role_name": "audit"}


@pytest.mark.parametrize("hosted,page_count", [(False, 11), (True, 10)])
def test_organization_discovery_paginates_local_and_bounds_hosted(sdk, hosted, page_count):
    _, add, _ = sdk
    add("sts").add_response("get_caller_identity", IDENTITY, {})
    organizations = add("organizations")
    for page in range(page_count):
        arguments = {} if page == 0 else {"NextToken": f"page-{page}"}
        response = {"Accounts": []}
        if page < 10:
            response["NextToken"] = f"page-{page + 1}"
        organizations.add_response("list_accounts", response, arguments)
    snapshot = aws.collect({"provider": "aws", "options": {"hosted": hosted,
        "organization_role_name": "audit", "include_source_account": False, "regions": [REGION]}}, [])
    discovery = snapshot["metadata"]["organization_discovery"]
    assert discovery["status"] == ("not_collected" if hosted else "empty")
    assert discovery["error"] == ({"code": "page_limit", "cause_status": "not_collected"} if hosted else None)
    assert snapshot["metadata"]["role_target_selection"]["status"] == ("partial" if hosted else "collected")
    assert snapshot["metadata"]["calls"] == page_count + 1


def test_explicit_and_discovered_duplicate_role_uses_one_target_slot(sdk):
    _, add, _ = sdk
    account = "222222222222"
    role = f"arn:aws:iam::{account}:role/audit"
    sts = add("sts")
    sts.add_response("get_caller_identity", IDENTITY, {})
    sts.add_client_error("assume_role", "AccessDenied", expected_params={"RoleArn": role,
        "RoleSessionName": "peaso-read-only", "ExternalId": "explicit-id"})
    add("organizations").add_response("list_accounts", {"Accounts": [{"Id": account, "State": "ACTIVE"}]}, {})
    snapshot = aws.collect({"provider": "aws", "auth": {"assume_roles": [{"role_arn": role, "external_id": "explicit-id"}]},
        "options": {"organization_role_name": "audit", "include_source_account": False, "regions": [REGION]}}, [])
    assert snapshot["metadata"]["role_target_selection"]["requested"] == 1
    assert snapshot["metadata"]["role_target_selection"]["omitted"] == 0
    assert snapshot["metadata"]["calls"] == 3


@pytest.mark.parametrize("include_source,scopes,source_expected", [
    (True, ["222222222222"], False), (False, [ACCOUNT], False), (True, [ACCOUNT], True),
])
def test_source_checkbox_respects_explicit_account_scope(sdk, include_source, scopes, source_expected):
    _, add, _ = sdk
    add("sts").add_response("get_caller_identity", IDENTITY, {})
    snapshot = aws.collect({"provider": "aws", "scopes": scopes,
        "options": {"include_source_account": include_source, "regions": [REGION]}}, [])
    assert (ACCOUNT in {identity["Account"] for identity in snapshot["metadata"]["caller_identities"]}) is source_expected
    if scopes == [ACCOUNT]:
        source = envelope(snapshot, "aws_account")
        assert (source["status"] == "collected") is source_expected
        if not source_expected:
            assert source["error"]["code"] == "account_role_not_configured"


def test_cross_account_identity_mismatch_fails_without_base_fallback(sdk):
    session, add, _ = sdk
    target = "999999999999"
    role = f"arn:aws:iam::{target}:role/audit"
    sts = add("sts")
    sts.add_response("get_caller_identity", IDENTITY, {})
    sts.add_response("assume_role", assumed_credentials(), {"RoleArn": role, "RoleSessionName": "peaso-read-only"})
    sts.add_response("get_caller_identity", IDENTITY, {})
    snapshot = aws.collect({"provider": "aws", "scopes": [target], "auth": {"assume_roles": [role]}}, ["vpc"])
    collection = next(c for c in snapshot["collections"] if c["type"] == "vpc")
    assert collection["status"] == "denied"
    assert collection["error"]["code"] == "account_identity_mismatch"
    assert snapshot["metadata"]["caller_identities"] == []
    assert snapshot["metadata"]["calls"] == 3


def test_vpn_pre_shared_keys_and_gateway_xml_never_serialized():
    response = {"VpnConnectionId": "vpn-1", "CustomerGatewayConfiguration": "<pre_shared_key>vpn-secret</pre_shared_key>", "Options": {"TunnelOptions": [{"OutsideIpAddress": "203.0.113.1", "PreSharedKey": "vpn-secret"}]}}
    safe = aws._safe(response)
    assert "vpn-secret" not in json.dumps(safe)
    assert safe == {"VpnConnectionId": "vpn-1", "Options": {"TunnelOptions": [{"OutsideIpAddress": "203.0.113.1"}]}}


def test_nested_instance_projection_missing_children_is_malformed(sdk):
    session, add, _ = sdk
    add("ec2").add_response("describe_instances", {"Reservations": [{"ReservationId": "r-1"}]}, {})
    read = aws.Requests({}).pages(session, "ec2", REGION, "describe_instances", "Reservations[].Instances[]")
    assert read.status == "malformed"
    assert read.items == []
    assert read.error["code"] == "malformed_response"


def test_policy_json_preserves_literal_percent_encoded_conditions():
    document = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*", "Condition": {"StringEquals": {"s3:prefix": "literal%2Fprefix"}}}]}
    assert aws._policy(json.dumps(document)) == document
    from urllib.parse import quote
    assert aws._policy(quote(json.dumps(document))) == document
    assert aws._policy("malformed")["collection_status"] == "malformed"


@pytest.mark.parametrize("provider,token,expected", [("env", "lambda-session-token", "env"), ("container-role", "ecs-session-token", "container-role"), ("shared-credentials-file", "profile-token", "platform_role_credentials_unavailable"), ("env", None, "platform_role_session_token_required")])
def test_platform_task_role_supports_lambda_and_ecs_and_excludes_profile_fallback(monkeypatch, provider, token, expected):
    credentials = SimpleNamespace(method=provider, get_frozen_credentials=lambda: SimpleNamespace(access_key="platform-key", secret_key="platform-secret", token=token))
    selected = SimpleNamespace(get_credentials=lambda: credentials)
    pinned = SimpleNamespace()
    monkeypatch.setattr(boto3, "Session", lambda **kwargs: pinned if kwargs.get("aws_access_key_id") else selected)
    if expected.startswith("platform_"):
        with pytest.raises(aws.ReadFailure, match=expected):
            aws._session({"method": "task_role"}, REGION)
    else:
        session, method = aws._session({"method": "task_role"}, REGION)
        assert session is pinned
        assert method == expected


def _client_error(operation, code, message):
    from botocore.exceptions import ClientError
    return ClientError({"Error": {"Code": code, "Message": message}}, operation)


@pytest.mark.parametrize("operation, code, message, state", [
    ("GetMacieSession", "AccessDeniedException", "Macie is not enabled.", "service_not_enabled"),
    ("ListClassificationJobs", "AccessDeniedException", "Macie is not enabled", "service_not_enabled"),
    ("ListPolicies", "AccessDeniedException", "No default admin could be found for account 222233334444 in Region us-east-1", "no_service_administrator"),
    ("DescribeOrganizationConfiguration", "AccessDeniedException", "Invoking account does not have access to describe the organization configuration.", "not_delegated_administrator"),
    ("GetDelegatedAdminAccount", "ResourceNotFoundException", "No delegated admin found for caller account.", "no_delegated_administrator"),
    ("GetDevEndpoints", "AccessDeniedException", "GetDevEndpoints operation is currently disabled.", "operation_disabled_for_account"),
    ("GetDevEndpoints", "InvalidInputException", "Operation is not supported in <eu-south-2> region", "region_operation_unsupported"),
    ("ListCustomModels", "ValidationException", "Unknown operation", "region_operation_unsupported"),
    ("ListCustomModels", "UnknownOperationException", "Unknown Operation", "region_operation_unsupported"),
    ("ListEndpoints", "UnknownOperationException", "Operation is disabled in this region.", "region_operation_unsupported"),
    ("ListEmailIdentities", "UnknownOperationException", None, "region_operation_unsupported"),
])
def test_documented_service_state_replies_are_facts_not_denials(operation, code, message, state):
    failure = aws._failure(_client_error(operation, code, message))
    assert (failure.status, failure.code) == ("empty", state)


@pytest.mark.parametrize("operation, code, message", [
    ("GetMacieSession", "AccessDeniedException", "User is not authorized to perform: macie2:GetMacieSession"),
    ("ListPolicies", "AccessDeniedException", "No default admin could be found for account 222233334444 in Region us-east-1 because of SCP"),
    ("DescribeOrganizationConfiguration", "AccessDeniedException", "Access denied"),
    ("ListFindings", "AccessDeniedException", "Macie is not enabled."),
    ("ListCustomModels", "ValidationException", "1 validation error detected"),
    ("GetDevEndpoints", "AccessDeniedException", ""),
])
def test_undocumented_or_nonmatching_replies_stay_denied_or_unknown(operation, code, message):
    failure = aws._failure(_client_error(operation, code, message))
    assert failure.status in {"denied", "unknown"} and failure.code == code


def test_service_state_detail_is_absent_container():
    requests = aws.Requests({})
    def raiser(*args, **kwargs):
        raise aws._failure(_client_error("GetMacieSession", "AccessDeniedException", "Macie is not enabled."))
    requests.call = raiser
    detail = requests.detail(None, "macie2", REGION, "get_macie_session")
    assert detail["collection_status"] == "empty" and detail["absent"] is True and detail["error"]["code"] == "service_not_enabled"


@pytest.mark.parametrize("operation", ["GetInstances", "GetRelationalDatabases", "GetStaticIps"])
def test_lightsail_region_setup_in_progress_is_transient_unknown_not_absence(sdk, operation):
    session, add, _ = sdk
    failure = aws._failure(_client_error(operation, "RegionSetupInProgressException", "Lightsail is setting up this region for your account, please try again later."))
    assert (failure.status, failure.code) == ("unknown", "region_setup_in_progress")
    assert "region_setup_in_progress" not in aws.SERVICE_STATE_CODES
    lightsail = add("lightsail")
    lightsail.add_client_error("get_instances", "RegionSetupInProgressException", "Lightsail is setting up this region for your account, please try again later.", expected_params={})
    read = aws.Requests({}).pages(session, "lightsail", REGION, "get_instances", "instances")
    assert read.status == "unknown" and read.items == [] and read.error["code"] == "region_setup_in_progress"
    requests = aws.Requests({})
    def raiser(*args, **kwargs):
        raise failure
    requests.call = raiser
    detail = requests.detail(None, "lightsail", REGION, "get_instances")
    assert detail["collection_status"] == "unknown" and "absent" not in detail


def test_role_report_scope_is_conservative():
    allow = lambda action, **extra: {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": action, "Resource": "*", **extra}]}
    assert not aws._may_allow_namespace(allow(["s3:GetObject", "ec2:Describe*"]), "bedrock")
    assert not aws._may_allow_namespace({"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}, "bedrock")
    for document in (allow("*"), allow("bedrock:InvokeModel"), allow("bed*:*"), allow("Bedrock:List*"), allow("b?drock:*"),
                     {"Statement": [{"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"}]}, {"collection_status": "malformed"}, allow(None)):
        assert aws._may_allow_namespace(document, "bedrock")


def test_roles_without_possible_bedrock_grant_skip_reports_only_when_documents_are_known(sdk):
    session, add, _ = sdk
    iam = add("iam")
    doc = lambda action: json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": action, "Resource": "*"}]})
    role = lambda name, attached, inline=(): {"RoleName": name, "RoleId": "AROAREVIEWROLE12345" + name[:2], "Arn": f"arn:aws:iam::{ACCOUNT}:role/{name}", "Path": "/", "CreateDate": NOW,
        "AssumeRolePolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": []}),
        "AttachedManagedPolicies": [{"PolicyName": arn.rsplit("/", 1)[1], "PolicyArn": arn} for arn in attached],
        "RolePolicyList": [{"PolicyName": "inline", "PolicyDocument": d} for d in inline]}
    s3_only, admin = f"arn:aws:iam::{ACCOUNT}:policy/s3-only", "arn:aws:iam::aws:policy/AdministratorAccess"
    policies = [{"PolicyName": arn.rsplit("/", 1)[1], "PolicyId": "ANPAREVIEWPOLICY12" + str(n), "Arn": arn, "Path": "/", "DefaultVersionId": "v1",
                 "PolicyVersionList": [{"Document": doc(action), "VersionId": "v1", "IsDefaultVersion": True}]} for n, (arn, action) in enumerate(((s3_only, "s3:GetObject"), (admin, "*")))]
    roles = [role("ad", [admin]), role("in", [s3_only], [doc("bedrock:InvokeModel")]), role("s3", [s3_only]), role("un", [f"arn:aws:iam::{ACCOUNT}:policy/unlisted"])]
    iam.add_response("get_account_authorization_details", {"RoleDetailList": roles, "Policies": policies, "IsTruncated": False}, {})
    items = {r["RoleName"]: r for r in aws._iam(aws.Requests({"service_last_accessed_concurrency": 1}, sleep=lambda _: None), session, REGION, {"iam_role"})["iam_role"].items}
    assert items["s3"]["ServicesLastAccessedStatus"]["reason"] == "identity_policies_cannot_allow_namespaces"
    assert all(items[name]["ServicesLastAccessedStatus"]["collection_status"] == "not_collected" for name in ("ad", "in", "un"))


@pytest.mark.parametrize("flag,want", [(True, "PASS"), (False, "FAIL"), ("denied", "UNKNOWN"), (None, "UNKNOWN"), ("missing_value", "UNKNOWN")])
def test_instance_termination_protection_native_fact(sdk, flag, want):
    from peaso.checks import CHECKS
    from peaso.checks import claude_aws_a_ec2  # noqa: F401 - register native predicate
    session, add, _ = sdk
    stub = add("ec2")
    params = {"InstanceId": "i-1234567890abcdef0", "Attribute": "userData"}
    stub.add_response("describe_instance_attribute", {"InstanceId": params["InstanceId"]}, params)
    protection_params = dict(params, Attribute="disableApiTermination")
    if flag == "denied":
        stub.add_client_error("describe_instance_attribute", "UnauthorizedOperation", expected_params=protection_params)
    elif flag == "missing_value":
        # A successful response without the boolean cannot prove either state.
        stub.add_response("describe_instance_attribute", {"DisableApiTermination": {}}, protection_params)
    else:
        response = {"InstanceId": params["InstanceId"]}
        if flag is not None:
            response.update(DisableApiTermination={"Value": flag}, UserData={"Value": "synthetic-content-must-be-discarded"})
        stub.add_response("describe_instance_attribute", response, protection_params)
    requests = aws.Requests({"max_calls": 2})
    original = {"InstanceId": params["InstanceId"]}
    item = aws._enrich(requests, session, REGION, "instance", [original])[0]
    assert original == {"InstanceId": params["InstanceId"]}
    assert requests.calls == 2
    assert "synthetic-content-must-be-discarded" not in json.dumps(item)
    check = next(check for check in CHECKS if check.id == "aws.claude_a.ec2.instance_termination_protection")
    status, evidence = check.evaluate(item, {})
    assert status == want
    if want in {"PASS", "FAIL"}:
        assert item["Attributes"]["DisableApiTermination"] is flag
        assert evidence["disable_api_termination"] is flag
    else:
        fact = item["Attributes"]["DisableApiTermination"]
        assert fact["collection_status"] == ("denied" if flag == "denied" else "malformed")
        assert evidence["reason"]


@pytest.mark.parametrize("arguments", [
    {"InstanceId": "i-1234567890abcdef0", "Attribute": "instanceType"},
    {"InstanceId": "i-1234567890abcdef0", "Attribute": "disableApiTermination", "DryRun": True},
    {"Attribute": "disableApiTermination"},
])
def test_instance_termination_protection_readguard_stays_narrow(arguments):
    requests = aws.Requests({})
    with pytest.raises(aws.ReadFailure, match="undeclared_instance_attribute_query"):
        requests.call(object(), "ec2", REGION, "describe_instance_attribute", **arguments)
    assert requests.calls == 0


@pytest.mark.parametrize("foreign,org,duplicate,reverse,expected", [
    (False, False, False, False, "collected"), (True, True, False, False, "collected"),
    (True, False, False, False, "partial"), (False, False, True, False, "partial"),
    (False, False, True, True, "partial"),
])
def test_cloudtrail_account_inventory_native_binding_and_duplicate_home(sdk, foreign, org, duplicate, reverse, expected):
    _, add, _ = sdk
    owner = "999999999999" if foreign else ACCOUNT
    arn = f"arn:aws:cloudtrail:{REGION}:{owner}:trail/native"
    trail = {"Name": "native", "TrailARN": arn, "HomeRegion": REGION,
             "IsOrganizationTrail": org, "IsMultiRegionTrail": True,
             "S3BucketName": "native-bucket"}
    add("sts").add_response("get_caller_identity", IDENTITY, {})
    add("ec2").add_response("describe_regions", {"Regions": [
        {"RegionName": REGION, "OptInStatus": "opt-in-not-required"}]}, {"AllRegions": True})
    ct = add("cloudtrail")
    conflicting = {**trail, "Name": "conflicting-native-name"}
    native_rows = ([conflicting, trail] if reverse else [trail, conflicting]) if duplicate else [trail]
    ct.add_response("describe_trails", {"trailList": native_rows}, {"includeShadowTrails": True})
    ct.add_response("get_trail_status", {"IsLogging": True}, {"Name": arn})
    ct.add_response("get_event_selectors", {"TrailARN": arn, "EventSelectors": []}, {"TrailName": arn})
    ct.add_client_error("get_insight_selectors", "InsightNotEnabledException",
                        expected_params={"TrailName": arn})
    snapshot = aws.collect({"provider": "aws", "scopes": [ACCOUNT], "options": {}},
                           ["cloudtrail_account_inventory"])
    inventory = envelope(snapshot, "cloudtrail_account_inventory")
    assert inventory["status"] == expected
    row = inventory["items"][0]
    assert len(row["_account_trail_observations"]) == (2 if duplicate else 1)
    assert row["_account_trail_binding"] == {
        "caller_account_id": ACCOUNT, "identity_operation": "sts:GetCallerIdentity",
        "describe_operation": "cloudtrail:DescribeTrails", "include_shadow_trails": True,
        "trail_arn": arn, "capture_observed_at": snapshot["created_at"],
    }
    assert row["AccountId"] == ACCOUNT
    assert row["SourceRegion"] == REGION
    if duplicate:
        assert inventory["error"]["code"] == "ambiguous_account_trail"


@pytest.mark.parametrize("mode,expected", [
    ("home_and_shadow", "collected"),
    ("conflicting_shadow", "partial"),
    ("denied_home", "partial"),
])
def test_cloudtrail_account_inventory_home_authority_across_native_regions(sdk, mode, expected):
    _, add, _ = sdk
    shadow_region = "eu-west-1"
    arn = f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/native"
    home = {"Name": "native", "TrailARN": arn, "HomeRegion": REGION,
            "IsOrganizationTrail": False, "IsMultiRegionTrail": True,
            "S3BucketName": "native-bucket"}
    shadow = dict(home)
    if mode == "conflicting_shadow":
        shadow["Name"] = "conflicting-name"
    add("sts").add_response("get_caller_identity", IDENTITY, {})
    add("ec2").add_response("describe_regions", {"Regions": [
        {"RegionName": shadow_region, "OptInStatus": "opt-in-not-required"},
        {"RegionName": REGION, "OptInStatus": "opt-in-not-required"}]}, {"AllRegions": True})
    add("cloudtrail", shadow_region).add_response("describe_trails", {"trailList": [shadow]},
                                                     {"includeShadowTrails": True})
    home_client = add("cloudtrail", REGION)
    home_client.add_response("get_trail_status", {"IsLogging": True}, {"Name": arn})
    home_client.add_response("get_event_selectors", {"TrailARN": arn, "EventSelectors": []}, {"TrailName": arn})
    home_client.add_client_error("get_insight_selectors", "InsightNotEnabledException",
                                 expected_params={"TrailName": arn})
    if mode == "denied_home":
        home_client.add_client_error("describe_trails", "AccessDeniedException",
                                     expected_params={"includeShadowTrails": True})
    else:
        home_client.add_response("describe_trails", {"trailList": [home]},
                                 {"includeShadowTrails": True})
    snapshot = aws.collect({"provider": "aws", "scopes": [ACCOUNT], "options": {}},
                           ["cloudtrail_account_inventory"])
    inventory = envelope(snapshot, "cloudtrail_account_inventory")
    assert inventory["status"] == expected, inventory
    row = inventory["items"][0]
    assert len(row["_account_trail_observations"]) == (1 if mode == "denied_home" else 2)
    if mode == "home_and_shadow":
        assert row["SourceRegion"] == REGION
        assert {x["SourceRegion"] for x in row["_account_trail_observations"]} == {REGION, shadow_region}
    else:
        assert inventory["error"]["code"] in {"ambiguous_account_trail", "AccessDeniedException"}
