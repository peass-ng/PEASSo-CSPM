"""Signed sw05 AWS source boundaries and three-valued decisions."""
from __future__ import annotations

import copy
import pytest

from peaso.checks import evaluate_check
from peaso.checks import compliance_new_sw05 as sw05  # noqa: F401  (registration side effect)

SCOPE = "123456789012/us-east-1"
STAGE_ARN = "arn:aws:apigateway:us-east-1::/restapis/api123/stages/prod"


def snapshot(kind, row, *, metadata=None, dependencies=None, status="collected", scope=None):
    scope = scope or ("123456789012/global" if kind in {"shield_protection", "iam_password_policy"} else SCOPE)
    context = {"provider": "aws", "scope": scope, "metadata": metadata or {},
               "created_at": "2026-10-12T00:00:00+00:00"}
    collections = {}
    wrappers = {}
    for current_kind, rows in {kind: [row], **(dependencies or {})}.items():
        collections[current_kind] = [{"type": current_kind, "scope": scope,
                                         "status": status if current_kind == kind else "collected",
                                         "items": rows}]
        wrappers[current_kind] = [{"type": current_kind, "scope": scope, "data": value}
                                  for value in rows]
    return {"context": context, "collections": collections, **wrappers}


def evaluate(check_id, kind, row, **kwargs):
    return evaluate_check(check_id, row, snapshot(kind, row, **kwargs))[0]


def ecs_row(environment=None, driver="awslogs"):
    container = {"name": "app", "environment": [] if environment is None else environment,
                 "logConfiguration": {"logDriver": driver}}
    arn = "arn:aws:ecs:us-east-1:123456789012:task-definition/demo:1"
    return {"taskDefinitionArn": arn, "Definition": {"collection_status": "collected",
             "taskDefinition": {"taskDefinitionArn": arn, "status": "ACTIVE",
                                "containerDefinitions": [container]}}}


def waf_row(metrics=True, rules=None):
    arn = "arn:aws:wafv2:us-east-1:123456789012:regional/rulegroup/test/id"
    return {"ARN": arn, "RuleGroup": {"ARN": arn, "VisibilityConfig":
            {"CloudWatchMetricsEnabled": metrics}, "Rules": [{"Name": "allow"}] if rules is None else rules}}


def stage_row(certificate_id="cert1", detail=None):
    row = {"id": STAGE_ARN, "ParentApiId": "api123", "stageName": "prod",
           "_provenance": {"source_operation": "get_stages", "parent_api_id": "api123",
                           "read_only": True}, "clientCertificateId": certificate_id}
    if detail is not None:
        row["ClientCertificate"] = detail
    return row


def certificate(expiry="2026-12-01T00:00:00+00:00"):
    return {"collection_status": "collected", "clientCertificateId": "cert1",
            "expirationDate": expiry}


CASES = [
    ("aws_ecs_task_definition_credential_environment_names", "ecs_task_definition",
     ecs_row(), ecs_row([{"name": "AWS_ACCESS_KEY_ID"}]), {}),
    ("aws_g6_ecs_all_containers_logging", "ecs_task_definition",
     ecs_row(), ecs_row(driver=""), {}),
    ("aws.pci.wafv2.rule_group_metrics", "wafv2_rule_group",
     waf_row(), waf_row(metrics=False), {}),
    ("aws.pci.wafv2.rule_group_nonempty", "wafv2_rule_group",
     waf_row(), waf_row(rules=[]), {}),
    ("aws.pci.vpc.authorized_igw_attachment", "internet_gateway",
     {"InternetGatewayId": "igw-1", "Attachments": [{"VpcId": "vpc-good", "State": "available"}]},
     {"InternetGatewayId": "igw-1", "Attachments": [{"VpcId": "vpc-bad", "State": "available"}]},
     {"approved_vpc_ids": ["vpc-good"]}),
    ("aws.pci.vpc.igw_routes_reviewed", "route_table",
     {"RouteTableId": "rtb-1", "Routes": [{"State": "active", "GatewayId": "igw-1", "DestinationCidrBlock": "0.0.0.0/0"}]},
     {"RouteTableId": "rtb-1", "Routes": [{"State": "active", "GatewayId": "igw-2", "DestinationCidrBlock": "0.0.0.0/0"}]},
     {"approved_public_routes": [{"RouteTableId": "rtb-1", "DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"}]}),
    ("aws.pci.vpc.peering_dns_resolution", "vpc_peering_connection",
     {"Status": {"Code": "active"}, "RequesterVpcInfo": {"OwnerId": "123456789012", "PeeringOptions": {"AllowDnsResolutionFromRemoteVpc": True}},
      "AccepterVpcInfo": {"OwnerId": "999999999999", "PeeringOptions": {"AllowDnsResolutionFromRemoteVpc": True}}},
     {"Status": {"Code": "active"}, "RequesterVpcInfo": {"OwnerId": "123456789012", "PeeringOptions": {"AllowDnsResolutionFromRemoteVpc": True}},
      "AccepterVpcInfo": {"OwnerId": "999999999999", "PeeringOptions": {"AllowDnsResolutionFromRemoteVpc": False}}}, {}),
    ("aws_vpc_peering_trusted_accounts", "vpc_peering_connection",
     {"Status": {"Code": "active"}, "RequesterVpcInfo": {"OwnerId": "123456789012"},
      "AccepterVpcInfo": {"OwnerId": "999999999999"}},
     {"Status": {"Code": "active"}, "RequesterVpcInfo": {"OwnerId": "123456789012"},
      "AccepterVpcInfo": {"OwnerId": "888888888888"}},
     {"trusted_account_ids": ["123456789012", "999999999999"]}),
    ("aws_g6_elbv2_only_https_tls_listeners", "load_balancer_v2",
     {"Type": "application", "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web/123", "Listeners": {"collection_status": "collected", "items":
       [{"ListenerArn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/web/123/456", "Protocol": "HTTPS", "Certificates": [{"CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/c"}]}]}},
     {"Type": "application", "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web/123", "Listeners": {"collection_status": "collected", "items":
       [{"ListenerArn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/web/123/456", "Protocol": "HTTP"}]}}, {}),
    ("aws_g6_ecr_public_repositories_absent", "ecr_public_repository",
     None, {"repositoryName": "public", "repositoryArn": "arn:aws:ecr-public::123456789012:repository/public"}, {}),
    ("aws_sqs_queue_depth_alarm_present", "sqs_queue",
     {"QueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/jobs"},
     {"QueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/other"}, {}),
    ("aws.pci.codepipeline.first_stage_single_deploy", "codepipeline_pipeline",
     {"name": "release", "Pipeline": {"collection_status": "collected", "pipeline": {"name": "release", "stages":
      [{"actions": [{"actionTypeId": {"category": "Source"}}]},
       {"actions": [{"actionTypeId": {"category": "Deploy"}}]}]}}},
     {"name": "release", "Pipeline": {"collection_status": "collected", "pipeline": {"name": "release", "stages":
      [{"actions": [{"actionTypeId": {"category": "Deploy"}},
                     {"actionTypeId": {"category": "Deploy"}}]}]}}}, {}),
    ("aws_cognito_session_expiry", "cognito_user_pool_client",
     {"UserPoolId": "us-east-1_pool", "ClientId": "client1", "ClientDetail": {"collection_status": "collected", "UserPoolClient": {"UserPoolId": "us-east-1_pool", "ClientId": "client1", "AccessTokenValidity": 60, "IdTokenValidity": 1,
      "RefreshTokenValidity": 7, "TokenValidityUnits": {"AccessToken": "minutes",
      "IdToken": "hours", "RefreshToken": "days"}}}},
     {"UserPoolId": "us-east-1_pool", "ClientId": "client1", "ClientDetail": {"collection_status": "collected", "UserPoolClient": {"UserPoolId": "us-east-1_pool", "ClientId": "client1", "AccessTokenValidity": 61, "IdTokenValidity": 1,
      "RefreshTokenValidity": 7, "TokenValidityUnits": {"AccessToken": "minutes",
      "IdToken": "hours", "RefreshToken": "days"}}}},
     {"max_refresh_token_minutes": 10080}),
    ("aws_log_retention_upper_bound", "log_group",
     {"logGroupName": "/aws/app", "retentionInDays": 30},
     {"logGroupName": "/aws/app", "retentionInDays": 90},
     {"log_group_purposes": {"/aws/app": "app"}, "log_retention_max_days_by_purpose": {"app": 30}}),
    ("aws_cis_ami_name_policy", "ec2_instance_image",
     {"ImageId": "ami-1", "OwnerId": "123456789012", "Name": "approved-web"},
     {"ImageId": "ami-1", "OwnerId": "123456789012", "Name": "unreviewed-web"},
     {"organization_ami_name_expression": "approved-[a-z]+"}),
    ("aws_g6_api_stage_valid_client_certificate", "rest_api_stage",
     stage_row(detail=certificate()), stage_row(detail=certificate("2026-10-11T00:00:00Z")), {}),
    ("aws.nist.apigateway_stage_valid_client_certificate", "rest_api_stage",
     stage_row(detail=certificate()), stage_row(detail=certificate("2026-10-11T00:00:00Z")),
     {"require_client_certificate": True}),
]


def case_index(check_id, kind, row, metadata):
    if check_id == "aws_g6_ecr_public_repositories_absent":
        rows = [] if row is None else [row]
        return snapshot(kind, {}, metadata=metadata, dependencies={kind: rows})
    if check_id == "aws_sqs_queue_depth_alarm_present":
        alarm = {"AlarmArn": "arn:aws:cloudwatch:us-east-1:123456789012:alarm:queue",
                 "Namespace": "AWS/SQS", "MetricName": "ApproximateNumberOfMessagesVisible",
                 "Dimensions": [{"Name": "QueueName", "Value": "jobs"}], "ActionsEnabled": True,
                 "AlarmActions": ["arn:aws:sns:us-east-1:123456789012:alerts"]}
        return snapshot(kind, row, metadata=metadata, dependencies={"cloudwatch_alarm": [alarm]})
    return snapshot(kind, row, metadata=metadata)


@pytest.mark.parametrize("check_id,kind,passing,failing,metadata", CASES,
                         ids=[case[0] for case in CASES])
def test_signed_pass_fail(check_id, kind, passing, failing, metadata):
    pass_item = {} if passing is None else passing
    pass_index = case_index(check_id, kind, passing, metadata)
    assert evaluate_check(check_id, pass_item, pass_index)[0] == "PASS"
    fail_index = case_index(check_id, kind, failing, metadata)
    assert evaluate_check(check_id, failing, fail_index)[0] == "FAIL"


@pytest.mark.parametrize("check_id,kind,passing,failing,metadata", CASES,
                         ids=[case[0] for case in CASES])
def test_incomplete_foreign_and_missing_facts_unknown(check_id, kind, passing, failing, metadata):
    item = {} if passing is None else passing
    index = case_index(check_id, kind, passing, metadata)
    incomplete = copy.deepcopy(index)
    incomplete["collections"][kind][0]["status"] = "partial"
    assert evaluate_check(check_id, item, incomplete)[0] == "UNKNOWN"
    foreign = copy.deepcopy(index)
    foreign["collections"][kind][0]["scope"] = "999999999999/us-east-1"
    assert evaluate_check(check_id, item, foreign)[0] == "UNKNOWN"
    missing = copy.deepcopy(index)
    missing["collections"].pop(kind)
    assert evaluate_check(check_id, item, missing)[0] == "UNKNOWN"
    malformed = copy.deepcopy(index)
    malformed[kind] = [{"type": kind, "scope": SCOPE, "data": []}]
    assert evaluate_check(check_id, item, malformed)[0] == "UNKNOWN"


def test_policy_and_not_applicable_boundaries():
    stage = stage_row("")
    assert evaluate("aws.nist.apigateway_stage_valid_client_certificate", "rest_api_stage", stage,
                    metadata={"require_client_certificate": False}) == "PASS"
    assert evaluate("aws.nist.apigateway_stage_valid_client_certificate", "rest_api_stage", stage,
                    metadata={"require_client_certificate": True}) == "FAIL"
    assert evaluate("aws.nist.apigateway_stage_valid_client_certificate", "rest_api_stage", stage) == "UNKNOWN"
    assert evaluate("aws_g6_api_stage_valid_client_certificate", "rest_api_stage", stage) == "FAIL"
    inactive = ecs_row()
    inactive["Definition"]["taskDefinition"]["status"] = "INACTIVE"
    assert evaluate("aws_g6_ecs_all_containers_logging", "ecs_task_definition", inactive) == "NOT_APPLICABLE"
    peering = {"Status": {"Code": "pending-acceptance"}}
    assert evaluate("aws.pci.vpc.peering_dns_resolution", "vpc_peering_connection", peering) == "NOT_APPLICABLE"
    foreign_ami = {"ImageId": "ami-1", "OwnerId": "999999999999", "Name": "anything"}
    assert evaluate("aws_cis_ami_name_policy", "ec2_instance_image", foreign_ami,
                    metadata={"organization_ami_name_expression": "approved-.+"}) == "NOT_APPLICABLE"


def test_unsigned_or_unavailable_detail_never_passes():
    item = waf_row()
    del item["RuleGroup"]["Rules"]
    assert evaluate("aws.pci.wafv2.rule_group_nonempty", "wafv2_rule_group", item) == "UNKNOWN"
    item = stage_row(detail={"collection_status": "denied", "clientCertificateId": "cert1"})
    assert evaluate("aws_g6_api_stage_valid_client_certificate", "rest_api_stage", item) == "UNKNOWN"
    item = {"logGroupName": "/aws/app"}
    metadata = {"log_group_purposes": {"/aws/app": "app"},
                "log_retention_max_days_by_purpose": {"app": 30}}
    assert evaluate("aws_log_retention_upper_bound", "log_group", item, metadata=metadata) == "UNKNOWN"
    item["_provenance"] = {"operation": "logs:DescribeLogGroups", "native_response_complete": True}
    assert evaluate("aws_log_retention_upper_bound", "log_group", item, metadata=metadata) == "FAIL"


def test_iam_password_policy_thresholds_and_global_scope():
    thresholds = {"MinimumPasswordLength": 14, "RequireSymbols": True,
                  "RequireNumbers": True, "RequireUppercaseCharacters": True,
                  "RequireLowercaseCharacters": True, "MaxPasswordAge": 90,
                  "PasswordReusePrevention": 12, "HardExpiry": True}
    row = {"PasswordPolicy": dict(thresholds)}
    check_id = "aws.pci.iam.configured_password_policy"
    index = snapshot("iam_password_policy", row,
                     metadata={"password_policy_thresholds": thresholds},
                     scope="123456789012/global")
    assert evaluate_check(check_id, {}, index)[0] == "PASS"
    weak = copy.deepcopy(row)
    weak["PasswordPolicy"]["MinimumPasswordLength"] = 8
    index = snapshot("iam_password_policy", weak,
                     metadata={"password_policy_thresholds": thresholds},
                     scope="123456789012/global")
    assert evaluate_check(check_id, {}, index)[0] == "FAIL"
    del weak["PasswordPolicy"]["MaxPasswordAge"]
    index = snapshot("iam_password_policy", weak,
                     metadata={"password_policy_thresholds": thresholds},
                     scope="123456789012/global")
    assert evaluate_check(check_id, {}, index)[0] == "UNKNOWN"
    assert evaluate_check(check_id, {}, snapshot("iam_password_policy", row,
                          scope="123456789012/global"))[0] == "UNKNOWN"
    assert evaluate_check(check_id, {}, snapshot("iam_password_policy", row,
                          metadata={"password_policy_thresholds": thresholds},
                          scope="123456789012/global", status="partial"))[0] == "UNKNOWN"


def test_shield_application_response_applicability_and_detail():
    check_id = "aws_shield_automatic_application_layer_response"
    row = {"Id": "p1", "ResourceArn": "arn:aws:cloudfront::123456789012:distribution/D1",
           "Protection": {"collection_status": "collected", "Id": "p1",
                          "ApplicationLayerAutomaticResponse": {"Status": "ENABLED"}}}
    assert evaluate(check_id, "shield_protection", row) == "PASS"
    alb = copy.deepcopy(row)
    alb["ResourceArn"] = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/web/id"
    assert evaluate(check_id, "shield_protection", alb, scope="123456789012/global") == "PASS"
    failed = copy.deepcopy(row)
    failed["Protection"]["ApplicationLayerAutomaticResponse"]["Status"] = "DISABLED"
    assert evaluate(check_id, "shield_protection", failed) == "FAIL"
    failed["Protection"]["collection_status"] = "denied"
    assert evaluate(check_id, "shield_protection", failed) == "UNKNOWN"
    other = copy.deepcopy(row)
    other["ResourceArn"] = "arn:aws:ec2:us-east-1:123456789012:eip-allocation/eipalloc-1"
    assert evaluate(check_id, "shield_protection", other) == "NOT_APPLICABLE"


def test_shield_health_check_resolution_and_missing_lookup():
    check_id = "aws_shield_protection_health_checks"
    row = {"Id": "p1", "ResourceArn": "arn:aws:cloudfront::123456789012:distribution/D1", "HealthCheckIds": ["hc-1"],
           "HealthChecks": [{"Id": "hc-1", "collection_status": "collected",
                             "HealthCheck": {"Id": "hc-1"}}]}
    assert evaluate(check_id, "shield_protection", row) == "PASS"
    missing = copy.deepcopy(row)
    missing["HealthChecks"][0] = {"Id": "hc-1", "collection_status": "empty", "absent": True}
    assert evaluate(check_id, "shield_protection", missing) == "FAIL"
    no_checks = {"Id": "p1", "ResourceArn": "arn:aws:cloudfront::123456789012:distribution/D1", "HealthCheckIds": []}
    assert evaluate(check_id, "shield_protection", no_checks) == "FAIL"
    partial = copy.deepcopy(row)
    partial.pop("HealthChecks")
    assert evaluate(check_id, "shield_protection", partial) == "UNKNOWN"
    denied = copy.deepcopy(row)
    denied["HealthChecks"][0]["collection_status"] = "denied"
    assert evaluate(check_id, "shield_protection", denied) == "UNKNOWN"


@pytest.mark.parametrize("check_id,kind,row,metadata,scope", [
    ("aws.pci.iam.configured_password_policy", "iam_password_policy",
     {"PasswordPolicy": {"MinimumPasswordLength": 14, "RequireSymbols": True,
      "RequireNumbers": True, "RequireUppercaseCharacters": True,
      "RequireLowercaseCharacters": True, "MaxPasswordAge": 90,
      "PasswordReusePrevention": 12, "HardExpiry": True}},
     {"password_policy_thresholds": {"MinimumPasswordLength": 14, "RequireSymbols": True,
      "RequireNumbers": True, "RequireUppercaseCharacters": True,
      "RequireLowercaseCharacters": True, "MaxPasswordAge": 90,
      "PasswordReusePrevention": 12, "HardExpiry": True}}, "123456789012/global"),
    ("aws_shield_automatic_application_layer_response", "shield_protection",
     {"Id": "p1", "ResourceArn": "arn:aws:cloudfront::123456789012:distribution/D1",
      "Protection": {"collection_status": "collected", "Id": "p1",
       "ApplicationLayerAutomaticResponse": {"Status": "ENABLED"}}}, {}, "123456789012/global"),
    ("aws_shield_protection_health_checks", "shield_protection",
     {"Id": "p1", "ResourceArn": "arn:aws:cloudfront::123456789012:distribution/D1",
      "HealthCheckIds": ["hc-1"], "HealthChecks": [{"Id": "hc-1",
       "collection_status": "collected", "HealthCheck": {"Id": "hc-1"}}]}, {}, "123456789012/global"),
], ids=["iam-password-policy", "shield-auto-response", "shield-health-checks"])
def test_remaining_evaluators_reject_incomplete_malformed_and_foreign_scope(
        check_id, kind, row, metadata, scope):
    item = {} if check_id == "aws.pci.iam.configured_password_policy" else row
    baseline = snapshot(kind, row, metadata=metadata, scope=scope)
    assert evaluate_check(check_id, item, baseline)[0] == "PASS"
    incomplete = copy.deepcopy(baseline)
    incomplete["collections"][kind][0]["status"] = "partial"
    assert evaluate_check(check_id, item, incomplete)[0] == "UNKNOWN"
    foreign = copy.deepcopy(baseline)
    foreign["collections"][kind][0]["scope"] = "999999999999/us-east-1"
    assert evaluate_check(check_id, item, foreign)[0] == "UNKNOWN"
    missing = copy.deepcopy(baseline)
    missing["collections"].pop(kind)
    assert evaluate_check(check_id, item, missing)[0] == "UNKNOWN"
    malformed = copy.deepcopy(baseline)
    malformed[kind] = [{"type": kind, "scope": scope, "data": []}]
    assert evaluate_check(check_id, item, malformed)[0] == "UNKNOWN"


def test_review_empty_envelope_cannot_hide_existing_resource():
    row = waf_row()
    assert evaluate("aws.pci.wafv2.rule_group_metrics", "wafv2_rule_group", row, status="empty") == "UNKNOWN"


@pytest.mark.parametrize("check_id", ["aws_ecs_task_definition_credential_environment_names", "aws_g6_ecs_all_containers_logging"])
def test_review_ecs_missing_or_duplicate_container_identity(check_id):
    for names in ([""], ["app", "app"]):
        row = ecs_row()
        container = row["Definition"]["taskDefinition"]["containerDefinitions"][0]
        row["Definition"]["taskDefinition"]["containerDefinitions"] = [{**container, "name": name} for name in names]
        assert evaluate(check_id, "ecs_task_definition", row) == "UNKNOWN"


def test_review_credential_name_check_includes_inactive_definitions_and_rejects_empty_names():
    check_id = "aws_ecs_task_definition_credential_environment_names"
    row = ecs_row([{"name": "AWS_SECRET_ACCESS_KEY"}])
    row["Definition"]["taskDefinition"]["status"] = "INACTIVE"
    assert evaluate(check_id, "ecs_task_definition", row) == "FAIL"
    row = ecs_row([{"name": ""}])
    assert evaluate(check_id, "ecs_task_definition", row) == "UNKNOWN"


def test_review_waf_nonempty_requires_native_rule_names():
    for rules in ([{}], [{"Name": ""}], [{"Name": "rule"}, {"Name": "rule"}]):
        assert evaluate("aws.pci.wafv2.rule_group_nonempty", "wafv2_rule_group", waf_row(rules=rules)) == "UNKNOWN"


@pytest.mark.parametrize("change", ["masked_gateway", "masked_destination", "malformed_destination", "wrong_address_family"])
def test_review_igw_routes_require_readable_valid_targets(change):
    case = next(row for row in CASES if row[0] == "aws.pci.vpc.igw_routes_reviewed")
    check_id, kind, passing, _, metadata = case
    row = copy.deepcopy(passing)
    route = row["Routes"][0]
    if change == "masked_gateway":
        route.pop("GatewayId")
        route["_coverage"] = {"GatewayId": {"status": "denied"}}
    elif change == "masked_destination":
        route["_coverage"] = {"DestinationCidrBlock": {"status": "denied"}}
    else:
        route["DestinationCidrBlock"] = "invalid" if change == "malformed_destination" else "::/0"
    assert evaluate(check_id, kind, row, metadata=metadata) == "UNKNOWN"


def test_review_peering_dns_requires_audited_account_endpoint():
    case = next(row for row in CASES if row[0] == "aws.pci.vpc.peering_dns_resolution")
    check_id, kind, passing, _, _ = case
    for owner in ("888888888888", "bad", None):
        row = copy.deepcopy(passing)
        if owner is None:
            row["RequesterVpcInfo"].pop("OwnerId")
        else:
            row["RequesterVpcInfo"]["OwnerId"] = owner
        assert evaluate(check_id, kind, row) == "UNKNOWN"


def test_review_peering_empty_trust_policy_is_explicit_and_bad_account_policy_is_unknown():
    case = next(row for row in CASES if row[0] == "aws_vpc_peering_trusted_accounts")
    check_id, kind, row, _, _ = case
    assert evaluate(check_id, kind, row, metadata={"trusted_account_ids": []}) == "FAIL"
    assert evaluate(check_id, kind, row, metadata={"trusted_account_ids": ["bad-account"]}) == "UNKNOWN"


@pytest.mark.parametrize("change", ["unknown_type", "empty_with_items", "foreign_listener", "other_parent", "duplicate_listener", "foreign_lb"])
def test_review_listener_inventory_and_parent_join(change):
    case = next(row for row in CASES if row[0] == "aws_g6_elbv2_only_https_tls_listeners")
    check_id, kind, passing, _, _ = case
    row = copy.deepcopy(passing)
    if change == "unknown_type":
        row["Type"] = "future-type"
    elif change == "empty_with_items":
        row["Listeners"]["collection_status"] = "empty"
    elif change == "duplicate_listener":
        row["Listeners"]["items"] *= 2
    elif change == "foreign_lb":
        row["LoadBalancerArn"] = row["LoadBalancerArn"].replace("123456789012", "999999999999")
    else:
        listener = row["Listeners"]["items"][0]
        listener["ListenerArn"] = listener["ListenerArn"].replace("123456789012", "999999999999") if change == "foreign_listener" else listener["ListenerArn"].replace("web/123", "other/987")
    assert evaluate(check_id, kind, row) == "UNKNOWN"


def test_review_complete_load_balancer_with_no_listeners_passes_universal_predicate():
    case = next(row for row in CASES if row[0] == "aws_g6_elbv2_only_https_tls_listeners")
    check_id, kind, passing, _, _ = case
    row = {**passing, "Listeners": {"collection_status": "empty", "items": []}}
    assert evaluate(check_id, kind, row) == "PASS"


@pytest.mark.parametrize("change", ["different_pool", "different_client", "missing_identity", "bad_unit_case"])
def test_review_cognito_join_and_unit_enum(change):
    case = next(row for row in CASES if row[0] == "aws_cognito_session_expiry")
    check_id, kind, passing, _, metadata = case
    row = copy.deepcopy(passing)
    client = row["ClientDetail"]["UserPoolClient"]
    if change == "missing_identity":
        client.pop("ClientId")
    elif change == "bad_unit_case":
        client["TokenValidityUnits"]["AccessToken"] = "MINUTES"
    else:
        client["UserPoolId" if change == "different_pool" else "ClientId"] = "other"
    assert evaluate(check_id, kind, row, metadata=metadata) == "UNKNOWN"


def test_review_ami_owner_and_shield_resource_malformed_are_unknown():
    assert evaluate("aws_cis_ami_name_policy", "ec2_instance_image", {"ImageId": "ami-1", "OwnerId": "", "Name": "approved"}, metadata={"organization_ami_name_expression": ".*"}) == "UNKNOWN"
    row = {"Id": "protection", "ResourceArn": "not-an-arn"}
    assert evaluate("aws_shield_automatic_application_layer_response", "shield_protection", row) == "UNKNOWN"


def test_review_account_only_scope_is_not_regional_authority():
    row = waf_row()
    assert evaluate("aws.pci.wafv2.rule_group_metrics", "wafv2_rule_group", row, scope="123456789012") == "UNKNOWN"


def test_review_global_and_regional_service_scope_authority():
    assert evaluate("aws.pci.wafv2.rule_group_metrics", "wafv2_rule_group", waf_row(), scope="123456789012/global") == "UNKNOWN"
    row = {"Id": "protection", "ResourceArn": "arn:aws:ec2:us-east-1:123456789012:eip-allocation/eipalloc-1", "HealthCheckIds": []}
    assert evaluate("aws_shield_protection_health_checks", "shield_protection", row, scope=SCOPE) == "UNKNOWN"
