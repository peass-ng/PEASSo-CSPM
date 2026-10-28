"""Compute/edge collector facts: read-only, paginated, never secret-bearing."""
import json

import pytest

boto3 = pytest.importorskip("boto3")
from botocore.stub import Stubber

from peaso.checks import evaluate_check
from peaso.collectors import aws
from peaso.collectors import aws_facts_compute_edge as edge

REGION = "us-east-1"
ACCOUNT = "123456789012"
SCOPE = f"{ACCOUNT}/{REGION}"
CONTEXT = {"scope": SCOPE, "Account": ACCOUNT, "provider": "aws", "created_at": "2026-01-01T00:00:00+00:00"}
CLUSTER = f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/c"
LB = f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/web/1"
LISTENER = f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:listener/app/web/1/80"
ACL = f"arn:aws:wafv2:{REGION}:{ACCOUNT}:regional/webacl/a/1"
CF_ACL = f"arn:aws:wafv2:{REGION}:{ACCOUNT}:global/webacl/g/2"
DENIED = ("AccessDeniedException", "denied")


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


def status(check, item, index=None):
    return evaluate_check(check, item, index)[0]


def test_extension_loaded_without_replacing_existing_kinds():
    for kind, spec in edge.SPECS.items():
        assert aws.SPECS[kind] == spec
    assert edge.GLOBAL_TYPES <= aws.GLOBAL_TYPES
    assert edge.READ_ACTIONS <= aws.READ_ACTIONS
    assert all(op.startswith(("get_", "list_", "describe_")) for _, op in edge.READ_ACTIONS)


def test_rest_custom_domain_routing_rules_are_cached_and_projected(sdk):
    session, add = sdk
    add("apigateway").add_response("get_base_path_mappings", {"items": []}, {"domainName": "api.example.com"})
    add("apigatewayv2").add_response("list_routing_rules", {"RoutingRules": [{
        "RoutingRuleId": "rule-1", "Priority": 1, "Conditions": [],
        "Actions": [{"InvokeApi": {"ApiId": "rest1", "Stage": "prod"}}]}]}, {"DomainName": "api.example.com"})
    row = {"domainName": "api.example.com", "routingMode": "ROUTING_RULE_ONLY"}
    projected = edge.ENRICHERS["apigateway_domain_name"](aws.Requests({}), session, REGION, [row])[0]
    assert projected["RoutingRules"]["collection_status"] == "collected"
    assert projected["RoutingRules"]["items"][0]["Priority"] == 1
    assert projected["RoutingRules"]["items"][0]["ConditionCount"] == 0
    assert "Conditions" not in projected["RoutingRules"]["items"][0]
    assert projected["RoutingRules"]["items"][0]["Actions"] == [{"InvokeApi": {"ApiId": "rest1", "Stage": "prod"}}]


def test_rest_routing_single_header_condition_retains_shape_without_value(sdk):
    import json

    session, add = sdk
    add("apigateway").add_response("get_base_path_mappings", {"items": []}, {"domainName": "api.example.com"})
    add("apigatewayv2").add_response("list_routing_rules", {"RoutingRules": [{
        "RoutingRuleId": "rule-1", "Priority": 1,
        "Conditions": [{"MatchHeaders": {"AnyOf": [{"Header": "x-route", "ValueGlob": "candidate-value"}]}}],
        "Actions": [{"InvokeApi": {"ApiId": "rest1", "Stage": "prod"}}]}]},
        {"DomainName": "api.example.com"})
    projected = edge.ENRICHERS["apigateway_domain_name"](aws.Requests({}), session, REGION, [
        {"domainName": "api.example.com", "routingMode": "ROUTING_RULE_ONLY"}])[0]
    rule = projected["RoutingRules"]["items"][0]
    assert rule["ConditionCount"] == 1 and rule["SingleHeaderCondition"] is True
    assert "Conditions" not in rule and "candidate-value" not in json.dumps(projected)


def test_rest_routing_single_base_path_condition_retains_shape_without_path(sdk):
    import json

    session, add = sdk
    add("apigateway").add_response("get_base_path_mappings", {"items": []}, {"domainName": "api.example.com"})
    add("apigatewayv2").add_response("list_routing_rules", {"RoutingRules": [{
        "RoutingRuleId": "rule-1", "Priority": 1,
        "Conditions": [{"MatchBasePaths": {"AnyOf": ["private-candidate-path"]}}],
        "Actions": [{"InvokeApi": {"ApiId": "rest1", "Stage": "prod", "StripBasePath": True}}]}]},
        {"DomainName": "api.example.com"})
    projected = edge.ENRICHERS["apigateway_domain_name"](aws.Requests({}), session, REGION, [
        {"domainName": "api.example.com", "routingMode": "ROUTING_RULE_ONLY"}])[0]
    rule = projected["RoutingRules"]["items"][0]
    assert rule["ConditionCount"] == 1 and rule["SingleBasePathCondition"] is True
    assert rule["Actions"][0]["InvokeApi"]["StripBasePath"] is True
    assert "Conditions" not in rule and "private-candidate-path" not in json.dumps(projected)


def test_rest_routing_header_and_base_path_shape_discards_both_values(sdk):
    import json

    session, add = sdk
    add("apigateway").add_response("get_base_path_mappings", {"items": []}, {"domainName": "api.example.com"})
    add("apigatewayv2").add_response("list_routing_rules", {"RoutingRules": [{
        "RoutingRuleId": "rule-1", "Priority": 1,
        "Conditions": [{"MatchBasePaths": {"AnyOf": ["private-path"]}},
                       {"MatchHeaders": {"AnyOf": [{"Header": "x-secret-route", "ValueGlob": "private-value"}]}}],
        "Actions": [{"InvokeApi": {"ApiId": "rest1", "Stage": "prod", "StripBasePath": True}}]}]},
        {"DomainName": "api.example.com"})
    projected = edge.ENRICHERS["apigateway_domain_name"](aws.Requests({}), session, REGION, [
        {"domainName": "api.example.com", "routingMode": "ROUTING_RULE_ONLY"}])[0]
    rule = projected["RoutingRules"]["items"][0]
    assert rule["ConditionCount"] == 2 and rule["HeaderAndBasePathConditions"] is True
    assert "Conditions" not in rule
    assert all(value not in json.dumps(projected) for value in ("private-path", "x-secret-route", "private-value"))


def test_launch_configuration_pagination_strips_user_data(sdk):
    session, add = sdk
    stub = add("autoscaling")
    lc = {"LaunchConfigurationName": "lc", "LaunchConfigurationARN": "arn:lc", "ImageId": "ami-1", "InstanceType": "t3.micro",
          "CreatedTime": "2026-01-01T00:00:00Z", "UserData": "c2VjcmV0", "AssociatePublicIpAddress": True,
          "MetadataOptions": {"HttpTokens": "required", "HttpPutResponseHopLimit": 1}}
    stub.add_response("describe_launch_configurations", {"LaunchConfigurations": [], "NextToken": "n"}, {})
    stub.add_response("describe_launch_configurations", {"LaunchConfigurations": [lc]}, {"NextToken": "n"})
    requests = aws.Requests({})
    read = requests.pages(session, "autoscaling", REGION, "describe_launch_configurations", "LaunchConfigurations")
    assert read.status == "collected"
    item = edge.ENRICHERS["launch_configuration"](requests, session, REGION, read.items)[0]
    assert "UserData" not in item and "c2VjcmV0" not in json.dumps(item, default=str)
    assert status("aws.c2b.autoscaling.lc_no_public_ip", item) == "FAIL"
    item["AssociatePublicIpAddress"] = False
    assert status("aws.c2b.autoscaling.lc_no_public_ip", item) == "PASS"


def _service(name, public):
    return {"serviceArn": f"arn:aws:ecs:{REGION}:{ACCOUNT}:service/c/{name}", "serviceName": name, "clusterArn": CLUSTER,
            "taskDefinition": f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/t:1", "launchType": "FARGATE", "platformVersion": "1.4.0", "loadBalancers": [], "events": [{"message": "x"}],
            "networkConfiguration": {"awsvpcConfiguration": {"subnets": ["subnet-1"], "assignPublicIp": "ENABLED" if public else "DISABLED"}},
            "taskSets": [{"taskSetArn": f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-set/c/{name}/ts",
                          "networkConfiguration": {"awsvpcConfiguration": {"subnets": ["subnet-1"], "assignPublicIp": "DISABLED"}}}]}


def test_ecs_services_and_task_sets_share_paginated_batch_reads(sdk):
    session, add = sdk
    stub = add("ecs")
    arns = [f"arn:aws:ecs:{REGION}:{ACCOUNT}:service/c/s{i}" for i in range(11)]
    stub.add_response("list_clusters", {"clusterArns": [CLUSTER]}, {})
    stub.add_response("list_services", {"serviceArns": arns[:6], "nextToken": "n"}, {"cluster": CLUSTER})
    stub.add_response("list_services", {"serviceArns": arns[6:]}, {"cluster": CLUSTER, "nextToken": "n"})
    stub.add_response("describe_services", {"services": [_service(f"s{i}", i == 0) for i in range(10)], "failures": []}, {"cluster": CLUSTER, "services": arns[:10]})
    stub.add_response("describe_services", {"services": [], "failures": [{"arn": arns[10], "reason": "MISSING"}]}, {"cluster": CLUSTER, "services": arns[10:]})
    requests = aws.Requests({})
    services = edge.FETCHERS["ecs_service"](requests, session, REGION, ACCOUNT)
    task_sets = edge.FETCHERS["ecs_task_set"](requests, session, REGION, ACCOUNT)
    assert requests.calls == 5
    assert services.status == "collected" and len(services.items) == 10
    assert "events" not in services.items[0] and "taskSets" not in services.items[0]
    assert status("aws.c2b.ecs.service_no_public_ip", services.items[0]) == "UNKNOWN"
    task_definition = services.items[0]["taskDefinition"]
    index = {"collections": {"ecs_task_definition": [{"scope": SCOPE, "status": "collected"}]},
             "ecs_task_definition": [{"data": {"taskDefinitionArn": task_definition,
                 "Definition": {"collection_status": "collected", "taskDefinition": {
                     "taskDefinitionArn": task_definition, "networkMode": "awsvpc",
                     "containerDefinitions": [{"name": "app"}]}}}}]}
    assert status("aws.c2b.ecs.service_no_public_ip", services.items[0], index) == "FAIL"
    assert status("aws.c2b.ecs.service_no_public_ip", services.items[1], index) == "PASS"
    assert task_sets.status == "collected" and len(task_sets.items) == 10
    assert status("aws.c2b.ecs.task_set_no_public_ip", task_sets.items[0]) == "PASS"


def test_ecs_service_denied_is_not_empty(sdk):
    session, add = sdk
    add("ecs").add_client_error("list_clusters", *DENIED)
    read = edge.FETCHERS["ecs_service"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "denied" and read.items == []


def test_ecs_account_setting_effective_value(sdk):
    session, add = sdk
    add("ecs").add_response("list_account_settings", {"settings": [{"name": "defaultLogDriverMode", "value": "non-blocking", "principalArn": "arn:p"}]},
                            {"name": "defaultLogDriverMode", "effectiveSettings": True})
    read = edge.FETCHERS["ecs_account_setting"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "collected" and read.items[0]["value"] == "non-blocking"


def test_ecs_task_definition_environment_names_only(sdk):
    session, add = sdk
    arn = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/t:1"
    add("ecs").add_response("describe_task_definition", {"taskDefinition": {"taskDefinitionArn": arn, "containerDefinitions": [
        {"name": "app", "environment": [{"name": "AWS_SECRET_ACCESS_KEY", "value": "hunter2"}]}, {"name": "side"}]}}, {"taskDefinition": arn})
    requests = aws.Requests({})
    from peaso.collectors.aws_b_services import ENRICHERS as base
    items = base["ecs_task_definition"](requests, session, REGION, [{"taskDefinitionArn": arn}])
    assert items[0]["Definition"]["collection_status"] == "collected"
    assert "environment" not in items[0]["Definition"]["taskDefinition"]["containerDefinitions"][0]
    assert status("aws.c2b.ecs.no_credential_named_env_vars", items[0]) == "UNKNOWN"
    item = edge.ENRICHERS["ecs_task_definition"](requests, session, REGION, items)[0]
    assert requests.calls == 1
    app, side = item["Definition"]["taskDefinition"]["containerDefinitions"]
    assert app["environment"] == [{"name": "AWS_SECRET_ACCESS_KEY"}] and side["environment"] == []
    assert "hunter2" not in json.dumps(item)
    assert status("aws.c2b.ecs.no_credential_named_env_vars", item) == "FAIL"


def test_lambda_variable_count_from_cached_configuration(sdk):
    session, add = sdk
    stub = add("lambda")
    stub.add_response("get_function_configuration", {"FunctionName": "f", "FunctionArn": "arn:f", "Environment": {"Variables": {"A": "secret", "B": "x"}}}, {"FunctionName": "f"})
    stub.add_response("get_function_configuration", {"FunctionName": "g", "FunctionArn": "arn:g"}, {"FunctionName": "g"})
    stub.add_client_error("get_function_configuration", *DENIED, expected_params={"FunctionName": "h"})
    absent = {"collection_status": "empty", "absent": True, "error": {"code": "ResourceNotFoundException"}}
    rows = [{"FunctionName": n, "FunctionArn": "arn:" + n, "PackageType": "Zip", "Policy": absent, "FunctionUrl": absent} for n in "fgh"]
    assert status("aws.c2b.lambda.env_vars_cmk", {**rows[0], "Environment": {}}) == "UNKNOWN"
    f, g, h = edge.ENRICHERS["lambda_function"](aws.Requests({}), session, REGION, rows)
    assert f["Environment"] == {"VariableCount": 2} and "secret" not in json.dumps(f)
    assert status("aws.c2b.lambda.env_vars_cmk", f) == "FAIL"
    assert status("aws.c2b.lambda.env_vars_cmk", {**f, "KMSKeyArn": "arn:aws:kms:us-east-1:1:key/k"}) == "PASS"
    assert g["Environment"] == {"VariableCount": 0} and status("aws.c2b.lambda.env_vars_cmk", g) == "PASS"
    assert h["Environment"] == {} and status("aws.c2b.lambda.env_vars_cmk", h) == "UNKNOWN"


def _eks():
    return {"name": "k", "Cluster": {"collection_status": "collected", "cluster": {"arn": "arn:k", "name": "k", "version": "1.30",
            "resourcesVpcConfig": {"endpointPublicAccess": False, "endpointPrivateAccess": True, "publicAccessCidrs": [], "securityGroupIds": [], "clusterSecurityGroupId": "sg-1"}}}}


def test_eks_vpc_cni_addon_collected_and_absent(sdk):
    session, add = sdk
    stub = add("eks")
    stub.add_response("describe_addon", {"addon": {"clusterName": "k", "addonName": "vpc-cni", "addonVersion": "v1.18.0-eksbuild.1", "configurationValues": '{"enableNetworkPolicy": "true"}'}},
                      {"clusterName": "k", "addonName": "vpc-cni"})
    stub.add_client_error("describe_addon", "ResourceNotFoundException", "none", expected_params={"clusterName": "k2", "addonName": "vpc-cni"})
    assert status("aws.c2b.eks.vpc_cni_network_policy", _eks()) == "UNKNOWN"
    first, second = edge.ENRICHERS["eks_cluster"](aws.Requests({}), session, REGION, [_eks(), {**_eks(), "name": "k2"}])
    assert first["VpcCniAddon"]["collection_status"] == "collected"
    assert status("aws.c2b.eks.vpc_cni_network_policy", first) == "PASS"
    assert second["VpcCniAddon"] == {"collection_status": "empty", "absent": True, "error": {"code": "ResourceNotFoundException"}}


def test_rest_api_authorizers_resources_and_methods(sdk):
    session, add = sdk
    stub = add("apigateway")
    stub.add_response("get_authorizers", {"items": [{"id": "au1", "name": "l", "type": "TOKEN", "authorizerCredentials": "arn:role"}]}, {"restApiId": "a1"})
    stub.add_response("get_resources", {"items": [{"id": "r0", "path": "/"}], "position": "p"}, {"restApiId": "a1", "embed": ["methods"]})
    stub.add_response("get_resources", {"items": [{"id": "r1", "path": "/x", "resourceMethods": {"GET": {
        "httpMethod": "GET", "authorizationType": "NONE", "methodIntegration": {"requestTemplates": {"application/json": "{\"key\":\"s3cr3t\"}"}}}}}]},
        {"restApiId": "a1", "embed": ["methods"], "position": "p"})
    base = {"id": "a1", "name": "api", "endpointConfiguration": {"types": ["REGIONAL"]}}
    assert status("aws.c2b.apigateway.methods_authorization_type", base) == "UNKNOWN"
    item = edge.ENRICHERS["rest_api"](aws.Requests({}), session, REGION, [base])[0]
    assert item["Authorizers"]["collection_status"] == "collected" and "authorizerCredentials" not in item["Authorizers"]["items"][0]
    assert [r["path"] for r in item["Resources"]["items"]] == ["/", "/x"]
    assert "s3cr3t" not in json.dumps(item)
    assert item["Methods"] == [{"resourceId": "r1", "path": "/x", "httpMethod": "GET", "authorizationType": "NONE"}]
    assert status("aws.c2b.apigateway.methods_authorization_type", item) == "FAIL"
    assert status("aws.c2b.apigateway.rest_api_has_authorizer", item) == "PASS"


def test_rest_api_denied_children_stay_unavailable(sdk):
    session, add = sdk
    stub = add("apigateway")
    stub.add_client_error("get_authorizers", "AccessDeniedException", "denied")
    stub.add_client_error("get_resources", "AccessDeniedException", "denied")
    item = edge.ENRICHERS["rest_api"](aws.Requests({}), session, REGION, [{"id": "a1", "name": "api", "endpointConfiguration": {"types": ["REGIONAL"]}}])[0]
    assert item["Resources"]["collection_status"] == "denied" and "items" not in item["Resources"] and "Methods" not in item
    assert status("aws.c2b.apigateway.methods_authorization_type", item) == "UNKNOWN"


def test_http_api_routes_and_authorizers(sdk):
    session, add = sdk
    stub = add("apigatewayv2")
    stub.add_response("get_authorizers", {"Items": []}, {"ApiId": "h1"})
    stub.add_response("get_routes", {"Items": [{"RouteId": "r1", "RouteKey": "GET /", "AuthorizationType": "JWT", "AuthorizerId": "z1"}], "NextToken": "n"}, {"ApiId": "h1"})
    stub.add_response("get_routes", {"Items": [{"RouteId": "r2", "RouteKey": "$default", "AuthorizationType": "NONE"}]}, {"ApiId": "h1", "NextToken": "n"})
    base = {"ApiId": "h1", "Name": "http", "ProtocolType": "HTTP"}
    assert status("aws.c2b.apigatewayv2.routes_authorization_type", base) == "UNKNOWN"
    item = edge.ENRICHERS["http_api"](aws.Requests({}), session, REGION, [base])[0]
    assert item["Authorizers"] == {"collection_status": "collected", "items": []}
    assert len(item["Routes"]["items"]) == 2
    assert status("aws.c2b.apigatewayv2.routes_authorization_type", item) == "FAIL"
    assert status("aws.c2b.apigatewayv2.api_has_authorizer", item) == "FAIL"


def test_wafv2_web_acls_regional_and_cloudfront_scopes(sdk):
    session, add = sdk
    stub = add("wafv2")
    summary = {"Name": "a", "Id": "1", "ARN": ACL, "LockToken": "lt"}
    stub.add_response("list_web_acls", {"WebACLs": [summary]}, {"Scope": "REGIONAL", "Limit": 100})
    stub.add_response("get_web_acl", {"WebACL": {"Name": "a", "Id": "1", "ARN": ACL, "DefaultAction": {"Allow": {}},
        "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": "a"}, "Rules": []}, "LockToken": "lt"},
        {"Name": "a", "Scope": "REGIONAL", "Id": "1"})
    stub.add_client_error("get_logging_configuration", "WAFNonexistentItemException", "none", expected_params={"ResourceArn": ACL})
    for resource_type in edge._WAFV2_RESOURCE_TYPES:
        if resource_type == "AMPLIFY":
            stub.add_client_error("list_resources_for_web_acl", "WAFInvalidParameterException", "unsupported", expected_params={"WebACLArn": ACL, "ResourceType": resource_type})
        else:
            stub.add_response("list_resources_for_web_acl", {"ResourceArns": [LB] if resource_type == "APPLICATION_LOAD_BALANCER" else []},
                              {"WebACLArn": ACL, "ResourceType": resource_type})
    stub.add_response("list_web_acls", {"WebACLs": [{"Name": "g", "Id": "2", "ARN": CF_ACL}]}, {"Scope": "CLOUDFRONT", "Limit": 100})
    stub.add_response("get_web_acl", {"WebACL": {"Name": "g", "Id": "2", "ARN": CF_ACL, "DefaultAction": {"Allow": {}},
        "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": "g"}}}, {"Name": "g", "Scope": "CLOUDFRONT", "Id": "2"})
    stub.add_response("get_logging_configuration", {"LoggingConfiguration": {"ResourceArn": CF_ACL, "LogDestinationConfigs": ["arn:aws:logs:us-east-1:1:log-group:aws-waf-logs-g"]}},
                      {"ResourceArn": CF_ACL})
    add("cloudfront").add_response("list_distributions_by_web_acl_id", {"DistributionList": {"Marker": "", "MaxItems": 100, "IsTruncated": False, "Quantity": 0}},
                                   {"WebACLId": CF_ACL})
    read = edge.FETCHERS["wafv2_web_acl"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "collected" and [r["Scope"] for r in read.items] == ["REGIONAL", "CLOUDFRONT"]
    regional, cloudfront = read.items
    assert "LockToken" not in json.dumps(read.items)
    assert regional["ResourceArns"]["ResourceArns"] == [LB] and regional["ResourceArns"]["ByResourceType"]["AMPLIFY"] == "not_applicable"
    assert cloudfront["ResourceArns"] == {"collection_status": "collected", "ResourceArns": []}
    assert status("aws.cb.wafv2.web_acl_logging", regional) == "FAIL"
    assert status("aws.cb.wafv2.web_acl_logging", cloudfront) == "PASS"
    lb = {"LoadBalancerArn": LB, "LoadBalancerName": "web", "Type": "application", "Scheme": "internal", "Listeners": {"collection_status": "empty", "items": []}}
    index = {"collections": {"wafv2_web_acl": [{"scope": SCOPE, "status": "collected"}]}, "wafv2_web_acl": [{"data": regional}], "context": CONTEXT}
    assert status("aws.c2b.elbv2.alb_wafv2_attached", lb, {"context": CONTEXT}) == "UNKNOWN"
    assert status("aws.c2b.elbv2.alb_wafv2_attached", lb, index) == "PASS"


def test_wafv2_list_denied_and_resource_failure_not_empty(sdk):
    session, add = sdk
    stub = add("wafv2")
    stub.add_client_error("list_web_acls", "WAFAccessDeniedException", "denied")
    assert edge.FETCHERS["wafv2_web_acl"](aws.Requests({}), session, "eu-west-1", ACCOUNT).status in ("denied", "unknown")
    stub.add_client_error("list_resources_for_web_acl", "WAFInternalErrorException", "boom")
    result = edge._resource_arns(aws.Requests({}), session, REGION, "wafv2", ("APPLICATION_LOAD_BALANCER",), WebACLArn=ACL)
    assert result["collection_status"] != "collected" and "ResourceArns" not in result


def test_wafv2_rule_group_detail(sdk):
    session, add = sdk
    stub = add("wafv2")
    arn = f"arn:aws:wafv2:eu-west-1:{ACCOUNT}:regional/rulegroup/g/1"
    pass_arn = f"arn:aws:wafv2:eu-west-1:{ACCOUNT}:regional/rulegroup/h/2"
    stub.add_response("list_rule_groups", {"RuleGroups": [{"Name": "g", "Id": "1", "ARN": arn}], "NextMarker": "m"}, {"Scope": "REGIONAL", "Limit": 100})
    stub.add_response("list_rule_groups", {"RuleGroups": [{"Name": "h", "Id": "2", "ARN": pass_arn}]},
                      {"Scope": "REGIONAL", "Limit": 100, "NextMarker": "m"})
    stub.add_response("get_rule_group", {"RuleGroup": {"Name": "g", "Id": "1", "ARN": arn, "Capacity": 1,
        "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": False, "MetricName": "g"},
        "Rules": []}, "LockToken": "lt"},
        {"Name": "g", "Scope": "REGIONAL", "Id": "1"})
    stub.add_response("get_rule_group", {"RuleGroup": {"Name": "h", "Id": "2", "ARN": pass_arn, "Capacity": 1,
        "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": "h"},
        "Rules": []}, "LockToken": "lt"},
        {"Name": "h", "Scope": "REGIONAL", "Id": "2"})
    read = edge.FETCHERS["wafv2_rule_group"](aws.Requests({}), session, "eu-west-1", ACCOUNT)
    assert read.status == "collected" and len(read.items) == 2
    scope = f"{ACCOUNT}/eu-west-1"
    index = {"context": {"provider": "aws", "scope": scope},
             "collections": {"wafv2_rule_group": [{"type": "wafv2_rule_group", "scope": scope,
                 "status": "collected", "items": read.items}]},
             "wafv2_rule_group": [{"type": "wafv2_rule_group", "scope": scope, "data": row}
                                  for row in read.items]}
    for check in ("aws.cb.wafv2.rule_group_metrics", "aws.pci.wafv2.rule_group_metrics"):
        assert status(check, read.items[0], index) == "FAIL"
        assert status(check, read.items[1], index) == "PASS"
        assert status(check, read.items[0]) == "UNKNOWN"
    assert status("aws.pci.wafv2.rule_group_nonempty", read.items[0], index) == "FAIL"
    assert status("aws.pci.wafv2.rule_group_metrics", {**read.items[0], "ARN": pass_arn}, index) == "UNKNOWN"


def test_classic_waf_global_rule_group_and_web_acl(sdk):
    session, add = sdk
    stub = add("waf")
    stub.add_response("list_rule_groups", {"RuleGroups": [{"RuleGroupId": "g1", "Name": "g"}]}, {"Limit": 100})
    stub.add_response("list_activated_rules_in_rule_group", {"ActivatedRules": []}, {"RuleGroupId": "g1", "Limit": 100})
    groups = edge.FETCHERS["waf_rule_group"](aws.Requests({}), session, "eu-west-1", ACCOUNT)
    assert groups.items[0]["ActivatedRules"] == {"collection_status": "collected", "ActivatedRules": []}
    assert status("aws.cb.waf.rule_group_not_empty", groups.items[0]) == "FAIL"
    arn = f"arn:aws:waf::{ACCOUNT}:webacl/w1"
    stub.add_response("list_web_acls", {"WebACLs": [{"WebACLId": "w1", "Name": "w"}]}, {"Limit": 100})
    stub.add_response("get_web_acl", {"WebACL": {"WebACLId": "w1", "WebACLArn": arn, "DefaultAction": {"Type": "ALLOW"}, "Rules": []}}, {"WebACLId": "w1"})
    stub.add_client_error("get_logging_configuration", "WAFNonexistentItemException", "none", expected_params={"ResourceArn": arn})
    acls = edge.FETCHERS["waf_web_acl"](aws.Requests({}), session, "eu-west-1", ACCOUNT)
    assert acls.items[0]["LoggingConfiguration"]["absent"] is True
    assert status("aws.cb.waf.web_acl_logging", acls.items[0]) == "FAIL"
    assert status("aws.cb.waf.web_acl_has_rules", acls.items[0]) == "FAIL"
    stub.add_response("list_rules", {"Rules": [{"RuleId": "r1", "Name": "r"}]}, {"Limit": 100})
    stub.add_response("get_rule", {"Rule": {"RuleId": "r1", "Name": "r", "Predicates": [{"Negated": False, "Type": "IPMatch", "DataId": "d"}]}}, {"RuleId": "r1"})
    rules = edge.FETCHERS["waf_rule"](aws.Requests({}), session, "eu-west-1", ACCOUNT)
    assert status("aws.cb.waf.rule_has_conditions", rules.items[0]) == "PASS"


def test_wafregional_manual_pagination_associations_and_denial(sdk):
    session, add = sdk
    stub = add("waf-regional")
    stub.add_response("list_web_acls", {"WebACLs": [{"WebACLId": "w1", "Name": "w"}], "NextMarker": "m"}, {"Limit": 100})
    stub.add_response("list_web_acls", {"WebACLs": []}, {"Limit": 100, "NextMarker": "m"})
    arn = f"arn:aws:waf-regional:{REGION}:{ACCOUNT}:webacl/w1"
    stub.add_response("get_web_acl", {"WebACL": {"WebACLId": "w1", "WebACLArn": arn, "DefaultAction": {"Type": "ALLOW"}, "Rules": []}}, {"WebACLId": "w1"})
    stub.add_response("get_logging_configuration", {"LoggingConfiguration": {"ResourceArn": arn, "LogDestinationConfigs": ["arn:aws:firehose:us-east-1:1:deliverystream/aws-waf-logs-x"]}}, {"ResourceArn": arn})
    stub.add_response("list_resources_for_web_acl", {"ResourceArns": [LB]}, {"WebACLId": "w1", "ResourceType": "APPLICATION_LOAD_BALANCER"})
    stub.add_response("list_resources_for_web_acl", {"ResourceArns": []}, {"WebACLId": "w1", "ResourceType": "API_GATEWAY"})
    read = edge.FETCHERS["wafregional_web_acl"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "collected"
    assert status("aws.cb.wafregional.web_acl_associated", read.items[0]) == "PASS"
    assert status("aws.cb.wafregional.web_acl_logging", read.items[0]) == "PASS"
    stub.add_client_error("list_rules", "AccessDeniedException", "denied")
    assert edge.FETCHERS["wafregional_rule"](aws.Requests({}), session, REGION, ACCOUNT).status == "denied"


def test_load_balancer_http_listener_rules(sdk):
    session, add = sdk
    stub = add("elbv2")
    stub.add_response("describe_rules", {"Rules": [{"RuleArn": "r1", "IsDefault": False, "Actions": [
        {"Type": "authenticate-oidc", "Order": 1, "AuthenticateOidcConfig": {"Issuer": "i", "AuthorizationEndpoint": "a", "TokenEndpoint": "t",
         "UserInfoEndpoint": "u", "ClientId": "c", "ClientSecret": "s3cr3t", "OnUnauthenticatedRequest": "allow"}}], "Conditions": []}], "NextMarker": "m"}, {"ListenerArn": LISTENER})
    stub.add_response("describe_rules", {"Rules": [{"RuleArn": "r2", "IsDefault": True, "Actions": [
        {"Type": "redirect", "RedirectConfig": {"Protocol": "HTTPS", "Port": "443", "StatusCode": "HTTP_301"}}]}]}, {"ListenerArn": LISTENER, "Marker": "m"})
    base = {"LoadBalancerArn": LB, "LoadBalancerName": "web", "Type": "application", "Scheme": "internal", "Listeners": {"collection_status": "collected", "items": [
        {"ListenerArn": LISTENER, "Protocol": "HTTP", "Port": 80, "DefaultActions": [{"Type": "forward", "TargetGroupArn": "arn:tg"}]}]}}
    assert status("aws.c2b.elbv2.http_listeners_redirect_https", base) == "UNKNOWN"
    item = edge.ENRICHERS["load_balancer"](aws.Requests({}), session, REGION, [base])[0]
    assert "s3cr3t" not in json.dumps(item)
    assert len(item["Listeners"]["items"][0]["Rules"]["items"]) == 2
    auth_action = item["Listeners"]["items"][0]["Rules"]["items"][0]["Actions"][0]
    assert auth_action["UnauthenticatedRequestMode"] == "allow"
    assert auth_action["UnauthenticatedRequestModeSource"] == "DescribeRules"
    # The collected default rule redirects, but the listener DefaultActions
    # still forward and the conditional rule has no terminal routing action.
    # Such inconsistent/incomplete evidence cannot establish HTTPS assurance.
    assert status("aws.c2b.elbv2.http_listeners_redirect_https", item) == "UNKNOWN"


def test_load_balancer_auth_rule_projects_documented_default_mode_only(sdk):
    session, add = sdk
    add("elbv2").add_response("describe_rules", {"Rules": [{"RuleArn": "default", "IsDefault": True,
        "Actions": [{"Type": "authenticate-cognito", "Order": 1,
                     "AuthenticateCognitoConfig": {"UserPoolArn": f"arn:aws:cognito-idp:{REGION}:{ACCOUNT}:userpool/p",
                                                    "UserPoolClientId": "client", "UserPoolDomain": "domain"}},
                    {"Type": "forward", "Order": 2, "TargetGroupArn": "arn:tg"}]}]}, {"ListenerArn": LISTENER})
    base = {"LoadBalancerArn": LB, "Type": "application", "Listeners": {"collection_status": "collected",
            "items": [{"ListenerArn": LISTENER, "Protocol": "HTTPS", "Port": 443,
                       "DefaultActions": [{"Type": "authenticate-cognito"}, {"Type": "forward"}]}]}}
    projected = edge.ENRICHERS["load_balancer"](aws.Requests({}), session, REGION, [base])[0]
    action = projected["Listeners"]["items"][0]["Rules"]["items"][0]["Actions"][0]
    assert action["UnauthenticatedRequestMode"] == "authenticate"
    assert action["UnauthenticatedRequestModeSource"] == "documented_default"
    assert "UserPoolClientId" not in json.dumps(projected)


def test_cloudfront_v2_log_deliveries(sdk):
    session, add = sdk
    stub = add("logs")
    dist = f"arn:aws:cloudfront::{ACCOUNT}:distribution/E1"
    stub.add_response("describe_delivery_sources", {"deliverySources": [{"name": "cf-E1", "resourceArns": [dist], "service": "cloudfront", "logType": "ACCESS_LOGS"},
                                                                       {"name": "other", "resourceArns": ["arn:x"]}]}, {})
    stub.add_response("describe_deliveries", {"deliveries": [{"id": "d1", "deliverySourceName": "cf-E1", "deliveryDestinationArn": "arn:dest"},
                                                             {"id": "d2", "deliverySourceName": "other", "deliveryDestinationArn": "arn:dest"}]}, {})
    config = {"Config": {"DistributionConfig": {"CallerReference": "r", "Logging": {"Enabled": False, "Bucket": "", "Prefix": "", "IncludeCookies": False},
                                                "DefaultCacheBehavior": {"ViewerProtocolPolicy": "https-only"}}}}
    rows = [{"ARN": dist, "Id": "E1", **config}, {"ARN": dist.replace("E1", "E2"), "Id": "E2", **config}]
    assert status("aws.c2b.cloudfront.logging_any", rows[0]) == "UNKNOWN"
    first, second = edge.ENRICHERS["cloudfront_distribution"](aws.Requests({}), session, "eu-west-1", rows)
    assert [d["id"] for d in first["LogDeliveries"]["deliveries"]] == ["d1"]
    assert status("aws.c2b.cloudfront.logging_any", first) == "PASS"
    assert second["LogDeliveries"] == {"collection_status": "collected", "deliveries": []}
    assert status("aws.c2b.cloudfront.logging_any", second) == "FAIL"


def test_cloudfront_log_delivery_denied_is_unknown(sdk):
    session, add = sdk
    stub = add("logs")
    stub.add_client_error("describe_delivery_sources", "AccessDeniedException", "denied")
    stub.add_response("describe_deliveries", {"deliveries": []}, {})
    item = edge.ENRICHERS["cloudfront_distribution"](aws.Requests({}), session, REGION, [{"ARN": "arn:d", "Id": "E1", "Config": {"DistributionConfig": {
        "CallerReference": "r", "Logging": {"Enabled": False, "Bucket": "", "Prefix": "", "IncludeCookies": False}, "DefaultCacheBehavior": {}}}}])[0]
    assert item["LogDeliveries"]["collection_status"] == "denied" and "deliveries" not in item["LogDeliveries"]
    assert status("aws.c2b.cloudfront.logging_any", item) == "UNKNOWN"


def test_cloudfront_oac_configuration_cached_and_projected(sdk):
    session, add = sdk
    logs = add("logs")
    logs.add_response("describe_delivery_sources", {"deliverySources": []}, {})
    logs.add_response("describe_deliveries", {"deliveries": []}, {})
    cloudfront = add("cloudfront")
    cloudfront.add_response("get_origin_access_control", {"OriginAccessControl": {"Id": "OAC1",
        "OriginAccessControlConfig": {"Name": "secret-name", "Description": "not needed",
                                      "SigningBehavior": "always", "SigningProtocol": "sigv4",
                                      "OriginAccessControlOriginType": "s3"}}}, {"Id": "OAC1"})
    rows = [{"Id": name, "ARN": f"arn:aws:cloudfront::{ACCOUNT}:distribution/{name}",
             "Config": {"DistributionConfig": {"Origins": {"Items": [
                 {"Id": "origin", "OriginAccessControlId": "OAC1"}]}}}} for name in ("D1", "D2")]
    result = edge.ENRICHERS["cloudfront_distribution"](aws.Requests({}), session, REGION, rows)
    assert result[0]["OriginAccessControls"] == result[1]["OriginAccessControls"]
    assert result[0]["OriginAccessControls"]["OAC1"] == {
        "collection_status": "collected", "Id": "OAC1", "SigningBehavior": "always",
        "SigningProtocol": "sigv4", "OriginAccessControlOriginType": "s3"}


def test_cloudfront_continuous_deployment_policy_cached_and_redacted(sdk):
    session, add = sdk
    logs = add("logs")
    logs.add_response("describe_delivery_sources", {"deliverySources": []}, {})
    logs.add_response("describe_deliveries", {"deliveries": []}, {})
    cloudfront = add("cloudfront")
    cloudfront.add_response("get_continuous_deployment_policy", {
        "ContinuousDeploymentPolicy": {"Id": "POLICY1", "LastModifiedTime": "2026-01-01T00:00:00Z",
            "ContinuousDeploymentPolicyConfig": {"Enabled": True,
                "StagingDistributionDnsNames": {"Quantity": 1, "Items": ["staging.cloudfront.net"]},
                "TrafficConfig": {"Type": "SingleHeader", "SingleHeaderConfig": {
                    "Header": "aws-cf-cd-test", "Value": "private-test-value"}}}}}, {"Id": "POLICY1"})
    rows = [{"Id": name, "Config": {"DistributionConfig": {
        "ContinuousDeploymentPolicyId": "POLICY1"}}} for name in ("D1", "D2")]
    projected = edge.ENRICHERS["cloudfront_distribution"](aws.Requests({}), session, REGION, rows)
    assert projected[0]["ContinuousDeploymentPolicy"] == projected[1]["ContinuousDeploymentPolicy"]
    policy = projected[0]["ContinuousDeploymentPolicy"]
    assert policy["collection_status"] == "collected" and policy["HeaderConditionPresent"] is True
    assert policy["StagingDistributionDnsNames"]["Items"] == ["staging.cloudfront.net"]
    assert "private-test-value" not in json.dumps(projected)
    assert "aws-cf-cd-test" not in json.dumps(projected)


def test_cloudfront_oai_canonical_user_cached_and_projected(sdk):
    session, add = sdk
    logs = add("logs")
    logs.add_response("describe_delivery_sources", {"deliverySources": []}, {})
    logs.add_response("describe_deliveries", {"deliveries": []}, {})
    cloudfront = add("cloudfront")
    canonical = "a" * 64
    cloudfront.add_response("get_cloud_front_origin_access_identity", {
        "CloudFrontOriginAccessIdentity": {"Id": "E123ABC", "S3CanonicalUserId": canonical,
            "CloudFrontOriginAccessIdentityConfig": {"Comment": "not needed", "CallerReference": "not needed"}}},
        {"Id": "E123ABC"})
    rows = [{"Id": name, "Config": {"DistributionConfig": {"Origins": {"Items": [
        {"Id": "s3", "S3OriginConfig": {"OriginAccessIdentity": "origin-access-identity/cloudfront/E123ABC"}}]}}}}
        for name in ("D1", "D2")]
    result = edge.ENRICHERS["cloudfront_distribution"](aws.Requests({}), session, REGION, rows)
    assert result[0]["OriginAccessIdentities"] == result[1]["OriginAccessIdentities"]
    assert result[0]["OriginAccessIdentities"]["E123ABC"] == {
        "collection_status": "collected", "Id": "E123ABC", "S3CanonicalUserId": canonical}


def test_beanstalk_configuration_keeps_only_named_options(sdk):
    session, add = sdk
    stub = add("elasticbeanstalk")
    stub.add_response("describe_environments", {"Environments": [{"EnvironmentName": "env1", "ApplicationName": "app", "EnvironmentArn": "arn:e"}]}, {"IncludeDeleted": False})
    stub.add_response("describe_configuration_settings", {"ConfigurationSettings": [{"ApplicationName": "app", "EnvironmentName": "env1", "OptionSettings": [
        {"Namespace": "aws:elasticbeanstalk:cloudwatch:logs", "OptionName": "StreamLogs", "Value": "true"},
        {"Namespace": "aws:elasticbeanstalk:application:environment", "OptionName": "DB_PASSWORD", "Value": "hunter2"}]}]},
        {"ApplicationName": "app", "EnvironmentName": "env1"})
    requests = aws.Requests({})
    read = edge.FETCHERS["elastic_beanstalk_environment"](requests, session, REGION, ACCOUNT)
    item = edge.ENRICHERS["elastic_beanstalk_environment"](requests, session, REGION, read.items)[0]
    assert "hunter2" not in json.dumps(item) and "DB_PASSWORD" not in json.dumps(item)
    assert status("aws.c2b.elasticbeanstalk.stream_logs", item) == "PASS"
    assert status("aws.c2b.elasticbeanstalk.managed_updates", item) == "UNKNOWN"


def test_appstream_fleet_and_appsync_cache(sdk):
    session, add = sdk
    fleet = {"Arn": "arn:f", "Name": "f", "InstanceType": "stream.standard.small", "ComputeCapacityStatus": {"Desired": 1}, "State": "RUNNING",
             "EnableDefaultInternetAccess": True, "MaxUserDurationInSeconds": 3600, "DisconnectTimeoutInSeconds": 300, "IdleDisconnectTimeoutInSeconds": 600}
    add("appstream").add_response("describe_fleets", {"Fleets": [fleet]}, {})
    read = aws.Requests({}).pages(session, "appstream", REGION, "describe_fleets", "Fleets")
    item = edge.ENRICHERS["appstream_fleet"](aws.Requests({}), session, REGION, read.items)[0]
    assert status("aws.c2b.appstream.no_default_internet", item) == "FAIL"
    stub = add("appsync")
    stub.add_response("get_api_cache", {"apiCache": {"type": "SMALL", "status": "AVAILABLE", "atRestEncryptionEnabled": True, "transitEncryptionEnabled": True}}, {"apiId": "g1"})
    stub.add_client_error("get_api_cache", "NotFoundException", "none", expected_params={"apiId": "g2"})
    api = {"apiId": "g1", "name": "gql", "arn": "arn:g1", "authenticationType": "AMAZON_COGNITO_USER_POOLS", "logConfig": {"fieldLogLevel": "ERROR", "cloudWatchLogsRoleArn": "arn:r"}}
    first, second = edge.ENRICHERS["appsync_graphql_api"](aws.Requests({}), session, REGION, [api, {**api, "apiId": "g2", "arn": "arn:g2"}])
    assert status("aws.c2b.appsync.cache_at_rest_encryption", first) == "PASS"
    assert second["ApiCache"]["absent"] is True


def test_directconnect_manual_pagination_strips_bgp_keys(sdk):
    session, add = sdk
    stub = add("directconnect")
    vif = {"virtualInterfaceId": "dxvif-1", "connectionId": "dxcon-1", "virtualGatewayId": "", "directConnectGatewayId": "gw1",
           "authKey": "bgp-secret", "customerRouterConfig": "neighbor password bgp-secret", "bgpPeers": [{"bgpPeerId": "p", "authKey": "bgp-secret"}]}
    stub.add_response("describe_virtual_interfaces", {"virtualInterfaces": [vif], "nextToken": "n"}, {})
    stub.add_response("describe_virtual_interfaces", {"virtualInterfaces": [{**vif, "virtualInterfaceId": "dxvif-2", "connectionId": "dxcon-2"}]}, {"nextToken": "n"})
    read = edge.FETCHERS["directconnect_virtual_interface"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "collected" and len(read.items) == 2
    assert "bgp-secret" not in json.dumps(read.items)
    stub.add_client_error("describe_connections", "DirectConnectClientException", "denied", http_status_code=403)
    assert edge.FETCHERS["directconnect_connection"](aws.Requests({}), session, REGION, ACCOUNT).status not in ("collected", "empty")


def test_managed_prefix_list_entries_paginated(sdk):
    session, add = sdk
    stub = add("ec2")
    stub.add_response("get_managed_prefix_list_entries", {"Entries": [{"Cidr": "10.0.0.0/8"}], "NextToken": "n"}, {"PrefixListId": "pl-1"})
    stub.add_response("get_managed_prefix_list_entries", {"Entries": [{"Cidr": "0.0.0.0/0"}]}, {"PrefixListId": "pl-1", "NextToken": "n"})
    stub.add_client_error("get_managed_prefix_list_entries", "UnauthorizedOperation", "denied", expected_params={"PrefixListId": "pl-2"})
    first, second = edge.ENRICHERS["managed_prefix_list"](aws.Requests({}), session, REGION, [{"PrefixListId": "pl-1"}, {"PrefixListId": "pl-2"}])
    assert first["Entries"] == {"collection_status": "collected", "items": [{"Cidr": "10.0.0.0/8"}, {"Cidr": "0.0.0.0/0"}]}
    assert second["Entries"]["collection_status"] == "denied" and "items" not in second["Entries"]


def test_managed_prefix_list_entries_are_bound_to_described_version(sdk):
    session, add = sdk
    add("ec2").add_response("get_managed_prefix_list_entries", {"Entries": [{"Cidr": "10.0.0.0/8"}]},
        {"PrefixListId": "pl-versioned", "TargetVersion": 3})
    row = edge.ENRICHERS["managed_prefix_list"](aws.Requests({}), session, REGION,
        [{"PrefixListId": "pl-versioned", "Version": 3}])[0]
    assert row["EntriesVersion"] == 3
    assert row["Entries"]["items"] == [{"Cidr": "10.0.0.0/8"}]


def test_image_launch_permissions_and_cluster_snapshot_attributes(sdk):
    session, add = sdk
    add("ec2").add_response("describe_image_attribute", {"ImageId": "ami-1", "LaunchPermissions": [{"Group": "all"}]}, {"ImageId": "ami-1", "Attribute": "launchPermission"})
    add("ec2").add_client_error("describe_image_attribute", "UnauthorizedOperation", "denied", expected_params={"ImageId": "ami-2", "Attribute": "launchPermission"})
    first, second = edge.ENRICHERS["ec2_image"](aws.Requests({}), session, REGION, [{"ImageId": "ami-1"}, {"ImageId": "ami-2"}])
    assert first["LaunchPermissions"] == [{"Group": "all"}] and first["_coverage"]["LaunchPermissions"]["status"] == "collected"
    assert "LaunchPermissions" not in second and second["_coverage"]["LaunchPermissions"]["status"] == "denied"
    add("rds").add_response("describe_db_cluster_snapshot_attributes", {"DBClusterSnapshotAttributesResult": {"DBClusterSnapshotIdentifier": "s1",
        "DBClusterSnapshotAttributes": [{"AttributeName": "restore", "AttributeValues": ["all"]}]}}, {"DBClusterSnapshotIdentifier": "s1"})
    snap = {"DBClusterSnapshotIdentifier": "s1", "DBClusterSnapshotArn": "arn:s1", "Engine": "postgres"}
    assert status("aws.cb.rds.cluster_snapshot_not_public_prowler", snap) == "UNKNOWN"
    item = edge.ENRICHERS["rds_cluster_snapshot"](aws.Requests({}), session, REGION, [snap])[0]
    assert item["Attributes"]["collection_status"] == "collected"
    assert status("aws.cb.rds.cluster_snapshot_not_public_prowler", item) == "FAIL"
