"""Internet-to-asset exposure (peaso.analysis.internet_exposure): PASS/FAIL/UNKNOWN per scenario."""
import copy

import pytest

from peaso.analysis import analyze
from peaso.analysis.internet_exposure import describe, intersect, pset, subtract, union
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

ACCOUNT = "111122223333"
SCOPE = f"{ACCOUNT}/us-east-1"
CHECK = "analysis.internet_exposure"


def coll(kind, items, scope=SCOPE, status=None, service="ec2"):
    return {"type": kind, "scope": scope, "service": service, "status": status or ("collected" if items else "empty"), "items": items}


def exposure(snapshot, kind=None):
    findings = [f for f in analyze(snapshot)["findings"] if f["check_id"] == CHECK and not f["resource_id"].startswith("inventory")]
    return findings


def one(snapshot, resource_type):
    report = analyze(snapshot)
    ids = {r["id"]: r["type"] for r in report["resources"]}
    found = [f for f in report["findings"] if f["check_id"] == CHECK and ids.get(f["resource_id"]) == resource_type]
    assert len(found) == 1, found
    return found[0]


# ------------------------------------------------------------------ ports

def test_port_set_arithmetic():
    allowed = union(pset("tcp", 20, 30), pset("tcp", 25, 90))
    assert describe(allowed) == ["tcp/20-90"]
    assert describe(subtract(allowed, pset("tcp", 22, 22))) == ["tcp/20-21", "tcp/23-90"]
    assert describe(intersect(pset("all"), pset("udp", 53, 53))) == ["udp/53"]
    assert describe(pset("-1")) == ["tcp/all", "udp/all", "icmp"]


# -------------------------------------------------------------------- AWS

def aws_network(sg_rules=None, nacl_entries=None, igw=True, extra=()):
    sg_rules = sg_rules if sg_rules is not None else [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    nacl_entries = nacl_entries if nacl_entries is not None else [
        {"RuleNumber": 100, "Egress": False, "Protocol": "-1", "RuleAction": "allow", "CidrBlock": "0.0.0.0/0"},
        {"RuleNumber": 100, "Egress": True, "Protocol": "-1", "RuleAction": "allow", "CidrBlock": "0.0.0.0/0"}]
    routes = [{"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local", "State": "active"}]
    if igw:
        routes.append({"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1", "State": "active"})
    extras = list(extra)
    if not any(c["type"] == "vpc_block_public_access_options" for c in extras):
        extras.append(coll("vpc_block_public_access_options", [{"VpcBlockPublicAccessOptions": {
            "State": "default-state", "InternetGatewayBlockMode": "off"}}]))
    if not any(c["type"] == "internet_gateway" for c in extras):
        extras.append(coll("internet_gateway", [{"InternetGatewayId": "igw-1", "Attachments": [{"VpcId": "vpc-1", "State": "available"}]}]))
    return [
        coll("vpc", [{"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/16"}]),
        coll("subnet", [{"SubnetId": "subnet-1", "VpcId": "vpc-1", "CidrBlock": "10.0.1.0/24"}]),
        coll("route_table", [{"RouteTableId": "rtb-1", "VpcId": "vpc-1", "Associations": [{"SubnetId": "subnet-1"}], "Routes": routes}]),
        coll("network_acl", [{"NetworkAclId": "acl-1", "VpcId": "vpc-1", "Associations": [{"SubnetId": "subnet-1"}], "Entries": nacl_entries}]),
        coll("security_group", [{"GroupId": "sg-1", "VpcId": "vpc-1", "IpPermissions": sg_rules}]),
        *extras]


def instance(public=True, groups=("sg-1",)):
    interface = {"NetworkInterfaceId": "eni-1", "SubnetId": "subnet-1", "VpcId": "vpc-1", "Groups": [{"GroupId": g} for g in groups]}
    if public:
        interface["Association"] = {"PublicIp": "54.1.2.3"}
    return coll("instance", [{"InstanceId": "i-1", "State": {"Name": "running"}, "SubnetId": "subnet-1", "VpcId": "vpc-1", "NetworkInterfaces": [interface]}])


def aws(*collections, metadata=None):
    return make_snapshot("aws", [SCOPE], list(collections), created_at="2026-10-10T00:00:00+00:00", metadata=metadata)


def test_aws_instance_open_ssh_fails_with_path_evidence():
    result = one(aws(*aws_network(), instance()), "instance")
    assert result["status"] == "FAIL" and result["severity"] == "high"
    assert result["evidence"]["exposed_ports"] == ["tcp/22"]
    assert result["evidence"]["public_addresses"] == ["54.1.2.3"]
    assert result["title"] == "Internet access to tcp/22 at 54.1.2.3"
    assert result["evidence"]["observed"] == "Internet access to tcp/22 at 54.1.2.3 is allowed."
    assert [s["layer"] for s in result["evidence"]["path"]] == ["security_group", "route", "network_acl"]


def test_aws_nacl_deny_before_allow_blocks():
    entries = [{"RuleNumber": 50, "Egress": False, "Protocol": "6", "PortRange": {"From": 22, "To": 22}, "RuleAction": "deny", "CidrBlock": "0.0.0.0/0"},
               {"RuleNumber": 100, "Egress": False, "Protocol": "-1", "RuleAction": "allow", "CidrBlock": "0.0.0.0/0"}]
    result = one(aws(*aws_network(nacl_entries=entries), instance()), "instance")
    assert result["status"] == "PASS" and result["evidence"]["blocked_by"] == "network_acl"


def test_aws_no_igw_route_passes_and_private_sg_passes():
    assert one(aws(*aws_network(igw=False), instance()), "instance")["status"] == "PASS"
    private = [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]
    result = one(aws(*aws_network(sg_rules=private), instance()), "instance")
    assert result["status"] == "PASS" and result["evidence"]["blocked_by"] == "security_group"


def test_aws_vpc_public_access_block_and_igw_attachment():
    def options(mode):
        return coll("vpc_block_public_access_options", [{"VpcBlockPublicAccessOptions": {
            "State": "default-state", "InternetGatewayBlockMode": mode}}])
    exclusions = coll("vpc_block_public_access_exclusion", [])
    blocked = one(aws(*aws_network(extra=[options("block-ingress"), exclusions]), instance()), "instance")
    assert blocked["status"] == "PASS" and blocked["evidence"]["blocked_by"] == "vpc_public_access_block"
    bidirectional = coll("vpc_block_public_access_exclusion", [{"ExclusionId": "e-1", "VpcId": "vpc-1",
        "State": "create-complete", "InternetGatewayExclusionMode": "allow-bidirectional"}])
    assert one(aws(*aws_network(extra=[options("block-ingress"), bidirectional]), instance()), "instance")["status"] == "FAIL"
    egress_only = coll("vpc_block_public_access_exclusion", [{"ExclusionId": "e-1", "SubnetId": "subnet-1",
        "State": "create-complete", "InternetGatewayExclusionMode": "allow-egress"}])
    assert one(aws(*aws_network(extra=[options("block-bidirectional"), egress_only]), instance()), "instance")["status"] == "PASS"
    detached = coll("internet_gateway", [{"InternetGatewayId": "igw-1", "Attachments": []}])
    assert one(aws(*aws_network(extra=[options("off"), detached]), instance()), "instance")["status"] == "PASS"


def test_aws_missing_security_group_inventory_is_unknown():
    network = [c for c in aws_network() if c["type"] != "security_group"] + [coll("security_group", [], status="denied")]
    assert one(aws(*network, instance()), "instance")["status"] == "UNKNOWN"


def test_aws_security_group_managed_prefix_list_world_entry():
    rules = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
              "PrefixListIds": [{"PrefixListId": "pl-1"}]}]
    prefix = coll("managed_prefix_list", [{"PrefixListId": "pl-1", "Entries": {
        "collection_status": "collected", "items": [{"Cidr": "0.0.0.0/0"}]}}])
    result = one(aws(*aws_network(sg_rules=rules, extra=[prefix]), instance()), "instance")
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/443"]
    missing = one(aws(*aws_network(sg_rules=rules), instance()), "instance")
    assert missing["status"] == "UNKNOWN"


def test_aws_instance_without_public_ip_is_not_assessed():
    assert not exposure(aws(*aws_network(), instance(public=False)))


def test_aws_ipv6_instance_requires_matching_sg_acl_and_igw_route():
    ipv6_instance = instance(public=False)
    ipv6_instance["items"][0]["NetworkInterfaces"][0]["Ipv6Addresses"] = [{"Ipv6Address": "2001:db8::10"}]
    network = aws_network()
    # An IPv4 path cannot make an IPv6-only address reachable.
    assert one(aws(*network, ipv6_instance), "instance")["status"] == "PASS"
    sg = next(c for c in network if c["type"] == "security_group")
    sg["items"][0]["IpPermissions"][0]["Ipv6Ranges"] = [{"CidrIpv6": "::/0"}]
    acl = next(c for c in network if c["type"] == "network_acl")
    for entry in acl["items"][0]["Entries"]:
        entry["Ipv6CidrBlock"] = "::/0"
    assert one(aws(*network, ipv6_instance), "instance")["status"] == "PASS"
    table = next(c for c in network if c["type"] == "route_table")
    table["items"][0]["Routes"].append({"DestinationIpv6CidrBlock": "::/0", "GatewayId": "igw-1", "State": "active"})
    result = one(aws(*network, ipv6_instance), "instance")
    assert result["status"] == "FAIL"
    assert result["evidence"]["exposed_ports"] == ["tcp/22"]


def test_aws_attached_eip_fills_missing_instance_public_association():
    eip = coll("elastic_ip", [{"AllocationId": "eipalloc-1", "AssociationId": "eipassoc-1",
                               "NetworkInterfaceId": "eni-1", "PublicIp": "54.1.2.3"}])
    result = one(aws(*aws_network(), instance(public=False), eip), "instance")
    assert result["status"] == "FAIL"
    assert result["evidence"]["public_addresses"] == ["54.1.2.3"]
    eip["items"].append({"AllocationId": "eipalloc-2", "AssociationId": "eipassoc-2",
                         "NetworkInterfaceId": "eni-1", "PublicIp": "54.1.2.4"})
    result = one(aws(*aws_network(), instance(public=False), eip), "instance")
    assert result["evidence"]["public_addresses"] == ["54.1.2.3", "54.1.2.4"]
    unattached = coll("elastic_ip", [{"AllocationId": "eipalloc-1", "PublicIp": "54.1.2.3"}])
    assert not exposure(aws(*aws_network(), instance(public=False), unattached))


def test_aws_internet_facing_alb_listener_and_sg():
    lb = {"LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/web/1", "Scheme": "internet-facing", "Type": "application",
          "DNSName": "web-1.us-east-1.elb.amazonaws.com", "VpcId": "vpc-1", "SecurityGroups": ["sg-1"], "AvailabilityZones": [{"SubnetId": "subnet-1"}],
          "Listeners": {"collection_status": "collected", "items": [{"Port": 443, "Protocol": "HTTPS"}, {"Port": 8080, "Protocol": "HTTP"}]}}
    rules = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    result = one(aws(*aws_network(sg_rules=rules), coll("load_balancer", [lb], service="elbv2")), "load_balancer")
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/443"]
    assert result["severity"] == "medium"
    internal = copy.deepcopy(lb) | {"Scheme": "internal"}
    assert not exposure(aws(*aws_network(sg_rules=rules), coll("load_balancer", [internal], service="elbv2")))
    unknown = copy.deepcopy(lb) | {"Listeners": {"collection_status": "denied", "items": []}}
    assert one(aws(*aws_network(sg_rules=rules), coll("load_balancer", [unknown], service="elbv2")), "load_balancer")["status"] == "UNKNOWN"


def test_aws_public_rds_instance():
    db = {"DBInstanceArn": "arn:aws:rds:us-east-1:111122223333:db:prod", "PubliclyAccessible": True, "Engine": "postgres", "Endpoint": {"Address": "prod.x.rds.amazonaws.com", "Port": 5432},
          "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-1", "Status": "active"}], "DBSubnetGroup": {"VpcId": "vpc-1", "Subnets": [{"SubnetIdentifier": "subnet-1"}]}}
    rules = [{"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    result = one(aws(*aws_network(sg_rules=rules), coll("rds_instance", [db], service="rds")), "rds_instance")
    assert result["status"] == "FAIL" and result["severity"] == "critical" and result["evidence"]["exposed_ports"] == ["tcp/5432"]
    assert one(aws(*aws_network(), coll("rds_instance", [db], service="rds")), "rds_instance")["status"] == "PASS"


def test_aws_redshift_public_cluster_uses_collected_subnet_route_and_acl():
    cluster = {"ClusterIdentifier": "warehouse", "PubliclyAccessible": True,
               "Endpoint": {"Address": "warehouse.example.amazonaws.com", "Port": 5439},
               "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-1"}], "ClusterSubnetGroupName": "redshift-subnets"}
    group = coll("redshift_subnet_group", [{"ClusterSubnetGroupName": "redshift-subnets", "VpcId": "vpc-1",
                 "Subnets": [{"SubnetIdentifier": "subnet-1"}]}], service="redshift")
    rules = [{"IpProtocol": "tcp", "FromPort": 5439, "ToPort": 5439, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    def row(network, include_group=True):
        return one(aws(*network, coll("redshift_cluster", [cluster], service="redshift"),
                       *([group] if include_group else [])), "redshift_cluster")
    assert row(aws_network(sg_rules=rules))["status"] == "FAIL"
    assert row(aws_network(sg_rules=rules, igw=False))["status"] == "PASS"
    assert row(aws_network(sg_rules=rules), include_group=False)["status"] == "UNKNOWN"


@pytest.mark.parametrize("kind,field,permission,operation", [
    ("ebs_snapshot", "CreateVolumePermissions", "createVolumePermission", "DescribeSnapshotAttribute"),
    ("ec2_image", "LaunchPermissions", "launchPermission", "DescribeImageAttribute"),
])
def test_aws_ec2_public_and_external_shares(kind, field, permission, operation):
    identity = {"SnapshotId": "snap-1"} if kind == "ebs_snapshot" else {"ImageId": "ami-1"}
    coverage = {"_coverage": {field: {"status": "collected", "source_operation": f"ec2:{operation}"}}}
    def row(values, state="unblocked"):
        settings = [coll("ec2_regional_settings", [{"SnapshotBlockPublicAccessState": state}])] if kind == "ebs_snapshot" else []
        return one(aws(coll(kind, [{**identity, **coverage, field: values}]), *settings), kind)
    public = row([{"Group": "all"}])
    assert public["status"] == "FAIL" and public["evidence"]["data_exposure"] is True
    external = row([{"UserId": "999988887777"}])
    assert external["status"] == "FAIL" and external["evidence"]["external_scope_ids"] == ["999988887777"]
    assert row([])["status"] == "PASS"
    if kind == "ebs_snapshot":
        assert row([{"Group": "all"}], "block-all-sharing")["status"] == "PASS"
        assert row([{"UserId": "999988887777"}], "block-all-sharing")["status"] == "FAIL"
    incomplete = one(aws(coll(kind, [{**identity, field: [{"Group": "all"}]}])), kind)
    assert incomplete["status"] == "UNKNOWN"


def test_aws_cloudfront_enabled_viewer_endpoint_and_missing_config():
    base = {"ARN": "arn:aws:cloudfront::111122223333:distribution/D1", "Id": "D1", "DomainName": "d123.cloudfront.net"}
    config = {"collection_status": "collected", "DistributionConfig": {"Enabled": True,
              "DefaultCacheBehavior": {"ViewerProtocolPolicy": "redirect-to-https"}}}
    def row(value):
        return one(aws(coll("cloudfront_distribution", [{**base, "Config": value}], service="cloudfront")), "cloudfront_distribution")
    exposed = row(config)
    assert exposed["status"] == "FAIL" and exposed["evidence"]["exposed_ports"] == ["tcp/80", "tcp/443"]
    assert row({"collection_status": "denied"})["status"] == "UNKNOWN"
    assert not exposure(aws(coll("cloudfront_distribution", [{**base, "Config": {**config, "DistributionConfig": {**config["DistributionConfig"], "Enabled": False}}}], service="cloudfront")))


def test_aws_app_runner_public_default_private_and_missing_detail():
    base = {"ServiceArn": f"arn:aws:apprunner:us-east-1:{ACCOUNT}:service/test/1", "ServiceUrl": "test.awsapprunner.com", "Status": "RUNNING"}
    def row(ingress):
        details = {"NetworkConfiguration": {"IngressConfiguration": ingress}, "ServiceUrl": base["ServiceUrl"], "Status": "RUNNING"}
        return one(aws(coll("app_runner_service", [{**base, "NetworkDetails": details}], service="apprunner")), "app_runner_service")
    assert row({})["status"] == "FAIL"  # Documented default is public.
    assert row({"IsPubliclyAccessible": True})["evidence"]["exposed_ports"] == ["tcp/443"]
    assert row({"IsPubliclyAccessible": False})["status"] == "PASS"
    assert one(aws(coll("app_runner_service", [{**base, "NetworkDetails": {"collection_status": "denied"}}], service="apprunner")), "app_runner_service")["status"] == "UNKNOWN"


def test_aws_amplify_hosted_branches_have_public_viewer_endpoint():
    base = {"appArn": f"arn:aws:amplify:us-east-1:{ACCOUNT}:apps/d1", "defaultDomain": "d1.amplifyapp.com", "enableBasicAuth": False}
    def snapshot(branches):
        return aws(coll("amplify_app", [{**base, "Branches": branches}], service="amplify"))
    hosted = one(snapshot({"collection_status": "collected", "items": [{"branchName": "main"}]}), "amplify_app")
    assert hosted["status"] == "FAIL" and hosted["evidence"]["exposed_ports"] == ["tcp/443"]
    assert one(snapshot({"collection_status": "denied"}), "amplify_app")["status"] == "UNKNOWN"
    assert not exposure(snapshot({"collection_status": "empty", "items": []}))


def test_aws_amplify_branch_display_auth_and_verified_custom_domain():
    app = {"appArn": f"arn:aws:amplify:us-east-1:{ACCOUNT}:apps/d1", "defaultDomain": "d1.amplifyapp.com",
           "enableBasicAuth": False, "Branches": {"collection_status": "collected", "items": [
               {"branchName": "main", "displayName": "web", "enableBasicAuth": True}]},
           "DomainAssociations": {"collection_status": "collected", "items": [
               {"domainName": "example.com", "domainStatus": "AVAILABLE", "subDomains": [
                   {"subDomainSetting": {"prefix": "www", "branchName": "main"}, "verified": True},
                   {"subDomainSetting": {"prefix": "old", "branchName": "main"}, "verified": False}]}]}}
    result = one(aws(coll("amplify_app", [app], service="amplify")), "amplify_app")
    assert result["status"] == "FAIL"
    assert result["evidence"]["public_addresses"] == ["web.d1.amplifyapp.com", "www.example.com"]
    assert result["evidence"]["authenticated_endpoint"] is True


def lambda_function(auth="NONE", policy=True):
    statements = [
        {"Effect": "Allow", "Principal": "*", "Action": "lambda:InvokeFunctionUrl", "Resource": "*",
         "Condition": {"StringEquals": {"lambda:FunctionUrlAuthType": "NONE"}}},
        {"Effect": "Allow", "Principal": "*", "Action": "lambda:InvokeFunction", "Resource": "*",
         "Condition": {"Bool": {"lambda:InvokedViaFunctionUrl": "true"}}},
    ]
    return {"FunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:f", "FunctionName": "f",
            "FunctionUrl": {"collection_status": "collected", "AuthType": auth, "FunctionUrl": "https://abc.lambda-url.us-east-1.on.aws/",
                            "CreationTime": "2026-01-01T00:00:00Z"},
            "Policy": {"collection_status": "collected", "Policy": {"Version": "2012-10-17", "Statement": statements}} if policy else {"collection_status": "empty", "absent": True}}


def test_lambda_function_url_auth_none():
    assert one(aws(coll("lambda_function", [lambda_function()], service="lambda")), "lambda_function")["status"] == "FAIL"
    assert one(aws(coll("lambda_function", [lambda_function(policy=False)], service="lambda")), "lambda_function")["status"] == "PASS"
    assert one(aws(coll("lambda_function", [lambda_function(auth="AWS_IAM")], service="lambda")), "lambda_function")["status"] == "PASS"
    denied = lambda_function() | {"Policy": {"collection_status": "denied"}}
    assert one(aws(coll("lambda_function", [denied], service="lambda")), "lambda_function")["status"] == "UNKNOWN"


def test_lambda_function_url_requires_both_public_invocation_actions_for_new_urls():
    base = lambda_function()
    policy = base["Policy"]["Policy"]
    only_url = copy.deepcopy(base)
    only_url["Policy"]["Policy"]["Statement"] = policy["Statement"][:1]
    assert one(aws(coll("lambda_function", [only_url], service="lambda")), "lambda_function")["status"] == "PASS"
    legacy = copy.deepcopy(only_url)
    legacy["FunctionUrl"]["CreationTime"] = "2024-01-01T00:00:00Z"
    assert one(aws(coll("lambda_function", [legacy], service="lambda")), "lambda_function")["status"] == "UNKNOWN"
    unknown = copy.deepcopy(base)
    unknown["Policy"]["Policy"]["Statement"][1]["Condition"] = {"StringEquals": {"aws:SourceVpce": "vpce-1"}}
    assert one(aws(coll("lambda_function", [unknown], service="lambda")), "lambda_function")["status"] == "UNKNOWN"
    blocked = copy.deepcopy(base)
    blocked["Policy"]["Policy"]["Statement"].append({"Effect": "Deny", "Principal": "*", "Action": "lambda:InvokeFunction",
                                                     "Resource": "*"})
    assert one(aws(coll("lambda_function", [blocked], service="lambda")), "lambda_function")["status"] == "PASS"
    wildcard = copy.deepcopy(base)
    wildcard["Policy"]["Policy"]["Statement"] = [{"Effect": "Allow", "Principal": "*",
        "Action": "lambda:Invoke*", "Resource": "*"}]
    assert one(aws(coll("lambda_function", [wildcard], service="lambda")), "lambda_function")["status"] == "FAIL"


def test_api_gateway_auth_not_collected_is_unknown_and_private_passes():
    api = {"id": "a1b2", "name": "api", "endpointConfiguration": {"types": ["REGIONAL"]}}
    result = one(aws(coll("rest_api", [api], service="apigateway")), "rest_api")
    assert result["status"] == "UNKNOWN" and result["evidence"]["collector_facts_needed"]
    private = api | {"endpointConfiguration": {"types": ["PRIVATE"]}}
    assert one(aws(coll("rest_api", [private], service="apigateway")), "rest_api")["status"] == "PASS"
    http = {"ApiId": "h1", "ApiEndpoint": "https://h1.execute-api.us-east-1.amazonaws.com", "ProtocolType": "HTTP",
            "Routes": [{"RouteKey": "GET /", "AuthorizationType": "NONE"}]}
    assert one(aws(coll("http_api", [http], service="apigatewayv2")), "http_api")["status"] == "FAIL"
    http["Routes"] = [{"RouteKey": "GET /", "AuthorizationType": "JWT"}]
    assert one(aws(coll("http_api", [http], service="apigatewayv2")), "http_api")["status"] == "PASS"


def test_rest_api_collected_method_authorization():
    api = {"id": "a1b2", "endpointConfiguration": {"types": ["REGIONAL"]},
           "Methods": [{"httpMethod": "GET", "authorizationType": "NONE", "apiKeyRequired": False}]}
    assert one(aws(coll("rest_api", [api], service="apigateway")), "rest_api")["status"] == "FAIL"
    api["Methods"][0]["authorizationType"] = "AWS_IAM"
    result = one(aws(coll("rest_api", [api], service="apigateway")), "rest_api")
    assert result["status"] == "PASS" and result["evidence"]["authenticated_endpoint"] is True
    api["Methods"][0].pop("apiKeyRequired")
    assert one(aws(coll("rest_api", [api], service="apigateway")), "rest_api")["status"] == "UNKNOWN"


def test_public_and_external_rds_snapshots():
    def snap(values):
        return {"DBSnapshotArn": f"arn:aws:rds:us-east-1:{ACCOUNT}:snapshot:s", "SnapshotType": "manual",
                "Attributes": {"collection_status": "collected", "DBSnapshotAttributesResult": {"DBSnapshotAttributes": [{"AttributeName": "restore", "AttributeValues": values}]}}}
    public = one(aws(coll("rds_snapshot", [snap(["all"])], service="rds")), "rds_snapshot")
    assert public["status"] == "FAIL" and public["severity"] == "critical" and public["evidence"]["data_exposure"]
    external = one(aws(coll("rds_snapshot", [snap(["999988887777"])], service="rds")), "rds_snapshot")
    assert external["status"] == "FAIL" and external["evidence"]["external_scope_ids"] == ["999988887777"]
    assert one(aws(coll("rds_snapshot", [snap([ACCOUNT])], service="rds")), "rds_snapshot")["status"] == "PASS"
    missing = snap([]) | {"Attributes": {"collection_status": "denied"}}
    assert one(aws(coll("rds_snapshot", [missing], service="rds")), "rds_snapshot")["status"] == "UNKNOWN"


def bucket(public_policy=True, bucket_pab=None):
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]}
    return {"Name": "b", "PolicyStatus": {"collection_status": "collected", "PolicyStatus": {"IsPublic": public_policy}},
            "Policy": {"collection_status": "collected", "Policy": policy}, "Acl": {"collection_status": "collected", "Grants": []},
            "PublicAccessBlock": {"collection_status": "collected", "PublicAccessBlockConfiguration": bucket_pab} if bucket_pab else {"collection_status": "empty", "absent": True}}


def test_s3_public_bucket_honours_account_block_public_access():
    account_open = coll("s3_account_public_access_block", [], status="empty", service="s3control")
    assert one(aws(coll("bucket", [bucket()], service="s3"), account_open), "bucket")["status"] == "FAIL"
    restricted = coll("s3_account_public_access_block", [{"PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}], service="s3control")
    result = one(aws(coll("bucket", [bucket()], service="s3"), restricted), "bucket")
    assert result["status"] == "PASS" and result["evidence"]["blocked_by"] == "public_access_block"
    assert one(aws(coll("bucket", [bucket()], service="s3")), "bucket")["status"] == "UNKNOWN"
    assert not exposure(aws(coll("bucket", [bucket(public_policy=False)], service="s3"), account_open))


def test_eks_public_endpoint_honours_cidrs():
    def cluster(cidrs):
        return {"name": "c", "Cluster": {"cluster": {"endpoint": "https://x.eks.amazonaws.com", "resourcesVpcConfig": {"endpointPublicAccess": True, "publicAccessCidrs": cidrs}}}}
    assert one(aws(coll("eks_cluster", [cluster(["0.0.0.0/0"])], service="eks")), "eks_cluster")["status"] == "FAIL"
    assert one(aws(coll("eks_cluster", [cluster(["203.0.113.0/24"])], service="eks")), "eks_cluster")["status"] == "PASS"


def test_network_graph_marks_exposed_nodes_from_internet():
    graph = analyze(aws(*aws_network(), instance()))["graphs"]["network"]
    internet = [n for n in graph["nodes"] if n["type"] == "internet"]
    assert len(internet) == 1
    edges = [e for e in graph["edges"] if e["type"] == "internet_exposure"]
    assert edges and edges[0]["source"] == internet[0]["id"] and edges[0]["evidence"]["exposed_ports"] == ["tcp/22"]
    target = next(n for n in graph["nodes"] if n["id"] == edges[0]["target"])
    assert target["exposure"]["status"] == "FAIL"
    assert any(a.get("kind") == "internet_exposed" for a in target["risk_annotations"])


def test_coverage_finding_lists_missing_inventory():
    snapshot = aws(coll("instance", [], status="denied"))
    report = analyze(snapshot)
    gap = [f for f in report["findings"] if f["check_id"] == CHECK and f["resource_id"] == "inventory:internet_exposure"]
    assert gap and gap[0]["status"] == "UNKNOWN" and {"type": "instance", "status": "denied"} in gap[0]["evidence"]["gaps"]


# -------------------------------------------------------------------- GCP

GSCOPE = "projects/p1"
NET = "https://www.googleapis.com/compute/v1/projects/p1/global/networks/default"


def gcp(*collections):
    return make_snapshot("gcp", [GSCOPE], list(collections), created_at="2026-10-10T00:00:00+00:00")


def gcoll(kind, items, status=None, service="compute"):
    return coll(kind, items, scope=GSCOPE, status=status, service=service)


def gcp_instance(tags=("web",)):
    return gcoll("instance", [{"id": "1", "name": "vm", "status": "RUNNING", "tags": {"items": list(tags)},
        "serviceAccounts": [{"email": "sa@p1.iam.gserviceaccount.com"}],
        "networkInterfaces": [{"name": "nic0", "network": NET, "accessConfigs": [{"natIP": "34.1.1.1"}]}]}])


def fw(name, priority, action, ports, targets=None, sources=("0.0.0.0/0",)):
    rule = {"id": name, "name": name, "network": NET, "direction": "INGRESS", "priority": priority, "sourceRanges": list(sources),
            action: [{"IPProtocol": "tcp", "ports": ports}]}
    if targets:
        rule["targetTags"] = targets
    return rule


def test_gcp_firewall_priority_deny_and_target_tags():
    rules = [fw("allow-ssh", 1000, "allowed", ["22"], ["web"]), fw("allow-rdp", 1000, "allowed", ["3389"], ["db"])]
    result = one(gcp(gcoll("firewall", rules), gcoll("firewall_policy", [], status="empty"), gcp_instance()), "instance")
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/22"]
    rules.append(fw("deny-ssh", 1000, "denied", ["22"]))
    result = one(gcp(gcoll("firewall", rules), gcoll("firewall_policy", [], status="empty"), gcp_instance()), "instance")
    assert result["status"] == "PASS"
    assert one(gcp(gcoll("firewall", [], status="denied"), gcp_instance()), "instance")["status"] == "UNKNOWN"
    public_subset = [fw("allow-public-subset", 1000, "allowed", ["443"], sources=("8.8.8.0/24",))]
    assert one(gcp(gcoll("firewall", public_subset), gcoll("firewall_policy", [], status="empty"),
                   gcp_instance()), "instance")["status"] == "FAIL"


def test_gcp_firewall_policy_requires_effective_attachment_decision():
    policy = {"name": "policy-1", "rules": [{"priority": 100, "direction": "INGRESS", "action": "allow",
        "match": {"srcIpRanges": ["0.0.0.0/0"], "layer4Configs": [{"ipProtocol": "tcp", "ports": ["22"]}]}}]}
    result = one(gcp(gcoll("firewall", [fw("allow-ssh", 1000, "allowed", ["22"])]),
                     gcoll("firewall_policy", [policy]), gcp_instance()), "instance")
    assert result["status"] == "UNKNOWN"
    assert any("per-instance rule decision" in gap["reason"] for gap in result["evidence"]["unresolved"])


def test_gcp_bigquery_legacy_acl_and_authorized_resource():
    public = {"name": "projects/p1/datasets/shared", "datasetReference": {"projectId": "p1", "datasetId": "shared"},
              "access": [{"role": "READER", "specialGroup": "allAuthenticatedUsers"}]}
    result = one(gcp(gcoll("bigquery_dataset", [public], service="bigquery")), "bigquery_dataset")
    assert result["status"] == "FAIL" and result["evidence"]["data_exposure"]
    assert result["evidence"]["authenticated_endpoint"]
    delegated = {"name": "projects/p1/datasets/source", "datasetReference": {"projectId": "p1", "datasetId": "source"},
                 "access": [{"view": {"projectId": "foreign", "datasetId": "views", "tableId": "v"}}]}
    result = one(gcp(gcoll("bigquery_dataset", [delegated], service="bigquery")), "bigquery_dataset")
    assert result["status"] == "FAIL" and result["evidence"]["external_scope_ids"] == ["foreign"]
    assert result["evidence"]["path"][0]["delegated"][0]["reference"]["projectId"] == "foreign"
    delegated["access"][0]["view"]["projectId"] = "p1"
    assert one(gcp(gcoll("bigquery_dataset", [delegated], service="bigquery")), "bigquery_dataset")["status"] == "UNKNOWN"
    delegated["access"] = [{"dataset": {"dataset": {"project_id": "foreign", "dataset_id": "views"},
                                 "target_types": ["VIEWS"]}}]
    result = one(gcp(gcoll("bigquery_dataset", [delegated], service="bigquery")), "bigquery_dataset")
    assert result["status"] == "FAIL" and result["evidence"]["external_scope_ids"] == ["foreign"]


@pytest.mark.parametrize("kind,target_segment,detail", [
    ("target_instance", "targetInstances", {"instance": "vm-ref"}),
    ("target_pool", "targetPools", {"instances": ["vm-ref"]}),
])
def test_gcp_external_forwarding_to_legacy_compute_target_joins_vm_firewall(kind, target_segment, detail):
    target = f"https://compute.googleapis.com/compute/v1/projects/p1/regions/us-central1/{target_segment}/t"
    vm = {"name": "vm", "selfLink": "vm-ref", "status": "RUNNING",
          "networkInterfaces": [{"network": NET}]}
    forwarding = {"name": "fr", "IPAddress": "34.4.4.4", "IPProtocol": "TCP", "ports": ["443"],
                  "loadBalancingScheme": "EXTERNAL", "target": target}
    result = one(gcp(gcoll("forwarding_rule", [forwarding]), gcoll(kind, [{"name": "t", "selfLink": target, **detail}]),
                     gcoll("instance", [vm]), gcoll("firewall", [fw("allow-443", 1000, "allowed", ["443"])]),
                     gcoll("firewall_policy", [], status="empty")), "forwarding_rule")
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/443"]


def test_gcp_beyondcorp_gateway_and_contact_center_private_ingress():
    connection = {"name": "projects/p1/locations/r/appConnections/c", "state": "CREATED",
                  "gateway": {"uri": "https://gate.example.test", "ingressPort": 19443}}
    result = one(gcp(gcoll("beyondcorp_connection", [connection], service="beyondcorp")), "beyondcorp_connection")
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/19443"]
    center = {"name": "projects/p1/locations/r/contactCenters/c", "privateAccess": {}}
    assert one(gcp(gcoll("contact_center", [center], service="contactcenteraiplatform")), "contact_center")["status"] == "FAIL"
    center["privateAccess"] = {"ingressSettings": [{"name": "AGENT"}]}
    assert one(gcp(gcoll("contact_center", [center], service="contactcenteraiplatform")), "contact_center")["status"] == "PASS"


def test_gcp_oracle_goldengate_public_deployment_keeps_foreign_firewall_unknown():
    deployment = {"name": "projects/p1/locations/r/goldengateDeployments/g",
                  "properties": {"isPublic": True, "publicIpAddress": "34.7.7.7", "nsgIds": ["nsg-1"]}}
    result = one(gcp(gcoll("oracle_goldengate_deployment", [deployment], service="oracledatabase")),
                 "oracle_goldengate_deployment")
    assert result["status"] == "UNKNOWN"
    assert result["evidence"]["public_addresses"] == ["34.7.7.7"]
    assert "no read endpoint for OCI NSG ingress" in result["evidence"]["unresolved"][0]["reason"]
    deployment["properties"]["isPublic"] = False
    assert not exposure(gcp(gcoll("oracle_goldengate_deployment", [deployment], service="oracledatabase")),
                        "oracle_goldengate_deployment")


def test_gcp_vertex_sandbox_public_load_balancer_is_reported_unknown():
    sandbox = {"name": "projects/p1/locations/r/reasoningEngines/e/sandboxEnvironments/s",
               "state": "STATE_RUNNING", "connectionInfo": {"loadBalancerIp": "34.1.2.3",
               "loadBalancerHostname": "s.example.test"}}
    result = one(gcp(gcoll("vertex_agent_sandbox", [sandbox], service="aiplatform")), "vertex_agent_sandbox")
    assert result["status"] == "UNKNOWN" and "34.1.2.3" in result["evidence"]["public_addresses"]
    assert "no listener port" in result["evidence"]["unresolved"][0]["reason"]


def test_gcp_firebase_rules_conditional_read_stays_unknown():
    release = {"name": "projects/p1/releases/cloud.firestore", "rulesetName": "projects/p1/rulesets/r",
               "source_inspected": True, "public_read": False, "public_write": False,
               "authenticated_read": False, "conditional_read": True, "services": ["cloud.firestore"]}
    result = one(gcp(gcoll("firebase_rules_release", [release], service="firebaserules")), "firebase_rules_release")
    assert result["status"] == "UNKNOWN" and result["evidence"]["unresolved"]


def test_gcp_cloud_run_invoker_and_ingress():
    def service(ingress="INGRESS_TRAFFIC_ALL", members=("allUsers",)):
        return {"name": "projects/p1/locations/r/services/s", "uri": "https://s.run.app", "ingress": ingress,
                "iamPolicy": {"bindings": [{"role": "roles/run.invoker", "members": list(members)}]}}
    assert one(gcp(gcoll("cloudrun_service", [service()], service="run")), "cloudrun_service")["status"] == "FAIL"
    service_invoker = service()
    service_invoker["iamPolicy"]["bindings"][0]["role"] = "roles/run.servicesInvoker"
    assert one(gcp(gcoll("cloudrun_service", [service_invoker], service="run")), "cloudrun_service")["status"] == "FAIL"
    assert one(gcp(gcoll("cloudrun_service", [service(members=["user:a@x.com"])], service="run")), "cloudrun_service")["status"] == "PASS"
    assert one(gcp(gcoll("cloudrun_service", [service(ingress="INGRESS_TRAFFIC_INTERNAL_ONLY")], service="run")), "cloudrun_service")["status"] == "PASS"
    no_policy = service()
    no_policy.pop("iamPolicy")
    assert one(gcp(gcoll("cloudrun_service", [no_policy], service="run")), "cloudrun_service")["status"] == "UNKNOWN"


@pytest.mark.parametrize("kind,service,role", [
    ("cloudrun_service", "run", "roles/run.invoker"),
    ("function", "cloudfunctions", "roles/cloudfunctions.invoker"),
])
def test_gcp_conditional_public_invoker_is_unresolved(kind, service, role):
    row = {"name": "projects/p1/locations/r/services/s", "uri": "https://s.run.app"} if kind == "cloudrun_service" else {
        "name": "projects/p1/locations/r/functions/f", "serviceConfig": {"uri": "https://f.cloudfunctions.net"}}
    row["iamPolicy"] = {"bindings": [{"role": role, "members": ["allUsers"],
        "condition": {"expression": "request.time < timestamp('2026-11-01T00:00:00Z')"}}]}
    result = one(gcp(gcoll(kind, [row], service=service)), kind)
    assert result["status"] == "UNKNOWN"
    assert result["evidence"]["unresolved"][0]["layer"] == "invoker"
    assert result["evidence"]["path"][-1]["decision"] == "unknown"

    row["iamPolicy"]["bindings"].append({"role": role, "members": ["allUsers"]})
    assert one(gcp(gcoll(kind, [row], service=service)), kind)["status"] == "FAIL"


def test_gcp_proxy_lb_cloud_armor():
    fr = {"id": "fr", "name": "fr", "selfLink": "fr", "loadBalancingScheme": "EXTERNAL_MANAGED", "IPAddress": "34.2.2.2", "IPProtocol": "TCP",
          "portRange": "443-443", "target": "https://x/targetHttpsProxies/p"}
    proxy = {"id": "p", "selfLink": "https://x/targetHttpsProxies/p", "urlMap": "https://x/urlMaps/m"}
    url_map = {"id": "m", "selfLink": "https://x/urlMaps/m", "defaultService": "https://x/backendServices/b"}
    backend = {"id": "b", "selfLink": "https://x/backendServices/b"}
    def snap(service):
        return gcp(gcoll("forwarding_rule", [fr]), gcoll("target_proxy", [proxy]), gcoll("url_map", [url_map]), gcoll("backend_service", [service]))
    assert one(snap(backend), "forwarding_rule")["status"] == "FAIL"
    assert one(snap(backend | {"securityPolicy": "https://x/securityPolicies/armor"}), "forwarding_rule")["status"] == "UNKNOWN"
    policy = {"name": "armor", "selfLink": "https://x/securityPolicies/armor", "rules": [
        {"priority": 2147483647, "action": "deny(403)", "match": {"config": {"srcIpRanges": ["*"]}}}]}
    guarded = gcp(gcoll("forwarding_rule", [fr]), gcoll("target_proxy", [proxy]), gcoll("url_map", [url_map]),
                  gcoll("backend_service", [backend | {"securityPolicy": policy["selfLink"]}]),
                  gcoll("security_policy", [policy]))
    assert one(guarded, "forwarding_rule")["status"] == "PASS"
    policy["rules"][0]["action"] = "allow"
    guarded = gcp(gcoll("forwarding_rule", [fr]), gcoll("target_proxy", [proxy]), gcoll("url_map", [url_map]),
                  gcoll("backend_service", [backend | {"securityPolicy": policy["selfLink"]}]),
                  gcoll("security_policy", [policy]))
    assert one(guarded, "forwarding_rule")["status"] == "FAIL"
    policy["rules"].insert(0, {"priority": 100, "action": "deny(403)",
                               "match": {"config": {"srcIpRanges": ["10.0.0.0/8"]}}})
    guarded = gcp(gcoll("forwarding_rule", [fr]), gcoll("target_proxy", [proxy]), gcoll("url_map", [url_map]),
                  gcoll("backend_service", [backend | {"securityPolicy": policy["selfLink"]}]),
                  gcoll("security_policy", [policy]))
    assert one(guarded, "forwarding_rule")["status"] == "FAIL"
    policy["rules"].pop(0)
    policy["rules"].insert(0, {"priority": 100, "action": "allow", "match": {"expr": {"expression": "request.path.startsWith('/admin')"}}})
    guarded = gcp(gcoll("forwarding_rule", [fr]), gcoll("target_proxy", [proxy]), gcoll("url_map", [url_map]),
                  gcoll("backend_service", [backend | {"securityPolicy": policy["selfLink"]}]),
                  gcoll("security_policy", [policy]))
    assert one(guarded, "forwarding_rule")["status"] == "UNKNOWN"
    no_address = copy.deepcopy(fr)
    no_address.pop("IPAddress")
    assert one(gcp(gcoll("forwarding_rule", [no_address])), "forwarding_rule")["status"] == "UNKNOWN"


def test_gcp_passthrough_lb_joins_healthy_vm_firewall_without_vm_public_ip():
    base = "https://compute.googleapis.com/compute/v1/projects/p1"
    vm_ref = base + "/zones/us-central1-a/instances/vm"
    service_ref = base + "/regions/us-central1/backendServices/nlb"
    fr = {"name": "nlb", "loadBalancingScheme": "EXTERNAL", "IPAddress": "34.2.2.2",
          "IPProtocol": "TCP", "portRange": "443-443", "backendService": service_ref}
    vm = {"name": "vm", "selfLink": vm_ref, "status": "RUNNING",
          "networkInterfaces": [{"network": NET, "networkIP": "10.0.0.2"}]}
    health = {"name": service_ref, "backendService": service_ref, "collection_status": "collected",
              "groups": [{"collection_status": "collected", "healthStatus": [
                  {"instance": vm_ref, "healthState": "HEALTHY"}]}]}
    def snap(rules):
        return gcp(gcoll("forwarding_rule", [fr]), gcoll("backend_service", [{"name": "nlb", "selfLink": service_ref,
                                                                             "BackendHealth": {"collection_status": "collected", "groups": health["groups"]}}]),
                   gcoll("instance", [vm]),
                   gcoll("firewall", rules), gcoll("firewall_policy", [], status="empty"))
    assert one(snap([fw("allow-web", 1000, "allowed", ["443"])]), "forwarding_rule")["status"] == "FAIL"
    assert one(snap([]), "forwarding_rule")["status"] == "PASS"


def test_gcp_ha_and_classic_vpn_public_ike_and_esp_endpoints():
    gateway = {"name": "ha", "vpnInterfaces": [{"id": 0, "ipAddress": "34.2.2.2"},
                                                 {"id": 1, "ipAddress": "10.0.0.2", "interconnectAttachment": "vlan"}]}
    result = one(gcp(gcoll("vpn_gateway", [gateway])), "vpn_gateway")
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["udp/500", "udp/4500", "esp"]
    gateway["vpnInterfaces"][0]["interconnectAttachment"] = "vlan"
    assert not exposure(gcp(gcoll("vpn_gateway", [gateway])))
    classic = {"name": "classic-esp", "IPAddress": "34.2.2.3", "IPProtocol": "ESP",
               "target": "https://compute.googleapis.com/compute/v1/projects/p1/regions/us/targetVpnGateways/vpn"}
    result = one(gcp(gcoll("forwarding_rule", [classic])), "forwarding_rule")
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["esp"]


def test_gcp_gke_and_sql():
    gke = {"name": "c", "endpoint": "35.1.1.1", "masterAuthorizedNetworksConfig": {"enabled": True, "cidrBlocks": [{"cidrBlock": "203.0.113.0/24"}]}}
    assert one(gcp(gcoll("gke_cluster", [gke], service="container")), "gke_cluster")["status"] == "PASS"
    gke["masterAuthorizedNetworksConfig"]["cidrBlocks"] = [{"cidrBlock": "8.8.8.0/24"}]
    assert one(gcp(gcoll("gke_cluster", [gke], service="container")), "gke_cluster")["status"] == "FAIL"
    assert one(gcp(gcoll("gke_cluster", [{"name": "c", "endpoint": "35.1.1.1"}], service="container")), "gke_cluster")["status"] == "FAIL"
    sql = {"name": "db", "databaseVersion": "MYSQL_8_0", "settings": {"ipConfiguration": {"ipv4Enabled": True, "authorizedNetworks": [{"value": "0.0.0.0/0"}]}}}
    result = one(gcp(gcoll("sql_instance", [sql], service="sqladmin")), "sql_instance")
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/3306-3307"]
    sql["settings"]["ipConfiguration"]["authorizedNetworks"] = []
    proxy_only = one(gcp(gcoll("sql_instance", [sql], service="sqladmin")), "sql_instance")
    assert proxy_only["status"] == "FAIL" and proxy_only["evidence"]["authenticated_endpoint"] is True
    assert proxy_only["evidence"]["exposed_ports"] == ["tcp/3307"]


def test_gcp_alloydb_public_ip_including_proxy_only_access():
    instance = {"name": "projects/p1/locations/us/clusters/c/instances/i", "state": "READY",
                "networkConfig": {"enablePublicIp": True, "authorizedExternalNetworks": []}}
    result = one(gcp(gcoll("alloydb_instance", [instance], service="alloydb")), "alloydb_instance")
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/5433"]
    assert result["evidence"]["authenticated_endpoint"] is True
    instance["networkConfig"]["enablePublicIp"] = False
    assert not exposure(gcp(gcoll("alloydb_instance", [instance], service="alloydb")))


def test_gcp_public_resource_iam_is_reported_with_conditions_and_read_status():
    secret = {"name": "projects/p1/secrets/s", "iamPolicy": {"bindings": [
        {"role": "roles/secretmanager.secretAccessor", "members": ["allUsers"]}]},
        "_coverage": {"iamPolicy": {"status": "collected"}}}
    rows = analyze(gcp(gcoll("secret", [secret], service="secretmanager")))["findings"]
    public = [row for row in rows if row["check_id"] == "analysis.gcp_public_iam"]
    assert len(public) == 1 and public[0]["status"] == "FAIL"
    conditional = copy.deepcopy(secret)
    conditional["iamPolicy"]["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}
    rows = analyze(gcp(gcoll("secret", [conditional], service="secretmanager")))["findings"]
    assert next(row for row in rows if row["check_id"] == "analysis.gcp_public_iam")["status"] == "UNKNOWN"
    denied = copy.deepcopy(secret)
    denied["_coverage"]["iamPolicy"]["status"] = "denied"
    rows = analyze(gcp(gcoll("secret", [denied], service="secretmanager")))["findings"]
    assert not any(row["check_id"] == "analysis.gcp_public_iam" for row in rows)
    project_policy = {"name": "projects/p1", "bindings": [{"role": "roles/viewer", "members": ["allAuthenticatedUsers"]}]}
    rows = analyze(gcp(gcoll("iam_policy", [project_policy], service="cloudasset")))["findings"]
    assert any(row["check_id"] == "analysis.gcp_public_iam" and row["status"] == "FAIL" for row in rows)


def test_gcp_bigquery_legacy_acl_enters_principal_exposure_review():
    dataset = {"id": "p1:dataset", "datasetReference": {"projectId": "p1", "datasetId": "dataset"},
               "access": [{"iamMember": "allUsers", "role": "READER"}]}
    rows = analyze(gcp(gcoll("bigquery_dataset", [dataset], service="bigquery")))["findings"]
    assert any(row["check_id"] == "analysis.principal_exposure" and row["status"] == "FAIL"
               and row["evidence"]["principals"][0]["principal"] == "allUsers" for row in rows)


def test_gcp_collected_bucket_acl_public_read_and_pap():
    bucket = {"name": "sample-bucket", "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": False}},
              "iamPolicy": {"bindings": []},
              "objectAccessControls": {"status": "collected", "all_pages": True, "all_objects": True, "all_versions": True,
                                       "items": [{"entity": "allUsers", "role": "READER", "objectRef": "opaque-ref"}]}}
    assert one(gcp(gcoll("bucket", [bucket], service="storage")), "bucket")["status"] == "FAIL"
    protected = copy.deepcopy(bucket)
    protected["iamConfiguration"]["publicAccessPrevention"] = "enforced"
    assert one(gcp(gcoll("bucket", [protected], service="storage")), "bucket")["status"] == "PASS"
    inherited = copy.deepcopy(bucket)
    inherited["iamConfiguration"]["publicAccessPrevention"] = "inherited"
    assert one(gcp(gcoll("bucket", [inherited], service="storage")), "bucket")["status"] == "UNKNOWN"
    incomplete = copy.deepcopy(bucket)
    incomplete["objectAccessControls"]["all_objects"] = False
    assert not exposure(gcp(gcoll("bucket", [incomplete], service="storage")))
    rows = analyze(gcp(gcoll("bucket", [bucket], service="storage")))["findings"]
    assert any(row["check_id"] == "analysis.principal_exposure" and row["status"] == "FAIL"
               for row in rows)
    rows = analyze(gcp(gcoll("bucket", [incomplete], service="storage")))["findings"]
    assert not any(row["check_id"] == "analysis.principal_exposure" for row in rows)


@pytest.mark.parametrize("kind,record,expected", [
    ("cloud_ftp_server", {"name": "projects/p1/locations/us/servers/s", "externalConfig":
                          {"ipAddress": "34.2.3.4", "allowedCidrBlocks": ["0.0.0.0/0"]}}, "FAIL"),
    ("cloud_ftp_server", {"name": "projects/p1/locations/us/servers/s", "externalConfig":
                          {"ipAddress": "34.2.3.4", "allowedCidrBlocks": ["192.0.2.0/24"]}}, "PASS"),
    ("looker_instance", {"name": "projects/p1/locations/us/instances/i", "publicIpEnabled": True,
                          "ingressPublicIp": "34.2.3.4", "ingressIpAllowlistConfig": {"enabled": False}}, "FAIL"),
    ("looker_instance", {"name": "projects/p1/locations/us/instances/i", "publicIpEnabled": True,
                          "ingressPublicIp": "34.2.3.4", "ingressIpAllowlistConfig":
                          {"enabled": True, "allowlistRules": [{"ipRange": "192.0.2.0/24"}]}}, "PASS"),
    ("blockchain_node", {"name": "projects/p1/locations/us/blockchainNodes/n", "privateServiceConnectEnabled": False,
                         "connectionInfo": {"endpointInfo": {"jsonRpcApiEndpoint": "https://node.example.com"}}}, "FAIL"),
    ("data_fusion_instance", {"name": "projects/p1/locations/us/instances/i", "privateInstance": False,
                              "apiEndpoint": "https://df.example.com/api"}, "FAIL"),
    ("vertex_index_endpoint", {"name": "projects/p1/locations/us/indexEndpoints/i", "publicEndpointEnabled": True,
                               "publicEndpointDomainName": "index.example.com"}, "FAIL"),
    ("vertex_feature_online_store", {"name": "projects/p1/locations/us/featureOnlineStores/f",
                                     "dedicatedServingEndpoint": {"publicEndpointDomainName": "feature.example.com"}}, "FAIL"),
    ("app_engine_application", {"name": "apps/p1", "defaultHostname": "p1.uc.r.appspot.com", "servingStatus": "SERVING"}, "FAIL"),
    ("app_engine_application", {"name": "apps/p1", "defaultHostname": "p1.uc.r.appspot.com", "servingStatus": "USER_DISABLED"}, "PASS"),
    ("api_gateway", {"name": "projects/p1/locations/us/gateways/g", "defaultHostname": "g.gateway.dev",
                     "state": "ACTIVE", "apiConfig": "projects/p1/locations/global/apis/a/configs/c"}, "FAIL"),
    ("firebase_apphosting_endpoint", {"name": "projects/p1/locations/us/backends/b",
                                       "uri": "https://b.hosted.app"}, "FAIL"),
])
def test_gcp_managed_service_public_endpoints(kind, record, expected):
    assert one(gcp(gcoll(kind, [record], service="managed")), kind)["status"] == expected


def test_gcp_workstation_public_gateway_and_private_cluster():
    cluster_name = "projects/p1/locations/us/workstationClusters/c"
    workstation = {"name": cluster_name + "/workstationConfigs/config/workstations/w",
                   "state": "STATE_RUNNING", "host": "80-w.c.cloudworkstations.dev"}
    cluster = {"name": cluster_name, "privateClusterConfig": {"enablePrivateEndpoint": False}}
    def scan(config):
        return gcp(gcoll("workstation", [workstation], service="workstations"),
                   gcoll("workstation_cluster", [config], service="workstations"))
    assert one(scan(cluster), "workstation")["status"] == "FAIL"
    cluster["privateClusterConfig"]["enablePrivateEndpoint"] = True
    assert one(scan(cluster), "workstation")["status"] == "PASS"
    assert one(gcp(gcoll("workstation", [workstation], service="workstations")), "workstation")["status"] == "UNKNOWN"


def test_gcp_tpu_external_address_keeps_unresolved_firewall_identity():
    node = {"name": "projects/p1/locations/us-central1-a/nodes/t",
            "networkConfig": {"enableExternalIps": True, "network": NET},
            "networkEndpoints": [{"ipAddress": "10.0.0.3", "accessConfig": {"externalIp": "34.3.3.3"}}]}
    result = one(gcp(gcoll("tpu_node", [node], service="tpu"),
                     gcoll("firewall", [], status="empty"), gcoll("firewall_policy", [], status="empty")), "tpu_node")
    assert result["status"] == "UNKNOWN"
    assert result["evidence"]["public_addresses"] == ["34.3.3.3"]
    assert result["evidence"]["unresolved"]


def test_gcp_vmware_external_ip_and_ordered_access_rules():
    cloud = "projects/p1/locations/us-central1-a/privateClouds/c"
    address = cloud + "/externalAddresses/a"
    policy = "projects/p1/locations/us-central1/networkPolicies/p"
    network = "projects/123/locations/global/vmwareEngineNetworks/n"
    base = [gcoll("vmware_external_address", [{"name": address, "state": "ACTIVE", "externalIp": "34.4.4.4"}], service="vmwareengine"),
            gcoll("vmware_private_cloud", [{"name": cloud, "networkConfig": {"vmwareEngineNetworkCanonical": network}}], service="vmwareengine"),
            gcoll("vmware_network_policy", [{"name": policy, "vmwareEngineNetworkCanonical": network,
                                               "externalIp": {"enabled": True, "state": "ACTIVE"}}], service="vmwareengine")]
    allow = {"name": policy + "/externalAccessRules/allow", "state": "ACTIVE", "priority": 200,
             "action": "ALLOW", "ipProtocol": "tcp", "sourceIpRanges": [{"ipAddressRange": "0.0.0.0/0"}],
             "destinationIpRanges": [{"externalAddress": address}], "destinationPorts": ["443"]}
    rule_collection = gcoll("vmware_external_access_rule", [allow], service="vmwareengine")
    assert one(gcp(*base, rule_collection), "vmware_external_address")["status"] == "FAIL"
    allow["sourceIpRanges"] = [{"ipAddressRange": "8.8.8.0/24"}]
    allow["destinationIpRanges"] = [{"ipAddressRange": "34.4.4.4/32"}]
    assert one(gcp(*base, rule_collection), "vmware_external_address")["status"] == "FAIL"
    deny = {**allow, "name": policy + "/externalAccessRules/deny", "priority": 100, "action": "DENY"}
    result = one(gcp(*base, gcoll("vmware_external_access_rule", [allow, deny], service="vmwareengine")),
                 "vmware_external_address")
    assert result["status"] == "PASS"
    deny["priority"] = 200
    assert one(gcp(*base, gcoll("vmware_external_access_rule", [allow, deny], service="vmwareengine")),
               "vmware_external_address")["status"] == "UNKNOWN"
    assert one(gcp(*base), "vmware_external_address")["status"] == "UNKNOWN"


def test_gcp_media_cdn_public_addresses_and_edge_armor():
    edge = {"name": "projects/p1/locations/global/edgeCacheServices/media",
            "ipv4Addresses": ["34.8.8.8"], "requireTls": True,
            "routing": {"hostRules": [{"hosts": ["media.example.com"]}]}}
    result = one(gcp(gcoll("media_cdn_service", [edge], service="networkservices")), "media_cdn_service")
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/443"]
    edge["edgeSecurityPolicy"] = "https://x/securityPolicies/armor"
    assert one(gcp(gcoll("media_cdn_service", [edge], service="networkservices")), "media_cdn_service")["status"] == "UNKNOWN"
    policy = {"name": "armor", "selfLink": edge["edgeSecurityPolicy"], "rules": [
        {"priority": 2147483647, "action": "deny(403)", "match": {"config": {"srcIpRanges": ["*"]}}}]}
    result = one(gcp(gcoll("media_cdn_service", [edge], service="networkservices"),
                     gcoll("security_policy", [policy])), "media_cdn_service")
    assert result["status"] == "PASS"




# ------------------------------------------------------------------ Azure

SUB = "/subscriptions/00000000-0000-0000-0000-000000000001"
RG = SUB + "/resourceGroups/rg/providers/Microsoft.Network"


def azure(*collections):
    return make_snapshot("azure", [SUB], list(collections), created_at="2026-10-10T00:00:00+00:00")


def acoll(kind, items, status=None, scope=SUB):
    return coll(kind, items, scope=scope, status=status, service="network")


def nsg(name, rules):
    return {"id": f"{RG}/networkSecurityGroups/{name}", "name": name, "properties": {"securityRules": [
        {"name": n, "properties": {"priority": p, "direction": "Inbound", "access": a, "protocol": "Tcp", "sourceAddressPrefix": "*",
                                   "destinationAddressPrefix": "*", "destinationPortRange": port}} for n, p, a, port in rules]}}


def azure_vm(subnet_rules, nic_rules, sku="Standard"):
    vnet = {"id": f"{RG}/virtualNetworks/v", "name": "v", "properties": {"subnets": [
        {"id": f"{RG}/virtualNetworks/v/subnets/s", "properties": {"networkSecurityGroup": {"id": f"{RG}/networkSecurityGroups/subnet-nsg"}} if subnet_rules is not None else {}}]}}
    nic = {"id": f"{RG}/networkInterfaces/nic", "name": "nic", "properties": {
        "virtualMachine": {"id": SUB + "/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"},
        "networkSecurityGroup": {"id": f"{RG}/networkSecurityGroups/nic-nsg"} if nic_rules is not None else None,
        "ipConfigurations": [{"id": f"{RG}/networkInterfaces/nic/ipConfigurations/ip", "name": "ip", "properties": {
            "privateIPAddress": "10.0.0.4", "subnet": {"id": f"{RG}/virtualNetworks/v/subnets/s"}, "publicIPAddress": {"id": f"{RG}/publicIPAddresses/pip"}}}]}}
    nsgs = ([nsg("subnet-nsg", subnet_rules)] if subnet_rules is not None else []) + ([nsg("nic-nsg", nic_rules)] if nic_rules is not None else [])
    return [acoll("vnet", [vnet]), acoll("nic", [nic]), acoll("nsg", nsgs),
            acoll("public_ip", [{"id": f"{RG}/publicIPAddresses/pip", "sku": {"name": sku}, "properties": {"ipAddress": "20.1.1.1"}}]),
            coll("vm", [{"id": SUB + "/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm", "name": "vm"}], scope=SUB, service="compute")]


def test_azure_nsg_subnet_and_nic_must_both_allow():
    result = one(azure(*azure_vm([("ssh", 100, "Allow", "22"), ("web", 110, "Allow", "443")], [("ssh", 100, "Allow", "22")])), "vm")
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/22"]
    blocked = one(azure(*azure_vm([("deny", 90, "Deny", "22"), ("ssh", 100, "Allow", "22")], [("ssh", 100, "Allow", "22")])), "vm")
    assert blocked["status"] == "PASS"
    assert one(azure(*azure_vm(None, None, sku="Standard")), "vm")["status"] == "PASS"
    open_basic = one(azure(*azure_vm(None, None, sku="Basic")), "vm")
    assert open_basic["status"] == "FAIL" and open_basic["severity"] == "critical"


def test_azure_app_service_and_aks():
    app = {"id": SUB + "/resourceGroups/rg/providers/Microsoft.Web/sites/app", "name": "app", "properties": {"defaultHostName": "app.azurewebsites.net", "httpsOnly": True}}
    config = {"id": app["id"] + "/config/web", "parent_id": app["id"], "properties": {"ipSecurityRestrictions": [{"ipAddress": "Any", "action": "Allow", "priority": 2147483647, "name": "Allow all"}]}}
    snapshot = azure(coll("app_service", [app], scope=SUB, service="web"), coll("app_service_config", [config], scope=app["id"], service="web"))
    assert one(snapshot, "app_service")["status"] == "FAIL"
    restricted = copy.deepcopy(config)
    restricted["properties"] = {"ipSecurityRestrictions": [{"ipAddress": "203.0.113.0/24", "action": "Allow", "priority": 100}], "ipSecurityRestrictionsDefaultAction": "Deny"}
    snapshot = azure(coll("app_service", [app], scope=SUB, service="web"), coll("app_service_config", [restricted], scope=app["id"], service="web"))
    assert one(snapshot, "app_service")["status"] == "PASS"
    assert one(azure(coll("app_service", [app], scope=SUB, service="web")), "app_service")["status"] == "UNKNOWN"
    aks = {"id": SUB + "/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/k", "properties": {"apiServerAccessProfile": {"authorizedIPRanges": ["203.0.113.0/24"]}}}
    assert one(azure(coll("aks_cluster", [aks], scope=SUB, service="aks")), "aks_cluster")["status"] == "PASS"
    aks["properties"]["apiServerAccessProfile"] = {}
    assert one(azure(coll("aks_cluster", [aks], scope=SUB, service="aks")), "aks_cluster")["status"] == "FAIL"


# -------------------------------------------------------------------- K8s

def k8s(*collections):
    return make_snapshot("k8s", ["cluster"], list(collections), created_at="2026-10-10T00:00:00+00:00")


def svc(spec, annotations=None, status=None):
    return coll("service", [{"metadata": {"name": "web", "namespace": "apps", "annotations": annotations or {}}, "spec": spec,
                             "status": status or {"loadBalancer": {"ingress": [{"hostname": "a.elb.amazonaws.com"}]}}}], scope="cluster", service="core")


@pytest.mark.parametrize("spec,annotations,expected", [
    ({"type": "LoadBalancer", "ports": [{"port": 443, "protocol": "TCP"}]}, None, "FAIL"),
    ({"type": "LoadBalancer", "ports": [{"port": 443}], "loadBalancerSourceRanges": ["203.0.113.0/24"]}, None, "PASS"),
    ({"type": "LoadBalancer", "ports": [{"port": 443}], "loadBalancerSourceRanges": ["8.8.8.8/32"]}, None, "FAIL"),
    ({"type": "LoadBalancer", "ports": [{"port": 443}], "loadBalancerSourceRanges": ["0.0.0.0/1"]}, None, "FAIL"),
    ({"type": "LoadBalancer", "ports": [{"port": 443}]}, {"service.beta.kubernetes.io/aws-load-balancer-scheme": "internal"}, "PASS"),
    ({"type": "LoadBalancer", "ports": [{"port": 443}]}, {"service.beta.kubernetes.io/load-balancer-source-ranges": "10.0.0.0/8"}, "PASS"),
])
def test_k8s_load_balancer_source_ranges(spec, annotations, expected):
    assert one(k8s(svc(spec, annotations)), "service")["status"] == expected


def test_k8s_nodeport_depends_on_node_addresses():
    spec = {"type": "NodePort", "ports": [{"port": 80, "nodePort": 30080}]}
    assert one(k8s(svc(spec), coll("node", [], status="denied", scope="cluster")), "service")["status"] == "UNKNOWN"
    private = coll("node", [{"metadata": {"name": "n"}, "status": {"addresses": [{"type": "InternalIP", "address": "10.0.0.5"}]}}], scope="cluster")
    assert one(k8s(svc(spec), private), "service")["status"] == "PASS"


def test_k8s_external_ip_on_clusterip_service_is_assessed():
    spec = {"type": "ClusterIP", "externalIPs": ["34.9.9.9"], "ports": [{"port": 8080}]}
    result = one(k8s(svc(spec, status={})), "service")
    assert result["status"] == "UNKNOWN"
    assert result["evidence"]["public_addresses"] == ["34.9.9.9"]
    assert result["evidence"]["exposed_ports"] == ["tcp/8080"]
    assert result["evidence"]["path"][-1] == {"layer": "external_ip", "decision": "unknown",
                                                "declared_public_addresses": ["34.9.9.9"]}
    assert {gap["layer"] for gap in result["evidence"]["unresolved"]} == {"inventory", "firewall"}
    assert result["evidence_summary"].splitlines() == [
        "The Service declares externalIPs 34.9.9.9.",
        "It declares tcp/8080 for that address.",
        "Address ownership and routing to a cluster node are not observed.",
        "Cloud firewall admission and live reachability remain unknown."]


def test_k8s_external_ip_survives_internal_load_balancer_block():
    spec = {"type": "LoadBalancer", "externalIPs": ["34.9.9.9"], "ports": [{"port": 8080}]}
    annotations = {"service.beta.kubernetes.io/aws-load-balancer-scheme": "internal"}
    result = one(k8s(svc(spec, annotations)), "service")
    assert result["status"] == "UNKNOWN"
    assert result["evidence"]["public_addresses"] == ["34.9.9.9"]


def test_k8s_observed_public_load_balancer_path_is_not_downgraded_by_external_ip():
    spec = {"type": "LoadBalancer", "externalIPs": ["34.9.9.9"], "ports": [{"port": 443}]}
    result = one(k8s(svc(spec)), "service")
    assert result["status"] == "FAIL"
    assert result["evidence"]["public_addresses"] == ["a.elb.amazonaws.com"]
    assert result["evidence"]["path"][-1]["decision"] == "unknown"


def test_k8s_nodeport_does_not_use_foreign_cluster_node():
    spec = {"type": "NodePort", "ports": [{"port": 80, "nodePort": 30080}]}
    service = svc(spec)["items"][0]
    service["provenance"] = {"cluster_id": "a"}
    node = {"metadata": {"name": "worker"}, "provenance": {"cluster_id": "b"},
            "status": {"addresses": [{"type": "ExternalIP", "address": "34.9.9.9"}]}}
    result = one(k8s(coll("service", [service], scope="cluster"), coll("node", [node], scope="cluster")), "service")
    assert result["status"] == "PASS"
    assert result["evidence"]["public_addresses"] == []


def test_k8s_external_dns_node_leaves_nodeport_and_kubelet_unresolved():
    spec = {"type": "NodePort", "ports": [{"port": 80, "nodePort": 30080}]}
    node = {"metadata": {"name": "worker"}, "status": {"addresses": [
        {"type": "ExternalDNS", "address": "worker.example.com"}],
        "daemonEndpoints": {"kubeletEndpoint": {"Port": 10250}}}}
    snapshot = k8s(svc(spec), coll("node", [node], scope="cluster"))
    assert one(snapshot, "service")["status"] == "UNKNOWN"
    assert one(snapshot, "node")["status"] == "UNKNOWN"


def test_k8s_internal_load_balancer_health_port_on_public_node_is_candidate():
    spec = {"type": "LoadBalancer", "healthCheckNodePort": 32000, "ports": [{"port": 443}]}
    annotations = {"service.beta.kubernetes.io/aws-load-balancer-scheme": "internal"}
    node = {"metadata": {"name": "worker"}, "status": {"addresses": [{"type": "ExternalIP", "address": "34.9.9.9"}]}}
    result = one(k8s(svc(spec, annotations), coll("node", [node], scope="cluster")), "service")
    assert result["status"] == "UNKNOWN"
    assert result["evidence"]["exposed_ports"] == ["tcp/32000"]


def test_k8s_pending_load_balancer_address_is_unknown():
    service = svc({"type": "LoadBalancer", "ports": [{"port": 443}]})["items"][0]
    service["status"] = {"loadBalancer": {"ingress": []}}
    result = one(k8s(coll("service", [service], scope="cluster")), "service")
    assert result["status"] == "UNKNOWN"


def test_k8s_ingress_allowlist():
    ingress = {"metadata": {"name": "i", "namespace": "apps", "annotations": {}}, "spec": {"rules": [{"host": "x.example.com"}], "tls": [{}]},
               "status": {"loadBalancer": {"ingress": [{"ip": "34.9.9.9"}]}}}
    result = one(k8s(coll("ingress", [ingress], scope="cluster")), "ingress")
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/80", "tcp/443"]
    ingress["metadata"]["annotations"] = {"nginx.ingress.kubernetes.io/whitelist-source-range": "10.0.0.0/8"}
    assert one(k8s(coll("ingress", [ingress], scope="cluster")), "ingress")["status"] == "PASS"
    ingress["metadata"]["annotations"] = {"nginx.ingress.kubernetes.io/whitelist-source-range": "8.8.8.8/32"}
    assert one(k8s(coll("ingress", [ingress], scope="cluster")), "ingress")["status"] == "FAIL"


def test_k8s_host_port_public_node_is_reported_with_firewall_gap():
    pod = {"metadata": {"name": "web", "namespace": "apps"}, "spec": {"nodeName": "worker",
           "containers": [{"name": "web", "ports": [{"containerPort": 8080, "hostPort": 8080}]}]},
           "status": {"phase": "Running"}}
    node = {"metadata": {"name": "worker"}, "status": {"addresses": [{"type": "ExternalIP", "address": "34.9.9.9"}]}}
    result = one(k8s(coll("pod", [pod], scope="cluster"), coll("node", [node], scope="cluster")), "pod")
    assert result["status"] == "UNKNOWN"
    assert result["evidence"]["exposed_ports"] == ["tcp/8080"]
    assert result["evidence"]["public_addresses"] == ["34.9.9.9"]
    assert any(g["layer"] == "security_group" for g in result["evidence"]["unresolved"])


def test_k8s_host_network_private_node_and_completed_pod():
    pod = {"metadata": {"name": "web", "namespace": "apps"}, "spec": {"nodeName": "worker", "hostNetwork": True,
           "containers": [{"name": "web", "ports": [{"containerPort": 9090}]}]}, "status": {"phase": "Running"}}
    node = {"metadata": {"name": "worker"}, "status": {"addresses": [{"type": "InternalIP", "address": "10.0.0.2"}]}}
    snapshot = k8s(coll("pod", [pod], scope="cluster"), coll("node", [node], scope="cluster"))
    assert one(snapshot, "pod")["status"] == "PASS"
    pod["status"]["phase"] = "Succeeded"
    assert exposure(k8s(coll("pod", [pod], scope="cluster"), coll("node", [node], scope="cluster"))) == []


def test_k8s_host_port_does_not_join_foreign_cluster_node():
    pod = {"metadata": {"name": "web", "namespace": "apps"}, "provenance": {"cluster_id": "a"},
           "spec": {"nodeName": "worker", "containers": [{"name": "web", "ports": [{"hostPort": 8080}]}]}}
    node = {"metadata": {"name": "worker"}, "provenance": {"cluster_id": "b"},
            "status": {"addresses": [{"type": "ExternalIP", "address": "34.9.9.9"}]}}
    result = one(k8s(coll("pod", [pod], scope="cluster"), coll("node", [node], scope="cluster")), "pod")
    assert result["status"] == "UNKNOWN"
    assert result["evidence"]["public_addresses"] == []


def test_k8s_public_host_ip_is_not_blocked_by_missing_node_external_ip():
    pod = {"metadata": {"name": "web", "namespace": "apps"},
           "spec": {"nodeName": "worker", "containers": [{"name": "web", "ports": [
               {"containerPort": 8443, "hostPort": 8443, "hostIP": "34.9.9.9"}]}]},
           "status": {"phase": "Running"}}
    node = {"metadata": {"name": "worker"}, "status": {"addresses": [{"type": "InternalIP", "address": "10.0.0.5"}]}}
    result = one(k8s(coll("pod", [pod], scope="cluster"), coll("node", [node], scope="cluster")), "pod")
    assert result["status"] == "UNKNOWN"
    assert result["evidence"]["public_addresses"] == ["34.9.9.9"]


def test_k8s_gateway_public_listener_remains_unresolved():
    gateway = {"metadata": {"name": "edge", "namespace": "apps"},
               "spec": {"listeners": [{"name": "web", "port": 443, "protocol": "HTTPS"}]},
               "status": {"addresses": [{"type": "IPAddress", "value": "34.9.9.9"}]}}
    result = one(k8s(coll("gateway", [gateway], scope="cluster")), "gateway")
    assert result["status"] == "UNKNOWN"
    assert result["evidence"]["public_addresses"] == ["34.9.9.9"]
    assert result["evidence"]["exposed_ports"] == ["tcp/443"]


def test_k8s_public_pod_ip_and_kubelet_endpoint_are_candidates():
    pod = {"metadata": {"name": "direct", "namespace": "apps"}, "spec": {
        "containers": [{"name": "web", "ports": [{"containerPort": 8080}]}]},
        "status": {"phase": "Running", "podIPs": [{"ip": "34.9.9.9"}]}}
    node = {"metadata": {"name": "worker"}, "status": {"addresses": [{"type": "ExternalIP", "address": "8.8.8.8"}],
            "daemonEndpoints": {"kubeletEndpoint": {"Port": 10250}}}}
    snapshot = k8s(coll("pod", [pod], scope="cluster"), coll("node", [node], scope="cluster"))
    pod_result, node_result = one(snapshot, "pod"), one(snapshot, "node")
    assert pod_result["status"] == "UNKNOWN" and pod_result["evidence"]["exposed_ports"] == ["tcp/8080"]
    assert node_result["status"] == "UNKNOWN" and node_result["evidence"]["exposed_ports"] == ["tcp/10250"]


def test_k8s_gateway_route_joins_public_parent_and_controller_routes_are_reported():
    gateway = {"metadata": {"name": "edge", "namespace": "apps"},
               "spec": {"listeners": [{"name": "web", "port": 443, "protocol": "HTTPS"}]},
               "status": {"addresses": [{"type": "IPAddress", "value": "34.9.9.9"}]}}
    route = {"metadata": {"name": "web", "namespace": "apps"},
             "spec": {"parentRefs": [{"name": "edge", "sectionName": "web"}], "rules": [{"backendRefs": [{"name": "web"}]}]}}
    snapshot = k8s(coll("gateway", [gateway], scope="cluster"), coll("httproute", [route], scope="cluster"))
    result = one(snapshot, "httproute")
    assert result["status"] == "UNKNOWN"
    assert result["evidence"]["public_addresses"] == ["34.9.9.9"]
    assert result["evidence"]["exposed_ports"] == ["tcp/443"]
    openshift = {"metadata": {"name": "web", "namespace": "apps"},
                 "spec": {"host": "web.example.com", "to": {"kind": "Service", "name": "web"}}}
    assert one(k8s(coll("openshift_route", [openshift], scope="cluster")), "openshift_route")["status"] == "UNKNOWN"


def test_k8s_mesh_only_virtual_service_is_not_public_candidate():
    mesh = {"metadata": {"name": "mesh", "namespace": "apps"},
            "spec": {"gateways": ["mesh"], "hosts": ["internal.local"], "http": [{"route": []}]}}
    assert exposure(k8s(coll("istio_virtual_service", [mesh], scope="cluster"))) == []


def test_k8s_externalname_and_public_backend_destinations_are_reported():
    alias = {"metadata": {"name": "vendor", "namespace": "apps"},
             "spec": {"type": "ExternalName", "externalName": "api.vendor.example"}}
    slice_data = {"metadata": {"name": "vendor-1", "namespace": "apps"},
                  "endpoints": [{"addresses": ["8.8.8.8"]}], "ports": [{"port": 443, "protocol": "TCP"}]}
    entry = {"metadata": {"name": "vendor", "namespace": "apps"},
             "spec": {"location": "MESH_EXTERNAL", "hosts": ["api.vendor.example"],
                      "endpoints": [{"address": "8.8.4.4"}], "ports": [{"number": 443, "protocol": "HTTPS"}]}}
    snapshot = k8s(coll("service", [alias], scope="cluster"), coll("endpointslice", [slice_data], scope="cluster"),
                   coll("istio_service_entry", [entry], scope="cluster"))
    for kind in ("service", "endpointslice", "istio_service_entry"):
        result = one(snapshot, kind)
        assert result["status"] == "UNKNOWN"
    assert one(snapshot, "endpointslice")["evidence"]["public_addresses"] == ["8.8.8.8"]
    assert one(snapshot, "istio_service_entry")["evidence"]["exposed_ports"] == ["tcp/443"]
    dns_entry = {"metadata": {"name": "vendor-dns", "namespace": "apps"},
                 "spec": {"location": "MESH_EXTERNAL", "hosts": ["api.vendor.example"],
                          "ports": [{"number": 443, "protocol": "HTTPS"}]}}
    assert one(k8s(coll("istio_service_entry", [dns_entry], scope="cluster")), "istio_service_entry")["status"] == "UNKNOWN"


def test_k8s_webhook_source_and_public_storage_receivers_are_reported():
    webhook = {"metadata": {"name": "external"}, "webhooks": [{
        "name": "audit.example", "clientConfig": {"url": "https://hooks.example.com/check"}}]}
    sync = {"metadata": {"name": "config", "namespace": "apps"},
            "spec": {"sourceType": "git", "git": {"repo": "https://git.example.com/org/config"}}}
    volume = {"metadata": {"name": "external"}, "spec": {"nfs": {"server": "8.8.8.8", "path": "/data"}}}
    snapshot = k8s(coll("admission_configuration", [webhook], scope="cluster"),
                   coll("configsync_rootsync", [sync], scope="cluster"),
                   coll("persistentvolume", [volume], scope="cluster"))
    for kind in ("admission_configuration", "configsync_rootsync", "persistentvolume"):
        result = one(snapshot, kind)
        assert result["status"] == "UNKNOWN"
    assert one(snapshot, "admission_configuration")["evidence"]["path"][0]["hosts"] == ["hooks.example.com"]


# ------------------------------------------------------------ end to end

def test_end_to_end_engine_report_on_demo_snapshot():
    snapshot = aws(*aws_network(), instance(), coll("lambda_function", [lambda_function()], service="lambda"),
                   coll("bucket", [bucket()], service="s3"), coll("s3_account_public_access_block", [], status="empty", service="s3control"))
    report = evaluate_snapshot(snapshot, categories=["exposure", "network"])
    found = {(f["resource_id"], f["status"]) for f in report["findings"] if f["check_id"] == CHECK}
    statuses = sorted(status for _, status in found)
    assert statuses.count("FAIL") == 3, found
    s3 = [f for f in report["findings"] if f["check_id"] == "aws.s3.public_access_block"]
    assert s3 and s3[0]["status"] == "FAIL"
    graph = report["graphs"]["network"]
    assert any(e["type"] == "internet_exposure" for e in graph["edges"])


def test_stopped_instance_keeps_fail_with_lower_severity():
    stopped = instance()
    stopped["items"][0]["State"] = {"Name": "stopped"}
    result = one(aws(*aws_network(), stopped), "instance")
    assert result["status"] == "FAIL" and result["severity"] == "medium" and any("stopped" in n for n in result["evidence"]["notes"])
    assert "stopped or deallocated" in result["evidence"]["observed"]


def test_public_https_observation_and_action_are_specific_and_brief():
    endpoint = "https://9gi0nszlth.execute-api.ca-central-1.amazonaws.com"
    api = {"ApiId": "9gi0nszlth", "ApiEndpoint": endpoint, "ProtocolType": "HTTP",
           "Routes": [{"RouteKey": "GET /", "AuthorizationType": "NONE"}]}
    result = one(aws(coll("http_api", [api], service="apigatewayv2")), "http_api")
    assert result["status"] == "FAIL" and result["severity"] == "medium"
    assert result["evidence"]["observed"] == f"Internet access to tcp/443 at {endpoint} is allowed."
    assert result["remediation"] == "Consider whether this endpoint needs internet access; restrict unnecessary source networks or ports."
    assert "no traffic was sent" in result["evidence"]["semantics"]


def test_missing_authorization_does_not_become_a_public_access_claim():
    api = {"ApiId": "a", "ApiEndpoint": "https://a.example.com", "ProtocolType": "HTTP"}
    result = one(aws(coll("http_api", [api], service="apigatewayv2")), "http_api")
    assert result["status"] == "UNKNOWN" and result["severity"] == "info"
    assert "could not be determined" in result["evidence"]["observed"]
    assert result["evidence"]["unresolved"] and result["evidence"]["collector_facts_needed"]
    assert "Collect the missing configuration" in result["remediation"]


@pytest.mark.parametrize("protocol,low,high,kind,severity", [
    ("tcp", 443, 443, "api", "medium"),
    ("udp", 443, 443, "public_ip", "high"),
    ("tcp", 22, 22, "public_ip", "high"),
    ("tcp", 3389, 3389, "public_ip", "high"),
    ("tcp", 443, 443, "control_plane", "high"),
    ("tcp", 5432, 5432, "database", "critical"),
    ("tcp", 0, 65535, "public_ip", "critical"),
    ("tcp", 0, 10000, "public_ip", "critical"),
    ("tcp", 8443, 8443, "public_ip", "high"),
])
def test_network_severity_distinguishes_web_admin_data_and_broad_ranges(protocol, low, high, kind, severity):
    from peaso.analysis.internet_exposure import Assessment
    assessment = Assessment({"type": "instance"}, kind)
    assessment.ports = pset(protocol, low, high)
    assert assessment.verdict() == "FAIL"
    assert assessment.severity() == severity


def test_data_shares_keep_risk_and_have_share_specific_actions():
    account_open = coll("s3_account_public_access_block", [], status="empty", service="s3control")
    result = one(aws(coll("bucket", [bucket()], service="s3"), account_open), "bucket")
    assert result["severity"] == "critical"
    assert result["evidence"]["observed"] == "Public access to the stored data is allowed."
    assert "policy or ACL" in result["remediation"] and "port" not in result["remediation"]
    snapshot = {"DBSnapshotArn": f"arn:aws:rds:us-east-1:{ACCOUNT}:snapshot:s", "SnapshotType": "manual",
                "Attributes": {"collection_status": "collected", "DBSnapshotAttributesResult": {
                    "DBSnapshotAttributes": [{"AttributeName": "restore", "AttributeValues": ["999988887777"]}]}}}
    result = one(aws(coll("rds_snapshot", [snapshot], service="rds")), "rds_snapshot")
    assert result["severity"] == "high"
    assert result["evidence"]["observed"] == "Snapshot restore access is granted to external accounts: 999988887777."
    assert result["remediation"] == "Restrict snapshot restore access to the accounts that need it."
