"""Internet-to-asset exposure (peaso.analysis.internet_exposure): PASS/FAIL/UNKNOWN per scenario."""
import copy
import ipaddress
import json

import pytest

from peaso.analysis import analyze
from peaso.analysis.internet_exposure import describe, intersect, pset, subtract, union
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

ACCOUNT = "111122223333"
SCOPE = f"{ACCOUNT}/us-east-1"
CHECK = "analysis.internet_exposure"


def coll(kind, items, scope=SCOPE, status=None, service="ec2"):
    if kind == "load_balancer":
        # Existing ELBv2 fixtures represent serving load balancers unless a test overrides State.
        items = [{**item, "State": item.get("State", {"Code": "active"}),
                  "IpAddressType": item.get("IpAddressType", "ipv4")} for item in items]
    return {"type": kind, "scope": scope, "service": service, "status": status or ("collected" if items else "empty"), "items": items}


def exposure(snapshot, kind=None):
    findings = [f for f in analyze(snapshot)["findings"] if f["check_id"] == CHECK and not f["resource_id"].startswith("inventory")]
    return findings


def one(snapshot, resource_type):
    report = analyze(snapshot)
    ids = {r["id"]: r["type"] for r in report["resources"]}
    found = [f for f in report["findings"] if f["check_id"] == CHECK and ids.get(f["resource_id"]) == resource_type
             and (resource_type not in ("lambda_function", "lambda_alias") or f["evidence"].get("exposure_kind") == "function_url")
             and (resource_type != "ecr_registry" or f["evidence"].get("exposure_kind") == "external_share")]
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


def with_ipv6_subnet(network, attribute="public"):
    subnet = next(c for c in network if c["type"] == "subnet")["items"][0]
    subnet["Ipv6CidrBlockAssociationSet"] = [{"Ipv6CidrBlock": "2600:1f18:abcd::/64",
        "Ipv6AddressAttribute": attribute, "Ipv6CidrBlockState": {"State": "associated"}}]
    return network


def instance(public=True, groups=("sg-1",)):
    interface = {"NetworkInterfaceId": "eni-1", "SubnetId": "subnet-1", "VpcId": "vpc-1", "Groups": [{"GroupId": g} for g in groups]}
    if public:
        interface["Association"] = {"PublicIp": "54.1.2.3"}
    return coll("instance", [{"InstanceId": "i-1", "State": {"Name": "running"}, "SubnetId": "subnet-1", "VpcId": "vpc-1", "NetworkInterfaces": [interface]}])


def aws(*collections, metadata=None):
    return make_snapshot("aws", [SCOPE], list(collections), created_at="2026-10-10T00:00:00+00:00", metadata=metadata)


def test_foreign_vpc_peering_requires_active_connection_and_local_route():
    from peaso.finding_observation import evidence_summary

    peer = {"VpcPeeringConnectionId": "pcx-1", "Status": {"Code": "active"},
            "RequesterVpcInfo": {"OwnerId": ACCOUNT, "VpcId": "vpc-local"},
            "AccepterVpcInfo": {"OwnerId": "444455556666", "VpcId": "vpc-peer"}}
    route = {"RouteTableId": "rtb-local", "VpcId": "vpc-local", "Routes": [
        {"VpcPeeringConnectionId": "pcx-1", "State": "active", "DestinationCidrBlock": "10.8.0.0/16"}]}
    connection = coll("vpc_peering", [peer])
    table = coll("route_table", [route])
    finding = one(aws(connection, table), "vpc_peering")
    assert finding["status"] == "FAIL"
    assert finding["evidence"]["exposure_kind"] == "external_network"
    assert finding["evidence"]["external_scope_ids"] == ["444455556666"]
    assert "Peer routing, endpoint filtering" in evidence_summary(finding)
    assert "VPC peering route" in finding["remediation"]

    blocked = one(aws(connection, coll("route_table", [{**route, "Routes": []}])), "vpc_peering")
    assert blocked["status"] == "PASS"
    assert "no active local route" in evidence_summary(blocked)
    unknown = one(aws(connection), "vpc_peering")
    assert unknown["status"] == "UNKNOWN"
    assert "route inventory is incomplete" in evidence_summary(unknown)
    malformed = one(aws(connection, coll("route_table", [{**route, "Routes": [None]}])), "vpc_peering")
    assert malformed["status"] == "UNKNOWN"
    assert not exposure(aws(coll("vpc_peering", [{**peer, "Status": {"Code": "pending-acceptance"}}]), table))
    assert not exposure(aws(coll("vpc_peering", [{**peer, "AccepterVpcInfo": {"OwnerId": ACCOUNT, "VpcId": "vpc-peer"}}]), table))


def test_foreign_transit_gateway_attachment_requires_joined_routes():
    from peaso.finding_observation import evidence_summary

    gateway = "tgw-1"
    foreign = {"TransitGatewayAttachmentId": "tgw-attach-foreign", "TransitGatewayId": gateway,
               "TransitGatewayOwnerId": ACCOUNT, "ResourceOwnerId": "444455556666",
               "ResourceType": "vpc", "ResourceId": "vpc-foreign", "State": "available"}
    local = {"TransitGatewayAttachmentId": "tgw-attach-local", "TransitGatewayId": gateway,
             "TransitGatewayOwnerId": ACCOUNT, "ResourceOwnerId": ACCOUNT,
             "ResourceType": "vpc", "ResourceId": "vpc-local", "State": "available",
             "Association": {"TransitGatewayRouteTableId": "tgw-rtb-1", "State": "associated"}}
    table = {"TransitGatewayRouteTableId": "tgw-rtb-1", "TransitGatewayId": gateway, "State": "available",
             "AssociationInventory": {"collection_status": "collected", "items": [
                 {"TransitGatewayAttachmentId": "tgw-attach-local", "State": "associated"}]},
             "RouteInventory": {"collection_status": "collected", "queries": ["type=static", "type=propagated"], "items": [
                 {"DestinationCidrBlock": "10.8.0.0/16", "Type": "static", "State": "active",
                  "TransitGatewayAttachments": [{"TransitGatewayAttachmentId": "tgw-attach-foreign",
                                                 "ResourceType": "vpc", "ResourceId": "vpc-foreign"}]}]}}
    vpc_table = {"RouteTableId": "rtb-local", "VpcId": "vpc-local", "Routes": [
        {"TransitGatewayId": gateway, "State": "active", "DestinationCidrBlock": "10.8.0.0/16"}]}

    def scan(foreign_row=foreign, gateway_table=table, local_table=vpc_table):
        return aws(coll("transit_gateway_attachment", [local, foreign_row]),
                   coll("transit_gateway_route_table", [gateway_table]), coll("route_table", [local_table]))

    finding = one(scan(), "transit_gateway_attachment")
    assert finding["status"] == "FAIL"
    assert finding["evidence"]["external_scope_ids"] == ["444455556666"]
    assert "Return routing and endpoint access remain unverified" in evidence_summary(finding)
    assert "foreign Transit Gateway attachment" in finding["remediation"]
    partial = {**table, "RouteInventory": {**table["RouteInventory"], "collection_status": "partial"}}
    assert one(scan(gateway_table=partial), "transit_gateway_attachment")["status"] == "UNKNOWN"
    assert one(scan(local_table={**vpc_table, "Routes": []}), "transit_gateway_attachment")["status"] == "UNKNOWN"
    unrelated = {**vpc_table, "Routes": [{**vpc_table["Routes"][0], "DestinationCidrBlock": "192.0.2.0/24"}]}
    assert one(scan(local_table=unrelated), "transit_gateway_attachment")["status"] == "UNKNOWN"
    blackhole = {**table, "RouteInventory": {**table["RouteInventory"], "items": [
        {**table["RouteInventory"]["items"][0], "State": "blackhole"}]}}
    assert one(scan(gateway_table=blackhole), "transit_gateway_attachment")["status"] == "UNKNOWN"
    assert not exposure(scan(foreign_row={**foreign, "State": "deleted"}))


def deployed_rest(api, *, stage="prod", authorization=None, api_key_required=None):
    methods = api.get("Methods") or []
    row = methods[0] if methods else {}
    stage_row = next((s for s in (api.get("Stages") or {}).get("items", []) if s.get("stageName") == stage), {})
    if not stage_row.get("deploymentId"):
        return coll("rest_api_method", [], service="apigateway")
    return coll("rest_api_method", [{"id": f"deployed/{api['id']}/{stage}/GET", "restApiId": api["id"],
        "stageArn": f"arn:aws:apigateway:us-east-1::/restapis/{api['id']}/stages/{stage}",
        "deploymentId": stage_row["deploymentId"], "resourcePath": "/", "httpMethod": row.get("httpMethod", "GET"),
        "authorizationType": row.get("authorizationType") if authorization is None else authorization,
        "apiKeyRequired": row.get("apiKeyRequired") if api_key_required is None else api_key_required,
        "_provenance": {"stage_deployment_join_verified": True}}], service="apigateway")


def test_aws_site_to_site_vpn_public_ipsec_frontend():
    connection = {"VpnConnectionId": "vpn-1", "State": "available",
                  "Options": {"OutsideIpAddressType": "PublicIpv4",
                              "TunnelOptions": [{"OutsideIpAddress": "54.1.2.3"}]},
                  "VgwTelemetry": [{"OutsideIpAddress": "54.1.2.3", "Status": "DOWN"}]}
    result = one(aws(coll("vpn_connection", [connection])), "vpn_connection")
    assert result["status"] == "FAIL"
    assert result["evidence"]["public_addresses"] == ["54.1.2.3"]
    assert result["evidence"]["exposed_ports"] == ["udp/500", "udp/4500", "esp"]
    assert result["evidence"]["authenticated_endpoint"] is True

    private = copy.deepcopy(connection)
    private["Options"]["OutsideIpAddressType"] = "PrivateIpv4"
    assert one(aws(coll("vpn_connection", [private])), "vpn_connection")["status"] == "PASS"

    missing = copy.deepcopy(connection)
    del missing["VgwTelemetry"]
    assert one(aws(coll("vpn_connection", [missing])), "vpn_connection")["status"] == "UNKNOWN"


def test_aws_client_vpn_managed_listener_and_inactive_state():
    endpoint = {"ClientVpnEndpointId": "cvpn-endpoint-1", "Status": {"Code": "available"},
                "DnsName": "*.cvpn-endpoint-1.prod.clientvpn.us-east-1.amazonaws.com",
                "TransportProtocol": "tcp", "VpnPort": 1194}
    result = one(aws(coll("client_vpn_endpoint", [endpoint])), "client_vpn_endpoint")
    assert result["status"] == "FAIL"
    assert result["evidence"]["exposed_ports"] == ["tcp/1194"]
    assert result["evidence"]["authenticated_endpoint"] is True
    assert result["evidence"]["path"][0]["dns_name"] == endpoint["DnsName"]

    inactive = copy.deepcopy(endpoint)
    inactive["Status"]["Code"] = "pending-associate"
    assert one(aws(coll("client_vpn_endpoint", [inactive])), "client_vpn_endpoint")["status"] == "PASS"

    incomplete = copy.deepcopy(endpoint)
    del incomplete["DnsName"]
    assert one(aws(coll("client_vpn_endpoint", [incomplete])), "client_vpn_endpoint")["status"] == "UNKNOWN"


def test_client_vpn_all_authenticated_clients_authorization_declaration():
    from peaso.analysis.catalog import REQUIRED_TYPES
    from peaso.finding_observation import evidence_summary

    assert "client_vpn_routing" in REQUIRED_TYPES["aws"]["exposure"]
    endpoint = {"ClientVpnEndpointId": "cvpn-endpoint-1", "Status": {"Code": "available"},
                "DnsName": "*.cvpn-endpoint-1.prod.clientvpn.us-east-1.amazonaws.com",
                "AuthorizationRules": {"ClientVpnEndpointId": "cvpn-endpoint-1", "collection_status": "collected",
                                       "items": [{"Status": {"Code": "active"}, "AuthorizeAllGroups": True,
                                                  "DestinationCidr": "10.20.0.0/16"}]}}

    def grants(row, routing=None):
        collections = [coll("client_vpn_endpoint", [row], service="ec2")]
        if routing is not None:
            collections.append(coll("client_vpn_routing", [routing], service="ec2"))
        return [f for f in exposure(aws(*collections))
                if f["evidence"].get("exposure_kind") == "vpn_client_authorization"]

    found = grants(endpoint)
    assert len(found) == 1 and found[0]["status"] == "FAIL"
    assert found[0]["evidence"]["path"][0]["destination_cidrs"] == ["10.20.0.0/16"]
    assert "Route and destination controls remain unverified" in evidence_summary(found[0])
    assert "authorization rule" in found[0]["remediation"]
    routed = {"id": "cvpn-endpoint-1", "ClientVpnEndpointId": "cvpn-endpoint-1"}
    routed["Routes"] = {"ClientVpnEndpointId": "cvpn-endpoint-1", "collection_status": "collected", "items": [
        {"ClientVpnEndpointId": "cvpn-endpoint-1", "DestinationCidr": "10.20.0.0/16",
         "TargetSubnet": "subnet-1234", "Status": {"Code": "active"}}]}
    routed["TargetNetworks"] = {"ClientVpnEndpointId": "cvpn-endpoint-1", "collection_status": "collected", "items": [
        {"ClientVpnEndpointId": "cvpn-endpoint-1", "TargetNetworkId": "subnet-1234",
         "VpcId": "vpc-1234", "AssociationId": "cvpn-assoc-1234",
         "Status": {"Code": "associated"}, "SecurityGroups": ["sg-1234"]}]}
    joined = grants(endpoint, routed)[0]
    assert joined["status"] == "FAIL"
    assert joined["evidence"]["path"][1]["layer"] == "client_route"
    assert joined["evidence"]["path"][1]["routes"][0]["vpc_id"] == "vpc-1234"
    assert any(gap["layer"] == "destination" for gap in joined["evidence"]["unresolved"])
    mismatched = copy.deepcopy(routed)
    mismatched["Routes"]["items"][0]["DestinationCidr"] = "10.30.0.0/16"
    assert all(step["layer"] != "client_route" for step in grants(endpoint, mismatched)[0]["evidence"]["path"])
    partial_routes = copy.deepcopy(routed)
    partial_routes["Routes"]["collection_status"] = "partial"
    assert all(step["layer"] != "client_route" for step in grants(endpoint, partial_routes)[0]["evidence"]["path"])
    wrong_target = copy.deepcopy(routed)
    wrong_target["TargetNetworks"]["items"][0]["ClientVpnEndpointId"] = "cvpn-endpoint-foreign"
    assert all(step["layer"] != "client_route" for step in grants(endpoint, wrong_target)[0]["evidence"]["path"])
    missing_association = copy.deepcopy(routed)
    missing_association["TargetNetworks"]["items"][0].pop("AssociationId")
    assert all(step["layer"] != "client_route" for step in grants(endpoint, missing_association)[0]["evidence"]["path"])
    scoped = copy.deepcopy(endpoint)
    scoped["AuthorizationRules"]["items"][0]["AuthorizeAllGroups"] = False
    assert grants(scoped) == []
    inactive = copy.deepcopy(endpoint)
    inactive["Status"]["Code"] = "deleted"
    assert grants(inactive) == []
    pending = copy.deepcopy(endpoint)
    pending["AuthorizationRules"]["items"][0]["Status"]["Code"] = "authorizing"
    assert grants(pending) == []
    malformed = copy.deepcopy(endpoint)
    malformed["AuthorizationRules"]["items"][0]["DestinationCidr"] = "not-a-cidr"
    assert grants(malformed)[0]["status"] == "UNKNOWN"
    partial = copy.deepcopy(endpoint)
    partial["AuthorizationRules"]["collection_status"] = "partial"
    assert grants(partial)[0]["status"] == "UNKNOWN"
    wrong = copy.deepcopy(endpoint)
    wrong["AuthorizationRules"]["ClientVpnEndpointId"] = "cvpn-endpoint-foreign"
    assert grants(wrong)[0]["status"] == "UNKNOWN"


def test_aws_vpc_endpoint_service_external_principal_permissions():
    service = {"ServiceId": "vpce-svc-1", "ServiceState": "Available",
               "AcceptanceRequired": False, "AllowedPrincipals": ["*"], "EndpointConnections": []}
    result = one(aws(coll("vpc_endpoint_service", [service])), "vpc_endpoint_service")
    assert result["status"] == "FAIL"
    assert result["evidence"]["path"][0]["external_principals"] == ["*"]
    assert result["evidence"]["path"][0]["acceptance_required"] is False

    named = copy.deepcopy(service)
    named["AllowedPrincipals"] = ["arn:aws:iam::999988887777:root"]
    named["AcceptanceRequired"] = True
    assert one(aws(coll("vpc_endpoint_service", [named])), "vpc_endpoint_service")["status"] == "FAIL"

    internal = copy.deepcopy(service)
    internal["AllowedPrincipals"] = [f"arn:aws:iam::{ACCOUNT}:root"]
    assert one(aws(coll("vpc_endpoint_service", [internal])), "vpc_endpoint_service")["status"] == "PASS"

    incomplete = copy.deepcopy(service)
    del incomplete["AllowedPrincipals"]
    assert one(aws(coll("vpc_endpoint_service", [incomplete])), "vpc_endpoint_service")["status"] == "UNKNOWN"


def test_aws_privatelink_external_connection_survives_removed_permission():
    service = {"ServiceId": "vpce-svc-1", "ServiceState": "Available", "AcceptanceRequired": True,
               "AllowedPrincipals": [], "EndpointConnections": [{"ServiceId": "vpce-svc-1",
                   "VpcEndpointId": "vpce-1", "VpcEndpointOwner": "999988887777", "VpcEndpointState": "Available"}]}
    result = one(aws(coll("vpc_endpoint_service", [service])), "vpc_endpoint_service")
    assert result["status"] == "FAIL"
    assert result["evidence"]["path"][0]["active_external_connections"] == [
        {"account": "999988887777", "endpoint": "vpce-1"}]

    pending = copy.deepcopy(service)
    pending["EndpointConnections"][0]["VpcEndpointState"] = "PendingAcceptance"
    assert one(aws(coll("vpc_endpoint_service", [pending])), "vpc_endpoint_service")["status"] == "PASS"

    missing = copy.deepcopy(service)
    del missing["EndpointConnections"]
    assert one(aws(coll("vpc_endpoint_service", [missing])), "vpc_endpoint_service")["status"] == "UNKNOWN"

    malformed = copy.deepcopy(service)
    malformed["EndpointConnections"][0]["VpcEndpointOwner"] = "not-an-account"
    assert one(aws(coll("vpc_endpoint_service", [malformed])), "vpc_endpoint_service")["status"] == "UNKNOWN"


def test_aws_ecr_registry_cross_account_image_replication():
    registry = {"id": f"ecr-registry/{ACCOUNT}/us-east-1", "registryId": ACCOUNT,
                "Replication": {"collection_status": "collected", "rules": [{
                    "destinations": [{"registryId": "999988887777", "region": "eu-west-1"}],
                    "repositoryFilters": [{"filterType": "PREFIX_MATCH", "filter": "prod/"}]}]}}
    result = one(aws(coll("ecr_registry", [registry], service="ecr")), "ecr_registry")
    assert result["status"] == "FAIL"
    assert result["evidence"]["path"][0]["external_destinations"] == [
        {"account": "999988887777", "region": "eu-west-1", "repository_prefixes": ["prod/"]}]

    internal = copy.deepcopy(registry)
    internal["Replication"]["rules"][0]["destinations"][0]["registryId"] = ACCOUNT
    assert one(aws(coll("ecr_registry", [internal], service="ecr")), "ecr_registry")["status"] == "PASS"

    incomplete = copy.deepcopy(registry)
    incomplete["Replication"]["collection_status"] = "denied"
    assert one(aws(coll("ecr_registry", [incomplete], service="ecr")), "ecr_registry")["status"] == "UNKNOWN"

    malformed = copy.deepcopy(registry)
    malformed["Replication"]["rules"][0]["destinations"][0]["registryId"] = "unknown"
    assert one(aws(coll("ecr_registry", [malformed], service="ecr")), "ecr_registry")["status"] == "UNKNOWN"


def test_ecr_registry_policy_foreign_pull_actions():
    prefix = f"arn:aws:ecr:us-east-1:{ACCOUNT}:repository/"
    principal = {"AWS": "arn:aws:iam::444455556666:root"}

    def policy(action=None, resource=prefix + "*", who=principal, **extra):
        return {"collection_status": "collected", "policyText": {"Statement": [{
            "Effect": "Allow", "Principal": who,
            "Action": action or ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
            "Resource": resource, **extra}]}}

    def result(read, registry_id=ACCOUNT):
        registry = {"id": f"ecr-registry/{ACCOUNT}/us-east-1", "registryId": registry_id,
                    "Replication": {"collection_status": "collected", "rules": []}, "RegistryPolicy": read}
        return [f for f in exposure(aws(coll("ecr_registry", [registry], service="ecr")))
                if f["evidence"].get("exposure_kind") == "external_registry_policy_pull"]

    named = result(policy())
    assert len(named) == 1 and named[0]["status"] == "FAIL"
    assert named[0]["evidence"]["external_scope_ids"] == ["444455556666"]
    assert result(policy(who="*"))[0]["status"] == "FAIL"
    assert result(policy(action="ecr:BatchGetImage")) == []
    assert result(policy(resource=f"arn:aws:ecr:us-east-1:999988887777:repository/*")) == []
    assert result(policy(who={"AWS": f"arn:aws:iam::{ACCOUNT}:root"})) == []
    assert result({"collection_status": "empty", "absent": True}) == []
    assert result(policy(Condition={"StringEquals": {"aws:PrincipalOrgID": "o-1234567890"}}))[0]["status"] == "UNKNOWN"
    denied = policy()
    denied["policyText"]["Statement"].append({"Effect": "Deny", "Principal": principal,
                                                 "Action": "ecr:*", "Resource": "*"})
    assert result(denied)[0]["status"] == "UNKNOWN"
    denied_one = policy()
    denied_one["policyText"]["Statement"].append({"Effect": "Deny", "Principal": principal,
                                                     "Action": "ecr:BatchGetImage", "Resource": "*"})
    assert result(denied_one)[0]["status"] == "UNKNOWN"
    assert result({"collection_status": "denied"})[0]["status"] == "UNKNOWN"
    assert result(policy(), registry_id="000000000000")[0]["status"] == "UNKNOWN"


def test_ecr_creation_template_foreign_pull_applies_only_to_future_repositories():
    principal = {"AWS": "arn:aws:iam::444455556666:root"}

    def statement(who=principal, actions=None, **extra):
        return {"Effect": "Allow", "Principal": who,
                "Action": actions or ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
                **extra}

    def result(rows, status="collected"):
        registry = {"id": f"ecr-registry/{ACCOUNT}/us-east-1", "registryId": ACCOUNT,
                    "Replication": {"collection_status": "collected", "rules": []},
                    "RegistryPolicy": {"collection_status": "empty", "absent": True},
                    "RepositoryCreationTemplates": {"collection_status": status, "items": rows}}
        return [f for f in exposure(aws(coll("ecr_registry", [registry], service="ecr")))
                if f["evidence"].get("exposure_kind") == "external_registry_template_pull"]

    def template(policy=None):
        return {"prefix": "prod", "appliedFor": ["REPLICATION"],
                "repositoryPolicy": {"Statement": [statement()]} if policy is None else policy}

    found = result([template()])
    assert len(found) == 1 and found[0]["status"] == "FAIL"
    assert found[0]["evidence"]["external_scope_ids"] == ["444455556666"]
    assert found[0]["evidence"]["path"][0]["future_grants"][0]["prefix"] == "prod"
    assert "future" in found[0]["evidence"]["semantics"]
    assert result([template({"Statement": [statement(who="*")]})])[0]["status"] == "FAIL"
    assert result([template({"Statement": [statement(actions="ecr:BatchGetImage")]})]) == []
    assert result([template({"Statement": [statement(who={"AWS": f"arn:aws:iam::{ACCOUNT}:root"})]})]) == []
    assert result([{"prefix": "ROOT", "appliedFor": ["CREATE_ON_PUSH"]}]) == []
    assert result([], status="empty") == []
    assert result([template({"Statement": [statement(Condition={"StringEquals": {"aws:PrincipalOrgID": "o-123"}})]})])[0]["status"] == "UNKNOWN"
    assert result([template({"Statement": [statement(), {"Effect": "Deny", "Principal": principal,
                                                     "Action": "ecr:*", "Resource": "*"}]})])[0]["status"] == "UNKNOWN"
    assert result([template({"Statement": [statement(), {"Effect": "Deny", "Principal": principal,
                                                     "Action": "ecr:BatchGetImage", "Resource": "*"}]})])[0]["status"] == "UNKNOWN"
    assert result([template()], status="denied")[0]["status"] == "UNKNOWN"


def test_ecr_public_repository_declares_anonymous_pull_without_image_inventory():
    from peaso.finding_observation import evidence_summary

    repository = {"registryId": ACCOUNT, "repositoryName": "team/app",
                  "repositoryArn": f"arn:aws:ecr-public::{ACCOUNT}:repository/team/app",
                  "repositoryUri": "public.ecr.aws/example/team/app"}
    found = one(aws(coll("ecr_public_repository", [repository], service="ecr-public")), "ecr_public_repository")
    assert found["status"] == "FAIL" and found["evidence"]["exposure_kind"] == "public_registry"
    assert found["evidence"]["data_exposure"] is False
    assert "any published images can be pulled anonymously" in evidence_summary(found)
    assert "migrate it" in found["remediation"]

    malformed = {**repository, "registryId": "999988887777"}
    unresolved = one(aws(coll("ecr_public_repository", [malformed], service="ecr-public")), "ecr_public_repository")
    assert unresolved["status"] == "UNKNOWN"
    assert "cannot be attributed" in evidence_summary(unresolved)
    assert not exposure(aws(coll("ecr_public_repository", [], service="ecr-public")))


def test_cloudwatch_subscription_filter_targets_foreign_log_destination():
    from peaso.finding_observation import evidence_summary
    from peaso.analysis.catalog import REQUIRED_TYPES

    assert "log_subscription_filter" in REQUIRED_TYPES["aws"]["exposure"]
    subscription = {"id": f"arn:aws:logs:us-east-1:{ACCOUNT}:log-group:/app/subscription-filter:to-partner",
                    "LogGroupArn": f"arn:aws:logs:us-east-1:{ACCOUNT}:log-group:/app",
                    "logGroupName": "/app", "filterName": "to-partner",
                    "DestinationArn": "arn:aws:logs:us-east-1:999988887777:destination:partner"}
    found = one(aws(coll("log_subscription_filter", [subscription], service="logs")), "log_subscription_filter")
    assert found["status"] == "FAIL" and found["evidence"]["external_scope_ids"] == ["999988887777"]
    assert "delivery was not verified" in evidence_summary(found)
    assert "external export" in found["remediation"]

    internal = {**subscription, "DestinationArn": f"arn:aws:logs:us-east-1:{ACCOUNT}:destination:internal"}
    assert not exposure(aws(coll("log_subscription_filter", [internal], service="logs")))
    malformed = {**subscription, "DestinationArn": "not-an-arn"}
    assert one(aws(coll("log_subscription_filter", [malformed], service="logs")), "log_subscription_filter")["status"] == "UNKNOWN"
    trusted = coll("organization_account", [{"Id": "999988887777"}], service="organizations")
    assert not exposure(aws(coll("log_subscription_filter", [subscription], service="logs"), trusted))


def test_cloudwatch_account_subscription_policy_targets_foreign_log_destination():
    from peaso.finding_observation import evidence_summary
    from peaso.analysis.catalog import REQUIRED_TYPES

    kind = "log_account_subscription_policy"
    assert kind in REQUIRED_TYPES["aws"]["exposure"]
    policy = {"id": f"{ACCOUNT}/us-east-1/log-account-policy/export",
              "accountId": ACCOUNT, "policyName": "export", "policyType": "SUBSCRIPTION_FILTER_POLICY",
              "DestinationArn": "arn:aws:logs:us-east-1:999988887777:destination:partner",
              "selectionCriteria": 'LogGroupName NOT IN ["skip"]'}
    found = one(aws(coll(kind, [policy], service="logs")), kind)
    assert found["status"] == "FAIL" and found["evidence"]["external_scope_ids"] == ["999988887777"]
    assert "account policy export" in evidence_summary(found)
    assert "delivery was not verified" in evidence_summary(found)
    own = {**policy, "DestinationArn": f"arn:aws:logs:us-east-1:{ACCOUNT}:destination:own"}
    assert not exposure(aws(coll(kind, [own], service="logs")))
    malformed = {**policy, "DestinationArn": "unknown"}
    assert one(aws(coll(kind, [malformed], service="logs")), kind)["status"] == "UNKNOWN"
    wrong_scope = {**policy, "accountId": "999988887777"}
    assert one(aws(coll(kind, [wrong_scope], service="logs")), kind)["status"] == "UNKNOWN"
    trusted = coll("organization_account", [{"Id": "999988887777"}], service="organizations")
    assert not exposure(aws(coll(kind, [policy], service="logs"), trusted))


def test_cloudwatch_destination_access_policy_grants_foreign_sender():
    from peaso.analysis.catalog import REQUIRED_TYPES

    assert "log_destination" in REQUIRED_TYPES["aws"]["exposure"]
    arn = f"arn:aws:logs:us-east-1:{ACCOUNT}:destination:receiver"
    statement = {"Effect": "Allow", "Principal": {"AWS": "999988887777"},
                 "Action": ["logs:PutSubscriptionFilter", "logs:PutAccountPolicy"], "Resource": arn}

    def findings(statements, **changes):
        row = {"arn": arn, "destinationName": "receiver", "targetArn": f"arn:aws:kinesis:us-east-1:{ACCOUNT}:stream/receiver",
               "accessPolicy": json.dumps({"Statement": statements}), **changes}
        return [f for f in exposure(aws(coll("log_destination", [row], service="logs")))
                if f["evidence"].get("exposure_kind") == "external_generic_policy_grant"]

    found = findings([statement])
    assert len(found) == 1 and found[0]["status"] == "FAIL"
    assert found[0]["evidence"]["external_scope_ids"] == ["999988887777"]
    assert found[0]["evidence"]["path"][0]["external_grants"][0]["actions"] == sorted(statement["Action"])
    assert findings([{**statement, "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}}]) == []
    assert findings([{**statement, "Resource": arn + "-other"}]) == []
    assert findings([statement, {**statement, "Effect": "Deny"}])[0]["status"] == "UNKNOWN"
    assert findings([{**statement, "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-123"}}}])[0]["status"] == "UNKNOWN"
    assert findings([statement], arn=arn.replace(ACCOUNT, "000000000000"))[0]["status"] == "UNKNOWN"
    assert findings([statement], accessPolicy="{broken")[0]["status"] == "UNKNOWN"
    assert findings([statement], accessPolicy="") == []


def test_private_ecr_repository_policy_foreign_image_pull_grant():
    from peaso.analysis.catalog import REQUIRED_TYPES
    from peaso.finding_observation import evidence_summary
    kind = "ecr_repository"
    assert kind in REQUIRED_TYPES["aws"]["exposure"]
    arn = f"arn:aws:ecr:us-east-1:{ACCOUNT}:repository/team/app"
    statement = {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
                 "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"], "Resource": arn}
    repo = {"repositoryArn": arn, "repositoryName": "team/app", "registryId": ACCOUNT,
            "Policy": {"collection_status": "collected", "registryId": ACCOUNT,
                       "repositoryName": "team/app", "policyText": {"Statement": [statement]}}}
    found = one(aws(coll(kind, [repo], service="ecr")), kind)
    assert found["status"] == "FAIL" and found["evidence"]["external_scope_ids"] == ["999988887777"]
    assert any("authentication" in gap.get("reason", "").lower() for gap in found["evidence"]["unresolved"])
    assert "image pulls were not observed" in evidence_summary(found)
    assert "ECR repository" in found["remediation"]
    own = {**repo, "Policy": {**repo["Policy"], "policyText": {"Statement": [{**statement,
           "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}}]}}}
    assert not exposure(aws(coll(kind, [own], service="ecr")))
    wrong_action = {**repo, "Policy": {**repo["Policy"], "policyText": {"Statement": [{**statement,
                    "Action": "ecr:DescribeImages"}]}}}
    assert not exposure(aws(coll(kind, [wrong_action], service="ecr")))
    wrong_resource = {**repo, "Policy": {**repo["Policy"], "policyText": {"Statement": [{**statement,
                      "Resource": arn + "-different"}]}}}
    assert not exposure(aws(coll(kind, [wrong_resource], service="ecr")))
    restricted = {**repo, "Policy": {**repo["Policy"], "policyText": {"Statement": [{**statement,
                  "Condition": {"StringEquals": {"aws:SourceAccount": "999988887777"}}}]}}}
    assert one(aws(coll(kind, [restricted], service="ecr")), kind)["status"] == "UNKNOWN"
    denied = {**repo, "Policy": {**repo["Policy"], "policyText": {"Statement": [statement,
              {"Effect": "Deny", "Principal": "*", "Action": "ecr:*", "Resource": arn}]}}}
    assert one(aws(coll(kind, [denied], service="ecr")), kind)["status"] == "UNKNOWN"
    missing = {**repo, "Policy": {"collection_status": "denied"}}
    assert one(aws(coll(kind, [missing], service="ecr")), kind)["status"] == "UNKNOWN"
    trusted = coll("organization_account", [{"Id": "999988887777"}], service="organizations")
    assert not exposure(aws(coll(kind, [repo], service="ecr"), trusted))


def test_secret_policy_foreign_read_requires_customer_key_candidate():
    from peaso.analysis.catalog import REQUIRED_TYPES
    from peaso.finding_observation import evidence_summary
    kind = "secret"
    assert kind in REQUIRED_TYPES["aws"]["exposure"]
    arn = f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:app/db-AbCdEf"
    statement = {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999988887777:role/reader"},
                 "Action": "secretsmanager:GetSecretValue", "Resource": arn}
    secret = {"ARN": arn, "Name": "app/db", "KmsKeyId": f"arn:aws:kms:us-east-1:{ACCOUNT}:key/abc",
              "_coverage": {"KmsKeyId": {"status": "collected"}},
              "Policy": {"collection_status": "collected", "ARN": arn, "Name": "app/db",
                         "ResourcePolicy": {"Statement": [statement]}}}
    found = one(aws(coll(kind, [secret], service="secretsmanager")), kind)
    assert found["status"] == "FAIL" and found["evidence"]["external_scope_ids"] == ["999988887777"]
    assert "no secret value was read" in evidence_summary(found)
    assert "KMS key policy" in found["remediation"]
    default = {**secret, "KmsKeyId": None, "_coverage": {"KmsKeyId": {"status": "empty",
               "documented_default": "aws/secretsmanager"}}}
    assert one(aws(coll(kind, [default], service="secretsmanager")), kind)["status"] == "PASS"
    missing_key = {**secret, "_coverage": {"KmsKeyId": {"status": "denied"}}}
    assert one(aws(coll(kind, [missing_key], service="secretsmanager")), kind)["status"] == "UNKNOWN"
    own = {**secret, "Policy": {**secret["Policy"], "ResourcePolicy": {"Statement": [{**statement,
           "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}}]}}}
    assert not exposure(aws(coll(kind, [own], service="secretsmanager")))
    wrong_action = {**secret, "Policy": {**secret["Policy"], "ResourcePolicy": {"Statement": [{**statement,
                    "Action": "secretsmanager:DescribeSecret"}]}}}
    assert not exposure(aws(coll(kind, [wrong_action], service="secretsmanager")))
    wrong_resource = {**secret, "Policy": {**secret["Policy"], "ResourcePolicy": {"Statement": [{**statement,
                      "Resource": arn + "-other"}]}}}
    assert not exposure(aws(coll(kind, [wrong_resource], service="secretsmanager")))
    conditioned = {**secret, "Policy": {**secret["Policy"], "ResourcePolicy": {"Statement": [{**statement,
                   "Condition": {"StringEquals": {"aws:SourceAccount": "999988887777"}}}]}}}
    assert one(aws(coll(kind, [conditioned], service="secretsmanager")), kind)["status"] == "UNKNOWN"
    denied = {**secret, "Policy": {**secret["Policy"], "ResourcePolicy": {"Statement": [statement,
              {"Effect": "Deny", "Principal": "*", "Action": "secretsmanager:GetSecretValue", "Resource": arn}]}}}
    assert one(aws(coll(kind, [denied], service="secretsmanager")), kind)["status"] == "UNKNOWN"
    trusted = coll("organization_account", [{"Id": "999988887777"}], service="organizations")
    assert not exposure(aws(coll(kind, [secret], service="secretsmanager"), trusted))


def test_sqs_queue_policy_foreign_receive_respects_key_and_scope():
    from peaso.analysis.catalog import REQUIRED_TYPES
    from peaso.finding_observation import evidence_summary
    kind = "sqs_queue"
    assert kind in REQUIRED_TYPES["aws"]["exposure"]
    arn = f"arn:aws:sqs:us-east-1:{ACCOUNT}:events"
    url = f"https://sqs.us-east-1.amazonaws.com/{ACCOUNT}/events"
    statement = {"Effect": "Allow", "Principal": {"AWS": "999988887777"},
                 "Action": "sqs:ReceiveMessage", "Resource": arn}
    attrs = {"QueueArn": arn, "Policy": {"Statement": [statement]}, "KmsMasterKeyId": "",
             "_coverage": {"KmsMasterKeyId": {"status": "empty"}}}
    queue = {"QueueUrl": url, "Attributes": {"collection_status": "collected", "Attributes": attrs}}
    found = one(aws(coll(kind, [queue], service="sqs")), kind)
    assert found["status"] == "FAIL" and found["evidence"]["external_scope_ids"] == ["999988887777"]
    assert "no messages were read" in evidence_summary(found)
    assert "SQS queue" in found["remediation"]
    managed = {**queue, "Attributes": {**queue["Attributes"], "Attributes": {
               **attrs, "KmsMasterKeyId": "alias/aws/sqs"}}}
    assert one(aws(coll(kind, [managed], service="sqs")), kind)["status"] == "PASS"
    own = {**queue, "Attributes": {**queue["Attributes"], "Attributes": {**attrs,
           "Policy": {"Statement": [{**statement, "Principal": {"AWS": ACCOUNT}}]}}}}
    assert not exposure(aws(coll(kind, [own], service="sqs")))
    wrong_action = {**queue, "Attributes": {**queue["Attributes"], "Attributes": {**attrs,
                    "Policy": {"Statement": [{**statement, "Action": "sqs:SendMessage"}]}}}}
    assert not exposure(aws(coll(kind, [wrong_action], service="sqs")))
    wrong_resource = {**queue, "Attributes": {**queue["Attributes"], "Attributes": {**attrs,
                      "Policy": {"Statement": [{**statement, "Resource": arn + "-other"}]}}}}
    assert not exposure(aws(coll(kind, [wrong_resource], service="sqs")))
    conditioned = {**queue, "Attributes": {**queue["Attributes"], "Attributes": {**attrs,
                   "Policy": {"Statement": [{**statement, "Condition": {"StringEquals": {"aws:SourceAccount": "999988887777"}}}]}}}}
    assert one(aws(coll(kind, [conditioned], service="sqs")), kind)["status"] == "UNKNOWN"
    denied = {**queue, "Attributes": {**queue["Attributes"], "Attributes": {**attrs,
              "Policy": {"Statement": [statement, {"Effect": "Deny", "Principal": "*",
                       "Action": "sqs:ReceiveMessage", "Resource": arn}]}}}}
    assert one(aws(coll(kind, [denied], service="sqs")), kind)["status"] == "UNKNOWN"
    mismatched = {**queue, "Attributes": {**queue["Attributes"], "Attributes": {**attrs,
                  "QueueArn": arn + "-other"}}}
    assert one(aws(coll(kind, [mismatched], service="sqs")), kind)["status"] == "UNKNOWN"
    unread = {**queue, "Attributes": {"collection_status": "denied"}}
    assert one(aws(coll(kind, [unread], service="sqs")), kind)["status"] == "UNKNOWN"
    trusted = coll("organization_account", [{"Id": "999988887777"}], service="organizations")
    assert not exposure(aws(coll(kind, [queue], service="sqs"), trusted))


def test_confirmed_foreign_owned_sns_topic_subscription():
    from peaso.analysis.catalog import REQUIRED_TYPES
    from peaso.finding_observation import evidence_summary
    kind = "sns_topic_subscription"
    assert kind in REQUIRED_TYPES["aws"]["exposure"]
    topic = f"arn:aws:sns:us-east-1:{ACCOUNT}:events"
    foreign = "999988887777"
    subscription = f"arn:aws:sns:us-east-1:{foreign}:events:12345678-1234-1234-1234-123456789012"
    row = {"id": subscription, "TopicArn": topic, "SubscriptionArn": subscription,
           "Owner": foreign, "Protocol": "https"}
    found = one(aws(coll(kind, [row], service="sns")), kind)
    assert found["status"] == "FAIL" and found["evidence"]["external_scope_ids"] == [foreign]
    assert "message delivery was not observed" in evidence_summary(found)
    assert "SNS topic" in found["remediation"]
    pending = {**row, "SubscriptionArn": "PendingConfirmation"}
    assert one(aws(coll(kind, [pending], service="sns")), kind)["status"] == "UNKNOWN"
    mismatched = {**row, "TopicArn": topic.replace(ACCOUNT, foreign)}
    assert one(aws(coll(kind, [mismatched], service="sns")), kind)["status"] == "UNKNOWN"
    own = {**row, "Owner": ACCOUNT, "SubscriptionArn": subscription.replace(foreign, ACCOUNT)}
    assert not exposure(aws(coll(kind, [own], service="sns")))
    trusted = coll("organization_account", [{"Id": foreign}], service="organizations")
    assert not exposure(aws(coll(kind, [row], service="sns"), trusted))


def test_sns_topic_policy_foreign_and_wildcard_subscribe_grants():
    from peaso.analysis.catalog import REQUIRED_TYPES
    from peaso.finding_observation import evidence_summary
    kind = "sns_topic"
    assert kind in REQUIRED_TYPES["aws"]["exposure"]
    arn = f"arn:aws:sns:us-east-1:{ACCOUNT}:events"
    statement = {"Effect": "Allow", "Principal": {"AWS": "999988887777"},
                 "Action": "sns:Subscribe", "Resource": arn}
    attrs = {"TopicArn": arn, "Owner": ACCOUNT, "Policy": {"Statement": [statement]}}
    topic = {"TopicArn": arn, "Attributes": {"collection_status": "collected", "Attributes": attrs}}
    found = one(aws(coll(kind, [topic], service="sns")), kind)
    assert found["status"] == "FAIL" and found["evidence"]["external_scope_ids"] == ["999988887777"]
    assert "no message delivery was observed" in evidence_summary(found)
    assert "Subscribe grant" in found["remediation"]
    wildcard = {**topic, "Attributes": {**topic["Attributes"], "Attributes": {**attrs,
                "Policy": {"Statement": [{**statement, "Principal": "*"}]}}}}
    public = one(aws(coll(kind, [wildcard], service="sns")), kind)
    assert public["status"] == "FAIL" and public["evidence"]["external_scope_ids"] == ["*"]
    assert "any principal" in evidence_summary(public)
    own = {**topic, "Attributes": {**topic["Attributes"], "Attributes": {**attrs,
           "Policy": {"Statement": [{**statement, "Principal": {"AWS": ACCOUNT}}]}}}}
    assert not exposure(aws(coll(kind, [own], service="sns")))
    wrong_action = {**topic, "Attributes": {**topic["Attributes"], "Attributes": {**attrs,
                    "Policy": {"Statement": [{**statement, "Action": "sns:Publish"}]}}}}
    assert not exposure(aws(coll(kind, [wrong_action], service="sns")))
    wrong_resource = {**topic, "Attributes": {**topic["Attributes"], "Attributes": {**attrs,
                      "Policy": {"Statement": [{**statement, "Resource": arn + "-other"}]}}}}
    assert not exposure(aws(coll(kind, [wrong_resource], service="sns")))
    conditioned = {**topic, "Attributes": {**topic["Attributes"], "Attributes": {**attrs,
                   "Policy": {"Statement": [{**statement,
                              "Condition": {"StringEquals": {"sns:Protocol": "https"}}}]}}}}
    assert one(aws(coll(kind, [conditioned], service="sns")), kind)["status"] == "UNKNOWN"
    denied = {**topic, "Attributes": {**topic["Attributes"], "Attributes": {**attrs,
              "Policy": {"Statement": [statement, {"Effect": "Deny", "Principal": "*",
                       "Action": "sns:Subscribe", "Resource": arn}]}}}}
    assert one(aws(coll(kind, [denied], service="sns")), kind)["status"] == "UNKNOWN"
    bad_owner = {**topic, "Attributes": {**topic["Attributes"], "Attributes": {**attrs,
                 "Owner": "999988887777"}}}
    assert one(aws(coll(kind, [bad_owner], service="sns")), kind)["status"] == "UNKNOWN"
    trusted = coll("organization_account", [{"Id": "999988887777"}], service="organizations")
    assert not exposure(aws(coll(kind, [topic], service="sns"), trusted))


def test_kms_key_policy_foreign_decrypt_grant_requires_enabled_customer_key():
    from peaso.analysis.catalog import REQUIRED_TYPES
    from peaso.finding_observation import evidence_summary
    kind = "kms_key"
    assert kind in REQUIRED_TYPES["aws"]["exposure"]
    key_id = "12345678-1234-1234-1234-123456789012"
    arn = f"arn:aws:kms:us-east-1:{ACCOUNT}:key/{key_id}"
    metadata = {"KeyId": key_id, "Arn": arn, "KeyManager": "CUSTOMER",
                "KeyUsage": "ENCRYPT_DECRYPT", "KeyState": "Enabled", "Enabled": True}
    statement = {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
                 "Action": "kms:Decrypt", "Resource": "*"}
    key = {"KeyId": key_id, "KeyArn": arn,
           "Metadata": {"collection_status": "collected", "KeyMetadata": metadata},
           "Policy": {"collection_status": "collected", "Policy": {"Statement": [statement]}}}
    found = one(aws(coll(kind, [key], service="kms")), kind)
    assert found["status"] == "FAIL" and found["evidence"]["external_scope_ids"] == ["999988887777"]
    assert "no decryption was observed" in evidence_summary(found)
    assert "KMS key policy" in found["remediation"]
    wildcard = {**key, "Policy": {**key["Policy"], "Policy": {"Statement": [{**statement, "Principal": "*"}]}}}
    assert one(aws(coll(kind, [wildcard], service="kms")), kind)["evidence"]["external_scope_ids"] == ["*"]
    own = {**key, "Policy": {**key["Policy"], "Policy": {"Statement": [{**statement,
           "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}}]}}}
    assert not exposure(aws(coll(kind, [own], service="kms")))
    wrong_action = {**key, "Policy": {**key["Policy"], "Policy": {"Statement": [{**statement,
                    "Action": "kms:DescribeKey"}]}}}
    assert not exposure(aws(coll(kind, [wrong_action], service="kms")))
    disabled = {**key, "Metadata": {"collection_status": "collected", "KeyMetadata": {
                **metadata, "KeyState": "Disabled", "Enabled": False}}}
    assert one(aws(coll(kind, [disabled], service="kms")), kind)["status"] == "PASS"
    managed = {**key, "Metadata": {"collection_status": "collected", "KeyMetadata": {
               **metadata, "KeyManager": "AWS"}}}
    assert not exposure(aws(coll(kind, [managed], service="kms")))
    signing = {**key, "Metadata": {"collection_status": "collected", "KeyMetadata": {
               **metadata, "KeyUsage": "SIGN_VERIFY"}}}
    assert not exposure(aws(coll(kind, [signing], service="kms")))
    unknown_manager = {**key, "Metadata": {"collection_status": "collected", "KeyMetadata": {
                       field: value for field, value in metadata.items() if field != "KeyManager"}}}
    assert one(aws(coll(kind, [unknown_manager], service="kms")), kind)["status"] == "UNKNOWN"
    conditioned = {**key, "Policy": {**key["Policy"], "Policy": {"Statement": [{**statement,
                   "Condition": {"StringEquals": {"kms:CallerAccount": "999988887777"}}}]}}}
    assert one(aws(coll(kind, [conditioned], service="kms")), kind)["status"] == "UNKNOWN"
    denied = {**key, "Policy": {**key["Policy"], "Policy": {"Statement": [statement,
              {"Effect": "Deny", "Principal": "*", "Action": "kms:Decrypt", "Resource": "*"}]}}}
    assert one(aws(coll(kind, [denied], service="kms")), kind)["status"] == "UNKNOWN"
    unread = {**key, "Policy": {"collection_status": "denied"}}
    assert one(aws(coll(kind, [unread], service="kms")), kind)["status"] == "UNKNOWN"
    trusted = coll("organization_account", [{"Id": "999988887777"}], service="organizations")
    assert not exposure(aws(coll(kind, [key], service="kms"), trusted))


def test_foreign_kms_grant_joins_key_state_policy_and_constraints():
    from peaso.analysis.catalog import REQUIRED_TYPES
    from peaso.finding_observation import evidence_summary
    kind = "kms_grant"
    assert kind in REQUIRED_TYPES["aws"]["exposure"]
    key_id = "12345678-1234-1234-1234-123456789012"
    arn = f"arn:aws:kms:us-east-1:{ACCOUNT}:key/{key_id}"
    metadata = {"KeyId": key_id, "Arn": arn, "KeyManager": "CUSTOMER",
                "KeyUsage": "ENCRYPT_DECRYPT", "KeyState": "Enabled", "Enabled": True}
    key = {"KeyId": key_id, "KeyArn": arn,
           "Metadata": {"collection_status": "collected", "KeyMetadata": metadata},
           "Policy": {"collection_status": "collected", "Policy": {"Statement": [
               {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
                "Action": "kms:*", "Resource": "*"}]}}}
    grant = {"id": arn + "/grant/g1", "GrantId": "g1", "KeyId": key_id, "KeyArn": arn,
             "GranteePrincipal": "arn:aws:iam::999988887777:role/reader", "Operations": ["Decrypt"]}
    collections = lambda row, key_row=key: aws(coll("kms_key", [key_row], service="kms"), coll(kind, [row], service="kms"))
    found = one(collections(grant), kind)
    assert found["status"] == "FAIL" and found["evidence"]["external_scope_ids"] == ["999988887777"]
    assert "ciphertext were not observed" in evidence_summary(found)
    assert "revoke the KMS grant" in found["remediation"]
    same = {**grant, "GranteePrincipal": f"arn:aws:iam::{ACCOUNT}:role/reader"}
    assert not exposure(collections(same))
    encrypt_only = {**grant, "Operations": ["Encrypt"]}
    assert not exposure(collections(encrypt_only))
    constrained = {**grant, "ConstraintKeys": {"EncryptionContextEquals": ["tenant"]}}
    assert one(collections(constrained), kind)["status"] == "UNKNOWN"
    disabled_key = {**key, "Metadata": {"collection_status": "collected", "KeyMetadata": {
                    **metadata, "KeyState": "Disabled", "Enabled": False}}}
    assert one(collections(grant, disabled_key), kind)["status"] == "PASS"
    deny_key = {**key, "Policy": {"collection_status": "collected", "Policy": {"Statement": [
                {"Effect": "Deny", "Principal": "*", "Action": "kms:Decrypt", "Resource": "*"}]}}}
    assert one(collections(grant, deny_key), kind)["status"] == "UNKNOWN"
    assert one(aws(coll(kind, [grant], service="kms")), kind)["status"] == "UNKNOWN"
    trusted = coll("organization_account", [{"Id": "999988887777"}], service="organizations")
    assert not exposure(aws(coll("kms_key", [key], service="kms"), coll(kind, [grant], service="kms"), trusted))


@pytest.mark.parametrize("actions,resource_suffix,deny,expected_authenticated", [
    (["es:DescribeDomain"], "/*", False, True),
    (["es:ESHttpGet"], "/other/*", False, False),
    (["es:ESHttpGet"], "/*", False, False),
    (["es:ESHttpGet"], "/*", True, True),
])
def test_opensearch_anonymous_policy_joins_http_action_domain_resource_and_deny(
        actions, resource_suffix, deny, expected_authenticated):
    arn = f"arn:aws:es:us-east-1:{ACCOUNT}:domain/search"
    statements = [{"Effect": "Allow", "Principal": "*", "Action": actions,
                   "Resource": arn + resource_suffix}]
    if deny:
        statements.append({"Effect": "Deny", "Principal": "*", "Action": "es:ESHttpGet",
                           "Resource": arn + "/*"})
    item = {"DomainName": "search", "Domain": {"collection_status": "collected", "DomainStatus": {
        "DomainName": "search", "ARN": arn, "Endpoint": "search.example.com",
        "AccessPolicies": {"Statement": statements}}}}
    result = one(aws(coll("opensearch_domain", [item], service="opensearch")), "opensearch_domain")
    assert result["evidence"]["authenticated_endpoint"] is expected_authenticated
    if resource_suffix == "/other/*" and not deny:
        assert result["status"] == "FAIL"
        policy_step = next(step for step in result["evidence"]["path"] if step["layer"] == "policy")
        assert policy_step["narrow_resource_declarations"] == [
            {"action": "es:eshttpget", "resource": arn + "/other/*"}]


def test_opensearch_narrow_http_grant_stays_unresolved_with_deny_or_condition():
    arn = f"arn:aws:es:us-east-1:{ACCOUNT}:domain/search"
    allow = {"Effect": "Allow", "Principal": "*", "Action": "es:ESHttpGet", "Resource": arn + "/index/*"}
    status = {"DomainName": "search", "ARN": arn, "Endpoint": "search.example.com",
              "AccessPolicies": {"Statement": [allow]}}
    item = {"DomainName": "search", "Domain": {"collection_status": "collected", "DomainStatus": status}}
    def finding():
        return one(aws(coll("opensearch_domain", [item], service="opensearch")), "opensearch_domain")
    assert finding()["status"] == "FAIL"
    status["AccessPolicies"]["Statement"].append({"Effect": "Deny", "Principal": "*",
        "Action": "es:ESHttpGet", "Resource": arn + "/index/private/*"})
    assert finding()["status"] == "UNKNOWN"
    status["AccessPolicies"]["Statement"].pop()
    allow["Condition"] = {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}
    assert finding()["status"] == "UNKNOWN"


def test_opensearch_fine_grained_auth_honors_anonymous_migration_setting():
    arn = f"arn:aws:es:us-east-1:{ACCOUNT}:domain/search"
    status = {"DomainName": "search", "ARN": arn, "Endpoint": "search.example.com",
              "AccessPolicies": {"Statement": [{"Effect": "Allow", "Principal": "*",
                  "Action": "es:ESHttpGet", "Resource": arn + "/*"}]},
              "AdvancedSecurityOptions": {"Enabled": True, "AnonymousAuthEnabled": True}}
    item = {"DomainName": "search", "Domain": {"collection_status": "collected", "DomainStatus": status}}
    def finding():
        return one(aws(coll("opensearch_domain", [item], service="opensearch")), "opensearch_domain")
    migration = finding()
    assert migration["status"] == "FAIL" and migration["evidence"]["authenticated_endpoint"] is False
    assert next(step for step in migration["evidence"]["path"] if step["layer"] == "fine_grained_access")["anonymous_auth_enabled"] is True
    status["AdvancedSecurityOptions"]["AnonymousAuthEnabled"] = False
    assert finding()["evidence"]["authenticated_endpoint"] is True
    del status["AdvancedSecurityOptions"]["AnonymousAuthEnabled"]
    assert finding()["evidence"]["authenticated_endpoint"] is False


def test_opensearch_dualstack_endpoint_v2_and_missing_host():
    arn = f"arn:aws:es:us-east-1:{ACCOUNT}:domain/search"
    status = {"DomainName": "search", "ARN": arn, "IPAddressType": "dualstack",
              "EndpointV2": "search.aos.us-east-1.on.aws",
              "AccessPolicies": {"Statement": [{"Effect": "Allow", "Principal": "*",
                  "Action": "es:ESHttpGet", "Resource": arn + "/*"}]}}
    item = {"DomainName": "search", "Domain": {"collection_status": "collected", "DomainStatus": status}}
    def finding():
        return one(aws(coll("opensearch_domain", [item], service="opensearch")), "opensearch_domain")
    result = finding()
    assert result["status"] == "FAIL" and result["evidence"]["public_addresses"] == ["search.aos.us-east-1.on.aws"]
    status["Endpoint"] = "search.es.amazonaws.com"
    assert finding()["evidence"]["public_addresses"] == ["search.aos.us-east-1.on.aws", "search.es.amazonaws.com"]
    del status["Endpoint"], status["EndpointV2"]
    unresolved = finding()
    assert unresolved["status"] == "UNKNOWN" and unresolved["evidence"]["public_addresses"] == []
    assert "opensearch:DescribeDomain" in unresolved["evidence"]["collector_facts_needed"]
    status["VPCOptions"] = {}
    assert not exposure(aws(coll("opensearch_domain", [item], service="opensearch")), "opensearch_domain")


def test_aws_instance_open_ssh_fails_with_path_evidence():
    result = one(aws(*aws_network(), instance()), "instance")
    assert result["status"] == "FAIL" and result["severity"] == "high"
    assert result["evidence"]["exposed_ports"] == ["tcp/22"]
    assert result["evidence"]["public_addresses"] == ["54.1.2.3"]
    assert result["title"] == "Internet access to tcp/22 at 54.1.2.3"
    assert result["evidence"]["observed"] == "Internet access to tcp/22 at 54.1.2.3 is allowed."
    assert [s["layer"] for s in result["evidence"]["path"]] == ["security_group", "route", "network_acl"]


@pytest.mark.parametrize("kind", ["instance", "network_interface"])
def test_aws_ec2_public_eni_narrow_sg_nacl_same_source_witness(kind):
    sg = [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
           "IpRanges": [{"CidrIp": "8.8.8.8/32"}]}]
    item = instance() if kind == "instance" else coll("network_interface", [{
        "NetworkInterfaceId": "eni-1", "SubnetId": "subnet-1", "VpcId": "vpc-1",
        "Association": {"PublicIp": "54.1.2.3"}, "Groups": [{"GroupId": "sg-1"}]}])
    def finding(return_source):
        acl = [{"RuleNumber": 100, "Egress": False, "Protocol": "6", "RuleAction": "allow",
                "CidrBlock": "8.8.8.8/32", "PortRange": {"From": 22, "To": 22}},
               {"RuleNumber": 100, "Egress": True, "Protocol": "6", "RuleAction": "allow",
                "CidrBlock": return_source, "PortRange": {"From": 1024, "To": 65535}}]
        return one(aws(*aws_network(sg_rules=sg, nacl_entries=acl), item), kind)
    admitted = finding("8.8.8.8/32")
    assert admitted["status"] == "FAIL" and admitted["evidence"]["exposed_ports"] == ["tcp/22"]
    assert any(step["layer"] == "network_acl_host" and step["public_host_witnesses"][0]["source_ip"] == "8.8.8.8"
               for step in admitted["evidence"]["path"])
    assert finding("1.1.1.1/32")["status"] == "PASS"


@pytest.mark.parametrize("kind", ["instance", "network_interface"])
def test_aws_ec2_public_eni_ipv6_host_sg_nacl_witness(kind):
    host = "2606:4700:4700::1111"
    sg = [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
           "Ipv6Ranges": [{"CidrIpv6": host + "/128"}]}]
    item = instance(public=False) if kind == "instance" else coll("network_interface", [{
        "NetworkInterfaceId": "eni-1", "SubnetId": "subnet-1", "VpcId": "vpc-1",
        "Groups": [{"GroupId": "sg-1"}], "DenyAllIgwTraffic": False,
        "Ipv6Addresses": [{"Ipv6Address": "2600:1f18:abcd::1"}]}])
    if kind == "instance":
        item["items"][0]["NetworkInterfaces"][0]["Ipv6Addresses"] = [{"Ipv6Address": "2600:1f18:abcd::1"}]
    def finding(return_source, ip_source=None):
        network = with_ipv6_subnet(aws_network(sg_rules=sg, nacl_entries=[
            {"RuleNumber": 100, "Egress": False, "Protocol": "6", "RuleAction": "allow",
             "Ipv6CidrBlock": host + "/128", "PortRange": {"From": 22, "To": 22}},
            {"RuleNumber": 100, "Egress": True, "Protocol": "6", "RuleAction": "allow",
             "Ipv6CidrBlock": return_source, "PortRange": {"From": 1024, "To": 65535}}]))
        if ip_source:
            association = next(c for c in network if c["type"] == "subnet")["items"][0]["Ipv6CidrBlockAssociationSet"][0]
            del association["Ipv6AddressAttribute"]
            association["IpSource"] = ip_source
        table = next(c for c in network if c["type"] == "route_table")
        table["items"][0]["Routes"].append({"DestinationIpv6CidrBlock": "::/0", "GatewayId": "igw-1", "State": "active"})
        detail = (coll("network_interface", [{"NetworkInterfaceId": "eni-1", "DenyAllIgwTraffic": False}]),) if kind == "instance" else ()
        return one(aws(*network, item, *detail), kind)
    admitted = finding(host + "/128")
    assert admitted["status"] == "FAIL" and admitted["evidence"]["exposed_ports"] == ["tcp/22"]
    assert any(step["layer"] == "network_acl_host" and step["public_host_witnesses"][0]["source_ip"] == host
               for step in admitted["evidence"]["path"])
    assert finding(host + "/128", ip_source="amazon")["status"] == "FAIL"
    assert finding("2606:4700:4700::1001/128")["status"] == "PASS"
    private = instance(public=False) if kind == "instance" else coll("network_interface", [{
        "NetworkInterfaceId": "eni-private", "SubnetId": "subnet-1", "VpcId": "vpc-1",
        "Groups": [{"GroupId": "sg-1"}], "Ipv6Addresses": [{"Ipv6Address": "fd80::1"}]}])
    if kind == "instance":
        private["items"][0]["NetworkInterfaces"][0]["Ipv6Addresses"] = [{"Ipv6Address": "fd80::1"}]
    assert not exposure(aws(*aws_network(sg_rules=sg), private))
    gua = instance(public=False) if kind == "instance" else coll("network_interface", [{
        "NetworkInterfaceId": "eni-private-gua", "SubnetId": "subnet-1", "VpcId": "vpc-1",
        "Groups": [{"GroupId": "sg-1"}], "DenyAllIgwTraffic": False,
        "Ipv6Addresses": [{"Ipv6Address": "2600:1f18:abcd::1"}]}])
    if kind == "instance":
        gua["items"][0]["NetworkInterfaces"][0]["Ipv6Addresses"] = [{"Ipv6Address": "2600:1f18:abcd::1"}]
    gua_detail = (coll("network_interface", [{"NetworkInterfaceId": "eni-1", "DenyAllIgwTraffic": False}]),) if kind == "instance" else ()
    assert not exposure(aws(*with_ipv6_subnet(aws_network(sg_rules=sg), "private"), gua, *gua_detail))
    unresolved = one(aws(*aws_network(sg_rules=sg), gua, *gua_detail), kind)
    assert unresolved["status"] == "UNKNOWN"
    assert "ec2:DescribeSubnets" in unresolved["evidence"]["collector_facts_needed"]


def test_aws_nacl_deny_before_allow_blocks():
    entries = [{"RuleNumber": 50, "Egress": False, "Protocol": "6", "PortRange": {"From": 22, "To": 22}, "RuleAction": "deny", "CidrBlock": "0.0.0.0/0"},
               {"RuleNumber": 100, "Egress": False, "Protocol": "-1", "RuleAction": "allow", "CidrBlock": "0.0.0.0/0"}]
    result = one(aws(*aws_network(nacl_entries=entries), instance()), "instance")
    assert result["status"] == "PASS" and result["evidence"]["blocked_by"] == "network_acl"


@pytest.mark.parametrize("target", ["instance", "load_balancer"])
def test_aws_world_nacl_ingress_requires_return_ephemeral_allowance(target):
    ingress = {"RuleNumber": 100, "Egress": False, "Protocol": "6", "RuleAction": "allow",
               "CidrBlock": "0.0.0.0/0", "PortRange": {"From": 22 if target == "instance" else 443,
                                                    "To": 22 if target == "instance" else 443}}
    lb = {"LoadBalancerArn": f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:loadbalancer/app/return/1",
          "Scheme": "internet-facing", "Type": "application", "DNSName": "return.example.com",
          "VpcId": "vpc-1", "SecurityGroups": ["sg-1"],
          "AvailabilityZones": [{"SubnetId": "subnet-1"}],
          "Listeners": {"collection_status": "collected", "items": [{"Port": 443, "Protocol": "HTTPS"}]}}
    sg = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
           "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    def finding(egress):
        asset = instance() if target == "instance" else coll("load_balancer", [lb], service="elbv2")
        rules = None if target == "instance" else sg
        return one(aws(*aws_network(sg_rules=rules, nacl_entries=[ingress, egress]), asset), target)
    blocked = {"RuleNumber": 100, "Egress": True, "Protocol": "6", "RuleAction": "allow",
               "CidrBlock": "0.0.0.0/0", "PortRange": {"From": 1, "To": 1023}}
    assert finding(blocked)["status"] == "PASS"
    allowed = {**blocked, "PortRange": {"From": 1024, "To": 65535}}
    assert finding(allowed)["status"] == "FAIL"


def test_aws_no_igw_route_passes_and_private_sg_passes():
    assert one(aws(*aws_network(igw=False), instance()), "instance")["status"] == "PASS"
    private = [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]
    result = one(aws(*aws_network(sg_rules=private), instance()), "instance")
    assert result["status"] == "PASS" and result["evidence"]["blocked_by"] == "security_group"


def test_aws_missing_route_or_public_access_block_read_is_unknown():
    for missing_type, source in (("route_table", "ec2:DescribeRouteTables"),
                                 ("vpc_block_public_access_options", "ec2:DescribeVpcBlockPublicAccessOptions")):
        network = [c for c in aws_network() if c["type"] != missing_type]
        network.append(coll(missing_type, [], status="denied"))
        result = one(aws(*network, instance()), "instance")
        assert result["status"] == "UNKNOWN"
        assert source in result["evidence"]["collector_facts_needed"]


def test_aws_missing_nacl_association_or_entries_is_unknown():
    for acl in (coll("network_acl", [], status="denied"),
                coll("network_acl", [{"NetworkAclId": "acl-1", "VpcId": "vpc-1",
                    "Associations": [{"SubnetId": "subnet-1"}]}])):
        network = [c for c in aws_network() if c["type"] != "network_acl"] + [acl]
        result = one(aws(*network, instance()), "instance")
        assert result["status"] == "UNKNOWN"
        assert "ec2:DescribeNetworkAcls" in result["evidence"]["collector_facts_needed"]


def test_aws_public_instance_missing_subnet_association_is_unknown():
    item = instance()["items"][0]
    del item["SubnetId"]
    del item["NetworkInterfaces"][0]["SubnetId"]
    result = one(aws(*aws_network(), coll("instance", [item])), "instance")
    assert result["status"] == "UNKNOWN"
    assert "ec2:DescribeInstances" in result["evidence"]["collector_facts_needed"]


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
    missing = coll("internet_gateway", [], status="denied")
    unresolved = one(aws(*aws_network(extra=[options("off"), missing]), instance()), "instance")
    assert unresolved["status"] == "UNKNOWN"
    assert "ec2:DescribeInternetGateways" in unresolved["evidence"]["collector_facts_needed"]
    assert next(step for step in unresolved["evidence"]["path"] if step["layer"] == "route")["decision"] == "unknown"
    for attachments in (None, [{"VpcId": "vpc-1"}], [{"VpcId": "vpc-1", "State": "attaching"}]):
        igw = coll("internet_gateway", [{"InternetGatewayId": "igw-1", **(
            {"Attachments": attachments} if attachments is not None else {})}])
        unresolved = one(aws(*aws_network(extra=[options("off"), igw]), instance()), "instance")
        assert unresolved["status"] == "UNKNOWN"
        assert next(step for step in unresolved["evidence"]["path"] if step["layer"] == "route")["decision"] == "unknown"


def test_aws_missing_security_group_inventory_is_unknown():
    network = [c for c in aws_network() if c["type"] != "security_group"] + [coll("security_group", [], status="denied")]
    assert one(aws(*network, instance()), "instance")["status"] == "UNKNOWN"


def test_aws_missing_attached_security_group_ids_is_unknown():
    result = one(aws(*aws_network(), instance(groups=())), "instance")
    assert result["status"] == "UNKNOWN"
    assert any(gap["layer"] == "security_group" for gap in result["evidence"]["unresolved"])


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
    ipv6_instance["items"][0]["NetworkInterfaces"][0]["Ipv6Addresses"] = [{"Ipv6Address": "2600:1f18:abcd::10"}]
    network = with_ipv6_subnet(aws_network())
    # An IPv4 path cannot make an IPv6-only address reachable.
    eni_detail = coll("network_interface", [{"NetworkInterfaceId": "eni-1", "DenyAllIgwTraffic": False}])
    assert one(aws(*network, ipv6_instance, eni_detail), "instance")["status"] == "PASS"
    sg = next(c for c in network if c["type"] == "security_group")
    sg["items"][0]["IpPermissions"][0]["Ipv6Ranges"] = [{"CidrIpv6": "::/0"}]
    acl = next(c for c in network if c["type"] == "network_acl")
    for entry in acl["items"][0]["Entries"]:
        entry["Ipv6CidrBlock"] = "::/0"
    assert one(aws(*network, ipv6_instance, eni_detail), "instance")["status"] == "PASS"
    table = next(c for c in network if c["type"] == "route_table")
    table["items"][0]["Routes"].append({"DestinationIpv6CidrBlock": "::/0", "GatewayId": "igw-1", "State": "active"})
    result = one(aws(*network, ipv6_instance, eni_detail), "instance")
    assert result["status"] == "FAIL"
    assert result["evidence"]["exposed_ports"] == ["tcp/22"]
    eni_detail["items"][0]["DenyAllIgwTraffic"] = True
    assert not exposure(aws(*network, ipv6_instance, eni_detail))
    eni_detail["items"][0].pop("DenyAllIgwTraffic")
    missing = one(aws(*network, ipv6_instance, eni_detail), "instance")
    assert missing["status"] == "UNKNOWN"
    assert "ec2:DescribeNetworkInterfaces" in missing["evidence"]["collector_facts_needed"]


def test_aws_standalone_eni_ipv6_igw_denial_blocks_public_path():
    network = with_ipv6_subnet(aws_network(sg_rules=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                                            "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}], nacl_entries=[
        {"RuleNumber": 100, "Egress": False, "Protocol": "-1", "RuleAction": "allow", "Ipv6CidrBlock": "::/0"},
        {"RuleNumber": 100, "Egress": True, "Protocol": "-1", "RuleAction": "allow", "Ipv6CidrBlock": "::/0"}]))
    next(c for c in network if c["type"] == "route_table")["items"][0]["Routes"].append(
        {"DestinationIpv6CidrBlock": "::/0", "GatewayId": "igw-1", "State": "active"})
    eni = coll("network_interface", [{"NetworkInterfaceId": "eni-1", "SubnetId": "subnet-1", "VpcId": "vpc-1",
                                      "Groups": [{"GroupId": "sg-1"}], "Ipv6Addresses": [{"Ipv6Address": "2600:1f18:abcd::1"}],
                                      "DenyAllIgwTraffic": True}])
    assert not exposure(aws(*network, eni))
    eni["items"][0]["DenyAllIgwTraffic"] = False
    assert one(aws(*network, eni), "network_interface")["status"] == "FAIL"


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


def test_aws_service_managed_addresses_and_interfaces_are_not_standalone_ec2_paths():
    service_eip = coll("elastic_ip", [{"AllocationId": "eipalloc-1", "AssociationId": "eipassoc-1",
                                      "NetworkInterfaceId": "eni-1", "PublicIp": "54.1.2.3",
                                      "ServiceManaged": "alb"}])
    assert not exposure(aws(*aws_network(), instance(public=False), service_eip))
    eni = {"NetworkInterfaceId": "eni-2", "SubnetId": "subnet-1", "VpcId": "vpc-1",
           "Association": {"PublicIp": "54.1.2.4"}, "Groups": [{"GroupId": "sg-1"}]}
    def assessed():
        return exposure(aws(*aws_network(), coll("network_interface", [eni])))
    assert any(finding["resource_id"] for finding in assessed())
    for field, value in (("InterfaceType", "lambda"), ("RequesterManaged", True),
                         ("Operator", {"Managed": True, "Principal": "amazonaws.com"})):
        eni[field] = value
        assert not assessed()
        del eni[field]


def test_aws_public_instance_requires_observed_lifecycle_state():
    item = instance()["items"][0]
    def finding():
        return one(aws(*aws_network(), coll("instance", [item])), "instance")
    assert finding()["status"] == "FAIL"
    item.pop("State")
    missing = finding()
    assert missing["status"] == "UNKNOWN"
    assert "ec2:DescribeInstances.State.Name" in missing["evidence"]["collector_facts_needed"]
    item["State"] = {"Name": "unknown-future-state"}
    assert finding()["status"] == "UNKNOWN"
    item["State"] = {"Name": "stopped"}
    assert finding()["status"] == "FAIL"


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


def test_aws_elbv2_observed_state_gates_current_listener_path():
    lb = {"LoadBalancerArn": f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:loadbalancer/app/web/1",
          "Scheme": "internet-facing", "Type": "application", "DNSName": "web.example.com", "VpcId": "vpc-1",
          "SecurityGroups": ["sg-1"], "AvailabilityZones": [{"SubnetId": "subnet-1"}],
          "Listeners": {"collection_status": "collected", "items": [{"Port": 443, "Protocol": "HTTPS"}]}}
    sg = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
           "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    def finding(state):
        row = dict(lb)
        if state is not None:
            row["State"] = {"Code": state}
        collection = coll("load_balancer", [row], service="elbv2")
        if state is None:
            del collection["items"][0]["State"]
        return one(aws(*aws_network(sg_rules=sg), collection), "load_balancer")
    assert finding("active")["status"] == "FAIL"
    impaired = finding("active_impaired")
    assert impaired["status"] == "FAIL"
    assert any("impaired scaling" in note for note in impaired["evidence"]["notes"])
    assert finding("failed")["status"] == "PASS"
    for state in (None, "provisioning"):
        unknown = finding(state)
        assert unknown["status"] == "UNKNOWN"
        assert "elbv2:DescribeLoadBalancers.State.Code" in unknown["evidence"]["collector_facts_needed"]


def test_aws_load_balancer_public_host_is_observed():
    lb = {"LoadBalancerArn": f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:loadbalancer/app/web/1",
          "Scheme": "internet-facing", "Type": "application", "VpcId": "vpc-1", "SecurityGroups": ["sg-1"],
          "AvailabilityZones": [{"SubnetId": "subnet-1"}],
          "Listeners": {"collection_status": "collected", "items": [{"Port": 443, "Protocol": "HTTPS"}]}}
    sg = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
           "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    def finding(kind, row, service):
        return one(aws(*aws_network(sg_rules=sg), coll(kind, [row], service=service)), kind)
    unknown = finding("load_balancer", lb, "elbv2")
    assert unknown["status"] == "UNKNOWN"
    assert "elbv2:DescribeLoadBalancers.DNSName" in unknown["evidence"]["collector_facts_needed"]
    lb["DNSName"] = "web.example.com"
    assert finding("load_balancer", lb, "elbv2")["status"] == "FAIL"
    lb.pop("DNSName")
    lb["Type"] = "network"
    lb["Listeners"]["items"][0]["Protocol"] = "TLS"
    lb["AvailabilityZones"][0]["LoadBalancerAddresses"] = [{"IpAddress": "54.1.2.3"}]
    nlb = finding("load_balancer", lb, "elbv2")
    assert nlb["status"] == "FAIL" and "54.1.2.3" in nlb["evidence"]["public_addresses"]
    classic = {"LoadBalancerName": "web", "Scheme": "internet-facing", "VPCId": "vpc-1",
               "Subnets": ["subnet-1"], "SecurityGroups": ["sg-1"],
               "ListenerDescriptions": [{"Listener": {"LoadBalancerPort": 443, "Protocol": "HTTPS"}}]}
    unknown_classic = finding("classic_load_balancer", classic, "elb")
    assert unknown_classic["status"] == "UNKNOWN"
    assert "elasticloadbalancing:DescribeLoadBalancers.DNSName" in unknown_classic["evidence"]["collector_facts_needed"]
    classic["DNSName"] = "classic.example.com"
    assert finding("classic_load_balancer", classic, "elb")["status"] == "FAIL"


def test_aws_alb_address_family_uses_observed_ip_address_type():
    lb = {"LoadBalancerArn": f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:loadbalancer/app/web/1",
          "Scheme": "internet-facing", "Type": "application", "DNSName": "web.example.com",
          "VpcId": "vpc-1", "SecurityGroups": ["sg-1"], "AvailabilityZones": [{"SubnetId": "subnet-1"}],
          "Listeners": {"collection_status": "collected", "items": [{"Port": 443, "Protocol": "HTTPS"}]}}
    ipv4_sg = {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
               "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    ipv6_sg = {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
               "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}
    ipv6_acl = [
        {"RuleNumber": 100, "Egress": False, "Protocol": "-1", "RuleAction": "allow", "Ipv6CidrBlock": "::/0"},
        {"RuleNumber": 100, "Egress": True, "Protocol": "-1", "RuleAction": "allow", "Ipv6CidrBlock": "::/0"},
    ]
    def finding(rules, nacl):
        return one(aws(*aws_network(sg_rules=rules, nacl_entries=nacl),
                       coll("load_balancer", [lb], service="elbv2")), "load_balancer")
    lb["IpAddressType"] = "dualstack-without-public-ipv4"
    assert finding([ipv4_sg], ipv6_acl)["status"] == "PASS"
    assert finding([ipv4_sg, ipv6_sg], ipv6_acl)["status"] == "FAIL"
    lb["IpAddressType"] = "dualstack"
    assert finding([ipv6_sg], ipv6_acl)["status"] == "FAIL"
    lb["IpAddressType"] = "ipv4"
    assert finding([ipv6_sg], ipv6_acl)["status"] == "PASS"
    lb.pop("IpAddressType")
    collection = coll("load_balancer", [lb], service="elbv2")
    del collection["items"][0]["IpAddressType"]
    unknown = one(aws(*aws_network(sg_rules=[ipv4_sg], nacl_entries=ipv6_acl), collection), "load_balancer")
    assert unknown["status"] == "UNKNOWN"
    assert "elbv2:DescribeLoadBalancers.IpAddressType" in unknown["evidence"]["collector_facts_needed"]


@pytest.mark.parametrize("kind,valid,invalid", [("application", "HTTPS", "TCP"), ("network", "TCP", "GENEVE")])
def test_aws_elbv2_malformed_listener_is_not_collected_empty(kind, valid, invalid):
    lb = {"LoadBalancerArn": f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:loadbalancer/{'app' if kind == 'application' else 'net'}/web/1",
          "Scheme": "internet-facing", "Type": kind, "DNSName": "web.example.com", "VpcId": "vpc-1",
          "SecurityGroups": ["sg-1"], "AvailabilityZones": [{"SubnetId": "subnet-1"}],
          "Listeners": {"collection_status": "collected", "items": [{"Port": 443, "Protocol": valid}]}}
    sg = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    def finding():
        return one(aws(*aws_network(sg_rules=sg), coll("load_balancer", [lb], service="elbv2")), "load_balancer")
    assert finding()["status"] == "FAIL"
    lb["Listeners"]["items"] = []
    assert finding()["status"] == "PASS"
    lb["Listeners"]["items"] = [{"Port": 0, "Protocol": valid}]
    assert finding()["status"] == "UNKNOWN"
    lb["Listeners"]["items"] = [{"Port": 443, "Protocol": invalid}]
    assert finding()["status"] == "UNKNOWN"
    lb["Listeners"]["items"] = [{"Port": 443, "Protocol": valid}, {"Port": 0, "Protocol": valid}]
    assert finding()["status"] == "FAIL"


def test_aws_load_balancer_narrow_public_sg_and_world_nacl():
    narrow = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
               "IpRanges": [{"CidrIp": "8.8.8.8/32"}]}]
    lb = {"LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/web/1",
          "Scheme": "internet-facing", "Type": "application", "DNSName": "web.example.com", "VpcId": "vpc-1",
          "SecurityGroups": ["sg-1"], "AvailabilityZones": [{"SubnetId": "subnet-1"}],
          "Listeners": {"collection_status": "collected", "items": [{"Port": 443, "Protocol": "HTTPS"}]}}
    result = one(aws(*aws_network(sg_rules=narrow), coll("load_balancer", [lb], service="elbv2")), "load_balancer")
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/443"]
    classic = {"LoadBalancerName": "web", "Scheme": "internet-facing", "DNSName": "classic.example.com",
               "VPCId": "vpc-1", "Subnets": ["subnet-1"], "SecurityGroups": ["sg-1"],
               "ListenerDescriptions": [{"Listener": {"LoadBalancerPort": 443, "Protocol": "HTTPS"}}]}
    assert one(aws(*aws_network(sg_rules=narrow), coll("classic_load_balancer", [classic], service="elb")),
               "classic_load_balancer")["status"] == "FAIL"
    private = [{**narrow[0], "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]
    assert one(aws(*aws_network(sg_rules=private), coll("load_balancer", [lb], service="elbv2")), "load_balancer")["status"] == "PASS"


def test_aws_classic_listener_missing_differs_from_collected_empty():
    classic = {"LoadBalancerName": "web", "Scheme": "internet-facing", "DNSName": "classic.example.com",
               "VPCId": "vpc-1", "Subnets": ["subnet-1"], "SecurityGroups": ["sg-1"]}
    def finding():
        return one(aws(*aws_network(), coll("classic_load_balancer", [classic], service="elb")), "classic_load_balancer")
    missing = finding()
    assert missing["status"] == "UNKNOWN"
    assert "elasticloadbalancing:DescribeLoadBalancers" in missing["evidence"]["collector_facts_needed"]
    classic["ListenerDescriptions"] = []
    assert finding()["status"] == "PASS"
    classic["ListenerDescriptions"] = [{"Listener": {"LoadBalancerPort": 0, "Protocol": "HTTP"}}]
    assert finding()["status"] == "UNKNOWN"
    classic["ListenerDescriptions"] = [{"Listener": {"LoadBalancerPort": 22, "Protocol": "TCP"}}]
    assert finding()["status"] == "FAIL"


def test_aws_alb_exact_public_nacl_host_witness_requires_same_source_and_world_sg():
    lb = {"LoadBalancerArn": f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:loadbalancer/app/host/1",
          "Scheme": "internet-facing", "Type": "application", "DNSName": "host.example.com", "VpcId": "vpc-1",
          "SecurityGroups": ["sg-1"], "AvailabilityZones": [{"SubnetId": "subnet-1"}],
          "Listeners": {"collection_status": "collected", "items": [{"Port": 443, "Protocol": "HTTPS"}]}}
    world_sg = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                 "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    host_acl = [
        {"RuleNumber": 100, "Egress": False, "Protocol": "6", "RuleAction": "allow",
         "CidrBlock": "8.8.8.8/32", "PortRange": {"From": 443, "To": 443}},
        {"RuleNumber": 100, "Egress": True, "Protocol": "6", "RuleAction": "allow",
         "CidrBlock": "8.8.8.8/32", "PortRange": {"From": 1024, "To": 65535}},
    ]
    def finding(rules=world_sg, entries=host_acl):
        return one(aws(*aws_network(sg_rules=rules, nacl_entries=entries),
                       coll("load_balancer", [lb], service="elbv2")), "load_balancer")
    result = finding()
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/443"]
    witness = next(step for step in result["evidence"]["path"] if step["layer"] == "network_acl_host")
    assert witness["public_host_witnesses"] == [{"source_ip": "8.8.8.8", "ports": ["tcp/443"]}]
    mismatched_return = copy.deepcopy(host_acl)
    mismatched_return[1]["CidrBlock"] = "9.9.9.9/32"
    assert finding(entries=mismatched_return)["status"] == "PASS"
    denied_first = copy.deepcopy(host_acl)
    denied_first.insert(0, {**host_acl[0], "RuleNumber": 50, "RuleAction": "deny"})
    assert finding(entries=denied_first)["status"] == "PASS"
    narrow_sg = [{**world_sg[0], "IpRanges": [{"CidrIp": "9.9.9.9/32"}]}]
    assert finding(rules=narrow_sg)["status"] == "PASS"


@pytest.mark.parametrize("kind,with_sg", [("network", True), ("network", False), ("classic", True)])
def test_aws_nlb_and_classic_exact_public_nacl_host_witness(kind, with_sg):
    world_sg = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                 "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    entries = [
        {"RuleNumber": 100, "Egress": False, "Protocol": "6", "RuleAction": "allow",
         "CidrBlock": "8.8.8.8/32", "PortRange": {"From": 443, "To": 443}},
        {"RuleNumber": 100, "Egress": True, "Protocol": "6", "RuleAction": "allow",
         "CidrBlock": "8.8.8.8/32", "PortRange": {"From": 1024, "To": 65535}},
    ]
    if kind == "classic":
        lb = {"LoadBalancerName": "host", "Scheme": "internet-facing", "DNSName": "classic.example.com",
              "VPCId": "vpc-1", "Subnets": ["subnet-1"], "SecurityGroups": ["sg-1"],
              "ListenerDescriptions": [{"Listener": {"LoadBalancerPort": 443, "Protocol": "HTTPS"}}]}
        resource_kind, service = "classic_load_balancer", "elb"
    else:
        lb = {"LoadBalancerArn": f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:loadbalancer/net/host/1",
              "Scheme": "internet-facing", "Type": "network", "DNSName": "nlb.example.com", "VpcId": "vpc-1",
              "SecurityGroups": ["sg-1"] if with_sg else [],
              "AvailabilityZones": [{"SubnetId": "subnet-1"}],
              "Listeners": {"collection_status": "collected", "items": [{"Port": 443, "Protocol": "TCP"}]}}
        resource_kind, service = "load_balancer", "elbv2"
    def finding(acl_entries):
        return one(aws(*aws_network(sg_rules=world_sg, nacl_entries=acl_entries),
                       coll(resource_kind, [lb], service=service)), resource_kind)
    allowed = finding(entries)
    assert allowed["status"] == "FAIL" and allowed["evidence"]["exposed_ports"] == ["tcp/443"]
    witness = next(step for step in allowed["evidence"]["path"] if step["layer"] == "network_acl_host")
    assert witness["public_host_witnesses"] == [{"source_ip": "8.8.8.8", "ports": ["tcp/443"]}]
    mismatched = copy.deepcopy(entries)
    mismatched[1]["CidrBlock"] = "9.9.9.9/32"
    assert finding(mismatched)["status"] == "PASS"


def test_aws_nlb_exact_ipv6_nacl_host_witness():
    lb = {"LoadBalancerArn": f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:loadbalancer/net/v6host/1",
          "Scheme": "internet-facing", "Type": "network", "IpAddressType": "dualstack",
          "DNSName": "v6host.example.com", "VpcId": "vpc-1", "SecurityGroups": ["sg-1"],
          "AvailabilityZones": [{"SubnetId": "subnet-1", "LoadBalancerAddresses": [
              {"IPv6Address": "2600:1f18:abcd::1"}]}],
          "Listeners": {"collection_status": "collected", "items": [{"Port": 443, "Protocol": "TCP"}]}}
    sg = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
           "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]
    entries = [
        {"RuleNumber": 100, "Egress": False, "Protocol": "6", "RuleAction": "allow",
         "Ipv6CidrBlock": "2600:1f18:abcd::2/128", "PortRange": {"From": 443, "To": 443}},
        {"RuleNumber": 100, "Egress": True, "Protocol": "6", "RuleAction": "allow",
         "Ipv6CidrBlock": "2600:1f18:abcd::2/128", "PortRange": {"From": 1024, "To": 65535}},
    ]
    def finding(acl_entries):
        return one(aws(*aws_network(sg_rules=sg, nacl_entries=acl_entries),
                       coll("load_balancer", [lb], service="elbv2")), "load_balancer")
    result = finding(entries)
    assert result["status"] == "FAIL"
    witness = next(step for step in result["evidence"]["path"] if step["layer"] == "network_acl_host")
    assert witness["public_host_witnesses"] == [{"source_ip": "2600:1f18:abcd::2", "ports": ["tcp/443"]}]
    mismatched = copy.deepcopy(entries)
    mismatched[1]["Ipv6CidrBlock"] = "2600:1f18:abcd::3/128"
    assert finding(mismatched)["status"] == "PASS"


@pytest.mark.parametrize("lb_type", ["application", "network"])
def test_aws_load_balancer_intersecting_public_sg_and_nacl_cidrs(lb_type):
    lb = {"LoadBalancerArn": f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:loadbalancer/{'app' if lb_type == 'application' else 'net'}/cidr/1",
          "Scheme": "internet-facing", "Type": lb_type, "DNSName": "cidr.example.com", "VpcId": "vpc-1",
          "SecurityGroups": ["sg-1"], "AvailabilityZones": [{"SubnetId": "subnet-1"}],
          "Listeners": {"collection_status": "collected", "items": [{"Port": 443, "Protocol": "HTTPS" if lb_type == "application" else "TCP"}]}}
    acl = [
        {"RuleNumber": 50, "Egress": False, "Protocol": "6", "RuleAction": "deny",
         "CidrBlock": "8.8.8.0/25", "PortRange": {"From": 443, "To": 443}},
        {"RuleNumber": 100, "Egress": False, "Protocol": "6", "RuleAction": "allow",
         "CidrBlock": "8.8.8.0/24", "PortRange": {"From": 443, "To": 443}},
        {"RuleNumber": 100, "Egress": True, "Protocol": "6", "RuleAction": "allow",
         "CidrBlock": "8.8.8.128/25", "PortRange": {"From": 1024, "To": 65535}},
    ]
    def finding(source, entries=acl):
        sg = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
               "IpRanges": [{"CidrIp": source}]}]
        return one(aws(*aws_network(sg_rules=sg, nacl_entries=entries),
                       coll("load_balancer", [lb], service="elbv2")), "load_balancer")
    admitted = finding("8.8.8.128/25")
    assert admitted["status"] == "FAIL"
    witness = next(step for step in admitted["evidence"]["path"] if step["layer"] == "network_acl_host")
    assert any(ipaddress.ip_address(row["source_ip"]) in ipaddress.ip_network("8.8.8.128/25")
               and row["ports"] == ["tcp/443"] for row in witness["public_host_witnesses"])
    assert finding("8.8.8.140/32")["status"] == "FAIL"
    edge_denies = [
        {"RuleNumber": 40 + index, "Egress": False, "Protocol": "6", "RuleAction": "deny",
         "CidrBlock": f"8.8.8.{host}/32", "PortRange": {"From": 443, "To": 443}}
        for index, host in enumerate((128, 129, 254, 255))]
    interior = finding("8.8.8.128/25", edge_denies + acl)
    assert interior["status"] == "FAIL"
    interior_witness = next(step for step in interior["evidence"]["path"]
                            if step["layer"] == "network_acl_host")
    assert any(130 <= int(ipaddress.ip_address(row["source_ip"])) % 256 <= 253
               for row in interior_witness["public_host_witnesses"])
    assert finding("8.8.8.64/32")["status"] == "PASS"
    assert finding("9.9.9.0/24")["status"] == "PASS"
    no_return = [dict(entry) for entry in acl]
    no_return[2] = {**no_return[2], "CidrBlock": "9.9.9.0/24"}
    assert finding("8.8.8.128/25", no_return)["status"] == "PASS"


def test_aws_nlb_static_public_ipv4_is_in_listener_evidence():
    lb = {"LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/net/web/1",
          "Scheme": "internet-facing", "Type": "network", "DNSName": "nlb.example.com", "VpcId": "vpc-1",
          "AvailabilityZones": [{"SubnetId": "subnet-1", "LoadBalancerAddresses": [
              {"IpAddress": "54.1.2.3", "AllocationId": "eipalloc-1"}, {"IpAddress": "10.0.1.3"}]}],
          "Listeners": {"collection_status": "collected", "items": [{"Port": 443, "Protocol": "TCP"}]}}
    result = one(aws(*aws_network(), coll("load_balancer", [lb], service="elbv2")), "load_balancer")
    assert result["status"] == "FAIL"
    assert result["evidence"]["public_addresses"] == ["54.1.2.3", "nlb.example.com"]
    assert next(s for s in result["evidence"]["path"] if s["layer"] == "public_address")["static_ipv4"] == [
        {"ip": "54.1.2.3", "allocation_id": "eipalloc-1"}]


def test_aws_nlb_static_ipv6_uses_ipv6_sg_and_nacl_path():
    lb = {"LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/net/v6/1",
          "Scheme": "internet-facing", "Type": "network", "IpAddressType": "dualstack", "DNSName": "v6.example.com", "VpcId": "vpc-1",
          "SecurityGroups": ["sg-1"], "AvailabilityZones": [{"SubnetId": "subnet-1", "LoadBalancerAddresses": [
              {"IPv6Address": "2600:1f18:abcd::1"}, {"IPv6Address": "fd00::1"}]}],
          "Listeners": {"collection_status": "collected", "items": [{"Port": 443, "Protocol": "TCP"}]}}
    sg = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
           "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]
    nacl = [{"RuleNumber": 100, "Egress": direction, "Protocol": "-1", "RuleAction": "allow",
             "Ipv6CidrBlock": "::/0"} for direction in (False, True)]
    def finding(rules=sg, entries=nacl):
        return one(aws(*aws_network(sg_rules=rules, nacl_entries=entries),
                       coll("load_balancer", [lb], service="elbv2")), "load_balancer")
    result = finding()
    assert result["status"] == "FAIL"
    assert result["evidence"]["public_addresses"] == ["2600:1f18:abcd::1", "v6.example.com"]
    assert next(s for s in result["evidence"]["path"] if s["layer"] == "public_address")["static_ipv6"] == [
        "2600:1f18:abcd::1"]
    assert finding(entries=[])["status"] == "PASS"
    assert finding(rules=[])["status"] == "PASS"


def test_aws_nlb_quic_and_tcp_quic_listener_transport_matches_sg():
    lb = {"LoadBalancerArn": f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:loadbalancer/net/quic/1",
          "Scheme": "internet-facing", "Type": "network", "DNSName": "quic.example.com", "VpcId": "vpc-1",
          "SecurityGroups": ["sg-1"], "AvailabilityZones": [{"SubnetId": "subnet-1"}],
          "Listeners": {"collection_status": "collected", "items": [{"Port": 443, "Protocol": "QUIC"}]}}
    udp = {"IpProtocol": "udp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    tcp = {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    def finding(rules):
        return one(aws(*aws_network(sg_rules=rules), coll("load_balancer", [lb], service="elbv2")), "load_balancer")
    quic = finding([udp])
    assert quic["status"] == "FAIL" and quic["evidence"]["exposed_ports"] == ["udp/443"]
    assert finding([tcp])["status"] == "PASS"
    lb["Listeners"]["items"][0]["Protocol"] = "TCP_QUIC"
    both = finding([tcp, udp])
    assert both["status"] == "FAIL" and both["evidence"]["exposed_ports"] == ["tcp/443", "udp/443"]


def test_aws_public_rds_instance():
    db = {"DBInstanceArn": "arn:aws:rds:us-east-1:111122223333:db:prod", "PubliclyAccessible": True, "Engine": "postgres", "Endpoint": {"Address": "prod.x.rds.amazonaws.com", "Port": 5432},
          "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-1", "Status": "active"}], "DBSubnetGroup": {"VpcId": "vpc-1", "Subnets": [{"SubnetIdentifier": "subnet-1"}]}}
    rules = [{"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    result = one(aws(*aws_network(sg_rules=rules), coll("rds_instance", [db], service="rds")), "rds_instance")
    assert result["status"] == "FAIL" and result["severity"] == "critical" and result["evidence"]["exposed_ports"] == ["tcp/5432"]
    half_internet = [{**rules[0], "IpRanges": [{"CidrIp": "0.0.0.0/1"}]}]
    assert one(aws(*aws_network(sg_rules=half_internet), coll("rds_instance", [db], service="rds")), "rds_instance")["status"] == "FAIL"
    assert one(aws(*aws_network(), coll("rds_instance", [db], service="rds")), "rds_instance")["status"] == "PASS"
    db["DBInstanceStatus"] = "stopped"
    dormant = one(aws(*aws_network(sg_rules=rules), coll("rds_instance", [db], service="rds")), "rds_instance")
    assert dormant["status"] == "FAIL" and dormant["severity"] == "high"
    assert "DB instance is stopped" in dormant["evidence"]["observed"]
    del db["Endpoint"]["Address"]
    missing_host = one(aws(*aws_network(sg_rules=rules), coll("rds_instance", [db], service="rds")), "rds_instance")
    assert missing_host["status"] == "UNKNOWN" and missing_host["evidence"]["public_addresses"] == []


@pytest.mark.parametrize("port", [None, 0, 65536, True, "5432"])
def test_aws_rds_endpoint_needs_observed_valid_listener_port(port):
    db = {"DBInstanceIdentifier": "db-1", "PubliclyAccessible": True, "DbInstancePort": 5432,
          "Endpoint": {"Address": "db.example.com"}, "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-1", "Status": "active"}],
          "DBSubnetGroup": {"VpcId": "vpc-1", "Subnets": [{"SubnetIdentifier": "subnet-1"}]}}
    if port is not None:
        db["Endpoint"]["Port"] = port
    sg = [{"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
           "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    unknown = one(aws(*aws_network(sg_rules=sg), coll("rds_instance", [db], service="rds")), "rds_instance")
    assert unknown["status"] == "UNKNOWN"
    assert "rds:DescribeDBInstances.Endpoint.Port" in unknown["evidence"]["collector_facts_needed"]
    db["Endpoint"]["Port"] = 5432
    assert one(aws(*aws_network(sg_rules=sg), coll("rds_instance", [db], service="rds")), "rds_instance")["status"] == "FAIL"


@pytest.mark.parametrize("kind,service,fact", [
    ("rds_instance", "rds", "rds:DescribeDBInstances.PubliclyAccessible"),
    ("redshift_cluster", "redshift", "redshift:DescribeClusters.PubliclyAccessible"),
])
def test_aws_database_missing_public_flag_is_unresolved(kind, service, fact):
    row = {"DBInstanceIdentifier": "db-1"} if kind == "rds_instance" else {"ClusterIdentifier": "cluster-1"}
    finding = one(aws(coll(kind, [row], service=service)), kind)
    assert finding["status"] == "UNKNOWN"
    assert fact in finding["evidence"]["collector_facts_needed"]
    row["PubliclyAccessible"] = False
    assert not exposure(aws(coll(kind, [row], service=service)))


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
    cluster["ClusterStatus"] = "paused"
    dormant = row(aws_network(sg_rules=rules))
    assert dormant["status"] == "FAIL" and dormant["severity"] == "medium"
    assert "Redshift cluster is paused" in dormant["evidence"]["observed"]
    assert row(aws_network(sg_rules=rules, igw=False))["status"] == "PASS"
    assert row(aws_network(sg_rules=rules), include_group=False)["status"] == "UNKNOWN"
    del cluster["Endpoint"]["Port"]
    unresolved = row(aws_network(sg_rules=rules))
    assert unresolved["status"] == "UNKNOWN" and unresolved["evidence"]["exposed_ports"] == []
    assert any(gap["layer"] == "listener" for gap in unresolved["evidence"]["unresolved"])
    cluster["Endpoint"]["Port"] = 5439
    del cluster["Endpoint"]["Address"]
    missing_host = row(aws_network(sg_rules=rules))
    assert missing_host["status"] == "UNKNOWN" and missing_host["evidence"]["public_addresses"] == []


@pytest.mark.parametrize("kind,port", [("rds_instance", 5432), ("redshift_cluster", 5439)])
def test_aws_public_database_narrow_sg_nacl_same_source_witness(kind, port):
    sg = [{"IpProtocol": "tcp", "FromPort": port, "ToPort": port,
           "IpRanges": [{"CidrIp": "8.8.8.8/32"}]}]
    def row(return_source):
        acl = [{"RuleNumber": 100, "Egress": False, "Protocol": "6", "RuleAction": "allow",
                "CidrBlock": "8.8.8.8/32", "PortRange": {"From": port, "To": port}},
               {"RuleNumber": 100, "Egress": True, "Protocol": "6", "RuleAction": "allow",
                "CidrBlock": return_source, "PortRange": {"From": 1024, "To": 65535}}]
        if kind == "rds_instance":
            db = {"DBInstanceArn": f"arn:aws:rds:us-east-1:{ACCOUNT}:db:narrow", "PubliclyAccessible": True,
                  "Endpoint": {"Address": "narrow.rds.amazonaws.com", "Port": port},
                  "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-1", "Status": "active"}],
                  "DBSubnetGroup": {"VpcId": "vpc-1", "Subnets": [{"SubnetIdentifier": "subnet-1"}]}}
            extra = [coll(kind, [db], service="rds")]
        else:
            db = {"ClusterIdentifier": "narrow", "PubliclyAccessible": True,
                  "Endpoint": {"Address": "narrow.redshift.amazonaws.com", "Port": port},
                  "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-1"}], "ClusterSubnetGroupName": "g"}
            extra = [coll(kind, [db], service="redshift"), coll("redshift_subnet_group", [
                {"ClusterSubnetGroupName": "g", "VpcId": "vpc-1", "Subnets": [{"SubnetIdentifier": "subnet-1"}]}], service="redshift")]
        return one(aws(*aws_network(sg_rules=sg, nacl_entries=acl), *extra), kind)
    admitted = row("8.8.8.8/32")
    assert admitted["status"] == "FAIL" and admitted["evidence"]["exposed_ports"] == [f"tcp/{port}"]
    assert any(step["layer"] == "network_acl_host" and step["public_host_witnesses"][0]["source_ip"] == "8.8.8.8"
               for step in admitted["evidence"]["path"])
    assert row("1.1.1.1/32")["status"] == "PASS"


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


def test_describe_images_public_flag_survives_missing_permission_detail_and_new_share_block():
    from peaso.finding_observation import evidence_summary
    image = {"ImageId": "ami-1", "OwnerId": ACCOUNT, "Public": True, "State": "available",
             "_coverage": {"LaunchPermissions": {"status": "denied"}}}
    settings = coll("ec2_regional_settings", [{"ImageBlockPublicAccessState": "block-new-sharing"}])
    found = one(aws(coll("ec2_image", [image]), settings), "ec2_image")
    assert found["status"] == "FAIL" and found["evidence"]["data_exposure"] is True
    assert found["evidence"]["path"][0]["layer"] == "image_public_flag"
    assert found["evidence"]["unresolved"][0]["layer"] == "attributes"
    assert "public launch permission" in evidence_summary(found)
    assert "public AMI launch permission" in found["remediation"]
    assert one(aws(coll("ec2_image", [{**image, "Public": False}]), settings), "ec2_image")["status"] == "UNKNOWN"
    assert one(aws(coll("ec2_image", [{**image, "OwnerId": "999988887777"}]), settings), "ec2_image")["status"] == "UNKNOWN"


def test_ami_organization_and_ou_launch_permissions_join_account_organization():
    from peaso.finding_observation import evidence_summary
    from peaso.analysis.catalog import REQUIRED_TYPES

    assert "aws_account_configuration" in REQUIRED_TYPES["aws"]["exposure"]

    org = "o-ours123456"
    config = coll("aws_account_configuration", [{"id": "account-configuration", "Organization": {
        "collection_status": "collected", "OrganizationId": org, "MasterAccountId": ACCOUNT}}])
    base = {"ImageId": "ami-1", "_coverage": {"LaunchPermissions": {"status": "collected",
            "source_operation": "ec2:DescribeImageAttribute"}}}
    foreign_org = "arn:aws:organizations::999988887777:organization/o-foreign1234"
    foreign_ou = "arn:aws:organizations::999988887777:ou/o-foreign1234/ou-1234-abcdef"
    own_org = f"arn:aws:organizations::{ACCOUNT}:organization/{org}"

    def image(permissions, include_config=True):
        return one(aws(coll("ec2_image", [{**base, "LaunchPermissions": permissions}]),
                       *([config] if include_config else [])), "ec2_image")

    for selector, arn in (("OrganizationArn", foreign_org), ("OrganizationalUnitArn", foreign_ou)):
        finding = image([{selector: arn}])
        assert finding["status"] == "FAIL"
        assert finding["evidence"]["external_scope_ids"] == [arn]
        assert "AMI launch access" in evidence_summary(finding)
        assert "AMI launch permission" in finding["remediation"]
        assert image([{selector: arn}], include_config=False)["status"] == "UNKNOWN"
    assert image([{"OrganizationArn": own_org}])["status"] == "PASS"
    wrong_management = f"arn:aws:organizations::999988887777:organization/{org}"
    assert image([{"OrganizationArn": wrong_management}])["status"] == "UNKNOWN"
    assert image([{"OrganizationArn": "not-an-arn"}])["status"] == "UNKNOWN"
    mixed = image([{"Group": "all"}, {"OrganizationArn": "not-an-arn"}])
    assert mixed["status"] == "FAIL" and mixed["evidence"]["data_exposure"] is True


def test_aws_ram_share_requires_active_resource_and_external_principal_associations():
    arn = f"arn:aws:ram:us-east-1:{ACCOUNT}:resource-share/share-1"
    resource_arn = f"arn:aws:ec2:us-east-1:{ACCOUNT}:subnet/subnet-1"

    def part(entities, status="collected"):
        return {"collection_status": status, "resourceShareAssociations": entities}

    def association(entity, status="ASSOCIATED", external=None):
        row = {"associatedEntity": entity, "status": status}
        if external is not None:
            row["external"] = external
        return row

    def result(principals, resources=None, share_status="ACTIVE", principal_status="collected"):
        share = {"resourceShareArn": arn, "status": share_status,
                 "ResourceAssociations": part([association(resource_arn)] if resources is None else resources),
                 "PrincipalAssociations": part(principals, principal_status)}
        return one(aws(coll("ram_resource_share", [share], service="ram")), "ram_resource_share")

    external = result([association("999988887777", external=True)])
    assert external["status"] == "FAIL"
    assert external["evidence"]["external_scope_ids"] == ["999988887777"]
    assert result([association("999988887777", external=True)], resources=[])["status"] == "PASS"
    assert result([association("999988887777", "ASSOCIATING", external=True)])["status"] == "UNKNOWN"
    assert result([association("999988887777", external=True)], principal_status="denied")["status"] == "UNKNOWN"
    assert result([association(ACCOUNT, external=False)])["status"] == "PASS"
    assert result([association("arn:aws:iam::999988887777:role/External")])["status"] == "FAIL"
    assert result([association("arn:aws:organizations::111122223333:organization/o-owned")])["status"] == "UNKNOWN"
    deleted = {"resourceShareArn": arn, "status": "DELETED",
               "ResourceAssociations": part([association(resource_arn)]),
               "PrincipalAssociations": part([association("999988887777", external=True)])}
    assert not exposure(aws(coll("ram_resource_share", [deleted], service="ram")))


def test_aws_cloudfront_enabled_viewer_endpoint_and_missing_config():
    base = {"ARN": "arn:aws:cloudfront::111122223333:distribution/D1", "Id": "D1", "DomainName": "d123.cloudfront.net", "Status": "Deployed"}
    config = {"collection_status": "collected", "DistributionConfig": {"Enabled": True,
              "DefaultCacheBehavior": {"ViewerProtocolPolicy": "redirect-to-https"}}}
    def row(value):
        return one(aws(coll("cloudfront_distribution", [{**base, "Config": value}], service="cloudfront")), "cloudfront_distribution")
    exposed = row(config)
    assert exposed["status"] == "FAIL" and exposed["evidence"]["exposed_ports"] == ["tcp/80", "tcp/443"]
    assert row({"collection_status": "denied"})["status"] == "UNKNOWN"
    assert not exposure(aws(coll("cloudfront_distribution", [{**base, "Config": {**config, "DistributionConfig": {**config["DistributionConfig"], "Enabled": False}}}], service="cloudfront")))
    base["Status"] = "InProgress"
    assert row(config)["status"] == "UNKNOWN"
    base.pop("Status")
    assert row(config)["status"] == "UNKNOWN"


def test_aws_cloudfront_origin_target_join_is_observed_separately_from_viewer():
    config = {"collection_status": "collected", "DistributionConfig": {"Enabled": True,
              "DefaultCacheBehavior": {"ViewerProtocolPolicy": "https-only", "TargetOriginId": "used"},
              "Origins": {"Quantity": 1, "Items": [{"Id": "other", "DomainName": "other.example.com"}]}}}
    distribution = {"ARN": f"arn:aws:cloudfront::{ACCOUNT}:distribution/D1", "Id": "D1",
                    "DomainName": "d123.cloudfront.net", "Status": "Deployed", "Config": config}
    def finding():
        return one(aws(coll("cloudfront_distribution", [distribution], service="cloudfront")),
                   "cloudfront_distribution")
    missing = finding()
    assert missing["status"] == "FAIL"
    assert any("no matching origin" in gap["reason"] for gap in missing["evidence"]["unresolved"])
    origins = config["DistributionConfig"]["Origins"]
    origins["Items"][0]["Id"] = "used"
    assert not [gap for gap in finding()["evidence"]["unresolved"] if gap["layer"] == "origin"]
    origins["Items"].append({"Id": "used", "DomainName": "duplicate.example.com"})
    origins["Quantity"] = 2
    assert any("not unique" in gap["reason"] for gap in finding()["evidence"]["unresolved"])
    origins["Items"].pop()
    assert any("quantity and items disagree" in gap["reason"] for gap in finding()["evidence"]["unresolved"])


def test_aws_cloudfront_staging_distribution_has_no_direct_viewer_host_witness():
    distribution = {"ARN": f"arn:aws:cloudfront::{ACCOUNT}:distribution/STAGING", "Id": "STAGING",
                    "DomainName": "staging.cloudfront.net", "Status": "Deployed", "Staging": True,
                    "Config": {"collection_status": "collected", "DistributionConfig": {"Enabled": True,
                        "Staging": True, "DefaultCacheBehavior": {"ViewerProtocolPolicy": "https-only"}}}}
    result = one(aws(coll("cloudfront_distribution", [distribution], service="cloudfront")), "cloudfront_distribution")
    assert result["status"] == "UNKNOWN" and result["evidence"]["public_addresses"] == []
    assert "cloudfront:GetContinuousDeploymentPolicy" in result["evidence"]["collector_facts_needed"]
    distribution["Staging"] = False
    distribution["Config"]["DistributionConfig"]["Staging"] = False
    assert one(aws(coll("cloudfront_distribution", [distribution], service="cloudfront")), "cloudfront_distribution")["status"] == "FAIL"


def test_aws_cloudfront_signed_viewer_access_is_per_behavior_and_options_exception():
    base = {"ARN": f"arn:aws:cloudfront::{ACCOUNT}:distribution/D1", "Id": "D1",
            "DomainName": "d123.cloudfront.net", "Status": "Deployed"}
    signed = {"ViewerProtocolPolicy": "https-only",
              "AllowedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]},
              "TrustedKeyGroups": {"Enabled": True, "Quantity": 1, "Items": ["key-group-1"]}}
    config = {"collection_status": "collected", "DistributionConfig": {"Enabled": True,
              "DefaultCacheBehavior": signed, "CacheBehaviors": {"Items": []}}}
    def finding():
        return one(aws(coll("cloudfront_distribution", [{**base, "Config": config}], service="cloudfront")),
                   "cloudfront_distribution")
    result = finding()
    assert result["status"] == "FAIL" and result["evidence"]["authenticated_endpoint"] is True
    assert next(step for step in result["evidence"]["path"] if step["layer"] == "viewer_access")["signed_request_paths"] == ["<default>"]
    config["DistributionConfig"]["CacheBehaviors"]["Items"] = [{"PathPattern": "public/*", "ViewerProtocolPolicy": "https-only",
                                                                     "AllowedMethods": {"Items": ["GET", "HEAD"]}}]
    assert finding()["evidence"]["authenticated_endpoint"] is False
    config["DistributionConfig"]["CacheBehaviors"]["Items"] = []
    signed["AllowedMethods"]["Items"].append("OPTIONS")
    assert finding()["evidence"]["authenticated_endpoint"] is False
    signed["AllowedMethods"]["Items"] = ["GET", "HEAD"]
    signed["TrustedKeyGroups"]["Quantity"] = 2
    assert finding()["evidence"]["authenticated_endpoint"] is False


def test_aws_cloudfront_observed_oai_bucket_policy_grant_requires_used_origin_and_exact_principal():
    distribution_arn = f"arn:aws:cloudfront::{ACCOUNT}:distribution/D1"
    oai_arn = "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E123ABC"
    config = {"collection_status": "collected", "DistributionConfig": {"Enabled": True,
              "DefaultCacheBehavior": {"ViewerProtocolPolicy": "https-only", "TargetOriginId": "s3-main"},
              "Origins": {"Items": [{"Id": "s3-main", "DomainName": "private-bucket.s3.us-east-1.amazonaws.com",
                                     "S3OriginConfig": {"OriginAccessIdentity": "origin-access-identity/cloudfront/E123ABC"}}]}}}
    distribution = {"ARN": distribution_arn, "Id": "D1", "DomainName": "d123.cloudfront.net", "Status": "Deployed", "Config": config}
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": oai_arn},
              "Action": "s3:GetObject", "Resource": "arn:aws:s3:::private-bucket/*"}]}
    bucket = {"Name": "private-bucket", "Policy": {"collection_status": "collected", "Policy": policy}}
    def finding():
        return one(aws(coll("cloudfront_distribution", [distribution], service="cloudfront"),
                       coll("bucket", [bucket], service="s3")), "cloudfront_distribution")
    result = finding()
    assert result["status"] == "FAIL"
    grants = [step for step in result["evidence"]["path"] if step["layer"] == "origin_policy"]
    assert len(grants) == 1 and grants[0]["decision"] == "allow_declaration"
    assert grants[0]["bucket"] == "private-bucket" and grants[0]["principal"] == oai_arn
    config["DistributionConfig"]["DefaultCacheBehavior"]["TargetOriginId"] = "other"
    assert not [step for step in finding()["evidence"]["path"] if step["layer"] == "origin_policy"]
    config["DistributionConfig"]["DefaultCacheBehavior"]["TargetOriginId"] = "s3-main"
    policy["Statement"][0]["Principal"]["AWS"] = oai_arn + "-other"
    assert not [step for step in finding()["evidence"]["path"] if step["layer"] == "origin_policy"]
    policy["Statement"][0]["Principal"]["AWS"] = oai_arn
    policy["Statement"].append({"Effect": "Deny", "Principal": "*", "Action": "s3:GetObject",
                                 "Resource": "arn:aws:s3:::private-bucket/*"})
    assert not [step for step in finding()["evidence"]["path"] if step["layer"] == "origin_policy"]


def test_aws_cloudfront_oai_canonical_user_bucket_policy_grant_is_exact():
    canonical = "a" * 64
    config = {"collection_status": "collected", "DistributionConfig": {"Enabled": True,
              "DefaultCacheBehavior": {"ViewerProtocolPolicy": "https-only", "TargetOriginId": "s3-main"},
              "Origins": {"Items": [{"Id": "s3-main", "DomainName": "private-bucket.s3.us-east-1.amazonaws.com",
                                     "S3OriginConfig": {"OriginAccessIdentity": "origin-access-identity/cloudfront/E123ABC"}}]}}}
    distribution = {"ARN": f"arn:aws:cloudfront::{ACCOUNT}:distribution/D1", "Id": "D1",
                    "DomainName": "d123.cloudfront.net", "Status": "Deployed", "Config": config,
                    "OriginAccessIdentities": {"E123ABC": {"collection_status": "collected", "Id": "E123ABC",
                                                         "S3CanonicalUserId": canonical}}}
    policy = {"Statement": [{"Effect": "Allow", "Principal": {"CanonicalUser": canonical},
              "Action": "s3:GetObject", "Resource": "arn:aws:s3:::private-bucket/*"}]}
    bucket = {"Name": "private-bucket", "Policy": {"collection_status": "collected", "Policy": policy}}
    def grants():
        result = one(aws(coll("cloudfront_distribution", [distribution], service="cloudfront"),
                         coll("bucket", [bucket], service="s3")), "cloudfront_distribution")
        return [step for step in result["evidence"]["path"] if step["layer"] == "origin_policy"]
    assert len(grants()) == 1 and grants()[0]["principal"] == canonical
    policy["Statement"][0]["Principal"]["CanonicalUser"] = "b" * 64
    assert not grants()
    policy["Statement"][0]["Principal"]["CanonicalUser"] = canonical
    distribution["OriginAccessIdentities"]["E123ABC"]["collection_status"] = "denied"
    assert not grants()


def test_aws_cloudfront_used_vpc_origin_requires_deployed_exact_detail():
    endpoint = f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:loadbalancer/app/backend/1"
    config = {"collection_status": "collected", "DistributionConfig": {"Enabled": True,
              "DefaultCacheBehavior": {"ViewerProtocolPolicy": "https-only", "TargetOriginId": "private"},
              "Origins": {"Items": [{"Id": "private", "VpcOriginConfig": {"VpcOriginId": "vo-one"}}]}}}
    distribution = {"ARN": f"arn:aws:cloudfront::{ACCOUNT}:distribution/D1", "Id": "D1",
                    "DomainName": "d123.cloudfront.net", "Status": "Deployed", "Config": config}
    vpc = {"Id": "vo-one", "Status": "Deployed", "VpcOrigin": {"Id": "vo-one", "Status": "Deployed",
           "VpcOriginEndpointConfig": {"Arn": endpoint, "HTTPPort": 80, "HTTPSPort": 443,
                                       "OriginProtocolPolicy": "https-only"}}}
    def result():
        return one(aws(coll("cloudfront_distribution", [distribution], service="cloudfront"),
                       coll("cloudfront_vpc_origin", [vpc], service="cloudfront")), "cloudfront_distribution")
    observed = result()
    assert observed["status"] == "FAIL"
    steps = [step for step in observed["evidence"]["path"] if step["layer"] == "origin"]
    assert steps == [{"layer": "origin", "decision": "allow_declaration", "origin_id": "private",
                      "vpc_origin_id": "vo-one", "origin_endpoint_arn": endpoint,
                      "vpc_origin_status": "Deployed", "semantics": steps[0]["semantics"]}]
    vpc["VpcOrigin"]["Id"] = "vo-other"
    mismatched = result()
    assert not [step for step in mismatched["evidence"]["path"] if step["layer"] == "origin"]
    assert any(gap.get("collector_fact") == "cloudfront:GetVpcOrigin" for gap in mismatched["evidence"]["unresolved"])
    vpc["VpcOrigin"]["Id"] = "vo-one"
    vpc["Status"] = "InProgress"
    assert not [step for step in result()["evidence"]["path"] if step["layer"] == "origin"]
    vpc["Status"] = "Deployed"
    config["DistributionConfig"]["DefaultCacheBehavior"]["TargetOriginId"] = "other"
    assert not [step for step in result()["evidence"]["path"] if step["layer"] == "origin"]


def test_aws_cloudfront_oac_requires_observed_signing_and_exact_distribution_policy():
    distribution_arn = f"arn:aws:cloudfront::{ACCOUNT}:distribution/D1"
    config = {"collection_status": "collected", "DistributionConfig": {"Enabled": True,
        "DefaultCacheBehavior": {"ViewerProtocolPolicy": "https-only", "TargetOriginId": "s3-main"},
        "Origins": {"Items": [{"Id": "s3-main", "DomainName": "private-bucket.s3.us-east-1.amazonaws.com",
                               "S3OriginConfig": {"OriginAccessIdentity": ""}, "OriginAccessControlId": "OAC1"}]}}}
    oac = {"collection_status": "collected", "Id": "OAC1", "SigningBehavior": "always",
           "SigningProtocol": "sigv4", "OriginAccessControlOriginType": "s3"}
    distribution = {"ARN": distribution_arn, "Id": "D1", "DomainName": "d123.cloudfront.net", "Status": "Deployed",
                    "Config": config, "OriginAccessControls": {"OAC1": oac}}
    statement = {"Effect": "Allow", "Principal": {"Service": "cloudfront.amazonaws.com"},
                 "Action": "s3:GetObject", "Resource": "arn:aws:s3:::private-bucket/*",
                 "Condition": {"StringEquals": {"AWS:SourceArn": distribution_arn}}}
    bucket = {"Name": "private-bucket", "Policy": {"collection_status": "collected",
              "Policy": {"Version": "2012-10-17", "Statement": [statement]}}}
    def steps():
        result = one(aws(coll("cloudfront_distribution", [distribution], service="cloudfront"),
                         coll("bucket", [bucket], service="s3")), "cloudfront_distribution")
        assert result["status"] == "FAIL"
        return result["evidence"]["path"]
    assert any(step["layer"] == "origin_policy" and step["decision"] == "allow_declaration"
               and step["source_arn"] == distribution_arn for step in steps())
    oac["SigningBehavior"] = "never"
    assert not any(step["layer"] == "origin_policy" for step in steps())
    oac["SigningBehavior"] = "no-override"
    assert any(step["layer"] == "origin_policy" for step in steps())
    oac["SigningBehavior"] = "always"
    statement["Condition"]["StringEquals"]["AWS:SourceArn"] = distribution_arn.replace("D1", "D2")
    assert not any(step["layer"] == "origin_policy" for step in steps())
    statement["Condition"] = {"ArnEquals": {"aws:SourceArn": distribution_arn}}
    assert any(step["layer"] == "origin_policy" for step in steps())
    statement["Condition"]["ArnEquals"]["aws:SourceAccount"] = ACCOUNT
    assert not any(step["layer"] == "origin_policy" for step in steps())
    del statement["Condition"]["ArnEquals"]["aws:SourceAccount"]
    distribution["OriginAccessControls"] = {}
    result = one(aws(coll("cloudfront_distribution", [distribution], service="cloudfront"),
                     coll("bucket", [bucket], service="s3")), "cloudfront_distribution")
    assert any(gap["layer"] == "origin_auth" for gap in result["evidence"]["unresolved"])


def test_aws_cloudfront_lambda_url_oac_requires_exact_host_and_both_policy_actions():
    distribution_arn = f"arn:aws:cloudfront::{ACCOUNT}:distribution/D1"
    function_arn = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:origin"
    host = "abc123.lambda-url.us-east-1.on.aws"
    config = {"collection_status": "collected", "DistributionConfig": {"Enabled": True,
        "DefaultCacheBehavior": {"ViewerProtocolPolicy": "https-only", "TargetOriginId": "lambda"},
        "Origins": {"Items": [{"Id": "lambda", "DomainName": host, "CustomOriginConfig": {},
                               "OriginAccessControlId": "OAC1"}]}}}
    oac = {"collection_status": "collected", "Id": "OAC1", "SigningBehavior": "always",
           "SigningProtocol": "sigv4", "OriginAccessControlOriginType": "lambda"}
    distribution = {"ARN": distribution_arn, "Id": "D1", "DomainName": "d123.cloudfront.net", "Status": "Deployed",
                    "Config": config, "OriginAccessControls": {"OAC1": oac}}
    actions = ("lambda:InvokeFunctionUrl", "lambda:InvokeFunction")
    statements = [{"Effect": "Allow", "Principal": {"Service": "cloudfront.amazonaws.com"},
                   "Action": action, "Resource": function_arn,
                   "Condition": {"ArnLike": {"AWS:SourceArn": distribution_arn}}} for action in actions]
    function = {"FunctionArn": function_arn, "FunctionName": "origin",
                "FunctionUrl": {"collection_status": "collected", "AuthType": "AWS_IAM",
                                "FunctionArn": function_arn, "FunctionUrl": f"https://{host}/"},
                "Policy": {"collection_status": "collected", "Policy": {"Statement": statements}}}
    kind = "lambda_function"
    def grants():
        result = one(aws(coll("cloudfront_distribution", [distribution], service="cloudfront"),
                         coll(kind, [function], service="lambda")), "cloudfront_distribution")
        assert result["status"] == "FAIL"
        return [x for x in result["evidence"]["path"] if x["layer"] == "origin_policy"]
    assert len(grants()) == 1 and grants()[0]["actions"] == ["lambda:invokefunction", "lambda:invokefunctionurl"]
    statements.pop()
    assert not grants()
    statements.append({"Effect": "Allow", "Principal": {"Service": "cloudfront.amazonaws.com"},
                       "Action": actions[1], "Resource": function_arn,
                       "Condition": {"ArnLike": {"AWS:SourceArn": distribution_arn.replace("D1", "D2")}}})
    assert not grants()
    statements[-1]["Condition"]["ArnLike"]["AWS:SourceArn"] = distribution_arn
    function["FunctionUrl"]["FunctionUrl"] = "https://other.lambda-url.us-east-1.on.aws/"
    assert not grants()
    function["FunctionUrl"]["FunctionUrl"] = f"https://{host}/"
    oac["SigningBehavior"] = "never"
    assert not grants()
    oac["SigningBehavior"] = "no-override"
    assert len(grants()) == 1
    oac["SigningBehavior"] = "always"
    alias_arn = function_arn + ":live"
    function["AliasArn"] = alias_arn
    function["FunctionUrl"]["FunctionArn"] = alias_arn
    for statement in statements:
        statement["Resource"] = alias_arn
    kind = "lambda_alias"
    assert len(grants()) == 1 and grants()[0]["function_arn"] == alias_arn


def test_aws_global_accelerator_static_ips_and_public_listener():
    accelerator = {"AcceleratorArn": f"arn:aws:globalaccelerator::{ACCOUNT}:accelerator/a",
                   "Enabled": True, "Status": "DEPLOYED", "IpSets": [
                       {"IpFamily": "IPv4", "IpAddresses": ["8.8.8.8"]},
                       {"IpFamily": "IPv6", "IpAddresses": ["2606:4700:4700::1111"]}]}
    listener = {"ListenerArn": "arn:aws:globalaccelerator::111122223333:accelerator/a/listener/l",
                "AcceleratorArn": accelerator["AcceleratorArn"], "Protocol": "TCP",
                "PortRanges": [{"FromPort": 443, "ToPort": 443}]}
    def snapshot(accelerator_row, listeners=None, listener_status=None):
        return aws(coll("globalaccelerator_accelerator", [accelerator_row], service="globalaccelerator"),
                   coll("globalaccelerator_listener", [listener] if listeners is None else listeners,
                        status=listener_status, service="globalaccelerator"))
    exposed = one(snapshot(accelerator), "globalaccelerator_accelerator")
    assert exposed["status"] == "FAIL"
    assert exposed["evidence"]["public_addresses"] == ["2606:4700:4700::1111", "8.8.8.8"]
    assert exposed["evidence"]["exposed_ports"] == ["tcp/443"]
    assert not exposure(snapshot({**accelerator, "Enabled": False}))
    assert one(snapshot(accelerator, []), "globalaccelerator_accelerator")["status"] == "PASS"
    assert one(snapshot(accelerator, [], "denied"), "globalaccelerator_accelerator")["status"] == "UNKNOWN"
    assert one(snapshot(accelerator, [{**listener, "PortRanges": [{}]}]), "globalaccelerator_accelerator")["status"] == "UNKNOWN"
    assert one(snapshot({**accelerator, "IpSets": [{"IpFamily": "IPv4", "IpAddresses": ["192.0.2.1"]}]}), "globalaccelerator_accelerator")["status"] == "UNKNOWN"


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


def test_lambda_aws_iam_url_reports_exact_external_policy_declaration():
    function = lambda_function(auth="AWS_IAM")
    arn = function["FunctionArn"]
    external = "arn:aws:iam::444455556666:role/client"
    function["Policy"]["Policy"]["Statement"] = [
        {"Effect": "Allow", "Principal": {"AWS": external}, "Action": "lambda:InvokeFunctionUrl", "Resource": arn},
        {"Effect": "Allow", "Principal": {"AWS": external}, "Action": "lambda:InvokeFunction", "Resource": arn}]
    def finding():
        return one(aws(coll("lambda_function", [function], service="lambda")), "lambda_function")
    reported = finding()
    assert reported["status"] == "UNKNOWN" and reported["evidence"]["authenticated_endpoint"] is True
    grants = [step for step in reported["evidence"]["path"] if step["layer"] == "policy"]
    assert len(grants) == 1 and grants[0]["decision"] == "allow_declaration" and grants[0]["principal"] == external
    function["Policy"]["Policy"]["Statement"][0]["Condition"] = {"StringEquals": {"lambda:FunctionUrlAuthType": "AWS_IAM"}}
    function["Policy"]["Policy"]["Statement"][1]["Condition"] = {"Bool": {"lambda:InvokedViaFunctionUrl": "true"}}
    assert finding()["status"] == "UNKNOWN"
    function["Policy"]["Policy"]["Statement"][0]["Condition"]["StringEquals"]["lambda:FunctionUrlAuthType"] = "NONE"
    assert finding()["status"] == "PASS"
    function["Policy"]["Policy"]["Statement"][0]["Condition"]["StringEquals"]["lambda:FunctionUrlAuthType"] = "AWS_IAM"
    function["Policy"]["Policy"]["Statement"][1]["Condition"]["Bool"]["lambda:InvokedViaFunctionUrl"] = "false"
    assert finding()["status"] == "PASS"
    function["Policy"]["Policy"]["Statement"][1]["Condition"]["Bool"]["lambda:InvokedViaFunctionUrl"] = "true"
    function["Policy"]["Policy"]["Statement"][1]["Resource"] = arn + ":other"
    assert finding()["status"] == "PASS"
    function["Policy"]["Policy"]["Statement"][1]["Resource"] = arn
    function["Policy"]["Policy"]["Statement"].append({"Effect": "Deny", "Principal": "*",
                                                         "Action": "lambda:InvokeFunction", "Resource": arn})
    assert finding()["status"] == "PASS"
    function["Policy"] = {"collection_status": "denied"}
    assert finding()["status"] == "UNKNOWN"
    assert "lambda:GetPolicy" in finding()["evidence"]["collector_facts_needed"]


def test_lambda_function_url_requires_both_public_invocation_actions_for_new_urls():
    base = lambda_function()
    policy = base["Policy"]["Policy"]
    only_url = copy.deepcopy(base)
    only_url["Policy"]["Policy"]["Statement"] = policy["Statement"][:1]
    assert one(aws(coll("lambda_function", [only_url], service="lambda")), "lambda_function")["status"] == "PASS"
    legacy = copy.deepcopy(only_url)
    legacy["FunctionUrl"]["CreationTime"] = "2024-01-01T00:00:00Z"
    assert one(aws(coll("lambda_function", [legacy], service="lambda")), "lambda_function")["status"] == "UNKNOWN"
    cutover_month = copy.deepcopy(only_url)
    cutover_month["FunctionUrl"]["CreationTime"] = "2025-10-15T00:00:00Z"
    assert one(aws(coll("lambda_function", [cutover_month], service="lambda")), "lambda_function")["status"] == "UNKNOWN"
    after_cutover = copy.deepcopy(only_url)
    after_cutover["FunctionUrl"]["CreationTime"] = "2025-11-01T00:00:00Z"
    assert one(aws(coll("lambda_function", [after_cutover], service="lambda")), "lambda_function")["status"] == "PASS"
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


def test_lambda_alias_url_uses_qualified_policy_and_keeps_failed_reads_unknown():
    base = lambda_function(auth="AWS_IAM")
    alias_arn = base["FunctionArn"] + ":live"
    alias = {"id": alias_arn, "AliasArn": alias_arn, "FunctionName": "f", "FunctionArn": base["FunctionArn"],
             "Name": "live", "FunctionUrl": {**lambda_function()["FunctionUrl"], "FunctionArn": alias_arn},
             "Policy": {"collection_status": "collected", "Policy": {"Version": "2012-10-17", "Statement": [
                 {"Effect": "Allow", "Principal": "*", "Action": "lambda:InvokeFunctionUrl", "Resource": alias_arn},
                 {"Effect": "Allow", "Principal": "*", "Action": "lambda:InvokeFunction", "Resource": alias_arn}]}}}

    def row(value):
        return one(aws(coll("lambda_function", [base], service="lambda"),
                       coll("lambda_alias", [value], service="lambda")), "lambda_alias")

    assert row(alias)["status"] == "FAIL"
    assert one(aws(coll("lambda_function", [base], service="lambda"),
                   coll("lambda_alias", [alias], service="lambda")), "lambda_function")["status"] == "PASS"
    wrong_arn = copy.deepcopy(alias)
    wrong_arn["Policy"]["Policy"]["Statement"][0]["Resource"] = base["FunctionArn"]
    assert row(wrong_arn)["status"] == "PASS"
    denied = {**alias, "FunctionUrl": {"collection_status": "denied"}}
    assert row(denied)["status"] == "UNKNOWN"
    malformed = {**alias, "FunctionUrl": {"collection_status": "collected", "FunctionUrl": alias["FunctionUrl"]["FunctionUrl"]}}
    assert row(malformed)["status"] == "UNKNOWN"
    foreign_alias = {**alias, "FunctionUrl": {**alias["FunctionUrl"], "FunctionArn": base["FunctionArn"]}}
    assert row(foreign_alias)["status"] == "UNKNOWN"


def test_lambda_direct_invoke_policy_covers_function_and_alias_without_urls():
    base = lambda_function(auth="AWS_IAM")
    arn = base["FunctionArn"]
    alias_arn = arn + ":live"

    def findings(policy_read, target=arn, alias=False):
        resource = {"id": target, "FunctionName": "f", "FunctionArn": arn,
                    "FunctionUrl": {"collection_status": "empty", "absent": True}, "Policy": policy_read}
        if alias:
            resource.update({"AliasArn": target, "Name": "live"})
        kind = "lambda_alias" if alias else "lambda_function"
        return [f for f in exposure(aws(coll(kind, [resource], service="lambda")))
                if f["evidence"].get("exposure_kind") == "external_lambda_invoke"]

    def policy(principal, action="lambda:InvokeFunction", resource=arn, **extra):
        return {"collection_status": "collected", "Policy": {"Statement": [{
            "Effect": "Allow", "Principal": principal, "Action": action, "Resource": resource, **extra}]}}

    external = {"AWS": "arn:aws:iam::444455556666:root"}
    result = findings(policy(external))
    assert len(result) == 1 and result[0]["status"] == "FAIL"
    assert result[0]["evidence"]["external_scope_ids"] == ["444455556666"]
    assert result[0]["evidence"]["authenticated_endpoint"] is True
    assert len(findings(policy(external, resource=alias_arn), alias=True, target=alias_arn)) == 1
    assert findings(policy(external, action="lambda:Invoke*", resource="*"))[0]["status"] == "FAIL"
    assert findings(policy(external, action="lambda:InvokeFunctionUrl")) == []
    assert findings(policy(external, resource=alias_arn)) == []
    assert findings(policy({"AWS": "arn:aws:iam::111122223333:root"})) == []
    assert findings({"collection_status": "empty", "absent": True}) == []
    assert findings(policy(external, Condition={"Bool": {"lambda:InvokedViaFunctionUrl": "true"}}))[0]["status"] == "UNKNOWN"
    denied = policy(external)
    denied["Policy"]["Statement"].append({"Effect": "Deny", "Principal": external,
                                              "Action": "lambda:InvokeFunction", "Resource": arn})
    assert findings(denied)[0]["status"] == "UNKNOWN"
    assert findings({"collection_status": "denied"})[0]["status"] == "UNKNOWN"


def test_lambda_layer_version_policy_foreign_get_layer_version():
    base = f"arn:aws:lambda:us-east-1:{ACCOUNT}:layer:shared"
    arn = base + ":2"

    def result(read, **changes):
        layer = {"id": arn, "LayerName": "shared", "LayerArn": base,
                 "LayerVersionArn": arn, "Version": 2, "Policy": read, **changes}
        return [f for f in exposure(aws(coll("lambda_layer_version", [layer], service="lambda")))
                if f["evidence"].get("exposure_kind") == "external_layer_share"]

    def policy(principal, action="lambda:GetLayerVersion", resource=arn, **extra):
        return {"collection_status": "collected", "Policy": {"Statement": [{
            "Effect": "Allow", "Principal": principal, "Action": action, "Resource": resource, **extra}]}}

    foreign = {"AWS": f"arn:aws:iam::444455556666:root"}
    named = result(policy(foreign))
    assert len(named) == 1 and named[0]["status"] == "FAIL"
    assert named[0]["evidence"]["external_scope_ids"] == ["444455556666"]
    assert result(policy("*"))[0]["status"] == "FAIL"
    assert result(policy(foreign, action="lambda:InvokeFunction")) == []
    assert result(policy(foreign, resource=base + ":3")) == []
    assert result(policy({"AWS": f"arn:aws:iam::{ACCOUNT}:root"})) == []
    assert result({"collection_status": "empty", "absent": True}) == []
    assert result(policy("*", Condition={"StringEquals": {"aws:PrincipalOrgID": "o-1234567890"}}))[0]["status"] == "UNKNOWN"
    denied = policy(foreign)
    denied["Policy"]["Statement"].append({"Effect": "Deny", "Principal": foreign,
                                              "Action": "lambda:GetLayerVersion", "Resource": arn})
    assert result(denied)[0]["status"] == "UNKNOWN"
    assert result({"collection_status": "denied"})[0]["status"] == "UNKNOWN"
    assert result(policy(foreign), LayerVersionArn=base + ":3")[0]["status"] == "UNKNOWN"


def test_lambda_published_version_direct_invoke_policy():
    base = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:app"
    arn = base + ":3"
    policy = {"collection_status": "collected", "Policy": {"Statement": [{
        "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::444455556666:root"},
        "Action": "lambda:InvokeFunction", "Resource": arn}]}}

    def result(**changes):
        version = {"id": arn, "FunctionName": "app", "BaseFunctionArn": base,
                   "FunctionArn": arn, "Version": "3", "Policy": policy, **changes}
        return [f for f in exposure(aws(coll("lambda_version", [version], service="lambda")))
                if f["evidence"].get("exposure_kind") == "external_lambda_invoke"]

    assert result()[0]["status"] == "FAIL"
    assert result()[0]["evidence"]["external_scope_ids"] == ["444455556666"]
    assert result(BaseFunctionArn=base + ":other")[0]["status"] == "UNKNOWN"
    assert result(Policy={"collection_status": "denied"})[0]["status"] == "UNKNOWN"


def test_api_gateway_auth_not_collected_is_unknown_and_private_passes():
    api = {"id": "a1b2", "name": "api", "endpointConfiguration": {"types": ["REGIONAL"]},
           "Stages": {"collection_status": "collected", "items": [{"stageName": "prod", "deploymentId": "dep-1"}]}}
    result = one(aws(coll("rest_api", [api], service="apigateway")), "rest_api")
    assert result["status"] == "UNKNOWN" and result["evidence"]["collector_facts_needed"]
    private = api | {"endpointConfiguration": {"types": ["PRIVATE"]}}
    assert one(aws(coll("rest_api", [private], service="apigateway")), "rest_api")["status"] == "PASS"
    http = {"ApiId": "h1", "ApiEndpoint": "https://h1.execute-api.us-east-1.amazonaws.com", "ProtocolType": "HTTP",
            "Routes": [{"RouteKey": "GET /", "AuthorizationType": "NONE"}],
            "Stages": {"collection_status": "collected", "items": [{"StageName": "$default", "AutoDeploy": True}]}}
    assert one(aws(coll("http_api", [http], service="apigatewayv2")), "http_api")["status"] == "UNKNOWN"
    http["Routes"] = [{"RouteKey": "GET /", "AuthorizationType": "JWT"}]
    assert one(aws(coll("http_api", [http], service="apigatewayv2")), "http_api")["status"] == "UNKNOWN"


def test_rest_api_collected_method_authorization():
    api = {"id": "a1b2", "endpointConfiguration": {"types": ["REGIONAL"]},
           "Methods": [{"httpMethod": "GET", "authorizationType": "NONE", "apiKeyRequired": False}],
           "Stages": {"collection_status": "collected", "items": [{"stageName": "prod", "deploymentId": "dep-1"}]}}
    assert one(aws(coll("rest_api", [api], service="apigateway"), deployed_rest(api)), "rest_api")["status"] == "FAIL"
    api["Methods"][0]["authorizationType"] = "AWS_IAM"
    result = one(aws(coll("rest_api", [api], service="apigateway"), deployed_rest(api)), "rest_api")
    assert result["status"] == "PASS" and result["evidence"]["authenticated_endpoint"] is True
    api["Methods"][0].pop("apiKeyRequired")
    assert one(aws(coll("rest_api", [api], service="apigateway"), deployed_rest(api)), "rest_api")["status"] == "UNKNOWN"


def test_rest_api_uses_deployed_method_authorization_not_live_method_edits():
    api = {"id": "a1b2", "endpointConfiguration": {"types": ["REGIONAL"]},
           "Methods": [{"httpMethod": "GET", "authorizationType": "NONE", "apiKeyRequired": False}],
           "Stages": {"collection_status": "collected", "items": [{"stageName": "prod", "deploymentId": "dep-1"}]}}
    def row(methods):
        return one(aws(coll("rest_api", [api], service="apigateway"), methods), "rest_api")
    assert row(deployed_rest(api, authorization="AWS_IAM"))["status"] == "PASS"
    api["Methods"][0]["authorizationType"] = "AWS_IAM"
    assert row(deployed_rest(api, authorization="NONE"))["status"] == "FAIL"
    assert row(coll("rest_api_method", [], status="denied", service="apigateway"))["status"] == "UNKNOWN"
    assert row(deployed_rest(api, authorization="NONE", api_key_required=True))["status"] == "PASS"


def test_rest_api_custom_domain_uses_only_the_mapped_deployment():
    api = {"id": "rest1", "disableExecuteApiEndpoint": True, "endpointConfiguration": {"types": ["REGIONAL"]},
           "Methods": [{"httpMethod": "GET", "authorizationType": "NONE", "apiKeyRequired": False}],
           "Stages": {"collection_status": "collected", "items": [
               {"stageName": "prod", "deploymentId": "dep-1"}, {"stageName": "dev", "deploymentId": "dep-2"}]}}
    domain = {"domainName": "rest.example.com", "endpointConfiguration": {"types": ["REGIONAL"]},
              "BasePathMappings": {"collection_status": "collected", "items": [{"restApiId": "rest1", "stage": "prod"}]}}
    methods = deployed_rest(api, stage="prod", authorization="AWS_IAM")["items"] + deployed_rest(api, stage="dev")["items"]
    def row():
        return one(aws(coll("rest_api", [api], service="apigateway"),
                       coll("apigateway_domain_name", [domain], service="apigateway"),
                       coll("rest_api_method", methods, service="apigateway")), "rest_api")
    assert row()["status"] == "PASS"
    domain["BasePathMappings"]["items"][0]["stage"] = "dev"
    assert row()["status"] == "FAIL"


def test_api_gateway_requires_collected_deployed_stage():
    rest = {"id": "rest1", "endpointConfiguration": {"types": ["REGIONAL"]},
            "Methods": [{"httpMethod": "GET", "authorizationType": "NONE", "apiKeyRequired": False}],
            "Stages": {"collection_status": "empty", "items": []}}
    def rest_row():
        return one(aws(coll("rest_api", [rest], service="apigateway"), deployed_rest(rest)), "rest_api")
    assert rest_row()["status"] == "PASS"
    rest["Stages"] = {"collection_status": "denied"}
    assert rest_row()["status"] == "UNKNOWN"
    rest["Stages"] = {"collection_status": "collected", "items": [{"stageName": "prod", "deploymentId": "dep-1"}]}
    assert rest_row()["status"] == "FAIL"
    http = {"ApiId": "http1", "ApiEndpoint": "https://http1.execute-api.us-east-1.amazonaws.com", "ProtocolType": "HTTP",
            "Routes": [{"RouteKey": "GET /", "AuthorizationType": "NONE"}],
            "Stages": {"collection_status": "collected", "items": [{"StageName": "$default", "AutoDeploy": False}]}}
    def http_row():
        return one(aws(coll("http_api", [http], service="apigatewayv2")), "http_api")
    assert http_row()["status"] == "PASS"
    http["Stages"]["items"][0]["AutoDeploy"] = True
    assert http_row()["status"] == "UNKNOWN"


def test_rest_api_custom_domain_routing_rule_reaches_deployed_stage():
    api = {"id": "rest1", "disableExecuteApiEndpoint": True, "endpointConfiguration": {"types": ["REGIONAL"]},
           "Methods": [{"httpMethod": "GET", "authorizationType": "NONE", "apiKeyRequired": False}],
           "Stages": {"collection_status": "collected", "items": [{"stageName": "prod", "deploymentId": "dep-1"}]}}
    domain = {"domainName": "api.example.com", "endpointConfiguration": {"types": ["REGIONAL"]},
              "routingMode": "ROUTING_RULE_ONLY", "RoutingRules": {"collection_status": "collected", "items": [
                  {"RoutingRuleId": "rule-1", "Priority": 1, "ConditionCount": 0,
                   "Actions": [{"InvokeApi": {"ApiId": "rest1", "Stage": "prod"}}]}]}}
    def row():
        return one(aws(coll("rest_api", [api], service="apigateway"),
                       coll("apigateway_domain_name", [domain], service="apigateway"), deployed_rest(api)), "rest_api")
    result = row()
    assert result["status"] == "FAIL"
    assert result["evidence"]["public_addresses"] == ["https://api.example.com"]
    domain["RoutingRules"]["items"][0]["ConditionCount"] = 1
    assert row()["status"] == "UNKNOWN"
    domain["RoutingRules"]["items"][0]["SingleHeaderCondition"] = True
    result = row()
    assert result["status"] == "FAIL"
    assert next(step for step in result["evidence"]["path"] if step["layer"] == "routing_condition")["condition_kind"] == "single_header"
    del domain["RoutingRules"]["items"][0]["SingleHeaderCondition"]
    domain["RoutingRules"]["items"][0]["SingleBasePathCondition"] = True
    domain["RoutingRules"]["items"][0]["Actions"][0]["InvokeApi"]["StripBasePath"] = True
    result = row()
    assert result["status"] == "FAIL"
    assert next(step for step in result["evidence"]["path"] if step["layer"] == "routing_condition")["condition_kind"] == "single_base_path_strip"
    domain["RoutingRules"]["items"][0]["ConditionCount"] = 2
    domain["RoutingRules"]["items"][0]["HeaderAndBasePathConditions"] = True
    result = row()
    assert result["status"] == "FAIL"
    assert next(step for step in result["evidence"]["path"] if step["layer"] == "routing_condition")["condition_kind"] == "header_and_base_path_strip"
    del domain["RoutingRules"]["items"][0]["HeaderAndBasePathConditions"]
    domain["RoutingRules"]["items"][0]["ConditionCount"] = 1
    domain["RoutingRules"]["items"][0]["Actions"][0]["InvokeApi"]["StripBasePath"] = False
    assert row()["status"] == "UNKNOWN"
    del domain["RoutingRules"]["items"][0]["SingleBasePathCondition"]
    domain["RoutingRules"]["items"][0]["ConditionCount"] = 0
    domain["RoutingRules"]["items"].insert(0, {"RoutingRuleId": "rule-0", "Priority": 0,
        "ConditionCount": 0, "Actions": [{"InvokeApi": {"ApiId": "other", "Stage": "prod"}}]})
    assert row()["status"] == "UNKNOWN"  # Invalid priority cannot prove routing.
    domain["RoutingRules"]["items"][0]["Priority"] = 1
    domain["RoutingRules"]["items"][1]["Priority"] = 2
    assert row()["status"] == "PASS"  # Earlier catch-all shadows the target rule.
    domain["RoutingRules"]["items"][0]["ConditionCount"] = 1
    assert row()["status"] == "UNKNOWN"  # Earlier conditional rule may shadow it.
    domain["RoutingRules"]["items"] = []
    assert row()["status"] == "PASS"
    domain["RoutingRules"] = {"collection_status": "denied"}
    assert row()["status"] == "UNKNOWN"


def test_rest_api_unconditional_global_invoke_deny_blocks_deployed_public_method():
    api = {"id": "rest1", "endpointConfiguration": {"types": ["REGIONAL"]},
           "Methods": [{"httpMethod": "GET", "authorizationType": "NONE", "apiKeyRequired": False}],
           "Stages": {"collection_status": "collected", "items": [{"stageName": "prod", "deploymentId": "dep-1"}]},
           "policy": {"Statement": [{"Effect": "Deny", "Principal": "*", "Action": "execute-api:Invoke",
                       "Resource": f"arn:aws:execute-api:us-east-1:{ACCOUNT}:rest1/*/*/*"}]}}
    result = one(aws(coll("rest_api", [api], service="apigateway"), deployed_rest(api)), "rest_api")
    assert result["status"] == "PASS" and result["evidence"]["blocked_by"] == "policy"
    assert next(step for step in result["evidence"]["path"] if step["layer"] == "policy")["denied_resource_scope"] == "all_api_routes"
    api["policy"]["Statement"][0]["Resource"] = "execute-api:/*"
    assert one(aws(coll("rest_api", [api], service="apigateway"), deployed_rest(api)), "rest_api")["status"] == "PASS"


def test_api_gateway_custom_mapping_requires_its_own_active_stage():
    rest = {"id": "rest1", "disableExecuteApiEndpoint": True, "endpointConfiguration": {"types": ["REGIONAL"]},
            "Methods": [{"httpMethod": "GET", "authorizationType": "NONE", "apiKeyRequired": False}],
            "Stages": {"collection_status": "collected", "items": [{"stageName": "prod", "deploymentId": "dep-1"},
                                                                {"stageName": "dev"}]}}
    rest_domain = {"domainName": "rest.example.com", "endpointConfiguration": {"types": ["REGIONAL"]},
                   "BasePathMappings": {"collection_status": "collected", "items": [{"restApiId": "rest1", "stage": "dev"}]}}
    def rest_row():
        return one(aws(coll("rest_api", [rest], service="apigateway"),
                       coll("apigateway_domain_name", [rest_domain], service="apigateway"), deployed_rest(rest)), "rest_api")
    assert rest_row()["status"] == "PASS"
    rest_domain["BasePathMappings"]["items"][0]["stage"] = "prod"
    assert rest_row()["status"] == "FAIL"
    rest_domain["routingMode"] = "ROUTING_RULE_THEN_API_MAPPING"
    rest_domain["RoutingRules"] = {"collection_status": "collected", "items": [{
        "RoutingRuleId": "rule-1", "Priority": 1, "ConditionCount": 0,
        "Actions": [{"InvokeApi": {"ApiId": "other", "Stage": "prod"}}]}]}
    assert rest_row()["status"] == "PASS"  # The catch-all rule shadows the mapping.
    rest_domain["RoutingRules"]["items"][0]["ConditionCount"] = 1
    assert rest_row()["status"] == "FAIL"  # The mapping handles requests that miss the rule.
    del rest_domain["routingMode"], rest_domain["RoutingRules"]
    rest_domain["BasePathMappings"] = {"collection_status": "empty", "items": []}
    assert rest_row()["status"] == "PASS"
    http = {"ApiId": "http1", "DisableExecuteApiEndpoint": True, "ProtocolType": "HTTP",
            "Routes": [{"RouteKey": "GET /", "AuthorizationType": "NONE"}],
            "Stages": {"collection_status": "collected", "items": [{"StageName": "prod", "AutoDeploy": True},
                                                                {"StageName": "dev", "AutoDeploy": False}]}}
    http_domain = {"DomainName": "http.example.com", "DomainNameConfigurations": [{"EndpointType": "REGIONAL"}],
                   "ApiMappings": {"collection_status": "collected", "items": [{"ApiId": "http1", "Stage": "dev"}]}}
    def http_row():
        return one(aws(coll("http_api", [http], service="apigatewayv2"),
                       coll("apigatewayv2_domain_name", [http_domain], service="apigatewayv2")), "http_api")
    assert http_row()["status"] == "PASS"
    http_domain["ApiMappings"]["items"][0]["Stage"] = "prod"
    assert http_row()["status"] == "UNKNOWN"
    http_domain["ApiMappings"] = {"collection_status": "empty", "items": []}
    assert http_row()["status"] == "PASS"


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


def test_redshift_manual_snapshot_restore_authorizations():
    arn = f"arn:aws:redshift:us-east-1:{ACCOUNT}:snapshot:warehouse/nightly"

    def result(**changes):
        data = {"SnapshotArn": arn, "SnapshotIdentifier": "nightly", "ClusterIdentifier": "warehouse",
                "OwnerAccount": ACCOUNT, "SnapshotType": "manual", "Status": "available",
                "AccountsWithRestoreAccess": [{"AccountId": "999988887777"}], **changes}
        return [f for f in exposure(aws(coll("redshift_snapshot", [data], service="redshift")))
                if f["evidence"].get("exposure_kind") == "external_redshift_snapshot_share"]

    found = result()
    assert len(found) == 1 and found[0]["status"] == "FAIL"
    assert found[0]["evidence"]["external_scope_ids"] == ["999988887777"]
    assert found[0]["evidence"]["path"][0]["snapshot_arn"] == arn
    assert result(AccountsWithRestoreAccess=[{"AccountAlias": "amazon-redshift-support"}])[0]["status"] == "FAIL"
    assert result(AccountsWithRestoreAccess=[{"AccountId": ACCOUNT}]) == []
    assert result(AccountsWithRestoreAccess=[]) == []
    assert result(SnapshotType="automated") == []
    assert result(Status="creating")[0]["status"] == "UNKNOWN"
    assert result(OwnerAccount="000000000000")[0]["status"] == "UNKNOWN"
    assert result(SnapshotArn=arn + "-wrong")[0]["status"] == "UNKNOWN"
    assert result(AccountsWithRestoreAccess=[{"AccountId": "invalid"}])[0]["status"] == "UNKNOWN"


def test_redshift_serverless_snapshot_namespace_and_provisioned_restore_grants():
    arn = f"arn:aws:redshift-serverless:us-east-1:{ACCOUNT}:snapshot/11111111-2222-3333-4444-555555555555"

    def result(**changes):
        data = {"id": arn, "snapshotArn": arn, "ownerAccount": ACCOUNT, "status": "AVAILABLE",
                "accountsWithRestoreAccess": ["999988887777"],
                "accountsWithProvisionedRestoreAccess": ["444455556666"], **changes}
        return [f for f in exposure(aws(coll("redshiftserverless_snapshot", [data], service="redshift-serverless")))
                if f["evidence"].get("exposure_kind") == "external_redshift_serverless_snapshot_share"]

    found = result()
    assert len(found) == 1 and found[0]["status"] == "FAIL"
    assert found[0]["evidence"]["external_scope_ids"] == ["444455556666", "999988887777"]
    targets = found[0]["evidence"]["path"][0]["external_targets"]
    assert targets == {"namespace": ["999988887777"], "provisioned_cluster": ["444455556666"]}
    assert result(accountsWithRestoreAccess=[ACCOUNT], accountsWithProvisionedRestoreAccess=[]) == []
    assert result(accountsWithRestoreAccess=[], accountsWithProvisionedRestoreAccess=[]) == []
    assert result(status="CREATING")[0]["status"] == "UNKNOWN"
    assert result(ownerAccount="000000000000")[0]["status"] == "UNKNOWN"
    assert result(snapshotArn=arn + "-other")[0]["status"] == "UNKNOWN"
    assert result(accountsWithRestoreAccess=["invalid"])[0]["status"] == "UNKNOWN"


@pytest.mark.parametrize("kind,service", [("docdb_cluster_snapshot", "docdb"),
                                          ("neptune_cluster_snapshot", "neptune")])
def test_documentdb_neptune_manual_snapshot_restore_shares(kind, service):
    arn = f"arn:aws:rds:us-east-1:{ACCOUNT}:cluster-snapshot:shared"

    def result(values, **changes):
        data = {"id": arn, "DBClusterSnapshotIdentifier": "shared", "DBClusterSnapshotArn": arn,
                "SnapshotType": "manual", "Status": "available", "StorageEncrypted": False,
                "Engine": service, "Attributes": {"collection_status": "collected",
                    "DBClusterSnapshotAttributesResult": {"DBClusterSnapshotIdentifier": "shared",
                        "DBClusterSnapshotAttributes": [{"AttributeName": "restore", "AttributeValues": values}]}}, **changes}
        return [f for f in exposure(aws(coll(kind, [data], service=service)))
                if f["evidence"].get("exposure_kind") == "external_cluster_snapshot_share"]

    public = result(["all"])
    assert len(public) == 1 and public[0]["status"] == "FAIL" and public[0]["severity"] == "critical"
    assert public[0]["evidence"]["external_scope_ids"] == ["*"]
    foreign = result(["999988887777"], StorageEncrypted=True)
    assert foreign[0]["status"] == "FAIL" and foreign[0]["evidence"]["external_scope_ids"] == ["999988887777"]
    assert result([ACCOUNT]) == []
    assert result([]) == []
    assert result(["all"], StorageEncrypted=True)[0]["status"] == "UNKNOWN"
    assert result(["999988887777"], SnapshotType="automated") == []
    assert result(["999988887777"], Status="creating")[0]["status"] == "UNKNOWN"
    assert result(["999988887777"], DBClusterSnapshotArn=arn + "-wrong")[0]["status"] == "UNKNOWN"
    assert result(["999988887777"], Attributes={"collection_status": "denied"})[0]["status"] == "UNKNOWN"
    assert result(["invalid"])[0]["status"] == "UNKNOWN"


def test_source_attributed_resource_policy_declares_foreign_grant():
    arn = f"arn:aws:elasticfilesystem:us-east-1:{ACCOUNT}:file-system/fs-12345678"
    principal = {"AWS": "arn:aws:iam::999988887777:root"}

    def result(statements, **changes):
        row = {"ResourceArn": arn, "Policy": {"Statement": statements},
               "_provenance": {"read_only": True, "owner_account": ACCOUNT,
                               "families": ["efs-filesystems"], "source_region": "us-east-1"}, **changes}
        return [f for f in exposure(aws(coll("aws_resource_policy", [row], service="efs")))
                if f["evidence"].get("exposure_kind") == "external_generic_policy_grant"]

    allow = {"Effect": "Allow", "Principal": principal, "Action": "elasticfilesystem:ClientMount", "Resource": arn}
    found = result([allow])
    assert len(found) == 1 and found[0]["status"] == "FAIL"
    assert found[0]["evidence"]["external_scope_ids"] == ["999988887777"]
    assert found[0]["evidence"]["path"][0]["external_grants"][0]["actions"] == ["elasticfilesystem:ClientMount"]
    assert result([{**allow, "Principal": "*"}])[0]["status"] == "FAIL"
    assert result([{**allow, "Principal": {"AWS": principal["AWS"], "Service": "backup.amazonaws.com"}}])[0]["status"] == "FAIL"
    assert result([{**allow, "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}}]) == []
    assert result([{**allow, "Principal": {"Service": "backup.amazonaws.com"}}]) == []
    assert result([{**allow, "Resource": "arn:aws:elasticfilesystem:us-east-1:000000000000:file-system/fs-12345678"}]) == []
    assert result([{"Effect": "Deny", "Principal": principal, "Action": "elasticfilesystem:ClientMount", "Resource": arn}]) == []
    assert result([allow, {**allow, "Effect": "Deny"}])[0]["status"] == "UNKNOWN"
    assert result([{**allow, "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-123"}}}])[0]["status"] == "UNKNOWN"
    bad_owner = {"read_only": True, "owner_account": "000000000000", "families": ["efs-filesystems"]}
    assert result([allow], _provenance=bad_owner)[0]["status"] == "UNKNOWN"
    assert result([allow], _provenance={"covered_services": ["efs"]})[0]["status"] == "UNKNOWN"

    serverless = f"arn:aws:redshift-serverless:us-east-1:{ACCOUNT}:snapshot/11111111-2222-3333-4444-555555555555"
    policy = {"ResourceArn": serverless, "Policy": {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "999988887777"},
              "Action": "redshift-serverless:RestoreFromSnapshot"}]},
              "_provenance": {"read_only": True, "owner_account": ACCOUNT, "families": ["redshift-snapshots"]}}
    shares = [f for f in exposure(aws(coll("aws_resource_policy", [policy], service="redshift-serverless")))
              if f["evidence"].get("exposure_kind") == "external_generic_policy_grant"]
    assert shares[0]["status"] == "FAIL"


def test_owned_iam_role_trust_declares_foreign_assume_role():
    arn = f"arn:aws:iam::{ACCOUNT}:role/team/Reader"
    statement = {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
                 "Action": "sts:AssumeRole"}

    def findings(statements, **changes):
        row = {"Arn": arn, "RoleName": "Reader", "AssumeRolePolicyDocument": {"Statement": statements}, **changes}
        return [f for f in exposure(aws(coll("iam_role", [row], service="iam")))
                if f["evidence"].get("exposure_kind") == "external_generic_policy_grant"]

    found = findings([statement])
    assert len(found) == 1 and found[0]["status"] == "FAIL"
    assert found[0]["evidence"]["external_scope_ids"] == ["999988887777"]
    assert found[0]["evidence"]["path"][0]["external_grants"][0]["actions"] == ["sts:AssumeRole"]
    assert findings([{**statement, "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}}]) == []
    assert findings([{**statement, "Action": "sts:TagSession"}]) == []
    assert findings([{**statement, "Action": "sts:AssumeR*"}])[0]["status"] == "FAIL"
    assert findings([statement, {**statement, "Effect": "Deny"}])[0]["status"] == "UNKNOWN"
    assert findings([statement, {"Effect": "Deny", "Principal": "*", "NotAction": "sts:TagSession"}])[0]["status"] == "UNKNOWN"
    assert findings([{**statement, "Condition": {"StringEquals": {"sts:ExternalId": "partner"}}}])[0]["status"] == "UNKNOWN"
    assert findings([statement], Arn=arn.replace(ACCOUNT, "000000000000"))[0]["status"] == "UNKNOWN"
    assert findings([statement], AssumeRolePolicyDocument="{broken")[0]["status"] == "UNKNOWN"
    assert findings([{**statement, "Principal": "*"}])[0]["evidence"]["external_scope_ids"] == ["*"]


@pytest.mark.parametrize("service,tail,action,dedicated", [
    ("sns", "topic", "sns:Publish", "sns:Subscribe"),
    ("sqs", "queue", "sqs:SendMessage", "sqs:ReceiveMessage"),
    ("ecr", "repository/fixture", "ecr:PutImage", "ecr:BatchGetImage"),
])
def test_base_resource_policy_additional_foreign_actions(service, tail, action, dedicated):
    arn = f"arn:aws:{service}:us-east-1:{ACCOUNT}:{tail}"
    provenance = {"read_only": True, "owner_account": ACCOUNT, "families": [service + "-base"],
                  "covered_services": ["sns", "sqs", "lambda", "ecr"]}

    def findings(actions):
        row = {"ResourceArn": arn, "Policy": {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "999988887777"},
               "Action": actions, "Resource": arn}]}, "_provenance": provenance}
        return [f for f in exposure(aws(coll("aws_resource_policy", [row], service=service)))
                if f["evidence"].get("exposure_kind") == "external_generic_policy_grant"]

    assert findings([dedicated]) == []
    found = findings([dedicated, action])
    assert len(found) == 1 and found[0]["status"] == "FAIL"
    assert found[0]["evidence"]["path"][0]["external_grants"][0]["actions"] == [action]


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
    narrowed = one(aws(coll("eks_cluster", [cluster(["8.8.8.8/32"])], service="eks")), "eks_cluster")
    assert narrowed["status"] == "FAIL" and narrowed["evidence"]["authenticated_endpoint"] is False
    assert any("anonymous" in note for note in narrowed["evidence"]["notes"])
    assert one(aws(coll("eks_cluster", [cluster(["2600::/32"])], service="eks")), "eks_cluster")["status"] == "FAIL"
    assert one(aws(coll("eks_cluster", [cluster(["10.0.0.0/8"])], service="eks")), "eks_cluster")["status"] == "PASS"
    assert one(aws(coll("eks_cluster", [cluster(["203.0.113.0/24"])], service="eks")), "eks_cluster")["status"] == "PASS"
    assert one(aws(coll("eks_cluster", [cluster(["0.0.0.0/1"])], service="eks")), "eks_cluster")["status"] == "FAIL"
    assert one(aws(coll("eks_cluster", [cluster(["::/1"])], service="eks")), "eks_cluster")["status"] == "FAIL"
    assert one(aws(coll("eks_cluster", [cluster(["fc00::/7"])], service="eks")), "eks_cluster")["status"] == "PASS"
    assert one(aws(coll("eks_cluster", [cluster(["2001:db8::/32"])], service="eks")), "eks_cluster")["status"] == "PASS"
    missing_host = cluster(["0.0.0.0/0"])
    del missing_host["Cluster"]["cluster"]["endpoint"]
    unresolved = one(aws(coll("eks_cluster", [missing_host], service="eks")), "eks_cluster")
    assert unresolved["status"] == "UNKNOWN" and unresolved["evidence"]["public_addresses"] == []
    assert "eks:DescribeCluster" in unresolved["evidence"]["collector_facts_needed"]


def test_eks_missing_public_endpoint_flag_is_unresolved():
    row = {"name": "c", "Cluster": {"cluster": {"endpoint": "https://x.eks.amazonaws.com",
           "resourcesVpcConfig": {}}}}
    def finding():
        return one(aws(coll("eks_cluster", [row], service="eks")), "eks_cluster")
    assert finding()["status"] == "UNKNOWN"
    assert "eks:DescribeCluster.resourcesVpcConfig.endpointPublicAccess" in finding()["evidence"]["collector_facts_needed"]
    row["Cluster"]["cluster"].pop("resourcesVpcConfig")
    assert "eks:DescribeCluster.resourcesVpcConfig" in finding()["evidence"]["collector_facts_needed"]
    row["Cluster"]["cluster"]["resourcesVpcConfig"] = {"endpointPublicAccess": False}
    assert not exposure(aws(coll("eks_cluster", [row], service="eks")))


def test_eks_new_ipv6_endpoint_without_cidrs_has_dual_stack_public_default():
    cluster = {"name": "c", "Cluster": {"cluster": {
        "endpoint": "https://cluster.us-east-1.api.aws", "kubernetesNetworkConfig": {"ipFamily": "ipv6"},
        "resourcesVpcConfig": {"endpointPublicAccess": True, "publicAccessCidrs": []}}}}
    def finding():
        return one(aws(coll("eks_cluster", [cluster], service="eks")), "eks_cluster")
    current = finding()
    assert current["status"] == "FAIL" and current["evidence"]["authenticated_endpoint"] is False
    step = next(x for x in current["evidence"]["path"] if x["layer"] == "source_ranges")
    assert step["public_access_cidrs"] == ["0.0.0.0/0", "::/0"]
    assert step["source"] == "documented_default"
    cluster["Cluster"]["cluster"]["endpoint"] = "https://cluster.us-east-1.eks.amazonaws.com"
    step = next(x for x in finding()["evidence"]["path"] if x["layer"] == "source_ranges")
    assert step["public_access_cidrs"] == ["0.0.0.0/0"]


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


def assert_gcp_observed_style(finding, resource_name):
    observed = finding["evidence"]["observed"]
    lines = observed.splitlines()
    assert 3 <= len(lines) <= 5
    assert lines[0].startswith("The ") and resource_name in lines[0]
    assert all(line.endswith(".") for line in lines)
    assert any(" may " in line or " could " in line for line in lines)
    assert " may " in lines[-1] or " could " in lines[-1]
    assert not any(word in observed.lower() for word in ("scan", "check", "test"))


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


def test_gcp_instance_effective_firewall_clears_unattached_policy_uncertainty():
    from copy import deepcopy
    vm = deepcopy(gcp_instance())
    link = "https://compute.googleapis.com/compute/v1/projects/p1/zones/us-central1-a/instances/vm"
    vm["items"][0]["selfLink"] = link
    effective = {"name": "projects/p1/zones/us-central1-a/instances/vm/interfaces/nic0/effectiveFirewalls",
                 "instance": "projects/p1/zones/us-central1-a/instances/vm", "networkInterface": "nic0",
                 "firewalls": [fw("allow-ssh", 1000, "allowed", ["22"], ["web"])],
                 "firewallPolicys": [], "effective_source_operation": "instances.getEffectiveFirewalls"}
    policy = {"name": "unattached-policy", "rules": [{"priority": 100, "action": "deny"}]}
    def assessment():
        return one(gcp(vm, gcoll("firewall", [], status="denied"),
                       gcoll("firewall_policy", [policy]),
                       gcoll("instance_effective_firewall", [effective])), "instance")
    result = assessment()
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/22"]
    effective["firewallPolicys"] = [{"id": "attached"}]
    assert assessment()["status"] == "UNKNOWN"
    effective["firewallPolicys"] = []
    effective["firewalls"] = []
    assert assessment()["status"] == "PASS"


def test_gcp_terminal_hierarchical_firewall_rule_preempts_vpc_rules():
    from copy import deepcopy
    vm = deepcopy(gcp_instance())
    vm["items"][0]["selfLink"] = "https://compute.googleapis.com/compute/v1/projects/p1/zones/us-central1-a/instances/vm"
    rule = {"priority": 0, "ruleName": "public-all", "direction": "INGRESS", "action": "deny",
            "match": {"srcIpRanges": ["0.0.0.0/0"], "layer4Configs": []}}
    effective = {"name": "projects/p1/zones/us-central1-a/instances/vm/interfaces/nic0/effectiveFirewalls",
                 "instance": "projects/p1/zones/us-central1-a/instances/vm", "networkInterface": "nic0",
                 "firewalls": [fw("allow-ssh", 1000, "allowed", ["22"])],
                 "firewallPolicys": [{"name": "org-policy", "type": "HIERARCHY", "rules": [rule]}],
                 "effective_source_operation": "instances.getEffectiveFirewalls"}

    def assessment():
        return one(gcp(vm, gcoll("firewall", [], status="denied"),
                       gcoll("instance_effective_firewall", [effective])), "instance")

    result = assessment()
    assert result["status"] == "PASS"
    rule["action"] = "allow"
    assert assessment()["status"] == "FAIL"
    assert_gcp_observed_style(assessment(), "vm")
    effective["firewallPolicys"].insert(0, {"name": "network-policy", "type": "NETWORK", "rules": []})
    result = assessment()
    assert result["status"] == "FAIL"
    assert next(step for step in result["evidence"]["path"] if step["layer"] == "effective_firewall")["policy"] == "org-policy"
    effective["firewallPolicys"].append({"name": "second-hierarchy", "type": "HIERARCHY", "rules": []})
    assert assessment()["status"] == "UNKNOWN"
    effective["firewallPolicys"].pop()
    effective["firewallPolicys"][0]["type"] = "UNKNOWN_TYPE"
    assert assessment()["status"] == "UNKNOWN"
    effective["firewallPolicys"][0]["type"] = "NETWORK"
    effective["firewallPolicys"].pop(0)
    rule["match"]["srcAddressGroups"] = ["projects/p/locations/global/addressGroups/g"]
    assert assessment()["status"] == "UNKNOWN"
    del rule["match"]["srcAddressGroups"]
    rule["action"] = "goto_next"
    assert assessment()["status"] == "UNKNOWN"
    rule["action"] = "deny"
    vm["items"][0]["networkInterfaces"][0]["ipv6AccessConfigs"] = [{"externalIpv6": "2600:1900::1"}]
    assert assessment()["status"] == "UNKNOWN"
    rule["match"]["srcIpRanges"].append("::/0")
    assert assessment()["status"] == "PASS"
    second = deepcopy(vm["items"][0]["networkInterfaces"][0])
    second["name"] = "nic1"
    vm["items"][0]["networkInterfaces"].append(second)
    assert assessment()["status"] == "UNKNOWN"
    assert_gcp_observed_style(assessment(), "vm")
    vm["items"][0]["networkInterfaces"].pop()
    rule["priority"] = 500
    effective["firewallPolicys"][0]["rules"] += [
        {"priority": 0, "direction": "EGRESS", "action": "allow", "match": {}},
        {"priority": 100, "direction": "INGRESS", "disabled": True, "action": "allow", "match": {}}]
    assert assessment()["status"] == "PASS"
    effective["firewallPolicys"][0]["rules"].append({"priority": 200, "direction": "INGRESS", "action": "allow",
        "match": {"srcIpRanges": ["8.8.8.0/24"], "layer4Configs": [{"ipProtocol": "tcp", "ports": ["443"]}]}})
    assert assessment()["status"] == "UNKNOWN"


def test_gcp_global_network_policy_precedes_classic_when_vpc_sets_before_order():
    vm = copy.deepcopy(gcp_instance())
    vm["items"][0]["selfLink"] = "https://compute.googleapis.com/compute/v1/projects/p1/zones/us-central1-a/instances/vm"
    network = {"name": "n", "selfLink": NET,
               "networkFirewallPolicyEnforcementOrder": "BEFORE_CLASSIC_FIREWALL"}
    rule = {"priority": 100, "ruleName": "net-ssh", "direction": "INGRESS", "action": "allow",
            "match": {"srcIpRanges": ["0.0.0.0/0"],
                      "layer4Configs": [{"ipProtocol": "tcp", "ports": ["22"]}]}}
    effective = {"name": "projects/p1/zones/us-central1-a/instances/vm/interfaces/nic0/effectiveFirewalls",
                 "instance": "projects/p1/zones/us-central1-a/instances/vm", "networkInterface": "nic0",
                 "firewalls": [fw("classic-deny", 1000, "denied", ["22"])],
                 "firewallPolicys": [{"name": "locations/global/firewallPolicies/net", "type": "NETWORK", "rules": [rule]}],
                 "effective_source_operation": "instances.getEffectiveFirewalls"}
    def finding():
        return one(gcp(vm, gcoll("network", [network]),
                       gcoll("instance_effective_firewall", [effective])), "instance")
    result = finding()
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/22"]
    assert next(step for step in result["evidence"]["path"] if step["layer"] == "effective_firewall")["basis"] == \
        "terminal global network ingress rule"
    assert "effective global network rule" in result["evidence"]["observed"]
    assert_gcp_observed_style(result, "vm")
    rule["action"] = "deny"
    rule["match"]["layer4Configs"] = []
    assert finding()["status"] == "PASS"
    rule["action"] = "allow"
    rule["match"]["layer4Configs"] = [{"ipProtocol": "tcp", "ports": ["22"]}]
    network["networkFirewallPolicyEnforcementOrder"] = "AFTER_CLASSIC_FIREWALL"
    result = finding()
    assert result["status"] == "UNKNOWN"
    assert_gcp_observed_style(result, "vm")
    network["networkFirewallPolicyEnforcementOrder"] = "BEFORE_CLASSIC_FIREWALL"
    effective["firewallPolicys"].append({"name": "system", "type": "SYSTEM_REGIONAL", "rules": []})
    assert finding()["status"] == "FAIL"
    effective["firewallPolicys"][-1]["rules"] = [{"priority": 100, "direction": "INGRESS", "action": "allow",
        "match": {"srcIpRanges": ["8.8.8.0/24"], "layer4Configs": []}}]
    assert finding()["status"] == "UNKNOWN"


def test_gcp_regional_system_policy_precedes_network_and_classic_rules():
    vm = copy.deepcopy(gcp_instance())
    vm["items"][0]["selfLink"] = "https://compute.googleapis.com/compute/v1/projects/p1/zones/us-central1-a/instances/vm"
    rule = {"priority": 100, "ruleName": "system-ssh", "direction": "INGRESS", "action": "allow",
            "match": {"srcIpRanges": ["0.0.0.0/0"],
                      "layer4Configs": [{"ipProtocol": "tcp", "ports": ["22"]}]}}
    effective = {"name": "projects/p1/zones/us-central1-a/instances/vm/interfaces/nic0/effectiveFirewalls",
                 "instance": "projects/p1/zones/us-central1-a/instances/vm", "networkInterface": "nic0",
                 "firewalls": [fw("classic-deny", 1000, "denied", ["22"])],
                 "firewallPolicys": [
                     {"name": "locations/us-central1/firewallPolicies/system", "type": "SYSTEM_REGIONAL", "rules": [rule]},
                     {"name": "locations/global/firewallPolicies/network", "type": "NETWORK", "rules": [
                         {"priority": 200, "direction": "INGRESS", "action": "deny",
                          "match": {"srcIpRanges": ["0.0.0.0/0"], "layer4Configs": []}}]}],
                 "effective_source_operation": "instances.getEffectiveFirewalls"}
    def finding():
        return one(gcp(vm, gcoll("instance_effective_firewall", [effective])), "instance")
    result = finding()
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/22"]
    assert "effective regional system rule" in result["evidence"]["observed"]
    assert_gcp_observed_style(result, "vm")
    rule["action"] = "deny"
    rule["match"]["layer4Configs"] = []
    assert finding()["status"] == "PASS"
    rule["action"] = "allow"
    rule["match"]["layer4Configs"] = [{"ipProtocol": "tcp", "ports": ["22"]}]
    effective["firewallPolicys"].append({"name": "system-2", "type": "SYSTEM_REGIONAL", "rules": []})
    assert finding()["status"] == "UNKNOWN"
    effective["firewallPolicys"].pop()
    effective["firewallPolicys"].append({"name": "system-global", "type": "SYSTEM_GLOBAL", "rules": []})
    assert finding()["status"] == "UNKNOWN"


def test_gcp_hierarchy_goto_next_reaches_regional_system_policy():
    vm = copy.deepcopy(gcp_instance())
    vm["items"][0]["selfLink"] = "https://compute.googleapis.com/compute/v1/projects/p1/zones/us-central1-a/instances/vm"
    hierarchy = {"priority": 100, "ruleName": "continue", "direction": "INGRESS", "action": "goto_next",
                 "match": {"srcIpRanges": ["0.0.0.0/0"], "layer4Configs": []}}
    system = {"priority": 100, "ruleName": "system-open", "direction": "INGRESS", "action": "allow",
              "match": {"srcIpRanges": ["0.0.0.0/0"], "layer4Configs": [{"ipProtocol": "tcp", "ports": ["22"]}]}}
    effective = {"name": "projects/p1/zones/us-central1-a/instances/vm/interfaces/nic0/effectiveFirewalls",
                 "instance": "projects/p1/zones/us-central1-a/instances/vm", "networkInterface": "nic0",
                 "firewalls": [fw("classic-deny", 1000, "denied", ["22"])],
                 "firewallPolicys": [
                     {"name": "locations/global/firewallPolicies/100", "type": "HIERARCHY", "rules": [hierarchy]},
                     {"name": "locations/us-central1/firewallPolicies/system", "type": "SYSTEM_REGIONAL", "rules": [system]}],
                 "effective_source_operation": "instances.getEffectiveFirewalls"}
    def finding():
        return one(gcp(vm, gcoll("instance_effective_firewall", [effective])), "instance")
    result = finding()
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/22"]
    assert any(step["layer"] == "hierarchy_transition" for step in result["evidence"]["path"])
    assert "effective regional system rule" in result["evidence"]["observed"]
    assert_gcp_observed_style(result, "vm")
    hierarchy["match"]["layer4Configs"] = [{"ipProtocol": "tcp", "ports": ["22"]}]
    system["match"]["layer4Configs"] = []
    result = finding()
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/22"]
    hierarchy["match"]["srcIpRanges"] = ["8.8.8.0/24"]
    assert finding()["status"] == "UNKNOWN"


def test_gcp_hierarchy_goto_next_reaches_before_classic_global_network_policy():
    vm = copy.deepcopy(gcp_instance())
    vm["items"][0]["selfLink"] = "https://compute.googleapis.com/compute/v1/projects/p1/zones/us-central1-a/instances/vm"
    network = {"name": "n", "selfLink": NET,
               "networkFirewallPolicyEnforcementOrder": "BEFORE_CLASSIC_FIREWALL"}
    hierarchy = {"priority": 100, "ruleName": "continue", "direction": "INGRESS", "action": "goto_next",
                 "match": {"srcIpRanges": ["0.0.0.0/0"], "layer4Configs": []}}
    global_rule = {"priority": 100, "ruleName": "network-open", "direction": "INGRESS", "action": "allow",
                   "match": {"srcIpRanges": ["0.0.0.0/0"], "layer4Configs": [{"ipProtocol": "tcp", "ports": ["22"]}]}}
    effective = {"name": "projects/p1/zones/us-central1-a/instances/vm/interfaces/nic0/effectiveFirewalls",
                 "instance": "projects/p1/zones/us-central1-a/instances/vm", "networkInterface": "nic0",
                 "firewalls": [fw("classic-deny", 1000, "denied", ["22"])],
                 "firewallPolicys": [
                     {"name": "locations/global/firewallPolicies/100", "type": "HIERARCHY", "rules": [hierarchy]},
                     {"name": "locations/global/firewallPolicies/net", "type": "NETWORK", "rules": [global_rule]}],
                 "effective_source_operation": "instances.getEffectiveFirewalls"}
    def finding():
        return one(gcp(vm, gcoll("network", [network]),
                       gcoll("instance_effective_firewall", [effective])), "instance")
    result = finding()
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/22"]
    assert "effective global network rule" in result["evidence"]["observed"]
    assert_gcp_observed_style(result, "vm")
    hierarchy["match"]["layer4Configs"] = [{"ipProtocol": "tcp", "ports": ["22"]}]
    global_rule["match"]["layer4Configs"] = []
    result = finding()
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/22"]
    network["networkFirewallPolicyEnforcementOrder"] = "AFTER_CLASSIC_FIREWALL"
    assert finding()["status"] == "UNKNOWN"
    network["networkFirewallPolicyEnforcementOrder"] = "BEFORE_CLASSIC_FIREWALL"
    hierarchy["match"]["srcIpRanges"] = ["8.8.8.0/24"]
    assert finding()["status"] == "UNKNOWN"


def test_gcp_regional_network_policy_precedes_classic_without_global_policy():
    vm = copy.deepcopy(gcp_instance())
    vm["items"][0]["selfLink"] = "https://compute.googleapis.com/compute/v1/projects/p1/zones/us-central1-a/instances/vm"
    network = {"name": "n", "selfLink": NET,
               "networkFirewallPolicyEnforcementOrder": "BEFORE_CLASSIC_FIREWALL"}
    rule = {"priority": 100, "ruleName": "regional-open", "direction": "INGRESS", "action": "allow",
            "match": {"srcIpRanges": ["0.0.0.0/0"],
                      "layer4Configs": [{"ipProtocol": "tcp", "ports": ["22"]}]}}
    effective = {"name": "projects/p1/zones/us-central1-a/instances/vm/interfaces/nic0/effectiveFirewalls",
                 "instance": "projects/p1/zones/us-central1-a/instances/vm", "networkInterface": "nic0",
                 "firewalls": [fw("classic-deny", 1000, "denied", ["22"])],
                 "firewallPolicys": [{"name": "regions/us-central1/firewallPolicies/r", "type": "NETWORK_REGIONAL",
                                     "rules": [rule]}],
                 "effective_source_operation": "instances.getEffectiveFirewalls"}
    def finding():
        return one(gcp(vm, gcoll("network", [network]),
                       gcoll("instance_effective_firewall", [effective])), "instance")
    result = finding()
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/22"]
    assert "effective regional network rule" in result["evidence"]["observed"]
    assert_gcp_observed_style(result, "vm")
    rule["action"] = "deny"
    rule["match"]["layer4Configs"] = []
    assert finding()["status"] == "PASS"
    rule["action"] = "allow"
    rule["match"]["layer4Configs"] = [{"ipProtocol": "tcp", "ports": ["22"]}]
    effective["firewallPolicys"].append({"name": "locations/global/firewallPolicies/100", "type": "HIERARCHY",
        "rules": [{"priority": 100, "direction": "INGRESS", "action": "goto_next",
                   "match": {"srcIpRanges": ["0.0.0.0/0"], "layer4Configs": []}}]})
    assert finding()["status"] == "FAIL"
    effective["firewallPolicys"].pop()
    effective["firewallPolicys"].append({"name": "locations/global/firewallPolicies/g", "type": "NETWORK", "rules": []})
    assert finding()["status"] == "FAIL"
    effective["firewallPolicys"][-1]["rules"] = [{"priority": 100, "direction": "INGRESS", "action": "allow",
        "match": {"srcIpRanges": ["8.8.8.0/24"], "layer4Configs": []}}]
    assert finding()["status"] == "UNKNOWN"
    effective["firewallPolicys"].pop()
    network["networkFirewallPolicyEnforcementOrder"] = "AFTER_CLASSIC_FIREWALL"
    assert finding()["status"] == "UNKNOWN"


def test_gcp_global_network_goto_next_reaches_regional_network_policy():
    vm = copy.deepcopy(gcp_instance())
    vm["items"][0]["selfLink"] = "https://compute.googleapis.com/compute/v1/projects/p1/zones/us-central1-a/instances/vm"
    network = {"name": "n", "selfLink": NET,
               "networkFirewallPolicyEnforcementOrder": "BEFORE_CLASSIC_FIREWALL"}
    global_rule = {"priority": 100, "ruleName": "continue", "direction": "INGRESS", "action": "goto_next",
                   "match": {"srcIpRanges": ["0.0.0.0/0"], "layer4Configs": []}}
    regional_rule = {"priority": 100, "ruleName": "regional-open", "direction": "INGRESS", "action": "allow",
                     "match": {"srcIpRanges": ["0.0.0.0/0"],
                               "layer4Configs": [{"ipProtocol": "tcp", "ports": ["22"]}]}}
    effective = {"name": "projects/p1/zones/us-central1-a/instances/vm/interfaces/nic0/effectiveFirewalls",
                 "instance": "projects/p1/zones/us-central1-a/instances/vm", "networkInterface": "nic0",
                 "firewalls": [fw("classic-deny", 1000, "denied", ["22"])],
                 "firewallPolicys": [
                     {"name": "locations/global/firewallPolicies/g", "type": "NETWORK", "rules": [global_rule]},
                     {"name": "regions/us-central1/firewallPolicies/r", "type": "NETWORK_REGIONAL", "rules": [regional_rule]}],
                 "effective_source_operation": "instances.getEffectiveFirewalls"}
    def finding():
        return one(gcp(vm, gcoll("network", [network]),
                       gcoll("instance_effective_firewall", [effective])), "instance")
    result = finding()
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/22"]
    assert any(step["layer"] == "network_transition" and step["decision"] == "goto_next"
               for step in result["evidence"]["path"])
    assert_gcp_observed_style(result, "vm")
    global_rule["match"]["layer4Configs"] = [{"ipProtocol": "tcp", "ports": ["22"]}]
    regional_rule["match"]["layer4Configs"] = []
    result = finding()
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/22"]
    regional_rule["action"] = "deny"
    result = finding()
    assert result["status"] == "UNKNOWN"
    assert "global network policy" in result["evidence"]["observed"]
    assert_gcp_observed_style(result, "vm")
    regional_rule["action"] = "allow"
    network["networkFirewallPolicyEnforcementOrder"] = "AFTER_CLASSIC_FIREWALL"
    assert finding()["status"] == "UNKNOWN"


def test_gcp_regional_system_goto_next_reaches_before_classic_network_policy():
    vm = copy.deepcopy(gcp_instance())
    vm["items"][0]["selfLink"] = "https://compute.googleapis.com/compute/v1/projects/p1/zones/us-central1-a/instances/vm"
    network = {"name": "n", "selfLink": NET,
               "networkFirewallPolicyEnforcementOrder": "BEFORE_CLASSIC_FIREWALL"}
    system_rule = {"priority": 100, "ruleName": "system-continue", "direction": "INGRESS", "action": "goto_next",
                   "match": {"srcIpRanges": ["0.0.0.0/0"], "layer4Configs": []}}
    network_rule = {"priority": 100, "ruleName": "network-open", "direction": "INGRESS", "action": "allow",
                    "match": {"srcIpRanges": ["0.0.0.0/0"],
                              "layer4Configs": [{"ipProtocol": "tcp", "ports": ["22"]}]}}
    effective = {"name": "projects/p1/zones/us-central1-a/instances/vm/interfaces/nic0/effectiveFirewalls",
                 "instance": "projects/p1/zones/us-central1-a/instances/vm", "networkInterface": "nic0",
                 "firewalls": [fw("classic-deny", 1000, "denied", ["22"])],
                 "firewallPolicys": [
                     {"name": "regions/us-central1/firewallPolicies/system", "type": "SYSTEM_REGIONAL", "rules": [system_rule]},
                     {"name": "locations/global/firewallPolicies/global", "type": "NETWORK", "rules": [network_rule]}],
                 "effective_source_operation": "instances.getEffectiveFirewalls"}
    def finding():
        return one(gcp(vm, gcoll("network", [network]),
                       gcoll("instance_effective_firewall", [effective])), "instance")
    result = finding()
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/22"]
    assert any(step["layer"] == "system_transition" for step in result["evidence"]["path"])
    assert_gcp_observed_style(result, "vm")
    system_rule["match"]["layer4Configs"] = [{"ipProtocol": "tcp", "ports": ["22"]}]
    network_rule["match"]["layer4Configs"] = []
    result = finding()
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/22"]
    network_rule["action"] = "deny"
    result = finding()
    assert result["status"] == "UNKNOWN"
    assert "regional system policy" in result["evidence"]["observed"]
    assert_gcp_observed_style(result, "vm")
    network_rule["action"] = "allow"
    effective["firewallPolicys"][1]["type"] = "NETWORK_REGIONAL"
    assert finding()["status"] == "FAIL"
    system_rule["match"]["srcIpRanges"] = ["8.8.8.0/24"]
    assert finding()["status"] == "UNKNOWN"
    system_rule["match"]["srcIpRanges"] = ["0.0.0.0/0"]
    network["networkFirewallPolicyEnforcementOrder"] = "AFTER_CLASSIC_FIREWALL"
    assert finding()["status"] == "UNKNOWN"


def test_gcp_classic_allow_precedes_network_policy_after_resolved_higher_layers():
    vm = copy.deepcopy(gcp_instance())
    vm["items"][0]["selfLink"] = "https://compute.googleapis.com/compute/v1/projects/p1/zones/us-central1-a/instances/vm"
    network = {"name": "n", "selfLink": NET,
               "networkFirewallPolicyEnforcementOrder": "AFTER_CLASSIC_FIREWALL"}
    hierarchy = {"priority": 100, "ruleName": "hierarchy-continue", "direction": "INGRESS", "action": "goto_next",
                 "match": {"srcIpRanges": ["0.0.0.0/0"], "layer4Configs": []}}
    system = {"priority": 100, "ruleName": "system-continue", "direction": "INGRESS", "action": "goto_next",
              "match": {"srcIpRanges": ["0.0.0.0/0"], "layer4Configs": []}}
    effective = {"name": "projects/p1/zones/us-central1-a/instances/vm/interfaces/nic0/effectiveFirewalls",
                 "instance": "projects/p1/zones/us-central1-a/instances/vm", "networkInterface": "nic0",
                 "firewalls": [fw("classic-open", 1000, "allowed", ["22"])],
                 "firewallPolicys": [
                     {"name": "locations/global/firewallPolicies/100", "type": "HIERARCHY", "rules": [hierarchy]},
                     {"name": "regions/us-central1/firewallPolicies/system", "type": "SYSTEM_REGIONAL", "rules": [system]},
                     {"name": "locations/global/firewallPolicies/g", "type": "NETWORK", "rules": [
                         {"priority": 100, "direction": "INGRESS", "action": "deny",
                          "match": {"srcIpRanges": ["0.0.0.0/0"], "layer4Configs": []}}]}],
                 "effective_source_operation": "instances.getEffectiveFirewalls"}
    def finding():
        return one(gcp(vm, gcoll("network", [network]),
                       gcoll("instance_effective_firewall", [effective])), "instance")
    result = finding()
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/22"]
    assert "classic rule classic-open" in result["evidence"]["observed"]
    assert_gcp_observed_style(result, "vm")
    network.pop("networkFirewallPolicyEnforcementOrder")
    assert finding()["status"] == "FAIL"
    network["networkFirewallPolicyEnforcementOrder"] = "AFTER_CLASSIC_FIREWALL"
    effective["firewalls"][0]["sourceTags"] = ["trusted"]
    assert finding()["status"] == "UNKNOWN"
    effective["firewalls"][0].pop("sourceTags")
    effective["firewalls"][0]["destinationRanges"] = ["10.0.0.0/8"]
    assert finding()["status"] == "UNKNOWN"
    effective["firewalls"][0].pop("destinationRanges")
    effective["firewalls"][0]["allowed"][0]["ports"] = ["invalid"]
    assert finding()["status"] == "UNKNOWN"
    effective["firewalls"][0]["allowed"][0]["ports"] = ["22"]
    system["match"]["layer4Configs"] = [{"ipProtocol": "tcp", "ports": ["22"]}]
    effective["firewalls"][0]["allowed"][0]["ports"] = ["22", "80"]
    result = finding()
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/22"]
    effective["firewalls"][0]["allowed"][0]["ports"] = ["80"]
    result = finding()
    assert result["status"] == "UNKNOWN"
    assert_gcp_observed_style(result, "vm")
    network["networkFirewallPolicyEnforcementOrder"] = "BEFORE_CLASSIC_FIREWALL"
    assert finding()["status"] != "FAIL"


def test_gcp_classic_allow_matches_public_interface_address_family():
    vm = copy.deepcopy(gcp_instance())
    vm["items"][0]["selfLink"] = "https://compute.googleapis.com/compute/v1/projects/p1/zones/us-central1-a/instances/vm"
    interface = vm["items"][0]["networkInterfaces"][0]
    interface["accessConfigs"] = []
    interface["ipv6AccessConfigs"] = [{"externalIpv6": "2600:1900::1"}]
    effective = {"name": "projects/p1/zones/us-central1-a/instances/vm/interfaces/nic0/effectiveFirewalls",
                 "instance": "projects/p1/zones/us-central1-a/instances/vm", "networkInterface": "nic0",
                 "firewalls": [fw("classic-open", 1000, "allowed", ["22"], sources=())],
                 "firewallPolicys": [{"name": "locations/global/firewallPolicies/g", "type": "NETWORK", "rules": []}],
                 "effective_source_operation": "instances.getEffectiveFirewalls"}
    network = {"name": "n", "selfLink": NET, "networkFirewallPolicyEnforcementOrder": "AFTER_CLASSIC_FIREWALL"}
    def finding():
        return one(gcp(vm, gcoll("network", [network]), gcoll("instance_effective_firewall", [effective])), "instance")
    result = finding()
    assert result["status"] == "UNKNOWN"
    assert_gcp_observed_style(result, "vm")
    effective["firewalls"][0]["sourceRanges"] = ["::/0"]
    result = finding()
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/22"]
    assert_gcp_observed_style(result, "vm")


def test_gcp_empty_classic_vpc_rules_continue_to_network_policy_after_classic():
    vm = copy.deepcopy(gcp_instance())
    vm["items"][0]["selfLink"] = "https://compute.googleapis.com/compute/v1/projects/p1/zones/us-central1-a/instances/vm"
    network = {"name": "n", "selfLink": NET,
               "networkFirewallPolicyEnforcementOrder": "AFTER_CLASSIC_FIREWALL"}
    network_rule = {"priority": 100, "ruleName": "network-https", "direction": "INGRESS", "action": "allow",
                    "match": {"srcIpRanges": ["0.0.0.0/0"],
                              "layer4Configs": [{"ipProtocol": "tcp", "ports": ["443"]}]}}
    effective = {"name": "projects/p1/zones/us-central1-a/instances/vm/interfaces/nic0/effectiveFirewalls",
                 "instance": "projects/p1/zones/us-central1-a/instances/vm", "networkInterface": "nic0",
                 "firewalls": [],
                 "firewallPolicys": [{"name": "locations/global/firewallPolicies/g", "type": "NETWORK",
                                     "rules": [network_rule]}],
                 "effective_source_operation": "instances.getEffectiveFirewalls"}
    def finding():
        return one(gcp(vm, gcoll("network", [network]),
                       gcoll("instance_effective_firewall", [effective])), "instance")
    result = finding()
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/443"]
    assert any(step["layer"] == "classic_transition" and step["vpc_rule_count"] == 0
               for step in result["evidence"]["path"])
    assert "network-https" in result["evidence"]["observed"]
    assert_gcp_observed_style(result, "vm")
    network.pop("networkFirewallPolicyEnforcementOrder")
    assert finding()["status"] == "FAIL"
    effective["firewalls"] = [fw("classic-deny", 1000, "denied", ["443"])]
    result = finding()
    assert result["status"] == "UNKNOWN"
    assert_gcp_observed_style(result, "vm")
    effective["firewalls"] = []
    effective["firewallPolicys"].append({"name": "unexpected", "type": "UNKNOWN_TYPE", "rules": []})
    assert finding()["status"] == "UNKNOWN"
    effective["firewallPolicys"].pop()
    effective["firewalls"] = [fw("private-only", 1000, "denied", ["443"], sources=("10.0.0.0/8",))]
    result = finding()
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/443"]
    assert any(step["layer"] == "classic_transition" and step["vpc_rule_count"] == 1
               for step in result["evidence"]["path"])
    effective["firewalls"][0]["sourceRanges"] = ["0.0.0.0/0"]
    assert finding()["status"] == "UNKNOWN"
    effective["firewalls"][0]["targetTags"] = ["other"]
    assert finding()["status"] == "FAIL"
    effective["firewalls"][0].pop("targetTags")
    effective["firewalls"][0]["disabled"] = True
    assert finding()["status"] == "FAIL"


def test_gcp_hierarchical_firewall_skips_private_only_earlier_rule_for_public_vm():
    vm = copy.deepcopy(gcp_instance())
    vm["items"][0]["selfLink"] = "https://compute.googleapis.com/compute/v1/projects/p1/zones/us-central1-a/instances/vm"
    private_rule = {"priority": 100, "ruleName": "private-ssh", "direction": "INGRESS", "action": "allow",
                    "match": {"srcIpRanges": ["10.0.0.0/8", "fc00::/7"],
                              "layer4Configs": [{"ipProtocol": "tcp", "ports": ["22"]}]}}
    public_rule = {"priority": 200, "ruleName": "public-all", "direction": "INGRESS", "action": "deny",
                   "match": {"srcIpRanges": ["0.0.0.0/0"], "layer4Configs": []}}
    effective = {"name": "projects/p1/zones/us-central1-a/instances/vm/interfaces/nic0/effectiveFirewalls",
                 "instance": "projects/p1/zones/us-central1-a/instances/vm", "networkInterface": "nic0",
                 "firewalls": [fw("allow-ssh", 1000, "allowed", ["22"])],
                 "firewallPolicys": [{"name": "org-policy", "type": "HIERARCHY", "rules": [private_rule, public_rule]}],
                 "effective_source_operation": "instances.getEffectiveFirewalls"}

    def assessment():
        return one(gcp(vm, gcoll("firewall", [], status="denied"),
                       gcoll("instance_effective_firewall", [effective])), "instance")

    assert assessment()["status"] == "PASS"
    public_rule["action"] = "allow"
    assert assessment()["status"] == "FAIL"
    assert_gcp_observed_style(assessment(), "vm")
    public_rule["match"]["layer4Configs"] = [{"ipProtocol": "tcp", "ports": ["22"]}]
    result = assessment()
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/22"]
    assert any(gap["layer"] == "firewall" and gap["decisive"] is False
               for gap in result["evidence"]["unresolved"])
    assert_gcp_observed_style(result, "vm")
    public_rule["action"] = "deny"
    assert assessment()["status"] == "UNKNOWN"
    public_rule["action"] = "allow"
    public_rule["match"]["layer4Configs"][0]["ports"] = ["70000"]
    assert assessment()["status"] == "UNKNOWN"
    public_rule["match"]["layer4Configs"] = []
    private_rule["match"]["srcIpRanges"].append("8.8.8.0/24")
    assert assessment()["status"] == "UNKNOWN"
    private_rule["match"]["srcIpRanges"].pop()
    private_rule["match"]["srcSecureTags"] = [{"name": "tagValues/123", "state": "EFFECTIVE"}]
    assert assessment()["status"] == "UNKNOWN"
    private_rule["match"].pop("srcSecureTags")
    private_rule["match"]["srcIpRanges"] = ["invalid"]
    assert assessment()["status"] == "UNKNOWN"


def test_gcp_hierarchical_port_deny_excludes_later_allow_subset():
    vm = copy.deepcopy(gcp_instance())
    vm["items"][0]["selfLink"] = "https://compute.googleapis.com/compute/v1/projects/p1/zones/us-central1-a/instances/vm"
    deny = {"priority": 100, "ruleName": "deny-443", "direction": "INGRESS", "action": "deny",
            "match": {"srcIpRanges": ["0.0.0.0/0"],
                      "layer4Configs": [{"ipProtocol": "tcp", "ports": ["443"]}]}}
    allow = {"priority": 200, "ruleName": "allow-web-range", "direction": "INGRESS", "action": "allow",
             "match": {"srcIpRanges": ["0.0.0.0/0"],
                       "layer4Configs": [{"ipProtocol": "tcp", "ports": ["443-445"]}]}}
    effective = {"name": "projects/p1/zones/us-central1-a/instances/vm/interfaces/nic0/effectiveFirewalls",
                 "instance": "projects/p1/zones/us-central1-a/instances/vm", "networkInterface": "nic0",
                 "firewalls": [fw("allow-ssh", 1000, "allowed", ["22"])],
                 "firewallPolicys": [{"name": "org-policy", "type": "HIERARCHY", "rules": [allow, deny]}],
                 "effective_source_operation": "instances.getEffectiveFirewalls"}
    def assessment():
        return one(gcp(vm, gcoll("firewall", [], status="denied"),
                       gcoll("instance_effective_firewall", [effective])), "instance")
    result = assessment()
    assert result["status"] == "FAIL"
    assert result["evidence"]["exposed_ports"] == ["tcp/444-445"]
    assert_gcp_observed_style(result, "vm")
    deny["match"]["layer4Configs"][0]["ports"] = ["443-445"]
    assert assessment()["status"] == "UNKNOWN"
    deny["match"]["layer4Configs"][0]["ports"] = ["443"]
    deny["match"]["srcIpRanges"] = ["8.8.8.0/24"]
    assert assessment()["status"] == "UNKNOWN"
    deny["match"]["srcIpRanges"] = ["0.0.0.0/0"]
    deny["match"]["layer4Configs"][0]["ports"] = ["70000"]
    assert assessment()["status"] == "UNKNOWN"


def test_gcp_multiple_hierarchical_policies_use_ancestor_association_order():
    vm = copy.deepcopy(gcp_instance())
    vm["items"][0]["selfLink"] = "https://compute.googleapis.com/compute/v1/projects/p1/zones/us-central1-a/instances/vm"
    ancestry = [{"resourceId": {"type": "project", "id": "p1"}},
                {"resourceId": {"type": "folder", "id": "20"}},
                {"resourceId": {"type": "organization", "id": "10"}}]
    project = {"name": GSCOPE, "_ancestry": ancestry}
    org_rule = {"priority": 100, "ruleName": "org-allow", "direction": "INGRESS", "action": "allow",
                "match": {"srcIpRanges": ["0.0.0.0/0"], "layer4Configs": []}}
    folder_rule = {"priority": 100, "ruleName": "folder-deny", "direction": "INGRESS", "action": "deny",
                   "match": {"srcIpRanges": ["0.0.0.0/0"], "layer4Configs": []}}
    effective = {"name": "projects/p1/zones/us-central1-a/instances/vm/interfaces/nic0/effectiveFirewalls",
                 "instance": "projects/p1/zones/us-central1-a/instances/vm", "networkInterface": "nic0",
                 "firewalls": [fw("allow-ssh", 1000, "allowed", ["22"])],
                 "firewallPolicys": [
                     {"name": "locations/global/firewallPolicies/200", "type": "HIERARCHY", "rules": [folder_rule]},
                     {"name": "locations/global/firewallPolicies/100", "type": "HIERARCHY", "rules": [org_rule]}],
                 "effective_source_operation": "instances.getEffectiveFirewalls"}
    org_association = {"name": "org-association", "attachmentTarget": "organizations/10",
                       "firewallPolicyId": "100", "priority": 1000}
    folder_association = {"name": "folder-association", "attachmentTarget": "folders/20",
                          "firewallPolicyId": "200", "priority": 1000}
    def assessment():
        return one(gcp(vm, gcoll("project", [project], service="resourcemanager"),
                       gcoll("instance_effective_firewall", [effective]),
                       coll("firewall_policy_association", [org_association], scope="organizations/10", service="compute"),
                       coll("firewall_policy_association", [folder_association], scope="folders/20", service="compute")),
                   "instance")
    result = assessment()
    assert result["status"] == "FAIL"
    assert next(step for step in result["evidence"]["path"] if step["layer"] == "effective_firewall")["policy"] == \
        "locations/global/firewallPolicies/100"
    assert_gcp_observed_style(result, "vm")
    org_association["firewallPolicyId"] = "999"
    result = assessment()
    assert result["status"] == "UNKNOWN"
    assert_gcp_observed_style(result, "vm")
    org_association["firewallPolicyId"] = "100"
    org_rule["action"] = "goto_next"
    result = assessment()
    assert result["status"] == "PASS"
    assert any(step["layer"] == "hierarchy_transition" and step["policy"] == "locations/global/firewallPolicies/100"
               for step in result["evidence"]["path"])
    folder_rule["action"] = "allow"
    result = assessment()
    assert result["status"] == "FAIL"
    assert_gcp_observed_style(result, "vm")
    org_rule["action"] = "deny"
    org_rule["match"]["srcIpRanges"] = ["10.0.0.0/8"]
    assert assessment()["status"] == "FAIL"
    org_rule["match"]["srcIpRanges"] = ["0.0.0.0/0"]
    org_rule["action"] = "goto_next"
    org_rule["match"]["layer4Configs"] = [{"ipProtocol": "tcp", "ports": ["22"]}]
    result = assessment()
    assert result["status"] == "FAIL"
    terminal = next(step for step in result["evidence"]["path"] if step["layer"] == "effective_firewall")
    assert terminal["allowed_ports"] == ["tcp/22"]
    assert next(step for step in result["evidence"]["path"] if step["layer"] == "hierarchy_transition")["ports"] == ["tcp/22"]
    assert_gcp_observed_style(result, "vm")
    folder_rule["match"]["layer4Configs"] = [{"ipProtocol": "tcp", "ports": ["443"]}]
    result = assessment()
    assert result["status"] == "UNKNOWN"
    assert "tcp/22" in result["evidence"]["observed"]
    assert_gcp_observed_style(result, "vm")
    folder_rule["match"]["layer4Configs"] = []
    folder_rule["action"] = "deny"
    result = assessment()
    assert result["status"] == "UNKNOWN"
    assert_gcp_observed_style(result, "vm")


def test_gcp_bigtable_direct_cross_project_reader_grant():
    table = {"name": "projects/p1/instances/orders/tables/current",
             "iamPolicy": {"bindings": [{"role": "roles/bigtable.reader", "members": [
                 "serviceAccount:reader@other-project.iam.gserviceaccount.com"]}]},
             "_coverage": {"iamPolicy": {"status": "collected"}}}

    def findings():
        return [row for row in analyze(gcp(gcoll("bigtable_table", [table], service="bigtableadmin")))["findings"]
                if row["check_id"] == "analysis.gcp_bigtable_external_reader"]

    rows = findings()
    assert len(rows) == 1 and rows[0]["status"] == "FAIL"
    assert_gcp_observed_style(rows[0], table["name"])
    assert rows[0]["evidence"]["permission"] == "bigtable.tables.readRows"
    assert rows[0]["evidence"]["direct_reader_grants"][0]["service_account_project"] == "other-project"
    assert "successful reads are not established" in rows[0]["evidence"]["semantics"]
    table["iamPolicy"]["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}
    assert findings()[0]["status"] == "UNKNOWN"
    assert_gcp_observed_style(findings()[0], table["name"])
    table["iamPolicy"]["bindings"][0].pop("condition")
    table["iamPolicy"]["bindings"][0]["members"] = ["serviceAccount:reader@p1.iam.gserviceaccount.com"]
    assert findings() == []
    table["iamPolicy"]["bindings"][0]["members"] = ["serviceAccount:reader@other-project.iam.gserviceaccount.com"]
    table["iamPolicy"]["bindings"][0]["role"] = "roles/bigtable.viewer"
    assert findings() == []
    table["iamPolicy"]["bindings"][0]["role"] = "roles/bigtable.reader"
    table["_coverage"]["iamPolicy"]["status"] = "denied"
    assert findings() == []


def test_gcp_composer_airflow_web_server_network_allowlist():
    environment = {"name": "projects/p1/locations/us-central1/environments/airflow",
                   "state": "RUNNING", "config": {"airflowUri": "https://example-dot-us-central1.composer.googleusercontent.com",
                                                   "privateEnvironmentConfig": {"enablePrivateEnvironment": True}}}

    def assessment():
        return one(gcp(gcoll("composer_environment", [environment], service="composer")), "composer_environment")

    result = assessment()
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/443"]
    assert_gcp_observed_style(result, environment["name"])
    assert result["evidence"]["authenticated_endpoint"] is True
    control = environment["config"]["webServerNetworkAccessControl"] = {"allowedIpRanges": []}
    assert assessment()["status"] == "PASS"
    control["allowedIpRanges"] = [{"value": "10.0.0.0/8"}]
    assert assessment()["status"] == "PASS"
    control["allowedIpRanges"] = [{"value": "8.8.8.0/24"}]
    assert assessment()["status"] == "FAIL"
    control["allowedIpRanges"] = [{"value": "bad-cidr"}]
    assert assessment()["status"] == "UNKNOWN"
    assert_gcp_observed_style(assessment(), environment["name"])
    control["allowedIpRanges"] = []
    environment["state"] = "UPDATING"
    assert assessment()["status"] == "UNKNOWN"
    environment["state"] = "RUNNING"
    del environment["config"]["airflowUri"]
    assert assessment()["status"] == "UNKNOWN"


def test_gcp_source_repository_direct_cross_project_reader_grant():
    repo = {"name": "projects/p1/repos/application", "iamPolicy": {"bindings": [{
        "role": "roles/source.reader", "members": ["serviceAccount:builder@foreign-project.iam.gserviceaccount.com"]}]},
        "_coverage": {"iamPolicy": {"status": "collected"}}}

    def findings():
        return [row for row in analyze(gcp(gcoll("source_repository", [repo], service="sourcerepo")))["findings"]
                if row["check_id"] == "analysis.gcp_source_repository_external_reader"]

    rows = findings()
    assert len(rows) == 1 and rows[0]["status"] == "FAIL"
    assert_gcp_observed_style(rows[0], repo["name"])
    assert rows[0]["evidence"]["permission"] == "source.repos.get"
    assert rows[0]["evidence"]["direct_reader_grants"][0]["service_account_project"] == "foreign-project"
    repo["iamPolicy"]["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}
    assert findings()[0]["status"] == "UNKNOWN"
    assert_gcp_observed_style(findings()[0], repo["name"])
    repo["iamPolicy"]["bindings"][0].pop("condition")
    repo["iamPolicy"]["bindings"][0]["members"] = ["serviceAccount:builder@p1.iam.gserviceaccount.com"]
    assert findings() == []
    repo["iamPolicy"]["bindings"][0]["members"] = ["serviceAccount:builder@foreign-project.iam.gserviceaccount.com"]
    repo["iamPolicy"]["bindings"][0]["role"] = "roles/source.viewer"
    assert findings() == []
    repo["iamPolicy"]["bindings"][0]["role"] = "roles/source.reader"
    repo["_coverage"]["iamPolicy"]["status"] = "denied"
    assert findings() == []


def test_gcp_cloud_tasks_direct_cross_project_enqueuer_grant():
    queue = {"name": "projects/p1/locations/us-central1/queues/outbound", "state": "RUNNING",
             "hasTargetOverride": True, "iamPolicy": {"bindings": [{"role": "roles/cloudtasks.enqueuer",
             "members": ["serviceAccount:sender@foreign-project.iam.gserviceaccount.com"]}]},
             "_coverage": {"iamPolicy": {"status": "collected"}}}

    def findings():
        return [row for row in analyze(gcp(gcoll("cloudtasks_queue", [queue], service="cloudtasks")))["findings"]
                if row["check_id"] == "analysis.gcp_cloud_tasks_external_enqueuer"]

    rows = findings()
    assert len(rows) == 1 and rows[0]["status"] == "FAIL"
    assert_gcp_observed_style(rows[0], queue["name"])
    assert rows[0]["evidence"]["permission"] == "cloudtasks.tasks.create"
    assert rows[0]["evidence"]["direct_enqueuer_grants"][0]["service_account_project"] == "foreign-project"
    queue["iamPolicy"]["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}
    assert findings()[0]["status"] == "UNKNOWN"
    assert_gcp_observed_style(findings()[0], queue["name"])
    queue["iamPolicy"]["bindings"][0].pop("condition")
    queue["iamPolicy"]["bindings"][0]["members"] = ["serviceAccount:sender@p1.iam.gserviceaccount.com"]
    assert findings() == []
    queue["iamPolicy"]["bindings"][0]["members"] = ["serviceAccount:sender@foreign-project.iam.gserviceaccount.com"]
    queue["iamPolicy"]["bindings"][0]["role"] = "roles/cloudtasks.viewer"
    assert findings() == []
    queue["iamPolicy"]["bindings"][0]["role"] = "roles/cloudtasks.enqueuer"
    queue["_coverage"]["iamPolicy"]["status"] = "denied"
    assert findings() == []


def test_gcp_scheduler_oidc_http_target_declaration_keeps_uri_path_private():
    job = {"name": "projects/p1/locations/us-central1/jobs/send",
           "state": "ENABLED", "httpTarget": {
               "uri": "https://api.example.com/private-capability?token=hidden",
               "httpMethod": "POST", "oidcToken": {
                   "serviceAccountEmail": "scheduler@p1.iam.gserviceaccount.com",
                   "audience": "https://api.example.com/private-capability"}}}

    def findings():
        return [row for row in analyze(gcp(gcoll("scheduler_job", [job], service="cloudscheduler")))["findings"]
                if row["check_id"] == "analysis.gcp_scheduler_oidc_target"]

    rows = findings()
    assert len(rows) == 1 and rows[0]["status"] == "FAIL"
    assert_gcp_observed_style(rows[0], job["name"])
    evidence = rows[0]["evidence"]
    assert evidence["target_origin"] == "https://api.example.com"
    assert evidence["service_account"] == "scheduler@p1.iam.gserviceaccount.com"
    assert "private-capability" not in str(evidence) and "hidden" not in str(evidence)
    job["state"] = "PAUSED"
    assert findings() == []
    job["state"] = "ENABLED"
    job["httpTarget"]["uri"] = "http://10.0.0.1/internal"
    assert findings() == []
    job["httpTarget"]["uri"] = "https://api.example.com:invalid/path"
    assert findings() == []
    job["httpTarget"]["uri"] = "https://api.example.com/path"
    job["httpTarget"].pop("oidcToken")
    assert findings() == []


def test_gcp_pubsub_oidc_push_records_only_target_origin_and_data_impact():
    subscription = {"name": "projects/p1/subscriptions/customer-events", "state": "ACTIVE",
                    "pushConfig": {"pushEndpoint": "https://api.example.com/private-capability?token=hidden",
                                   "oidcToken": {"serviceAccountEmail": "push@p1.iam.gserviceaccount.com",
                                                 "audience": "https://api.example.com/private-capability"}}}

    def findings():
        return [row for row in analyze(gcp(gcoll("pubsub_subscription", [subscription], service="pubsub")))["findings"]
                if row["check_id"] == "analysis.gcp_pubsub_oidc_push"]

    rows = findings()
    assert len(rows) == 1 and rows[0]["status"] == "FAIL"
    assert_gcp_observed_style(rows[0], subscription["name"])
    evidence = rows[0]["evidence"]
    assert evidence["target_origin"] == "https://api.example.com"
    assert evidence["service_account"] == "push@p1.iam.gserviceaccount.com"
    assert "message data" in evidence["observed"].splitlines()[-1]
    assert "private-capability" not in str(evidence) and "hidden" not in str(evidence)
    subscription["pushConfig"]["pushEndpoint"] = "https://10.0.0.1/push"
    assert findings() == []
    subscription["pushConfig"]["pushEndpoint"] = "https://api.example.com/push"
    subscription["pushConfig"].pop("oidcToken")
    assert findings() == []


def test_gcp_artifact_registry_public_reader_grant():
    repo = {"name": "projects/p1/locations/us-central1/repositories/packages", "format": "DOCKER",
            "iamPolicy": {"bindings": [{"role": "roles/artifactregistry.reader", "members": ["allUsers"]}]},
            "_coverage": {"iamPolicy": {"status": "collected"}}}

    def findings():
        return [row for row in analyze(gcp(gcoll("artifact_repository", [repo], service="artifactregistry")))["findings"]
                if row["check_id"] == "analysis.gcp_artifact_public_reader"]

    rows = findings()
    assert len(rows) == 1 and rows[0]["status"] == "FAIL"
    assert_gcp_observed_style(rows[0], repo["name"])
    assert not any(row["check_id"] == "analysis.gcp_public_iam" for row in
                   analyze(gcp(gcoll("artifact_repository", [repo], service="artifactregistry")))["findings"])
    assert rows[0]["evidence"]["permission"] == "artifactregistry.repositories.downloadArtifacts"
    assert "successful downloads are not established" in rows[0]["evidence"]["semantics"]
    repo["iamPolicy"]["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}
    assert findings()[0]["status"] == "UNKNOWN"
    assert_gcp_observed_style(findings()[0], repo["name"])
    repo["iamPolicy"]["bindings"][0].pop("condition")
    repo["iamPolicy"]["bindings"][0]["members"] = ["allAuthenticatedUsers"]
    assert findings()[0]["status"] == "FAIL"
    repo["iamPolicy"]["bindings"][0]["role"] = "roles/artifactregistry.viewer"
    assert findings() == []
    assert any(row["check_id"] == "analysis.gcp_public_iam" for row in
               analyze(gcp(gcoll("artifact_repository", [repo], service="artifactregistry")))["findings"])
    repo["iamPolicy"]["bindings"][0]["role"] = "roles/artifactregistry.reader"
    repo["_coverage"]["iamPolicy"]["status"] = "denied"
    assert findings() == []


@pytest.mark.parametrize("kind,role,permission", [
    ("pubsub_topic", "roles/pubsub.publisher", "pubsub.topics.publish"),
    ("pubsub_subscription", "roles/pubsub.subscriber", "pubsub.subscriptions.consume"),
])
def test_gcp_pubsub_direct_public_publish_or_consume_grant(kind, role, permission):
    segment = "topics" if kind == "pubsub_topic" else "subscriptions"
    item = {"name": f"projects/p1/{segment}/messages",
            "iamPolicy": {"bindings": [{"role": role, "members": ["allUsers"]}]},
            "_coverage": {"iamPolicy": {"status": "collected"}}}

    def report():
        return analyze(gcp(gcoll(kind, [item], service="pubsub")))["findings"]

    rows = [row for row in report() if row["check_id"] == "analysis.gcp_pubsub_public_grant"]
    assert len(rows) == 1 and rows[0]["status"] == "FAIL"
    assert_gcp_observed_style(rows[0], item["name"])
    assert rows[0]["evidence"]["permission"] == permission
    assert not any(row["check_id"] == "analysis.gcp_public_iam" for row in report())
    item["iamPolicy"]["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}
    rows = [row for row in report() if row["check_id"] == "analysis.gcp_pubsub_public_grant"]
    assert len(rows) == 1 and rows[0]["status"] == "UNKNOWN"
    assert_gcp_observed_style(rows[0], item["name"])
    item["iamPolicy"]["bindings"][0].pop("condition")
    item["iamPolicy"]["bindings"][0]["members"] = ["allAuthenticatedUsers"]
    assert any(row["check_id"] == "analysis.gcp_pubsub_public_grant" for row in report())
    item["iamPolicy"]["bindings"][0]["role"] = "roles/pubsub.viewer"
    assert not any(row["check_id"] == "analysis.gcp_pubsub_public_grant" for row in report())
    assert any(row["check_id"] == "analysis.gcp_public_iam" for row in report())
    item["iamPolicy"]["bindings"][0]["role"] = role
    item["_coverage"]["iamPolicy"]["status"] = "denied"
    assert not any(row["check_id"] == "analysis.gcp_pubsub_public_grant" for row in report())


def test_gcp_secret_direct_cross_project_accessor_grant():
    secret = {"name": "projects/p1/secrets/api-key",
              "iamPolicy": {"bindings": [{"role": "roles/secretmanager.secretAccessor",
                             "members": ["serviceAccount:reader@foreign-project.iam.gserviceaccount.com"]}]},
              "_coverage": {"iamPolicy": {"status": "collected"}}}

    def findings():
        return [row for row in analyze(gcp(gcoll("secret", [secret], service="secretmanager")))["findings"]
                if row["check_id"] == "analysis.gcp_secret_external_accessor"]

    rows = findings()
    assert len(rows) == 1 and rows[0]["status"] == "FAIL"
    assert_gcp_observed_style(rows[0], secret["name"])
    assert rows[0]["evidence"]["permission"] == "secretmanager.versions.access"
    assert rows[0]["evidence"]["direct_accessor_grants"][0]["service_account_project"] == "foreign-project"
    secret["iamPolicy"]["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}
    assert findings()[0]["status"] == "UNKNOWN"
    assert_gcp_observed_style(findings()[0], secret["name"])
    secret["iamPolicy"]["bindings"][0].pop("condition")
    secret["iamPolicy"]["bindings"][0]["members"] = ["serviceAccount:reader@p1.iam.gserviceaccount.com"]
    assert findings() == []
    secret["iamPolicy"]["bindings"][0]["members"] = ["serviceAccount:reader@foreign-project.iam.gserviceaccount.com"]
    secret["iamPolicy"]["bindings"][0]["role"] = "roles/secretmanager.viewer"
    assert findings() == []
    secret["iamPolicy"]["bindings"][0]["role"] = "roles/secretmanager.secretAccessor"
    secret["_coverage"]["iamPolicy"]["status"] = "denied"
    assert findings() == []


@pytest.mark.parametrize("role", ["roles/cloudkms.cryptoKeyDecrypter", "roles/cloudkms.cryptoKeyEncrypterDecrypter"])
def test_gcp_kms_direct_cross_project_decrypter_grant(role):
    key = {"name": "projects/p1/locations/global/keyRings/app/cryptoKeys/data", "purpose": "ENCRYPT_DECRYPT",
           "iamPolicy": {"bindings": [{"role": role,
                          "members": ["serviceAccount:reader@foreign-project.iam.gserviceaccount.com"]}]},
           "_coverage": {"iamPolicy": {"status": "collected"}}}

    def findings():
        return [row for row in analyze(gcp(gcoll("kms_key", [key], service="cloudkms")))["findings"]
                if row["check_id"] == "analysis.gcp_kms_external_decrypter"]

    rows = findings()
    assert len(rows) == 1 and rows[0]["status"] == "FAIL"
    assert_gcp_observed_style(rows[0], key["name"])
    assert rows[0]["evidence"]["permission"] == "cloudkms.cryptoKeyVersions.useToDecrypt"
    key["iamPolicy"]["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}
    assert findings()[0]["status"] == "UNKNOWN"
    assert_gcp_observed_style(findings()[0], key["name"])
    key["iamPolicy"]["bindings"][0].pop("condition")
    key["iamPolicy"]["bindings"][0]["members"] = ["serviceAccount:reader@p1.iam.gserviceaccount.com"]
    assert findings() == []
    key["iamPolicy"]["bindings"][0]["members"] = ["serviceAccount:reader@foreign-project.iam.gserviceaccount.com"]
    key["iamPolicy"]["bindings"][0]["role"] = "roles/cloudkms.viewer"
    assert findings() == []
    key["iamPolicy"]["bindings"][0]["role"] = role
    key["_coverage"]["iamPolicy"]["status"] = "denied"
    assert findings() == []


@pytest.mark.parametrize("kind,destination", [
    ("logging", "logging.googleapis.com/projects/foreign-project/locations/global/buckets/audit"),
    ("bigquery", "bigquery.googleapis.com/projects/foreign-project/datasets/audit"),
    ("pubsub", "pubsub.googleapis.com/projects/foreign-project/topics/audit"),
])
def test_gcp_logging_sink_declares_cross_project_destination(kind, destination):
    sink = {"name": "projects/p1/sinks/export", "destination": destination,
            "disabled": False, "writerIdentity": "serviceAccount:writer@p1.iam.gserviceaccount.com",
            "filter": "severity>=ERROR"}

    def findings():
        return [row for row in analyze(gcp(gcoll("log_sink", [sink], service="logging")))["findings"]
                if row["check_id"] == "analysis.gcp_logging_cross_project_sink"]

    rows = findings()
    assert len(rows) == 1 and rows[0]["status"] == "FAIL"
    assert_gcp_observed_style(rows[0], sink["name"])
    assert rows[0]["evidence"]["destination_kind"] == kind
    assert rows[0]["evidence"]["destination_project"] == "foreign-project"
    assert "sensitive log data" in rows[0]["evidence"]["observed"].splitlines()[-1]
    sink["disabled"] = True
    assert findings() == []
    sink["disabled"] = False
    sink["destination"] = destination.replace("foreign-project", "p1")
    assert findings() == []
    sink["destination"] = "storage.googleapis.com/bucket-with-unknown-owner"
    assert findings() == []
    sink["destination"] = destination.replace("foreign-project", "123456789012")
    assert findings() == []  # Project number may name the same project as source ID.


def test_gcp_bigquery_legacy_acl_and_authorized_resource():
    public = {"name": "projects/p1/datasets/shared", "datasetReference": {"projectId": "p1", "datasetId": "shared"},
              "access": [{"role": "READER", "specialGroup": "allAuthenticatedUsers"}]}
    result = one(gcp(gcoll("bigquery_dataset", [public], service="bigquery")), "bigquery_dataset")
    assert result["status"] == "FAIL" and result["evidence"]["data_exposure"]
    assert result["evidence"]["authenticated_endpoint"]
    public["access"][0]["role"] = "roles/bigquery.metadataViewer"
    assert one(gcp(gcoll("bigquery_dataset", [public], service="bigquery")), "bigquery_dataset")["status"] == "UNKNOWN"
    public["access"][0]["role"] = "READER"
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
    delegated["access"] = [{"routine": {"projectId": "foreign", "datasetId": "api", "routineId": "r"},
                            "role": "roles/bigquery.routineMetadataViewer"}]
    assert one(gcp(gcoll("bigquery_dataset", [delegated], service="bigquery")), "bigquery_dataset")["status"] == "UNKNOWN"
    delegated["access"][0]["role"] = "roles/bigquery.routineDataViewer"
    assert one(gcp(gcoll("bigquery_dataset", [delegated], service="bigquery")), "bigquery_dataset")["status"] == "FAIL"


def test_gcp_authorized_resource_uses_scanned_project_id_and_number_boundary():
    source = {"name": "projects/p1/datasets/source", "access": [
        {"view": {"projectId": "123", "datasetId": "views", "tableId": "v"}}]}
    project = {"name": "projects/p1", "projectId": "p1", "projectNumber": "123"}
    result = one(gcp(gcoll("project", [project], service="cloudresourcemanager"),
                     gcoll("bigquery_dataset", [source], service="bigquery")), "bigquery_dataset")
    assert result["status"] == "UNKNOWN"
    assert result["evidence"].get("external_scope_ids") == []
    source["access"][0]["view"]["projectId"] = "foreign"
    result = one(gcp(gcoll("project", [project], service="cloudresourcemanager"),
                     gcoll("bigquery_dataset", [source], service="bigquery")), "bigquery_dataset")
    assert result["status"] == "FAIL" and result["evidence"]["external_scope_ids"] == ["foreign"]


def test_gcp_authorized_resources_join_public_destination_in_other_scanned_project():
    from peaso.analysis.internet_exposure import Inventory, _gcp_bigquery_dataset
    from peaso.snapshot import resources
    source = {"name": "projects/p1/datasets/source", "access": [
        {"view": {"projectId": "p2", "datasetId": "shared", "tableId": "v"}},
        {"routine": {"projectId": "p2", "datasetId": "shared", "routineId": "r"}}]}
    destination = {"name": "projects/p2/datasets/shared", "access": [
        {"role": "READER", "specialGroup": "allUsers"}]}
    project = {"name": "projects/p2", "projectId": "p2", "projectNumber": "222"}
    role = {"name": "projects/p2/roles/publicReader", "includedPermissions": [
        "bigquery.tables.getData", "bigquery.routines.get"]}
    view = {"name": "projects/p2/datasets/shared/tables/v", "type": "VIEW", "iamPolicy": {"bindings": []}}
    routine = {"name": "projects/p2/datasets/shared/routines/r", "routineType": "PROCEDURE",
               "iamPolicy": {"bindings": []}}
    def assessment():
        snap = make_snapshot("gcp", ["projects/p1", "projects/p2"], [
            gcoll("bigquery_dataset", [source], service="bigquery"),
            coll("project", [project], scope="projects/p2", service="cloudresourcemanager"),
            coll("iam_role", [role], scope="projects/p2", service="iam"),
            coll("bigquery_dataset", [destination], scope="projects/p2", service="bigquery"),
            coll("bigquery_table", [view], scope="projects/p2", service="bigquery"),
            coll("bigquery_routine_metadata", [routine], scope="projects/p2", service="bigquery")],
            created_at="2026-10-10T00:00:00+00:00")
        items = resources(snap)
        current = next(row for row in items if row["type"] == "bigquery_dataset" and row["data"]["name"] == source["name"])
        return _gcp_bigquery_dataset(snap, Inventory(snap, items), current)
    result = assessment()
    assert result.verdict() == "FAIL"
    assert result.external_ids == []
    assert len(result.path[-1]["public_views"]) == len(result.path[-1]["public_routines"]) == 1
    source["access"][0]["view"]["projectId"] = "222"
    source["access"][1]["routine"]["projectId"] = "222"
    assert assessment().verdict() == "FAIL"
    destination["access"] = []
    assert assessment().verdict() == "UNKNOWN"
    project["_inherited_iam_policies"] = [{"name": "folders/42", "ancestor": "folders/42",
        "bindings": [{"role": role["name"], "members": ["allUsers"]}]}]
    project["_coverage"] = {"_inherited_iam_policies": {"status": "collected"}}
    inherited = assessment()
    assert inherited.verdict() == "FAIL"
    assert inherited.path[-1]["public_views"][0]["inherited_public"][0]["scope"] == "folders/42"
    assert inherited.path[-1]["public_routines"][0]["inherited_public"][0]["scope"] == "folders/42"
    project["_coverage"]["_inherited_iam_policies"]["status"] = "partial"
    assert assessment().verdict() == "UNKNOWN"


def test_gcp_authorized_view_with_public_reader_exposes_source_dataset():
    from peaso.analysis.internet_exposure import Inventory, _gcp_bigquery_dataset
    from peaso.snapshot import resources
    source = {"name": "projects/p1/datasets/source", "access": [
        {"view": {"projectId": "p1", "datasetId": "views", "tableId": "public_view"}}]}
    target = {"name": "projects/p1/datasets/views", "access": [
        {"role": "READER", "specialGroup": "allUsers"}]}
    view = {"name": "projects/p1/datasets/views/tables/public_view", "type": "VIEW",
            "iamPolicy": {"bindings": []}}
    def assessment(table=view):
        snap = gcp(gcoll("bigquery_dataset", [source, target], service="bigquery"),
                   gcoll("bigquery_table", [table] if table else [], service="bigquery"))
        items = resources(snap)
        current = next(row for row in items if row["type"] == "bigquery_dataset" and row["data"]["name"] == source["name"])
        return _gcp_bigquery_dataset(snap, Inventory(snap, items), current)
    assert assessment().verdict() == "FAIL"
    target["access"] = []
    view["iamPolicy"]["bindings"] = [{"role": "roles/bigquery.dataViewer", "members": ["allUsers"]}]
    assert assessment().verdict() == "FAIL"
    view["iamPolicy"]["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}
    assert assessment().verdict() == "UNKNOWN"
    assert assessment(None).verdict() == "UNKNOWN"


def test_gcp_dataset_access_conditions_do_not_prove_public_or_delegated_read():
    from peaso.analysis.internet_exposure import Inventory, _gcp_bigquery_dataset
    from peaso.snapshot import resources
    condition = {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}
    source = {"name": "projects/p1/datasets/source", "access": [
        {"role": "READER", "iamMember": "allUsers", "condition": condition}]}
    def assessment():
        snap = gcp(gcoll("bigquery_dataset", [source], service="bigquery"))
        items = resources(snap)
        return _gcp_bigquery_dataset(snap, Inventory(snap, items), items[0])
    result = assessment()
    assert result.verdict() == "UNKNOWN"
    assert result.path[-1]["conditional_public"][0]["member"] == "allUsers"
    source["access"][0].pop("condition")
    assert assessment().verdict() == "FAIL"
    source["access"] = [{"view": {"projectId": "outside", "datasetId": "shared", "tableId": "v"},
                         "condition": condition}]
    result = assessment()
    assert result.verdict() == "UNKNOWN" and result.external_ids == []
    assert result.path[-1]["conditional_delegated"][0]["kind"] == "view"
    source["access"][0].pop("condition")
    assert assessment().verdict() == "FAIL"


def test_gcp_dataset_project_special_groups_join_project_and_ancestor_roles():
    from peaso.analysis.internet_exposure import Inventory, _gcp_bigquery_dataset
    from peaso.snapshot import resources
    dataset = {"name": "projects/p1/datasets/data", "access": [
        {"role": "READER", "specialGroup": "projectReaders"}]}
    policy = {"name": "projects/p1", "bindings": [{
        "role": "roles/viewer", "members": ["allUsers"]}]}
    project = {"name": "projects/123", "projectId": "p1", "projectNumber": "123",
               "_inherited_iam_policies": [],
               "_coverage": {"_inherited_iam_policies": {"status": "collected"}}}
    def assessment():
        snap = gcp(gcoll("bigquery_dataset", [dataset], service="bigquery"),
                   gcoll("iam_policy", [policy], service="cloudasset"),
                   gcoll("project", [project], service="cloudresourcemanager"))
        items = resources(snap)
        current = next(row for row in items if row["type"] == "bigquery_dataset")
        return _gcp_bigquery_dataset(snap, Inventory(snap, items), current)
    result = assessment()
    assert result.verdict() == "FAIL"
    assert result.path[-1]["grants"][0]["iam_role"] == "roles/viewer"
    policy["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}
    assert assessment().verdict() == "UNKNOWN"
    policy["bindings"][0].pop("condition")
    policy["bindings"][0]["role"] = "roles/editor"
    assert assessment() is None
    dataset["access"][0].update({"specialGroup": "projectWriters", "role": "WRITER"})
    assert assessment().verdict() == "FAIL"
    policy["bindings"][0]["members"] = ["serviceAccount:sa@outside.iam.gserviceaccount.com"]
    result = assessment()
    assert result.verdict() == "FAIL" and result.external_ids == ["outside"]
    policy["bindings"] = []
    dataset["access"][0].update({"specialGroup": "projectOwners", "role": "OWNER"})
    project["_inherited_iam_policies"] = [{"name": "folders/42", "ancestor": "folders/42",
        "bindings": [{"role": "roles/owner", "members": ["allUsers"]}]}]
    result = assessment()
    assert result.verdict() == "FAIL" and result.path[-1]["grants"][0]["scope"] == "folders/42"
    project["_coverage"]["_inherited_iam_policies"]["status"] = "partial"
    assert assessment().verdict() == "UNKNOWN"


def test_gcp_authorized_resources_join_destination_project_special_groups():
    from peaso.analysis.internet_exposure import Inventory, _gcp_bigquery_dataset
    from peaso.snapshot import resources
    source = {"name": "projects/p1/datasets/source", "access": [
        {"view": {"projectId": "p2", "datasetId": "shared", "tableId": "v"}},
        {"routine": {"projectId": "p2", "datasetId": "shared", "routineId": "r"}}]}
    target = {"name": "projects/p2/datasets/shared", "access": [
        {"role": "READER", "specialGroup": "projectReaders"}]}
    view = {"name": "projects/p2/datasets/shared/tables/v", "type": "VIEW", "iamPolicy": {"bindings": []}}
    routine = {"name": "projects/p2/datasets/shared/routines/r", "routineType": "PROCEDURE",
               "iamPolicy": {"bindings": []}}
    project = {"name": "projects/222", "projectId": "p2", "projectNumber": "222",
               "_inherited_iam_policies": [], "_coverage": {"_inherited_iam_policies": {"status": "collected"}}}
    policy = {"name": "projects/p2", "bindings": [{"role": "roles/viewer", "members": ["allUsers"]}]}
    def assessment():
        snap = make_snapshot("gcp", ["projects/p1", "projects/p2"], [
            coll("bigquery_dataset", [source], scope="projects/p1", service="bigquery"),
            coll("bigquery_dataset", [target], scope="projects/p2", service="bigquery"),
            coll("bigquery_table", [view], scope="projects/p2", service="bigquery"),
            coll("bigquery_routine_metadata", [routine], scope="projects/p2", service="bigquery"),
            coll("project", [project], scope="projects/p2", service="cloudresourcemanager"),
            coll("iam_policy", [policy], scope="projects/p2", service="cloudasset")],
            created_at="2026-10-10T00:00:00+00:00")
        items = resources(snap)
        current = next(row for row in items if row["type"] == "bigquery_dataset" and row["data"]["name"] == source["name"])
        return _gcp_bigquery_dataset(snap, Inventory(snap, items), current)
    result = assessment()
    assert result.verdict() == "FAIL"
    assert len(result.path[-1]["public_views"]) == len(result.path[-1]["public_routines"]) == 1
    assert result.path[-1]["public_views"][0]["dataset_project_grants"][0]["scope"] == "projects/p2"
    policy["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}
    assert assessment().verdict() == "UNKNOWN"
    policy["bindings"][0].pop("condition")
    policy["bindings"][0]["members"] = ["serviceAccount:sa@outside.iam.gserviceaccount.com"]
    result = assessment()
    assert result.verdict() == "FAIL" and result.external_ids == ["outside"]


def test_gcp_authorized_view_conditional_destination_dataset_acl_is_unknown():
    from peaso.analysis.internet_exposure import Inventory, _gcp_bigquery_dataset
    from peaso.snapshot import resources
    source = {"name": "projects/p1/datasets/source", "access": [
        {"view": {"projectId": "p1", "datasetId": "views", "tableId": "v"}}]}
    destination = {"name": "projects/p1/datasets/views", "access": [
        {"role": "READER", "iamMember": "allUsers", "condition": {"expression": "true"}}]}
    view = {"name": "projects/p1/datasets/views/tables/v", "type": "VIEW", "iamPolicy": {"bindings": []}}
    def assessment():
        snap = gcp(gcoll("bigquery_dataset", [source, destination], service="bigquery"),
                   gcoll("bigquery_table", [view], service="bigquery"))
        items = resources(snap)
        current = next(row for row in items if row["type"] == "bigquery_dataset" and row["data"]["name"] == source["name"])
        return _gcp_bigquery_dataset(snap, Inventory(snap, items), current)
    assert assessment().verdict() == "UNKNOWN"
    destination["access"][0].pop("condition")
    assert assessment().verdict() == "FAIL"


def test_gcp_authorized_dataset_public_view_joins_scheduled_table_inventory():
    from peaso.analysis.internet_exposure import GCP_TYPES, Inventory, _gcp_bigquery_dataset
    from peaso.snapshot import resources
    assert "bigquery_table" in GCP_TYPES
    source = {"name": "projects/p1/datasets/source", "access": [{"dataset": {
        "dataset": {"project_id": "p1", "dataset_id": "views"}, "target_types": ["VIEWS"]}}]}
    target = {"name": "projects/p1/datasets/views", "access": [
        {"role": "READER", "iamMember": "allUsers"}]}
    view = {"name": "projects/p1/datasets/views/tables/v", "type": "MATERIALIZED_VIEW",
            "iamPolicy": {"bindings": []}}
    def assessment(table=view):
        snap = gcp(gcoll("bigquery_dataset", [source, target], service="bigquery"),
                   gcoll("bigquery_table", [table] if table else [], service="bigquery"))
        items = resources(snap)
        current = next(row for row in items if row["type"] == "bigquery_dataset" and row["data"]["name"] == source["name"])
        return _gcp_bigquery_dataset(snap, Inventory(snap, items), current)
    result = assessment()
    assert result.verdict() == "FAIL"
    assert any(step["layer"] == "authorized_view" and step["public_views"][0]["authorization"] == "authorized_dataset"
               for step in result.path)
    assert assessment(None).verdict() == "UNKNOWN"


def test_gcp_authorized_routine_public_invocation_joins_cached_iam():
    from peaso.analysis.internet_exposure import GCP_TYPES, Inventory, _gcp_bigquery_dataset
    from peaso.snapshot import resources
    assert "bigquery_routine_metadata" in GCP_TYPES
    source = {"name": "projects/p1/datasets/source", "access": [{"routine": {
        "projectId": "p1", "datasetId": "api", "routineId": "run"}}]}
    target = {"name": "projects/p1/datasets/api", "access": []}
    routine = {"name": "projects/p1/datasets/api/routines/run", "routineType": "PROCEDURE",
               "iamPolicy": {"bindings": [{"role": "roles/bigquery.routineDataViewer", "members": ["allUsers"]}]}}
    def assessment():
        snap = gcp(gcoll("bigquery_dataset", [source, target], service="bigquery"),
                   gcoll("bigquery_routine_metadata", [routine], service="bigquery"))
        items = resources(snap)
        current = next(row for row in items if row["type"] == "bigquery_dataset" and row["data"]["name"] == source["name"])
        return _gcp_bigquery_dataset(snap, Inventory(snap, items), current)
    result = assessment()
    assert result.verdict() == "FAIL"
    assert any(step["layer"] == "authorized_routine" and step["public_routines"][0]["routine_type"] == "PROCEDURE"
               for step in result.path)
    routine["iamPolicy"]["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}
    assert assessment().verdict() == "UNKNOWN"
    target["access"] = [{"role": "READER", "iamMember": "allUsers"}]
    assert assessment().verdict() == "FAIL"


def test_gcp_authorized_resources_join_project_inherited_public_permissions():
    from peaso.analysis.internet_exposure import GCP_TYPES, Inventory, _gcp_bigquery_dataset
    from peaso.snapshot import resources
    assert {"iam_policy", "iam_role", "bigquery_table", "bigquery_routine_metadata"} <= set(GCP_TYPES)
    source = {"name": "projects/p1/datasets/source", "access": [
        {"view": {"projectId": "p1", "datasetId": "api", "tableId": "v"}},
        {"routine": {"projectId": "p1", "datasetId": "api", "routineId": "r"}}]}
    target = {"name": "projects/p1/datasets/api", "access": []}
    view = {"name": "projects/p1/datasets/api/tables/v", "type": "VIEW", "iamPolicy": {"bindings": []}}
    routine = {"name": "projects/p1/datasets/api/routines/r", "routineType": "PROCEDURE",
               "iamPolicy": {"bindings": []}}
    policy = {"name": "projects/p1", "bindings": [
        {"role": "projects/p1/roles/viewer", "members": ["allUsers"]},
        {"role": "projects/p1/roles/unrelated", "members": ["allAuthenticatedUsers"]}]}
    role = {"name": "projects/p1/roles/viewer", "includedPermissions": ["bigquery.tables.getData"]}
    unrelated = {"name": "projects/p1/roles/unrelated", "includedPermissions": ["bigquery.datasets.get"]}
    def assessment():
        snap = gcp(gcoll("bigquery_dataset", [source, target], service="bigquery"),
                   gcoll("bigquery_table", [view], service="bigquery"),
                   gcoll("bigquery_routine_metadata", [routine], service="bigquery"),
                   gcoll("iam_policy", [policy], service="cloudasset"),
                   gcoll("iam_role", [role, unrelated], service="iam"))
        items = resources(snap)
        current = next(row for row in items if row["type"] == "bigquery_dataset" and row["data"]["name"] == source["name"])
        return _gcp_bigquery_dataset(snap, Inventory(snap, items), current)
    result = assessment()
    assert result.verdict() == "FAIL"
    assert len(result.path[-1]["public_views"]) == 1
    assert not result.path[-1]["public_routines"]
    role["includedPermissions"] = ["bigquery.routines.get"]
    result = assessment()
    assert result.verdict() == "FAIL"
    assert not result.path[-1]["public_views"]
    assert len(result.path[-1]["public_routines"]) == 1
    policy["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}
    assert assessment().verdict() == "UNKNOWN"
    policy["bindings"][0].pop("condition")
    policy["name"] = "projects/unrelated"
    assert assessment().verdict() == "UNKNOWN"


def test_gcp_authorized_view_joins_verified_ancestor_public_readers():
    from peaso.analysis.internet_exposure import Inventory, _gcp_bigquery_dataset
    from peaso.snapshot import resources
    source = {"name": "projects/p1/datasets/source", "access": [
        {"view": {"projectId": "p1", "datasetId": "views", "tableId": "v"}}]}
    destination = {"name": "projects/p1/datasets/views", "access": []}
    view = {"name": "projects/p1/datasets/views/tables/v", "type": "VIEW",
            "iamPolicy": {"bindings": []}}
    ancestor = {"name": "folders/42", "ancestor": "folders/42", "bindings": [
        {"role": "roles/bigquery.dataViewer", "members": ["allUsers"]}]}
    project = {"name": "projects/p1", "_inherited_iam_policies": [ancestor],
               "_coverage": {"_inherited_iam_policies": {"status": "collected"}}}
    role = {"name": "roles/bigquery.dataViewer", "includedPermissions": ["bigquery.tables.getData"]}
    def assessment():
        snap = gcp(gcoll("bigquery_dataset", [source, destination], service="bigquery"),
                   gcoll("bigquery_table", [view], service="bigquery"),
                   gcoll("project", [project], service="cloudresourcemanager"),
                   gcoll("iam_role", [role], service="iam"))
        items = resources(snap)
        current = next(row for row in items if row["type"] == "bigquery_dataset" and row["data"]["name"] == source["name"])
        return _gcp_bigquery_dataset(snap, Inventory(snap, items), current)
    result = assessment()
    assert result.verdict() == "FAIL"
    assert result.path[-1]["public_views"][0]["inherited_public"][0]["scope"] == "folders/42"
    project["_coverage"]["_inherited_iam_policies"]["status"] = "partial"
    assert assessment().verdict() == "UNKNOWN"
    project["_coverage"]["_inherited_iam_policies"]["status"] = "collected"
    ancestor["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}
    assert assessment().verdict() == "UNKNOWN"


def test_gcp_authorized_routine_joins_verified_ancestor_public_invocation():
    from peaso.analysis.internet_exposure import Inventory, _gcp_bigquery_dataset
    from peaso.snapshot import resources
    source = {"name": "projects/p1/datasets/source", "access": [
        {"routine": {"projectId": "p1", "datasetId": "api", "routineId": "r"}}]}
    destination = {"name": "projects/p1/datasets/api", "access": []}
    routine = {"name": "projects/p1/datasets/api/routines/r", "routineType": "PROCEDURE",
               "iamPolicy": {"bindings": []}}
    project = {"name": "projects/p1", "_inherited_iam_policies": [
        {"name": "organizations/9", "ancestor": "organizations/9", "bindings": [
            {"role": "roles/bigquery.routineDataViewer", "members": ["allAuthenticatedUsers"]}]}],
        "_coverage": {"_inherited_iam_policies": {"status": "collected"}}}
    role = {"name": "roles/bigquery.routineDataViewer", "includedPermissions": ["bigquery.routines.get"]}
    def assessment():
        snap = gcp(gcoll("bigquery_dataset", [source, destination], service="bigquery"),
                   gcoll("bigquery_routine_metadata", [routine], service="bigquery"),
                   gcoll("project", [project], service="cloudresourcemanager"),
                   gcoll("iam_role", [role], service="iam"))
        items = resources(snap)
        current = next(row for row in items if row["type"] == "bigquery_dataset" and row["data"]["name"] == source["name"])
        return _gcp_bigquery_dataset(snap, Inventory(snap, items), current)
    result = assessment()
    assert result.verdict() == "FAIL"
    assert result.path[-1]["public_routines"][0]["inherited_public"][0]["scope"] == "organizations/9"
    assert result.path[-1]["public_routines"][0]["mutation_possible"] is True
    source["access"][0]["role"] = "roles/bigquery.routineMetadataViewer"
    assert assessment().verdict() == "UNKNOWN"
    source["access"][0]["role"] = "roles/bigquery.routineDataViewer"
    result = assessment()
    assert result.verdict() == "FAIL" and result.path[-1]["public_routines"][0]["mutation_possible"] is False
    source["access"][0]["role"] = "roles/bigquery.routineDataEditor"
    result = assessment()
    assert result.verdict() == "FAIL" and result.path[-1]["public_routines"][0]["mutation_possible"] is True


def test_gcp_authorized_resources_join_direct_custom_role_permissions():
    from peaso.analysis.internet_exposure import Inventory, _gcp_bigquery_dataset
    from peaso.snapshot import resources
    source = {"name": "projects/p1/datasets/source", "access": [
        {"view": {"projectId": "p1", "datasetId": "api", "tableId": "v"}},
        {"routine": {"projectId": "p1", "datasetId": "api", "routineId": "r"}}]}
    target = {"name": "projects/p1/datasets/api", "access": []}
    view_role = {"name": "projects/p1/roles/viewData", "includedPermissions": ["bigquery.tables.getData"]}
    routine_role = {"name": "projects/p1/roles/useRoutine", "includedPermissions": ["bigquery.routines.get"]}
    view = {"name": "projects/p1/datasets/api/tables/v", "type": "VIEW", "iamPolicy": {"bindings": [
        {"role": view_role["name"], "members": ["allUsers"]}]}}
    routine = {"name": "projects/p1/datasets/api/routines/r", "routineType": "PROCEDURE", "iamPolicy": {"bindings": [
        {"role": routine_role["name"], "members": ["allAuthenticatedUsers"]}]}}
    def assessment():
        snap = gcp(gcoll("bigquery_dataset", [source, target], service="bigquery"),
                   gcoll("bigquery_table", [view], service="bigquery"),
                   gcoll("bigquery_routine_metadata", [routine], service="bigquery"),
                   gcoll("iam_role", [view_role, routine_role], service="iam"))
        items = resources(snap)
        current = next(row for row in items if row["type"] == "bigquery_dataset" and row["data"]["name"] == source["name"])
        return _gcp_bigquery_dataset(snap, Inventory(snap, items), current)
    result = assessment()
    assert result.verdict() == "FAIL"
    assert len(result.path[-1]["public_views"]) == len(result.path[-1]["public_routines"]) == 1
    view_role["includedPermissions"] = ["bigquery.tables.get"]
    result = assessment()
    assert not result.path[-1]["public_views"] and len(result.path[-1]["public_routines"]) == 1
    routine_role["includedPermissions"] = ["bigquery.routines.list"]
    assert assessment().verdict() == "UNKNOWN"


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


def test_gcp_cloud_run_instance_public_url_invoker_and_state():
    instance = {"name": "projects/p1/locations/us-central1/instances/i", "ingress": "INGRESS_TRAFFIC_ALL",
                "urls": ["https://i.run.app/path?token=secret"], "reconciling": False,
                "terminalCondition": {"state": "CONDITION_SUCCEEDED"},
                "iamPolicy": {"bindings": [{"role": "roles/run.invoker", "members": ["allUsers"]}]}}
    def finding():
        return one(gcp(gcoll("cloudrun_instance", [instance], service="run")), "cloudrun_instance")
    result = finding()
    assert result["status"] == "FAIL"
    assert result["evidence"]["public_addresses"] == ["https://i.run.app"]
    assert "secret" not in str(result)
    assert_gcp_observed_style(result, instance["name"])
    instance["iamPolicy"]["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}
    assert finding()["status"] == "UNKNOWN"
    instance["iamPolicy"]["bindings"][0].pop("condition")
    instance["iamPolicy"]["bindings"] = []
    assert finding()["status"] == "UNKNOWN"
    instance["invokerIamDisabled"] = True
    assert finding()["status"] == "FAIL"
    instance["iapEnabled"] = True
    assert finding()["status"] == "UNKNOWN"
    instance["iapEnabled"] = False
    instance["reconciling"] = True
    assert finding()["status"] == "UNKNOWN"
    instance["reconciling"] = False
    instance["defaultUriDisabled"] = True
    assert finding()["status"] == "UNKNOWN"
    instance["defaultUriDisabled"] = False
    instance["ingress"] = "INGRESS_TRAFFIC_INTERNAL_ONLY"
    assert not exposure(gcp(gcoll("cloudrun_instance", [instance], service="run")), "cloudrun_instance")
    instance.pop("ingress")
    result = finding()
    assert result["status"] == "UNKNOWN"
    assert_gcp_observed_style(result, instance["name"])


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


def test_gcp_function_v2_joins_backing_cloud_run_service_access():
    service_name = "projects/p1/locations/r/services/f"
    function = {"name": "projects/p1/locations/r/functions/f", "serviceConfig": {
        "service": service_name, "uri": "https://f.cloudfunctions.net", "ingressSettings": "ALLOW_ALL"},
        "iamPolicy": {"bindings": []}}
    backing = {"name": service_name, "uri": "https://f.run.app", "ingress": "INGRESS_TRAFFIC_ALL",
               "iamPolicy": {"bindings": [{"role": "roles/run.invoker", "members": ["allUsers"]}]}}
    def finding(*rows):
        return one(gcp(gcoll("function", [function], service="cloudfunctions"), *rows), "function")
    assert finding(gcoll("cloudrun_service", [backing], service="run"))["status"] == "FAIL"
    backing["ingress"] = "INGRESS_TRAFFIC_INTERNAL_ONLY"
    assert finding(gcoll("cloudrun_service", [backing], service="run"))["status"] == "PASS"
    backing["ingress"] = "INGRESS_TRAFFIC_ALL"
    backing.pop("iamPolicy")
    assert finding(gcoll("cloudrun_service", [backing], service="run"))["status"] == "UNKNOWN"
    assert finding()["status"] == "UNKNOWN"


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


def test_gcp_public_url_map_redirect_without_backend_service():
    fr = {"name": "redirect-fr", "loadBalancingScheme": "EXTERNAL_MANAGED", "IPAddress": "34.2.2.2",
          "IPProtocol": "TCP", "portRange": "80-80", "target": "https://x/targetHttpProxies/p"}
    proxy = {"selfLink": fr["target"], "urlMap": "https://x/urlMaps/m"}
    url_map = {"selfLink": proxy["urlMap"], "defaultUrlRedirect": {
        "hostRedirect": "new.example.com", "httpsRedirect": True, "stripQuery": False,
        "redirectResponseCode": "MOVED_PERMANENTLY_DEFAULT"}}
    def finding():
        return one(gcp(gcoll("forwarding_rule", [fr]), gcoll("target_proxy", [proxy]),
                       gcoll("url_map", [url_map])), "forwarding_rule")
    result = finding()
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/80"]
    assert any(step["layer"] == "url_redirect" and step["routes"][0]["host_redirect"] == "new.example.com"
               for step in result["evidence"]["path"])
    assert_gcp_observed_style(result, "redirect-fr")
    url_map["hostRules"] = [{"hosts": ["old.example.com"], "pathMatcher": "redirect-matcher"}]
    url_map["pathMatchers"] = [{"name": "redirect-matcher", "defaultUrlRedirect": {
        "hostRedirect": "new.example.com", "stripQuery": True}}]
    url_map.pop("defaultUrlRedirect")
    result = finding()
    assert result["status"] == "FAIL"
    assert "stripQuery set to true" in result["evidence"]["observed"]
    url_map["pathMatchers"][0]["pathRules"] = [{"paths": ["/old/*"], "urlRedirect": {
        "hostRedirect": "new.example.com", "redirectResponseCode": "FOUND"}}]
    assert finding()["status"] == "FAIL"
    url_map["pathMatchers"][0]["pathRules"][0]["urlRedirect"]["redirectResponseCode"] = "BAD"
    assert finding()["status"] == "UNKNOWN"
    url_map["pathMatchers"][0]["pathRules"][0]["urlRedirect"]["redirectResponseCode"] = "FOUND"
    url_map["hostRules"][0]["pathMatcher"] = "unrelated"
    assert finding()["status"] == "UNKNOWN"
    url_map["hostRules"][0]["pathMatcher"] = "redirect-matcher"
    url_map["defaultService"] = "https://x/backendServices/missing"
    result = finding()
    assert result["status"] == "FAIL"
    assert any(gap["layer"] == "backend" and gap["decisive"] is False
               for gap in result["evidence"]["unresolved"])
    fr.pop("IPAddress")
    result = finding()
    assert result["status"] == "UNKNOWN"
    assert_gcp_observed_style(result, "redirect-fr")
    fr["IPAddress"] = "34.2.2.2"
    matcher = url_map["pathMatchers"][0]
    matcher.pop("pathRules")
    matcher["routeRules"] = [
        {"priority": 200, "matchRules": [{"prefixMatch": "/other"}],
         "service": "https://x/backendServices/missing"},
        {"priority": 100, "matchRules": [{"prefixMatch": "/"}],
         "urlRedirect": {"hostRedirect": "new.example.com", "redirectResponseCode": "FOUND"}}]
    result = finding()
    assert result["status"] == "FAIL"
    assert any(step["layer"] == "url_redirect" and step["routes"][0]["route"] == "first_route_rule"
               for step in result["evidence"]["path"])
    matcher["routeRules"][0]["priority"] = 50
    matcher["routeRules"][0]["matchRules"] = [{"prefixMatch": "/"}]
    assert finding()["status"] == "UNKNOWN"
    matcher["routeRules"][0]["priority"] = 200
    matcher["routeRules"][1]["matchRules"] = [{"prefixMatch": "/", "headerMatches": [{"headerName": "X-Test"}]}]
    assert finding()["status"] == "UNKNOWN"
    matcher["routeRules"][1]["matchRules"] = [{"prefixMatch": "/signin"}]
    result = finding()
    assert result["status"] == "FAIL"
    assert next(step for step in result["evidence"]["path"] if step["layer"] == "url_redirect")["routes"][0]["match_path"] == "/signin"
    assert "request path prefix /signin" in result["evidence"]["observed"]
    assert_gcp_observed_style(result, "redirect-fr")
    matcher["routeRules"][1]["matchRules"] = [{"fullPathMatch": "/signin/finish"}]
    result = finding()
    assert result["status"] == "FAIL"
    assert next(step for step in result["evidence"]["path"] if step["layer"] == "url_redirect")["routes"][0]["match_path_type"] == "fullPathMatch"
    assert "request path exact /signin/finish" in result["evidence"]["observed"]
    assert_gcp_observed_style(result, "redirect-fr")
    matcher["routeRules"][1]["matchRules"] = [{"prefixMatch": "signin"}]
    assert finding()["status"] == "UNKNOWN"
    matcher["routeRules"][1]["matchRules"] = [{"prefixMatch": "/signin", "queryParameterMatches": [{}]}]
    assert finding()["status"] == "UNKNOWN"
    matcher["routeRules"][0]["priority"] = 50
    matcher["routeRules"][0]["matchRules"] = [{"prefixMatch": "/api"}]
    matcher["routeRules"][1]["matchRules"] = [{"fullPathMatch": "/signin/finish"}]
    result = finding()
    assert result["status"] == "FAIL"
    assert next(step for step in result["evidence"]["path"] if step["layer"] == "url_redirect")["routes"][0]["route"] == "disjoint_route_rule"
    assert_gcp_observed_style(result, "redirect-fr")
    matcher["routeRules"][0]["matchRules"] = [{"prefixMatch": "/"}]
    assert finding()["status"] == "UNKNOWN"
    matcher["routeRules"][0]["matchRules"] = [{"prefixMatch": "/api"}, {"fullPathMatch": "/signin/finish"}]
    assert finding()["status"] == "UNKNOWN"


def test_gcp_http_url_map_default_redirect_for_unmatched_exact_host_rules():
    forwarding = {"name": "http-redirect", "IPAddress": "34.2.2.2", "IPProtocol": "TCP",
                  "portRange": "80-80", "loadBalancingScheme": "EXTERNAL_MANAGED",
                  "target": "https://x/targetHttpProxies/p"}
    proxy = {"selfLink": forwarding["target"], "urlMap": "https://x/urlMaps/m"}
    url_map = {"selfLink": proxy["urlMap"],
               "hostRules": [{"hosts": ["site.example.com"], "pathMatcher": "site"}],
               "pathMatchers": [{"name": "site", "defaultService": "https://x/backendServices/private"}],
               "defaultUrlRedirect": {"hostRedirect": "landing.example.com", "redirectResponseCode": "FOUND"}}
    def finding():
        return one(gcp(gcoll("forwarding_rule", [forwarding]), gcoll("target_proxy", [proxy]),
                       gcoll("url_map", [url_map])), "forwarding_rule")
    result = finding()
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/80"]
    route = next(step for step in result["evidence"]["path"] if step["layer"] == "url_redirect")["routes"][0]
    assert route["route"] == "unmatched_host_default" and route["host_witness"] == "peaso-unmatched.invalid"
    assert "unmatched host peaso-unmatched.invalid" in result["evidence"]["observed"]
    assert_gcp_observed_style(result, "http-redirect")
    url_map["hostRules"][0]["hosts"] = ["*.example.com", "*"]
    assert finding()["status"] == "UNKNOWN"
    url_map["hostRules"][0]["hosts"] = ["peaso-unmatched.invalid"]
    assert finding()["status"] == "UNKNOWN"
    url_map["hostRules"][0]["hosts"] = ["site.example.com"]
    forwarding["target"] = "https://x/targetHttpsProxies/p"
    proxy["selfLink"] = forwarding["target"]
    assert finding()["status"] == "UNKNOWN"


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
    assert_gcp_observed_style(result, "ha")
    gateway["vpnInterfaces"][0]["interconnectAttachment"] = "vlan"
    assert not exposure(gcp(gcoll("vpn_gateway", [gateway])))
    classic = {"name": "classic-esp", "IPAddress": "34.2.2.3", "IPProtocol": "ESP",
               "target": "https://compute.googleapis.com/compute/v1/projects/p1/regions/us/targetVpnGateways/vpn"}
    result = one(gcp(gcoll("forwarding_rule", [classic])), "forwarding_rule")
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["esp"]
    assert_gcp_observed_style(result, "classic-esp")


def test_gcp_established_ha_vpn_tunnel_joins_public_gateway_interface_and_external_peer():
    prefix = "https://compute.googleapis.com/compute/v1/projects/p1/regions/us/"
    gateway_ref = prefix + "vpnGateways/ha"
    gateway = {"name": "ha", "selfLink": gateway_ref,
               "vpnInterfaces": [{"id": 0, "ipAddress": "34.2.2.2"},
                                 {"id": 1, "ipAddress": "34.2.2.3"}]}
    tunnel = {"name": "peer-tunnel", "status": "ESTABLISHED", "vpnGateway": gateway_ref,
              "vpnGatewayInterface": 0, "peerExternalGateway": prefix + "externalVpnGateways/peer",
              "localTrafficSelector": ["10.0.0.0/8"]}
    def finding(gateways=None):
        return one(gcp(gcoll("vpn_gateway", [gateway] if gateways is None else gateways),
                       gcoll("vpn_tunnel", [tunnel])), "vpn_tunnel")
    result = finding()
    assert result["status"] == "FAIL"
    assert result["evidence"]["public_addresses"] == ["34.2.2.2"]
    assert result["evidence"]["exposed_ports"] == ["udp/500", "udp/4500", "esp"]
    assert "established" in result["title"].lower() and "peer gateway" in result["evidence"]["observed"]
    assert "10.0.0.0/8" not in result["evidence"]["observed"]  # selector is not a routed service path
    assert_gcp_observed_style(result, "peer-tunnel")
    result = finding([])
    assert result["status"] == "UNKNOWN"
    assert_gcp_observed_style(result, "peer-tunnel")
    gateway["vpnInterfaces"][0]["interconnectAttachment"] = "vlan"
    assert finding()["status"] == "UNKNOWN"
    gateway["vpnInterfaces"][0].pop("interconnectAttachment")
    tunnel["status"] = "STOPPED"
    assert not any("peer-tunnel" in str(row["evidence"]) for row in
                   exposure(gcp(gcoll("vpn_gateway", [gateway]), gcoll("vpn_tunnel", [tunnel]))))
    tunnel["status"] = "ESTABLISHED"
    tunnel.pop("peerExternalGateway")
    tunnel["peerGcpGateway"] = prefix + "vpnGateways/another"
    assert not any("peer-tunnel" in str(row["evidence"]) for row in
                   exposure(gcp(gcoll("vpn_gateway", [gateway]), gcoll("vpn_tunnel", [tunnel]))))
    tunnel["peerGcpGateway"] = "https://compute.googleapis.com/compute/v1/projects/p2/regions/us/vpnGateways/peer"
    result = finding()
    assert result["status"] == "FAIL" and "project p2" in result["evidence"]["observed"]
    assert "third party" not in result["evidence"]["observed"].lower()
    assert_gcp_observed_style(result, "peer-tunnel")
    tunnel["peerGcpGateway"] += "?unexpected=1"
    assert not any("peer-tunnel" in str(row["evidence"]) for row in
                   exposure(gcp(gcoll("vpn_gateway", [gateway]), gcoll("vpn_tunnel", [tunnel]))))


def test_gcp_established_classic_vpn_tunnel_requires_public_forwarding_triplet():
    prefix = "https://compute.googleapis.com/compute/v1/projects/p1/regions/us/"
    gateway_ref = prefix + "targetVpnGateways/classic"
    tunnel = {"name": "classic-peer", "status": "ESTABLISHED", "targetVpnGateway": gateway_ref,
              "peerIp": "8.8.8.8", "localTrafficSelector": ["10.0.0.0/8"]}
    rules = [{"name": "esp", "target": gateway_ref, "IPAddress": "34.2.2.2",
              "IPProtocol": "ESP", "loadBalancingScheme": "EXTERNAL"},
             {"name": "ike", "target": gateway_ref, "IPAddress": "34.2.2.2",
              "IPProtocol": "UDP", "ports": ["500"], "loadBalancingScheme": "EXTERNAL"},
             {"name": "nat-t", "target": gateway_ref, "IPAddress": "34.2.2.2",
              "IPProtocol": "UDP", "portRange": "4500-4500", "loadBalancingScheme": "EXTERNAL"}]
    def finding():
        return one(gcp(gcoll("vpn_gateway", [{"name": "classic", "selfLink": gateway_ref}]),
                       gcoll("vpn_tunnel", [tunnel]), gcoll("forwarding_rule", rules)), "vpn_tunnel")
    result = finding()
    assert result["status"] == "FAIL" and result["evidence"]["public_addresses"] == ["34.2.2.2"]
    assert "peer 8.8.8.8" in result["evidence"]["observed"]
    assert_gcp_observed_style(result, "classic-peer")
    rules.pop()
    result = finding()
    assert result["status"] == "UNKNOWN"
    assert_gcp_observed_style(result, "classic-peer")
    rules.append({"name": "nat-t", "target": gateway_ref, "IPAddress": "34.2.2.3",
                  "IPProtocol": "UDP", "ports": ["4500"], "loadBalancingScheme": "EXTERNAL"})
    assert finding()["status"] == "UNKNOWN"
    rules[-1]["IPAddress"] = "34.2.2.2"
    rules[-1]["ports"] = ["443"]
    assert finding()["status"] == "UNKNOWN"


def test_gcp_active_cross_project_vpc_peering_is_unresolved_without_route_and_firewall():
    network = {"name": "local-vpc", "selfLink": NET,
               "peerings": [{"name": "partner-link", "network":
                             "https://compute.googleapis.com/compute/v1/projects/p2/global/networks/peer-vpc",
                             "state": "ACTIVE", "importCustomRoutes": False, "exportCustomRoutes": True}]}
    def snapshot():
        return gcp(gcoll("network", [network]))
    result = one(snapshot(), "network")
    assert result["status"] == "UNKNOWN" and "project p2" in result["evidence"]["observed"]
    assert result["evidence"]["public_addresses"] == []
    assert "third party" not in result["evidence"]["observed"].lower()
    assert_gcp_observed_style(result, "local-vpc")
    report = evaluate_snapshot(snapshot(), categories=["exposure", "network"])
    assert not any(edge["type"] == "internet_exposure" for edge in report["graphs"]["network"]["edges"])
    network["peerings"][0]["state"] = "INACTIVE"
    assert not exposure(snapshot())
    network["peerings"][0]["state"] = "ACTIVE"
    network["peerings"][0]["network"] = "projects/p1/global/networks/peer-vpc"
    assert not exposure(snapshot())
    network["peerings"][0]["network"] = "projects/p2/global/networks/peer-vpc"
    assert one(snapshot(), "network")["status"] == "UNKNOWN"
    network["peerings"][0]["network"] = "https://compute.googleapis.com/compute/v1/projects/p2/global/networks/peer-vpc?bad=1"
    assert not exposure(snapshot())


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


def test_gcp_alloydb_data_api_exposes_private_ip_instance_only_when_enabled():
    from peaso.analysis.internet_exposure import _gcp_alloydb
    instance = {"name": "projects/p1/locations/us/clusters/c/instances/i", "state": "READY",
                "networkConfig": {"enablePublicIp": False}, "dataApiAccess": "ENABLED"}
    resource = {"provider": "gcp", "type": "alloydb_instance", "data": instance}
    result = _gcp_alloydb(None, None, resource)
    assert result.verdict() == "FAIL"
    assert result.ports == {"tcp": ((443, 443),)}
    assert result.authenticated is True
    assert result.endpoint == "alloydb.googleapis.com"
    instance["networkConfig"]["enablePublicIp"] = True
    combined = _gcp_alloydb(None, None, resource)
    assert combined.verdict() == "FAIL"
    assert combined.ports == {"tcp": ((443, 443), (5433, 5433))}
    instance["networkConfig"]["enablePublicIp"] = False
    for access in ("DISABLED", "DEFAULT_DATA_API_ENABLED_FOR_GOOGLE_CLOUD_SERVICES"):
        instance["dataApiAccess"] = access
        assert _gcp_alloydb(None, None, resource) is None


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
    from peaso.analysis.internet_exposure import GCP_TYPES
    from peaso.engine import plan_collection
    assert {"bucket_acl", "object_acl"} <= set(GCP_TYPES)
    assert {"bucket_acl", "object_acl"} <= set(plan_collection({
        "connector": {"provider": "gcp"}, "categories": ["exposure"]}))
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
    assert one(gcp(gcoll("bucket", [incomplete], service="storage")), "bucket")["status"] == "UNKNOWN"
    rows = analyze(gcp(gcoll("bucket", [bucket], service="storage")))["findings"]
    assert any(row["check_id"] == "analysis.principal_exposure" and row["status"] == "FAIL"
               for row in rows)
    rows = analyze(gcp(gcoll("bucket", [incomplete], service="storage")))["findings"]
    assert not any(row["check_id"] == "analysis.principal_exposure" and row["status"] == "FAIL" for row in rows)


def test_gcp_object_acl_exposure_keeps_exact_hashed_object_generation():
    bucket = {"name": "sample-bucket", "iamConfiguration": {
        "uniformBucketLevelAccess": {"enabled": False}, "publicAccessPrevention": "not_enforced"},
        "iamPolicy": {"bindings": []},
        "bucketAccessControls": {"status": "collected", "all_pages": True, "items": []},
        "objectAccessControls": {"status": "collected", "all_pages": True,
            "all_objects": True, "all_versions": True, "source_inventory": "object_acl",
            "source_requests": ["request-1"],
            "items": [{"entity": "allUsers", "role": "READER"},
                      {"entity": "allUsers", "role": "READER"}]}}
    native = [{"name": "sample-bucket/objects/" + ref + "/acl/public", "bucket": "sample-bucket",
               "entity": "allUsers", "role": "READER", "objectRef": ref,
               "generation": generation,
               "_provenance": {"source_requests": ["request-1"]}}
              for ref, generation in (("a" * 64, "123"), ("b" * 64, "456"))]
    def result():
        return one(gcp(gcoll("bucket", [bucket], service="storage"),
                       gcoll("object_acl", native, service="storage")), "bucket")
    evidence = str(result()["evidence"])
    assert result()["status"] == "FAIL"
    assert "a" * 64 in evidence and "b" * 64 in evidence
    assert "123" in evidence and "456" in evidence
    native[0]["_provenance"]["source_requests"] = ["foreign-request"]
    assert "a" * 64 not in str(result()["evidence"])


def test_gcp_live_gke_service_inventory_candidates_and_missing_cluster():
    from peaso.analysis.internet_exposure import GCP_TYPES
    from peaso.engine import plan_collection
    assert "gke_exposure_service" in GCP_TYPES
    assert "gke_exposure_service" in plan_collection({
        "connector": {"provider": "gcp"}, "categories": ["exposure"]})
    cluster = "projects/p1/locations/r1/clusters/c1"
    service = {"name": cluster + "/namespaces/default/services/web", "cluster": cluster,
               "spec": {"type": "LoadBalancer", "ports": [{"port": 443, "protocol": "TCP"}],
                        "loadBalancerSourceRanges": ["0.0.0.0/0"]},
               "status": {"loadBalancer": {"ingress": [{"ip": "34.1.2.3"}]}}}
    result = one(gcp(gcoll("gke_exposure_service", [service], service="kubernetes")), "gke_exposure_service")
    assert result["status"] == "UNKNOWN"
    assert "34.1.2.3" in str(result["evidence"])
    service["spec"] = {"type": "NodePort", "ports": [{"nodePort": 30080, "protocol": "TCP"}]}
    result = one(gcp(gcoll("gke_exposure_service", [service], service="kubernetes")), "gke_exposure_service")
    assert result["status"] == "UNKNOWN" and "30080" in str(result["evidence"])
    marker = {"name": cluster + "/serviceInventory", "cluster": cluster,
              "inventoryStatus": "unavailable", "reason": "gke_cluster_endpoint_or_ca_unproved"}
    assert one(gcp(gcoll("gke_exposure_service", [marker], service="kubernetes")),
               "gke_exposure_service")["status"] == "UNKNOWN"
    marker["inventoryStatus"] = "collected"
    assert not exposure(gcp(gcoll("gke_exposure_service", [marker], service="kubernetes")))


def test_gcp_live_gke_ingress_inventory_candidate_and_gap():
    from peaso.analysis.internet_exposure import GCP_TYPES
    from peaso.engine import plan_collection
    assert "gke_exposure_ingress" in GCP_TYPES
    assert "gke_exposure_ingress" in plan_collection({
        "connector": {"provider": "gcp"}, "categories": ["exposure"]})
    cluster = "projects/p1/locations/r1/clusters/c1"
    ingress = {"name": cluster + "/namespaces/default/ingresses/web", "cluster": cluster,
               "ingressClassName": "gce", "hosts": ["example.com"], "hasDefaultBackend": True,
               "status": {"loadBalancer": {"ingress": [{"ip": "34.1.2.3"}]}}}
    result = one(gcp(gcoll("gke_exposure_ingress", [ingress], service="kubernetes")), "gke_exposure_ingress")
    assert result["status"] == "UNKNOWN" and "34.1.2.3" in str(result["evidence"])
    marker = {"name": cluster + "/ingressInventory", "cluster": cluster,
              "inventoryStatus": "unavailable", "reason": "gke_exposure_services_read_unavailable"}
    assert one(gcp(gcoll("gke_exposure_ingress", [marker], service="kubernetes")),
               "gke_exposure_ingress")["status"] == "UNKNOWN"
    marker["inventoryStatus"] = "collected"
    assert not exposure(gcp(gcoll("gke_exposure_ingress", [marker], service="kubernetes")))


def test_gcp_loadbalancer_service_joins_controller_backend_cloud_edge(monkeypatch):
    from types import SimpleNamespace
    from peaso.analysis import internet_exposure as exposure_module
    from peaso.analysis.internet_exposure import Inventory, _gcp_gke_exposure_service
    from peaso.snapshot import resources
    cluster = "projects/p1/locations/us-central1/clusters/c1"
    backend_ref = "https://compute.googleapis.com/compute/v1/projects/p1/regions/us-central1/backendServices/k8s-be-web"
    service = {"name": cluster + "/namespaces/default/services/web", "cluster": cluster,
               "namespace": "default", "kubernetesName": "web",
               "spec": {"type": "LoadBalancer", "ports": [{"port": 8080, "protocol": "TCP"}]},
               "status": {"loadBalancer": {"ingress": [{"ip": "34.1.2.3"}]}},
               "annotations": {"service.kubernetes.io/tcp-forwarding-rule": "k8s-fw-web",
                               "service.kubernetes.io/backend-service": "k8s-be-web"}}
    marker = {"name": cluster + "/serviceInventory", "cluster": cluster,
              "inventoryStatus": "collected", "serviceCount": 1}
    forwarding = {"name": "k8s-fw-web", "loadBalancingScheme": "EXTERNAL",
                  "IPAddress": "34.1.2.3", "IPProtocol": "TCP", "portRange": "8080-8080",
                  "backendService": backend_ref}
    backend = {"name": "k8s-be-web", "selfLink": backend_ref}
    monkeypatch.setattr(exposure_module, "_gcp_forwarding_rule", lambda *args:
                        SimpleNamespace(verdict=lambda: "FAIL", ports=pset("tcp", 8080, 8080), path=[]))
    def assessment():
        snap = gcp(gcoll("gke_exposure_service", [service, marker], service="kubernetes"),
                   gcoll("forwarding_rule", [forwarding]), gcoll("backend_service", [backend]))
        items = resources(snap)
        current = next(row for row in items if row["type"] == "gke_exposure_service"
                       and row["data"]["name"] == service["name"])
        return _gcp_gke_exposure_service(snap, Inventory(snap, items), current)
    assert assessment().verdict() == "FAIL"
    assert describe(assessment().ports) == ["tcp/8080"]
    monkeypatch.setattr(exposure_module, "_gcp_gke_nodeport_direct_node", lambda *args:
                        pset("tcp", 30080, 30080))
    assert describe(assessment().ports) == ["tcp/8080", "tcp/30080"]
    monkeypatch.setattr(exposure_module, "_gcp_gke_nodeport_direct_node", lambda *args: None)
    forwarding["IPAddress"] = "34.1.2.4"
    assert assessment().verdict() == "UNKNOWN"
    forwarding["IPAddress"] = "34.1.2.3"
    forwarding["backendService"] = backend_ref.replace("k8s-be-web", "unrelated")
    assert assessment().verdict() == "UNKNOWN"
    forwarding["backendService"] = backend_ref
    marker["inventoryStatus"] = "unavailable"
    assert assessment().verdict() == "UNKNOWN"
    marker["inventoryStatus"] = "collected"
    service["annotations"].pop("service.kubernetes.io/tcp-forwarding-rule")
    service["annotations"]["service.kubernetes.io/l3-forwarding-rule"] = "k8s-fw-web"
    service["spec"]["ports"].append({"port": 8081, "protocol": "UDP"})
    forwarding.update(IPProtocol="L3_DEFAULT", allPorts=True)
    monkeypatch.setattr(exposure_module, "_gcp_forwarding_rule", lambda *args:
                        SimpleNamespace(verdict=lambda: "FAIL", ports=pset("all"), path=[]))
    assert describe(assessment().ports) == ["tcp/8080", "udp/8081"]
    forwarding["allPorts"] = False
    assert assessment().verdict() == "UNKNOWN"


def test_gcp_l3_default_forwarding_rule_all_ports_includes_tcp_and_udp():
    from peaso.analysis.internet_exposure import Inventory, _gcp_forwarding_rule
    from peaso.snapshot import resources
    forwarding = {"name": "mixed", "loadBalancingScheme": "EXTERNAL", "IPAddress": "34.1.2.3",
                  "IPProtocol": "L3_DEFAULT", "allPorts": True,
                  "backendService": "https://compute.googleapis.com/compute/v1/projects/p1/regions/r1/backendServices/mixed"}
    snap = gcp(gcoll("forwarding_rule", [forwarding]))
    items = resources(snap)
    rule = next(row for row in items if row["type"] == "forwarding_rule")
    edge = _gcp_forwarding_rule(snap, Inventory(snap, items), rule)
    assert intersect(edge.ports, pset("tcp", 8080, 8080))
    assert intersect(edge.ports, pset("udp", 8081, 8081))


def test_gcp_legacy_loadbalancer_service_joins_exact_target_pool(monkeypatch):
    from types import SimpleNamespace
    from peaso.analysis import internet_exposure as exposure_module
    from peaso.analysis.internet_exposure import Inventory, _gcp_gke_exposure_service
    from peaso.snapshot import resources
    cluster = "projects/p1/locations/us-central1/clusters/c1"
    pool_ref = "https://compute.googleapis.com/compute/v1/projects/p1/regions/us-central1/targetPools/k8s-pool-web"
    service = {"name": cluster + "/namespaces/default/services/web", "cluster": cluster,
               "spec": {"type": "LoadBalancer", "ports": [{"port": 8080, "protocol": "TCP"}]},
               "status": {"loadBalancer": {"ingress": [{"ip": "34.1.2.3"}]}},
               "annotations": {"service.kubernetes.io/tcp-forwarding-rule": "k8s-fw-web"}}
    marker = {"name": cluster + "/serviceInventory", "cluster": cluster,
              "inventoryStatus": "collected", "serviceCount": 1}
    forwarding = {"name": "k8s-fw-web", "loadBalancingScheme": "EXTERNAL",
                  "IPAddress": "34.1.2.3", "IPProtocol": "TCP", "portRange": "8080-8080", "target": pool_ref}
    pool = {"name": "k8s-pool-web", "selfLink": pool_ref}
    monkeypatch.setattr(exposure_module, "_gcp_forwarding_rule", lambda *args:
                        SimpleNamespace(verdict=lambda: "FAIL", ports=pset("tcp", 8080, 8080), path=[]))
    def assessment():
        snap = gcp(gcoll("gke_exposure_service", [service, marker], service="kubernetes"),
                   gcoll("forwarding_rule", [forwarding]), gcoll("target_pool", [pool]))
        items = resources(snap)
        current = next(row for row in items if row["type"] == "gke_exposure_service"
                       and row["data"]["name"] == service["name"])
        return _gcp_gke_exposure_service(snap, Inventory(snap, items), current)
    assert assessment().verdict() == "FAIL"
    forwarding["target"] = pool_ref.replace("k8s-pool-web", "unrelated")
    assert assessment().verdict() == "UNKNOWN"


def test_gcp_ingress_joins_exact_controller_cloud_edge():
    from peaso.analysis.internet_exposure import Inventory, _gcp_gke_exposure_ingress
    from peaso.snapshot import resources
    cluster = "projects/p1/locations/us-central1/clusters/c1"
    base = "https://compute.googleapis.com/compute/v1/projects/p1/global"
    proxy_ref = base + "/targetHttpProxies/k8s-tp-web"
    map_ref = base + "/urlMaps/k8s-um-web"
    backend_ref = base + "/backendServices/k8s-be-web"
    ingress = {"name": cluster + "/namespaces/default/ingresses/web", "cluster": cluster,
               "annotations": {"kubernetes.io/ingress.class": "gce",
                               "ingress.kubernetes.io/forwarding-rule": "k8s-fw-web",
                               "ingress.kubernetes.io/target-proxy": "k8s-tp-web",
                               "ingress.kubernetes.io/url-map": "k8s-um-web"},
               "hosts": ["example.com"],
               "status": {"loadBalancer": {"ingress": [{"ip": "34.1.2.3"}]}}}
    marker = {"name": cluster + "/ingressInventory", "cluster": cluster,
              "inventoryStatus": "collected", "ingressCount": 1}
    forwarding = {"name": "k8s-fw-web", "loadBalancingScheme": "EXTERNAL_MANAGED",
                  "IPAddress": "34.1.2.3", "IPProtocol": "TCP", "portRange": "80-80",
                  "target": proxy_ref}
    proxy = {"name": "k8s-tp-web", "selfLink": proxy_ref, "urlMap": map_ref}
    url_map = {"name": "k8s-um-web", "selfLink": map_ref, "defaultService": backend_ref}
    backend = {"name": "k8s-be-web", "selfLink": backend_ref}
    def assessment():
        snap = gcp(gcoll("gke_exposure_ingress", [ingress, marker], service="kubernetes"),
                   gcoll("forwarding_rule", [forwarding]), gcoll("target_proxy", [proxy]),
                   gcoll("url_map", [url_map]), gcoll("backend_service", [backend]))
        items = resources(snap)
        current = next(row for row in items if row["type"] == "gke_exposure_ingress"
                       and row["data"]["name"] == ingress["name"])
        return _gcp_gke_exposure_ingress(snap, Inventory(snap, items), current)
    result = assessment()
    assert result.verdict() == "FAIL" and describe(result.ports) == ["tcp/80"]
    assert result.path[-1]["forwarding_rule"] == "k8s-fw-web"
    ingress["hosts"] = []
    assert assessment().verdict() == "UNKNOWN"
    ingress["hosts"] = ["example.com"]
    ingress["annotations"].pop("ingress.kubernetes.io/forwarding-rule")
    ingress["annotations"].pop("ingress.kubernetes.io/target-proxy")
    ingress["annotations"].update({"ingress.kubernetes.io/https-forwarding-rule": "k8s-fs-web",
                                   "ingress.kubernetes.io/https-target-proxy": "k8s-ts-web"})
    forwarding.update(name="k8s-fs-web", portRange="443-443",
                      target=base + "/targetHttpsProxies/k8s-ts-web")
    proxy["selfLink"] = forwarding["target"]
    assert assessment().verdict() == "FAIL" and describe(assessment().ports) == ["tcp/443"]
    ingress["annotations"].update({"ingress.kubernetes.io/forwarding-rule": "k8s-fw-web",
                                   "ingress.kubernetes.io/target-proxy": "k8s-tp-web"})
    ingress["annotations"].pop("ingress.kubernetes.io/https-forwarding-rule")
    ingress["annotations"].pop("ingress.kubernetes.io/https-target-proxy")
    forwarding.update(name="k8s-fw-web", portRange="80-80", target=proxy_ref)
    proxy["selfLink"] = proxy_ref
    ingress["annotations"]["kubernetes.io/ingress.class"] = "gce-internal"
    assert assessment().verdict() == "UNKNOWN"
    ingress["annotations"]["kubernetes.io/ingress.class"] = "gce"
    forwarding["target"] = base + "/targetHttpProxies/unrelated"
    assert assessment().verdict() == "UNKNOWN"
    forwarding["target"] = proxy_ref
    marker["inventoryStatus"] = "unavailable"
    assert assessment().verdict() == "UNKNOWN"
    marker["inventoryStatus"] = "collected"
    url_map["defaultService"] = base + "/backendServices/missing"
    assert assessment().verdict() == "UNKNOWN"


def test_gcp_live_gke_host_bound_pod_candidate_and_gap():
    from peaso.analysis.internet_exposure import GCP_TYPES
    from peaso.engine import plan_collection
    assert "gke_exposure_pod" in GCP_TYPES
    assert "gke_exposure_pod" in plan_collection({
        "connector": {"provider": "gcp"}, "categories": ["exposure"]})
    cluster = "projects/p1/locations/r1/clusters/c1"
    pod = {"name": cluster + "/namespaces/default/pods/web", "cluster": cluster,
           "hostNetwork": True, "hostPorts": [{"hostPort": 8080, "protocol": "TCP"}],
           "nodeName": "node-a", "hostIP": "34.1.2.3", "phase": "Running"}
    result = one(gcp(gcoll("gke_exposure_pod", [pod], service="kubernetes")), "gke_exposure_pod")
    assert result["status"] == "UNKNOWN" and "8080" in str(result["evidence"])
    pod["phase"] = "Succeeded"
    assert not exposure(gcp(gcoll("gke_exposure_pod", [pod], service="kubernetes")))
    marker = {"name": cluster + "/podInventory", "cluster": cluster,
              "inventoryStatus": "unavailable", "reason": "gke_exposure_services_read_unavailable"}
    assert one(gcp(gcoll("gke_exposure_pod", [marker], service="kubernetes")),
               "gke_exposure_pod")["status"] == "UNKNOWN"


def test_gcp_live_gke_node_inventory_is_supporting_evidence():
    from peaso.analysis.internet_exposure import GCP_TYPES
    from peaso.engine import plan_collection
    assert "gke_exposure_node" in GCP_TYPES
    assert "gke_exposure_node" in plan_collection({
        "connector": {"provider": "gcp"}, "categories": ["exposure"]})
    cluster = "projects/p1/locations/r1/clusters/c1"
    node = {"name": cluster + "/nodes/gke-node-1", "cluster": cluster,
            "providerID": "gce://p1/us-central1-a/gke-node-1",
            "addresses": [{"type": "ExternalIP", "address": "34.1.2.3"}]}
    assert not exposure(gcp(gcoll("gke_exposure_node", [node], service="kubernetes")))
    marker = {"name": cluster + "/nodeInventory", "cluster": cluster,
              "inventoryStatus": "unavailable", "reason": "gke_exposure_services_read_unavailable"}
    assert one(gcp(gcoll("gke_exposure_node", [marker], service="kubernetes")),
               "gke_exposure_node")["status"] == "UNKNOWN"


def test_gcp_hostport_joins_exact_live_node_vm_and_effective_firewall():
    cluster = "projects/p1/locations/us-central1/clusters/c1"
    pod = {"name": cluster + "/namespaces/default/pods/web", "cluster": cluster,
           "hostNetwork": False, "hostPorts": [{"hostPort": 8080, "protocol": "TCP"}],
           "nodeName": "node-a", "hostIP": "10.1.2.3", "phase": "Running"}
    node = {"name": cluster + "/nodes/node-a", "cluster": cluster,
            "kubernetesName": "node-a", "providerID": "gce://p1/us-central1-a/vm",
            "addresses": [{"type": "InternalIP", "address": "10.1.2.3"},
                          {"type": "ExternalIP", "address": "34.1.1.1"}]}
    vm = copy.deepcopy(gcp_instance())
    vm["items"][0]["selfLink"] = "https://compute.googleapis.com/compute/v1/projects/p1/zones/us-central1-a/instances/vm"
    effective = {"name": "projects/p1/zones/us-central1-a/instances/vm/interfaces/nic0/effectiveFirewalls",
                 "instance": "projects/p1/zones/us-central1-a/instances/vm", "networkInterface": "nic0",
                 "firewalls": [fw("allow-hostport", 1000, "allowed", ["8080"], ["web"])],
                 "firewallPolicys": [], "effective_source_operation": "instances.getEffectiveFirewalls"}
    def result():
        return one(gcp(gcoll("gke_exposure_pod", [pod], service="kubernetes"),
                       gcoll("gke_exposure_node", [node], service="kubernetes"), vm,
                       gcoll("instance_effective_firewall", [effective]),
                       gcoll("firewall", [], status="denied")), "gke_exposure_pod")
    assert result()["status"] == "FAIL" and result()["evidence"]["exposed_ports"] == ["tcp/8080"]
    pod["hostPorts"][0]["bindIP"] = "127.0.0.1"
    assert result()["status"] == "UNKNOWN"
    pod["hostPorts"][0]["bindIP"] = "10.1.2.3"
    assert result()["status"] == "UNKNOWN"
    vm["items"][0]["networkInterfaces"][0]["networkIP"] = "10.1.2.3"
    assert result()["status"] == "FAIL"
    vm["items"][0]["networkInterfaces"][0]["networkIP"] = "10.1.2.4"
    assert result()["status"] == "UNKNOWN"
    pod["hostPorts"][0]["bindIP"] = "0.0.0.0"
    assert result()["status"] == "FAIL"
    pod["hostNetwork"] = True
    pod["hostPorts"][0]["portSource"] = "hostNetwork"
    assert result()["status"] == "FAIL"
    pod["hostNetwork"] = False
    pod["hostPorts"][0].pop("portSource")
    node["addresses"][1]["address"] = "34.1.1.2"
    assert result()["status"] == "UNKNOWN"
    node["addresses"][1]["address"] = "34.1.1.1"
    effective["firewallPolicys"] = [{"type": "HIERARCHY", "name": "organizations/9/locations/global/firewallPolicies/1",
                                    "rules": [{"priority": 100, "direction": "INGRESS", "action": "allow",
                                               "match": {"srcIpRanges": ["0.0.0.0/0"]}}]}]
    assert result()["status"] == "FAIL"
    effective["firewallPolicys"] = [{"name": "unresolved-policy"}]
    assert result()["status"] == "UNKNOWN"


def test_gcp_nodeport_joins_ready_backend_node_vm_and_effective_firewall():
    cluster = "projects/p1/locations/us-central1/clusters/c1"
    service = {"name": cluster + "/namespaces/default/services/web", "cluster": cluster,
               "namespace": "default", "kubernetesName": "web",
               "spec": {"type": "NodePort", "externalTrafficPolicy": "Local",
                        "ports": [{"name": "http", "port": 80, "targetPort": 8080,
                                   "nodePort": 30080, "protocol": "TCP"}]}}
    service_marker = {"name": cluster + "/serviceInventory", "cluster": cluster,
                      "inventoryStatus": "collected", "serviceCount": 1}
    slice_row = {"name": cluster + "/namespaces/default/endpointslices/web-abc", "cluster": cluster,
                 "namespace": "default", "serviceName": "web", "addressType": "IPv4",
                 "ports": [{"name": "http", "port": 8080, "protocol": "TCP"}],
                 "readyEndpointCount": 1, "readyNodeNames": ["node-a"]}
    slice_marker = {"name": cluster + "/endpointsliceInventory", "cluster": cluster,
                    "inventoryStatus": "collected", "endpointsliceCount": 1}
    node = {"name": cluster + "/nodes/node-a", "cluster": cluster, "kubernetesName": "node-a",
            "providerID": "gce://p1/us-central1-a/vm",
            "addresses": [{"type": "ExternalIP", "address": "34.1.1.1"}]}
    node_marker = {"name": cluster + "/nodeInventory", "cluster": cluster,
                   "inventoryStatus": "collected", "nodeCount": 1}
    vm = copy.deepcopy(gcp_instance())
    vm["items"][0]["selfLink"] = "https://compute.googleapis.com/compute/v1/projects/p1/zones/us-central1-a/instances/vm"
    effective = {"name": "projects/p1/zones/us-central1-a/instances/vm/interfaces/nic0/effectiveFirewalls",
                 "instance": "projects/p1/zones/us-central1-a/instances/vm", "networkInterface": "nic0",
                 "firewalls": [fw("allow-nodeport", 1000, "allowed", ["30080"], ["web"])],
                 "firewallPolicys": [], "effective_source_operation": "instances.getEffectiveFirewalls"}
    def result():
        report = analyze(gcp(gcoll("gke_exposure_service", [service, service_marker], service="kubernetes"),
                             gcoll("gke_exposure_endpointslice", [slice_row, slice_marker], service="kubernetes"),
                             gcoll("gke_exposure_node", [node, node_marker], service="kubernetes"), vm,
                             gcoll("instance_effective_firewall", [effective]),
                             gcoll("firewall", [], status="denied")))
        resource_id = next(row["id"] for row in report["resources"] if row["type"] == "gke_exposure_service"
                           and row["data"]["name"] == service["name"])
        return next(row for row in report["findings"] if row["check_id"] == CHECK
                    and row["resource_id"] == resource_id)
    assert result()["status"] == "FAIL" and result()["evidence"]["exposed_ports"] == ["tcp/30080"]
    service["spec"]["type"] = "LoadBalancer"
    service["spec"]["allocateLoadBalancerNodePorts"] = False
    assert result()["status"] == "FAIL" and result()["evidence"]["exposed_ports"] == ["tcp/30080"]
    service["spec"]["type"] = "NodePort"
    slice_row["readyNodeNames"] = ["other-node"]
    assert result()["status"] == "UNKNOWN"
    service["spec"]["externalTrafficPolicy"] = "Cluster"
    assert result()["status"] == "FAIL"
    slice_row["ports"][0]["port"] = 8081
    assert result()["status"] == "UNKNOWN"
    slice_row["ports"][0]["port"] = 8080
    slice_marker["inventoryStatus"] = "unavailable"
    assert result()["status"] == "UNKNOWN"
    slice_marker["inventoryStatus"] = "collected"
    effective["firewallPolicys"] = [{"name": "unresolved-policy"}]
    assert result()["status"] == "UNKNOWN"
    effective["firewallPolicys"] = []
    service_marker["inventoryStatus"] = "unavailable"
    assert result()["status"] == "UNKNOWN"
    service_marker["inventoryStatus"] = "collected"
    service["spec"].update(type="ClusterIP", externalIPs=["34.1.1.1"])
    effective["firewalls"] = [fw("allow-external-ip", 1000, "allowed", ["80"], ["web"])]
    assert result()["status"] == "UNKNOWN"
    service["spec"]["externalTrafficPolicy"] = "unrecognized"
    assert result()["status"] == "UNKNOWN"


def test_gcp_live_gke_gateway_and_httproute_candidates():
    from peaso.analysis.internet_exposure import GCP_TYPES
    from peaso.engine import plan_collection
    selected = set(plan_collection({"connector": {"provider": "gcp"}, "categories": ["exposure"]}))
    assert {"gke_exposure_gateway", "gke_exposure_gatewayclass", "gke_exposure_httproute"} <= set(GCP_TYPES) & selected
    cluster = "projects/p1/locations/r1/clusters/c1"
    gateway = {"name": cluster + "/namespaces/default/gateways/web", "cluster": cluster,
               "namespace": "default", "kubernetesName": "web",
               "gatewayClassName": "gke-l7-global-external-managed",
               "listeners": [{"name": "https", "port": 443, "protocol": "HTTPS"}],
               "addresses": [{"type": "IPAddress", "value": "34.1.2.3"}]}
    route = {"name": cluster + "/namespaces/default/httproutes/web", "cluster": cluster,
             "hostnames": ["example.com"], "parentRefs": [{"name": "web"}],
             "backendRefs": [{"name": "svc", "port": 8080}]}
    result = one(gcp(gcoll("gke_exposure_gateway", [gateway], service="kubernetes")), "gke_exposure_gateway")
    assert result["status"] == "UNKNOWN" and "tcp/443" in str(result["evidence"])
    result = one(gcp(gcoll("gke_exposure_httproute", [route], service="kubernetes")), "gke_exposure_httproute")
    assert result["status"] == "UNKNOWN" and "example.com" in str(result["evidence"])
    marker = {"name": cluster + "/gatewayInventory", "cluster": cluster,
              "inventoryStatus": "unavailable", "reason": "gke_exposure_services_read_unavailable"}
    assert one(gcp(gcoll("gke_exposure_gateway", [marker], service="kubernetes")),
               "gke_exposure_gateway")["status"] == "UNKNOWN"


def test_gcp_gateway_joins_exact_controller_cloud_edge():
    from peaso.analysis.internet_exposure import Inventory, _gcp_gke_exposure_gateway, _gcp_gke_exposure_httproute
    from peaso.snapshot import resources
    cluster = "projects/p1/locations/us-central1/clusters/c1"
    base = "https://compute.googleapis.com/compute/v1/projects/p1/global"
    proxy_ref = base + "/targetHttpsProxies/gkegw-tp1"
    map_ref = base + "/urlMaps/gkegw-url-map1"
    backend_ref = base + "/backendServices/gkegw-be1"
    gateway = {"name": cluster + "/namespaces/default/gateways/web", "cluster": cluster,
               "namespace": "default", "kubernetesName": "web",
               "gatewayClassName": "gke-l7-global-external-managed",
               "listeners": [{"name": "https", "port": 443, "protocol": "HTTPS"}],
               "addresses": [{"type": "IPAddress", "value": "34.1.2.3"}],
               "annotations": {"networking.gke.io/forwarding-rules": "gkegw-fr1",
                               "networking.gke.io/target-proxies": "gkegw-tp1",
                               "networking.gke.io/url-maps": "gkegw-url-map1"}}
    marker = {"name": cluster + "/gatewayInventory", "cluster": cluster,
              "inventoryStatus": "collected", "gatewayCount": 1}
    gateway_class = {"name": cluster + "/gatewayclasses/gke-l7-global-external-managed",
                     "cluster": cluster, "kubernetesName": "gke-l7-global-external-managed",
                     "controllerName": "networking.gke.io/gateway"}
    class_marker = {"name": cluster + "/gatewayclassInventory", "cluster": cluster,
                    "inventoryStatus": "collected", "gatewayclassCount": 1}
    forwarding = {"name": "gkegw-fr1", "loadBalancingScheme": "EXTERNAL_MANAGED",
                  "IPAddress": "34.1.2.3", "IPProtocol": "TCP", "portRange": "443-443",
                  "target": proxy_ref}
    proxy = {"name": "gkegw-tp1", "selfLink": proxy_ref, "urlMap": map_ref}
    url_map = {"name": "gkegw-url-map1", "selfLink": map_ref, "defaultService": backend_ref}
    backend = {"name": "gkegw-be1", "selfLink": backend_ref}
    route = {"name": cluster + "/namespaces/default/httproutes/web", "cluster": cluster,
             "namespace": "default", "generation": 3, "hostnames": ["example.com"],
             "parentRefs": [{"name": "web", "sectionName": "https"}],
             "backendRefs": [{"name": "app", "port": 8080}],
             "parentStatus": [{"controllerName": "networking.gke.io/gateway",
                               "parentRef": {"name": "web", "sectionName": "https"},
                               "conditions": [{"type": "Accepted", "status": "True", "observedGeneration": 3},
                                              {"type": "Reconciled", "status": "True", "observedGeneration": 3}]}]}
    route_marker = {"name": cluster + "/httprouteInventory", "cluster": cluster,
                    "inventoryStatus": "collected", "httprouteCount": 1}
    extra = []
    def assessment(kind="gke_exposure_gateway"):
        snap = gcp(gcoll("gke_exposure_gateway", [gateway, marker], service="kubernetes"),
                   gcoll("gke_exposure_gatewayclass", [gateway_class, class_marker], service="kubernetes"),
                   gcoll("gke_exposure_httproute", [route, route_marker], service="kubernetes"),
                   gcoll("forwarding_rule", [forwarding, *extra]), gcoll("target_proxy", [proxy]),
                   gcoll("url_map", [url_map]), gcoll("backend_service", [backend]))
        items = resources(snap)
        current = next(row for row in items if row["type"] == kind
                       and row["data"]["name"] == (gateway if kind == "gke_exposure_gateway" else route)["name"])
        evaluator = _gcp_gke_exposure_gateway if kind == "gke_exposure_gateway" else _gcp_gke_exposure_httproute
        return evaluator(snap, Inventory(snap, items), current)
    assert assessment().verdict() == "FAIL" and describe(assessment().ports) == ["tcp/443"]
    assert assessment().path[-1]["forwarding_rule"] == "gkegw-fr1"
    assert assessment("gke_exposure_httproute").verdict() == "FAIL"
    gateway["gatewayClassName"] = "gke-l7-rilb"
    assert assessment().verdict() == "UNKNOWN"
    gateway["gatewayClassName"] = "gke-l7-global-external-managed"
    url_map["selfLink"] = base + "/urlMaps/unrelated"
    assert assessment().verdict() == "UNKNOWN"
    url_map["selfLink"] = map_ref
    marker["inventoryStatus"] = "unavailable"
    assert assessment().verdict() == "UNKNOWN"
    marker["inventoryStatus"] = "collected"
    gateway_class["controllerName"] = "unrelated.example/controller"
    assert assessment().verdict() == "UNKNOWN"
    gateway_class["controllerName"] = "networking.gke.io/gateway"
    extra.append({**forwarding, "selfLink": base + "/forwardingRules/duplicate"})
    assert assessment().verdict() == "UNKNOWN"
    extra.clear()
    route["parentStatus"][0]["conditions"][0]["observedGeneration"] = 2
    assert assessment("gke_exposure_httproute").verdict() == "UNKNOWN"
    route["parentStatus"][0]["conditions"][0]["observedGeneration"] = 3
    route["parentRefs"][0]["sectionName"] = "http"
    assert assessment("gke_exposure_httproute").verdict() == "UNKNOWN"
    route["parentRefs"][0]["sectionName"] = "https"
    route["parentStatus"][0]["conditions"].append(
        {"type": "ResolvedRefs", "status": "False", "observedGeneration": 3})
    assert assessment("gke_exposure_httproute").verdict() == "UNKNOWN"
    route["parentStatus"][0]["conditions"].pop()
    route["parentStatus"][0]["controllerName"] = "unrelated.example/controller"
    assert assessment("gke_exposure_httproute").verdict() == "UNKNOWN"


def test_gcp_gke_endpointslice_inventory_gap_is_unknown():
    from peaso.analysis.internet_exposure import GCP_TYPES
    from peaso.engine import plan_collection
    selected = set(plan_collection({"connector": {"provider": "gcp"}, "categories": ["exposure"]}))
    assert "gke_exposure_endpointslice" in set(GCP_TYPES) & selected
    cluster = "projects/p1/locations/r1/clusters/c1"
    marker = {"name": cluster + "/endpointsliceInventory", "cluster": cluster,
              "inventoryStatus": "unavailable", "reason": "gke_exposure_services_read_unavailable"}
    assert one(gcp(gcoll("gke_exposure_endpointslice", [marker], service="kubernetes")),
               "gke_exposure_endpointslice")["status"] == "UNKNOWN"
    marker["inventoryStatus"] = "collected"
    assert not [finding for finding in exposure(gcp(gcoll("gke_exposure_endpointslice", [marker],
                                                       service="kubernetes")))
                if finding["resource_type"] == "gke_exposure_endpointslice"]


def test_gcp_nonuniform_bucket_missing_acl_inventory_is_unknown():
    bucket = {"name": "sample-bucket", "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": False},
              "publicAccessPrevention": "not_enforced"}, "iamPolicy": {"bindings": []}}
    result = one(gcp(gcoll("bucket", [bucket], service="storage")), "bucket")
    assert result["status"] == "UNKNOWN"
    assert "bucketAccessControls inventory incomplete" in str(result["evidence"])
    assert "objectAccessControls inventory incomplete" in str(result["evidence"])
    bucket["bucketAccessControls"] = {"status": "collected", "all_pages": True, "items": []}
    bucket["objectAccessControls"] = {"status": "collected", "all_pages": True,
                                       "all_objects": True, "all_versions": True, "items": []}
    assert one(gcp(gcoll("bucket", [bucket], service="storage")), "bucket")["status"] == "UNKNOWN"


def test_gcp_bucket_inherited_public_grant_and_effective_pap():
    from peaso.analysis.internet_exposure import Inventory, _gcp_bucket
    from peaso.snapshot import resources
    bucket = {"name": "sample-bucket", "iamPolicy": {"bindings": []},
              "iamConfiguration": {"publicAccessPrevention": "inherited"}}
    inherited = {"name": "sample-bucket", "resolutionComplete": True, "publicAccess": True,
                 "publicWrite": False, "policyScopes": [GSCOPE, "organizations/123"]}
    policy = {"name": GSCOPE + "/policies/storage.publicAccessPrevention",
              "constraint": "storage.publicAccessPrevention", "spec": {"rules": [{"enforce": False}]}}
    def assessment(*extra):
        snap = gcp(gcoll("bucket", [bucket], service="storage"),
                   gcoll("bucket_effective_iam", [inherited], service="storage"), *extra)
        items = resources(snap)
        return _gcp_bucket(snap, Inventory(snap, items), next(row for row in items if row["type"] == "bucket"))
    assert assessment(gcoll("org_policy_effective", [policy], service="orgpolicy")).verdict() == "FAIL"
    policy["spec"]["rules"][0]["enforce"] = True
    assert assessment(gcoll("org_policy_effective", [policy], service="orgpolicy")).verdict() == "PASS"
    policy["spec"]["rules"].append({"enforce": False})
    assert assessment(gcoll("org_policy_effective", [policy], service="orgpolicy")).verdict() == "UNKNOWN"
    assert assessment().verdict() == "UNKNOWN"


def test_gcp_bucket_requires_complete_negative_ancestor_iam_before_no_finding():
    from peaso.analysis.internet_exposure import Inventory, _gcp_bucket
    from peaso.snapshot import resources
    bucket = {"name": "sample-bucket", "iamPolicy": {"bindings": []},
              "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True},
                                   "publicAccessPrevention": "not_enforced"}}
    effective = {"name": "sample-bucket", "resolutionComplete": True, "publicAccess": False}
    def assessment(*extra):
        snap = gcp(gcoll("bucket", [bucket], service="storage"),
                   gcoll("managed_folder", [], status="empty", service="storage"), *extra)
        items = resources(snap)
        return _gcp_bucket(snap, Inventory(snap, items), next(row for row in items if row["type"] == "bucket"))
    missing = assessment()
    assert missing is not None and missing.verdict() == "UNKNOWN"
    assert missing.path[-1]["effective_iam_unresolved"] is True
    assert assessment(gcoll("bucket_effective_iam", [effective], service="storage")) is None
    effective["resolutionComplete"] = False
    assert assessment(gcoll("bucket_effective_iam", [effective], service="storage")).verdict() == "UNKNOWN"
    effective.update(resolutionComplete=True, publicAccess=True)
    assert assessment(gcoll("bucket_effective_iam", [effective], service="storage")).verdict() == "FAIL"


def test_gcp_bucket_ip_filter_blocks_direct_public_grant_without_public_network_range():
    from peaso.analysis.internet_exposure import Inventory, _gcp_bucket
    from peaso.snapshot import resources
    bucket = {"name": "sample-bucket", "iamPolicy": {"bindings": [
        {"role": "roles/storage.objectViewer", "members": ["allUsers"]}]},
        "iamConfiguration": {"publicAccessPrevention": "inherited"},
        "ipFilter": {"mode": "Enabled", "publicNetworkSource": {"allowedIpCidrRanges": []},
                     "allowAllServiceAgentAccess": True}}
    effective = {"name": GSCOPE + "/policies/storage.publicAccessPrevention",
                 "constraint": "storage.publicAccessPrevention", "spec": {"rules": [{"enforce": False}]}}
    def assessment(with_effective=False):
        snap = gcp(gcoll("bucket", [bucket], service="storage"),
                   *(gcoll("org_policy_effective", [effective], service="orgpolicy"),) if with_effective else ())
        items = resources(snap)
        return _gcp_bucket(snap, Inventory(snap, items), items[0])
    result = assessment()
    assert result.verdict() == "PASS"
    assert any(step["layer"] == "bucket_ip_filter" and step["decision"] == "block" for step in result.path)
    bucket["ipFilter"]["publicNetworkSource"]["allowedIpCidrRanges"] = ["8.8.8.0/24"]
    assert assessment().verdict() == "UNKNOWN"  # inherited PAP is still unresolved
    assert assessment(with_effective=True).verdict() == "FAIL"
    bucket["ipFilter"]["publicNetworkSource"]["allowedIpCidrRanges"] = ["bad-cidr"]
    assert assessment(with_effective=True).verdict() == "UNKNOWN"


def test_gcp_bucket_custom_role_permissions_gate_public_object_exposure():
    from peaso.analysis.internet_exposure import GCP_TYPES, Inventory, _gcp_bucket
    from peaso.snapshot import resources
    assert "iam_role" in GCP_TYPES
    role_name = "projects/p1/roles/custom"
    bucket = {"name": "sample-bucket", "iamPolicy": {"bindings": [
        {"role": role_name, "members": ["allUsers"]}]},
        "iamConfiguration": {"publicAccessPrevention": "inherited"}}
    effective = {"name": GSCOPE + "/policies/storage.publicAccessPrevention",
                 "constraint": "storage.publicAccessPrevention", "spec": {"rules": [{"enforce": False}]}}
    role = {"name": role_name, "includedPermissions": ["storage.objects.get"]}
    def assessment(with_role=True):
        snap = gcp(gcoll("bucket", [bucket], service="storage"),
                   gcoll("org_policy_effective", [effective], service="orgpolicy"),
                   gcoll("iam_role", [role] if with_role else [], service="iam"))
        items = resources(snap)
        return _gcp_bucket(snap, Inventory(snap, items), next(row for row in items if row["type"] == "bucket"))
    assert assessment().verdict() == "FAIL"
    bucket["iamPolicy"]["bindings"][0]["condition"] = {}
    assert assessment().verdict() == "UNKNOWN"
    bucket["iamPolicy"]["bindings"][0].pop("condition")
    role["includedPermissions"] = ["logging.logEntries.list"]
    assert assessment().verdict() == "UNKNOWN"  # Ancestor IAM remains uncollected.
    assert assessment(with_role=False).verdict() == "UNKNOWN"


def test_gcp_public_managed_folder_joins_cached_folder_policy():
    from peaso.analysis.internet_exposure import GCP_TYPES, Inventory, _gcp_bucket
    from peaso.snapshot import resources
    assert "managed_folder" in GCP_TYPES
    bucket = {"name": "sample-bucket", "iamPolicy": {"bindings": []},
              "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True},
                                   "publicAccessPrevention": "not_enforced"}}
    folder = {"name": "public/", "bucket": "sample-bucket", "iamPolicy": {"bindings": [
        {"role": "roles/storage.objectViewer", "members": ["allUsers"]}]}}
    def assessment():
        snap = gcp(gcoll("bucket", [bucket], service="storage"),
                   gcoll("managed_folder", [folder], service="storage"))
        items = resources(snap)
        return _gcp_bucket(snap, Inventory(snap, items), next(row for row in items if row["type"] == "bucket"))
    result = assessment()
    assert result.verdict() == "FAIL"
    assert result.path[-1]["managed_folder_grants"][0]["folder"] == "public/"
    folder["iamPolicy"]["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}
    assert assessment().verdict() == "UNKNOWN"
    folder["iamPolicy"]["bindings"][0]["condition"] = {}
    assert assessment().verdict() == "UNKNOWN"
    folder["iamPolicy"]["bindings"][0].pop("condition")
    folder["iamPolicy"]["bindings"][0]["role"] = "projects/p1/roles/unknown"
    assert assessment().verdict() == "UNKNOWN"
    bucket["iamConfiguration"]["publicAccessPrevention"] = "enforced"
    assert assessment().verdict() == "PASS"


def test_gcp_managed_folder_parent_prefix_and_incomplete_inventory():
    from peaso.analysis.internet_exposure import Inventory, _gcp_bucket
    from peaso.snapshot import resources
    bucket = {"name": "sample-bucket", "iamPolicy": {"bindings": []},
              "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True},
                                   "publicAccessPrevention": "not_enforced"}}
    parent = {"name": "parent/", "bucket": "sample-bucket", "iamPolicy": {"bindings": [
        {"role": "roles/storage.objectViewer", "members": ["allUsers"]}]}}
    child = {"name": "parent/child/", "bucket": "sample-bucket", "iamPolicy": {"bindings": []}}
    def assessment(folders, status="collected"):
        snap = gcp(gcoll("bucket", [bucket], service="storage"),
                   gcoll("managed_folder", folders, status=status, service="storage"))
        items = resources(snap)
        return _gcp_bucket(snap, Inventory(snap, items), next(row for row in items if row["type"] == "bucket"))
    result = assessment([parent, child])
    assert result.verdict() == "FAIL"
    assert result.path[-1]["managed_folder_grants"][0]["folder"] == "parent/"
    incomplete = assessment([], status="partial")
    assert incomplete.verdict() == "UNKNOWN"
    assert incomplete.path[-1]["managed_folder_unresolved"] == [
        {"reason": "managed folder inventory incomplete"}]
    assert assessment([], status="empty").verdict() == "UNKNOWN"  # Ancestor IAM remains uncollected.


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
    extra = ([gcoll("app_engine_firewall_rule", [{"priority": 2147483647, "sourceRange": "*",
                                                 "action": "ALLOW"}], service="appengine")]
             if kind == "app_engine_application" else [])
    assert one(gcp(gcoll(kind, [record], service="managed"), *extra), kind)["status"] == expected


def test_gcp_app_engine_ordered_ingress_firewall_controls_public_hostname():
    app = {"name": "apps/p1", "defaultHostname": "p1.uc.r.appspot.com", "servingStatus": "SERVING"}
    missing = one(gcp(gcoll("app_engine_application", [app], service="appengine")),
                  "app_engine_application")
    assert missing["status"] == "UNKNOWN"
    assert_gcp_observed_style(missing, "apps/p1")
    rules = [{"priority": 100, "sourceRange": "10.0.0.0/8", "action": "ALLOW"},
             {"priority": 2147483647, "sourceRange": "*", "action": "DENY"}]
    def finding(status=None):
        return one(gcp(gcoll("app_engine_application", [app], service="appengine"),
                       gcoll("app_engine_firewall_rule", [] if status == "denied" else rules,
                             status=status, service="appengine")),
                   "app_engine_application")
    assert finding()["status"] == "PASS"
    rules[1]["action"] = "ALLOW"
    result = finding()
    assert result["status"] == "FAIL" and "priority 2147483647" in result["evidence"]["observed"]
    assert_gcp_observed_style(result, "apps/p1")
    rules[0] = {"priority": 100, "sourceRange": "8.8.8.0/24", "action": "ALLOW"}
    rules[1]["action"] = "DENY"
    result = finding()
    assert result["status"] == "FAIL" and "source 8.8.8.0/24" in result["evidence"]["observed"]
    assert_gcp_observed_style(result, "apps/p1")
    rules[0]["action"] = "DENY"
    assert finding()["status"] == "UNKNOWN"  # other public sources may use a later rule
    rules[0]["sourceRange"] = "0.0.0.0/0"
    assert finding()["status"] == "UNKNOWN"  # IPv6 and earlier public overlap remain unresolved
    rules[0]["sourceRange"] = "10.0.0.0/8"
    assert finding(status="denied")["status"] == "UNKNOWN"
    rules[1]["priority"] = 100
    assert finding()["status"] == "UNKNOWN"
    rules[1]["priority"] = 2147483647
    app["servingStatus"] = "UNSPECIFIED"
    result = finding()
    assert result["status"] == "UNKNOWN"
    assert_gcp_observed_style(result, "apps/p1")


def test_gcp_dataproc_component_gateway_declared_endpoint_and_limits():
    cluster = {"projectId": "p1", "clusterName": "spark-a", "status": {"state": "RUNNING"},
               "config": {"endpointConfig": {"enableHttpPortAccess": True,
                   "httpPorts": {"YARN ResourceManager": "https://gateway.dataproc.google.com/yarn/?token=secret"}}}}
    def finding():
        return one(gcp(gcoll("dataproc_cluster", [cluster], service="dataproc")), "dataproc_cluster")
    result = finding()
    assert result["status"] == "FAIL"
    assert result["evidence"]["public_addresses"] == ["https://gateway.dataproc.google.com"]
    assert "secret" not in str(result)
    assert_gcp_observed_style(result, "spark-a")
    cluster["status"]["state"] = "STOPPED"
    result = finding()
    assert result["status"] == "UNKNOWN"
    assert_gcp_observed_style(result, "spark-a")
    cluster["status"]["state"] = "RUNNING"
    cluster["config"]["endpointConfig"]["httpPorts"] = {}
    result = finding()
    assert result["status"] == "UNKNOWN"
    assert_gcp_observed_style(result, "spark-a")
    cluster["config"]["endpointConfig"]["httpPorts"] = {"YARN": "https://gateway.example.com:8443/yarn/"}
    assert finding()["status"] == "UNKNOWN"
    cluster["config"]["endpointConfig"]["enableHttpPortAccess"] = False
    assert not exposure(gcp(gcoll("dataproc_cluster", [cluster], service="dataproc")), "dataproc_cluster")


def test_gcp_workbench_jupyter_proxy_declared_endpoint_and_limits():
    instance = {"name": "projects/p1/locations/us-central1-a/instances/book-a", "state": "ACTIVE",
                "disableProxyAccess": False,
                "proxyUri": "https://book-a.notebooks.googleusercontent.com/lab/?ticket=secret"}
    def finding():
        return one(gcp(gcoll("workbench_instance", [instance], service="notebooks")), "workbench_instance")
    result = finding()
    assert result["status"] == "FAIL"
    assert result["evidence"]["public_addresses"] == ["https://book-a.notebooks.googleusercontent.com"]
    assert "secret" not in str(result)
    assert_gcp_observed_style(result, instance["name"])
    instance["state"] = "STOPPED"
    result = finding()
    assert result["status"] == "UNKNOWN"
    assert_gcp_observed_style(result, instance["name"])
    instance["state"] = "ACTIVE"
    instance["proxyUri"] = "http://book-a.example.com/lab/"
    result = finding()
    assert result["status"] == "UNKNOWN"
    assert_gcp_observed_style(result, instance["name"])
    instance["disableProxyAccess"] = True
    assert not exposure(gcp(gcoll("workbench_instance", [instance], service="notebooks")), "workbench_instance")


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


def test_gcp_tpu_external_port_joins_collected_target_tags_and_firewall():
    from peaso.analysis.internet_exposure import Inventory, _gcp_tpu_node
    from peaso.snapshot import resources
    node = {"name": "projects/p1/locations/us-central1-a/nodes/t", "state": "READY",
            "networkConfig": {"network": NET}, "tags": ["web"],
            "serviceAccount": {"email": "sa@p1.iam.gserviceaccount.com"},
            "networkEndpoints": [{"ipAddress": "10.0.0.3", "port": 22,
                "accessConfig": {"externalIp": "34.3.3.3"}}]}
    rule = fw("allow-ssh", 1000, "allowed", ["22"], targets=["web"])
    def assessment(policy=None):
        snap = gcp(gcoll("tpu_node", [node], service="tpu"),
                   gcoll("firewall", [rule]), gcoll("firewall_policy", [policy] if policy else [],
                       status="collected" if policy else "empty"))
        items = resources(snap)
        return _gcp_tpu_node(snap, Inventory(snap, items), next(row for row in items if row["type"] == "tpu_node"))
    allowed = assessment()
    assert allowed.verdict() == "FAIL" and allowed.ports == pset("tcp", 22, 22)
    node["networkConfigs"] = [{"network": NET, "subnetwork": "subnet-a"},
                              {"network": NET, "subnetwork": "subnet-b"}]
    node.pop("networkConfig")
    assert assessment().verdict() == "FAIL"
    node["networkConfigs"][1]["network"] = "https://www.googleapis.com/compute/v1/projects/p1/global/networks/other"
    assert assessment().verdict() == "UNKNOWN"
    distinct = one(gcp(gcoll("tpu_node", [node], service="tpu"),
                       gcoll("firewall", [rule]), gcoll("firewall_policy", [], status="empty")), "tpu_node")
    assert "distinct VPC networks" in distinct["evidence"]["observed"]
    assert_gcp_observed_style(distinct, node["name"])
    node["networkConfigs"][0]["enableExternalIps"] = True
    node["networkConfigs"][1]["enableExternalIps"] = False
    selected = assessment()
    assert selected.verdict() == "FAIL" and selected.ports == pset("tcp", 22, 22)
    assert any(step["layer"] == "tpu_network_config" and step["network"] == NET for step in selected.path)
    selected_finding = one(gcp(gcoll("tpu_node", [node], service="tpu"),
        gcoll("firewall", [rule]), gcoll("firewall_policy", [], status="empty")), "tpu_node")
    assert "selected VPC" in selected_finding["evidence"]["observed"]
    assert_gcp_observed_style(selected_finding, node["name"])
    node["networkConfigs"][1]["enableExternalIps"] = True
    assert assessment().verdict() == "UNKNOWN"
    node["networkConfigs"][1]["enableExternalIps"] = False
    node["networkConfigs"][0].pop("enableExternalIps")
    assert assessment().verdict() == "UNKNOWN"
    node["networkConfigs"][0]["enableExternalIps"] = True
    node["networkConfigs"][0]["enableExternalIps"] = False
    node["networkConfigs"][1]["enableExternalIps"] = True
    assert assessment().verdict() == "UNKNOWN"
    node["networkConfigs"][0].pop("enableExternalIps")
    node["networkConfigs"][1].pop("enableExternalIps")
    node["networkConfigs"][1]["network"] = NET
    assert_gcp_observed_style(one(gcp(gcoll("tpu_node", [node], service="tpu"),
        gcoll("firewall", [rule]), gcoll("firewall_policy", [], status="empty")), "tpu_node"), node["name"])
    rule["allowed"][0]["ports"] = ["22", "80"]
    assert assessment().ports == pset("tcp", 22, 22)
    node["networkEndpoints"][0]["port"] = 443
    assert assessment().verdict() == "UNKNOWN"
    assert_gcp_observed_style(one(gcp(gcoll("tpu_node", [node], service="tpu"),
        gcoll("firewall", [rule]), gcoll("firewall_policy", [], status="empty")), "tpu_node"), node["name"])
    node["networkEndpoints"][0].pop("port")
    assert assessment().verdict() == "UNKNOWN"
    node["networkEndpoints"][0]["port"] = 22
    node.pop("tags")
    assert assessment().verdict() == "UNKNOWN"
    node["tags"] = ["web"]
    assert assessment({"name": "p", "rules": []}).verdict() == "UNKNOWN"


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


def test_gcp_backend_bucket_edge_policy_is_not_an_unprotected_route():
    from peaso.analysis.internet_exposure import Inventory, _gcp_forwarding_rule
    from peaso.snapshot import resources
    target = "https://compute.googleapis.com/compute/v1/projects/p1/global/targetHttpProxies/p"
    url_map = "https://compute.googleapis.com/compute/v1/projects/p1/global/urlMaps/m"
    backend = "https://compute.googleapis.com/compute/v1/projects/p1/global/backendBuckets/b"
    policy_ref = "https://compute.googleapis.com/compute/v1/projects/p1/global/securityPolicies/deny"
    forwarding = {"name": "fr", "IPAddress": "34.4.4.4", "IPProtocol": "TCP", "ports": ["443"],
                  "loadBalancingScheme": "EXTERNAL_MANAGED", "target": target}
    bucket = {"name": "b", "selfLink": backend, "bucketName": "origin-bucket", "enableCdn": True,
              "edgeSecurityPolicy": policy_ref}
    policy = {"name": "deny", "selfLink": policy_ref, "rules": [
        {"priority": 2147483647, "action": "deny(403)", "match": {"config": {"srcIpRanges": ["*"]}}}]}
    def assessment(bucket_row=bucket):
        snap = gcp(gcoll("forwarding_rule", [forwarding]),
                   gcoll("target_proxy", [{"name": "p", "selfLink": target, "urlMap": url_map}]),
                   gcoll("url_map", [{"name": "m", "selfLink": url_map, "defaultService": backend}]),
                   gcoll("backend_bucket", [bucket_row] if bucket_row else []),
                   gcoll("security_policy", [policy]))
        items = resources(snap)
        return _gcp_forwarding_rule(snap, Inventory(snap, items),
                                    next(row for row in items if row["type"] == "forwarding_rule"))
    assert assessment().verdict() == "PASS"
    bucket.pop("edgeSecurityPolicy")
    assert assessment().verdict() == "FAIL"
    assert assessment(None).verdict() == "UNKNOWN"


def test_gcp_backend_bucket_joins_private_origin_service_agent_grant():
    from peaso.analysis.internet_exposure import Inventory, _gcp_forwarding_rule
    from peaso.snapshot import resources
    prefix = "https://compute.googleapis.com/compute/v1/projects/p1/global/"
    target, url_map, backend = (prefix + kind + "/" + name for kind, name in (
        ("targetHttpProxies", "p"), ("urlMaps", "m"), ("backendBuckets", "b")))
    agent = "serviceAccount:service-123@https-lb.iam.gserviceaccount.com"
    policy = {"bindings": [{"role": "roles/storage.objectViewer", "members": [agent]}]}
    bucket = {"name": "origin-bucket", "iamPolicy": policy}
    def assessment():
        snap = gcp(gcoll("forwarding_rule", [{"name": "fr", "IPAddress": "34.4.4.4",
                    "IPProtocol": "TCP", "ports": ["443"], "target": target}]),
                   gcoll("target_proxy", [{"name": "p", "selfLink": target, "urlMap": url_map}]),
                   gcoll("url_map", [{"name": "m", "selfLink": url_map, "defaultService": backend}]),
                   gcoll("backend_bucket", [{"name": "b", "selfLink": backend,
                                              "bucketName": "origin-bucket", "enableCdn": True}]),
                   gcoll("project", [{"name": "projects/123", "projectNumber": "123"}]),
                   gcoll("bucket", [bucket], service="storage"))
        items = resources(snap)
        return _gcp_forwarding_rule(snap, Inventory(snap, items),
                                    next(row for row in items if row["type"] == "forwarding_rule"))
    result = assessment()
    origin = next(step for step in result.path if step["layer"] == "cdn_origin")
    assert result.verdict() == "FAIL" and origin["decision"] == "allow"
    assert origin["cdn_service_agent_read_grant"] is True
    assert origin["object_content_observed"] is False
    policy["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}
    origin = next(step for step in assessment().path if step["layer"] == "cdn_origin")
    assert origin["decision"] == "unknown"


def test_gcp_backend_bucket_joins_direct_public_origin_read_grant():
    prefix = "https://compute.googleapis.com/compute/v1/projects/p1/global/"
    target, url_map, backend = (prefix + kind + "/" + name for kind, name in (
        ("targetHttpProxies", "p"), ("urlMaps", "m"), ("backendBuckets", "b")))
    bucket = {"name": "origin-bucket",
              "iamPolicy": {"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]},
              "_coverage": {"iamPolicy": {"status": "collected"}},
              "iamConfiguration": {"publicAccessPrevention": "not_enforced"}}
    url_map_row = {"name": "m", "selfLink": url_map, "defaultService": backend}

    def finding():
        return one(gcp(gcoll("forwarding_rule", [{"name": "fr", "IPAddress": "34.4.4.4",
                    "IPProtocol": "TCP", "ports": ["443"], "target": target}]),
                   gcoll("target_proxy", [{"name": "p", "selfLink": target, "urlMap": url_map}]),
                   gcoll("url_map", [url_map_row]),
                   gcoll("backend_bucket", [{"name": "b", "selfLink": backend,
                                              "bucketName": "origin-bucket", "enableCdn": True}]),
                   gcoll("bucket", [bucket], service="storage")), "forwarding_rule")

    result = finding()
    assert result["status"] == "FAIL"
    assert_gcp_observed_style(result, "fr")
    origin = next(step for step in result["evidence"]["path"] if step["layer"] == "cdn_origin")
    assert origin["decision"] == "allow"
    assert origin["public_origin_read_grants"] == [{"role": "roles/storage.objectViewer", "member": "allUsers"}]
    assert origin["cdn_service_agent_read_grant"] is False
    url_map_row["hostRules"] = [{"hosts": ["*"], "pathMatcher": "site"}]
    url_map_row["pathMatchers"] = [{"name": "site", "defaultService": prefix + "backendServices/other"}]
    assert finding()["status"] == "UNKNOWN"
    url_map_row["hostRules"][0]["hosts"] = ["site.example.com"]
    result = finding()
    assert result["status"] == "FAIL"
    assert "unmatched Host peaso-unmatched.invalid" in result["evidence"]["observed"]
    assert_gcp_observed_style(result, "fr")
    url_map_row.pop("hostRules")
    url_map_row.pop("pathMatchers")
    bucket["iamPolicy"]["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}
    assert next(step for step in finding()["evidence"]["path"] if step["layer"] == "cdn_origin")["decision"] == "unknown"
    bucket["iamPolicy"]["bindings"][0].pop("condition")
    bucket["iamConfiguration"]["publicAccessPrevention"] = "enforced"
    assert next(step for step in finding()["evidence"]["path"] if step["layer"] == "cdn_origin")["decision"] == "unknown"
    bucket["iamConfiguration"]["publicAccessPrevention"] = "not_enforced"
    bucket["ipFilter"] = {"mode": "Enabled", "publicNetworkSource": {"allowedIpCidrRanges": []}}
    assert next(step for step in finding()["evidence"]["path"] if step["layer"] == "cdn_origin")["decision"] == "unknown"
    bucket.pop("ipFilter")
    bucket["iamPolicy"]["bindings"][0]["role"] = "roles/storage.objectCreator"
    assert next(step for step in finding()["evidence"]["path"] if step["layer"] == "cdn_origin")["decision"] == "unknown"
    bucket["iamPolicy"]["bindings"][0]["role"] = "roles/storage.objectViewer"
    bucket["iamPolicy"]["bindings"][0]["members"] = ["allAuthenticatedUsers"]
    bucket["ipFilter"] = {"mode": "Disabled"}
    assert next(step for step in finding()["evidence"]["path"] if step["layer"] == "cdn_origin")["decision"] == "allow"
    bucket["_coverage"]["iamPolicy"]["status"] = "denied"
    assert next(step for step in finding()["evidence"]["path"] if step["layer"] == "cdn_origin")["decision"] == "unknown"


def test_gcp_backend_bucket_joins_complete_public_object_acl_on_default_route():
    prefix = "https://compute.googleapis.com/compute/v1/projects/p1/global/"
    target, url_map_ref, backend = (prefix + kind + "/" + name for kind, name in (
        ("targetHttpProxies", "p"), ("urlMaps", "m"), ("backendBuckets", "b")))
    url_map = {"name": "m", "selfLink": url_map_ref, "defaultService": backend}
    acl = {"status": "collected", "all_pages": True, "all_objects": True, "all_versions": True,
           "projection": "full", "source_inventory": "object_acl", "source_requests": ["storage.objects.list"],
           "items": [{"entity": "allUsers", "role": "READER"}]}
    bucket = {"name": "origin-bucket", "iamPolicy": {"bindings": []},
              "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": False},
                                   "publicAccessPrevention": "not_enforced"},
              "objectAccessControls": acl}
    def finding():
        return one(gcp(gcoll("forwarding_rule", [{"name": "acl-fr", "IPAddress": "34.4.4.4",
                    "IPProtocol": "TCP", "ports": ["443"], "target": target}]),
                   gcoll("target_proxy", [{"name": "p", "selfLink": target, "urlMap": url_map_ref}]),
                   gcoll("url_map", [url_map]),
                   gcoll("backend_bucket", [{"name": "b", "selfLink": backend,
                                              "bucketName": "origin-bucket", "enableCdn": True}]),
                   gcoll("bucket", [bucket], service="storage")), "forwarding_rule")
    result = finding()
    assert result["status"] == "FAIL"
    origin = next(step for step in result["evidence"]["path"] if step["layer"] == "cdn_origin")
    assert origin["public_object_acl_grants"] == [{"role": "object ACL READER", "member": "allUsers",
                                                   "source": "objectAccessControls"}]
    assert "At least one origin object" in result["evidence"]["observed"]
    assert_gcp_observed_style(result, "acl-fr")
    acl["all_versions"] = False
    assert next(step for step in finding()["evidence"]["path"] if step["layer"] == "cdn_origin")["decision"] == "unknown"
    acl["all_versions"] = True
    bucket["iamConfiguration"]["publicAccessPrevention"] = "enforced"
    assert next(step for step in finding()["evidence"]["path"] if step["layer"] == "cdn_origin")["decision"] == "unknown"
    bucket["iamConfiguration"]["publicAccessPrevention"] = "not_enforced"
    bucket["ipFilter"] = {"mode": "Enabled", "publicNetworkSource": {"allowedIpCidrRanges": []}}
    assert next(step for step in finding()["evidence"]["path"] if step["layer"] == "cdn_origin")["decision"] == "unknown"
    bucket.pop("ipFilter")
    url_map["hostRules"] = [{"hosts": ["site.example.com"], "pathMatcher": "other"}]
    url_map["pathMatchers"] = [{"name": "other", "defaultService": prefix + "backendServices/other"}]
    result = finding()
    origin = next(step for step in result["evidence"]["path"] if step["layer"] == "cdn_origin")
    assert result["status"] == "FAIL" and origin["host_witness"] == "peaso-unmatched.invalid"
    assert "unmatched Host peaso-unmatched.invalid" in result["evidence"]["observed"]
    assert_gcp_observed_style(result, "acl-fr")
    url_map["hostRules"] = [{"hosts": ["*"], "pathMatcher": "other"}]
    url_map["pathMatchers"] = [{"name": "other", "defaultService": prefix + "backendServices/other"}]
    result = finding()
    assert result["status"] == "UNKNOWN"
    assert not any(step["layer"] == "cdn_origin" for step in result["evidence"]["path"])
    url_map["pathMatchers"][0]["defaultService"] = backend
    result = finding()
    assert result["status"] == "FAIL"
    assert_gcp_observed_style(result, "acl-fr")
    url_map["pathMatchers"][0]["pathRules"] = [{"paths": ["/*"], "service": prefix + "backendServices/other"}]
    result = finding()
    assert result["status"] == "UNKNOWN"
    assert not any(step["layer"] == "cdn_origin" for step in result["evidence"]["path"])


def test_gcp_backend_bucket_joins_public_managed_folder_on_default_route():
    prefix = "https://compute.googleapis.com/compute/v1/projects/p1/global/"
    target, url_map_ref, backend = (prefix + kind + "/" + name for kind, name in (
        ("targetHttpProxies", "p"), ("urlMaps", "m"), ("backendBuckets", "b")))
    bucket = {"name": "origin-bucket", "iamPolicy": {"bindings": []},
              "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True},
                                   "publicAccessPrevention": "not_enforced"}}
    folder = {"name": "public/", "bucket": "origin-bucket", "iamPolicy": {"bindings": [
        {"role": "roles/storage.objectViewer", "members": ["allUsers"]}]}}
    role = {"name": "projects/p1/roles/folderObjectReader", "includedPermissions": ["storage.objects.get"]}
    url_map = {"name": "m", "selfLink": url_map_ref, "defaultService": backend}
    def finding():
        return one(gcp(gcoll("forwarding_rule", [{"name": "folder-fr", "IPAddress": "34.4.4.4",
                    "IPProtocol": "TCP", "ports": ["443"], "target": target}]),
                   gcoll("target_proxy", [{"name": "p", "selfLink": target, "urlMap": url_map_ref}]),
                   gcoll("url_map", [url_map]),
                   gcoll("backend_bucket", [{"name": "b", "selfLink": backend,
                                              "bucketName": "origin-bucket", "enableCdn": True}]),
                   gcoll("bucket", [bucket], service="storage"),
                   gcoll("managed_folder", [folder], service="storage"),
                   gcoll("iam_role", [role], service="iam")), "forwarding_rule")
    result = finding()
    assert result["status"] == "FAIL"
    origin = next(step for step in result["evidence"]["path"] if step["layer"] == "cdn_origin")
    assert origin["public_managed_folder_grants"] == [{"role": "roles/storage.objectViewer",
        "member": "allUsers", "folder": "public/", "source": "managed_folder"}]
    assert "managed folder public/" in result["evidence"]["observed"]
    assert_gcp_observed_style(result, "folder-fr")
    folder["iamPolicy"]["bindings"][0]["role"] = role["name"]
    assert finding()["status"] == "FAIL"
    role["includedPermissions"] = ["storage.objects.list"]
    assert next(step for step in finding()["evidence"]["path"] if step["layer"] == "cdn_origin")["decision"] == "unknown"
    role["includedPermissions"] = ["storage.objects.get"]
    folder["iamPolicy"]["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}
    assert next(step for step in finding()["evidence"]["path"] if step["layer"] == "cdn_origin")["decision"] == "unknown"
    folder["iamPolicy"]["bindings"][0].pop("condition")
    bucket["iamConfiguration"]["publicAccessPrevention"] = "enforced"
    assert next(step for step in finding()["evidence"]["path"] if step["layer"] == "cdn_origin")["decision"] == "unknown"
    bucket["iamConfiguration"]["publicAccessPrevention"] = "not_enforced"
    folder["bucket"] = "other-bucket"
    assert next(step for step in finding()["evidence"]["path"] if step["layer"] == "cdn_origin")["decision"] == "unknown"
    folder["bucket"] = "origin-bucket"
    url_map["hostRules"] = [{"hosts": ["site.example.com"], "pathMatcher": "site"}]
    url_map["pathMatchers"] = [{"name": "site", "defaultService": prefix + "backendServices/other"}]
    result = finding()
    assert result["status"] == "FAIL"
    assert "unmatched Host peaso-unmatched.invalid" in result["evidence"]["observed"]
    assert_gcp_observed_style(result, "folder-fr")


def test_gcp_backend_bucket_joins_project_inherited_service_agent_read_grant():
    from peaso.analysis.internet_exposure import Inventory, _gcp_forwarding_rule
    from peaso.snapshot import resources
    prefix = "https://compute.googleapis.com/compute/v1/projects/p1/global/"
    target, url_map, backend = (prefix + kind + "/" + name for kind, name in (
        ("targetHttpProxies", "p"), ("urlMaps", "m"), ("backendBuckets", "b")))
    role_name = "projects/p1/roles/cdnOriginReader"
    project_policy = {"name": GSCOPE, "bindings": [
        {"role": role_name, "members": ["serviceAccount:service-123@https-lb.iam.gserviceaccount.com"]}]}
    role = {"name": role_name, "includedPermissions": ["storage.objects.get"]}
    def assessment():
        snap = gcp(gcoll("forwarding_rule", [{"name": "fr", "IPAddress": "34.4.4.4",
                    "IPProtocol": "TCP", "ports": ["443"], "target": target}]),
                   gcoll("target_proxy", [{"name": "p", "selfLink": target, "urlMap": url_map}]),
                   gcoll("url_map", [{"name": "m", "selfLink": url_map, "defaultService": backend}]),
                   gcoll("backend_bucket", [{"name": "b", "selfLink": backend,
                                              "bucketName": "origin-bucket", "enableCdn": True}]),
                   gcoll("project", [{"name": GSCOPE, "projectNumber": "123"}]),
                   gcoll("bucket", [{"name": "origin-bucket", "iamPolicy": {"bindings": []}}], service="storage"),
                   gcoll("iam_policy", [project_policy], service="cloudasset"),
                   gcoll("iam_role", [role], service="iam"))
        items = resources(snap)
        return _gcp_forwarding_rule(snap, Inventory(snap, items),
                                    next(row for row in items if row["type"] == "forwarding_rule"))
    origin = next(step for step in assessment().path if step["layer"] == "cdn_origin")
    assert origin["decision"] == "allow"
    assert origin["cdn_service_agent_inherited_grants"][0]["permission"] == "storage.objects.get"
    role["includedPermissions"] = ["storage.buckets.get"]
    assert next(step for step in assessment().path if step["layer"] == "cdn_origin")["decision"] == "unknown"
    role["includedPermissions"] = ["storage.objects.get"]
    project_policy["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}
    assert next(step for step in assessment().path if step["layer"] == "cdn_origin")["decision"] == "unknown"


def test_gcp_backend_bucket_joins_project_public_object_viewer_grant():
    prefix = "https://compute.googleapis.com/compute/v1/projects/p1/global/"
    target, url_map, backend = (prefix + kind + "/" + name for kind, name in (
        ("targetHttpProxies", "p"), ("urlMaps", "m"), ("backendBuckets", "b")))
    bucket = {"name": "origin-bucket", "iamPolicy": {"bindings": []},
              "_coverage": {"iamPolicy": {"status": "collected"}},
              "iamConfiguration": {"publicAccessPrevention": "not_enforced"}}
    project_policy = {"name": GSCOPE, "bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]}
    custom_role = {"name": "projects/p1/roles/originReader", "stage": "GA",
                   "includedPermissions": ["storage.objects.get"]}
    def finding():
        return one(gcp(gcoll("forwarding_rule", [{"name": "fr", "IPAddress": "34.4.4.4",
                    "IPProtocol": "TCP", "ports": ["443"], "target": target}]),
                   gcoll("target_proxy", [{"name": "p", "selfLink": target, "urlMap": url_map}]),
                   gcoll("url_map", [{"name": "m", "selfLink": url_map, "defaultService": backend}]),
                   gcoll("backend_bucket", [{"name": "b", "selfLink": backend,
                                              "bucketName": "origin-bucket", "enableCdn": True}]),
                   gcoll("bucket", [bucket], service="storage"),
                   gcoll("iam_policy", [project_policy], service="cloudasset"),
                   gcoll("iam_role", [custom_role], service="iam")), "forwarding_rule")
    result = finding()
    assert result["status"] == "FAIL"
    assert_gcp_observed_style(result, "fr")
    origin = next(step for step in result["evidence"]["path"] if step["layer"] == "cdn_origin")
    assert origin["public_origin_read_grants"] == [
        {"role": "roles/storage.objectViewer", "member": "allUsers", "scope": GSCOPE}]
    assert GSCOPE in result["evidence"]["observed"]
    project_policy["bindings"][0]["role"] = custom_role["name"]
    result = finding()
    assert next(step for step in result["evidence"]["path"] if step["layer"] == "cdn_origin")["public_origin_read_grants"] == [
        {"role": custom_role["name"], "member": "allUsers", "scope": GSCOPE,
         "permission": "storage.objects.get"}]
    assert "including storage.objects.get" in result["evidence"]["observed"]
    assert_gcp_observed_style(result, "fr")
    custom_role["includedPermissions"] = ["storage.objects.create"]
    assert next(step for step in finding()["evidence"]["path"] if step["layer"] == "cdn_origin")["decision"] == "unknown"
    custom_role["includedPermissions"] = ["storage.objects.get"]
    custom_role["stage"] = "DISABLED"
    assert next(step for step in finding()["evidence"]["path"] if step["layer"] == "cdn_origin")["decision"] == "unknown"
    custom_role["stage"] = "GA"
    project_policy["bindings"] = []
    bucket["iamPolicy"]["bindings"] = [{"role": custom_role["name"], "members": ["allUsers"]}]
    origin = next(step for step in finding()["evidence"]["path"] if step["layer"] == "cdn_origin")
    assert origin["public_origin_read_grants"] == [
        {"role": custom_role["name"], "member": "allUsers", "permission": "storage.objects.get"}]
    bucket["iamPolicy"]["bindings"] = []
    project_policy["bindings"] = [{"role": custom_role["name"], "members": ["allUsers"]}]
    project_policy["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}
    assert next(step for step in finding()["evidence"]["path"] if step["layer"] == "cdn_origin")["decision"] == "unknown"
    project_policy["bindings"][0].pop("condition")
    bucket["iamConfiguration"]["publicAccessPrevention"] = "enforced"
    assert next(step for step in finding()["evidence"]["path"] if step["layer"] == "cdn_origin")["decision"] == "unknown"
    bucket["iamConfiguration"]["publicAccessPrevention"] = "not_enforced"
    bucket["ipFilter"] = {"mode": "Enabled", "publicNetworkSource": {"allowedIpCidrRanges": []}}
    assert next(step for step in finding()["evidence"]["path"] if step["layer"] == "cdn_origin")["decision"] == "unknown"


def test_gcp_url_map_weighted_and_route_rule_backends_join_armor():
    from peaso.analysis.internet_exposure import Inventory, _gcp_forwarding_rule
    from peaso.snapshot import resources
    prefix = "https://compute.googleapis.com/compute/v1/projects/p1/global/"
    target, url_map, backend, policy_ref = (prefix + kind + "/" + name for kind, name in (
        ("targetHttpProxies", "p"), ("urlMaps", "m"), ("backendServices", "b"), ("securityPolicies", "deny")))
    forwarding = {"name": "fr", "IPAddress": "34.4.4.4", "IPProtocol": "TCP", "ports": ["443"],
                  "loadBalancingScheme": "EXTERNAL_MANAGED", "target": target}
    policy = {"name": "deny", "selfLink": policy_ref, "rules": [
        {"priority": 2147483647, "action": "deny(403)", "match": {"config": {"srcIpRanges": ["*"]}}}]}
    action = {"weightedBackendServices": [{"backendService": backend, "weight": 100}]}
    for mapping, expected in (
            ({"defaultRouteAction": action}, "PASS"),
            ({"pathMatchers": [{"defaultRouteAction": action}]}, "UNKNOWN"),
            ({"pathMatchers": [{"pathRules": [{"routeAction": action}]}]}, "UNKNOWN"),
            ({"pathMatchers": [{"routeRules": [{"routeAction": action}]}]}, "UNKNOWN"),
            ({"hostRules": [{"hosts": ["site.example.com"], "pathMatcher": "site"}],
              "pathMatchers": [{"name": "site", "defaultRouteAction": action}]}, "PASS"),
            ({"hostRules": [{"hosts": ["*"], "pathMatcher": "site"}],
              "pathMatchers": [{"name": "site", "routeRules": [{"priority": 100,
                  "matchRules": [{"prefixMatch": "/"}], "routeAction": action}]}]}, "PASS"),
            ({"hostRules": [{"hosts": ["*"], "pathMatcher": "site"}],
              "pathMatchers": [{"name": "site", "routeRules": [{"priority": 100,
                  "matchRules": [{"prefixMatch": "/"}], "routeAction": action},
                  {"priority": 200, "matchRules": [{"fullPathMatch": "/later"}],
                   "service": prefix + "backendServices/missing"}]}]}, "PASS"),
            ({"hostRules": [{"hosts": ["*"], "pathMatcher": "site"}],
              "pathMatchers": [{"name": "site", "routeRules": [{"priority": 100,
                  "matchRules": [{"prefixMatch": "/"}], "routeAction": action},
                  {"priority": 100, "matchRules": [{"fullPathMatch": "/later"}],
                   "service": prefix + "backendServices/missing"}]}]}, "UNKNOWN"),
            ({"hostRules": [{"hosts": ["*"], "pathMatcher": "site"}],
              "pathMatchers": [{"name": "site", "routeRules": [{"priority": 100,
                  "matchRules": [{"prefixMatch": "/", "headerMatches": [{"headerName": "X-Test"}]}],
                  "routeAction": action}]}]}, "UNKNOWN"),
            ({"hostRules": [{"hosts": ["*"], "pathMatcher": "site"}],
              "pathMatchers": [{"name": "site", "defaultRouteAction": action, "routeRules": [
                  {"priority": 100, "matchRules": [{"prefixMatch": "/"}],
                   "service": prefix + "backendServices/missing"}]}]}, "UNKNOWN")):
        snap = gcp(gcoll("forwarding_rule", [forwarding]),
                   gcoll("target_proxy", [{"name": "p", "selfLink": target, "urlMap": url_map}]),
                   gcoll("url_map", [{"name": "m", "selfLink": url_map, **mapping}]),
                   gcoll("backend_service", [{"name": "b", "selfLink": backend, "securityPolicy": policy_ref}]),
                   gcoll("security_policy", [policy]))
        items = resources(snap)
        result = _gcp_forwarding_rule(snap, Inventory(snap, items),
                                      next(row for row in items if row["type"] == "forwarding_rule"))
        assert result.verdict() == expected, mapping
        if any(step["layer"] == "url_route_rule" for step in result.path) and expected == "UNKNOWN":
            assert_gcp_observed_style(one(snap, "forwarding_rule"), "fr")
    policy["rules"][0]["action"] = "allow"
    universal = {"hostRules": [{"hosts": ["*"], "pathMatcher": "site"}],
                 "pathMatchers": [{"name": "site", "routeRules": [{"priority": 100,
                     "matchRules": [{"prefixMatch": "/"}], "routeAction": action}]}]}
    result = one(gcp(gcoll("forwarding_rule", [forwarding]),
                     gcoll("target_proxy", [{"name": "p", "selfLink": target, "urlMap": url_map}]),
                     gcoll("url_map", [{"name": "m", "selfLink": url_map, **universal}]),
                     gcoll("backend_service", [{"name": "b", "selfLink": backend, "securityPolicy": policy_ref}]),
                     gcoll("security_policy", [policy])), "forwarding_rule")
    assert result["status"] == "FAIL" and "priority 100" in result["evidence"]["observed"]
    assert_gcp_observed_style(result, "fr")
    universal["pathMatchers"][0]["routeRules"].append({"priority": 200,
        "matchRules": [{"fullPathMatch": "/later"}], "service": prefix + "backendServices/missing"})
    result = one(gcp(gcoll("forwarding_rule", [forwarding]),
                     gcoll("target_proxy", [{"name": "p", "selfLink": target, "urlMap": url_map}]),
                     gcoll("url_map", [{"name": "m", "selfLink": url_map, **universal}]),
                     gcoll("backend_service", [{"name": "b", "selfLink": backend, "securityPolicy": policy_ref}]),
                     gcoll("security_policy", [policy])), "forwarding_rule")
    assert result["status"] == "FAIL"
    assert_gcp_observed_style(result, "fr")


def test_gcp_path_rule_backend_bucket_requires_selected_host_path_and_public_origin():
    prefix = "https://compute.googleapis.com/compute/v1/projects/p1/global/"
    target = prefix + "targetHttpProxies/p"
    url_map = prefix + "urlMaps/m"
    backend = prefix + "backendBuckets/b"
    other = prefix + "backendBuckets/other"
    mapping = {"name": "m", "selfLink": url_map,
               "hostRules": [{"hosts": ["site.example.com"], "pathMatcher": "site"}],
               "pathMatchers": [{"name": "site", "defaultService": other,
                                 "pathRules": [{"paths": ["/public/*"], "service": backend}]}]}
    bucket = {"name": "origin-bucket", "iamPolicy": {"bindings": [
        {"role": "roles/storage.objectViewer", "members": ["allUsers"]}]},
        "_coverage": {"iamPolicy": {"status": "collected"}},
        "iamConfiguration": {"publicAccessPrevention": "not_enforced"}}

    def finding():
        return one(gcp(gcoll("forwarding_rule", [{"name": "fr", "IPAddress": "34.4.4.4",
                    "IPProtocol": "TCP", "ports": ["80"], "target": target}]),
                   gcoll("target_proxy", [{"name": "p", "selfLink": target, "urlMap": url_map}]),
                   gcoll("url_map", [mapping]),
                   gcoll("backend_bucket", [{"name": "b", "selfLink": backend,
                                              "bucketName": "origin-bucket", "enableCdn": True}]),
                   gcoll("bucket", [bucket], service="storage")), "forwarding_rule")

    result = finding()
    assert result["status"] == "FAIL", result
    assert_gcp_observed_style(result, "fr")
    assert "Host site.example.com path /public/peaso-witness" in result["evidence"]["observed"]
    assert any(step["layer"] == "url_path_rule" for step in result["evidence"]["path"])
    mapping["pathMatchers"][0]["pathRules"].insert(0, {"paths": ["/public/peaso-witness"], "service": other})
    assert finding()["status"] == "UNKNOWN"
    mapping["pathMatchers"][0]["pathRules"][0]["paths"] = ["/public/other"]
    assert finding()["status"] == "FAIL"
    mapping["pathMatchers"][0]["pathRules"][1]["paths"] = ["public/*"]
    assert finding()["status"] == "UNKNOWN"


def test_gcp_path_rule_backend_cloud_armor_deny_is_partial_unknown():
    prefix = "https://compute.googleapis.com/compute/v1/projects/p1/global/"
    target, url_map, backend, policy_ref = (prefix + kind + "/" + name for kind, name in (
        ("targetHttpProxies", "p"), ("urlMaps", "m"),
        ("backendServices", "b"), ("securityPolicies", "deny")))
    mapping = {"name": "m", "selfLink": url_map,
               "hostRules": [{"hosts": ["*"], "pathMatcher": "site"}],
               "pathMatchers": [{"name": "site", "pathRules": [
                   {"paths": ["/private/*"], "service": backend}]}]}
    policy = {"name": "deny", "selfLink": policy_ref, "rules": [
        {"priority": 2147483647, "action": "deny(403)",
         "match": {"config": {"srcIpRanges": ["*"]}}}]}
    snap = gcp(gcoll("forwarding_rule", [{"name": "fr", "IPAddress": "34.4.4.4",
                    "IPProtocol": "TCP", "ports": ["80"], "target": target}]),
               gcoll("target_proxy", [{"name": "p", "selfLink": target, "urlMap": url_map}]),
               gcoll("url_map", [mapping]),
               gcoll("backend_service", [{"name": "b", "selfLink": backend,
                                           "securityPolicy": policy_ref}]),
               gcoll("security_policy", [policy]))
    result = one(snap, "forwarding_rule")
    assert result["status"] == "UNKNOWN"
    assert_gcp_observed_style(result, "fr")
    assert "path rule /private/*" in result["evidence"]["observed"]
    mapping["pathMatchers"][0]["pathRules"][0]["paths"] = ["/*"]
    universal = one(gcp(gcoll("forwarding_rule", [{"name": "fr", "IPAddress": "34.4.4.4",
                    "IPProtocol": "TCP", "ports": ["80"], "target": target}]),
                gcoll("target_proxy", [{"name": "p", "selfLink": target, "urlMap": url_map}]),
                gcoll("url_map", [mapping]),
                gcoll("backend_service", [{"name": "b", "selfLink": backend,
                                            "securityPolicy": policy_ref}]),
                gcoll("security_policy", [policy])), "forwarding_rule")
    assert universal["status"] == "PASS"


def test_gcp_first_route_rule_backend_path_witness_is_positive_only():
    prefix = "https://compute.googleapis.com/compute/v1/projects/p1/global/"
    target, url_map_ref, backend, policy_ref = (prefix + kind + "/" + name for kind, name in (
        ("targetHttpProxies", "p"), ("urlMaps", "m"), ("backendServices", "b"), ("securityPolicies", "armor")))
    forwarding = {"name": "route-fr", "IPAddress": "34.4.4.4", "IPProtocol": "TCP",
                  "ports": ["80"], "target": target, "loadBalancingScheme": "EXTERNAL_MANAGED"}
    rule = {"priority": 10, "matchRules": [{"fullPathMatch": "/admin"}], "service": backend}
    url_map = {"name": "m", "selfLink": url_map_ref,
               "hostRules": [{"hosts": ["site.example.com"], "pathMatcher": "site"}],
               "pathMatchers": [{"name": "site", "defaultService": prefix + "backendServices/other",
                                 "routeRules": [rule]}]}
    policy = {"name": "armor", "selfLink": policy_ref,
              "rules": [{"priority": 2147483647, "action": "allow", "match": {"config": {"srcIpRanges": ["*"]}}}]}
    def finding():
        return one(gcp(gcoll("forwarding_rule", [forwarding]),
                       gcoll("target_proxy", [{"name": "p", "selfLink": target, "urlMap": url_map_ref}]),
                       gcoll("url_map", [url_map]),
                       gcoll("backend_service", [{"name": "b", "selfLink": backend,
                                                  "securityPolicy": policy_ref}]),
                       gcoll("security_policy", [policy])), "forwarding_rule")
    result = finding()
    assert result["status"] == "FAIL" and result["evidence"]["exposed_ports"] == ["tcp/80"]
    assert "Host site.example.com" in result["evidence"]["observed"]
    assert "path exact /admin" in result["evidence"]["observed"]
    assert_gcp_observed_style(result, "route-fr")
    policy["rules"][0]["action"] = "deny(403)"
    result = finding()
    assert result["status"] == "UNKNOWN"
    assert any("other host and path routes" in gap["reason"] for gap in result["evidence"]["unresolved"])
    assert_gcp_observed_style(result, "route-fr")
    policy["rules"][0]["action"] = "allow"
    rule["matchRules"] = [{"prefixMatch": "/admin"}]
    assert finding()["status"] == "FAIL"
    rule["matchRules"] = [{"prefixMatch": "/admin", "headerMatches": [{"headerName": "X-Token"}]}]
    result = finding()
    assert result["status"] == "UNKNOWN"
    assert not any(step["layer"] == "url_route_rule" for step in result["evidence"]["path"])


def test_gcp_later_path_route_rule_backend_requires_disjoint_predecessors():
    prefix = "https://compute.googleapis.com/compute/v1/projects/p1/global/"
    target, url_map_ref, backend, policy_ref = (prefix + kind + "/" + name for kind, name in (
        ("targetHttpProxies", "p"), ("urlMaps", "m"), ("backendServices", "b"), ("securityPolicies", "armor")))
    forwarding = {"name": "later-fr", "IPAddress": "34.4.4.4", "IPProtocol": "TCP",
                  "ports": ["80"], "target": target, "loadBalancingScheme": "EXTERNAL_MANAGED"}
    earlier = {"priority": 10, "matchRules": [{"prefixMatch": "/old",
                   "headerMatches": [{"headerName": "X-Choice", "exactMatch": "old"}]}],
               "service": prefix + "backendServices/missing"}
    later = {"priority": 20, "matchRules": [{"fullPathMatch": "/admin"}], "service": backend}
    url_map = {"name": "m", "selfLink": url_map_ref,
               "hostRules": [{"hosts": ["site.example.com"], "pathMatcher": "site"}],
               "pathMatchers": [{"name": "site", "routeRules": [earlier, later]}]}
    policy = {"name": "armor", "selfLink": policy_ref,
              "rules": [{"priority": 2147483647, "action": "allow", "match": {"config": {"srcIpRanges": ["*"]}}}]}
    def finding():
        return one(gcp(gcoll("forwarding_rule", [forwarding]),
                       gcoll("target_proxy", [{"name": "p", "selfLink": target, "urlMap": url_map_ref}]),
                       gcoll("url_map", [url_map]),
                       gcoll("backend_service", [{"name": "b", "selfLink": backend,
                                                  "securityPolicy": policy_ref}]),
                       gcoll("security_policy", [policy])), "forwarding_rule")
    result = finding()
    assert result["status"] == "FAIL" and "priority 20" in result["evidence"]["observed"]
    assert "path exact /admin" in result["evidence"]["observed"]
    assert_gcp_observed_style(result, "later-fr")
    policy["rules"][0]["action"] = "deny(403)"
    result = finding()
    assert result["status"] == "UNKNOWN"
    assert_gcp_observed_style(result, "later-fr")
    policy["rules"][0]["action"] = "allow"
    earlier["matchRules"][0]["prefixMatch"] = "/"
    assert finding()["status"] == "UNKNOWN"
    earlier["matchRules"][0]["prefixMatch"] = "/old"
    later["matchRules"] = [{"prefixMatch": "/admin"}]
    result = finding()
    assert result["status"] == "FAIL" and "path prefix /admin" in result["evidence"]["observed"]
    assert_gcp_observed_style(result, "later-fr")
    earlier["matchRules"][0]["prefixMatch"] = "/admin"
    assert finding()["status"] == "UNKNOWN"
    later["matchRules"] = [{"fullPathMatch": "/admin"}]
    earlier["matchRules"] = [{"pathTemplateMatch": "/{path=**}"}]
    assert finding()["status"] == "UNKNOWN"


def test_gcp_cdn_backend_service_edge_policy_precedes_cache_and_backend_policy():
    from peaso.analysis.internet_exposure import Inventory, _gcp_forwarding_rule
    from peaso.snapshot import resources
    prefix = "https://compute.googleapis.com/compute/v1/projects/p1/global/"
    target = prefix + "targetHttpProxies/p"
    url_map = prefix + "urlMaps/m"
    backend_ref = prefix + "backendServices/b"
    edge_ref = prefix + "securityPolicies/edge"
    backend_policy_ref = prefix + "securityPolicies/backend"
    deny = [{"priority": 2147483647, "action": "deny(403)", "match": {"config": {"srcIpRanges": ["*"]}}}]
    allow = [{"priority": 2147483647, "action": "allow", "match": {"config": {"srcIpRanges": ["*"]}}}]
    forwarding = {"name": "fr", "IPAddress": "34.4.4.4", "IPProtocol": "TCP", "ports": ["443"],
                  "loadBalancingScheme": "EXTERNAL_MANAGED", "target": target}
    backend = {"name": "b", "selfLink": backend_ref, "enableCDN": True,
               "securityPolicy": backend_policy_ref, "edgeSecurityPolicy": edge_ref}
    edge = {"name": "edge", "selfLink": edge_ref, "rules": deny}
    backend_policy = {"name": "backend", "selfLink": backend_policy_ref, "rules": deny}
    def assess_backend():
        snap = gcp(gcoll("forwarding_rule", [forwarding]),
                   gcoll("target_proxy", [{"name": "p", "selfLink": target, "urlMap": url_map}]),
                   gcoll("url_map", [{"name": "m", "selfLink": url_map, "defaultService": backend_ref}]),
                   gcoll("backend_service", [backend]), gcoll("security_policy", [edge, backend_policy]))
        items = resources(snap)
        return _gcp_forwarding_rule(snap, Inventory(snap, items),
                                    next(row for row in items if row["type"] == "forwarding_rule"))
    assert assess_backend().verdict() == "PASS"  # edge deny covers cache hits
    backend.pop("edgeSecurityPolicy")
    assert assess_backend().verdict() == "UNKNOWN"  # backend deny only covers misses
    backend["enableCDN"] = False
    assert assess_backend().verdict() == "PASS"
    backend_policy["rules"] = allow
    assert assess_backend().verdict() == "FAIL"


def test_gcp_vmware_declared_public_path_preserves_nsx_api_boundary():
    from peaso.analysis.internet_exposure import Inventory, _gcp_vmware_address
    from peaso.snapshot import resources
    cloud = "projects/p1/locations/us-central1-a/privateClouds/c"
    address = cloud + "/externalAddresses/a"
    policy = "projects/p1/locations/us-central1/networkPolicies/p"
    network = "projects/123/locations/global/vmwareEngineNetworks/n"
    snap = gcp(
        gcoll("vmware_external_address", [{"name": address, "state": "ACTIVE", "externalIp": "34.4.4.4"}], service="vmwareengine"),
        gcoll("vmware_private_cloud", [{"name": cloud, "networkConfig": {"vmwareEngineNetworkCanonical": network}}], service="vmwareengine"),
        gcoll("vmware_network_policy", [{"name": policy, "vmwareEngineNetworkCanonical": network,
                                         "externalIp": {"enabled": True, "state": "ACTIVE"}}], service="vmwareengine"),
        gcoll("vmware_external_access_rule", [{"name": policy + "/externalAccessRules/allow", "state": "ACTIVE",
            "priority": 100, "action": "ALLOW", "ipProtocol": "tcp", "sourceIpRanges": [{"ipAddressRange": "0.0.0.0/0"}],
            "destinationIpRanges": [{"externalAddress": address}], "destinationPorts": ["443"]}], service="vmwareengine"))
    items = resources(snap)
    resource = next(row for row in items if row["type"] == "vmware_external_address")
    assessment = _gcp_vmware_address(snap, Inventory(snap, items), resource)
    assert assessment.verdict() == "FAIL" and assessment.ports == pset("tcp", 443, 443)
    assert any("NSX gateway and distributed firewall rules are not visible" in note for note in assessment.notes)


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
    config = {"id": app["id"] + "/config/web", "parent_id": app["id"], "properties": {"ipSecurityRestrictions": [{"ipAddress": "Any", "action": "Allow", "priority": 2147483647, "name": "Allow all"}], "scmIpSecurityRestrictionsUseMain": True}}
    snapshot = azure(coll("app_service", [app], scope=SUB, service="web"), coll("app_service_config", [config], scope=app["id"], service="web"))
    assert one(snapshot, "app_service")["status"] == "FAIL"
    restricted = copy.deepcopy(config)
    restricted["properties"] = {"ipSecurityRestrictions": [{"ipAddress": "203.0.113.0/24", "action": "Allow", "priority": 100}], "ipSecurityRestrictionsDefaultAction": "Deny", "scmIpSecurityRestrictionsUseMain": True}
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
    ({"type": "LoadBalancer", "ports": [{"port": 443}]}, {"service.beta.kubernetes.io/load-balancer-source-ranges": "*"}, "FAIL"),
])
def test_k8s_load_balancer_source_ranges(spec, annotations, expected):
    assert one(k8s(svc(spec, annotations)), "service")["status"] == expected


def test_k8s_invalid_service_source_range_stays_unknown():
    spec = {"type": "LoadBalancer", "ports": [{"port": 443}]}
    annotations = {"service.beta.kubernetes.io/load-balancer-source-ranges": "not-a-cidr"}
    result = one(k8s(svc(spec, annotations)), "service")
    assert result["status"] == "UNKNOWN"
    assert result["evidence"]["blocked_by"] is None
    assert result["evidence"]["path"][-1] == {"layer": "source_ranges", "decision": "unknown",
                                             "invalid_source_ranges": ["not-a-cidr"]}
    observed = result["evidence_summary"].splitlines()
    assert len(observed) == 4
    assert observed[0] == "The Service has source range not-a-cidr, which is not a valid IP range."
    assert "may" in observed[2] and "could" in observed[3]


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


def test_k8s_invalid_ingress_source_range_stays_unknown():
    ingress = {"metadata": {"name": "i", "namespace": "apps", "annotations":
               {"nginx.ingress.kubernetes.io/whitelist-source-range": "10.0.0.0/8, broken-cidr"}},
               "spec": {"rules": [{"host": "x.example.com"}]},
               "status": {"loadBalancer": {"ingress": [{"ip": "34.9.9.9"}]}}}
    result = one(k8s(coll("ingress", [ingress], scope="cluster")), "ingress")
    assert result["status"] == "UNKNOWN"
    assert result["evidence"]["blocked_by"] is None
    assert result["evidence"]["path"][-1] == {"layer": "source_ranges", "decision": "unknown",
                                             "invalid_source_ranges": ["broken-cidr"]}
    observed = result["evidence_summary"].splitlines()
    assert len(observed) == 4
    assert observed[0] == "The Ingress has source range broken-cidr, which is not a valid IP range."
    assert "may" in observed[2] and "could" in observed[3]


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


def test_http_api_live_route_does_not_claim_deployed_public_access():
    endpoint = "https://9gi0nszlth.execute-api.ca-central-1.amazonaws.com"
    api = {"ApiId": "9gi0nszlth", "ApiEndpoint": endpoint, "ProtocolType": "HTTP",
           "Routes": [{"RouteKey": "GET /", "AuthorizationType": "NONE"}],
           "Stages": {"collection_status": "collected", "items": [{"StageName": "$default", "AutoDeploy": True}]}}
    result = one(aws(coll("http_api", [api], service="apigatewayv2")), "http_api")
    assert result["status"] == "UNKNOWN" and result["severity"] == "info"
    assert "apigatewayv2:ExportApi" in result["evidence"]["collector_facts_needed"]
    assert result["evidence"]["public_addresses"] == [endpoint]
    assert result["evidence"]["observed"] == "Internet access could not be determined because required configuration is missing."
    assert "no traffic was sent" in result["evidence"]["semantics"]


def test_missing_authorization_does_not_become_a_public_access_claim():
    api = {"ApiId": "a", "ApiEndpoint": "https://a.example.com", "ProtocolType": "HTTP",
           "Stages": {"collection_status": "collected", "items": [{"StageName": "$default", "AutoDeploy": True}]}}
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
    observed = result["evidence"]["observed"].splitlines()
    assert len(observed) == 3
    assert observed[0] == "The snapshot restore permission names external accounts: 999988887777."
    assert "may restore" in observed[1] and "could expose" in observed[2]
    assert result["remediation"] == "Restrict snapshot restore access to the accounts that need it."
