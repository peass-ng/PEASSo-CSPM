"""Complete offline network stage: findings, topology, exposure annotation and JSON.

python -m examples.benchmark_peaso_network --provider k8s
python -m examples.benchmark_peaso_network --provider aws
"""
import argparse
import hashlib
import json
import time

from peaso.analysis.common import analysis_context
from peaso.analysis import network, internet_exposure
from peaso.snapshot import digest, make_snapshot, resources


def synthetic_snapshot(provider, workloads=5000, selectors=1000, subnets=300):
    if workloads < 1 or selectors < 1 or subnets < 1:
        raise ValueError("inventory sizes must be positive")
    if provider == "k8s":
        scope = "cluster/apps"

        def native(kind, name, **extra):
            return {"id": f"k8s://cluster/{kind}/apps/{name}",
                    "metadata": {"name": name, "namespace": "apps", "labels": {"app": name, "tier": "web"}},
                    "provenance": {"cluster_id": "cluster", "namespace": "apps"}, **extra}

        facts = {
            "pod": [native("pod", f"app-{i}", spec={"nodeName": "node-a"},
                           status={"podIP": f"10.{i // 62500 % 250}.{i // 250 % 250}.{i % 250 + 1}"})
                    for i in range(workloads)],
            "service": [native("service", f"svc-{i}", spec={
                "type": "LoadBalancer" if i % 4 == 0 else "ClusterIP", "selector": {"app": f"app-{i}"},
                "ports": [{"port": 443, "targetPort": 8443}]},
                status={"loadBalancer": {"ingress": [{"ip": "203.0.113.10"}]}}) for i in range(selectors)],
            "networkpolicy": [native("networkpolicy", f"policy-{i}", spec={
                "podSelector": {"matchLabels": {"app": f"app-{i}"}}, "policyTypes": ["Ingress"], "ingress": []})
                for i in range(selectors)],
        }
        metadata = {"cluster_id": "cluster"}
    elif provider == "aws":
        scope = "111122223333/us-east-1"
        facts = {
            "instance": [{"InstanceId": f"i-{i}", "State": {"Name": "running"}, "VpcId": "vpc-a",
                          "SubnetId": f"subnet-{i % subnets}", "PublicIpAddress": f"8.8.{i // 250 % 250}.{i % 250 + 1}",
                          "SecurityGroups": [{"GroupId": "sg-a"}]} for i in range(workloads)],
            "subnet": [{"SubnetId": f"subnet-{i}", "VpcId": "vpc-a"} for i in range(subnets)],
            "vpc": [{"VpcId": "vpc-a"}],
            "security_group": [{"GroupId": "sg-a", "IpPermissions": [
                {"IpProtocol": "tcp", "FromPort": p, "ToPort": p, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                for p in range(400, 420)]}],
            "route_table": [{"RouteTableId": f"rt-{i}", "VpcId": "vpc-a", "Associations": [
                                 {"SubnetId": f"subnet-{i}", "AssociationState": {"State": "associated"}}],
                             "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-a", "State": "active"}]}
                            for i in range(subnets)],
            "internet_gateway": [{"InternetGatewayId": "igw-a", "Attachments": [{"VpcId": "vpc-a", "State": "available"}]}],
            "vpc_block_public_access_options": [{"VpcBlockPublicAccessOptions": {
                "State": "default-state", "InternetGatewayBlockMode": "off"}}],
            "network_acl": [{"NetworkAclId": f"acl-{i}", "VpcId": "vpc-a", "Associations": [{"SubnetId": f"subnet-{i}"}],
                             "Entries": [{"RuleNumber": 100, "Protocol": "-1", "CidrBlock": "0.0.0.0/0",
                                          "RuleAction": "allow", "Egress": direction} for direction in (False, True)]}
                            for i in range(subnets)],
        }
        metadata = {}
    elif provider == "gcp":
        scope = "benchmark-project"
        networks = [f"projects/{scope}/global/networks/network-{i}" for i in range(subnets)]
        facts = {
            "network": [{"name": f"network-{i}", "selfLink": name} for i, name in enumerate(networks)],
            "instance": [{"name": f"vm-{i}", "id": str(i), "status": "RUNNING",
                          "tags": {"items": ["web"]},
                          "serviceAccounts": [{"email": f"web@{scope}.iam.gserviceaccount.com"}],
                          "networkInterfaces": [{"name": "nic0", "network": networks[i % subnets],
                              "accessConfigs": [{"natIP": f"8.8.{i // 250 % 250}.{i % 250 + 1}"}]}]}
                         for i in range(workloads)],
            "firewall": [{"name": f"rule-{i}-{port}", "network": name, "priority": 1000,
                          "sourceRanges": ["0.0.0.0/0"], "targetTags": ["web"],
                          "allowed": [{"IPProtocol": "tcp", "ports": [str(port)]}]}
                         for i, name in enumerate(networks) for port in range(400, 420)],
            "firewall_policy": [],
        }
        metadata = {}
    elif provider == "azure":
        scope = "/subscriptions/benchmark"
        prefix = scope + "/resourceGroups/benchmark/providers/Microsoft.Network"
        nsg = prefix + "/networkSecurityGroups/shared"
        subnet = prefix + "/virtualNetworks/shared/subnets/default"
        facts = {
            "nsg": [{"id": nsg, "properties": {"securityRules": [
                {"name": f"allow-{p}", "properties": {"priority": p, "direction": "Inbound", "access": "Allow",
                 "protocol": "Tcp", "sourceAddressPrefix": "*", "destinationAddressPrefix": "*",
                 "destinationPortRange": str(p)}} for p in range(400, 420)]}}],
            "subnet": [{"id": subnet, "properties": {"networkSecurityGroup": {"id": nsg}}}],
            "nic": [{"id": f"{prefix}/networkInterfaces/nic-{i}", "properties": {"ipConfigurations": [
                {"id": f"{prefix}/networkInterfaces/nic-{i}/ipConfigurations/ip", "properties": {
                    "privateIPAddress": f"10.{i // 62500 % 250}.{i // 250 % 250}.{i % 250 + 1}",
                    "subnet": {"id": subnet}, "loadBalancerBackendAddressPools": [
                        {"id": f"{prefix}/loadBalancers/lb-{i}/backendAddressPools/pool"}]}}]}}
                    for i in range(workloads)],
            "public_ip": [{"id": f"{prefix}/publicIPAddresses/ip-{i}", "properties": {"ipAddress": "20.1.1.1"}}
                          for i in range(selectors)],
            "load_balancer": [{"id": f"{prefix}/loadBalancers/lb-{i}", "properties": {
                "frontendIPConfigurations": [{"id": f"front-{i}", "properties": {
                    "publicIPAddress": {"id": f"{prefix}/publicIPAddresses/ip-{i}"}}}],
                "loadBalancingRules": [{"name": f"web-{p}", "properties": {
                    "frontendIPConfiguration": {"id": f"front-{i}"}, "protocol": "Tcp", "frontendPort": p,
                    "backendPort": p, "backendAddressPool": {
                        "id": f"{prefix}/loadBalancers/lb-{i % workloads}/backendAddressPools/pool"}}}
                    for p in (400, 401, 402, 403)]}} for i in range(selectors)],
        }
        metadata = {}
    else:
        raise ValueError("benchmark provider must be aws, gcp, azure or k8s")
    return make_snapshot(provider, [scope], [
        {"type": kind, "scope": scope, "status": "collected" if items else "empty", "items": items} for kind, items in facts.items()],
        created_at="2026-01-01T00:00:00+00:00", metadata=metadata)


def run_stage(snapshot):
    inventory = resources(snapshot)
    with analysis_context(snapshot):
        findings = network.exposure_findings(snapshot, inventory) + internet_exposure.internet_findings(snapshot, inventory)
        graph = internet_exposure.annotate_network(network.build_network(snapshot, inventory), snapshot, inventory)
    return {"findings": findings, "graph": graph}


def benchmark(provider="k8s", workloads=5000, selectors=1000, subnets=300):
    snapshot = synthetic_snapshot(provider, workloads, selectors, subnets)
    before = digest(snapshot)
    times, serialization, fingerprints = [], [], []
    for _ in range(3):
        started = time.perf_counter()
        result = run_stage(snapshot)
        times.append(round(time.perf_counter() - started, 6))
        started = time.perf_counter()
        encoded = json.dumps(result, sort_keys=True).encode()
        serialization.append(round(time.perf_counter() - started, 6))
        fingerprints.append(hashlib.sha256(encoded).hexdigest())
    assert len(set(fingerprints)) == 1 and digest(snapshot) == before
    return {"provider": provider, "resources": sum(len(c["items"]) for c in snapshot["collections"]),
            "findings": len(result["findings"]), "nodes": len(result["graph"]["nodes"]),
            "edges": len(result["graph"]["edges"]), "network_stage_seconds": times,
            "serialization_seconds": serialization, "output_digest": fingerprints[0], "input_unchanged": True,
            "cloud_calls": 0, "limitations": "Synthetic complete offline network stage; excludes cloud collection, other engine categories, IAM, privilege escalation and report persistence."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", choices=("aws", "gcp", "azure", "k8s"), default="k8s")
    parser.add_argument("--workloads", type=int, default=5000)
    parser.add_argument("--selectors", type=int, default=1000)
    parser.add_argument("--subnets", type=int, default=300)
    args = parser.parse_args()
    print(json.dumps(benchmark(args.provider, args.workloads, args.selectors, args.subnets), indent=2))
