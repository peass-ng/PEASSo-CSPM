"""Signed EC2 group and IPv6 semantic fixtures over cached same-Region facts."""
from peaso.checks import evaluate_check
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
from peaso.checks import compliance_new_aws_ec2  # noqa: F401  (registration side effect)


DEFAULT_ID = "aws_cis_ec2_default_security_group_not_attached"
IPV6_ID = "aws_g6_ec2_instance_no_public_ipv6"
SCOPE = "111111111111/us-east-1"


def eni(interface_id="eni-1", group_ids=("sg-app",), addresses=()):
    return {"NetworkInterfaceId": interface_id, "VpcId": "vpc-1",
            "Groups": [{"GroupId": group_id, "GroupName": "untrusted-display-name"} for group_id in group_ids],
            "Ipv6Addresses": [{"Ipv6Address": address} for address in addresses]}


def instance(*interfaces, state="running"):
    return {"InstanceId": "i-inert", "State": {"Name": state}, "VpcId": "vpc-1",
            "NetworkInterfaces": list(interfaces or (eni(),)),
            "_provenance": {"operation": "ec2:DescribeInstances", "native_response_complete": True}}


def scoped(instances, groups=(), *, instance_status="collected", group_status="collected"):
    return {"collections": {
        "instance": [{"type": "instance", "scope": SCOPE, "status": instance_status, "items": list(instances)}],
        "security_group": [{"type": "security_group", "scope": SCOPE, "status": group_status,
                            "items": list(groups)}]},
        "instance": [{"type": "instance", "scope": SCOPE, "data": row} for row in instances],
        "security_group": [{"type": "security_group", "scope": SCOPE, "data": row} for row in groups]}


def group(group_id, name, vpc="vpc-1"):
    return {"GroupId": group_id, "GroupName": name, "VpcId": vpc}


def evaluate(check_id, item, index):
    return evaluate_check(check_id, item, index)


def test_default_group_join_uses_every_interface_exact_vpc_and_group_id():
    row = instance(eni(), eni("eni-2", ("sg-default",)))
    groups = [group("sg-app", "application"), group("sg-default", "default")]
    status, evidence = evaluate(DEFAULT_ID, row, scoped([row], groups))
    assert status == "FAIL" and evidence["default_group_ids"] == ["sg-default"]
    clean = instance(eni(), eni("eni-2", ("sg-worker",)))
    clean_groups = [group("sg-app", "application"), group("sg-worker", "worker")]
    assert evaluate(DEFAULT_ID, clean, scoped([clean], clean_groups))[0] == "PASS"
    # A same-named group from another VPC cannot satisfy a GroupId join.
    wrong_vpc = [group("sg-app", "default", "vpc-other"), group("sg-app", "application")]
    assert evaluate(DEFAULT_ID, instance(), scoped([instance()], wrong_vpc))[0] == "PASS"


def test_default_group_missing_denied_malformed_and_terminated_states():
    row = instance()
    assert evaluate(DEFAULT_ID, row, scoped([row], []))[0] == "UNKNOWN"
    assert evaluate(DEFAULT_ID, row, scoped([row], [group("sg-app", "application")],
                                           group_status="denied"))[0] == "UNKNOWN"
    assert evaluate(DEFAULT_ID, row, scoped([row], [group("sg-app", "application")],
                                           instance_status="partial"))[0] == "UNKNOWN"
    malformed = instance(eni(group_ids=()))
    assert evaluate(DEFAULT_ID, malformed, scoped([malformed], [group("sg-app", "application")]))[0] == "UNKNOWN"
    cross_vpc = instance(eni())
    cross_vpc["NetworkInterfaces"][0]["VpcId"] = "vpc-other"
    assert evaluate(DEFAULT_ID, cross_vpc, scoped([cross_vpc], [group("sg-app", "application")]))[0] == "UNKNOWN"
    ended = instance(state="terminated")
    assert evaluate(DEFAULT_ID, ended, scoped([ended], []))[0] == "NOT_APPLICABLE"


def test_global_ipv6_allocation_is_distinct_from_ipv4_or_private_ipv6():
    exposed = instance(eni(addresses=("fd00::1",)), eni("eni-2", addresses=("2600:1f18:abcd::1",)))
    status, evidence = evaluate(IPV6_ID, exposed, scoped([exposed]))
    assert status == "FAIL" and evidence["globally_routable_ipv6"][0]["network_interface_id"] == "eni-2"
    private = instance(eni(addresses=("fd00::1",)))
    private["PublicIpAddress"] = "203.0.113.10"
    assert evaluate(IPV6_ID, private, scoped([private]))[0] == "PASS"
    omitted = instance(eni())
    del omitted["NetworkInterfaces"][0]["Ipv6Addresses"]
    assert evaluate(IPV6_ID, omitted, scoped([omitted]))[0] == "PASS"


def test_ipv6_missing_unproven_or_malformed_facts_stay_unknown():
    row = instance()
    row["_provenance"] = {"operation": "ec2:DescribeInstances", "native_response_complete": False}
    assert evaluate(IPV6_ID, row, scoped([row]))[0] == "UNKNOWN"
    bad = instance(eni(addresses=("not-ipv6",)))
    assert evaluate(IPV6_ID, bad, scoped([bad]))[0] == "UNKNOWN"
    denied = instance()
    denied["NetworkInterfaces"][0]["_coverage"] = {"Ipv6Addresses": {"status": "denied"}}
    del denied["NetworkInterfaces"][0]["Ipv6Addresses"]
    assert evaluate(IPV6_ID, denied, scoped([denied]))[0] == "UNKNOWN"
    missing_eni = instance()
    del missing_eni["NetworkInterfaces"]
    assert evaluate(IPV6_ID, missing_eni, scoped([missing_eni]))[0] == "UNKNOWN"
    assert evaluate(IPV6_ID, instance(), scoped([instance()], instance_status="partial"))[0] == "UNKNOWN"
    ended = instance(state="terminated")
    assert evaluate(IPV6_ID, ended, scoped([ended]))[0] == "NOT_APPLICABLE"


def test_production_engine_scopes_ec2_joins_and_native_response_marker():
    row = instance(eni(), eni("eni-2", ("sg-default",), ("2600:1f18:abcd::1",)))
    snapshot = make_snapshot(
        "aws", [SCOPE], [
            {"type": "instance", "scope": SCOPE, "service": "ec2", "status": "collected", "items": [row]},
            {"type": "security_group", "scope": SCOPE, "service": "ec2", "status": "collected",
             "items": [group("sg-app", "application"), group("sg-default", "default")]},
        ], created_at="2026-10-12T05:00:00+00:00")
    report = evaluate_snapshot(snapshot, categories=["hardening", "exposure"], checks=[DEFAULT_ID, IPV6_ID])
    statuses = {finding["check_id"]: finding["status"] for finding in report["findings"]
                if finding["check_id"] in {DEFAULT_ID, IPV6_ID}}
    assert statuses == {DEFAULT_ID: "FAIL", IPV6_ID: "FAIL"}
