from copy import deepcopy

import pytest

from peaso.checks import CHECKS
from peaso.engine import _finding, compact_report, hydrate_frameworks
from peaso.finding_priority import review_metadata


def test_architecture_setting_is_not_rated_as_a_compromise():
    check = next(c for c in CHECKS if c.id == "azure.app.http2")
    assert check.severity == "medium"
    row = _finding(check, "azure", "/subscriptions/s", "app1", "app", "FAIL", {"field": "properties.http20Enabled", "configured": False})
    assert row["severity"] == "low"
    assert review_metadata(check.id, check.severity)["source_severity"] == "medium"


@pytest.mark.parametrize("ports, expected", [(["443"], "medium"), (["80", "443"], "medium"),
                                            (["22"], "high"), (["443", "22"], "high"),
                                            (["*"], "high")])
def test_engine_rates_known_web_and_admin_rules_from_their_actual_ports(ports, expected):
    check = next(c for c in CHECKS if c.id == "azure.claude.vm_nic_nsg_internet_tcp_ingress")
    evidence = {"internet_allow_rules": [{"ports": ports}]}
    before = deepcopy(evidence)
    row = _finding(check, "azure", "/subscriptions/s", "vm1", "vm", "FAIL", evidence)
    assert row["severity"] == expected
    assert evidence == before


def test_archived_priorities_are_not_rewritten_by_schema_migration():
    archived = {"schema_version": "1.0", "snapshot_id": "old", "findings": [{
        "id": "old1", "check_id": "azure.app.http2", "provider": "azure",
        "status": "FAIL", "severity": "critical", "frameworks": [],
    }]}
    before = deepcopy(archived)
    restored = hydrate_frameworks(compact_report(archived))
    assert restored["findings"][0]["severity"] == "critical"
    assert archived == before


def test_two_port_contexts_of_the_same_check_keep_distinct_priorities():
    check = next(c for c in CHECKS if c.id == "azure.claude.vm_nic_nsg_internet_tcp_ingress")
    rows = [_finding(check, "azure", "/subscriptions/s", "vm" + port, "vm", "FAIL",
                     {"internet_allow_rules": [{"ports": [port]}]}) for port in ("443", "22")]
    restored = hydrate_frameworks(compact_report({"schema_version": "1.0", "snapshot_id": "new", "findings": rows}))
    assert {row["resource_id"]: row["severity"] for row in restored["findings"]} == {
        "vm443": "medium", "vm22": "high",
    }


@pytest.mark.parametrize("port,expected",[(443,"medium"),(80,"medium"),(22,"high"),(5432,"high")])
def test_aws_priority_uses_real_registered_ingress_evidence(port,expected):
    c=next(c for c in CHECKS if c.id=="aws.ec2.restrict_internet_ingress")
    status,e=c.evaluate({"IpPermissions":[{"IpProtocol":"tcp","FromPort":port,"ToPort":port,
        "IpRanges":[{"CidrIp":"0.0.0.0/0"}],"Ipv6Ranges":[]}]},{})
    assert status=="FAIL"
    assert _finding(c,"aws","123456789012/us-east-1","sg-1","ec2",status,e)["severity"]==expected


def test_aws_all_protocols_includes_sensitive_administrative_ports():
    c=next(c for c in CHECKS if c.id=="aws.ec2.restrict_internet_ingress")
    status,e=c.evaluate({"IpPermissions":[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"::/0"}],"Ipv6Ranges":[{"CidrIpv6":"::/0"}]}]},{})
    assert status=="FAIL"
    assert _finding(c,"aws","123456789012/us-east-1","sg-1","ec2",status,e)["severity"]=="high"


@pytest.mark.parametrize("port,expected",[(443,"medium"),(22,"high"),(5432,"high")])
def test_bounded_native_path_witness_is_prioritized_without_claiming_listener(port,expected):
    from peaso.checks.aws_finding_priority import WITNESS_IDS
    for cid in WITNESS_IDS:
        c=next(c for c in CHECKS if c.id==cid)
        e={"configured_path_witness":{"protocol":"tcp","destination_port":port,"application_listening":"unknown"}}
        row=_finding(c,"aws","123456789012/us-east-1","i-1","ec2","FAIL",e)
        assert row["severity"]==expected
        assert row["evidence"]==e


