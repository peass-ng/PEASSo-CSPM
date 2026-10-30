from copy import deepcopy

import pytest

from peaso.checks import CHECKS, CHECK_ALIASES
from peaso.engine import _finding, compact_report, hydrate_frameworks
from peaso.finding_priority import effective_priority, review_metadata, reviews


def test_reviewed_priorities_bind_original_ratings_and_preserve_signed_registry():
    registered = {c.id: c for c in CHECKS}
    for cid, row in reviews().items():
        if cid in CHECK_ALIASES:
            # A retired duplicate keeps its archived review for stored scans;
            # its registered survivor must carry its own reviewed priority.
            assert cid not in registered and CHECK_ALIASES[cid] in registered and CHECK_ALIASES[cid] in reviews(), cid
            continue
        source = registered[cid].severity
        assert source == row["current"]
        assert effective_priority(cid, source) == row["recommended"]
        assert registered[cid].public()["severity"] == row["recommended"]
        assert registered[cid].severity == source
    assert effective_priority("unknown.check", "critical") == "critical"
    with pytest.raises(ValueError, match="source priority changed"):
        effective_priority("azure.app.http2", "critical")


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


def test_every_active_control_has_an_explicit_reviewed_priority():
    from peaso.checks.native_only import automated_checks
    active={c.id for c in automated_checks(CHECKS)}
    assert active <= reviews().keys()


def test_new_priority_reviews_bind_the_actual_registered_sources():
    import json
    from pathlib import Path
    path = Path(__file__).resolve().parents[1] / "peaso/checks/reviewed_release_priorities_20261020.json"
    rows = json.loads(path.read_text())
    registered = {check.id: check for check in CHECKS}
    assert len(rows) == 200
    for cid, row in rows.items():
        check = registered[cid]
        assert (row["source_module"], row["source_kind"], row["source_title"]) == (
            check.evaluate.__module__, check.kind, check.title)
        assert row["current"] == check.severity
        assert row["recommended"] == check.severity
        assert row["reason"] and reviews()[cid] == {key: row[key] for key in ("current", "recommended", "reason")}


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


def test_new_report_metadata_carries_fingerprint_and_survives_hydration():
    from peaso.engine import attach_reviewed_description_meta,hydrate_finding
    from peaso.finding_presentation import evaluator_contract_fingerprint
    cid="aws.cb.lightsail.ssh_restricted"
    meta=attach_reviewed_description_meta({cid:{"title":"original"}})
    proof=meta[cid]["clarity_evaluation_contract"]
    assert proof==evaluator_contract_fingerprint() and len(proof)==64
    row=hydrate_finding({"check_id":cid,"status":"FAIL","severity":"high"},check_meta=meta)
    assert row["clarity_evaluation_contract"]==proof
