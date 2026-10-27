from peaso.aws_exposure_applicability_evidence import (
    CUSTOMER_SG, PUBLIC_RANGE_SG, SETTING_ID, SSM, SUBNET, augment, observed,
)


def index(kind, rows):
    return {kind: [{"data": row} for row in rows],
            "collections": {kind: [{"status": "collected"}]}}


def finding(check_id, evidence):
    return {"provider": "aws", "category": "exposure", "check_id": check_id,
            "status": "FAIL", "evidence": evidence}


def test_subnet_eni_applicability_is_explicit_without_changing_verdict():
    recorded = {"map_public_ip_on_launch": True}
    rows = [{"SubnetId": "subnet-1"}, {"SubnetId": "subnet-2"}]
    evidence = augment(SUBNET, "FAIL", recorded, {"SubnetId": "subnet-1"}, index("network_interface", rows))
    assert recorded == {"map_public_ip_on_launch": True}
    assert evidence["matching_network_interface_count"] == 1
    assert "1 collected network interface" in observed(finding(SUBNET, evidence))
    assert len(observed(finding(SUBNET, evidence)).splitlines()) == 4
    assert augment(SUBNET, "PASS", recorded, {"SubnetId": "subnet-1"}, index("network_interface", rows)) is recorded


def test_customer_eni_and_any_port_are_spelled_out():
    recorded = {"world_ingress_rule_found": True, "customer_enis": ["eni-1"]}
    evidence = augment(CUSTOMER_SG, "FAIL", recorded, {}, {})
    text = observed(finding(CUSTOMER_SG, evidence))
    assert evidence["customer_network_interface_count"] == 1
    assert "customer-managed" in text and "could accept outside connections" in text
    assert len(text.splitlines()) == 4


def test_specific_public_range_rule_records_single_port():
    item = {"IpPermissions": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
              "IpRanges": [{"CidrIp": "8.8.8.0/24"}], "Ipv6Ranges": []}]}
    evidence = augment(PUBLIC_RANGE_SG, "FAIL", {"specific_public_range_match": True}, item, {})
    assert evidence["matched_public_range_rule"] == {"protocol": "tcp", "from_port": 443,
                                                     "to_port": 443, "source_kind": "specific_public_cidr"}
    assert "tcp port 443" in observed(finding(PUBLIC_RANGE_SG, evidence))
    assert len(observed(finding(PUBLIC_RANGE_SG, evidence)).splitlines()) == 3


def test_ssm_exact_setting_id_is_recorded_and_bounded():
    rows = [{"ServiceSetting": {"SettingId": SETTING_ID, "SettingValue": "Enable"}}]
    recorded = {"setting_value": "Enable"}
    evidence = augment(SSM, "FAIL", recorded, {}, index("ssm_service_settings", rows))
    assert evidence["setting_id"] == SETTING_ID
    assert evidence["public_document_sharing_enabled"] is True
    assert "could be read by people outside the account" in observed(finding(SSM, evidence))
    assert len(observed(finding(SSM, evidence)).splitlines()) == 3
    assert augment(SSM, "FAIL", recorded, {}, index("ssm_service_settings", [])) is recorded


def test_review_document_includes_augmented_evidence_and_observed_text():
    from peaso.ai.pipeline import findings_document
    evidence = augment(SUBNET, "FAIL", {"map_public_ip_on_launch": True}, {"SubnetId": "subnet-1"},
                       index("network_interface", [{"SubnetId": "subnet-1"}]))
    row = {**finding(SUBNET, evidence), "id": "finding-1", "resource_id": "resource-1"}
    document = findings_document({"provider": "aws"}, [row])
    assert document["items"][0]["evidence"]["matching_network_interface_count"] == 1
    assert "collected network interface" not in document["items"][0]["evidence_summary"]
    assert "2 collected network interfaces" not in observed(row)
    assert "1 collected network interface" in observed(row)


def test_observed_text_is_bounded_and_contains_no_review_or_fix_language():
    cases = [
        (SUBNET, {"map_public_ip_on_launch": True, "matching_network_interface_count": 2,
                  "in_use_from_collected_eni": True}),
        (CUSTOMER_SG, {"world_ingress_rule_found": True, "customer_enis": ["eni-1"]}),
        (PUBLIC_RANGE_SG, {"specific_public_range_match": True}),
        (SSM, {"setting_value": "Enable"}),
    ]
    for cid, evidence in cases:
        lines = observed(finding(cid, evidence)).splitlines()
        assert 3 <= len(lines) <= 5
        assert all(line.endswith(".") and len(line) <= 130 for line in lines)
        assert not any(term in " ".join(lines).lower() for term in ("control", "review", "does not prove", "remediate"))
