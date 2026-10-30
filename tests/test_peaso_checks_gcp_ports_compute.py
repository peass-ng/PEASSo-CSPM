"""Compute declaration truths and exact source-defect counterexamples."""
import copy
import pytest
from peaso.checks import CHECKS, gcp_ports_compute as ports
from peaso.checks.fixtures import CASES

REGISTRY = {check.id: check for check in CHECKS if check.id in ports.IDS}


@pytest.mark.parametrize("cid", ports.IDS)
@pytest.mark.parametrize("case,wanted", [("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"), ("malformed", "UNKNOWN"), ("denied", "UNKNOWN")])
def test_compute_available_truth_and_unavailable_evidence(cid, case, wanted):
    item = {"collection_status": "denied"} if case == "denied" else copy.deepcopy(CASES[cid][case])
    index = copy.deepcopy(CASES[cid].get(case + "_index", CASES[cid].get("pass_index", {})))
    before = copy.deepcopy((item, index))
    actual, evidence = REGISTRY[cid].evaluate(item, index)
    assert actual == wanted, evidence
    assert (item, index) == before


def test_mixed_interface_public_address_source_false_clean_counterexample():
    item = {"networkInterfaces": [{}, {"accessConfigs": [{"natIP": "203.0.113.1"}]}]}
    check = REGISTRY[ports.REFERENCE_SPECS["compute_instance_with_no_public_ip_addresses"]]
    assert check.evaluate(item, {})[0] == "FAIL"
    # Exact source's instance_without_access_config CTE includes this VM.
    assert any("accessConfigs" not in row for row in item["networkInterfaces"])


@pytest.mark.parametrize("query,port", [("compute_firewall_rule_ssh_access_restricted", 22), ("compute_firewall_rule_rdp_access_restricted", 3389)])
def test_missing_ports_and_ipv6_broad_range_are_real_declared_ingress(query, port):
    check = REGISTRY[ports.REFERENCE_SPECS[query]]
    assert check.evaluate({"direction": "INGRESS", "sourceRanges": ["::/0"], "allowed": [{"IPProtocol": "tcp"}]}, {})[0] == "FAIL"
    assert check.evaluate({"direction": "INGRESS", "sourceRanges": ["0.0.0.0/0"], "disabled": True,
        "allowed": [{"IPProtocol": "tcp", "ports": [str(port)]}]}, {})[0] == "NOT_APPLICABLE"


def test_stricter_sql_tls_mode_is_not_a_failure():
    check = REGISTRY[ports.REFERENCE_SPECS["sql_instance_require_ssl_enabled"]]
    item = {"databaseVersion": "POSTGRES_16", "settings": {"ipConfiguration": {"sslMode": "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"}}}
    assert check.evaluate(item, {})[0] == "PASS"
    assert item["settings"]["ipConfiguration"]["sslMode"] != "ENCRYPTED_ONLY"


def test_declared_gke_scope_needs_both_name_and_label():
    check = REGISTRY[ports.REFERENCE_SPECS["compute_instance_ip_forwarding_disabled"]]
    assert check.evaluate({"name": "gke-node", "canIpForward": True}, {})[0] == "FAIL"
    assert check.evaluate({"name": "gke-node", "labels": {"goog-gke-node": "pool"}, "canIpForward": True}, {})[0] == "NOT_APPLICABLE"


def test_audit_scope_absence_is_required_failure_only_after_complete_root_policy():
    check = REGISTRY[ports.REFERENCE_SPECS["audit_logging_configured_for_all_service"]]
    assert check.target == "scope"
    fixture = CASES[check.id]
    assert check.evaluate(fixture["fail"], fixture["fail_index"])[0] == "FAIL"
    assert check.evaluate(fixture["pass"], {})[0] == "UNKNOWN"
    index = copy.deepcopy(fixture["pass_index"])
    index["collections"]["iam_policy"][0]["status"] = "partial"
    assert check.evaluate(fixture["pass"], index)[0] == "UNKNOWN"


def test_audit_scope_uses_inherited_effective_audit_configs():
    check = REGISTRY[ports.REFERENCE_SPECS["audit_logging_configured_for_all_service"]]
    all_types = [{"service": "allServices", "auditLogConfigs": [{"logType": t} for t in ("ADMIN_READ", "DATA_READ", "DATA_WRITE")]}]
    def index(entries, status="collected", missing=()):
        root = {"name": "projects/p", "auditConfigs": [], "effectiveAuditConfigs": entries,
                "_coverage": {"effectiveAuditConfigs": {"status": status, "missing_scopes": list(missing)}}}
        return {"collections": {"iam_policy": [{"scope": "projects/p", "status": "collected"}]}, "iam_policy": [{"data": root}]}
    inherited = [{"scope": "projects/p", "auditConfigs": []}, {"scope": "organizations/1", "auditConfigs": all_types}]
    assert check.evaluate({"scope": "projects/p"}, index(inherited))[0] == "PASS"
    assert check.evaluate({"scope": "projects/p"}, index([{"scope": "projects/p", "auditConfigs": []},
        {"scope": "organizations/1", "auditConfigs": []}]))[0] == "FAIL"
    assert check.evaluate({"scope": "projects/p"}, index([{"scope": "projects/p", "auditConfigs": []}], "partial", ["organizations/1"]))[0] == "UNKNOWN"
    exempt = copy.deepcopy(inherited)
    exempt[1]["auditConfigs"][0]["auditLogConfigs"][1]["exemptedMembers"] = ["user:a@example.com"]
    assert check.evaluate({"scope": "projects/p"}, index(exempt))[0] == "FAIL"


@pytest.mark.parametrize("port", [22, 3389])
@pytest.mark.parametrize("sources,wanted", [
    ({"sourceRanges": []}, "FAIL"),
    ({"sourceRanges": [], "sourceTags": [], "sourceServiceAccounts": []}, "FAIL"),
    ({"sourceRanges": [], "sourceTags": ["trusted"]}, "PASS"),
    ({"sourceRanges": [], "sourceServiceAccounts": ["vm@p.iam.gserviceaccount.com"]}, "PASS"),
    ({"sourceRanges": [], "sourceTags": "trusted"}, "UNKNOWN"),
    ({"_coverage": {"sourceTags": {"status": "denied"}}}, "UNKNOWN"),
])
def test_firewall_empty_source_default_and_selector_evidence(port, sources, wanted):
    query = "compute_firewall_rule_" + ("ssh" if port == 22 else "rdp") + "_access_restricted"
    check = REGISTRY[ports.REFERENCE_SPECS[query]]
    item = {"direction": "INGRESS", "allowed": [{"IPProtocol": "tcp", "ports": [str(port)]}], **sources}
    assert check.evaluate(item, {})[0] == wanted
