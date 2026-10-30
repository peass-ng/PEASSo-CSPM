"""Signed NetworkPolicy declarations: adverse source, protocol and port cases."""
from copy import deepcopy

import pytest

from peaso.checks import evaluate_check
from peaso.checks import compliance_new_k8s_network as new


def verdict(check_id, rule, *, policy_types=None):
    item = {"spec": {"policyTypes": policy_types or ["Ingress"], "ingress": [rule]}}
    return evaluate_check(check_id, item, {})


def test_signed_ids_and_declared_dependencies():
    for check_id in new.IDS:
        for expected, field in (("PASS", "pass"), ("FAIL", "fail"), ("UNKNOWN", "missing"), ("UNKNOWN", "malformed")):
            assert evaluate_check(check_id, new.CASES[check_id][field], {})[0] == expected
        assert evaluate_check(check_id, {"collection_status": "denied"}, {})[0] == "UNKNOWN"
        assert evaluate_check(check_id, {"spec": {"policyTypes": ["Egress"], "ingress": []}}, {})[0] == "NOT_APPLICABLE"


@pytest.mark.parametrize("source", [None, [], [{"ipBlock": {"cidr": "0.0.0.0/0"}}], [{"ipBlock": {"cidr": "::/0"}}]])
def test_observed_all_source_declared_ingress_fails(source):
    rule = {} if source is None else {"from": source}
    state, evidence = verdict(new.IDS[0], rule)
    assert state == "FAIL"
    assert evidence["all_source_rules"] == [0]
    assert "unproved" in evidence["semantics"]


@pytest.mark.parametrize("source", [
    [{"ipBlock": {"cidr": "0.0.0.0/0", "except": ["10.0.0.0/8"]}}],
    [{"ipBlock": {"cidr": "10.0.0.0/8"}}],
    [{"podSelector": {"matchLabels": {"app": "api"}}}],
    [{"namespaceSelector": {"matchExpressions": [{"key": "tier", "operator": "In", "values": ["prod"]}]}}],
])
def test_bounded_source_declarations_pass_exact_signed_predicate(source):
    assert verdict(new.IDS[0], {"from": source})[0] == "PASS"


@pytest.mark.parametrize("source", [
    [{}],
    [{"ipBlock": {"cidr": "not-a-cidr"}}],
    [{"ipBlock": {"cidr": "0.0.0.0/0", "except": ["2001:db8::/32"]}}],
    [{"ipBlock": {"cidr": "10.0.0.0/8", "except": ["172.16.0.0/12"]}}],
    [{"ipBlock": {"cidr": "0.0.0.0/0", "except": ["0.0.0.0/0"]}}],
    [{"ipBlock": {"cidr": "0.0.0.0/0"}, "podSelector": {}}],
    [{"podSelector": {"matchLabels": {"app": True}}}],
    [{"podSelector": {"matchExpressions": [{"key": "team", "operator": "Something", "values": []}]}}],
    [{"unexpected": "field"}],
    "everyone",
])
def test_malformed_or_unsupported_source_never_passes(source):
    assert verdict(new.IDS[0], {"from": source})[0] == "UNKNOWN"


def test_explicit_empty_ingress_is_a_valid_default_deny_declaration():
    for check_id in new.IDS:
        state, evidence = evaluate_check(check_id, {"spec": {"policyTypes": ["Ingress"], "ingress": []}}, {})
        assert state == "PASS"
        assert evidence["assessed_rules"] == 0
    # Separate signed 'must contain allow rules' proposal must not be registered
    # as a vulnerability: an empty list is intentional default deny.
    assert "k8s_networkpolicy_has_ingress_or_egress_rules" not in new.IDS


@pytest.mark.parametrize("ports,expected", [
    (None, "FAIL"), ([], "FAIL"), ([{}], "FAIL"),
    ([{"port": 22}], "FAIL"), ([{"port": 3389, "protocol": "TCP"}], "FAIL"),
    ([{"port": 20, "endPort": 23}], "FAIL"),
    ([{"port": 3388, "endPort": 3390}], "FAIL"),
    ([{"port": 22, "protocol": "UDP"}], "PASS"),
    ([{"port": 22, "protocol": "SCTP"}], "PASS"),
    ([{"port": 443}], "PASS"),
    ([{"port": "ssh", "protocol": "TCP"}], "UNKNOWN"),
    ([{"port": "ssh", "endPort": 23}], "UNKNOWN"),
    ([{"port": 0}], "UNKNOWN"), ([{"port": 65536}], "UNKNOWN"),
    ([{"port": 100, "endPort": 50}], "UNKNOWN"),
    ([{"port": 22, "protocol": "future"}], "UNKNOWN"),
])
def test_world_source_remote_admin_port_protocol_and_range_defaults(ports, expected):
    rule = {"from": []}
    if ports is not None:
        rule["ports"] = ports
    state, evidence = verdict(new.IDS[1], rule)
    assert state == expected
    if expected == "FAIL":
        assert "no actual service listener" in evidence["semantics"]


def test_restricted_peer_does_not_make_tcp_22_world_and_malformed_peer_stays_unknown():
    bounded = {"from": [{"ipBlock": {"cidr": "192.0.2.0/24"}}], "ports": [{"port": 22}]}
    assert verdict(new.IDS[1], bounded)[0] == "PASS"
    wrong = deepcopy(bounded)
    wrong["from"][0]["ipBlock"]["cidr"] = "bad"
    assert verdict(new.IDS[1], wrong)[0] == "UNKNOWN"
    assert verdict(new.IDS[1], {"from": [{}], "ports": [{"port": 22}]})[0] == "UNKNOWN"


def test_definite_bad_rule_wins_over_separate_malformed_rule():
    for check_id in new.IDS:
        bad = new.CASES[check_id]["fail"]["spec"]["ingress"][0]
        item = {"spec": {"policyTypes": ["Ingress"], "ingress": [{"from": "malformed"}, bad]}}
        assert evaluate_check(check_id, item, {})[0] == "FAIL"


def test_definite_bad_peer_or_port_wins_over_unknown_sibling():
    rule = {"from": [{"podSelector": {"matchLabels": {"app": True}}}, {"ipBlock": {"cidr": "0.0.0.0/0"}}]}
    assert verdict(new.IDS[0], rule)[0] == "FAIL"
    rule = {"from": [], "ports": [{"port": "ssh"}, {"port": 22}]}
    assert verdict(new.IDS[1], rule)[0] == "FAIL"


def test_missing_or_unreadable_policy_fields_are_unknown():
    for check_id in new.IDS:
        assert evaluate_check(check_id, {"spec": {"ingress": []}}, {})[0] == "UNKNOWN"
        assert evaluate_check(check_id, {"spec": {"policyTypes": ["Ingress"], "_coverage": {"ingress": {"status": "denied"}}}}, {})[0] == "UNKNOWN"
