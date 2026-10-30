"""Azure NSG declaration-audit gap natives and the verified-only Azure corrected-merge contract."""
import copy

import pytest

from peaso.checks import CHECKS, azure_gap_nsg as gap
from peaso.checks.claude_azure_common import nsg_case, nsg_rule
from peaso.checks.fixtures import CASES

REGISTRY = {check.id: check for check in CHECKS}
SHADOW = nsg_rule("deny-internet", "*", "Internet", "*", access="Deny")


def _status(cid, *rules):
    return REGISTRY[cid].evaluate(nsg_case(*rules), {})[0]


@pytest.mark.parametrize("cid", gap.CHECK_IDS, ids=str)
def test_fixture_pass_fail_and_input_not_mutated(cid):
    for label, expected in (("pass", "PASS"), ("fail", "FAIL")):
        item = copy.deepcopy(CASES[cid][label])
        before = copy.deepcopy(item)
        assert REGISTRY[cid].evaluate(item, {})[0] == expected
        assert item == before
    for item in ({}, None, {"properties": {}}):
        assert REGISTRY[cid].evaluate(item, {})[0] == "UNKNOWN"


def test_declaration_semantics_ignore_higher_priority_deny_and_outbound_or_trusted_sources():
    rdp = gap.SOURCE_QUERIES["network_security_group_rdp_access_restricted"]
    assert _status(rdp, SHADOW, nsg_rule("open", "Tcp", "0.0.0.0/0", "3389")) == "FAIL"
    assert _status(rdp, nsg_rule("open", "*", ["10.0.0.0/8", "Internet"], ["22", "3000-4000"])) == "FAIL"
    assert _status(rdp, nsg_rule("out", "Tcp", "Internet", "3389", direction="Outbound")) == "PASS"
    assert _status(rdp, nsg_rule("deny", "Tcp", "Internet", "3389", access="Deny")) == "PASS"
    assert _status(rdp, nsg_rule("udp", "Udp", "Internet", "3389")) == "PASS"
    assert _status(rdp, nsg_rule("trusted", "Tcp", "203.0.113.0/24", "*")) == "PASS"
    assert _status(rdp, nsg_rule("bad", "Tcp", "Internet", "33x89")) == "UNKNOWN"


def test_upstream_port_defects_are_corrected_not_reproduced():
    udp = gap.SOURCE_QUERIES["network_security_group_udp_service_restricted"]
    both = gap.SOURCE_QUERIES["network_security_group_https_port_80_443_access_restricted"]
    http = gap.SOURCE_QUERIES["network_security_group_https_access_restricted"]
    assert _status(udp, nsg_rule("dns", "Udp", "Internet", "53")) == "FAIL"  # source omitted exact ports
    assert _status(udp, nsg_rule("ntp", "*", "*", "123")) == "FAIL"
    assert _status(udp, nsg_rule("tcp", "Tcp", "*", "53")) == "PASS"
    assert _status(both, nsg_rule("web", "Tcp", "Internet", "80-81")) == "FAIL"  # source required 80 AND 443 in one range
    assert _status(both, nsg_rule("tls", "Tcp", "Internet", "443")) == "FAIL"
    assert _status(http, nsg_rule("tls", "Tcp", "Internet", "443")) == "PASS"
    remote = gap.SOURCE_QUERIES["network_security_group_remote_access_restricted"]
    assert _status(remote, SHADOW, nsg_rule("ssh", "Tcp", "Internet", "22")) == "FAIL"
    assert _status(remote, nsg_rule("web", "Tcp", "Internet", "443")) == "PASS"


def test_prowler_udp_any_and_singular_field_defects_are_corrected():
    udp = gap.PROWLER_SOURCES["prowler.azure.network_udp_internet_access_restricted"]
    rdp = gap.PROWLER_SOURCES["prowler.azure.network_rdp_internet_access_restricted"]
    assert _status(udp, SHADOW, nsg_rule("hi", "Udp", "Internet", "40000")) == "FAIL"
    assert _status(udp, nsg_rule("any", "*", ["10.0.0.0/8", "0.0.0.0/0"], ["9000-9100"])) == "FAIL"  # plural fields + Any
    assert _status(udp, nsg_rule("tcp", "Tcp", "Internet", "*")) == "PASS"
    assert _status(udp, nsg_rule("bad", "Udp", "Internet", "x")) == "UNKNOWN"
    assert _status(rdp, nsg_rule("all", "Tcp", "Internet", "*")) == "FAIL"  # Prowler misses port '*'


