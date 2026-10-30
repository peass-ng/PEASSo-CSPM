"""Per-port firewall checks keep the rule's actual verdicts."""
import pytest

from peaso.checks import CHECKS
from peaso.checks.claude_gcp_k8s_common import CASES
from peaso.checks.claude_gcp_k8s_compute import FIREWALL_PORTS, FIREWALL_PORT_IDS


@pytest.mark.parametrize("suffix", FIREWALL_PORTS)
def test_port_rule_verdicts_for_every_input_shape(suffix):
    cid = FIREWALL_PORT_IDS[suffix]
    check = next(c for c in CHECKS if c.id == cid)
    for case, expected in (("pass", "PASS"), ("fail", "FAIL"),
                           ("missing", "UNKNOWN"), ("malformed", "UNKNOWN"),
                           ("not_applicable", "NOT_APPLICABLE")):
        assert check.evaluate(CASES[cid][case], {})[0] == expected
