"""Security Hub ELB.17 listener policy table and unknown-policy boundaries."""
from __future__ import annotations

import pytest

from peaso.checks import CHECKS
from peaso.checks.claude2_aws_b_edge import _lb, _l
from peaso.checks.claude2_aws_b_edge import RECOMMENDED_POLICIES, _lb, _l


CHECK = next(check for check in CHECKS if check.id == "aws.c2b.elbv2.recommended_tls_policy")
ELB17 = {
    "ELBSecurityPolicy-TLS13-1-3-2021-06",
    "ELBSecurityPolicy-TLS13-1-3-FIPS-2023-04",
    "ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
    "ELBSecurityPolicy-TLS13-1-2-Res-FIPS-2023-04",
    "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09",
    "ELBSecurityPolicy-TLS13-1-3-PQ-2025-09",
    "ELBSecurityPolicy-TLS13-1-2-Res-FIPS-PQ-2025-09",
    "ELBSecurityPolicy-TLS13-1-3-FIPS-PQ-2025-09",
}


def listener(kind, policy, *, include_policy=True):
    protocol = "HTTPS" if kind == "application" else "TLS"
    row = _l(protocol, policy if include_policy else None)
    return _lb(kind, listeners=[row])


@pytest.mark.parametrize("kind", ["application", "network"])
@pytest.mark.parametrize("policy", sorted(ELB17))
def test_all_documented_security_hub_policies_pass_for_supported_listener(kind, policy):
    status, evidence = CHECK.evaluate(listener(kind, policy), {})
    assert status == "PASS"
    assert evidence["approved_policies"] == [policy]


@pytest.mark.parametrize("policy", [
    "ELBSecurityPolicy-2016-08",
    "ELBSecurityPolicy-TLS-1-1-2017-01",
    "ELBSecurityPolicy-TLS13-1-0-2021-06",
    "ELBSecurityPolicy-TLS13-1-2-2021-06",
    "ELBSecurityPolicy-TLS13-1-2-FIPS-2023-04",
    "ELBSecurityPolicy-TLS13-1-2-Ext1-PQ-2025-09",
])
def test_explicitly_reviewed_nonapproved_policies_fail_without_calling_them_all_obsolete(policy):
    status, evidence = CHECK.evaluate(listener("application", policy), {})
    assert status == "FAIL"
    assert evidence["non_recommended_policies"] == [policy]


@pytest.mark.parametrize("policy", [
    "ELBSecurityPolicy-TLS13-1-3-PQ-2027-01",
    "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-10",
    "ELBSecurityPolicy-UNKNOWN",
])
def test_unreviewed_future_or_unknown_policy_is_unknown_even_with_secure_name(policy):
    assert CHECK.evaluate(listener("application", policy), {})[0] == "UNKNOWN"


def test_missing_malformed_or_denied_listener_policy_is_unknown():
    assert CHECK.evaluate(listener("network", None, include_policy=False), {})[0] == "UNKNOWN"
    malformed = listener("application", "ELBSecurityPolicy-TLS13-1-3-2021-06")
    malformed["Listeners"]["items"][0]["SslPolicy"] = ["ELBSecurityPolicy-TLS13-1-3-2021-06"]
    assert CHECK.evaluate(malformed, {})[0] == "UNKNOWN"
    denied = listener("application", "ELBSecurityPolicy-TLS13-1-3-2021-06")
    denied["Listeners"]["collection_status"] = "denied"
    assert CHECK.evaluate(denied, {})[0] == "UNKNOWN"


def test_unrelated_listener_protocols_and_gateway_are_not_applicable():
    assert CHECK.evaluate(_lb("application", listeners=[_l("HTTP", port=80)]), {})[0] == "NOT_APPLICABLE"
    assert CHECK.evaluate(_lb("network", listeners=[_l("TCP", port=80)]), {})[0] == "NOT_APPLICABLE"
    assert CHECK.evaluate(_lb("gateway"), {})[0] == "NOT_APPLICABLE"


def test_known_failure_remains_visible_when_other_policy_is_unreviewed():
    item = _lb("application", listeners=[_l("HTTPS", "ELBSecurityPolicy-2016-08", port=443),
                                         _l("HTTPS", "ELBSecurityPolicy-TLS13-1-3-PQ-2027-01", port=8443)])
    status, evidence = CHECK.evaluate(item, {})
    assert status == "FAIL"
    assert evidence["non_recommended_policies"] == ["ELBSecurityPolicy-2016-08"]
    assert evidence["unresolved_listeners"][0]["ssl_policy"] == "ELBSecurityPolicy-TLS13-1-3-PQ-2027-01"
