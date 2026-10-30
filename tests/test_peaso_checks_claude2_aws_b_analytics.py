"""Behaviour tests for the claude2_aws_b analytics group (EFS, EMR, Elasticsearch, Firehose, RDS snapshots), runnable on its own."""
from peaso.checks.hacktricks_scope import includes
import copy

import pytest

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks import claude2_aws_b_analytics as group
from peaso.checks.claude2_aws_b_common import IDS, ROWS, CONTEXT, Unavailable

REGISTRY = {check.id: check for check in CHECKS}
HACKTRICKS = "HackTricks Cloud Best Practices"
PREFIXES = ("aws.c2b.efs.", "aws.c2b.emr.", "aws.c2b.es.", "aws.c2b.firehose.", "aws.c2b.rds.")
MINE = [cid for cid in IDS if cid.startswith(PREFIXES)]
STANDARD = {"pass", "fail", "manual", "unknown", "not_applicable", "missing", "malformed", "index", "case_indices"}


def _evaluate(cid, name):
    cases = CASES[cid]
    index = cases.get(name + "_index", cases.get("index", {}))
    data, scoped = copy.deepcopy(cases[name]), copy.deepcopy(index)
    before, before_index = copy.deepcopy(data), copy.deepcopy(scoped)
    status = REGISTRY[cid].evaluate(data, scoped)[0]
    assert data == before and scoped == before_index
    return status


@pytest.mark.parametrize("cid", MINE)
def test_pass_fail_unknown(cid):
    check, cases = REGISTRY[cid], CASES[cid]
    assert _evaluate(cid, "pass") == "PASS"
    assert _evaluate(cid, "fail") == "FAIL"
    assert _evaluate(cid, "unknown") == "UNKNOWN"
    for item in ({}, None, {"collection_status": "denied"}):
        assert check.evaluate(item, cases.get("index", {}))[0] == "UNKNOWN"
    if "not_applicable" in cases:
        assert _evaluate(cid, "not_applicable") == "NOT_APPLICABLE"
    if "pass_index" in cases:
        assert check.evaluate(copy.deepcopy(cases["pass"]), {"context": dict(CONTEXT)})[0] in ("UNKNOWN", "NOT_APPLICABLE")
    assert (HACKTRICKS in check.frameworks) == includes(check.id) and ROWS[cid]


@pytest.mark.parametrize("cid,key", [(c, k) for c in MINE for k in CASES[c] if k not in STANDARD and not k.endswith(("_index", "_expect"))])
def test_named_fixtures(cid, key):
    expected = CASES[cid].get(key + "_expect") or ("PASS" if key.endswith("_pass") else None)
    assert expected, key
    assert _evaluate(cid, key) == expected


def test_prowler_sg_rule_semantics():
    rule = group.prowler_rule_public_any
    assert rule({"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []})
    assert rule({"IpProtocol": "-1", "IpRanges": [{"CidrIp": "8.8.8.0/24"}], "Ipv6Ranges": []})
    assert not rule({"IpProtocol": "-1", "IpRanges": [{"CidrIp": "10.0.0.0/8"}], "Ipv6Ranges": []})
    assert rule({"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535, "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []})
    assert not rule({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []})
    with pytest.raises(Unavailable):
        rule({"IpProtocol": "-1", "IpRanges": [{"CidrIp": "not-a-cidr"}], "Ipv6Ranges": []})


def test_efs_ssl_condition_key_case_insensitive():
    check = REGISTRY["aws.c2b.efs.policy_enforces_ssl"]
    policy = {"Statement": [{"Effect": "Deny", "Principal": {"AWS": ["*"]}, "Action": ["elasticfilesystem:*"],
                             "Condition": {"Bool": {"aws:securetransport": ["false"]}}}]}
    assert check.evaluate(group._fs(policy=policy), {})[0] == "PASS"
    allow = {"Statement": [{**policy["Statement"][0], "Effect": "Allow"}]}
    assert check.evaluate(group._fs(policy=allow), {})[0] == "FAIL"
