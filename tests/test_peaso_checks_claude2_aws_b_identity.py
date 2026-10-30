"""Behaviour tests for the claude2_aws_b identity group (ACM, Private CA, Bedrock, Cognito, Connect, Directory Service, FMS)."""
import copy
import re

import pytest

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks import claude2_aws_b_identity as identity
from peaso.checks.claude2_aws_b_common import IDS, CONTEXT

REGISTRY = {check.id: check for check in CHECKS}
GROUP = [cid for cid in IDS if cid.split(".")[2] in ("acm", "acmpca", "bedrock", "cognito", "connect", "directoryservice", "fms")]
STANDARD = {"pass", "fail", "manual", "unknown", "not_applicable", "missing", "malformed", "index", "case_indices"}


def _evaluate(cid, name, index=None):
    cases = CASES[cid]
    index = cases.get(name + "_index", cases.get("index", {})) if index is None else index
    data, scoped = copy.deepcopy(cases[name]), copy.deepcopy(index)
    before = (copy.deepcopy(data), copy.deepcopy(scoped))
    status = REGISTRY[cid].evaluate(data, scoped)[0]
    assert (data, scoped) == before
    return status


@pytest.mark.parametrize("cid", GROUP)
def test_fixtures(cid):
    cases = CASES[cid]
    assert _evaluate(cid, "pass") == "PASS"
    assert _evaluate(cid, "fail" if "fail" in cases else "manual") == ("FAIL" if "fail" in cases else "MANUAL")
    assert _evaluate(cid, "unknown") == "UNKNOWN"
    for value in ({}, None, {"collection_status": "denied"}):
        assert REGISTRY[cid].evaluate(value, cases.get("index", {}))[0] == "UNKNOWN"
    for key in cases:
        if key not in STANDARD and not key.endswith(("_index", "_expect")):
            expected = "NOT_APPLICABLE" if key == "not_applicable" else cases.get(key + "_expect") or ("PASS" if key.endswith("_pass") else None)
            assert _evaluate(cid, key) == expected, key
    if "pass_index" in cases:
        assert REGISTRY[cid].evaluate(copy.deepcopy(cases["pass"]), {"context": dict(CONTEXT)})[0] in ("UNKNOWN", "NOT_APPLICABLE")


def test_client_with_unreadable_configuration_is_unknown():
    item = copy.deepcopy(CASES["aws.c2b.cognito.clients_token_revocation"]["pass"])
    item["Clients"]["items"][0]["Configuration"] = {"collection_status": "denied"}
    assert REGISTRY["aws.c2b.cognito.clients_token_revocation"].evaluate(item, {})[0] == "UNKNOWN"


def test_issued_certificate_without_validity_is_unknown():
    item = copy.deepcopy(CASES["aws.c2b.acm.in_use_not_expiring_7_days"]["pass"])
    del item["Certificate"]["Certificate"]["NotAfter"]
    assert REGISTRY["aws.c2b.acm.in_use_not_expiring_7_days"].evaluate(item, {"context": dict(CONTEXT)})[0] == "UNKNOWN"


def test_bedrock_activity_unknown_keeps_vpc_unknown():
    cid = "aws.c2b.bedrock.vpc_endpoints"
    index = copy.deepcopy(CASES[cid]["not_applicable_index"])
    index["collections"]["bedrock_agent"] = [{"scope": "111111111111/us-east-1", "status": "denied"}]
    index["network_interface"] = [{"data": {"NetworkInterfaceId": "eni-1", "VpcId": "vpc-1"}}]
    assert REGISTRY[cid].evaluate(copy.deepcopy(CASES[cid]["pass"]), index)[0] == "UNKNOWN"


def test_collector_facts_are_read_only():
    for fact in identity.COLLECTOR_FACTS:
        assert fact["kind"] and fact["fields"] and fact["checks"]
        assert re.findall(r"\b(?:List|Describe|Get)[A-Z]", fact["api"]), fact["api"]
        assert not re.search(r"\b(?:Create|Put|Update|Delete|Enable|Disable|Register|Associate|Start|Tag)[A-Z]", fact["api"]), fact["api"]
