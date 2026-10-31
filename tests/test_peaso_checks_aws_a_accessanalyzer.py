"""Regional absence, inactive-state and unavailability truth cases."""
import copy
import pytest
from peaso.checks import CHECKS, aws_a_accessanalyzer as rules
from peaso.checks.fixtures import CASES
from peaso.checks.aws_a_facts import scope_fixture

REGISTRY = {c.id: c for c in CHECKS if c.id in rules.NATIVE_IDS}


@pytest.mark.parametrize("cid", rules.NATIVE_IDS)
def test_analyzer_variant_real_states_and_purity(cid):
    cases = CASES[cid]
    for state, expected in (("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"), ("malformed", "UNKNOWN")):
        item, index = copy.deepcopy(cases[state]), copy.deepcopy(cases.get(state + "_index", cases["index"]))
        before = copy.deepcopy((item, index))
        assert REGISTRY[cid].evaluate(item, index)[0] == expected
        assert (item, index) == before
    assert REGISTRY[cid].evaluate(rules.SUBJECT, scope_fixture("access_analyzer", [], status="denied"))[0] == "UNKNOWN"


def test_presence_does_not_masquerade_as_active_status_or_region_empty():
    index = scope_fixture("access_analyzer", [{"arn": "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/inert", "status": "DISABLED"}])
    assert REGISTRY["aws.a.accessanalyzer.region_present"].evaluate(rules.SUBJECT, index)[0] == "PASS"
    assert REGISTRY["aws.a.accessanalyzer.region_active"].evaluate(rules.SUBJECT, index)[0] == "FAIL"
    for kind in REGISTRY:
        assert REGISTRY[kind].evaluate(rules.SUBJECT, scope_fixture("access_analyzer", []))[0] == "FAIL"


def test_mixed_active_and_failed_analyzer_preserves_any_alarm_row():
    check = REGISTRY["aws.a.accessanalyzer.region_active"]
    assert check.evaluate(rules.SUBJECT, scope_fixture("access_analyzer", [{"status": "ACTIVE"}, {"status": "FAILED"}]))[0] == "FAIL"
    assert check.evaluate(rules.SUBJECT, scope_fixture("access_analyzer", [{"status": "future"}]))[0] == "UNKNOWN"


def test_collector_reads_existing_analyzers_without_creating_one(monkeypatch):
    boto3 = pytest.importorskip("boto3")
    from botocore.stub import Stubber
    from peaso.collectors import aws
    session = boto3.Session(aws_access_key_id="inert", aws_secret_access_key="inert", region_name="us-east-1")
    client = session.client("accessanalyzer", region_name="us-east-1")
    monkeypatch.setattr(aws.Requests, "client", lambda *args, **kwargs: client)
    analyzer = {"arn": "arn:aws:access-analyzer:us-east-1:111122223333:analyzer/a", "name": "a", "type": "ACCOUNT",
                "status": "ACTIVE", "createdAt": "2026-01-01T00:00:00Z"}
    stub = Stubber(client)
    stub.add_response("list_analyzers", {"analyzers": [analyzer]}, {})
    with stub:
        read = aws.Requests({}).pages(session, "accessanalyzer", "us-east-1", "list_analyzers", "analyzers")
        assert read.status == "collected" and [row["arn"] for row in read.items] == [analyzer["arn"]]
        with pytest.raises(aws.ReadFailure):
            aws.Requests({}).call(session, "accessanalyzer", "us-east-1", "create_analyzer", analyzerName="x", type="ACCOUNT")
        assert ("accessanalyzer", "create_analyzer") not in aws.READ_ACTIONS
        stub.assert_no_pending_responses()
