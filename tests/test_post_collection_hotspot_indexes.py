"""Post-collection hot paths keep their exact results with fewer repeated computations."""
from collections import Counter

from peaso.analysis.internet_exposure import Inventory
from peaso.privesc.effective_permissions.aws import AwsModel
from peaso.snapshot import FrozenDict, FrozenList, _freeze
from test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, allow, aws_snap, col, edges, reached, real, role, role_arn, user)

TID = "aws-lambda-passrole-createfunction-dynamodb-stream-trigger"
BASE = ("iam:PassRole", "lambda:CreateFunction", "lambda:CreateEventSourceMapping", "dynamodb:CreateTable")
READ = ("dynamodb:DescribeStream", "dynamodb:GetShardIterator", "dynamodb:GetRecords", "dynamodb:ListStreams")


def _counted(monkeypatch):
    calls = Counter()
    original = AwsModel.check

    def check(self, principal, req, ref):
        calls[(req.get("action"), ref)] += 1
        return original(self, principal, req, ref)

    monkeypatch.setattr(AwsModel, "check", check)
    return calls


def _tables_and_functions(names):
    tables = [{"Table": {"TableName": name}} for name in names]
    functions = [{"FunctionName": name, "FunctionArn": f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{name}"}
                 for name in names]
    return [col("dynamodb_table", tables), col("lambda_function", functions)]


def test_dynamodb_stream_route_checks_each_new_function_once_per_region(monkeypatch):
    calls = _counted(monkeypatch)
    blocked = user("alice", allow(*BASE[1:], "dynamodb:PutItem"),
                   {"Effect": "Allow", "Action": "iam:PassRole", "Resource": role_arn("fn"),
                    "Condition": {"StringEquals": {"iam:AssociatedResourceArn": "arn:aws:lambda:x:y:function:other"}}})
    roles = [role("fn", "lambda.amazonaws.com", allow(*READ))]
    result = real(aws_snap([blocked], roles, _tables_and_functions(["a", "b", "c"])), TID)
    assert edges(result, ALICE) == []
    generated = [(action, ref) for action, ref in calls
                 if isinstance(ref, str) and ("/peasoprivescaudit" in ref or ":peasoprivescaudit" in ref)]
    creates = [ref for action, ref in generated if action == "lambda:CreateFunction"]
    tables = [ref for action, ref in generated if action == "dynamodb:CreateTable"]
    assert len(creates) == len(tables) == 5
    assert all(calls[("lambda:CreateFunction", ref)] == 1 for ref in creates)
    assert calls[("dynamodb:ListStreams", "__peaso_resource_less_action__")] == 1


def test_dynamodb_stream_route_skips_stream_reads_without_table_writes(monkeypatch):
    calls = _counted(monkeypatch)
    roles = [role("fn", "lambda.amazonaws.com", allow(*READ))]
    inventory = [col("lambda_function", [], "empty"), col("dynamodb_table", [], "empty")]
    assert edges(real(aws_snap([user("alice", allow(*BASE))], roles, inventory), TID), ALICE) == []
    assert not any(action in READ or action == "lambda:CreateFunction" for action, _ in calls)
    assert reached(real(aws_snap([user("alice", allow(*BASE, "dynamodb:PutItem"))], roles, inventory), TID),
                   ALICE) == {role_arn("fn"): "conditional"}


def _eager(resources):
    by_id = {}
    for resource in resources:
        for key in Inventory._keys(None, resource):
            by_id.setdefault((resource["type"], key), resource)
    return by_id


def test_inventory_lazy_identifier_index_matches_eager_first_match():
    rows = [
        {"type": "security_group", "native_id": "sg-1", "data": {"GroupId": "SG-1", "VpcId": "vpc-1"}},
        {"type": "security_group", "native_id": "sg-1", "data": {"GroupId": "sg-2"}},
        {"type": "subnet", "native_id": "subnet-1", "data": {"SubnetId": "subnet-1", "VpcId": "vpc-1"}},
        {"type": "service", "native_id": "x", "data": {"metadata": {"namespace": "ns", "name": "web"}}},
        {"type": "metric", "native_id": 7, "data": ["not", "a", "dict"]},
    ]
    inventory = Inventory({"provider": "aws", "collections": []}, rows)
    eager = _eager(rows)
    for kind, key in [*eager, ("security_group", "SG-1"), ("security_group", "missing"), ("subnet", "VPC-1"),
                      ("metric", 7), ("nothing", "x")]:
        expected = eager.get((kind, str(key))) or eager.get((kind, str(key).lower()))
        assert inventory.get(kind, key) is expected
    assert inventory.get("security_group", None) is None


def test_freeze_leaf_fast_path_is_identical():
    class Mapping(dict):
        pass

    leaf = "text"
    value = {"a": [1, 2.5, True, None, leaf, ("t", {"x": 1})], "b": Mapping(c=[]), "d": leaf}
    frozen = _freeze(value)
    assert frozen == {**value, "a": [1, 2.5, True, None, leaf, ["t", {"x": 1}]]} and type(frozen) is FrozenDict
    assert type(frozen["a"]) is FrozenList and type(frozen["a"][5]) is FrozenList
    assert type(frozen["a"][5][1]) is FrozenDict and type(frozen["b"]) is FrozenDict
    assert frozen["d"] is leaf and frozen["a"][4] is leaf
    assert _freeze(frozen) is frozen
