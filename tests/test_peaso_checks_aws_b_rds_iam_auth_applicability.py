"""IAM DB authentication applies only to supported standalone RDS options."""
import copy

import pytest

from peaso.checks import CHECKS
from peaso.checks.claude_aws_b_common import inventory


CHECK = next(check for check in CHECKS if check.id == "aws.cb.rds.instance_iam_auth_all_engines")
ARN = "arn:aws:rds:us-east-1:111111111111:db:db1"


def instance(engine="mysql", enabled=False, **other):
    return {"DBInstanceArn": ARN, "Engine": engine, "EngineVersion": "8.0.40", "DBInstanceClass": "db.r6g.large",
            "DBSubnetGroup": {"Subnets": [{"SubnetIdentifier": "subnet-1"}]},
            "IAMDatabaseAuthenticationEnabled": enabled, **other}


def capability(engine="mysql", supported=True, **other):
    return {"id": ARN, "DBInstanceArn": ARN, "Engine": engine, "EngineVersion": "8.0.40",
            "DBInstanceClass": "db.r6g.large", "SupportsIAMDatabaseAuthentication": supported, **other}


def evaluate(item, rows=None, collection_status=None):
    index = inventory("rds_iam_auth_capability", rows or [], status=collection_status)
    before = copy.deepcopy(item)
    outcome, _evidence = CHECK.evaluate(item, index)
    assert item == before
    return outcome


@pytest.mark.parametrize("engine,version", [("mysql", "8.0.40"), ("mariadb", "11.8.3"), ("postgres", "17.4")])
def test_supported_disabled_fails_and_enabled_passes(engine, version):
    item = instance(engine, EngineVersion=version)
    fact = capability(engine, EngineVersion=version)
    assert evaluate(item, [fact]) == "FAIL"
    assert evaluate({**item, "IAMDatabaseAuthenticationEnabled": True}, [fact]) == "PASS"


def test_observed_enabled_passes_when_option_no_longer_orderable_or_denied():
    item = instance(enabled=True)
    assert evaluate(item, []) == "PASS"
    assert evaluate(item, [], "denied") == "PASS"


@pytest.mark.parametrize("engine", ["oracle-ee", "oracle-se2", "sqlserver-ee", "sqlserver-web", "db2-ae", "custom-oracle-ee", "docdb", "aurora-mysql"])
def test_unsupported_engines_not_applicable(engine):
    assert evaluate(instance(engine), [capability()]) == "NOT_APPLICABLE"


@pytest.mark.parametrize("engine", ["future-rds-engine", "sqlserver-future", "", "MYSQL"])
def test_unrecognized_engine_is_unknown(engine):
    assert evaluate(instance(engine), [capability()]) == "UNKNOWN"


@pytest.mark.parametrize("engine", ["mysql", "mariadb", "postgres"])
def test_cluster_members_are_not_instance_configuration(engine):
    assert evaluate(instance(engine, DBClusterIdentifier="cluster-1"), [capability(engine)]) == "NOT_APPLICABLE"


def test_false_with_unsupported_or_unavailable_capability():
    item = instance()
    assert evaluate(item, [capability(supported=False)]) == "NOT_APPLICABLE"
    assert evaluate(item, []) == "UNKNOWN"
    assert evaluate(item, [], "denied") == "UNKNOWN"
    assert evaluate(item, [{key: value for key, value in capability().items() if key != "SupportsIAMDatabaseAuthentication"}]) == "UNKNOWN"
    assert evaluate(item, [capability(EngineVersion="8.4.6")]) == "UNKNOWN"
    assert evaluate(item, [capability(), capability()]) == "UNKNOWN"
    denied = capability()
    denied["_coverage"] = {"SupportsIAMDatabaseAuthentication": {"status": "denied"}}
    assert evaluate(item, [denied]) == "UNKNOWN"


def test_missing_or_malformed_instance_facts_are_unknown():
    item = instance()
    for field in ("Engine", "EngineVersion", "DBInstanceClass", "DBSubnetGroup", "IAMDatabaseAuthenticationEnabled"):
        missing = {key: value for key, value in item.items() if key != field}
        assert evaluate(missing, [capability()]) == "UNKNOWN"
    assert evaluate({**item, "IAMDatabaseAuthenticationEnabled": "false"}, [capability()]) == "UNKNOWN"
    assert evaluate({**item, "collection_status": "denied"}, [capability()]) == "UNKNOWN"


def test_outposts_excluded_and_unreadable_placement_unknown():
    item = instance(DBSubnetGroup={"Subnets": [{"SubnetIdentifier": "subnet-1", "SubnetOutpost": {"Arn": "arn:aws:outposts:us-east-1:111111111111:outpost/op-1"}}]})
    assert evaluate(item, [capability()]) == "NOT_APPLICABLE"
    assert evaluate({**item, "IAMDatabaseAuthenticationEnabled": True}, []) == "NOT_APPLICABLE"
    item["DBSubnetGroup"] = {"Subnets": [{"SubnetIdentifier": "subnet-1", "SubnetOutpost": {}}]}
    assert evaluate(item, [capability()]) == "FAIL"
    assert evaluate({**item, "IAMDatabaseAuthenticationEnabled": True}, []) == "PASS"
    item["DBSubnetGroup"]["Subnets"][0]["SubnetOutpost"] = {"Arn": None}
    assert evaluate(item, [capability()]) == "UNKNOWN"
