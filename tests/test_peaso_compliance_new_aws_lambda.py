"""Signed Lambda role-existence fixtures over complete account-global IAM facts."""

from peaso.checks import CHECKS, evaluate_check
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
from peaso.checks import compliance_new_aws_lambda  # noqa: F401  (registration side effect)


CHECK_ID = "aws_cis_lambda_execution_role_exists"
UNIQUE_ID = "aws_cis_lambda_execution_role_unique"
ACCOUNT = "123456789012"
SCOPE = ACCOUNT + "/eu-west-1"
GLOBAL = ACCOUNT + "/global"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/app-exec"
CALLER = {"Account": ACCOUNT,
          "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/Audit/peaso-read-only"}


def function(name="app", role=ROLE):
    return {"FunctionArn": f"arn:aws:lambda:eu-west-1:{ACCOUNT}:function:{name}",
            "FunctionName": name, "Role": role, "AccountId": ACCOUNT, "Region": "eu-west-1"}


def iam_role(arn=ROLE):
    return {"Arn": arn, "RoleName": arn.rsplit("/", 1)[-1], "AccountId": ACCOUNT}


def index(functions, roles, *, function_status="collected", role_status="collected",
          callers=None, role_global=True):
    return {"context": {"provider": "aws", "scope": SCOPE, "Account": ACCOUNT,
                        "metadata": {"caller_identities": [CALLER] if callers is None else callers}},
            "collections": {
                "lambda_function": [{"type": "lambda_function", "scope": SCOPE, "status": function_status,
                                     "account_id": ACCOUNT, "global": False, "items": functions}],
                "iam_role": [{"type": "iam_role", "scope": GLOBAL, "status": role_status,
                              "account_id": ACCOUNT, "global": role_global, "items": roles}]},
            "lambda_function": [{"type": "lambda_function", "scope": SCOPE, "data": row} for row in functions],
            "iam_role": [{"type": "iam_role", "scope": GLOBAL, "data": row} for row in roles]}


def evaluate(item, functions=None, roles=None, **kwargs):
    return evaluate_check(CHECK_ID, item, index([item] if functions is None else functions,
                                                [iam_role()] if roles is None else roles, **kwargs))


def test_exact_same_account_role_arn_exists_or_is_proven_absent():
    item = function()
    assert evaluate(item)[0] == "PASS"
    status, evidence = evaluate(item, roles=[])
    assert status == "FAIL" and evidence["execution_role_arn"] == ROLE
    assert evaluate(item, roles=[iam_role(f"arn:aws:iam::{ACCOUNT}:role/other")])[0] == "FAIL"


def test_missing_denied_partial_and_malformed_facts_stay_unknown():
    item = function()
    assert evaluate(item, role_status="denied")[0] == "UNKNOWN"
    assert evaluate(item, function_status="partial")[0] == "UNKNOWN"
    assert evaluate(item, callers=[])[0] == "UNKNOWN"
    assert evaluate(item, role_global=False)[0] == "UNKNOWN"
    assert evaluate(item, roles=[{"Arn": ROLE}])[0] == "UNKNOWN"
    foreign_item = function()
    foreign_item["AccountId"] = "999999999999"
    assert evaluate(foreign_item)[0] == "UNKNOWN"
    assert evaluate(function(role=f"arn:aws:iam::999999999999:role/foreign"), roles=[])[0] == "UNKNOWN"
    missing = function()
    del missing["Role"]
    assert evaluate(missing)[0] == "UNKNOWN"


def test_duplicate_or_detached_function_and_role_inventory_unknown():
    item = function()
    assert evaluate(item, functions=[item, function()])[0] == "UNKNOWN"
    assert evaluate(item, roles=[iam_role(), iam_role()])[0] == "UNKNOWN"
    detached = function(role=f"arn:aws:iam::{ACCOUNT}:role/other")
    assert evaluate(detached, functions=[item])[0] == "UNKNOWN"


def test_production_engine_joins_account_global_roles_to_regional_function():
    item = function()
    snapshot = make_snapshot("aws", [SCOPE], [
        {"type": "lambda_function", "scope": SCOPE, "service": "lambda", "status": "collected",
         "account_id": ACCOUNT, "global": False, "items": [item]},
        {"type": "iam_role", "scope": GLOBAL, "service": "iam", "status": "collected",
         "account_id": ACCOUNT, "global": True, "items": [iam_role()]},
    ], created_at="2026-10-12T00:00:00+00:00", metadata={"caller_identities": [CALLER]})
    report = evaluate_snapshot(snapshot, categories=["least_privilege"], checks=[CHECK_ID])
    findings = [finding for finding in report["findings"] if finding["check_id"] == CHECK_ID]
    assert len(findings) == 1 and findings[0]["status"] == "PASS"


def usage(status="collected", shared=None):
    return {"schema_version": 1, "accounts": [{"account_id": ACCOUNT, "partition": "aws",
            "status": status, "enabled_regions": ["eu-west-1"], "observed_regions": ["eu-west-1"],
            "shared_active_roles": [] if shared is None else shared}]}


def unique_index(item, *, summary=None, function_status="collected"):
    facts = index([item], [], function_status=function_status)
    facts["context"]["metadata"]["lambda_execution_role_usage"] = usage() if summary is None else summary
    return facts


def unique_function(state="Active"):
    item = function()
    item["Configuration"] = {"collection_status": "collected", "FunctionArn": item["FunctionArn"],
                             "Role": ROLE, "State": state}
    return item


def test_active_lambda_role_uniqueness_uses_account_summary():
    item = unique_function()
    assert evaluate_check(UNIQUE_ID, item, unique_index(item))[0] == "PASS"
    shared = [{"role_arn": ROLE, "function_count": 2}]
    status, evidence = evaluate_check(UNIQUE_ID, item, unique_index(item, summary=usage("partial", shared)))
    assert status == "FAIL" and evidence["active_function_count"] == 2
    assert evaluate_check(UNIQUE_ID, item, unique_index(item, summary=usage("partial")))[0] == "UNKNOWN"
    assert evaluate_check(UNIQUE_ID, item, unique_index(item, function_status="partial"))[0] == "UNKNOWN"
    assert evaluate_check(UNIQUE_ID, unique_function("Inactive"),
                          unique_index(unique_function("Inactive")))[0] == "NOT_APPLICABLE"


def test_unavailable_or_mismatched_lambda_role_usage_is_unknown():
    item = unique_function()
    assert evaluate_check(UNIQUE_ID, item, unique_index(item, summary={}))[0] == "UNKNOWN"
    assert evaluate_check(UNIQUE_ID, item, unique_index(item, function_status="denied"))[0] == "UNKNOWN"
    missing = unique_function()
    del missing["Configuration"]["State"]
    assert evaluate_check(UNIQUE_ID, missing, unique_index(missing))[0] == "UNKNOWN"
    future = unique_function("FutureState")
    assert evaluate_check(UNIQUE_ID, future, unique_index(future))[0] == "UNKNOWN"
    mismatch = unique_function()
    mismatch["Configuration"]["Role"] = f"arn:aws:iam::{ACCOUNT}:role/other"
    assert evaluate_check(UNIQUE_ID, mismatch, unique_index(mismatch))[0] == "UNKNOWN"
    foreign = unique_function()
    foreign["Role"] = "arn:aws-cn:iam::123456789012:role/foreign"
    assert evaluate_check(UNIQUE_ID, foreign, unique_index(foreign))[0] == "UNKNOWN"


def test_production_engine_reads_lambda_role_usage_metadata():
    item = unique_function()
    snapshot = make_snapshot("aws", [SCOPE], [
        {"type": "lambda_function", "scope": SCOPE, "service": "lambda", "status": "collected",
         "account_id": ACCOUNT, "global": False, "items": [item]},
    ], created_at="2026-10-12T00:00:00+00:00",
        metadata={"caller_identities": [CALLER], "lambda_execution_role_usage": usage()})
    report = evaluate_snapshot(snapshot, categories=["least_privilege"], checks=[UNIQUE_ID])
    findings = [finding for finding in report["findings"] if finding["check_id"] == UNIQUE_ID]
    assert len(findings) == 1 and findings[0]["status"] == "PASS"
    check = next(check for check in CHECKS if check.id == UNIQUE_ID)
    assert (check.provider, check.kind, check.category, check.severity, check.target) == (
        "aws", "lambda_function", "least_privilege", "medium", "resource")
