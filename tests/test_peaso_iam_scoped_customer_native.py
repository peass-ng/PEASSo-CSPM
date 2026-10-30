"""Exact customer-managed policy pipeline for the scoped-action PCI check."""
from __future__ import annotations

import json

import boto3
import pytest
from botocore.stub import Stubber

from peaso import engine
from peaso.collectors import aws
from peaso.checks import evaluate_check
from peaso.checks.aws_pci_iam_scoped_source_correction import CHECK_ID
from peaso.snapshot import make_snapshot

ACCOUNT = "123456789012"
REGION = "us-east-1"
SCOPE = ACCOUNT + "/global"
CUSTOMER = f"arn:aws:iam::{ACCOUNT}:policy/UnattachedCustomer"
AWS_OWNED = "arn:aws:iam::aws:policy/aws-service-role/AmazonCloudWatchRUMServiceRolePolicy"
RESOURCE = "arn:aws:s3:::example/object"


def _document(action="s3:GetObject", *, not_action=False):
    key = "NotAction" if not_action else "Action"
    return {"Statement": [{"Effect": "Allow", key: action, "Resource": RESOURCE}]}


def _run(monkeypatch, *, action="s3:GetObject", not_action=False, mode="normal", legacy_aws=False):
    session = boto3.Session(aws_access_key_id="fixture", aws_secret_access_key="fixture", region_name=REGION)
    clients = {name: session.client(name) for name in ("sts", "iam")}
    monkeypatch.setattr(aws, "_session", lambda auth, selected_region: (session, "fixture"))
    monkeypatch.setattr(aws.Requests, "client", lambda self, selected_session, service, selected_region: clients[service])
    request = {"connector": {"provider": "aws", "scopes": [ACCOUNT + "/" + REGION],
        "auth": {}, "options": {"service_concurrency": 1}}, "checks": [CHECK_ID]}
    assert engine.plan_collection(request) == ["iam_customer_policy"]
    with Stubber(clients["sts"]) as sts, Stubber(clients["iam"]) as iam:
        sts.add_response("get_caller_identity", {"Account": ACCOUNT,
            "Arn": f"arn:aws:iam::{ACCOUNT}:user/Reader", "UserId": "READONLYFIXTURE"}, {})
        if mode == "denied":
            iam.add_client_error("list_policies", service_error_code="AccessDenied",
                expected_params={"Scope": "Local", "OnlyAttached": False})
        else:
            arn = AWS_OWNED if mode == "foreign" else CUSTOMER
            policies = [] if mode == "empty" else [{"Arn": arn, "DefaultVersionId": "v1", "AttachmentCount": 0}]
            partial = mode == "partial"
            response = {"Policies": policies, "IsTruncated": partial}
            if partial:
                response["Marker"] = "next"
            iam.add_response("list_policies", response, {"Scope": "Local", "OnlyAttached": False})
            if partial:
                iam.add_client_error("list_policies", service_error_code="AccessDenied",
                    expected_params={"Scope": "Local", "OnlyAttached": False, "Marker": "next"})
            if mode not in ("empty", "foreign"):
                iam.add_response("get_policy_version", {"PolicyVersion": {"VersionId": "v1",
                    "IsDefaultVersion": True, "Document": json.dumps(_document(action, not_action=not_action))}},
                    {"PolicyArn": CUSTOMER, "VersionId": "v1"})
        snapshot = engine.collect_snapshot(request)
        sts.assert_no_pending_responses()
        iam.assert_no_pending_responses()
    if legacy_aws:
        legacy = {"Arn": AWS_OWNED, "AccountId": ACCOUNT, "DefaultVersionId": "v1",
            "PolicyVersionList": [{"VersionId": "v1", "IsDefaultVersion": True,
                "Document": _document("*")}]}
        snapshot = make_snapshot("aws", snapshot["scopes"], [
            *(c for c in snapshot["collections"] if c["type"] != "iam_policy"),
            {"type": "iam_policy", "scope": SCOPE, "account_id": ACCOUNT,
             "global": True, "status": "collected", "items": [legacy]}],
            created_at=snapshot["created_at"], metadata=snapshot["metadata"])
    findings = [f for f in engine.evaluate_snapshot(snapshot, checks=[CHECK_ID])["findings"]
                if f["check_id"] == CHECK_ID]
    return snapshot, findings


@pytest.mark.parametrize("action,not_action,expected", [
    ("s3:GetObject", False, "PASS"),
    ("*", False, "FAIL"),
    ("s3:*", False, "FAIL"),
    ("iam:*", True, "FAIL"),
    ("*", True, "PASS"),
])
def test_sdk_customer_default_document(monkeypatch, action, not_action, expected):
    snapshot, findings = _run(monkeypatch, action=action, not_action=not_action)
    assert len(findings) == 1
    assert findings[0]["status"] == expected
    envelope, = [c for c in snapshot["collections"] if c["type"] == "iam_customer_policy"]
    assert envelope["status"] == "collected" and envelope["scope"] == SCOPE
    assert envelope["items"][0]["AttachmentCount"] == 0
    assert snapshot["metadata"]["authorized_evidence_generation"]["generation_requests"] == 0


def test_legacy_aws_owned_reference_does_not_poison_customer(monkeypatch):
    _, findings = _run(monkeypatch, legacy_aws=True)
    assert len(findings) == 1 and findings[0]["status"] == "PASS"


@pytest.mark.parametrize("mode,expected", [
    ("empty", "EMPTY"), ("denied", "DENIED"),
    ("partial", "UNKNOWN"), ("foreign", "UNKNOWN"),
])
def test_sdk_unavailable_and_out_of_universe(monkeypatch, mode, expected):
    _, findings = _run(monkeypatch, mode=mode)
    assert findings
    assert {f["status"] for f in findings} == {expected}
    assert "PASS" not in {f["status"] for f in findings}


def test_exact_projection_and_default_version_guards(monkeypatch):
    snapshot, findings = _run(monkeypatch)
    assert findings[0]["status"] == "PASS"
    collection, = [c for c in snapshot["collections"] if c["type"] == "iam_customer_policy"]
    row = collection["items"][0]
    context = {"provider": "aws", "Account": ACCOUNT, "scope": SCOPE}
    base = {"context": context, "collections": {"iam_customer_policy": [collection]},
        "iam_customer_policy": [{"type": "iam_customer_policy", "scope": SCOPE,
                                 "provider": "aws", "data": row}]}
    assert evaluate_check(CHECK_ID, row, base)[0] == "PASS"
    mismatch = json.loads(json.dumps(base))
    mismatch["iam_customer_policy"][0]["data"]["DefaultVersionId"] = "v2"
    assert evaluate_check(CHECK_ID, mismatch["iam_customer_policy"][0]["data"], mismatch)[0] == "UNKNOWN"
    wrong_default = json.loads(json.dumps(base))
    wrong_default["collections"]["iam_customer_policy"][0]["items"][0]["DefaultVersionId"] = "v2"
    wrong_default["iam_customer_policy"][0]["data"]["DefaultVersionId"] = "v2"
    assert evaluate_check(CHECK_ID, wrong_default["iam_customer_policy"][0]["data"], wrong_default)[0] == "UNKNOWN"
    duplicate = json.loads(json.dumps(base))
    duplicate["collections"]["iam_customer_policy"][0]["items"].append(row)
    duplicate["iam_customer_policy"].append(duplicate["iam_customer_policy"][0])
    assert evaluate_check(CHECK_ID, row, duplicate)[0] == "UNKNOWN"
    partial_detail = json.loads(json.dumps(base))
    partial_detail["collections"]["iam_customer_policy"][0]["items"][0]["DefaultDocument"]["collection_status"] = "partial"
    partial_detail["iam_customer_policy"][0]["data"]["DefaultDocument"]["collection_status"] = "partial"
    assert evaluate_check(CHECK_ID, partial_detail["iam_customer_policy"][0]["data"], partial_detail)[0] == "UNKNOWN"
    foreign = json.loads(json.dumps(base))
    foreign["collections"]["iam_customer_policy"][0]["items"][0]["Arn"] = AWS_OWNED
    foreign["iam_customer_policy"][0]["data"]["Arn"] = AWS_OWNED
    assert evaluate_check(CHECK_ID, foreign["iam_customer_policy"][0]["data"], foreign)[0] == "UNKNOWN"


