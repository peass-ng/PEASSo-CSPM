"""Private-ECR source correction over read-only SDK-shaped evidence."""
from __future__ import annotations

import copy
import json

import pytest

from test_peaso_collectors_aws import sdk
from peaso.checks import CHECKS
from peaso.checks import aws_ecr_source_correction as correction
from peaso.collectors import aws
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

CID = correction.CHECK_ID
ACCOUNT = "123456789012"
REGION = "us-east-1"
SCOPE = f"{ACCOUNT}/{REGION}"
ARN = f"arn:aws:ecr:{REGION}:{ACCOUNT}:repository/app"
BASE = {"repositoryArn": ARN, "repositoryName": "app", "registryId": ACCOUNT,
        "imageTagMutability": "MUTABLE"}


def statement(principal, action=None, **extra):
    return {"Effect": "Allow", "Principal": principal,
            "Action": ["ecr:BatchGetImage"] if action is None else action, **extra}


def policy(*statements):
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def findings(snapshot):
    return [row for row in evaluate_snapshot(snapshot, checks=[CID])["findings"]
            if row["check_id"] == CID]


def snapshot(row, status="collected"):
    items = [copy.deepcopy(row)] if row is not None and status in ("collected", "partial") else []
    envelope = {"type": "ecr_repository", "scope": SCOPE, "service": "ecr",
                "status": status, "items": items}
    return make_snapshot("aws", [SCOPE], [envelope])


def test_corrected_source_metadata_describes_private_repository_check():
    check = next(row for row in CHECKS if row.id == CID)
    assert check.kind == "ecr_repository" and check.target == "resource"
    assert check.dependencies == ["ecr_repository"]
    public = check.public()
    assert public["title"] == correction.TITLE
    from tests.reviewed_guidance_presentation import assert_description_preserves_contract
    assert_description_preserves_contract(CID)
    assert "private ECR" in public["description"] and "ignoring conditions" in public["description"]
    assert "not inventory public ECR" in public["description"] and "prove effective public access" in public["description"]
    assert public["source_correction"] == public["proposal_provenance"]["source_correction"]
    assert public["proposal_provenance"]["signed_resource_kind"] == "ecr_public_repository"
    assert public["proposal_provenance"]["signed_spec_status"] == "historical_superseded_for_this_check"


@pytest.mark.parametrize("document,status", [
    (policy(statement({"AWS": ["*"]})), "FAIL"),
    (policy(statement({"AWS": ["*"]}, Condition={"StringEquals": {"aws:PrincipalOrgID": "o-1"}})), "FAIL"),
    (policy(statement({"AWS": ["arn:aws:iam::123456789012:role/ci"]})), "PASS"),
    (policy(statement("*")), "FAIL"),  # policyToCanonical maps bare * to Principal.AWS=["*"].
    (policy(statement({"AWS": ["*"]}, action=[])), "PASS"),
    (policy(statement({"AWS": "*"})), "FAIL"),
    (policy(statement({"AWS": ["*"]}, action="ecr:BatchGetImage")), "FAIL"),
    (policy(statement({"AWS": "arn:aws:iam::123456789012:role/ci"}, action="ecr:BatchGetImage")), "PASS"),
    (json.dumps({"Statement": statement("*", action="ecr:BatchGetImage")}), "FAIL"),
    (policy(statement({"Service": "lambda.amazonaws.com"})), "PASS"),
    (json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": ["*"]}}]}), "UNKNOWN"),
    (policy(statement({"AWS": ["*", 7]})), "UNKNOWN"),
    (policy(statement({"AWS": ["*"]}, action=["ecr:BatchGetImage", 7])), "UNKNOWN"),
    (policy(statement(None)), "UNKNOWN"),
    (policy(statement([])), "UNKNOWN"),
    (policy(statement({})), "UNKNOWN"),
    (policy(statement({"Other": "*"})), "UNKNOWN"),
    (policy(statement({"Service": 7})), "UNKNOWN"),
    (policy(statement({"AWS": "%2A"})), "UNKNOWN"),
    (policy(statement({"AWS": ["*"]}, Condition={"Bool": []})), "UNKNOWN"),
    (policy(statement({"AWS": ["*"]}, NotPrincipal=7)), "UNKNOWN"),
    (policy(statement({"AWS": ["*"]}, NotAction=7)), "UNKNOWN"),
    (json.dumps({"Version": 7, "Statement": [statement({"AWS": ["*"]})]}), "UNKNOWN"),
    (policy(statement({"AWS": ["*"]}, Effect="Typo")), "UNKNOWN"),
    ("{bad", "UNKNOWN"),
])
def test_pinned_policy_std_canonical_shapes(document, status):
    row = {**BASE, "Policy": {"collection_status": "collected", "registryId": ACCOUNT,
                             "repositoryName": "app", "policyText": document}}
    assert [f["status"] for f in findings(snapshot(row))] == [status]


def test_documented_absent_policy_passes_and_undocumented_absence_does_not():
    row = {**BASE, "Policy": {"collection_status": "empty", "absent": True,
                             "error": {"code": "RepositoryPolicyNotFoundException"}}}
    assert [f["status"] for f in findings(snapshot(row))] == ["PASS"]
    row["Policy"]["error"] = {}
    assert [f["status"] for f in findings(snapshot(row))] == ["PASS"]
    row["Policy"].pop("error")
    assert [f["status"] for f in findings(snapshot(row))] == ["UNKNOWN"]


@pytest.mark.parametrize("change", [
    {"repositoryArn": "arn:aws:ecr:us-east-1:999999999999:repository/app"},
    {"registryId": "999999999999"},
    {"repositoryName": "other"},
])
def test_foreign_repository_identity_cannot_pass(change):
    row = {**BASE, "Policy": {"collection_status": "empty", "absent": True,
                             "error": {"code": "RepositoryPolicyNotFoundException"}}, **change}
    assert all(f["status"] != "PASS" for f in findings(snapshot(row)))


@pytest.mark.parametrize("status", ["partial", "denied", "malformed"])
def test_incomplete_parent_inventory_never_passes(status):
    row = {**BASE, "Policy": {"collection_status": "empty", "absent": True,
                             "error": {"code": "RepositoryPolicyNotFoundException"}}}
    assert all(f["status"] != "PASS" for f in findings(snapshot(row, status=status)))


@pytest.mark.parametrize("mode,expected", [
    ("wildcard", "FAIL"), ("bare_wildcard", "FAIL"),
    ("scalar_wildcard", "FAIL"), ("scalar_action", "FAIL"),
    ("singleton_statement", "FAIL"), ("private", "PASS"), ("absent", "PASS"),
    ("detail_denied", "UNKNOWN"), ("list_denied", "DENIED"),
    ("partial_pages", "UNKNOWN"), ("malformed_policy", "UNKNOWN"),
    ("foreign_detail", "UNKNOWN"), ("foreign_listing", "UNKNOWN"),
])
def test_sdk_collector_to_engine_ecr_policy(sdk, mode, expected):
    _, add, _ = sdk
    add("sts").add_response("get_caller_identity", {"Account": ACCOUNT,
        "Arn": f"arn:aws:iam::{ACCOUNT}:user/reviewer", "UserId": "AIDAREVIEWER"}, {})
    ecr = add("ecr")
    if mode == "list_denied":
        ecr.add_client_error("describe_repositories", "AccessDeniedException", expected_params={})
    else:
        row = dict(BASE)
        if mode == "foreign_listing":
            row["repositoryArn"] = ARN.replace(ACCOUNT, "999999999999")
        response = {"repositories": [row]}
        if mode == "partial_pages":
            response["nextToken"] = "more"
        ecr.add_response("describe_repositories", response, {})
        if mode == "absent":
            ecr.add_client_error("get_repository_policy", "RepositoryPolicyNotFoundException",
                                 expected_params={"repositoryName": "app"})
        elif mode == "detail_denied":
            ecr.add_client_error("get_repository_policy", "AccessDeniedException",
                                 expected_params={"repositoryName": "app"})
        else:
            principal = {"AWS": ["arn:aws:iam::123456789012:role/ci"]} if mode == "private" else (
                "*" if mode in ("bare_wildcard", "singleton_statement") else
                {"AWS": "*"} if mode == "scalar_wildcard" else {"AWS": ["*"]})
            action = "ecr:BatchGetImage" if mode == "scalar_action" else None
            document = (json.dumps({"Statement": statement(principal, action=action)})
                        if mode == "singleton_statement" else policy(statement(principal, action=action)))
            returned = {"registryId": "999999999999" if mode == "foreign_detail" else ACCOUNT,
                        "repositoryName": "app",
                        "policyText": "{bad" if mode == "malformed_policy" else document}
            ecr.add_response("get_repository_policy", returned, {"repositoryName": "app"})
        ecr.add_client_error("get_lifecycle_policy", "LifecyclePolicyNotFoundException",
                             expected_params={"repositoryName": "app"})
    connector = {"provider": "aws", "scopes": [REGION],
                 "options": {"service_concurrency": 1, "retry_attempts": 1,
                             **({"max_pages": 1} if mode == "partial_pages" else {})}}
    captured = aws.collect(connector, ["ecr_repository"])
    scoped = [c for c in captured["collections"] if c["type"] == "ecr_repository" and c["scope"] == SCOPE]
    assert len(scoped) == 1
    statuses = [f["status"] for f in findings(captured)]
    if expected in {"PASS", "FAIL"}:
        assert statuses == [expected], (scoped[0]["items"][0].get("Policy"), findings(captured)[0]["evidence"])
    else:
        assert expected in statuses and not any(status in {"PASS", "FAIL"} for status in statuses)
    assert "selected-secret-must-not-leak" not in json.dumps(captured)


def test_raw_duplicate_ecr_rows_cannot_be_deduplicated_into_pass():
    row = {**BASE, "Policy": {"collection_status": "empty", "absent": True,
                             "error": {"code": "RepositoryPolicyNotFoundException"}}}
    duplicate = copy.deepcopy(row)
    captured = make_snapshot("aws", [SCOPE], [{"type": "ecr_repository", "scope": SCOPE,
        "service": "ecr", "status": "collected", "items": [row, duplicate]}])
    assert all(f["status"] != "PASS" for f in findings(captured))


def test_caller_partition_must_match_repository_arn_when_present():
    row = {**BASE, "Policy": {"collection_status": "empty", "absent": True, "error": {}}}
    captured = make_snapshot("aws", [SCOPE], [{"type": "ecr_repository", "scope": SCOPE,
        "service": "ecr", "status": "collected", "items": [row]}], metadata={
        "caller_identities": [{"Account": ACCOUNT,
            "Arn": f"arn:aws-us-gov:iam::{ACCOUNT}:user/reviewer"}]})
    assert all(f["status"] != "PASS" for f in findings(captured))


def test_seventeen_complete_empty_private_ecr_regions_have_no_false_pass_or_unknown():
    regions = [f"us-east-{n}" for n in range(1, 10)] + [f"us-west-{n}" for n in range(1, 9)]
    scopes = [f"{ACCOUNT}/{region}" for region in regions]
    collections = [{"type": "ecr_repository", "scope": scope, "service": "ecr",
                    "status": "empty", "items": []} for scope in scopes]
    report = evaluate_snapshot(make_snapshot("aws", scopes, collections), checks=[CID])
    statuses = [f["status"] for f in report["findings"] if f["check_id"] == CID]
    coverage = [row for row in report["coverage"] if row.get("check_id") == CID]
    assert statuses and set(statuses) == {"EMPTY"}
    assert len(coverage) == 17 and all(row["by_status"] == {"EMPTY": 1} for row in coverage)
