"""Isolated signed AWS swarm 39 evaluator tests."""
from __future__ import annotations

import copy

import pytest

from peaso.checks import CHECKS, evaluate_check
from peaso.checks import compliance_new_sw39 as sw


SCOPE = "123456789012/us-east-1"
ACCOUNT = "123456789012"
BASE_POLICY = {"status": "collected", "scope": SCOPE}


@pytest.fixture(scope="module", autouse=True)
def cleanup_registry():
    yield
    CHECKS[:] = [check for check in CHECKS if check.id not in sw.SPECS]


def facts(kind, rows, *, extra=None, policy=None, status=None, scope=SCOPE):
    kinds = {kind: rows, **(extra or {})}
    index = {"context": {"provider": "aws", "scope": scope,
                         "metadata": {"compliance_policy": {**BASE_POLICY, **(policy or {})}}},
             "collections": {}}
    for name, batch in kinds.items():
        state = status if name == kind and status is not None else ("collected" if batch else "empty")
        index["collections"][name] = [{"type": name, "scope": scope, "status": state,
                                        "items": copy.deepcopy(batch)}]
        index[name] = [{"type": name, "scope": scope, "data": copy.deepcopy(row)} for row in batch]
    return index


def check(check_id, row, index):
    return evaluate_check(check_id, row, index)[0]


def test_waf_regional_associations():
    cid = "aws_nist_waf_web_acl_resource_associated"
    row = {"WebACLId": "acl-1", "WebACL": {"WebACLId": "acl-1"},
           "ResourceArns": {"collection_status": "collected", "ByResourceType":
                            {"APPLICATION_LOAD_BALANCER": "collected", "API_GATEWAY": "collected"},
                            "ResourceArns": [f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:loadbalancer/app/a/b"]}}
    assert check(cid, row, facts("wafregional_web_acl", [row])) == "PASS"
    empty = copy.deepcopy(row)
    empty["ResourceArns"]["ResourceArns"] = []
    assert check(cid, empty, facts("wafregional_web_acl", [empty])) == "FAIL"
    partial = copy.deepcopy(row)
    partial["ResourceArns"]["collection_status"] = "partial"
    assert check(cid, partial, facts("wafregional_web_acl", [partial])) == "UNKNOWN"
    assert check(cid, row, facts("wafregional_web_acl", [row], status="partial")) == "UNKNOWN"


def test_detective_ai_graph():
    cid = "aws_detective_ai_account_graph_enabled"
    subject = {"scope": SCOPE}
    graph = {"Arn": f"arn:aws:detective:us-east-1:{ACCOUNT}:graph/abc", "CreatedTime": "2026-01-01T00:00:00Z"}
    assert check(cid, subject, facts("detective_graph", [graph], policy={"ai_workload": True})) == "PASS"
    assert check(cid, subject, facts("detective_graph", [], policy={"ai_workload": True})) == "FAIL"
    assert check(cid, subject, facts("detective_graph", [], policy={"ai_workload": False})) == "NOT_APPLICABLE"
    assert check(cid, subject, facts("detective_graph", [], status="partial", policy={"ai_workload": True})) == "UNKNOWN"
    assert check(cid, subject, facts("detective_graph", [], policy={})) == "UNKNOWN"


def test_sagemaker_domain_images():
    cid = "aws_sagemaker_approved_image_restriction"
    row = {"DomainArn": f"arn:aws:sagemaker:us-east-1:{ACCOUNT}:domain/d-abc",
           "DefaultUserSettings": {"CustomImages": [{"ImageName": "approved"}],
                                   "JupyterLabAppSettings": {"CustomImages": []}},
           "DefaultSpaceSettings": {"JupyterLabAppSettings": {"CustomImages": []}}}
    policy = {"approved_sagemaker_image_names": ["approved"]}
    assert check(cid, row, facts("sagemaker_domain", [row], policy=policy)) == "PASS"
    bad = copy.deepcopy(row)
    bad["DefaultSpaceSettings"]["JupyterLabAppSettings"]["CustomImages"] = [{"ImageName": "unapproved"}]
    assert check(cid, bad, facts("sagemaker_domain", [bad], policy=policy)) == "FAIL"
    assert check(cid, row, facts("sagemaker_domain", [row])) == "UNKNOWN"
    malformed = copy.deepcopy(row)
    malformed["DefaultUserSettings"]["CustomImages"] = "approved"
    assert check(cid, malformed, facts("sagemaker_domain", [malformed], policy=policy)) == "UNKNOWN"


def test_budgets_stop_action():
    cid = "aws_budgets_stop_action"
    doc = f"arn:aws:ssm:us-east-1:{ACCOUNT}:document/StopApproved"
    role = f"arn:aws:iam::{ACCOUNT}:role/StopRole"
    row = {"ActionId": "act-1", "BudgetName": "dev-budget", "ActionStatus": "STANDBY",
           "ActionType": "RUN_SSM_DOCUMENTS", "ActionThreshold":
           {"ActionThresholdValue": 90, "ActionThresholdType": "PERCENTAGE"},
           "SsmActionDefinition": {"DocumentArn": doc}, "TargetRoleArns": [role]}
    policy = {"approved_stop_document_arns": [doc], "approved_stop_target_role_arns": [role],
              "budget_action_thresholds": {"dev-budget": {"ActionThresholdType": "PERCENTAGE", "ActionThresholdValue": 90}}}
    assert check(cid, row, facts("budget_action", [row], policy=policy)) == "PASS"
    bad = {**row, "ActionStatus": "EXECUTION_FAILURE"}
    assert check(cid, bad, facts("budget_action", [bad], policy=policy)) == "FAIL"
    other = {**row, "ActionId": "act-2", "ActionType": "APPLY_IAM_POLICY"}
    together = facts("budget_action", [other, row], policy=policy)
    assert check(cid, other, together) == "PASS"
    assert check(cid, row, facts("budget_action", [row])) == "UNKNOWN"
    assert check(cid, row, facts("budget_action", [row], status="denied", policy=policy)) == "UNKNOWN"


def test_public_alb_listener_tls():
    cid = "aws_service_transport_peer_authentication"
    lb_arn = f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:loadbalancer/app/a/b"
    arn = f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:listener/app/a/b/c"
    cert = f"arn:aws:acm:us-east-1:{ACCOUNT}:certificate/abc"
    row = {"ListenerArn": arn, "LoadBalancerArn": lb_arn, "Protocol": "HTTPS",
           "Certificates": [{"CertificateArn": cert}], "SslPolicy": "approved-tls"}
    lb = {"LoadBalancerArn": lb_arn, "Type": "application", "Scheme": "internet-facing"}
    policy = {"approved_acm_certificate_arns": [cert], "approved_tls_policies": ["approved-tls"]}
    index = lambda r, l=lb, p=policy: facts("elbv2_listener", [r], extra={"load_balancer": [l]}, policy=p)
    assert check(cid, row, index(row)) == "PASS"
    http = {**row, "Protocol": "HTTP"}
    assert check(cid, http, index(http)) == "FAIL"
    internal = {**lb, "Scheme": "internal"}
    assert check(cid, row, index(row, internal)) == "NOT_APPLICABLE"
    assert check(cid, row, index(row, p={})) == "UNKNOWN"
    malformed = {**row, "Certificates": "bad"}
    assert check(cid, malformed, index(malformed)) == "UNKNOWN"


def test_siem_subscriptions():
    cid = "aws_siem_log_delivery"
    subject = {"scope": SCOPE}
    siem = f"arn:aws:firehose:us-east-1:{ACCOUNT}:deliverystream/siem"
    dest = f"arn:aws:logs:us-east-1:{ACCOUNT}:destination:siem"
    destinations = [{"arn": dest, "targetArn": siem}]
    subscription = {"logGroupName": "/security", "subscriptionFilters":
                    [{"destinationArn": dest, "filterPattern": ""}]}
    policy = {"approved_siem_destination_arn": siem, "designated_log_groups": ["/security"]}
    index = lambda sub, p=policy: facts("log_destination", destinations,
                                      extra={"log_subscription_filter": [sub]}, policy=p)
    assert check(cid, subject, index(subscription)) == "PASS"
    bad = {**subscription, "subscriptionFilters": []}
    assert check(cid, subject, index(bad)) == "FAIL"
    assert check(cid, subject, index(subscription, p={})) == "UNKNOWN"
    missing = facts("log_destination", destinations, policy=policy)
    assert check(cid, subject, missing) == "UNKNOWN"


def test_development_backup_exact_selection():
    cid = "aws_development_backup_assignment"
    arn = f"arn:aws:ec2:us-east-1:{ACCOUNT}:volume/vol-1"
    plan = {"BackupPlanId": "plan-1", "Rules": [{"ScheduleExpression": "cron(0 5 ? * * *)"}]}
    row = {"id": "plan-1/sel-1", "BackupPlanId": "plan-1", "SelectionId": "sel-1",
           "Resources": [arn], "NotResources": [], "ListOfTags": [], "Conditions": {}}
    policy = {"development_resource_arns": [arn]}
    index = lambda r, p=policy: facts("backup_selection", [r], extra={"backup_plan": [plan]}, policy=p)
    assert check(cid, row, index(row)) == "PASS"
    bad = {**row, "Resources": []}
    assert check(cid, bad, index(bad)) == "FAIL"
    assert check(cid, row, index(row, p={"development_resource_arns": []})) == "NOT_APPLICABLE"
    assert check(cid, row, index(row, p={})) == "UNKNOWN"
    tags = {**row, "ListOfTags": [{"ConditionKey": "env", "ConditionValue": "dev"}]}
    assert check(cid, tags, index(tags)) == "UNKNOWN"


def test_codecommit_independent_premerge_review():
    cid = "aws.pci.codecommit.pr_review_approval"
    author = f"arn:aws:iam::{ACCOUNT}:user/author"
    reviewer = f"arn:aws:iam::{ACCOUNT}:user/reviewer"
    row = {"pullRequestId": "1", "pullRequestStatus": "CLOSED", "authorArn": author,
           "pullRequestTargets": [{"repositoryName": "repo", "mergeMetadata":
                                   {"IsMerged": True, "MergedAt": "2026-01-02T00:00:00Z"}}],
           "ApprovalStates": [{"UserArn": reviewer, "ApprovalState": "APPROVE"}],
           "ApprovalEvents": [{"UserArn": reviewer, "ApprovalState": "APPROVE",
                               "eventDate": "2026-01-01T00:00:00Z"}]}
    policy = {"security_reviewer_arns": [reviewer]}
    index = lambda r, p=policy: facts("codecommit_pull_request", [r], policy=p)
    assert check(cid, row, index(row)) == "PASS"
    late = copy.deepcopy(row)
    late["ApprovalEvents"][0]["eventDate"] = "2026-01-03T00:00:00Z"
    assert check(cid, late, index(late)) == "FAIL"
    revoked = copy.deepcopy(row)
    revoked["ApprovalEvents"].append({"UserArn": reviewer, "ApprovalState": "REVOKE",
                                      "eventDate": "2026-01-01T12:00:00Z"})
    assert check(cid, revoked, index(revoked)) == "FAIL"
    unmerged = copy.deepcopy(row)
    unmerged["pullRequestTargets"][0]["mergeMetadata"]["IsMerged"] = False
    assert check(cid, unmerged, index(unmerged)) == "NOT_APPLICABLE"
    assert check(cid, row, index(row, p={})) == "UNKNOWN"
    missing = copy.deepcopy(row)
    del missing["ApprovalEvents"]
    assert check(cid, missing, index(missing)) == "UNKNOWN"


def test_unrestricted_resource_policy():
    cid = "aws_cis_aws_resource_policy_unrestricted_principal"
    arn = f"arn:aws:s3:us-east-1:{ACCOUNT}:bucket/example"
    row = {"ResourceArn": arn, "Policy": {"Statement":
           [{"Sid": "one", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": arn,
             "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-approved"}}}]}}
    index = lambda r: facts("aws_resource_policy", [r])
    assert check(cid, row, index(row)) == "PASS"
    bad = copy.deepcopy(row)
    bad["Policy"]["Statement"][0]["Condition"] = {"Bool": {"aws:SecureTransport": "true"}}
    assert check(cid, bad, index(bad)) == "FAIL"
    missing = copy.deepcopy(row)
    del missing["Policy"]
    assert check(cid, missing, index(missing)) == "UNKNOWN"
    denied = copy.deepcopy(bad)
    denied["Policy"]["Statement"].append({"Effect": "Deny", "Principal": "*"})
    assert check(cid, denied, index(denied)) == "UNKNOWN"


@pytest.mark.parametrize("check_id", list(sw.SPECS))
def test_signed_metadata_digest_and_missing_collection(check_id):
    kind = sw.SPECS[check_id][0]
    assert check(check_id, {}, facts(kind, [])) == "UNKNOWN"


@pytest.mark.parametrize("check_id", list(sw.SPECS))
def test_foreign_scope_and_malformed_envelope_are_unknown(check_id):
    subject = {"scope": SCOPE} if check_id in {
        "aws_detective_ai_account_graph_enabled", "aws_siem_log_delivery"} else {}
    kind = sw.SPECS[check_id][0]
    index = facts(kind, [], scope="123456789012/eu-west-1")
    index["context"]["scope"] = SCOPE
    assert check(check_id, subject, index) == "UNKNOWN"
    index = facts(kind, [])
    index["collections"][kind][0]["items"] = "malformed"
    assert check(check_id, subject, index) == "UNKNOWN"
