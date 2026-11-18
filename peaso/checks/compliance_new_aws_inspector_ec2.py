"""Signed EC2 Inspector finding predicate over existing regional cached facts.

The evaluator never requests AWS data. A clean finding inventory is a PASS
only when the same account and Region have active Inspector EC2 coverage.
"""
from __future__ import annotations

from datetime import datetime
import re

from . import register, result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects
from .fixtures import CASES


CHECK_ID = "aws_inspector2_ec2_no_high_critical_findings"
SPEC_SHA256 = "19e3708f8d4caadf3c96f39850def20bc39256bb7aa3cdf7955e76cd4cd52bf1"
_SCOPE = re.compile(r"^([0-9]{12})/([a-z0-9-]+)$")
_FINDING_ARN = re.compile(r"^arn:aws(?:-us-gov|-cn)?:inspector2:([a-z0-9-]+):([0-9]{12}):finding/[a-f0-9]{32}$")
_SEVERITIES = {"INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNTRIAGED"}


def _scoped(index, kind, scope):
    envelopes = get(index, "collections", dict).get(kind)
    if (not isinstance(envelopes, list) or len(envelopes) != 1 or
            not isinstance(envelopes[0], dict) or
            envelopes[0].get("type") != kind or envelopes[0].get("scope") != scope):
        raise Unavailable("Inspector inventory scope authority unavailable: " + kind)
    return complete_items(index, kind)


@register(CHECK_ID, "aws", "hardening", "inspector2_finding",
          "EC2 has no active HIGH or CRITICAL Inspector findings", "high", "RA-5",
          "Remediate each active HIGH or CRITICAL EC2 finding and verify Inspector EC2 coverage before accepting a clean result.",
          target="scope", dependencies=["inspector2_finding", "inspector2_account_status"])
def ec2_no_high_critical_findings(item, index):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "aws":
        raise Unavailable("Inspector provider authority unavailable")
    scope = get(context, "scope", str)
    identity = _SCOPE.fullmatch(scope)
    if identity is None:
        raise Unavailable("Inspector regional scope unavailable")
    captured_at = get(context, "created_at", str)
    try:
        instant = datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Unavailable("Inspector snapshot capture time malformed") from exc
    if instant.tzinfo is None:
        raise Unavailable("Inspector snapshot capture time lacks zone")

    findings = _scoped(index, "inspector2_finding", scope)
    bad, seen = [], set()
    for finding in findings:
        arn = get(finding, "findingArn", str)
        parsed_arn = _FINDING_ARN.fullmatch(arn)
        if (not parsed_arn or parsed_arn.group(1) != identity.group(2) or
                parsed_arn.group(2) != identity.group(1) or arn in seen):
            raise Unavailable("Inspector finding identity missing or duplicated")
        seen.add(arn)
        if get(finding, "status", str) != "ACTIVE":
            raise Unavailable("finding contradicts ACTIVE ListFindings filter")
        if get(finding, "awsAccountId", str) != identity.group(1):
            raise Unavailable("Inspector finding account differs from assessed scope")
        resources = list_of_objects(get(finding, "resources", list))
        if not resources:
            raise Unavailable("Inspector finding resources unavailable")
        types = {get(resource, "type", str) for resource in resources}
        if "AWS_EC2_INSTANCE" not in types:
            continue
        severity = get(finding, "severity", str)
        if severity not in _SEVERITIES:
            raise Unavailable("Inspector EC2 finding severity unrecognized")
        if severity in {"HIGH", "CRITICAL"}:
            bad.append(arn)
    if bad:
        return result(True, scope=scope, captured_at=captured_at,
                      active_high_critical_ec2_findings=sorted(bad),
                      semantics="Complete ACTIVE findings snapshot; finding details or remediation not inferred")

    statuses = _scoped(index, "inspector2_account_status", scope)
    if len(statuses) != 1:
        raise Unavailable("Inspector account status not unique in Region")
    state = statuses[0]
    if (get(state, "accountId", str) != identity.group(1) or
            get(state, "id", str) != f"inspector2/{identity.group(1)}/{identity.group(2)}"):
        raise Unavailable("Inspector account status differs from assessed scope")
    account_status = get(state, "State.status", str)
    ec2_status = get(state, "ResourceState.ec2.status", str)
    known = {"ENABLED", "DISABLED", "ENABLING", "DISABLING", "SUSPENDING", "SUSPENDED"}
    if account_status not in known or ec2_status not in known:
        return unknown("Unrecognized Inspector coverage status", account_status=account_status, ec2_status=ec2_status)
    if "DISABLED" in (account_status, ec2_status):
        return "NOT_APPLICABLE", {"reason": "Inspector EC2 scanning is disabled; absence of findings is not evidence of clean instances",
                                  "scope": scope, "account_status": account_status, "ec2_status": ec2_status}
    if account_status != "ENABLED" or ec2_status != "ENABLED":
        return unknown("Inspector EC2 coverage is not active; clean findings cannot be established",
                       scope=scope, account_status=account_status, ec2_status=ec2_status)
    return result(False, scope=scope, captured_at=captured_at,
                  active_high_critical_ec2_findings=[],
                  semantics="Complete ACTIVE finding inventory and enabled EC2 account coverage")


def _fixture(finding_rows, *, state="ENABLED"):
    scope = "123456789012/us-east-1"
    account = {"id": "inspector2/123456789012/us-east-1", "accountId": "123456789012",
               "State": {"status": "ENABLED"}, "ResourceState": {"ec2": {"status": state}}}
    return {"context": {"provider": "aws", "scope": scope,
                        "created_at": "2026-10-12T00:00:00+00:00"}, "collections": {
        "inspector2_finding": [{"type": "inspector2_finding", "scope": scope,
                                "status": "collected", "items": finding_rows}],
        "inspector2_account_status": [{"type": "inspector2_account_status", "scope": scope,
                                       "status": "collected", "items": [account]}]},
        "inspector2_finding": [{"type": "inspector2_finding", "scope": scope, "data": row}
                               for row in finding_rows],
        "inspector2_account_status": [{"type": "inspector2_account_status", "scope": scope,
                                       "data": account}]}


_bad = {"findingArn": "arn:aws:inspector2:us-east-1:123456789012:finding/ffffffffffffffffffffffffffffffff",
        "awsAccountId": "123456789012", "status": "ACTIVE", "severity": "HIGH",
        "resources": [{"type": "AWS_EC2_INSTANCE", "id": "i-0123456789abcdef0"}]}
CASES[CHECK_ID] = {"pass": {}, "pass_index": _fixture([]),
                   "fail": {}, "fail_index": _fixture([_bad]),
                   "unknown": {}, "unknown_index": _fixture([], state="ENABLING")}
