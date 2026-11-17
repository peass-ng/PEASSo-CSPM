"""AWS Organizations SCP/RCP denials are an organization guardrail, not an IAM gap.

A Region-restriction SCP turns every read in a disabled Region into
AccessDenied. Those reads must not be reported as permission gaps of the
scanning identity, while real IAM denials in allowed Regions still are.
"""
import copy
import json

import pytest

from peaso.engine import evaluate_snapshot
from peaso.policy_denial import policy_from_message
from peaso.snapshot import SCHEMA_VERSION

ACCOUNT = "123456789012"
ALLOWED, BLOCKED = f"{ACCOUNT}/us-east-1", f"{ACCOUNT}/eu-west-1"
SCP_MESSAGE = (f"User: arn:aws:sts::{ACCOUNT}:assumed-role/peaso/scan is not authorized to perform: sqs:listqueues "
               f"on resource: arn:aws:sqs:eu-west-1:{ACCOUNT}: with an explicit deny in a service control policy: "
               "arn:aws:organizations::111111111111:policy/o-example/service_control_policy/p-example")


@pytest.mark.parametrize("message,policy", [
    (SCP_MESSAGE, "service_control_policy"),
    ("... is not authorized to perform: s3:GetObject because no service control policy allows the s3:GetObject action",
     "service_control_policy"),
    ("... with an explicit deny in a resource control policy", "resource_control_policy"),
    ("... because no identity-based policy allows the sqs:listqueues action", None),
    ("... with an explicit deny in an identity-based policy", None),
    (None, None),
])
def test_policy_type_is_read_from_the_denial_message(message, policy):
    assert policy_from_message(message) == policy


def _collection(kind, scope, status, error=None, items=()):
    row = {"type": kind, "scope": scope, "service": kind.split("_")[0], "status": status, "items": list(items),
           "account_id": ACCOUNT, "global": False}
    if error:
        row["error"] = error
    return row


def _evaluate(collections):
    snapshot = {"schema_version": SCHEMA_VERSION, "provider": "aws", "scopes": [ALLOWED, BLOCKED],
                "created_at": "2026-11-17T00:00:00Z", "metadata": {}, "collections": collections}
    return evaluate_snapshot(snapshot, checks=["aws.sqs.encryption"], include_not_applicable=True)


def _rows(report, level, scope, kind="sqs_queue"):
    return [row for row in report["coverage"] if row["level"] == level and row["scope"] == scope and row.get("type") == kind]


def test_scp_denied_region_is_blocked_by_policy_not_a_permission_gap():
    scp = {"code": "AccessDenied", "cause_status": "denied", "denied_by": "service_control_policy"}
    report = _evaluate([_collection("sqs_queue", ALLOWED, "empty"), _collection("sqs_queue", BLOCKED, "denied", scp)])
    collection, = _rows(report, "collection", BLOCKED)
    assert collection["status"] == "blocked_by_policy"
    assert collection["denied_by"] == "service_control_policy"
    assert collection["error_code"] == "AccessDenied"
    check, = _rows(report, "check", BLOCKED)
    assert check["status"] == "blocked_by_policy" and "DENIED" not in check["by_status"]
    blocked = [f for f in report["findings"] if f["scope"] == BLOCKED and f["check_id"] == "aws.sqs.encryption"]
    assert blocked and all(f["status"] == "NOT_APPLICABLE" for f in blocked)
    assert all(f["evidence"]["denied_by"] == "service_control_policy" for f in blocked)
    assert not any(f["status"] == "DENIED" for f in report["findings"])


def test_iam_denial_in_an_allowed_region_stays_denied():
    iam = {"code": "AccessDenied", "cause_status": "denied"}
    report = _evaluate([_collection("sqs_queue", ALLOWED, "denied", iam), _collection("sqs_queue", BLOCKED, "empty")])
    collection, = _rows(report, "collection", ALLOWED)
    assert collection["status"] == "denied" and "denied_by" not in collection
    check, = _rows(report, "check", ALLOWED)
    assert check["status"] == "denied"
    assert any(f["status"] == "DENIED" and f["scope"] == ALLOWED for f in report["findings"])


def test_reasonless_denial_is_attributed_only_where_the_guardrail_is_proven():
    """A service that omits the reason is the guardrail only in a scope that
    shows SCP denials and when the identity can read that inventory elsewhere."""
    scp = {"code": "AccessDeniedException", "denied_by": "service_control_policy"}
    bare = {"code": "AccessDeniedException"}
    report = _evaluate([
        _collection("sqs_queue", ALLOWED, "empty"), _collection("sqs_queue", BLOCKED, "denied", bare),
        _collection("sns_topic", BLOCKED, "denied", scp), _collection("sns_topic", ALLOWED, "empty"),
        # Denied everywhere: a real IAM gap even in the guarded Region.
        _collection("kms_key", ALLOWED, "denied", bare), _collection("kms_key", BLOCKED, "denied", bare)])
    inferred, = _rows(report, "collection", BLOCKED)
    assert inferred["status"] == "blocked_by_policy" and inferred["denied_by_inferred"] is True
    for scope in (ALLOWED, BLOCKED):
        gap, = _rows(report, "collection", scope, "kms_key")
        assert gap["status"] == "denied" and "denied_by" not in gap


def test_scope_without_any_scp_evidence_never_infers_a_guardrail():
    bare = {"code": "AccessDenied"}
    report = _evaluate([_collection("sqs_queue", ALLOWED, "empty"), _collection("sqs_queue", BLOCKED, "denied", bare)])
    collection, = _rows(report, "collection", BLOCKED)
    assert collection["status"] == "denied"


def _collect(monkeypatch, tmp_path, kinds, fail):
    """Run the real AWS collector with one fake client per (service, region)."""
    import tempfile
    boto3 = pytest.importorskip("boto3")
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))  # hermetic, fast image-scratch sweep
    from botocore.exceptions import ClientError
    from botocore.stub import Stubber
    from peaso.collectors import aws
    session = boto3.Session(aws_access_key_id="INERT", aws_secret_access_key="INERT", region_name="us-east-1")
    sts = session.client("sts", region_name="us-east-1")

    class Client:
        def __init__(self, service, region):
            self.real = session.client(service, region_name=region)
            self.meta = self.real.meta
            self.service, self.region = service, region

        def can_paginate(self, operation):
            return False

        def __getattr__(self, operation):
            def call(**kwargs):
                message = fail(self.service, self.region)
                if message is None:
                    return {}
                raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": message}}, operation)
            return call

    monkeypatch.setattr(aws, "_session", lambda auth, region: (session, "fixture"))
    monkeypatch.setattr(aws.Requests, "client",
                        lambda self, _session, service, region: sts if service == "sts" else Client(service, region))
    with Stubber(sts) as stub:
        stub.add_response("get_caller_identity", {"Account": ACCOUNT,
            "Arn": f"arn:aws:iam::{ACCOUNT}:user/reviewer", "UserId": "AIDAREVIEWER"}, {})
        return aws.collect({"provider": "aws", "scopes": [ACCOUNT], "auth": {"profile": "fixture"},
            "options": {"regions": ["us-east-1", "eu-west-1"], "retry_attempts": 1, "service_concurrency": 1,
                        "scope_concurrency": 1}}, kinds)


@pytest.mark.parametrize("kind", ["sqs_queue", "carrier_gateway"])
def test_collector_records_the_policy_type_without_the_message(monkeypatch, tmp_path, kind):
    snapshot = _collect(monkeypatch, tmp_path, [kind], lambda service, region: SCP_MESSAGE if region == "eu-west-1" else None)
    rows = {row["scope"]: row for row in snapshot["collections"] if row["type"] == kind}
    blocked = rows[BLOCKED]
    assert blocked["status"] == "denied" and blocked["error"]["denied_by"] == "service_control_policy"
    assert "AccessDeniedException" in (blocked["error"].get("code"), blocked["error"].get("cause_code"))
    assert "denied_by" not in (rows[ALLOWED].get("error") or {})
    serialized = json.dumps(snapshot)
    assert not any(fragment in serialized for fragment in ("o-example", "p-example", "not authorized"))
    # The persisted snapshot alone (no in-memory markers) yields the same classification.
    report = evaluate_snapshot(json.loads(serialized), checks=["aws.sqs.encryption"], include_not_applicable=True)
    coverage, = [row for row in report["coverage"] if row["level"] == "collection" and row["type"] == kind
                 and row["scope"] == BLOCKED]
    assert coverage["status"] == "blocked_by_policy" and coverage["error_code"] == "AccessDeniedException"


def test_wrapped_inventory_keeps_the_provider_denial_code(monkeypatch, tmp_path):
    """Network inventories used to report their own wrapper code, losing AccessDenied."""
    snapshot = _collect(monkeypatch, tmp_path, ["carrier_gateway"],
                        lambda service, region: "no identity-based policy allows the action")
    report = evaluate_snapshot(copy.deepcopy(snapshot), checks=["aws.sqs.encryption"], include_not_applicable=True)
    rows = [row for row in report["coverage"] if row["level"] == "collection" and row["type"] == "carrier_gateway"]
    assert rows and all(row["status"] == "denied" and row["error_code"] == "AccessDeniedException" for row in rows)
