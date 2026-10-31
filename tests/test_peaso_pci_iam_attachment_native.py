"""Complete native IAM authorization details through the normal collector and engine."""
import json
from datetime import datetime, timezone

import boto3
import pytest
from botocore.stub import Stubber

from peaso.collectors import aws
from peaso.engine import evaluate_snapshot
from peaso.snapshot import seal

ACCOUNT = "123456789012"
REGION = "us-east-1"
ARN = f"arn:aws:iam::{ACCOUNT}:policy/Example"
CHECK = "aws.pci.iam.policy_attached_to_active_principal"
NOW = datetime(2026, 10, 18, tzinfo=timezone.utc)
DOC = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]})
TRUST = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": "*"}}]})
UNTRUSTED = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "sts:AssumeRole", "Principal": {"AWS": "*"}}]})


def policy(count):
    return {"PolicyName": "Example", "PolicyId": "ANPAEXAMPLEPOLICY1234", "Arn": ARN, "Path": "/",
            "DefaultVersionId": "v1", "AttachmentCount": count,
            "PolicyVersionList": [{"Document": DOC, "VersionId": "v1", "IsDefaultVersion": True}]}


def user(groups=(), attached=False):
    return {"UserName": "Alice", "UserId": "AIDAEXAMPLEUSER12345", "Arn": f"arn:aws:iam::{ACCOUNT}:user/Alice",
            "Path": "/", "CreateDate": NOW, "GroupList": list(groups),
            "AttachedManagedPolicies": [{"PolicyName": "Example", "PolicyArn": ARN}] if attached else []}


def group(attached=False):
    return {"GroupName": "Ops", "GroupId": "AGPAEXAMPLEGROUP1234", "Arn": f"arn:aws:iam::{ACCOUNT}:group/Ops",
            "Path": "/", "CreateDate": NOW,
            "AttachedManagedPolicies": [{"PolicyName": "Example", "PolicyArn": ARN}] if attached else []}


def role(attached=False, trust=TRUST):
    return {"RoleName": "Worker", "RoleId": "AROAEXAMPLEROLE12345", "Arn": f"arn:aws:iam::{ACCOUNT}:role/Worker",
            "Path": "/", "CreateDate": NOW, "AssumeRolePolicyDocument": trust,
            "AttachedManagedPolicies": [{"PolicyName": "Example", "PolicyArn": ARN}] if attached else []}


def run(monkeypatch, users=(), groups=(), roles=(), count=0, *, denied=False, truncated=False, mutate=None, mutate_snapshot=None):
    session = boto3.Session(aws_access_key_id="fixture-key", aws_secret_access_key="fixture-secret", region_name=REGION)
    sts = session.client("sts", region_name=REGION)
    iam = session.client("iam", region_name=REGION)
    sts_stub, iam_stub = Stubber(sts), Stubber(iam)
    sts_stub.add_response("get_caller_identity", {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/reviewer", "UserId": "AIDAREVIEWER"}, {})
    if denied:
        iam_stub.add_client_error("get_account_authorization_details", "AccessDenied", expected_params={})
    else:
        response = {"UserDetailList": list(users), "GroupDetailList": list(groups), "RoleDetailList": list(roles),
                    "Policies": [policy(count)], "IsTruncated": truncated}
        if mutate:
            mutate(response)
        if truncated:
            response["Marker"] = "next"
        iam_stub.add_response("get_account_authorization_details", response, {})
        if truncated:
            iam_stub.add_client_error("get_account_authorization_details", "AccessDenied", expected_params={"Marker": "next"})
        for item in users:
            name = item["UserName"]
            iam_stub.add_response("list_access_keys", {"AccessKeyMetadata": []}, {"UserName": name})
            iam_stub.add_client_error("get_login_profile", "NoSuchEntity", expected_params={"UserName": name})
            iam_stub.add_response("list_mfa_devices", {"MFADevices": []}, {"UserName": name})
    clients = {"sts": sts, "iam": iam}
    monkeypatch.setattr(aws.Requests, "client", lambda self, _session, service, region: clients[service])
    monkeypatch.setattr(aws, "_session", lambda auth, region: (session, "fixture"))
    with sts_stub, iam_stub:
        snapshot = aws.collect({"provider": "aws", "scopes": [ACCOUNT], "options": {"regions": [REGION], "service_concurrency": 1}},
                               ["iam_policy", "iam_user", "iam_group", "iam_role"])
        if mutate_snapshot:
            mutate_snapshot(snapshot)
            snapshot = seal(snapshot)
        rows = [r for r in evaluate_snapshot(snapshot, checks=[CHECK])["findings"]
                if r["check_id"] == CHECK and not r["resource_id"].startswith("inventory:")]
        if not denied:
            assert len(rows) == 1
            return rows[0]
        assert not rows or all(r["status"] == "UNKNOWN" for r in rows)
        return rows[0] if rows else None


@pytest.mark.parametrize("users,groups,roles,count,status", [
    ([], [], [], 0, "FAIL"),
    ([user(attached=True)], [], [], 1, "PASS"),
    ([user(groups=["Ops"])], [group(attached=True)], [], 1, "PASS"),
    ([], [group(attached=True)], [], 1, "FAIL"),
    ([], [], [role(attached=True)], 1, "PASS"),
    ([], [], [role(attached=True, trust=UNTRUSTED)], 1, "FAIL"),
])
def test_complete_configuration(monkeypatch, users, groups, roles, count, status):
    row = run(monkeypatch, users, groups, roles, count)
    assert row["status"] == status
    assert "activity_source" not in row["evidence"]


def test_denied_and_incomplete(monkeypatch):
    assert run(monkeypatch, denied=True) is None
    assert run(monkeypatch, users=[user(attached=True)], count=1, truncated=True)["status"] == "UNKNOWN"


def test_foreign_or_malformed(monkeypatch):
    assert run(monkeypatch, users=[user(attached=True)], count=2)["status"] == "UNKNOWN"
    foreign = user(attached=True)
    foreign["Arn"] = "arn:aws:iam::999999999999:user/Alice"
    assert run(monkeypatch, users=[foreign], count=1)["status"] == "UNKNOWN"
    assert run(monkeypatch, users=[user(groups=["Missing"])], groups=[group(attached=True)], count=1)["status"] == "UNKNOWN"


def test_native_field_guards_and_legacy_shape_cannot_bypass(monkeypatch):
    def edit(kind, field, value):
        def mutate(snapshot):
            row = next(c for c in snapshot["collections"] if c["type"] == kind)["items"][0]
            row[field] = value
        return mutate
    assert run(monkeypatch, users=[user(attached=True)], count=1,
               mutate_snapshot=edit("iam_policy", "AttachedUsers", []))["status"] == "PASS"
    def denied_group_list(snapshot):
        row = next(c for c in snapshot["collections"] if c["type"] == "iam_user")["items"][0]
        row["_coverage"] = {"GroupList": {"status": "denied"}}
    assert run(monkeypatch, users=[user(groups=["Ops"])], groups=[group(attached=True)], count=1,
               mutate_snapshot=denied_group_list)["status"] == "UNKNOWN"
    # Botocore rejects invalid response types, so exercise the malformed retained
    # field after normal native collection and before normal engine evaluation.
    def null_group_list(snapshot):
        row = next(c for c in snapshot["collections"] if c["type"] == "iam_user")["items"][0]
        row["GroupList"] = None
    assert run(monkeypatch, users=[user(groups=["Ops"])], groups=[group(attached=True)], count=1,
               mutate_snapshot=null_group_list)["status"] == "UNKNOWN"


def test_conditional_trust_is_not_asserted_as_effective_access(monkeypatch):
    conditional = json.dumps({"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
        "Principal": {"AWS": "*"}, "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-example"}}}]})
    assert run(monkeypatch, roles=[role(attached=True, trust=conditional)], count=1)["status"] == "UNKNOWN"


def trust(key, principal, action):
    return json.dumps({"Statement": [{"Effect": "Allow", "Action": action, "Principal": {key: principal}}]})


@pytest.mark.parametrize("key,principal,action", [
    ("AWS", "210987654321", "sts:AssumeRole"),
    ("AWS", "arn:aws:iam::210987654321:root", "sts:AssumeRole"),
    ("AWS", "arn:aws:iam::210987654321:role/team/Worker", "sts:AssumeRole"),
    ("AWS", "arn:aws:sts::210987654321:assumed-role/Worker/session", "sts:AssumeRole"),
    ("Service", "lambda.amazonaws.com", "sts:AssumeRole"),
    ("Service", "s3.ap-east-1.amazonaws.com", "sts:AssumeRole"),
    ("Federated", f"arn:aws:iam::{ACCOUNT}:saml-provider/Example", "sts:AssumeRoleWithSAML"),
    ("Federated", f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com", "sts:AssumeRoleWithWebIdentity"),
    ("Federated", "accounts.google.com", "sts:AssumeRoleWithWebIdentity"),
])
def test_documented_literal_principal_forms(monkeypatch, key, principal, action):
    row = run(monkeypatch, roles=[role(attached=True, trust=trust(key, principal, action))], count=1)
    assert row["status"] == "PASS"
    assert row["evidence"]["attachment_kind"] == "trusted_iam_role"


@pytest.mark.parametrize("key,principal,action", [
    ("AWS", "not-a-principal", "sts:AssumeRole"),
    ("AWS", "AROAXXXXXXXXXXXXXXXX", "sts:AssumeRole"),
    ("AWS", "arn:aws:iam::not-an-account:root", "sts:AssumeRole"),
    ("AWS", "arn:aws-cn:iam::210987654321:root", "sts:AssumeRole"),
    ("AWS", f"arn:aws:iam::{ACCOUNT}:group/Ops", "sts:AssumeRole"),
    ("AWS", f"arn:aws:iam::{ACCOUNT}:role//Worker", "sts:AssumeRole"),
    ("AWS", f"arn:aws:iam::{ACCOUNT}:role/Work*", "sts:AssumeRole"),
    ("Service", "not-a-service", "sts:AssumeRole"),
    ("Service", "*.amazonaws.com", "sts:AssumeRole"),
    ("Service", "bad-.amazonaws.com", "sts:AssumeRole"),
    ("Service", "s3.not-a-region.amazonaws.com", "sts:AssumeRole"),
    ("Federated", "not-a-provider", "sts:AssumeRoleWithWebIdentity"),
    ("Federated", "arn:aws:iam::210987654321:saml-provider/Other", "sts:AssumeRoleWithSAML"),
    ("Federated", f"arn:aws:iam::{ACCOUNT}:saml-provider/", "sts:AssumeRoleWithSAML"),
    ("Federated", f"arn:aws:iam::{ACCOUNT}:oidc-provider/not_a_hostname", "sts:AssumeRoleWithWebIdentity"),
])
def test_unrecognized_or_orphaned_principal_cannot_prove_attachment(monkeypatch, key, principal, action):
    assert run(monkeypatch, roles=[role(attached=True, trust=trust(key, principal, action))], count=1)["status"] == "UNKNOWN"


def test_mixed_principal_and_deny_ambiguity(monkeypatch):
    mixed = trust("AWS", ["210987654321", "AROAXXXXXXXXXXXXXXXX"], "sts:AssumeRole")
    assert run(monkeypatch, roles=[role(attached=True, trust=mixed)], count=1)["status"] == "UNKNOWN"
    allow_deny = json.dumps({"Statement": [
        {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": "210987654321"}},
        {"Effect": "Deny", "Action": "sts:AssumeRole", "Principal": {"AWS": "210987654321"}},
    ]})
    assert run(monkeypatch, roles=[role(attached=True, trust=allow_deny)], count=1)["status"] == "UNKNOWN"


# Service DNS names documented by AWS or observed as literal forms in a complete
# read-only GetAccountAuthorizationDetails response; parser shape only.
@pytest.mark.parametrize('principal', [
    'apidestinations.events.amazonaws.com',
    'ops.apigateway.amazonaws.com',
    'application-signals.cloudwatch.amazonaws.com',
    'streams.metrics.cloudwatch.amazonaws.com',
    'monitoring.rds.amazonaws.com',
    'replicator.lambda.amazonaws.com',
    'logger.cloudfront.amazonaws.com',
    'member.org.stacksets.cloudformation.amazonaws.com',
    'settings.replication.dynamodb.amazonaws.com',
    'malware-protection.guardduty.amazonaws.com',
    'runtime-identity.bedrock-agentcore.amazonaws.com',
])
def test_documented_multilabel_service_principal(monkeypatch, principal):
    row = run(monkeypatch, roles=[role(attached=True, trust=trust('Service', principal, 'sts:AssumeRole'))], count=1)
    assert row['status'] == 'PASS'
    assert row['evidence']['attachment_kind'] == 'trusted_iam_role'


@pytest.mark.parametrize('principal', [
    '*.events.amazonaws.com',
    'apidestinations.events.amazonaws.com.',
    'https://apidestinations.events.amazonaws.com',
    'apidestinations.events.amazonaws.com:443',
    'apidestinations..events.amazonaws.com',
    'apidestinations.events.amazonaws.com.cn',
    's3.not-a-region.amazonaws.com',
])
def test_multilabel_service_malformed_or_wrong_partition_unknown(monkeypatch, principal):
    row = run(monkeypatch, roles=[role(attached=True, trust=trust('Service', principal, 'sts:AssumeRole'))], count=1)
    assert row['status'] == 'UNKNOWN'


def _distinct_attached_role(name, trust_document):
    value = role(attached=True, trust=trust_document)
    value['RoleName'] = name
    value['RoleId'] = 'AROAEXAMPLE' + ('ORDER12345' if name == 'First' else 'ORDER67890')
    value['Arn'] = f'arn:aws:iam::{ACCOUNT}:role/{name}'
    return value


@pytest.mark.parametrize('opaque', [
    json.dumps({'Statement': [{'Effect': 'Allow', 'Action': 'sts:AssumeRole',
        'Principal': {'AWS': '*'}, 'Condition': {'StringEquals': {'aws:PrincipalOrgID': 'o-example'}}}]}),
    trust('AWS', 'AROAXXXXXXXXXXXXXXXX', 'sts:AssumeRole'),
])
@pytest.mark.parametrize('opaque_first', [True, False])
def test_distinct_opaque_role_cannot_hide_complete_trusted_role(monkeypatch, opaque, opaque_first):
    unknown_role = _distinct_attached_role('First', opaque)
    trusted_role = _distinct_attached_role('Second', TRUST)
    roles = [unknown_role, trusted_role] if opaque_first else [trusted_role, unknown_role]
    row = run(monkeypatch, roles=roles, count=2)
    assert row['status'] == 'PASS'
    assert row['evidence']['attachment_kind'] == 'trusted_iam_role'


def test_distinct_opaque_roles_without_witness_remain_unknown(monkeypatch):
    opaque = trust('AWS', 'AROAXXXXXXXXXXXXXXXX', 'sts:AssumeRole')
    roles = [_distinct_attached_role('First', opaque), _distinct_attached_role('Second', opaque)]
    assert run(monkeypatch, roles=roles, count=2)['status'] == 'UNKNOWN'


def test_distinct_complete_untrusted_roles_fail(monkeypatch):
    roles = [_distinct_attached_role('First', UNTRUSTED), _distinct_attached_role('Second', UNTRUSTED)]
    assert run(monkeypatch, roles=roles, count=2)['status'] == 'FAIL'
