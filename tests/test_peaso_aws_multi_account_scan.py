"""AWS multi-account scan end to end: per-account role sessions, scopes,
account-global reads, one denied account and cross-account trust.

Real boto3 sessions/clients answer from a `before-call` hook keyed by the
account the session's credentials belong to, so no request leaves the process
and concurrent reads are order-independent."""
import copy
import json
import threading
from collections import Counter
from datetime import datetime, timezone
from types import SimpleNamespace
from urllib.parse import quote

import pytest

boto3 = pytest.importorskip("boto3")

from peaso.collectors import aws
from peaso.engine import evaluate_snapshot
from peaso.snapshot import validate

SOURCE, A, B, C = "900000000009", "111111111111", "222222222222", "333333333333"
REGIONS = ["us-east-1", "eu-west-1"]
EXPIRED = datetime(2026, 1, 1, tzinfo=timezone.utc)
READONLY = "arn:aws:iam::aws:policy/ReadOnlyAccess"
CROSS_CHECK = "aws.claude_a.iam.role_readonly_not_cross_account"


def role(account, name, trusted_account):
    return {"RoleName": name, "RoleId": f"AROA{account}{name.upper()}", "Path": "/",
            "Arn": f"arn:aws:iam::{account}:role/{name}", "CreateDate": EXPIRED,
            # botocore decodes the URL-encoded JSON trust document of the wire format.
            "AssumeRolePolicyDocument": quote(json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{trusted_account}:root"}, "Action": "sts:AssumeRole"}]})),
            "RolePolicyList": [], "AttachedManagedPolicies": [{"PolicyName": "ReadOnlyAccess", "PolicyArn": READONLY}],
            "InstanceProfileList": [], "Tags": []}


# A's reader role trusts account B (cross-account); B's trusts only itself.
ROLES = {A: [role(A, "PartnerReader", B)], B: [role(B, "LocalReader", B)]}


class FakeAws:
    def __init__(self):
        self.calls = Counter()
        self.assumed = []
        self.lock = threading.Lock()
        self.clients = {}

    @staticmethod
    def account_of(session):
        from peaso.collectors.aws_request_pool import wrapper_root
        session = wrapper_root(session) or session
        key = session.get_credentials().get_frozen_credentials().access_key
        return SOURCE if key == "AKIASOURCEKEY0000000" else key.removeprefix("ASIA")[:12]

    def client(self, session, service, region, **_):
        account = self.account_of(session)
        with self.lock:
            key = (account, service, region)
            if key not in self.clients:
                client = boto3.Session(aws_access_key_id="x", aws_secret_access_key="y",
                                       region_name=region).client(service, region_name=region)
                client.meta.events.register_first(
                    "before-call.*.*", lambda model, params, **kw: self.answer(account, service, region, model.name, params.get("body")))
                self.clients[key] = client
            return self.clients[key]

    def answer(self, account, service, region, operation, params):
        with self.lock:
            self.calls[(account, service, region, operation)] += 1
        ok = lambda body: (SimpleNamespace(status_code=200), {**body, "ResponseMetadata": {"HTTPStatusCode": 200}})
        deny = (SimpleNamespace(status_code=403), {"Error": {"Code": "AccessDenied", "Message": "denied"},
                                                   "ResponseMetadata": {"HTTPStatusCode": 403}})
        if (service, operation) == ("sts", "GetCallerIdentity"):
            if account == SOURCE:
                return ok({"Account": SOURCE, "Arn": f"arn:aws:iam::{SOURCE}:user/scanner", "UserId": "AIDASOURCE"})
            return ok({"Account": account, "Arn": f"arn:aws:sts::{account}:assumed-role/Audit/peaso-read-only",
                       "UserId": f"AROA{account}:peaso-read-only"})
        if (service, operation) == ("sts", "AssumeRole"):
            target = params["RoleArn"].split(":")[4]
            with self.lock:
                self.assumed.append((account, params["RoleArn"], params.get("ExternalId")))
            if account != SOURCE or target == C:
                return deny
            return ok({"Credentials": {"AccessKeyId": f"ASIA{target}00000000", "SecretAccessKey": f"secret-{target}",
                                       "SessionToken": f"token-{target}", "Expiration": EXPIRED}})
        if (service, operation) == ("organizations", "ListAccounts"):
            return ok({"Accounts": [{"Id": x, "Arn": f"arn:aws:organizations::{SOURCE}:account/o-x/{x}", "Name": x,
                                     "Email": f"{x}@example.com", "Status": "ACTIVE", "State": "ACTIVE"}
                                    for x in (SOURCE, A, B, C)]})
        if account == SOURCE:
            return deny  # the source credential never reads member inventory
        if (service, operation) == ("ec2", "DescribeVpcs"):
            return ok({"Vpcs": [{"VpcId": f"vpc-{account}-{region}", "OwnerId": account, "CidrBlock": "10.0.0.0/16",
                                 "State": "available", "IsDefault": False}]})
        if (service, operation) == ("iam", "GetAccountAuthorizationDetails"):
            return ok({"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": copy.deepcopy(ROLES[account]), "Policies": [],
                       "IsTruncated": False})
        return deny


@pytest.fixture
def fake(monkeypatch):
    fake = FakeAws()
    monkeypatch.setattr(aws.Requests, "client", fake.client)
    for name in ("AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    return fake


def scan(mode):
    auth = {"method": "assume_role", "aws_access_key_id": "AKIASOURCEKEY0000000",
            "aws_secret_access_key": "source-secret", "external_id": "shared-external"}
    options = {"regions": list(REGIONS), "include_source_account": False}
    scopes = []
    if mode == "assume_roles":
        auth["assume_roles"] = [{"role_arn": f"arn:aws:iam::{A}:role/Audit", "external_id": "external-a"},
                                f"arn:aws:iam::{B}:role/Audit", f"arn:aws:iam::{C}:role/Audit"]
        scopes = [A, B, C]
    else:
        options["organization_role_name"] = "Audit"
    return aws.collect({"provider": "aws", "scopes": scopes, "auth": auth, "options": options}, ["vpc", "iam_role"])


def by_scope(snapshot, kind):
    return {c["scope"]: c for c in snapshot["collections"] if c["type"] == kind}


@pytest.mark.parametrize("mode", ["assume_roles", "organization"])
def test_multi_account_scan_isolates_accounts_regions_and_denied_member(fake, mode):
    snapshot = scan(mode)
    validate(snapshot)

    # Every member session is its own role, assumed from the source with its External ID.
    expected_ids = {A: "external-a" if mode == "assume_roles" else "shared-external", B: "shared-external", C: "shared-external"}
    assert sorted(fake.assumed) == sorted((SOURCE, f"arn:aws:iam::{x}:role/Audit", expected_ids[x]) for x in (A, B, C))
    assert sorted(i["Account"] for i in snapshot["metadata"]["caller_identities"]) == [A, B]
    assert [(e["account"], e["status"]) for e in snapshot["metadata"]["authentication_errors"]] == [(C, "denied")]

    # Regional resources land in their own account/Region scope, read with that account's session.
    vpcs = by_scope(snapshot, "vpc")
    for account in (A, B):
        for region in REGIONS:
            envelope = vpcs[f"{account}/{region}"]
            assert envelope["status"] == "collected"
            assert [(v["VpcId"], v["AccountId"], v["Region"]) for v in envelope["items"]] == [
                (f"vpc-{account}-{region}", account, region)]
    # Account-global inventory: once per account (not per Region, not once overall).
    roles = by_scope(snapshot, "iam_role")
    for account in (A, B):
        assert roles[f"{account}/global"]["status"] == "collected", roles[f"{account}/global"]
        assert [r["Arn"] for r in roles[f"{account}/global"]["items"]] == [r["Arn"] for r in ROLES[account]]
        reads = [k for k, n in fake.calls.items() for _ in range(n)
                 if k[0] == account and k[3] == "GetAccountAuthorizationDetails"]
        assert len(reads) == 1, reads
    assert not any(scope.endswith(region) for scope in roles for region in REGIONS)

    # The denied member is denied everywhere and nothing was read for it.
    for region in REGIONS:
        assert vpcs[f"{C}/{region}"]["status"] == "denied"
        assert vpcs[f"{C}/{region}"]["items"] == []
    assert roles[f"{C}/global"]["status"] == "denied"
    assert not any(k[0] == C and k[1] != "sts" for k in fake.calls)
    assert not any(k[0] == SOURCE and k[1] not in {"sts", "organizations"} for k in fake.calls)

    # Analysis: A's role trusted by B is reported cross-account in A's scope,
    # B's self-trusted role passes, and C is reported denied instead of passing.
    report = evaluate_snapshot(snapshot, checks=[CROSS_CHECK])
    results = {(f["scope"], f["status"]): f for f in report["findings"] if f["check_id"] == CROSS_CHECK}
    statuses = {(f["scope"].split("/")[0], f["status"]) for f in report["findings"] if f["check_id"] == CROSS_CHECK}
    assert (A, "FAIL") in statuses and (B, "PASS") in statuses, statuses
    assert {s for acct, s in statuses if acct == A} == {"FAIL"}
    assert {s for acct, s in statuses if acct == B} == {"PASS"}
    assert {s for acct, s in statuses if acct == C} == {"DENIED"}
    failing = next(f for (scope, status), f in results.items() if status == "FAIL")
    assert f"arn:aws:iam::{B}:root" in str(failing["evidence"])
