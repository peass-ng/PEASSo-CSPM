"""Exercise the AWS federated trust path used by live analyzer acceptance."""

from peaso.analysis.trust import aws_federated_trust
from peaso.snapshot import make_snapshot, resources


def test_oidc_role_is_reviewed_without_analyzer_crash():
    account = "111122223333"
    scope = f"{account}/us-east-1"
    provider = f"arn:aws:iam::{account}:oidc-provider/token.actions.githubusercontent.com"
    role = {
        "RoleName": "reviewed-role",
        "Arn": f"arn:aws:iam::{account}:role/reviewed-role",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Federated": provider},
                "Action": "sts:AssumeRoleWithWebIdentity",
            }],
        },
    }
    snapshot = make_snapshot("aws", [scope], [{
        "type": "iam_role", "scope": scope, "service": "iam",
        "status": "collected", "items": [role],
    }], created_at="2026-10-10T00:00:00+00:00")

    status, _, evidence = aws_federated_trust(snapshot, resources(snapshot)[0])

    assert status == "MANUAL"
    assert evidence["federated_trusts"]
