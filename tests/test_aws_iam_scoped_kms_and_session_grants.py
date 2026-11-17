"""Scoped KMS decrypt grants and port-forwarding-only Session Manager grants are not broad access."""
from __future__ import annotations

import peaso.engine  # noqa: F401  registers every native check
from peaso.checks import evaluate_check
from peaso.checks.claude_aws_a_iam import ACCOUNT, allow, doc, inline, pol

KEY = "arn:aws:kms:us-east-1:%s:key/d7a73257-0000-4000-8000-000000000001" % ACCOUNT
VIA_SECRETS = {"StringEquals": {"kms:ViaService": "secretsmanager.us-east-1.amazonaws.com"}}
SECRET = "arn:aws:secretsmanager:us-east-1:%s:secret:app-AbCdEf" % ACCOUNT
INLINE = "aws.claude_a.iam.role_inline_no_blocked_kms_actions"
MANAGED = "aws.claude_a.iam.custom_policy_no_blocked_kms_actions"
PRIVESC = "aws.claude_a.iam.prowler_role_inline_no_privilege_escalation"


def status(check, row):
    return evaluate_check(check, row, {})[0]


def kms(statement):
    return status(INLINE, inline("iam_role", statement)), status(MANAGED, pol(statement))


def test_kms_decrypt_on_one_key_passes():
    assert kms(allow("kms:Decrypt", KEY, Condition=VIA_SECRETS)) == ("PASS", "PASS")
    assert kms(allow(["kms:Decrypt", "kms:ReEncryptFrom"], [KEY, "arn:aws:kms:us-east-1:%s:alias/app" % ACCOUNT])) == ("PASS", "PASS")


def test_kms_decrypt_on_all_keys_fails():
    for resource in ("*", "arn:aws:kms:*:%s:key/*" % ACCOUNT, "arn:aws:kms:us-east-1:*:key/*", "arn:aws:kms:*:*:*"):
        assert kms(allow("kms:Decrypt", resource)) == ("FAIL", "FAIL"), resource
    # kms:ViaService alone still lets every key be used through that service.
    assert kms(allow("kms:Decrypt", "arn:aws:kms:*:%s:key/*" % ACCOUNT, Condition=VIA_SECRETS)) == ("FAIL", "FAIL")


def test_all_keys_with_pinned_encryption_context_passes():
    condition = dict(VIA_SECRETS, StringEquals={"kms:ViaService": "secretsmanager.us-east-1.amazonaws.com",
                                                "kms:EncryptionContext:SecretARN": SECRET})
    assert kms(allow("kms:Decrypt", "arn:aws:kms:us-east-1:%s:key/*" % ACCOUNT, Condition=condition)) == ("PASS", "PASS")
    one_secret = {"StringLike": {"kms:EncryptionContext:SecretARN": SECRET[:-6] + "??????"}}
    assert kms(allow("kms:Decrypt", "arn:aws:kms:us-east-1:%s:key/*" % ACCOUNT, Condition=one_secret)) == ("PASS", "PASS")
    # IfExists / ForAllValues also match ciphertexts that carry no encryption context.
    for loose in ({"StringEqualsIfExists": {"kms:EncryptionContext:SecretARN": SECRET}},
                  {"ForAllValues:StringEquals": {"kms:EncryptionContextKeys": "SecretARN"}}):
        assert kms(allow("kms:Decrypt", "*", Condition=loose)) == ("FAIL", "FAIL"), loose
    wildcard = {"StringLike": {"kms:EncryptionContext:SecretARN": "arn:aws:secretsmanager:*"}}
    assert kms(allow("kms:Decrypt", "*", Condition=wildcard)) == ("FAIL", "FAIL")


TUNNEL_DOC = "arn:aws:ssm:us-east-1:%s:document/app-*-database-tunnel" % ACCOUNT
INSTANCES = "arn:aws:ec2:us-east-1:%s:instance/*" % ACCOUNT
DOC_CHECK = {"BoolIfExists": {"ssm:SessionDocumentAccessCheck": "true"},
             "StringEquals": {"ssm:resourceTag/access": "database-tunnel"}}


def session_role(*statements):
    return status(PRIVESC, inline("iam_role", *statements))


def test_port_forwarding_only_session_is_not_escalation():
    assert session_role(allow("ssm:StartSession", INSTANCES, Condition=DOC_CHECK), allow("ssm:StartSession", TUNNEL_DOC)) == "PASS"
    aws_port = "arn:aws:ssm:us-east-1::document/AWS-StartPortForwardingSessionToRemoteHost"
    assert session_role(allow("ssm:StartSession", [INSTANCES, aws_port], Condition=DOC_CHECK)) == "PASS"


def test_shell_capable_session_is_escalation():
    # No document access check: Session Manager falls back to the default shell document.
    assert session_role(allow("ssm:StartSession", INSTANCES), allow("ssm:StartSession", TUNNEL_DOC)) == "FAIL"
    shell = "arn:aws:ssm:us-east-1::document/SSM-SessionManagerRunShell"
    assert session_role(allow("ssm:StartSession", INSTANCES, Condition=DOC_CHECK), allow("ssm:StartSession", shell)) == "FAIL"
    assert session_role(allow("ssm:StartSession", "*", Condition=DOC_CHECK)) == "FAIL"
    # The Session Manager preferences shell document lives in the customer's account.
    for account_shell in ("arn:aws:ssm:us-east-1:%s:document/SSM-SessionManagerRunShell" % ACCOUNT,
                          "arn:aws:ssm:*:%s:document/SSM-*" % ACCOUNT):
        assert session_role(allow("ssm:StartSession", INSTANCES, Condition=DOC_CHECK),
                            allow("ssm:StartSession", account_shell)) == "FAIL", account_shell
    any_doc = "arn:aws:ssm:us-east-1:%s:document/*" % ACCOUNT
    assert session_role(allow("ssm:StartSession", INSTANCES, Condition=DOC_CHECK), allow("ssm:StartSession", any_doc)) == "FAIL"
    assert session_role(allow("ssm:StartSession", [INSTANCES, any_doc], Condition=DOC_CHECK)) == "FAIL"
    # Other escalation combinations are unaffected by the session restriction.
    assert session_role(allow("ssm:StartSession", INSTANCES, Condition=DOC_CHECK), allow("ssm:StartSession", TUNNEL_DOC),
                        allow("iam:CreatePolicyVersion")) == "FAIL"
