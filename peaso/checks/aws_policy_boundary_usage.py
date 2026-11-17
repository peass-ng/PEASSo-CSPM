"""Managed policies used only as permissions boundaries grant nothing.

A permissions boundary caps the identity-based permissions of the users and
roles it is set on; it never adds a permission. A customer-managed policy whose
IAM ``PermissionsBoundaryUsageCount`` is positive and whose permission-policy
``AttachmentCount`` is zero therefore cannot be an administrator or wildcard
grant, however broad its Allow statements are (boundaries usually Allow "*" on
"*" and subtract with Deny). Checks that judge what a managed policy *grants*
must not fail it; checks about whether a policy is *used* keep their own logic.
"""
from __future__ import annotations

POLICY_KINDS = frozenset({"iam_policy", "iam_customer_policy", "iam_managed_policy"})

# Managed-policy checks that judge attachment or use rather than granted access.
USAGE_CHECKS = frozenset({
    "aws.claude_a.iam.aws_managed_policy_attached_to_role",
    "aws.claude_a.iam.custom_policy_attached_to_role",
    "aws.claude_a.iam.policy_in_use",
    "aws.claude_a.iam.custom_policy_in_use",
    "aws.claude_a.iam.cloudshell_full_access_not_attached",
    "aws.pci.iam.policy_attached_to_active_principal",
})


def _count(item, key):
    value = item.get(key) if isinstance(item, dict) else None
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def boundary_only(item):
    """Return the boundary usage count when the policy is only a boundary, else None."""
    boundary, attached = _count(item, "PermissionsBoundaryUsageCount"), _count(item, "AttachmentCount")
    return boundary if boundary and attached == 0 else None


def apply(check_id, kind, item, status, evidence):
    """Turn a grant-check verdict on a boundary-only policy into NOT_APPLICABLE."""
    if kind not in POLICY_KINDS or check_id in USAGE_CHECKS or status in ("NOT_APPLICABLE", "EMPTY", "DENIED"):
        return status, evidence
    count = boundary_only(item)
    if count is None:
        return status, evidence
    return "NOT_APPLICABLE", {
        "reason": "Policy is used only as a permissions boundary; a boundary limits permissions and grants none.",
        "permissions_boundary_usage_count": count, "permissions_policy_attachment_count": 0,
        "native_result": {"status": status, "evidence": evidence}}
