"""Bind organization shadow trails to a successful audited-account discovery."""
import re
from .facts import Unavailable, get


def owner(item, index, arn, account, home):
    match = re.fullmatch(r"arn:(aws|aws-us-gov|aws-cn):cloudtrail:" + re.escape(home) + r":([0-9]{12}):trail/[^/]+", arn)
    if match is None:
        raise Unavailable("CloudTrail ARN does not match its native home Region")
    if match[2] == account:
        return account
    proof = item.get("_account_trail_binding")
    if (item.get("IsOrganizationTrail") is not True or item.get("AccountId") != account
            or not isinstance(proof, dict) or proof.get("caller_account_id") != account
            or proof.get("trail_arn") != arn or proof.get("include_shadow_trails") is not True
            or proof.get("identity_operation") != "sts:GetCallerIdentity"
            or proof.get("describe_operation") != "cloudtrail:DescribeTrails"
            or proof.get("capture_observed_at") != get(index, "context.created_at", str)):
        raise Unavailable("organization trail native account binding unavailable")
    return match[2]
