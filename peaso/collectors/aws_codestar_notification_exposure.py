"""CodeStar notification rule targets without event payload or build content."""
import re

KIND = "codestar_notification_rule"
SPECS = {KIND: ("codestar-notifications", "list_notification_rules", "NotificationRules")}
NATIVE_IDS = {KIND: "Arn"}
READ_ACTIONS = {("codestar-notifications", "describe_notification_rule")}


def collect(requests, session, region, account):
    from .aws import ReadResult

    listing = requests.pages(session, "codestar-notifications", region,
                             "list_notification_rules", "NotificationRules")
    if listing.status not in ("collected", "empty"):
        return ReadResult([], listing.status, listing.error)
    rows, failures, seen = [], [], set()
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    arn_pattern = re.compile(r"arn:" + partition + r":codestar-notifications:" + re.escape(region) +
                             r":" + re.escape(account) + r":notificationrule/[A-Za-z0-9-]+\Z")
    for listed in listing.items:
        arn = listed.get("Arn") if isinstance(listed, dict) else None
        if not isinstance(arn, str) or not arn_pattern.fullmatch(arn) or arn in seen:
            failures.append("notification_rule_identity_unresolved")
            continue
        seen.add(arn)
        response = requests.detail(session, "codestar-notifications", region,
                                   "describe_notification_rule", Arn=arn)
        if response.get("collection_status") != "collected" or response.get("Arn") != arn:
            failures.append("notification_rule_detail_unavailable")
            continue
        targets = response.get("Targets")
        status = response.get("Status")
        if not isinstance(targets, list) or status not in ("ENABLED", "DISABLED"):
            failures.append("notification_rule_targets_unresolved")
            continue
        projected = []
        for target in targets:
            if (not isinstance(target, dict) or not isinstance(target.get("TargetAddress"), str) or
                    not isinstance(target.get("TargetType"), str) or
                    target.get("TargetStatus") not in ("PENDING", "ACTIVE", "UNREACHABLE", "INACTIVE", "DEACTIVATED")):
                failures.append("notification_target_malformed")
                continue
            projected.append({key: target[key] for key in ("TargetType", "TargetAddress", "TargetStatus")})
        rows.append({"Arn": arn, "Status": status, "Targets": projected,
                     "TargetCollectionStatus": "partial" if len(projected) != len(targets) else "collected"})
    status = "partial" if rows and failures else "malformed" if failures else "collected" if rows else "empty"
    return ReadResult(rows, status, {"code": failures[0]} if failures else None)


FETCHERS = {KIND: collect}
