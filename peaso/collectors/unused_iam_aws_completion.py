"""Read-only, organization-wide Identity Center permission-set consumers.

This is an opt-in helper until the AWS collector registers its own resource type.
It deliberately does not reuse the account-local identity_center authentication check.
"""
from __future__ import annotations

import re

ACCOUNT = re.compile(r"[0-9]{12}\Z")
INSTANCE = re.compile(r"arn:(aws(?:-[a-z0-9]+)*):sso:::instance/((?:sso)?ins-[A-Za-z0-9.-]{16})\Z")
PRINCIPAL = re.compile(r"(?:[0-9a-f]{10}-)?[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")
GOOD = {"collected", "empty"}
FILTERS = ("LATEST_PERMISSION_SET_PROVISIONED", "LATEST_PERMISSION_SET_NOT_PROVISIONED")
READ_ACTIONS = {
    ("organizations", "list_accounts"),
    ("sso-admin", "list_instances"),
    ("sso-admin", "list_permission_sets"),
    ("sso-admin", "list_accounts_for_provisioned_permission_set"),
    ("sso-admin", "list_account_assignments"),
}
SPECS = {"aws_identity_center_permission_set_consumer": ("sso-admin", "list_instances", "Instances")}
NATIVE_IDS = {"aws_identity_center_permission_set_consumer": "PermissionSetArn"}


def _problem(read, operation):
    return {"status": read.status, "reason": (read.error or {}).get("code", operation + "_incomplete")}


def _accounts(read):
    if read.status not in GOOD:
        return None, _problem(read, "organizations_list_accounts")
    found = set()
    for row in read.items:
        if not isinstance(row, dict) or not ACCOUNT.fullmatch(str(row.get("Id", ""))) or row["Id"] in found:
            return None, {"status": "malformed", "reason": "organization_account_invalid"}
        found.add(row["Id"])
    if not found:
        return None, {"status": "not_collected", "reason": "organization_account_universe_empty"}
    return found, None


def _account_ids(read, allowed, operation):
    if read.status not in GOOD:
        return None, _problem(read, operation)
    values = read.items
    if any(not isinstance(value, str) or not ACCOUNT.fullmatch(value) for value in values):
        return None, {"status": "malformed", "reason": operation + "_account_invalid"}
    if len(set(values)) != len(values) or not set(values) <= allowed:
        return None, {"status": "malformed", "reason": operation + "_account_binding_invalid"}
    return set(values), None


def collect(requests, session, region):
    """Return complete per-set rows; the caller supplies the Identity Center home region.

    ``requests.pages`` enforces native NextToken completion and configured limits.
    The Organizations read is required to check assignments even where a set has
    no successful provisioning. An organization instance outside its home region
    therefore yields unresolved evidence rather than a fabricated empty result.
    """
    org = requests.pages(session, "organizations", region, "list_accounts", "Accounts")
    accounts, error = _accounts(org)
    if error:
        return {"status": error["status"], "reason": error["reason"], "items": []}
    instances = requests.pages(session, "sso-admin", region, "list_instances", "Instances")
    if instances.status not in GOOD:
        error = _problem(instances, "list_instances")
        return {**error, "items": []}
    if not instances.items:
        return {"status": "not_collected", "reason": "identity_center_home_region_unresolved", "items": []}
    rows, seen_instances = [], set()
    partition = session.get_partition_for_region(region)
    for instance in instances.items:
        arn = instance.get("InstanceArn") if isinstance(instance, dict) else None
        match = INSTANCE.fullmatch(arn) if isinstance(arn, str) else None
        if (not match or match[1] != partition or arn in seen_instances
                or instance.get("Status") != "ACTIVE"
                or instance.get("OwnerAccountId") not in accounts):
            return {"status": "malformed", "reason": "identity_center_instance_invalid", "items": rows}
        from .aws_identity_center_regions import remember
        # The organization consumer is collected in the audited owner account.
        remember(requests, instance["OwnerAccountId"], region)
        seen_instances.add(arn)
        listed = requests.pages(session, "sso-admin", region, "list_permission_sets", "PermissionSets", InstanceArn=arn)
        if listed.status not in GOOD:
            return {**_problem(listed, "list_permission_sets"), "items": rows}
        seen_sets = set()
        for permission in listed.items:
            prefix = f"arn:{match[1]}:sso:::permissionSet/{match[2]}/"
            if (not isinstance(permission, str) or not permission.startswith(prefix)
                    or not re.fullmatch(r"ps-[A-Za-z0-9./-]{16}", permission[len(prefix):])
                    or permission in seen_sets):
                return {"status": "malformed", "reason": "identity_center_permission_set_invalid", "items": rows}
            seen_sets.add(permission)
            row = {"InstanceArn": arn, "OwnerAccountId": instance["OwnerAccountId"], "PermissionSetArn": permission,
                   "OrganizationAccounts": sorted(accounts), "ProvisionedAccounts": [],
                   "ProvisioningStates": {}, "Assignments": [], "status": "collected",
                   "_provenance": {"home_region": region, "organization_accounts_complete": True,
                                    "read_only": True, "all_accounts_checked": False}}
            rows.append(row)
            args = {"InstanceArn": arn, "PermissionSetArn": permission}
            reads = {"ALL": requests.pages(session, "sso-admin", region,
                     "list_accounts_for_provisioned_permission_set", "AccountIds", **args)}
            for state in FILTERS:
                reads[state] = requests.pages(session, "sso-admin", region,
                    "list_accounts_for_provisioned_permission_set", "AccountIds", ProvisioningStatus=state, **args)
            bound = {}
            provisioning_error = None
            for state, read in reads.items():
                bound[state], error = _account_ids(read, accounts, "provisioning_" + state.lower())
                if error:
                    row.update(error)
                    provisioning_error = error
                    break
            if not provisioning_error:
                if (bound[FILTERS[0]] & bound[FILTERS[1]]
                        or bound[FILTERS[0]] | bound[FILTERS[1]] != bound["ALL"]):
                    row.update(status="malformed", reason="provisioning_state_partition_invalid")
                else:
                    row["ProvisionedAccounts"] = sorted(bound["ALL"])
                    row["ProvisioningStates"] = {
                        account: ("latest_provisioned" if account in bound[FILTERS[0]] else "latest_not_provisioned")
                        for account in bound["ALL"]}
            seen_assignments = set()
            for account in sorted(accounts):
                read = requests.pages(session, "sso-admin", region, "list_account_assignments",
                                      "AccountAssignments", AccountId=account, **args)
                if read.status not in GOOD:
                    row.update(_problem(read, "list_account_assignments"))
                    continue
                for assignment in read.items:
                    if not isinstance(assignment, dict):
                        row.update(status="malformed", reason="account_assignment_invalid")
                        continue
                    principal = assignment.get("PrincipalId")
                    kind = assignment.get("PrincipalType")
                    key = (account, kind, principal)
                    if (assignment.get("AccountId") != account or assignment.get("PermissionSetArn") != permission
                            or kind not in ("USER", "GROUP") or not isinstance(principal, str)
                            or not PRINCIPAL.fullmatch(principal) or key in seen_assignments):
                        row.update(status="malformed", reason="account_assignment_binding_invalid")
                        continue
                    seen_assignments.add(key)
                    row["Assignments"].append({"AccountId": account, "PrincipalType": kind, "PrincipalId": principal})
            row["_provenance"]["all_accounts_checked"] = row["status"] == "collected"
    return {"status": "collected", "items": rows}


def fetch(requests, session, region, account):
    """AWS extension adapter; root registers this module's specs/actions/fetcher."""
    from .aws import ReadResult
    result = collect(requests, session, region)
    rows = [row for row in result["items"] if row["OwnerAccountId"] == account]
    if result["items"] and not rows:
        return ReadResult([], "not_collected", {"code": "identity_center_instance_owner_context_required"})
    if rows and any(account not in row["OrganizationAccounts"] for row in rows):
        return ReadResult([], "malformed", {"code": "identity_center_collector_account_outside_organization"})
    for row in rows:
        row["AuditedAccountId"] = account
        row["Region"] = region
    problems = [row for row in rows if row["status"] != "collected"]
    status = result["status"]
    reason = result.get("reason")
    if status == "collected" and problems:
        status = "partial"
        reason = problems[0].get("reason", "permission_set_consumer_incomplete")
    return ReadResult(rows, status, {"code": reason} if reason else None)


FETCHERS = {"aws_identity_center_permission_set_consumer": fetch}


def observe_credential_report(requests, session, region, items):
    """Bind report reads generated after the scan's start to the actual read clock."""
    from datetime import datetime, timezone
    observed = datetime.now(timezone.utc).isoformat()
    started = requests.observed_at.isoformat()
    return [{**row, '_credential_report_observation': {
        'operation': 'iam:GetCredentialReport', 'observed_at': observed,
        'scan_started_at': started}} for row in items]


ENRICHERS = {'iam_credential_report': observe_credential_report}
