"""Structural Identity Center permission-set consumer decision, independent of use."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from dataclasses import replace
from pathlib import Path
import json


def _permission_set_unresolved(permission, reason):
    return "UNKNOWN", {"permission_set_arn": permission, "reason": reason,
        "summary": reason +
        "\nThe permission set has incomplete or inconsistent recorded consumer identities."
        "\nIt is unclear which users could receive its permissions and reach account data."}


def evaluate_permission_set(row):
    if not isinstance(row, dict) or not isinstance(row.get("PermissionSetArn"), str):
        return "UNKNOWN", {"summary": "Permission-set identity is unresolved."}
    permission = row["PermissionSetArn"]
    assignments = row.get("Assignments")
    provisioned = row.get("ProvisionedAccounts")
    if not isinstance(assignments, list) or not isinstance(provisioned, list):
        return "UNKNOWN", {"summary": "Permission-set consumer inventory is unresolved."}
    # Producer rows bind every retained consumer to the organization account
    # universe. Validate that shape before allowing a positive declaration.
    accounts = row.get("OrganizationAccounts")
    proof = row.get("_provenance")
    permission_match = re.fullmatch(
        r"arn:(aws(?:-[a-z0-9]+)*):sso:::permissionSet/((?:sso)?ins-[A-Za-z0-9.-]{16})/ps-[A-Za-z0-9./-]{16}",
        permission,
    )
    if (permission_match is None or not isinstance(accounts, list) or not accounts
            or any(not isinstance(a, str) or not re.fullmatch(r"[0-9]{12}", a) for a in accounts)
            or len(set(accounts)) != len(accounts) or not isinstance(proof, dict)
            or proof.get("read_only", True) is not True
            or row.get("status") not in ("collected", "partial", "denied", "unknown", "timeout")):
        return _permission_set_unresolved(permission, 'Permission-set consumer identity or organization binding is malformed.')
    if "InstanceArn" in row and row["InstanceArn"] != (
            "arn:" + permission_match[1] + ":sso:::instance/" + permission_match[2]):
        return _permission_set_unresolved(permission, 'Permission-set instance identity disagrees with its ARN.')
    if (any(not isinstance(a, str) or a not in accounts for a in provisioned)
            or len(set(provisioned)) != len(provisioned)):
        return _permission_set_unresolved(permission, 'Permission-set provisioned account identity is malformed.')
    states = row.get("ProvisioningStates")
    if (not isinstance(states, dict) or set(states) != set(provisioned)
            or any(v not in ("latest_provisioned", "latest_not_provisioned") for v in states.values())):
        return _permission_set_unresolved(permission, 'Permission-set provisioning states disagree with its accounts.')
    seen = set()
    for assignment in assignments:
        if (not isinstance(assignment, dict) or assignment.get("AccountId") not in accounts
                or assignment.get("PrincipalType") not in ("USER", "GROUP")
                or not isinstance(assignment.get("PrincipalId"), str)
                or not re.fullmatch(r"(?:[0-9a-f]{10}-)?[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", assignment["PrincipalId"])):
            return _permission_set_unresolved(permission, 'Permission-set assignment identity is malformed.')
        key = assignment["AccountId"], assignment["PrincipalType"], assignment["PrincipalId"]
        if key in seen:
            return _permission_set_unresolved(permission, 'Permission-set assignment identity is duplicated.')
        seen.add(key)
    if assignments or provisioned:
        accounts = sorted(set(provisioned) | {a["AccountId"] for a in assignments if isinstance(a, dict) and isinstance(a.get("AccountId"), str)})
        return "PASS", {"permission_set_arn": permission, "consumer_accounts": accounts,
                        "assignments": assignments, "provisioning_states": row.get("ProvisioningStates", {}),
                        "summary": f"Permission set {permission} has a captured assignment or provisioned account.\nIts current structural consumer is recorded across {len(accounts)} account(s).\nProvisioning and assignment do not establish permission use."}
    proof = row.get("_provenance")
    if (row.get("status") != "collected" or not isinstance(proof, dict)
            or proof.get("organization_accounts_complete") is not True
            or proof.get("all_accounts_checked") is not True
            or not isinstance(row.get("OrganizationAccounts"), list)
            or any(not isinstance(a, str) or not re.fullmatch(r"[0-9]{12}", a) for a in row["OrganizationAccounts"])):
        return "UNKNOWN", {"permission_set_arn": permission, "summary": f"Permission set {permission} has unresolved account or provisioning reads.\nNo complete all-account consumer absence is established.\nReview the source read before acting."}
    return "FAIL", {"permission_set_arn": permission, "consumer_accounts": [],
                    "summary": f"Permission set {permission} has no assignment or provisioned account.\nComplete organization-account and provisioning reads found no current consumer.\nThis is structural absence, not a measurement of permission use."}


PERMISSION_SET_CHECK = "aws.iam.identity_center.permission_set_has_consumer_all_accounts"
PERMISSION_SET_KIND = "aws_identity_center_permission_set_consumer"


def evaluate_permission_set_native(item, index):
    try:
        context = index.get("context", {})
        scope = context.get("scope")
        match = re.fullmatch(r"([0-9]{12})/([a-z]{2}(?:-gov)?-[a-z]+-[0-9])", scope or "")
        if (context.get("provider") != "aws" or not match or not isinstance(item, dict)
                or item.get("AuditedAccountId") != match[1] or item.get("OwnerAccountId") != match[1]
                or item.get("Region") != match[2]):
            raise ValueError("Identity Center audited account and regional scope disagree")
        collections = index.get("collections", {}).get(PERMISSION_SET_KIND)
        if not isinstance(collections, list) or len(collections) != 1:
            raise ValueError("unique Identity Center consumer collection unavailable")
        source = collections[0]
        if (source.get("type") != PERMISSION_SET_KIND or source.get("scope") != scope
                or source.get("service") != "sso-admin" or source.get("status") not in ("collected", "partial")
                or not isinstance(source.get("items"), list)
                or sum(row == item for row in source["items"]) != 1):
            raise ValueError("Identity Center current resource projection is incomplete")
        status, evidence = evaluate_permission_set(item)
        if status == "FAIL" and source["status"] != "collected":
            return "UNKNOWN", {"summary": "Identity Center source collection is partial.\nAll-account absence is not proven at collection scope.\nReview missing permission-set reads."}
        return status, evidence
    except (ValueError, TypeError, AttributeError) as exc:
        return "UNKNOWN", {"reason": str(exc), "summary": f"Identity Center consumer evidence is unresolved: {exc}.\nThe permission set must match the current account and region.\nNo all-account absence is established."}


_PASSWORD_TRACKING = datetime(2014, 10, 20, tzinfo=timezone.utc)
_KEY_TRACKING = datetime(2015, 4, 22, tzinfo=timezone.utc)


def _instant(value, name):
    if not isinstance(value, str) or not value or value in {"N/A", "no_information", "not_supported"}:
        raise ValueError(name + " has no usable timestamp")
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError(name + " lacks timezone")
    return stamp.astimezone(timezone.utc)


def _date_or_marker(item, field, markers):
    value = item.get(field)
    if value in markers:
        return None, value
    return _instant(value, field), None


def evaluate_credential_report(item, index, *, days=45, include_password=True, include_keys=True):
    """Strict replacement decision for the 45/90-day report-based controls.

    A documented no-use marker can establish a bounded observation only when
    current credential metadata and the report clock cover the full threshold.
    Inconsistent/missing fields never become a PASS or a stale-use claim.
    """
    try:
        if days not in (45, 90) or not isinstance(item, dict) or not isinstance(index, dict):
            raise ValueError("credential report input is invalid")
        if item.get("collection_status", "collected") not in ("collected", "empty"):
            raise ValueError("credential report row is incomplete")
        coverage = item.get("_coverage", {})
        if not isinstance(coverage, dict) or any(
                not isinstance(entry, dict) or entry.get("status") not in ("collected", "empty")
                for entry in coverage.values()):
            raise ValueError("credential report field coverage is incomplete")
        context = index.get("context")
        if not isinstance(context, dict) or context.get("provider", "aws") != "aws":
            raise ValueError("AWS snapshot context is unavailable")
        snapshot = _instant(context.get("created_at"), "snapshot clock")
        report = _instant(item.get("ReportGeneratedTime"), "credential report clock")
        observation = item.get('_credential_report_observation')
        observed = snapshot
        if observation is not None:
            if (not isinstance(observation, dict) or observation.get('operation') != 'iam:GetCredentialReport'
                    or _instant(observation.get('scan_started_at'), 'report scan start') != snapshot):
                raise ValueError('credential report observation belongs to another scan')
            observed = _instant(observation.get('observed_at'), 'report read clock')
            if not snapshot <= observed <= snapshot + timedelta(days=1):
                raise ValueError('credential report observation is outside the scan interval')
        if report > observed or observed - report > timedelta(hours=4):
            raise ValueError("credential report clock is stale or after its native read")
        user, arn = item.get("user"), item.get("arn")
        scope = context.get("scope")
        match = re.fullmatch(r"arn:(aws(?:-[a-z0-9]+)*):iam::([0-9]{12}):(root|user/(.+))", arn or "")
        if (not match or not isinstance(user, str) or not user
                or (scope and scope.split("/")[0] != match[2])
                or (user == "<root_account>") != (match[3] == "root")
                or (user != "<root_account>" and match[4].rsplit("/", 1)[-1] != user)):
            raise ValueError("credential report user and account binding is invalid")
        if user == "<root_account>":
            return "MANUAL", {"reason": "root credential use requires separate owner review"}
        user_created = _instant(item.get("user_creation_time"), "user creation")
        if user_created > report:
            raise ValueError("user creation is after report")
        cutoff = report - timedelta(days=days)
        states, stale, unresolved = [], [], []
        specs = ([('password', 'password_enabled', 'password_last_used', 'password_last_changed', _PASSWORD_TRACKING, 'no_information')]
                 if include_password else [])
        specs += [(f'access_key_{n}', f'access_key_{n}_active', f'access_key_{n}_last_used_date',
                   f'access_key_{n}_last_rotated', _KEY_TRACKING, 'N/A') for n in (1, 2)] if include_keys else []
        for label, active_field, used_field, since_field, tracking, no_use in specs:
            active = item.get(active_field)
            if active not in ("true", "false"):
                unresolved.append(label + " state unavailable")
                continue
            if active == "false":
                continue
            state = {"credential": label, "state": "active"}
            states.append(state)
            try:
                since = _instant(item.get(since_field), since_field)
                if not user_created <= since <= report:
                    raise ValueError("credential date outside current user/report lifetime")
                used, marker = _date_or_marker(item, used_field, {no_use})
                if used is not None:
                    if not tracking <= used <= report or used < user_created:
                        raise ValueError("recorded use outside tracking or user lifetime")
                    if used < since:
                        raise ValueError("recorded use predates current credential date")
                    state.update(last_used=used.isoformat(), credential_date=since.isoformat())
                    if used < cutoff:
                        stale.append(state)
                elif since >= tracking:
                    state.update(last_used=None, credential_date=since.isoformat(), observation="no recorded use since AWS tracking began")
                    if since < cutoff:
                        stale.append(state)
                    else:
                        unresolved.append(label + " has no recorded use but is newer than the threshold")
                else:
                    unresolved.append(label + " no-use marker predates tracking")
            except (ValueError, TypeError) as exc:
                unresolved.append(label + ": " + str(exc))
        evidence = {"user": user, "user_arn": arn, "report_generated_at": report.isoformat(),
                    "threshold_days": days, "captured_credentials": states, "stale_credentials": stale}
        if stale:
            names = ", ".join(entry["credential"] for entry in stale)
            return "FAIL", {**evidence, "summary": f"IAM user {user} has stale recorded credential evidence for {names}.\nThe report was generated on {report.date().isoformat()} and the review threshold is {days} days.\nReview each enabled credential before changing access."}
        if unresolved:
            return "UNKNOWN", {**evidence, "reason": "; ".join(unresolved),
                               "summary": f"IAM user {user} has unresolved enabled-credential use evidence.\nThe report cannot establish a complete {days}-day decision for every enabled credential.\nReview the reported dates and source coverage."}
        if not states:
            return "NOT_APPLICABLE", {**evidence, "summary": f"IAM user {user} has no enabled credential in the assessed report fields.\nNo password or access key is assessed for recent use.\nThis does not describe other credential families."}
        return "PASS", {**evidence, "summary": f"IAM user {user} has recent recorded use for every assessed enabled credential.\nThe report was generated on {report.date().isoformat()} within the captured snapshot window.\nThis does not assess other credential families."}
    except (ValueError, TypeError, AttributeError, OverflowError) as exc:
        return "UNKNOWN", {"reason": str(exc), "summary": f"Credential report evidence is unresolved: {exc}.\nThe report clock, identity and enabled credential dates must agree.\nNo inactivity decision follows from missing metadata."}


_SUCCESSORS = {
    "aws.a.iam.unused_credentials_45_days": (45, True, True),
    "aws.a.iam.unused_credentials_90_days": (90, True, True),
    "aws.gap.iam.active_keys_used_within_45_days": (45, False, True),
    "aws.claude_a.iam.console_password_used_45": (45, True, False),
    "aws.claude_a.iam.prowler_console_password_used_45": (45, True, False),
    "aws.claude_a.iam.access_keys_used_45": (45, False, True),
}


def install(registry):
    """Register a distinct Identity Center control and correct six existing IDs."""
    from peaso.checks.fixtures import CASES
    from peaso.checks import catalog
    folder = Path(__file__).with_name("checks")
    native = json.loads((folder / "unused_iam_aws_completion_cases.json").read_text())
    credential = json.loads((folder / "unused_iam_aws_completion_credentials_cases.json").read_text())
    review = json.loads((folder / "unused_iam_aws_completion_review.json").read_text())
    if set(native) != {PERMISSION_SET_KIND} or set(credential) != set(_SUCCESSORS):
        raise ValueError("AWS completion case IDs changed")
    if review.get("check_ids") != [PERMISSION_SET_CHECK, *_SUCCESSORS]:
        raise ValueError("AWS completion review IDs changed")
    found = {check.id: check for check in registry.CHECKS if check.id in _SUCCESSORS}
    if set(found) != set(_SUCCESSORS) or any(check.provider != "aws" or check.kind != "iam_credential_report" for check in found.values()):
        raise ValueError("AWS credential-report predecessors changed")
    def successor(ident):
        days, password, keys = _SUCCESSORS[ident]
        def evaluate(item, index):
            status, evidence = evaluate_credential_report(item, index, days=days,
                include_password=password, include_keys=keys)
            if status == 'MANUAL' and ident.startswith('aws.claude_a.iam.'):
                return 'NOT_APPLICABLE', {'reason': 'root credential use is assessed separately'}
            return status, evidence
        return evaluate
    registry.CHECKS[:] = [replace(check, evaluate=successor(check.id),
        category="hardening", allow_incomplete_failure=True)
        if check.id in _SUCCESSORS else check for check in registry.CHECKS]
    previous_description = catalog.description_for
    def description_for(ident):
        previous = previous_description(ident)
        if ident not in _SUCCESSORS:
            return previous
        days, password, keys = _SUCCESSORS[ident]
        population = 'console passwords and access keys' if password and keys else 'console passwords' if password else 'access keys'
        return {**previous,
            'description': f'Reviews enabled {population} from a current identity-bound AWS credential report against a {days}-day threshold. Recorded use, current credential lifetime and documented tracking limits must agree; recent creation without recorded use remains unresolved.',
            'evaluated': ['credential report generated within four hours of its bound native read', 'same-account user identity, current credential dates and enabled state', f'{days}-day recorded-use or documented no-use interval for {population}'],
            'pass_when': 'All assessed enabled credentials have current, consistent recent recorded use.',
            'fail_when': f'At least one assessed enabled credential has recorded use older than {days} days, or a documented no-use marker covering that interval within its current lifetime.',
            'not_applicable_when': 'No credential in the assessed family is enabled; root handling remains separate. Missing, stale, denied, inconsistent or insufficient observation is unresolved.'}
    catalog.description_for = description_for
    CASES.update(credential)
    CASES[PERMISSION_SET_CHECK] = native[PERMISSION_SET_KIND]
    registry.register(PERMISSION_SET_CHECK, "aws", "hardening", PERMISSION_SET_KIND,
        "Identity Center permission set has a consumer across organization accounts", "low", "AC-6",
        "Review the permission set and its intended account consumers before retiring an unassigned set.",
        allow_incomplete_failure=True)(evaluate_permission_set_native)
