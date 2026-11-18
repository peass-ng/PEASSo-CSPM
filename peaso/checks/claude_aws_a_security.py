"""claude_aws_a security services: GuardDuty, KMS, CloudTrail multi-region, Organizations and
Security Hub (Steampipe aws-compliance / aws-perimeter and Prowler).

Detector facts come from guardduty:GetDetector (``Configuration``). Facts the collector does not
gather yet (administrator/member accounts, findings, organization admin accounts, organization
configuration, Security Hub hubs, organization policies) are read from documented item fields or
kinds; when absent the predicate is UNKNOWN (see COLLECTOR FACTS NEEDED in the coverage doc).
"""
from __future__ import annotations

from . import result
from .facts import Unavailable, get, list_of_objects
from .claude_aws_a_common import (install, items, idx, region, account, strings, policy_document, turbot_public_statements,
                                  TURBOT_KEYS, is_policy_public, C, P, R, ACCOUNT)
from .claude_aws_a_ec2 import w, DROP

GD = "https://docs.aws.amazon.com/guardduty/latest/APIReference/"
KMS = "https://docs.aws.amazon.com/kms/latest/APIReference/"
SH = "https://docs.aws.amazon.com/securityhub/1.0/APIReference/"
ORG = "https://docs.aws.amazon.com/organizations/latest/APIReference/"
FSBP = "https://docs.aws.amazon.com/securityhub/latest/userguide/"


def collected(item, key):
    """A nested API response recorded on the item; denied/failed reads raise Unavailable."""
    value = get(item, key, dict)
    status = value.get("collection_status", "collected")
    if status not in ("collected", "empty"):
        raise Unavailable("%s not collected (%s)" % (key, status))
    if status == "empty" and value.get("items") not in (None, []):
        raise Unavailable("%s empty response has retained items" % key)
    return value


# =========================================================================== GuardDuty detector fixtures
FEATURES = [{"Name": n, "Status": "ENABLED"} for n in ("S3_DATA_EVENTS", "EKS_AUDIT_LOGS", "EBS_MALWARE_PROTECTION", "RDS_LOGIN_EVENTS",
                                                         "EKS_RUNTIME_MONITORING", "LAMBDA_NETWORK_LOGS", "AI_PROTECTION")]
FEATURES.append({"Name": "RUNTIME_MONITORING", "Status": "ENABLED", "AdditionalConfiguration": [
    {"Name": "EKS_ADDON_MANAGEMENT", "Status": "ENABLED"}, {"Name": "ECS_FARGATE_AGENT_MANAGEMENT", "Status": "ENABLED"},
    {"Name": "EC2_AGENT_MANAGEMENT", "Status": "ENABLED"}]})
DATA_SOURCES = {"S3Logs": {"Status": "ENABLED"}, "Kubernetes": {"AuditLogs": {"Status": "ENABLED"}},
                "MalwareProtection": {"ScanEc2InstanceWithFindings": {"EbsVolumes": {"Status": "ENABLED"}}}}
DET = {"DetectorId": "d1", "Configuration": {"Status": "ENABLED", "DataSources": DATA_SOURCES, "Features": FEATURES},
       "Administrator": {"collection_status": "collected", "Administrator": {"AccountId": "999999999999", "RelationshipStatus": "Enabled"}},
       "Members": {"collection_status": "collected", "items": []},
       "FindingIds": {"collection_status": "collected", "items": []},
       "HighSeverityFindingIds": {"collection_status": "collected", "items": []},
       "OrganizationConfiguration": {"collection_status": "collected", "AutoEnableOrganizationMembers": "ALL"}}
DISABLED = w(DET, Configuration__Status="DISABLED")


def features(item):
    return list_of_objects(get(item, "Configuration.Features", list))


def feature(item, name):
    rows = [f for f in features(item) if get(f, "Name", str) == name]
    return rows


def detector_enabled(item):
    status = get(item, "Configuration.Status", str)
    if status not in ("ENABLED", "DISABLED"):
        raise Unavailable("unrecognized detector status")
    return status == "ENABLED"


def without_feature(name):
    return w(DET, Configuration__Features=[f for f in FEATURES if f["Name"] != name])


def disabled_feature(name):
    return w(DET, Configuration__Features=[dict(f, Status="DISABLED") if f["Name"] == name else f for f in FEATURES])


# --------------------------------------------------------------------------- Steampipe feature checks
def _steampipe_feature(cid, title, rows, name, extra_name=None, *, severity="medium", remediation, docs):
    def ok(item):
        for f in features(item):
            if get(f, "Name", str) != name:
                continue
            if extra_name is None:
                if f.get("Status") == "ENABLED":
                    return True
            else:
                for c in list_of_objects(f.get("AdditionalConfiguration") or []):
                    if c.get("Name") == extra_name and c.get("Status") == "ENABLED":
                        return True
        return False
    failing = disabled_feature(name) if extra_name is None else w(DET, Configuration__Features=[
        dict(f, AdditionalConfiguration=[dict(c, Status="DISABLED") for c in f.get("AdditionalConfiguration", [])]) if f["Name"] == name else f for f in FEATURES])

    @install(cid, "guardduty_detector", title, DET, failing, rows=rows, severity=severity, control="SI-4", remediation=remediation, docs=docs,
             extra={"fail_absent": without_feature(name)},
             note="Native detector gate: Features has %s%s with Status ENABLED and detector Status is ENABLED; pinned Steampipe feature query does not check detector status." % (name, (" / AdditionalConfiguration " + extra_name) if extra_name else ""))
    def evaluate(item, index):
        feature_on = ok(item)
        hit = feature_on and detector_enabled(item)
        return result(not hit, feature=name, configuration=extra_name, enabled=hit,
                      feature_enabled=feature_on, detector_enabled=hit if feature_on else None)
    return evaluate


_steampipe_feature("aws.claude_a.guardduty.ebs_malware_protection_feature", "GuardDuty detector enables EBS malware protection",
    [C + "guardduty_detector_ec2_malware_protection_enabled", C + "foundational_security_guardduty_8"], "EBS_MALWARE_PROTECTION",
    remediation="Enable GuardDuty Malware Protection for EC2 (EBS volume scanning).",
    docs=[GD + "API_GetDetector.html", FSBP + "guardduty-controls.html#guardduty-8"])
_steampipe_feature("aws.claude_a.guardduty.eks_runtime_monitoring_feature", "GuardDuty detector enables EKS Runtime Monitoring",
    [C + "guardduty_detector_eks_runtime_monitoring_enabled", C + "foundational_security_guardduty_7"], "EKS_RUNTIME_MONITORING",
    remediation="Enable GuardDuty EKS Runtime Monitoring.", docs=[GD + "API_DetectorFeatureConfigurationResult.html", FSBP + "guardduty-controls.html#guardduty-7"])
_steampipe_feature("aws.claude_a.guardduty.ecs_runtime_agent_management", "GuardDuty Runtime Monitoring manages the ECS Fargate agent",
    [C + "guardduty_detector_ecs_runtime_monitoring_enabled", C + "foundational_security_guardduty_12"], "RUNTIME_MONITORING", "ECS_FARGATE_AGENT_MANAGEMENT",
    remediation="Enable GuardDuty Runtime Monitoring with automated agent management for ECS Fargate.",
    docs=[GD + "API_DetectorAdditionalConfigurationResult.html", FSBP + "guardduty-controls.html#guardduty-12"])
_steampipe_feature("aws.claude_a.guardduty.ec2_runtime_agent_management", "GuardDuty Runtime Monitoring manages the EC2 agent",
    [C + "guardduty_detector_ec2_runtime_monitoring_enabled", C + "foundational_security_guardduty_13"], "RUNTIME_MONITORING", "EC2_AGENT_MANAGEMENT",
    remediation="Enable GuardDuty Runtime Monitoring with automated agent management for EC2.",
    docs=[GD + "API_DetectorAdditionalConfigurationResult.html", FSBP + "guardduty-controls.html#guardduty-13"])

SKIP_REGIONS = ("af-south-1", "ap-northeast-3", "ap-southeast-3", "eu-south-1", "cn-north-1", "cn-northwest-1", "me-south-1", "us-gov-east-1")


@install("aws.claude_a.guardduty.region_centrally_configured", "guardduty_detector", "Region's GuardDuty detector is managed by an administrator account",
    {}, {}, target="scope", pass_index=idx(guardduty_detector=[DET]),
    fail_index=idx(guardduty_detector=[w(DET, Administrator={"collection_status": "collected"})]),
    rows=[C + "guardduty_centrally_configured"], severity="medium", control="SI-4",
    remediation="Enroll the account in the organization's GuardDuty delegated administrator.", docs=[GD + "API_GetAdministratorAccount.html"],
    extra={"na": ({}, idx(guardduty_detector=[])), "fail_disabled": ({}, idx(guardduty_detector=[DISABLED]))},
    note="Steampipe: no detector is info (NOT_APPLICABLE); DISABLED alarms; ENABLED with an administrator (master) account is ok. "
         "Needs guardduty:GetAdministratorAccount on each detector (collector fact).")
def centrally_configured(context, index):
    if region(index) in SKIP_REGIONS:
        return "NOT_APPLICABLE", {"reason": "source skips this region"}
    detectors = items(index, "guardduty_detector")
    if not detectors:
        return "NOT_APPLICABLE", {"reason": "no detector (source info status)"}
    states = []
    for d in detectors:
        if not detector_enabled(d):
            states.append(False)
            continue
        admin = collected(d, "Administrator")
        states.append(bool((admin.get("Administrator") or {}).get("AccountId")))
    return result(not any(states), managed=states)


@install("aws.claude_a.guardduty.detector_no_findings", "guardduty_detector", "Enabled GuardDuty detector has no active severity-8 findings",
    DET, w(DET, HighSeverityFindingIds={"collection_status": "collected", "items": ["f1"]}), rows=[C + "guardduty_no_high_severity_findings"],
    severity="high", control="SI-4", remediation="Investigate and remediate active severity-8 GuardDuty findings; archive only after resolution.", docs=[GD + "API_ListFindings.html"],
    extra={"na": DISABLED}, note="Semantic correction to pinned Steampipe SQL: its query counts every historical/archived finding despite the high-severity title. Use collected ListFindings criteria severity Eq ['8'] and service.archived Eq ['false']; missing/denied criteria response is UNKNOWN.")
def detector_no_findings(item, index):
    if not detector_enabled(item):
        return "NOT_APPLICABLE", {"reason": "detector not enabled"}
    found = get(collected(item, "HighSeverityFindingIds"), "items", list)
    if any(not isinstance(finding_id, str) or not finding_id for finding_id in found):
        raise Unavailable("malformed GuardDuty finding ID list")
    return result(bool(found), active_severity_8_findings=len(found))


@install("aws.claude_a.guardduty.finding_archived", "guardduty_finding", "GuardDuty finding is archived",
    {"Id": "f1", "Arn": "arn:aws:guardduty:us-east-1:%s:detector/d1/finding/f1" % ACCOUNT, "Service": {"Archived": True}},
    {"Id": "f1", "Arn": "arn:aws:guardduty:us-east-1:%s:detector/d1/finding/f1" % ACCOUNT, "Service": {"Archived": False}},
    rows=[C + "guardduty_finding_archived"], severity="low", control="SI-4", remediation="Review and archive resolved GuardDuty findings.",
    docs=[GD + "API_GetFindings.html"], note="Needs guardduty:ListFindings + GetFindings (kind guardduty_finding, collector fact).")
def finding_archived(item, index):
    archived = get(item, "Service.Archived", bool)
    return result(not archived, archived=archived)


# --------------------------------------------------------------------------- Prowler detector checks
def datasource(item, path):
    status = get(item, "Configuration.DataSources." + path + ".Status", str)
    return status == "ENABLED"


def prowler_flags(item):
    """Prowler GuardDuty._get_detector feature flags."""
    flags = {"rds": False, "lambda": False, "ai": None, "eks_runtime": False, "runtime": None}
    for f in features(item):
        name, status = f.get("Name", ""), f.get("Status", "DISABLED")
        if name == "RDS_LOGIN_EVENTS" and status == "ENABLED":
            flags["rds"] = True
        elif name == "LAMBDA_NETWORK_LOGS" and status == "ENABLED":
            flags["lambda"] = True
        elif name == "AI_PROTECTION":
            flags["ai"] = status == "ENABLED"
        elif name in ("EKS_RUNTIME_MONITORING", "RUNTIME_MONITORING"):
            if status == "ENABLED":
                flags["eks_runtime"] = True
            if name == "RUNTIME_MONITORING":
                flags["runtime"] = status == "ENABLED"
    return flags


def _prowler_protection(cid, title, row, reader, failing, *, remediation, docs):
    @install(cid, "guardduty_detector", title, DET, failing, rows=[P + row], severity="medium" if "audit" not in row else "high", control="SI-4",
             remediation=remediation, docs=docs, extra={"na": DISABLED}, note="Prowler reports only detectors whose status is ENABLED.")
    def evaluate(item, index):
        if not detector_enabled(item):
            return "NOT_APPLICABLE", {"reason": "detector not enabled"}
        on = reader(item)
        return result(not on, enabled=on)
    return evaluate


_prowler_protection("aws.claude_a.guardduty.prowler_s3_protection", "Enabled GuardDuty detector has S3 Protection (Prowler)", "guardduty_s3_protection_enabled",
    lambda i: datasource(i, "S3Logs"), w(DET, Configuration__DataSources__S3Logs__Status="DISABLED"),
    remediation="Enable GuardDuty S3 Protection.", docs=[GD + "API_S3LogsConfigurationResult.html"])
_prowler_protection("aws.claude_a.guardduty.prowler_eks_audit_logs", "Enabled GuardDuty detector monitors EKS audit logs (Prowler)", "guardduty_eks_audit_log_enabled",
    lambda i: datasource(i, "Kubernetes.AuditLogs"), w(DET, Configuration__DataSources__Kubernetes__AuditLogs__Status="DISABLED"),
    remediation="Enable GuardDuty EKS Audit Log Monitoring.", docs=[GD + "API_KubernetesAuditLogsConfigurationResult.html"])
_prowler_protection("aws.claude_a.guardduty.prowler_ec2_malware_protection", "Enabled GuardDuty detector scans EBS volumes for malware (Prowler)",
    "guardduty_ec2_malware_protection_enabled", lambda i: datasource(i, "MalwareProtection.ScanEc2InstanceWithFindings.EbsVolumes"),
    w(DET, Configuration__DataSources__MalwareProtection__ScanEc2InstanceWithFindings__EbsVolumes__Status="DISABLED"),
    remediation="Enable GuardDuty Malware Protection for EC2.", docs=[GD + "API_MalwareProtectionConfigurationResult.html"])
_prowler_protection("aws.claude_a.guardduty.prowler_rds_protection", "Enabled GuardDuty detector has RDS Protection (Prowler)", "guardduty_rds_protection_enabled",
    lambda i: prowler_flags(i)["rds"], without_feature("RDS_LOGIN_EVENTS"), remediation="Enable GuardDuty RDS Protection.",
    docs=[GD + "API_DetectorFeatureConfigurationResult.html"])
_prowler_protection("aws.claude_a.guardduty.prowler_lambda_protection", "Enabled GuardDuty detector has Lambda Protection (Prowler)", "guardduty_lambda_protection_enabled",
    lambda i: prowler_flags(i)["lambda"], disabled_feature("LAMBDA_NETWORK_LOGS"), remediation="Enable GuardDuty Lambda Protection.",
    docs=[GD + "API_DetectorFeatureConfigurationResult.html"])
_prowler_protection("aws.claude_a.guardduty.prowler_eks_runtime_monitoring", "Enabled GuardDuty detector has EKS runtime monitoring (Prowler)",
    "guardduty_eks_runtime_monitoring_enabled", lambda i: prowler_flags(i)["eks_runtime"],
    w(DET, Configuration__Features=[dict(f, Status="DISABLED") if f["Name"] in ("EKS_RUNTIME_MONITORING", "RUNTIME_MONITORING") else f for f in FEATURES]),
    remediation="Enable GuardDuty Runtime Monitoring for EKS.", docs=[GD + "API_DetectorFeatureConfigurationResult.html"])


@install("aws.claude_a.guardduty.prowler_ai_protection", "guardduty_detector", "GuardDuty detector has AI Protection enabled (Prowler)",
    DET, disabled_feature("AI_PROTECTION"), rows=[P + "guardduty_ai_protection_enabled"], severity="medium", control="SI-4",
    remediation="Enable the GuardDuty AI_PROTECTION feature.", docs=[GD + "API_DetectorFeatureConfigurationResult.html"],
    note="Prowler MANUAL when the detector is not ENABLED or the AI_PROTECTION feature is not reported.")
def ai_protection(item, index):
    if not detector_enabled(item):
        return "MANUAL", {"reason": "detector state not ENABLED"}
    flag = prowler_flags(item)["ai"]
    if flag is None:
        return "MANUAL", {"reason": "AI_PROTECTION feature not reported"}
    return result(not flag, ai_protection=flag)


@install("aws.claude_a.guardduty.prowler_runtime_monitoring", "guardduty_detector", "GuardDuty detector has unified Runtime Monitoring enabled (Prowler)",
    DET, disabled_feature("RUNTIME_MONITORING"), rows=[P + "guardduty_runtime_monitoring_enabled"], severity="medium", control="SI-4",
    remediation="Enable GuardDuty RUNTIME_MONITORING (not only the legacy EKS feature).", docs=[GD + "API_DetectorFeatureConfigurationResult.html"],
    extra={"fail_legacy": w(without_feature("RUNTIME_MONITORING"))},
    note="Legacy EKS_RUNTIME_MONITORING alone fails; MANUAL when the detector is not ENABLED or the feature is not reported.")
def runtime_monitoring(item, index):
    if not detector_enabled(item):
        return "MANUAL", {"reason": "detector state not ENABLED"}
    flags = prowler_flags(item)
    if flags["runtime"] is True:
        return result(False, runtime_monitoring=True)
    if flags["eks_runtime"]:
        return result(True, runtime_monitoring=False, legacy_eks_runtime=True)
    if flags["runtime"] is None:
        return "MANUAL", {"reason": "RUNTIME_MONITORING feature not reported"}
    return result(True, runtime_monitoring=False)


@install("aws.claude_a.guardduty.prowler_centrally_managed", "guardduty_detector", "GuardDuty detector has an administrator or member accounts (Prowler)",
    DET, w(DET, Administrator={"collection_status": "collected"}), rows=[P + "guardduty_centrally_managed"], severity="medium", control="SI-4",
    remediation="Manage GuardDuty centrally through an administrator account.", docs=[GD + "API_GetAdministratorAccount.html", GD + "API_ListMembers.html"],
    extra={"pass_members": w(DET, Administrator={"collection_status": "collected"}, Members={"collection_status": "collected", "items": [{"AccountId": "1"}]})},
    note="Needs guardduty:GetAdministratorAccount and ListMembers (collector facts).")
def centrally_managed(item, index):
    admin = (collected(item, "Administrator").get("Administrator") or {}).get("AccountId")
    members = get(collected(item, "Members"), "items", list)
    return result(not admin and not members, administrator=bool(admin), members=len(members))


@install("aws.claude_a.guardduty.prowler_no_high_severity_findings", "guardduty_detector", "GuardDuty detector has no active severity-8 findings (Prowler)",
    DET, w(DET, HighSeverityFindingIds={"collection_status": "collected", "items": ["f1"]}), rows=[P + "guardduty_no_high_severity_findings"],
    severity="high", control="SI-4", remediation="Investigate and remediate high-severity GuardDuty findings.", docs=[GD + "API_ListFindings.html"],
    note="Prowler ListFindings criteria severity Eq ['8'] and service.archived Eq ['false'] (collector fact HighSeverityFindingIds); any detector status.")
def high_findings(item, index):
    found = get(collected(item, "HighSeverityFindingIds"), "items", list)
    return result(bool(found), findings=len(found))


ADMIN = {"AdminAccountId": "999999999999", "AdminStatus": "ENABLED"}


@install("aws.claude_a.guardduty.prowler_delegated_admin_region", "guardduty_detector", "Region has a GuardDuty delegated administrator, enabled detector and auto-enable (Prowler)",
    {}, {}, target="scope", pass_index=idx(guardduty_detector=[DET], guardduty_organization_admin_account=[ADMIN]),
    fail_index=idx(guardduty_detector=[], guardduty_organization_admin_account=[ADMIN]),
    dependencies=["guardduty_detector", "guardduty_organization_admin_account"], rows=[P + "guardduty_delegated_admin_enabled_all_regions"],
    severity="medium", control="SI-4", remediation="Designate a GuardDuty delegated administrator and auto-enable members in every region.",
    docs=[GD + "API_ListOrganizationAdminAccounts.html", GD + "API_DescribeOrganizationConfiguration.html"],
    extra={"fail_no_admin": ({}, idx(guardduty_detector=[DET], guardduty_organization_admin_account=[])),
           "fail_auto": ({}, idx(guardduty_detector=[w(DET, OrganizationConfiguration__AutoEnableOrganizationMembers="NONE")], guardduty_organization_admin_account=[ADMIN]))},
    note="No detector or a disabled detector fails without further facts. A denied admin lookup with no other issue is UNKNOWN (Prowler MANUAL); "
         "a denied organization configuration is UNKNOWN unless another issue already fails.")
def gd_delegated_admin(context, index):
    detectors = items(index, "guardduty_detector")
    if not detectors or not any(detector_enabled(d) for d in detectors):
        return result(True, issue="detector not enabled")
    admins = items(index, "guardduty_organization_admin_account")
    if not any(get(a, "AdminStatus", str) == "ENABLED" for a in admins):
        return result(True, issue="no delegated administrator configured")
    for d in detectors:
        if not detector_enabled(d):
            return result(True, issue="detector not enabled")
        mode = get(collected(d, "OrganizationConfiguration"), "AutoEnableOrganizationMembers", str)
        if mode not in ("NEW", "ALL"):
            return result(True, issue="organization auto-enable not configured")
    return result(False, delegated_admin=True)


# =========================================================================== KMS
META = {"KeyId": "k1", "Arn": "arn:aws:kms:us-east-1:%s:key/k1" % ACCOUNT, "KeyManager": "CUSTOMER", "KeyState": "Enabled", "Enabled": True,
        "Origin": "AWS_KMS", "KeySpec": "SYMMETRIC_DEFAULT", "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT", "MultiRegion": False}
KEY_POLICY = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::%s:root" % ACCOUNT}, "Action": "kms:*", "Resource": "*"}]}
PUBLIC_POLICY = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "kms:Decrypt", "Resource": "*"}]}
KEY = {"KeyId": "k1", "KeyArn": META["Arn"], "Metadata": {"KeyMetadata": META}, "Rotation": {"KeyRotationEnabled": True},
       "Policy": {"Policy": KEY_POLICY, "PolicyName": "default"}}
AWS_KEY = w(KEY, Metadata__KeyMetadata__KeyManager="AWS")


def meta(item, field, expected=str):
    return get(item, "Metadata.KeyMetadata." + field, expected)


def customer(item):
    manager = meta(item, "KeyManager")
    if manager not in ("AWS", "CUSTOMER"):
        raise Unavailable("unrecognized key manager")
    return manager == "CUSTOMER"


def key_policy(item):
    return policy_document(get(item, "Policy.Policy"))


KMS_KEYS = ("kms:calleraccount",) + TURBOT_KEYS


@install("aws.claude_a.kms.key_policy_not_public", "kms_key", "Customer managed KMS key policy has no unrestricted public statement",
    KEY, w(KEY, Policy__Policy=PUBLIC_POLICY), rows=[C + "kms_cmk_policy_prohibit_public_access", C + "foundational_security_kms_5",
                                                      R + "kms_key_policy_prohibit_public_access"],
    severity="critical", category="exposure", control="AC-3", remediation="Replace wildcard principals in the key policy or add account/organization conditions.",
    docs=[KMS + "API_GetKeyPolicy.html", FSBP + "kms-controls.html#kms-5"], extra={"na": AWS_KEY,
        "pass_conditioned": w(KEY, Policy__Policy={"Statement": [dict(PUBLIC_POLICY["Statement"][0], Condition={"StringEquals": {"kms:CallerAccount": ACCOUNT}})]})},
    note="Allow + Principal * without kms:CallerAccount/aws:SourceOwner/SourceAccount/PrincipalOrgID/PrincipalAccount/PrincipalArn/SourceArn restriction; "
         "StringLike/ArnEquals/ArnLike of '*' do not restrict. Compliance and perimeter queries are identical.")
def key_policy_public(item, index):
    if not customer(item):
        return "NOT_APPLICABLE", {"reason": "AWS managed key"}
    bad = turbot_public_statements(key_policy(item), KMS_KEYS, arn_equals_wildcard=True)
    return result(bool(bad), public_statements=len(bad))


@install("aws.claude_a.kms.customer_key_enabled_or_pending_deletion", "kms_key", "Customer managed KMS key is enabled or scheduled for deletion",
    KEY, w(KEY, Metadata__KeyMetadata__Enabled=False, Metadata__KeyMetadata__KeyState="Disabled"), rows=[C + "kms_cmk_unused"],
    severity="low", control="CM-7", remediation="Delete (schedule deletion of) disabled customer managed keys that are no longer needed.",
    docs=[KMS + "API_KeyMetadata.html"], extra={"na": AWS_KEY, "pass_pending": w(KEY, Metadata__KeyMetadata__Enabled=False, Metadata__KeyMetadata__KeyState="PendingDeletion")},
    note="Steampipe reads the Enabled flag: not enabled and KeyState <> PendingDeletion alarms.")
def cmk_unused(item, index):
    if not customer(item):
        return "NOT_APPLICABLE", {"reason": "AWS managed key"}
    enabled, state = meta(item, "Enabled", bool), meta(item, "KeyState")
    return result(not enabled and state != "PendingDeletion", enabled=enabled, key_state=state)


@install("aws.claude_a.kms.customer_key_not_pending_deletion", "kms_key", "Customer managed KMS key is not pending deletion",
    w(KEY, Metadata__KeyMetadata__KeyState="Disabled", Metadata__KeyMetadata__Enabled=False), w(KEY, Metadata__KeyMetadata__KeyState="PendingDeletion"),
    rows=[C + "kms_key_not_pending_deletion", C + "foundational_security_kms_3"], severity="medium", control="SC-12",
    remediation="Cancel the scheduled deletion if the key is still needed.", docs=[KMS + "API_KeyMetadata.html", FSBP + "kms-controls.html#kms-3"],
    extra={"na": AWS_KEY}, note="Every key state other than PendingDeletion is ok (disabled keys included).")
def not_pending(item, index):
    if not customer(item):
        return "NOT_APPLICABLE", {"reason": "AWS managed key"}
    state = meta(item, "KeyState")
    return result(state == "PendingDeletion", key_state=state)


@install("aws.claude_a.kms.prowler_cmk_used", "kms_key", "Customer managed KMS key is Enabled or PendingDeletion (Prowler)",
    KEY, w(KEY, Metadata__KeyMetadata__KeyState="Disabled"), rows=[P + "kms_cmk_are_used"], severity="medium", control="CM-7",
    remediation="Re-enable or schedule deletion of unused customer managed keys.", docs=[KMS + "API_KeyMetadata.html"], extra={"na": AWS_KEY})
def cmk_used(item, index):
    if not customer(item):
        return "NOT_APPLICABLE", {"reason": "AWS managed key"}
    state = meta(item, "KeyState")
    return result(state not in ("Enabled", "PendingDeletion"), key_state=state)


def enabled_customer(item):
    return customer(item) and meta(item, "KeyState") == "Enabled"


@install("aws.claude_a.kms.prowler_cmk_single_region", "kms_key", "Enabled customer managed KMS key is not multi-Region (Prowler)",
    KEY, w(KEY, Metadata__KeyMetadata__MultiRegion=True), rows=[P + "kms_cmk_not_multi_region"], severity="medium", control="SC-12",
    remediation="Use single-Region keys unless multi-Region replication is required and reviewed.", docs=[KMS + "API_KeyMetadata.html"],
    extra={"na": w(KEY, Metadata__KeyMetadata__KeyState="Disabled")})
def single_region(item, index):
    if not enabled_customer(item):
        return "NOT_APPLICABLE", {"reason": "not an enabled customer managed key"}
    multi = meta(item, "MultiRegion", bool)
    return result(multi, multi_region=multi)


@install("aws.claude_a.kms.prowler_cmk_rotation", "kms_key", "Enabled symmetric customer managed KMS key has rotation enabled (Prowler)",
    KEY, w(KEY, Rotation={"KeyRotationEnabled": False}), rows=[P + "kms_cmk_rotation_enabled"], severity="medium", control="SC-12",
    remediation="Enable automatic key rotation.", docs=[KMS + "API_GetKeyRotationStatus.html"],
    extra={"na": w(KEY, Metadata__KeyMetadata__CustomerMasterKeySpec="RSA_2048"), "fail_external": w(KEY, Metadata__KeyMetadata__Origin="EXTERNAL", Rotation=DROP)},
    note="'SYMMETRIC' substring of CustomerMasterKeySpec; Prowler does not read rotation for EXTERNAL* origins, which therefore fail.")
def prowler_rotation(item, index):
    if not enabled_customer(item) or "SYMMETRIC" not in meta(item, "CustomerMasterKeySpec"):
        return "NOT_APPLICABLE", {"reason": "not an enabled symmetric customer managed key"}
    if "EXTERNAL" in meta(item, "Origin"):
        return result(True, rotation_enabled=None, origin=meta(item, "Origin"))
    enabled = get(item, "Rotation.KeyRotationEnabled", bool)
    return result(not enabled, rotation_enabled=enabled)


@install("aws.claude_a.kms.prowler_key_not_public", "kms_key", "Enabled customer managed KMS key policy is not public (Prowler)",
    KEY, w(KEY, Policy__Policy=PUBLIC_POLICY), index=idx(), rows=[P + "kms_key_not_publicly_accessible"], severity="high", category="exposure",
    control="AC-3", remediation="Remove public principals from the key policy or add restrictive conditions.", docs=[KMS + "API_GetKeyPolicy.html"],
    extra={"na": AWS_KEY}, note="Prowler is_policy_public(policy, audited account, not_allowed_actions=[]) with cross-account allowed.")
def prowler_kms_public(item, index):
    if not enabled_customer(item):
        return "NOT_APPLICABLE", {"reason": "not an enabled customer managed key"}
    public = is_policy_public(key_policy(item), account(index))
    return result(bool(public), public=bool(public))


# =========================================================================== CloudTrail
TRAIL = {"Name": "main", "TrailARN": "arn:aws:cloudtrail:us-east-1:%s:trail/main" % ACCOUNT, "HomeRegion": "us-east-1",
         "IsMultiRegionTrail": True, "IsOrganizationTrail": False, "Status": {"IsLogging": True}}


@install("aws.claude_a.cloudtrail.account_has_logging_multi_region_trail", "cloudtrail", "Account has a logging multi-Region CloudTrail trail",
    {}, {}, target="scope", pass_index=idx(cloudtrail=[TRAIL]), fail_index=idx(cloudtrail=[w(TRAIL, IsMultiRegionTrail=False)]),
    rows=[C + "foundational_security_cloudtrail_1"], severity="high", control="AU-2",
    remediation="Create a multi-Region trail that is logging (or rely on a logging organization trail).",
    docs=["https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_DescribeTrails.html", FSBP + "cloudtrail-controls.html#cloudtrail-1"],
    extra={"na": ({}, idx(cloudtrail=[w(TRAIL, IsOrganizationTrail=True, Status={"collection_status": "denied"})])),
           "fail_none": ({}, idx(cloudtrail=[])), "fail_stopped": ({}, idx(cloudtrail=[w(TRAIL, Status__IsLogging=False)]))},
    note="Account-level result evaluated in each region scope (multi-Region trails are listed in every region). An organization trail whose "
         "status is unavailable is info (NOT_APPLICABLE) as in the source.")
def multi_region_trail(context, index):
    trails = items(index, "cloudtrail")
    unknown_status = False
    org_unknown = False
    for t in trails:
        multi = get(t, "IsMultiRegionTrail", bool)
        org = get(t, "IsOrganizationTrail", bool)
        try:
            logging = get(t, "Status.IsLogging", bool)
        except Unavailable:
            logging = None
        if multi and logging is True:
            return result(False, trail=t.get("Name"))
        if multi and logging is None:
            if org:
                org_unknown = True
            else:
                unknown_status = True
    if unknown_status:
        raise Unavailable("multi-Region trail logging status unavailable")
    if org_unknown:
        return "NOT_APPLICABLE", {"reason": "organization trail logging status unavailable (source info status)"}
    return result(True, trails=len(trails), multi_region_logging_trail_found=False,
                  observed="No collected multi-Region trail is confirmed to be actively logging.")


# =========================================================================== Organizations
ACCT_CFG = {"id": "account-configuration", "Partition": "aws", "Organization": {"collection_status": "collected", "OrganizationId": "o-abc1234567"},
            "DelegatedAdministrators": {"collection_status": "collected", "items": []}}
NO_ORG = w(ACCT_CFG, Organization={"collection_status": "empty", "absent": True})


def in_organization(item):
    org = get(item, "Organization", dict)
    if org.get("collection_status") == "empty" and org.get("absent") is True:
        return False
    if not get(org, "OrganizationId", str).startswith("o-"):
        raise Unavailable("malformed organization id")
    return True


@install("aws.claude_a.organizations.no_untrusted_delegated_administrators", "aws_account_configuration",
    "Organization has no delegated administrators outside the trusted list (Prowler)",
    ACCT_CFG, w(ACCT_CFG, DelegatedAdministrators={"collection_status": "collected", "items": [{"Id": "999999999999"}]}),
    rows=[P + "organizations_delegated_administrators"], severity="medium", control="AC-2",
    remediation="Review delegated administrators and deregister untrusted ones.", docs=[ORG + "API_ListDelegatedAdministrators.html"],
    extra={"na": NO_ORG}, note="Prowler trusted list (organizations_trusted_delegated_administrators) defaults to empty, so any delegated administrator fails. "
                               "Needs organizations:ListDelegatedAdministrators (collector fact).")
def delegated_admins(item, index):
    if not in_organization(item):
        return "NOT_APPLICABLE", {"reason": "account not in an organization"}
    admins = list_of_objects(get(collected(item, "DelegatedAdministrators"), "items", list))
    return result(bool(admins), delegated_administrators=[a.get("Id") for a in admins])


OPT_OUT = {"Id": "p-ai", "Type": "AISERVICES_OPT_OUT_POLICY", "Content": {"services": {"default": {"opt_out_policy": {
    "@@assign": "optOut", "@@operators_allowed_for_child_policies": ["@@none"]}}}}, "Targets": [{"TargetId": "r-1"}]}
SCP = {"Id": "p-scp", "Type": "SERVICE_CONTROL_POLICY", "Content": {"Statement": [{"Effect": "Deny", "NotAction": "iam:*", "Resource": "*",
       "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["us-east-1"]}}}]}, "Targets": [{"TargetId": ACCOUNT}]}
TAGP = {"Id": "p-tag", "Type": "TAG_POLICY", "Content": {"tags": {}}, "Targets": [{"TargetId": "r-1"}]}


def org_policies(index, kind_type):
    configs = items(index, "aws_account_configuration")
    if len(configs) != 1:
        raise Unavailable("account configuration unavailable")
    if not in_organization(configs[0]):
        return None
    out = []
    for p in items(index, "organization_policy"):
        if get(p, "Type", str) == kind_type:
            out.append(p)
    return out


def _org_index(*policies, org=ACCT_CFG):
    return idx(aws_account_configuration=[org], organization_policy=list(policies))


def _org_check(cid, title, row, kind_type, evaluate_policies, passing, failing, *, severity, remediation, docs, note):
    @install(cid, "organization_policy", title, {}, {}, target="scope", pass_index=_org_index(*passing), fail_index=_org_index(*failing),
             dependencies=["aws_account_configuration", "organization_policy"], rows=[P + row], severity=severity, control="CM-6",
             remediation=remediation, docs=docs, extra={"fail_not_in_org": ({}, _org_index(org=NO_ORG))}, note=note)
    def evaluate(context, index):
        policies = org_policies(index, kind_type)
        if policies is None:
            return result(True, reason="AWS Organizations is not in use")
        return evaluate_policies(policies, account(index)) if evaluate_policies is _deny_regions else evaluate_policies(policies)
    return evaluate


def _opt_out(policies):
    for p in policies:
        content = get(p, "Content", dict)
        opt = content.get("services", {}).get("default", {}).get("opt_out_policy", {})
        if opt.get("@@assign") == "optOut" and opt.get("@@operators_allowed_for_child_policies") == ["@@none"]:
            return result(False, policy=p.get("Id"), opt_out_content_match=True)
    return result(True, policies=len(policies), opt_out_content_match=False)


# https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_aws_deny-requested-region.html
GLOBAL_ONLY_SERVICES = frozenset({"cloudfront", "iam", "organizations", "route53", "support",
                                  "budgets", "globalaccelerator", "importexport", "waf"})


def _deny_regions(policies, account_id):
    indirect = False
    unproven = False
    for p in policies:
        targets = list_of_objects(get(p, "Targets", list))
        direct = any(t.get("TargetId") == account_id for t in targets)
        # Content may be the raw DescribePolicy JSON string; Statement a dict or
        # a (frozen) list. isinstance, not type(), since snapshot lists are frozen.
        for s in policy_document(p.get("Content")):
            cond = s.get("Condition")
            if cond is None:
                continue
            if not isinstance(cond, dict):
                raise Unavailable("malformed SCP statement condition")
            block = cond.get("StringNotEquals") if s.get("Effect") == "Deny" else None
            if block is not None and not isinstance(block, dict):
                raise Unavailable("malformed SCP condition operator block")
            if block and "aws:RequestedRegion" in block:
                regions = block["aws:RequestedRegion"]
                if (not isinstance(regions, (str, list, tuple)) or not regions or
                        not all(isinstance(r, str) and r for r in (regions if isinstance(regions, (list, tuple)) else [regions]))):
                    raise Unavailable("approved region set unavailable")
                # Extra condition keys are ANDed with the region test. A scoped
                # resource or empty NotAction likewise cannot prove broad denial.
                actions = s.get("Action")
                exclusions = s.get("NotAction")
                excluded_actions = exclusions if isinstance(exclusions, (list, tuple)) else [exclusions]
                # NotAction may exempt only documented single-endpoint global services
                # (IAM user guide deny-requested-region example); ec2:*, *:* etc. stay unproven.
                broad_action = ((actions == "*" or actions == ["*"]) and "NotAction" not in s) or (
                    exclusions and all(isinstance(a, str) and a.count(":") == 1 and a.split(":")[0] in GLOBAL_ONLY_SERVICES
                                       and a.split(":")[1] for a in excluded_actions)
                    and "Action" not in s)
                resources = s.get("Resource")
                broad_resource = (resources == "*" or resources == ["*"]) and "NotResource" not in s
                broad_condition = len(cond) == 1 and len(block) == 1
                if not (broad_action and broad_resource and broad_condition):
                    if direct:
                        unproven = True
                    elif targets:
                        indirect = True
                    continue
                if direct:
                    return result(False, policy=p.get("Id"), approved_regions=regions, direct_region_deny_match=True)
                if targets:
                    indirect = True
    if indirect or unproven:
        return "MANUAL", {"reason": "Region-deny policies are collected, but inheritance or additional conditions require effective-SCP review", "indirect_targets": indirect, "additional_conditions_or_scope": unproven, "policies": len(policies)}
    return result(True, policies=len(policies), direct_region_deny_match=False)


def _tag_attached(policies):
    attached = [p.get("Id") for p in policies if list_of_objects(get(p, "Targets", list))]
    return result(not attached, attached_tag_policies=attached)


ORG_NOTE = " Needs organizations:ListPolicies(Filter=type) + DescribePolicy + ListTargetsForPolicy (kind organization_policy, collector fact); not in an organization fails."
_org_check("aws.claude_a.organizations.ai_services_opt_out", "Organization opts out of AI services and blocks child overrides (Prowler)",
    "organizations_opt_out_ai_services_policy", "AISERVICES_OPT_OUT_POLICY", _opt_out, [OPT_OUT],
    [dict(OPT_OUT, Content={"services": {"default": {"opt_out_policy": {"@@assign": "optIn"}}}})], severity="low",
    remediation="Attach an AI services opt-out policy with @@assign optOut and @@operators_allowed_for_child_policies [@@none].",
    docs=[ORG + "API_DescribePolicy.html", "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_ai-opt-out.html"], note="Prowler." + ORG_NOTE)
_org_check("aws.claude_a.organizations.scp_restricts_regions", "Organization SCP restricts aws:RequestedRegion (Prowler)",
    "organizations_scp_check_deny_regions", "SERVICE_CONTROL_POLICY", _deny_regions, [SCP],
    [dict(SCP, Content={"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})], severity="low",
    remediation="Add an SCP that denies requests outside approved regions (aws:RequestedRegion).",
    docs=[ORG + "API_DescribePolicy.html", "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples_general.html"],
    note="Prowler with organizations_enabled_regions at its default [] (any region-restricting statement passes)." + ORG_NOTE)
_org_check("aws.claude_a.organizations.tag_policy_attached", "Organization has an attached tag policy (Prowler)",
    "organizations_tags_policies_enabled_and_attached", "TAG_POLICY", _tag_attached, [TAGP], [dict(TAGP, Targets=[])], severity="low",
    remediation="Create a tag policy and attach it to the organization root, OUs or accounts.",
    docs=[ORG + "API_ListTargetsForPolicy.html"], note="Prowler." + ORG_NOTE)


# =========================================================================== Security Hub
HUB = {"HubArn": "arn:aws:securityhub:us-east-1:%s:hub/default" % ACCOUNT,
       "EnabledStandards": {"collection_status": "collected", "items": [{"StandardsArn": "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"}]},
       "ProductSubscriptions": {"collection_status": "collected", "items": []},
       "OrganizationConfiguration": {"collection_status": "collected", "AutoEnable": True}}


@install("aws.claude_a.securityhub.enabled_with_standard_or_integration", "securityhub_hub", "Security Hub is enabled with a standard or an integration (Prowler)",
    {}, {}, target="scope", pass_index=idx(securityhub_hub=[HUB]),
    fail_index=idx(securityhub_hub=[w(HUB, EnabledStandards={"collection_status": "collected", "items": []})]),
    rows=[P + "securityhub_enabled"], severity="medium", control="SI-4", remediation="Enable Security Hub and at least one standard or integration.",
    docs=[SH + "API_DescribeHub.html", SH + "API_GetEnabledStandards.html", SH + "API_ListEnabledProductsForImport.html"],
    extra={"fail_none": ({}, idx(securityhub_hub=[])),
           "pass_integration": ({}, idx(securityhub_hub=[w(HUB, EnabledStandards={"collection_status": "collected", "items": []},
               ProductSubscriptions={"collection_status": "collected", "items": ["arn:aws:securityhub:us-east-1:%s:product-subscription/crowdstrike/crowdstrike-falcon" % ACCOUNT]})]))},
    note="Needs securityhub:DescribeHub/GetEnabledStandards/ListEnabledProductsForImport (kind securityhub_hub, collector fact); an empty regional list "
         "means DescribeHub returned InvalidAccessException (not enabled). Self-integrations containing /aws/securityhub are ignored.")
def securityhub_enabled(context, index):
    hubs = items(index, "securityhub_hub")
    if not hubs:
        return result(True, hub="not enabled")
    for hub in hubs:
        standards = get(collected(hub, "EnabledStandards"), "items", list)
        products = [p for p in strings(get(collected(hub, "ProductSubscriptions"), "items", list)) if "/aws/securityhub" not in p]
        if not standards and not products:
            return result(True, standards=0, integrations=0, standard_or_integration_found=False)
    return result(False, hubs=len(hubs), standard_or_integration_found=True)


SH_ADMIN = {"AccountId": "999999999999", "Status": "ENABLED"}


@install("aws.claude_a.securityhub.prowler_delegated_admin_region", "securityhub_hub", "Region has a Security Hub delegated administrator, active hub and auto-enable (Prowler)",
    {}, {}, target="scope", pass_index=idx(securityhub_hub=[HUB], securityhub_organization_admin_account=[SH_ADMIN]),
    fail_index=idx(securityhub_hub=[], securityhub_organization_admin_account=[SH_ADMIN]),
    dependencies=["securityhub_hub", "securityhub_organization_admin_account"], rows=[P + "securityhub_delegated_admin_enabled_all_regions"],
    severity="medium", control="SI-4", remediation="Designate a Security Hub delegated administrator and enable auto-enable in every region.",
    docs=[SH + "API_ListOrganizationAdminAccounts.html", SH + "API_DescribeOrganizationConfiguration.html"],
    extra={"fail_no_admin": ({}, idx(securityhub_hub=[HUB], securityhub_organization_admin_account=[])),
           "fail_auto": ({}, idx(securityhub_hub=[w(HUB, OrganizationConfiguration__AutoEnable=False)], securityhub_organization_admin_account=[SH_ADMIN]))},
    note="An inactive hub fails without further facts; denied admin lookup or organization configuration with no other issue is UNKNOWN (Prowler MANUAL).")
def sh_delegated_admin(context, index):
    hubs = items(index, "securityhub_hub")
    if not hubs:
        return result(True, issue="Security Hub not enabled")
    admins = items(index, "securityhub_organization_admin_account")
    if not any(get(a, "Status", str) == "ENABLED" for a in admins):
        return result(True, issue="no delegated administrator configured")
    for hub in hubs:
        if not get(collected(hub, "OrganizationConfiguration"), "AutoEnable", bool):
            return result(True, issue="organization auto-enable not configured")
    return result(False, delegated_admin=True)
