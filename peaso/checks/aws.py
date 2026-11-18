"""AWS configuration checks; boto3 response envelopes are retained as facts."""
from . import register, result, unknown
from .facts import Unavailable, field_check, get, guard, list_of_objects
from .fixtures import CASES


for args in [
    ("aws.ebs.encryption", "ebs_volume", "Encrypted", True, False, "EBS volume encryption is enabled"),
    ("aws.rds.encryption", "rds_instance", "StorageEncrypted", True, False, "RDS instance storage encryption is enabled"),
    ("aws.rds.cluster_encryption", "rds_cluster", "StorageEncrypted", True, False, "RDS cluster storage encryption is enabled"),
    ("aws.rds.deletion_protection", "rds_instance", "DeletionProtection", True, False, "RDS instance deletion protection is enabled"),
    ("aws.rds.cluster_deletion_protection", "rds_cluster", "DeletionProtection", True, False, "RDS cluster deletion protection is enabled"),
    ("aws.cloudtrail.multi_region", "cloudtrail", "IsMultiRegionTrail", True, False, "CloudTrail trail covers all regions"),
    ("aws.cloudtrail.log_validation", "cloudtrail", "LogFileValidationEnabled", True, False, "CloudTrail log file validation is enabled"),
    ("aws.cloudtrail.logging", "cloudtrail", "Status.IsLogging", True, False, "CloudTrail trail is actively logging"),
    ("aws.eks.private_endpoint", "eks_cluster", "Cluster.cluster.resourcesVpcConfig.endpointPrivateAccess", True, False, "EKS cluster provides a private API endpoint"),
    ("aws.ecr.scan_on_push", "ecr_repository", "imageScanningConfiguration.scanOnPush", True, False, "ECR repository enables scan on push"),
    ("aws.secretsmanager.rotation", "secret", "RotationEnabled", True, False, "Secrets Manager secret rotation is enabled"),
    ("aws.iam.no_root_keys", "iam_account_summary", "SummaryMap.AccountAccessKeysPresent", 0, 1, "Root account has no access keys"),
]:
    cid, kind, path, good, bad, title = args
    field_check(cid, "aws", kind, path, good, bad, title, expected=type(good))


def _native_optional(item, key, default, expected):
    """Use an AWS omission default only when the field was not read or was confirmed empty."""
    guard(item)
    coverage = item.get("_coverage", {})
    marker = coverage.get(key)
    if key not in item and (key not in coverage or
            isinstance(marker, dict) and marker.get("status") == "empty"):
        return default
    return get(item, key, expected)


@register("aws.rds.no_public_endpoint", "aws", "exposure", "rds_instance", "RDS instance avoids a public endpoint", "high", "SC-7", "Disable public accessibility or document the approved exposure and restrict network access.")
def rds_public(item, index):
    value = get(item, "PubliclyAccessible", bool)
    return result(value, publicly_accessible=value, semantics="Endpoint configuration, not tested network reachability")
CASES["aws.rds.no_public_endpoint"] = {"pass": {"PubliclyAccessible": False}, "fail": {"PubliclyAccessible": True}}


@register("aws.s3.versioning", "aws", "hardening", "bucket", "S3 bucket versioning is enabled", "medium", "CP-9", "Enable versioning and use lifecycle retention aligned with recovery needs.")
def versioning(item, index):
    config = get(item, "Versioning", dict)
    state = _native_optional(config, "Status", None, str)
    if state not in ("Enabled", "Suspended", None):
        return unknown("unrecognized S3 versioning state")
    return result(state != "Enabled", versioning_status=state or "not_enabled")
CASES["aws.s3.versioning"] = {"pass": {"Versioning": {"Status": "Enabled"}}, "fail": {"Versioning": {}}}


@register("aws.s3.access_logging", "aws", "hardening", "bucket", "S3 bucket has server access logging configured", "low", "AU-2", "Enable access logging to an appropriate protected bucket, or review a documented alternative data-access audit control.")
def logging(item, index):
    config = get(item, "Logging", dict)
    enabled = _native_optional(config, "LoggingEnabled", None, dict)
    if enabled is not None:
        get(enabled, "TargetBucket", str)
    return result(enabled is None, logging_enabled=enabled, semantics="CloudTrail data event coverage is a separate control")
CASES["aws.s3.access_logging"] = {"pass": {"Logging": {"LoggingEnabled": {"TargetBucket": "audit"}}}, "fail": {"Logging": {}}}


@register("aws.s3.no_public_acl", "aws", "exposure", "bucket", "S3 bucket ACL has no public group grants", "high", "AC-3", "Remove public ACL grants, disable ACLs where feasible, and review Public Access Block enforcement.")
def acl(item, index):
    grants = list_of_objects(get(item, "Acl.Grants", list))
    public, unresolved = [], []
    for grant in grants:
        try:
            grantee = get(grant, "Grantee", dict)
            uri = _native_optional(grantee, "URI", None, str)
            if uri in ("http://acs.amazonaws.com/groups/global/AllUsers", "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"):
                public.append(grant)
        except Unavailable as exc:
            unresolved.append(str(exc))
    if public:
        return "MANUAL", {"public_acl_grants": public, "reason": "Public ACL is declared; bucket/account IgnorePublicAcls and Object Ownership determine effectiveness"}
    if unresolved:
        return unknown("bucket ACL grantee facts unavailable", unresolved=unresolved)
    return result(False, public_acl_grants=[])
CASES["aws.s3.no_public_acl"] = {"pass": {"Acl": {"Grants": []}}, "manual": {"Acl": {"Grants": [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}]}}}


@register("aws.kms.rotation", "aws", "hardening", "kms_key", "Customer-managed symmetric KMS key rotation is enabled", "medium", "SC-12", "Enable automatic rotation for eligible symmetric customer-managed KMS keys.")
def rotation(item, index):
    metadata = get(item, "Metadata.KeyMetadata", dict)
    manager, origin, spec = (get(metadata, key, str) for key in ("KeyManager", "Origin", "KeySpec"))
    if manager == "AWS" or origin != "AWS_KMS" or spec != "SYMMETRIC_DEFAULT":
        return "NOT_APPLICABLE", {"key_metadata": metadata}
    enabled = get(item, "Rotation.KeyRotationEnabled", bool)
    return result(not enabled, rotation_enabled=enabled)
CASES["aws.kms.rotation"] = {state: {"Metadata": {"KeyMetadata": {"KeyManager": "CUSTOMER", "Origin": "AWS_KMS", "KeySpec": "SYMMETRIC_DEFAULT"}}, "Rotation": {"KeyRotationEnabled": v}} for state, v in (("pass", True), ("fail", False))}


_MANAGEMENT_SOURCE_DOMAINS = ("other", "kms.amazonaws.com", "rdsdata.amazonaws.com")


def _advanced_management_coverage(selector):
    """Prove source domains and read/write directions covered by one selector.

    Conditions inside one selector intersect; independent selectors union. CloudTrail
    permits the two named management-source exclusions, so finite source domains
    suffice for proving unrestricted coverage without assuming service inventory.
    """
    fields = list_of_objects(get(selector, "FieldSelectors", list))
    by_name = {}
    for field in fields:
        name = get(field, "Field", str)
        if name in by_name:
            raise Unavailable("repeated advanced management field: " + name)
        operators = set(field) - {"Field"}
        if not operators or operators - {"Equals", "NotEquals", "StartsWith", "NotStartsWith", "EndsWith", "NotEndsWith"}:
            raise Unavailable("unsupported advanced management operator")
        for operator in operators:
            values = get(field, operator, list)
            if not values or any(not isinstance(value, str) or not value for value in values):
                raise Unavailable("malformed advanced management filter")
        by_name[name] = field
    category = by_name.get("eventCategory")
    if category is None or set(category) != {"Field", "Equals"}:
        raise Unavailable("advanced eventCategory must use Equals")
    values = get(category, "Equals", list)
    if values not in (["Management"], ["Data"], ["NetworkActivity"]):
        raise Unavailable("unsupported advanced eventCategory")
    if values != ["Management"]:
        return set()
    if set(by_name) - {"eventCategory", "readOnly", "eventSource"}:
        raise Unavailable("unsupported advanced management field")
    read = by_name.get("readOnly")
    directions = {"read", "write"}
    if read is not None:
        if set(read) != {"Field", "Equals"}:
            raise Unavailable("unsupported advanced readOnly filter")
        values = get(read, "Equals", list)
        if any(value not in ("true", "false") for value in values):
            raise Unavailable("unsupported advanced readOnly value")
        directions = {direction for value, direction in (("true", "read"), ("false", "write")) if value in values}
    sources = set(_MANAGEMENT_SOURCE_DOMAINS)
    source = by_name.get("eventSource")
    if source is not None:
        if set(source) != {"Field", "NotEquals"}:
            raise Unavailable("unsupported advanced eventSource filter")
        excluded = get(source, "NotEquals", list)
        if any(value not in ("kms.amazonaws.com", "rdsdata.amazonaws.com") for value in excluded):
            raise Unavailable("unsupported advanced eventSource exclusion")
        sources.difference_update(excluded)
    return {(direction, source) for direction in directions for source in sources}


@register("aws.cloudtrail.management_events", "aws", "hardening", "cloudtrail", "CloudTrail records both read and write management events", "high", "AU-2", "Configure complete management event selectors and review excluded event sources.")
def trail_events(item, index):
    selectors = get(item, "EventSelectors", dict)
    # A successful native GetEventSelectors read must belong to this trail.
    # Legacy hand-authored facts omit collection_status and retain prior behavior.
    if selectors.get("collection_status") == "collected":
        if get(selectors, "TrailARN", str) != get(item, "TrailARN", str):
            return unknown("CloudTrail selector response trail identity mismatch")
    advanced = _native_optional(selectors, "AdvancedEventSelectors", [], list)
    if advanced:
        rows = list_of_objects(advanced)
        basic = _native_optional(selectors, "EventSelectors", [], list)
        if basic:
            return unknown("basic and advanced CloudTrail selectors cannot coexist")
        covered, unresolved = set(), []
        for row in rows:
            try:
                covered.update(_advanced_management_coverage(row))
            except Unavailable as exc:
                unresolved.append(str(exc))
        required = {(direction, source) for direction in ("read", "write")
                    for source in _MANAGEMENT_SOURCE_DOMAINS}
        if required <= covered:
            return result(False, advanced_event_selectors=rows)
        if unresolved:
            return unknown("advanced management event coverage unresolved", unresolved=unresolved)
        return result(True, advanced_event_selectors=rows)
    rows = list_of_objects(get(selectors, "EventSelectors", list))
    complete, unresolved = False, []
    for row in rows:
        try:
            if not get(row, "IncludeManagementEvents", bool):
                continue
            read_write = get(row, "ReadWriteType", str)
            excluded = _native_optional(row, "ExcludeManagementEventSources", [], list)
            if any(not isinstance(source, str) for source in excluded):
                raise Unavailable("malformed excluded management event sources")
            if read_write == "All" and not excluded:
                complete = True
        except Unavailable as exc:
            unresolved.append(str(exc))
    if complete:
        return result(False, event_selectors=rows)
    if unresolved:
        return unknown("management event selector facts unavailable", unresolved=unresolved)
    return result(True, event_selectors=rows)
CASES["aws.cloudtrail.management_events"] = {"pass": {"EventSelectors": {"EventSelectors": [{"IncludeManagementEvents": True, "ReadWriteType": "All"}]}}, "fail": {"EventSelectors": {"EventSelectors": []}}}


@register("aws.eks.control_plane_logging", "aws", "hardening", "eks_cluster", "EKS enables all control-plane log categories", "medium", "AU-2", "Enable API, audit, authenticator, controllerManager and scheduler logs.")
def eks_logging(item, index):
    rows = list_of_objects(get(item, "Cluster.cluster.logging.clusterLogging", list))
    enabled = set()
    for row in rows:
        if get(row, "enabled", bool):
            types = get(row, "types", list)
            if not all(isinstance(t, str) for t in types):
                return unknown("malformed EKS log categories")
            enabled.update(types)
    missing = sorted({"api", "audit", "authenticator", "controllerManager", "scheduler"} - enabled)
    return result(bool(missing), enabled_categories=sorted(enabled), missing_categories=missing)
CASES["aws.eks.control_plane_logging"] = {"pass": {"Cluster": {"cluster": {"logging": {"clusterLogging": [{"enabled": True, "types": ["api", "audit", "authenticator", "controllerManager", "scheduler"]}]}}}}, "fail": {"Cluster": {"cluster": {"logging": {"clusterLogging": []}}}}}


@register("aws.iam.access_key_count", "aws", "hardening", "iam_user", "IAM user avoids multiple active long-lived access keys", "medium", "IA-5", "Review key rotation overlap and prefer short-lived role credentials.")
def key_count(item, index):
    keys = list_of_objects(get(item, "AccessKeys.items", list))
    active, unresolved = 0, []
    for key in keys:
        try:
            status = get(key, "Status", str)
            if status not in ("Active", "Inactive"):
                raise Unavailable("unrecognized access key status")
            active += status == "Active"
        except Unavailable as exc:
            unresolved.append(str(exc))
    if active > 1:
        return result(True, active_key_count=active)
    if unresolved:
        return unknown("access key status unavailable", active_key_count=active, unresolved=unresolved)
    return result(False, active_key_count=active)
CASES["aws.iam.access_key_count"] = {"pass": {"AccessKeys": {"collection_status": "collected", "items": [{"Status": "Active"}]}}, "fail": {"AccessKeys": {"collection_status": "collected", "items": [{"Status": "Active"}, {"Status": "Active"}]}}}


@register("aws.logs.retention", "aws", "hardening", "log_group", "CloudWatch log group has a retention policy", "low", "AU-11", "Set explicit retention consistent with incident response and regulatory needs.")
def retention(item, index):
    get(item, "logGroupName", str)
    days = _native_optional(item, "retentionInDays", None, int)
    if days is None:
        return result(True, retention="never_expire", semantics="Valid API omission means unlimited retention; review intentional retention and cost")
    if days <= 0:
        return unknown("invalid retention duration")
    return result(False, retention_days=days)
CASES["aws.logs.retention"] = {"pass": {"logGroupName": "audit", "retentionInDays": 90}, "fail": {"logGroupName": "audit"}}


@register("aws.rds.backups", "aws", "hardening", "rds_instance", "RDS automatic backup retention is nonzero", "medium", "CP-9", "Enable automated backups with retention suitable for recovery requirements.")
def backups(item, index):
    guard(item)
    field = "ReadReplicaSourceDBInstanceIdentifier"
    coverage = item.get("_coverage", {})
    marker = coverage.get(field)
    replica = ""
    empty_omission = field not in item and isinstance(marker, dict) and marker.get("status") == "empty"
    if not empty_omission and (field in item or field in coverage):
        replica = get(item, field, str)
    if replica:
        return "NOT_APPLICABLE", {"reason": "Read replica backup eligibility needs separate engine/version policy review"}
    days = get(item, "BackupRetentionPeriod", int)
    if not 0 <= days <= 35:
        return unknown("invalid RDS backup retention")
    return result(days == 0, backup_retention_days=days)
CASES["aws.rds.backups"] = {"pass": {"BackupRetentionPeriod": 7}, "fail": {"BackupRetentionPeriod": 0}}


@register("aws.iam.root_mfa", "aws", "hardening", "iam_credential_report", "Root credentials have MFA configured", "high", "IA-2", "Enable MFA on existing root credentials or centrally remove unused root credentials where supported.")
def root_mfa(item, index):
    user = get(item, "user", str)
    if user != "<root_account>":
        return "NOT_APPLICABLE", {"reason": "Root-only credential control"}
    flags = {key: get(item, key, str) for key in ("password_enabled", "access_key_1_active", "access_key_2_active", "mfa_active")}
    if any(value not in ("true", "false") for value in flags.values()):
        return unknown("malformed credential report boolean")
    if all(flags[key] == "false" for key in ("password_enabled", "access_key_1_active", "access_key_2_active")):
        return "NOT_APPLICABLE", {"reason": "Root has no active password or key credentials"}
    return result(flags["mfa_active"] != "true", credential_flags=flags)
CASES["aws.iam.root_mfa"] = {state: {"user": "<root_account>", "password_enabled": "true", "access_key_1_active": "false", "access_key_2_active": "false", "mfa_active": flag} for state, flag in (("pass", "true"), ("fail", "false"))}


@register("aws.ecr.immutable_tags", "aws", "hardening", "ecr_repository", "ECR repository enforces immutable tags", "medium", "CM-6", "Enable immutable release tags and restrict mutable exclusions to signature tags.")
def ecr_immutable_tags(item, index):
    from .aws_b_ecr import immutable_tags
    return immutable_tags(item, index)
CASES["aws.ecr.immutable_tags"] = {"pass": {"imageTagMutability": "IMMUTABLE"}, "fail": {"imageTagMutability": "MUTABLE"}, "missing": {}, "malformed": {"imageTagMutability": None}}
