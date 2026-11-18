"""claude_aws_b database services: RDS, Neptune, Redshift, Redshift Serverless, MemoryDB, OpenSearch."""
from __future__ import annotations

from datetime import timedelta
import re

from . import result, unknown
from .facts import Unavailable, get, guard, list_of_objects, complete_items, optional
from .claude_aws_b_common import (install, flag, absent_or, strings, empty, clock, parse_time, account, policy_document,
    is_policy_public, kms_manager, protected_resources, selection_resources, subnet_is_public_prowler, subnet_is_public_turbot,
    explicit_igw_subnets, subnet_vpc, subnet_route_table, sg_rule_open, security_groups, add_months, scope_of, inventory, indexes, CONTEXT, ACCOUNT)

P, C, X = "prowler.aws.", "aws-compliance.control.", "aws-perimeter.control."
D_INST = "https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DBInstance.html"
D_CLUS = "https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DBCluster.html"
D_SNAP_ATTR = "https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBSnapshotAttributes.html"
D_CSNAP_ATTR = "https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBClusterSnapshotAttributes.html"
D_EVENTS = "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Events.Messages.html"
D_BACKUP_SEL = "https://docs.aws.amazon.com/aws-backup/latest/devguide/API_BackupSelection.html"
D_BACKUP_PR = "https://docs.aws.amazon.com/aws-backup/latest/devguide/API_ProtectedResource.html"
D_PARAMS = "https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBParameters.html"
D_CPARAMS = "https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBClusterParameters.html"
D_NEPTUNE = "https://docs.aws.amazon.com/neptune/latest/apiref/API_DBCluster.html"
D_REDSHIFT = "https://docs.aws.amazon.com/redshift/latest/APIReference/API_Cluster.html"
D_OS = "https://docs.aws.amazon.com/opensearch-service/latest/APIReference/API_DomainStatus.html"

INST_ARN = "arn:aws:rds:us-east-1:111111111111:db:db1"
CLUS_ARN = "arn:aws:rds:us-east-1:111111111111:cluster:c1"
KMS_ARN = "arn:aws:kms:us-east-1:111111111111:key/k1"


def _rds_parameter_text(values, name):
    """RDS names contain dots, so read their literal dictionary keys."""
    guard(values)
    if name not in values:
        raise Unavailable("missing RDS parameter: " + name)
    literal = {"value": values[name]}
    if name in values.get("_coverage", {}):
        literal["_coverage"] = {"value": values["_coverage"][name]}
    return get(literal, "value", str)


def _rds_binary_parameter(values, name):
    """Interpret only the documented RDS parameter string spellings."""
    value = _rds_parameter_text(values, name)
    if value in ("1", "ON"):
        return True, value
    if value in ("0", "OFF"):
        return False, value
    raise Unavailable("unrecognized RDS parameter value: " + name)


def _mariadb_secure_transport_applicable(item):
    """The MariaDB parameter exists from engine version 10.5 onward."""
    version = get(item, "EngineVersion", str)
    components = version.split(".")
    if len(components) < 2 or not all(part.isdecimal() for part in components[:2]):
        raise Unavailable("unrecognized MariaDB engine version")
    return (int(components[0]), int(components[1])) >= (10, 5)


def _kms_index(manager="CUSTOMER"):
    return inventory("kms_key", [{"Metadata": {"KeyMetadata": {"Arn": KMS_ARN, "KeyId": "k1", "KeyManager": manager}}}])


def _not_docdb(item):
    engine = get(item, "Engine", str)
    return {"engine": engine, "reason": "Prowler RDS service excludes DocumentDB"} if engine == "docdb" else None


def _engine_is(*engines, contains=False):
    def applies(item):
        engine = get(item, "Engine", str)
        ok = any(e in engine for e in engines) if contains else engine in engines
        return None if ok else {"engine": engine, "applicable_engines": list(engines)}
    return applies


def _exports(item, sentinel):
    value = absent_or(item, sentinel, "EnabledCloudwatchLogsExports", [], list)
    return strings(value, "EnabledCloudwatchLogsExports")


# =========================================================================== RDS clusters
@install("aws.cb.rds.cluster_backtrack_window_positive", "rds_cluster", "Supported Aurora MySQL cluster has a positive backtrack window",
    {"DBClusterArn": CLUS_ARN, "Engine": "aurora-mysql", "EngineVersion": "8.0.mysql_aurora.3.08.2", "BacktrackWindow": 86400},
    {"DBClusterArn": CLUS_ARN, "Engine": "aurora-mysql", "EngineVersion": "8.0.mysql_aurora.3.08.2", "BacktrackWindow": 0},
    rows=[P + "rds_cluster_backtrack_enabled"], severity="low",
    remediation="For an existing disabled cluster, review a replacement or snapshot restore created with Backtrack enabled; it cannot be enabled in place.",
    docs=[D_CLUS, "https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraMySQL.Managing.Backtrack.html"],
    extra={"not_applicable": {"DBClusterArn": CLUS_ARN, "Engine": "aurora-postgresql"}},
    note="Prowler's source row did not gate Region/version, but AWS supports Backtrack only for Aurora MySQL 2, 3 and 8.4 in documented Regions (reviewed 2026-10-12). Reuse the exact reviewed applicability and positive-window predicate of aurora_backtracking_configured; missing evidence is UNKNOWN.")
def cluster_backtrack(item, index):
    return aurora_backtracking(item, index)


_BACKTRACK_REGIONS = frozenset({
    "us-east-1", "us-east-2", "us-west-1", "us-west-2", "ap-south-1", "ap-northeast-3",
    "ap-northeast-2", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ca-central-1",
    "eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3",
})
_NO_BACKTRACK_REGIONS = frozenset({
    "af-south-1", "ap-east-1", "ap-southeast-3", "ap-southeast-5", "ap-southeast-4",
    "ap-southeast-6", "ap-east-2", "ap-southeast-7", "ca-west-1", "cn-north-1",
    "cn-northwest-1", "eu-south-1", "eu-south-2", "eu-north-1", "eu-central-2",
    "il-central-1", "mx-central-1", "me-south-1", "me-central-1", "sa-east-1",
    "us-gov-east-1", "us-gov-west-1",
})


@install("aws.cb.rds.aurora_backtracking_configured", "rds_cluster", "Supported Aurora MySQL cluster has Backtrack enabled with a positive window",
    {"DBClusterArn": CLUS_ARN, "Engine": "aurora-mysql", "EngineVersion": "8.0.mysql_aurora.3.08.2", "BacktrackWindow": 86400},
    {"DBClusterArn": CLUS_ARN, "Engine": "aurora-mysql", "EngineVersion": "8.0.mysql_aurora.3.08.2", "BacktrackWindow": 0},
    rows=[C + "rds_db_cluster_aurora_backtracking_enabled"], severity="low",
    remediation="Configure a Backtrack window on the Aurora MySQL cluster.", docs=[D_CLUS],
    extra={"not_applicable": {"DBClusterArn": CLUS_ARN, "Engine": "postgres"}},
    note="The pinned source required only a non-NULL window, but AWS says zero disables Backtrack. Applies to Aurora MySQL 2, 3, and 8.4 only in the documented Region/version table (reviewed 2026-10-12); a disabled existing cluster cannot be enabled by ModifyDBCluster and requires a separately reviewed replacement or restore.")
def aurora_backtracking(item, index):
    engine = get(item, "Engine", str)
    if engine != "aurora-mysql":
        return "NOT_APPLICABLE", {"engine": engine}
    version = get(item, "EngineVersion", str)
    v2 = re.fullmatch(r"5\.7\.mysql_aurora\.2\.(\d+)\.(\d+)", version)
    v3 = re.fullmatch(r"8\.0\.mysql_aurora\.3\.\d+\.\d+", version)
    v84 = re.fullmatch(r"8\.4\.mysql_aurora\.8\.4\.\d+", version)
    if not (v2 or v3 or v84):
        if re.fullmatch(r"5\.6\.mysql_aurora\.1\.\d+\.\d+", version):
            return "NOT_APPLICABLE", {"engine": engine, "engine_version": version, "reason": "Aurora MySQL version 1 is unsupported for Backtrack"}
        return unknown("unrecognized Aurora MySQL Backtrack engine version", engine_version=version)
    arn = get(item, "DBClusterArn", str)
    parts = arn.split(":")
    if len(parts) < 6 or parts[0] != "arn" or parts[2] != "rds" or not parts[3]:
        return unknown("RDS cluster ARN lacks a valid Region")
    region = parts[3]
    if region in _NO_BACKTRACK_REGIONS or (region == "ap-northeast-3" and v2 and (int(v2[1]), int(v2[2])) < (7, 3)):
        return "NOT_APPLICABLE", {"engine": engine, "engine_version": version, "region": region}
    if region not in _BACKTRACK_REGIONS:
        return unknown("Aurora Backtrack Region availability unreviewed", region=region)
    window = get(item, "BacktrackWindow", int)
    if window < 0 or window > 72 * 3600:
        return unknown("unrecognized Aurora Backtrack window", backtrack_window=window)
    return result(window == 0, backtrack_window=window, engine_version=version, region=region)


_CW_ENGINES = ("aurora-mysql", "aurora-postgresql", "mysql", "postgres")


@install("aws.cb.rds.cluster_cloudwatch_log_exports", "rds_cluster", "RDS cluster exports logs to CloudWatch Logs",
    {"DBClusterArn": CLUS_ARN, "Engine": "aurora-mysql", "EnabledCloudwatchLogsExports": ["audit"]}, {"DBClusterArn": CLUS_ARN, "Engine": "aurora-mysql"},
    rows=[P + "rds_cluster_integration_cloudwatch_logs"], severity="medium", control="AU-2",
    remediation="Enable CloudWatch Logs exports (EnabledCloudwatchLogsExports) for the cluster's engine log types.", docs=[D_CLUS],
    extra={"not_applicable": {"DBClusterArn": CLUS_ARN, "Engine": "neptune"}}, note="Prowler valid engines: aurora-mysql, aurora-postgresql, mysql, postgres.")
def cluster_cw(item, index):
    engine = get(item, "Engine", str)
    if engine not in _CW_ENGINES:
        return "NOT_APPLICABLE", {"engine": engine}
    exports = _exports(item, "DBClusterArn")
    return result(not exports, exports=exports)


@install("aws.cb.rds.multi_az_cluster_minor_upgrade", "rds_cluster", "Multi-AZ DB cluster enables automatic minor version upgrades",
    {"DBClusterArn": CLUS_ARN, "MultiAZ": True, "AutoMinorVersionUpgrade": True}, {"DBClusterArn": CLUS_ARN, "MultiAZ": True},
    rows=[P + "rds_cluster_minor_version_upgrade_enabled"], severity="medium",
    remediation="Enable AutoMinorVersionUpgrade on the Multi-AZ DB cluster.", docs=[D_CLUS],
    extra={"not_applicable": {"DBClusterArn": CLUS_ARN, "MultiAZ": False}},
    note="Prowler only evaluates MultiAZ clusters (AutoMinorVersionUpgrade applies to Multi-AZ DB clusters); absent flag is False.")
def cluster_minor(item, index):
    multi = get(item, "MultiAZ", bool)
    if not multi:
        return "NOT_APPLICABLE", {"multi_az": False}
    value = absent_or(item, "DBClusterArn", "AutoMinorVersionUpgrade", False, bool)
    return result(not value, auto_minor_version_upgrade=value)


_DEFAULT_PORTS = {3306: ("mysql", "mariadb", "aurora-mysql"), 5432: ("postgres", "aurora-postgresql"), 1521: ("oracle",), 1433: ("sqlserver",), 50000: ("db2",)}


def _default_port(engine, port):
    return any(name in engine.lower() for name in _DEFAULT_PORTS.get(port, ()))


for _kind, _path, _row, _arn in (("rds_cluster", "Port", "rds_cluster_non_default_port", "DBClusterArn"), ("rds_instance", "Endpoint.Port", "rds_instance_non_default_port", "DBInstanceArn")):
    def _port(kind, path, row, arn):
        from .fixtures import nest
        @install("aws.cb.rds." + kind.split("_")[1] + "_engine_default_port_prowler", kind, "RDS " + kind.split("_")[1] + " does not use its engine default port",
            {arn: "a", "Engine": "postgres", **nest(path, 15432)}, {arn: "a", "Engine": "postgres", **nest(path, 5432)},
            rows=[P + row], severity="low", category="network",
            remediation="Recreate or restore the database on a non-default port and update client configuration (port changes are obscurity, not access control).",
            docs=[D_CLUS if kind == "rds_cluster" else D_INST], extra={"not_applicable": {arn: "a", "Engine": "docdb", **nest(path, 27017)}},
            note="Prowler default port map includes db2 50000 and uses substring engine matching; distinct from the aws.b engine-default port policy.")
        def evaluate(item, index):
            skip = _not_docdb(item)
            if skip:
                return "NOT_APPLICABLE", skip
            engine = get(item, "Engine", str)
            port = get(item, path, int)
            return result(_default_port(engine, port), engine=engine, port=port)
    _port(_kind, _path, _row, _arn)


def _plan_index(resources):
    return inventory("backup_plan", [{"BackupPlanId": "p", "Selections": {"collection_status": "collected", "items": [{"SelectionId": "s", "Selection": {"BackupSelection": {"Resources": resources}}}]}}])


@install("aws.cb.rds.cluster_in_backup_plan_selection", "rds_cluster", "RDS cluster is selected by an AWS Backup plan",
    {"DBClusterArn": CLUS_ARN, "Engine": "aurora-mysql"}, {"DBClusterArn": CLUS_ARN, "Engine": "aurora-mysql"},
    rows=[P + "rds_cluster_protected_by_backup_plan"], severity="high", control="CP-9",
    remediation="Add the cluster ARN (or an rds cluster wildcard) to an AWS Backup plan resource selection.",
    docs=[D_BACKUP_SEL], dependencies=["rds_cluster", "backup_plan"],
    extra={"pass_index": _plan_index([CLUS_ARN]), "fail_index": _plan_index(["arn:aws:rds:us-east-1:111111111111:db:other"])},
    note="Prowler protected_resources are backup selection Resources; arn:<partition>:rds:*:*:cluster:* and * also count.")
def cluster_selected(item, index):
    skip = _not_docdb(item)
    if skip:
        return "NOT_APPLICABLE", skip
    arn = get(item, "DBClusterArn", str)
    partition = arn.split(":")[1] if arn.count(":") > 2 else "aws"
    resources = selection_resources(index)
    hit = arn in resources or ("arn:%s:rds:*:*:cluster:*" % partition) in resources or "*" in resources
    return result(not hit, resource_arn=arn, backup_selection_match=hit)


def _instance_backup_selection(item, index, arn):
    from .aws_backup_selection import matches
    tags = None
    if "TagList" in item or "TagList" in item.get("_coverage", {}):
        tags = {}
        for tag in list_of_objects(get(item, "TagList", list)):
            key, value = get(tag, "Key", str), get(tag, "Value", str)
            if key in tags:
                raise Unavailable("ambiguous duplicate RDS resource tag")
            tags[key] = value
    found, uncertain = False, False
    for plan in complete_items(index, "backup_plan"):
        selections = get(plan, "Selections", dict)
        if selections.get("collection_status") not in ("collected", "empty"):
            raise Unavailable("backup selections unavailable")
        for selection in list_of_objects(get(selections, "items", list)):
            selected = matches(get(selection, "Selection.BackupSelection", dict), arn, tags)
            found |= selected is True
            uncertain |= selected is None
    if not found and uncertain:
        raise Unavailable("Backup tag selection needs complete resource tags or service opt-in evidence")
    return found


@install("aws.cb.rds.instance_in_backup_plan_selection", "rds_instance", "Non-Aurora RDS instance is selected by an AWS Backup plan",
    {"DBInstanceArn": INST_ARN, "Engine": "postgres"}, {"DBInstanceArn": INST_ARN, "Engine": "postgres"},
    rows=[P + "rds_instance_protected_by_backup_plan"], severity="high", control="CP-9",
    remediation="Add the DB instance ARN (or an rds instance wildcard) to an AWS Backup plan resource selection.",
    docs=[D_BACKUP_SEL], dependencies=["rds_instance", "backup_plan"],
    extra={"pass_index": _plan_index(["arn:aws:rds:*:*:db:*", INST_ARN]), "fail_index": _plan_index([]), "not_applicable": {"DBInstanceArn": INST_ARN, "Engine": "aurora-mysql"}},
    note="Prowler skips aurora, aurora-mysql and aurora-postgresql instances; matches the ARN, arn:<partition>:rds:*:*:instance:* or *.")
def instance_selected(item, index):
    engine = get(item, "Engine", str)
    if engine in ("aurora", "aurora-mysql", "aurora-postgresql", "docdb"):
        return "NOT_APPLICABLE", {"engine": engine}
    arn = get(item, "DBInstanceArn", str)
    partition = arn.split(":")[1] if arn.count(":") > 2 else "aws"
    hit = _instance_backup_selection(item, index, arn)
    return result(not hit, resource_arn=arn, backup_selection_match=hit)


def _protected_index(arn, rtype):
    return inventory("backup_protected_resource", [{"ResourceArn": arn, "ResourceType": rtype}])


@install("aws.cb.rds.aurora_cluster_protected_resource", "rds_cluster", "Aurora cluster is an AWS Backup protected resource",
    {"DBClusterArn": CLUS_ARN, "Engine": "aurora-postgresql"}, {"DBClusterArn": CLUS_ARN, "Engine": "aurora-postgresql"},
    rows=[C + "rds_db_cluster_aurora_protected_by_backup_plan"], severity="medium", control="CP-9",
    remediation="Protect the Aurora cluster with an AWS Backup plan so recovery points exist.", docs=[D_BACKUP_PR],
    dependencies=["rds_cluster", "backup_protected_resource"],
    extra={"pass_index": _protected_index(CLUS_ARN, "Aurora"), "fail_index": _protected_index(CLUS_ARN, "RDS"), "not_applicable": {"DBClusterArn": CLUS_ARN, "Engine": "mysql"}})
def aurora_protected(item, index):
    engine = get(item, "Engine", str)
    if "aurora" not in engine:
        return "NOT_APPLICABLE", {"engine": engine}
    arn = get(item, "DBClusterArn", str)
    hit = any(get(r, "ResourceArn", str) == arn and get(r, "ResourceType", str) == "Aurora" for r in protected_resources(index))
    return result(not hit, resource_arn=arn, protected_resource_match=hit)


@install("aws.cb.rds.instance_protected_resource", "rds_instance", "RDS instance is an AWS Backup protected resource",
    {"DBInstanceArn": INST_ARN}, {"DBInstanceArn": INST_ARN},
    rows=[C + "rds_db_instance_protected_by_backup_plan"], severity="medium", control="CP-9",
    remediation="Protect the DB instance with an AWS Backup plan so recovery points exist.", docs=[D_BACKUP_PR],
    dependencies=["rds_instance", "backup_protected_resource"],
    extra={"pass_index": _protected_index(INST_ARN, "RDS"), "fail_index": _protected_index("arn:other", "RDS")})
def instance_protected(item, index):
    arn = get(item, "DBInstanceArn", str)
    hit = any(get(r, "ResourceArn", str) == arn and get(r, "ResourceType", str) == "RDS" for r in protected_resources(index))
    return result(not hit, resource_arn=arn, protected_resource_match=hit)


def _tag_plan_index(resources, tag_keys):
    return inventory("backup_plan", [{"BackupPlanId": "p", "Selections": {"collection_status": "collected", "items": [{"SelectionId": "s", "Selection": {"BackupSelection": {"Resources": resources, "ListOfTags": [{"ConditionType": "STRINGEQUALS", "ConditionKey": k, "ConditionValue": "yes"} for k in tag_keys]}}}]}}])


@install("aws.cb.rds.instance_in_backup_selection_or_tag", "rds_instance", "RDS instance is in a backup selection by ARN or tag key",
    {"DBInstanceArn": INST_ARN, "TagList": [{"Key": "backup", "Value": "yes"}]}, {"DBInstanceArn": INST_ARN, "TagList": []},
    rows=[C + "rds_db_instance_in_backup_plan"], severity="medium", control="CP-9",
    remediation="Include the DB instance in an AWS Backup selection by ARN or by a selection tag.", docs=[D_BACKUP_SEL],
    dependencies=["rds_instance", "backup_plan"], extra={"index": _tag_plan_index([], ["backup"])},
    note="Source: selection Resources contains the instance ARN exactly, or any ListOfTags ConditionKey is one of the instance tag keys.")
def instance_in_plan(item, index):
    arn = get(item, "DBInstanceArn", str)
    tags = {}
    for tag in list_of_objects(absent_or(item, "DBInstanceArn", "TagList", [], list)):
        key, value = get(tag, "Key", str), get(tag, "Value", str)
        if key in tags:
            raise Unavailable("ambiguous duplicate RDS resource tag")
        tags[key] = value
    resources, selected_tags = [], []
    for plan in complete_items(index, "backup_plan"):
        selections = get(plan, "Selections", dict)
        if selections.get("collection_status") not in ("collected", "empty"):
            raise Unavailable("backup selections unavailable")
        for selection in list_of_objects(selections.get("items", [])):
            body = get(selection, "Selection.BackupSelection", dict)
            resources += strings(optional(body, "Resources", [], list))
            for condition in list_of_objects(optional(body, "ListOfTags", [], list)):
                if get(condition, "ConditionType", str) != "STRINGEQUALS":
                    raise Unavailable("unsupported backup ListOfTags condition")
                selected_tags.append((get(condition, "ConditionKey", str), get(condition, "ConditionValue", str)))
    matched = sorted({key for key, value in selected_tags if key in tags and tags[key] == value})
    hit = _instance_backup_selection(item, index, arn)
    return result(not hit, resource_arn=arn, selection_or_tag_key_match=hit, matched_tag_keys=matched)


@install("aws.cb.rds.cluster_cmk_encryption", "rds_cluster", "RDS cluster storage is encrypted with a customer managed KMS key",
    {"DBClusterArn": CLUS_ARN, "StorageEncrypted": True, "KmsKeyId": KMS_ARN}, {"DBClusterArn": CLUS_ARN, "StorageEncrypted": False},
    rows=[C + "rds_db_cluster_encrypted_with_cmk"], severity="medium", control="SC-28",
    remediation="Restore the cluster from a snapshot copied with a customer managed KMS key.", docs=[D_CLUS],
    dependencies=["rds_cluster", "kms_key"], extra={"index": _kms_index("CUSTOMER")})
def cluster_cmk(item, index):
    if not get(item, "StorageEncrypted", bool):
        return result(True, storage_encrypted=False)
    manager = kms_manager(index, get(item, "KmsKeyId", str))
    return result(manager != "CUSTOMER", key_manager=manager)


@install("aws.cb.rds.aurora_mysql_server_audit_logging", "rds_cluster", "Aurora MySQL cluster parameter group enables server_audit_logging",
    {"DBClusterArn": CLUS_ARN, "Engine": "aurora-mysql", "ClusterParameterGroupValues": {"server_audit_logging": "1", "server_audit_events": "CONNECT"}},
    {"DBClusterArn": CLUS_ARN, "Engine": "aurora-mysql", "ClusterParameterGroupValues": {"server_audit_logging": "0"}},
    rows=[C + "rds_db_cluster_aurora_mysql_audit_logging_enabled"], severity="medium", control="AU-2",
    remediation="Set server_audit_logging = ON and choose server_audit_events in the cluster parameter group.", docs=[D_CPARAMS],
    extra={"not_applicable": {"DBClusterArn": CLUS_ARN, "Engine": "aurora-postgresql"}},
    note="Cluster parameter configuration only: server_audit_logging must be ON/1 and server_audit_events must name at least one supported event; this does not prove log delivery or comprehensive event coverage.")
def aurora_audit(item, index):
    engine = get(item, "Engine", str)
    if engine != "aurora-mysql":
        return "NOT_APPLICABLE", {"engine": engine}
    values = get(item, "ClusterParameterGroupValues", dict)
    enabled, setting = _rds_binary_parameter(values, "server_audit_logging")
    if not enabled:
        return result(True, server_audit_logging=setting)
    events = get(values, "server_audit_events", str)
    if not events.strip():
        return result(True, server_audit_logging=setting, server_audit_events=events)
    supported = {"CONNECT", "QUERY", "QUERY_DCL", "QUERY_DDL", "QUERY_DML", "TABLE"}
    selected = events.split(",")
    if any(event not in supported for event in selected):
        raise Unavailable("unrecognized Aurora MySQL server_audit_events value")
    return result(False, server_audit_logging=setting, server_audit_events=selected)


@install("aws.cb.rds.aurora_postgres_postgresql_log_export", "rds_cluster", "Aurora PostgreSQL cluster exports the postgresql log",
    {"DBClusterArn": CLUS_ARN, "Engine": "aurora-postgresql", "EnabledCloudwatchLogsExports": ["postgresql"]}, {"DBClusterArn": CLUS_ARN, "Engine": "aurora-postgresql"},
    rows=[C + "rds_db_cluster_aurora_postgres_logging_enabled"], severity="medium", control="AU-2",
    remediation="Enable the postgresql CloudWatch Logs export on the Aurora PostgreSQL cluster.", docs=[D_CLUS],
    extra={"not_applicable": {"DBClusterArn": CLUS_ARN, "Engine": "aurora-mysql"}})
def aurora_pg_logs(item, index):
    engine = get(item, "Engine", str)
    if engine != "aurora-postgresql":
        return "NOT_APPLICABLE", {"engine": engine}
    exports = _exports(item, "DBClusterArn")
    return result("postgresql" not in exports, exports=exports)


@install("aws.cb.rds.cluster_log_exports_declared", "rds_cluster", "RDS cluster declares CloudWatch log exports",
    {"DBClusterArn": CLUS_ARN, "EnabledCloudwatchLogsExports": ["error"]}, {"DBClusterArn": CLUS_ARN},
    rows=[C + "rds_db_instance_and_cluster_enhanced_monitoring_enabled"], severity="low", control="AU-2",
    remediation="Enable CloudWatch Logs exports on the DB cluster.", docs=[D_CLUS],
    note="Cluster half of the source UNION: enabled_cloudwatch_logs_exports IS NOT NULL (the source labels it enhanced monitoring).")
def cluster_exports(item, index):
    exports = _exports(item, "DBClusterArn")
    return result(not exports, exports=exports)


@install("aws.cb.rds.instance_enhanced_monitoring_except_m1_small", "rds_instance", "RDS instance has enhanced monitoring (db.m1.small excepted)",
    {"DBInstanceArn": INST_ARN, "DBInstanceClass": "db.r6g.large", "EnhancedMonitoringResourceArn": "arn:aws:logs:x"}, {"DBInstanceArn": INST_ARN, "DBInstanceClass": "db.r6g.large"},
    rows=[C + "rds_db_instance_and_cluster_enhanced_monitoring_enabled"], severity="low", control="SI-4",
    remediation="Enable Enhanced Monitoring (MonitoringInterval > 0 with a monitoring role).", docs=[D_INST],
    extra={"not_applicable": {"DBInstanceArn": INST_ARN, "DBInstanceClass": "db.m1.small"}},
    note="Instance half of the source UNION; db.m1.small is skipped, so distinct from aws.rds.enhanced_monitoring.")
def instance_em(item, index):
    klass = get(item, "DBInstanceClass", str)
    if klass == "db.m1.small":
        return "NOT_APPLICABLE", {"instance_class": klass}
    arn = absent_or(item, "DBInstanceArn", "EnhancedMonitoringResourceArn", None, str)
    return result(not arn, enhanced_monitoring_resource_arn=arn)


@install("aws.cb.rds.cluster_tls_parameters", "rds_cluster", "RDS cluster parameter group enforces TLS connections",
    {"DBClusterArn": CLUS_ARN, "Engine": "aurora-postgresql", "ClusterParameterGroupValues": {"rds.force_ssl": "1"}},
    {"DBClusterArn": CLUS_ARN, "Engine": "aurora-postgresql", "ClusterParameterGroupValues": {"rds.force_ssl": "0"}},
    rows=[P + "rds_instance_transport_encrypted"], severity="high", control="SC-8",
    remediation="Set rds.force_ssl = 1 (PostgreSQL) or require_secure_transport = ON (MySQL) in the matching DB cluster parameter group.", docs=[D_CPARAMS],
    extra={"not_applicable": {"DBClusterArn": CLUS_ARN, "Engine": "docdb"}},
    note="Aurora and Multi-AZ MySQL/PostgreSQL clusters only. Use rds.force_ssl 1/0 for PostgreSQL and require_secure_transport ON/1 or OFF/0 for MySQL; missing, denied and unrecognized parameter strings are UNKNOWN. Configuration does not prove a client handshake.")
def cluster_tls(item, index):
    engine = get(item, "Engine", str)
    parameter = {"aurora-postgresql": "rds.force_ssl", "postgres": "rds.force_ssl",
                 "aurora-mysql": "require_secure_transport", "mysql": "require_secure_transport"}.get(engine)
    if parameter is None:
        return "NOT_APPLICABLE", {"engine": engine, "reason": "unsupported RDS cluster TLS engine"}
    if engine in ("postgres", "mysql") and not _multi_az_tls_engine_version_applicable(item, engine):
        return "NOT_APPLICABLE", {"engine": engine, "engine_version": get(item, "EngineVersion", str)}
    values = get(item, "ClusterParameterGroupValues", dict)
    if parameter == "rds.force_ssl":
        value = _rds_parameter_text(values, parameter)
        if value not in ("0", "1"):
            raise Unavailable("unrecognized RDS parameter value: rds.force_ssl")
        enabled = value == "1"
    else:
        enabled, value = _rds_binary_parameter(values, parameter)
    return result(not enabled, parameter=parameter, value=value)


def _multi_az_tls_engine_version_applicable(item, engine):
    """Known Multi-AZ cluster releases from AWS's dated regional support table."""
    version = get(item, "EngineVersion", str)
    parts = version.split(".")
    if len(parts) < 2 or not all(part.isdecimal() for part in parts[:2]):
        raise Unavailable("unrecognized Multi-AZ DB cluster engine version")
    major, minor = int(parts[0]), int(parts[1])
    if engine == "mysql":
        if major < 8:
            return False
        if (major, minor) in ((8, 0), (8, 4)):
            return True
        raise Unavailable("unreviewed Multi-AZ MySQL engine version")
    if major < 13:
        return False
    if major == 13:
        return minor == 4 or minor >= 7
    if major == 14:
        return minor >= 5
    if major <= 18:
        return True
    raise Unavailable("unreviewed Multi-AZ PostgreSQL engine version")


# =========================================================================== RDS instances
_TLS_SUPPORTED = ("sqlserver-se", "sqlserver-ee", "sqlserver-ex", "sqlserver-web", "postgres", "aurora-postgresql", "mysql", "mariadb", "aurora-mysql")


@install("aws.cb.rds.instance_tls_parameters", "rds_instance", "Standalone RDS instance parameter group enforces TLS connections",
    {"DBInstanceArn": INST_ARN, "Engine": "postgres", "ParameterGroupValues": {"rds.force_ssl": "1"}},
    {"DBInstanceArn": INST_ARN, "Engine": "mysql", "EngineVersion": "8.0.40", "ParameterGroupValues": {"require_secure_transport": "0"}},
    rows=[P + "rds_instance_transport_encrypted"], severity="high", control="SC-8",
    remediation="Set rds.force_ssl = 1 (SQL Server/PostgreSQL) or require_secure_transport = ON (MySQL/MariaDB) in the DB parameter group; follow the parameter apply method for the engine.",
    docs=[D_PARAMS], extra={"not_applicable": {"DBInstanceArn": INST_ARN, "Engine": "oracle-ee"}},
    note="Standalone supported engines only; allowlisted DescribeDBParameters strings ON/1 and OFF/0 are equivalent for require_secure_transport. MariaDB supports it from 10.5; missing or unrecognized values are unknown.")
def instance_tls(item, index):
    engine = get(item, "Engine", str)
    cluster = absent_or(item, "DBInstanceArn", "DBClusterIdentifier", None, str)
    if cluster or engine not in _TLS_SUPPORTED:
        return "NOT_APPLICABLE", {"engine": engine, "cluster": cluster}
    if engine == "mariadb" and not _mariadb_secure_transport_applicable(item):
        return "NOT_APPLICABLE", {"engine": engine, "engine_version": get(item, "EngineVersion", str)}
    values = get(item, "ParameterGroupValues", dict)
    if engine in ("sqlserver-se", "sqlserver-ee", "sqlserver-ex", "sqlserver-web", "postgres", "aurora-postgresql"):
        value = _rds_parameter_text(values, "rds.force_ssl")
        if value not in ("0", "1"):
            raise Unavailable("unrecognized RDS parameter value: rds.force_ssl")
        return result(value != "1", parameter="rds.force_ssl", value=value)
    enabled, value = _rds_binary_parameter(values, "require_secure_transport")
    return result(not enabled, parameter="require_secure_transport", value=value)


for _cid, _row, _test, _param, _rem in (
    ("aws.cb.rds.postgres_force_ssl_parameter", "rds_db_instance_connections_encryption_enabled", lambda e: e in ("sqlserver", "postgres"), "rds.force_ssl", "Set rds.force_ssl = 1 in the PostgreSQL DB parameter group."),
    ("aws.cb.rds.mariadb_require_secure_transport", "rds_db_instance_mariadb_encryption_in_transit_enabled", lambda e: e == "mariadb", "require_secure_transport", "Set require_secure_transport = ON in the MariaDB DB parameter group."),
    ("aws.cb.rds.sqlserver_force_ssl_parameter", "rds_db_instance_sql_server_encryption_in_transit_enabled", lambda e: e.startswith("sqlserver"), "rds.force_ssl", "Set rds.force_ssl = 1 in the SQL Server DB parameter group."),
):
    def _param_check(cid, row, test, param, rem):
        engine = {"rds.force_ssl": "postgres" if "postgres" in cid else "sqlserver-se", "require_secure_transport": "mariadb"}[param]
        @install(cid, "rds_instance", "RDS instance parameter group sets " + param + " = 1",
            {"DBInstanceArn": INST_ARN, "Engine": engine, **({"EngineVersion": "10.11.8"} if cid == "aws.cb.rds.mariadb_require_secure_transport" else {}), "ParameterGroupValues": {param: "1"}}, {"DBInstanceArn": INST_ARN, "Engine": engine, **({"EngineVersion": "10.11.8"} if cid == "aws.cb.rds.mariadb_require_secure_transport" else {}), "ParameterGroupValues": {param: "0"}},
            rows=[C + row], severity="high", control="SC-8", remediation=rem, docs=[D_PARAMS],
            extra={"not_applicable": {"DBInstanceArn": INST_ARN, "Engine": "oracle-ee"}},
            note="Source joins each attached DB parameter group; requires the allowlisted ParameterGroupValues fact." + (" MariaDB supports require_secure_transport from 10.5 and accepts the documented ON/1 and OFF/0 string forms; missing/unrecognized values are unknown." if cid == "aws.cb.rds.mariadb_require_secure_transport" else "") + (" The literal engine list ('sqlserver','postgres') never matches RDS SQL Server engine names, so only postgres applies." if "postgres" in cid else ""))
        def evaluate(item, index):
            actual = get(item, "Engine", str)
            if not test(actual):
                return "NOT_APPLICABLE", {"engine": actual}
            if cid == "aws.cb.rds.mariadb_require_secure_transport" and not _mariadb_secure_transport_applicable(item):
                return "NOT_APPLICABLE", {"engine": actual, "engine_version": get(item, "EngineVersion", str)}
            values = get(item, "ParameterGroupValues", dict)
            if cid == "aws.cb.rds.mariadb_require_secure_transport":
                enabled, value = _rds_binary_parameter(values, param)
                return result(not enabled, parameter=param, value=value)
            value = _rds_parameter_text(values, param)
            if value not in {"0", "1"}:
                raise Unavailable("unrecognized RDS force_ssl parameter")
            return result(value != "1", parameter=param, value=value)
    _param_check(_cid, _row, _test, _param, _rem)


for _cid, _row, _test, _required, _engine in (
    ("aws.cb.rds.mariadb_log_exports", "rds_db_instance_mariadb_logging_enabled", lambda e: e == "mariadb", ("audit", "error", "general", "slowquery"), "mariadb"),
    ("aws.cb.rds.postgres_log_exports", "rds_db_instance_postgres_logging_enabled", lambda e: e == "postgres", ("postgresql", "upgrade"), "postgres"),
    ("aws.cb.rds.sqlserver_error_log_export", "rds_db_instance_sql_server_logging_enabled", lambda e: e.startswith("sqlserver"), ("error",), "sqlserver-ee"),
):
    def _logs(cid, row, test, required, engine):
        @install(cid, "rds_instance", "RDS " + engine + " instance exports " + ", ".join(required) + " logs",
            {"DBInstanceArn": INST_ARN, "Engine": engine, "EnabledCloudwatchLogsExports": list(required)}, {"DBInstanceArn": INST_ARN, "Engine": engine},
            rows=[C + row], severity="medium", control="AU-2",
            remediation="Enable the " + ", ".join(required) + " CloudWatch Logs exports on the DB instance.", docs=[D_INST],
            extra={"not_applicable": {"DBInstanceArn": INST_ARN, "Engine": "oracle-ee"}})
        def evaluate(item, index):
            actual = get(item, "Engine", str)
            if not test(actual):
                return "NOT_APPLICABLE", {"engine": actual}
            exports = _exports(item, "DBInstanceArn")
            return result(not set(required) <= set(exports), exports=exports, required=list(required))
    _logs(_cid, _row, _test, _required, _engine)


_VULN = ("10.11", "10.12", "10.13", "11.6", "11.7", "11.8")
for _cid, _row, _test, _engine in (
    ("aws.cb.rds.aurora_postgres_local_file_read_versions", "rds_db_cluster_aurora_postgres_not_exposed_to_local_file_read_vulnerability", lambda e: "aurora-postgres" in e.lower(), "aurora-postgresql"),
    ("aws.cb.rds.postgres_local_file_read_versions", "rds_db_instance_postgres_not_exposed_to_local_file_read_vulnerability", lambda e: e == "postgres", "postgres"),
):
    def _vuln(cid, row, test, engine):
        @install(cid, "rds_instance", "RDS " + engine + " instance does not run a version exposed to the log_fdw local file read issue",
            {"DBInstanceArn": INST_ARN, "Engine": engine, "EngineVersion": "15.4"}, {"DBInstanceArn": INST_ARN, "Engine": engine, "EngineVersion": "11.7"},
            rows=[C + row], severity="high", control="SI-2",
            remediation="Upgrade the PostgreSQL engine to a version that is not 10.11-10.13 or 11.6-11.8.",
            docs=["https://aws.amazon.com/security/security-bulletins/AWS-2022-004/"], extra={"not_applicable": {"DBInstanceArn": INST_ARN, "Engine": "mysql", "EngineVersion": "8.0"}},
            note="Pinned version list 10.11, 10.12, 10.13, 11.6, 11.7, 11.8 (LIKE without wildcards = equality). The Aurora row queries aws_rds_db_instance.")
        def evaluate(item, index):
            actual = get(item, "Engine", str)
            if not test(actual):
                return "NOT_APPLICABLE", {"engine": actual}
            version = get(item, "EngineVersion", str)
            return result(version in _VULN, engine_version=version)
    _vuln(_cid, _row, _test, _engine)


@install("aws.cb.rds.instance_backup_retention_nonzero_all", "rds_instance", "RDS instance automated backup retention is at least one day",
    {"DBInstanceArn": INST_ARN, "BackupRetentionPeriod": 1}, {"DBInstanceArn": INST_ARN, "BackupRetentionPeriod": 0},
    rows=[C + "rds_db_instance_backup_enabled"], severity="medium", control="CP-9",
    remediation="Set BackupRetentionPeriod to at least 1 day.", docs=[D_INST],
    note="Source alarms when backup_retention_period < 1 for every instance, including read replicas (aws.rds.backups skips replicas).")
def instance_backup(item, index):
    days = get(item, "BackupRetentionPeriod", int)
    return result(days < 1, backup_retention_days=days)


@install("aws.cb.rds.instance_copy_tags_all_engines", "rds_instance", "RDS instance copies tags to snapshots",
    {"DBInstanceArn": INST_ARN, "CopyTagsToSnapshot": True}, {"DBInstanceArn": INST_ARN, "CopyTagsToSnapshot": False},
    rows=[C + "rds_db_instance_copy_tags_to_snapshot_enabled"], severity="low",
    remediation="Enable CopyTagsToSnapshot on the DB instance.", docs=[D_INST],
    note="Source has no Aurora exclusion, unlike aws.rds.copy_snapshot_tags.")
def instance_copy_tags(item, index):
    value = get(item, "CopyTagsToSnapshot", bool)
    return result(not value, copy_tags_to_snapshot=value)


_IAM_KNOWN_NON_INSTANCE_ENGINES = {
    "aurora", "aurora-mysql", "aurora-postgresql", "docdb", "neptune",
    "db2-ae", "db2-ce", "db2-se",
    "oracle-ee", "oracle-ee-cdb", "oracle-se2", "oracle-se2-cdb",
    "sqlserver-dev-ee", "sqlserver-ee", "sqlserver-se", "sqlserver-ex", "sqlserver-web",
    "custom-oracle-ee", "custom-oracle-ee-cdb", "custom-oracle-se2", "custom-oracle-se2-cdb",
    "custom-sqlserver-ee", "custom-sqlserver-se", "custom-sqlserver-web", "custom-sqlserver-dev",
}


@install("aws.cb.rds.instance_iam_auth_all_engines", "rds_instance", "RDS instance enables IAM database authentication",
    {"DBInstanceArn": INST_ARN, "Engine": "mysql", "IAMDatabaseAuthenticationEnabled": True},
    {"DBInstanceArn": INST_ARN, "Engine": "mysql", "EngineVersion": "8.0.40", "DBInstanceClass": "db.r6g.large",
     "DBSubnetGroup": {"Subnets": [{"SubnetIdentifier": "subnet-1"}]}, "IAMDatabaseAuthenticationEnabled": False},
    rows=[C + "rds_db_instance_iam_authentication_enabled"], severity="medium", control="IA-2",
    remediation="For a supported standalone RDS instance, enable IAM database authentication after verifying engine, version, class, and database-user prerequisites.",
    docs=[D_INST, "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html"],
    dependencies=["rds_iam_auth_capability"],
    extra={"index": inventory("rds_iam_auth_capability", [{"id": INST_ARN, "DBInstanceArn": INST_ARN,
             "Engine": "mysql", "EngineVersion": "8.0.40", "DBInstanceClass": "db.r6g.large",
             "SupportsIAMDatabaseAuthentication": True}]),
           "not_applicable": {"DBInstanceArn": INST_ARN, "Engine": "oracle-ee", "IAMDatabaseAuthenticationEnabled": False}},
    note="Standalone RDS MySQL/MariaDB/PostgreSQL only; Aurora and Multi-AZ members use the cluster IAM-auth setting. A collected true instance flag proves configuration only; a false flag fails only with matching region/version/class SupportsIAMDatabaseAuthentication=true. Missing, denied, empty or conflicting capability evidence and unrecognized engine names are UNKNOWN; known unsupported engines and RDS on Outposts are not applicable.")
def instance_iam_all(item, index):
    engine = get(item, "Engine", str)
    if engine not in ("mysql", "mariadb", "postgres"):
        if engine in _IAM_KNOWN_NON_INSTANCE_ENGINES:
            return "NOT_APPLICABLE", {"engine": engine, "reason": "IAM DB auth unsupported or configured on the cluster"}
        raise Unavailable("unrecognized RDS IAM DB auth engine")
    cluster = absent_or(item, "DBInstanceArn", "DBClusterIdentifier", None, str)
    if cluster:
        return "NOT_APPLICABLE", {"engine": engine, "cluster": cluster, "reason": "IAM DB auth configured on the cluster"}
    placement_observed = "DBSubnetGroup" in item or "DBSubnetGroup" in item.get("_coverage", {})
    if placement_observed:
        subnets = list_of_objects(get(item, "DBSubnetGroup.Subnets", list))
        if not subnets:
            raise Unavailable("RDS subnet placement unavailable")
        for subnet in subnets:
            if "SubnetOutpost" in subnet:
                outpost = get(subnet, "SubnetOutpost", dict)
                if outpost and get(outpost, "Arn", str):
                    return "NOT_APPLICABLE", {"engine": engine, "reason": "IAM DB auth unsupported on RDS on Outposts"}
    value = get(item, "IAMDatabaseAuthenticationEnabled", bool)
    if value:
        return result(False, iam_database_authentication=True, configuration_scope="instance")
    if not placement_observed:
        raise Unavailable("RDS subnet placement unavailable")
    arn = get(item, "DBInstanceArn", str)
    version = get(item, "EngineVersion", str)
    klass = get(item, "DBInstanceClass", str)
    matches = [row for row in complete_items(index, "rds_iam_auth_capability") if get(row, "DBInstanceArn", str) == arn]
    if len(matches) != 1:
        raise Unavailable("matching RDS IAM auth capability unavailable")
    capability = matches[0]
    if any(get(capability, name, str) != expected for name, expected in
           (("Engine", engine), ("EngineVersion", version), ("DBInstanceClass", klass))):
        raise Unavailable("RDS IAM auth capability does not match instance")
    supported = get(capability, "SupportsIAMDatabaseAuthentication", bool)
    if not supported:
        return "NOT_APPLICABLE", {"engine": engine, "engine_version": version, "instance_class": klass,
                                  "reason": "RDS reports IAM DB auth unsupported for this option"}
    return result(True, iam_database_authentication=False, supports_iam_database_authentication=True,
                  configuration_scope="instance")


_IAM_ENGINES = ("postgres", "aurora-postgresql", "mysql", "mariadb", "aurora-mysql", "aurora")


@install("aws.cb.rds.instance_iam_auth_supported_engines", "rds_instance", "RDS MySQL/MariaDB/PostgreSQL instance enables IAM database authentication",
    {"DBInstanceArn": INST_ARN, "Engine": "mysql", "IAMDatabaseAuthenticationEnabled": True}, {"DBInstanceArn": INST_ARN, "Engine": "mysql"},
    rows=[P + "rds_instance_iam_authentication_enabled"], severity="medium", control="IA-2",
    remediation="Enable IAM database authentication on the DB instance (or its cluster).", docs=[D_INST],
    extra={"not_applicable": {"DBInstanceArn": INST_ARN, "Engine": "oracle-ee"}},
    note="Prowler engine substring filter; absent IAMDatabaseAuthenticationEnabled is False.")
def instance_iam_supported(item, index):
    engine = get(item, "Engine", str)
    if not any(name in engine for name in _IAM_ENGINES):
        return "NOT_APPLICABLE", {"engine": engine}
    value = absent_or(item, "DBInstanceArn", "IAMDatabaseAuthenticationEnabled", False, bool)
    return result(not value, iam_database_authentication=value)


def _cluster_of(item, index):
    cid = absent_or(item, "DBInstanceArn", "DBClusterIdentifier", None, str)
    if not cid:
        return None
    rows = [c for c in complete_items(index, "rds_cluster") if c.get("DBClusterIdentifier") == cid]
    return rows[0] if len(rows) == 1 else False


_CLUSTER_IDX = inventory("rds_cluster", [{"DBClusterIdentifier": "c1", "MasterUsername": "owner", "MultiAZ": True}])


@install("aws.cb.rds.instance_default_master_username", "rds_instance", "RDS instance (or its cluster) does not use the admin or postgres master username",
    {"DBInstanceArn": INST_ARN, "Engine": "aurora-mysql", "DBClusterIdentifier": "c1", "MasterUsername": "admin"}, {"DBInstanceArn": INST_ARN, "Engine": "postgres", "MasterUsername": "postgres"},
    rows=[P + "rds_instance_default_admin"], severity="medium", control="IA-5",
    remediation="Recreate the database with a non-default master username and migrate data.", docs=[D_INST],
    dependencies=["rds_instance", "rds_cluster"], extra={"index": _CLUSTER_IDX},
    note="Cluster members are judged by the cluster MasterUsername; a cluster missing from the inventory fails in prowler and is FAIL here only when the cluster inventory is complete.")
def instance_admin(item, index):
    skip = _not_docdb(item)
    if skip:
        return "NOT_APPLICABLE", skip
    cluster = _cluster_of(item, index)
    if cluster is None:
        name = absent_or(item, "DBInstanceArn", "MasterUsername", "", str)
    elif cluster is False:
        return result(True, reason="member cluster not found in the complete cluster inventory")
    else:
        name = get(cluster, "MasterUsername", str)
    return result(name in ("admin", "postgres"), master_username=name)


@install("aws.cb.rds.instance_multi_az_or_cluster", "rds_instance", "RDS instance (or its cluster) is Multi-AZ",
    {"DBInstanceArn": INST_ARN, "Engine": "aurora-mysql", "DBClusterIdentifier": "c1", "MultiAZ": False}, {"DBInstanceArn": INST_ARN, "Engine": "postgres", "MultiAZ": False},
    rows=[P + "rds_instance_multi_az"], severity="medium", control="CP-10",
    remediation="Enable Multi-AZ on the DB instance or cluster.", docs=[D_INST], dependencies=["rds_instance", "rds_cluster"], extra={"index": _CLUSTER_IDX})
def instance_multi(item, index):
    skip = _not_docdb(item)
    if skip:
        return "NOT_APPLICABLE", skip
    cluster = _cluster_of(item, index)
    if cluster is False:
        return result(True, reason="member cluster not found in the complete cluster inventory")
    value = get(cluster, "MultiAZ", bool) if cluster else get(item, "MultiAZ", bool)
    return result(not value, multi_az=value, via_cluster=bool(cluster))


@install("aws.cb.rds.instance_multi_az_non_aurora", "rds_instance", "Non-Aurora RDS instance has Multi-AZ enabled",
    {"DBInstanceArn": INST_ARN, "Engine": "postgres", "MultiAZ": True}, {"DBInstanceArn": INST_ARN, "Engine": "postgres", "MultiAZ": False},
    rows=[C + "rds_db_instance_multiple_az_enabled"], severity="medium", control="CP-10",
    remediation="Enable Multi-AZ deployment on the DB instance.", docs=[D_INST], extra={"not_applicable": {"DBInstanceArn": INST_ARN, "Engine": "aurora-postgresql", "MultiAZ": False}})
def instance_multi_c(item, index):
    engine = get(item, "Engine", str)
    if "aurora-mysql" in engine.lower() or "aurora-postgres" in engine.lower():
        return "NOT_APPLICABLE", {"engine": engine}
    value = get(item, "MultiAZ", bool)
    return result(not value, multi_az=value)


@install("aws.cb.rds.instance_extended_support", "rds_instance", "RDS instance is not enrolled in RDS Extended Support",
    {"DBInstanceArn": INST_ARN, "EngineLifecycleSupport": "open-source-rds-extended-support-disabled"}, {"DBInstanceArn": INST_ARN, "EngineLifecycleSupport": "open-source-rds-extended-support"},
    rows=[P + "rds_instance_extended_support"], severity="medium", control="SI-2",
    remediation="Upgrade to a supported major version and set EngineLifecycleSupport to open-source-rds-extended-support-disabled.", docs=[D_INST])
def instance_extended(item, index):
    value = absent_or(item, "DBInstanceArn", "EngineLifecycleSupport", None, str)
    return result(value == "open-source-rds-extended-support", engine_lifecycle_support=value)


def _cert_index(valid_till):
    return inventory("rds_certificate", [{"CertificateIdentifier": "rds-ca-rsa2048-g1", "ValidTill": valid_till, "CustomerOverride": False}])


def _ca(item, index):
    ident = get(item, "CACertificateIdentifier", str)
    rows = [c for c in complete_items(index, "rds_certificate") if c.get("CertificateIdentifier") == ident]
    if len(rows) != 1:
        raise Unavailable("CA certificate join unresolved")
    return parse_time(get(rows[0], "ValidTill", str))


@install("aws.cb.rds.ca_certificate_valid_3_months", "rds_instance", "RDS instance CA certificate is valid for more than three months",
    {"DBInstanceArn": INST_ARN, "Engine": "postgres", "CACertificateIdentifier": "rds-ca-rsa2048-g1"}, {"DBInstanceArn": INST_ARN, "Engine": "postgres", "CACertificateIdentifier": "rds-ca-rsa2048-g1"},
    rows=[P + "rds_instance_certificate_expiration"], severity="high", control="SC-12",
    remediation="Rotate the DB instance to a CA certificate with more than three months of validity (ModifyDBInstance CACertificateIdentifier).",
    docs=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL-certificate-rotation.html"], dependencies=["rds_instance", "rds_certificate"],
    extra={"pass_index": _cert_index("2061-01-01T00:00:00+00:00"), "fail_index": _cert_index("2026-02-01T00:00:00+00:00")},
    note="Prowler joins DescribeCertificates on CACertificateIdentifier; PASS when ValidTill > now + 3 months (snapshot clock).")
def ca_three_months(item, index):
    skip = _not_docdb(item)
    if skip:
        return "NOT_APPLICABLE", skip
    valid = _ca(item, index)
    now = clock(item, index)
    return result(not valid > add_months(now, 3), valid_till=valid.isoformat(), evaluated_at=now.isoformat())


@install("aws.cb.rds.ca_certificate_not_expiring_7_days", "rds_instance", "RDS instance CA certificate does not expire within 7 days",
    {"DBInstanceArn": INST_ARN, "CACertificateIdentifier": "rds-ca-rsa2048-g1"}, {"DBInstanceArn": INST_ARN, "CACertificateIdentifier": "rds-ca-rsa2048-g1"},
    rows=[C + "rds_db_instance_ca_certificate_expires_7_days"], severity="high", control="SC-12",
    remediation="Rotate the DB instance to a current RDS CA certificate.", docs=["https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_Certificate.html"],
    dependencies=["rds_instance", "rds_certificate"],
    extra={"pass_index": _cert_index("2026-03-01T00:00:00+00:00"), "fail_index": _cert_index("2026-01-05T00:00:00+00:00")},
    note="Pinned source alarms when the CA ValidTill timestamp is within 7 days. Compare its exact aware UTC interval with the captured snapshot clock; an expired CA also alarms, and unavailable certificate or clock evidence is UNKNOWN.")
def ca_seven(item, index):
    try:
        valid = _ca(item, index)
        captured_at = clock(item, index)
    except ValueError as exc:
        raise Unavailable("CA validity or captured snapshot time unavailable") from exc
    delta = valid - captured_at
    return result(delta <= timedelta(days=7), valid_till=valid.isoformat(),
                  evaluated_at=captured_at.isoformat(), seconds_remaining=delta.total_seconds())


@install("aws.cb.rds.engine_version_available", "rds_instance", "RDS instance engine version is still offered by RDS",
    {"DBInstanceArn": INST_ARN, "Engine": "postgres", "EngineVersion": "16.3"}, {"DBInstanceArn": INST_ARN, "Engine": "postgres", "EngineVersion": "9.6.1"},
    rows=[P + "rds_instance_deprecated_engine_version"], severity="high", control="SI-2",
    remediation="Upgrade the DB instance to an engine version listed by DescribeDBEngineVersions.",
    docs=["https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBEngineVersions.html"], dependencies=["rds_instance", "rds_engine_version"],
    extra={"index": inventory("rds_engine_version", [{"Engine": "postgres", "EngineVersion": "16.3"}])})
def engine_version(item, index):
    skip = _not_docdb(item)
    if skip:
        return "NOT_APPLICABLE", skip
    engine, version = get(item, "Engine", str), get(item, "EngineVersion", str)
    offered = {get(r, "EngineVersion", str) for r in complete_items(index, "rds_engine_version") if r.get("Engine") == engine}
    return result(version not in offered, engine=engine, engine_version=version, offered_versions=len(offered), engine_version_available=version in offered)


_NET = indexes(
    inventory("subnet", [{"SubnetId": "subnet-pub", "VpcId": "vpc-1"}, {"SubnetId": "subnet-priv", "VpcId": "vpc-1"}]),
    inventory("route_table", [{"VpcId": "vpc-1", "Associations": [{"SubnetId": "subnet-pub"}], "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"}]},
                              {"VpcId": "vpc-1", "Associations": [{"Main": True}], "Routes": [{"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"}]}]),
    inventory("security_group", [{"GroupId": "sg-open", "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}]},
                                 {"GroupId": "sg-closed", "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "10.0.0.0/8"}], "Ipv6Ranges": []}]}]))


def _instance_net(sg, subnet, public=True):
    return {"DBInstanceArn": INST_ARN, "Engine": "postgres", "PubliclyAccessible": public, "Endpoint": {"Port": 5432},
            "VpcSecurityGroups": [{"VpcSecurityGroupId": sg, "Status": "active"}],
            "DBSubnetGroup": {"VpcId": "vpc-1", "Subnets": [{"SubnetIdentifier": subnet, "SubnetStatus": "Active"}]}}


def _active_sgs(item, path):
    return [get(g, "VpcSecurityGroupId", str) for g in list_of_objects(get(item, path, list)) if get(g, "Status", str) == "active"]


@install("aws.cb.rds.instance_internet_exposed", "rds_instance", "RDS instance is not public with an open port in a public subnet",
    _instance_net("sg-closed", "subnet-pub"), _instance_net("sg-open", "subnet-pub"),
    rows=[P + "rds_instance_no_public_access"], severity="critical", category="exposure", control="SC-7",
    remediation="Disable PubliclyAccessible, restrict the VPC security group ingress on the database port and place the instance in private subnets.",
    docs=[D_INST, "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html"],
    dependencies=["rds_instance", "security_group", "subnet", "route_table"], extra={"index": _NET},
    note="Prowler: PubliclyAccessible, an active VPC SG rule open to 0.0.0.0/0 or ::/0 on the endpoint port (tcp), and an Active DB subnet that is public (0.0.0.0/0 via igw-).")
def instance_exposed(item, index):
    skip = _not_docdb(item)
    if skip:
        return "NOT_APPLICABLE", skip
    if not absent_or(item, "DBInstanceArn", "PubliclyAccessible", False, bool):
        return result(False, publicly_accessible=False)
    sgs = _active_sgs(item, "VpcSecurityGroups")
    port = absent_or(item, "DBInstanceArn", "Endpoint.Port", None, int)
    if not sgs or not port:
        return result(False, publicly_accessible=True, reason="no active security group or endpoint port")
    open_groups = [get(g, "GroupId", str) for g in security_groups(index, sgs)
                   if any(sg_rule_open(r, "tcp", [port], any_address=True) for r in list_of_objects(get(g, "IpPermissions", list)))]
    if not open_groups:
        return result(False, publicly_accessible=True, open_security_groups=[])
    subnets = [get(s, "SubnetIdentifier", str) for s in list_of_objects(absent_or(item, "DBInstanceArn", "DBSubnetGroup.Subnets", [], list)) if s.get("SubnetStatus") == "Active"]
    public = [s for s in subnets if subnet_is_public_prowler(index, s)]
    return result(bool(public), open_security_groups=open_groups, public_subnets=public, endpoint_port=port)


@install("aws.cb.rds.instance_no_public_subnet", "rds_instance", "RDS instance DB subnet group has no public subnet",
    _instance_net("sg-closed", "subnet-priv"), _instance_net("sg-closed", "subnet-pub"),
    rows=[C + "rds_db_instance_no_public_subnet"], severity="high", category="network", control="SC-7",
    remediation="Review each DB subnet's effective route table; replace unapproved direct-IGW subnet membership with an owner-approved private subnet group after planning connectivity and failover. A NAT-only default route is not this finding.",
    docs=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html"],
    dependencies=["rds_instance", "subnet", "route_table"], extra={"index": _NET},
    note="Pinned Steampipe SQL grouped IGW and NAT routes, but AWS defines a NAT default route as outbound access from a private subnet. For this direct-internet-gateway subnet setting, inspect each DB subnet's effective explicit or VPC main route table; only a 0.0.0.0/0 route to igw- is public, and missing or incomplete evidence is UNKNOWN. This is a route configuration check, not workload reachability.")
def instance_subnet(item, index):
    subnets = [get(s, "SubnetIdentifier", str) for s in list_of_objects(get(item, "DBSubnetGroup.Subnets", list))]
    if not subnets:
        raise Unavailable("DB subnet group has no observed subnets")
    public = []
    for subnet_id in subnets:
        subnet = subnet_vpc(index, subnet_id)
        table, _ = subnet_route_table(index, subnet_id, get(subnet, "VpcId", str))
        routes = list_of_objects(get(table, "Routes", list))
        if not routes:
            raise Unavailable("effective subnet route table has no observed routes")
        for route in routes:
            guard(route)
            if route.get("DestinationCidrBlock") != "0.0.0.0/0":
                continue
            target_fields = ("GatewayId", "NatGatewayId", "TransitGatewayId", "NetworkInterfaceId",
                             "VpcPeeringConnectionId", "EgressOnlyInternetGatewayId", "LocalGatewayId",
                             "CarrierGatewayId", "CoreNetworkArn", "VpcEndpointId", "InstanceId")
            coverage = route.get("_coverage", {})
            for field in target_fields:
                status = coverage.get(field)
                if status is not None and (not isinstance(status, dict) or status.get("status") not in ("collected", "empty")):
                    raise Unavailable("subnet default-route target unavailable")
            targets = [(field, route[field]) for field in target_fields if field in route]
            if len(targets) != 1 or not isinstance(targets[0][1], str) or not targets[0][1]:
                raise Unavailable("missing or malformed subnet default-route target")
            gateway = route.get("GatewayId")
            if isinstance(gateway, str) and gateway.startswith("igw-"):
                public.append(subnet_id)
                break
    return result(bool(public), public_subnets=public)


# --------------------------------------------------------------------------- snapshots
def _snap_attrs(item, path):
    rows = list_of_objects(get(item, path, list))
    return [(get(r, "AttributeName", str), strings(get(r, "AttributeValues", list), "AttributeValues")) for r in rows]


_ISNAP = "Attributes.DBSnapshotAttributesResult.DBSnapshotAttributes"
_CSNAP = "Attributes.DBClusterSnapshotAttributesResult.DBClusterSnapshotAttributes"


def _snap(kind, values, engine="postgres", extra=None):
    path = _ISNAP if kind == "rds_snapshot" else _CSNAP
    from .fixtures import nest
    return {"Engine": engine, **(extra or {}), **nest(path, [{"AttributeName": "restore", "AttributeValues": values}])}


for _kind in ("rds_snapshot", "rds_cluster_snapshot"):
    def _snapshots(kind):
        path = _ISNAP if kind == "rds_snapshot" else _CSNAP
        label = "instance" if kind == "rds_snapshot" else "cluster"
        exact_rows = [C + "rds_db_snapshot_prohibit_public_access"] + ([X + "rds_db_snapshot_prohibit_public_access"] if kind == "rds_snapshot" else [X + "rds_db_cluster_snapshot_prohibit_public_access"])

        @install("aws.cb.rds." + label + "_snapshot_restore_not_all_exact", kind, "RDS " + label + " snapshot restore attribute does not include public access",
            _snap(kind, []), _snap(kind, ["all"]), rows=exact_rows, severity="critical", category="exposure", control="AC-3",
            remediation="Remove the 'all' value from the snapshot restore attribute (ModifyDB" + ("" if kind == "rds_snapshot" else "Cluster") + "SnapshotAttribute ValuesToRemove=all).",
            docs=[D_SNAP_ATTR if kind == "rds_snapshot" else D_CSNAP_ATTR],
            note="The pinned Steampipe/perimeter row used exact [\"all\"] equality. RDS DescribeDBSnapshotAttributes and DescribeDBClusterSnapshotAttributes define a restore attribute containing 'all' as public even with account IDs alongside it.")
        def exact(item, index):
            attrs = _snap_attrs(item, path)
            if not any(name == "restore" for name, _ in attrs):
                return unknown("snapshot restore attribute missing")
            hit = [name for name, values in attrs if name == "restore" and "all" in values]
            return result(bool(hit), public_attributes=hit)

        @install("aws.cb.rds." + label + "_snapshot_not_public_prowler", kind, "RDS " + label + " snapshot is not publicly shared",
            _snap(kind, ["222222222222"]), _snap(kind, ["all"]), rows=[P + "rds_snapshots_public_access"], severity="critical", category="exposure", control="AC-3",
            remediation="Remove the 'all' value from the snapshot restore attribute.", docs=[D_SNAP_ATTR if kind == "rds_snapshot" else D_CSNAP_ATTR],
            extra={"not_applicable": _snap(kind, [], engine="docdb")}, note="Prowler: 'all' in any attribute's AttributeValues; DocumentDB snapshots excluded.")
        def prowler_public(item, index):
            skip = _not_docdb(item)
            if skip:
                return "NOT_APPLICABLE", skip
            attrs = _snap_attrs(item, path)
            return result(public := any("all" in values for _, values in attrs), attributes=[n for n, _ in attrs], public_attribute=public)

        @install("aws.cb.rds." + label + "_snapshot_shared_accounts_review", kind, "RDS " + label + " snapshot is not shared outside the account without review",
            _snap(kind, []), _snap(kind, [], extra={}) , rows=[X + "rds_db_snapshot_shared_with_trusted_accounts"], severity="medium", category="exposure", control="AC-3",
            remediation="Confirm every account in the snapshot restore attribute is trusted; remove untrusted accounts.", docs=[D_SNAP_ATTR if kind == "rds_snapshot" else D_CSNAP_ATTR],
            extra={"fail": None, "manual": _snap(kind, ["222222222222"])},
            note="Perimeter trusted_accounts is a site-configured variable with placeholder defaults; shares to other accounts emit 'info', so they are MANUAL here and no shares PASS.")
        def shared(item, index):
            attrs = _snap_attrs(item, path)
            shared_with = sorted({v for _, values in attrs for v in values})
            if not shared_with:
                return result(False, shared_with=[])
            return "MANUAL", {"shared_with": shared_with, "question": "Are all of these accounts trusted for this snapshot?"}
    _snapshots(_kind)

from .fixtures import CASES as _CASES
for _label in ("instance", "cluster"):
    _c = _CASES["aws.cb.rds." + _label + "_snapshot_shared_accounts_review"]
    _c.pop("fail", None)


@install("aws.cb.rds.cluster_snapshot_encrypted", "rds_cluster_snapshot", "RDS cluster snapshot is encrypted",
    {"Engine": "aurora-mysql", "StorageEncrypted": True}, {"Engine": "aurora-mysql", "StorageEncrypted": False},
    rows=[P + "rds_snapshots_encrypted"], severity="high", control="SC-28",
    remediation="Copy the cluster snapshot with KMS encryption and delete the unencrypted copy.", docs=["https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DBClusterSnapshot.html"],
    extra={"not_applicable": {"Engine": "docdb", "StorageEncrypted": False}}, note="Cluster half of prowler rds_snapshots_encrypted; the instance half merges into aws.rds.snapshot_encryption.")
def csnap_encrypted(item, index):
    skip = _not_docdb(item)
    if skip:
        return "NOT_APPLICABLE", skip
    value = get(item, "StorageEncrypted", bool)
    return result(not value, storage_encrypted=value)


# --------------------------------------------------------------------------- event subscriptions (scope)
_REQUIRED = {"db-cluster": {"maintenance", "failure"}, "db-instance": {"maintenance", "configuration change", "failure"},
             "db-parameter-group": {"configuration change"}, "db-security-group": {"failure", "configuration change"}}
_TRIGGER = {"db-cluster": "rds_cluster", "db-instance": "rds_instance", "db-parameter-group": "rds_instance", "db-security-group": "rds_instance"}
_ROW = {"db-cluster": "rds_cluster_critical_event_subscription", "db-instance": "rds_instance_critical_event_subscription",
        "db-parameter-group": "rds_instance_event_subscription_parameter_groups", "db-security-group": "rds_instance_event_subscription_security_groups"}
_SEV = {"db-cluster": "medium", "db-instance": "medium", "db-parameter-group": "low", "db-security-group": "medium"}


for _source in _REQUIRED:
    def _subscription(source):
        trigger = _TRIGGER[source]
        anchor = {"scope": CONTEXT["scope"]}
        resources = inventory(trigger, [{"DBInstanceArn" if trigger == "rds_instance" else "DBClusterArn": "a"}])
        good = indexes(resources, inventory("rds_event_subscription", [{"SourceType": source, "Enabled": True, "EventCategoriesList": []}]))
        bad = indexes(resources, inventory("rds_event_subscription", [{"SourceType": source, "Enabled": True, "EventCategoriesList": ["maintenance"] if source != "db-parameter-group" else ["other"]}]))
        none = indexes(inventory(trigger, []), inventory("rds_event_subscription", []))

        @install("aws.cb.rds." + source.replace("db-", "").replace("-", "_") + "_critical_event_subscription", "rds_event_subscription",
            "Region with RDS resources has an enabled " + source + " event subscription for " + ", ".join(sorted(_REQUIRED[source])),
            anchor, anchor, rows=[P + _ROW[source]], severity=_SEV[source], control="SI-4", target="scope", dependencies=[trigger, "rds_event_subscription"],
            remediation="Create an enabled RDS event subscription with SourceType " + source + " for all categories or for " + ", ".join(sorted(_REQUIRED[source])) + ".",
            docs=[D_EVENTS, "https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_EventSubscription.html"],
            extra={"pass_index": good, "fail_index": bad, "not_applicable_index": none},
            note="Prowler emits one finding per subscription (and account-level FAILs for unrelated subscriptions); here one regional result: PASS when any enabled subscription of the source type has an empty category list or includes every required category (superset relaxed to avoid false positives). Regions without the triggering resources are NOT_APPLICABLE.")
        def evaluate(item, index):
            scope = scope_of(item)
            if not complete_items(index, trigger):
                return "NOT_APPLICABLE", {"scope": scope, "reason": "no " + trigger + " in region"}
            matching = []
            for sub in complete_items(index, "rds_event_subscription"):
                if get(sub, "SourceType", str) != source or not get(sub, "Enabled", bool):
                    continue
                categories = strings(absent_or(sub, "SourceType", "EventCategoriesList", [], list))
                if not categories or _REQUIRED[source] <= set(categories):
                    matching.append(sub.get("CustSubscriptionId"))
            return result(not matching, scope=scope, matching_subscriptions=matching)
    _subscription(_source)


# =========================================================================== Neptune
def _neptune(item):
    engine = get(item, "Engine", str)
    return None if engine == "neptune" else {"engine": engine, "reason": "not a Neptune cluster"}


NEP = {"DBClusterArn": "arn:aws:rds:us-east-1:111111111111:cluster:n1", "Engine": "neptune"}
for _cid, _path, _good, _bad, _rows, _sev, _rem, _ctl in (
    ("aws.cb.neptune.backup_retention_7_days", "BackupRetentionPeriod", None, None, ["neptune_cluster_backup_enabled", "neptune_db_cluster_automated_backup_enabled"], "medium", "Set the Neptune cluster BackupRetentionPeriod to at least 7 days.", "CP-9"),
    ("aws.cb.neptune.copy_tags_to_snapshot", "CopyTagsToSnapshot", True, False, ["neptune_cluster_copy_tags_to_snapshots", "neptune_db_cluster_copy_tags_to_snapshot_enabled"], "low", "Enable CopyTagsToSnapshot on the Neptune cluster.", "CM-6"),
    ("aws.cb.neptune.deletion_protection", "DeletionProtection", True, False, ["neptune_cluster_deletion_protection", "neptune_db_cluster_deletion_protection_enabled"], "medium", "Enable DeletionProtection on the Neptune cluster.", "CP-9"),
    ("aws.cb.neptune.iam_authentication", "IAMDatabaseAuthenticationEnabled", True, False, ["neptune_cluster_iam_authentication_enabled", "neptune_db_cluster_iam_authentication_enabled"], "medium", "Enable IAM database authentication on the Neptune cluster.", "IA-2"),
    ("aws.cb.neptune.storage_encrypted", "StorageEncrypted", True, False, ["neptune_cluster_storage_encrypted", "neptune_db_cluster_encryption_at_rest_enabled"], "high", "Create an encrypted Neptune cluster from an encrypted snapshot copy.", "SC-28"),
    ("aws.cb.neptune.multi_az", "MultiAZ", True, False, ["neptune_cluster_multi_az"], "medium", "Add read replicas in other Availability Zones so the Neptune cluster is Multi-AZ.", "CP-10"),
):
    if _path == "BackupRetentionPeriod":
        @install(_cid, "neptune_cluster", "Neptune cluster retains automated backups at least 7 days", {**NEP, "BackupRetentionPeriod": 7}, {**NEP, "BackupRetentionPeriod": 1},
            rows=[(P if r.startswith("neptune_cluster") else C) + r for r in _rows], severity=_sev, remediation=_rem, control=_ctl, docs=[D_NEPTUNE],
            extra={"not_applicable": {**NEP, "Engine": "docdb", "BackupRetentionPeriod": 1}}, note="Prowler minimum_backup_retention_period default 7 and steampipe >= 7.")
        def nep_backup(item, index):
            skip = _neptune(item)
            if skip:
                return "NOT_APPLICABLE", skip
            days = get(item, "BackupRetentionPeriod", int)
            return result(days < 7, backup_retention_days=days)
    else:
        flag(_cid, "neptune_cluster", "Neptune cluster " + _path + " is enabled", _path, rows=[(P if r.startswith("neptune_cluster") else C) + r for r in _rows],
             severity=_sev, remediation=_rem, sentinel="DBClusterArn", base=NEP, applies=_neptune, na_item={**NEP, "Engine": "docdb", _path: False},
             docs=[D_NEPTUNE], control=_ctl, **({"default": False} if _path == "IAMDatabaseAuthenticationEnabled" else {}))


@install("aws.cb.neptune.audit_log_export", "neptune_cluster", "Neptune cluster exports audit logs to CloudWatch Logs",
    {**NEP, "EnabledCloudwatchLogsExports": ["audit"]}, NEP, rows=[P + "neptune_cluster_integration_cloudwatch_logs", C + "neptune_db_cluster_audit_logging_enabled"],
    severity="medium", control="AU-2", remediation="Enable the audit CloudWatch Logs export and the neptune_enable_audit_log parameter.", docs=[D_NEPTUNE],
    extra={"not_applicable": {**NEP, "Engine": "docdb"}})
def nep_audit(item, index):
    skip = _neptune(item)
    if skip:
        return "NOT_APPLICABLE", skip
    exports = _exports(item, "DBClusterArn")
    return result("audit" not in exports, exports=exports)


_NSNAP = {"Engine": "neptune", "StorageEncrypted": True}


@install("aws.cb.neptune.snapshot_encrypted", "rds_cluster_snapshot", "Neptune cluster snapshot is encrypted",
    _NSNAP, {**_NSNAP, "StorageEncrypted": False}, rows=[P + "neptune_cluster_snapshot_encrypted", C + "neptune_db_cluster_snapshot_encryption_at_rest_enabled"],
    severity="medium", control="SC-28", remediation="Copy the Neptune snapshot with KMS encryption and delete the unencrypted snapshot.",
    docs=["https://docs.aws.amazon.com/neptune/latest/apiref/API_DBClusterSnapshot.html"], extra={"not_applicable": {**_NSNAP, "Engine": "aurora-mysql"}})
def nep_snap_enc(item, index):
    skip = _neptune(item)
    if skip:
        return "NOT_APPLICABLE", skip
    value = get(item, "StorageEncrypted", bool)
    return result(not value, storage_encrypted=value)


@install("aws.cb.neptune.snapshot_not_public_prowler", "rds_cluster_snapshot", "Neptune cluster snapshot is not publicly shared",
    _snap("rds_cluster_snapshot", [], engine="neptune"), _snap("rds_cluster_snapshot", ["all", "222222222222"], engine="neptune"),
    rows=[P + "neptune_cluster_public_snapshot"], severity="critical", category="exposure", control="AC-3",
    remediation="Remove 'all' from the Neptune snapshot restore attribute.", docs=[D_CSNAP_ATTR], extra={"not_applicable": _snap("rds_cluster_snapshot", [], engine="aurora-mysql")})
def nep_snap_public(item, index):
    skip = _neptune(item)
    if skip:
        return "NOT_APPLICABLE", skip
    public = any("all" in values for _, values in _snap_attrs(item, _CSNAP))
    return result(public, public_attribute_value_detected=public)


@install("aws.cb.neptune.snapshot_restore_not_all_exact", "rds_cluster_snapshot", "Neptune cluster snapshot restore attribute does not include public access",
    _snap("rds_cluster_snapshot", [], engine="neptune"), _snap("rds_cluster_snapshot", ["all"], engine="neptune"),
    rows=[C + "neptune_db_cluster_snapshot_prohibit_public_access"], severity="critical", category="exposure", control="AC-3",
    remediation="Remove 'all' from the Neptune snapshot restore attribute.", docs=[D_CSNAP_ATTR], extra={"not_applicable": _snap("rds_cluster_snapshot", [], engine="aurora-mysql")},
    note="The pinned source used exact [\"all\"] equality. Neptune's DescribeDBClusterSnapshotAttributes API defines a restore attribute containing 'all' as public even when account IDs are also present.")
def nep_snap_exact(item, index):
    skip = _neptune(item)
    if skip:
        return "NOT_APPLICABLE", skip
    attrs = _snap_attrs(item, _CSNAP)
    if not any(name == "restore" for name, _ in attrs):
        return unknown("snapshot restore attribute missing")
    public = any(name == "restore" and "all" in values for name, values in attrs)
    return result(public, public_restore_attribute=public)


def _subnet_group_index(subnet):
    return indexes(_NET, inventory("rds_db_subnet_group", [{"DBSubnetGroupName": "g1", "VpcId": "vpc-1", "Subnets": [{"SubnetIdentifier": subnet, "SubnetStatus": "Active"}]}]))


def _group_subnets(item, index):
    name = get(item, "DBSubnetGroup", str)
    rows = [g for g in complete_items(index, "rds_db_subnet_group") if g.get("DBSubnetGroupName") == name]
    if len(rows) != 1:
        raise Unavailable("DB subnet group join unresolved")
    return [get(s, "SubnetIdentifier", str) for s in list_of_objects(get(rows[0], "Subnets", list))]


for _cid, _row, _helper, _label in (("aws.cb.neptune.no_public_subnet_prowler", P + "neptune_cluster_uses_public_subnet", subnet_is_public_prowler, "0.0.0.0/0 via igw-"),
                                   ("aws.cb.neptune.no_public_subnet_steampipe", C + "neptune_db_cluster_no_public_subnet", subnet_is_public_prowler, "0.0.0.0/0 via igw-")):
    def _nep_subnet(cid, row, helper, label):
        @install(cid, "neptune_cluster", "Neptune cluster subnet group has no public subnet (" + label + ")", {**NEP, "DBSubnetGroup": "g1"}, {**NEP, "DBSubnetGroup": "g1"},
            rows=[row], severity="medium", category="network", control="SC-7", remediation="Use a DB subnet group with only private subnets for the Neptune cluster.",
            docs=["https://docs.aws.amazon.com/neptune/latest/userguide/get-started-vpc.html"], dependencies=["neptune_cluster", "rds_db_subnet_group", "subnet", "route_table"],
            extra={"pass_index": _subnet_group_index("subnet-priv"), "fail_index": _subnet_group_index("subnet-pub")},
            note="Joins DescribeDBSubnetGroups by the cluster DBSubnetGroup name; public classification: " + label + " in the effective route table. The pinned Steampipe SQL also counts outbound NAT routes as public; that is excluded from this ingress-exposure check.")
        def evaluate(item, index):
            skip = _neptune(item)
            if skip:
                return "NOT_APPLICABLE", skip
            public = [s for s in _group_subnets(item, index) if helper(index, s)]
            return result(bool(public), public_subnets=public)
    _nep_subnet(_cid, _row, _helper, _label)


# =========================================================================== Redshift
RS = {"ClusterIdentifier": "rs1", "Encrypted": True}
for _cid, _path, _good, _bad, _rows, _sev, _rem, _ctl, _cat in (
    ("aws.cb.redshift.allow_version_upgrade", "AllowVersionUpgrade", True, False, [P + "redshift_cluster_automatic_upgrades", C + "redshift_cluster_automatic_upgrade_major_versions_enabled"], "medium", "Enable AllowVersionUpgrade on the Redshift cluster.", "SI-2", "hardening"),
    ("aws.cb.redshift.enhanced_vpc_routing", "EnhancedVpcRouting", True, False, [P + "redshift_cluster_enhanced_vpc_routing", C + "redshift_cluster_enhanced_vpc_routing_enabled"], "medium", "Enable EnhancedVpcRouting on the Redshift cluster.", "SC-7", "network"),
    ("aws.cb.redshift.multi_az", "MultiAZ", "Enabled", "Disabled", [P + "redshift_cluster_multi_az_enabled", C + "redshift_cluster_multiple_az_enabled"], "medium", "Enable Multi-AZ on the RA3 Redshift cluster.", "CP-10", "hardening"),
    ("aws.cb.redshift.encrypted", "Encrypted", True, False, [P + "redshift_cluster_encrypted_at_rest"], "critical", "Enable encryption on the Redshift cluster (ModifyCluster Encrypted=true).", "SC-28", "hardening"),
    ("aws.cb.redshift.not_publicly_accessible", "PubliclyAccessible", False, True, [C + "redshift_cluster_prohibit_public_access", X + "redshift_cluster_prohibit_public_access"], "critical", "Set PubliclyAccessible to false on the Redshift cluster.", "SC-7", "exposure"),
):
    flag(_cid, "redshift_cluster", "Redshift cluster " + _path + " is " + str(_good), _path, rows=_rows, severity=_sev, remediation=_rem, sentinel="ClusterIdentifier",
         base={"ClusterIdentifier": "rs1"}, good=_good, bad=_bad, expected=type(_good), docs=[D_REDSHIFT], control=_ctl, category=_cat,
         note="AWS DescribeClusters MultiAZ is the string Enabled/Disabled; steampipe exposes it as a boolean." if _path == "MultiAZ" else None)


for _cid, _path, _value, _rows, _rem in (
    ("aws.cb.redshift.non_default_master_username", "MasterUsername", "awsuser", [P + "redshift_cluster_non_default_username", C + "redshift_cluster_no_default_admin_name"], "Create the cluster with a master username other than awsuser and migrate."),
    ("aws.cb.redshift.non_default_database_name", "DBName", "dev", [P + "redshift_cluster_non_default_database_name", C + "redshift_cluster_no_default_database_name"], "Use a database name other than dev."),
):
    def _not_default(cid, path, value, rows, rem):
        @install(cid, "redshift_cluster", "Redshift cluster " + path + " is not the default " + value, {"ClusterIdentifier": "rs1", path: "custom"}, {"ClusterIdentifier": "rs1", path: value},
            rows=rows, severity="medium" if path == "MasterUsername" else "low", control="IA-5" if path == "MasterUsername" else "CM-6", remediation=rem, docs=[D_REDSHIFT])
        def evaluate(item, index):
            actual = get(item, path, str)
            return result(actual == value, **{path: actual})
    _not_default(_cid, _path, _value, _rows, _rem)


@install("aws.cb.redshift.audit_logging", "redshift_cluster", "Redshift cluster audit logging is enabled",
    {"ClusterIdentifier": "rs1", "LoggingStatus": {"LoggingEnabled": True}}, {"ClusterIdentifier": "rs1", "LoggingStatus": {"LoggingEnabled": False}},
    rows=[P + "redshift_cluster_audit_logging", C + "redshift_cluster_audit_logging_enabled"], severity="medium", control="AU-2",
    remediation="Enable audit logging to S3 or CloudWatch (EnableLogging).", docs=["https://docs.aws.amazon.com/redshift/latest/APIReference/API_DescribeLoggingStatus.html"],
    note="Needs LoggingStatus = DescribeLoggingStatus response.")
def rs_logging(item, index):
    value = get(item, "LoggingStatus.LoggingEnabled", bool)
    return result(not value, logging_enabled=value)


@install("aws.cb.redshift.encrypted_and_logging", "redshift_cluster", "Redshift cluster is encrypted and audit logging is enabled",
    {"ClusterIdentifier": "rs1", "Encrypted": True, "LoggingStatus": {"LoggingEnabled": True}}, {"ClusterIdentifier": "rs1", "Encrypted": True, "LoggingStatus": {"LoggingEnabled": False}},
    rows=[C + "redshift_cluster_encryption_logging_enabled"], severity="medium", control="AU-2",
    remediation="Enable cluster encryption and audit logging.", docs=[D_REDSHIFT])
def rs_enc_logging(item, index):
    if not get(item, "Encrypted", bool):
        return result(True, encrypted=False)
    value = get(item, "LoggingStatus.LoggingEnabled", bool)
    return result(not value, encrypted=True, logging_enabled=value)


@install("aws.cb.redshift.require_ssl", "redshift_cluster", "Redshift cluster parameter group sets require_ssl to true",
    {"ClusterIdentifier": "rs1", "ParameterGroupValues": {"require_ssl": "true"}}, {"ClusterIdentifier": "rs1", "ParameterGroupValues": {"require_ssl": "false"}},
    rows=[P + "redshift_cluster_in_transit_encryption_enabled", C + "redshift_cluster_encryption_in_transit_enabled"], severity="high", control="SC-8",
    remediation="Set require_ssl = true in the cluster parameter group and reboot.", docs=["https://docs.aws.amazon.com/redshift/latest/mgmt/connecting-ssl-support.html"],
    note="Needs ParameterGroupValues (DescribeClusterParameters for the cluster's parameter group, allowlisted require_ssl).")
def rs_ssl(item, index):
    values = get(item, "ParameterGroupValues", dict)
    value = get(values, "require_ssl", str)
    if value.lower() not in {"true", "false"}:
        raise Unavailable("unrecognized Redshift require_ssl parameter")
    return result(value.lower() != "true", require_ssl=value)


def _rs_snaps(rows):
    return inventory("redshift_snapshot", rows)


@install("aws.cb.redshift.has_snapshot", "redshift_cluster", "Redshift cluster has at least one snapshot",
    {"ClusterIdentifier": "rs1"}, {"ClusterIdentifier": "rs1"}, rows=[P + "redshift_cluster_automated_snapshot"], severity="high", control="CP-9",
    remediation="Keep automated snapshots enabled (AutomatedSnapshotRetentionPeriod > 0).", docs=["https://docs.aws.amazon.com/redshift/latest/APIReference/API_DescribeClusterSnapshots.html"],
    dependencies=["redshift_cluster", "redshift_snapshot"], extra={"pass_index": _rs_snaps([{"ClusterIdentifier": "rs1", "SnapshotType": "automated"}]), "fail_index": _rs_snaps([])},
    note="Prowler: the cluster has any snapshot in DescribeClusterSnapshots.")
def rs_snapshot(item, index):
    name = get(item, "ClusterIdentifier", str)
    snaps = [s for s in complete_items(index, "redshift_snapshot") if s.get("ClusterIdentifier") == name]
    return result(not snaps, snapshots=len(snaps))


@install("aws.cb.redshift.snapshot_retention_7_days", "redshift_cluster", "Redshift automated snapshot retention is at least 7 days",
    {"ClusterIdentifier": "rs1", "AutomatedSnapshotRetentionPeriod": 7}, {"ClusterIdentifier": "rs1", "AutomatedSnapshotRetentionPeriod": 1},
    rows=[C + "redshift_cluster_automatic_snapshots_min_7_days"], severity="medium", control="CP-9", remediation="Set AutomatedSnapshotRetentionPeriod to at least 7.", docs=[D_REDSHIFT])
def rs_retention(item, index):
    days = get(item, "AutomatedSnapshotRetentionPeriod", int)
    return result(days < 7, retention_days=days)


@install("aws.cb.redshift.maintenance_settings", "redshift_cluster", "Redshift cluster allows version upgrades and keeps 7 days of snapshots",
    {"ClusterIdentifier": "rs1", "AllowVersionUpgrade": True, "AutomatedSnapshotRetentionPeriod": 7}, {"ClusterIdentifier": "rs1", "AllowVersionUpgrade": True, "AutomatedSnapshotRetentionPeriod": 3},
    rows=[C + "redshift_cluster_maintenance_settings_check"], severity="medium", control="SI-2", remediation="Enable AllowVersionUpgrade and set snapshot retention to at least 7 days.", docs=[D_REDSHIFT])
def rs_maint(item, index):
    upgrade = get(item, "AllowVersionUpgrade", bool)
    days = get(item, "AutomatedSnapshotRetentionPeriod", int)
    return result(not (upgrade and days >= 7), allow_version_upgrade=upgrade, retention_days=days)


@install("aws.cb.redshift.kms_key_declared", "redshift_cluster", "Redshift cluster is encrypted with a declared KMS key",
    {"ClusterIdentifier": "rs1", "Encrypted": True, "KmsKeyId": KMS_ARN}, {"ClusterIdentifier": "rs1", "Encrypted": True},
    rows=[C + "redshift_cluster_kms_enabled"], severity="medium", control="SC-28", remediation="Encrypt the cluster with an AWS KMS key.", docs=[D_REDSHIFT])
def rs_kms(item, index):
    enc = get(item, "Encrypted", bool)
    key = absent_or(item, "ClusterIdentifier", "KmsKeyId", None, str)
    return result(not (enc and key), encrypted=enc, kms_key_id=key)


@install("aws.cb.redshift.cmk_encryption", "redshift_cluster", "Redshift cluster is encrypted with a customer managed KMS key",
    {"ClusterIdentifier": "rs1", "Encrypted": True, "KmsKeyId": KMS_ARN}, {"ClusterIdentifier": "rs1", "Encrypted": False},
    rows=[C + "redshift_cluster_encrypted_with_cmk"], severity="medium", control="SC-28", remediation="Re-encrypt the cluster with a customer managed KMS key.",
    docs=[D_REDSHIFT], dependencies=["redshift_cluster", "kms_key"], extra={"index": _kms_index()})
def rs_cmk(item, index):
    if not get(item, "Encrypted", bool):
        return result(True, encrypted=False)
    manager = kms_manager(index, get(item, "KmsKeyId", str))
    return result(manager != "CUSTOMER", encrypted=True, key_manager=manager)


def _rs_net(sg_open, subnet):
    return indexes(_NET, inventory("redshift_subnet_group", [{"ClusterSubnetGroupName": "rg", "Subnets": [{"SubnetIdentifier": subnet}]}]),
                   inventory("security_group", [{"GroupId": "sg-1", "IpPermissions": [{"IpProtocol": "-1" if sg_open else "tcp", "FromPort": 5439, "ToPort": 5439, "IpRanges": [{"CidrIp": "0.0.0.0/0" if sg_open else "10.0.0.0/8"}], "Ipv6Ranges": []}]}]))


_RS_NET_ITEM = {"ClusterIdentifier": "rs1", "PubliclyAccessible": True, "Endpoint": {"Address": "rs1.example", "Port": 5439}, "ClusterSubnetGroupName": "rg", "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-1", "Status": "active"}]}


@install("aws.cb.redshift.internet_exposed", "redshift_cluster", "Redshift cluster is not public in a public subnet with an all-ports open security group",
    _RS_NET_ITEM, _RS_NET_ITEM, rows=[P + "redshift_cluster_public_access"], severity="critical", category="exposure", control="SC-7",
    remediation="Disable PubliclyAccessible, use private subnets and remove 0.0.0.0/0 ingress from the cluster security groups.", docs=[D_REDSHIFT],
    dependencies=["redshift_cluster", "redshift_subnet_group", "security_group", "subnet", "route_table"],
    extra={"pass_index": _rs_net(True, "subnet-priv"), "fail_index": _rs_net(True, "subnet-pub")},
    note="Prowler: endpoint address + PubliclyAccessible, any public subnet (0.0.0.0/0 via igw-) in the cluster subnet group, and a VPC SG rule with check_security_group(rule, 'tcp', any_address=True) (all ports or protocol -1).")
def rs_exposed(item, index):
    address = absent_or(item, "ClusterIdentifier", "Endpoint.Address", None, str)
    if not (address and get(item, "PubliclyAccessible", bool)):
        return result(False, publicly_accessible=False)
    name = get(item, "ClusterSubnetGroupName", str)
    groups = [g for g in complete_items(index, "redshift_subnet_group") if g.get("ClusterSubnetGroupName") == name]
    if len(groups) != 1:
        raise Unavailable("cluster subnet group join unresolved")
    subnets = [get(s, "SubnetIdentifier", str) for s in list_of_objects(get(groups[0], "Subnets", list))]
    if not any(subnet_is_public_prowler(index, s) for s in subnets):
        return result(False, public_subnet=False)
    sgs = [get(g, "VpcSecurityGroupId", str) for g in list_of_objects(get(item, "VpcSecurityGroups", list))]
    open_groups = [get(g, "GroupId", str) for g in security_groups(index, sgs) if any(sg_rule_open(r, "tcp", None, any_address=True) for r in list_of_objects(get(g, "IpPermissions", list)))]
    return result(bool(open_groups), open_security_groups=open_groups)


def _sg_port_open(rule, port):
    ranges = [r.get("CidrIp") for r in list_of_objects(rule.get("IpRanges", []))] + [r.get("CidrIpv6") for r in list_of_objects(rule.get("Ipv6Ranges", []))]
    if not any(c in ("0.0.0.0/0", "::/0") for c in ranges):
        return False
    if str(rule.get("IpProtocol")) == "-1" and rule.get("FromPort") is None:
        return True
    low, high = rule.get("FromPort"), rule.get("ToPort")
    return isinstance(low, int) and isinstance(high, int) and low <= port <= high


@install("aws.cb.redshift.security_group_port_restricted", "redshift_cluster", "Redshift security groups do not allow the cluster port from 0.0.0.0/0 or ::/0",
    {"ClusterIdentifier": "rs1", "Endpoint": {"Port": 5439}, "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-1"}]}, {"ClusterIdentifier": "rs1", "Endpoint": {"Port": 5439}, "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-1"}]},
    rows=[C + "redshift_cluster_security_group_restrict_ingress_redshift_port"], severity="high", category="network", control="SC-7",
    remediation="Restrict security group ingress on the Redshift port to known CIDRs or security groups.", docs=[D_REDSHIFT],
    dependencies=["redshift_cluster", "security_group"], extra={"pass_index": _rs_net(False, "x"), "fail_index": _rs_net(True, "x")},
    note="Source: ingress from 0.0.0.0/0 or ::/0 with protocol -1 (no from_port) or a port range covering coalesce(endpoint port, 5439). Any protocol with a covering range counts.")
def rs_sg(item, index):
    port = absent_or(item, "ClusterIdentifier", "Endpoint.Port", 5439, int)
    sgs = [get(g, "VpcSecurityGroupId", str) for g in list_of_objects(get(item, "VpcSecurityGroups", list))]
    offending = [get(g, "GroupId", str) for g in security_groups(index, sgs) if any(_sg_port_open(r, port) for r in list_of_objects(get(g, "IpPermissions", list)))]
    return result(bool(offending), port=port, offending_security_groups=offending)


# --------------------------------------------------------------------------- Redshift Serverless
NS = {"namespaceArn": "arn:aws:redshift-serverless:us-east-1:111111111111:namespace/n"}
WG = {"workgroupArn": "arn:aws:redshift-serverless:us-east-1:111111111111:workgroup/w"}
D_NS = "https://docs.aws.amazon.com/redshift-serverless/latest/APIReference/API_Namespace.html"
D_WG = "https://docs.aws.amazon.com/redshift-serverless/latest/APIReference/API_Workgroup.html"


@install("aws.cb.redshiftserverless.connection_user_log_exports", "redshiftserverless_namespace", "Redshift Serverless namespace exports connection and user logs",
    {**NS, "logExports": ["connectionlog", "userlog", "useractivitylog"]}, {**NS, "logExports": ["userlog"]},
    rows=[C + "redshiftserverless_namespace_export_connection_and_user_log_to_cloudwatch"], severity="medium", control="AU-2",
    remediation="Configure the namespace logExports to include connectionlog and userlog.", docs=[D_NS])
def ns_logs(item, index):
    exports = strings(absent_or(item, "namespaceArn", "logExports", [], list))
    return result(not {"connectionlog", "userlog"} <= set(exports), log_exports=exports)


for _cid, _path, _value, _row in (("aws.cb.redshiftserverless.non_default_admin_username", "adminUsername", "admin", "redshiftserverless_namespace_no_default_admin_username"),
                                  ("aws.cb.redshiftserverless.non_default_database_name", "dbName", "dev", "redshiftserverless_namespace_no_default_database_username")):
    def _ns(cid, path, value, row):
        @install(cid, "redshiftserverless_namespace", "Redshift Serverless namespace " + path + " is not " + value, {**NS, path: "custom"}, {**NS, path: value},
            rows=[C + row], severity="low", control="IA-5", remediation="Create the namespace with a non-default " + path + ".", docs=[D_NS])
        def evaluate(item, index):
            actual = get(item, path, str)
            return result(actual == value, **{path: actual})
    _ns(_cid, _path, _value, _row)


@install("aws.cb.redshiftserverless.require_ssl", "redshiftserverless_workgroup", "Redshift Serverless workgroup requires SSL",
    {**WG, "configParameters": [{"parameterKey": "require_ssl", "parameterValue": "true"}]}, {**WG, "configParameters": [{"parameterKey": "require_ssl", "parameterValue": "false"}]},
    rows=[C + "redshiftserverless_workgroup_encryption_in_transit_enabled"], severity="high", control="SC-8",
    remediation="Set the require_ssl config parameter to true on the workgroup.", docs=["https://docs.aws.amazon.com/redshift-serverless/latest/APIReference/API_ConfigParameter.html"])
def wg_ssl(item, index):
    params = list_of_objects(get(item, "configParameters", list))
    ok = any(p.get("parameterKey") == "require_ssl" and p.get("parameterValue") == "true" for p in params)
    return result(not ok, require_ssl_enabled=ok)


flag("aws.cb.redshiftserverless.enhanced_vpc_routing", "redshiftserverless_workgroup", "Redshift Serverless workgroup uses enhanced VPC routing", "enhancedVpcRouting",
     rows=[C + "redshiftserverless_workgroup_enhanced_vpc_routing_enabled"], severity="medium", remediation="Enable enhancedVpcRouting on the workgroup.", sentinel="workgroupArn",
     base=WG, docs=[D_WG], category="network", control="SC-7")
flag("aws.cb.redshiftserverless.not_publicly_accessible", "redshiftserverless_workgroup", "Redshift Serverless workgroup is not publicly accessible", "publiclyAccessible",
     rows=[C + "redshiftserverless_workgroup_restrict_public_access"], severity="high", remediation="Set publiclyAccessible to false on the workgroup.", sentinel="workgroupArn",
     base=WG, good=False, bad=True, docs=[D_WG], category="exposure", control="SC-7")


# =========================================================================== MemoryDB
MDB = {"ARN": "arn:aws:memorydb:us-east-1:111111111111:cluster/m"}
flag("aws.cb.memorydb.auto_minor_version_upgrade", "memorydb_cluster", "MemoryDB cluster enables automatic minor version upgrades", "AutoMinorVersionUpgrade",
     rows=[P + "memorydb_cluster_auto_minor_version_upgrades"], severity="medium", remediation="Enable AutoMinorVersionUpgrade on the MemoryDB cluster.", sentinel="ARN", base=MDB,
     docs=["https://docs.aws.amazon.com/memorydb/latest/APIReference/API_Cluster.html"], control="SI-2")
flag("aws.cb.memorydb.tls_enabled", "memorydb_cluster", "MemoryDB cluster enables in-transit encryption (TLS)", "TLSEnabled",
     rows=[P + "memorydb_cluster_in_transit_encryption_enabled"], severity="medium", remediation="Recreate the MemoryDB cluster with TLSEnabled true.", sentinel="ARN", base=MDB,
     docs=["https://docs.aws.amazon.com/memorydb/latest/APIReference/API_Cluster.html"], control="SC-8")


# =========================================================================== OpenSearch
DS = "Domain.DomainStatus."


def _os(status):
    return {"DomainName": "d", "Domain": {"DomainStatus": {"ARN": "arn:aws:es:us-east-1:111111111111:domain/d", **status}}}


def _ds(item, path, default=None, expected=None, strict=True):
    get(item, "Domain.DomainStatus.ARN", str)
    if strict:
        return get(item, DS + path, expected)
    return absent_or(get(item, "Domain.DomainStatus", dict), "ARN", path, default, expected)


def os_check(cid, title, rows, sev, rem, passing, failing, *, docs=(D_OS,), note=None, category="hardening", control="CM-6", extra=None, dependencies=None):
    def decorate(function):
        return install(cid, "opensearch_domain", title, _os(passing), _os(failing), rows=rows, severity=sev, remediation=rem, docs=list(docs), note=note,
                       category=category, control=control, extra=extra, dependencies=dependencies)(function)
    return decorate


@os_check("aws.cb.opensearch.encryption_at_rest", "OpenSearch domain encryption at rest is enabled",
    [C + "opensearch_domain_encryption_at_rest_enabled", P + "opensearch_service_domains_encryption_at_rest_enabled"], "critical",
    "Enable EncryptionAtRestOptions on the domain.", {"EncryptionAtRestOptions": {"Enabled": True}}, {"EncryptionAtRestOptions": {"Enabled": False}}, control="SC-28")
def os_enc(item, index):
    value = _ds(item, "EncryptionAtRestOptions.Enabled", expected=bool)
    return result(not value, enabled=value)


@os_check("aws.cb.opensearch.fine_grained_access_control", "OpenSearch domain fine-grained access control is enabled",
    [C + "opensearch_domain_fine_grained_access_enabled", P + "opensearch_service_domains_access_control_enabled"], "high",
    "Enable AdvancedSecurityOptions (fine-grained access control).", {"AdvancedSecurityOptions": {"Enabled": True}}, {"AdvancedSecurityOptions": {"Enabled": False}}, control="AC-3")
def os_fgac(item, index):
    value = _ds(item, "AdvancedSecurityOptions.Enabled", False, bool, strict=False)
    return result(not value, enabled=value)


@os_check("aws.cb.opensearch.internal_user_database_disabled", "OpenSearch domain internal user database is disabled",
    [C + "opensearch_domain_internal_user_database_disabled", P + "opensearch_service_domains_internal_user_database_enabled"], "medium",
    "Use IAM or SAML users instead of the internal user database.", {"AdvancedSecurityOptions": {"Enabled": True, "InternalUserDatabaseEnabled": False}}, {"AdvancedSecurityOptions": {"Enabled": True, "InternalUserDatabaseEnabled": True}}, control="IA-2")
def os_iudb(item, index):
    value = _ds(item, "AdvancedSecurityOptions.InternalUserDatabaseEnabled", False, bool, strict=False)
    return result(value, internal_user_database=value)


@os_check("aws.cb.opensearch.service_software_current", "OpenSearch domain has no pending service software update",
    [C + "opensearch_domain_updated_with_latest_service_software_version", P + "opensearch_service_domains_updated_to_the_latest_service_software_version"], "high",
    "Apply the available service software update (StartServiceSoftwareUpdate).", {"ServiceSoftwareOptions": {"UpdateAvailable": False}}, {"ServiceSoftwareOptions": {"UpdateAvailable": True}}, control="SI-2")
def os_sw(item, index):
    value = _ds(item, "ServiceSoftwareOptions.UpdateAvailable", expected=bool)
    return result(value, update_available=value)


@os_check("aws.cb.opensearch.data_node_fault_tolerance", "OpenSearch domain has zone awareness and at least three data nodes",
    [C + "opensearch_domain_data_node_fault_tolerance", P + "opensearch_service_domains_fault_tolerant_data_nodes"], "medium",
    "Enable zone awareness and configure at least three data nodes.", {"ClusterConfig": {"InstanceCount": 3, "ZoneAwarenessEnabled": True}}, {"ClusterConfig": {"InstanceCount": 3, "ZoneAwarenessEnabled": False}},
    control="CP-10", note="Numeric InstanceCount >= 3; the steampipe text comparison ('10' > '2' is false) is an upstream defect not reproduced.")
def os_data(item, index):
    count = _ds(item, "ClusterConfig.InstanceCount", expected=int)
    zone = _ds(item, "ClusterConfig.ZoneAwarenessEnabled", False, bool, strict=False)
    return result(not (count >= 3 and zone), instance_count=count, zone_awareness=zone)


@os_check("aws.cb.opensearch.dedicated_master_nodes", "OpenSearch domain has at least three dedicated master nodes",
    [P + "opensearch_service_domains_fault_tolerant_master_nodes"], "medium", "Enable dedicated master nodes with a count of at least three.",
    {"ClusterConfig": {"DedicatedMasterEnabled": True, "DedicatedMasterCount": 3}}, {"ClusterConfig": {"DedicatedMasterEnabled": False}}, control="CP-10")
def os_master(item, index):
    enabled = _ds(item, "ClusterConfig.DedicatedMasterEnabled", False, bool, strict=False)
    if not enabled:
        return result(True, dedicated_master=False)
    count = _ds(item, "ClusterConfig.DedicatedMasterCount", expected=int)
    return result(count < 3, dedicated_master_count=count)


@os_check("aws.cb.opensearch.cognito_dashboards_auth", "OpenSearch domain enables Cognito authentication for Dashboards",
    [C + "opensearch_domain_cognito_authentication_enabled_for_kibana"], "medium", "Enable CognitoOptions for OpenSearch Dashboards.",
    {"CognitoOptions": {"Enabled": True}}, {"CognitoOptions": {"Enabled": False}}, control="IA-2")
def os_cognito(item, index):
    value = _ds(item, "CognitoOptions.Enabled", False, bool, strict=False)
    return result(not value, cognito=value)


@os_check("aws.cb.opensearch.cognito_or_saml_dashboards_auth", "OpenSearch domain enables Cognito or SAML authentication for Dashboards",
    [P + "opensearch_service_domains_use_cognito_authentication_for_kibana"], "medium", "Enable Cognito or SAML authentication for OpenSearch Dashboards.",
    {"CognitoOptions": {"Enabled": False}, "AdvancedSecurityOptions": {"SAMLOptions": {"Enabled": True}}}, {"CognitoOptions": {"Enabled": False}}, control="IA-2")
def os_cognito_saml(item, index):
    cognito = _ds(item, "CognitoOptions.Enabled", False, bool, strict=False)
    saml = _ds(item, "AdvancedSecurityOptions.SAMLOptions.Enabled", False, bool, strict=False)
    return result(not (cognito or saml), cognito=cognito, saml=saml)


_SKIP_N2N = ("af-south-1", "eu-south-1", "cn-north-1", "cn-northwest-1")


def _region(item):
    arn = get(item, "Domain.DomainStatus.ARN", str)
    parts = arn.split(":")
    if len(parts) < 4 or not parts[3]:
        raise Unavailable("domain region unresolved")
    return parts[3]


@os_check("aws.cb.opensearch.node_to_node_encryption", "OpenSearch domain enables node-to-node encryption",
    [P + "opensearch_service_domains_node_to_node_encryption_enabled"], "high", "Enable NodeToNodeEncryptionOptions on the domain.",
    {"NodeToNodeEncryptionOptions": {"Enabled": True}}, {"NodeToNodeEncryptionOptions": {"Enabled": False}}, control="SC-8")
def os_n2n(item, index):
    value = _ds(item, "NodeToNodeEncryptionOptions.Enabled", expected=bool)
    return result(not value, enabled=value)


@os_check("aws.cb.opensearch.node_to_node_encryption_region_skip", "OpenSearch domain enables node-to-node encryption (source region exceptions)",
    [C + "opensearch_domain_node_to_node_encryption_enabled"], "high", "Enable NodeToNodeEncryptionOptions on the domain.",
    {"NodeToNodeEncryptionOptions": {"Enabled": True}}, {"NodeToNodeEncryptionOptions": {"Enabled": False}}, control="SC-8",
    extra={"not_applicable": {"DomainName": "d", "Domain": {"DomainStatus": {"ARN": "arn:aws:es:af-south-1:111111111111:domain/d"}}}},
    note="Source skips af-south-1, eu-south-1, cn-north-1 and cn-northwest-1.")
def os_n2n_skip(item, index):
    region = _region(item)
    if region in _SKIP_N2N:
        return "NOT_APPLICABLE", {"region": region}
    value = _ds(item, "NodeToNodeEncryptionOptions.Enabled", expected=bool)
    return result(not value, enabled=value)


@os_check("aws.cb.opensearch.enforce_https", "OpenSearch domain enforces HTTPS",
    [P + "opensearch_service_domains_https_communications_enforced"], "high", "Enable DomainEndpointOptions.EnforceHTTPS.",
    {"DomainEndpointOptions": {"EnforceHTTPS": True}}, {"DomainEndpointOptions": {"EnforceHTTPS": False}}, control="SC-8")
def os_https(item, index):
    value = _ds(item, "DomainEndpointOptions.EnforceHTTPS", expected=bool)
    return result(not value, enforce_https=value)


def _log_opts(item):
    options = _ds(item, "LogPublishingOptions", None, dict, strict=False)
    return options


@os_check("aws.cb.opensearch.audit_logs_enabled", "OpenSearch domain publishes audit logs",
    [P + "opensearch_service_domains_audit_logging_enabled"], "high", "Enable AUDIT_LOGS publishing (requires fine-grained access control).",
    {"LogPublishingOptions": {"AUDIT_LOGS": {"Enabled": True}}}, {"LogPublishingOptions": {}}, control="AU-2")
def os_audit(item, index):
    options = _log_opts(item) or {}
    audit = options.get("AUDIT_LOGS") or {}
    return result(audit.get("Enabled") is not True, audit_logs=audit.get("Enabled"))


@os_check("aws.cb.opensearch.slow_logs_enabled", "OpenSearch domain publishes search and index slow logs",
    [P + "opensearch_service_domains_cloudwatch_logging_enabled"], "low", "Enable SEARCH_SLOW_LOGS and INDEX_SLOW_LOGS publishing to CloudWatch Logs.",
    {"LogPublishingOptions": {"SEARCH_SLOW_LOGS": {"Enabled": True}, "INDEX_SLOW_LOGS": {"Enabled": True}}}, {"LogPublishingOptions": {"SEARCH_SLOW_LOGS": {"Enabled": True}}}, control="AU-2")
def os_slow(item, index):
    options = _log_opts(item) or {}
    search = (options.get("SEARCH_SLOW_LOGS") or {}).get("Enabled") is True
    idx = (options.get("INDEX_SLOW_LOGS") or {}).get("Enabled") is True
    return result(not (search and idx), search_slow=search, index_slow=idx)


@os_check("aws.cb.opensearch.enabled_logs_have_log_group", "OpenSearch domain enabled log types each target a CloudWatch log group",
    [C + "opensearch_domain_logs_to_cloudwatch"], "medium", "Configure LogPublishingOptions with a CloudWatch Logs log group for each enabled log type.",
    {"LogPublishingOptions": {"AUDIT_LOGS": {"Enabled": True, "CloudWatchLogsLogGroupArn": "arn:aws:logs:x"}}}, {"LogPublishingOptions": {"AUDIT_LOGS": {"Enabled": True}}}, control="AU-2",
    note="Source alarms when LogPublishingOptions is null, or when any of AUDIT_LOGS, INDEX_SLOW_LOGS, SEARCH_SLOW_LOGS, ES_APPLICATION_LOGS is enabled without CloudWatchLogsLogGroupArn.")
def os_log_groups(item, index):
    options = _log_opts(item)
    if options is None:
        return result(True, log_publishing_options=None)
    bad = [k for k in ("AUDIT_LOGS", "INDEX_SLOW_LOGS", "SEARCH_SLOW_LOGS", "ES_APPLICATION_LOGS")
           if isinstance(options.get(k), dict) and options[k].get("Enabled") is True and not options[k].get("CloudWatchLogsLogGroupArn")]
    return result(bool(bad), enabled_without_log_group=bad)


def _os_net(public_subnet):
    return inventory("route_table", [{"VpcId": "vpc-1", "Associations": [{"SubnetId": "subnet-pub"}], "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"}]}])


@os_check("aws.cb.opensearch.in_vpc_private_subnets", "OpenSearch domain is in a VPC without explicitly public subnets",
    [C + "opensearch_domain_in_vpc", X + "opensearch_domain_in_vpc"], "high", "Create the domain inside a VPC using private subnets.",
    {"VPCOptions": {"VPCId": "vpc-1", "SubnetIds": ["subnet-priv"]}}, {"VPCOptions": {"VPCId": "vpc-1", "SubnetIds": ["subnet-pub"]}},
    category="network", control="SC-7", dependencies=["opensearch_domain", "route_table"], extra={"index": _os_net(True)},
    note="Source: no VPCId alarms; a domain subnet explicitly associated with a route table with 0.0.0.0/0 -> igw- alarms (main-table associations are not considered).")
def os_vpc(item, index):
    options = _ds(item, "VPCOptions", None, dict, strict=False)
    vpc = absent_or(options, "SubnetIds", "VPCId", None, str) if options else None
    if not vpc:
        return result(True, vpc_id=None)
    subnets = strings(_ds(item, "VPCOptions.SubnetIds", expected=list))
    public = sorted(set(subnets) & explicit_igw_subnets(index))
    return result(bool(public), vpc_id=vpc, public_subnets=public)


@os_check("aws.cb.opensearch.access_policy_not_public", "OpenSearch domain outside a VPC has no public access policy",
    [P + "opensearch_service_domains_not_publicly_accessible"], "critical", "Place the domain in a VPC or restrict its access policy to specific principals or private source IPs.",
    {"AccessPolicies": '{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"es:*","Resource":"*"}]}'},
    {"AccessPolicies": '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"es:*","Resource":"*"}]}'}, category="exposure", control="AC-3",
    extra={"index": {"context": dict(CONTEXT)}}, note="Prowler: VPC domains PASS; otherwise is_policy_public(AccessPolicies, audited account) with no trusted IPs.")
def os_public(item, index):
    vpc_opts = _ds(item, "VPCOptions", None, dict, strict=False)
    if vpc_opts and vpc_opts.get("VPCId"):
        return result(False, vpc_id=vpc_opts.get("VPCId"))
    raw = _ds(item, "AccessPolicies", None, str, strict=False)
    if not raw:
        return result(False, access_policy=None)
    public = is_policy_public(policy_document(raw), account(index))
    return result(public, public=public)
