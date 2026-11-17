"""AWS upstream-gap predicates (Prowler / Steampipe aws-compliance / aws-perimeter).

The checks in this module answer the documented requirement of upstream controls whose
pinned evaluator was rejected as an invalid predicate (for example a CloudTrail selector
test that reads only the selector name, or an S3 TLS deny that ignores Action/Resource).
Each one uses only facts that the collector already gathers: DescribeTrails plus
GetTrailStatus/GetEventSelectors, bucket policy/ACL details, the IAM credential report,
DescribeHub, ListAnalyzers + ListFindingsV2 and DescribeSecurityGroups.

Missing, denied or malformed facts are UNKNOWN. The reviewed upstream rows are recorded
in ``peaso/rulepacks/reviewed_aws_gap.json``.
"""
from __future__ import annotations

import copy
import fnmatch
import re
from datetime import timedelta

from . import register, result, CHECKS
from .facts import Unavailable, get, list_of_objects, optional
from .fixtures import CASES
from .claude_aws_a_common import idx, items, strings, as_list, _denied_index, ACCOUNT, SCOPE
from .claude_aws_a_ec2 import w, partition

NATIVE_IDS = []
CT = "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/"


def install(cid, kind, title, severity, control, remediation, *, category="hardening", target="resource", dependencies=None, cases, ids=None,
            allow_incomplete_failure=False):
    """Register a gap predicate and its behaviour fixtures (``cases`` uses the shared CASES keys)."""
    if not cid.startswith("aws.gap."):
        raise ValueError("aws_gap predicate ids must use the aws.gap. prefix")
    deps = list(dependencies or [kind])

    def decorate(function):
        register(cid, "aws", category, kind, title, severity, control, remediation, target=target, dependencies=deps,
                 allow_incomplete_failure=allow_incomplete_failure)(function)
        case = {"missing": {}, "malformed": None, **cases}
        if target == "scope" and "unknown" not in case:
            case["unknown"] = {}
            case["unknown_index"] = _denied_index(case.get("pass_index", {}), deps)
        CASES[cid] = case
        (NATIVE_IDS if ids is None else ids).append(cid)
        return function
    return decorate


# =========================================================================== CloudTrail selector semantics
def selector_body(trail):
    body = get(trail, "EventSelectors", dict)
    status = optional(body, "collection_status", None, str)
    if status not in (None, "collected"):
        raise Unavailable("trail event selectors not collected")
    if status == "collected":
        # GetEventSelectors returns the ARN of the trail whose selectors were
        # read. A successful read for another trail cannot prove this trail's
        # management or data-event coverage. Unmarked legacy fixture bodies
        # retain their historical input contract; native receipts stay strict.
        expected_arn = get(trail, "TrailARN", str)
        if (re.fullmatch(r"arn:[a-z0-9-]+:cloudtrail:[a-z0-9-]+:[0-9]{12}:trail/[A-Za-z0-9_.-]+", expected_arn) is None
                or get(body, "TrailARN", str) != expected_arn):
            raise Unavailable("trail event selector identity mismatch")
    basic = list_of_objects(optional(body, "EventSelectors", [], list))
    advanced = list_of_objects(optional(body, "AdvancedEventSelectors", [], list))
    if basic and advanced:
        raise Unavailable("basic and advanced trail selectors cannot coexist")
    return basic, advanced


def logging_state(trail):
    """True/False from GetTrailStatus, None when the status read is unavailable."""
    try:
        return get(trail, "Status.IsLogging", bool)
    except Unavailable:
        return None


def field_admits(field, value):
    """CloudTrail advanced field selector operators (all present operators must hold)."""
    checks = []
    for op, test in (("Equals", lambda v, xs: v in xs), ("NotEquals", lambda v, xs: v not in xs),
                     ("StartsWith", lambda v, xs: any(v.startswith(x) for x in xs)),
                     ("NotStartsWith", lambda v, xs: all(not v.startswith(x) for x in xs)),
                     ("EndsWith", lambda v, xs: any(v.endswith(x) for x in xs)),
                     ("NotEndsWith", lambda v, xs: all(not v.endswith(x) for x in xs))):
        if op in field:
            checks.append(test(value, strings(field[op], "advanced selector " + op)))
    return all(checks)


def fields(selector):
    out = {}
    for field in list_of_objects(selector.get("FieldSelectors") or []):
        name = field.get("Field")
        if not isinstance(name, str):
            raise Unavailable("malformed advanced field selector")
        out.setdefault(name, []).append(field)
    return out


def admits(groups, name, value):
    return all(field_admits(f, value) for f in groups.get(name, []))


def management_coverage(trail):
    """(read, write, excluded_sources) for management events recorded by one trail's selectors."""
    basic, advanced = selector_body(trail)
    read = write = False
    excluded = []
    for row in basic:
        include = row.get("IncludeManagementEvents", True)
        mode = row.get("ReadWriteType", "All")
        if not isinstance(include, bool) or mode not in ("All", "ReadOnly", "WriteOnly"):
            raise Unavailable("malformed basic event selector")
        if not include:
            continue
        read |= mode in ("All", "ReadOnly")
        write |= mode in ("All", "WriteOnly")
        excluded.extend(strings(row.get("ExcludeManagementEventSources") or [], "ExcludeManagementEventSources"))
    for selector in advanced:
        groups = fields(selector)
        if not groups.get("eventCategory") or not admits(groups, "eventCategory", "Management"):
            continue
        if set(groups) - {"eventCategory", "readOnly", "eventSource"}:
            continue  # field not documented for management selectors: coverage not proven
        sources = groups.get("eventSource", [])
        if any(set(f) & {"Equals", "StartsWith", "EndsWith"} for f in sources):
            continue  # selector limited to chosen event sources
        for f in sources:
            excluded.extend(strings(f.get("NotEquals") or [], "eventSource NotEquals") + strings(f.get("NotStartsWith") or [], "eventSource NotStartsWith"))
        read |= admits(groups, "readOnly", "true")
        write |= admits(groups, "readOnly", "false")
    return read, write, sorted(set(excluded))


def _s3_value_covers(value, bucket, part):
    if value in ("arn:%s:s3" % part, "arn:%s:s3:::" % part, "arn:%s:s3:::*/*" % part):
        return True
    return bucket is not None and value == "arn:%s:s3:::%s/" % (part, bucket)


def s3_data_coverage(trail, bucket, part):
    """(read, write) S3 object data events recorded for ``bucket`` (None: every bucket)."""
    basic, advanced = selector_body(trail)
    read = write = False
    for row in basic:
        mode = row.get("ReadWriteType", "All")
        if mode not in ("All", "ReadOnly", "WriteOnly"):
            raise Unavailable("malformed basic event selector")
        for resource in list_of_objects(row.get("DataResources") or []):
            if resource.get("Type") != "AWS::S3::Object":
                continue
            if any(_s3_value_covers(v, bucket, part) for v in strings(resource.get("Values") or [], "DataResources.Values")):
                read |= mode in ("All", "ReadOnly")
                write |= mode in ("All", "WriteOnly")
    for selector in advanced:
        groups = fields(selector)
        if not groups.get("eventCategory") or not admits(groups, "eventCategory", "Data"):
            continue
        if not groups.get("resources.type") or not admits(groups, "resources.type", "AWS::S3::Object"):
            continue
        if set(groups) - {"eventCategory", "resources.type", "readOnly", "resources.ARN"}:
            continue  # eventName/eventSource/userIdentity filters record only part of the object events
        if groups.get("resources.ARN"):
            if bucket is None:
                continue  # any ARN filter (inclusion or exclusion) leaves some bucket unrecorded
            probe = "arn:%s:s3:::%s/" % (part, bucket)
            if not admits(groups, "resources.ARN", probe) or not admits(groups, "resources.ARN", probe + "any-object-key"):
                continue
        read |= admits(groups, "readOnly", "true")
        write |= admits(groups, "readOnly", "false")
    return read, write


BEDROCK_TYPES = ("AWS::Bedrock::AgentAlias", "AWS::Bedrock::FlowAlias", "AWS::Bedrock::Guardrail", "AWS::Bedrock::InlineAgent",
                 "AWS::Bedrock::KnowledgeBase", "AWS::Bedrock::Model", "AWS::Bedrock::Prompt")
BEDROCK_SOURCES = ("bedrock.amazonaws.com", "bedrock-agent.amazonaws.com", "bedrock-runtime.amazonaws.com", "bedrock-agent-runtime.amazonaws.com",
                   "bedrock-data-automation.amazonaws.com", "bedrock-data-automation-runtime.amazonaws.com")


def bedrock_coverage(trail):
    """Which Bedrock events a trail's selectors record: 'management', 'data' or None."""
    basic, advanced = selector_body(trail)
    for row in basic:
        include, mode = row.get("IncludeManagementEvents", True), row.get("ReadWriteType", "All")
        if include is True and mode in ("All", "WriteOnly"):
            return "management"
    for selector in advanced:
        groups = fields(selector)
        if groups.get("eventCategory") and admits(groups, "eventCategory", "Management"):
            if set(groups) - {"eventCategory", "readOnly", "eventSource"}:
                continue
            if admits(groups, "readOnly", "false") and any(admits(groups, "eventSource", s) for s in BEDROCK_SOURCES):
                return "management"
        if groups.get("eventCategory") and admits(groups, "eventCategory", "Data") and groups.get("resources.type"):
            # Only resource-type/category/readOnly narrowing keeps every Bedrock data event of that type.
            if set(groups) - {"eventCategory", "resources.type", "readOnly"}:
                continue
            if any(admits(groups, "resources.type", t) for t in BEDROCK_TYPES):
                return "data"
    return None


def _trail_scan(trails, accept):
    """PASS when a trail satisfies ``accept``; UNKNOWN when a candidate could not be evaluated; else FAIL."""
    unknown_reasons, evaluated = [], []
    for trail in trails:
        try:
            verdict = accept(trail)
        except Unavailable as exc:
            unknown_reasons.append(str(exc))
            continue
        if verdict is True:
            return result(False, trail=trail.get("TrailARN") or trail.get("Name"))
        evaluated.append({"trail": trail.get("TrailARN") or trail.get("Name"),
                          "matches_required_configuration": verdict})
        if verdict is None:
            unknown_reasons.append("trail logging status unavailable")
    if unknown_reasons:
        raise Unavailable("; ".join(sorted(set(unknown_reasons))))
    return result(True, trails_considered=len(trails), trail_evaluations=evaluated,
                  observed="No evaluated trail satisfies this check's logging and event-selector requirements.")


def _logging_and(trail, predicate):
    logging = logging_state(trail)
    if logging is False:
        return False
    ok = predicate(trail)
    if not ok:
        return False
    return True if logging else None


TRAIL_ARN = "arn:aws:cloudtrail:us-east-1:%s:trail/audit" % ACCOUNT
TRAIL = {"Name": "audit", "TrailARN": "arn:aws:cloudtrail:us-east-1:%s:trail/audit" % ACCOUNT, "HomeRegion": "us-east-1",
         "IsMultiRegionTrail": True, "IsOrganizationTrail": False, "IncludeGlobalServiceEvents": True, "LogFileValidationEnabled": True,
         "KmsKeyId": "arn:aws:kms:us-east-1:%s:key/k1" % ACCOUNT, "Status": {"IsLogging": True},
         "EventSelectors": {"collection_status": "collected", "TrailARN": TRAIL_ARN, "EventSelectors": [{"ReadWriteType": "All", "IncludeManagementEvents": True,
                                                                                  "DataResources": [], "ExcludeManagementEventSources": []}]}}
ADV_MGMT = {"collection_status": "collected", "TrailARN": TRAIL_ARN, "AdvancedEventSelectors": [
    {"Name": "Management events selector", "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}]}]}
ADV_DATA_NAMED = {"collection_status": "collected", "TrailARN": TRAIL_ARN, "AdvancedEventSelectors": [
    {"Name": "Management events selector", "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]},
                                                               {"Field": "resources.type", "Equals": ["AWS::S3::Object"]}]}]}


def _mgmt_complete(trail):
    return management_complete(trail)
    # per-source proof in appended helper


@install("aws.gap.cloudtrail.multi_region_read_write_management", "cloudtrail",
    "A logging multi-Region CloudTrail trail records read and write management events", "high", "AU-2",
    "Create (or fix) a multi-Region trail that is logging and records All (read and write) management events.", target="scope",
    cases={"pass": {}, "pass_index": idx(cloudtrail=[TRAIL]), "fail": {}, "fail_index": idx(cloudtrail=[w(TRAIL, IsMultiRegionTrail=False)]),
           "variants": [("PASS", {}, idx(cloudtrail=[w(TRAIL, EventSelectors=ADV_MGMT)])),
                        ("FAIL", {}, idx(cloudtrail=[w(TRAIL, EventSelectors=ADV_DATA_NAMED)])),
                        ("FAIL", {}, idx(cloudtrail=[w(TRAIL, Status__IsLogging=False)])),
                        ("FAIL", {}, idx(cloudtrail=[w(TRAIL, EventSelectors__EventSelectors=[{"ReadWriteType": "WriteOnly", "IncludeManagementEvents": True}])])),
                        ("FAIL", {}, idx(cloudtrail=[])),
                        ("UNKNOWN", {}, idx(cloudtrail=[w(TRAIL, Status={"collection_status": "denied"})]))]})
def multi_region_read_write(context, index):
    trails = items(index, "cloudtrail")
    candidates = [t for t in trails if get(t, "IsMultiRegionTrail", bool)]
    return _trail_scan(candidates, lambda t: _logging_and(t, _mgmt_complete))


@install("aws.gap.cloudtrail.region_logging_management_events", "cloudtrail",
    "Region is covered by a logging trail that records read and write management events", "high", "AU-2",
    "Ensure a logging trail (multi-Region or homed in this Region) records All management events.", target="scope",
    cases={"pass": {}, "pass_index": idx(cloudtrail=[w(TRAIL, IsMultiRegionTrail=False)]), "fail": {},
           "fail_index": idx(cloudtrail=[w(TRAIL, EventSelectors=ADV_DATA_NAMED)]),
           "variants": [("PASS", {}, idx(cloudtrail=[w(TRAIL, EventSelectors=ADV_MGMT)])),
                        ("FAIL", {}, idx(cloudtrail=[w(TRAIL, IsMultiRegionTrail=False, HomeRegion="eu-west-1")])),
                        ("FAIL", {}, idx(cloudtrail=[]))]})
def region_management(context, index):
    from .claude_aws_a_common import region
    here = region(index)
    candidates = [t for t in items(index, "cloudtrail") if get(t, "IsMultiRegionTrail", bool) or get(t, "HomeRegion", str) == here]
    return _trail_scan(candidates, lambda t: _logging_and(t, _mgmt_complete))


@install("aws.gap.cloudtrail.trail_security_best_practices", "cloudtrail",
    "Home-region trail is logging, multi-Region, global, validated, KMS-encrypted and records all management events", "high", "AU-9",
    "Enable logging, multi-Region, global service events, log file validation, KMS encryption and complete management event selectors.",
    cases={"pass": TRAIL, "fail": w(TRAIL, LogFileValidationEnabled=False),
           "not_applicable": w(TRAIL, HomeRegion="eu-west-1"), "index": idx(),
           "variants": [("FAIL", w(TRAIL, EventSelectors=ADV_DATA_NAMED), None),
                        ("FAIL", w(TRAIL, EventSelectors__EventSelectors=[{"ReadWriteType": "All", "IncludeManagementEvents": True,
                                                                           "ExcludeManagementEventSources": ["kms.amazonaws.com"]}]), None),
                        ("FAIL", w(TRAIL, KmsKeyId=""), None),
                        ("PASS", w(TRAIL, EventSelectors=ADV_MGMT), None)]})
def security_trail(item, index):
    from .claude_aws_a_common import region
    if get(item, "HomeRegion", str) != region(index):
        return "NOT_APPLICABLE", {"reason": "trail shadow copy outside its home Region"}
    failed = []
    if not get(item, "Status.IsLogging", bool):
        failed.append("not logging")
    for key, label in (("IncludeGlobalServiceEvents", "no global service events"), ("IsMultiRegionTrail", "not multi-Region"),
                       ("LogFileValidationEnabled", "log file validation disabled")):
        if not get(item, key, bool):
            failed.append(label)
    if not get(item, "KmsKeyId", str):
        failed.append("no KMS key")
    read, write, excluded = management_coverage(item)
    if not (read and write):
        failed.append("management events not fully recorded")
    if excluded:
        failed.append("management event sources excluded")
    return result(bool(failed), failures=failed, excluded_sources=excluded)


S3_ALL = {"collection_status": "collected", "TrailARN": TRAIL_ARN, "EventSelectors": [{"ReadWriteType": "All", "IncludeManagementEvents": True,
          "DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3"]}]}]}
S3_ADV_WRITE = {"collection_status": "collected", "TrailARN": TRAIL_ARN, "AdvancedEventSelectors": [{"FieldSelectors": [
    {"Field": "eventCategory", "Equals": ["Data"]}, {"Field": "resources.type", "Equals": ["AWS::S3::Object"]}, {"Field": "readOnly", "Equals": ["false"]}]}]}
S3_ADV_ALL = {"collection_status": "collected", "TrailARN": TRAIL_ARN, "AdvancedEventSelectors": [{"FieldSelectors": [
    {"Field": "eventCategory", "Equals": ["Data"]}, {"Field": "resources.type", "Equals": ["AWS::S3::Object"]}]}]}
S3_ADV_ONE_EVENT = {"collection_status": "collected", "TrailARN": TRAIL_ARN, "AdvancedEventSelectors": [{"FieldSelectors": [
    {"Field": "eventCategory", "Equals": ["Data"]}, {"Field": "resources.type", "Equals": ["AWS::S3::Object"]}, {"Field": "eventName", "Equals": ["PutObject"]}]}]}


def _region_trails(index):
    from .claude_aws_a_common import region
    here = region(index)
    return [t for t in items(index, "cloudtrail") if get(t, "IsMultiRegionTrail", bool) or get(t, "HomeRegion", str) == here]


for _mode in ("read", "write"):
    def _install_all(mode=_mode):
        cid = "aws.gap.cloudtrail.s3_all_buckets_%s_data_events" % mode
        other = S3_ADV_WRITE if mode == "read" else w(S3_ADV_WRITE, AdvancedEventSelectors=[{"FieldSelectors": [
            {"Field": "eventCategory", "Equals": ["Data"]}, {"Field": "resources.type", "Equals": ["AWS::S3::Object"]}, {"Field": "readOnly", "Equals": ["true"]}]}])

        @install(cid, "cloudtrail", "A logging trail records S3 object-level %s data events for all buckets" % mode, "medium", "AU-2",
            "Add an S3 object data event selector for all buckets (%s events) to a logging multi-Region trail." % mode, target="scope",
            cases={"pass": {}, "pass_index": idx(cloudtrail=[w(TRAIL, EventSelectors=S3_ALL)]), "fail": {},
                   "fail_index": idx(cloudtrail=[w(TRAIL, EventSelectors=other)]),
                   "variants": [("PASS", {}, idx(cloudtrail=[w(TRAIL, EventSelectors=S3_ADV_ALL)])),
                                ("FAIL", {}, idx(cloudtrail=[w(TRAIL, EventSelectors=S3_ADV_ONE_EVENT)])),
                                ("FAIL", {}, idx(cloudtrail=[w(TRAIL, EventSelectors=S3_ALL, Status__IsLogging=False)])),
                                ("FAIL", {}, idx(cloudtrail=[w(TRAIL, EventSelectors__EventSelectors=[{"ReadWriteType": "All",
                                    "DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::one-bucket/"]}]}])]))]})
        def evaluate(context, index):
            part = partition(index)
            position = 0 if mode == "read" else 1
            return _trail_scan(_region_trails(index), lambda t: _logging_and(t, lambda x: s3_data_coverage(x, None, part)[position]))
    _install_all()


def _global_index(**kinds):
    from .claude_aws_a_security import ACCT_CFG
    kinds.setdefault("aws_account_configuration", [ACCT_CFG])
    index = idx(**kinds)
    index["context"]["scope"] = index["context"]["_scope"] = ACCOUNT + "/global"
    for envelopes in index["collections"].values():
        for envelope in envelopes:
            envelope["scope"] = ACCOUNT + "/global"
    return index


BUCKET = {"Name": "b1", "Location": {"collection_status": "collected", "LocationConstraint": None}}
for _mode, _need in (("read", ("read",)), ("write", ("write",)), ("read_write", ("read", "write"))):
    def _install_bucket(mode=_mode, need=_need):
        cid = "aws.gap.s3.object_%s_events_logged" % mode
        bucket_only = {"collection_status": "collected", "TrailARN": TRAIL_ARN, "EventSelectors": [{"ReadWriteType": "All",
                       "DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::b1/"]}]}]}
        wrong = {"collection_status": "collected", "TrailARN": TRAIL_ARN, "EventSelectors": [{"ReadWriteType": "WriteOnly" if "read" in need else "ReadOnly",
                 "DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3"]}]}]}
        sibling = {"collection_status": "collected", "TrailARN": TRAIL_ARN, "EventSelectors": [{"ReadWriteType": "All",
                   "DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::b1-other/"]}]}]}

        @install(cid, "bucket", "S3 bucket object-level %s events are recorded by a logging multi-Region trail" % mode.replace("_", " and "),
            "medium", "AU-2", "Record S3 object data events (%s) for this bucket in a logging multi-Region trail." % mode.replace("_", " and "),
            dependencies=["bucket", "cloudtrail_account_inventory", "aws_account_configuration"],
            cases={"pass": BUCKET, "fail": BUCKET, "index": _global_index(cloudtrail_account_inventory=[w(TRAIL, EventSelectors=bucket_only)]),
                   "fail_index": _global_index(cloudtrail_account_inventory=[w(TRAIL, EventSelectors=wrong)]),
                   "variants": [("PASS", BUCKET, _global_index(cloudtrail_account_inventory=[w(TRAIL, EventSelectors=S3_ALL)])),
                                ("FAIL", BUCKET, _global_index(cloudtrail_account_inventory=[w(TRAIL, EventSelectors=sibling)])),
                                ("FAIL", BUCKET, _global_index(cloudtrail_account_inventory=[w(TRAIL, EventSelectors=S3_ALL, IsMultiRegionTrail=False)])),
                                ("FAIL", BUCKET, _global_index(cloudtrail_account_inventory=[w(TRAIL, EventSelectors=S3_ALL, Status__IsLogging=False)])),
                                ("UNKNOWN", BUCKET, _global_index(cloudtrail_account_inventory=[w(TRAIL, EventSelectors={"collection_status": "denied"})]))]})
        def evaluate(item, index):
            name = get(item, "Name", str)
            part = partition(index)
            trails = [t for t in items(index, "cloudtrail_account_inventory") if get(t, "IsMultiRegionTrail", bool)]

            def covers(trail):
                read, write = s3_data_coverage(trail, name, part)
                return all({"read": read, "write": write}[n] for n in need)
            return _trail_scan(trails, lambda t: _logging_and(t, covers))
    _install_bucket()


BEDROCK_DATA = {"collection_status": "collected", "TrailARN": TRAIL_ARN, "AdvancedEventSelectors": [{"FieldSelectors": [
    {"Field": "eventCategory", "Equals": ["Data"]}, {"Field": "resources.type", "Equals": ["AWS::Bedrock::Model"]}]}]}
BEDROCK_WRONG = {"collection_status": "collected", "TrailARN": TRAIL_ARN, "AdvancedEventSelectors": [{"FieldSelectors": [
    {"Field": "eventCategory", "Equals": ["Data"]}, {"Field": "resources.type", "Equals": ["AWS::Bedrock::Model"]}, {"Field": "eventName", "Equals": ["PutObject"]}]}]}


@install("aws.gap.cloudtrail.bedrock_api_logging", "cloudtrail", "A logging trail records Amazon Bedrock API calls", "medium", "AU-2",
    "Record write management events (Bedrock control plane) or Bedrock data events in a logging trail.", target="scope",
    cases={"pass": {}, "pass_index": idx(cloudtrail=[TRAIL]), "fail": {}, "fail_index": idx(cloudtrail=[w(TRAIL, EventSelectors=BEDROCK_WRONG)]),
           "variants": [("PASS", {}, idx(cloudtrail=[w(TRAIL, EventSelectors=BEDROCK_DATA)])),
                        ("FAIL", {}, idx(cloudtrail=[w(TRAIL, Status__IsLogging=False)])),
                        ("FAIL", {}, idx(cloudtrail=[w(TRAIL, EventSelectors__EventSelectors=[{"ReadWriteType": "ReadOnly", "IncludeManagementEvents": True}])]))]})
def bedrock_logging(context, index):
    return _trail_scan(_region_trails(index), lambda t: _logging_and(t, lambda x: bedrock_coverage(x) is not None))


# =========================================================================== S3 bucket policy and public write
def _values(value):
    return [v for v in as_list(value)]


def _principal_everyone(principal):
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return "*" in _values(principal.get("AWS"))
    return False


def _bool_false(value):
    values = _values(value)
    return bool(values) and all(v is False or (isinstance(v, str) and v.lower() == "false") for v in values)


def denies_insecure_transport(statement, bucket_arn, object_resource=None):
    if statement.get("Effect") != "Deny" or any(k in statement for k in ("NotAction", "NotResource", "NotPrincipal")):
        return False
    if not _principal_everyone(statement.get("Principal")):
        return False
    actions = [a.lower() for a in _values(statement.get("Action")) if isinstance(a, str)]
    if not any(a in ("*", "s3:*") for a in actions):
        return False
    resources = [r for r in _values(statement.get("Resource")) if isinstance(r, str)]
    object_prefix = bucket_arn + "/"
    def covers_objects(resource):
        # A literal key match proves nothing about the remaining object namespace.
        return (resource.endswith("*") and not any(c in resource[:-1] for c in "*?[")
                and object_prefix.startswith(resource[:-1]))
    bucket_covered = any(fnmatch.fnmatchcase(bucket_arn, r) for r in resources)
    objects_covered = any(covers_objects(r) for r in resources)
    covered = (bucket_covered and objects_covered) if object_resource is None else (objects_covered if object_resource else bucket_covered)
    if not covered:
        return False
    condition = statement.get("Condition")
    if not isinstance(condition, dict) or len(condition) != 1:
        return False
    (operator, block), = condition.items()
    if operator.lower() not in ("bool", "boolifexists") or not isinstance(block, dict) or len(block) != 1:
        return False
    (key, value), = block.items()
    return key.lower() == "aws:securetransport" and _bool_false(value)


def _s3():
    from . import claude_aws_a_s3
    return claude_aws_a_s3


S3B = {"Name": "b1", "Policy": {"collection_status": "collected", "Policy": {"Version": "2012-10-17", "Statement": [
    {"Sid": "TLS", "Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": ["arn:aws:s3:::b1", "arn:aws:s3:::b1/*"],
     "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}}}


@install("aws.gap.s3.bucket_policy_denies_insecure_transport", "bucket", "S3 bucket policy denies every request made without TLS", "medium", "SC-8",
    "Add a Deny statement for Principal *, Action s3:*, the bucket and bucket/* ARNs with Condition Bool aws:SecureTransport false.",
    cases={"pass": S3B, "fail": w(S3B, Policy__Policy__Statement=[{**S3B["Policy"]["Policy"]["Statement"][0], "Action": "s3:PutObject"}]),
           "index": idx(),
           "variants": [("FAIL", w(S3B, Policy={"collection_status": "empty", "absent": True}), None),
                        ("FAIL", w(S3B, Policy__Policy__Statement=[{**S3B["Policy"]["Policy"]["Statement"][0], "Resource": "arn:aws:s3:::b1"}]), None),
                        ("PASS", w(S3B, Policy__Policy__Statement=[{**S3B["Policy"]["Policy"]["Statement"][0], "Resource": "*", "Action": ["s3:*"],
                                                                   "Principal": {"AWS": "*"}, "Condition": {"Bool": {"aws:SecureTransport": False}}}]), None),
                        ("FAIL", w(S3B, Policy__Policy__Statement=[{**S3B["Policy"]["Policy"]["Statement"][0], "Condition": {
                            "Bool": {"aws:SecureTransport": "false"}, "StringEquals": {"aws:PrincipalAccount": ACCOUNT}}}]), None)]})
def enforces_tls(item, index):
    arn = "arn:%s:s3:::%s" % (partition(index), get(item, "Name", str))
    statements = _s3().statements(item)
    bucket_matches = [s.get("Sid") for s in statements if denies_insecure_transport(s, arn, False)]
    object_matches = [s.get("Sid") for s in statements if denies_insecure_transport(s, arn, True)]
    return result(not (bucket_matches and object_matches), bucket_statements=bucket_matches, object_statements=object_matches, statements=len(statements))


@install("aws.gap.s3.no_public_write_acl_or_policy", "bucket", "S3 bucket is not publicly writable through its ACL or its policy", "critical", "AC-3",
    "Remove public WRITE/WRITE_ACP/FULL_CONTROL ACL grants and public write policy statements, or enable Block Public Access.",
    category="exposure", dependencies=["bucket", "s3_account_public_access_block"], cases={})
def no_public_write(item, index):
    statuses = {}
    for cid in ("aws.claude_a.s3.prowler_public_write_acl", "aws.claude_a.s3.prowler_policy_public_write"):
        check = next(c for c in CHECKS if c.id == cid)
        statuses[cid] = check.evaluate(item, index)[0]
    if "FAIL" in statuses.values():
        return result(True, components=statuses)
    if any(s not in ("PASS", "NOT_APPLICABLE") for s in statuses.values()):
        raise Unavailable("public write component not proven: %s" % statuses)
    return result(False, components=statuses)


def _public_write_cases():
    s3 = _s3()
    return {"pass": s3.B, "fail": w(s3.B, PublicAccessBlock=s3.ABSENT, Acl=s3.acl_with(s3.ALL_USERS, "WRITE")), "index": s3.IDX,
            "variants": [("FAIL", w(s3.B, PublicAccessBlock=s3.ABSENT, Policy=s3.PUBLIC_WRITE_POLICY), s3.IDX)]}


# =========================================================================== IAM root usage from the credential report
def _root_recent(days, inclusive_days):
    def evaluate(item, index):
        from .claude_aws_a_iam import report_time, now, is_root
        if not is_root(item):
            return "NOT_APPLICABLE", {"reason": "credential report row is not the root user"}
        current = now(item, index)
        recent = {}
        for field in ("password_last_used", "access_key_1_last_used_date", "access_key_2_last_used_date"):
            used = report_time(item, field)
            if used is None:
                continue
            if inclusive_days:
                hit = (current - used).days <= days
            else:
                hit = current - used <= timedelta(days=days)
            if hit:
                recent[field] = used.isoformat()
        return result(bool(recent), recent_use=recent, window_days=days)
    return evaluate


def _root_cases(days):
    from .claude_aws_a_iam import ROOT
    old = "2025-01-01T00:00:00+00:00"
    recent = "2025-12-31T00:00:00+00:00"
    return {"pass": w(ROOT, password_last_used=old), "fail": w(ROOT, access_key_1_last_used_date=recent), "index": idx(),
            "not_applicable": w(ROOT, user="alice"),
            "variants": [("FAIL", w(ROOT, password_last_used=old, access_key_2_last_used_date=recent), idx()),
                         ("PASS", ROOT, idx())]}


install("aws.gap.iam.root_not_used_90_days", "iam_credential_report", "Root user password and access keys were not used in the last 90 days",
    "high", "AC-6", "Stop using the root user; use IAM roles/Identity Center and delete root access keys.", cases={})(_root_recent(90, False))
install("aws.gap.iam.root_not_used_1_day", "iam_credential_report", "Root user password and access keys were not used in the last day (Prowler threshold)",
    "high", "AC-6", "Stop using the root user; use IAM roles/Identity Center and delete root access keys.", cases={})(_root_recent(1, True))


# =========================================================================== Security Hub and IAM Access Analyzer
@install("aws.gap.securityhub.region_hub_enabled", "securityhub_hub", "Security Hub is enabled in the Region", "medium", "SI-4",
    "Enable Security Hub in every enabled Region.", target="scope",
    cases={"pass": {}, "pass_index": idx(securityhub_hub=[{"HubArn": "arn:aws:securityhub:us-east-1:%s:hub/default" % ACCOUNT}]),
           "fail": {}, "fail_index": idx(securityhub_hub=[])})
def securityhub_region(context, index):
    hubs = items(index, "securityhub_hub")
    arns = [get(h, "HubArn", str) for h in hubs]
    return result(not arns, hubs=arns)


ANALYZER = {"arn": "arn:aws:access-analyzer:us-east-1:%s:analyzer/a" % ACCOUNT, "name": "a", "type": "ACCOUNT", "status": "ACTIVE",
            "Findings": [{"id": "f0", "status": "ARCHIVED"}]}
SCOPE_CONTEXT = {"provider": "aws", "scope": SCOPE, "_scope": SCOPE, "Account": ACCOUNT}
EXPOSED_BUCKET = {"id": "f1", "status": "ACTIVE", "findingType": "ExternalAccess", "resource": "arn:aws:s3:::shared-bucket",
                  "resourceType": "AWS::S3::Bucket", "resourceOwnerAccount": ACCOUNT,
                  "FindingDetails": {"collection_status": "collected", "items": [{"externalAccessDetails": {
                      "principal": {"AWS": "999988887777"}, "action": ["s3:GetObject"], "condition": {}, "isPublic": False}}]}}
SCAN_ANALYZER = {"arn": "arn:aws:access-analyzer:us-east-1:%s:analyzer/peaso-scan-0123-external" % ACCOUNT,
                 "name": "peaso-scan-0123-external", "type": "ACCOUNT", "status": "ACTIVE", "_scan_temporary": True,
                 "_coverage": {"InitialAnalysis": {"status": "partial", "reason": "initial_analysis_completion_unconfirmed"}},
                 "Findings": [EXPOSED_BUCKET]}


def _scan_index(analyzers):
    index = idx(access_analyzer=analyzers)
    envelope = index["collections"]["access_analyzer"][0]
    envelope.update(status="partial", error={"code": "initial_analysis_completion_unconfirmed"})
    return index


@install("aws.gap.accessanalyzer.no_active_findings", "access_analyzer", "Active IAM Access Analyzer has no active findings", "medium", "AC-6",
    "Review each active Access Analyzer finding and resolve the access or archive it as intended.", category="least_privilege",
    target="scope", allow_incomplete_failure=True,
    cases={"pass": SCOPE_CONTEXT, "pass_index": idx(access_analyzer=[ANALYZER]),
           "fail": SCOPE_CONTEXT, "fail_index": idx(access_analyzer=[w(ANALYZER, Findings=[EXPOSED_BUCKET])]),
           "not_applicable": SCOPE_CONTEXT, "not_applicable_index": idx(access_analyzer=[w(ANALYZER, status="CREATING")]),
           "variants": [("UNKNOWN", SCOPE_CONTEXT, idx(access_analyzer=[w(ANALYZER, Findings=[{"id": "f1", "status": "future"}])])),
                        ("FAIL", SCOPE_CONTEXT, _scan_index([SCAN_ANALYZER])),
                        ("UNKNOWN", SCOPE_CONTEXT, _scan_index([w(SCAN_ANALYZER, Findings=[])]))],
           "unknown": SCOPE_CONTEXT, "unknown_index": _denied_index(idx(access_analyzer=[ANALYZER]), ["access_analyzer"])})
def analyzer_findings(context, index):
    """Report active findings by the resources they name, never by a scan-owned analyzer.

    Findings from a temporary scan analyzer are real provider evidence about the
    customer's resources, so they still fail the Region. A temporary analyzer
    with no findings proves nothing (its initial analysis may be unfinished).
    """
    from .aws_a_facts import scope_subject
    from .aws_access_analyzer_scope import inventory, describe, is_external_access, is_scan_temporary, bounded, FINDING_STATES
    scope = scope_subject(context)
    customer, temporary, listing_complete = inventory(index, scope)
    active_analyzers = [a for a in customer + temporary if a.get("status") == "ACTIVE"]
    exposed, other, total, unresolved = [], [], 0, False
    for analyzer in active_analyzers:
        try:
            findings = list_of_objects(get(analyzer, "Findings", list))
        except Unavailable:
            unresolved = True
            continue
        coverage = analyzer.get("_coverage", {}).get("Findings")
        if coverage is not None and (not isinstance(coverage, dict) or coverage.get("status") not in ("collected", "empty")):
            unresolved = True
        total += len(findings)
        for finding in findings:
            state = finding.get("status")
            if state not in FINDING_STATES:
                unresolved = True
            elif state == "ACTIVE":
                (exposed if is_external_access(finding) else other).append(describe(finding, analyzer))
    if exposed or other:
        shown, more = bounded(exposed)
        evidence = {"active_findings": len(exposed) + len(other), "findings": total,
                    "external_resources": sorted({row["resource"] for row in exposed if isinstance(row.get("resource"), str)}),
                    "externally_accessible_resources": shown,
                    "customer_analyzers": [a.get("arn") for a in customer]}
        if more:
            evidence["externally_accessible_resources_not_shown"] = more
        if other:
            evidence["other_active_findings"], extra = bounded(other)
            if extra:
                evidence["other_active_findings_not_shown"] = extra
        scan_types = sorted({str(a.get("type")) for a in active_analyzers if is_scan_temporary(a)})
        if scan_types:
            evidence["scan_temporary_analyzer"] = ("The account had no %s analyzer here; PEASO created a temporary one for the scan, "
                                                   "read its findings and deleted it." % "/".join(scan_types))
        return result(True, **evidence)
    if unresolved or not listing_complete:
        raise Unavailable("Access Analyzer findings not fully collected")
    if not active_analyzers:
        return "NOT_APPLICABLE", {"reason": "no ACTIVE analyzer in the Region",
                                  "statuses": [a.get("status") for a in customer]}
    for analyzer in active_analyzers:
        initial = analyzer.get("_coverage", {}).get("InitialAnalysis", {})
        if initial.get("status") not in (None, "collected", "empty"):
            raise Unavailable("Access Analyzer initial analysis is incomplete")
    return result(False, active_findings=0, findings=total, customer_analyzers=[a.get("arn") for a in customer])


# =========================================================================== Security group high-risk ports (IPv4 and IPv6)
def _sg():
    from . import claude_aws_a_network
    return claude_aws_a_network


@install("aws.gap.vpc.sg_world_any_common_ports", "security_group",
    "Security group allows no 0.0.0.0/0 or ::/0 ingress to high-risk common ports", "high", "SC-7",
    "Remove or narrow ingress from 0.0.0.0/0 and ::/0 to administrative, database and service ports.", category="exposure", cases={})
def sg_common_ports(item, index):
    net = _sg()
    get(item, "GroupId", str)
    hits = net._turbot(item, v6=True, ports=net.COMMON20)
    return result(bool(hits), matching_rules=len(hits))


def _late_cases():
    """Fixtures that need sibling modules after registration order is settled."""
    CASES["aws.gap.s3.no_public_write_acl_or_policy"].update(_public_write_cases())
    for cid, days in (("aws.gap.iam.root_not_used_90_days", 90), ("aws.gap.iam.root_not_used_1_day", 1)):
        CASES[cid].update(_root_cases(days))
    net = _sg()
    CASES["aws.gap.vpc.sg_world_any_common_ports"].update({
        "pass": net.SG, "fail": net.sg_with(net.world_rule("tcp", 8080, 8080, "::/0")),
        "variants": [("FAIL", net.sg_with(net.world_rule("tcp", 0, 65535)), None),
                     ("PASS", net.sg_with(net.world_rule("tcp", 443, 443)), None),
                     ("PASS", net.sg_with(net.world_rule("tcp", 22, 22, "10.0.0.0/8")), None)]})


_late_cases()


# =========================================================================== Classic ELB certificates and IAM key usage
CLB = {"LoadBalancerName": "classic", "ListenerDescriptions": [{"Listener": {"Protocol": "HTTPS", "LoadBalancerPort": 443, "InstanceProtocol": "HTTP",
       "InstancePort": 80, "SSLCertificateId": "arn:aws:acm:us-east-1:%s:certificate/c1" % ACCOUNT}, "PolicyNames": []}]}


@install("aws.gap.classic_elb.ssl_listeners_use_acm", "classic_load_balancer", "Classic ELB HTTPS/SSL listeners use an ACM certificate", "medium", "SC-17",
    "Import or issue the certificate in ACM and attach the ACM certificate to every HTTPS/SSL listener.",
    cases={"pass": CLB, "fail": w(CLB, ListenerDescriptions=[{"Listener": {**CLB["ListenerDescriptions"][0]["Listener"],
           "SSLCertificateId": "arn:aws:iam::%s:server-certificate/legacy" % ACCOUNT}, "PolicyNames": []}]), "index": idx(),
           "not_applicable": w(CLB, ListenerDescriptions=[{"Listener": {"Protocol": "HTTP", "LoadBalancerPort": 80, "InstanceProtocol": "HTTP", "InstancePort": 80}}])})
def clb_acm(item, index):
    get(item, "LoadBalancerName", str)
    listeners = [get(row, "Listener", dict) for row in list_of_objects(get(item, "ListenerDescriptions", list))]
    secure = [row for row in listeners if get(row, "Protocol", str).upper() in ("HTTPS", "SSL")]
    if not secure:
        return "NOT_APPLICABLE", {"reason": "no HTTPS/SSL listener"}
    prefix = "arn:%s:acm:" % partition(index)
    bad = [row.get("SSLCertificateId") for row in secure if not str(row.get("SSLCertificateId") or "").startswith(prefix)]
    return result(bool(bad), non_acm_certificates=bad)


def _key_cases():
    from .claude_aws_a_iam import ROW
    return {"pass": ROW, "fail": w(ROW, access_key_1_last_used_date="2025-10-01T00:00:00+00:00"), "index": idx(),
            "variants": [("FAIL", w(ROW, access_key_1_active="false", access_key_2_active="true", access_key_2_last_rotated="2025-01-01T00:00:00+00:00",
                                    access_key_2_last_used_date="N/A"), idx()),
                         ("PASS", w(ROW, access_key_1_last_rotated="2025-12-20T00:00:00+00:00", access_key_1_last_used_date="N/A"), idx())],
            "not_applicable": w(ROW, access_key_1_active="false")}


@install("aws.gap.iam.active_keys_used_within_45_days", "iam_credential_report", "Every active access key was used within the last 45 days", "medium", "AC-2",
    "Deactivate or delete active access keys unused for 45 days or more.", cases={})
def keys_45(item, index):
    from .claude_aws_a_iam import report_time, now
    get(item, "user", str)
    current = now(item, index)
    active, stale = 0, []
    for n in (1, 2):
        flag = get(item, "access_key_%d_active" % n, str)
        if flag not in ("true", "false"):
            raise Unavailable("credential report boolean not true/false")
        if flag != "true":
            continue
        active += 1
        used = report_time(item, "access_key_%d_last_used_date" % n)
        since = used or report_time(item, "access_key_%d_last_rotated" % n)
        if since is None:
            raise Unavailable("active key without usage or creation time")
        if current - since >= timedelta(days=45):
            stale.append(n)
    if not active:
        return "NOT_APPLICABLE", {"reason": "no active access key"}
    return result(bool(stale), stale_keys=stale)


CASES["aws.gap.iam.active_keys_used_within_45_days"].update(_key_cases())


# CloudTrail source-domain management selector proof.
SOURCES = ("ec2.amazonaws.com", "kms.amazonaws.com", "rdsdata.amazonaws.com")
EXCLUDABLE = frozenset(SOURCES[1:])


def _strings(value, label):
    if not isinstance(value, list) or not value or any(not isinstance(x, str) or not x for x in value):
        raise Unavailable("malformed " + label)
    return value


def _basic(row):
    # CloudTrail's omitted basic fields retain the existing selector defaults.
    include = row.get("IncludeManagementEvents", True)
    mode = row.get("ReadWriteType", "All")
    exclusions = row.get("ExcludeManagementEventSources", [])
    if type(include) is not bool or mode not in ("All", "ReadOnly", "WriteOnly"):
        raise Unavailable("malformed basic management selector")
    if not isinstance(exclusions, list) or any(not isinstance(x, str) or x not in EXCLUDABLE for x in exclusions):
        raise Unavailable("unsupported basic management source exclusion")
    if not include:
        return set()
    reads = ("read", "write") if mode == "All" else (("read",) if mode == "ReadOnly" else ("write",))
    return {(source, direction) for source in SOURCES if source not in exclusions for direction in reads}


def _advanced(row):
    selectors = list_of_objects(get(row, "FieldSelectors", list))
    categories = [field for field in selectors if get(field, "Field", str) == "eventCategory"]
    if len(categories) != 1:
        raise Unavailable("advanced management category unavailable")
    category = categories[0]
    if category is None or set(category) != {"Field", "Equals"}:
        raise Unavailable("advanced management category unavailable")
    values = _strings(get(category, "Equals", list), "advanced category")
    if values == ["Data"]:
        return set()
    if values != ["Management"]:
        raise Unavailable("unsupported advanced management category")
    fields = {}
    for field in selectors:
        name = get(field, "Field", str)
        if name in fields or name not in ("eventCategory", "readOnly", "eventSource"):
            raise Unavailable("unsupported or repeated advanced management field")
        fields[name] = field
    read = fields.get("readOnly")
    if read is None:
        directions = ("read", "write")
    else:
        if set(read) != {"Field", "Equals"}:
            raise Unavailable("unsupported advanced readOnly filter")
        values = _strings(get(read, "Equals", list), "advanced readOnly")
        if any(value not in ("true", "false") for value in values):
            raise Unavailable("unsupported advanced readOnly value")
        directions = tuple(direction for direction, value in (("read", "true"), ("write", "false")) if value in values)
    source_filter = fields.get("eventSource")
    exclusions = []
    if source_filter is not None:
        if set(source_filter) != {"Field", "NotEquals"}:
            raise Unavailable("unsupported advanced eventSource filter")
        exclusions = _strings(get(source_filter, "NotEquals", list), "advanced eventSource")
        if any(source not in EXCLUDABLE for source in exclusions):
            raise Unavailable("unsupported advanced eventSource exclusion")
    return {(source, direction) for source in SOURCES if source not in exclusions for direction in directions}


def management_complete(trail):
    """Prove every management source domain has both read and write coverage.

    Event selectors OR together. An unknown selector does not cancel a complete
    known sibling; absent complete known coverage, unsupported forms are UNKNOWN.
    """
    body = get(trail, "EventSelectors", dict)
    if body.get("collection_status") not in (None, "collected"):
        raise Unavailable("CloudTrail GetEventSelectors unavailable")
    if "EventSelectors" not in body and "AdvancedEventSelectors" not in body:
        raise Unavailable("CloudTrail selector lists unavailable")
    basic = list_of_objects(get(body, "EventSelectors", list)) if "EventSelectors" in body else []
    advanced = list_of_objects(get(body, "AdvancedEventSelectors", list)) if "AdvancedEventSelectors" in body else []
    if basic and advanced:
        raise Unavailable("CloudTrail basic and advanced selectors cannot coexist")
    covered, unresolved = set(), False
    for selector, parse in [(row, _basic) for row in basic] + [(row, _advanced) for row in advanced]:
        try:
            covered.update(parse(selector))
        except Unavailable:
            unresolved = True
    required = {(source, direction) for source in SOURCES for direction in ("read", "write")}
    if required <= covered:
        return True
    if unresolved:
        raise Unavailable("management selector coverage unresolved")
    return False
