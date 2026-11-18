"""Signed wave 46 AWS compliance predicates over scoped offline facts."""
from __future__ import annotations

import json
import math
import re
from dataclasses import replace
from datetime import datetime, timezone
from ipaddress import ip_address

from . import CHECKS, register, result, unknown
from .facts import MemoIndex, Unavailable, complete_items, get, memoized

SIGNED = {'aws.pci.cloudwatch.metric_alarm_settings': {'category': 'hardening',
                                              'provider': 'aws',
                                              'remediation_hint': 'Edit the CloudWatch alarm Period, '
                                                                  'Threshold, ComparisonOperator, '
                                                                  'EvaluationPeriods and AlarmActions to the '
                                                                  'approved metric specification.',
                                              'resource_kind': 'cloudwatch_alarm',
                                              'severity': 'medium',
                                              'sha': 'f952a1a0911b095bc315ddd5ba72bda3dfed636b8549a074ab0af7400fa6c7f6',
                                              'title': 'CloudWatch metric alarms use required settings'},
 'aws.pci.cloudwatch.resource_metric_alarm': {'category': 'hardening',
                                              'provider': 'aws',
                                              'remediation_hint': 'Create an enabled CloudWatch metric alarm '
                                                                  'with the required Namespace, MetricName, '
                                                                  'resource Dimension and AlarmActions.',
                                              'resource_kind': 'cloudwatch_alarm',
                                              'severity': 'medium',
                                              'sha': 'd71b53a6dfd32629038a75afdd3a3181c299ea2d312fc7b2d85501b929cceabe',
                                              'title': 'Resources have required metric alarms'},
 'aws.pci.iam.third_party_temporary_access': {'category': 'hardening',
                                              'provider': 'aws',
                                              'remediation_hint': 'Add a time-bound Condition to the '
                                                                  'third-party role trust policy and remove '
                                                                  'the partner principal when the approved '
                                                                  'window ends.',
                                              'resource_kind': 'iam_role',
                                              'severity': 'high',
                                              'sha': 'f3c0d7c47b9c88566b955a806d6075e73be58064b632f700e28146567449c540',
                                              'title': 'Third-party access is time bounded'},
 'aws_cloudwatch_alarm_missing_data_realert': {'category': 'hardening',
                                               'provider': 'aws',
                                               'remediation_hint': 'Set the CloudWatch alarm '
                                                                   'TreatMissingData and evaluation period '
                                                                   'for the approved inactivity window, with '
                                                                   'AlarmActions enabled.',
                                               'resource_kind': 'cloudwatch_alarm',
                                               'severity': 'medium',
                                               'sha': '9304cf9a57e41a2e08874c0bc192c265405c003d51bb37acca3356bc17b40c62',
                                               'title': 'Realert on inactivity in a set period'},
 'aws_ec2_ai_nitro_instance_type': {'category': 'compliance',
                                    'provider': 'aws',
                                    'remediation_hint': 'Select a Nitro-backed EC2 InstanceType for each '
                                                        'tagged AI workload instance and redeploy it.',
                                    'resource_kind': 'instance',
                                    'severity': 'medium',
                                    'sha': '45085bd6385e367d26a621a17d677fe3263f51600189a0bd26a57ceab4b382ef',
                                    'title': 'Hardware-Enforced Compute Isolation'},
 'aws_ec2_instance_time_offset_monitored': {'category': 'hardening',
                                            'provider': 'aws',
                                            'remediation_hint': 'Publish CWAgent time_offset for every '
                                                                'running instance and correct hosts over '
                                                                '1,000 ms or missing samples for 24 hours.',
                                            'resource_kind': 'instance',
                                            'severity': 'medium',
                                            'sha': '91b9bb1d8529b0482e874133f51bb2ad51316332903294a7d39d15e29bcd2660',
                                            'title': 'EC2 instance time offset is monitored'},
 'aws_g6_sns_no_named_cross_account_principals': {'category': 'exposure',
                                                  'provider': 'aws',
                                                  'remediation_hint': 'Remove external account principals or '
                                                                      'add them to a reviewed '
                                                                      'approved-account allowlist.',
                                                  'resource_kind': 'sns_topic',
                                                  'severity': 'high',
                                                  'sha': 'e7d2b3a85c5843ef15e80ff422a6fd0dd6dffa6bb66cc81f55a8e8b9f0e06955',
                                                  'title': 'SNS topic policies exclude unapproved '
                                                           'cross-account principals'},
 'aws_guardduty_doh_threat_list': {'category': 'hardening',
                                   'provider': 'aws',
                                   'remediation_hint': 'Upload the approved DNS-over-HTTPS domain or IP list '
                                                       'to GuardDuty as an active threat-intelligence set.',
                                   'resource_kind': 'guardduty_detector',
                                   'severity': 'medium',
                                   'sha': 'a0a3fd76be879a29b392946df2d3f81c0093e0ba28564f1d58460e2890010711',
                                   'title': 'Apply custom threat list for GuardDuty to alert on access to '
                                            'DoH servers'},
 'aws_guardduty_suppression_filters': {'category': 'hardening',
                                       'provider': 'aws',
                                       'remediation_hint': 'Remove overbroad GuardDuty filters or set only '
                                                           'approved finding criteria to ARCHIVE; keep other '
                                                           'findings visible.',
                                       'resource_kind': 'guardduty_detector',
                                       'severity': 'medium',
                                       'sha': 'b6111f16b728762e7cd14d422407edcf730aedcf2b6f587e1df04de1a98c70a2',
                                       'title': 'GuardDuty suppression filters configured'},
 'aws_guardduty_threat_feed': {'category': 'hardening',
                               'provider': 'aws',
                               'remediation_hint': 'Enable the GuardDuty detector and set each approved '
                                                   'custom ThreatIntelSet to ACTIVE.',
                               'resource_kind': 'guardduty_detector',
                               'severity': 'medium',
                               'sha': 'c472f0b925eba31aaf383b325fbabce80865d409a92d96bf98f766404b87f3a7',
                               'title': 'GuardDuty threat intelligence feeds are active'},
 'aws_guardduty_trusted_administrator': {'category': 'hardening',
                                         'provider': 'aws',
                                         'remediation_hint': 'Set the approved GuardDuty delegated '
                                                             'administrator account and invite or associate '
                                                             'the scoped member accounts.',
                                         'resource_kind': 'guardduty_detector',
                                         'severity': 'medium',
                                         'sha': 'c24dc9739e1a2b0a125b7b2ba3b65ff4e8fc9d7539a7d35f48eb0337b237da1e',
                                         'title': 'aws-perimeter.control.guarduty_findings_shared_with_trusted_accounts'},
 'aws_nist_ec2_instance_not_publicly_accessible': {'category': 'compliance',
                                                   'provider': 'aws',
                                                   'remediation_hint': 'Configure the resource to satisfy '
                                                                       'the stated predicate and review '
                                                                       'missing inventory or policy inputs.',
                                                   'resource_kind': 'instance',
                                                   'severity': 'medium',
                                                   'sha': '74cbf6b2b5fa1d4184ca17247291df3db48b9d8057eb8f5ad8b8ea2d0dba001c',
                                                   'title': 'EC2 instances should not have a public IP '
                                                            'address'},
 'aws_nist_sns_topic_notification_delivery_status_enabled': {'category': 'compliance',
                                                             'provider': 'aws',
                                                             'remediation_hint': 'Configure the resource to '
                                                                                 'satisfy the stated '
                                                                                 'predicate and review '
                                                                                 'missing inventory or '
                                                                                 'policy inputs.',
                                                             'resource_kind': 'sns_topic',
                                                             'severity': 'medium',
                                                             'sha': 'e1200e96c2f5008f705d0f765504c0cb873b2790481833d4486fe371645e416a',
                                                             'title': 'Logging of delivery status should be '
                                                                      'enabled for notification messages '
                                                                      'sent to a topic'},
 'aws_partner_role_external_id_present': {'category': 'hardening',
                                          'provider': 'aws',
                                          'remediation_hint': 'Add Condition.StringEquals.sts:ExternalId '
                                                              'with a nonempty customer-specific value to '
                                                              'the partner role trust policy.',
                                          'resource_kind': 'iam_role',
                                          'severity': 'medium',
                                          'sha': 'c06abc575685056e972417a5326782a2ff3af8eddd4d990c6e8e31b62e61ca51',
                                          'title': 'Partner role ExternalId condition present'},
 'aws_shield_ddos_detected_alarm': {'category': 'hardening',
                                    'provider': 'aws',
                                    'remediation_hint': 'Create an AWS/DDoSProtection DDoSDetected alarm '
                                                        'with ResourceArn dimension, Threshold <= 1 and '
                                                        'enabled AlarmActions.',
                                    'resource_kind': 'cloudwatch_alarm',
                                    'severity': 'medium',
                                    'sha': 'a7dd3527729f04f3d022a58f3b89f8eb67578399be80f6c2fc58a8255fb52c17',
                                    'title': 'Alert based on DDoSDetected metric'}}

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_ARN_ACCOUNT = re.compile(r"arn:aws(?:-[a-z0-9-]+)?:iam::([0-9]{12}):(root|user/.+|role/.+)\Z")
_IDS = {"instance": "InstanceId", "cloudwatch_alarm": "AlarmArn", "guardduty_detector": "DetectorId",
        "sns_topic": "TopicArn", "iam_role": "Arn"}


def _context(index):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "aws":
        raise Unavailable("AWS provider authority unavailable")
    scope = get(context, "scope", str)
    match = re.fullmatch(r"([0-9]{12})/(global|[a-z]{2}(?:-[a-z]+)+-[0-9])", scope)
    if not match:
        raise Unavailable("AWS account/Region scope unavailable")
    return scope, match.group(1), match.group(2)


def _items(index, kind):
    if type(index) is MemoIndex:
        return list(memoized(index, ("sw46._items", kind), lambda: _validated_items(index, kind)))
    return _validated_items(index, kind)


def _validated_items(index, kind):
    scope, _, _ = _context(index)
    envelopes = get(index, "collections", dict).get(kind)
    if (not isinstance(envelopes, list) or len(envelopes) != 1 or
            not isinstance(envelopes[0], dict) or envelopes[0].get("type") != kind or
            envelopes[0].get("scope") != scope):
        raise Unavailable("collection scope authority unavailable: " + kind)
    rows = complete_items(index, kind)
    if envelopes[0].get("items") != rows:
        raise Unavailable("collection envelope disagrees with resource inventory: " + kind)
    wrappers = get(index, kind, list)
    if len(wrappers) != len(rows) or any(
        not isinstance(w, dict) or w.get("type") != kind or w.get("scope") != scope or
        w.get("data") != row for w, row in zip(wrappers, rows)
    ):
        raise Unavailable("malformed or foreign-scope resource wrappers: " + kind)
    return rows


def _resource_lookup(rows, key):
    by_id, duplicate = {}, False
    for row in rows:
        value = get(row, key, str)
        if not value:
            raise Unavailable("empty inventory identity")
        if value in by_id:
            duplicate = True
        else:
            by_id[value] = row
    return by_id, duplicate


def _resource(item, index, kind):
    if type(index) is MemoIndex:
        rows = _items(index, kind)
        key = _IDS[kind]
        identity = get(item, key, str)
        if not identity:
            raise Unavailable("missing resource identity")
        by_id, duplicate = memoized(index, ("sw46._resource", kind, key),
            lambda: _resource_lookup(rows, key))
        if duplicate or identity not in by_id or by_id[identity] != item:
            raise Unavailable("ambiguous or foreign resource identity")
        return identity
    rows = _items(index, kind)
    key = _IDS[kind]
    identity = get(item, key, str)
    if not identity:
        raise Unavailable("missing resource identity")
    seen = []
    for row in rows:
        value = get(row, key, str)
        if not value:
            raise Unavailable("empty inventory identity")
        seen.append(value)
    if len(seen) != len(set(seen)) or seen.count(identity) != 1 or rows[seen.index(identity)] != item:
        raise Unavailable("ambiguous or foreign resource identity")
    return identity


def _policy(index, cid):
    scope, _, _ = _context(index)
    metadata = get(get(index, "context", dict), "metadata", dict) if "metadata" in index["context"] else {}
    policy = metadata.get("approved_policy", index.get("approved_policy"))
    if not isinstance(policy, dict):
        raise Unavailable("approved check policy unavailable")
    if get(policy, "scope", str) != scope:
        raise Unavailable("approved policy has foreign or missing scope")
    checks = get(policy, "checks", dict)
    if cid not in checks or not isinstance(checks[cid], dict):
        raise Unavailable("approved check policy unavailable: " + cid)
    return checks[cid]


def _strings(value, *, allow_empty=True):
    if not isinstance(value, list) or any(not isinstance(x, str) or not x for x in value):
        raise Unavailable("malformed string inventory")
    if len(value) != len(set(value)) or (not allow_empty and not value):
        raise Unavailable("empty or duplicate string inventory")
    return value


def _number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise Unavailable("malformed numeric fact")
    return value


def _api_optional(item, key, default):
    if not isinstance(item, dict):
        raise Unavailable("malformed API object")
    coverage = item.get("_coverage", {})
    if not isinstance(coverage, dict):
        raise Unavailable("malformed API field coverage")
    mark = coverage.get(key)
    if mark is not None and (not isinstance(mark, dict) or mark.get("status") not in ("collected", "empty")):
        raise Unavailable("API field unavailable: " + key)
    if key in item:
        return get(item, key)
    if mark is not None and mark.get("status") == "collected":
        raise Unavailable("collected API field absent: " + key)
    return default


def _timestamp(value):
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise Unavailable("malformed timestamp") from exc
    else:
        raise Unavailable("malformed timestamp")
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise Unavailable("timestamp has no timezone")
    return dt.astimezone(timezone.utc)


def _document(value):
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError as exc:
            raise Unavailable("malformed policy document") from exc
    if not isinstance(value, dict) or value.get("Version") not in ("2008-10-17", "2012-10-17"):
        raise Unavailable("unrecognized or malformed policy document")
    statements = get(value, "Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or any(not isinstance(s, dict) for s in statements):
        raise Unavailable("malformed policy statements")
    return statements


def _aws_principals(statement):
    principal = get(statement, "Principal")
    if not isinstance(principal, dict):
        raise Unavailable("dynamic or wildcard principal cannot be resolved")
    aws = get(principal, "AWS")
    values = [aws] if isinstance(aws, str) else aws
    return _strings(values, allow_empty=False)


def _actions(statement):
    value = get(statement, "Action")
    return _strings([value] if isinstance(value, str) else value, allow_empty=False)


def _condition(statement):
    condition = _api_optional(statement, "Condition", {})
    if not isinstance(condition, dict):
        raise Unavailable("malformed policy condition")
    return condition


def _alarm_rows(index):
    rows = _items(index, "cloudwatch_alarm")
    _, account, region = _context(index)
    seen = set()
    for row in rows:
        arn = _alarm_identity(row, account, region)
        if arn in seen or not arn:
            raise Unavailable("duplicate or empty alarm ARN")
        seen.add(arn)
    return rows


def _alarm_identity(row, account, region):
    arn = get(row, "AlarmArn", str)
    match = re.fullmatch(r"arn:aws(?:-[a-z0-9-]+)?:cloudwatch:([a-z0-9-]+):([0-9]{12}):alarm:.+", arn)
    if not match or match.groups() != (region, account):
        raise Unavailable("foreign-scope CloudWatch alarm")
    return arn


def _metric(row):
    return get(row, "Namespace", str), get(row, "MetricName", str), get(row, "Dimensions", list)


def _dimensions(value):
    if not isinstance(value, list):
        raise Unavailable("malformed metric dimensions")
    result = {}
    for d in value:
        name, val = get(d, "Name", str), get(d, "Value", str)
        if not name or not val or name in result:
            raise Unavailable("empty or duplicate metric dimension")
        result[name] = val
    return result


def _actions_enabled(row):
    actions = _strings(get(row, "AlarmActions", list))
    return get(row, "ActionsEnabled", bool) and bool(actions)


def _ec2_nitro(item, index, cid):
    _resource(item, index, "instance")
    policy = _policy(index, cid)
    tag_key = get(policy, "workload_tag_key", str)
    tag_values = _strings(get(policy, "ai_workload_values", list), allow_empty=False)
    if not tag_key:
        raise Unavailable("empty workload tag key")
    tags = get(item, "Tags", list)
    mapped = {}
    for tag in tags:
        k, v = get(tag, "Key", str), get(tag, "Value", str)
        if not k or k in mapped:
            raise Unavailable("malformed or duplicate EC2 tag")
        mapped[k] = v
    if mapped.get(tag_key) not in tag_values:
        return "NOT_APPLICABLE", {"reason": "instance is not tagged as an in-scope AI workload"}
    typ = get(item, "InstanceType", str)
    types = _items(index, "ec2_instance_type")
    all_types = [get(row, "InstanceType", str) for row in types]
    if any(not value for value in all_types) or len(all_types) != len(set(all_types)):
        raise Unavailable("malformed or duplicate instance-type inventory")
    matches = [row for row in types if get(row, "InstanceType", str) == typ]
    if len(matches) != 1:
        raise Unavailable("instance type detail absent or ambiguous")
    hypervisor = get(matches[0], "Hypervisor", str)
    if hypervisor not in ("nitro", "xen"):
        return unknown("unrecognized instance-type hypervisor")
    return result(hypervisor != "nitro", instance_type=typ, hypervisor=hypervisor)


def _ec2_time(item, index, cid):
    iid = _resource(item, index, "instance")
    state = get(item, "State.Name", str)
    if state not in {"pending", "running", "shutting-down", "terminated", "stopping", "stopped"}:
        return unknown("unrecognized EC2 instance state")
    if state != "running":
        return "NOT_APPLICABLE", {"reason": "instance is not running"}
    sample = get(item, "TimeOffset", dict)
    if (sample.get("collection_status") == "empty" and sample.get("error", {}).get("code") == "no_exact_clock_metric_datapoints"
            and sample.get("InstanceId") == iid and sample.get("Namespace") == "CWAgent" and sample.get("MetricName") == "time_offset"
            and sample.get("_provenance", {}).get("source_operation") == "cloudwatch:GetMetricStatistics"):
        proof = get(sample, "_provenance", dict)
        if (proof.get("dimensions") != [{"Name": "InstanceId", "Value": iid}]
                or proof.get("unit") != "Milliseconds" or proof.get("period_seconds") != 300):
            raise Unavailable("empty time-offset query identity unavailable")
        start, end = _timestamp(get(sample, "WindowStart")), _timestamp(get(sample, "WindowEnd"))
        now = _timestamp(get(index, "context.created_at"))
        if not 86400 <= (end - start).total_seconds() < 86460 or end > now or (now - end).total_seconds() > 60:
            raise Unavailable("empty time-offset query does not cover the captured day")
        return result(True, instance_id=iid, monitored=False, reason="No CWAgent time_offset datapoints were published in the collected day", window_start=start.isoformat(), window_end=end.isoformat())
    if get(sample, "collection_status", str) != "collected" or get(sample, "InstanceId", str) != iid or get(sample, "Namespace", str) != "CWAgent" or get(sample, "MetricName", str) != "time_offset":
        raise Unavailable("time-offset telemetry incomplete or mismatched")
    ts = _timestamp(get(sample, "Timestamp"))
    now = _timestamp(get(get(index, "context", dict), "created_at"))
    if ts > now:
        return unknown("time-offset sample is after snapshot capture")
    offset = _number(get(sample, "ValueMilliseconds"))
    age = (now - ts).total_seconds()
    return result(abs(offset) > 1000 or age > 86400, offset_milliseconds=offset, sample_age_seconds=age)


def _ec2_public(item, index, cid):
    iid = _resource(item, index, "instance")
    exposure = get(item, "PublicReachability", dict)
    if get(exposure, "collection_status", str) != "collected" or get(exposure, "InstanceId", str) != iid:
        raise Unavailable("complete public-reachability projection unavailable")
    paths = get(exposure, "Paths", list)
    if get(exposure, "route_inventory_complete", bool) is not True or get(exposure, "ingress_inventory_complete", bool) is not True or get(exposure, "target_inventory_complete", bool) is not True or get(exposure, "listener_inventory_complete", bool) is not True:
        raise Unavailable("network path inventory incomplete")
    unsafe = []
    for path in paths:
        source = get(path, "Source", str)
        if source not in ("public_ipv4", "public_ipv6", "internet_facing_elbv2"):
            raise Unavailable("unrecognized network path source")
        address = get(path, "AddressOrTargetArn", str)
        if not address:
            raise Unavailable("empty public path target")
        if source != "internet_facing_elbv2":
            try:
                if not ip_address(address).is_global:
                    raise Unavailable("nonpublic address in public-path projection")
            except ValueError as exc:
                raise Unavailable("malformed public address") from exc
        route = get(path, "RouteToInternet", bool)
        ingress = get(path, "IngressAllowed", bool)
        listening = get(path, "ListeningPortVerified", bool)
        if route and ingress and listening:
            unsafe.append(address)
    return result(bool(unsafe), instance_id=iid, reachable_public_paths=unsafe)

def _scope_item(item, index):
    scope, account, region = _context(index)
    if get(item, "scope", str) != scope:
        raise Unavailable("foreign scope subject")
    return account, region


def _alarm_settings(item, index, cid):
    account, region = _scope_item(item, index)
    spec = _policy(index, cid)
    namespace, metric = get(spec, "Namespace", str), get(spec, "MetricName", str)
    dims = _dimensions(get(spec, "Dimensions", list))
    period = get(spec, "Period", int)
    threshold = _number(get(spec, "Threshold"))
    comparison = get(spec, "ComparisonOperator", str)
    periods = get(spec, "EvaluationPeriods", int)
    actions = set(_strings(get(spec, "AlarmActions", list), allow_empty=False))
    if not namespace or not metric or period <= 0 or periods <= 0 or not comparison:
        raise Unavailable("malformed approved alarm settings")
    matches, bad = [], []
    for row in _alarm_rows(index):
        arn = _alarm_identity(row, account, region)
        ns, name, actual_dims = _metric(row)
        if name != metric or ns != namespace or _dimensions(actual_dims) != dims:
            continue
        matches.append(arn)
        row_period = get(row, "Period", int)
        row_threshold = _number(get(row, "Threshold"))
        row_comparison = get(row, "ComparisonOperator", str)
        row_periods = get(row, "EvaluationPeriods", int)
        row_actions = set(_strings(get(row, "AlarmActions", list)))
        if (row_period != period or row_threshold != threshold or row_comparison != comparison or
                row_periods != periods or row_actions != actions):
            bad.append(arn)
    if not matches:
        return unknown("no alarm matches the approved metric identity")
    return result(bool(bad), matched_alarm_arns=matches, mismatched_alarm_arns=bad)


def _resource_alarm(item, index, cid):
    account, region = _scope_item(item, index)
    spec = _policy(index, cid)
    kind = get(spec, "resource_kind", str)
    dimension = get(spec, "dimension_name", str)
    namespace, metric = get(spec, "Namespace", str), get(spec, "MetricName", str)
    resources = _strings(get(spec, "resource_dimension_values", list))
    if not kind or not dimension or not namespace or not metric:
        raise Unavailable("malformed approved resource alarm scope")
    alarms = []
    for row in _alarm_rows(index):
        arn = _alarm_identity(row, account, region)
        ns, name, dims = _metric(row)
        if ns == namespace and name == metric:
            alarms.append((arn, _dimensions(dims), _actions_enabled(row)))
    missing = [value for value in resources if not any(
        dims.get(dimension) == value and enabled for _, dims, enabled in alarms)]
    if not resources:
        return "NOT_APPLICABLE", {"reason": "approved resource inventory is empty", "resource_kind": kind}
    return result(bool(missing), resource_kind=kind, missing_resource_dimensions=missing)


def _inactivity_alarm(item, index, cid):
    account, region = _scope_item(item, index)
    specs = get(_policy(index, cid), "metrics", list)
    if not specs:
        return "NOT_APPLICABLE", {"reason": "no approved inactivity metrics in this scope"}
    alarms = _alarm_rows(index)
    missing = []
    for spec in specs:
        namespace, metric = get(spec, "Namespace", str), get(spec, "MetricName", str)
        dims = _dimensions(get(spec, "Dimensions", list))
        interval = get(spec, "approved_interval_seconds", int)
        if not namespace or not metric or interval <= 0:
            raise Unavailable("malformed inactivity metric specification")
        compliant = False
        for row in alarms:
            _alarm_identity(row, account, region)
            ns, name, actual_dims = _metric(row)
            if ns != namespace or name != metric or _dimensions(actual_dims) != dims:
                continue
            period, periods = get(row, "Period", int), get(row, "EvaluationPeriods", int)
            if period <= 0 or periods <= 0:
                raise Unavailable("malformed alarm evaluation window")
            if (get(row, "TreatMissingData", str) == "breaching" and period * periods <= interval
                    and _actions_enabled(row)):
                compliant = True
        if not compliant:
            missing.append({"Namespace": namespace, "MetricName": metric, "Dimensions": dims})
    return result(bool(missing), unprotected_inactivity_metrics=missing)


def _shield_alarm(item, index, cid):
    account, region = _scope_item(item, index)
    protections = _items(index, "shield_protection_region")
    resources = []
    for p in protections:
        arn = get(p, "ResourceArn", str)
        if not arn or arn in resources or get(p, "SourceRegion", str) != region:
            raise Unavailable("malformed Shield regional protection projection")
        parts = arn.split(":", 5)
        if (len(parts) != 6 or parts[0] != "arn" or not parts[1].startswith("aws") or
                not parts[2] or not parts[5] or (parts[3] and parts[3] != region) or
                (parts[4] and parts[4] != account)):
            raise Unavailable("Shield protection resource ARN has foreign scope")
        resources.append(arn)
    alarms = _alarm_rows(index)
    missing = []
    for resource in resources:
        found = False
        for row in alarms:
            _alarm_identity(row, account, region)
            ns, name, dims = _metric(row)
            if ns != "AWS/DDoSProtection" or name != "DDoSDetected":
                continue
            if _dimensions(dims) != {"ResourceArn": resource}:
                continue
            threshold = _number(get(row, "Threshold"))
            comparison = get(row, "ComparisonOperator", str)
            if comparison not in {"GreaterThanThreshold", "GreaterThanOrEqualToThreshold",
                                  "LessThanThreshold", "LessThanOrEqualToThreshold"}:
                return unknown("unsupported DDoSDetected alarm comparison operator")
            # DDoSDetected is binary: alert on 1, remain non-breaching on 0.
            detects_attack = ((comparison == "GreaterThanThreshold" and 0 <= threshold < 1)
                              or (comparison == "GreaterThanOrEqualToThreshold" and 0 < threshold <= 1))
            if detects_attack and _actions_enabled(row):
                found = True
        if not found:
            missing.append(resource)
    if not resources:
        return "NOT_APPLICABLE", {"reason": "no Shield protections assigned to this Region"}
    return result(bool(missing), protection_resources_without_alarm=missing)


def _detector(item, index):
    return _resource(item, index, "guardduty_detector")


def _detail_listing(item, field, identity):
    listing = get(item, field, dict)
    if get(listing, "collection_status", str) not in ("collected", "empty") or get(listing, "DetectorId", str) != identity:
        raise Unavailable("detector detail listing incomplete or mismatched: " + field)
    rows = get(listing, "items", list)
    if any(not isinstance(row, dict) for row in rows):
        raise Unavailable("malformed detector detail listing: " + field)
    return rows


def _guardduty_doh(item, index, cid):
    did = _detector(item, index)
    approved = _strings(get(_policy(index, cid), "approved_doh_locations", list), allow_empty=False)
    feeds = _detail_listing(item, "ThreatIntelSets", did)
    matching, seen = [], set()
    for feed in feeds:
        fid = get(feed, "Id", str)
        status = get(feed, "Status", str)
        location = get(feed, "Location", str)
        fmt = get(feed, "Format", str)
        if not fid or fid in seen or not location or status not in {"ACTIVE", "INACTIVE", "ACTIVATING", "DEACTIVATING", "ERROR", "DELETE_PENDING"} or not fmt:
            raise Unavailable("malformed GuardDuty threat set")
        seen.add(fid)
        if location in approved and status == "ACTIVE":
            matching.append(fid)
    return result(not matching, detector_id=did, active_approved_doh_set_ids=matching)


def _guardduty_filters(item, index, cid):
    did = _detector(item, index)
    approved = get(_policy(index, cid), "approved_low_value_criteria", list)
    if not isinstance(approved, list) or any(not isinstance(x, dict) for x in approved):
        raise Unavailable("malformed approved filter criteria")
    if not approved:
        return "NOT_APPLICABLE", {"reason": "no required suppression criteria"}
    filters = _detail_listing(item, "Filters", did)
    seen, unapproved = set(), []
    for row in filters:
        name, action = get(row, "Name", str), get(row, "Action", str)
        criteria = get(row, "FindingCriteria", dict)
        if not name or name in seen or action not in {"ARCHIVE", "NOOP"}:
            raise Unavailable("malformed GuardDuty filter")
        seen.add(name)
        if action == "ARCHIVE" and criteria not in approved:
            unapproved.append(name)
    missing = [criteria for criteria in approved if not any(
        get(row, "Action", str) == "ARCHIVE" and get(row, "FindingCriteria", dict) == criteria
        for row in filters)]
    return result(bool(missing or unapproved), detector_id=did,
                  missing_approved_criteria=missing, unapproved_archive_filters=unapproved)


def _guardduty_feed(item, index, cid):
    did = _detector(item, index)
    approved = _strings(get(_policy(index, cid), "approved_threat_set_ids", list), allow_empty=False)
    status = get(item, "Configuration.Status", str)
    if status not in {"ENABLED", "DISABLED"}:
        raise Unavailable("unrecognized detector status")
    feeds = _detail_listing(item, "ThreatIntelSets", did)
    by_id = {}
    for feed in feeds:
        fid, feed_status = get(feed, "Id", str), get(feed, "Status", str)
        if not fid or fid in by_id or feed_status not in {"ACTIVE", "INACTIVE", "ACTIVATING", "DEACTIVATING", "ERROR", "DELETE_PENDING"}:
            raise Unavailable("malformed or duplicate threat set")
        by_id[fid] = feed_status
    bad = [fid for fid in approved if by_id.get(fid) != "ACTIVE"]
    return result(status != "ENABLED" or bool(bad), detector_id=did, inactive_or_missing_approved_feed_ids=bad)


def _guardduty_admin(item, index, cid):
    did = _detector(item, index)
    trusted = _strings(get(_policy(index, cid), "trusted_account_ids", list))
    if any(not _ACCOUNT.fullmatch(x) for x in trusted):
        raise Unavailable("malformed trusted account ID")
    admin = get(item, "Administrator", dict)
    if get(admin, "collection_status", str) != "collected" or get(admin, "DetectorId", str) != did:
        raise Unavailable("administrator relationship detail unavailable")
    administrators = get(admin, "AdminAccounts", list)
    invitations = _detail_listing(item, "Invitations", did)
    observed = []
    for row in administrators:
        aid = get(row, "AdminAccountId", str)
        if not _ACCOUNT.fullmatch(aid):
            raise Unavailable("malformed administrator account ID")
        observed.append(aid)
    for row in invitations:
        aid = get(row, "AccountId", str)
        state = get(row, "RelationshipStatus", str)
        if not _ACCOUNT.fullmatch(aid) or state not in {"Accepted", "Invited", "Declined", "Removed", "EmailVerificationInProgress", "EmailVerificationFailed"}:
            raise Unavailable("malformed invitation relationship")
        if state in {"Accepted", "Invited"}:
            observed.append(aid)
    return result(any(aid not in trusted for aid in observed), detector_id=did,
                  untrusted_accounts=sorted(set(observed) - set(trusted)))

def _sns_policy(item, index, cid):
    arn = _resource(item, index, "sns_topic")
    _, owner, region = _context(index)
    if not re.fullmatch(r"arn:aws(?:-[a-z0-9-]+)?:sns:" + region + r":" + owner + r":[^:]+", arn):
        raise Unavailable("SNS topic ARN does not belong to scoped owner")
    approved = _strings(get(_policy(index, cid), "approved_account_ids", list))
    if any(not _ACCOUNT.fullmatch(x) for x in approved):
        raise Unavailable("malformed approved account scope")
    attrs = get(item, "Attributes", dict)
    if get(attrs, "collection_status", str) != "collected":
        raise Unavailable("topic attributes unavailable")
    document = get(get(attrs, "Attributes", dict), "Policy")
    bad = []
    for statement in _document(document):
        effect = get(statement, "Effect", str)
        if effect not in ("Allow", "Deny"):
            raise Unavailable("unrecognized SNS policy effect")
        if effect == "Deny":
            continue
        if "NotAction" in statement or "NotPrincipal" in statement:
            return unknown("SNS policy has dynamic action or principal")
        actions = _actions(statement)
        if any(action == "*" or action.lower().startswith("sns:") for action in actions):
            if "NotResource" in statement:
                return unknown("SNS policy uses unresolved NotResource scope")
            resources = _api_optional(statement, "Resource", None)
            resources = [resources] if isinstance(resources, str) else resources
            if resources is None:
                return unknown("SNS policy statement resource scope unavailable")
            resources = _strings(resources, allow_empty=False)
            if any(value not in (arn, "*") for value in resources):
                return unknown("SNS policy statement has unresolved resource scope")
            if _condition(statement):
                return unknown("SNS policy condition prevents literal grant resolution")
            for principal in _aws_principals(statement):
                if _ACCOUNT.fullmatch(principal):
                    account = principal
                else:
                    match = _ARN_ACCOUNT.fullmatch(principal)
                    if not match:
                        return unknown("SNS policy principal is not a literal AWS account or IAM ARN")
                    account = match.group(1)
                if account != owner and account not in approved:
                    bad.append(account)
    return result(bool(bad), topic_arn=arn, unapproved_account_ids=sorted(set(bad)))


_FEEDBACK_PREFIX = {"http": "HTTP", "https": "HTTP", "sqs": "SQS", "lambda": "Lambda",
                    "application": "Application", "firehose": "Firehose"}


def _sns_delivery(item, index, cid):
    arn = _resource(item, index, "sns_topic")
    _, owner, region = _context(index)
    if not re.fullmatch(r"arn:aws(?:-[a-z0-9-]+)?:sns:" + region + r":" + owner + r":[^:]+", arn):
        raise Unavailable("SNS topic ARN does not belong to scoped owner and Region")
    subscriptions = _items(index, "sns_subscription")
    protocols = set()
    seen = set()
    for sub in subscriptions:
        sid = get(sub, "id", str)
        if not sid or sid in seen:
            raise Unavailable("duplicate or malformed SNS subscription identity")
        seen.add(sid)
        if get(sub, "TopicArn", str) == arn:
            protocols.add(get(sub, "Protocol", str).lower())
    attrs = get(item, "Attributes", dict)
    if get(attrs, "collection_status", str) != "collected":
        raise Unavailable("topic attributes unavailable")
    values = get(attrs, "Attributes", dict)
    if get(values, "TopicArn", str) != arn:
        raise Unavailable("topic attributes ARN mismatch")
    if not protocols:
        return "NOT_APPLICABLE", {"reason": "no subscriptions in complete scoped protocol inventory"}
    unsupported = protocols & {"email", "email-json", "sms"}
    protocols = protocols - unsupported
    if not protocols:
        return "NOT_APPLICABLE", {"reason": "SNS delivery-status feedback logging does not support these subscription protocols", "protocols": sorted(unsupported)}
    missing = []
    for protocol in sorted(protocols):
        prefix = _FEEDBACK_PREFIX.get(protocol)
        if prefix is None:
            return unknown("delivery protocol has no reviewed feedback-field mapping", protocol=protocol)
        fail_role = _api_optional(values, prefix + "FailureFeedbackRoleArn", "")
        success_role = _api_optional(values, prefix + "SuccessFeedbackRoleArn", "")
        rate = _api_optional(values, prefix + "SuccessFeedbackSampleRate", "0")
        for field in (fail_role, success_role):
            if not isinstance(field, str):
                raise Unavailable("malformed SNS feedback role")
            if field and not re.fullmatch(r"arn:aws(?:-[a-z0-9-]+)?:iam::[0-9]{12}:role/.+", field):
                raise Unavailable("malformed SNS feedback role ARN")
        try:
            sample_rate = float(rate)
        except (ValueError, TypeError):
            raise Unavailable("malformed SNS success feedback sample rate")
        if not math.isfinite(sample_rate) or not 0 <= sample_rate <= 100:
            raise Unavailable("SNS success feedback sample rate outside range")
        if not fail_role or not success_role or sample_rate <= 0:
            missing.append(protocol)
    return result(bool(missing), topic_arn=arn, protocols_without_complete_feedback=missing)


def _role_statements(item, index):
    arn = _resource(item, index, "iam_role")
    _, owner, region = _context(index)
    if region != "global" or not re.fullmatch(r"arn:aws(?:-[a-z0-9-]+)?:iam::" + owner + r":role/.+", arn):
        raise Unavailable("IAM role is outside account-global scope")
    return arn, _document(get(item, "AssumeRolePolicyDocument"))


def _trust_allow(statements, principals):
    matches = []
    for statement in statements:
        effect = get(statement, "Effect", str)
        if effect not in {"Allow", "Deny"}:
            raise Unavailable("unrecognized trust effect")
        if effect != "Allow":
            continue
        if "NotPrincipal" in statement or "NotAction" in statement:
            raise Unavailable("dynamic trust principal or action")
        actions = _actions(statement)
        if not any(action.lower() in {"sts:assumerole", "sts:*", "*"} for action in actions):
            continue
        if any(principal in principals for principal in _aws_principals(statement)):
            matches.append(statement)
    return matches


def _partner_external(item, index, cid):
    arn, statements = _role_statements(item, index)
    spec = _policy(index, cid)
    role_arns = _strings(get(spec, "customer_role_arns", list))
    providers = _strings(get(spec, "provider_principal_arns", list), allow_empty=False)
    if arn not in role_arns:
        return "NOT_APPLICABLE", {"reason": "role outside inventoried customer-assumable roles"}
    matched = _trust_allow(statements, providers)
    if not matched:
        return "NOT_APPLICABLE", {"reason": "no provider AssumeRole trust statement"}
    missing = []
    for pos, statement in enumerate(matched):
        condition = _condition(statement)
        external = _api_optional(condition, "StringEquals", {})
        if not isinstance(external, dict):
            raise Unavailable("malformed ExternalId condition")
        value = _api_optional(external, "sts:ExternalId", None)
        if not isinstance(value, str) or not value.strip():
            missing.append(pos)
    return result(bool(missing), role_arn=arn, statements_without_external_id=missing)


def _temporary_access(item, index, cid):
    arn, statements = _role_statements(item, index)
    spec = _policy(index, cid)
    principals = _strings(get(spec, "third_party_principal_arns", list), allow_empty=False)
    approved_end = _timestamp(get(spec, "approved_window_end"))
    now = _timestamp(get(get(index, "context", dict), "created_at"))
    matched = _trust_allow(statements, principals)
    if not matched:
        if now > approved_end:
            return result(False, role_arn=arn, reason="third-party principal absent after approved window")
        return "NOT_APPLICABLE", {"reason": "no third-party trust statement before window end"}
    unbounded = []
    for pos, statement in enumerate(matched):
        condition = _condition(statement)
        limits = _api_optional(condition, "DateLessThan", {})
        if not isinstance(limits, dict):
            raise Unavailable("malformed time-bound trust condition")
        end = _api_optional(limits, "aws:CurrentTime", None)
        if end is None:
            unbounded.append(pos)
        elif _timestamp(end) > approved_end:
            unbounded.append(pos)
    return result(bool(unbounded), role_arn=arn, statements_exceeding_window=unbounded)


_EVALUATORS = {
    "aws_ec2_ai_nitro_instance_type": _ec2_nitro,
    "aws_ec2_instance_time_offset_monitored": _ec2_time,
    "aws_nist_ec2_instance_not_publicly_accessible": _ec2_public,
    "aws.pci.cloudwatch.metric_alarm_settings": _alarm_settings,
    "aws.pci.cloudwatch.resource_metric_alarm": _resource_alarm,
    "aws_cloudwatch_alarm_missing_data_realert": _inactivity_alarm,
    "aws_shield_ddos_detected_alarm": _shield_alarm,
    "aws_guardduty_doh_threat_list": _guardduty_doh,
    "aws_guardduty_suppression_filters": _guardduty_filters,
    "aws_guardduty_threat_feed": _guardduty_feed,
    "aws_guardduty_trusted_administrator": _guardduty_admin,
    "aws_g6_sns_no_named_cross_account_principals": _sns_policy,
    "aws_nist_sns_topic_notification_delivery_status_enabled": _sns_delivery,
    "aws.pci.iam.third_party_temporary_access": _temporary_access,
    "aws_partner_role_external_id_present": _partner_external,
}
_DEPENDENCIES = {
    "aws_ec2_ai_nitro_instance_type": ["instance", "ec2_instance_type"],
    "aws_ec2_instance_time_offset_monitored": ["instance"],
    "aws_nist_ec2_instance_not_publicly_accessible": ["instance"],
    "aws.pci.cloudwatch.metric_alarm_settings": ["cloudwatch_alarm"],
    "aws.pci.cloudwatch.resource_metric_alarm": ["cloudwatch_alarm"],
    "aws_cloudwatch_alarm_missing_data_realert": ["cloudwatch_alarm"],
    "aws_shield_ddos_detected_alarm": ["cloudwatch_alarm", "shield_protection_region"],
    "aws_guardduty_doh_threat_list": ["guardduty_detector"],
    "aws_guardduty_suppression_filters": ["guardduty_detector"],
    "aws_guardduty_threat_feed": ["guardduty_detector"],
    "aws_guardduty_trusted_administrator": ["guardduty_detector"],
    "aws_g6_sns_no_named_cross_account_principals": ["sns_topic"],
    "aws_nist_sns_topic_notification_delivery_status_enabled": ["sns_topic", "sns_subscription"],
    "aws.pci.iam.third_party_temporary_access": ["iam_role"],
    "aws_partner_role_external_id_present": ["iam_role"],
}
_SCOPE_CHECKS = {"aws.pci.cloudwatch.metric_alarm_settings", "aws.pci.cloudwatch.resource_metric_alarm",
                 "aws_cloudwatch_alarm_missing_data_realert", "aws_shield_ddos_detected_alarm"}
for _cid, _meta in SIGNED.items():
    def _make(cid, meta):
        # The legacy registry has no compliance category; preserve the signed
        # category on the immutable Check after its defensive wrapper is built.
        @register(cid, meta["provider"], meta["category"] if meta["category"] != "compliance" else "hardening",
                  meta["resource_kind"], meta["title"], meta["severity"], "CM-6",
                  meta["remediation_hint"], target="scope" if cid in _SCOPE_CHECKS else "resource",
                  dependencies=_DEPENDENCIES[cid])
        def evaluate(item, index):
            return _EVALUATORS[cid](item, index, cid)
        if meta["category"] == "compliance":
            CHECKS[-1] = replace(CHECKS[-1], category="compliance")
        return evaluate
    _make(_cid, _meta)
