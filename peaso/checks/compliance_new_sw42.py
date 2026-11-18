"""Signed AWS compliance checks over complete, scoped, read-only facts.

Operator thresholds and allowlists are scope-bound in context.metadata.compliance_policy.
Absent policy or collector coverage produces UNKNOWN.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import re

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects, optional


# id: resource kind, severity, signed category, signed title, spec_digest(entry)
SPECS = {
    "aws_vpc_uses_amazonprovided_dns": ("vpc", "medium", "hardening", "Use strictly AWS VPC DNS resolver", "dd1d059fb8c63e624677fafe73cf26196709333ec1c7fc1499bc3b8da72f5a75"),
    "aws_cis_lightsail_bucket_iam_policy": ("lightsail_bucket", "medium", "least_privilege", "Lightsail bucket access uses scoped IAM policies", "59a5bceb0acc12f0fb26fdb525125f4086ccb64d43e59c7d838822d683ff9717"),
    "aws_cis_lightsail_bucket_private": ("lightsail_bucket", "high", "exposure", "Lightsail buckets are private", "3973047c4beedaa9f01cf690e683c4bcb19607452a4f45471bb8d791cf39d63e"),
    "aws.pci.backup.plan_frequency_retention": ("backup_plan", "medium", "hardening", "Backup plans meet required frequency and retention", "deb0b6e966e137b7a6f47426bc3f55f5187f20863fea534e57ce3f29188590c1"),
    "aws_backup_plan_rule_required_frequency": ("backup_plan", "medium", "compliance", "AWS Backup plan rules meet the required backup frequency", "e9855247d6dd1a45cd7767adba376d0b48e8b4efeffbe1cbf49f9bc7926ac756"),
    "aws_nist_backup_plan_min_retention_35_days": ("backup_plan", "medium", "compliance", "Backup plan min frequency and min retention check", "6915599455cb7b972a05a9478c53876eaadd963a1fc0187a6e7f766b54d1c15a"),
    "aws_cis_elbv2_only_tls_listeners": ("load_balancer", "medium", "hardening", "ALB and NLB listeners require TLS", "198efb32c483e91f881ee3c06bba4748ef80aa08d3ff5cd091b7136b4022b0bb"),
    "aws_elbv2_stickiness_duration_30_minutes": ("load_balancer", "medium", "compliance", "When stickiness is enabled, session cookies MUST expire within 30 minutes of inactivity.", "9adeaba6fae755db635909ae6003d83660e6b01eb8727af89780df44c28c706f"),
    "aws_nist_elb_application_gateway_network_lb_multiple_az_configured": ("load_balancer", "medium", "compliance", "ELB application, network, and gateway load balancers should span multiple availability zones", "7979537013efaac7d1ec7b1e5cdc43ac458caf92a8c79304e6e976d06da0ae89"),
    "aws_cloudtrail_administration_command": ("aws_cloudtrail_activity", "medium", "identity", "Cloud Administration Command", "b8d8ac2116199403d574c147fca3771dd7d2cdc645ead30819b1ed20cc013895"),
    "aws_cloudtrail_event_triggered_execution": ("aws_cloudtrail_activity", "medium", "identity", "Event Triggered Execution", "7d104a7b51e7421b4cc90bc0fca76ccd9cd04ade8f9ef76a7fd9286965aa1053"),
    "aws_cloudtrail_permission_group_discovery": ("aws_cloudtrail_activity", "medium", "identity", "Permission Groups Discovery", "496742d3c1e696eabb9738d92246448707ada190c63306eacb97346b92c3b9a9"),
    "aws_securityhub_aggregated_findings_present": ("securityhub_hub", "medium", "hardening", "Security Hub aggregated findings are present", "b2d20a9aa0be50be2ba613734a238808b2b6cc92a53d29d38a3d015580f8a110"),
    "aws_securityhub_standards_control_baseline": ("securityhub_hub", "medium", "hardening", "Security Hub standards and controls match baseline", "4b95af4ace2fc3952fb4b8b758ad121bcc41cbd23348a5fc52eb36d6ba3b3a65"),
    "aws_backup_recent_restore_test": ("backup_restore_job", "high", "hardening", "Backup resource types have recent successful restore tests", "93375bd84a6cfc54f50850a8068e738282b380710fdd48f494cfaa2a583f8ab2"),
}
PROPOSED_SPEC_SHA256 = {cid: row[4] for cid, row in SPECS.items()}


def _signed(cid, dependencies, *, target="resource"):
    kind, severity, category, title, _ = SPECS[cid]

    def decorate(fn):
        register(cid, "aws", category if category in {"hardening", "exposure", "least_privilege", "iam_graph", "network"} else "hardening",
                 kind, title, severity, "CM-6", "Review the complete resource facts and approved scope policy.",
                 target=target, dependencies=dependencies)(fn)
        # The legacy registry validates a narrower category enum than the signed catalog.
        position = next(i for i, check in enumerate(CHECKS) if check.id == cid)
        CHECKS[position] = replace(CHECKS[position], category=category)
        return fn
    return decorate


def _scope(index):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "aws":
        raise Unavailable("AWS provider authority unavailable")
    scope = get(context, "scope", str)
    if not re.fullmatch(r"[0-9]{12}/[a-z]{2}(?:-[a-z]+)+-[0-9]", scope):
        raise Unavailable("AWS account/Region scope unavailable")
    return scope


def _rows(index, kind):
    scope = _scope(index)
    envelopes = get(index, "collections", dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable("single complete collection unavailable: " + kind)
    envelope = get({"envelope": envelopes[0]}, "envelope", dict)
    if (get(envelope, "type", str) != kind or get(envelope, "scope", str) != scope or
            get(envelope, "status", str) not in ("collected", "empty") or
            envelope.get("coverage_status", "collected") not in ("collected", "empty")):
        raise Unavailable("foreign or incomplete collection: " + kind)
    rows = complete_items(index, kind)
    declared = list_of_objects(get(envelope, "items", list))
    wrappers = list_of_objects(get(index, kind, list))
    if (len(rows) != len(declared) or len(rows) != len(wrappers) or
            (envelope["status"] == "empty") != (not rows)):
        raise Unavailable("collection cardinality unavailable: " + kind)
    encode = lambda value: json.dumps(value, sort_keys=True, default=str)
    if Counter(map(encode, rows)) != Counter(map(encode, declared)):
        raise Unavailable("collection projection differs from snapshot: " + kind)
    for wrapper in wrappers:
        if (get(wrapper, "type", str) != kind or get(wrapper, "scope", str) != scope or
                wrapper.get("provider", "aws") != "aws"):
            raise Unavailable("foreign resource wrapper: " + kind)
    if Counter(map(encode, rows)) != Counter(encode(get(w, "data", dict)) for w in wrappers):
        raise Unavailable("resource wrappers differ from collection: " + kind)
    return rows, envelope, scope


def _item(item, index, kind, identity):
    rows, _, scope = _rows(index, kind)
    keys = [get(row, identity, str) for row in rows]
    key = get(item, identity, str)
    if not key or any(not k for k in keys) or len(set(keys)) != len(keys) or keys.count(key) != 1 or rows[keys.index(key)] != item:
        raise Unavailable("resource absent or duplicated in complete inventory")
    return scope


def _arn_scope(arn, scope, service):
    match = re.fullmatch(r"arn:(aws|aws-cn|aws-us-gov):([^:]+):([^:]*):([0-9]{12}):(.+)", arn)
    if not match or match.group(2) != service or match.group(3) != scope.split("/", 1)[1] or match.group(4) != scope.split("/", 1)[0]:
        raise Unavailable("resource ARN does not match audited scope")


def _policy(index, scope):
    policy = get(get(get(index, "context", dict), "metadata", dict), "compliance_policy", dict)
    if get(policy, "status", str) != "collected" or get(policy, "scope", str) != scope:
        raise Unavailable("approved scope-bound compliance policy unavailable")
    return policy


def _positive_number(value, name):
    if type(value) not in (int, float) or not (0 < value < float("inf")):
        raise Unavailable("missing or invalid " + name)
    return float(value)


def _strings(value, *, nonempty=False):
    if not isinstance(value, list) or (nonempty and not value) or any(not isinstance(x, str) or not x for x in value) or len(value) != len(set(value)):
        raise Unavailable("malformed complete string list")
    return set(value)


def _timestamp(value):
    if not isinstance(value, str):
        raise Unavailable("timestamp unavailable")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Unavailable("malformed timestamp") from exc
    if parsed.tzinfo is None:
        raise Unavailable("timestamp timezone unavailable")
    return parsed.astimezone(timezone.utc)


def _child(parent, field):
    child = get(parent, field, dict)
    if get(child, "collection_status", str) not in ("collected", "empty"):
        raise Unavailable("incomplete child collection: " + field)
    rows = list_of_objects(get(child, "items", list))
    if (child["collection_status"] == "empty") != (not rows):
        raise Unavailable("malformed child collection: " + field)
    return rows


def _plan(item, index):
    scope = _item(item, index, "backup_plan", "BackupPlanArn")
    arn = get(item, "BackupPlanArn", str)
    _arn_scope(arn, scope, "backup")
    if ":plan:" not in arn:
        raise Unavailable("backup resource is not a plan")
    detail = get(item, "Plan", dict)
    if get(detail, "collection_status", str) != "collected":
        raise Unavailable("GetBackupPlan detail incomplete")
    rules = list_of_objects(get(detail, "BackupPlan.Rules", list))
    if not rules:
        raise Unavailable("backup plan has no evaluable rules")
    return rules, scope


def _schedule_hours(expression):
    """Resolve only schedules whose maximum UTC gap is provable from syntax."""
    if not isinstance(expression, str):
        raise Unavailable("backup schedule unavailable")
    rate = re.fullmatch(r"rate\(([1-9][0-9]*) (hour|hours|day|days|week|weeks)\)", expression)
    if rate:
        count = int(rate.group(1))
        unit = rate.group(2)
        if (count == 1 and unit.endswith("s")) or (count != 1 and not unit.endswith("s")):
            raise Unavailable("malformed rate unit")
        return count * (1 if unit.startswith("hour") else 24 if unit.startswith("day") else 168)
    cron = re.fullmatch(r"cron\(([^()]+)\)", expression)
    if not cron:
        raise Unavailable("unsupported backup schedule")
    parts = cron.group(1).split()
    if (len(parts) != 6 or parts[3] != "*" or parts[5] != "*" or
            (parts[2], parts[4]) not in (("*", "?"), ("?", "*"))):
        raise Unavailable("cron recurrence cannot be bounded")
    minute = parts[0]
    if not minute.isdigit() or not 0 <= int(minute) < 60:
        raise Unavailable("cron minute cannot be bounded")
    hour = parts[1]
    if hour == "*":
        hours = list(range(24))
    elif re.fullmatch(r"(?:\*/|0/)([1-9][0-9]*)", hour):
        step = int(hour.split("/")[1])
        if 24 % step:
            raise Unavailable("cron hour step does not divide day")
        hours = list(range(0, 24, step))
    elif re.fullmatch(r"(?:[0-9]|1[0-9]|2[0-3])(?:,(?:[0-9]|1[0-9]|2[0-3]))*", hour):
        hours = sorted({int(x) for x in hour.split(",")})
    else:
        raise Unavailable("cron hour cannot be bounded")
    if not hours:
        raise Unavailable("cron has no hours")
    gaps = [b - a for a, b in zip(hours, hours[1:])] + [24 + hours[0] - hours[-1]]
    return max(gaps)


def _rule_schedule_hours(rule):
    timezone_name = rule.get("ScheduleExpressionTimezone", "UTC")
    if not isinstance(timezone_name, str) or timezone_name not in ("UTC", "Etc/UTC"):
        raise Unavailable("backup schedule timezone has variable UTC intervals")
    if "ScheduleExpressionTimezone" in rule.get("_coverage", {}):
        get(rule, "ScheduleExpressionTimezone", str)
    return _schedule_hours(get(rule, "ScheduleExpression", str))


def _rule_enabled(rule):
    # AWS Backup GetBackupPlan rules have no Enabled property; a present rule is active.
    return get(rule, "Enabled", bool) if "Enabled" in rule or "Enabled" in rule.get("_coverage", {}) else True


def _rule_retention(rule, *, indefinite_ok=False):
    if "Lifecycle" not in rule and "Lifecycle" not in rule.get("_coverage", {}):
        return None if indefinite_ok else get(rule, "Lifecycle", dict)
    lifecycle = get(rule, "Lifecycle", dict)
    if "DeleteAfterDays" not in lifecycle and "DeleteAfterDays" not in lifecycle.get("_coverage", {}):
        return None if indefinite_ok else get(lifecycle, "DeleteAfterDays", int)
    days = get(lifecycle, "DeleteAfterDays", int)
    if days < 0:
        raise Unavailable("invalid backup retention")
    return days


@_signed("aws_vpc_uses_amazonprovided_dns", ["vpc", "dhcp_options"])
def vpc_uses_amazon_dns(item, index):
    scope = _item(item, index, "vpc", "VpcId")
    vpc_id = get(item, "VpcId", str)
    if not re.fullmatch(r"vpc-[0-9a-f]+", vpc_id):
        raise Unavailable("malformed VPC identity")
    options_id = get(item, "DhcpOptionsId", str)
    options, _, _ = _rows(index, "dhcp_options")
    ids = [get(row, "DhcpOptionsId", str) for row in options]
    if len(set(ids)) != len(ids) or ids.count(options_id) != 1:
        raise Unavailable("associated DHCP options absent or duplicated")
    configurations = list_of_objects(get(options[ids.index(options_id)], "DhcpConfigurations", list))
    dns = [row for row in configurations if get(row, "Key", str) == "domain-name-servers"]
    if len(dns) != 1:
        raise Unavailable("DNS DHCP configuration absent or duplicated")
    values = _strings([get(row, "Value", str) for row in list_of_objects(get(dns[0], "Values", list))], nonempty=True)
    return result(values != {"AmazonProvidedDNS"}, vpc_id=vpc_id, dhcp_options_id=options_id,
                  dns_servers=sorted(values), scope=scope)


@_signed("aws_cis_lightsail_bucket_iam_policy", ["lightsail_bucket", "lightsail_iam_policy_attachment"])
def lightsail_bucket_iam_policy(item, index):
    scope = _item(item, index, "lightsail_bucket", "arn")
    arn = get(item, "arn", str)
    _arn_scope(arn, scope, "lightsail")
    policy = _policy(index, scope)
    required = _strings(get(policy, "iam_required_lightsail_bucket_arns", list))
    approved_principals = _strings(get(policy, "approved_lightsail_principals", list), nonempty=True)
    approved_actions = _strings(get(policy, "approved_lightsail_actions", list), nonempty=True)
    approved_actions = {action.casefold() for action in approved_actions}
    if arn not in required:
        return "NOT_APPLICABLE", {"bucket_arn": arn, "reason": "IAM-managed bucket access not required by approved policy"}
    attachments, _, _ = _rows(index, "lightsail_iam_policy_attachment")
    suitable = False
    broad = []
    for attachment in attachments:
        principal = get(attachment, "PrincipalArn", str)
        document = get(attachment, "PolicyDocument", dict)
        statements = get(document, "Statement")
        if isinstance(statements, dict):
            statements = [statements]
        statements = list_of_objects(statements)
        for statement in statements:
            if get(statement, "Effect", str) != "Allow":
                continue
            actions = statement.get("Action")
            resources = statement.get("Resource")
            actions = [actions] if isinstance(actions, str) else actions
            resources = [resources] if isinstance(resources, str) else resources
            action_set = _strings(actions, nonempty=True)
            resource_set = _strings(resources, nonempty=True)
            if "*" in resource_set or any("*" in resource for resource in resource_set):
                raise Unavailable("wildcard IAM resource effect cannot be bounded")
            if arn not in resource_set:
                continue
            if any("*" in action or "?" in action for action in action_set):
                raise Unavailable("wildcard IAM action effect cannot be bounded")
            if principal in approved_principals and {action.casefold() for action in action_set} <= approved_actions and resource_set == {arn}:
                suitable = True
            else:
                broad.append(principal)
    if broad:
        return result(True, bucket_arn=arn, broad_principals=sorted(set(broad)))
    return result(not suitable, bucket_arn=arn, scoped_policy_present=suitable)


@_signed("aws_cis_lightsail_bucket_private", ["lightsail_bucket"])
def lightsail_bucket_private(item, index):
    scope = _item(item, index, "lightsail_bucket", "arn")
    arn = get(item, "arn", str)
    _arn_scope(arn, scope, "lightsail")
    access = get(item, "accessRules", dict)
    get_object = get(access, "getObject", str)
    overrides = get(access, "allowPublicOverrides", bool)
    if get_object not in ("public", "private"):
        raise Unavailable("unrecognized Lightsail bucket access rule")
    # Lightsail GetBuckets.AccessRules defines public as anonymous access to
    # every object, regardless of allowPublicOverrides. S3 account BPA is not
    # a native Lightsail bucket fact and cannot authenticate this decision.
    if get_object == "public":
        return result(True, bucket_arn=arn, public_get_object=True)
    if not overrides:
        return result(False, bucket_arn=arn, public_get_object=False, public_overrides=False)
    return unknown("private defaults allow public object ACL overrides; complete native object exposure is unproven", bucket_arn=arn)


def _required_frequency(index, scope):
    return _positive_number(get(_policy(index, scope), "required_frequency_hours"), "required_frequency_hours")


@_signed("aws.pci.backup.plan_frequency_retention", ["backup_plan"])
def backup_frequency_retention(item, index):
    rules, scope = _plan(item, index)
    policy = _policy(index, scope)
    frequency = _positive_number(get(policy, "required_frequency_hours"), "required_frequency_hours")
    retention = _positive_number(get(policy, "required_retention_days"), "required_retention_days")
    failures = []
    enabled = 0
    for number, rule in enumerate(rules, 1):
        if not _rule_enabled(rule):
            continue
        enabled += 1
        gap = _rule_schedule_hours(rule)
        days = _rule_retention(rule)
        if gap > frequency or days < retention:
            failures.append(number)
    if not enabled:
        return "NOT_APPLICABLE", {"reason": "no enabled backup rules"}
    return result(bool(failures), failing_rule_numbers=failures,
                  required_frequency_hours=frequency, required_retention_days=retention)


@_signed("aws_backup_plan_rule_required_frequency", ["backup_plan"])
def backup_rule_frequency(item, index):
    rules, scope = _plan(item, index)
    frequency = _required_frequency(index, scope)
    failures = []
    for number, rule in enumerate(rules, 1):
        gap = _rule_schedule_hours(rule)
        continuous = rule.get("EnableContinuousBackup", False)
        if type(continuous) is not bool:
            raise Unavailable("malformed continuous backup flag")
        if gap > frequency:
            if continuous:
                covered_gap = _positive_number(get(rule, "ContinuousRecoveryPointMaxGapHours"), "continuous recovery-point gap")
                if covered_gap <= frequency:
                    continue
            failures.append(number)
    return result(bool(failures), failing_rule_numbers=failures, required_frequency_hours=frequency)


@_signed("aws_nist_backup_plan_min_retention_35_days", ["backup_plan"])
def backup_nist_frequency_retention(item, index):
    rules, scope = _plan(item, index)
    frequency = _required_frequency(index, scope)
    qualified = []
    uncertain = False
    for number, rule in enumerate(rules, 1):
        if not _rule_enabled(rule):
            continue
        try:
            gap = _rule_schedule_hours(rule)
            days = _rule_retention(rule, indefinite_ok=True)
        except Unavailable:
            uncertain = True
            continue
        if gap <= frequency and (days is None or days >= 35):
            qualified.append(number)
    if qualified:
        return result(False, qualifying_rule_numbers=qualified, required_frequency_hours=frequency)
    if uncertain:
        return unknown("one or more rule schedules or retention values unresolved")
    return result(True, qualifying_rule_numbers=[], required_frequency_hours=frequency)


def _lb(item, index):
    scope = _item(item, index, "load_balancer", "LoadBalancerArn")
    arn = get(item, "LoadBalancerArn", str)
    _arn_scope(arn, scope, "elasticloadbalancing")
    lb_type = get(item, "Type", str)
    if lb_type not in ("application", "network", "gateway"):
        raise Unavailable("unrecognized ELBv2 load balancer type")
    prefix = {"application": "app", "network": "net", "gateway": "gwy"}[lb_type]
    if not arn.split(":", 5)[-1].startswith("loadbalancer/" + prefix + "/"):
        raise Unavailable("load balancer ARN and type disagree")
    return arn, lb_type, scope


@_signed("aws_cis_elbv2_only_tls_listeners", ["load_balancer"])
def elbv2_tls_listeners(item, index):
    arn, lb_type, scope = _lb(item, index)
    if lb_type == "gateway":
        return "NOT_APPLICABLE", {"load_balancer_arn": arn, "reason": "gateway load balancer has no HTTP or TCP listeners"}
    listeners = _child(item, "Listeners")
    approved_redirects = _strings(get(_policy(index, scope), "approved_https_redirect_listener_arns", list))
    plaintext = []
    for listener in listeners:
        listener_arn = get(listener, "ListenerArn", str)
        protocol = get(listener, "Protocol", str)
        if (lb_type, protocol) in (("application", "HTTPS"), ("network", "TLS")):
            continue
        if protocol == "TCP" and lb_type == "network":
            plaintext.append(listener_arn)
        elif protocol == "HTTP" and lb_type == "application":
            actions = list_of_objects(get(listener, "DefaultActions", list))
            action_types = [get(action, "Type", str) for action in actions]
            if any(action_type not in ("authenticate-cognito", "authenticate-oidc", "forward", "redirect", "fixed-response") for action_type in action_types):
                raise Unavailable("unrecognized ALB default action")
            if (not action_types or action_types[-1] != "redirect" or
                    any(action_type not in ("authenticate-cognito", "authenticate-oidc") for action_type in action_types[:-1])):
                plaintext.append(listener_arn)
                continue
            redirect = get(actions[-1], "RedirectConfig", dict)
            if (get(redirect, "Protocol", str) == "HTTPS" and
                    get(redirect, "Port", str) == "443" and
                    get(redirect, "StatusCode", str) in ("HTTP_301", "HTTP_302") and
                    listener_arn in approved_redirects):
                continue
            if listener_arn not in approved_redirects:
                raise Unavailable("HTTP redirect has no explicit approval")
            plaintext.append(listener_arn)
        else:
            raise Unavailable("unrecognized or mismatched listener protocol")
    return result(bool(plaintext), load_balancer_arn=arn, plaintext_listener_arns=plaintext)


def _target_groups(index, arn):
    groups, _, scope = _rows(index, "target_group")
    selected = []
    ids = set()
    for group in groups:
        group_arn = get(group, "TargetGroupArn", str)
        _arn_scope(group_arn, scope, "elasticloadbalancing")
        if not group_arn.split(":", 5)[-1].startswith("targetgroup/"):
            raise Unavailable("malformed target group ARN")
        if group_arn in ids:
            raise Unavailable("duplicate target group ARN")
        ids.add(group_arn)
        lb_arns = _strings(get(group, "LoadBalancerArns", list))
        for associated_arn in lb_arns:
            _arn_scope(associated_arn, scope, "elasticloadbalancing")
        if arn in lb_arns:
            selected.append(group)
    return selected


@_signed("aws_elbv2_stickiness_duration_30_minutes", ["load_balancer", "target_group"])
def elbv2_stickiness(item, index):
    arn, lb_type, _ = _lb(item, index)
    if lb_type != "application":
        return "NOT_APPLICABLE", {"load_balancer_arn": arn, "reason": "only ALB cookie stickiness is in scope"}
    groups = _target_groups(index, arn)
    excessive = []
    for group in groups:
        attrs = get(group, "Attributes", dict)
        if get(attrs, "collection_status", str) != "collected":
            raise Unavailable("target group attributes incomplete")
        values = {}
        for attribute in list_of_objects(get(attrs, "Attributes", list)):
            key = get(attribute, "Key", str)
            if key in values:
                raise Unavailable("duplicate target group attribute")
            values[key] = get(attribute, "Value", str)
        if values.get("stickiness.enabled") not in ("true", "false"):
            raise Unavailable("target group stickiness flag unavailable")
        if values["stickiness.enabled"] == "true":
            if values.get("stickiness.type") != "lb_cookie":
                raise Unavailable("enabled stickiness mode has no checked cookie duration")
            duration = values.get("stickiness.lb_cookie.duration_seconds")
            if not isinstance(duration, str) or not duration.isdigit() or int(duration) <= 0:
                raise Unavailable("target group cookie duration unavailable")
            if int(duration) > 1800:
                excessive.append(get(group, "TargetGroupArn", str))
    for listener in _child(item, "Listeners"):
        for rule in _child(listener, "Rules"):
            for action in list_of_objects(get(rule, "Actions", list)):
                if get(action, "Type", str) != "forward":
                    continue
                forward = optional(action, "ForwardConfig", {}, dict)
                stickiness = optional(forward, "TargetGroupStickinessConfig", {}, dict)
                enabled = optional(stickiness, "Enabled", False, bool)
                if enabled:
                    duration = get(stickiness, "DurationSeconds", int)
                    if duration <= 0:
                        raise Unavailable("invalid forward-action cookie duration")
                    if duration > 1800:
                        excessive.append(get(rule, "RuleArn", str))
    return result(bool(excessive), load_balancer_arn=arn, excessive_stickiness_sources=sorted(set(excessive)))


@_signed("aws_nist_elb_application_gateway_network_lb_multiple_az_configured", ["load_balancer", "target_group"])
def elbv2_healthy_targets_multi_az(item, index):
    arn, lb_type, scope = _lb(item, index)
    declared = {get(row, "ZoneName", str) for row in list_of_objects(get(item, "AvailabilityZones", list))}
    if not declared or any(not re.fullmatch(re.escape(scope.split("/")[1]) + r"[a-z]", zone) for zone in declared):
        raise Unavailable("load balancer availability-zone inventory malformed")
    zones = set()
    for group in _target_groups(index, arn):
        target_type = get(group, "TargetType", str)
        if target_type not in ("instance", "ip", "lambda", "alb"):
            raise Unavailable("unrecognized target group target type")
        health = get(group, "TargetHealth", dict)
        if get(health, "collection_status", str) != "collected":
            raise Unavailable("target health inventory incomplete")
        for row in list_of_objects(get(health, "TargetHealthDescriptions", list)):
            get(row, "Target.Id", str)
            state = get(row, "TargetHealth.State", str)
            if state not in ("initial", "healthy", "unhealthy", "unused", "draining", "unavailable"):
                raise Unavailable("unrecognized target health state")
            if target_type in ("instance", "ip") and state == "healthy":
                zone = get(row, "Target.AvailabilityZone", str)
                if zone not in declared:
                    raise Unavailable("healthy target zone not in load balancer zone mapping")
                zones.add(zone)
    return result(len(zones) < 2, load_balancer_arn=arn, healthy_target_zones=sorted(zones), lb_type=lb_type)


_ACTIVITY = {
    "aws_cloudtrail_administration_command": ({"SendCommand", "StartAutomationExecution", "StartSession"}, "ssm.amazonaws.com", "approved_remote_administration_principals"),
    "aws_cloudtrail_event_triggered_execution": ({"PutRule", "PutTargets"}, "events.amazonaws.com", "approved_event_automation_principals"),
    "aws_cloudtrail_permission_group_discovery": ({"ListGroups", "GetGroup", "ListAttachedGroupPolicies"}, "iam.amazonaws.com", "approved_iam_inventory_principals"),
}


def _activity(item, index, cid):
    names, source, policy_field = _ACTIVITY[cid]
    rows, envelope, scope = _rows(index, "aws_cloudtrail_activity")
    if get(item, "scope", str) != scope:
        raise Unavailable("activity scope subject differs from collection")
    if cid == "aws_cloudtrail_permission_group_discovery" and scope.split("/")[1] != "us-east-1":
        raise Unavailable("IAM global-event home Region not established for this scope")
    coverage = get(envelope, "EventCoverage", dict)
    if get(coverage, "collection_status", str) != "collected" or get(coverage, "projection", str) != "full_event_identity_and_error":
        raise Unavailable("requested CloudTrail event history not fully collected")
    covered = _strings(get(coverage, "EventNames", list))
    if not names <= covered:
        raise Unavailable("CloudTrail event-name coverage incomplete")
    start = _timestamp(get(coverage, "WindowStart", str))
    end = _timestamp(get(coverage, "WindowEnd", str))
    if start >= end:
        raise Unavailable("invalid CloudTrail observation window")
    approved = _strings(get(_policy(index, scope), policy_field, list))
    flagged = []
    seen = set()
    for row in rows:
        event_id = get(row, "EventId", str)
        if not event_id or event_id in seen:
            raise Unavailable("missing or duplicate CloudTrail event ID")
        seen.add(event_id)
        name = get(row, "EventName", str)
        if name not in covered:
            raise Unavailable("event outside declared query coverage")
        if not start <= _timestamp(get(row, "EventTime", str)) <= end:
            raise Unavailable("event outside declared observation window")
        event = get(row, "CloudTrailEvent", dict)
        if get(event, "recipientAccountId", str) != scope.split("/")[0] or get(event, "awsRegion", str) != scope.split("/")[1]:
            raise Unavailable("foreign CloudTrail event account or Region")
        event_source = get(event, "eventSource", str)
        if name in names:
            if event_source != source:
                raise Unavailable("queried event source does not match operation")
            actor = get(event, "userIdentity.arn", str)
            error = event.get("errorCode")
            if error is not None and (not isinstance(error, str) or not error):
                raise Unavailable("malformed CloudTrail error code")
            if error is None and "errorMessage" in event:
                raise Unavailable("CloudTrail error message without status code")
            if error is None and actor not in approved:
                flagged.append(event_id)
    return result(bool(flagged), scope=scope, unapproved_successful_event_ids=sorted(flagged),
                  window_start=start.isoformat(), window_end=end.isoformat())


@_signed("aws_cloudtrail_administration_command", ["aws_cloudtrail_activity"], target="scope")
def cloudtrail_administration_command(item, index):
    return _activity(item, index, "aws_cloudtrail_administration_command")


@_signed("aws_cloudtrail_event_triggered_execution", ["aws_cloudtrail_activity"], target="scope")
def cloudtrail_event_triggered_execution(item, index):
    return _activity(item, index, "aws_cloudtrail_event_triggered_execution")


@_signed("aws_cloudtrail_permission_group_discovery", ["aws_cloudtrail_activity"], target="scope")
def cloudtrail_permission_group_discovery(item, index):
    return _activity(item, index, "aws_cloudtrail_permission_group_discovery")


def _hub(item, index):
    scope = _item(item, index, "securityhub_hub", "HubArn")
    arn = get(item, "HubArn", str)
    _arn_scope(arn, scope, "securityhub")
    return arn, scope


@_signed("aws_securityhub_aggregated_findings_present", ["securityhub_hub"])
def securityhub_aggregated_findings(item, index):
    arn, scope = _hub(item, index)
    required = _strings(get(_policy(index, scope), "required_aggregated_regions", list), nonempty=True)
    aggregators = _child(item, "FindingAggregators")
    findings = _child(item, "AggregatedFindings")
    if len(aggregators) > 1:
        raise Unavailable("ambiguous Security Hub finding aggregators")
    if not aggregators:
        return result(True, hub_arn=arn, reason="no configured finding aggregator")
    aggregator = aggregators[0]
    aggregator_arn = get(aggregator, "FindingAggregatorArn", str)
    _arn_scope(aggregator_arn, scope, "securityhub")
    if not aggregator_arn.split(":", 5)[-1].startswith("finding-aggregator/"):
        raise Unavailable("malformed finding aggregator identity")
    mode = get(aggregator, "RegionLinkingMode", str)
    if mode != "SPECIFIED_REGIONS":
        raise Unavailable("aggregator region mode needs audited Region expansion")
    linked = _strings(get(aggregator, "Regions", list)) | {scope.split("/")[1]}
    observed = set()
    for finding in findings:
        region = get(finding, "Region", str)
        account = get(finding, "AwsAccountId", str)
        if not re.fullmatch(r"[0-9]{12}", account) or region not in linked:
            raise Unavailable("aggregated finding origin malformed or outside linked Regions")
        observed.add(region)
    missing_links = sorted(required - linked)
    missing_findings = sorted(required - observed)
    return result(bool(missing_links or missing_findings), hub_arn=arn,
                  missing_linked_regions=missing_links, regions_without_imported_findings=missing_findings)


@_signed("aws_securityhub_standards_control_baseline", ["securityhub_hub"])
def securityhub_standards_baseline(item, index):
    arn, scope = _hub(item, index)
    baseline = list_of_objects(get(_policy(index, scope), "securityhub_standards_baseline", list))
    expected = {}
    for standard in baseline:
        standard_arn = get(standard, "StandardsArn", str)
        controls = get(standard, "Controls", dict)
        if standard_arn in expected:
            raise Unavailable("duplicate baseline standard")
        if any(not isinstance(cid, str) or not cid or status not in ("ENABLED", "DISABLED") for cid, status in controls.items()):
            raise Unavailable("malformed baseline control status")
        expected[standard_arn] = controls
    enabled = _child(item, "EnabledStandards")
    actual = {}
    for standard in enabled:
        standard_arn = get(standard, "StandardsArn", str)
        subscription_arn = get(standard, "StandardsSubscriptionArn", str)
        status = get(standard, "StandardsStatus", str)
        if standard_arn in actual or status != "READY":
            raise Unavailable("duplicate or transitional enabled standard")
        actual[standard_arn] = subscription_arn
    control_sets = _child(item, "StandardsControls")
    observed_controls = {}
    for control_set in control_sets:
        subscription = get(control_set, "StandardsSubscriptionArn", str)
        if subscription in observed_controls or subscription not in actual.values():
            raise Unavailable("control inventory not tied to one enabled standard")
        controls = _child(control_set, "Controls")
        statuses = {}
        for control in controls:
            cid = get(control, "ControlId", str)
            status = get(control, "ControlStatus", str)
            if cid in statuses or status not in ("ENABLED", "DISABLED"):
                raise Unavailable("duplicate or malformed control status")
            statuses[cid] = status
        observed_controls[subscription] = statuses
    if set(observed_controls) != set(actual.values()):
        raise Unavailable("enabled standard control inventory incomplete")
    mismatch = sorted(standard for standard in set(expected) | set(actual)
                      if standard not in expected or standard not in actual or
                      observed_controls[actual[standard]] != expected[standard])
    return result(bool(mismatch), hub_arn=arn, mismatched_standard_arns=mismatch)


@_signed("aws_backup_recent_restore_test", ["backup_restore_testing_plan", "backup_restore_testing_selection", "backup_restore_job"], target="scope")
def backup_recent_restore_test(item, index):
    plans, _, scope = _rows(index, "backup_restore_testing_plan")
    selections, _, _ = _rows(index, "backup_restore_testing_selection")
    jobs, _, _ = _rows(index, "backup_restore_job")
    if get(item, "scope", str) != scope:
        raise Unavailable("restore-testing scope subject differs from collection")
    capture = _timestamp(get(get(index, "context", dict), "created_at", str))
    threshold = capture - timedelta(days=365)
    plan_by_name = {}
    for plan in plans:
        name = get(plan, "RestoreTestingPlanName", str)
        arn = get(plan, "RestoreTestingPlanArn", str)
        _arn_scope(arn, scope, "backup")
        if ":restore-testing-plan:" not in arn:
            raise Unavailable("malformed restore testing plan ARN")
        if not name or name in plan_by_name:
            raise Unavailable("duplicate or malformed restore testing plan")
        plan_by_name[name] = arn
    selected = set()
    for selection in selections:
        name = get(selection, "RestoreTestingPlanName", str)
        resource_type = get(selection, "ProtectedResourceType", str)
        if name not in plan_by_name or not resource_type:
            raise Unavailable("restore testing selection has no scoped plan or resource type")
        selected.add((plan_by_name[name], resource_type))
    if plans and not selected:
        raise Unavailable("restore testing plans have no complete selections")
    successes = set()
    job_ids = set()
    for job in jobs:
        job_id = get(job, "RestoreJobId", str)
        if not job_id or job_id in job_ids:
            raise Unavailable("duplicate or malformed restore job ID")
        job_ids.add(job_id)
        if get(job, "AccountId", str) != scope.split("/")[0]:
            raise Unavailable("foreign restore job account")
        # ListRestoreJobs also returns ordinary restores. Its optional CreatedBy
        # identifies restore-testing jobs; an authenticated complete API read
        # can establish its absence, unlike an incomplete imported record.
        if job.get('CreatedBy', {}) == {} and job.get('_provenance') == {
                'source_operation': 'ListRestoreJobs', 'read_only': True,
                'optional_fields_complete': ['CreatedBy']}:
            continue
        created_by = get(job, "CreatedBy", dict)
        plan_arn = get(created_by, "RestoreTestingPlanArn", str)
        resource_type = get(job, "ResourceType", str)
        if plan_arn not in plan_by_name.values() or not resource_type:
            raise Unavailable("restore job not tied to a scoped testing plan")
        status = get(job, "Status", str)
        if status not in ("PENDING", "RUNNING", "COMPLETED", "ABORTED", "FAILED"):
            raise Unavailable("unrecognized restore job status")
        if status == "COMPLETED":
            completed = _timestamp(get(job, "CompletionDate", str))
            if completed > capture:
                raise Unavailable("restore job completed after capture instant")
            if completed >= threshold:
                successes.add((plan_arn, resource_type))
    if not selected:
        return "NOT_APPLICABLE", {"reason": "no restore testing plans or selected resource types"}
    missing = sorted(selected - successes)
    return result(bool(missing), missing_recent_restore_tests=[{"RestoreTestingPlanArn": arn, "ResourceType": kind} for arn, kind in missing],
                  completed_after=threshold.isoformat())
