"""Signed sw38 AWS snapshot checks. All policy and inventory inputs are scope-bound."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from ipaddress import ip_network
import re

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get

SPECS = {'aws.nist.sc_8_1_coverage': {'category': 'compliance',
                              'kind': 'transport_endpoint',
                              'provider': 'aws',
                              'remediation': 'Correct the failing configuration and update the approved '
                                             'scope.',
                              'severity': 'medium',
                              'sha': 'cef0b27e9ed24fb06c26e6fdd10f6238c944ec53a9040f8e6c852b807de12e3e',
                              'title': 'Transmitted data uses approved TLS on all endpoints'},
 'aws.nist.sc_8_coverage': {'category': 'compliance',
                            'kind': 'transport_endpoint',
                            'provider': 'aws',
                            'remediation': 'Correct the failing configuration and update the approved '
                                           'scope.',
                            'severity': 'medium',
                            'sha': 'a0f38d61c06a90d2fb02f3d4c248386a2ccaac5f7430e5b81f4642b54a107bbd',
                            'title': 'Transmitted data uses approved TLS on all endpoints'},
 'aws.nist.waf_classic_regional_acl_logging': {'category': 'hardening',
                                               'kind': 'waf_web_acl',
                                               'provider': 'aws',
                                               'remediation': 'Configure WAF Classic logging for every '
                                                              'regional web ACL.',
                                               'severity': 'medium',
                                               'sha': '023ce98c86c95852868f72dad9cfd3d314cd6a34a39a872abbbd315270535049',
                                               'title': 'Regional WAF Classic web ACLs have logging '
                                                        'destinations'},
 'aws.pci.s3.allowed_policy_principals': {'category': 'hardening',
                                          'kind': 'bucket',
                                          'provider': 'aws',
                                          'remediation': 'Edit the S3 bucket policy to restrict Allow '
                                                         'principals and aws:SourceIp or aws:SourceVpc '
                                                         'conditions to the approved inventory.',
                                          'severity': 'medium',
                                          'sha': '317030dbef447895cec24e66eec5fba22ed11024b501de92635c61d8a91e7cbc',
                                          'title': 'S3 policy grants only allowed identities and '
                                                   'networks'},
 'aws.pci.s3.bucket_backup_plan': {'category': 'hardening',
                                   'kind': 'bucket',
                                   'provider': 'aws',
                                   'remediation': 'Add each scoped bucket ARN to an active AWS Backup '
                                                  'selection in a plan with scheduled rules.',
                                   'severity': 'medium',
                                   'sha': '513050bcd45d11b9f69992dfb22bdda9ddcf5d521ff08bbf8649a6893578ef51',
                                   'title': 'S3 buckets are protected by a backup plan'},
 'aws_cis_s3_macie_classification_coverage': {'category': 'hardening',
                                              'kind': 'bucket',
                                              'provider': 'aws',
                                              'remediation': 'Enable Macie automated discovery or '
                                                             'create a RUNNING classification job whose '
                                                             'bucket selection includes each scoped S3 '
                                                             'bucket.',
                                              'severity': 'medium',
                                              'sha': '37edfbc6d6a08827e6a80da0100f627ee4896d0286a7942cb1d4825b3e20f078',
                                              'title': 'S3 buckets have verifiable Macie discovery '
                                                       'coverage'},
 'aws_cloudwatchlogs_cloud_storage_staging': {'category': 'identity',
                                              'kind': 'log_group',
                                              'provider': 'aws',
                                              'remediation': 'Remove unauthorized staging-bucket write '
                                                             'grants and investigate PutObject or '
                                                             'CopyObject CloudTrail data events from '
                                                             'unapproved principals.',
                                              'severity': 'medium',
                                              'sha': '01643070282c6b06d5aeb5c9135b422ea8bf938ba0ecba548dca33f2e51a504e',
                                              'title': 'Data from Cloud Storage'},
 'aws_cloudwatchlogs_information_repository_read': {'category': 'identity',
                                                    'kind': 'log_group',
                                                    'provider': 'aws',
                                                    'remediation': 'Remove unapproved principals from '
                                                                   'Secrets Manager, S3 and database '
                                                                   'read policies and investigate '
                                                                   'matching CloudTrail data events.',
                                                    'severity': 'medium',
                                                    'sha': '63e948da06d66d0183e7ad9a175ba94c2928023e1555afe257b5d5bc2f10048a',
                                                    'title': 'Data from Information Repositories'},
 'aws_logging_service_multi_az': {'category': 'hardening',
                                  'kind': 'opensearch_domain',
                                  'provider': 'aws',
                                  'remediation': 'Enable zoneAwarenessEnabled and at least two '
                                                 'availability zones on the OpenSearch domain.',
                                  'severity': 'medium',
                                  'sha': 'cbcb80f840ef82079582cbb0e5703e4a91532b0656ccf60864b6b6f52a63e554',
                                  'title': 'SIEM has redundant availability zones'},
 'aws_nist_autoscaling_use_multiple_instance_types_in_multiple_az': {'category': 'compliance',
                                                                     'kind': 'autoscaling_group',
                                                                     'provider': 'aws',
                                                                     'remediation': 'Configure the '
                                                                                    'resource to '
                                                                                    'satisfy the stated '
                                                                                    'predicate and '
                                                                                    'review missing '
                                                                                    'inventory or '
                                                                                    'policy inputs.',
                                                                     'severity': 'medium',
                                                                     'sha': 'af9baef84cb8dd2df765bfec52fc10d22c9c25f27a5b050ad89340e4935c7581',
                                                                     'title': 'EC2 auto scaling groups '
                                                                              'should use multiple '
                                                                              'instance types in '
                                                                              'multiple availability '
                                                                              'zones'},
 'aws_nist_elasticache_redis_cluster_automatic_backup_retention_15_days': {'category': 'compliance',
                                                                           'kind': 'elasticache_replication_group',
                                                                           'provider': 'aws',
                                                                           'remediation': 'Configure '
                                                                                          'the resource '
                                                                                          'to satisfy '
                                                                                          'the stated '
                                                                                          'predicate '
                                                                                          'and review '
                                                                                          'missing '
                                                                                          'inventory or '
                                                                                          'policy '
                                                                                          'inputs.',
                                                                           'severity': 'medium',
                                                                           'sha': '86e68b1fb4a09d61f71806c6326ec565d59de68ec34eccf6e41ce6066e78047c',
                                                                           'title': 'ElastiCache Redis '
                                                                                    'cluster automatic '
                                                                                    'backup should be '
                                                                                    'enabled with '
                                                                                    'retention period '
                                                                                    'of 15 days or '
                                                                                    'greater'},
 'aws_nist_opensearch_domain_logs_to_cloudwatch': {'category': 'compliance',
                                                   'kind': 'opensearch_domain',
                                                   'provider': 'aws',
                                                   'remediation': 'Configure the resource to satisfy '
                                                                  'the stated predicate and review '
                                                                  'missing inventory or policy inputs.',
                                                   'severity': 'medium',
                                                   'sha': '31d16d407ecc59e34789db6851f8c72a450bf8fde8d413aa996a5d69770a0781',
                                                   'title': 'OpenSearch domains logs to AWS CloudWatch '
                                                            'Logs'},
 'aws_nist_vpc_igw_attached_to_authorized_vpc': {'category': 'compliance',
                                                 'kind': 'internet_gateway',
                                                 'provider': 'aws',
                                                 'remediation': 'Configure the resource to satisfy the '
                                                                'stated predicate and review missing '
                                                                'inventory or policy inputs.',
                                                 'severity': 'medium',
                                                 'sha': '99bbeca6a2285f2cd95590c9f379b82e739c549037661527f773a1f909015212',
                                                 'title': 'VPC internet gateways should be attached to '
                                                          'authorized vpc'},
 'aws_nist_waf_web_acl_logging_enabled': {'category': 'compliance',
                                          'kind': 'waf_web_acl',
                                          'provider': 'aws',
                                          'remediation': 'Configure the resource to satisfy the stated '
                                                         'predicate and review missing inventory or '
                                                         'policy inputs.',
                                          'severity': 'medium',
                                          'sha': '5ca4c3d3daa92bf479bb530c1a4922ea9cf0e3cddae6175b169c82b6bdb3186f',
                                          'title': 'WAF web ACL logging should be enabled'},
 'aws_resource_priority_tags_present': {'category': 'hardening',
                                        'kind': 'aws_tagged_resource',
                                        'provider': 'aws',
                                        'remediation': 'Add approved classification and criticality or '
                                                       'business-value tag keys and values to every '
                                                       'scoped EC2, S3, RDS and Lambda resource.',
                                        'severity': 'medium',
                                        'sha': 'f841ad1b7c0635e81a32d96c7cc23c6354b67e5a1a66e0d936763e6735526859',
                                        'title': 'AWS resources carry approved classification and '
                                                 'priority tags'}}
PROPOSED_SPEC_SHA256 = {cid: spec["sha"] for cid, spec in SPECS.items()}


def _scope(index):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "aws":
        raise Unavailable("foreign provider")
    scope = get(context, "scope", str)
    if not re.fullmatch(r"[0-9]{12}/(?:global|[a-z]{2}(?:-[a-z]+)+-[0-9])", scope):
        raise Unavailable("invalid AWS scope")
    return scope


def _rows(index, kind, *, scope=None):
    scope = _scope(index) if scope is None else scope
    envelopes = get(index, "collections", dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable("collection scope or pagination unavailable: " + kind)
    envelope = get({"row": envelopes[0]}, "row", dict)
    if (envelope.get("type") != kind or envelope.get("scope") != scope or
            envelope.get("status") not in ("collected", "empty") or
            envelope.get("coverage_status", "collected") not in ("collected", "empty")):
        raise Unavailable("incomplete or foreign collection: " + kind)
    rows = complete_items(index, kind)
    shown = get(envelope, "items", list)
    raw = get(index, kind, list)
    if (len(rows) != len(shown) or len(rows) != len(raw) or
            envelope["status"] == "empty" and rows):
        raise Unavailable("collection projection incomplete: " + kind)
    for wrapper in raw:
        if (get(wrapper, "type", str) != kind or get(wrapper, "scope", str) != scope or
                wrapper.get("provider", "aws") != "aws"):
            raise Unavailable("foreign resource wrapper: " + kind)
    for row in rows:
        if sum(row == candidate for candidate in shown) != 1:
            raise Unavailable("ambiguous or missing collection item: " + kind)
    return rows


def _subject(item, index, kind, identity):
    rows = _rows(index, kind)
    name = get(item, identity, str)
    if not name or sum(get(row, identity, str) == name and row == item for row in rows) != 1:
        raise Unavailable("subject absent or ambiguous in scoped inventory")
    if sum(get(row, identity, str) == name for row in rows) != 1:
        raise Unavailable("duplicate subject identity")
    return name


def _policy(index):
    scope = _scope(index)
    metadata = get(get(index, "context", dict), "metadata", dict)
    if 'sw38_policy' in metadata:
        policy = get(metadata, 'sw38_policy', dict)
    else:
        policy = get(get(metadata, 'compliance_policy', dict), 'sw38_policy', dict)
        if 'by_scope' in policy:
            policy = get(get(policy, 'by_scope', dict), scope, dict)
    if policy.get("status") != "collected" or policy.get("scope") != scope:
        raise Unavailable("scope-bound operator policy unavailable")
    return policy


def _strings(value, *, nonempty=False):
    if (not isinstance(value, list) or any(not isinstance(v, str) or not v.strip() for v in value)
            or len(value) != len(set(value)) or nonempty and not value):
        raise Unavailable("malformed policy or fact string list")
    return set(value)


def _objects(value):
    if not isinstance(value, list) or any(not isinstance(v, dict) for v in value):
        raise Unavailable("malformed object list")
    return value


def _arn_account_region(arn, service, scope):
    account, region = scope.split("/")
    match = re.fullmatch(r"arn:(aws(?:-[a-z0-9-]+)?):" + re.escape(service) + r":([^:]*):([0-9]{12}):.+", arn)
    if not match or match.group(2) != region or match.group(3) != account:
        raise Unavailable("foreign or malformed ARN")
    return match.group(1)


def _register(cid, evaluator, *dependencies, target="resource"):
    spec = SPECS[cid]
    category = spec["category"] if spec["category"] in {"hardening", "exposure", "least_privilege", "iam_graph", "network"} else "hardening"
    register(cid, "aws", category, spec["kind"], spec["title"], spec["severity"], "CM-6",
             spec["remediation"], target=target, dependencies=list(dependencies or (spec["kind"],)))(evaluator)
    if CHECKS[-1].category != spec["category"]:
        CHECKS[-1] = replace(CHECKS[-1], category=spec["category"])
    return evaluator


def _log_events(item, index):
    name = _subject(item, index, "log_group", "logGroupName")
    scope = _scope(index)
    events = get(item, "CloudTrailDataEvents", dict)
    if (get(events, "collection_status", str) != "collected" or
            get(events, "selectors_complete", bool) is not True or
            get(events, "retention_complete", bool) is not True or
            get(events, "log_group_name", str) != name or
            get(events, "scope", str) != scope):
        raise Unavailable("CloudTrail data-event selectors, retention or scope incomplete")
    return name, _objects(get(events, "items", list))


def _event_data(event):
    timestamp = get(event, "eventTime", str)
    try:
        if datetime.fromisoformat(timestamp.replace("Z", "+00:00")).tzinfo is None:
            raise ValueError("naive event time")
    except ValueError as exc:
        raise Unavailable("event time unavailable or malformed") from exc
    name = get(event, "eventName", str)
    principal = get(event, "userIdentity", dict)
    arn = get(principal, "arn", str)
    if not re.fullmatch(r"arn:aws(?:-[a-z0-9-]+)?:[a-z0-9-]+:[^:]*:[0-9]{12}:.+", arn):
        raise Unavailable("event principal ARN unavailable")
    resource = get(event, "resourceArn", str)
    if not re.fullmatch(r"arn:aws(?:-[a-z0-9-]+)?:[a-z0-9-]+:[^:]*:[0-9]{0,12}:.+", resource):
        raise Unavailable("event resource ARN unavailable")
    error = event.get("errorCode")
    if error is not None and (not isinstance(error, str) or not error):
        raise Unavailable("malformed event errorCode")
    return name, arn, resource, error


def cloud_storage_staging(item, index):
    name, events = _log_events(item, index)
    policy = _policy(index)
    staging = get(policy, "staging_bucket_writers", dict)
    if not staging:
        raise Unavailable("designated staging bucket policy absent")
    approved = {bucket: _strings(writers) for bucket, writers in staging.items()}
    if any(not isinstance(bucket, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{2,62}", bucket) for bucket in approved):
        raise Unavailable("malformed staging bucket policy")
    unexpected = []
    for event in events:
        operation, principal, resource, error = _event_data(event)
        if operation not in {"PutObject", "CopyObject"} or error is not None:
            continue
        match = re.fullmatch(r"arn:aws(?:-[a-z0-9-]+)?:s3:::(?P<bucket>[^/]+)/.+", resource)
        if match and match.group("bucket") in approved and principal not in approved[match.group("bucket")]:
            unexpected.append({"principal": principal, "resource": resource, "eventTime": event["eventTime"]})
    return result(bool(unexpected), log_group=name, unapproved_successful_staging_writes=unexpected)


def information_repository_read(item, index):
    name, events = _log_events(item, index)
    policy = _policy(index)
    repositories = get(policy, "information_repository_arns", list)
    approved = _strings(get(policy, "approved_data_access_principals", list))
    scoped = _strings(repositories, nonempty=True)
    unexpected = []
    for event in events:
        operation, principal, resource, error = _event_data(event)
        if operation in {"GetSecretValue", "GetObject", "ExecuteStatement"} and error is None:
            # Object ARNs are matched to an approved bucket ARN prefix; other resources match exactly.
            matched = any(resource == target or target.startswith("arn:aws:s3:::") and
                          resource.startswith(target.rstrip("/") + "/") for target in scoped)
            if matched and principal not in approved:
                unexpected.append({"principal": principal, "resource": resource, "eventTime": event["eventTime"]})
    return result(bool(unexpected), log_group=name, unapproved_successful_repository_reads=unexpected)


_register("aws_cloudwatchlogs_cloud_storage_staging", cloud_storage_staging, "log_group")
_register("aws_cloudwatchlogs_information_repository_read", information_repository_read, "log_group")

def _bucket(item, index):
    name = _subject(item, index, "bucket", "Name")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{2,62}", name):
        raise Unavailable("malformed bucket name")
    return name, "arn:aws:s3:::" + name


def allowed_policy_principals(item, index):
    bucket, arn = _bucket(item, index)
    policy = _policy(index)
    principals = _strings(get(policy, "allowed_s3_principals", list))
    networks = _strings(get(policy, "allowed_s3_source_ips", list))
    vpcs = _strings(get(policy, "allowed_s3_source_vpcs", list))
    try:
        allowed_networks = [ip_network(value, strict=False) for value in networks]
    except ValueError as exc:
        raise Unavailable("malformed approved source IP CIDR") from exc
    data = get(item, "Policy", dict)
    if data.get("absent") is True and data.get("collection_status") in ("empty", "collected"):
        return result(False, bucket=bucket, policy="absent")
    if get(data, "collection_status", str) != "collected":
        raise Unavailable("bucket policy unavailable")
    statements = get(get(data, "Policy", dict), "Statement", list)
    bad, uncertain = [], []
    for statement in _objects(statements):
        effect = get(statement, "Effect", str)
        if effect not in {"Allow", "Deny"}:
            raise Unavailable("unrecognized policy effect")
        if effect == "Deny":
            # Deny may neutralize a broad Allow; an unsafe grant cannot be proven.
            uncertain.append("Deny")
            continue
        if any(key in statement for key in ("NotPrincipal", "NotAction", "NotResource")):
            uncertain.append("unsupported inverse policy statement")
            continue
        resources = statement.get("Resource")
        resources = [resources] if isinstance(resources, str) else resources
        actions = statement.get("Action")
        actions = [actions] if isinstance(actions, str) else actions
        if not isinstance(resources, list) or not resources or any(not isinstance(v, str) or v not in {arn, arn + "/*"} for v in resources):
            uncertain.append("unresolved policy resource")
            continue
        if not isinstance(actions, list) or not actions or any(not isinstance(v, str) or not v for v in actions):
            uncertain.append("unresolved policy action")
            continue
        raw_principal = get(statement, "Principal")
        if raw_principal == "*":
            members = {"*"}
        elif isinstance(raw_principal, dict) and raw_principal and set(raw_principal) <= {"AWS", "Federated", "Service"}:
            members = set()
            for value in raw_principal.values():
                values = [value] if isinstance(value, str) else value
                members.update(_strings(values, nonempty=True))
        else:
            uncertain.append("unsupported principal syntax")
            continue
        condition = statement.get("Condition", {})
        if not isinstance(condition, dict):
            uncertain.append("malformed condition")
            continue
        network_safe = False
        if condition:
            if set(condition) != {"IpAddress"} and set(condition) != {"StringEquals"}:
                uncertain.append("unsupported condition operator")
                continue
            operator = next(iter(condition))
            field = "aws:SourceIp" if operator == "IpAddress" else "aws:SourceVpc"
            if not isinstance(condition[operator], dict) or set(condition[operator]) != {field}:
                uncertain.append("unsupported condition keys")
                continue
            values = condition[operator][field]
            values = [values] if isinstance(values, str) else values
            try:
                selected = _strings(values, nonempty=True)
                network_safe = (all(any(ip_network(v, strict=False).subnet_of(a) for a in allowed_networks) for v in selected)
                                if operator == "IpAddress" else selected <= vpcs)
            except ValueError:
                uncertain.append("malformed source IP condition")
                continue
        if not (members <= principals or network_safe):
            if "*" in members:
                uncertain.append("public-access-block interaction unresolved")
            else:
                bad.append({"principals": sorted(members), "actions": sorted(actions)})
    if bad and not uncertain:
        return result(True, bucket=bucket, unapproved_allows=bad)
    if uncertain:
        return unknown("policy semantics or Deny interaction unresolved", bucket=bucket, uncertain=uncertain)
    return result(False, bucket=bucket, allowed_statement_count=len(statements))


def bucket_backup_plan(item, index):
    bucket, arn = _bucket(item, index)
    scope = _scope(index)
    coverage = _rows(index, "s3_backup_plan_coverage", scope=scope)
    if len(coverage) != 1:
        raise Unavailable("account-wide Backup selection coverage absent or ambiguous")
    fact = coverage[0]
    if get(fact, "AccountId", str) != scope[:12] or get(fact, "AllEnabledRegionsCollected", bool) is not True:
        raise Unavailable("Backup region coverage incomplete")
    selected = False
    uncertain = False
    for selection in _objects(get(fact, "Selections", list)):
        region = get(selection, "Region", str)
        if not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]", region):
            raise Unavailable("malformed Backup selection region")
        if get(selection, "Active", bool) is not True or get(selection, "ScheduledRules", int) <= 0:
            continue
        resources = _strings(get(selection, "Resources", list))
        excludes = _strings(get(selection, "NotResources", list))
        from .aws_backup_selection import arn_matches
        # A complete RDS-only wildcard cannot select an S3 bucket, regardless
        # of its additional AND tag restrictions.
        if resources and not get(selection, "ListOfTags", list) and not any(arn_matches(value, arn) for value in resources):
            continue
        if any(arn_matches(value, arn) for value in excludes):
            continue
        if any("*" in value for value in resources | excludes):
            uncertain = True
            continue
        conditions = get(selection, "Conditions", dict)
        if conditions or get(selection, "ListOfTags", list):
            uncertain = True
            continue
        if arn in resources and arn not in excludes:
            selected = True
    if selected:
        return result(False, bucket_arn=arn, active_selection=True)
    if uncertain:
        return unknown("Backup wildcard or conditional selection cannot be resolved", bucket_arn=arn)
    return result(True, bucket_arn=arn, active_selection=False)


def _macie_match(block, bucket, account):
    if not isinstance(block, dict):
        raise Unavailable("malformed Macie bucket criteria")
    rules = _objects(get(block, "and", list))
    if not rules:
        return None
    uncertain = False
    for rule in rules:
        if set(rule) != {"simpleCriterion"}:
            uncertain = True
            continue
        criterion = get(rule, "simpleCriterion", dict)
        key = get(criterion, "key", str)
        comparator = get(criterion, "comparator", str)
        values = _strings(get(criterion, "values", list), nonempty=True)
        if key not in {"ACCOUNT_ID", "S3_BUCKET_NAME"} or comparator not in {"EQ", "NE"}:
            uncertain = True
            continue
        matched = (account if key == "ACCOUNT_ID" else bucket) in values
        if comparator == "NE":
            matched = not matched
        if not matched:
            return False
    return None if uncertain else True


def macie_classification_coverage(item, index):
    bucket, arn = _bucket(item, index)
    scope = _scope(index)
    location = get(item, "Location", dict)
    if get(location, "collection_status", str) != "collected":
        raise Unavailable("bucket home Region unavailable")
    region = location.get("LocationConstraint")
    if region is None:
        region = "us-east-1"
    if region == "EU":
        region = "eu-west-1"
    if not isinstance(region, str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]", region):
        raise Unavailable("bucket home Region unavailable")
    coverage = _rows(index, "s3_macie_region_coverage", scope=scope)
    if len(coverage) != 1 or get(coverage[0], "AccountId", str) != scope[:12] or get(coverage[0], "AllEnabledRegionsCollected", bool) is not True:
        raise Unavailable("account-wide Macie region coverage incomplete")
    matching = [row for row in _objects(get(coverage[0], "Regions", list)) if get(row, "Region", str) == region]
    if len(matching) != 1:
        raise Unavailable("Macie session for bucket Region unavailable")
    regional = matching[0]
    state = get(regional, "Session.status", str)
    if state not in {"ENABLED", "PAUSED", "DISABLED"}:
        raise Unavailable("Macie session status unrecognized")
    if state == "ENABLED" and get(regional, "AutomatedDiscovery.status", str) == "ENABLED":
        return result(False, bucket_arn=arn, coverage="automated_discovery")
    if state == "ENABLED" and get(regional, "AutomatedDiscovery.status", str) not in {"ENABLED", "DISABLED"}:
        raise Unavailable("Macie discovery status unrecognized")
    if get(regional, "Jobs.collection_status", str) not in {"collected", "empty"}:
        raise Unavailable("regional classification jobs incomplete")
    uncertain = False
    covered = False
    for job in _objects(get(regional, "Jobs.items", list)):
        status = get(job, "jobStatus", str)
        if status not in {"RUNNING", "COMPLETE", "CANCELLED", "PAUSED", "IDLE", "USER_PAUSED"}:
            raise Unavailable("classification job status unrecognized")
        if status not in {"RUNNING", "COMPLETE"}:
            continue
        definition = get(job, "s3JobDefinition", dict)
        if "bucketDefinitions" in definition and "bucketCriteria" in definition:
            uncertain = True
            continue
        if "bucketDefinitions" in definition:
            for group in _objects(get(definition, "bucketDefinitions", list)):
                if get(group, "accountId", str) == scope[:12] and bucket in _strings(get(group, "buckets", list)):
                    covered = True
        elif "bucketCriteria" in definition:
            criteria = get(definition, "bucketCriteria", dict)
            included = _macie_match(get(criteria, "includes", dict), bucket, scope[:12])
            excluded = _macie_match(get(criteria, "excludes", dict), bucket, scope[:12]) if "excludes" in criteria else False
            if included is True and excluded is False:
                covered = True
            if included is None or excluded is None:
                uncertain = True
        else:
            uncertain = True
    if uncertain:
        return unknown("classification job bucket criteria unresolved", bucket_arn=arn)
    if covered:
        return result(False, bucket_arn=arn, coverage="classification_job")
    return result(True, bucket_arn=arn, coverage="none")


_register("aws.pci.s3.allowed_policy_principals", allowed_policy_principals, "bucket")
_register("aws.pci.s3.bucket_backup_plan", bucket_backup_plan, "bucket", "s3_backup_plan_coverage")
_register("aws_cis_s3_macie_classification_coverage", macie_classification_coverage,
          "bucket", "s3_macie_region_coverage")

def authorized_igw(item, index):
    igw = _subject(item, index, "internet_gateway", "InternetGatewayId")
    scope = _scope(index)
    if scope.endswith("/global"):
        raise Unavailable("internet gateway requires regional scope")
    approved = _strings(get(_policy(index), "approved_vpc_ids", list))
    bad = []
    for attachment in _objects(get(item, "Attachments", list)):
        vpc = get(attachment, "VpcId", str)
        if not re.fullmatch(r"vpc-[0-9a-f]+", vpc):
            raise Unavailable("malformed attached VPC ID")
        state = get(attachment, "State", str)
        if state not in {"available", "attaching", "detaching", "detached"}:
            raise Unavailable("unrecognized gateway attachment state")
        if state != "detached" and vpc not in approved:
            bad.append(vpc)
    return result(bool(bad), internet_gateway_id=igw, unauthorized_vpc_ids=bad)


def _transport(item, index):
    scope = _scope(index)
    if get(item, "scope", str) != scope or get(item, "provider", str) != "aws":
        raise Unavailable("foreign transport scope target")
    policy = _policy(index)
    approved = _strings(get(policy, "approved_tls_policies", list), nonempty=True)
    unsafe = []
    external = 0
    seen = set()
    for endpoint in _rows(index, "transport_endpoint"):
        identity = get(endpoint, "id", str)
        if not identity or identity in seen:
            raise Unavailable("ambiguous transport endpoint identity")
        seen.add(identity)
        if get(endpoint, "AccountId", str) != scope[:12] or get(endpoint, "Scope", str) != scope:
            raise Unavailable("foreign transport endpoint")
        source = get(endpoint, "SourceKind", str)
        if source == "elbv2_listener":
            _arn_account_region(identity, "elasticloadbalancing", scope)
        elif source == "apigateway_domain":
            if not re.fullmatch(r"arn:aws(?:-[a-z0-9-]+)?:apigateway:" +
                                re.escape(scope.split("/")[1]) + r"::/domainnames/.+", identity):
                raise Unavailable("foreign API Gateway endpoint")
        elif source == "cloudfront_distribution":
            if not re.fullmatch(r"arn:aws(?:-[a-z0-9-]+)?:cloudfront::" +
                                re.escape(scope[:12]) + r":distribution/.+", identity):
                raise Unavailable("foreign CloudFront endpoint")
        else:
            raise Unavailable("unrecognized transport endpoint source")
        protocol = get(endpoint, "Protocol", str)
        if protocol not in {"HTTP", "HTTPS", "TLS"}:
            raise Unavailable("unrecognized endpoint protocol")
        if get(endpoint, "External", bool) is not True:
            continue
        external += 1
        if protocol == "HTTP":
            unsafe.append(identity)
            continue
        tls_policy = get(endpoint, "TLSPolicy", str)
        if not tls_policy:
            raise Unavailable("TLS policy unavailable")
        if tls_policy not in approved:
            unsafe.append(identity)
    if not external:
        return "NOT_APPLICABLE", {"reason": "no external transport endpoints in the complete inventory"}
    return result(bool(unsafe), external_endpoint_count=external, unsafe_endpoint_ids=unsafe)


def _waf_account(index):
    scope = _scope(index)
    if not scope.endswith("/global"):
        raise Unavailable("account-wide WAF coverage requires global scope")
    rows = _rows(index, "waf_account_acl_inventory", scope=scope)
    if len(rows) != 1 or get(rows[0], "AccountId", str) != scope[:12] or get(rows[0], "AllEnabledRegionsCollected", bool) is not True:
        raise Unavailable("account-wide WAF inventory incomplete")
    for field, identity in (("RegionalClassic", "WebACLId"), ("WAFv2", "ARN")):
        seen = set()
        for row in _objects(get(rows[0], field, list)):
            value = get(row, identity, str)
            region = get(row, "Region", str)
            if (not value or value in seen or
                    not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]", region)):
                raise Unavailable("ambiguous or malformed account-wide WAF ACL identity")
            if field == "WAFv2":
                _arn_account_region(value, "wafv2", scope[:12] + "/" + region)
            else:
                acl_arn = get(row, "WebACL.WebACLArn", str)
                _arn_account_region(acl_arn, "waf-regional", scope[:12] + "/" + region)
                if not acl_arn.endswith("/" + value):
                    raise Unavailable("regional WAF ACL ARN and ID differ")
            seen.add(value)
    return rows[0]


def _waf_scope(item, index):
    scope = _scope(index)
    if get(item, "scope", str) != scope or get(item, "provider", str) != "aws":
        raise Unavailable("foreign WAF scope target")
    if not scope.endswith("/global"):
        return None
    return scope


def _logging_missing(row, identifier, *, classic=False):
    logging = get(row, "LoggingConfiguration", dict)
    if logging.get("absent") is True and logging.get("collection_status") in {"collected", "empty"}:
        return True
    if get(logging, "collection_status", str) != "collected":
        raise Unavailable("ACL logging detail unavailable: " + identifier)
    config = get(logging, "LoggingConfiguration", dict)
    destinations = _strings(get(config, "LogDestinationConfigs", list))
    from peaso.aws_waf_logging import valid_destination_arn
    if any(not valid_destination_arn(arn, classic=classic) for arn in destinations):
        raise Unavailable("malformed WAF logging destination ARN")
    return not destinations


def waf_classic_regional_logging(item, index):
    if _waf_scope(item, index) is None:
        return "NOT_APPLICABLE", {"reason": "account-wide WAF check runs in global scope"}
    regional = _objects(get(_waf_account(index), "RegionalClassic", list))
    if not regional:
        return "NOT_APPLICABLE", {"reason": "no regional WAF Classic ACLs"}
    bad = []
    for row in regional:
        acl_id = get(row, "WebACLId", str)
        if _logging_missing(row, acl_id, classic=True):
            bad.append(acl_id)
    return result(bool(bad), regional_acl_ids_without_logging=bad)


def waf_all_logging(item, index):
    if _waf_scope(item, index) is None:
        return "NOT_APPLICABLE", {"reason": "account-wide WAF check runs in global scope"}
    account = _waf_account(index)
    bad = []
    assessed = 0
    for kind, rows in (("waf_web_acl", _rows(index, "waf_web_acl")),
                       ("wafregional_web_acl", _objects(get(account, "RegionalClassic", list))),
                       ("wafv2_web_acl", _objects(get(account, "WAFv2", list)))):
        for row in rows:
            assessed += 1
            identifier = get(row, "ARN", str) if kind == "wafv2_web_acl" else get(row, "WebACLId", str)
            if kind == "waf_web_acl":
                global_arn = get(row, "WebACL.WebACLArn", str)
                if not re.fullmatch(r"arn:aws(?:-[a-z0-9-]+)?:waf::" + re.escape(_scope(index)[:12]) +
                                    r":webacl/" + re.escape(identifier), global_arn):
                    raise Unavailable("foreign global WAF ACL")
            if _logging_missing(row, identifier, classic=kind != "wafv2_web_acl"):
                bad.append(identifier)
    if not assessed:
        return "NOT_APPLICABLE", {"reason": "no WAF ACLs in the complete account inventory"}
    return result(bool(bad), acl_ids_without_logging=bad)


def logging_service_multi_az(item, index):
    scope = _scope(index)
    if get(item, "scope", str) != scope or get(item, "provider", str) != "aws":
        raise Unavailable("foreign SIEM scope target")
    if scope.endswith("/global"):
        return "NOT_APPLICABLE", {"reason": "OpenSearch domain inventory is regional"}
    designated = get(_policy(index), "siem_domain_arn", str)
    _arn_account_region(designated, "es", scope)
    matches = []
    for row in _rows(index, "opensearch_domain"):
        domain = get(row, "Domain.DomainStatus", dict)
        if get(domain, "ARN", str) == designated:
            matches.append((row, domain))
    if len(matches) != 1:
        raise Unavailable("designated SIEM domain absent or ambiguous")
    row, domain = matches[0]
    domain_name = get(row, "DomainName", str)
    arn = get(domain, "ARN", str)
    if get(domain, "DomainName", str) != domain_name:
        raise Unavailable("OpenSearch domain identity mismatch")
    enabled = get(domain, "ClusterConfig.ZoneAwarenessEnabled", bool)
    if not enabled:
        return result(True, domain_arn=arn, zone_awareness_enabled=False)
    count = get(domain, "ClusterConfig.ZoneAwarenessConfig.AvailabilityZoneCount", int)
    if count < 1:
        raise Unavailable("invalid availability zone count")
    return result(not enabled or count < 2, domain_arn=arn, zone_awareness_enabled=enabled, availability_zone_count=count)


def opensearch_logs(item, index):
    domain_name = _subject(item, index, "opensearch_domain", "DomainName")
    scope = _scope(index)
    required = _strings(get(_policy(index), "required_opensearch_log_types", list), nonempty=True)
    if not required <= {"INDEX_SLOW_LOGS", "SEARCH_SLOW_LOGS", "ES_APPLICATION_LOGS", "AUDIT_LOGS"}:
        raise Unavailable("unrecognized required OpenSearch log type")
    domain = get(item, "Domain.DomainStatus", dict)
    arn = get(domain, "ARN", str)
    _arn_account_region(arn, "es", scope)
    if get(domain, "DomainName", str) != domain_name:
        raise Unavailable("OpenSearch domain identity mismatch")
    options = get(domain, "LogPublishingOptions", dict)
    bad = []
    for kind in required:
        if kind not in options:
            bad.append(kind)
            continue
        option = get(options, kind, dict)
        enabled = get(option, "Enabled", bool)
        destination = option.get("CloudWatchLogsLogGroupArn")
        if enabled and (not isinstance(destination, str) or not destination):
            raise Unavailable("enabled log type destination unavailable")
        if not enabled:
            bad.append(kind)
        else:
            _arn_account_region(destination, "logs", scope)
    return result(bool(bad), domain_arn=arn, required_log_types=sorted(required), disabled_log_types=sorted(bad))


_register("aws_nist_vpc_igw_attached_to_authorized_vpc", authorized_igw, "internet_gateway")
_register("aws.nist.sc_8_coverage", _transport, "transport_endpoint", target="scope")
_register("aws.nist.sc_8_1_coverage", _transport, "transport_endpoint", target="scope")
# These questions require one complete account-wide inventory, not a regional target.
waf_classic_regional_logging.evaluation_scope = "aws_account"
waf_all_logging.evaluation_scope = "aws_account"
_register("aws.nist.waf_classic_regional_acl_logging", waf_classic_regional_logging,
          "waf_account_acl_inventory", target="scope")
_register("aws_nist_waf_web_acl_logging_enabled", waf_all_logging,
          "waf_web_acl", "waf_account_acl_inventory", target="scope")
_register("aws_logging_service_multi_az", logging_service_multi_az, "opensearch_domain", target="scope")
_register("aws_nist_opensearch_domain_logs_to_cloudwatch", opensearch_logs, "opensearch_domain")

def resource_priority_tags(item, index):
    arn = _subject(item, index, "aws_tagged_resource", "ResourceArn")
    scope = _scope(index)
    if scope.endswith("/global"):
        raise Unavailable("tagged resource coverage requires a home-Region projection")
    envelope = get(index, "collections", dict)["aws_tagged_resource"][0]
    if _strings(get(envelope, "covered_source_kinds", list)) != {"instance", "bucket", "rds_db_instance", "lambda_function"}:
        raise Unavailable("taggable resource source coverage incomplete")
    source = get(item, "SourceKind", str)
    if source not in {"instance", "bucket", "rds_db_instance", "lambda_function"}:
        raise Unavailable("unrecognized tagged resource source")
    if get(item, "AccountId", str) != scope[:12]:
        raise Unavailable("foreign tagged resource account")
    if source == "bucket":
        if not re.fullmatch(r"arn:aws(?:-[a-z0-9-]+)?:s3:::[a-z0-9][a-z0-9.-]{2,62}", arn):
            raise Unavailable("malformed S3 bucket ARN")
    else:
        service = {"instance": "ec2", "rds_db_instance": "rds", "lambda_function": "lambda"}[source]
        _arn_account_region(arn, service, scope)
    policy = _policy(index)
    class_keys = _strings(get(policy, "classification_tag_keys", list), nonempty=True)
    priority_keys = _strings(get(policy, "priority_tag_keys", list), nonempty=True)
    allowed_class = _strings(get(policy, "allowed_classification_values", list), nonempty=True)
    allowed_priority = _strings(get(policy, "allowed_priority_values", list), nonempty=True)
    raw = get(item, "Tags", dict)
    if any(not isinstance(key, str) or not isinstance(value, str) for key, value in raw.items()):
        raise Unavailable("malformed tag map")
    classification = any(raw.get(key) in allowed_class for key in class_keys)
    priority = any(raw.get(key) in allowed_priority for key in priority_keys)
    return result(not (classification and priority), resource_arn=arn,
                  approved_classification=classification, approved_priority=priority)


def redis_backup_retention(item, index):
    arn = _subject(item, index, "elasticache_replication_group", "ARN")
    _arn_account_region(arn, "elasticache", _scope(index))
    engine = get(item, "Engine", str)
    if engine not in {"redis", "valkey"}:
        if engine == "memcached":
            return "NOT_APPLICABLE", {"replication_group_arn": arn, "reason": "not a Redis replication group"}
        raise Unavailable("unknown replication group engine")
    if "SnapshotRetentionLimit" in item or "SnapshotRetentionLimit" in item.get("_coverage", {}):
        days = get(item, "SnapshotRetentionLimit", int)
    elif (get(item, "_provenance.operation", str) == "elasticache:DescribeReplicationGroups" and
          get(item, "_provenance.native_response_complete", bool) is True):
        days = 0  # Documented omitted value on complete DescribeReplicationGroups response.
    else:
        raise Unavailable("snapshot retention detail incomplete")
    if days < 0:
        raise Unavailable("invalid snapshot retention days")
    return result(days < 15, replication_group_arn=arn, snapshot_retention_days=days)


def autoscaling_multiple_types_az(item, index):
    arn = _subject(item, index, "autoscaling_group", "AutoScalingGroupARN")
    _arn_account_region(arn, "autoscaling", _scope(index))
    zones = _strings(get(item, "AvailabilityZones", list), nonempty=True)
    if any(not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9][a-z]", zone) for zone in zones):
        raise Unavailable("malformed availability zone")
    policy = get(item, "MixedInstancesPolicy", dict)
    if get(policy, "collection_status", str) != "collected":
        raise Unavailable("effective mixed policy unavailable")
    types = _strings(get(policy, "EffectiveInstanceTypes", list), nonempty=True)
    if any(not re.fullmatch(r"[a-z][0-9a-z-]*\.[0-9a-z]+", value) for value in types):
        raise Unavailable("malformed effective instance type")
    return result(len(zones) < 2 or len(types) < 2, autoscaling_group_arn=arn,
                  effective_instance_types=sorted(types), availability_zones=sorted(zones))


_register("aws_resource_priority_tags_present", resource_priority_tags, "aws_tagged_resource")
_register("aws_nist_elasticache_redis_cluster_automatic_backup_retention_15_days", redis_backup_retention,
          "elasticache_replication_group")
_register("aws_nist_autoscaling_use_multiple_instance_types_in_multiple_az", autoscaling_multiple_types_az,
          "autoscaling_group")
