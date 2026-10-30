"""Retain original evaluator source and explain formerly identical PASS/FAIL evidence."""
import gzip
import hashlib
import json
from pathlib import Path
from copy import deepcopy

import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from tests.observed_evidence_successors import AWS_FIELDS

ROOT=Path(__file__).resolve().parents[1]
PROOF=json.loads((ROOT/'tests/fixtures/aws_observed_evidence_successors.json').read_text())
# Account-global partition discovery was reviewed separately from the additive
# evidence changes recorded in PROOF. Strip only this exact block before
# checking the original evidence-change and historical-source hashes.
ACCOUNT_GLOBAL_PARTITION_ADDENDUM='''        # The collector always records native STS caller identities, including
        # focused scans that do not request account contact/organization facts.
        # Use only identities bound to this exact account; never guess a
        # partition from another account or from the string "global".
        identities = context.get("metadata", {}).get("caller_identities", []) if isinstance(context.get("metadata"), dict) else []
        observed = set()
        for identity in identities if isinstance(identities, list) else []:
            if not isinstance(identity, dict) or identity.get("Account") != scope.split("/", 1)[0]:
                continue
            arn = identity.get("Arn")
            match = re.fullmatch(r"arn:(aws|aws-cn|aws-us-gov):(?:iam|sts)::([0-9]{12}):.+", arn) if isinstance(arn, str) else None
            if not match or match[2] != identity["Account"]:
                raise Unavailable("caller partition identity mismatch")
            observed.add(match[1])
        if len(observed) > 1:
            raise Unavailable("conflicting caller partitions for account")
        if observed:
            return observed.pop()
'''
# Security corrections accepted after the additive evidence review. These are
# exact inverse deltas, NOT new historical hashes or old predicates to execute.
# Review reports are under docs/aws-review; integrated at
# 15842280dfb336f356497451d94ec46b2ba5d4ee. Both immutable PROOF hashes remain
# mandatory after reconstruction, so extra edits anywhere still fail closed.
REVIEWED_NATIVE_SOURCE_DELTAS = {
    # identity-closure-review: IDENTITY-1 binds MetricDataQuery.AccountId.
    'aws_gap_metrics.py': (
        (
            (
                '\n'
                'def _metric_identity(alarm, name, namespace, filter_keys=frozenset()):\n'
                '    """True: alarm watches exactly this metric; None: references it in a form not modelled; False otherwise."""\n'
            ),
            (
                '\n'
                'def _metric_identity(alarm, name, namespace, filter_keys=frozenset(), *, account=None):\n'
                '    """True: alarm watches exactly this metric; None: references it in a form not modelled; False otherwise."""\n'
            ),
        ),
        (
            (
                '    for query in queries:\n'
                '        direct = "Metric" in query or "Metric" in query.get("_coverage", {})\n'
            ),
            (
                '    for query in queries:\n'
                '        watched_account = optional(query, "AccountId", account, str)\n'
                '        if watched_account is not None:\n'
                '            if re.fullmatch(r"[0-9]{12}", watched_account) is None:\n'
                '                raise Unavailable("malformed alarm metric account")\n'
                '            if account is None:\n'
                '                raise Unavailable("alarm metric account identity unverified")\n'
                '            if watched_account != account:\n'
                '                continue\n'
                '        direct = "Metric" in query or "Metric" in query.get("_coverage", {})\n'
            ),
        ),
        (
            (
                '                try:\n'
                '                    watches = _metric_identity(alarm, name, namespace, filter_keys)\n'
                '                except Unavailable as exc:\n'
            ),
            (
                '                try:\n'
                '                    watches = _metric_identity(alarm, name, namespace, filter_keys, account=account)\n'
                '                except Unavailable as exc:\n'
            ),
        ),
    ),
    # service-family-review; network-cross-service-sdk-review: ambiguous HeadBucket is UNKNOWN.
    'claude2_aws_b_edge.py': (
        (
            (
                '         extra={"index": inventory("bucket", [{"Name": "site"}]), "not_applicable": _cf(Origins=_origins_of(_custom())),\n'
                '                "cross_account_pass": {**_cf(Origins=_origins_of(_s3o(bucket="partner"))), "OriginBucketProbes": {"collection_status": "collected", "results": [{"Bucket": "partner", "HttpStatusCode": 403}]}},\n'
                '                "unprobed": _cf(Origins=_origins_of(_s3o(bucket="partner"))), "unprobed_expect": "UNKNOWN"},\n'
                '         note="S3 origins are those with S3OriginConfig (prowler) or a \'.s3.\' domain (steampipe); the bucket is the domain prefix before \'.s3\'. A bucket in the account inventory exists; otherwise "\n'
                '              "the HeadBucket probe decides (404 = missing, 200/301/403 = exists). Corrected for steampipe, which alarms on any bucket owned by another account.")\n'
                'def cf_s3_bucket(item, index):\n'
            ),
            (
                '         extra={"index": inventory("bucket", [{"Name": "site"}]), "not_applicable": _cf(Origins=_origins_of(_custom())),\n'
                '                "fail_expect": "UNKNOWN", "cross_account_unknown_expect": "UNKNOWN", "cross_account_unknown": {**_cf(Origins=_origins_of(_s3o(bucket="partner"))), "OriginBucketProbes": {"collection_status": "collected", "results": [{"Bucket": "partner", "HttpStatusCode": 403}]}},\n'
                '                "unprobed": _cf(Origins=_origins_of(_s3o(bucket="partner"))), "unprobed_expect": "UNKNOWN"},\n'
                '         note="S3 origins are those with S3OriginConfig (prowler) or a \'.s3.\' domain (steampipe); the bucket is the domain prefix before \'.s3\'. A bucket in the account inventory exists; otherwise "\n'
                '              "external origin existence remains UNKNOWN. Bare HeadBucket HTTP error codes cannot distinguish missing buckets from inaccessible buckets, and this collector has no bound origin-probe producer.")\n'
                'def cf_s3_bucket(item, index):\n'
            ),
        ),
        (
            (
                '        owned = set()\n'
                '    probes = None\n'
                '    missing, unresolved = [], []\n'
                '    for name in names:\n'
                '        if name in owned:\n'
                '            continue\n'
                '        if probes is None:\n'
                '            try:\n'
                '                found = detail(item, "OriginBucketProbes")\n'
                '                probes = {get(row, "Bucket", str): get(row, "HttpStatusCode", int) for row in list_of_objects(get(found or {"results": []}, "results", list))}\n'
                '            except Unavailable:\n'
                '                probes = {}\n'
                '        code = probes.get(name)\n'
                '        if code == 404:\n'
                '            missing.append(name)\n'
                '        elif code not in (200, 301, 403):\n'
                '            unresolved.append(name)\n'
                '    if missing:\n'
                '        return result(True, missing_buckets=missing)\n'
                '    if unresolved:\n'
            ),
            (
                '        owned = set()\n'
                '    # There is no collector-produced, request-bound origin probe contract.\n'
                '    # HeadBucket 400/403/404 are ambiguous errors, and a synthetic status code\n'
                '    # (including 200/301) cannot bind a native observation to this origin.\n'
                '    unresolved = [name for name in names if name not in owned]\n'
                '    if unresolved:\n'
            ),
        ),
    ),
    # core-semantic-review, network-closure-review, network-semantic-review;
    # test_aws_launch_template_instance_metadata_review: profile IDs, enclave
    # CIDRs/protocols, launch metadata provenance, and the native ENI enum.
    'claude_aws_a_ec2.py': (
        (
            (
                '\n'
                '@install("aws.claude_a.ec2.instance_profile_attached", "instance", "EC2 instance has an IAM instance profile",\n'
            ),
            (
                '\n'
                'def _validated_profile(item):\n'
                '    profile = _profile(item)\n'
                '    if profile is not None:\n'
                '        # A retained empty/malformed attachment object cannot establish a\n'
                '        # profile. Native DescribeInstances attachments carry both identifiers.\n'
                '        if not get(profile, "Arn", str) or not get(profile, "Id", str):\n'
                '            raise Unavailable("instance profile identifiers unavailable")\n'
                '    return profile\n'
                '\n'
                '\n'
                '@install("aws.claude_a.ec2.instance_profile_attached", "instance", "EC2 instance has an IAM instance profile",\n'
            ),
        ),
        (
            (
                'def inst_profile(item, index):\n'
                '    profile = _profile(item)\n'
                '    return result(profile is None, instance_profile=(profile or {}).get("Arn"))\n'
            ),
            (
                'def inst_profile(item, index):\n'
                '    profile = _validated_profile(item)\n'
                '    return result(profile is None, instance_profile=(profile or {}).get("Arn"))\n'
            ),
        ),
        (
            (
                '        return na\n'
                '    profile = _profile(item)\n'
                '    return result(profile is None, instance_profile=(profile or {}).get("Arn"))\n'
            ),
            (
                '        return na\n'
                '    profile = _validated_profile(item)\n'
                '    return result(profile is None, instance_profile=(profile or {}).get("Arn"))\n'
            ),
        ),
        (
            (
                '        return "NOT_APPLICABLE", {"reason": "instance has no public IPv4"}\n'
                '    return result(_profile(item) is None, public_ip=ip)\n'
                '\n'
            ),
            (
                '        return "NOT_APPLICABLE", {"reason": "instance has no public IPv4"}\n'
                '    return result(_validated_profile(item) is None, public_ip=ip)\n'
                '\n'
            ),
        ),
        (
            (
                'def _world_range(rule, protocols):\n'
                '    v4 = [r.get("CidrIp") for r in list_of_objects(get(rule, "IpRanges", list))]\n'
                '    v6 = [r.get("CidrIpv6") for r in list_of_objects(get(rule, "Ipv6Ranges", list))]\n'
                '    if not any(isinstance(c, str) and is_cidr_public(c) for c in v4 + v6):\n'
                '        return None\n'
                '    proto = get(rule, "IpProtocol", str)\n'
                '    if proto == "-1":\n'
                '        return "all"\n'
                '    if proto not in protocols:\n'
                '        return None\n'
                '    low, high = rule.get("FromPort"), rule.get("ToPort")\n'
                '    if low is None or high is None:\n'
                '        return None\n'
                '    if low == 0 and high == 65535:\n'
            ),
            (
                'def _world_range(rule, protocols):\n'
                '    from .claude_aws_a_common import _sg_protocol, _sg_bounds, _rule_ranges\n'
                '    from ipaddress import ip_network\n'
                '    v4, v6 = _rule_ranges(rule)\n'
                '    for version, ranges in ((4, v4), (6, v6)):\n'
                '        for cidr in ranges:\n'
                '            try:\n'
                '                if ip_network(cidr).version != version:\n'
                '                    raise ValueError("address family mismatch")\n'
                '            except ValueError as exc:\n'
                '                raise Unavailable("malformed enclave security-group CIDR") from exc\n'
                '    if not any(is_cidr_public(c) for c in v4 + v6):\n'
                '        return None\n'
                '    proto = _sg_protocol(get(rule, "IpProtocol", str))\n'
                '    bounds = _sg_bounds(rule, proto)\n'
                '    if proto == "-1":\n'
                '        return "all"\n'
                '    if proto not in {_sg_protocol(value) for value in protocols}:\n'
                '        return None\n'
                '    low, high = bounds\n'
                '    if low == 0 and high == 65535:\n'
            ),
        ),
        (
            (
                'LT_INST = w(INST, Tags=[{"Key": "aws:ec2launchtemplate:id", "Value": "lt-1"}],\n'
                '            LaunchTemplateData={"NetworkInterfaces": [{"DeviceIndex": 0, "AssociatePublicIpAddress": False}]})\n'
                '\n'
            ),
            (
                'LT_INST = w(INST, Tags=[{"Key": "aws:ec2launchtemplate:id", "Value": "lt-1"}],\n'
                '            LaunchTemplateData={"NetworkInterfaces": [{"AssociatePublicIpAddress": False}],\n'
                '                "InstanceId": INST["InstanceId"], "collection_status": "collected", "NetworkInterfacesComplete": True,\n'
                '                "_provenance": {"profile": "aws-launch-template-instance-network-metadata-v1",\n'
                '                    "source_operation": "ec2:GetLaunchTemplateData", "region": REGION, "read_only": True}})\n'
                '\n'
            ),
        ),
        (
            (
                '    index=idx(instance=[LT_INST, w(LT_INST, InstanceId="i-2", Tags=[{"Key": "aws:ec2launchtemplate:id", "Value": "lt-2"}],\n'
                '                                   LaunchTemplateData={"NetworkInterfaces": [{"DeviceIndex": 0, "AssociatePublicIpAddress": True}]})]),\n'
                '    rows=[C + "ec2_launch_template_not_publicly_accessible", C + "foundational_security_ec2_25"], severity="high", category="exposure", control="SC-7",\n'
            ),
            (
                '    index=idx(instance=[LT_INST, w(LT_INST, InstanceId="i-2", Tags=[{"Key": "aws:ec2launchtemplate:id", "Value": "lt-2"}],\n'
                '                                   LaunchTemplateData__InstanceId="i-2",\n'
                '                                   LaunchTemplateData__NetworkInterfaces=[{"AssociatePublicIpAddress": True}])]),\n'
                '    rows=[C + "ec2_launch_template_not_publicly_accessible", C + "foundational_security_ec2_25"], severity="high", category="exposure", control="SC-7",\n'
            ),
        ),
        (
            (
                '        return "NOT_APPLICABLE", {"reason": "no instance launched from this template"}\n'
                '    for inst in tagged:\n'
                '        data = get(inst, "LaunchTemplateData", dict)\n'
                '        for nic in list_of_objects(optional(data, "NetworkInterfaces", [], list)):\n'
                '            if nic.get("AssociatePublicIpAddress") is True:\n'
                '                return result(True, instance=inst.get("InstanceId"))\n'
                '    return result(False, instances=len(tagged))\n'
            ),
            (
                '        return "NOT_APPLICABLE", {"reason": "no instance launched from this template"}\n'
                '    incomplete = False\n'
                '    for inst in tagged:\n'
                '        try:\n'
                '            data = get(inst, "LaunchTemplateData", dict)\n'
                '            proof = get(data, "_provenance", dict)\n'
                '            if (get(data, "collection_status", str) != "collected"\n'
                '                    or get(data, "InstanceId", str) != get(inst, "InstanceId", str)\n'
                '                    or get(proof, "profile", str) != "aws-launch-template-instance-network-metadata-v1"\n'
                '                    or get(proof, "source_operation", str) != "ec2:GetLaunchTemplateData"\n'
                '                    or get(proof, "region", str) != region(index) or get(proof, "read_only", bool) is not True):\n'
                '                raise Unavailable("instance launch template data source binding unavailable")\n'
                '            nics = list_of_objects(get(data, "NetworkInterfaces", list))\n'
                '            flags = []\n'
                '            for nic in nics:\n'
                '                try:\n'
                '                    flags.append(get(nic, "AssociatePublicIpAddress", bool))\n'
                '                except Unavailable:\n'
                '                    incomplete = True\n'
                '            if any(flags):\n'
                '                return result(True, instance=inst.get("InstanceId"))\n'
                '            if get(data, "NetworkInterfacesComplete", bool) is not True:\n'
                '                incomplete = True\n'
                '        except Unavailable:\n'
                '            incomplete = True\n'
                '    if incomplete:\n'
                '        raise Unavailable("instance launch template network metadata incomplete")\n'
                '    return result(False, instances=len(tagged))\n'
            ),
        ),
        (
            (
                '    status = get(item, "Status", str)\n'
                '    attached = absent_or(item, "NetworkInterfaceId", "Attachment.InstanceId", None, str)\n'
            ),
            (
                '    status = get(item, "Status", str)\n'
                '    if status not in ("available", "associated", "attaching", "in-use", "detaching"):\n'
                '        raise Unavailable("unrecognized network interface status")\n'
                '    attached = absent_or(item, "NetworkInterfaceId", "Attachment.InstanceId", None, str)\n'
            ),
        ),
    ),
    # data-sdk-closure-review: exact tag values/exclusions and typed RDS/Redshift parameters.
    'claude_aws_b_db.py': (
        (
            (
                'def _tag_plan_index(resources, tag_keys):\n'
                '    return inventory("backup_plan", [{"BackupPlanId": "p", "Selections": {"collection_status": "collected", "items": [{"SelectionId": "s", "Selection": {"BackupSelection": {"Resources": resources, "ListOfTags": [{"ConditionType": "STRINGEQUALS", "ConditionKey": k, "ConditionValue": "v"} for k in tag_keys]}}}]}}])\n'
                '\n'
            ),
            (
                'def _tag_plan_index(resources, tag_keys):\n'
                '    return inventory("backup_plan", [{"BackupPlanId": "p", "Selections": {"collection_status": "collected", "items": [{"SelectionId": "s", "Selection": {"BackupSelection": {"Resources": resources, "ListOfTags": [{"ConditionType": "STRINGEQUALS", "ConditionKey": k, "ConditionValue": "yes"} for k in tag_keys]}}}]}}])\n'
                '\n'
            ),
        ),
        (
            (
                '    arn = get(item, "DBInstanceArn", str)\n'
                '    tags = {get(t, "Key", str) for t in list_of_objects(absent_or(item, "DBInstanceArn", "TagList", [], list))}\n'
                '    resources, keys = [], set()\n'
                '    for plan in complete_items(index, "backup_plan"):\n'
            ),
            (
                '    arn = get(item, "DBInstanceArn", str)\n'
                '    tags = {}\n'
                '    for tag in list_of_objects(absent_or(item, "DBInstanceArn", "TagList", [], list)):\n'
                '        key, value = get(tag, "Key", str), get(tag, "Value", str)\n'
                '        if key in tags:\n'
                '            raise Unavailable("ambiguous duplicate RDS resource tag")\n'
                '        tags[key] = value\n'
                '    resources, selected_tags = [], []\n'
                '    for plan in complete_items(index, "backup_plan"):\n'
            ),
        ),
        (
            (
                '            body = get(selection, "Selection.BackupSelection", dict)\n'
                '            resources += strings(optional(body, "Resources", [], list))\n'
                '            keys |= {get(t, "ConditionKey", str) for t in list_of_objects(optional(body, "ListOfTags", [], list))}\n'
                '    hit = arn in resources or bool(tags & keys)\n'
                '    return result(not hit, resource_arn=arn, selection_or_tag_key_match=hit, matched_tag_keys=sorted(tags & keys))\n'
                '\n'
            ),
            (
                '            body = get(selection, "Selection.BackupSelection", dict)\n'
                '            if optional(body, "NotResources", [], list) or optional(body, "Conditions", {}, dict):\n'
                '                raise Unavailable("backup selection exclusions or conditions require separate matching proof")\n'
                '            resources += strings(optional(body, "Resources", [], list))\n'
                '            for condition in list_of_objects(optional(body, "ListOfTags", [], list)):\n'
                '                if get(condition, "ConditionType", str) != "STRINGEQUALS":\n'
                '                    raise Unavailable("unsupported backup ListOfTags condition")\n'
                '                selected_tags.append((get(condition, "ConditionKey", str), get(condition, "ConditionValue", str)))\n'
                '    matched = sorted({key for key, value in selected_tags if key in tags and tags[key] == value})\n'
                '    hit = arn in resources or bool(matched)\n'
                '    return result(not hit, resource_arn=arn, selection_or_tag_key_match=hit, matched_tag_keys=matched)\n'
                '\n'
            ),
        ),
        (
            (
                '                return result(not enabled, parameter=param, value=value)\n'
                '            return result(values.get(param) != "1", parameter=param, value=values.get(param))\n'
                '    _param_check(_cid, _row, _test, _param, _rem)\n'
            ),
            (
                '                return result(not enabled, parameter=param, value=value)\n'
                '            value = _rds_parameter_text(values, param)\n'
                '            if value not in {"0", "1"}:\n'
                '                raise Unavailable("unrecognized RDS force_ssl parameter")\n'
                '            return result(value != "1", parameter=param, value=value)\n'
                '    _param_check(_cid, _row, _test, _param, _rem)\n'
            ),
        ),
        (
            (
                '    values = get(item, "ParameterGroupValues", dict)\n'
                '    value = values.get("require_ssl")\n'
                '    return result(not (isinstance(value, str) and value.lower() == "true"), require_ssl=value)\n'
                '\n'
            ),
            (
                '    values = get(item, "ParameterGroupValues", dict)\n'
                '    value = get(values, "require_ssl", str)\n'
                '    if value.lower() not in {"true", "false"}:\n'
                '        raise Unavailable("unrecognized Redshift require_ssl parameter")\n'
                '    return result(value.lower() != "true", require_ssl=value)\n'
                '\n'
            ),
        ),
    ),
    # identity-sdk-closure-review: bind the flagged managed default to its unique version ID.
    'compliance_new_sw40.py': (
        (
            (
                'from .aws_all_policies import scan as _customer_policy_scan\n'
                'from .facts import Unavailable, complete_items, get, optional\n'
                '\n'
            ),
            (
                'from .aws_all_policies import scan as _customer_policy_scan\n'
                'from .facts import Unavailable, complete_items, get, optional, list_of_objects\n'
                '\n'
            ),
        ),
        (
            (
                '        raise Unavailable("foreign or malformed managed-policy ARN")\n'
                '    versions = get(row, "PolicyVersionList", list)\n'
                '    defaults = [v for v in versions if isinstance(v, dict) and get(v, "IsDefaultVersion", bool)]\n'
                '    if len(defaults) != 1:\n'
                '        raise Unavailable("exactly one default policy version required")\n'
                '    return arn, _document(get(defaults[0], "Document"))\n'
            ),
            (
                '        raise Unavailable("foreign or malformed managed-policy ARN")\n'
                '    versions = list_of_objects(get(row, "PolicyVersionList", list)); version_id = get(row, "DefaultVersionId", str)\n'
                '    version_ids = [get(v, "VersionId", str) for v in versions]; defaults = [v for v in versions if get(v, "IsDefaultVersion", bool)]\n'
                '    if not version_id or any(not v for v in version_ids) or len(set(version_ids)) != len(version_ids) or len(defaults) != 1 or get(defaults[0], "VersionId", str) != version_id:\n'
                '        raise Unavailable("exactly one matching default policy version required")\n'
                '    return arn, _document(get(defaults[0], "Document"))\n'
            ),
        ),
    ),
    # workload-resource-followup-review; test_aws_lambda_role_policy_review_20261019: native IAM declarations replace a synthetic effective-admin flag.
    'compliance_new_sw41.py': (
        (
            (
                'def _admin(item,index):\n'
                '    arn,role=_role(item,index)\n'
                '    # This fact must be derived from complete identity policy documents, boundaries,\n'
                '    # session/SCP constraints and explicit Deny, not merely attachment names.\n'
                "    analysis=get(role,'EffectiveAdminAccess',dict)\n"
                "    if get(analysis,'collection_status',str)!='collected' or get(analysis,'role_arn',str)!=get(role,'Arn',str) or get(analysis,'complete',bool) is not True:\n"
                "        raise Unavailable('effective role policy analysis incomplete')\n"
                "    admin=get(analysis,'unconditional_action_resource_star',bool)\n"
                "    return result(admin,function_arn=arn,role_arn=get(role,'Arn',str), unconditional_admin=admin)\n"
                '\n'
            ),
            (
                'def _admin(item,index):\n'
                '    from fnmatch import fnmatchcase\n'
                '    from .aws_a_facts import api_optional\n'
                '    from .aws_bedrock_review_20261019 import _documents, _policy_document\n'
                '    from .aws_lambda_role_policy_review_20261019 import _attached_defaults, _iam_inventory\n'
                '    from .facts import optional\n'
                '\n'
                '    arn,role=_role(item,index)\n'
                "    account=_scope(index).split('/')[0]\n"
                "    partition=arn.split(':')[1]\n"
                "    role_arn=get(role,'Arn',str)\n"
                "    if not role_arn.startswith('arn:'+partition+':iam::'+account+':role/'):\n"
                "        raise Unavailable('execution role partition mismatch')\n"
                "    _iam_inventory(index,'iam_role',account)\n"
                "    operation='iam:GetAccountAuthorizationDetails'\n"
                "    attachments=_objects(api_optional(role,'AttachedManagedPolicies',list,[],operation=operation))\n"
                "    attached_arns=[get(policy,'PolicyArn',str) for policy in attachments]\n"
                '    if len(attached_arns)!=len(set(attached_arns)) or any(\n'
                "            re.fullmatch(r'arn:'+re.escape(partition)+r':iam::(?:aws|'+account+r'):policy/.+',value) is None\n"
                '            for value in attached_arns):\n'
                "        raise Unavailable('managed policy attachment identity unresolved')\n"
                '    # The signed predicate has an explicit AdministratorAccess attachment OR.\n'
                '    # This branch observes that declaration, not its effective permission set.\n'
                "    admin_arn='arn:'+partition+':iam::aws:policy/AdministratorAccess'\n"
                '    if admin_arn in attached_arns:\n'
                '        return result(True,function_arn=arn,role_arn=role_arn,administrator_access_attached=True,\n'
                "            branch='exact_aws_administratoraccess_attachment',\n"
                "            observed='Execution role has the exact AWS AdministratorAccess policy attached; effective permissions remain unassessed.')\n"
                '    if attached_arns:\n'
                "        policies=_iam_inventory(index,'iam_policy',account)\n"
                '        _attached_defaults(role,policies,account,partition)\n'
                "    documents=_documents(role,index,account,'RolePolicyList')\n"
                '    could_create_role=False\n'
                '    for document in documents:\n'
                "        statements=get(_policy_document(document),'Statement')\n"
                '        for statement in _objects([statements] if isinstance(statements,dict) else statements):\n'
                "            effect=get(statement,'Effect',str)\n"
                '            # Conditions/resources can only narrow a statement; ignoring them\n'
                '            # here deliberately overestimates whether this action is possible.\n'
                "            optional(statement,'Condition',None,dict)\n"
                "            for field in ('Resource','NotResource'):\n"
                '                optional(statement,field,None)\n'
                "            action=optional(statement,'Action',None)\n"
                "            not_action=optional(statement,'NotAction',None)\n"
                '            values=_actions(action if action is not None else not_action)\n'
                "            if any(re.fullmatch(r'(?:\\*|[A-Za-z0-9*?-]+:[A-Za-z0-9*?]+)',value) is None for value in values):\n"
                "                raise Unavailable('unsupported IAM action pattern')\n"
                "            matches=any(fnmatchcase('iam:createrole',value.lower()) for value in values)\n"
                "            if effect=='Allow' and (matches if action is not None else not matches):\n"
                '                could_create_role=True\n'
                '    if could_create_role:\n'
                "        return unknown('identity policies might allow iam:CreateRole; full effective administrator access requires additional evidence',\n"
                "            function_arn=arn,role_arn=role_arn,branch='effective_access_unresolved',\n"
                "            observed='Role policies could allow iam:CreateRole; boundaries, SCPs and other effective-access constraints are unassessed.')\n"
                '    # IAM CreateRole has no resource-based grants. Without an identity Allow\n'
                '    # for this necessary action, this role cannot have all direct actions.\n'
                '    # This says nothing about transitive assumption or privilege escalation.\n'
                "    return result(False,function_arn=arn,role_arn=role_arn,branch='necessary_direct_action_not_allowed',\n"
                "        observed='Complete role policies cannot Allow iam:CreateRole, ruling out full direct administrator access; escalation is unassessed.')\n"
                '\n'
            ),
        ),
        (
            (
                " 'aws_cis_lambda_database_secrets_manager':['lambda_function','iam_role','secret'],\n"
                " 'aws_cis_lambda_execution_role_no_admin':['lambda_function','iam_role'],\n"
                " 'aws.pci.vpc.approved_egress':['security_group'],\n"
            ),
            (
                " 'aws_cis_lambda_database_secrets_manager':['lambda_function','iam_role','secret'],\n"
                " 'aws_cis_lambda_execution_role_no_admin':['lambda_function','iam_role','iam_policy'],\n"
                " 'aws.pci.vpc.approved_egress':['security_group'],\n"
            ),
        ),
    ),
    # test_aws_beanstalk_runtime_metadata_review (classic SSL regressions);
    # services-closure-review: classic ELB SSL is a TLS listener protocol.
    'compliance_new_sw47.py': (
        (
            (
                '            protocol = get(listener, "Protocol", str)\n'
                '            if protocol in {"HTTPS", "TLS"}:\n'
                '                if kind == "classic":\n'
            ),
            (
                '            protocol = get(listener, "Protocol", str)\n'
                '            if protocol in {"HTTPS", "TLS"} or (kind == "classic" and protocol == "SSL"):\n'
                '                if kind == "classic":\n'
            ),
        ),
    ),
    # fe6f7901 (#104): the overlapping ElastiCache subnet id is retired as an
    # alias of its surviving Prowler-semantics native check.
    'claude2_aws_b_data.py': (
        (
            'from . import result, unknown\n',
            'from . import alias_check, result, unknown\n',
        ),
        (
            (
                '_ec_public("aws.c2b.elasticache.cluster_public_subnet", "ElastiCache cluster has no subnet routed to an internet gateway",\n'
                '    [C + "elasticache_cluster_no_public_subnet"], subnet_is_public_prowler,\n'
                '    "Semantic correction to pinned Steampipe SQL: its NAT default-route branch describes outbound access, not public ingress; classify only an effective 0.0.0.0/0 route to igw-.")\n'
            ),
            'alias_check("aws.c2b.elasticache.cluster_public_subnet", "aws.c2b.elasticache.cluster_public_subnet_prowler")\n',
        ),
    ),
    # a9d62a01: S3 ownership controls are decided only from collected detail.
    'claude_aws_a_s3.py': (
        (
            (
                '        return result(True, ownership=None)\n'
                '    rules = list_of_objects(get(controls, "OwnershipControls.Rules", list))\n'
            ),
            (
                '        return result(True, ownership=None)\n'
                '    if get(controls, "collection_status", str) != "collected":\n'
                '        raise Unavailable("ownership controls detail unavailable")\n'
                '    rules = list_of_objects(get(controls, "OwnershipControls.Rules", list))\n'
            ),
        ),
    ),
}

BY_ID={check.id:check for check in CHECKS}
FROZEN={}
for name in ('aws_bulk_clarity_reviewed.json.gz','aws_final_clarity_reviewed.json.gz'):
    FROZEN.update(json.loads(gzip.decompress((ROOT/'tests/fixtures'/name).read_bytes())))
for case in json.loads((ROOT/'tests/fixtures/post_dfaf_aws.json').read_text()):
    if case['name'] in ('pass','fail'):
        FROZEN.setdefault(case['id'],{})[case['expected']] = case


def _assert_original_source(name, text):
    record=PROOF[name]
    if name == 'claude_aws_a_ec2.py':
        assert text.count(ACCOUNT_GLOBAL_PARTITION_ADDENDUM) == 1
        text=text.replace(ACCOUNT_GLOBAL_PARTITION_ADDENDUM,'')
    for before, after in reversed(REVIEWED_NATIVE_SOURCE_DELTAS.get(name, ())):
        assert text.count(after) == 1, name
        text = text.replace(after, before, 1)
    assert hashlib.sha256(text.encode()).hexdigest()==record['current_sha256']
    for before,after in reversed(record['replacements']):
        assert after in text
        text=text.replace(after,before)
    assert hashlib.sha256(text.encode()).hexdigest()==record['original_sha256']


CORRECTED_NATIVE_SUCCESSORS = {'aws_cis_lambda_execution_role_no_admin'}


@pytest.mark.parametrize('branch,expected,deciding_branch', [
    ('narrow', 'PASS', 'necessary_direct_action_not_allowed'),
    ('aws_admin', 'FAIL', 'exact_aws_administratoraccess_attachment'),
    ('custom_star', 'UNKNOWN', 'effective_access_unresolved'),
    ('denied_role', 'UNKNOWN', None),
])
def test_corrected_lambda_alias_records_native_declarations_without_effective_access_claims(branch, expected, deciding_branch):
    # Independently specified native fixture for the accepted legacy contract:
    # docs/aws-review/workload-resource-followup-review.{json,md} and
    # tests/test_aws_lambda_role_policy_review_20261019.py. A custom '*' Allow
    # cannot prove effective administrator access through boundaries and SCPs.
    account, scope = '123456789012', '123456789012/us-east-1'
    role_arn = f'arn:aws:iam::{account}:role/evidence-review'
    item = {'FunctionName': 'evidence-review',
            'FunctionArn': f'arn:aws:lambda:us-east-1:{account}:function:evidence-review',
            'Role': role_arn}
    role = {'RoleName': 'evidence-review', 'Arn': role_arn, 'AccountId': account,
            'RolePolicyList': [{'PolicyName': 'logging', 'PolicyDocument': {
                'Statement': [{'Effect': 'Allow', 'Action': '*' if branch == 'custom_star' else 'logs:CreateLogStream', 'Resource': '*'}]}}],
            'AttachedManagedPolicies': ([{'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'}]
                                        if branch == 'aws_admin' else []),
            '_provenance': {'operation': 'iam:GetAccountAuthorizationDetails', 'native_response_complete': True}}
    index = {'context': {'provider': 'aws', 'scope': scope, 'Account': account}, 'collections': {}}
    for kind, rows, global_type in [('lambda_function', [item], False), ('iam_role', [role], True), ('iam_policy', [], True)]:
        native_scope = account + '/global' if global_type else scope
        index['collections'][kind] = [{'type': kind, 'scope': native_scope, 'account_id': account,
                                      'global': global_type, 'status': 'collected' if rows else 'empty', 'items': rows}]
        index[kind] = [{'type': kind, 'scope': native_scope, 'data': row} for row in rows]
    if branch == 'denied_role':
        index['collections']['iam_role'][0]['status'] = 'denied'
    before = deepcopy((item, index))
    check = BY_ID['aws_cis_lambda_execution_role_no_admin']
    assert check.dependencies == ['lambda_function', 'iam_role', 'iam_policy']
    status, evidence = check.evaluate(item, index)
    assert status == expected, evidence
    assert (item, index) == before
    assert 'unconditional_admin' not in evidence
    assert 'EffectiveAdminAccess' not in json.dumps(index)
    if deciding_branch is not None:
        assert evidence['branch'] == deciding_branch
        assert evidence['function_arn'] == item['FunctionArn']
        assert evidence['role_arn'] == role_arn
        assert 'unassessed' in evidence['observed']
    if branch == 'aws_admin':
        assert evidence['administrator_access_attached'] is True


@pytest.mark.parametrize('cid',sorted(((set(CASES)|set(FROZEN))&set(AWS_FIELDS))-CORRECTED_NATIVE_SUCCESSORS))
def test_actual_evaluator_keeps_verdict_and_records_decisive_setting(cid):
    cases=CASES.get(cid,{});check=BY_ID[cid]
    for state in ('pass','fail'):
        if cid in FROZEN:
            frozen=FROZEN[cid][state.upper()];item,index=deepcopy((frozen['item'],frozen['index']))
        else:
            assert state in cases, (cid, state)
            case=cases[state];index=deepcopy(case.get('index',{}))
            # Native CASES keep the raw item alongside their named index.
            index=deepcopy(cases.get(state+'_index',cases.get('index',index)))
            item=deepcopy(case.get('item',case))
        status,evidence=check.evaluate(item,index)
        assert status==state.upper(),(cid,state,status,evidence)
        # Some positive paths already carried a distinct match marker.
        if state == 'pass':
            positive_fields = AWS_FIELDS[cid] | {'matched', 'active_attachment', 'policy'}
            if cid == 'aws.pci.shield.protection_all_internet_resources':
                # Its unchanged PASS path records assessed resource counts;
                # global_cloudfront_scope is an additive FAIL-path witness.
                assert evidence['assessed'] == 0
                assert evidence['unprotected_resource_arns'] == []
                positive_fields |= {'assessed', 'unprotected_resource_arns'}
            assert set(evidence) & positive_fields, (cid, state, evidence)
