"""Structural AWS network association checks over current native EC2 facts."""
from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path

from peaso.checks.facts import Unavailable, complete_items, get, guard, list_of_objects, optional
from peaso.checks.claude_aws_a_common import items
from peaso.checks import result

ROUTED_IDS = frozenset({
    'aws.claude_a.vpc.sg_in_use_anywhere',
    'aws.claude_a.vpc.nondefault_nacl_associated',
    'aws.claude_a.vpc.nacl_associated',
})
SPECS = (
    ('aws.network.route_table_associated', 'route_table', 'Route table has a main, subnet, or gateway association', 'Associations', 'RouteTableId', 'Review the route table and delete it if no VPC routing requires it.'),
    ('aws.network.internet_gateway_attached', 'internet_gateway', 'Internet gateway is attached to a VPC', 'Attachments', 'InternetGatewayId', 'Review the internet gateway and delete it if no VPC requires it.'),
    ('aws.network.vpn_gateway_attached', 'vpn_gateway', 'Virtual private gateway is attached to a VPC', 'VpcAttachments', 'VpnGatewayId', 'Review the virtual private gateway and delete it if no VPC requires it.'),
    ('aws.network.target_group_has_load_balancer', 'target_group', 'Target group has an associated load balancer', 'LoadBalancerArns', 'TargetGroupArn', 'Review the target group with its service owner before removing it; retain planned deployment and autoscaling dependencies.'),
)


def _current_source(item, index, kind, id_field):
    context = index.get('context', {})
    scope = context.get('scope')
    if (context.get('provider') != 'aws' or not isinstance(scope, str)
            or not re.fullmatch(r'[0-9]{12}/[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+', scope)):
        raise Unavailable('current AWS account/region scope is unavailable')
    ident = get(item, id_field, str)
    if not ident:
        raise Unavailable('native EC2 resource identity is empty')
    envelopes = index.get('collections', {}).get(kind)
    projections = index.get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1 or not isinstance(projections, list):
        raise Unavailable('unique native collection is unavailable: ' + kind)
    source = envelopes[0]
    if (not isinstance(source, dict) or source.get('type') != kind or source.get('scope') != scope
            or source.get('status') not in ('collected', 'partial') or not isinstance(source.get('items'), list)):
        raise Unavailable('current scoped native collection is unavailable: ' + kind)
    target_rows = [row for row in projections if isinstance(row, dict) and row.get('type') == kind
                   and row.get('scope') == scope and isinstance(row.get('data'), dict)
                   and row['data'].get(id_field) == ident]
    matches = [recorded for recorded in source['items'] if isinstance(recorded, dict)
               and recorded.get(id_field) == ident]
    if len(matches) != 1 or matches[0] != item or len(target_rows) != 1 or target_rows[0]['data'] != item:
        raise Unavailable('current native resource is absent, duplicated, or mismatched')
    projection_complete = len(projections) == len(source['items']) and all(
        isinstance(row, dict) and row.get('type') == kind and row.get('scope') == scope
        and row.get('data') == recorded for row, recorded in zip(projections, source['items']))
    return source, projection_complete


def _association(item, index, kind, field, id_field):
    """A valid known consumer wins; only a complete current item can prove absence."""
    source, projection_complete = _current_source(item, index, kind, id_field)
    values = get(item, field, list)
    unresolved = False
    consumers = []
    try:
        values = list_of_objects(values)
    except Unavailable:
        raise
    for value in values:
        try:
            guard(value)
            if field == 'Associations':
                main = optional(value, 'Main', False, bool)
                subnet = optional(value, 'SubnetId', None, str)
                gateway = optional(value, 'GatewayId', None, str)
                association_id = optional(value, 'RouteTableAssociationId', None, str)
                if main or subnet or gateway:
                    consumers.append({'main': main, 'subnet_id': subnet, 'gateway_id': gateway, 'association_id': association_id})
                else:
                    unresolved = True
            else:
                vpc = get(value, 'VpcId', str)
                state = value.get('State')
                if state is not None and state not in ('attached', 'available'):
                    unresolved = True
                    continue
                if not vpc:
                    unresolved = True
                else:
                    consumers.append({'vpc_id': vpc})
        except Unavailable:
            unresolved = True
    if consumers:
        return 'PASS', {'associations': consumers, 'association_count': len(consumers),
                        'summary': f'{kind.replace("_", " " ).capitalize()} has {len(consumers)} current native association(s).\nThe association is a structural consumer.\nTraffic activity was not assessed.'}
    if unresolved:
        raise Unavailable('association entries are incomplete or malformed')
    if source['status'] != 'collected' or not projection_complete:
        raise Unavailable('complete current native collection is required for absence')
    return 'FAIL', {'associations': [], 'association_count': 0,
                    'summary': f'{kind.replace("_", " " ).capitalize()} has no current native associations.\nThe complete scoped EC2 response records no structural consumer.\nTraffic activity was not assessed.'}


def _evaluate(item, index, kind, field, id_field):
    try:
        return _association(item, index, kind, field, id_field)
    except Unavailable as exc:
        reason = str(exc)
        return 'UNKNOWN', {'reason': reason, 'summary':
            f'{kind.replace("_", " ").capitalize()} association evidence is incomplete.\n{reason.rstrip(".")}.\nCurrent structural use could not be determined.'}


def route_table(item, index):
    return _evaluate(item, index, 'route_table', 'Associations', 'RouteTableId')


def internet_gateway(item, index):
    return _evaluate(item, index, 'internet_gateway', 'Attachments', 'InternetGatewayId')


def vpn_gateway(item, index):
    return _evaluate(item, index, 'vpn_gateway', 'VpcAttachments', 'VpnGatewayId')



def target_group(item, index):
    """Only report a missing ELB association, never global workload inactivity."""
    try:
        source, complete = _current_source(item, index, 'target_group', 'TargetGroupArn')
        scope = index['context']['scope']
        account, region = scope.split('/')
        prefix = rf'arn:(aws(?:-us-gov|-cn)?):elasticloadbalancing:{re.escape(region)}:{account}:'
        arn = get(item, 'TargetGroupArn', str)
        match = re.fullmatch(prefix + r'targetgroup/[^/]+/[0-9a-f]+', arn)
        if not match or source.get('service') != 'elbv2':
            raise Unavailable('target-group identity or ELB source does not match the current scope')
        arns = get(item, 'LoadBalancerArns', list)
        for value in arns:
            if (not isinstance(value, str) or not re.fullmatch(prefix + r'loadbalancer/(?:app|net|gwy)/[^/]+/[0-9a-f]+', value)
                    or value.split(':', 2)[1] != match.group(1)):
                raise Unavailable('load-balancer association ARN is malformed or outside the current account/region')
        if not arns and (source['status'] != 'collected' or not complete):
            raise Unavailable('complete current native target-group inventory is required for absence')
        status = 'PASS' if arns else 'FAIL'
        observation = f'{len(arns)} associated load balancer(s) are recorded.' if arns else 'No associated load balancer is recorded in the current ELB response.'
        return status, {'target_group_arn': arn, 'load_balancer_arns': arns,
            'summary': observation + '\nThis describes the current load-balancer association, not measured traffic use.\nReview deployment and autoscaling dependencies before removing the target group.'}
    except (Unavailable, KeyError, TypeError, ValueError) as exc:
        return 'UNKNOWN', {'reason': str(exc), 'summary': 'Target-group load-balancer associations could not be determined.\n' + str(exc).rstrip('.') + '.\nMissing or incomplete inventory does not establish an unused target group.'}


def sg_not_used(item, index):
    gid, name = get(item, "GroupId", str), get(item, "GroupName", str)
    if name == "default":
        return "NOT_APPLICABLE", {"reason": "default groups cannot be deleted"}
    unresolved = []
    # A positive reference is decisive even when another dependency collection
    # is partial. Absence requires every declared dependency to be complete.
    for kind in ("network_interface", "lambda_function", "batch_compute_environment", "security_group"):
        envelopes = index.get("collections", {}).get(kind, [])
        projections = index.get(kind, [])
        scope = index.get("context", {}).get("scope")
        if (not envelopes or not isinstance(projections, list) or not isinstance(scope, str)
                or any(not isinstance(envelope, dict) or envelope.get("type") != kind
                       or envelope.get("scope") != scope for envelope in envelopes)):
            unresolved.append(Unavailable("scoped dependency not collected: " + kind))
            continue
        for projection in projections:
            try:
                if (not isinstance(projection, dict) or projection.get("type") != kind
                        or projection.get("scope") != scope):
                    raise Unavailable("malformed scoped dependency projection: " + kind)
                other = get(projection, "data", dict)
                if kind == "network_interface":
                    for group in list_of_objects(get(other, "Groups", list)):
                        if get(group, "GroupId", str) == gid:
                            return result(False, used_by="network_interface")
                elif kind == "lambda_function":
                    config = optional(other, "VpcConfig", {}, dict)
                    if gid in optional(config, "SecurityGroupIds", [], list):
                        return result(False, used_by="lambda_function")
                elif kind == "batch_compute_environment":
                    config = optional(other, "computeResources", {}, dict)
                    if gid in optional(config, "securityGroupIds", [], list):
                        return result(False, used_by="batch_compute_environment")
                else:
                    for direction in ("IpPermissions", "IpPermissionsEgress"):
                        for rule in list_of_objects(optional(other, direction, [], list)):
                            for pair in list_of_objects(optional(rule, "UserIdGroupPairs", [], list)):
                                if get(pair, "GroupId", str) == gid:
                                    return result(False, used_by="security_group_reference",
                                                  direction="egress" if direction == "IpPermissionsEgress" else "ingress")
            except Unavailable as exc:
                unresolved.append(exc)
    if unresolved:
        raise unresolved[0]
    for kind in ("network_interface", "lambda_function", "batch_compute_environment", "security_group"):
        complete_items(index, kind)
    return result(True, group_id=gid, recognized_reference_found=False)


def _security_group(item, index):
    try:
        status, evidence = sg_not_used(item, index)
        if status in ('PASS', 'FAIL'):
            gid = item.get('GroupId', 'Security group')
            observation = ('A current '+str(evidence.get('used_by', 'network'))+' reference was captured.' if status == 'PASS' else 'No reference was captured in complete ENI, Lambda, Batch and security-group rule inventories.')
            evidence['summary'] = f'{gid}: {observation}\nBoth ingress and egress security-group references are considered.\nReview ownership before retiring a group; traffic inactivity is not measured.'
        return status, evidence
    except (Unavailable, ValueError, TypeError, KeyError) as exc:
        return 'UNKNOWN', {'reason': str(exc), 'summary': 'Security-group references are unresolved.\nThe required current reference inventory is incomplete or malformed.\nMissing data cannot establish that the group is unused.'}


def install(registry):
    from peaso.checks.fixtures import CASES
    raw = Path(__file__).with_name('checks').joinpath('unused_network_aws_cases.json').read_bytes()
    cases = json.loads(raw)
    if set(cases) != {spec[0] for spec in SPECS}:
        raise ValueError('AWS unused-network native case IDs changed')
    by_id = {check.id: check for check in registry.CHECKS}
    missing = ROUTED_IDS - by_id.keys()
    if missing:
        raise ValueError('AWS unused-network routing refers to missing controls: ' + ', '.join(sorted(missing)))
    if any(by_id[cid].category not in ('network', 'hardening') for cid in ROUTED_IDS):
        raise ValueError('AWS unused-network predecessor category changed')
    registry.CHECKS[:] = [replace(check, category='hardening') if check.id in ROUTED_IDS else check
                         for check in registry.CHECKS]
    registry.CHECKS[:] = [replace(check, evaluate=_security_group, allow_incomplete_failure=True) if check.id == 'aws.claude_a.vpc.sg_in_use_anywhere' else check for check in registry.CHECKS]
    from peaso.checks import catalog
    previous_description = catalog.description_for
    def description_for(ident):
        description = previous_description(ident)
        if ident != 'aws.claude_a.vpc.sg_in_use_anywhere':
            return description
        return {**description,
            'description': 'Reviews current non-default security-group references in complete scoped ENI, Lambda, Batch and security-group inventories, including both ingress and egress group rules. This is structural configuration evidence, not measured traffic inactivity.',
            'evaluated': ['same-scope ENI security groups, Lambda VPC groups and Batch compute-resource groups', 'other security-group ingress and egress references', 'complete dependency inventory before reporting no recognized reference'],
            'pass_when': 'A captured scoped network declaration references this group.',
            'fail_when': 'Complete supported reference inventories contain no recognized consumer of this non-default group.'}
    catalog.description_for = description_for
    CASES.update(cases)
    for spec, evaluate in zip(SPECS, (route_table, internet_gateway, vpn_gateway, target_group)):
        cid, kind, title, _, _, remediation = spec
        registry.register(cid, 'aws', 'hardening', kind, title, 'low', 'CM-7', remediation,
            dependencies=(kind,), allow_incomplete_failure=True)(evaluate)
