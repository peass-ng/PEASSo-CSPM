"""Offline network review and SDK-to-native regressions; no cloud connections.

"""
from copy import deepcopy
from functools import lru_cache
from pathlib import Path

import pytest

from scripts import audit_aws_native_contracts as native
from scripts import audit_aws_field_producers as fields
from tests.test_peaso_collectors_aws import sdk, IDENTITY, ACCOUNT, REGION

ROOT = Path(__file__).resolve().parents[1]
KINDS = {'security_group', 'network_acl', 'route_table', 'subnet', 'network_interface', 'vpc'}
@lru_cache(maxsize=1)
def cohort():
    active = native.active_ids()
    return tuple(c for c in native.registry() if c.id in active and c.kind in KINDS)


@lru_cache(maxsize=1)
def cases():
    return native.behavior_module().CASES


def state_index(case, state):
    return deepcopy(case.get(state + '_index', case.get('case_indices', {}).get(state, case.get('index', {}))))


# Dict.get/optional derived joins are recorded explicitly in addition to the
# instrumented native accessor paths. These are source-reviewed, not all tested.
MANUAL_PATHS = {
    'security_group': ['GroupId', 'GroupName', 'VpcId', 'IpPermissions[].IpProtocol', 'IpPermissions[].FromPort', 'IpPermissions[].ToPort', 'IpPermissions[].IpRanges[].CidrIp', 'IpPermissions[].Ipv6Ranges[].CidrIpv6', 'IpPermissions[].UserIdGroupPairs[].GroupId', 'IpPermissionsEgress[].IpRanges[].CidrIp'],
    'network_acl': ['NetworkAclId', 'IsDefault', 'Associations[].SubnetId', 'Entries[].RuleNumber', 'Entries[].Egress', 'Entries[].RuleAction', 'Entries[].Protocol', 'Entries[].CidrBlock', 'Entries[].Ipv6CidrBlock', 'Entries[].PortRange.From', 'Entries[].PortRange.To', 'Entries[].IcmpTypeCode.Type', 'Entries[].IcmpTypeCode.Code'],
    'route_table': ['RouteTableId', 'VpcId', 'Associations[].Main', 'Associations[].SubnetId', 'Routes[].DestinationCidrBlock', 'Routes[].DestinationIpv6CidrBlock', 'Routes[].GatewayId', 'Routes[].NatGatewayId'],
    'subnet': ['SubnetId', 'VpcId', 'AvailabilityZone', 'MapPublicIpOnLaunch'],
    'network_interface': ['NetworkInterfaceId', 'VpcId', 'SubnetId', 'Groups[].GroupId', 'Groups[].GroupName', 'InterfaceType', 'SourceDestCheck', 'Association.PublicIp', 'Attachment.InstanceId', 'Attachment.InstanceOwnerId', 'Status'],
    'vpc': ['VpcId', 'OwnerId', 'DhcpOptionsId'],
}


def test_all_reviewed_kind_paths_are_native_sdk_members():
    from peaso.collectors import aws
    models = fields.Models()
    for kind, paths in MANUAL_PATHS.items():
        service, operation, expression = aws.SPECS[kind]
        shape = fields.shape_at(models.output(service, operation), expression)
        assert kind not in aws.FETCHERS
        if kind == 'vpc':
            from peaso.collectors.aws_network_inventory import vpc_dns_attributes
            assert aws.ENRICHERS[kind] is vpc_dns_attributes
        else:
            assert kind not in aws.ENRICHERS
        assert all(fields.shape_at(shape, path) is not None for path in paths)
    permission = models.session.get_service_model('ec2').shape_for('IpPermission')
    assert not {'IpRanges', 'Ipv6Ranges'} & set(permission.required_members)


@pytest.mark.parametrize('protocol,low,high', [('icmp', -1, -1), ('1', 8, 0), ('icmpv6', 128, -1), ('58', 128, 0)])
def test_icmp_type_and_code_are_independent_values(protocol, low, high):
    from peaso.checks import claude_aws_a_network as n
    from peaso.checks.claude_aws_a_common import prowler_sg_open
    assert prowler_sg_open(n.world_rule(protocol, low, high), '-1', all_ports=True, any_address=True)
    assert not prowler_sg_open(n.world_rule(protocol, low, high), 'tcp', [22], any_address=True)


@pytest.mark.parametrize('protocol,low,high', [('icmp', -1, 0), ('1', 256, 0), ('icmpv6', 128, -2), ('58', 128, 256)])
def test_malformed_icmp_type_code_never_passes(protocol, low, high):
    from peaso.checks import claude_aws_a_network as n
    check = next(c for c in cohort() if c.id == 'aws.claude_a.vpc.sg_no_world_ssh')
    assert check.evaluate(n.sg_with(n.world_rule(protocol, low, high)), n.idx(**n.IN_USE))[0] == 'UNKNOWN'


@pytest.mark.parametrize('field,value', [('IpRanges', [{'CidrIp': '::/0'}]), ('Ipv6Ranges', [{'CidrIpv6': '0.0.0.0/0'}]), ('IpRanges', [{'CidrIp': 'garbage'}])])
def test_malformed_cidr_and_family_never_passes(field, value):
    from peaso.checks import claude_aws_a_network as n
    row = n.world_rule('6', 443, 443)
    row[field] = value
    check = next(c for c in cohort() if c.id == 'aws.claude_a.vpc.sg_no_world_ssh')
    assert check.evaluate(n.sg_with(row), n.idx(**n.IN_USE))[0] == 'UNKNOWN'


def test_optional_range_array_omission_is_conservative_unknown():
    from peaso.checks import claude_aws_a_network as n
    row = n.world_rule('6', 443, 443)
    del row['Ipv6Ranges']
    check = next(c for c in cohort() if c.id == 'aws.claude_a.vpc.sg_no_world_ssh')
    assert check.evaluate(n.sg_with(row), n.idx(**n.IN_USE))[0] == 'UNKNOWN'


@pytest.mark.parametrize('check', cohort(), ids=lambda c: c.id)
def test_each_predicate_witness_and_unavailable_inputs(check):
    case = cases()[check.id]
    for state, expected in [('pass', 'PASS'), ('fail', 'FAIL'), ('unknown', 'UNKNOWN')]:
        if state in case:
            data, index = deepcopy(case[state]), state_index(case, state)
            before = deepcopy((data, index))
            assert check.evaluate(data, index)[0] == expected
            assert (data, index) == before
    for data in [case.get('missing', {}), case.get('malformed'), {'collection_status': 'denied'}]:
        assert check.evaluate(deepcopy(data), state_index(case, 'pass'))[0] == 'UNKNOWN'


@pytest.mark.parametrize('check', cohort(), ids=lambda c: c.id)
@pytest.mark.parametrize('status', ['denied', 'partial', 'not_collected', 'malformed'])
def test_engine_empty_incomplete_subject_never_passes(check, status):
    from peaso.engine import evaluate_snapshot
    from peaso.snapshot import make_snapshot
    snap = make_snapshot('aws', [ACCOUNT + '/' + REGION], [{'type': kind, 'scope': ACCOUNT + '/' + REGION,
                         'service': 'ec2', 'status': status, 'items': []} for kind in {check.kind, *check.dependencies}])
    findings = evaluate_snapshot(snap, checks=[check.id])['findings']
    assert findings and all(f['status'] != 'PASS' for f in findings)


def collect_sdk(sdk, payloads):
    from peaso.collectors import aws
    _, add, _ = sdk
    add('sts').add_response('get_caller_identity', IDENTITY, {})
    ec2 = add('ec2')
    for kind, row in sorted(payloads.items()):
        _, operation, expression = aws.SPECS[kind]
        ec2.add_response(operation, {expression: [row]}, {})
        if kind == 'vpc':
            for attribute, output in [('enableDnsSupport', 'EnableDnsSupport'),
                                      ('enableDnsHostnames', 'EnableDnsHostnames')]:
                ec2.add_response('describe_vpc_attribute',
                                 {'VpcId': row['VpcId'], output: {'Value': True}},
                                 {'VpcId': row['VpcId'], 'Attribute': attribute})
    return aws.collect({'provider': 'aws', 'scopes': [ACCOUNT], 'options': {'regions': [REGION], 'service_concurrency': 1, 'retry_attempts': 1}}, list(payloads))


@pytest.mark.parametrize('kind', sorted(KINDS))
def test_sdk_network_kind_projection_and_consumer(sdk, kind):
    from peaso.checks import claude_aws_a_network as net
    from peaso.engine import evaluate_snapshot
    examples = {'vpc': (net.VPC, 'aws.claude_a.vpc.vpc_has_subnets'),
                'subnet': (net.SUBNET, 'aws.claude_a.vpc.subnet_no_auto_public_ip'),
                'route_table': (net.RTB_MAIN, 'aws.claude_a.vpc.route_table_no_default_igw_route'),
                'security_group': (net.SG, 'aws.ec2.restrict_internet_ingress'),
                'network_acl': (net.NACL, 'aws.claude_a.vpc.nacl_no_world_tcp_22'),
                'network_interface': (net.ENI, 'aws.claude_a.ec2.eni_source_dest_check')}
    row, cid = examples[kind]
    payload = {kind: deepcopy(row)}
    if kind == 'vpc':
        payload['subnet'] = deepcopy(net.SUBNET)
    snap = collect_sdk(sdk, payload)
    env = next(e for e in snap['collections'] if e['type'] == kind and e['status'] == 'collected')
    item, = env['items']
    assert all(item[key] == value for key, value in row.items())
    if kind == 'vpc':
        assert item['NetworkDnsAttributes'] == [
            {'VpcId': row['VpcId'], 'EnableDnsSupport': {'Value': True}},
            {'VpcId': row['VpcId'], 'EnableDnsHostnames': {'Value': True}},
        ]
        assert all(item['_coverage'][key]['status'] == 'collected'
                   for key in ('enableDnsSupport', 'enableDnsHostnames'))
    expected = 'FAIL' if kind == 'security_group' else 'PASS'  # SG declares world HTTPS.
    assert evaluate_snapshot(snap, checks=[cid])['findings'][0]['status'] == expected


@pytest.mark.parametrize('protocol,low,high,expected', [
    ('tcp', 22, 22, 'FAIL'), ('6', 22, 22, 'FAIL'), ('6', 443, 443, 'PASS'),
    ('udp', 22, 22, 'PASS'), ('17', 22, 22, 'PASS'), ('-1', None, None, 'FAIL'),
    ('6', 0, 65535, 'FAIL'), ('6', 0, 0, 'PASS'), ('6', 65535, 65535, 'PASS'),
    ('6', 23, 22, 'UNKNOWN'), ('6', -1, 22, 'UNKNOWN'), ('6', 65536, 65537, 'UNKNOWN'),
    ('6', None, None, 'UNKNOWN'), ('oops', 22, 22, 'UNKNOWN'), ('256', 22, 22, 'UNKNOWN'),
    ('icmp', -1, -1, 'PASS'), ('1', -1, -1, 'PASS'), ('icmpv6', 128, 0, 'PASS'), ('58', 128, 0, 'PASS'),
])
def test_sdk_numeric_protocol_and_range_to_registered_ssh(sdk, protocol, low, high, expected):
    from peaso.checks import claude_aws_a_network as net
    from peaso.engine import evaluate_snapshot
    payload = {'security_group': net.sg_with(net.world_rule(protocol, low, high)), 'vpc': deepcopy(net.VPC), 'network_interface': deepcopy(net.ENI)}
    snap = collect_sdk(sdk, payload)
    report = evaluate_snapshot(snap, checks=['aws.claude_a.vpc.sg_no_world_ssh'])
    assert report['findings'][0]['status'] == expected


@pytest.mark.parametrize('protocol', ['udp', '17', 'tcp', '6'])
def test_sdk_any_port_customer_interface_named_numeric_equivalence(sdk, protocol):
    from peaso.checks import claude_aws_a_network as net
    from peaso.engine import evaluate_snapshot
    snap = collect_sdk(sdk, {'security_group': net.sg_with(net.world_rule(protocol, 443, 443)), 'vpc': deepcopy(net.VPC), 'network_interface': deepcopy(net.ENI)})
    assert evaluate_snapshot(snap, checks=['aws.claude_a.vpc.sg_no_world_any_port_on_customer_enis'])['findings'][0]['status'] == 'FAIL'


@pytest.mark.parametrize('kind', sorted(KINDS))
def test_sdk_denied_network_collection_cannot_pass(sdk, kind):
    from peaso.collectors import aws
    from peaso.engine import evaluate_snapshot
    _, add, _ = sdk
    add('sts').add_response('get_caller_identity', IDENTITY, {})
    add('ec2').add_client_error(aws.SPECS[kind][1], service_error_code='AccessDenied', http_status_code=403, expected_params={})
    snap = aws.collect({'provider': 'aws', 'scopes': [ACCOUNT], 'options': {'regions': [REGION], 'retry_attempts': 1}}, [kind])
    check = next(c for c in cohort() if c.kind == kind and c.target == 'resource')
    findings = evaluate_snapshot(snap, checks=[check.id])['findings']
    assert findings and all(f['status'] == 'DENIED' for f in findings)


@pytest.mark.parametrize('changes', [{'Protocol': 'oops'}, {'RuleAction': 'oops'}, {'PortRange': {'From': 23, 'To': 22}}, {'PortRange': {'From': 65536, 'To': 65537}}])
@pytest.mark.parametrize('suffix', ['nacl_no_world_tcp_22', 'nacl_no_world_remote_admin'])
def test_nacl_malformed_facts_are_unknown(changes, suffix):
    from peaso.checks import claude_aws_a_network as net
    row = net.nacl_entry('6', 22, 22)
    row.update(changes)
    check = next(c for c in cohort() if c.id == 'aws.claude_a.vpc.' + suffix)
    assert check.evaluate(net.nacl_with(row), deepcopy(net.NACL_INDEX))[0] == 'UNKNOWN'


@pytest.mark.parametrize('mode,expected', [('allow', 'FAIL'), ('earlier_deny', 'PASS'), ('later_deny', 'FAIL'),
    ('v4_deny_v6_allow', 'FAIL'), ('v6_deny_v4_allow', 'FAIL'), ('egress_only', 'PASS'), ('specific_source', 'PASS'),
    ('udp', 'PASS'), ('all_protocols', 'FAIL'), ('missing_ports', 'UNKNOWN'), ('reversed', 'UNKNOWN'), ('overflow', 'UNKNOWN')])
@pytest.mark.parametrize('suffix', ['nacl_no_world_tcp_22', 'nacl_no_world_remote_admin'])
def test_sdk_nacl_order_family_direction_and_intervals(sdk, mode, expected, suffix):
    from peaso.checks import claude_aws_a_network as n
    from peaso.engine import evaluate_snapshot
    row = n.nacl_entry('6', 22, 22)
    entries = [row]
    if mode in ('earlier_deny', 'later_deny'):
        entries.append(n.nacl_entry('6', 22, 22, action='deny', number=1 if mode == 'earlier_deny' else 200))
    if mode == 'v4_deny_v6_allow':
        entries = [n.nacl_entry('6', 22, 22, action='deny', number=1), n.nacl_entry('6', 22, 22, cidr='::/0')]
    if mode == 'v6_deny_v4_allow':
        entries = [n.nacl_entry('6', 22, 22, action='deny', number=1, cidr='::/0'), row]
    if mode == 'egress_only':
        row['Egress'] = True
    if mode == 'specific_source':
        row['CidrBlock'] = '8.8.8.8/32'
    if mode == 'udp':
        row['Protocol'] = '17'
    if mode == 'all_protocols':
        entries = [n.nacl_entry('-1')]
    if mode == 'missing_ports':
        del row['PortRange']
    if mode == 'reversed':
        row['PortRange'] = {'From': 23, 'To': 22}
    if mode == 'overflow':
        row['PortRange'] = {'From': 65536, 'To': 65537}
    item = dict(deepcopy(n.NACL), Entries=entries)
    snap = collect_sdk(sdk, {'network_acl': item})
    if suffix == 'nacl_no_world_remote_admin' and mode in ('earlier_deny', 'udp'):
        expected = 'FAIL'  # Individual-entry declaration question ignores order and includes UDP.
    assert evaluate_snapshot(snap, checks=['aws.claude_a.vpc.' + suffix])['findings'][0]['status'] == expected


def test_remote_admin_reversed_bounds_need_unknown():
    from peaso.checks import claude_aws_a_network as n
    check = next(c for c in cohort() if c.id == 'aws.claude_a.vpc.nacl_no_world_remote_admin')
    assert check.evaluate(n.nacl_with(n.nacl_entry('6', 23, 22)), {})[0] == 'UNKNOWN'


@pytest.mark.parametrize('protocol', ['6', '17'])
def test_literal_protocol_filter_numeric_equivalence(protocol):
    from peaso.checks import claude_aws_a_network as n
    check = next(c for c in cohort() if c.id == 'aws.claude_a.vpc.sg_world_v4_no_tcp_udp')
    assert check.evaluate(n.sg_with(n.world_rule(protocol, 443, 443)), {})[0] == 'FAIL'


@pytest.mark.parametrize('protocol,expected', [('6', 'FAIL'), ('tcp', 'FAIL'), ('17', 'FAIL'), ('udp', 'FAIL'), ('-1', 'FAIL'), ('icmp', 'PASS')])
def test_sdk_literal_protocol_filter_native_names_numbers(sdk, protocol, expected):
    from peaso.checks import claude_aws_a_network as n
    from peaso.engine import evaluate_snapshot
    low, high = (-1, -1) if protocol == 'icmp' else (None, None) if protocol == '-1' else (443, 443)
    snap = collect_sdk(sdk, {'security_group': n.sg_with(n.world_rule(protocol, low, high))})
    assert evaluate_snapshot(snap, checks=['aws.claude_a.vpc.sg_world_v4_no_tcp_udp'])['findings'][0]['status'] == expected


@pytest.mark.parametrize('status,expected', [('available', 'FAIL'), ('associated', 'PASS'), ('attaching', 'PASS'), ('in-use', 'PASS'), ('detaching', 'PASS'), ('garbage', 'UNKNOWN')])
def test_sdk_eni_status_enum_and_optional_managed_attachment(sdk, status, expected):
    from peaso.checks import claude_aws_a_network as n
    from peaso.engine import evaluate_snapshot
    row = dict(deepcopy(n.ENI), Status=status)
    row.pop('Attachment', None)
    snap = collect_sdk(sdk, {'network_interface': row})
    assert evaluate_snapshot(snap, checks=['aws.claude_a.ec2.eni_in_use'])['findings'][0]['status'] == expected


@pytest.mark.parametrize('route,expected', [
    ({'DestinationCidrBlock': '0.0.0.0/0', 'GatewayId': 'igw-1'}, 'FAIL'),
    ({'DestinationCidrBlock': '0.0.0.0/0', 'GatewayId': 'igw-1', 'State': 'blackhole'}, 'FAIL'),
    ({'DestinationCidrBlock': '0.0.0.0/0', 'NatGatewayId': 'nat-1'}, 'PASS'),
    ({'DestinationCidrBlock': '10.0.0.0/16', 'GatewayId': 'local'}, 'PASS'),
    ({'DestinationIpv6CidrBlock': '::/0', 'GatewayId': 'igw-1'}, 'PASS'),
])
def test_sdk_ipv4_literal_route_scope_and_optional_non_igw_target(sdk, route, expected):
    from peaso.engine import evaluate_snapshot
    snap = collect_sdk(sdk, {'route_table': {'RouteTableId': 'rtb-1', 'Routes': [route]}})
    assert evaluate_snapshot(snap, checks=['aws.claude_a.vpc.route_table_no_default_igw_route'])['findings'][0]['status'] == expected


def test_eni_invalid_status_needs_unknown():
    check = next(c for c in cohort() if c.id == 'aws.claude_a.ec2.eni_in_use')
    assert check.evaluate({'NetworkInterfaceId': 'eni-1', 'Status': 'garbage'}, {})[0] == 'UNKNOWN'


@pytest.mark.parametrize('route', [
    {'DestinationCidrBlock': '0.0.0.0/0', 'GatewayId': {}},
    {'DestinationCidrBlock': {'collection_status': 'denied'}, 'GatewayId': 'igw-1'},
    {'DestinationCidrBlock': '0.0.0.0/0', 'GatewayId': 'igw-1', '_coverage': {'GatewayId': {'status': 'denied'}}},
])
def test_route_optional_native_fields_respect_types_and_coverage(route):
    check = next(c for c in cohort() if c.id == 'aws.claude_a.vpc.route_table_no_default_igw_route')
    assert check.evaluate({'RouteTableId': 'rtb-1', 'Routes': [route]}, {})[0] == 'UNKNOWN'


def test_intentional_literal_route_port_and_flowlog_distinctions():
    from peaso.checks import claude_aws_a_network as n
    by_id = {c.id: c for c in cohort()}
    def run(suffix, item, index=None):
        return by_id['aws.claude_a.vpc.' + suffix].evaluate(item, deepcopy(index or {}))[0]
    assert run('sg_world_v4_only_80_443', n.sg_with(n.world_rule('udp', 80, 80))) == 'PASS'
    ipv6 = {'RouteTableId': 'rtb-test', 'Routes': [{'DestinationIpv6CidrBlock': '::/0', 'GatewayId': 'igw-1'}]}
    assert run('route_table_no_default_igw_route', ipv6) == 'PASS'
    index = n.idx(network_interface=[n.ENI], flow_log=[dict(n.FLOW, FlowLogStatus='FAILED')])
    assert run('flow_logs_active', n.VPC, index) == 'FAIL'
    assert run('in_use_vpc_has_flow_log', n.VPC, index) == 'PASS'
    # Ordered deny stops the Prowler criterion; the literal individual-entry
    # remote-admin criterion deliberately still reports the allow declaration.
    item = n.nacl_with(n.nacl_entry('6', 22, 22, action='deny', number=1), n.nacl_entry('6', 22, 22, number=2))
    assert run('nacl_no_world_tcp_22', item) == 'PASS'
    assert run('nacl_no_world_remote_admin', item) == 'FAIL'
