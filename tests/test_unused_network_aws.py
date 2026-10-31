from copy import deepcopy

import pytest

from peaso import unused_network_aws as subject
from peaso.checks import CHECKS
from peaso.unused_network_aws import sg_not_used
from peaso.checks.claude_aws_a_common import idx
from peaso.checks.claude_aws_a_ec2 import SG
from peaso.checks.facts import MemoIndex
from peaso.checks.fixtures import CASES
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

SCOPE = '123456789012/us-east-1'
NOW = '2026-10-21T12:00:00Z'


def installed():
    if not any(c.id == subject.SPECS[0][0] for c in CHECKS):
        import peaso.checks as registry
        subject.install(registry)


def snapshot(kind, item, status='collected'):
    return make_snapshot('aws', [SCOPE], [{'type': kind, 'scope': SCOPE, 'service': 'ec2',
        'status': status, 'items': [item]}], created_at=NOW)


@pytest.mark.parametrize('spec,evaluator', list(zip(subject.SPECS, (subject.route_table, subject.internet_gateway, subject.vpn_gateway))))
def test_bound_cases_and_real_engine(spec, evaluator):
    installed()
    cid, kind, *_ = spec
    check = next(c for c in CHECKS if c.id == cid)
    assert check.category == 'hardening' and check.dependencies == [kind]
    assert all(next(c for c in CHECKS if c.id == old).category == 'hardening' for old in subject.ROUTED_IDS)
    case = CASES[cid]
    for key, expected in [('pass', 'PASS'), ('fail', 'FAIL'), ('unknown', 'UNKNOWN'), ('missing', 'UNKNOWN'), ('malformed', 'UNKNOWN')]:
        assert check.evaluate(case[key], idx(**{kind: [case[key]]}))[0] == expected
        if key in ('pass', 'fail', 'unknown'):
            report = evaluate_snapshot(snapshot(kind, case[key]), categories=['hardening'], checks=[cid])
            assert report['findings'][0]['status'] == expected
            assert len(report['findings'][0]['evidence']['summary'].splitlines()) == 3
    report = evaluate_snapshot(make_snapshot('aws', [SCOPE], [], created_at=NOW), categories=['hardening'], checks=[cid])
    assert not any(f['status'] == 'FAIL' for f in report['findings'])


@pytest.mark.parametrize('association', [
    {'Main': True}, {'SubnetId': 'subnet-1'}, {'GatewayId': 'igw-1'},
])
def test_every_route_table_consumer(association):
    item = {'RouteTableId': 'rtb-1', 'Associations': [association]}
    assert subject.route_table(item, idx(route_table=[item]))[0] == 'PASS'


def test_positive_reference_survives_unrelated_malformed_association():
    item = {'InternetGatewayId': 'igw-1', 'Attachments': [{'_coverage': {'VpcId': {'status': 'denied'}}}, {'VpcId': 'vpc-1'}]}
    assert subject.internet_gateway(item, idx(internet_gateway=[item]))[0] == 'PASS'
    item['Attachments'] = item['Attachments'][:1]
    assert subject.internet_gateway(item, idx(internet_gateway=[item]))[0] == 'UNKNOWN'


def test_sg_egress_reference_and_partial_positive_and_absence_gate():
    target = {**SG, 'GroupId': 'sg-target'}
    other = {**SG, 'GroupId': 'sg-other', 'IpPermissionsEgress': [{'UserIdGroupPairs': [{'GroupId': 'sg-target'}]}]}
    index = idx(network_interface=[], lambda_function=[], batch_compute_environment=[], security_group=[target, other])
    assert sg_not_used(target, MemoIndex(index))[0] == 'PASS'
    partial = deepcopy(index)
    partial['collections']['security_group'][0]['status'] = 'partial'
    assert sg_not_used(target, MemoIndex(partial))[0] == 'PASS'
    partial['security_group'][1]['data']['IpPermissionsEgress'] = []
    with pytest.raises(ValueError):
        sg_not_used(target, MemoIndex(partial))
    assert sg_not_used(target, MemoIndex(index))[0] == 'PASS'
    index['security_group'][1]['data']['IpPermissionsEgress'] = []
    assert sg_not_used(target, MemoIndex(index))[0] == 'FAIL'


def test_missing_field_and_foreign_or_mismatched_source_never_fail():
    installed()
    item = {'RouteTableId': 'rtb-1', 'Associations': []}
    check = next(c for c in CHECKS if c.id == 'aws.network.route_table_associated')
    missing = {'RouteTableId': 'rtb-1'}
    assert check.evaluate(missing, idx(route_table=[missing]))[0] == 'UNKNOWN'
    foreign = idx(route_table=[item])
    foreign['context']['scope'] = '999999999999/us-east-1'
    assert check.evaluate(item, foreign)[0] == 'UNKNOWN'
    mismatch = idx(route_table=[item])
    mismatch['route_table'][0]['data'] = {'RouteTableId': 'rtb-2', 'Associations': []}
    assert check.evaluate(item, mismatch)[0] == 'UNKNOWN'
    partial = idx(route_table=[item])
    partial['collections']['route_table'][0]['status'] = 'partial'
    assert check.evaluate(item, partial)[0] == 'UNKNOWN'
    used = {'RouteTableId': 'rtb-1', 'Associations': [{'GatewayId': 'igw-1'}]}
    partial = idx(route_table=[used])
    partial['collections']['route_table'][0]['status'] = 'partial'
    assert check.evaluate(used, partial)[0] == 'PASS'


def test_positive_association_survives_unrelated_partial_projection():
    used = {'VpnGatewayId': 'vgw-1', 'VpcAttachments': [{'VpcId': 'vpc-1'}]}
    unrelated = {'VpnGatewayId': 'vgw-2', 'VpcAttachments': []}
    index = idx(vpn_gateway=[used, unrelated])
    index['collections']['vpn_gateway'][0]['status'] = 'partial'
    index['vpn_gateway'][1]['data'] = {'VpnGatewayId': 'vgw-2', 'VpcAttachments': [{'VpcId': 'vpc-2'}]}
    assert subject.vpn_gateway(used, index)[0] == 'PASS'
    installed()
    check = next(c for c in CHECKS if c.id == 'aws.network.vpn_gateway_attached')
    assert check.evaluate(unrelated, index)[0] == 'UNKNOWN'


def test_packaged_cases_carry_scoped_indexes_for_offline_evaluation():
    installed()
    for cid, *_ in subject.SPECS:
        check = next(c for c in CHECKS if c.id == cid)
        case = CASES[cid]
        for variant, expected in [('pass', 'PASS'), ('fail', 'FAIL'), ('unknown', 'UNKNOWN')]:
            assert check.evaluate(case[variant], case[variant + '_index'])[0] == expected


@pytest.mark.parametrize('state', ['attaching', 'detaching', 'detached', 'unrecognized'])
def test_gateway_transition_is_unresolved_not_an_attached_or_unused_verdict(state):
    item = {'VpnGatewayId': 'vgw-1', 'VpcAttachments': [{'VpcId': 'vpc-1', 'State': state}]}
    installed()
    check = next(c for c in CHECKS if c.id == 'aws.network.vpn_gateway_attached')
    assert check.evaluate(item, idx(vpn_gateway=[item]))[0] == 'UNKNOWN'
