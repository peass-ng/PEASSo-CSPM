"""Keep native configuration witnesses separate from observed listener claims.

These tests investigate the old signed listener contract without weakening it.
No guest execution, packet probes, cloud calls, or registry-module imports.
The existing separately selected Stubber integration validates the producer.
"""
from copy import deepcopy

import botocore.session
import pytest

from peaso.checks import CHECKS
from peaso.analysis.aws_public_ingress import DEPENDENCIES, MODEL, witness
from peaso.engine import evaluate_snapshot
from tests.test_peaso_aws_public_ingress_native import facts, snapshot, SCOPE

OLD = 'aws_nist_ec2_instance_not_publicly_accessible'
ALTERNATIVES = ['aws.nist.ec2_instance_effective_public_reachability',
                'aws_fedramp_ec2_effective_public_exposure']


def old_evaluate(rows, status='collected'):
    item = rows['instance'][0]
    index = {'context': {'provider': 'aws', 'scope': SCOPE},
             'collections': {'instance': [{'type': 'instance', 'scope': SCOPE,
                                           'status': status, 'items': rows['instance']}]},
             'instance': [{'type': 'instance', 'scope': SCOPE, 'data': row} for row in rows['instance']]}
    check = next(c for c in CHECKS if c.id == OLD)
    return check.evaluate(item, index)


def test_native_configuration_proof_does_not_claim_listener_or_closed_universe():
    snap = snapshot(facts())
    proof = witness(snap, SCOPE, 'i-12345678')
    assert proof['model'] == MODEL
    assert proof['application_listening'] == 'unknown'
    assert proof['network_probes'] is False
    assert proof['all_paths_evaluated'] is False
    assert proof['destination_port'] == 443
    assert 'ListeningPortVerified' not in proof
    assert {'security_group', 'network_acl', 'instance', 'network_interface', 'internet_gateway',
            'route_table', 'vpc_block_public_access_options'} <= {r['type'] for r in proof['native_evidence_refs']}


def test_supported_native_counterexample_fails_configuration_alternatives_only():
    rows = facts()
    report = evaluate_snapshot(snapshot(rows), checks=ALTERNATIVES)
    assert [f['status'] for f in report['findings']] == ['FAIL', 'FAIL']
    assert old_evaluate(rows)[0] == 'UNKNOWN'


def test_genuine_configuration_proof_cannot_be_relabelled_as_old_projection():
    rows = facts()
    proof = witness(snapshot(rows), SCOPE, 'i-12345678')
    rows['instance'][0]['PublicReachability'] = deepcopy(proof)
    assert old_evaluate(rows)[0] == 'UNKNOWN'


@pytest.mark.parametrize('mode', ['sg_closed', 'no_public_ipv4', 'ipv6_only', 'stopped', 'listenerless_same_config'])
def test_absent_configuration_counterexample_never_proves_old_contract_pass(mode):
    rows = facts()
    if mode == 'sg_closed':
        rows['security_group'][0]['IpPermissions'] = []
    if mode in ('no_public_ipv4', 'ipv6_only'):
        rows['instance'][0].pop('PublicIpAddress')
        for row in [rows['network_interface'][0], rows['instance'][0]['NetworkInterfaces'][0]]:
            row['PrivateIpAddresses'][0].pop('Association')
            if mode == 'ipv6_only':
                row['Ipv6Addresses'] = [{'Ipv6Address': '2600:1f18:1234::1'}]
    if mode == 'stopped':
        rows['instance'][0]['State']['Name'] = 'stopped'
    # A listenerless guest has exactly the same declared EC2/ENI/SG/NACL/route
    # facts. No fabricated guest flag is added to make this distinction.
    assert old_evaluate(rows)[0] == 'UNKNOWN'
    report = evaluate_snapshot(snapshot(rows), checks=ALTERNATIVES)
    expected = 'FAIL' if mode == 'listenerless_same_config' else 'UNKNOWN'
    assert [f['status'] for f in report['findings']] == [expected, expected]


@pytest.mark.parametrize('status', ['denied', 'partial', 'not_collected', 'malformed'])
def test_denied_or_incomplete_native_dependencies_never_prove_a_path(status):
    rows = facts()
    if status != 'partial':
        rows['security_group'] = []
    snap = snapshot(rows, {'security_group': status})
    assert witness(snap, SCOPE, 'i-12345678') is None
    assert all(f['status'] != 'PASS' for f in evaluate_snapshot(snap, checks=ALTERNATIVES)['findings'])
    assert old_evaluate(rows)[0] == 'UNKNOWN'


@pytest.mark.parametrize('status', ['denied', 'partial', 'not_collected', 'malformed'])
def test_old_subject_inventory_unavailable_never_passes(status):
    assert old_evaluate(facts(), status)[0] == 'UNKNOWN'


def test_native_dependency_expansion_is_explicit_and_does_not_include_guest_execution():
    from peaso.collectors.bulk_evidence import expand_native_requirements
    from peaso.collectors.aws_public_ingress_native import READ_ACTIONS
    assert DEPENDENCIES <= expand_native_requirements('aws', {'ec2_effective_ingress'})
    assert all(service == 'ec2' and operation.startswith('describe_') for service, operation in READ_ACTIONS)
    assert not {'ssm_managed_instance', 'load_balancer', 'ec2_listener_inventory'} & DEPENDENCIES


def test_sdk_response_contracts_expose_configuration_not_guest_listener_state():
    session = botocore.session.get_session()
    ec2 = session.get_service_model('ec2').shape_for('Instance')
    assert 'PublicIpAddress' in ec2.members and 'NetworkInterfaces' in ec2.members
    assert 'PublicReachability' not in ec2.members and 'ListeningPortVerified' not in ec2.members
    listeners = session.get_service_model('elbv2').operation_model('DescribeListeners').output_shape.members['Listeners'].member
    assert 'Port' in listeners.members and 'Protocol' in listeners.members
    assert 'ListeningPortVerified' not in listeners.members
