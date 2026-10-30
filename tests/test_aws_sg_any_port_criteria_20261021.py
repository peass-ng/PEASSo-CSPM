"""One unchanged evaluator: single-port world ingress is sufficient to FAIL."""
import copy
import hashlib
from pathlib import Path

import pytest

from peaso.checks import evaluate_check
from peaso.checks import claude_aws_a_network as native
from peaso.checks import aws_sg_any_port_description_correction_20261021 as correction
from peaso.checks.catalog import _base_description_for, description_for
from peaso.checks.aws_finding_clarity_reviewed import description as reviewed_description
from peaso.checks.claude_aws_a_common import idx, prowler_sg_open

CID = correction.CHECK_ID
ROOT = Path(__file__).resolve().parents[1]


def test_exact_description_successor_preserves_history_and_evaluator_sources():
    from tests.reviewed_guidance_presentation import assert_description_preserves_contract
    assert_description_preserves_contract(CID)
    before = reviewed_description(CID, _base_description_for(CID))
    assert 'opens all ports' in before['fail_when']
    original = copy.deepcopy(before)
    current = correction.description(before)
    assert before == original
    assert current == description_for(CID)
    assert 'single TCP or UDP port' in current['fail_when']
    assert 'Opening every port is not required' in current['fail_when']
    assert current['evaluated'] == before['evaluated']
    assert current['not_applicable_when'] == before['not_applicable_when']
    assert current['description_correction']['source_revision'] == correction.SOURCE_REVISION
    for path, expected in {
        'peaso/checks/claude_aws_a_network.py': 'dfe343109801c31dec12324a7b97fd76d88f6913161d8495b1bac9abb195abe6',
        'peaso/checks/claude_aws_a_common.py': '42218f329b77e55cd56c2f46de0a82ab260c849ca1ae1e89ac95a54e201a87d8',
    }.items():
        assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == expected
    before['fail_when'] = 'Changed criterion'
    with pytest.raises(ValueError, match='reviewed description changed'):
        correction.description(before)
    assert description_for('aws.claude_a.vpc.sg_no_world_all_traffic').get('description_correction') is None


@pytest.mark.parametrize('cidr,protocol,port,kind,owner,expected', [
    ('0.0.0.0/0', 'tcp', 22, 'interface', '123456789012', 'FAIL'),
    ('::/0', 'tcp', 22, 'interface', '123456789012', 'FAIL'),
    ('0.0.0.0/0', 'udp', 53, 'interface', '123456789012', 'FAIL'),
    ('10.0.0.0/8', 'tcp', 22, 'interface', '123456789012', 'PASS'),
    ('0.0.0.0/0', 'tcp', 22, 'vpc_endpoint', '123456789012', 'PASS'),
    ('0.0.0.0/0', 'tcp', 22, 'api_gateway_managed', '123456789012', 'PASS'),
    ('0.0.0.0/0', 'tcp', 22, 'interface', 'amazon-elb', 'PASS'),
])
def test_single_port_and_existing_managed_interface_exceptions(cidr, protocol, port, kind, owner, expected):
    rule = native.world_rule(protocol, port, port, cidr)
    item = native.sg_with(rule)
    eni = native.w(native.ENI, InterfaceType=kind, Attachment__InstanceOwnerId=owner)
    index = idx(**dict(native.IN_USE, network_interface=[eni]))
    original = copy.deepcopy((item, index))
    assert evaluate_check(CID, item, index)[0] == expected
    assert (item, index) == original
    if cidr == '0.0.0.0/0':
        assert prowler_sg_open(rule, '-1', any_address=True, all_ports=True)
        assert not prowler_sg_open(rule, '-1', any_address=True, all_ports=False)


def test_unused_and_missing_inventory_remain_na_or_unknown():
    item = native.sg_with(native.world_rule('tcp', 22, 22))
    assert evaluate_check(CID, native.w(item, GroupId='sg-unused'), idx(**native.IN_USE))[0] == 'NOT_APPLICABLE'
    assert evaluate_check(CID, item, idx(**dict(native.IN_USE, network_interface=None)))[0] == 'UNKNOWN'
    malformed = native.sg_with(native.world_rule('tcp', 22, 1))
    assert evaluate_check(CID, malformed, idx(**native.IN_USE))[0] == 'UNKNOWN'


def test_report_and_reviewer_input_keep_single_port_witness_and_corrected_criteria():
    from peaso.engine import evaluate_snapshot
    from peaso.snapshot import make_snapshot
    from peaso.ai.pipeline import inputs, findings_document
    item = native.sg_with(native.world_rule('tcp', 22, 22))
    collections = [{'type': kind, 'scope': native.ACCOUNT + '/' + native.REGION, 'status': 'collected', 'items': items}
                   for kind, items in dict(native.IN_USE, security_group=[item]).items()]
    report = evaluate_snapshot(make_snapshot('aws', [native.ACCOUNT + '/' + native.REGION], collections), checks=[CID])
    hardening, exposure, _ = inputs(report)
    finding = next(row for row in hardening + exposure if row['check_id'] == CID)
    assert finding['status'] == 'FAIL'
    assert finding['evidence']['customer_enis']
    assert finding['evidence']['internet_ingress'] == [dict(protocol='tcp', from_port=22, to_port=22, source='0.0.0.0/0')]
    document = findings_document(report, [finding])
    observed = document['items'][0]
    assert observed['fail_when'] == description_for(CID)['fail_when']
    assert 'TCP 22 from 0.0.0.0/0' in observed['evidence_summary']
    assert 'all ports do not need to be open' in observed['evidence_summary']
