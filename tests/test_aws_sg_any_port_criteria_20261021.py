"""One unchanged evaluator: single-port world ingress is sufficient to FAIL."""
import copy

import pytest

from peaso.checks import evaluate_check
from peaso.checks import claude_aws_a_network as native
from peaso.checks import aws_sg_any_port_description_correction_20261021 as correction
from peaso.checks.catalog import description_for
from peaso.checks.claude_aws_a_common import idx, prowler_sg_open

CID = correction.CHECK_ID
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
