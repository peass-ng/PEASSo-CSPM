from peaso.collectors.aws_facts_compute_edge import _target_group_attributes


def test_nlb_target_group_source_mode_uses_read_only_detail_and_projects_one_attribute():
    class Requests:
        def __init__(self):
            self.calls = []

        def detail(self, session, service, region, operation, **kwargs):
            self.calls.append((service, region, operation, kwargs))
            return {'collection_status': 'collected', 'Attributes': [
                {'Key': 'preserve_client_ip.enabled', 'Value': 'true'},
                {'Key': 'proxy_protocol_v2.enabled', 'Value': 'false'}]}

    requests = Requests()
    item = {'TargetGroupArn': 'arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/t/1',
            'Protocol': 'TCP', 'TargetType': 'ip'}
    output = _target_group_attributes(requests, object(), 'us-east-1', [item])
    assert requests.calls == [('elbv2', 'us-east-1', 'describe_target_group_attributes',
                               {'TargetGroupArn': item['TargetGroupArn']})]
    assert output[0]['SourceAttributes'] == {
        'collection_status': 'collected', 'preserve_client_ip_enabled': True}
    assert output[0]['TargetGroupArn'] == item['TargetGroupArn']
    assert 'SourceAttributes' not in item
