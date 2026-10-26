"""The AWS collector keeps only its most recently used SDK clients."""
from peaso.collectors import aws


class Session:
    def __init__(self):
        self.built = []

    def client(self, service, region_name=None, config=None):
        client = object()
        self.built.append((service, region_name))
        return client


def test_least_recently_used_clients_are_evicted_and_rebuilt(monkeypatch):
    monkeypatch.setattr(aws, 'MAX_CACHED_CLIENTS', 3)
    requests, session = aws.Requests({}), Session()
    first = requests.client(session, 'ec2', 'us-east-1')
    requests.client(session, 'iam', 'us-east-1')
    requests.client(session, 's3', 'us-east-1')
    assert requests.client(session, 'ec2', 'us-east-1') is first  # a hit refreshes ec2
    requests.client(session, 'kms', 'us-east-1')  # evicts iam, the oldest unused
    assert len(requests._clients) == 3
    assert [key[1] for key in requests._clients] == ['s3', 'ec2', 'kms']
    assert requests.client(session, 'ec2', 'us-east-1') is first
    rebuilt = requests.client(session, 'iam', 'us-east-1')
    assert session.built == [('ec2', 'us-east-1'), ('iam', 'us-east-1'), ('s3', 'us-east-1'),
                             ('kms', 'us-east-1'), ('iam', 'us-east-1')]
    assert rebuilt is requests.client(session, 'iam', 'us-east-1')
    assert requests.clients_created == 5


def test_preinstalled_clients_are_served_from_a_plain_mapping():
    requests, session = aws.Requests({}), Session()
    stub = object()
    requests._clients = {(id(session), 'ec2', 'us-east-1'): stub}
    assert requests.client(session, 'ec2', 'us-east-1') is stub
    assert session.built == []
