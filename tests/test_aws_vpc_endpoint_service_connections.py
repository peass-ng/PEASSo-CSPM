"""PrivateLink provider-side connection collection uses one regional read."""

from peaso.collectors.aws import READ_ACTIONS, ReadResult
from peaso.collectors.aws_facts_cb_ca import _endpoint_services


class Requests:
    def __init__(self, connection_status="collected"):
        self.calls = []
        self.connection_status = connection_status

    def pages(self, session, service, region, operation, expression, **kwargs):
        self.calls.append((operation, kwargs))
        if operation == "describe_vpc_endpoint_service_configurations":
            return ReadResult([{"ServiceId": "vpce-svc-1"}, {"ServiceId": "vpce-svc-2"}])
        if operation == "describe_vpc_endpoint_connections":
            return ReadResult([{"ServiceId": "vpce-svc-1", "VpcEndpointId": "vpce-1",
                                "VpcEndpointOwner": "999988887777", "VpcEndpointState": "Available"}],
                              self.connection_status)
        assert operation == "describe_vpc_endpoint_service_permissions"
        return ReadResult([], "empty")


def test_endpoint_connections_are_read_once_and_joined_by_service_id():
    assert ("ec2", "describe_vpc_endpoint_connections") in READ_ACTIONS
    requests = Requests()
    result = _endpoint_services(requests, object(), "us-east-1", "111122223333")
    assert result.items[0]["EndpointConnections"] == [{
        "ServiceId": "vpce-svc-1", "VpcEndpointId": "vpce-1",
        "VpcEndpointOwner": "999988887777", "VpcEndpointState": "Available"}]
    assert result.items[1]["EndpointConnections"] == []
    assert sum(operation == "describe_vpc_endpoint_connections" for operation, _ in requests.calls) == 1


def test_partial_connection_read_cannot_prove_absence():
    result = _endpoint_services(Requests("partial"), object(), "us-east-1", "111122223333")
    assert all("EndpointConnections" not in row for row in result.items)
    assert all(row["_coverage"]["EndpointConnections"]["status"] == "partial" for row in result.items)
