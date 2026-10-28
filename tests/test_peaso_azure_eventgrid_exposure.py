"""Event Grid topic and domain public publishing paths."""

import pytest

from peaso.analysis.internet_exposure import assess
from peaso.snapshot import make_snapshot, resources
from tests.test_peaso_azure_bulk_native import SCOPE, parent


@pytest.mark.parametrize("kind,arm_type", [
    ("eventgrid_topic", "Microsoft.EventGrid/topics"),
    ("eventgrid_domain", "Microsoft.EventGrid/domains"),
])
def test_publisher_public_endpoint_and_ip_gate(kind, arm_type):
    rid = SCOPE + "/resourceGroups/rg/providers/" + arm_type + "/publisher"

    def decision(props):
        item = parent(rid, arm_type, props)
        snapshot = make_snapshot("azure", [SCOPE], [{"type": kind, "scope": SCOPE,
            "service": "Microsoft.EventGrid", "status": "collected", "items": [item]}])
        return next(row for row in assess(snapshot, resources(snapshot)) if row.resource["type"] == kind)

    base = {"endpoint": "https://publisher.eventgrid.azure.net/api/events"}
    public = decision(base)
    assert public.verdict() == "FAIL" and public.ports == {"tcp": ((443, 443),)}
    assert public.authenticated is True
    assert decision({**base, "publicNetworkAccess": "Disabled"}).verdict() == "PASS"
    assert decision({**base, "inboundIpRules": [{"ipMask": "10.0.0.0/8", "action": "Allow"}]}).verdict() == "PASS"
    assert decision({**base, "inboundIpRules": [{"ipMask": "8.8.8.0/24", "action": "Allow"}]}).verdict() == "FAIL"
    assert decision({**base, "inboundIpRules": [{"ipMask": "bad", "action": "Allow"}]}).verdict() == "UNKNOWN"
    assert decision({"publicNetworkAccess": "Enabled"}).verdict() == "UNKNOWN"
