"""Traffic Manager profile DNS referrals use one cached ARM profile list."""
from peaso.analysis.internet_exposure import assess
from peaso.collectors.azure import ENDPOINTS
from peaso.snapshot import make_snapshot, resources


SCOPE = "/subscriptions/test"


def decision(properties):
    item = {"id": SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/trafficManagerProfiles/tm",
            "type": "Microsoft.Network/trafficManagerProfiles", "properties": properties}
    snapshot = make_snapshot("azure", [SCOPE], [{"type": "traffic_manager_profile", "scope": SCOPE,
        "service": "Microsoft.Network", "status": "collected", "items": [item]}])
    result = assess(snapshot, resources(snapshot))
    assert len(result) == 1
    return result[0]


def test_profile_endpoint_states_and_external_target():
    assert ENDPOINTS["traffic_manager_profile"] == ("Microsoft.Network/trafficManagerProfiles", "2022-04-01")
    base = {"profileStatus": "Enabled", "dnsConfig": {"fqdn": "tm.trafficmanager.net"},
            "endpoints": [{"id": "external", "properties": {"endpointStatus": "Enabled", "target": "other.example"}}]}
    active = decision(base)
    assert active.verdict() == "FAIL"
    assert active.addresses == ["tm.trafficmanager.net"]
    assert active.ports == {"tcp": ((53, 53),), "udp": ((53, 53),)}
    assert active.path[-1]["declared_targets"] == ["other.example"]
    assert any(g["layer"] == "target" for g in active.unresolved)
    assert decision({**base, "profileStatus": "Disabled"}).verdict() == "PASS"
    assert decision({**base, "endpoints": []}).verdict() == "PASS"
    assert decision({**base, "endpoints": [{"properties": {"endpointStatus": "Disabled"}}]}).verdict() == "PASS"
    assert decision({**base, "endpoints": [{"properties": {"target": "other.example"}}]}).verdict() == "UNKNOWN"
    assert decision({**base, "endpoints": None}).verdict() == "UNKNOWN"
    assert decision({**base, "dnsConfig": {}}).verdict() == "UNKNOWN"
