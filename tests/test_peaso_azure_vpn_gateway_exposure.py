"""VPN gateway listeners use collected gateway, public-IP and connection facts."""

from peaso.analysis.internet_exposure import _observed, assess
from peaso.snapshot import make_snapshot, resources


SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
BASE = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network"
GATEWAY = BASE + "/virtualNetworkGateways/vpn"
PIP = BASE + "/publicIPAddresses/vpn"


def decision(gateway_properties, *, pip_address="20.1.2.3", connections=None, connection_status="empty"):
    collections = [{"type": "virtual_network_gateway", "scope": SCOPE, "service": "Microsoft.Network",
                    "status": "collected", "items": [{"id": GATEWAY, "properties": gateway_properties}]}]
    if pip_address is not None:
        collections.append({"type": "public_ip", "scope": SCOPE, "service": "Microsoft.Network",
                            "status": "collected", "items": [{"id": PIP, "properties": {"ipAddress": pip_address}}]})
    collections.append({"type": "virtual_network_gateway_connection", "scope": SCOPE,
                        "service": "Microsoft.Network", "status": connection_status,
                        "items": connections or []})
    snapshot = make_snapshot("azure", [SCOPE], collections)
    before = repr(snapshot)
    rows = assess(snapshot, resources(snapshot))
    assert repr(snapshot) == before
    return next(row for row in rows if row.resource["type"] == "virtual_network_gateway")


BASE_PROPS = {"gatewayType": "Vpn", "provisioningState": "Succeeded",
              "ipConfigurations": [{"properties": {"publicIPAddress": {"id": PIP}}}]}


def test_vpn_gateway_point_to_site_listener_protocols():
    sstp = decision({**BASE_PROPS, "vpnClientConfiguration": {"vpnClientProtocols": ["SSTP"]}})
    assert sstp.verdict() == "FAIL"
    assert sstp.addresses == ["20.1.2.3"]
    assert sstp.ports == {"tcp": ((443, 443),)}
    assert sstp.authenticated is True
    assert "Azure VPN gateway" in _observed(sstp, "FAIL")
    assert "VPC" not in _observed(sstp, "FAIL")
    ike = decision({**BASE_PROPS, "vpnClientConfiguration": {"vpnClientProtocols": ["IkeV2"]}})
    assert ike.verdict() == "FAIL" and ike.ports == {"udp": ((500, 500), (4500, 4500))}


def test_vpn_gateway_site_to_site_connection_and_unknowns():
    connection = {"id": BASE + "/connections/site", "properties": {
        "virtualNetworkGateway1": {"id": GATEWAY}, "connectionType": "IPsec",
        "connectionStatus": "Connected", "localNetworkGateway2": {"id": BASE + "/localNetworkGateways/site"}}}
    active = decision(BASE_PROPS, connections=[connection], connection_status="collected")
    assert active.verdict() == "FAIL" and active.ports == {"udp": ((500, 500), (4500, 4500))}
    assert active.external_ids == [BASE + "/localNetworkGateways/site"]
    assert any(step["layer"] == "external_tunnel" for step in active.path)
    assert decision(BASE_PROPS, connection_status="not_collected").verdict() == "UNKNOWN"
    assert decision({**BASE_PROPS, "vpnClientConfiguration": {}}).verdict() == "UNKNOWN"
    assert decision(BASE_PROPS, pip_address=None).verdict() == "UNKNOWN"


def test_vpn_gateway_non_vpn_or_unconfigured():
    express = decision({**BASE_PROPS, "gatewayType": "ExpressRoute"})
    assert express.verdict() == "PASS" and express.ports == {}
    assert "ExpressRoute gateway" in _observed(express, "PASS")
    assert decision(BASE_PROPS).verdict() == "UNKNOWN"
    assert decision({**BASE_PROPS, "provisioningState": "Updating"}).verdict() == "UNKNOWN"


def test_vpn_gateway_radius_secret_is_not_kept_in_snapshot_metadata():
    # The collector's read path strips the RADIUS secret before metadata retention.
    from peaso.collectors.azure import _ReaderExposure
    scope = "/subscriptions/00000000-0000-0000-0000-000000000000"
    gateway = scope + "/resourceGroups/rg/providers/Microsoft.Network/virtualNetworkGateways/gw"
    native = {"id": gateway, "properties": {"vpnClientConfiguration": {
        "vpnClientProtocols": ["OpenVPN"], "radiusServerSecret": "do-not-store"}}}
    collection = _ReaderExposure({})._read(("virtual_network_gateway", scope, "Microsoft.Network", lambda: iter([[native]])))
    assert collection["status"] == "collected"
    assert collection["items"] == [{"id": gateway, "properties": {"vpnClientConfiguration": {"vpnClientProtocols": ["OpenVPN"]}}}]


def test_gateway_selection_includes_public_address_and_connection_facts():
    from peaso.collectors.azure import _selected
    selected = _selected({}, ["virtual_network_gateway"])
    assert {"virtual_network_gateway", "public_ip", "resource_group",
            "virtual_network_gateway_connection"} <= selected
