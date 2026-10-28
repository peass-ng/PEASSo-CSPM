"""Azure Public DNS authoritative listener evidence."""

from urllib.parse import urlsplit

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import make_snapshot, resources
from tests.test_peaso_azure_bulk_native import SCOPE, SUB, Transport, parent

RID = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/dnsZones/example.com"
SERVERS = ["ns1-01.azure-dns.com", "ns2-01.azure-dns.net",
           "ns3-01.azure-dns.org", "ns4-01.azure-dns.info"]


def decision(properties, *, full=True):
    item = parent(RID, "Microsoft.Network/dnsZones", properties)
    if full:
        item["_provenance"] = {"representation": "full", "source_operation": "get"}
    snapshot = make_snapshot("azure", [SCOPE], [{"type": "dns_zone", "scope": SCOPE,
        "service": "Microsoft.Network", "status": "collected", "items": [item]}])
    before = repr(snapshot)
    rows = assess(snapshot, resources(snapshot))
    assert repr(snapshot) == before and len(rows) == 1
    return rows[0]


def test_public_dns_zone_has_anonymous_authoritative_listener():
    row = decision({"nameServers": SERVERS, "numberOfRecordSets": 3})
    assert row.verdict() == "FAIL"
    assert row.ports == {"udp": ((53, 53),), "tcp": ((53, 53),)}
    assert row.addresses == sorted(SERVERS)
    assert row.authenticated is False
    assert "does not establish" in row.notes[0]


def test_private_or_incomplete_dns_zone():
    assert decision({"zoneType": "Private"}).verdict() == "PASS"
    assert decision({"zoneType": "Public", "nameServers": SERVERS}, full=False).verdict() == "UNKNOWN"
    assert decision({"zoneType": "Public"}).verdict() == "UNKNOWN"
    assert decision({"zoneType": "Other", "nameServers": SERVERS}).verdict() == "UNKNOWN"
    assert decision({"zoneType": "Public", "nameServers": ["bad/host"]}).verdict() == "UNKNOWN"


def test_collector_fetches_authoritative_zone_once_and_lists_records_once():
    kind = "Microsoft.Network/dnsZones"
    listing = parent(RID, kind, {})
    detail = parent(RID, kind, {"zoneType": "Public", "nameServers": SERVERS, "numberOfRecordSets": 2})
    api = Transport({SCOPE + "/providers/" + kind: {"value": [listing]}, RID: detail,
                     RID + "/all": {"value": []}})
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                             ["dns_zone", "dns_record"], transport=api)
    zone = next(c for c in snapshot["collections"] if c["type"] == "dns_zone")
    records = next(c for c in snapshot["collections"] if c["type"] == "dns_record")
    assert zone["items"][0]["_provenance"]["representation"] == "full"
    assert records["status"] == "empty"
    assert sum(urlsplit(url).path == RID for url in api.calls) == 1
    assert sum(urlsplit(url).path == RID + "/all" for url in api.calls) == 1
    assert assess(snapshot, resources(snapshot))[0].verdict() == "FAIL"


PRIVATE = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/privateDnsZones/internal.example"
OTHER = "33333333-3333-3333-3333-333333333333"


def private_decision(links, *, status="collected", scopes=None):
    collections = [
        {"type": "private_dns_zone", "scope": SCOPE, "service": "Microsoft.Network",
         "status": "collected", "items": [parent(PRIVATE, "Microsoft.Network/privateDnsZones", {})]},
        {"type": "private_dns_link", "scope": PRIVATE, "service": "Microsoft.Network",
         "status": status, "items": links},
    ]
    snapshot = make_snapshot("azure", scopes or [SCOPE], collections)
    return next(row for row in assess(snapshot, resources(snapshot))
                if row.resource["type"] == "private_dns_zone")


def link(subscription=SUB, *, state="Completed", provisioning="Succeeded", target=None):
    destination = target or f"/subscriptions/{subscription}/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet"
    return parent(PRIVATE + "/virtualNetworkLinks/link",
                  "Microsoft.Network/privateDnsZones/virtualNetworkLinks",
                  {"virtualNetwork": {"id": destination}, "virtualNetworkLinkState": state,
                   "provisioningState": provisioning})


def test_private_dns_zone_foreign_vnet_link():
    row = private_decision([link(OTHER)])
    assert row.verdict() == "FAIL"
    assert row.data_exposure is True and row.external_ids == [OTHER]
    assert row.ports == {}
    assert private_decision([link()]).verdict() == "PASS"
    assert private_decision([link(OTHER)], scopes=[SCOPE, "/subscriptions/" + OTHER]).verdict() == "PASS"
    assert private_decision([], status="empty").verdict() == "PASS"


def test_private_dns_zone_missing_or_transitioning_link_evidence():
    assert private_decision([], status="denied").verdict() == "UNKNOWN"
    assert private_decision([link(OTHER, state="InProgress")]).verdict() == "UNKNOWN"
    assert private_decision([link(OTHER, target="not-an-arm-id")]).verdict() == "UNKNOWN"
    assert private_decision([link(OTHER, provisioning="Failed")]).verdict() == "UNKNOWN"


def test_private_dns_zone_collector_lists_links_once():
    zone = parent(PRIVATE, "Microsoft.Network/privateDnsZones", {})
    foreign_link = link(OTHER)
    api = Transport({SCOPE + "/providers/Microsoft.Network/privateDnsZones": {"value": [zone]},
                     PRIVATE + "/virtualNetworkLinks": {"value": [foreign_link]}})
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                             ["private_dns_zone", "private_dns_link"], transport=api)
    assert sum(urlsplit(url).path == PRIVATE + "/virtualNetworkLinks" for url in api.calls) == 1
    assert next(row for row in assess(snapshot, resources(snapshot))
                if row.resource["type"] == "private_dns_zone").verdict() == "FAIL"
