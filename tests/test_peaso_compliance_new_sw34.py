"""Signed Azure checks against complete, partial, malformed, and foreign facts."""
from __future__ import annotations

import copy
import hashlib
import json

from peaso.checks import evaluate_check
from tests.compliance_draft_isolation import staged_registry
from peaso.checks import CHECKS, evaluate_check
with staged_registry(("compliance_new_sw34",)):
    from peaso.checks import compliance_new_sw34 as sw34

SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
VNET = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet"
SUBNET = VNET + "/subnets/workload"
NIC = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic"
FW = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw"
ROUTES = SUBNET + "/providers/PEASO/effectiveRoutes/default"
BOT = SCOPE + "/resourceGroups/rg/providers/Microsoft.BotService/botServices/bot"
KEY = BOT + "/providers/PEASO/cmkKeys/resolved"
KEY_URL = "https://vault.vault.azure.net/keys/key/version"
NOW = "2026-10-12T12:00:00+00:00"


def subnet(**updates):
    row = {"id": SUBNET, "_policy": {"source": "approved_policy", "status": "collected", "inScope": True,
                                     "routeCoverageSourceId": "approved-route-audit"}}
    row.update(updates)
    return row


def bot(**updates):
    row = {"id": BOT, "_policy": {"source": "approved_policy", "status": "collected",
                           "cmkSupported": True, "cmkRequired": True},
           "_provenance": {"source_operation": "botServices/get", "read_only": True,
                           "representation": "full"},
           "properties": {"isCmekEnabled": True, "cmekKeyVaultUrl": KEY_URL}}
    row.update(updates)
    return row


def route(prefix="0.0.0.0/0", hop="VirtualAppliance", address="10.0.0.4", **updates):
    row = {"nicId": NIC, "destinationPrefix": prefix, "internetBound": True,
           "nextHopType": hop, "nextHopIpAddress": address}
    row.update(updates)
    return row


def route_fact(routes=None, **updates):
    row = {"id": ROUTES, "subnetId": SUBNET,
           "_provenance": {"source_operation": "networkInterfaces/getEffectiveRouteTable", "read_only": True},
           "exhaustiveInternetDestinations": True, "allAttachedNicsCovered": True,
           "families": ["ipv4"], "ipv6Enabled": False, "nicIds": [NIC],
           "internetRoutes": [route()] if routes is None else routes}
    row.update(updates)
    row["_provenance"].setdefault("captured_at", NOW)
    try:
        route_hash = hashlib.sha256(json.dumps(row["internetRoutes"], sort_keys=True,
            separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    except (TypeError, ValueError):
        route_hash = "0" * 64
    row.setdefault("coverage", {"scope_id": VNET.casefold(), "subnet_id": SUBNET.casefold(),
        "nicIds": row["nicIds"], "routeRowsSha256": route_hash,
        "attachedNicInventoryComplete": True, "activeRouteTablesComplete": True,
        "internetDestinationPartitionComplete": True,
        "_provenance": {"source_operation": "ExternalCompleteSubnetRouting_Read",
            "source_id": "approved-route-audit", "read_only": True, "policy_approved": True,
            "complete": True, "captured_at": NOW}})
    return row


def firewall(**updates):
    row = {"id": FW, "kind": "AzureFirewall", "deployed": True, "approved": True,
           "approvalSource": "approved_policy",
           "privateIpAddresses": ["10.0.0.4"]}
    row.update(updates)
    return row


def key(**updates):
    row = {"id": KEY, "botId": BOT, "keyUrl": KEY_URL,
           "_provenance": {"source_operation": "KeyVault/keys/get", "read_only": True},
           "usable": True, "approved": True, "approvalSource": "approved_policy"}
    row.update(updates)
    return row


def index(collections, *, scope=SCOPE, provider="azure"):
    facts = {"context": {"provider": provider, "scope": scope, "created_at": NOW}, "collections": {}}
    for kind, envelope_scope, rows, status in collections:
        facts["collections"][kind] = [{"type": kind, "scope": envelope_scope,
                                       "status": status, "items": rows}]
        facts[kind] = [{"type": kind, "scope": envelope_scope, "data": row} for row in rows]
    return facts


def subnet_index(row=None, routes=None, firewalls=None, *, route_status="collected"):
    row = subnet() if row is None else row
    routes = [route_fact()] if routes is None else routes
    firewalls = [firewall()] if firewalls is None else firewalls
    return index([("subnet", VNET, [row], "collected"),
                  ("subnet_effective_route", VNET, routes, route_status),
                  ("approved_firewall", VNET, firewalls, "collected")], scope=VNET)


def bot_index(row=None, keys=None, *, bot_status="collected"):
    row = bot() if row is None else row
    keys = [key()] if keys is None else keys
    return index([("bot_service", SCOPE, [row], bot_status),
                  ("bot_cmk_key", SCOPE, keys, "collected")])


def test_subnet_pass_with_approved_default_and_more_specific_effective_routes():
    row = subnet()
    facts = subnet_index(row, [route_fact([route(), route("8.8.8.0/24")])])
    status, evidence = evaluate_check(sw34.SUBNET_ID, row, facts)
    assert status == "PASS" and evidence["route_count"] == 2


def test_subnet_fail_on_positive_effective_bypass():
    row = subnet()
    facts = subnet_index(row, [route_fact([route(), route("8.8.8.0/24", "Internet")])])
    status, evidence = evaluate_check(sw34.SUBNET_ID, row, facts)
    assert status == "FAIL" and evidence["bypass_routes"][0][1] == "8.8.8.0/24"


def test_subnet_ipv6_and_supported_ngfw_are_covered():
    row = subnet()
    ngfw = firewall(id=SCOPE + "/resourceGroups/rg/providers/Contoso.Network/appliances/ngfw",
                    kind="SupportedNGFW", privateIpAddresses=["10.0.0.5", "fd00::5"])
    routes = [route(address="10.0.0.5"), route("::/0", address="fd00::5")]
    fact = route_fact(routes, families=["ipv4", "ipv6"], ipv6Enabled=True)
    assert evaluate_check(sw34.SUBNET_ID, row, subnet_index(row, [fact], [ngfw]))[0] == "PASS"
    missing_v6 = route_fact([routes[0]], families=["ipv4", "ipv6"], ipv6Enabled=True)
    assert evaluate_check(sw34.SUBNET_ID, row, subnet_index(row, [missing_v6], [ngfw]))[0] == "UNKNOWN"


def test_subnet_unknown_for_missing_incomplete_malformed_and_foreign_facts():
    row = subnet()
    assert evaluate_check(sw34.SUBNET_ID, row, index([("subnet", VNET, [row], "collected")], scope=VNET))[0] == "UNKNOWN"
    assert evaluate_check(sw34.SUBNET_ID, row, subnet_index(row, route_status="partial"))[0] == "UNKNOWN"
    assert evaluate_check(sw34.SUBNET_ID, row, subnet_index(row, [route_fact(families=["ipv4", "ipv6"])]))[0] == "UNKNOWN"
    assert evaluate_check(sw34.SUBNET_ID, row, subnet_index(row, [route_fact([route(nextHopIpAddress=object())])]))[0] == "UNKNOWN"
    facts = subnet_index(row)
    facts["context"]["scope"] = "/subscriptions/22222222-2222-2222-2222-222222222222"
    assert evaluate_check(sw34.SUBNET_ID, row, facts)[0] == "UNKNOWN"
    facts = subnet_index(row, [route_fact(subnetId=VNET + "/subnets/other")])
    assert evaluate_check(sw34.SUBNET_ID, row, facts)[0] == "UNKNOWN"
    assert evaluate_check(sw34.SUBNET_ID, row, subnet_index(row, [route_fact([route(hop="None")])]))[0] == "UNKNOWN"
    assert evaluate_check(sw34.SUBNET_ID, row, subnet_index(row, [route_fact()], [firewall(approvalSource="guess")]))[0] == "UNKNOWN"
    facts = subnet_index(row)
    facts["collections"]["subnet"][0]["items"] = []
    assert evaluate_check(sw34.SUBNET_ID, row, facts)[0] == "UNKNOWN"


def test_subnet_out_of_scope_is_not_applicable():
    row = subnet(_policy={"source": "approved_policy", "status": "collected", "inScope": False})
    assert evaluate_check(sw34.SUBNET_ID, row, subnet_index(row, routes=[]))[0] == "NOT_APPLICABLE"


def test_bot_pass_fail_and_confirmed_missing_url():
    row = bot()
    assert evaluate_check(sw34.BOT_ID, row, bot_index(row))[0] == "PASS"
    disabled = bot(properties={"isCmekEnabled": False})
    assert evaluate_check(sw34.BOT_ID, disabled, bot_index(disabled, keys=[]))[0] == "FAIL"
    missing = bot(properties={"isCmekEnabled": True,
                              "_coverage": {"cmekKeyVaultUrl": {"status": "empty"}}})
    assert evaluate_check(sw34.BOT_ID, missing, bot_index(missing, keys=[]))[0] == "FAIL"
    empty = bot(properties={"isCmekEnabled": True, "cmekKeyVaultUrl": ""})
    assert evaluate_check(sw34.BOT_ID, empty, bot_index(empty, keys=[]))[0] == "FAIL"


def test_bot_unknown_for_missing_incomplete_malformed_and_foreign_facts():
    row = bot()
    assert evaluate_check(sw34.BOT_ID, row, index([("bot_service", SCOPE, [row], "collected")]))[0] == "UNKNOWN"
    assert evaluate_check(sw34.BOT_ID, row, bot_index(row, bot_status="partial"))[0] == "UNKNOWN"
    omitted = bot(properties={"isCmekEnabled": True})
    assert evaluate_check(sw34.BOT_ID, omitted, bot_index(omitted))[0] == "UNKNOWN"
    malformed = bot(properties={"isCmekEnabled": "true", "cmekKeyVaultUrl": KEY_URL})
    assert evaluate_check(sw34.BOT_ID, malformed, bot_index(malformed))[0] == "UNKNOWN"
    no_flag = bot(properties={"cmekKeyVaultUrl": KEY_URL})
    assert evaluate_check(sw34.BOT_ID, no_flag, bot_index(no_flag))[0] == "UNKNOWN"
    assert evaluate_check(sw34.BOT_ID, row, bot_index(row, [key(usable=False)]))[0] == "UNKNOWN"
    assert evaluate_check(sw34.BOT_ID, row, bot_index(row, [key(approvalSource="guess")]))[0] == "UNKNOWN"
    facts = bot_index(row)
    facts["context"]["provider"] = "aws"
    assert evaluate_check(sw34.BOT_ID, row, facts)[0] == "UNKNOWN"
    assert evaluate_check(sw34.BOT_ID, row, bot_index(row, [key(botId=SUBNET)]))[0] == "UNKNOWN"


def test_bot_not_applicable_only_with_authoritative_support_policy():
    row = bot(_policy={"source": "approved_policy", "status": "collected",
                       "cmkSupported": False, "cmkRequired": True})
    assert evaluate_check(sw34.BOT_ID, row, bot_index(row, keys=[]))[0] == "NOT_APPLICABLE"
    untrusted = bot(_policy={"source": "guess", "status": "collected",
                             "cmkSupported": False, "cmkRequired": True})
    assert evaluate_check(sw34.BOT_ID, untrusted, bot_index(untrusted, keys=[]))[0] == "UNKNOWN"


def test_signed_metadata_and_immutable_facts():
    row = subnet()
    facts = subnet_index(row)
    before = copy.deepcopy((row, facts))
    assert evaluate_check(sw34.SUBNET_ID, row, facts)[0] == "PASS"
    assert (row, facts) == before
