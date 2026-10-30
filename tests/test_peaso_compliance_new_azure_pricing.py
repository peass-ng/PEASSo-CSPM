"""Provider-shaped Defender pricing and owner-policy evidence fixtures."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from peaso.checks import evaluate_check
from peaso.checks import compliance_new_azure_pricing as new
from peaso.collectors.azure import _defender_containers_policy
from peaso.collectors import azure
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot
from peaso.checks import CHECKS, evaluate_check

NOW = datetime(2026, 10, 12, tzinfo=timezone.utc)
SCOPE = "/subscriptions/sub"


def supplied(**changes):
    value = {"observed_at": NOW.isoformat(), "max_age_seconds": 600, "max_policy_items": 10,
             "subscriptions": [{"scope": SCOPE, "required_extensions": ["ContainerSensor", "AgentlessDiscoveryForKubernetes"]}]}
    value.update(changes)
    return value


def policy(**changes):
    return _defender_containers_policy({"compliance_policy": {"defender_containers": supplied(**changes)}},
                                       [SCOPE], NOW.isoformat())


def pricing(name, *, tier="Standard", subplan=None, extensions=None, rid=None, coverage="FullyCovered"):
    props = {"pricingTier": tier, "extensions": extensions if extensions is not None else []}
    if coverage is not None:
        props["resourcesCoverageStatus"] = coverage
    if subplan is not None:
        props["subPlan"] = subplan
    return {"id": rid or SCOPE + "/providers/Microsoft.Security/pricings/" + name,
            "name": name, "properties": props}


def indexed(rows, *, owner=None, collection="collected", scope=SCOPE):
    return {"context": {"scope": scope, "created_at": NOW.isoformat(),
                        "metadata": {"defender_containers_policy": policy() if owner is None else owner}},
            "collections": {"security_pricing": [{"scope": scope, "status": collection}]},
            "security_pricing": [{"data": row} for row in rows]}


def verdict(cid, rows, **kwargs):
    return evaluate_check(cid, {"scope": SCOPE}, indexed(rows, **kwargs))


def ext(name, enabled="True", code=None):
    row = {"name": name, "isEnabled": enabled}
    if code is not None:
        row["operationStatus"] = {"code": code}
    return row


def test_file_integrity_requires_standard_p2_and_declared_extension():
    cid = new.FIM_ID
    good = pricing("VirtualMachines", subplan="P2", extensions=[ext("FileIntegrityMonitoring")])
    status, evidence = verdict(cid, [good])
    assert status == "PASS" and evidence["subplan"] == "P2" and "host monitoring unverified" in evidence["semantics"]
    for row in (pricing("VirtualMachines", tier="Free", subplan="P2", extensions=[ext("FileIntegrityMonitoring")]),
                pricing("VirtualMachines", subplan="P1", extensions=[ext("FileIntegrityMonitoring")]),
                pricing("VirtualMachines", subplan="P2"),
                pricing("VirtualMachines", subplan="P2", extensions=[ext("FileIntegrityMonitoring", "False")])):
        assert verdict(cid, [row])[0] == "FAIL"
    free_without_extensions = pricing("VirtualMachines", tier="Free")
    del free_without_extensions["properties"]["extensions"]
    assert verdict(cid, [free_without_extensions])[0] == "FAIL"
    p1_without_extensions = pricing("VirtualMachines", subplan="P1")
    del p1_without_extensions["properties"]["extensions"]
    assert verdict(cid, [p1_without_extensions])[0] == "FAIL"
    assert verdict(cid, [good], collection="denied")[0] == "UNKNOWN"
    assert verdict(cid, [good], collection="partial")[0] == "UNKNOWN"
    assert verdict(cid, [])[0] == "UNKNOWN"
    assert verdict(cid, [pricing("VirtualMachines", subplan="P3", extensions=[ext("FileIntegrityMonitoring")])])[0] == "UNKNOWN"
    assert verdict(cid, [pricing("VirtualMachines", extensions=[ext("FileIntegrityMonitoring")])])[0] == "UNKNOWN"
    for coverage in (None, "PartiallyCovered", "NotCovered", "Mystery"):
        row = pricing("VirtualMachines", subplan="P2", extensions=[ext("FileIntegrityMonitoring")], coverage=coverage)
        assert verdict(cid, [row])[0] == "UNKNOWN"


def test_file_integrity_operation_and_duplicate_or_foreign_pricing_are_uncertain():
    cid = new.FIM_ID
    for code in ("Failed", "InProgress", "Pending", "UnknownProviderValue"):
        row = pricing("VirtualMachines", subplan="P2", extensions=[ext("FileIntegrityMonitoring", code=code)])
        assert verdict(cid, [row])[0] == "UNKNOWN"
    success = pricing("VirtualMachines", subplan="P2", extensions=[ext("FileIntegrityMonitoring", code="Succeeded")])
    assert verdict(cid, [success])[0] == "PASS"
    assert verdict(cid, [success, deepcopy(success)])[0] == "UNKNOWN"
    foreign = pricing("VirtualMachines", subplan="P2", extensions=[ext("FileIntegrityMonitoring")],
                      rid="/subscriptions/other/providers/Microsoft.Security/pricings/VirtualMachines")
    assert verdict(cid, [foreign])[0] == "UNKNOWN"
    lowercase = deepcopy(success)
    lowercase["id"] = lowercase["id"].lower()
    assert verdict(cid, [lowercase])[0] == "PASS"


def test_owner_policy_is_exact_subscription_bound_fresh_typed_and_bounded():
    assert policy()["status"] == "collected"
    assert policy()["subscriptions"][0]["required_extensions"] == ["ContainerSensor", "AgentlessDiscoveryForKubernetes"]
    for changes in ({"max_policy_items": 1}, {"max_policy_items": True},
                    {"observed_at": (NOW - timedelta(hours=1)).isoformat()},
                    {"subscriptions": []},
                    {"subscriptions": [{"scope": "/subscriptions/other", "required_extensions": ["ContainerSensor"]}]},
                    {"subscriptions": [{"scope": SCOPE, "required_extensions": []}]},
                    {"subscriptions": [{"scope": SCOPE, "required_extensions": ["ContainerSensor", "ContainerSensor"]}]},
                    {"subscriptions": [{"scope": SCOPE, "required_extensions": [42]}]},
                    {"subscriptions": [{"scope": SCOPE, "required_extensions": ["UnsupportedExtension"]}]},
                    {"unapproved": "value"}):
        assert policy(**changes)["status"] == "unknown"
    assert _defender_containers_policy({}, [SCOPE], NOW.isoformat())["status"] == "unknown"


def test_persistent_defender_requirement_survives_later_scan_and_explicit_expiry_still_applies():
    desired = supplied()
    del desired["observed_at"], desired["max_age_seconds"]
    later = (NOW + timedelta(days=14)).isoformat()
    persistent = _defender_containers_policy({"compliance_policy": {"defender_containers": desired}}, [SCOPE], later)
    assert persistent["status"] == "collected"
    assert "observed_at" not in persistent and "max_age_seconds" not in persistent
    row = pricing("Containers", extensions=[ext("ContainerSensor"), ext("AgentlessDiscoveryForKubernetes")])
    assessment = indexed([row], owner=persistent)
    assessment["context"]["created_at"] = later
    assert evaluate_check(new.CONTAINERS_ID, {"scope": SCOPE}, assessment)[0] == "PASS"
    malformed = dict(desired, observed_at=NOW.isoformat())
    assert _defender_containers_policy({"compliance_policy": {"defender_containers": malformed}}, [SCOPE], later)["status"] == "unknown"
    assessment["context"]["metadata"]["defender_containers_policy"]["max_age_seconds"] = 600
    assert evaluate_check(new.CONTAINERS_ID, {"scope": SCOPE}, assessment)[0] == "UNKNOWN"
    assert _defender_containers_policy({"compliance_policy": {"defender_containers": supplied()}}, [SCOPE], later)["status"] == "unknown"


def test_containers_requires_each_owner_named_extension_and_no_assumed_defaults():
    cid = new.CONTAINERS_ID
    good = pricing("Containers", extensions=[ext("ContainerSensor"), ext("AgentlessDiscoveryForKubernetes")])
    status, evidence = verdict(cid, [good])
    assert status == "PASS" and evidence["required_extension_count"] == 2
    assert "required_extensions" not in evidence
    assert verdict(cid, [pricing("Containers", tier="Free", extensions=good["properties"]["extensions"])])[0] == "FAIL"
    free_without_extensions = pricing("Containers", tier="Free")
    del free_without_extensions["properties"]["extensions"]
    assert verdict(cid, [free_without_extensions])[0] == "FAIL"
    status, evidence = verdict(cid, [pricing("Containers", extensions=[ext("ContainerSensor")])])
    assert status == "FAIL" and evidence["missing_examples"] == ["AgentlessDiscoveryForKubernetes"]
    assert verdict(cid, [pricing("Containers", extensions=[ext("ContainerSensor", "False"), ext("AgentlessDiscoveryForKubernetes")])])[0] == "FAIL"
    assert verdict(cid, [pricing("Containers", extensions=[ext("ContainerSensor", code="Failed"), ext("AgentlessDiscoveryForKubernetes")])])[0] == "UNKNOWN"
    assert verdict(cid, [good], collection="partial")[0] == "UNKNOWN"
    assert verdict(cid, [])[0] == "UNKNOWN"
    assert verdict(cid, [good], owner={"status": "unknown", "reason": "missing"})[0] == "UNKNOWN"
    for coverage in (None, "PartiallyCovered", "NotCovered"):
        row = pricing("Containers", extensions=good["properties"]["extensions"], coverage=coverage)
        assert verdict(cid, [row])[0] == "UNKNOWN"


def test_offline_policy_timestamp_scope_and_extension_duplicates_are_unknown():
    good = pricing("Containers", extensions=[ext("ContainerSensor"), ext("AgentlessDiscoveryForKubernetes")])
    data = indexed([good])
    data["context"]["created_at"] = "2026-10-12T00:00:00"
    assert evaluate_check(new.CONTAINERS_ID, {"scope": SCOPE}, data)[0] == "UNKNOWN"
    data = indexed([good])
    data["context"]["metadata"]["defender_containers_policy"]["observed_at"] = "2026-10-12T00:00:00"
    assert evaluate_check(new.CONTAINERS_ID, {"scope": SCOPE}, data)[0] == "UNKNOWN"
    data = indexed([good])
    data["context"]["metadata"]["defender_containers_policy"]["subscriptions"][0]["scope"] = "/subscriptions/other"
    assert evaluate_check(new.CONTAINERS_ID, {"scope": SCOPE}, data)[0] == "UNKNOWN"
    data = indexed([good])
    data["context"]["metadata"]["defender_containers_policy"]["max_policy_items"] = 1
    assert evaluate_check(new.CONTAINERS_ID, {"scope": SCOPE}, data)[0] == "UNKNOWN"
    data = indexed([good])
    data["context"]["metadata"]["defender_containers_policy"]["subscriptions"][0]["required_extensions"] = ["UnsupportedExtension"]
    assert evaluate_check(new.CONTAINERS_ID, {"scope": SCOPE}, data)[0] == "UNKNOWN"
    duplicate = pricing("Containers", extensions=[ext("ContainerSensor"), ext("ContainerSensor"), ext("AgentlessDiscoveryForKubernetes")])
    assert verdict(new.CONTAINERS_ID, [duplicate])[0] == "UNKNOWN"


def test_snapshot_engine_keeps_two_distinct_results_and_denied_inventory_unknown():
    rows = [pricing("VirtualMachines", subplan="P2", extensions=[ext("FileIntegrityMonitoring")]),
            pricing("Containers", extensions=[ext("ContainerSensor"), ext("AgentlessDiscoveryForKubernetes")])]
    snap = make_snapshot("azure", [SCOPE], [{"type": "security_pricing", "scope": SCOPE,
           "service": "Microsoft.Security", "status": "collected", "items": rows}],
           created_at=NOW.isoformat(), metadata={"defender_containers_policy": policy()})
    report = evaluate_snapshot(snap, checks=list(new.IDS))
    assert report["stats"]["by_status"] == {"PASS": 2}
    assert {row["check_id"] for row in report["findings"]} == set(new.IDS)
    denied = make_snapshot("azure", [SCOPE], [{"type": "security_pricing", "scope": SCOPE,
           "service": "Microsoft.Security", "status": "denied", "items": []}],
           created_at=NOW.isoformat(), metadata={"defender_containers_policy": policy()})
    report = evaluate_snapshot(denied, checks=list(new.IDS))
    assert report["stats"]["by_status"] in ({"DENIED": 2}, {"UNKNOWN": 2})


def test_actual_collector_pricing_list_and_owner_policy_reach_engine_once():
    rows = [pricing("VirtualMachines", subplan="P2", extensions=[ext("FileIntegrityMonitoring")]),
            pricing("Containers", extensions=[ext("ContainerSensor"), ext("AgentlessDiscoveryForKubernetes")])]
    # Actual ARM pricing GETs include the resource type; old synthetic predicate
    # rows above remain unchanged and are not accepted as complete native GETs.
    for row in rows:
        row['type'] = 'Microsoft.Security/pricings'

    class PricingTransport:
        tenant = "tenant-fixture"

        def __init__(self):
            self.calls = []

        def request(self, url, *, body=None, audience=azure.ARM):
            self.calls.append((url, body, audience))
            assert audience == azure.ARM
            if urlsplit(url).path == "/providers/Microsoft.ResourceGraph/resources":
                assert body is not None and body["subscriptions"] == ["sub"]
                return {"data": [], "resultTruncated": "false"}
            path = urlsplit(url).path
            assert body is None
            if path == SCOPE + "/providers/Microsoft.Security/pricings":
                return {"value": deepcopy(rows)}
            for row in rows:
                if path == row["id"]:
                    return deepcopy(row)
            raise AssertionError(path)

    transport = PricingTransport()
    live_policy = supplied(observed_at=datetime.now(timezone.utc).isoformat())
    snapshot = azure.collect({"scopes": ["sub"], "options": {"compliance_policy": {"defender_containers": live_policy}}},
                             ["security_pricing"], transport=transport)
    pricing_inventory = [row for row in snapshot["collections"] if row["type"] == "security_pricing"]
    assert len(pricing_inventory) == 1 and pricing_inventory[0]["status"] == "collected"
    assert len(pricing_inventory[0]["items"]) == 2
    assert snapshot["metadata"]["defender_containers_policy"]["status"] == "collected"
    pricing_calls = [url for url, body, _ in transport.calls if body is None]
    assert len(transport.calls) == 4 and len(pricing_calls) == 3
    assert all("api-version=2024-01-01" in url for url in pricing_calls)
    assert {urlsplit(url).path for url in pricing_calls} == {
        SCOPE + "/providers/Microsoft.Security/pricings", *(row["id"] for row in rows)}
    report = evaluate_snapshot(snapshot, checks=list(new.IDS))
    assert report["stats"]["by_status"] == {"PASS": 2}
