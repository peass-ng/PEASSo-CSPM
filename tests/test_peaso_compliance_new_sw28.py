"""Source and scope boundaries for signed Azure agentless Kubernetes pricing."""
from __future__ import annotations

import copy

import pytest

from peaso.checks import CHECKS, evaluate_check
from peaso.checks import compliance_new_sw28 as sw28


SCOPE = "/subscriptions/sub"
CLUSTER = SCOPE + "/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/aks"


@pytest.fixture(scope="module", autouse=True)
def clean_draft_registration():
    yield
    CHECKS[:] = [check for check in CHECKS if check.id != sw28.ID]


def plan(name, *, tier="Standard", enabled="True", operation=None, inherited="False"):
    extensions = [] if enabled is None else [{"name": "AgentlessDiscoveryForKubernetes",
                                               "isEnabled": enabled}]
    if operation is not None and extensions:
        extensions[0]["operationStatus"] = {"code": operation}
    props = {"pricingTier": tier, "inherited": inherited, "extensions": extensions}
    if inherited == "True":
        props["inheritedFrom"] = SCOPE
    return {"id": CLUSTER + "/providers/Microsoft.Security/pricings/" + name,
            "name": name, "properties": props}


def priced_row(*, containers=None, posture=None):
    return {"id": CLUSTER,
            "_provenance": {"source_operation": "Microsoft.Security/pricings GET",
                            "api_version": "2024-01-01", "read_only": True,
                            "effective_scope": CLUSTER},
            "plans": [containers or plan("Containers"),
                      posture or plan("CloudPosture", tier="Free", enabled=None)]}


def index(*, clusters=None, pricing=None, pricing_status=None, cluster_status=None):
    clusters = [{"id": CLUSTER}] if clusters is None else clusters
    pricing = [priced_row()] if pricing is None else pricing
    collections = {}
    wrappers = {}
    for kind, rows, status in (("aks_cluster", clusters, cluster_status),
                               ("defender_pricing", pricing, pricing_status)):
        status = status or ("empty" if not rows else "collected")
        collections[kind] = [{"type": kind, "scope": SCOPE, "status": status,
                              "items": rows}]
        wrappers[kind] = [{"type": kind, "scope": SCOPE, "data": row}
                          for row in rows]
    return {"context": {"provider": "azure", "scope": SCOPE},
            "collections": collections, **wrappers}


def evaluate(facts=None, item=None):
    return evaluate_check(sw28.ID, {"scope": SCOPE} if item is None else item,
                          index() if facts is None else facts)


def test_containers_and_cloudposture_can_each_satisfy_cluster():
    assert evaluate()[0] == "PASS"
    row = priced_row(containers=plan("Containers", tier="Free", enabled=None),
                     posture=plan("CloudPosture", inherited="True"))
    assert evaluate(index(pricing=[row]))[0] == "PASS"


def test_complete_pricing_without_applicable_enabled_extension_fails():
    row = priced_row(containers=plan("Containers", enabled="False"))
    status, evidence = evaluate(index(pricing=[row]))
    assert status == "FAIL"
    assert evidence["clusters_without_enabled_extension"] == [CLUSTER.lower()]
    both_free = priced_row(containers=plan("Containers", tier="Free", enabled=None))
    assert evaluate(index(pricing=[both_free]))[0] == "FAIL"


def test_failed_operation_unknown_even_with_other_enabled_plan():
    row = priced_row(containers=plan("Containers", operation="Failed"),
                     posture=plan("CloudPosture"))
    assert evaluate(index(pricing=[row]))[0] == "UNKNOWN"
    row = priced_row(containers=plan("Containers", operation="Pending"))
    assert evaluate(index(pricing=[row]))[0] == "UNKNOWN"
    row = priced_row(containers=plan("Containers", operation="Succeeded"))
    assert evaluate(index(pricing=[row]))[0] == "PASS"


def test_incomplete_missing_malformed_and_foreign_facts_unknown():
    assert evaluate(index(pricing_status="partial"))[0] == "UNKNOWN"
    assert evaluate(index(cluster_status="denied"))[0] == "UNKNOWN"
    assert evaluate(index(pricing=[]))[0] == "UNKNOWN"
    assert evaluate(index(pricing=[priced_row(), priced_row()]))[0] == "UNKNOWN"
    assert evaluate({})[0] == "UNKNOWN"
    foreign = priced_row()
    foreign["_provenance"]["effective_scope"] = SCOPE + "/other"
    assert evaluate(index(pricing=[foreign]))[0] == "UNKNOWN"
    foreign = priced_row()
    foreign["plans"][0]["id"] = SCOPE + "/providers/Microsoft.Security/pricings/Containers"
    assert evaluate(index(pricing=[foreign]))[0] == "UNKNOWN"
    assert evaluate(index(), {"scope": "/subscriptions/other"})[0] == "UNKNOWN"
    row = priced_row(containers=plan("Containers", enabled=True))
    assert evaluate(index(pricing=[row]))[0] == "UNKNOWN"
    row = priced_row(containers=plan("Containers", tier="Premium"))
    assert evaluate(index(pricing=[row]))[0] == "UNKNOWN"
    row = priced_row(containers=plan("Containers", inherited="Maybe"))
    assert evaluate(index(pricing=[row]))[0] == "UNKNOWN"
    row = priced_row(containers=plan("Containers", inherited="True"))
    row["plans"][0]["properties"]["inheritedFrom"] = "/subscriptions/other"
    assert evaluate(index(pricing=[row]))[0] == "UNKNOWN"
    row = priced_row()
    row["plans"][0]["properties"]["inheritedFrom"] = "/subscriptions/other"
    assert evaluate(index(pricing=[row]))[0] == "UNKNOWN"
    row = priced_row()
    row["plans"][0]["properties"].pop("extensions")
    assert evaluate(index(pricing=[row]))[0] == "UNKNOWN"


def test_empty_complete_cluster_inventory_not_applicable():
    assert evaluate(index(clusters=[], pricing=[]))[0] == "NOT_APPLICABLE"


def test_evaluation_does_not_mutate_facts():
    facts = index()
    before = copy.deepcopy(facts)
    assert evaluate(facts)[0] == "PASS"
    assert facts == before
