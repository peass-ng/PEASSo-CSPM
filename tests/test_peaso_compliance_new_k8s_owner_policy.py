# Historical fixture contracts; current native admission is tested separately.
"""Defensive signed owner-policy predicates over complete Kubernetes facts."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from peaso.checks import evaluate_check
from peaso.checks import compliance_new_k8s_owner_policy as checks
from peaso.checks.facts import MemoIndex
from peaso.collectors.k8s import _owner_policy_metadata
from peaso.collectors import k8s
from tests.archived_check_contract import evaluate_snapshot


NOW = datetime(2026, 10, 12, tzinfo=timezone.utc)


def owner(**changes):
    value = {"cluster_id": "c1", "observed_at": NOW.isoformat(), "max_age_seconds": 600,
             "max_policy_items": 10, "namespace_labels": {"required_key": "team", "required_value": "platform",
             "master_label_key": "owner", "required_master_value": "core"}, "target_namespace": "apps",
             "authorized_namespaces": ["apps"], "serviceType": "LoadBalancer",
             "selected_loadbalancer_services": [{"namespace": "apps", "name": "web", "uid": "uid-1"}]}
    value.update(changes)
    return value


def index(policy=None, *, roles=(), role_status="collected", services=None, service_status="collected", scope="*"):
    if policy is None:
        policy = _owner_policy_metadata({"compliance_policy": owner()}, "c1", NOW.isoformat())
    if services is None:
        services = [svc()]
    return {"context": {"created_at": NOW.isoformat(), "metadata": {"cluster_id": "c1", "compliance_policy": policy}},
            "collections": {"rolebinding": [{"status": role_status}], "service": [{"status": service_status}]},
            "rolebinding": [{"data": {"metadata": {"namespace": namespace, "name": name}}} for namespace, name in roles],
            "service": [{"data": row} for row in services]}


def ns(labels=None, *, full=True):
    item = {"metadata": {"name": "apps"}}
    if labels is not None:
        item["metadata"]["labels"] = labels
    if full:
        item["provenance"] = {"evidence": "read-only list"}
    return item


def svc(namespace="apps", name="web", uid="uid-1", kind="LoadBalancer"):
    return {"metadata": {"namespace": namespace, "name": name, "uid": uid}, "spec": {"type": kind}}


def check(cid, item, indexed=None):
    return evaluate_check(cid, item, indexed or index())


def test_parser_requires_current_cluster_bound_bounded_typed_owner_policy():
    parsed = _owner_policy_metadata({"compliance_policy": owner()}, "c1", NOW.isoformat())
    assert parsed["status"] == "collected" and parsed["source"] == "operator-supplied"
    assert parsed["selected_loadbalancer_services"][0]["uid"] == "uid-1"
    for changes in ({"cluster_id": "other"}, {"max_policy_items": 2},
                    {"observed_at": (NOW-timedelta(hours=1)).isoformat()},
                    {"selected_loadbalancer_services": [{"namespace": "apps", "name": "web"}]},
                    {"namespace_labels": {"required_key": "team", "required_value": "a",
                                          "master_label_key": "team", "required_master_value": "b"}},
                    {"unknown_policy_field": "x"}):
        assert _owner_policy_metadata({"compliance_policy": owner(**changes)}, "c1", NOW.isoformat())["status"] == "unknown"
    conflict = _owner_policy_metadata({"compliance_policy": owner(serviceType="ClusterIP")}, "c1", NOW.isoformat())
    assert conflict["status"] == "collected" and conflict["service_type_conflict"] is True
    assert _owner_policy_metadata({}, "c1", NOW.isoformat())["status"] == "unknown"
    assert _owner_policy_metadata({"compliance_policy": owner(max_policy_items=1)}, "c1", NOW.isoformat())["status"] == "unknown"


def test_persistent_desired_policy_survives_later_scan_but_explicit_expiry_does_not():
    desired = owner()
    del desired["observed_at"], desired["max_age_seconds"]
    later = (NOW + timedelta(days=14)).isoformat()
    persistent = _owner_policy_metadata({"compliance_policy": desired}, "c1", later)
    assert persistent["status"] == "collected"
    assert "observed_at" not in persistent and "max_age_seconds" not in persistent
    assessment = index(persistent)
    assessment["context"]["created_at"] = later
    assert check(checks.LABEL_ID, ns({"team": "platform", "owner": "core"}), assessment)[0] == "PASS"
    incomplete = deepcopy(desired)
    incomplete["observed_at"] = NOW.isoformat()
    assert _owner_policy_metadata({"compliance_policy": incomplete}, "c1", later)["status"] == "unknown"
    invalid_snapshot = deepcopy(persistent)
    invalid_snapshot["max_age_seconds"] = 600
    assert check(checks.LABEL_ID, ns({"team": "platform", "owner": "core"}), index(invalid_snapshot))[0] == "UNKNOWN"
    assert _owner_policy_metadata({"compliance_policy": owner()}, "c1", later)["status"] == "unknown"


def test_namespace_label_pair_and_unreadable_absence():
    cid = checks.LABEL_ID
    assert check(cid, ns({"team": "platform", "owner": "core"}))[0] == "PASS"
    status, evidence = check(cid, ns({"team": "platform"}))
    assert status == "FAIL" and evidence["mismatched_label_keys"] == ["owner"]
    assert check(cid, ns())[0] == "FAIL"  # Full API object omits unset map.
    assert check(cid, ns(full=False))[0] == "UNKNOWN"
    assert check(cid, ns({"team": 7}))[0] == "UNKNOWN"
    unknown_index = index({"status": "unknown", "reason": "owner_policy_missing"})
    assert check(cid, ns({"team": "platform", "owner": "core"}), unknown_index)[0] == "UNKNOWN"


def test_rolebinding_requires_exact_target_and_complete_inventory():
    cid = checks.ROLE_ID
    assert check(cid, ns(), index(roles=[("apps", "viewer")]))[0] == "PASS"
    assert check(cid, ns(), index(roles=[("other", "viewer")]))[0] == "FAIL"
    assert check(cid, ns(), index(role_status="denied"))[0] == "UNKNOWN"
    assert check(cid, ns(), index(role_status="partial"))[0] == "UNKNOWN"
    assert check(cid, {"metadata": {"name": "other"}}, index())[0] == "NOT_APPLICABLE"
    duplicate = index(roles=[("apps", "viewer"), ("apps", "viewer")])
    assert check(cid, ns(), duplicate)[0] == "PASS"  # Presence, not count.
    malformed = index(roles=[("apps", "viewer")])
    malformed["rolebinding"][0]["data"]["metadata"]["namespace"] = 3
    assert check(cid, ns(), malformed)[0] == "UNKNOWN"


def test_authorized_namespace_only_for_loadbalancer_declaration():
    cid = checks.AUTHORIZED_ID
    assert check(cid, svc())[0] == "PASS"
    status, evidence = check(cid, svc(namespace="other"))
    assert status == "FAIL" and evidence["namespace"] == "other"
    assert check(cid, svc(namespace="other", kind="ClusterIP"))[0] == "NOT_APPLICABLE"
    assert check(cid, svc(kind="Mystery"))[0] == "UNKNOWN"
    bad = deepcopy(svc())
    del bad["metadata"]["uid"]
    assert check(cid, bad)[0] == "UNKNOWN"


def test_required_type_and_selected_uid_are_distinct_owner_policies():
    assert check(checks.TYPE_ID, svc())[0] == "PASS"
    assert check(checks.TYPE_ID, svc(kind="ClusterIP"))[0] == "FAIL"
    assert check(checks.SELECTED_ID, {"scope": "*"})[0] == "PASS"
    status, evidence = check(checks.SELECTED_ID, {"scope": "*"}, index(services=[svc(kind="ClusterIP")]))
    assert status == "FAIL" and evidence["wrong_type_count"] == 1
    assert check(checks.SELECTED_ID, {"scope": "*"}, index(services=[svc(uid="recreated")]))[0] == "UNKNOWN"
    status, evidence = check(checks.SELECTED_ID, {"scope": "*"}, index(services=[svc(name="other")]))
    assert status == "UNKNOWN" and evidence["missing_count"] == 1
    assert check(checks.SELECTED_ID, {"scope": "*"}, index(services=[], service_status="empty"))[0] == "UNKNOWN"
    assert check(checks.SELECTED_ID, {"scope": "*"}, index(service_status="denied"))[0] == "UNKNOWN"
    unknown = index({"status": "unknown", "reason": "owner_service_type_policy_conflicting"})
    assert check(checks.TYPE_ID, svc(), unknown)[0] == "UNKNOWN"
    assert check(checks.SELECTED_ID, {"scope": "*"}, unknown)[0] == "UNKNOWN"


def test_service_conflict_does_not_suppress_independent_namespace_rules():
    conflict = _owner_policy_metadata({"compliance_policy": owner(serviceType="ClusterIP")}, "c1", NOW.isoformat())
    assessment = index(conflict, roles=[("apps", "viewer")])
    assert check(checks.LABEL_ID, ns({"team": "platform", "owner": "core"}), assessment)[0] == "PASS"
    assert check(checks.ROLE_ID, ns(), assessment)[0] == "PASS"
    for cid in (checks.AUTHORIZED_ID, checks.TYPE_ID):
        assert check(cid, svc(), assessment)[0] == "UNKNOWN"
    assert check(checks.SELECTED_ID, {"scope": "*"}, assessment)[0] == "UNKNOWN"


def test_large_owner_sets_are_indexed_once_per_scoped_evaluation_without_repeating_policy():
    selected = [{"namespace": "apps", "name": f"app-{i}", "uid": f"uid-{i}"} for i in range(3000)]
    policy = _owner_policy_metadata({"compliance_policy": owner(max_policy_items=7000,
                            authorized_namespaces=[f"team-{i}" for i in range(3000)],
                            selected_loadbalancer_services=selected)}, "c1", NOW.isoformat())
    assert policy["status"] == "collected"
    shared = MemoIndex(index(policy))
    for i in (0, 1500, 2999):
        item = svc(name=f"app-{i}", uid=f"uid-{i}")
        status, evidence = check(checks.AUTHORIZED_ID, item, shared)
        assert status == "FAIL" and evidence["authorized_namespace_count"] == 3000
        assert "authorized_namespaces" not in evidence
    shared["service"] = [{"data": svc(name=f"app-{i}", uid=f"uid-{i}")} for i in range(3000)]
    status, evidence = check(checks.SELECTED_ID, {"scope": "*"}, shared)
    assert status == "PASS" and evidence["assessed_count"] == 3000
    assert {"owner_policy_validated", "owner_policy_authorized_namespaces", "owner_policy_selected_service_identities"} <= {key[0] for key in shared.memo}
    assert len(shared.memo[("owner_policy_selected_service_identities",)][1]) == 3000


def test_offline_naive_datetime_cannot_produce_a_policy_verdict():
    assessment = index()
    assessment["context"]["created_at"] = "2026-10-12T00:00:00"
    assert check(checks.LABEL_ID, ns({"team": "platform", "owner": "core"}), assessment)[0] == "UNKNOWN"
    assessment = index()
    assessment["context"]["metadata"]["compliance_policy"]["observed_at"] = "2026-10-12T00:00:00"
    assert check(checks.LABEL_ID, ns({"team": "platform", "owner": "core"}), assessment)[0] == "UNKNOWN"


def test_selected_scope_omission_and_restricted_namespace_are_visible_unknown():
    selected = _owner_policy_metadata({"compliance_policy": owner(
        selected_loadbalancer_services=[{"namespace": "apps", "name": "web", "uid": "uid-1"},
                                        {"namespace": "other", "name": "api", "uid": "uid-2"}])}, "c1", NOW.isoformat())
    assessed = index(selected, services=[svc()], scope="apps")
    status, evidence = check(checks.SELECTED_ID, {"scope": "apps"}, assessed)
    assert status == "UNKNOWN" and evidence["outside_scanned_scope_count"] == 1
    assert evidence["assessed_count"] == 1
    status, evidence = check(checks.SELECTED_ID, {"scope": "other"}, index(selected, services=[], service_status="empty"))
    assert status == "UNKNOWN" and evidence["missing_count"] == 1
    assert evidence["missing_examples"][0]["selected_uid"] == "uid-2"
    status, evidence = check(checks.SELECTED_ID, {"scope": "apps"}, index(selected, services=[svc(kind="NodePort")]))
    assert status == "FAIL" and evidence["wrong_type_count"] == 1 and evidence["outside_scanned_scope_count"] == 1


def test_policy_parameter_absence_and_stale_snapshot_are_unknown():
    parsed = _owner_policy_metadata({"compliance_policy": owner()}, "c1", NOW.isoformat())
    del parsed["authorized_namespaces"]
    assert check(checks.AUTHORIZED_ID, svc(), index(parsed))[0] == "UNKNOWN"
    stale = index()
    stale["context"]["created_at"] = (NOW + timedelta(hours=1)).isoformat()
    assert check(checks.LABEL_ID, ns({"team": "platform", "owner": "core"}), stale)[0] == "UNKNOWN"


def test_collector_to_engine_keeps_typed_policy_and_complete_paged_inventory():
    class API:
        api_client = SimpleNamespace(configuration=SimpleNamespace(host="https://fixture.invalid"))

        def __init__(self):
            self.calls = []

        def get_json(self, path, params=None):
            self.calls.append((path, dict(params or {})))
            if path.endswith("/namespaces"):
                rows = [{"metadata": {"name": "apps", "uid": "ns-1",
                                      "labels": {"team": "platform", "owner": "core"}}}]
            elif path.endswith("/rolebindings"):
                rows = [{"metadata": {"namespace": "apps", "name": "viewer", "uid": "rb-1"}}]
            elif path.endswith("/services"):
                rows = [{"metadata": {"namespace": "apps", "name": "web", "uid": "uid-1"},
                         "spec": {"type": "LoadBalancer"}}]
            else:
                raise AssertionError(path)
            return {"metadata": {"resourceVersion": "7"}, "items": rows}

    timestamp = datetime.now(timezone.utc).isoformat()
    policy = owner(observed_at=timestamp, max_age_seconds=600)
    api = API()
    snapshot = k8s.collect({"provider": "k8s", "auth": {"cluster_id": "c1"}, "scopes": ["*"],
                            "options": {"inventories": ["namespace", "rolebinding", "service"],
                                        "compliance_policy": policy}}, api=api)
    assert snapshot["metadata"]["compliance_policy"]["status"] == "collected"
    assert len(api.calls) == 3 and all("limit" in params for _, params in api.calls)
    report = evaluate_snapshot(snapshot, checks=list(checks.IDS))
    assert report["stats"]["by_status"] == {"PASS": 5}
    assert {row["check_id"] for row in report["findings"]} == set(checks.IDS)
    foreign = deepcopy(snapshot)
    foreign["metadata"]["compliance_policy"]["cluster_id"] = "other"
    from peaso.snapshot import seal
    # Re-sealing only changes the snapshot digest; evaluation remains offline.
    foreign = seal(foreign)
    rejected = evaluate_snapshot(foreign, checks=list(checks.IDS))
    assert rejected["stats"]["by_status"] == {"UNKNOWN": 5}

    restricted = owner(observed_at=timestamp, selected_loadbalancer_services=[
        {"namespace": "apps", "name": "web", "uid": "uid-1"},
        {"namespace": "other", "name": "api", "uid": "uid-2"}])
    limited = k8s.collect({"provider": "k8s", "auth": {"cluster_id": "c1"}, "scopes": ["apps"],
                           "options": {"inventories": ["service"], "compliance_policy": restricted}}, api=API())
    report = evaluate_snapshot(limited, checks=[checks.SELECTED_ID])
    assert report["stats"]["by_status"] == {"UNKNOWN": 1}
    assert report["findings"][0]["evidence"]["outside_scanned_scope_count"] == 1
