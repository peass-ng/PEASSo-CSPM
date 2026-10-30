# Historical fixture contracts; current native admission is tested separately.
"""Provider-shaped Cosmos backup retention cases bound to an approved owner minimum."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from peaso.checks import CHECKS, evaluate_check
from peaso.checks import compliance_new_azure_data_protection as new
from peaso.collectors.azure import _cosmos_backup_retention_policy
from peaso.collectors import azure
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot


SCOPE = "/subscriptions/sub"
BASE = SCOPE + "/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/"
NOW = datetime(2026, 10, 12, tzinfo=timezone.utc)


def test_cosmos_check_imports_with_supported_hardening_category():
    registered = [check for check in CHECKS if check.id == new.COSMOS_ID]
    assert len(registered) == 1
    assert registered[0].category == "hardening"


def account(name, backup):
    return {"id": BASE + name, "name": name, "type": "Microsoft.DocumentDB/databaseAccounts",
            "properties": {"backupPolicy": backup}}


def periodic(hours):
    return {"type": "Periodic", "periodicModeProperties": {"backupRetentionIntervalInHours": hours}}


def continuous(tier):
    return {"type": "Continuous", "continuousModeProperties": {"tier": tier}}


def owner(names=("a",), *, minimum=7, observed=None):
    return {"status": "collected", "observed_at": observed or NOW.isoformat(),
            "max_age_seconds": 600, "max_policy_items": 10,
            "accounts": [{"subscription_scope": SCOPE, "resource_id": BASE + name,
                          "min_retention_days": minimum} for name in names]}


def indexed(accounts, *, policy=None, status="collected"):
    return {"context": {"scope": SCOPE, "created_at": NOW.isoformat(),
                        "metadata": {"cosmos_backup_retention": owner() if policy is None else policy}},
            "collections": {"cosmos_account": [{"scope": SCOPE, "status": status}]},
            "cosmos_account": [{"data": row} for row in accounts]}


def verdict(accounts, **kwargs):
    return evaluate_check(new.COSMOS_ID, {"scope": SCOPE}, indexed(accounts, **kwargs))


def test_periodic_and_continuous_retention_are_compared_without_rounding_or_restore_claim():
    assert verdict([account("a", periodic(168))])[0] == "PASS"
    status, evidence = verdict([account("a", periodic(167))])
    assert status == "FAIL" and evidence["below_minimum_examples"][0]["observed_hours"] == 167
    assert "restore readiness unverified" in evidence["semantics"]
    assert verdict([account("a", continuous("Continuous7Days"))])[0] == "PASS"
    assert verdict([account("a", continuous("Continuous30Days"))], policy=owner(minimum=30))[0] == "PASS"
    assert verdict([account("a", continuous("Continuous7Days"))], policy=owner(minimum=30))[0] == "FAIL"


def test_missing_malformed_or_unrecognized_facts_are_unknown():
    for backup in ({}, {"type": "Unrecognized"}, periodic(0), periodic(-1), periodic("168"),
                   continuous("FutureTier"), {"type": "Continuous"}):
        assert verdict([account("a", backup)])[0] == "UNKNOWN"
    assert verdict([account("a", periodic(168))], status="denied")[0] == "UNKNOWN"
    assert verdict([account("a", periodic(168))], status="partial")[0] == "UNKNOWN"


def test_missing_or_foreign_owner_threshold_and_stale_input_are_unknown():
    row = account("a", periodic(168))
    assert verdict([row], policy={"status": "unknown", "reason": "owner_input_missing"})[0] == "UNKNOWN"
    assert verdict([row], policy=owner(("other",)))[0] == "UNKNOWN"
    assert verdict([row], policy=owner(observed=(NOW - timedelta(hours=1)).isoformat()))[0] == "UNKNOWN"
    for mutate in (
        lambda p: p["accounts"][0].update(min_retention_days=True),
        lambda p: p["accounts"][0].update(subscription_scope="/subscriptions/other"),
        lambda p: p["accounts"].append(deepcopy(p["accounts"][0])),
        lambda p: p.update(max_policy_items=0),
    ):
        policy = owner()
        mutate(policy)
        assert verdict([row], policy=policy)[0] == "UNKNOWN"


def test_collector_whitelists_persistent_exact_account_owner_input_across_later_scan():
    desired = owner()
    del desired["status"], desired["observed_at"], desired["max_age_seconds"]
    later = (NOW + timedelta(days=14)).isoformat()
    options = {"compliance_policy": {"cosmos_backup_retention": desired}}
    parsed = _cosmos_backup_retention_policy(options, [SCOPE], later)
    assert parsed["status"] == "collected" and "observed_at" not in parsed
    assessment = indexed([account("a", periodic(168))], policy=parsed)
    assessment["context"]["created_at"] = later
    assert evaluate_check(new.COSMOS_ID, {"scope": SCOPE}, assessment)[0] == "PASS"
    bad = deepcopy(desired)
    bad["observed_at"] = NOW.isoformat()
    assert _cosmos_backup_retention_policy({"compliance_policy": {"cosmos_backup_retention": bad}}, [SCOPE], later)["status"] == "unknown"
    bad = deepcopy(desired)
    bad["accounts"][0]["subscription_scope"] = "/subscriptions/other"
    assert _cosmos_backup_retention_policy({"compliance_policy": {"cosmos_backup_retention": bad}}, [SCOPE], later)["status"] == "unknown"
    expiring = owner()
    del expiring["status"]
    assert _cosmos_backup_retention_policy({"compliance_policy": {"cosmos_backup_retention": expiring}}, [SCOPE], later)["status"] == "unknown"
    many = deepcopy(desired)
    many["accounts"] = [{"subscription_scope": SCOPE, "resource_id": BASE + f"account-{i:04d}",
                         "min_retention_days": 7} for i in range(1201)]
    many["max_policy_items"] = len(many["accounts"])
    assert _cosmos_backup_retention_policy({"compliance_policy": {"cosmos_backup_retention": many}}, [SCOPE], later)["status"] == "collected"


def test_definite_failure_precedes_unknown_and_empty_inventory_is_not_applicable():
    rows = [account("a", periodic(24)), account("b", {"type": "Continuous"})]
    status, evidence = verdict(rows, policy=owner(("a", "b")))
    assert status == "FAIL" and evidence["below_minimum_count"] == 1 and evidence["unresolved_count"] == 1
    assert verdict([], policy=owner())[0] == "NOT_APPLICABLE"
    assert verdict([account("a", periodic(168))], policy=owner(("a", "b")))[0] == "UNKNOWN"


def test_engine_scope_result_is_distinct_and_missing_policy_remains_unknown():
    row = account("a", continuous("Continuous7Days"))
    snapshot = make_snapshot("azure", [SCOPE], [{"type": "cosmos_account", "scope": SCOPE,
                           "service": "Microsoft.DocumentDB", "status": "collected", "items": [row]}],
                           created_at=NOW.isoformat(), metadata={"cosmos_backup_retention": owner()})
    report = evaluate_snapshot(snapshot, checks=[new.COSMOS_ID])
    assert report["stats"]["by_status"] == {"PASS": 1}
    assert report["findings"][0]["check_id"] == new.COSMOS_ID
    snapshot["metadata"]["cosmos_backup_retention"] = {"status": "unknown", "reason": "missing"}
    snapshot.pop("snapshot_id")  # The changed fixture must be resealed by evaluate_snapshot.
    report = evaluate_snapshot(snapshot, checks=[new.COSMOS_ID])
    assert report["stats"]["by_status"] == {"UNKNOWN": 1}


def test_existing_azure_account_collector_and_typed_policy_reach_engine():
    class AccountTransport:
        tenant = "tenant-fixture"

        def __init__(self):
            self.calls = []

        def request(self, url, *, body=None, audience=azure.ARM):
            self.calls.append((url, body, audience))
            assert audience == azure.ARM
            path = urlsplit(url).path
            if path == "/providers/Microsoft.ResourceGraph/resources":
                assert body is not None and body["subscriptions"] == ["sub"]
                return {"data": [], "resultTruncated": "false"}
            if path == SCOPE + "/providers/Microsoft.DocumentDB/databaseAccounts":
                assert body is None
                return {"value": [account("a", continuous("Continuous30Days"))]}
            if path == BASE + "a/providers/Microsoft.Insights/diagnosticSettings":
                return {"value": []}
            raise AssertionError("unexpected Azure read: " + path)

    desired = owner(minimum=30)
    del desired["status"], desired["observed_at"], desired["max_age_seconds"]
    transport = AccountTransport()
    snapshot = azure.collect({"scopes": ["sub"], "options": {"compliance_policy": {
                             "cosmos_backup_retention": desired}}}, ["cosmos_account"], transport=transport)
    assert snapshot["metadata"]["cosmos_backup_retention"]["status"] == "collected"
    assert sum(urlsplit(url).path == SCOPE + "/providers/Microsoft.DocumentDB/databaseAccounts"
               for url, _, _ in transport.calls) == 1
    report = evaluate_snapshot(snapshot, checks=[new.COSMOS_ID])
    assert report["stats"]["by_status"] == {"PASS": 1}
