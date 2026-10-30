"""Inert normal planner/collector/engine Cloud SQL managed lockout witnesses."""
import copy
import json
from peaso.collectors import gcp
from tests.archived_check_contract import collect_snapshot, evaluate_snapshot
from peaso.snapshot import seal

CID = "gcp_cloudsql_failed_attempts_lockout"

class API:
    def __init__(self, mode="valid"):
        self.mode, self.requests, self.evidence = mode, [], []
    def request(self, method, url, **kwargs):
        request_id = "req-" + str(len(self.requests) + 1)
        self.requests.append({"method": method, "url": url, **kwargs})
        assert method == "GET"
        if url.endswith("/instances"):
            row = {"name": "db1", "project": "p-one", "state": "RUNNABLE",
                   "databaseVersion": "MYSQL_8_0", "instanceType": "CLOUD_SQL_INSTANCE",
                   "settings": {"passwordValidationPolicy": {"enablePasswordPolicy": True}}}
            if self.mode.startswith("version:"):
                row["databaseVersion"] = self.mode.split(":", 1)[1]
            if self.mode == "disabled_instance":
                row["settings"]["passwordValidationPolicy"]["enablePasswordPolicy"] = False
            if self.mode == "fake_instance":
                row["settings"]["passwordValidationPolicy"] = {"failedAttemptsCheck": True}
            if self.mode == "replica":
                row["masterInstanceName"] = "primary-db"
            if self.mode == "stopped":
                row["state"] = "SUSPENDED"
            data = {"items": [row]}
        else:
            assert url == "https://sqladmin.googleapis.com/sql/v1beta4/projects/p-one/instances/db1/users"
            if self.mode == "denied":
                error = gcp.ReadError("denied", "inert_users_denied")
                error.request_id = request_id
                self.evidence.append({"id": request_id, "method": method, "url": url, "status": "denied"})
                raise error
            user = {"name": "test-user", "host": "%", "type": "BUILT_IN", "instance": "db1", "project": "p-one",
                    "passwordPolicy": {"enableFailedAttemptsCheck": True, "allowedFailedAttempts": 5}}
            other = {**copy.deepcopy(user), "name": "second-user"}
            rows = [user, other]
            if self.mode == "hosts":
                other["name"], other["host"] = user["name"], "localhost"
            if self.mode == "disabled_user":
                user["passwordPolicy"]["enableFailedAttemptsCheck"] = False
            if self.mode.startswith("threshold:"):
                user["passwordPolicy"]["allowedFailedAttempts"] = json.loads(self.mode.split(":", 1)[1])
            if self.mode == "iam":
                other["type"] = "CLOUD_IAM_USER"
            if self.mode == "foreign":
                other["project"] = "foreign"
            if self.mode == "duplicate":
                other = copy.deepcopy(user); other["passwordPolicy"]["enableFailedAttemptsCheck"] = False
                rows = [user, other]
            if self.mode == "empty":
                rows = []
            data = {"kind": "sql#usersList", "items": rows}
            if self.mode == "partial":
                data["warning"] = {"code": "INCOMPLETE"}
        self.evidence.append({"id": request_id, "method": method, "url": url, "status": "collected"})
        return copy.deepcopy(data), request_id
    def close(self):
        pass

def observe(monkeypatch, mode="valid", mutate=None, approved_scope=None, return_snapshot=False):
    api = API(mode)
    monkeypatch.setattr(gcp, "Credentials", lambda *a, **k: None)
    monkeypatch.setattr(gcp, "Transport", lambda *a, **k: api)
    request = {"connector": {"provider": "gcp", "scopes": ["projects/p-one"],
               "options": {"include_inherited": False, "concurrency": 1}}, "checks": [CID]}
    if approved_scope is not None:
        request["connector"]["options"]["sw09_policy"] = {"status": "collected", "scope": "projects/p-one", "lockout_account_scopes": {"db1": approved_scope}}
    snapshot = collect_snapshot(request)
    if mutate:
        mutate(snapshot)
        snapshot = seal(snapshot)
    result = evaluate_snapshot(snapshot, checks=[CID], include_not_applicable=True)
    rows = [f for f in result["findings"] if f["check_id"] == CID]
    assert len(rows) == 1
    assert len(api.requests) == 2 and all(r["method"] == "GET" for r in api.requests)
    return (rows[0], snapshot) if return_snapshot else rows[0]

def witness(finding):
    assert finding["status"] == "UNKNOWN"
    return finding["evidence"]["native_lockout_witness"]

def test_native_policy_witness_does_not_claim_whole_original_scope(monkeypatch):
    finding = observe(monkeypatch)
    proof = witness(finding)
    assert proof["configured_builtin_user_count"] == 2
    assert proof["api_visible_account_count"] == 2
    assert proof["scope_authority"] == "original_principal_universe_unresolved"
    assert "test-user" not in json.dumps(finding["evidence"])
    assert "second-user" not in json.dumps(finding["evidence"])

def test_host_qualified_accounts_remain_distinct(monkeypatch):
    assert witness(observe(monkeypatch, "hosts"))["configured_builtin_user_count"] == 2

def test_disabled_policy_is_not_violation_of_unknown_rate_limiting(monkeypatch):
    for mode in ("disabled_user", "disabled_instance", "fake_instance"):
        assert observe(monkeypatch, mode)["status"] == "UNKNOWN"

def test_malformed_threshold_never_supplies_witness(monkeypatch):
    for value in ("0", "-1", "true", '\"5\"', "null"):
        finding = observe(monkeypatch, "threshold:" + value)
        assert finding["status"] == "UNKNOWN"
        assert finding["evidence"].get("native_lockout_witness", {}).get("configured_builtin_user_count", 0) < 2

def test_mixed_authentication_does_not_expand_builtin_scope(monkeypatch):
    proof = witness(observe(monkeypatch, "iam"))
    assert proof["configured_builtin_user_count"] == 1
    assert proof["unsupported_authentication_type_count"] == 1

def test_denied_partial_source_cannot_supply_complete_witness(monkeypatch):
    for mode in ("denied", "partial"):
        finding = observe(monkeypatch, mode)
        assert finding["status"] == "UNKNOWN"
        assert "native_lockout_witness" not in finding["evidence"]

def test_foreign_and_conflicting_users_are_rejected_before_classification(monkeypatch):
    for mode in ("foreign", "duplicate"):
        finding = observe(monkeypatch, mode)
        assert finding["status"] == "UNKNOWN"
        assert "native_lockout_witness" not in finding["evidence"]

def test_unsupported_engines_and_state_are_not_inapplicable_security(monkeypatch):
    for mode in ("version:MYSQL_5_7", "version:POSTGRES_17", "version:SQLSERVER_2019_STANDARD", "replica", "stopped"):
        assert observe(monkeypatch, mode)["status"] == "UNKNOWN"

def test_empty_inventory_does_not_vacuously_prove_lockout(monkeypatch):
    finding = observe(monkeypatch, "empty")
    assert finding["status"] == "UNKNOWN"
    assert "native_lockout_witness" not in finding["evidence"]

def test_foreign_capture_cannot_supply_bound_configuration(monkeypatch):
    def mutate(snapshot):
        envelope = next(c for c in snapshot["collections"] if c["type"] == "sql_instance")
        envelope["items"][0]["usersList"]["items"][0]["_provenance"]["scope"] = "projects/foreign"
    finding = observe(monkeypatch, mutate=mutate)
    assert finding["status"] == "UNKNOWN"
    assert "native_lockout_witness" not in finding["evidence"]


def test_current_capture_and_exact_users_operation_are_required(monkeypatch):
    def stale(snapshot):
        instance = next(c for c in snapshot["collections"] if c["type"] == "sql_instance")["items"][0]
        for row in [instance, *instance["usersList"]["items"]]:
            row["_provenance"]["collected_at"] = "2020-01-01T00:00:00Z"
    def wrong_operation(snapshot):
        refs = next(c for c in snapshot["collections"] if c["type"] == "sql_instance")["items"][0]["usersList"]["source_requests"]
        for source in snapshot["metadata"]["source_requests"]:
            if source["id"] in refs:
                source["url"] = source["url"].replace("/db1/users", "/foreign-db/users")
    for mutate in (stale, wrong_operation):
        finding = observe(monkeypatch, mutate=mutate)
        assert finding["status"] == "UNKNOWN"
        assert "native_lockout_witness" not in finding["evidence"]


def approved_accounts(hosts=False):
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    return {"approved_by": "fixture-owner-not-provider-observation", "evidence_ref": "fixture:approved-customer-account-scope",
            "reviewed_at": (now-timedelta(hours=1)).isoformat(), "expires_at": (now+timedelta(days=1)).isoformat(),
            "responsibility": "customer-controlled-database-accounts",
            "accounts": [{"name": "test-user", "host": "%", "type": "BUILT_IN"},
                         {"name": "test-user" if hosts else "second-user", "host": "localhost" if hosts else "%", "type": "BUILT_IN"}]}

def test_approved_exact_customer_scope_supports_original_configured_positive(monkeypatch):
    for mode in ("valid", "hosts"):
        finding = observe(monkeypatch, mode, approved_scope=approved_accounts(mode=="hosts"))
        assert finding["status"] == "PASS"
        assert finding["evidence"]["native_lockout_witness"]["configured_builtin_user_count"] == 2
        assert finding["evidence"]["approved_scope"]["responsibility"] == "customer-controlled-database-accounts"
        assert "runtime" in finding["evidence"]["native_lockout_witness"]["claim"]

def test_approved_scope_cannot_hide_unmatched_or_unsupported_accounts(monkeypatch):
    for mutation in ("subset", "extra", "duplicate", "wrong-host", "wrong-type", "expired", "future-review", "missing-approval", "wrong-responsibility"):
        scope = approved_accounts()
        if mutation == "subset": scope["accounts"].pop()
        elif mutation == "extra": scope["accounts"].append({"name":"unobserved", "host":"%", "type":"BUILT_IN"})
        elif mutation == "duplicate": scope["accounts"].append(copy.deepcopy(scope["accounts"][0]))
        elif mutation == "wrong-host": scope["accounts"][0]["host"] = "elsewhere"
        elif mutation == "wrong-type": scope["accounts"][0]["type"] = "CLOUD_IAM_USER"
        elif mutation == "expired": scope["expires_at"] = "2020-01-01T00:00:00Z"
        elif mutation == "future-review": scope["reviewed_at"] = "2099-01-01T00:00:00Z"
        elif mutation == "missing-approval": del scope["approved_by"]
        elif mutation == "wrong-responsibility": scope["responsibility"] = "all-provider-system-accounts"
        finding = observe(monkeypatch, approved_scope=scope)
        assert finding["status"] == "UNKNOWN"
        assert finding["evidence"]["native_lockout_witness"]["configured_builtin_user_count"] == 2

def test_approved_roster_never_overrides_native_policy_or_source_gap(monkeypatch):
    for mode in ("iam", "disabled_user", "threshold:0", "denied", "partial", "foreign", "duplicate", "version:MYSQL_5_7"):
        assert observe(monkeypatch, mode, approved_scope=approved_accounts())["status"] == "UNKNOWN"
