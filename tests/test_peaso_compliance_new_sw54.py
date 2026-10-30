"""Standalone draft tests for sw54; run this file alone with --noconftest."""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from peaso.checks import CHECKS, evaluate_check
from peaso.checks import compliance_new_sw54 as checks

PROJECT = "projects/demo"
ORG = "organizations/123"
NOW = datetime(2026, 10, 12, tzinfo=timezone.utc)


@pytest.fixture(scope="module", autouse=True)
def remove_draft_registrations():
    yield
    CHECKS[:] = [check for check in CHECKS if check.id not in checks.IDS]


def iso(days=0, hours=0):
    return (NOW + timedelta(days=days, hours=hours)).isoformat()


def index(kind, rows, *, scope=PROJECT, policy=None, other=None, status="collected"):
    facts = {"context": {"provider": "gcp", "scope": scope, "created_at": iso(),
        "metadata": {"compliance_policy": {"status": "collected", "scope": scope, **(policy or {})}}},
        "collections": {}}
    entries = {kind: (rows, status), **(other or {})}
    for k, (items, state) in entries.items():
        facts["collections"][k] = [{"type": k, "scope": scope, "status": state, "items": items}]
        facts[k] = [{"type": k, "scope": scope, "data": row} for row in items]
    return facts


def evaluate(check_id, item, facts):
    return evaluate_check(check_id, item, facts)[0]


def log_setup(mode, *, fail=False):
    one = {"name": PROJECT + "/sinks/a", "destination": "storage.googleapis.com/logs",
           "disabled": False, "filter": "", "exclusions": []}
    two = {"name": PROJECT + "/sinks/b", "destination": "storage.googleapis.com/logs2",
           "disabled": False, "filter": "", "exclusions": []}
    p = {"logging": {"ancestor_inventory_complete": True, "ancestor_sinks": [],
        "customer_data_buckets": ["customer"], "separation_exceptions": [],
        "bucket_register_complete": True, "required_log_classes": ["audit.read"],
        "critical_log_classes": ["audit.read"], "require_two_destinations": True,
        "independent_destination_pairs": [{"destinations": ["storage.googleapis.com/logs", "storage.googleapis.com/logs2"]}],
        "approved_customer_destination": "storage.googleapis.com/logs",
        "approved_siem_destination": "storage.googleapis.com/logs"}}
    rows = [one, two]
    if mode == "isolation":
        one["destination"] = "storage.googleapis.com/customer" if fail else "storage.googleapis.com/logs"
    elif mode == "redundancy":
        if fail: rows = [one]
    elif mode in ("export", "siem"):
        if fail: one["disabled"] = True
    facts = index("log_sink", rows, policy=p)
    return facts["context"], facts


def cert_pem(days_old):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.test")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=days_old))
        .not_valid_after(NOW + timedelta(days=100)).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def cert_setup(mode, *, fail=False):
    row = {"name": PROJECT + "/locations/global/certificates/a", "createTime": iso(-181 if fail else -30),
        "expireTime": iso(-31 if fail else 100), "managed": {"state": "ACTIVE", "domains": ["example.test"]},
        "deployment": {"status": "collected", "deployed": True, "replacement_inventory_complete": True,
            "replacements": []}, "pemCertificate": cert_pem(91 if fail else 30)}
    if mode == "renewal" and not fail:
        row["expireTime"] = iso(-31)
        row["deployment"]["replacements"] = [{"name": PROJECT + "/locations/global/certificates/b",
            "state": "ACTIVE", "domains": ["example.test"], "deployedAt": iso(-61)}]
    return row, index("certificate", [row])


def build_setup(mode, *, fail=False):
    row = {"id": "trigger-a", "approvalConfig": {"approvalRequired": not fail},
           "buildDefinition": {"status": "collected", "steps": ([] if fail else [{"id": "security-test"}])}}
    p = {"cloudbuild": {"deployment_coverage": "cloudbuild_only",
        "production_trigger_ids": ["trigger-a"], "production_trigger_scope_complete": True,
        "approval_required": True,
        "security_test_step": "security-test"}}
    build = {"id": "build-a", "triggerId": "trigger-a", "productionDeployment": True,
             "status": "FAILURE" if fail else "SUCCESS",
             "sourceProvenance": {"resolvedRepoSource": {"commitSha": "abc"}},
             "substitutions": {"COMMIT_SHA": "abc"}}
    return row, index("cloudbuild_trigger", [row], policy=p,
                      other={"cloudbuild_build": ([build], "collected")})


def workforce_setup(mode, *, fail=False):
    pool = {"name": "locations/global/workforcePools/customer", "state": "INACTIVE" if fail and mode == "federation" else "ACTIVE"}
    provider = {"name": pool["name"] + "/providers/oidc", "state": "ACTIVE",
        "oidc": {"issuerUri": "https://issuer.test", "allowedAudiences": ["aud"]},
        "attributeMapping": {"attribute.mfa": "assertion.mfa" if not fail else "assertion.sub"}}
    p = {"workforce": {"mapping_complete": True, "customer_provider_mapping": [{"pool": pool["name"], "provider": provider["name"],
        "issuer": "https://issuer.test", "audiences": ["aud"], "mfa_claim": "attribute.mfa",
        "mfa_mapping": "assertion.mfa", "idp_assurance_verified": True}]}}
    return pool, index("workforce_pool", [pool], scope=ORG, policy=p,
                       other={"workforce_provider": ([provider], "collected")})


def gke_setup(*, fail=False):
    url = "https://compute.googleapis.com/compute/v1/projects/demo/zones/us-central1-a/instanceGroups/pool"
    row = {"name": PROJECT + "/locations/us-central1/clusters/a", "nodePools": [
        {"name": "pool", "management": {"autoUpgrade": not fail}, "instanceGroupUrls": [url]}]}
    manager = {"instanceGroup": url, "targetSize": 2}
    return row, index("gke_cluster", [row], other={"instance_group_manager": ([manager], "collected")})


def alert_setup(mode, *, fail=False):
    project = {"projectId": "demo"}
    filter_value = ({"kms": 'protoPayload.methodName="DisableCryptoKeyVersion" OR protoPayload.methodName="DestroyCryptoKeyVersion"',
        "enumeration": 'protoPayload.methodName =~ "\\.(list|get)$"',
        "query": 'protoPayload.methodName="logging.entries.list"'}[mode])
    metric = {"name": PROJECT + "/metrics/metric-a", "metricId": "metric-a", "filter": filter_value,
        "labelExtractors": {"principal": "EXTRACT(protoPayload.authenticationInfo.principalEmail)"}}
    alert = {"name": "alert-a", "enabled": not fail,
        "notificationChannels": ["channel"], "conditions": [{"conditionThreshold": {
            "filter": 'metric.type="logging.googleapis.com/user/metric-a"',
            "comparison": "COMPARISON_GT", "thresholdValue": 10,
            "aggregations": [{"alignmentPeriod": "300s", "perSeriesAligner": "ALIGN_SUM",
                             "groupByFields": ["metric.label.principal"]}]}}]}
    p = {"monitoring": {"approved_query_count": 10}}
    facts = index("logging_metric", [metric], policy=p,
        other={"alert_policy": ([alert], "collected")})
    return facts["context"], facts


CASES = {
    "gcp_kms_key_destroy_alert": lambda fail: alert_setup("kms", fail=fail),
    "gcp_logging_enumeration_alert": lambda fail: alert_setup("enumeration", fail=fail),
    "gcp_logging_query_rate_alert": lambda fail: alert_setup("query", fail=fail),
    "gcp_c5_log_export": lambda fail: log_setup("export", fail=fail),
    "gcp_c5_log_isolation": lambda fail: log_setup("isolation", fail=fail),
    "gcp_c5_logging_redundancy": lambda fail: log_setup("redundancy", fail=fail),
    "gcp_c5_siem_sink": lambda fail: log_setup("siem", fail=fail),
    "gcp_certificate_renewal_30_days": lambda fail: cert_setup("renewal", fail=fail),
    "gcp_certificate_rotation_180_days": lambda fail: cert_setup("180", fail=fail),
    "gcp_certificate_rotation_90_days": lambda fail: cert_setup("90", fail=fail),
    "gcp_c5_build_provenance": lambda fail: build_setup("provenance", fail=fail),
    "gcp_c5_cloudbuild_gate": lambda fail: build_setup("gate", fail=fail),
    "gcp_c5_workforce_federation": lambda fail: workforce_setup("federation", fail=fail),
    "gcp_iam_workforce_mfa": lambda fail: workforce_setup("mfa", fail=fail),
    "gcp_gke_small_cluster_auto_upgrade": lambda fail: gke_setup(fail=fail),
}


@pytest.mark.parametrize("check_id", list(CASES))
def test_pass_fail_and_missing_fact(check_id):
    safe, facts = CASES[check_id](False)
    assert evaluate(check_id, safe, facts) == "PASS"
    unsafe, facts = CASES[check_id](True)
    assert evaluate(check_id, unsafe, facts) == "FAIL"
    safe, facts = CASES[check_id](False)
    facts["collections"].pop(next(iter(facts["collections"])))
    assert evaluate(check_id, safe, facts) == "UNKNOWN"


@pytest.mark.parametrize("check_id", list(CASES))
def test_incomplete_malformed_and_foreign_scope(check_id):
    row, facts = CASES[check_id](False)
    main = next(iter(facts["collections"]))
    incomplete = copy.deepcopy(facts)
    incomplete["collections"][main][0]["status"] = "partial"
    assert evaluate(check_id, row, incomplete) == "UNKNOWN"
    malformed = copy.deepcopy(facts)
    malformed["collections"][main][0]["items"] = "bad"
    assert evaluate(check_id, row, malformed) == "UNKNOWN"
    foreign = copy.deepcopy(facts)
    foreign["context"]["scope"] = "projects/other" if facts["context"]["scope"] == PROJECT else "organizations/other"
    assert evaluate(check_id, row, foreign) == "UNKNOWN"


@pytest.mark.parametrize("check_id", [
    "gcp_certificate_renewal_30_days", "gcp_certificate_rotation_180_days", "gcp_certificate_rotation_90_days"])
def test_undeployed_certificate_not_applicable(check_id):
    row, facts = CASES[check_id](False)
    row["deployment"]["deployed"] = False
    assert evaluate(check_id, row, facts) == "NOT_APPLICABLE"


@pytest.mark.parametrize("check_id", ["gcp_c5_build_provenance", "gcp_c5_cloudbuild_gate"])
def test_out_of_scope_trigger_not_applicable(check_id):
    row, facts = CASES[check_id](False)
    facts["context"]["metadata"]["compliance_policy"]["cloudbuild"]["production_trigger_ids"] = []
    assert evaluate(check_id, row, facts) == "NOT_APPLICABLE"


@pytest.mark.parametrize("check_id", ["gcp_c5_workforce_federation", "gcp_iam_workforce_mfa"])
def test_unmapped_pool_not_applicable(check_id):
    row, facts = CASES[check_id](False)
    facts["context"]["metadata"]["compliance_policy"]["workforce"]["customer_provider_mapping"] = []
    assert evaluate(check_id, row, facts) == "NOT_APPLICABLE"


@pytest.mark.parametrize("check_id", list(CASES))
def test_malformed_required_native_field_is_unknown(check_id):
    row, facts = CASES[check_id](False)
    if check_id.startswith("gcp_logging_") or check_id == "gcp_kms_key_destroy_alert":
        facts["logging_metric"][0]["data"]["filter"] = ["bad"]
    elif check_id.startswith("gcp_c5_log") or check_id == "gcp_c5_siem_sink":
        facts["log_sink"][0]["data"]["disabled"] = "false"
    elif check_id.startswith("gcp_certificate_"):
        row["deployment"]["deployed"] = "yes"
    elif check_id.startswith("gcp_c5_build") or check_id == "gcp_c5_cloudbuild_gate":
        facts["context"]["metadata"]["compliance_policy"]["cloudbuild"]["production_trigger_ids"] = [23]
    elif check_id in ("gcp_c5_workforce_federation", "gcp_iam_workforce_mfa"):
        facts["workforce_provider"][0]["data"]["state"] = []
    else:
        row["nodePools"][0]["management"]["autoUpgrade"] = "yes"
    assert evaluate(check_id, row, facts) == "UNKNOWN"


def test_redundancy_requires_approved_independent_pair():
    row, facts = log_setup("redundancy")
    facts["context"]["metadata"]["compliance_policy"]["logging"]["independent_destination_pairs"] = []
    assert evaluate("gcp_c5_logging_redundancy", row, facts) == "UNKNOWN"


def test_redundancy_not_applicable_without_two_destination_requirement():
    row, facts = log_setup("redundancy")
    facts["context"]["metadata"]["compliance_policy"]["logging"]["require_two_destinations"] = False
    assert evaluate("gcp_c5_logging_redundancy", row, facts) == "NOT_APPLICABLE"


def test_renewal_waits_for_full_24_hour_window():
    row, facts = cert_setup("renewal", fail=True)
    row["expireTime"] = iso(days=29, hours=12)
    assert evaluate("gcp_certificate_renewal_30_days", row, facts) == "UNKNOWN"


def test_cert_rotation_90_does_not_use_resource_create_time():
    row, facts = cert_setup("90")
    row["createTime"] = iso(-400)
    assert evaluate("gcp_certificate_rotation_90_days", row, facts) == "PASS"
    row["pemCertificate"] = "not a certificate"
    assert evaluate("gcp_certificate_rotation_90_days", row, facts) == "UNKNOWN"


def test_production_builds_outside_cloudbuild_are_unknown():
    for check_id in ("gcp_c5_build_provenance", "gcp_c5_cloudbuild_gate"):
        row, facts = CASES[check_id](False)
        facts["context"]["metadata"]["compliance_policy"]["cloudbuild"]["deployment_coverage"] = "partial"
        assert evaluate(check_id, row, facts) == "UNKNOWN"


def test_empty_complete_sink_inventory_is_evaluated_at_scope():
    for mode, check_id, expected in (
        ("export", "gcp_c5_log_export", "FAIL"),
        ("isolation", "gcp_c5_log_isolation", "PASS"),
        ("redundancy", "gcp_c5_logging_redundancy", "FAIL"),
        ("siem", "gcp_c5_siem_sink", "FAIL"),
    ):
        _, facts = log_setup(mode)
        facts["collections"]["log_sink"][0].update(status="empty", items=[])
        facts["log_sink"] = []
        assert evaluate(check_id, facts["context"], facts) == expected


def test_engine_runs_scope_sink_check_on_empty_inventory(monkeypatch):
    import peaso.engine as engine
    monkeypatch.setattr(engine, "CATEGORIES", engine.CATEGORIES + ("logging",))
    from tests.archived_check_contract import evaluate_snapshot
    from peaso.snapshot import make_snapshot

    _, facts = log_setup("export")
    snapshot = make_snapshot("gcp", [PROJECT], [{"type": "log_sink", "scope": PROJECT,
        "service": "logging", "status": "empty", "items": []}], created_at=iso(),
        metadata=facts["context"]["metadata"])
    report = evaluate_snapshot(snapshot, checks=["gcp_c5_log_export"])
    finding, = [row for row in report["findings"] if row["check_id"] == "gcp_c5_log_export"]
    assert finding["status"] == "FAIL", finding


def test_complex_sink_filter_and_external_isolation_are_unknown():
    row, facts = log_setup("export")
    facts["log_sink"][0]["data"]["filter"] = 'severity>=ERROR'
    assert evaluate("gcp_c5_log_export", row, facts) == "UNKNOWN"
    row, facts = log_setup("isolation")
    facts["log_sink"][0]["data"]["destination"] = "pubsub.googleapis.com/projects/demo/topics/logs"
    assert evaluate("gcp_c5_log_isolation", row, facts) == "UNKNOWN"


def test_kms_and_enumeration_do_not_require_query_threshold_policy():
    for mode, check_id in (("kms", "gcp_kms_key_destroy_alert"),
                           ("enumeration", "gcp_logging_enumeration_alert")):
        row, facts = alert_setup(mode)
        facts["context"]["metadata"] = {}
        assert evaluate(check_id, row, facts) == "PASS"


@pytest.mark.parametrize("mode,check_id", [
    ("kms", "gcp_kms_key_destroy_alert"),
    ("enumeration", "gcp_logging_enumeration_alert"),
    ("query", "gcp_logging_query_rate_alert"),
])
def test_collector_metric_name_and_scope_binding(mode, check_id):
    row, facts = alert_setup(mode)
    assert evaluate(check_id, row, facts) == "PASS"
    facts["logging_metric"][0]["data"]["name"] = "projects/other/metrics/metric-a"
    assert evaluate(check_id, row, facts) == "UNKNOWN"
    facts["logging_metric"][0]["data"]["name"] = PROJECT + "/metrics/metric-a"
    facts["logging_metric"][0]["data"]["metricId"] = "different"
    assert evaluate(check_id, row, facts) == "UNKNOWN"


@pytest.mark.parametrize("mode,check_id", [
    ("kms", "gcp_kms_key_destroy_alert"),
    ("enumeration", "gcp_logging_enumeration_alert"),
    ("query", "gcp_logging_query_rate_alert"),
])
def test_disabled_logging_metric_cannot_satisfy_alert(mode, check_id):
    row, facts = alert_setup(mode)
    facts["logging_metric"][0]["data"]["disabled"] = True
    assert evaluate(check_id, row, facts) == "FAIL"
    facts["logging_metric"][0]["data"]["disabled"] = "false"
    assert evaluate(check_id, row, facts) == "UNKNOWN"
