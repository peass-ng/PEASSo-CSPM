"""Source-bound outcomes for the sw08 signed GCP predicates."""
from __future__ import annotations

import copy

import pytest

from peaso.checks import CHECKS, evaluate_check
from peaso.checks import compliance_new_sw08 as sw08


SCOPE = "projects/demo"
WB = SCOPE + "/locations/us-central1-a/instances/book"
KEY = SCOPE + "/locations/us/keyRings/ring/cryptoKeys/key"
VERSION = KEY + "/cryptoKeyVersions/1"
LOG = SCOPE + "/locations/global/buckets/security"
REPO = SCOPE + "/locations/us/repositories/images"
API_KEY = SCOPE + "/locations/global/keys/key-1"
SQL_USER = SCOPE + "/instances/db/users/root@%25"


@pytest.fixture(scope="module", autouse=True)
def remove_local_registrations_after_module():
    yield
    ids = {check_id for check_id, _ in sw08._DEFINITIONS}
    CHECKS[:] = [check for check in CHECKS if check.id not in ids]


def fact(name, **fields):
    return {"name": name, "_provenance": {"scope": SCOPE}, **fields}


def index(kind, row, policy=None, *, status="collected", metadata=None, other=None):
    meta = dict(metadata or {})
    if policy is not None:
        meta["compliance_policy"] = {"status": "collected", "scope": SCOPE, **policy}
    envelopes = {kind: [{"type": kind, "scope": SCOPE, "status": status, "items": [row]}]}
    resources = {kind: [{"type": kind, "scope": SCOPE, "data": row}]}
    if other:
        for extra_kind, rows in other.items():
            envelopes[extra_kind] = [{"type": extra_kind, "scope": SCOPE, "status": "collected", "items": rows}]
            resources[extra_kind] = [{"type": extra_kind, "scope": SCOPE, "data": value} for value in rows]
    return {"context": {"provider": "gcp", "scope": SCOPE, "metadata": meta},
            "collections": envelopes, **resources}


def outcome(check_id, kind, row, policy=None, **kwargs):
    return evaluate_check(check_id, row, index(kind, row, policy, **kwargs))[0]


def workbench(**setup):
    defaults = {"vmImage": {"project": "images", "family": "approved"},
                "networkInterfaces": [{"network": "projects/demo/global/networks/private"}],
                "metadata": {"notebook-disable-downloads": "true", "notebook-disable-root": "true",
                             "notebook-disable-terminal": "true"}, "disablePublicIp": True}
    defaults.update(setup)
    return fact(WB, gceSetup=defaults)


POLICY = {"approved_workbench_images": ["vm:images/family/approved"],
          "approved_workbench_networks": ["projects/demo/global/networks/private"],
          "workbench_sensitive": {WB: True},
          "approved_workbench_exceptions": {WB: {"notebook-disable-root": False,
                                                  "notebook-disable-terminal": False}}}


@pytest.mark.parametrize("check_id", [
    "gcp_workbench_approved_image", "gcp_workbench_approved_vpc",
    "gcp_workbench_download_disabled", "gcp_workbench_no_public_ip",
    "gcp_workbench_root_disabled", "gcp_workbench_terminal_disabled"])
def test_workbench_pass_and_inventory_unknown(check_id):
    row = workbench()
    assert outcome(check_id, "workbench_instance", row, POLICY) == "PASS"
    assert outcome(check_id, "workbench_instance", row, POLICY, status="partial") == "UNKNOWN"
    assert outcome(check_id, "workbench_instance", row) == "UNKNOWN"
    malformed = copy.deepcopy(row)
    malformed["gceSetup"] = []
    assert outcome(check_id, "workbench_instance", malformed, POLICY) == "UNKNOWN"
    foreign = copy.deepcopy(row)
    foreign["_provenance"]["scope"] = "projects/other"
    assert outcome(check_id, "workbench_instance", foreign, POLICY) == "UNKNOWN"


def test_workbench_image_and_network_fail_only_on_explicit_mismatch():
    image = workbench(vmImage={"project": "images", "family": "unapproved"})
    assert outcome("gcp_workbench_approved_image", "workbench_instance", image, POLICY) == "FAIL"
    image["gceSetup"].pop("vmImage")
    assert outcome("gcp_workbench_approved_image", "workbench_instance", image, POLICY) == "UNKNOWN"
    network = workbench(networkInterfaces=[{"network": "projects/demo/global/networks/public"}])
    assert outcome("gcp_workbench_approved_vpc", "workbench_instance", network, POLICY) == "FAIL"
    network["gceSetup"].pop("networkInterfaces")
    assert outcome("gcp_workbench_approved_vpc", "workbench_instance", network, POLICY) == "UNKNOWN"


@pytest.mark.parametrize("check_id,field,metadata", [
    ("gcp_workbench_download_disabled", "notebook-disable-downloads", True),
    ("gcp_workbench_no_public_ip", "disablePublicIp", False),
    ("gcp_workbench_root_disabled", "notebook-disable-root", True),
    ("gcp_workbench_terminal_disabled", "notebook-disable-terminal", True)])
def test_workbench_sensitive_controls_and_non_sensitive_policy(check_id, field, metadata):
    row = workbench()
    if metadata:
        row["gceSetup"]["metadata"][field] = "false"
    else:
        row["gceSetup"][field] = False
    assert outcome(check_id, "workbench_instance", row, POLICY) == "FAIL"
    if metadata:
        row["gceSetup"]["metadata"].pop(field)
    else:
        row["gceSetup"].pop(field)
    assert outcome(check_id, "workbench_instance", row, POLICY) == "UNKNOWN"
    non_sensitive = {**POLICY, "workbench_sensitive": {WB: False}}
    if check_id in ("gcp_workbench_download_disabled", "gcp_workbench_no_public_ip"):
        assert outcome(check_id, "workbench_instance", row, non_sensitive) == "NOT_APPLICABLE"
    else:
        enabled = workbench()
        enabled["gceSetup"]["metadata"][field] = "false"
        assert outcome(check_id, "workbench_instance", enabled, non_sensitive) == "FAIL"
        approved = copy.deepcopy(non_sensitive)
        approved["approved_workbench_exceptions"][WB][field] = True
        assert outcome(check_id, "workbench_instance", enabled, approved) == "PASS"
        no_exception = copy.deepcopy(non_sensitive)
        no_exception["approved_workbench_exceptions"] = {}
        assert outcome(check_id, "workbench_instance", enabled, no_exception) == "FAIL"
        approved.pop("approved_workbench_exceptions")
        assert outcome(check_id, "workbench_instance", enabled, approved) == "UNKNOWN"


def test_bucket_classification_scope_and_labels():
    check_id = "gcp_c5_classification_label"
    policy = {"classified_buckets": ["bucket-a"], "required_classification_key": "classification",
              "approved_classification_values": ["internal", "restricted"]}
    row = fact("bucket-a", labels={"classification": "internal"})
    assert outcome(check_id, "bucket", row, policy) == "PASS"
    assert outcome(check_id, "bucket", fact("bucket-a", labels={}), policy) == "FAIL"
    assert outcome(check_id, "bucket", fact("bucket-a", labels={"classification": "public"}), policy) == "FAIL"
    assert outcome(check_id, "bucket", fact("bucket-b", labels={}), policy) == "NOT_APPLICABLE"
    assert outcome(check_id, "bucket", row, None) == "UNKNOWN"
    assert outcome(check_id, "bucket", fact("bucket-a"), policy) == "UNKNOWN"
    full = fact("bucket-a")
    full["_provenance"]["representation"] = "full"
    assert outcome(check_id, "bucket", full, policy) == "FAIL"
    assert outcome(check_id, "bucket", row, policy, status="partial") == "UNKNOWN"


def test_hsm_designation_and_protection():
    check_id = "gcp_c5_kms_hsm"
    policy = {"designated_hsm_keys": [KEY], "approved_external_vpc_keys": []}
    assert outcome(check_id, "kms_key", fact(KEY, primary={"protectionLevel": "HSM"}), policy) == "PASS"
    assert outcome(check_id, "kms_key", fact(KEY, primary={"protectionLevel": "SOFTWARE"}), policy) == "FAIL"
    external = fact(KEY, primary={"protectionLevel": "EXTERNAL_VPC"})
    assert outcome(check_id, "kms_key", external, policy) == "FAIL"
    assert outcome(check_id, "kms_key", external, {**policy, "approved_external_vpc_keys": [KEY]}) == "PASS"
    assert outcome(check_id, "kms_key", fact(KEY, primary={"protectionLevel": "HSM"}),
                   {"designated_hsm_keys": ["other"]}) == "NOT_APPLICABLE"
    assert outcome(check_id, "kms_key", fact(KEY), policy) == "UNKNOWN"
    assert outcome(check_id, "kms_key", external) == "UNKNOWN"
    assert outcome(check_id, "kms_key", external, policy, status="partial") == "UNKNOWN"


def test_scheduled_key_deletion_requires_complete_version_inventory():
    check_id = "gcp_kms_key_kms_keys_scheduled_deletion_56316ac06650"
    key = fact(KEY)
    good = fact(VERSION, state="ENABLED")
    bad = fact(VERSION, state="DESTROY_SCHEDULED", destroyTime="2026-11-01T00:00:00Z")
    assert outcome(check_id, "kms_key", key, other={"kms_key_version": [good]}) == "PASS"
    assert outcome(check_id, "kms_key", key, other={"kms_key_version": [bad]}) == "FAIL"
    assert outcome(check_id, "kms_key", key, other={"kms_key_version": []}) == "PASS"
    assert outcome(check_id, "kms_key", key) == "UNKNOWN"
    assert outcome(check_id, "kms_key", key, other={"kms_key_version": [fact(VERSION, state="DESTROY_SCHEDULED")]}) == "UNKNOWN"
    assert outcome(check_id, "kms_key", key, other={"kms_key_version": [fact(VERSION, state="INVALID")]}) == "UNKNOWN"
    assert outcome(check_id, "kms_key", key, status="partial", other={"kms_key_version": [good]}) == "UNKNOWN"


def test_logging_bucket_retention_default_and_supplied_threshold():
    check_id = "gcp_pci_asset_6ee2fef37d98"
    assert outcome(check_id, "logging_bucket", fact(LOG, retentionDays=365)) == "PASS"
    assert outcome(check_id, "logging_bucket", fact(LOG, retentionDays=364)) == "FAIL"
    assert outcome(check_id, "logging_bucket", fact(LOG, retentionDays=90), metadata={"MinRetentionTime": 90}) == "PASS"
    assert outcome(check_id, "logging_bucket", fact(LOG, retentionDays=30), metadata={"MinRetentionTime": 90}) == "FAIL"
    assert outcome(check_id, "logging_bucket", fact(LOG)) == "UNKNOWN"
    assert outcome(check_id, "logging_bucket", fact(LOG, retentionDays="365")) == "UNKNOWN"
    assert outcome(check_id, "logging_bucket", fact(LOG, retentionDays=365), status="partial") == "UNKNOWN"


def test_approved_kms_algorithm_only_grades_enabled_versions():
    check_id = "gcp_kms_approved_algorithm"
    policy = {"approved_algorithms": ["GOOGLE_SYMMETRIC_ENCRYPTION"]}
    assert outcome(check_id, "kms_key_version", fact(VERSION, state="ENABLED", algorithm="GOOGLE_SYMMETRIC_ENCRYPTION"), policy) == "PASS"
    assert outcome(check_id, "kms_key_version", fact(VERSION, state="ENABLED", algorithm="RSA_DECRYPT_OAEP_2048_SHA256"), policy) == "FAIL"
    assert outcome(check_id, "kms_key_version", fact(VERSION, state="DISABLED"), policy) == "NOT_APPLICABLE"
    assert outcome(check_id, "kms_key_version", fact(VERSION, state="ENABLED"), policy) == "UNKNOWN"
    assert outcome(check_id, "kms_key_version", fact(VERSION, state="ENABLED", algorithm="GOOGLE_SYMMETRIC_ENCRYPTION")) == "UNKNOWN"
    assert outcome(check_id, "kms_key_version", fact(VERSION, state="ENABLED", algorithm="GOOGLE_SYMMETRIC_ENCRYPTION"), policy, status="partial") == "UNKNOWN"


def test_artifact_cleanup_policy_delete_age_and_dry_run():
    check_id = "gcp_artifact_registry_cleanup_policy"
    policy = {"max_artifact_age": 86400}
    safe = fact(REPO, cleanupPolicyDryRun=False,
                cleanupPolicies={"old": {"action": "DELETE", "condition": {"olderThan": "86399.5s"}}})
    assert outcome(check_id, "artifact_repository", safe, policy) == "PASS"
    unsafe = fact(REPO, cleanupPolicyDryRun=False,
                  cleanupPolicies={"old": {"action": "DELETE", "condition": {"olderThan": "86401s"}}})
    assert outcome(check_id, "artifact_repository", unsafe, policy) == "FAIL"
    assert outcome(check_id, "artifact_repository", fact(REPO, cleanupPolicyDryRun=False, cleanupPolicies={}), policy) == "FAIL"
    assert outcome(check_id, "artifact_repository", fact(REPO, cleanupPolicyDryRun=True,
                   cleanupPolicies=safe["cleanupPolicies"]), policy) == "FAIL"
    assert outcome(check_id, "artifact_repository", fact(REPO, cleanupPolicyDryRun=False), policy) == "UNKNOWN"
    assert outcome(check_id, "artifact_repository", safe) == "UNKNOWN"
    assert outcome(check_id, "artifact_repository", safe, policy, status="partial") == "UNKNOWN"


def test_api_key_disabled_target_service_is_only_decisive_outcome():
    check_id = "gcp.apikeys.active_service_restrictions"
    key = fact(API_KEY, restrictions={"apiTargets": [{"service": "foo.googleapis.com"}]})
    enabled = fact(SCOPE + "/services/foo.googleapis.com", state="ENABLED")
    disabled = fact(SCOPE + "/services/foo.googleapis.com", state="DISABLED")
    assert outcome(check_id, "api_key", key, other={"service_usage": [disabled]}) == "FAIL"
    assert outcome(check_id, "api_key", key, other={"service_usage": [enabled]}) == "UNKNOWN"
    assert outcome(check_id, "api_key", key, other={"service_usage": []}) == "UNKNOWN"
    assert outcome(check_id, "api_key", fact(API_KEY, restrictions={"apiTargets": []}),
                   other={"service_usage": [disabled]}) == "UNKNOWN"
    assert outcome(check_id, "api_key", key) == "UNKNOWN"
    assert outcome(check_id, "api_key", key, status="partial", other={"service_usage": [disabled]}) == "UNKNOWN"


def test_mysql_admin_user_posture_with_parent_instance_proof():
    check_id = "gcp.sql.mysql_admin_account_posture"
    instance = fact("db", databaseVersion="MYSQL_8_0")
    root = fact(SQL_USER, instanceId="db", userName="root", host="%", type="BUILT_IN")
    safe = fact(SCOPE + "/instances/db/users/root@localhost", instanceId="db", userName="root", host="localhost", type="BUILT_IN")
    assert outcome(check_id, "sql_user", root, other={"sql_instance": [instance]}) == "FAIL"
    assert outcome(check_id, "sql_user", safe, other={"sql_instance": [instance]}) == "PASS"
    postgres = fact("db", databaseVersion="POSTGRES_15")
    assert outcome(check_id, "sql_user", root, other={"sql_instance": [postgres]}) == "NOT_APPLICABLE"
    assert outcome(check_id, "sql_user", root) == "UNKNOWN"
    assert outcome(check_id, "sql_user", fact(SQL_USER, instanceId="db", userName="root", type="BUILT_IN"),
                   other={"sql_instance": [instance]}) == "UNKNOWN"
    assert outcome(check_id, "sql_user", root, status="partial", other={"sql_instance": [instance]}) == "UNKNOWN"


@pytest.mark.parametrize("mutation", ["wrapper_scope", "wrapper_provider", "empty_scope", "envelope_projection"])
def test_sw08_authority_and_projection_regressions(mutation):
    row = workbench()
    ix = index("workbench_instance", row, POLICY)
    if mutation == "wrapper_scope":
        ix["workbench_instance"][0]["scope"] = "projects/foreign"
    elif mutation == "wrapper_provider":
        ix["workbench_instance"][0]["provider"] = "aws"
    elif mutation == "empty_scope":
        ix["context"]["scope"] = "projects/"
        ix["collections"]["workbench_instance"][0]["scope"] = "projects/"
    else:
        extra = workbench()
        extra["name"] += "-second"
        extra["gceSetup"]["vmImage"]["family"] = "unapproved"
        ix["collections"]["workbench_instance"][0]["items"] = [row, extra]
        ix["workbench_instance"].append({"type": "workbench_instance", "scope": SCOPE, "data": row})
    for cid, _ in sw08._DEFINITIONS:
        if cid.startswith("gcp_workbench_"):
            assert evaluate_check(cid, row, ix)[0] == "UNKNOWN"


@pytest.mark.parametrize("version", [
    fact("projects/foreign/locations/us/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1", state="ENABLED"),
    fact(VERSION + "/extra", state="ENABLED"),
    fact(VERSION, state="DESTROY_SCHEDULED", destroyTime="not-a-time"),
    fact(VERSION, state="DESTROY_SCHEDULED", destroyTime="2026-13-01T00:00:00Z"),
])
def test_scheduled_deletion_malformed_identity_and_time(version):
    assert outcome("gcp_kms_key_kms_keys_scheduled_deletion_56316ac06650", "kms_key", fact(KEY),
                   other={"kms_key_version": [version]}) == "UNKNOWN"


@pytest.mark.parametrize("kind", ["kms_key_version", "service_usage", "sql_instance"])
def test_sw08_dependency_wrapper_scope_must_match(kind):
    rows = {"kms_key_version": fact(VERSION, state="ENABLED"),
            "service_usage": fact(SCOPE + "/services/foo.googleapis.com", state="DISABLED"),
            "sql_instance": fact("db", databaseVersion="MYSQL_8_0")}
    cases = {"kms_key_version": ("gcp_kms_key_kms_keys_scheduled_deletion_56316ac06650", "kms_key", fact(KEY)),
             "service_usage": ("gcp.apikeys.active_service_restrictions", "api_key", fact(API_KEY,
                                  restrictions={"apiTargets": [{"service": "foo.googleapis.com"}]})),
             "sql_instance": ("gcp.sql.mysql_admin_account_posture", "sql_user", fact(SQL_USER,
                                  instanceId="db", userName="root", host="%", type="BUILT_IN"))}
    cid, primary, row = cases[kind]
    ix = index(primary, row, other={kind: [rows[kind]]})
    ix[kind][0]["scope"] = "projects/foreign"
    assert evaluate_check(cid, row, ix)[0] == "UNKNOWN"


@pytest.mark.parametrize("field,value", [("type", "ALIEN"), ("userName", "someone-else"), ("host", "localhost")])
def test_mysql_admin_identity_and_type_cannot_be_fabricated(field, value):
    user = fact(SQL_USER, instanceId="db", userName="root", host="%", type="BUILT_IN")
    user[field] = value
    assert outcome("gcp.sql.mysql_admin_account_posture", "sql_user", user,
                   other={"sql_instance": [fact("db", databaseVersion="MYSQL_8_0")]}) == "UNKNOWN"


def test_artifact_full_proto_omission_and_non_age_delete():
    cid = "gcp_artifact_registry_cleanup_policy"
    policy = {"max_artifact_age": 86400}
    row = fact(REPO, cleanupPolicies={"old": {"action": "DELETE", "condition": {"olderThan": "80000s"}}})
    row["_provenance"]["representation"] = "full"
    assert outcome(cid, "artifact_repository", row, policy) == "PASS"
    row.pop("cleanupPolicies")
    assert outcome(cid, "artifact_repository", row, policy) == "FAIL"
    row["cleanupPolicies"] = {"tags": {"action": "DELETE", "condition": {"tagState": "UNTAGGED"}},
                              "old": {"action": "DELETE", "condition": {"olderThan": "80000s"}}}
    assert outcome(cid, "artifact_repository", row, policy) == "PASS"
    row["cleanupPolicies"].pop("old")
    assert outcome(cid, "artifact_repository", row, policy) == "FAIL"
    row["_coverage"] = {"cleanupPolicyDryRun": {"status": "denied"}}
    assert outcome(cid, "artifact_repository", row, policy) == "UNKNOWN"


@pytest.mark.parametrize("cid,kind,row,policy,expected", [
    ("gcp_workbench_approved_image", "workbench_instance", workbench(), {**POLICY, "approved_workbench_images": []}, "FAIL"),
    ("gcp_workbench_approved_vpc", "workbench_instance", workbench(), {**POLICY, "approved_workbench_networks": []}, "FAIL"),
    ("gcp_c5_classification_label", "bucket", fact("bucket-a", labels={}), {"classified_buckets": []}, "NOT_APPLICABLE"),
    ("gcp_c5_kms_hsm", "kms_key", fact(KEY), {"designated_hsm_keys": []}, "NOT_APPLICABLE"),
    ("gcp_kms_approved_algorithm", "kms_key_version", fact(VERSION, state="ENABLED", algorithm="GOOGLE_SYMMETRIC_ENCRYPTION"),
        {"approved_algorithms": []}, "FAIL"),
])
def test_explicit_empty_owner_lists_have_defined_meaning(cid, kind, row, policy, expected):
    assert outcome(cid, kind, row, policy) == expected


@pytest.mark.parametrize("cid,kind,row,policy", [
    ("gcp_workbench_approved_image", "workbench_instance", workbench(), POLICY),
    ("gcp_c5_kms_hsm", "kms_key", fact(KEY, primary={"protectionLevel": "HSM"}), {"designated_hsm_keys": [KEY]}),
    ("gcp_kms_approved_algorithm", "kms_key_version", fact(VERSION, state="ENABLED", algorithm="GOOGLE_SYMMETRIC_ENCRYPTION"),
        {"approved_algorithms": ["GOOGLE_SYMMETRIC_ENCRYPTION"]}),
    ("gcp_pci_asset_6ee2fef37d98", "logging_bucket", fact(LOG, retentionDays=365), None),
    ("gcp_artifact_registry_cleanup_policy", "artifact_repository", fact(REPO, cleanupPolicyDryRun=False,
        cleanupPolicies={"old": {"action": "DELETE", "condition": {"olderThan": "80000s"}}}), {"max_artifact_age": 86400}),
    ("gcp.apikeys.active_service_restrictions", "api_key", fact(API_KEY, restrictions={"apiTargets": [{"service": "foo.googleapis.com"}]}), None),
])
def test_sw08_truncated_native_resource_names_unknown(cid, kind, row, policy):
    row = copy.deepcopy(row)
    row["name"] = SCOPE + "/locations/us/"
    assert outcome(cid, kind, row, policy) == "UNKNOWN"


@pytest.mark.parametrize("algorithm", ["ALIEN", "CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED", " "])
def test_kms_unrecognized_algorithm_never_passes_even_if_allowlisted(algorithm):
    row = fact(VERSION, state="ENABLED", algorithm=algorithm)
    assert outcome("gcp_kms_approved_algorithm", "kms_key_version", row,
                   {"approved_algorithms": [algorithm]}) == "UNKNOWN"


@pytest.mark.parametrize("image,policy_value,expected", [
    ({"project": "images", "name": "approved"}, "vm:images/name/approved", "PASS"),
    ({"project": "images", "name": "approved"}, "vm:images/family/approved", "FAIL"),
    ({"project": "images", "family": "approved"}, "vm:images/name/approved", "FAIL"),
    ({"project": "images", "imageFamily": "approved"}, "vm:images/family/approved", "UNKNOWN"),
    ({"project": "images", "family": "approved", "name": "approved"}, "vm:images/family/approved", "UNKNOWN"),
])
def test_workbench_v2_vm_image_fields_and_selector_identity(image, policy_value, expected):
    assert outcome("gcp_workbench_approved_image", "workbench_instance", workbench(vmImage=image),
                   {**POLICY, "approved_workbench_images": [policy_value]}) == expected


def test_workbench_v2_container_and_mutually_exclusive_image_union():
    row = workbench(containerImage={"repository": "gcr.io/images/notebook", "tag": "approved"})
    policy = {**POLICY, "approved_workbench_images": ["vm:images/family/approved", "container:gcr.io/images/notebook/approved"]}
    assert outcome("gcp_workbench_approved_image", "workbench_instance", row, policy) == "UNKNOWN"
    row["gceSetup"].pop("vmImage")
    assert outcome("gcp_workbench_approved_image", "workbench_instance", row, policy) == "PASS"
    row["gceSetup"]["containerImage"] = {"repository": "gcr.io/images/notebook", "digest": "approved"}
    assert outcome("gcp_workbench_approved_image", "workbench_instance", row, policy) == "UNKNOWN"


def test_collector_workbench_v2_image_matches_evaluator():
    from tests.test_peaso_collectors_gcp import snapshot as collect, collection
    scope = "projects/p-one"
    name = scope + "/locations/us-central1-a/instances/book"
    policy = {"status": "collected", "scope": scope, "approved_workbench_images": ["vm:images/family/approved"]}
    result, _ = collect(["workbench_instance"], lambda request: {"instances": [{"name": name,
                       "gceSetup": {"vmImage": {"project": "images", "family": "approved"}}}]}, compliance_policy=policy)
    env = collection(result, "workbench_instance")
    row = env["items"][0]
    ix = {"context": {"provider": "gcp", "scope": scope, "metadata": result["metadata"]},
          "collections": {"workbench_instance": [env]},
          "workbench_instance": [{"scope": scope, "type": "workbench_instance", "data": row}]}
    assert evaluate_check("gcp_workbench_approved_image", row, ix)[0] == "PASS"


@pytest.mark.parametrize("policy", [
    {"action": "KEEP", "condition": {"olderThan": "garbage"}},
    {"action": "KEEP", "condition": {"tagState": "ALIEN"}},
    {"action": "KEEP", "mostRecentVersions": {"keepCount": True}},
    {"action": "KEEP", "condition": {}, "mostRecentVersions": {"keepCount": 5}},
])
def test_malformed_cleanup_sibling_cannot_hide_behind_qualifying_delete(policy):
    row = fact(REPO, cleanupPolicyDryRun=False, cleanupPolicies={
        "old": {"action": "DELETE", "condition": {"olderThan": "80000s"}}, "keep": policy})
    assert outcome("gcp_artifact_registry_cleanup_policy", "artifact_repository", row,
                   {"max_artifact_age": 86400}) == "UNKNOWN"


@pytest.mark.parametrize("version", ["MYSQL_8_0_18", "MYSQL_8_0_26", "MYSQL_8_4"])
def test_mysql_minor_version_engine_is_recognized(version):
    row = fact(SQL_USER, instanceId="db", userName="root", host="%", type="BUILT_IN")
    assert outcome("gcp.sql.mysql_admin_account_posture", "sql_user", row,
                   other={"sql_instance": [fact("db", databaseVersion=version)]}) == "FAIL"
