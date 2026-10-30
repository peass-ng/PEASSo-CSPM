"""Source-reviewed native GCP predicates: positive, negative and coverage gaps."""
import copy

import pytest

# Explicit module import until the registry owner's coordinated import lands.
from peaso.checks import gcp_extended, CHECKS
from peaso.checks.fixtures import CASES

CHECKS_BY_ID = {check.id: check for check in CHECKS if check.id in gcp_extended.IDS}


@pytest.mark.parametrize("cid", gcp_extended.IDS)
@pytest.mark.parametrize("case,status", [("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"),
                                         ("malformed", "UNKNOWN"), ("denied", "UNKNOWN")])
def test_all_reviewed_predicates_strict_and_immutable(cid, case, status):
    item = {"collection_status": "denied"} if case == "denied" else copy.deepcopy(CASES[cid][case])
    original = copy.deepcopy(item)
    index = {}
    if cid == "gcp.reviewed.network.flow_logs" and case == "fail":
        item.update(selfLink="projects/p/regions/r/subnetworks/s", network="projects/p/global/networks/n")
        original = copy.deepcopy(item)
        index = {"collections": {"vpc_flow_logs_config": [{"scope": "projects/p", "status": "empty"}]},
                 "vpc_flow_logs_config": []}
    result, evidence = CHECKS_BY_ID[cid].evaluate(item, index)
    assert result == status, (cid, case, evidence)
    assert isinstance(evidence, dict)
    assert item == original


@pytest.mark.parametrize("cid", gcp_extended.IDS)
def test_denied_detail_cannot_become_a_configuration_pass(cid):
    item = copy.deepcopy(CASES[cid]["pass"])
    field = next(key for key in item if not key.startswith("_"))
    item["_coverage"] = {field: {"status": "denied", "error": {"code": "permission_denied"}}}
    assert CHECKS_BY_ID[cid].evaluate(item, {})[0] == "UNKNOWN"


def evaluate(suffix, item):
    return CHECKS_BY_ID[gcp_extended.PREFIX + suffix].evaluate(item, {})


def test_gke_naming_exemptions_remain_owner_review():
    assert evaluate("compute.ip_forwarding", {"name": "gke-node", "canIpForward": True})[0] == "MANUAL"
    assert evaluate("compute.single_interface", {"name": "gke-node", "networkInterfaces": [{}, {}]})[0] == "MANUAL"
    assert evaluate("compute.no_default_service_account", {"name": "gke-node", "serviceAccounts":
        [{"email": "123-compute@developer.gserviceaccount.com"}]})[0] == "MANUAL"


def test_persistent_disk_rule_does_not_treat_ephemeral_scratch_as_backup_policy():
    assert evaluate("compute.disk_auto_delete", {"disks": [{"type": "SCRATCH", "autoDelete": True}]})[0] == "PASS"
    assert evaluate("compute.disk_auto_delete", {"disks": [{"type": "PERSISTENT", "autoDelete": "false"}]})[0] == "UNKNOWN"


def test_metadata_missing_duplicate_and_malformed_values_are_unknown():
    for rows in [[], [{"key": "serial-port-enable", "value": "unexpected"}],
                 [{"key": "serial-port-enable", "value": "false"}] * 2]:
        assert evaluate("compute.no_serial_console", {"metadata": {"items": rows}})[0] == "UNKNOWN"
    assert evaluate("compute.no_serial_console", {"metadata": {"items": [{"key": "serial-port-enable", "value": "TRUE"}]}})[0] == "FAIL"


def test_sql_engine_applicability_and_known_enum_values():
    assert evaluate("sql.mysql_local_infile", {"databaseVersion": "POSTGRES_16"})[0] == "NOT_APPLICABLE"
    assert evaluate("sql.mysql_local_infile", {"databaseVersion": "MYSQL_8_0", "settings": {"databaseFlags": []}})[0] == "UNKNOWN"
    for flag, value, suffix in [("log_statement", "all", "sql.postgres_log_statement"),
                                ("log_error_verbosity", "verbose", "sql.postgres_log_error_verbosity")]:
        item = {"databaseVersion": "POSTGRES_16", "settings": {"databaseFlags": [{"name": flag, "value": value}]}}
        assert evaluate(suffix, item)[0] == "FAIL"
    assert evaluate("sql.high_availability", {"instanceType": "READ_REPLICA_INSTANCE"})[0] == "NOT_APPLICABLE"


def test_kms_rotation_uses_snapshot_time_exact_boundaries_and_purpose():
    item = copy.deepcopy(CASES[gcp_extended.PREFIX + "kms.rotation_90_days"]["pass"])
    item["nextRotationTime"] = "2026-10-09T00:00:00Z"
    assert evaluate("kms.rotation_90_days", item)[0] == "FAIL"
    item["nextRotationTime"] = "2027-01-08T00:00:01Z"  # 90 days plus one second
    assert evaluate("kms.rotation_90_days", item)[0] == "FAIL"
    item["nextRotationTime"] = "2027-01-08T00:00:00Z"
    assert evaluate("kms.rotation_90_days", item)[0] == "PASS"
    item["rotationPeriod"] = "7776000.000000001s"
    assert evaluate("kms.rotation_90_days", item)[0] == "FAIL"
    assert evaluate("kms.rotation_enabled", {"purpose": "ASYMMETRIC_SIGN"})[0] == "NOT_APPLICABLE"
    assert evaluate("kms.rotation_enabled", {"purpose": "ENCRYPT_DECRYPT", "rotationPeriod": "bad"})[0] == "UNKNOWN"


def test_conditional_public_kms_binding_is_declared_member_evidence_only():
    item = {"iamPolicy": {"bindings": [{"role": "roles/cloudkms.cryptoKeyEncrypterDecrypter", "members": ["allUsers"],
        "condition": {"expression": "false"}}]}}
    status, evidence = evaluate("kms.no_public_iam", item)
    assert status == "FAIL"
    assert evidence["public_bindings"][0]["condition"] == {"expression": "false"}
    assert "no effective-access claim" in evidence["semantics"]


def test_bigquery_public_principals_are_exact_matches_not_substrings():
    item = {"access": [{"userByEmail": "allUsers@example.org", "role": "READER"},
                        {"view": {"datasetId": "allAuthenticatedUsers", "projectId": "p", "tableId": "t"}}]}
    assert evaluate("bigquery.no_public_acl", item)[0] == "PASS"
    assert evaluate("bigquery.no_public_acl", {"access": [{"iamMember": "allUsers", "role": "READER"}]})[0] == "FAIL"
    assert evaluate("bigquery.cmek", {"defaultEncryptionConfiguration": {"kmsKeyName": ""}})[0] == "UNKNOWN"


FULL = {"_provenance": {"representation": "full", "collected_at": "2026-10-10T00:00:00Z"}}
PARTIAL = {"_provenance": {"representation": "partial", "collected_at": "2026-10-10T00:00:00Z"}}
NETWORK = "https://www.googleapis.com/compute/v1/projects/p/global/networks/n"
SUBNET = {"name": "s", "purpose": "PRIVATE", "network": NETWORK, "region": "regions/r",
          "selfLink": "https://www.googleapis.com/compute/v1/projects/p/regions/r/subnetworks/s"}


def nm_index(status="collected", configs=(), reason=None):
    envelope = {"scope": "projects/p", "status": status, **({"error": {"reason": reason}} if reason else {})}
    return {"collections": {"vpc_flow_logs_config": [envelope]}, "vpc_flow_logs_config": [{"data": c} for c in configs]}


def test_flow_logs_absence_is_fail_only_on_full_subnet_representation():
    status, evidence = evaluate("network.flow_logs", {**SUBNET, **FULL})
    assert status == "UNKNOWN" and evidence["network"] == NETWORK
    assert evidence["network_management_configs"] == "not_collected"
    check = CHECKS_BY_ID[gcp_extended.PREFIX + "network.flow_logs"]
    assert check.evaluate({**SUBNET, **FULL}, nm_index(status="empty"))[0] == "FAIL"
    # Provenance completeness: the same omission from a partial/unmarked read stays UNKNOWN.
    assert evaluate("network.flow_logs", {**SUBNET, **PARTIAL})[0] == "UNKNOWN"
    assert evaluate("network.flow_logs", dict(SUBNET))[0] == "UNKNOWN"
    assert evaluate("network.flow_logs", {**SUBNET, **FULL, "logConfig": {"enable": True}})[0] == "PASS"
    assert evaluate("network.flow_logs", {**SUBNET, **FULL, "enableFlowLogs": True, "logConfig": {"enable": False}})[0] == "UNKNOWN"
    for purpose in ("REGIONAL_MANAGED_PROXY", "PRIVATE_SERVICE_CONNECT", "GLOBAL_MANAGED_PROXY"):
        assert evaluate("network.flow_logs", {**SUBNET, **FULL, "purpose": purpose})[0] == "NOT_APPLICABLE"
    assert evaluate("network.flow_logs", {**SUBNET, **FULL, "purpose": "FUTURE_PURPOSE"})[0] == "UNKNOWN"


def test_flow_logs_network_management_configs_can_satisfy_and_are_reported():
    check = CHECKS_BY_ID[gcp_extended.PREFIX + "network.flow_logs"]
    item = {**SUBNET, **FULL}
    network_config = {"name": "projects/p/locations/global/vpcFlowLogsConfigs/c", "network": "projects/p/global/networks/n", "configLevel": "project"}
    assert check.evaluate(item, nm_index(configs=[network_config]))[0] == "PASS"
    assert check.evaluate(item, nm_index(configs=[{**network_config, "state": "DISABLED"}]))[0] == "FAIL"
    assert check.evaluate(item, nm_index(configs=[{"name": "organizations/1/locations/global/vpcFlowLogsConfigs/o",
        "configLevel": "organization"}]))[0] == "PASS"
    assert check.evaluate(item, nm_index(configs=[{**network_config, "filterExpr": "x"}]))[0] == "MANUAL"
    status, evidence = check.evaluate(item, nm_index("unknown", reason="SERVICE_DISABLED"))
    assert status == "UNKNOWN" and evidence["network_management_configs"] == "unverified"
    assert evidence["network_management_status"] == [{"status": "unknown", "error": "SERVICE_DISABLED"}]


@pytest.mark.parametrize("suffix", ["kms.rotation_enabled", "kms.rotation_90_days"])
def test_kms_unset_rotation_fails_on_full_key_and_inapplicable_keys_are_not_applicable(suffix):
    key = {"purpose": "ENCRYPT_DECRYPT", "primary": {"state": "ENABLED", "protectionLevel": "SOFTWARE"}}
    status, evidence = evaluate(suffix, {**key, **FULL})
    assert status == "FAIL" and evidence["source"].startswith("omitted")
    assert evaluate(suffix, {**key, **PARTIAL})[0] == "UNKNOWN"
    assert evaluate(suffix, dict(key))[0] == "UNKNOWN"
    for state in ("DESTROYED", "DESTROY_SCHEDULED", "DISABLED"):
        assert evaluate(suffix, {**key, **FULL, "primary": {"state": state}})[0] == "NOT_APPLICABLE"
    for purpose in ("ASYMMETRIC_SIGN", "ASYMMETRIC_DECRYPT", "MAC", "RAW_ENCRYPT_DECRYPT", "KEY_ENCAPSULATION"):
        assert evaluate(suffix, {"purpose": purpose, **FULL})[0] == "NOT_APPLICABLE"
    assert evaluate(suffix, {**key, **FULL, "primary": {"state": "ENABLED", "protectionLevel": "EXTERNAL"}})[0] == "NOT_APPLICABLE"
    assert evaluate(suffix, {"purpose": "ENCRYPT_DECRYPT", **FULL})[0] == "NOT_APPLICABLE"  # no primary version
    assert evaluate(suffix, {"purpose": "FUTURE", **FULL})[0] == "UNKNOWN"


@pytest.mark.parametrize("suffix", ["storage.versioning", "storage.access_logging", "storage.lifecycle"])
def test_bucket_omitted_configuration_fails_only_with_projection_full(suffix):
    bucket = {"name": "b", "iamConfiguration": {}}
    assert evaluate(suffix, {**bucket, **FULL})[0] == "FAIL"
    assert evaluate(suffix, {**bucket, **PARTIAL})[0] == "UNKNOWN"
    assert evaluate(suffix, dict(bucket))[0] == "UNKNOWN"
    field = {"storage.versioning": "versioning", "storage.access_logging": "logging", "storage.lifecycle": "lifecycle"}[suffix]
    denied = {**bucket, **FULL, "_coverage": {field: {"status": "denied"}}}
    assert evaluate(suffix, denied)[0] == "UNKNOWN"
    assert evaluate("storage.versioning", {**bucket, **FULL, "versioning": {"enabled": True}})[0] == "PASS"
    assert evaluate("storage.access_logging", {**bucket, **FULL, "logging": {"logBucket": "logs"}})[0] == "PASS"


def test_bigquery_full_details_default_to_google_managed_key_and_empty_acl():
    dataset = {"datasetReference": {"datasetId": "sales"}}
    status, evidence = evaluate("bigquery.cmek", {**dataset, **FULL})
    assert status == "FAIL" and evidence["default_encryption_configuration"] == {}
    assert evaluate("bigquery.cmek", {**dataset, **PARTIAL})[0] == "UNKNOWN"
    assert evaluate("bigquery.no_public_acl", {**dataset, **FULL})[0] == "PASS"
    assert evaluate("bigquery.no_public_acl", {**dataset, **PARTIAL})[0] == "UNKNOWN"
    anonymous = {"datasetReference": {"datasetId": "_" + "a" * 40}, **FULL}
    assert evaluate("bigquery.cmek", anonymous)[0] == "NOT_APPLICABLE"
    denied = {**dataset, **FULL, "_coverage": {"access": {"status": "denied"}}}
    assert evaluate("bigquery.no_public_acl", denied)[0] == "UNKNOWN"


CORE = {check.id: check for check in CHECKS if check.id.startswith("gcp.")}


def audit_policy(entries, status="collected", missing=(), name="projects/p"):
    return {"name": name, "bindings": [], "effectiveAuditConfigs": entries,
            "_coverage": {"effectiveAuditConfigs": {"status": status, "missing_scopes": list(missing)}}}


def test_data_access_audit_evaluates_inherited_union_and_skips_resource_policies():
    check = CORE["gcp.iam.data_access_audit"]
    data = [{"service": "allServices", "auditLogConfigs": [{"logType": "DATA_READ"}, {"logType": "DATA_WRITE"}]}]
    status, evidence = check.evaluate(audit_policy([{"scope": "projects/p", "auditConfigs": []},
        {"scope": "folders/2", "auditConfigs": data}]), {})
    assert status == "PASS" and evidence["configured_at"][0]["scope"] == "folders/2"
    status, evidence = check.evaluate(audit_policy([{"scope": "projects/p", "auditConfigs": []},
        {"scope": "organizations/1", "auditConfigs": [{"service": "storage.googleapis.com", "auditLogConfigs": [{"logType": "DATA_READ"}]}]}]), {})
    assert status == "FAIL" and evidence["evaluated_scopes"] == ["projects/p", "organizations/1"]
    # Completeness: an uncollected (e.g. denied) ancestor cannot yield FAIL.
    assert check.evaluate(audit_policy([{"scope": "projects/p", "auditConfigs": []}], "partial", ["organizations/1"]), {})[0] == "UNKNOWN"
    # A missing ancestor leaves hierarchy-wide source authority unresolved,
    # including potential exemptions; a local enabling level cannot prove PASS.
    assert check.evaluate(audit_policy([{"scope": "projects/p", "auditConfigs": data}], "partial", ["organizations/1"]), {})[0] == "UNKNOWN"
    assert check.evaluate({"name": "projects/p", "auditConfigs": data}, {})[0] == "UNKNOWN"  # not materialized
    exempt = copy.deepcopy(data)
    exempt[0]["auditLogConfigs"][0]["exemptedMembers"] = ["user:a@example.com"]
    assert check.evaluate(audit_policy([{"scope": "projects/p", "auditConfigs": exempt}]), {})[0] == "MANUAL"
    assert check.evaluate({"name": "//storage.googleapis.com/projects/_/buckets/b", "bindings": []}, {})[0] == "NOT_APPLICABLE"


def test_private_google_access_is_low_severity_and_grouped_by_network():
    check = CORE["gcp.subnetwork.private_google_access"]
    assert check.severity == "low"
    status, evidence = check.evaluate({"privateIpGoogleAccess": False, "purpose": "PRIVATE", "network": NETWORK}, {})
    assert status == "FAIL" and evidence["network"] == NETWORK
    assert check.evaluate({"privateIpGoogleAccess": True}, {})[0] == "PASS"
    assert check.evaluate({"privateIpGoogleAccess": False, "purpose": "REGIONAL_MANAGED_PROXY"}, {})[0] == "NOT_APPLICABLE"
    assert check.evaluate({"purpose": "PRIVATE"}, {})[0] == "UNKNOWN"


def test_internet_ingress_reports_matching_target_instances():
    check = CORE["gcp.compute.restrict_internet_ingress"]
    rule = {"direction": "INGRESS", "sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
            "network": NETWORK, "targetTags": ["ssh"]}
    def index(*instances):
        return {"collections": {"instance": [{"scope": "projects/p", "status": "collected" if instances else "empty"}]},
                "instance": [{"data": i} for i in instances]}
    vm = {"name": "vm", "status": "RUNNING", "tags": {"items": ["ssh"]}, "networkInterfaces": [{"network": NETWORK, "accessConfigs": [{}]}]}
    status, evidence = check.evaluate(rule, index(vm))
    assert status == "FAIL" and evidence["target_instances"] == 1 and evidence["target_instance_sample"][0]["external_ip"]
    status, evidence = check.evaluate(rule, index({**vm, "tags": {"items": ["web"]}}))
    assert status == "FAIL" and evidence["target_instances"] == 0 and evidence["practical_severity"] == "low"
    assert check.evaluate(rule, {})[1]["target_instances"].startswith("unknown")
    assert check.evaluate({**rule, "disabled": True}, index(vm))[0] == "NOT_APPLICABLE"


def org_policy_index(policy=None, status="collected"):
    envelope = {"scope": "projects/p", "status": status}
    rows = [] if policy is None else [{"data": {"name": "projects/p/policies/storage.publicAccessPrevention",
                                                "constraint": "storage.publicAccessPrevention", **policy}}]
    return {"context": {"provider": "gcp", "scope": "projects/p"},
            "collections": {"org_policy_effective": [envelope]}, "org_policy_effective": rows}


def test_inherited_public_access_prevention_resolves_effective_org_policy():
    check = CORE["gcp.storage.public_access_prevention"]
    assert "org_policy_effective" in check.dependencies
    bucket = {"name": "b", "iamConfiguration": {"publicAccessPrevention": "inherited"}}
    status, evidence = check.evaluate(bucket, org_policy_index({"spec": {"rules": [{"enforce": True}]}}))
    assert status == "PASS" and evidence["org_policy_enforced"] is True
    assert evidence["effective_org_policy"] == "projects/p/policies/storage.publicAccessPrevention"
    assert check.evaluate(bucket, org_policy_index({"spec": {"rules": [{"enforce": False}]}}))[0] == "FAIL"
    # Nothing set anywhere in the hierarchy: the boolean constraint is not enforced.
    assert check.evaluate(bucket, org_policy_index({}))[0] == "FAIL"
    assert check.evaluate(bucket, org_policy_index({"spec": {}}))[0] == "FAIL"
    for index in ({}, org_policy_index(status="denied"), org_policy_index(None),
                  org_policy_index({"spec": {"rules": [{"enforce": True, "condition": {"expression": "x"}}]}}),
                  org_policy_index({"spec": {"rules": [{"enforce": True}, {"enforce": False}]}}),
                  org_policy_index({"spec": {"rules": [{"enforce": "true"}]}}),
                  org_policy_index({"spec": {"rules": "bad"}})):
        assert check.evaluate(bucket, index)[0] == "UNKNOWN"
    assert check.evaluate({"iamConfiguration": {"publicAccessPrevention": "enforced"}}, {})[0] == "PASS"


@pytest.mark.parametrize("cid", ["gcp.ports.bigquery_dataset_not_publicly_accessible", "gcp.claude.bigquery_dataset.no_gmail_access"])
def test_dataset_acl_omitted_only_counts_as_empty_on_full_details(cid):
    check = CORE[cid]
    assert check.evaluate({"datasetReference": {"datasetId": "d"}, **FULL}, {})[0] == "PASS"
    assert check.evaluate({"datasetReference": {"datasetId": "d"}, **PARTIAL}, {})[0] == "UNKNOWN"
    assert check.evaluate({"datasetReference": {"datasetId": "d"}}, {})[0] == "UNKNOWN"
    bad = {"access": [{"specialGroup": "allAuthenticatedUsers"}, {"role": "READER", "userByEmail": "x@gmail.com"}], **FULL}
    assert check.evaluate(bad, {})[0] == "FAIL"


UNCONFIGURED_TRUST = {"context": {"metadata": {"trusted_users": None, "trusted_groups": None, "trusted_service_accounts": None,
                                               "trusted_domains": [], "trusted_domains_explicit": False}}}
CONFIGURED_TRUST = {"context": {"metadata": {"trusted_users": ["ok@example.com"], "trusted_groups": None,
                                             "trusted_service_accounts": None, "trusted_domains": [], "trusted_domains_explicit": False}}}


@pytest.mark.parametrize("cid", ["gcp.claude.bucket.policy_shared_access", "gcp.claude.subnetwork.policy_shared_access",
                                 "gcp.ports.billing_account_policy_shared_access"])
def test_unconfigured_trust_lists_decide_only_public_principals(cid):
    check = CORE[cid]
    def policy(*members):
        return {"iamPolicy": {"bindings": [{"role": "roles/viewer", "members": list(members)}]}}
    status, evidence = check.evaluate(policy("user:someone@example.com"), UNCONFIGURED_TRUST)
    assert status == "MANUAL" and "not configured" in evidence["reason"]
    status, evidence = check.evaluate(policy("user:someone@example.com", "allUsers"), UNCONFIGURED_TRUST)
    assert status == "FAIL"
    declared = evidence.get("untrusted_declarations", evidence.get("untrusted_nonproject_declarations"))
    assert [row["principal"] for row in declared] == ["allUsers"]
    # One configured list makes the others explicit empty lists.
    assert check.evaluate(policy("user:ok@example.com"), CONFIGURED_TRUST)[0] == "PASS"
    assert check.evaluate(policy("user:other@example.com"), CONFIGURED_TRUST)[0] == "FAIL"
    assert check.evaluate(policy("group:g@example.com"), CONFIGURED_TRUST)[0] == "FAIL"
    malformed = {"context": {"metadata": {**CONFIGURED_TRUST["context"]["metadata"], "trusted_users": "ok@example.com"}}}
    assert check.evaluate(policy("user:ok@example.com"), malformed)[0] == "UNKNOWN"
    assert check.evaluate({"name": "x"}, UNCONFIGURED_TRUST)[0] == "UNKNOWN"


# Shape of the live GKE QA cluster read: proto3 JSON omits false booleans, a
# second pool lacks secure boot and uses GCE_METADATA, both pools use "default".
GKE_LIVE = {"name": "qa", "legacyAbac": {}, "masterAuthorizedNetworksConfig": {},
    "controlPlaneEndpointsConfig": {"ipEndpointsConfig": {"authorizedNetworksConfig": {}, "enabled": True}},
    "privateClusterConfig": {"privateEndpoint": "10.128.0.43"}, "networkConfig": {"network": "projects/p/global/networks/default"},
    "addonsConfig": {"networkPolicyConfig": {"disabled": True}}, "autopilot": {},
    "workloadIdentityConfig": {"workloadPool": "p.svc.id.goog"},
    "nodeConfig": {"serviceAccount": "default", "shieldedInstanceConfig": {"enableSecureBoot": True, "enableIntegrityMonitoring": True}},
    "nodePools": [
        {"name": "default-pool", "config": {"serviceAccount": "default", "workloadMetadataConfig": {"mode": "GKE_METADATA"},
            "shieldedInstanceConfig": {"enableSecureBoot": True, "enableIntegrityMonitoring": True}}},
        {"name": "pool-weak", "config": {"workloadMetadataConfig": {"mode": "GCE_METADATA"},
            "shieldedInstanceConfig": {"enableIntegrityMonitoring": True}}}]}


@pytest.mark.parametrize("cid,status", [
    ("gcp.gke.no_legacy_abac", "PASS"), ("gcp.gke.authorized_networks", "FAIL"), ("gcp.gke.private_nodes", "FAIL"),
    ("gcp.gke.network_policy", "FAIL"), ("gcp.ports.kubernetes_cluster_intra_node_visibility_enabled", "FAIL"),
    ("gcp.ports.kubernetes_cluster_shielded_node_secure_boot_enabled", "FAIL"),
    ("gcp.ports.kubernetes_cluster_shielded_instance_integrity_monitoring_enabled", "PASS"),
    ("gcp.gke.workload_identity", "PASS"), ("gcp.gke.node_pools_gke_metadata", "FAIL"),
    ("gcp.claude.gke.nodes_no_default_service_account", "FAIL"), ("gcp.gke.control_plane_restricted", "FAIL")])
def test_gke_omitted_false_values_and_every_node_pool_resolve(cid, status):
    item = copy.deepcopy(GKE_LIVE)
    found, evidence = CORE[cid].evaluate(item, {})
    assert found == status, evidence
    assert item == GKE_LIVE
    if cid.endswith("secure_boot_enabled"):
        assert evidence["failing_node_pools"] == ["pool-weak"]
    if cid.endswith("node_pools_gke_metadata"):
        assert evidence["node_pools_exposing_compute_metadata"] == [{"node_pool": "pool-weak", "mode": "GCE_METADATA"}]
    if cid.endswith("nodes_no_default_service_account"):
        # An omitted pool serviceAccount is the documented "default" account.
        assert evidence["default_service_account_pools"] == ["default-pool", "pool-weak"]


def test_gke_absence_rules_stay_unknown_without_identity_coverage_or_addon_state():
    for cid in ("gcp.gke.no_legacy_abac", "gcp.gke.authorized_networks", "gcp.gke.private_nodes", "gcp.gke.workload_identity",
                "gcp.ports.kubernetes_cluster_intra_node_visibility_enabled"):
        assert CORE[cid].evaluate({}, {})[0] == "UNKNOWN"
        assert CORE[cid].evaluate({"legacyAbac": {}}, {})[0] == "UNKNOWN"  # nameless object
    assert CORE["gcp.gke.no_legacy_abac"].evaluate({"name": "c", "legacyAbac": {"_coverage": {"enabled": {"status": "denied"}}}}, {})[0] == "UNKNOWN"
    # networkPolicy omitted while the add-on is not explicitly disabled is not decided.
    assert CORE["gcp.gke.network_policy"].evaluate({"name": "c"}, {})[0] == "UNKNOWN"
    assert CORE["gcp.gke.network_policy"].evaluate({"name": "c", "addonsConfig": {"networkPolicyConfig": {"disabled": False}}}, {})[0] == "UNKNOWN"
    autopilot = {"name": "c", "autopilot": {"enabled": True}}
    assert CORE["gcp.gke.workload_identity"].evaluate(autopilot, {})[0] == "PASS"
    assert CORE["gcp.gke.node_pools_gke_metadata"].evaluate(autopilot, {})[0] == "PASS"
    # Without a cluster workload pool an unset pool mode cannot be GKE_METADATA.
    unset = {"name": "c", "nodePools": [{"name": "a", "config": {}}]}
    assert CORE["gcp.gke.node_pools_gke_metadata"].evaluate(unset, {})[0] == "FAIL"
    assert CORE["gcp.gke.node_pools_gke_metadata"].evaluate({**unset, "workloadIdentityConfig": {"workloadPool": "p.svc.id.goog"}}, {})[0] == "UNKNOWN"
    assert CORE["gcp.ports.kubernetes_cluster_shielded_node_secure_boot_enabled"].evaluate({"name": "c", "nodePools": []}, {})[0] == "UNKNOWN"


@pytest.mark.parametrize("cid,item,status", [
    # Legacy-only read: omitted enablePrivateEndpoint is false.
    ("gcp.gke.private_endpoint", {"name": "c", "privateClusterConfig": {}}, "FAIL"),
    ("gcp.gke.private_endpoint", {"name": "c", "privateClusterConfig": {"enablePrivateEndpoint": True}}, "PASS"),
    # Live shape: ipEndpointsConfig.enablePublicEndpoint true.
    ("gcp.gke.private_endpoint", GKE_LIVE | {"controlPlaneEndpointsConfig": {"ipEndpointsConfig": {"enabled": True, "enablePublicEndpoint": True}}}, "FAIL"),
    ("gcp.gke.private_endpoint", {"name": "c", "controlPlaneEndpointsConfig": {"ipEndpointsConfig": {"enabled": True}}}, "PASS"),
    ("gcp.gke.private_endpoint", {"privateClusterConfig": {}}, "UNKNOWN"),
    ("gcp.gke.shielded_nodes", {"name": "c", "shieldedNodes": {}}, "FAIL"),
    ("gcp.gke.shielded_nodes", {"name": "c"}, "FAIL"),
    ("gcp.gke.shielded_nodes", {"shieldedNodes": {}}, "UNKNOWN"),
    ("gcp.ports.kubernetes_cluster_auto_repair_enabled", {"nodePools": [{"name": "a", "management": {"autoRepair": True}}, {"name": "b", "management": {"autoUpgrade": True}}]}, "FAIL"),
    ("gcp.ports.kubernetes_cluster_auto_repair_enabled", {"nodePools": [{"name": "a", "management": {"autoRepair": True}}, {"name": "b"}]}, "UNKNOWN"),
    ("gcp.ports.kubernetes_cluster_auto_upgrade_enabled", {"nodePools": [{"name": "a", "management": {"autoUpgrade": True}}]}, "PASS"),
    ("gcp.ports.kubernetes_cluster_use_ip_aliases", {"name": "c", "ipAllocationPolicy": {"useRoutes": True}}, "FAIL"),
    ("gcp.ports.kubernetes_cluster_use_ip_aliases", {"name": "c", "ipAllocationPolicy": {}}, "UNKNOWN"),
    ("gcp.ports.kubernetes_cluster_use_ip_aliases", {"name": "c", "ipAllocationPolicy": {"useIpAliases": True}}, "PASS"),
])
def test_gke_sweep_omitted_false_values(cid, item, status):
    assert CORE[cid].evaluate(copy.deepcopy(item), {})[0] == status


# OS Login: unset metadata is decided by the effective compute.requireOsLogin.
from peaso.checks.claude_gcp_k8s_common import scope_index as _oslogin_scope_index

_OSLOGIN_IDS = {"project": "gcp.claude.project.oslogin_enabled", "2fa": "gcp.reviewed.project.os_login_2fa",
                "instance": "gcp.compute.os_login", "ports": "gcp.ports.compute_oslogin_metadata_precedence"}
_ALL = {check.id: check for check in CHECKS}
# gcp.compute.os_login is a retired alias of the ports survivor; resolve it so both ids keep the same contract.
from peaso.checks import CHECK_ALIASES as _ALIASES
_ALL.update({retired: _ALL[survivor] for retired, survivor in _ALIASES.items()})


def _oslogin_policy(enforce=None, extra=None):
    items = list(extra or [])
    if enforce is not None:
        items.append({"constraint": "compute.requireOsLogin", "name": "projects/p/policies/compute.requireOsLogin",
                      "spec": {"rules": [{"enforce": enforce}]}})
    return items


def _project(items=None, scope="projects/p"):
    metadata = {"fingerprint": "f", "kind": "compute#metadata"}
    if items is not None:
        metadata["items"] = items
    return {"name": scope, "projectId": scope.split("/")[1], "commonInstanceMetadata": metadata, "_provenance": {"scope": scope}}


def _index(project=None, enforce=None):
    kinds = {"org_policy_effective": _oslogin_policy(enforce)}
    if project is not None:
        kinds["project"] = [project]
    return _oslogin_scope_index(kinds, scope="projects/p")


@pytest.mark.parametrize("items", [None, [], [{"key": "startup-script", "value": "x"}]])
def test_project_oslogin_unset_follows_effective_require_os_login(items):
    project = _project(items)
    check = _ALL[_OSLOGIN_IDS["project"]]
    assert check.evaluate(project, _index(enforce=False))[0] == "FAIL"
    assert check.evaluate(project, _index(enforce=True))[0] == "PASS"
    assert check.evaluate(project, _index())[0] == "UNKNOWN"  # constraint not collected
    denied = _oslogin_scope_index({"org_policy_effective": []}, scope="projects/p")
    denied["collections"]["org_policy_effective"] = [{"scope": "projects/p", "status": "denied"}]
    assert check.evaluate(project, denied)[0] == "UNKNOWN"


def test_project_oslogin_explicit_duplicate_and_compute_disabled():
    check = _ALL[_OSLOGIN_IDS["project"]]
    on = _project([{"key": "enable-oslogin", "value": "TRUE"}])
    off = _project([{"key": "enable-oslogin", "value": "FALSE"}])
    dup = _project([{"key": "enable-oslogin", "value": "TRUE"}, {"key": "enable-oslogin", "value": "TRUE"}])
    # An explicit TRUE passes regardless of the org policy: no new FAIL on enabled projects.
    for enforce in (None, False, True):
        assert check.evaluate(on, _index(enforce=enforce))[0] == "PASS"
    assert check.evaluate(off, _index(enforce=False))[0] == "FAIL"
    assert check.evaluate(dup, _index(enforce=False))[0] == "UNKNOWN"
    disabled = {"name": "projects/p", "_provenance": {"scope": "projects/p"},
                "_coverage": {"computeConfig": {"error": {"reason": "SERVICE_DISABLED", "service": "compute.googleapis.com",
                                                          "consumer": "projects/p"}}}}
    assert check.evaluate(disabled, _index(enforce=False))[0] == "NOT_APPLICABLE"
    other_error = {"name": "projects/p", "_provenance": {"scope": "projects/p"},
                   "_coverage": {"computeConfig": {"error": {"reason": "PERMISSION_DENIED"}}}}
    assert check.evaluate(other_error, _index(enforce=False))[0] == "UNKNOWN"


def test_os_login_2fa_unset_fails_duplicate_unknown_disabled_not_applicable():
    check = _ALL[_OSLOGIN_IDS["2fa"]]
    assert check.evaluate(_project(None), {})[0] == "FAIL"
    assert check.evaluate(_project([{"key": "enable-oslogin", "value": "TRUE"}]), {})[0] == "FAIL"
    assert check.evaluate(_project([{"key": "enable-oslogin", "value": "TRUE"}, {"key": "enable-oslogin-2fa", "value": "TRUE"}]), {})[0] == "PASS"
    dup = [{"key": "enable-oslogin-2fa", "value": "TRUE"}, {"key": "enable-oslogin-2fa", "value": "FALSE"}]
    assert check.evaluate(_project(dup), {})[0] == "UNKNOWN"
    disabled = {"name": "projects/p", "_provenance": {"scope": "projects/p"},
                "_coverage": {"computeConfig": {"error": {"reason": "SERVICE_DISABLED", "service": "compute.googleapis.com",
                                                          "consumer": "projects/p"}}}}
    assert check.evaluate(disabled, {})[0] == "NOT_APPLICABLE"


@pytest.mark.parametrize("cid", ["instance", "ports"])
def test_instance_oslogin_precedence_and_org_policy_fallback(cid):
    check = _ALL[_OSLOGIN_IDS[cid]]
    def vm(items=None):
        return {"name": "vm", "metadata": {"fingerprint": "f", **({"items": items} if items is not None else {})},
                "_provenance": {"scope": "projects/p"}}
    on, off = [{"key": "enable-oslogin", "value": "TRUE"}], [{"key": "enable-oslogin", "value": "FALSE"}]
    # Instance FALSE overrides project TRUE; instance TRUE wins over project unset.
    assert check.evaluate(vm(off), _index(_project(on), enforce=True))[0] == "FAIL"
    assert check.evaluate(vm(on), _index(_project(None), enforce=False))[0] == "PASS"
    # Instance unset inherits the project declaration.
    assert check.evaluate(vm(), _index(_project(on), enforce=False))[0] == "PASS"
    assert check.evaluate(vm(), _index(_project(off), enforce=True))[0] == "FAIL"
    # Unset at both levels: the effective constraint decides, absent -> UNKNOWN.
    assert check.evaluate(vm(), _index(_project([]), enforce=False))[0] == "FAIL"
    assert check.evaluate(vm(), _index(_project(None), enforce=True))[0] == "PASS"
    assert check.evaluate(vm(), _index(_project(None)))[0] == "UNKNOWN"
    assert check.evaluate(vm(), _index(None, enforce=False))[0] == "UNKNOWN"  # project relation missing


def test_app_engine_iap_omitted_on_identified_app_is_disabled():
    check = _ALL["gcp.ports.app_engine_application_iap_enabled"]
    app = {"id": "gcp-labs-0atempep", "name": "apps/gcp-labs-0atempep", "servingStatus": "SERVING",
           "defaultHostname": "gcp-labs-0atempep.uc.r.appspot.com"}
    assert check.evaluate(app, {})[0] == "FAIL"
    assert check.evaluate({**app, "iap": {"oauth2ClientId": "c"}}, {})[0] == "FAIL"
    assert check.evaluate({**app, "iap": {"enabled": True, "oauth2ClientId": "c"}}, {})[0] == "PASS"
    assert check.evaluate({**app, "iap": {"enabled": "yes"}}, {})[0] == "UNKNOWN"
    assert check.evaluate({"servingStatus": "SERVING"}, {})[0] == "UNKNOWN"
    assert check.evaluate({**app, "_coverage": {"iap": {"status": "denied"}}}, {})[0] == "UNKNOWN"


@pytest.mark.parametrize("purpose", ["MAC", "ASYMMETRIC_SIGN", "ENCRYPT_DECRYPT"])
def test_ports_kms_rotation_without_primary_matches_reviewed_applicability(purpose):
    check = _ALL["gcp.ports.kms_key_rotated_within_90_day"]
    key = {"name": "projects/p/locations/global/keyRings/r/cryptoKeys/k", "purpose": purpose,
           "versionTemplate": {"algorithm": "X"}, "_provenance": {"representation": "full"}}
    assert check.evaluate(key, {})[0] == "NOT_APPLICABLE"
    partial = {**key, "_provenance": {}}
    assert check.evaluate(partial, {})[0] == ("NOT_APPLICABLE" if purpose != "ENCRYPT_DECRYPT" else "UNKNOWN")
    assert check.evaluate({**key, "primary": {"state": "ENABLED"}}, {})[0] == ("FAIL" if purpose == "ENCRYPT_DECRYPT" else "NOT_APPLICABLE")
