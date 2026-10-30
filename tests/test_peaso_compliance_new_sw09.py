"""Sw09 signed predicates over scoped, complete GCP facts."""
from __future__ import annotations

import copy
import pytest

from peaso.checks import CHECKS, evaluate_check
from peaso.checks import compliance_new_sw09 as sw

SCOPE = "projects/test-project"
STAMP = "2026-10-12T12:00:00Z"


def entry(kind, row, *, status="collected", scope=SCOPE):
    return ({"type": kind, "scope": scope, "status": status, "items": [row]},
            {"type": kind, "scope": scope, "data": row})


def snapshot(kind, row, *, extras=None, policy=None, status="collected", scope=SCOPE):
    row.setdefault("_provenance", {}).setdefault("scope", SCOPE)
    envelope, resource = entry(kind, row, status=status, scope=scope)
    index = {"context": {"provider": "gcp", "scope": SCOPE, "created_at": STAMP,
             "metadata": {"sw09_policy": {"status": "collected", "scope": SCOPE, **(policy or {})}}},
             "collections": {kind: [envelope]}, kind: [resource]}
    if kind == "iam_policy" and policy and "approved_iam_roster" in policy:
        index["context"]["metadata"]["source_requests"] = [{"id": "iam-search", "method": "GET", "status": "collected",
            "url": "https://cloudasset.googleapis.com/v1/" + SCOPE + ":searchAllIamPolicies"}]
        envelope["source_requests"] = ["iam-search"]
        row["_provenance"]["source_requests"] = ["iam-search"]
    for other_kind, other_rows in (extras or {}).items():
        for other in other_rows:
            other.setdefault("_provenance", {}).setdefault("scope", SCOPE)
        index["collections"][other_kind] = [{"type": other_kind, "scope": SCOPE,
            "status": "collected", "items": other_rows}]
        index[other_kind] = [{"type": other_kind, "scope": SCOPE, "data": other}
                             for other in other_rows]
    return index


def outcome(check_id, row, *, extras=None, policy=None, status="collected", scope=SCOPE):
    kind = sw.META[check_id]["resource_kind"]
    return evaluate_check(check_id, row, snapshot(kind, row, extras=extras,
                                                 policy=policy, status=status, scope=scope))[0]


def base_cases():
    sql = {"name": "db1", "databaseVersion": "POSTGRES_16",
           "settings": {"databaseFlags": [{"name": "cloudsql.iam_authentication", "value": "on"}],
                        "passwordValidationPolicy": {"enablePasswordPolicy": True,
                                                     "failedAttemptsCheck": True}},
           "usersList": {"status": "collected", "instance": "db1",
                         "items": [{"name": "person", "type": "CLOUD_IAM_USER"}]}}
    audit = {"name": SCOPE,
             "effectiveAuditConfigs": [{"scope": SCOPE, "auditConfigs": [
                 {"service": "pubsub.googleapis.com", "auditLogConfigs": [
                     {"logType": "DATA_READ", "exemptedMembers": []},
                     {"logType": "DATA_WRITE", "exemptedMembers": []}]},
                 {"service": "spanner.googleapis.com", "auditLogConfigs": [
                     {"logType": "DATA_READ", "exemptedMembers": []},
                     {"logType": "DATA_WRITE", "exemptedMembers": []}]}]}],
             "_coverage": {"effectiveAuditConfigs": {"status": "collected",
                                                    "ancestry_known": True}}}
    full = {"_provenance": {"representation": "full"}}
    return {
        "gcp.sql.iam_database_authentication": (sql, {**sql, "usersList": {"status": "collected", "instance": "db1", "items": []}}, {}, {}),
        "gcp_cloudsql_failed_attempts_lockout": (sql, {**sql, "settings": {**sql["settings"],
            "passwordValidationPolicy": {"enablePasswordPolicy": True, "failedAttemptsCheck": False}}}, {}, {}),
        "gcp_sql_instance_sql_instance_does_have_iam_4b5fe00566e6": (sql, {**sql,
            "settings": {**sql["settings"], "databaseFlags": []}}, {}, {}),
        "gcp_sql_trace3625_off": ({**sql, "databaseVersion": "SQLSERVER_2019_STANDARD",
            "settings": {"databaseFlags": [{"name": "3625", "value": "off"}]}},
            {**sql, "databaseVersion": "SQLSERVER_2019_STANDARD",
            "settings": {"databaseFlags": [{"name": "3625", "value": "on"}]}}, {}, {}),
        "gcp_compute_approved_image": ({"name": "vm", "disks": [{"boot": True, "source": "disk-1"}]},
            {"name": "vm", "disks": [{"boot": True, "source": "disk-2"}]},
            {"disk": [{"selfLink": "disk-1", "sourceImage": "https://compute.googleapis.com/compute/v1/projects/approved/global/images/good"},
                      {"selfLink": "disk-2", "sourceImage": "https://compute.googleapis.com/compute/v1/projects/unknown/global/images/bad"}]},
            {"approved_image_projects": ["approved"]}),
        "gcp_pci_iam_policy_9a8ce875703d": (audit, {**audit, "effectiveAuditConfigs": [
            {"scope": SCOPE, "auditConfigs": [{"service": "pubsub.googleapis.com",
              "auditLogConfigs": [{"logType": "DATA_READ", "exemptedMembers": []}]}]}]}, {},
            {"required_audit_principals": ["user:auditor@example.test"]}),
        "gcp_pci_iam_policy_ca1281da7ab2": (audit, {**audit, "effectiveAuditConfigs": [
            {"scope": SCOPE, "auditConfigs": [{"service": "spanner.googleapis.com",
              "auditLogConfigs": [{"logType": "DATA_READ", "exemptedMembers": []}]}]}]}, {},
            {"required_audit_principals": ["user:auditor@example.test"]}),
        "gcp_network_auto_subnets_enabled": ({"selfLink": "network-1", "autoCreateSubnetworks": True},
            {"selfLink": "network-1", "autoCreateSubnetworks": False}, {},
            {"auto_subnet_vpcs": ["network-1"]}),
        "gcp_vpc_peering_allowlist": ({**full, "name": "vpc", "peerings": [{"network": "peer-good", "state": "ACTIVE"}]},
            {**full, "name": "vpc", "peerings": [{"network": "peer-bad", "state": "ACTIVE"}]}, {},
            {"approved_peer_networks": ["peer-good"]}),
        "gcp_certificate_validity": ({"name": "cert", "expireTime": "2026-11-12T00:00:00Z",
            "managed": {"state": "ACTIVE"}}, {"name": "cert", "expireTime": "2026-09-12T00:00:00Z",
            "managed": {"state": "ACTIVE"}}, {}, {}),
        "gcp_cloudbuild_trigger_trust": ({**full, "id": "trigger", "disabled": False,
            "github": {"owner": "org", "name": "repo"}, "serviceAccount": "build@project"},
            {**full, "id": "trigger", "disabled": False,
            "github": {"owner": "evil", "name": "repo"}, "serviceAccount": "build@project"}, {},
            {"approved_repositories": ["github/org/repo"],
             "approved_build_service_accounts": ["build@project"]}),
        "gcp_resource_approved_location": ({"name": "asset", "assetType": "x", "location": "europe-west1"},
            {"name": "asset", "assetType": "x", "location": "us-central1"}, {},
            {"approved_locations": ["europe-west1"]}),
        "gcp_resource_label_inventory": ({"name": "asset", "labels": {"owner": "one", "criticality": "high", "data_classification": "internal"}},
            {"name": "asset", "labels": {"owner": "one", "criticality": "high"}}, {},
            {"required_label_keys": ["owner", "criticality", "data_classification"]}),
        "gcp_gke_client_certificate_enabled": ({"name": "cluster", "masterAuth": {"clientCertificateConfig": {"issueClientCertificate": False}}},
            {"name": "cluster", "masterAuth": {"clientCertificateConfig": {"issueClientCertificate": True}}}, {},
            {"legacy_client_certificate_exceptions": []}),
        "gcp_c5_tls_policy": ({"name": "proxy", "sslPolicy": "policy-1"},
            {"name": "proxy", "sslPolicy": "policy-2"},
            {"ssl_policy": [{"selfLink": "policy-1", "minTlsVersion": "TLS_1_2", "profile": "CUSTOM",
                             "customFeatures": ["TLS_AES_128_GCM_SHA256"]},
                            {"selfLink": "policy-2", "minTlsVersion": "TLS_1_0", "profile": "CUSTOM",
                             "customFeatures": ["TLS_AES_128_GCM_SHA256"]}]},
            {"approved_min_tls": "TLS_1_2", "approved_ciphers": ["TLS_AES_128_GCM_SHA256"]}),
        "gcp.appengine.version_https_only": ({"name": "apps/test-project/services/default/versions/v1",
            "_provenance": {"representation": "full"},
            "servingStatus": "SERVING", "handlers": [{"securityLevel": "SECURE_ALWAYS"}]},
            {"name": "apps/test-project/services/default/versions/v1",
            "_provenance": {"representation": "full"},
            "servingStatus": "SERVING", "handlers": [{"securityLevel": "SECURE_DEFAULT"}]}, {}, {}),
        "gcp_https_proxy_mtls_required": ({**full, "name": "proxy", "serverTlsPolicy": "tls-1"},
            {**full, "name": "proxy", "serverTlsPolicy": "tls-2"},
            {"server_tls_policy": [{"name": "tls-1", "mtlsPolicy": {"clientValidationMode": "REJECT_INVALID"}},
                                   {"name": "tls-2", "mtlsPolicy": {"clientValidationMode": "ALLOW_INVALID_OR_MISSING_CLIENT_CERT"}}]}, {}),
        "gcp_autoscaler_capacity_target": ({"name": "scale", "target": "mig", "autoscalingPolicy": {
            "cpuUtilization": {"utilizationTarget": 0.7}, "maxNumReplicas": 5}},
            {"name": "scale", "target": "mig", "autoscalingPolicy": {
            "cpuUtilization": {"utilizationTarget": 0.9}, "maxNumReplicas": 5}},
            {"instance_group_manager": [{"selfLink": "mig", "targetSize": 3}]}, {}),
        "gcp_pci_firewall_2080b14f1361": ({**full, "name": "firewall", "direction": "INGRESS",
            "disabled": False, "sourceRanges": ["10.0.0.0/8"], "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}]},
            {**full, "name": "firewall", "direction": "INGRESS",
            "disabled": False, "sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}]}, {}, {}),
    }


CASES = base_cases()
CASES.update({
    "gcp_c5_network_separation": (
        {"selfLink": "network-1"}, {"selfLink": "network-2"},
        {"instance": [{"name": "prod", "labels": {"env": "production"},
                       "networkInterfaces": [{"network": "network-1", "subnetwork": "subnet-a"},
                                             {"network": "network-2", "subnetwork": "subnet-shared"}]},
                      {"name": "dev", "labels": {"env": "nonproduction"},
                       "networkInterfaces": [{"network": "network-1", "subnetwork": "subnet-b"},
                                             {"network": "network-2", "subnetwork": "subnet-shared"}]}]},
        {"segregated_vpcs": ["network-1", "network-2"]}),
    "gcp_c5_network_topology": (
        {"selfLink": "network-1"}, {"selfLink": "network-2"},
        {"subnetwork": [{"selfLink": "subnet-a", "network": "network-1", "region": "region-1"}],
         "firewall": [{"selfLink": "fw-a", "network": "network-1"}]},
        {"topology_register": [{"kind": "network", "name": "network-1"},
                               {"kind": "subnetwork", "name": "subnet-a",
                                "network": "network-1", "region": "region-1"}]}),
    "gcp_c5_iam_inventory": (
        {"name": "resource-1", "bindings": [{"role": "roles/viewer", "members": ["user:approved@example.test"]}]},
        {"name": "resource-1", "bindings": [{"role": "roles/owner", "members": ["user:unknown@example.test"]}]},
        {}, {"approved_iam_roster": [{"resource": "resource-1", "role": "roles/viewer",
                                      "principal": "user:approved@example.test", "approved": True}]}),
})


@pytest.mark.parametrize("check_id", sorted(CASES))
def test_sw09_signed_pass_fail_and_metadata(check_id):
    good, bad, extras, policy = CASES[check_id]
    expected = ("UNKNOWN", "UNKNOWN") if check_id == "gcp_cloudsql_failed_attempts_lockout" else ("PASS", "FAIL")
    assert outcome(check_id, good, extras=extras, policy=policy) == expected[0]
    assert outcome(check_id, bad, extras=extras, policy=policy) == expected[1]


@pytest.mark.parametrize("check_id", sorted(CASES))
def test_sw09_incomplete_foreign_and_missing_are_unknown(check_id):
    good, _, extras, policy = CASES[check_id]
    assert outcome(check_id, good, extras=extras, policy=policy, status="partial") == "UNKNOWN"
    assert outcome(check_id, good, extras=extras, policy=policy, scope="projects/foreign") == "UNKNOWN"
    malformed = copy.deepcopy(good)
    malformed["_coverage"] = {**malformed.get("_coverage", {}),
                                "name": {"status": "denied"}}
    if check_id not in ("gcp_resource_label_inventory", "gcp_network_auto_subnets_enabled"):
        assert outcome(check_id, malformed, extras=extras, policy=policy) == "UNKNOWN"
    else:
        malformed = copy.deepcopy(good)
        key = "labels" if check_id == "gcp_resource_label_inventory" else "autoCreateSubnetworks"
        malformed[key] = {"malformed": True}
        assert outcome(check_id, malformed, extras=extras, policy=policy) == "UNKNOWN"
    if policy:
        assert outcome(check_id, good, extras=extras, policy={}) == "UNKNOWN"
    else:
        missing_keys = {
            "gcp.sql.iam_database_authentication": "usersList",
            "gcp_cloudsql_failed_attempts_lockout": "settings",
            "gcp_sql_instance_sql_instance_does_have_iam_4b5fe00566e6": "settings",
            "gcp_sql_trace3625_off": "settings",
            "gcp_pci_iam_policy_9a8ce875703d": "effectiveAuditConfigs",
            "gcp_pci_iam_policy_ca1281da7ab2": "effectiveAuditConfigs",
            "gcp_certificate_validity": "managed",
            "gcp.appengine.version_https_only": "handlers",
            "gcp_https_proxy_mtls_required": "_provenance",
            "gcp_autoscaler_capacity_target": "target",
            "gcp_pci_firewall_2080b14f1361": "_provenance",
        }
        missing = copy.deepcopy(good)
        missing.pop(missing_keys[check_id])
        assert outcome(check_id, missing, extras=extras, policy=policy) == "UNKNOWN"


def test_sw09_not_applicable_and_uncertain_edges():
    sql, _, _, _ = CASES["gcp.sql.iam_database_authentication"]
    assert outcome("gcp.sql.iam_database_authentication", {**sql,
        "databaseVersion": "SQLSERVER_2019_STANDARD"}) == "NOT_APPLICABLE"
    assert outcome("gcp_cloudsql_failed_attempts_lockout", {**sql,
        "databaseVersion": "SQLSERVER_2019_STANDARD"}) == "UNKNOWN"
    assert outcome("gcp_sql_trace3625_off", sql) == "NOT_APPLICABLE"
    trigger, _, _, policy = CASES["gcp_cloudbuild_trigger_trust"]
    assert outcome("gcp_cloudbuild_trigger_trust", {**trigger, "disabled": True}, policy=policy) == "NOT_APPLICABLE"
    version, _, _, _ = CASES["gcp.appengine.version_https_only"]
    assert outcome("gcp.appengine.version_https_only", {**version,
        "servingStatus": "STOPPED"}) == "NOT_APPLICABLE"
    rule, _, _, _ = CASES["gcp_pci_firewall_2080b14f1361"]
    assert outcome("gcp_pci_firewall_2080b14f1361", {**rule,
        "direction": "EGRESS"}) == "NOT_APPLICABLE"
    network, _, _, policy = CASES["gcp_network_auto_subnets_enabled"]
    assert outcome("gcp_network_auto_subnets_enabled", {**network, "selfLink": "outside"},
                   policy=policy) == "NOT_APPLICABLE"
    network, _, extras, policy = CASES["gcp_c5_network_separation"]
    assert outcome("gcp_c5_network_separation", {**network, "selfLink": "outside"},
                   extras=extras, policy=policy) == "NOT_APPLICABLE"
    proxy, _, extras, _ = CASES["gcp_https_proxy_mtls_required"]
    proxy_without_policy = {key: value for key, value in proxy.items() if key != "serverTlsPolicy"}
    assert outcome("gcp_https_proxy_mtls_required", proxy_without_policy,
                   extras=extras) == "FAIL"
    assert outcome("gcp_sql_trace3625_off", {**sql,
        "databaseVersion": "SQLSERVER_2019_STANDARD",
        "settings": {"databaseFlags": []}}) == "UNKNOWN"


def teardown_module(module):
    # Direct module import registers checks; isolate these tests from later files.
    ids = set(sw.META)
    CHECKS[:] = [check for check in CHECKS if check.id not in ids]


@pytest.mark.parametrize("check_id", sorted(CASES))
@pytest.mark.parametrize("mutation", ["coverage", "provenance", "provider", "duplicate"])
def test_sw09_shared_inventory_authority(check_id, mutation):
    row, _, extras, policy = copy.deepcopy(CASES[check_id])
    ix = snapshot(sw.META[check_id]["resource_kind"], row, extras=extras, policy=policy)
    kind = sw.META[check_id]["resource_kind"]
    if mutation == "coverage":
        ix["collections"][kind][0]["coverage_status"] = "partial"
    elif mutation == "provenance":
        row["_provenance"]["scope"] = "projects/foreign"
    elif mutation == "provider":
        ix[kind][0]["provider"] = "aws"
    else:
        ix[kind].append(copy.deepcopy(ix[kind][0]))
        ix["collections"][kind][0]["items"].append(copy.deepcopy(row))
    assert evaluate_check(check_id, row, ix)[0] == "UNKNOWN"


@pytest.mark.parametrize("kind,name", [("ALIEN", "person"), ("CLOUD_IAM_USER", "")])
def test_sql_iam_malformed_user_unknown(kind, name):
    row = copy.deepcopy(CASES["gcp.sql.iam_database_authentication"][0])
    row["usersList"]["items"] = [{"type": kind, "name": name}]
    assert outcome("gcp.sql.iam_database_authentication", row) == "UNKNOWN"


@pytest.mark.parametrize("engine", ["MYSQL_", "POSTGRES_garbage", "SQLSERVER_UNKNOWN"])
@pytest.mark.parametrize("cid", ["gcp.sql.iam_database_authentication", "gcp_sql_trace3625_off",
                                 "gcp_sql_instance_sql_instance_does_have_iam_4b5fe00566e6"])
def test_sql_engine_malformed_version_unknown(cid, engine):
    row = copy.deepcopy(CASES[cid][0])
    row["databaseVersion"] = engine
    assert outcome(cid, row) == "UNKNOWN"


def test_sql_lockout_rejects_invented_instance_field_and_real_user_shape():
    cid = "gcp_cloudsql_failed_attempts_lockout"
    row = copy.deepcopy(CASES[cid][0])
    assert outcome(cid, row) == "UNKNOWN"  # fabricated failedAttemptsCheck=true
    row["settings"]["passwordValidationPolicy"].pop("failedAttemptsCheck")
    row["usersList"]["items"][0]["passwordPolicy"] = {"enableFailedAttemptsCheck": True}
    assert outcome(cid, row) == "UNKNOWN"  # partial user configuration does not prove full principal scope


@pytest.mark.parametrize("cid", ["gcp_pci_iam_policy_9a8ce875703d", "gcp_pci_iam_policy_ca1281da7ab2"])
@pytest.mark.parametrize("mutation", ["foreign", "duplicate", "missing_root", "missing_scope"])
def test_effective_audit_rejects_invalid_ancestry(cid, mutation):
    row, _, extras, policy = copy.deepcopy(CASES[cid])
    if mutation == "foreign":
        row["effectiveAuditConfigs"][0]["scope"] = "projects/foreign"
    elif mutation == "duplicate":
        row["effectiveAuditConfigs"].append(copy.deepcopy(row["effectiveAuditConfigs"][0]))
    elif mutation == "missing_root":
        row["effectiveAuditConfigs"] = []
    else:
        row["_coverage"]["effectiveAuditConfigs"]["missing_scopes"] = ["organizations/1"]
    assert outcome(cid, row, extras=extras, policy=policy) == "UNKNOWN"


def test_appengine_masked_handler_list_is_unknown():
    cid = "gcp.appengine.version_https_only"
    row = copy.deepcopy(CASES[cid][0])
    row["_field_mask"] = "versions(id,name,servingStatus,env,handlers(securityLevel)),nextPageToken"
    row["_provenance"]["representation"] = "partial"
    assert outcome(cid, row) == "UNKNOWN"
    row["_provenance"]["representation"] = "full"
    assert outcome(cid, row) == "UNKNOWN"  # a field mask cannot be promoted to full
    row["servingStatus"] = "STOPPED"
    assert outcome(cid, row) == "NOT_APPLICABLE"


def test_autoscaler_boolean_is_not_a_number():
    cid = "gcp_autoscaler_capacity_target"
    row, _, extras, policy = copy.deepcopy(CASES[cid])
    row["autoscalingPolicy"]["cpuUtilization"]["utilizationTarget"] = True
    assert outcome(cid, row, extras=extras, policy=policy) == "UNKNOWN"


@pytest.mark.parametrize("field", ["sourceTags", "sourceServiceAccounts"])
def test_firewall_selectors_do_not_default_to_public(field):
    cid = "gcp_pci_firewall_2080b14f1361"
    row = copy.deepcopy(CASES[cid][1])
    row.pop("sourceRanges")
    row[field] = ["selected-source"]
    assert outcome(cid, row) == "PASS"
    row["sourceRanges"] = []
    assert outcome(cid, row) == "PASS"
    row[field] = []
    assert outcome(cid, row) == "FAIL"
    row["_coverage"] = {field: {"status": "denied"}}
    assert outcome(cid, row) == "UNKNOWN"


@pytest.mark.parametrize("protocol,ports", [("all", None), ("ipip", None), ("tcp", ["0"]), ("6", ["0-65535"])])
def test_firewall_all_protocols_and_zero_port(protocol, ports):
    cid = "gcp_pci_firewall_2080b14f1361"
    row = copy.deepcopy(CASES[cid][1])
    row["allowed"] = [{"IPProtocol": protocol, **({"ports": ports} if ports is not None else {})}]
    assert outcome(cid, row) == "FAIL"
    row["sourceRanges"] = ["10.0.0.0/8"]
    assert outcome(cid, row) == "PASS"


def test_firewall_ports_on_non_port_protocol_unknown():
    cid = "gcp_pci_firewall_2080b14f1361"
    row = copy.deepcopy(CASES[cid][1])
    row["allowed"] = [{"IPProtocol": "icmp", "ports": ["443"]}]
    assert outcome(cid, row) == "UNKNOWN"


def test_empty_custom_tls_features_unknown():
    cid = "gcp_c5_tls_policy"
    row, _, extras, policy = copy.deepcopy(CASES[cid])
    extras["ssl_policy"][0]["customFeatures"] = []
    assert outcome(cid, row, extras=extras, policy=policy) == "UNKNOWN"


def test_iam_roster_contradiction_and_search_coverage_unknown():
    cid = "gcp_c5_iam_inventory"
    row, _, extras, policy = copy.deepcopy(CASES[cid])
    policy["approved_iam_roster"].append({**policy["approved_iam_roster"][0], "approved": False})
    assert outcome(cid, row, policy=policy) == "UNKNOWN"
    policy["approved_iam_roster"].pop()
    ix = snapshot("iam_policy", row, policy=policy)
    ix["context"]["metadata"]["source_requests"] = []
    assert evaluate_check(cid, row, ix)[0] == "UNKNOWN"
    ix["context"]["metadata"]["source_requests"] = [{"id": "root-only", "method": "POST", "status": "collected",
        "url": "https://cloudresourcemanager.googleapis.com/v3/" + SCOPE + ":getIamPolicy"}]
    assert evaluate_check(cid, row, ix)[0] == "UNKNOWN"


@pytest.mark.parametrize("mutation", ["empty_interfaces", "empty_subnetwork"])
def test_network_separation_missing_relationship_unknown(mutation):
    cid = "gcp_c5_network_separation"
    row, _, extras, policy = copy.deepcopy(CASES[cid])
    if mutation == "empty_interfaces":
        extras["instance"][0]["networkInterfaces"] = []
    else:
        extras["instance"][0]["networkInterfaces"][0]["subnetwork"] = ""
    assert outcome(cid, row, extras=extras, policy=policy) == "UNKNOWN"


def test_cloudbuild_source_project_omission_uses_owner_project():
    cid = "gcp_cloudbuild_trigger_trust"
    row = {"id": "trigger", "_provenance": {"representation": "full"},
           "triggerTemplate": {"repoName": "repo"}, "serviceAccount": "build@project"}
    policy = {"approved_repositories": [SCOPE + "/repos/repo"], "approved_build_service_accounts": ["build@project"]}
    assert outcome(cid, row, policy=policy) == "PASS"
    row["_coverage"] = {"triggerTemplate": {"status": "denied"}}
    assert outcome(cid, row, policy=policy) == "UNKNOWN"


@pytest.mark.parametrize("expiry,expected", [("2026-11-12T00:00:00Z", "PASS"), ("2026-09-12T00:00:00Z", "FAIL"),
                                            ("20261112T000000Z", "UNKNOWN")])
def test_certificate_selfmanaged_and_malformed_timestamp(expiry, expected):
    cid = "gcp_certificate_validity"
    row = {"name": "cert", "expireTime": expiry, "selfManaged": {}}
    assert outcome(cid, row) == expected
    row["managed"] = {"state": "ACTIVE"}
    assert outcome(cid, row) == "UNKNOWN"


def test_collector_iam_search_provenance_and_root_only_snapshot():
    from tests.test_peaso_collectors_gcp import snapshot as collect, collection
    cid = "gcp_c5_iam_inventory"
    policy = {"status": "collected", "scope": "projects/p-one", "approved_iam_roster": [
        {"resource": "//compute.googleapis.com/projects/p-one/zones/us/instances/vm", "role": "roles/viewer",
         "principal": "user:approved@example.test", "approved": True}]}
    def resolve(request):
        if request["url"].endswith(":getIamPolicy"):
            return {}
        if request["url"].endswith(":searchAllIamPolicies"):
            return {"results": [{"resource": policy["approved_iam_roster"][0]["resource"],
                "policy": {"bindings": [{"role": "roles/viewer", "members": ["user:approved@example.test"]}]}}]}
        return {}
    for resource_iam in (True, False):
        result, _ = collect(["iam_policy"], resolve, resource_iam=resource_iam, sw09_policy=policy)
        env = collection(result, "iam_policy")
        ix = {"context": {"provider": "gcp", "scope": "projects/p-one", "metadata": result["metadata"]},
              "collections": {"iam_policy": [env]}, "iam_policy": [
                  {"type": "iam_policy", "scope": "projects/p-one", "data": row} for row in env["items"]]}
        for row in env["items"]:
            expected = "PASS" if row["name"].startswith("//compute") and resource_iam else "UNKNOWN"
            assert evaluate_check(cid, row, ix)[0] == expected


@pytest.mark.parametrize("mode,expected", [("ALLOW_INVALID_OR_MISSING_CLIENT_CERT", "FAIL"),
                                          ("ALLOW_INVALID", "UNKNOWN"), ("REJECT_INVALID", "PASS")])
def test_mtls_real_provider_enum(mode, expected):
    cid = "gcp_https_proxy_mtls_required"
    row, _, extras, _ = copy.deepcopy(CASES[cid])
    extras["server_tls_policy"][0]["mtlsPolicy"]["clientValidationMode"] = mode
    assert outcome(cid, row, extras=extras) == expected


@pytest.mark.parametrize("record", [{"kind": "subnetwork", "name": "absent"},
                                    {"kind": "firewall", "name": "absent", "network": ""}])
def test_missing_topology_asset_does_not_validate_malformed_register(record):
    cid = "gcp_c5_network_topology"
    row, _, extras, policy = copy.deepcopy(CASES[cid])
    policy["topology_register"].append(record)
    assert outcome(cid, row, extras=extras, policy=policy) == "UNKNOWN"


@pytest.mark.parametrize("value,expected", [("on", "FAIL"), ("off", "PASS")])
def test_sql_trace_actual_provider_flag_name(value, expected):
    cid = "gcp_sql_trace3625_off"
    row = {"name": "db", "databaseVersion": "SQLSERVER_2019_STANDARD", "settings": {
        "databaseFlags": [{"name": "3625 (trace flag)", "value": value}]}}
    assert outcome(cid, row) == expected
    row["settings"]["databaseFlags"].append({"name": "3625", "value": "off"})
    assert outcome(cid, row) == "UNKNOWN"
