"""Isolated tests for eight signed Azure snapshot compliance predicates.

Run this file alone with --noconftest. Registration is immediately restored;
all assertions use the captured module-local Check objects.
"""
from __future__ import annotations

import copy

import pytest

from peaso.checks import CHECKS

_BASELINE = tuple(CHECKS)
from peaso.checks import compliance_new_sw22 as sw

CHECKS[:] = _BASELINE

SCOPE = "/subscriptions/sub"
TENANT = "tenant"
NOW = "2026-10-12T00:00:00Z"
PREFIX = SCOPE + "/resourceGroups/rg/providers/"
PRINCIPAL = "12345678-1234-1234-1234-123456789abc"


def full(operation, version="2025-09-01", **extra):
    return {"representation": "full", "read_only": True,
            "source_operation": operation, "api_version": version, **extra}


def facts(kinds, *, scope=SCOPE, metadata=None, services=None):
    context = {"provider": "azure", "scope": scope, "created_at": NOW,
               "metadata": {} if metadata is None else metadata}
    index = {"context": context, "collections": {}}
    for kind, rows in kinds.items():
        service = (services or {}).get(kind, "ARM")
        index["collections"][kind] = [{"type": kind, "scope": scope, "service": service,
                                       "status": "collected" if rows else "empty", "items": rows}]
        index[kind] = [{"provider": "azure", "type": kind, "scope": scope, "data": row} for row in rows]
    return index


def policy(name, **extra):
    return {"sw22": {name: {"status": "collected", "scope": SCOPE,
                            "evidence_ref": "approved-policy-v1", **extra}}}


def evaluate(cid, index, item=None):
    return sw.LOCAL_CHECKS[cid].evaluate(index["context"] if item is None else item, index)


def easm_fixture():
    row = {"id": PREFIX + "Microsoft.Easm/workspaces/easm",
           "properties": {"provisioningState": "Succeeded"}}
    return facts({"easm_workspace": [row]}), None


def arc_fixture():
    rid = PREFIX + "Microsoft.Kubernetes/connectedClusters/arc"
    row = {"id": rid, "_coverage": {"extensions": {"status": "collected", "parent_id": rid}},
           "extensions": [{"id": rid + "/providers/Microsoft.KubernetesConfiguration/extensions/defender",
                           "parent_id": rid, "properties": {"extensionType": "microsoft.azuredefender.kubernetes",
                                                              "provisioningState": "Succeeded"}}]}
    return facts({"arc_kubernetes_cluster": [row]}), None


def credential_fixture():
    proof = {"tenant_id": TENANT, "tenant_verified": True, "credential_context_id": "capture",
             "customer_context_id": "customer"}
    row = {"id": PRINCIPAL, "_provenance": {**proof, "read_only": True, "endpoint": "/v1.0/servicePrincipals"},
           "passwordCredentials": [{"keyId": "credential", "startDateTime": "2026-09-01T00:00:00Z",
                                     "endDateTime": "2027-01-01T00:00:00Z"}], "keyCredentials": []}
    index = facts({"service_principal": [row]}, scope="/tenants/" + TENANT,
                  metadata=proof, services={"service_principal": "Microsoft.Graph"})
    index["collections"]["service_principal"][0]["_provenance"] = proof.copy()
    return index, row


def port_fixture():
    row = {"metadata": {"namespace": "apps", "name": "web", "uid": "uid-web"},
           "spec": {"type": "ClusterIP", "ports": [{"port": 443}]},
           "_provenance": full("core/v1/services:LIST", "v1", cluster_id="aks")}
    metadata = policy("approved_service_ports", cluster_id="aks", services=[{
        "namespace": "apps", "name": "web", "allowed": [{"port": 443, "protocol": "TCP"}]}])
    metadata["cluster_id"] = "aks"
    return facts({"service": [row]}, metadata=metadata, services={"service": "Kubernetes.core/v1"}), None


def ise_fixture():
    vault = PREFIX + "Microsoft.KeyVault/vaults/keys"
    row = {"id": PREFIX + "Microsoft.Logic/integrationServiceEnvironments/ise",
           "_provenance": full("Microsoft.Logic/integrationServiceEnvironments:GET", "2019-05-01"),
           "properties": {"encryptionConfiguration": {"encryptionKeyReference": {
               "keyName": "cmk", "keyVault": {"id": vault}, "keyVersion": "version1"}}}}
    metadata = policy("approved_ise_keys", keys=[{"vault_id": vault, "key_name": "cmk", "key_version": "version1"}])
    return facts({"integration_service_environment": [row]}, metadata=metadata), None


def restore_fixture():
    from tests.backup_c5_fixture_data import fixture_index
    return fixture_index(sw.RESTORE_ID, SCOPE, NOW), None


def source_fixture():
    repo = {"id": "repo1", "organization_id": "provider-org", "owner": "cloud_service_provider",
            "_provenance": full("AzureDevOps.repositories:LIST")}
    metadata = policy("provider_source_lifecycle", organization_id="provider-org", provider_owned=True,
                      max_age_seconds=86400, repositories=[{"repository_id": "repo1", "stage_ids": ["build", "release"]}])
    records = [{"scope": SCOPE, "organization_id": "provider-org", "repository_id": "repo1", "stage_id": stage,
                "control": control, "source_authority": "provider_auditor", "outcome": "enforced",
                "observed_at": "2026-10-11T12:00:00Z", "evidence_ref": "provider-attestation",
                "_provenance": full("external:provider-source-lifecycle")}
               for stage in ("build", "release") for control in sorted(sw._SOURCE_CONTROLS)]
    return facts({"source_control": [repo], "source_control_evidence": records}, metadata=metadata), None


def edge_binding(resource, kind, frontends, **extra):
    rid = resource["id"]
    return {"resource_id": rid, "resource_etag": resource["etag"], "resource_kind": kind,
            "public": bool(frontends), "public_frontend_ids": frontends,
            "_provenance": full("Azure.publicEdgeProtection:resolve"),
            "_coverage": {"frontends": {"status": "collected" if frontends else "empty", "parent_id": rid}}, **extra}


def network_fixture():
    ip = {"id": PREFIX + "Microsoft.Network/publicIPAddresses/ip", "etag": "v1",
          "_provenance": full("Microsoft.Network/publicIPAddresses:GET"),
          "properties": {"ddosSettings": {"protectionMode": "Enabled"}}}
    gateway = {"id": PREFIX + "Microsoft.Network/applicationGateways/gw", "etag": "v1",
               "_provenance": full("Microsoft.Network/applicationGateways:GET"),
               "properties": {"frontendIPConfigurations": [{
                   "id": PREFIX + "Microsoft.Network/applicationGateways/gw/frontendIPConfigurations/public",
                   "properties": {"publicIPAddress": {"id": ip["id"]}}}]}}
    waf = {"id": PREFIX + "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/waf",
           "_provenance": full("Azure.WAF:GET"), "properties": {
               "policySettings": {"state": "Enabled", "mode": "Prevention"},
               "customRules": [{"name": "block"}], "provisioningState": "Succeeded", "resourceState": "Enabled"}}
    ip_binding = edge_binding(ip, "public_ip", [ip["id"]])
    gw_binding = edge_binding(gateway, "application_gateway", [gateway["properties"]["frontendIPConfigurations"][0]["id"]],
                              effective_waf_policy_ids=[waf["id"]], waf_linkage_evidence_ref="effective-route-bindings")
    gw_binding["_coverage"]["effective_waf"] = {"status": "collected", "parent_id": gateway["id"]}
    kinds = {kind: [] for kind in sw._EDGE_TYPES}
    kinds.update(public_ip=[ip], application_gateway=[gateway], public_edge_binding=[ip_binding, gw_binding], waf_policy=[waf])
    return facts(kinds), None


FIXTURES = {sw.NETWORK_ID: network_fixture, sw.CREDENTIAL_ID: credential_fixture,
            sw.RESTORE_ID: restore_fixture, sw.SOURCE_ID: source_fixture, sw.EASM_ID: easm_fixture,
            sw.ARC_ID: arc_fixture, sw.PORT_ID: port_fixture, sw.ISE_ID: ise_fixture}


def row(index, kind):
    return index[kind][0]["data"]


@pytest.mark.parametrize("cid", sw.IDS)
def test_signed_pass_and_immutable_repeat(cid):
    index, item = FIXTURES[cid]()
    original = copy.deepcopy(index)
    for _ in range(2):
        assert evaluate(cid, index, item)[0] == "PASS"
    assert index == original
    assert CHECKS == list(_BASELINE)


@pytest.mark.parametrize("cid", sw.IDS)
def test_positive_failure(cid):
    index, item = FIXTURES[cid]()
    if cid == sw.NETWORK_ID:
        row(index, "public_ip")["properties"]["ddosSettings"]["protectionMode"] = "Disabled"
    elif cid == sw.CREDENTIAL_ID:
        item["passwordCredentials"][0]["startDateTime"] = "2026-01-01T00:00:00Z"
    elif cid == sw.RESTORE_ID:
        row(index, "restore_test_record")["validation_result"] = "Failed"
        row(index, "restore_test_record")["restored_data_verified"] = False
        row(index, "restore_test_record")["validationEvidence"]["usableDataValidation"]["result"] = "Failed"
    elif cid == sw.SOURCE_ID:
        row(index, "source_control_evidence")["outcome"] = "missing"
    elif cid == sw.EASM_ID:
        row(index, "easm_workspace")["properties"]["provisioningState"] = "Failed"
    elif cid == sw.ARC_ID:
        row(index, "arc_kubernetes_cluster")["extensions"][0]["properties"]["provisioningState"] = "Failed"
    elif cid == sw.PORT_ID:
        row(index, "service")["spec"]["ports"][0]["port"] = 80
    elif cid == sw.ISE_ID:
        row(index, "integration_service_environment")["properties"]["encryptionConfiguration"] = {}
    assert evaluate(cid, index, item)[0] == "FAIL"


@pytest.mark.parametrize("cid", sw.IDS)
@pytest.mark.parametrize("problem", ["incomplete", "missing_inventory", "malformed", "foreign_scope", "foreign_wrapper", "next_page"])
def test_unknown_inventory_boundary(cid, problem):
    index, item = FIXTURES[cid]()
    kind = sw.LOCAL_CHECKS[cid].dependencies[0]
    envelope = index["collections"][kind][0]
    if problem == "incomplete":
        envelope["status"] = "partial"
    elif problem == "missing_inventory":
        del index["collections"][kind]
    elif problem == "malformed":
        envelope["items"] = "invalid"
    elif problem == "foreign_scope":
        envelope["scope"] = "/subscriptions/foreign"
    elif problem == "foreign_wrapper":
        index[kind][0]["scope"] = "/subscriptions/foreign"
    elif problem == "next_page":
        envelope["nextLink"] = "unconsumed-page"
    assert evaluate(cid, index, item)[0] == "UNKNOWN"


@pytest.mark.parametrize("cid", sw.IDS)
def test_unknown_missing_or_malformed_required_fact(cid):
    index, item = FIXTURES[cid]()
    if cid == sw.NETWORK_ID:
        del row(index, "public_ip")["properties"]["ddosSettings"]
    elif cid == sw.CREDENTIAL_ID:
        del item["passwordCredentials"][0]["startDateTime"]
    elif cid == sw.RESTORE_ID:
        del row(index, "restore_test_record")["identity_evidence_ref"]
    elif cid == sw.SOURCE_ID:
        del row(index, "source_control_evidence")["evidence_ref"]
    elif cid == sw.EASM_ID:
        row(index, "easm_workspace")["properties"]["provisioningState"] = False
    elif cid == sw.ARC_ID:
        row(index, "arc_kubernetes_cluster")["extensions"] = "invalid"
    elif cid == sw.PORT_ID:
        row(index, "service")["spec"]["ports"][0]["port"] = True
    elif cid == sw.ISE_ID:
        del row(index, "integration_service_environment")["properties"]["encryptionConfiguration"]
    assert evaluate(cid, index, item)[0] == "UNKNOWN"


@pytest.mark.parametrize("cid", [sw.NETWORK_ID, sw.ARC_ID, sw.PORT_ID])
def test_not_applicable_complete_empty_inventory(cid):
    index, _ = FIXTURES[cid]()
    for kind in list(index["collections"]):
        index[kind] = []
        index["collections"][kind][0].update(status="empty", items=[])
    assert evaluate(cid, index)[0] == "NOT_APPLICABLE"


def test_easm_empty_fails_and_pagination_gap_never_passes():
    index = facts({"easm_workspace": []})
    assert evaluate(sw.EASM_ID, index)[0] == "FAIL"
    index, _ = easm_fixture()
    row(index, "easm_workspace")["properties"]["provisioningState"] = "new-state"
    assert evaluate(sw.EASM_ID, index)[0] == "UNKNOWN"


@pytest.mark.parametrize("state", ["Failed", "Creating", "Updating", "Deleting"])
def test_arc_no_successful_matching_extension_fails(state):
    index, _ = arc_fixture()
    extension = row(index, "arc_kubernetes_cluster")["extensions"][0]
    extension["properties"]["provisioningState"] = state
    assert evaluate(sw.ARC_ID, index)[0] == "FAIL"
    extension["properties"]["provisioningState"] = "Unrecognized"
    assert evaluate(sw.ARC_ID, index)[0] == "UNKNOWN"


def test_arc_empty_extensions_fail_and_wrong_parent_unknown():
    index, _ = arc_fixture()
    cluster = row(index, "arc_kubernetes_cluster")
    cluster["extensions"] = []
    cluster["_coverage"]["extensions"]["status"] = "empty"
    assert evaluate(sw.ARC_ID, index)[0] == "FAIL"
    cluster["_coverage"]["extensions"]["parent_id"] += "foreign"
    assert evaluate(sw.ARC_ID, index)[0] == "UNKNOWN"


def test_credential_age_boundary_expired_future_empty_and_policy():
    index, item = credential_fixture()
    credential = item["passwordCredentials"][0]
    credential["startDateTime"] = "2026-07-14T00:00:00Z"  # exactly 90 days
    assert evaluate(sw.CREDENTIAL_ID, index, item)[0] == "PASS"
    credential["startDateTime"] = "2026-07-13T23:59:59Z"
    assert evaluate(sw.CREDENTIAL_ID, index, item)[0] == "FAIL"
    credential["endDateTime"] = NOW
    assert evaluate(sw.CREDENTIAL_ID, index, item)[0] == "PASS"
    credential.update(startDateTime="2026-11-01T00:00:00Z", endDateTime="2027-01-01T00:00:00Z")
    assert evaluate(sw.CREDENTIAL_ID, index, item)[0] == "PASS"
    item["passwordCredentials"] = []
    assert evaluate(sw.CREDENTIAL_ID, index, item)[0] == "PASS"
    index["context"]["metadata"]["parameters"] = {"maxCredentialAgeDays": False}
    assert evaluate(sw.CREDENTIAL_ID, index, item)[0] == "UNKNOWN"


def test_credential_certificates_and_graph_authority():
    index, item = credential_fixture()
    item["keyCredentials"] = [{"keyId": "certificate", "startDateTime": "2026-01-01T00:00:00Z", "endDateTime": "2027-01-01T00:00:00Z"}]
    assert evaluate(sw.CREDENTIAL_ID, index, item)[0] == "FAIL"
    index["collections"]["service_principal"][0]["_provenance"]["customer_context_id"] = "foreign"
    assert evaluate(sw.CREDENTIAL_ID, index, item)[0] == "UNKNOWN"


@pytest.mark.parametrize("change", ["type", "protocol", "policy", "cluster", "projection"])
def test_service_unresolved_fact_unknown(change):
    index, _ = port_fixture()
    service = row(index, "service")
    if change == "type":
        service["spec"]["type"] = "unrecognized"
    elif change == "protocol":
        service["spec"]["ports"][0]["protocol"] = "QUIC"
    elif change == "policy":
        index["context"]["metadata"]["sw22"]["approved_service_ports"]["services"] = []
    elif change == "cluster":
        service["_provenance"]["cluster_id"] = "foreign"
    elif change == "projection":
        service["_provenance"]["representation"] = "partial"
    assert evaluate(sw.PORT_ID, index)[0] == "UNKNOWN"


def test_service_protocol_pair_and_targetport_are_distinct():
    index, _ = port_fixture()
    service = row(index, "service")
    service["spec"]["ports"][0]["targetPort"] = 1
    assert evaluate(sw.PORT_ID, index)[0] == "PASS"
    service["spec"]["ports"][0]["protocol"] = "UDP"
    assert evaluate(sw.PORT_ID, index)[0] == "FAIL"
    service["spec"] = {"type": "ExternalName", "externalName": "example.com"}
    assert evaluate(sw.PORT_ID, index)[0] == "NOT_APPLICABLE"


@pytest.mark.parametrize("ref", [None, {}, {"keyName": ""}, {"keyName": "cmk", "keyVault": None}, {"keyName": "cmk", "keyVault": {"id": ""}}])
def test_ise_complete_unusable_reference_fails(ref):
    index, _ = ise_fixture()
    row(index, "integration_service_environment")["properties"]["encryptionConfiguration"]["encryptionKeyReference"] = ref
    assert evaluate(sw.ISE_ID, index)[0] == "FAIL"


def test_ise_approval_version_missing_policy_and_api_generation_unknown():
    index, _ = ise_fixture()
    ise = row(index, "integration_service_environment")
    ref = ise["properties"]["encryptionConfiguration"]["encryptionKeyReference"]
    ref["keyVersion"] = "other"
    assert evaluate(sw.ISE_ID, index)[0] == "UNKNOWN"
    ref["keyVersion"] = "version1"
    del index["context"]["metadata"]["sw22"]
    assert evaluate(sw.ISE_ID, index)[0] == "UNKNOWN"
    index, _ = ise_fixture()
    row(index, "integration_service_environment")["_provenance"]["api_version"] = "future"
    assert evaluate(sw.ISE_ID, index)[0] == "UNKNOWN"


@pytest.mark.parametrize("problem", ["friendly_name", "class_gap", "unknown_outcome", "future", "wrong_job", "too_long_window"])
def test_restore_unresolved_identity_scope_outcome_unknown(problem):
    index, _ = restore_fixture()
    record = row(index, "restore_test_record")
    if problem == "friendly_name":
        record["identity_basis"] = "entityFriendlyName"
    elif problem == "class_gap":
        index["context"]["metadata"]["sw22"]["restore_tests"]["data_classes"].pop()
    elif problem == "unknown_outcome":
        record["validation_result"] = "not-measured"
    elif problem == "future":
        record["validated_at"] = "2027-01-01T00:00:00Z"
    elif problem == "wrong_job":
        record["job_id"] += "foreign"
    elif problem == "too_long_window":
        index["context"]["metadata"]["sw22"]["restore_tests"]["maxRestoreTestAgeDays"] = 366
    assert evaluate(sw.RESTORE_ID, index)[0] == "UNKNOWN"


def test_restore_complete_job_without_validation_cannot_pass_and_old_job_fails():
    index, _ = restore_fixture()
    index["restore_test_record"] = []
    index["collections"]["restore_test_record"][0].update(status="empty", items=[])
    assert evaluate(sw.RESTORE_ID, index)[0] == "FAIL"
    index, _ = restore_fixture()
    row(index, "backup_job")["properties"]["endTime"] = "2025-10-11T00:00:00Z"
    row(index, "backup_job")["properties"]["startTime"] = "2025-10-10T23:00:00Z"
    from tests.backup_c5_fixture_data import refresh_restore_digests
    refresh_restore_digests(index)
    assert evaluate(sw.RESTORE_ID, index)[0] == "FAIL"


@pytest.mark.parametrize("problem", ["customer", "inheritance_gap", "authority", "stale", "stage_gap"])
def test_provider_lifecycle_customer_or_incomplete_evidence_unknown(problem):
    index, _ = source_fixture()
    if problem == "customer":
        index["context"]["metadata"]["sw22"]["provider_source_lifecycle"]["provider_owned"] = False
    elif problem == "inheritance_gap":
        row(index, "source_control_evidence")["outcome"] = "declared-only"
    elif problem == "authority":
        row(index, "source_control_evidence")["source_authority"] = "customer"
    elif problem == "stale":
        row(index, "source_control_evidence")["observed_at"] = "2025-01-01T00:00:00Z"
    elif problem == "stage_gap":
        index["source_control_evidence"].pop()
        index["collections"]["source_control_evidence"][0]["items"].pop()
    assert evaluate(sw.SOURCE_ID, index)[0] == "UNKNOWN"


@pytest.mark.parametrize("problem", ["missing_binding", "stale_binding", "waf_gap", "state_default", "foreign_waf", "wrong_public_ip", "unresolved_plan"])
def test_edge_unresolved_mapping_or_waf_unknown(problem):
    index, _ = network_fixture()
    binding = index["public_edge_binding"][1]["data"]
    if problem == "missing_binding":
        index["public_edge_binding"].pop()
        index["collections"]["public_edge_binding"][0]["items"].pop()
    elif problem == "stale_binding":
        binding["resource_etag"] = "v2"
    elif problem == "waf_gap":
        binding["_coverage"]["effective_waf"]["status"] = "partial"
    elif problem == "state_default":
        del row(index, "waf_policy")["properties"]["policySettings"]["state"]
    elif problem == "foreign_waf":
        binding["effective_waf_policy_ids"][0] = binding["effective_waf_policy_ids"][0].replace("/subscriptions/sub/", "/subscriptions/foreign/")
    elif problem == "wrong_public_ip":
        row(index, "application_gateway")["properties"]["frontendIPConfigurations"][0]["properties"]["publicIPAddress"]["id"] += "other"
    elif problem == "unresolved_plan":
        row(index, "public_ip")["properties"]["ddosSettings"]["ddosProtectionPlan"] = {"id": PREFIX + "Microsoft.Network/ddosProtectionPlans/plan"}
    assert evaluate(sw.NETWORK_ID, index)[0] == "UNKNOWN"


@pytest.mark.parametrize("state,mode", [("Disabled", "Prevention"), ("Enabled", "Detection")])
def test_edge_explicit_bad_waf_fails(state, mode):
    index, _ = network_fixture()
    row(index, "waf_policy")["properties"]["policySettings"].update(state=state, mode=mode)
    assert evaluate(sw.NETWORK_ID, index)[0] == "FAIL"


def test_edge_resolved_missing_waf_fails():
    index, _ = network_fixture()
    index["public_edge_binding"][1]["data"]["effective_waf_policy_ids"] = [None]
    assert evaluate(sw.NETWORK_ID, index)[0] == "FAIL"


def test_network_inherited_vnet_exact_join_and_disabled_ip_override():
    index, _ = network_fixture()
    ip = row(index, "public_ip")
    binding = row(index, "public_edge_binding")
    vnet = {"id": PREFIX + "Microsoft.Network/virtualNetworks/vnet", "properties": {
        "enableDdosProtection": True, "ddosProtectionPlan": {"id": PREFIX + "Microsoft.Network/ddosProtectionPlans/plan"}}}
    plan = {"id": vnet["properties"]["ddosProtectionPlan"]["id"], "properties": {"provisioningState": "Succeeded"}}
    for kind, native in (("vnet", vnet), ("ddos_plan", plan)):
        added = facts({kind: [native]})
        index[kind] = added[kind]
        index["collections"][kind] = added["collections"][kind]
    binding.update(inherited_vnet_id=vnet["id"], vnet_association_evidence_ref="exact-ip-subnet-binding")
    binding["_coverage"]["inherited_vnet"] = {"status": "collected", "parent_id": ip["id"]}
    ip["properties"]["ddosSettings"]["protectionMode"] = "VirtualNetworkInherited"
    assert evaluate(sw.NETWORK_ID, index)[0] == "PASS"
    vnet["properties"]["enableDdosProtection"] = False
    assert evaluate(sw.NETWORK_ID, index)[0] == "FAIL"
    vnet["properties"]["enableDdosProtection"] = True
    ip["properties"]["ddosSettings"]["protectionMode"] = "Disabled"
    assert evaluate(sw.NETWORK_ID, index)[0] == "FAIL"


def frontdoor_fixture():
    door = {"id": PREFIX + "Microsoft.Network/frontDoors/fd", "etag": "v1",
            "_provenance": full("Microsoft.Network/frontDoors:GET", "2021-06-01")}
    frontend = door["id"] + "/frontendEndpoints/default"
    door["properties"] = {"frontendEndpoints": [{"id": frontend, "properties": {"hostName": "fd.azurefd.net"}}]}
    waf = {"id": PREFIX + "Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/waf",
           "_provenance": full("Azure.WAF:GET", "2022-05-01"), "properties": {
               "policySettings": {"mode": "Prevention"}, "customRules": {"rules": [{}]},
               "provisioningState": "Succeeded", "resourceState": "Enabled"}}
    binding = edge_binding(door, "frontdoor", [frontend], effective_waf_policy_ids=[waf["id"]],
                           waf_linkage_evidence_ref="classic-endpoint-policy", ddos={"resource_id": door["id"],
                           "state": "Protected", "mapping_ref": "documented-product-ddos-mapping", "evidence_ref": "measured-product-protection"})
    for field in ("ddos", "effective_waf"):
        binding["_coverage"][field] = {"status": "collected", "parent_id": door["id"]}
    kinds = {kind: [] for kind in sw._EDGE_TYPES}
    kinds.update(frontdoor=[door], public_edge_binding=[binding], waf_policy=[waf])
    return facts(kinds)


def test_frontdoor_documented_policy_and_rule_defaults_and_product_ddos():
    index = frontdoor_fixture()
    assert evaluate(sw.NETWORK_ID, index)[0] == "PASS"
    row(index, "public_edge_binding")["ddos"]["state"] = "Unsupported"
    assert evaluate(sw.NETWORK_ID, index)[0] == "UNKNOWN"
    row(index, "public_edge_binding")["ddos"]["state"] = "Unprotected"
    assert evaluate(sw.NETWORK_ID, index)[0] == "FAIL"
    row(index, "waf_policy")["_provenance"]["api_version"] = "unknown"
    assert evaluate(sw.NETWORK_ID, index)[0] == "UNKNOWN"


@pytest.mark.parametrize("cid", [cid for cid in sw.IDS if sw.LOCAL_CHECKS[cid].target == "scope"])
def test_scope_target_foreign_authority_unknown(cid):
    index, _ = FIXTURES[cid]()
    foreign = {**index["context"], "scope": "/subscriptions/foreign"}
    assert evaluate(cid, index, foreign)[0] == "UNKNOWN"


def test_credential_memoized_inventory_once_per_index(monkeypatch):
    from peaso.checks.facts import MemoIndex
    index, first = credential_fixture()
    second = copy.deepcopy(first)
    second["id"] = "abcdefab-1234-1234-1234-123456789abc"
    index["collections"]["service_principal"][0]["items"].append(second)
    index["service_principal"].append({"provider": "azure", "type": "service_principal",
                                       "scope": index["context"]["scope"], "data": second})
    index = MemoIndex(index)
    original, calls = sw.complete_items, []
    def counted(index, kind):
        calls.append(kind)
        return original(index, kind)
    monkeypatch.setattr(sw, "complete_items", counted)
    assert evaluate(sw.CREDENTIAL_ID, index, first)[0] == "PASS"
    assert evaluate(sw.CREDENTIAL_ID, index, second)[0] == "PASS"
    assert calls == ["service_principal"]


def test_credential_unavailable_parameter_must_not_default():
    index, item = credential_fixture()
    index["context"]["metadata"]["_coverage"] = {"parameters": {"status": "denied"}}
    assert evaluate(sw.CREDENTIAL_ID, index, item)[0] == "UNKNOWN"


def test_frontdoor_frontend_binding_cannot_hide_native_public_endpoint():
    index = frontdoor_fixture()
    binding = row(index, "public_edge_binding")
    binding.update(public=False, public_frontend_ids=[])
    binding["_coverage"]["frontends"]["status"] = "empty"
    assert evaluate(sw.NETWORK_ID, index)[0] == "UNKNOWN"


def test_modern_frontdoor_native_endpoint_and_policy_bindings():
    index = frontdoor_fixture()
    classic = row(index, "frontdoor")
    profile_id = PREFIX + "Microsoft.Cdn/profiles/fd"
    endpoint_id = profile_id + "/afdEndpoints/default"
    profile = {"id": profile_id, "etag": "v1", "sku": {"name": "Premium_AzureFrontDoor"},
               "_provenance": full("Microsoft.Cdn/profiles:GET", "2024-02-01"),
               "endpoints": [{"id": endpoint_id, "properties": {"hostName": "fd.azurefd.net"}}],
               "_coverage": {"endpoints": {"status": "collected", "parent_id": profile_id}}}
    index["frontdoor"] = []
    index["collections"]["frontdoor"][0].update(status="empty", items=[])
    added = facts({"frontdoor_profile": [profile]})
    index["frontdoor_profile"] = added["frontdoor_profile"]
    index["collections"]["frontdoor_profile"] = added["collections"]["frontdoor_profile"]
    binding = row(index, "public_edge_binding")
    binding.update(resource_id=profile_id, resource_kind="frontdoor_profile", public_frontend_ids=[endpoint_id])
    for coverage in binding["_coverage"].values():
        coverage["parent_id"] = profile_id
    binding["ddos"]["resource_id"] = profile_id
    assert evaluate(sw.NETWORK_ID, index)[0] == "PASS"
    profile["_coverage"]["endpoints"]["status"] = "partial"
    assert evaluate(sw.NETWORK_ID, index)[0] == "UNKNOWN"


def test_network_complete_private_frontend_is_not_applicable():
    gateway = {"id": PREFIX + "Microsoft.Network/applicationGateways/private", "etag": "v1",
               "_provenance": full("Microsoft.Network/applicationGateways:GET"),
               "properties": {"frontendIPConfigurations": [{"id": PREFIX +
                   "Microsoft.Network/applicationGateways/private/frontendIPConfigurations/private",
                   "properties": {"privateIPAddress": "10.0.0.1"}}]}}
    kinds = {kind: [] for kind in sw._EDGE_TYPES}
    kinds.update(application_gateway=[gateway], public_edge_binding=[edge_binding(gateway, "application_gateway", [])])
    assert evaluate(sw.NETWORK_ID, facts(kinds))[0] == "NOT_APPLICABLE"


def test_ise_malformed_reference_and_approval_inventory_unknown():
    index, _ = ise_fixture()
    ref = row(index, "integration_service_environment")["properties"]["encryptionConfiguration"]["encryptionKeyReference"]
    ref["keyVault"] = "bad"
    assert evaluate(sw.ISE_ID, index)[0] == "UNKNOWN"
    index, _ = ise_fixture()
    keys = index["context"]["metadata"]["sw22"]["approved_ise_keys"]["keys"]
    keys.append({"vault_id": keys[0]["vault_id"], "key_name": "bad name", "key_version": None})
    assert evaluate(sw.ISE_ID, index)[0] == "UNKNOWN"


def test_duplicate_native_frontend_cannot_be_collapsed_into_safe_binding():
    index, _ = network_fixture()
    frontends = row(index, "application_gateway")["properties"]["frontendIPConfigurations"]
    frontends.append(copy.deepcopy(frontends[0]))
    assert evaluate(sw.NETWORK_ID, index)[0] == "UNKNOWN"
