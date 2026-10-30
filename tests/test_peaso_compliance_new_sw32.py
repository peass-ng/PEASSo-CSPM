"""Isolated source-bound tests for sw32 signed Azure checks."""
from __future__ import annotations

import copy

import pytest

from peaso.checks import CHECKS, evaluate_check
from peaso.checks import compliance_new_sw32 as sw

SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
BASE = SCOPE + "/resourceGroups/rg/providers/"


@pytest.fixture(scope="module", autouse=True)
def clean_registry():
    yield
    CHECKS[:] = [check for check in CHECKS if check.id not in sw.IDS]


def row_id(provider, typ, name="one"):
    return BASE + provider + "/" + typ + "/" + name


def child(parent, path, name="one", **fields):
    return {"id": parent["id"] + "/" + path + "/" + name, **fields}


def embedded(parent, field, path, children):
    parent[field] = children
    parent.setdefault("_coverage", {})[field] = {"status": "collected" if children else "empty"}
    return parent


def snapshot(rows, policy=None):
    policy = {"status": "collected", "scope": SCOPE, **(policy or {})}
    return {"context": {"provider": "azure", "scope": SCOPE,
                        "created_at": "2026-10-12T00:00:00Z",
                        "metadata": {"compliance_policy": {"sw32": policy}}},
            "collections": {kind: [{"type": kind, "scope": SCOPE,
                                  "status": "collected" if values else "empty", "items": values}]
                            for kind, values in rows.items()},
            **{kind: [{"type": kind, "scope": SCOPE, "data": value} for value in values]
               for kind, values in rows.items()}}


def case(check_id):
    if check_id == "azure.cis.mysql_single_audit_log_events_connection":
        server = {"id": row_id("Microsoft.DBforMySQL", "servers")}
        embedded(server, "configurations", "configurations", [
            child(server, "configurations", "audit_log_enabled", properties={"value": "ON"}),
            child(server, "configurations", "audit_log_events", properties={"value": "CONNECTION,TABLE_ACCESS"})])
        for config in server["configurations"]:
            config["name"] = config["id"].rsplit("/", 1)[-1]
        good = snapshot({"mysql_single_server": [server]})
        bad = copy.deepcopy(good)
        bad["mysql_single_server"][0]["data"]["configurations"][0]["properties"]["value"] = "OFF"
        return good, bad, "PASS", "FAIL"
    if check_id == "azure.gap.container_registry_vulnerabilities_remediated":
        registry = {"id": row_id("Microsoft.ContainerRegistry", "registries"),
                    "vulnerabilityAssessment": {"name": "stable-key", "properties": {"status": {"code": "Healthy"}}}}
        embedded(registry, "imageManifests", "imageManifests", [])
        embedded(registry, "vulnerabilitySubAssessments", "vulnerabilitySubAssessments", [])
        policy = {"registry_vulnerability_assessment_key": "stable-key", "max_registry_scan_age_seconds": 86400}
        good = snapshot({"container_registry": [registry]}, policy)
        bad = copy.deepcopy(good)
        item = bad["container_registry"][0]["data"]
        digest = "sha256:" + "a" * 64
        embedded(item, "imageManifests", "imageManifests", [child(item, "imageManifests", repositoryName="r", imageDigest=digest)])
        embedded(item, "vulnerabilitySubAssessments", "vulnerabilitySubAssessments", [child(item, "vulnerabilitySubAssessments", assessmentKey="stable-key", properties={"resourceDetails": {"id": item["id"]}, "additionalData": {"repositoryName": "r", "imageDigest": digest}, "timeGenerated": "2026-10-11T00:00:00Z", "status": {"code": "Unhealthy"}})])
        return good, bad, "PASS", "FAIL"
    if check_id == "azure.other.acr_untagged_retention":
        reg = {"id": row_id("Microsoft.ContainerRegistry", "registries"), "sku": {"name": "Premium"},
               "properties": {"policies": {"retentionPolicy": {"status": "enabled", "days": 7}}}}
        good = snapshot({"container_registry": [reg]}, {"acr_max_untagged_days": 30})
        bad = copy.deepcopy(good)
        bad["container_registry"][0]["data"]["properties"]["policies"]["retentionPolicy"]["status"] = "disabled"
        return good, bad, "UNKNOWN", "FAIL"
    if check_id == "azure_devops_project_1_2_8_6_fb0e5a8":
        project = {"id": "project-guid", "_provenance": {"api_version": "7.1", "includeHidden": True, "includeAllUrls": True}}
        embedded(project, "repositories", "repositories", [{"id": "repo-guid", "projectId": "project-guid", "remoteUrl": "https://dev.azure.com/org/project/_git/repo", "validRemoteUrls": ["ssh://dev.azure.com/org/project/repo"]}])
        good = snapshot({"devops_project": [project]})
        bad = copy.deepcopy(good)
        bad["devops_project"][0]["data"]["repositories"][0]["validRemoteUrls"].append("https://user@dev.azure.com/org/project/repo")
        return good, bad, "PASS", "FAIL"
    if check_id == "azure_devops_project_6_5_5_2_2908a87":
        project = {"id": "project-guid"}
        embedded(project, "pipelines", "pipelines", [{"id": 5, "projectId": "project-guid", "resolved_revision": "abcdef", "templates_complete": True, "dynamic_expressions_resolved": True, "deployment_stages": [{"deployment_job_count": 1}, {"deployment_job_count": 2}]}])
        good = snapshot({"devops_project": [project]}, {"later_stage_deployment_limit": 2})
        bad = copy.deepcopy(good)
        bad["devops_project"][0]["data"]["pipelines"][0]["deployment_stages"][0]["deployment_job_count"] = 2
        return good, bad, "PASS", "FAIL"
    if check_id in ("azure_cosmos_account_10_2_1_1_13_5c115b0", "azure_cosmos_account_10_2_1_1_23_e04a63d"):
        mongo = check_id.endswith("13_5c115b0")
        account = {"id": row_id("Microsoft.DocumentDB", "databaseAccounts"), "properties": {"capabilities": [{"name": "EnableMongo"}]},
                   "supported_log_categories": ["MongoRequests", "DataPlaneRequests"]}
        logs = [{"enabled": True, "category": "MongoRequests" if mongo else "DataPlaneRequests"}]
        embedded(account, "diagnosticSettings", "providers/Microsoft.Insights/diagnosticSettings", [child(account, "providers/Microsoft.Insights/diagnosticSettings", properties={"logs": logs, "workspaceId": row_id("Microsoft.OperationalInsights", "workspaces")})])
        rows = {"cosmos_account": [account]}
        if mongo:
            rows["mongo_cluster"] = []
        good = snapshot(rows, {"approved_cosmos_workspaces": [row_id("Microsoft.OperationalInsights", "workspaces")]})
        bad = copy.deepcopy(good)
        embedded(bad["cosmos_account"][0]["data"], "diagnosticSettings", "providers/Microsoft.Insights/diagnosticSettings", [])
        return good, bad, "PASS", "FAIL"
    if check_id in ("azure_role_assignment_7_2_1_14_6743a56", "azure_role_assignment_aks_cluster_rbac_enabled_675305a"):
        role_id = row_id("Microsoft.Authorization", "roleDefinitions")
        role = {"id": role_id, "properties": {"type": "CustomRole", "roleName": "Custom", "assignableScopes": [SCOPE], "permissions": [{"actions": ["Microsoft.Compute/read"], "notActions": []}]}}
        assignment = {"id": row_id("Microsoft.Authorization", "roleAssignments"), "properties": {"roleDefinitionId": role_id, "principalId": "principal", "scope": SCOPE}}
        policy = {"rbac_relevant_scopes_complete": True}
        if check_id.endswith("675305a"):
            policy["required_role_assignments"] = [{"principalId": "principal", "roleDefinitionId": role_id, "scope": SCOPE}]
        good = snapshot({"role_definition": [role], "role_assignment": [assignment]}, policy)
        bad = copy.deepcopy(good)
        if check_id.endswith("675305a"):
            bad["role_assignment"] = []
            bad["collections"]["role_assignment"][0].update(status="empty", items=[])
        else:
            bad["role_definition"][0]["data"]["properties"]["assignableScopes"] = ["/"]
            bad["role_definition"][0]["data"]["properties"]["permissions"][0]["actions"] = ["*"]
        return good, bad, "PASS", "FAIL"
    if check_id == "azure_c5_ops_20_01b":
        ws = {"id": row_id("Microsoft.OperationalInsights", "workspaces")}
        incident = child(ws, "providers/Microsoft.SecurityInsights/incidents", properties={"status": "Closed", "classification": "TruePositive", "severity": "High", "lastModifiedTimeUtc": "2026-10-11T00:00:00Z"}, classification_reason_required=False, process_evidence={"identified": "verified", "recorded": "verified", "prioritized": "verified", "instructions_followed": "verified"})
        embedded(ws, "incidents", "providers/Microsoft.SecurityInsights/incidents", [incident])
        policy = {"incident_review": {"start": "2026-10-01T00:00:00Z", "end": "2026-10-12T00:00:00Z", "approved": True, "allowed_classifications": ["TruePositive"], "allowed_priorities": ["High"]}}
        good = snapshot({"sentinel_workspace": [ws]}, policy)
        bad = copy.deepcopy(good)
        bad["sentinel_workspace"][0]["data"]["incidents"][0]["properties"]["classification"] = "FalsePositive"
        return good, bad, "PASS", "FAIL"
    if check_id == "azure_c5_ops_25_02b":
        assessment = {"id": row_id("Microsoft.Security", "assessments"), "name": "key", "properties": {"status": {"code": "Unhealthy"}}, "severity_criteria_evidence": {"criteria_version": "v1", "assigned_severity_matches_criteria": True}}
        metadata = {"id": row_id("Microsoft.Security", "assessmentMetadata"), "name": "key", "properties": {"severity": "High"}}
        good = snapshot({"security_assessment": [assessment], "assessment_metadata": [metadata]}, {"vulnerability_severity_criteria": {"approved": True, "finding_coverage_complete": True, "version": "v1"}})
        bad = copy.deepcopy(good)
        bad["security_assessment"][0]["data"]["severity_criteria_evidence"]["assigned_severity_matches_criteria"] = False
        return good, bad, "PASS", "FAIL"
    if check_id == "azure.cis.private_endpoint_should_mariadb_servers":
        server = {"id": row_id("Microsoft.DBforMariaDB", "servers"), "properties": {"publicNetworkAccess": "Disabled"}}
        embedded(server, "privateEndpointConnections", "privateEndpointConnections", [child(server, "privateEndpointConnections", properties={"privateLinkServiceConnectionState": {"status": "Approved"}, "privateLinkServiceId": server["id"], "privateEndpoint": {"id": row_id("Microsoft.Network", "privateEndpoints")}})])
        good = snapshot({"mariadb_server": [server]})
        bad = copy.deepcopy(good)
        embedded(bad["mariadb_server"][0]["data"], "privateEndpointConnections", "privateEndpointConnections", [])
        return good, bad, "PASS", "FAIL"
    if check_id == "azure.other.vault_key_approved_algorithm":
        key = {"id": row_id("Microsoft.KeyVault", "vaults") + "/keys/key"}
        version = child(key, "versions", attributes={"enabled": True}, encryption_use=True,
                        key={"kty": "EC", "crv": "P-256"}, algorithm_policy_approved=True,
                        import_provenance="generated")
        embedded(key, "versions", "versions", [version])
        policy = {"approved_key_algorithms": {"industry_standard_confirmed": True, "minimum_rsa_bits": 2048, "approved_ec_curves": ["P-256"]}}
        good = snapshot({"vault_key": [key]}, policy)
        bad = copy.deepcopy(good)
        bad["vault_key"][0]["data"]["versions"][0]["key"]["crv"] = "P-192"
        return good, bad, "PASS", "FAIL"
    if check_id == "azure.other.monitor_dashboard_access":
        dash = {"id": row_id("Microsoft.Portal", "dashboards"), "effectiveAccess": {"viewers": ["principal"], "public_share_enabled": False, "ancestor_scopes_complete": True, "role_definitions_complete": True, "conditions_resolved": True, "transitive_groups_complete": True, "alternate_sharing_complete": True}}
        policy = {"sensitive_dashboard_ids": [dash["id"]], "approved_dashboard_viewers": ["principal"]}
        good = snapshot({"dashboard": [dash]}, policy)
        bad = copy.deepcopy(good)
        bad["dashboard"][0]["data"]["effectiveAccess"]["viewers"].append("outsider")
        return good, bad, "PASS", "FAIL"
    if check_id == "azure.other.vnet_peering_allowlist":
        vnet = {"id": row_id("Microsoft.Network", "virtualNetworks")}
        approved_peer = row_id("Microsoft.Network", "virtualNetworks", "approved")
        embedded(vnet, "virtualNetworkPeerings", "virtualNetworkPeerings", [child(vnet, "virtualNetworkPeerings", properties={"peeringState": "Connected", "remoteVirtualNetwork": {"id": approved_peer}})])
        policy = {"approved_peer_ids": [approved_peer], "unapproved_peering_prevention": {"controlled_unapproved_request_succeeded": False, "enforced_deny_policy": True, "controlled_unapproved_request_rejected": False}}
        good = snapshot({"vnet": [vnet]}, policy)
        bad = copy.deepcopy(good)
        bad["vnet"][0]["data"]["virtualNetworkPeerings"][0]["properties"]["remoteVirtualNetwork"]["id"] = row_id("Microsoft.Network", "virtualNetworks", "unapproved")
        return good, bad, "PASS", "FAIL"
    raise AssertionError(check_id)


@pytest.mark.parametrize("check_id", sw.IDS)
def test_signed_cases(check_id):
    good, bad, good_status, bad_status = case(check_id)
    subject = good["context"]
    assert evaluate_check(check_id, subject, good)[0] == good_status
    assert evaluate_check(check_id, bad["context"], bad)[0] == bad_status
    missing = copy.deepcopy(good)
    first = sw.SPECS[check_id]["dependencies"][0]
    missing["collections"].pop(first)
    missing.pop(first)
    assert evaluate_check(check_id, missing["context"], missing)[0] == "UNKNOWN"
    incomplete = copy.deepcopy(good)
    first = sw.SPECS[check_id]["dependencies"][0]
    incomplete["collections"][first][0]["status"] = "partial"
    assert evaluate_check(check_id, incomplete["context"], incomplete)[0] == "UNKNOWN"
    malformed = copy.deepcopy(good)
    malformed[first][0]["type"] = "wrong_kind"
    assert evaluate_check(check_id, malformed["context"], malformed)[0] == "UNKNOWN"
    malformed = copy.deepcopy(good)
    malformed["context"]["scope"] = "/subscriptions/foreign"
    assert evaluate_check(check_id, malformed["context"], malformed)[0] == "UNKNOWN"


def test_not_applicable_and_partial_boundaries():
    for check_id, kind in (("azure.cis.mysql_single_audit_log_events_connection", "mysql_single_server"),
                           ("azure_devops_project_1_2_8_6_fb0e5a8", "devops_project"),
                           ("azure.cis.private_endpoint_should_mariadb_servers", "mariadb_server")):
        facts = snapshot({kind: []})
        assert evaluate_check(check_id, facts["context"], facts)[0] == "NOT_APPLICABLE"
    check_id = "azure.other.vnet_peering_allowlist"
    facts, _, _, _ = case(check_id)
    del facts["context"]["metadata"]["compliance_policy"]["sw32"]["unapproved_peering_prevention"]
    assert evaluate_check(check_id, facts["context"], facts)[0] == "UNKNOWN"
    check_id = "azure_devops_project_1_2_8_6_fb0e5a8"
    facts, _, _, _ = case(check_id)
    del facts["devops_project"][0]["data"]["repositories"][0]["validRemoteUrls"]
    assert evaluate_check(check_id, facts["context"], facts)[0] == "UNKNOWN"


def test_cross_source_evidence_gates():
    check_id = "azure.other.acr_untagged_retention"
    safe, bad, _, _ = case(check_id)
    assert evaluate_check(check_id, safe["context"], safe)[0] == "UNKNOWN"
    del bad["context"]["metadata"]["compliance_policy"]["sw32"]["acr_max_untagged_days"]
    assert evaluate_check(check_id, bad["context"], bad)[0] == "FAIL"

    check_id = "azure.other.vault_key_approved_algorithm"
    safe, _, _, _ = case(check_id)
    embedded(safe["vault_key"][0]["data"], "versions", "versions", [])
    assert evaluate_check(check_id, safe["context"], safe)[0] == "UNKNOWN"

    check_id = "azure_c5_ops_20_01b"
    safe, _, _, _ = case(check_id)
    del safe["sentinel_workspace"][0]["data"]["incidents"][0]["process_evidence"]
    assert evaluate_check(check_id, safe["context"], safe)[0] == "UNKNOWN"

    check_id = "azure_cosmos_account_10_2_1_1_23_e04a63d"
    safe, _, _, _ = case(check_id)
    del safe["cosmos_account"][0]["data"]["supported_log_categories"]
    assert evaluate_check(check_id, safe["context"], safe)[0] == "UNKNOWN"

    check_id = "azure.other.monitor_dashboard_access"
    safe, _, _, _ = case(check_id)
    safe["dashboard"][0]["data"]["effectiveAccess"]["transitive_groups_complete"] = False
    assert evaluate_check(check_id, safe["context"], safe)[0] == "UNKNOWN"


