"""Isolated contract tests for the sw26 Azure proposal evaluators."""
from __future__ import annotations

import copy

import pytest

from peaso.checks import CHECKS, evaluate_check
from peaso.checks import compliance_new_sw26 as sw26

SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
SITE = SCOPE + "/resourceGroups/rg/providers/Microsoft.Web/sites/app"
CONFIG = SITE + "/config/web"
POD = SCOPE + "/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/aks/pods/default/p"
ACI = SCOPE + "/resourceGroups/rg/providers/Microsoft.ContainerInstance/containerGroups/g"
CONTAINER = SCOPE + "/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a/blobServices/default/containers/c"
PROFILE = SCOPE + "/resourceGroups/rg/providers/Microsoft.Cdn/profiles/p"
ROLE = SCOPE + "/providers/Microsoft.Authorization/roleDefinitions/r"
VAULT = SCOPE + "/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/v"
SETTING = SCOPE + "/resourceGroups/rg/providers/Microsoft.Web/sites/app/providers/Microsoft.Insights/diagnosticSettings/d"
NOW = "2026-10-12T00:00:00+00:00"


@pytest.fixture(scope="module", autouse=True)
def restore_registry_after_module():
    yield
    CHECKS[:] = [check for check in CHECKS if check.id not in sw26.SPECS]


def scoped(inventories, cid=None, policy=None, *, status="collected", scope=SCOPE):
    collections = {}
    wrapped = {}
    for kind, rows in inventories.items():
        collections[kind] = [{"type": kind, "scope": scope,
                              "status": status if rows else "empty", "items": rows}]
        wrapped[kind] = [{"type": kind, "scope": scope, "data": row} for row in rows]
    context = {"provider": "azure", "scope": scope, "created_at": NOW,
               "metadata": {"compliance_policy": {"sw26": {"scope": scope, "status": "collected",
                   **({cid: policy} if cid is not None and policy is not None else {})}}}}
    return {"context": context, "collections": collections, **wrapped}


def run(cid, inventories, policy=None, **kw):
    index = scoped(inventories, cid, policy, **kw)
    return evaluate_check(cid, {"scope": index["context"]["scope"]}, index)[0]



def enumeration_external_run(cid, inventories, policy, *, status="collected"):
    """Synthetic independently sourced event and persisted-sink observations."""
    rows = copy.deepcopy(inventories)
    index = scoped(rows, cid, copy.deepcopy(policy), status=status)
    metadata = index["context"]["metadata"]
    metadata.update(credential_context_id="capture-1", customer_context_id="customer-1")
    owned = metadata["compliance_policy"]["sw26"][cid]
    sink = SCOPE + "/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/logs"
    owned.update(eventSourceId="event-observer", logSourceId="sink-reader",
                 approvedSinkIds=[sink], observedSinkId=sink)
    common = {"scope": SCOPE, "readOnly": True, "observer": "external-observer",
              "authorizationDocumentId": "external-evidence-doc",
              "credential_context_id": "capture-1", "customer_context_id": "customer-1",
              "observedAt": "2026-10-11T12:00:00Z"}
    event_env = index["collections"]["enumeration_event"][0]
    event_env["_provenance"] = {**common, "sourceOperation": "external_independent_event_inventory",
        "sourceId": "event-observer", "coverage": {"status": "complete",
        "windowStart": owned["window_start"], "windowEnd": owned["window_end"]}}
    log_env = index["collections"]["enumeration_log_record"][0]
    log_env["_provenance"] = {**common, "sourceOperation": "external_persisted_sink_read",
        "sourceId": "sink-reader", "sinkId": sink, "coverage": {"status": "complete",
        "windowStart": owned["window_start"], "windowEnd": "2026-10-11T00:00:00Z"}}
    for row in log_env["items"]:
        row.update(sinkId=sink, persistedAt="2026-10-05T00:01:00Z")
    index["enumeration_log_record"] = [{"type": "enumeration_log_record", "scope": SCOPE, "data": row}
                                       for row in log_env["items"]]
    return evaluate_check(cid, {"scope": SCOPE}, index)[0]

def site(kind="app", **properties):
    return {"id": SITE, "kind": kind, "runtimeId": "python3.13", "properties": properties}


def config(tls="1.3"):
    return {"id": CONFIG, "parent_id": SITE, "properties": {"minTlsVersion": tls}}


def tls_policy():
    return {"valid_until": "2026-12-31T00:00:00+00:00", "latest_supported": "1.3",
            "organization_minimum": "1.2"}


@pytest.mark.parametrize("cid", ["azure.gap.appservice_api_app_latest_tls_version", "azure.other.app_latest_tls"])
def test_tls_pass_fail_unknown_and_empty(cid):
    policy = tls_policy()
    if cid == "azure.other.app_latest_tls":
        policy.update(runtime_support_complete=True, scm_in_scope=False,
                      supported_version_source="dated-provider-catalog",
                      supportedTlsByRuntime={"python3.13": "1.3"})
    base = {"app_service": [site()], "app_service_config": [config()]}
    assert run(cid, base, policy) == "PASS"
    assert run(cid, base, policy, status="partial") == "UNKNOWN"
    assert run(cid, {**base, "app_service_config": [config("1.2")]}, policy) == "FAIL"
    assert run(cid, {"app_service": [site()], "app_service_config": []}, policy) == "UNKNOWN"
    assert run(cid, {**base, "app_service_config": [config("future")]}, policy) == "UNKNOWN"
    assert run(cid, base) == "UNKNOWN"
    assert run(cid, {"app_service": [], "app_service_config": []}, policy) == "NOT_APPLICABLE"


def test_federated_auth_pass_fail_unknown_and_empty():
    cid = "azure_c5_pi_01_02ac"
    auth = {"platform": {"enabled": True}, "globalValidation": {"requireAuthentication": True,
        "excludedPaths": []}, "identityProviders": {"azureActiveDirectory": {"enabled": True,
        "registration": {"clientId": "client"}}}}
    row = {**site(), "authSettingsV2": {"properties": auth}}
    policy = {"customer_federated_app_ids": [SITE], "interfaces": {SITE.casefold(): {
        "status": "collected", "protocol": "OIDC", "tested": True, "present": True}}}
    assert run(cid, {"app_service": [row]}, policy) == "PASS"
    assert run(cid, {"app_service": [row]}, policy, status="partial") == "UNKNOWN"
    bad = copy.deepcopy(row)
    bad["authSettingsV2"]["properties"]["globalValidation"]["requireAuthentication"] = False
    assert run(cid, {"app_service": [bad]}, policy) == "FAIL"
    assert run(cid, {"app_service": [site()]}, policy) == "UNKNOWN"
    assert run(cid, {"app_service": [row]}) == "UNKNOWN"
    assert run(cid, {"app_service": []}, {"customer_federated_app_ids": []}) == "NOT_APPLICABLE"


def pod():
    return {"id": POD, "_provenance": {"representation": "full"}, "spec": {"os": {"name": "linux"},
        "hostPID": False, "securityContext": {"effectiveFsGroup": 1000,
            "effectiveSupplementalGroups": [1000], "supplementalGroupsPolicy": "Strict"},
        "containers": [{"name": "c", "effectiveIdentity": {"uid": 1000, "gid": 1000,
            "supplementalGroups": [1000]}, "env": [{"name": "PASSWORD",
                "valueFrom": {"secretKeyRef": {"name": "s", "key": "password"}}}]}],
        "initContainers": [], "ephemeralContainers": []}}


def test_pod_identity_pass_fail_unknown_and_empty():
    cid = "azure.gap.kubernetes_cluster_pods_and_containers_uses_approved_user_and_group_id"
    policy = {"approved_uid_ranges": [{"min": 1000, "max": 2000}],
              "approved_gid_ranges": [{"min": 1000, "max": 2000}]}
    good = pod()
    assert run(cid, {"pod": [good]}, policy) == "PASS"
    assert run(cid, {"pod": [good]}, policy, status="partial") == "UNKNOWN"
    bad = copy.deepcopy(good)
    bad["spec"]["containers"][0]["effectiveIdentity"]["supplementalGroups"] = [999]
    assert run(cid, {"pod": [bad]}, policy) == "FAIL"
    missing = copy.deepcopy(good)
    del missing["spec"]["containers"][0]["effectiveIdentity"]
    assert run(cid, {"pod": [missing]}, policy) == "UNKNOWN"
    assert run(cid, {"pod": [good]}) == "UNKNOWN"
    assert run(cid, {"pod": []}, policy) == "NOT_APPLICABLE"


def test_host_pid_pass_fail_unknown_and_empty():
    cid = "azure_aks_cluster_1_4_5_2_3ac7b3c"
    base = {"pod": [pod()], "container_group": []}
    assert run(cid, base) == "PASS"
    assert run(cid, base, status="partial") == "UNKNOWN"
    bad = pod()
    bad["spec"]["hostPID"] = True
    assert run(cid, {**base, "pod": [bad]}) == "FAIL"
    assert run(cid, {"pod": [pod()], "container_group": [{"id": ACI}]}) == "UNKNOWN"
    malformed = pod()
    malformed["spec"]["hostPID"] = "false"
    assert run(cid, {**base, "pod": [malformed]}) == "UNKNOWN"
    assert run(cid, {"pod": [], "container_group": []}) == "NOT_APPLICABLE"


def test_literal_secret_env_pass_fail_unknown_and_no_matching_keys():
    cid = "azure_aks_cluster_3_5_1_14_247ebcd"
    policy = {"secretKeys": ["PASSWORD"]}
    base = {"pod": [pod()], "container_group": []}
    assert run(cid, base, policy) == "PASS"
    assert run(cid, base, policy, status="partial") == "UNKNOWN"
    bad = pod()
    bad["spec"]["containers"][0]["env"][0] = {"name": "PASSWORD", "value": "dummy"}
    assert run(cid, {**base, "pod": [bad]}, policy) == "FAIL"
    unresolved = pod()
    unresolved["spec"]["containers"][0]["env"][0] = {"name": "PASSWORD", "valueFrom": {"configMapKeyRef": {"name": "x"}}}
    assert run(cid, {**base, "pod": [unresolved]}, policy) == "UNKNOWN"
    assert run(cid, base) == "UNKNOWN"
    assert run(cid, {"pod": [], "container_group": []}, policy) == "PASS"


def access(paths, *, principal="p", container=CONTAINER):
    return {"status": "collected", "principalId": principal, "containerId": container,
            "paths": {name: {"status": "collected", "effective_access": value}
                      for name, value in paths.items()}}


def test_blob_uniform_deny_pass_fail_unknown_and_empty():
    cid = "azure.other.blob_uniform_deny"
    policy = {"protectedContainerIds": [CONTAINER], "deniedPrincipalIds": ["p"]}
    names = ("rbac", "container_acl", "hns_acl", "sas", "account_key", "data_plane")
    clean = {"id": CONTAINER, "effectiveBlobRead": {"p": access(dict.fromkeys(names, False))}}
    assert run(cid, {"storage_container": [clean]}, policy) == "PASS"
    assert run(cid, {"storage_container": [clean]}, policy, status="partial") == "UNKNOWN"
    bad = copy.deepcopy(clean)
    bad["effectiveBlobRead"]["p"]["paths"]["rbac"]["effective_access"] = True
    assert run(cid, {"storage_container": [bad]}, policy) == "FAIL"
    missing = copy.deepcopy(clean)
    del missing["effectiveBlobRead"]["p"]["paths"]["sas"]
    assert run(cid, {"storage_container": [missing]}, policy) == "UNKNOWN"
    assert run(cid, {"storage_container": [clean]}) == "UNKNOWN"
    assert run(cid, {"storage_container": []}, {**policy, "protectedContainerIds": []}) == "NOT_APPLICABLE"


def test_cross_tenant_blob_pass_fail_unknown_and_empty():
    cid = "azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_3f8ed7f"
    policy = {"approvedTenantIds": ["tenant-home"]}
    paths = {name: False for name in ("rbac", "acl", "sas", "account_key", "data_plane")}
    principal = {**access(paths), "homeTenantId": "other"}
    clean = {"id": CONTAINER, "properties": {"publicAccess": "None"},
             "crossTenantAccess": {"status": "collected", "principals": [principal],
                                   "allPrincipalPathsEnumerated": True}}
    assert run(cid, {"storage_container": [clean]}, policy) == "PASS"
    assert run(cid, {"storage_container": [clean]}, policy, status="partial") == "UNKNOWN"
    bad = copy.deepcopy(clean)
    bad["crossTenantAccess"]["principals"][0]["paths"]["sas"]["effective_access"] = True
    assert run(cid, {"storage_container": [bad]}, policy) == "FAIL"
    missing = copy.deepcopy(clean)
    missing["crossTenantAccess"]["allPrincipalPathsEnumerated"] = False
    assert run(cid, {"storage_container": [missing]}, policy) == "UNKNOWN"
    assert run(cid, {"storage_container": [clean]}) == "UNKNOWN"
    assert run(cid, {"storage_container": []}, policy) == "NOT_APPLICABLE"


def test_log_writer_separation_pass_fail_unknown():
    cid = "azure.other.log_writer_separation"
    policy = {"sourceWorkloadPrincipalIds": ["p"]}
    names = ("rbac", "groups", "workspace", "storage_acl", "sas", "shared_key", "alternate")
    entry = {**access(dict.fromkeys(names, False)), "sinkId": "sink"}
    clean = {"id": SETTING, "resolvedSinks": [{"id": "sink", "status": "collected",
                                                 "sourceAccess": {"p": entry}}]}
    assert run(cid, {"diagnostic_setting": [clean]}, policy) == "PASS"
    assert run(cid, {"diagnostic_setting": [clean]}, policy, status="partial") == "UNKNOWN"
    bad = copy.deepcopy(clean)
    bad["resolvedSinks"][0]["sourceAccess"]["p"]["paths"]["groups"]["effective_access"] = True
    assert run(cid, {"diagnostic_setting": [bad]}, policy) == "FAIL"
    missing = copy.deepcopy(clean)
    del missing["resolvedSinks"][0]["sourceAccess"]["p"]["paths"]["shared_key"]
    assert run(cid, {"diagnostic_setting": [missing]}, policy) == "UNKNOWN"
    assert run(cid, {"diagnostic_setting": [clean]}) == "UNKNOWN"


def test_enumeration_logging_pass_fail_unknown():
    cid = "azure.other.enumeration_logging"
    policy = {"window_start": "2026-10-01T00:00:00Z", "window_end": "2026-10-10T00:00:00Z",
              "delivery_delay_seconds": 86400}
    event = {"id": SCOPE + "/providers/PEASO/e/1", "eventId": "e1",
             "timestamp": "2026-10-05T00:00:00Z", "clientIdentity": "p", "activityNature": "list"}
    record = {**event, "id": SCOPE + "/providers/PEASO/log/1"}
    base = {"diagnostic_setting": [{"id": SETTING}], "enumeration_event": [event],
            "enumeration_log_record": [record]}
    assert enumeration_external_run(cid, base, policy) == "PASS"
    assert run(cid, base, policy, status="partial") == "UNKNOWN"
    assert enumeration_external_run(cid, {**base, "enumeration_log_record": []}, policy) == "FAIL"
    malformed = copy.deepcopy(base)
    malformed["enumeration_event"][0]["timestamp"] = "bad"
    assert enumeration_external_run(cid, malformed, policy) == "UNKNOWN"
    assert run(cid, base) == "UNKNOWN"
    assert enumeration_external_run(cid, {**base, "enumeration_event": []}, policy) == "UNKNOWN"


def role(actions, *, excluded=None):
    return {"id": ROLE, "properties": {"type": "CustomRole", "assignableScopes": [SCOPE],
        "permissions": [{"actions": actions, "notActions": excluded or [], "dataActions": [], "notDataActions": []}]}}


def test_custom_role_wildcards_pass_fail_unknown():
    cid = "azure_role_assignment_aks_cluster_rbac_enabled_1c8eacd"
    ops = ["Microsoft.Compute/virtualMachines/read", "Microsoft.Compute/virtualMachines/write"]
    policy = {"operationCatalogStatus": "collected", "providerOperations": ops,
              "protectedScopes": [SCOPE]}
    assert run(cid, {"role_definition": [role([ops[0]])]}, policy) == "PASS"
    assert run(cid, {"role_definition": [role([ops[0]])]}, policy, status="partial") == "UNKNOWN"
    assert run(cid, {"role_definition": [role(["Microsoft.Compute/virtualMachines/*"])]}, policy) == "FAIL"
    assert run(cid, {"role_definition": [role(["Microsoft.Compute/virtualMachines/*"], excluded=[ops[1]])]}, policy) == "PASS"
    assert run(cid, {"role_definition": [role([ops[0]])]}) == "UNKNOWN"
    malformed = role([ops[0]])
    del malformed["properties"]["permissions"][0]["notActions"]
    assert run(cid, {"role_definition": [malformed]}, policy) == "UNKNOWN"


def test_keyvault_blocked_actions_pass_fail_unknown():
    cid = "azure_vault_keyvault_rbac_enabled_0179c48"
    op = "Microsoft.KeyVault/vaults/keys/delete"
    policy = {"operationCatalogStatus": "collected", "providerOperations": [op],
              "blockedKeyVaultActions": [op], "protectedVaultIds": [VAULT]}
    assignment = {"id": SCOPE + "/providers/Microsoft.Authorization/roleAssignments/a",
                  "properties": {"scope": VAULT, "conditionVersion": "", "condition": "",
                                 "roleDefinitionId": ROLE}}
    base = {"role_definition": [role(["Microsoft.KeyVault/vaults/keys/read"])],
            "role_assignment": [assignment]}
    assert run(cid, base, policy) == "PASS"
    assert run(cid, base, policy, status="partial") == "UNKNOWN"
    assert run(cid, {**base, "role_definition": [role(["Microsoft.KeyVault/vaults/keys/*"])]}, policy) == "FAIL"
    assert run(cid, base) == "UNKNOWN"
    bad = copy.deepcopy(base)
    del bad["role_assignment"][0]["properties"]["condition"]
    assert run(cid, bad, policy) == "UNKNOWN"


def profile_cert(state="Enabled", source="AzureKeyVault"):
    return {"id": PROFILE, "sku": {"name": "Standard_Microsoft"},
        "_coverage": {"customDomains": {"status": "collected"}},
        "customDomains": [{"id": PROFILE + "/endpoints/e/customDomains/d",
                           "properties": {"customHttpsProvisioningState": state,
                                          "customHttpsParameters": {"certificateSource": source}}}]}


def test_cdn_cert_pass_fail_unknown_and_empty():
    cid = "azure_cdn_profile_1_2_8_5_ed953a0"
    assert run(cid, {"cdn_profile": [profile_cert()]}) == "PASS"
    assert run(cid, {"cdn_profile": [profile_cert()]}, status="partial") == "UNKNOWN"
    assert run(cid, {"cdn_profile": [profile_cert("Enabled", "Cdn")]}) == "FAIL"
    assert run(cid, {"cdn_profile": [profile_cert("Enabling")]}) == "UNKNOWN"
    malformed = profile_cert()
    del malformed["customDomains"][0]["properties"]["customHttpsParameters"]
    assert run(cid, {"cdn_profile": [malformed]}) == "UNKNOWN"
    assert run(cid, {"cdn_profile": []}) == "NOT_APPLICABLE"


def profile_origin(mode="SystemAssignedIdentity", *, rbac=True):
    group_id = PROFILE + "/originGroups/g"
    return {"id": PROFILE, "sku": {"name": "Premium_AzureFrontDoor"},
        "identity": {"type": "SystemAssigned", "principalId": "principal"},
        "_coverage": {"routes": {"status": "collected"}, "originGroups": {"status": "collected"}},
        "routes": [{"id": PROFILE + "/afdEndpoints/e/routes/r", "properties": {"originGroup": {"id": group_id}},
                    "originAuthenticationPrerequisites": {"status": "collected", "forwardingHttpsOnly": True,
                        "originGroupProbeHttps": True, "noPrivateLink": True}}],
        "originGroups": [{"id": group_id, "_provenance": {"representation": "full"},
            "properties": {"authentication": None if mode is None else {
            "type": mode, "scope": "https://storage.azure.com/.default"}},
            "origins": [{"id": group_id + "/origins/o", "blobContainerEvidence": {
                "status": "collected", "isContainer": True, "requiredByPolicy": True}, "blobRbacEvidence": {
                "status": "collected", "principalId": "principal", "dataReader": rbac}}]}]}


def test_frontdoor_origin_pass_fail_unknown_and_empty():
    cid = "azure_cdn_profile_10_3_4_1_4e40487"
    assert run(cid, {"cdn_profile": [profile_origin()]}) == "PASS"
    assert run(cid, {"cdn_profile": [profile_origin()]}, status="partial") == "UNKNOWN"
    user_assigned = profile_origin("UserAssignedIdentity")
    identity_id = SCOPE + "/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/u"
    user_assigned["identity"] = {"type": "UserAssigned", "userAssignedIdentities": {
        identity_id.casefold(): {"principalId": "principal"}}}
    user_assigned["originGroups"][0]["properties"]["authentication"]["userAssignedIdentity"] = {"id": identity_id}
    assert run(cid, {"cdn_profile": [user_assigned]}) == "PASS"
    assert run(cid, {"cdn_profile": [profile_origin(None)]}) == "FAIL"
    noncontainer = profile_origin()
    noncontainer["originGroups"][0]["origins"][0]["blobContainerEvidence"]["isContainer"] = False
    assert run(cid, {"cdn_profile": [noncontainer]}) == "FAIL"
    missing = profile_origin()
    del missing["originGroups"][0]["origins"][0]["blobRbacEvidence"]
    assert run(cid, {"cdn_profile": [missing]}) == "UNKNOWN"
    assert run(cid, {"cdn_profile": [profile_cert()]}) == "NOT_APPLICABLE"
    unknown_generation = profile_cert()
    unknown_generation["sku"]["name"] = "Unknown_Cdn_Generation"
    assert run(cid, {"cdn_profile": [unknown_generation]}) == "UNKNOWN"
    assert run(cid, {"cdn_profile": []}) == "NOT_APPLICABLE"


def test_production_change_pass_fail_unknown():
    cid = "azure_c5_dev_08_02b"
    target = SCOPE + "/resourceGroups/rg/providers/Microsoft.Web/sites/app"
    policy = {"window_start": "2026-10-01T00:00:00Z", "window_end": "2026-10-10T00:00:00Z",
              "productionResourceIds": [target], "dataPlaneChangesComplete": True}
    change = {"id": SCOPE + "/providers/PEASO/changes/1", "resourceId": target,
              "timestamp": "2026-10-05T00:00:00Z", "correlationId": "c", "actorId": "p",
              "status": "Succeeded"}
    activity = {"id": "azure-activity://record", "resourceId": target, "correlationId": "c",
                "caller": "p", "operationName": {"value": "Microsoft.Web/sites/write"},
                "status": {"value": "Succeeded"}, "eventTimestamp": "2026-10-05T00:00:00Z"}
    base = {"production_change": [change], "activity_log": [activity]}
    assert run(cid, base, policy) == "PASS"
    assert run(cid, base, policy, status="partial") == "UNKNOWN"
    assert run(cid, {**base, "activity_log": []}, policy) == "FAIL"
    no_actor = copy.deepcopy(base)
    del no_actor["production_change"][0]["actorId"]
    assert run(cid, no_actor, policy) == "FAIL"
    no_caller = copy.deepcopy(base)
    del no_caller["activity_log"][0]["caller"]
    assert run(cid, no_caller, policy) == "FAIL"
    assert run(cid, base) == "UNKNOWN"
    bad = copy.deepcopy(base)
    bad["activity_log"][0]["eventTimestamp"] = "bad"
    assert run(cid, bad, policy) == "UNKNOWN"
    assert run(cid, {**base, "production_change": []}, policy) == "UNKNOWN"


def test_signed_metadata_and_foreign_or_incomplete_scope():
    cid = "azure_aks_cluster_1_4_5_2_3ac7b3c"
    base = {"pod": [pod()], "container_group": []}
    assert run(cid, base, status="partial") == "UNKNOWN"
    index = scoped(base)
    index["context"]["provider"] = "aws"
    assert evaluate_check(cid, {"scope": SCOPE}, index)[0] == "UNKNOWN"
    index = scoped(base)
    index["pod"][0]["scope"] = SCOPE + "/foreign"
    assert evaluate_check(cid, {"scope": SCOPE}, index)[0] == "UNKNOWN"
    index = scoped(base)
    index["pod"].append(copy.deepcopy(index["pod"][0]))
    assert evaluate_check(cid, {"scope": SCOPE}, index)[0] == "UNKNOWN"


def test_enumeration_event_identity_cannot_be_reused():
    cid = "azure.other.enumeration_logging"
    policy = {"window_start": "2026-10-01T00:00:00Z", "window_end": "2026-10-10T00:00:00Z",
              "delivery_delay_seconds": 86400}
    event = {"id": SCOPE + "/providers/PEASO/e/1", "eventId": "e1",
             "timestamp": "2026-10-05T00:00:00Z", "clientIdentity": "p", "activityNature": "list"}
    record = {**event, "id": SCOPE + "/providers/PEASO/log/1"}
    second = {**event, "id": SCOPE + "/providers/PEASO/e/2"}
    rows = {"diagnostic_setting": [{"id": SETTING}], "enumeration_event": [event, second],
            "enumeration_log_record": [record]}
    assert run(cid, rows, policy) == "UNKNOWN"


@pytest.mark.parametrize("variant,expected", [
    ("distinct_matched", "PASS"),
    ("distinct_unmatched", "FAIL"),
    ("duplicate_other_time", "UNKNOWN"),
    ("duplicate_other_subject", "UNKNOWN"),
    ("partial_source", "UNKNOWN"),
])
def test_enumeration_unique_event_mapping_boundaries(variant, expected):
    cid = "azure.other.enumeration_logging"
    policy = {"window_start": "2026-10-01T00:00:00Z", "window_end": "2026-10-10T00:00:00Z",
              "delivery_delay_seconds": 86400}
    first = {"id": SCOPE + "/providers/PEASO/e/1", "eventId": "e1",
             "timestamp": "2026-10-05T00:00:00Z", "clientIdentity": "p", "activityNature": "list"}
    second = {**first, "id": SCOPE + "/providers/PEASO/e/2", "eventId": "e2"}
    if variant == "duplicate_other_time":
        second.update(eventId="e1", timestamp="2026-10-06T00:00:00Z")
    elif variant == "duplicate_other_subject":
        second.update(eventId="e1", clientIdentity="other")
    records = [{**first, "id": SCOPE + "/providers/PEASO/log/1"}]
    if variant == "distinct_matched":
        records.append({**second, "id": SCOPE + "/providers/PEASO/log/2"})
    rows = {"diagnostic_setting": [{"id": SETTING}], "enumeration_event": [first, second],
            "enumeration_log_record": records}
    assert enumeration_external_run(cid, rows, policy, status="partial" if variant == "partial_source" else "collected") == expected


def test_enumeration_empty_event_identity_unavailable():
    cid = "azure.other.enumeration_logging"
    policy = {"window_start": "2026-10-01T00:00:00Z", "window_end": "2026-10-10T00:00:00Z",
              "delivery_delay_seconds": 86400}
    event = {"id": SCOPE + "/providers/PEASO/e/1", "eventId": "",
             "timestamp": "2026-10-05T00:00:00Z", "clientIdentity": "p", "activityNature": "list"}
    record = {**event, "id": SCOPE + "/providers/PEASO/log/1"}
    assert run(cid, {"diagnostic_setting": [{"id": SETTING}], "enumeration_event": [event],
                     "enumeration_log_record": [record]}, policy) == "UNKNOWN"
