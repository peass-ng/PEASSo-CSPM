"""Isolated signed Azure sw30 predicate tests."""
from __future__ import annotations

import copy

import pytest

from peaso.checks import evaluate_check
from peaso.checks import compliance_new_sw30 as sw
from peaso.checks import CHECKS, evaluate_check

SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
NOW = "2026-10-12T12:00:00Z"
AKS = SCOPE + "/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/a"
SYN = SCOPE + "/resourceGroups/rg/providers/Microsoft.Synapse/workspaces/w"
NSG = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/n"
ADMIN_SUBNET = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v/subnets/admin"
APP_SUBNET = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v/subnets/app"
POOL = SYN + "/sqlPools/p"
STORE = SCOPE + "/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/s"
KEY = "https://vault.vault.azure.net/keys/approved"
ENDPOINT = "https://s.blob.core.windows.net/"


def covered(row, **children):
    row.setdefault("_coverage", {})
    for field, value in children.items():
        row[field] = value
        row["_coverage"][field] = {"status": "collected" if value else "empty"}
    return row


def fresh(**kw):
    return {"status": "collected", "complete": True, "asOf": NOW,
            "maxAgeSeconds": 3600, **kw}


def pod(uid=1000, privileged=False):
    return {"metadata": {"namespace": "apps", "name": "app", "uid": "pod-1"}, "spec": {"os": {"name": "linux"},
        "securityContext": {"runAsUser": uid},
        "containers": [{"name": "app", "securityContext": {"privileged": privileged}}]}}


def index(kind, row, policy=None, extras=None, status="collected"):
    groups = {kind: [row], **(extras or {})}
    return {"context": {"provider": "azure", "scope": SCOPE, "created_at": NOW,
            "metadata": {"compliance_policy": {"status": "collected", **(policy or {})}}},
        "collections": {k: [{"type": k, "scope": SCOPE,
            "status": status if k == kind else "collected", "items": rows}]
            for k, rows in groups.items()},
        **{k: [{"type": k, "scope": SCOPE, "data": x} for x in rows]
           for k, rows in groups.items()}}


def fixture(check_id):
    if check_id in (sw.VULN, sw.DIAG, sw.SUPPORT, sw.PRIV, sw.NONROOT, sw.KMS):
        row = {"id": AKS, "location": "westeurope", "_provenance": {"representation": "full"},
               "properties": {"kubernetesVersion": "1.30.5", "supportPlan": "KubernetesOfficial",
                    "securityProfile": {"azureKeyVaultKms": {"enabled": True, "keyId": KEY}}}}
        policy = {}
        if check_id == sw.VULN:
            policy["aksAdvisories"] = fresh(vulnerableVersions=[], supportedBranches=["1.30"])
            row["properties"]["kubernetesVersion"] = "1.30.5"
            def fail(r, p): p["aksAdvisories"]["vulnerableVersions"] = ["1.30.5"]
        elif check_id == sw.DIAG:
            covered(row, diagnosticCategories=[{"name": "kube-audit", "properties": {"categoryType": "Logs"}}],
                    diagnosticSettings=[{"id": AKS + "/providers/Microsoft.Insights/diagnosticSettings/d",
                        "properties": {"workspaceId": SCOPE + "/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/log",
                                       "logs": [{"category": "kube-audit", "enabled": True}]}}],
                    diagnosticDestinations=[{"id": SCOPE + "/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/log", "usable": True}])
            def fail(r, p): r["diagnosticSettings"][0]["properties"]["logs"][0]["enabled"] = False
        elif check_id == sw.SUPPORT:
            policy["oldestVersionSupported"] = "1.29.0"
            policy["aksRegionalSupport"] = fresh(location="westeurope", supportPlan="KubernetesOfficial", supportedVersions=["1.30.5", "1.29.0"])
            def fail(r, p): r["properties"]["kubernetesVersion"] = "1.29.0"
        elif check_id in (sw.PRIV, sw.NONROOT):
            row["podInventory"] = {"status": "collected", "pagesComplete": True,
                "namespacesComplete": True, "consistent": True, "fullPodRepresentation": True, "clusterId": AKS,
                "resourceVersion": "42", "items": [pod()]}
            if check_id == sw.PRIV:
                def fail(r, p): r["podInventory"]["items"][0]["spec"]["containers"][0]["securityContext"]["privileged"] = True
            else:
                def fail(r, p): r["podInventory"]["items"][0]["spec"]["securityContext"]["runAsUser"] = 0
        else:
            row["kmsKeyEvidence"] = {"status": "collected", "complete": True, "keyId": KEY,
                "exists": True, "enabled": True, "identityCanUse": True, "networkReachable": True}
            def fail(r, p): r["properties"]["securityProfile"]["azureKeyVaultKms"]["enabled"] = False
        return "aks_cluster", row, policy, {}, fail
    if check_id in (sw.PRIVATE, sw.CMK, sw.STORAGE_AUDIT, sw.COMBINED, sw.RETENTION, sw.PUBLIC):
        row = {"id": SYN, "_provenance": {"representation": "full"},
            "properties": {"publicNetworkAccess": "Disabled", "encryption": {"cmk": {
                "status": "Consistent", "key": {"name": "approved", "keyVaultUrl": "https://vault.vault.azure.net"}}}},
            "keyResolution": {"status": "collected", "complete": True, "keyId": KEY,
                "exists": True, "enabled": True, "accessible": True}}
        covered(row, sqlPools=[{"id": POOL, "properties": {"status": "Online"}}])
        policy, extras = {}, {}
        if check_id == sw.PRIVATE:
            ep = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/privateEndpoints/e"
            covered(row, privateEndpointConnections=[{"id": SYN + "/privateEndpointConnections/c",
                "properties": {"privateLinkServiceConnectionState": {"status": "Approved"},
                               "privateEndpoint": {"id": ep}}}],
                resolvedPrivateEndpoints=[{"id": ep, "properties": {"privateLinkServiceConnections": [
                    {"properties": {"privateLinkServiceId": SYN, "groupIds": ["sql"]}}]}}])
            def fail(r, p): r["resolvedPrivateEndpoints"][0]["properties"]["privateLinkServiceConnections"][0]["properties"]["groupIds"] = ["dev"]
        elif check_id == sw.CMK:
            policy["approvedKeyVaultKeyId"] = KEY
            def fail(r, p): r["properties"]["encryption"]["cmk"]["status"] = "Disabled"
        elif check_id == sw.STORAGE_AUDIT:
            policy["requiredStorageAccountId"] = STORE
            extras["storage_account"] = [{"id": STORE, "properties": {"primaryEndpoints": {"blob": ENDPOINT}}}]
            covered(row, sqlPoolAuditingSettings=[{"poolId": POOL, "properties": {"state": "Enabled", "storageEndpoint": ENDPOINT}}])
            def fail(r, p): r["sqlPoolAuditingSettings"][0]["properties"]["state"] = "Disabled"
        elif check_id == sw.COMBINED:
            policy.update(requiredKeyId=KEY, requiredAuditSink=ENDPOINT)
            covered(row, sqlPoolBlobAuditingPolicies=[{"poolId": POOL, "sinkUsable": True,
                "properties": {"state": "Enabled", "storageEndpoint": ENDPOINT}}])
            def fail(r, p): r["sqlPoolBlobAuditingPolicies"][0]["properties"]["state"] = "Disabled"
        elif check_id == sw.RETENTION:
            policy.update(minimumRetentionDays=3, maximumRetentionDays=14)
            covered(row, sqlPoolRetentionEvidence=[{"poolId": POOL, "status": "collected",
                "authoritative": True, "automaticSnapshotsEnabled": True, "retentionDays": 7}])
            def fail(r, p): r["sqlPoolRetentionEvidence"][0]["retentionDays"] = 0
        else:
            def fail(r, p): r["properties"]["publicNetworkAccess"] = "Enabled"
        return "synapse_workspace", row, policy, extras, fail
    row = {"id": NSG}
    policy = {}
    if check_id == sw.ADMIN:
        policy.update(approvedAdminPorts=[22], approvedAdminSourceCidrs=["10.0.0.0/24"],
            adminApplicationPairs=[{"adminSubnetId": ADMIN_SUBNET, "applicationSubnetId": APP_SUBNET}])
        row["effectiveAdminPaths"] = {"status": "collected", "complete": True, "nsgId": NSG,
            "paths": [{"role": "admin-to-application", "associationsResolved": True,
                "sourceSubnetId": ADMIN_SUBNET, "destinationSubnetId": APP_SUBNET,
                "sourceCidr": "10.0.0.0/24", "destinationPort": 22,
                "subnetNsgAllows": True, "nicNsgAllows": True}]}
        def fail(r, p): r["effectiveAdminPaths"]["paths"][0]["destinationPort"] = 3389
    elif check_id == sw.MONITOR:
        policy.update(monitorPrincipalIds=["monitor"], approvedDestinations=["10.0.0.5"], approvedPorts=[443])
        row["effectiveMonitorPaths"] = {"status": "collected", "complete": True, "nsgId": NSG,
            "paths": [{"principalId": "monitor", "identityAndRouteResolved": True,
                "destination": "10.0.0.5", "destinationPort": 443, "reachable": True}]}
        def fail(r, p): r["effectiveMonitorPaths"]["paths"][0]["destinationPort"] = 22
    else:
        policy["approvedSourceCidrs"] = ["10.0.0.0/24"]
        row["effectiveInternetIngress"] = {"status": "collected", "complete": True, "nsgId": NSG,
            "paths": [{"associationResolved": True, "rulesAndTagsExpanded": True,
                "sourceCidr": "10.0.0.0/24", "destinationPort": 443, "allowed": True}]}
        def fail(r, p): r["effectiveInternetIngress"]["paths"][0]["sourceCidr"] = "0.0.0.0/0"
    return "nsg", row, policy, {}, fail


@pytest.mark.parametrize("check_id", tuple(sw.SPECS))
def test_pass_fail_and_conservative_unknown(check_id):
    kind, row, policy, extras, make_fail = fixture(check_id)
    def assess(r=row, p=policy, status="collected", more=extras):
        return evaluate_check(check_id, r, index(kind, r, p, more, status))[0]
    assert assess() == "PASS", check_id
    broken = copy.deepcopy(row)
    broken_policy = copy.deepcopy(policy)
    make_fail(broken, broken_policy)
    assert assess(broken, broken_policy) == "FAIL", check_id
    assert assess(status="partial") == "UNKNOWN", check_id
    malformed = copy.deepcopy(row)
    malformed["id"] = "not-an-ARM-id"
    assert assess(malformed) == "UNKNOWN", check_id
    assert evaluate_check(check_id, row, {"context": {"provider": "azure", "scope": SCOPE}})[0] == "UNKNOWN"
    missing = copy.deepcopy(row)
    field = {sw.VULN: "properties.kubernetesVersion", sw.DIAG: "diagnosticCategories",
        sw.SUPPORT: "location", sw.PRIV: "podInventory", sw.NONROOT: "podInventory",
        sw.KMS: "properties.securityProfile", sw.PRIVATE: "privateEndpointConnections",
        sw.CMK: "properties.encryption", sw.STORAGE_AUDIT: "sqlPoolAuditingSettings",
        sw.COMBINED: "sqlPoolBlobAuditingPolicies", sw.RETENTION: "sqlPoolRetentionEvidence",
        sw.PUBLIC: "properties.publicNetworkAccess", sw.ADMIN: "effectiveAdminPaths",
        sw.MONITOR: "effectiveMonitorPaths", sw.HTTPS: "effectiveInternetIngress"}[check_id]
    parent = missing
    for part in field.split(".")[:-1]:
        parent = parent[part]
    parent.pop(field.split(".")[-1])
    assert assess(missing) == "UNKNOWN", check_id
    foreign = index(kind, row, policy, extras)
    foreign["context"]["scope"] = "/subscriptions/another"
    assert evaluate_check(check_id, row, foreign)[0] == "UNKNOWN", check_id


@pytest.mark.parametrize("check_id", (sw.NONROOT, sw.PRIVATE, sw.STORAGE_AUDIT, sw.COMBINED, sw.RETENTION, sw.PUBLIC, sw.HTTPS, sw.ADMIN))
def test_not_applicable_when_complete_empty_scope(check_id):
    kind, row, policy, extras, _ = fixture(check_id)
    if kind == "synapse_workspace":
        covered(row, sqlPools=[])
    elif check_id == sw.NONROOT:
        row["podInventory"]["items"] = []
    else:
        field = "effectiveInternetIngress" if check_id == sw.HTTPS else "effectiveAdminPaths"
        row[field]["paths"] = []
        if check_id == sw.ADMIN:
            policy["adminApplicationPairs"] = []
    assert evaluate_check(check_id, row, index(kind, row, policy, extras))[0] == "NOT_APPLICABLE"


def test_adversarial_boundaries():
    kind, row, policy, extras, _ = fixture(sw.ADMIN)
    row["effectiveAdminPaths"]["paths"][0].update(destinationPort=3389, subnetNsgAllows=False)
    assert evaluate_check(sw.ADMIN, row, index(kind, row, policy))[0] == "PASS"
    kind, row, policy, extras, _ = fixture(sw.PRIVATE)
    row["resolvedPrivateEndpoints"][0]["properties"]["privateLinkServiceConnections"][0]["properties"]["groupIds"] = ["dev"]
    assert evaluate_check(sw.PRIVATE, row, index(kind, row, policy))[0] == "FAIL"
    kind, row, policy, extras, _ = fixture(sw.NONROOT)
    row["podInventory"]["items"][0]["spec"]["containers"][0]["securityContext"]["runAsUser"] = 0
    assert evaluate_check(sw.NONROOT, row, index(kind, row, policy))[0] == "FAIL"
    kind, row, policy, extras, _ = fixture(sw.SUPPORT)
    row["properties"]["kubernetesVersion"] = "1.29.0"
    status, evidence = evaluate_check(sw.SUPPORT, row, index(kind, row, policy))
    assert status == "FAIL" and evidence["requirement_6_3_3_5_status"] == "PASS"


