"""Entry-point correlation and severity regressions; no provider calls."""
import copy
import pytest

from peaso.snapshot import make_snapshot, resources
from peaso.principal_exposure import project, canonical
from peaso.least_privilege import project as least


def test_k8s_host_port_path_is_correlated_to_pod_service_account():
    pod = {"metadata": {"name": "web", "namespace": "app"}, "spec": {"nodeName": "worker",
           "serviceAccountName": "app", "containers": [{"name": "web", "ports": [{"containerPort": 8080, "hostPort": 8080}]}]},
           "status": {"phase": "Running"}}
    node = {"metadata": {"name": "worker"}, "status": {"addresses": [{"type": "ExternalIP", "address": "34.9.9.9"}]}}
    snap = snapshot("k8s", {"pod": [pod], "node": [node], "serviceaccount": [
        {"metadata": {"name": "app", "namespace": "app"}}], "networkpolicy": []})
    card = project(snap, resources(snap))["cluster|system:serviceaccount:app:app"]
    signal = next(x for x in card["exposures"] if x["kind"] == "internet_workload")
    assert signal["state"] == "unknown"
    assert signal["ports"] == ["tcp/8080"]
    assert signal["public_addresses"] == ["34.9.9.9"]

ACCOUNT = "111111111111"
ARN = f"arn:aws:iam::{ACCOUNT}:role/app"


def snapshot(provider, items, metadata=None, scope=None):
    scope = scope or {"aws": ACCOUNT + "/us-east-1", "gcp": "projects/home", "azure": "/subscriptions/home", "k8s": "cluster"}[provider]
    return make_snapshot(provider, [scope], [{"type": kind, "scope": scope, "service": kind,
        "status": "collected" if rows else "empty", "items": rows} for kind, rows in items.items()], metadata=metadata or {})


def aws_role(principal, condition=None):
    statement = {"Effect": "Allow", "Principal": {"AWS": principal}, "Action": "sts:AssumeRole"}
    if condition is not None:
        statement["Condition"] = condition
    return {"Arn": ARN, "RoleName": "app", "AssumeRolePolicyDocument": {"Statement": [statement]},
        "RolePolicyList": [{"PolicyName": "admin", "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}]}


def test_external_aws_admin_is_critical_but_same_org_is_trusted():
    snap = snapshot("aws", {"iam_role": [aws_role("arn:aws:iam::222222222222:root")]})
    result = least("aws", resources(snap), snapshot=snap)
    card = result["items"][0]
    assert card["severity"] == "critical" and card["base_severity"] == "high"
    assert card["exposures"][0]["kind"] == "external_assumption"
    trusted = snapshot("aws", {"iam_role": [aws_role("arn:aws:iam::222222222222:root")],
        "organization_account": [{"Id": "222222222222"}]})
    assert not project(trusted, resources(trusted))[ARN]["exposures"]


def test_conditional_trust_and_deny_never_become_unrestricted_access():
    role = aws_role("*", {"StringEquals": {"aws:PrincipalOrgID": "o-home"}})
    snap = snapshot("aws", {"iam_role": [role]})
    card = project(snap, resources(snap))[ARN]
    assert card["exposures"][0]["state"] == "conditional"
    assert card["severity"] == "high"
    role["AssumeRolePolicyDocument"]["Statement"][0]["Effect"] = "Deny"
    snap = snapshot("aws", {"iam_role": [role]})
    assert not project(snap, resources(snap))[ARN]["exposures"]


def test_gcp_impersonation_and_actas_are_distinct_and_scope_bound():
    sa = {"email": "app@home.iam.gserviceaccount.com", "iamPolicy": {"bindings": [
        {"role": "roles/iam.serviceAccountTokenCreator", "members": ["serviceAccount:caller@outside.iam.gserviceaccount.com"]},
        {"role": "roles/iam.serviceAccountUser", "members": ["user:third@outside.test"]}]}}
    snap = snapshot("gcp", {"service_account": [sa]}, {"trusted_domains": ["home.test"]})
    card = project(snap, resources(snap))["serviceAccount:" + sa["email"]]
    assert [s["state"] for s in card["exposures"]] == ["declared", "conditional"]
    assert card["exposures"][1]["requires_workload_control"]
    assert card["exposures"][0]["caller"].endswith("outside.iam.gserviceaccount.com")


def test_gcp_foreign_project_policy_does_not_apply_to_other_service_accounts():
    snap = snapshot("gcp", {"service_account": [{"email": "app@home.iam.gserviceaccount.com"}]})
    snap["collections"].append({"type": "iam_policy", "scope": "projects/other", "service": "iam", "status": "collected", "items": [
        {"bindings": [{"role": "roles/iam.serviceAccountTokenCreator", "members": ["allUsers"]}]}]})
    assert not project(snap, resources(snap))["serviceAccount:app@home.iam.gserviceaccount.com"]["exposures"]


def test_gcp_managed_ad_external_domain_trust_is_a_principal_signal():
    domain = {"name": "projects/home/locations/global/domains/home.test", "fqdn": "home.test",
              "trusts": [{"targetDomainName": "partner.test", "state": "CONNECTED", "trustDirection": "INBOUND"}]}
    snap = snapshot("gcp", {"managed_ad_domain": [domain]}, {"trusted_domains": ["home.test"]})
    card = project(snap, resources(snap))["home.test"]
    assert card["exposures"][0]["kind"] == "external_domain_trust"
    assert card["exposures"][0]["state"] == "declared"
    assert card["exposures"][0]["target_domain"] == "partner.test"


def test_gcp_identity_platform_anonymous_tenant_signup_signal():
    tenant = {"name": "projects/home/tenants/open", "enableAnonymousUser": True}
    snap = snapshot("gcp", {"identityplatform_tenant": [tenant]})
    assert project(snap, resources(snap))[tenant["name"]]["exposures"][0]["kind"] == "anonymous_identity_signup"
    tenant["client"] = {"permissions": {"disabledUserSignup": True}}
    snap = snapshot("gcp", {"identityplatform_tenant": [tenant]})
    assert project(snap, resources(snap))[tenant["name"]]["exposures"][0]["state"] == "conditional"


def test_gcp_identity_platform_anonymous_project_signup_signal():
    config = {"name": "projects/home/config", "signIn": {"anonymous": {"enabled": True}}}
    snap = snapshot("gcp", {"identityplatform_config": [config]})
    assert project(snap, resources(snap))[config["name"]]["exposures"][0]["state"] == "declared"


def test_azure_foreign_application_is_external_and_federation_is_conditional():
    snap = snapshot("azure", {"directory_service_principal": [{"id": "sp", "appId": "app", "appOwnerOrganizationId": "outside"}],
        "directory_federated_credential": [{"id": "fic", "appId": "app", "issuer": "https://token.actions.githubusercontent.com", "subject": "repo:home/app:ref:refs/heads/main"}]}, {"tenant_id": "home"})
    card = project(snap, resources(snap))["sp"]
    assert {e["kind"] for e in card["exposures"]} == {"external_identity", "federated_trust"}
    assert next(e for e in card["exposures"] if e["kind"] == "federated_trust")["state"] == "conditional"


@pytest.mark.parametrize("audience", ["AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount",
    "PersonalMicrosoftAccount"])
def test_azure_application_external_sign_in_audience_is_conditional(audience):
    app = {"id": "app-object", "appId": "client-id", "signInAudience": audience}
    snap = snapshot("azure", {"directory_application": [app]}, {"tenant_id": "home"})
    card = project(snap, resources(snap))["app-object"]
    assert len(card["exposures"]) == 1
    signal = card["exposures"][0]
    assert signal["kind"] == "external_app_audience" and signal["state"] == "conditional"
    assert signal["sign_in_audience"] == audience and signal["app_id"] == "client-id"
    app["signInAudience"] = "AzureADMyOrg"
    snap = snapshot("azure", {"directory_application": [app]}, {"tenant_id": "home"})
    assert "app-object" not in project(snap, resources(snap))


def test_azure_directory_index_is_built_once_and_does_not_cross_snapshots(monkeypatch):
    from peaso.analysis import trust
    from peaso.analysis.common import _CONTEXT

    original = trust._azure_foreign
    indexed = []

    def counted(snap):
        indexed.append(snap)
        return original(snap)

    monkeypatch.setattr(trust, "_azure_foreign", counted)
    identities = {"directory_service_principal": [
        {"id": f"sp{i}", "appOwnerOrganizationId": "owner"} for i in range(3)]}
    external = snapshot("azure", identities, {"tenant_id": "other"})
    home = snapshot("azure", identities, {"tenant_id": "owner"})
    before = copy.deepcopy(external)
    assert _CONTEXT.get() is None
    assert all(card["exposures"] for card in project(external, resources(external)).values())
    assert not any(card["exposures"] for card in project(home, resources(home)).values())
    assert len(indexed) == 2 and indexed[0] is external and indexed[1] is home
    assert external == before and _CONTEXT.get() is None


def kube(public=True, automount=True, selector=True):
    service = {"metadata": {"name": "web", "namespace": "app"},
        "spec": {"type": "LoadBalancer", "ports": [{"port": 80, "targetPort": 8080}], "selector": {"app": "web"} if selector else {}},
        "status": {"loadBalancer": {"ingress": [{"ip": "8.8.8.8" if public else "10.0.0.8"}]}}}
    return snapshot("k8s", {"networkpolicy": [], "service": [service], "pod": [{"metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
        "spec": {"serviceAccountName": "app", "automountServiceAccountToken": automount}}],
        "serviceaccount": [{"metadata": {"name": "app", "namespace": "app"}}],
        "clusterrole": [{"metadata": {"name": "admin"}, "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]}],
        "clusterrolebinding": [{"metadata": {"name": "admin"}, "roleRef": {"kind": "ClusterRole", "name": "admin"},
            "subjects": [{"kind": "ServiceAccount", "name": "app", "namespace": "app"}]}]})


def test_public_kubernetes_service_correlates_selector_namespace_and_identity():
    snap = kube()
    cards = project(snap, resources(snap))
    card = cards[canonical("k8s", "system:serviceaccount:app:app", "cluster")]
    assert card["severity"] == "critical"
    assert card["exposures"][0]["ports"] == ["tcp/80"]
    assert card["exposures"][0]["requires_application_compromise"]


def test_kubernetes_private_service_disabled_token_and_empty_selector_do_not_expose_identity():
    for snap in (kube(public=False), kube(automount=False), kube(selector=False)):
        assert not any(c["exposures"] for c in project(snap, resources(snap)).values())


def test_pending_loadbalancer_and_networkpolicy_do_not_raise_criticality():
    snap = kube()
    next(c for c in snap["collections"] if c["type"] == "service")["items"][0]["status"] = {}
    card = project(snap, resources(snap))["cluster|system:serviceaccount:app:app"]
    assert card["exposures"][0]["state"] == "unknown" and card["severity"] == "high"
    snap = kube()
    snap["collections"].append({"type": "networkpolicy", "scope": "cluster", "service": "k8s", "status": "collected", "items": [{
        "metadata": {"name": "restrict", "namespace": "app"},
        "spec": {"podSelector": {"matchLabels": {"app": "web"}}, "policyTypes": ["Ingress"], "ingress": []}}]})
    card = project(snap, resources(snap))["cluster|system:serviceaccount:app:app"]
    assert card["exposures"][0]["state"] == "conditional" and card["severity"] == "high"


def test_privesc_raises_severity_preserves_confidence_and_exposes_source():
    from peaso import privesc
    snap = snapshot("aws", {"iam_role": [aws_role("arn:aws:iam::222222222222:root")], "iam_user": [], "iam_policy": [], "iam_group": []})
    original = copy.deepcopy(snap)
    result = privesc.analyze(snap, entries=[])
    admin = next(f for f in result["findings"] if f["check_id"] == "admin-equivalent")
    assert admin["base_severity"] == "high" and admin["severity"] == "critical"
    assert admin["evidence"]["principal_exposures"]
    node = next(n for n in result["graph"]["nodes"] if n["id"] == ARN)
    assert node["exposures"]
    detail = result["graph"]["edges"][0]["technique_details"][0]
    assert detail["severity"] == "critical" and detail["confidence"] == admin["evidence"]["confidence"]
    assert snap == original


def test_exposure_requirements_are_included_in_collection_plans():
    from peaso.analysis import REQUIRED_TYPES, privesc_required_types
    for provider, kind in [("aws", "ecs_task"), ("gcp", "cloudrun_service"), ("azure", "directory_federated_credential"), ("k8s", "ingress")]:
        assert kind in REQUIRED_TYPES[provider]["least_privilege"]
        assert kind in privesc_required_types(provider)


def test_kubernetes_provenance_separates_namespaces_and_clusters():
    snap = kube()
    for collection in snap["collections"]:
        collection["scope"] = "*"
        for row in collection["items"]:
            row["provenance"] = {"cluster_id": "real-cluster"}
    cards = project(snap, resources(snap))
    assert cards["real-cluster|system:serviceaccount:app:app"]["exposures"]
    page = least("k8s", resources(snap), snapshot=snap)
    assert next(c for c in page["items"] if c["principal"] == "system:serviceaccount:app:app")["exposures"]
    from peaso import privesc
    result = privesc.analyze(snap, entries=[])
    assert next(n for n in result["graph"]["nodes"] if n["id"] == "k8s:real-cluster:sa:app:app")["exposures"]


def test_public_cloud_run_uses_runtime_service_account():
    snap = snapshot("gcp", {"cloudrun_service": [{"name": "projects/home/locations/eu/services/web", "uri": "https://web.run.app",
        "ingress": "INGRESS_TRAFFIC_ALL", "invokerIamDisabled": True, "template": {"serviceAccount": "app@home.iam.gserviceaccount.com"}}]})
    card = project(snap, resources(snap))["serviceAccount:app@home.iam.gserviceaccount.com"]
    assert card["exposures"][0]["state"] == "declared"
    assert card["exposures"][0]["ports"] == ["tcp/443"]


def test_ecs_public_eni_uses_task_role_and_never_execution_role():
    from peaso.analysis.internet_exposure import Assessment, pset
    from unittest.mock import patch
    snap = snapshot("aws", {"network_interface": [{"NetworkInterfaceId": "eni-task"}],
        "ecs_task": [{"taskArn": "task", "lastStatus": "RUNNING", "taskDefinitionArn": "definition", "attachments": [
            {"details": [{"name": "networkInterfaceId", "value": "eni-task"}]}]}],
        "ecs_task_definition": [{"taskDefinitionArn": "definition", "taskRoleArn": ARN, "executionRoleArn": "execution-role"}]})
    rows = resources(snap)
    assessment = Assessment(next(r for r in rows if r["type"] == "network_interface"), "interface")
    assessment.ports = pset("tcp", 80, 80)
    assessment.addresses = ["8.8.8.8"]
    with patch("peaso.principal_exposure.assess", return_value=[assessment]):
        cards = project(snap, rows)
    assert cards[ARN]["exposures"][0]["kind"] == "internet_workload"
    assert "execution-role" not in cards


def test_azure_managed_identity_federated_credentials_resolve_arm_parent():
    parent = "/subscriptions/home/resourceGroups/app/providers/Microsoft.ManagedIdentity/userAssignedIdentities/app"
    snap = snapshot("azure", {"managed_identity": [{"id": parent, "properties": {"principalId": "identity"}}],
        "managed_identity_federated_credential": [{"id": parent + "/federatedIdentityCredentials/github", "properties": {
            "issuer": "https://token.actions.githubusercontent.com", "subject": "repo:owner/app:ref:refs/heads/main", "audiences": ["api://AzureADTokenExchange"]}}]}, {"tenant_id": "home"})
    assert project(snap, resources(snap))["identity"]["exposures"][0]["state"] == "conditional"


def test_unpinned_multitenant_oidc_trust_raises_priority():
    role = aws_role("ignored")
    statement = role["AssumeRolePolicyDocument"]["Statement"][0]
    statement.update(Principal={"Federated": f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"},
                     Action="sts:AssumeRoleWithWebIdentity", Condition={"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}})
    provider = {"Arn": f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com",
                "Provider": {"collection_status": "collected", "Url": "token.actions.githubusercontent.com",
                             "ClientIDList": ["sts.amazonaws.com"]}}
    snap = snapshot("aws", {"iam_role": [role], "iam_oidc_provider": [provider]})
    card = project(snap, resources(snap))[ARN]
    assert card["exposures"][0]["state"] == "declared" and card["severity"] == "critical"
    statement["Condition"]["StringEquals"]["token.actions.githubusercontent.com:sub"] = "repo:owned/app:ref:refs/heads/main"
    snap = snapshot("aws", {"iam_role": [role], "iam_oidc_provider": [provider]})
    assert project(snap, resources(snap))[ARN]["exposures"][0]["state"] == "conditional"


def test_kubernetes_external_named_impersonation_respects_namespace_and_resource_names():
    snap = snapshot("k8s", {
        "serviceaccount": [{"metadata": {"name": "target", "namespace": "app"}}, {"metadata": {"name": "other", "namespace": "app"}}, {"metadata": {"name": "target", "namespace": "other"}}],
        "role": [{"metadata": {"name": "impersonator", "namespace": "app"}, "rules": [{"apiGroups": [""], "resources": ["serviceaccounts"], "verbs": ["impersonate"], "resourceNames": ["target"]}]}],
        "rolebinding": [{"metadata": {"name": "external", "namespace": "app"}, "roleRef": {"kind": "Role", "name": "impersonator"}, "subjects": [{"kind": "User", "name": "caller@external.test"}]}]}, {"trusted_domains": ["home.test"]})
    cards = project(snap, resources(snap))
    assert cards["cluster|system:serviceaccount:app:target"]["exposures"][0]["kind"] == "external_impersonation"
    assert "cluster|system:serviceaccount:app:other" not in cards
    assert "cluster|system:serviceaccount:other:target" not in cards


def test_azure_container_app_public_environment_and_internal_environment():
    env_id = "/subscriptions/home/providers/Microsoft.App/managedEnvironments/env"
    app = {"id": "app", "type": "Microsoft.App/containerApps", "identity": {"principalId": "mi"}, "properties": {
        "provisioningState": "Succeeded", "environmentId": env_id, "configuration": {"ingress": {"external": True, "fqdn": "app.example.test"}}}}
    environment = {"id": env_id, "type": "Microsoft.App/managedEnvironments", "properties": {"publicNetworkAccess": "Enabled"}}
    snap = snapshot("azure", {"resource_graph": [app, environment]})
    assert project(snap, resources(snap))["mi"]["exposures"][0]["state"] == "declared"
    environment["properties"]["publicNetworkAccess"] = "Disabled"
    snap = snapshot("azure", {"resource_graph": [app, environment]})
    assert "mi" not in project(snap, resources(snap))
    snap = snapshot("azure", {"resource_graph": [app]})
    assert project(snap, resources(snap))["mi"]["exposures"][0]["state"] == "unknown"


def test_azure_container_instance_public_port_links_managed_identity():
    snap = snapshot("azure", {"container_group": [{"id": "container", "identity": {"principalId": "mi"}, "properties": {
        "provisioningState": "Succeeded", "ipAddress": {"type": "Public", "ip": "8.8.8.8", "ports": [{"port": 8080}]}}}]})
    exposure = project(snap, resources(snap))["mi"]["exposures"][0]
    assert exposure["state"] == "declared" and exposure["ports"] == ["tcp/8080"]


def test_disabled_automount_still_detects_a_mounted_projected_token():
    snap = kube(automount=False)
    spec = next(c for c in snap["collections"] if c["type"] == "pod")["items"][0]["spec"]
    spec["volumes"] = [{"name": "token", "projected": {"sources": [{"serviceAccountToken": {"path": "token"}}]}}]
    assert not project(snap, resources(snap))["cluster|system:serviceaccount:app:app"]["exposures"]
    spec["containers"] = [{"name": "web", "volumeMounts": [{"name": "token", "mountPath": "/token"}]}]
    assert project(snap, resources(snap))["cluster|system:serviceaccount:app:app"]["exposures"]
