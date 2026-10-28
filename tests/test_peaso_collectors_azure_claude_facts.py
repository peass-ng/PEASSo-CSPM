"""Azure collector facts read by the claude/claude2 Azure checks (plans, ASEs, slots, site logs, Automation variables, Entra roles/device policy)."""
from urllib.parse import parse_qs, urlsplit

from peaso.collectors import azure
from peaso.snapshot import validate

from test_peaso_collectors_azure_perf import FakeAzure, ReadError, rows

SUB = "/subscriptions/sub-a"
RG = SUB + "/resourceGroups/rg/providers"
SITE = RG + "/Microsoft.Web/sites/app"
AUTO = RG + "/Microsoft.Automation/automationAccounts/auto"


def test_plans_environments_slots_and_site_logs_are_collected_without_sas_urls():
    def handler(url, body, audience):
        path = urlsplit(url).path
        if path == SUB + "/providers/Microsoft.Web/serverfarms":
            return {"value": [{"id": RG + "/Microsoft.Web/serverfarms/plan", "sku": {"name": "B1", "tier": "Basic"}, "properties": {}}]}
        if path == SUB + "/providers/Microsoft.Web/hostingEnvironments":
            return {"value": [{"id": RG + "/Microsoft.Web/hostingEnvironments/ase", "properties": {"clusterSettings": [{"name": "InternalEncryption", "value": "true"}]}}]}
        if path == SUB + "/providers/Microsoft.Web/sites":
            return {"value": [{"id": SITE, "name": "app", "properties": {"httpsOnly": True}}]}
        if path == SITE + "/slots":
            return {"value": [{"id": SITE + "/slots/staging", "name": "app/staging",
                              "type": "Microsoft.Web/sites/slots", "properties": {"httpsOnly": False}}]}
        if path == SITE + "/slots/staging/config/web":
            return {"id": path, "type": "Microsoft.Web/sites/slots/config", "properties": {
                "ipSecurityRestrictionsDefaultAction": "Deny", "scmIpSecurityRestrictionsUseMain": True,
                "appSettings": [{"name": "secret", "value": "SLOT_SECRET_VALUE"}]}}
        if path == SITE + "/slots/staging/config/authsettingsV2":
            return {"id": path, "type": "Microsoft.Web/sites/slots/config", "properties": {
                "platform": {"enabled": True}, "globalValidation": {
                    "requireAuthentication": True, "unauthenticatedClientAction": "Return401",
                    "excludedPaths": []}, "identityProviders": {
                    "azureActiveDirectory": {"enabled": True, "registration": {"clientSecret": "SLOT_AUTH_SECRET"}}}}}
        if path == SITE + "/config/logs":
            return {"id": SITE + "/config/logs", "name": "logs", "properties": {
                "failedRequestsTracing": {"enabled": False}, "detailedErrorMessages": {"enabled": True},
                "httpLogs": {"azureBlobStorage": {"enabled": True, "retentionInDays": 7, "sasUrl": "https://x.blob/c?sig=SASTOKEN9"}},
                "applicationLogs": {"azureBlobStorage": {"level": "Error", "sasUrl": "https://x.blob/c?sig=SASTOKEN9"}}}}
        if path.startswith(SITE + "/config/"):
            return {"id": SITE + path[len(SITE):], "properties": {}}
        return {"value": []}
    snapshot = azure.collect({"scopes": ["sub-a"]}, ["app_service", "app_service_plan", "app_service_environment", "app_service_slot"], transport=FakeAzure(handler))
    assert validate(snapshot) == snapshot
    assert rows(snapshot, "app_service_plan")[0]["items"][0]["sku"]["name"] == "B1"
    assert rows(snapshot, "app_service_environment")[0]["items"][0]["properties"]["clusterSettings"] == [{"name": "InternalEncryption", "value": "true"}]
    slot = rows(snapshot, "app_service_slot", SUB)[0]
    assert slot["status"] == "collected"
    assert slot["items"][0]["properties"]["httpsOnly"] is False and slot["items"][0]["parent_id"] == SITE
    assert slot["items"][0]["_coverage"]["configuration"]["status"] == "collected"
    assert slot["items"][0]["configuration"]["properties"]["ipSecurityRestrictionsDefaultAction"] == "Deny"
    assert slot["items"][0]["_coverage"]["authSettingsV2"]["status"] == "collected"
    assert slot["items"][0]["authSettingsV2"]["properties"]["globalValidation"]["excludedPaths"] == []
    assert "SLOT_SECRET_VALUE" not in repr(snapshot)
    assert "SLOT_AUTH_SECRET" not in repr(snapshot)
    site = rows(snapshot, "app_service")[0]["items"][0]
    logs = site["logsConfiguration"]["properties"]
    assert logs["failedRequestsTracing"] == {"enabled": False}
    assert logs["httpLogs"]["azureBlobStorage"] == {"enabled": True, "retentionInDays": 7}
    assert "SASTOKEN9" not in repr(snapshot)


def test_automation_variables_keep_encryption_flag_but_never_values():
    def handler(url, body, audience):
        path = urlsplit(url).path
        if path == SUB + "/providers/Microsoft.Automation/automationAccounts":
            return {"value": [{"id": AUTO, "name": "auto", "properties": {}}]}
        if path == AUTO + "/variables":
            return {"value": [{"id": AUTO + "/variables/plain", "name": "plain", "properties": {"isEncrypted": False, "value": "\"hunter2\""}},
                              {"id": AUTO + "/variables/enc", "name": "enc", "properties": {"isEncrypted": True}}]}
        return {"value": []}
    snapshot = azure.collect({"scopes": ["sub-a"]}, ["automation_variable"], transport=FakeAzure(handler))
    assert validate(snapshot) == snapshot
    variables = rows(snapshot, "automation_variable", SUB)[0]
    assert variables["status"] == "collected"
    assert {item["name"]: item["properties"]["isEncrypted"] for item in variables["items"]} == {"plain": False, "enc": True}
    assert "hunter2" not in repr(snapshot)


def test_denied_child_reads_never_derive_an_empty_slot_or_variable_inventory():
    def handler(url, body, audience):
        path = urlsplit(url).path
        if path == SUB + "/providers/Microsoft.Web/sites":
            return {"value": [{"id": SITE, "properties": {}}]}
        if path == SUB + "/providers/Microsoft.Automation/automationAccounts":
            return {"value": [{"id": AUTO, "properties": {}}]}
        if path in (SITE + "/slots", AUTO + "/variables"):
            raise ReadError(403)
        if path.startswith(SITE + "/config/"):
            return {"id": SITE + path[len(SITE):], "properties": {}}
        return {"value": []}
    snapshot = azure.collect({"scopes": ["sub-a"]}, ["app_service_slot", "automation_variable"], transport=FakeAzure(handler))
    for kind in ("app_service_slot", "automation_variable"):
        collection = rows(snapshot, kind, SUB)[0]
        assert collection["status"] not in ("collected", "empty") and collection["error"]["code"] == "parent_inventory_incomplete"


def test_directory_roles_and_device_registration_policy():
    def handler(url, body, audience):
        path = urlsplit(url).path
        if path == "/v1.0/directoryRoles":
            return {"value": [{"id": "r1", "displayName": "Global Administrator", "roleTemplateId": "62e90394-69f5-4237-9190-012177145e10"}]}
        if path == "/v1.0/policies/deviceRegistrationPolicy":
            return {"id": "deviceRegistrationPolicy", "multiFactorAuthConfiguration": "required"}
        return {"value": []}
    api = FakeAzure(handler)
    snapshot = azure.collect({"scopes": ["sub-a"]}, ["directory_role", "directory_device_registration_policy", "user_registration_detail"], transport=api)
    assert validate(snapshot) == snapshot
    selects = {urlsplit(url).path: parse_qs(urlsplit(url).query).get("$select", [""])[0].split(",") for url, _, _ in api.calls}
    assert "roleTemplateId" in selects["/v1.0/directoryRoles"]
    assert {"isMfaRegistered", "userPrincipalName"} <= set(selects["/v1.0/reports/authenticationMethods/userRegistrationDetails"])
    assert rows(snapshot, "directory_role")[0]["items"][0]["roleTemplateId"] == "62e90394-69f5-4237-9190-012177145e10"
    policy = rows(snapshot, "directory_device_registration_policy")[0]
    assert policy["status"] == "collected" and policy["items"][0]["multiFactorAuthConfiguration"] == "required"


def test_denied_device_registration_policy_is_a_denied_envelope():
    def handler(url, body, audience):
        if urlsplit(url).path == "/v1.0/policies/deviceRegistrationPolicy":
            raise ReadError(403)
        return {"value": []}
    snapshot = azure.collect({"scopes": ["sub-a"]}, ["directory_device_registration_policy"], transport=FakeAzure(handler))
    policy = rows(snapshot, "directory_device_registration_policy")[0]
    assert policy["status"] == "denied" and policy["items"] == []


def test_tenant_record_is_scoped_to_the_authenticated_tenant_like_directory_facts():
    def handler(url, body, audience):
        if urlsplit(url).path == "/tenants":
            return {"value": [{"id": "/tenants/tenant-a", "tenantId": "tenant-a"}]}
        return {"value": []}
    snapshot = azure.collect({"scopes": ["sub-a"]}, ["tenant", "directory_role"], transport=FakeAzure(handler))
    assert rows(snapshot, "tenant")[0]["scope"] == rows(snapshot, "directory_role")[0]["scope"] == "/tenants/tenant-a"


def test_service_principal_alternative_names_distinguish_managed_identity_kinds():
    uami = "/subscriptions/sub-a/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uami"
    def handler(url, body, audience):
        if urlsplit(url).path == "/v1.0/servicePrincipals":
            return {"value": [{"id": "sp-sys", "servicePrincipalType": "ManagedIdentity", "alternativeNames": ["isExplicit=False", SITE]},
                              {"id": "sp-user", "servicePrincipalType": "ManagedIdentity", "alternativeNames": ["isExplicit=True", uami]}]}
        return {"value": []}
    api = FakeAzure(handler)
    snapshot = azure.collect({"scopes": ["sub-a"]}, ["directory_service_principal"], transport=api)
    url = next(url for url, _, _ in api.calls if urlsplit(url).path == "/v1.0/servicePrincipals")
    assert "alternativeNames" in parse_qs(urlsplit(url).query)["$select"][0].split(",")
    items = {item["id"]: item for item in rows(snapshot, "directory_service_principal")[0]["items"]}
    assert items["sp-sys"]["alternativeNames"] == ["isExplicit=False", SITE]
    assert items["sp-user"]["alternativeNames"] == ["isExplicit=True", uami]
