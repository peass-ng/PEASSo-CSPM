"""HackTricks Cloud Best Practices: Azure / Entra ID checks not covered by Prowler/Powerpipe.

Each predicate reads a field the Azure collector already keeps (after
_metadata_only) and is derived from the cited HackTricks Cloud technique page.
Missing fields are UNKNOWN unless the ARM contract documents an omission default,
which is then applied only inside a collected `properties` object.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from . import result
from .facts import Unavailable, complete_items, get, list_of_objects, optional
from .fixtures import CASES
from .hacktricks_bp_common import ht_register

AZ = "pentesting-cloud/azure-security/"
PRIV = AZ + "az-privilege-escalation/"


def _arm(kind, name, **properties):
    return {"id": "/subscriptions/s/resourceGroups/rg/providers/" + kind + "/" + name, "name": name, "properties": properties}


# ---------------------------------------------------------------- local (key/SAS) authentication
def local_auth(slug, kind, provider_type, service, page, *, severity="medium", extra=()):
    cid = "azure.htbp." + slug

    @ht_register(cid, "azure", "least_privilege", kind, service + " disables local (key/SAS) authentication", severity, "IA-2",
                 "Set properties.disableLocalAuth=true so the data plane only accepts Microsoft Entra ID tokens governed by "
                 "Azure RBAC; keys obtained through listKeys-style actions then stop working.",
                 pages=[page])
    def evaluate(item, index):
        properties = get(item, "properties", dict)
        disabled = get(properties, "disableLocalAuth", bool)
        return result(not disabled, disable_local_auth=disabled,
                      **{name: properties.get(name) for name in extra if name in properties},
                      semantics="Keys/SAS rules authenticate without an Entra identity and bypass data-plane RBAC")
    CASES[cid] = {"pass": _arm(provider_type, "x", disableLocalAuth=True), "fail": _arm(provider_type, "x", disableLocalAuth=False),
                  "missing": _arm(provider_type, "x"), "malformed": _arm(provider_type, "x", disableLocalAuth="false")}


local_auth("eventhub.local_auth_disabled", "eventhub_namespace", "Microsoft.EventHub/namespaces", "Event Hubs namespace",
           AZ + "az-persistence/az-event-hubs-persistence.md")
local_auth("eventgrid.topic_local_auth_disabled", "eventgrid_topic", "Microsoft.EventGrid/topics", "Event Grid topic",
           PRIV + "az-event-grid-privesc.md")
local_auth("eventgrid.domain_local_auth_disabled", "eventgrid_domain", "Microsoft.EventGrid/domains", "Event Grid domain",
           PRIV + "az-event-grid-privesc.md")
local_auth("signalr.local_auth_disabled", "signalr_service", "Microsoft.SignalRService/signalR", "SignalR service",
           PRIV + "az-signalr-web-pubsub-privesc.md")
local_auth("webpubsub.local_auth_disabled", "web_pubsub", "Microsoft.SignalRService/webPubSub", "Web PubSub service",
           PRIV + "az-signalr-web-pubsub-privesc.md")
local_auth("appconfig.local_auth_disabled", "app_configuration", "Microsoft.AppConfiguration/configurationStores", "App Configuration store",
           PRIV + "az-app-configuration-privesc.md")
local_auth("search.api_key_auth_disabled", "search_service", "Microsoft.Search/searchServices", "AI Search service",
           PRIV + "az-ai-search-privesc.md", extra=("authOptions",))
local_auth("iothub.local_auth_disabled", "iot_hub", "Microsoft.Devices/IotHubs", "IoT Hub (hub-level shared access policies)",
           PRIV + "az-iot-hub-privesc.md", extra=("disableDeviceSAS", "disableModuleSAS"))


@ht_register("azure.htbp.redis.access_key_auth_disabled", "azure", "least_privilege", "redis_cache",
             "Azure Cache for Redis disables access-key authentication", "medium", "IA-2",
             "Enable Microsoft Entra authentication and set disableAccessKeyAuthentication=true so listKeys output no longer "
             "authenticates to the cache data plane.",
             pages=[PRIV + "az-redis-privesc.md", AZ + "az-post-exploitation/az-redis-post-exploitation.md"])
def redis_keys(item, index):
    disabled = get(item, "properties.disableAccessKeyAuthentication", bool)
    return result(not disabled, disable_access_key_authentication=disabled)


CASES["azure.htbp.redis.access_key_auth_disabled"] = {
    "pass": _arm("Microsoft.Cache/redis", "r", disableAccessKeyAuthentication=True),
    "fail": _arm("Microsoft.Cache/redis", "r", disableAccessKeyAuthentication=False),
    "missing": _arm("Microsoft.Cache/redis", "r"), "malformed": _arm("Microsoft.Cache/redis", "r", disableAccessKeyAuthentication=0)}


@ht_register("azure.htbp.batch.shared_key_auth_disabled", "azure", "least_privilege", "batch_account",
             "Batch account does not allow SharedKey data-plane authentication", "high", "IA-2",
             "Remove SharedKey from allowedAuthenticationModes (keep AAD / TaskAuthenticationToken); account keys let any "
             "holder submit tasks that run commands on pool nodes.",
             pages=[PRIV + "az-batch-privesc.md"])
def batch_shared_key(item, index):
    modes = get(item, "properties.allowedAuthenticationModes", list)
    if any(not isinstance(mode, str) for mode in modes):
        raise Unavailable("malformed allowedAuthenticationModes")
    if any(mode not in ("SharedKey", "AAD", "TaskAuthenticationToken") for mode in modes):
        raise Unavailable("unrecognized allowedAuthenticationModes")
    return result("SharedKey" in modes, allowed_authentication_modes=modes)


CASES["azure.htbp.batch.shared_key_auth_disabled"] = {
    "pass": _arm("Microsoft.Batch/batchAccounts", "b", allowedAuthenticationModes=["AAD", "TaskAuthenticationToken"]),
    "fail": _arm("Microsoft.Batch/batchAccounts", "b", allowedAuthenticationModes=["SharedKey", "AAD"]),
    "missing": _arm("Microsoft.Batch/batchAccounts", "b"), "malformed": _arm("Microsoft.Batch/batchAccounts", "b", allowedAuthenticationModes="SharedKey")}


# ---------------------------------------------------------------- anonymous / non-Entra access paths
@ht_register("azure.htbp.acr.anonymous_pull_disabled", "azure", "exposure", "container_registry",
             "Container registry does not allow anonymous (unauthenticated) pull", "high", "AC-3",
             "Set anonymousPullEnabled=false unless the registry is intentionally public; anonymous pull exposes every "
             "repository in the registry to unauthenticated clients.",
             pages=[AZ + "az-unauthenticated-enum-and-initial-entry/az-container-registry-unauth.md"])
def acr_anonymous(item, index):
    enabled = get(item, "properties.anonymousPullEnabled", bool)
    return result(enabled, anonymous_pull_enabled=enabled, sku=optional(item, "sku", {}, dict).get("name"))


CASES["azure.htbp.acr.anonymous_pull_disabled"] = {
    "pass": _arm("Microsoft.ContainerRegistry/registries", "acr", anonymousPullEnabled=False, adminUserEnabled=False),
    "fail": _arm("Microsoft.ContainerRegistry/registries", "acr", anonymousPullEnabled=True),
    "missing": _arm("Microsoft.ContainerRegistry/registries", "acr"),
    "malformed": _arm("Microsoft.ContainerRegistry/registries", "acr", anonymousPullEnabled="true")}


@ht_register("azure.htbp.keyvault.template_deployment_disabled", "azure", "least_privilege", "vault",
             "Key Vault does not let ARM template deployments retrieve its secrets", "medium", "AC-6",
             "Set enabledForTemplateDeployment=false unless the vault deliberately serves ARM/Bicep secret references; with it "
             "enabled, Microsoft.KeyVault/vaults/deploy/action reveals secrets without any data-plane permission.",
             pages=[PRIV + "az-key-vault-privesc.md"])
def keyvault_template(item, index):
    properties = get(item, "properties", dict)
    get(properties, "tenantId", str)
    # ARM omits the flags when false (documented default).
    enabled = optional(properties, "enabledForTemplateDeployment", False, bool)
    return result(enabled, enabled_for_template_deployment=enabled,
                  enabled_for_deployment=optional(properties, "enabledForDeployment", False, bool))


_KV = {"tenantId": "00000000-0000-0000-0000-000000000001", "sku": {"name": "standard"}}
CASES["azure.htbp.keyvault.template_deployment_disabled"] = {
    "pass": _arm("Microsoft.KeyVault/vaults", "kv", **_KV), "fail": _arm("Microsoft.KeyVault/vaults", "kv", **_KV, enabledForTemplateDeployment=True),
    "missing": {"id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv", "name": "kv"},
    "malformed": _arm("Microsoft.KeyVault/vaults", "kv", **_KV, enabledForTemplateDeployment="yes")}


@ht_register("azure.htbp.sql.entra_only_authentication", "azure", "least_privilege", "sql_server",
             "SQL server with a Microsoft Entra administrator enforces Entra-only authentication", "medium", "IA-2",
             "Enable Microsoft Entra-only authentication so SQL logins (and a reset administrator password) cannot be used.",
             pages=[PRIV + "az-sql-privesc.md", AZ + "az-persistence/az-sql-persistence.md"])
def sql_entra_only(item, index):
    admins = list_of_objects(get(item, "serverAdministrators", list))
    entra = [admin for admin in admins if get(admin, "properties.administratorType", str) == "ActiveDirectory"]
    if not entra:
        return "NOT_APPLICABLE", {"reason": "no Microsoft Entra administrator (azure.claude.sql_server_entra_admin)"}
    modes = list_of_objects(get(item, "azureADOnlyAuthentications", list))
    flags = [get(mode, "properties.azureADOnlyAuthentication", bool) for mode in modes]
    if len(flags) != 1 or flags[0] is None:
        return "UNKNOWN", {"reason": "missing or malformed native SQL authentication mode"}
    return result(not all(flags), azure_ad_only_authentication=flags)


def _sql(only):
    return {**_arm("Microsoft.Sql/servers", "sql"), "serverAdministrators": [
        {"properties": {"administratorType": "ActiveDirectory", "login": "dba"}}],
        "azureADOnlyAuthentications": [{"properties": {"azureADOnlyAuthentication": only}}]}


CASES["azure.htbp.sql.entra_only_authentication"] = {
    "pass": _sql(True), "fail": _sql(False), "missing": _arm("Microsoft.Sql/servers", "sql"),
    "malformed": {**_arm("Microsoft.Sql/servers", "sql"), "serverAdministrators": [{"properties": {"administratorType": "ActiveDirectory"}}],
                  "azureADOnlyAuthentications": [{"properties": {"azureADOnlyAuthentication": "no"}}]}}


@ht_register("azure.htbp.postgresql.password_auth_disabled", "azure", "least_privilege", "postgresql_flexible_server",
             "PostgreSQL flexible server disables password authentication", "medium", "IA-2",
             "Set authConfig.passwordAuth=Disabled with Microsoft Entra authentication enabled, so resetting the administrator "
             "password through ARM no longer yields database access.",
             pages=[PRIV + "az-postgresql-privesc.md"])
def postgres_password(item, index):
    value = get(item, "properties.authConfig.passwordAuth", str)
    if value not in ("Enabled", "Disabled"):
        raise Unavailable("unrecognized passwordAuth value")
    return result(value == "Enabled", password_auth=value,
                  active_directory_auth=optional(get(item, "properties.authConfig", dict), "activeDirectoryAuth", None))


_PG = "Microsoft.DBforPostgreSQL/flexibleServers"
CASES["azure.htbp.postgresql.password_auth_disabled"] = {
    "pass": _arm(_PG, "pg", authConfig={"activeDirectoryAuth": "Enabled", "passwordAuth": "Disabled"}),
    "fail": _arm(_PG, "pg", authConfig={"activeDirectoryAuth": "Enabled", "passwordAuth": "Enabled"}),
    "missing": _arm(_PG, "pg"), "malformed": _arm(_PG, "pg", authConfig={"passwordAuth": True})}


@ht_register("azure.htbp.storage.sftp_local_users_disabled", "azure", "least_privilege", "storage_account",
             "Storage account does not expose SFTP local-user access", "medium", "IA-2",
             "Disable SFTP (isSftpEnabled=false) or local users (isLocalUserEnabled=false) when not required; SFTP local-user "
             "passwords/keys are credentials outside Entra ID and are not blocked by allowSharedKeyAccess=false.",
             pages=[AZ + "az-persistence/az-storage-persistence.md"])
def storage_sftp(item, index):
    properties = get(item, "properties", dict)
    get(properties, "provisioningState", str)
    sftp = optional(properties, "isSftpEnabled", False, bool)
    local_users = optional(properties, "isLocalUserEnabled", True, bool)
    return result(sftp and local_users, is_sftp_enabled=sftp, is_local_user_enabled=local_users,
                  semantics="ARM omits isSftpEnabled when false; local users default to enabled")


_SA = "Microsoft.Storage/storageAccounts"
CASES["azure.htbp.storage.sftp_local_users_disabled"] = {
    "pass": _arm(_SA, "sa", provisioningState="Succeeded", allowSharedKeyAccess=False),
    "fail": _arm(_SA, "sa", provisioningState="Succeeded", isSftpEnabled=True, isHnsEnabled=True),
    "missing": _arm(_SA, "sa"), "malformed": _arm(_SA, "sa", provisioningState="Succeeded", isSftpEnabled="true")}


@ht_register("azure.htbp.logicapp.request_trigger_caller_restricted", "azure", "exposure", "logic_app_workflow",
             "Logic App HTTP request trigger restricts callers beyond the SAS callback URL", "medium", "AC-3",
             "Add accessControl.triggers.allowedCallerIpAddresses or an OAuth (Entra ID) authorization policy for Request "
             "triggers; otherwise anyone holding the signed callback URL can invoke the workflow from anywhere.",
             pages=[AZ + "az-unauthenticated-enum-and-initial-entry/az-logic-apps-unauth.md",
                    AZ + "az-post-exploitation/az-logic-apps-post-exploitation.md"])
def logic_trigger(item, index):
    properties = get(item, "properties", dict)
    state = get(properties, "state", str)
    triggers = get(properties, "definition.triggers", dict)
    request = sorted(name for name, trigger in triggers.items() if isinstance(trigger, dict) and trigger.get("type") == "Request")
    if any(not isinstance(trigger, dict) for trigger in triggers.values()):
        raise Unavailable("malformed trigger definition")
    if not request:
        return "NOT_APPLICABLE", {"reason": "no HTTP Request trigger"}
    if state != "Enabled":
        return "NOT_APPLICABLE", {"reason": "workflow state " + state}
    control = optional(optional(properties, "accessControl", {}, dict), "triggers", {}, dict)
    ips = optional(control, "allowedCallerIpAddresses", None)
    oauth = optional(control, "openAuthenticationPolicies", None)
    if ips is not None and not isinstance(ips, list) or oauth is not None and not isinstance(oauth, dict):
        raise Unavailable("malformed trigger access control")
    ranges = []
    for entry in ips or []:
        value = get(entry, "addressRange", str)
        try:
            if "-" in value:
                first, last = (ipaddress.IPv4Address(part) for part in value.split("-"))
                if first > last:
                    raise ValueError("reversed native IPv4 range")
            else:
                network = ipaddress.IPv4Network(value, strict=False)
                first, last = network.network_address, network.broadcast_address
        except (ValueError, TypeError) as exc:
            raise Unavailable("malformed native caller IPv4 range") from exc
        ranges.append((int(first), int(last)))
    end = -1
    for first, last in sorted(ranges):
        if first > end + 1:
            break
        end = max(end, last)
    # Empty is the documented Only other Logic Apps option. A nonempty
    # union admitting the entire IPv4 space imposes no source restriction.
    ip_restricted = ips is not None and (not ips or end < (1 << 32) - 1)
    policies = optional(oauth or {}, "policies", {}, dict)
    restricted = ip_restricted or bool(policies)

    return result(not restricted, request_triggers=request, allowed_caller_ip_ranges=ips,
                  oauth_policies=sorted(optional(oauth or {}, "policies", {}, dict)),
                  semantics="An empty allowedCallerIpAddresses list admits only other Logic Apps and counts as restricted")


def _workflow(access=None, state="Enabled"):
    properties = {"state": state, "definition": {"triggers": {"manual": {"type": "Request", "kind": "Http"}}}}
    if access is not None:
        properties["accessControl"] = {"triggers": access}
    return {"id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Logic/workflows/wf", "name": "wf", "properties": properties}


CASES["azure.htbp.logicapp.request_trigger_caller_restricted"] = {
    "pass": _workflow({"allowedCallerIpAddresses": [{"addressRange": "203.0.113.0/24"}]}), "fail": _workflow(),
    "missing": {"id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Logic/workflows/wf", "name": "wf", "properties": {"state": "Enabled"}},
    "malformed": {"name": "wf", "properties": {"state": "Enabled", "definition": {"triggers": {"manual": "Request"}}}}}


# ---------------------------------------------------------------- Entra ID applications
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
TIER0_GRAPH_ROLES = frozenset((
    "RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All", "Application.ReadWrite.All",
    "Directory.ReadWrite.All", "Group.ReadWrite.All", "GroupMember.ReadWrite.All", "User.ReadWrite.All",
    "UserAuthenticationMethod.ReadWrite.All", "Domain.ReadWrite.All", "Policy.ReadWrite.ConditionalAccess",
    "Policy.ReadWrite.AuthenticationMethod", "RoleManagementPolicy.ReadWrite.Directory", "PrivilegedAccess.ReadWrite.AzureADGroup",
    "RoleAssignmentSchedule.ReadWrite.Directory", "RoleEligibilitySchedule.ReadWrite.Directory"))


def graph_roles(index):
    """Microsoft Graph application-permission id -> value, from the collected Graph service principal."""
    principals = complete_items(index, "directory_service_principal")
    graph = [p for p in principals if p.get("appId") == GRAPH_APP_ID]
    if len(graph) != 1:
        raise Unavailable("Microsoft Graph service principal not in the collected inventory")
    return {get(role, "id", str): get(role, "value", str) for role in list_of_objects(get(graph[0], "appRoles", list))
            if isinstance(role.get("value"), str)}


@ht_register("azure.htbp.entra.app_no_tier0_graph_application_permissions", "azure", "least_privilege", "directory_application",
             "Application registration does not request tier-0 Microsoft Graph application permissions", "high", "AC-6",
             "Replace tier-0 Graph application permissions (RoleManagement/AppRoleAssignment/Application/Directory ReadWrite...) "
             "with least-privileged or delegated permissions, restrict who can add credentials to the app, and review its owners.",
             pages=[PRIV + "az-entraid-privesc/README.md"], dependencies=["directory_application", "directory_service_principal"])
def app_tier0(item, index):
    get(item, "appId", str)
    names = graph_roles(index)
    requested = []
    for resource in list_of_objects(get(item, "requiredResourceAccess", list)):
        if get(resource, "resourceAppId", str) != GRAPH_APP_ID:
            continue
        for access in list_of_objects(get(resource, "resourceAccess", list)):
            if get(access, "type", str) == "Role":
                name = names.get(get(access, "id", str))
                if name in TIER0_GRAPH_ROLES:
                    requested.append(name)
    return result(bool(requested), tier0_application_permissions=sorted(set(requested)),
                  sign_in_audience=item.get("signInAudience"),
                  semantics="Requested (manifest) application permissions; admin consent state is evaluated by the privesc graph")


_ROLE_ID = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"
_GRAPH_INDEX = {"collections": {"directory_service_principal": [{"scope": "tenant", "status": "collected"}]},
                "directory_service_principal": [{"data": {"id": "sp-graph", "appId": GRAPH_APP_ID, "appRoles": [
                    {"id": _ROLE_ID, "value": "RoleManagement.ReadWrite.Directory"},
                    {"id": "df021288-bdef-4463-88db-98f22de89214", "value": "User.Read.All"}]}}]}


def _app(role_id):
    return {"id": "app-1", "appId": "11111111-1111-1111-1111-111111111111", "signInAudience": "AzureADMyOrg",
            "requiredResourceAccess": [{"resourceAppId": GRAPH_APP_ID, "resourceAccess": [{"id": role_id, "type": "Role"}]}]}


CASES["azure.htbp.entra.app_no_tier0_graph_application_permissions"] = {
    "pass": _app("df021288-bdef-4463-88db-98f22de89214"), "fail": _app(_ROLE_ID), "index": _GRAPH_INDEX,
    "missing": {"id": "app-1", "appId": "11111111-1111-1111-1111-111111111111"},
    "malformed": {"id": "app-1", "appId": "1", "requiredResourceAccess": [{"resourceAppId": GRAPH_APP_ID, "resourceAccess": "Role"}]}}


@ht_register("azure.htbp.entra.temporary_access_pass_one_time", "azure", "hardening", "authentication_methods_policy",
             "Temporary Access Pass, when enabled, is one-time use with a short maximum lifetime", "low", "IA-5",
             "Set the TemporaryAccessPass method configuration to isUsableOnce=true and keep maximumLifetimeInMinutes at or below "
             "480; a reusable long-lived TAP issued through UserAuthenticationMethod.ReadWrite.All is a durable sign-in for any user.",
             pages=[PRIV + "az-entraid-privesc/README.md"])
def tap_policy(item, index):
    configs = [c for c in list_of_objects(get(item, "authenticationMethodConfigurations", list)) if c.get("id") == "TemporaryAccessPass"]
    if len(configs) != 1:
        raise Unavailable("TemporaryAccessPass configuration not present")
    config = configs[0]
    state = get(config, "state", str)
    if state == "disabled":
        return "NOT_APPLICABLE", {"reason": "Temporary Access Pass disabled"}
    if state != "enabled":
        raise Unavailable("unrecognized TAP state")
    once = get(config, "isUsableOnce", bool)
    lifetime = get(config, "maximumLifetimeInMinutes", int)
    if lifetime <= 0:
        raise Unavailable("nonpositive TAP lifetime")
    return result(not once or lifetime > 480, is_usable_once=once, maximum_lifetime_minutes=lifetime)


def _tap(**config):
    return {"id": "authenticationMethodsPolicy", "authenticationMethodConfigurations": [
        {"id": "Fido2", "state": "enabled"}, {"id": "TemporaryAccessPass", **config}]}


CASES["azure.htbp.entra.temporary_access_pass_one_time"] = {
    "pass": _tap(state="enabled", isUsableOnce=True, maximumLifetimeInMinutes=60),
    "fail": _tap(state="enabled", isUsableOnce=False, maximumLifetimeInMinutes=480),
    "not_applicable": _tap(state="disabled"),
    "missing": {"id": "authenticationMethodsPolicy", "authenticationMethodConfigurations": [{"id": "Fido2", "state": "enabled"}]},
    "malformed": _tap(state="enabled", isUsableOnce="true", maximumLifetimeInMinutes=60)}


# ---------------------------------------------------------------- snapshot time
def _snapshot_time(index):
    context = index.get("context") if isinstance(index, dict) else None
    value = context.get("created_at") if isinstance(context, dict) else None
    return _instant(value, "snapshot created_at")


def _instant(value, label):
    if not isinstance(value, str) or not value:
        raise Unavailable("malformed timestamp: " + label)
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise Unavailable("malformed timestamp: " + label)
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


_NOW = {"context": {"created_at": "2026-10-01T00:00:00Z"}}


# ---------------------------------------------------------------- App Service publishing (SCM/Kudu, FTP)
APP_PAGES = [PRIV + "az-app-services-privesc.md", AZ + "az-unauthenticated-enum-and-initial-entry/az-app-services-functions-unauth.md"]


@ht_register("azure.htbp.appservice.scm_basic_auth_disabled", "azure", "least_privilege", "app_service",
             "App Service SCM (Kudu) site does not accept basic-auth publishing credentials", "medium", "IA-2",
             "Set basicPublishingCredentialsPolicies/scm allow=false; deploy with Microsoft Entra identities. Publishing "
             "credentials (publishxml/config list) then no longer authenticate Kudu deployment and command endpoints.",
             pages=APP_PAGES)
def scm_basic_auth(item, index):
    allow = get(item, "scmBasicAuthPolicy.properties.allow", bool)
    return result(allow, scm_basic_auth_allowed=allow)


def _site(**fields):
    return {"id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Web/sites/app", "name": "app", "kind": "app", "properties": {}, **fields}


def _policy(allow):
    return {"properties": {"allow": allow}}


CASES["azure.htbp.appservice.scm_basic_auth_disabled"] = {
    "pass": _site(scmBasicAuthPolicy=_policy(False)), "fail": _site(scmBasicAuthPolicy=_policy(True)),
    "missing": _site(), "malformed": _site(scmBasicAuthPolicy=_policy("true"))}

FTPS_STATES = ("AllAllowed", "FtpsOnly", "Disabled")


@ht_register("azure.htbp.appservice.ftp_basic_auth_disabled", "azure", "least_privilege", "app_service",
             "App Service with FTP(S) enabled does not accept basic-auth FTP publishing credentials", "medium", "IA-2",
             "Set basicPublishingCredentialsPolicies/ftp allow=false, or disable FTP entirely (ftpsState=Disabled); FTP "
             "publishing credentials let any holder replace the deployed code.",
             pages=APP_PAGES)
def ftp_basic_auth(item, index):
    state = get(item, "configuration.properties.ftpsState", str)
    if state not in FTPS_STATES:
        raise Unavailable("unrecognized ftpsState")
    if state == "Disabled":
        return "NOT_APPLICABLE", {"reason": "FTP and FTPS are disabled", "ftps_state": state}
    allow = get(item, "ftpBasicAuthPolicy.properties.allow", bool)
    return result(allow, ftp_basic_auth_allowed=allow, ftps_state=state)


def _ftp(state, allow):
    return _site(configuration={"properties": {"ftpsState": state}}, ftpBasicAuthPolicy=_policy(allow))


CASES["azure.htbp.appservice.ftp_basic_auth_disabled"] = {
    "pass": _ftp("FtpsOnly", False), "fail": _ftp("FtpsOnly", True), "not_applicable": _ftp("Disabled", True),
    "missing": _site(configuration={"properties": {"ftpsState": "FtpsOnly"}}), "malformed": _ftp("FtpsOnly", 1)}


ANY_SOURCE = ("Any", "0.0.0.0/0", "::/0")


def _restricted(rules, default):
    """Whether an App Service access-restriction rule set denies unmatched callers.

    Rules are evaluated in priority order (lowest first), so the first rule that
    matches every source ("Any", including the synthetic "Allow all"/"Deny all"
    rule ARM returns) decides. Without such a rule the explicit default action
    decides; when the API returns no default action (older contract) any defined
    rule adds the implicit deny-all."""
    if default not in (None, "Allow", "Deny"):
        raise Unavailable("unrecognized restriction default action")
    rules = list_of_objects(rules)
    def priority(rule):
        value = rule.get("priority")
        return value if isinstance(value, int) and not isinstance(value, bool) else 2 ** 31
    for rule in sorted(rules, key=priority):
        source = rule.get("ipAddress")
        universal = source in ANY_SOURCE
        if isinstance(source, str) and not universal:
            try:
                universal = ipaddress.ip_network(source, strict=False).prefixlen == 0
            except ValueError:
                pass
        if universal and not rule.get("vnetSubnetResourceId") and not rule.get("headers"):
            action = rule.get("action", "Allow")
            if action not in ("Allow", "Deny"):
                raise Unavailable("unrecognized restriction rule action")
            return action == "Deny"
    if default is not None:
        return default == "Deny"
    return bool(rules)


@ht_register("azure.htbp.appservice.scm_site_restricted_like_main", "azure", "exposure", "app_service",
             "App Service with main-site access restrictions also restricts its SCM (Kudu) site", "medium", "SC-7",
             "Set scmIpSecurityRestrictionsUseMain=true or define SCM access restrictions with a Deny default; otherwise the "
             "Kudu deployment/command endpoint stays reachable from anywhere while the app itself is restricted.",
             pages=APP_PAGES)
def scm_restricted(item, index):
    if optional(get(item, "properties", dict), "publicNetworkAccess", None) == "Disabled":
        return "NOT_APPLICABLE", {"reason": "public network access disabled for the site"}
    config = get(item, "configuration.properties", dict)
    main = _restricted(get(config, "ipSecurityRestrictions", list), optional(config, "ipSecurityRestrictionsDefaultAction", None))
    if not main:
        return "NOT_APPLICABLE", {"reason": "main site has no access restrictions (exposure tracked by native checks)"}
    use_main = get(config, "scmIpSecurityRestrictionsUseMain", bool)
    scm = use_main or _restricted(get(config, "scmIpSecurityRestrictions", list), optional(config, "scmIpSecurityRestrictionsDefaultAction", None))
    return result(not scm, main_restricted=main, scm_use_main=use_main, scm_restricted=scm)


_ALLOW_ALL = [{"ipAddress": "Any", "action": "Allow", "priority": 2147483647, "name": "Allow all"}]
_DENY = [{"ipAddress": "203.0.113.0/24", "action": "Allow", "priority": 100}, {"ipAddress": "Any", "action": "Deny", "priority": 2147483647}]


def _restrictions(use_main, scm_rules, main_rules=_DENY):
    return _site(configuration={"properties": {"ipSecurityRestrictions": main_rules, "ipSecurityRestrictionsDefaultAction": "Deny",
                                               "scmIpSecurityRestrictions": scm_rules, "scmIpSecurityRestrictionsDefaultAction": "Allow",
                                               "scmIpSecurityRestrictionsUseMain": use_main}})


CASES["azure.htbp.appservice.scm_site_restricted_like_main"] = {
    "pass": _restrictions(True, _ALLOW_ALL), "fail": _restrictions(False, _ALLOW_ALL),
    "not_applicable": _site(configuration={"properties": {"ipSecurityRestrictions": _ALLOW_ALL, "ipSecurityRestrictionsDefaultAction": "Allow"}}),
    "missing": _site(configuration={"properties": {"ipSecurityRestrictions": _DENY, "ipSecurityRestrictionsDefaultAction": "Deny"}}),
    "malformed": _site(configuration={"properties": {"ipSecurityRestrictions": "Any", "ipSecurityRestrictionsDefaultAction": "Deny"}})}


# ---------------------------------------------------------------- Entra service-principal credentials and FICs
@ht_register("azure.htbp.entra.service_principal_no_password_credentials", "azure", "least_privilege", "directory_service_principal",
             "Non-SAML service principal object carries no active password credential", "high", "IA-5",
             "Remove password credentials from the service principal object (they are not shown with the app registration) and "
             "enable app instance property lock; issue credentials on the owning app registration or use managed/federated identity.",
             pages=[PRIV + "az-entraid-privesc/README.md"])
def sp_passwords(item, index):
    get(item, "id", str)
    credentials = list_of_objects(get(item, "passwordCredentials", list))
    if optional(item, "preferredSingleSignOnMode", None) == "saml":
        return "NOT_APPLICABLE", {"reason": "SAML SSO service principals hold the signing-certificate password credential"}
    if not credentials:
        return "PASS", {"password_credentials": 0}
    now = _snapshot_time(index)
    active = []
    for credential in credentials:
        end = credential.get("endDateTime")
        if end is None or _instant(end, "credential endDateTime") > now:
            active.append({"key_id": credential.get("keyId"), "end": end})
    return result(bool(active), active_password_credentials=active, app_owner_organization=item.get("appOwnerOrganizationId"),
                  service_principal_type=item.get("servicePrincipalType"))


def _sp(credentials, mode=None):
    return {"id": "sp-1", "appId": "a-1", "servicePrincipalType": "Application", "preferredSingleSignOnMode": mode,
            "passwordCredentials": credentials, "keyCredentials": []}


CASES["azure.htbp.entra.service_principal_no_password_credentials"] = {
    "pass": _sp([]), "fail": _sp([{"keyId": "k", "endDateTime": "2027-01-01T00:00:00Z"}]), "index": _NOW,
    "not_applicable": _sp([{"keyId": "k", "endDateTime": "2027-01-01T00:00:00Z"}], "saml"),
    "missing": {"id": "sp-1", "appId": "a-1"}, "malformed": {"id": "sp-1", "passwordCredentials": ["secret"]}}

GITHUB_ISSUER = "token.actions.githubusercontent.com"
FIC_PAGES = [AZ + "az-basic-information/az-federation-abuse.md", AZ + "az-persistence/az-entraid-persistence.md"]


def _fic_finding(issuer, subject):
    if not isinstance(issuer, str) or not isinstance(subject, str) or not issuer or not subject:
        raise Unavailable("malformed federated identity credential")
    if (urlsplit(issuer).hostname or "").lower() != GITHUB_ISSUER:
        return "NOT_APPLICABLE", {"reason": "issuer is not GitHub Actions", "issuer": issuer}
    parts = subject.split(":")
    pull_request = parts[-1] == "pull_request" and len(parts) >= 2 and parts[-2] != "environment"
    return result(pull_request, issuer=issuer, subject=subject,
                  semantics="sub=repo:<org>/<repo>:pull_request is satisfied by any collaborator's pull-request workflow")


FIC_REMEDIATION = ("Scope the GitHub subject to a protected environment (environment:<name> with required reviewers) or a protected "
                   "branch/tag ref instead of pull_request, so only reviewed workflows can mint Entra tokens for this identity.")


@ht_register("azure.htbp.entra.app_fic_github_not_pull_request", "azure", "least_privilege", "directory_federated_credential",
             "Application federated credential does not trust GitHub pull_request workflows", "high", "IA-5", FIC_REMEDIATION,
             pages=FIC_PAGES)
def app_fic(item, index):
    get(item, "id", str)
    return _fic_finding(get(item, "issuer", str), get(item, "subject", str))


@ht_register("azure.htbp.managed_identity.fic_github_not_pull_request", "azure", "least_privilege", "managed_identity_federated_credential",
             "Managed identity federated credential does not trust GitHub pull_request workflows", "high", "IA-5", FIC_REMEDIATION,
             pages=FIC_PAGES + [AZ + "az-cross-tenant-and-cross-subscription-attacks/cross-tenant-identity-attacks.md"])
def mi_fic(item, index):
    properties = get(item, "properties", dict)
    return _fic_finding(get(properties, "issuer", str), get(properties, "subject", str))


def _app_fic(subject, issuer="https://token.actions.githubusercontent.com"):
    return {"id": "applications/app/federatedIdentityCredentials/f", "issuer": issuer, "subject": subject, "audiences": ["api://AzureADTokenExchange"]}


def _mi_fic(subject, issuer="https://token.actions.githubusercontent.com"):
    return {"id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi/federatedIdentityCredentials/f",
            "properties": {"issuer": issuer, "subject": subject, "audiences": ["api://AzureADTokenExchange"]}}


for _cid, _make in (("azure.htbp.entra.app_fic_github_not_pull_request", _app_fic), ("azure.htbp.managed_identity.fic_github_not_pull_request", _mi_fic)):
    CASES[_cid] = {"pass": _make("repo:org/repo:environment:prod"), "fail": _make("repo:org/repo:pull_request"),
                   "not_applicable": _make("system:serviceaccount:ns:sa", "https://eastus.oic.prod-aks.azure.com/t/c/"),
                   "missing": {"id": "x"}, "malformed": _make(["repo:org/repo:pull_request"])}


# ---------------------------------------------------------------- Automation webhooks
@ht_register("azure.htbp.automation.webhook_expiry_bounded", "azure", "hardening", "automation_account",
             "Enabled Automation webhooks expire within one year of the snapshot", "medium", "AC-2",
             "Delete unused webhooks and recreate needed ones with short expiries; a webhook URI is an anonymous trigger that runs "
             "its runbook as the account's identity until it expires.",
             pages=[AZ + "az-persistence/az-automation-accounts-persistence.md", PRIV + "az-automation-accounts-privesc.md"])
def webhook_expiry(item, index):
    hooks = list_of_objects(get(item, "webhooks", list))
    long_lived = []
    now = None
    for hook in hooks:
        properties = get(hook, "properties", dict)
        if not get(properties, "isEnabled", bool):
            continue
        now = now or _snapshot_time(index)
        expiry = properties.get("expiryTime")
        if expiry is None or _instant(expiry, "webhook expiryTime") > now + timedelta(days=365):
            long_lived.append({"name": hook.get("name"), "expiry": expiry, "run_on": properties.get("runOn"),
                               "runbook": (properties.get("runbook") or {}).get("name") if isinstance(properties.get("runbook"), dict) else None})
    return result(bool(long_lived), long_lived_webhooks=long_lived, webhooks=len(hooks))


def _account(*hooks):
    return {"id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Automation/automationAccounts/a", "name": "a", "properties": {},
            "webhooks": [{"id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Automation/automationAccounts/a/webhooks/h" + str(n), "name": "h" + str(n),
                          "properties": {"isEnabled": enabled, "expiryTime": expiry, "runbook": {"name": "rb"}}} for n, (enabled, expiry) in enumerate(hooks)]}


CASES["azure.htbp.automation.webhook_expiry_bounded"] = {
    "pass": _account((True, "2027-01-01T00:00:00+00:00"), (False, "2036-01-01T00:00:00+00:00")),
    "fail": _account((True, "2036-01-01T00:00:00+00:00")), "index": _NOW,
    "missing": {"id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Automation/automationAccounts/a", "properties": {}},
    "malformed": {"id": "a", "properties": {}, "webhooks": [{"name": "h", "properties": {"isEnabled": "yes"}}]}}


# ---------------------------------------------------------------- Synapse workspace firewall
@ht_register("azure.htbp.synapse.firewall_no_allow_all_internet", "azure", "network", "synapse_workspace",
             "Synapse workspace IP firewall has no Internet-wide allow rule", "high", "SC-7",
             "Remove 0.0.0.0-255.255.255.255 (AllowAll) firewall rules and allow only specific client ranges, or disable public "
             "network access and use private endpoints.",
             pages=[PRIV + "az-synapse-privesc.md"])
def synapse_allow_all(item, index):
    properties = get(item, "properties", dict)
    if optional(properties, "publicNetworkAccess", None) == "Disabled":
        return "NOT_APPLICABLE", {"reason": "public network access disabled"}
    wide = []
    for rule in list_of_objects(get(item, "firewallRules", list)):
        try:
            start = ipaddress.IPv4Address(get(rule, "properties.startIpAddress", str))
            end = ipaddress.IPv4Address(get(rule, "properties.endIpAddress", str))
        except ValueError:
            raise Unavailable("malformed firewall rule address")
        if int(start) > int(end):
            raise Unavailable("reversed firewall address range")
        # 0.0.0.0-0.0.0.0 is the "Allow Azure services" rule; anything spanning
        # at least half of the IPv4 space is treated as Internet-wide.
        if int(end) - int(start) + 1 >= 2 ** 31:
            wide.append({"name": rule.get("name"), "start": str(start), "end": str(end)})
    return result(bool(wide), internet_wide_rules=wide,
                  semantics="A rule spanning half or more of the IPv4 space admits essentially the whole Internet")


def _synapse(*ranges):
    rid = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Synapse/workspaces/ws"
    return {"id": rid, "properties": {"publicNetworkAccess": "Enabled"}, "firewallRules": [
        {"id": rid + "/firewallRules/r" + str(n), "name": "r" + str(n), "properties": {"startIpAddress": start, "endIpAddress": end}}
        for n, (start, end) in enumerate(ranges)]}


CASES["azure.htbp.synapse.firewall_no_allow_all_internet"] = {
    "pass": _synapse(("0.0.0.0", "0.0.0.0"), ("203.0.113.1", "203.0.113.9")), "fail": _synapse(("0.0.0.0", "255.255.255.255")),
    "missing": {"id": "ws", "properties": {}}, "malformed": {"id": "ws", "properties": {}, "firewallRules": [{"properties": {"startIpAddress": 0}}]}}
