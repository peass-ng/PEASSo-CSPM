"""Differential source CASE fixtures and native read-only service boundaries."""
from peaso.checks.hacktricks_scope import includes
import copy
import json
from urllib.parse import urlsplit
from pathlib import Path
import re

import pytest

from peaso.checks import CHECKS, HACKTRICKS, azure_ports_services as ports
from peaso.checks.fixtures import CASES
from peaso.collectors.azure import collect, ENDPOINTS, ARM
from peaso.collectors.azure import _metadata_only
from peaso.collectors.azure import _Reader, AzureReadError

REGISTRY = {check.id: check for check in CHECKS}
REVIEWS = json.loads((Path(__file__).resolve().parent.parent / "peaso/rulepacks/reviewed_azure_ports_services.json").read_text())
SOURCE_CASES = {row["source_review"]["query_id"]: row["source_review"]["status_case_sql"] for row in REVIEWS.values()}

# Independently stated source-table columns (including source join outcomes).
# These fixtures preserve the actual pinned CASE branch rather than merely
# asserting a broad title such as "private networking" or "managed identity".
ORACLES = {
    "redis_cache_ssl_enabled": ({"enable_non_ssl_port": False}, {"enable_non_ssl_port": True}),
    "redis_cache_min_tls_1_2": ({"minimum_tls_version": "1.2"}, {"minimum_tls_version": "1.1"}),
    "redis_cache_no_basic_sku": ({"sku_name": "Standard"}, {"sku_name": "Basic"}),
    "redis_cache_in_virtual_network": ({"subnet_id": "/subnet"}, {"subnet_id": None}),
    "redis_cache_uses_private_link": ({"source_join_id": "matched-approved-connection"}, {"source_join_id": None}),
    "cognitive_service_local_auth_disabled": ({"disable_local_auth": True}, {"disable_local_auth": False}),
    "cognitive_account_public_network_access_disabled": ({"public_network_access": "Disabled"}, {"public_network_access": "Enabled"}),
    "cognitive_account_restrict_public_access": ({"source_join_id": None}, {"source_join_id": "VirtualNetworks-with-Allow"}),
    "cognitive_account_encrypted_with_cmk": ({"source_join_id": "CMK-capability", "encryption": {"keySource": "Microsoft.KeyVault"}}, {"source_join_id": "CMK-capability", "encryption": {"keySource": "Microsoft.CognitiveServices"}}),
    "cognitive_account_private_link_used": ({"private_endpoint_connections": [{}], "source_join_id": "network-capability-and-approved"}, {"private_endpoint_connections": [{}], "source_join_id": None}),
    "app_configuration_private_link_used": ({"sku_name": "standard", "public_network_access": "Enabled", "private_endpoint_connections": [{"privateLinkServiceConnectionStateStatus": "Approved"}]}, {"sku_name": "standard", "public_network_access": "Enabled", "private_endpoint_connections": []}),
    "app_configuration_sku_standard": ({"sku_name": "standard"}, {"sku_name": "free"}),
    "app_configuration_encryption_enabled": ({"encryption": {"keyVaultProperties": {"keyIdentifier": "https://vault/keys/key"}}}, {"encryption": {"keyVaultProperties": {"keyIdentifier": None}}}),
    "data_factory_public_network_access_disabled": ({"public_network_access": "Disabled"}, {"public_network_access": "Enabled"}),
    "data_factory_encrypted_with_cmk": ({"encryption": {"vaultBaseUrl": "https://vault"}}, {"encryption": {"vaultBaseUrl": None}}),
    "data_factory_uses_git_repository": ({"repo_configuration": {"repositoryName": "source-control"}}, {"repo_configuration": {"repositoryName": None}}),
    "data_factory_uses_private_link": ({"source_join_id": "approved"}, {"source_join_id": None}),
    "apimanagement_service_with_virtual_network": ({"virtual_network_type": "External"}, {"virtual_network_type": "None"}),
    "search_service_public_network_access_disabled": ({"public_network_access": "Disabled"}, {"public_network_access": "Enabled"}),
    "search_service_uses_private_link": ({"source_join_id": "approved"}, {"source_join_id": None}),
    "search_service_uses_managed_identity": ({"identity": {"type": "SystemAssigned"}}, {"identity": {"type": "SystemAssigned, UserAssigned"}}),
    "search_service_uses_sku_supporting_private_link": ({"sku_name": "basic"}, {"sku_name": "free"}),
}


def source_status(query, columns):
    """Execute only the reviewed source CASE against one in-memory truth row."""
    duckdb = pytest.importorskip("duckdb")
    case = SOURCE_CASES[query]
    case = re.sub(r"--[^\n]*", "", case)
    case = re.sub(r"\b[a-z]+\.id\b", "source_join_id", case)
    case = re.sub(r"\b[a-z]+\.(\w+)\b", r"\1", case)
    case = case.replace("jsonb_array_length", "json_array_length")
    case = re.sub(r"(\w+)\s*@>\s*('(?:[^']*)')::jsonb", r"json_contains(\1, \2)", case)
    case = re.sub(r"(\w+(?:\s*->>?\s*'[^']+')+)\s+(is\s+not\s+null|=)", r"(\1) \2", case, flags=re.I)
    values = []
    names = []
    for name, value in columns.items():
        assert re.fullmatch(r"[a-z_]+", name)
        names.append("?" + ("::JSON" if isinstance(value, (dict, list)) else "") + " AS " + name)
        values.append(json.dumps(value) if isinstance(value, (dict, list)) else value)
    with duckdb.connect(":memory:") as database:
        return database.execute("SELECT " + case + " FROM (SELECT " + ",".join(names) + ")", values).fetchone()[0]


@pytest.mark.parametrize("query", ports.SOURCE_QUERIES, ids=str)
def test_source_case_truth_matches_native_pass_and_fail(query):
    cid = ports.SOURCE_QUERIES[query]
    assert query in ORACLES
    for case_index, (label, native_status, sql_status) in enumerate((("pass", "PASS", "ok"), ("fail", "FAIL", "alarm"))):
        assert source_status(query, ORACLES[query][case_index]) == sql_status
        item = copy.deepcopy(CASES[cid][label])
        original = copy.deepcopy(item)
        assert REGISTRY[cid].evaluate(item, {})[0] == native_status
        assert item == original


@pytest.mark.parametrize("cid", ports.CHECK_IDS, ids=str)
def test_missing_denied_malformed_are_unknown_and_framework_is_present(cid):
    check = REGISTRY[cid]
    for item in ({}, None, [], "malformed", {"collection_status": "denied"}):
        assert check.evaluate(item, {})[0] == "UNKNOWN"
    passing = copy.deepcopy(CASES[cid]["pass"])
    passing["collection_status"] = "partial"
    assert check.evaluate(passing, {})[0] == "UNKNOWN"
    assert (HACKTRICKS in check.frameworks) == includes(check.id)
    assert check.dependencies == [check.kind]


def test_cognitive_private_zero_connections_preserves_info_not_success():
    query = "cognitive_account_private_link_used"
    assert source_status(query, {"private_endpoint_connections": [], "source_join_id": None}) == "info"
    assert REGISTRY[ports.SOURCE_QUERIES[query]].evaluate({"properties": {"privateEndpointConnections": []}}, {})[0] == "MANUAL"


def test_app_configuration_free_sku_is_inapplicable_even_with_missing_network_facts():
    query = "app_configuration_private_link_used"
    assert source_status(query, {"sku_name": "free", "public_network_access": None, "private_endpoint_connections": None}) == "skip"
    assert REGISTRY[ports.SOURCE_QUERIES[query]].evaluate({"sku": {"name": "free"}}, {})[0] == "NOT_APPLICABLE"


def test_cognitive_capability_exemptions_are_explicit_source_branches():
    assert source_status("cognitive_account_encrypted_with_cmk", {"source_join_id": None, "encryption": None}) == "ok"
    item = {"properties": {"capabilities": []}}
    for query in ("cognitive_account_encrypted_with_cmk", "cognitive_account_restrict_public_access"):
        status, evidence = REGISTRY[ports.SOURCE_QUERIES[query]].evaluate(item, {})
        assert status == "PASS"
        assert "upstream does not alarm" in evidence["source_predicate"]
    assert REGISTRY[ports.SOURCE_QUERIES["cognitive_account_encrypted_with_cmk"]].evaluate({"properties": {}}, {})[0] == "UNKNOWN"


def test_scalar_enum_and_boolean_malformed_inputs_do_not_become_safe():
    assert REGISTRY[ports.SOURCE_QUERIES["redis_cache_ssl_enabled"]].evaluate({"properties": {"enableNonSslPort": "false"}}, {})[0] == "UNKNOWN"
    assert REGISTRY[ports.SOURCE_QUERIES["redis_cache_min_tls_1_2"]].evaluate({"properties": {"minimumTlsVersion": "future"}}, {})[0] == "UNKNOWN"
    assert REGISTRY[ports.SOURCE_QUERIES["search_service_uses_managed_identity"]].evaluate({"identity": {"type": "future"}}, {})[0] == "UNKNOWN"


class ServiceApi:
    tenant = "tenant"

    def __init__(self, kind):
        self.kind = kind
        self.calls = []

    def request(self, url, body=None, audience=ARM):
        self.calls.append((url, body))
        if body:
            return {"data": []}
        endpoint = ENDPOINTS[self.kind][0]
        rid = "/subscriptions/sub/resourceGroups/group/providers/" + endpoint + "/resource"
        row = {"id": rid, "type": endpoint, "name": "resource", "properties": {"publicNetworkAccess": "Disabled", "apiProperties": {"storageAccountConnectionString": "secret"}, "globalParameters": {"PASSWORD": {"value": "secret"}}, "redisConfiguration": {"rdb-storage-connection-string": "secret"}}}
        path = urlsplit(url).path
        if path == rid:
            return row
        if path.startswith(rid + "/"):
            return {"value": []}
        return {"value": [row]}


# App Configuration list rows get a native detail GET plus Event Grid and NSP child reads.
EXPECTED_CALLS = {"app_configuration": 5}


@pytest.mark.parametrize("kind", ["redis_cache", "cognitive_account", "app_configuration", "data_factory", "api_management", "search_service"])
def test_new_service_collection_is_authoritative_bounded_and_contains_no_sensitive_settings(kind):
    api = ServiceApi(kind)
    calls = EXPECTED_CALLS.get(kind, 2)
    snapshot = collect({"scopes": ["sub"], "options": {"max_calls": calls, "retries": 0}}, [kind], transport=api)
    service = next(row for row in snapshot["collections"] if row["type"] == kind)
    assert service["status"] == "collected"
    assert snapshot["metadata"]["calls"] == calls
    assert service["items"][0]["properties"]["publicNetworkAccess"] == "Disabled"
    assert '"secret"' not in json.dumps(snapshot)
    assert all(not any(term in url.lower() for term in ("listkeys", "/secrets/", "linkedservices", "globalparameters")) for url, _ in api.calls)


def test_manual_only_source_rows_are_separate_and_never_supported_wrappers():
    root = Path(__file__).resolve().parent.parent
    manual = json.loads((root / "peaso/rulepacks/reviewed_azure_ports_manual.json").read_text())
    assigned = set(json.loads((root / "peaso/rulepacks/port_partitions.json").read_text())["partitions"]["azure"]["check_ids"])
    assert len(manual) == 412
    assert set(manual) <= assigned
    for cid, row in manual.items():
        assert row["disposition"] == "rejected" and row["native_checks"] == []
        assert row["review_classification"] == "manual_attestation"
        assert row["manual_requirement"]["question"]
        assert row["source_review"]["constant_source_status"] == "info"
        assert row["source_review"]["condition"] == "none"


def test_credential_tag_keys_and_redaction_status_remain_but_literals_do_not():
    marker = "INERT_QA_MARKER_NOT_A_REAL_SECRET"
    payload = {"tags": {"api_token": marker, "client-secret": marker, "Name": "resource", "HttpTokens": "required"}, "properties": {"HttpTokens": "required"}}
    safe = _metadata_only(payload)
    assert marker not in json.dumps(safe)
    assert set(safe["tags"]) == set(payload["tags"])
    assert safe["tags"]["api_token"] == "[REDACTED]"
    assert safe["tags"]["Name"] == "resource"
    assert safe["tags"]["HttpTokens"] == safe["properties"]["HttpTokens"] == "required"
    assert safe["_redacted_metadata"]["tags"] == [{"key": "api_token", "status": "redacted"}, {"key": "client-secret", "status": "redacted"}]


def test_default_reader_has_no_implicit_call_page_or_resource_caps():
    reader = _Reader({"concurrency": 2, "retries": 0})
    assert reader.budget.max_calls is reader.budget.max_pages is reader.budget.max_items is None
    for _ in range(205):
        reader.call(lambda: {})
    reader.run([("metadata", "scope", "test", lambda: iter([[{"id": "record-" + str(i)} for i in range(10005)]]))])
    assert reader.collections[0]["status"] == "collected"
    assert len(reader.collections[0]["items"]) == 10005
    assert reader.metadata()["explicit_limits"] == {}
    assert not reader.metadata()["intentional_partial"]


def test_default_subscription_discovery_passes_old_page_and_scope_caps():
    calls = []
    class FullSubscriptions:
        tenant = "tenant"
        def request(self, url, body=None, audience=ARM):
            calls.append(url)
            page = int(url.rsplit("page=", 1)[-1]) if "page=" in url else 0
            records = [{"id": "/subscriptions/sub-" + str(page * 10 + offset), "subscriptionId": "sub-" + str(page * 10 + offset)} for offset in range(10)]
            result = {"value": records}
            if page < 11:
                result["nextLink"] = ARM + "/subscriptions?api-version=2022-12-01&page=" + str(page + 1)
            return result
    snapshot = collect({"scopes": ["*"]}, ["subscription"], transport=FullSubscriptions())
    assert len(snapshot["scopes"]) == 120
    assert len(calls) == 12
    assert snapshot["collections"][0]["status"] == "collected"
    assert not snapshot["metadata"]["intentional_partial"]


def test_explicit_scope_limit_is_reported_as_intentional_partial():
    class Scopes:
        tenant = "tenant"
        def request(self, url, body=None, audience=ARM):
            return {"value": [{"id": "/subscriptions/sub-" + str(i), "subscriptionId": "sub-" + str(i)} for i in range(3)]}
    snapshot = collect({"scopes": ["*"], "options": {"max_scopes": 2}}, ["subscription"], transport=Scopes())
    assert len(snapshot["scopes"]) == 2
    assert snapshot["collections"][0]["status"] == "partial"
    assert snapshot["metadata"]["intentional_partial"]
    assert snapshot["metadata"]["explicit_limits"] == {"max_scopes": 2}


def test_cancel_hook_prevents_another_read_without_synthetic_budget_limits():
    cancelled = [False]
    reader = _Reader({"_cancel_check": lambda: cancelled[0]})
    assert reader.call(lambda: "read") == "read"
    cancelled[0] = True
    with pytest.raises(AzureReadError, match="collection_cancelled"):
        reader.call(lambda: pytest.fail("cancelled read must not run"))
    assert reader.budget.calls == 1


def test_core_cancel_event_is_honored_for_cached_reads():
    import threading
    event = threading.Event()
    reader = _Reader({"cancel_event": event})
    event.set()
    reader.run([("metadata", "scope", "test", lambda: iter([[{"id": "cached"}]]))])
    assert reader.collections[0]["status"] == "partial"
    assert reader.collections[0]["items"] == []
    assert reader.metadata()["intentional_partial"]


class DirectoryApi:
    tenant = "tenant-a"

    def __init__(self):
        self.calls = []

    def request(self, url, body=None, audience=ARM):
        self.calls.append((url, audience))
        if body:
            return {"data": []}
        if audience != "https://graph.microsoft.com":
            return {"value": []}
        path = url.split("?", 1)[0]
        if path.endswith("/servicePrincipals"):
            return {"value": [{"id": "caller", "appRoles": []}, {"id": "resource", "appRoles": [{"id": "role-read", "value": "Read.Metadata", "isEnabled": True}]}]}
        if path.endswith("/caller/appRoleAssignments"):
            return {"value": [{"id": "assignment", "principalId": "caller", "resourceId": "resource", "appRoleId": "role-read"}]}
        if path.endswith("/resource/appRoleAssignments"):
            return {"value": []}
        if path.endswith("/applications"):
            return {"value": [{"id": "application", "signInAudience": "AzureADMyOrg"}]}
        if path.endswith("/groups"):
            return {"value": [{"id": "group", "isAssignableToRole": True, "membershipRule": None}]}
        if path.endswith("/owners"):
            return {"value": [{"id": "owner"}]}
        if path.endswith("/authorizationPolicy"):
            return {"id": "authorizationPolicy", "allowInvitesFrom": "adminsAndGuestInviters", "guestUserRoleId": "guest-role"}
        if path.endswith("/administrativeUnits"):
            return {"value": [{"id": "unit", "isMemberManagementRestricted": True}]}
        if path.endswith("/administrativeUnits/unit/members"):
            return {"value": [{"id": "member"}]}
        if path.endswith("/domains"):
            return {"value": [{"id": "example.test", "authenticationType": "Managed", "isVerified": True}]}
        if path.endswith("/roleEligibilitySchedules"):
            return {"value": [{"id": "eligibility", "principalId": "caller", "roleDefinitionId": "definition", "directoryScopeId": "/"}]}
        raise AssertionError("Unreviewed directory endpoint: " + url)


def test_defensive_directory_facts_are_scoped_and_app_role_value_comes_from_resource_sp():
    api = DirectoryApi()
    wanted = ["directory_app_role_assignment", "directory_owner", "directory_authorization_policy", "directory_administrative_unit_member", "directory_domain", "directory_role_eligibility_schedule"]
    snapshot = collect({"scopes": ["sub"]}, wanted, transport=api)
    assigned = next(row for row in snapshot["collections"] if row["type"] == "directory_app_role_assignment" and row["items"])
    fact = assigned["items"][0]
    assert fact["appRoleValue"] == "Read.Metadata"
    assert fact["principalId"] == "caller" and fact["resourceId"] == "resource"
    assert fact["_provenance"]["tenant_id"] == "tenant-a"
    assert fact["_provenance"]["effective_access"] == "not_computed"
    owners = [row for row in snapshot["collections"] if row["type"] == "directory_owner"]
    assert len(owners) == 4
    assert all(row["items"][0]["ownerIds"] == ["owner"] for row in owners)
    assert {row["items"][0]["objectType"] for row in owners} == {"application", "servicePrincipal", "group"}
    policy = next(row for row in snapshot["collections"] if row["type"] == "directory_authorization_policy")
    assert policy["items"][0]["allowInvitesFrom"] == "adminsAndGuestInviters"
    members = next(row for row in snapshot["collections"] if row["type"] == "directory_administrative_unit_member")
    assert members["items"][0]["administrativeUnitId"] == "unit"
    assert all(not any(term in url for term in ("addPassword", "addKey", "getPassword", "secretText")) for url, _ in api.calls)


def test_app_role_value_denial_is_unknown_enrichment_not_an_invented_permission():
    class DeniedResource(DirectoryApi):
        def request(self, url, body=None, audience=ARM):
            if url.split("?", 1)[0].endswith("/servicePrincipals"):
                return {"value": [{"id": "caller", "appRoles": []}]}
            if url.split("?", 1)[0].endswith("/servicePrincipals/resource"):
                raise AzureReadError("403", 403)
            return super().request(url, body, audience)
    snapshot = collect({"scopes": ["sub"]}, ["directory_app_role_assignment"], transport=DeniedResource())
    fact = next(row for row in snapshot["collections"] if row["type"] == "directory_app_role_assignment")["items"][0]
    assert "appRoleValue" not in fact
    assert fact["_coverage"]["appRoleValue"]["status"] == "denied"


def test_graph_only_portable_token_never_constructs_ambient_arm_credentials(monkeypatch):
    from peaso.collectors import azure
    monkeypatch.setattr(azure, "credential_for", lambda *_: pytest.fail("Graph-only portable auth must not fall back to an ARM identity"))
    transport = azure.AzureTransport({"method": "token", "graph_token": "opaque-graph-token"})
    assert transport.token("https://graph.microsoft.com") == "opaque-graph-token"
    with pytest.raises(AzureReadError, match="audience_token_unavailable"):
        transport.token(ARM)


def test_managed_identity_federation_metadata_preserves_issuer_subject_audiences():
    identity = "/subscriptions/sub/resourceGroups/g/providers/Microsoft.ManagedIdentity/userAssignedIdentities/identity"
    class FederatedApi:
        tenant = "tenant-a"
        def request(self, url, body=None, audience=ARM):
            if body:
                assert "identity" in body["query"]
                return {"data": []}
            if "/federatedIdentityCredentials?" in url:
                return {"value": [{"id": identity + "/federatedIdentityCredentials/credential", "properties": {"issuer": "https://issuer.example", "subject": "service-account", "audiences": ["api://AzureADTokenExchange"]}}]}
            return {"value": [{"id": identity, "properties": {"principalId": "principal", "clientId": "client"}}]}
    snapshot = collect({"scopes": ["sub"]}, ["managed_identity_federated_credential"], transport=FederatedApi())
    collection = next(row for row in snapshot["collections"] if row["type"] == "managed_identity_federated_credential")
    assert collection["status"] == "collected"
    assert collection["items"][0]["properties"]["issuer"] == "https://issuer.example"


@pytest.mark.parametrize("mode,expected", [("empty", "empty"), ("denied", "denied")])
def test_managed_identity_federation_complete_empty_and_denied_are_distinct(mode, expected):
    identity = "/subscriptions/sub/resourceGroups/g/providers/Microsoft.ManagedIdentity/userAssignedIdentities/identity"
    calls = []
    class FederatedApi:
        tenant = "tenant-a"
        def request(self, url, body=None, audience=ARM):
            calls.append((url, body))
            if body:
                return {"data": []}
            if "/federatedIdentityCredentials?" in url:
                if mode == "denied":
                    raise AzureReadError("403", 403)
                return {"value": []}
            return {"value": [{"id": identity, "properties": {"principalId": "principal"}}]}
    snapshot = collect({"scopes": ["sub"]}, ["managed_identity_federated_credential"], transport=FederatedApi())
    collection = next(row for row in snapshot["collections"] if row["type"] == "managed_identity_federated_credential")
    assert collection["status"] == expected and collection["items"] == []
    if mode == "denied":
        assert collection["error"]["code"] == "403"
    assert all(not any(operation in url.lower() for operation in ("create", "update", "listkeys", "secrets")) for url, _ in calls)


@pytest.mark.parametrize("denied", [False, True])
def test_service_principal_observed_first_party_fields_selected_and_retained_without_inference(denied):
    calls = []
    class Principals:
        tenant = "tenant"
        def request(self, url, body=None, audience=None):
            calls.append(url)
            assert audience == "https://graph.microsoft.com"
            selected = url.split("$select=", 1)[1].split(",")
            assert {"appOwnerOrganizationId", "servicePrincipalType", "appId"} <= set(selected)
            if denied:
                raise AzureReadError("403", 403)
            return {"value": [{"id": "principal", "appId": "observed-app", "appOwnerOrganizationId": "observed-owner-org", "servicePrincipalType": "Application"}]}
    snapshot = collect({"scopes": ["sub"]}, ["directory_service_principal"], transport=Principals())
    row = next(item for item in snapshot["collections"] if item["type"] == "directory_service_principal")
    assert len(calls) == 1
    if denied:
        assert row["status"] == "denied" and row["items"] == []
    else:
        assert row["status"] == "collected"
        assert {key: row["items"][0][key] for key in ("id", "appId", "appOwnerOrganizationId", "servicePrincipalType")} == {"id": "principal", "appId": "observed-app", "appOwnerOrganizationId": "observed-owner-org", "servicePrincipalType": "Application"}
        assert row["items"][0]["_provenance"]["tenant_id"] == "tenant"
        assert row["items"][0]["_provenance"]["tenant_verified"] is False
        assert "first_party" not in row["items"][0]
