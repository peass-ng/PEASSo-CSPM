"""Full-default collection regressions use fixtures beyond former hidden caps."""
import threading
from types import SimpleNamespace

from peaso.collectors.gcp import GCPCollector, Transport, Credentials
from tests.test_peaso_collectors_gcp import FixtureTransport, connector, collection


def test_extended_fact_hydration_projects_native_metadata_with_exact_read_requests():
    requests = []
    def resolve(request):
        requests.append(request)
        url, params = request["url"], request.get("params") or {}
        if url.endswith("/metrics"):
            assert params["fields"] == "metrics(name,filter,disabled,bucketName,labelExtractors,metricDescriptor(type,metricKind,valueType)),nextPageToken"
            return {"metrics": [{"name": "event", "filter": 'resource.type="gcs_bucket" AND protoPayload.methodName="storage.setIamPermissions"', "metricDescriptor": {"type": "logging.googleapis.com/user/event", "metricKind": "DELTA", "valueType": "INT64"}}]}
        if url.endswith("/alertPolicies"):
            assert "documentation" not in params["fields"] and "conditions" in params["fields"]
            return {"alertPolicies": [{"name": "projects/p-one/alertPolicies/a", "enabled": True, "conditions": [{"conditionThreshold": {"filter": 'metric.type="logging.googleapis.com/user/event" resource.type="gcs_bucket"', "comparison": "COMPARISON_GT", "thresholdValue": 0, "duration": "0s"}}]}]}
        if "serviceusage.googleapis.com" in url:
            assert request["method"] == "GET"
            assert url == "https://serviceusage.googleapis.com/v1/projects/p-one/services"
            assert params["pageSize"] == 200
            return {"services": [{"name": "projects/p-one/services/compute.googleapis.com", "state": "ENABLED"}]}
        if "alloydb.googleapis.com" in url and url.endswith("/clusters"):
            assert "initialUser" not in params["fields"]
            return {"clusters": [{"name": "projects/p-one/locations/r/clusters/c", "encryptionInfo": {"encryptionType": "CUSTOMER_MANAGED_ENCRYPTION"}}]}
        if "alloydb.googleapis.com" in url and url.endswith("/instances"):
            assert "databaseFlags" in params["fields"] and "password" not in params["fields"]
            return {"instances": [{"name": "projects/p-one/locations/r/clusters/c/instances/i", "databaseFlags": {"log_min_messages": "error"}}]}
        if "essentialcontacts.googleapis.com" in url:
            return {"contacts": [{"name": "projects/p-one/contacts/c", "notificationCategorySubscriptions": ["ALL"]}]}
        if "accessapproval.googleapis.com" in url:
            assert "enrolledServices" in params["fields"]
            return {"name": "projects/p-one/accessApprovalSettings", "enrolledServices": [{"cloudProduct": "all", "enrollmentLevel": "BLOCK_ALL"}]}
        if url.endswith("/billingInfo"):
            return {"name": "projects/p-one/billingInfo", "projectId": "p-one", "billingAccountName": "billingAccounts/000000-000000-000000"}
        if "cloudbilling.googleapis.com" in url and not url.endswith(":getIamPolicy"):
            return {"name": "billingAccounts/000000-000000-000000", "open": True}
        if "bigtableadmin.googleapis.com" in url and url.endswith("/instances"):
            return {"instances": [{"name": "projects/p-one/instances/i", "state": "READY"}]}
        if "run.googleapis.com" in url and url.endswith("/jobs"):
            return {"jobs": [{"name": "projects/p-one/locations/r/jobs/j"}]}
        if url.endswith(":getIamPolicy"):
            if "bigtableadmin" in url:
                assert request["method"] == "POST" and request["body"] == {"options": {"requestedPolicyVersion": 3}}
            else:
                assert request["method"] == "GET" and params["options.requestedPolicyVersion"] == 3
            return {}  # Successful omitted IAM repeated bindings is known empty.
        raise AssertionError("unexpected API request " + url)
    kinds = ["logging_metric", "monitoring_alert_policy", "service_usage", "alloydb_cluster", "alloydb_instance", "essential_contact", "access_approval_settings", "billing_account", "bigtable_instance", "cloudrun_job"]
    reader = FixtureTransport(resolve)
    snapshot = GCPCollector(connector(kinds, alloydb_locations=["r"], cloudrun_locations=["r"]), transport=reader).collect()
    assert all(collection(snapshot, kind)["status"] == "collected" for kind in kinds)
    assert collection(snapshot, "logging_metric")["items"][0]["name"] == "projects/p-one/metrics/event"
    for kind in ("bigtable_instance", "billing_account", "cloudrun_job"):
        assert collection(snapshot, kind)["items"][0]["iamPolicy"] == {"bindings": []}
    assert not any(":enable" in request["url"] or "/tabledata" in request["url"] for request in requests)
    assert all(request["method"] == "GET" or request["url"].endswith(":getIamPolicy") for request in requests)
    # Evaluate the actual native metric/alert configuration with only pure checks.
    from peaso.checks import CHECKS, gcp_ports_logging
    from peaso.snapshot import resources
    cid = gcp_ports_logging.REFERENCE_SPECS["logging_metric_alert_storage_iam_permission_changes"]
    check = next(check for check in CHECKS if check.id == cid)
    index = {kind: [row for row in resources(snapshot) if row["type"] == kind] for kind in ("logging_metric", "monitoring_alert_policy")}
    index["collections"] = {kind: [collection(snapshot, kind)] for kind in index}
    assert check.evaluate({"projectId": "p-one"}, index)[0] == "PASS"


def test_partial_bigtable_locations_and_denied_billing_policy_preserve_gaps():
    from peaso.collectors.gcp import ReadError
    def resolve(request):
        url = request["url"]
        if "bigtableadmin" in url and url.endswith("/instances"):
            return {"instances": [{"name": "projects/p-one/instances/i"}], "failedLocations": ["unreachable-region"]}
        if url.endswith("/billingInfo"):
            return {"billingAccountName": "billingAccounts/000000-000000-000000"}
        if "cloudbilling" in url and url.endswith(":getIamPolicy"):
            raise ReadError("denied", "api_error", http_status=403, reason="IAM_PERMISSION_DENIED")
        if "cloudbilling" in url:
            return {"name": "billingAccounts/000000-000000-000000"}
        if url.endswith(":getIamPolicy"):
            return {}
        return {}
    reader = FixtureTransport(resolve)
    snapshot = GCPCollector(connector(["bigtable_instance", "billing_account"]), transport=reader).collect()
    assert collection(snapshot, "bigtable_instance")["status"] == "partial"
    assert collection(snapshot, "bigtable_instance")["error"]["code"] == "unreachable_locations"
    billing = collection(snapshot, "billing_account")["items"][0]
    assert billing["_coverage"]["iamPolicy"]["status"] == "denied"
    assert billing["_coverage"]["iamPolicy"]["error"]["http_status"] == 403
    assert all(request["method"] in ("GET", "POST") for request in reader.requests)


def test_builtin_role_definitions_remain_available_in_each_referencing_project():
    def resolve(request):
        url = request["url"]
        if "cloudresourcemanager" in url and url.endswith(":getIamPolicy"):
            return {"bindings": [{"role": "roles/viewer", "members": ["user:reviewer@example.com"]}]}
        if url.endswith("/roles/viewer"):
            return {"name": "roles/viewer", "includedPermissions": ["compute.instances.get"]}
        if url.endswith("/projects/p-one") and "cloudresourcemanager" in url:
            return {"name": "projects/123", "projectId": "p-one"}
        if url.endswith("/projects/p-two") and "cloudresourcemanager" in url:
            return {"name": "projects/456", "projectId": "p-two"}
        return {"roles": [], "results": []}
    reader = FixtureTransport(resolve)
    snapshot = GCPCollector(connector(["iam_policy", "iam_role"], scopes=["projects/p-one", "projects/p-two"]), transport=reader).collect()
    # fe3de60a reads a referenced role once per scan and keeps one definition in
    # the snapshot; the engine index is snapshot-wide, so both projects' bindings
    # resolve against it (see test_referenced_external_owner_role_is_read_once...).
    for scope in snapshot["scopes"]:
        assert collection(snapshot, "iam_role", scope)["status"] in ("collected", "empty")
    viewer = [row for envelope in snapshot["collections"] if envelope["type"] == "iam_role"
              for row in envelope["items"] if row.get("name") == "roles/viewer"]
    assert len(viewer) == 1 and viewer[0]["includedPermissions"] == ["compute.instances.get"]
    assert viewer[0]["_provenance"]["scope"] in snapshot["scopes"]
    assert sum(request["url"].endswith("/roles/viewer") for request in reader.requests) == 1
    assert all(request["url"].endswith("/roles/viewer") for request in reader.requests if "/v1/roles/" in request["url"])


def test_progress_callback_is_transient_and_settles_denied_inventories_without_payload():
    import json
    from peaso.collectors.gcp import ReadError
    events = []
    def resolve(request):
        if request["url"].endswith("/firewalls"):
            raise ReadError("denied", "api_error", http_status=403)
        return {"items": [{"name": "n", "description": "fixture-private-inventory-marker"}]}
    request = connector(["network", "firewall"], _progress_callback=events.append)
    snapshot = GCPCollector(request, transport=FixtureTransport(resolve)).collect()
    assert events[-1]["completed"] == 2 and events[-1]["total"] == 2 and events[-1]["resources"] == 1
    assert events[-1]["dynamic_total"] is False and events[-1]["phase"] == "completed"
    assert [event["completed"] for event in events] == sorted(event["completed"] for event in events)
    assert "fixture-private-inventory-marker" not in json.dumps(events)
    assert "_progress_callback" not in json.dumps(snapshot)
    assert callable(request["options"]["_progress_callback"])


def test_serviceaccount_policy_uses_official_read_only_post_empty_body_and_v3_query():
    def resolve(request):
        if request["url"].endswith("/serviceAccounts"):
            return {"accounts": [{"name": "projects/p-one/serviceAccounts/sa@p-one.iam.gserviceaccount.com", "email": "sa@p-one.iam.gserviceaccount.com"}]}
        assert request["url"].endswith(":getIamPolicy")
        assert request["method"] == "POST" and request["body"] is None
        assert request["params"] == {"options.requestedPolicyVersion": 3}
        return {"version": 3, "bindings": [{"role": "roles/viewer", "members": ["user:reviewer@example.com"], "condition": {"expression": "request.time < timestamp('2027-01-01T00:00:00Z')"}}]}
    snapshot = GCPCollector(connector(["service_account"]), transport=FixtureTransport(resolve)).collect()
    account = collection(snapshot, "service_account")["items"][0]
    assert account["_coverage"]["iamPolicy"]["status"] == "collected"
    assert account["iamPolicy"]["version"] == 3 and account["iamPolicy"]["bindings"][0]["condition"]


def test_default_gcp_pagination_exceeds_ten_pages_and_ten_thousand_resources():
    def resolve(request):
        page = int((request.get("params") or {}).get("pageToken", "0"))
        return {"items": [{"name": f"n-{page}-{i}"} for i in range(1000)],
                **({"nextPageToken": str(page + 1)} if page < 10 else {})}
    reader = FixtureTransport(resolve)
    result = GCPCollector(connector(["network"]), transport=reader).collect()
    found = collection(result, "network")
    assert found["status"] == "collected"
    assert len(found["items"]) == 11000
    assert reader.calls == 11
    assert result["metadata"]["max_pages"] is None
    assert result["metadata"]["max_resources"] is None
    assert result["metadata"]["intentional_limits"] == {}


def test_default_transport_exceeds_two_hundred_calls_without_a_cap(monkeypatch):
    credentials = SimpleNamespace(headers=lambda: {}, close=lambda: None)
    transport = Transport(credentials, {})
    session = SimpleNamespace(request=lambda *a, **k: SimpleNamespace(status_code=200, json=lambda: {}))
    monkeypatch.setattr(transport, "_session", lambda: session)
    for index in range(201):
        transport.request("GET", f"https://compute.googleapis.com/compute/v1/projects/p/global/networks/n-{index}")
    assert transport.calls == 201 and transport.max_calls is None


def test_default_discovery_exceeds_a_hundred_scopes_and_selects_all_accessible_projects():
    def resolve(request):
        if request["url"].endswith("projects:search"):
            return {"projects": [{"projectId": f"p-{i}", "name": f"projects/{i}"} for i in range(101)]}
        if request["url"].endswith("organizations:search"):
            return {"organizations": [{"name": "organizations/123"}]}
        if request["url"].endswith("folders:search"):
            return {"folders": [{"name": "folders/456"}]}
        return {"items": []}
    reader = FixtureTransport(resolve)
    result = GCPCollector({"provider": "gcp", "scopes": [], "options": {"inventories": ["network"],
        "include_inherited": False}}, transport=reader).collect()
    assert len(result["metadata"]["resolved_scopes"]) == 103
    assert "projects/p-100" in result["scopes"]
    assert result["metadata"]["max_calls"] is None and result["metadata"]["max_scopes"] is None
    assert not result["metadata"]["scope_coverage"]
    assert all(c.get("error", {}).get("code") not in ("scope_limit", "page_limit", "resource_limit", "call_limit")
               for c in result["collections"])


def test_explicit_opt_in_cap_is_reported_as_intentional_partial():
    reader = FixtureTransport(lambda request: {"items": [{"name": "a"}], "nextPageToken": "next"})
    result = GCPCollector(connector(["network"], max_pages=1), transport=reader).collect()
    assert collection(result, "network")["status"] == "partial"
    assert result["metadata"]["intentional_limits"] == {"max_pages": 1}
    assert result["metadata"]["collection_mode"] == "intentionally_limited"


def test_cancellation_prevents_requests_without_credential_or_cloud_side_effects(monkeypatch):
    event = threading.Event()
    event.set()
    credentials = SimpleNamespace(headers=lambda: (_ for _ in ()).throw(AssertionError("auth after cancellation")))
    transport = Transport(credentials, {"cancel_event": event})
    from peaso.collectors.gcp import ReadError
    import pytest
    with pytest.raises(ReadError, match="cancelled"):
        transport.request("GET", "https://compute.googleapis.com/compute/v1/projects/p/global/networks")
    assert transport.calls == 0


def test_directory_memberships_are_scoped_paged_and_transitive_denial_is_not_complete():
    from peaso.collectors.gcp import ReadError
    def resolve(request):
        url = request["url"]
        if url.endswith(":getIamPolicy"):
            return {"bindings": [{"role": "roles/viewer", "members": ["group:team@example.org"]}]}
        if url.endswith(":searchAllIamPolicies"):
            return {"results": []}
        if url.endswith("/groups"):
            assert request["params"]["parent"] == "customers/C123"
            return {"groups": [{"name": "groups/G", "groupKey": {"id": "team@example.org"}}]}
        if url.endswith("groups:lookup"):
            return {"name": "groups/G"}
        if url.endswith("groups/G"):
            return {"name": "groups/G", "groupKey": {"id": "team@example.org"}}
        if url.endswith("memberships:searchTransitiveMemberships"):
            raise ReadError("denied", "api_error", http_status=403)
        if url.endswith("/memberships"):
            if request["params"].get("pageToken"):
                return {"memberships": [{"name": "groups/G/memberships/b", "memberKey": {"id": "b@example.org"}}]}
            return {"memberships": [{"name": "groups/G/memberships/a", "memberKey": {"id": "a@example.org"}}], "nextPageToken": "next"}
        return {}
    reader = FixtureTransport(resolve)
    result = GCPCollector(connector(["group", "group_membership"], cloud_identity_customers=["C123"]), transport=reader).collect()
    found = collection(result, "group_membership")
    assert found["status"] == "partial" and found["error"]["kind"] == "denied"
    assert len(found["items"]) == 2
    assert all(member["membershipCoverage"]["completeTransitiveClosure"] is False for member in found["items"])
    assert collection(result, "group")["items"][0]["_coverage"]["transitiveMemberships"]["status"] == "denied"


def test_predefined_roles_collect_actual_permissions_and_preserve_conditional_binding():
    def resolve(request):
        if request["url"].endswith(":getIamPolicy"):
            return {"version": 3, "bindings": [{"role": "roles/editor", "members": ["user:a@example.org"],
                "condition": {"expression": "false"}}]}
        if request["url"].endswith("/roles/editor"):
            return {"name": "roles/editor", "includedPermissions": ["compute.instances.get"]}
        return {"roles": [], "results": []}
    result = GCPCollector(connector(["iam_policy", "iam_role"]), transport=FixtureTransport(resolve)).collect()
    assert collection(result, "iam_role")["items"][0]["includedPermissions"] == ["compute.instances.get"]
    assert collection(result, "iam_policy")["items"][0]["bindings"][0]["condition"]["expression"] == "false"


def test_boundary_policies_and_bindings_remain_native_metadata_conditions():
    def resolve(request):
        if request["url"].endswith("/principalAccessBoundaryPolicies"):
            return {"principalAccessBoundaryPolicies": [{"name": "organizations/123/locations/global/principalAccessBoundaryPolicies/p",
                "details": {"rules": [{"resources": ["//cloudresourcemanager.googleapis.com/projects/1"], "effect": "ALLOW"}]}}]}
        return {"policyBindings": [{"name": "organizations/123/locations/global/policyBindings/b", "condition": {"expression": "false"}}]}
    result = GCPCollector(connector(["principal_access_boundary_policy", "policy_binding"], scopes=["organizations/123"]),
        transport=FixtureTransport(resolve)).collect()
    assert collection(result, "policy_binding", "organizations/123")["items"][0]["condition"]["expression"] == "false"
    assert collection(result, "principal_access_boundary_policy", "organizations/123")["items"][0]["details"]["rules"]


def test_workspace_directory_reads_only_explicit_metadata_and_paginates_with_selected_identity():
    def resolve(request):
        url, params = request["url"], request["params"]
        assert request["method"] == "GET"
        if url == "https://cloudresourcemanager.googleapis.com/v3/projects/p-one":
            return {"name": "projects/123456789012", "projectId": "p-one", "parent": "organizations/123"}
        if url == "https://cloudresourcemanager.googleapis.com/v3/organizations/123":
            return {"name": "organizations/123", "directoryCustomerId": "C123"}
        assert url.startswith("https://admin.googleapis.com/admin/directory/v1/")
        assert "fields" in params and "password" not in params["fields"]
        if url.endswith("/users"):
            assert params["customer"] == "C123" and params["viewType"] == "admin_view"
            assert params["projection"] == "full"
            if params.get("pageToken"):
                return {"users": [{"id": "2", "customerId": "C123", "primaryEmail": "b@example.org", "isAdmin": False, "isDelegatedAdmin": True}]}
            return {"users": [{"id": "1", "customerId": "C123", "primaryEmail": "a@example.org", "isAdmin": True, "isDelegatedAdmin": False}], "nextPageToken": "next"}
        if url.endswith("/roles"):
            return {"items": [{"roleId": "r", "roleName": "delegated", "isSuperAdminRole": False,
                "rolePrivileges": [{"privilegeName": "USERS_RETRIEVE", "serviceId": "directory"}]}]}
        return {"items": [{"roleAssignmentId": "a", "roleId": "r", "assignedTo": "2", "scopeType": "CUSTOMER",
            "condition": "resource.name != ''"}]}
    reader = FixtureTransport(resolve)
    result = GCPCollector(connector(["workspace_user", "workspace_role", "workspace_role_assignment"], workspace_customers=["C123"]),
        transport=reader).collect()
    users = collection(result, "workspace_user")["items"]
    assert len(users) == 2 and users[0]["isAdmin"] is True and users[1]["isDelegatedAdmin"] is True
    assert collection(result, "workspace_role")["items"][0]["rolePrivileges"][0]["privilegeName"] == "USERS_RETRIEVE"
    assert collection(result, "workspace_role_assignment")["items"][0]["condition"]
    binding = users[0]["_directoryBinding"]
    assert binding["status"] == "collected" and binding["customer"] == "C123"
    assert [row["requested"] for row in binding["chain"]] == ["projects/p-one", "organizations/123"]
    assert [request["url"] for request in reader.requests] == [
        "https://cloudresourcemanager.googleapis.com/v3/projects/p-one",
        "https://cloudresourcemanager.googleapis.com/v3/organizations/123",
        "https://admin.googleapis.com/admin/directory/v1/users",
        "https://admin.googleapis.com/admin/directory/v1/users",
        # c1eba0e4 reuses the proven Directory ancestry for roles and assignments.
        "https://admin.googleapis.com/admin/directory/v1/customer/C123/roles",
        "https://admin.googleapis.com/admin/directory/v1/customer/C123/roleassignments"]


def test_workspace_api_denial_stays_denied_without_enablement_or_consent():
    from peaso.collectors.gcp import ReadError
    reader = FixtureTransport(lambda request: (_ for _ in ()).throw(ReadError("denied", "api_error", http_status=403)))
    result = GCPCollector(connector(["workspace_user", "workspace_role", "workspace_role_assignment"], workspace_customers=["C123"]),
        transport=reader).collect()
    assert all(row["status"] == "denied" for row in result["collections"])
    assert all(request["method"] == "GET" for request in reader.requests)


def test_key_and_table_inventory_is_metadata_only_and_dataproc_regions_are_explicit():
    def resolve(request):
        url = request["url"]
        if "apikeys.googleapis.com" in url:
            assert "keyString" not in request["params"]["fields"]
            return {"keys": [{"name": "projects/p-one/locations/global/keys/k", "uid": "key-id", "createTime": "2026-01-01T00:00:00Z",
                "restrictions": {"apiTargets": [{"service": "storage.googleapis.com"}]}}]}
        if url.endswith("/datasets"):
            return {"datasets": [{"datasetReference": {"projectId": "p-one", "datasetId": "d"}}]}
        if url.endswith("/datasets/d"):
            return {"datasetReference": {"projectId": "p-one", "datasetId": "d"}, "access": []}
        if url.endswith("/tables"):
            return {"tables": [{"tableReference": {"projectId": "p-one", "datasetId": "d", "tableId": "t"}, "type": "TABLE"}]}
        if url.endswith("/tables/t"):
            assert "view" not in request["params"]["fields"] and "query" not in request["params"]["fields"]
            return {"tableReference": {"projectId": "p-one", "datasetId": "d", "tableId": "t"}, "type": "TABLE", "encryptionConfiguration": {"kmsKeyName": "projects/p/locations/r/keyRings/a/cryptoKeys/k"}}
        if "dataproc" in url:
            assert "/regions/r-a/clusters" in url
            return {"clusters": [{"clusterName": "c", "config": {"encryptionConfig": {"gcePdKmsKeyName": "projects/p/locations/r/keyRings/a/cryptoKeys/k"}}}]}
        if url.endswith("/managedZones"):
            return {"managedZones": [{"name": "zone", "visibility": "public", "dnssecConfig": {"state": "on"}}]}
        return {"policies": []}
    reader = FixtureTransport(resolve)
    result = GCPCollector(connector(["api_key", "bigquery_table", "dataproc_cluster", "dns_managed_zone", "dns_policy"],
        dataproc_regions=["r-a"]), transport=reader).collect()
    assert collection(result, "api_key")["items"][0]["restrictions"]["apiTargets"]
    assert collection(result, "bigquery_table")["items"][0]["encryptionConfiguration"]
    assert collection(result, "dataproc_cluster")["items"][0]["config"]["encryptionConfig"]
    assert not any(":getKeyString" in request["url"] or "tabledata" in request["url"] or ":query" in request["url"] for request in reader.requests)
