"""Native collector acceptance fixtures; no real cloud writes or credentials."""
from __future__ import annotations

import copy
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from peaso.collectors import gcp
from peaso.analysis import network_snapshot
from peaso.snapshot import resources, validate


class FixtureTransport:
    def __init__(self, resolver):
        self.resolver = resolver
        self.requests = []
        self.calls = 0
        self.evidence = []
        self.lock = threading.Lock()

    def request(self, method, url, **kwargs):
        with self.lock:
            self.calls += 1
            request_id = f"request-{self.calls}"
            request = {"method": method, "url": url, **copy.deepcopy(kwargs)}
            self.requests.append(request)
        try:
            data = self.resolver(request)
        except gcp.ReadError as exc:
            exc.request_id = request_id
            self.evidence.append({"id": request_id, "url": url, "method": method,
                "status": exc.status, "error": exc.error})
            raise
        self.evidence.append({"id": request_id, "url": url, "method": method, "status": "collected"})
        return copy.deepcopy(data), request_id


class NativeDataFixtureTransport(FixtureTransport):
    """Retain the actual successful HTTP identity receipt used for CRM aliases."""
    def request(self, method, url, **kwargs):
        data, request_id = super().request(method, url, **kwargs)
        receipt = next(r for r in self.evidence if r['id'] == request_id)
        receipt.update(scope=kwargs['scope'], http_status=200, query=kwargs.get('params', {}))
        if kwargs.get('body'):
            receipt['request'] = copy.deepcopy(kwargs['body'])
        return data, request_id


def connector(kinds, scopes=None, **options):
    return {"provider": "gcp", "scopes": scopes or ["projects/p-one"],
            "options": {"inventories": kinds, "include_inherited": False, "concurrency": 1, **options}}


def snapshot(kinds, resolver, scopes=None, **options):
    transport = FixtureTransport(resolver)
    result = gcp.GCPCollector(connector(kinds, scopes, **options), transport=transport).collect()
    assert validate(result) == result
    return result, transport


def collection(result, kind, scope="projects/p-one"):
    return next(c for c in result["collections"] if c["type"] == kind and c["scope"] == scope)


def test_selection_fetches_only_required_facts():
    result, transport = snapshot(["bucket", "network"], lambda r: {"items": []})
    assert {c["type"] for c in result["collections"]} == {"bucket", "network"}
    assert len(transport.requests) == 2
    assert {r["url"] for r in transport.requests} == {
        "https://storage.googleapis.com/storage/v1/b",
        "https://compute.googleapis.com/compute/v1/projects/p-one/global/networks"}
    collector = gcp.GCPCollector(connector(["bucket", "network"]), ["network"], transport=transport)
    assert {c["type"] for c in collector.collect()["collections"]} == {"network"}


def test_psc_and_neg_inventories_include_global_and_aggregated_native_resources():
    kinds = ["service_attachment", "network_endpoint_group", "network_attachment"]
    def resolver(request):
        path = request["url"]
        if "/global/networkEndpointGroups" in path:
            return {"items": [{"name": "global-neg", "selfLink": "https://www.googleapis.com/compute/v1/projects/p-one/global/networkEndpointGroups/global-neg"}]}
        segment = path.rsplit("/", 1)[1]
        return {"items": {"regions/us-central1": {segment: [{"name": segment,
            "selfLink": f"https://www.googleapis.com/compute/v1/projects/p-one/regions/us-central1/{segment}/regional"}]}}}
    result, transport = snapshot(kinds, resolver)
    assert len(transport.requests) == 4
    assert len(collection(result, "network_endpoint_group")["items"]) == 2
    for kind in kinds:
        assert collection(result, kind)["status"] == "collected"
        assert collection(result, kind)["source_requests"]


@pytest.mark.parametrize("kind,service,key,option", [
    ("vpc_access_connector", "vpcaccess", "connectors", "vpcaccess_locations"),
    ("filestore_instance", "file", "instances", "filestore_locations"),
    ("redis_instance", "redis", "instances", "redis_locations"),
])
def test_managed_network_metadata_uses_location_pagination_without_iam_reads(kind, service, key, option):
    assert f"{service}.googleapis.com" in gcp.HOSTS
    def resolver(request):
        assert request["method"] == "GET"
        assert request["url"] == f"https://{service}.googleapis.com/v1/projects/p-one/locations/us-central1/{key}"
        token = request.get("params", {}).get("pageToken")
        name = f"projects/p-one/locations/us-central1/{key}/{'two' if token else 'one'}"
        return {key: [{"name": name, "network": "net"}], **({} if token else {"nextPageToken": "next"})}
    result, transport = snapshot([kind], resolver, **{option: ["us-central1"]})
    assert len(transport.requests) == 2
    assert len(collection(result, kind)["items"]) == 2
    assert collection(result, kind)["status"] == "collected"


def test_connector_location_discovery_and_denied_region_stay_in_coverage():
    def resolver(request):
        if request["url"].endswith("/locations"):
            return {"locations": [{"locationId": "us-central1"}]}
        raise gcp.ReadError("denied", "denied")
    result, transport = snapshot(["vpc_access_connector"], resolver)
    assert len(transport.requests) == 2
    assert collection(result, "vpc_access_connector")["status"] == "denied"


def test_native_peering_effective_route_exchange_survives_network_projection():
    effective = {"stackType": "IPV4_IPV6", "importSubnetRoutesWithPublicIpFromPeer": True,
        "exportSubnetRoutesWithPublicIpToPeer": False}
    network = {"name": "net", "selfLink": "projects/p-one/global/networks/net", "peerings": [{
        "network": "projects/p-two/global/networks/peer", "state": "ACTIVE",
        "stackType": "IPV4_ONLY", "importSubnetRoutesWithPublicIp": False,
        "connectionStatus": {"trafficConfiguration": effective,
            "consensusState": {"updateStatus": "PENDING_PEER_ACKNOWLEDGMENT"}}}]}
    result, transport = snapshot(["network"], lambda request: {"items": [network]})
    projected = network_snapshot(result)
    collected = next(r for r in resources(projected) if r["type"] == "network")
    assert collected["data"]["peerings"][0]["connectionStatus"]["trafficConfiguration"] == effective
    assert collected["data"]["peerings"][0]["connectionStatus"]["consensusState"]["updateStatus"] == "PENDING_PEER_ACKNOWLEDGMENT"
    assert collection(result, "network")["source_requests"]
    assert len(transport.requests) == 1


def test_policy_based_routes_are_collected_from_network_connectivity_api():
    route_name = "projects/p-one/locations/global/policyBasedRoutes/redirect"
    def resolve(request):
        assert request["method"] == "GET"
        assert request["url"] == "https://networkconnectivity.googleapis.com/v1/projects/p-one/locations/global/policyBasedRoutes"
        return {"policyBasedRoutes": [{"name": route_name, "network": "projects/p-one/global/networks/net",
            "priority": 100, "nextHopIlbIp": "10.0.0.10"}]}
    result, transport = snapshot(["policy_based_route"], resolve)
    row = collection(result, "policy_based_route")
    assert row["status"] == "collected"
    assert row["items"][0]["name"] == route_name
    assert len(transport.requests) == 1


def test_regional_effective_firewalls_capture_system_policy_context():
    network = "https://www.googleapis.com/compute/v1/projects/p-one/global/networks/net"
    subnet = "https://www.googleapis.com/compute/v1/projects/p-one/regions/us-east1/subnetworks/s1"
    def resolve(request):
        url = request["url"]
        if url.endswith("/global/networks"):
            return {"items": [{"name": "net", "selfLink": network}]}
        if url.endswith("/aggregated/subnetworks"):
            return {"items": {"regions/us-east1": {"subnetworks": [{"name": "s1", "selfLink": subnet,
                "network": network, "region": "https://www.googleapis.com/compute/v1/projects/p-one/regions/us-east1"}]}}}
        assert url.endswith("/regions/us-east1/firewallPolicies/getEffectiveFirewalls")
        assert request["params"]["network"] == network
        return {"firewalls": [], "firewallPolicys": [{"name": "system", "type": "SYSTEM_REGIONAL", "rules": []}]}
    result, transport = snapshot(["effective_firewall"], resolve,
        compute_resource_iam=False)
    assert {c["type"] for c in result["collections"]} == {"effective_firewall"}
    captured = collection(result, "effective_firewall")
    assert captured["status"] == "collected"
    assert captured["items"][0]["firewallPolicys"][0]["type"] == "SYSTEM_REGIONAL"
    assert captured["items"][0]["effective_source_operation"] == "regionNetworkFirewallPolicies.getEffectiveFirewalls"
    assert captured["items"][0]["_provenance"]["source_requests"]
    assert set(captured["items"][0]["_provenance"]["source_requests"]) <= set(captured["source_requests"])
    assert captured["source_requests"]
    assert len(transport.requests) == 3
    assert any(r["type"] == "effective_firewall" for r in resources(network_snapshot(result)))


def test_no_requirements_performs_no_auth_or_requests(monkeypatch):
    monkeypatch.setattr(gcp, "Credentials", lambda *a, **k: pytest.fail("unexpected auth"))
    result = gcp.collect(connector(["network"]), [])
    assert result["collections"] == []
    assert result["metadata"]["calls"] == 0


def test_pagination_dedup_preserves_query_and_request_provenance():
    def resolve(request):
        params = request["params"]
        assert params["maxResults"] == 500  # compute list maximum when page_size is unset
        return {"items": [{"name": "same"}, {"name": "second"}]} if params.get("pageToken") else {
            "items": [{"name": "same"}], "nextPageToken": "private-page-token"}
    result, transport = snapshot(["network"], resolve)
    found = collection(result, "network")
    assert found["status"] == "collected"
    assert len(found["items"]) == 2
    assert len(found["source_requests"]) == 2
    assert transport.requests[1]["params"]["pageToken"] == "private-page-token"


@pytest.mark.parametrize("case,code", [("limit", "page_limit"), ("repeated", "repeated_pagination_token")])
def test_truncation_is_partial_without_extra_page_reads(case, code):
    result, transport = snapshot(["network"], lambda r: {"items": [{"name": "one"}], "nextPageToken": "same"},
                                 max_pages=1 if case == "limit" else 5)
    found = collection(result, "network")
    assert found["status"] == "partial"
    assert found["error"]["code"] == code
    assert transport.calls == (1 if case == "limit" else 2)


def test_resource_cap_is_global():
    result, _ = snapshot(["network"], lambda r: {"items": [{"name": "a"}, {"name": "b"}]},
                         scopes=["projects/p-one", "projects/p-two"], max_resources=1)
    assert sum(len(c["items"]) for c in result["collections"]) == 1
    assert all(c["error"]["code"] == "resource_limit" for c in result["collections"])
    assert collection(result, "network")["status"] == "partial"


@pytest.mark.parametrize("state,wire", [("denied", "denied"), ("unavailable", "unknown"),
                                      ("unsupported", "unknown"), ("malformed", "malformed")])
def test_distinct_unavailable_denied_unsupported_malformed(state, wire):
    def fail(request):
        raise gcp.ReadError(state, "safe_error")
    result, _ = snapshot(["network"], fail)
    found = collection(result, "network")
    assert found["status"] == wire
    assert found["coverage_status"] == state
    assert found["items"] == []
    assert found["error"]["kind"] == state
    assert found["source_requests"] == ["request-1"]


def test_empty_success_is_not_denial_or_unknown():
    result, _ = snapshot(["network"], lambda r: {})
    assert collection(result, "network")["status"] == "empty"


def test_empty_aggregated_response_is_empty_and_partial_warning_is_visible():
    result, _ = snapshot(["instance"], lambda r: {})
    assert collection(result, "instance")["status"] == "empty"
    result, _ = snapshot(["instance"], lambda r: {"items": {"zones/r": {"instances": [{"name": "vm"}],
        "warning": {"code": "UNREACHABLE"}}}})
    assert collection(result, "instance")["status"] == "partial"
    assert collection(result, "instance")["error"]["code"] == "partial_api_warning"


def test_malformed_list_shape_preserves_the_exact_request_evidence():
    result, _ = snapshot(["network"], lambda r: {"items": "invalid"})
    found = collection(result, "network")
    assert found["status"] == "malformed"
    assert found["source_requests"] == ["request-1"]


def test_partial_keeps_successful_page_and_later_denial_evidence():
    def resolve(request):
        if request["params"].get("pageToken"):
            raise gcp.ReadError("denied", "api_error", http_status=403)
        return {"items": [{"name": "one"}], "nextPageToken": "next"}
    result, _ = snapshot(["network"], resolve)
    found = collection(result, "network")
    assert found["status"] == "partial"
    assert found["error"]["kind"] == "denied"
    assert found["source_requests"] == ["request-1", "request-2"]


def test_cross_project_and_zone_native_ids_do_not_collide():
    def resolve(request):
        project = request["scope"].split("/")[1]
        return {"items": {zone: {"instances": [{"id": "123", "name": "same", "selfLink":
            f"https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}/instances/same",
            "networkInterfaces": [{"accessConfigs": [{"natIP": "203.0.113.1"}]}],
            "shieldedInstanceConfig": {"enableSecureBoot": True}}]}
            for zone in ["zone-a", "zone-b"]}}
    result, _ = snapshot(["instance"], resolve, scopes=["p-one", "p-two"])
    found = resources(result)
    assert len(found) == 4
    assert len({r["id"] for r in found}) == 4
    assert all(r["data"]["id"] == "123" for r in found)
    assert all(r["data"]["networkInterfaces"][0]["accessConfigs"][0]["natIP"] == "203.0.113.1" for r in found)
    assert all(r["data"]["shieldedInstanceConfig"]["enableSecureBoot"] is True for r in found)


def test_bucket_hydration_and_sensitive_metadata_projection():
    def resolve(request):
        if request["url"].endswith("/iam"):
            return {"version": 3, "bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"],
                "condition": {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}}]}
        return {"items": [{"name": "bucket", "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True},
            "publicAccessPrevention": "enforced"}, "encryption": {"defaultKmsKeyName": "projects/p-one/locations/global/keyRings/r/cryptoKeys/k"},
            "privateKeyData": "do-not-store", "metadata": {"items": [{"key": "startup-script", "value": "embedded-password"},
                {"key": "enable-oslogin", "value": "TRUE"}]}}]}
    result, _ = snapshot(["bucket"], resolve)
    item = collection(result, "bucket")["items"][0]
    assert item["iamPolicy"]["bindings"][0]["condition"]
    assert item["_coverage"]["iamPolicy"]["status"] == "collected"
    assert len(item["_provenance"]["source_requests"]) == 2
    assert {e["type"] for e in item["_relationships"]} == {"encrypted_with"}
    assert "do-not-store" not in json.dumps(result)
    assert "embedded-password" not in json.dumps(result)
    assert item["metadata"]["items"][1]["value"] == "TRUE"


def test_hydration_denial_does_not_turn_known_bucket_into_empty_inventory():
    def resolve(request):
        if request["url"].endswith("/iam"):
            raise gcp.ReadError("denied", "api_error", http_status=403)
        return {"items": [{"name": "bucket"}]}
    result, _ = snapshot(["bucket"], resolve)
    found = collection(result, "bucket")
    assert found["status"] == "collected"
    assert found["items"][0]["iamPolicy"]["collection_status"] == "denied"
    assert found["items"][0]["_coverage"]["iamPolicy"]["status"] == "denied"


def test_inherited_policies_are_deduped_without_sibling_inventory():
    def resolve(request):
        if request["url"].endswith(":getAncestry"):
            return {"ancestor": [{"resourceId": {"type": "folder", "id": "12"}},
                {"resourceId": {"type": "organization", "id": "34"}}]}
        if request["url"].endswith(":getIamPolicy"):
            return {"version": 3, "bindings": [{"role": "roles/viewer", "members": ["user:a@example.org"]}]}
        return {"results": []}
    result, transport = snapshot(["iam_policy"], resolve, scopes=["p-one", "p-two"], include_inherited=True)
    assert result["scopes"] == ["projects/p-one", "projects/p-two"]
    assert result["metadata"]["inherited_scopes"] == ["folders/12", "organizations/34"]
    assert sum(r["url"].endswith("folders/12:getIamPolicy") for r in transport.requests) == 1
    assert not any(":searchAllIamPolicies" in r["url"] and r["scope"].startswith(("folders/", "organizations/"))
                   for r in transport.requests)


def test_explicit_project_restrictions_are_enforced_before_auth():
    with pytest.raises(ValueError, match="outside project_restrictions"):
        gcp.collect(connector(["network"], ["p-other"], project_restrictions=["p-one"]))


def test_all_projects_discovery_filters_excluded_projects_without_inventory_reads():
    def resolve(request):
        if request["url"].endswith("projects:search"):
            return {"projects": [{"projectId": "p-one", "name": "projects/1"}, {"projectId": "p-two", "name": "projects/2"}]}
        return {"items": []}
    result, transport = snapshot(["network"], resolve, scopes=["*"], all_projects=True, project_restrictions=["p-one"])
    assert result["metadata"]["resolved_scopes"] == ["projects/p-one"]
    assert not any("p-two" in request["url"] for request in transport.requests)
    assert "p-two" not in json.dumps(result)


def test_organization_restrictions_do_not_make_broad_cai_reads():
    result, transport = snapshot(["asset", "iam_policy"], lambda r: {}, scopes=["organizations/12"], project_restrictions=["p-one"])
    assert collection(result, "asset", "organizations/12")["coverage_status"] == "unsupported"
    assert not any("cloudasset" in r["url"] for r in transport.requests)


def test_unsupported_scope_inventory_is_explicit():
    result, transport = snapshot(["bucket"], lambda r: pytest.fail("unexpected read"), scopes=["organizations/12"])
    assert collection(result, "bucket", "organizations/12")["error"]["code"] == "inventory_not_supported_at_scope"
    assert transport.calls == 0


def test_shared_vpc_host_project_reference_never_broadens_scope():
    def resolve(request):
        if request["url"].endswith("/projects/p-one"):
            return {"kind": "compute#project", "name": "p-one", "xpnProjectStatus": "HOST"}
        if request["url"].endswith("getXpnHost"):
            return {"name": "host-project", "id": "654"}
        return {"resources": [{"id": "p-one", "type": "PROJECT"}]}
    result, transport = snapshot(["shared_vpc"], resolve)
    assert len(collection(result, "shared_vpc")["items"]) == 2
    project_url = "https://compute.googleapis.com/compute/v1/projects/p-one"
    assert all(r["url"] == project_url or r["url"].startswith(project_url + "/")
               for r in transport.requests)


def test_service_account_keys_are_metadata_only_and_no_parent_visibility_is_not_empty():
    def resolve(request):
        if request["url"].endswith("/serviceAccounts"):
            return {"accounts": [{"name": "projects/p-one/serviceAccounts/a", "email": "a@p-one.iam.gserviceaccount.com"}]}
        if request["url"].endswith(":getIamPolicy"):
            return {"bindings": []}
        return {"keys": [{"name": "projects/p-one/serviceAccounts/a/keys/123", "keyType": "USER_MANAGED",
            "validAfterTime": "2026-01-01", "privateKeyData": "sensitive", "publicKeyData": "sensitive"}]}
    result, _ = snapshot(["service_account_key"], resolve)
    assert {c["type"] for c in result["collections"]} == {"service_account_key"}
    assert "sensitive" not in json.dumps(result)
    def denied(request):
        raise gcp.ReadError("denied", "api_error", http_status=403)
    result, _ = snapshot(["service_account_key"], denied)
    assert collection(result, "service_account_key")["status"] == "unknown"
    assert collection(result, "service_account_key")["error"]["code"] == "service_account_inventory_incomplete"


def test_service_account_listing_caps_iam_page_size_and_reads_next_page():
    def resolve(request):
        if request["url"].endswith("/serviceAccounts"):
            assert request["params"]["pageSize"] == 100
            token = request["params"].get("pageToken")
            if token is None:
                return {"accounts": [{"name": "projects/p-one/serviceAccounts/first@p-one.iam.gserviceaccount.com",
                                      "email": "first@p-one.iam.gserviceaccount.com"}], "nextPageToken": "next"}
            assert token == "next"
            return {"accounts": [{"name": "projects/p-one/serviceAccounts/second@p-one.iam.gserviceaccount.com",
                                  "email": "second@p-one.iam.gserviceaccount.com"}]}
        assert request["url"].endswith(":getIamPolicy")
        return {"bindings": []}

    result, transport = snapshot(["service_account"], resolve, page_size=1000,
                                 service_account_activity=False)
    accounts = collection(result, "service_account")
    assert accounts["status"] == "collected"
    assert {item["email"] for item in accounts["items"]} == {
        "first@p-one.iam.gserviceaccount.com", "second@p-one.iam.gserviceaccount.com"}
    assert len([request for request in transport.requests if request["url"].endswith("/serviceAccounts")]) == 2


def test_activity_projection_never_stores_log_payload_or_proves_inactivity():
    result, transport = snapshot(["activity"], lambda r: {"entries": [{"insertId": "event", "timestamp": "2026-10-10T00:00:00Z",
        "protoPayload": {"authenticationInfo": {"principalEmail": "a@p-one.iam.gserviceaccount.com",
            "serviceAccountKeyName": "projects/p-one/serviceAccounts/a/keys/k"}, "request": {"password": "do-not-store"}}}]})
    item = collection(result, "activity")["items"][0]
    assert item["coverageWindow"]["absenceProvesUnused"] is False
    assert "do-not-store" not in json.dumps(result)
    assert transport.requests[0]["method"] == "POST"
    assert transport.requests[0]["body"]["resourceNames"] == ["projects/p-one"]


def test_iam_role_resolution_reuses_only_referenced_builtin_roles():
    def resolve(request):
        if request["url"].endswith(":getIamPolicy"):
            return {"bindings": [{"role": "roles/viewer", "members": ["user:a@example.org"]},
                                 {"role": "roles/viewer", "members": ["user:b@example.org"]}]}
        if request["url"].endswith("/roles/viewer"):
            return {"name": "roles/viewer", "includedPermissions": ["compute.instances.get"]}
        return {"roles": [], "results": []}
    result, transport = snapshot(["iam_policy", "iam_role"], resolve)
    assert sum(r["url"].endswith("/roles/viewer") for r in transport.requests) == 1
    assert collection(result, "iam_role")["items"][0]["includedPermissions"] == ["compute.instances.get"]


def test_kms_enumerates_locations_and_hydrates_key_iam():
    def resolve(request):
        if request["url"].endswith("/locations"):
            return {"locations": [{"name": "projects/p-one/locations/global"}]}
        if request["url"].endswith("/keyRings"):
            return {"keyRings": [{"name": "projects/p-one/locations/global/keyRings/r"}]}
        if request["url"].endswith("/cryptoKeys"):
            return {"cryptoKeys": [{"name": "projects/p-one/locations/global/keyRings/r/cryptoKeys/k", "rotationPeriod": "7776000s"}]}
        return {"bindings": []}
    result, transport = snapshot(["kms_key"], resolve)
    assert all("locations/-/keyRings" not in r["url"] for r in transport.requests)
    assert collection(result, "kms_key")["items"][0]["iamPolicy"]["bindings"] == []


CONTENT_ONLY_TYPES = {
    "composer_dag_source", "log_secret_sample", "gcs_selected_object", "gcs_selected_archive",
    "dataform_selected_file", "app_engine_version_secret", "workflow_source", "dataflow_job",
    "batch_job", "dataproc_job", "gke_workload_literal", "function_source_archive", "artifact_selected_file",
    "appengine_deployment_source", "cloudbuild_artifact_source", "cloudbuild_log_source",
    "clouddeploy_release_source", "source_repository_file",
    "cloudtasks_selected_task", "bigquery_selected_routine",
}


def test_content_only_inventories_are_excluded_by_default():
    collector = gcp.GCPCollector({'provider': 'gcp', 'scopes': ['projects/p-one'],
        'options': {'include_inherited': False}}, transport=FixtureTransport(lambda request: {}))
    try:
        assert CONTENT_ONLY_TYPES <= gcp.SUPPORTED_TYPES
        assert not CONTENT_ONLY_TYPES & collector.wanted
    finally:
        collector.hydration_pool.shutdown(wait=True)


@pytest.mark.parametrize('kind', sorted(CONTENT_ONLY_TYPES))
def test_explicit_disabled_content_inventory_cannot_claim_collected_or_clean(kind):
    result, transport = snapshot([kind], lambda request: {}, content_secret_scans=False)
    envelope = collection(result, kind)
    # Disabled inspection is unavailable evidence, never a complete empty
    # inventory. The envelope must reject it before invoking a content fetcher.
    assert envelope['status'] == 'unknown'
    assert envelope['coverage_status'] in {'unavailable', 'not_collected', 'unsupported'}
    assert envelope['items'] == []
    assert envelope.get('error', {}).get('code') != 'collector_error'
    from peaso.checks import CHECKS
    checks = [check for check in CHECKS if check.kind == kind and check.provider == 'gcp']
    assert checks
    index = {'context': {'provider': 'gcp', 'scope': 'projects/p-one'}, 'collections': {kind: [envelope]}}
    assert all(check.evaluate({}, index)[0] == 'UNKNOWN' for check in checks)
    assert not any('workflows.googleapis.com' in request['url'] for request in transport.requests)


def test_native_service_coverage_and_configuration_fixture():
    def resolve(request):
        url = request["url"]
        if url == 'https://cloudresourcemanager.googleapis.com/v3/projects/p-one':
            return {'name': 'projects/123456789012', 'projectId': 'p-one', 'parent': 'organizations/123'}
        if url == 'https://cloudresourcemanager.googleapis.com/v3/organizations/123':
            return {'name': 'organizations/123', 'directoryCustomerId': 'Cfixture'}
        if url == 'https://admin.googleapis.com/admin/directory/v1/users':
            assert request['params']['customer'] == 'Cfixture'
            assert request['params']['projection'] == 'full'
            return {'users': []}
        if url in {'https://admin.googleapis.com/admin/directory/v1/customer/Cfixture/roles',
                   'https://admin.googleapis.com/admin/directory/v1/customer/Cfixture/roleassignments'}:
            return {'items': []}
        if url == 'https://compute.googleapis.com/compute/v1/projects/p-one':
            return {'kind': 'compute#project', 'name': 'p-one', 'xpnProjectStatus': 'HOST'}
        if url == 'https://appengine.googleapis.com/v1beta/apps/p-one':
            return {'name': 'apps/p-one', 'serviceAccount': 'p-one@appspot.gserviceaccount.com'}
        if url == 'https://biglake.googleapis.com/iceberg/v1/restcatalog/extensions/projects/p-one/catalogs':
            return {'iceberg-catalogs': []}
        if url == 'https://osconfig.googleapis.com/v1/projects/p-one/locations/global/projectFeatureSettings':
            return {'name': 'projects/p-one/locations/global/projectFeatureSettings',
                    'patchAndConfigFeatureSet': 'OSCONFIG_C'}
        if url == 'https://admin.googleapis.com/admin/directory/v1/customers/Cfixture':
            return {'id': 'Cfixture', 'customerDomain': 'example.test'}
        if ':getEffectivePolicy' in url:
            constraint = url.rsplit('/policies/', 1)[1].split(':', 1)[0]
            return {'name': 'projects/123456789012/policies/' + constraint, 'spec': {'rules': []}}
        if url.endswith(":getIamPolicy") or url.endswith("/iam"):
            return {"version": 3, "bindings": [], "auditConfigs": [{"service": "allServices"}]}
        if ":searchAllIamPolicies" in url:
            return {"results": []}
        if url.endswith("/assets"):
            return {"assets": [{"name": "//run.googleapis.com/projects/p-one/locations/europe-west1/services/s", "assetType": "run.googleapis.com/Service",
                "resource": {"data": {"ingress": "INGRESS_TRAFFIC_ALL"}}}]}
        if "/aggregated/" in url:
            segment = url.rsplit("/", 1)[1]
            if segment == "instances":
                return {"items": {}}
            return {"items": {"regions/r": {segment: [{"name": segment, "network": "projects/host/global/networks/n",
                "networkInterfaces": [{"subnetwork": "projects/host/regions/r/subnetworks/s", "accessConfigs": [{"natIP": "203.0.113.1"}]}],
                "shieldedInstanceConfig": {"enableSecureBoot": True}}]}}}
        if url.endswith("/zones"):
            return {"items": [{"name": "r-a", "region": "projects/p-one/regions/r"}]}
        if url.endswith("/clusters"):
            if 'dataproc.googleapis.com' in url:
                return {'clusters': []}
            return {"clusters": [{"name": "gke", "location": "europe-west1",
                "selfLink": "https://container.googleapis.com/v1/projects/p-one/locations/europe-west1/clusters/gke", "privateClusterConfig": {"enablePrivateNodes": True},
                "masterAuth": {"clientCertificate": "do-not-store", "clientKey": "do-not-store", "password": "do-not-store"}}]}
        if url.endswith("/backupRuns"):
            return {"items": []}
        if "sqladmin" in url:
            return {"items": [{"name": "sql", "settings": {"ipConfiguration": {"ipv4Enabled": False}, "backupConfiguration": {"enabled": True}}}]}
        if url.endswith("/secrets"):
            return {"secrets": [{"name": "projects/p-one/secrets/s", "replication": {"automatic": {}}}]}
        if url.endswith("/serviceAccounts"):
            return {"accounts": []}
        if url.endswith("/workloadIdentityPools"):
            return {"workloadIdentityPools": [{"name": "projects/p-one/locations/global/workloadIdentityPools/w"}]}
        if url.endswith("/providers"):
            return {"workloadIdentityPoolProviders": [{"name": "projects/p-one/locations/global/workloadIdentityPools/w/providers/p",
                "attributeCondition": "assertion.repository_owner == 'trusted'", "oidc": {"issuerUri": "https://token.actions.githubusercontent.com"}}]}
        if url.endswith("/recommendations"):
            return {"recommendations": [{"name": "recommendation", "content": {"overview": {"removedPermissions": ["compute.instances.delete"]}}}]}
        if '/insightTypes/google.iam.serviceAccount.Insight/' in url:
            return {'insights': []}
        if url.endswith("/insights"):
            return {"insights": [{"name": "projects/p-one/locations/global/insightTypes/google.iam.policy.Insight/insights/fixture", "content": {"unusedPermissions": ["compute.instances.delete"]}}]}
        if url.endswith("/sinks"):
            return {"sinks": [{"name": "sink", "destination": "storage.googleapis.com/log-bucket"}]}
        if url.endswith("/getXpnHost"):
            return {"name": "host"}
        if url.endswith("/getXpnResources"):
            return {"resources": []}
        if "cloudidentity.googleapis.com" in url:
            assert request["params"]["parent"] == "customers/Cfixture"
            return {"groups": []}
        if "appengine.googleapis.com" in url:
            return {"name": "apps/p-one", "id": "p-one", "iap": {"enabled": True}}
        if url.endswith("/firewallPolicies/listAssociations"):
            return {"kind": "compute#FirewallPoliciesListAssociations", "associations": []}
        return {"items": []}
    # PAB policy ownership is organization-level, so it is exercised in the
    # dedicated org-scope fixture rather than asserted as an empty project API.
    # Perimeters need project ancestry (include_inherited), tested separately.
    # Content-only inventories require a separately named, opted-in request.
    from peaso.collectors.gcp_network_catalog import PRIVATE_SERVICES
    organization_network_types = {kind for kind, plan in PRIVATE_SERVICES.items() if plan.get('scope_kind') == 'organizations'}
    kinds = sorted(gcp.SUPPORTED_TYPES - CONTENT_ONLY_TYPES - gcp.CONTENT_ONLY_TYPES - organization_network_types - {"project", "organization", "folder", "workforce_pool", "workforce_provider", "kms_key", "kms_key_ring", "activity", "principal_access_boundary_policy", "firewall_policy_association", "service_perimeter", "audit_log", "scc_finding", "scc_notification_config", "provider_access_event", "asset_previous", "asset_audit_log", "deployed_image", "effective_firewall", "folder_policy_grant_constraints", "organization_policy_grant_constraints", "service_catalog_version"})
    result, transport = snapshot(kinds, resolve, cloud_identity_customers=["Cfixture"], regions=["r"],
        sw51_policy={'scope': 'projects/p-one', 'status': 'collected', 'approved_asset_types': ['compute.googleapis.com/Instance']})
    # Project identity is collected once to bind project-scoped evidence.
    assert {c["type"] for c in result["collections"]} == set(kinds) | {"project"}
    assert collection(result, "shared_vpc")["status"] == "collected"
    assert not any(c["status"] in ("malformed", "unknown") for c in result["collections"]), [(c["type"], c.get("error")) for c in result["collections"] if c["status"] in ("malformed", "unknown")]
    assert {r["url"] for r in transport.requests if "workflows.googleapis.com" in r["url"]} == {
        "https://workflows.googleapis.com/v1/projects/p-one/locations"}
    assert collection(result, "gke_cluster")["status"] == "collected"
    assert "do-not-store" not in json.dumps(result)
    assert collection(result, "workload_identity_provider")["items"][0]["attributeCondition"]
    assert collection(result, "asset")["items"][0]["assetType"] == "run.googleapis.com/Service"
    assert any("aggregated/backendServices" in r["url"] for r in transport.requests)
    assert any("aggregated/vpnTunnels" in r["url"] for r in transport.requests)
    assert any("aggregated/targetHttpsProxies" in r["url"] for r in transport.requests)
    assert any("aggregated/firewallPolicies" in r["url"] for r in transport.requests)
    assert any("cloudkms" not in r["url"] for r in transport.requests)


class Response:
    def __init__(self, status=200, data=None):
        self.status_code, self.data = status, data if data is not None else {"items": []}

    def json(self):
        return copy.deepcopy(self.data)


def http_transport(monkeypatch, responses, **options):
    calls = []
    def request(method, url, **kwargs):
        calls.append({"method": method, "url": url, **kwargs})
        value = responses[min(len(calls) - 1, len(responses) - 1)]
        if isinstance(value, Exception):
            raise value
        return value
    session = SimpleNamespace(request=request, close=lambda: None)
    transport = gcp.Transport(SimpleNamespace(headers=lambda: {"Authorization": "Bearer sensitive-token"}, close=lambda: None),
                              options, sleep=lambda _: None)
    monkeypatch.setattr(transport, "_session", lambda: session)
    return transport, calls


@pytest.mark.parametrize("service,segment", [("vpcaccess", "connectors"), ("file", "instances"), ("redis", "instances")])
def test_managed_network_hosts_pass_the_real_transport_boundary(monkeypatch, service, segment):
    transport, calls = http_transport(monkeypatch, [Response(200, {segment: []})], retries=0)
    value, _ = transport.request("GET", f"https://{service}.googleapis.com/v1/projects/p-one/locations/us-central1/{segment}", scope="projects/p-one")
    assert value == {segment: []}
    assert len(calls) == 1 and calls[0]["allow_redirects"] is False


def test_transport_retries_and_budget_count_each_attempt_redacts_api_messages(monkeypatch):
    data = {"error": {"message": "Bearer sensitive-token private-secret", "details": [{"reason": "SERVICE_DISABLED"}]}}
    transport, calls = http_transport(monkeypatch, [Response(503, data), Response(403, data)], retries=2)
    with pytest.raises(gcp.ReadError) as caught:
        transport.request("GET", "https://cloudasset.googleapis.com/v1/projects/p-one/assets", scope="projects/p-one")
    assert caught.value.status == "unavailable"
    assert caught.value.error["reason"] == "SERVICE_DISABLED"
    assert transport.calls == 2
    assert transport.evidence[0]["attempts"] == 2
    assert "sensitive-token" not in json.dumps(transport.evidence)
    assert calls[0]["allow_redirects"] is False


def test_transport_keeps_service_disabled_consumer_and_service_through_the_request_cache(monkeypatch):
    data = {"error": {"details": [{"reason": "SERVICE_DISABLED", "metadata": {"consumer": "projects/p-one",
        "service": "dataproc.googleapis.com", "activationUrl": "https://console.developers.google.com/x"}}]}}
    transport, _ = http_transport(monkeypatch, [Response(403, data)])
    url = "https://dataproc.googleapis.com/v1/projects/p-one/regions/r/clusters"
    for _ in range(2):  # the second read is served from the coalescing cache
        with pytest.raises(gcp.ReadError) as caught:
            transport.request("GET", url, scope="projects/p-one")
        assert caught.value.error == {"code": "api_error", "http_status": 403, "reason": "SERVICE_DISABLED",
                                      "consumer": "projects/p-one", "service": "dataproc.googleapis.com"}
    assert transport.calls == 1


def test_transport_coalesces_requests_and_does_not_store_page_tokens(monkeypatch):
    transport, calls = http_transport(monkeypatch, [Response()])
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: transport.request("GET", "https://compute.googleapis.com/compute/v1/projects/p-one/global/networks",
            params={"pageToken": "sensitive-continuation", "maxResults": 100}, scope="projects/p-one"), range(20)))
    assert len(calls) == 1
    assert len({r[1] for r in results}) == 1
    assert "sensitive-continuation" not in json.dumps(transport.evidence)
    results[0][0]["changed"] = True
    assert "changed" not in results[1][0]


def test_real_http_transport_preserves_cursor_until_all_native_pages_are_read(monkeypatch):
    transport, calls = http_transport(monkeypatch, [
        Response(data={'items': [{'name': 'first'}], 'nextPageToken': 'opaque-page-cursor', 'accessToken': 'credential-sentinel'}),
        Response(data={'items': [{'name': 'second'}]})])
    result = gcp.GCPCollector(connector(['network']), transport=transport).collect()
    native = collection(result, 'network')
    assert native['status'] == 'collected' and len(native['items']) == 2
    assert [row['name'] for row in native['items']] == ['first', 'second']
    assert len(calls) == 2 and calls[1]['params']['pageToken'] == 'opaque-page-cursor'
    encoded = json.dumps(result)
    assert 'opaque-page-cursor' not in encoded and 'credential-sentinel' not in encoded
    assert 'sensitive-token' not in json.dumps(transport.evidence)


@pytest.mark.parametrize('mode', ['denied_second', 'page_limit', 'repeated_cursor'])
def test_http_native_cursor_failures_preserve_partial_instead_of_certifying_first_page(monkeypatch, mode):
    second = Response(403, {}) if mode == 'denied_second' else Response(data={'items': [{'name': 'second'}], 'nextPageToken': 'cursor'})
    transport, calls = http_transport(monkeypatch, [Response(data={'items': [{'name': 'first'}], 'nextPageToken': 'cursor'}), second], retries=0)
    result = gcp.GCPCollector(connector(['network'], **({'max_pages': 1} if mode == 'page_limit' else {})), transport=transport).collect()
    assert collection(result, 'network')['status'] == 'partial'
    assert len(calls) == (1 if mode == 'page_limit' else 2)
    assert 'cursor' not in json.dumps(result)


@pytest.mark.parametrize('token', [0, False, [], {}, ['cursor']])
def test_malformed_native_pagination_cursor_cannot_claim_a_complete_inventory(monkeypatch, token):
    transport, _ = http_transport(monkeypatch, [Response(data={'items': [{'name': 'first'}], 'nextPageToken': token})])
    result = gcp.GCPCollector(connector(['network']), transport=transport).collect()
    native = collection(result, 'network')
    assert native['status'] == 'partial'
    assert native['error']['code'] == 'malformed_pagination_token'


def test_transport_budget_stops_transient_retries(monkeypatch):
    transport, calls = http_transport(monkeypatch, [Response(503, {})], retries=5, max_calls=2)
    with pytest.raises(gcp.ReadError, match="call_limit"):
        transport.request("GET", "https://compute.googleapis.com/compute/v1/projects/p-one/global/networks")
    assert len(calls) == 2


@pytest.mark.parametrize("service,segment", [
    ("certificatemanager", "certificates"),
    ("networksecurity", "serverTlsPolicies"),
])
def test_compliance_service_metadata_reaches_http_transport(monkeypatch, service, segment):
    transport, calls = http_transport(monkeypatch, [Response(data={})])
    url = f"https://{service}.googleapis.com/v1/projects/p-one/locations/global/{segment}"
    transport.request("GET", url, scope="projects/p-one")
    assert len(calls) == 1 and calls[0]["url"] == url
    with pytest.raises(gcp.ReadError, match="cloud_mutation_prohibited"):
        transport.request("POST", url, scope="projects/p-one")
    assert len(calls) == 1


@pytest.mark.parametrize("method,url,params,body", [
    ("GET", "https://biglake.googleapis.com/iceberg/v1/restcatalog/extensions/projects/p-one1/catalogs",
     {"view": "CATALOG_VIEW_BASIC", "page-size": 100}, None),
    ("GET", "https://biglake.googleapis.com/v1/projects/p-one1/catalogs/c1/namespaces/n1/tables/t1:getIamPolicy",
     {"options.requestedPolicyVersion": 3}, None),
    ("GET", "https://cloudtasks.googleapis.com/v2/projects/p-one1/locations/us-central1/queues",
     {"pageSize": 100, "pageToken": "cursor"}, None),
    ("POST", "https://cloudtasks.googleapis.com/v2/projects/p-one1/locations/us-central1/queues/q1:getIamPolicy",
     None, {"options": {"requestedPolicyVersion": 3}}),
    ("GET", "https://dataform.googleapis.com/v1/projects/p-one1/locations/us-central1/repositories/r1:getIamPolicy",
     None, None),
    ("GET", "https://firebaseapphosting.googleapis.com/v1/projects/p-one1/locations/us-central1/backends",
     {"pageSize": 100}, None),
])
def test_privesc_read_routes_reach_http_with_exact_project(monkeypatch, method, url, params, body):
    transport, calls = http_transport(monkeypatch, [Response()])
    transport.request(method, url, scope="projects/p-one1", params=params, body=body)
    assert len(calls) == 1 and calls[0]["url"] == url and calls[0]["allow_redirects"] is False


@pytest.mark.parametrize("method,url,params,body", [
    ("GET", "https://biglake.googleapis.com.evil.example/iceberg/v1/restcatalog/extensions/projects/p-one1/catalogs", None, None),
    ("GET", "https://:secret@biglake.googleapis.com/iceberg/v1/restcatalog/extensions/projects/p-one1/catalogs", None, None),
    ("GET", "https://biglake.googleapis.com/iceberg/v1/restcatalog/extensions/projects/other/catalogs", None, None),
    ("GET", "https://biglake.googleapis.com/iceberg/v1/restcatalog/extensions/projects/p-one1/%2e%2e/catalogs", None, None),
    ("GET", "https://biglake.googleapis.com/iceberg/v1/restcatalog/extensions/projects/p-one1/catalogs?access_token=x", None, None),
    ("GET", "https://biglake.googleapis.com/iceberg/v1/restcatalog/extensions/projects/p-one1/catalogs", {"access_token": "x"}, None),
    ("GET", "https://cloudtasks.googleapis.com/v2/projects/p-one1/locations/us-central1/queues/q1/tasks", None, None),
    ("POST", "https://cloudtasks.googleapis.com/v2/projects/p-one1/locations/us-central1/queues/q1:purge", None, {}),
    ("POST", "https://cloudtasks.googleapis.com/v2/projects/p-one1/locations/us-central1/queues/q1:getIamPolicy", None, {"options": {"requestedPolicyVersion": 1}}),
    ("GET", "https://dataform.googleapis.com/v1/projects/other/locations/us-central1/repositories", None, None),
    ("GET", "https://firebaseapphosting.googleapis.com/v1/projects/p-one1/locations/us-central1/backends", {"pageToken": "cursor", "api_key": "x"}, None),
])
def test_privesc_read_routes_reject_unsafe_boundary(monkeypatch, method, url, params, body):
    transport, calls = http_transport(monkeypatch, [Response()])
    with pytest.raises(gcp.ReadError, match="unsafe_api_endpoint"):
        transport.request(method, url, scope="projects/p-one1", params=params, body=body)
    assert calls == []


@pytest.mark.parametrize("method,url,code", [
    ("GET", "https://attacker.example/x", "unsafe_api_endpoint"),
    ("GET", "http://compute.googleapis.com/x", "unsafe_api_endpoint"),
    ("GET", "https://compute.googleapis.com/x?access_token=sensitive", "unsafe_api_endpoint"),
    ("GET", "https://user:pass@compute.googleapis.com/x", "unsafe_api_endpoint"),
    ("POST", "https://compute.googleapis.com/compute/v1/projects/p-one/global/networks", "cloud_mutation_prohibited"),
    ("DELETE", "https://compute.googleapis.com/x", "cloud_mutation_prohibited"),
    ("GET", "https://secretmanager.googleapis.com/v1/projects/p-one/secrets/s/versions/latest:access", "sensitive_value_read_prohibited"),
    ("GET", "https://iam.googleapis.com/v1/projects/p-one/serviceAccounts/a/keys/k", "sensitive_value_read_prohibited")])
def test_transport_rejects_mutations_secret_values_and_unsafe_origins(monkeypatch, method, url, code):
    transport, calls = http_transport(monkeypatch, [Response()])
    with pytest.raises(gcp.ReadError, match=code):
        transport.request(method, url)
    assert calls == []


def test_authentication_failure_never_falls_back_or_returns_credential_details(monkeypatch):
    import google.auth
    monkeypatch.setattr(google.auth, "default", lambda **kwargs: (_ for _ in ()).throw(RuntimeError("private-key secret")))
    monkeypatch.setattr(gcp, "_gcloud", lambda *args: pytest.fail("unrelated gcloud fallback"))
    result = gcp.collect({**connector(["network"]), "auth": {"method": "adc"}})
    assert collection(result, "network")["status"] == "denied"
    assert collection(result, "network")["error"]["code"] == "credential_initialization_failed"
    assert "private-key secret" not in json.dumps(result)


@pytest.mark.parametrize("auth,method", [({"sa_json": {}}, "service-account"), ({"service_account_file": ""}, "service-account"),
    ({"external_account_json": {}}, "external-account"), ({"external_account_file": ""}, "external-account"), ({"token": ""}, "token")])
def test_empty_explicit_credentials_are_failures_in_the_selected_source_not_adc_fallback(monkeypatch, auth, method):
    import google.auth
    monkeypatch.setattr(google.auth, "default", lambda **kwargs: pytest.fail("empty explicit credential fell back to ADC"))
    result = gcp.collect({**connector(["network"]), "auth": auth})
    assert result["metadata"]["auth_method"] == method
    assert collection(result, "network")["status"] == "denied"


@pytest.mark.parametrize("auth", [[], "invalid"])
def test_malformed_auth_objects_do_not_select_default_credentials(auth):
    with pytest.raises(ValueError, match="auth must be an object"):
        gcp.collect({**connector(["network"]), "auth": auth})


def test_unsupported_auth_method_never_serializes_arbitrary_auth_values():
    result = gcp.collect({**connector(["network"]), "auth": {"method": "sensitive-pasted-value"}})
    assert result["metadata"]["auth_method"] == "unsupported"
    assert "sensitive-pasted-value" not in json.dumps(result)


@pytest.mark.parametrize("auth", [
    {"method": "service-account", "service_account_file": "/nonexistent/key.json"},
    {"method": "service-account", "sa_json": '{"private_key":"sensitive"}'},
    {"method": "external-account", "external_account_file": "/nonexistent/wif.json"},
    {"method": "impersonation", "target_principal": "target@example.org"},
    {"method": "not-supported"},
])
def test_explicit_auth_branch_failures_are_redacted_and_never_fallback(monkeypatch, auth):
    import google.auth
    monkeypatch.setattr(google.auth, "default", lambda **kwargs: pytest.fail("unrelated ADC fallback"))
    result = gcp.collect({**connector(["network"]), "auth": auth})
    assert collection(result, "network")["status"] in ("denied", "unknown")
    assert "sensitive" not in json.dumps(result)
    assert "/nonexistent" not in json.dumps(result)


def test_gcloud_pins_account_and_impersonation_across_refresh(monkeypatch):
    commands = []
    def cli(command, env):
        commands.append((list(command), dict(env)))
        if command == ["config", "get-value", "account"]:
            return "selected@example.org"
        if command == ["config", "get-value", "auth/impersonate_service_account"]:
            return "target@example.org"
        return "sensitive-token"
    monkeypatch.setattr(gcp, "_gcloud", cli)
    credentials = gcp.Credentials({"method": "gcloud"})
    credentials.headers()
    monkeypatch.setenv("CLOUDSDK_CORE_ACCOUNT", "different@example.org")
    monkeypatch.setenv("CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT", "different-target@example.org")
    credentials.gcloud.expires = 0
    credentials.headers()
    for command, env in commands[2:]:
        assert command[command.index("--account") + 1] == "selected@example.org"
        assert command[command.index("--impersonate-service-account") + 1] == "target@example.org"
        assert env["CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT"] == "target@example.org"


def test_gcloud_auth_refresh_failure_is_redacted(monkeypatch):
    tokens = []
    def cli(command, env):
        if command[0] == "config":
            return "selected@example.org"
        tokens.append(command)
        raise gcp.ReadError("denied", "gcloud_auth_failed")
    monkeypatch.setattr(gcp, "_gcloud", cli)
    credentials = gcp.Credentials({"method": "gcloud"})
    with pytest.raises(gcp.ReadError, match="gcloud_auth_failed"):
        credentials.headers()
    with pytest.raises(gcp.ReadError, match="gcloud_auth_failed"):
        credentials.headers()
    assert len(tokens) == 1


@pytest.mark.parametrize("method", ["adc", "service-account", "external-account", "metadata", "impersonation"])
def test_google_auth_success_selects_only_requested_branch_and_refresh_failure_is_safe(monkeypatch, tmp_path, method):
    import google.auth
    from google.auth import compute_engine, impersonated_credentials
    from google.oauth2 import service_account
    calls = []
    class FakeCredential:
        def before_request(self, request, verb, url, headers):
            headers["Authorization"] = "Bearer sensitive-token"
    fake = FakeCredential()
    def factory(branch):
        def construct(*args, **kwargs):
            calls.append((branch, args, kwargs))
            return (fake, "p-one") if branch in ("adc", "external-account") else fake
        return construct
    monkeypatch.setattr(google.auth, "default", factory("adc"))
    monkeypatch.setattr(google.auth, "load_credentials_from_dict", factory("external-account"))
    monkeypatch.setattr(service_account.Credentials, "from_service_account_info", factory("service-account"))
    monkeypatch.setattr(compute_engine, "Credentials", factory("metadata"))
    monkeypatch.setattr(impersonated_credentials, "Credentials", factory("impersonation"))
    path = tmp_path / "wif.json"
    path.write_text(json.dumps({"type": "external_account", "token_url": "https://sts.googleapis.com/v1/token",
                               "credential_source": {"file": "/identity/token"}}))
    auth = {"method": method, "sa_json": {"type": "service_account"}, "external_account_file": str(path),
        "source_auth": {"method": "adc"}, "target_principal": "target@example.org", "delegates": ["delegate@example.org"]}
    credentials = gcp.Credentials(auth)
    assert credentials.headers()["Authorization"].startswith("Bearer ")
    assert [c[0] for c in calls] == (["adc", "impersonation"] if method == "impersonation" else [method])
    if method == "impersonation":
        assert calls[-1][2]["delegates"] == ["delegate@example.org"]
        assert calls[-1][2]["target_scopes"] == gcp.OAUTH_SCOPES
    fake.before_request = lambda *args: (_ for _ in ()).throw(RuntimeError("private-token refresh failed"))
    with pytest.raises(gcp.ReadError, match="credential_refresh_failed") as caught:
        credentials.headers()
    assert "private-token" not in str(caught.value)
    credentials.close()


def test_external_account_rejects_other_credential_types(monkeypatch, tmp_path):
    path = tmp_path / "wrong.json"
    path.write_text('{"type":"authorized_user","refresh_token":"sensitive"}')
    import google.auth
    monkeypatch.setattr(google.auth, "load_credentials_from_file", lambda *a, **k: pytest.fail("wrong loader"))
    with pytest.raises(gcp.ReadError, match="external_account_config_required"):
        gcp.Credentials({"method": "external-account", "external_account_file": str(path)})


def test_delegated_impersonation_accepts_only_the_explicit_pinned_gcloud_source(monkeypatch):
    from google.auth import impersonated_credentials
    monkeypatch.setattr(gcp, "_gcloud", lambda command, env: "sensitive-source-token")
    captured = {}
    def factory(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(before_request=lambda *args: None)
    monkeypatch.setattr(impersonated_credentials, "Credentials", factory)
    credentials = gcp.Credentials({"method": "impersonation", "source_auth": {"method": "gcloud",
        "account": "chosen@example.org", "impersonate_service_account": ""},
        "target_principal": "target@example.org", "delegates": ["delegate@example.org"]})
    captured["source_credentials"].refresh(None)
    assert captured["source_credentials"].token == "sensitive-source-token"
    assert captured["target_principal"] == "target@example.org"
    assert captured["delegates"] == ["delegate@example.org"]
    assert credentials.source.gcloud.env["CLOUDSDK_CORE_ACCOUNT"] == "chosen@example.org"
    credentials.close()


def test_shared_vpc_resources_page_without_losing_host_ownership():
    def resolve(request):
        if request["url"].endswith("/projects/p-one"):
            return {"kind": "compute#project", "name": "p-one", "xpnProjectStatus": "HOST"}
        if request["url"].endswith("getXpnHost"):
            return {"name": "host"}
        if request["params"].get("pageToken"):
            return {"resources": [{"id": "p-b", "type": "PROJECT"}]}
        return {"resources": [{"id": "p-a", "type": "PROJECT"}], "nextPageToken": "next"}
    result, transport = snapshot(["shared_vpc"], resolve)
    items = collection(result, "shared_vpc")["items"]
    assert len(items) == 3
    assert {item["serviceProject"] for item in items} == {"projects/p-one", "p-a", "p-b"}
    assert transport.calls == 4


def test_project_iam_denial_still_collects_available_resource_iam():
    def resolve(request):
        if request["url"].endswith(":getIamPolicy"):
            raise gcp.ReadError("denied", "api_error", http_status=403)
        return {"results": [{"resource": "//storage.googleapis.com/b", "policy": {"bindings": []}}]}
    result, transport = snapshot(["iam_policy"], resolve)
    found = collection(result, "iam_policy")
    assert found["status"] == "partial"
    assert found["items"][0]["name"] == "//storage.googleapis.com/b"
    assert found["error"]["kind"] == "denied"
    assert transport.calls == 2


def test_org_descendant_discovery_filters_projects_before_service_reads():
    def resolve(request):
        if request["url"].endswith("/assets"):
            assert request["params"]["assetTypes"] == ["cloudresourcemanager.googleapis.com/Project"]
            return {"assets": [{"name": "//cloudresourcemanager.googleapis.com/projects/1", "resource": {"data": {"projectId": "p-one"}}},
                {"name": "//cloudresourcemanager.googleapis.com/projects/2", "resource": {"data": {"projectId": "p-excluded"}}}]}
        return {"items": []}
    result, transport = snapshot(["network"], resolve, scopes=["organizations/12"], discover_projects=True,
                                 project_restrictions=["p-one"])
    assert result["metadata"]["resolved_scopes"] == ["organizations/12", "projects/p-one"]
    assert not any("p-excluded" in request["url"] for request in transport.requests)


def test_deny_policy_list_hydrates_rules_and_conditions():
    name = "policies/cloudresourcemanager.googleapis.com%2Fprojects%2Fp-one/denypolicies/p"
    def resolve(request):
        if request["url"].endswith("/denypolicies"):
            return {"policies": [{"name": name}]}
        return {"name": name, "rules": [{"denyRule": {"deniedPrincipals": ["principalSet://goog/public:all"],
            "deniedPermissions": ["storage.googleapis.com/objects.get"], "denialCondition": {"expression": "true"}}}]}
    result, _ = snapshot(["iam_deny_policy"], resolve)
    assert collection(result, "iam_deny_policy")["items"][0]["rules"][0]["denyRule"]["denialCondition"]


def test_gke_unreachable_zone_marks_partial_not_complete():
    result, _ = snapshot(["gke_cluster"], lambda r: {"clusters": [{"name": "known", "location": "r-a"}],
        "missingZones": ["r-b"]})
    assert collection(result, "gke_cluster")["status"] == "partial"
    assert collection(result, "gke_cluster")["error"]["code"] == "unreachable_locations"


def test_sanitize_drops_inline_environment_and_project_metadata_values():
    result = gcp.sanitize({"environmentVariables": {"PASSWORD": "sensitive"},
        "env": [{"name": "PASSWORD", "value": "sensitive"}, {"name": "SECRET", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}}],
        "commonInstanceMetadata": {"items": [{"key": "ssh-keys", "value": "sensitive"}, {"key": "serial-port-enable", "value": "FALSE"}]}})
    assert "sensitive" not in json.dumps(result)
    assert result["env"][1]["valueFrom"]["secretKeyRef"]["name"] == "s"
    assert result["commonInstanceMetadata"]["items"][1]["value"] == "FALSE"


def test_inline_external_account_uses_subject_supplier_without_source_execution(monkeypatch):
    from google.auth import identity_pool
    captured = {}
    def factory(info, **kwargs):
        captured.update(info=info, **kwargs)
        return SimpleNamespace(before_request=lambda *a: None)
    monkeypatch.setattr(identity_pool.Credentials, "from_info", factory)
    credentials = gcp.Credentials({"method": "external-account", "external_account_json": {
        "type": "external_account", "token_url": "https://sts.googleapis.com/v1/token",
        "audience": "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/a",
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt", "credential_source": {"url": "https://untrusted.example/token"}},
        "subject_token": "private-subject-token"})
    assert "credential_source" not in captured["info"]
    assert captured["info"]["subject_token_supplier"].get_subject_token(None, None) == "private-subject-token"
    credentials.close()


@pytest.mark.parametrize("config,code", [
    ({"token_url": "https://untrusted.example/token"}, "unsafe_external_token_endpoint"),
    ({"service_account_impersonation_url": "https://untrusted.example/token"}, "unsafe_external_impersonation_endpoint"),
    ({"credential_source": {"executable": {"command": "touch /tmp/untrusted"}}}, "external_executable_source_prohibited"),
    ({"credential_source": {"url": "https://untrusted.example/token"}}, "external_source_requires_local_file_or_inline_token"),
])
def test_external_config_destinations_validated_before_loading(config, code):
    info = {"type": "external_account", "token_url": "https://sts.googleapis.com/v1/token", "credential_source": {"file": "/token"}, **config}
    with pytest.raises(gcp.ReadError, match=code):
        gcp.validate_external_config(info)


@pytest.mark.parametrize("field,value", [("service_account_impersonation_url", {}), ("service_account_impersonation_url", 123),
                                         ("credential_source", {"environment_id": "aws1", "url": None})])
def test_malformed_external_destinations_produce_only_safe_validator_errors(field, value):
    with pytest.raises(gcp.ReadError):
        gcp.validate_external_config({"type": "external_account", "token_url": "https://sts.googleapis.com/v1/token", field: value})


def test_inline_external_account_requires_explicit_ephemeral_token():
    with pytest.raises(gcp.ReadError, match="inline_subject_token_required"):
        gcp.Credentials({"method": "external-account", "external_account_json": {"type": "external_account",
            "token_url": "https://sts.googleapis.com/v1/token"}})


def test_engine_evaluation_remains_offline_and_sealed_with_native_bucket_facts():
    from peaso.engine import evaluate_snapshot
    result, transport = snapshot(["bucket"], lambda r: {"bindings": []} if r["url"].endswith("/iam") else
        {"items": [{"name": "bucket", "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True},
            "publicAccessPrevention": "enforced"}}]})
    calls = transport.calls
    report = evaluate_snapshot(result, categories=["hardening", "exposure"])
    assert transport.calls == calls
    assert report["snapshot_id"] == result["snapshot_id"]
    assert any(f["check_id"] == "gcp.storage.uniform_access" and f["status"] == "PASS" for f in report["findings"])


def test_direct_bigquery_artifact_run_functions_metadata_has_no_payload_reads():
    def resolve(request):
        url = request["url"]
        if url == "https://cloudfunctions.googleapis.com/v2/projects/p-one/locations":
            return {"locations": [{"name": "projects/p-one/locations/r", "locationId": "r"}]}
        if url.endswith(":getIamPolicy"):
            return {"version": 3, "bindings": []}
        if url.endswith("/datasets"):
            return {"datasets": [{"datasetReference": {"projectId": "p-one", "datasetId": "d"}}]}
        if url.endswith("/datasets/d"):
            assert request["params"] == {"accessPolicyVersion": 3, "datasetView": "FULL"}
            return {"datasetReference": {"projectId": "p-one", "datasetId": "d"},
                "access": [], "defaultEncryptionConfiguration": {"kmsKeyName": "projects/p-one/locations/r/keyRings/a/cryptoKeys/k"}}
        if url.endswith("/repositories"):
            return {"repositories": [{"name": "projects/p-one/locations/r/repositories/a", "format": "DOCKER",
                "dockerConfig": {"immutableTags": True}}]}
        if url.endswith("/services"):
            return {"services": [{"name": "projects/p-one/locations/r/services/s", "ingress": "INGRESS_TRAFFIC_INTERNAL_ONLY",
                "template": {"containers": [{"env": [{"name": "PASSWORD", "value": "sensitive-inline-value"}]}]}}]}
        if url.endswith("/functions"):
            return {"functions": [{"name": "projects/p-one/locations/r/functions/f", "serviceConfig": {
                "ingressSettings": "ALLOW_INTERNAL_ONLY", "environmentVariables": {"PASSWORD": "sensitive-inline-value"}}}]}
        pytest.fail("unplanned API read: " + url)
    result, transport = snapshot(["bigquery_dataset", "artifact_repository", "cloudrun_service", "function"], resolve,
        cloudrun_locations=["r"], artifactregistry_locations=["r"])
    assert all(c["status"] == "collected" for c in result["collections"])
    assert collection(result, "bigquery_dataset")["items"][0]["access"] == []
    assert collection(result, "cloudrun_service")["items"][0]["iamPolicy"]["version"] == 3
    assert "sensitive-inline-value" not in json.dumps(result)
    assert not any("tabledata" in request["url"] or ":download" in request["url"] for request in transport.requests)


def test_run_location_discovery_never_uses_unsupported_wildcard():
    def resolve(request):
        if request["url"].endswith("/locations"):
            return {"locations": [{"name": "projects/p-one/locations/r-a", "locationId": "r-a"}]}
        assert "/locations/r-a/services" in request["url"]
        return {"services": []}
    result, transport = snapshot(["cloudrun_service"], resolve)
    assert collection(result, "cloudrun_service")["status"] == "empty"
    assert transport.calls == 2
    assert not any("/locations/-/services" in request["url"] for request in transport.requests)


def test_unreadable_region_does_not_hide_readable_other_region():
    def resolve(request):
        if "/locations/r-denied/" in request["url"]:
            raise gcp.ReadError("denied", "api_error", http_status=403)
        if request["url"].endswith(":getIamPolicy"):
            return {"bindings": []}
        return {"services": [{"name": "projects/p-one/locations/r-good/services/s"}]}
    result, transport = snapshot(["cloudrun_service"], resolve, cloudrun_locations=["r-denied", "r-good"])
    found = collection(result, "cloudrun_service")
    assert found["status"] == "partial"
    assert len(found["items"]) == 1
    assert found["error"]["kind"] == "denied"


def test_bigquery_detail_denial_does_not_imply_dataset_acl_is_empty():
    def resolve(request):
        if request["url"].endswith("/datasets"):
            return {"datasets": [{"datasetReference": {"projectId": "p-one", "datasetId": "d"}}]}
        raise gcp.ReadError("denied", "api_error", http_status=403)
    result, _ = snapshot(["bigquery_dataset"], resolve)
    item = collection(result, "bigquery_dataset")["items"][0]
    assert "access" not in item
    assert item["_coverage"]["datasetDetails"]["status"] == "denied"


def test_hierarchy_firewall_parent_is_full_org_or_folder_name():
    def resolve(request):
        assert request["params"]["parentId"] == request["scope"]
        assert request["url"] == "https://compute.googleapis.com/compute/v1/locations/global/firewallPolicies"
        return {"items": []}
    result, transport = snapshot(["firewall_policy"], resolve, scopes=["organizations/12", "folders/34"])
    assert all(c["status"] == "empty" for c in result["collections"])


def test_empty_project_and_ancestor_firewall_policies_prove_hierarchy_absence():
    def resolve(request):
        if request["url"].endswith(":getAncestry"):
            return {"ancestor": [{"resourceId": {"type": "project", "id": "123"}},
                {"resourceId": {"type": "folder", "id": "34"}},
                {"resourceId": {"type": "organization", "id": "12"}}]}
        if request["url"].endswith("/aggregated/firewallPolicies"):
            return {"items": {}}
        if request["url"].endswith("/firewallPolicies/listAssociations"):
            return {"kind": "compute#FirewallPoliciesListAssociations", "associations": []}
        if request["url"].endswith("/locations/global/firewallPolicies"):
            return {"items": []}
        raise AssertionError(request["url"])
    result, transport = snapshot(["firewall_policy", "firewall_policy_association"], resolve, include_inherited=True)
    proof = result["metadata"]["network_context"]["gcp"]["firewall_hierarchy"]
    assert proof["status"] == "collected" and proof["complete"] is True and proof["policies"] == []
    assert {e["path"] for e in proof["source_evidence"]} == {
        "projects/p-one:getAncestry", "collections.firewall_policy[projects/p-one]",
        "collections.firewall_policy_association[folders/34]",
        "collections.firewall_policy_association[organizations/12]"}
    assert sum(r["url"].endswith("/locations/global/firewallPolicies") for r in transport.requests) == 2


def test_network_firewall_policy_attachment_prevents_empty_hierarchy_proof():
    def resolve(request):
        if request["url"].endswith(":getAncestry"):
            return {"ancestor": [{"resourceId": {"type": "project", "id": "123"}},
                {"resourceId": {"type": "organization", "id": "12"}}]}
        if request["url"].endswith("/global/networks"):
            return {"items": [{"name": "net", "selfLink": "projects/p-one/global/networks/net",
                "firewallPolicy": "projects/p-one/global/firewallPolicies/policy"}]}
        if request["url"].endswith("/aggregated/firewallPolicies"):
            return {"items": {}}
        if request["url"].endswith("/firewallPolicies/listAssociations"):
            return {"kind": "compute#FirewallPoliciesListAssociations", "associations": []}
        if request["url"].endswith("/locations/global/firewallPolicies"):
            return {"items": []}
        raise AssertionError(request["url"])
    result, _ = snapshot(["network", "firewall_policy", "firewall_policy_association"], resolve, include_inherited=True)
    assert "network_context" not in result["metadata"]


def test_denied_ancestor_firewall_inventory_cannot_prove_hierarchy_absence():
    def resolve(request):
        if request["url"].endswith(":getAncestry"):
            return {"ancestor": [{"resourceId": {"type": "project", "id": "123"}},
                {"resourceId": {"type": "organization", "id": "12"}}]}
        if request["url"].endswith("/aggregated/firewallPolicies"):
            return {"items": {}}
        if request["url"].endswith("/locations/global/firewallPolicies"):
            return {"items": []}
        raise gcp.ReadError("denied", "api_error", http_status=403)
    result, _ = snapshot(["firewall_policy", "firewall_policy_association"], resolve, include_inherited=True)
    assert "network_context" not in result["metadata"]
    assert collection(result, "firewall_policy_association", "organizations/12")["status"] == "denied"


def test_policy_owned_elsewhere_but_attached_to_ancestor_prevents_empty_proof():
    def resolve(request):
        if request["url"].endswith(":getAncestry"):
            return {"ancestor": [{"resourceId": {"type": "project", "id": "123"}},
                {"resourceId": {"type": "folder", "id": "34"}}]}
        if request["url"].endswith("/aggregated/firewallPolicies"):
            return {"items": {}}
        if request["url"].endswith("/locations/global/firewallPolicies"):
            return {"items": []}
        if request["url"].endswith("/firewallPolicies/listAssociations"):
            return {"kind": "compute#FirewallPoliciesListAssociations", "associations": [
                {"name": "outside-policy", "attachmentTarget": "folders/34", "firewallPolicyId": "567"}]}
        raise AssertionError(request["url"])
    result, _ = snapshot(["firewall_policy", "firewall_policy_association"], resolve, include_inherited=True)
    assert "network_context" not in result["metadata"]
    assert collection(result, "firewall_policy_association", "folders/34")["status"] == "collected"


def test_unassociated_project_firewall_policy_does_not_hide_empty_effective_hierarchy():
    def resolve(request):
        if request["url"].endswith(":getAncestry"):
            return {"ancestor": [{"resourceId": {"type": "project", "id": "123"}},
                {"resourceId": {"type": "organization", "id": "12"}}]}
        if request["url"].endswith("/aggregated/firewallPolicies"):
            return {"items": {"global": {"firewallPolicies": [{"name": "unused-policy", "rules": [{"action": "deny"}]}]}}}
        if request["url"].endswith("/firewallPolicies/listAssociations"):
            return {"kind": "compute#FirewallPoliciesListAssociations", "associations": []}
        if request["url"].endswith("/locations/global/firewallPolicies"):
            return {"items": []}
        raise AssertionError(request["url"])
    result, _ = snapshot(["firewall_policy", "firewall_policy_association"], resolve, include_inherited=True)
    assert collection(result, "firewall_policy")["status"] == "collected"
    assert result["metadata"]["network_context"]["gcp"]["firewall_hierarchy"]["unaffected_projects"] == ["projects/p-one"]


def test_firewall_hierarchy_proof_is_scoped_to_safe_projects():
    def resolve(request):
        if request["url"].endswith(":getAncestry"):
            return {"ancestor": [{"resourceId": {"type": "project", "id": "123"}},
                {"resourceId": {"type": "organization", "id": "12"}}]}
        if request["url"].endswith("/aggregated/firewallPolicies"):
            association = ([{"attachmentTarget": "projects/p-two/global/networks/main"}]
                if request["scope"] == "projects/p-two" else [])
            return {"items": {"global": {"firewallPolicies": [{"name": "policy", "associations": association}]}}}
        if request["url"].endswith("/firewallPolicies/listAssociations"):
            return {"kind": "compute#FirewallPoliciesListAssociations", "associations": []}
        if request["url"].endswith("/locations/global/firewallPolicies"):
            return {"items": []}
        raise AssertionError(request["url"])
    result, _ = snapshot(["firewall_policy", "firewall_policy_association"], resolve,
        scopes=["projects/p-one", "projects/p-two"], include_inherited=True)
    context = result["metadata"]["network_context"]["gcp"]["firewall_hierarchy"]
    assert context["unaffected_projects"] == ["projects/p-one"]
    assert context["project_ancestors"] == {"projects/p-one": ["organizations/12"]}


@pytest.mark.parametrize("option,value", [("concurrency", 33), ("max_pages", 0), ("max_calls", True),
                                         ("max_resources", -1), ("page_size", 1001)])
def test_invalid_limits_fail_before_collection(option, value):
    with pytest.raises(ValueError, match=option):
        gcp.GCPCollector(connector(["network"], **{option: value}))


def test_full_representation_marker_only_on_unmasked_complete_reads():
    def resolve(request):
        url = request["url"]
        if url.endswith("/iam") or url.endswith(":getIamPolicy"):
            return {"bindings": []}
        if url.endswith("/storage/v1/b"):
            assert request["params"]["projection"] == "full"
            return {"items": [{"name": "bucket"}]}
        if url.endswith("aggregated/subnetworks"):
            return {"items": {"regions/r": {"subnetworks": [{"name": "s", "purpose": "PRIVATE"}]}}}
        if url.endswith("/datasets"):
            return {"datasets": [{"datasetReference": {"projectId": "p-one", "datasetId": "ok"}}, {"datasetReference": {"projectId": "p-one", "datasetId": "denied"}}]}
        if url.endswith("/datasets/ok"):
            assert request["params"]["datasetView"] == "FULL"
            return {"datasetReference": {"projectId": "p-one", "datasetId": "ok"}}
        if url.endswith("/datasets/denied"):
            raise gcp.ReadError("denied", "api_error", http_status=403)
        return {"items": []}
    result, _ = snapshot(["bucket", "subnetwork", "bigquery_dataset"], resolve, concurrency=4)
    assert collection(result, "bucket")["items"][0]["_provenance"]["representation"] == "full"
    assert collection(result, "subnetwork")["items"][0]["_provenance"]["representation"] == "full"
    datasets = {item["datasetReference"]["datasetId"]: item for item in collection(result, "bigquery_dataset")["items"]}
    assert datasets["ok"]["_provenance"]["representation"] == "full"
    assert datasets["denied"]["_provenance"]["representation"] == "partial"
    assert all("_representation" not in item for c in result["collections"] for item in c["items"])


def test_effective_audit_configs_union_organization_folder_and_project():
    org_config = [{"service": "allServices", "auditLogConfigs": [{"logType": "DATA_READ"}, {"logType": "DATA_WRITE"}]}]
    def resolve(request, *, org_denied=False):
        url = request["url"]
        if url.endswith(":getAncestry"):
            return {"ancestor": [{"resourceId": {"type": "project", "id": "p-one"}}, {"resourceId": {"type": "folder", "id": "12"}},
                {"resourceId": {"type": "organization", "id": "34"}}]}
        if url.endswith("organizations/34:getIamPolicy"):
            if org_denied:
                raise gcp.ReadError("denied", "api_error", http_status=403)
            assert request["body"] == {"options": {"requestedPolicyVersion": 3}}
            return {"version": 3, "auditConfigs": org_config}
        if url.endswith(":getIamPolicy"):
            return {"version": 1, "bindings": []}
        return {"results": []}
    result, _ = snapshot(["iam_policy"], resolve, include_inherited=True)
    root = next(i for i in collection(result, "iam_policy")["items"] if i["name"] == "projects/p-one")
    assert [e["scope"] for e in root["effectiveAuditConfigs"]] == ["projects/p-one", "folders/12", "organizations/34"]
    assert root["effectiveAuditConfigs"][2]["auditConfigs"] == org_config
    assert root["_coverage"]["effectiveAuditConfigs"]["status"] == "collected"
    assert root["_coverage"]["effectiveAuditConfigs"]["source_requests"]
    result, _ = snapshot(["iam_policy"], lambda r: resolve(r, org_denied=True), include_inherited=True)
    root = next(i for i in collection(result, "iam_policy")["items"] if i["name"] == "projects/p-one")
    assert root["_coverage"]["effectiveAuditConfigs"]["status"] == "partial"
    assert root["_coverage"]["effectiveAuditConfigs"]["missing_scopes"] == ["organizations/34"]


def test_vpc_flow_logs_configs_collect_project_and_applicable_org_configs():
    def resolve(request):
        url = request["url"]
        assert request["method"] == "GET"
        if url.endswith(":queryOrgVpcFlowLogsConfigs"):
            return {"vpcFlowLogsConfigs": [{"name": "organizations/34/locations/global/vpcFlowLogsConfigs/org", "state": "ENABLED"}]}
        return {"vpcFlowLogsConfigs": [{"name": "projects/p-one/locations/global/vpcFlowLogsConfigs/c",
            "network": "projects/p-one/global/networks/n"}]}
    result, transport = snapshot(["vpc_flow_logs_config"], resolve)
    items = {i["configLevel"]: i for i in collection(result, "vpc_flow_logs_config")["items"]}
    assert set(items) == {"project", "organization"}
    assert all(r["url"].startswith("https://networkmanagement.googleapis.com/v1/projects/p-one/locations/global/") for r in transport.requests)
    disabled, _ = snapshot(["vpc_flow_logs_config"], lambda r: (_ for _ in ()).throw(
        gcp.ReadError("unavailable", "api_error", http_status=403, reason="SERVICE_DISABLED")))
    found = collection(disabled, "vpc_flow_logs_config")
    assert found["status"] == "unknown" and found["error"]["reason"] == "SERVICE_DISABLED"


def test_parallel_hydration_preserves_page_order_and_provenance():
    names = [f"bucket-{i:02d}" for i in range(40)]
    def resolve(request):
        if request["url"].endswith("/iam"):
            return {"bindings": [{"role": "roles/viewer", "members": ["user:" + request["url"].split("/b/")[1].split("/")[0] + "@example.org"]}]}
        return {"items": [{"name": name} for name in names]}
    result, _ = snapshot(["bucket"], resolve, concurrency=8)
    items = collection(result, "bucket")["items"]
    assert sorted(i["name"] for i in items) == names
    for item in items:
        assert item["iamPolicy"]["bindings"][0]["members"] == ["user:" + item["name"] + "@example.org"]
        assert len(item["_provenance"]["source_requests"]) == 2


def test_transport_backs_off_on_quota_errors_honouring_retry_after(monkeypatch):
    throttled = Response(429, {"error": {"details": [{"reason": "RATE_LIMIT_EXCEEDED"}]}})
    throttled.headers = {"Retry-After": "7"}
    transport, calls = http_transport(monkeypatch, [throttled, Response(403, {"error": {"details": [{"reason": "RATE_LIMIT_EXCEEDED"}]}}),
        Response(200, {"items": []})], retries=4)
    sleeps = []
    transport.sleep = sleeps.append
    data, _ = transport.request("GET", "https://compute.googleapis.com/compute/v1/projects/p-one/global/networks")
    assert data == {"items": []} and len(calls) == 3
    assert sleeps[0] == 7 and 0.5 <= sleeps[1] <= 2
    assert gcp.Transport(SimpleNamespace(headers=dict, close=lambda: None), {}).retries == 4
    assert gcp.GCPCollector(connector(["network"], concurrency=32)).workers == 32


def test_claude2_logging_facts_channels_metrics_scopes_and_bucket_name():
    def resolve(request):
        url = request["url"]
        if url.endswith("/notificationChannels"):
            assert request["params"]["fields"] == "notificationChannels(name,type,enabled,verificationStatus),nextPageToken"
            return {"notificationChannels": [{"name": "projects/p-one/notificationChannels/1", "type": "email",
                                              "enabled": True, "verificationStatus": "VERIFIED"}]}
        if url.endswith("/metrics"):
            assert "bucketName" in request["params"]["fields"]
            return {"metrics": [{"name": "m", "filter": "x", "bucketName": "projects/p-one/locations/global/buckets/b"}]}
        if url.endswith(":listMetricsScopesByMonitoredProject"):
            assert request["params"] == {"monitoredResourceContainer": "projects/p-one"}
            return {"metricsScopes": [{"name": "locations/global/metricsScopes/111"}]}
        if url.endswith("/compute/v1/projects/p-one"):
            return {}
        return {"name": "projects/111", "projectId": "p-one"}
    result, transport = snapshot(["monitoring_notification_channel", "logging_metric", "project"], resolve,
                                 include_inherited=False)
    channel = collection(result, "monitoring_notification_channel")["items"][0]
    assert channel["verificationStatus"] == "VERIFIED" and channel["_provenance"]["source_requests"]
    assert collection(result, "logging_metric")["items"][0]["bucketName"].endswith("/buckets/b")
    project = collection(result, "project")["items"][0]
    assert project["_monitoring_metrics_scopes"] == ["locations/global/metricsScopes/111"]
    coverage = project["_coverage"]["_monitoring_metrics_scopes"]
    assert coverage["status"] == "collected" and set(coverage["source_requests"]) <= set(project["_provenance"]["source_requests"])
    assert all(r["method"] == "GET" for r in transport.requests if "monitoring" in r["url"] or "logging" in r["url"])
    def denied(request):
        if request["url"].endswith(":listMetricsScopesByMonitoredProject"):
            raise gcp.ReadError("denied", "api_error", http_status=403)
        return resolve(request)
    result, _ = snapshot(["project"], denied, include_inherited=False)
    project = collection(result, "project")["items"][0]
    assert "_monitoring_metrics_scopes" not in project
    assert project["_coverage"]["_monitoring_metrics_scopes"]["status"] == "denied"


def test_inherited_sinks_attach_every_ancestor_sink_only_when_complete():
    sink = {"name": "agg", "destination": "storage.googleapis.com/b", "filter": "", "includeChildren": True,
            "interceptChildren": False, "exclusions": [{"name": "e", "filter": "x"}], "writerIdentity": "serviceAccount:w"}
    def resolve(request, *, folder_denied=False):
        url = request["url"]
        if url.endswith(":getAncestry"):
            return {"ancestor": [{"resourceId": {"type": "project", "id": "p-one"}}, {"resourceId": {"type": "folder", "id": "12"}},
                {"resourceId": {"type": "organization", "id": "34"}}]}
        if url.endswith("folders/12/sinks"):
            if folder_denied:
                raise gcp.ReadError("denied", "api_error", http_status=403)
            return {"sinks": []}
        if url.endswith("organizations/34/sinks"):
            return {"sinks": [sink]}
        if url.endswith("/sinks"):
            return {"sinks": []}
        if url.endswith(":listMetricsScopesByMonitoredProject"):
            return {"metricsScopes": []}
        if url.endswith(":getIamPolicy"):
            return {"bindings": []}
        if url.startswith("https://cloudresourcemanager.googleapis.com/v3/projects/p-one"):
            return {"name": "projects/111", "projectId": "p-one"}
        return {}
    result, _ = snapshot(["project", "log_sink"], resolve, include_inherited=True)
    project = collection(result, "project")["items"][0]
    assert project["_inherited_sinks"] == [{**{k: v for k, v in sink.items() if k != "writerIdentity"},
                                            "name": "organizations/34/sinks/agg", "ancestor": "organizations/34"}]
    coverage = project["_coverage"]["_inherited_sinks"]
    assert coverage["ancestors"] == ["folders/12", "organizations/34"] and coverage["source_requests"]
    assert set(coverage["source_requests"]) <= set(project["_provenance"]["source_requests"])
    result, _ = snapshot(["project", "log_sink"], lambda r: resolve(r, folder_denied=True), include_inherited=True)
    project = collection(result, "project")["items"][0]
    assert "_inherited_sinks" not in project and "_inherited_sinks" not in project.get("_coverage", {})


def test_inherited_root_iam_policies_attach_to_project_only_when_every_ancestor_is_collected():
    org_binding = {"role": "roles/editor", "members": ["serviceAccount:w@p-one.iam.gserviceaccount.com"]}
    def resolve(request, *, folder_denied=False):
        url = request["url"]
        if url.endswith(":getAncestry"):
            return {"ancestor": [{"resourceId": {"type": "project", "id": "p-one"}}, {"resourceId": {"type": "folder", "id": "12"}},
                {"resourceId": {"type": "organization", "id": "34"}}]}
        if url.endswith("folders/12:getIamPolicy"):
            if folder_denied:
                raise gcp.ReadError("denied", "api_error", http_status=403)
            return {"etag": "f"}
        if url.endswith("organizations/34:getIamPolicy"):
            assert request["method"] == "POST" and request["body"] == {"options": {"requestedPolicyVersion": 3}}
            return {"bindings": [org_binding], "etag": "o", "version": 3}
        if url.endswith(":getIamPolicy"):
            return {"bindings": []}
        if url.startswith("https://cloudresourcemanager.googleapis.com/v3/projects/p-one"):
            return {"name": "projects/111", "projectId": "p-one"}
        return {}
    result, _ = snapshot(["project", "iam_policy"], resolve, include_inherited=True)
    project = collection(result, "project")["items"][0]
    assert project["_inherited_iam_policies"] == [
        {"name": "folders/12", "bindings": [], "etag": "f", "ancestor": "folders/12"},
        {"name": "organizations/34", "bindings": [org_binding], "etag": "o", "version": 3, "ancestor": "organizations/34"}]
    coverage = project["_coverage"]["_inherited_iam_policies"]
    assert coverage["status"] == "collected" and coverage["ancestors"] == ["folders/12", "organizations/34"]
    assert coverage["source_requests"] and set(coverage["source_requests"]) <= set(project["_provenance"]["source_requests"])
    result, _ = snapshot(["project", "iam_policy"], lambda r: resolve(r, folder_denied=True), include_inherited=True)
    project = collection(result, "project")["items"][0]
    assert "_inherited_iam_policies" not in project and "_inherited_iam_policies" not in project.get("_coverage", {})


def test_effective_org_policy_is_read_per_project_with_get_effective_policy():
    def resolve(request):
        assert request["method"] == "GET"
        if request["url"] == "https://cloudresourcemanager.googleapis.com/v3/projects/p-one":
            return {"name": "projects/111", "projectId": "p-one"}
        constraint = request["url"].rsplit("/", 1)[1].split(":")[0]
        return {"name": "projects/111/policies/" + constraint, "spec": {"rules": [{"enforce": True}]}}
    result, transport = snapshot(["org_policy_effective"], resolve)
    # One getEffectivePolicy GET per requested constraint on the project; never a
    # policies.list / listConstraints enumeration.
    requested = set(gcp.ORG_POLICY_CONSTRAINTS)
    assert {"storage.publicAccessPrevention", "compute.requireOsLogin"} <= requested
    urls = [r["url"] for r in transport.requests]
    assert len(urls) == len(requested) + 1 and set(urls) == {
        "https://orgpolicy.googleapis.com/v2/projects/p-one/policies/" + c + ":getEffectivePolicy" for c in requested} | {
        "https://cloudresourcemanager.googleapis.com/v3/projects/p-one"}
    items = collection(result, "org_policy_effective")["items"]
    assert sorted(item["constraint"] for item in items) == sorted(requested)
    assert all(item["_provenance"]["representation"] == "full" and item["_provenance"]["source_requests"] for item in items)
    # One constraint denied: the collection is not complete, so no check reads a partial set.
    def partial(request):
        if "requireOsLogin" in request["url"]:
            raise gcp.ReadError("denied", "api_error", http_status=403)
        return resolve(request)
    partial_result, _ = snapshot(["org_policy_effective"], partial)
    assert collection(partial_result, "org_policy_effective")["status"] != "collected"
    denied, _ = snapshot(["org_policy_effective"], lambda r: (_ for _ in ()).throw(gcp.ReadError("denied", "api_error", http_status=403)))
    assert collection(denied, "org_policy_effective")["status"] == "denied"


def test_restricted_dataproc_region_and_anonymous_bigquery_datasets_are_not_denials():
    def resolve(request):
        url = request["url"]
        if url.endswith("/regions"):
            return {"items": [{"name": "us-central1"}, {"name": "me-central2"}]}
        if "me-central2" in url:
            raise gcp.http_error(403, {"error": {"details": [{"reason": "LOCATION_POLICY_VIOLATED"}]}})
        if "dataproc" in url:
            return {"clusters": [{"name": "projects/p-one/regions/us-central1/clusters/c", "clusterName": "c"}]}
        raise AssertionError(url)
    result, _ = snapshot(["dataproc_cluster"], resolve)
    found = collection(result, "dataproc_cluster")
    assert found["status"] == "collected" and len(found["items"]) == 1
    def denied(request):
        if "me-central2" in request["url"] or "us-central1" in request["url"]:
            raise gcp.http_error(403, {"error": {"details": [{"reason": "IAM_PERMISSION_DENIED"}]}})
        return resolve(request)
    assert collection(snapshot(["dataproc_cluster"], denied)[0], "dataproc_cluster")["status"] == "denied"
    anonymous = "_" + "a" * 40
    def bigquery(request):
        url = request["url"]
        if anonymous in url:
            raise gcp.http_error(403, {"error": {"errors": [{"reason": "accessDenied"}]}})
        if url.endswith("/datasets"):
            return {"datasets": [{"datasetReference": {"projectId": "p-one", "datasetId": anonymous}},
                {"datasetReference": {"projectId": "p-one", "datasetId": "d"}}]}
        if url.endswith("/tables"):
            return {"tables": [{"tableReference": {"projectId": "p-one", "datasetId": "d", "tableId": "t"}}]}
        if "/tables/" in url:
            return {"tableReference": {"projectId": "p-one", "datasetId": "d", "tableId": "t"}, "type": "TABLE"}
        return {"datasetReference": {"projectId": "p-one", "datasetId": url.rsplit("/", 1)[1]}}
    result, transport = snapshot(["bigquery_table"], bigquery)
    tables = collection(result, "bigquery_table")
    assert tables["status"] == "collected" and len(tables["items"]) == 1
    assert not any(anonymous in r["url"] and "/tables" in r["url"] for r in transport.requests)


def test_bigquery_routine_metadata_uses_cached_read_only_iam_policy():
    reference = {"projectId": "p-one", "datasetId": "d", "routineId": "run"}
    policy_url = "https://bigquery.googleapis.com/bigquery/v2/projects/p-one/datasets/d/routines/run:getIamPolicy"
    def resolve(request):
        url = request["url"]
        if url.endswith("/datasets"):
            return {"datasets": [{"datasetReference": {"projectId": "p-one", "datasetId": "d"}}]}
        if url.endswith("/datasets/d"):
            return {"datasetReference": {"projectId": "p-one", "datasetId": "d"}, "access": []}
        if url.endswith("/datasets/d/routines"):
            return {"routines": [{"routineReference": reference, "routineType": "PROCEDURE", "language": "SQL"}]}
        if url == policy_url:
            assert request["method"] == "POST"
            return {"bindings": [{"role": "roles/bigquery.routineDataViewer", "members": ["allUsers"]}]}
        raise AssertionError(url)
    result, transport = snapshot(["bigquery_routine_metadata"], resolve)
    row = collection(result, "bigquery_routine_metadata")["items"][0]
    assert row["_coverage"]["iamPolicy"]["status"] == "collected"
    assert row["iamPolicy"]["bindings"][0]["members"] == ["allUsers"]
    assert sum(request["url"] == policy_url for request in transport.requests) == 1


def test_bigquery_routine_public_custom_role_is_hydrated_once():
    reference = {"projectId": "p-one", "datasetId": "d", "routineId": "run"}
    role = "projects/p-one/roles/useRoutine"
    role_url = "https://iam.googleapis.com/v1/" + role
    def resolve(request):
        url = request["url"]
        if url.endswith("/datasets"):
            return {"datasets": [{"datasetReference": {"projectId": "p-one", "datasetId": "d"}}]}
        if url.endswith("/datasets/d"):
            return {"datasetReference": {"projectId": "p-one", "datasetId": "d"}, "access": []}
        if url.endswith("/datasets/d/routines"):
            return {"routines": [{"routineReference": reference, "routineType": "PROCEDURE", "language": "SQL"}]}
        if url.endswith("/routines/run:getIamPolicy"):
            return {"bindings": [{"role": role, "members": ["allUsers"]}]}
        if url == role_url:
            assert request["method"] == "GET"
            return {"name": role, "includedPermissions": ["bigquery.routines.get"]}
        raise AssertionError(url)
    result, transport = snapshot(["bigquery_routine_metadata", "iam_role"], resolve)
    roles = collection(result, "iam_role")["items"]
    assert len(roles) == 1 and roles[0]["includedPermissions"] == ["bigquery.routines.get"]
    assert sum(request["url"] == role_url for request in transport.requests) == 1


def test_public_bucket_custom_role_is_hydrated_once_for_permission_review():
    role = "projects/p-one/roles/objectReader"
    role_url = "https://iam.googleapis.com/v1/" + role
    def resolve(request):
        url = request["url"]
        if url == "https://storage.googleapis.com/storage/v1/b":
            return {"items": [{"name": "sample-bucket", "iamConfiguration": {
                "uniformBucketLevelAccess": {"enabled": True}, "publicAccessPrevention": "inherited"}}]}
        if url == "https://storage.googleapis.com/storage/v1/b/sample-bucket/iam":
            return {"bindings": [{"role": role, "members": ["allUsers"]}]}
        if url == role_url:
            assert request["method"] == "GET"
            return {"name": role, "includedPermissions": ["storage.objects.get"]}
        raise AssertionError(url)
    result, transport = snapshot(["bucket", "iam_role"], resolve)
    roles = collection(result, "iam_role")["items"]
    assert len(roles) == 1 and roles[0]["includedPermissions"] == ["storage.objects.get"]
    assert sum(request["url"] == role_url for request in transport.requests) == 1


def test_storage_effective_public_grants_use_collected_custom_role_permissions():
    from peaso.collectors.gcp_storage_acl_native import _public_grants
    role = "projects/p-one/roles/objectReader"
    policy = {"bindings": [{"role": role, "members": ["allUsers"]}]}
    class Collector:
        def __init__(self, permissions):
            self.permissions = permissions
        def items(self, kind):
            assert kind == "iam_role"
            return [("projects/p-one", {"name": role, "includedPermissions": self.permissions})]
    assert _public_grants(policy, Collector(["storage.objects.get"])) == (True, False)
    assert _public_grants(policy, Collector(["storage.objects.create"])) == (True, True)
    assert _public_grants(policy, Collector(["logging.logEntries.list"])) == (False, False)
    with pytest.raises(gcp.ReadError, match="storage_public_role_permissions_unresolved"):
        _public_grants(policy, Collector(None))


def test_discovery_search_results_are_metadata_and_kinds_are_evaluated_only_at_native_scope_types():
    def resolve(request):
        url = request["url"]
        if url.endswith("projects:search"):
            return {"projects": [{"projectId": "p-one", "name": "projects/1"}]}
        if url.endswith("organizations:search"):
            return {"organizations": [{"name": "organizations/12"}]}
        if url.endswith("folders:search"):
            return {"folders": []}
        if url.endswith("/contacts"):
            return {"contacts": [{"name": "organizations/12/contacts/1", "email": "sec@example.com"}]}
        if "cloudresourcemanager" in url and "projects/p-one" in url:
            return {"projectId": "p-one", "name": "projects/1"}
        if "cloudresourcemanager" in url and "organizations/12" in url:
            return {"name": "organizations/12"}
        return {"items": []}
    result, _ = snapshot(["bucket", "organization", "project"], resolve, scopes=["*"], all_projects=True, all_hierarchy=True,
                         include_inherited=False)
    assert not [c for c in result["collections"] if c["scope"] == "discovery"]
    discovered = {row["type"]: row for row in result["metadata"]["hierarchy_discovery"]}
    assert discovered["project"]["resource_count"] == 1 and discovered["project"]["source_requests"]
    assert discovered["organization"]["status"] == "collected"
    pairs = {(c["type"], c["scope"]) for c in result["collections"]}
    assert ("bucket", "projects/p-one") in pairs and ("bucket", "organizations/12") not in pairs
    assert ("organization", "organizations/12") in pairs and ("organization", "projects/p-one") not in pairs
    assert result["metadata"]["scope_type_omissions"]["bucket"] == ["organizations"]
    assert "organizations" not in result["metadata"]["scope_type_omissions"].get("organization", [])


def test_subnetwork_and_key_ring_policies_are_hydrated_read_only_with_provenance():
    from peaso.checks import CHECKS
    by_id = {check.id: check for check in CHECKS}
    def resolve(request):
        url = request["url"]
        if url.endswith("aggregated/subnetworks"):
            return {"items": {"regions/us-central1": {"subnetworks": [
                {"name": name, "region": "https://www.googleapis.com/compute/v1/projects/p-one/regions/us-central1"}
                for name in ("empty", "shared", "denied")]}}}
        if url.endswith("/subnetworks/empty/getIamPolicy"):
            return {"etag": "ACAB"}  # documented: empty bindings are omitted
        if url.endswith("/subnetworks/shared/getIamPolicy"):
            return {"bindings": [{"role": "roles/compute.networkUser", "members": ["user:other@example.com"]}]}
        if url.endswith("/subnetworks/denied/getIamPolicy"):
            raise gcp.ReadError("denied", "IAM_PERMISSION_DENIED")
        if url.endswith("/locations"):
            return {"locations": [{"name": "projects/p-one/locations/global"}]}
        if url.endswith("/keyRings"):
            return {"keyRings": [{"name": "projects/p-one/locations/global/keyRings/r"}]}
        if url.endswith("keyRings/r:getIamPolicy"):
            return {"bindings": [{"role": "roles/cloudkms.viewer", "members": ["user:trusted@example.com"]}]}
        return {"items": []}
    result, transport = snapshot(["subnetwork", "kms_key_ring"], resolve)
    policy_reads = [r for r in transport.requests if "getIamPolicy" in r["url"]]
    assert policy_reads and all(r["method"] == "GET" for r in policy_reads)
    assert all(r["params"] in ({"optionsRequestedPolicyVersion": 3}, {"options.requestedPolicyVersion": 3}) for r in policy_reads)
    subnets = {item["name"]: item for item in collection(result, "subnetwork")["items"]}
    for item in subnets.values():
        assert set(item["_coverage"]["iamPolicy"]["source_requests"]) <= set(item["_provenance"]["source_requests"])
        assert item["_coverage"]["iamPolicy"]["source_requests"]
    check = by_id["gcp.claude.subnetwork.policy_shared_access"]
    index = {"context": {"metadata": {"trusted_users": ["trusted@example.com"], "trusted_groups": [], "trusted_domains": [],
                                      "trusted_service_accounts": []}}}
    from peaso.checks.facts import Unavailable
    def run(item, check=check):
        try:
            return check.evaluate(item, index)[0]
        except (Unavailable, KeyError, TypeError, ValueError):
            return "UNKNOWN"
    assert run(subnets["empty"]) == "NOT_APPLICABLE"
    assert run(subnets["shared"]) == "FAIL"
    assert subnets["denied"]["_coverage"]["iamPolicy"]["status"] == "denied" and run(subnets["denied"]) == "UNKNOWN"
    ring = collection(result, "kms_key_ring")["items"][0]
    assert run(ring, by_id["gcp.claude.kms_key_ring.policy_shared_access"]) == "PASS"
    assert ring["_coverage"]["iamPolicy"]["source_requests"][0] in ring["_provenance"]["source_requests"]


def disabled(consumer, service):
    return gcp.http_error(403, {"error": {"details": [{"reason": "SERVICE_DISABLED",
        "metadata": {"consumer": consumer, "service": service}}]}})


def test_cloud_run_lists_v1_locations_and_skips_location_policy_regions():
    def resolve(request):
        url = request["url"]
        if url == "https://run.googleapis.com/v1/projects/p-one/locations":
            return {"locations": [{"name": "projects/p-one/locations/r-a", "locationId": "r-a"},
                                  {"name": "projects/p-one/locations/r-blocked", "locationId": "r-blocked"}]}
        if "/locations/r-blocked/" in url:
            raise gcp.http_error(403, {"error": {"details": [{"reason": "LOCATION_POLICY_VIOLATED"}]}})
        if url.endswith(":getIamPolicy"):
            return {}
        if url.endswith("/locations/r-a/services"):
            return {"services": [{"name": "projects/p-one/locations/r-a/services/s"}]}
        if url.endswith("/locations/r-a/jobs"):
            return {"jobs": []}
        raise AssertionError(url)
    result, transport = snapshot(["cloudrun_service", "cloudrun_job"], resolve)
    services = collection(result, "cloudrun_service")
    assert services["status"] == "collected" and services["items"][0]["iamPolicy"] == {"bindings": []}
    assert collection(result, "cloudrun_job")["status"] == "empty"
    assert not any("/v2/projects/p-one/locations" == r["url"][-len("/v2/projects/p-one/locations"):] for r in transport.requests)


def test_service_disabled_in_target_project_is_unknown_and_quota_project_disablement_stays_unknown():
    def resolve(request):
        url = request["url"]
        if "run.googleapis.com" in url:
            raise disabled("projects/p-one", "run.googleapis.com")
        if "dataproc" in url:
            raise disabled("projects/p-one", "dataproc.googleapis.com")
        if url.endswith("/regions"):
            return {"items": [{"name": "r-a"}, {"name": "r-b"}]}
        if "accessapproval" in url:
            raise disabled("projects/32555940559", "accessapproval.googleapis.com")
        raise AssertionError(url)
    result, transport = snapshot(["cloudrun_service", "dataproc_cluster", "access_approval_settings"], resolve)
    for kind in ("cloudrun_service", "dataproc_cluster"):
        found = collection(result, kind)
        assert found["status"] == "unknown" and found["coverage_status"] == "unavailable"
        assert found["error"]["reason"] == "SERVICE_DISABLED"
        assert found["service_state"]["state"] == "disabled" and found["service_state"]["source_requests"]
        assert set(found["service_state"]["source_requests"]) <= set(found["source_requests"])
    # one disabled-service error per inventory, not one per region
    assert sum("dataproc" in r["url"] for r in transport.requests) == 1
    approval = collection(result, "access_approval_settings")
    assert approval["status"] == "unknown" and approval["error"]["consumer"] == "projects/32555940559"


@pytest.mark.parametrize("kind,service,host", [
    ("bucket", "storage.googleapis.com", "storage.googleapis.com"),
    ("bigquery_dataset", "bigquery.googleapis.com", "bigquery.googleapis.com"),
])
def test_disabled_data_service_for_numeric_project_preserves_unknown_and_control_coverage(kind, service, host):
    from peaso.engine import evaluate_snapshot

    def resolve(request):
        if kind == 'bigquery_dataset' and request['url'] == 'https://cloudresourcemanager.googleapis.com/v3/projects/123':
            return {'name': 'projects/123', 'projectId': 'native-project'}
        assert host in request["url"]
        raise disabled("projects/123", service)

    transport = NativeDataFixtureTransport(resolve)
    result = gcp.GCPCollector(connector([kind], scopes=['projects/123']), transport=transport).collect()
    validate(result)
    found = collection(result, kind, "projects/123")
    assert found["status"] == "unknown" and found["coverage_status"] == "unavailable"
    assert found["items"] == []
    assert found["error"] == {"kind": "unavailable", "code": "api_error", "http_status": 403,
        "reason": "SERVICE_DISABLED", "consumer": "projects/123", "service": service}
    assert found["service_state"] == {"state": "disabled", "reason": "SERVICE_DISABLED",
        "service": service, "consumer": "projects/123", "source_requests": found["source_requests"]}
    check_id = "gcp.storage.uniform_access" if kind == "bucket" else "gcp.reviewed.bigquery.cmek"
    report = evaluate_snapshot(result, checks=[check_id])
    assert transport.calls == (2 if kind == 'bigquery_dataset' else 1)
    assert any(f["check_id"] == check_id and f["status"] == "UNKNOWN" for f in report["findings"])
    assert not any(f["check_id"] == check_id and f["status"] in ("NOT_APPLICABLE", "PASS", "EMPTY")
                   for f in report["findings"])


@pytest.mark.parametrize("kind,response", [("bucket", {"items": []}), ("bigquery_dataset", {"datasets": []})])
def test_successful_empty_data_service_inventory_is_still_empty(kind, response):
    def resolve(request):
        if kind == 'bigquery_dataset' and request['url'] == 'https://cloudresourcemanager.googleapis.com/v3/projects/123':
            return {'name': 'projects/123', 'projectId': 'native-project'}
        return response
    transport = NativeDataFixtureTransport(resolve)
    result = gcp.GCPCollector(connector([kind], scopes=['projects/123']), transport=transport).collect()
    validate(result)
    found = collection(result, kind, "projects/123")
    assert found["status"] == found["coverage_status"] == "empty"
    assert found["items"] == [] and "error" not in found and "service_state" not in found


def test_disabled_quota_project_does_not_mark_numeric_target_service_disabled():
    def resolve(request):
        raise disabled("projects/999", "storage.googleapis.com")

    result, _ = snapshot(["bucket"], resolve, scopes=["projects/123"])
    found = collection(result, "bucket", "projects/123")
    assert found["status"] == "unknown" and found["coverage_status"] == "unavailable"
    assert found["error"]["consumer"] == "projects/999" and "service_state" not in found


def test_disabled_service_after_rows_keeps_partial_inventory_and_metadata():
    transport = FixtureTransport(lambda request: {"items": []})
    collector = gcp.GCPCollector(connector(["bigquery_dataset"], scopes=["projects/123"]), transport=transport)
    error = disabled("projects/123", "bigquery.googleapis.com")
    error.request_id = "request-2"

    def fetch():
        yield [{"name": "projects/123/datasets/existing", "datasetReference": {"datasetId": "existing"}}], "request-1"
        raise error

    found = collector.envelope("bigquery_dataset", "projects/123", "bigquery", fetch)
    assert found["status"] == found["coverage_status"] == "partial"
    assert len(found["items"]) == 1 and found["error"]["reason"] == "SERVICE_DISABLED"
    assert found["source_requests"] == ["request-1", "request-2"]
    assert found["service_state"]["source_requests"] == ["request-2"]


def test_service_account_activity_attaches_policy_analyzer_facts_only_for_listed_accounts():
    from peaso.checks import CHECKS
    check = next(c for c in CHECKS if c.id == "gcp.claude.service_account.recently_used")
    from datetime import datetime, timedelta, timezone
    recent = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%dT00:00:00Z")
    observed = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT00:00:00Z")
    period = {"startTime": "2024-11-28T08:00:00Z", "endTime": observed}
    def account(name):
        return {"name": f"projects/p-one/serviceAccounts/{name}@p-one.iam.gserviceaccount.com",
                "email": f"{name}@p-one.iam.gserviceaccount.com", "uniqueId": str(123456789000000000000 + ["recent", "stale", "never", "unlisted"].index(name))}
    def activity(name, last=None):
        body = {"serviceAccount": {"serviceAccountId": str(123456789000000000000 + ["recent", "stale", "never", "unlisted"].index(name))}}
        if last:
            body["lastAuthenticatedTime"] = last
        return {"fullResourceName": f"//iam.googleapis.com/projects/p-one/serviceAccounts/{name}@p-one.iam.gserviceaccount.com",
                "activityType": "serviceAccountLastAuthentication", "observationPeriod": period, "activity": body}
    def resolve(request, denied=False):
        url = request["url"]
        if url.endswith("/serviceAccounts"):
            return {"accounts": [account(n) for n in ("recent", "stale", "never", "unlisted")]}
        if "policyanalyzer" in url:
            assert request["method"] == "GET"
            assert url.endswith("/locations/global/activityTypes/serviceAccountLastAuthentication/activities:query")
            if denied:
                raise gcp.ReadError("denied", "api_error", http_status=403)
            return {"activities": [activity("recent", recent), activity("stale", "2025-01-01T00:00:00Z"),
                                   activity("never")]}
        return {"bindings": []}
    result, _ = snapshot(["service_account"], resolve)
    items = {item["email"].split("@")[0]: item for item in collection(result, "service_account")["items"]}
    status = {name: check.evaluate(item, {})[0] for name, item in items.items()}
    assert status == {"recent": "PASS", "stale": "FAIL", "never": "UNKNOWN", "unlisted": "UNKNOWN"}
    for name in ("recent", "stale", "never"):
        coverage = items[name]["_coverage"]["_activity"]
        assert coverage["status"] == "collected" and coverage["source_requests"]
        assert set(coverage["source_requests"]) <= set(items[name]["_provenance"]["source_requests"])
    assert items["unlisted"]["_coverage"]["_activity"]["status"] == "not_observed"
    result, _ = snapshot(["service_account"], lambda r: resolve(r, denied=True))
    found = collection(result, "service_account")
    assert found["status"] == "collected" and len(found["items"]) == 4
    assert all("_activity" not in item and item["_coverage"]["_activity"]["status"] == "denied" for item in found["items"])
    assert all(check.evaluate(item, {})[0] == "DENIED" for item in found["items"])


def test_default_service_usage_selection_reads_container_scanning_state():
    from peaso.checks import CHECKS
    check = next(c for c in CHECKS if c.id == "gcp.claude.project.container_scanning_api_enabled")
    def resolve(request):
        assert request["url"].endswith("/services")
        assert request["params"]["pageSize"] <= 200
        assert "filter" not in request["params"]
        return {"services": [{"name": "projects/123/services/containerscanning.googleapis.com", "state": "DISABLED"},
                            {"name": "projects/123/services/cloudasset.googleapis.com", "state": "ENABLED"}]}
    result, transport = snapshot(["service_usage"], resolve)
    assert len(transport.requests) == 1
    assert transport.requests[0]["url"].endswith("/services")
    rows = collection(result, "service_usage")["items"]
    row = next(r for r in rows if r["name"].endswith("containerscanning.googleapis.com"))
    assert row["_provenance"]["source_requests"]
    index = {"collections": {"service_usage": [{"scope": "projects/p-one", "status": "collected"}]},
             "service_usage": [{"data": r} for r in rows]}
    assert check.evaluate({"projectId": "p-one", "name": "projects/123"}, index)[0] == "FAIL"


def test_service_perimeters_of_the_project_organization_are_listed_at_project_scope():
    from peaso.checks import CHECKS
    check = next(c for c in CHECKS if c.id == "gcp.claude.project.storage_vpc_service_controls")
    def resolve(request, *, ancestors=({"type": "organization", "id": "34"},), denied=False, perimeter=True):
        url = request["url"]
        if url.endswith(":getAncestry"):
            return {"ancestor": [{"resourceId": {"type": "project", "id": "p-one"}}] + [{"resourceId": a} for a in ancestors]}
        if url == "https://accesscontextmanager.googleapis.com/v1/accessPolicies":
            assert request["method"] == "GET" and request["params"]["parent"] == "organizations/34"
            if denied:
                raise gcp.ReadError("denied", "api_error", http_status=403)
            return {"accessPolicies": [{"name": "accessPolicies/9", "parent": "organizations/34"}]}
        if url.endswith("accessPolicies/9/servicePerimeters"):
            return {"servicePerimeters": [{"name": "accessPolicies/9/servicePerimeters/p", "status": {
                "restrictedServices": ["storage.googleapis.com"] if perimeter else ["bigquery.googleapis.com"],
                "resources": ["projects/111"]}}]}
        if url.startswith("https://cloudresourcemanager.googleapis.com/v3/projects/p-one"):
            return {"name": "projects/111", "projectId": "p-one"}
        return {}
    def run(**kw):
        result, transport = snapshot(["project", "service_perimeter"], lambda r: resolve(r, **kw), include_inherited=True,
                                     metrics_scopes=False)
        found = collection(result, "service_perimeter")
        index = {"collections": {"service_perimeter": [found]}, "service_perimeter": [{"data": x} for x in found["items"]]}
        return found, check.evaluate({"name": "projects/111"}, index)[0]
    found, status = run()
    assert status == "PASS" and found["items"][0]["accessPolicy"] == "accessPolicies/9"
    assert len(found["items"][0]["_provenance"]["source_requests"]) == 1 and found["source_requests"]
    assert run(perimeter=False)[1] == "FAIL"
    found, status = run(ancestors=())
    assert found["status"] == "empty" and status == "FAIL"  # no organization: no access policy can apply
    found, status = run(denied=True)
    assert found["status"] == "denied" and status == "UNKNOWN"


def test_app_engine_not_found_for_this_project_application_is_empty_not_unknown():
    def not_found(resource):
        return gcp.http_error(404, {"error": {"code": 404, "status": "NOT_FOUND", "details": [
            {"@type": "type.googleapis.com/google.rpc.ResourceInfo", "resourceName": resource}]}})
    def raiser(error):
        def resolve(request):
            raise error
        return resolve
    result, _ = snapshot(["app_engine_application"], raiser(not_found("projects/p-one/locations/global/applications/p-one")))
    assert collection(result, "app_engine_application")["status"] == "empty"
    # A 404 for another resource, without ResourceInfo, or a 403 stays not collected.
    for error in (not_found("projects/other/locations/global/applications/other"), gcp.http_error(404, {"error": {"code": 404}}),
                  gcp.http_error(403, {"error": {"code": 403}})):
        result, _ = snapshot(["app_engine_application"], raiser(error))
        assert collection(result, "app_engine_application")["status"] in ("unknown", "denied")
    app = {"name": "apps/p-one", "id": "p-one", "defaultHostname": "p-one.uc.r.appspot.com", "servingStatus": "SERVING"}
    result, _ = snapshot(["app_engine_application"], lambda request: app)
    assert collection(result, "app_engine_application")["status"] == "collected"


def test_service_account_key_activity_attaches_policy_analyzer_key_facts():
    from peaso.checks import CHECKS
    check = next(c for c in CHECKS if c.id == "gcp.claude.service_account_key.recently_used")
    from datetime import datetime, timedelta, timezone
    recent = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%dT00:00:00Z")
    observed = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT00:00:00Z")
    period = {"startTime": "2024-05-13T07:00:00Z", "endTime": observed}
    sa = "projects/p-one/serviceAccounts/a@p-one.iam.gserviceaccount.com"
    def key(name):
        return {"name": f"{sa}/keys/{name}", "keyType": "USER_MANAGED", "keyAlgorithm": "KEY_ALG_RSA_2048", "validAfterTime": period["startTime"]}
    def activity(name, last=None):
        body = {"serviceAccountKey": {"fullResourceName": f"//iam.googleapis.com/{sa}/keys/{name}", "serviceAccountId": "1"}}
        if last:
            body["lastAuthenticatedTime"] = last
        return {"fullResourceName": f"//iam.googleapis.com/{sa}/keys/{name}", "activityType": "serviceAccountKeyLastAuthentication",
                "observationPeriod": period, "activity": body}
    def resolve(request, denied=False):
        url = request["url"]
        if url.endswith("/serviceAccounts"):
            return {"accounts": [{"name": sa, "email": "a@p-one.iam.gserviceaccount.com", "uniqueId": "1"}]}
        if url.endswith("/keys"):
            return {"keys": [key(n) for n in ("recent", "stale", "never", "unlisted")]}
        if "serviceAccountKeyLastAuthentication" in url:
            assert request["method"] == "GET"
            if denied:
                raise gcp.ReadError("denied", "api_error", http_status=403)
            return {"activities": [activity("recent", recent), activity("stale", "2024-06-23T07:00:00Z"), activity("never")]}
        if "policyanalyzer" in url:
            return {"activities": []}
        return {"bindings": []}
    result, transport = snapshot(["service_account", "service_account_key"], resolve)
    assert sum("serviceAccountKeyLastAuthentication" in r["url"] for r in transport.requests) == 1
    items = {item["name"].rsplit("/", 1)[1]: item for item in collection(result, "service_account_key")["items"]}
    assert {name: check.evaluate(item, {})[0] for name, item in items.items()} == {
        "recent": "PASS", "stale": "FAIL", "never": "FAIL", "unlisted": "UNKNOWN"}
    assert set(items["recent"]["_coverage"]["_activity"]["source_requests"]) <= set(items["recent"]["_provenance"]["source_requests"])
    assert items["unlisted"]["_coverage"]["_activity"]["status"] == "not_observed"
    result, _ = snapshot(["service_account", "service_account_key"], lambda r: resolve(r, denied=True))
    found = collection(result, "service_account_key")
    assert found["status"] == "collected" and len(found["items"]) == 4
    assert all(check.evaluate(item, {})[0] == "DENIED" and item["_coverage"]["_activity"]["status"] == "denied" for item in found["items"])


@pytest.mark.parametrize('numeric_alias', [False, True])
def test_unused_account_insight_collector_to_hardening_json(numeric_alias):
    from datetime import datetime, timedelta, timezone
    from peaso.engine import evaluate_snapshot, hydrate_frameworks
    from peaso.unused_iam_gcp import INSIGHT_CHECK
    scope = 'projects/usage-project'
    email = 'unused@usage-project.iam.gserviceaccount.com'
    uid = '123456789012345678901'
    token = '123456789012' if numeric_alias else 'usage-project'
    refresh = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    prefix = f'projects/{token}/locations/global/insightTypes/google.iam.serviceAccount.Insight/insights/'
    def resolve(request):
        url = request['url']
        if url.endswith('/serviceAccounts'):
            return {'accounts': [{'name': scope+'/serviceAccounts/'+email, 'email': email,
                                  'uniqueId': uid, 'disabled': False}]}
        if url == 'https://cloudresourcemanager.googleapis.com/v3/'+scope:
            return {'name': 'projects/123456789012', 'projectId': 'usage-project'}
        if url.endswith('/insights'):
            assert request['method'] == 'GET'
            if request.get('params', {}).get('pageToken') == 'next-page':
                return {'insights': [{'name': prefix+'unused', 'insightSubtype': 'SERVICE_ACCOUNT_USAGE',
                    'category': 'SECURITY', 'content': {'email': email, 'serviceAccountId': uid},
                    'stateInfo': {'state': 'ACTIVE'}, 'lastRefreshTime': refresh,
                    'observationPeriod': '7776000s',
                    'targetResources': ['//cloudresourcemanager.googleapis.com/projects/'+token]}]}
            return {'insights': [], 'nextPageToken': 'next-page'}
        if 'policyanalyzer' in url:
            return {'activities': []}
        return {'bindings': []}
    transport = NativeDataFixtureTransport(resolve)
    result = gcp.GCPCollector(connector(['service_account', 'service_account_insight'], scopes=[scope]), transport=transport).collect()
    found = collection(result, 'service_account_insight', scope=scope)
    assert found['status'] == 'collected', found
    assert len(found['items']) == 1
    assert sum(request['url'].endswith('/insights') for request in transport.requests) == 2
    report = hydrate_frameworks(evaluate_snapshot(result, categories=['hardening'], checks=[INSIGHT_CHECK]))
    finding = json.loads(json.dumps(report))['findings'][0]
    assert finding['check_id'] == INSIGHT_CHECK
    assert finding['status'] == 'FAIL', finding
    assert finding['category'] == 'hardening'
    assert 'HackTricks Cloud Best Practices' in finding['frameworks']
    assert finding['evidence']['service_account_id'] == uid
    assert not any('secret' in request['url'].lower() for request in transport.requests)


def test_unused_group_collector_keeps_per_group_pagination_and_independent_failures():
    from peaso.engine import evaluate_snapshot
    from peaso.unused_iam_gcp_authorization import GROUP
    scope = 'projects/usage-project'
    def resolve(request):
        url = request['url']
        if url == 'https://cloudidentity.googleapis.com/v1/groups':
            assert request['params']['view'] == 'FULL'
            return {'groups': [{'name': 'groups/'+name, 'parent': 'customers/Csynthetic',
                'groupKey': {'id': name+'@example.test'},
                **({'dynamicGroupMetadata': {'status': {'status': 'UPDATING_MEMBERSHIPS'}}} if name == 'dynamic' else {})}
                for name in ('empty', 'denied', 'dynamic')]}
        if url.endswith('/memberships:searchTransitiveMemberships') or '/groups/denied/' in url:
            raise gcp.ReadError('denied', 'api_error', http_status=403)
        if url.endswith('/memberships'):
            if request.get('params', {}).get('pageToken') == 'finish':
                return {'memberships': []}
            return {'memberships': [], 'nextPageToken': 'finish'}
        return {}
    transport = NativeDataFixtureTransport(resolve)
    result = gcp.GCPCollector(connector(['group', 'group_membership'], scopes=[scope],
        cloud_identity_customers=['Csynthetic']), transport=transport).collect()
    groups = {item['name']: item for item in collection(result, 'group', scope=scope)['items']}
    assert groups['groups/empty']['_coverage']['directMemberships']['status'] == 'collected'
    assert len(groups['groups/empty']['_coverage']['directMemberships']['source_requests']) == 2
    assert groups['groups/denied']['_coverage']['directMemberships']['status'] == 'denied'
    report = evaluate_snapshot(result, categories=['hardening'], checks=[GROUP])
    statuses = {row['resource_name']: row['status'] for row in report['findings']}
    assert statuses == {'groups/empty': 'FAIL', 'groups/denied': 'DENIED', 'groups/dynamic': 'UNKNOWN'}, [(r['resource_name'], r['status'], r['evidence']) for r in report['findings']]


@pytest.mark.parametrize('numeric_alias', [False, True])
def test_unused_policy_grant_collector_to_hardening_matches_current_binding(numeric_alias):
    from datetime import datetime, timedelta, timezone
    from peaso.engine import evaluate_snapshot, hydrate_frameworks
    from peaso.unused_iam_gcp_authorization import GRANT
    scope = 'projects/usage-project'
    member = 'group:obsolete@example.test'
    returned_scope = 'projects/123456789012' if numeric_alias else scope
    refreshed = (datetime.now(timezone.utc)-timedelta(days=1)).isoformat()
    def resolve(request):
        url = request['url']
        if url.endswith(':getIamPolicy'):
            assert request['method'] == 'POST'
            return {'bindings': [{'role': 'roles/viewer', 'members': [member]}]}
        if url == 'https://cloudresourcemanager.googleapis.com/v3/'+scope:
            return {'name': 'projects/123456789012', 'projectId': 'usage-project'}
        if url.endswith('/insights'):
            return {'insights': [{'name': returned_scope+'/locations/global/insightTypes/google.iam.policy.Insight/insights/unused',
                'content': {'role': 'roles/viewer', 'member': member, 'exercisedPermissions': [], 'inferredPermissions': []},
                'category': 'SECURITY', 'insightSubtype': 'PERMISSIONS_USAGE',
                'stateInfo': {'state': 'ACTIVE'}, 'lastRefreshTime': refreshed, 'observationPeriod': '7776000s',
                'targetResources': ['//cloudresourcemanager.googleapis.com/'+returned_scope]}]}
        return {}
    transport = NativeDataFixtureTransport(resolve)
    result = gcp.GCPCollector(connector(['insight', 'iam_policy'], scopes=[scope], resource_iam=False), transport=transport).collect()
    report = hydrate_frameworks(evaluate_snapshot(result, categories=['hardening'], checks=[GRANT]))
    finding = json.loads(json.dumps(report))['findings'][0]
    assert finding['status'] == 'FAIL', finding['evidence']
    assert finding['evidence']['principal'] == member
    assert finding['evidence']['role'] == 'roles/viewer'
    assert 'HackTricks Cloud Best Practices' in finding['frameworks']


@pytest.mark.parametrize('mode,expected', [('old', 'FAIL'), ('recent', 'PASS'), ('denied', 'DENIED'),
    ('foreign', 'UNKNOWN'), ('missing', 'UNKNOWN'), ('new', 'PASS'), ('suspended', 'NOT_APPLICABLE')])
def test_unused_directory_user_uses_individual_metadata_not_inaccurate_list_login(mode, expected):
    from datetime import datetime, timedelta, timezone
    from peaso.engine import evaluate_snapshot, hydrate_frameworks
    from peaso.unused_iam_gcp_directory import USER
    from peaso.gcp_directory_usage_contract import KIND, FIELDS, USERS
    scope, org, customer = 'projects/usage-project', 'organizations/123456789012', 'Csynthetic'
    uid, email = '123456789012345678901', 'user@example.test'
    recent = (datetime.now(timezone.utc)-timedelta(days=1)).isoformat()
    def resolve(request):
        url = request['url']
        if url == 'https://cloudresourcemanager.googleapis.com/v3/'+scope:
            return {'name': 'projects/987654321012', 'projectId': 'usage-project', 'parent': org}
        if url == 'https://cloudresourcemanager.googleapis.com/v3/'+org:
            return {'name': org, 'directoryCustomerId': customer}
        if url == USERS:
            return {'users': [{'id': uid, 'customerId': customer, 'primaryEmail': email,
                'suspended': mode == 'suspended', 'archived': False, 'lastLoginTime': recent}]}
        if url == USERS+'/'+uid:
            assert request['method'] == 'GET'
            assert request['params']['fields'] == FIELDS
            assert 'password' not in request['params']['fields'] and 'token' not in request['params']['fields']
            if mode == 'denied':
                raise gcp.ReadError('denied', 'api_error', http_status=403)
            return {'id': 'different-user' if mode == 'foreign' else uid, 'customerId': customer,
                'primaryEmail': email, 'suspended': False, 'archived': False,
                'creationTime': recent if mode == 'new' else '2024-01-01T00:00:00Z',
                **({} if mode == 'missing' else {'lastLoginTime': recent if mode in ('new', 'recent') else '2025-01-01T00:00:00Z'})}
        return {}
    transport = NativeDataFixtureTransport(resolve)
    result = gcp.GCPCollector(connector(['workspace_user', KIND], scopes=[scope],
        workspace_customers=[customer]), transport=transport).collect()
    report = hydrate_frameworks(evaluate_snapshot(result, categories=['hardening'], checks=[USER]))
    finding = json.loads(json.dumps(report))['findings'][0]
    assert finding['status'] == expected, finding['evidence']
    assert finding['service'] == 'admin.googleapis.com'
    assert 'HackTricks Cloud Best Practices' in finding['frameworks']
    if mode == 'old':
        assert finding['evidence']['last_recorded_login'].startswith('2025-01-01')
    assert sum(request['url'] == USERS+'/'+uid for request in transport.requests) == int(mode != 'suspended')


@pytest.mark.parametrize('workforce,numeric_alias', [(False, False), (False, True), (True, False)])
def test_unused_federation_pool_collector_to_hardening(workforce, numeric_alias):
    from peaso.engine import evaluate_snapshot, hydrate_frameworks
    from peaso.unused_iam_gcp_directory import WORKLOAD, WORKFORCE
    scope = 'organizations/123456789012' if workforce else 'projects/usage-project'
    kind, child = ('workforce_pool', 'workforce_provider') if workforce else ('workload_identity_pool', 'workload_identity_provider')
    name = ('locations/global/workforcePools/synthetic' if workforce else
            ('projects/987654321012' if numeric_alias else scope)+'/locations/global/workloadIdentityPools/synthetic')
    def resolve(request):
        url = request['url']
        if url == 'https://cloudresourcemanager.googleapis.com/v3/'+scope:
            return {'name': 'projects/987654321012', 'projectId': 'usage-project'}
        if url.endswith('/workforcePools'):
            assert request['params']['parent'] == scope
            return {'workforcePools': [{'name': name, 'parent': scope, 'state': 'ACTIVE'}]}
        if url.endswith('/workloadIdentityPools'):
            return {'workloadIdentityPools': [{'name': name, 'state': 'ACTIVE'}]}
        if url.endswith('/providers'):
            assert url == 'https://iam.googleapis.com/v1/'+name+'/providers'
            return {'workforcePoolProviders' if workforce else 'workloadIdentityPoolProviders': []}
        return {}
    transport = NativeDataFixtureTransport(resolve)
    result = gcp.GCPCollector(connector([kind, child], scopes=[scope]), transport=transport).collect()
    report = hydrate_frameworks(evaluate_snapshot(result, categories=['hardening'], checks=[WORKFORCE if workforce else WORKLOAD]))
    finding = json.loads(json.dumps(report))['findings'][0]
    assert finding['status'] == 'FAIL', finding['evidence']
    assert finding['service'] == 'iam'
    assert finding['evidence']['pool_name'] == name
    assert 'HackTricks Cloud Best Practices' in finding['frameworks']


def test_unused_directory_parallel_reads_preserve_other_users_when_one_get_is_denied():
    from peaso.engine import evaluate_snapshot
    from peaso.unused_iam_gcp_directory import USER
    from peaso.gcp_directory_usage_contract import KIND, USERS
    scope, org, customer = 'projects/usage-project', 'organizations/123456789012', 'Csynthetic'
    users = [{'id': uid, 'customerId': customer, 'primaryEmail': uid+'@example.test', 'suspended': False, 'archived': False}
             for uid in ('123456789012345678901', '123456789012345678902')]
    def resolve(request):
        url = request['url']
        if url == 'https://cloudresourcemanager.googleapis.com/v3/'+scope:
            return {'name': 'projects/987654321012', 'projectId': 'usage-project', 'parent': org}
        if url == 'https://cloudresourcemanager.googleapis.com/v3/'+org:
            return {'name': org, 'directoryCustomerId': customer}
        if url == USERS:
            return {'users': users}
        for user in users:
            if url == USERS+'/'+user['id']:
                if user['id'].endswith('2'):
                    raise gcp.ReadError('denied', 'api_error', http_status=403)
                return {**user, 'creationTime': '2024-01-01T00:00:00Z', 'lastLoginTime': '2025-01-01T00:00:00Z'}
        return {}
    transport = NativeDataFixtureTransport(resolve)
    result = gcp.GCPCollector(connector(['workspace_user', KIND], scopes=[scope],
        workspace_customers=[customer], concurrency=2), transport=transport).collect()
    report = evaluate_snapshot(result, categories=['hardening'], checks=[USER])
    statuses = {row['resource_name']: row['status'] for row in report['findings']}
    assert statuses == {f'customers/{customer}/workspace_user/{users[0]["id"]}': 'FAIL',
                        f'customers/{customer}/workspace_user/{users[1]["id"]}': 'DENIED'}
    assert len(transport.requests) == 5
    assert sum(request['url'].startswith('https://cloudresourcemanager.googleapis.com/v3/')
               for request in transport.requests) == 2


@pytest.mark.parametrize('hmac', [False, True])
@pytest.mark.parametrize('mode,expected', [('old', 'FAIL'), ('recent', 'PASS'), ('empty', 'UNKNOWN'),
    ('failed', 'UNKNOWN'), ('denied', 'DENIED'), ('pagination', 'PASS'), ('partial', 'UNKNOWN'), ('foreign', 'UNKNOWN')])
def test_recorded_key_usage_collector_to_hardening(hmac, mode, expected):
    from datetime import datetime, timedelta, timezone
    from peaso.engine import evaluate_snapshot, hydrate_frameworks
    from peaso.unused_iam_gcp_keys import API_CHECK, HMAC_CHECK
    from peaso.gcp_key_usage_contract import API, HMAC, PARENTS, METRICS, RESOURCES
    kind = HMAC if hmac else API
    scope, ident = 'projects/usage-project', 'GOOG1syntheticPublicAccessId' if hmac else 'synthetic-key-uid'
    now = datetime.now(timezone.utc)
    def counts(recent=False):
        start = now-timedelta(days=3 if recent else 180)
        labels = {'response_code_class': '4xx' if mode == 'failed' else '2xx'} if not hmac else {
            'access_id': ident, 'authentication_method': 'HMAC', 'response_code': '403' if mode == 'failed' else '200'}
        resource = {'project_id': 'foreign-project' if mode == 'foreign' else 'usage-project'}
        if not hmac: resource['credential_id'] = 'apikey:'+ident
        return {'metric': {'type': METRICS[kind], 'labels': labels}, 'resource': {'type': RESOURCES[kind], 'labels': resource},
            'metricKind': 'DELTA', 'valueType': 'INT64', 'points': [{'interval': {'startTime': start.isoformat(),
                'endTime': (start+timedelta(days=1)).isoformat()}, 'value': {'int64Value': '3'}}]}
    def resolve(request):
        url, params = request['url'], request.get('params', {})
        if url == 'https://cloudresourcemanager.googleapis.com/v3/'+scope:
            return {'name': 'projects/123456789012', 'projectId': 'usage-project'}
        if url.endswith('/keys'):
            assert 'keyString' not in params['fields']
            return {'keys': [{'name': 'projects/123456789012/locations/global/keys/example', 'uid': ident,
                'createTime': '2024-01-01T00:00:00Z'}]}
        if url.endswith('/hmacKeys'):
            return {'items': [{'accessId': ident, 'projectId': 'usage-project', 'serviceAccountEmail': 'worker@usage-project.iam.gserviceaccount.com',
                              'state': 'ACTIVE', 'timeCreated': '2024-01-01T00:00:00Z'}]}
        if url.endswith('/timeSeries'):
            assert request['method'] == 'GET'
            assert ident in params['filter'] and 'project="usage-project"' in params['filter']
            assert params['aggregation.crossSeriesReducer'] == 'REDUCE_SUM'
            if mode == 'denied': raise gcp.ReadError('denied', 'api_error', http_status=403)
            if mode == 'empty': return {'timeSeries': []}
            if mode == 'pagination' and not params.get('pageToken'):
                return {'timeSeries': [counts()], 'nextPageToken': 'next'}
            body = {'timeSeries': [counts(mode in ('recent', 'pagination'))]}
            if mode == 'partial': body['executionErrors'] = [{'code': 14, 'message': 'partial test response'}]
            return body
        return {}
    transport = NativeDataFixtureTransport(resolve)
    result = gcp.GCPCollector(connector([PARENTS[kind], kind], scopes=[scope]), transport=transport).collect()
    report = hydrate_frameworks(evaluate_snapshot(result, categories=['hardening'], checks=[HMAC_CHECK if hmac else API_CHECK]))
    finding = json.loads(json.dumps(report))['findings'][0]
    assert finding['status'] == expected, finding['evidence']
    assert 'HackTricks Cloud Best Practices' in finding['frameworks']
    assert all(request['method'] == 'GET' for request in transport.requests)
    assert not any('getKeyString' in request['url'] or ':create' in request['url'] for request in transport.requests)
    if expected == 'FAIL':
        assert finding['evidence']['days_since_recorded_successful_interval'] >= 178
        assert finding['evidence']['universal_inactivity_established'] is False


def test_hmac_key_usage_reads_only_selected_bucket_projects_and_preserves_independent_use():
    from datetime import datetime, timedelta, timezone
    from peaso.engine import evaluate_snapshot
    from peaso.unused_iam_gcp_keys import HMAC_CHECK
    from peaso.gcp_key_usage_contract import HMAC, METRICS
    owner, bucket = 'projects/usage-project', 'projects/bucket-project'
    ident = 'GOOG1syntheticPublicAccessId'
    now = datetime.now(timezone.utc)
    def resolve(request):
        url, scope = request['url'], request['scope']
        if url.startswith('https://cloudresourcemanager.googleapis.com/v3/'):
            project = scope.split('/')[1]
            return {'name': 'projects/'+('123456789012' if scope == owner else '123456789013'), 'projectId': project}
        if url.endswith('/hmacKeys'):
            return {'items': [] if scope == bucket else [{'accessId': ident, 'projectId': 'usage-project',
                'serviceAccountEmail': 'worker@usage-project.iam.gserviceaccount.com', 'state': 'ACTIVE', 'timeCreated': '2024-01-01T00:00:00Z'}]}
        if url.endswith('/timeSeries'):
            assert scope in (owner, bucket)
            if scope == owner: raise gcp.ReadError('denied', 'api_error', http_status=403)
            return {'timeSeries': [{'metric': {'type': METRICS[HMAC], 'labels': {'access_id': ident, 'authentication_method': 'HMAC', 'response_code': '200'}},
                'resource': {'type': 'gcs_bucket', 'labels': {'project_id': 'bucket-project'}}, 'metricKind': 'DELTA', 'valueType': 'INT64',
                'points': [{'interval': {'startTime': (now-timedelta(days=3)).isoformat(), 'endTime': (now-timedelta(days=2)).isoformat()}, 'value': {'int64Value': '1'}}]}]}
        return {}
    transport = NativeDataFixtureTransport(resolve)
    result = gcp.GCPCollector(connector(['storage_hmac_key', HMAC], scopes=[owner, bucket]), transport=transport).collect()
    report = evaluate_snapshot(result, categories=['hardening'], checks=[HMAC_CHECK])
    finding = next(row for row in report['findings'] if row['evidence'].get('credential_id') == ident)
    assert finding['status'] == 'PASS', finding['evidence']
    assert finding['evidence']['latest_recorded_successful_interval']['project_scope'] == bucket
    assert {request['scope'] for request in transport.requests} == {owner, bucket}


@pytest.mark.parametrize('org,numeric_alias', [(False, False), (False, True), (True, False)])
@pytest.mark.parametrize('mode,expected', [('bound', 'PASS'), ('unbound', 'FAIL'), ('filtered', 'UNKNOWN'), ('denied', 'DENIED')])
def test_custom_role_consumers_require_root_and_complete_resource_policy_inventory(org, numeric_alias, mode, expected):
    from peaso.engine import evaluate_snapshot, hydrate_frameworks
    from peaso.unused_iam_gcp_roles import CHECK
    scope = 'organizations/123456789012' if org else 'projects/usage-project'
    listed_name = ('projects/987654321012' if numeric_alias else scope)+'/roles/synthetic'
    granted_name = scope+'/roles/synthetic'
    role = {'name': listed_name, 'includedPermissions': ['compute.instances.get', 'compute.instances.delete'], 'stage': 'GA'}
    def resolve(request):
        url = request['url']
        if url == 'https://cloudresourcemanager.googleapis.com/v3/'+scope:
            return {'name': 'projects/987654321012', 'projectId': 'usage-project'}
        if url == 'https://iam.googleapis.com/v1/'+scope+'/roles':
            assert request['params']['view'] == 'FULL'
            return {'roles': [role]}
        if url == 'https://iam.googleapis.com/v1/'+granted_name:
            return role
        if url.endswith(':getIamPolicy'):
            assert request['body'] == {'options': {'requestedPolicyVersion': 3}}
            return {'bindings': []}
        if url.endswith(':searchAllIamPolicies'):
            assert not request.get('params', {}).get('query')
            if mode == 'denied': raise gcp.ReadError('denied', 'api_error', http_status=403)
            if request.get('params', {}).get('pageToken') == 'final':
                return {'results': [] if mode != 'bound' else [{'resource': '//storage.googleapis.com/example-bucket',
                    'project': 'projects/987654321012', 'policy': {'bindings': [{'role': granted_name, 'members': ['group:team@example.test']}]}}]}
            return {'results': [], 'nextPageToken': 'final'}
        return {}
    transport = NativeDataFixtureTransport(resolve)
    result = gcp.GCPCollector(connector(['iam_role', 'iam_policy'], scopes=[scope], resource_iam=mode != 'filtered'), transport=transport).collect()
    role_collection = collection(result, 'iam_role', scope)
    assert role_collection['status'] == 'collected', role_collection
    # A numeric project alias for a listed role must not trigger an extra GET
    # and falsely classify the same role as a duplicate provider identity.
    assert not any(request['url'] == 'https://iam.googleapis.com/v1/'+granted_name for request in transport.requests)
    report = hydrate_frameworks(evaluate_snapshot(result, categories=['hardening'], checks=[CHECK]))
    finding = json.loads(json.dumps(report))['findings'][0]
    assert finding['status'] == expected, finding['evidence']
    assert 'HackTricks Cloud Best Practices' in finding['frameworks']
    if expected == 'FAIL': assert finding['evidence']['included_permissions'] == role['includedPermissions']



def test_backend_service_collects_healthy_vm_identity_without_guessing_group_members():
    base = "https://www.googleapis.com/compute/v1/projects/p-one"
    service = base + "/global/backendServices/web"
    group = base + "/zones/us-central1-a/instanceGroups/web"
    vm = base + "/zones/us-central1-a/instances/web"
    def resolver(request):
        if request["method"] == "POST":
            assert request["url"] == service + "/getHealth"
            assert request["body"] == {"group": group}
            return {"healthStatus": [{"instance": vm, "healthState": "HEALTHY"}]}
        return {"items": {"global": {"backendServices": [{"name": "web", "selfLink": service,
            "backends": [{"group": group}]}]}}}
    result, transport = snapshot(["backend_service_health"], resolver)
    health = collection(result, "backend_service_health")["items"][0]
    assert health["collection_status"] == "collected"
    assert health["groups"][0]["healthStatus"] == [{"instance": vm, "healthState": "HEALTHY"}]
    assert [request["method"] for request in transport.requests] == ["GET", "POST"]
    def denied(request):
        if request["method"] == "POST":
            raise gcp.ReadError("denied", "missing_compute_backend_service_get")
        return resolver(request)
    result, _ = snapshot(["backend_service_health"], denied)
    health = collection(result, "backend_service_health")["items"][0]
    assert health["collection_status"] == "partial"
    assert health["groups"][0]["collection_status"] == "denied"
