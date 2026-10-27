"""Native collection paths for the network service catalog (no live credentials)."""
import json
from types import SimpleNamespace

import pytest

from tests.test_peaso_collectors_gcp import snapshot, collection
from peaso.collectors.gcp_network_catalog import api_root


def test_gcp_exposure_catalog_types_are_supported_and_scheduled():
    from peaso.analysis.internet_exposure import GCP_TYPES
    from peaso.collectors.gcp import GCPCollector, SUPPORTED_TYPES
    from peaso.collectors.gcp_network_catalog import TYPES, REGIONAL, PRIVATE_SERVICES
    from tests.test_peaso_collectors_gcp import FixtureTransport, connector

    native_catalog = set(GCP_TYPES) & (set(REGIONAL) | set(PRIVATE_SERVICES) | {
        "target_pool", "target_instance", "identityplatform_config", "firebase_rules_release", "firebase_database_rules"})
    assert {"api_gateway", "firebase_apphosting_endpoint", "media_cdn_service",
            "vmware_external_address", "firebase_rules_release", "firebase_database_rules"} <= native_catalog
    assert native_catalog <= TYPES <= SUPPORTED_TYPES
    collector = GCPCollector(connector(sorted(native_catalog)),
                             transport=FixtureTransport(lambda _: {}))
    jobs = [kind for kind, _, _, _ in collector.scope_jobs("projects/p-one")]
    assert set(jobs) == native_catalog
    assert len(jobs) == len(native_catalog)


def test_gcp_tpu_metadata_plan_includes_firewall_targets_and_endpoint_port():
    from peaso.collectors.gcp_network_catalog import PRIVATE_SERVICES
    fields = PRIVATE_SERVICES["tpu_node"]["fields"]
    assert "tags" in fields and "serviceAccount(email)" in fields and "networkEndpoints(ipAddress,accessConfig(externalIp),port)" in fields


@pytest.mark.parametrize("kind,service,segment", [
    ("redis_cluster", "redis", "clusters"), ("netapp_storage_pool", "netapp", "storagePools"),
    ("netapp_volume", "netapp", "volumes"), ("service_connection_policy", "networkconnectivity", "serviceConnectionPolicies"),
    ("network_connectivity_spoke", "networkconnectivity", "spokes"), ("batch_network_job", "batch", "jobs"),
    ("managed_kafka_cluster", "managedkafka", "clusters"), ("memorystore_instance", "memorystore", "instances"),
    ("vertex_endpoint", "aiplatform", "endpoints"),
])
def test_gcp_network_service_native_lists_are_paginated_and_metadata_only(kind, service, segment):
    def resolver(request):
        assert request["method"] == "GET"
        assert request["url"] == api_root(service, "v1", "us-central1") + f"/projects/p-one/locations/us-central1/{segment}"
        token = request.get("params", {}).get("pageToken")
        if kind == "batch_network_job":
            assert "allocationPolicy" in request["params"]["fields"]
            assert "taskGroups" not in request["params"]["fields"]
        return {segment: [{"name": f"projects/p-one/locations/us-central1/{segment}/{'two' if token else 'one'}"}],
                **({} if token else {"nextPageToken": "page-two"})}
    snap, transport = snapshot([kind], resolver, regions=["us-central1"])
    assert collection(snap, kind)["status"] == "collected"
    assert len(collection(snap, kind)["items"]) == 2 and len(transport.requests) == 2


def test_gcp_api_gateway_native_list_feeds_public_endpoint_analysis():
    from peaso.analysis import analyze
    def resolver(request):
        assert request["method"] == "GET"
        assert request["url"] == "https://apigateway.googleapis.com/v1/projects/p-one/locations/us-central1/gateways"
        return {"gateways": [{"name": "projects/p-one/locations/us-central1/gateways/g",
                              "defaultHostname": "g.gateway.dev", "state": "ACTIVE"}]}
    snap, transport = snapshot(["api_gateway"], resolver, regions=["us-central1"])
    assert collection(snap, "api_gateway")["status"] == "collected"
    assert len(transport.requests) == 1
    assert any(f["check_id"] == "analysis.internet_exposure" and f["status"] == "FAIL"
               for f in analyze(snap)["findings"])


def test_gcp_firebase_apphosting_uses_identical_backend_request_for_scan_cache():
    from peaso.analysis import analyze
    def resolver(request):
        assert request["method"] == "GET"
        if request["url"].endswith("/locations"):
            return {"locations": [{"locationId": "us-central1"}]}
        assert request["url"] == "https://firebaseapphosting.googleapis.com/v1/projects/p-one/locations/us-central1/backends"
        return {"backends": [{"name": "projects/p-one/locations/us-central1/backends/b",
                              "uri": "https://b.hosted.app"}]}
    snap, transport = snapshot(["firebase_apphosting_backend", "firebase_apphosting_endpoint"], resolver,
                               regions=["us-central1"])
    assert collection(snap, "firebase_apphosting_endpoint")["status"] == "collected"
    backend_requests = [r for r in transport.requests if r["url"].endswith("/backends")]
    # FixtureTransport records both invocations; the production Transport
    # coalesces identical requests under its per-scan response cache.
    assert len(backend_requests) == 2
    assert backend_requests[0] == backend_requests[1]
    assert any(f["check_id"] == "analysis.internet_exposure" and f["status"] == "FAIL"
               for f in analyze(snap)["findings"])


def test_gcp_media_cdn_global_service_collection_feeds_exposure():
    from peaso.analysis import analyze
    def resolver(request):
        assert request["method"] == "GET"
        assert request["url"] == "https://networkservices.googleapis.com/v1/projects/p-one/locations/global/edgeCacheServices"
        assert "ipv4Addresses" in request["params"]["fields"]
        return {"edgeCacheServices": [{"name": "projects/p-one/locations/global/edgeCacheServices/s",
                                        "ipv4Addresses": ["34.8.8.8"], "requireTls": True}]}
    snap, transport = snapshot(["media_cdn_service"], resolver)
    assert collection(snap, "media_cdn_service")["status"] == "collected"
    assert len(transport.requests) == 1
    assert any(f["check_id"] == "analysis.internet_exposure" and f["status"] == "FAIL"
               for f in analyze(snap)["findings"])


@pytest.mark.parametrize("kind,segment", [("target_pool", "targetPools"), ("target_instance", "targetInstances")])
def test_gcp_compute_forward_targets_use_aggregated_inventory(kind, segment):
    def resolver(request):
        assert request["method"] == "GET"
        assert request["url"] == f"https://compute.googleapis.com/compute/v1/projects/p-one/aggregated/{segment}"
        assert request["params"]["returnPartialSuccess"] == "true"
        return {"items": {"zones/us-central1-a": {segment: [{"name": "t", "selfLink":
            f"https://compute.googleapis.com/compute/v1/projects/p-one/zones/us-central1-a/{segment}/t"}]}}}
    snap, transport = snapshot([kind], resolver)
    assert collection(snap, kind)["status"] == "collected"
    assert len(collection(snap, kind)["items"]) == len(transport.requests) == 1


def test_gcp_identity_platform_config_reads_only_signup_controls():
    def resolver(request):
        assert request["method"] == "GET"
        assert request["url"] == "https://identitytoolkit.googleapis.com/admin/v2/projects/p-one/config"
        assert request["params"]["fields"] == "name,signIn(anonymous(enabled)),client(permissions(disabledUserSignup))"
        return {"name": "projects/p-one/config", "signIn": {"anonymous": {"enabled": True}}}
    snap, transport = snapshot(["identityplatform_config"], resolver)
    assert collection(snap, "identityplatform_config")["status"] == "collected"
    assert len(transport.requests) == 1


def test_gcp_firebase_rules_releases_read_ruleset_once_without_storing_source():
    from peaso.analysis import analyze
    content = "service cloud.firestore { match /databases/{db}/documents { match /public/{id} { allow read: if true; } } }"
    def resolver(request):
        assert request["method"] == "GET"
        if request["url"].endswith("/releases"):
            return {"releases": [
                {"name": "projects/p-one/releases/cloud.firestore", "rulesetName": "projects/p-one/rulesets/r1"},
                {"name": "projects/p-one/releases/cloud.firestore/prod", "rulesetName": "projects/p-one/rulesets/r1"}]}
        assert request["url"] == "https://firebaserules.googleapis.com/v1/projects/p-one/rulesets/r1"
        return {"name": "projects/p-one/rulesets/r1", "source": {"files": [{"content": content}]},
                "metadata": {"services": ["cloud.firestore"]}}
    snap, transport = snapshot(["firebase_rules_release"], resolver)
    rows = collection(snap, "firebase_rules_release")["items"]
    assert len(rows) == 2 and len(transport.requests) == 2
    assert all(row["public_read"] is True and "source" not in row for row in rows)
    assert content not in json.dumps(snap)
    assert any(f["check_id"] == "analysis.internet_exposure" and f["status"] == "FAIL"
               for f in analyze(snap)["findings"])


def test_gcp_firebase_rules_summary_ignores_comments_and_unknown_conditions():
    from peaso.collectors.gcp_firebase_rules_exposure import summarize
    source = """// allow read: if true;
    service cloud.firestore { match /databases/{db}/documents {
      match /items/{id} { allow get: if request.auth != null;
        allow list: if request.time < timestamp('2030-01-01'); }
    } }"""
    assert summarize([{"content": source}]) == {"public_read": False, "public_write": False,
        "authenticated_read": True, "authenticated_write": False,
        "conditional_read": True, "conditional_write": False}
    assert summarize([{"content": "allow get: if request.auth == null; allow write: if false;"}]) == {
        "public_read": True, "public_write": False, "authenticated_read": False,
        "authenticated_write": False, "conditional_read": False, "conditional_write": False}
    assert summarize([{"content": "allow write: if request.auth != null; allow create: if request.time < timestamp('2030-01-01');"}]) == {
        "public_read": False, "public_write": False, "authenticated_read": False,
        "authenticated_write": True, "conditional_read": False, "conditional_write": True}


def test_gcp_firebase_database_rules_are_projected_before_snapshot():
    from peaso.analysis.internet_exposure import assess
    from peaso.collectors.gcp import GCPCollector
    from peaso.snapshot import resources
    from tests.test_peaso_collectors_gcp import NativeDataFixtureTransport, connector
    source = {"rules": {"private": {".read": "auth != null"},
                        "public": {".read": True, ".write": "now < 2000000000000"}}}
    def resolver(request):
        assert request["method"] == "GET"
        if request["url"] == "https://cloudresourcemanager.googleapis.com/v3/projects/p-one01":
            return {"name": "projects/123", "projectId": "p-one01"}
        if request["url"].endswith("/locations/-/instances"):
            assert request["url"] == "https://firebasedatabase.googleapis.com/v1beta/projects/123/locations/-/instances"
            return {"instances": [{"name": "projects/123/locations/us-central1/instances/db",
                                   "databaseUrl": "https://db.europe-west1.firebasedatabase.app", "state": "ACTIVE"}]}
        assert request["url"] == "https://db.europe-west1.firebasedatabase.app/.settings/rules.json"
        return source
    transport = NativeDataFixtureTransport(resolver)
    snap = GCPCollector(connector(["firebase_database_rules"], scopes=["projects/p-one01"]), transport=transport).collect()
    row = collection(snap, "firebase_database_rules", scope="projects/p-one01")["items"][0]
    assert row["public_read"] is True and row["conditional_write"] is True
    assert "rules" not in row and json.dumps(source) not in json.dumps(snap)
    assert len(transport.requests) == 3
    assert any(a.resource["type"] == "firebase_database_rules" and a.verdict() == "FAIL"
               for a in assess(snap, resources(snap)))


def test_gcp_firebase_database_rules_parser_preserves_unknown_conditions():
    from peaso.collectors.gcp_firebase_database_exposure import summarize_rules, _rules_url
    flags = summarize_rules({"rules": {"private": {".read": False},
        "users": {"$uid": {".read": "auth.uid == $uid", ".write": "auth != null"}}}})
    assert flags == {"public_read": False, "public_write": False, "authenticated_read": False,
                     "authenticated_write": True, "conditional_read": True, "conditional_write": False}
    assert _rules_url("https://db.firebaseio.com") == "https://db.firebaseio.com/.settings/rules.json"
    with pytest.raises(Exception):
        _rules_url("https://attacker.example/.settings/rules.json")


def test_gcp_firebase_write_only_rules_stay_visible_as_unresolved():
    from peaso.analysis.internet_exposure import _gcp_firebase_rules
    from peaso.collectors.gcp_firebase_database_exposure import summarize_rules
    flags = summarize_rules({"rules": {".write": "auth != null"}})
    resource = {"type": "firebase_database_rules", "data": {**flags, "source_inspected": True}}
    assessed = _gcp_firebase_rules(None, None, resource)
    assert assessed.verdict() == "UNKNOWN" and assessed.authenticated is True
    flags = summarize_rules({"rules": {".write": "auth.uid == $uid"}})
    resource["data"] = {**flags, "source_inspected": True}
    assert _gcp_firebase_rules(None, None, resource).verdict() == "UNKNOWN"


def test_gcp_firebase_database_rules_transport_cache_keeps_only_flags():
    from peaso.collectors.gcp import Transport
    from peaso.collectors.gcp_firebase_database_exposure import _read_rules
    raw = {"rules": {"secret_path": {".read": True}}}
    class Response:
        status_code = 200
        content = json.dumps(raw).encode()
        def json(self):
            return raw
    class Session:
        calls = 0
        def request(self, *args, **kwargs):
            self.calls += 1
            return Response()
    session = Session()
    transport = Transport(SimpleNamespace(headers=lambda: {}), {"retries": 0})
    transport._session = lambda: session
    collector = SimpleNamespace(transport=transport)
    url = "https://db.firebaseio.com/.settings/rules.json"
    assert _read_rules(collector, url, "projects/p-one")[0]["public_read"] is True
    assert _read_rules(collector, url, "projects/p-one")[0]["public_read"] is True
    assert session.calls == 1 and "secret_path" not in json.dumps(
        [entry.get("data") for entry in transport.cache.values()])


def test_gcp_firebase_database_rules_denied_read_is_not_clearance():
    from peaso.collectors.gcp import GCPCollector, ReadError
    from tests.test_peaso_collectors_gcp import NativeDataFixtureTransport, connector
    def resolver(request):
        if request["url"].endswith("/projects/p-one01"):
            return {"name": "projects/123", "projectId": "p-one01"}
        if request["url"].endswith("/locations/-/instances"):
            return {"instances": [{"name": "projects/123/locations/us-central1/instances/db",
                                   "databaseUrl": "https://db.firebaseio.com", "state": "ACTIVE"}]}
        raise ReadError("denied", "firebase_database_rules_denied")
    snap = GCPCollector(connector(["firebase_database_rules"], scopes=["projects/p-one01"]),
                        transport=NativeDataFixtureTransport(resolver)).collect()
    row = collection(snap, "firebase_database_rules", scope="projects/p-one01")
    assert row["status"] == "denied" and row["items"] == []


def test_gcp_firebase_rules_exact_host_uses_existing_transport_cache():
    from peaso.collectors.gcp import Transport
    from peaso.collectors.gcp_firebase_rules_exposure import _read
    class Response:
        status_code = 200
        content = b'{"releases": []}'
        headers = {}
        def json(self):
            return {"releases": []}
    class Session:
        calls = 0
        def request(self, *args, **kwargs):
            self.calls += 1
            return Response()
    session = Session()
    transport = Transport(SimpleNamespace(headers=lambda: {}), {"retries": 0})
    transport._session = lambda: session
    url = "https://firebaserules.googleapis.com/v1/projects/p-one/releases"
    collector = SimpleNamespace(transport=transport)
    assert _read(collector, url, "projects/p-one", {})[0] == {"releases": []}
    assert _read(collector, url, "projects/p-one", {})[0] == {"releases": []}
    assert session.calls == 1


@pytest.mark.parametrize("kind,location,parent_segment,child_segment", [
    ("vmware_external_address", "us-central1-a", "privateClouds", "externalAddresses"),
    ("vmware_external_access_rule", "us-central1", "networkPolicies", "externalAccessRules"),
])
def test_gcp_vmware_external_access_collection_uses_parent_scoped_metadata(kind, location, parent_segment, child_segment):
    parent = f"projects/p-one/locations/{location}/{parent_segment}/p"
    def resolver(request):
        assert request["method"] == "GET"
        assert "fields" in request["params"]
        if request["url"].endswith("/" + parent_segment):
            return {parent_segment: [{"name": parent}]}
        assert request["url"].endswith("/" + parent + "/" + child_segment)
        return {child_segment: [{"name": parent + "/" + child_segment + "/c"}]}
    snap, transport = snapshot([kind], resolver, regions=[location])
    assert collection(snap, kind)["status"] == "collected"
    assert len(collection(snap, kind)["items"]) == 1
    assert len(transport.requests) == 2


def test_dataflow_lists_active_jobs_then_fetches_only_network_environment():
    def resolver(request):
        assert request["method"] == "GET"
        if request["url"].endswith("jobs:aggregated"):
            return {"jobs": [{"id": "job-one", "location": "us-central1", "name": "job"}]}
        assert request["url"].endswith("/locations/us-central1/jobs/job-one")
        assert request["params"]["view"] == "JOB_VIEW_ALL"
        assert "workerPools(network,subnetwork,ipConfiguration)" in request["params"]["fields"]
        assert "steps" not in request["params"]["fields"]
        return {"id": "job-one", "location": "us-central1", "environment": {"workerPools": [{"network": "net", "subnetwork": "sub"}]}}
    snap, transport = snapshot(["dataflow_network_job"], resolver)
    row = collection(snap, "dataflow_network_job")
    assert row["status"] == "collected"
    assert row["items"][0]["environment"]["workerPools"][0]["network"] == "net"
    assert len(transport.requests) == 2


def test_dataflow_aggregate_location_failure_is_not_clean_empty():
    snap, _ = snapshot(["dataflow_network_job"], lambda request: {"jobs": [], "failedLocation": ["us-central1"]})
    assert collection(snap, "dataflow_network_job")["status"] not in {"empty", "collected"}


def test_private_service_networking_keeps_native_peering_connection_and_read_sources():
    def resolver(request):
        if request["url"].endswith("/networks"):
            return {"items": [{"name": "net"}]}
        assert request["url"] == "https://servicenetworking.googleapis.com/v1/services/servicenetworking.googleapis.com/connections"
        assert request["params"]["network"] == "projects/p-one/global/networks/net"
        return {"connections": [{"network": "projects/p-one/global/networks/net", "peering": "servicenetworking-googleapis-com"}]}
    snap, _ = snapshot(["service_networking_connection"], resolver)
    row = collection(snap, "service_networking_connection")
    assert row["status"] == "collected" and len(row["source_requests"]) == 2
    assert row["items"][0]["peering"] == "servicenetworking-googleapis-com"


def test_appengine_network_versions_have_an_independent_safe_fields_mask():
    def resolver(request):
        if request["url"].endswith("/services"):
            return {"services": [{"id": "default", "name": "apps/p-one/services/default"}]}
        assert request["url"].endswith("/services/default/versions")
        assert request["params"]["fields"] == "versions(id,name,servingStatus,env,network,vpcAccessConnector),nextPageToken"
        return {"versions": [{"id": "v1", "name": "apps/p-one/services/default/versions/v1", "network": {"name": "net"}}]}
    snap, _ = snapshot(["app_engine_network_version"], resolver)
    assert collection(snap, "app_engine_network_version")["items"][0]["network"] == {"name": "net"}


def test_azure_parent_scoped_network_lists_use_the_native_parent_and_subscription_scope():
    from peaso.collectors import azure
    from tests.test_peaso_azure_bulk_native import Transport, SUB, SCOPE, BASE, routes, parent, envelope
    rid = BASE + "Microsoft.Network/dnsResolvers/resolver"
    child = rid + "/inboundEndpoints/inbound"
    native = routes("dns_resolver", rid, {"virtualNetwork": {"id": BASE + "Microsoft.Network/virtualNetworks/net"}})
    native[rid + "/inboundEndpoints"] = {"value": [parent(child, "Microsoft.Network/dnsResolvers/inboundEndpoints", {
        "ipConfigurations": [{"privateIpAddress": "10.0.0.4", "subnet": {"id": BASE + "Microsoft.Network/virtualNetworks/net/subnets/sub"}}]})]}
    snap = azure.collect({"scopes": [SUB], "options": {"retries": 0}}, ["dns_inbound_endpoint"], transport=Transport(native))
    row = envelope(snap, "dns_inbound_endpoint")
    assert row["status"] == "collected" and row["scope"] == SCOPE
    assert row["items"][0]["id"] == child


def test_azure_denied_dns_parent_never_creates_a_clean_empty_child():
    from peaso.collectors import azure
    from tests.test_peaso_azure_bulk_native import Transport, SUB, SCOPE, envelope
    native = {SCOPE + "/providers/Microsoft.Network/dnsResolvers": azure.AzureReadError("forbidden", 403)}
    snap = azure.collect({"scopes": [SUB], "options": {"retries": 0}}, ["dns_resolver", "dns_inbound_endpoint"], transport=Transport(native))
    assert envelope(snap, "dns_inbound_endpoint")["status"] not in {"collected", "empty"}


def test_azure_container_app_ingress_survives_native_collection_and_agent_projection():
    from peaso.collectors import azure
    from peaso.snapshot import resources
    from peaso.ai.network import native_network_resource
    from tests.test_peaso_azure_bulk_native import Transport, SUB, BASE, routes, envelope
    rid = BASE + "Microsoft.App/containerApps/app"
    env = BASE + "Microsoft.App/managedEnvironments/env"
    native = routes("container_app", rid, {"managedEnvironmentId": env,
        "configuration": {"ingress": {"external": True, "targetPort": 8080, "fqdn": "app.example.com"}}})
    snap = azure.collect({"scopes": [SUB], "options": {"retries": 0}}, ["container_app"], transport=Transport(native))
    assert envelope(snap, "container_app")["status"] == "collected"
    app = next(r for r in resources(snap) if r["type"] == "container_app")
    data = native_network_resource(app)["data"]
    assert data["properties"]["managedEnvironmentId"] == env
    assert data["properties"]["configuration"]["ingress"]["targetPort"] == 8080


def test_aws_detail_enrichment_retains_networks_and_explicit_denied_coverage():
    from peaso.collectors.aws import ReadResult
    from peaso.collectors.aws_network_catalog import detail_enricher
    calls = []
    class Requests:
        def call(self, session, service, region, operation, **arguments):
            calls.append((service, operation, arguments))
            return {"Service": {"ServiceArn": "arn:aws:apprunner:us-east-1:111111111111:service/app/one", "NetworkConfiguration": {
                "EgressConfiguration": {"VpcConnectorArn": "connector"}}, "SourceConfiguration": {"RuntimeEnvironmentVariables": {"key": "SECRET_SENTINEL"}}}}
    rows = [{"ServiceArn": "arn:aws:apprunner:us-east-1:111111111111:service/app/one"}]
    result = detail_enricher("app_runner_service")(Requests(), None, "us-east-1", rows)
    assert calls[0][0:2] == ("apprunner", "describe_service")
    assert result[0]["NetworkDetails"]["NetworkConfiguration"]["EgressConfiguration"]["VpcConnectorArn"] == "connector"
    assert "SECRET_SENTINEL" not in json.dumps(result)


def test_aws_sensitive_configuration_literals_are_stripped_from_snapshot_values():
    from peaso.collectors.aws import _safe
    raw = {"Service": {"SourceConfiguration": {"ImageRepository": {"ImageConfiguration": {
        "RuntimeEnvironmentVariables": {"key": "SECRET_SENTINEL"}, "RuntimeEnvironmentSecrets": {"secret": "SECRET_SENTINEL"}}}}}}
    assert "SECRET_SENTINEL" not in json.dumps(_safe(raw))
    assert "SECRET_SENTINEL" not in json.dumps(_safe({"PipelineConfigurationBody": "SECRET_SENTINEL"}))


@pytest.mark.parametrize("kind,service,operation,root,identity", [
    ("app_runner_service", "apprunner", "describe_service", "Service", {"ServiceArn": "arn:aws:apprunner:us-east-1:111111111111:service/app/one"}),
    ("osis_pipeline", "osis", "get_pipeline", "Pipeline", {"PipelineName": "pipeline"}),
])
def test_network_configuration_responses_are_projected_before_the_shared_request_cache(kind, service, operation, root, identity):
    from peaso.collectors.aws import Requests
    from peaso.collectors.aws_network_catalog import detail_enricher
    class Client:
        def __getattr__(self, name):
            assert name == operation
            return lambda **arguments: {root: {**identity, "NetworkConfiguration": {"VpcId": "vpc-one"},
                "PipelineConfigurationBody": "SECRET_SENTINEL", "SourceConfiguration": {"RuntimeEnvironmentVariables": {"key": "SECRET_SENTINEL"}}}}
    class Session:
        def client(self, native_service, **arguments):
            assert native_service == service
            return Client()
    requests = Requests({"retry_attempts": 1})
    detail_enricher(kind)(requests, Session(), "us-east-1", [dict(identity)])
    assert requests.calls == 1
    cached = [future.result() for future in requests._cache.values()]
    assert "vpc-one" in json.dumps(cached)
    assert "SECRET_SENTINEL" not in json.dumps(cached)


@pytest.mark.parametrize("kind", ["eks_nodegroup", "eks_fargate_profile"])
def test_eks_network_children_discover_clusters_and_keep_detail_denials_partial(kind):
    from peaso.collectors.aws import ReadResult
    from peaso.collectors.aws_network_catalog import eks_children
    calls = []
    root = "nodegroup" if kind == "eks_nodegroup" else "fargateProfile"
    class Requests:
        def pages(self, session, service, region, operation, key, **arguments):
            calls.append((operation, arguments))
            return ReadResult(["cluster"] if operation == "list_clusters" else ["one", "two"], "collected")
        def call(self, session, service, region, operation, **arguments):
            calls.append((operation, arguments))
            if "two" in arguments.values():
                return {"collection_status": "denied", "error": {"code": "AccessDenied"}}
            return {root: {"clusterName": "cluster", "subnets": ["subnet-one"]}}
    result = eks_children(kind)(Requests(), None, "us-east-1", "111111111111")
    assert result.status == "partial" and len(result.items) == 1
    assert result.items[0]["subnets"] == ["subnet-one"]
    assert all(args.get("clusterName") == "cluster" for op, args in calls if op != "list_clusters")


def test_quicksight_vpc_connections_supply_native_account_argument():
    from peaso.collectors.aws import ReadResult
    from peaso.collectors.aws_network_catalog import quicksight_connections
    class Requests:
        def pages(self, session, service, region, operation, key, **arguments):
            assert (service, operation, key) == ("quicksight", "list_vpc_connections", "VPCConnectionSummaries")
            assert arguments == {"AwsAccountId": "111111111111"}
            return ReadResult([], "empty")
    assert quicksight_connections(Requests(), None, "us-east-1", "111111111111").status == "empty"


@pytest.mark.parametrize("kind", ["rest_api", "http_api"])
def test_api_network_integrations_use_native_methods_and_are_safe_before_cache(kind):
    from peaso.collectors.aws import Requests
    from peaso.collectors.aws_network_catalog import api_integrations
    calls = []
    class Client:
        def can_paginate(self, operation):
            return True
        def get_paginator(self, operation):
            token = "position" if kind == "rest_api" else "NextToken"
            return SimpleNamespace(_pagination_cfg={"input_token": token, "output_token": token})
        def get_resources(self, **args):
            calls.append(args)
            return {"items": [{"id": "resource", "resourceMethods": {"GET": {"methodIntegration": {
                "connectionId": "link", "connectionType": "VPC_LINK", "uri": "https://user:SECRET_SENTINEL@example.com/path?key=SECRET_SENTINEL",
                "requestTemplates": {"application/json": "SECRET_SENTINEL"}}}}}],
                    **({} if args.get("position") else {"position": "next-page"})}
        def get_integrations(self, **args):
            calls.append(args)
            return {"Items": [{"IntegrationId": "integration", "ConnectionId": "link", "ConnectionType": "VPC_LINK",
                "IntegrationUri": "https://example.com/path?key=SECRET_SENTINEL", "RequestParameters": {"header": "SECRET_SENTINEL"}}],
                    **({} if args.get("NextToken") else {"NextToken": "next-page"})}
    class Session:
        def client(self, service, **kwargs):
            return Client()
    requests = Requests({"retry_attempts": 1})
    row = {"id": "api"} if kind == "rest_api" else {"ApiId": "api"}
    result = api_integrations(kind)(requests, Session(), "us-east-1", [row])
    assert len(calls) == 2 and requests.calls == 2
    assert result[0]["_coverage"]["NetworkResources" if kind == "rest_api" else "NetworkIntegrations"]["status"] == "collected"
    assert "link" in json.dumps(result)
    assert "SECRET_SENTINEL" not in json.dumps([future.result() for future in requests._cache.values()])


def test_new_aws_sdk_operations_and_iam_permissions_are_reviewed():
    from peaso.collectors.aws_network_catalog import SPECS, READ_ACTIONS
    from scripts.peaso_deploy_customer_policy import build_policy, iam_action, VERIFIED_ACTIONS
    reads = READ_ACTIONS | {(s, op) for s, op, _ in SPECS.values()}
    assert all(iam_action(s, op) in VERIFIED_ACTIONS for s, op in reads)
    policy = build_policy(reads)
    gateway = next(s for s in policy["Statement"] if s["Sid"] == "ApiGatewayConfigurationRead")
    assert {row["Fn::Sub"] for row in gateway["Resource"]} == {
        "arn:${AWS::Partition}:apigateway:*::/vpclinks", "arn:${AWS::Partition}:apigateway:*::/restapis/*/resources",
        "arn:${AWS::Partition}:apigateway:*::/apis/*/integrations"}


def test_generated_customer_role_contains_network_metadata_reads_within_iam_limits():
    from pathlib import Path
    from scripts.peaso_deploy_customer_policy import build_policy, split_policy, policy_size
    template = json.loads((Path(__file__).resolve().parents[1] / "infra/aws/customer-role.json").read_text())
    documents = [resource["Properties"]["PolicyDocument"] for name, resource in sorted(template["Resources"].items())
                 if resource["Type"] == "AWS::IAM::ManagedPolicy"]
    assert documents == split_policy(build_policy())
    assert all(policy_size(document) <= 6144 for document in documents)
    assert len(documents) <= 10
    actions = {action for document in documents for statement in document["Statement"]
               for action in ([statement["Action"]] if isinstance(statement["Action"], str) else statement["Action"])}
    assert {"quicksight:ListVPCConnections", "osis:GetPipeline", "eks:DescribeFargateProfile", "route53:GetHostedZone"} <= actions
    assert not actions & {"secretsmanager:GetSecretValue", "s3:GetObject", "s3:GetObjectVersion"}
