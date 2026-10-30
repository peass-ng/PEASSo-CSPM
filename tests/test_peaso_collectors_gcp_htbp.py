"""GCP collector additions for HackTricks Best Practices checks: stubbed, read-only, no secret values."""
from __future__ import annotations

import json

from peaso.collectors import gcp
from tests.test_peaso_collectors_gcp import collection, snapshot


def denied(request):
    raise gcp.ReadError("denied", "api_error", http_status=403)


def test_sanitize_keeps_token_identity_and_environment_names_only():
    result = gcp.sanitize({
        "pushConfig": {"pushEndpoint": "https://x", "oidcToken": {"serviceAccountEmail": "sa@p.iam.gserviceaccount.com", "audience": "a"}},
        "accessToken": "ya29.do-not-store", "oauthToken": "raw-string-token-do-not-store",
        "serviceConfig": {"environmentVariables": {"DB_PASSWORD": "do-not-store", "PORT": "8080"},
                          "secretEnvironmentVariables": [{"key": "API_KEY", "projectId": "p", "secret": "s", "version": "latest", "value": "do-not-store"}]},
        "buildConfig": {"environmentVariables": [{"name": "GOFLAGS", "value": "do-not-store"}]}})
    dumped = json.dumps(result)
    assert "do-not-store" not in dumped
    assert result["pushConfig"]["oidcToken"] == {"serviceAccountEmail": "sa@p.iam.gserviceaccount.com", "audience": "a"}
    assert "oauthToken" not in result and "accessToken" not in result
    assert result["serviceConfig"]["environmentVariableNames"] == ["DB_PASSWORD", "PORT"]
    assert result["serviceConfig"]["secretEnvironmentVariables"] == [{"key": "API_KEY", "projectId": "p", "secret": "s", "version": "latest"}]
    assert result["buildConfig"]["environmentVariableNames"] == ["GOFLAGS"]


def test_cloudbuild_triggers_paginate_and_drop_inline_build_and_substitution_values():
    def resolve(request):
        assert request["method"] == "GET"
        assert request["url"] == "https://cloudbuild.googleapis.com/v1/projects/p-one/locations/global/triggers"
        if request["params"].get("pageToken") == "t2":
            return {"triggers": [{"id": "2", "name": "push", "resourceName": "projects/p-one/locations/global/triggers/2"}]}
        return {"nextPageToken": "t2", "triggers": [{
            "id": "1", "name": "pr", "resourceName": "projects/p-one/locations/global/triggers/1",
            "github": {"owner": "o", "name": "r", "pullRequest": {"branch": "^main$"}},
            "substitutions": {"_TOKEN": "do-not-store"},
            "build": {"steps": [{"name": "bash", "script": "curl do-not-store", "args": ["do-not-store"], "env": ["K=do-not-store"]}]}}]}
    result, transport = snapshot(["cloudbuild_trigger"], resolve, cloudbuild_locations=[])
    triggers = collection(result, "cloudbuild_trigger")
    assert triggers["status"] == "collected" and len(triggers["items"]) == 2 and transport.calls == 2
    assert "do-not-store" not in json.dumps(result)
    first = next(x for x in triggers["items"] if x["id"] == "1")
    assert first["substitutionNames"] == ["_TOKEN"] and first["inlineBuild"]["stepCount"] == 1
    assert first["_provenance"]["representation"] == "full"
    assert collection(snapshot(["cloudbuild_trigger"], denied)[0], "cloudbuild_trigger")["status"] == "denied"


def test_cloudbuild_regional_triggers_only_when_selected():
    seen = []
    def resolve(request):
        seen.append(request["url"])
        if "/locations/europe-west1/" in request["url"]:
            raise gcp.ReadError("denied", "api_error", http_status=403)
        return {"triggers": [{"id": "1", "resourceName": "projects/p-one/locations/global/triggers/1"}]}
    result, _ = snapshot(["cloudbuild_trigger"], resolve, cloudbuild_locations=["europe-west1"])
    assert len(seen) == 2 and collection(result, "cloudbuild_trigger")["status"] == "partial"


def test_hmac_keys_are_metadata_only():
    def resolve(request):
        assert request["url"] == "https://storage.googleapis.com/storage/v1/projects/p-one/hmacKeys"
        return {"items": [{"kind": "storage#hmacKeyMetadata", "id": "p-one/GOOG1", "accessId": "GOOG1",
            "selfLink": "https://www.googleapis.com/storage/v1/projects/p-one/hmacKeys/GOOG1", "secret": "do-not-store",
            "serviceAccountEmail": "sa@p-one.iam.gserviceaccount.com", "state": "ACTIVE", "timeCreated": "2025-01-01T00:00:00Z", "etag": "e"}]}
    result, _ = snapshot(["storage_hmac_key"], resolve)
    item = collection(result, "storage_hmac_key")["items"][0]
    assert item["state"] == "ACTIVE" and "secret" not in item and "do-not-store" not in json.dumps(result)
    assert collection(snapshot(["storage_hmac_key"], denied)[0], "storage_hmac_key")["status"] == "denied"


def test_composer_regions_bounded_and_env_values_dropped():
    def resolve(request):
        url = request["url"]
        if url.endswith("/regions"):
            return {"items": [{"name": "us-central1"}, {"name": "me-central2"}]}
        if "me-central2" in url:
            raise gcp.http_error(403, {"error": {"details": [{"reason": "LOCATION_POLICY_VIOLATED"}]}})
        assert url == "https://composer.googleapis.com/v1/projects/p-one/locations/us-central1/environments"
        return {"environments": [{"name": "projects/p-one/locations/us-central1/environments/e", "config": {
            "nodeConfig": {"serviceAccount": "1-compute@developer.gserviceaccount.com"},
            "softwareConfig": {"envVariables": {"SMTP_PASSWORD": "do-not-store"}, "airflowConfigOverrides": {"smtp-smtp_password": "do-not-store"}}}}]}
    result, _ = snapshot(["composer_environment"], resolve)
    composer = collection(result, "composer_environment")
    assert composer["status"] == "collected" and "do-not-store" not in json.dumps(result)
    software = composer["items"][0]["config"]["softwareConfig"]
    assert software["envVariableNames"] == ["SMTP_PASSWORD"] and software["airflowConfigOverrideNames"] == ["smtp-smtp_password"]


def test_workbench_wildcard_list_and_metadata_values_allowlisted():
    def resolve(request):
        if request["url"].endswith(":getIamPolicy"):
            # Each listed instance's IAM policy is hydrated (75087001).
            assert request["url"] == "https://notebooks.googleapis.com/v2/projects/p-one/locations/us-central1-a/instances/nb:getIamPolicy"
            return {"bindings": []}
        assert request["url"] == "https://notebooks.googleapis.com/v2/projects/p-one/locations/-/instances"
        return {"instances": [{"name": "projects/p-one/locations/us-central1-a/instances/nb", "gceSetup": {
            "serviceAccounts": [{"email": "1-compute@developer.gserviceaccount.com"}],
            "metadata": {"notebook-disable-root": "true", "post-startup-script": "gs://do-not-store/s.sh"}}}]}
    result, _ = snapshot(["workbench_instance"], resolve)
    instance = collection(result, "workbench_instance")["items"][0]
    assert instance["gceSetup"]["metadata"] == {"notebook-disable-root": "true", "post-startup-script": None}
    assert instance["iamPolicy"] == {"bindings": []}
    unavailable = snapshot(["workbench_instance"], lambda r: (_ for _ in ()).throw(gcp.ReadError("unavailable", "api_error", http_status=400)))[0]
    assert collection(unavailable, "workbench_instance")["status"] == "unknown"


def test_scheduler_jobs_keep_identity_and_path_drop_body_headers_query():
    def resolve(request):
        url = request["url"]
        if url.endswith("/locations"):
            return {"locations": [{"name": "projects/p-one/locations/us-central1", "locationId": "us-central1"}]}
        assert url == "https://cloudscheduler.googleapis.com/v1/projects/p-one/locations/us-central1/jobs"
        return {"jobs": [{"name": "projects/p-one/locations/us-central1/jobs/j", "state": "ENABLED", "httpTarget": {
            "uri": "https://cloudresourcemanager.googleapis.com/v1/projects/p-one:setIamPolicy?key=do-not-store",
            "httpMethod": "POST", "body": "ZG8tbm90LXN0b3Jl", "headers": {"X-Api-Key": "do-not-store"},
            "oauthToken": {"serviceAccountEmail": "sa@p-one.iam.gserviceaccount.com", "scope": "https://www.googleapis.com/auth/cloud-platform"}}}]}
    result, _ = snapshot(["scheduler_job"], resolve)
    target = collection(result, "scheduler_job")["items"][0]["httpTarget"]
    assert "do-not-store" not in json.dumps(result) and "ZG8tbm90LXN0b3Jl" not in json.dumps(result)
    assert target["uri"] == "https://cloudresourcemanager.googleapis.com/v1/projects/p-one:setIamPolicy"
    assert target["headerNames"] == ["X-Api-Key"] and target["oauthToken"]["serviceAccountEmail"] == "sa@p-one.iam.gserviceaccount.com"
    assert collection(snapshot(["scheduler_job"], denied)[0], "scheduler_job")["status"] == "denied"


def test_location_option_is_bounded():
    result, transport = snapshot(["scheduler_job"], lambda r: {"jobs": []}, cloudscheduler_locations=["r"] * 1 + [f"r{i}" for i in range(100)])
    assert collection(result, "scheduler_job")["status"] == "unknown" and transport.calls == 0


def test_domains_registrations_global_name_and_state_only():
    listing = "https://domains.googleapis.com/v1/projects/p-one/locations/global/registrations"
    def resolve(request):
        if not request["url"].startswith("https://domains.googleapis.com/"):
            # 16bb81e0 also reads the project and its IAM policy/roles for the
            # registration-owner join; none of them touches registrant contacts.
            assert "registrations" not in request["url"], request
            return {}
        if request["url"].endswith(":getIamPolicy"):
            assert request["url"] == listing + "/example.com:getIamPolicy" and request["method"] == "GET"
            return {"bindings": []}
        assert request["method"] == "GET"
        assert request["url"] == listing
        assert request["params"]["fields"] == "registrations(name,domainName,state,expireTime,dnsSettings),nextPageToken"
        return {"registrations": [{"name": "projects/p-one/locations/global/registrations/example.com", "domainName": "example.com",
                                   "state": "ACTIVE", "contactSettings": {"registrantContact": {"email": "do-not-store"}}}]}
    result, transport = snapshot(["domains_registration"], resolve)
    registrations = collection(result, "domains_registration")
    assert registrations["status"] == "collected"
    assert [r["url"] for r in transport.requests if r["url"].startswith(listing)] == [listing, listing + "/example.com:getIamPolicy"]
    assert registrations["items"][0]["domainName"] == "example.com" and "do-not-store" not in json.dumps(result)
    assert collection(snapshot(["domains_registration"], denied)[0], "domains_registration")["status"] == "denied"


def _groups(settings):
    def resolve(request):
        url = request["url"]
        if url == "https://cloudidentity.googleapis.com/v1/groups":
            return {"groups": [{"name": "groups/g1", "groupKey": {"id": "open@example.com"}},
                               {"name": "groups/g2", "groupKey": {"id": "closed@example.com"}}]}
        if url.startswith("https://www.googleapis.com/groups/v1/groups/"):
            assert request["method"] == "GET" and request["params"] == {"alt": "json"}
            return settings(url.rsplit("/", 1)[1])
        return {"items": []}
    return resolve


def test_group_settings_are_optional_and_keep_join_flags_only():
    calls = []
    def settings(email):
        calls.append(email)
        if email.startswith("closed"):
            raise gcp.ReadError("denied", "api_error", http_status=403)
        return {"email": email, "whoCanJoin": "ANYONE_CAN_JOIN", "allowExternalMembers": "true", "description": "do-not-store"}
    result, _ = snapshot(["group"], _groups(settings), cloud_identity_customers=["Cfixture"])
    assert not calls  # not read unless group_settings=true
    result, _ = snapshot(["group"], _groups(settings), cloud_identity_customers=["Cfixture"], group_settings=True)
    groups = {g["groupKey"]["id"]: g for g in collection(result, "group")["items"]}
    assert sorted(calls) == ["closed@example.com", "open@example.com"]
    assert groups["open@example.com"]["groupSettings"] == {"whoCanJoin": "ANYONE_CAN_JOIN", "allowExternalMembers": "true"}
    assert groups["open@example.com"]["_coverage"]["groupSettings"]["status"] == "collected"
    assert "groupSettings" not in groups["closed@example.com"]
    assert groups["closed@example.com"]["_coverage"]["groupSettings"]["status"] == "denied"
    assert "do-not-store" not in json.dumps(result)


def test_bucket_notifications_read_per_collected_bucket_without_custom_attribute_values():
    def resolve(request):
        url = request["url"]
        if url == "https://storage.googleapis.com/storage/v1/b":
            return {"items": [{"name": "data", "projectNumber": "111"}]}
        if url.endswith("/iam"):
            return {"bindings": []}
        assert url == "https://storage.googleapis.com/storage/v1/b/data/notificationConfigs"
        assert "pageSize" not in request["params"] and "maxResults" not in request["params"]
        return {"kind": "storage#notifications", "items": [{"id": "7", "topic": "//pubsub.googleapis.com/projects/other/topics/t",
                "payload_format": "JSON_API_V1", "custom_attributes": {"token": "do-not-store"}}]}
    result, _ = snapshot(["bucket_notification"], resolve)
    configs = collection(result, "bucket_notification")
    assert configs["status"] == "collected"
    item = configs["items"][0]
    assert item["bucket"] == "data" and item["bucketProject"] == "p-one" and item["customAttributeNames"] == ["token"]
    assert "do-not-store" not in json.dumps(result)
    def bucket_denied(request):
        if request["url"] == "https://storage.googleapis.com/storage/v1/b":
            raise gcp.ReadError("denied", "api_error", http_status=403)
        return {"items": []}
    assert collection(snapshot(["bucket_notification"], bucket_denied)[0], "bucket_notification")["status"] != "collected"
