"""Offline native Service Usage DNS join regression; no provider calls."""

from copy import deepcopy

import pytest

from peaso.collectors import gcp
from peaso.engine import evaluate_snapshot, plan_collection
from peaso.snapshot import validate
from tests.test_peaso_gcp_api_key_alias_native import Transport, SCOPE, NUMBER, CHECK


TARGET = "compute.googleapis.com"
MARKET = "listing.endpoints.publisher.cloud.goog"


class NativeTransport(Transport):
    def __init__(self, *, targets=(TARGET,), rows=None):
        super().__init__()
        self.targets = targets
        # The unrelated row is ENABLED: unrelated DISABLED catalog rows are not stored.
        self.rows = rows if rows is not None else [(TARGET, "DISABLED"), (MARKET, "ENABLED")]

    def request(self, method, url, **kwargs):
        response, ref = super().request(method, url, **kwargs)
        if url.startswith("https://apikeys.googleapis.com/"):
            response["keys"][0]["restrictions"]["apiTargets"] = [
                {"service": name} for name in self.targets]
        elif url.startswith("https://serviceusage.googleapis.com/"):
            response["services"] = [{"name": NUMBER + "/services/" + name,
                                     "parent": NUMBER, "config": {"name": name},
                                     "state": state} for name, state in self.rows]
        return response, ref


def capture(*, targets=(TARGET,), rows=None, mutate=None, mutate_collection=None):
    request = {"connector": {"provider": "gcp", "scopes": [SCOPE], "options": {
        "include_inherited": False, "metrics_scopes": False, "concurrency": 1}}, "checks": [CHECK]}
    requirements = plan_collection(request)
    assert requirements == ["api_key", "service_usage"]
    transport = NativeTransport(targets=targets, rows=rows)
    collector = gcp.GCPCollector(request["connector"], requirements, transport=transport)
    snapshot = collector.collect()
    assert len(transport.requests) == 3
    usage = next(c for c in snapshot["collections"] if c["type"] == "service_usage")
    if mutate:
        mutate(usage["items"])
    if mutate_collection:
        mutate_collection(usage)
    if mutate or mutate_collection:
        snapshot.pop("snapshot_id")
    snapshot = validate(snapshot)
    before = deepcopy(snapshot)
    findings = evaluate_snapshot(snapshot, checks=[CHECK])["findings"]
    assert snapshot == before
    assert len(findings) == 1
    return findings[0]


def test_fully_resolved_disabled_target_with_unrelated_marketplace_is_fail():
    assert capture()["status"] == "FAIL"


def test_marketplace_target_and_filtered_optional_config_are_supported():
    assert capture(targets=(MARKET,), rows=[(TARGET, "DISABLED"), (MARKET, "DISABLED")],
                   mutate=lambda rows: rows[1].pop("config"))["status"] == "FAIL"


def test_case_insensitive_api_target_and_service_dns_join():
    assert capture(targets=(TARGET.upper(),), rows=[(TARGET.upper(), "DISABLED"),
                                                       (MARKET, "DISABLED")])["status"] == "FAIL"


def test_missing_target_remains_unknown_even_with_another_disabled_target():
    assert capture(targets=(TARGET, "absent.example.org"))["status"] == "UNKNOWN"


def test_enabled_only_remains_unknown():
    assert capture(rows=[(TARGET, "ENABLED"), (MARKET, "DISABLED")])["status"] == "UNKNOWN"


@pytest.mark.parametrize("mutate", [
    lambda rows: rows[1].update(name="projects/foreign/services/" + MARKET),
    lambda rows: rows[1].update(parent="projects/foreign"),
    lambda rows: rows[1]["config"].update(name="other.example.org"),
    lambda rows: rows[1].update(state="STATE_UNSPECIFIED"),
    lambda rows: rows[1].update(rawNativeName="projects/999/services/" + MARKET),
    lambda rows: rows[1]["_provenance"]["derived_project_alias"].update(canonical_name="projects/foreign/services/" + MARKET),
    lambda rows: rows[1].update(name=SCOPE + "/services/invalid..example.org"),
])
def test_foreign_malformed_or_contradictory_native_fact_is_unknown(mutate):
    assert capture(mutate=mutate)["status"] == "UNKNOWN"


def test_casefold_duplicate_service_identity_is_unknown():
    assert capture(rows=[(TARGET, "DISABLED"), (TARGET.upper(), "DISABLED")])["status"] == "UNKNOWN"


def test_partial_service_usage_coverage_is_unknown():
    assert capture(mutate_collection=lambda collection: collection.update(coverage_status="partial"))["status"] == "UNKNOWN"


@pytest.mark.parametrize("path", ["parent", "config", "config.name", "rawNativeName",
                                  "_provenance.derived_project_alias",
                                  "_provenance.derived_project_alias.project_identity_source_requests"])
def test_present_native_identity_fields_marked_denied_remain_unknown(path):
    def denied(rows):
        row = rows[0]
        parts = path.split('.')
        for field in parts[:-1]:
            row = row[field]
        row.setdefault('_coverage', {})[parts[-1]] = {'status': 'denied'}
    assert capture(mutate=denied)['status'] == 'UNKNOWN'
