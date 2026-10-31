"""The project service catalog keeps enabled services and only the disabled services something reads."""
from types import SimpleNamespace

from peaso.collectors.gcp import GCPCollector


def row(service, state):
    return {"name": f"projects/p/services/{service}", "state": state}


def test_disabled_catalog_rows_are_dropped_unless_read_by_name():
    usage = {"type": "service_usage", "scope": "projects/p", "items": [
        row("compute.googleapis.com", "ENABLED"), row("custom.example.cloud.goog", "ENABLED"),
        row("run.googleapis.com", "DISABLED"), row("translate.googleapis.com", "DISABLED"),
        row("a10-thunder.endpoints.vendor.cloud.goog", "DISABLED"), row("speech.googleapis.com", "DISABLED")]}
    keys = {"items": [{"name": "projects/p/locations/global/keys/k",
                       "restrictions": {"apiTargets": [{"service": "translate.googleapis.com"}]}}]}
    other = {"type": "service_usage", "scope": "projects/q", "items": [row("speech.googleapis.com", "DISABLED")]}
    collector = SimpleNamespace(collections={("service_usage", "projects/p"): usage, ("api_key", "projects/p"): keys,
                                             ("service_usage", "projects/q"): other})
    GCPCollector.prune_disabled_services(collector)
    kept = {r["name"].rsplit("/", 1)[1]: r["state"] for r in usage["items"]}
    assert kept == {"compute.googleapis.com": "ENABLED", "custom.example.cloud.goog": "ENABLED",
                    "run.googleapis.com": "DISABLED", "translate.googleapis.com": "DISABLED"}
    assert usage["omitted_disabled_services"] == 2
    assert other["items"] == []  # an API key in another project does not keep this project's row
