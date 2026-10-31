"""SERVICE_DISABLED can name the consumer project by number while the scan uses the project ID."""
from types import SimpleNamespace

import pytest

from peaso.collectors import gcp

SCOPE = "projects/fixture-project"
NUMBER = "projects/12345"


def collector(project_rows):
    value = gcp.GCPCollector({"provider": "gcp", "scopes": [SCOPE], "options": {"inventories": ["bucket"]}},
                             transport=SimpleNamespace(evidence=[]))
    if project_rows is not None:
        value.collections[("project", SCOPE)] = {"type": "project", "scope": SCOPE, "status": "collected",
                                                  "items": project_rows, "source_requests": ["r0"]}
    return value


def disabled(consumer):
    def fetch():
        error = gcp.ReadError("unavailable", "api_error", http_status=403, reason="SERVICE_DISABLED")
        error.error.update({"consumer": consumer, "service": "storage.googleapis.com"})
        error.request_id = "r1"
        raise error
        yield  # pragma: no cover
    return fetch


@pytest.mark.parametrize("consumer", [SCOPE, NUMBER])
def test_disabled_service_recorded_for_the_scanned_project(consumer):
    value = collector([{"name": NUMBER, "projectId": "fixture-project"}])
    envelope = value.add("bucket", SCOPE, "storage", disabled(consumer))
    assert envelope["service_state"]["state"] == "disabled"
    assert envelope["service_state"]["consumer"] == SCOPE


@pytest.mark.parametrize("rows,consumer", [
    ([{"name": NUMBER, "projectId": "fixture-project"}], "projects/99999"),  # quota project, not the target
    (None, NUMBER),  # number never proved by a project read
])
def test_unproved_numeric_consumer_is_not_the_scanned_project(rows, consumer):
    value = collector(rows)
    envelope = value.add("bucket", SCOPE, "storage", disabled(consumer))
    value.bind_numeric_disabled_consumers()
    assert "service_state" not in envelope


def test_project_read_after_the_failed_read_still_binds_at_finish():
    value = collector(None)
    envelope = value.add("bucket", SCOPE, "storage", disabled(NUMBER))
    value.collections[("project", SCOPE)] = {"type": "project", "scope": SCOPE, "status": "collected",
                                              "items": [{"name": NUMBER, "projectId": "fixture-project"}]}
    value.bind_numeric_disabled_consumers()
    assert value.collections[("bucket", SCOPE)]["service_state"]["consumer"] == SCOPE
