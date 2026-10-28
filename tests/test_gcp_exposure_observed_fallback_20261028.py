"""New GCP paths retain resource-first observed evidence in every verdict."""

import pytest

from peaso.analysis.internet_exposure import Assessment, _observed


@pytest.mark.parametrize("resource_type", (
    "developerconnect_account_connector", "developerconnect_connection",
    "developerconnect_git_repository_link", "firestore_database",
    "livestream_input", "managed_kafka_cluster", "secure_source_manager_instance",
))
@pytest.mark.parametrize("status", ("FAIL", "PASS", "UNKNOWN"))
def test_new_gcp_path_has_connected_recorded_observation(resource_type, status):
    resource = {"provider": "gcp", "type": resource_type, "data": {}}
    assessment = Assessment(resource, "database" if resource_type == "firestore_database" else "managed_endpoint")
    if status == "FAIL":
        assessment.step("public_endpoint", "allow", endpoint="example.invalid")
        assessment.endpoint = "example.invalid"
    elif status == "PASS":
        assessment.step("public_endpoint", "block")
    else:
        assessment.gap("public_endpoint", "endpoint value is missing")
    lines = _observed(assessment, status).splitlines()
    assert len(lines) == 3
    assert lines[0].startswith("The " + resource_type.replace("_", " "))
    assert all(line.endswith(".") for line in lines)
    if status == "UNKNOWN":
        assert "public endpoint" in lines[0]
        assert "endpoint value is missing" in lines[0]
