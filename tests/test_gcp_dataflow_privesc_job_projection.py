"""Only exact Dataflow worker/code references survive the read-only projection."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys
from types import ModuleType


MODULE = "peaso.collectors.gcp_dataflow_privesc_jobs"
ROOT = Path(__file__).resolve().parents[1]


def projection():
    package = ModuleType("peaso.collectors")
    package.__path__ = [str(ROOT / "peaso/collectors")]
    sys.modules.setdefault("peaso.collectors", package)
    spec = spec_from_file_location(MODULE, ROOT / "peaso/collectors/gcp_dataflow_privesc_jobs.py")
    module = module_from_spec(spec)
    sys.modules[MODULE] = module
    spec.loader.exec_module(module)
    return module


def job():
    return {"projectId": "p1", "id": "job_1", "location": "us-central1",
            "currentState": "JOB_STATE_RUNNING", "type": "JOB_TYPE_STREAMING",
            "labels": {"secret": "must-not-be-stored"},
            "environment": {"serviceAccountEmail": "worker@p1.iam.gserviceaccount.com",
                            "sdkPipelineOptions": {"options": {
                                "pythonExternalTextTransformGcsPath": "gs://code-bucket/udf.py",
                                "unrelated_secret": "must-not-be-stored"}},
                            "workerPools": [{"packages": [
                                {"name": "pinned.py", "location": "storage.googleapis.com/code-bucket/pinned.py",
                                 "sha256": "a" * 64},
                                {"name": "mutable.py", "location": "storage.googleapis.com/code-bucket/mutable.py"}]}]}}




def test_foreign_or_incomplete_job_fails_closed():
    module = projection()
    for mutate in (
        lambda row: row.update(projectId="other"),
        lambda row: row["environment"].pop("workerPools"),
        lambda row: row["environment"]["workerPools"][0]["packages"][0].update(sha256="bad"),
    ):
        value = job()
        mutate(value)
        try:
            module.project_job(value, "projects/p1", {"p1", "123"})
        except ValueError:
            pass
        else:
            raise AssertionError("invalid Dataflow job was accepted")


def test_generation_pinned_or_unrelated_options_do_not_become_artifact_edges():
    module = projection()
    value = job()
    value["environment"]["sdkPipelineOptions"]["options"].update({
        "pythonExternalTextTransformGcsPath": "gs://code-bucket/udf.py#123",
        "yaml_pipeline_file": "gs://code-bucket/launcher-only.yaml",
        "other": "gs://code-bucket/not-code.txt"})
    result = module.project_job(value, "projects/p1", {"p1"})
    assert {r["object"] for r in result["codeObjects"]} == {"pinned.py", "mutable.py"}


def test_documented_default_worker_is_joined_by_verified_project_number():
    module = projection()
    value = job()
    value["environment"].pop("serviceAccountEmail")
    result = module.project_job(value, "projects/p1", {"p1", "123"}, "123")
    assert result["workerServiceAccountEmail"] == "123-compute@developer.gserviceaccount.com"
    assert result["workerIdentitySource"] == "documented_default"
    assert module.project_job(value, "projects/p1", {"p1"})["workerServiceAccountEmail"] is None


def test_object_metadata_keeps_only_replacement_blockers():
    module = projection()
    row = {"bucket": "code-bucket", "name": "udf.py", "generation": "123",
           "temporaryHold": False, "eventBasedHold": True,
           "retention": {"mode": "Locked", "retainUntilTime": "2030-01-01T00:00:00Z"},
           "metadata": {"password": "must-not-be-stored"}}
    result = module._metadata(row, "code-bucket", "udf.py")
    assert result["eventBasedHold"] is True
    assert result["retainUntilTime"] == "2030-01-01T00:00:00Z"
    assert "must-not-be-stored" not in repr(result)
    try:
        module._metadata(row, "other-bucket", "udf.py")
    except ValueError:
        pass
    else:
        raise AssertionError("foreign object metadata was accepted")




def test_active_batch_template_is_projected_without_parameters():
    module = projection()
    row = {
        "name": "projects/p1/locations/us-central1/pipelines/daily",
        "type": "PIPELINE_TYPE_BATCH", "state": "STATE_ACTIVE",
        "scheduleInfo": {"schedule": "0 2 * * *"},
        "workload": {"dataflowLaunchTemplateRequest": {
            "projectId": "p1", "gcsPath": "gs://code-bucket/template.json",
            "launchParameters": {"environment": {
                "serviceAccountEmail": "worker@p1.iam.gserviceaccount.com"},
                "parameters": {"password": "must-not-be-stored"}}}}}
    result = module.project_pipeline(row, "projects/p1", "123")
    assert result["templateObject"] == {"kind": "standard_template", "bucket": "code-bucket",
                                        "object": "template.json"}
    assert result["workerServiceAccountEmail"] == "worker@p1.iam.gserviceaccount.com"
    assert result["schedulePresent"] is True
    assert "must-not-be-stored" not in repr(result)
    row["scheduleInfo"] = {}
    assert module.project_pipeline(row, "projects/p1", "123")["schedulePresent"] is False
    row["state"] = "STATE_PAUSED"
    assert module.project_pipeline(row, "projects/p1", "123") is None


def test_pipeline_pages_enumerates_locations_and_active_batch_templates(monkeypatch):
    module = projection()
    fake_gcp = ModuleType("peaso.collectors.gcp")
    fake_gcp.ReadError = type("ReadError", (Exception,), {})
    monkeypatch.setitem(sys.modules, "peaso.collectors.gcp", fake_gcp)

    class Collector:
        collections = {("project", "projects/p1"): {"items": [
            {"projectId": "p1", "name": "projects/123"}]}}

        def pages(self, url, scope, **kwargs):
            assert scope == "projects/p1"
            if "appengine.googleapis.com" in url:
                yield ([{"locationId": "us-central1"}], "locations")
            else:
                assert url.endswith("/locations/us-central1/pipelines")
                assert kwargs["params"]["filter"] == "type:BATCH,status:ACTIVE"
                yield ([{"name": "projects/p1/locations/us-central1/pipelines/daily",
                         "type": "PIPELINE_TYPE_BATCH", "state": "STATE_ACTIVE",
                         "scheduleInfo": {"schedule": "0 2 * *"},
                         "workload": {"dataflowFlexTemplateRequest": {
                             "projectId": "p1", "launchParameter": {
                                 "containerSpecGcsPath": "gs://code-bucket/spec.json",
                                 "environment": {}}}}}], "pipelines")

    pages = list(module.pipeline_pages(Collector(), "projects/p1"))
    assert pages[0] == ([], "locations")
    assert pages[-1][0][0]["templateObject"]["object"] == "spec.json"
    assert pages[-1][0][0]["workerServiceAccountEmail"] == "123-compute@developer.gserviceaccount.com"
