"""Project active Dataflow jobs to worker identities and code object references.

The projection discards arbitrary pipeline options and job steps. It never reads
artifact contents and does not infer execution from an unrelated bucket object.
"""

from __future__ import annotations

import re
from urllib.parse import quote


_JOB_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_REGION = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
_EMAIL = re.compile(r"[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.iam\.gserviceaccount\.com\Z")
_BUCKET = re.compile(r"[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]\Z")
_UDF_KEYS = frozenset({"pythonExternalTextTransformGcsPath", "javascriptTextTransformGcsPath"})
_PIPELINE_NAME = re.compile(r"projects/([^/]+)/locations/([a-z][a-z0-9-]{0,62})/pipelines/([A-Za-z0-9_-]{1,128})\Z")


def _object_ref(raw):
    if not isinstance(raw, str):
        return None
    if raw.startswith("gs://"):
        path = raw[5:]
    elif raw.startswith("storage.googleapis.com/"):
        path = raw[len("storage.googleapis.com/"):]
    else:
        return None
    if "/" not in path or any(mark in path for mark in ("?", "#", "\n", "\r")):
        return None
    bucket, obj = path.split("/", 1)
    if not _BUCKET.fullmatch(bucket) or not obj or len(obj.encode()) > 1024:
        return None
    return bucket, obj


def _udf_refs(options, depth=0):
    if not isinstance(options, dict) or depth > 4:
        return []
    out = []
    for key, value in options.items():
        if key in _UDF_KEYS:
            ref = _object_ref(value)
            if ref:
                out.append({"kind": "udf_or_yaml", "bucket": ref[0], "object": ref[1],
                            "sha256": None})
        elif key in ("options", "parameters", "pipelineOptions") and isinstance(value, dict):
            out.extend(_udf_refs(value, depth + 1))
    return out


def project_job(row, project, aliases, default_number=None):
    if not isinstance(row, dict) or row.get("projectId") not in aliases:
        raise ValueError("dataflow_project_identity")
    job_id, region = row.get("id"), row.get("location")
    if not isinstance(job_id, str) or not _JOB_ID.fullmatch(job_id) or not isinstance(region, str) or not _REGION.fullmatch(region):
        raise ValueError("dataflow_job_identity")
    environment = row.get("environment")
    if not isinstance(environment, dict):
        raise ValueError("dataflow_job_environment")
    email = environment.get("serviceAccountEmail")
    identity_source = "explicit"
    if email in (None, "") and isinstance(default_number, str) and default_number.isdigit():
        email = f"{default_number}-compute@developer.gserviceaccount.com"
        identity_source = "documented_default"
    elif email in (None, ""):
        email = None
        identity_source = "unresolved_default"
    if email is not None and (not isinstance(email, str) or not _EMAIL.fullmatch(email)):
        if identity_source != "documented_default" or not re.fullmatch(r"[0-9]+-compute@developer\.gserviceaccount\.com", email):
            raise ValueError("dataflow_worker_identity")
    pools = environment.get("workerPools")
    if not isinstance(pools, list) or len(pools) > 32:
        raise ValueError("dataflow_worker_pools")
    references = []
    for pool in pools:
        if (not isinstance(pool, dict) or not isinstance(pool.get("packages", []), list)
                or len(pool.get("packages", [])) > 64):
            raise ValueError("dataflow_packages")
        for package in pool.get("packages", []):
            if not isinstance(package, dict):
                raise ValueError("dataflow_package")
            ref = _object_ref(package.get("location"))
            if not ref:
                continue
            checksum = package.get("sha256")
            if checksum is not None and (not isinstance(checksum, str)
                                         or not re.fullmatch(r"[0-9a-fA-F]{64}", checksum)):
                raise ValueError("dataflow_package_checksum")
            references.append({"kind": "worker_package", "bucket": ref[0],
                               "object": ref[1], "sha256": checksum})
    references.extend(_udf_refs(environment.get("sdkPipelineOptions")))
    deduped = list({(r["kind"], r["bucket"], r["object"], r["sha256"]): r for r in references}.values())
    if len(deduped) > 256:
        raise ValueError("dataflow_code_references_bound")
    return {"name": f"{project}/locations/{region}/jobs/{job_id}", "projectId": project.split("/", 1)[1],
            "location": region, "id": job_id, "currentState": row.get("currentState"),
            "type": row.get("type"), "workerServiceAccountEmail": email,
            "workerIdentitySource": identity_source,
            "codeObjects": deduped, "_representation": "privesc_code_references"}


def _metadata(row, bucket, object_name):
    if (not isinstance(row, dict) or row.get("bucket") != bucket or row.get("name") != object_name
            or not isinstance(row.get("generation"), str)
            or not row["generation"].isdigit() or row.get("timeDeleted")):
        raise ValueError("dataflow_code_object_metadata")
    retention = row.get("retention")
    if retention is not None and not isinstance(retention, dict):
        raise ValueError("dataflow_code_object_retention")
    for key in ("temporaryHold", "eventBasedHold"):
        if key in row and type(row[key]) is not bool:
            raise ValueError("dataflow_code_object_hold")
    return {"generation": row["generation"],
            "temporaryHold": row.get("temporaryHold") is True,
            "eventBasedHold": row.get("eventBasedHold") is True,
            "retentionExpirationTime": row.get("retentionExpirationTime"),
            "retainUntilTime": (retention or {}).get("retainUntilTime")}


def collection_pages(collector, scope):
    from .gcp import ReadError

    project = scope.split("/", 1)[1]
    project_rows = collector.collections.get(("project", scope), {}).get("items", [])
    numbers = [str(item.get("name", "")).split("/")[-1] for item in project_rows
               if item.get("projectId") == project and str(item.get("name", "")).startswith("projects/")]
    aliases = {project, *numbers}
    url = f"https://dataflow.googleapis.com/v1b3/projects/{quote(project, safe='')}/jobs:aggregated"
    for jobs, list_request in collector.pages(url, scope, key="jobs", params={"filter": "ACTIVE"}):
        yield [], list_request
        for job in jobs:
            job_id, region = job.get("id"), job.get("location")
            if (not isinstance(job_id, str) or not _JOB_ID.fullmatch(job_id)
                    or not isinstance(region, str) or not _REGION.fullmatch(region)):
                raise ReadError("malformed", "dataflow_job_identity")
            detail = (f"https://dataflow.googleapis.com/v1b3/projects/{quote(project, safe='')}"
                      f"/locations/{quote(region, safe='')}/jobs/{quote(job_id, safe='')}")
            for rows, get_request in collector.pages(detail, scope, single=True,
                                                      params={"view": "JOB_VIEW_ALL"}):
                try:
                    projected = project_job(rows[0], scope, aliases,
                                            numbers[0] if len(numbers) == 1 and numbers[0].isdigit() else None)
                except ValueError as exc:
                    raise ReadError("malformed", str(exc)) from exc
                metadata_cache = {}
                for artifact in projected["codeObjects"]:
                    if artifact["sha256"]:
                        artifact["metadataStatus"] = "checksum_pinned"
                        continue
                    key = (artifact["bucket"], artifact["object"])
                    if key not in metadata_cache:
                        object_url = ("https://storage.googleapis.com/storage/v1/b/"
                                      + quote(key[0], safe="") + "/o/" + quote(key[1], safe=""))
                        try:
                            metadata, _ = collector.read(object_url, scope)
                            metadata_cache[key] = ("collected", _metadata(metadata, *key))
                        except (ReadError, ValueError):
                            metadata_cache[key] = ("unavailable", None)
                    artifact["metadataStatus"], artifact["metadata"] = metadata_cache[key]
                yield [projected], get_request


def project_pipeline(row, scope, project_number=None):
    """Keep scheduled template references and the intended worker identity."""
    if not isinstance(row, dict):
        raise ValueError("dataflow_pipeline")
    match = _PIPELINE_NAME.fullmatch(str(row.get("name") or ""))
    if not match or match.group(1) != scope.split("/", 1)[1]:
        raise ValueError("dataflow_pipeline_identity")
    if row.get("type") != "PIPELINE_TYPE_BATCH" or row.get("state") != "STATE_ACTIVE":
        return None
    schedule = row.get("scheduleInfo")
    schedule_present = (isinstance(schedule, dict) and isinstance(schedule.get("schedule"), str)
                        and bool(schedule["schedule"]))
    workload = row.get("workload")
    if not isinstance(workload, dict):
        raise ValueError("dataflow_pipeline_workload")
    standard = workload.get("dataflowLaunchTemplateRequest")
    flex = workload.get("dataflowFlexTemplateRequest")
    if isinstance(standard, dict) == isinstance(flex, dict):
        raise ValueError("dataflow_pipeline_template")
    if isinstance(standard, dict):
        path = standard.get("gcsPath")
        parameters = standard.get("launchParameters")
        if parameters is not None and not isinstance(parameters, dict):
            raise ValueError("dataflow_pipeline_launch_parameters")
        environment = (parameters or {}).get("environment")
        kind = "standard_template"
        job_project = standard.get("projectId")
    else:
        parameter = flex.get("launchParameter")
        if parameter is not None and not isinstance(parameter, dict):
            raise ValueError("dataflow_pipeline_launch_parameter")
        parameter = parameter or {}
        path = parameter.get("containerSpecGcsPath")
        environment = parameter.get("environment")
        kind = "flex_container_spec"
        job_project = flex.get("projectId")
    if not isinstance(environment, dict):
        environment = {}
    email = environment.get("serviceAccountEmail")
    identity_source = "explicit"
    if email in (None, ""):
        email = f"{project_number}-compute@developer.gserviceaccount.com" if project_number else None
        identity_source = "documented_default" if email else "unresolved_default"
    if email is not None and (not isinstance(email, str) or
                              not (_EMAIL.fullmatch(email) or
                                   re.fullmatch(r"[0-9]+-compute@developer\.gserviceaccount\.com", email))):
        raise ValueError("dataflow_pipeline_worker_identity")
    ref = _object_ref(path)
    return {"name": row["name"], "projectId": scope.split("/", 1)[1],
            "jobProjectId": job_project, "workerServiceAccountEmail": email,
            "workerIdentitySource": identity_source,
            "schedulePresent": schedule_present,
            "templateObject": ({"kind": kind, "bucket": ref[0], "object": ref[1]} if ref else None),
            "_representation": "batch_template_reference"}


def pipeline_pages(collector, scope):
    from .gcp import ReadError

    project = scope.split("/", 1)[1]
    project_rows = collector.collections.get(("project", scope), {}).get("items", [])
    numbers = [str(item.get("name", "")).split("/")[-1] for item in project_rows
               if item.get("projectId") == project and str(item.get("name", "")).startswith("projects/")]
    number = numbers[0] if len(numbers) == 1 and numbers[0].isdigit() else None
    locations_url = f"https://appengine.googleapis.com/v1/apps/{quote(project, safe='')}/locations"
    for locations, location_request in collector.pages(locations_url, scope, key="locations"):
        yield [], location_request
        # Region identities are checked in order before any pipeline read.
        regions, failure = [], None
        for location in locations:
            region = location.get("locationId") if isinstance(location, dict) else None
            if not isinstance(region, str) or not _REGION.fullmatch(region):
                failure = ReadError("malformed", "dataflow_pipeline_location")
                break
            regions.append(region)

        def region_pages(region):
            url = (f"https://datapipelines.googleapis.com/v1/projects/{quote(project, safe='')}"
                   f"/locations/{quote(region, safe='')}/pipelines")
            for pipelines, list_request in collector.pages(url, scope, key="pipelines",
                                                           params={"filter": "type:BATCH,status:ACTIVE"}):
                projected = []
                for pipeline in pipelines:
                    try:
                        result = project_pipeline(pipeline, scope, number)
                    except ValueError as exc:
                        raise ReadError("malformed", str(exc)) from exc
                    if result is not None:
                        projected.append(result)
                yield projected, list_request
        from .gcp_fanout import fanout_pages
        yield from fanout_pages(collector, regions, region_pages)
        if failure is not None:
            raise failure
