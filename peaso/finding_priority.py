"""Reviewed finding priorities, separate from immutable source benchmark ratings."""
from functools import lru_cache
import json
from pathlib import Path

VERSION = "finding-priority-20261019-v1"


@lru_cache(maxsize=1)
def reviews():
    from .checks import (azure_finding_clarity_reviewed, aws_finding_clarity_reviewed,
                         k8s_finding_clarity_reviewed, k8s_workload_clarity_reviewed,
                         k8s_gc_threshold_source_correction, gcp_firewall_clarity_reviewed,
                         gcp_scalar_clarity_reviewed, gcp_remaining_clarity_reviewed, aws_database_clarity_reviewed, azure_bulk_clarity_reviewed, aws_remaining_clarity_reviewed, aws_final_clarity_reviewed, aws_bulk_clarity_reviewed, aws_compute_storage_clarity_reviewed)
    output = {}
    for module in (azure_finding_clarity_reviewed, aws_finding_clarity_reviewed):
        for cid, row in module.SEVERITY_REVIEW.items():
            output[cid] = dict(row)
    for module in (k8s_finding_clarity_reviewed, k8s_workload_clarity_reviewed,
                   k8s_gc_threshold_source_correction, gcp_firewall_clarity_reviewed,
                   gcp_scalar_clarity_reviewed, gcp_remaining_clarity_reviewed, aws_database_clarity_reviewed, azure_bulk_clarity_reviewed, aws_remaining_clarity_reviewed, aws_final_clarity_reviewed, aws_bulk_clarity_reviewed, aws_compute_storage_clarity_reviewed):
        for cid, (source, target) in module.REVIEWED_RISKS.items():
            if cid in output:
                raise ValueError("Duplicate reviewed priority: " + cid)
            output[cid] = {"current": source, "recommended": target,
                           "reason": "Priority of the specific captured configuration; no live compromise is inferred."}
    output["gcp.ports.sql_private_ip_assignments"] = {
        "current": "medium", "recommended": "medium",
        "reason": "Incoming public SQL IP declaration; outbound OUTGOING addresses are not public incoming endpoints, and reachability is not established."}
    # Source-reviewed successor checks retain their registered priorities.
    # The review records exact callback module, kind, and title so future
    # registration changes require a new decision rather than silent reuse.
    source_reviews = json.loads((Path(__file__).parent / "checks/reviewed_release_priorities_20261020.json").read_text())
    for cid, row in source_reviews.items():
        if cid in output:
            raise ValueError("Duplicate reviewed priority: " + cid)
        output[cid] = {key: row[key] for key in ("current", "recommended", "reason")}
    allowed = {"critical", "high", "medium", "low", "info"}
    for cid, row in output.items():
        if row["current"] not in allowed or row["recommended"] not in allowed or not row.get("reason"):
            raise ValueError("Invalid reviewed priority: " + cid)
    return output


def effective_priority(check_id, source_severity):
    row = reviews().get(check_id)
    if row is None:
        return source_severity
    return row["recommended"]


def review_metadata(check_id, source_severity):
    priority = effective_priority(check_id, source_severity)
    if priority == source_severity:
        return None
    return {"version": VERSION, "source_severity": source_severity,
            "severity": priority, "reason": reviews()[check_id]["reason"]}


def source_priority(row):
    """Recover a signed rating only from an exact current reviewed public row.

    Legacy rows keep their own rating. Claimed review metadata is never an
    authority by itself: both its full value and the public rating must agree
    with the locally reviewed source-to-priority decision.
    """
    if not isinstance(row, dict):
        raise ValueError("Invalid priority metadata row")
    severity = row.get("severity")
    if "severity_review" not in row:
        return severity
    review = row["severity_review"]
    if not isinstance(review, dict):
        raise ValueError("Invalid reviewed priority provenance")
    check_id = row.get("id")
    if not isinstance(check_id, str) or check_id not in reviews():
        raise ValueError("Unknown reviewed priority provenance")
    source = reviews()[check_id]["current"]
    expected = review_metadata(check_id, source)
    if expected is None or review != expected or severity != expected["severity"]:
        raise ValueError("Reviewed priority provenance differs from trusted review")
    return source
