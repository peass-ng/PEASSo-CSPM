"""ECR latest-image scan facts are digest-scoped and never imply a clean scan."""
from __future__ import annotations

import copy
from datetime import datetime, timezone

import pytest

from peaso.checks import evaluate_check
from peaso.checks import claude2_aws_b  # noqa: F401 - register native checks
from peaso.collectors.aws import ReadResult
from peaso.collectors.aws_facts_data_identity import _ecr_latest_scan, _ecr_repository
from peaso.engine import plan_collection


CHECK = "aws.c2b.ecr.latest_image_no_medium_plus_findings"
DIGEST_OLD = "sha256:" + "a" * 64
DIGEST_NEW = "sha256:" + "b" * 64
MEDIA = "application/vnd.docker.container.image.v1+json"


def image(digest, pushed, **extra):
    return {"imageDigest": digest, "imagePushedAt": pushed, "imageTags": ["latest"], "artifactMediaType": MEDIA, **extra}


def repo(*images):
    return {"repositoryName": "app", "registryId": "111111111111", "imageScanningConfiguration": {"scanOnPush": True},
            "Images": {"collection_status": "collected", "items": list(images)}}


def fact(digest=DIGEST_NEW, status="COMPLETE", counts=None, completed="2026-10-01T00:00:00+00:00", **extra):
    return {"collection_status": "collected", "source_api": "ecr:DescribeImageScanFindings", "imageDigest": digest,
            "pages": 1, "imageScanStatus": {"status": status},
            "imageScanFindingsSummary": {"findingSeverityCounts": {} if counts is None else counts,
                                         "imageScanCompletedAt": completed}, **extra}


def assess(scan, *, status=None, counts=None):
    latest = image(DIGEST_NEW, "2026-10-01T00:00:00+00:00")
    if scan is not None:
        latest["ScanFindings"] = scan
    if status is not None:
        latest["imageScanStatus"] = {"status": status}
    if counts is not None:
        latest["imageScanFindingsSummary"] = {"findingSeverityCounts": counts}
    return evaluate_check(CHECK, repo(image(DIGEST_OLD, "2026-09-01T00:00:00+00:00"), latest), {})


def test_complete_new_basic_requires_observed_counts_and_scan_completion():
    state, evidence = assess(fact(counts={"LOW": 2}))
    assert state == "PASS"
    assert evidence["image_digest"] == DIGEST_NEW
    assert evidence["source_api"] == "ecr:DescribeImageScanFindings"
    assert evidence["scan_completed_at"] == "2026-10-01T00:00:00+00:00"
    for severity in ("MEDIUM", "HIGH", "CRITICAL"):
        assert assess(fact(counts={severity: 1}))[0] == "FAIL"
    assert assess(fact(counts={}))[0] == "PASS"
    for malformed in (fact(counts={"HIGH": True}), fact(counts={"HIGH": -1}), fact(counts={"HIGH": "0"}),
                      fact(completed=None), fact(completed="not-a-time"), fact(completed=float("nan")),
                      fact(pages=0), fact(digest=DIGEST_OLD)):
        assert assess(malformed)[0] == "UNKNOWN"
    absent_counts = fact()
    del absent_counts["imageScanFindingsSummary"]["findingSeverityCounts"]
    assert assess(absent_counts)[0] == "UNKNOWN"


def test_pending_failed_denied_and_missing_never_pass_from_empty_counts():
    assert assess(fact(status="FAILED"))[0] == "FAIL"
    for state in ("PENDING", "IN_PROGRESS", "UNSUPPORTED_IMAGE", "ACTIVE", "FINDINGS_UNAVAILABLE", "SCAN_ELIGIBILITY_EXPIRED"):
        assert assess(fact(status=state))[0] == "UNKNOWN"
    assert assess({"collection_status": "denied", "imageDigest": DIGEST_NEW})[0] == "UNKNOWN"
    assert assess({"collection_status": "partial", "imageDigest": DIGEST_NEW})[0] == "UNKNOWN"
    assert assess(None)[0] == "UNKNOWN"
    # Historical snapshots remain valid when DescribeImages did provide facts.
    assert assess(None, status="COMPLETE", counts={"LOW": 3})[0] == "PASS"
    assert assess(None, status="COMPLETE", counts={"MEDIUM": 1})[0] == "FAIL"
    assert assess(None, status="COMPLETE")[0] == "UNKNOWN"


class FakeRequests:
    max_pages = None
    ecr_latest_scan_requested = True

    def __init__(self, images, replies):
        self.images = images
        self.replies = list(replies)
        self.calls = []

    def pages(self, session, service, region, operation, expression, **kwargs):
        self.calls.append((operation, copy.deepcopy(kwargs)))
        assert (service, region, operation, expression) == ("ecr", "us-east-1", "describe_images", "imageDetails")
        return ReadResult(copy.deepcopy(self.images), "collected")

    def call(self, session, service, region, operation, **kwargs):
        self.calls.append((operation, copy.deepcopy(kwargs)))
        assert (service, region, operation) == ("ecr", "us-east-1", "describe_image_scan_findings")
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return copy.deepcopy(reply)


def response(digest=DIGEST_NEW, *, status="COMPLETE", counts=None, token=None):
    return {"imageId": {"imageDigest": digest}, "repositoryName": "app", "registryId": "111111111111",
            "imageScanStatus": {"status": status},
            "imageScanFindings": {"findingSeverityCounts": {} if counts is None else counts,
                                  "imageScanCompletedAt": "2026-10-01T00:00:00+00:00"},
            **({"nextToken": token} if token is not None else {})}


def hydrate(requests):
    return _ecr_repository(requests, object(), "us-east-1", [
        {"repositoryName": "app", "registryId": "111111111111", "imageScanningConfiguration": {"scanOnPush": True}}
    ])[0]


def test_collector_reads_only_latest_digest_and_exhausts_pages():
    old = image(DIGEST_OLD, "2026-09-01T00:00:00+00:00")
    new = image(DIGEST_NEW, "2026-10-01T00:00:00+00:00")
    requests = FakeRequests([new, old], [response(token="next"), response()])
    collected = hydrate(requests)
    assert [operation for operation, _ in requests.calls] == ["describe_images", "describe_image_scan_findings", "describe_image_scan_findings"]
    assert all(args["imageId"] == {"imageDigest": DIGEST_NEW} and args["registryId"] == "111111111111"
               for _, args in requests.calls[1:])
    assert requests.calls[-1][1]["nextToken"] == "next"
    assert collected["Images"]["items"][0]["ScanFindings"]["pages"] == 2
    assert "ScanFindings" not in collected["Images"]["items"][1]
    assert evaluate_check(CHECK, collected, {})[0] == "PASS"


def test_equal_push_time_uses_same_last_image_in_collector_and_predicate():
    tied = "2026-10-01T00:00:00+00:00"
    for rows, expected_digest in (([image(DIGEST_OLD, tied), image(DIGEST_NEW, tied)], DIGEST_NEW),
                                  ([image(DIGEST_NEW, tied), image(DIGEST_OLD, tied)], DIGEST_OLD)):
        requests = FakeRequests(rows, [response(expected_digest)])
        collected = hydrate(requests)
        assert requests.calls[1][1]["imageId"] == {"imageDigest": expected_digest}
        assert evaluate_check(CHECK, collected, {})[0] == "PASS"


def test_missing_media_type_is_unknown_not_empty_inventory():
    unclassified = image(DIGEST_NEW, "2026-10-01T00:00:00+00:00")
    del unclassified["artifactMediaType"]
    assert assess(fact())[0] == "PASS"
    assert evaluate_check(CHECK, repo(unclassified), {})[0] == "UNKNOWN"
    requests = FakeRequests([unclassified], [])
    collected = hydrate(requests)
    assert [operation for operation, _ in requests.calls] == ["describe_images"]
    assert evaluate_check(CHECK, collected, {})[0] == "UNKNOWN"


def test_collector_denial_mismatch_and_page_limit_keep_unknown():
    images = [image(DIGEST_NEW, "2026-10-01T00:00:00+00:00")]
    from peaso.collectors.aws import ReadFailure
    denied = hydrate(FakeRequests(images, [ReadFailure("denied", "AccessDeniedException")]))
    assert evaluate_check(CHECK, denied, {})[0] == "UNKNOWN"
    mismatch = hydrate(FakeRequests(images, [response(DIGEST_OLD)]))
    assert evaluate_check(CHECK, mismatch, {})[0] == "UNKNOWN"
    limited = FakeRequests(images, [response(token="next")])
    limited.max_pages = 1
    assert evaluate_check(CHECK, hydrate(limited), {})[0] == "UNKNOWN"
    unrelated = FakeRequests(images, [])
    unrelated.ecr_latest_scan_requested = False
    hydrate(unrelated)
    assert [call[0] for call in unrelated.calls] == ["describe_images"]


def test_selected_check_planner_retains_real_inventory_dependencies():
    request = {"connector": {"provider": "aws"}, "categories": ["hardening"], "checks": [CHECK]}
    assert "ecr_repository" in plan_collection(request)
    assert all(not kind.startswith("_fact:") for kind in plan_collection(request))
    other = {**request, "categories": ["exposure"], "checks": ["aws.c2b.ecr.repository_not_public"]}
    assert "ecr_repository" in plan_collection(other)


def test_registered_read_action_uses_shared_single_flight_cache():
    boto3 = pytest.importorskip("boto3")
    from botocore.stub import Stubber
    from peaso.collectors.aws import Requests

    session = boto3.Session(aws_access_key_id="inert", aws_secret_access_key="inert", region_name="us-east-1")
    client = session.client("ecr", region_name="us-east-1")
    with Stubber(client) as stub:
        stub.add_response("describe_image_scan_findings", {
            "imageId": {"imageDigest": DIGEST_NEW}, "repositoryName": "app", "registryId": "111111111111",
            "imageScanStatus": {"status": "COMPLETE"}, "imageScanFindings": {
                "findingSeverityCounts": {"LOW": 1}, "imageScanCompletedAt": datetime(2026, 10, 1, tzinfo=timezone.utc)},
        }, {"repositoryName": "app", "registryId": "111111111111", "imageId": {"imageDigest": DIGEST_NEW}, "maxResults": 1000})
        requests = Requests({})
        requests.client = lambda context, service, region: client
        arguments = {"repositoryName": "app", "registryId": "111111111111"}
        first = _ecr_latest_scan(requests, session, "us-east-1", arguments, DIGEST_NEW)
        second = _ecr_latest_scan(requests, session, "us-east-1", arguments, DIGEST_NEW)
        assert first == second and first["collection_status"] == "collected"
        assert requests.calls == 1 and requests.cache_hits >= 1


def test_engine_selected_fact_signal_is_private_and_check_scoped(monkeypatch):
    import peaso.engine as engine
    import peaso.collectors as collectors
    seen = []

    def capture(connector, requirements):
        seen.append((connector["options"]["_ecr_latest_scan_requested"], requirements))
        return {"provider": "aws", "scopes": [], "collections": [], "metadata": {}}

    monkeypatch.setattr(collectors, "collect_live", capture)
    def validate(snapshot, *, metadata_entry=None):
        # The engine records its collection plan through validate's single-pass metadata entry.
        assert metadata_entry is not None and metadata_entry[0] == "collection_plan"
        return {**snapshot, "metadata": {**snapshot["metadata"], metadata_entry[0]: metadata_entry[1]}}

    monkeypatch.setattr(engine, "validate", validate)
    monkeypatch.setattr(engine, "seal", lambda snapshot: snapshot)
    engine.collect_snapshot({"connector": {"provider": "aws"}, "categories": ["hardening"], "checks": [CHECK]})
    assert seen[-1][0] is True and "ecr_repository" in seen[-1][1]
    engine.collect_snapshot({"connector": {"provider": "aws", "options": {"_ecr_latest_scan_requested": True}}, "categories": ["exposure"],
                             "checks": ["aws.c2b.ecr.repository_not_public"]})
    assert seen[-1][0] is False and "ecr_repository" in seen[-1][1]
    engine.collect_snapshot({"connector": {"provider": "aws"}})
    assert seen[-1][0] is True and "ecr_repository" in seen[-1][1]
    from peaso.collectors import aws
    with pytest.raises(ValueError, match="selection must be boolean"):
        aws.collect({"provider": "aws", "options": {"_ecr_latest_scan_requested": "yes"}}, [])
