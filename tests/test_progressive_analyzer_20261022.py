"""Focused progressive AI readiness and final reuse tests."""

import json
import copy
import threading
import time
from concurrent.futures import CancelledError
from types import SimpleNamespace

import pytest
from peaso import progressive_analyzer
from peaso.ai import pipeline


class FakeArtifacts:
    def __init__(self):
        self.values = {
            "partial-report": {"bundle_version": 1, "report_json": "report-json"},
            "report-json": {"publication": {"state": "partial", "phase": "collecting",
                                               "sections": {"network": {"status": "running", "data_revision": 1},
                                                            "hardening": {"status": "running", "data_revision": 1},
                                                            "images": {"status": "running", "data_revision": 1}}}},
            "partial-snapshot": {"metadata": {"ai_access_reference": "captured"}},
        }

    def get(self, tenant, reference):
        return self.values[reference]

    def put(self, tenant, ident, kind, value):
        reference = f"{kind}-{len(self.values)}"
        self.values[reference] = value
        return reference


class FakeStore:
    def __init__(self):
        self.lock = threading.Lock()
        self.row = {"status": "collecting", "deadline": time.time() + 10,
                    "partial_report": "partial-report", "partial_snapshot": "partial-snapshot",
                    "data": json.dumps({"ai_enabled": True})}
        self.leases = {}
        self.results = {}

    def job(self, tenant, ident):
        with self.lock:
            return dict(self.row)

    def claim_stage(self, tenant, ident, stage, revision, owner, lease_seconds):
        with self.lock:
            if self.row["status"] != "collecting" or stage in self.results or stage in self.leases:
                return False
            self.leases[stage] = (revision, owner)
            return True

    def heartbeat_stage(self, tenant, ident, stage, revision, owner, lease_seconds):
        with self.lock:
            return self.leases.get(stage) == (revision, owner)

    def finish_stage(self, tenant, ident, stage, revision, owner, reference):
        with self.lock:
            if self.leases.get(stage) != (revision, owner):
                return False
            self.results[stage] = {"data_revision": revision, "result_ref": reference}
            del self.leases[stage]
            return True

    def stage_results(self, tenant, ident):
        with self.lock:
            return dict(self.results)

    def expire_job(self, tenant, ident):
        with self.lock:
            self.row["status"] = "timed_out"


class FakeStageProcess:
    instances = []

    def __init__(self, worker, tenant, ident, stage, revision, job, selectors):
        self.worker, self.tenant, self.ident = worker, tenant, ident
        self.stage, self.revision = stage, revision
        self.job, self.selectors = job, selectors
        self.cancelled = threading.Event()
        self.done = threading.Event()
        self.result_ref = None
        self.process = self
        self.thread = threading.Thread(target=self._run)
        self.instances.append(self)

    def _run(self):
        try:
            report, snapshot, _ = progressive_analyzer._ready(self.job, self.worker.artifacts, self.tenant)
            output = progressive_analyzer.review_scan(report, snapshot, self.selectors,
                stages=(self.stage,), cancel_event=self.cancelled)
            if not self.cancelled.is_set():
                self.result_ref = self.worker.artifacts.put(self.tenant, self.ident, "ai-review",
                    {"stage": self.stage, "data_revision": self.revision, "result": output})
        finally:
            self.done.set()

    def start(self):
        self.thread.start()

    def poll(self):
        return (self.result_ref or False) if self.done.is_set() else progressive_analyzer._PENDING

    def request_stop(self):
        self.cancelled.set()

    def join(self, timeout=None):
        self.thread.join(timeout)

    def is_alive(self):
        return self.thread.is_alive()

    def kill(self):
        self.cancelled.set()

    def close(self):
        self.thread.join(timeout=1)


def test_network_starts_while_images_blocked_and_no_stage_starts_early(monkeypatch, tmp_path):
    store, artifacts = FakeStore(), FakeArtifacts()
    store.row["status"] = "queued"
    network_started, release_network, native_published, final_called = (threading.Event() for _ in range(4))
    calls = []

    def review(report, snapshot, selectors, **kwargs):
        stage = kwargs["stages"][0]
        calls.append(stage)
        if stage == "network":
            network_started.set()
            assert release_network.wait(3)
        return {"status": "completed", "reviews": {stage: []}, "network": {"status": "completed", "findings": []}}

    monkeypatch.setattr(progressive_analyzer, "review_scan", review)
    monkeypatch.setattr(progressive_analyzer, "review_concurrency", lambda: 2)
    monkeypatch.setattr(progressive_analyzer, "_StageProcess", FakeStageProcess)
    worker = SimpleNamespace(role="analyzer", store=store, artifacts=artifacts,
        settings=SimpleNamespace(state_dir=tmp_path, identity_dir=tmp_path, lease_seconds=30),
        stopping=threading.Event())

    def final(tenant, ident, *, stage_poll=None):
        with store.lock:
            store.row["status"] = "analyzing"
        native_published.set()
        while stage_poll is not None and not stage_poll(store.job(tenant, ident)):
            assert not worker.stopping.wait(.01)
        assert store.stage_results(tenant, ident)["network"]["data_revision"] == 1
        final_called.set()
        with store.lock:
            store.row["status"] = "completed"
    worker.run_once = final
    thread = threading.Thread(target=progressive_analyzer.run_progressive,
                              args=(worker, "tenant", "scan"), kwargs={"poll_seconds": .01})
    thread.start()
    try:
        time.sleep(.05)
        assert calls == []
        with store.lock:
            store.row["status"] = "collecting"
        artifacts.values["report-json"]["publication"]["sections"]["network"]["status"] = "complete"
        assert network_started.wait(2)
        assert not final_called.is_set()
        assert artifacts.values["report-json"]["publication"]["sections"]["images"]["status"] == "running"
        assert calls == ["network"]
        with store.lock:
            store.row["status"] = "collected"
        assert native_published.wait(2), "Native publication must not wait for the AI stage"
        assert not final_called.is_set()
        release_network.set()
        assert final_called.wait(2)
    finally:
        release_network.set()
        worker.stopping.set()
        thread.join(timeout=3)
    assert not thread.is_alive()
    assert artifacts.values[store.results["network"]["result_ref"]]["result"]["status"] == "completed"


def test_cancelled_scan_stops_inflight_stage_and_rejects_late_result(monkeypatch, tmp_path):
    store, artifacts = FakeStore(), FakeArtifacts()
    artifacts.values["report-json"]["publication"]["sections"]["network"]["status"] = "complete"
    started = threading.Event()

    def review(report, snapshot, selectors, **kwargs):
        started.set()
        assert kwargs["cancel_event"].wait(2)
        return {"status": "completed", "network": {"status": "completed", "findings": []}}

    monkeypatch.setattr(progressive_analyzer, "review_scan", review)
    monkeypatch.setattr(progressive_analyzer, "review_concurrency", lambda: 2)
    monkeypatch.setattr(progressive_analyzer, "_StageProcess", FakeStageProcess)
    worker = SimpleNamespace(role="analyzer", store=store, artifacts=artifacts,
        settings=SimpleNamespace(state_dir=tmp_path, identity_dir=tmp_path, lease_seconds=30),
        stopping=threading.Event(), run_once=lambda *a: (_ for _ in ()).throw(AssertionError("final run after cancellation")))
    thread = threading.Thread(target=progressive_analyzer.run_progressive,
        args=(worker, "tenant", "scan"), kwargs={"poll_seconds": .01})
    thread.start()
    assert started.wait(2)
    with store.lock:
        store.row["status"] = "cancelled"
    thread.join(timeout=3)
    assert not thread.is_alive()
    assert not store.results
    assert FakeStageProcess.instances[-1].cancelled.is_set()
    assert not FakeStageProcess.instances[-1].is_alive()


def test_remote_invoke_cancellation_runs_hosted_cleanup(monkeypatch):
    cancelled, cleaned = threading.Event(), threading.Event()
    monkeypatch.setattr(pipeline.isolation, "remote", lambda: True)
    monkeypatch.setattr("peaso.ai.fargate.configuration", lambda: {})

    def hosted(stage, root, token, timeout, *, sleep, prepare, **kwargs):
        assert stage == "priorities"
        try:
            sleep(30)
        finally:
            cleaned.set()

    monkeypatch.setattr("peaso.ai.fargate.invoke", hosted)
    # Hardening and Exposure have no hosted model agent; only Network and
    # Priorities may start a task.
    with pytest.raises(ValueError, match="unknown_ai_stage"):
        pipeline.invoke("hardening", {"scan": {}, "resources": []}, [], "token", [], [], 40)
    timer = threading.Timer(.02, cancelled.set)
    timer.start()
    try:
        with pytest.raises(CancelledError):
            pipeline.invoke("priorities", {"scan": {}, "resources": []}, [], "token", [], [], 40,
                            cancel_event=cancelled)
    finally:
        timer.join()
    assert cleaned.is_set()


def test_reused_review_skips_completed_ai_and_priorities_waits_for_reviewers(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "Settings", lambda: SimpleNamespace(state_dir=tmp_path, identity_dir=tmp_path, auth_mode="local"))
    monkeypatch.setattr("peaso.storage.runtime.stores", lambda _: (SimpleNamespace(), None))
    monkeypatch.setattr("peaso.ai.providers.review_disabled", lambda *a: False)
    monkeypatch.setattr("peaso.ai.providers.resolve_access", lambda *a, **kw: ("private-token", "test"))
    monkeypatch.setattr("peaso.ai.providers.credential_value", lambda _: "private-token")
    monkeypatch.setattr(pipeline.isolation, "available", lambda: True)
    monkeypatch.setattr(pipeline.isolation, "remote", lambda: False)
    monkeypatch.setattr(pipeline, "available_memory", lambda: 4 * 1024**3)
    monkeypatch.setattr("peaso.snapshot.resources", lambda _: [])
    network_context = {"report": {"provider": "aws", "graphs": {}}, "inventory": [
        {"id": "r", "provider": "aws", "scope": "123456789012/us-east-1", "type": "security_group"}]}
    monkeypatch.setattr("peaso.ai.network.prepare", lambda *a: network_context)
    monkeypatch.setattr("peaso.ai.network.with_findings", lambda report, findings: report)
    monkeypatch.setattr("peaso.least_privilege.project", lambda *a, **kw: {"items": []})
    monkeypatch.setenv("PEASO_AI_MAX_CONCURRENCY", "1")
    report = {"provider": "aws", "findings": [
        {"id": "h1", "check_id": "h", "category": "hardening", "resource_id": "r", "scope": "123456789012/us-east-1", "status": "FAIL"},
        {"id": "e1", "check_id": "e", "category": "exposure", "resource_id": "r", "scope": "123456789012/us-east-1", "status": "FAIL"}], "graphs": {}}
    calls = []

    def invoke(stage, platform, entries, token, findings, reviews, timeout):
        calls.append(stage)
        assert stage == "priorities"
        assert {row["finding_id"] for row in reviews} == {"h1", "e1"}
        return {"actions": [], "limitations": []}

    monkeypatch.setattr(pipeline, "invoke", invoke)
    # A Hardening-only request starts no model agent: native FAILs are final.
    early = pipeline.review_scan(report, {}, {}, tenant="tenant", artifacts=None, stages=("hardening",))
    assert calls == [] and early["status"] == "skipped", early
    assert early["reason"] == "no_ai_sections_selected"
    network_result = dict(pipeline.validate_network({"explanation": "One security group needs owner review.",
        "findings": [{"title": "Narrow source range", "description": "The group permits a broad source range.",
            "rationale": "The broad range weakens the intended tier boundary.", "resource_id": "r",
            "severity": "medium", "status": "MANUAL", "evidence": {
                "summary": "The group permits a broad source range.", "resource_ids": ["r"],
                "graph_refs": [], "observations": ["The source range is broad."]},
            "remediation": "Confirm client ranges and narrow the rule.",
            "verification": "Read the resulting rule and confirm required clients."}]}, network_context),
        status="completed")
    final = pipeline.review_scan(report, {}, {}, tenant="tenant", artifacts=None,
        reused_stages={"hardening": early, "network": {"status": "completed",
            "network": network_result}})
    # The completed Network result is reused; only Priorities runs, over the
    # native-final Hardening and Exposure reviews.
    assert calls == ["priorities"]
    assert final["status"] == "completed"
    assert final["network"] == network_result
    assert [row["finding_id"] for row in final["reviews"]["hardening"]] == ["h1"]
    assert [row["finding_id"] for row in final["reviews"]["exposure"]] == ["e1"]
    assert final["coverage"]["model_reviewed"] == 0 and final["coverage"]["native_final"] == 2
    native = copy.deepcopy(report)
    def failing(stage, platform, entries, token, findings, reviews, timeout):
        raise RuntimeError("isolated priorities agent failed")
    monkeypatch.setattr(pipeline, "invoke", failing)
    failed = pipeline.review_scan(report, {}, {}, tenant="tenant", artifacts=None,
        reused_stages={"hardening": early, "network": {"status": "completed",
            "network": network_result}})
    assert failed["status"] == "partial"
    assert failed["actions"] == []
    assert "Prioritized recommendations could not be completed." in failed["limitations"]
    assert [row["finding_id"] for row in failed["reviews"]["hardening"]] == ["h1"]
    assert report == native and all(row["status"] == "FAIL" for row in report["findings"])


def _exact_reuse_fixture(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "Settings", lambda: SimpleNamespace(
        state_dir=tmp_path, identity_dir=tmp_path, auth_mode="local"))
    monkeypatch.setattr("peaso.storage.runtime.stores", lambda _: (SimpleNamespace(), None))
    monkeypatch.setattr("peaso.ai.providers.review_disabled", lambda *a: False)
    monkeypatch.setattr("peaso.ai.providers.resolve_access", lambda *a, **kw: ("private-token", "test"))
    monkeypatch.setattr("peaso.ai.providers.credential_value", lambda _: "private-token")
    monkeypatch.setattr(pipeline.isolation, "available", lambda: True)
    monkeypatch.setattr(pipeline.isolation, "remote", lambda: False)
    monkeypatch.setattr(pipeline, "available_memory", lambda: 4 * 1024**3)
    monkeypatch.setattr("peaso.snapshot.resources", lambda snapshot: snapshot.get("resources", []))
    monkeypatch.setattr("peaso.ai.network.prepare", lambda *a: None)
    monkeypatch.setattr("peaso.ai.network.with_findings", lambda report, findings: report)
    monkeypatch.setattr("peaso.least_privilege.project", lambda *a, **kw: {"items": []})
    monkeypatch.setenv("PEASO_AI_MAX_CONCURRENCY", "1")
    calls = []
    def invoke(stage, platform, entries, token, findings, reviews, timeout, **kwargs):
        calls.append((stage, [row["id"] for row in findings], copy.deepcopy(reviews)))
        assert stage == "priorities"
        return {"actions": [], "limitations": []}
    monkeypatch.setattr(pipeline, "invoke", invoke)
    return calls


def _hardening_report(ids, *, stamp="2026-10-22T10:00:00Z"):
    return {"provider": "aws", "snapshot_id": stamp, "created_at": stamp,
            "findings": [{"id": ident, "check_id": ident, "category": "hardening",
                          "status": "FAIL", "resource_id": "r", "scope": "123456789012/us-east-1"}
                         for ident in ids], "graphs": {}}


def test_exact_finding_reuse_reviews_only_six_new_rows(monkeypatch, tmp_path):
    # Hardening rows are native-final: a checkpoint review never feeds a model
    # Hardening agent, and the six new rows need no model review either.
    calls = _exact_reuse_fixture(monkeypatch, tmp_path)
    snapshot = {"resources": [{"id": "r", "scope": "123456789012/us-east-1",
                               "provider": "aws", "data": {"state": "captured"}}]}
    early = pipeline.review_scan(_hardening_report([f"h{i:03}" for i in range(140)]), snapshot, {},
                                 tenant="tenant", artifacts=None, stages=("hardening",))
    assert early["status"] == "skipped" and calls == []
    saved_early = copy.deepcopy(early)
    final_report = _hardening_report([f"h{i:03}" for i in range(146)], stamp="2026-10-22T10:05:00Z")
    final = pipeline.review_scan(final_report, snapshot, {}, tenant="tenant", artifacts=None,
                                 reused_stages={"hardening": early})
    assert [stage for stage, _, _ in calls] == ["priorities"]
    assert len([row for row in final["reviews"]["hardening"] if row["verdict"] == "FAIL"]) == 146
    assert final["coverage"]["native_final"] == 146 and final["coverage"]["model_reviewed"] == 0
    reused_priority_input = calls[0][2]
    calls.clear()
    reference = pipeline.review_scan(final_report, snapshot, {}, tenant="tenant", artifacts=None)
    assert final["reviews"] == reference["reviews"]
    assert final["coverage"] == reference["coverage"]
    assert final["actions"] == reference["actions"]
    assert reused_priority_input == calls[0][2]
    final["reviews"]["hardening"][0]["reason"] = "changed after reuse"
    assert early == saved_early


@pytest.mark.parametrize("change", ["finding", "resource", "time", "provider", "identity", "legacy", "version", "unconcluded", "tampered"])
def test_exact_finding_reuse_falls_back_without_matching_proof(monkeypatch, tmp_path, change):
    # No prior Hardening artifact, however altered, replaces native-final reviews.
    calls = _exact_reuse_fixture(monkeypatch, tmp_path)
    base = _hardening_report(["h1"])
    snapshot = {"resources": [{"id": "r", "scope": "123456789012/us-east-1",
                               "provider": "aws", "data": {"state": "old"}}]}
    prior = copy.deepcopy(pipeline.review_scan(base, snapshot, {}, tenant="tenant", artifacts=None))
    assert prior["status"] == "completed" and len(prior["reviews"]["hardening"]) == 1
    prior["review_fingerprints"] = {"hardening": {"h1": "f" * 64}}
    prior["review_fingerprint_version"] = 2
    report, current_snapshot = copy.deepcopy(base), copy.deepcopy(snapshot)
    if change == "finding":
        report["findings"][0]["evidence"] = {"changed": True}
    elif change == "resource":
        current_snapshot["resources"][0]["data"]["state"] = "new"
    elif change == "time":
        report["findings"][0]["evidence"] = {"capture_time": "2026-10-22T10:01:00Z"}
    elif change == "provider":
        report["provider"] = "gcp"
    elif change == "identity":
        prior["review_fingerprints"]["hardening"]["h1"] = "0" * 64
    elif change == "legacy":
        del prior["review_fingerprints"]
    elif change == "version":
        prior["review_fingerprint_version"] = 0
    elif change == "unconcluded":
        prior["reviews"]["hardening"][0]["verdict"] = "UNKNOWN"
    elif change == "tampered":
        prior["reviews"]["hardening"].append(copy.deepcopy(prior["reviews"]["hardening"][0]))
        prior["reviews"]["hardening"][0]["reason"] = "tampered prior reason"
    calls.clear()
    result = pipeline.review_scan(report, current_snapshot, {}, tenant="tenant", artifacts=None,
                                  reused_stages={"hardening": prior})
    reused_input = [rows for stage, _, rows in calls]
    calls.clear()
    reference = pipeline.review_scan(report, current_snapshot, {}, tenant="tenant", artifacts=None)
    assert result["status"] == reference["status"] == "completed"
    assert result["reviews"] == reference["reviews"]
    assert [(row["finding_id"], row["verdict"]) for row in result["reviews"]["hardening"]] == [("h1", "FAIL")]
    assert reused_input == [rows for stage, _, rows in calls]
    assert "review_fingerprints" not in result


def test_exact_finding_reuse_preserves_cancellation_for_new_rows(monkeypatch, tmp_path):
    calls = _exact_reuse_fixture(monkeypatch, tmp_path)
    report = _hardening_report(("old", "new"))
    prior = pipeline.review_scan(dict(report, findings=report["findings"][:1]), {}, {},
                                 tenant="tenant", artifacts=None)
    calls.clear()
    cancelled = threading.Event()
    cancelled.set()
    def cancelled_invoke(stage, platform, entries, token, findings, reviews, timeout, *, cancel_event=None, **kwargs):
        calls.append(stage)
        assert cancel_event is cancelled and cancel_event.is_set()
        raise CancelledError()
    monkeypatch.setattr(pipeline, "invoke", cancelled_invoke)
    result = pipeline.review_scan(report, {}, {}, tenant="tenant", artifacts=None,
                                  reused_stages={"hardening": prior}, cancel_event=cancelled)
    # The cancelled Priorities agent yields a partial result; native-final
    # Hardening rows stay FAIL for both the reused and the new finding.
    assert result["status"] == "partial"
    assert result["actions"] == []
    assert [(row["finding_id"], row["verdict"]) for row in result["reviews"]["hardening"]] == [
        ("old", "FAIL"), ("new", "FAIL")]
    assert calls == ["priorities"]


def test_exact_review_artifact_requires_complete_authoritative_revision():
    from peaso.worker import _reusable_stages
    class Artifacts:
        def get(self, tenant, reference):
            assert (tenant, reference) == ("tenant", "review-ref")
            return {"stage": "network", "data_revision": 9,
                    "result": {"status": "completed", "network": {"status": "completed"}}}
    stages = {"network": {"data_revision": 9, "result_ref": "review-ref"}}
    section = {"network": {"status": "complete", "data_revision": 9}}
    assert "network" in _reusable_stages(Artifacts(), "tenant", section, stages)
    section["network"]["data_revision"] = 10
    assert _reusable_stages(Artifacts(), "tenant", section, stages) == {}
    section["network"].update(status="running", data_revision=9)
    assert _reusable_stages(Artifacts(), "tenant", section, stages) == {}
    # Hardening has no model stage, so no stored Hardening artifact is reusable.
    hardening = {"hardening": {"data_revision": 9, "result_ref": "review-ref"}}
    assert _reusable_stages(Artifacts(), "tenant",
                            {"hardening": {"status": "complete", "data_revision": 9}}, hardening) == {}


def test_ready_restores_every_native_observation_with_mixed_statuses():
    rows = [
        {"id": "asset-fail", "check_id": "check", "provider": "aws", "status": "FAIL",
         "category": "hardening", "resource_id": "r1", "evidence": {"setting": "unsafe"}},
        {"id": "asset-pass", "check_id": "check", "provider": "aws", "status": "PASS",
         "category": "hardening", "resource_id": "r2", "evidence": {"setting": "safe"}},
    ]
    grouped = {"finding_grouping": "check-v1", "findings": [{"id": "check-card",
        "check_id": "check", "provider": "aws", "status": "FAIL", "grouped": True,
        "member_count": 2, "status_counts": {"FAIL": 1, "PASS": 1},
        "observations": copy.deepcopy(rows)}],
        "stats": {"finding_count": 1, "observation_count": 2},
        "publication": {"state": "partial", "phase": "collecting", "sections": {
            "hardening": {"status": "complete", "data_revision": 9}}}}
    artifacts = FakeArtifacts()
    artifacts.values["report-json"] = grouped
    restored, _, _ = progressive_analyzer._ready({"partial_report": "partial-report",
        "partial_snapshot": "partial-snapshot"}, artifacts, "tenant")
    assert restored["findings"] == rows
    assert [row["id"] for row in pipeline.inputs(restored)[0]] == ["asset-fail"]
    restored["findings"][0]["evidence"]["setting"] = "local mutation"
    assert grouped["findings"][0]["observations"] == rows
    for corruption in (lambda g: g["observations"].pop(),
                       lambda g: g["observations"][1].update(id="asset-fail"),
                       lambda g: g["observations"][1].update(status="FAIL")):
        damaged = copy.deepcopy(grouped)
        corruption(damaged["findings"][0])
        artifacts.values["report-json"] = damaged
        assert progressive_analyzer._ready({"partial_report": "partial-report",
            "partial_snapshot": "partial-snapshot"}, artifacts, "tenant") is None


def test_ready_restores_single_asset_card_without_aggregate_fields():
    member = {"id": "internet-asset", "provider": "aws",
              "check_id": "analysis.internet_exposure", "status": "FAIL",
              "category": "exposure", "resource_id": "asset"}
    report = {"finding_grouping": "check-v1", "findings": [
        dict(member, observations=[copy.deepcopy(member)])],
        "stats": {"finding_count": 1, "observation_count": 1},
        "publication": {"state": "partial", "phase": "collecting", "sections": {}}}
    artifacts = FakeArtifacts()
    artifacts.values["report-json"] = report
    restored, _, _ = progressive_analyzer._ready({"partial_report": "partial-report",
        "partial_snapshot": "partial-snapshot"}, artifacts, "tenant")
    assert restored["findings"] == [member]


def test_access_reference_reuses_only_exact_bound_entries(monkeypatch, tmp_path):
    from peaso.worker import _cached_ai_access_reference
    encrypted = []
    class Cipher:
        def __init__(self, path):
            assert path == tmp_path
        def encrypt(self, value):
            encrypted.append(copy.deepcopy(value))
            return "sealed-private-value"
    monkeypatch.setattr("peaso.ai.crypto.AICipher", Cipher)
    class Artifacts:
        def __init__(self):
            self.rows = []
        def put(self, tenant, ident, kind, value):
            assert (tenant, kind) == ("tenant", "ai-access")
            self.rows.append(copy.deepcopy(value))
            return f"ref-{len(self.rows)}"
    artifacts, cache = Artifacts(), {}
    bound = [{"provider": "aws", "account_id": "123456789012", "target_scopes": ["123456789012/us-east-1"],
              "token": "private-token"}]
    first = _cached_ai_access_reference(artifacts, "tenant", "scan", bound, cache, tmp_path)
    assert _cached_ai_access_reference(artifacts, "tenant", "scan", copy.deepcopy(bound), cache, tmp_path) == first
    assert len(artifacts.rows) == len(encrypted) == 1
    assert "private-token" not in json.dumps(artifacts.rows)
    changed = copy.deepcopy(bound)
    changed[0]["target_scopes"] = ["123456789012/us-west-2"]
    assert _cached_ai_access_reference(artifacts, "tenant", "scan", changed, cache, tmp_path) != first
    changed[0]["token"] = "different-private-token"
    assert _cached_ai_access_reference(artifacts, "tenant", "scan", changed, cache, tmp_path) == "ref-3"
    assert _cached_ai_access_reference(artifacts, "tenant", "other-scan", bound, cache, tmp_path) == "ref-4"


def test_partial_prior_reuses_conclusive_observations_only(monkeypatch, tmp_path):
    calls = _exact_reuse_fixture(monkeypatch, tmp_path)
    prior = pipeline.review_scan(_hardening_report(("old-a", "old-b"), stamp="checkpoint"), {}, {},
                                 tenant="tenant", artifacts=None)
    prior["status"] = "partial"
    prior["reviews"]["hardening"][1].update(verdict="UNKNOWN", reason="The prior reviewer timed out.")
    calls.clear()
    current = _hardening_report(("old-a", "old-b", "new"), stamp="final")
    result = pipeline.review_scan(current, {}, {}, tenant="tenant", artifacts=None,
                                  reused_stages={"hardening": prior})
    assert [stage for stage, _, _ in calls] == ["priorities"]
    assert [(row["finding_id"], row["verdict"]) for row in result["reviews"]["hardening"]] == [
        ("old-a", "FAIL"), ("old-b", "FAIL"), ("new", "FAIL")]
    assert result["coverage"] == {"hardening": 3, "exposure": 0, "reviewed": 3,
                                   "native_final": 3, "model_reviewed": 0, "total": 3}
    reused_priority_input = calls[0][2]
    calls.clear()
    reference = pipeline.review_scan(current, {}, {}, tenant="tenant", artifacts=None)
    assert result["reviews"] == reference["reviews"]
    assert result["actions"] == reference["actions"]
    assert result["coverage"] == reference["coverage"]
    assert reused_priority_input == calls[0][2]


def test_grouped_checkpoint_and_raw_final_share_observation_fingerprint(monkeypatch, tmp_path):
    calls = _exact_reuse_fixture(monkeypatch, tmp_path)
    row = {"id": "asset-fail", "check_id": "check", "provider": "aws", "status": "FAIL",
           "category": "hardening", "resource_id": "r", "scope": "123456789012/us-east-1",
           "evidence": {"observed": "unsafe"}}
    grouped = {"provider": "aws", "snapshot_id": "checkpoint", "created_at": "checkpoint-time",
        "finding_grouping": "check-v1", "findings": [{"id": "group-id", "check_id": "check",
            "provider": "aws", "status": "FAIL", "grouped": True, "member_count": 1,
            "status_counts": {"FAIL": 1}, "observations": [copy.deepcopy(row)]}],
        "stats": {"finding_count": 1, "observation_count": 1}, "graphs": {},
        "publication": {"state": "partial", "phase": "collecting", "sections": {
            "hardening": {"status": "complete", "data_revision": 9}}}}
    artifacts = FakeArtifacts()
    artifacts.values["report-json"] = grouped
    progressive, _, _ = progressive_analyzer._ready({"partial_report": "partial-report",
        "partial_snapshot": "partial-snapshot"}, artifacts, "tenant")
    final_raw = dict(progressive, finding_grouping=None, findings=[copy.deepcopy(row)],
                     snapshot_id="final", created_at="final-time")
    identity = {"ai_user": "tenant", "auth_source": "test", "access_reference": None}
    def fingerprints(report):
        return pipeline.review_fingerprints(report, {}, pipeline.inputs(report)[0],
                                            identity=identity, entries=[])
    assert fingerprints(progressive) == fingerprints(final_raw)
    assert list(fingerprints(final_raw)) == ["asset-fail"]
    early = pipeline.review_scan(progressive, {}, {}, tenant="tenant", artifacts=None)
    early_input = calls[0][2]
    calls.clear()
    final = pipeline.review_scan(final_raw, {}, {}, tenant="tenant", artifacts=None,
                                 reused_stages={"hardening": early})
    assert final["reviews"]["hardening"] == early["reviews"]["hardening"]
    assert [stage for stage, _, _ in calls] == ["priorities"] and calls[0][2] == early_input


def test_fingerprint_changes_with_identity_reference_and_access_epoch():
    finding = {"id": "f", "provider": "aws", "category": "hardening", "status": "FAIL",
               "scope": "123456789012/us-east-1", "resource_id": "r"}
    report = {"provider": "aws", "created_at": "checkpoint-view"}
    identity = {"ai_user": "owner", "auth_source": "personal", "access_reference": "sealed-a"}
    entries = [{"provider": "aws", "account_id": "123456789012", "captured_at": 100,
                "expires_at": 200, "target_scopes": ["123456789012/us-east-1"]}]
    def fingerprint(boundary=identity, access=entries):
        return pipeline.review_fingerprints(report, {}, [finding], identity=boundary,
                                            entries=access)["f"]
    original = fingerprint()
    assert fingerprint(dict(identity, access_reference="sealed-b")) != original
    assert fingerprint(dict(identity, ai_user="other-owner")) != original
    assert fingerprint(identity, [dict(entries[0], captured_at=101)]) != original
    assert fingerprint(identity, [dict(entries[0], expires_at=201)]) != original
