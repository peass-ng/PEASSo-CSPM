"""Analyzer-side watcher for independently ready scan review sections.

The collector only publishes public snapshot/report artifacts. This module is
run under the analyzer role, where AI authentication and isolated invocation
are available. Stage artifacts are stored separately from collector manifests.
"""

import copy
import json
import logging
import multiprocessing
import signal
import time
import uuid
from pathlib import Path

from peaso.ai.pipeline import review_concurrency, review_scan
from peaso.storage import FileArtifacts, S3Artifacts


LOGGER = logging.getLogger(__name__)
STAGES = ("network", "hardening", "exposure")
TERMINAL = {"completed", "failed", "cancelled", "timed_out", "queue_exhausted"}
_PENDING = object()


def _ready(job, artifacts, tenant):
    """Return one consistent public checkpoint and its complete sections."""
    report_ref, snapshot_ref = job.get("partial_report"), job.get("partial_snapshot")
    if not report_ref or not snapshot_ref:
        return None
    report = artifacts.get(tenant, report_ref)
    if isinstance(report, dict) and report.get("bundle_version") == 1:
        report_json = report.get("report_json")
        if not isinstance(report_json, str):
            return None
        report = artifacts.get(tenant, report_json)
    if not isinstance(report, dict):
        return None
    publication = report.get("publication", {})
    if publication.get("state") != "partial" or publication.get("phase") != "collecting":
        return None
    sections = publication.get("sections", {})
    if not isinstance(sections, dict):
        return None
    if report.get("finding_grouping") == "check-v1":
        # The download has check cards, while final review receives native
        # per-asset findings. Each card contains its lossless observations.
        groups = report.get("findings")
        stats = report.get("stats")
        if (not isinstance(groups, list) or not isinstance(stats, dict)
                or stats.get("finding_count") != len(groups)):
            return None
        observations, seen = [], set()
        for group in groups:
            if not isinstance(group, dict):
                return None
            members = group.get("observations")
            if not isinstance(members, list) or not members or not isinstance(members[0], dict):
                return None
            grouped = group.get("grouped") is True
            if grouped:
                if group.get("member_count") != len(members):
                    return None
            elif (not (group.get("secret_fingerprint") or
                       group.get("check_id") == "analysis.internet_exposure")
                  or group.get("id") != members[0].get("id")
                  or group.get("status") != members[0].get("status")):
                return None
            counts = {}
            for member in members:
                if (not isinstance(member, dict) or not isinstance(member.get("id"), str)
                        or not member["id"] or member["id"] in seen
                        or member.get("provider") != group.get("provider")
                        or member.get("check_id") != group.get("check_id")
                        or "observations" in member or "_detail_reference" in member):
                    return None
                seen.add(member["id"])
                status = member.get("status")
                counts[status] = counts.get(status, 0) + 1
                observations.append(copy.deepcopy(member))
            if grouped and group.get("status_counts") != counts:
                return None
        if stats.get("observation_count") != len(observations):
            return None
        report = dict(report, findings=observations)
    snapshot = artifacts.get(tenant, snapshot_ref)
    return report, snapshot, sections


def _ready_sections(job, artifacts, tenant):
    """Read readiness only; stage children independently validate full artifacts.

    Published bundles carry the same publication metadata in their summary.
    Legacy bundles without it fall back to their report JSON, without fetching
    the native snapshot in the watcher process.
    """
    report_ref, snapshot_ref = job.get("partial_report"), job.get("partial_snapshot")
    if not report_ref or not snapshot_ref:
        return None
    report = artifacts.get(tenant, report_ref)
    if isinstance(report, dict) and report.get("bundle_version") == 1:
        report_json = report.get("report_json")
        if not isinstance(report_json, str):
            return None
        summary = report.get("summary")
        if isinstance(summary, dict) and isinstance(summary.get("publication"), dict):
            report = summary
        else:
            report = artifacts.get(tenant, report_json)
    if not isinstance(report, dict):
        return None
    publication = report.get("publication", {})
    if (not isinstance(publication, dict) or publication.get("state") != "partial"
            or publication.get("phase") != "collecting"):
        return None
    sections = publication.get("sections")
    return sections if isinstance(sections, dict) else None


def _artifact_config(artifacts):
    if isinstance(artifacts, FileArtifacts):
        return {"mode": "file", "root": str(artifacts.root)}
    if isinstance(artifacts, S3Artifacts):
        return {"mode": "s3", "bucket": artifacts.bucket, "kms_key": artifacts.kms_key}
    raise TypeError("Progressive analyzer needs a durable artifact store")


def _stage_child(config, tenant, ident, stage, revision, report_ref, snapshot_ref,
                 selectors, deadline, context, cancelled, connection):
    """Run one stage in a stoppable analyzer child; send only the artifact ref."""
    signal.signal(signal.SIGTERM, lambda *_: cancelled.set())
    signal.signal(signal.SIGINT, lambda *_: cancelled.set())
    try:
        artifacts = (FileArtifacts(Path(config["root"]))
                     if config["mode"] == "file" else
                     S3Artifacts(config["bucket"], kms_key=config.get("kms_key")))
        checkpoint = _ready({"partial_report": report_ref, "partial_snapshot": snapshot_ref},
                            artifacts, tenant)
        if cancelled.is_set() or checkpoint is None or time.time() >= deadline:
            return
        report, snapshot, sections = checkpoint
        section = sections.get(stage, {})
        if section.get("status") != "complete" or section.get("data_revision") != revision:
            return
        output = review_scan(report, snapshot, selectors, tenant=tenant, artifacts=artifacts,
                             deadline=deadline, context=context, stages=(stage,),
                             cancel_event=cancelled)
        if cancelled.is_set() or time.time() >= deadline:
            return
        # Even unavailable stage responses are useful to the public overlay;
        # final analysis only reuses completed stages and can retry failures.
        reference = artifacts.put(tenant, ident, "ai-review", {
            "stage": stage, "data_revision": revision, "result": output})
        connection.send(reference)
    except BaseException:
        LOGGER.warning("Progressive AI stage %s could not finish", stage, exc_info=False)
    finally:
        connection.close()


class _StageProcess:
    """Own one review process and a cancellation signal for its isolated invoke."""

    def __init__(self, worker, tenant, ident, stage, revision, job, selectors):
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe(duplex=False)
        self.pipe = parent
        self.child_pipe = child
        self.cancelled = context.Event()
        self.process = context.Process(target=_stage_child, args=(
            _artifact_config(worker.artifacts), tenant, ident, stage, revision,
            job["partial_report"], job["partial_snapshot"], selectors, job["deadline"],
            {"state_dir": str(worker.settings.state_dir),
             "identity_dir": str(worker.settings.identity_dir)}, self.cancelled, child), daemon=False)

    def start(self):
        try:
            self.process.start()
        except BaseException:
            self.pipe.close()
            raise
        finally:
            self.child_pipe.close()

    def poll(self):
        if self.pipe.poll():
            try:
                return self.pipe.recv()
            except EOFError:
                return False
        return _PENDING if self.process.is_alive() else False

    def request_stop(self):
        self.cancelled.set()
        if self.process.is_alive():
            try:
                self.process.terminate()
            except ProcessLookupError:
                pass

    def close(self):
        self.process.join(timeout=1)
        self.pipe.close()


def _stop_active(active, grace_seconds=35):
    """Ask all children to run local/Fargate cleanup, then bound shutdown."""
    for _, task in active.values():
        task.request_stop()
    end = time.monotonic() + grace_seconds
    for _, task in active.values():
        task.process.join(timeout=max(0, end - time.monotonic()))
        if task.process.is_alive():
            try:
                task.process.kill()
            except ProcessLookupError:
                pass
            task.process.join(timeout=2)
        task.close()
    active.clear()


def run_progressive(worker, tenant, ident, *, poll_seconds=0.25):
    """Watch collector checkpoints, then run the normal final analyzer.

    Stage claim/result rows fence duplicate launches across analyzer restarts.
    The watcher never receives connector secrets or starts collector logic.
    """
    if worker.role != "analyzer":
        raise ValueError("Progressive reviews require analyzer role")
    if not tenant or not ident:
        raise ValueError("Progressive reviews require tenant and scan ID")
    active = {}
    seen = set()
    owner = uuid.uuid4().hex
    lease_seconds = max(30, int(getattr(worker.settings, "lease_seconds", 30)))
    next_heartbeat = 0.0
    checkpoint_key = None
    checkpoint_sections = None
    try:
        max_workers = max(1, min(2, review_concurrency()))
    except (ValueError, OSError):
        max_workers = 1
    def poll_active(job):
        nonlocal next_heartbeat
        for stage, (revision, task) in tuple(active.items()):
            result_ref = task.poll()
            if result_ref is _PENDING:
                continue
            task.close()
            del active[stage]
            if isinstance(result_ref, str) and job["status"] in {"collecting", "collected", "analyzing"}:
                worker.store.finish_stage(tenant, ident, stage, revision, owner, result_ref)
        if active and time.time() >= next_heartbeat:
            lost = {}
            for stage, (revision, task) in active.items():
                if not worker.store.heartbeat_stage(tenant, ident, stage, revision,
                                                    owner, lease_seconds):
                    LOGGER.warning("Progressive AI stage lease lost for %s", stage)
                    lost[stage] = (revision, task)
            if lost:
                lost_names = tuple(lost)
                _stop_active(lost)
                for stage in lost_names:
                    active.pop(stage, None)
            next_heartbeat = time.time() + lease_seconds / 3
        return not active

    prewarm = getattr(worker, "prewarm", None)
    if callable(prewarm):
        # Final evaluation's one-time engine import and source proof overlaps
        # collection on this otherwise idle analyzer instead of following it.
        try:
            provider = json.loads(worker.store.job(tenant, ident)["connector"])["data"].get("provider")
        except Exception:  # noqa: BLE001 - an unknown provider only skips the warm evaluation
            provider = None
        prewarm(provider)
    try:
        while not worker.stopping.is_set():
            job = worker.store.job(tenant, ident)
            if job["status"] in TERMINAL:
                break
            if time.time() >= job["deadline"]:
                worker.store.expire_job(tenant, ident)
                break
            poll_active(job)
            if job["status"] == "collected":
                if active:
                    # Publish final native data immediately. The worker keeps
                    # polling these stages while its child publishes, then
                    # supplies their durable results before final AI review.
                    worker.run_once(tenant, ident, stage_poll=poll_active)
                else:
                    worker.run_once(tenant, ident)
                break
            if job["status"] == "queued":
                worker.stopping.wait(poll_seconds)
                continue
            if job["status"] != "collecting":
                break
            selectors = json.loads(job["data"])
            if selectors.get("ai_enabled", True):
                # Artifact references are immutable and paired by the durable
                # publication transaction. Keep only readiness metadata here;
                # heartbeat/result/claim handling still runs on every poll.
                key = (job.get("partial_report"), job.get("partial_snapshot"))
                if key != checkpoint_key:
                    checkpoint_sections = _ready_sections(job, worker.artifacts, tenant)
                    checkpoint_key = key
                if checkpoint_sections is not None:
                    eligible = []
                    for stage in STAGES:
                        # A higher revision can supersede a live durable claim.
                        # Keep the running child's handle until it settles so
                        # every child remains bounded, heartbeated and drained.
                        if stage in active:
                            continue
                        section = checkpoint_sections.get(stage, {})
                        if not isinstance(section, dict) or section.get("status") != "complete":
                            continue
                        revision = section.get("data_revision")
                        if type(revision) is int and revision >= 0 and (stage, revision) not in seen:
                            eligible.append((stage, revision))
                    if not eligible or len(active) >= max_workers:
                        worker.stopping.wait(poll_seconds)
                        continue
                    persisted = worker.store.stage_results(tenant, ident)
                    for stage, revision in eligible:
                        if persisted.get(stage, {}).get("data_revision") == revision:
                            seen.add((stage, revision))
                            continue
                        if len(active) >= max_workers:
                            break
                        if not worker.store.claim_stage(tenant, ident, stage, revision, owner, lease_seconds):
                            continue
                        seen.add((stage, revision))
                        try:
                            task = _StageProcess(worker, tenant, ident, stage, revision, job, selectors)
                            task.start()
                        except Exception:
                            LOGGER.warning("Progressive AI stage %s could not start", stage, exc_info=False)
                            continue
                        active[stage] = (revision, task)
            worker.stopping.wait(poll_seconds)
    finally:
        _stop_active(active)
        discard = getattr(worker, "discard_prewarmed", None)
        if callable(discard):
            discard()
    return worker.store.job(tenant, ident)["status"]
