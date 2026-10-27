"""Incremental, public scan checkpoints produced from settled native envelopes.

The worker supplies the credential/privacy boundary and durable callbacks. A
collection callback buffers each settled envelope, and commits bounded batches
before report/section publication. Report evaluation is bounded to newly
available checks and a time/collection cadence; no provider request is
repeated by this module.
"""
from __future__ import annotations

import copy
import json
import threading
import time
from collections import defaultdict

from .gc_pause import gc_paused
from .snapshot import make_snapshot, validate, seal
from .settle_memo import settle_token


# Adaptive quiet period after a cumulative report pass (CPU seconds factor, cap).
REPORT_CPU_FACTOR = 4.0
REPORT_QUIET_CAP = 300.0
# Routine cumulative passes may use at most this share of the session's wall
# time in total. A pass costs more as the inventory grows; the quiet cap alone
# let a large estate spend over a third of its collector time re-evaluating.
REPORT_CPU_SHARE = 0.1


class _Superseded(BaseException):
    """A finished collection makes an unforced cumulative pass obsolete."""


class CheckpointSession:
    """Private collector callback with public, durable per-envelope handoff.

    ``public_snapshot`` must apply secret_capture.public_snapshot followed by
    credential redaction and sealing. ``on_checkpoint`` receives a sealed public
    bounded batch with report=None; the worker commits it under one fenced
    (tenant, scan, owner, sequence) checkpoint before exposing its rows.
    A second callback with a cumulative public snapshot and report publishes an
    evaluated partial result. The worker persists encrypted private evidence
    before either callback. Persistence errors must propagate.
    """

    def __init__(self, request, on_checkpoint, public_snapshot, *,
                 interval=8.0, collection_stride=24, clock=time.monotonic,
                 batch_size=64, batch_interval=1.0, batch_bytes=8 * 1024 * 1024,
                 min_report_interval=None):
        from .engine import _selection, _analysis_selection, _privesc_selected, _selected_graph_categories, CATEGORIES
        from .analysis import REQUIRED_TYPES, privesc_required_types

        connector = request["connector"]
        self.provider = connector["provider"]
        self.request = request
        self.requested_scopes = list(connector.get("scopes") or [])
        self.content_checks = request.get("content_checks") or []
        self.categories = request.get("categories", []) if self.content_checks else request.get("categories") or list(CATEGORIES)
        self.explicit_checks = request.get("checks")
        self.frameworks = request.get("frameworks")
        _, self.native_checks = _selection(self.provider, self.categories,
                                           self.explicit_checks, self.frameworks, content_checks=self.content_checks)
        self.analysis_checks = _analysis_selection(self.provider, self.categories,
                                                    self.explicit_checks, self.frameworks)
        self.graph_categories = _selected_graph_categories(self.categories, self.native_checks,
            self.analysis_checks, request.get("categories"), self.explicit_checks, self.frameworks)
        self.analysis_requirements = REQUIRED_TYPES.get(self.provider, {})
        self.privesc = _privesc_selected(self.provider, self.categories,
                                        self.explicit_checks, self.frameworks)
        self.privesc_requirements = set(privesc_required_types(self.provider)) if self.privesc is not None else set()
        from .engine import plan_collection
        from .scan_sections import dependencies
        section_requirements = {name: values for name, values in self.analysis_requirements.items()
                                if name in self.categories}
        # IAM graphs share a completion marker with least privilege. The graph
        # requirements are a subset of that section's inventories; include them
        # even for requests selecting only iam_graph.
        if "iam_graph" in self.graph_categories:
            section_requirements["least_privilege"] = sorted(
                set(section_requirements.get("least_privilege", ()))
                | set(self.analysis_requirements.get("iam_graph", ())))
        self.section_dependencies = dependencies(self.native_checks, self.analysis_checks,
            section_requirements,
            self.privesc_requirements if self.privesc is not None else None, plan_collection(request))
        self.collection_revisions = {}
        self.collection_finished = False
        self.content_tail_active = False
        self.final_metadata = None
        self.image_targets = []
        self.global_types = set()
        self.global_scope = None
        self.effective_scopes = list(self.requested_scopes)
        self.scope_plan = None
        if self.provider == 'azure':
            from .collectors.azure import DIRECTORY, DIRECTORY_SINGLETONS, _subscription
            self.effective_scopes = [_subscription(scope) for scope in self.requested_scopes if scope != '*']
            self.global_types = set(DIRECTORY) | set(DIRECTORY_SINGLETONS) | {'tenant'}
            self.global_scope = '/tenants/' + (connector.get('auth', {}).get('tenant_id') or 'selected')
        if self.provider == 'aws':
            from .collectors.aws import GLOBAL_TYPES
            self.global_types = set(GLOBAL_TYPES)
            from .aws_image_selection_20261021 import CHECK, selections
            if any(check.id == CHECK for check in self.native_checks):
                self.image_targets = selections(connector.get('options', {}), self.requested_scopes)
        elif self.provider == 'k8s':
            from .collectors.k8s import ENDPOINTS
            self.global_types = {kind for kind, (_, namespaced) in ENDPOINTS.items() if not namespaced}
        self.public_snapshot = public_snapshot
        self.on_checkpoint = on_checkpoint
        self.interval = max(0.0, float(interval))
        # Raw batches remain durable at their own cadence. Re-evaluating the
        # cumulative inventory needs a minimum interval even when one batch
        # already exceeds collection_stride. New sections bypass this delay.
        self.min_report_interval = (self.interval if min_report_interval is None
                                    else max(0.0, float(min_report_interval)))
        self.adaptive_report_cadence = min_report_interval is None
        self.last_report_cpu = 0.0
        self.report_cpu_total = 0.0
        self.report_started = None
        self.collection_stride = max(1, int(collection_stride))
        self.clock = clock
        self.collections = {}
        self.lock = threading.RLock()
        self.publish_lock = threading.Lock()
        self.wake = threading.Event()
        self.stop = False
        self.force = False
        self.error = None
        self.sequence = 0
        self.next_sequence = 0
        self.pending = {}
        # (type, scope) -> (raw settle token, public envelope it produced).
        self.settle_memo = {}
        self.pending_bytes = 0
        self.pending_since = None
        self.batch_size = max(1, int(batch_size))
        self.batch_interval = max(0.0, float(batch_interval))
        self.batch_bytes = max(1, int(batch_bytes))
        self.last_published = 0
        self.last_time = float("-inf")
        self.published_categories = set()
        self.published_sections = set()
        self.thread = threading.Thread(target=self._background, name="peaso-checkpoint", daemon=True)
        self.thread.start()

    def _snapshot(self, envelopes, *, sequence=None, sections=None):
        # Only observed, exact native scopes enter this partial view. The
        # explicit scope boundary is retained separately for coverage.
        # A global clock envelope is cluster evidence, not a wildcard target.
        # Keep it intact while deriving only selected namespaces/context scopes.
        scopes = sorted({row["scope"] for row in envelopes
            if not (self.provider == "k8s" and row["type"] == "node_clock"
                    and row["scope"] == "*")}) or self.requested_scopes
        # Only the completed collector can supply final, validated context.
        # Keep the checkpoint's partial/section fences authoritative even if
        # collector metadata happens to contain keys with the same names.
        metadata = copy.deepcopy(self.final_metadata) if self.collection_finished and self.final_metadata is not None else {}
        metadata.update({"intentional_partial": True,
                    "scope_coverage": {"status": "partial", "reason": "Collection is still in progress"},
                    "requested_scopes": self.requested_scopes,
                    "incremental": {"sequence": self.sequence if sequence is None else sequence, "phase": "collecting",
                                    "completed_collections": len(envelopes),
                                    "completed_kinds": sorted({row["type"] for row in envelopes
                                        if row["status"] in {"collected", "empty"}})}})
        metadata.pop('sections', None)
        if self.scope_plan is not None:
            metadata["incremental"]["scope_plan"] = list(self.scope_plan)
        if self.provider == 'aws' and self.image_targets:
            from .collectors.aws_image_vulnerability_runtime_20261021 import attach_metadata
            attach_metadata(metadata, envelopes, self.image_targets)
        if sections is not None:
            metadata['sections'] = sections
        return make_snapshot(self.provider, scopes, envelopes, metadata=metadata)

    def _ready(self, collections=None, *, sections=None):
        collections = self.collections if collections is None else collections
        if sections is None:
            from .scan_sections import states
            with self.lock:
                sections = states(self.provider, self.effective_scopes, self.section_dependencies,
                    collections, self.collection_revisions, finished=self.collection_finished,
                    global_types=self.global_types, global_scope=self.global_scope)
        complete = defaultdict(set)
        for (kind, scope), row in collections.items():
            if row["status"] in {"collected", "empty"}:
                complete[kind].add(scope)
        available = {kind for kind, _ in collections}
        native = [check.id for check in self.native_checks
                  if ({check.kind} | set(getattr(check, "dependencies", ()))) <= available]
        analysis = [check["id"] for check in self.analysis_checks
                    if sections.get(check["category"], {}).get("status") == "complete"]
        privesc = ["privesc"] if self.privesc is not None and sections.get("privesc", {}).get("status") == "complete" else []
        return native + analysis + privesc, complete

    def restore(self, snapshots, sequence):
        """Resume immutable public deltas from this tenant/scan, without republishing them."""
        with self.lock:
            if self.sequence or type(sequence) is not int or sequence < 0:
                raise ValueError("Invalid checkpoint restoration")
            restored = {}
            revisions = {}
            for candidate in sorted(snapshots, key=lambda row: row.get('metadata', {}).get('incremental', {}).get('sequence', 0)):
                snapshot = validate(candidate)
                if snapshot["provider"] != self.provider or not snapshot["collections"]:
                    raise ValueError("Checkpoint provider or envelope mismatch")
                metadata = snapshot.get('metadata', {}).get('incremental', {})
                end = metadata.get('sequence', sequence)
                if type(end) is not int or not 0 <= end <= sequence:
                    raise ValueError('Invalid restored checkpoint sequence')
                batch_revisions = metadata.get('batch_revisions')
                if batch_revisions is not None and (not isinstance(batch_revisions, list)
                        or len(batch_revisions) != len(snapshot['collections'])):
                    raise ValueError('Invalid restored batch revisions')
                if len(snapshot['collections']) != 1 and batch_revisions is None:
                    raise ValueError('Multi-envelope checkpoint lacks revisions')
                for offset, envelope in enumerate(snapshot['collections']):
                    revision = (batch_revisions[offset] if batch_revisions is not None else
                                metadata.get('data_revision', end))
                    if type(revision) is not int or not 0 <= revision <= end:
                        raise ValueError('Invalid restored data revision')
                    key = (envelope['type'], envelope['scope'])
                    if revision >= revisions.get(key, -1):
                        restored[key] = envelope
                        revisions[key] = revision
            self.collections = restored
            self.sequence = sequence
            self.next_sequence = sequence
            self.collection_revisions = revisions
            self.last_published = sequence
            if restored:
                self.wake.set()

    def restore_final(self, snapshot):
        """Seed the latest sealed native envelopes without replaying publication."""
        candidate = validate(snapshot)
        if candidate["provider"] != self.provider:
            raise ValueError("Resume snapshot provider mismatch")
        with self.lock:
            for row in candidate["collections"]:
                key = (row["type"], row["scope"])
                self.collections[key] = row
                self.collection_revisions[key] = max(self.sequence,
                                                     self.collection_revisions.get(key, 0))

    def _scope_ready(self, kind, scope, complete):
        if scope in complete.get(kind, ()):
            return True
        if self.provider == "aws" and "/" in scope:
            account = scope.split("/", 1)[0]
            return account + "/global" in complete.get(kind, ())
        return False

    def _filter_report(self, report, complete, *, sequence=None, collections=None, sections=None):
        collections = self.collections if collections is None else collections
        dependencies = {check.id: {check.kind} | set(getattr(check, "dependencies", ()))
                        for check in self.native_checks}
        dependencies.update({check["id"]: set(self.analysis_requirements.get(check["category"], ()))
                             for check in self.analysis_checks})
        if self.privesc is not None:
            dependencies["privesc"] = self.privesc_requirements
        # A partial snapshot can contain one complete scope while another has
        # not been reached. Never publish PASS (or a negative EMPTY/NA result)
        # in the latter scope based on defaulted or missing native facts.
        by_id = {check.id: check for check in self.native_checks}
        from .engine import hydrate_finding
        def field(finding, name):
            if name in finding:
                return finding[name]
            return hydrate_finding(finding, report.get('check_frameworks'), report.get('check_meta'),
                report.get('check_meta_encoding'), report.get('remediation_templates')).get(name)
        def supported(finding):
            required = (self.privesc_requirements if field(finding, "category") == "privesc"
                        else dependencies.get(finding["check_id"], ()))
            if all(self._scope_ready(kind, finding["scope"], complete) for kind in required):
                return True
            if finding.get("status") == "UNKNOWN":
                settled = defaultdict(set)
                for kind, scope in collections:
                    settled[kind].add(scope)
                return all(self._scope_ready(kind, finding["scope"], settled) for kind in required)
            check = by_id.get(finding["check_id"])
            if finding.get("status") != "FAIL" or not getattr(check, "allow_incomplete_failure", False):
                return False
            row = collections.get((check.kind, finding["scope"]))
            return (row is not None and row["status"] == "partial" and bool(row.get("items"))
                    and all(self._scope_ready(kind, finding["scope"], complete)
                            for kind in set(required) - {check.kind}))
        report["findings"] = [finding for finding in report["findings"] if supported(finding)]
        report["coverage"] = [row for row in report["coverage"]
                              if row.get("level") != "check" or all(
                                  self._scope_ready(kind, row.get("scope", ""), complete)
                                  for kind in dependencies.get(row.get("check_id"), ()))]
        # Negative aggregate rows cannot be scoped reliably until all target
        # inventories are known. Leave them for the final report.
        report.pop("finding_aggregates", None)
        report["stats"].pop("aggregated_finding_count", None)
        report["stats"].pop("aggregated_statuses", None)
        report["stats"]["coverage_complete"] = False
        report["stats"]["inventory_complete"] = False
        report["publication"] = {"state": "partial", "phase": "collecting", "sequence": self.sequence if sequence is None else sequence,
                                 "completed_collections": len(collections)}
        report["publication"]["sections"] = sections or {}
        # evaluate_snapshot counts before the conservative scope filter. Keep
        # displayed counters tied to rows actually published.
        from collections import Counter
        report["stats"]["finding_count"] = len(report["findings"])
        report["stats"]["by_status"] = dict(Counter(row["status"] for row in report["findings"]))
        report["stats"]["by_severity"] = dict(Counter(field(row, "severity") for row in report["findings"]
                                                       if row["status"] == "FAIL"))
        return report

    def on_collection(self, envelope):
        """Buffer a bounded public delta before returning to the provider scheduler."""
        with self.lock:
            if self.error is not None:
                raise RuntimeError("checkpoint publication failed") from self.error
            sequence = self._settled(envelope)
            self.wake.set()
            return sequence

    settled = on_collection

    def on_content_tail(self, active):
        """Defer routine cumulative reports during AWS automatic content reads.

        Native deltas retain their normal durability and explicit flushes still
        publish. The terminal edge publishes the latest cumulative public view.
        """
        if self.provider != 'aws' or type(active) is not bool:
            raise ValueError('Invalid AWS content tail state')
        with self.lock:
            if self.error is not None:
                raise RuntimeError('checkpoint publication failed') from self.error
            previous = self.content_tail_active
            self.content_tail_active = active
            self.wake.set()
        if previous and not active:
            return self._maybe_publish(force=True)
        return None

    def on_scope_plan(self, scopes):
        """Accept one immutable native AWS discovery plan, never observed scopes.

        Restored checkpoints carry facts, not discovery authority. A retry must
        rediscover its plan; if facts are already durable, give the new section
        states their own watermark without changing those facts' revisions.
        """
        import re
        if (self.provider != 'aws' or not isinstance(scopes, tuple) or not scopes
                or any(not isinstance(scope, str) or not re.fullmatch(
                    r'[0-9]{12}/[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+', scope) for scope in scopes)
                or len(set(scopes)) != len(scopes)):
            raise ValueError('Invalid native scope plan')
        scopes = tuple(sorted(scopes))
        with self.lock:
            if self.error is not None:
                raise RuntimeError('checkpoint publication failed') from self.error
            if self.scope_plan is not None:
                if self.scope_plan != scopes:
                    raise ValueError('Native scope plan changed during collection')
                return
            if self.collection_finished:
                raise ValueError('Native scope plan arrived after collection closure')
            self._flush_pending()
            self.scope_plan = scopes
            self.effective_scopes = list(scopes)
            self._advance_watermark()
            self.wake.set()

    def _advance_watermark(self):
        """Persist a state-only update with the existing envelope revision."""
        if not self.collections:
            return
        sequence = self.sequence + 1
        envelope = next(reversed(self.collections.values()))
        from .secret_evidence import _lock as private_evidence_lock
        with private_evidence_lock:
            raw = self._snapshot([envelope], sequence=sequence)
            raw['metadata']['incremental']['data_revision'] = self.collection_revisions[(envelope['type'], envelope['scope'])]
            # raw and each public result are fresh documents owned here: seal
            # and validate adopt them instead of copying the inventory again.
            with gc_paused():
                delta = validate(self.public_snapshot(seal(raw, owned=True)), owned=True)
        try:
            self.on_checkpoint(delta, None, sequence)
        except BaseException as exc:
            self.error = exc
            raise
        self.sequence = self.next_sequence = sequence

    def _settled(self, envelope):
        if not isinstance(envelope, dict):
            raise TypeError("collection envelope must be an object")
        from .secret_evidence import _lock as private_evidence_lock
        with private_evidence_lock:
            # Collectors re-emit every settled envelope after their finalizers.
            # An identical native envelope under the same public-state token
            # (connector credentials and private-evidence state) yields the
            # same public envelope with no new side effect: skip rebuilding it.
            token = settle_token(self.public_snapshot, envelope)
            if token is not None:
                memo = self.settle_memo.get(token[0])
                current = self.pending.get(token[0], (None, self.collections.get(token[0]), 0))[1]
                if memo is not None and memo[0] == token and current is not None and memo[1] is current:
                    return self.next_sequence
            # make_snapshot owns the independent structural copy. Copying the
            # same native envelope before that repeated a complete traversal.
            one = self._snapshot([envelope], sequence=self.next_sequence + 1)
            with gc_paused():
                one = validate(self.public_snapshot(one), owned=True)
        public_envelope = one["collections"][0]
        key = (public_envelope["type"], public_envelope["scope"])
        previous = self.pending.get(key, (None, self.collections.get(key), 0))[1]
        if previous == public_envelope:
            self._remember_settle(token, key, previous)
            return self.next_sequence
        self.next_sequence += 1
        size = len(json.dumps(public_envelope, separators=(',', ':'), ensure_ascii=False).encode())
        if not self.pending:
            self.pending_since = self.clock()
        prior = self.pending.get(key)
        if prior:
            self.pending_bytes -= prior[2]
        self.pending[key] = (self.next_sequence, public_envelope, size)
        self._remember_settle(token, key, public_envelope)
        self.pending_bytes += size
        if len(self.pending) >= self.batch_size or self.pending_bytes >= self.batch_bytes:
            self._flush_pending()
        return self.next_sequence

    def _remember_settle(self, token, key, public_envelope):
        if token is None or token[0] != key:
            self.settle_memo.pop(key, None)
        else:
            self.settle_memo[key] = (token, public_envelope)

    def _flush_pending(self):
        """Commit one immutable batch before advancing the visible watermark.

        Called with self.lock held. A failed upload or fenced acknowledgment
        leaves committed collections unchanged and propagates to the collector.
        """
        if not self.pending:
            return
        entries = sorted(self.pending.values(), key=lambda entry: entry[0])
        end = self.next_sequence
        raw = self._snapshot([row for _, row, _ in entries], sequence=end)
        raw['metadata']['incremental']['batch_revisions'] = [revision for revision, _, _ in entries]
        from .secret_evidence import _lock as private_evidence_lock
        with private_evidence_lock, gc_paused():
            batch = validate(self.public_snapshot(seal(raw, owned=True)), owned=True)
        try:
            self.on_checkpoint(batch, None, end)
        except BaseException as exc:
            self.error = exc
            raise
        for (revision, pending_row, _), row in zip(entries, batch['collections']):
            key = (row['type'], row['scope'])
            memo = self.settle_memo.get(key)
            if memo is not None and memo[1] is pending_row:
                # The committed row is this pending envelope's validated copy.
                self.settle_memo[key] = (memo[0], row)
            self.collections[key] = row
            self.collection_revisions[key] = revision
            if self.provider == 'azure' and row['type'] == 'subscription' and '*' in self.requested_scopes:
                selected = [item.get('id') for item in row.get('items', [])
                    if isinstance(item.get('id'), str) and item['id'].startswith('/subscriptions/')]
                maximum = self.request.get('connector', {}).get('options', {}).get('max_scopes')
                self.effective_scopes = selected if maximum is None else selected[:maximum]
        self.sequence = end
        self.pending.clear()
        self.pending_bytes = 0
        self.pending_since = None
        self.wake.set()

    def _background(self):
        while True:
            self.wake.wait(timeout=min(self.batch_interval, 0.25) if self.batch_interval else 0.1)
            self.wake.clear()
            with self.lock:
                if self.stop:
                    return
            try:
                with self.lock:
                    if (self.pending and self.pending_since is not None and
                            self.clock() - self.pending_since >= self.batch_interval):
                        self._flush_pending()
                self._maybe_publish(force=self.force)
            except BaseException as exc:
                with self.lock:
                    self.error = exc

    def _maybe_publish(self, *, force=False):
        if force:
            return self._publish(force=True)
        # The analyzer evaluates a finished collection completely. An unforced
        # cumulative pass started before the finish stops at its next phase
        # boundary instead of competing with the final snapshot for CPU.
        # Per-check events (dynamic_total=False) run inside a timed engine
        # span and never stop the pass, so no span records a failure.
        from .progress import bind_callback, current_callback
        previous = current_callback()

        def superseded(event=None):
            if ((event is None or event.get("dynamic_total") is True)
                    and self.collection_finished):
                raise _Superseded
            if previous is not None and event is not None:
                previous(event)
        try:
            with bind_callback(superseded):
                return self._publish(force=False, superseded=superseded)
        except _Superseded:
            return None

    def _publish(self, *, force, superseded=None):
        # One evaluator at a time; provider settlement never waits for evaluation.
        with self.publish_lock:
            with self.lock:
                if force:
                    self._flush_pending()
                elif self.collection_finished:
                    return None
                if self.sequence == self.last_published:
                    return None
                sequence = self.sequence
                from .scan_sections import states
                sections = states(self.provider, self.effective_scopes, self.section_dependencies,
                    self.collections, self.collection_revisions, finished=self.collection_finished,
                    global_types=self.global_types, global_scope=self.global_scope)
                completed_sections = {name for name, state in sections.items() if state['status'] == 'complete'}
                graph_sections = set()
                if 'network' in completed_sections and 'network' in self.graph_categories:
                    graph_sections.add('network')
                if 'least_privilege' in completed_sections and 'iam_graph' in self.graph_categories:
                    graph_sections.add('iam_graph')
                ready, complete = self._ready(sections=sections)
                if not ready and not graph_sections:
                    return None
                ready_ids = set(ready)
                categories = {check.category for check in self.native_checks if check.id in ready_ids}
                categories.update(check["category"] for check in self.analysis_checks if check["id"] in ready_ids)
                if "privesc" in ready_ids:
                    categories.add("privesc")
                if (not force and self.content_tail_active
                        and categories <= self.published_categories
                        and completed_sections <= self.published_sections):
                    return None
                now = self.clock()
                if self.report_started is None:
                    self.report_started = now
                quiet = self.min_report_interval
                # Leave CPU for collection between costly cumulative rebuilds:
                # one pass may use at most ~1/5 of the collector's time, and all
                # passes together at most REPORT_CPU_SHARE of it. New
                # sections/categories and explicit flushes bypass this gate;
                # their cost still counts toward the share.
                if self.adaptive_report_cadence:
                    quiet = max(quiet, min(REPORT_QUIET_CAP, REPORT_CPU_FACTOR * self.last_report_cpu))
                if (not force and categories <= self.published_categories
                        and completed_sections <= self.published_sections
                        and (now - self.last_time < quiet
                             or (sequence - self.last_published < self.collection_stride
                                 and now - self.last_time < self.interval)
                             or (self.adaptive_report_cadence and self.report_cpu_total
                                 > REPORT_CPU_SHARE * (now - self.report_started)))):
                    return None
                # Committed public envelopes are replaced, never edited in
                # place. Capture their mapping atomically; make_snapshot below
                # already copies and seals the complete native data.
                collections = dict(self.collections)
            cpu_started = time.thread_time()
            raw = self._snapshot(list(collections.values()), sequence=sequence, sections=sections)
            from .secret_evidence import _lock as private_evidence_lock
            with private_evidence_lock, gc_paused():
                snapshot = validate(self.public_snapshot(raw), owned=True)
            if superseded is not None:
                superseded()
            from .engine import evaluate_snapshot
            report = evaluate_snapshot(snapshot, categories=self.categories, checks=ready,
                                       frameworks=self.frameworks, include_not_applicable=False,
                                       completed_graph_sections=graph_sections,
                                       content_checks=[cid for cid in self.content_checks if cid in ready])
            report = self._filter_report(report, complete, sequence=sequence, collections=collections, sections=sections)
            if superseded is not None:
                superseded()
            self.on_checkpoint(snapshot, report, sequence)
            with self.lock:
                self.published_categories.update(categories)
                self.published_sections.update(completed_sections)
                # Give collection a full interval after a slow publication;
                # its evaluation time must not consume the next quiet period.
                self.last_published, self.last_time = sequence, self.clock()
                self.last_report_cpu = max(0.0, time.thread_time() - cpu_started)
                self.report_cpu_total += self.last_report_cpu
            return report

    def sections(self):
        from .scan_sections import states
        with self.lock:
            self._flush_pending()
            return states(self.provider, self.effective_scopes, self.section_dependencies,
                self.collections, self.collection_revisions, finished=self.collection_finished,
                global_types=self.global_types, global_scope=self.global_scope)

    def finish_collection(self, final_metadata=None):
        """Seal section batches after the provider finalizers have all settled."""
        with self.lock:
            if self.collection_finished:
                return
            if final_metadata is not None and type(final_metadata) is not dict:
                raise ValueError("Final collector metadata must be an object")
            self.final_metadata = copy.deepcopy(final_metadata)
            self._flush_pending()
            self.collection_finished = True
            self._advance_watermark()
            self.wake.set()

    def publish(self, **_):
        return self._maybe_publish(force=True)

    def flush(self):
        """Wait for prior evaluations, then publish the latest durable evidence."""
        with self.lock:
            if self.error is not None:
                raise RuntimeError("checkpoint publication failed") from self.error
        try:
            return self._maybe_publish(force=True)
        except BaseException as exc:
            with self.lock:
                self.error = exc
            raise

    def close(self):
        """Stop the publisher; a finished collection is evaluated by the analyzer.

        After finish_collection every batch and the final watermark are already
        durable. Rebuilding the whole cumulative report here only duplicated
        the analyzer's complete evaluation. Interrupted collections still
        publish their latest partial report.
        """
        try:
            if self.collection_finished:
                with self.lock:
                    if self.error is not None:
                        raise RuntimeError("checkpoint publication failed") from self.error
                    self._flush_pending()
            else:
                self.flush()
        finally:
            with self.lock:
                self.stop = True
                self.wake.set()
            self.thread.join(timeout=2.0)
