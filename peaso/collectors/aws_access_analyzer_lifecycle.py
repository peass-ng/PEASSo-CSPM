"""Access Analyzer inventory with scan-owned temporary analyzers.

Per account and Region the scan lists the analyzers that already exist and
reads their findings. Only when no usable analyzer exists does it create a
temporary one (named ``peaso-scan-*``), wait for it, read its findings and
delete it again. Cleanup runs on success, failure, cancellation and deadline,
and only ever targets analyzers this scan created; pre-existing analyzers are
never changed. When creation is denied the Region keeps the read-only result
and is reported with ``access_analyzer_create_denied``.
"""
from __future__ import annotations

import time
import uuid

MINIMUM_AGE_SECONDS = 180
READY_TIMEOUT_SECONDS = 600
UNUSED_ACCESS_AGE_DAYS = 90
OK = {"collected", "empty"}
SCAN_ANALYZER_PREFIX = "peaso-scan-"

# Access Analyzer operations available through the generic request path. Every
# other operation (StartResourceScan, UpdateFindings, archive rules, ...) stays
# banned. Creation and deletion exist only on the lifecycle-owned client below.
READ_ONLY_OPERATIONS = frozenset({
    "list_analyzers", "get_analyzer", "list_findings", "list_findings_v2",
    "get_finding", "get_finding_v2"})


class _ScanAnalyzerClient:
    """Access Analyzer client limited to reads plus scan-owned create/delete."""

    def __init__(self, client, created_names):
        self._client = client
        self._created = created_names

    def create_analyzer(self, **arguments):
        name = arguments.get("analyzerName")
        if not isinstance(name, str) or not name.startswith(SCAN_ANALYZER_PREFIX):
            from .aws import ReadFailure
            raise ReadFailure("not_collected", "access_analyzer_live_api_banned")
        self._created.add(name)
        return self._client.create_analyzer(**arguments)

    def delete_analyzer(self, **arguments):
        # Only analyzers this scan attempted to create may be deleted.
        if arguments.get("analyzerName") not in self._created:
            from .aws import ReadFailure
            raise ReadFailure("not_collected", "access_analyzer_live_api_banned")
        return self._client.delete_analyzer(**arguments)

    def __getattr__(self, name):
        if name in READ_ONLY_OPERATIONS:
            return getattr(self._client, name)
        from .aws import ReadFailure
        raise ReadFailure("not_collected", "access_analyzer_live_api_banned")


class AnalyzerLifecycle:
    def __init__(self, requests, events, progress=None):
        self.requests = requests
        self.events = events
        self.progress = progress
        self.inventories = {}
        self.owned = {}
        self.created_names = set()
        self.usage_regions = {}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        # Covers exceptions/cancellation before an analyzer's collection job starts.
        for key in list(self.owned):
            self.cleanup(key)

    def event(self, account, region, **values):
        row = {"account_id": account, "region": region, **values}
        self.events.append(row)
        return row

    def _client(self, session, region):
        from .aws import _ANALYZER_READ
        _ANALYZER_READ.allowed = True
        try:
            client = self.requests.client(session, "accessanalyzer", region)
        finally:
            _ANALYZER_READ.allowed = False
        return _ScanAnalyzerClient(client, self.created_names)

    def prepare(self, session, identity, regions):
        """List first; a failed/partial inventory never proves an analyzer absent."""
        from .aws import _failure
        from .aws_iam_usage_extension import register_context
        usage_scan = register_context(self.requests, session, identity, regions)
        for region in regions:
            self.usage_regions[(id(session), region)] = usage_scan
        account = identity["Account"]
        partition = identity["Arn"].split(":")[1]
        reads = {}
        for region in regions:
            self.requests.check_deadline()
            read = self.requests.pages(session, "accessanalyzer", region, "list_analyzers", "analyzers")
            reads[region] = read
            self.inventories[(id(session), region)] = read
        # Unused IAM analysis is account-global within a partition. Prefer an
        # existing analyzer anywhere in the scanned Regions; never duplicate it.
        unused_exists = any(item.get("type") in {"ACCOUNT_UNUSED_ACCESS", "ORGANIZATION_UNUSED_ACCESS"}
                            and (not usage_scan or item.get("status") in {"ACTIVE", "CREATING"})
                            for read in reads.values() for item in read.items)
        unused_regions = {}
        for region in regions:
            unused_regions.setdefault(session.get_partition_for_region(region), region)
        for region, read in reads.items():
            if read.status not in OK:
                continue
            types = {item.get("type") for item in read.items
                     if not usage_scan or item.get("status") in {"ACTIVE", "CREATING"}}
            required = ["ACCOUNT"]
            if not unused_exists and region == unused_regions.get(partition) and all(r.status in OK for r in reads.values()):
                required.append("ACCOUNT_UNUSED_ACCESS")
            for analyzer_type in required:
                if analyzer_type in types or (analyzer_type == "ACCOUNT" and "ORGANIZATION" in types):
                    continue
                self.requests.check_deadline()
                name = SCAN_ANALYZER_PREFIX + uuid.uuid4().hex + ("-unused" if analyzer_type.endswith("UNUSED_ACCESS") else "-external")
                arn = f"arn:{partition}:access-analyzer:{region}:{account}:analyzer/{name}"
                record = self.event(account, region, type=analyzer_type, arn=arn, create_status="pending")
                args = {"analyzerName": name, "type": analyzer_type, "clientToken": name}
                if analyzer_type == "ACCOUNT_UNUSED_ACCESS":
                    args["configuration"] = {"unusedAccess": {"unusedAccessAge": UNUSED_ACCESS_AGE_DAYS}}
                key = (id(session), region, name)
                try:
                    client = self._client(session, region)
                    # Register the unique attempted name before sending: a
                    # timeout can hide a successful server-side creation.
                    self.owned[key] = (client, record)
                    response = client.create_analyzer(**args)
                    record.update(create_status="created", ready_after=time.monotonic() + MINIMUM_AGE_SECONDS)
                    if response.get("arn") != arn:
                        raise ValueError("unexpected analyzer ARN")
                    read.items.append({"arn": arn, "name": name, "type": analyzer_type,
                                       "status": "CREATING", "_scan_temporary": True,
                                       **({"configuration": args["configuration"]} if "configuration" in args else {})})
                    read.status = "collected" if read.status in OK else "partial"
                except Exception as exc:
                    failure = _failure(exc)
                    record.update(create_status="failed", error={"code": failure.code})
                    if failure.status == "denied" or failure.code in {"ConflictException", "ServiceQuotaExceededException", "ValidationException"}:
                        self.owned.pop(key, None)
                    elif key in self.owned:
                        record["create_status"] = "uncertain"
                        self.cleanup(key)
                    # Existing analyzers are still read; the missing analyzer
                    # type leaves its checks UNKNOWN rather than failing the scan.
                    read.status = "partial" if read.items else "unknown"
                    code = "access_analyzer_create_denied" if failure.status == "denied" else "access_analyzer_creation_failed"
                    read.error = {"code": code, "cause_status": failure.status,
                                  "operation": "access-analyzer:CreateAnalyzer", "cause_code": failure.code}

    def _wait(self, deadline, account, region):
        from peaso.progress import emit_progress
        while time.monotonic() < deadline:
            self.requests.check_deadline()
            emit_progress(self.progress, phase="collecting", provider="aws", scope=f"{account}/{region}",
                          dynamic_total=False)
            self.requests._sleep(max(0, min(10, deadline - time.monotonic())))

    def collect(self, session, identity, region, enrich):
        from .aws import _failure
        account = identity["Account"]
        usage_scan = self.usage_regions.get((id(session), region), False)
        read = self.inventories.get((id(session), region))
        if read is None:
            # Not prepared: read existing analyzers only.
            read = self.requests.pages(session, "accessanalyzer", region, "list_analyzers", "analyzers")
            if read.status not in OK:
                return read
        owned = [key for key in list(self.owned) if key[:2] == (id(session), region)]
        try:
            # Both analyzers were created before any wait: their warm-up overlaps.
            for key in owned:
                client, record = self.owned[key]
                self._wait(record["ready_after"], account, region)
                deadline = record["ready_after"] + READY_TIMEOUT_SECONDS
                while True:
                    self.requests.check_deadline()
                    # Read fresh readiness on every poll; never cache CREATING.
                    detail = client.get_analyzer(analyzerName=key[2])
                    summary = detail.get("analyzer", {})
                    if summary.get("arn") != record["arn"] or summary.get("type") != record["type"]:
                        raise ValueError("unexpected analyzer summary")
                    item = next(row for row in read.items if row.get("arn") == record["arn"])
                    item.update(summary)
                    if summary.get("status") == "ACTIVE":
                        break
                    if summary.get("status") != "CREATING" or time.monotonic() >= deadline:
                        from .aws import ReadFailure
                        raise ReadFailure("timeout", "access_analyzer_not_active")
                    self._wait(min(deadline, time.monotonic() + 10), account, region)
            pending = [item for item in read.items if usage_scan and item.get("status") == "CREATING"
                       and not item.get("_scan_temporary") and isinstance(item.get("name"), str)]
            if pending:
                # One warm-up serves every customer-owned analyzer in the Region.
                self._wait(time.monotonic() + MINIMUM_AGE_SECONDS, account, region)
            deadline = time.monotonic() + READY_TIMEOUT_SECONDS
            for item in pending:
                client = self._client(session, region)
                while True:
                    self.requests.check_deadline()
                    summary = client.get_analyzer(analyzerName=item["name"]).get("analyzer", {})
                    if summary.get("arn") != item.get("arn") or summary.get("type") != item.get("type"):
                        raise ValueError("unexpected analyzer summary")
                    item.update(summary)
                    if summary.get("status") == "ACTIVE":
                        break
                    if summary.get("status") != "CREATING" or time.monotonic() >= deadline:
                        from .aws import ReadFailure
                        raise ReadFailure("timeout", "access_analyzer_not_active")
                    self._wait(min(deadline, time.monotonic() + 10), account, region)
            if read.items:
                read.items = enrich(self.requests, session, region, read.items)
            for item in read.items:
                if item.get("_scan_temporary"):
                    # ACTIVE is service readiness, not proof that initial analysis
                    # has finished. Empty findings cannot establish compliance.
                    item.setdefault("_coverage", {})["InitialAnalysis"] = {
                        "status": "partial", "reason": "initial_analysis_completion_unconfirmed",
                        "minimum_wait_seconds": MINIMUM_AGE_SECONDS}
            if owned:
                read.status = "partial" if read.items else "unknown"
                read.error = read.error or {"code": "initial_analysis_completion_unconfirmed"}
        except Exception as exc:
            failure = _failure(exc)
            read.status = "partial" if read.items else failure.status
            read.error = {"code": failure.code, "cause_status": failure.status}
        finally:
            for key in owned:
                self.cleanup(key)
        return read

    def cleanup(self, key):
        from .aws import _failure
        client, record = self.owned.pop(key)
        # Cleanup deliberately bypasses the scan deadline/cancellation and read
        # budget. Those limits must never prevent removing scan-owned resources.
        try:
            for attempt in range(3):
                try:
                    client.delete_analyzer(analyzerName=key[2], clientToken=key[2])
                    record["cleanup_status"] = "deleted"
                    break
                except Exception as exc:
                    failure = _failure(exc)
                    if failure.code == "ResourceNotFoundException":
                        record["cleanup_status"] = "absent"
                        break
                    transient = failure.status == "timeout" or failure.code in {
                        "Throttling", "ThrottlingException", "TooManyRequestsException",
                        "InternalServerException", "ServiceUnavailableException"}
                    if transient and attempt < 2:
                        self.requests._sleep(2 ** attempt)
                        continue
                    record.update(cleanup_status="failed", cleanup_error={"code": failure.code})
                    break
        finally:
            record.pop("ready_after", None)
