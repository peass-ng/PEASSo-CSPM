"""Read-only Access Analyzer inventory.

A scan never creates, updates or deletes an analyzer. It only lists the
analyzers that already exist in each Region and reads their saved findings.
When none exists, the inventory is empty with a specific reason.
"""
from __future__ import annotations

# The only Access Analyzer operations a scan may call. Every other operation
# (CreateAnalyzer, DeleteAnalyzer, StartResourceScan, ...) stays banned.
READ_ONLY_OPERATIONS = frozenset({
    "list_analyzers", "get_analyzer", "list_findings", "list_findings_v2",
    "get_finding", "get_finding_v2"})


class AnalyzerLifecycle:
    def __init__(self, requests, events, progress=None):
        self.requests = requests
        self.events = events

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def prepare(self, session, identity, regions):
        # Nothing is provisioned: existing analyzers are read per Region.
        return None

    def collect(self, session, identity, region, enrich):
        from .aws import ReadResult

        read = self.requests.pages(session, "accessanalyzer", region, "list_analyzers", "analyzers")
        if read.status not in ("collected", "empty"):
            return read
        if not read.items:
            self.events.append({"account_id": identity.get("Account"), "region": region,
                                "status": "empty", "reason": "no_existing_access_analyzer"})
            return ReadResult([], "empty")
        return ReadResult(enrich(self.requests, session, region, read.items), "collected")
