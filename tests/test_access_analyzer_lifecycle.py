"""Scans read existing Access Analyzers and only create, then delete, their own."""

import pytest

from peaso.collectors.aws import ReadFailure, ReadResult, Requests
from peaso.collectors.aws_access_analyzer_lifecycle import AnalyzerLifecycle

ACCOUNT = "111122223333"
IDENTITY = {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:role/scan"}
REGION = "us-east-1"
EXISTING = {"arn": f"arn:aws:access-analyzer:{REGION}:{ACCOUNT}:analyzer/customer", "name": "customer",
            "type": "ACCOUNT", "status": "ACTIVE"}
EXISTING_UNUSED = {"arn": f"arn:aws:access-analyzer:{REGION}:{ACCOUNT}:analyzer/customer-unused",
                   "name": "customer-unused", "type": "ACCOUNT_UNUSED_ACCESS", "status": "ACTIVE"}


class Denied(Exception):
    response = {"Error": {"Code": "AccessDeniedException"}}


class Session:
    def get_partition_for_region(self, region):
        return "aws"


class AnalyzerService:
    """In-memory Access Analyzer: one account, analyzers keyed by name."""

    def __init__(self, existing=(), *, deny_create=False, fail_get=None):
        self.analyzers = {row["name"]: dict(row) for row in existing}
        self.deny_create, self.fail_get = deny_create, fail_get
        self.created, self.deleted = [], []

    def create_analyzer(self, analyzerName, type, clientToken, configuration=None):
        if self.deny_create:
            raise Denied()
        arn = f"arn:aws:access-analyzer:{REGION}:{ACCOUNT}:analyzer/{analyzerName}"
        self.analyzers[analyzerName] = {"arn": arn, "name": analyzerName, "type": type, "status": "ACTIVE"}
        self.created.append(analyzerName)
        return {"arn": arn}

    def get_analyzer(self, analyzerName):
        if self.fail_get:
            raise self.fail_get
        return {"analyzer": dict(self.analyzers[analyzerName])}

    def delete_analyzer(self, analyzerName, clientToken):
        self.deleted.append(analyzerName)
        del self.analyzers[analyzerName]

    def start_resource_scan(self, **kwargs):
        pytest.fail("StartResourceScan must never be called")


class FakeRequests:
    def __init__(self, service, *, cancel_after_checks=None):
        self.service, self.checks, self.cancel_after = service, 0, cancel_after_checks

    def check_deadline(self):
        self.checks += 1
        if self.cancel_after is not None and self.checks > self.cancel_after:
            raise ReadFailure("timeout", "intentional_scan_deadline")

    def _sleep(self, seconds):
        pass

    def client(self, session, service, region):
        assert service == "accessanalyzer"
        return self.service

    def pages(self, session, service, region, operation, expression, **arguments):
        assert (service, operation) == ("accessanalyzer", "list_analyzers")
        rows = [dict(row) for row in self.service.analyzers.values()]
        return ReadResult(rows, "collected" if rows else "empty")


def enrich_with_findings(requests, session, region, items):
    return [{**item, "Findings": []} for item in items]


def run_scan(service, **options):
    requests, events, session = FakeRequests(service, **options), [], Session()
    with AnalyzerLifecycle(requests, events) as lifecycle:
        lifecycle.prepare(session, IDENTITY, [REGION])
        read = lifecycle.collect(session, IDENTITY, REGION, enrich_with_findings)
    return read, events


@pytest.fixture(autouse=True)
def no_waiting(monkeypatch):
    from peaso.collectors import aws_access_analyzer_lifecycle as lifecycle
    monkeypatch.setattr(lifecycle, "MINIMUM_AGE_SECONDS", 0)


def test_region_without_analyzer_creates_reads_and_deletes_its_own():
    service = AnalyzerService()
    read, events = run_scan(service)
    assert len(service.created) == 2 and all(name.startswith("peaso-scan-") for name in service.created)
    assert sorted(service.deleted) == sorted(service.created) and service.analyzers == {}
    assert {row["type"] for row in read.items} == {"ACCOUNT", "ACCOUNT_UNUSED_ACCESS"}
    assert all("Findings" in row for row in read.items)
    assert {row["cleanup_status"] for row in events} == {"deleted"}


def test_existing_analyzers_are_read_without_creating_or_deleting():
    service = AnalyzerService([EXISTING, EXISTING_UNUSED])
    read, events = run_scan(service)
    assert read.status == "collected" and service.created == [] and service.deleted == []
    assert {row["name"] for row in read.items} == {"customer", "customer-unused"}
    assert set(service.analyzers) == {"customer", "customer-unused"} and events == []


def test_only_missing_type_is_created_and_pre_existing_is_kept():
    service = AnalyzerService([EXISTING])
    read, _ = run_scan(service)
    assert len(service.created) == 1 and service.deleted == service.created
    assert set(service.analyzers) == {"customer"}
    assert "customer" in {row["name"] for row in read.items}


def test_create_denied_falls_back_to_read_only_and_is_unknown():
    service = AnalyzerService(deny_create=True)
    read, events = run_scan(service)
    assert read.status == "unknown" and read.items == []
    assert read.error["code"] == "access_analyzer_create_denied"
    assert service.deleted == [] and {row["create_status"] for row in events} == {"failed"}


def test_create_denied_still_reads_existing_analyzer():
    service = AnalyzerService([EXISTING], deny_create=True)
    read, _ = run_scan(service)
    assert read.status == "partial" and read.error["code"] == "access_analyzer_create_denied"
    assert [row["name"] for row in read.items] == ["customer"] and "Findings" in read.items[0]
    assert service.deleted == []


def test_read_failure_still_deletes_own_analyzer_but_never_pre_existing():
    service = AnalyzerService([EXISTING], fail_get=ReadFailure("unknown", "InternalServerException"))
    read, events = run_scan(service)
    assert read.status == "partial" and service.deleted == service.created != []
    assert set(service.analyzers) == {"customer"}
    assert events[0]["cleanup_status"] == "deleted"


def test_deadline_during_collection_still_deletes_own_analyzers():
    # prepare uses one deadline check per Region plus one per creation.
    service = AnalyzerService()
    read, _ = run_scan(service, cancel_after_checks=3)
    assert read.status != "collected" and read.error["code"] == "intentional_scan_deadline"
    assert sorted(service.deleted) == sorted(service.created) and service.analyzers == {}


def test_cancel_before_collection_deletes_own_analyzers_on_exit():
    service = AnalyzerService([EXISTING])
    requests, session = FakeRequests(service), Session()
    with pytest.raises(RuntimeError):
        with AnalyzerLifecycle(requests, []) as lifecycle:
            lifecycle.prepare(session, IDENTITY, [REGION])
            raise RuntimeError("scan cancelled")
    assert service.created and service.deleted == service.created
    assert set(service.analyzers) == {"customer"}


def test_lifecycle_client_refuses_foreign_deletes_and_other_mutations():
    service = AnalyzerService([EXISTING])
    lifecycle = AnalyzerLifecycle(FakeRequests(service), [])
    client = lifecycle._client(Session(), REGION)
    for call in (lambda: client.delete_analyzer(analyzerName="customer", clientToken="x"),
                 lambda: client.create_analyzer(analyzerName="customer2", type="ACCOUNT", clientToken="x"),
                 lambda: client.start_resource_scan(analyzerArn=EXISTING["arn"], resourceArn="x")):
        with pytest.raises(ReadFailure):
            call()
    assert set(service.analyzers) == {"customer"} and service.deleted == []


class ForbiddenSession:
    def client(self, *args, **kwargs):
        raise AssertionError("AWS client construction is forbidden")


@pytest.mark.parametrize("operation", ["create_analyzer", "delete_analyzer", "start_resource_scan",
                                       "update_findings", "create_archive_rule"])
@pytest.mark.parametrize("method", ["call", "pages"])
def test_generic_request_path_refuses_analyzer_changes_before_any_client(method, operation):
    args = (ForbiddenSession(), "accessanalyzer", REGION, operation)
    if method == "pages":
        args += ("analyzers",)
    with pytest.raises(ReadFailure):
        getattr(Requests({}), method)(*args)
