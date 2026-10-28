"""Scan-local AWS read sharing, bounded item concurrency and batch seeding."""

import threading
import time
from types import SimpleNamespace

import boto3
import botocore.client
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from peaso.collectors import aws
from peaso.collectors import aws_request_pool as pool

REGION = "us-east-1"


def _session():
    return boto3.Session(aws_access_key_id="AKIDEXAMPLE", aws_secret_access_key="example",
                         region_name=REGION)


@pytest.fixture
def native(monkeypatch):
    """Replace the botocore wire call; record every native request."""
    calls, handlers = [], {}
    lock = threading.Lock()

    def make_api_call(self, operation_name, api_params):
        with lock:
            calls.append((self.meta.service_model.service_name, operation_name, dict(api_params)))
        handler = handlers.get(operation_name)
        if handler is None:
            return {"ResponseMetadata": {"HTTPStatusCode": 200}}
        return handler(api_params)
    monkeypatch.setattr(botocore.client.BaseClient, "_make_api_call", make_api_call)
    return calls, handlers


def _error(code, status):
    return ClientError({"Error": {"Code": code, "Message": "m"},
                        "ResponseMetadata": {"HTTPStatusCode": status}}, "GetRole")


def test_tag_compliance_504_retries_one_page_with_physical_call_accounting(native, monkeypatch):
    calls, handlers = native
    waits = []
    monkeypatch.setattr(pool.time, "sleep", waits.append)
    attempts = iter([_error("504", 504), {"ResourceTagMappingList": []}])

    def get_resources(_params):
        value = next(attempts)
        if isinstance(value, Exception):
            raise value
        return value

    handlers["GetResources"] = get_resources
    requests = aws.Requests({"max_calls": 2})
    read = requests.pages(_session(), "resourcegroupstaggingapi", REGION,
                          "get_resources", "ResourceTagMappingList",
                          IncludeComplianceDetails=True, ExcludeCompliantResources=False,
                          ResourcesPerPage=100)
    assert read.status == "empty" and read.items == []
    assert requests.calls == 2 and requests.raw_reads.gateway_retries == 1
    assert [name for _, name, _ in calls] == ["GetResources", "GetResources"]
    assert waits == [0.2]


def test_tag_compliance_504_respects_scan_call_limit(native, monkeypatch):
    calls, handlers = native
    monkeypatch.setattr(pool.time, "sleep", lambda _: None)
    handlers["GetResources"] = lambda _: (_ for _ in ()).throw(_error("504", 504))
    requests = aws.Requests({"max_calls": 1})
    read = requests.pages(_session(), "resourcegroupstaggingapi", REGION,
                          "get_resources", "ResourceTagMappingList",
                          IncludeComplianceDetails=True, ExcludeCompliantResources=False,
                          ResourcesPerPage=100)
    assert read.status == "not_collected" and read.error["code"] == "call_limit"
    assert requests.calls == 1 and len(calls) == 1


def test_identical_reads_share_one_native_call_within_a_scan(native):
    calls, handlers = native
    handlers["GetRole"] = lambda params: {"Role": {"RoleName": params["RoleName"]}}
    session = _session()
    requests = aws.Requests({})
    first = requests.client(session, "iam", REGION).get_role(RoleName="a")
    with pool.shared_reads():
        a = requests.client(session, "iam", REGION).get_role(RoleName="a")
        b = requests.client(session, "iam", "eu-west-1").get_role(RoleName="a")  # global endpoint
        requests.client(session, "iam", REGION).get_role(RoleName="b")
    assert a == b == first
    # Outside Requests.call (no shared_reads) every call reaches AWS.
    assert [c[2]["RoleName"] for c in calls] == ["a", "a", "b"]
    a["Role"]["RoleName"] = "mutated"
    with pool.shared_reads():
        again = requests.client(session, "iam", REGION).get_role(RoleName="a")
    assert again["Role"]["RoleName"] == "a"
    # A new scan never sees the previous scan's answers.
    with pool.shared_reads():
        aws.Requests({}).client(session, "iam", REGION).get_role(RoleName="a")
    assert len(calls) == 4


def test_selected_ecs_content_reuses_exact_native_revision_within_scan(native):
    calls, handlers = native
    arn = 'arn:aws:ecs:us-east-1:123456789012:task-definition/example:1'
    handlers['DescribeTaskDefinition'] = lambda params: {
        'taskDefinition': {'taskDefinitionArn': params['taskDefinition'],
                           'containerDefinitions': [{'name': 'web', 'environment': [
                               {'name': 'PASSWORD', 'value': 'private-test-value'}]}]},
        'ResponseMetadata': {'HTTPStatusCode': 200}}
    session = _session()
    requests = aws.Requests({'content_secret_scans': True})
    with pool.shared_reads():
        native_response = requests.client(session, 'ecs', REGION).describe_task_definition(taskDefinition=arn)
    selected = requests.client(session, 'ecs', REGION,
        _metadata_profile='aws-selected-configuration-content-v1')
    content_response = selected.describe_task_definition(taskDefinition=arn)
    assert content_response == native_response and content_response is not native_response
    assert [name for _, name, _ in calls] == ['DescribeTaskDefinition']
    assert requests.raw_reads.hits == 1
    selected.describe_task_definition(taskDefinition=arn[:-1] + '2')
    assert [name for _, name, _ in calls] == ['DescribeTaskDefinition'] * 2


def test_content_scan_retains_ecs_revision_before_ordinary_cache_entries():
    cache = pool.RawReadCache(max_bytes=320, max_entry_bytes=320)
    cache.owner = SimpleNamespace(content_secret_scans=True)
    ecs = (1, 'endpoint', 'ecs', 'DescribeTaskDefinition', 'revision')
    ordinary = (1, 'endpoint', 'ec2', 'DescribeInstances', 'instance')
    cache._store(ecs, ('ok', {'taskDefinition': 'x' * 90}))
    cache._store(ordinary, ('ok', {'Reservations': 'y' * 90}))
    assert ecs in cache._entries and ordinary not in cache._entries
    assert cache.stats()['bytes'] <= cache.max_bytes


def test_mutating_secret_and_streaming_operations_are_never_shared():
    model = boto3.Session(region_name=REGION).client("s3", aws_access_key_id="a", aws_secret_access_key="b").meta.service_model
    assert pool.eligible("s3", "GetBucketPolicy", model.operation_model("GetBucketPolicy"))
    assert not pool.eligible("s3", "GetObject", model.operation_model("GetObject"))
    assert not pool.eligible("s3", "PutBucketPolicy", model.operation_model("PutBucketPolicy"))
    lam = boto3.Session(region_name=REGION).client("lambda", aws_access_key_id="a", aws_secret_access_key="b").meta.service_model
    assert not pool.eligible("lambda", "GetFunction", lam.operation_model("GetFunction"))
    assert not pool.eligible("lambda", "GetFunctionUrlConfig", lam.operation_model("GetFunctionUrlConfig"))
    assert not pool.eligible("sts", "GetCallerIdentity", None)
    assert not pool.eligible("secretsmanager", "GetSecretValue", None)


def test_single_flight_and_transient_errors_are_not_cached(native):
    calls, handlers = native
    gate, started = threading.Event(), threading.Event()
    outcomes = iter([_error("Throttling", 400), _error("InternalError", 500), _error("X", 429), None, _error("AccessDenied", 403)])

    def get_role(params):
        if params["RoleName"] == "slow":
            started.set()
            gate.wait(5)
            return {"Role": {"RoleName": "slow"}}
        failure = next(outcomes)
        if failure is not None:
            raise failure
        return {"Role": {"RoleName": params["RoleName"]}}
    handlers["GetRole"] = get_role
    session, requests = _session(), aws.Requests({})
    client = requests.client(session, "iam", REGION)
    results = []

    def read():
        with pool.shared_reads():
            results.append(client.get_role(RoleName="slow"))
    threads = [threading.Thread(target=read) for _ in range(4)]
    threads[0].start()
    assert started.wait(5)
    for thread in threads[1:]:
        thread.start()
    time.sleep(0.05)
    gate.set()
    for thread in threads:
        thread.join(5)
    assert len(results) == 4 and sum(1 for c in calls if c[2]["RoleName"] == "slow") == 1
    with pool.shared_reads():
        for code in ("Throttling", "InternalError", "X"):
            with pytest.raises(ClientError) as raised:
                client.get_role(RoleName="t")
            assert raised.value.response["Error"]["Code"] == code
        assert client.get_role(RoleName="t") == {"Role": {"RoleName": "t"}}
        assert client.get_role(RoleName="t") == {"Role": {"RoleName": "t"}}
        for _ in range(2):  # a definitive denial is shared
            with pytest.raises(ClientError) as raised:
                client.get_role(RoleName="d")
            assert raised.value.response["Error"]["Code"] == "AccessDenied"
    assert sum(1 for c in calls if c[2]["RoleName"] == "t") == 4
    assert sum(1 for c in calls if c[2]["RoleName"] == "d") == 1


def test_cache_is_memory_bounded():
    cache = pool.RawReadCache(max_bytes=4000, max_entry_bytes=1500)
    for index in range(10):
        cache._store(("k", index), ("ok", {"v": "x" * 500}))
    cache._store(("big",), ("ok", {"v": "x" * 5000}))
    stats = cache.stats()
    assert stats["bytes"] <= 4000 and stats["evicted"] > 0 and stats["oversized"] == 1
    assert ("big",) not in cache._entries and ("k", 9) in cache._entries and ("k", 0) not in cache._entries


def test_stubbed_clients_bypass_sharing():
    session, requests = _session(), aws.Requests({})
    client = requests.client(session, "iam", REGION)
    with Stubber(client) as stub:
        stub.add_response("get_role", {"Role": {"RoleName": "a", "Path": "/", "RoleId": "AROAEXAMPLEEXAMPLE1", "Arn": "arn:aws:iam::123456789012:role/a", "CreateDate": "2026-01-01"}}, {"RoleName": "a"})
        stub.add_response("get_role", {"Role": {"RoleName": "b", "Path": "/", "RoleId": "AROAEXAMPLEEXAMPLE1", "Arn": "arn:aws:iam::123456789012:role/b", "CreateDate": "2026-01-01"}}, {"RoleName": "a"})
        with pool.shared_reads():
            assert client.get_role(RoleName="a")["Role"]["RoleName"] == "a"
            assert client.get_role(RoleName="a")["Role"]["RoleName"] == "b"


def test_adaptive_limiter_halves_on_throttle_and_grows_back():
    limiter = pool.AdaptiveLimiter(initial=8, maximum=10)
    with pytest.raises(ClientError):
        with limiter.slot("k"):
            raise _error("Throttling", 400)
    assert limiter._state["k"][0] == 4.0 and limiter.throttles == 1
    for _ in range(40):
        with limiter.slot("k"):
            pass
    assert 4.0 < limiter._state["k"][0] <= 10.0
    with pytest.raises(ClientError):
        with limiter.slot("k"):
            raise _error("AccessDenied", 403)
    assert limiter.throttles == 1


def test_ordered_map_keeps_order_and_first_error():
    requests = aws.Requests({})
    assert pool.ordered_map(requests, list(range(30)), lambda n: (time.sleep(0.001 * (n % 3)), n * 2)[1]) == [n * 2 for n in range(30)]

    def fail(n):
        if n in (3, 7):
            raise ValueError(n)
        return n
    with pytest.raises(ValueError) as raised:
        pool.ordered_map(requests, list(range(10)), fail)
    assert raised.value.args == (3,)
    seen = []
    capped = aws.Requests({"max_calls": 100})
    with pytest.raises(ValueError):
        pool.ordered_map(capped, list(range(10)), lambda n: (seen.append(n), fail(n))[1])
    assert seen == [0, 1, 2, 3]  # serial mode stops exactly where the loop did


def test_item_wise_wrapper_equals_serial_rows_and_only_wraps_reviewed_enrichers():
    def enrich(requests, session, region, items):
        return [dict(item, seen=item["n"] * 3) for item in items]
    enrich.__module__, enrich.__qualname__ = "peaso.collectors.aws_facts_ext", "_lambda_function"
    wrapped = pool.item_wise("peaso.collectors.aws_facts_ext", enrich)
    items = [{"n": n} for n in range(25)]
    for requests in (aws.Requests({}), aws.Requests({"max_calls": 5})):
        assert wrapped(requests, None, REGION, items) == enrich(requests, None, REGION, items)
    other = lambda requests, session, region, items: items  # noqa: E731
    assert pool.item_wise("peaso.collectors.aws_facts_ext", other) is other


def test_app_runner_detail_rows_each_read_their_own_service(native):
    calls, handlers = native
    arns = [f"arn:aws:apprunner:{REGION}:123456789012:service/s{n}/id" for n in range(3)]
    handlers["DescribeService"] = lambda params: {"Service": {
        "ServiceArn": params["ServiceArn"], "ServiceName": params["ServiceArn"].split("/")[1],
        "ServiceId": "id", "Status": "RUNNING", "CreatedAt": "2026-01-01", "UpdatedAt": "2026-01-01",
        "SourceConfiguration": {"AutoDeploymentsEnabled": False, "ImageRepository": {"ImageIdentifier": "img", "ImageRepositoryType": "ECR"}},
        "InstanceConfiguration": {}, "NetworkConfiguration": {"IpAddressType": "IPV4"}}}
    from peaso.collectors.aws_network_catalog import detail_enricher
    enricher = pool.item_wise("peaso.collectors.aws_network_catalog", detail_enricher("app_runner_service"))
    for options in ({}, {"max_calls": 50}):
        rows = enricher(aws.Requests(options), _session(), REGION, [{"ServiceArn": arn} for arn in arns])
        assert [row["NetworkDetails"].get("ImageIdentifier") for row in rows] == ["img"] * 3
        assert all("_coverage" not in row["NetworkDetails"] for row in rows)
    assert sorted(c[2]["ServiceArn"] for c in calls if c[1] == "DescribeService") == sorted(arns * 2)


def test_batch_seeding_answers_single_identifier_reads_exactly(native):
    calls, handlers = native

    def batch_get_builds(params):
        ids = params["ids"]
        return {"builds": [{"id": value, "arn": "arn:" + value} for value in ids if value != "gone"],
                "buildsNotFound": [value for value in ids if value == "gone"],
                "ResponseMetadata": {"HTTPStatusCode": 200}}
    handlers["BatchGetBuilds"] = batch_get_builds
    session, requests = _session(), aws.Requests({})
    ids = [f"p:{n}" for n in range(150)] + ["gone"]
    assert pool.seed_batch_details(requests, session, "codebuild", REGION, "batch_get_builds", ids) == len(ids)
    assert [len(c[2]["ids"]) for c in calls] == [100, 51]
    single = [requests.call(session, "codebuild", REGION, "batch_get_builds", ids=[value]) for value in ids]
    assert len(calls) == 2
    fresh = aws.Requests({})
    expected = [fresh.call(session, "codebuild", REGION, "batch_get_builds", ids=[value]) for value in ids]
    assert single == expected and len(calls) == 2 + len(ids)


def test_batch_prefetch_is_scan_local_single_flight_and_retries_transient_errors(native):
    calls, handlers = native
    started, release = threading.Event(), threading.Event()
    attempts = 0

    def batch_get_builds(params):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            started.set()
            assert release.wait(5)
        if attempts in (2, 3):
            raise _error("Throttling" if attempts == 2 else "InternalError",
                         429 if attempts == 2 else 500)
        return {"builds": [{"id": value} for value in params["ids"]],
                "buildsNotFound": [], "ResponseMetadata": {"HTTPStatusCode": 200}}

    handlers["BatchGetBuilds"] = batch_get_builds
    session, requests = _session(), aws.Requests({})
    ids = ["project:1", "project:2"]
    results = []

    def seed():
        results.append(pool.seed_batch_details(requests, session, "codebuild", REGION,
                                               "batch_get_builds", ids))

    threads = [threading.Thread(target=seed) for _ in range(2)]
    threads[0].start()
    assert started.wait(5)
    threads[1].start()
    release.set()
    for thread in threads:
        thread.join(5)
    assert not any(thread.is_alive() for thread in threads)
    assert len(results) == 2 and len(calls) == 1
    assert [c[2]["ids"] for c in calls] == [ids]

    # A separate scan has its own cache. Neither 429 nor 5xx is retained.
    other = aws.Requests({})
    assert pool.seed_batch_details(other, session, "codebuild", REGION, "batch_get_builds", ids) == 0
    assert pool.seed_batch_details(other, session, "codebuild", REGION, "batch_get_builds", ids) == 0
    assert pool.seed_batch_details(other, session, "codebuild", REGION, "batch_get_builds", ids) == 2
    assert len(calls) == 4
    assert pool.seed_batch_details(other, session, "codebuild", REGION, "batch_get_builds", ids) == 0
    assert len(calls) == 4


def test_metadata_wrappers_share_pooled_clients():
    from peaso.collectors.aws_network_catalog import MetadataSession
    session, requests = _session(), aws.Requests({})
    first = pool.canonical_wrapper(requests, MetadataSession(session))
    second = pool.canonical_wrapper(requests, MetadataSession(session))
    assert first is second
    assert pool.wrapper_root(first) is session
    assert first.native.client("ec2", region_name=REGION) is requests.client(session, "ec2", REGION)


def test_only_metadata_projection_profiles_share_native_reads():
    assert None in pool.SHARED_PROFILES and "fms-managed-web-acl-metadata-v1" in pool.SHARED_PROFILES
    for content in ("aws-code-log-content-indicators-v1", "aws-package-content-indicators-v1",
                    "aws-lambda-environment-content-v1", "aws-selected-configuration-content-v1",
                    "aws-selected-s3-source-content-v1", "aws-build-deployment-referenced-source-v1",
                    "aws-workload-referenced-source-v1", "aws-ecs-selected-environment-file-v1"):
        assert content not in pool.SHARED_PROFILES


def test_fms_profiled_listing_reuses_the_plain_listing(native):
    calls, handlers = native
    handlers["ListWebACLs"] = lambda params: {"WebACLs": [], "ResponseMetadata": {"HTTPStatusCode": 200}}
    session, requests = _session(), aws.Requests({})
    plain = requests.call(session, "wafv2", REGION, "list_web_acls", Scope="REGIONAL", Limit=100)
    profiled = requests.call(session, "wafv2", REGION, "list_web_acls", Scope="REGIONAL", Limit=100,
                             _metadata_profile="fms-managed-web-acl-metadata-v1")
    assert plain.get("WebACLs") == [] and isinstance(profiled, dict)
    assert sum(1 for c in calls if c[1] == "ListWebACLs") == 1


def test_app_runner_detail_enricher_reads_every_row_without_wrapper(native):
    calls, handlers = native
    arns = [f"arn:aws:apprunner:{REGION}:123456789012:service/s{n}/id" for n in range(3)]
    handlers["DescribeService"] = lambda params: {"Service": {
        "ServiceArn": params["ServiceArn"], "ServiceName": "s", "ServiceId": "id", "Status": "RUNNING",
        "CreatedAt": "2026-01-01", "UpdatedAt": "2026-01-01", "InstanceConfiguration": {},
        "SourceConfiguration": {"ImageRepository": {"ImageIdentifier": "img", "ImageRepositoryType": "ECR"}},
        "NetworkConfiguration": {"IpAddressType": "IPV4"}}}
    from peaso.collectors.aws_network_catalog import detail_enricher
    rows = detail_enricher("app_runner_service")(aws.Requests({}), _session(), REGION, [{"ServiceArn": arn} for arn in arns])
    assert [row["NetworkDetails"].get("ImageIdentifier") for row in rows] == ["img"] * 3


def _concurrent_handlers(handlers, responses):
    """Install handlers that sleep briefly and record peak concurrency."""
    state = {"active": 0, "peak": 0}
    lock = threading.Lock()

    def wrap(build):
        def handler(params):
            with lock:
                state["active"] += 1
                state["peak"] = max(state["peak"], state["active"])
            try:
                time.sleep(0.01)
                return build(params)
            finally:
                with lock:
                    state["active"] -= 1
        return handler
    for operation, build in responses.items():
        handlers[operation] = wrap(build)
    return state


def _bucket_responses():
    def location(params):
        return {"LocationConstraint": {"b0": None, "b1": "EU", "b2": "eu-west-2"}.get(params["Bucket"], "ap-south-1")}

    def missing(code):
        def raise_(params):
            raise ClientError({"Error": {"Code": code, "Message": "m"},
                               "ResponseMetadata": {"HTTPStatusCode": 404}}, "GetBucketPolicy")
        return raise_
    return {
        "ListBuckets": lambda params: {"Buckets": [{"Name": "b%d" % i} for i in range(5)]},
        "GetBucketLocation": location,
        "GetBucketPolicy": lambda params: (missing("NoSuchBucketPolicy")(params) if params["Bucket"] == "b3"
                                            else {"Policy": '{"Statement": [{"Sid": "%s"}]}' % params["Bucket"]}),
        "GetBucketVersioning": lambda params: {"Status": "Enabled" if params["Bucket"] < "b2" else "Suspended"},
        "GetBucketTagging": missing("NoSuchTagSet"),
        "GetBucketAcl": lambda params: {"Grants": [{"Permission": params["Bucket"]}]},
    }


def test_bucket_reads_run_concurrently_and_build_the_serial_rows(native):
    calls, handlers = native
    _concurrent_handlers(handlers, _bucket_responses())
    serial = aws._buckets(aws.Requests({"service_concurrency": 1}), _session(), REGION)
    serial_calls = sorted(map(repr, calls))
    calls.clear()
    state = _concurrent_handlers(handlers, _bucket_responses())
    parallel = aws._buckets(aws.Requests({}), _session(), REGION)
    assert state["peak"] > 1
    assert parallel.items == serial.items and parallel.status == serial.status
    assert [list(item) for item in parallel.items] == [list(item) for item in serial.items]
    assert sorted(map(repr, calls)) == serial_calls
    assert serial.items[1]["Versioning"]["Status"] == "Enabled"
    assert serial.items[0]["Policy"]["Policy"]["Statement"][0]["Sid"] == "b0"


def _user_responses():
    return {
        "GetAccountAuthorizationDetails": lambda params: {
            "UserDetailList": [{"UserName": "u%d" % i, "Arn": "arn:aws:iam::1:user/u%d" % i} for i in range(4)],
            "IsTruncated": False},
        "ListAccessKeys": lambda params: {"AccessKeyMetadata": [
            {"AccessKeyId": "AKIA" + params["UserName"] + str(n)} for n in range(int(params["UserName"][1:]) % 3)]},
        "GetAccessKeyLastUsed": lambda params: {"AccessKeyLastUsed": {"ServiceName": params["AccessKeyId"]}},
        "ListMFADevices": lambda params: {"MFADevices": [{"SerialNumber": params["UserName"]}]},
        "ListSSHPublicKeys": lambda params: {"SSHPublicKeys": [{"SSHPublicKeyId": params["UserName"], "Status": "Active",
                                                                "UserName": "dropped"}]},
    }


def test_iam_user_reads_run_concurrently_and_build_the_serial_rows(native, monkeypatch):
    calls, handlers = native
    monkeypatch.setattr(aws, "_services_last_accessed", lambda *args: None)
    _concurrent_handlers(handlers, _user_responses())
    serial = aws._iam(aws.Requests({"service_concurrency": 1}), _session(), REGION, {"iam_user"})["iam_user"]
    serial_calls = sorted(map(repr, calls))
    calls.clear()
    state = _concurrent_handlers(handlers, _user_responses())
    parallel = aws._iam(aws.Requests({}), _session(), REGION, {"iam_user"})["iam_user"]
    assert state["peak"] > 1
    assert parallel.items == serial.items
    assert [list(item) for item in parallel.items] == [list(item) for item in serial.items]
    assert sorted(map(repr, calls)) == serial_calls
    assert [len(item["AccessKeys"]["items"]) for item in serial.items] == [0, 1, 2, 0]


def test_object_acl_sample_reads_run_concurrently_and_keep_key_order(native):
    from peaso.collectors import aws_s3_object_acl_review_20261019 as review
    calls, handlers = native

    def acl(params):
        if params["Key"] == "k2":
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "m"},
                               "ResponseMetadata": {"HTTPStatusCode": 403}}, "GetObjectAcl")
        return {"Grants": [{"Grantee": {"Type": "CanonicalUser", "ID": params["Key"]}, "Permission": "READ"}]}
    responses = {"ListObjectsV2": lambda params: {"Name": "bucket", "IsTruncated": False, "KeyCount": 7,
                                                  "Contents": [{"Key": "k%d" % i} for i in range(6)] + [{"Key": "k1"}]},
                 "GetObjectAcl": acl}
    item = {"Name": "bucket", "Location": {"collection_status": "collected", "LocationConstraint": None}}
    _concurrent_handlers(handlers, responses)
    serial = review.sample_bucket(aws.Requests({"service_concurrency": 1}), _session(), item)
    calls.clear()
    state = _concurrent_handlers(handlers, responses)
    parallel = review.sample_bucket(aws.Requests({}), _session(), item)
    assert state["peak"] > 1
    assert parallel == serial
    assert [obj["Key"] for obj in serial["objects"]] == ["k0", "k1", "k2", "k3", "k4", "k5"]
    assert serial["objects"][2]["error"]["code"] == "AccessDenied" and serial["collection_status"] == "partial"
    assert serial["errors"] == [{"operation": "ListObjectsV2", "status": "malformed", "code": "object_key_missing_or_duplicate"}]


def _finding_history_responses(now):
    from datetime import timedelta
    account, product = "123456789012", f"arn:aws:securityhub:{REGION}::product/aws/securityhub"

    def finding(index, label="HIGH", age_days=1, region=REGION):
        created = (now - timedelta(days=age_days)).isoformat()
        return {"SchemaVersion": "2018-10-08", "Id": f"f{index}", "ProductArn": product,
                "GeneratorId": "fixture", "AwsAccountId": account, "Region": region,
                "CreatedAt": created, "UpdatedAt": created, "Title": "t", "Description": "d",
                "Resources": [], "RecordState": "ACTIVE", "Severity": {"Label": label},
                "Workflow": {"Status": "NEW"}}

    findings = [finding(0), finding(1, "LOW"), finding(2, age_days=120), finding(3), finding(4),
                finding(5), finding(6, region="eu-west-1"), finding(7)]

    def history(params):
        fid = params["FindingIdentifier"]["Id"]
        if fid == "f3":
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "m"},
                               "ResponseMetadata": {"HTTPStatusCode": 403}}, "GetFindingHistory")
        created = now - timedelta(days=1)
        records = [{"FindingIdentifier": params["FindingIdentifier"], "FindingCreated": True,
                    "UpdateTime": created + timedelta(seconds=1),
                    "UpdateSource": {"Type": "BATCH_IMPORT_FINDINGS", "Identity": product}, "Updates": []}]
        if fid != "f4":
            records.append({"FindingIdentifier": params["FindingIdentifier"], "FindingCreated": False,
                            "UpdateTime": created + timedelta(hours=int(fid[1:]) + 1),
                            "UpdateSource": {"Type": "BATCH_UPDATE_FINDINGS", "Identity": "arn:aws:iam::123456789012:role/r"},
                            "Updates": [{"UpdatedField": "Workflow.Status", "OldValue": "NEW", "NewValue": "NOTIFIED"}]})
        return {"Records": records}
    return account, {"GetFindings": lambda params: {"Findings": findings}, "GetFindingHistory": history}


def test_finding_histories_read_concurrently_match_serial_order_and_stop(native):
    from datetime import datetime, timezone
    from peaso.collectors import aws_wave_semantics_native as wave
    calls, handlers = native
    now = datetime.now(timezone.utc)

    def run(options):
        account, responses = _finding_history_responses(now)
        state = _concurrent_handlers(handlers, responses)
        requests = aws.Requests(options)
        requests.observed_at = now
        return wave.collect(requests, _session(), REGION, account), state
    serial, _ = run({"service_concurrency": 1})
    serial_calls = sorted(map(repr, calls))
    calls.clear()
    parallel, state = run({})
    assert state["peak"] > 1
    assert (parallel.items, parallel.status, parallel.error) == (serial.items, serial.status, serial.error)
    assert sorted(map(repr, calls)) == serial_calls
    # The out-of-scope finding stops the read where the serial loop returned.
    assert serial.status == "partial" and serial.error == {"code": "securityhub_history_finding_scope_invalid"}
    assert [row["id"] for row in serial.items] == ["f0", "f2", "f3", "f4", "f5"]
    assert [row["complete"] for row in serial.items] == [True, False, False, True, True]
    assert serial.items[2]["_coverage"]["history"]["reason"] == "history_read_incomplete"
    assert all(call[2]["FindingIdentifier"]["Id"] != "f7" for call in calls if call[1] == "GetFindingHistory")
