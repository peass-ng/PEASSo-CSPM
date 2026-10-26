"""The botocore CA bundle is loaded into a shared TLS context once, and a TLS
transport failure of one read is retried a bounded number of times."""

from __future__ import annotations

import ssl
import threading
from types import SimpleNamespace

import pytest
from botocore import httpsession
from botocore.exceptions import SSLError

from peaso.collectors import aws_request_pool, aws_tls_context


class CountingContext:
    def __init__(self):
        self.loads = []

    def load_verify_locations(self, path):
        self.loads.append(path)


def pool(context):
    return SimpleNamespace(conn_kw={"ssl_context": context}, cert_reqs=None, ca_certs=None,
                           ca_cert_dir=None, ca_cert_data=None)


def setup(conn, url="https://ec2.us-east-1.amazonaws.com/", verify=True):
    httpsession.URLLib3Session._setup_ssl_cert(object.__new__(httpsession.URLLib3Session), conn, url, verify)


def test_install_is_idempotent_and_wraps_botocore():
    assert aws_tls_context.install() is True
    first = httpsession.URLLib3Session._setup_ssl_cert
    assert aws_tls_context.install() is True
    assert httpsession.URLLib3Session._setup_ssl_cert is first
    assert first._peaso_tls_once is True


def test_bundle_loaded_once_per_context_and_never_per_connection():
    aws_tls_context.install()
    context = CountingContext()
    conns = [pool(context) for _ in range(20)]
    for conn in conns:
        setup(conn)
    assert context.loads == [httpsession.get_cert_path(True)]
    assert all(conn.cert_reqs == "CERT_REQUIRED" and conn.ca_certs is None for conn in conns)


def test_concurrent_setup_loads_once():
    aws_tls_context.install()
    context = CountingContext()
    barrier = threading.Barrier(16)

    def run():
        barrier.wait()
        for _ in range(50):
            setup(pool(context))

    threads = [threading.Thread(target=run) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(context.loads) == 1


def test_custom_bundle_path_is_honoured(tmp_path):
    aws_tls_context.install()
    bundle = str(tmp_path / "ca.pem")
    context = CountingContext()
    conn = pool(context)
    setup(conn, verify=bundle)
    assert context.loads == [bundle]
    # A context already holding another bundle keeps botocore's own behaviour.
    other = pool(context)
    setup(other, verify=True)
    assert other.ca_certs == httpsession.get_cert_path(True)
    assert context.loads == [bundle]


def test_verify_false_and_plain_http_keep_original_behaviour():
    aws_tls_context.install()
    context = CountingContext()
    conn = pool(context)
    setup(conn, verify=False)
    assert conn.cert_reqs == "CERT_NONE" and conn.ca_certs is None
    plain = pool(context)
    setup(plain, url="http://localhost:9000/", verify=True)
    assert context.loads == []


def test_real_ssl_context_verifies_with_loaded_store():
    aws_tls_context.install()
    context = ssl.create_default_context()
    context.load_verify_locations  # real attribute
    conn = pool(context)
    setup(conn)
    assert conn.ca_certs is None and conn.cert_reqs == "CERT_REQUIRED"
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.cert_store_stats()["x509_ca"] > 0


class FakeClient:
    def __init__(self, failures, error=None):
        self.calls = 0
        self.failures = failures
        self.error = error or SSLError(endpoint_url="https://x", error="EOF")
        self.meta = SimpleNamespace(endpoint_url="https://ec2.us-east-1.amazonaws.com",
                                    service_model=SimpleNamespace(service_name="ec2"),
                                    region_name="us-east-1")

    def _make_api_call(self, operation_name, api_params):
        self.calls += 1
        if self.calls <= self.failures:
            raise self.error
        return {"ok": self.calls}


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(aws_request_pool.time, "sleep", lambda _s: None)


def test_tls_failure_of_read_is_retried():
    cache = aws_request_pool.RawReadCache()
    client = FakeClient(failures=2)
    cache.install(client, object())
    assert client._make_api_call("DescribeVpcs", {}) == {"ok": 3}
    assert cache.tls_retries == 2


def test_tls_retry_is_bounded():
    cache = aws_request_pool.RawReadCache()
    client = FakeClient(failures=10)
    cache.install(client, object())
    with pytest.raises(SSLError):
        client._make_api_call("DescribeVpcs", {})
    assert client.calls == len(aws_request_pool.TLS_RETRY_DELAYS) + 1


def test_other_errors_and_writes_are_not_retried():
    cache = aws_request_pool.RawReadCache()
    client = FakeClient(failures=1, error=RuntimeError("boom"))
    cache.install(client, object())
    with pytest.raises(RuntimeError):
        client._make_api_call("DescribeVpcs", {})
    assert client.calls == 1
    writer = FakeClient(failures=1)
    cache.install(writer, object())
    with pytest.raises(SSLError):
        writer._make_api_call("CreateVpc", {})
    assert writer.calls == 1
