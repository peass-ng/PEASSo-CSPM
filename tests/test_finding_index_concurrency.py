"""Native S3 index reads are bounded, ordered and tenant-scoped on cold cache."""
import ast
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
import io
import json
from pathlib import Path
import threading
import time

import pytest

from peaso.storage.artifacts import FileArtifacts, S3Artifacts, prefix

TENANT, SCAN = 'synthetic-owner', 'd' * 32


def reference(index, tenant=TENANT):
    return f'{prefix(tenant)}/{SCAN}/finding-index-{index:032x}.json'


def finding_index(artifacts):
    # Compile the actual nested function with its real decorator and adapter.
    # No server/engine/scanner initialization is needed for this isolated seam.
    source = Path(__file__).resolve().parents[1] / 'peaso/server/app.py'
    tree = ast.parse(source.read_text())
    node = next(node for node in ast.walk(tree)
                if isinstance(node, ast.FunctionDef) and node.name == 'finding_index')
    namespace = {'artifacts': artifacts, 'lru_cache': lru_cache}
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), 'exec'), namespace)
    return namespace['finding_index']


class Objects:
    def __init__(self, count, *, delay=0, tenant=TENANT):
        self.payloads = {reference(i, tenant): {'items': [{'id': f'{tenant}-{i}-a'}, {'id': f'{tenant}-{i}-b'}]}
                         for i in range(count)}
        self.delay = delay
        self.lock = threading.Lock()
        self.calls = []
        self.active = self.peak = 0
        self.first_entered, self.release_first, self.eight_entered = (threading.Event() for _ in range(3))
        self.block_first = False
        self.failures = {}
        self.threads = set()

    def get_object(self, Bucket, Key):
        ref = Key.removeprefix('artifacts/')
        with self.lock:
            self.calls.append(ref)
            self.threads.add(threading.get_ident())
            self.active += 1
            self.peak = max(self.peak, self.active)
            if len(self.calls) == 8:
                self.eight_entered.set()
        try:
            if self.block_first and ref == reference(0):
                self.first_entered.set()
                assert self.release_first.wait(5)
            if self.delay:
                # Force completion to differ from input reference order.
                ordinal = int(ref.rsplit('-', 1)[1].split('.')[0], 16)
                time.sleep(self.delay * (1 + (7 - ordinal % 8) / 8))
            if ref in self.failures:
                raise self.failures[ref]
            return {'Body': io.BytesIO(json.dumps(self.payloads[ref]).encode())}
        finally:
            with self.lock:
                self.active -= 1


def test_native_s3_prefetch_never_submits_beyond_eight_and_preserves_order():
    client = Objects(37)
    client.block_first = True
    index = finding_index(S3Artifacts('private', client))
    references = tuple(reference(i) for i in range(37))
    with ThreadPoolExecutor(max_workers=1) as caller:
        future = caller.submit(index, TENANT, 'report', references)
        try:
            assert client.first_entered.wait(5) and client.eight_entered.wait(5)
            # Later reads complete, but no ninth read is admitted while the
            # first ordered result is still pending (unlike eager map()).
            assert len(client.calls) == 8 and not future.done()
        finally:
            client.release_first.set()
        result = future.result(timeout=5)
    assert result == tuple(item for ref in references for item in client.payloads[ref]['items'])
    assert client.peak <= 8 and client.peak > 1
    assert index(TENANT, 'report', references) is result
    assert len(client.calls) == 37 and index.cache_info().hits == 1


def test_first_input_order_failure_wins_and_no_partial_result_is_cached():
    client = Objects(19, delay=.002)
    client.failures = {reference(1): ValueError('first ordered error'),
                       reference(4): RuntimeError('later error')}
    index = finding_index(S3Artifacts('private', client))
    refs = tuple(reference(i) for i in range(19))
    for _ in range(2):
        with pytest.raises(ValueError, match='first ordered error'):
            index(TENANT, 'report', refs)
    assert index.cache_info().currsize == 0
    assert client.calls.count(reference(0)) == 2
    assert client.peak <= 8
    client.failures.clear()
    result = index(TENANT, 'report', refs)
    assert len(result) == 38 and index.cache_info().currsize == 1


def test_ordered_chunk_validation_error_precedes_a_later_read_error():
    client = Objects(12, delay=.001)
    client.payloads[reference(1)] = {'missing_items': []}
    client.failures[reference(4)] = RuntimeError('later read error')
    index = finding_index(S3Artifacts('private', client))
    with pytest.raises(KeyError, match='items'):
        index(TENANT, 'report', tuple(reference(i) for i in range(12)))
    assert index.cache_info().currsize == 0


def test_tenant_and_report_reference_remain_in_the_exact_cache_key():
    client = Objects(10)
    other = 'another-owner'
    client.payloads.update(Objects(10, tenant=other).payloads)
    index = finding_index(S3Artifacts('private', client))
    refs = tuple(reference(i) for i in range(10))
    first = index(TENANT, 'report-a', refs)
    with pytest.raises(ValueError, match='Invalid artifact reference'):
        index(other, 'report-a', refs)
    assert len(client.calls) == 10  # Tenant rejection precedes every SDK read.
    second = index(other, 'report-a', tuple(reference(i, other) for i in range(10)))
    assert second != first
    assert all(row['id'].startswith(other) for row in second)
    assert index(TENANT, 'report-b', refs) == first
    assert len(client.calls) == 30 and index.cache_info().currsize == 3


@pytest.mark.parametrize('kind', ['custom', 's3_subclass', 'local'])
def test_custom_and_local_adapters_keep_sequential_calling_policy(kind, tmp_path):
    client = Objects(5, delay=.001)
    if kind == 's3_subclass':
        class CustomS3(S3Artifacts):
            pass
        backend = CustomS3('private', client)
    elif kind == 'custom':
        class Custom:
            def get(self, tenant, ref):
                return json.load(client.get_object(Bucket='private', Key='artifacts/' + ref)['Body'])
        backend = Custom()
    else:
        class Local(FileArtifacts):
            def get(self, tenant, ref):
                client.threads.add(threading.get_ident())
                return super().get(tenant, ref)
        backend = Local(tmp_path)
        for ref, payload in client.payloads.items():
            target = tmp_path/ref
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(payload))
    index = finding_index(backend)
    result = index(TENANT, 'report', tuple(reference(i) for i in range(5)))
    assert len(result) == 10
    assert client.threads == {threading.get_ident()}
    assert client.peak <= 1


def test_empty_and_single_reference_remain_correct():
    client = Objects(1)
    index = finding_index(S3Artifacts('private', client))
    assert index(TENANT, 'empty', ()) == ()
    assert index(TENANT, 'single', (reference(0),)) == tuple(client.payloads[reference(0)]['items'])
    assert len(client.calls) == 1 and client.threads == {threading.get_ident()}
