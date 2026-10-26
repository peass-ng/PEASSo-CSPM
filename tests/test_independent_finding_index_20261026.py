"""Independent index packing preserves complete legacy rows and API behavior."""
from copy import deepcopy
import json
import pytest

from peaso.storage.reports import _FindingIndexWriter, finding_summary, CHUNK_BYTES, INDEX_CHUNK_ROWS
from tests.test_peaso_report_api_paging_perf import api, route


class Memory:
    def __init__(self): self.values = {}; self.kinds = []
    def put(self, tenant, ident, kind, value):
        assert (tenant, ident) == ('alice', '1' * 32)
        ref = str(len(self.values)); self.values[ref] = deepcopy(value); self.kinds.append(kind)
        return ref


class Encoded(Memory):
    def _put_json_bytes(self, tenant, ident, kind, body):
        assert type(body) is bytes
        return self.put(tenant, ident, kind, json.loads(body))


@pytest.mark.parametrize('store_type', [Memory, Encoded])
def test_large_index_exact_rows_and_request_reduction(store_type):
    rows = [dict(id=f'f-{i:07d}', check_id='fixture', category='hardening', status='FAIL',
                 resource_id=f'asset-{i}', evidence={'unchanged-private-detail': 'never-copy'},
                 frameworks=['CIS', 'NIST'], title='Unicode ü →', scope='123456789012/us-east-1')
            for i in range(102686)]
    store = store_type(); writer = _FindingIndexWriter(store, 'alice', '1' * 32)
    for row in rows: writer.add(row)
    writer.flush()
    actual = [item for chunk in writer.chunks for item in store.values[chunk['reference']]['items']]
    assert actual == [finding_summary(row) for row in rows]
    assert len(writer.chunks) == 21
    assert sum(chunk['count'] for chunk in writer.chunks) == len(rows)
    assert all(0 < chunk['count'] <= INDEX_CHUNK_ROWS for chunk in writer.chunks)
    assert all(len(json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()) <= CHUNK_BYTES + 10
               for value in store.values.values())
    assert set(store.kinds) == {'finding-index'}
    assert all('evidence' not in row for row in actual)


@pytest.mark.parametrize('store_type', [Memory, Encoded])
def test_byte_bound_forces_early_flush_without_truncating_or_reordering(store_type):
    rows = [dict(id=str(i), check_id='x', title='x'*1000, remediation='z'*5000,
                 frameworks=['unicode Ω'*400]) for i in range(1000)]
    store = store_type(); writer = _FindingIndexWriter(store, 'alice', '1'*32)
    for row in rows: writer.add(row)
    writer.flush()
    actual = [item for chunk in writer.chunks for item in store.values[chunk['reference']]['items']]
    assert actual == [finding_summary(row) for row in rows]
    assert len(writer.chunks) > 1 and all(chunk['count'] < INDEX_CHUNK_ROWS for chunk in writer.chunks)
    assert all(len(json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()) <= CHUNK_BYTES + 10
               for value in store.values.values())


def test_empty_and_failure_do_not_claim_a_chunk_committed():
    store = Memory(); writer = _FindingIndexWriter(store, 'alice', '1'*32)
    writer.flush(); assert writer.chunks == [] and store.values == {}
    writer.add({'id': 'one'})
    def denied(*args): raise OSError('storage unavailable')
    store.put = denied
    with pytest.raises(OSError): writer.flush()
    assert writer.chunks == []


@pytest.mark.parametrize('query', [
    {}, {'categories':'hardening'}, {'categories':'exposure','status':'FAIL'},
    {'framework':'CIS AWS'}, {'framework':'Only this row'}, {'search':'Explicit title'},
    {'sort_by':'severity','sort_order':'desc','offset':3,'limit':7},
    {'sort_by':'resource_id','offset':2,'limit':5}, {'aggregation':'check'},
    {'aggregation':'check','status':'FAIL','service':'s3'}, {'finding_type':'detected_leaks'},
])
def test_independent_manifest_legacy_identical_api_filters_pages_facets(api, query):
    client, artifacts, rows, manifest = api
    headers={'Authorization':'Bearer alice'}
    legacy = client.get(route('findings'), params=query, headers=headers)
    assert legacy.status_code == 200
    manifest['finding_index_chunks'] = [{'reference':'new-index-0','count':13},
                                        {'reference':'new-index-1','count':23}]
    manifest['finding_count'] = len(rows)
    artifacts.items['new-index-0'] = {'items':deepcopy(rows[:13])}
    artifacts.items['new-index-1'] = {'items':deepcopy(rows[13:])}
    artifacts.reads.clear()
    compact = client.get(route('findings'), params=query, headers=headers)
    assert compact.status_code == 200 and compact.json() == legacy.json()
    assert artifacts.reads['index'] == 0
    assert artifacts.reads['new-index-0'] == artifacts.reads['new-index-1'] == 1
    assert client.get(route('findings'), headers={'Authorization':'Bearer bob'}).status_code == 404


@pytest.mark.parametrize('bad', [None, {}, [{'reference':'new','count':True}],
    [{'reference':'new','count':35}], [{'reference':'new','count':36},{'reference':'new','count':1}],
    [{'count':36}], []])
def test_malformed_explicit_new_manifest_rejected_not_silently_legacy(api, bad):
    client, artifacts, rows, manifest = api
    manifest['finding_count'] = len(rows); manifest['finding_index_chunks'] = bad
    response = client.get(route('findings'), headers={'Authorization':'Bearer alice'})
    assert response.status_code == 409
    assert artifacts.reads['index'] == 0
