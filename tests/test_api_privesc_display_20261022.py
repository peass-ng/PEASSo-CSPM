"""API privilege detail parity without loading engine catalogs at request time."""
import json
import gzip
from copy import deepcopy
import subprocess
import sys

from peaso.server import privesc_display_catalog as display
from peaso.server.report_projection_static_20261020 import privesc_technique_details
import pytest


def test_exact_historical_and_invalid_binding_parity():
    from peaso import engine
    from peaso.privesc import versioned_catalog as source
    data = display._load()
    assert len(data['bindings']) >= 100
    assert len(data['details']) < 10000
    current = dict(source.current_binding(), tenant_id='tenant-a')
    cases = [current]
    for status in ('exact_previous_current', 'exact_bounded_v5', 'exact_additive_v4', 'exact_legacy'):
        row = next(row for row in data['bindings'] if row[3] == status)
        cases.append({'schema': source.BINDING_SCHEMA, 'tenant_id': 'tenant-a',
                      'manifest_sha256': row[0], 'effective_tree_sha256': row[1],
                      'source_revision': row[2]})
    cases += [None, {}, dict(current, tenant_id='other'), dict(current, effective_tree_sha256='0' * 64)]
    ids = sorted({ident for row in data['bindings'] for ident in row[4]})
    ids += ['admin-equivalent', 'unknown-technique']
    current_row = next(row for row in data['bindings'] if row[:3] == [
        current['manifest_sha256'], current['effective_tree_sha256'], current['source_revision']])
    previous_row = next(row for row in data['bindings'] if row[3] == 'exact_bounded_v5')
    assert any(current_row[4][ident] != previous_row[4][ident]
               for ident in current_row[4].keys() & previous_row[4].keys())
    for binding in cases:
        assert privesc_technique_details(ids, catalog_binding=binding, tenant_id='tenant-a') == \
            engine.privesc_technique_details(ids, catalog_binding=binding, tenant_id='tenant-a')


def test_query_only_import_and_display_lookup_leave_evaluator_unloaded():
    script = '''
import json, sys
from peaso.privesc import queries
from peaso.server.privesc_display_catalog import _load, lookup_details
data = _load()
binding = dict(data['current_binding'], tenant_id='tenant-a')
ident = next(iter(data['_by_binding'][(binding['manifest_sha256'], binding['effective_tree_sha256'], binding['source_revision'])][1]))
rows, status = lookup_details([ident], binding, tenant_id='tenant-a')
assert ident in rows and status == 'exact_strict_privesc'
for module in ('peaso.privesc.evaluator', 'peaso.privesc.versioned_catalog', 'peaso.engine',
               'peaso.privesc.effective_permissions.principal_evidence'):
    assert module not in sys.modules, module
import peaso.privesc as p
assert p.MODELS is p.MODELS
class Selected(Exception): pass
def selected(snapshot): raise Selected()
p.MODELS['fixture'] = selected
assert p.__getattr__('MODELS')['fixture'] is selected
try: p.analyze({'provider': 'fixture'}, entries=[])
except Selected: pass
else: raise AssertionError('mutated MODELS was not used by analysis')
print(json.dumps({'status': status, 'id': ident}))
'''
    result = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['status'] == 'exact_strict_privesc'


def test_display_artifact_with_unindexed_current_binding_fails_closed(tmp_path, monkeypatch):
    document = json.loads(gzip.decompress((display.PACK / 'api_privesc_display.json.gz').read_bytes()))
    document['current_binding']['effective_tree_sha256'] = '0' * 64
    raw = json.dumps(document, sort_keys=True, separators=(',', ':')).encode()
    (tmp_path / 'api_privesc_display.json.gz').write_bytes(gzip.compress(raw, mtime=0))
    monkeypatch.setattr(display, 'PACK', tmp_path)
    display._load.cache_clear()
    try:
        with pytest.raises(ValueError, match='unavailable'):
            display._load()
    finally:
        display._load.cache_clear()


@pytest.mark.parametrize('fault', ['bool_index', 'out_of_bounds', 'wrong_id', 'duplicate_row'])
def test_compact_reference_validation(tmp_path, monkeypatch, fault):
    source = json.loads(gzip.decompress((display.PACK / 'api_privesc_display.json.gz').read_bytes()))
    document = deepcopy(source)
    entries = document['bindings'][0][4]
    ident = next(iter(entries))
    if fault == 'bool_index':
        entries[ident] = True
    elif fault == 'out_of_bounds':
        entries[ident] = len(document['details'])
    elif fault == 'wrong_id':
        entries[ident] = next(index for index, row in enumerate(document['details']) if row['id'] != ident)
    else:
        document['details'].append(deepcopy(document['details'][0]))
    raw = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
    (tmp_path / 'api_privesc_display.json.gz').write_bytes(gzip.compress(raw, compresslevel=9, mtime=0))
    monkeypatch.setattr(display, 'PACK', tmp_path)
    display._load.cache_clear()
    try:
        with pytest.raises(ValueError, match='unavailable'):
            display._load()
    finally:
        display._load.cache_clear()
