"""Lossless inputs for both holistic agents, including future collector types."""
import json
import sqlite3
import subprocess
import sys

import pytest

from peaso.ai import briefing, network
from peaso.ai.pipeline import private_json
from peaso.analysis.network import NETWORK_TYPES
from peaso.analysis.reachability import REACHABILITY_TYPES
from peaso.collectors import supported_types


def detail(db, domain, ident):
    value = json.loads(db.execute('SELECT detail FROM records WHERE domain=? AND id=?', (domain, ident)).fetchone()[0])
    if value == {'_exact_parts': True}:
        from peaso.ai.context_reader import part_materialize
        return part_materialize(db, domain, ident, '', [100 * 1024 * 1024])
    return value


@pytest.mark.parametrize('provider', ('aws', 'gcp', 'azure', 'k8s'))
def test_every_collected_type_and_native_field_reaches_network(tmp_path, provider):
    kinds = set(supported_types(provider)) | NETWORK_TYPES | set(REACHABILITY_TYPES[provider])
    inventory = [dict(id=kind, native_id=kind, type=kind, scope='scope', provider=provider,
                      data={'futureNativeNetworkField': {'routes': ['exact-route'], 'tokenBindingPolicy': 'exact-policy'},
                            'environment': {'network': 'exact-network'}}) for kind in sorted(kinds)]
    findings = [dict(id='f-'+status, category='network', check_id='network.native', status=status,
                     severity='critical', resource_id=inventory[0]['id'], evidence={'exact': status})
                for status in ('FAIL', 'UNKNOWN', 'DENIED', 'MANUAL', 'PASS')]
    from peaso.checks import CHECKS
    for check in CHECKS:
        if check.provider == provider and (check.category == 'network' or check.kind in NETWORK_TYPES | set(REACHABILITY_TYPES[provider])):
            findings.append(dict(id='native-'+check.id, check_id=check.id, category=check.category,
                status='UNKNOWN', severity=check.severity, resource_id=inventory[0]['id'], evidence={'exact': check.id}))
    report = dict(provider=provider, findings=findings, graphs={'network': {'nodes': [], 'edges': []}},
                  account_context={'owner': 'exact-owner'}, exposure_findings=[{'id': 'e', 'status': 'FAIL', 'evidence': {'all': 'exact'}}])
    snapshot = {'metadata': {'account_context': 'exact-account'}, 'collections': [{'type': 'new-kind', 'status': 'denied', 'items': []}]}
    prepared = network.prepare(report, inventory, snapshot)
    network.build(tmp_path, prepared, [], private_json)
    briefing.materialize_context(tmp_path)
    with sqlite3.connect(tmp_path/'context.sqlite') as db:
        assert dict(db.execute("SELECT id,detail FROM records WHERE domain='source_resources'")) == {
            row['id']: briefing.encode(row) for row in inventory}
        for key, value in report.items():
            assert detail(db, 'source_report', key) == value
        assert detail(db, 'source_snapshot', 'metadata') == snapshot['metadata']
    index = json.loads((tmp_path/'platform.json').read_text())['data_index']
    assert index['resource_types'] == {kind: 1 for kind in kinds}


def test_priorities_all_statuses_and_sources_are_exact(tmp_path):
    findings = [dict(id=str(i), category=category, status=status, check_id=category,
                     severity='critical', evidence={'full': 'evidence'}, resource_id='r')
                for i, (category, status) in enumerate((c, s) for c in ('hardening', 'exposure', 'secrets', 'network', 'privesc')
                    for s in ('FAIL', 'PASS', 'UNKNOWN', 'DENIED', 'MANUAL', 'EMPTY', 'NOT_APPLICABLE'))]
    report = {'provider': 'aws', 'findings': findings, 'account_context': {'owner': 'owner'},
              'secrets': [{'location': 'exact-location', 'value': 'synthetic-test-value'}],
              'graphs': {name: {'nodes': [{'id': name+'-node', 'attrs': {'exact': name}}], 'edges': []}
                         for name in ('iam', 'privesc', 'network')}}
    platform = {'report': report, 'inventory': [{'id': 'r', 'type': 'new-kind', 'data': {'exact': 'all'}}],
                'least_privilege': {'items': [{'id': 'lp', 'principal': 'principal', 'suggestions': [{'confidence': 'unknown'}]}]},
                'network_review': {'status': 'completed', 'explanation': 'architecture', 'findings': [{'id': 'n', 'evidence': {'exact': 'finding'}}]},
                'snapshot_context': {'metadata': {'account_id': 'account'}}}
    briefing.build(tmp_path, platform, [], [], private_json)
    with sqlite3.connect(tmp_path/'context.sqlite') as db:
        for finding in findings:
            assert detail(db, 'findings', finding['id'])['finding'] == finding
        for key, value in report.items():
            assert detail(db, 'source_report', key) == value
        assert detail(db, 'resources', 'r') == platform['inventory'][0]
        assert detail(db, 'least_privilege', 'lp') == platform['least_privilege']['items'][0]
        assert detail(db, 'metadata', 'network_review') == platform['network_review']
        assert detail(db, 'source_snapshot', 'metadata') == platform['snapshot_context']['metadata']


def read(root, *args):
    return json.loads(subprocess.check_output([sys.executable, 'context.py', *args], cwd=root))


def test_full_default_lookup_search_and_large_object_keys(tmp_path):
    report = {'provider': 'aws', 'findings': [], 'future': {f'key/{i}': {'exact': 'x'*1000} for i in range(40)}}
    platform = {'report': report, 'inventory': [{'id': 'r', 'type': 'future', 'data': {'native': 'unique-needle'}}]}
    briefing.build(tmp_path, platform, [], [], private_json)
    assert read(tmp_path, 'get', 'resources', 'r') == platform['inventory'][0]
    assert read(tmp_path, 'list', 'resources', '--type', 'future', '--query', 'unique-needle')['total'] == 1
    assert read(tmp_path, 'list', 'resources', '--query', '%')['total'] == 0
    keys = []
    offset = 0
    while True:
        page = read(tmp_path, 'get', 'source_report', 'future', '--keys', '--offset', str(offset))
        keys.extend(page['items'])
        if page['next_offset'] is None:
            break
        offset = page['next_offset']
    assert keys == list(report['future'])
    for key in keys:
        pointer = '/'+key.replace('~', '~0').replace('/', '~1')
        assert read(tmp_path, 'get', 'source_report', 'future', '--path', pointer) == report['future'][key]


def test_unprojected_resource_can_support_valid_network_output(tmp_path, monkeypatch):
    from peaso.ai.contracts import validate_network
    from peaso.ai.output_validation import context
    inventory = [{'id': 'future', 'native_id': 'native-future', 'type': 'future_network_type',
                  'provider': 'aws', 'scope': 'scope', 'service': 'future-service', 'data': {'nativeRoutingField': 'exact'}}]
    report = {'provider': 'aws', 'findings': [], 'graphs': {'network': {'nodes': [], 'edges': []}}}
    prepared = network.prepare(report, inventory, {})
    assert prepared is not None
    network.build(tmp_path, prepared, [], private_json)
    output = {'explanation': 'A native routing boundary needs review.', 'findings': [{
        'title': 'Review the collected routing boundary', 'description': 'The native routing field identifies this boundary.',
        'rationale': 'Review the trust boundary before changing the route.', 'resource_id': 'future', 'severity': 'medium',
        'status': 'MANUAL', 'evidence': {'summary': 'A native routing boundary was collected.',
            'resource_ids': ['future'], 'graph_refs': [], 'observations': ['nativeRoutingField is exact.']},
        'remediation': 'Confirm dependencies and review the routing boundary.', 'verification': 'Read the native routing configuration.'}]}
    trusted = validate_network(output, prepared)
    from peaso.ai import output_validation
    monkeypatch.setattr(output_validation, 'MAX_ROWS', 0)
    local = validate_network(output, context('network', tmp_path))
    assert trusted == local


def test_large_sources_and_long_strings_have_bounded_exact_reads(tmp_path):
    from peaso.ai.context_reader import PART_BYTES
    rows = [{'id': str(i), 'native': {'route': 'route-'+str(i), 'rules': list(range(100))}} for i in range(1500)]
    text = ('é東京\\"\n' * 30000) + 'final-exact-text'
    report = {'provider': 'aws', 'findings': [], 'large': {'rows': rows, 'text': text},
              'literal_marker': {'_exact_parts': True}}
    briefing.build(tmp_path, {'report': report, 'inventory': []}, [], [], private_json)
    with sqlite3.connect(tmp_path/'context.sqlite') as db:
        assert db.execute('SELECT MAX(length(CAST(value AS BLOB))) FROM record_parts').fetchone()[0] <= PART_BYTES
        assert db.execute('SELECT MAX(length(CAST(detail AS BLOB))) FROM records').fetchone()[0] <= PART_BYTES
    assert read(tmp_path, 'get', 'source_report', 'large')['error'] == 'selected_value_too_large'
    assert read(tmp_path, 'get', 'source_report', 'literal_marker') == {'_exact_parts': True}
    assert read(tmp_path, 'get', 'source_report', 'large', '--keys')['items'] == ['rows', 'text']
    def local_read(*args):
        import contextlib
        import io
        import os
        from peaso.ai import context_reader
        previous_dir, previous_argv = os.getcwd(), sys.argv
        output = io.StringIO()
        try:
            os.chdir(tmp_path)
            sys.argv = ['context.py', *args]
            with contextlib.redirect_stdout(output):
                context_reader.main()
        finally:
            os.chdir(previous_dir)
            sys.argv = previous_argv
        return json.loads(output.getvalue())
    retrieved = []
    offset = 0
    while True:
        page = local_read('get', 'source_report', 'large', '--path', '/rows', '--offset', str(offset), '--limit', '20')
        retrieved.extend(page['items'])
        if page['next_offset'] is None:
            break
        offset = page['next_offset']
    assert retrieved == rows
    chunks = [local_read('get', 'source_report', 'large', '--path', '/text', '--chars', '4000', '--offset', str(offset))['text']
              for offset in range(0, len(text), 4000)]
    assert ''.join(chunks) == text
    assert read(tmp_path, 'get', 'source_report', 'large', '--path', '/rows/1499/native') == rows[-1]['native']
    assert read(tmp_path, 'list', 'source_report', '--query', 'route-1499')['total'] == 1


def test_large_native_records_keep_validation_metadata_and_full_evidence(tmp_path):
    from peaso.ai.output_validation import context
    finding = {'id': 'f', 'category': 'hardening', 'status': 'FAIL', 'severity': 'critical',
               'check_id': 'native', 'resource_id': 'r', 'evidence': {'payload': 'x' * 200000}}
    row = {'id': 'r', 'provider': 'aws', 'scope': 'scope', 'service': 'native',
           'type': 'future', 'data': {'payload': 'y' * 200000}}
    report = {'provider': 'aws', 'findings': [finding]}
    briefing.build(tmp_path, {'report': report, 'inventory': [row]}, [], [], private_json)
    local = context('priorities', tmp_path)
    assert local['report']['findings'] == [{'id': 'f', 'category': 'hardening', 'status': 'FAIL', 'resource_id': 'r'}]
    assert context('network', tmp_path)['inventory'][0]['service'] == 'native'
    assert read(tmp_path, 'get', 'findings', 'f', '--path', '/finding/evidence/payload', '--chars', '4000')['text'] == 'x' * 4000
    assert read(tmp_path, 'get', 'resources', 'r', '--path', '/data/payload', '--chars', '4000')['text'] == 'y' * 4000


def test_filtered_list_reads_records_once_with_the_two_pass_page_and_total(tmp_path):
    inventory = [{'id': f'r{i:03}', 'type': 'kind-a' if i % 3 else 'kind-b',
                  'data': {'native': 'needle' if i % 2 else 'other', 'pad': 'x' * (i % 7) * 300}} for i in range(90)]
    # One record above the fragment bound keeps its needle only in record_parts.
    inventory.append({'id': 'r-large', 'type': 'kind-b', 'data': {f'k{i}': 'y' * 1000 for i in range(300)} | {'tail': 'needle'}})
    briefing.build(tmp_path, {'report': {'provider': 'aws', 'findings': []}, 'inventory': inventory}, [], [], private_json)

    def two_pass(where, params, limit, offset):
        with sqlite3.connect(tmp_path/'context.sqlite') as db:
            total = db.execute('SELECT COUNT(*) FROM records WHERE ' + where, params).fetchone()[0]
            items = [json.loads(row[0]) for row in db.execute(
                'SELECT summary FROM records WHERE ' + where + ' ORDER BY risk,id LIMIT ? OFFSET ?', (*params, limit, offset))]
        return total, items

    query = ("domain=? AND (instr(detail,?)>0 OR EXISTS(SELECT 1 FROM record_parts p WHERE p.domain=records.domain "
             "AND p.id=records.id AND instr(p.value,?)>0))")
    cases = [(['--query', 'needle'], query, ['resources', 'needle', 'needle']),
             (['--type', 'kind-b'], "domain=? AND json_extract(summary,'$.type')=?", ['resources', 'kind-b']),
             (['--query', 'absent-needle'], query, ['resources', 'absent-needle', 'absent-needle'])]
    for flags, where, params in cases:
        for limit, offset in ((8, 0), (20, 20), (5, 44), (8, 45), (8, 1000)):
            page = read(tmp_path, 'list', 'resources', *flags, '--limit', str(limit), '--offset', str(offset))
            total, items = two_pass(where, params, limit, offset)
            assert page['total'] == total
            assert page['items'] == items[:len(page['items'])] and (page['items'] or not items)
            following = offset + len(page['items'])
            assert page['next_offset'] == (following if following < total else None)
