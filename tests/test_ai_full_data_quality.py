"""Lossless inputs for both holistic agents, including future collector types."""
import json
import sqlite3
import subprocess
import sys

import pytest
import yaml

from peaso.ai import briefing, network
from peaso.ai.pipeline import private_json
from peaso.analysis.network import NETWORK_TYPES
from peaso.analysis.reachability import REACHABILITY_TYPES
from peaso.collectors import supported_types


def detail(db, domain, ident):
    return json.loads(db.execute('SELECT detail FROM records WHERE domain=? AND id=?', (domain, ident)).fetchone()[0])


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


@pytest.mark.parametrize('stage', ('network', 'priorities'))
def test_quality_limits_and_full_lookup_instructions(stage):
    from pathlib import Path
    config = yaml.safe_load((Path('peaso/ai/agents')/(stage+'.yaml')).read_text())
    assert config['agent']['thinking_effort'] == 'high'
    assert config['agent']['max_turns'] >= 30
    assert config['agent']['max_runtime_minutes'] >= 5
    assert config['tools']['exec_timeout_seconds'] >= 60
    assert config['tools']['exec_max_output_chars'] >= 16000
    assert 'source_report' in config['system_prompt'] and '--keys' in config['system_prompt']
    from peaso.ai.review_groups import stage_limit
    assert stage_limit(stage, True) >= 600
    assert stage_limit(stage, False) >= 150


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
