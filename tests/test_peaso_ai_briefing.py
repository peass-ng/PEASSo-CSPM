"""Prioritization compaction preserves evidence, uncertainty and exact lookups."""
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

from peaso.ai.briefing import build
from peaso.ai.pipeline import private_json


def fixture():
    rows = [dict(id='f' + str(i), category='hardening', check_id='control', title='Restrict access',
        severity='high', status='FAIL', scope='projects/p' + str(i % 2), resource_id='r' + str(i),
        evidence={'setting': 'public' if i % 2 else 'private', 'raw': 'native-detail-' * 500},
        remediation='Restrict the effective policy.') for i in range(60)]
    resources = [dict(id=row['resource_id'], native_id='native-' + row['resource_id'], provider='gcp',
        scope=row['scope'], type='bucket', data={'policy': {'mode': row['evidence']['setting']}, 'raw': row['evidence']['raw']}) for row in rows]
    platform = {'report': {'provider': 'gcp', 'created_at': '2026-10-20T10:00:00Z', 'scopes': ['projects/p0', 'projects/p1'],
        'findings': rows, 'resources': resources, 'coverage': [{'level': 'scope', 'status': 'unknown', 'reason': 'Missing projects'}],
        'graphs': {
            'privesc': {'nodes': [{'id': 'principal', 'scope': 'projects/p0', 'type': 'service_account'}],
                'edges': [{'id': 'pe', 'source': 'principal', 'target': 'admin', 'confidence': 'conditional', 'techniques': ['technique'],
                    'findings': ['f0'], 'technique_details': [{'id': 'technique', 'severity': 'critical', 'confidence': 'conditional',
                        'conditions': ['owner approval is required'], 'mitigation': 'Remove the binding', 'blockers_not_evaluated': ['deny policy']}]}]},
            'iam': {'nodes': [{'id': 'iam-principal', 'native_id': 'principal', 'resource_id': 'r0', 'scope': 'projects/p0',
                'risk_annotations': [{'type': 'high_risk_grant', 'state': 'conditional'}],
                'card': {'effective_access': 'unknown', 'grant_summary': {'high_risk_allowed': 1},
                         'restrictions': {'condition': 'business hours'}, 'source_grants': []}}], 'edges': []},
            'network': {'semantics': 'Structural candidates only', 'nodes': [{'id': 'net-resource', 'resource_id': 'r0'}],
                'edges': [{'id': 'ne', 'source': 'internet', 'target': 'net-resource', 'type': 'rule_candidate',
                    'layer': 'modeled_rule', 'confidence': 'low', 'evidence': {'source': {'resource_id': 'native-r0'}, 'native_rule': {'port': 22, 'source': '0.0.0.0/0'},
                        'reachability': 'unknown', 'uncertainty': 'Route not collected'}}]}}},
        'inventory': resources, 'least_privilege': {'items': [{'id': 'principal', 'principal': 'principal', 'severity': 'high',
            'suggestions': [{'value': 'roles/editor', 'confidence': 'provider_recommendation'},
                            {'value': 'roles/owner', 'confidence': 'declared_grant_only'}]}],
            'coverage': {'limitations': ['Declared access is not unused access.']}}}
    reviews = [{'finding_id': row['id'], 'verdict': 'FAIL', 'reason': ''} for row in rows]
    reviews[-1] = {'finding_id': rows[-1]['id'], 'verdict': 'PASS', 'reason': 'Effective restriction was ignored.'}
    return platform, rows, reviews


def read(root, *args):
    result = subprocess.run([sys.executable, 'context.py', *args], cwd=root, text=True, capture_output=True, check=True)
    return json.loads(result.stdout)


def test_priorities_keeps_native_failed_hardening_and_exposure_in_every_lookup(tmp_path):
    platform, rows, reviews = fixture()
    findings, final = [], []
    for category in ('hardening', 'exposure'):
        for verdict in ('FAIL', 'PASS', 'UNKNOWN', 'DENIED', 'MANUAL', 'NOT_APPLICABLE', 'EMPTY'):
            ident = category + '-' + verdict
            findings.append(dict(rows[0], id=ident, category=category))
            final.append({'finding_id': ident, 'verdict': verdict, 'reason': '' if verdict == 'FAIL' else 'Review result.'})
        findings.append(dict(rows[0], id=category + '-unreviewed', category=category))
        findings.append(dict(rows[0], id=category + '-original-pass', category=category, status='PASS'))
    findings.append(dict(rows[0], id='network-advice', category='network', status='MANUAL'))
    platform['report']['findings'] = findings
    build(tmp_path, platform, findings, final, private_json)
    expected = {category + '-' + verdict for category in ('hardening', 'exposure')
                for verdict in ('FAIL', 'PASS', 'UNKNOWN', 'DENIED', 'MANUAL', 'NOT_APPLICABLE', 'EMPTY', 'unreviewed')}
    expected.add('network-advice')
    with sqlite3.connect(tmp_path / 'context.sqlite') as db:
        assert {row[0] for row in db.execute("SELECT id FROM records WHERE domain='findings'")} == expected
        assert {row[0] for row in db.execute('SELECT finding_id FROM members')} == expected
    brief = json.loads((tmp_path / 'platform.json').read_text())
    assert brief['review_counts'] == {'hardening:FAIL': 8, 'exposure:FAIL': 8, 'network:MANUAL': 1}
    assert {case['example']['id'] for case in brief['sections']['findings']} <= expected
    assert {case['facts']['category'] for case in brief['sections']['findings']} == {'hardening', 'exposure', 'network'}


def test_small_overview_keeps_full_native_details_and_all_five_domains(tmp_path):
    platform, rows, reviews = fixture()
    rows[7]['severity'] = 'critical'
    build(tmp_path, platform, rows, reviews, private_json)
    overview = json.loads((tmp_path/'platform.json').read_text())
    assert len((tmp_path/'platform.json').read_bytes()) < len(json.dumps(platform).encode()) / 10
    assert 'report' not in overview and 'inventory' not in overview
    for section in ('findings', 'least_privilege', 'privesc', 'iam', 'network'):
        assert overview['counts']['cases'][section] > 0
    group, = overview['sections']['findings']
    assert group['count'] == 60 and group['facts']['scope_count'] == 2
    assert group['facts']['evidence_variant_count'] == 2
    assert group['example']['id'] == 'f7' and group['severity'] == 'critical'
    assert group['facts']['scope_sample'] == ['projects/p0', 'projects/p1']
    assert overview['review_counts'] == {'hardening:FAIL': 60}
    detail = read(tmp_path, 'get', 'findings', 'f0', '--path', '/finding/evidence/raw')
    assert detail == rows[0]['evidence']['raw']
    assert read(tmp_path, 'get', 'resources', 'r0', '--path', '/data/policy') == {'mode': 'private'}
    assert (tmp_path/'context.sqlite').stat().st_mode & 0o777 == 0o600
    # Compact data is a reading guide; original conditions and blockers survive.
    technique = read(tmp_path, 'get', 'privesc_edges', 'pe', '--path', '/technique_details/0')
    assert technique['conditions'] == ['owner approval is required'] and technique['blockers_not_evaluated'] == ['deny policy']


def test_reader_lists_all_members_and_never_silently_truncates_evidence(tmp_path):
    platform, rows, reviews = fixture()
    build(tmp_path, platform, rows, reviews, private_json)
    group = read(tmp_path, 'list', 'finding_groups')['items'][0]
    first = read(tmp_path, 'members', group['id'], '--limit', '20')
    assert first['total'] == 60 and len(first['items']) == 20
    second = read(tmp_path, 'members', group['id'], '--limit', '20', '--offset', '20')
    assert {row['id'] for row in first['items']}.isdisjoint(row['id'] for row in second['items'])
    assert all(row['verdict'] == 'FAIL' for row in first['items'])
    assert read(tmp_path, 'get', 'findings', 'f59') != {'error': 'record_not_found'}
    with sqlite3.connect(tmp_path/'context.sqlite') as db:
        db.execute('INSERT INTO records VALUES(?,?,?,?,?,?)', ('resources', 'large', '{}', json.dumps({'large': 'x' * 13000, 'small': 1}), 4, 0))
    assert read(tmp_path, 'get', 'resources', 'large', '--path', '/large')['error'] == 'selected_value_too_large'
    window = read(tmp_path, 'get', 'resources', 'large', '--path', '/large', '--chars', '100', '--offset', '200')
    assert window == {'type': 'text', 'total': 13000, 'offset': 200, 'text': 'x' * 100}
    assert read(tmp_path, 'get', 'resources', 'large', '--path', '/small') == 1


def test_reference_links_connect_risks_without_promoting_access_confidence(tmp_path):
    platform, rows, reviews = fixture()
    build(tmp_path, platform, rows, reviews, private_json)
    related = read(tmp_path, 'related', 'resources', 'r0', '--limit', '20')
    assert {'findings', 'iam_nodes', 'network_nodes'} <= {row['domain'] for row in related['items']}
    iam = read(tmp_path, 'get', 'iam_nodes', 'iam-principal')['summary']
    assert iam['grants']['effective_access'] == 'unknown'
    network = read(tmp_path, 'get', 'network_edges', 'ne')['summary']
    assert network['reachability'] == 'unknown' and network['layer'] == 'modeled_rule'
    suggestions = read(tmp_path, 'get', 'least_privilege', 'principal')['summary']['suggestion_counts']
    assert suggestions == {'provider_recommendation': 1, 'declared_grant_only': 1}


def test_ambiguous_native_names_do_not_cross_link_accounts(tmp_path):
    platform, rows, reviews = fixture()
    platform['inventory'] += [
        {'id': 'account-a', 'native_id': 'admin', 'scope': 'account-a', 'data': {}},
        {'id': 'account-b', 'native_id': 'admin', 'scope': 'account-b', 'data': {}},
    ]
    build(tmp_path, platform, rows, reviews, private_json)
    related = read(tmp_path, 'related', 'privesc_edges', 'pe', '--limit', '20')
    assert not any(row['domain'] == 'resources' and row['summary']['id'] in ('account-a', 'account-b') for row in related['items'])


def test_decision_catalog_includes_every_case_without_top_n_sampling(tmp_path):
    platform, rows, reviews = fixture()
    for i, row in enumerate(rows):
        row['check_id'] = 'control-' + str(i)
    build(tmp_path, platform, rows, reviews, private_json)
    brief = json.loads((tmp_path/'platform.json').read_text())
    assert brief['counts']['cases']['findings'] == 60
    assert len(brief['sections']['findings']) == 60
    offset, ids = 0, set()
    while offset is not None:
        page = read(tmp_path, 'list', 'decision_findings', '--limit', '20', '--offset', str(offset))
        assert 0 < len(page['items']) <= 20
        ids.update(row['id'] for row in page['items'])
        offset = page['next_offset']
    assert len(ids) == 60


def test_gcp_principal_links_use_provider_identity_fields_not_display_names(tmp_path):
    email = 'audit@project.iam.gserviceaccount.com'
    member = 'serviceAccount:' + email
    platform = {'report': {'provider': 'gcp', 'findings': [], 'graphs': {'privesc': {'nodes': [
        {'id': member, 'provider': 'gcp', 'scope': 'projects/p', 'attrs': {'email': email}},
        {'id': 'different-cloud', 'provider': 'azure', 'scope': '/tenants/t', 'attrs': {'email': email}},
    ], 'edges': []}}}, 'inventory': [
        {'id': 'resource', 'type': 'service_account', 'provider': 'gcp', 'scope': 'projects/p',
         'native_id': 'projects/p/serviceAccounts/' + email, 'data': {'email': email}},
    ], 'least_privilege': {'items': [{'id': member, 'principal': member, 'provider': 'gcp',
        'suggestions': [{'value': 'roles/editor', 'confidence': 'provider_recommendation'}]}]}}
    build(tmp_path, platform, [], [], private_json)
    related = read(tmp_path, 'related', 'resources', 'resource', '--limit', '20')
    assert ('privesc_nodes', member) in {(row['domain'], row['summary']['id']) for row in related['items']}
    assert ('least_privilege', member) in {(row['domain'], row['summary']['id']) for row in related['items']}
    assert not any(row['summary']['id'] == 'different-cloud' for row in related['items'])


def test_decision_brief_prejoins_related_risks_and_keeps_provider_advice_separate(tmp_path):
    platform, rows, reviews = fixture()
    build(tmp_path, platform, rows, reviews, private_json)
    brief = json.loads((tmp_path/'platform.json').read_text())
    case, = brief['sections']['findings']
    assert case['related']['privesc'] == 1 and case['related']['network'] == 1
    assert case['related']['iam'] == 1
    assert {item['state'] for item in brief['sections']['least_privilege']} == {'provider_recommendation', 'declared_grant_only'}
    linked = read(tmp_path, 'related_cases', 'decision_findings', case['id'], '--limit', '20')
    assert linked['total'] == sum(case['related'].values())
    assert {'decision_privesc', 'decision_iam', 'decision_network'} <= {item['domain'] for item in linked['items']}
    members = read(tmp_path, 'members', 'decision_findings', case['id'], '--limit', '4')
    assert members['total'] == 60 and len(members['items']) == 4
    assert all(item['domain'] == 'findings' and item['summary']['verdict'] == 'FAIL' for item in members['items'])


def test_repeated_edges_collapse_but_ports_and_technique_confidence_do_not(tmp_path):
    import copy
    platform, rows, reviews = fixture()
    graphs = platform['report']['graphs']
    original = graphs['privesc']['edges'][0]
    graphs['privesc']['edges'] = [copy.deepcopy(original) | {'id': f'edge-{i}'} for i in range(40)]
    changed = copy.deepcopy(original)
    changed.update(id='mixed', confidence='derived')
    changed['technique_details'].append({'id': 'another-technique', 'confidence': 'derived', 'severity': 'high'})
    graphs['privesc']['edges'].append(changed)
    first_rule = graphs['network']['edges'][0]
    graphs['network']['edges'] = [copy.deepcopy(first_rule) | {'id': f'rule-{i}'} for i in range(40)]
    different = copy.deepcopy(first_rule)
    different['id'] = 'different-port'
    different['evidence']['native_rule']['port'] = 3389
    graphs['network']['edges'].append(different)
    build(tmp_path, platform, rows, reviews, private_json)
    brief = json.loads((tmp_path/'platform.json').read_text())
    assert len(brief['sections']['privesc']) == 2
    assert sorted(case['count'] for case in brief['sections']['privesc']) == [1, 40]
    mixed = next(case for case in brief['sections']['privesc'] if case['state'] == 'derived')
    assert mixed['facts']['technique_confidences'] == ['conditional', 'derived']
    assert len(brief['sections']['network']) == 2
    assert {case['facts']['rule']['port'] for case in brief['sections']['network']} == {22, 3389}
    assert all(case['state'] == 'unknown' for case in brief['sections']['network'])


def test_case_examples_members_and_original_details_are_all_resolvable(tmp_path):
    platform, rows, reviews = fixture()
    build(tmp_path, platform, rows, reviews, private_json)
    brief = json.loads((tmp_path/'platform.json').read_text())
    for section, cases in brief['sections'].items():
        assert len(cases) == brief['counts']['cases'][section]
        for case in cases:
            assert set(case) == {'id', 'signal', 'state', 'severity', 'count', 'unit', 'facts', 'example', 'related'}
            example = read(tmp_path, 'get', case['example']['domain'], case['example']['id'])
            assert example['summary']['id'] == case['example']['id']
            members = read(tmp_path, 'members', 'decision_' + section, case['id'])
            assert members['total'] > 0


def test_no_risk_marked_graph_record_is_lost_from_the_decision_catalog(tmp_path):
    platform, rows, reviews = fixture()
    platform['report']['graphs']['iam']['edges'] = [
        {'id': 'risky-trust', 'source': 'iam-principal', 'target': 'external',
         'risk_annotations': [{'type': 'external_trust', 'state': 'conditional'}]}]
    platform['report']['graphs']['network']['nodes'].append(
        {'id': 'network-risk', 'type': 'endpoint', 'scope': 'projects/p0', 'risk_annotations': [{'type': 'unresolved_boundary'}]})
    build(tmp_path, platform, rows, reviews, private_json)
    with sqlite3.connect(tmp_path/'context.sqlite') as db:
        source = set(db.execute("SELECT domain,id FROM records WHERE candidate=1 AND domain IN ('least_privilege','privesc_edges','iam_nodes','iam_edges','network_nodes','network_edges')"))
        represented = set(db.execute('SELECT domain,id FROM case_members'))
    assert source <= represented


def test_focus_filters_recommendations_by_case_instead_of_mixing_principal_suggestions(tmp_path):
    platform, rows, reviews = fixture()
    build(tmp_path, platform, rows, reviews, private_json)
    brief = json.loads((tmp_path/'platform.json').read_text())
    for case in brief['sections']['least_privilege']:
        bundle = read(tmp_path, 'focus', 'decision_least_privilege', case['id'], '--limit', '1')
        evidence = bundle['members'][0]['evidence']
        assert evidence['matching_suggestion_count'] == 1
        assert {item['confidence'] for item in evidence['matching_suggestions_sample']} == {case['state']}
        assert {item['value'] for item in evidence['matching_suggestions_sample']} == (
            {'roles/editor'} if case['state'] == 'provider_recommendation' else {'roles/owner'})


def test_focus_finds_the_connected_member_in_a_broad_group_with_concrete_witnesses(tmp_path):
    platform, rows, reviews = fixture()
    rows[0]['severity'] = 'critical'
    graphs = platform['report']['graphs']
    graphs['privesc']['edges'][0]['findings'] = ['f40']
    graphs['iam']['nodes'][0]['resource_id'] = 'r40'
    graphs['network']['nodes'][0]['resource_id'] = 'r40'
    graphs['network']['edges'][0]['evidence']['source']['resource_id'] = 'native-r40'
    build(tmp_path, platform, rows, reviews, private_json)
    brief = json.loads((tmp_path/'platform.json').read_text())
    case = brief['sections']['findings'][0]
    assert case['example']['id'] == 'f0'
    bundle = read(tmp_path, 'focus', 'decision_findings', case['id'], '--limit', '2')
    assert {item['ref']['id'] for item in bundle['members']} == {'f0', 'f40'}
    connected = next(item for item in bundle['members'] if item['ref']['id'] == 'f40')
    assert connected['linked_sections'] > 0 and connected['related']
    for related in connected['related']:
        assert related['via']['id'] and related['member']['id']
        assert read(tmp_path, 'get', related['member']['domain'], related['member']['id'])['summary']['id'] == related['member']['id']


def test_brief_preserves_escalation_outcomes_and_permission_field_semantics(tmp_path):
    platform, rows, reviews = fixture()
    technique = platform['report']['graphs']['privesc']['edges'][0]['technique_details'][0]
    technique.update(outcome='act_as', outcome_inferred=True, grants=['iam-admin'])
    card = platform['report']['graphs']['iam']['nodes'][0]['card']
    card['source_grants'] = [{'severity': 'high', 'allowed_declaration': True,
        'native_grant': {'Effect': 'Allow', 'NotAction': ['iam:DeleteUser']}, 'conditional': False}]
    build(tmp_path, platform, rows, reviews, private_json)
    brief = json.loads((tmp_path/'platform.json').read_text())
    escalation = brief['sections']['privesc'][0]
    assert escalation['facts']['outcomes'] == ['act_as'] and escalation['facts']['outcome_inferred'] is True
    assert escalation['facts']['capabilities_sample'] == ['iam-admin']
    assert brief['sections']['iam'][0]['facts']['permission_sample'] == [{'field': 'NotAction', 'value': 'iam:DeleteUser'}]
    bundle = read(tmp_path, 'focus', 'decision_privesc', escalation['id'])
    evidence = bundle['members'][0]['evidence']
    assert evidence['techniques_sample'][0]['conditions'] == ['owner approval is required']
    assert evidence['techniques_sample'][0]['blockers_not_evaluated'] == ['deny policy']
    assert evidence['finding_constraints_sample']  # Original finding references remain available.


def test_nonreference_scalar_equal_to_a_resource_name_creates_no_relationship(tmp_path):
    platform, rows, reviews = fixture()
    platform['inventory'].append({'id': 'named-private', 'native_id': 'private', 'scope': 'projects/p0',
                                 'type': 'bucket', 'data': {}})
    build(tmp_path, platform, rows, reviews, private_json)
    related = read(tmp_path, 'related', 'findings', 'f0', '--limit', '20')
    assert not any(item['domain'] == 'resources' and item['summary']['id'] == 'named-private' for item in related['items'])


def test_network_grouping_preserves_target_restrictions_and_ignores_json_key_order(tmp_path):
    import copy
    platform, rows, reviews = fixture()
    edge = platform['report']['graphs']['network']['edges'][0]
    edge['evidence']['native_rule'] = {'direction': 'INGRESS', 'allowed': [{'IPProtocol': 'tcp', 'ports': ['22']}],
                                     'sourceRanges': ['0.0.0.0/0'], 'targetTags': ['vpn-admin'], 'priority': 1000}
    reordered = copy.deepcopy(edge) | {'id': 'reordered'}
    reordered['evidence']['native_rule'] = dict(reversed(list(edge['evidence']['native_rule'].items())))
    different = copy.deepcopy(edge) | {'id': 'other-target'}
    different['evidence']['native_rule']['targetTags'] = ['production']
    platform['report']['graphs']['network']['edges'] = [edge, reordered, different]
    build(tmp_path, platform, rows, reviews, private_json)
    cases = json.loads((tmp_path/'platform.json').read_text())['sections']['network']
    assert len(cases) == 2 and sorted(case['count'] for case in cases) == [1, 2]


def test_historical_reciprocal_edge_ids_keep_both_directions_in_priorities(tmp_path):
    platform, rows, reviews = fixture()
    edges = [
        {'id': 'old-unordered-id', 'source': 'a', 'target': 'b', 'confidence': 'conditional', 'techniques': ['forward']},
        {'id': 'old-unordered-id', 'source': 'b', 'target': 'a', 'confidence': 'conditional', 'techniques': ['reverse']}]
    platform['report']['graphs']['privesc']['edges'] = edges
    build(tmp_path, platform, rows, reviews, private_json)
    with sqlite3.connect(tmp_path / 'context.sqlite') as db:
        stored = db.execute("SELECT id,detail FROM records WHERE domain='privesc_edges'").fetchall()
    assert len(stored) == 2 and len({key for key, _ in stored}) == 2
    assert {(json.loads(detail)['source'], json.loads(detail)['target']) for _, detail in stored} == {('a','b'),('b','a')}
    assert all(json.loads(detail)['id'] == 'old-unordered-id' for _, detail in stored)
    assert [edge['id'] for edge in edges] == ['old-unordered-id','old-unordered-id']
