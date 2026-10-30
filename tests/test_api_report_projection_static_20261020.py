"""Source-bound parity against the real engine in independent fresh processes."""
import json
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
HELPER = 'peaso.server.report_projection_static_20261020'


PROBE = r'''
import copy, hashlib, importlib, json, sys, time
probe_started = time.perf_counter()
from pathlib import Path
import hashlib
from peaso.server import report_projection_static_20261020 as projection
m = importlib.import_module(sys.argv[1])
mode = sys.argv[2]
out = []
def call(name, *args, **kwargs):
    original = copy.deepcopy((args, kwargs))
    try:
        result = getattr(m, name)(*args, **kwargs)
        record = {'result': result, 'identity_first': bool(args) and result is args[0]}
        if name == 'hydrate_finding' and isinstance(result, dict):
            record['shared_values'] = sorted(k for k, v in result.items()
                if isinstance(v, (list, dict)) and isinstance(args[0], dict) and k in args[0] and v is args[0][k])
    except Exception as error:
        record = {'error': type(error).__name__, 'message': str(error)}
    record['inputs_unchanged'] = (args, kwargs) == original
    out.append(record)
if mode == 'hydration':
    fields = ('title', 'remediation', 'service', 'category', 'severity', 'finding_type',
              'description', 'evaluated', 'pass_when', 'fail_when', 'not_applicable_when',
              'rationale', 'clarity_evaluation_contract')
    defaults = {field: ['evaluation'] if field == 'evaluated' else 'archived ' + field for field in fields}
    row = {'check_id': 'example', 'evidence': {'archived': True}}
    for encoding in (None, m.CHECK_META_ENCODING, dict(m.CHECK_META_ENCODING, version=2)):
        for field in fields:
            for override in ({}, {field: None}, {field: ''}, {field: ['explicit']}):
                call('hydrate_finding', dict(row, **override), {'example': ['A']}, {'example': defaults}, encoding)
    for flags in ('r', 'm', 'rm', '', 'mr', 'rr', None, False, 1, [], {}):
        for description in ('archived description', None, 1, ['description']):
            for template in ({'summary': 'archived remediation'}, {'summary': None}, [], None):
                call('hydrate_finding', row, None, {'example': {'description': description, '_derived': flags}},
                     m.CHECK_META_ENCODING, {'example': template})
    for flags in ('r', 'm', 'rm'):
        for field in ('rationale', 'remediation'):
            for value in (None, '', [], 'explicit'):
                call('hydrate_finding', dict(row, **{field: value}), None,
                     {'example': {'description': 'archived', '_derived': flags}}, m.CHECK_META_ENCODING,
                     {'example': {'summary': 'archived action'}})
    for meta in (None, {}, [], 0, 1, 'bad', {'example': None}, {'example': []},
                 {'example': 1}, {'example': 'bad'}, {'example': {'unexpected': ['kept'], '_derived': 'rm'}}):
        call('hydrate_finding', row, None, meta)
    for value in (None, [], 1, 'bad'):
        call('hydrate_finding', value)
        call('hydrate_finding', row, value)
        call('hydrate_finding', row, {}, {'example': {'_derived': 'm'}}, m.CHECK_META_ENCODING, value)
    call('hydrate_finding', row)
    call('hydrate_finding', row, {}, {})
    call('hydrate_finding', dict(row, frameworks=['explicit']), {'example': ['A']}, {'example': defaults})
    for status in ('UNKNOWN', 'DENIED', 'MANUAL', 'EMPTY', 'PASS', 'FAIL', None, 1):
        for evidence in (None, [], 'bad', {}, {'exposure_kind': 'external_share'}, {'external_scope_ids': ['account']},
                         {'data_exposure': True}, {'data_exposure': True, 'source': {'resource_type': 'rds_snapshot'}},
                         {'data_exposure': True, 'source': {'resource_type': 'rds_cluster_snapshot'}},
                         {'data_exposure': True, 'source': []}, {'exposure_kind': 'control_plane'}):
            call('hydrate_finding', {'check_id': 'analysis.internet_exposure', 'status': status, 'evidence': evidence},
                 None, {'analysis.internet_exposure': {'remediation': 'archived'}})
    for value in ([], ['A', 'B'], ('tuple',), 'string', {'key': True}, None, 1):
        call('finding_frameworks', {'check_id': 'example', 'frameworks': value}, {'example': ['default']})
        call('finding_frameworks', row, {'example': value})
    for labels in (None, {}, [], 1, 'bad'):
        call('finding_frameworks', row, labels)
    labels = ['A']; result = m.finding_frameworks(row, {'example': labels}); result.append('B')
    explicit = {'frameworks': ['A']}; result = m.finding_frameworks(explicit, {}); result.append('B')
    out.append({'framework_default_copy': labels == ['A'], 'framework_explicit_copy': explicit == {'frameworks': ['A']}})
elif mode == 'catalog':
    from peaso.privesc import versioned_catalog as vc
    from peaso.privesc.effective_permissions.principal_evidence import BULK_CONTRACT
    base = dict(vc.current_binding(), tenant_id='tenant-a')
    legacy_ids = json.loads(vc.LEGACY_DELTA.read_text())['legacy_ids']
    prior, _ = vc._verified_prior()
    from peaso import privesc
    current_ids = {entry['id'] for entry in privesc.catalog()['entries']}
    ids = sorted(set(legacy_ids) | set(prior) | set(BULK_CONTRACT) | current_ids | {'admin-equivalent', 'unknown-technique'})
    bindings = [('current', base, 'tenant-a')]
    for label, manifest, tree in (
        ('prior-current', vc.PRIOR_CURRENT_MANIFEST, vc.PRIOR_CURRENT_TREE),
        ('prior-disclosure', vc.PRIOR_DISCLOSURE_MANIFEST, vc.PRIOR_DISCLOSURE_TREE),
        ('bounded', vc.BOUNDED_MANIFEST, vc.BOUNDED_TREE),
        ('prior-bounded', vc.PRIOR_BOUNDED_MANIFEST, vc.PRIOR_BOUNDED_TREE),
        ('v4', vc.V4_MANIFEST, vc.V4_EFFECTIVE_TREE)):
        bindings.append((label, dict(base, manifest_sha256=manifest, effective_tree_sha256=tree), 'tenant-a'))
    bindings += [('legacy', dict(base, manifest_sha256=vc.LEGACY_MANIFEST, source_revision=vc.LEGACY_REVISION), 'tenant-a'),
                 ('unversioned', None, 'tenant-a'), ('foreign-tenant', base, 'tenant-b'),
                 ('missing-tenant', vc.current_binding(), 'tenant-a'), ('invalid', {}, 'tenant-a'),
                 ('unknown-manifest', dict(base, manifest_sha256='untrusted'), 'tenant-a'),
                 ('invalid-type', [], 'tenant-a'), ('invalid-schema', dict(base, schema='untrusted'), 'tenant-a')]
    for label, binding, tenant in bindings:
        value = m.privesc_technique_details(ids, catalog_binding=binding, tenant_id=tenant)
        payload = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
        out.append({'binding': label, 'digest': hashlib.sha256(payload).hexdigest(),
                    'known': sum(not r.get('unknown') for r in value.values()),
                    'statuses': sorted({r['catalog_lookup_status'] for r in value.values()}),
                    'admin': value['admin-equivalent'], 'unknown': value['unknown-technique']})
    current, _ = vc.lookup_entries(ids, base, tenant_id='tenant-a')
    for ident in sorted(current):
        detail = m.privesc_technique_details([ident], catalog_binding=base, tenant_id='tenant-a')[ident]
        before = copy.deepcopy(detail)
        # Requirements and conditions are deep copies; other list fields are shallow copies.
        def mutate_nested(value):
            if isinstance(value, dict):
                for child in list(value.values()):
                    mutate_nested(child)
                value['changed'] = []
            elif isinstance(value, list):
                for child in list(value):
                    mutate_nested(child)
                value.append('changed')
        mutate_nested(detail['requires'])
        mutate_nested(detail['conditions'])
        for field in ('requires', 'required_permissions', 'conditions', 'blockers', 'references'):
            detail[field].update({'changed': []}) if isinstance(detail[field], dict) else detail[field].append('changed')
        fresh = m.privesc_technique_details([ident], catalog_binding=base, tenant_id='tenant-a')[ident]
        assert fresh == before, ident
    admin = m.privesc_technique_details(['admin-equivalent'])
    admin['admin-equivalent']['required_permissions']['all_of'].append('changed')
    assert m.privesc_technique_details(['admin-equivalent'])['admin-equivalent']['required_permissions']['all_of'] == ['administrator-equivalent grant on the scope']
    out.append({'defensive_copy_entries_checked': len(current)})
    # Leaf labels include provider-specific grant descriptions and recursive groups.
    requirements = [None, 'permission', {'action': 'iam:PassRole', 'resource': 'arn:role'},
        {'data_action': 'read', 'scope': 'scope'}, {'entra_permission': 'Directory.ReadWrite.All'},
        {'graph_app_permission': 'AppRoleAssignment.ReadWrite.All'}, {'entra_role': 'Role'},
        {'entra_pim_eligible_role': 'Eligible'}, {'entra_tenant_setting': 'Setting'},
        {'verb': 'create', 'resource': 'pods', 'subresource': 'exec', 'api_group': 'core', 'namespace': 'ns'},
        {'entra_owner_of': 'application'}, {'z': 1, 'a': 2}, {'action': 'read', 'resource': '*'}]
    for requirement in requirements:
        call('_permission_text', requirement)
    for requires in ({'all_of': [{'action': 'a'}, {'any_of': [{'action': 'b'}, [{'action': 'c'}, {'action': 'd'}]]}]},
                     {'any_of': [{'all_of': [{'action': 'a'}, {'any_of': [{'action': 'b'}, {'action': 'c'}]}]}]},
                     {'all_of': [{'any_of': [{'action': str(i)} for i in range(100)]},
                                 {'any_of': [{'action': str(i)} for i in range(100)]}]}):
        call('_required_permissions', requires)
    assert out[-1]['result']['alternatives'] is None
    call('privesc_technique_details', ['unknown-technique', 'unknown-technique'], catalog_binding={})
    for invalid in (None, 1, [None], [[]], {}, 'bad'):
        call('privesc_technique_details', invalid, catalog_binding={})
elif mode == 'endpoint':
    import os, tempfile
    os.environ.update(AWS_EC2_METADATA_DISABLED='true', PEASO_STORAGE='sqlite')
    os.environ.pop('PEASO_WORKFLOW_ARN', None)
    import socket
    def offline(*args, **kwargs):
        raise AssertionError('Outbound network forbidden in principal fixture')
    socket.create_connection = socket.getaddrinfo = socket.socket.connect = offline
    from fastapi import HTTPException
    from mangum import Mangum
    from peaso.auth import Identity
    from peaso.server.app import create_app
    from peaso.server.config import Settings
    from peaso.storage import StoreError
    from peaso.privesc import catalog
    from peaso.privesc.versioned_catalog import current_binding
    technique = next(e['id'] for e in catalog()['entries'] if e.get('provider') == 'aws' and e.get('requires'))
    binding = dict(current_binding(), tenant_id='alice')
    grant = {'permission': 'archived:Grant', 'grant': {'policy_name': 'archived-only',
             'statement_document': {'Effect': 'Allow', 'Action': ['archived:Grant'], 'Resource': ['*']}}}
    reference = {'policy_name': 'archived-only'}
    runtime = {'id': technique, 'granting_permissions': [grant], 'evidence_refs': [reference],
               'conditions': ['recorded condition'], 'confidence': 'conditional', 'severity': 'high'}
    graph = {'nodes': [{'id': 'principal-a', 'kind': 'principal', 'type': 'aws_user'},
                       {'id': 'target', 'kind': 'entity', 'type': 'aws_account_admin'}],
             'edges': [{'source': 'principal-a', 'target': 'target', 'confidence': 'conditional',
                        'techniques': [technique], 'technique_details': [runtime], 'evidence_refs': [reference]}]}
    finding = {'id': 'finding-a', 'check_id': 'privesc', 'provider': 'aws', 'resource_id': 'principal-a',
               'scope': '111111111111', 'status': 'FAIL', 'evidence': {}, 'category': 'privesc'}
    bundle = {'graphs': {'privesc': graph}, 'findings': [finding], 'privesc_catalog': binding,
              'summary': {'privesc_catalog': binding}, 'check_frameworks': {'privesc': ['Archived framework']},
              'check_meta': {'privesc': {'title': 'Archived title', 'description': 'Archived description',
                            'service': 'iam', 'category': 'privesc', 'severity': 'high', '_derived': 'rm'}},
              'check_meta_encoding': m.CHECK_META_ENCODING,
              'remediation_templates': {'privesc': {'summary': 'Archived remediation'}}}
    class Users:
        def authenticate(self, header):
            if header in ('Bearer alice', 'Bearer bob'):
                return Identity(header.split()[1])
            raise HTTPException(401, 'Invalid authentication')
    class Store:
        def job(self, tenant, ident):
            if tenant != 'alice' or ident != 'scan-a':
                raise StoreError(404, 'Scan not found')
            return {'id': ident, 'status': 'completed', 'report': 'manifest'}
    class Artifacts:
        def get(self, tenant, reference):
            assert tenant == 'alice' and reference == 'manifest'
            return copy.deepcopy(bundle)
    with tempfile.TemporaryDirectory(prefix='projection-principal-') as temporary:
        root = Path(temporary)
        app = create_app(Settings(state_dir=root/'state', identity_dir=root/'identity', auth_mode='cognito'),
                         store=Store(), artifacts=Artifacts(), authenticator=Users())
        handler = Mangum(app, lifespan='off')
        baseline_analysis = {name for name in sys.modules if name == 'peaso.analysis' or name.startswith('peaso.analysis.')}
        path = '/api/scans/scan-a/privesc/principals/principal-a'
        def invoke(tenant='alice'):
            event = {'version': '2.0', 'routeKey': 'GET ' + path, 'rawPath': path, 'rawQueryString': '',
                'headers': {'host': '127.0.0.1', 'authorization': 'Bearer ' + tenant},
                'requestContext': {'stage': '$default', 'domainName': '127.0.0.1', 'requestId': 'projection-principal',
                    'http': {'method': 'GET', 'path': path, 'protocol': 'HTTP/1.1', 'sourceIp': '127.0.0.1', 'userAgent': 'test'}},
                'isBase64Encoded': False}
            return handler(event, object())
        for label, candidate, expected in [('current', binding, 'exact_strict_privesc'),
                ('foreign-binding', dict(binding, tenant_id='bob'), 'tenant_binding_mismatch'),
                ('missing-binding', None, 'invalid_catalog_binding')]:
            if candidate is None:
                bundle.pop('privesc_catalog', None)
            else:
                bundle['privesc_catalog'] = candidate
            request_started = time.perf_counter()
            response = invoke()
            request_seconds = time.perf_counter() - request_started
            assert response['statusCode'] == 200, response
            card = json.loads(response['body'])
            assert card['catalog_lookup']['status'] == expected, card
            detail = card['outgoing'][0]['technique_details'][0]
            assert detail['granting_permissions'] == [grant]
            assert detail['evidence'] == [reference]
            assert detail['evaluated_conditions'] == ['recorded condition']
            assert detail['confidence'] == detail['edge_confidence'] == 'conditional'
            row = card['findings'][0]
            assert row['title'] == 'Archived title' and row['description'] == row['rationale'] == 'Archived description'
            assert row['remediation'] == 'Archived remediation' and row['frameworks'] == ['Archived framework']
            if label == 'current':
                assert detail['required_permissions']['leaves'] and detail['summary']
            else:
                assert detail['unknown'] is True and 'summary' not in detail
            out.append({'endpoint_binding': label, 'status': response['statusCode'], 'catalog_status': expected,
                        'request_seconds': request_seconds})
        assert graph['edges'][0]['technique_details'][0] == runtime
        assert invoke('bob')['statusCode'] == 404
        # App service-label imports are accepted independently of this helper.
        # Standalone helper probes still require zero analysis imports.
        analysis_added = sorted({name for name in sys.modules if name == 'peaso.analysis' or name.startswith('peaso.analysis.')} - baseline_analysis)
        out.append({'cross_tenant_http_status': 404, 'request_added_analysis_modules': analysis_added,
                    'fresh_probe_seconds': time.perf_counter() - probe_started})
else:
    raise AssertionError(mode)
if sys.argv[1] != 'peaso.engine':
    assert not [name for name in sys.modules if name == 'peaso.engine' or name == 'peaso.checks'
                or name.startswith('peaso.checks.') or (mode != 'endpoint' and
                    (name == 'peaso.analysis' or name.startswith('peaso.analysis.')))]
print(json.dumps(out, sort_keys=True))
'''


def run_probe(module, mode):
    result = subprocess.run([sys.executable, '-c', PROBE, module, mode], cwd=ROOT,
                            text=True, capture_output=True, timeout=90)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize('mode', ['hydration', 'catalog'])
def test_real_engine_fresh_process_parity(mode):
    expected = run_probe('peaso.engine', mode)
    actual = run_probe(HELPER, mode)
    assert actual == expected
    if mode == 'catalog':
        current = next(row for row in actual if row.get('binding') == 'current')
        assert current['known'] > 600
        assert current['statuses'] == ['exact_strict_privesc']
        for label, status in [('foreign-tenant', 'tenant_binding_mismatch'),
                              ('missing-tenant', 'tenant_binding_mismatch'),
                              ('invalid', 'invalid_catalog_binding'),
                              ('unknown-manifest', 'unknown_catalog_manifest')]:
            row = next(row for row in actual if row.get('binding') == label)
            assert row['known'] == 0 and row['statuses'] == [status]


def test_principal_inspector_hosted_route_uses_archived_fields_and_tenant_catalog():
    result = run_probe(HELPER, 'endpoint')
    assert len(result) == 4
    print(json.dumps({'principal_inspector_evidence': result}, sort_keys=True))
