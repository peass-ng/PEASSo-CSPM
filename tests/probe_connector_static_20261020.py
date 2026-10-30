"""Fresh real hosted Mangum POST/PATCH proof with checks imports forbidden."""
import importlib.abc
import json
import os
from pathlib import Path
import resource
import socket
import sys
import tempfile
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
started = time.perf_counter()
os.environ.update(AWS_EC2_METADATA_DISABLED='true', AWS_CONFIG_FILE='/nonexistent/offline-connector-proof',
                  AWS_SHARED_CREDENTIALS_FILE='/nonexistent/offline-connector-proof', PEASO_STORAGE='sqlite')
os.environ.pop('PEASO_WORKFLOW_ARN', None)


blocked_imports = []


class BlockNative(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'peaso.engine' or fullname == 'peaso.checks' or fullname.startswith('peaso.checks.'):
            blocked_imports.append((fullname, [(f.filename, f.name, f.lineno) for f in traceback.extract_stack()[-36:]]))
            raise AssertionError('Connector runtime attempted native import: ' + fullname)


sys.meta_path.insert(0, BlockNative())
network_attempts = []


def forbidden(*args, **kwargs):
    network_attempts.append(True)
    raise AssertionError('Outbound network/DNS forbidden in offline connector proof')


for owner, names in ((socket, ('create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex')),
                     (socket.socket, ('connect', 'connect_ex', 'sendto'))):
    for name in names:
        setattr(owner, name, forbidden)

from fastapi import HTTPException
from mangum import Mangum
from peaso.auth import Identity
from peaso.server.app import create_app
from peaso.server.config import Settings
from peaso.server.native_policy_validation_static_20261020 import module_ids
from peaso.server import native_policy_validation as review_validation


class OfflineIdentity:
    def authenticate(self, authorization):
        if authorization != 'Bearer alice':
            raise HTTPException(401, 'Invalid authentication')
        return Identity('alice', True)


scope = '/subscriptions/customer'
modules = ('compliance_new_sw16', 'compliance_new_sw17', 'compliance_new_sw19', 'compliance_new_sw26')
roster = module_ids()


def policy(module, checks):
    if module.endswith('sw17'):
        return {'status': 'collected', 'scope': scope, 'checks': checks}
    if module.endswith('sw16'):
        return {'sw16': checks}
    return {module.rsplit('_', 1)[-1]: {'status': 'collected', 'scope': scope, **checks}}


with tempfile.TemporaryDirectory(prefix='peaso-static-connector-proof-') as temporary:
    directory = Path(temporary)
    app = create_app(Settings(state_dir=directory / 'state', identity_dir=directory / 'identity',
                              auth_mode='cognito', require_connector_access_check=False),
                     authenticator=OfflineIdentity())
    handler = Mangum(app, lifespan='off')

    def invoke(path, method, data):
        event = {'version': '2.0', 'routeKey': method + ' ' + path, 'rawPath': path, 'rawQueryString': '',
            'headers': {'host': '127.0.0.1', 'authorization': 'Bearer alice', 'content-type': 'application/json'},
            'requestContext': {'stage': '$default', 'domainName': '127.0.0.1', 'requestId': 'offline-connector-proof',
                'http': {'method': method, 'path': path, 'protocol': 'HTTP/1.1', 'sourceIp': '127.0.0.1', 'userAgent': 'offline-proof'}},
            'isBase64Encoded': False, 'body': json.dumps(data)}
        return handler(event, object())

    # Saving requires a passing Check access receipt; the cloud access probe
    # itself is outside this proof, so it reports a pass without network.
    from peaso.server import access_check
    access_check.check_access = lambda *args, **kwargs: {'status': 'pass', 'issues': [], 'principals': []}

    def create(body):
        checked = invoke('/api/connectors/check-access', 'POST', body)
        if checked['statusCode'] != 200:
            return checked
        return invoke('/api/connectors', 'POST', {**body, 'check_token': json.loads(checked['body'])['check_token']})

    def edit(connector_id, body, options):
        candidate = {'name': body['name'], 'provider': body['provider'], 'scopes': body.get('scopes', []),
                     'options': options, 'auth': {}, 'connector_id': connector_id}
        checked = invoke('/api/connectors/check-access', 'POST', candidate)
        if checked['statusCode'] != 200:
            return checked
        return invoke('/api/connectors/' + connector_id, 'PATCH',
                      {'options': options, 'check_token': json.loads(checked['body'])['check_token']})

    auth = {'method': 'token', 'arm_token': 'fixture-arm', 'logs_token': 'fixture-logs'}
    counts = {'accepted_post': 0, 'accepted_patch': 0, 'rejected_post': 0, 'rejected_patch': 0}
    # Exactly the owner's prepared real timeout scenario, frozen from inert
    # BINDING literals; the capacity probe is never executed or imported.
    fixture = json.loads(Path(__file__).with_name('connector_owner_fixture_20261020.json').read_text())
    exact_body = fixture['body']
    assert exact_body['provider'] == 'azure' and set(exact_body['options']['compliance_policy']) == {'sw16'}
    owner_map_calls = []
    monitor_id = 5
    sys.monitoring.use_tool_id(monitor_id, 'offline-static-connector-owner')
    sys.monitoring.register_callback(monitor_id, sys.monitoring.events.PY_START,
                                    lambda code, offset: owner_map_calls.append(True))
    sys.monitoring.set_local_events(monitor_id, review_validation._check_review_map.__code__,
                                    sys.monitoring.events.PY_START)
    response = create(exact_body)
    assert response['statusCode'] == 201, (response, blocked_imports)
    cold_seconds = time.perf_counter() - started
    exact_id = json.loads(response['body'])['id']
    assert edit(exact_id, exact_body, exact_body['options'])['statusCode'] == 200
    sys.monitoring.set_local_events(monitor_id, review_validation._check_review_map.__code__, 0)
    sys.monitoring.free_tool_id(monitor_id)
    assert len(owner_map_calls) == 4  # Check access and save, for both POST and PATCH
    for module in modules:
        connector_id = None
        for cid in sorted(roster[module]):
            review = {'status': 'collected', 'scope': scope} if module.endswith('sw16') else {}
            options = {'compliance_policy': policy(module, {cid: review})}
            body = {'name': 'Offline', 'provider': 'azure', 'auth': auth, 'options': options}
            response = create(body)
            assert response['statusCode'] == 201, (module, cid, response, blocked_imports)
            connector_id = json.loads(response['body'])['id']
            counts['accepted_post'] += 1
            response = edit(connector_id, body, options)
            assert response['statusCode'] == 200, (module, cid, response)
            counts['accepted_patch'] += 1
        wrong_ids = sorted(set().union(*roster.values()) - roster[module]) + ['unreviewed.invalid', 'azure.storage.https_only']
        invalid_maps = [{cid: {'status': 'collected', 'scope': scope}} for cid in wrong_ids]
        sample = sorted(roster[module])[0]
        invalid_maps += [{sample: value} for value in (None, False, 0, 1, '', 'review', [], [1])]
        if module.endswith('sw16'):
            invalid_maps += [{sample: value} for value in ({}, {'status': 'collected'}, {'scope': scope},
                              {'status': 'missing', 'scope': scope}, {'status': 'collected', 'scope': '*'},
                              {'status': 'collected', 'scope': '/subscriptions/' + 'x' * 129})]
        for checks in invalid_maps:
            options = {'compliance_policy': policy(module, checks)}
            body = {'name': 'Offline', 'provider': 'azure', 'auth': auth, 'options': options}
            response = create(body)
            assert response['statusCode'] == 422, (module, checks, response)
            assert 'Run Check access' not in response['body'], (module, checks, response)
            counts['rejected_post'] += 1
            response = edit(connector_id, body, options)
            assert response['statusCode'] == 422, (module, checks, response)
            assert 'Run Check access' not in response['body'], (module, checks, response)
            counts['rejected_patch'] += 1
    loaded = [name for name in sys.modules if name == 'peaso.engine' or name.startswith('peaso.checks')]
    analysis_loaded = sorted(name for name in sys.modules if name == 'peaso.analysis' or name.startswith('peaso.analysis.'))
    assert not loaded, loaded
    assert not network_attempts
    print(json.dumps({'counts': counts, 'native_modules_loaded': loaded, 'analysis_modules_loaded': analysis_loaded,
        'exact_owner_fixture': True, 'owner_check_review_map_calls': len(owner_map_calls),
        'network_attempts': len(network_attempts),
        'cold_response_wall_seconds': round(cold_seconds, 4), 'total_wall_seconds': round(time.perf_counter() - started, 4),
        'max_rss_mb': round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024 / 1024, 2),
        'python': sys.version.split()[0], 'auth_mode': 'cognito',
        'limits': 'Local fresh Python/Mangum/FastAPI hosted-mode validation with synthetic identity and SQLite; no AWS timing claims.'}))
