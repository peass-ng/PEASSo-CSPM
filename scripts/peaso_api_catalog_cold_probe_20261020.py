"""Offline fresh-process Mangum proof; synthetic identity/SQLite, no hosted claims."""
import importlib.abc
import json
import os
from pathlib import Path
import resource
import socket
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
started = time.perf_counter()
cpu_started = time.process_time()
os.environ.update(AWS_EC2_METADATA_DISABLED='true', AWS_CONFIG_FILE='/nonexistent/offline-api-proof',
                  AWS_SHARED_CREDENTIALS_FILE='/nonexistent/offline-api-proof', PEASO_STORAGE='sqlite')
os.environ.pop('PEASO_WORKFLOW_ARN', None)


class BlockNative(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'peaso.engine' or any(fullname == prefix or fullname.startswith(prefix + '.')
                                             for prefix in ('peaso.checks', 'peaso.analysis')):
            raise AssertionError('API runtime attempted native import: ' + fullname)


sys.meta_path.insert(0, BlockNative())
network_attempts = []

def forbidden(*args, **kwargs):
    network_attempts.append(True)
    raise AssertionError('Outbound network/DNS forbidden in offline API proof')

for owner, names in ((socket, ('create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex')),
                     (socket.socket, ('connect', 'connect_ex', 'sendto'))):
    for name in names:
        setattr(owner, name, forbidden)

from fastapi import HTTPException
from mangum import Mangum
from peaso.auth import Identity
from peaso.server.app import create_app
from peaso.server.config import Settings


class OfflineIdentity:
    def authenticate(self, authorization):
        if authorization not in ('Bearer alice', 'Bearer bob'):
            raise HTTPException(401, 'Invalid authentication')
        return Identity(authorization.split()[1], True)


scenario = sys.argv[1] if len(sys.argv) > 1 else 'full'
with tempfile.TemporaryDirectory(prefix='peaso-materialized-api-proof-') as temporary:
    directory = Path(temporary)
    app = create_app(Settings(state_dir=directory / 'state', identity_dir=directory / 'identity',
                              local_token='offline-api-proof-token-0123456789'), authenticator=OfflineIdentity())
    # Stored exactly as the connector API writes it: scan creation decrypts the connector options.
    connector = app.state.store.add_connector('alice', {'name': 'Offline', 'provider': 'aws'},
                                              app.state.cipher.encrypt({'auth': {}, 'options': {}}))
    handler = Mangum(app, lifespan='off')
    initialized = time.perf_counter() - started

    def invoke(path, query='', method='GET', data=None, token='alice', headers=None):
        event = {'version': '2.0', 'routeKey': method + ' ' + path, 'rawPath': path, 'rawQueryString': query,
            'headers': {'host': '127.0.0.1', **({'authorization': 'Bearer ' + token} if token else {}),
                        **({'content-type': 'application/json'} if data is not None else {}), **(headers or {})},
            'requestContext': {'stage': '$default', 'domainName': '127.0.0.1', 'requestId': 'offline-proof',
                'http': {'method': method, 'path': path, 'protocol': 'HTTP/1.1', 'sourceIp': '127.0.0.1', 'userAgent': 'offline-proof'}},
            'isBase64Encoded': False}
        if data is not None:
            event['body'] = json.dumps(data)
        return handler(event, object())

    routes = {'full': ('/api/catalog', ''), 'summary': ('/api/catalog', 'view=summary'),
              'frameworks': ('/api/catalog/frameworks', ''), 'scans': ('/api/scans', ''),
              'setup': ('/api/me', ''), 'lookups': ('/api/catalog/frameworks', ''),
              'full_max': ('/api/catalog', 'limit=500')}
    if scenario == 'scan_create':
        response = invoke('/api/scans', method='POST', data={'connector_id': connector['id'],
                          'checks': ['aws.ec2.imdsv2'], 'ai_enabled': False})
        assert response['statusCode'] == 201, response
    else:
        response = invoke(*routes[scenario])
        assert response['statusCode'] == 200, response
    cold_wall = time.perf_counter() - started
    cold_cpu = time.process_time() - cpu_started
    body = response.get('body', '')
    envelope_bytes = len(json.dumps(response).encode())
    assert len(body.encode()) <= 4 * 1024 * 1024 and envelope_bytes <= 6 * 1024 * 1024
    maximum_body, maximum_envelope = len(body.encode()), envelope_bytes
    if scenario == 'lookups':
        from peaso.server import materialized_catalog as catalog
        assert catalog.description_for('azure_aks_cluster_10_2_1_1_17_885658f') is not None
        assert catalog.description_for('unreviewed.invalid') is None
        assert 'cis' in catalog.expand_framework_selectors({'cis'})
    if scenario == 'full_max':
        from peaso.server import materialized_catalog as catalog
        expected = [row['id'] for row in catalog._load()['full']['checks']]
        rows, page = [], json.loads(body)
        while True:
            rows.extend(row['id'] for row in page['checks'])
            next_offset = page['pagination']['next_offset']
            if next_offset is None:
                break
            following = invoke('/api/catalog', 'limit=500&offset=' + str(next_offset))
            assert following['statusCode'] == 200
            maximum_body = max(maximum_body, len(following['body'].encode()))
            maximum_envelope = max(maximum_envelope, len(json.dumps(following).encode()))
            page = json.loads(following['body'])
        assert rows == expected
        assert maximum_body <= 4 * 1024 * 1024 and maximum_envelope <= 6 * 1024 * 1024
    if scenario in ('full', 'summary', 'frameworks', 'full_max'):
        path, query = routes[scenario]
        etag = response['headers']['etag']
        assert invoke(path, query, token=None, headers={'if-none-match': etag})['statusCode'] == 401
        assert invoke(path, query, headers={'if-none-match': etag})['statusCode'] == 304
        assert invoke(path, query, token='bob')['headers']['cache-control'] == 'private, no-cache'
    if scenario == 'scan_create':
        for checks in (['unreviewed.invalid'], ['azure.storage.https_only'], ['aws_bedrock_automated_reasoning_policy_attached']):
            assert invoke('/api/scans', method='POST', data={'connector_id': connector['id'],
                          'checks': checks, 'ai_enabled': False})['statusCode'] == 422
        assert invoke('/api/scans', method='POST', token='bob', data={'connector_id': connector['id'],
                      'checks': ['aws.ec2.imdsv2'], 'ai_enabled': False})['statusCode'] == 404
    assert not network_attempts
    loaded = [name for name in sys.modules if name == 'peaso.engine' or name.startswith(('peaso.checks', 'peaso.analysis'))]
    assert not loaded, loaded
    print(json.dumps({'scenario': scenario, 'python': sys.version.split()[0], 'status': response['statusCode'],
        'initialization_wall_seconds': round(initialized, 4), 'cold_response_wall_seconds': round(cold_wall, 4),
        'cold_response_cpu_seconds': round(cold_cpu, 4), 'max_rss_mb': round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024 / 1024, 2),
        'body_bytes': len(body.encode()), 'mangum_envelope_bytes': envelope_bytes,
        'maximum_page_body_bytes': maximum_body, 'maximum_page_envelope_bytes': maximum_envelope, 'native_modules_loaded': loaded,
        'network_attempts': len(network_attempts), 'limits': 'Local cold subprocess with real Mangum/FastAPI and synthetic auth/SQLite; excludes hosted Cognito, DynamoDB, Lambda CPU allocation and gateway latency.'}))
