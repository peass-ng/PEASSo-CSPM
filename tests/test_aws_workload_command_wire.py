"""Selected command definitions read through real botocore, urllib3 and TLS.

botocore's Stubber answers before the transport, so it cannot show how the
bounded reader handles a real HTTP response. Here every request leaves the SDK
over TLS to a local server that answers like ECS and STS: a production-shaped
task definition (tens of KB, environment and secrets, no entryPoint or command)
with a Content-Length body or a chunked one.
"""
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import ssl
import threading

import boto3
import pytest

from peaso import secret_scanning as scanning
from peaso.checks import aws_workload_command_source_20261020 as consumer
from peaso.collectors import aws_workload_command_source_20261020 as source

ACCOUNT, REGION = '123456789012', 'us-east-1'
SCOPE = ACCOUNT + '/' + REGION
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
STS_BODY = (
    '<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
    '<GetCallerIdentityResult><Arn>arn:aws:iam::%s:user/local-review</Arn>'
    '<UserId>AIDALOCALREVIEW</UserId><Account>%s</Account></GetCallerIdentityResult>'
    '<ResponseMetadata><RequestId>11111111-1111-4111-8111-111111111111</RequestId>'
    '</ResponseMetadata></GetCallerIdentityResponse>' % (ACCOUNT, ACCOUNT)).encode()


def target(name, revision=7):
    return {'scope': SCOPE, 'service': 'ecs',
            'definition_arn': f'arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/{name}:{revision}'}


def task_definition(selected, command=None):
    """Shape of a real service definition: no entryPoint/command, large env."""
    _, _, _, family, revision = source.parse(selected)
    container = {
        'name': family, 'image': f'{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/{family}:sha-0123abcd',
        'cpu': 0, 'essential': True, 'portMappings': [{'containerPort': 8080, 'hostPort': 8080, 'protocol': 'tcp'}],
        'environment': [{'name': f'SETTING_{i}', 'value': 'v' * 900} for i in range(40)],
        'secrets': [{'name': f'SECRET_{i}', 'valueFrom': f'arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:s{i}'}
                    for i in range(9)],
        'mountPoints': [], 'volumesFrom': [], 'systemControls': [],
        'logConfiguration': {'logDriver': 'awslogs', 'options': {'awslogs-group': '/svc/' + family}}}
    if command is not None:
        container['command'] = command
    return {'taskDefinition': {
        'taskDefinitionArn': selected['definition_arn'], 'family': family, 'revision': revision,
        'status': 'ACTIVE', 'containerDefinitions': [container], 'networkMode': 'awsvpc',
        'requiresAttributes': [{'name': f'com.amazonaws.ecs.capability.attr-{i}'} for i in range(11)],
        'compatibilities': ['EC2', 'FARGATE'], 'cpu': '512', 'memory': '1024',
        'registeredAt': 1795000000.0, 'registeredBy': f'arn:aws:sts::{ACCOUNT}:assumed-role/deploy/ci'}}


def certificate(directory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'local aws stub')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(f'*.{REGION}.amazonaws.com'),
                                                        x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = directory / 'cert.pem', directory / 'key.pem'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cert_path, key_path


@pytest.fixture
def aws_stub(tmp_path, monkeypatch):
    """A local TLS endpoint for sts/ecs.<region>.amazonaws.com; nothing leaves the host."""
    cert_path, key_path = certificate(tmp_path)
    state = {'framing': 'length', 'definitions': {}, 'hosts': [], 'failures': {}}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *args):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers['Content-Length']))
            host = self.headers['Host'].split(':')[0]
            state['hosts'].append(host)
            status = 200
            if host.startswith('sts.'):
                payload, kind = STS_BODY, 'text/xml'
            else:
                arn = json.loads(body)['taskDefinition']
                failures = state['failures'].get(arn, [])
                if failures:
                    status, code = failures.pop(0)
                    payload = json.dumps({'__type': code, 'message': TOKEN}).encode()
                else:
                    payload = json.dumps(state['definitions'][arn]).encode()
                kind = 'application/x-amz-json-1.1'
            self.send_response(status)
            self.send_header('Content-Type', kind)
            self.send_header('x-amzn-RequestId', '22222222-2222-4222-8222-222222222222')
            if state['framing'] == 'chunked':
                self.send_header('Transfer-Encoding', 'chunked')
                self.end_headers()
                for offset in range(0, len(payload), 4093):
                    piece = payload[offset:offset + 4093]
                    self.wfile.write(b'%x\r\n%s\r\n' % (len(piece), piece))
                self.wfile.write(b'0\r\n\r\n')
            else:
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]

    import botocore.httpsession
    import urllib3.util.connection as connection
    original = connection.create_connection

    def route(address, *args, **kwargs):
        host, _ = address
        assert host.endswith('.amazonaws.com'), host
        return original(('127.0.0.1', port), *args, **kwargs)

    monkeypatch.setattr(connection, 'create_connection', route)
    # Trust only the stub's certificate; hostname verification stays on.
    monkeypatch.setattr(botocore.httpsession, 'get_cert_path', lambda verify: str(cert_path))
    monkeypatch.setenv('AWS_EC2_METADATA_DISABLED', 'true')
    monkeypatch.setenv('AWS_CONFIG_FILE', str(tmp_path / 'absent-config'))
    monkeypatch.setenv('AWS_SHARED_CREDENTIALS_FILE', str(tmp_path / 'absent-credentials'))
    scanning._RESULTS.clear()
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        scanning._RESULTS.clear()


def collect(targets):
    plan = source.prepare({'content_secret_scans': True, 'check_id': source.CHECK,
                           'content_secret_scan_grants': [source.GRANT], source.OPTION: targets}, [SCOPE])
    def session(scope):
        return boto3.Session(aws_access_key_id='offline-key', aws_secret_access_key='offline-secret',
                             region_name=REGION)
    return source.collect(plan, session)


@pytest.mark.parametrize('framing', ['length', 'chunked'])
def test_selected_service_definitions_are_read_and_assessed_over_the_wire(aws_stub, framing):
    aws_stub['framing'] = framing
    targets = [target('svc-web'), target('svc-api', 12), target('svc-migrate', 3)]
    for t in targets[:2]:
        aws_stub['definitions'][t['definition_arn']] = task_definition(t)
    migrate = targets[2]
    aws_stub['definitions'][migrate['definition_arn']] = task_definition(migrate, ['./migrate', '--token', TOKEN])
    assert all(len(json.dumps(d)) > 30000 for d in aws_stub['definitions'].values())

    result = collect(targets)

    assert aws_stub['hosts'] == ['sts.us-east-1.amazonaws.com'] + ['ecs.us-east-1.amazonaws.com'] * 3
    assert [row['native_bound'] for row in result['items']] == [True, True, True]
    assert [consumer.evaluate(row, result)[0] for row in result['items']] == ['PASS', 'PASS', 'FAIL']
    status, evidence = consumer.evaluate_collection(result)
    assert status == 'FAIL' and evidence['complete'] is True
