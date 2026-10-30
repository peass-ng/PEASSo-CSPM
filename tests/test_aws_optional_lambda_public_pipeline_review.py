"""Bounded public Lambda ZIP pipeline with real pinned offline detectors; no cloud."""
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
from types import SimpleNamespace
import base64
import io
import json
import zipfile

import boto3
from botocore.stub import Stubber
import pytest

from peaso import engine, secret_scanning
from peaso.collectors import aws, aws_package_content_indicators as packages

ACCOUNT, REGION = '123456789012', 'us-east-1'
SCOPE = ACCOUNT + '/' + REGION
FN = f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:review'
CID = 'aws.review.lambda_function.package_content_secret_indicators'
URL = f'https://awslambda-inert.s3.{REGION}.amazonaws.com/package?X-Amz-Signature=INERT_NO_NETWORK'
# Deliberately synthetic GitHub-shaped canary; never validated with a service.
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
NOW = datetime(2026, 10, 19, 12, tzinfo=timezone.utc)


@pytest.fixture
def public_pipeline(monkeypatch):
    session = boto3.Session(aws_access_key_id='inert', aws_secret_access_key='inert', region_name=REGION)
    original = aws.Requests
    calls, downloads, clients, requests_seen, stub_errors = [], [], {}, [], []
    native = {}

    class Client:
        def __init__(self, service, region):
            self.service = service
            self.sdk = session.client(service, region_name=region)
            self.meta = self.sdk.meta
        def can_paginate(self, operation):
            return self.sdk.can_paginate(operation)
        def get_paginator(self, operation):
            return self.sdk.get_paginator(operation)
        def __getattr__(self, operation):
            def invoke(**arguments):
                calls.append((self.service, operation, deepcopy(arguments)))
                response = native.get((self.service, operation))
                with Stubber(self.sdk) as stub:
                    try:
                        if response is None:
                            stub.add_client_error(operation, 'AccessDeniedException', expected_params=arguments)
                        else:
                            stub.add_response(operation, deepcopy(response), arguments)
                    except Exception as exc:
                        stub_errors.append(type(exc).__name__)
                        raise
                    result = getattr(self.sdk, operation)(**arguments)
                    stub.assert_no_pending_responses()
                    return result
            return invoke

    class Requests(original):
        def __init__(self, options):
            super().__init__(options, sleep=lambda _: None)
            self.observed_at = NOW
            requests_seen.append(self)
        def client(self, selected, service, region):
            if (service, region) not in clients:
                clients[service, region] = Client(service, region)
            return clients[service, region]

    monkeypatch.setattr(aws, 'Requests', Requests)
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'inert'))
    secret_scanning._RESULTS.clear()

    def collect(case):
        content = io.BytesIO()
        with zipfile.ZipFile(content, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('config.py', 'GITHUB_TOKEN="' + TOKEN + '"' if case == 'positive' else 'STAGE="review"')
        payload = content.getvalue()
        if case == 'truncated_zip': payload = payload[:-8]
        row = {'FunctionName': 'review', 'FunctionArn': FN, 'Version': '$LATEST',
               'PackageType': 'Zip', 'Runtime': 'python3.13'}
        native.update({
            ('sts', 'get_caller_identity'): {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/review', 'UserId': 'inert'},
            ('lambda', 'list_functions'): {'Functions': [row]},
            ('lambda', 'get_function_configuration'): {**row, 'State': 'Active'},
            ('lambda', 'get_function'): {'Configuration': {**row, 'CodeSize': len(payload),
                'CodeSha256': base64.b64encode(sha256(payload).digest()).decode()},
                'Code': {'RepositoryType': 'S3', 'Location': URL}},
        })
        if case == 'denied':
            native['lambda', 'get_function'] = None
        elif case == 'hash_mismatch':
            native['lambda', 'get_function']['Configuration']['CodeSha256'] = base64.b64encode(bytes(32)).decode()
        elif case == 'missing_version':
            del native['lambda', 'get_function']['Configuration']['Version']

        class Response:
            status = 200
            headers = {'Content-Length': str(len(payload))}
            def __init__(self): self.source = io.BytesIO(payload)
            def geturl(self): return URL
            def read(self, count): return self.source.read(count)
            def __enter__(self): return self
            def __exit__(self, *args): return None

        def open_memory(url, timeout):
            assert url == URL and 0 < timeout <= 30
            downloads.append(url)
            return Response()
        monkeypatch.setattr(packages, 'build_opener', lambda *args: SimpleNamespace(open=open_memory))
        options = {'regions': [REGION], 'retry_attempts': 1, 'max_workers': 1, 'max_calls': 80}
        if case != 'default_off': options['content_secret_scans'] = True
        selected = 'aws.b.lambda.active_tracing' if case == 'unselected' else CID
        # Actual public planner supplies the internal named-content selection;
        # collect_live dispatches to the unchanged aws.collect implementation.
        snapshot = engine.collect_snapshot({'connector': {'provider': 'aws', 'scopes': [SCOPE], 'options': options}, 'checks': [selected]})
        assert not stub_errors, stub_errors
        assert len(requests_seen) == 1
        requests = requests_seen[0]
        assert requests.content_secret_scan_kinds == (frozenset() if case == 'unselected' else frozenset({'lambda_function'}))
        report = engine.evaluate_snapshot(snapshot, checks=[CID], include_not_applicable=True)
        findings = [row for row in report['findings'] if row['check_id'] == CID]
        assert len(findings) == 1 and not findings[0]['resource_id'].startswith('inventory:'), findings
        cached = [future.result() for future in requests._cache.values() if not future.exception()]
        safe = json.dumps([snapshot, cached, report], default=str)
        assert TOKEN not in safe and URL not in safe and 'INERT_NO_NETWORK' not in safe
        return snapshot, findings[0], calls, downloads

    yield collect
    secret_scanning._RESULTS.clear()


@pytest.mark.parametrize('case,expected', [
    ('positive', 'FAIL'), ('negative', 'PASS'), ('denied', 'UNKNOWN'),
    ('hash_mismatch', 'UNKNOWN'), ('missing_version', 'UNKNOWN'), ('truncated_zip', 'UNKNOWN'),
    ('default_off', 'UNKNOWN'), ('unselected', 'UNKNOWN'),
])
def test_optional_lambda_public_pipeline(public_pipeline, case, expected):
    snapshot, finding, calls, downloads = public_pipeline(case)
    assert finding['status'] == expected, finding
    content_calls = [args for service, operation, args in calls if (service, operation) == ('lambda', 'get_function')]
    if case in {'default_off', 'unselected'}:
        assert not content_calls and not downloads
    else:
        assert content_calls == [{'FunctionName': FN, 'Qualifier': '$LATEST'}]
        assert bool(downloads) is (case not in {'denied', 'missing_version'})
    if case in {'positive', 'negative'}:
        item = next(c['items'][0] for c in snapshot['collections'] if c['type'] == 'lambda_function')
        assert item['PackageContentSource']['PackageSecretIndicators']['NativeResponseComplete'] is True
        if case == 'positive':
            leaks = finding['evidence']['secret_leaks']
            assert finding['evidence']['credential_validation'] == 'not_attempted'
            assert len(leaks) == 1
            assert {d['engine'] for d in leaks[0]['detectors']} == {'kingfisher', 'trufflehog'}
        else:
            assert finding['evidence']['source_complete'] is True
            assert finding['evidence']['secret_leaks'] == []
