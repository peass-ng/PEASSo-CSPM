"""Normal-package offline Developer Connect producer -> consumer fixtures."""
import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

from peaso.collectors import gcp_developerconnect_file_native_20261021 as source
from peaso.checks import gcp_developerconnect_file_secret_review_20261021 as consumer

ROOT = Path(__file__).resolve().parents[1]
SCOPE = 'projects/example-project'
LINK = SCOPE+'/locations/us-central1/connections/connection-one/gitRepositoryLinks/link-one'
UID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
COMMIT = 'a'*40
PATH = 'config/app.txt'
TOKEN = 'synthetic-offline-read-token'


def fixture(provider='github', secret=False):
    data = b'TESTSECRET example' if secret else b'ordinary text only'
    uri = {'github': 'https://github.com/example-org/example-repo.git',
           'gitlab': 'https://gitlab.com/example-org/example-repo.git',
           'bitbucket': 'https://bitbucket.org/example-org/example-repo.git'}[provider]
    target = {'link_name': LINK, 'link_uid': UID, 'clone_uri': uri, 'provider': provider,
              'commit_sha': COMMIT, 'path': PATH, 'blob_sha': source.git_blob_sha(data)}
    link = {'name': LINK, 'uid': UID, 'cloneUri': uri, 'etag': 'etag-one', 'reconciling': False}
    project = {'name': 'projects/123456789', 'projectId': 'example-project', 'state': 'ACTIVE'}
    expiry = (datetime.now(timezone.utc)+timedelta(minutes=20)).isoformat()
    token = {'token': TOKEN, 'expirationTime': expiry, 'gitUsername': 'x-access-token'}
    commit = {'sha' if provider == 'github' else 'id' if provider == 'gitlab' else 'hash': COMMIT}
    if provider == 'github':
        file = {'type': 'file', 'path': PATH, 'sha': target['blob_sha'], 'encoding': 'base64',
                'content': base64.b64encode(data).decode(), 'size': len(data)}
    elif provider == 'gitlab':
        file = {'file_path': PATH, 'ref': COMMIT, 'blob_id': target['blob_sha'], 'encoding': 'base64',
                'content': base64.b64encode(data).decode(), 'size': len(data)}
    else: file = data
    return target, link, project, token, commit, file


class Response:
    def __init__(self, url, payload, *, status=200, final=None, length=None, content_type='application/json'):
        self.url = final or url
        self.status_code = status
        self.history = []
        self.headers = {'Content-Length': str(len(payload) if length is None else length), 'Content-Type': content_type}
        self.payload = payload
        self.closed = False
    def iter_content(self, chunk_size):
        for i in range(0, len(self.payload), chunk_size): yield self.payload[i:i+chunk_size]
    def close(self): self.closed = True


class FakeSession:
    def __init__(self, target, link, project, token, commit, file, *, cloud, change=None):
        self.target, self.link, self.project, self.token, self.commit, self.file = target, link, project, token, commit, file
        self.cloud, self.change, self.calls, self.closed = cloud, change or {}, [], False
        self.cookies = SimpleNamespace(clear=lambda: None)
    def request(self, method, url, **kw):
        import requests
        assert kw['allow_redirects'] is False and kw['stream'] is True
        expected = requests.Request(method, url, params=kw.get('params')).prepare().url
        self.calls.append((method, url))
        headers = kw['headers']
        if self.cloud:
            assert headers['Authorization'] == 'Bearer cloud-offline-token'
            if url.endswith(':fetchReadToken'): body = self.token
            elif 'cloudresourcemanager' in url: body = self.project
            else:
                body = dict(self.link)
                if self.change.get('drift') and sum('/gitRepositoryLinks/' in x[1] for x in self.calls) > 1:
                    body['etag'] = 'etag-two'
            payload = json.dumps(body, separators=(',', ':')).encode()
        else:
            assert 'cloud-offline-token' not in repr(headers)
            assert TOKEN in repr(headers)
            if '/commit/' in url or '/commits/' in url: body = self.commit
            elif kw.get('params') == {'format':'meta'}:
                body = {'type':'commit_file','path':PATH,'size':len(self.file),'attributes':[]}
            else: body = self.file
            payload = body if type(body) is bytes else json.dumps(body, separators=(',', ':')).encode()
        status = 403 if self.change.get('denied') and self.change['denied'] in url else 200
        final = 'https://foreign.invalid/steal' if self.change.get('foreign') and self.change['foreign'] in url else None
        length = len(payload)+1 if self.change.get('truncated') and self.change['truncated'] in url else None
        return Response(expected, payload, status=status, final=final, length=length,
                        content_type='text/plain' if type(body) is bytes else 'application/json')
    def close(self): self.closed = True


class Transport:
    def __init__(self):
        self.lock = threading.RLock(); self.calls = 0; self.max_calls = 28; self.timeout = 10; self.evidence = []
        self.credentials = SimpleNamespace(headers=lambda: {'Authorization': 'Bearer cloud-offline-token'})
        self.cancel_after = None
    def check_cancelled(self):
        if self.cancel_after is not None and self.calls >= self.cancel_after: raise RuntimeError('cancelled')


def fake_engine(payload, path, timeout):
    return [('TESTSECRET', 'offline', 1)] if b'TESTSECRET' in payload else []


def collect_case(monkeypatch, provider='github', secret=False, change=None, edit=None):
    from peaso import secret_scanning
    monkeypatch.setattr(secret_scanning, '_scan_kingfisher', fake_engine)
    monkeypatch.setattr(secret_scanning, '_scan_trufflehog', fake_engine)
    target, link, project, token, commit, file = fixture(provider, secret)
    if edit: edit(target, link, project, token, commit, file)
    cloud = FakeSession(target, link, project, token, commit, file, cloud=True, change=change)
    remote = FakeSession(target, link, project, token, commit, file, cloud=False, change=change)
    transport = Transport()
    result = source.collect_native(transport, scope=SCOPE, selectors=[target], enabled=True, cloud_session=cloud, remote_session=remote)
    assert cloud.closed and remote.closed
    assert TOKEN not in repr(result) and 'cloud-offline-token' not in repr(result)
    return result, transport, cloud, remote


def view(result):
    row = result['rows'][0]
    identity = row['resource_id']; ids = row['source_requests']
    item = {'name': identity, '_resource_id': identity, 'native_id': identity,
        source.MARKER: {'schema': source.SCHEMA, 'scope': SCOPE, 'row': row, 'source_requests': ids},
        '_provenance': {'scope': SCOPE, 'source_requests': ids}}
    index = {'context': {'provider': 'gcp', 'scope': SCOPE,
        'metadata': {source.OPTION: [row['target']], 'source_requests': result['source_requests']}},
        'collections': {source.KIND: [{'scope': SCOPE, 'items': [item]}]}}
    return item,index


def evaluate(result):
    return consumer.evaluate(*view(result))


@pytest.mark.parametrize('provider', ['github','gitlab','bitbucket'])
@pytest.mark.parametrize('secret,expected', [(True,'FAIL'),(False,'PASS')])
def test_selected_native_provider_bytes(monkeypatch, provider, secret, expected):
    result, transport, cloud, remote = collect_case(monkeypatch, provider, secret)
    assert result['status'] == expected
    status,evidence = evaluate(result)
    assert status == expected,evidence
    assert len(cloud.calls) == 5 and len(remote.calls) == (3 if provider == 'bitbucket' else 2)
    assert 'TESTSECRET' not in repr(result) and 'TESTSECRET' not in repr(evidence)
    if secret:
        leaks = evidence['secret_leaks']
        assert len(leaks) == 1 and {d['engine'] for d in leaks[0]['detectors']} == {'kingfisher','trufflehog'}
        assert len(leaks[0]['fingerprint']) == 64


@pytest.mark.parametrize('change', [
    {'drift': True}, {'denied': 'fetchReadToken'}, {'denied': '/contents/'}, {'foreign': '/contents/'},
    {'truncated': '/contents/'}, {'foreign': 'developerconnect.googleapis.com'}, {'denied': 'developerconnect.googleapis.com'},
])
def test_denied_drift_foreign_truncated(monkeypatch, change):
    result, _, _, _ = collect_case(monkeypatch, change=change)
    assert result['status'] == 'UNKNOWN'
    assert evaluate(result)[0] == 'UNKNOWN'


def test_wrong_project_link_commit_blob(monkeypatch):
    cases = [lambda t,l,p,k,c,f: p.update(projectId='foreign'),
             lambda t,l,p,k,c,f: l.update(uid='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'),
             lambda t,l,p,k,c,f: c.update(sha='b'*40),
             lambda t,l,p,k,c,f: f.update(sha='b'*40)]
    for edit in cases:
        result,_,_,_ = collect_case(monkeypatch, edit=edit)
        assert result['status'] == 'UNKNOWN'
        assert evaluate(result)[0] == 'UNKNOWN'


def test_default_off_and_invalid_selector_zero_io():
    target,*_ = fixture()
    t = Transport()
    assert source.collect_native(t, scope=SCOPE, selectors=[target], enabled=False)['status'] == 'UNKNOWN'
    assert t.calls == 0
    for field,value in [('link_name','projects/foreign/locations/us-central1/connections/c/gitRepositoryLinks/l'),
                        ('clone_uri','https://evil.example.org/o/r.git'), ('commit_sha','main with spaces'),
                        ('path','../secret'), ('path','safe/%2e%2e/secret')]:
        changed = dict(target,**{field:value})
        with pytest.raises(ValueError): source.selections([changed],SCOPE)
    assert t.calls == 0


def test_cancel_cleanup(monkeypatch):
    target,link,project,token,commit,file = fixture()
    cloud = FakeSession(target,link,project,token,commit,file,cloud=True)
    remote = FakeSession(target,link,project,token,commit,file,cloud=False)
    transport=Transport();transport.cancel_after=2
    result=source.collect_native(transport,scope=SCOPE,selectors=[target],enabled=True,cloud_session=cloud,remote_session=remote)
    assert result['status']=='UNKNOWN' and not remote.calls and cloud.closed and remote.closed


def test_unsupported_enterprise_and_branch_unknown_without_authentication():
    target,*_ = fixture()
    enterprise = dict(target, provider='enterprise', clone_uri='https://git.example.org/team/repo.git')
    branch = dict(target, commit_sha='main')
    for selected in (enterprise, branch):
        t = Transport()
        result = source.collect_native(t,scope=SCOPE,selectors=[selected],enabled=True)
        assert result['status']=='UNKNOWN' and t.calls==0 and evaluate(result)[0]=='UNKNOWN'


def test_partial_positive_retained_when_one_detector_unavailable(monkeypatch):
    from peaso import secret_scanning
    secret_scanning._RESULTS.clear()
    monkeypatch.setattr(secret_scanning, '_scan_kingfisher', fake_engine)
    def unavailable(payload,path,timeout): raise RuntimeError('offline detector unavailable')
    monkeypatch.setattr(secret_scanning, '_scan_trufflehog', unavailable)
    target,link,project,token,commit,file = fixture(secret=True)
    cloud=FakeSession(target,link,project,token,commit,file,cloud=True)
    remote=FakeSession(target,link,project,token,commit,file,cloud=False)
    result=source.collect_native(Transport(),scope=SCOPE,selectors=[target],enabled=True,cloud_session=cloud,remote_session=remote)
    assert result['status']=='FAIL' and not result['complete']
    assert evaluate(result)[0]=='FAIL'


def test_token_without_short_expiry_stops_before_remote(monkeypatch):
    def edit(target,link,project,token,commit,file): token['expirationTime']=''
    result,transport,cloud,remote=collect_case(monkeypatch,edit=edit)
    assert result['status']=='UNKNOWN' and not remote.calls
    assert all('token' not in repr(r).lower() or r['operation']=='developerconnect_selected_token' for r in result['source_requests'])


def test_four_target_bound_before_auth():
    target,*_ = fixture()
    four = [dict(target,path=f'config/file-{i}.txt') for i in range(4)]
    assert len(source.selections(four,SCOPE)) == 4
    with pytest.raises(ValueError): source.selections(four+[dict(target,path='config/file-4.txt')],SCOPE)
    assert source.MAX_CALLS == 32
