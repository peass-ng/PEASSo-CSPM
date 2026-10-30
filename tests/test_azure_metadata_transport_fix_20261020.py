"""Registered current SAS/native storage control impact through real transport.

HTTP fixtures are independent native ARM bodies and carry explicit HTTP status;
no registry overlays, CASES or synthetic completeness facts are injected.
"""
import base64
import io
import json
import os
from pathlib import Path
import socket
import time
from urllib.parse import urlsplit

import pytest
from peaso import checks, engine
from peaso.collectors import azure
from peaso.checks import azure_sas_expiry_policy_declaration_proposal_20261020 as sas
from tests.test_azure_storage_native_review_20261020 import NativeHTTP, SUB, SCOPE, ACCOUNT

PRIVATE = 'native-response-text-must-not-escape'
CAPTURES = []


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args, **kwargs): raise AssertionError('Live network/DNS/auth forbidden')
    for name in ('connect','connect_ex','sendto'): monkeypatch.setattr(socket.socket,name,blocked)
    for name in ('create_connection','getaddrinfo','gethostbyname','gethostbyname_ex'): monkeypatch.setattr(socket,name,blocked)
    monkeypatch.setattr(azure,'credential_for',blocked)


@pytest.fixture(scope='session',autouse=True)
def native_receipts():
    yield
    if folder := os.environ.get('AZURE_TRANSPORT_FIX_RECEIPTS'):
        Path(folder).mkdir(parents=True,exist_ok=True)
        Path(folder,'native-captures.json').write_text(json.dumps(CAPTURES,indent=2)+'\n')


def native_capture(monkeypatch, mode='coherent', action='Block'):
    def configure(http):
        http.a['properties']['sasPolicy'] = {'expirationAction':action,'sasExpirationPeriod':'3.00:00:00'}
    http = NativeHTTP('azure.storage.https_only','positive',configure)
    captures = []
    class Opener:
        def open(self, request, timeout):
            response = http.open(request,timeout)
            raw = response.getvalue(); response.close()
            status = 200
            if urlsplit(request.full_url).path.casefold() == ACCOUNT.casefold():
                assert request.get_method() == 'GET' and urlsplit(request.full_url).netloc == 'management.azure.com'
                if mode == 'http206': status = 206
                elif mode == 'denied': status = 403
                elif mode == 'duplicate':
                    replacement = '"expirationAction": "Log", "expirationAction": "Block"' if action == 'Block' else '"expirationAction": "Block", "expirationAction": "Log"'
                    needle = '"expirationAction": ' + json.dumps(action)
                    assert raw.count(needle.encode()) == 1
                    raw = raw.replace(needle.encode(),replacement.encode())
                elif mode == 'nonfinite': raw = raw[:-1] + b',"unexpected":NaN}'
                elif mode == 'malformed': raw = raw[:-1]
                elif mode == 'omitted':
                    data=json.loads(raw); data['properties'].pop('sasPolicy'); raw=json.dumps(data).encode()
            result=io.BytesIO(raw);result.status=status;captures.append((result,status,request.full_url))
            return result
    monkeypatch.setattr(azure,'build_opener',lambda *args:Opener())
    claims={'tid':'22222222-2222-2222-2222-222222222222','aud':azure.ARM,'exp':int(time.time())+3600}
    token='eyJhbGciOiJub25lIn0.'+base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')+'.inert'
    connector={'provider':'azure','scopes':[SUB],'auth':{'method':'token','arm_token':token,'tenant_id':claims['tid']},
        'options':{'concurrency':1,'retries':0}}
    snapshot=azure.collect(connector,['storage_account'])
    report=engine.evaluate_snapshot(snapshot,checks=[sas.CHECK])
    assert not http.unexpected,http.unexpected
    assert all(response.closed for response,_,_ in captures)
    assert PRIVATE not in json.dumps(snapshot)+json.dumps(report)
    if action == 'Block' or mode == 'coherent':
        CAPTURES.append({'case':mode+'_'+action,'mode':mode,'action':action,'snapshot':snapshot,
            'observed_statuses':sorted({f['status'] for f in report['findings']}),
            'requests':http.calls,'http_responses':[{'status':status,'url':url} for _,status,url in captures]})
    return snapshot,report['findings'],captures


@pytest.mark.parametrize('action,expected',[('Block','PASS'),('Log','FAIL')])
def test_registered_native_coherent200_keeps_decisive_policy(monkeypatch,action,expected):
    assert len([c for c in checks.CHECKS if c.id==sas.CHECK]) == 1
    snapshot,findings,_=native_capture(monkeypatch,action=action)
    assert len(findings)==1 and findings[0]['status']==expected


@pytest.mark.parametrize('action',['Block','Log'])
@pytest.mark.parametrize('mode',['http206','duplicate','nonfinite','malformed','denied'])
def test_registered_native_uncertain_transport_never_decisive(monkeypatch,mode,action):
    snapshot,findings,captures=native_capture(monkeypatch,mode,action)
    # The public engine may emit both resource and collection uncertainty.
    assert findings and {finding['status'] for finding in findings} == {'UNKNOWN'},findings


def test_registered_native_absent_optional_policy_is_real_failure(monkeypatch):
    _,findings,_=native_capture(monkeypatch,'omitted')
    assert len(findings)==1 and findings[0]['status']=='FAIL'


@pytest.mark.parametrize('limit',[None,262144])
@pytest.mark.parametrize('status',[None,True,201,202,203,204,205,206,207,304,400,401,403,404,429,500])
def test_complete_status_required_in_both_decode_branches(monkeypatch,limit,status):
    response=io.BytesIO(b'{"value":[]}')
    if status is not None: response.status=status
    class Opener:
        def open(self,request,timeout):
            assert request.get_method()=='GET' and request.full_url==azure.ARM+SCOPE+'?api-version=2022-12-01'
            return response
    monkeypatch.setattr(azure,'build_opener',lambda *args:Opener())
    transport=azure.AzureTransport({'method':'token','arm_token':'INERT_TRANSPORT_FIXTURE'})
    with pytest.raises((ValueError,azure.AzureReadError)):
        transport.request(azure.ARM+SCOPE+'?api-version=2022-12-01',max_response_bytes=limit)
    assert response.closed


@pytest.mark.parametrize('limit',[None,262144])
@pytest.mark.parametrize('raw',[b'{"a":false,"a":true}',b'{"x":{"a":0,"a":1}}',
    b'{"value":[{"id":"one","id":"two"}]}',b'{"a":NaN}',b'{"a":Infinity}',b'{"a":-Infinity}',
    b'{"a":1e999}',b'{"a":-1e999}',b'{',b'null trailing',b'{"a":0,"\\u0061":1}'])
def test_ambiguous_or_nonfinite_json_rejected_both_branches(monkeypatch,limit,raw):
    response=io.BytesIO(raw);response.status=200
    class Opener:
        def open(self,request,timeout): return response
    monkeypatch.setattr(azure,'build_opener',lambda *args:Opener())
    transport=azure.AzureTransport({'method':'token','arm_token':'INERT_TRANSPORT_FIXTURE'})
    with pytest.raises((ValueError,azure.AzureReadError)):
        transport.request(azure.ARM+SCOPE+'?api-version=2022-12-01',max_response_bytes=limit)
    assert response.closed


@pytest.mark.parametrize('limit',[None,262144])
@pytest.mark.parametrize('raw,expected',[(b'{"a":false,"nested":[1,2.25,{},null]}',{'a':False,'nested':[1,2.25,{},None]}),
    (b'{"maximum":1.7976931348623157e308}',{'maximum':1.7976931348623157e308}),
    (b'{"a":1,"nested":{"a":2}}',{'a':1,'nested':{'a':2}})])
def test_strict_valid_json_keeps_types_and_independent_names(monkeypatch,limit,raw,expected):
    response=io.BytesIO(raw);response.status=200
    class Opener:
        def open(self,request,timeout): return response
    monkeypatch.setattr(azure,'build_opener',lambda *args:Opener())
    transport=azure.AzureTransport({'method':'token','arm_token':'INERT_TRANSPORT_FIXTURE'})
    assert transport.request(azure.ARM+SCOPE+'?api-version=2022-12-01',max_response_bytes=limit)==expected
    assert response.closed


@pytest.mark.parametrize('limit',[0,True,-1,20000001,1.5])
def test_existing_invalid_byte_limit_still_rejected(monkeypatch,limit):
    response=io.BytesIO(b'{"value":[]}');response.status=200
    class Opener:
        def open(self,request,timeout): return response
    monkeypatch.setattr(azure,'build_opener',lambda *args:Opener())
    transport=azure.AzureTransport({'method':'token','arm_token':'INERT_TRANSPORT_FIXTURE'})
    with pytest.raises(ValueError,match='invalid response byte limit'):
        transport.request(azure.ARM+SCOPE+'?api-version=2022-12-01',max_response_bytes=limit)
    assert response.closed


def test_existing_oversized_bounded_response_never_decoded(monkeypatch):
    response=io.BytesIO(b'{"value":[]}');response.status=200
    class Opener:
        def open(self,request,timeout): return response
    monkeypatch.setattr(azure,'build_opener',lambda *args:Opener())
    transport=azure.AzureTransport({'method':'token','arm_token':'INERT_TRANSPORT_FIXTURE'})
    with pytest.raises(azure.AzureReadError,match='response_too_large'):
        transport.request(azure.ARM+SCOPE+'?api-version=2022-12-01',max_response_bytes=3)
    assert response.closed


def test_retained_current_native_snapshots_replay_public_engine():
    import gzip
    root=Path(__file__).resolve().parents[1]
    pack=json.loads(gzip.decompress((root/'tests/fixtures/azure_metadata_transport_successor_native_cases_20261020.json.gz').read_bytes()))
    assert len(pack['cases']) == 5
    for case in pack['cases']:
        report=engine.evaluate_snapshot(case['snapshot'],checks=[sas.CHECK])
        assert sorted({f['status'] for f in report['findings']}) == case['observed_statuses']
