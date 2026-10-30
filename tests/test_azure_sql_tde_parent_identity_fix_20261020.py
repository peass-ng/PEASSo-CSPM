"""Official SQL TDE GET identity forms through current HTTP/collector/engine."""
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import socket
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit

import pytest
from peaso import engine
from peaso.collectors import azure
from tests.test_azure_database_crypto_backup_2_native_review_20261020 import NativeHTTP, DATABASE as DB, SUB, TDE as CID
from tests.test_azure_database_crypto_backup_2_native_review_20261020 import NativeHTTP, DATABASE as DB, SUB, SCOPE, TDE as CID

OTHER='99999999-9999-9999-9999-999999999999'
CAPTURES=[]


class Wire(NativeHTTP):
    """Reuse the independently constructed native SQL family HTTP router."""
    def __init__(self, form, state, mode):
        self.responses=[]
        def native(d):
            # Independent official response DTO; no CASES or evaluator output.
            value={'id':DB if form=='parent' else DB+'/transparentDataEncryption/current','name':'current',
                'type':'Microsoft.Sql/servers/databases/transparentDataEncryption','properties':{'state':state}}
            if mode=='foreign_database':value['id']=value['id'].replace('/databases/app','/databases/foreign')
            if mode=='foreign_subscription':value['id']=value['id'].replace(SUB,OTHER)
            if mode=='wrong_name':value['name']='previous'
            if mode=='wrong_type':value['type']='Microsoft.Sql/servers/databases'
            if mode=='missing_name':value.pop('name')
            if mode=='missing_type':value.pop('type')
            if mode=='missing_properties':value.pop('properties')
            if mode=='malformed_properties':value['properties']=[]
            if mode=='missing_state':value['properties'].pop('state')
            if mode=='malformed_state':value['properties']['state']=True
            if mode=='legacy_optional_child':value.pop('name');value.pop('type')
            d['tde']=value
            self.tde=deepcopy(value)
        super().__init__(CID,'child_partial' if mode=='database_partial' else 'positive',native)
        self.case_mode=mode
    def open(self,request,timeout):
        if self.case_mode=='denied' and urlsplit(request.full_url).path==DB+'/transparentDataEncryption/current':
            assert request.get_method()=='GET' and urlsplit(request.full_url).netloc=='management.azure.com'
            self.calls.append({'method':'GET','host':'management.azure.com','path':DB+'/transparentDataEncryption/current'})
            raise HTTPError(request.full_url,403,'native fixture denied',{},io.BytesIO(b'{}'))
        parsed=urlsplit(request.full_url)
        if parsed.path in {self.d['rid']+'/azureADOnlyAuthentications',self.d['rid']+'/privateEndpointConnections'}:
            # Current read-only server child LISTs; the reviewed server declares none.
            assert request.get_method()=='GET' and request.data is None and parsed.netloc=='management.azure.com'
            assert parse_qs(parsed.query)=={'api-version':['2023-08-01']}
            self.calls.append({'method':'GET','host':parsed.netloc,'path':parsed.path,'query':parse_qs(parsed.query)})
            response=io.BytesIO(b'{"value": []}');response.status=200
            self.responses.append(response)
            return response
        response=super().open(request,timeout)
        self.responses.append(response)
        return response


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*a,**kw):raise AssertionError('Network/DNS/auth forbidden')
    for obj,names in ((socket,('getaddrinfo','gethostbyname','create_connection')),
                      (socket.socket,('connect','connect_ex','sendto')),(azure,('credential_for',))):
        for name in names:monkeypatch.setattr(obj,name,blocked)


@pytest.fixture(scope='session', autouse=True)
def portable_native_receipts():
    yield
    if path := os.environ.get('AZURE_TDE_NATIVE_RECEIPTS'):
        Path(path).write_text(json.dumps({'cases':CAPTURES},indent=2)+'\n')


def capture(monkeypatch, form, state, mode='coherent'):
    wire=Wire(form,state,mode);monkeypatch.setattr(azure,'build_opener',lambda *a:wire)
    connector={'provider':'azure','scopes':[SUB],'auth':{'method':'token','arm_token':'inert-tde-native-fixture'},
        'options':{'concurrency':1,'retries':0}}
    wanted=engine.plan_collection({'connector':connector,'checks':[CID]})
    snapshot=azure.collect(connector,wanted)
    findings=engine.evaluate_snapshot(snapshot,checks=[CID],include_not_applicable=True)['findings']
    assert not wire.unexpected,wire.unexpected
    assert all(response.closed for response in wire.responses)
    assert sum(c['path']==DB+'/transparentDataEncryption/current' for c in wire.calls)==1
    if mode=='coherent':
        CAPTURES.append({'form':form,'state':state,'native_response':wire.tde,'snapshot':snapshot,
            'observed_statuses':sorted({f['status']for f in findings}),'requests':wire.calls})
    return findings,snapshot,wire


@pytest.mark.parametrize('form',['parent','child'])
@pytest.mark.parametrize('state,expected',[('Enabled','PASS'),('Disabled','FAIL')])
def test_official_native_tde_identity_keeps_decisive_state(monkeypatch,form,state,expected):
    findings,snapshot,wire=capture(monkeypatch,form,state)
    assert {f['status']for f in findings}=={expected},findings
    rows=[r for c in snapshot['collections']if c['type']=='sql_tde' for r in c['items']]
    assert len(rows)==1 and rows[0]['id']==wire.tde['id'] and rows[0]['parent_id']==DB


@pytest.mark.parametrize('form',['parent','child'])
@pytest.mark.parametrize('mode',['foreign_database','foreign_subscription','wrong_name','wrong_type',
    'missing_properties','malformed_properties','missing_state','malformed_state','denied','database_partial'])
def test_native_tde_incomplete_or_foreign_is_unresolved(monkeypatch,form,mode):
    findings,_,_=capture(monkeypatch,form,'Enabled',mode)
    assert findings and {f['status']for f in findings}=={'UNKNOWN'},findings


@pytest.mark.parametrize('mode',['missing_name','missing_type'])
def test_parent_identity_requires_exact_native_name_and_type(monkeypatch,mode):
    findings,_,_=capture(monkeypatch,'parent','Enabled',mode)
    assert {f['status']for f in findings}=={'UNKNOWN'},findings


def test_preexisting_child_optional_type_name_compatibility(monkeypatch):
    findings,_,_=capture(monkeypatch,'child','Enabled','legacy_optional_child')
    assert {f['status']for f in findings}=={'PASS'},findings




