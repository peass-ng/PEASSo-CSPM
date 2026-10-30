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


def test_current_successor_preserves_predecessor_and_is_idempotent():
    from peaso import checks
    # The TDE-only successor is now a historical epoch: Azure collect gained the
    # separately reviewed package/metadata-only statements, and the current
    # admission chain keeps the same signed TDE receipt.
    from peaso.checks import azure_metadata_only_tde_admission_successor_20261020 as admission
    from peaso.checks import azure_nsp_query_cmk_production_tde_successor_20261020 as tde_historical
    from peaso.checks import azure_nsp_query_cmk_production_admission_20261020 as predecessor
    before=tuple(checks.CHECKS)
    receipt,_,_=admission.reviewed_inputs()
    admission.install();admission.install()
    assert tuple(checks.CHECKS)==before
    assert receipt['before_collect_sha256']!=receipt['functions']['peaso.collectors.azure:collect']['source_sha256']
    # The old signed receipts are historical, rather than silently repinned.
    with pytest.raises(RuntimeError,match='Azure collect changed outside reviewed TDE body'):
        tde_historical.reviewed_inputs()
    with pytest.raises(RuntimeError,match='production disk callable source changed'):
        predecessor.reviewed_inputs()


@pytest.mark.parametrize('which',['collect','selected'])
def test_current_successor_rejects_executing_callable_replacement(monkeypatch,which):
    import types
    from peaso.checks import azure_metadata_only_tde_admission_successor_20261020 as admission
    admission.reviewed_inputs()
    name='collect'if which=='collect'else'_selected';original=getattr(azure,name)
    clone=types.FunctionType(original.__code__,original.__globals__,original.__name__,original.__defaults__,original.__closure__)
    clone.__kwdefaults__=original.__kwdefaults__;clone.__qualname__=original.__qualname__
    monkeypatch.setattr(azure,name,clone)
    with pytest.raises(RuntimeError):admission.reviewed_inputs()


@pytest.mark.parametrize('which',['collect','selected','helper','receipt','predecessor_helper','predecessor_receipt','predecessor_pack','cases'])
def test_current_successor_rejects_source_and_historical_drift(tmp_path,which):
    import shutil
    from pathlib import Path
    from peaso.checks import azure_nsp_query_cmk_production_tde_successor_20261020 as admission
    from peaso.checks import azure_metadata_only_tde_admission_successor_20261020 as current
    root=Path(__file__).resolve().parents[1]
    # The current chain admits the same signed TDE receipt; the TDE-only helper
    # is historical and must keep rejecting today's collect epoch.
    receipt,_,_=current.reviewed_inputs()
    assert receipt==json.loads((root/'peaso/checks'/admission.RECEIPT).read_bytes())
    paths={receipt['helper_path'],'peaso/checks/'+admission.RECEIPT,receipt['predecessor_pack']['path'],*receipt['predecessor_files']}
    for helper in (admission.prepared.predecessor,admission.prepared,admission):
        relative='peaso/checks/'+helper.RECEIPT;signed=json.loads((root/relative).read_bytes())
        paths.update({relative,signed['helper_path'],*signed.get('sources',{}),*signed.get('predecessor_files',{})})
        paths.update(row['path']for row in signed['functions'].values());paths.update(row['path']for row in signed['fixtures'])
        if 'predecessor_pack' in signed:paths.add(signed['predecessor_pack']['path'])
    for relative in paths:
        destination=tmp_path/relative;destination.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(root/relative,destination)
    targets={'collect':'peaso/collectors/azure.py','selected':'peaso/collectors/azure.py','helper':receipt['helper_path'],
        'receipt':'peaso/checks/'+admission.RECEIPT,'predecessor_helper':'peaso/checks/azure_nsp_query_cmk_production_admission_20261020.py',
        'predecessor_receipt':'peaso/checks/azure_nsp_query_cmk_production_admission_20261020.json',
        'predecessor_pack':receipt['predecessor_pack']['path'],'cases':receipt['fixtures'][0]['path']}
    epoch='Azure collect changed outside reviewed TDE body'
    # Every copied input passes the file guards; only the historical collect
    # epoch gate rejects the unmodified copy.
    with pytest.raises(RuntimeError,match=epoch):admission.reviewed_inputs(tmp_path)
    target=tmp_path/targets[which]
    if which in ('collect','selected'):
        text=target.read_text();name='collect'if which=='collect'else'_selected'
        marker='def '+name+'(';start=text.index(marker);end=text.index('\n',start)
        text=text[:end+1]+'    raise RuntimeError("unreviewed source")\n'+text[end+1:]
        target.write_text(text)
    else:
        with target.open('ab')as stream:stream.write(b'\n')
    with pytest.raises(RuntimeError)as error:admission.reviewed_inputs(tmp_path)
    if which not in ('collect','selected'):
        # Signed file drift is caught by its own guard before the epoch gate.
        assert str(error.value)!=epoch
