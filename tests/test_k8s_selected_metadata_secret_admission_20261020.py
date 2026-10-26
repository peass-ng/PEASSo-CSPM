"""Unregistered finite source/clone/native admission; no production hooks."""
from copy import deepcopy
import gzip
import json
from pathlib import Path
import re
import shutil
import types

import pytest
from peaso import checks
from peaso.collectors import k8s
from peaso.checks import k8s_selected_metadata_secret_admission_20261020 as admission
from tests.test_k8s_selected_metadata_secret_review_20261020 import offline,source,consumer,TOKEN,NS,capture


def copy_inputs(tmp_path):
    root=Path(__file__).resolve().parents[1];r=json.loads((root/'peaso/checks'/admission.RECEIPT).read_bytes())
    paths=set(r['sources'])|{v['path']for v in r['fixtures']}|{v['path']for v in r['functions'].values()}|{'peaso/checks/'+admission.RECEIPT}
    for relative in paths:
        target=tmp_path/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(root/relative,target)
    return r


def test_prepared_only_no_registration_inventory_options_or_global_mutation():
    before=tuple(checks.CHECKS);types_before=tuple(k8s.TYPES)
    r,cases,d,evaluate=admission.reviewed_inputs()
    assert r['registered']is False and not hasattr(admission,'install')
    assert tuple(checks.CHECKS)==before and tuple(k8s.TYPES)==types_before
    assert not any(c.id==d['id']for c in checks.CHECKS)and source.KIND not in k8s.TYPES
    for branch in('pass','fail','unknown'):
        assert evaluate(cases[source.CHECK][branch],cases[source.CHECK][branch+'_index'])[0]==branch.upper()
    cases[source.CHECK]['pass'].clear()
    assert admission.reviewed_inputs()[1][source.CHECK]['pass']


@pytest.mark.parametrize('which',['producer','consumer','helper','receipt','cases','fixture','proposal','setup','shared_source'])
def test_source_fixture_receipt_or_exact_shared_callable_drift(tmp_path,which):
    r=copy_inputs(tmp_path)
    names={'producer':'peaso/collectors/k8s_selected_metadata_secret_indicators_20261020.py',
           'consumer':'peaso/checks/k8s_selected_metadata_secret_review_20261020.py','helper':r['helper_path'],
           'receipt':'peaso/checks/'+admission.RECEIPT,'cases':'peaso/checks/'+admission.CASES,
           'fixture':'tests/fixtures/k8s_selected_metadata_secret_native_20261020.json.gz',
           'proposal':'peaso/checks/k8s_selected_metadata_secret_proposal_20261020.json',
           'setup':'docs/peaso-k8s-selected-metadata-secrets-proposal-20261020.md',
           'shared_source':'peaso/collectors/k8s_literal_secret_indicators.py'}
    path=tmp_path/names[which]
    if which=='shared_source':
        text=path.read_text();text=text.replace('    """Return safe selection metadata plus transient union-redaction callback state."""','    """Unreviewed changed exact callable."""',1);path.write_text(text)
    else:
        with path.open('ab')as stream:stream.write(b'\n')
    with pytest.raises(RuntimeError):admission.reviewed_inputs(tmp_path)


def test_unrelated_shared_module_addition_does_not_freeze_file(tmp_path):
    copy_inputs(tmp_path)
    with(tmp_path/'peaso/collectors/k8s_literal_secret_indicators.py').open('a')as stream:stream.write('\n# unrelated future extension\n')
    assert admission.reviewed_inputs(tmp_path)[2]['id']==source.CHECK


@pytest.mark.parametrize('which',['private_read','extract','scan','namespace','regex','consumer_clone','wire_guard','privacy','source_alias','detector_version'])
def test_private_or_imported_runtime_binding_replacement_rejected(monkeypatch,which):
    if which=='private_read':monkeypatch.setitem(source._GLOBALS,'_read',lambda *a:None)
    elif which=='extract':monkeypatch.setattr(source,'_extract',lambda *a:None)
    elif which=='scan':monkeypatch.setitem(source._GLOBALS,'scan_content',lambda *a,**kw:{'complete':True})
    elif which=='namespace':monkeypatch.setitem(source._GLOBALS,'KIND','k8s_selected_literals')
    elif which=='regex':monkeypatch.setattr(source,'_NAME',re.compile('.*'))
    elif which=='consumer_clone':
        original=consumer._evaluate;clone=types.FunctionType(original.__code__,original.__globals__,original.__name__,original.__defaults__,original.__closure__)
        monkeypatch.setattr(consumer,'_evaluate',clone)
    elif which=='wire_guard':monkeypatch.setattr(source,'_wire_debug_enabled',lambda *a:False)
    elif which=='privacy':monkeypatch.setattr(source,'private_native_logs',lambda:None)
    elif which=='source_alias':monkeypatch.setattr(consumer,'source',object())
    else:monkeypatch.setattr(admission.scanning,'KINGFISHER_VERSION','0.0.0')
    with pytest.raises(RuntimeError):admission.reviewed_inputs()


@pytest.mark.parametrize('which',['producer','consumer','clone','native_read'])
def test_in_memory_code_replacement_rejected(monkeypatch,which):
    function={'producer':source._extract,'consumer':consumer.evaluate,'clone':source._GLOBALS['identity'],'native_read':source._NATIVE_READ}[which]
    monkeypatch.setattr(function,'__code__',(lambda *a,**kw:('PASS',{})).__code__)
    with pytest.raises(RuntimeError):admission.reviewed_inputs()


def test_retained_real_pinned_native_captures_are_redacted_and_replay():
    root=Path(__file__).resolve().parents[1]
    fixtures=json.loads(gzip.decompress((root/'tests/fixtures/k8s_selected_metadata_secret_native_20261020.json.gz').read_bytes()))
    assert fixtures['registered']is False
    for frame in fixtures['captures']:
        assert consumer.evaluate(frame['item'],frame['index'])[0]==frame['branch'].upper()
        assert {f['status']for f in frame['findings']}=={frame['branch'].upper()}
        assert len(frame['native_requests'])==(1 if frame['branch']=='unknown'else 2)
        assert TOKEN not in json.dumps(frame)


def test_union_scrub_includes_incoming_metadata_keys_locations_and_encoded_values():
    import base64
    matches={TOKEN};encoded=base64.b64encode(TOKEN.encode()).decode()
    scopes,rows,metadata=source.redact_output([TOKEN],[{'id':TOKEN,'location':encoded}],{TOKEN:{'value':TOKEN}},matches)
    assert not matches and TOKEN in json.dumps([scopes,rows,metadata])


def test_detector_deadline_cannot_become_clean_or_retain_match(monkeypatch):
    def setup(api):monkeypatch.setitem(source._GLOBALS,'MAX_SECONDS',0)
    (status,_),trace,_,_=capture(monkeypatch,positive=True,api_setup=setup)
    assert status=='UNKNOWN'and not trace.calls and not trace.scans
