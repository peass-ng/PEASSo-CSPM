"""Unregistered finite source/clone/native admission; no production hooks."""
import gzip
import json
from pathlib import Path
import shutil

import pytest
from peaso import checks
from peaso.collectors import k8s
from peaso.checks import k8s_selected_metadata_secret_admission_20261020 as admission
from tests.test_k8s_selected_metadata_secret_review_20261020 import source, consumer, TOKEN, capture


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
