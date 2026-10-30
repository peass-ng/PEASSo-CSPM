"""Unregistered finite source/clone/native admission; no production hooks."""
import gzip
import json
from pathlib import Path

from tests.test_k8s_selected_metadata_secret_review_20261020 import offline,source,consumer,TOKEN,NS,capture


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
