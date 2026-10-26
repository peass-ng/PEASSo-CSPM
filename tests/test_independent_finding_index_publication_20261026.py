"""Exercise ordinary publication/download/detail contracts without fixture guards bypassed."""
from tests.test_peaso_api_large import test_large_downloads_pages_details_facets_and_graph_envelopes

import json
import gzip
import hashlib
from pathlib import Path
import types
import pytest
from peaso.storage import FileArtifacts
from peaso.storage.artifacts import S3Artifacts
from peaso.storage import reports
from tests.test_peaso_artifact_batch import MemoryS3


def report_fixture():
    return dict(schema_version='1.0', provider='aws', snapshot_id='independent-index',
        created_at='2026-10-26T00:00:00Z', scopes=['123456789012/us-east-1'], resources=[],
        coverage=[], graphs={}, stats={}, findings=[dict(id=f'f-{i:06d}',check_id='fixture',
        category='hardening',provider='aws',service='s3',status='FAIL',severity='high',title='Exact',
        scope='123456789012/us-east-1',resource_id=f'r-{i}',frameworks=['CIS'],
        evidence={'retained':'x'*6000}) for i in range(1802)])


def test_full_publisher_retains_original_detail_chunk_payloads_and_all_summaries(tmp_path):
    original = types.ModuleType('reference_report_publisher')
    before = Path(reports.__file__).resolve().parents[2]/'tests/fixtures/report-index-publisher-before-20261026.py.gz'
    raw = gzip.decompress(before.read_bytes())
    assert hashlib.sha256(raw).hexdigest() == 'b0fdb90bb2d2f7d6c9315dc128813735c88d77c1f6280487e527ea68c992ac81'
    exec(compile(raw, str(before), 'exec'), original.__dict__)
    legacy = FileArtifacts(tmp_path/'legacy'); current = FileArtifacts(tmp_path/'current')
    report=report_fixture(); tenant='alice'; ident='1'*32
    old=legacy.get(tenant,original.publish_report(legacy,tenant,ident,report))
    new=current.get(tenant,reports.publish_report(current,tenant,ident,report))
    def details(store,manifest):
        return [(chunk['first_id'],chunk['last_id'],chunk['count'],
                 store.get(tenant,chunk['reference'])) for chunk in manifest['finding_chunks']]
    assert details(legacy,old)==details(current,new)
    old_rows=[row for chunk in old['finding_chunks'] for row in legacy.get(tenant,chunk['index_reference'])['items']]
    new_rows=[row for chunk in new['finding_index_chunks'] for row in current.get(tenant,chunk['reference'])['items']]
    assert new_rows==old_rows
    assert len(new['finding_chunks'])==len(old['finding_chunks'])==8
    assert len(new['finding_index_chunks'])==1
    assert current.get(tenant,new['report_json'])==legacy.get(tenant,old['report_json'])
    assert current.get_text(tenant,new['report_markdown'])==legacy.get_text(tenant,old['report_markdown'])


@pytest.mark.parametrize('failure',[False,True])
def test_actual_batch_waits_for_new_index_and_never_commits_failed_manifest(failure):
    class Client(MemoryS3):
        def put_object(self,**request):
            if failure and '/finding-index-' in request['Key']: raise OSError('index upload denied')
            if hasattr(request['Body'],'read'):request['Body']=request['Body'].read()
            return super().put_object(**request)
    client=Client();artifacts=S3Artifacts('isolated',client=client)
    if failure:
        with pytest.raises(OSError,match='index upload denied'):
            reports.publish_report(artifacts,'alice','1'*32,report_fixture())
        assert not any('/manifest-' in key for key in client.objects)
    else:
        reference=reports.publish_report(artifacts,'alice','1'*32,report_fixture())
        assert client.order[-1]=='artifacts/'+reference
        manifest=artifacts.get('alice',reference)
        assert sum(chunk['count'] for chunk in manifest['finding_index_chunks'])==1802
        assert all('artifacts/'+chunk['reference'] in client.objects for chunk in manifest['finding_index_chunks'])
