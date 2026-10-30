"""Exercise ordinary publication/download/detail contracts without fixture guards bypassed."""

import pytest
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
