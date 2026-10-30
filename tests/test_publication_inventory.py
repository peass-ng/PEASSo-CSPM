"""Publication reuses preparation only inside a single owned invocation."""
import sys

from peaso import snapshot as native
from peaso.engine import evaluate_snapshot
from peaso.least_privilege import project
from peaso.storage.artifacts import FileArtifacts
from peaso.storage import reports
from peaso.worker import redact_report


def fixture():
    scope = '123456789012/us-east-1'
    snapshot = native.make_snapshot('aws', [scope], [
        {'type': 'bucket', 'scope': scope, 'status': 'collected',
         'items': [{'Name': 'synthetic-one', 'recorded_label': 'original λ'}, {'Name': 'synthetic-two'}]},
        {'type': 'iam_role', 'scope': scope, 'status': 'collected', 'items': [{
            'Arn': 'arn:aws:iam::123456789012:role/synthetic', 'RoleName': 'synthetic',
            'AssumeRolePolicyDocument': {'Statement': []},
            'RolePolicyList': [{'PolicyName': 'inline', 'PolicyDocument': {
                'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}}]}]}],
        created_at='2026-01-01T00:00:00+00:00')
    report = redact_report(evaluate_snapshot(snapshot, checks=['aws.s3.default_encryption'],
        categories=['hardening'], include_not_applicable=False))
    # Download selection must not remove native context from least privilege.
    report['resources'] = [row for row in report['resources'] if row['type'] == 'bucket']
    return report, snapshot


def test_shared_inventory_keeps_full_projection_and_filtered_download(tmp_path):
    report, snapshot = fixture()
    original = native.digest(report), native.digest(snapshot)
    expected = project('aws', native.resources(snapshot), snapshot=snapshot)
    assert expected['total'] > 0
    artifacts = FileArtifacts(tmp_path)
    calls = []
    previous = sys.getprofile()

    def observe(frame, event, argument):
        if (event == 'call' and frame.f_code is native.resources.__code__
                and frame.f_back.f_code.co_filename == reports.__file__):
            calls.append(frame.f_back.f_code.co_name)

    try:
        sys.setprofile(observe)
        reference = reports.publish_report(artifacts, 'tenant', 'f' * 32, report, snapshot)
    finally:
        sys.setprofile(previous)
    # One lazy inventory build inside publication is shared by every projection.
    assert calls == ['get_inventory']
    bundle = artifacts.get('tenant', reference)
    assert artifacts.get('tenant', bundle['least_privilege']) == expected
    rows = [row for chunk in bundle['resource_chunks']
            for row in artifacts.get('tenant', chunk['reference'])['items']]
    assert len(rows) == 2 and all(row['type'] == 'bucket' for row in rows)
    assert (native.digest(report), native.digest(snapshot)) == original


def test_later_publication_rebuilds_from_changed_native_facts(tmp_path):
    report, snapshot = fixture()
    artifacts = FileArtifacts(tmp_path)
    first = artifacts.get('tenant', reports.publish_report(artifacts, 'tenant', 'f' * 32, report, snapshot))
    snapshot['collections'][0]['items'][0]['recorded_label'] = 'fresh value'
    snapshot = native.seal(snapshot)
    report = dict(report, snapshot_id=snapshot['snapshot_id'])
    second = artifacts.get('tenant', reports.publish_report(artifacts, 'tenant', 'f' * 32, report, snapshot))
    assert 'fresh value' in artifacts.get_text('tenant', second['report_markdown'])
    assert 'fresh value' not in artifacts.get_text('tenant', first['report_markdown'])
    rows = [row for chunk in second['resource_chunks']
            for row in artifacts.get('tenant', chunk['reference'])['items']]
    assert next(row for row in rows if row['native_id'] == 'synthetic-one')['data']['recorded_label'] == 'fresh value'
