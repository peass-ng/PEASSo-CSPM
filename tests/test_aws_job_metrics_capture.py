"""Actual collector output/call parity with diagnostics enabled or broken."""
import json
import importlib
from datetime import datetime, timezone
from uuid import UUID

import peaso.checks  # Establish the native admission registry before direct collector import.
from peaso import collection_job_metrics as jobs, runtime_metrics as metrics
from peaso.collectors import aws
from tests.test_peaso_collectors_aws import ACCOUNT, IDENTITY, REGION, sdk


def test_actual_global_and_regional_jobs_preserve_complete_snapshot_and_calls(sdk, monkeypatch):
    _, add, _ = sdk
    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 10, 29, tzinfo=timezone.utc)
    monkeypatch.setattr(aws, 'datetime', FixedDateTime)
    # Producer-owned scan capture nonces are inputs to full snapshot identity.
    # Fix their generators rather than excluding any returned metadata.
    for name in ('aws_selected_configuration_secret_indicators',
                 'aws_s3_selected_source_secret_indicators',
                 'aws_lambda_environment_secret_indicators',
                 'aws_ecs_environment_file_secret_indicators',
                 'aws_build_deployment_referenced_source_indicators',
                 'aws_workload_referenced_source_indicators',
                 'aws_codebuild_buildspec_source_20261020',
                 'aws_workload_command_source_20261020'):
        module = importlib.import_module('peaso.collectors.' + name)
        monkeypatch.setattr(module, 'uuid4', lambda: UUID(int=1))
    frames, snapshots = [], []
    def broken(_):
        raise RuntimeError('PRIVATE-DELIVERY-FAILURE')
    try:
        for sink in (None, frames.append, broken):
            metrics.close()
            if sink is not None:
                metrics.configure(sink, role='collector', interval_seconds=60)
            add('sts').add_response('get_caller_identity', IDENTITY, {})
            add('ec2').add_response('describe_vpcs', {'Vpcs': []}, {})
            snapshots.append(aws.collect({'provider': 'aws', 'scopes': [ACCOUNT],
                'options': {'regions': [REGION]}}, ['aws_account', 'vpc']))
    finally:
        metrics.close()
    assert snapshots[0] == snapshots[1] == snapshots[2]
    assert all(s['metadata']['calls'] == 2 for s in snapshots)
    events = [e for tag, e in frames if tag == '__collection_job_metrics__' and 'job' in e]
    kinds = {e['kind_sha256'] for e in events}
    assert kinds == {jobs.kind_digest('aws_account'), jobs.kind_digest('vpc')}
    assert len(events) == 2 and all(jobs.validate(e) for e in events)
    assert len({e['scope_hmac_sha256'] for e in events}) == 2  # global vs regional
    assert not any(raw in json.dumps(events) for raw in (ACCOUNT, REGION, IDENTITY['Arn'], 'PRIVATE'))
