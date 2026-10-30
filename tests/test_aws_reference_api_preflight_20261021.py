"""Pure AWS reference selector parity and cold API boundary."""
import copy
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT
NATIVE = ROOT / 'peaso/collectors'
SCOPE = '123456789012/us-east-1'
BUCKET = 'selected-source-bucket'


def pure_module():
    from peaso.server import content_selection_preflight_20261021
    return content_selection_preflight_20261021


@pytest.fixture
def pure():
    return pure_module()


def workload(profile='glue_script', *, key='jobs/script.py'):
    row = {'profile': profile, 'scope': SCOPE, 'source_s3_uri': f's3://{BUCKET}/{key}'}
    if profile == 'glue_script':
        row['job_name'] = 'AuditJob'
    elif profile.startswith('emr_serverless_'):
        row.update(job_run_arn='arn:aws:emr-serverless:us-east-1:123456789012:/applications/app1/jobruns/run1', attempt=1)
    elif profile == 'emr_step_jar':
        row.update(cluster_id='j-ABC123', step_id='s-DEF456')
    else:
        row.update(cluster_arn='arn:aws:sagemaker:us-east-1:123456789012:cluster/abcdefghijkl',
                   instance_group='workers', entry_script='OnCreate',
                   source_s3_uri=f's3://sagemaker-selected-source-bucket/{key}')
    return row


def build(profile='codebuild_s3_source', *, key='jobs/source.zip'):
    row = {'profile': profile, 'scope': SCOPE, 'source_s3_uri': f's3://{BUCKET}/{key}'}
    if profile.startswith('codebuild_'):
        row['project_arn'] = 'arn:aws:codebuild:us-east-1:123456789012:project/AuditProject'
    elif profile == 'elasticbeanstalk_source_bundle':
        row.update(application_name='AuditApp', version_label='v1',
                   version_arn='arn:aws:elasticbeanstalk:us-east-1:123456789012:applicationversion/AuditApp/v1')
    else:
        row.update(app_id='d1234', branch_name='main', job_id='1',
                   job_arn='arn:aws:amplify:us-east-1:123456789012:apps/d1234/branches/main/jobs/1')
    return row


def selected(pure, *, workloads=(), builds=(), ecs=(), extra=(), kinds=()):
    options = {'selected_aws_s3_sources': [pure.workload_ref.source_target(t) for t in workloads]
               + [pure.build_ref.source_target(t) for t in builds]
               + [pure.ecs_env.source_target(t) for t in ecs] + list(extra)}
    if workloads:
        options['selected_aws_workload_sources'] = list(workloads)
    if builds:
        options['selected_aws_build_deployment_sources'] = list(builds)
    if ecs:
        options['selected_aws_ecs_environment_files'] = list(ecs)
    if kinds:
        options.update(content_secret_scans=True, _content_secret_scan_kinds=list(kinds))
    return options


def ecs_target():
    return dict(scope=SCOPE, task_definition_arn='arn:aws:ecs:us-east-1:123456789012:task-definition/app:1',
                container='app', environment_file_arn='arn:aws:s3:::selected-source-bucket/jobs/config.env')


@pytest.mark.parametrize('profile,key', [
    ('glue_script', 'jobs/script.py'), ('emr_serverless_spark', 'jobs/script.py'),
    ('emr_serverless_spark_jar', 'jobs/code.jar'), ('emr_serverless_hive', 'jobs/query.sql'),
    ('emr_serverless_hive_init', 'jobs/init.sql'), ('emr_step_jar', 'jobs/code.jar'),
    ('sagemaker_hyperpod_lifecycle', 'jobs/init.py'),
])
def test_workload_native_profiles(pure, profile, key):
    row = workload(profile, key=key)
    opts = selected(pure, workloads=[row])
    assert pure.workload_ref.selected_targets(opts, [SCOPE]) == [row]
    bad = copy.deepcopy(row); bad['source_s3_uri'] = 'https://example.invalid/source'
    with pytest.raises((ValueError, TypeError)):
        pure.workload_ref.selected_targets({**opts, 'selected_aws_workload_sources': [bad]}, [SCOPE])
    with pytest.raises((ValueError, TypeError)):
        pure.workload_ref.selected_targets(opts, ['123456789012/eu-west-1'])


@pytest.mark.parametrize('profile,key', [
    ('codebuild_s3_source', 'jobs/source.zip'), ('codebuild_s3_buildspec', 'jobs/buildspec.yml'),
    ('elasticbeanstalk_source_bundle', 'jobs/source.zip'), ('amplify_s3_zip_deployment', 'jobs/source.zip'),
])
def test_build_native_profiles(pure, profile, key):
    row = build(profile, key=key)
    opts = selected(pure, builds=[row])
    assert pure.build_ref.selected_targets(opts, [SCOPE]) == [row]
    bad = copy.deepcopy(row); bad['foreign'] = True
    with pytest.raises((ValueError, TypeError)):
        pure.build_ref.selected_targets({**opts, 'selected_aws_build_deployment_sources': [bad]}, [SCOPE])
    with pytest.raises((ValueError, TypeError)):
        pure.build_ref.selected_targets(opts, ['123456789012/eu-west-1'])


def test_s3_union_with_ecs_and_both_reference_kinds(pure):
    w = workload(); b = build(key='jobs/source.zip'); e = ecs_target()
    kinds = ('workload_referenced_source_content', 'build_deployment_referenced_source_content',
             'ecs_selected_environment_file_content')
    opts = selected(pure, workloads=[w], builds=[b], ecs=[e], kinds=kinds)
    assert pure.s3.selected_targets(opts, [SCOPE])
    assert pure.workload_ref.selected_targets(opts, [SCOPE]) == [w]
    assert pure.build_ref.selected_targets(opts, [SCOPE]) == [b]
    assert pure.ecs_env.selected_targets(opts, [SCOPE]) == [e]
    extra = dict(scope=SCOPE, bucket=BUCKET, key='jobs/unrelated.py', format='text')
    opts['selected_aws_s3_sources'].append(extra)
    for validator in (pure.workload_ref.selected_targets, pure.build_ref.selected_targets,
                      pure.ecs_env.selected_targets):
        with pytest.raises(ValueError):
            validator(opts, [SCOPE])
    opts['_content_secret_scan_kinds'].append(pure.s3.KIND)
    assert pure.workload_ref.selected_targets(opts, [SCOPE]) == [w]
    assert pure.build_ref.selected_targets(opts, [SCOPE]) == [b]
    assert pure.ecs_env.selected_targets(opts, [SCOPE]) == [e]


def test_source_binding_duplicate_version_and_default_off(pure):
    assert pure.workload_ref.selected_targets({}, []) == []
    assert pure.build_ref.selected_targets({}, []) == []
    w = workload(); opts = selected(pure, workloads=[w])
    opts['content_secret_scans'] = False
    assert pure.workload_ref.selected_targets(opts, [SCOPE]) == [w]
    opts['selected_aws_s3_sources'].append(dict(scope=SCOPE, bucket=BUCKET, key='jobs/unrelated.py', format='text'))
    assert pure.workload_ref.selected_targets(opts, [SCOPE]) == [w]
    opts['selected_aws_s3_sources'].pop()
    opts['selected_aws_s3_sources'][0]['format'] = 'zip'
    with pytest.raises(ValueError):
        pure.workload_ref.selected_targets(opts, [SCOPE])
    b = build(); b['version_id'] = 'version-1'; opts = selected(pure, builds=[b])
    assert pure.build_ref.selected_targets(opts, [SCOPE]) == [b]
    del opts['selected_aws_s3_sources'][0]['version_id']
    with pytest.raises(ValueError):
        pure.build_ref.selected_targets(opts, [SCOPE])
    opts = selected(pure, workloads=[w, copy.deepcopy(w)])
    with pytest.raises(ValueError):
        pure.workload_ref.selected_targets(opts, [SCOPE])


def test_cold_api_preflight_denies_collector_import_and_network():
    script = r'''
import importlib.abc, importlib.util, json, socket, sys
from types import SimpleNamespace
sys.path.insert(0, 'ROOT')
class Deny(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith(('peaso.collectors', 'peaso.checks', 'peaso.engine', 'peaso.analysis',
                                 'boto3', 'botocore', 'google.auth', 'azure.identity', 'kubernetes')):
            raise AssertionError('heavy_import:' + fullname)
sys.meta_path.insert(0, Deny())
def no_network(*args, **kwargs): raise AssertionError('network_attempt')
socket.socket.connect = no_network
socket.create_connection = no_network
from peaso.server import validation as module
assert module.pure_selection.__file__ == 'STAGE/content_selection_preflight_20261021.py'
cases = json.loads('CASES')
for provider, options, scopes, expected in cases:
    try:
        module.validate_connector(provider, {}, options, SimpleNamespace(auth_mode='local'), scopes=scopes)
        status = 200
    except Exception as exc:
        status = getattr(exc, 'status_code', None)
    assert status == expected, (options, status, expected)
assert {'selected_aws_workload_sources', 'selected_aws_build_deployment_sources'} <= module.OPTIONS
assert not any(k.startswith(('peaso.collectors', 'peaso.checks', 'peaso.engine', 'peaso.analysis',
                             'boto3', 'botocore', 'google.auth', 'azure.identity', 'kubernetes')) for k in sys.modules)
print('aws-reference-cold-ok', len(cases))
'''
    pure = pure_module(); w = workload(); b = build()
    cases = []
    for option, row in [('selected_aws_workload_sources', w), ('selected_aws_build_deployment_sources', b)]:
        opts = selected(pure, workloads=[row] if option.endswith('workload_sources') else (),
                        builds=[row] if option.endswith('build_deployment_sources') else ())
        cases.append(['aws', opts, [SCOPE], 200])
        bad = copy.deepcopy(opts); bad[option][0]['foreign'] = True
        cases.append(['aws', bad, [SCOPE], 422])
        cases.append(['gcp', opts, [SCOPE], 422])
    cases.append(['aws', {}, [], 200])
    script = (script.replace('ROOT', str(ROOT)).replace('STAGE', str(HERE / 'peaso/server'))
             .replace('VALIDATION', str(HERE / 'peaso/server/validation.py'))
             .replace('CASES', json.dumps(cases)))
    result = subprocess.run([sys.executable, '-I', '-c', script], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert 'aws-reference-cold-ok' in result.stdout
