"""Offline selector and cold API preflight regression tests."""
import ast
import copy
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
PURE = ROOT / 'peaso/server/content_selection_preflight_20261021.py'
GUID = '12345678-1234-1234-1234-123456789abc'
AZ_SCOPE = '/subscriptions/' + GUID
AWS_SCOPE = '123456789012/us-east-1'
DIGEST = 'sha256:' + 'a' * 64


def load_pure():
    from peaso.server import content_selection_preflight_20261021
    return content_selection_preflight_20261021


@pytest.fixture
def pure():
    return load_pure()


def registry_case():
    row = dict(cluster_id='cluster', namespace='default', pod='pod-a', uid='abc123',
               resource_version='42', container_type='regular', container_name='app',
               image='registry.example.com/team/app@' + DIGEST)
    return {'selected_k8s_registry_images': [row], 'selected_registry_hosts': ['registry.example.com']}, ['default']


def flux_case():
    return {'selected_k8s_flux_artifacts': [dict(cluster_id='cluster', kind='HelmChart', namespace='default',
        name='chart', uid='abc123', resource_version='42', generation=2, artifact_digest=DIGEST,
        artifact_revision='1.2.3', artifact_path='helmchart/default/chart/chart-1.2.3.tgz', artifact_size=100,
        service_namespace='flux-system', service_uid='service123', service_resource_version='12',
        service_port_name='http')]}, ['default', 'flux-system']


def ml_case():
    rid = AZ_SCOPE + '/resourceGroups/group/providers/Microsoft.MachineLearningServices/workspaces/workspace/environments/python/versions/v1'
    return {'selected_azure_ml_environment_versions': [{'resource_id': rid}]}, [AZ_SCOPE]


def db_case():
    rid = AZ_SCOPE + '/resourceGroups/group/providers/Microsoft.Databricks/workspaces/workspace1'
    return {'selected_azure_databricks_files': [{'workspace_resource_id': rid, 'path': '/Shared/config.py', 'object_type': 'FILE'}]}, [AZ_SCOPE]


def synapse_case():
    rid = AZ_SCOPE + '/resourceGroups/group/providers/Microsoft.Synapse/workspaces/workspace'
    return {'selected_azure_synapse_notebooks': [{'workspace_resource_id': rid, 'notebook_name': 'book'}]}, [AZ_SCOPE]


def aws_config_case():
    return {'selected_aws_configuration_content': [dict(surface='codepipeline_configuration', scope=AWS_SCOPE,
        resource_id='arn:aws:codepipeline:us-east-1:123456789012:pipeline', version=1)]}, [AWS_SCOPE]


def ecs_case():
    source = dict(scope=AWS_SCOPE, bucket='sample-bucket', key='service.env', format='text')
    row = dict(scope=AWS_SCOPE, task_definition_arn='arn:aws:ecs:us-east-1:123456789012:task-definition/app:1',
               container='app', environment_file_arn='arn:aws:s3:::sample-bucket/service.env')
    return {'selected_aws_s3_sources': [source], 'selected_aws_ecs_environment_files': [row]}, [AWS_SCOPE]


def workerpool_case():
    scope = 'projects/project-one'
    pool = scope + '/locations/us-east1/workerPools/pool'
    row = dict(pool_name=pool, pool_uid='12345678-1234-1234-1234-123456789abc',
               revision_name=pool + '/revisions/revision', revision_uid='abcdefab-1234-1234-1234-123456789abc',
               container_index=0, immutable_reference='us-east1-docker.pkg.dev/project-one/repo/image@' + DIGEST)
    return {'selected_cloudrun_worker_pool_revision_images': [row]}, [scope]


def developerconnect_case():
    scope = 'projects/project-one'
    row = dict(link_name=scope + '/locations/us-east1/connections/connection/gitRepositoryLinks/link',
               link_uid='12345678-1234-1234-1234-123456789abc', clone_uri='https://github.com/team/repo.git',
               provider='github', commit_sha='a' * 40, path='config/settings.yaml', blob_sha='b' * 40)
    return {'selected_developerconnect_files': [row]}, [scope]


def declaration_case():
    rid = (AZ_SCOPE + '/resourceGroups/group/providers/Microsoft.DataFactory/'
           'factories/factory/pipelines/pipeline')
    return {'selected_azure_data_factory_declarations': [{'resource_id': rid}]}, [AZ_SCOPE]


@pytest.mark.parametrize('name,fixture', [
    ('registry', registry_case), ('flux', flux_case), ('ml_asset', ml_case),
    ('databricks', db_case), ('synapse', synapse_case), ('aws_config', aws_config_case),
    ('ecs_env', ecs_case), ('declaration', declaration_case),
])
def test_native_selection_valid_and_invalid(pure, name, fixture):
    options, scopes = fixture()
    selected = getattr(pure, name).selected_targets(options, scopes)
    assert selected
    bad = copy.deepcopy(options)
    key = next(k for k in bad if k.startswith('selected_') and
               (name != 'ecs_env' or k == 'selected_aws_ecs_environment_files'))
    bad[key][0]['foreign_field'] = 'foreign'
    with pytest.raises((ValueError, TypeError, KeyError)):
        getattr(pure, name).selected_targets(bad, scopes)
    with pytest.raises((ValueError, TypeError, KeyError)):
        getattr(pure, name).selected_targets(options, ['foreign'])


def test_registry_credentials_are_separate_and_exact(pure):
    options, scopes = registry_case()
    selected = pure.registry.selected_targets(options, scopes)
    assert pure.registry.registry_credentials({}, selected, options['selected_registry_hosts']) == {}
    for method, fields in [('basic', {'username': 'user', 'password': 'pass'}),
                           ('bearer', {'token': 'test-token'})]:
        entry = dict(host='registry.example.com', repository='team/app', method=method, **fields)
        assert len(pure.registry.registry_credentials({'registry_auth': [entry]}, selected, options['selected_registry_hosts'])) == 1
        entry['repository'] = 'foreign/app'
        with pytest.raises(ValueError):
            pure.registry.registry_credentials({'registry_auth': [entry]}, selected, options['selected_registry_hosts'])
    options['registry_auth'] = []
    with pytest.raises(ValueError):
        pure.registry.selected_targets(options, scopes)


def test_ecs_source_binding_and_versioned_configuration(pure):
    options, scopes = ecs_case()
    assert pure.ecs_env.selected_targets(options, scopes)
    options['selected_aws_s3_sources'][0]['key'] = 'other.env'
    with pytest.raises(ValueError):
        pure.ecs_env.selected_targets(options, scopes)
    options, scopes = aws_config_case()
    del options['selected_aws_configuration_content'][0]['version']
    with pytest.raises(ValueError):
        pure.aws_config.selected_targets(options, scopes)


def test_ml_dockerfile_databricks_output_and_cloudformation(pure):
    storage = dict(service='blob', resource_id=AZ_SCOPE + '/resourceGroups/group/providers/Microsoft.Storage/storageAccounts/store123',
                   container='source', object='Dockerfile', format='text')
    asset = dict(resource_id=AZ_SCOPE + '/resourceGroups/group/providers/Microsoft.MachineLearningServices/workspaces/workspace/environments/python/versions/v1',
                 datastore='workspaceblobstore', storage=storage)
    assert pure.ml_asset.selected_targets({'selected_azure_ml_environment_versions': [asset]}, [AZ_SCOPE])['environment']
    asset['storage']['format'] = 'zip'
    with pytest.raises(ValueError):
        pure.ml_asset.selected_targets({'selected_azure_ml_environment_versions': [asset]}, [AZ_SCOPE])
    db = dict(workspace_resource_id=AZ_SCOPE + '/resourceGroups/group/providers/Microsoft.Databricks/workspaces/workspace1',
              job_id=1, parent_run_id=2, task_run_id=3, task_key='task', content='task_logs')
    assert pure.databricks.selected_targets({'selected_azure_databricks_task_outputs': [db]}, [AZ_SCOPE])
    db['task_run_id'] = 2
    with pytest.raises(ValueError):
        pure.databricks.selected_targets({'selected_azure_databricks_task_outputs': [db]}, [AZ_SCOPE])
    cf = dict(surface='cloudformation_template', scope=AWS_SCOPE,
              resource_id='arn:aws:cloudformation:us-east-1:123456789012:stack/App/abc123')
    assert pure.aws_config.selected_targets({'selected_aws_configuration_content': [cf]}, [AWS_SCOPE])
    cf['version'] = 1
    with pytest.raises(ValueError):
        pure.aws_config.selected_targets({'selected_aws_configuration_content': [cf]}, [AWS_SCOPE])


def test_workload_command_default_off_and_scope(pure):
    assert pure.workload.targets({}, [], [], 'aws') == []
    row = dict(scope=AWS_SCOPE, service='ecs',
               definition_arn='arn:aws:ecs:us-east-1:123456789012:task-definition/app:1')
    assert pure.workload.targets({'selected_aws_workload_commands': [row]}, [AWS_SCOPE], [], 'aws')
    with pytest.raises(ValueError):
        pure.workload.targets({'selected_aws_workload_commands': [row]}, [AWS_SCOPE], [], 'gcp')


@pytest.mark.parametrize('name,fixture', [('workerpool', workerpool_case), ('developerconnect', developerconnect_case)])
def test_gcp_new_source_selectors(pure, name, fixture):
    options, scopes = fixture()
    key, = options
    assert getattr(pure, name).selections(options[key], scopes[0])
    bad = copy.deepcopy(options[key])
    bad[0]['foreign'] = True
    with pytest.raises(ValueError):
        getattr(pure, name).selections(bad, scopes[0])
    with pytest.raises(ValueError):
        getattr(pure, name).selections(options[key], 'projects/foreign')


def bind_static_selector_peers(node):
    """Replace only the reviewed two-name peer imports with their pure bindings."""
    peers = {
        'aws_ecs_environment_file_secret_indicators': 'ecs_env',
        'aws_workload_referenced_source_indicators': 'workload_ref',
        'aws_build_deployment_referenced_source_indicators': 'build_ref',
    }
    class Bind(ast.NodeTransformer):
        def visit_ImportFrom(self, value):
            if value.level != 1 or value.module not in peers:
                return value
            assert [alias.name for alias in value.names] == ['source_target', 'OPTION']
            names = ', '.join(alias.asname or alias.name for alias in value.names)
            module = peers[value.module]
            return ast.parse(names + ' = peers.' + module + '.source_target, peers.' + module + '.OPTION').body[0]
    return Bind().visit(copy.deepcopy(node))


def test_copied_selector_ast_matches_native():
    native = {'registry': 'k8s_selected_registry_image_20261021',
              'flux': 'k8s_selected_flux_artifact_20261021',
              'ml_asset': 'azure_ml_selected_asset_secret_indicators',
              'databricks': 'azure_databricks_notebook_secret_indicators',
              'synapse': 'azure_synapse_selected_notebook_secret_indicators',
              'ecs_env': 'aws_ecs_environment_file_secret_indicators',
              'aws_config': 'aws_selected_configuration_secret_indicators',
              'workerpool': 'gcp_workerpool_image_native_20261021',
              'developerconnect': 'gcp_developerconnect_file_native_20261021'}
    pure_tree = ast.parse(PURE.read_text())
    for name, filename in native.items():
        path = ROOT / 'peaso/collectors' / (filename + '.py')
        source = ast.parse(path.read_text())
        factory = next(node for node in pure_tree.body if isinstance(node, ast.FunctionDef) and node.name == '_make_' + name)
        fn_name = 'selections' if name in ('workerpool', 'developerconnect') else 'selected_targets'
        native_fn = next(node for node in source.body if isinstance(node, ast.FunctionDef) and node.name == fn_name)
        copied_fn = next(node for node in factory.body if isinstance(node, ast.FunctionDef) and node.name == fn_name)
        assert ast.dump(bind_static_selector_peers(native_fn), include_attributes=False) == ast.dump(copied_fn, include_attributes=False)


def test_fresh_process_api_preflight_denies_native_imports_and_io():
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
for provider, auth, options, scopes, expected in cases:
    try:
        module.validate_connector(provider, auth, options, SimpleNamespace(auth_mode='local'), scopes=scopes)
        status = 200
    except Exception as exc:
        status = getattr(exc, 'status_code', None)
    assert status == expected, (provider, options, status, expected)
assert not any(k.startswith(('peaso.collectors', 'peaso.checks', 'peaso.engine', 'peaso.analysis',
                             'boto3', 'botocore', 'google.auth', 'azure.identity', 'kubernetes')) for k in sys.modules)
print('cold-preflight-ok', len(cases))
'''
    cases = []
    for provider, fixture in [('k8s', registry_case), ('k8s', flux_case), ('azure', ml_case),
                              ('azure', db_case), ('azure', synapse_case), ('aws', aws_config_case),
                              ('aws', ecs_case), ('gcp', workerpool_case), ('gcp', developerconnect_case)]:
        options, scopes = fixture()
        cases.append([provider, {}, options, scopes, 200])
        bad = copy.deepcopy(options)
        key = next(k for k in bad if k.startswith('selected_') and
                   (fixture != ecs_case or k == 'selected_aws_ecs_environment_files'))
        bad[key][0]['foreign_field'] = 'foreign'
        cases.append([provider, {}, bad, scopes, 422])
    options, scopes = registry_case()
    cases.append(['k8s', {'registry_auth': [dict(host='registry.example.com', repository='team/app', method='bearer', token='test-token')]}, copy.deepcopy(options), scopes, 200])
    options['registry_auth'] = []
    cases.append(['k8s', {}, options, scopes, 422])
    script = (script.replace('ROOT', str(ROOT)).replace('STAGE', str(ROOT / 'peaso/server'))
             .replace('VALIDATION', str(ROOT / 'peaso/server/validation.py'))
             .replace('CASES', json.dumps(cases)))
    result = subprocess.run([sys.executable, '-I', '-c', script], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert 'cold-preflight-ok' in result.stdout
