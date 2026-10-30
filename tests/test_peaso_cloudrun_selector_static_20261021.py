"""Exact native grammar parity and cold API input validation boundaries."""
import ast
from copy import deepcopy
import importlib
import os
from pathlib import Path
import re
import subprocess
import sys
from types import SimpleNamespace
import pytest

ROOT = Path(os.environ.get('PEASO_SELECTOR_BASE', Path(__file__).resolve().parents[1]))
CANDIDATE = Path(os.environ.get('PEASO_SELECTOR_CANDIDATE', Path(__file__).parent if (Path(__file__).parent/'peaso').is_dir() else ROOT))
import peaso.server
peaso.server.__path__.insert(0, str(CANDIDATE / 'peaso/server'))
static = importlib.import_module('peaso.server.cloudrun_job_selection_static_20261021')
grammar = importlib.import_module('peaso.server.cloudrun_image_grammar_static_20261021')


def nodes(path):
    result = {}
    for node in ast.parse(path.read_text()).body:
        name = getattr(node, 'name', None)
        if isinstance(node, ast.Assign):
            name = getattr(node.targets[0], 'id', None)
        if name:
            result[name] = node
    return result


def native_reference():
    assoc = {'re': re}
    tree = nodes(ROOT/'peaso/checks/gcp_workload_image_source_association_20261020.py')
    kept = nodes(Path(grammar.__file__))
    for name, node in tree.items():
        if name in kept:
            exec(compile(ast.Module(body=[node], type_ignores=[]), '<native-grammar>', 'exec'), assoc)
    env = {'deepcopy': deepcopy, 're': re, 'association': SimpleNamespace(**assoc)}
    tree = nodes(ROOT/'peaso/collectors/gcp_cloudrun_v2_job_declared_images_20261020.py')
    for name in ('MAX_SELECTIONS', '_require', 'normalize_selection'):
        exec(compile(ast.Module(body=[tree[name]], type_ignores=[]), '<native-selector>', 'exec'), env)
    env['source'] = SimpleNamespace(normalize_selection=env['normalize_selection'])
    env['OPTION'] = static.OPTION
    tree = nodes(ROOT/'peaso/collectors/gcp_cloudrun_job_image_runtime_20261020.py')
    exec(compile(ast.Module(body=[tree['validate_options']], type_ignores=[]), '<native-preflight>', 'exec'), env)
    return env['validate_options']


def selection():
    digest = 'sha256:' + 'a'*64
    return {'api_version': 'run.googleapis.com/v2', 'kind': 'Job', 'project_id': 'audit-project',
            'resource_name': 'projects/audit-project/locations/europe-west1/jobs/audit-job',
            'resource_uid': '12345678-1234-4123-8123-123456789abc', 'container_name': 'worker',
            'digest': digest, 'repository': 'projects/audit-project/locations/europe-west1/repositories/containers',
            'immutable_reference': 'europe-west1-docker.pkg.dev/audit-project/containers/worker@'+digest}


def outcome(fn, options, scopes):
    before = deepcopy(options)
    try:
        result = ('ok', fn(options, scopes))
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        result = (type(exc).__name__ if type(exc).__name__ != '_Unknown' else '_Unknown', str(exc))
    assert options == before
    return result


@pytest.mark.parametrize('change', [
    'valid', 'disabled', 'bad_bool', 'empty', 'five', 'duplicate', 'discovery', 'two_scopes',
    'foreign_scope', 'foreign_project', 'foreign_digest', 'bad_uuid', 'mutable', 'unknown_field',
    'wrong_kind', 'wrong_api', 'wrong_container', 'bad_name', 'repository_mismatch', 'no_option',
])
def test_native_parity_and_immutable_inputs(change):
    item = selection()
    options, scopes = {static.OPTION: [item], 'content_secret_scans': True}, ['projects/audit-project']
    if change == 'disabled': options['content_secret_scans'] = False
    elif change == 'bad_bool': options['content_secret_scans'] = 'true'
    elif change == 'empty': options[static.OPTION] = []
    elif change == 'five': options[static.OPTION] *= 5
    elif change == 'duplicate': options[static.OPTION] *= 2
    elif change == 'discovery': options['all_projects'] = True
    elif change == 'two_scopes': scopes *= 2
    elif change == 'foreign_scope': scopes = ['projects/foreign-project']
    elif change == 'foreign_project': item['project_id'] = 'foreign-project'
    elif change == 'foreign_digest': item['digest'] = 'sha256:'+'b'*64
    elif change == 'bad_uuid': item['resource_uid'] = 'not-a-uuid'
    elif change == 'mutable': item['immutable_reference'] = item['immutable_reference'].split('@')[0]+':latest'
    elif change == 'unknown_field': item['credential'] = 'synthetic-unknown'
    elif change == 'wrong_kind': item['kind'] = 'Service'
    elif change == 'wrong_api': item['api_version'] = 'run.googleapis.com/v1'
    elif change == 'wrong_container': item['container_name'] = '../worker'
    elif change == 'bad_name': item['resource_name'] += '/extra'
    elif change == 'repository_mismatch': item['repository'] += 'other'
    elif change == 'no_option': options = {}
    assert outcome(static.validate_options, options, scopes) == outcome(native_reference(), options, scopes)
    if change in ('valid', 'disabled'):
        result = static.validate_options(options, scopes)
        assert result == [item] and result is not options[static.OPTION] and result[0] is not item


def test_cold_selector_and_connector_rejection_without_native_or_network():
    script = r'''
import sys, importlib.abc, socket
sys.path.insert(0, ROOT)
import peaso.server
peaso.server.__path__.insert(0, OVERLAY)
sys.modules.pop('peaso.server.validation', None)
class Block(importlib.abc.MetaPathFinder):
 def find_spec(self, name, path=None, target=None):
  if name in ('peaso.collectors','peaso.checks','peaso.engine','peaso.analysis') or name.startswith(('peaso.collectors.','peaso.checks.')):
   raise ImportError('unexpected native import: '+name)
sys.meta_path.insert(0,Block())
def no_socket(*args,**kwargs): raise AssertionError('unexpected network')
socket.socket = no_socket
from peaso.server.cloudrun_job_selection_static_20261021 import validate_options
assert validate_options(OPTIONS, ['projects/audit-project']) == OPTIONS['selected_cloudrun_job_declared_images']
from peaso.server.validation import validate_connector
from types import SimpleNamespace
for mode in ('local','cognito'):
 for enabled in (True,False):
  opts={**OPTIONS,'image_vulnerability_scans':enabled,'content_secret_scans':False}
  validate_connector('gcp', {'method':'token','token':'synthetic-offline'}, opts, SimpleNamespace(auth_mode=mode), scopes=['projects/audit-project'])
from fastapi import HTTPException
for provider, options in [('gcp', {'selected_cloudrun_job_declared_images': []}), ('aws', OPTIONS)]:
 try: validate_connector(provider, {}, options, None, scopes=['projects/audit-project'])
 except HTTPException as exc: assert exc.status_code == 422
 else: raise AssertionError('bad selector/provider admitted')
assert not any(name in sys.modules for name in ('peaso.collectors','peaso.checks','peaso.engine','peaso.analysis'))
'''
    prefix = 'ROOT='+repr(str(ROOT))+'\nOVERLAY='+repr(str(CANDIDATE/'peaso/server'))+'\nOPTIONS='+repr({static.OPTION:[selection()]})+'\n'
    result = subprocess.run([sys.executable, '-c', prefix+script], text=True, capture_output=True,
                            env={**os.environ, 'PYTHONDONTWRITEBYTECODE':'1'}, timeout=30)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('provider, flag, with_selector, accepted', [
    ('gcp', True, True, True), ('gcp', False, True, True), ('gcp', False, False, True),
    ('gcp', True, False, False), ('gcp', 'true', True, False),
    ('aws', True, True, False), ('azure', True, True, False), ('k8s', True, True, False),
])
def test_independent_image_opt_in(provider, flag, with_selector, accepted):
    options = {'image_vulnerability_scans': flag, 'content_secret_scans': False}
    if with_selector: options[static.OPTION] = [selection()]
    original = deepcopy(options)
    if accepted: static.validate_image_options(provider, options, ['projects/audit-project'])
    else:
        with pytest.raises(ValueError):
            static.validate_image_options(provider, options, ['projects/audit-project'])
    assert options == original


@pytest.mark.parametrize('case', ['absent','valid','bad_provider','no_inventory','future',
                                  'too_wide','bad_class','duplicate_class','bad_cap','unknown_policy'])
def test_audit_parser_exact_native_behavior(case):
    from datetime import datetime, timezone
    candidate = importlib.import_module('peaso.server.gcp_audit_options_static_20261021')
    tree = nodes(ROOT/'peaso/collectors/gcp_audit_native.py')
    env = {'datetime':datetime,'timezone':timezone}
    for name in ('CLASSES','_instant','validate_audit_options'):
        exec(compile(ast.Module(body=[tree[name]], type_ignores=[]), '<native-audit-parser>', 'exec'), env)
    provider = 'gcp'
    opts = {'inventories':['audit_log'], 'audit_window':{'start':'2020-01-01T00:00:00Z',
            'end':'2020-01-01T01:00:00Z','classes':['activity']},
            'max_pages':1,'max_calls':1,'max_resources':1}
    if case=='absent':opts={}
    elif case=='bad_provider':provider='aws'
    elif case=='no_inventory':opts['inventories']=[]
    elif case=='future':opts['audit_window']['end']='2999-01-01T01:00:00Z'
    elif case=='too_wide':opts['audit_window']['end']='2020-01-03T01:00:00Z'
    elif case=='bad_class':opts['audit_window']['classes']=['unknown']
    elif case=='duplicate_class':opts['audit_window']['classes']*=2
    elif case=='bad_cap':opts['max_calls']=True
    elif case=='unknown_policy':opts['audit_detection_policy']={'unknown':True}
    def bound(fn):
        def invoke(options, ignored):return fn(provider,options)
        return invoke
    assert outcome(bound(candidate.validate_audit_options),opts,[]) == outcome(bound(env['validate_audit_options']),opts,[])
