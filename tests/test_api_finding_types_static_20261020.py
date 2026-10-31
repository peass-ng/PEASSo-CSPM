"""Exact metadata parity; no provider collection, external auth or findings."""
from pathlib import Path
import subprocess
import sys

import pytest

from peaso import presentation_metadata_20261020 as static

ROOT = Path(__file__).resolve().parents[1]


def test_fresh_api_annotations_do_not_import_native_registry():
    program = '''
import importlib.abc,sys
class BlockNative(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  if fullname=='peaso.checks' or fullname.startswith('peaso.checks.'):
   raise AssertionError('native registry reached')
sys.meta_path.insert(0,BlockNative())
from peaso.server.finding_types_static_20261020 import install,ALIASES
from peaso.finding_types import annotate
install();install()
assert annotate({'check_id':'analysis.internet_exposure'})['finding_type']=='network'
assert annotate({'check_id':'aws.iam.root_mfa'})['finding_type']=='authentication'
assert annotate({'check_id':'unknown','category':'privesc'})['finding_type']=='permissions'
assert annotate({'check_id':'unknown','finding_type':'network'})['finding_type']=='network'
assert annotate({'check_id':'unknown','finding_type':'not-real'})['finding_type']=='unclassified'
for alias in ALIASES: assert annotate({'check_id':alias})['finding_type']!='unclassified'
assert 'peaso.checks' not in sys.modules
'''
    subprocess.run([sys.executable, '-c', program], cwd=ROOT,
                   capture_output=True, text=True, check=True, timeout=30)


@pytest.mark.parametrize('damage', ['oversize', 'missing'])
def test_tampered_registry_fails_closed(tmp_path, monkeypatch, damage):
    target=tmp_path/'taxonomy.json'
    if damage=='oversize': target.write_bytes(b' '*(static.MAX_REGISTRY_BYTES+1))
    monkeypatch.setattr(static,'REGISTRY_PATH',target)
    static._checks.cache_clear()
    try:
        with pytest.raises((OSError,ValueError)): static.type_for('analysis.internet_exposure')
    finally: static._checks.cache_clear()


def test_result_roster_and_aliases_are_immutable():
    with pytest.raises(TypeError): static.ALIASES['x']='y'
    with pytest.raises(TypeError): static._checks()['x']='network'


def test_api_creation_then_real_native_catalog_in_same_process():
    program = '''
from pathlib import Path
import tempfile
from peaso.server.app import create_app
from peaso.server.config import Settings
import json
from peaso.checks import CHECK_ALIASES,CHECKS
from peaso.finding_types import type_for,registry
with tempfile.TemporaryDirectory() as tmp:
 p=Path(tmp)
 app=create_app(Settings(state_dir=p/'state',identity_dir=p/'identity'))
 from peaso.engine import get_catalog
 from peaso.checks import CHECKS
 catalog=get_catalog()
 assert len(CHECKS)>0
 assert len(catalog['checks'])>0
'''
    result=subprocess.run([sys.executable,'-c',program],cwd=ROOT,capture_output=True,text=True,timeout=180)
    assert result.returncode==0, result.stderr


@pytest.mark.parametrize('damage',['oversize','missing'])
def test_scope_tamper_rejected(tmp_path,monkeypatch,damage):
    target=tmp_path/'scope.json'
    if damage=='oversize':target.write_bytes(b' '*(static.MAX_REGISTRY_BYTES+1))
    monkeypatch.setattr(static,'SCOPE_PATH',target);static._scope.cache_clear()
    try:
        with pytest.raises((OSError,ValueError)):static.includes_in_hacktricks('analysis.internet_exposure')
    finally:static._scope.cache_clear()
