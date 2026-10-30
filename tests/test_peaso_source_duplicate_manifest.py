"""Canonical bytes and every distinct file survive the exact export optimization."""
import gzip,hashlib,json,zipfile
from pathlib import Path
import pytest
from scripts import peaso_deploy as deploy
PLAIN='peaso/rulepacks/upstream_manifest.json';GZIP=PLAIN+'.gz'

def test_only_byte_identical_exact_generated_companion_is_omitted():
 raw=b'{"checks":[]}\n';compressed=gzip.compress(raw,mtime=0)
 source={PLAIN:raw,GZIP:compressed,'tests/fixtures/keep.json.gz':compressed,'peaso/privesc/keep.yaml':b'techniques: []\n'}
 before=dict(source);deploy._omit_verified_duplicate_manifest(source)
 assert source=={k:v for k,v in before.items()if k!=GZIP}
 assert source[PLAIN]==raw and before[GZIP]==compressed

@pytest.mark.parametrize('data',[b'not gzip',gzip.compress(b'{"checks":[1]}',mtime=0),gzip.compress(b'{"checks":[]}\nextra',mtime=0),gzip.compress(b'{"checks":[]}\n',mtime=0)[:-4]])
def test_malformed_stale_or_longer_companion_cannot_silently_disappear(data):
 source={PLAIN:b'{"checks":[]}\n',GZIP:data};before=dict(source)
 with pytest.raises(RuntimeError,match='upstream manifest gzip'):deploy._omit_verified_duplicate_manifest(source)
 assert source==before

@pytest.mark.parametrize('name',[PLAIN,GZIP])
def test_unique_provenance_input_is_never_omitted(name):
 source={name:b'distinct bytes'};before=dict(source);deploy._omit_verified_duplicate_manifest(source);assert source==before


@pytest.mark.parametrize('changed',[PLAIN,GZIP])
def test_source_pair_changed_after_capture_aborts_export(tmp_path,changed):
 raw=b'{"checks":[]}\n';source={PLAIN:raw,GZIP:gzip.compress(raw,mtime=0)}
 for name,content in source.items():
  path=tmp_path/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(content)
 (tmp_path/changed).write_bytes(b'{"checks":[1]}\n'if changed==PLAIN else gzip.compress(raw,mtime=1))
 before=dict(source)
 with pytest.raises(RuntimeError,match='changed during freeze'):deploy._omit_verified_duplicate_manifest(source,tmp_path)
 assert source==before
