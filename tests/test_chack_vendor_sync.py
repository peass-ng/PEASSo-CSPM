"""scripts/sync_chack_vendor.py keeps the vendored chack helpers byte-identical to upstream."""
import hashlib
import json
from pathlib import Path
import shutil

import pytest

from scripts import sync_chack_vendor

VENDOR = Path(__file__).resolve().parents[1] / 'peaso/ai/_vendor/chack'
NEW_COMMIT = 'a' * 40


@pytest.fixture
def trees(tmp_path):
    vendor = tmp_path / 'vendor'
    shutil.copytree(VENDOR, vendor, ignore=shutil.ignore_patterns('__pycache__'))
    source = tmp_path / 'upstream'
    for name, entry in json.loads((vendor / 'provenance.json').read_text())['files'].items():
        target = source / entry['upstream_path']
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(vendor / name, target)
    return vendor, source


def test_current_copy_is_left_untouched(trees):
    vendor, source = trees
    before = {path.name: path.read_bytes() for path in vendor.rglob('*') if path.is_file()}
    assert sync_chack_vendor.stale_files(vendor, source) == []
    assert sync_chack_vendor.sync(vendor, source, NEW_COMMIT) == []
    assert {path.name: path.read_bytes() for path in vendor.rglob('*') if path.is_file()} == before


def test_upstream_change_is_copied_and_recorded(trees):
    vendor, source = trees
    upstream = source / 'chack_agent/config/thinking_effort.yaml'
    upstream.write_bytes(upstream.read_bytes() + b'  new-model: [low, high]\n')
    assert sync_chack_vendor.stale_files(vendor, source) == ['config/thinking_effort.yaml']

    assert sync_chack_vendor.sync(vendor, source, NEW_COMMIT) == ['config/thinking_effort.yaml']

    assert sync_chack_vendor.stale_files(vendor, source) == []
    manifest = json.loads((vendor / 'provenance.json').read_text())
    data = (vendor / 'config/thinking_effort.yaml').read_bytes()
    assert data == upstream.read_bytes()
    assert manifest['commit'] == NEW_COMMIT
    assert manifest['files']['config/thinking_effort.yaml'] == {
        'upstream_path': 'chack_agent/config/thinking_effort.yaml',
        'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
    notice = (vendor / 'LICENSE').read_bytes()
    assert NEW_COMMIT.encode() in notice
    assert manifest['license']['notice_sha256'] == hashlib.sha256(notice).hexdigest()


def test_missing_vendored_file_is_stale(trees):
    vendor, source = trees
    (vendor / 'model_aliases.py').unlink()
    assert sync_chack_vendor.stale_files(vendor, source) == ['model_aliases.py']
    sync_chack_vendor.sync(vendor, source, NEW_COMMIT)
    assert (vendor / 'model_aliases.py').read_bytes() == (source / 'chack_agent/model_aliases.py').read_bytes()


def test_rejects_non_sha_commit(trees):
    vendor, source = trees
    with pytest.raises(ValueError):
        sync_chack_vendor.sync(vendor, source, 'master')
