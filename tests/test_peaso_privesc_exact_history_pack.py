"""Lossless runtime history keeps the exact archived bytes and rejects substitutions."""
import base64
import gzip
import hashlib
import json
from pathlib import Path
import struct
import zipfile

import pytest

from peaso.privesc import versioned_catalog as catalog
from scripts.peaso_build_privesc_history_pack import declarations


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def test_every_packed_tar_block_and_manifest_matches_pinned_original():
    packed = catalog.RUNTIME_HISTORY_PACK.read_bytes()
    assert _sha(packed) == catalog.RUNTIME_HISTORY_SHA256
    with zipfile.ZipFile(catalog.RUNTIME_HISTORY_PACK) as archive:
        assert set(archive.namelist()) == {
            'index.json', 'blocks.bin', 'references.bin', 'manifests.bin'}
        index = json.loads(archive.read('index.json'))
        blocks = archive.read('blocks.bin')
        refs = archive.read('references.bin')
        manifests = archive.read('manifests.bin')
    assert index['schema'] == 'privesc-exact-history-v1'
    assert len(index['versions']) == len(declarations()) == 137
    assert len(blocks) == 512 * len(index['block_sha256'])
    assert all(_sha(blocks[n*512:(n+1)*512]) == digest
               for n, digest in enumerate(index['block_sha256']))
    for manifest_path, archive_path, manifest_digest, archive_digest, *_ in declarations():
        row = index['versions'][archive_path.name]
        assert row['archive_sha256'] == archive_digest
        assert row['manifest_name'] == manifest_path.name
        assert row['manifest_sha256'] == manifest_digest
        offset, count = row['reference_offset'], row['reference_count']
        ids = struct.unpack_from('<' + 'H' * count, refs, offset)
        raw = b''.join(blocks[n*512:(n+1)*512] for n in ids)
        original = archive_path.read_bytes()
        assert raw == gzip.decompress(original)
        assert base64.b64decode(row['header']) == original[:len(base64.b64decode(row['header']))]
        assert base64.b64decode(row['trailer']) == original[-8:]
        start, size = row['manifest_offset'], row['manifest_size']
        assert manifests[start:start+size] == manifest_path.read_bytes()
        assert _sha(original) == archive_digest


def test_mwaa_exclusion_reason_update_keeps_previous_current_binding():
    current = catalog.current_binding()
    previous = dict(current,
                    manifest_sha256=catalog.MWAA_TOKEN_REASON_685_PREVIOUS_MANIFEST,
                    effective_tree_sha256=catalog.MWAA_TOKEN_REASON_685_PREVIOUS_TREE)
    ids = ['aws-mwaa-s3-putobject-dag']
    current_entries, current_status = catalog.lookup_entries(ids, current)
    previous_entries, previous_status = catalog.lookup_entries(ids, previous)
    assert current_status == 'exact_strict_privesc'
    assert previous_status == 'exact_previous_current'
    assert current_entries == previous_entries


def test_lineage_resolution_keeps_previous_current_binding():
    current = catalog.current_binding()
    previous = dict(current,
                    manifest_sha256=catalog.LINEAGE_685_PREVIOUS_MANIFEST,
                    effective_tree_sha256=catalog.LINEAGE_685_PREVIOUS_TREE)
    ids = ['aws-mwaa-s3-putobject-dag']
    current_entries, current_status = catalog.lookup_entries(ids, current)
    previous_entries, previous_status = catalog.lookup_entries(ids, previous)
    assert current_status == 'exact_strict_privesc'
    assert previous_status == 'exact_previous_current'
    assert current_entries == previous_entries


def test_missing_archive_and_manifest_use_exact_pinned_pack(tmp_path, monkeypatch):
    row = next(item for item in declarations()
               if item[1].name == 'prior-bulk-691-final-two-role-effects-catalog.tar.gz')
    manifest, archive, manifest_sha, archive_sha, tree, count, excluded = row
    expected = catalog._verified_archived_current(*row)
    local_pack = tmp_path / catalog.RUNTIME_HISTORY_PACK.name
    local_pack.write_bytes(catalog.RUNTIME_HISTORY_PACK.read_bytes())
    monkeypatch.setattr(catalog, 'RUNTIME_HISTORY_PACK', local_pack)
    local_manifest, local_archive = tmp_path / manifest.name, tmp_path / archive.name
    recovered = catalog._verified_archived_current(local_manifest, local_archive,
                                                    manifest_sha, archive_sha, tree, count, excluded)
    assert recovered == expected


def test_historical_safe_loaders_preserve_complete_entries_and_order(monkeypatch):
    import yaml
    from peaso.privesc import schema
    if not hasattr(yaml, 'CSafeLoader'):
        pytest.skip('LibYAML safe constructor is unavailable')
    row = next(item for item in declarations()
               if item[1].name == 'prior-bulk-691-final-two-role-effects-catalog.tar.gz')
    monkeypatch.setattr(schema, 'SAFE_YAML_LOADER', yaml.SafeLoader)
    expected_current = catalog._verified_archived_current(*row)
    catalog._verified_prior.cache_clear()
    expected_prior = catalog._verified_prior()
    monkeypatch.setattr(schema, 'SAFE_YAML_LOADER', yaml.CSafeLoader)
    actual_current = catalog._verified_archived_current(*row)
    catalog._verified_prior.cache_clear()
    actual_prior = catalog._verified_prior()
    catalog._verified_prior.cache_clear()
    assert actual_current == expected_current
    assert list(actual_current) == list(expected_current)
    assert actual_prior == expected_prior
    assert list(actual_prior[0]) == list(expected_prior[0])


@pytest.mark.parametrize('missing', ['archive', 'manifest', 'both'])
def test_precanonical_685_binding_recovers_only_exact_pinned_history(tmp_path, monkeypatch, missing):
    row = next(item for item in declarations()
               if item[1].name == 'prior-reviewed-685-99a-catalog.tar.gz')
    manifest, archive, manifest_sha, archive_sha, tree, count, excluded = row
    local_pack = tmp_path / catalog.RUNTIME_HISTORY_PACK.name
    local_pack.write_bytes(catalog.RUNTIME_HISTORY_PACK.read_bytes())
    monkeypatch.setattr(catalog, 'RUNTIME_HISTORY_PACK', local_pack)
    local_manifest, local_archive = tmp_path / manifest.name, tmp_path / archive.name
    if missing == 'archive':
        local_manifest.write_bytes(manifest.read_bytes())
    elif missing == 'manifest':
        local_archive.write_bytes(archive.read_bytes())
    recovered = catalog._verified_archived_current(
        local_manifest, local_archive, manifest_sha, archive_sha, tree, count, excluded)
    assert len(recovered) == 685
    assert recovered['azure-apim-developer-portal-sso-external-principal']['source'].endswith(
        '#microsoftapimanagementserviceuserstokenaction')


@pytest.mark.parametrize('target', ['pack', 'archive', 'manifest'])
def test_pack_and_changed_present_originals_fail_closed(tmp_path, monkeypatch, target):
    row = next(item for item in declarations()
               if item[1].name == 'prior-bulk-691-final-two-role-effects-catalog.tar.gz')
    manifest, archive, manifest_sha, archive_sha, *_ = row
    local_pack = tmp_path / catalog.RUNTIME_HISTORY_PACK.name
    local_pack.write_bytes(catalog.RUNTIME_HISTORY_PACK.read_bytes())
    monkeypatch.setattr(catalog, 'RUNTIME_HISTORY_PACK', local_pack)
    local_manifest, local_archive = tmp_path / manifest.name, tmp_path / archive.name
    if target == 'pack':
        local_pack.write_bytes(local_pack.read_bytes() + b'changed')
    elif target == 'archive':
        local_archive.write_bytes(archive.read_bytes() + b'changed')
    else:
        local_manifest.write_bytes(manifest.read_bytes() + b'changed')
    with pytest.raises(ValueError):
        catalog._history_original_pair(local_manifest, local_archive, manifest_sha, archive_sha)


def _history_source_bytes():
    root = Path(__file__).resolve().parents[1]
    names = {'peaso/privesc/versioned_catalog.py',
             'peaso/privesc/catalog_versions/runtime-history-v1.zip'}
    for manifest, archive, *_ in declarations():
        names.add(manifest.relative_to(root).as_posix())
        names.add(archive.relative_to(root).as_posix())
    return root, {name: (root / name).read_bytes() for name in names}


def test_source_freeze_omits_only_verified_reconstructible_originals():
    from scripts.peaso_deploy import _omit_verified_reconstructible_privesc_history
    root, source = _history_source_bytes()
    omitted = _omit_verified_reconstructible_privesc_history(source, root)
    # 137 exact versions (4d878747 added the prior-reviewed-685 APIM catalog), two files each.
    assert len(omitted) == 2 * len(declarations()) == 274
    assert set(source) == {'peaso/privesc/versioned_catalog.py',
                           'peaso/privesc/catalog_versions/runtime-history-v1.zip'}


@pytest.mark.parametrize('target', ['pack', 'original'])
def test_source_freeze_rejects_changed_history_bytes(target):
    from scripts.peaso_deploy import _omit_verified_reconstructible_privesc_history
    root, source = _history_source_bytes()
    name = ('peaso/privesc/catalog_versions/runtime-history-v1.zip' if target == 'pack'
            else 'peaso/privesc/catalog_versions/prior-bulk-691-final-two-role-effects-catalog.tar.gz')
    source[name] += b'changed'
    with pytest.raises(RuntimeError):
        _omit_verified_reconstructible_privesc_history(source, root)
