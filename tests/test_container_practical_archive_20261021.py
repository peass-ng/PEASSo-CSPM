"""Hermetic file-backed image fixtures and archive boundary regression."""
import io
import json
import os
from pathlib import Path
import tarfile

import pytest

from peaso import container_image_archive_20261020 as archive
from peaso import trivy_container_runner_20261020 as runner


def wire(value):
    return json.dumps(value, separators=(',', ':')).encode()


def small_image(tmp_path, layer_entries):
    """Build an independently hashed image from synthetic tar metadata."""
    layers = []
    for index, entries in enumerate(layer_entries):
        layer = tmp_path / f'small-{index}.tar'
        with tarfile.open(layer, 'w', format=tarfile.USTAR_FORMAT) as tar:
            for name, kind, data, major, minor, link in entries:
                item = tarfile.TarInfo(name)
                item.type, item.devmajor, item.devminor, item.linkname = kind, major, minor, link
                item.size = len(data)
                tar.addfile(item, io.BytesIO(data) if data else None)
        layers.append(layer)
    config = wire({'os': 'linux', 'architecture': 'amd64',
                   'rootfs': {'type': 'layers',
                              'diff_ids': [archive.sha(layer.read_bytes()) for layer in layers]}})
    manifest = wire({'schemaVersion': 2, 'mediaType': archive.OCI,
                     'config': {'mediaType': 'application/vnd.oci.image.config.v1+json',
                                'digest': archive.sha(config), 'size': len(config)},
                     'layers': [{'mediaType': 'application/vnd.oci.image.layer.v1.tar',
                                 'digest': archive.sha(layer.read_bytes()), 'size': layer.stat().st_size}
                                for layer in layers]})
    digest = archive.sha(manifest)
    image_identity = {'provider': 'aws', 'scope': '123456789012/us-east-1',
                      'immutable_reference': '123456789012.dkr.ecr.us-east-1.amazonaws.com/example@' + digest,
                      'manifest_digest': digest, 'config_digest': archive.sha(config)}
    return image_identity, manifest, config, layers


def image(tmp_path, *, bad=None):
    layer = tmp_path / 'source.tar'
    with tarfile.open(layer, 'w', format=tarfile.USTAR_FORMAT) as tar:
        def add(name, kind, data=b'', link=''):
            item = tarfile.TarInfo(name)
            item.type, item.linkname = kind, link
            if kind == tarfile.REGTYPE:
                item.size = len(data)
                tar.addfile(item, io.BytesIO(data))
            else:
                tar.addfile(item)
        add('etc/', tarfile.DIRTYPE)
        add('etc/os-release', tarfile.REGTYPE, b'ID=alpine\nVERSION_ID=3.22.0\n')
        add('usr/', tarfile.DIRTYPE)
        add('usr/lib/', tarfile.DIRTYPE)
        add('usr/lib/libc.so', tarfile.REGTYPE, b'library')
        add('lib', tarfile.SYMTYPE, link='usr/lib')
        add('lib64', tarfile.SYMTYPE, link='/usr/lib')
        add('usr/lib/libc-copy.so', tarfile.LNKTYPE, link='usr/lib/libc.so')
        add('usr/lib/relative.so', tarfile.SYMTYPE, link='../lib/libc.so')
        if bad == 'escape':
            add('escape', tarfile.SYMTYPE, link='../../private')
        if bad == 'special':
            add('device', tarfile.CHRTYPE)
        if bad == 'traversal':
            add('../outside', tarfile.REGTYPE, b'bad')
        if bad == 'hardescape':
            add('bad-hardlink', tarfile.LNKTYPE, link='../../outside')
        # Incompressible source > the old 8 MiB per-layer cap.
        add('usr/lib/big.bin', tarfile.REGTYPE, os.urandom(9 * 1024 * 1024))
    raw = layer.read_bytes()
    config = wire({'os': 'linux', 'architecture': 'amd64',
        'rootfs': {'type': 'layers', 'diff_ids': [archive.sha(raw)]}})
    manifest = wire({'schemaVersion': 2, 'mediaType': archive.OCI,
        'config': {'mediaType': 'application/vnd.oci.image.config.v1+json',
                   'digest': archive.sha(config), 'size': len(config)},
        'layers': [{'mediaType': 'application/vnd.oci.image.layer.v1.tar',
                    'digest': archive.sha(raw), 'size': len(raw)}]})
    digest = archive.sha(manifest)
    identity = {'provider': 'aws', 'scope': '123456789012/us-east-1',
        'immutable_reference': '123456789012.dkr.ecr.us-east-1.amazonaws.com/example@' + digest,
        'manifest_digest': digest, 'config_digest': archive.sha(config)}
    return identity, manifest, config, layer


def test_file_backed_ordinary_linux_and_bytes_compatibility(tmp_path):
    identity, manifest, config, layer = image(tmp_path)
    assert layer.stat().st_size > 8 * 1024 * 1024
    proof = archive.write_archive(tmp_path / 'docker.tar', identity, manifest, config,
                                  [layer], archive_format='docker')
    assert proof['members'] == 10 and proof['expanded_bytes'] > 8 * 1024 * 1024
    assert not list(tmp_path.glob('peaso-image-layers-*'))
    with tarfile.open(tmp_path / 'docker.tar') as tar:
        assert tar.extractfile('layer-0/layer.tar').read() == layer.read_bytes()
    proof = archive.write_archive(tmp_path / 'oci.tar', identity, manifest, config,
                                  [layer], archive_format='oci')
    assert proof['format'] == 'oci'
    archive.validate(identity, manifest, config, [layer.read_bytes()])


def test_report_clean_and_finding_states(tmp_path):
    identity, _, config, _ = image(tmp_path)
    diff_ids = archive.decode(config)['rootfs']['diff_ids']
    base = {'SchemaVersion': 2, 'ArtifactType': 'container_image',
            'Metadata': {'ImageID': identity['config_digest'], 'DiffIDs': diff_ids},
            'Results': [{'Class': 'os-pkgs', 'Type': 'alpine', 'Target': 'fixture',
                         'Packages': [{'Name': 'fixture'}], 'Vulnerabilities': []}]}
    database = {'fresh': True}
    clean = runner.parse_report(wire(base), 0, identity, diff_ids=diff_ids, database=database)
    assert clean['status'] == 'PASS' and clean['complete']
    base['Results'][0]['Vulnerabilities'] = [{'VulnerabilityID': 'CVE-2026-12345',
        'PkgName': 'fixture', 'InstalledVersion': '1.0', 'FixedVersion': '1.1',
        'Status': 'fixed', 'Severity': 'HIGH'}]
    finding = runner.parse_report(wire(base), 0, identity, diff_ids=diff_ids, database=database)
    assert finding['status'] == 'FAIL' and finding['complete'] and len(finding['findings']) == 1


@pytest.mark.parametrize('bad,reason', [('escape', 'image_path_escape'),
                                        ('special', 'unsupported_tar_member'),
                                        ('traversal', 'unsafe_image_path'),
                                        ('hardescape', 'unsafe_hardlink_target')])
def test_unsafe_member_rejected_and_cleaned(tmp_path, bad, reason):
    args = image(tmp_path, bad=bad)
    output = tmp_path / 'output.tar'
    with pytest.raises(ValueError, match=reason):
        archive.write_archive(output, *args[:3], [args[3]], archive_format='docker')
    assert not output.exists() and not list(tmp_path.glob('peaso-image-layers-*'))


def test_tamper_cancel_and_limits(tmp_path, monkeypatch):
    identity, manifest, config, layer = image(tmp_path)
    with layer.open('r+b') as stream:
        stream.seek(1024)
        stream.write(b'changed')
    with pytest.raises(ValueError, match='layer_descriptor_mismatch'):
        archive.validate(identity, manifest, config, [layer])
    identity, manifest, config, layer = image(tmp_path)
    def cancel():
        raise RuntimeError('cancelled')
    with pytest.raises(RuntimeError, match='cancelled'):
        archive.write_archive(tmp_path / 'cancel.tar', identity, manifest, config,
                              [layer], check=cancel)
    assert not (tmp_path / 'cancel.tar').exists()
    monkeypatch.setattr(archive, 'MAX_EXPANDED', 8 * 1024 * 1024)
    with pytest.raises(ValueError, match='expanded_image_bound'):
        archive.validate(identity, manifest, config, [layer])


def test_source_symlink_refused(tmp_path):
    identity, manifest, config, layer = image(tmp_path)
    link = tmp_path / 'source-link.tar'
    link.symlink_to(layer)
    with pytest.raises(ValueError, match='owned_regular_layer_required'):
        archive.validate(identity, manifest, config, [link])


def test_virtual_files_and_bounded_readers(tmp_path):
    identity, manifest, config, layer = image(tmp_path)
    selected = {}
    def collect(name, reader, size, layer_index):
        assert layer_index == 0
        if size < 100:
            selected[name] = reader.read()
            assert reader.read() == b''
    proof = archive.visit_files(identity, manifest, config, [layer], collect)
    assert proof['visited_files'] == 4 and proof['links_seen'] == 4 and proof['links_skipped'] == 3
    assert selected['etc/os-release'].startswith(b'ID=alpine')
    assert selected['usr/lib/libc-copy.so'] == b'library'
    assert 'lib' not in selected and 'lib64' not in selected
    assert not list(tmp_path.glob('peaso-image-visit-*'))


@pytest.mark.parametrize('archive_format', ['oci', 'docker'])
def test_standard_character_devices_validate_build_and_shadow_files(tmp_path, archive_format):
    regular = lambda name, data: (name, tarfile.REGTYPE, data, 0, 0, '')
    devices = [(name, tarfile.CHRTYPE, b'', major, minor, '') for name, major, minor in (
        ('dev/console', 5, 1), ('dev/null', 1, 3), ('dev/random', 1, 8),
        ('dev/urandom', 1, 9), ('dev/zero', 1, 5))]
    args = small_image(tmp_path, [[('dev/', tarfile.DIRTYPE, b'', 0, 0, ''),
                                   regular('dev/null', b'old secret'),
                                   regular('dev/zero', b'old zero'),
                                   regular('etc/os-release', b'ID=alpine\n')],
                                  devices + [regular('etc/updated', b'new content')]])
    image_identity, manifest, config, layers = args
    validated, _, budget = archive.validate(image_identity, manifest, config, layers)
    assert validated['mediaType'] == archive.OCI
    assert budget[1] == 10
    seen = {}
    visit = archive.visit_files(image_identity, manifest, config, layers,
                                lambda name, reader, size, index:
                                seen.setdefault(name, (reader.read(), size, index)))
    assert seen == {'etc/os-release': (b'ID=alpine\n', 10, 0),
                    'etc/updated': (b'new content', 11, 1)}
    assert visit['visited_files'] == 2
    output = tmp_path / f'standard-{archive_format}.tar'
    proof = archive.write_archive(output, image_identity, manifest, config, layers,
                                  archive_format=archive_format)
    assert proof['format'] == archive_format and proof['members'] == 10
    with tarfile.open(output) as tar:
        if archive_format == 'oci':
            names = {'oci-layout', 'index.json'}
            names.update('blobs/sha256/' + digest[7:] for digest in
                         [image_identity['manifest_digest'], image_identity['config_digest']])
            names.update('blobs/sha256/' + archive.sha(layer.read_bytes())[7:] for layer in layers)
        else:
            names = {'manifest.json', image_identity['config_digest'][7:] + '.json',
                     'layer-0/layer.tar', 'layer-1/layer.tar'}
        assert {member.name for member in tar} == names
    assert not (tmp_path / 'dev').exists()


@pytest.mark.parametrize('name,kind,data,major,minor,link,alias', [
    ('dev/full', tarfile.CHRTYPE, b'', 1, 7, '', False),
    ('dev/null', tarfile.CHRTYPE, b'', 2, 3, '', False),
    ('dev/null', tarfile.CHRTYPE, b'', 1, 4, '', False),
    ('dev/null', tarfile.CHRTYPE, b'x', 1, 3, '', False),
    ('alias/null', tarfile.CHRTYPE, b'', 1, 3, '', True),
    ('dev/null', tarfile.BLKTYPE, b'', 1, 3, '', False),
    ('dev/null', tarfile.FIFOTYPE, b'', 1, 3, '', False),
    ('dev/null', b's', b'', 1, 3, '', False),
])
def test_nonstandard_special_members_remain_rejected(tmp_path, name, kind, data,
                                                      major, minor, link, alias):
    entries = [('dev/', tarfile.DIRTYPE, b'', 0, 0, '')]
    if alias:
        entries.append(('alias', tarfile.SYMTYPE, b'', 0, 0, 'dev'))
    entries.append((name, kind, data, major, minor, link))
    image_identity, manifest, config, layers = small_image(tmp_path, [entries])
    with pytest.raises(ValueError, match='unsupported_tar_member'):
        archive.validate(image_identity, manifest, config, layers)
    assert not (tmp_path / 'dev').exists()


def test_gzip_path_and_diffid(tmp_path):
    import gzip
    identity, manifest_raw, config, layer = image(tmp_path)
    compressed = tmp_path / 'compressed.tar.gz'
    with layer.open('rb') as source, gzip.open(compressed, 'wb', compresslevel=1) as dest:
        while part := source.read(65536):
            dest.write(part)
    manifest = archive.decode(manifest_raw)
    manifest['layers'][0] = {'mediaType': 'application/vnd.oci.image.layer.v1.tar+gzip',
                             'size': compressed.stat().st_size,
                             'digest': archive.sha(compressed.read_bytes())}
    manifest_raw = wire(manifest)
    identity['manifest_digest'] = archive.sha(manifest_raw)
    identity['immutable_reference'] = identity['immutable_reference'].split('@')[0] + '@' + identity['manifest_digest']
    proof = archive.write_archive(tmp_path / 'gzip-oci.tar', identity, manifest_raw, config,
                                  [compressed], archive_format='oci')
    assert proof['members'] == 10
    with tarfile.open(tmp_path / 'gzip-oci.tar') as tar:
        blob = tar.extractfile('blobs/sha256/' + manifest['layers'][0]['digest'][7:]).read()
    assert blob == compressed.read_bytes()
    with compressed.open('ab') as stream:
        stream.write(b'junk')
    with pytest.raises(ValueError):
        archive.validate(identity, manifest_raw, config, [compressed])


def with_second_layer(tmp_path, original, member_name, kind=tarfile.REGTYPE, data=b''):
    identity, manifest_raw, config_raw, first = original
    second = tmp_path / 'second.tar'
    with tarfile.open(second, 'w', format=tarfile.USTAR_FORMAT) as tar:
        item = tarfile.TarInfo(member_name)
        item.type = kind
        item.size = len(data) if kind == tarfile.REGTYPE else 0
        tar.addfile(item, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    config = archive.decode(config_raw)
    config['rootfs']['diff_ids'].append(archive.sha(second.read_bytes()))
    config_raw = wire(config)
    manifest = archive.decode(manifest_raw)
    manifest['config']['digest'] = archive.sha(config_raw)
    manifest['config']['size'] = len(config_raw)
    manifest['layers'].append({'mediaType': 'application/vnd.oci.image.layer.v1.tar',
                               'digest': archive.sha(second.read_bytes()), 'size': second.stat().st_size})
    manifest_raw = wire(manifest)
    identity = dict(identity)
    identity['config_digest'] = archive.sha(config_raw)
    identity['manifest_digest'] = archive.sha(manifest_raw)
    identity['immutable_reference'] = identity['immutable_reference'].split('@')[0] + '@' + identity['manifest_digest']
    return identity, manifest_raw, config_raw, [first, second]


def test_whiteout_excludes_deleted_file_from_final_visit(tmp_path):
    identity, manifest, config, layers = with_second_layer(tmp_path, image(tmp_path),
                                                             'etc/.wh.os-release')
    seen = []
    proof = archive.visit_files(identity, manifest, config, layers,
                                lambda name, reader, size, layer: seen.append(name))
    assert 'etc/os-release' not in seen
    assert 'etc/.wh.os-release' not in seen
    assert proof['visited_files'] == 3


def test_partial_callback_retains_prior_verified_layer_only(tmp_path):
    identity, manifest, config, layers = with_second_layer(tmp_path, image(tmp_path),
                                                             'device', tarfile.CHRTYPE)
    partial, final = [], []
    with pytest.raises(ValueError, match='unsupported_tar_member'):
        archive.visit_files(identity, manifest, config, layers,
            lambda name, reader, size, layer: final.append(name),
            partial_callback=lambda name, reader, size, layer: partial.append((name, layer)))
    assert ('etc/os-release', 0) in partial and not final


def test_descriptor_member_and_archive_caps(tmp_path, monkeypatch):
    identity, manifest, config, layer = image(tmp_path)
    monkeypatch.setattr(archive, 'MAX_LAYER', 8 * 1024 * 1024)
    with pytest.raises(ValueError, match='unsupported_descriptor'):
        archive.validate(identity, manifest, config, [layer])
    monkeypatch.setattr(archive, 'MAX_LAYER', 512 * 1024 * 1024)
    monkeypatch.setattr(archive, 'MAX_MEMBERS', 5)
    with pytest.raises(ValueError, match='tar_member_bound'):
        archive.validate(identity, manifest, config, [layer])
    monkeypatch.setattr(archive, 'MAX_MEMBERS', 200000)
    monkeypatch.setattr(archive, 'MAX_ARCHIVE', 1024 * 1024)
    output = tmp_path / 'too-large.tar'
    with pytest.raises(ValueError, match='owned_archive_bound'):
        archive.write_archive(output, identity, manifest, config, [layer])
    assert not output.exists()


def test_low_free_disk_refuses_and_cleans(tmp_path, monkeypatch):
    from types import SimpleNamespace
    identity, manifest, config, layer = image(tmp_path)
    monkeypatch.setattr(archive.shutil, 'disk_usage', lambda _: SimpleNamespace(free=0))
    output = tmp_path / 'no-space.tar'
    with pytest.raises(ValueError, match='scratch_disk_bound'):
        archive.write_archive(output, identity, manifest, config, [layer])
    assert not output.exists() and not list(tmp_path.glob('peaso-image-layers-*'))


@pytest.mark.parametrize('archive_format', ['oci', 'docker'])
def test_standard_dot_prefix_root_and_links(tmp_path, archive_format):
    args = small_image(tmp_path, [[
        ('.', tarfile.DIRTYPE, b'', 0, 0, ''),
        ('./usr', tarfile.DIRTYPE, b'', 0, 0, ''),
        ('./usr/bin', tarfile.DIRTYPE, b'', 0, 0, ''),
        ('./usr/bin/tool', tarfile.REGTYPE, b'payload', 0, 0, ''),
        ('./bin', tarfile.SYMTYPE, b'', 0, 0, 'usr/bin'),
        ('./usr/bin/copy', tarfile.LNKTYPE, b'', 0, 0, './usr/bin/tool'),
        ('./dev/null', tarfile.CHRTYPE, b'', 1, 3, ''),
    ]])
    observed = {}
    archive.visit_files(*args, lambda name, reader, size, index:
                        observed.setdefault(name, reader.read()))
    assert observed == {'usr/bin/tool': b'payload', 'usr/bin/copy': b'payload'}
    output = tmp_path / 'dot-prefix.tar'
    proof = archive.write_archive(output, *args, archive_format=archive_format)
    assert proof['members'] == 7
    assert not (tmp_path / 'usr').exists() and not (tmp_path / 'dev').exists()


def test_slash_root_directory_entry_is_the_root_marker(tmp_path):
    # Some image builders emit a '/' directory as the first layer member.
    args = small_image(tmp_path, [[
        ('/', tarfile.DIRTYPE, b'', 0, 0, ''),
        ('etc', tarfile.DIRTYPE, b'', 0, 0, ''),
        ('etc/app.conf', tarfile.REGTYPE, b'payload', 0, 0, ''),
    ]])
    observed = {}
    archive.visit_files(*args, lambda name, reader, size, index:
                        observed.setdefault(name, reader.read()))
    assert observed == {'etc/app.conf': b'payload'}


@pytest.mark.parametrize('entries,reason', [
    ([('/', tarfile.DIRTYPE, b'', 0, 0, ''),
      ('.', tarfile.DIRTYPE, b'', 0, 0, '')], 'duplicate_tar_member'),
    ([('/etc/file', tarfile.REGTYPE, b'bad', 0, 0, '')], 'unsafe_image_path'),
    ([('./a', tarfile.REGTYPE, b'one', 0, 0, ''),
      ('a', tarfile.REGTYPE, b'two', 0, 0, '')], 'duplicate_tar_member'),
    ([('.', tarfile.DIRTYPE, b'', 0, 0, ''),
      ('./', tarfile.DIRTYPE, b'', 0, 0, '')], 'duplicate_tar_member'),
    ([('./../outside', tarfile.REGTYPE, b'bad', 0, 0, '')], 'unsafe_image_path'),
    ([('./etc/./file', tarfile.REGTYPE, b'bad', 0, 0, '')], 'unsafe_image_path'),
    ([('./etc/../file', tarfile.REGTYPE, b'bad', 0, 0, '')], 'unsafe_image_path'),
    ([('.', tarfile.REGTYPE, b'bad', 0, 0, '')], 'unsafe_image_path'),
    ([('./', tarfile.SYMTYPE, b'', 0, 0, 'elsewhere')], 'unsafe_image_path'),
    ([('.', tarfile.DIRTYPE, b'bad', 0, 0, '')], 'unsafe_image_path'),
])
def test_dot_prefix_retains_canonical_path_guards(tmp_path, entries, reason):
    with pytest.raises(ValueError, match=reason):
        archive.validate(*small_image(tmp_path, [entries]))
