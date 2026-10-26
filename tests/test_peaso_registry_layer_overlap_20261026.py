"""Registry layers validated while later layers download replay the serial outcome."""
import gzip
import io
import json
import os
from pathlib import Path
import tarfile
import threading

import pytest

from peaso import container_image_archive_20261020 as archive
from peaso.collectors.registry_layer_overlap_20261026 import fetch_layers


def wire(value):
    return json.dumps(value, separators=(',', ':')).encode()


def _tar(members):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for name, data in members:
            item = tarfile.TarInfo(name)
            item.size = len(data)
            tar.addfile(item, io.BytesIO(data))
    return buffer.getvalue()


def image(*, corrupt_second=False):
    """Three layers; later layers replace and white out earlier files."""
    expanded = [_tar([('etc/a', b'first a'), ('etc/b', b'first b'), ('usr/c', b'c' * 5000)]),
                _tar([('etc/a', b'second a'), ('etc/.wh.b', b'')]),
                _tar([('usr/d', b'd' * 70000)])]
    blobs = [gzip.compress(raw, mtime=0) for raw in expanded]
    if corrupt_second:
        expanded[1] = expanded[1] + b'x'  # diff_id no longer matches the layer bytes
    config = wire({'os': 'linux', 'architecture': 'amd64',
                   'rootfs': {'type': 'layers', 'diff_ids': [archive.sha(raw) for raw in expanded]}})
    manifest = wire({'schemaVersion': 2, 'mediaType': archive.OCI,
                     'config': {'mediaType': 'application/vnd.oci.image.config.v1+json',
                                'digest': archive.sha(config), 'size': len(config)},
                     'layers': [{'mediaType': 'application/vnd.oci.image.layer.v1.tar+gzip',
                                 'digest': archive.sha(blob), 'size': len(blob)} for blob in blobs]})
    digest = archive.sha(manifest)
    identity = {'provider': 'k8s', 'scope': 'cluster-1',
                'immutable_reference': 'registry.example/team/app@' + digest,
                'manifest_digest': digest, 'config_digest': archive.sha(config)}
    descriptors = json.loads(manifest)['layers']
    return identity, manifest, config, descriptors, dict(zip((d['digest'] for d in descriptors), blobs))


class Reader:
    def __init__(self, blobs, *, fail_digest=None, gates=None):
        self.blobs, self.fail_digest, self.gates = blobs, fail_digest, gates
        self.receipts, self.threads = [], set()

    def check(self):
        pass

    def get(self, category, digest, cap, *, size=None, destination=None):
        self.threads.add(threading.current_thread().name)
        if self.gates is not None:
            self.gates[len(self.receipts)].wait(5)
        self.receipts.append((category, digest, size, destination.name))
        if digest == self.fail_digest:
            raise ValueError('registry_unavailable')
        destination.write_bytes(self.blobs[digest])
        return destination


def serial(reader, descriptors, directory):
    return [reader.get('blobs', d['digest'], archive.MAX_LAYER, size=d['size'],
                       destination=directory / ('layer-' + str(i))) for i, d in enumerate(descriptors)]


def visits(identity, manifest, config, layers, **extra):
    seen = []

    def partial(name, stream, length, layer):
        seen.append(('partial', layer, name, stream.read(length)))

    def final(name, stream, length, layer):
        seen.append(('final', layer, name, stream.read(length)))
    stats = archive.visit_files(identity, manifest, config, layers, final, partial_callback=partial, **extra)
    return seen, stats


@pytest.fixture(autouse=True)
def fresh_memos(tmp_path, monkeypatch):
    import tempfile
    (tmp_path / 'scratch').mkdir()
    monkeypatch.setattr(tempfile, 'tempdir', str(tmp_path / 'scratch'))
    archive._PROVEN.clear(); archive._STAGED.clear()
    yield
    archive._PROVEN.clear(); archive._STAGED.clear()


def scratch_dirs():
    import tempfile
    return {p.name for p in Path(tempfile.gettempdir()).glob('peaso-image-visit-*')}


def test_prebuilt_visits_and_staged_archive_match_the_serial_flow(tmp_path):
    identity, manifest, config, descriptors, blobs = image()
    (tmp_path / 'serial').mkdir(); (tmp_path / 'overlap').mkdir()
    reader = Reader(blobs)
    layers = serial(reader, descriptors, tmp_path / 'serial')
    expected = visits(identity, manifest, config, layers, stage=True)
    expected_archive = tmp_path / 'expected.tar'
    archive.write_archive(expected_archive, identity, manifest, config, layers, archive_format='docker')
    archive._PROVEN.clear(); archive._STAGED.clear()

    before = scratch_dirs()
    overlapped = Reader(blobs)
    layers, prebuilt = fetch_layers(overlapped, descriptors, tmp_path / 'overlap',
                                    lambda i: 'layer-' + str(i), identity, manifest, config, lambda: None)
    assert prebuilt is not None and overlapped.threads == {'peaso-layer-download'}
    assert [r[:3] for r in overlapped.receipts] == [r[:3] for r in reader.receipts]
    assert visits(identity, manifest, config, layers, stage=True, prebuilt=prebuilt) == expected
    assert ('partial', 0, 'etc/b', b'first b') in expected[0]  # earlier layer's file is still visited
    produced = tmp_path / 'produced.tar'
    archive.write_archive(produced, identity, manifest, config, layers, archive_format='docker')
    assert produced.read_bytes() == expected_archive.read_bytes()
    assert scratch_dirs() <= before


def test_prebuilt_validate_matches_and_is_used_once(tmp_path):
    identity, manifest, config, descriptors, blobs = image()
    layers, prebuilt = fetch_layers(Reader(blobs), descriptors, tmp_path, lambda i: 'layer-' + str(i),
                                    identity, manifest, config, lambda: None)
    expected = archive.validate(identity, manifest, config, layers)
    assert archive.validate(identity, manifest, config, layers, prebuilt=prebuilt) == expected
    assert not prebuilt.scratch.exists()
    assert archive.validate(identity, manifest, config, layers, prebuilt=prebuilt) == expected


@pytest.mark.parametrize('consumer', ['validate', 'visit'])
def test_tampered_prebuilt_archive_is_rejected_before_callbacks(tmp_path, consumer):
    identity, manifest, config, descriptors, blobs = image()
    layers, prebuilt = fetch_layers(Reader(blobs), descriptors, tmp_path, lambda i: 'layer-' + str(i),
                                    identity, manifest, config, lambda: None)
    victim = prebuilt.built.path
    before = victim.stat()
    raw = bytearray(victim.read_bytes())
    raw[3000] ^= 1
    victim.write_bytes(raw)
    os.utime(victim, ns=(before.st_atime_ns, before.st_mtime_ns))
    seen = []
    with pytest.raises(ValueError, match='layer_changed_during_archive'):
        if consumer == 'validate':
            archive.validate(identity, manifest, config, layers, stage=True, prebuilt=prebuilt)
        else:
            archive.visit_files(identity, manifest, config, layers, lambda *args: seen.append(args),
                                partial_callback=lambda *args: seen.append(args), prebuilt=prebuilt)
    assert seen == [] and not prebuilt.scratch.exists()


def test_prebuilt_for_other_layers_is_removed_and_ignored(tmp_path):
    identity, manifest, config, descriptors, blobs = image()
    layers, prebuilt = fetch_layers(Reader(blobs), descriptors, tmp_path, lambda i: 'layer-' + str(i),
                                    identity, manifest, config, lambda: None)
    copies = []
    for path in layers:
        copy = path.with_name(path.name + '.copy')
        copy.write_bytes(path.read_bytes())
        copies.append(copy)
    expected = visits(identity, manifest, config, copies)
    archive._PROVEN.clear()
    assert visits(identity, manifest, config, copies, prebuilt=prebuilt) == expected
    assert not prebuilt.scratch.exists()


def test_download_error_wins_after_the_same_reads(tmp_path):
    identity, manifest, config, descriptors, blobs = image()
    (tmp_path / 'serial').mkdir(); (tmp_path / 'overlap').mkdir()
    reader = Reader(blobs, fail_digest=descriptors[2]['digest'])
    with pytest.raises(ValueError, match='registry_unavailable'):
        serial(reader, descriptors, tmp_path / 'serial')
    before = scratch_dirs()
    overlapped = Reader(blobs, fail_digest=descriptors[2]['digest'])
    with pytest.raises(ValueError, match='registry_unavailable'):
        fetch_layers(overlapped, descriptors, tmp_path / 'overlap', lambda i: 'layer-' + str(i),
                     identity, manifest, config, lambda: None)
    assert [r[:3] for r in overlapped.receipts] == [r[:3] for r in reader.receipts]
    assert scratch_dirs() <= before


def test_invalid_layer_yields_no_prebuilt_and_the_serial_error_and_visits(tmp_path):
    identity, manifest, config, descriptors, blobs = image(corrupt_second=True)
    (tmp_path / 'serial').mkdir(); (tmp_path / 'overlap').mkdir()
    layers = serial(Reader(blobs), descriptors, tmp_path / 'serial')
    seen = []
    with pytest.raises(ValueError) as serial_error:
        archive.visit_files(identity, manifest, config, layers, lambda *_: None,
                            partial_callback=lambda name, *_: seen.append(name))
    before = scratch_dirs()
    layers, prebuilt = fetch_layers(Reader(blobs), descriptors, tmp_path / 'overlap',
                                    lambda i: 'layer-' + str(i), identity, manifest, config, lambda: None)
    assert prebuilt is None and scratch_dirs() <= before
    again = []
    with pytest.raises(ValueError) as overlap_error:
        archive.visit_files(identity, manifest, config, layers, lambda *_: None,
                            partial_callback=lambda name, *_: again.append(name), prebuilt=prebuilt)
    assert str(overlap_error.value) == str(serial_error.value) and again == seen and seen


def test_validation_starts_before_the_last_layer_arrives(tmp_path):
    identity, manifest, config, descriptors, blobs = image()
    gates = [threading.Event() for _ in descriptors]
    gates[0].set(); gates[1].set()
    original = archive._expand
    expanded = []

    def expand(raw, desc, *args, **kwargs):
        expanded.append(desc['digest'])
        if len(expanded) == 2:
            gates[2].set()  # the last download may only finish after layer 1 expanded
        return original(raw, desc, *args, **kwargs)
    archive._expand = expand
    try:
        layers, prebuilt = fetch_layers(Reader(blobs, gates=gates), descriptors, tmp_path,
                                        lambda i: 'layer-' + str(i), identity, manifest, config, lambda: None)
    finally:
        archive._expand = original
    assert prebuilt is not None and expanded == [d['digest'] for d in descriptors]
    prebuilt.discard()


class Capture:
    """The capture readers' shape: get() retains each blob in _blobs."""

    def __init__(self, manifest, config, blobs, uri):
        self.source, self.uri, self.reads, self.threads = blobs, uri, [], set()
        self._blobs = {('manifests', archive.sha(manifest)): manifest, ('blobs', archive.sha(config)): config}

    def check(self):
        pass

    def get(self, uri, category, digest, cap, size=None):
        self.threads.add(threading.current_thread().name)
        self.reads.append((uri, category, digest, size))
        self._blobs.setdefault((category, digest), self.source[digest])
        return self._blobs[(category, digest)]


def test_gcp_capture_reads_are_unchanged_and_validation_replays(tmp_path):
    from peaso.collectors.gcp_layer_overlap_20261026 import read_layers
    identity, manifest, config, descriptors, blobs = image()
    identity = dict(identity, provider='gcp', scope='project-1',
                    immutable_reference='us-docker.pkg.dev/project-1/repo/app@' + identity['manifest_digest'])
    uri = 'https://' + identity['immutable_reference']
    serial = Capture(manifest, config, blobs, uri)
    for layer in descriptors:
        serial.get(uri, 'blobs', layer['digest'], archive.MAX_LAYER, layer['size'])
    payloads = [serial._blobs[('blobs', d['digest'])] for d in descriptors]
    expected = archive.validate(identity, manifest, config, payloads, stage=True)
    archive._PROVEN.clear(); archive._STAGED.clear()

    captured = Capture(manifest, config, blobs, uri)
    prebuilt = read_layers(captured, uri, descriptors, archive.MAX_LAYER, 'project-1',
                           identity['manifest_digest'], identity['config_digest'])
    assert prebuilt is not None and captured.prebuilt is prebuilt
    assert captured.reads == serial.reads and captured.threads == {'peaso-layer-download'}
    payloads = [captured._blobs[('blobs', d['digest'])] for d in descriptors]
    # The caller's own (different) reference still uses the prebuilt digests.
    other = dict(identity, immutable_reference='europe-docker.pkg.dev/p/r/app@' + identity['manifest_digest'])
    assert archive.validate(other, manifest, config, payloads, stage=True,
                            prebuilt=vars(captured).pop('prebuilt')) == expected
    staged = archive._STAGED.take(archive._chain(config, *archive._graph(identity, manifest, config, payloads)[1:]))
    assert staged is not None and staged[0] == prebuilt.scratch  # handed on to write_archive


def test_gcp_plain_reader_keeps_the_serial_loop(tmp_path):
    from peaso.collectors.gcp_layer_overlap_20261026 import read_layers
    identity, manifest, config, descriptors, blobs = image()

    class Plain:
        def __init__(self):
            self.reads = []

        def get(self, *args):
            self.reads.append((args, threading.current_thread().name))
    plain = Plain()
    assert read_layers(plain, 'https://x/y@' + identity['manifest_digest'], descriptors, 1, 's',
                       identity['manifest_digest'], identity['config_digest']) is None
    assert [name for _, name in plain.reads] == [threading.current_thread().name] * len(descriptors)
