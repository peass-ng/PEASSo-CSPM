"""Layer indexing fast paths give the standard answers, errors included."""
import io
import random
import tarfile
import threading
import time
from pathlib import Path

import pytest

from peaso import container_image_archive_20261020 as archive
from peaso import trivy_container_runner_20261020 as runner
from peaso import trivy_version_probe_20261026 as probe
from peaso.image_tar_header_20261026 import header


def standard(buf):
    try:
        m = tarfile.TarInfo.frombuf(buf, 'utf-8', 'strict')
    except Exception as exc:
        return type(exc), str(exc)
    return m.name, m.linkname, m.size, m.type, m.devmajor, m.devminor


def fast(buf):
    try:
        m = header(buf)
    except Exception as exc:
        return type(exc), str(exc)
    return m.name, m.linkname, m.size, m.type, m.devmajor, m.devminor


def blocks():
    out = []
    for fmt in (tarfile.USTAR_FORMAT, tarfile.GNU_FORMAT, tarfile.PAX_FORMAT):
        for name, kind, extra in [
                ('etc/passwd', tarfile.REGTYPE, {}), ('usr/lib/', tarfile.DIRTYPE, {}),
                ('a/' * 60 + 'deep', tarfile.REGTYPE, {}), ('lib', tarfile.SYMTYPE, {'linkname': 'usr/lib'}),
                ('bin/sh', tarfile.LNKTYPE, {'linkname': 'bin/bash'}),
                ('dev/null', tarfile.CHRTYPE, {'devmajor': 1, 'devminor': 3}),
                ('café/üml', tarfile.REGTYPE, {}),
                ('big', tarfile.REGTYPE, {'uid': 8 ** 9, 'mtime': 2 ** 40})]:
            info = tarfile.TarInfo(name)
            info.type = kind
            for key, value in extra.items():
                setattr(info, key, value)
            try:
                raw = info.tobuf(fmt, 'utf-8', 'surrogateescape')
            except ValueError:
                continue
            out.extend(raw[at:at + 512] for at in range(0, len(raw), 512))
    return out


def test_header_matches_frombuf_on_real_shapes_and_mutations():
    rng = random.Random(20261026)
    cases = blocks()
    old_dir = bytearray(cases[0])
    old_dir[0:100] = b'old/dir/'.ljust(100, b'\0')
    old_dir[156:157] = tarfile.AREGTYPE
    cases.append(bytes(old_dir))
    for base in list(cases):
        for _ in range(150):
            raw = bytearray(base)
            for _ in range(rng.randint(1, 3)):
                at = rng.choice([rng.randrange(512), rng.randrange(100, 160), rng.randrange(329, 345)])
                raw[at] = rng.choice([0, 0x20, 0x30, 0x37, 0x38, 0x80, 0xff, rng.randrange(256)])
            if rng.random() < .5:  # keep the unsigned checksum valid so field decoding is exercised
                raw[148:156] = b' ' * 8
                raw[148:156] = b'%06o\0 ' % sum(raw)
            cases.append(bytes(raw))
    signed = bytearray(cases[0])
    signed[0:5] = 'caf\u00e9'.encode()
    signed[148:156] = b' ' * 8
    signed[148:156] = b'%06o\0 ' % (sum(signed) - 256 * sum(b > 127 for b in signed))
    cases.append(bytes(signed))
    assert standard(cases[-1])[0] == 'caf\u00e9' + standard(cases[0])[0][5:]
    cases.append(bytes(512))
    seen_ok = seen_err = 0
    for buf in cases:
        expected = standard(buf)
        assert fast(buf) == expected, buf
        seen_err += isinstance(expected[0], type)
        seen_ok += not isinstance(expected[0], type)
    assert seen_ok > 100 and seen_err > 100


def layer(tmp_path, members, name='layer.tar'):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.GNU_FORMAT) as tar:
        for path, kind, link in members:
            info = tarfile.TarInfo(path)
            info.type, info.linkname = kind, link
            data = b'' if kind != tarfile.REGTYPE else path.encode()
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    target = tmp_path / name
    target.write_bytes(buffer.getvalue())
    return target


def index(paths, monkeypatch=None, plain=False):
    if plain:
        monkeypatch.setattr(archive._Parents, 'resolve', lambda self, value: archive._resolve(value, self.nodes))
    nodes, count = {}, 0
    for number, path in enumerate(paths):
        count = archive._tar_members(path, nodes, count, lambda: None, number, [0])
    if plain:
        monkeypatch.undo()
    return count, nodes


def test_parent_memo_follows_symlinks_added_after_plain_parents(tmp_path, monkeypatch):
    reg, sym, dirt = tarfile.REGTYPE, tarfile.SYMTYPE, tarfile.DIRTYPE
    first = layer(tmp_path, [('x/y/one', reg, ''), ('x', sym, 'z'), ('x/y/two', reg, ''),
                             ('z/y/three', reg, ''), ('usr/lib/a', reg, ''), ('lib', sym, 'usr/lib'),
                             ('lib/b', reg, ''), ('usr/lib/c', sym, 'a'), ('usr/lib/d', reg, '')], 'one.tar')
    second = layer(tmp_path, [('usr/lib/e', reg, ''), ('usr', sym, 'opt'), ('usr/lib/f', reg, ''),
                              ('w/v', dirt, ''), ('w/v/g', reg, '')], 'two.tar')
    fast_result = index([first, second])
    assert fast_result == index([first, second], monkeypatch, plain=True)
    nodes = fast_result[1]
    assert 'z/y/two' in nodes and 'x/y/two' not in nodes and 'usr/lib/b' in nodes and 'opt/lib/f' in nodes


@pytest.mark.parametrize('damage', ['short_member', 'trailing', 'odd_size', 'no_terminator'])
def test_mapped_reader_keeps_tar_bound_errors(tmp_path, damage):
    path = layer(tmp_path, [('etc/a', tarfile.REGTYPE, ''), ('etc/b', tarfile.REGTYPE, '')])
    raw = path.read_bytes()
    big = tarfile.TarInfo('etc/big')
    big.size = 5000
    raw = {'short_member': big.tobuf(tarfile.GNU_FORMAT, 'utf-8', 'strict') + bytes(1536),
           'trailing': raw[:-512] + b'x' + bytes(511), 'odd_size': raw + b'\0',
           'no_terminator': raw[:2048]}[damage]
    path.write_bytes(raw)
    with pytest.raises(ValueError) as caught:
        index([path])
    assert str(caught.value) == {'short_member': 'truncated_tar_member', 'trailing': 'tar_trailing_content',
                                 'odd_size': 'truncated_tar', 'no_terminator': 'tar_terminator_required'}[damage]


def test_version_probe_overlaps_archive_and_reruns_unclean_results(tmp_path, monkeypatch):
    calls = []
    def execute(argv, env, root, end, cancel):
        calls.append(threading.current_thread().name)
        time.sleep(.05)
        return (b'Version: 0.68.1\n', b'', 1 if len(calls) == 1 else 0, None, 0)
    monkeypatch.setattr(probe.process, '_execute', execute)
    job = probe.VersionProbe('/bin/trivy', {}, tmp_path, time.monotonic() + 30, lambda: None)
    assert job.result()[2] == 0
    assert calls == ['peaso-trivy-version', threading.current_thread().name]


def test_version_probe_is_joined_when_archive_fails(tmp_path, monkeypatch):
    started, finished = threading.Event(), threading.Event()
    def execute(*args):
        started.set(); time.sleep(.1); finished.set()
        return (b'Version: 0.68.1\n', b'', 0, None, 0)
    monkeypatch.setattr(runner.process, '_execute', execute)
    def broken(*args, **kwargs):
        assert started.wait(5)
        raise ValueError('layer_changed_during_archive')
    monkeypatch.setattr(runner.archive, 'write_archive', broken)
    monkeypatch.setattr(runner, 'database_state', lambda _: {'fresh': True, 'schema_version': 2})
    binary = tmp_path / 'trivy'
    binary.write_text('#!/bin/sh\n'); binary.chmod(0o700)
    image = {'provider': 'aws', 'scope': '123456789012/us-east-1',
             'immutable_reference': '123456789012.dkr.ecr.us-east-1.amazonaws.com/x@sha256:' + 'a' * 64,
             'manifest_digest': 'sha256:' + 'a' * 64, 'config_digest': 'sha256:' + 'b' * 64}
    config = b'{"rootfs":{"diff_ids":[]}}'
    result = runner.scan_image(image, b'{}', config, [], native_verifier=lambda: dict(image), enabled=True,
                               db_cache=tmp_path, cli=str(binary), scratch_parent=tmp_path, timeout=60)
    assert finished.is_set() and result['status'] == 'UNKNOWN'
    assert result['reason'] == 'input_or_scan_unavailable'
