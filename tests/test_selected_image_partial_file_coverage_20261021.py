"""A partial file cannot hide a later verified image-file secret."""
import io
import json
import tarfile
from types import SimpleNamespace

import pytest

from peaso import container_image_archive_20261020 as archive
import test_ecr_public_image as public
import test_pod_oci_index_20261021 as pod


def replace_layer(value, *, pod_image, gap, hit):
    stream = io.BytesIO()
    first = {'binary': b'\x00\xff\x01\x02', 'nested': b'PK\x03\x04not-an-unpacked-archive'}[gap]
    name = '00-binary.bin' if gap == 'binary' else '00-nested.zip'
    data = ('TOKEN=' + public.TOKEN + '\n' if hit else 'MODE=ready\n').encode()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for path, raw in ((name, first), ('zz-later.env', data)):
            entry = tarfile.TarInfo(path)
            entry.size = len(raw)
            tar.addfile(entry, io.BytesIO(raw))
    layer = stream.getvalue()
    config = json.loads(value['config'] if pod_image else value.config)
    config['rootfs']['diff_ids'] = [archive.sha(layer)]
    config = public.wire(config)
    manifest = json.loads(value['manifest'] if pod_image else value.manifest)
    manifest['config'].update(size=len(config), digest=archive.sha(config))
    manifest['layers'][0].update(size=len(layer), digest=archive.sha(layer))
    manifest = public.wire(manifest)
    if pod_image:
        return dict(value, layer=layer, config=config, manifest=manifest, digest=archive.sha(manifest))
    return SimpleNamespace(layer=layer, config=config, manifest=manifest, digest=archive.sha(manifest),
        target=dict(value.target, image_digest=archive.sha(manifest)))


@pytest.mark.parametrize('gap', ['binary', 'nested'])
@pytest.mark.parametrize('hit', [False, True])
def test_ecr_public_partial_file_keeps_later_secret(monkeypatch, gap, hit):
    original = public.image
    monkeypatch.setattr(public, 'image', lambda *args: replace_layer(original(), pod_image=False, gap=gap, hit=hit))
    result = public.capture()
    assert result.secret[0] == ('FAIL' if hit else 'UNKNOWN'), result.secret
    assert result.item['ECRPublicImageContent']['secret_complete'] is False
    assert len(result.item['ECRPublicImageContent']['parts']) >= 4
    assert public.TOKEN not in json.dumps(result.item)
    if hit:
        assert not result.redacted  # found values are not redacted


@pytest.mark.parametrize('gap', ['binary', 'nested'])
@pytest.mark.parametrize('hit', [False, True])
def test_pod_partial_file_keeps_later_secret(monkeypatch, gap, hit):
    original = pod.leaf
    monkeypatch.setattr(pod, 'leaf', lambda arch, *args: replace_layer(original(arch), pod_image=True, gap=gap, hit=hit))
    result = pod.capture()
    assert result['secret'][0] == ('FAIL' if hit else 'UNKNOWN'), result['secret']
    assert result['marker']['complete'] is False
    assert public.TOKEN not in json.dumps(result['marker'])
    if hit:
        assert not result['redacted']  # found values are not redacted


@pytest.mark.parametrize('provider', ['pod', 'public'])
def test_secret_file_gap_does_not_disable_independent_trivy(monkeypatch, provider):
    if provider == 'public':
        original = public.image
        monkeypatch.setattr(public, 'image', lambda *args: replace_layer(original(), pod_image=False, gap='binary', hit=False))
        result = public.capture(vuln=True, vuln_hit=True)
        assert result.secret[0] == 'UNKNOWN'
        assert result.vuln[0] == 'FAIL', result.vuln
    else:
        original = pod.leaf
        monkeypatch.setattr(pod, 'leaf', lambda arch, *args: replace_layer(original(arch), pod_image=True, gap='binary', hit=False))
        result = pod.capture(vuln=True, vuln_first=True)
        assert result['secret'][0] == 'UNKNOWN'
        assert result['vulnerability'][0] == 'FAIL', result['vulnerability']


@pytest.mark.parametrize('provider', ['pod', 'public'])
def test_partial_first_detector_part_keeps_later_secret(monkeypatch, provider):
    original = pod.source.scan_with_source
    seen = []
    def partial_once(*args, **kwargs):
        result = original(*args, **kwargs)
        seen.append(1)
        if len(seen) == 1:
            result['complete'] = False
            result['engines'][0]['status'] = 'unavailable'
        return result
    monkeypatch.setattr(pod.source, 'scan_with_source', partial_once)
    result = public.capture(hit=True) if provider == 'public' else pod.capture(second_hit=True)
    verdict = result.secret if provider == 'public' else result['secret']
    marker = result.item['ECRPublicImageContent'] if provider == 'public' else result['marker']
    assert verdict[0] == 'FAIL', verdict
    assert marker.get('secret_complete', marker.get('complete')) is False
    assert len(seen) > 1


@pytest.mark.parametrize('provider', ['pod', 'public'])
@pytest.mark.parametrize('code', ['collection_cancelled', 'intentional_scan_deadline', 'deadline_exceeded'])
def test_registry_read_preserves_typed_cancellation(monkeypatch, provider, code):
    class Cancelled(RuntimeError):
        pass
    error = Cancelled('cancelled by request')
    error.code = code
    original = pod.source.RegistryReader.check
    def cancel_during_stream(self):
        if self.calls > 0:
            raise error
        return original(self)
    monkeypatch.setattr(pod.source.RegistryReader, 'check', cancel_during_stream)
    with pytest.raises(Cancelled) as caught:
        public.capture() if provider == 'public' else pod.capture()
    assert caught.value is error


@pytest.mark.parametrize('provider', ['pod', 'public'])
def test_unattested_leak_location_cannot_fail(monkeypatch, provider):
    result = public.capture(hit=True) if provider == 'public' else pod.capture(second_hit=True)
    marker = result.item['ECRPublicImageContent'] if provider == 'public' else result['marker']
    for part in marker['parts']:
        for engine in part['engines']:
            engine['status'] = 'unavailable'
    if provider == 'public':
        verdict = public.consumer.evaluate(result.item, result.index, public.selection.SECRET_CHECK)
    else:
        verdict = pod.consumer.evaluate(result['item'], result['contexts'][pod.source.SECRET_KIND], pod.source.SECRET_KIND)
    assert verdict[0] == 'UNKNOWN', verdict


@pytest.mark.parametrize('provider', ['pod', 'public'])
def test_unknown_detector_without_pinned_version_cannot_fail(provider):
    result = public.capture(hit=True) if provider == 'public' else pod.capture(second_hit=True)
    marker = result.item['ECRPublicImageContent'] if provider == 'public' else result['marker']
    for part in marker['parts']:
        part['engines'] = [{'engine': 'untrusted', 'status': 'complete'}]
    for leak in marker['leaks']:
        leak['detectors'] = [{'engine': 'untrusted', 'rule': 'unknown'}]
    if provider == 'public':
        verdict = public.consumer.evaluate(result.item, result.index, public.selection.SECRET_CHECK)
    else:
        verdict = pod.consumer.evaluate(result['item'], result['contexts'][pod.source.SECRET_KIND], pod.source.SECRET_KIND)
    assert verdict[0] == 'UNKNOWN', verdict
