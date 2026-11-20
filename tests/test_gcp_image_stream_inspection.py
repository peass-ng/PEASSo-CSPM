import gzip
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
from urllib.parse import quote

import pytest
from test_gcp_image_stream_reader import reader, Response, digest

from peaso.collectors import gcp_image_stream_reader_20261021 as streaming
from peaso.collectors import gcp_image_stream_inspection_20261021 as inspection
SCOPE = 'projects/review'
REPO = SCOPE + '/locations/us-central1/repositories/images'
REPOSITORIES = [{'name': REPO, 'format': 'DOCKER'}]
PROJECTS = [{'name': 'projects/123456789', 'projectId': 'review'}]


def encoded(value):
    return json.dumps(value, separators=(',', ':')).encode()


def image(size=100, compressed=False, unsafe=False, concat=False, bad_diff=False, body=None):
    if body is not None:
        size = len(body)
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        member = tarfile.TarInfo('../escape' if unsafe else 'app/config.txt')
        member.size = size
        archive.addfile(member, io.BytesIO(b'x' * size if body is None else body))
    expanded = output.getvalue()
    layer = gzip.compress(expanded, mtime=0) if compressed else expanded
    if concat:
        layer += gzip.compress(b'other', mtime=0)
    config = encoded({'os': 'linux', 'architecture': 'amd64', 'rootfs': {'type': 'layers',
        'diff_ids': ['sha256:' + 'b' * 64 if bad_diff else digest(expanded)]}})
    manifest = encoded({'schemaVersion': 2, 'mediaType': inspection.native.OCI,
        'config': {'mediaType': 'application/vnd.oci.image.config.v1+json', 'size': len(config), 'digest': digest(config)},
        'layers': [{'mediaType': 'application/vnd.oci.image.layer.v1.tar' + ('+gzip' if compressed else ''),
                    'size': len(layer), 'digest': digest(layer)}]})
    md = digest(manifest)
    row = {'name': REPO + '/dockerImages/' + quote('app@' + md, safe=''),
           'uri': 'https://us-central1-docker.pkg.dev/review/images/app@' + md,
           'digest': md, 'repository': REPO}
    blobs = {digest(raw): raw for raw in (manifest, config, layer)}
    return row, blobs


def run(row, blobs):
    current = reader(Response(b''))
    current.__class__ = streaming.Reader
    closed = []
    def request(method, url, **kwargs):
        response = Response(blobs[url.rsplit('/', 1)[-1]])
        response.url = url
        original = response.close
        def close():
            original()
            closed.append(url)
        response.close = close
        return response
    current.session.request = request
    return inspection.inspect_image(row, SCOPE, REPOSITORIES, PROJECTS, current), current, closed


@pytest.fixture
def scans(monkeypatch):
    calls = []
    def scan(data, path, timeout, *, _redact_values=None):
        assert len(data) <= inspection.WINDOW + inspection.OVERLAP
        calls.append((len(data), path))
        return {'complete': True, 'engines': [
            {'engine': 'kingfisher', 'status': 'complete', 'version': inspection.native.KINGFISHER_VERSION},
            {'engine': 'trufflehog', 'status': 'complete', 'version': inspection.native.TRUFFLEHOG_VERSION}], 'leaks': []}
    monkeypatch.setattr(inspection.native, 'scan_content', scan)
    return calls


@pytest.mark.parametrize('compressed', [False, True])
def test_large_layer_runs_full_inspection_without_old_eight_mib_ceiling(tmp_path, monkeypatch, scans, compressed):
    monkeypatch.setattr(inspection.tempfile, 'tempdir', str(tmp_path))
    result, current, closed = run(*image(9 * 1024 * 1024, compressed=compressed))
    assert result['status'] == 'collected'
    assert result['complete'] is True
    assert result['regular_files'] == 1
    assert result['expanded_bytes'] > 8 * 1024 * 1024
    assert current.calls == len(closed) == 3
    assert len(scans) >= 11
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('kwargs', [{'bad_diff': True}, {'unsafe': True}, {'compressed': True, 'concat': True}])
def test_invalid_layers_never_become_clean_results_and_all_scratch_is_removed(tmp_path, monkeypatch, scans, kwargs):
    monkeypatch.setattr(inspection.tempfile, 'tempdir', str(tmp_path))
    result, _, closed = run(*image(**kwargs))
    assert result['status'] == 'unavailable'
    assert result['complete'] is False
    assert result['leaks'] == []
    assert len(closed) == 3
    assert list(tmp_path.iterdir()) == []


def test_file_coverage_limit_remains_explicitly_incomplete(tmp_path, monkeypatch, scans):
    monkeypatch.setattr(inspection.tempfile, 'tempdir', str(tmp_path))
    monkeypatch.setattr(inspection, 'MAX_FILE', 1)
    result, _, _ = run(*image())
    assert result['status'] == 'partial'
    assert result['complete'] is False
    assert list(tmp_path.iterdir()) == []


def test_detector_failure_closes_downloads_and_removes_scratch(tmp_path, monkeypatch):
    monkeypatch.setattr(inspection.tempfile, 'tempdir', str(tmp_path))
    count = [0]
    def fail(data, path, timeout, *, _redact_values=None):
        count[0] += 1
        return {'complete': count[0] == 1, 'engines': [], 'leaks': []}
    monkeypatch.setattr(inspection.native, 'scan_content', fail)
    result, _, closed = run(*image())
    assert result['complete'] is False
    assert len(closed) == 3
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('missing_selected_digest', [False, True])
def test_enricher_keeps_native_selection_and_binding_function(monkeypatch, missing_selected_digest):
    row, _ = image()
    expected = row['uri']
    options = {'content_secret_scans': True, '_content_secret_scan_kinds': ['artifact_image'],
        'selected_artifact_images': [expected.removeprefix('https://')]}
    missing = expected.split('@')[0] + '@sha256:' + '0' * 64
    if missing_selected_digest:
        options['selected_artifact_images'].append(missing.removeprefix('https://'))
    unselected, _ = image(size=50)
    before = json.loads(json.dumps(options))
    calls = []
    native_bind = inspection.native.bind_image
    def bound(selected, scope, repositories, projects):
        calls.append(('bind', selected['uri'], scope))
        return native_bind(selected, scope, repositories, projects)
    class Reader:
        def __init__(self):
            self.request_ids = []
            self.closed = False
        def close(self):
            self.closed = True
    reader = Reader()
    def inspect_selected(selected, scope, repositories, projects, source):
        assert source is reader
        assert selected is row and scope == SCOPE
        assert repositories == REPOSITORIES and projects == PROJECTS
        calls.append(('inspect', selected['uri'], scope))
        source.request_ids.append('fixture-native-read')
        return {'schema': inspection.native.SCHEMA, 'status': 'collected', 'complete': True, 'leaks': []}
    monkeypatch.setattr(inspection.native, 'bind_image', bound)
    monkeypatch.setattr(inspection, 'inspect_image', inspect_selected)
    collector = type('Collector', (), {'options': options, 'scopes': [SCOPE],
        'transport': object(), 'collections': {
            ('artifact_image', SCOPE): {'status': 'collected', 'items': [row, unselected]},
            ('artifact_repository', SCOPE): {'status': 'collected', 'items': REPOSITORIES},
            ('project', SCOPE): {'status': 'collected', 'items': PROJECTS}}})()
    inspection.enrich(collector, reader_factory=lambda transport: reader)
    assert calls == [('bind', expected, SCOPE), ('inspect', expected, SCOPE)]
    assert options == before
    assert reader.closed is True
    assert row['_coverage'][inspection.native.MARKER] == {
        'status': 'collected', 'source_requests': ['fixture-native-read']}
    assert row['_provenance']['scope'] == SCOPE
    assert row['_provenance']['source_requests'] == ['fixture-native-read']
    selection = collector.artifact_image_secret_selections[SCOPE]
    assert selection['unresolved'] == ([missing] if missing_selected_digest else [])
    context = {'scope': SCOPE, 'metadata': {'artifact_image_secret_selections': {SCOPE: selection}}}
    assert reviewed_predicate().evaluate(unselected, {'context': context})[0] == 'NOT_APPLICABLE'


def reviewed_predicate():
    from peaso.checks import gcp_image_stream_review_20261021 as reviewed
    return reviewed


def index(row):
    return {'context': {'provider': 'gcp', 'scope': SCOPE}, 'collections': {
        kind: [{'scope': SCOPE, 'status': 'collected', 'items': rows}]
        for kind, rows in [('artifact_image', [row]), ('artifact_repository', REPOSITORIES), ('project', PROJECTS)]}}


def test_large_complete_marker_is_accepted_by_identical_predicate_with_new_capacities(scans):
    row, blobs = image(9 * 1024 * 1024)
    result, _, _ = run(row, blobs)
    row[inspection.native.MARKER] = result
    review = reviewed_predicate()
    assert review._leaf_evaluate.__code__ is review.predecessor.evaluate.__code__
    assert review.predecessor.evaluate(row, index(row))[0] == 'UNKNOWN'
    assert review.evaluate(row, index(row))[0] == 'PASS'


def test_confirmed_leak_survives_later_rootfs_failure(monkeypatch):
    calls = []
    def scan(data, path, timeout, *, _redact_values=None):
        calls.append(path)
        return {'complete': True, 'engines': [
            {'engine': 'kingfisher', 'version': inspection.native.KINGFISHER_VERSION, 'status': 'complete'},
            {'engine': 'trufflehog', 'version': inspection.native.TRUFFLEHOG_VERSION, 'status': 'complete'}],
            'leaks': [{'fingerprint': 'a' * 64,
                'detectors': [{'engine': 'kingfisher', 'rule': 'synthetic'}],
                'locations': [{'path': path, 'line': 1}]}]}
    monkeypatch.setattr(inspection.native, 'scan_content', scan)
    row, blobs = image(bad_diff=True)
    result, _, _ = run(row, blobs)
    row[inspection.native.MARKER] = result
    assert result['status'] == 'partial'
    assert result['complete'] is False
    assert len(result['leaks']) == 1
    assert reviewed_predicate().evaluate(row, index(row))[0] == 'FAIL'


@pytest.mark.parametrize('header', [b'PK\x03\x04', b'\x1f\x8b', b'BZh', b'\xfd7zXZ',
                                   b'7z\xbc\xaf', b'Rar!', b'\x28\xb5\x2f\xfd'])
def test_unexpanded_nested_archive_is_never_a_clean_image(scans, header):
    row, blobs = image(body=header + b'unexpanded content')
    result, _, _ = run(row, blobs)
    assert result['status'] == 'partial'
    assert result['complete'] is False
    row[inspection.native.MARKER] = result
    assert reviewed_predicate().evaluate(row, index(row))[0] == 'UNKNOWN'


def test_installer_replaces_only_the_existing_check_and_is_idempotent():
    from peaso.checks import CHECKS
    from dataclasses import replace
    review = reviewed_predicate()
    before = list(CHECKS)
    try:
        matches = [i for i, check in enumerate(CHECKS) if check.id == review.predecessor.CHECK_ID]
        assert len(matches) == 1
        position = matches[0]
        review.install()
        assert len(CHECKS) == len(before)
        assert CHECKS[position].evaluate.__wrapped__ is review.evaluate
        assert CHECKS[position] == replace(before[position], evaluate=CHECKS[position].evaluate)
        assert CHECKS[position].evaluate is not review.evaluate
        assert CHECKS[position].evaluate(None, {})[0] == 'UNKNOWN'
        assert all(CHECKS[i] is item for i, item in enumerate(before) if i != position)
        review.install()
    finally:
        CHECKS[:] = before
