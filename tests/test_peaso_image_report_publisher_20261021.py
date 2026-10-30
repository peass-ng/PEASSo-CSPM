from copy import deepcopy
from peaso.storage import FileArtifacts
from peaso.storage.reports import publish_report
from peaso.snapshot import make_snapshot
from tests.test_peaso_image_findings_20261021 import BASE


def _proof(tmp_path):
    from peaso import analysis, engine  # Same native analyzer context as the worker.
    artifacts = FileArtifacts(tmp_path)
    ident = 'a' * 32
    observation = deepcopy(BASE)
    observation['scan']['stderr'] = 'synthetic-sensitive-canary'
    metadata = {'image_vulnerability_scan': {'selected': True, 'observations': [observation]}}
    report = {'schema_version': '1.0', 'provider': 'gcp', 'snapshot_id': 'fixture',
              'created_at': '2026-10-21T00:00:00Z', 'scopes': ['projects/example-project'],
              'snapshot_metadata': deepcopy(metadata), 'resources': [], 'findings': [],
              'coverage': [], 'stats': {'finding_count': 0, 'resource_count': 0}, 'graphs': {}}
    snapshot = make_snapshot('gcp', ['projects/example-project'], [], metadata=metadata)
    reference = publish_report(artifacts, 'workspace-a', ident, report, snapshot)
    manifest = artifacts.get('workspace-a', reference)
    assert 'image_vulnerability_scan' in manifest
    assert 'image_vulnerability_scan' not in manifest['summary']['snapshot_metadata']
    public = artifacts.get('workspace-a', manifest['report_json'])
    assert 'image_vulnerability_scan' not in public['snapshot_metadata']
    captured = artifacts.get('workspace-a', manifest['image_vulnerability_scan']['artifact'])
    assert captured['observations'][0]['scan']['findings'][0]['package'] == 'busybox'
    assert 'stderr' not in captured['observations'][0]['scan']
    assert report['snapshot_metadata'] == metadata


def test_real_report_publisher_keeps_images_separate_and_safe(tmp_path):
    import os
    import subprocess
    import sys
    from pathlib import Path
    # The child checks report publication in the shipped attestation mode. The
    # suite-wide PEASO_SOURCE_ATTESTATION=always re-proves every pinned source on
    # each nested call during the cold peaso.checks import (minutes of CPU), which
    # is unrelated to keeping image observations separate and safe.
    env = {key: value for key, value in os.environ.items() if key != 'PEASO_SOURCE_ATTESTATION'}
    result = subprocess.run([sys.executable, '-c',
        'from pathlib import Path; from tests.test_peaso_image_report_publisher_20261021 import _proof; import sys; _proof(Path(sys.argv[1]))', str(tmp_path)],
        cwd=str(Path(__file__).parent), env={**env, 'PYTHONPATH':os.pathsep.join(sys.path), 'PYTHONDONTWRITEBYTECODE':'1'},
        capture_output=True, text=True, timeout=180)
    assert result.returncode == 0, result.stderr
