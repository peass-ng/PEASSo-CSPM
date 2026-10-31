"""A bad full-object digest is never treated as a transient transport error."""
import importlib.util
from pathlib import Path

import pytest
from peaso.collectors import aws_package_content_indicators as content

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('peaso.collectors._digest_resume_test',
    ROOT/'peaso/collectors/aws_image_vulnerability_native_20261021.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
spec = importlib.util.spec_from_file_location('resume_digest_fixture',
    ROOT/'tests/synthetic/benchmark_peaso_ecr_resume.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def test_complete_wrong_digest_fails_once_and_removes_file(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    payload = b'owned-fixture-bytes'*1024
    state = fixture.requests()
    with fixture.LocalFixture(payload, mode='clean') as server:
        monkeypatch.setattr(content, 'build_opener', server.opener)
        with pytest.raises(ValueError, match='^image_blob_download_unavailable$'):
            native.download_blob_path(state, fixture.URL, fixture.REGION,
                'sha256:'+'0'*64, len(payload), tmp_path/'layer')
    assert state.calls == 1 and server.requests == [None]
    assert not (tmp_path/'layer').exists()
