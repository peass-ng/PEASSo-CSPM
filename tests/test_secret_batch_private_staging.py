"""Without Linux /dev/shm, batches stage in a private temp dir removed after the scan."""
import json
import os
import stat
from pathlib import Path

from peaso import secret_scanning as scanning, secret_scanning_batch as batch


def test_batch_stages_in_private_temp_dir_without_dev_shm(monkeypatch, tmp_path):
    monkeypatch.setattr(batch.sys, 'platform', 'darwin')
    monkeypatch.setattr(batch.tempfile, 'gettempdir', lambda: str(tmp_path))
    monkeypatch.setattr(scanning, '_trufflehog', lambda: '/synthetic-tool')
    seen = []

    def run(argv, payload, timeout):
        paths = [Path(x) for x in argv if str(tmp_path) in x]
        seen.extend(stat.S_IMODE(p.parent.stat().st_mode) for p in paths)
        return b'\n'.join(json.dumps({
            'Raw': 'synthetic-token', 'Verified': False, 'DetectorName': 'Synthetic',
            'SourceMetadata': {'Data': {'Filesystem': {'file': str(p)}}},
        }).encode() for p in paths if b'synthetic-token' in p.read_bytes())
    monkeypatch.setattr(scanning, '_run', run)

    assert batch._volatile_shm_available(1024)
    items = [(b'synthetic-token one', 'a'), (b'clean two', 'b')]
    prepared = batch._prepare_trufflehog_batch(items, 30)
    assert seen == [0o700, 0o700]
    assert b'synthetic-token' in prepared[items[0]] and prepared[items[1]] == b''
    assert not os.listdir(tmp_path)
