"""Selected DB lifecycle and credential isolation; no real downloads."""
import importlib.util
import json
import os
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('db_runtime', ROOT/'peaso/trivy_database_20261021.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_disabled_no_files_or_subprocess(tmp_path, monkeypatch):
    def forbidden(*a,**kw): raise AssertionError('disabled work')
    monkeypatch.setattr(module, 'refresh', forbidden)
    root = tmp_path/'absent'
    with module.database_lease(enabled=False, cache_root=root) as cache:
        assert cache is None
    assert not root.exists()


def test_refresh_missing_once_then_reuse_under_lock(tmp_path, monkeypatch):
    from peaso import trivy_container_runner_20261020 as scanner

    bundled = tmp_path / 'missing' / 'trivy'
    local = tmp_path / 'bin' / 'trivy'
    local.parent.mkdir()
    local.touch(mode=0o700)
    monkeypatch.setattr(scanner, 'DEFAULT_CLI', str(bundled))
    monkeypatch.setenv('PATH', str(local.parent))
    root = tmp_path/'cache'
    generation = root/'generations'/'fixture'
    calls = []
    def current(root):
        if not generation.exists(): raise module.DatabaseUnavailable('missing')
        return generation
    def refresh(root, **kwargs):
        calls.append(kwargs)
        generation.mkdir(parents=True)
        return generation
    monkeypatch.setattr(module,'current_cache',current)
    monkeypatch.setattr(module,'refresh',refresh)
    for _ in range(2):
        with module.database_lease(enabled=True, cache_root=root) as cache:
            assert cache == generation.resolve()
            fd = os.open(root/'.lease', os.O_RDWR)
            try:
                with pytest.raises(BlockingIOError):
                    module.fcntl.flock(fd,module.fcntl.LOCK_EX|module.fcntl.LOCK_NB)
            finally: os.close(fd)
    assert calls == [{'trivy': str(local)}]


def test_failed_refresh_releases_lock_and_keeps_failure(tmp_path,monkeypatch):
    root=tmp_path/'cache'
    def unavailable(*a,**kw): raise module.DatabaseUnavailable('unavailable')
    monkeypatch.setattr(module,'current_cache',unavailable)
    monkeypatch.setattr(module,'refresh',unavailable)
    with pytest.raises(module.DatabaseUnavailable):
        with module.database_lease(enabled=True,cache_root=root):
            pytest.fail('failed DB became scanable')
    fd=os.open(root/'.lease',os.O_RDWR)
    try: module.fcntl.flock(fd,module.fcntl.LOCK_EX|module.fcntl.LOCK_NB)
    finally: os.close(fd)


def test_download_environment_is_closed_and_empty_config(tmp_path,monkeypatch):
    for name in ('AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_CONTAINER_CREDENTIALS_RELATIVE_URI',
                 'GOOGLE_APPLICATION_CREDENTIALS','AZURE_CLIENT_SECRET','HTTPS_PROXY','TRIVY_USERNAME'):
        monkeypatch.setenv(name,'synthetic-must-not-pass')
    seen=[]
    class Usage: free=module.MAX_CACHE_BYTES+module.FREE_RESERVE_BYTES+1
    monkeypatch.setattr(module.shutil,'disk_usage',lambda root:Usage())
    def download(argv,staging,env):
        assert not any(value=='synthetic-must-not-pass' for value in env.values())
        assert set(env)=={'PATH','HOME','XDG_CONFIG_HOME','TMPDIR','TRIVY_DISABLE_TELEMETRY','LANG','NO_COLOR'}
        config=Path(argv[argv.index('--config')+1])
        assert json.loads(config.read_text())=={}
        assert argv[argv.index('--db-repository')+1]=='ghcr.io/aquasecurity/trivy-db:2'
        seen.append(env)
    monkeypatch.setattr(module,'_download',download)
    monkeypatch.setattr(module,'validate_db',lambda *a,**kw:{})
    module.refresh(tmp_path/'cache')
    assert len(seen)==1


def test_linked_root_and_lock_rejected(tmp_path):
    root=tmp_path/'cache'; root.mkdir()
    (root/'.lease').symlink_to(tmp_path/'other')
    with pytest.raises(OSError):
        with module.database_lease(enabled=True,cache_root=root):pass
    link=tmp_path/'linked';link.symlink_to(root,target_is_directory=True)
    with pytest.raises(module.DatabaseUnavailable):
        with module.database_lease(enabled=True,cache_root=link):pass
