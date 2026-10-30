"""Offline packaging and DB lifecycle checks; never download or pull images."""

import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import struct

import pytest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("peaso_trivy_db", ROOT / "peaso/trivy_database_20261021.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
NOW = dt.datetime(2026, 10, 21, 4, 0, tzinfo=dt.timezone.utc)


def db_at(cache, *, updated=NOW, next_update=None, version=2):
    db = cache / "db"
    db.mkdir(parents=True)
    # bbolt meta-page format fixture only, not a complete scanner database.
    meta = struct.pack("<IIIIQQQQQ", 0xed0cdaed, 2, 4096, 0, 2, 0, 3, 4, 0)
    checksum = 14695981039346656037
    for octet in meta:
        checksum = ((checksum ^ octet) * 1099511628211) & ((1 << 64) - 1)
    raw = struct.pack("<QHHI", 0, 4, 0, 0) + meta + struct.pack("<Q", checksum)
    (db / "trivy.db").write_bytes(raw + bytes(16384 - len(raw)))
    (db / "metadata.json").write_text(json.dumps({
        "Version": version,
        "UpdatedAt": updated.isoformat(),
        "NextUpdate": (next_update or updated + dt.timedelta(hours=24)).isoformat(),
    }))






def test_only_collector_gets_trivy_in_multistage_image():
    dockerfile = (ROOT / "Dockerfile.peaso").read_text()
    runtime = dockerfile.split("FROM python:3.12-slim-bookworm AS runtime", 1)[1].split("FROM runtime AS collector", 1)[0]
    collector = dockerfile.split("FROM runtime AS collector", 1)[1].split("FROM runtime AS analyzer", 1)[0]
    analyzer_and_api = dockerfile.split("FROM runtime AS analyzer", 1)[1]
    assert "COPY --from=trivy-cli" not in runtime + analyzer_and_api
    assert "COPY --from=trivy-cli /usr/local/bin/trivy /usr/local/bin/trivy" in collector
    assert "COPY --from=trivy-cli /usr/local/bin/trivy /usr/local/bin/trivy" in (ROOT / "infra/aws/Dockerfile.worker").read_text()


@pytest.mark.parametrize("change", ["missing", "stale", "expired", "schema"])
def test_missing_or_stale_db_fails_closed(tmp_path, change):
    root = tmp_path / "cache"
    generation = root / "generations" / "old"
    if change != "missing":
        updated = NOW - dt.timedelta(hours=25) if change == "stale" else NOW
        expiry = NOW - dt.timedelta(seconds=1) if change == "expired" else None
        db_at(generation, updated=updated, next_update=expiry, version=1 if change == "schema" else 2)
    root.mkdir(exist_ok=True)
    (root / "current").symlink_to("generations/old")
    with pytest.raises((module.DatabaseUnavailable, OSError)):
        module.current_cache(root, NOW)


def test_refresh_uses_official_repo_and_switches_atomically(tmp_path, monkeypatch):
    root = tmp_path / "cache"
    old = root / "generations" / "old"
    db_at(old, updated=NOW - dt.timedelta(hours=1))
    (root / "current").symlink_to("generations/old")
    monkeypatch.setattr(module.shutil, "disk_usage", lambda _: type("Disk", (), {"free": 9 * 1024**3})())

    def fake_run(argv, staging, env):
        assert argv[0:2] == ["trivy", "image"]
        assert argv[argv.index("--db-repository") + 1] == module.DB_REPOSITORY
        assert env["TRIVY_DISABLE_TELEMETRY"] == "true"
        db_at(Path(argv[argv.index("--cache-dir") + 1]))
        assert (root / "current").resolve() == old

    monkeypatch.setattr(module, "_download", fake_run)
    new = module.refresh(root, now=NOW)
    assert (root / "current").resolve() == new
    assert old.exists()
    assert module.current_cache(root, NOW) == root / "current"


def test_failed_download_or_atomic_switch_preserves_good_db(tmp_path, monkeypatch):
    root = tmp_path / "cache"
    old = root / "generations" / "old"
    db_at(old, updated=NOW - dt.timedelta(hours=1))
    (root / "current").symlink_to("generations/old")
    monkeypatch.setattr(module.shutil, "disk_usage", lambda _: type("Disk", (), {"free": 9 * 1024**3})())

    def fail_download(*_args, **_kwargs):
        raise subprocess.CalledProcessError(1, "trivy")

    monkeypatch.setattr(module, "_download", fail_download)
    with pytest.raises(subprocess.CalledProcessError):
        module.refresh(root, now=NOW)
    assert (root / "current").resolve() == old
    assert not list(root.glob(".staging-*"))

    def fake_run(argv, staging, env):
        db_at(Path(argv[argv.index("--cache-dir") + 1]))

    monkeypatch.setattr(module, "_download", fake_run)
    original_replace = module.os.replace

    def fail_switch(src, dst):
        if Path(dst) == root / "current":
            raise OSError("atomic switch failed")
        return original_replace(src, dst)

    monkeypatch.setattr(module.os, "replace", fail_switch)
    with pytest.raises(OSError):
        module.refresh(root, now=NOW)
    assert (root / "current").resolve() == old
    assert sorted(x.name for x in (root / "generations").iterdir()) == ["old"]


def test_disk_bound_rejects_before_download(tmp_path, monkeypatch):
    monkeypatch.setattr(module.shutil, "disk_usage", lambda _: type("Disk", (), {"free": 1})())

    def no_download(*_args, **_kwargs):
        pytest.fail("download must not start without disk headroom")

    monkeypatch.setattr(module, "_download", no_download)
    with pytest.raises(module.DatabaseUnavailable, match="insufficient free disk"):
        module.refresh(tmp_path / "cache", now=NOW)


def test_refresh_retains_at_most_current_and_previous(tmp_path, monkeypatch):
    root = tmp_path / "cache"
    old = root / "generations" / "old"
    db_at(old, updated=NOW - dt.timedelta(hours=1))
    (root / "current").symlink_to("generations/old")
    monkeypatch.setattr(module.shutil, "disk_usage", lambda _: type("Disk", (), {"free": 9 * 1024**3})())

    def fake_run(argv, staging, env):
        db_at(Path(argv[argv.index("--cache-dir") + 1]))

    monkeypatch.setattr(module, "_download", fake_run)
    first = module.refresh(root, now=NOW)
    second = module.refresh(root, now=NOW)
    assert (root / "current").resolve() == second
    assert first.exists()
    assert not old.exists()
    assert len(list((root / "generations").iterdir())) == 2


@pytest.mark.parametrize("offset", [8,16,20,24,32,72])
def test_corrupt_bbolt_meta_never_admitted(tmp_path, offset):
    db_at(tmp_path)
    path = tmp_path / "db/trivy.db"
    raw = bytearray(path.read_bytes())
    raw[offset] ^= 1
    path.write_bytes(raw)
    with pytest.raises(module.DatabaseUnavailable):
        module.validate_db(tmp_path, NOW)


