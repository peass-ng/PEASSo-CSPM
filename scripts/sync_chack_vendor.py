#!/usr/bin/env python3
"""Re-sync peaso/ai/_vendor/chack from the latest chack-agent master.

The worker installs chack-agent from master, so the vendored SDK-free helpers must
track master too. Without --source the script shallow-clones master; --check exits 1
when the vendored bytes differ from that tree instead of writing anything.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

SOURCE_URL = 'https://github.com/carlospolop/chack-agent.git'
VENDOR = Path(__file__).resolve().parents[1] / 'peaso/ai/_vendor/chack'
COMMIT_RE = re.compile(r'\b[0-9a-f]{40}\b')


def _git(*arguments, cwd=None):
    return subprocess.run(['git', *arguments], cwd=cwd, check=True, text=True, timeout=180,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'}).stdout.strip()


def stale_files(vendor: Path, source: Path) -> list[str]:
    """Vendored files whose bytes differ from the upstream tree at ``source``."""
    manifest = json.loads((vendor / 'provenance.json').read_text())
    return sorted(name for name, entry in manifest['files'].items()
                  if not (vendor / name).is_file()
                  or (vendor / name).read_bytes() != (source / entry['upstream_path']).read_bytes())


def sync(vendor: Path, source: Path, commit: str) -> list[str]:
    """Copy upstream bytes into ``vendor`` and record ``commit``; returns the changed files."""
    if not COMMIT_RE.fullmatch(commit):
        raise ValueError('commit must be a 40-character SHA')
    changed = stale_files(vendor, source)
    if not changed:
        return []
    manifest = json.loads((vendor / 'provenance.json').read_text())
    for name, entry in manifest['files'].items():
        data = (source / entry['upstream_path']).read_bytes()
        (vendor / name).parent.mkdir(parents=True, exist_ok=True)
        (vendor / name).write_bytes(data)
        entry.update(sha256=hashlib.sha256(data).hexdigest(), bytes=len(data))
    notice = vendor / manifest['license']['local_notice']
    notice.write_text(COMMIT_RE.sub(commit, notice.read_text(), count=1))
    manifest['commit'] = commit
    manifest['license']['notice_sha256'] = hashlib.sha256(notice.read_bytes()).hexdigest()
    (vendor / 'provenance.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return changed


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='fail when the vendored files are stale')
    parser.add_argument('--source', type=Path, help='existing chack-agent checkout (default: clone master)')
    arguments = parser.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix='chack-vendor-') as folder:
        source = arguments.source
        if source is None:
            source = Path(folder) / 'chack-agent'
            _git('clone', '--depth=1', '--branch=master', '--single-branch', SOURCE_URL, str(source))
        commit = _git('rev-parse', 'HEAD', cwd=source)
        if arguments.check:
            stale = stale_files(VENDOR, source)
            for name in stale:
                print(f'stale: {name} differs from chack-agent {commit}', file=sys.stderr)
            return 1 if stale else 0
        changed = sync(VENDOR, source, commit)
        print(f'synced {", ".join(changed)} from {commit}' if changed else f'already current with {commit}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
