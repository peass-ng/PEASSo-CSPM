"""Record reviewed current bytes for the two whole-tree conservation tests.

tests/test_native_admission_cpu_successor_20261020.py and
tests/test_provider_combined_source_bridge_20261020.py pin every file of an
earlier package.  After an integration has been reviewed, run this from the
repository root to record the exact current bytes of every file that differs:

    PYTHONPATH=$PWD python scripts/peaso_reviewed_successors_refresh.py

It rewrites tests/fixtures/reviewed_current_successors_20261026.json.gz and the
fixture digest in tests/reviewed_current_successors_20261026.py.  The rows that
the tests already record in source are never changed.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'tests/reviewed_current_successors_20261026.py'


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _project(manifest, reviewed, read, skip):
    changes, reverted = {}, []
    for name, row in sorted(manifest.items()):
        if name in skip:
            continue
        raw = read(name)
        current, prior = _sha(raw), reviewed.get(name)
        if current == row['sha256']:
            if prior:
                reverted.append(name)
            continue
        if prior and prior['after_sha256'] == current and prior['after_size'] == len(raw):
            continue
        changes[name] = [row['sha256'], prior['after_sha256'] if prior else None, current, len(raw)]
    return {'changes': changes, 'reverted': reverted}


def main() -> None:
    import tests.reviewed_current_successors_20261026 as successors

    # Load the in-source maps alone: the tests must not apply the old fixture.
    successors.extend = lambda section, reviewed, reviewable: frozenset(reviewable)
    import tests.test_native_admission_cpu_successor_20261020 as native
    import tests.test_provider_combined_source_bridge_20261020 as bridge

    def read(name):
        if name == native.RETIRED_CATALOG_PATH:
            return native.retired_catalog_bytes(ROOT, name)
        if name == native.RETAINED_UPSTREAM_PATH:
            return native.retained_upstream_bytes(ROOT)
        return (ROOT / name).read_bytes()

    initializer = {'peaso/checks/__init__.py'}
    epoch = json.loads(gzip.decompress((ROOT / native.EPOCH).read_bytes()))['files']
    value = {
        'schema': 1,
        'native_admission_cpu_successor_20261020': _project(
            epoch, native.REVIEWED_CURRENT_CHANGES, read, initializer),
        'provider_combined_source_bridge_20261020': _project(
            bridge.pinned_baseline()['files'], bridge.REVIEWED_CURRENT_CHANGES, read,
            set(bridge.GENERATED_CATALOGS) | initializer),
    }
    raw = gzip.compress(json.dumps(value, sort_keys=True, separators=(',', ':')).encode(),
                        compresslevel=9, mtime=0)
    successors.FIXTURE.write_bytes(raw)
    source = HELPER.read_text()
    source, count = re.subn(r"(?m)^FIXTURE_SHA256 = '[0-9a-f]{64}'$",
                            f"FIXTURE_SHA256 = '{_sha(raw)}'", source)
    assert count == 1
    HELPER.write_text(source)
    for section, rows in value.items():
        if section != 'schema':
            print(section, len(rows['changes']), 'changed,', len(rows['reverted']), 'reverted')


if __name__ == '__main__':
    main()
