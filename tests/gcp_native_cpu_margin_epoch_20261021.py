"""Finite CPU artifact-only successor; original predecessor bytes remain pinned."""
import gzip
import hashlib
import json

FIXTURE = 'tests/fixtures/gcp_native_cpu_margin_predecessor_20261021.json.gz'
FIXTURE_SHA256 = '005e18b792bfb9fcdaffc93a97287228913bb235b04e90fa2423cf50c168fd21'
CHANGES = {'peaso/checks/gcp_positive_conservation_shared_source_successor_20261020.py': {'before_sha256': 'ad8275dce86cfb6bf0b04b206db23ccf6d0a4c0bbf74301c33d4df65de4955cb', 'after_sha256': '3c8773e8b3b051c9106d09afef17f281003ab107df6a368fd917afbecc3ecbea'}, 'peaso/checks/gcp_positive_conservation_source_bridge_20261020.json': {'before_sha256': 'a3df8dc295d0ca6cd9a7e7cabd11af2036d6dc245e52bb55f0273ca7ff8ec2e9', 'after_sha256': '833f82de54bc9c0cdae0143ecf09e7b8dbcb0509af958512449bf12ea16397a6'}, 'peaso/gcp_positive_conservation_source_admission_successor_20261020.py': {'before_sha256': 'f077d9937a0ce9e0363c622255e917968f1142c49afec92dec25c8880debcd40', 'after_sha256': '8c7fe64a893645a7facd75c5f49bc2c3e6239488022e0a504b1bb65786558bd3'}}

# Exact successor tuple. Update these three pins together for an assessed runtime
# successor; a caller cannot choose a new tuple through function arguments.
CURRENT_CPU_MARGIN_SHA256 = {
    'peaso/checks/gcp_positive_conservation_shared_source_successor_20261020.py': 'c038db3dd79631ba4eec2fc86194a4ecccb426cd2c0253112e120c3994da9820',
    'peaso/checks/gcp_positive_conservation_source_bridge_20261020.json': '1c7fb74ae85374da9a3dc163760c59c6e8c77af2a6e6f2502724c4eec8e7f4c2',
    'peaso/gcp_positive_conservation_source_admission_successor_20261020.py': '7c8a89db080244abaefe9712caff8ce11ba8fe1bcbb7fa61aa0e3897aefc7278',
}
PRE_RAWV2_FIXTURE = 'tests/fixtures/gcp_native_cpu_margin_pre_rawv2_20261021.json.gz'
PRE_RAWV2_FIXTURE_SHA256 = '17597fd6b63779b9a65bde9585b1e96cc195e5c862445bac85b681a24f388a82'


def cpu_margin_pre_rawv2_bytes(root, name, current=None):
    """Project only the exact current triplet to the pinned CPU-margin triplet."""
    if name not in CHANGES:
        raise AssertionError('unreviewed CPU source path')
    if set(CURRENT_CPU_MARGIN_SHA256) != set(CHANGES):
        raise AssertionError('CPU successor tuple changed')
    fixture = (root / PRE_RAWV2_FIXTURE).read_bytes()
    assert hashlib.sha256(fixture).hexdigest() == PRE_RAWV2_FIXTURE_SHA256
    before = json.loads(gzip.decompress(fixture))
    assert set(before) == set(CHANGES)
    for path, row in before.items():
        assert row['sha256'] == CHANGES[path]['after_sha256']
        assert hashlib.sha256(bytes.fromhex(row['hex'])).hexdigest() == row['sha256']
    for path, digest in CURRENT_CPU_MARGIN_SHA256.items():
        raw = current if path == name and current is not None else (root / path).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == digest
    return bytes.fromhex(before[name]['hex'])


def predecessor_bytes(root, name, current=None):
    if name not in CHANGES:
        raise AssertionError('unreviewed CPU source path')
    raw = (root / FIXTURE).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == FIXTURE_SHA256
    before = json.loads(gzip.decompress(raw))
    assert set(before) == set(CHANGES)
    for path, row in before.items():
        assert row['sha256'] == CHANGES[path]['before_sha256']
        assert hashlib.sha256(bytes.fromhex(row['hex'])).hexdigest() == row['sha256']
    current = (root / name).read_bytes() if current is None else current
    assert hashlib.sha256(current).hexdigest() == CHANGES[name]['after_sha256']
    return bytes.fromhex(before[name]['hex'])
