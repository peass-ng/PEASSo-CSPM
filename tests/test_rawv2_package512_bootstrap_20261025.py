"""Finite batch512 bootstrap preserves the immutable RawV2 epoch and fresh proofs."""
import hashlib
import json
from pathlib import Path
import pytest
from peaso import private_secret_source_epoch_20261021 as epoch
from peaso.checks import private_secret_shared_source_successor_20261021 as shared
from peaso.collectors import aws_package_content_indicators as package
ROOT = Path(__file__).resolve().parents[1]
PACKAGE = 'peaso/collectors/aws_package_content_indicators.py'
GUARD = 'peaso/rawv2_private_source_successor_20261021.py'
PACKAGE_BEFORE = 'ce459d4b5ed0ae991591f09f61b462f7841f0977d5935579e561409c0117e7e6'
GUARD_BEFORE = '3ef9840685cc94829a12c7c54693da901ac6ddb691f493e53290255c5224d940'


def test_current_package_producer_projection_retains_source_and_module_binding():
    row = epoch.source_rows()[PACKAGE]
    definition = next(item for item in row['definitions'] if item['name'] == '_image')
    old = {'path': PACKAGE, 'qualname': '_image', 'sha256': definition['before'],
           'module_sha256': row['before_sha256']}
    current = shared.rawv2_current_content_projection(package._image, old, ROOT)
    assert current['sha256'] == json.loads((ROOT / shared._PRIVATE_RECEIPT).read_bytes())['rawv2_package128_admission']['current_definitions']['_image']['current_sha256']
    assert current['module_sha256'] == hashlib.sha256((ROOT / PACKAGE).read_bytes()).hexdigest()
    with pytest.raises(epoch.AdmissionError):
        shared.rawv2_current_content_projection(package._image, dict(old, sha256='0' * 64), ROOT)
