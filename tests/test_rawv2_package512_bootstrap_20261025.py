"""Finite batch512 bootstrap preserves the immutable RawV2 epoch and fresh proofs."""
import hashlib
from pathlib import Path
import pytest
from peaso import rawv2_private_source_successor_20261021 as rawv2
from peaso import private_secret_source_epoch_20261021 as epoch
from peaso.checks import private_secret_shared_source_successor_20261021 as shared
from peaso.collectors import aws_package_content_indicators as package
ROOT = Path(__file__).resolve().parents[1]
PACKAGE = 'peaso/collectors/aws_package_content_indicators.py'
GUARD = 'peaso/rawv2_private_source_successor_20261021.py'
PACKAGE_BEFORE = 'ce459d4b5ed0ae991591f09f61b462f7841f0977d5935579e561409c0117e7e6'
GUARD_BEFORE = '3ef9840685cc94829a12c7c54693da901ac6ddb691f493e53290255c5224d940'

def test_exact_current_sources_reconstruct_unchanged_ancestors():
    from peaso import checks
    assert len(checks.CHECKS) == 4179
    assert len(epoch.source_rows()) == 50
    assert hashlib.sha256((ROOT / 'peaso/private_secret_source_epoch_20261021.json').read_bytes()).hexdigest() == '013f6c236602e32ffcb54a00f19c46cd5255424dba35220e182232374faec5b5'
    source = (ROOT / PACKAGE).read_bytes()
    before = rawv2.source_bytes(PACKAGE, source, PACKAGE_BEFORE, ROOT)
    assert hashlib.sha256(before).hexdigest() == PACKAGE_BEFORE
    guard = shared.rawv2_bootstrap_source((ROOT / GUARD).read_bytes(), GUARD_BEFORE, ROOT)
    assert hashlib.sha256(guard).hexdigest() == GUARD_BEFORE
    rawv2._receipt(ROOT)

def test_current_package_producer_projection_retains_source_and_module_binding():
    row = epoch.source_rows()[PACKAGE]
    definition = next(item for item in row['definitions'] if item['name'] == '_image')
    old = {'path': PACKAGE, 'qualname': '_image', 'sha256': definition['before'],
           'module_sha256': row['before_sha256']}
    current = shared.rawv2_current_content_projection(package._image, old, ROOT)
    successor = shared._private_receipt()['rawv2_package128_admission']['current_definitions']['_image']
    assert successor['predecessor_sha256'] == definition['after']
    assert successor['predecessor_ast_sha256'] == definition['after_ast_sha256']
    assert current['sha256'] == successor['current_sha256']
    assert current['module_sha256'] == hashlib.sha256((ROOT / PACKAGE).read_bytes()).hexdigest()
    with pytest.raises(epoch.AdmissionError):
        shared.rawv2_current_content_projection(package._image, dict(old, sha256='0' * 64), ROOT)


def test_current_image_transition_rejects_tampered_live_callable(monkeypatch):
    row = epoch.source_rows()[PACKAGE]
    definition = next(item for item in row['definitions'] if item['name'] == '_image')
    old = {'path': PACKAGE, 'qualname': '_image', 'sha256': definition['before'],
           'module_sha256': row['before_sha256']}
    monkeypatch.setattr(package._image, '__code__', package._image.__code__.replace(
        co_consts=package._image.__code__.co_consts + ('unreviewed',)))
    with pytest.raises((RuntimeError, epoch.AdmissionError)):
        shared.rawv2_current_content_projection(package._image, old, ROOT)

@pytest.mark.parametrize('relative', [PACKAGE, GUARD, shared._PRIVATE_RECEIPT, 'peaso/private_secret_source_epoch_20261021.zip'])
def test_transient_fresh_source_or_receipt_mutation_rejected(monkeypatch, relative):
    source = (ROOT / PACKAGE).read_bytes()
    original = Path.read_bytes
    def changed(path):
        value = original(path)
        return value + b'\n' if path.resolve() == ROOT / relative else value
    with monkeypatch.context() as patch:
        patch.setattr(Path, 'read_bytes', changed)
        with pytest.raises((RuntimeError, epoch.AdmissionError)):
            shared.rawv2_package_source(source, PACKAGE_BEFORE, ROOT)
    assert hashlib.sha256(shared.rawv2_package_source(source, PACKAGE_BEFORE, ROOT)).hexdigest() == PACKAGE_BEFORE

@pytest.mark.parametrize('change', ['helper_code', 'helper_defaults', 'producer_code', 'producer_defaults'])
def test_live_helper_and_producer_mutation_rejected(monkeypatch, change):
    row = epoch.source_rows()[PACKAGE]
    definition = next(item for item in row['definitions'] if item['name'] == '_image')
    old = {'path': PACKAGE, 'qualname': '_image', 'sha256': definition['before']}
    if change == 'helper_code':
        monkeypatch.setattr(shared.rawv2_package_source, '__code__', shared.rawv2_package_source.__code__.replace(co_consts=shared.rawv2_package_source.__code__.co_consts + ('foreign',)))
    elif change == 'helper_defaults':
        monkeypatch.setattr(shared.rawv2_package_source, '__defaults__', ('foreign',))
    elif change == 'producer_code':
        monkeypatch.setattr(package._image, '__code__', package._image.__code__.replace(co_consts=package._image.__code__.co_consts + ('foreign',)))
    else:
        monkeypatch.setattr(package._image, '__defaults__', ('foreign',))
    with pytest.raises((RuntimeError, epoch.AdmissionError)):
        shared.rawv2_current_content_projection(package._image, old, ROOT)

def test_foreign_root_and_ancestor_rejected(tmp_path):
    source = (ROOT / PACKAGE).read_bytes()
    for expected, root in [(PACKAGE_BEFORE, tmp_path), ('0' * 64, ROOT)]:
        with pytest.raises(RuntimeError):
            shared.rawv2_package_source(source, expected, root)
