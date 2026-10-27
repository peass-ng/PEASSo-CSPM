"""Current Cloud Build batching preserves the original private source witnesses."""
import hashlib
from pathlib import Path
import pytest
import peaso.checks
from peaso import private_secret_source_epoch_20261021 as epoch
from peaso.collectors import gcp_configuration_secret_indicators as projection
ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'peaso/collectors/gcp_configuration_secret_indicators.py'


def test_current_definition_and_exact_original_archive_predecessor():
    row = epoch.source_rows()[SOURCE]
    definition = row['definitions'][0]
    assert definition['after'] == 'c816006f295a07a925f9c99b77cdce532ddb1b9fdf5b248be42a7e06b8812ac8'
    assert definition['before'] == 'eecd847f28ac0b50a4f77b7648d3df53be3538277f736a381c775e5f615b4747'
    proof = epoch.trusted_definition(projection.project_response, ROOT)
    assert proof['current']['source_sha256'] != definition['after']
    assert proof['historical']['source_sha256'] == definition['before']
    raw = (ROOT / SOURCE).read_bytes()
    assert proof['current']['file_sha256'] == hashlib.sha256(raw).hexdigest()
    before = epoch.predecessor_bytes(SOURCE, raw, row['before_sha256'], ROOT)
    assert hashlib.sha256(before).hexdigest() == row['before_sha256']


@pytest.mark.parametrize('change', ['source', 'code', 'defaults', 'helper'])
def test_current_source_code_defaults_and_alias_helper_tamper_rejected(monkeypatch, change):
    if change == 'source':
        original = Path.read_bytes
        monkeypatch.setattr(Path, 'read_bytes', lambda path: original(path) + (b'\n' if path.resolve() == ROOT / SOURCE else b''))
    elif change == 'code':
        fn = projection.project_response
        monkeypatch.setattr(fn, '__code__', fn.__code__.replace(co_consts=fn.__code__.co_consts + ('foreign',)))
    elif change == 'defaults':
        monkeypatch.setattr(projection.project_response, '__kwdefaults__', {})
    else:
        fn = projection.number_alias
        monkeypatch.setattr(fn, '__code__', fn.__code__.replace(co_consts=fn.__code__.co_consts + ('foreign',)))
    with pytest.raises(epoch.AdmissionError):
        epoch.trusted_definition(projection.project_response, ROOT)
