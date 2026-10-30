"""Current Cloud Build batching preserves the original private source witnesses."""
from pathlib import Path
import pytest
from peaso import private_secret_source_epoch_20261021 as epoch
from peaso.collectors import gcp_configuration_secret_indicators as projection
ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'peaso/collectors/gcp_configuration_secret_indicators.py'


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
