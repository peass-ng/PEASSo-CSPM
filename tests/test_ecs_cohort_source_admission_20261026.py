"""Current ECS optimization preserves exact historical witnesses and live guards."""
from pathlib import Path

import pytest
from peaso import private_secret_source_epoch_20261021 as epoch
from peaso.collectors import aws_selected_configuration_secret_indicators as producer

ROOT = Path(epoch.__file__).resolve().parents[1]


def test_executing_code_tamper_rejected(monkeypatch):
    replacement = compile('def collect_selected(*args, **kwargs): return []', producer.__file__, 'exec').co_consts[0]
    monkeypatch.setattr(producer.collect_selected, '__code__', replacement)
    with pytest.raises(epoch.AdmissionError):
        epoch.trusted_definition(producer.collect_selected, ROOT)


