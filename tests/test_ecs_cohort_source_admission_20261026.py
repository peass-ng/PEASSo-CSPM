"""Current ECS optimization preserves exact historical witnesses and live guards."""
import hashlib
import json
from pathlib import Path

import pytest
from peaso import private_secret_source_epoch_20261021 as epoch
from peaso.collectors import aws_selected_configuration_secret_indicators as producer

ROOT = Path(epoch.__file__).resolve().parents[1]
TARGET = 'peaso/collectors/aws_selected_configuration_secret_indicators.py'


def test_current_and_historical_callable_proof():
    proof = epoch.trusted_definition(producer.collect_selected, ROOT)
    assert proof['current']['source_sha256'] == '85372f9597ec1d5ef8d84e2fea4ec2cdf980a72baaaa5f55c7a3916b54eb94ba'
    assert proof['historical']['source_sha256'] == 'd639bec8e2b20bd0ebdd72ef774995bbaa12f9ed0051cc4f6f4635290907cc0b'
    row = {'path': TARGET, 'qualname': 'collect_selected', 'sha256': proof['historical']['source_sha256']}
    assert epoch.callable_projection(producer.collect_selected, row, ROOT)['sha256'] == proof['current']['source_sha256']


def test_all_fifty_definition_witnesses_before_pins_and_archive_unchanged():
    receipt = json.loads((ROOT/'peaso/private_secret_source_epoch_20261021.json').read_bytes())
    rows = [{key: row[key] for key in ('path', 'before_sha256', 'definitions')} for row in receipt['sources']]
    assert len(rows) == 50
    assert hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest() == 'ab8fee380d3c6599a1c004e90422672d2c0ac62679afa5c94b92d3b6243a2026'
    assert hashlib.sha256((ROOT/'peaso/private_secret_source_epoch_20261021.zip').read_bytes()).hexdigest() == '3eb403fa363c559f7053060d409f60ac8c693350350423a6dc775412df4300c0'


@pytest.mark.parametrize('tampered', [TARGET, 'peaso/secret_evidence.py'])
def test_live_source_and_dependency_tamper_rejected_without_editing_checkout(tmp_path, tampered):
    for name in (TARGET, 'peaso/secret_evidence.py'):
        destination = tmp_path/name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((ROOT/name).read_bytes())
    row = epoch.source_rows()[TARGET]
    assert epoch._live(tmp_path, TARGET, row)[0] == (ROOT/TARGET).read_bytes()
    file = tmp_path/tampered
    file.write_bytes(file.read_bytes()+b'\n# changed source\n')
    with pytest.raises(epoch.AdmissionError):
        epoch._live(tmp_path, TARGET, row)


def test_executing_code_tamper_rejected(monkeypatch):
    replacement = compile('def collect_selected(*args, **kwargs): return []', producer.__file__, 'exec').co_consts[0]
    monkeypatch.setattr(producer.collect_selected, '__code__', replacement)
    with pytest.raises(epoch.AdmissionError):
        epoch.trusted_definition(producer.collect_selected, ROOT)


def test_defaults_tamper_rejected(monkeypatch):
    monkeypatch.setattr(producer.collect_selected, '__defaults__', (None,))
    with pytest.raises(epoch.AdmissionError):
        epoch.trusted_definition(producer.collect_selected, ROOT)


def test_global_bound_tamper_rejected(monkeypatch):
    monkeypatch.setattr(producer, 'MAX_TOTAL', 0)
    with pytest.raises(epoch.AdmissionError):
        epoch.trusted_definition(producer.collect_selected, ROOT)


def test_foreign_callable_reference_rejected():
    row = {'path': 'peaso/collectors/aws.py', 'qualname': 'collect_selected',
           'sha256': 'd639bec8e2b20bd0ebdd72ef774995bbaa12f9ed0051cc4f6f4635290907cc0b'}
    with pytest.raises(epoch.AdmissionError):
        epoch.callable_projection(producer.collect_selected, row, ROOT)


def test_unchanged_native_projection_and_extraction_remain_admitted():
    for name in ('project_response', 'extract'):
        epoch.trusted_definition(getattr(producer, name), ROOT)
