"""New native declarations cannot be admitted with absent or incomplete witnesses."""
import json
from pathlib import Path

import pytest

from peaso.checks import CHECKS
from peaso.checks import azure_automation_aci_metadata_review_20261020 as module


@pytest.mark.parametrize('fault', ['absent', 'invalid_json', 'empty', 'missing_unknown_index'])
def test_incomplete_native_fixture_admission_fails_before_changing_registry(monkeypatch, fault):
    target = Path(module.__file__).with_name('azure_automation_aci_metadata_review_20261020_fixtures.json')
    original = target.read_text()
    read_text = Path.read_text
    fixtures = json.loads(original)
    if fault == 'missing_unknown_index':
        del fixtures[module.AUTOMATION]['unknown_index']

    def damaged(path, *args, **kwargs):
        if path != target:
            return read_text(path, *args, **kwargs)
        if fault == 'absent':
            raise FileNotFoundError('fixture unavailable')
        if fault == 'invalid_json':
            return '{'
        return '{}' if fault == 'empty' else json.dumps(fixtures)

    before = tuple(CHECKS)
    monkeypatch.setattr(Path, 'read_text', damaged)
    with pytest.raises((FileNotFoundError, json.JSONDecodeError, RuntimeError)):
        module.install()
    assert tuple(CHECKS) == before


