"""Focused negatives for finite source proof reuse inside shared admission."""
import importlib
import inspect
import json
import sys
from pathlib import Path

import pytest

from peaso.checks import private_secret_shared_source_successor_20261021 as shared


ROOT = Path(__file__).resolve().parents[1]


def _row(gcp=False):
    receipt = json.loads((ROOT / 'peaso/checks' / shared.RECEIPT).read_bytes())
    qualified = next(qualified for qualified, row in receipt['functions'].items()
                     if not gcp or row['path'].startswith('peaso/checks/gcp_'))
    module_name, name = qualified.split(':')
    function = importlib.import_module(module_name)
    for part in name.split('.'):
        function = getattr(function, part)
    return function, receipt['functions'][qualified], qualified


def test_forged_batch_or_map_cannot_skip_source_proof():
    with pytest.raises(RuntimeError, match='Invalid finite callable proof batch'):
        shared._check_function(({'forged': 'map'},), None, ROOT, {})
    with pytest.raises(RuntimeError, match='Invalid finite callable proof batch'):
        shared._check_function(((_row()[0], _row()[1], 7),), None, ROOT, {})




