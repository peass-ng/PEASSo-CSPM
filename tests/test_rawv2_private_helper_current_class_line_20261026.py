"""Current class metadata follows the exact admitted helper, preserving history."""
import ast
import hashlib
import json
from pathlib import Path

import pytest

from peaso import private_secret_source_epoch_20261021 as epoch
from peaso import rawv2_private_source_successor_20261021 as rawv2
from peaso import secret_evidence


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / rawv2.PRIVATE_HELPER
RECEIPT = ROOT / rawv2.RECEIPT
RECEIPT_SHA256 = '5d55cdb408eefce6021a0506b076306ce8219d846971adf4bc4e4c9df5402ca6'


@pytest.fixture
def current_class_lines(monkeypatch):
    # Python 3.13+ creates this metadata. Exercise the same guard on 3.12 too.
    for node in ast.parse(HELPER.read_bytes()).body:
        if isinstance(node, ast.ClassDef):
            monkeypatch.setattr(getattr(secret_evidence, node.name), '__firstlineno__',
                                node.lineno, raising=False)
    return json.loads(RECEIPT.read_bytes())


def test_exact_admitted_current_helper_preserves_immutable_class_witness(current_class_lines):
    raw = HELPER.read_bytes()
    assert hashlib.sha256(RECEIPT.read_bytes()).hexdigest() == RECEIPT_SHA256
    assert current_class_lines['private_helper_classes']['EphemeralCipher']['lineno'] == 794
    before = epoch.predecessor_bytes(rawv2.PRIVATE_HELPER, raw, rawv2.PRIVATE_HELPER_SHA256, ROOT)
    assert hashlib.sha256(before).hexdigest() == rawv2.PRIVATE_HELPER_SHA256
    assert secret_evidence.EphemeralCipher.__firstlineno__ == 898
    assert rawv2._verify_private_helper(ROOT, current_class_lines) is True


@pytest.mark.parametrize('line', [794, 899, True])
def test_stale_forged_or_noninteger_current_class_line_rejected(monkeypatch, current_class_lines, line):
    monkeypatch.setattr(secret_evidence.EphemeralCipher, '__firstlineno__', line)
    with pytest.raises(RuntimeError, match='Private helper class line changed: EphemeralCipher'):
        rawv2._verify_private_helper(ROOT, current_class_lines)


def test_current_method_code_still_requires_exact_source(monkeypatch, current_class_lines):
    method = secret_evidence.EphemeralCipher.encrypt
    monkeypatch.setattr(method, '__code__', method.__code__.replace(
        co_consts=method.__code__.co_consts + ('foreign',)))
    with pytest.raises(RuntimeError, match='Private helper live method changed: EphemeralCipher.encrypt'):
        rawv2._verify_private_helper(ROOT, current_class_lines)


def test_unadmitted_source_rejected_before_current_metadata(monkeypatch, current_class_lines):
    original = Path.read_bytes

    def changed(path):
        value = original(path)
        return value + b'\n' if path.resolve() == HELPER else value

    # A plausible current metadata value cannot authorize changed source bytes.
    monkeypatch.setattr(secret_evidence.EphemeralCipher, '__firstlineno__', 803)
    monkeypatch.setattr(Path, 'read_bytes', changed)
    with pytest.raises(epoch.AdmissionError, match='unreviewed predecessor request'):
        rawv2._verify_private_helper(ROOT, current_class_lines)
