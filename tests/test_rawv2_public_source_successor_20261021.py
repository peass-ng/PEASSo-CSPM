"""Pure finite-source checks; package bootstrap integration runs separately."""
import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'peaso/rawv2_public_source_successor_20261021.py'


def helper():
    spec = importlib.util.spec_from_file_location('rawv2_source_isolated_test', HELPER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class RawV2PublicSourceSuccessorTest(unittest.TestCase):
    def test_exact_retained_source_and_helper_receipt(self):
        module = helper()
        receipt = module._receipt(ROOT)
        old = (ROOT / module.SCANNER).read_bytes()
        if hashlib.sha256(old).hexdigest() != module.SCANNER_AFTER:
            # Later scanner edits are admitted by the immutable 2026-10-21 source
            # epoch, whose archived predecessor is exactly this successor's after.
            from peaso import private_secret_source_epoch_20261021 as epoch
            self.assertEqual(epoch.source_rows()[module.SCANNER]['before_sha256'], module.SCANNER_AFTER)
            old = epoch.predecessor_bytes(module.SCANNER, old, module.SCANNER_AFTER, ROOT)
        self.assertEqual(hashlib.sha256(old).hexdigest(), module.SCANNER_AFTER)
        for edit in reversed(receipt['edits']):
            after = edit['after'].encode()
            self.assertEqual(old.count(after), 1)
            old = old.replace(after, edit['before'].encode(), 1)
        self.assertEqual(hashlib.sha256(old).hexdigest(), module.SCANNER_BEFORE)
        self.assertEqual(set(module._function_sources(old)), set(receipt['before_functions']))

    def test_other_sources_require_exact_hash_and_scanner_rejects_wrong_pin(self):
        module = helper()
        expected = hashlib.sha256(b'unchanged').hexdigest()
        self.assertEqual(module.source_bytes('other', b'unchanged', expected, ROOT), b'unchanged')
        with self.assertRaises(RuntimeError):
            module.source_bytes('other', b'changed', expected, ROOT)
        with self.assertRaises(RuntimeError):
            module.source_bytes(module.SCANNER, b'changed', module.SCANNER_BEFORE, ROOT)



if __name__ == '__main__':
    unittest.main()
