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

    def test_finite_later_clones_have_exact_body_deltas(self):
        module = helper()
        receipt = module._receipt(ROOT)
        initializer = (ROOT / 'peaso/checks/__init__.py').read_text()
        self.assertEqual(set(receipt['clones']), set(module._LATER_ADMISSIONS))
        for name, row in receipt['clones'].items():
            guard = (ROOT / 'peaso/checks' / (name + '.py')).read_text()
            import ast
            node = next(item for item in ast.parse(guard).body
                        if isinstance(item, ast.FunctionDef) and item.name == 'reviewed_inputs')
            body = ''.join(guard.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])
            self.assertEqual(hashlib.sha256(body.encode()).hexdigest(), row['before_sha256'])
            self.assertEqual(body.count(row['before']), 1)
            transformed = body.replace(row['before'], row['after'], 1)
            if name == 'gcp_dataproc_source_runtime_admission_20261020':
                original_import = '    from .gcp_dataproc_referenced_source_proposal_20261020 import validate_proposal\n'
                self.assertEqual(transformed.count(original_import), 1)
                self.assertEqual(transformed.count('    validate_proposal()\n'), 1)
                transformed = transformed.replace(original_import, '', 1).replace(
                    '    validate_proposal()\n', '    _validate_dataproc_proposal()\n', 1)
            self.assertEqual(hashlib.sha256(transformed.encode()).hexdigest(), row['after_sha256'])
            compile(transformed, name, 'exec')
            if name == 'gcp_workbench_source_runtime_admission_20261020':
                bridge = (ROOT / 'peaso/checks/gcp_positive_conservation_shared_source_successor_20261020.py').read_text()
                self.assertEqual(bridge.count("install_admission('" + name + "')"), 1)
            else:
                self.assertEqual(initializer.count('_rawv2_source.install_admission("' + name + '")'), 1)
        with self.assertRaises(RuntimeError):
            module.install_admission('unreviewed')


if __name__ == '__main__':
    unittest.main()
