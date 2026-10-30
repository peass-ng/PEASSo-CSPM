"""Offline checks for source-accounting completeness and integrity boundaries."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('audit_gcp_source_parity', ROOT / 'scripts/audit_gcp_source_parity.py')
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


class SourceParityTests(unittest.TestCase):
    def test_shared_sql_is_bound_beyond_legacy_control_wrapper(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            directory = base / 'steampipe-mod-gcp-perimeter'
            directory.mkdir()
            path = directory / 'controls.pp'
            wrapper = 'control "resource_trust" {\n title = "Resource trust"\n sql = local.trust_sql\n}\n'
            local = 'locals {\n trust_sql = <<EOQ\n select case when allowed then \'ok\' else \'alarm\' end status;\n EOQ\n}\n'
            def enumerate_one(text):
                path.write_text(text)
                raw = path.read_bytes()
                source = {'repository': audit.REPOS[2], 'revision': 'a' * 40, 'license': 'Apache-2.0',
                          'files': [{'path': 'controls.pp', 'type': 'blob', 'sha': audit.blob_sha(raw), 'sha256': audit.digest(raw)}]}
                return audit.enumerate_sources(base, [source])[0]
            first = enumerate_one(wrapper + local)
            second = enumerate_one(wrapper + local.replace('when allowed', 'when forbidden'))
            self.assertEqual(first['upstream_evaluator']['sha256'], second['upstream_evaluator']['sha256'])
            self.assertNotEqual(first['upstream_evaluator']['resolved_sha256'], second['upstream_evaluator']['resolved_sha256'])
            self.assertIn('when forbidden', second['_evaluator_text'])

    def test_integrity_rejects_modified_blob_and_unlisted_source(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            sources = []
            for repo in audit.REPOS:
                directory = base / repo.split('/')[-1]
                directory.mkdir()
                files = []
                if repo != audit.REPOS[0]:
                    raw = b'control "x" {\n title = "Example"\n}\n'
                    (directory / 'x.pp').write_bytes(raw)
                    files = [{'path': 'x.pp', 'sha': audit.blob_sha(raw), 'sha256': audit.digest(raw)}]
                sources.append({'repository': repo, 'revision': 'a' * 40, 'files': files,
                                'corpus_sha256': audit.digest(json.dumps(files, sort_keys=True, separators=(',', ':')).encode())})
            (base / 'sources.json').write_text(json.dumps(sources))
            audit.verify(base)
            file = base / 'steampipe-mod-gcp-perimeter/x.pp'
            original = file.read_bytes()
            file.write_bytes(original + b'changed')
            with self.assertRaisesRegex(ValueError, 'integrity mismatch'):
                audit.verify(base)
            file.write_bytes(original)
            (file.parent / 'unlisted.pp').write_text('control "hidden" {}')
            with self.assertRaisesRegex(ValueError, 'differs from pinned inventory'):
                audit.verify(base)

    def test_native_catalog_presence_cannot_close_missing_manifest_mapping(self):
        upstream = next(iter(audit.WORKBENCH_IDS))
        native = audit.WORKBENCH_IDS[upstream]
        pending = audit.admission_state({'check_id': upstream}, [], {native: {}})
        self.assertEqual(pending['disposition'], 'awaiting-manifest-mapping')
        self.assertFalse(pending['manifest_mapping_present'])
        self.assertEqual(pending['requirements'], [])
        partial = audit.admission_state({'check_id': upstream}, [native], {native: {'requirement_controls': [{'framework_id': 'pci_4.0_gcp', 'requirement_id': '1.2.8.37', 'decision': 'PARTIAL'}]}})
        self.assertEqual(partial['requirement_mapping_assurance'], 'reviewed_partial')
        self.assertEqual(len(partial['requirements']), 1)
        self.assertEqual(audit.admission_state({'check_id': upstream}, [native], {})['disposition'],
                         'awaiting-catalog-regeneration')
        self.assertEqual(audit.admission_state({'check_id': upstream}, [native], {native: {}})['disposition'],
                         'mapped-active')

    def test_manual_info_does_not_make_secret_content_unautomatable(self):
        row = {'check_id': 'gcp-compliance.control.cis_v400_1_17',
               'title': 'Ensure Secrets are Not Stored in Cloud Functions Environment Variables by Using Secret Manager',
               'source': 'https://github.com/turbot/example', '_evaluator_text': "'info' status, 'Manual verification required.' reason",
               'upstream_evaluator': {'resolved_sha256': '0' * 64}}
        review = audit.review_omission(row)
        self.assertEqual(review['classification'], 'useful_automatable_gap')
        self.assertIn('buildConfig.environmentVariables', review['proposal']['fields'])
        self.assertIn('redacted', review['assessment'])
        self.assertIn('names only', review['assessment'])


if __name__ == '__main__':
    unittest.main()
