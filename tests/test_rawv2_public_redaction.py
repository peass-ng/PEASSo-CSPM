"""Pure parser proofs; synthetic credentials, no cloud or verification calls."""
import base64
import json
import unittest
from unittest.mock import patch
from peaso import secret_scanning as scanning


class RawV2RedactionTests(unittest.TestCase):
    def setUp(self):
        scanning._RESULTS.clear()
        self.primary = 'AKIA' + '7MQ2ZR9WL4CV8NK1'
        self.component = '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT1vW8'

    def test_complete_pair_redacts_source_path_and_metadata_callback_without_extra_fingerprint(self):
        full = self.primary + ':' + self.component
        row = json.dumps({'Raw': self.primary, 'RawV2': full, 'Verified': False, 'DetectorName': 'AWS'}).encode()
        with patch.object(scanning, '_trufflehog', return_value='synthetic'), patch.object(scanning, '_run', return_value=row) as run, patch.object(scanning, '_scan_kingfisher', return_value=[]):
            values = set()
            outcome = scanning.scan_content((self.primary + '\n' + self.component).encode(), '/app/' + self.component + '.env', _redact_values=values.update)
        self.assertTrue({'stdin', '--json', '--no-verification', '--no-update', '--no-verification-cache',
            '--force-skip-archives', '--fail-on-scan-errors'} <= set(run.call_args.args[0]))
        self.assertTrue(outcome['complete'])
        self.assertEqual([r['fingerprint'] for r in outcome['leaks']], [scanning._fingerprint(self.primary)])
        # Found values stay visible: the exact path is kept and nothing is redacted.
        self.assertEqual(outcome['leaks'][0]['locations'], [{'path': '/app/' + self.component + '.env', 'line': 1}])
        self.assertEqual(values, set())
        metadata = scanning.redact_matches({'label': self.component}, {self.component})
        self.assertEqual(metadata, {'label': self.component})

    def test_redacted_cache_never_retains_complete_pair_or_secret_component(self):
        full = self.primary + ':' + self.component
        row = json.dumps({'Raw': self.primary, 'RawV2': full, 'Verified': False, 'DetectorName': 'AWS'}).encode()
        with patch.object(scanning, '_trufflehog', return_value='synthetic'), patch.object(scanning, '_run', return_value=row), patch.object(scanning, '_scan_kingfisher', return_value=[]):
            first = scanning.scan_content((self.primary + '\n' + self.component).encode(), '/app/' + self.component)
            second = scanning.scan_content((self.primary + '\n' + self.component).encode(), '/app/' + self.component)
        self.assertEqual(first, second)
        for value in (self.primary, self.component, full):
            self.assertNotIn(value, repr(scanning._RESULTS))

    def test_component_requires_recognized_format_and_valid_offline_result(self):
        full = self.primary + ':' + self.component
        self.assertEqual(scanning._complete_match_values(self.primary, full, rule='AWS'), [full, self.component])
        self.assertEqual(scanning._complete_match_values(self.primary, self.primary + ':invalid', rule='AWS'), [self.primary + ':invalid'])
        row = json.dumps({'Raw': self.primary, 'RawV2': full, 'Verified': True, 'DetectorName': 'AWS'}).encode()
        with patch.object(scanning, '_trufflehog', return_value='synthetic'), patch.object(scanning, '_run', return_value=row), patch.object(scanning, '_scan_kingfisher', return_value=[]):
            values = set()
            outcome = scanning.scan_content(self.primary.encode(), 'file', _redact_values=values.update)
        self.assertFalse(outcome['complete'])
        self.assertFalse(outcome['leaks'])
        self.assertFalse(values)

    def test_decoded_only_aws_pair_redacts_filename_and_metadata_with_unknown_line(self):
        full = self.primary + ':' + self.component
        payload = base64.b64encode(('AWS_ACCESS_KEY_ID=' + self.primary + '\nAWS_SECRET_ACCESS_KEY=' + self.component + '\n').encode())
        self.assertNotIn(self.primary.encode(), payload)
        self.assertNotIn(self.component.encode(), payload)
        # This is the decoded Raw/RawV2 shape confirmed with both pinned offline
        # scanners against this exact encoded fixture; no live verification.
        row = json.dumps({'Raw': self.primary, 'RawV2': full, 'Verified': False, 'DetectorName': 'AWS'}).encode()
        with patch.object(scanning, '_trufflehog', return_value='synthetic'), patch.object(scanning, '_run', return_value=row), patch.object(scanning, '_scan_kingfisher', return_value=[]):
            values = set()
            outcome = scanning.scan_content(payload, '/app/' + self.component + '.env', _redact_values=values.update)
        self.assertTrue(outcome['complete'])
        self.assertEqual([r['fingerprint'] for r in outcome['leaks']], [scanning._fingerprint(self.primary)])
        # Found values stay visible: the exact path is kept and nothing is redacted.
        self.assertEqual(outcome['leaks'][0]['locations'], [{'path': '/app/' + self.component + '.env'}])
        self.assertEqual(values, set())
        metadata = {'label': self.component, 'file': '/app/' + self.component + '.env'}
        self.assertEqual(scanning.redact_matches(metadata, {self.component}), metadata)
        self.assertNotIn(self.component, repr(scanning._RESULTS))


if __name__ == '__main__':
    unittest.main()
