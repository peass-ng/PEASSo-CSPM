"""Native Dataproc selected dependency parsing and bounded transport regressions."""
import json
from pathlib import Path
import threading
import time
from types import SimpleNamespace
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'peaso/collectors/gcp_dataproc_referenced_source_secret_indicators.py'


from unittest.mock import patch
from peaso.collectors import gcp_dataproc_referenced_source_secret_indicators as native

Incomplete = native.Incomplete


def functions():
    return native.parse, native.reference


class DependencyTests(unittest.TestCase):
    def setUp(self):
        self.parse, self.reference = functions()
        self.target = dict(profile='job', resource='projects/myproject1/regions/us-central1/jobs/job-1',
                           field='pysparkJob.pythonFileUris[0]', bucket='owned-bucket',
                           object='deps/helpers.py', generation='17')
        self.job = dict(reference={'projectId': 'myproject1', 'jobId': 'job-1'},
                        jobUuid='12345678-1234-1234-1234-123456789abc',
                        pysparkJob={'mainPythonFileUri': 'gs://owned-bucket/main.py',
                                    'pythonFileUris': ['gs://owned-bucket/deps/helpers.py']})

    def test_native_dependency_bound(self):
        self.assertEqual(self.parse(self.target), 'projects/myproject1')
        self.assertEqual(self.reference(self.job, self.target), self.reference(self.job, self.target))
        changed = json.loads(json.dumps(self.job))
        changed['pysparkJob']['pythonFileUris'][0] = 'gs://owned-bucket/deps/other.py'
        with self.assertRaises(Incomplete):
            self.reference(changed, self.target)

    def test_foreign_project_and_wrong_job_union(self):
        with self.assertRaises(Incomplete):
            self.parse({**self.target, 'field': 'sparkJob.pythonFileUris[0]'})
        foreign = {**self.target, 'resource': 'projects/otherproj1/regions/us-central1/jobs/job-1'}
        self.parse(foreign)
        with self.assertRaises(Incomplete):
            self.reference(self.job, foreign)
        wrong = {**self.job, 'sparkJob': self.job['pysparkJob']}
        with self.assertRaises(Incomplete):
            self.reference(wrong, self.target)

    def test_missing_malformed_and_binary(self):
        for field, obj in [('pysparkJob.pythonFileUris[100]', 'deps/helpers.py'),
                           ('pysparkJob.pythonFileUris[-1]', 'deps/helpers.py'),
                           ('pysparkJob.pythonFileUris[0]', 'deps/helpers.bin')]:
            with self.subTest(field=field, obj=obj), self.assertRaises(Incomplete):
                self.parse({**self.target, 'field': field, 'object': obj})
        for value in ([], [None], ['gs://foreign-bucket/deps/helpers.py']):
            with self.subTest(value=value), self.assertRaises(Incomplete):
                self.reference({**self.job, 'pysparkJob': {'pythonFileUris': value}}, self.target)

    def test_existing_main_field(self):
        target = {**self.target, 'field': 'pysparkJob.mainPythonFileUri', 'object': 'main.py'}
        self.parse(target)
        self.reference(self.job, target)

    def test_cancelled_before_credentials_and_denied_is_incomplete(self):
        class Response:
            status_code = 403
            history = []
            headers = {}
            def __init__(self, url):
                self.url = url
                self.closed = False
            def close(self):
                self.closed = True
        class Session:
            def __init__(self):
                self.response = None
                self.closed = False
            def request(self, method, url, **kwargs):
                self.response = Response(url)
                return self.response
            def close(self):
                self.closed = True
        session = Session()
        state = dict(deadline=time.monotonic() + 20, capture='a' * 32, ledger=[], calls=0, bytes=0)
        credentials = SimpleNamespace(headers=lambda: {'Authorization': 'Bearer offline-token'})
        transport = SimpleNamespace(check_cancelled=lambda: None, deadline=None, deadline_seconds=None,
                                    started=time.monotonic(), timeout=10, lock=threading.RLock(),
                                    max_calls=None, calls=0, credentials=credentials, options={})
        url = 'https://dataproc.googleapis.com/v1/' + self.target['resource']
        with patch.object(native.git, '_session', lambda: session):
            with self.assertRaisesRegex(Incomplete, 'denied'):
                native._read(transport, state, 'selected', 'projects/myproject1', 'reference_before', url, {})
        self.assertTrue(session.closed and session.response.closed)
        self.assertEqual(state['ledger'][0]['status'], 'unavailable')
        before = transport.calls
        transport.check_cancelled = lambda: (_ for _ in ()).throw(Incomplete('cancelled'))
        with self.assertRaisesRegex(Incomplete, 'cancelled'):
            native._read(transport, state, 'selected', 'projects/myproject1', 'reference_before', url, {})
        self.assertEqual(transport.calls, before)


if __name__ == '__main__':
    unittest.main()
