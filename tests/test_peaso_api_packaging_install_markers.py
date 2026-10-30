"""Offline package regression: optional pip markers must not exhaust API caps."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch
import zipfile

SPEC = importlib.util.spec_from_file_location(
    'api_packaging_marker_deploy', Path(__file__).parents[1] / 'scripts/peaso_deploy.py')
deploy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(deploy)


class ApiInstallationMarkerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'checkout'
        self.build = Path(self.tmp.name) / 'build'
        self.root.mkdir()
        self.build.mkdir()
        self.source = {
            'peaso/__init__.py': b'# fixture\n',
            'peaso/server/app.py': b'APP = "unchanged"\n',
            'risk_rules/fixture.json': b'{}\n',
            'bluepeass/__init__.py': b'# fixture\n',
            'bluepeass/k8s.py': b'# fixture\n',
            'bluepeass/k8s_risks.py': b'# fixture\n',
            'scripts/cloud_permission_risks.py': b'# fixture\n',
        }
        for name, body in self.source.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        files = {n: hashlib.sha256(v).hexdigest() for n, v in self.source.items()}
        self.release = {'source_version': hashlib.sha256(
            json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                        'files': files}
        (self.build / 'release.json').write_text(json.dumps(self.release))
        for name, value in [('ROOT', self.root), ('BUILD', self.build),
                            ('source_root', lambda: self.root)]:
            patcher = patch.object(deploy, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        # The SDK model gate reviews the real source tree; it has its own tests.
        from scripts import peaso_api_service_model_gate as gate
        patcher = patch.object(gate, 'prune_api_service_models',
                               lambda root: {'allowed_services': [], 'removed_models': 0})
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.object(socket, 'create_connection', side_effect=AssertionError('No network'))
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.object(socket.socket, 'connect', side_effect=AssertionError('No network'))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.target = self.build / 'api-package'
        self.dependencies = {}
        self.markers = []
        self.pip_calls = 0

    def write(self, name, body):
        path = self.target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        return path

    def fake_pip(self, args, **kwargs):
        self.assertEqual(args[1:4], ['-m', 'pip', 'install'])
        self.assertEqual(Path(args[args.index('--target') + 1]), self.target)
        self.pip_calls += 1
        for name, body in self.dependencies.items():
            self.write(name, body)

    def package(self):
        with patch.object(deploy, 'run', self.fake_pip), contextlib.redirect_stdout(io.StringIO()):
            return deploy.package_api()

    def realistic_dependencies(self):
        for distribution in ('boto3-1.43.38', 'cryptography-50.0.2', 'fastapi-0.143.2',
                             'mangum-0.22.0', 'pyjwt-2.15.1', 'pyyaml-6.0.3',
                             'requests-2.34.2', 'uvicorn-0.54.0'):
            parent = distribution + '.dist-info/'
            self.markers.append(parent + 'REQUESTED')
            self.dependencies.update({parent + 'REQUESTED': b'', parent + 'METADATA': b'Version: fixture\n',
                                      parent + 'RECORD': b'original installation record\n',
                                      parent + 'INSTALLER': b'pip\n'})
        self.dependencies['dependency/__init__.py'] = b'VALUE = "required"\n'

    def test_package_4601_member_regression_preserves_every_nonmarker_byte(self):
        self.realistic_dependencies()
        # Reproduce the measured V30 pre-fix inventory, without pip/cloud/builds.
        fillers = 4601 - len(self.source) - 1 - len(self.dependencies)
        self.dependencies.update({f'dependency/data/{n:04d}.txt': b'kept\n' for n in range(fillers)})
        archive = self.package()
        with zipfile.ZipFile(archive) as z:
            expected = {**self.source, **{n: b for n, b in self.dependencies.items() if n not in self.markers},
                        'peaso_release.json': (self.build / 'release.json').read_bytes()}
            self.assertEqual(len(z.namelist()), 4593)
            self.assertLessEqual(len(z.namelist()), deploy.artifact_update.MAX_API_MEMBERS)
            self.assertEqual(set(z.namelist()), set(expected))
            for name, body in expected.items():
                self.assertEqual(z.read(name), body, name)
                self.assertEqual((self.target / name).read_bytes(), body, name)
            self.assertTrue(all(not (self.target / n).exists() for n in self.markers))
        self.assertEqual(self.pip_calls, 1)

    def test_nonempty_or_noninstaller_requested_files_are_preserved(self):
        self.target.mkdir()
        removed = 'empty-1.dist-info/REQUESTED'
        kept = {'comment-1.dist-info/REQUESTED': b'# explicitly requested\n',
                'code/REQUESTED': b'', 'nested/pkg-1.dist-info/REQUESTED': b'',
                'pkg-1.dist-info/requested': b'', '.dist-info/REQUESTED': b'',
                'pkg-1.dist-info/METADATA': b'', 'pkg-1.dist-info/RECORD': b'',
                'pkg-1.dist-info/INSTALLER': b''}
        self.write(removed, b'')
        for name, body in kept.items():
            self.write(name, body)
        self.assertEqual(deploy.omit_empty_api_installation_markers(self.target), [removed])
        for name, body in kept.items():
            self.assertEqual((self.target / name).read_bytes(), body)
        self.assertEqual(deploy.omit_empty_api_installation_markers(self.target), [])

    def test_late_symlink_is_rejected_before_any_marker_removal(self):
        self.target.mkdir()
        early = self.write('a-1.dist-info/REQUESTED', b'')
        outside = self.root / 'outside'
        outside.write_bytes(b'untouched')
        (self.target / 'z-link').symlink_to(outside)
        with self.assertRaises(RuntimeError):
            deploy.omit_empty_api_installation_markers(self.target)
        self.assertTrue(early.exists())
        self.assertEqual(outside.read_bytes(), b'untouched')

    def test_late_hardlink_is_rejected_before_any_marker_removal(self):
        self.target.mkdir()
        early = self.write('a-1.dist-info/REQUESTED', b'')
        outside = self.root / 'outside'
        outside.write_bytes(b'untouched')
        os.link(outside, self.target / 'z-link')
        with self.assertRaises(RuntimeError):
            deploy.omit_empty_api_installation_markers(self.target)
        self.assertTrue(early.exists())
        self.assertEqual(outside.read_bytes(), b'untouched')

    def test_nonempty_marker_survives_complete_packaging(self):
        self.dependencies = {'dependency/__init__.py': b'# code\n',
                             'dependency-1.dist-info/REQUESTED': b'# owner marker\n'}
        archive = self.package()
        with zipfile.ZipFile(archive) as z:
            for name, body in self.dependencies.items():
                self.assertEqual(z.read(name), body)

    def test_remaining_member_overflow_fails_before_zip_is_written(self):
        self.dependencies = {f'dependency/{n}.py': b'# required\n' for n in range(4)}
        with patch.object(deploy, 'CURRENT_API_MEMBER_LIMIT', len(self.source) + 1):
            with self.assertRaisesRegex(RuntimeError, 'member limit'):
                self.package()
        self.assertFalse((self.build / 'api.zip').exists())

    def test_identical_inputs_have_identical_zip_bytes(self):
        self.realistic_dependencies()
        archive = self.package()
        before = archive.read_bytes()
        self.package()
        self.assertEqual(archive.read_bytes(), before)
        self.assertEqual(self.pip_calls, 2)


if __name__ == '__main__':
    unittest.main()
