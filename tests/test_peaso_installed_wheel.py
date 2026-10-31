"""Build offline and use the distribution without the source checkout on sys.path."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

import pytest


# No runtime code reads test data, so the wheel must not ship anything under tests/.
ADMISSION_RUNTIME_DATA = ()


@pytest.fixture(scope='module')
def installed_wheel(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    work = tmp_path_factory.mktemp('installed-peaso')
    source = work / 'source'
    source.mkdir()
    for folder in ('peaso', 'risk_rules', 'bluepeass', 'scripts'):
        shutil.copytree(root / folder, source / folder,
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '.cache', '.work'))
    for name in ('pyproject.toml', 'LICENSE'):
        shutil.copy2(root / name, source / name)
    for name in ADMISSION_RUNTIME_DATA:
        destination = source / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / name, destination)
    environment = {key: value for key, value in os.environ.items()
                   if key not in ('PYTHONPATH', 'HACKTRICKS_CLOUD_ROOT') and not key.startswith(
                       ('PEASO_', 'AWS_', 'AZURE_', 'GOOGLE_', 'CLOUDSDK_', 'GCLOUD_', 'K8S_'))}
    build = subprocess.run([sys.executable, '-I', '-c',
        "from setuptools.build_meta import build_wheel; build_wheel('dist')"],
        cwd=source, env=environment, capture_output=True, text=True, timeout=120)
    assert build.returncode == 0, (build.stdout + build.stderr)[-4000:]
    wheel, = (source / 'dist').glob('*.whl')
    target = work / 'installed'
    target.mkdir()
    with zipfile.ZipFile(wheel) as archive:
        assert {name for name in archive.namelist() if name.startswith('tests/')} == set(ADMISSION_RUNTIME_DATA)
        for name in ADMISSION_RUNTIME_DATA:
            assert archive.read(name) == (root / name).read_bytes(), name
        for folder in ('peaso', 'risk_rules'):
            paths = (source / folder).rglob('*') if folder == 'peaso' else (source / folder).glob('*')
            for path in paths:
                if path.is_file() and path.suffix in ('.json', '.yaml', '.txt'):
                    name = path.relative_to(source).as_posix()
                    assert name in archive.namelist(), 'Runtime data omitted from wheel: ' + name
                    assert archive.read(name) == path.read_bytes(), name
    install = subprocess.run([sys.executable, '-I', '-m', 'pip', 'install', '--no-index', '--no-deps',
                              '--no-compile', '--target', str(target), str(wheel)],
                             cwd=work, env=environment, capture_output=True, text=True, timeout=60)
    assert install.returncode == 0, (install.stdout + install.stderr)[-4000:]
    # The source tree is removed before any imports. Neither an editable
    # installation nor the current directory can supply missing resources.
    shutil.rmtree(source)
    return target, environment


def test_installed_catalog_and_privesc_work_without_checkout(installed_wheel):
    target, environment = installed_wheel
    code = '''
import sys,json
sys.path.insert(0, sys.argv[1])
from peaso.engine import get_catalog
from peaso.privesc import load_catalog
from peaso.privesc.versioned_catalog import current_binding
from peaso.collectors import bulk_evidence
catalog = get_catalog()
privileges = load_catalog()
assert not privileges['errors'], privileges['errors'][:3]
assert current_binding()['schema'] == 'privesc-catalog-binding-v1'
print(json.dumps({'checks': len(catalog['checks']), 'techniques': len(privileges['entries'])}))
'''
    result = subprocess.run([sys.executable, '-I', '-c', code, str(target)],
                            cwd=target, env=environment, capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stderr[-4000:]
    counts = json.loads(result.stdout)
    from peaso.engine import get_catalog
    from peaso.privesc import load_catalog
    assert counts['checks'] == len(get_catalog()['checks']) > 0
    assert counts['techniques'] == len(load_catalog()['entries']) >= 600


def test_installed_cli_help_works_without_checkout(installed_wheel):
    target, environment = installed_wheel
    code = """
import sys
sys.path.insert(0, sys.argv[1])
from importlib.metadata import distributions
package = next(d for d in distributions(path=[sys.argv[1]])
               if d.metadata['Name'] == 'hacktricks-cspm')
entries = {e.name: e for e in package.entry_points if e.group == 'console_scripts'}
assert {'hacktricks-cspm', 'peaso'} <= set(entries)
for name in ('hacktricks-cspm', 'peaso'):
    try:
        code = entries[name].load()(['--help'])
    except SystemExit as exc:
        assert exc.code == 0
    else:
        assert code in (None, 0)
"""
    result = subprocess.run([sys.executable, '-I', '-c', code, str(target)],
                            cwd=target, env=environment, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr[-2000:]
    assert 'scan' in result.stdout and 'catalog' in result.stdout
