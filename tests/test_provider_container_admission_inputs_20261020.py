"""Keep immutable admission data available in both container source layouts."""
from pathlib import Path
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = {
    'tests/fixtures/azure_nsp_query_cmk_metadata_proposal_20261020.json.gz':
        'a478816f3f9d0a6a732d1ff80b61cd80779e01e36172bda3a36f4fac16417fac',
    'tests/fixtures/azure_nsp_query_cmk_runtime_native_20261020.json.gz':
        '2d7c24828dbc5d22de6a68c96668e87db1c9fdaec01419eaf5b25219b5ef50a5',
    'tests/fixtures/azure_nsp_query_cmk_production_native_20261020.json.gz':
        'be06f6b6fc2ebe96a8c9da2138eaaea941e9a2e266432e45a9e253bc24f2558a',
    'tests/fixtures/azure_sql_tde_parent_identity_predecessor_20261020.json.gz':
        'ea4125608adcffd7ef148a40620dd1130afab7fb4ff27e5d08a6215834ef6af7',
}
RECIPES = ('Dockerfile.peaso', 'infra/aws/Dockerfile.worker')
IMPORT = '''
import sys,json
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from peaso.engine import get_catalog
from peaso.privesc import load_catalog
import peaso.engine
assert Path(peaso.engine.__file__).resolve().is_relative_to(Path(sys.argv[1]))
catalog = get_catalog()
privileges = load_catalog()
assert not privileges['errors'], privileges['errors'][:3]
assert len(catalog['checks']) > 0 and len(privileges['entries']) >= 600
print(json.dumps({'checks': len(catalog['checks']), 'techniques': len(privileges['entries'])}))
'''

# The API package serves privilege metadata from the reviewed display pack and
# ships no engine catalogs (see scripts/peaso_deploy.API_ENGINE_CATALOG_PREFIXES),
# so it is checked through the check registry and that display pack instead.
API_IMPORT = '''
import sys,json
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import peaso.engine
from peaso.server.privesc_display_catalog import _load
assert Path(peaso.engine.__file__).resolve().is_relative_to(Path(sys.argv[1]))
assert not (Path(sys.argv[1]) / 'peaso/privesc/catalog').exists()
checks = [check.public() for check in peaso.engine._registry()]
display = _load()
assert len(checks) > 0 and len(display['details']) >= 600
print(json.dumps({'checks': len(checks), 'techniques': len(display['details'])}))
'''


def _copies(recipe):
    for line in recipe.read_text().replace('\\\n', '').splitlines():
        if not line.startswith('COPY ') or '--from=' in line:
            continue
        words = [word for word in shlex.split(line)[1:] if not word.startswith('--')]
        destination = words[-1]
        # Runtime WORKDIR is /app; frontend copies belong to /build.
        if destination.startswith('/') and not destination.startswith('/app/'):
            continue
        yield words[:-1], destination


def _copy_file(source, destination):
    source, destination = Path(source), Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def test_context_includes_only_four_immutable_admission_inputs(tmp_path):
    for name, digest in FIXTURES.items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest
    (tmp_path / '.gitignore').write_text((ROOT / '.dockerignore').read_text())
    subprocess.run(['git', 'init', '-q', str(tmp_path)], check=True, capture_output=True)
    candidates = {path.relative_to(ROOT).as_posix() for path in (ROOT / 'tests').rglob('*')
                  if path.is_file() and '__pycache__' not in path.parts}
    # The scoped directory/exact-file rules use compatible Git/Docker semantics.
    # This checks context selection locally; it does not invoke a Docker engine.
    ignored = subprocess.run(
        ['git', '-C', str(tmp_path), 'check-ignore', '--no-index', '--stdin', '-z'],
        input='\0'.join(sorted(candidates)) + '\0', text=True, capture_output=True)
    assert ignored.returncode in (0, 1), ignored.stderr
    excluded = set(ignored.stdout.rstrip('\0').split('\0'))
    assert candidates - excluded == set(FIXTURES)


@pytest.mark.parametrize('recipe_name', RECIPES)
def test_container_source_registry_imports_without_test_suite(tmp_path, recipe_name):
    staged = tmp_path.resolve()
    recipe = ROOT / recipe_name
    fixture_copies = []
    for sources, destination in _copies(recipe):
        assert not any(name in {'.', './', 'tests', 'tests/', 'tests/fixtures', 'tests/fixtures/'}
                       for name in sources), 'Container must copy only exact admission input paths'
        if not all(source.startswith(('pyproject.toml', 'peaso', 'bluepeass', 'scripts',
                                      'risk_rules', 'infra/aws/sdk-constraints.txt', 'tests'))
                   for source in sources):
            continue
        for name in sources:
            if name.startswith('tests'):
                assert name in FIXTURES, 'Container must not copy the test suite: ' + name
                fixture_copies.append(name)
            source = ROOT / name
            target = staged / destination.removeprefix('/app/').removeprefix('./')
            if not source.is_dir() and (len(sources) > 1 or destination.endswith('/')):
                target = target / source.name
            if source.is_dir():
                shutil.copytree(source, target, copy_function=_copy_file, dirs_exist_ok=True,
                                ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '.cache', '.work'))
            else:
                _copy_file(source, target)
    assert sorted(fixture_copies) == sorted(FIXTURES)
    assert {path.relative_to(staged).as_posix() for path in (staged / 'tests').rglob('*')
            if path.is_file()} == set(FIXTURES)
    for name, digest in FIXTURES.items():
        assert hashlib.sha256((staged / name).read_bytes()).hexdigest() == digest
    text = recipe.read_text()
    assert text.index(next(iter(FIXTURES))) < text.index('RUN pip install')
    environment = {key: value for key, value in os.environ.items()
                   if key not in ('PYTHONPATH', 'HACKTRICKS_CLOUD_ROOT') and not key.startswith(
                       ('PEASO_', 'AWS_', 'AZURE_', 'GOOGLE_', 'CLOUDSDK_', 'GCLOUD_', 'K8S_'))}
    environment['PYTHONDONTWRITEBYTECODE'] = '1'

    def invoke():
        return subprocess.run([sys.executable, '-I', '-c', IMPORT, str(staged)],
                              cwd=staged, env=environment, text=True, capture_output=True, timeout=90)

    result = invoke()
    assert result.returncode == 0, result.stderr[-4000:]
    counts = json.loads(result.stdout)
    assert counts['checks'] > 0 and counts['techniques'] >= 600
    # Missing immutable inputs must fail rather than silently drop native checks.
    (staged / next(iter(FIXTURES))).unlink()
    negative = invoke()
    assert negative.returncode != 0
    assert 'admission' in negative.stderr or 'successor' in negative.stderr


def test_api_package_retains_frozen_admission_data_and_imports_without_source(tmp_path, monkeypatch):
    import zipfile
    from scripts import peaso_deploy as deploy

    monkeypatch.setattr(deploy, 'BUILD', tmp_path.resolve() / 'build')
    source = deploy.BUILD / 'source-snapshot'
    for name in ('peaso', 'risk_rules'):
        shutil.copytree(ROOT / name, source / name,
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '.cache', '.work'))
    for name in ('bluepeass/__init__.py', 'bluepeass/k8s.py', 'bluepeass/k8s_risks.py',
                 'scripts/cloud_permission_risks.py', 'infra/aws/sdk-constraints.txt', *FIXTURES):
        _copy_file(ROOT / name, source / name)
    files = {path.relative_to(source).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
             for path in source.rglob('*') if path.is_file()}
    release = {'files': files, 'source_version': hashlib.sha256(
        json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
    for path in (source / 'release.json', deploy.BUILD / 'release.json'):
        path.write_text(json.dumps(release))
    deploy.normalize_frozen_permissions(source, ['release.json', *files])
    assert deploy.RUNTIME_ADMISSION_INPUTS == FIXTURES
    assert set(FIXTURES) <= set(deploy.REPRODUCTION_INPUT_PATTERNS)

    installs = []

    def offline_install(arguments, **kwargs):
        assert arguments[1:4] == ['-m', 'pip', 'install']
        target = Path(arguments[arguments.index('--target') + 1])
        assert target == deploy.BUILD / 'api-package'
        installs.append(arguments)
        # The packaged SDK model gate needs the pinned botocore tree that pip
        # would install; copy the locally installed, version-checked one offline.
        import botocore
        from importlib.metadata import distribution
        botocore_root = Path(botocore.__file__).parent
        dist = distribution('botocore')
        assert dist.version == '1.43.38'
        shutil.copytree(botocore_root, target / 'botocore',
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        shutil.copytree(Path(dist._path), target / Path(dist._path).name)

    # Only the dependency installation boundary is stubbed; staging, guards,
    # frozen hashes, public permissions and ZIP production use the real code.
    monkeypatch.setattr(deploy, 'run', offline_install)
    package = deploy.package_api()
    assert len(installs) == 1
    target = deploy.BUILD / 'api-package'
    original_zip = package.read_bytes()
    with zipfile.ZipFile(package) as archive:
        assert {name for name in archive.namelist() if name.startswith('tests/')} == set(FIXTURES)
        for name, digest in FIXTURES.items():
            assert hashlib.sha256(archive.read(name)).hexdigest() == digest
            assert hashlib.sha256((target / name).read_bytes()).hexdigest() == digest
        print(json.dumps({'api_members': len(archive.infolist()),
                          'api_uncompressed_bytes': sum(info.file_size for info in archive.infolist()),
                          'api_zip_bytes': package.stat().st_size,
                          'dependency_installation': 'stubbed'}))

    name = next(iter(FIXTURES))
    original_fixture = (target / name).read_bytes()
    (target / name).write_bytes(b'tampered')
    with pytest.raises(RuntimeError, match='differs'):
        deploy.verify_api_source()
    (target / name).write_bytes(original_fixture)
    (target / name).unlink()
    with pytest.raises(RuntimeError, match='differs'):
        deploy.verify_api_source()
    _copy_file(ROOT / name, target / name)

    for payload in (b'tampered', None):
        with zipfile.ZipFile(package) as archive:
            members = [(info, archive.read(info)) for info in archive.infolist()]
        with zipfile.ZipFile(package, 'w') as archive:
            for info, content in members:
                if info.filename == name:
                    if payload is None:
                        continue
                    content = payload
                archive.writestr(info, content)
        with pytest.raises(RuntimeError, match='ZIP (source differs|omits supplied source)'):
            deploy.verify_api_source()
        package.write_bytes(original_zip)

    frozen = source / name
    original_frozen = frozen.read_bytes()
    frozen.write_bytes(b'tampered')
    with pytest.raises(RuntimeError, match='Frozen source changed'):
        deploy.source_root()
    frozen.unlink()
    with pytest.raises(RuntimeError, match='Frozen source changed'):
        deploy.source_root()
    frozen.write_bytes(original_frozen)
    frozen.chmod(0o644)
    deploy.verify_api_source()

    # Delete the frozen source before importing the staged API package. Its
    # registry must work with no source checkout or rest of the test suite.
    shutil.rmtree(source)
    environment = {key: value for key, value in os.environ.items()
                   if key not in ('PYTHONPATH', 'HACKTRICKS_CLOUD_ROOT') and not key.startswith(
                       ('PEASO_', 'AWS_', 'AZURE_', 'GOOGLE_', 'CLOUDSDK_', 'GCLOUD_', 'K8S_'))}
    environment['PYTHONDONTWRITEBYTECODE'] = '1'
    result = subprocess.run([sys.executable, '-I', '-c', API_IMPORT, str(target)],
                            cwd=target, env=environment, text=True, capture_output=True, timeout=90)
    assert result.returncode == 0, result.stderr[-4000:]
