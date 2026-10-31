"""Offline contract tests for the HackTricks Cloud privesc catalog export/sync pipeline."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
from unittest.mock import Mock

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


exporter = _load('privesc_export_under_test', 'scripts/export_privesc_catalog.py')
syncer = exporter.sync_module
fetcher = _load('permission_fetch_privesc', 'scripts/fetch_hacktricks_permissions.py')
SyncError = exporter.SyncError  # export and its sync module share one exception type

ENTRY = """\
# Fixture conventions comment (must survive byte for byte).
- id: gcp-iam-serviceaccounts-getaccesstoken
  provider: gcp
  service: iam
  title: Mint OAuth access tokens for a service account
  source: src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-iam-privesc.md#iamserviceaccountsgetaccesstoken
  summary: The source obtains the privileges of service accounts it can mint tokens for.
  requires:
    all_of:
      - action: iam.serviceAccounts.getAccessToken
        resource: "{target.email}"
  target:
    kind: gcp_service_account
    selector:
      resource_permission_covers_target: iam.serviceAccounts.getAccessToken
    scope: any
  severity: critical
  mitigation: Restrict iam.serviceAccounts.getAccessToken.
"""


def entry(ident, service='iam'):
    return ENTRY.replace('gcp-iam-serviceaccounts-getaccesstoken', ident).replace('service: iam', f'service: {service}')


def make_repo(tmp_path, files):
    """A minimal target root: schema.py + catalog files."""
    target = tmp_path / 'repo'
    (target / 'peaso/privesc').mkdir(parents=True)
    shutil.copy(ROOT / 'peaso/privesc/schema.py', target / 'peaso/privesc/schema.py')
    for rel, text in files.items():
        path = target / 'peaso/privesc/catalog' / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    (target / 'risk_rules').mkdir()
    return target


def catalog(target):
    return target / 'peaso/privesc/catalog'


def upstream(book):
    return book / 'src/privilege-escalation-paths'


def snapshot(root):
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob('*')) if p.is_file()}


def test_current_effective_manifest_matches_catalog_files():
    manifest = json.loads((ROOT / 'risk_rules/hacktricks-privesc-source.json').read_text())
    files = ROOT / 'peaso/privesc/catalog'
    actual = {path.relative_to(files).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
              for path in files.rglob('*.yaml')}
    assert manifest['sha256'] == actual
    assert manifest['effective']['local_ahead_files'] == sorted(
        name for name, digest in actual.items()
        if digest != manifest['canonical_sha256'].get(name))


@pytest.fixture
def synced(tmp_path):
    """Repo + book after an initial export and sync."""
    target = make_repo(tmp_path, {'gcp/iam.yaml': entry('gcp-iam-one'), 'gcp/storage.yaml': entry('gcp-storage-one', 'storage'),
                                  'k8s/_excluded.yaml': '- source: src/x.md#a\n  technique: T\n  reason: R\n'})
    book = tmp_path / 'book'
    exporter.export(book, repo_root=target)
    syncer.sync(book, target)
    return target, book


def test_round_trip_on_current_catalog_is_noop(tmp_path):
    """Export the real catalog, sync it back into a copy: catalog bytes unchanged, --check clean."""
    target = tmp_path / 'repo'
    (target / 'peaso/privesc').mkdir(parents=True)
    (target / 'risk_rules').mkdir()
    shutil.copy(ROOT / 'peaso/privesc/schema.py', target / 'peaso/privesc/schema.py')
    shutil.copytree(ROOT / 'peaso/privesc/catalog', catalog(target))
    before = snapshot(catalog(target))
    book = tmp_path / 'book'
    exporter.export(book, repo_root=target)
    first = snapshot(upstream(book))
    exporter.export(book, repo_root=target, check=True)
    assert syncer.sync(book, target) == 1  # only the provenance manifest is created
    assert snapshot(catalog(target)) == before
    syncer.sync(book, target, check=True)
    manifest = json.loads((target / 'risk_rules/hacktricks-privesc-source.json').read_text())
    yaml_files = {k: v for k, v in before.items() if '/' in k and k.endswith('.yaml')}
    assert manifest['canonical_sha256'] == manifest['sha256'] == {k: hashlib.sha256(v).hexdigest()
                                                                  for k, v in sorted(yaml_files.items())}
    assert manifest['effective']['local_ahead_files'] == manifest['effective']['local_deleted_files'] == []
    assert manifest['revision'] is None  # not a git checkout: never claim a revision
    # Deterministic export: re-exporting into a fresh book yields identical bytes.
    exporter.export(tmp_path / 'book2', repo_root=target)
    assert snapshot(upstream(tmp_path / 'book2')) == first
    assert set(k for k in first if '/' in k) == set(yaml_files)
    assert 'README.md' in first


def test_every_source_points_at_a_hacktricks_page_anchor():
    for path in sorted((ROOT / 'peaso/privesc/catalog').glob('*/*.yaml')):
        for item in yaml.safe_load(path.read_text()) or []:
            if 'id' in item:
                assert re.fullmatch(r'src/\S+\.md#\S+', item['source']), (path.name, item['id'])


def test_check_detects_upstream_drift_without_writing(synced):
    target, book = synced
    (upstream(book) / 'gcp/iam.yaml').write_text(entry('gcp-iam-one') + entry('gcp-iam-two')[entry('gcp-iam-two').index('- id'):])
    before = snapshot(target)
    with pytest.raises(SyncError, match='Stale privesc catalog: .*gcp/iam.yaml'):
        syncer.sync(book, target, check=True)
    assert snapshot(target) == before
    syncer.sync(book, target)
    assert 'gcp-iam-two' in (catalog(target) / 'gcp/iam.yaml').read_text()
    syncer.sync(book, target, check=True)


def test_check_detects_local_drift_from_manifest(synced):
    target, book = synced
    (catalog(target) / 'gcp/iam.yaml').write_text(entry('gcp-iam-one').replace('critical', 'high'))
    with pytest.raises(SyncError, match='hacktricks-privesc-source.json'):
        syncer.sync(book, target, check=True)


@pytest.mark.parametrize('rel, text, message', [
    ('gcp/iam.yaml', '- id: [unclosed\n', 'YAML parse error'),
    ('gcp/iam.yaml', entry('gcp-iam-one').replace('severity: critical', 'severity: catastrophic'), 'severity must be one of'),
    ('gcp/iam.yaml', entry('gcp-iam-one') + '  exploit_steps: nope\n', 'unknown fields'),
    ('gcp/iam.yaml', entry('aws-iam-one'), 'id prefix must match provider'),
    ('gcp/storage.yaml', entry('gcp-iam-one', 'storage'), 'duplicate id'),
    ('oci/iam.yaml', entry('gcp-iam-one'), 'Unexpected directory in privesc tree: oci'),
    ('gcp/Bad Name.yaml', entry('gcp-iam-x'), 'lowercase'),
    ('gcp/nested/iam.yaml', entry('gcp-iam-x'), 'Unexpected directory'),
    ('stray.yaml', entry('gcp-iam-x'), 'Unexpected file'),
])
def test_invalid_upstream_is_rejected_and_nothing_written(synced, rel, text, message):
    target, book = synced
    path = upstream(book) / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    before = snapshot(target)
    with pytest.raises(SyncError, match=message):
        syncer.sync(book, target)
    with pytest.raises(SyncError, match=message):
        syncer.sync(book, target, validate_only=True)
    assert snapshot(target) == before


def test_upstream_symlink_is_rejected(synced, tmp_path):
    target, book = synced
    outside = tmp_path / 'outside.yaml'
    outside.write_text(entry('gcp-iam-x'))
    (upstream(book) / 'gcp/link.yaml').symlink_to(outside)
    with pytest.raises(SyncError, match='symbolic link'):
        syncer.sync(book, target)


def test_upstream_removal_needs_reviewed_ledger(synced, tmp_path):
    target, book = synced
    (upstream(book) / 'gcp/storage.yaml').unlink()
    with pytest.raises(SyncError, match='gcp-storage-one'):
        syncer.sync(book, target)
    assert (catalog(target) / 'gcp/storage.yaml').exists()
    ledger = tmp_path / 'ledger.json'
    ledger.write_text(json.dumps({'version': 1, 'review': {'description': 'Retired upstream after review.'},
                                  'accepted_removals': {'gcp-storage-one': 'Duplicate of gcp-iam-one.'}}))
    syncer.sync(book, target, ledger_path=ledger)
    assert not (catalog(target) / 'gcp/storage.yaml').exists()
    manifest = json.loads((target / 'risk_rules/hacktricks-privesc-source.json').read_text())
    assert manifest['ledger']['review']['description'] == 'Retired upstream after review.'
    syncer.sync(book, target, ledger_path=ledger, check=True)


def test_excluded_item_removal_is_guarded(synced):
    target, book = synced
    (upstream(book) / 'k8s/_excluded.yaml').write_text('[]\n')
    with pytest.raises(SyncError, match=r'excluded:src/x.md#a\|T'):
        syncer.sync(book, target)


def test_partial_upstream_removal_keeps_local_items_until_reviewed(synced, tmp_path):
    target, book = synced
    local = (catalog(target) / 'gcp/iam.yaml').read_bytes()
    prior_manifest = (target / 'risk_rules/hacktricks-privesc-source.json').read_bytes()
    upstream_item = entry('gcp-iam-two').encode()
    (upstream(book) / 'gcp/iam.yaml').write_bytes(upstream_item)
    syncer.sync(book, target)
    assert (catalog(target) / 'gcp/iam.yaml').read_bytes() == local
    manifest = json.loads((target / 'risk_rules/hacktricks-privesc-source.json').read_text())
    assert manifest['canonical_sha256']['gcp/iam.yaml'] == hashlib.sha256(upstream_item).hexdigest()
    assert manifest['sha256']['gcp/iam.yaml'] == hashlib.sha256(local).hexdigest()
    assert 'gcp/iam.yaml' in manifest['effective']['local_ahead_files']
    syncer.sync(book, target, check=True)

    ledger = tmp_path / 'ledger.json'
    ledger.write_text(json.dumps({'version': 1, 'review': {'description': 'Reviewed old route.'},
                                  'accepted_removals': {'gcp-iam-one': 'Old route retired.'}}))
    # The same change against the original base is accepted with a reviewed ledger.
    (target / 'risk_rules/hacktricks-privesc-source.json').write_bytes(prior_manifest)
    syncer.sync(book, target, ledger_path=ledger)
    assert (catalog(target) / 'gcp/iam.yaml').read_bytes() == upstream_item


def test_invalid_ledger_is_rejected(synced, tmp_path):
    target, book = synced
    ledger = tmp_path / 'ledger.json'
    ledger.write_text(json.dumps({'version': 1, 'review': {'description': 'x'}, 'accepted_removals': {'gcp-x': ''}}))
    with pytest.raises(SyncError, match='non-empty reasons'):
        syncer.sync(book, target, ledger_path=ledger)


def test_id_moved_between_upstream_files_is_not_a_loss(synced):
    target, book = synced
    (upstream(book) / 'gcp/storage.yaml').unlink()
    moved = entry('gcp-storage-one', 'storage')
    (upstream(book) / 'gcp/iam.yaml').write_text(entry('gcp-iam-one') + moved[moved.index('- id'):])
    syncer.sync(book, target)
    assert not (catalog(target) / 'gcp/storage.yaml').exists()
    assert 'gcp-storage-one' in (catalog(target) / 'gcp/iam.yaml').read_text()


def test_local_only_and_local_ahead_files_are_kept(synced):
    target, book = synced
    (catalog(target) / 'gcp/run.yaml').write_text(entry('gcp-run-one', 'run'))
    ahead = entry('gcp-iam-one').replace('critical', 'high')
    (catalog(target) / 'gcp/iam.yaml').write_text(ahead)
    syncer.sync(book, target)
    assert (catalog(target) / 'gcp/iam.yaml').read_text() == ahead
    assert (catalog(target) / 'gcp/run.yaml').exists()
    manifest = json.loads((target / 'risk_rules/hacktricks-privesc-source.json').read_text())
    assert manifest['effective']['local_ahead_files'] == ['gcp/iam.yaml', 'gcp/run.yaml']
    syncer.sync(book, target, check=True)
    # Once upstreamed, the files are canonical again.
    exporter.export(book, repo_root=target)
    syncer.sync(book, target)
    manifest = json.loads((target / 'risk_rules/hacktricks-privesc-source.json').read_text())
    assert manifest['effective']['local_ahead_files'] == []


def test_both_sides_changed_is_a_conflict(synced):
    target, book = synced
    (catalog(target) / 'gcp/iam.yaml').write_text(entry('gcp-iam-one').replace('critical', 'high'))
    (upstream(book) / 'gcp/iam.yaml').write_text(entry('gcp-iam-one').replace('critical', 'medium'))
    before = snapshot(target)
    with pytest.raises(SyncError, match='both changed.*gcp/iam.yaml'):
        syncer.sync(book, target)
    assert snapshot(target) == before
    syncer.sync(book, target, prefer_upstream=True)
    assert 'severity: medium' in (catalog(target) / 'gcp/iam.yaml').read_text()


def test_local_only_id_lost_on_prefer_upstream_is_refused(synced):
    target, book = synced
    extra = entry('gcp-iam-local')
    (catalog(target) / 'gcp/iam.yaml').write_text(entry('gcp-iam-one') + extra[extra.index('- id'):])
    (upstream(book) / 'gcp/iam.yaml').write_text(entry('gcp-iam-one').replace('critical', 'medium'))
    with pytest.raises(SyncError, match='gcp-iam-local'):
        syncer.sync(book, target, prefer_upstream=True)


def test_missing_upstream_directory(tmp_path):
    target = make_repo(tmp_path, {'gcp/iam.yaml': entry('gcp-iam-one')})
    (tmp_path / 'book/src').mkdir(parents=True)
    with pytest.raises(SyncError, match='Missing upstream'):
        syncer.sync(tmp_path / 'book', target)
    assert syncer.sync(tmp_path / 'book', target, allow_missing_upstream=True) == 0
    assert not (target / 'risk_rules/hacktricks-privesc-source.json').exists()


def test_revision_kept_when_canonical_hashes_unchanged(synced):
    target, book = synced
    path = target / 'risk_rules/hacktricks-privesc-source.json'
    manifest = json.loads(path.read_text())
    manifest['revision'] = 'a' * 40
    path.write_text(json.dumps(manifest, indent=2) + '\n')
    syncer.sync(book, target, check=True)


def test_book_revision_from_git_checkout(tmp_path):
    book = tmp_path / 'book'
    (upstream(book) / 'gcp').mkdir(parents=True)
    (upstream(book) / 'gcp/iam.yaml').write_text(entry('gcp-iam-one'))
    git = ['git', '-C', str(book), '-c', 'user.name=t', '-c', 'user.email=t@example.invalid']
    subprocess.run(['git', 'init', '-q', str(book)], check=True)
    subprocess.run([*git, 'add', '.'], check=True)
    subprocess.run([*git, 'commit', '-qm', 'x'], check=True)
    assert re.fullmatch(r'[0-9a-f]{40}', syncer.book_revision(book))
    (upstream(book) / 'gcp/iam.yaml').write_text(entry('gcp-iam-two'))
    assert syncer.book_revision(book) is None  # uncommitted privesc tree: no revision claimed


def test_export_refuses_to_drop_upstream_only_content(synced):
    target, book = synced
    (upstream(book) / 'gcp/run.yaml').write_text(entry('gcp-run-upstream', 'run'))
    with pytest.raises(SyncError, match='gcp/run.yaml'):
        exporter.export(book, repo_root=target)
    with pytest.raises(SyncError, match='Stale upstream'):
        exporter.export(book, repo_root=target, check=True, prune=True)
    exporter.export(book, repo_root=target, prune=True)
    assert not (upstream(book) / 'gcp/run.yaml').exists()


def test_export_refuses_invalid_local_catalog(tmp_path):
    target = make_repo(tmp_path, {'gcp/iam.yaml': entry('gcp-iam-one').replace('critical', 'catastrophic')})
    with pytest.raises(SyncError, match='Invalid local'):
        exporter.export(tmp_path / 'book', repo_root=target)
    assert not (tmp_path / 'book').exists()


def test_export_copies_json_schema_when_present(tmp_path):
    target = make_repo(tmp_path, {'gcp/iam.yaml': entry('gcp-iam-one')})
    (target / 'peaso/privesc/privesc-technique.schema.json').write_text('{"type": "array"}\n')
    exporter.export(tmp_path / 'book', repo_root=target)
    out = upstream(tmp_path / 'book')
    assert (out / 'privesc-technique.schema.json').read_text() == '{"type": "array"}\n'
    assert '(privesc-technique.schema.json)' in (out / 'README.md').read_text()
    syncer.sync(tmp_path / 'book', target, validate_only=True)


def test_fetch_with_privesc_sparse_checks_out_catalog_and_pages(tmp_path, monkeypatch):
    calls = []

    def git(arguments, deadline):
        calls.append(arguments)
        if arguments[0] == 'clone':
            checkout = Path(arguments[-1])
            (checkout / 'src/permission-categorizations').mkdir(parents=True)
            for provider in ('aws', 'gcp', 'azure', 'k8s'):
                (checkout / 'src/permission-categorizations' / f'{provider}.yaml').write_text(provider)
    monkeypatch.setattr(fetcher, '_git', git)
    monkeypatch.setattr(fetcher.time, 'sleep', Mock())
    fetcher.fetch(tmp_path / 'optional', with_privesc=True)
    sparse = [c for c in calls if 'sparse-checkout' in c][0]
    assert sparse[-3:] == ['src/permission-categorizations',
                           'src/privilege-escalation-paths', 'src/pentesting-cloud']
    calls.clear()
    with pytest.raises(RuntimeError, match='five attempts'):
        fetcher.fetch(tmp_path / 'required', require_privesc=True)
    assert sum(c[0] == 'clone' for c in calls) == 5
    assert not (tmp_path / 'required').exists()


def test_fetch_default_is_permissions_only(tmp_path, monkeypatch):
    calls = []

    def git(arguments, deadline):
        calls.append(arguments)
        if arguments[0] == 'clone':
            checkout = Path(arguments[-1]) / 'src/permission-categorizations'
            checkout.mkdir(parents=True)
            for provider in ('aws', 'gcp', 'azure', 'k8s'):
                (checkout / f'{provider}.yaml').write_text(provider)
    monkeypatch.setattr(fetcher, '_git', git)
    fetcher.fetch(tmp_path / 'source')
    assert [c for c in calls if 'sparse-checkout' in c][0][-1] == 'src/permission-categorizations'


WORKFLOWS = ROOT / '.github/workflows'


def _workflow(name):
    workflow = yaml.safe_load((WORKFLOWS / name).read_text())
    return workflow, workflow[True]  # PyYAML parses the bare `on` key as boolean True


@pytest.mark.parametrize('name', ['sync-permission-categorizations.yml', 'tests.yml'])
def test_workflows_pin_actions_and_reference_existing_files(name):
    workflow, _ = _workflow(name)
    for job_name, job in workflow['jobs'].items():
        base = ROOT / job.get('defaults', {}).get('run', {}).get('working-directory', '.')
        for step in job['steps']:
            if 'uses' in step:
                assert re.fullmatch(r'[\w.-]+/[\w.-]+@[0-9a-f]{40}', step['uses']), step['uses']
            run = step.get('run', '')
            for script in re.findall(r'(?:\.\./)*(?:scripts|tests)/[\w./-]+\.py', run):
                assert (base / script).resolve().is_file(), (job_name, script)


def test_sync_workflow_syncs_both_catalogs_and_commits_only_on_change():
    workflow, triggers = _workflow('sync-permission-categorizations.yml')
    assert 'schedule' in triggers and 'workflow_dispatch' in triggers
    steps = [s for job in workflow['jobs'].values() for s in job['steps']]
    text = '\n'.join(s.get('run', '') for s in steps)
    for needed in ('scripts/sync_hacktricks_privesc.py', 'scripts/fetch_hacktricks_permissions.py --destination',
                   '--with-privesc', '--require-privesc', '--revision-file', 'tests/test_privesc_sync.py', '--check',
                   'risk_rules/hacktricks-privesc-source.json',
                   'peaso/privesc/catalog', 'scripts/sync_hacktricks_permissions.py'):
        assert needed in text, needed
    assert '--allow-missing-upstream' not in text
    for job in workflow['jobs'].values():
        commit = [s['run'] for s in job['steps'] if 'git commit' in s.get('run', '')]
        assert all('git diff --cached --quiet' in run for run in commit)



def _junit(tmp_path, reasons):
    cases = ''.join(f'<testcase classname="t" name="n{i}"><skipped message="{r}"/></testcase>' for i, r in enumerate(reasons))
    path = tmp_path / 'report.xml'
    path.write_text(f'<testsuites><testsuite>{cases}<testcase classname="t" name="ok"/></testsuite></testsuites>')
    return path


def test_skip_gate_allows_documented_skips_and_rejects_others(tmp_path):
    checker = _load('check_test_skips_under_test', 'scripts/check_test_skips.py')
    allowed = checker.PYTEST_ALLOWED
    ok = _junit(tmp_path, ['tests/x.py:1: private QA capture is unavailable; no live collection attempted'] * 3)
    assert checker.check(checker.pytest_skips(ok), allowed) == []
    over = _junit(tmp_path, ['private QA capture is unavailable; no live collection attempted'] * 4)
    assert 'exceed the budget' in checker.check(checker.pytest_skips(over), allowed)[0]
    missing = _junit(tmp_path, ["could not import 'moto': No module named 'moto'"])
    assert 'unexpected skip' in checker.check(checker.pytest_skips(missing), allowed)[0]
    report = tmp_path / 'pw.json'
    report.write_text(json.dumps({'stats': {'unexpected': 0, 'flaky': 0}, 'suites': [
        {'file': 'live.spec.ts', 'specs': [{'title': 'live', 'tests': [{'status': 'skipped'}]}], 'suites': []},
        {'file': 'ui.spec.ts', 'specs': [{'title': 'ui', 'tests': [{'status': 'skipped'}]}], 'suites': []}]}))
    problems = checker.check(checker.playwright_skips(report), checker.PLAYWRIGHT_ALLOWED)
    assert problems == ['unexpected skip: ui: ui.spec.ts']
