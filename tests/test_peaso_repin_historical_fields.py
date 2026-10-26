"""The source re-pin tool never rewrites historical witnesses (NEXT-PROVENANCE-1)."""
import ast
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location('peaso_repin_sources', ROOT / 'scripts/peaso_repin_sources.py')
repin = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(repin)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _git(cwd, *args):
    subprocess.run(['git', *args], cwd=cwd, check=True, capture_output=True)


def test_pointer_rule_separates_history_from_current_pins():
    historical = [
        ('prior_audit_immutable', 'before_sha256'),
        ('immutable_prior_reports', 0, 'current_sha256'),
        ('original_review_attestation', 'sha256_before_and_after_unchanged'),
        ('prior_reports_immutable', 'docs/check-review/x.json', 'after'),
        ('lineage', 'retained_predecessors', 2, 'sha256'),
        ('verified_installed_layouts', 'cp312', 'closure_sha256', 'peaso/x.py'),
    ]
    current = [
        ('sources', 'peaso/collectors/azure.py', 'current_sha256'),
        ('checks', 'gcp.review.prior_x', 'source_sha256'),  # a check id, not a schema key
        ('lineage', 'predecessor_receipt_sha256'),
        ('predecessor_receipt_sha256',),
        ('prior_bridge_receipt_sha256',),
        ('predecessor_files', 'peaso/checks/a.py'),
        ('historical_receipt_sha256',),
        ('producers', 'securityhub_finding_history', 'fetcher', 'sha256'),
        ('archived_checks', 3, 'clarity_evaluation_contract'),
    ]
    assert all(repin.historical_pointer(p) for p in historical)
    assert not any(repin.historical_pointer(p) for p in current)


def test_substitute_keeps_historical_digest_and_moves_current_pin():
    old, new = 'a' * 64, 'b' * 64
    text = json.dumps({
        'current_sha256': old,
        'prior_audit_immutable': {'before_sha256': old, 'after_sha256': old},
        'note': f'path:93:{old}',
        old: {'archived': [old]},
    }, indent=2) + '\n'
    out = json.loads(repin.substitute('docs/r.json', text, {old: new}))
    assert out['current_sha256'] == new
    assert out['prior_audit_immutable'] == {'before_sha256': old, 'after_sha256': old}
    assert out['note'] == f'path:93:{new}'
    assert out[new] == {'archived': [old]}
    # Non-JSON files have no pointers: every pinned digest follows the edit.
    assert repin.substitute('t.py', f"X = '{old}'\n", {old: new}) == f"X = '{new}'\n"


def test_repin_run_preserves_historical_fields_and_frozen_files(tmp_path, monkeypatch):
    src = tmp_path / 'peaso/mod.py'
    src.parent.mkdir(parents=True)
    src.write_text('def f():\n    return 1\n')
    before = _sha(src.read_bytes())
    receipt = tmp_path / 'docs/receipt.json'
    receipt.parent.mkdir()
    receipt.write_text(json.dumps({
        'current_sha256': before,
        'prior_audit_immutable': {'before_sha256': before, 'same_bytes': True},
        'original_review_attestation': {'sha256_before_and_after_unchanged': before},
    }, indent=2) + '\n')
    frozen = tmp_path / 'tests/fixtures/gcp-wave2-final-services-history-20261020/predecessor-hashes.json'
    frozen.parent.mkdir(parents=True)
    frozen.write_text(json.dumps({'peaso/mod.py': before}) + '\n')
    _git(tmp_path, 'init', '-q')
    _git(tmp_path, 'add', '-A')
    _git(tmp_path, '-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-qm', 'base')

    src.write_text('def f():\n    return 2\n')
    after = _sha(src.read_bytes())
    monkeypatch.setattr(repin, 'ROOT', tmp_path)
    monkeypatch.setattr(sys, 'argv', ['peaso_repin_sources.py'])
    assert repin.main() == 0

    data = json.loads(receipt.read_text())
    assert data['current_sha256'] == after
    assert data['prior_audit_immutable']['before_sha256'] == before
    assert data['original_review_attestation']['sha256_before_and_after_unchanged'] == before
    assert json.loads(frozen.read_text()) == {'peaso/mod.py': before}


def test_archived_epoch_azure_transport_witnesses_are_conserved():
    """NEXT-EPOCH-1: the epoch keeps the AzureTransport hashes of its archived epoch_after source."""
    assert 'peaso/private_secret_source_epoch_20261021.json' in repin.FROZEN
    epoch = json.loads((ROOT / 'peaso/private_secret_source_epoch_20261021.json').read_bytes())
    row = next(r for r in epoch['sources'] if r['path'] == 'peaso/collectors/azure.py')
    assert row['after_sha256'] == '36116c0439e811ade854d3a74f6679e8675b985d9bf1a0863d2fdddaf2718b63'
    transport = next(d for d in row['definitions'] if d['name'] == 'AzureTransport')
    assert transport['after'] == '794280788976fc7deeea34010d65ac1ce87a2bdc3ff673b6b4ceed837e877457'
    assert transport['methods']['request']['after'] == (
        '885b4a2772ad7b81023b99a6760d66172d65426bc30f69fb754eab764ffec1f9')
    # The current collector is admitted by the reviewed collector successor, not the epoch.
    successor = json.loads((ROOT / 'peaso/private_reviewed_collector_successor_20261022.json').read_bytes())
    assert successor['sources']['peaso/collectors/azure.py']['current_sha256'] == _sha(
        (ROOT / 'peaso/collectors/azure.py').read_bytes())


def test_python_pin_blocks_refresh_current_and_freeze_history(tmp_path):
    old, new = 'a' * 64, 'b' * 64
    (tmp_path / 'docs').mkdir()
    (tmp_path / 'docs/r.json').write_text('{}\n')
    cur = _sha((tmp_path / 'docs/r.json').read_bytes())
    rel = 'tests/test_x.py'
    text = (
        "import json\n"
        f"REPORT_SHA256 = '{old}'\n"
        "PINNED = json.loads(r'''\n"
        f'{{"docs/r.json": "{old}"}}\n'
        "''')\n"
        f"EPOCH = json.loads(r'''{{\"docs/r.json\": \"{old}\"}}''')\n"
        f"SUCC = {{'docs/r.json': {{'before_sha256': '{old}', 'after_sha256': '{old}'}}}}\n"
    )
    blocks = {(rel, 'PINNED'): 'current', (rel, 'EPOCH'): 'historical', (rel, 'SUCC'): 'current'}
    saved = repin.PY_PIN_BLOCKS, repin.CURRENT_PIN_CONSTANTS
    repin.PY_PIN_BLOCKS, repin.CURRENT_PIN_CONSTANTS = blocks, {(rel, 'REPORT_SHA256'): 'docs/r.json'}
    try:
        refreshed = repin.refresh_current_pins(rel, text, root=tmp_path)
        assert refreshed.count(cur) == 3 and refreshed.count(old) == 2
        assert f"REPORT_SHA256 = '{cur}'" in refreshed
        assert f"'before_sha256': '{old}', 'after_sha256': '{cur}'" in refreshed
        assert f'EPOCH = json.loads(r\'\'\'{{"docs/r.json": "{old}"}}' in refreshed
        mapped = repin.substitute(rel, text, {old: new})
        # Only the unregistered-history digests move with the edit mapping.
        assert mapped.count(old) == 2 and mapped.count(new) == 3
    finally:
        repin.PY_PIN_BLOCKS, repin.CURRENT_PIN_CONSTANTS = saved


def test_registered_python_pins_are_current_in_tree():
    """A stale current pin fails here (and in push_locked's gate) instead of rotting."""
    registered = {path for path, _ in (*repin.PY_PIN_BLOCKS, *repin.CURRENT_PIN_CONSTANTS)}
    for rel in sorted(registered):
        text = (ROOT / rel).read_text(encoding='utf-8', errors='surrogateescape')
        assert {name for path, name in repin.PY_PIN_BLOCKS if path == rel} <= {
            node.targets[0].id for node in ast.parse(text).body
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)}, rel
        assert repin.refresh_current_pins(rel, text) == text, f'{rel}: stale current pin; run scripts/peaso_repin_sources.py'
