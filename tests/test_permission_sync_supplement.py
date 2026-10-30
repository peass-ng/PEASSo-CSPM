"""Small offline fixtures for the canonical/reviewed-permission merge boundary."""
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('supplement_sync', ROOT / 'scripts/sync_hacktricks_permissions.py')
syncer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(syncer)


def categories(**levels):
    return {level: levels.get(level, []) for level in syncer.LEVELS}


def reviewed(providers=None):
    providers = providers or {'aws': categories(high=['sample:Write'])}
    return dict(version=1, review=dict(
        description='Fixture reviewed additions',
        baseline_archive=dict(name='accepted-source.zip', sha256='a' * 64),
        provider_sha256={p: dict(baseline='b' * 64, reviewed='c' * 64) for p in providers}),
        providers=providers)


def write_supplement(target, value):
    path = target / syncer.SUPPLEMENT_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + '\n')
    return path


def files_under(target):
    return {p.relative_to(target).as_posix(): p.read_bytes() for p in target.rglob('*') if p.is_file()}


@pytest.fixture
def tree(tmp_path, monkeypatch):
    book, target = tmp_path / 'book', tmp_path / 'target'
    source = book / 'src/permission-categorizations'
    source.mkdir(parents=True)
    for provider in syncer.PROVIDERS[:3]:
        value = dict(version=1, provider=provider, permission_categories=categories(),
                     combinations={'critical': [], 'high': []}, untouched_note='Keep metadata')
        (source / f'{provider}.yaml').write_text('# canonical fixture\n' + yaml.safe_dump(value, sort_keys=False))
    (source / 'k8s.yaml').write_text('# unchanged Kubernetes fixture\n' + yaml.safe_dump(dict(
        version=1, provider='k8s', rules=[dict(id='fallback', match={'always': True},
        severity='low', description='Discovery')]), sort_keys=False))
    engine = target / 'scripts/cloud_permission_risks.py'
    engine.parent.mkdir(parents=True)
    engine.touch()
    monkeypatch.setattr(syncer.subprocess, 'check_output', lambda *a, **kw: 'd' * 40)
    return book, target, source


def change_source(source, provider, **fields):
    path = source / f'{provider}.yaml'
    value = yaml.safe_load(path.read_bytes())
    value.update(fields)
    path.write_text('# upstream bytes are authoritative\n' + yaml.safe_dump(value, sort_keys=False))


def test_absent_supplement_keeps_legacy_bytes_and_manifest(tree):
    book, target, source = tree
    syncer.sync(book, target)
    hashes = {}
    for provider in syncer.PROVIDERS:
        raw = (source / f'{provider}.yaml').read_bytes()
        assert (target / 'risk_rules' / f'{provider}.yaml').read_bytes() == raw
        hashes[f'{provider}.yaml'] = hashlib.sha256(raw).hexdigest()
        if provider != 'k8s':
            expected = yaml.safe_dump(yaml.safe_load(raw)['permission_categories'], sort_keys=False, width=120).encode()
            assert (target / f'{provider}_permissions_cat.yaml').read_bytes() == expected
    expected = dict(repository='HackTricks-wiki/hacktricks-cloud', revision='d' * 40,
                    path='src/permission-categorizations', sha256=hashes)
    assert (target / 'risk_rules/hacktricks-source.json').read_bytes() == (json.dumps(expected, indent=2) + '\n').encode()
    before = files_under(target)
    syncer.sync(book, target, check=True)
    syncer.sync(book, target)
    assert files_under(target) == before


@pytest.mark.parametrize('provider,variants', [
    ('aws', ['sample:Read', 'SAMPLE:READ']),
    ('azure', ['Microsoft.Sample/widgets/read', 'microsoft.sample/WIDGETS/READ']),
])
def test_same_level_case_variants_remain_valid_and_canonical_wins(tree, provider, variants):
    book, target, source = tree
    change_source(source, provider, permission_categories=categories(low=variants))
    write_supplement(target, reviewed({provider: categories(high=[variants[0].swapcase()])}))
    syncer.sync(book, target)
    assert (target / 'risk_rules' / f'{provider}.yaml').read_bytes() == (source / f'{provider}.yaml').read_bytes()
    actual = yaml.safe_load((target / f'{provider}_permissions_cat.yaml').read_bytes())
    assert actual == categories(low=variants)


@pytest.mark.parametrize('provider,variants', [
    ('aws', ['sample:Read', 'SAMPLE:READ']),
    ('azure', ['Microsoft.Sample/widgets/read', 'microsoft.sample/WIDGETS/READ']),
])
def test_supplement_same_level_case_variants_are_preserved(tree, provider, variants):
    book, target, _ = tree
    write_supplement(target, reviewed({provider: categories(low=variants)}))
    syncer.sync(book, target)
    assert yaml.safe_load((target / f'{provider}_permissions_cat.yaml').read_bytes()) == categories(low=sorted(variants))


def test_gcp_case_remains_significant(tree):
    book, target, source = tree
    change_source(source, 'gcp', permission_categories=categories(low=['sample.widgets.Read']))
    write_supplement(target, reviewed({'gcp': categories(high=['sample.widgets.read'])}))
    syncer.sync(book, target)
    assert yaml.safe_load((target / 'gcp_permissions_cat.yaml').read_bytes()) == categories(
        low=['sample.widgets.Read'], high=['sample.widgets.read'])


@pytest.mark.parametrize('provider,variants', [
    ('aws', ['sample:Read', 'SAMPLE:READ']),
    ('azure', ['Microsoft.Sample/widgets/read', 'microsoft.sample/WIDGETS/READ']),
    ('gcp', ['sample.widgets.read', 'sample.widgets.read']),
])
def test_true_cross_level_conflicts_fail_before_writes(tree, provider, variants):
    book, target, source = tree
    change_source(source, provider, permission_categories=categories(low=[variants[0]], high=[variants[1]]))
    before = files_under(target)
    with pytest.raises(ValueError, match='Duplicate permission'):
        syncer.sync(book, target)
    assert files_under(target) == before
    change_source(source, provider, permission_categories=categories())
    write_supplement(target, reviewed({provider: categories(low=[variants[0]], high=[variants[1]])}))
    before = files_under(target)
    with pytest.raises(ValueError, match='conflicting supplement'):
        syncer.sync(book, target)
    assert files_under(target) == before






def test_effective_hashes_remain_compatible_with_existing_provenance_validator(tree):
    book, target, _ = tree
    write_supplement(target, reviewed())
    syncer.sync(book, target)
    validator_spec = importlib.util.spec_from_file_location(
        'supplement_provenance_validator', ROOT / 'scripts/peaso_validate_risk_catalog.py')
    validator = importlib.util.module_from_spec(validator_spec)
    validator_spec.loader.exec_module(validator)
    review_catalog = {'sources': [dict(id='hacktricks-criticality',
        repository='HackTricks-wiki/hacktricks-cloud', revision='d' * 40)]}
    assert validator.validate_bundled_provenance(review_catalog, root=target) == []
    path = target / 'risk_rules/aws.yaml'
    path.write_bytes(path.read_bytes() + b'\n# unrecorded change\n')
    assert validator.validate_bundled_provenance(review_catalog, root=target) == ['bundled source hash mismatch: aws.yaml']


def test_cloud_target_preserves_legacy_combinations_and_uses_effective_bundle(tree):
    book, target, source = tree
    engine = target / 'src/CloudPEASS/permission_risk_classifier.py'
    engine.parent.mkdir(parents=True)
    engine.touch()
    folder = target / 'src/sensitive_permissions'
    folder.mkdir()
    legacy = '# exact legacy formatting\nvery_sensitive_combinations = []\nsensitive_combinations = []\n'
    for provider in syncer.PROVIDERS[:3]:
        (folder / f'{provider}.py').write_text(legacy)
    write_supplement(target, reviewed())
    syncer.sync(book, target)
    rules = target / 'src/CloudPEASS/risk_rules'
    assert yaml.safe_load((rules / 'aws.yaml').read_bytes())['permission_categories']['high'] == ['sample:Write']
    for provider in syncer.PROVIDERS[:3]:
        assert (folder / f'{provider}.py').read_text() == legacy
        assert not (target / f'{provider}_permissions_cat.yaml').exists()
    assert (rules / 'k8s.yaml').read_bytes() == (source / 'k8s.yaml').read_bytes()
    before = files_under(target)
    syncer.sync(book, target, check=True)
    assert files_under(target) == before


@pytest.mark.parametrize('bad', [
    categories(high=['sample:*']), categories(high=[' sample:Read']),
    categories(high=['sample:Read\n']), categories(high=['sample:Read?']),
    categories(high=['sample:Read', 'sample:Read']), categories(high=[None]),
    categories(high='sample:Read'), {'high': ['sample:Read']},
    dict(categories(), unsupported=[]),
])
def test_malformed_supplements_are_rejected_before_writes(tree, bad):
    book, target, _ = tree
    write_supplement(target, reviewed({'aws': bad}))
    before = files_under(target)
    with pytest.raises(ValueError):
        syncer.sync(book, target)
    assert files_under(target) == before


def test_duplicate_json_keys_missing_file_and_k8s_are_rejected(tree):
    book, target, _ = tree
    with pytest.raises(FileNotFoundError):
        syncer.sync(book, target, supplement_path=target / 'absent.json')
    supplement = write_supplement(target, reviewed())
    supplement.write_text(supplement.read_text().replace('"version": 1', '"version": 1, "version": 1'))
    before = files_under(target)
    with pytest.raises(ValueError, match='Duplicate supplement JSON key'):
        syncer.sync(book, target, validate_only=True)
    assert files_under(target) == before
    write_supplement(target, reviewed({'k8s': categories()}))
    with pytest.raises(ValueError, match='Unsupported supplement providers'):
        syncer.sync(book, target)


def test_conflicting_non_permission_identifier_is_not_made_a_permission(tree):
    book, target, source = tree
    change_source(source, 'aws', non_permission_identifiers=['SAMPLE:WRITE'])
    write_supplement(target, reviewed())
    before = files_under(target)
    with pytest.raises(ValueError, match='non-permission identifiers'):
        syncer.sync(book, target)
    assert files_under(target) == before


@pytest.mark.parametrize('adoption', ['missing', 'marker', 'category', 'override'])
def test_reviewed_non_permission_metadata_keeps_semantics_and_upstream_precedence(tree, monkeypatch, adoption):
    book, target, source = tree
    value = reviewed({'aws': categories()})
    value['non_permission_identifiers'] = {'aws': ['SNS:Receive']}
    write_supplement(target, value)
    if adoption == 'marker':
        change_source(source, 'aws', non_permission_identifiers=['sns:receive'])
    elif adoption == 'category':
        change_source(source, 'aws', permission_categories=categories(high=['sns:receive']))
    elif adoption == 'override':
        change_source(source, 'aws', severity_overrides={'sns:receive': 'high'})
    syncer.sync(book, target)
    rules = yaml.safe_load((target / 'risk_rules/aws.yaml').read_bytes())
    manifest = json.loads((target / 'risk_rules/hacktricks-source.json').read_bytes())
    applied = manifest['effective']['supplement_non_permission_identifiers']['aws']
    assert applied == (['SNS:Receive'] if adoption == 'missing' else [])
    if adoption != 'missing':
        assert (target / 'risk_rules/aws.yaml').read_bytes() == (source / 'aws.yaml').read_bytes()
    if adoption in {'missing', 'marker'}:
        assert not any(rules['permission_categories'].values())
        assert [p.casefold() for p in rules['non_permission_identifiers']] == ['sns:receive']
    engine_spec = importlib.util.spec_from_file_location('supplement_classifier', ROOT / 'scripts/cloud_permission_risks.py')
    engine = importlib.util.module_from_spec(engine_spec)
    # Dataclasses resolve their module while loading the classifier.
    import sys
    monkeypatch.setitem(sys.modules, engine_spec.name, engine)
    engine_spec.loader.exec_module(engine)
    monkeypatch.setattr(engine, '_bundled_rules_path', lambda p: target / 'risk_rules' / f'{p}.yaml')
    expected = 'low' if adoption in {'missing', 'marker'} else 'high'
    assert engine.classify_permission('aws', 'SNS:Receive', unknown_default='critical', offline=True) == expected
    assert engine.classify_permission('aws', 'sns:receive', unknown_default='medium', offline=True) == expected
    syncer.sync(book, target, check=True)


@pytest.mark.parametrize('identifiers', [['SAMPLE:WRITE'], ['SNS:Receive', 'sns:receive'], ['SNS:*'], 'SNS:Receive'])
def test_malformed_or_conflicting_reviewed_non_permission_metadata_is_rejected(tree, identifiers):
    book, target, _ = tree
    value = reviewed()
    value['non_permission_identifiers'] = {'aws': identifiers}
    write_supplement(target, value)
    before = files_under(target)
    with pytest.raises(ValueError):
        syncer.sync(book, target)
    assert files_under(target) == before


def test_real_reviewed_coverage_survives_old_upstream_and_repeated_sync(tree):
    book, target, source = tree
    value, raw = syncer.load_supplement(ROOT / syncer.SUPPLEMENT_PATH)
    assert {p: [len(value['providers'][p][level]) for level in syncer.LEVELS] for p in value['providers']} == {
        'aws': [2, 2, 2, 0], 'gcp': [71, 271, 55, 1]}
    assert value['non_permission_identifiers'] == {'aws': ['SNS:Receive']}
    supplement = target / syncer.SUPPLEMENT_PATH
    supplement.parent.mkdir(parents=True)
    supplement.write_bytes(raw)
    syncer.sync(book, target)
    for provider, reviewed_categories in value['providers'].items():
        catalog = yaml.safe_load((target / f'{provider}_permissions_cat.yaml').read_bytes())
        rules = yaml.safe_load((target / 'risk_rules' / f'{provider}.yaml').read_bytes())
        assert catalog == reviewed_categories == rules['permission_categories']
        assert rules['untouched_note'] == 'Keep metadata'
    assert yaml.safe_load((target / 'risk_rules/aws.yaml').read_bytes())['non_permission_identifiers'] == ['SNS:Receive']
    for provider in ('azure', 'k8s'):
        assert (target / 'risk_rules' / f'{provider}.yaml').read_bytes() == (source / f'{provider}.yaml').read_bytes()
    before = files_under(target)
    syncer.sync(book, target)
    syncer.sync(book, target, check=True)
    assert files_under(target) == before
