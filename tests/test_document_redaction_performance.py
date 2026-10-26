"""Whole-document privacy semantics compared with the prior sequential model."""
import copy
import json
import random
import re

import pytest
from peaso.auth import secrets as module


def legacy(value, secrets=()):
    """Frozen pre-optimization contract, including ordered marker cascades."""
    if isinstance(value, dict):
        labels = [item for key, item in value.items() if str(key).lower() in {'key', 'name'} and isinstance(item, str)]
        paired = any(module.SENSITIVE.fullmatch(re.sub(r'[^a-zA-Z0-9]', '', label)) for label in labels)
        return {str(k): '[REDACTED]' if (module.SENSITIVE.fullmatch(re.sub(r'[^a-zA-Z0-9]', '', str(k)))
            or (paired and str(k).lower() in {'value', 'content', 'data'})) and isinstance(v, (str, dict, list))
            else legacy(v, secrets) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [legacy(v, secrets) for v in value]
    if isinstance(value, str):
        value = re.sub(r'-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----',
            '[REDACTED PRIVATE KEY]', value)
        for secret in sorted(set(secrets), key=len, reverse=True):
            if secret and (len(secret) >= 4 or value == secret):
                value = value.replace(secret, '[REDACTED]')
        return value
    return value


@pytest.mark.parametrize('values,text', [
    (['abc', 'abcd'], 'abcd abc abcde'),
    (['synthetic-value', 'REDACTED'], 'synthetic-value'),
    (['[REDACTED]', 'secret', 'REDA'], 'secret [REDACTED]'),
    (['', 'x', 'abc'], 'x'),
    (['', 'x', 'abc'], 'prefix-abc-x'),
    (['a.b*', '[abc]', '\\foo'], 'a.b* [abc] \\foo'),
    (['café🔑', 'λ-value'], 'café🔑 λ-value'),
    (['PRIVATE'], '-----BEGIN RSA PRIVATE KEY-----\nsynthetic\n-----END RSA PRIVATE KEY-----'),
    (['aaaab', 'aaaa'], 'aaaaa'*20000),
])
def test_overlaps_short_values_unicode_pem_and_marker_cascades(values, text):
    assert module.redact(text, values) == legacy(text, values)


def test_sensitive_name_pairing_and_json_shape_are_unchanged():
    value = {'rows': [{'name': 'DB_PASSWORD', 'value': 'secret', 'other': 'keep'},
        {'key': 'session-token', 'content': {'nested': 'secret'}},
        {'name': 'public', 'value': ['secret', 1, False, None]},
        {'privateKey': {'nested': 'secret'}, 'credential': ('secret',)}], 1: 'secret'}
    before = copy.deepcopy(value)
    assert module.redact(value, ['secret']) == legacy(value, ['secret'])
    assert value == before


def test_random_nested_documents_exactly_match_sequential_contract():
    rng = random.Random(20261022)
    atoms = ['', 'abc', 'abcd', 'secret-value', '[REDACTED]', 'REDACTED', 'REDA',
        'café🔑', 'plain', 'password', '\\x.[a]']
    for _ in range(500):
        values = rng.sample(atoms, rng.randrange(len(atoms)+1))
        rows = [{'name': rng.choice(atoms), 'value': ' '.join(rng.choices(atoms, k=4)),
                 'children': (rng.choice(atoms), rng.randrange(10), None)} for _ in range(8)]
        assert module.redact({'items': rows}, values) == legacy({'items': rows}, values)


def test_compiler_is_not_allowed_to_cache_credentials_process_wide():
    import gc
    import weakref
    sentinel = 'synthetic-no-global-credential-cache-opaque-value'
    plan = module.Redactor([sentinel])
    assert plan('prefix '+sentinel) == legacy('prefix '+sentinel, [sentinel])
    for name in ('_cache', '_cache2'):
        assert sentinel not in repr(getattr(re, name, {}))
    if plan.matcher is not None:
        pattern = weakref.ref(plan.matcher)
        del plan
        gc.collect()
        assert pattern() is None


def test_unavailable_compiler_and_oversized_prefilters_use_exact_fallback(monkeypatch):
    monkeypatch.setattr(module, '_literal_matcher', lambda values: None)
    values = ['synthetic-value', 'REDACTED', 'x']
    value = {'text': ['synthetic-value', 'x', 'plain']}
    assert module.redact(value, values) == legacy(value, values)
    plan = module.Redactor(['a'* (module.MAX_PREFILTER_CHARS+1)])
    assert plan.matcher is None
    assert plan('plain') == 'plain'
    many = ['synthetic-'+str(i) for i in range(module.MAX_PREFILTER_VALUES+1)]
    plan = module.Redactor(many)
    assert plan.matcher is None
    assert plan('prefix synthetic-2048') == legacy('prefix synthetic-2048', many)


def test_preparation_freezes_generator_values_for_entire_document():
    value = {'first': 'synthetic-value', 'second': 'synthetic-value'}
    assert module.redact(value, (v for v in ['synthetic-value'])) == {
        'first': '[REDACTED]', 'second': '[REDACTED]'}


def test_capture_public_snapshot_keeps_exact_private_locations_and_aliases(monkeypatch):
    from peaso import secret_evidence as evidence
    from peaso import snapshot as snapshots
    value = 'synthetic-retained-value-café'
    snapshot = snapshots.make_snapshot('aws', ['123456789012/us-east-1'], [{
        'type': 'bucket', 'scope': '123456789012/us-east-1', 'status': 'collected',
        'items': [{'Name': 'fixture-'+value, 'metadata': {value: 'prefix '+value}}]}])
    # Isolate the canonical resource projection seam. Native source-admission
    # and integration tests still run separately against the admitted package.
    monkeypatch.setattr(snapshots, 'resources', lambda raw: [{'native_id': 'fixture-'+value,
        'scope': '123456789012/us-east-1', 'data': raw['collections'][0]['items'][0]}])
    cipher = evidence.EphemeralCipher()
    sink = evidence.Capture(cipher, 'workspace', 'a'*32)
    sink.remember(value, 'fingerprint', {'resource_id': 'fixture-'+value,
        'scope': '123456789012/us-east-1', 'path': 'native'}, 'configuration', 'fixture', ['test'])
    calls = []
    original = module.Redactor
    class Counted(original):
        def __init__(self, *args, **kwargs):
            calls.append(1)
            super().__init__(*args, **kwargs)
    monkeypatch.setattr(module, 'Redactor', Counted)
    before = json.dumps(snapshot, ensure_ascii=False)
    public = sink.public_snapshot(snapshot)
    # Found values stay visible: no Redactor runs and the snapshot is unchanged.
    assert calls == []
    assert json.dumps(public, ensure_ascii=False) == before
    assert value in json.dumps(public, ensure_ascii=False)
    assert public['collections'][0]['items'][0]['metadata'] == {value: 'prefix ' + value}
    document = sink.document()
    row = cipher.decrypt(document['records']['fingerprint'])
    # The exact private location is kept and no resource alias is minted.
    assert row == {'tenant': 'workspace', 'scan_id': 'a'*32, 'fingerprint': 'fingerprint',
        'value': value, 'locations': [{'resource_id': 'fixture-'+value, 'scope': '123456789012/us-east-1',
            'path': 'native', '_check_ids': ['test']}],
        'detectors': [{'engine': 'configuration', 'rule': 'fixture'}], 'check_ids': ['test']}
