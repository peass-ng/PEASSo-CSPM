"""Found secrets stay visible; private capture seals each record once per run."""
import copy
import random

import pytest

from peaso import secret_evidence as se
from peaso import secret_scanning as scanning
from peaso.auth.secrets import Redactor, redact
from peaso.snapshot import make_snapshot


SECRET = 'AKIAIOSFODNN7EXAMPLEQ'


def _rows(capture):
    return {fp: capture.cipher.decrypt(sealed) for fp, sealed in capture.records.items()}


def _remember_all(events):
    for value, rid, path, line in events:
        with se.source_context(resource_id=rid, scope='111122223333/us-east-1', path=path):
            se.remember(value, scanning._fingerprint(value), path=path, line=line,
                        engine='trufflehog', rule='AWS', public_path=path)


def _events():
    rng = random.Random(5)
    values = [SECRET + str(i) for i in range(6)]
    return [(rng.choice(values), f'r{rng.randrange(4)}', f'f{rng.randrange(5)}', rng.randrange(1, 4))
            for _ in range(300)]


def test_batched_capture_matches_serial_records():
    events = _events()
    with se.capture(se.EphemeralCipher()) as serial:
        _remember_all(events)
        expected = _rows(serial)
        counters = (serial.bytes, serial.locations, serial.incomplete)
    with se.capture(se.EphemeralCipher()) as batched:
        with se.batched():
            _remember_all(events)
            # Open rows are not sealed until the run ends.
            assert set(batched.records) == set(expected)
        assert _rows(batched) == expected
        assert (batched.bytes, batched.locations, batched.incomplete) == counters


def test_found_values_stay_visible_and_unchanged_records_keep_their_seal():
    native = {'FunctionArn': 'arn:aws:lambda:us-east-1:111122223333:function:f',
              'Environment': {'Variables': {'DB_PASSWORD': SECRET, 'KEY_' + SECRET: 'x'}}}
    snapshot = make_snapshot('aws', ['111122223333'], [{'type': 'lambda_function',
        'scope': '111122223333/us-east-1', 'status': 'collected', 'items': [native]}],
        created_at='2026-01-01T00:00:00+00:00')
    original = copy.deepcopy(snapshot)
    with se.capture(se.EphemeralCipher()) as capture:
        with se.source_context(resource_id=native['FunctionArn'], path='env'):
            se.remember(SECRET, scanning._fingerprint(SECRET), path='env', engine='configuration', rule='x')
        public = capture.public_snapshot(snapshot)
        assert public == original
        assert SECRET in str(public)
        assert capture.redactions == {}
        sealed = dict(capture.records)
        capture.public_snapshot(snapshot)
        # The scope was bound once; a repeated identical call re-encrypts nothing.
        assert capture.records == sealed
        row = capture.cipher.decrypt(next(iter(capture.records.values())))
        assert row['value'] == SECRET
        assert row['locations'][0]['scope'] == '111122223333/us-east-1'


def _reference_bind(capture, snapshot):
    """The previous bind_snapshot algorithm, applied to plaintext rows."""
    from peaso.snapshot import resources
    candidates = {}
    def walk(value, resource):
        if isinstance(value, dict):
            if isinstance(value.get('fingerprint'), str) and value['fingerprint'] in capture.records and isinstance(value.get('locations'), list):
                for loc in value['locations']:
                    key = (value['fingerprint'], loc.get('path'))
                    ref = {**resource, **{k: loc[k] for k in ('scope', 'layer', 'resource_id') if loc.get(k)}}
                    if ref not in candidates.setdefault(key, []):
                        candidates[key].append(ref)
            for child in value.values():
                walk(child, resource)
        elif isinstance(value, list):
            for child in value:
                walk(child, resource)
    authorities = {}
    for resource in resources(snapshot):
        native = resource.get('data', {})
        for ident in {resource['native_id'], *[native.get(k) for k in ('Arn', 'arn', 'id', 'name', 'FunctionArn', 'taskDefinitionArn', 'jobDefinitionArn') if isinstance(native.get(k), str)]}:
            authorities.setdefault(ident, set()).add(resource['scope'])
        walk(native, {'resource_id': resource['native_id'], 'scope': resource['scope']})
    rows = _rows(capture)
    for fp, row in rows.items():
        for loc in row['locations']:
            scopes = authorities.get(loc.get('resource_id'), ())
            if len(scopes) == 1 and (not loc.get('scope') or loc['scope'] == next(iter(scopes)).rsplit('/', 1)[-1]):
                loc['scope'] = next(iter(scopes))
            parents = {fp} | {primary for primary, related in capture.related.items() if fp in related}
            options = []
            for parent in parents:
                for option in candidates.get((parent, loc.get('_public_path', loc.get('witness_path'))), []):
                    if option not in options:
                        options.append(option)
            exact = [option for option in options if option['resource_id'] == loc.get('resource_id')
                     and (not loc.get('scope') or option['scope'] == loc['scope'])]
            if exact:
                options = exact
            bound = (len(options) == 1 and (not loc.get('scope') or loc['scope'] == options[0]['scope'])
                and (not loc.get('resource_id') or options[0]['resource_id'] == loc['resource_id']
                or str(loc.get('_public_path', '')).startswith(options[0]['resource_id'] + '.')))
            if bound:
                loc['_canonical_resource_id'], loc['_canonical_scope'] = options[0]['resource_id'], options[0]['scope']
            if not loc.get('resource_id') and len(options) == 1:
                loc.update(options[0])
    return rows


@pytest.mark.parametrize('seed', range(6))
def test_indexed_bind_matches_previous_algorithm(seed):
    rng = random.Random(seed)
    values = [SECRET + str(i) for i in range(8)]
    rids = [f'arn:aws:lambda:us-east-1:111122223333:function:f{i}' for i in range(5)]
    items, collections = [], []
    for i, rid in enumerate(rids):
        item = {'FunctionArn': rid, 'name': f'f{i}'}
        if rng.random() < .7:
            value = rng.choice(values)
            item['leaks'] = [{'fingerprint': scanning._fingerprint(value), 'detectors': [],
                              'locations': [{'path': rng.choice(['a', 'b', 'c'])}]}]
        items.append(item)
    collections.append({'type': 'lambda_function', 'scope': '111122223333/us-east-1',
                        'status': 'collected', 'items': items})
    collections.append({'type': 'lambda_function', 'scope': '111122223333/us-west-2', 'status': 'collected',
                        'items': [dict(items[0], FunctionArn=rids[0].replace('east-1', 'west-2'), name='dup')]})
    snapshot = make_snapshot('aws', ['111122223333'], collections, created_at='2026-01-01T00:00:00+00:00')
    with se.capture(se.EphemeralCipher()) as capture:
        for _ in range(40):
            value = rng.choice(values)
            fields = {'path': rng.choice(['a', 'b', 'c'])}
            if rng.random() < .6:
                fields['resource_id'] = rng.choice(rids + ['other'])
            if rng.random() < .3:
                fields['scope'] = rng.choice(['us-east-1', '111122223333/us-east-1', 'x'])
            with se.source_context(**fields):
                se.remember(value, scanning._fingerprint(value), path=fields['path'], engine='kingfisher',
                            rule='r', public_path=fields['path'])
        primary, child = scanning._fingerprint(values[0]), scanning._fingerprint(values[1])
        if primary in capture.records and child in capture.records:
            capture.related[primary] = {child}
        expected = _reference_bind(capture, snapshot)
        capture.bind_snapshot(snapshot)
        assert _rows(capture) == expected


def test_scan_content_keeps_found_values_in_paths_and_metadata(monkeypatch):
    seen = []
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda payload, path, timeout: [(SECRET, 'aws', 1)])
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda payload, path, timeout: scanning._DetectorMatches())
    outcome = scanning.scan_content(b'key=' + SECRET.encode(), 'dir/' + SECRET + '.env', _redact_values=seen.append)
    assert seen == [frozenset()]
    assert outcome['leaks'][0]['locations'] == [{'path': 'dir/' + SECRET + '.env', 'line': 1}]
    assert scanning.redact_matches({'a': [SECRET]}, [SECRET]) == {'a': [SECRET]}


def test_clean_outcome_is_reused_under_private_capture(monkeypatch):
    calls = []
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda payload, path, timeout: calls.append(path) or [])
    monkeypatch.setattr(scanning, '_prepared_trufflehog_output', lambda payload, path: None)
    monkeypatch.setattr(scanning, '_trufflehog', lambda: 'trufflehog')
    monkeypatch.setattr(scanning, '_run', lambda argv, payload, timeout: calls.append('run') or b'')
    payload = b'clean bytes %d' % random.randrange(1 << 60)
    with se.capture(se.EphemeralCipher()):
        first = scanning.scan_content(payload, 'one')
        assert scanning.scan_content(payload, 'one') == first
        # Same bytes at another path: Kingfisher runs again, TruffleHog does not.
        scanning.scan_content(payload, 'two')
    assert calls == ['one', 'run', 'two']
    assert first['complete'] and first['leaks'] == []


def test_value_only_redaction_keeps_found_secret_fields():
    document = {'DB_PASSWORD': SECRET, 'env': [{'name': 'TOKEN', 'value': SECRET}],
                'key': '-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----', 'auth': 'scanner-own-credential'}
    assert redact(document, ('scanner-own-credential',), fields=False) == dict(document, auth='[REDACTED]')
    assert Redactor(('scanner-own-credential',))(document)['DB_PASSWORD'] == '[REDACTED]'
