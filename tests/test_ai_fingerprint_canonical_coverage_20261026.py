"""Call-local coverage reuse preserves the ordinary document/hash contract."""
from copy import deepcopy
import hashlib
import json
from types import SimpleNamespace

import pytest

from peaso.ai import collection_coverage
from peaso.ai import pipeline


def fixture(case):
    scopes = ['scope-a', 'scope-b', 'scope-a', 'scope-b', None, 'scope-a', 'scope-b', None]
    findings = [dict(id=f'finding-{i}', resource_id=f'resource-{i}', status='FAIL', category='hardening',
                     check_id='synthetic-check', evidence={'recorded': i},
                     **({'scope': scope} if scope is not None else {}))
                for i, scope in enumerate(scopes)]
    inventory = {f'resource-{i}': {'id': f'resource-{i}', 'scope': scope or '*',
                                 'data': {'setting': i}} for i, scope in enumerate(scopes)}
    rows = [{'level': 'collection', 'scope': scope, 'type': 'kind', 'status': 'collected', 'resource_count': 1}
            for scope in ('*', 'scope-a', 'scope-b')]
    if case in ('denied', 'partial'):
        rows[1]['status'] = case
    if case == 'mixed':
        rows.extend([
            {'level': 'collection', 'scope': 'scope-b', 'type': 'denied-kind', 'status': 'denied'},
            {'level': 'collection', 'scope': 'scope-a', 'type': 'partial-kind', 'status': 'partial', 'resource_count': 3},
            {'level': 'collection', 'scope': '*', 'type': 'unknown-kind', 'status': 'unknown', 'resource_count': True},
            {'level': 'collection', 'scope': 'scope-a', 'type': 'bad-status', 'status': 'invented'},
            {'level': 'check', 'scope': 'scope-a', 'type': 'not-collection', 'status': 'collected'},
        ])
    if case == 'truncated':
        rows.extend({'level': 'collection', 'scope': scope, 'type': f'kind-{i}',
                     'status': 'partial' if i % 2 else 'denied', 'resource_count': i}
                    for scope in ('scope-a', 'scope-b') for i in range(collection_coverage.MAX_ENTRIES + 2))
    report = {'provider': 'aws', 'snapshot_id': 'revision-one', 'created_at': '2026-10-26', 'coverage': rows}
    return report, inventory, findings


def ordinary_payloads(report, inventory, findings, identity):
    """Reference contract: use the standalone normalizer freshly for each row."""
    coverage = collection_coverage.index(report['coverage'])
    payloads = []
    for row in findings:
        references = set(pipeline.referenced_strings(row))
        context = pipeline.review_context(report, inventory, [row], _references=references, _coverage=coverage)
        document = pipeline.findings_document(context['scan'], [row], context['resources'], _references=(references,))
        document['scan'].pop('snapshot_id', None)
        document['scan'].pop('created_at', None)
        payloads.append({'document': document, 'identity': identity, 'access_boundary': []})
    return payloads


@pytest.mark.parametrize('case', ['complete', 'denied', 'partial', 'mixed', 'truncated'])
def test_documents_and_fingerprints_match_fresh_two_step_normalization(monkeypatch, case):
    monkeypatch.setattr(pipeline, '_evidence_summary', lambda: lambda finding: 'The synthetic setting is recorded.')
    report, inventory, findings = fixture(case)
    before = deepcopy((report, inventory, findings))
    identity = {'ai_user': 'owned-user', 'access_reference': 'revision-one'}
    expected = ordinary_payloads(report, inventory, findings, identity)
    encoded = [json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False) for payload in expected]
    captured, index_calls = [], []
    original_index = collection_coverage.index

    def counted(rows):
        index_calls.append(True)
        return original_index(rows)

    def capture(value, **kwargs):
        result = json.dumps(value, **kwargs)
        captured.append(result)
        return result

    monkeypatch.setattr(collection_coverage, 'index', counted)
    monkeypatch.setattr(pipeline, 'json', SimpleNamespace(dumps=capture))
    result = pipeline.review_fingerprints(report, inventory, findings, identity=identity, entries=[])
    assert captured == encoded
    assert result == {row['id']: hashlib.sha256(payload.encode()).hexdigest()
                      for row, payload in zip(findings, encoded)}
    assert len(index_calls) == 4  # One report proof, then one ordinary normalization per scope.
    assert (report, inventory, findings) == before
    if case == 'truncated':
        for payload in expected[:4]:
            coverage = payload['document']['scan']['collection_coverage']
            assert len(coverage['entries']) == collection_coverage.MAX_ENTRIES
            assert coverage['truncated'] is True


def test_no_proof_or_canonical_document_is_reused_between_calls(monkeypatch):
    monkeypatch.setattr(pipeline, '_evidence_summary', lambda: lambda finding: 'The synthetic setting is recorded.')
    report, inventory, findings = fixture('complete')
    identity = {'ai_user': 'owned-user'}
    first = pipeline.review_fingerprints(report, inventory, findings, identity=identity, entries=[])
    report['coverage'][1]['status'] = 'denied'
    expected = ordinary_payloads(report, inventory, findings, identity)
    second = pipeline.review_fingerprints(report, inventory, findings, identity=identity, entries=[])
    assert second == {row['id']: hashlib.sha256(json.dumps(payload, sort_keys=True,
        separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
        for row, payload in zip(findings, expected)}
    assert first['finding-0'] != second['finding-0']
    assert first['finding-1'] == second['finding-1']


def test_standalone_document_still_validates_supplied_coverage(monkeypatch):
    monkeypatch.setattr(pipeline, '_evidence_summary', lambda: lambda finding: '')
    scan = {'provider': 'aws', 'collection_coverage': {'entries': [
        {'scope': 'scope-a', 'type': 'valid-kind', 'status': 'partial'},
        {'scope': 'scope-a', 'type': 'invalid-kind', 'status': 'invented'},
        {'scope': 'scope-b', 'type': 'foreign-kind', 'status': 'denied'},
    ], 'truncated': False}}
    document = pipeline.findings_document(scan, [{'id': 'finding', 'scope': 'scope-a'}])
    assert document['scan']['collection_coverage'] == {'entries': [
        {'scope': 'scope-a', 'type': 'valid-kind', 'status': 'partial'}], 'truncated': False}
