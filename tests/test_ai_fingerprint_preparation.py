"""Prepared references preserve exact review documents and authorization hashes."""
import copy

import pytest

from peaso.ai import pipeline


def fixture(provider, access):
    scope = {'aws': '123456789012/us-east-1', 'gcp': 'projects/synthetic',
             'azure': 'subscriptions/synthetic', 'k8s': 'namespace-a'}[provider]
    inventory = {key: {'id': key, 'type': 'synthetic', 'scope': scope,
        'data': {'recorded_label': 'λ', 'references': ['r2']}}
        for key in ('r1', 'r2', 'unrelated')}
    row = {'id': 'finding', 'check_id': 'unit.synthetic', 'provider': provider,
        'scope': scope, 'resource_id': 'r1', 'status': 'UNKNOWN',
        'evidence': {'references': ['r1', 'r1'], 'cluster_id': 'cluster-a'}}
    report = {'provider': provider, 'snapshot_id': 'checkpoint', 'created_at': 'time'}
    entry = {'provider': provider, 'target_scopes': [scope], 'captured_at': 100, 'expires_at': 200,
             'account_id': '123456789012', 'cluster_id': 'cluster-a', 'audience': 'synthetic'}
    entries = [] if access == 'none' else [entry if access == 'matching' else dict(entry, provider='other')]
    return report, inventory, row, entries


@pytest.mark.parametrize('provider', ['aws', 'gcp', 'azure', 'k8s'])
def test_fingerprints_depend_only_on_matching_provider_access(provider):
    values = {}
    for access in ('none', 'matching', 'other-provider'):
        report, inventory, row, entries = fixture(provider, access)
        original = copy.deepcopy((report, inventory, row, entries))
        values[access] = pipeline.review_fingerprints(report, inventory, [row],
            identity={'owner': 'synthetic', 'access_reference': 'sealed'}, entries=entries)['finding']
        assert (report, inventory, row, entries) == original
    assert values['other-provider'] == values['none'] != values['matching']


def test_references_are_recomputed_after_evidence_and_native_changes():
    report, inventory, row, entries = fixture('aws', 'matching')

    def fingerprint():
        return pipeline.review_fingerprints(report, inventory, [row], identity={}, entries=entries)

    first = fingerprint()
    row['evidence']['references'].append('r2')
    second = fingerprint()
    assert second != first
    inventory['r2']['data']['recorded_label'] = 'fresh'
    third = fingerprint()
    assert third != second
    entries[0]['expires_at'] += 1
    changed = fingerprint()
    assert changed != third
    entries[0]['captured_at'] += 1
    assert fingerprint() != changed


def test_prepared_helpers_preserve_mapped_resource_identity_and_duplicate_rows():
    report, inventory, row, _ = fixture('gcp', 'none')
    inventory['r1']['id'] = 'alias'
    refs = set(pipeline.referenced_strings([row]))
    expected = pipeline.review_context(report, inventory, [row])
    assert pipeline.review_context(report, inventory, [row], _references=refs) == expected
    document = pipeline.findings_document(report, [row, row], expected['resources'])
    assert pipeline.findings_document(report, [row, row], expected['resources'],
                                     _references=(refs, refs)) == document
    assert document['items'][0]['supporting_resources'] == []


def test_no_provider_access_still_validates_scope_row_shapes():
    with pytest.raises(AttributeError):
        pipeline.review_credentials([], 'aws', [None], {})
