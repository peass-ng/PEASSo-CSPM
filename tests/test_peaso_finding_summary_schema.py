"""Shared finding-summary schema keeps archived fields, limits and privacy."""
from copy import deepcopy
import json
import random

import pytest

from tests.synthetic.benchmark_peaso_finding_pages import literal_summary
from peaso.storage.reports import finding_summary


@pytest.mark.parametrize('field, limit', [('title', 400), ('resource_id', 1000), ('scope', 500),
    ('remediation', 1000), ('service', 100), ('check_id', 200), ('category', 100), ('provider', 30),
    ('id', 2000), ('resource_name', 2000), ('finding_type', 2000)])
@pytest.mark.parametrize('extra', [0, 1, 20])
def test_all_length_boundaries_and_unicode_match_original(field, limit, extra):
    finding = {'id': 'native', 'secret_fingerprint': 'recorded', field: '雲' * (limit + extra),
        'evidence_summary': 'recorded setting', 'evidence': {'private': 'not a summary field'}}
    original = deepcopy(finding)
    actual = finding_summary(finding)
    assert json.dumps(actual) == json.dumps(literal_summary(finding))
    assert actual.get('summary_truncated', False) == bool(extra)
    assert finding == original
    assert 'evidence' not in actual


@pytest.mark.parametrize('fingerprint', [None, '', False, 0, [], 'recorded-fingerprint', 1])
def test_only_secret_summaries_admit_recorded_evidence_summary(fingerprint):
    finding = {'id': 'native', 'secret_fingerprint': fingerprint, 'evidence_summary': 'recorded value hidden',
        'secret_value': 'must not be included', 'evidence': {'secret': 'must not be included'}}
    actual = finding_summary(finding)
    assert actual == literal_summary(finding)
    assert ('evidence_summary' in actual) == bool(fingerprint)
    assert 'secret_value' not in actual and 'evidence' not in actual
    assert 'evidence_summary' not in finding_summary({'id': 'next', 'evidence_summary': 'not a secret row'})


def test_nested_approved_values_keep_original_shared_ownership_and_key_order():
    review = {'status': 'reviewed', 'items': ['recorded']}
    finding = {'finding_type': 'configuration', 'id': 'native', 'ai_review': review,
        'frameworks': ['archived'], 'linked_check_ids': ['archived.check'], 'detail_available': False}
    actual, expected = finding_summary(finding), literal_summary(finding)
    assert json.dumps(actual) == json.dumps(expected)
    assert actual['ai_review'] is review
    assert actual['frameworks'] is finding['frameworks']
    assert actual['detail_available'] is True


def test_random_archived_field_combinations_match_original():
    randomizer = random.Random(8433)
    fields = ['id', 'title', 'scope', 'category', 'resource_id', 'remediation', 'service', 'check_id',
        'provider', 'frameworks', 'status', 'secret_fingerprint', 'evidence_summary', 'finding_type',
        'ai_review', 'evidence', 'private_field', 'summary_truncated']
    values = [None, '', 0, True, ['archived'], {'nested': 'archived'}, 'ordinary', '雲' * 2200]
    for _ in range(200):
        finding = {field: randomizer.choice(values) for field in randomizer.sample(fields, randomizer.randrange(len(fields)))}
        assert json.dumps(finding_summary(finding)) == json.dumps(literal_summary(finding))
