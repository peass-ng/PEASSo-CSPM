"""A selected image cannot be clean while its native receipt records HIGH CVEs."""
from copy import deepcopy
import importlib.util
import os
import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks import k8s_selected_registry_image_review_20261021 as k8s_review

IDS = ['azure.review.aks.selected_pod_image_high_vulnerabilities', 'k8s.review.selected_registry_image_high_vulnerabilities']


@pytest.mark.parametrize('check_id', IDS)
@pytest.mark.parametrize('mutation,expected', [
    ('complete_clean', 'PASS'), ('high_finding_with_clean_status', 'FAIL'),
    ('critical_finding_with_clean_status', 'FAIL'), ('partial_positive', 'FAIL'),
    ('denied_collection', 'UNKNOWN'), ('missing_vulnerability_record', 'UNKNOWN'),
    ('stale_database', 'UNKNOWN'), ('foreign_finding_digest', 'UNKNOWN'),
    ('positive_with_unknown_status', 'FAIL'), ('malformed_positive', 'UNKNOWN'),
])
def test_selected_image_vulnerability_marker_is_consistent(check_id, mutation, expected):
    check = next(check for check in CHECKS if check.id == check_id)
    cases = CASES[check_id]
    name = 'fail' if mutation in {'partial_positive', 'positive_with_unknown_status'} else 'pass'
    item = deepcopy(cases[name])
    index = deepcopy(cases.get(name + '_index', cases.get('index', {})))
    marker = item['SelectedAksImage']['image'] if check_id.startswith('azure') else item['SelectedRegistryImage']
    if mutation in {'high_finding_with_clean_status', 'critical_finding_with_clean_status', 'foreign_finding_digest', 'malformed_positive'}:
        marker['vulnerability']['findings'] = [{
            'severity': 'BROKEN' if mutation == 'malformed_positive' else 'CRITICAL' if mutation.startswith('critical') else 'HIGH',
            'image_digest': 'sha256:' + 'f' * 64 if mutation == 'foreign_finding_digest' else marker['manifest_digest'],
            'vulnerability_id': 'CVE-2026-1001', 'package': 'synthetic-package', 'version': '1'}]
    elif mutation == 'partial_positive':
        marker['complete'] = False
        marker['vulnerability']['complete'] = False
        marker['vulnerability']['coverage_status'] = 'PARTIAL'
    elif mutation == 'positive_with_unknown_status': marker['vulnerability']['status'] = 'UNKNOWN'
    elif mutation == 'missing_vulnerability_record': marker['vulnerability'] = None
    elif mutation == 'stale_database': marker['vulnerability']['database']['fresh'] = False
    for envelope in index['collections'][check.kind]:
        for n, native in enumerate(envelope['items']):
            if native.get('id') == item['id']: envelope['items'][n] = deepcopy(item)
        if mutation == 'denied_collection': envelope['status'] = 'denied'
        elif mutation == 'partial_positive': envelope['status'] = 'partial'
    for row in index.get(check.kind, []):
        if row.get('data', {}).get('id') == item['id']: row['data'] = deepcopy(item)
    before_item, before_index = deepcopy(item), deepcopy(index)
    status, evidence = check.evaluate(item, index)
    assert status == expected, evidence
    if mutation in {'high_finding_with_clean_status', 'critical_finding_with_clean_status', 'positive_with_unknown_status'}:
        assert evidence['complete'] is False
        assert evidence['coverage_status'] == 'UNKNOWN'
        assert evidence['vulnerabilities'] == marker['vulnerability']['findings']
    assert item == before_item and index == before_index
