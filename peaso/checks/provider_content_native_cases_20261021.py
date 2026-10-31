"""Captured offline native cases for the selected ACR and Artifact Registry checks.

Runtime registration loads only package data; native snapshots were captured by
focused offline collector fixtures and are verified by evaluator tests.
"""
from copy import deepcopy
import json
from pathlib import Path

IDS = frozenset(('azure.review.acr.selected_image_high_critical_vulnerabilities', 'gcp.review.artifact_image.selected_image_vulnerabilities'))
REQUIRED = frozenset(('pass', 'pass_index', 'fail', 'fail_index',
                      'unknown', 'unknown_index', 'missing', 'missing_index'))


def native_case(check_id):
    if check_id not in IDS:
        raise ValueError('unrecognized provider native case')
    raw = Path(__file__).with_suffix('.json').read_bytes()
    cases = json.loads(raw)
    if set(cases) != IDS or any(not isinstance(case, dict) or not REQUIRED <= set(case)
                                 for case in cases.values()):
        raise RuntimeError('Provider native reproduction IDs or cases changed')
    return deepcopy(cases[check_id])
