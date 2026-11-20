"""Evidence-bound report compilation; generated prose cannot change native verdicts."""
import hashlib
import json
from typing import Annotated, Literal
from pydantic import Field
from .contracts import Strict

Text = Annotated[str, Field(min_length=1, max_length=12000, pattern=r'\S')]


class Reference(Strict):
    domain: Literal['findings', 'least_privilege', 'privesc_edges', 'actions']
    id: str = Field(min_length=1)


class Issue(Strict):
    title: str = Field(min_length=1, max_length=300, pattern=r'\S')
    kind: Literal['vulnerability', 'hardening', 'leaks', 'image_cves']
    severity: Literal['critical', 'high', 'medium', 'low', 'info']
    status: Literal['confirmed', 'needs_review']
    description: Text
    impact: Text
    recommendation: Text
    verification: Text
    references: list[Reference] = Field(min_length=1)


class Exclusion(Strict):
    reference: Reference
    reason: str = Field(min_length=1, max_length=1000, pattern=r'\S')


class FindingsReport(Strict):
    summary: Text
    issues: list[Issue] = Field(max_length=500)
    exclusions: list[Exclusion]
    limitations: list[Text]


def source_index(platform):
    """Only this trusted index can authorize references or required coverage."""
    from peaso.finding_types import annotate
    report = platform.get('report', {})
    result = []
    for row in report.get('findings', []):
        if row.get('status') not in ('FAIL', 'MANUAL', 'UNKNOWN', 'DENIED'):
            continue
        evidence = row.get('evidence') or {}
        check = row.get('check_id', '')
        kind = ('leaks' if evidence.get('secret_leaks') or annotate(row)['finding_type'] == 'detected_leaks'
                else 'image_cves' if ('selected_' in check and 'image' in check and 'vulnerabilit' in check
                    or evidence.get('Image') and isinstance(evidence.get('Vulnerabilities'), list))
                else None)
        result.append({'domain': 'findings', 'id': row['id'], 'kind': kind,
                       'confirmed': row.get('status') == 'FAIL', 'required': row.get('status') == 'FAIL'})
    for index, row in enumerate(platform.get('least_privilege', {}).get('items', [])):
        if row.get('suggestions') or row.get('exposures'):
            result.append({'domain': 'least_privilege', 'id': str(row.get('id', index)),
                           'kind': None, 'confirmed': False, 'required': True})
    for index, row in enumerate((report.get('graphs', {}).get('privesc') or {}).get('edges', [])):
        result.append({'domain': 'privesc_edges', 'id': str(row.get('id', index)),
                       'kind': None, 'confirmed': False, 'required': True})
    for action in platform.get('top_actions', []):
        result.append({'domain': 'actions', 'id': str(action['rank']), 'kind': None,
                       'confirmed': False, 'required': True})
    # The lossless reader can distinguish historic duplicate graph IDs by their
    # records, but report references deliberately identify the original edge.
    return list({(r['domain'], r['id']): r for r in result}.values())


def build(root, platform, findings, reviews, write_json):
    from .briefing import build as build_context
    build_context(root, platform, findings, reviews, write_json)
    write_json(root / 'report-sources.json', source_index(platform))
    write_json(root / 'analysis-status.json', platform.get('analysis_status', {}))
    write_json(root / 'top-actions.json', platform.get('top_actions', []))


def validate(data, sources):
    value = FindingsReport.model_validate(data).model_dump()
    known = {(r['domain'], r['id']): r for r in sources}
    required = {key for key, row in known.items() if row['required']}
    covered, seen_groups = set(), set()
    for issue in value['issues']:
        keys = [(r['domain'], r['id']) for r in issue['references']]
        if len(keys) != len(set(keys)) or any(key not in known for key in keys):
            raise ValueError('unknown_report_reference')
        if covered.intersection(keys):
            raise ValueError('duplicate_report_reference')
        covered.update(keys)
        kinds = {known[key]['kind'] for key in keys} - {None}
        if kinds and kinds != {issue['kind']}:
            raise ValueError('report_group_mismatch')
        if issue['kind'] in ('leaks', 'image_cves'):
            if issue['kind'] in seen_groups or not kinds:
                raise ValueError('duplicate_report_group')
            seen_groups.add(issue['kind'])
        if issue['status'] == 'confirmed' and not any(known[key]['confirmed'] for key in keys):
            raise ValueError('unconfirmed_report_issue')
        if issue['kind'] == 'hardening' and issue['severity'] != 'info':
            raise ValueError('hardening_report_severity')
        signature = json.dumps(sorted(keys), separators=(',', ':'))
        issue['id'] = 'report-' + hashlib.sha256(signature.encode()).hexdigest()[:24]
    for exclusion in value['exclusions']:
        ref = exclusion['reference']
        key = ref['domain'], ref['id']
        if key not in known or key in covered or known[key]['kind'] in ('leaks', 'image_cves') and known[key]['required']:
            raise ValueError('invalid_report_exclusion')
        covered.add(key)
    if not required <= covered:
        raise ValueError('report_coverage_mismatch')
    value['issues'].sort(key=lambda r: (['critical', 'high', 'medium', 'low', 'info'].index(r['severity']), r['id']))
    return dict(value, status='completed', source_count=len(known), covered_count=len(covered))
