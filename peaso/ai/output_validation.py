"""Validate agent output against its original local evidence before upload.

The backend independently repeats all validation against its trusted report.
"""
import json
import os
from pathlib import Path
import re

MAX_ROWS = 200_000
MAX_OUTPUT = 8_000_000


class InvalidAgentOutput(ValueError):
    pass


def context(stage, root):
    if stage == 'report_combination':
        return json.loads((root / 'combined-reports.json').read_text())
    if stage == 'findings_report':
        return json.loads((root / 'report-sources.json').read_text())
    import sqlite3
    from contextlib import closing
    with closing(sqlite3.connect((root/'context.sqlite').as_uri() + '?mode=ro', uri=True)) as db:
        def rows(domain, detail=False):
            columns = 'id,detail' if detail else 'id'
            values = db.execute(f'SELECT {columns} FROM records WHERE domain=? LIMIT ?', (domain, MAX_ROWS + 1))
            for position, value in enumerate(values):
                if position >= MAX_ROWS:
                    raise InvalidAgentOutput('agent_context_limit')
                yield value
        if stage == 'network':
            inventory = []
            for ident, detail in rows('resources', True):
                row = json.loads(detail)
                if row == {'_exact_parts': True}:
                    row = json.loads(db.execute('SELECT summary FROM records WHERE domain=? AND id=?', ('resources', ident)).fetchone()[0])
                inventory.append({key: row[key] for key in ('id', 'provider', 'scope', 'native_id', 'service') if key in row})
            # Full source inventory can exceed the old projected-row ceiling.
            # The bounded SQLite transport already limits its bytes. Only index
            # metadata is needed to validate references, never native secrets.
            known = {row['id'] for row in inventory}
            column = 'summary' if any(row[1] == 'summary' for row in db.execute('PRAGMA table_info(records)')) else 'detail'
            for ident, summary in db.execute(f"SELECT id,{column} FROM records WHERE domain='source_resources'"):
                if ident not in known:
                    row = json.loads(summary)
                    inventory.append({key: row[key] for key in ('id', 'provider', 'scope', 'native_id', 'service') if key in row})
                    known.add(ident)
            return {'inventory': inventory, 'report': {'graphs': {'network': {
                'nodes': [{'id': row[0]} for row in rows('network_nodes')],
                'edges': [{'id': row[0]} for row in rows('network_edges')]}}}}
        if stage != 'priorities':
            raise InvalidAgentOutput('invalid_agent_stage')
        findings, reviews = [], []
        for ident, detail in rows('findings', True):
            value = json.loads(detail)
            if value == {'_exact_parts': True}:
                summary = json.loads(db.execute('SELECT summary FROM records WHERE domain=? AND id=?', ('findings', ident)).fetchone()[0])
                value = {'finding': summary, 'review': {'finding_id': ident, 'verdict': summary.get('verdict', summary.get('status')), 'reason': summary.get('review_reason', '')}}
            row = value['finding']
            findings.append({key: row[key] for key in ('id', 'status', 'category', 'resource_id') if key in row})
            if value.get('review'):
                reviews.append(value['review'])
        # The current action contract accepts finding references only. Resource
        # records remain available to the agent in SQLite, but are not needed
        # to validate its output and must not impose an unrelated row cap.
        return {'report': {'findings': findings}, 'reviews': reviews}


def validate(stage, data, original):
    from .contracts import validate_actions, validate_network
    if stage == 'report_combination':
        from .combined_reports import validate as validate_combined
        validate_combined(data, original)
    elif stage == 'findings_report':
        from .findings_report import validate as validate_report
        validate_report(data, original)
    elif stage == 'network':
        validate_network(data, original)
    else:
        validate_actions(data, original['report'], original['reviews'], require_assessment=True)
    return data


def feedback(error):
    codes = {'combined_coverage_mismatch', 'combined_special_kind_mismatch', 'combined_special_group_mismatch',
             'combined_severity_mismatch', 'unknown_or_duplicate_combined_reference', 'review_coverage_mismatch', 'unknown_action_reference', 'action_rank_mismatch',
             'invalid_action', 'action_reference_missing', 'unknown_network_reference', 'duplicate_network_finding', 'unknown_report_reference', 'duplicate_report_reference',
             'report_group_mismatch', 'duplicate_report_group', 'unconfirmed_report_issue',
             'hardening_report_severity', 'invalid_report_exclusion', 'report_coverage_mismatch', 'report_draft_incomplete',
             'unknown_or_duplicate_permission_review', 'use_source_task_definition_count',
             'missing_report_severity_evidence', 'unsupported_report_severity', 'unsupported_report_severity_source',
             'info_vulnerability_requires_hardening',
             'use_source_retention_benchmark', 'leave_room_for_source_facts'}
    result = {'code': str(error) if str(error) in codes else 'invalid_output'}
    if hasattr(error, 'missing'):
        result['missing_references'] = error.missing
    if getattr(error, 'duplicate_references', None):
        result['duplicate_references'] = error.duplicate_references
    if getattr(error, 'unknown_reference_count', 0):
        result['unknown_reference_count'] = error.unknown_reference_count
    if hasattr(error, 'errors'):
        errors = error.errors(include_input=False, include_context=False, include_url=False)
        result['fields'] = [{'type': row['type'], 'path': [part if isinstance(part, int) or
            isinstance(part, str) and re.fullmatch(r'[a-z_]{1,40}', part) else 'field'
            for part in row['loc']]} for row in errors[:8]]
    return result


def private_file(path, data):
    path = Path(path)
    path.unlink(missing_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(data, stream)
