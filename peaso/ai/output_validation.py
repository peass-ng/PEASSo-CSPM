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
                inventory.append({key: row[key] for key in ('id', 'provider', 'scope', 'native_id', 'service') if key in row})
            return {'inventory': inventory, 'report': {'graphs': {'network': {
                'nodes': [{'id': row[0]} for row in rows('network_nodes')],
                'edges': [{'id': row[0]} for row in rows('network_edges')]}}}}
        if stage != 'priorities':
            raise InvalidAgentOutput('invalid_agent_stage')
        findings, reviews = [], []
        for ident, detail in rows('findings', True):
            value = json.loads(detail)
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
    if stage == 'network':
        validate_network(data, original)
    else:
        validate_actions(data, original['report'], original['reviews'], require_assessment=True)
    return data


def feedback(error):
    codes = {'review_coverage_mismatch', 'unknown_action_reference', 'action_rank_mismatch',
             'invalid_action', 'action_reference_missing', 'unknown_network_reference', 'duplicate_network_finding'}
    result = {'code': str(error) if str(error) in codes else 'invalid_output'}
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
