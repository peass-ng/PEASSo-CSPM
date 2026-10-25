"""Small, scope-bound collection receipts for cross-resource review evidence."""

_STATUSES = frozenset(('collected', 'empty', 'partial', 'denied', 'unknown',
                       'malformed', 'timeout', 'not_collected'))
MAX_ENTRIES = 4096


def index(rows):
    """Index metadata only; never include native objects or provider error text."""
    result = {}
    if not isinstance(rows, list):
        return result
    for row in rows:
        if not isinstance(row, dict) or row.get('level') != 'collection':
            continue
        scope, kind, status = (row.get(key) for key in ('scope', 'type', 'status'))
        if (not all(isinstance(value, str) and 0 < len(value) <= 512
                    and not any(ord(char) < 32 for char in value)
                    for value in (scope, kind)) or not isinstance(status, str) or status not in _STATUSES):
            continue
        receipt = {'scope': scope, 'type': kind, 'status': status}
        count = row.get('resource_count')
        if type(count) is int and 0 <= count < 2**63:
            receipt['resource_count'] = count
        result.setdefault(scope, []).append(receipt)
    return result


def for_findings(by_scope, findings):
    """Share a bounded receipt list once per batch, keeping unknowns explicit."""
    scopes = {row.get('scope') for row in findings if isinstance(row.get('scope'), str)}
    scopes.add('*')
    rows, truncated = [], False
    for scope in sorted(scopes):
        entries = by_scope.get(scope, ())
        remaining = MAX_ENTRIES - len(rows)
        rows.extend(entries[:remaining])
        truncated = truncated or len(entries) > remaining
    return {'entries': rows, 'truncated': truncated} if rows or truncated else None
