"""Source-backed reporting of affected units and scanner benchmarks."""
import re

_READ_ONLY_ROOT = 'aws.b.ecs.all_readonly_roots'
_RECOVERY_RETENTION = 'aws.c2b.backup.recovery_point_retention_35'
_NUMERIC_TASK_SCOPE = re.compile(
    r'\b\d+\s+(?:(?:[a-z]+[ -]){0,5})task[ -]definition', re.IGNORECASE)
_RETENTION_BENCHMARK = re.compile(r'\b(?:35|thirty[ -]five)[ -]+days?\b', re.IGNORECASE)


def observation(check, status, scope, asset, evidence):
    if status != 'FAIL':
        return {}
    if check == _READ_ONLY_ROOT and scope and asset:
        return {'writable_task_definitions': [[scope, asset]]}
    if check == _RECOVERY_RETENTION:
        days = evidence.get('delete_after_days')
        return {'retention_benchmark': True,
                'short_retention_days': [days] if type(days) is int and 0 <= days < 35 else []}
    return {}


def consolidate(rows):
    facts = [row.get('source_facts', {}) for row in rows]
    task_definitions = sorted({tuple(unit) for fact in facts for unit in fact.get('writable_task_definitions', ())})
    output = {'writable_task_definitions': [list(unit) for unit in task_definitions]} if task_definitions else {}
    if any(fact.get('retention_benchmark') for fact in facts):
        output['retention_benchmark'] = True
        output['short_retention_days'] = sorted({days for fact in facts for days in fact.get('short_retention_days', ())})
    return output


def present(issue, facts):
    if not facts:
        return
    prose = ' '.join(issue[field] for field in ('title', 'description', 'impact', 'recommendation', 'verification'))
    statements = []
    if facts.get('writable_task_definitions'):
        if _NUMERIC_TASK_SCOPE.search(prose):
            raise ValueError('use_source_task_definition_count')
        count = len(facts['writable_task_definitions'])
        unit = 'task definition' if count == 1 else 'task definitions'
        statements.append(f'**{count} affected {unit}.** Each has at least one container with a writable root filesystem.')
    if facts.get('retention_benchmark'):
        if _RETENTION_BENCHMARK.search(prose):
            raise ValueError('use_source_retention_benchmark')
        days = facts['short_retention_days']
        observed = (f' Observed expiry settings are {days[0]} days.'
                    if len(days) == 1 else f' Observed expiry settings range from {days[0]} to {days[-1]} days.' if days else '')
        statements.append('**The scan applies a 35-day retention benchmark.**' + observed
                          + ' Confirm the owner’s required recovery window before changing retention.')
    description = '\n\n'.join([*statements, issue['description']])
    if len(description) > 2500:
        raise ValueError('leave_room_for_source_facts')
    issue.update(source_facts=facts, description=description)
