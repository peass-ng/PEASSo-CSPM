"""Exact-scope collection coverage required before native-final substitution."""


def complete_scopes(coverage, check_ids):
    """Return check/scope pairs whose evaluation and dependencies are complete.

    A FAIL from an observed item can coexist with a partial collection. In
    particular, a field omitted from a partial representation can be mistaken
    for a documented default, so row status alone is not sufficient here.
    """
    if not isinstance(coverage, list) or not check_ids:
        return frozenset()
    from peaso.checks import CHECKS

    definitions = {check.id: check for check in CHECKS if check.id in check_ids}
    if len(definitions) != len(check_ids):
        return frozenset()
    statuses = {}
    for entry in coverage:
        if not isinstance(entry, dict) or not isinstance(entry.get('scope'), str):
            continue
        level = entry.get('level')
        if level == 'check' and entry.get('check_id') in check_ids:
            key = ('check', entry['check_id'], entry['scope'])
        elif level == 'collection' and isinstance(entry.get('type'), str):
            key = ('collection', entry['type'], entry['scope'])
        else:
            continue
        statuses.setdefault(key, []).append(entry.get('status'))
    complete = set()
    for (level, check_id, scope), values in statuses.items():
        if level != 'check' or values != ['evaluated']:
            continue
        definition = definitions[check_id]
        dependencies = definition.dependencies
        if (dependencies and
                statuses.get(('collection', definition.kind, scope)) == ['collected'] and
                all(statuses.get(('collection', kind, scope)) in (['collected'], ['empty'])
                    for kind in dependencies)):
            complete.add((check_id, scope))
    return frozenset(complete)
