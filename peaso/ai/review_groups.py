"""Reviewer work planning: one agent item per group of equivalent findings.

Large scans repeat one control failure with identical evidence on many
resources (for example the same pod setting on every replica). Reviewing each
copy costs one agent item and the same reasoning every time. A group holds
findings of one check, scope and resource type whose evidence is identical
once each finding's own identifiers are replaced. Only the first finding of a
group is sent to the reviewer.

The copy rule is deliberately one-sided. A confirmed FAIL is the native
result, so it is copied to the other group members unchanged. Any other
verdict would overturn or weaken a native failure; the remaining members are
then reviewed individually, so every overturn is decided on the finding's own
document. Findings without evidence are never grouped.
"""
import json
import math

BATCH_SIZE = 40
_IDENTIFIERS = ('resource_id', 'native_resource_id', 'resource_name')
_PLACEHOLDER = '\x00'  # json.dumps escapes control characters, so never ambiguous.


def group_key(row):
    """Equivalence key, or None when the finding must be reviewed on its own."""
    check = row.get('check_id')
    evidence = row.get('evidence')
    if not isinstance(check, str) or evidence is None or evidence in ('', {}, []):
        return None
    try:
        text = json.dumps(evidence, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
    except (TypeError, ValueError):
        return None
    own = {row.get(key) for key in _IDENTIFIERS}
    for value in sorted((value for value in own if isinstance(value, str) and len(value) > 2),
                        key=len, reverse=True):
        text = text.replace(value, _PLACEHOLDER)
    scope = row.get('scope') if isinstance(row.get('scope'), str) else None
    kind = row.get('resource_type') if isinstance(row.get('resource_type'), str) else None
    return check, scope, kind, text


def plan(findings):
    """Return (representatives, members) preserving input order.

    members maps a representative finding id to the other findings of its
    group, in input order. Singleton groups have no entry.
    """
    first = {}
    representatives = []
    members = {}
    for row in findings:
        key = group_key(row)
        leader = first.get(key) if key is not None else None
        if leader is None:
            if key is not None:
                first[key] = row
            representatives.append(row)
        else:
            members.setdefault(leader['id'], []).append(row)
    return representatives, members


def chunks(rows, size=BATCH_SIZE):
    """Split into the fewest batches of at most size, with balanced lengths."""
    rows = list(rows)
    if not rows:
        return []
    count = math.ceil(len(rows) / size)
    base, extra = divmod(len(rows), count)
    out, start = [], 0
    for index in range(count):
        stop = start + base + (index < extra)
        out.append(rows[start:stop])
        start = stop
    return out


def expand(reviews, members):
    """Copy confirmed FAIL reviews to group members.

    Returns (rows, recheck): rows are the review rows for the representatives
    plus copied FAIL rows for their members; recheck lists the members whose
    representative was not confirmed and that need their own review.
    """
    rows, recheck = [], []
    for review in reviews:
        rows.append(review)
        group = members.get(review['finding_id'], ())
        if review['verdict'] == 'FAIL':
            rows.extend({'finding_id': row['id'], 'verdict': 'FAIL', 'reason': ''} for row in group)
        else:
            recheck.extend(group)
    return rows, recheck


def publish_reserve(remaining, remote):
    """Seconds kept before the scan deadline for the final report publication.

    The final publish follows the AI stage inside the same deadline; an AI
    stage that runs to the deadline leaves no time to publish its results.
    """
    remaining = max(0.0, remaining)
    if not remote:
        return min(10.0, remaining)
    return min(300.0, max(10.0, .25 * remaining))


def stage_limit(stage, remote):
    """Per-invocation ceiling; the shared scan budget still bounds every call.

    Holistic stages read the whole scan, so a fixed 600 s ceiling cut off large
    scans that still had budget left. Both stay below the 1800 s task limit.
    """
    if stage == 'priorities':
        return 1500 if remote else 150
    if stage == 'network':
        return 900 if remote else 150
    return 480 if remote else 120
