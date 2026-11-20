"""Edit issues in a private workspace. Publication still requires server validation."""
import argparse
import fcntl
import json
from pathlib import Path
import sys
import uuid

from .findings_report import AgentIssue, Exclusion, SPECIAL_KINDS
from .output_validation import MAX_OUTPUT, private_file


def initial_draft(report):
    issues = {
        issue['id']: {key: issue[key] for key in AgentIssue.model_fields if key in issue}
        for issue in report.get('issues', [])
        if issue['kind'] not in SPECIAL_KINDS
    }
    exclusions = {}
    for row in report.get('exclusions', []):
        if not 100 <= len(row['reason'].strip()) <= 300:
            continue
        reference = row['reference']
        exclusions[json.dumps([reference['domain'], reference['id']])] = row
    return {'issues': issues, 'exclusions': exclusions}


def candidate(draft):
    return {'summary': 'Consolidated assessment findings.', 'issues': list(draft['issues'].values()),
            'exclusions': list(draft['exclusions'].values()), 'limitations': []}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('sources', 'list', 'get', 'add', 'update', 'delete', 'exclusions', 'exclude', 'include'))
    parser.add_argument('id', nargs='?')
    parser.add_argument('--offset', type=int, default=0)
    args = parser.parse_args()
    # Tool calls can arrive in parallel. Serialize updates to the local draft.
    with Path('report-draft.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        edit(parser, args)


def edit(parser, args):
    path = Path('report-draft.json')
    draft = json.loads(path.read_text())
    issues = draft['issues']
    sources = json.loads(Path('report-sources.json').read_text())
    by_alias = {source['source_id']: source for source in sources}

    def resolve(reference):
        if isinstance(reference, dict) and reference.keys() == {'source_id'}:
            source = by_alias.get(reference['source_id'])
            if not source:
                parser.error('Unknown short source ID')
            return {key: source[key] for key in ('domain', 'id')}
        return reference

    if args.operation in ('sources', 'list', 'exclusions'):
        rows = [{'id': ident, 'title': issue['title']} for ident, issue in issues.items()]
        if args.operation == 'sources':
            rows = [source for source in sources if not args.id or source['source_id'].startswith(args.id.upper())]
        if args.operation == 'exclusions':
            rows = list(draft['exclusions'].values())
        start = max(args.offset, 0)
        end = start + 25
        print(json.dumps({'items': rows[start:end], 'next_offset': end if end < len(rows) else None}))
        return
    if args.operation == 'get':
        if args.id not in issues:
            parser.error('Unknown draft issue ID')
        print(json.dumps(issues[args.id]))
        return
    if args.operation in ('update', 'delete') and args.id not in issues:
        parser.error('Unknown draft issue ID')
    if args.operation == 'delete':
        del issues[args.id]
    else:
        # Model-supplied documents arrive on stdin, with no shell evaluation.
        raw = sys.stdin.buffer.read(MAX_OUTPUT + 1)
        if len(raw) > MAX_OUTPUT:
            parser.error('Draft input exceeds the byte limit')
        document = json.loads(raw)
        if args.operation in ('exclude', 'include'):
            from .findings_report import Reference
            if args.operation == 'exclude':
                document['reference'] = resolve(document['reference'])
                item = Exclusion.model_validate(document)
            else:
                item = Reference.model_validate(resolve(document))
            reference = item.reference if args.operation == 'exclude' else item
            key = json.dumps([reference.domain, reference.id])
            if args.operation == 'exclude':
                draft['exclusions'][key] = item.model_dump()
            else:
                draft['exclusions'].pop(key, None)
        else:
            ident = args.id if args.operation == 'update' else uuid.uuid4().hex
            document['references'] = [resolve(reference) for reference in document['references']]
            issues[ident] = AgentIssue.model_validate(document).model_dump()
            if len(issues) > 500:
                parser.error('Too many draft issues')
    if len(json.dumps(draft).encode()) > MAX_OUTPUT:
        parser.error('Draft exceeds the byte limit')
    temporary = path.with_name('draft-' + uuid.uuid4().hex + '.json')
    try:
        private_file(temporary, draft)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    print(json.dumps({'saved': True, 'id': ident if args.operation in ('add', 'update') else args.id}))


if __name__ == '__main__':
    main()
