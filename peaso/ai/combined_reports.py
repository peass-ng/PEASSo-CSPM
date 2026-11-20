"""Compile immutable issue snapshots across assessments with complete provenance."""
import hashlib
import json
from collections import Counter
from typing import Annotated
from pydantic import Field
from .contracts import Strict
from .findings_report import Issue, Text, RISK, SPECIAL_KINDS

CombinedText = Annotated[str, Field(min_length=1, max_length=120000, pattern=r'\S')]


class Reference(Strict):
    report_id: str = Field(min_length=1)
    issue_id: str = Field(min_length=1)


class CombinedIssue(Issue):
    description: CombinedText
    impact: CombinedText
    recommendation: CombinedText
    verification: CombinedText
    references: list[Reference] = Field(min_length=1)


class CombinedReport(Strict):
    summary: Text
    issues: list[CombinedIssue] = Field(max_length=500)
    limitations: list[Text]


def version(report):
    value = {key: report.get(key) for key in ('status', 'issues', 'summary', 'limitations')}
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def validate(data, reports):
    value = CombinedReport.model_validate(data).model_dump()
    known = {(report['scan_id'], issue['id']): issue for report in reports for issue in report['issues']}
    if len(known) != sum(len(report['issues']) for report in reports):
        raise ValueError('combined_coverage_mismatch')
    covered = set()
    special = Counter()
    for issue in value['issues']:
        keys = [(ref['report_id'], ref['issue_id']) for ref in issue['references']]
        if len(keys) != len(set(keys)) or any(key not in known or key in covered for key in keys):
            raise ValueError('unknown_or_duplicate_combined_reference')
        source = [known[key] for key in keys]
        kinds = {row['kind'] for row in source}
        if (kinds & SPECIAL_KINDS and (len(kinds) != 1 or issue['kind'] not in kinds)
                or issue['kind'] in SPECIAL_KINDS and kinds != {issue['kind']}):
            raise ValueError('combined_special_kind_mismatch')
        if issue['kind'] in SPECIAL_KINDS:
            special[issue['kind']] += 1
        if issue['severity'] != min((row['severity'] for row in source), key=RISK.index):
            raise ValueError('combined_severity_mismatch')
        if (issue['kind'] == 'hardening' and (kinds != {'hardening'} or issue['severity'] != 'info')
                or kinds == {'hardening'} and issue['kind'] != 'hardening'):
            raise ValueError('hardening_report_severity')
        if issue['status'] == 'confirmed' and not any(row['status'] == 'confirmed' for row in source):
            raise ValueError('unconfirmed_report_issue')
        covered.update(keys)
    expected = {row['kind'] for row in known.values()} & SPECIAL_KINDS
    if set(special) != expected or any(count != 1 for count in special.values()):
        raise ValueError('combined_special_group_mismatch')
    if covered != set(known):
        raise ValueError('combined_coverage_mismatch')
    value['issues'].sort(key=lambda issue: RISK.index(issue['severity']))
    inherited = [text for report in reports for text in report.get('limitations', [])]
    value['limitations'] = list(dict.fromkeys(inherited + value['limitations']))
    return dict(value, status='completed', source_count=len(known), covered_count=len(covered))


def build(root, platform, write_json):
    reports = [{key: report[key] for key in ('scan_id', 'connector_name', 'provider', 'created_at', 'issues', 'limitations')}
               for report in platform['reports']]
    write_json(root / 'combined-reports.json', reports)
    write_json(root / 'platform.json', {'reports': [
        {key: report[key] for key in ('scan_id', 'connector_name', 'provider', 'created_at')} |
        {'limitation_count': len(report['limitations'])} |
        {'issues': [{key: issue[key] for key in ('id', 'title', 'kind', 'severity', 'status')} for issue in report['issues'][:12]], 'issue_count': len(report['issues'])}
        for report in reports]})


def main():
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=('list', 'get', 'report'))
    parser.add_argument('report_id', nargs='?')
    parser.add_argument('issue_id', nargs='?')
    parser.add_argument('--offset', type=int, default=0)
    parser.add_argument('--limit', type=int, default=20)
    parser.add_argument('--chars', type=int, default=4000)
    parser.add_argument('--field', choices=('description', 'impact', 'recommendation', 'verification', 'references', 'limitations'))
    args = parser.parse_args()
    if args.offset < 0 or not 1 <= args.limit <= 50 or not 1 <= args.chars <= 16000:
        parser.error('Invalid pagination')
    reports = json.loads(Path('combined-reports.json').read_text())
    if args.command == 'list':
        rows = [dict(report_id=report['scan_id'], **{k: issue[k] for k in
                ('id', 'title', 'kind', 'severity', 'status')}) for report in reports for issue in report['issues']]
        end = args.offset + args.limit
        print(json.dumps({'items': rows[args.offset:end], 'total': len(rows),
                          'next_offset': end if end < len(rows) else None}))
    else:
        issue = (next(({k: v for k, v in report.items() if k != 'issues'} for report in reports
                       if report['scan_id'] == args.report_id), None) if args.command == 'report' else
                 next((issue for report in reports if report['scan_id'] == args.report_id
                       for issue in report['issues'] if issue['id'] == args.issue_id), None))
        if issue is None:
            parser.error('Source issue not found')
        if args.field and args.field not in issue:
            parser.error('Field not found')
        text = json.dumps(issue[args.field] if args.field else issue)
        end = args.offset + args.chars
        print(json.dumps({'text': text[args.offset:end], 'next_offset': end if end < len(text) else None}))


if __name__ == '__main__':
    main()
