"""Compile immutable issue snapshots across assessments with complete provenance."""
import hashlib
import json
from collections import Counter
from typing import Annotated
from pydantic import Field
from peaso.finding_subjects import ISOLATED_PROBLEMS, present_verified_scope, set_issue_subjects
from .contracts import Strict
from .findings_report import Issue, Text, SPECIAL_KINDS
from .report_severity import RISK, SeverityEvidence, validate_rating

CombinedText = Annotated[str, Field(min_length=1, max_length=120000, pattern=r'\S')]


class Reference(Strict):
    report_id: str = Field(min_length=1)
    issue_id: str = Field(min_length=1)


class CombinedIssue(Issue):
    description: Annotated[str, Field(min_length=1, max_length=2500, pattern=r'\S')]
    impact: CombinedText
    recommendation: CombinedText
    verification: CombinedText
    references: list[Reference] = Field(min_length=1)
    severity_evidence: SeverityEvidence[Reference] | None = None


class CombinedReport(Strict):
    summary: Text
    issues: list[CombinedIssue] = Field(max_length=500)
    limitations: list[Text]


def version(report):
    value = {key: report.get(key) for key in ('status', 'issues', 'summary', 'limitations')}
    if report.get('running_images'):
        value['running_images'] = report['running_images']
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


class CombinedReferenceCoverageError(ValueError):
    def __init__(self, missing, unknown, duplicates):
        def references(keys):
            return [{'report_id': report, 'issue_id': issue} for report, issue in sorted(keys)]

        self.missing = references(missing)
        self.duplicate_references = references(duplicates)
        self.unknown_reference_count = len(unknown)
        super().__init__('unknown_or_duplicate_combined_reference' if unknown or duplicates
                         else 'combined_coverage_mismatch')


def confirmed_issues(report):
    return [issue for issue in report.get('issues', ()) if issue.get('status') == 'confirmed']


def validate(data, reports):
    from .report_source_facts import consolidate, present
    value = CombinedReport.model_validate(data).model_dump()
    sources = [(report['scan_id'], issue['id'], issue) for report in reports for issue in confirmed_issues(report)]
    known = {(scan_id, issue_id): present_verified_scope(issue) for scan_id, issue_id, issue in sources}
    if len(known) != len(sources):
        raise ValueError('combined_coverage_mismatch')
    covered = Counter((ref['report_id'], ref['issue_id'])
                      for issue in value['issues'] for ref in issue['references'])
    missing = known.keys() - covered.keys()
    unknown = covered.keys() - known.keys()
    duplicates = {key for key, count in covered.items() if count > 1 and key in known}
    if missing or unknown or duplicates:
        raise CombinedReferenceCoverageError(missing, unknown, duplicates)
    special = Counter()
    for issue in value['issues']:
        keys = [(ref['report_id'], ref['issue_id']) for ref in issue['references']]
        source = [known[key] for key in keys]
        present(issue, consolidate(source))
        problems = {problem for row in source for problem in row.get('affected_problems', [])}
        isolated = ISOLATED_PROBLEMS.intersection(problems)
        if isolated and (len(problems) > 1 or any(not isolated.intersection(row.get('affected_problems', [])) for row in source)):
            raise ValueError('mixed_direct_subjects')
        set_issue_subjects(issue, (asset for row in source for asset in row.get('affected_subjects', [])),
                           incomplete=any('affected_subjects' not in row or row.get('affected_scope_incomplete')
                                          for row in source))
        issue['affected_problems'] = sorted(problems)
        recommendations = [dict(item, report_id=ref['report_id'], issue_id=ref['issue_id'])
                           for ref, row in zip(issue['references'], source)
                           for item in row.get('permission_recommendations', [])]
        if recommendations:
            issue['permission_recommendations'] = recommendations
        kinds = {row['kind'] for row in source}
        if (kinds & SPECIAL_KINDS and (len(kinds) != 1 or issue['kind'] not in kinds)
                or issue['kind'] in SPECIAL_KINDS and kinds != {issue['kind']}):
            raise ValueError('combined_special_kind_mismatch')
        if issue['kind'] in SPECIAL_KINDS:
            special[issue['kind']] += 1
            details = []
            for ref, original in zip(issue['references'], source):
                for row in original.get('special_details', []):
                    details.append(dict(row, report_id=ref['report_id'], issue_id=ref['issue_id']))
            if details:
                from .special_report_details import IMAGE_IMPACT, bind_running_images, prose
                if issue['kind'] == 'image_cves':
                    bind_running_images(details, (row for report in reports for row in report.get('running_images', ())))
                    issue['impact'] = IMAGE_IMPACT
                if issue['kind'] == 'leaks':
                    for index, row in enumerate(details, 1):
                        row['label'] = f'Leak {index}'
                issue['special_details'] = details
                issue['title'], issue['description'] = prose(issue['kind'], details)
        highest_source = min(RISK.index(row['severity']) for row in source)
        if issue['kind'] == 'image_cves':
            from .special_report_details import image_report_severity
            issue['severity'] = image_report_severity(RISK[highest_source])
        combined_severity = RISK.index(issue['severity'])
        if (issue['kind'] != 'image_cves' and (combined_severity < highest_source
                or issue['kind'] in SPECIAL_KINDS and combined_severity != highest_source)):
            raise ValueError('combined_severity_mismatch')
        confirmed_vulnerability = any(row['kind'] == 'vulnerability' and row['status'] == 'confirmed'
                                      for row in source)
        if (issue['kind'] == 'hardening' and (issue['severity'] != 'info'
                or any(row['kind'] == 'vulnerability' and row.get('severity_evidence') for row in source))
                or kinds == {'hardening'} and issue['kind'] != 'hardening'):
            raise ValueError('hardening_report_severity')
        if issue['status'] != 'confirmed' or (issue['kind'] == 'vulnerability' and not confirmed_vulnerability):
            raise ValueError('unconfirmed_report_issue')
        evidence = validate_rating(issue)
        if evidence:
            ref = evidence['reference']
            key = (ref['report_id'], ref['issue_id'])
            original = known.get(key)
            prior_evidence = original.get('severity_evidence') if original else None
            assets = set(original.get('affected_assets', ())) if original else set()
            if prior_evidence:
                # The original reference bound the exact scope before labels
                # were disambiguated across all of that report's subjects.
                assets.update(item['native_id'] for item in original.get('affected_subjects', ())
                              if item['kind'] == 'resource' and item['native_id'] == prior_evidence['asset'])
            if (key not in keys or original['kind'] != 'vulnerability' or original['status'] != 'confirmed'
                    or combined_severity < RISK.index(original['severity'])
                    or evidence['asset'] not in assets):
                raise ValueError('unsupported_report_severity_source')
            if prior_evidence and any(evidence[field] != prior_evidence[field] for field in (
                    'asset', 'consequence', 'prerequisites', 'impact_level',
                    'internet_reachable', 'prerequisites_supported')):
                raise ValueError('unsupported_report_severity_source')
    expected = {row['kind'] for row in known.values()} & SPECIAL_KINDS
    if set(special) != expected or any(count != 1 for count in special.values()):
        raise ValueError('combined_special_group_mismatch')
    value['issues'].sort(key=lambda issue: RISK.index(issue['severity']))
    inherited = [text for report in reports for text in report.get('limitations', [])]
    value['limitations'] = list(dict.fromkeys(inherited + value['limitations']))
    return dict(value, status='completed', source_count=len(known), covered_count=len(covered))


def build(root, platform, write_json):
    fields = ('scan_id', 'connector_name', 'provider', 'created_at', 'limitations')
    reports = [{key: report[key] for key in fields} | {'issues': confirmed_issues(report)}
               for report in platform['reports']]
    for report, original in zip(reports, platform['reports']):
        report['issues'] = [present_verified_scope(issue) for issue in report['issues']]
        if original.get('running_images'):
            report['running_images'] = original['running_images']
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
    parser.add_argument('--field', choices=('description', 'impact', 'recommendation', 'verification',
                                           'references', 'severity_evidence', 'limitations'))
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
