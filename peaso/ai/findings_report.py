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


class AgentIssue(Issue):
    kind: Literal['vulnerability', 'hardening']


class AgentReport(FindingsReport):
    issues: list[AgentIssue] = Field(max_length=500)


SPECIAL_KINDS = {'leaks', 'image_cves'}
RISK = ['critical', 'high', 'medium', 'low', 'info']


def _issue_id(references):
    signature = json.dumps(sorted((r['domain'], r['id']) for r in references), separators=(',', ':'))
    return 'report-' + hashlib.sha256(signature.encode()).hexdigest()[:24]


def agent_sources(sources):
    return [row for row in sources if row['kind'] not in SPECIAL_KINDS]


def pregenerate(platform, sources=None):
    """Create fixed leak/CVE findings before any model call, using no secret values."""
    from peaso.engine import hydrate_finding
    sources = source_index(platform) if sources is None else sources
    native = platform.get('report', {})
    findings = {row['id']: row for row in native.get('findings', [])}
    issues, exclusions = [], []
    covered = 0
    for kind in ('leaks', 'image_cves'):
        members = [row for row in sources if row['kind'] == kind]
        positive = [row for row in members if row['domain'] == 'findings' and row['confirmed']]
        unresolved = [row for row in members if row['domain'] == 'findings' and not row['confirmed']]
        for row in unresolved:
            exclusions.append({'reference': {'domain': row['domain'], 'id': row['id']},
                'reason': 'No confirmed positive observation; retain the native coverage or review state.'})
        covered += len(members)
        if not positive:
            continue
        rows = [hydrate_finding(findings[row['id']], native.get('check_frameworks'), native.get('check_meta'),
                               native.get('check_meta_encoding'), native.get('remediation_templates')) for row in positive]
        refs = [{'domain': row['domain'], 'id': row['id']} for row in
                positive + [row for row in members if row['domain'] == 'actions']]
        scopes = sorted({str(row.get('scope')) for row in rows if row.get('scope')})
        assets = sorted({str(row.get('native_resource_id') or row.get('resource_id')) for row in rows
                         if row.get('native_resource_id') or row.get('resource_id')})
        locations = '\n'.join('- ' + asset for asset in assets)
        # Complete evidence remains reachable through every original reference;
        # bound only the readable preview, never the underlying membership.
        if len(locations) > 8000:
            locations = locations[:8000] + '\nAdditional locations are in the supporting check results.'
        severity = min((row.get('severity', 'high') for row in rows), key=lambda v: RISK.index(v) if v in RISK else 2)
        if severity not in RISK:
            severity = 'high'
        leaks = kind == 'leaks'
        issues.append({'id': _issue_id(refs), 'title': 'Detected credential and secret leaks' if leaks else
                       'Container images contain known-vulnerable packages', 'kind': kind,
            'severity': severity, 'status': 'confirmed',
            'description': (f'All {len(positive)} positive source check results are consolidated in this finding. '
                'These are observations, not distinct vulnerability counts. '
                f'Affected scopes: {", ".join(scopes) or "See supporting evidence"}.\n\n'
                f'Affected resources:\n{locations or "See supporting check results."}\n\n' +
                ('Supporting evidence retains safe leak locations and detector details; matched values are omitted from this report.' if leaks else
                 'Supporting evidence retains immutable image digests, CVEs, package versions, fixed versions and coverage details.')),
            'impact': ('Detected secrets may enable access within their permissions if still valid. Detection alone does not establish credential validity or misuse.' if leaks else
                       'Affected package versions match vulnerability advisories. Source severity is retained; runtime reachability, deployment status and exploitability require separate review.'),
            'recommendation': ('Review each detected location, rotate or revoke affected credentials, remove exposed copies, and restrict access to the affected configuration, artifacts or logs.' if leaks else
                               'Review each affected immutable image and vendor applicability, update affected packages or base images to compatible patched versions, rebuild and redeploy, and document advisories without an available fix.'),
            'verification': ('Rescan the affected sources, confirm exposed credentials are retired, and verify replacement credentials work only for their intended consumers.' if leaks else
                             'Rescan rebuilt immutable digests, confirm affected package versions are addressed or documented as not affected, and verify intended workloads use the rebuilt images.'),
            'references': refs})
    return {'summary': 'Pre-generated findings from captured scan evidence.', 'issues': issues,
            'exclusions': exclusions, 'limitations': [],
            'status': 'partial' if agent_sources(sources) else 'completed',
            'source_count': len(sources), 'covered_count': covered}


def complete(data, sources, prebuilt):
    """Append validated model findings without accepting edits to fixed findings."""
    value = validate(data, agent_sources(sources))
    value['issues'] = sorted(prebuilt['issues'] + value['issues'], key=lambda r: (RISK.index(r['severity']), r['id']))
    value['exclusions'] = prebuilt['exclusions'] + value['exclusions']
    value['source_count'] = len(sources)
    value['covered_count'] += prebuilt['covered_count']
    if prebuilt['issues']:
        value['summary'] = f"{len(prebuilt['issues'])} pre-generated findings and {len(value['issues']) - len(prebuilt['issues'])} compiled findings. " + value['summary']
    return value


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
    finding_sources = {row['id']: row for row in result if row['domain'] == 'findings'}
    for action in platform.get('top_actions', []):
        supporting = [finding_sources.get(ident) for ident in action.get('finding_ids', [])]
        kinds = {row['kind'] for row in supporting if row}
        kind = (next(iter(kinds)) if len(kinds) == 1 and kinds <= SPECIAL_KINDS and
                supporting and all(row and row['confirmed'] for row in supporting) else None)
        result.append({'domain': 'actions', 'id': str(action['rank']), 'kind': kind,
                       'confirmed': False, 'required': True})
    # The lossless reader can distinguish historic duplicate graph IDs by their
    # records, but report references deliberately identify the original edge.
    return list({(r['domain'], r['id']): r for r in result}.values())


def build(root, platform, findings, reviews, write_json):
    from .briefing import build as build_context
    sources = source_index(platform)
    assigned = agent_sources(sources)
    reserved = {row['id'] for row in sources if row['domain'] == 'findings' and row['kind'] in SPECIAL_KINDS}
    action_ids = {row['id'] for row in assigned if row['domain'] == 'actions'}
    def scoped_report(report):
        return dict(report, findings=[row for row in report.get('findings', []) if row['id'] not in reserved])
    scoped = dict(platform, report=scoped_report(platform.get('report', {})),
                  top_actions=[row for row in platform.get('top_actions', []) if str(row['rank']) in action_ids])
    if 'source_report' in scoped:
        scoped['source_report'] = scoped_report(scoped['source_report'])
    build_context(root, scoped, [row for row in findings if row['id'] not in reserved],
                  [row for row in reviews if row['finding_id'] not in reserved], write_json)
    write_json(root / 'report-sources.json', assigned)
    write_json(root / 'analysis-status.json', platform.get('analysis_status', {}))
    write_json(root / 'top-actions.json', scoped['top_actions'])


def validate(data, sources):
    value = AgentReport.model_validate(data).model_dump()
    known = {(r['domain'], r['id']): r for r in agent_sources(sources)}
    required = {key for key, row in known.items() if row['required']}
    covered = set()
    for issue in value['issues']:
        keys = [(r['domain'], r['id']) for r in issue['references']]
        if len(keys) != len(set(keys)) or any(key not in known for key in keys):
            raise ValueError('unknown_report_reference')
        if covered.intersection(keys):
            raise ValueError('duplicate_report_reference')
        covered.update(keys)
        if issue['status'] == 'confirmed' and not any(known[key]['confirmed'] for key in keys):
            raise ValueError('unconfirmed_report_issue')
        if issue['kind'] == 'hardening' and issue['severity'] != 'info':
            raise ValueError('hardening_report_severity')
        issue['id'] = _issue_id(issue['references'])
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
