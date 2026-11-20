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
                    or evidence.get('Image') and isinstance(evidence.get('Vulnerabilities'), list)
                    or evidence.get('image_digest') and isinstance(evidence.get('severity_counts'), dict))
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


def _scoped_context(platform, sources):
    """Limit evidence to assigned observations and explicit nearby dependencies."""
    from .pipeline import referenced_strings
    from peaso.engine import hydrate_finding
    assigned = agent_sources(sources)
    required = {r['id'] for r in assigned if r['domain'] == 'findings' and r['required']}
    allowed = {r['id'] for r in assigned if r['domain'] == 'findings'}
    report = platform.get('report', {})
    actions = {r['id'] for r in assigned if r['domain'] == 'actions'}
    least_ids = {r['id'] for r in assigned if r['domain'] == 'least_privilege'}
    least = [row for i, row in enumerate(platform.get('least_privilege', {}).get('items', []))
             if str(row.get('id', i)) in least_ids]
    top = [row for row in platform.get('top_actions', []) if str(row['rank']) in actions]
    network_review = platform.get('network_review') or {}
    network_ids = {r['id'] for r in network_review.get('findings', [])}
    selected = [hydrate_finding(row, report.get('check_frameworks'), report.get('check_meta'),
                report.get('check_meta_encoding'), report.get('remediation_templates'))
                for row in report.get('findings', []) if row['id'] in required | network_ids]
    paths = (report.get('graphs', {}).get('privesc') or {})
    inventory = platform.get('inventory', [])
    universe = {row.get(key) for row in inventory for key in ('id', 'native_id') if isinstance(row.get(key), str)}
    for graph in report.get('graphs', {}).values():
        if isinstance(graph, dict):
            universe.update(row['id'] for kind in ('nodes', 'edges') for row in graph.get(kind, []) if isinstance(row.get('id'), str))
    def references(value):
        return set(referenced_strings(value)) & universe
    roots = references([selected, least, top, paths])
    # Conditional findings on the same affected assets can explain a limitation.
    for row in report.get('findings', []):
        if row['id'] in allowed and row['id'] not in required | network_ids and row.get('resource_id') in roots:
            selected.append(hydrate_finding(row, report.get('check_frameworks'), report.get('check_meta'),
                            report.get('check_meta_encoding'), report.get('remediation_templates')))
    roots.update(references(selected))
    related = []
    graphs = {'privesc': paths}
    # Two explicit relationship/dependency hops; unrelated inventory stays out.
    for _ in range(2):
        related = [row for row in inventory if row.get('id') in roots or row.get('native_id') in roots]
        roots.update(references(related))
        for name in ('iam', 'network'):
            graph = report.get('graphs', {}).get(name) or {}
            nodes = [row for row in graph.get('nodes', []) if references(row) & roots]
            ids = {row['id'] for row in nodes}
            edges = [row for row in graph.get('edges', []) if row.get('source') in ids or row.get('target') in ids or row.get('id') in roots]
            roots.update(references([nodes, edges]))
            graphs[name] = {**{k: v for k, v in graph.items() if k not in ('nodes', 'edges')}, 'nodes': nodes, 'edges': edges}
    # Include edge endpoints and resources reached by the final dependency hop.
    for name in ('iam', 'network'):
        graph = report.get('graphs', {}).get(name) or {}
        edges = graphs[name]['edges']
        ids = {row.get(key) for row in edges for key in ('source', 'target')}
        graphs[name]['nodes'] = [row for row in graph.get('nodes', []) if row.get('id') in ids or row.get('id') in roots]
        graphs[name].update(context_restricted=True, total_nodes=len(graphs[name]['nodes']), total_edges=len(edges))
    roots.update(references(graphs))
    related = [row for row in inventory if row.get('id') in roots or row.get('native_id') in roots]
    selected_ids = {row['id'] for row in selected}
    selected_checks = {row.get('check_id') for row in selected}
    scopes = {row.get('scope') for row in selected + related} | {'*'}
    kinds = {row.get('type') for row in related}
    gaps = [row for row in report.get('coverage', []) if str(row.get('status', '')).upper() in
            {'DENIED', 'UNKNOWN', 'PARTIAL', 'ERROR', 'TIMEOUT', 'NOT_COLLECTED', 'MALFORMED'} and
            (row.get('check_id') in selected_checks or row.get('scope') in scopes and row.get('type') in kinds)]
    context_report = {key: report[key] for key in ('provider', 'snapshot_id', 'created_at', 'schema_version',
                      'scopes', 'check_meta_encoding', 'remediation_templates') if key in report}
    context_report.update(findings=selected, graphs=graphs, coverage=gaps)
    for key in ('check_meta', 'check_frameworks', 'remediation_templates'):
        if isinstance(report.get(key), dict):
            context_report[key] = {k: v for k, v in report[key].items() if k in selected_checks}
    snapshot = platform.get('snapshot_context') or {}
    snapshot_context = {key: snapshot[key] for key in ('provider', 'snapshot_id', 'created_at', 'scopes', 'schema_version') if key in snapshot}
    snapshot_context['metadata'] = {key: value for key, value in (snapshot.get('metadata') or {}).items()
                                    if key in ('input_mode', 'requested_scopes')}
    scoped = {'report': context_report, 'inventory': related, 'snapshot_context': snapshot_context,
              'least_privilege': {'items': least, 'total': len(least)}, 'top_actions': top,
              'network_review': network_review, 'analysis_status': platform.get('analysis_status', {})}
    return scoped, [r for r in assigned if r['domain'] != 'findings' or r['id'] in selected_ids]


def build(root, platform, findings, reviews, write_json):
    from .briefing import build as build_context
    scoped, assigned = _scoped_context(platform, source_index(platform))
    identifiers = {r['id'] for r in assigned if r['domain'] == 'findings'}
    def write_context(path, value):
        if path.name == 'platform.json':
            sections = value.get('sections', {})
            value = dict(value, sections={key: rows[:12] for key, rows in sections.items()},
                section_totals={key: len(rows) for key, rows in sections.items()},
                reading_notes=[
                    'Each section previews up to 12 cases. Read remaining groups with context.py list decision_SECTION; continue next_offset until null.',
                    'Detailed evidence is available through targeted local lookups. Missing facts remain uncertain.'])
            value['data_index'] = dict(value.get('data_index', {}),
                semantics='Evidence is scoped to assigned findings and their related dependencies.')
        write_json(path, value)
    build_context(root, scoped, [row for row in findings if row['id'] in identifiers],
                  [row for row in reviews if row['finding_id'] in identifiers], write_context)
    write_json(root / 'report-sources.json', assigned)
    write_json(root / 'analysis-status.json', scoped['analysis_status'])
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
