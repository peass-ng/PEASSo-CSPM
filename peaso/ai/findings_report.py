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
    description: Annotated[str, Field(min_length=1, max_length=2500, pattern=r'\S')]
    impact: Text
    recommendation: Text
    verification: Text
    references: list[Reference] = Field(min_length=1)


class Exclusion(Strict):
    reference: Reference
    reason: str = Field(min_length=100, max_length=300, pattern=r'\S')


class FindingsReport(Strict):
    summary: Text
    issues: list[Issue] = Field(max_length=500)
    exclusions: list[Exclusion]
    limitations: list[Text]


class AgentIssue(Issue):
    kind: Literal['vulnerability', 'hardening']
    manual_affected_assets: list[Annotated[str, Field(min_length=1, max_length=500, pattern=r'\S')]] = Field(default_factory=list, max_length=200)
    permission_review_ids: list[Annotated[str, Field(pattern=r'^PR-[0-9a-f]{12}$')]] = Field(default_factory=list)


class AgentReport(FindingsReport):
    issues: list[AgentIssue] = Field(max_length=500)


SPECIAL_KINDS = {'leaks', 'image_cves'}
RISK = ['critical', 'high', 'medium', 'low', 'info']


def _issue_id(references):
    signature = json.dumps(sorted((r['domain'], r['id']) for r in references), separators=(',', ':'))
    return 'report-' + hashlib.sha256(signature.encode()).hexdigest()[:24]


def agent_sources(sources):
    return [row for row in sources if row['kind'] not in SPECIAL_KINDS]


def must_include_in_issue(source):
    return source['domain'] == 'findings' and source['confirmed']


def pregenerate(platform, sources=None):
    """Create fixed leak/CVE findings before any model call, using no secret values."""
    from peaso.engine import hydrate_finding
    sources = source_index(platform) if sources is None else sources
    from .special_report_details import (IMAGE_IMPACT, bind_running_images, image_details, image_report_severity,
                                         leak_details, prose, running_images)
    native = platform.get('report', {})
    runtime = running_images(platform.get('inventory', ()))
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
        severity = min((row.get('severity', 'high') for row in rows), key=lambda v: RISK.index(v) if v in RISK else 2)
        if severity not in RISK:
            severity = 'high'
        leaks = kind == 'leaks'
        details = leak_details(rows) if leaks else image_details(rows)
        if not leaks:
            severity = image_report_severity(severity)
            bind_running_images(details, runtime)
        title, description = prose(kind, details)
        detail_assets = {asset for row in details for asset in
                         (row['assets'] if leaks else [row['asset']]) if asset}
        # Detailed image rows and leak locations carry the real assets, while
        # some native finding records have a synthetic finding-level resource.
        detail_source_ids = {ident for row in details for ident in row['finding_ids']
                             if (row['assets'] if leaks else row['asset'])}
        source_assets = {asset for source in positive for asset in source.get('assets', [])
                         if source['id'] not in detail_source_ids or asset in detail_assets}
        issues.append({'id': _issue_id(refs), 'title': title, 'kind': kind,
            'severity': severity, 'status': 'confirmed', 'description': description,
            'special_details': details,
            'impact': ('Detected secrets may enable access within their permissions if still valid. Detection alone does not establish credential validity or misuse.' if leaks else
                       IMAGE_IMPACT),
            'recommendation': ('Review each detected location, rotate or revoke affected credentials, remove exposed copies, and restrict access to the affected configuration, artifacts or logs.' if leaks else
                               'Review each affected immutable image and vendor applicability, update affected packages or base images to compatible patched versions, rebuild and redeploy, and document advisories without an available fix.'),
            'verification': ('Rescan the affected sources, confirm exposed credentials are retired, and verify replacement credentials work only for their intended consumers.' if leaks else
                             'Rescan rebuilt immutable digests, confirm affected package versions are addressed or documented as not affected, and verify intended workloads use the rebuilt images.'),
            'references': refs,
            'affected_assets': sorted(detail_assets | source_assets)})
    return {'summary': 'Pre-generated findings from captured scan evidence.', 'issues': issues,
            'exclusions': exclusions, 'limitations': [],
            'status': 'partial' if agent_sources(sources) else 'completed',
            'source_count': len(sources), 'covered_count': covered,
            **({'running_images': runtime} if runtime else {})}


def complete(data, sources, prebuilt, previous_report=None):
    """Append validated model findings without accepting edits to fixed findings."""
    value = validate({key: item for key, item in data.items() if key != 'draft_issue_ids'}, agent_sources(sources))
    previous_ids = {issue['id'] for issue in (previous_report or {}).get('issues', [])
                    if issue['kind'] not in SPECIAL_KINDS}
    edits = data.get('draft_issue_ids', {})
    claimed = set()
    for issue in value['issues']:
        previous_id = edits.get(issue['id'])
        if isinstance(previous_id, str) and previous_id in previous_ids and previous_id not in claimed:
            if previous_id == issue['id'] or all(other['id'] != previous_id for other in value['issues']):
                issue['id'] = previous_id
                claimed.add(previous_id)
    assets = {(row['domain'], row['id']): row.get('assets', []) for row in sources}
    recommendations = {row['id']: row.get('permission_recommendations', []) for row in sources
                       if row['domain'] == 'least_privilege'}
    for issue in value['issues']:
        issue['affected_assets'] = sorted({asset for ref in issue['references']
            for asset in assets.get((ref['domain'], ref['id']), [])})
        if issue['permission_review_ids']:
            linked_reviews = {item['review_id']: item for ref in issue['references'] if ref['domain'] == 'least_privilege'
                              for item in recommendations.get(ref['id'], [])}
            issue['permission_recommendations'] = [linked_reviews[ident] for ident in issue['permission_review_ids']]
        else:
            del issue['permission_review_ids']
        if 'manual_affected_assets' in issue:
            issue['manual_affected_assets'] = sorted({asset.strip() for asset in issue['manual_affected_assets']}
                                                     - set(issue['affected_assets']))
    value['issues'] = sorted(prebuilt['issues'] + value['issues'], key=lambda r: (RISK.index(r['severity']), r['id']))
    value['exclusions'] = prebuilt['exclusions'] + value['exclusions']
    value['source_count'] = len(sources)
    value['covered_count'] += prebuilt['covered_count']
    if prebuilt.get('running_images'):
        value['running_images'] = prebuilt['running_images']
    if prebuilt['issues']:
        value['summary'] = f"{len(prebuilt['issues'])} pre-generated findings and {len(value['issues']) - len(prebuilt['issues'])} compiled findings. " + value['summary']
    return value


def source_index(platform):
    """Only this trusted index can authorize references or required coverage."""
    from peaso.finding_types import annotate
    from .report_source_facts import observation
    report = platform.get('report', {})
    result = []
    network_ids = {row['id'] for row in (platform.get('network_review') or {}).get('findings', [])}
    inventory = {row['id']: row for row in platform.get('inventory', []) if row.get('id')}
    def asset(ident):
        if isinstance(ident, str):
            return inventory.get(ident, {}).get('native_id') or ident

    def graph_assets(node):
        attrs = node.get('attrs') or {}
        members = node.get('members')
        if isinstance(members, list) and members:
            return [asset(member) for member in members]
        return [node.get('native_id') or attrs.get('arn') or attrs.get('email') or
                asset(node.get('resource_id')) or asset(node.get('id'))]

    meta = report.get('check_meta') or {}
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
        identifiers = [row.get('native_resource_id') or asset(row.get('resource_id'))]
        if identifiers[0] == 'ec2-regional-settings' and report.get('provider') == 'aws' and row.get('scope'):
            identifiers[0] = f"{row['scope']}/ec2-regional-settings"
        linked = evidence.get('resource_ids', [])
        if isinstance(linked, list):
            identifiers.extend(asset(ident) for ident in linked if isinstance(ident, str) and
                               (ident in inventory or evidence.get('source') == 'ai_network_review'))
        category = row.get('category') or (meta.get(check) or {}).get('category')
        if row['id'] in network_ids:
            category = 'network'
        if category == 'privesc':
            for target in evidence.get('targets', []):
                if isinstance(target, dict):
                    identifiers.extend(graph_assets(target))
        facts = observation(check, row.get('status'), row.get('scope'), identifiers[0], evidence)
        result.append({'category': category, 'assets': sorted({ident for ident in identifiers if isinstance(ident, str) and ident}),
                       **({'source_facts': facts} if facts else {}),
                       'domain': 'findings', 'id': row['id'], 'kind': kind,
                       'actionable': row.get('status') == 'FAIL',
                       'confirmed': row.get('status') == 'FAIL', 'required': row.get('status') == 'FAIL' or category in ('hardening', 'exposure', 'network')})
    for index, row in enumerate(platform.get('least_privilege', {}).get('items', [])):
        if row.get('suggestions') or row.get('exposures'):
            reviews = [dict(item, principal=row['principal'], provider=row.get('provider', report.get('provider')))
                       for item in row.get('suggestions', []) if item.get('confidence') in
                       {'provider_recommendation', 'tracked_without_observed_use'} and row.get('principal')]
            for review in reviews:
                fingerprint = json.dumps(review, sort_keys=True, separators=(',', ':')).encode()
                review['review_id'] = 'PR-' + hashlib.sha256(fingerprint).hexdigest()[:12]
            result.append({'domain': 'least_privilege', 'id': str(row.get('id', index)),
                           'kind': None, 'confirmed': False, 'required': True, 'actionable': True,
                           **({'permission_recommendations': reviews} if reviews else {}),
                           'assets': sorted({item for item in [row.get('principal'), *(
                               asset(exposure.get('resource_id')) for exposure in row.get('exposures', []))]
                               if isinstance(item, str) and item})})
    graph = report.get('graphs', {}).get('privesc') or {}
    nodes = {row['id']: row for row in graph.get('nodes', [])}
    for index, row in enumerate(graph.get('edges', [])):
        endpoint_ids = [row.get('source'), row.get('target')]
        identifiers = [ident for endpoint in endpoint_ids
                       for ident in graph_assets(nodes.get(endpoint, {'id': endpoint}))]
        result.append({'domain': 'privesc_edges', 'id': str(row.get('id', index)),
                       'kind': None, 'confirmed': False, 'required': True, 'actionable': False,
                       'assets': sorted({ident for ident in identifiers if isinstance(ident, str) and ident})})
    finding_sources = {row['id']: row for row in result if row['domain'] == 'findings'}
    for action in platform.get('top_actions', []):
        supporting = [finding_sources.get(ident) for ident in action.get('finding_ids', [])]
        kinds = {row['kind'] for row in supporting if row}
        kind = (next(iter(kinds)) if len(kinds) == 1 and kinds <= SPECIAL_KINDS and
                supporting and all(row and row['confirmed'] for row in supporting) else None)
        result.append({'domain': 'actions', 'id': str(action['rank']), 'kind': kind,
                       'confirmed': False, 'required': True, 'actionable': False,
                       'assets': sorted({asset_id for row in supporting if row for asset_id in row.get('assets', [])})})
    # The lossless reader can distinguish historic duplicate graph IDs by their
    # records, but report references deliberately identify the original edge.
    from collections import Counter
    rows = {(row['domain'], row['id']): row for row in result}
    prefixes = {'hardening': 'HC', 'exposure': 'EX', 'network': 'NW',
                'least_privilege': 'LP', 'privesc_edges': 'PE', 'actions': 'AC'}
    counts = Counter()
    for key in sorted(rows):
        row = rows[key]
        prefix = prefixes.get(row.get('category') or row['domain'], 'F')
        counts[prefix] += 1
        row['source_id'] = f'{prefix}-{counts[prefix]:03}'
        row.setdefault('assets', [])
    return list(rows.values())


def _scoped_context(platform, sources):
    """Limit evidence to assigned observations and explicit nearby dependencies."""
    from .pipeline import referenced_strings
    from peaso.engine import hydrate_finding
    assigned = agent_sources(sources)
    required = {r['id'] for r in assigned if r['domain'] == 'findings' and r['required']}
    allowed = {r['id'] for r in assigned if r['domain'] == 'findings'}
    report = platform.get('report', {})
    actions = {r['id'] for r in assigned if r['domain'] == 'actions'}
    least_reviews = {r['id']: r.get('permission_recommendations', []) for r in assigned if r['domain'] == 'least_privilege'}
    least = [dict(row, permission_recommendations=least_reviews[str(row.get('id', i))])
             for i, row in enumerate(platform.get('least_privilege', {}).get('items', []))
             if str(row.get('id', i)) in least_reviews]
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
    write_json(root / 'report-sources.json', [dict(
        {key: val for key, val in row.items() if key != 'permission_recommendations'},
        **({'permission_review_ids': [item['review_id'] for item in row['permission_recommendations']]}
           if row.get('permission_recommendations') else {})) for row in assigned])
    write_json(root / 'analysis-status.json', scoped['analysis_status'])
    write_json(root / 'top-actions.json', scoped['top_actions'])
    from .report_draft import initial_draft
    write_json(root / 'report-draft.json', initial_draft(platform.get('previous_findings_report') or {}, assigned))


class MissingReportEvidence(ValueError):
    def __init__(self, missing):
        super().__init__('report_coverage_mismatch')
        self.missing = [{key: row[key] for key in ('domain', 'id', 'source_id') if key in row}
                        for row in missing]


def validate(data, sources):
    value = AgentReport.model_validate(data).model_dump()
    known = {(r['domain'], r['id']): r for r in agent_sources(sources)}
    from .report_source_facts import consolidate, present
    required = {key for key, row in known.items() if row['required']}
    covered = set()
    rejected_exclusions = set()
    for issue in value['issues']:
        keys = [(r['domain'], r['id']) for r in issue['references']]
        if len(keys) != len(set(keys)) or any(key not in known for key in keys):
            raise ValueError('unknown_report_reference')
        if covered.intersection(keys):
            raise ValueError('duplicate_report_reference')
        covered.update(keys)
        confirmed = any(known[key]['confirmed'] for key in keys)
        if ((issue['kind'] == 'vulnerability' and issue['status'] != 'confirmed')
                or (issue['status'] == 'confirmed' and not confirmed)
                or not any(known[key].get('actionable', True) for key in keys)):
            raise ValueError('unconfirmed_report_issue')
        if issue['kind'] == 'hardening' and issue['severity'] != 'info':
            raise ValueError('hardening_report_severity')
        if issue['permission_review_ids']:
            available = {ident for key in keys for ident in (known[key].get('permission_review_ids') or
                         [item['review_id'] for item in known[key].get('permission_recommendations', [])])}
            chosen = issue['permission_review_ids']
            if len(set(chosen)) != len(chosen) or not set(chosen) <= available:
                raise ValueError('unknown_or_duplicate_permission_review')
        present(issue, consolidate(known[key] for key in keys))
        issue['id'] = _issue_id(issue['references'])
    for exclusion in value['exclusions']:
        ref = exclusion['reference']
        key = ref['domain'], ref['id']
        if key not in known or key in covered or known[key]['kind'] in ('leaks', 'image_cves') and known[key]['required']:
            raise ValueError('invalid_report_exclusion')
        if not 100 <= len(exclusion['reason'].strip()) <= 300:
            raise ValueError('invalid_report_exclusion')
        covered.add(key)
        if must_include_in_issue(known[key]):
            rejected_exclusions.add(key)
    missing = (required - covered) | rejected_exclusions
    if missing:
        raise MissingReportEvidence(known[key] for key in sorted(missing))
    value['issues'].sort(key=lambda r: (['critical', 'high', 'medium', 'low', 'info'].index(r['severity']), r['id']))
    return dict(value, status='completed', source_count=len(known), covered_count=len(covered))
