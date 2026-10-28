"""Strict output contracts plus cross-reference checks beyond JSON Schema."""
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator


class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)


class Review(Strict):
    finding_id: str
    verdict: Literal['PASS', 'FAIL', 'UNKNOWN', 'DENIED', 'MANUAL', 'NOT_APPLICABLE', 'EMPTY']
    reason: str = Field(max_length=500, description='Must be empty for FAIL; otherwise explain the verdict and any likely check error in at most 500 characters.')

    @model_validator(mode='after')
    def reason_matches_verdict(self):
        if self.verdict == 'FAIL' and self.reason != '':
            raise ValueError('Confirmed FAIL must have an empty reason')
        if self.verdict != 'FAIL' and not self.reason.strip():
            raise ValueError('Other verdicts must explain the result')
        return self


class Reviews(Strict):
    items: list[Review]


class LegacyAction(Strict):
    rank: int = Field(ge=1, le=15)
    title: str = Field(min_length=1, max_length=300)
    finding_ids: list[str]
    rationale: str = Field(min_length=1, max_length=1000)
    steps: list[Annotated[str, Field(min_length=1, max_length=500)]] = Field(min_length=1, max_length=5)
    verification: str = Field(min_length=1, max_length=700)


class Action(LegacyAction):
    severity: Literal['critical', 'high', 'medium', 'low', 'info']
    effort: Literal['high', 'medium', 'low']


class ArchivedAction(LegacyAction):
    severity: Literal['critical', 'high', 'medium', 'low', 'info'] | None = None
    effort: Literal['high', 'medium', 'low'] | None = None


class ArchivedRecommendations(Strict):
    actions: list[ArchivedAction] = Field(max_length=15)
    limitations: list[str]


class Recommendations(Strict):
    actions: list[Action] = Field(max_length=15)
    limitations: list[str]


class NetworkEvidence(Strict):
    summary: str = Field(min_length=1, max_length=1000, description='One to three short, natural-language lines explaining the exact weak boundary, observed configuration and affected resources. Include concrete selectors, CIDRs and ports when available; no generic warnings.')
    resource_ids: list[str] = Field(min_length=1, max_length=50, description='Existing original platform IDs for every affected control or workload, including the primary resource_id.')
    graph_refs: list[str] = Field(max_length=50, description='Existing node or edge IDs supporting the configuration and relationships; never invented references.')
    observations: list[Annotated[str, Field(min_length=1, max_length=1000)]] = Field(min_length=1, max_length=10, description='Specific observed rule values, native resource identifiers, selectors, protocols/ports and evidence paths supporting this finding.')

    @model_validator(mode='after')
    def meaningful_evidence(self):
        if not self.summary.strip() or any(not item.strip() for item in self.observations):
            raise ValueError('Network evidence must contain substantive text')
        return self


class NetworkFinding(Strict):
    title: str = Field(min_length=1, max_length=300, description='A concise actionable title naming the affected boundary or control and the needed change.')
    description: str = Field(min_length=1, max_length=1000, description='What is misconfigured: identify the affected tier/boundary, native controls and exact observed rule or route. Do not claim live reachability from configuration alone.')
    rationale: str = Field(min_length=1, max_length=1000, description='Why this configuration weakens segmentation, which workloads or tiers are affected, and any decision-changing dependency or intent assumption.')
    resource_id: str = Field(min_length=1, description='Primary affected control’s original platform resource ID, not its graph ID or native ID. The platform derives its display identity and scope.')
    severity: Literal['critical', 'high', 'medium', 'low', 'info'] = Field(description='Severity justified by the evidenced scope and impact of the boundary weakness; do not inflate based on unverified exploitation.')
    status: Literal['FAIL', 'MANUAL', 'UNKNOWN'] = Field(description='FAIL for an evidenced configuration weakness; MANUAL when the recommendation depends on unconfirmed intent or dependencies; UNKNOWN when configuration is missing or denied.')
    evidence: NetworkEvidence
    remediation: str = Field(min_length=1, max_length=2000, description='Concrete change to the named enforcement control: allowed source/destination and protocols/ports where evidenced, prerequisites and staged rollout preserving required dependencies.')
    verification: str = Field(min_length=1, max_length=1000, description='Specific read-only configuration checks and owner validation of required connectivity after the change, including expected allowed and restricted flows.')

    @model_validator(mode='after')
    def meaningful_finding(self):
        if any(not getattr(self, name).strip() for name in ('title', 'description', 'rationale', 'resource_id', 'remediation', 'verification')):
            raise ValueError('Network finding fields must contain substantive text')
        return self


class NetworkReview(Strict):
    explanation: str = Field(min_length=1, max_length=12000, description='Readable outline with ### headings per VPC/VNet/network, #### headings per subnet tier/connectivity boundary, and short - bullet lists separated by blank lines. Introduce each network with region, address space and purpose. Explain tier placement, purpose and enforcement in one or two sentences per bullet; group equivalent default networks. No dense global paragraphs.')
    findings: list[NetworkFinding] = Field(max_length=100)


def validate_network(data, platform):
    """Bind generated findings to supplied native resources and graph records."""
    from peaso.analysis.common import stable_id
    value = NetworkReview.model_validate(data).model_dump()
    resources = {row['id']: row for row in platform.get('source_inventory', platform['inventory'])}
    graph = platform['report'].get('graphs', {}).get('network') or {}
    graph_ids = {row['id'] for kind in ('nodes', 'edges') for row in graph.get(kind, [])}
    seen = set()
    for row in value['findings']:
        evidence = row['evidence']
        resource = resources.get(row['resource_id'])
        if (not resource or row['resource_id'] not in evidence['resource_ids']
                or not set(evidence['resource_ids']) <= resources.keys()
                or not set(evidence['graph_refs']) <= graph_ids):
            raise ValueError('unknown_network_reference')
        key = (row['resource_id'], row['title'].strip().casefold())
        if key in seen:
            raise ValueError('duplicate_network_finding')
        seen.add(key)
        ident = stable_id('ai.network', *key)
        row.update(id=ident, check_id='ai.network.' + ident.split(':')[1], category='network',
                   provider=resource['provider'], scope=resource['scope'], service=resource.get('service') or 'network',
                   frameworks=[], finding_type='network', native_resource_id=resource.get('native_id') or resource['id'],
                   resource_name=resource.get('name') or resource.get('native_id') or resource['id'])
        evidence['source'] = 'ai_network_review'
        row['evidence_summary'] = evidence['summary']
    return value


def validate_reviews(data, findings):
    value = Reviews.model_validate(data).model_dump()
    expected = {row['id'] for row in findings}
    ids = [row['finding_id'] for row in value['items']]
    if len(ids) != len(set(ids)) or set(ids) != expected:
        raise ValueError('review_coverage_mismatch')
    return value


def validate_actions(data, report, reviews, *, require_assessment=False):
    model = Recommendations if require_assessment else ArchivedRecommendations
    value = model.model_validate(data).model_dump(exclude_none=True)
    actions = value['actions']
    if [a['rank'] for a in actions] != list(range(1, len(actions) + 1)):
        raise ValueError('action_rank_mismatch')
    meta = report.get('check_meta') or {}
    def category(row):
        return row.get('category', (meta.get(row.get('check_id')) or {}).get('category'))
    findings = {row['id'] for row in report['findings'] if row.get('status') == 'FAIL'
                or (category(row) in ('network', 'privesc') and row.get('status') in ('MANUAL', 'UNKNOWN'))}
    rejected = {r['finding_id'] for r in reviews if r['verdict'] != 'FAIL'}
    titles = set()
    for action in actions:
        title = action['title'].strip().casefold()
        if title in titles:
            raise ValueError('invalid_action')
        titles.add(title)
        if not set(action['finding_ids']) <= findings - rejected:
            raise ValueError('unknown_action_reference')
        if not action['finding_ids']:
            raise ValueError('action_reference_missing')
    return value
