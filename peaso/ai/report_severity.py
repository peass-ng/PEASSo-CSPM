"""Evidence required for elevated vulnerability ratings in compiled reports."""
from typing import Annotated, Generic, Literal, TypeVar

from pydantic import Field

from .contracts import Strict


RISK = ['critical', 'high', 'medium', 'low', 'info']
EVIDENCED_RATINGS = {'medium', 'high', 'critical'}
SourceReference = TypeVar('SourceReference')
EvidenceText = Annotated[str, Field(min_length=1, max_length=600, pattern=r'\S')]


class SeverityEvidence(Strict, Generic[SourceReference]):
    reference: SourceReference
    asset: EvidenceText
    consequence: EvidenceText
    prerequisites: EvidenceText
    prerequisites_supported: bool
    impact_level: Literal['material', 'high', 'critical']
    internet_reachable: bool


def validate_rating(issue):
    """Check the rubric against the agent's explicit evidence claims."""
    evidence = issue.get('severity_evidence')
    if issue['kind'] == 'vulnerability' and issue['severity'] == 'info':
        raise ValueError('info_vulnerability_requires_hardening')
    if issue['kind'] != 'vulnerability' or issue['severity'] not in EVIDENCED_RATINGS:
        issue.pop('severity_evidence', None)
        return None
    if evidence is None:
        raise ValueError('missing_report_severity_evidence')
    if not evidence['prerequisites_supported']:
        raise ValueError('unsupported_report_severity')
    impact = evidence['impact_level']
    reachable = evidence['internet_reachable']
    ceiling = ('critical' if reachable and impact == 'critical' else
               'high' if impact == 'critical' or reachable and impact == 'high' else 'medium')
    if RISK.index(issue['severity']) < RISK.index(ceiling):
        raise ValueError('unsupported_report_severity')
    return evidence
