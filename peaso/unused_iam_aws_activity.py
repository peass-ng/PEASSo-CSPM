"""Age-aware IAM role observations over the existing native Hardening control."""
from datetime import timedelta
from pathlib import Path
from dataclasses import replace
from functools import wraps
from copy import deepcopy
import json
import re

from peaso.iam_usage_evidence import instant

CHECK = 'aws.claude_a.iam.role_used_within_60_days'
TITLE = 'IAM role has recent recorded use or was created within 60 days'


class ActivityError(ValueError):
    def __init__(self, reason, status='UNKNOWN'):
        super().__init__(reason);self.status = status


def field(item, name, default=...):
    if not isinstance(item, dict): raise ActivityError('native IAM role is unavailable')
    if item.get('collection_status', 'collected') not in ('collected', 'empty'):
        raise ActivityError('native IAM role metadata is unavailable', 'DENIED' if item.get('collection_status') == 'denied' else 'UNKNOWN')
    cov = item.get('_coverage', {})
    if not isinstance(cov, dict): raise ActivityError('IAM field coverage is malformed')
    marker = cov.get(name)
    if marker is not None and (not isinstance(marker, dict) or marker.get('status') not in ('collected', 'empty')):
        raise ActivityError('IAM role field is unavailable: '+name, 'DENIED' if isinstance(marker, dict) and marker.get('status') == 'denied' else 'UNKNOWN')
    if name not in item:
        if default is ...: raise ActivityError('IAM role field is missing: '+name)
        return default
    return item[name]


def evaluate(item, index):
    try:
        context = index.get('context', {})
        proof = field(item, '_provenance', {})
        clock = proof.get('collected_at') if isinstance(proof, dict) else None
        now = instant(clock or context.get('created_at'))
        if context.get('provider', 'aws') != 'aws': raise ActivityError('role observation belongs to another provider')
        name, uid, arn = field(item, 'RoleName'), field(item, 'RoleId'), field(item, 'Arn')
        match = re.fullmatch(r'arn:aws[a-z-]*:iam::([0-9]{12}):role/(.+)', arn or '')
        if (not isinstance(name, str) or not name or not isinstance(uid, str) or not uid
                or not match or match[2].split('/')[-1] != name):
            raise ActivityError('current role name, ID and ARN are inconsistent')
        scope = context.get('scope')
        if scope and str(scope).split('/')[0] != match[1]: raise ActivityError('role belongs to a different AWS account')
        if isinstance(proof, dict):
            if proof.get('scope') and str(proof['scope']).split('/')[0] != match[1]:
                raise ActivityError('role capture belongs to another AWS account')
            if proof.get('account_id') and proof['account_id'] != match[1]:
                raise ActivityError('role capture account ID is inconsistent')
            if context.get('created_at') and now > instant(context['created_at']):
                raise ActivityError('role capture time is after the snapshot')
        created = instant(field(item, 'CreateDate'))
        if created > now: raise ActivityError('role creation date is in the future')
        usage = field(item, 'RoleLastUsed', {})
        if usage is None: usage = {}
        if not isinstance(usage, dict): raise ActivityError('native RoleLastUsed metadata is malformed')
        field(item, 'RoleLastUsed.LastUsedDate', None)  # Honor flattened native field coverage too.
        raw = field(usage, 'LastUsedDate', None)
        last = instant(raw) if raw is not None else None
        if last is not None and not created <= last <= now:
            raise ActivityError('last-used date is outside the current role lifetime')
        cutoff = now-timedelta(days=60)
        evidence = {'role_name': name, 'role_id': uid, 'role_arn': arn, 'created_at': created.isoformat(),
                    'observed_at': now.isoformat(), 'cutoff': cutoff.isoformat(), 'threshold_days': 60,
                    'last_used': last.isoformat() if last else None}
        if created >= cutoff:
            return 'PASS', {**evidence, 'object_age_days': (now-created).days,
                'summary': f'Role {name} was created on {created.date().isoformat()}.\nIt has not existed beyond the 60-day review threshold.\nThis creation age is separate from recorded AWS use.'}
        if last is None:
            return 'UNKNOWN', {**evidence, 'reason': 'bounded AWS tracking has no recorded last-used date',
                'summary': f'Role {name} has no recorded date in its RoleLastUsed metadata.\nA missing date within AWS tracking does not establish a complete 60-day inactivity interval.\nIts recent recorded activity is unresolved.'}
        days = (now-last).days
        failed = last < cutoff
        return ('FAIL' if failed else 'PASS'), {**evidence, 'days_since_recorded_use': days,
            'summary': f'Role {name} was last recorded in use on {last.date().isoformat()}, {days} days before capture.\n' +
                ('That activity is older than the 60-day review threshold.\nAn obsolete role may keep access available after its workload is removed.' if failed else
                 'That activity is within the 60-day review period.\nThe date belongs to the current role lifetime.')}
    except (ActivityError, ValueError, TypeError, KeyError, AttributeError, OverflowError) as exc:
        return getattr(exc, 'status', 'UNKNOWN'), {'reason': str(exc),
            'summary': f'{str(exc).rstrip(".")}.\nThe required current-role creation or last-use metadata is unavailable or inconsistent.\nIts inactivity cannot be established from these facts.'}


def install(registry):
    from peaso.checks.fixtures import CASES
    from peaso.checks import catalog
    folder = Path(__file__).with_name('checks')
    raw = (folder/'unused_iam_aws_activity_cases.json').read_bytes()
    review_raw = (folder/'unused_iam_aws_activity_review.json').read_bytes()
    cases, review = json.loads(raw), json.loads(review_raw)
    if set(cases) != {CHECK} or review['check_id'] != CHECK:
        raise ValueError('AWS role activity native review ID changed')
    matching = [check for check in registry.CHECKS if check.id == CHECK]
    if len(matching) != 1 or matching[0].provider != 'aws' or matching[0].kind != 'iam_role':
        raise ValueError('AWS role activity predecessor changed')
    registry.CHECKS[:] = [replace(check, evaluate=evaluate, category='hardening', title=TITLE,
        remediation='Review ownership, dependencies, last recorded use and unused-access insights before disabling or deleting an obsolete role.')
        if check.id == CHECK else check for check in registry.CHECKS]
    CASES[CHECK] = cases[CHECK]
    original = catalog.description_for
    @wraps(original)
    def description_for(ident):
        previous = original(ident)
        if ident != CHECK: return previous
        return {**deepcopy(previous), **deepcopy(review['updated_description_fields'])}
    catalog.description_for = description_for


