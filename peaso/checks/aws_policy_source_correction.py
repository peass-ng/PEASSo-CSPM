"""Source successors for signed IAM proposals, grounded in pinned upstream SQL.

The signed JSON and compiled lookup stay immutable historical ancestry. These
successors correct their claimed compliance scope without inventing a broader
upstream rule for AWS-managed or inline policies.
"""
from __future__ import annotations
from copy import deepcopy
import hashlib
import json
from pathlib import Path

SOURCE_URL = 'https://github.com/turbot/steampipe-mod-aws-compliance/blob/803dda1f7555ed5cea959aef30cfa0719b030d8c/conformance_pack/iam.pp'
PRIOR = {
    'aws.nist.all_iam_policies_no_star_star': '4e94b0ccee34cecfe013e32d54b1f766ffaafa182769f935cb2e411856dea17e',
    'aws.nist.all_managed_policies_no_service_wildcard': '84ea14357d0f2ab3c4738c4915bc62827a2c5c04292db7f964167dc5604ffcda',
    'aws_nist_iam_policy_no_star_star': 'bfa2678dcfe748dd0c489b29be17ae7c7ac7e3a012881a02b6aa452c4d73fde1',
    'aws_nist_iam_all_policy_no_service_wild_card': '8cd167ae327ff4efe12f8c28986c399d605e064161ded7eab02253939443be75',
    'aws_g6_iam_all_policy_star_star': 'b48a7c0d1eeed48c7b08a682b9084e0f3f4e8f33520df3604e28f3d9e99f6643',
    'aws_g6_iam_all_policy_service_wildcard': '52becf18c443df1aca7d30bb8fbdd00ced195f31a499d4ea78c737b90c1dcf0e',
    'aws_fedramp_iam_all_policies_no_admin_star': 'a3e80ebf0b15f8577c7f3b174dcaa5b245ffd56ad0f26e0f7e73f7bafb84a71c',
    'aws_fedramp_iam_all_policies_no_service_wildcard': 'c0569f92cc41cf75a31733af082730c5acd882f0ee88aed46665d2d4bd17817d',
}
SERVICE = {'aws.nist.all_managed_policies_no_service_wildcard', 'aws_nist_iam_all_policy_no_service_wild_card',
           'aws_g6_iam_all_policy_service_wildcard', 'aws_fedramp_iam_all_policies_no_service_wildcard'}
FEDRAMP = {'aws_fedramp_iam_all_policies_no_admin_star', 'aws_fedramp_iam_all_policies_no_service_wildcard'}
FEDRAMP_FROZEN = {'aws_fedramp_iam_all_policies_no_service_wildcard': {'id': 'aws_fedramp_iam_all_policies_no_service_wildcard',
                                                      'provider': 'aws',
                                                      'resource_kind': 'iam_policy',
                                                      'data_source': 'IAM ListPolicies/GetPolicyVersion '
                                                                     'plus '
                                                                     'ListUserPolicies/GetUserPolicy, '
                                                                     'ListRolePolicies/GetRolePolicy, '
                                                                     'ListGroupPolicies/GetGroupPolicy, '
                                                                     'and attached AWS-managed policy '
                                                                     'versions',
                                                      'predicate': 'FAIL if an effective Allow in any '
                                                                   'attached managed or inline IAM '
                                                                   'policy grants service:* on Resource '
                                                                   '* without a restricting condition '
                                                                   'or applicable explicit Deny; PASS '
                                                                   'when no in-scope policy does; '
                                                                   'UNKNOWN if an attached policy '
                                                                   'version cannot be read.',
                                                      'severity': 'medium',
                                                      'category': 'compliance',
                                                      'title': 'All IAM policy types avoid unrestricted '
                                                               'service access',
                                                      'description': 'Extends customer-managed policy '
                                                                     'coverage to attached AWS-managed '
                                                                     'and inline policies.',
                                                      'remediation_hint': 'Configure the named AWS '
                                                                          'resource to satisfy the '
                                                                          'predicate and verify all '
                                                                          'in-scope resources.'},
 'aws_fedramp_iam_all_policies_no_admin_star': {'id': 'aws_fedramp_iam_all_policies_no_admin_star',
                                                'provider': 'aws',
                                                'resource_kind': 'iam_policy',
                                                'data_source': 'IAM ListPolicies/GetPolicyVersion plus '
                                                               'inline user, role, and group policy '
                                                               'reads and attached AWS-managed policy '
                                                               'versions',
                                                'predicate': 'FAIL if any in-scope attached managed or '
                                                             'inline policy contains effective Allow '
                                                             'with Action * and Resource * without '
                                                             'restrictive condition or applicable Deny; '
                                                             'PASS if none do; UNKNOWN if policy '
                                                             'documents or attachments are incomplete.',
                                                'severity': 'medium',
                                                'category': 'compliance',
                                                'title': 'All IAM policy types avoid star-star '
                                                         'administration',
                                                'description': 'Tests unrestricted full administrator '
                                                               'grants across managed and inline policy '
                                                               'types.',
                                                'remediation_hint': 'Configure the named AWS resource '
                                                                    'to satisfy the predicate and '
                                                                    'verify all in-scope resources.'}}
FROZEN = json.loads(Path(__file__).with_name('aws_all_policies.json').read_text())
FROZEN.update(FEDRAMP_FROZEN)


def _digest(data):
    if not isinstance(data, str):
        data = json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(data.encode()).hexdigest()


def _entry(cid):
    old = FROZEN[cid]
    service = cid in SERVICE
    query = 'iam_all_policy_no_service_wild_card' if service else 'iam_policy_no_star_star'
    source_sha = ('0b6198af38a69e452441d756f0ad79a03bedd43549322adb5eee094c57390aa5' if service else
                  '4d1ba120336afd068b5a41277b7e692634b60bc2e98a668ef37d86fd5f1ac754')
    title = ('Customer-managed IAM policies avoid service-wide wildcard actions' if service else
             'Customer-managed IAM policies avoid full administrator statements')
    description = ('Checks every customer-managed default policy, attached or unattached, for literal Resource=* and Allow Action=* or an Action ending in :*. AWS-managed and inline policies are outside the pinned control.' if service else
                   'Checks every customer-managed default policy, attached or unattached, for literal Resource=* and Allow Action=* or *:*. AWS-managed and inline policies are outside the pinned control.')
    predicate = ('For every customer-managed default IAM policy, attached or unattached, FAIL on an Allow statement with literal Resource=* and Action=* or Action LIKE %:*. PASS only with a complete customer-managed policy inventory and default documents and no match; UNKNOWN on incomplete, denied, or malformed evidence. AWS-managed and inline policies are outside this source control.' if service else
                 'For every customer-managed default IAM policy, attached or unattached, FAIL on an Allow statement with literal Resource=* and Action=* or *:*. PASS only with a complete customer-managed policy inventory and default documents and no match; UNKNOWN on incomplete, denied, or malformed evidence. AWS-managed and inline policies are outside this source control.')
    spec = {key: old[key] for key in ('id', 'provider', 'resource_kind', 'severity', 'category', 'remediation_hint')}
    spec.update(data_source='iam:ListPolicies Scope=Local OnlyAttached=False; iam:GetPolicyVersion default version document',
                predicate=predicate, title=title, description=description)
    source_line = '#L1343-L1381' if service else '#L865-L904'
    provenance = {
        'version': 'peaso-source-correction-v1', 'status': 'source_erratum_successor',
        'prior_frozen_signed_spec_sha256': PRIOR[cid], 'prior_frozen_status': 'historical_superseded_for_this_check',
        'current_canonical_spec_sha256': _digest(spec), 'current_predicate_sha256': _digest(predicate),
        'source_url': SOURCE_URL + source_line,
        'source_query': query, 'source_evaluator_sha256': source_sha,
        'criterion_scope': 'All customer-managed default policies including unattached; excludes AWS-managed and inline; literal Resource=*',
    }
    prose = {'title': title, 'description': description, 'evaluated': [spec['data_source']],
             'pass_when': 'Complete customer-managed default policy inventory has no matching statement.',
             'fail_when': 'At least one customer-managed default policy has the pinned Allow wildcard statement.',
             'not_applicable_when': 'No separate applicability exclusion; an empty complete customer policy inventory satisfies the control.',
             'remediation': spec['remediation_hint'], 'evaluator_version': '2.0.0',
             'source_correction': provenance}
    return {'spec': spec, 'provenance': provenance, 'description': prose}

CORRECTIONS = {cid: _entry(cid) for cid in PRIOR}

def description(cid):
    return deepcopy(CORRECTIONS[cid]['description'])

def correction_provenance(cid):
    return deepcopy(CORRECTIONS[cid]['provenance'])
