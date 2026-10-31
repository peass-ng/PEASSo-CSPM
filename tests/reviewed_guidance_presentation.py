"""Assertions for signed source contracts plus the separately reviewed UI layer."""
from copy import deepcopy
from peaso.checks import CHECKS
from peaso.checks.catalog import _base_description_for,description_for
from peaso.remediation import template


def assert_approved_presentation(check_id, original):
    """Keep source bindings/commands while permitting short reviewed prose."""
    saved=deepcopy(original)
    current=template(check_id)
    assert original==saved
    assert current and current['review_status']=='approved'
    from peaso.checks.native_only import exclusions
    if check_id in exclusions() and current==original:
        # Archived operator-review controls are retained byte-for-byte for old
        # reports, and are outside the active automated presentation redesign.
        assert current==original
        return current
    assert current['summary'] and 1<=len(current['steps'])<=2
    assert len(current['summary'].split())<=40
    assert all(0<len(step.split())<=40 for step in current['steps'])
    assert current['references'] and current['caveats']
    assert {key:value for key,value in current.items() if key not in {'summary','steps','caveats'}}=={
        key:value for key,value in original.items() if key not in {'summary','steps','caveats'}}
    assert_description_preserves_contract(check_id)
    return current


def assert_description_preserves_contract(check_id):
    original=_base_description_for(check_id)
    current=description_for(check_id)
    changed_fields={'description'}
    if check_id == 'aws.claude_a.vpc.sg_no_world_any_port_on_customer_enis':
        # This exact source-reviewed prose erratum preserves the frozen row
        # and unchanged evaluator; no other control receives a criterion waiver.
        from peaso.checks.aws_sg_any_port_description_correction_20261021 import description
        from peaso.checks.aws_finding_clarity_reviewed import description as reviewed_description
        assert current == description(reviewed_description(check_id, original))
        changed_fields.update({'pass_when', 'fail_when', 'description_correction'})
    # Three separately reviewed interval corrections deliberately replace the
    # old exact-endpoint criterion; no other criterion differences are allowed.
    lightsail_ports={
        'aws.cb.lightsail.ssh_rdp_http_world_closed': ('22, 80 or 3389', '0.0.0.0/0 or ::/0'),
        'aws.cb.lightsail.ssh_restricted': ('22', '0.0.0.0/0'),
        'aws.cb.lightsail.rdp_restricted': ('3389', '0.0.0.0/0'),
    }
    if check_id in lightsail_ports:
        ports,sources=lightsail_ports[check_id]
        assert current['pass_when']==f'No valid TCP interval containing {ports} permits {sources}.'
        assert current['fail_when']==f'A valid TCP interval containing {ports} permits {sources}.'
        from peaso.checks.aws_compute_storage_clarity_reviewed import ROWS
        row=ROWS[check_id]
        assert row['reviewed_binding']['helper_contract']['source_sha256']=='b4199ed341491f07ba38a732d25096ab6ce8d3dc848a55a25fda49a4efbbfeff'
        assert row['criterion_correction']=='Inclusive bounded TCP intervals are tested for containing the selected port; exact interval endpoints no longer required.'
        changed_fields.update({'pass_when','fail_when'})
    azure_corrections = {
        'azure.claude.network_watcher_flow_logs_retention_90': {
            'pass_when': 'PASS when flow logs exist and each is enabled with retention zero (unlimited) or at least 90 days.',
            'fail_when': 'FAIL when no flow logs exist, a log is disabled, or a positive retention is below 90 days. Negative, missing or malformed durations are UNKNOWN.',
        },
        'azure.claude.sql_database_long_term_retention': {
            'pass_when': 'PASS when all three reported durations are recognized ISO durations and at least one is positive.',
            'fail_when': 'FAIL when all three recognized durations are zero; malformed or missing durations are UNKNOWN.',
            'not_applicable_when': 'NOT_APPLICABLE when the parent database is master.',
        },
        'azure.claude.storage_key_expiration_policy_max_90': {
            'pass_when': 'PASS when the reported integer expiration period is 1–90 days.',
            'fail_when': 'FAIL when the policy is absent, zero, or greater than 90 days; missing or malformed required evidence and negative days are UNKNOWN.',
        },
    }
    if check_id in azure_corrections:
        expected = azure_corrections[check_id]
        assert {key: current[key] for key in expected} == expected
        from peaso.checks.azure_finding_clarity_reviewed import ROWS
        assert {key: value for key, value in ROWS[check_id]['description_fields'].items()
                if key != 'description'} == expected
        changed_fields.update(expected)
    if check_id == 'azure.claude.storage_access_keys_rotated_90':
        # The native storage successor requires both dated keys; the original
        # signed guidance row and its incomplete-time criterion stay retained.
        from peaso.checks.azure_native_review_copy_20261020 import SUCCESSORS
        predecessor, fields = SUCCESSORS[(check_id, 'description')]
        assert predecessor == 'a0827ceecb2174fb121e97cedb5570bb10382ba6103add0d351dd8abef0e9c17'
        expected = {
            'description': 'Checks both native storage-key creation times against the captured scan time. Either key older than 90 days fails; incomplete, future or malformed times remain unresolved.',
            'pass_when': 'Both key1 and key2 have valid creation times no more than 90 days before the captured scan time.',
            'fail_when': 'At least one of the two valid native key creation times is more than 90 days before the captured scan time.',
            'not_applicable_when': 'No automatic exclusion; absent, incomplete, future or malformed key creation times remain UNKNOWN.',
        }
        assert fields == expected
        assert {key: current[key] for key in expected} == expected
        changed_fields.update(expected)
    # The reviewed credential-report successors (120406f2) replace the
    # criterion prose for exactly these six IDs; evaluator binding is unchanged.
    credential_successors = {
        'aws.a.iam.unused_credentials_45_days': (45, 'console passwords and access keys'),
        'aws.a.iam.unused_credentials_90_days': (90, 'console passwords and access keys'),
        'aws.gap.iam.active_keys_used_within_45_days': (45, 'access keys'),
        'aws.claude_a.iam.console_password_used_45': (45, 'console passwords'),
        'aws.claude_a.iam.prowler_console_password_used_45': (45, 'console passwords'),
        'aws.claude_a.iam.access_keys_used_45': (45, 'access keys'),
    }
    if check_id in credential_successors:
        days, population = credential_successors[check_id]
        expected = {
            'description': f'Reviews enabled {population} from a current identity-bound AWS credential report against a {days}-day threshold. Recorded use, current credential lifetime and documented tracking limits must agree; recent creation without recorded use remains unresolved.',
            'evaluated': ['credential report generated within four hours of its bound native read', 'same-account user identity, current credential dates and enabled state', f'{days}-day recorded-use or documented no-use interval for {population}'],
            'pass_when': 'All assessed enabled credentials have current, consistent recent recorded use.',
            'fail_when': f'At least one assessed enabled credential has recorded use older than {days} days, or a documented no-use marker covering that interval within its current lifetime.',
            'not_applicable_when': 'No credential in the assessed family is enabled; root handling remains separate. Missing, stale, denied, inconsistent or insufficient observation is unresolved.',
        }
        assert {key: current[key] for key in expected} == expected
        changed_fields.update(expected)
    if check_id == 'aws.claude_a.iam.role_used_within_60_days':
        # Reviewed role-activity successor (120406f2): the review file supplies
        # the replacement criterion fields.
        import json
        from pathlib import Path
        review = json.loads((Path(__file__).resolve().parents[1] / 'peaso/checks/unused_iam_aws_activity_review.json').read_text())
        assert review['check_id'] == check_id
        expected = review['updated_description_fields']
        assert set(expected) == {'description', 'evaluated', 'pass_when', 'fail_when', 'not_applicable_when'}
        assert {key: current[key] for key in expected} == expected
        changed_fields.update(expected)
    if check_id == 'aws.claude_a.vpc.sg_in_use_anywhere':
        # Reviewed unused-network successor (120406f2): peaso/unused_network_aws.py
        # rebinds the evaluator to the complete reference inventory and replaces
        # exactly these criterion fields; the remediation binding is unchanged.
        expected = {
            'description': 'Reviews current non-default security-group references in complete scoped ENI, Lambda, Batch and security-group inventories, including both ingress and egress group rules. This is structural configuration evidence, not measured traffic inactivity.',
            'evaluated': ['same-scope ENI security groups, Lambda VPC groups and Batch compute-resource groups', 'other security-group ingress and egress references', 'complete dependency inventory before reporting no recognized reference'],
            'pass_when': 'A captured scoped network declaration references this group.',
            'fail_when': 'Complete supported reference inventories contain no recognized consumer of this non-default group.',
        }
        assert {key: current[key] for key in expected} == expected
        changed_fields.update(expected)
    assert {key:value for key,value in current.items() if key not in changed_fields}=={
        key:value for key,value in original.items() if key not in changed_fields}
    assert 0<len(current['description'].split())<=45
    return current


def assert_reviewed_text_only_admission(check_id, *, require_binding=True):
    check=next(c for c in CHECKS if c.id==check_id)
    current=template(check_id)
    assert current and current['review_status']=='approved'
    assert current['cli']==[] and not current.get('iac')
    assert 1<=len(current['steps'])<=2 and len(current['summary'].split())<=40
    assert current['references'] and current['caveats']
    assert all(ref['url'].startswith('https://') for ref in current['references'])
    if require_binding:
        assert current['field_binding']['kind']==check.kind
        assert current['field_binding']['target']==check.target
    assert_description_preserves_contract(check_id)
    return current
