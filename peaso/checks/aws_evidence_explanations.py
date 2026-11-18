"""Exact-check observations and reviewed interpretations for the AWS registry.

The catalog binds each display field to the evaluator which actually records it.
No setting is inferred from PASS/FAIL and no unrecognized field is displayed.
"""
import json
from functools import lru_cache
from math import isfinite
from pathlib import Path


@lru_cache(maxsize=1)
def review_rows():
    historical = json.loads(Path(__file__).with_suffix('.json').read_text())
    current = json.loads(Path(__file__).with_name('aws_current_evidence_rows_20261022.json').read_text())
    if set(historical) & set(current):
        raise ValueError('Current AWS evidence rows overlap historical review')
    return historical | current


def reviewed_explanation(check_id, observation, status=None):
    if not isinstance(check_id, str):
        return None
    row = review_rows().get(check_id)
    if not row or not isinstance(observation, str) or not observation.strip():
        return None
    purpose = row['purpose']
    return observation if purpose in observation else observation.rstrip() + ' ' + purpose


def _text(value):
    return isinstance(value, str) and 0 < len(value) <= 200 and all(ord(c) >= 32 for c in value)


def _value(value, allowed):
    if type(value) is bool and 'boolean' in allowed:
        return 'yes' if value else 'no'
    if type(value) in (int, float) and 'number' in allowed and isfinite(value):
        return str(value)
    if isinstance(value, str) and 'text' in allowed:
        if value == '':
            return 'empty'
        if _text(value) and not value.lstrip().startswith(('{', '[')):
            return 'yes' if value == 'true' else 'no' if value == 'false' else '“' + value + '”'
    if value is None and 'null' in allowed:
        return 'not recorded'
    if isinstance(value, list) and 'list' in allowed:
        if not value:
            return 'none'
        if all(_text(v) for v in value) and len(', '.join(value)) <= 75:
            return ', '.join('“' + v + '”' for v in value)
        # Contents remain available in raw evidence; count is not interpreted
        # as proof of a successful scan, complete protection or safe access.
        return str(len(value)) + ' recorded entries'
    if isinstance(value, dict) and 'object' in allowed:
        if not value:
            return 'no recorded entries'
        if len(value) <= 3 and all(_text(k) and type(v) is bool for k, v in value.items()):
            return ', '.join(k + ': ' + ('yes' if v else 'no') for k, v in value.items())
        return str(len(value)) + ' recorded entries'
    return None


def _specific_observation(finding):
    """Decisive native shapes that cannot be summarized as generic field counts."""
    cid, e = finding['check_id'], finding['evidence']
    if cid == 'aws_organizations_security_service_tamper_scp' and isinstance(e.get('unprotected_services'), dict):
        unprotected = e['unprotected_services']
        names = {'guardduty': 'GuardDuty', 'config': 'AWS Config', 'securityhub': 'Security Hub', 'cloudtrail': 'CloudTrail'}
        services = sorted({names[s] for gaps in unprotected.values() if isinstance(gaps, list) for s in gaps if s in names})
        if not unprotected:
            return 'Every member account inherits SCPs denying GuardDuty, Config, Security Hub and CloudTrail tampering.'
        if services:
            return (f'{len(unprotected)} member accounts can disable security services their SCPs do not protect: '
                    + ', '.join(services) + '.')
    if cid == 'aws.htbp.elbv2.mtls_no_shared_cdn_origin_ca' and isinstance(e.get('shared_cdn_cas'), list):
        providers = sorted({m.get('provider') for m in e['shared_cdn_cas'] if isinstance(m, dict) and isinstance(m.get('provider'), str)})
        store = 'Trust store ' + e['trust_store_name'] if isinstance(e.get('trust_store_name'), str) else 'The trust store'
        if not e['shared_cdn_cas']:
            return f'{store} trusts no known shared CDN origin-pull CA.'
        if providers:
            return (f'{store} trusts the {", ".join(providers)} origin-pull CA shared by all its customers, so any of them '
                    'can pass this listener\'s client-certificate check.')
    if cid == 'aws.review.cognito.app_client_refresh_token_rotation' and e.get('refresh_token_rotation') in ('ENABLED', 'DISABLED'):
        return 'Refresh token rotation is '+('enabled.' if e['refresh_token_rotation'] == 'ENABLED' else 'disabled.')
    if cid.startswith('aws.review.') and 'secret_indicators' in cid:
        categories = e.get('matched_categories')
        if isinstance(categories, list) and all(isinstance(value, str) for value in categories):
            return ('Possible passwords or credentials were found in the checked configuration.' if categories else
                    'No signs of secrets were found in the checked configuration.')
        leaks = e.get('secret_leaks')
        if isinstance(leaks, list) and type(e.get('source_complete')) is bool:
            if leaks:
                return 'Possible credentials were found in the inspected package contents.'
            return ('No signs of secrets were found in the inspected package contents.' if e['source_complete'] else
                    'The package scan was incomplete, so exposed secrets could not be ruled out.')
    if cid == 'aws.review.lambda.execution_role_policy_admin_grants':
        patterns = e.get('declared_admin_patterns')
        if isinstance(patterns, list) and all(isinstance(value, dict) for value in patterns):
            return ('The function’s role policies include a grant of every action on every resource; other policies can still restrict access.' if patterns else
                    'The function’s role policies contain no explicit grant of every action on every resource.')
    if cid == 'aws.cb.kafka.cmk_encryption_at_rest' and _text(e.get('data_volume_kms_key_id')):
        return 'MSK volume-encryption key: ' + e['data_volume_kms_key_id'] + '.'
    if cid == 'aws.claude_a.guardduty.ecs_runtime_agent_management' and type(e.get('enabled')) is bool:
        return 'GuardDuty ECS Fargate agent management is ' + ('enabled.' if e['enabled'] else 'disabled.')
    if cid.startswith(('aws.gap.cloudwatch.metric_alarm.', 'aws.gap.cloudwatch.cis_alarm.')):
        if e.get('matching_metric_alarm') is True and e.get('trail_logging') is True:
            return 'The trail is logging and has a matching event filter and metric alarm.'
        if e.get('observed') == 'No logging trail has a matching event filter and metric alarm.':
            return 'No evaluated trail has the required event filter and metric alarm.'
        if e.get('observed') == 'No logging trail has a matching event filter and metric alarm with enabled SNS notification to a confirmed subscriber.':
            return 'No evaluated trail has the required filter, alarm and confirmed notification chain.'
    if cid.startswith('aws.cb.ram.shared_with_'):
        principals = e.get('principals_to_review')
        if isinstance(principals, list) and all(_text(value) for value in principals):
            return f'{len(principals)} declared sharing principals require trust review.' if principals else 'No matching sharing principals are recorded.'
    if cid == 'aws.claude2_a.cloudwatch.cross_account_sharing_role_absent':
        roles, principals = e.get('cross_account_sharing_role'), e.get('trusted_principals')
        if isinstance(roles, list) and roles and isinstance(principals, list):
            return f'The CloudWatch sharing role declares {len(principals)} trusted principals.'
    if cid in ('aws_costexplorer_anomaly_alert', 'aws_costexplorer_prod_anomaly_monitor', 'aws_costexplorer_qa_anomaly_monitor'):
        monitors, subscribed = e.get('matching_active_monitors'), e.get('thresholded_subscribed_monitors')
        if isinstance(monitors, list) and isinstance(subscribed, list):
            return f'{len(monitors)} active monitors match the scope; {len(subscribed)} have approved thresholds and subscribers.'
    if cid == 'aws.pci.cloudwatch.metric_alarm_settings':
        mismatched = e.get('mismatched_alarm_arns')
        if isinstance(mismatched, list) and all(_text(value) for value in mismatched):
            return f'{len(mismatched)} assessed alarms differ from the approved period or threshold settings.'
    if cid == 'aws_sensitive_data_rest_access_controls':
        flags, indexes = e.get('disabled_block_flags'), e.get('unapproved_statement_indexes')
        if isinstance(flags, list) and isinstance(indexes, list):
            return f'Public-block flags disabled: {len(flags)}; unapproved reader-policy statements: {len(indexes)}.'
    if cid in ('aws.nist.sc_8_1_coverage', 'aws.nist.sc_8_coverage'):
        unsafe, total = e.get('unsafe_endpoint_ids'), e.get('external_endpoint_count')
        if isinstance(unsafe, list) and type(total) is int and total >= 0:
            return f'Endpoints outside the approved TLS settings: {len(unsafe)} of {total} assessed.'
    if cid == 'aws_wafv2_monitoring_rate_rule':
        endpoints = e.get('endpoints_without_rate_alert')
        if isinstance(endpoints, list):
            return f'Endpoints without the required rate alert: {len(endpoints)}.'
    if cid.startswith('aws.gap.ec2.instance_no_iam_') and isinstance(e.get('roles'), dict):
        roles = e['roles']
        if not roles:
            return 'No assessed instance role declares a matching sensitive action.'
        for role, actions in roles.items():
            if _text(role) and isinstance(actions, list) and actions and all(_text(action) for action in actions):
                action = actions[0]
                return f'Role “{role}” declares matched action “{action}”.' if len(actions) == 1 else f'Role “{role}” declares {len(actions)} matched actions, including “{action}”.'
    if cid == 'aws.pci.kms.enclave_attestation_events':
        pcr, observed = e.get('pcr'), e.get('observed')
        if _text(pcr) and _text(observed):
            return f'The recorded attestation event reports {pcr} value “{observed}”.'
        if isinstance(e.get('checked_pcrs'), list) and all(_text(value) for value in e['checked_pcrs']):
            return f'The recorded attestation event has {len(e["checked_pcrs"])} assessed platform measurements.'
    if cid == 'aws_cognito_session_expiry':
        values = e.get('validity_minutes')
        if isinstance(values, dict):
            allowed = {'AccessToken': 'Access token', 'IdToken': 'ID token', 'RefreshToken': 'refresh token'}
            parts = [allowed[key] + f': {value:g} minutes' for key, value in values.items() if key in allowed and type(value) in (int, float) and isfinite(value) and value >= 0]
            if parts:
                return '; '.join(parts) + '.'
    if cid == 'aws_nist_backup_plan_min_retention_35_days':
        rules, frequency, retention = e.get('qualifying_rules'), e.get('required_frequency_hours'), e.get('required_retention_days')
        if isinstance(rules, list) and type(frequency) in (int, float) and isfinite(frequency) and type(retention) is int:
            return f'{len(rules)} backup rules meet both the {frequency:g}-hour interval and {retention}-day retention requirements.'
    if cid == 'aws_backup_plan_rule_required_frequency':
        failed, frequency = e.get('failed_rules'), e.get('required_frequency_hours')
        if isinstance(failed, list) and all(type(value) is int and value > 0 for value in failed) and type(frequency) in (int, float) and isfinite(frequency):
            return f'{len(failed)} backup rules miss the required interval of at most {frequency:g} hours.'
    if cid == 'aws_cloudwatch_metric_alarm_has_threshold':
        threshold, low, high = e.get('threshold'), e.get('approved_min'), e.get('approved_max')
        if all(type(value) in (int, float) and isfinite(value) for value in (threshold, low, high)):
            return f'The alarm threshold is {threshold:g}; the approved range is {low:g}–{high:g}.'
    if cid == 'aws_vpn_tunnel_encryption_configuration':
        site, client = e.get('unsafe_tunnels'), e.get('unsafe_client_vpns')
        if isinstance(site, list) and isinstance(client, list):
            return f'VPN encryption deviations: {len(site)} site-to-site tunnels and {len(client)} Client VPN endpoints.'
    if cid == 'aws.pci.shield.srt_access' and isinstance(e.get('role_arn'), str):
        missing = e.get('missing_log_buckets')
        if isinstance(missing, list):
            return 'The DDoS response role is ' + ('declared' if e['role_arn'] else 'not declared') + f'; {len(missing)} required log buckets are missing.'
    if cid == 'aws.pci.fms.web_acl_rule_priority':
        acls = e.get('noncompliant_web_acl_arns')
        if isinstance(acls, list) and all(_text(value) for value in acls):
            return f'{len(acls)} assessed web ACLs differ from the required unique rule priorities.'
    if cid == 'aws_backup_failure_notification':
        topic, event = e.get('notification_topic_present'), e.get('backup_failure_event_present')
        if type(topic) is bool and type(event) is bool:
            return 'A notification topic is ' + ('declared' if topic else 'absent') + '; backup-failure events are ' + ('included.' if event else 'not included.')
    if cid == 'aws_account_expected_organization_master':
        observed, expected = e.get('observed_management_account_id'), e.get('expected_management_account_id')
        if all(isinstance(value, str) and len(value) == 12 and value.isdecimal() for value in (observed, expected)):
            return f'The organization management account is {observed}; owner policy expects {expected}.'
    if cid == 'aws_partner_role_external_id_present':
        indexes = e.get('statements_without_external_id')
        if isinstance(indexes, list) and all(type(index) is int and index >= 0 for index in indexes):
            return f'{len(indexes)} assessed partner-trust statements lack the required ExternalId condition.'
    if cid == 'aws_cis_lambda_execution_role_exists':
        role = e.get('execution_role_arn')
        if _text(role):
            return 'The function declares an execution-role ARN; the saved result does not record whether that role exists.'
    if cid == 'aws.pci.iam.policy_arn_attachment':
        required = e.get('required_policy_arn')
        if _text(required):
            return 'The required policy ARN is recorded; the saved result does not retain the attachment outcome.'
    if cid == 'aws_cis_ec2_instance_approved_ami':
        image, owner = e.get('image_id'), e.get('image_owner_id')
        if _text(image) and isinstance(owner, str) and len(owner) == 12 and owner.isdecimal():
            return f'The instance uses image “{image}” from account {owner}; approval membership is not retained in this result.'
    if cid == 'aws_cis_lambda_database_secrets_manager':
        refs = e.get('resolved_secret_arns')
        if isinstance(refs, list) and all(_text(value) for value in refs):
            return f'{len(refs)} declared database references resolve to inventoried Secrets Manager secrets.'
    if cid in ('aws_ecr_image_provenance', 'aws_ecr_sbom_present'):
        digest = e.get('image_digest')
        field = 'verified_signature_artifacts' if cid == 'aws_ecr_image_provenance' else 'matching_sbom_artifacts'
        values = e.get(field)
        if _text(digest) and isinstance(values, list) and all(_text(value) for value in values):
            noun = 'verified signature artifacts' if cid == 'aws_ecr_image_provenance' else 'matching SBOM artifacts'
            return f'The assessed image digest has {len(values)} {noun}.'
    # Exact reason strings are explicit native witnesses, never inferred from FAIL.
    reasons = {
        'aws_lambda_code_signing_configured': {'no code-signing config': 'The function has no code-signing configuration.'},
        'aws_nist_autoscaling_use_multiple_instance_types_in_multiple_az': {'fewer than two zones': 'The Auto Scaling group declares fewer than two Availability Zones.'},
        'aws_cis_backup_recovery_point_isolation': {'unencrypted recovery point': 'The recovery point reports encryption disabled.'},
        'aws_cis_beanstalk_persistent_logs_s3': {'log publication disabled': 'The Beanstalk environment declares persistent S3 log publication disabled.'},
        'aws_cis_lambda_database_secrets_manager': {'database variable does not reference inventoried secret ARN': 'A database variable does not reference an inventoried Secrets Manager secret ARN.'},
        'aws_nist_secretsmanager_secret_automatic_rotation_enabled': {'automatic rotation disabled': 'The secret declares automatic rotation disabled.'},
        'aws_bedrock_automated_reasoning_policy_attached': {'no policy attached': 'The linked guardrail has no automated-reasoning policy attached.'},
    }
    reason = e.get('reason')
    if isinstance(reason, str):
        return reasons.get(cid, {}).get(reason)
    return None


def _observation(finding, row):
    from .selected_content_observed import observation as selected_content
    selected = selected_content(finding)
    if selected:
        return selected
    cid, e = finding['check_id'], finding['evidence']
    specific = _specific_observation(finding)
    if specific:
        return specific
    # These functions validate native witnesses. Legacy static failure strings
    # which rely solely on a verdict are deliberately excluded here.
    from .aws_scope_observed_evidence import evidence_summary as scopes
    from .aws_core_observed_evidence import evidence_summary as core
    from .aws_typed_finding_summary import evidence_summary as typed
    from .aws_pass_observed_evidence import evidence_summary as passed
    from .aws_final_clarity_reviewed import evidence_summary as final
    from .aws_bulk_finding_summary import evidence_summary as bulk
    from .aws_remaining_finding_summary import evidence_summary as remaining
    for summarize in (scopes, core, typed, passed, final, bulk, remaining):
        observation = summarize(finding)
        if observation:
            if cid.startswith('aws.claude_a.ec2.instance_port_') and observation.endswith('; endpoint reachability is not established.'):
                return observation.removesuffix('; endpoint reachability is not established.') + '.'
            return observation
    observed = e.get('observed')
    if (cid == 'aws.review.codebuild.selected_inline_buildspec_secret_indicators'
            and finding.get('status') == 'UNKNOWN' and observed in {
                'The selected inline CodeBuild buildspec was unavailable, a reference, incomplete or unbound. Secret absence could not be assessed.',
                'Selected inline CodeBuild source was unavailable, incomplete or unbound.'}):
        return 'The selected inline CodeBuild source could not be fully inspected, so no clean result is established.'
    if (cid == 'aws.review.s3.selected_source_secret_indicators' and finding.get('status') == 'UNKNOWN'
            and {k: v for k, v in e.items() if k != 'reason'} == {'observed': 'Selected S3 source content was unreadable, unsupported, incomplete or unbound. A clean result cannot be established.',
                      'complete': False, 'coverage': 'incomplete'}):
        return 'The selected S3 source could not be fully inspected, so no clean result is established.'
    if _text(observed) and ' ' in observed and observed.endswith('.') and not observed.lstrip().startswith(('{', '[')):
        return observed
    facts = []
    for spec in row.get('fields', []):
        if spec['key'] not in e:
            continue
        value = _value(e[spec['key']], spec['types'])
        if value is not None:
            facts.append(spec['label'] + ': ' + value)
        if len(facts) == 2:
            break
    return '; '.join(facts) + '.' if facts else None


def evidence_summary(finding):
    if not isinstance(finding, dict) or finding.get('provider') != 'aws':
        return None
    cid, e, status = finding.get('check_id'), finding.get('evidence'), finding.get('status')
    if not isinstance(cid, str) or not isinstance(status, str):
        return None
    row = review_rows().get(cid)
    if row is None or not isinstance(e, dict):
        return None
    if status not in {'PASS', 'FAIL', 'UNKNOWN', 'DENIED', 'MANUAL', 'NOT_APPLICABLE', 'EMPTY'}:
        return None
    from .aws_current_evidence_20261022 import CURRENT_IDS, explanation as current_explanation
    if cid in CURRENT_IDS:
        return current_explanation(cid, e)
    observed_finding = dict(finding, check_id=row['alias_of']) if row.get('alias_of') else finding
    from .aws_natural_evidence import complete_explanation, natural_observation
    complete = complete_explanation(observed_finding)
    if complete and status in {'PASS', 'FAIL', 'UNKNOWN', 'DENIED'}:
        return complete
    observation = _observation(observed_finding, row) if e else None
    observation = natural_observation(observed_finding, row, observation)
    if observation is None:
        if status == 'NOT_APPLICABLE':
            observation = 'This resource is outside the control’s applicability.'
        elif status == 'EMPTY':
            observation = 'No applicable resources were recorded.'
        else:
            observation = 'No usable deciding evidence was recorded.'
    if status in {'UNKNOWN', 'DENIED'}:
        # A retained partial value is useful, but cannot stand in for a verdict.
        observation = ('Required evidence is unavailable; this check is undetermined.' if observation == 'No usable deciding evidence was recorded.' else observation + ' The check remains undetermined.')
    elif status == 'MANUAL' and 'owner review' not in row['purpose'].lower() and 'review' not in observation.lower():
        observation += ' Owner review is required.'
    return reviewed_explanation(cid, observation, status)
