"""Signed AWS sw48 predicates. Facts must be complete, scoped and unambiguous."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import re

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, guard, optional, list_of_objects

# (kind, category, severity, title, signed digest, remediation)
SPECS = {
'aws_nist_config_enabled_all_regions': ('config_account_region_coverage','compliance','medium','AWS Config should be enabled','530a285b1afe78c7f01411ef9e27a8f041a5611d5bead9c8f1ef261e37882112','Enable AWS Config recording and delivery in every enabled Region.'),
'aws.pci.secretsmanager.kms_encryption_any': ('secret','hardening','medium','Secrets Manager secrets use AWS KMS encryption','9324f2166db3358028a9710c333e2c57f30e648fcabd61c7ee02f99e8b7dd186','Configure an enabled AWS or customer managed KMS key.'),
'aws_nist_secretsmanager_secret_automatic_rotation_enabled': ('secret','compliance','medium','Secrets Manager secrets should have automatic rotation enabled','db6bb47b7f124649a83f0b962cdaa58bf1f40d6801eaa9aa73ddd4c8c0362bd6','Enable rotation with a valid schedule and rotation Lambda when required.'),
'aws.pci.redshift.expected_settings': ('redshift_cluster','hardening','medium','Redshift cluster settings match expected values','38c746a2e5ec77f7fa915997fa72df9f9d0d435ee4d643aec3c4608ea861c54a','Apply the approved cluster and parameter settings.'),
'aws.pci.classic_elb.custom_ssl_policy': ('classic_elb','hardening','medium','Classic ELB uses a custom SSL policy','9d2bbdd5be9457b43485d3efd2edb653d9ea176f3b78e2e4f5338cd2e69de148','Attach the approved custom SSL negotiation policy.'),
'aws.pci.classic_elb.predefined_ssl_policy': ('classic_elb','hardening','medium','Classic ELB uses a predefined SSL policy','1ff52081ecafd555fb82cfb6e24d916bf7301f46108b8fb0fa3cbf18627fdf2f','Attach an AWS predefined SSL negotiation policy.'),
'aws_vpn_tunnel_encryption_configuration': ('vpn_connection','hardening','medium','VPN encryption configuration','86f0010351ebf4eed6a1904812960e73b9b801981abc9e346be69bfc590649bf','Remove AES128 and DES tunnel options and configure Client VPN certificate.'),
'aws_organizations_environment_account_separation': ('aws_organization_account','hardening','medium','Production and test workloads use separate accounts','a362adab743ea6ec9d04ba4e218d44668ff16f8e68d5c440ef6a486b0b00c415','Separate production and development workloads across approved boundaries.'),
'aws.nist.sc_36_coverage': ('recovery_group','compliance','medium','Processing and storage groups span distinct Availability Zones','fd1f85e1e38939de526b4cc74654ab79c61dd3f9b789000ec470f8bd9c869e5b','Deploy each approved recovery group across at least two Availability Zones.'),
'aws_nist_rds_db_instance_and_cluster_enhanced_monitoring_enabled': ('rds_instance','compliance','medium','RDS DB instance and cluster enhanced monitoring should be enabled','009e790f149fa2a8608cab7e756d0e9ceb7ef24ec6b3141e749df9dbc16567b3','Enable enhanced monitoring on every applicable instance.'),
'aws_nist_cloudformation_stack_drift_detection_check': ('cloudformation_stack','compliance','medium','CloudFormation stacks differ from the expected configuration','4fa6774db96af2536b3534f9b5febb1c34c520e7f0144a02e528e52d028a1c84','Run stack drift detection within the approved maximum age and remediate drift.'),
'aws_g6_ecs_fargate_storage_encryption': ('ecs_cluster','hardening','medium','ECS task backing volumes are encrypted at rest','5580704dae69d3ca7622cca4189c105558769a682cf3e7a466d28d073855441e','Encrypt managed EBS and task EFS backing volumes.'),
'aws_autoscaling_userdata_plaintext_aws_key': ('autoscaling_launch_configuration','hardening','high','Auto Scaling user data has no embedded AWS key pair','dcc512242074b6b73493eecf1f96aca1bc39083ca4ecb8e33fc4c66fed30b924','Use an instance role or Secrets Manager instead of embedded keys.'),
'aws_sagemaker_model_clarify_bias_job': ('sagemaker_processing_job','compliance','medium','Model Monitoring and Bias Detection','e7f5077bce0d47265d0ded7bf6025b7d8a9e26ee230d52b43a6842bb3dfec711','Enable an endpoint-linked monitoring schedule and run Clarify within the approved interval.'),
'aws_ecr_repository_lifecycle_retention': ('ecr_repository','compliance','medium','Confirm that artifacts older than the specified retention period are automatically deleted','00846deee6ffa670bd8cc57fc77e0ded4a2b224c5d0613b81289a4ecaaf02376','Configure a tagStatus=any sinceImagePushed expiration rule within approved retention.'),
}

_ARN = re.compile(r'^arn:aws(?:-[a-z0-9-]+)?:[^:]+:[a-z0-9-]*:[0-9]{12}:.+$')
_SCOPE = re.compile(r'^[0-9]{12}/[a-z0-9-]+$')


def _inventory(index, kind, item=None):
    context = get(index, 'context', dict)
    if get(context, 'provider', str) != 'aws':
        raise Unavailable('foreign provider')
    scope = get(context, 'scope', str)
    if not _SCOPE.fullmatch(scope):
        raise Unavailable('AWS account/Region scope unavailable')
    envelopes = get(index, 'collections', dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable('complete collection unavailable: ' + kind)
    env = envelopes[0]
    if (not isinstance(env, dict) or env.get('type') != kind or env.get('scope') != scope or
            env.get('status') not in ('collected', 'empty') or not isinstance(env.get('items'), list)):
        raise Unavailable('foreign or incomplete collection: ' + kind)
    rows = complete_items(index, kind)
    wrappers = get(index, kind, list)
    if (len(rows) != len(env['items']) or rows != env['items'] or len(wrappers) != len(rows) or
            any(not isinstance(w, dict) or w.get('type') != kind or w.get('scope') != scope or w.get('data') != row for w, row in zip(wrappers, rows))):
        raise Unavailable('collection projection mismatch: ' + kind)
    for row in rows:
        guard(row)
        for field in ('ARN','Arn','arn','DBInstanceArn','DBClusterArn','repositoryArn','clusterArn','StackId','LoadBalancerArn','ProcessingJobArn'):
            if field in row and isinstance(row[field], str) and row[field].startswith('arn:'):
                arn = row[field]
                if not _ARN.fullmatch(arn) or f':{scope.split("/")[1]}:{scope.split("/")[0]}:' not in arn:
                    raise Unavailable('foreign ARN in ' + kind)
    if item is not None and sum(row == item for row in rows) != 1:
        raise Unavailable('subject absent or duplicated in complete inventory')
    return rows


def _policy(index, name, expected):
    value = get(get(index, 'context.metadata', dict), 'parameters', dict)
    value = get(value, name, expected)
    return value


def _positive_int(value):
    return type(value) is int and value > 0


def _date(value):
    if not isinstance(value, str):
        raise Unavailable('timestamp unavailable')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise Unavailable('malformed timestamp') from exc
    if parsed.tzinfo is None:
        raise Unavailable('timestamp timezone unavailable')
    return parsed.astimezone(timezone.utc)


def _config(item, index):
    """One account-global verdict from complete native discovery and Config reads."""
    scope = get(index, 'context.scope', str)
    if not scope.endswith('/global') or get(item, 'scope', str) != scope:
        raise Unavailable('Config account-global subject unavailable')
    account = scope.split('/')[0]
    proofs = _inventory(index, 'config_account_region_coverage')
    if len(proofs) != 1:
        raise Unavailable('unique account Config proof unavailable')
    proof = proofs[0]
    if get(proof, 'AccountId', str) != account or get(proof, 'id', str) != account:
        raise Unavailable('foreign Config account proof')
    provenance = get(proof, '_provenance', dict)
    discovery = get(proof, 'Discovery', dict)
    capture = get(index, 'context.created_at', str)
    caller = re.fullmatch(r'arn:([^:]+):(?:iam|sts)::([0-9]{12}):.+', get(discovery, 'caller_arn', str))
    if (get(provenance, 'read_only', bool) is not True or get(provenance, 'account_global_complete', bool) is not True
            or get(provenance, 'observed_at', str) != capture or get(discovery, 'observed_at', str) != capture
            or get(discovery, 'scope', str) != scope or get(discovery, 'caller_account_id', str) != account
            or get(discovery, 'source_operation', str) != 'ec2:DescribeRegions'
            or get(discovery, 'all_regions', bool) is not True or get(discovery, 'read_only', bool) is not True
            or caller is None or caller.group(1) != get(discovery, 'partition', str) or caller.group(2) != account):
        raise Unavailable('Config native account/discovery provenance unavailable')
    raw = get(discovery, 'raw_regions', list)
    from peaso.collectors.aws_config_account_native import region_partition
    seen, enabled = set(), []
    for row in raw:
        name, state = get(row, 'RegionName', str), get(row, 'OptInStatus', str)
        if (not re.fullmatch(r'[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+', name)
                or region_partition(name) != caller.group(1) or name in seen
                or state not in {'opted-in', 'opt-in-not-required', 'not-opted-in'}):
            raise Unavailable('duplicate or malformed native Region discovery')
        seen.add(name)
        if state != 'not-opted-in':
            enabled.append(name)
    # Regions an Organizations SCP denies were excluded from the scan.
    denied = discovery.get('scp_denied_regions', [])
    if not isinstance(denied, list) or any(region not in enabled for region in denied):
        raise Unavailable('malformed SCP Region exclusion')
    enabled = sorted(region for region in enabled if region not in denied)
    rows = get(proof, 'Regions', list)
    if (not enabled or get(discovery, 'regions', list) != enabled or len(rows) != len(enabled)
            or [get(row, 'RegionName', str) for row in rows] != enabled):
        raise Unavailable('Config enabled-Region proof incomplete')
    from .aws_config_recording import _recording_scope, _run_state
    failures, unresolved = [], []
    global_recording_regions = []
    unproven_global_regions = []
    legacy_global_regions = {
        "us-east-1", "us-east-2", "us-west-1", "us-west-2", "ca-central-1", "sa-east-1",
        "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "eu-south-1",
        "ap-south-1", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-southeast-1", "ap-southeast-2",
        "ap-east-1", "af-south-1", "me-south-1", "cn-north-1", "cn-northwest-1", "us-gov-west-1", "us-gov-east-1",
    }
    # Global IAM resources need recording in one eligible pre-February-2022
    # Region, not every Region. New global types use their service home Region.
    # https://docs.aws.amazon.com/config/latest/developerguide/select-resources.html
    for row in rows:
        region = get(row, 'RegionName', str)
        recorders = get(row, 'Recorders', list)
        channels = get(row, 'DeliveryChannels', list)
        if len(recorders) > 1 or len(channels) > 1:
            raise Unavailable('ambiguous Config recorder or delivery channel')
        if not recorders or not channels:
            failures.append({'region': region, 'reason': 'recorder or delivery channel absent'})
            continue
        if any(get(entry, 'AccountId', str) != account or get(entry, 'Region', str) != region
               for entry in [*recorders, *channels]):
            raise Unavailable('foreign Config regional item in account proof')
        if not get(channels[0], 'name', str):
            raise Unavailable('delivery channel identity unavailable')
        rec = recorders[0]
        name = get(rec, 'name', str)
        status = get(rec, 'Status', dict)
        if get(status, 'collection_status', str) != 'collected':
            raise Unavailable('recorder status unavailable')
        run, last = _run_state(rec, name)
        if run in {'stopped', 'failed'}:
            failures.append({'region': region, 'reason': 'recorder not recording', 'last_status': last})
            continue
        group = get(rec, 'recordingGroup', dict)
        coverage, strategy, _, excluded = _recording_scope(group)
        if coverage == 'restricted':
            failures.append({'region': region, 'reason': 'recording group restricted', 'strategy': strategy,
                             'excluded_types': excluded})
        elif run != 'running':
            unresolved.append({'region': region, 'reason': 'recorder run state unconfirmed'})
        elif region in legacy_global_regions:
            try:
                if get(group, 'includeGlobalResourceTypes', bool) is True:
                    global_recording_regions.append(region)
            except Unavailable:
                unproven_global_regions.append(region)
    if not global_recording_regions and unproven_global_regions:
        unresolved.append({'reason': 'global IAM recording flag unavailable', 'regions': unproven_global_regions})
    if not global_recording_regions and not unresolved and not failures:
        if set(enabled) & legacy_global_regions:
            failures.append({'reason': 'global IAM resource recording is disabled in every eligible audited Region'})
        else:
            unresolved.append({'reason': 'no audited Region supports legacy global IAM recording'})
    if failures:
        return result(True, account_id=account, enabled_regions=enabled, failing_regions=failures,
                      unresolved_regions=unresolved, account_wide=True)
    if unresolved:
        return unknown('Config global-resource or run-state subclaim unresolved', account_id=account,
                       enabled_regions=enabled, unresolved_regions=unresolved, account_wide=True)
    return result(False, account_id=account, enabled_regions=enabled, account_wide=True)


def _kms(item, index):
    _inventory(index, 'secret', item)
    key = get(item, 'KmsKeyId', str)
    if not key:
        return unknown('service default KMS key unresolved')
    keys = _inventory(index, 'kms_key')
    matches = [row for row in keys if key in (row.get('KeyId'), row.get('Arn'), row.get('KeyArn'))]
    if len(matches) != 1:
        return unknown('KMS key identity unresolved')
    meta = get(matches[0], 'Metadata.KeyMetadata', dict)
    if get(meta, 'KeyManager', str) not in ('AWS', 'CUSTOMER') or get(meta, 'KeyState', str) not in ('Enabled','Disabled','PendingDeletion','PendingImport','Unavailable'):
        raise Unavailable('unrecognized KMS key metadata')
    return result(meta['KeyState'] != 'Enabled', key_id=key)



def _valid_rotation_schedule(expression):
    """Conservative subset of AWS Secrets Manager's rate/cron grammar."""
    if len(expression) > 256:
        return False
    rate = re.fullmatch(r'rate\(([1-9][0-9]*) (hour|hours|day|days)\)', expression)
    if rate:
        value = int(rate.group(1))
        unit = rate.group(2)
        if (value == 1) != (not unit.endswith('s')):
            return False
        return 4 <= value <= 999 * 24 if unit.startswith('hour') else 1 <= value <= 999
    cron = re.fullmatch(r'cron\(([^()]*)\)', expression)
    if not cron:
        return False
    fields = cron.group(1).split()
    if len(fields) != 6:
        return False
    minute, hour, month_day, month, week_day, year = fields
    if minute != '0' or year != '*' or ((month_day == '?') == (week_day == '?')):
        return False

    def values(field, low, high, names=()):
        if field == '*':
            return set(range(low, high + 1))
        result = set()
        for part in field.split(','):
            endpoints = part.split('-')
            if len(endpoints) > 2 or not all(endpoints):
                return None
            numbers = []
            for endpoint in endpoints:
                if endpoint in names:
                    numbers.append(low + names.index(endpoint))
                elif re.fullmatch(r'[0-9]{1,2}', endpoint):
                    numbers.append(int(endpoint))
                else:
                    return None
            if any(number < low or number > high for number in numbers):
                return None
            if len(numbers) == 2 and numbers[0] > numbers[1]:
                return None
            result.update(range(numbers[0], numbers[-1] + 1))
        return result

    if hour.startswith('/') or '/' in hour:
        match = re.fullmatch(r'([0-9]{0,2})/([0-9]{1,2})', hour)
        if not match:
            return False
        start = int(match.group(1) or 0)
        step = int(match.group(2))
        if start > 23 or not 4 <= step <= 23:
            return False
        hours = list(range(start, 24, step))
    else:
        hours = sorted(values(hour, 0, 23) or ())
    if not hours or min(b - a for a, b in zip(hours, hours[1:] + [hours[0] + 24])) < 4:
        return False
    months = values(month, 1, 12, ('JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN',
                                    'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'))
    if not months:
        return False
    if month_day != '?' and not values(month_day, 1, 31):
        return False
    if week_day != '?' and not values(week_day, 1, 7,
                                      ('SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT')):
        return False
    return True


def _rotation(item, index):
    _inventory(index, 'secret', item)
    enabled = get(item, 'RotationEnabled', bool)
    if not enabled:
        return result(True, reason='automatic rotation disabled')
    rules_marker = item.get('_coverage', {}).get('RotationRules')
    if 'RotationRules' not in item and isinstance(rules_marker, dict) and (
            rules_marker.get('status') == 'empty' and
            rules_marker.get('source_operation') == 'secretsmanager:DescribeSecret' and
            rules_marker.get('native_member_present') is False):
        rules = {}
    else:
        rules = get(item, 'RotationRules', dict)
    # Read each present fact through the strict accessor, including nested
    # coverage. An unreadable or malformed alternate cannot be ignored merely
    # because the other schedule form looks valid.
    schedule = optional(rules, 'ScheduleExpression', None, str)
    days = optional(rules, 'AutomaticallyAfterDays', None, int)
    if schedule is not None and not _valid_rotation_schedule(schedule):
        raise Unavailable('rotation schedule is malformed or outside the supported grammar')
    if days is not None and not _positive_int(days):
        raise Unavailable('malformed rotation schedule')
    if schedule is None and days is None:
        return result(True, reason='rotation schedule absent')

    required = (get(item, 'RotationLambdaRequired', bool) if
                'RotationLambdaRequired' in item or 'RotationLambdaRequired' in item.get('_coverage', {}) else None)
    lambda_arn = (get(item, 'RotationLambdaARN', str) if
                  'RotationLambdaARN' in item or 'RotationLambdaARN' in item.get('_coverage', {}) else None)
    owner = (get(item, 'OwningService', str) if
             'OwningService' in item or 'OwningService' in item.get('_coverage', {}) else None)
    if lambda_arn is not None and not lambda_arn:
        raise Unavailable('malformed rotation Lambda ARN')
    if owner is not None and not owner:
        raise Unavailable('malformed owning service')
    if required is True and not lambda_arn:
        if owner == 'rds':
            raise Unavailable('rotation method evidence contradictory')
        return result(True, reason='required rotation Lambda absent')
    # RDS-owned managed secret rotation is native and does not use a Lambda.
    # A new PASS requires a DescribeSecret-bound witness; retain the legacy
    # explicit requirement contract for callers that already supply it.
    coverage = item.get('_coverage', {})
    def native(field):
        marker = coverage.get(field)
        return (isinstance(marker, dict) and marker.get('status') == 'collected'
                and marker.get('source_operation') == 'secretsmanager:DescribeSecret')
    if required is False or (lambda_arn and (native('RotationLambdaARN') or required is not None)):
        return result(False, rotation_enabled=enabled)
    if owner == 'rds' and native('OwningService'):
        return result(False, rotation_enabled=enabled)
    return unknown('rotation method or managed owner unavailable')


def _redshift(item, index):
    _inventory(index, 'redshift_cluster', item)
    approved = _policy(index, 'redshift_expected_settings', dict)
    if not approved or set(approved) != {'cluster_fields','parameters'} or not isinstance(approved['cluster_fields'], dict) or not isinstance(approved['parameters'], dict) or not (approved['cluster_fields'] or approved['parameters']):
        raise Unavailable('approved setting map unavailable')
    groups = get(item, 'ClusterParameterGroups', list)
    if any(not isinstance(g, dict) or not isinstance(g.get('ParameterGroupName'), str) for g in groups):
        raise Unavailable('malformed parameter group list')
    if len({g['ParameterGroupName'] for g in groups}) != len(groups):
        raise Unavailable('duplicate Redshift parameter group')
    actual = get(item, 'ClusterParameterValues', dict)
    if set(actual) != {g['ParameterGroupName'] for g in groups}:
        raise Unavailable('parameter group detail incomplete')
    mismatches = []
    for field, expected in approved['cluster_fields'].items():
        if not isinstance(field, str) or '.' in field or field not in item:
            raise Unavailable('named cluster field unavailable')
        if get(item, field) != expected:
            mismatches.append(field)
    for group in groups:
        name = group['ParameterGroupName']
        params = get(actual, name, dict)
        for param, expected in approved['parameters'].items():
            if get(params, param) != expected:
                mismatches.append(name + '/' + param)
    return result(bool(mismatches), mismatched_settings=mismatches)


def _elb_policy_source(item, index, field, request):
    from peaso.collectors.aws_classic_elb_policies_native import OPERATION, policy_rows
    source = get(item, field, dict)
    if get(source, 'collection_status', str) != 'collected':
        raise Unavailable('ELB policy source incomplete: ' + field)
    provenance = get(source, '_provenance', dict)
    scope = get(index, 'context.scope', str)
    account, region = scope.split('/')
    captured = _date(get(provenance, 'captured_at', str))
    if (get(provenance, 'operation', str) != OPERATION or get(provenance, 'account_id', str) != account
            or get(provenance, 'region', str) != region or get(provenance, 'request', dict) != request
            or get(provenance, 'read_only', bool) is not True
            or captured != _date(get(index, 'context.created_at', str))):
        raise Unavailable('ELB policy request/capture binding mismatch')
    try:
        return policy_rows(get(source, 'PolicyDescriptions', list))
    except ValueError as exc:
        raise Unavailable(str(exc)) from exc


def _elb(item, index, custom):
    from peaso.collectors.aws_classic_elb_policies_native import SSL_TYPE, tls_names
    _inventory(index, 'classic_elb', item)
    try:
        names = tls_names(item)
    except ValueError as exc:
        raise Unavailable(str(exc)) from exc
    if not names:
        return 'NOT_APPLICABLE', {'reason': 'no HTTPS or SSL listener'}
    approved = _policy(index, 'classic_elb_custom_ssl_policy', dict) if custom else None
    if custom and (not approved or not all(isinstance(k, str) and k and isinstance(v, str) for k, v in approved.items())):
        raise Unavailable('approved custom SSL policy unavailable')
    policies = _elb_policy_source(item, index, 'SSLPolicyDetails',
        {'LoadBalancerName': get(item, 'LoadBalancerName', str), 'PolicyNames': names})
    by_name = {policy['PolicyName']: policy for policy in policies}
    if set(by_name) != set(names):
        raise Unavailable('ELB policy detail references incomplete or foreign')
    catalog = {} if custom else {policy['PolicyName']: policy for policy in
        _elb_policy_source(item, index, 'SSLPolicyCatalog', {})}
    known_types = {SSL_TYPE, 'ProxyProtocolPolicyType', 'AppCookieStickinessPolicyType',
                   'LBCookieStickinessPolicyType', 'BackendServerAuthenticationPolicyType', 'PublicKeyPolicyType'}
    unsafe, unresolved = [], []
    for listener in get(item, 'ListenerDescriptions', list):
        if listener['Listener']['Protocol'] not in ('HTTPS', 'SSL'):
            continue
        matched, equivalent_reference = False, False
        for name in listener['PolicyNames']:
            policy = by_name[name]
            if policy['PolicyTypeName'] not in known_types:
                raise Unavailable('unknown ELB policy type')
            if policy['PolicyTypeName'] != SSL_TYPE:
                continue
            values = {a['AttributeName']: a['AttributeValue'] for a in policy['PolicyAttributeDescriptions']}
            if custom:
                matched |= values == approved
            else:
                native = catalog.get(name)
                matched |= native is not None and native == policy
                # AWS permits a customer name when referencing a predefined
                # policy. Equal settings alone cannot prove that reference.
                equivalent_reference |= any(
                    sample['PolicyTypeName'] == SSL_TYPE
                    and sample['PolicyAttributeDescriptions'] == policy['PolicyAttributeDescriptions']
                    for sample in catalog.values())
        if not matched:
            (unresolved if equivalent_reference else unsafe).append(get(listener, 'Listener.LoadBalancerPort', int))
    if unresolved and not unsafe:
        return unknown('equivalent predefined settings have no verified policy reference', listener_ports=unresolved)
    return result(bool(unsafe), listener_ports=unsafe,
        semantics='Effective approved SSL configuration; historical policy creator/origin and live TLS behavior unverified'
        if custom else 'Exact provider sample catalog name/type/attributes; historical policy creator/origin and live TLS behavior unverified')


def _vpn(item, index):
    if get(item, 'scope', str) != get(index, 'context.scope', str):
        raise Unavailable('VPN scope subject mismatch')
    vpns = _inventory(index, 'vpn_connection')
    clients = _inventory(index, 'client_vpn_endpoint')
    unsafe = []
    active_sites = 0
    for vpn in vpns:
        state = get(vpn, 'State', str)
        if state not in ('available','pending','deleting','deleted'):
            raise Unavailable('unrecognized VPN state')
        if state != 'available':
            continue
        active_sites += 1
        tunnels = get(vpn, 'Options.TunnelOptions', list)
        if len(tunnels) != 2:
            raise Unavailable('Site-to-Site tunnel inventory unavailable')
        for n,tunnel in enumerate(tunnels):
            for phase in ('Phase1EncryptionAlgorithms','Phase2EncryptionAlgorithms'):
                algorithms = get(tunnel, phase, list)
                if not algorithms:
                    unsafe.append((get(vpn,'VpnConnectionId',str),n))
                for algorithm in algorithms:
                    value = get(algorithm, 'Value', str)
                    if value in ('AES128','DES'):
                        unsafe.append((get(vpn,'VpnConnectionId',str),n))
    unsafe_clients = []
    active_clients = 0
    for client in clients:
        if get(client, 'Status.Code', str) != 'available':
            continue
        active_clients += 1
        certificate = get(client, 'ServerCertificateArn', str)
        transport = get(client, 'TransportProtocol', str)
        if not certificate or transport not in ('tcp', 'udp'):
            unsafe_clients.append(get(client, 'ClientVpnEndpointId', str))
    if not active_sites and not active_clients:
        return 'NOT_APPLICABLE', {'reason':'no available Site-to-Site or Client VPN'}
    return result(bool(unsafe or unsafe_clients), unsafe_tunnels=sorted(set(unsafe)), unsafe_client_vpns=unsafe_clients)



def _observed_environment_workloads(index, policy):
    """Validate a definite EC2 counterexample without certifying its universe."""
    from peaso.collectors.aws_environment_boundaries_native import normalize, owner_metadata, NAMESPACE
    context = get(index, 'context', dict)
    scope = get(context, 'scope', str)
    parameters = get(context, 'metadata.parameters', dict)
    try:
        owner = normalize({'compliance_parameters': {NAMESPACE: parameters[NAMESPACE]}}, [scope])
        approved = owner_metadata(owner, _date(get(context, 'created_at', str)))
    except (KeyError, ValueError, TypeError, OverflowError):
        raise Unavailable('current native environment classification authority unavailable') from None
    if approved.get('environment_boundaries') != policy:
        raise Unavailable('native environment owner criteria stale or competing')
    kind = 'environment_workload_resource'
    envelopes = get(index, 'collections', dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable('native environment observation envelope unavailable')
    envelope = envelopes[0]
    if (not isinstance(envelope, dict) or envelope.get('type') != kind or envelope.get('scope') != scope
            or envelope.get('status') != 'partial'
            or not isinstance(envelope.get('items'), list)):
        raise Unavailable('native environment observation scope unavailable')
    rows = envelope['items']
    wrappers = get(index, kind, list)
    if (not rows or len(rows) > 4096 or len(wrappers) != len(rows)
            or any(not isinstance(w, dict) or w.get('type') != kind or w.get('scope') != scope
                   or w.get('data') != row for w, row in zip(wrappers, rows))):
        raise Unavailable('native environment observation projection mismatch')
    account, region = scope.split('/')
    partition = 'aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'
    classifications = {r['resource_arn']: r['environment'] for r in owner['workload_classifications']}
    seen = set()
    for row in rows:
        guard(row)
        identifier = get(row, 'ResourceId', str)
        arn = get(row, 'id', str)
        provenance = get(row, '_provenance', dict)
        if (not re.fullmatch(r'i-(?:[0-9a-f]{8}|[0-9a-f]{17})', identifier)
                or arn != f'arn:{partition}:ec2:{region}:{account}:instance/{identifier}' or arn in seen
                or row.get('ResourceKind') != 'instance' or row.get('BoundaryId') != account
                or row.get('AccountId', account) != account or row.get('Region', region) != region
                or row.get('Environment') not in ('production', 'development', 'test')
                or classifications.get(arn) != row.get('Environment')
                or set(provenance) != {'source_operation', 'read_only', 'classification_source', 'native_scope'}
                or provenance['source_operation'] != 'ec2:DescribeInstances' or provenance['read_only'] is not True
                or provenance['classification_source'] != 'explicit_owner_criteria' or provenance['native_scope'] != scope):
            raise Unavailable('foreign, ambiguous or non-native environment observation')
        seen.add(arn)
    return rows


def _separation(item, index):
    _inventory(index, 'aws_organization_account', item)
    policy = _policy(index, 'environment_boundaries', dict)
    if (set(policy) != {'production','development'} or
            any(not isinstance(v,list) or not v or any(not isinstance(x,str) or not x for x in v) for v in policy.values())):
        raise Unavailable('approved environment boundary policy unavailable')
    partial = False
    try:
        resources = _inventory(index, 'environment_workload_resource')
    except Unavailable:
        resources = _observed_environment_workloads(index, policy)
        partial = True
    if not resources or not all(isinstance(row,dict) for row in resources):
        raise Unavailable('environment tag inventory unavailable')
    prod, dev = set(), set()
    for row in resources:
        env = get(row, 'Environment', str)
        boundary = get(row, 'BoundaryId', str)
        if env not in ('production','development','test') or not boundary:
            raise Unavailable('environment mapping incomplete')
        approved = policy['production' if env == 'production' else 'development']
        if boundary not in approved:
            return result(True, unapproved_boundary=boundary)
        (prod if env == 'production' else dev).add(boundary)
    if not prod or not dev:
        raise Unavailable('both environment inventories required')
    if prod & dev:
        return result(True, shared_boundaries=sorted(prod & dev))
    if partial:
        raise Unavailable('complete environment workload and connectivity inventories required for PASS')
    links = _inventory(index, 'environment_boundary_link')
    for link in links:
        left,right = get(link,'SourceBoundaryId',str),get(link,'DestinationBoundaryId',str)
        if get(link,'Reachable',bool) and ((left in prod and right in dev) or (left in dev and right in prod)):
            return result(True, cross_boundary_link=(left,right))
    return result(False)


def _recovery(item, index):
    _inventory(index, 'recovery_group', item)
    members = get(item, 'Members', list)
    if not members:
        raise Unavailable('approved recovery group members unavailable')
    identities = [(get(member,'Kind',str),get(member,'Id',str)) for member in members]
    if len(identities) != len(set(identities)) or any(not identity for _, identity in identities):
        raise Unavailable('duplicate or malformed recovery group member')
    instances = _inventory(index, 'instance')
    dbs = _inventory(index, 'rds_instance')
    zones = set()
    for member in members:
        kind, identity = get(member,'Kind',str), get(member,'Id',str)
        rows = instances if kind == 'instance' else dbs if kind == 'rds_instance' else None
        if rows is None:
            raise Unavailable('unsupported recovery member kind')
        matches = [row for row in rows if row.get('InstanceId' if kind == 'instance' else 'DBInstanceIdentifier') == identity]
        if len(matches) != 1:
            raise Unavailable('recovery member placement unavailable')
        row = matches[0]
        if kind == 'instance':
            state = get(row,'State.Name',str)
            if state not in ('pending','running','shutting-down','terminated','stopping','stopped'):
                raise Unavailable('unrecognized EC2 recovery member state')
            if state == 'running':
                zones.add(get(row,'Placement.AvailabilityZone',str))
        else:
            state = get(row,'DBInstanceStatus',str)
            if state not in ('available','creating','deleting','modifying','stopped','stopping','starting','failed','inaccessible-encryption-credentials'):
                raise Unavailable('unrecognized RDS recovery member state')
            if state == 'available':
                zones.add(get(row,'AvailabilityZone',str))
    if '' in zones:
        raise Unavailable('empty availability zone')
    return result(len(zones) < 2, availability_zones=sorted(zones))


def _rds(item, index):
    instances = _inventory(index, 'rds_instance', item)
    clusters = _inventory(index, 'rds_cluster')
    identities = {get(row,'DBInstanceIdentifier',str) for row in instances}
    if len(identities) != len(instances):
        raise Unavailable('duplicate RDS instance identity')
    for cluster in clusters:
        for member in get(cluster,'DBClusterMembers',list):
            if get(member,'DBInstanceIdentifier',str) not in identities:
                raise Unavailable('cluster member inventory incomplete')
    interval = get(item,'MonitoringInterval',int)
    if interval < 0:
        raise Unavailable('invalid monitoring interval')
    role = get(item,'MonitoringRoleArn',str)
    resource = get(item,'EnhancedMonitoringResourceArn',str)
    return result(interval == 0 or not role or not resource, monitoring_interval=interval)


def _drift(item, index):
    _inventory(index, 'cloudformation_stack', item)
    days = _policy(index, 'cloudformation_max_drift_age_days', int)
    if not _positive_int(days):
        raise Unavailable('approved drift age unavailable')
    detail = get(item,'DriftDetection',dict)
    if get(detail,'DetectionStatus',str) != 'DETECTION_COMPLETE':
        return unknown('completed drift detection unavailable')
    age = (_date(get(index,'context.created_at',str)) - _date(get(detail,'DetectionTime',str))).total_seconds()/86400
    if age < 0:
        raise Unavailable('drift detection after snapshot capture')
    status = get(detail,'StackDriftStatus',str)
    if status not in ('IN_SYNC','DRIFTED','NOT_CHECKED','UNKNOWN'):
        raise Unavailable('unrecognized stack drift status')
    if status in ('NOT_CHECKED','UNKNOWN'):
        return unknown('drift status unresolved')
    return result(age > days or status == 'DRIFTED', drift_age_days=age, drift_status=status)


def _ecs(item, index):
    _inventory(index, 'ecs_cluster', item)
    services = _inventory(index, 'ecs_service')
    definitions = _inventory(index, 'ecs_task_definition')
    efs = _inventory(index, 'efs_file_system')
    cluster = get(item,'clusterArn',str)
    scope = get(index, 'context.scope', str)
    account, region = scope.split('/')
    cluster_match = re.fullmatch(r'arn:(aws|aws-us-gov|aws-cn):ecs:' + re.escape(region) +
                                r':' + re.escape(account) + r':cluster/[^/]+', cluster)
    if cluster_match is None:
        raise Unavailable('ECS cluster identity unavailable')
    partition = cluster_match.group(1)
    related = [s for s in services if get(s,'clusterArn',str) == cluster]
    bad = []
    for service in related:
        configurations = get(service,'volumeConfigurations',list)
        coverage = get(service,'_coverage.volumeConfigurations',dict)
        service_arn = get(service,'serviceArn',str)
        service_match = re.fullmatch(r'arn:' + partition + r':ecs:' + re.escape(region) +
                                    r':' + re.escape(account) + r':service/(?:[^/]+/)?[^/]+', service_arn)
        if service_match is None:
            raise Unavailable('ECS service identity unavailable')
        if (coverage.get('status') not in {'empty', 'collected'} or
                (coverage.get('source_operation'), coverage.get('deployment_status')) not in {('ecs:DescribeServices', 'PRIMARY'), ('ecs:DescribeServiceRevisions', 'CURRENT')} or
                coverage.get('native_member_present') is not (coverage['status'] == 'collected') or
                (coverage['status'] == 'empty' and configurations != []) or
                coverage.get('account_id') != scope.split('/')[0] or
                coverage.get('region') != scope.split('/')[1] or
                coverage.get('service_arn') != get(service,'serviceArn',str) or
                coverage.get('cluster_arn') != cluster or
                coverage.get('task_definition_arn') != get(service,'taskDefinition',str)):
            raise Unavailable('service deployment volume provenance unavailable')
        if coverage.get('source_operation') == 'ecs:DescribeServiceRevisions':
            revision_arn = get(service, 'VolumeConfigurationServiceRevisionArn', str)
            summaries = list_of_objects(get(service, 'currentServiceRevisions', list))
            active = []
            for summary in summaries:
                counts = [get(summary, key, int) for key in ('requestedTaskCount', 'runningTaskCount', 'pendingTaskCount')]
                if any(value < 0 for value in counts):
                    raise Unavailable('negative service revision task counts')
                if any(counts):
                    active.append(get(summary, 'arn', str))
            prefix = f'arn:{partition}:ecs:{region}:{account}:service-revision/' + service_arn.split(':service/', 1)[-1] + '/'
            if (active != [revision_arn] or coverage.get('service_revision_arn') != revision_arn
                    or not revision_arn.startswith(prefix)):
                raise Unavailable('service revision volume binding unavailable')
        arn = get(service,'taskDefinition',str)
        if not re.fullmatch(r'arn:' + partition + r':ecs:' + re.escape(region) +
                            r':' + re.escape(account) + r':task-definition/[^:]+:[0-9]+', arn):
            raise Unavailable('foreign or malformed task definition ARN')
        matches = [d for d in definitions if get(d,'taskDefinitionArn',str) == arn]
        if len(matches) != 1:
            raise Unavailable('task definition join unavailable')
        if (get(matches[0], 'Definition.collection_status', str) != 'collected' or
                get(matches[0], 'Definition.taskDefinition.taskDefinitionArn', str) != arn):
            raise Unavailable('task definition detail identity unavailable')
        volumes = get(matches[0],'Definition.taskDefinition.volumes',list)
        launch_names = []
        for volume in volumes:
            guard(volume)
            if 'configuredAtLaunch' in volume or 'configuredAtLaunch' in volume.get('_coverage', {}):
                launch = get(volume,'configuredAtLaunch',bool)
            else:
                launch = False
            if launch is True:
                launch_names.append(get(volume,'name',str))
        config_names = [get(config,'name',str) for config in configurations]
        if (len(config_names) != len(set(config_names)) or
                len(launch_names) != len(set(launch_names)) or
                set(config_names) != set(launch_names)):
            raise Unavailable('service launch-volume configuration join unavailable')
        for config in configurations:
            get(config,'managedEBSVolume',dict)
            if not get(config,'managedEBSVolume.encrypted',bool):
                bad.append(get(service,'serviceArn',str))
        for volume in volumes:
            if 'efsVolumeConfiguration' not in volume and 'efsVolumeConfiguration' not in volume.get('_coverage', {}):
                continue
            get(volume,'efsVolumeConfiguration',dict)
            fsid = get(volume,'efsVolumeConfiguration.fileSystemId',str)
            found = [f for f in efs if get(f,'FileSystemId',str) == fsid]
            if len(found) != 1:
                raise Unavailable('EFS join unavailable')
            if not get(found[0],'Encrypted',bool):
                bad.append(fsid)
    return result(bool(bad), unencrypted_volumes=bad)


def _userdata(item, index):
    _inventory(index, 'autoscaling_launch_configuration', item)
    indicators = get(item,'UserDataIndicators',dict)
    if get(indicators,'InspectionStatus',str) != 'collected':
        return unknown('user data could not be read or decoded')
    return result(found := get(indicators,'HasAwsKeyPair',bool), has_aws_key_pair=found)


def _clarify(item, index):
    if get(item, 'scope', str) != get(index, 'context.scope', str):
        raise Unavailable('SageMaker scope subject mismatch')
    endpoints = _inventory(index, 'sagemaker_endpoint')
    schedules = _inventory(index, 'sagemaker_monitoring_schedule')
    jobs = _inventory(index, 'sagemaker_processing_job')
    days = _policy(index, 'clarify_monitoring_interval_days', int)
    if not _positive_int(days):
        raise Unavailable('approved monitoring interval unavailable')
    capture = _date(get(index,'context.created_at',str))
    if any(not isinstance(e.get('EndpointName'),str) or not e['EndpointName'] for e in endpoints):
        raise Unavailable('endpoint identity incomplete')
    if len({e['EndpointName'] for e in endpoints}) != len(endpoints):
        raise Unavailable('duplicate SageMaker endpoint')
    if any(get(e,'ModelLinkageStatus',str) != 'verified' for e in endpoints):
        raise Unavailable('endpoint-to-model linkage unavailable')
    if any(not isinstance(s.get('EndpointName'),str) or not s['EndpointName'] or
           s.get('MonitoringScheduleStatus') not in {'Pending', 'Failed', 'Scheduled', 'Stopped'} for s in schedules):
        raise Unavailable('monitoring schedule identity or status incomplete')
    for job in jobs:
        status = get(job, 'ProcessingJobStatus', str)
        if status not in {'InProgress', 'Completed', 'Failed', 'Stopping', 'Stopped'}:
            raise Unavailable('processing job status incomplete')
        image = get(job, 'AppSpecification.ImageUri', str)
        if not image:
            raise Unavailable('processing job image unavailable')
        # Native non-Clarify image evidence cannot satisfy this predicate and
        # does not require a fabricated endpoint identity.
        if 'clarify' not in image.lower() and job.get('EndpointLinkageStatus') == 'not_clarify':
            continue
        if (not isinstance(job.get('EndpointName'), str) or not job['EndpointName']
                or job.get('EndpointLinkageStatus') == 'unresolved'):
            raise Unavailable('processing job endpoint linkage incomplete')
    if not endpoints:
        return 'NOT_APPLICABLE', {'reason':'no in-scope SageMaker endpoint'}
    failures = []
    for endpoint in endpoints:
        linked = get(endpoint,'EndpointName',str)
        applicable = [s for s in schedules if s.get('EndpointName') == linked]
        if not any(get(s,'MonitoringScheduleStatus',str) == 'Scheduled' for s in applicable):
            failures.append((linked,'schedule'))
            continue
        recent = False
        for job in jobs:
            if job.get('EndpointLinkageStatus') == 'not_clarify' or job.get('EndpointName') != linked or get(job,'ProcessingJobStatus',str) != 'Completed':
                continue
            uri = get(job,'AppSpecification.ImageUri',str)
            if 'clarify' not in uri.lower() or not get(job,'EndpointLinkedInput',bool):
                continue
            age = (capture - _date(get(job,'CreationTime',str))).total_seconds()/86400
            recent |= 0 <= age <= days
        if not recent:
            failures.append((linked,'recent_clarify_job'))
    return result(bool(failures), failing_endpoints=failures)


def _ecr(item, index):
    _inventory(index, 'ecr_repository', item)
    days = _policy(index, 'ecr_retention_days', int)
    if not _positive_int(days):
        raise Unavailable('approved ECR retention threshold unavailable')
    policy = get(item,'LifecyclePolicy',dict)
    raw = get(policy,'lifecyclePolicyText',str)
    try:
        doc = json.loads(raw)
    except ValueError as exc:
        raise Unavailable('malformed ECR lifecycle policy') from exc
    if not isinstance(doc, dict) or not isinstance(doc.get('rules'),list):
        raise Unavailable('malformed lifecycle rules')
    suitable = False
    for rule in doc['rules']:
        selection = get(rule,'selection',dict)
        action = get(rule,'action',dict)
        if selection.get('tagStatus') == 'any' and selection.get('countType') == 'sinceImagePushed' and selection.get('countUnit') == 'days' and action.get('type') == 'expire':
            count = get(selection,'countNumber',int)
            if not _positive_int(count):
                raise Unavailable('invalid lifecycle age')
            suitable |= count <= days
    return result(not suitable, retention_days=days)

EVALUATORS = {
'aws_nist_config_enabled_all_regions': _config,
'aws.pci.secretsmanager.kms_encryption_any': _kms,
'aws_nist_secretsmanager_secret_automatic_rotation_enabled': _rotation,
'aws.pci.redshift.expected_settings': _redshift,
'aws.pci.classic_elb.custom_ssl_policy': lambda i,x: _elb(i,x,True),
'aws.pci.classic_elb.predefined_ssl_policy': lambda i,x: _elb(i,x,False),
'aws_vpn_tunnel_encryption_configuration': _vpn,
'aws_organizations_environment_account_separation': _separation,
'aws.nist.sc_36_coverage': _recovery,
'aws_nist_rds_db_instance_and_cluster_enhanced_monitoring_enabled': _rds,
'aws_nist_cloudformation_stack_drift_detection_check': _drift,
'aws_g6_ecs_fargate_storage_encryption': _ecs,
'aws_autoscaling_userdata_plaintext_aws_key': _userdata,
'aws_sagemaker_model_clarify_bias_job': _clarify,
'aws_ecr_repository_lifecycle_retention': _ecr,
}
DEPENDENCIES = {
'aws_nist_config_enabled_all_regions':['config_account_region_coverage'],
'aws.pci.secretsmanager.kms_encryption_any':['secret','kms_key'],
'aws.pci.classic_elb.custom_ssl_policy':['classic_elb'],
'aws.pci.classic_elb.predefined_ssl_policy':['classic_elb'],
'aws_vpn_tunnel_encryption_configuration':['vpn_connection','client_vpn_endpoint'],
'aws_organizations_environment_account_separation':['aws_organization_account','environment_workload_resource','environment_boundary_link'],
'aws.nist.sc_36_coverage':['recovery_group','instance','rds_instance'],
'aws_nist_rds_db_instance_and_cluster_enhanced_monitoring_enabled':['rds_instance','rds_cluster'],
'aws_g6_ecs_fargate_storage_encryption':['ecs_cluster','ecs_service','ecs_task_definition','efs_file_system'],
'aws_sagemaker_model_clarify_bias_job':['sagemaker_processing_job','sagemaker_endpoint','sagemaker_monitoring_schedule'],
}

def _install(identifier, spec):
    kind, category, severity, title, sha, remediation = spec
    @register(identifier,'aws',category if category != 'compliance' else 'hardening',kind,title,severity,'CM-6',remediation,
              target='scope' if identifier in ('aws_nist_config_enabled_all_regions','aws_vpn_tunnel_encryption_configuration','aws_sagemaker_model_clarify_bias_job') else 'resource',
              dependencies=DEPENDENCIES.get(identifier,[kind]))
    def check(item,index):
        return EVALUATORS[identifier](item,index)
    check.__name__ = identifier.replace('.','_')
    if identifier == 'aws_nist_config_enabled_all_regions':
        check.evaluation_scope = 'aws_account'
    if CHECKS[-1].id != identifier:
        raise RuntimeError('unexpected check registry order')
    object.__setattr__(CHECKS[-1],'category',category)
    return check

for _identifier,_spec in SPECS.items():
    _install(_identifier,_spec)
