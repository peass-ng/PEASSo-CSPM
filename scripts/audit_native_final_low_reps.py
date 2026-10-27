#!/usr/bin/env python3
"""Conservative source proof for the exact-992 low-representative audit slice.

This reads sanitized numeric/source inventories and installed evaluator source.
It never loads a cloud snapshot, finding evidence values, or model credentials.
"""
import argparse
import ast
import hashlib
import inspect
import json
from pathlib import Path
import sys
import textwrap


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SAFE_CALLS = frozenset({
    'get', 'result', 'unknown', 'isinstance', 'any', 'all', 'len', 'bool',
    'str', 'int', 'set', 'sorted', 'list', 'dict', 'tuple', 'values', 'items',
    'startswith', 'endswith', 'strip', 'lower', 'upper', 'issubset',
    'append', 'count', 'split', 'type', 'sum', 'Unavailable', 'setdefault', 'add',
})
# These names only locate source for provisional candidates. They never make a
# check source-proven; helper chains and optional omissions need separate proof.
CANDIDATE_HELPERS = frozenset({
    'list_of_objects', 'optional', 'absent_or', 'api_optional', 'csv_boolean',
    'password_row', 'complete_items', 'scope_subject', 'home', 'stage',
    'method_settings', 'config', 'viewer_http', 'setting', 'threat_mode',
    'project', 'task', 'certificate', 'lb_attrs', 'lb_attribute',
    '_backup_status', '_insights', 'cluster', '_workgroup', '_cfg',
    '_type', '_viewer_policy', '_settings', '_methods', '_default_data',
    'volume_state', 'access_keys', 'flag', 'split_name', 'strings',
    'encryption_rules', 'section', 'versioning_enabled', 'detector_enabled',
    'customer', 'collected', '_attrs', '_native_optional', '_enabled_lifecycle_rules',
    '_wg_conf', '_wg_enabled', '_wg_encryption', '_origins', '_listeners',
    '_protocol', '_policy', '_tls_listeners', 'detail', 'detail_list',
    '_table_body', 'cluster_body', 'empty', 'meta', 'prowler_flags', 'reader',
    'origins', '_observed_project', '_artifact_setting',
})
# These helpers interpret policy documents, findings or unproved index joins.
# The decision follows their source behavior, irrespective of check ID spelling.
BOUND_REGISTRATIONS = frozenset({
    'aws.a.cloudwatch.any_state_actions',
    'aws.b.cloudfront.access_logging', 'aws.b.cloudfront.sni',
    'aws.b.cognito.no_guest_identities', 'aws.b.dynamodb.deletion_protection',
    'aws.b.dynamodb.point_in_time_recovery', 'aws.b.lambda.active_tracing',
    'aws.b.rds_instance.iam_authentication', 'aws.b.rds_instance.snapshot_tags',
    'aws.b.ssm.parameter_secure_type', 'aws.cloudtrail.kms_encryption',
    'aws.lambda.vpc_configuration', 'aws.sns.kms_encryption',
})
MANUAL_RETAIN = {
    'aws.b.ecr.lifecycle_rules':
        'peaso/checks/aws_b_ecr.py:23 parses lifecyclePolicyText with json.loads; '
        'this is serialized policy content, so rule-presence inference remains AI-reviewed.',
    'aws.b.dynamodb.kms_description':
        'SSEDescription omission at peaso/checks/aws_b_regional.py:87 uses dict.get; '
        'the independent review has not proved that the recorded Table response '
        'is complete for this optional field.',
    'aws.b.lambda.reserved_concurrency':
        'Missing ReservedConcurrentExecutions at peaso/checks/aws_b_core.py:139 '
        'is a failing branch; the independent review has not pinned the '
        'GetFunctionConcurrency omission receipt for this response.',
}
SPECIAL_SOURCE_PINS = {
    'peaso/checks/aws_a_iam.py': '87eb85344dfae79d426809f9b711ff06ff5accbecbeb27d879fc2f46a8373168',
    'peaso/checks/aws_a_facts.py': '6499b70ab725fe55edafa8adf436ffd50aab99cd5c105e67dcfdb15e615d339d',
    'peaso/checks/claude2_aws_b_edge.py': '7302840c0c26e9967f88fc0b2e057c9bbdd46a18920ace663ae2337d52dbc54e',
    'peaso/collectors/aws_b_services.py': '5fb58e5f02d8a05f41a70258a2a5108b88334bc165f59b443e5910b7689c10a3',
}


def call_name(node):
    function = node.func
    if isinstance(function, ast.Name):
        return function.id
    if isinstance(function, ast.Attribute):
        return function.attr
    return '<dynamic>'


def proof(check, inventory, field_specs):
    from peaso.checks import CHECKS
    registered = next((row for row in CHECKS if row.id == check['check_id']), None)
    if registered is None:
        raise ValueError('missing registered evaluator: ' + check['check_id'])
    function = inspect.unwrap(registered.evaluate)
    raw, start = inspect.getsourcelines(function)
    body = ''.join(raw)
    relative = str(Path(inspect.getsourcefile(function)).resolve().relative_to(ROOT))
    evaluator_hash = hashlib.sha256(body.encode()).hexdigest()
    if (inventory['evaluator_source_sha256'] != evaluator_hash
            or inventory['native_fail_count'] != check['native_fail_count']
            or inventory['initial_representatives'] != check['initial_representatives']):
        raise ValueError('source or exact-992 count changed: ' + check['check_id'])
    syntax = ast.parse(textwrap.dedent(body))
    definition = next((node for node in ast.walk(syntax)
                       if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))), None)
    if definition is None:
        raise ValueError('evaluator has no source function: ' + check['check_id'])
    nodes = [node for statement in definition.body for node in ast.walk(statement)]
    calls = [{'name': call_name(node), 'line': start + node.lineno - 1}
             for node in nodes if isinstance(node, ast.Call)]
    fields = [{'path': node.args[1].value, 'line': start + node.lineno - 1}
              for node in nodes if isinstance(node, ast.Call) and call_name(node) == 'get'
              and len(node.args) > 1 and isinstance(node.args[1], ast.Constant)
              and isinstance(node.args[1].value, str)]
    spec = field_specs.get(check['check_id'])
    if spec:
        fields.append({'path': spec['path'], 'line': start + definition.lineno - 1,
                       'binding': 'FIELD_SPECS registration'})
    result_lines = sorted({start + node.lineno - 1 for node in nodes
                           if isinstance(node, ast.Call) and call_name(node) == 'result'})
    predicates = [
        {'line': start + node.lineno - 1,
         'expression': ast.get_source_segment(textwrap.dedent(body), node.args[0])}
        for node in nodes if isinstance(node, ast.Call) and call_name(node) == 'result'
        and node.args
    ]
    index_read = next((start + node.lineno - 1 for node in nodes
                       if isinstance(node, ast.Name) and node.id == 'index'
                       and isinstance(node.ctx, ast.Load)), None)
    helper_refs = []
    unresolved = []
    for call in calls:
        name = call['name']
        if name == 'acceptable' and check['check_id'].startswith('aws.a.iam.password_policy_'):
            continue  # PASSWORD_SPECS: fixed bool/threshold lambdas, lines 12-20.
        if name in SAFE_CALLS or name in {'get', 'result', 'unknown'}:
            continue
        target = function.__globals__.get(name)
        if name in CANDIDATE_HELPERS and inspect.isfunction(target):
            lines, helper_start = inspect.getsourcelines(target)
            path = str(Path(inspect.getsourcefile(target)).resolve().relative_to(ROOT))
            approved_helper = ((check['check_id'].startswith('aws.a.iam.password_policy_')
                                and name in {'password_row', 'scope_subject'})
                               or (check['check_id'] == 'aws.c2b.cloudfront.custom_ssl_certificate'
                                   and name == '_cfg'))
            helper_refs.append({'path': path, 'lines': f'{helper_start}-{helper_start + len(lines) - 1}',
                                'symbol': target.__name__,
                                'source_file_sha256': hashlib.sha256((ROOT / path).read_bytes()).hexdigest(),
                                'purpose': ('reviewed strict field/complete collection helper' if approved_helper
                                            else 'candidate helper source; chain and omissions unverified')})
        else:
            unresolved.append(call)
    unsupported = unresolved[0] if unresolved else None
    # A proof here is deliberately narrow. Helpers and scoped joins can be
    # admitted only after a separate exact code-path and completeness review.
    binding_line = None
    binding_path = None
    if check['check_id'] in BOUND_REGISTRATIONS or spec:
        for candidate in sorted((ROOT / 'peaso/checks').glob('*.py')):
            for number, line in enumerate(candidate.read_text().splitlines(), 1):
                if '"' + check['check_id'] + '"' in line:
                    binding_line = number
                    binding_path = str(candidate.relative_to(ROOT))
                    break
            if binding_line is not None:
                break
        if check['check_id'] in {'aws.b.rds_instance.iam_authentication',
                                 'aws.b.rds_instance.snapshot_tags'}:
            binding_path = 'peaso/checks/aws_b_databases.py'
            binding_line = 12 if check['check_id'].endswith('iam_authentication') else 15
        # Dynamically assembled IDs need a separate registration audit.
    bound = bool(fields) or bool(helper_refs) or binding_line is not None or check['check_id'] in {
        'aws.b.cloudfront.waf_reference', 'aws.b.cloudfront.default_root_object',
        'aws.b.cloudfront.field_level_encryption', 'aws.b.cloudfront.geo_restrictions',
        'aws.b.cloudfront.custom_acm_certificate', 'aws.b.ecr.lifecycle_rules',
        'aws.b.cloudfront.origin_group_metadata',
    }
    # The two special parsers below only inspect structured API metadata; the
    # source lines and recorded fields are pinned in the row, not inferred from
    # the control title.
    structured = check['check_id'] == 'aws.b.ecr.lifecycle_rules'
    if structured:
        unresolved = [call for call in unresolved if call['name'] != 'loads']
        unsupported = unresolved[0] if unresolved else None
        helper_refs.append({'path': 'peaso/checks/aws_b_ecr.py', 'lines': '17-29',
                            'symbol': 'lifecycle', 'purpose': 'JSON rules metadata presence only',
                            'source_file_sha256': hashlib.sha256((ROOT / 'peaso/checks/aws_b_ecr.py').read_bytes()).hexdigest()})
    reviewed_scope = check['check_id'].startswith('aws.a.iam.password_policy_')
    password_fields = []
    if reviewed_scope:
        from peaso.checks.aws_a_iam import PASSWORD_SPECS, STRONG_FIELDS
        suffix = check['check_id'].removeprefix('aws.a.iam.password_policy_')
        if suffix in PASSWORD_SPECS:
            password_fields = ['iam_password_policy.PasswordPolicy.' + PASSWORD_SPECS[suffix][0]]
        elif suffix == 'strong_min_length_8':
            password_fields = ['iam_password_policy.PasswordPolicy.MinimumPasswordLength'] + [
                'iam_password_policy.PasswordPolicy.' + field for field in STRONG_FIELDS]
        elif suffix == 'strong_min_length_14_reuse_24_age_90':
            password_fields = ['iam_password_policy.PasswordPolicy.MinimumPasswordLength'] + [
                'iam_password_policy.PasswordPolicy.' + field for field in STRONG_FIELDS] + [
                'iam_password_policy.PasswordPolicy.PasswordReusePrevention',
                'iam_password_policy.PasswordPolicy.MaxPasswordAge']
        else:
            raise ValueError('unreviewed password spec: ' + suffix)
    simple = ((registered.target == 'resource' or reviewed_scope)
              and (index_read is None or reviewed_scope)
              and unsupported is None and bound and bool(result_lines))
    from peaso.checks.facts import get as strict_get
    dynamic_gets = [node for node in nodes if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name) and node.func.id == 'get'
                    and len(node.args) > 1
                    and not (isinstance(node.args[1], ast.Constant)
                             and isinstance(node.args[1].value, str))]
    direct = (registered.target == 'resource' and index_read is None
              and unsupported is None and not helper_refs and bool(fields)
              and bool(result_lines) and function.__globals__.get('get') is strict_get
              and (not dynamic_gets or (spec is not None and binding_line is not None
                                        and all(isinstance(node.args[1], ast.Name)
                                                and node.args[1].id == 'path'
                                                for node in dynamic_gets)))
              and not any(isinstance(node.func, ast.Attribute) and node.func.attr == 'get'
                          for node in nodes if isinstance(node, ast.Call)))
    special = (reviewed_scope or
               check['check_id'] == 'aws.c2b.cloudfront.custom_ssl_certificate')
    if special:
        paths = (('peaso/checks/aws_a_iam.py', 'peaso/checks/aws_a_facts.py')
                 if reviewed_scope else
                 ('peaso/checks/claude2_aws_b_edge.py', 'peaso/collectors/aws_b_services.py'))
        for path in paths:
            if hashlib.sha256((ROOT / path).read_bytes()).hexdigest() != SPECIAL_SOURCE_PINS[path]:
                raise ValueError('reviewed helper or collector source changed: ' + path)
    if check['check_id'] in MANUAL_RETAIN:
        decision, reason = 'retain_ai', MANUAL_RETAIN[check['check_id']]
    elif simple and (direct or special):
        decision, reason = ('native_final_source_proven',
            f'Evaluator {relative}:{start}-{start + len(raw) - 1} uses only '
            'recorded fields, fixed comparisons and cited pure helpers; '
            'malformed or unavailable facts do not establish FAIL.')
    elif simple:
        decision, reason = ('provisional_source_candidate',
            f'Evaluator {relative}:{start}-{start + len(raw) - 1} has an '
            'unverified helper chain, dynamic field binding, or optional '
            'dict.get omission; AI remains required pending collector/API proof.')
    elif index_read is not None:
        decision, reason = 'retain_ai', f'Scoped/index dependency at {relative}:{index_read} is not proven complete in this slice.'
    elif unsupported:
        decision, reason = 'retain_ai', f'Helper {unsupported["name"]} at {relative}:{unsupported["line"]} is not traced to recorded fields in this slice.'
    elif not fields:
        decision, reason = 'retain_ai', f'No strict recorded-field path proved at {relative}:{start}.'
    else:
        decision, reason = 'retain_ai', f'Evaluator branch/length at {relative}:{start} needs separate source proof.'
    return {
        'check_id': check['check_id'], 'decision': decision, 'reason': reason,
        'native_fail_count': check['native_fail_count'],
        'initial_representatives': check['initial_representatives'],
        'evaluator': {'path': relative, 'first_line': start,
                      'last_line': start + len(raw) - 1,
                      'source_file_sha256': hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
                      'function_sha256': evaluator_hash,
                      'symbol': definition.name},
        'recorded_field_reads': fields,
        'bound_api_fields': ([field['path'] for field in fields]
                             + password_fields
                             + (['LifecyclePolicy.collection_status', 'LifecyclePolicy.absent',
                                 'LifecyclePolicy.lifecyclePolicyText', 'rules'] if structured else [])
                             + (['Config.DistributionConfig.ViewerCertificate.CloudFrontDefaultCertificate']
                                if check['check_id'] == 'aws.c2b.cloudfront.custom_ssl_certificate' else [])),
        'source_field_binding': {'path': binding_path, 'line': binding_line,
                                 'source_file_sha256': hashlib.sha256((ROOT / binding_path).read_bytes()).hexdigest() if binding_path else None,
                                 'purpose': 'literal ID and field/setting registration'} if binding_line else None,
        'result_lines': result_lines,
        'fail_predicates': predicates,
        'helper_source_refs': ([{'path': 'peaso/checks/facts.py', 'lines': '12-53',
                                 'purpose': 'strict coverage-checked get/guard'}]
                               if any(call['name'] == 'get' for call in calls) else [])
                              + ([{'path': 'peaso/checks/__init__.py', 'lines': '178-183',
                                   'purpose': 'pure FAIL/PASS/UNKNOWN construction'}]
                                 if any(call['name'] in {'result', 'unknown'} for call in calls) else [])
                              + helper_refs
                              + ([{'path': 'peaso/checks/aws_a_facts.py', 'lines': '20-50',
                                   'purpose': 'complete scope-matched IAM policy collection'}]
                                 if reviewed_scope else [])
                              + ([{'path': 'peaso/checks/aws_a_iam.py', 'lines': '12-20',
                                   'purpose': 'fixed password-policy acceptable value predicates'}]
                                 if reviewed_scope else [])
                              + ([{'path': 'peaso/collectors/aws.py', 'lines': '1321-1324',
                                   'purpose': 'GetLifecyclePolicy response or exact absent marker'}]
                                 if structured else [])
                              + ([{'path': 'peaso/collectors/aws_b_services.py', 'lines': '475-476',
                                   'purpose': 'GetDistributionConfig complete response'}]
                                 if check['check_id'] == 'aws.c2b.cloudfront.custom_ssl_certificate' else []),
        'index_read_line': index_read,
        'untraced_helper_call': unsupported,
        'evidence_keys': inventory['evidence_keys'],
        'evidence_type_counts': inventory['evidence_type_counts'],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('split_ids')
    parser.add_argument('source_inventory')
    parser.add_argument('--disjoint-split', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    split = json.loads(Path(args.split_ids).read_text())
    disjoint = json.loads(Path(args.disjoint_split).read_text())
    inventory = json.loads(Path(args.source_inventory).read_text())
    selected = split.get('check_ids')
    if (split.get('scan_id') != inventory.get('scan_id')
            or type(selected) is not list
            or split.get('check_count') != len(selected)
            or inventory.get('zero_disagreement_checks') != 293):
        raise ValueError('wrong audit slice/source inventory')
    by_id = {row['check_id']: row for row in inventory['checks']}
    if (disjoint.get('scan_id') != split['scan_id']
            or disjoint.get('check_count') != 72
            or len(set(selected) & set(disjoint.get('check_ids', []))) != 0):
        raise ValueError('audit worker split overlaps or changed')
    from peaso.checks.facts import FIELD_SPECS
    rows = [proof(by_id[ident], by_id[ident], FIELD_SPECS)
            for ident in selected]
    if (len(rows) != 190 or len({row['check_id'] for row in rows}) != len(rows)
            or any(row['initial_representatives'] >= 3 for row in rows)):
        raise ValueError('low-representative split changed')
    value = {'schema_version': 2, 'status': 'independent_source_review',
             'allowlist_activation': False,
             'scan_id': split['scan_id'], 'source_commit': inventory['source_commit'],
             'scope': 'code-worker 190-ID disjoint low-representative source slice',
             'source_inventory_sha256': hashlib.sha256(Path(args.source_inventory).read_bytes()).hexdigest(),
             'split_sha256': hashlib.sha256(Path(args.split_ids).read_bytes()).hexdigest(),
             'disjoint_split_sha256': hashlib.sha256(Path(args.disjoint_split).read_bytes()).hexdigest(),
             'source_proven_count': sum(row['decision'] == 'native_final_source_proven' for row in rows),
             'provisional_candidate_count': sum(row['decision'] == 'provisional_source_candidate' for row in rows),
             'retain_ai_count': sum(row['decision'] == 'retain_ai' for row in rows),
             'checks': rows}
    Path(args.output).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: value[key] for key in ('source_proven_count', 'retain_ai_count')}))


if __name__ == '__main__':
    main()
