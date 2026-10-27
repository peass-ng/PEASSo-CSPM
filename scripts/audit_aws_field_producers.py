#!/usr/bin/env python3
"""Offline field-producer review; never opens an AWS client or network socket.

Run: .venv/bin/python scripts/audit_aws_field_producers.py
An SDK shape is a possible response, not an availability/completeness promise.
Fixture reads are witnesses, never collector evidence. Unresolved paths remain
explicit even when the outer collection kind has a registered producer.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import inspect
import json
from functools import lru_cache
from pathlib import Path
import re
import sys
import textwrap
import xml.etree.ElementTree as ET
from botocore.exceptions import UnknownServiceError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import audit_aws_native_contracts as native


# Current admitted AWS evaluators outside peaso.checks are finite and source
# reviewed. Keep this list exact so unrelated application functions cannot be
# mistaken for registered AWS predicate helpers.
CURRENT_AWS_EVALUATOR_MODULES = frozenset({
    'peaso.unused_iam_aws_activity',
    'peaso.unused_iam_aws_completion',
    'peaso.unused_iam_aws_federation_consumers',
    'peaso.unused_iam_aws_inline',
    'peaso.unused_network_aws',
})


def _reviewed_evaluator_module_name(module):
    return module == 'peaso.checks' or module.startswith('peaso.checks.') or module in CURRENT_AWS_EVALUATOR_MODULES


def _reviewed_evaluator_module(function):
    return _reviewed_evaluator_module_name(function.__module__)


# These native image predicates require exact dict instances for sealed proof.
# Profiling still compares complete normal/instrumented verdict and evidence,
# but dict-subclass read interception cannot be used on their input objects.
EXACT_DICT_IMAGE_EVALUATORS = frozenset({
    'aws.review.ecr.selected_image_vulnerabilities',
    'aws.review.ecr_public.selected_image_high_vulnerabilities',
    'aws.review.ecr_public.selected_image_secret_indicators',
    'aws.review.workload.selected_image_secret_indicators',
})


@lru_cache(maxsize=None)
def function_tree(fn):
    try:
        tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                node.decorator_list = []  # Registration is not a runtime call.
        return tree
    except (SyntaxError, OSError, TypeError):
        return ast.Module(body=[], type_ignores=[])


def callback_graph(check):
    """Follow registered facades, per-ID dispatch, defaults and local helpers."""
    queue = [check.evaluate]
    seen, output = set(), []
    while queue and len(output) < 100:
        fn = inspect.unwrap(queue.pop())
        if id(fn) in seen or not inspect.isfunction(fn):
            continue
        seen.add(id(fn))
        if not _reviewed_evaluator_module(fn):
            continue
        output.append(fn)
        mapping = fn.__globals__.get('EVALUATORS', {})
        if isinstance(mapping, dict) and callable(mapping.get(check.id)):
            queue.append(mapping[check.id])
        candidates = list(fn.__defaults__ or ()) + [getattr(fn, 'reviewed_target', None)]
        for cell in fn.__closure__ or ():
            try:
                candidates.append(cell.cell_contents)
            except ValueError:
                pass
        queue.extend(x for x in candidates if inspect.isfunction(x))
        tree = function_tree(fn)
        for call in ast.walk(tree):
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name):
                helper = fn.__globals__.get(call.func.id)
                if call.func.id == '_bound_kms' and not check.id.startswith('aws.review.kms.enclave_'):
                    continue  # The admitted facade gates this branch on this ID.
                if inspect.isfunction(helper) and _reviewed_evaluator_module(helper):
                    # Accessors are represented as reads, not recursively expanded.
                    if helper.__module__ != 'peaso.checks.facts':
                        queue.append(helper)
    return output


def static_reads(functions):
    output = []
    for fn in functions:
        source, start = inspect.getsourcelines(fn)
        for node in ast.walk(function_tree(fn)):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ('get', 'optional', 'api_optional') and len(node.args) >= 2:
                path, obj, accessor = node.args[1], node.args[0], node.func.id
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'get' and node.args:
                path, obj, accessor = node.args[0], node.func.value, 'dict.get'
            elif isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load):
                path, obj, accessor = node.slice, node.value, 'subscript'
            else:
                continue
            output.append({'path': path.value if isinstance(path, ast.Constant) and isinstance(path.value, str) else None,
                           'object': ast.unparse(obj), 'accessor': accessor,
                           'file': str(Path(inspect.getsourcefile(fn)).relative_to(ROOT)),
                           'line': start + node.lineno - 1})
    return sorted({json.dumps(row, sort_keys=True): row for row in output}.values(), key=lambda x: (x['file'], x['line']))


def shape_at(shape, path):
    for part in re.sub(r'\[\]', '', path or '').split('.'):
        if not part:
            continue
        while shape is not None and shape.type_name == 'list':
            shape = shape.member
        if shape is None or shape.type_name != 'structure' or part not in shape.members:
            return None
        shape = shape.members[part]
    while shape is not None and shape.type_name == 'list':
        shape = shape.member
    return shape


class Models:
    def __init__(self):
        import botocore.session
        self.session = botocore.session.get_session()
        self.models = {}

    def output(self, service, operation):
        from botocore import xform_name
        if service not in self.models:
            self.models[service] = self.session.get_service_model(service)
        model = self.models[service]
        name = next(name for name in model.operation_names if xform_name(name) == operation)
        return model.operation_model(name).output_shape


def modeled_value(shape, depth=0, ancestors=()):
    """Possible SDK response including optional members; bounded recursive data."""
    if shape is None:
        return {}
    if depth > 12 or shape.name in ancestors:
        return [] if shape.type_name == 'list' else {} if shape.type_name in ('structure', 'map') else ''
    parents = ancestors + (shape.name,)
    if shape.type_name == 'structure':
        policy = json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': '*', 'Principal': {'AWS': 'arn:aws:iam::123456789012:root'}}]})
        members = list(shape.members.items())
        if shape.is_tagged_union:
            members = members[:1]  # Other union branches remain undemonstrated.
        policy_fields = {'Policy', 'ResourcePolicy', 'AssumeRolePolicyDocument', 'PolicyDocument', 'policyDocument', 'Document', 'sessionPolicy'}
        pagination = {'nexttoken', 'marker', 'istruncated', 'nextmarker', 'nextpagetoken', 'continuationtoken', 'nextcontinuationtoken', 'paginationtoken'}
        return {name: (policy if member.type_name == 'string' and name in policy_fields else modeled_value(member, depth + 1, parents))
                for name, member in members if name in shape.required_members or name.lower() not in pagination}
    if shape.type_name == 'list':
        return [modeled_value(shape.member, depth + 1, parents) for _ in range(max(1, shape.metadata.get('min', 1)))]
    if shape.type_name == 'map':
        return {}
    if shape.type_name == 'boolean':
        return False
    if shape.type_name in ('integer', 'long'):
        return max(shape.metadata.get('min', 1), min(1, shape.metadata.get('max', 1)))
    if shape.type_name in ('float', 'double'):
        return 1.0
    if shape.type_name == 'timestamp':
        return datetime(2026, 10, 19, tzinfo=timezone.utc)
    if shape.type_name == 'blob':
        return b''
    if getattr(shape, 'enum', None):
        return shape.enum[0]
    length = min(max(17, shape.metadata.get('min', 0)), shape.metadata.get('max', 100))
    return ('audit-placeholder-' * (length // 18 + 1))[:length]


@lru_cache(maxsize=1)
def response_examples():
    """Existing benign SDK-response examples, never synthetic predicate items.

    Preserve source attribution and filter/validate them against SDK output
    members before using them. A fixture alone is never a production claim.
    """
    from importlib import import_module
    result = {}
    for module_name in ('test_aws_additional_secret_review_20261019', 'test_aws_configuration_payload_secret_review_20261019'):
        module = import_module('tests.' + module_name)
        for kind in module.KINDS:
            service, operation, arguments, response, item = module.fixture(kind, detected=False)
            result[(service, operation)] = (response, 'tests/' + module_name + '.py::fixture[' + kind + ']')
    stamp = datetime(2026, 10, 19, tzinfo=timezone.utc)
    account, region = '123456789012', 'us-east-1'
    function = {'FunctionName': 'worker', 'FunctionArn': f'arn:aws:lambda:{region}:{account}:function:worker', 'Environment': {'Variables': {}}}
    agent = {'agentId': 'ABCDEFGHIJ', 'agentArn': f'arn:aws:bedrock:{region}:{account}:agent/ABCDEFGHIJ',
             'agentName': 'example', 'agentVersion': 'DRAFT', 'agentResourceRoleArn': f'arn:aws:iam::{account}:role/agent',
             'agentStatus': 'PREPARED', 'idleSessionTTLInSeconds': 600, 'createdAt': stamp, 'updatedAt': stamp}
    examples = {
        ('sts', 'get_caller_identity'): {'Account': account, 'Arn': f'arn:aws:iam::{account}:user/audit', 'UserId': 'AIDAEXAMPLEAUDIT'},
        ('iam', 'get_account_summary'): {'SummaryMap': {'AccountMFAEnabled': 1, 'AccountAccessKeysPresent': 0}},
        ('iam', 'list_policies'): {'Policies': [{'Arn': f'arn:aws:iam::{account}:policy/audit', 'PolicyName': 'audit', 'PolicyId': 'ANPAEXAMPLEAUDIT000000', 'DefaultVersionId': 'v1', 'AttachmentCount': 1}]},
        ('iam', 'get_policy_version'): {'PolicyVersion': {'VersionId': 'v1', 'IsDefaultVersion': True, 'Document': json.dumps({'Statement': [{'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': '*'}]})}},
        ('ec2', 'describe_instances'): {'Reservations': [{'Instances': [{'InstanceId': 'i-0123456789abcdef0', 'State': {'Name': 'running'}, 'Tags': [{'Key': 'aws:ec2launchtemplate:id', 'Value': 'lt-1234567890abcdef0'}], 'MetadataOptions': {'HttpTokens': 'required'}}]}]},
        ('ec2', 'get_launch_template_data'): {'LaunchTemplateData': {'NetworkInterfaces': [{'AssociatePublicIpAddress': False}]}},
        ('cloudwatch', 'get_metric_statistics'): {'Label': 'time_offset', 'Datapoints': [{'Timestamp': datetime(2026, 10, 18, 23, 55, tzinfo=timezone.utc), 'Minimum': 0, 'Maximum': 10, 'Unit': 'Milliseconds'}]},
        ('cloudtrail', 'describe_trails'): {'trailList': [{'TrailARN': f'arn:aws:cloudtrail:{region}:{account}:trail/audit', 'Name': 'audit', 'HomeRegion': region, 'IsMultiRegionTrail': True, 'IsOrganizationTrail': False, 'S3BucketName': 'audit-trail-bucket'}]},
        ('cloudtrail', 'get_trail_status'): {'IsLogging': True},
        ('cloudtrail', 'get_event_selectors'): {'TrailARN': f'arn:aws:cloudtrail:{region}:{account}:trail/audit', 'EventSelectors': [{'ReadWriteType': 'All', 'IncludeManagementEvents': True}]},
        ('acm', 'list_certificates'): {'CertificateSummaryList': [{'CertificateArn': f'arn:aws:acm:{region}:{account}:certificate/12345678-1234-1234-1234-123456789012', 'DomainName': 'audit.example'}]},
        ('lambda', 'list_functions'): {'Functions': [function]},
        ('lambda', 'get_function_configuration'): function,
        ('cloudformation', 'describe_stacks'): {'Stacks': [{'StackId': f'arn:aws:cloudformation:{region}:{account}:stack/demo/12345678-1234-1234-1234-123456789012', 'StackName': 'demo', 'StackStatus': 'CREATE_COMPLETE', 'CreationTime': stamp, 'Outputs': []}]},
        ('bedrock-agent', 'list_agents'): {'agentSummaries': [{'agentId': 'ABCDEFGHIJ', 'agentName': 'example', 'agentStatus': 'PREPARED', 'updatedAt': stamp}]},
        ('bedrock-agent', 'get_agent'): {'agent': agent},
        ('bedrock-agent', 'list_agent_aliases'): {'agentAliasSummaries': []},
        ('ec2', 'describe_regions'): {'Regions': [{'RegionName': region, 'OptInStatus': 'opt-in-not-required'}]},
        ('ec2', 'describe_launch_templates'): {'LaunchTemplates': [{'LaunchTemplateId': 'lt-abc123', 'LatestVersionNumber': 1, 'DefaultVersionNumber': 1}]},
        ('ssm', 'list_documents'): {'DocumentIdentifiers': [{'Name': 'OwnedDocument', 'Owner': account, 'DocumentVersion': '3', 'DocumentType': 'Command'}]},
        ('stepfunctions', 'list_state_machines'): {'stateMachines': [{'stateMachineArn': f'arn:aws:states:{region}:{account}:stateMachine:example', 'name': 'example', 'type': 'STANDARD', 'creationDate': stamp}]},
        ('sagemaker', 'list_notebook_instances'): {'NotebookInstances': [{'NotebookInstanceName': 'example', 'NotebookInstanceArn': f'arn:aws:sagemaker:{region}:{account}:notebook-instance/example', 'NotebookInstanceStatus': 'InService', 'CreationTime': stamp}]},
        ('sagemaker', 'describe_notebook_instance'): {'NotebookInstanceName': 'example', 'NotebookInstanceArn': f'arn:aws:sagemaker:{region}:{account}:notebook-instance/example', 'NotebookInstanceLifecycleConfigName': 'attached'},
        ('datapipeline', 'list_pipelines'): {'pipelineIdList': [{'id': 'df-abc123', 'name': 'example'}]},
    }
    import csv
    import io
    # Standard report-column example; SDK validates the blob, while the actual
    # CSV parser (not a structure-shape guess) establishes emitted columns.
    report_row = {'user': 'audit', 'arn': f'arn:aws:iam::{account}:user/audit',
                  'user_creation_time': stamp.isoformat(), 'password_enabled': 'true',
                  'password_last_used': stamp.isoformat(), 'password_last_changed': stamp.isoformat(),
                  'password_next_rotation': 'N/A', 'mfa_active': 'true'}
    for number in (1, 2):
        report_row.update({f'access_key_{number}_active': 'false', f'access_key_{number}_last_rotated': 'N/A',
            f'access_key_{number}_last_used_date': 'N/A', f'access_key_{number}_last_used_region': 'N/A',
            f'access_key_{number}_last_used_service': 'N/A', f'cert_{number}_active': 'false',
            f'cert_{number}_last_rotated': 'N/A'})
    report_csv = io.StringIO()
    writer = csv.DictWriter(report_csv, fieldnames=list(report_row), lineterminator='\n')
    writer.writeheader()
    writer.writerow(report_row)
    examples[('iam', 'get_credential_report')] = {'Content': report_csv.getvalue().encode(),
        'ReportFormat': 'text/csv', 'GeneratedTime': stamp}
    result.update({key: (value, 'scripts/audit_aws_field_producers.py::response_examples (SDK-validated benign response)') for key, value in examples.items()})
    return result


def required_value(shape):
    if shape.type_name == 'structure':
        return {key: required_value(shape.members[key]) for key in shape.required_members}
    if shape.type_name == 'list':
        return [required_value(shape.member)] if shape.metadata.get('min', 0) else []
    return modeled_value(shape)


def merge_shaped(shape, base, overlay):
    if shape.type_name == 'structure' and isinstance(overlay, dict):
        result = dict(base) if isinstance(base, dict) else {}
        for name, value in overlay.items():
            if name in shape.members:
                result[name] = merge_shaped(shape.members[name], result.get(name), value)
        return result
    if shape.type_name == 'list' and isinstance(overlay, list):
        return [merge_shaped(shape.member, required_value(shape.member), value) for value in overlay]
    return deepcopy(overlay)


def field_paths(value, prefix=''):
    found = set()
    if isinstance(value, dict):
        for key, child in value.items():
            path = '.'.join(filter(None, (prefix, key)))
            found.add(path)
            found.update(field_paths(child, path))
    elif isinstance(value, list):
        for child in value:
            found.update(field_paths(child, prefix + '[]'))
    return found


def probe_producer(kind, models, *, public_pipeline=False):
    """Exercise real projection callbacks on SDK-shaped *modeled* responses.

    This intentionally cannot prove completeness, real identifiers or semantic
    branches. Failure/absence is undemonstrated, not a confirmed production gap.
    No boto/session clients exist; socket creation is blocked as a backstop.
    """
    import jmespath
    import socket
    from unittest.mock import patch
    from peaso.collectors import aws
    from peaso.collectors.bulk_evidence import ALIASES
    kind = ALIASES['aws'].get(kind, kind)
    calls = set()
    examples = set()
    class Client:
        def __init__(self, service):
            from types import SimpleNamespace
            self.service = service
            self.meta = SimpleNamespace(service_model=models.session.get_service_model(service))
        def can_paginate(self, operation):
            return False
        def __getattr__(self, operation):
            def call(**arguments):
                from botocore.validate import validate_parameters
                calls.add((self.service, operation))
                shape = models.output(self.service, operation)
                value = modeled_value(shape)
                example = response_examples().get((self.service, operation))
                if example:
                    value = merge_shaped(shape, required_value(shape), example[0])
                    examples.add(example[1])
                if self.service == 'ec2' and operation == 'describe_instance_attribute':
                    value['InstanceId'] = arguments['InstanceId']
                    if arguments['Attribute'] == 'userData':
                        value['UserData'] = {'Value': ''}
                validate_parameters(value, shape)
                # Botocore adds transport metadata outside the operation output shape.
                value['ResponseMetadata'] = {'HTTPStatusCode': 200}
                return value
            return call
    requests = aws.Requests({'max_calls': 1000, 'max_pages': 1, 'max_resources': 3, 'retry_attempts': 1}, sleep=lambda _: None)
    requests.observed_at = datetime(2026, 10, 19, tzinfo=timezone.utc)
    requests.client = lambda session, service, region: Client(service)
    phase = 'base'
    try:
        with patch.object(socket, 'socket', side_effect=RuntimeError('network disabled in field audit')):
            if public_pipeline:
                from peaso.snapshot import validate
                from types import SimpleNamespace
                with patch.object(aws, '_session', return_value=(SimpleNamespace(region_name='us-east-1', get_partition_for_region=models.session.get_partition_for_region, get_available_regions=models.session.get_available_regions), 'offline-modeled')), patch.object(aws, 'Requests', return_value=requests):
                    snapshot = aws.collect({'provider': 'aws', 'scopes': ['123456789012'],
                        'options': {'retry_attempts': 1, '_ec2_clock_metric_requested': True}}, [kind])
                validate(snapshot)
                envelopes = [e for e in snapshot['collections'] if e['type'] == kind]
                paths = set().union(*(field_paths(item) for e in envelopes for item in e.get('items', [])))
                return {'status': 'modeled-public-pipeline-executed', 'paths': sorted(paths),
                        'response_count': sum(len(e.get('items', [])) for e in envelopes),
                        'envelope_errors': [e['error'] for e in envelopes if e.get('error')],
                        'collection_status': ','.join(sorted({e['status'] for e in envelopes})) or 'absent',
                        'sdk_response_examples': sorted(examples),
                        'append_metadata_source': 'peaso/collectors/aws.py::collect.append (executed)',
                        'operations': [list(c) for c in sorted(calls)]}
            if kind in {'iam_user', 'iam_group', 'iam_role', 'iam_policy'}:
                read = aws._iam(requests, None, 'us-east-1', {kind})[kind]
            elif kind == 'bucket':
                read = aws._buckets(requests, None, 'us-east-1')
            elif kind in aws.FETCHERS:
                read = aws.FETCHERS[kind](requests, None, 'us-east-1', '123456789012')
            elif kind in aws.SPECS:
                service, operation, expression = aws.SPECS[kind]
                read = (requests.pages(None, service, 'us-east-1', operation, expression) if expression else
                        aws.ReadResult([requests.call(None, service, 'us-east-1', operation)]))
                read.items = aws._enrich(requests, None, 'us-east-1', kind, read.items,
                                         account='123456789012', partition='aws')
            else:
                return {'status': 'unmodeled-special-dispatch', 'paths': []}
            phase = 'extension'
            if kind in aws.ENRICHERS:
                read.items = aws.ENRICHERS[kind](requests, None, 'us-east-1', read.items)
            # Actual append adds these independently of the service response.
            paths = set().union(*(field_paths(aws._safe(item)) for item in read.items)) if read.items else set()
            if read.items:
                paths.add('AccountId')
                if kind not in aws.GLOBAL_TYPES:
                    paths.add('Region')
            return {'status': 'modeled-projection-executed', 'paths': sorted(paths),
                    'response_count': len(read.items), 'collection_status': read.status,
                    'sdk_response_examples': sorted(examples),
                    'append_metadata_source': 'peaso/collectors/aws.py::collect.append (source-traced AccountId/Region)',
                    'operations': [list(c) for c in sorted(calls)]}
    except Exception as exc:
        return {'status': 'undemonstrated', 'phase': phase, 'exception': type(exc).__name__, 'exception_message': str(exc)[:200],
                'paths': [], 'operations': [list(c) for c in sorted(calls)]}


def producer(kind, models):
    from peaso.collectors import aws
    from peaso.collectors.bulk_evidence import ALIASES
    kind = ALIASES['aws'].get(kind, kind)
    row = {'native_kind': kind, 'outer_kind_registered': kind in aws.AWS_TYPES}
    for key, mapping in [('fetcher', aws.FETCHERS), ('enricher', aws.ENRICHERS)]:
        if kind in mapping:
            row[key] = native.source_ref(mapping[kind])
            stages, queue, seen = [], [mapping[kind]], set()
            while queue:
                fn = queue.pop(0)
                if id(fn) in seen or not inspect.isfunction(fn):
                    continue
                seen.add(id(fn))
                stages.append(native.source_ref(fn))
                for cell in fn.__closure__ or ():
                    try:
                        candidate = cell.cell_contents
                    except ValueError:
                        continue
                    if inspect.isfunction(candidate) and candidate.__module__.startswith('peaso.collectors'):
                        queue.append(candidate)
            row[key + '_stages'] = stages
    shape = None
    special = {'bucket': ('s3', 'list_buckets', 'Buckets'),
               **{k: ('iam', 'get_account_authorization_details', p) for k, p in
                  [('iam_user', 'UserDetailList'), ('iam_group', 'GroupDetailList'),
                   ('iam_role', 'RoleDetailList'), ('iam_policy', 'Policies')]}}
    if kind in special:
        row['special_dispatch'] = native.source_ref(aws._buckets if kind == 'bucket' else aws._iam)
    if kind in aws.SPECS or kind in special:
        spec = aws.SPECS.get(kind, special.get(kind))
        row['spec'] = list(spec)
        try:
            shape = shape_at(models.output(spec[0], spec[1]), spec[2])
            if shape is not None:
                row['api_item_shape'] = shape.name
                row['api_top_fields'] = sorted(shape.members) if shape.type_name == 'structure' else []
        except (ValueError, KeyError, StopIteration, UnknownServiceError) as exc:
            row['shape_error'] = type(exc).__name__
    # _enrich starts from a deepcopy; later extension callbacks can project.
    row['native_shape_retention_proven'] = shape is not None and kind not in special and kind not in aws.FETCHERS and kind not in aws.ENRICHERS
    row['projection_review'] = 'base-deepcopy-no-extension' if row['native_shape_retention_proven'] else 'custom-or-extension-projection-needs-review'
    return row, shape


class ReadTrackedDict(dict):
    """Instrument input reads only; retain dict behavior and never record values."""
    def _record(self, key, accessor):
        frame = sys._getframe(2)
        if (isinstance(key, str) and _reviewed_evaluator_module_name(frame.f_globals.get('__name__', ''))
                and not frame.f_code.co_filename.endswith('/facts.py')):
            self._record_read(self, key, accessor)

    def get(self, key, default=None):
        self._record(key, 'dict.get')
        return super().get(key, default)

    def __getitem__(self, key):
        self._record(key, 'subscript')
        return super().__getitem__(key)


def tracked_input(value, record, memo=None):
    memo = {} if memo is None else memo
    if id(value) in memo:
        return memo[id(value)]
    if isinstance(value, dict):
        result = ReadTrackedDict()
        result._record_read = record
        memo[id(value)] = result
        for key, child in value.items():
            dict.__setitem__(result, key, tracked_input(child, record, memo))
        return result
    if isinstance(value, list):
        result = []
        memo[id(value)] = result
        result.extend(tracked_input(child, record, memo) for child in value)
        return result
    return value


def fixture_reads(check, cases):
    """One bounded witness walk, with identity-based root/dependency attribution."""
    from peaso.checks import facts
    from peaso.checks.facts import get, optional
    records, outcomes = set(), {}
    for case in ('pass', 'fail', 'unknown'):
        if case not in cases:
            continue
        data = deepcopy(cases[case])
        index = deepcopy(cases.get(case + '_index', cases.get('case_indices', {}).get(case, cases.get('index', {}))))
        origins = {}
        def record(obj, key, accessor):
            origin = origins.get(id(obj))
            records.add((origin[0] if origin else None,
                         '.'.join(filter(None, (origin[1], key))) if origin else key,
                         'root-or-dependency' if origin else 'derived-object-unattributed', accessor))
        # Compare normal and instrumented execution; instrumentation must not
        # silently change the predicate's status or its evidence.
        try:
            baseline = check.evaluate(deepcopy(data), deepcopy(index))
        except Exception as exc:
            baseline = ('ERROR:' + type(exc).__name__, {})
        if check.id not in EXACT_DICT_IMAGE_EVALUATORS:
            data, index = tracked_input([data, index], record)
        def walk(value, kind, path='', depth=0):
            if depth > 24:
                return
            if isinstance(value, dict):
                origins.setdefault(id(value), (kind, path))
                for key, child in value.items():
                    walk(child, kind, '.'.join(filter(None, (path, key))), depth + 1)
            elif isinstance(value, list):
                for child in value:
                    walk(child, kind, path + '[]', depth + 1)
        walk(data, '@engine' if check.target == 'scope' else check.kind,
             'context' if check.target == 'scope' else '')
        origins[id(index)] = ('@engine', '')
        if isinstance(index.get('context'), dict):
            walk(index['context'], '@engine', 'context')
        if isinstance(index.get('collections'), dict):
            origins[id(index['collections'])] = ('@engine', 'collections')
        for kind, resources in index.items():
            if isinstance(resources, list):
                for resource in resources:
                    if isinstance(resource, dict) and 'data' in resource:
                        origins[id(resource)] = ('@engine', kind + '[]')
                        walk(resource['data'], kind)
        for kind, envelopes in index.get('collections', {}).items():
            if isinstance(envelopes, list):
                for envelope in envelopes:
                    if isinstance(envelope, dict):
                        origins[id(envelope)] = ('@engine', 'collections.' + kind + '[]')
                        for item in envelope.get('items', []):
                            walk(item, kind)
        codes = {get.__code__, optional.__code__}
        def profile(frame, event, arg):
            if event == 'call' and frame.f_code in codes:
                obj = frame.f_locals.get('item')
                key = frame.f_locals.get('path', frame.f_locals.get('key'))
                if isinstance(key, str):
                    record(obj, key, frame.f_code.co_name)
        old = sys.getprofile()
        try:
            sys.setprofile(profile)
            observed = check.evaluate(data, index)
            outcomes[case] = observed[0]
        except Exception as exc:
            observed = ('ERROR:' + type(exc).__name__, {})
            outcomes[case] = observed[0]
        finally:
            sys.setprofile(old)
        if observed != baseline:
            raise AssertionError(f'direct-dict instrumentation changed {check.id}/{case}: {baseline[0]} -> {observed[0]}')
    grouped = {}
    for kind, path, attribution, accessor in records:
        grouped.setdefault((kind, path, attribution), set()).add(accessor)
    return [{'kind': k, 'path': p, 'attribution': a, 'observed_accessors': sorted(accessors),
             'required_accessor_observed': bool(accessors & {'get', 'subscript'})}
            for (k, p, a), accessors in sorted(grouped.items(), key=lambda x: (x[0][0] or '', x[0][1], x[0][2]))], outcomes


def engine_field_produced(path, kinds):
    """Bounded source contract for the engine index and collector envelopes."""
    if path in {'context', 'context.provider', 'context.scope', 'context.Account', 'context.created_at', 'context.snapshot_id', 'context.metadata', 'collections'}:
        return True
    for kind in kinds:
        if path in {kind, kind + '[].data', kind + '[].scope', kind + '[].type', 'collections.' + kind}:
            return True
        if path.startswith('collections.' + kind + '[].'):
            return path.removeprefix('collections.' + kind + '[].') in {'type', 'scope', 'status', 'items', 'account_id', 'global'}
    return False


def producer_triage(cases, active):
    """Source + SDK + projection triage, with causal fixture reproduction.

    These deliberately distinguish missing derivation, wrong nesting, a dropped
    native field, and telemetry disabled by design. None relies on rg absence.
    """
    entries = [
        ('aws_cis_lambda_execution_role_no_admin', 'iam_role', 'EffectiveAdminAccess', 'missing-derived-producer',
         'GetAccountAuthorizationDetails RoleDetail has no effective-admin result. _iam emits policy documents/PolicySources but no analysis of boundaries/session/SCP/Denies.', 'peaso/checks/compliance_new_sw41.py:281; peaso/collectors/aws.py::_iam'),
        ('aws_nist_ec2_instance_not_publicly_accessible', 'instance', 'PublicReachability', 'missing-derived-producer',
         'DescribeInstances has no joined route/ingress/listener proof. _enrich and unique_instances do not construct the required complete PublicReachability projection.', 'peaso/checks/compliance_new_sw46.py:398; peaso/collectors/aws.py::_enrich; peaso/collectors/aws_facts_v4_holds.py::unique_instances'),
        ('aws_ec2_instance_time_offset_monitored', 'instance', 'TimeOffset', 'missing-derived-producer',
         'DescribeInstances has no CWAgent sample; the instance pipeline does not query or join CWAgent/time_offset metric data.', 'peaso/checks/compliance_new_sw46.py:384; peaso/collectors/aws.py::_enrich'),
        ('aws_cloudtrail_s3_siem_delivery', 'bucket', 'CloudTrailObjectsByPrefix', 'missing-derived-producer',
         'ListBuckets does not include prefix object listings. _buckets performs settings reads; no branch builds the required trail-specific ListObjectsV2 keyed projection.', 'peaso/checks/compliance_new_sw35.py:315; peaso/collectors/aws.py::_buckets'),
        ('aws_cloudtrail_bucket_lifecycle_retention_365', 'bucket', 'ObjectLock.ObjectLockEnabled', 'native-response-envelope-mismatch',
         'GetObjectLockConfiguration returns ObjectLockConfiguration.ObjectLockEnabled, stored by _buckets under ObjectLock without flattening. The evaluator reads one level too high.', 'peaso/checks/compliance_new_sw35.py:279; peaso/collectors/aws.py::_buckets'),
        ('aws_cloudtrail_bucket_lifecycle_retention_365', 'bucket', 'ObjectLock.Rule.DefaultRetention', 'native-response-envelope-mismatch',
         'The native path is ObjectLock.ObjectLockConfiguration.Rule.DefaultRetention. No collector flattens ObjectLockConfiguration for this callback.', 'peaso/checks/compliance_new_sw35.py:284; peaso/collectors/aws.py::_buckets'),
        ('aws.claude_a.ec2.launch_template_instances_no_public_ip', 'instance', 'LaunchTemplateData', 'missing-native-detail-read',
         'GetLaunchTemplateData can return this field, but the instance pipeline only reads DescribeInstances/DescribeInstanceAttribute; it never calls GetLaunchTemplateData. Launch-template Versions is a different kind/source.', 'peaso/checks/claude_aws_a_ec2.py:1103; peaso/collectors/aws.py::_enrich'),
        ('aws_cis_lightsail_bucket_private', 'lightsail_bucket', 'accessRules', 'native-field-dropped-by-projection',
         'GetBuckets bucket shape has accessRules. Actual aws_facts_swc._lightsail _pick retains only name/arn/accessLogConfig/resourcesReceivingAccess; executing it drops accessRules.', 'peaso/checks/compliance_new_sw42.py:298; peaso/collectors/aws_facts_swc.py::_lightsail'),
        ('aws_cis_lightsail_bucket_private', 'lightsail_bucket', 'AccountPublicAccessBlock', 'missing-derived-producer',
         'GetBuckets does not supply an S3-control PublicAccessBlockConfiguration, and neither Lightsail route constructs AccountPublicAccessBlock. Existing narrow IAM bucket route also has no such fact.', 'peaso/checks/compliance_new_sw42.py:303; peaso/collectors/aws_facts_swc.py::_lightsail; peaso/collectors/aws_lightsail_iam_native.py::bucket_metadata'),
        ('aws.claude_a.iam.user_bedrock_access_not_stale', 'iam_user', 'ServicesLastAccessed', 'readonly-telemetry-unavailable-by-design',
         '_services_last_accessed relies on _sla_reports, which deliberately returns no rows and generation_disabled because existing job IDs cannot be enumerated read-only. This is a known evidence boundary, not a new projection bug.', 'peaso/collectors/aws.py::_sla_reports/_services_last_accessed'),
    ]
    dispositions = {
        'aws.claude_a.iam.user_bedrock_access_not_stale': ('fixed-selection-gated-native-read-report', 'aws_iam_report_native generates AWS Read-classified SERVICE_LEVEL jobs only for selected usage checks, validates session/account/principal/job identity, paginates within one bounded batch deadline and preserves denied or incomplete reports as UNKNOWN. Access history does not prove effective permissions.', 'tests/test_aws_identity_sdk_closure_review.py'),
        'aws_cis_lambda_execution_role_no_admin': ('fixed-native-policy-consumer', 'EffectiveAdminAccess is no longer consumed; current legacy evaluator reads native role policies and exact AdministratorAccess attachment, with conservative unresolved effective semantics.', 'tests/test_aws_lambda_role_policy_review_20261019.py::test_legacy_actual_sdk_native_branches'),
        'aws_nist_ec2_instance_not_publicly_accessible': ('archived-exact-listening-contract', 'Exact listening/process reachability is archived; route/SG facts do not prove host listening. No complete PublicReachability producer is claimed.', 'tests/test_aws_ec2_public_reachability_review.py'),
        'aws_ec2_instance_time_offset_monitored': ('fixed-native-metric-producer', 'aws_ec2_clock_metadata.enrich produces request-bound TimeOffset.ValueMilliseconds from exact CWAgent/time_offset GetMetricStatistics; absence/denial/malformed remains unavailable.', 'tests/test_aws_ec2_clock_metadata_review.py::test_native_metric_requests_through_registered_consumer'),
        'aws_cloudtrail_s3_siem_delivery': ('fixed-native-delivery-metadata-replacement', 'Legacy CloudTrailObjectsByPrefix is not produced or consumed. Consumer now reads cloudtrail_account_inventory.CloudTrailS3DeliveryObjects from organization-trail metadata reads, not SIEM receipt or content evidence.', 'tests/test_aws_cloudtrail_s3_delivery_metadata_review.py::test_real_sdk_enrichment_cache_and_registered_snapshot_consumer'),
        'aws.claude_a.ec2.launch_template_instances_no_public_ip': ('fixed-native-instance-detail-producer', 'aws_launch_template_instance_metadata reads GetLaunchTemplateData for tagged instances and projects request-bound NetworkInterfaces flags before caching; no raw user data retained.', 'tests/test_aws_launch_template_instance_metadata_review.py::test_real_sdk_shared_cache_enrichment_and_registered_snapshot_consumer'),
    }
    from peaso.checks.native_only import exclusions
    excluded = exclusions()
    checks = {c.id: c for c in native.registry()}
    rows = []
    for cid, kind, field, status, evidence, source in entries:
        row = {'id': cid, 'kind': kind, 'field': field, 'status': status, 'evidence': evidence,
               'sources': source, 'currently_active': cid in active}
        if status == 'native-response-envelope-mismatch' or (cid == 'aws_cis_lightsail_bucket_private'):
            row['found_status'] = status
            row['status'] = 'fixed-under-bounded-runtime-ownership'
            row['fix'] = ('Require native ObjectLockConfiguration wrapper; do not accept the old flat synthetic fixture.'
                          if status == 'native-response-envelope-mismatch' else
                          'Retain native accessRules; public FAIL, private with no overrides PASS, private allowing object overrides UNKNOWN without claiming complete object exposure.')
        if cid in dispositions:
            row['found_status'] = status
            row['status'], row['current_contract'], row['directed_sdk_test'] = dispositions[cid]
        row['automatic_scope_excluded'] = cid in excluded
        if cid in excluded:
            row['exclusion_reason'] = excluded[cid]['reason']
        case = cases.get(cid, {})
        if 'pass' in case and cid in checks and status != 'readonly-telemetry-unavailable-by-design':
            data = deepcopy(case['pass'])
            index = deepcopy(case.get('pass_index', case.get('case_indices', {}).get('pass', case.get('index', {}))))
            row['synthetic_fixture_status'] = checks[cid].evaluate(data, index)[0]
            key = field.split('.')[-1]
            if status == 'native-response-envelope-mismatch':
                key = 'ObjectLockEnabled'
            def remove(value):
                if isinstance(value, dict):
                    value.pop(key, None)
                    for child in value.values():
                        remove(child)
                elif isinstance(value, list):
                    for child in value:
                        remove(child)
            remove(data)
            remove(index)
            outcome = checks[cid].evaluate(data, index)
            row['historical_field_removal'] = {'status': outcome[0], 'reason': outcome[1].get('reason')}
        rows.append(row)
    return rows


def required_producer_gaps(cases, active):
    """Manually source-traced complete routes; absence of a modeled path alone is insufficient."""
    from peaso.collectors import aws
    from peaso.collectors import aws_facts_compute_edge as edge, aws_facts_swc as swc
    contracts = [
        ('aws_cis_lightsail_ssm_patch_compliance', 'lightsail_instance', ['SsmMatch', 'PatchState'],
         [aws._enrich],
         'Native GetInstances has neither field and this kind has no registered fetcher or enricher. The base deep-copy enrichment has no Lightsail-instance branch or SSM association. No native instance-to-SSM identity match is supplied.',
         'Design a reliable owner-approved Lightsail-to-SSM identity binding, then request-bound DescribeInstancePatchStates; retain UNKNOWN until that binding exists.'),
        ('aws_cis_elasticbeanstalk_https_listener', 'elastic_beanstalk_environment', ['EnvironmentResources', 'AssociatedLoadBalancers'],
         [edge._beanstalk_environments, edge._beanstalk_configuration],
         'Native DescribeEnvironments Resources.LoadBalancer is a different shape. The only fetcher/enricher reads DescribeEnvironments and filtered DescribeConfigurationSettings; neither produces EnvironmentResources/AssociatedLoadBalancers or invokes DescribeEnvironmentResources and LB joins.',
         'Add complete native environment-resource association and name/ARN-bound ELB/ELBv2 listener reads before evaluating TLS; do not rename the shallow native Resources object.'),
        ('aws_cis_elasticbeanstalk_load_balancer_access_logs', 'elastic_beanstalk_environment', ['EnvironmentResources', 'AssociatedLoadBalancers'],
         [edge._beanstalk_environments, edge._beanstalk_configuration],
         'Same unproduced environment-to-load-balancer join; no associated native attributes/log destination are emitted by this route.',
         'Share a complete environment-resource/LB join and explicitly read LB attributes with identity and coverage validation.'),
        ('aws_cis_beanstalk_persistent_logs_s3', 'elastic_beanstalk_environment', ['Configuration.hostmanager_options_complete', 'S3LogDestination'],
         [edge._beanstalk_configuration],
         'The callback allowlists only StreamLogs, ManagedActionsEnabled and health SystemType, discarding hostmanager LogPublicationControl. It emits neither hostmanager_options_complete nor S3LogDestination.',
         'Retain documented hostmanager publication metadata with native completeness and derive a verified S3 destination; do not invent an inferred bucket/prefix.'),
        ('aws_wafv2_request_validation_rules', 'load_balancer_v2', ['WAFWebACLArn'],
         [swc._lb],
         'Native DescribeLoadBalancers has no WAFWebACLArn. The registered _lb projection only reads DescribeListeners, adds Listeners and source provenance. WAF association requires a separate service API and validated join.',
         'Use request-bound WAFv2 GetWebACLForResource or a complete ListResourcesForWebACL join, including explicit absent association and denial states.'),
    ]
    checks = {c.id: c for c in native.registry()}
    output = []
    for cid, kind, paths, callbacks, evidence, proposal in contracts:
        case = cases[cid]
        data = deepcopy(case['pass'])
        index = deepcopy(case.get('pass_index', case.get('case_indices', {}).get('pass', case.get('index', {}))))
        before = checks[cid].evaluate(data, index)[0]
        # Delete the exact first missing root/leaf throughout mirrored fixtures.
        key = paths[0].split('.')[-1]
        def remove(value):
            if isinstance(value, dict):
                value.pop(key, None)
                for child in value.values():
                    remove(child)
            elif isinstance(value, list):
                for child in value:
                    remove(child)
        remove(data)
        remove(index)
        after, details = checks[cid].evaluate(data, index)
        integrated_waf = cid == 'aws_wafv2_request_validation_rules' and 'peaso.collectors.aws_alb_waf_association_metadata' in aws.EXTENSION_MODULES
        from peaso.checks.native_only import exclusions
        archived = cid in exclusions()
        integrated_beanstalk = kind == 'elastic_beanstalk_environment' and 'peaso.collectors.aws_beanstalk_runtime_metadata' in aws.EXTENSION_MODULES
        output.append({'id': cid, 'kind': kind, 'required_paths': paths, 'currently_active': cid in active,
            'automatic_scope_excluded': archived,
            'status': 'fixed-native-association-producer' if integrated_waf else 'fixed-native-beanstalk-runtime-producer' if integrated_beanstalk else 'archived-exact-contract' if archived else 'confirmed-required-producer-gap', 'evidence': evidence, 'fix_proposal': proposal,
            'route_sources': [native.source_ref(fn) for fn in callbacks],
            'synthetic_positive_status': before, 'synchronized_field_removal': {'field': key, 'status': after, 'reason': details.get('reason')},
            'runtime_fix_authorized': integrated_waf or integrated_beanstalk,
            'current_fix': 'Request-bound own-account regional GetWebACLForResource; explicit nonexistent-item absence only; no consumer edit.' if integrated_waf else 'Sibling-owned native environment/resources/LB listener/attributes producer and documented managed log path resolution; no delivered-log or retention claim.' if integrated_beanstalk else None,
            'modeled_absence_alone_is_not_proof': True})
    return output


def kind_remainder(rows, producers):
    """Account for every represented kind; never call a candidate a proven bug."""
    output = []
    for kind in sorted(producers):
        related = [row for row in rows if kind in {row['kind'], *row['dependencies']} or any(f['kind'] == kind for f in row['fields'])]
        grouped = {}
        for row in related:
            for field in row['fields']:
                if field['kind'] != kind or field['status'] in ('proven-native-shape', 'derived-producer'):
                    continue
                entry = grouped.setdefault(field['path'], {'path': field['path'], 'ids': set(),
                    'required_accessor_ids': set(), 'sdk_base_member_possible': field['sdk_shape_member']})
                entry['ids'].add(row['id'])
                if field.get('required_accessor_observed'):
                    entry['required_accessor_ids'].add(row['id'])
        paths = []
        for entry in grouped.values():
            entry['ids'] = sorted(entry['ids'])
            entry['required_accessor_ids'] = sorted(entry['required_accessor_ids'])
            entry['disposition'] = ('possible-native-member-unexercised' if entry['sdk_base_member_possible']
                                    else 'detail-or-derived-contract-unproved')
            paths.append(entry)
        output.append({'kind': kind, 'active_ids': sorted(row['id'] for row in related),
            'public_pipeline_status': producers[kind]['public_pipeline_probe']['collection_status'] if 'collection_status' in producers[kind]['public_pipeline_probe'] else 'undemonstrated',
            'unproved_paths': sorted(paths, key=lambda r: (-bool(r['required_accessor_ids']), -len(r['required_accessor_ids']), r['path'])),
            'semantic_completeness_proven': False})
    return output


def regression_receipts():
    receipts = []
    for name in ('field-final-bounded.xml', 'field-producers.xml', 'field-alb-waf.xml', 'field-native-producer-receipts.xml', 'field-base-edge.xml', 'field-sw40-iam.xml', 'rds-backtracking-legacy.xml', 'object-lock-legacy.xml', 'lightsail-legacy.xml'):
        path = native.DEFAULT_RECEIPTS / name
        if not path.exists():
            receipts.append({'path': str(path), 'status': 'not-found'})
            continue
        suites = ET.parse(path).getroot()
        cases = list(suites.iter('testcase'))
        receipts.append({'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                         'tests': len(cases), 'failures': sum(c.find('failure') is not None for c in cases),
                         'errors': sum(c.find('error') is not None for c in cases),
                         'skipped': sum(c.find('skipped') is not None for c in cases)})
    return receipts


def lightsail_ssm_contract_review(models, active):
    """Bounded installed-model identity audit, not an assertion about future APIs."""
    model = models.session.get_service_model('lightsail')
    reviewed, candidates = [], []
    for name in model.operation_names:
        if not name.startswith(('Get', 'List')):
            continue
        reviewed.append(name)
        seen = set()
        def visit(shape, path='', depth=0):
            if shape is None or depth > 16 or shape.name in seen:
                return
            seen.add(shape.name)
            if shape.type_name == 'structure':
                for key, child in shape.members.items():
                    selected = '.'.join(filter(None, (path, key)))
                    if any(term in key.lower() for term in ('instanceid', 'sourceid', 'ssm', 'managedinstance')):
                        candidates.append({'operation': name, 'path': selected})
                    visit(child, selected, depth + 1)
            elif shape.type_name == 'list':
                visit(shape.member, path + '[]', depth + 1)
            elif shape.type_name == 'map':
                visit(shape.value, path + '.*', depth + 1)
        visit(model.operation_model(name).output_shape)
    instance = shape_at(models.output('lightsail', 'get_instance'), 'instance')
    managed = shape_at(models.output('ssm', 'describe_instance_information'), 'InstanceInformationList')
    alternatives = ['aws.cb.ssm.instance_patch_compliant', 'aws.cb.ssm.resource_compliance_summary_compliant']
    return {'id': 'aws_cis_lightsail_ssm_patch_compliance', 'status': 'unsupported-exact-join-in-reviewed-native-surfaces',
        'reviewed_get_list_operations': sorted(reviewed), 'candidate_cross_identity_members': candidates,
        'get_instance_fields': sorted(instance.members), 'ssm_source_types': managed.members['SourceType'].enum,
        'support_code_documentation': instance.members['supportCode'].documentation,
        'support_code_documentation_sha256': hashlib.sha256(instance.members['supportCode'].documentation.encode()).hexdigest(),
        'conclusion': 'No documented immutable Lightsail ARN to SSM managed-node ID binding in the reviewed installed SDK read surfaces. supportCode is documented only as a support lookup code. IP/name/tags/supportCode heuristics are not accepted.',
        'proposal': 'Root-owned unsupported_exact_contract archival under the current native read-only contract, preserving active managed-node patch alternatives. This does not claim every future provider interface is impossible.',
        'active_alternatives': {cid: cid in active for cid in alternatives}}


def consumer_receipts():
    contracts = [
        *[(cid, 'tests/test_aws_beanstalk_runtime_metadata_review.py', 'test_real_sdk_cache_and_registered_snapshot_positive_negative', 'field-beanstalk.xml', 'Sibling native configuration/resources/classic-or-v2 LB reads through real cache and registered snapshot consumer; log destination is documented managed-path resolution only, not delivery or retention.')
          for cid in ('aws_cis_elasticbeanstalk_https_listener', 'aws_cis_elasticbeanstalk_load_balancer_access_logs', 'aws_cis_beanstalk_persistent_logs_s3')],
        ('aws.a.iam.report_console_mfa', 'tests/test_aws_field_producer_review.py', 'test_sdk_existing_csv_report_public_pipeline_to_registered_consumer', 'field-producers.xml', 'SDK existing report blob through public collector CSV parser to registered snapshot consumer; no report generation.'),
        ('aws_wafv2_request_validation_rules', 'tests/test_aws_alb_waf_association_metadata.py', 'test_sdk_public_lb_pipeline_to_consumer_with_controlled_waf_inventory', 'field-alb-waf.xml', 'Actual SDK public ALB pipeline and request-bound WAF association to registered consumer with controlled WAF subject inventory; PASS/FAIL/UNKNOWN. Root owns shared hook.'),
        ('aws_cis_lambda_execution_role_no_admin', 'tests/test_aws_lambda_role_policy_review_20261019.py', 'test_legacy_actual_sdk_native_branches', 'field-native-producer-receipts.xml', 'Native Lambda/IAM read branches to legacy registered consumer; no EffectiveAdminAccess flag.'),
        ('aws_ec2_instance_time_offset_monitored', 'tests/test_aws_ec2_clock_metadata_review.py', 'test_native_metric_requests_through_registered_consumer', 'field-native-producer-receipts.xml', 'Actual SDK metric requests through enrich and registered snapshot consumer; positive/negative offsets.'),
        ('aws_cloudtrail_s3_siem_delivery', 'tests/test_aws_cloudtrail_s3_delivery_metadata_review.py', 'test_real_sdk_enrichment_cache_and_registered_snapshot_consumer', 'field-native-producer-receipts.xml', 'Actual SDK metadata reads through pre-cache projection, enrichment and registered snapshot consumer; bounded delivery only.'),
        ('aws.claude_a.ec2.launch_template_instances_no_public_ip', 'tests/test_aws_launch_template_instance_metadata_review.py', 'test_real_sdk_shared_cache_enrichment_and_registered_snapshot_consumer', 'field-native-producer-receipts.xml', 'Actual SDK GetLaunchTemplateData through shared cache, enrichment and registered snapshot consumer.'),
        ('aws_nist_rds_db_cluster_aurora_backtracking_enabled', 'tests/test_aws_field_producer_review.py', 'test_backtracking_sdk_to_public_collector_to_registered_predicate', 'field-producers.xml', 'SDK DescribeDBClusters through public collector, validated snapshot and registered predicate.'),
        ('aws_cis_lightsail_bucket_private', 'tests/test_aws_field_producer_review.py', 'test_lightsail_sdk_public_collector_retains_native_access_rules', 'field-producers.xml', 'SDK GetBuckets through public collector and registered accessRules predicate.'),
        ('aws_cloudtrail_bucket_lifecycle_retention_365', 'tests/test_aws_field_producer_review.py', 'test_sdk_bucket_object_lock_response_wrapper_reaches_retention_predicate', 'field-producers.xml', 'SDK settings through actual bucket callback and registered predicate using synchronized dependency fixture; full public dispatch not exercised in this receipt.'),
        ('aws.a.iam.attached_policy_no_star_star', 'tests/test_aws_field_producer_review.py', 'test_sdk_gaad_public_pipeline_binds_managed_default_version[aws.a.iam.attached_policy_no_star_star', 'field-producers.xml', 'SDK GAAD through public collector to registered snapshot consumer; missing/duplicate/mismatched default joins UNKNOWN.'),
        ('aws.pci.iam.nonconsole_mfa_policy', 'tests/test_aws_field_producer_review.py', 'test_sdk_gaad_public_pipeline_binds_managed_default_version[aws.pci.iam.nonconsole_mfa_policy', 'field-producers.xml', 'SDK GAAD through public collector to registered snapshot consumer; native default identity validated.'),
        ('aws.pci.iam.policy_attached_to_active_principal', 'tests/test_aws_field_producer_review.py', 'test_sdk_gaad_public_pipeline_binds_managed_default_version[aws.pci.iam.policy_attached_to_active_principal', 'field-producers.xml', 'SDK GAAD user/group/role/policy inventories through public collector to native declared-attachment snapshot consumer.'),
    ]
    output = []
    for cid, source, prefix, receipt, contract in contracts:
        path = native.DEFAULT_RECEIPTS / receipt
        combined = native.DEFAULT_RECEIPTS / 'field-final-bounded.xml'
        if receipt in ('field-producers.xml', 'field-alb-waf.xml', 'field-beanstalk.xml') and combined.exists():
            path = combined
        tests = []
        if path.exists():
            for case in ET.parse(path).getroot().iter('testcase'):
                if case.get('name', '').startswith(prefix):
                    tests.append({'name': case.get('name'), 'classname': case.get('classname'),
                                  'passed': all(case.find(state) is None for state in ('failure', 'error', 'skipped'))})
        output.append({'id': cid, 'test_source': source, 'source_sha256': hashlib.sha256((ROOT / source).read_bytes()).hexdigest(),
            'receipt': str(path), 'receipt_sha256': hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None,
            'tests': tests, 'status': 'executed-bounded-sdk-receipt' if tests and all(t['passed'] for t in tests) else 'unproved',
            'source_modified_after_receipt': path.exists() and (ROOT / source).stat().st_mtime_ns > path.stat().st_mtime_ns,
            'contract': contract, 'semantic_completeness_proven': False})
    return output


def pipeline_source_fingerprint():
    """Bind emission receipts to the exact collector/snapshot pipeline sources."""
    paths = [*(ROOT / 'peaso/collectors').glob('aws*.py'), ROOT / 'peaso/snapshot.py']
    manifest = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(paths)}
    return hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()


def sdk_emission_receipts(additional_receipts=()):
    """Read exact field paths recorded from actual SDK test pipeline outputs.

    Passing test/source hashes are required. The receipt proves field emission
    for these executions, not value correctness or semantic branch completeness.
    """
    receipts, rejected = {}, []
    current_pipeline = pipeline_source_fingerprint()
    paths = [native.DEFAULT_RECEIPTS / name for name in ('field-final-bounded.xml', 'field-producers.xml', 'field-alb-waf.xml')]
    paths.extend(Path(path).resolve() for path in additional_receipts)
    for path in dict.fromkeys(paths):
        if not path.exists():
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        for case in ET.parse(path).getroot().iter('testcase'):
            for prop in case.findall('./properties/property'):
                if prop.get('name') != 'aws_field_emission':
                    continue
                value = json.loads(prop.get('value', '{}'))
                source = ROOT / value.get('test_source', '')
                reason = None
                if any(case.find(state) is not None for state in ('failure', 'error', 'skipped')):
                    reason = 'test-did-not-pass'
                elif not source.is_file() or source.resolve().parent != (ROOT / 'tests').resolve():
                    reason = 'unknown-test-source'
                elif hashlib.sha256(source.read_bytes()).hexdigest() != value.get('test_source_sha256'):
                    reason = 'test-source-hash-changed'
                elif value.get('pipeline_source_fingerprint') != current_pipeline:
                    reason = 'collector-pipeline-source-hash-changed'
                if reason:
                    rejected.append({'receipt': str(path), 'test': case.get('name'), 'reason': reason})
                    continue
                key = hashlib.sha256((str(path) + case.get('classname', '') + case.get('name', '') + prop.get('value', '')).encode()).hexdigest()[:20]
                receipts[key] = {**value, 'receipt': str(path), 'receipt_sha256': digest,
                    'test': case.get('classname', '') + '::' + case.get('name', ''),
                    'status': 'executed-sdk-pipeline-field-emission', 'semantic_completeness_proven': False}
    return receipts, rejected


def build(additional_receipts=()):
    import botocore
    from peaso.checks.facts import FIELD_SPECS
    active = native.active_ids()
    checks = [c for c in native.registry() if c.id in active]
    registered = {c.id for c in checks}
    models = Models()
    sdk_receipts, rejected_sdk_receipts = sdk_emission_receipts(additional_receipts)
    sdk_by_kind = {}
    for receipt_id, receipt in sdk_receipts.items():
        sdk_by_kind.setdefault(receipt['kind'], []).append(receipt_id)
    producers, shapes, graphs = {}, {}, {}
    cases = native.behavior_module().CASES
    rows = []
    for check in checks:
        functions = callback_graph(check)
        reads = static_reads(functions)
        witnesses, outcomes = fixture_reads(check, cases.get(check.id, {}))
        if check.id in FIELD_SPECS:
            reads.append({'path': FIELD_SPECS[check.id]['path'], 'object': 'item', 'accessor': 'FIELD_SPECS', 'file': 'peaso/checks/facts.py', 'line': 60})
        kinds = set(check.dependencies) | {check.kind} | {w['kind'] for w in witnesses if w['kind'] and w['kind'] != '@engine'}
        for kind in sorted(kinds):
            if kind not in producers:
                producers[kind], shapes[kind] = producer(kind, models)
                producers[kind]['modeled_probe'] = probe_producer(kind, models)
                producers[kind]['public_pipeline_probe'] = probe_producer(kind, models, public_pipeline=True)
        fields = []
        for witness in witnesses:
            kind, path = witness['kind'], witness['path']
            shape = shape_at(shapes.get(kind), path) if kind else None
            emission_receipts = [name for name in ('modeled_probe', 'public_pipeline_probe')
                                 if kind in producers and path in producers[kind][name]['paths']]
            field_sdk_receipts = [rid for rid in sdk_by_kind.get(kind, []) if path in sdk_receipts[rid]['paths']]
            produced = bool(emission_receipts or field_sdk_receipts)
            engine_produced = kind == '@engine' and engine_field_produced(path, kinds)
            field = {**witness, 'sdk_shape_member': shape is not None,
                     'modeled_projection_emits_path': bool(emission_receipts), 'emission_receipts': emission_receipts,
                     'sdk_emission_receipts': field_sdk_receipts, 'producer_emission_demonstrated': produced,
                     'status': ('proven-native-shape' if produced and shape is not None and producers[kind]['native_shape_retention_proven']
                                else 'derived-producer' if produced or engine_produced else 'witness-only')}
            if kind == '@engine':
                field['engine_metadata_source'] = 'peaso/engine.py::_index/scoped_index; peaso/collectors/aws.py::collect.append'
            fields.append(field)
        # Unvisited literal direct-root reads still need ledger entries.
        witnessed = {(f['kind'], f['path']) for f in fields}
        for read in reads:
            if read['accessor'] == 'FIELD_SPECS' and read['path'] and (check.kind, read['path']) not in witnessed:
                shape = shape_at(shapes[check.kind], read['path'])
                fields.append({'kind': check.kind, 'path': read['path'], 'attribution': 'static-item-may-be-helper-parameter',
                               'sdk_shape_member': shape is not None, 'status': 'needsmanualreview'})
        unvisited_static = [read for read in reads if read['path'] is None or not any(
            f['path'] == read['path'] or f['path'].endswith('.' + read['path']) for f in fields)]
        unresolved = [f for f in fields if f['status'] not in ('proven-native-shape', 'derived-producer')]
        # Static helper parameters may be renamed, direct .get/subscript reads
        # and conditional branches are not exhaustively tracked by witnesses.
        status = 'witness-only' if witnesses else 'needsmanualreview'
        dynamic_unresolved = any(r['path'] is None for r in reads) and check.id not in FIELD_SPECS
        if fields and not unresolved and not dynamic_unresolved:
            status = 'proven-native-shape' if all(f['status'] == 'proven-native-shape' for f in fields) else 'derived-producer'
        graph = {'callbacks': [native.source_ref(f) for f in functions], 'static_accessor_reads': reads}
        graph_id = hashlib.sha256(json.dumps(graph, sort_keys=True).encode()).hexdigest()[:16]
        graphs[graph_id] = graph
        blockers = []
        if unresolved:
            blockers.append(f'{len(unresolved)} identified fields have only fixture/static evidence; inspect the listed paths and kind projection contracts.')
        if dynamic_unresolved:
            blockers.append('Dynamic accessor arguments need additional branch-specific tracing.')
        if not witnesses:
            blockers.append('No attributed accessor read from the bounded saved-fixture walk.')
        if check.id in EXACT_DICT_IMAGE_EVALUATORS:
            blockers.append('Exact-dict native image proof prevents dict-subclass read tracing; complete verdict and evidence equality was replayed under the accessor-call profiler, with direct reads left for static source review.')
        rows.append({'id': check.id, 'kind': check.kind, 'dependencies': list(check.dependencies),
                     'status': status, 'callback_contract': graph_id,
                     'fields': fields, 'fixture_outcomes': outcomes,
                     'unproved_contracts': [{'kind': f['kind'], 'path': f['path'],
                         'reason': 'no modeled or accepted SDK emission receipt for this exact attributed path',
                         'required_accessor_observed': f.get('required_accessor_observed', False)} for f in unresolved],
                     'unvisited_static_reads': unvisited_static,
                     'direct_dict_instrumentation': 'exact_dict_native_predicate' if check.id in EXACT_DICT_IMAGE_EVALUATORS else 'tracked_dict',
                     'branch_completeness_proven': False,
                     'semantic_completeness_proven': False, 'live_verified': False,
                     'blockers': blockers})
    # Review every supported AWS kind, including kinds with no active consumer.
    from peaso.collectors import aws
    for kind in sorted(aws.AWS_TYPES):
        if kind not in producers:
            producers[kind], shapes[kind] = producer(kind, models)
            producers[kind]['modeled_probe'] = probe_producer(kind, models)
            producers[kind]['public_pipeline_probe'] = probe_producer(kind, models, public_pipeline=True)
    fixed = next((f for c in checks if c.id == 'aws_nist_rds_db_cluster_aurora_backtracking_enabled'
                  for f in callback_graph(c) if f.__name__ == '_backtracking'), None)
    triage = producer_triage(cases, active)
    for finding in triage:
        kind, path = finding['kind'], finding['field']
        finding['base_sdk_member_exists'] = shape_at(shapes.get(kind), path) is not None
        finding['modeled_projection_emits_path'] = path in producers[kind]['modeled_probe']['paths']
        finding['projection_miss_alone_is_not_evidence'] = True
        if finding.get('found_status', finding['status']) == 'native-response-envelope-mismatch':
            correct = path.replace('ObjectLock.', 'ObjectLockConfiguration.', 1)
            finding['correct_api_contract'] = {'service': 's3', 'operation': 'get_object_lock_configuration',
                                              'path': correct, 'sdk_member_exists': shape_at(models.output('s3', 'get_object_lock_configuration'), correct) is not None}
    from peaso.checks.native_only import exclusions
    return {'schema_version': 2,
            'source_input_hashes': {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
                for path in sorted({'scripts/audit_aws_field_producers.py', 'scripts/audit_aws_native_contracts.py',
                    'peaso/rulepacks/native_catalog.json', 'peaso/checks/native_only.json', 'peaso/checks/bulk_pending.json',
                    'peaso/checks/facts.py', 'tests/fixtures/release-test-inputs.json.xz',
                    *[ref['file'] for graph in graphs.values() for ref in graph['callbacks']]})},
            'behavior_witness_sha256': hashlib.sha256(json.dumps(cases, sort_keys=True, default=str).encode()).hexdigest(),
            'scope': 'active AWS catalog snapshot', 'botocore_version': botocore.__version__,
            'active_ids': len(active), 'supported_aws_kinds': len(aws.AWS_TYPES),
            'catalog_sha256': hashlib.sha256((ROOT / 'peaso/rulepacks/native_catalog.json').read_bytes()).hexdigest(),
            'catalog_ids_pending_exclusion_rebuild': sorted(active & set(exclusions())), 'missing_registered_ids': sorted(active - registered),
            'counts': dict(Counter(r['status'] for r in rows)),
            'evidence_boundary': 'Review status covers identified accessor fields only, not exhaustive semantics. SDK shape membership proves only API-boundary possibility; credited field emission requires an executed modeled or source-bound SDK pipeline receipt. Derived-producer means the actual callback emitted the path in a modeled probe or a passing SDK-pipeline receipt with matching recorded test-source and collector-pipeline hashes; this does not prove values, availability, branch completeness, SDK parameter correctness, or real-world success. Fixtures prove reads only. No cloud calls, live proof, or new broad predicate gate.',
            'preserved_prior_gate': '/tmp/peasso-aws-review-20261019/native (10,565 baseline passes; not rerun)',
            'callback_contracts': graphs, 'producers': producers, 'checks': rows,
            'pipeline_source_fingerprint': pipeline_source_fingerprint(),
            'sdk_emission_receipts': sdk_receipts, 'rejected_sdk_emission_receipts': rejected_sdk_receipts,
            'producer_triage': triage, 'confirmed_required_producer_gaps': required_producer_gaps(cases, active),
            'kind_remainder': kind_remainder(rows, producers),
            'lightsail_ssm_identity_review': lightsail_ssm_contract_review(models, active),
            'collector_source_hashes': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                                       for p in sorted((ROOT / 'peaso/collectors').glob('aws*.py'))},
            'bounded_runtime_fix_hashes': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in
                ['peaso/checks/aws_a_iam_policies.py', 'peaso/checks/claude2_aws_b_edge.py', 'peaso/checks/compliance_new_sw40.py', 'peaso/checks/compliance_new_sw35.py', 'peaso/checks/compliance_new_sw42.py', 'peaso/checks/compliance_new_sw43.py', 'peaso/collectors/aws_facts_swc.py']},
            'regression_receipts': regression_receipts(), 'producer_consumer_receipts': consumer_receipts(),
            'corrected_semantic_branches': [
                {'id': 'aws.c2b.cloudfront.s3_origin_bucket_exists',
                 'before': 'External origin absent from owned inventory plus synthetic collected 403 probe returned PASS; 404 returned FAIL.',
                 'after': 'External origins return UNKNOWN for unbound 200/301/400/403/404. Complete owned inventory remains positive existence evidence.',
                 'native_contract': 'Installed botocore HeadBucket documentation explicitly makes generic 400/403/404 ambiguous between missing and inaccessible.',
                 'missing_producer': 'No request-bound OriginBucketProbes collector contract exists; no probe source was invented.',
                 'test': 'tests/test_aws_field_producer_review.py::test_sdk_head_bucket_generic_error_is_not_bucket_existence_evidence'},
                {'ids': ['aws.a.iam.attached_policy_no_star_star', 'aws.pci.iam.nonconsole_mfa_policy', 'aws.pci.iam.policy_attached_to_active_principal'],
                 'before': 'Base attached-policy check returned PASS with DefaultVersionId=v2 and sole flagged safe VersionId=v1. The sw40 helper also selected by flag alone (source review).',
                 'after': 'Unique nonempty VersionId values and exactly one flagged default matching nonempty DefaultVersionId required; contradictions/missing identity UNKNOWN.',
                 'test': 'tests/test_aws_field_producer_review.py::test_sdk_gaad_public_pipeline_binds_managed_default_version'}],
            'limitations': ['Literal get/optional/api_optional, direct dict.get/subscript and FIELD_SPECS reads are statically enumerated; saved-fixture dict subclasses additionally trace direct input reads with baseline status/evidence equality. Derived copies, aliases and unvisited control-flow branches remain unproved.',
                            'Source-traced AccountId/Region append metadata is credited separately from service API responses.',
                            'Each kind has a separate public collector pipeline probe, exercising actual nested dispatch, provenance and omission normalization. Empty/error envelopes and missed optional branches remain unproved; callback-only and public receipts are distinguished per field.',
                            'Modeled SDK output is validated, but placeholder identities, optional combinations, request parameters and real service availability are not certified.',
                            'Observed get/subscript reads are strict accesses in particular visited branches, not proof that the field is universally required; optional() can internally call get(). Candidate lists are not confirmed bugs.',
                            'Optional content retrieval is disabled; those callbacks retain explicit unproved content-producer fields.'],
            'confirmed_gaps': [{'id': 'aws_nist_rds_db_cluster_aurora_backtracking_enabled',
                                'field': 'BacktrackingSupported', 'status': 'fixed-under-bounded-runtime-ownership',
                                'evidence': 'DescribeDBClusters DBCluster has BacktrackWindow but no BacktrackingSupported; no collector derivation exists. Removing this synthetic field from the positive item and mirrored dependency inventory yields UNKNOWN missing fact: BacktrackingSupported.',
                                'fix': 'Require native BacktrackWindow; explicit positive PASS and zero FAIL follow SDK field documentation; missing/negative/malformed UNKNOWN. Known non-Aurora engines retain NOT_APPLICABLE.',
                                'fixed_evaluator': native.source_ref(fixed) if fixed else None,
                                'source_sha256': hashlib.sha256((ROOT / 'peaso/checks/compliance_new_sw43.py').read_bytes()).hexdigest(),
                                'sdk_field_documentation_sha256': hashlib.sha256(shapes['rds_cluster'].members['BacktrackWindow'].documentation.encode()).hexdigest(),
                                'regression_receipts': ['/tmp/peasso-aws-review-20261019/native/field-producers.xml', '/tmp/peasso-aws-review-20261019/native/rds-backtracking-legacy.xml']} ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk-receipt", action="append", default=[], type=Path, help="Additional source-bound JUnit SDK emission receipt; hashes and passing outcomes remain mandatory")
    args = parser.parse_args()
    for path in args.sdk_receipt:
        if not path.is_file():
            parser.error("SDK receipt does not exist: " + str(path))
    report = build(args.sdk_receipt)
    destination = ROOT / 'docs/aws-review/field-producers.json'
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, separators=(',', ':'), sort_keys=True) + '\n')
    lines = ['# AWS field producer review', '', report['evidence_boundary'], '',
        f"Snapshot: {report['active_ids']} active IDs, {len(report['checks'])} unique rows, {report['supported_aws_kinds']} supported AWS kinds. Catalog SHA256 `{report['catalog_sha256']}`.",
        f"Catalog IDs awaiting root exclusion rebuild: {report['catalog_ids_pending_exclusion_rebuild']}. Observed-field review states: {report['counts']}. These are not completed semantic reviews. Installed botocore: {report['botocore_version']}.", '',
        'Each kind has callback-only and public collector pipeline probes. Both use SDK-validated modeled responses and execute real Requests/cache/projection code; public probes additionally execute nested dispatch, append metadata and snapshot validation. '
        'Per-field `emission_receipts` identify modeled probes and `sdk_emission_receipts` identify passing SDK pipeline executions that recorded that exact emitted path with matching test-source and collector-pipeline hashes. Possible SDK members, source literals and saved-fixture reads do not count as producer-to-consumer proof. '
        'Direct dictionary input reads are traced with normal-versus-instrumented status/evidence equality; static aliases and unvisited branches remain explicit in JSON.', '',
        '## Confirmed required-contract history and dispositions', '',
        'These five IDs have source-reviewed missing-contract history and synchronized positive-fixture removal reproductions. They take priority over optional/unvisited modeled paths. WAF association and sibling-owned Beanstalk contracts now have native producers; current integration and archival state are explicit per row. These repaired history rows do not imply their required fields remain unproduced.', '',
        '| ID | Historical missing paths | Current disposition | Causal reproduction | Resolution / proposal |', '|---|---|---|---|---|']
    for row in report['confirmed_required_producer_gaps']:
        paths = ', '.join(row['kind'] + '.' + path for path in row['required_paths'])
        resolution = row['current_fix'] or ('Root archived the unsupported exact Lightsail-to-SSM contract; native managed-node patch alternatives remain active.' if row['automatic_scope_excluded'] else row['fix_proposal'])
        lines.append(f"| {row['id']} | {paths} | {row['status']} | {row['synthetic_positive_status']} → {row['synchronized_field_removal']['status']}: {row['synchronized_field_removal']['reason']} | {resolution} |")
    identity = report['lightsail_ssm_identity_review']
    lines.extend(['', f"Lightsail identity review: {len(identity['reviewed_get_list_operations'])} modeled Get/List operations, no candidate immutable cross-identity member. SSM SourceType values: {identity['ssm_source_types']}. " + identity['conclusion'] + ' ' + identity['proposal'], '', 'Route source hashes and source reasoning are recorded in `confirmed_required_producer_gaps`; a modeled path miss alone establishes none of these findings.', '',
        '## Corrected false decisions', '',
        'CloudFront external-origin probes previously returned PASS for 403 and FAIL for 404. Generic HeadBucket errors cannot establish either conclusion; all unbound probe codes now leave external origins UNKNOWN, while complete owned bucket inventory still proves a positive existence observation. '
        'No OriginBucketProbes producer was invented. Native 200 would require a separately implemented request/bucket-binding contract before receiving credit.', '',
        'The base attached-policy evaluator and sw40 managed-policy helper now require unique nonempty version IDs and exactly one flagged default matching DefaultVersionId. Missing or contradictory joins return UNKNOWN; valid declared empty-list semantics remain unchanged. '
        'The exact sw40 module pin was updated atomically. Coordinator owns central catalog/descriptions and final gates.', '',
        '## Refreshed historical ten-path triage', '',
        'The historical paths below remain as findings history, not a claim that repaired consumers still require them. Lambda uses native policy declarations; exact EC2 listening semantics are archived; clock metrics, bounded CloudTrail S3 delivery metadata and launch-template details now have native producers. '
        'ObjectLock, Lightsail and RDS retain their prior bounded corrections. ServicesLastAccessed now has a selection-gated native Read-classified report producer; its bounded SDK receipt does not certify every history branch or effective access.', '',
        '| ID | Historical path | Current disposition | Active catalog / excluded |', '|---|---|---|---|'])
    for row in report['producer_triage']:
        lines.append(f"| {row['id']} | {row['kind']}.{row['field']} | {row['status']} | {row['currently_active']} / {row['automatic_scope_excluded']} |")
    lines.extend(['', 'RDS: the old synthetic BacktrackingSupported dependency was removed; native BacktrackWindow positive/zero/missing/malformed branches have SDK-to-public-collector regressions. Full capability/version support inference remains outside this proof.', '',
        '## Executed producer-to-consumer receipts', '',
        'These receipts cover bounded SDK cases only. They do not establish live availability, all optional API branches, complete effective access or a finished semantic review.', '',
        '| ID | Executed cases | Contract |', '|---|---:|---|'])
    for row in report['producer_consumer_receipts']:
        lines.append(f"| {row['id']} | {len(row['tests'])} ({row['status']}) | {row['contract']} Test: `{row['test_source']}` |")
    lines.extend(['', 'Exact test names, receipt/source hashes and source-after-receipt checks are in JSON. JUnit files are bounded local receipts under `/tmp/peasso-aws-review-20261019/native`.', '',
        'Verification receipts: ' + '; '.join(f"{Path(r['path']).name}: {r.get('tests', '?')} tests, {r.get('failures', '?')} failures, {r.get('errors', '?')} errors" for r in report['regression_receipts']) + '.', '',
        'Reproduce: `.venv/bin/python scripts/audit_aws_field_producers.py`. Targeted verification: `.venv/bin/python -m pytest -q tests/test_aws_field_producer_review.py`.', '',
        'The prior 10,565-pass baseline is preserved as history, not rerun or extended by this audit.', '',
        '## Systematic remainder by AWS kind', '',
        'Every supported kind is probed, including those without active consumers. Required-column counts are paths with strict accesses observed in a visited fixture branch; they are not universally required field claims. '
        'JSON `kind_remainder` gives each exact path and affected IDs, distinguishing possible native members from unproved detail/derived contracts. These candidates require source review before being called missing producers.', '',
        '| Kind | Related IDs | Strict paths unproved | Other paths unproved | Public modeled status |', '|---|---:|---:|---:|---|'])
    for row in report['kind_remainder']:
        strict = sum(bool(path['required_accessor_ids']) for path in row['unproved_paths'])
        lines.append(f"| {row['kind']} | {len(row['active_ids'])} | {strict} | {len(row['unproved_paths']) - strict} | {row['public_pipeline_status']} |")
    lines.extend(['', '## Remaining boundaries', ''])
    lines.extend('- ' + limit for limit in report['limitations'])
    lines.extend(['', '## Every active AWS ID', '',
        'The strict-read column enumerates exact attributed paths without an emission receipt. Other unresolved reads and source-located static expressions are enumerated per ID in JSON `unproved_contracts` and `unvisited_static_reads`; callback source graphs are deduplicated under `callback_contracts`. '
        'Every row has semantic_completeness_proven=false and branch_completeness_proven=false.', '',
        '| ID | Observed-field state | Exact unproved observed strict reads | Other unproved / unvisited static |', '|---|---|---|---|'])
    for row in report['checks']:
        strict = [f for f in row['unproved_contracts'] if f['required_accessor_observed']]
        paths = '<br>'.join((f['kind'] or 'unattributed') + '.' + f['path'].replace('|', '&#124;') for f in strict) or '—'
        lines.append(f"| {row['id']} | {row['status']} | {paths} | {len(row['unproved_contracts']) - len(strict)} / {len(row['unvisited_static_reads'])} |")
    destination.with_suffix('.md').write_text('\n'.join(lines) + '\n')
    print(json.dumps({'active': report['active_ids'], 'rows': len(report['checks']), 'counts': report['counts'],
                      'kinds': len(report['producers']), 'historical_required_gaps': len(report['confirmed_required_producer_gaps']),
                      'unresolved_active_required_gaps': sum(row['status'] == 'confirmed-required-producer-gap' and row['currently_active'] for row in report['confirmed_required_producer_gaps']),
                      'missing': report['missing_registered_ids']}))


if __name__ == '__main__':
    main()
