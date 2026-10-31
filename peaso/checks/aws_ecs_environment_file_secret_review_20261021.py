"""Evidence-bound ECS environment file secret indicator review."""
from copy import deepcopy
import re
from peaso.collectors import aws_ecs_environment_file_secret_indicators as ecs
from peaso.collectors import aws_s3_selected_source_secret_indicators as s3
from . import aws_s3_selected_source_secret_review_20261020 as s3_check


def evaluate(item, index):
    try:
        ctx = index['context']; scope = ctx['scope']; meta = ctx['metadata']
        if ctx['provider'] != 'aws' or ecs.s3.SCOPE.fullmatch(scope) is None or meta[ecs.KIND + '_authorized'] is not True:
            raise ValueError()
        collection, = [c for c in index['collections'][ecs.KIND] if c.get('scope') == scope]
        rows = collection['items']; selected = meta[ecs.KIND + '_selection'][scope]
        if (collection['status'] not in ('collected', 'partial') or not isinstance(rows, list)
                or len({r['id'] for r in rows}) != len(rows) or set(r['id'] for r in rows) != set(selected)
                or sum(r == item for r in rows) != 1):
            raise ValueError()
        ident = item['id']; marker = item[ecs.MARKER]
        if (ident not in selected or set(marker) != {'schema', 'identity', 'scope', 'capture', 'associated',
                'file_count', 'ecs_request', 'ecs_after_request', 'association', 'association_coherent',
                's3_identity', 's3_item', 'uncovered_files'}
                or marker['schema'] != ecs.SCHEMA or marker['identity'] != ident or marker['scope'] != scope
                or marker['capture'] != meta[ecs.KIND + '_capture']
                or item['_provenance'] != {'scope': scope, 'capture': marker['capture']}
                or marker['associated'] is not True or type(marker['file_count']) is not int
                or not 1 <= marker['file_count'] <= ecs.MAX_ENVIRONMENT_FILES
                or type(marker['uncovered_files']) is not int or not 0 <= marker['uncovered_files'] < marker['file_count']
                or not isinstance(marker['ecs_request'], str) or not re.fullmatch('[0-9a-f]{64}', marker['ecs_request'])
                or not isinstance(marker['ecs_after_request'], str) or not re.fullmatch('[0-9a-f]{64}', marker['ecs_after_request'])
                or not isinstance(marker['association'], str) or not re.fullmatch('[0-9a-f]{64}', marker['association'])
                or marker['association_coherent'] is not True
                or not isinstance(marker['s3_identity'], str) or marker['s3_identity'] not in meta[s3.KIND + '_selection'][scope]):
            raise ValueError()
        source = marker['s3_item']
        if not isinstance(source, dict) or source.get('id') != marker['s3_identity']:
            raise ValueError()
        native_meta = deepcopy(meta)
        native_meta[s3.KIND + '_selection'][scope] = [marker['s3_identity']]
        refs = source[s3.MARKER]['source_requests']
        native_meta[s3.KIND + '_receipts'] = [r for r in meta[s3.KIND + '_receipts'] if r.get('id') in refs]
        native_index = {'context': {**ctx, 'metadata': native_meta}, 'collections': {s3.KIND: [{
            'scope': scope, 'service': 's3', 'status': 'collected' if collection['status'] == 'collected' else 'partial',
            'items': [source]}]}}
        status, evidence = s3_check.evaluate(source, native_index)
        if status == 'FAIL':
            return 'FAIL', {'observed': 'The ACTIVE ECS task revision names this container and S3 environment file.\nThe selected file text contains a likely secret whose value is hidden.\nSomeone who can read the file may use that credential to reach related data.',
                'secret_leaks': evidence['secret_leaks'], 'complete': False, 'coverage': 'selected_file_positive',
                'uncovered_files': marker['uncovered_files']}
        if status == 'PASS' and marker['uncovered_files'] == 0:
            return 'PASS', {'observed': 'The ACTIVE ECS task revision names this container and S3 environment file.\nAll declared environment files for this container were read without a supported secret indicator.\nThat lowers the observed risk of a credential in these files being read by someone with file access.',
                'secret_leaks': [], 'complete': True, 'coverage': 'selected_environment_files', 'uncovered_files': 0}
        return 'UNKNOWN', {'observed': 'The ACTIVE ECS task revision names this container and S3 environment file.\nIts text or another declared environment file was not recorded completely.\nA secret in that file could be available to someone with file access and put related data at risk.',
            'complete': False, 'coverage': 'incomplete', 'uncovered_files': marker['uncovered_files']}
    except (ValueError, TypeError, KeyError, AttributeError, IndexError):
        return 'UNKNOWN', {'observed': 'The recorded ECS task revision, container, or S3 file association is missing or inconsistent.\nThat leaves the declared environment file setting unclear.\nIf that file carries a credential, someone with file access may reach related data.',
            'complete': False, 'coverage': 'unbound'}


def install(register):
    from . import CHECKS
    from .fixtures import CASES
    import json
    from pathlib import Path
    if any(c.id == ecs.CHECK for c in CHECKS):
        return
    raw = Path(__file__).with_name('aws_ecs_environment_file_native_cases_20261021.json').read_bytes()
    cases = json.loads(raw)
    if set(cases) != {ecs.CHECK} or ecs.CHECK in CASES:
        raise RuntimeError('ECS environment-file native cases missing or duplicated')
    CASES.update(cases)
    register(ecs.CHECK, 'aws', 'exposure', ecs.KIND,
        'Selected ECS environment file has no detected secrets', 'high', 'security_configuration',
        'Remove confirmed exposed credentials from the selected environment file and rotate them.',
        dependencies=['aws_account', ecs.KIND], allow_incomplete_failure=True)(evaluate)
