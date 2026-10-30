"""Compact source inverses retain exact predecessor reconstruction and rejection."""
import ast
import base64
import copy
import hashlib
import json
from pathlib import Path
import zlib
import pytest
from peaso.checks import private_secret_shared_source_successor_20261021 as shared

ROOT = Path(__file__).resolve().parents[1]


def test_every_compact_file_and_callable_reconstructs_its_exact_predecessor():
    receipt = shared._private_receipt()
    count = 0
    for group in ('provider_group_files', 'provider_group_callables'):
        for name, row in receipt[group].items():
            path, _, qualified = name.partition(':')
            raw = (ROOT / path).read_bytes()
            if not qualified and path == 'peaso/checks/azure_metadata_only_tde_admission_successor_20261020.py':
                raw = shared._reviewed_epoch.previous_guard_source(path, raw, ROOT)
            if qualified:
                nodes = ast.parse(raw).body
                for part in qualified.split('.'):
                    node = next(n for n in nodes if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.name == part)
                    nodes = getattr(node, 'body', [])
                first = min([node.lineno] + [n.lineno for n in node.decorator_list])
                raw = b''.join(raw.splitlines(True)[first-1:node.end_lineno])
                if hashlib.sha256(raw).hexdigest() != row['current_sha256']:
                    if path == 'peaso/collectors/gcp.py' and qualified.startswith('GCPCollector.'):
                        raw = shared._reviewed_epoch.previous_gcp_method_source(
                            qualified.split('.', 1)[1], raw.decode(), ROOT).encode()
                    elif (path, qualified) in (('peaso/collectors/azure.py', 'collect'),
                                                    ('peaso/collectors/azure.py', '_selected'),
                                                    ('peaso/collectors/k8s.py', 'collect')):
                        raw = shared._reviewed_epoch.previous_function_source(
                            path, qualified, raw.decode(), ROOT).encode()
                    elif path in ('peaso/collectors/aws_code_log_content_indicators.py',
                                  'peaso/collectors/aws_workload_command_source_20261020.py'):
                        # The finite 2026-10-28 successor proves the exact current file edit.
                        from peaso import private_secret_current_source_successor_20261028 as successor
                        prior = successor.reviewed_predecessor(path, (ROOT / path).read_bytes(), ROOT)
                        nodes = ast.parse(prior).body
                        for part in qualified.split('.'):
                            node = next(n for n in nodes if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.name == part)
                            nodes = getattr(node, 'body', [])
                        first = min([node.lineno] + [n.lineno for n in node.decorator_list])
                        raw = b''.join(prior.splitlines(True)[first-1:node.end_lineno])
                    elif (path, qualified) == ('peaso/checks/azure_metadata_only_tde_admission_successor_20261020.py', 'reviewed_inputs'):
                        raw = shared._reviewed_epoch.previous_guard_function_source(
                            path, qualified, raw.decode(), ROOT).encode()
            assert hashlib.sha256(raw).hexdigest() == row['current_sha256'], name
            if name == 'peaso/collectors/aws_code_log_content_indicators.py:scan_logs':
                # 2be06449 rebound only this row's current digest across the
                # reviewed c2e6a793 edit; the finite 2026-10-28 successor
                # reverses that edit before the retained compact delta applies.
                from peaso import private_secret_current_source_successor_20261028 as successor
                prior = successor.reviewed_predecessor(path, (ROOT / path).read_bytes(), ROOT)
                nodes = ast.parse(prior).body
                node = next(n for n in nodes if isinstance(n, ast.FunctionDef) and n.name == qualified)
                first = min([node.lineno] + [n.lineno for n in node.decorator_list])
                raw = b''.join(prior.splitlines(True)[first-1:node.end_lineno])
                assert hashlib.sha256(raw).hexdigest() == '1c388123f3bce528f3d91b87d42ed28a438032a7c02897cd1eda1081d384623c'
                row = dict(row, current_sha256=hashlib.sha256(raw).hexdigest())
            before = shared._reverse(raw.decode(), row).encode()
            assert hashlib.sha256(before).hexdigest() == row['predecessor_sha256'], name
            count += 1
    assert count > 50


def test_changed_compact_inverse_cannot_reconstruct_the_pinned_predecessor():
    row = copy.deepcopy(shared._private_receipt()['provider_group_files']['peaso/snapshot.py'])
    delta = json.loads(zlib.decompress(base64.b64decode(row['exact_delta_zlib'])))
    before, after = delta['exact_replacements'][0]
    delta['exact_replacements'][0] = [before, after + '# changed']
    row['exact_delta_zlib'] = base64.b64encode(zlib.compress(json.dumps(delta).encode())).decode()
    with pytest.raises(RuntimeError):
        shared._reverse((ROOT / 'peaso/snapshot.py').read_text(), row)
