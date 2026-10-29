"""Only fixed-label telemetry wrappers differ from the reviewed 1f45 source."""
import ast
import hashlib
import json
from pathlib import Path

import pytest

from peaso import runtime_metrics


ROOT = Path(__file__).resolve().parents[1]
LABELS = frozenset('''
worker.snapshot.load worker.native_checkpoint.wait worker.stage_results.wait worker.stage_results.load
ai.network.reuse.revision_check ai.network.reuse.revision_rejected
ai.network.reuse.artifact_check ai.network.reuse.artifact_unavailable ai.network.reuse.accepted
ai.network.reuse.validation ai.network.reuse.validated
'''.split())
BASE = '1f45df8dbabf707d3637bb6562e0789336fa4f8f'
BASE_AST = {
    'peaso/worker.py': '401ad85bfa7d7a849ce4ab8bc2cf63481f6c65302c32e0f19ce812a2f78fd4ac',
    'peaso/ai/pipeline.py': '4343a7bc60c8da88e0e81d51326748ea9b734b6e57c40960af4c173e928e9eeb',
    'peaso/runtime_metrics.py': '8e73b5b7d1b24352b0453a81534238643e7302dd2ef47a222fe37cea5e07070e',
}


class StripMetrics(ast.NodeTransformer):
    def visit_With(self, node):
        self.generic_visit(node)
        if len(node.items) == 1 and node.items[0].optional_vars is None:
            call = node.items[0].context_expr
            if (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                    and call.func.id == '_runtime_span' and not call.keywords
                    and len(call.args) == 1 and isinstance(call.args[0], ast.Constant)
                    and call.args[0].value in LABELS):
                return node.body
        return node


class NormalizeRoster(ast.NodeTransformer):
    def visit_Assign(self, node):
        if any(isinstance(target, ast.Name) and target.id == '_STAGES' for target in node.targets):
            value = node.value
            if (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                    and value.func.id == 'frozenset' and len(value.args) == 1
                    and isinstance(value.args[0], ast.Call)
                    and isinstance(value.args[0].func, ast.Attribute)
                    and value.args[0].func.attr == 'split'
                    and isinstance(value.args[0].func.value, ast.Constant)
                    and isinstance(value.args[0].func.value.value, str)):
                # Normalize only the existing literal, keeping the surrounding
                # expression in the proof so new executable code cannot hide.
                value.args[0].func.value.value = 'registered_roster'
        return self.generic_visit(node)


def canonical_ast(value):
    # Empty optional AST fields differ across Python versions. Keep every
    # nonempty node/field/value; this proof also works in shallow CI checkouts.
    if isinstance(value, ast.AST):
        return [type(value).__name__, [[name, canonical_ast(item)] for name, item in ast.iter_fields(value)
                                      if item is not None and item != []]]
    if isinstance(value, list):
        return [canonical_ast(item) for item in value]
    if isinstance(value, bytes):
        return ['bytes', value.hex()]
    if value is Ellipsis:
        return ['ellipsis']
    return value


@pytest.mark.parametrize('name', BASE_AST)
def test_only_metrics_wrappers_or_fixed_roster_differ_from_1f45(name):
    tree = ast.parse((ROOT / name).read_bytes())
    transform = NormalizeRoster if name.endswith('runtime_metrics.py') else StripMetrics
    normalized = json.dumps(canonical_ast(transform().visit(tree)), separators=(',', ':'), ensure_ascii=True)
    assert hashlib.sha256(normalized.encode()).hexdigest() == BASE_AST[name]


def test_registered_labels_extend_only_the_reviewed_fixed_roster():
    assert LABELS <= runtime_metrics._STAGES
    original = runtime_metrics._STAGES - LABELS
    assert len(original) == 57
    assert hashlib.sha256('\n'.join(sorted(original)).encode()).hexdigest() == (
        'a7a6b28adcad4540307c6b175f62d761731bd9f6e9463b34f539427011dadf17')
