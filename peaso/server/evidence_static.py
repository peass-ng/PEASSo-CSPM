"""Hash-bound, process-local execution of reviewed evidence presentation sources.

The namespace is private to this loader. It does not modify sys.modules, import
peaso.checks, or register native evaluators. Original reviewed functions run in
original order using exact source bytes and original JSON review data.
"""
from __future__ import annotations
import ast
import builtins
import hashlib
import importlib.util
import json
from pathlib import Path
import re
from decimal import Decimal
from functools import lru_cache
from threading import RLock
from types import ModuleType, SimpleNamespace

ROOT = Path(__file__).resolve().parent
SOURCE_ROOT = Path(__file__).resolve().parents[2]
SOURCE_MANIFEST_SHA256 = 'd2180217732e500f7730be06d2aef6672bb53a1a9f0bd406b5331eed4366cc9d'
DATA_MANIFEST_SHA256 = '867a23d463ef5acfc35d27e5ab08545688649160f97cb21ffb191313cf77e698'


def _load_pinned_manifest(name, expected):
    data = (ROOT / name).read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ImportError('evidence presentation manifest changed: ' + name)
    return json.loads(data)


MANIFEST = _load_pinned_manifest('evidence_static_source_manifest.json', SOURCE_MANIFEST_SHA256)
DATA_SHA256 = _load_pinned_manifest('evidence_static_data_manifest.json', DATA_MANIFEST_SHA256)
_MODULES = {}
_LOAD_LOCK = RLock()
_NATIVE_SLICES = {
    'checks.k8s_ports_components': ('compare',),
    'checks.gcp_public_read_native': ('READ_ROLES',),
    'checks.claude_gcp_k8s_iam': ('MULTI_TENANT_ISSUERS',),
    'checks.hacktricks_bp_gcp': ('EXFIL_HOST', 'IAM_REPLAY'),
    'checks.claude_gcp_k8s_common': ('duration_seconds',),
}
_NATIVE_REGISTRARS = frozenset({
    'checks.aws', 'checks.azure', 'checks.claude2_gcp_common',
    'checks.gcp_metric_alert_native', 'checks.gcp_ports_iam',
    'checks.k8s_ports_workloads',
})


def _verified(relative, table=MANIFEST):
    expected = table.get(relative)
    if expected is None:
        raise ImportError('unreviewed presentation source: ' + relative)
    path = SOURCE_ROOT / relative
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ImportError('reviewed presentation source changed: ' + relative)
    return path, data


@lru_cache(maxsize=1)
def verify_closure():
    for relative in MANIFEST:
        _verified(relative)
    for relative in DATA_SHA256:
        if not relative.startswith('materialized/'):
            _verified(relative, DATA_SHA256)
    for name in ('evidence_static_field_specs.json', 'evidence_static_privesc_entries.json'):
        expected = DATA_SHA256['materialized/' + name]
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != expected:
            raise ImportError('materialized presentation input changed: ' + name)


def _materialized_facts():
    specs = json.loads((ROOT / 'evidence_static_field_specs.json').read_text())
    classes = {'bool': bool, 'int': int, 'str': str, 'list': list, 'dict': dict, 'float': float}
    for row in specs.values():
        row['expected'] = classes[row['expected']]
    module = _load_source('checks.facts')
    module.FIELD_SPECS = specs
    return module


def _catalog():
    entries = json.loads((ROOT / 'evidence_static_privesc_entries.json').read_text())
    return {'entries': [dict(id=key, **value) for key, value in entries.items()]}


def _resolve(name, globals_, level):
    if level:
        package = globals_['__package__']
        return importlib.util.resolve_name('.' * level + name, package)
    return name


def _private_import(name, globals=None, locals=None, fromlist=(), level=0):
    full = _resolve(name, globals or {}, level)
    if full == 'peaso.privesc' and 'catalog' in fromlist:
        return SimpleNamespace(catalog=_catalog)
    if full == 'peaso.checks' and fromlist:
        raise ImportError('native checks registry is unavailable in presentation loader')
    if (full.startswith('peaso.checks.') or full.startswith('peaso.analysis.')
            or full in {'peaso.privesc.finding_explanation', 'peaso.privesc.aws_observed_evidence_v3',
                        'peaso.privesc.gcp_observed_impact', 'peaso.privesc.azure_observed_impact',
                        'peaso.privesc.k8s_observed_impact'}):
        module = _load_source(full[6:])
        return module
    return builtins.__import__(name, globals, locals, fromlist, level)


def _selected_tree(source, filename, names):
    tree = ast.parse(source, filename=filename)
    body = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name in names:
            body.append(node)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(target, ast.Name) and target.id in names for target in targets):
                body.append(node)
    if len(body) != len(names):
        raise ImportError('presentation slice symbols changed: ' + filename)
    return ast.fix_missing_locations(ast.Module(body=body, type_ignores=[]))


def _load_source(relative):
    # Publish a fully initialized module to concurrent local API requests.
    # Recursive formatter imports use the same thread's reentrant lock.
    with _LOAD_LOCK:
        return _load_source_locked(relative)


def _load_source_locked(relative):
    if relative in _MODULES:
        return _MODULES[relative]
    if relative in _NATIVE_REGISTRARS:
        raise ImportError('native evaluator cannot load in evidence presentation: ' + relative)
    path, data = _verified('peaso/' + relative.replace('.', '/') + '.py')
    module = ModuleType('peaso_evidence.' + relative)
    module.__file__ = str(path)
    module.__package__ = 'peaso.' + relative.rpartition('.')[0]
    module.__dict__['__builtins__'] = dict(vars(builtins), __import__=_private_import)
    _MODULES[relative] = module
    if relative in _NATIVE_SLICES:
        module.__dict__.update({'re': re, 'Decimal': Decimal})
        if relative in ('checks.k8s_ports_components', 'checks.claude_gcp_k8s_common'):
            facts = _materialized_facts()
            module.__dict__.update({'Unavailable': facts.Unavailable, 'get': facts.get, 'guard': facts.guard})
        code = compile(_selected_tree(data, str(path), _NATIVE_SLICES[relative]), str(path), 'exec')
    else:
        code = compile(data, str(path), 'exec')
    try:
        exec(code, module.__dict__)
    except Exception:
        _MODULES.pop(relative, None)
        raise
    return module


def evidence_summary(finding):
    """Exact reviewed finding_observation.evidence_summary, without native init."""
    verify_closure()
    return _load_source('finding_observation').evidence_summary(finding)
