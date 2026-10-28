"""Exact successor for reviewed GCP, Kubernetes, and Azure collector sources.

The immutable 2026-10-21 source epoch remains unchanged. This bridge accepts
only the three reviewed collector byte strings and their original epoch rows.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import importlib
import json
from pathlib import Path
import re
import sys
from types import FunctionType, ModuleType
import zipfile
import zlib

from . import private_secret_source_epoch_20261021 as _epoch

_RECEIPT_SHA256 = "20e38eb5ae85f786c898ebc9422be160a4303f505ec7eeacb64a9a9237987430"
_SELF_SHA256 = "b1fc0b85ad1e7d2555b2813f3e80048ee05a7232cafc209e76ad2a0414c64890"
_ROOT = Path(__file__).resolve().parent.parent


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _receipt() -> dict:
    path = Path(__file__).with_suffix(".json")
    raw = path.read_bytes()
    if _sha(raw) != _RECEIPT_SHA256:
        raise _epoch.AdmissionError("reviewed collector receipt changed")
    source = Path(__file__).read_bytes()
    normalized = re.sub(rb'(_RECEIPT_SHA256|_SELF_SHA256) = "[0-9a-f]{64}"',
                        lambda match: match.group(1) + b' = "' + b'0' * 64 + b'"', source)
    if _sha(normalized) != _SELF_SHA256:
        raise _epoch.AdmissionError("reviewed collector attestor changed")
    receipt = json.loads(raw)
    if (receipt.get("version") != 1
            or receipt.get("source_epoch_receipt_sha256") != _epoch._RECEIPT_SHA256
            or receipt.get("source_epoch_archive_sha256") != _epoch._ARCHIVE_SHA256
            or receipt.get("init_sha256") != _sha((_ROOT / "peaso/__init__.py").read_bytes())
            or receipt.get("attestor_normalized_sha256") != _SELF_SHA256
            or set(receipt.get("guard_sources", {})) != {"peaso/checks/azure_metadata_only_tde_admission_successor_20261020.py"}
            or set(receipt.get("sources", {})) != {
                "peaso/collectors/gcp.py", "peaso/collectors/k8s.py", "peaso/collectors/azure.py",
                "peaso/collectors/azure_selected_storage_secret_indicators.py"
            }):
        raise _epoch.AdmissionError("reviewed collector receipt metadata changed")
    return receipt


def predecessor_bytes(relative: str, current: bytes, expected_before: str,
                      root: str | Path) -> bytes:
    receipt = _receipt()
    row = receipt["sources"].get(relative)
    if row is None:
        return _epoch.predecessor_bytes(relative, current, expected_before, root)
    if (type(current) is not bytes or type(expected_before) is not str
            or Path(root).resolve(strict=True) != _ROOT):
        raise _epoch.AdmissionError("reviewed collector request changed")
    epoch_rows = _epoch.source_rows()
    epoch_row = epoch_rows[relative]
    if (expected_before != row["epoch_before_sha256"]
            or epoch_row["before_sha256"] != row["epoch_before_sha256"]
            or epoch_row["after_sha256"] != row["epoch_after_sha256"]):
        raise _epoch.AdmissionError("reviewed collector epoch row changed")
    live_path = _epoch._root_path(root, relative)
    if current != live_path.read_bytes() or _sha(current) != row["current_sha256"]:
        raise _epoch.AdmissionError("reviewed collector current source changed")
    epoch_after = zlib.decompress(base64.b64decode(row["epoch_after_zlib_b64"], validate=True))
    if _sha(epoch_after) != row["epoch_after_sha256"]:
        raise _epoch.AdmissionError("reviewed collector epoch source changed")
    archive = Path(_epoch.__file__).with_suffix(".zip")
    if _sha(archive.read_bytes()) != receipt["source_epoch_archive_sha256"]:
        raise _epoch.AdmissionError("reviewed collector predecessor archive changed")
    with zipfile.ZipFile(archive) as bundle:
        if sorted(bundle.namelist()) != sorted(epoch_rows):
            raise _epoch.AdmissionError("reviewed collector predecessor roster changed")
        before = bundle.read(relative)
    if _sha(before) != expected_before:
        raise _epoch.AdmissionError("reviewed collector predecessor changed")
    return before


def previous_function_source(relative: str, name: str, current_fragment: str,
                             root: str | Path) -> str:
    """Return one exact prior function body from a reviewed collector pair."""
    receipt = _receipt()
    row = receipt["sources"].get(relative)
    if row is None or (relative, name) not in (("peaso/collectors/azure.py", "collect"), ("peaso/collectors/azure.py", "_selected"), ("peaso/collectors/k8s.py", "collect")):
        raise _epoch.AdmissionError("unreviewed collector function request")
    if Path(root).resolve(strict=True) != _ROOT:
        raise _epoch.AdmissionError("reviewed collector root changed")
    current = _epoch._root_path(root, relative).read_bytes()
    if _sha(current) != row["current_sha256"]:
        raise _epoch.AdmissionError("reviewed collector current source changed")
    previous = zlib.decompress(base64.b64decode(row["epoch_after_zlib_b64"], validate=True))
    if _sha(previous) != row["epoch_after_sha256"]:
        raise _epoch.AdmissionError("reviewed collector epoch source changed")
    def fragment(raw: bytes) -> str:
        tree = ast.parse(raw)
        nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
        if len(nodes) != 1:
            raise _epoch.AdmissionError("reviewed collector function ambiguous")
        node = nodes[0]
        return b"".join(raw.splitlines(keepends=True)[node.lineno - 1:node.end_lineno]).decode()
    if fragment(current) != current_fragment:
        raise _epoch.AdmissionError("reviewed collector function source changed")
    return fragment(previous)


def previous_guard_source(relative: str, current: bytes, root: str | Path) -> bytes:
    """Return exact prior bytes for a reviewed signed guard successor."""
    receipt = _receipt()
    row = receipt["guard_sources"].get(relative)
    if row is None or Path(root).resolve(strict=True) != _ROOT or type(current) is not bytes:
        raise _epoch.AdmissionError("unreviewed guard source request")
    live = _epoch._root_path(root, relative).read_bytes()
    if current != live or _sha(current) != row["current_sha256"]:
        raise _epoch.AdmissionError("reviewed guard current source changed")
    prior = zlib.decompress(base64.b64decode(row["prior_zlib_b64"], validate=True))
    if _sha(prior) != row["prior_sha256"]:
        raise _epoch.AdmissionError("reviewed guard prior source changed")
    return prior


def previous_guard_function_source(relative: str, name: str, current_fragment: str,
                                   root: str | Path) -> str:
    """Project one exact guard callable to its reviewed prior source."""
    if relative != "peaso/checks/azure_metadata_only_tde_admission_successor_20261020.py" or name != "reviewed_inputs":
        raise _epoch.AdmissionError("unreviewed guard callable request")
    current = _epoch._root_path(root, relative).read_bytes()
    previous = previous_guard_source(relative, current, root)
    def fragment(raw: bytes) -> str:
        tree = ast.parse(raw)
        nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
        if len(nodes) != 1:
            raise _epoch.AdmissionError("reviewed guard callable ambiguous")
        node = nodes[0]
        return b"".join(raw.splitlines(keepends=True)[node.lineno - 1:node.end_lineno]).decode()
    if fragment(current) != current_fragment:
        raise _epoch.AdmissionError("reviewed guard callable source changed")
    return fragment(previous)



def _verify_graph_current(root):
    """The one reviewed Graph batch module, including its live dependencies."""
    relative = "peaso/collectors/azure_graph_batch.py"
    proofs = _receipt().get("current_helper_sources")
    if type(proofs) is not dict or set(proofs) != {relative}:
        raise _epoch.AdmissionError("reviewed Graph helper roster changed")
    proof = proofs[relative]
    path = _epoch._root_path(root, relative)
    raw = path.read_bytes()
    module = importlib.import_module("peaso.collectors.azure_graph_batch")
    if (sys.modules.get(module.__name__) is not module
            or Path(module.__file__).resolve() != path or _sha(raw) != proof["sha256"]):
        raise _epoch.AdmissionError("reviewed Graph helper source changed")
    tree = ast.parse(raw, filename=str(path))
    compiled = compile(raw, str(path), "exec", dont_inherit=True, optimize=sys.flags.optimize)
    constants = _epoch._constants(tree, str(path))
    expected_routes = tuple(re.compile(pattern, flags) for pattern, flags in proof["routes"])
    if (not _epoch._same(module.ROUTES, expected_routes) or type(module._MISSING) is not object):
        raise _epoch.AdmissionError("reviewed Graph route/sentinel changed")
    constants["ROUTES"], constants["_MISSING"] = expected_routes, module._MISSING
    functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    classes = {n.name: n for n in tree.body if isinstance(n, ast.ClassDef)}
    actual_functions = {name for name, value in vars(module).items()
                        if type(value) is FunctionType and value.__module__ == module.__name__}
    actual_classes = {name for name, value in vars(module).items()
                      if type(value) is type and value.__module__ == module.__name__}
    if (set(functions) != set(proof["functions"]) or actual_functions != set(functions)
            or set(classes) != set(proof["classes"]) or actual_classes != set(classes)):
        raise _epoch.AdmissionError("reviewed Graph callable roster changed")
    for name, node in functions.items():
        fn = vars(module)[name]
        if (fn.__globals__ is not vars(module) or fn.__qualname__ != name
                or not _epoch._code_equal(fn.__code__, _epoch._code_from(compiled, name))):
            raise _epoch.AdmissionError("reviewed Graph callable changed")
        _epoch._check_defaults(fn, node, constants, fn.__code__.co_filename)
        _epoch._check_globals(fn, tree, compiled, constants, module, root)
    for name, node in classes.items():
        cls = vars(module)[name]
        _epoch._check_class(cls, node, compiled, module, constants, tree, root)
        for fn in vars(cls).values():
            if type(fn) is FunctionType:
                _epoch._check_globals(fn, tree, compiled, constants, module, root)


def verify_k8s_literal_current(module, root):
    """Attest only the newly introduced literal worker and grant accessors."""
    relative = "peaso/collectors/k8s.py"
    path = _epoch._root_path(root, relative)
    raw = path.read_bytes()
    if (module is not sys.modules.get("peaso.collectors.k8s")
            or Path(module.__file__).resolve() != path
            or _sha(raw) != _receipt()["sources"][relative]["current_sha256"]):
        raise _epoch.AdmissionError("reviewed K8s literal source changed")
    tree = ast.parse(raw, filename=str(path))
    compiled = compile(raw, str(path), "exec", dont_inherit=True, optimize=sys.flags.optimize)
    constants = _epoch._constants(tree, str(path))
    fn = module._automatic_literal_group
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == fn.__name__)
    if (type(fn) is not FunctionType or fn.__globals__ is not vars(module)
            or fn.__qualname__ != "_automatic_literal_group"
            or not _epoch._code_equal(fn.__code__, _epoch._code_from(compiled, fn.__name__))):
        raise _epoch.AdmissionError("reviewed K8s literal callable changed")
    _epoch._check_defaults(fn, node, constants, fn.__code__.co_filename)
    _epoch._check_globals(fn, tree, compiled, constants, module, root)
    node = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "_LiteralReader")
    _epoch._check_class(module._LiteralReader, node, compiled, module, constants, tree, root)
    for member in vars(module._LiteralReader).values():
        if type(member) is FunctionType:
            _epoch._check_globals(member, tree, compiled, constants, module, root)
    node = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "_BoundedPool")
    prop = vars(module._BoundedPool).get("literal_paths")
    accessors = [n for n in node.body if isinstance(n, ast.FunctionDef) and n.name == "literal_paths"]
    if type(prop) is not property or prop.fdel is not None or len(accessors) != 2:
        raise _epoch.AdmissionError("reviewed K8s literal property changed")
    class_code = _epoch._code_from(compiled, "_BoundedPool")
    expected = [c for c in class_code.co_consts if isinstance(c, type(fn.__code__)) and c.co_name == "literal_paths"]
    if len(expected) != 2:
        raise _epoch.AdmissionError("reviewed K8s literal property ambiguous")
    for member, ast_node, code in zip((prop.fget, prop.fset), accessors, expected):
        if (type(member) is not FunctionType or member.__globals__ is not vars(module)
                or member.__module__ != module.__name__ or member.__qualname__ != "_BoundedPool.literal_paths"
                or not _epoch._code_equal(member.__code__, code)):
            raise _epoch.AdmissionError("reviewed K8s grant accessor changed")
        _epoch._check_defaults(member, ast_node, constants, member.__code__.co_filename)
        _epoch._check_globals(member, tree, compiled, constants, module, root)

def trusted_definition(fn: FunctionType, root: str | Path) -> dict:
    """Prove a reviewed collector transport method against exact live source."""
    module_name = getattr(fn, "__module__", "")
    if (module_name, getattr(fn, "__qualname__", "")) not in (("peaso.collectors.gcp", "Transport.request"), ("peaso.collectors.azure", "AzureTransport.request")):
        return _epoch.trusted_definition(fn, root)
    relative = module_name.replace(".", "/") + ".py"
    row = _receipt()["sources"][relative]
    source = _epoch._root_path(root, relative).read_bytes()
    if Path(root).resolve(strict=True) != _ROOT or _sha(source) != row["current_sha256"]:
        raise _epoch.AdmissionError("reviewed transport source changed")
    owner_module = sys.modules.get(module_name)
    parts = fn.__qualname__.split(".")
    if (type(fn) is not FunctionType or type(owner_module) is not ModuleType
            or fn.__globals__ is not vars(owner_module)
            or Path(owner_module.__file__).resolve(strict=True) != _ROOT / relative
            or vars(vars(owner_module)[parts[0]]).get(parts[1]) is not fn
            or Path(fn.__code__.co_filename).resolve(strict=True) != _ROOT / relative):
        raise _epoch.AdmissionError("reviewed transport callable binding changed")
    compiled = compile(source, str(_ROOT / relative), "exec", dont_inherit=True, optimize=sys.flags.optimize)
    expected = _epoch._code_from(_epoch._code_from(compiled, parts[0]), parts[1])
    if not _epoch._code_equal(fn.__code__, expected):
        raise _epoch.AdmissionError("reviewed transport executing code changed")
    tree = ast.parse(source, filename=str(_ROOT / relative))
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == parts[0]]
    methods = [node for node in classes[0].body if isinstance(node, ast.FunctionDef) and node.name == parts[1]] if len(classes) == 1 else []
    if len(methods) != 1:
        raise _epoch.AdmissionError("reviewed transport method ambiguous")
    constants = _epoch._constants(tree, str(_ROOT / relative))
    _epoch._check_defaults(fn, methods[0], constants, fn.__code__.co_filename)
    _epoch._check_globals(fn, tree, compiled, constants, owner_module, root)
    if module_name == "peaso.collectors.azure":
        validator = vars(owner_module)["_validate_readonly_post"]
        _epoch._check_globals(validator, tree, compiled, constants, owner_module, root)
        _verify_graph_current(root)
    before = predecessor_bytes(relative, source, row["epoch_before_sha256"], root)
    if _sha(before) != row["epoch_before_sha256"]:
        raise _epoch.AdmissionError("reviewed transport predecessor changed")
    return {"historical": {"path": relative, "file_sha256": row["epoch_before_sha256"]},
            "current": {"path": relative, "file_sha256": row["current_sha256"]}}


def previous_gcp_method_source(name: str, current_fragment: str,
                               root: str | Path) -> str:
    """Project a reviewed GCP collector method to its exact prior source."""
    if name not in ("__init__", "collect", "dependent_jobs", "envelope", "finish", "scope_jobs", "workspace_directory"):
        raise _epoch.AdmissionError("unreviewed GCP method request")
    relative = "peaso/collectors/gcp.py"
    row = _receipt()["sources"][relative]
    if Path(root).resolve(strict=True) != _ROOT:
        raise _epoch.AdmissionError("reviewed GCP root changed")
    current = _epoch._root_path(root, relative).read_bytes()
    if _sha(current) != row["current_sha256"]:
        raise _epoch.AdmissionError("reviewed GCP current source changed")
    previous = zlib.decompress(base64.b64decode(row["epoch_after_zlib_b64"], validate=True))
    if _sha(previous) != row["epoch_after_sha256"]:
        raise _epoch.AdmissionError("reviewed GCP epoch source changed")
    def fragment(raw: bytes) -> str:
        tree = ast.parse(raw)
        classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "GCPCollector"]
        if len(classes) != 1:
            raise _epoch.AdmissionError("reviewed GCP class ambiguous")
        methods = [node for node in classes[0].body if isinstance(node, ast.FunctionDef) and node.name == name]
        if len(methods) != 1:
            raise _epoch.AdmissionError("reviewed GCP method ambiguous")
        node = methods[0]
        return b"".join(raw.splitlines(keepends=True)[node.lineno - 1:node.end_lineno]).decode()
    if fragment(current) != current_fragment:
        raise _epoch.AdmissionError("reviewed GCP method source changed")
    return fragment(previous)
