"""Finite current-to-reviewed source bridge for the 2026-10-28 release wave.

Only four exact live sources are admitted. The retained 2026-10-21 epoch and
the 2026-10-22 collector successor still prove their own predecessors.
"""
from __future__ import annotations

import base64
import ast
import hashlib
import importlib
import inspect
import json
from pathlib import Path
import sys
from types import FunctionType
import zipfile

_RECEIPT_SHA256 = "5d3eab2f4ff7af31af5a713612b1294db982f86cb4895aa834d1879559ee16ae"
_ROOT = Path(__file__).resolve().parent.parent


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def reviewed_predecessor(relative: str, current: bytes, root: str | Path) -> bytes:
    """Return exact prior bytes after verifying the complete current file."""
    from peaso.private_secret_source_epoch_20261021 import AdmissionError, _root_path

    if Path(root).resolve(strict=True) != _ROOT or type(current) is not bytes:
        raise AdmissionError("finite successor root or source changed")
    receipt_path = Path(__file__).with_suffix(".json")
    receipt_raw = receipt_path.read_bytes()
    if _sha(receipt_raw) != _RECEIPT_SHA256:
        raise AdmissionError("finite successor receipt changed")
    receipt = json.loads(receipt_raw)
    if receipt.get("version") != 1 or set(receipt.get("sources", {})) != {
            "peaso/collectors/aws_code_log_content_indicators.py",
            "peaso/collectors/aws_workload_command_source_20261020.py",
            "peaso/collectors/azure.py", "peaso/collectors/gcp.py"}:
        raise AdmissionError("finite successor roster changed")
    row = receipt["sources"].get(relative)
    if row is None or current != _root_path(root, relative).read_bytes() or _sha(current) != row["current_sha256"]:
        raise AdmissionError("finite successor current source changed")
    prior = current
    for start, end, old64, new64 in reversed(row["edits"]):
        old = base64.b64decode(old64, validate=True)
        new = base64.b64decode(new64, validate=True)
        if prior[start:end] != new:
            raise AdmissionError("finite successor edit changed")
        prior = prior[:start] + old + prior[end:]
    if _sha(prior) != row["predecessor_sha256"]:
        raise AdmissionError("finite successor predecessor changed")
    return prior


def epoch_predecessor(relative: str, current: bytes, expected_before: str,
                      root: str | Path) -> bytes:
    """Continue the unchanged epoch archive proof for either AWS source."""
    from peaso import private_secret_source_epoch_20261021 as epoch
    if relative not in {
            "peaso/collectors/aws_code_log_content_indicators.py",
            "peaso/collectors/aws_workload_command_source_20261020.py"}:
        raise epoch.AdmissionError("finite AWS source request changed")
    prior = reviewed_predecessor(relative, current, root)
    row = epoch.source_rows()[relative]
    if _sha(prior) != row["after_sha256"] or expected_before != row["before_sha256"]:
        raise epoch.AdmissionError("finite AWS epoch linkage changed")
    archive = Path(epoch.__file__).with_suffix(".zip")
    if _sha(archive.read_bytes()) != epoch._ARCHIVE_SHA256:
        raise epoch.AdmissionError("finite AWS epoch archive changed")
    with zipfile.ZipFile(archive) as bundle:
        if sorted(bundle.namelist()) != sorted(epoch.source_rows()):
            raise epoch.AdmissionError("finite AWS epoch roster changed")
        before = bundle.read(relative)
    if _sha(before) != expected_before:
        raise epoch.AdmissionError("finite AWS predecessor changed")
    return before


def unchanged_callable_projection(function: FunctionType, row: dict, root: str | Path) -> dict:
    """Prove the two unchanged producer bodies in their exact new modules."""
    from peaso import private_secret_source_epoch_20261021 as epoch
    allowed = {
        ("peaso.collectors.aws_code_log_content_indicators", "project_response"),
        ("peaso.collectors.aws_workload_command_source_20261020", "collect"),
    }
    key = (getattr(function, "__module__", None), getattr(function, "__qualname__", None))
    if key not in allowed or type(function) is not FunctionType:
        raise epoch.AdmissionError("finite producer callable changed")
    relative = key[0].replace(".", "/") + ".py"
    source_path = epoch._root_path(root, relative)
    current = source_path.read_bytes()
    prior = reviewed_predecessor(relative, current, root)
    source_row = epoch.source_rows()[relative]
    if _sha(prior) != source_row["after_sha256"]:
        raise epoch.AdmissionError("finite producer epoch source changed")
    module = sys.modules.get(key[0])
    if (module is not importlib.import_module(key[0])
            or getattr(module, key[1]) is not function
            or function.__globals__ is not vars(module)
            or Path(module.__file__).resolve(strict=True) != source_path
            or Path(function.__code__.co_filename).resolve(strict=True) != source_path):
        raise epoch.AdmissionError("finite producer callable binding changed")
    tree = ast.parse(current, filename=str(source_path))
    old_tree = ast.parse(prior, filename=str(source_path))
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == key[1]]
    old_nodes = [n for n in old_tree.body if isinstance(n, ast.FunctionDef) and n.name == key[1]]
    definitions = [d for d in source_row["definitions"] if d["name"] == key[1]]
    if len(nodes) != 1 or len(old_nodes) != 1 or len(definitions) != 1:
        raise epoch.AdmissionError("finite producer function roster changed")
    node, old_node, definition = nodes[0], old_nodes[0], definitions[0]
    current_sha = definition["after"]
    current_ast = definition["after_ast_sha256"]
    if relative == "peaso/collectors/aws_code_log_content_indicators.py":
        transition = epoch._receipt()[0]["current_reviewed_files"][relative]["current_definitions"][key[1]]
        if (transition["predecessor_sha256"] != definition["after"]
                or transition["predecessor_ast_sha256"] != definition["after_ast_sha256"]):
            raise epoch.AdmissionError("finite log producer transition changed")
        current_sha = transition["current_sha256"]
        current_ast = transition["current_ast_sha256"]
    def fragment(raw: bytes, definition_node: ast.FunctionDef) -> bytes:
        return b"".join(raw.splitlines(keepends=True)[definition_node.lineno - 1:definition_node.end_lineno])
    current_fragment = fragment(current, node)
    if (current_fragment != fragment(prior, old_node)
            or _sha(current_fragment) != current_sha
            or epoch._ast_hash(node) != current_ast
            or inspect.getsource(function).encode() != current_fragment):
        raise epoch.AdmissionError("finite producer body changed")
    compiled = compile(current, str(source_path), "exec", dont_inherit=True, optimize=sys.flags.optimize)
    if not epoch._code_equal(function.__code__, epoch._code_from(compiled, key[1])):
        raise epoch.AdmissionError("finite producer executing code changed")
    constants = epoch._constants(tree, str(source_path))
    epoch._check_defaults(function, node, constants, function.__code__.co_filename)
    epoch._check_globals(function, tree, compiled, constants, module, root)
    proof = {
        "historical": {"path": relative, "name": key[1], "module": key[0],
                       "file_sha256": source_row["before_sha256"],
                       "source_sha256": definition["before"],
                       "ast_sha256": definition["before_ast_sha256"]},
        "current": {"path": relative, "name": key[1], "module": key[0],
                    "file_sha256": _sha(current), "source_sha256": current_sha,
                    "ast_sha256": current_ast},
    }
    # Reuse the sealed epoch's historical-row/default projection unchanged.
    namespace = dict(vars(epoch), trusted_definition=lambda fn, base: proof if fn is function and Path(base).resolve(strict=True) == _ROOT else None)
    projector = FunctionType(epoch.callable_projection.__code__, namespace,
                             epoch.callable_projection.__name__,
                             epoch.callable_projection.__defaults__)
    return projector(function, row, root)
