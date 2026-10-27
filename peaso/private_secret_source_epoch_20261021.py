"""Finite, fail-closed source bridge for the reviewed 50 private secret sources.

This module is an isolated admission artifact.  It does not patch the runtime,
change a registry, or grant admission from a source hash alone.
"""
from __future__ import annotations

import __future__
import ast
import builtins
import contextlib
import dis
import hashlib
import hmac
import importlib.util
import io
import json
import marshal
import os
import re
from pathlib import Path, PurePosixPath
import sys
import sysconfig
from types import CodeType, FunctionType, MethodType, ModuleType
import zipfile
from peaso import source_attestation_mode as _attestation_mode

_RECEIPT_SHA256 = "a942073e7a9ba589ade194103b50dba0f21c9e27c0ac792569511bdafc73d814"
_SELF_SHA256 = "e05033dad7c538fec3f75e124260ee54fa37f150d865dea4e25dbba5a3df5af2"
_ARCHIVE_SHA256 = "3eb403fa363c559f7053060d409f60ac8c693350350423a6dc775412df4300c0"
_HELPER_SHA256 = "15092e316c2331e03fdae7fad4dda5ed92310a1c15a827b0009fbcd54a11693a"
_BASE = "6b6ee759234d7e2dad978342838cb3af4e1fe767"
_PREDECESSOR = "cc76270102e3e43893e81c53f9636272006d640a"


class AdmissionError(ValueError):
    """The supplied source, callable, or historical row is outside the pin."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _same(a: object, b: object) -> bool:
    """Equality for immutable/literal Python values, preserving False versus 0."""
    if type(a) is not type(b):
        return False
    if type(a) is re.Pattern:
        return a.pattern == b.pattern and a.flags == b.flags
    if isinstance(a, (tuple, list)):
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b))
    if isinstance(a, dict):
        if all(type(k) is str for k in a) and all(type(k) is str for k in b):
            return (len(a) == len(b) and all(k in b and _same(v, b[k])
                                            for k, v in a.items()))
        return len(a) == len(b) and all(any(_same(k, q) and _same(v, w) for q, w in b.items()) for k, v in a.items())
    if isinstance(a, (set, frozenset)):
        return len(a) == len(b) and all(any(_same(x, y) for y in b) for x in a)
    return a == b


def _relative(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise AdmissionError("invalid relative path")
    if type(value) is not str:
        p = PurePosixPath(value)
        if p.is_absolute() or str(p) != value or any(x in (".", "..") for x in p.parts):
            raise AdmissionError("noncanonical relative path")
        return value
    # Preserve the predecessor's lexical '.' case; _root_path still rejects
    # it as a non-file. This CPU change does not broaden or narrow admission.
    if value == ".":
        return value
    if value.startswith("/") or any(x in ("", ".", "..") for x in value.split("/")):
        raise AdmissionError("noncanonical relative path")
    return value


# BEGIN BOOTSTRAP ARTIFACT FACTORY
def _bootstrap_artifact_factory():
    import hashlib as h
    import hmac as a
    import marshal as m
    import os as o
    import sys as sy
    import types as t
    cache, secret = {}, o.urandom(32)
    def lookup(raw, filename, flags):
        key = (h.sha256(raw).digest(), filename, sy.implementation.cache_tag, sy.flags.optimize, flags)
        entry = cache.get(key)
        if entry is None:
            code = compile(raw, filename, "exec", flags=flags, dont_inherit=True, optimize=sy.flags.optimize)
            pending = [code]
            while pending:
                value = pending.pop()
                kind = type(value)
                if kind is t.CodeType: pending.extend(value.co_consts)
                elif kind in (tuple, frozenset): pending.extend(value)
                elif not (value is None or value is Ellipsis or kind in (bool, int, float, complex, str, bytes)):
                    raise ValueError("mutable bootstrap artifact")
            entry = (code, a.digest(secret, m.dumps((key, id(code)), 2), "sha256"))
            if len(cache) >= 4: cache.clear()
            cache[key] = entry
        if (type(entry) is not tuple or len(entry) != 2 or type(entry[0]) is not t.CodeType
                or type(entry[1]) is not bytes or not a.compare_digest(entry[1],
                    a.digest(secret, m.dumps((key, id(entry[0])), 2), "sha256"))):
            raise ValueError("bootstrap artifact mismatch")
        return entry[0]
    return lookup
# END BOOTSTRAP ARTIFACT FACTORY

_BOOTSTRAP_ARTIFACT = _bootstrap_artifact_factory()
_BOOTSTRAP_ARTIFACT_ANCHOR = _BOOTSTRAP_ARTIFACT
_BOOTSTRAP_ARTIFACT_STORAGE = dict(zip(_BOOTSTRAP_ARTIFACT.__code__.co_freevars,
    (cell.cell_contents for cell in _BOOTSTRAP_ARTIFACT.__closure__)))["cache"]


# BEGIN SELF CODE CACHE FACTORY
def _self_code_cache():
    """Read bounded signed code and immutable source metadata artifacts."""
    import builtins as local_builtins
    import hashlib as local_hashlib
    import hmac as local_hmac
    import marshal as local_marshal
    import os as local_os
    import sys as local_sys
    import types as local_types

    entries = {}
    secret = local_os.urandom(32)

    def lookup(path, raw, code_vectors=None):
        if local_os is not local_sys.modules.get("os"):
            raise local_builtins.ValueError("attestor random source binding mismatch")
        key = (local_builtins.str(path), local_builtins.str(path.resolve(strict=True)),
               local_hashlib.sha256(raw).digest(), local_sys.implementation.cache_tag,
               local_sys.flags.optimize)
        if code_vectors is not None:
            if (local_builtins.type(code_vectors) is not local_builtins.tuple
                    or local_builtins.len(code_vectors) != 2
                    or any(local_builtins.type(v) is not local_builtins.tuple for v in code_vectors)
                    or local_builtins.len(code_vectors[0]) != local_builtins.len(code_vectors[1])
                    or any(local_builtins.type(c) is not local_types.CodeType
                           for v in code_vectors for c in v)):
                raise local_builtins.ValueError("code vector shape mismatch")
            key += ("code-vectors-v1", tuple(tuple(local_builtins.id(c) for c in v)
                                            for v in code_vectors))
            entry = entries.get(key)
            if entry is None:
                pending = [c for vector in code_vectors for c in vector]
                while pending:
                    value = pending.pop()
                    kind = local_builtins.type(value)
                    if kind is local_types.CodeType:
                        pending.extend(value.co_consts)
                    elif kind in (tuple, frozenset):
                        pending.extend(value)
                    elif not (value is None or value is Ellipsis or kind in
                              (bool, int, float, complex, str, bytes)):
                        raise local_builtins.ValueError("mutable code vector refused")
                if local_marshal.dumps(code_vectors[0], 2) != local_marshal.dumps(code_vectors[1], 2):
                    raise local_builtins.ValueError("code vector source mismatch")
                entry = (code_vectors, local_hmac.digest(secret, local_marshal.dumps(key, 2), "sha256"))
                if local_builtins.len(entries) >= 64:
                    entries.clear()
                entries[key] = entry
            if (local_builtins.type(entry) is not local_builtins.tuple
                    or local_builtins.len(entry) != 2
                    or local_builtins.type(entry[0]) is not local_builtins.tuple
                    or local_builtins.len(entry[0]) != 2
                    or any(local_builtins.type(v) is not local_builtins.tuple for v in entry[0])
                    or any(local_builtins.len(saved) != local_builtins.len(current)
                           or any(a is not b for a, b in zip(saved, current))
                           for saved, current in zip(entry[0], code_vectors))
                    or local_builtins.type(entry[1]) is not local_builtins.bytes
                    or not local_hmac.compare_digest(entry[1], local_hmac.digest(
                        secret, local_marshal.dumps(key, 2), "sha256"))):
                raise local_builtins.ValueError("code vector artifact mismatch")
            return entry[0]
        entry = entries.get(key)
        if entry is None:
            return None
        if (local_builtins.type(entry) is not local_builtins.tuple
                or local_builtins.len(entry) != 3
                or local_builtins.type(entry[0]) is not local_types.CodeType
                or local_builtins.type(entry[2]) is not local_builtins.bytes
                or not local_hmac.compare_digest(
                    entry[2], local_hmac.digest(secret,
                    local_marshal.dumps((key, local_builtins.id(entry[0]), entry[1]), 2),
                    "sha256"))):
            raise local_builtins.ValueError("attestor code cache artifact mismatch")
        return entry[0], entry[1]

    return lookup
# END SELF CODE CACHE FACTORY


_SELF_CODE_CACHE = _self_code_cache()
_SELF_CODE_CACHE_ANCHOR = _SELF_CODE_CACHE
_SELF_CODE_CACHE_STORAGE = _SELF_CODE_CACHE.__closure__[0].cell_contents


def _immutable_code_constants(code: CodeType) -> bool:
    """Reject mutable or unfamiliar constants even inside nested code."""
    pending = list(code.co_consts)
    while pending:
        value = pending.pop()
        kind = type(value)
        if kind is CodeType:
            pending.extend(value.co_consts)
        elif kind is tuple or kind is frozenset:
            pending.extend(value)
        elif value is None or value is Ellipsis or kind in (
                bool, int, float, complex, str, bytes):
            continue
        else:
            return False
    return True


def _self_metadata(tree: ast.Module, source_constants: dict) -> tuple:
    wanted = ("_RECEIPT_SHA256", "_SELF_SHA256", "_ARCHIVE_SHA256",
              "_HELPER_SHA256", "_BASE", "_PREDECESSOR", "_ALIAS_DEPENDENCIES")
    constants = []
    for name in wanted:
        value = source_constants[name]
        if name == "_ALIAS_DEPENDENCIES":
            if type(value) is not dict or any(type(k) is not str or type(v) is not str
                                               for k, v in value.items()):
                raise AdmissionError("attestor alias metadata mismatch")
            value = tuple(sorted(value.items()))
        elif type(value) is not str:
            raise AdmissionError("attestor scalar metadata mismatch")
        constants.append((name, value))
    specs = tuple((node.name,
                   tuple(ast.literal_eval(expr) for expr in node.args.defaults),
                   tuple((arg.arg, ast.literal_eval(expr)) for arg, expr in
                         zip(node.args.kwonlyargs, node.args.kw_defaults) if expr is not None))
                  for node in tree.body
                  if type(node) in (ast.FunctionDef, ast.AsyncFunctionDef))
    return tuple(constants), specs


def _self_cached_code(path: Path, raw: bytes) -> tuple | None:
    """Freshly prove the small cache code from this read before consulting it."""
    lines = raw.splitlines(keepends=True)
    boot_begin = [i for i, line in enumerate(lines) if line == b"# BEGIN BOOTSTRAP ARTIFACT FACTORY\n"]
    boot_end = [i for i, line in enumerate(lines) if line == b"# END BOOTSTRAP ARTIFACT FACTORY\n"]
    if len(boot_begin) != 1 or len(boot_end) != 1 or boot_end[0] <= boot_begin[0]:
        raise AdmissionError("bootstrap artifact source mismatch")
    boot_raw = b"\n" * (boot_begin[0] + 1) + b"".join(lines[boot_begin[0] + 1:boot_end[0]])
    boot = compile(boot_raw, __file__, "exec", flags=__future__.annotations.compiler_flag,
                   dont_inherit=True, optimize=sys.flags.optimize)
    factories = [c for c in boot.co_consts if type(c) is CodeType
                 and c.co_name == "_bootstrap_artifact_factory"]
    if len(factories) != 1:
        raise AdmissionError("bootstrap artifact factory ambiguity")
    boot_factory = factories[0]
    lookups = [c for c in boot_factory.co_consts if type(c) is CodeType and c.co_name == "lookup"]
    if len(lookups) != 1:
        raise AdmissionError("bootstrap artifact lookup ambiguity")
    boot_lookup = lookups[0]
    provider = globals().get("_BOOTSTRAP_ARTIFACT")
    factory = globals().get("_bootstrap_artifact_factory")
    if (type(factory) is not FunctionType or factory.__globals__ is not globals()
            or factory.__defaults__ is not None or factory.__kwdefaults__ is not None
            or factory.__closure__ is not None or factory.__qualname__ != "_bootstrap_artifact_factory"
            or factory.__module__ != __name__ or factory.__name__ != "_bootstrap_artifact_factory"
            or marshal.dumps(factory.__code__, 2) != marshal.dumps(boot_factory, 2)
            or type(provider) is not FunctionType or provider is not _BOOTSTRAP_ARTIFACT_ANCHOR
            or provider.__globals__ is not globals() or provider.__defaults__ is not None
            or provider.__kwdefaults__ is not None or provider.__closure__ is None
            or provider.__qualname__ != "_bootstrap_artifact_factory.<locals>.lookup"
            or provider.__module__ != __name__ or provider.__name__ != "lookup"
            or marshal.dumps(provider.__code__, 2) != marshal.dumps(boot_lookup, 2)):
        raise AdmissionError("bootstrap artifact binding mismatch")
    cells = dict(zip(provider.__code__.co_freevars,
                     (cell.cell_contents for cell in provider.__closure__)))
    if (set(cells) != {"cache", "secret", "h", "a", "m", "sy", "t"}
            or cells["h"] is not hashlib
            or cells["a"] is not hmac or cells["m"] is not marshal
            or cells["sy"] is not sys or cells["t"] is not sys.modules.get("types")
            or cells["cache"] is not _BOOTSTRAP_ARTIFACT_STORAGE
            or type(cells["cache"]) is not dict or type(cells["secret"]) is not bytes
            or len(cells["secret"]) != 32):
        raise AdmissionError("bootstrap artifact closure mismatch")
    begin = [i for i, line in enumerate(lines) if line == b"# BEGIN SELF CODE CACHE FACTORY\n"]
    end = [i for i, line in enumerate(lines) if line == b"# END SELF CODE CACHE FACTORY\n"]
    if len(begin) != 1 or len(end) != 1 or end[0] <= begin[0] + 1:
        raise AdmissionError("attestor cache factory source mismatch")
    # Prefix blank lines so the freshly compiled code retains original line
    # numbers.  No cached parser/compiler participates in this bootstrap.
    fragment = b"\n" * (begin[0] + 1) + b"".join(lines[begin[0] + 1:end[0]])
    try:
        expected = provider(fragment, __file__, __future__.annotations.compiler_flag)
    except ValueError as exc:
        raise AdmissionError("bootstrap artifact mismatch") from exc
    factory_code = [c for c in expected.co_consts
                    if type(c) is CodeType and c.co_name == "_self_code_cache"]
    if len(factory_code) != 1:
        raise AdmissionError("attestor cache factory ambiguity")
    lookup_code = [c for c in factory_code[0].co_consts
                   if type(c) is CodeType and c.co_name == "lookup"]
    factory = globals().get("_self_code_cache")
    lookup = globals().get("_SELF_CODE_CACHE")
    try:
        closure = (dict(zip(lookup.__code__.co_freevars,
                            (cell.cell_contents for cell in lookup.__closure__)))
                   if type(lookup) is FunctionType and lookup.__closure__ is not None else {})
        factory_code_bytes = marshal.dumps(factory.__code__, 2) if type(factory) is FunctionType else None
        lookup_code_bytes = marshal.dumps(lookup.__code__, 2) if type(lookup) is FunctionType else None
    except (ValueError, TypeError, AttributeError) as exc:
        raise AdmissionError("attestor cache binding mismatch") from exc
    expected_cells = {"entries", "local_builtins", "local_hashlib", "local_hmac",
                      "local_marshal", "local_os", "local_sys", "local_types", "secret"}
    if (len(lookup_code) != 1 or type(factory) is not FunctionType
            or factory.__name__ != "_self_code_cache" or factory.__qualname__ != "_self_code_cache"
            or factory.__module__ != __name__
            or factory.__globals__ is not globals() or factory.__defaults__ is not None
            or factory.__kwdefaults__ is not None or factory.__closure__ is not None
            or factory_code_bytes != marshal.dumps(factory_code[0], 2)
            or type(lookup) is not FunctionType or lookup is not _SELF_CODE_CACHE_ANCHOR
            or lookup.__name__ != "lookup" or lookup.__qualname__ != "_self_code_cache.<locals>.lookup"
            or lookup.__module__ != __name__
            or lookup.__globals__ is not globals() or lookup.__defaults__ != (None,)
            or lookup.__kwdefaults__ is not None
            or lookup_code_bytes != marshal.dumps(lookup_code[0], 2)
            or set(closure) != expected_cells
            or closure.get("entries") is not _SELF_CODE_CACHE_STORAGE
            or type(_SELF_CODE_CACHE_STORAGE) is not dict
            or type(closure.get("secret")) is not bytes
            or len(closure["secret"]) != 32
            or closure.get("local_builtins") is not builtins
            or closure.get("local_hashlib") is not hashlib
            or closure.get("local_hmac") is not hmac
            or closure.get("local_marshal") is not marshal
            or closure.get("local_os") is not os
            or closure.get("local_sys") is not sys
            or closure.get("local_types") is not sys.modules.get("types")
            or getattr(closure["local_types"], "CodeType", None) is not CodeType
            or any(sys.modules.get(name) is not module for name, module in
                   (("builtins", builtins), ("hashlib", hashlib), ("hmac", hmac),
                    ("marshal", marshal), ("os", os), ("sys", sys)))):
        raise AdmissionError("attestor cache binding mismatch")
    try:
        result = lookup(path, raw)
    except ValueError as exc:
        raise AdmissionError("attestor code cache artifact mismatch") from exc
    if result is None:
        return None
    code, metadata = result
    def immutable(value: object) -> bool:
        return (type(value) is tuple and all(immutable(item) for item in value)
                or type(value) in (str, bytes, int, bool) or value is None)
    # This exact CodeType identity was recursively proved immutable before
    # insertion. The authenticated cache holds its reference; replacing it
    # fails lookup's MAC, and immutable constants cannot change in place.
    if not immutable(metadata):
        raise AdmissionError("attestor cached artifact is mutable")
    return code, metadata


_SELF_PROVEN = []


def _self() -> None:
    """Fresh source and live binding proof for this small attestor module."""
    if not _attestation_mode.repeat(_SELF_PROVEN):
        return
    module = sys.modules.get(__name__)
    if type(module) is not ModuleType or vars(module) is not globals():
        raise AdmissionError("attestor module binding mismatch")
    path = Path(__file__).resolve(strict=True)
    raw = path.read_bytes()
    normalized, count = re.subn(
        rb'(?m)^(_RECEIPT_SHA256|_SELF_SHA256) = "[0-9a-f]{64}"$',
        lambda match: match.group(1) + b' = "' + b'0' * 64 + b'"', raw)
    if count != 2 or _sha(normalized) != _SELF_SHA256:
        raise AdmissionError("attestor source mismatch")
    artifact = _self_cached_code(Path(__file__), raw)
    if artifact is None:
        tree = ast.parse(raw)
        source_constants = _constants(tree, str(path))
        compiled = compile(raw, __file__, "exec", dont_inherit=True)
        nodes = {x.name: x for x in tree.body if isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef))}
    else:
        compiled, metadata = artifact
        source_constants = dict(metadata[0])
        source_constants["_ALIAS_DEPENDENCIES"] = dict(source_constants["_ALIAS_DEPENDENCIES"])
        specs = {name: (defaults, keywords) for name, defaults, keywords in metadata[1]}
    for key in ("_RECEIPT_SHA256", "_SELF_SHA256", "_ARCHIVE_SHA256", "_HELPER_SHA256", "_BASE", "_PREDECESSOR", "_ALIAS_DEPENDENCIES"):
        if key not in source_constants or not _same(globals().get(key), source_constants[key]):
            raise AdmissionError("attestor constant binding mismatch")
    actual = {name: value for name, value in globals().items()
              if type(value) is FunctionType and value.__module__ == __name__
              and name not in ("_SELF_CODE_CACHE", "_SELF_CODE_CACHE_ANCHOR",
                               "_BOOTSTRAP_ARTIFACT", "_BOOTSTRAP_ARTIFACT_ANCHOR")}
    if set(actual) != (set(nodes) if artifact is None else set(specs)):
        raise AdmissionError("attestor function roster mismatch")
    expected_codes = {}
    for code in compiled.co_consts:
        if isinstance(code, CodeType):
            name = code.co_name
            expected_codes[name] = code if name not in expected_codes else None
    ordered_names = sorted(actual)
    expected_live = tuple(expected_codes.get(name) for name in ordered_names)
    if any(code is None for code in expected_live):
        raise AdmissionError("attestor live code mismatch")
    try:
        # Reuse only a source-keyed correspondence between these exact immutable
        # CodeType objects. Current bindings are collected anew on every entry;
        # a replaced code object takes a fresh immutable/full-byte comparison.
        _SELF_CODE_CACHE(Path(__file__), raw,
                         (tuple(actual[name].__code__ for name in ordered_names), expected_live))
    except ValueError as exc:
        raise AdmissionError("attestor live code mismatch") from exc
    for name, fn in actual.items():
        expected_code = expected_codes.get(name)
        if expected_code is None:
            raise AdmissionError("compiled definition missing or ambiguous")
        # Full recursive marshal equality above also proves that the actual
        # constants have the canonical immutable types. The cached canonical
        # module itself still passes its original recursive immutability guard.
        if fn.__globals__ is not globals() or fn.__qualname__ != name:
            raise AdmissionError("attestor live code mismatch: " + name)
        if artifact is None:
            node = nodes[name]
            _check_defaults(fn, node, source_constants, __file__)
        else:
            defaults, keywords = specs[name]
            # These are authenticated immutable literal AST artifacts, not a
            # cached default verdict. Compare the current defaults and closure
            # every time without reparsing synthetic function declarations.
            if (not _same(fn.__defaults__ or (), defaults)
                    or not _same(fn.__kwdefaults__ or {}, dict(keywords))
                    or fn.__closure__ is not None or fn.__code__.co_freevars):
                raise AdmissionError("attestor live default or closure mismatch")
    if artifact is None:
        metadata = _self_metadata(tree, source_constants)
        if not _immutable_code_constants(compiled):
            raise AdmissionError("attestor code has mutable constants")
        cache_path = Path(__file__)
        key = (str(cache_path), str(cache_path.resolve(strict=True)), hashlib.sha256(raw).digest(),
               sys.implementation.cache_tag, sys.flags.optimize)
        secret = dict(zip(_SELF_CODE_CACHE.__code__.co_freevars,
                          (cell.cell_contents for cell in _SELF_CODE_CACHE.__closure__)))["secret"]
        signature = hmac.digest(secret,
                                marshal.dumps((key, id(compiled), metadata), 2), "sha256")
        if len(_SELF_CODE_CACHE_STORAGE) >= 64:
            _SELF_CODE_CACHE_STORAGE.clear()
        _SELF_CODE_CACHE_STORAGE[key] = (compiled, metadata, signature)
    _SELF_PROVEN.append(True)


def _receipt() -> tuple[dict, dict[str, dict]]:
    _self()
    file = Path(__file__).with_name("private_secret_source_epoch_20261021.json")
    data = file.read_bytes()
    if _sha(data) != _RECEIPT_SHA256:
        raise AdmissionError("receipt identity mismatch")
    try:
        artifact = _SELF_CODE_CACHE(file, data)
    except ValueError as exc:
        raise AdmissionError("receipt parsed artifact mismatch") from exc
    if artifact is not None:
        _, metadata = artifact
        if (type(metadata) is not tuple or len(metadata) != 2
                or metadata[0] != "parsed-private-receipt-v1"
                or type(metadata[1]) is not bytes):
            raise AdmissionError("receipt parsed artifact mismatch")
        try:
            # Decode a fresh object graph. Caller mutation cannot alter the
            # retained immutable artifact, and no live-source result is stored.
            receipt = marshal.loads(metadata[1])
            return receipt, {row["path"]: row for row in receipt["sources"]}
        except (ValueError, TypeError, EOFError) as exc:
            raise AdmissionError("receipt parsed artifact mismatch") from exc
    receipt = json.loads(data)
    rows = receipt.get("sources")
    if (receipt.get("version") != 1 or receipt.get("base") != _BASE
            or receipt.get("attestor_normalized_sha256") != _SELF_SHA256
            or receipt.get("predecessor_source_commit") != _PREDECESSOR
            or receipt.get("source_manifest_claim_sha256") != "73fbd321f4d4d33be8970b8006daff4143b9fba490430d2adac6e4854740dd4b"
            or receipt.get("observed_source_manifest_sha256") != receipt.get("source_manifest_claim_sha256")
            or receipt.get("before_archive_sha256") != _ARCHIVE_SHA256
            or receipt.get("helper") != {"path": "peaso/secret_evidence.py", "sha256": _HELPER_SHA256}
            or not isinstance(rows, list) or len(rows) != 50):
        raise AdmissionError("receipt roster mismatch")
    by_path = {_relative(x["path"]): x for x in rows}
    if len(by_path) != 50 or len({x["before_sha256"] for x in rows}) != 50:
        raise AdmissionError("duplicate source row")
    for row in rows:
        if len(row["before_sha256"]) != 64 or len(row["after_sha256"]) != 64:
            raise AdmissionError("invalid source hash")
        if not isinstance(row["definitions"], list) or not row["definitions"]:
            raise AdmissionError("empty definitions")
        names = [d["name"] for d in row["definitions"]]
        if len(names) != len(set(names)):
            raise AdmissionError("duplicate definition")
    metadata = ("parsed-private-receipt-v1", marshal.dumps(receipt, 2))
    sentinel = compile("None", str(file), "eval", dont_inherit=True)
    key = (str(file), str(file.resolve(strict=True)), hashlib.sha256(data).digest(),
           sys.implementation.cache_tag, sys.flags.optimize)
    secret = dict(zip(_SELF_CODE_CACHE.__code__.co_freevars,
                      (cell.cell_contents for cell in _SELF_CODE_CACHE.__closure__)))["secret"]
    signature = hmac.digest(secret, marshal.dumps((key, id(sentinel), metadata), 2), "sha256")
    if len(_SELF_CODE_CACHE_STORAGE) >= 64:
        _SELF_CODE_CACHE_STORAGE.clear()
    _SELF_CODE_CACHE_STORAGE[key] = (sentinel, metadata, signature)
    return receipt, by_path


def _root_path(root: str | Path, relative: str) -> Path:
    relative = _relative(relative)
    base = Path(root).resolve(strict=True)
    if not base.is_dir():
        raise AdmissionError("root is not a directory")
    target = base.joinpath(*PurePosixPath(relative).parts)
    if target.is_symlink() or target.resolve(strict=True) != target or not target.is_file():
        raise AdmissionError("source location mismatch")
    return target


def _live(root: str | Path, relative: str, row: dict) -> tuple[bytes, Path]:
    helper = _root_path(root, "peaso/secret_evidence.py")
    if _sha(helper.read_bytes()) != "9b6f3c63b7e730bafa5fe7535406c717e5483d505bc3d9cbc82db6079768ffe2":
        raise AdmissionError("private dependency mismatch")
    path = _root_path(root, relative)
    data = path.read_bytes()
    if relative in ("peaso/collectors/aws_code_log_content_indicators.py",
                    "peaso/collectors/gcp_log_secret_indicators.py",
                    "peaso/collectors/gcp_configuration_secret_indicators.py",
                    "peaso/collectors/aws_selected_configuration_secret_indicators.py"):
        receipt, _ = _receipt()
        transition = receipt["current_reviewed_files"][relative]
        old_sha = {
            "peaso/collectors/gcp_configuration_secret_indicators.py": "fece1e1e725f899dc06f7d257e97a5cf018b27f4915524289d398832d4e8969b",
            "peaso/collectors/aws_selected_configuration_secret_indicators.py": "c7a87afb1fc02740979a34efa2a03141d4e0daddbfdda1e45c604507c31c450f",
            "peaso/collectors/aws_code_log_content_indicators.py": "9a93faa6ea79503a43d80da060b9623b27b05ee22b7a5cda5b2037b63d02f8f4",
            "peaso/collectors/gcp_log_secret_indicators.py": "742707093416635c370b49b5f4d4ceb7aa6ead869a7d3748e1ee3698a4ab8268",
        }[relative]
        if (transition["predecessor_sha256"] != old_sha
                or transition["current_sha256"] != row["after_sha256"]):
            raise AdmissionError("reviewed source transition changed")
        text = data.decode("utf-8")
        for before, after in transition["exact_replacements"]:
            if text.count(after) != 1:
                raise AdmissionError("reviewed source replacement changed")
            text = text.replace(after, before, 1)
        for addition in transition["exact_additions"]:
            if text.count(addition) != 1:
                raise AdmissionError("reviewed source addition changed")
            text = text.replace(addition, "", 1)
        if _sha(text.encode("utf-8")) != old_sha:
            raise AdmissionError("reviewed source predecessor changed")
    if _sha(data) != row["after_sha256"]:
        raise AdmissionError("current source mismatch")
    return data, path


def source_rows() -> dict[str, dict]:
    """Return a new mapping of the 50 immutable source rows, keyed by path."""
    _, rows = _receipt()
    return json.loads(json.dumps(rows))


def predecessor_bytes(relative: str, current: bytes, expected_before: str, root: str | Path) -> bytes:
    """Return the exact cc762 predecessor for one pinned, live after-source."""
    receipt, rows = _receipt()
    relative = _relative(relative)
    row = rows.get(relative)
    if row is None:
        transition = receipt["current_reviewed_files"].get(relative)
        if (transition is None or type(current) is not bytes
                or expected_before != transition["predecessor_sha256"]
                or _sha(current) != transition["current_sha256"]
                or current != _root_path(root, relative).read_bytes()):
            raise AdmissionError("unreviewed predecessor request")
        text = current.decode("utf-8")
        for before, after in transition["exact_replacements"]:
            if text.count(after) != 1:
                raise AdmissionError("reviewed replacement changed")
            text = text.replace(after, before, 1)
        for addition in transition["exact_additions"]:
            if text.count(addition) != 1:
                raise AdmissionError("reviewed addition changed")
            text = text.replace(addition, "", 1)
        before = text.encode("utf-8")
        if _sha(before) != expected_before:
            raise AdmissionError("reviewed predecessor changed")
        return before
    if type(current) is not bytes or expected_before != row["before_sha256"]:
        raise AdmissionError("unreviewed predecessor request")
    live, _ = _live(root, relative, row)
    if current != live:
        raise AdmissionError("current bytes differ from disk")
    archive = Path(__file__).with_name("private_secret_source_epoch_20261021.zip")
    if _sha(archive.read_bytes()) != _ARCHIVE_SHA256:
        raise AdmissionError("predecessor archive mismatch")
    with zipfile.ZipFile(archive) as z:
        if sorted(z.namelist()) != sorted(rows):
            raise AdmissionError("predecessor archive roster mismatch")
        before = z.read(relative)
    if _sha(before) != expected_before:
        raise AdmissionError("predecessor bytes mismatch")
    return before


def predecessor_batch(requests: list[tuple[str, bytes, str]] | tuple[tuple[str, bytes, str], ...],
                      root: str | Path) -> dict[str, bytes]:
    """Return pinned predecessors for a finite set of live sources atomically."""
    _, rows = _receipt()
    return _predecessor_batch_rows(requests, root, rows)


def predecessor_bundle(requests: list[tuple[str, bytes, str]] | tuple[tuple[str, bytes, str], ...],
                       root: str | Path) -> tuple[list[str], dict[str, bytes]]:
    """Prove the full roster and selected predecessors in one fresh operation."""
    _, rows = _receipt()
    return sorted(rows), _predecessor_batch_rows(requests, root, rows)


def _predecessor_batch_rows(requests: list[tuple[str, bytes, str]] | tuple[tuple[str, bytes, str], ...],
                            root: str | Path, rows: dict[str, dict]) -> dict[str, bytes]:
    """Batch mechanics; callers must supply rows from their own fresh receipt."""
    if type(requests) not in (list, tuple) or not requests or len(requests) > len(rows):
        raise AdmissionError("invalid predecessor batch")
    selected = []
    seen = set()
    for request in requests:
        if type(request) not in (list, tuple) or len(request) != 3:
            raise AdmissionError("invalid predecessor request")
        relative, current, expected_before = request
        if type(relative) is not str or type(current) is not bytes or type(expected_before) is not str:
            raise AdmissionError("invalid predecessor request types")
        relative = _relative(relative)
        row = rows.get(relative)
        if relative in seen or row is None or expected_before != row["before_sha256"]:
            raise AdmissionError("unreviewed predecessor request")
        seen.add(relative)
        selected.append((relative, current, expected_before, row))
    for relative, current, _, row in selected:
        try:
            live, _ = _live(root, relative, row)
        except (OSError, TypeError) as exc:
            raise AdmissionError("source location mismatch") from exc
        if current != live:
            raise AdmissionError("current bytes differ from disk")
    archive = Path(__file__).with_name("private_secret_source_epoch_20261021.zip")
    archive_bytes = archive.read_bytes()
    if _sha(archive_bytes) != _ARCHIVE_SHA256:
        raise AdmissionError("predecessor archive mismatch")
    result = {}
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as z:
        if sorted(z.namelist()) != sorted(rows):
            raise AdmissionError("predecessor archive roster mismatch")
        for relative, _, expected_before, _ in selected:
            before = z.read(relative)
            if _sha(before) != expected_before:
                raise AdmissionError("predecessor bytes mismatch")
            result[relative] = before
    return result


def _code_equal(a: CodeType, b: CodeType) -> bool:
    fields = ("co_argcount", "co_posonlyargcount", "co_kwonlyargcount", "co_nlocals",
              "co_stacksize", "co_flags", "co_code", "co_names", "co_varnames",
              "co_freevars", "co_cellvars", "co_filename", "co_name", "co_qualname",
              "co_firstlineno", "co_linetable", "co_exceptiontable")
    return (all(getattr(a, field) == getattr(b, field) for field in fields)
            and len(a.co_consts) == len(b.co_consts)
            and all(_code_equal(x, y) if isinstance(x, CodeType) and isinstance(y, CodeType)
                    else _same(x, y) for x, y in zip(a.co_consts, b.co_consts)))


def _ast_form(value: object) -> object:
    if isinstance(value, ast.AST):
        return {"node": type(value).__name__, "fields": {
            key: _ast_form(member) for key, member in ast.iter_fields(value)
            if key not in ("lineno", "col_offset", "end_lineno", "end_col_offset")
            and not (key == "type_params" and not member)
            and not (key == "is_lazy" and type(member) in (bool, int) and member == 0)}}
    if isinstance(value, list):
        return [_ast_form(x) for x in value]
    if isinstance(value, tuple):
        return {"tuple": [_ast_form(x) for x in value]}
    if value is None or type(value) in (str, int, bool, float):
        return value
    if isinstance(value, bytes):
        return {"bytes": value.hex()}
    if value is Ellipsis:
        return {"literal": "Ellipsis"}
    if isinstance(value, complex):
        return {"complex": [value.real, value.imag]}
    raise AdmissionError("unreviewed AST value")


def _ast_hash(node: ast.AST) -> str:
    return _sha(json.dumps(_ast_form(node), sort_keys=True).encode())


def _source_hash(data: bytes, node: ast.AST) -> str:
    lines = data.splitlines(keepends=True)
    start = min([node.lineno] + [d.lineno for d in getattr(node, "decorator_list", [])])
    return _sha(b"".join(lines[start - 1:node.end_lineno]))


def _code_from(container: CodeType, name: str) -> CodeType:
    found = [x for x in container.co_consts if isinstance(x, CodeType) and x.co_name == name]
    if len(found) != 1:
        raise AdmissionError("compiled definition missing or ambiguous")
    return found[0]


def _literal(expr: ast.AST, constants: dict[str, object], filename: str, namespace: dict | None = None) -> object:
    if isinstance(expr, ast.Name) and expr.id in constants:
        return constants[expr.id]
    if isinstance(expr, ast.BinOp) and type(expr.op) in (ast.Add, ast.Mult):
        left = _literal(expr.left, constants, filename, namespace)
        right = _literal(expr.right, constants, filename, namespace)
        if type(left) is type(right) is int and 0 <= left <= 1 << 30 and 0 <= right <= 1 << 30:
            result = left + right if type(expr.op) is ast.Add else left * right
            if result <= 1 << 32:
                return result
        if type(expr.op) is ast.Add and type(left) is type(right) is str and len(left) + len(right) <= 8192:
            return left + right
        raise AdmissionError("unsupported finite arithmetic")
    if isinstance(expr, (ast.Tuple, ast.List, ast.Set)):
        items = [_literal(x, constants, filename, namespace) for x in expr.elts]
        return tuple(items) if type(expr) is ast.Tuple else list(items) if type(expr) is ast.List else set(items)
    if isinstance(expr, ast.Dict) and all(key is not None for key in expr.keys):
        return {_literal(k, constants, filename, namespace): _literal(v, constants, filename, namespace)
                for k, v in zip(expr.keys, expr.values)}
    if (isinstance(expr, ast.Call) and type(expr.func) is ast.Attribute
            and type(expr.func.value) is ast.Name and expr.func.value.id == "re"
            and expr.func.attr == "compile" and len(expr.args) in (1, 2)
            and not expr.keywords):
        pattern = _literal(expr.args[0], constants, filename, namespace)
        flag = 0
        if len(expr.args) == 2:
            flags = expr.args[1]
            if (type(flags) is not ast.Attribute or type(flags.value) is not ast.Name
                    or flags.value.id != "re" or flags.attr not in ("I", "IGNORECASE")):
                raise AdmissionError("unsupported regex flags")
            flag = re.I
        if type(pattern) is not str or len(pattern) > 8192:
            raise AdmissionError("unsupported regex pattern")
        return re.compile(pattern, flag)
    if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name) and namespace is not None:
        module = namespace.get(expr.value.id)
        if type(module) is ModuleType and sys.modules.get(module.__name__) is module and hasattr(module, expr.attr):
            return getattr(module, expr.attr)
    if isinstance(expr, ast.Lambda):
        return _code_from(compile(ast.Expression(expr), filename, "eval", dont_inherit=True), "<lambda>")
    if (isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name)
            and expr.func.id == "frozenset" and len(expr.args) == 1 and not expr.keywords):
        arg = expr.args[0]
        if (type(arg) is ast.Call and type(arg.func) is ast.Attribute
                and type(arg.func.value) is ast.Constant and type(arg.func.value.value) is str
                and arg.func.attr == "split" and not arg.args and not arg.keywords
                and len(arg.func.value.value) <= 8192):
            return frozenset(arg.func.value.value.split())
        try:
            return frozenset(ast.literal_eval(expr.args[0]))
        except (ValueError, TypeError, SyntaxError) as exc:
            raise AdmissionError("nonliteral frozenset") from exc
    try:
        return ast.literal_eval(expr)
    except (ValueError, TypeError, SyntaxError, MemoryError) as exc:
        raise AdmissionError("nonliteral default/global is outside finite contract") from exc


def _constants(tree: ast.Module, filename: str) -> dict[str, object]:
    values: dict[str, object] = {}
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and type(node.targets[0]) is ast.Tuple and type(node.value) is ast.Tuple
                and len(node.targets[0].elts) == len(node.value.elts)
                and all(type(x) is ast.Name for x in node.targets[0].elts)):
            try:
                parts = [_literal(x, values, filename) for x in node.value.elts]
            except AdmissionError:
                continue
            for target, value in zip(node.targets[0].elts, parts):
                values[target.id] = value
            continue
        if isinstance(node, ast.Assign) and all(isinstance(t, ast.Name) for t in node.targets):
            try:
                value = _literal(node.value, values, filename)
            except AdmissionError:
                continue
            for target in node.targets:
                values[target.id] = value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            try:
                values[node.target.id] = _literal(node.value, values, filename)
            except AdmissionError:
                pass
    return values


def _globals_used(code: CodeType) -> set[str]:
    names = {i.argval for i in dis.get_instructions(code) if i.opname in ("LOAD_GLOBAL", "LOAD_NAME")}
    for item in code.co_consts:
        if isinstance(item, CodeType):
            names.update(_globals_used(item))
    return names


def _check_defaults(fn: FunctionType, node: ast.FunctionDef | ast.AsyncFunctionDef, constants: dict, filename: str, owner: type | None = None) -> None:
    expected = tuple(_literal(x, constants, filename, fn.__globals__) for x in node.args.defaults)
    actual = fn.__defaults__ or ()
    if len(actual) != len(expected):
        raise AdmissionError("default count mismatch")
    for a, b in zip(actual, expected):
        if isinstance(b, CodeType):
            if type(a) is not FunctionType or not _code_equal(a.__code__, b) or a.__globals__ is not fn.__globals__ or a.__closure__:
                raise AdmissionError("lambda default mismatch")
        elif not _same(a, b):
            raise AdmissionError("default value mismatch")
    expected_kw = {arg.arg: _literal(value, constants, filename, fn.__globals__) for arg, value in zip(node.args.kwonlyargs, node.args.kw_defaults) if value is not None}
    kw = fn.__kwdefaults__ or {}
    if set(kw) != set(expected_kw):
        raise AdmissionError("keyword default mismatch")
    for key, expected_value in expected_kw.items():
        actual_value = kw[key]
        if isinstance(expected_value, CodeType):
            if (type(actual_value) is not FunctionType
                    or not _code_equal(actual_value.__code__, expected_value)
                    or actual_value.__globals__ is not fn.__globals__
                    or actual_value.__closure__ is not None):
                raise AdmissionError("lambda keyword default mismatch")
        elif not _same(actual_value, expected_value):
            raise AdmissionError("keyword default mismatch")
    if owner is None:
        if fn.__closure__ is not None or fn.__code__.co_freevars:
            raise AdmissionError("unexpected top-level closure")
    elif fn.__code__.co_freevars:
        if (fn.__code__.co_freevars != ("__class__",) or fn.__closure__ is None
                or len(fn.__closure__) != 1 or fn.__closure__[0].cell_contents is not owner):
            raise AdmissionError("class closure binding mismatch")
    elif fn.__closure__ is not None:
        raise AdmissionError("unexpected method closure")



def _expected_helper_code(path: Path, data: bytes, filename: str) -> CodeType:
    """Reuse only signed, immutable compilation artifacts after a fresh self proof."""
    _self()
    if (type(path) is not type(Path()) or type(data) is not bytes
            or type(filename) is not str or path.resolve(strict=True) != path
            or Path(filename).resolve(strict=True) != path):
        raise AdmissionError("helper code source mismatch")
    cache_path = Path(filename)
    try:
        artifact = _SELF_CODE_CACHE(cache_path, data)
    except ValueError as exc:
        raise AdmissionError("helper code cache artifact mismatch") from exc
    if artifact is None:
        code = compile(data, filename, "exec", dont_inherit=True)
        if not _immutable_code_constants(code):
            raise AdmissionError("helper code has mutable constants")
        key = (str(cache_path), str(path), hashlib.sha256(data).digest(),
               sys.implementation.cache_tag, sys.flags.optimize)
        secret = dict(zip(_SELF_CODE_CACHE.__code__.co_freevars,
                          (cell.cell_contents for cell in _SELF_CODE_CACHE.__closure__)))["secret"]
        signature = hmac.digest(secret, marshal.dumps((key, id(code), ()), 2), "sha256")
        if len(_SELF_CODE_CACHE_STORAGE) >= 64:
            _SELF_CODE_CACHE_STORAGE.clear()
        _SELF_CODE_CACHE_STORAGE[key] = (code, (), signature)
    else:
        code, metadata = artifact
        if type(metadata) is not tuple or metadata:
            raise AdmissionError("helper code cache artifact mismatch")
    return code



def _check_contextmanager_helper(value: object, imported: ModuleType, attr: str,
                                 path: Path, data: bytes) -> None:
    """Admit only the two reviewed helper bodies wrapped by stdlib contextmanager."""
    tree = ast.parse(data)
    nodes = [x for x in tree.body if type(x) is ast.FunctionDef and x.name == attr]
    if (len(nodes) != 1 or len(nodes[0].decorator_list) != 1
            or type(nodes[0].decorator_list[0]) is not ast.Name
            or nodes[0].decorator_list[0].id != "contextmanager"):
        raise AdmissionError("unsupported helper decorator")
    stdlib = Path(sysconfig.get_path("stdlib")).resolve(strict=True)
    stdpath = (stdlib / "contextlib.py").resolve(strict=True)
    decorator = contextlib.contextmanager
    if (sys.modules.get("contextlib") is not contextlib
            or getattr(imported, "contextmanager", None) is not decorator
            or type(decorator) is not FunctionType
            or decorator.__globals__ is not vars(contextlib)
            or Path(contextlib.__file__).resolve(strict=True) != stdpath
            or Path(decorator.__code__.co_filename).resolve(strict=True) != stdpath):
        raise AdmissionError("contextmanager stdlib binding mismatch")
    compiled_stdlib = _expected_helper_code(stdpath, stdpath.read_bytes(),
                                            decorator.__code__.co_filename)
    std_code = _code_from(compiled_stdlib, "contextmanager")
    if not _code_equal(decorator.__code__, std_code):
        raise AdmissionError("contextmanager stdlib code mismatch")
    wrapper_code = _code_from(std_code, "helper")
    if (type(value) is not FunctionType or getattr(imported, attr, None) is not value
            or value.__module__ != imported.__name__
            or value.__name__ != attr or value.__qualname__ != attr
            or value.__globals__ is not vars(contextlib)
            or value.__defaults__ is not None or value.__kwdefaults__ is not None
            or Path(value.__code__.co_filename).resolve(strict=True) != stdpath
            or not _code_equal(value.__code__, wrapper_code)
            or value.__code__.co_freevars != ("func",)
            or value.__closure__ is None or len(value.__closure__) != 1
            or set(vars(value)) != {"__wrapped__"}):
        raise AdmissionError("contextmanager wrapper binding mismatch")
    raw = value.__wrapped__
    if (type(raw) is not FunctionType or value.__closure__[0].cell_contents is not raw
            or raw.__module__ != imported.__name__
            or raw.__name__ != attr or raw.__qualname__ != attr
            or raw.__globals__ is not vars(imported)
            or Path(raw.__code__.co_filename).resolve(strict=True) != path
            or value.__doc__ != raw.__doc__
            or not _same(value.__annotations__, raw.__annotations__)):
        raise AdmissionError("contextmanager wrapped body binding mismatch")
    compiled_helper = _expected_helper_code(path, data, raw.__code__.co_filename)
    if not _code_equal(raw.__code__, _code_from(compiled_helper, attr)):
        raise AdmissionError("contextmanager wrapped body code mismatch")
    _check_defaults(raw, nodes[0], _constants(tree, str(path)), str(path))



def _check_helper_import(value: object, imported: ModuleType, attr: str | None, root: str | Path) -> None:
    if imported.__name__ != "peaso.secret_evidence":
        return
    path = _root_path(root, "peaso/secret_evidence.py")
    if Path(getattr(imported, "__file__", "")).resolve(strict=True) != path:
        raise AdmissionError("helper module location mismatch")
    data = path.read_bytes()
    if (_sha(data) != _receipt()[0]["current_reviewed_files"]["peaso/secret_evidence.py"]["current_sha256"]
            or _sha(predecessor_bytes("peaso/secret_evidence.py", data, _HELPER_SHA256, root)) != _HELPER_SHA256):
        raise AdmissionError("helper module source mismatch")
    if attr is None:
        return
    if attr in ("capture", "source_context"):
        _check_contextmanager_helper(value, imported, attr, path, data)
        return
    if type(value) is FunctionType:
        if (value.__module__ != imported.__name__ or value.__globals__ is not vars(imported)
                or value.__qualname__ != attr or Path(value.__code__.co_filename).resolve(strict=True) != path):
            raise AdmissionError("helper callable binding mismatch")
        tree = ast.parse(data)
        nodes = [x for x in tree.body if isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef)) and x.name == attr]
        if len(nodes) != 1:
            raise AdmissionError("helper callable source ambiguity")
        compiled = _expected_helper_code(path, data, value.__code__.co_filename)
        if not _code_equal(value.__code__, _code_from(compiled, attr)):
            raise AdmissionError("helper callable code mismatch")
        _check_defaults(value, nodes[0], _constants(tree, str(path)), str(path))



# This unchanged dependency supplies the same Incomplete class to two reviewed
# sources.  Every other alias origin must occur in the 50-row receipt.
_ALIAS_DEPENDENCIES = {
    "peaso/collectors/gcp_git_transport.py": "3b872883dc04776fba11e489b38238e212f15aba78a517ca0c52248efde2c9f0",
    "peaso/collectors/gcp_git_content.py": "dccb7525a2bceab717f80c30fc02f4153b1c2ae440ffa4cf3ca9769c57c0493b",
    "peaso/collectors/aws_workload_command_runtime_20261020.py": "de543276807257ff814980b78e523be21de02cecab7f9b31b2cb7dfb0940b09d",
}


def _alias_source(module: ModuleType, root: str | Path) -> tuple[ast.Module, CodeType]:
    if type(module) is not ModuleType or sys.modules.get(module.__name__) is not module:
        raise AdmissionError("alias origin module identity mismatch")
    base = Path(root).resolve(strict=True)
    file = getattr(module, "__file__", None)
    if type(file) is not str:
        raise AdmissionError("alias origin has no source")
    try:
        relative = Path(file).resolve(strict=True).relative_to(base).as_posix()
    except ValueError as exc:
        raise AdmissionError("alias origin outside root") from exc
    rows = _receipt()[1]
    expected = rows[relative]["after_sha256"] if relative in rows else _ALIAS_DEPENDENCIES.get(relative)
    if (expected is None or module.__name__ != relative[:-3].replace("/", ".")
            or Path(file).resolve(strict=True) != _root_path(root, relative)):
        raise AdmissionError("unreviewed alias origin")
    data = _root_path(root, relative).read_bytes()
    if _sha(data) != expected:
        raise AdmissionError("alias origin source mismatch")
    return ast.parse(data, filename=file), _expected_helper_code(Path(file).resolve(strict=True), data, file)


def _alias_binding(module: ModuleType, name: str, root: str | Path,
                   trail: frozenset[tuple[str, str]] | None = None) -> object:
    if trail is None:
        trail = frozenset()
    key = (module.__name__, name)
    if key in trail:
        raise AdmissionError("cyclic alias")
    tree, compiled = _alias_source(module, root)
    bindings = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if (alias.asname or alias.name.split(".")[0]) == name:
                    bindings.append(("import", node, alias))
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if (alias.asname or alias.name) == name:
                    bindings.append(("from", node, alias))
        elif isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                raise AdmissionError("ambiguous alias assignment")
            bindings.append(("assign", node, None))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == name:
            bindings.append(("definition", node, None))
    if len(bindings) != 1:
        raise AdmissionError("alias source binding ambiguity: " + name)
    kind, node, alias = bindings[0]
    live = vars(module).get(name)
    if kind == "import":
        imported = sys.modules.get(alias.name)
        expected = imported if alias.asname else sys.modules.get(alias.name.split(".")[0])
        if type(expected) is not ModuleType or live is not expected:
            raise AdmissionError("alias import identity mismatch")
    elif kind == "from":
        package = module.__package__ or module.__name__.rpartition(".")[0]
        source = importlib.util.resolve_name("." * node.level + (node.module or ""), package) if node.level else node.module
        imported = sys.modules.get(source)
        exported = vars(imported).get(alias.name) if type(imported) is ModuleType else None
        module_import = False
        if node.module is None and node.level:
            candidate = sys.modules.get(source + "." + alias.name)
            if type(candidate) is ModuleType:
                exported = candidate
                module_import = True
        if (not module_import and type(imported) is not ModuleType) or live is not exported:
            raise AdmissionError("alias from-import identity mismatch")
        if type(live) is type:
            if type(imported) is not ModuleType:
                raise AdmissionError("class import origin missing")
            _alias_binding(imported, alias.name, root, trail | {key})
    elif kind == "assign":
        expr = node.value
        if isinstance(expr, ast.Name):
            expected = _alias_binding(module, expr.id, root, trail | {key})
        elif isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name):
            origin = _alias_binding(module, expr.value.id, root, trail | {key})
            if type(origin) is not ModuleType:
                raise AdmissionError("alias attribute origin is not a module")
            expected = _alias_binding(origin, expr.attr, root, trail | {key})
        else:
            raise AdmissionError("unsupported alias expression")
        if live is not expected:
            raise AdmissionError("alias assignment identity mismatch")
    elif isinstance(node, ast.ClassDef):
        if type(live) is not type:
            raise AdmissionError("alias class identity mismatch")
        _check_class(live, node, compiled, module, _constants(tree, getattr(module, "__file__")), tree, root)
    else:
        raise AdmissionError("alias origin is not a module or class")
    if type(live) is ModuleType:
        _alias_source(live, root)
    elif type(live) is not type:
        raise AdmissionError("alias value is not a module or class")
    return live

def _imported_module_alias(module: ModuleType, tree: ast.Module, name: str,
                           root: str | Path) -> ModuleType:
    matches = [(node, alias) for node in tree.body if isinstance(node, ast.ImportFrom)
               for alias in node.names if (alias.asname or alias.name) == name]
    if len(matches) != 1:
        raise AdmissionError("module alias source ambiguity")
    row, alias = matches[0]
    package = module.__package__ or module.__name__.rpartition(".")[0]
    source = (importlib.util.resolve_name("." * row.level + (row.module or ""), package)
              if row.level else row.module)
    parent = sys.modules.get(source)
    bound = getattr(parent, alias.name, None) if parent is not None else None
    if (type(bound) is not ModuleType or vars(module).get(name) is not bound
            or sys.modules.get(bound.__name__) is not bound):
        raise AdmissionError("module alias binding mismatch")
    relative = bound.__name__.replace(".", "/") + ".py"
    if Path(getattr(bound, "__file__", "")).resolve(strict=True) != _root_path(root, relative):
        raise AdmissionError("module alias location mismatch")
    _, rows = _receipt()
    if relative in rows:
        _live(root, relative, rows[relative])
    return bound


def _check_reviewed_alias(name: str, value: object, tree: ast.Module,
                          module: ModuleType, root: str | Path) -> bool:
    allowed = {
        ("peaso.collectors.gcp_appengine_source_secret_indicators", "Incomplete"),
        ("peaso.collectors.gcp_composer_source_secret_indicators", "Incomplete"),
        ("peaso.collectors.gcp_selected_task_routine_secret_indicators", "Incomplete"),
        ("peaso.collectors.gcp_sourcerepo_secret_indicators", "Incomplete"),
        ("peaso.collectors.gcp_batch_referenced_source_20261020", "objects"),
        ("peaso.collectors.gcp_batch_referenced_source_20261020", "Incomplete"),
        ("peaso.collectors.gcp_dataflow_referenced_source_20261020", "Incomplete"),
        ("peaso.collectors.gcp_dataproc_referenced_source_secret_indicators", "Incomplete"),
        ("peaso.collectors.gcp_workbench_referenced_source_20261020", "Incomplete"),
    }
    if (module.__name__, name) not in allowed:
        return False
    assignments = [node for node in tree.body if isinstance(node, ast.Assign)
                   and len(node.targets) == 1 and type(node.targets[0]) is ast.Name
                   and node.targets[0].id == name]
    if (len(assignments) != 1 or type(assignments[0].value) is not ast.Attribute
            or type(assignments[0].value.value) is not ast.Name):
        raise AdmissionError("reviewed alias source mismatch")
    expr = assignments[0].value
    imported = _imported_module_alias(module, tree, expr.value.id, root)
    if value is not getattr(imported, expr.attr, None):
        raise AdmissionError("reviewed alias binding mismatch")
    if name == "Incomplete":
        if type(value) is not type or sys.modules.get(value.__module__) is None:
            raise AdmissionError("reviewed exception class mismatch")
        owner = sys.modules[value.__module__]
        if vars(owner).get(value.__name__) is not value:
            raise AdmissionError("reviewed exception owner mismatch")
        relative = owner.__name__.replace(".", "/") + ".py"
        path = _root_path(root, relative)
        if Path(getattr(owner, "__file__", "")).resolve(strict=True) != path:
            raise AdmissionError("reviewed exception source location mismatch")
        data = path.read_bytes()
        _, rows = _receipt()
        if relative in rows:
            data, _ = _live(root, relative, rows[relative])
        source_tree = ast.parse(data, filename=str(path))
        classes = [x for x in source_tree.body if type(x) is ast.ClassDef and x.name == value.__name__]
        if len(classes) != 1:
            raise AdmissionError("reviewed exception source ambiguity")
        compiled = compile(data, str(path), "exec", dont_inherit=True)
        _check_class(value, classes[0], compiled, owner,
                     _constants(source_tree, str(path)), source_tree, root)
    elif type(value) is not ModuleType or sys.modules.get(value.__name__) is not value:
        raise AdmissionError("reviewed module alias mismatch")
    return True

def _check_class(owner: type, node: ast.ClassDef, compiled: CodeType, module: ModuleType,
                 constants: dict, tree: ast.Module, root: str | Path) -> None:
    if type(owner) is not type or owner.__module__ != module.__name__ or owner.__qualname__ != node.name:
        raise AdmissionError("class binding mismatch")
    names = [x for x in node.body if isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef))]
    pass_class_sources = {
        "peaso.collectors.aws_s3_selected_source_secret_indicators",
        "peaso.collectors.azure_devops_selected_content_secret_indicators",
        "peaso.collectors.gcp_artifact_file_secret_indicators",
        "peaso.collectors.gcp_job_literal_secret_indicators",
    }
    pass_only = (node.name == "Incomplete" and module.__name__ in pass_class_sources
                 and len(node.body) == 1 and isinstance(node.body[0], ast.Pass))
    if (len({x.name for x in names}) != len(names)
            or (not pass_only and any(not isinstance(x, (ast.Expr, ast.FunctionDef, ast.AsyncFunctionDef)) for x in node.body))):
        raise AdmissionError("unsupported class body")
    allowed_meta = {"__module__", "__doc__", "__dict__", "__weakref__", "__firstlineno__", "__static_attributes__"}
    if set(vars(owner)) - allowed_meta != {x.name for x in names}:
        raise AdmissionError("class member roster mismatch")
    bases = []
    for base in node.bases:
        if isinstance(base, ast.Name) and type(getattr(builtins, base.id, None)) is type:
            expected = getattr(builtins, base.id)
        elif isinstance(base, ast.Name):
            import_rows = [item for item in tree.body if isinstance(item, ast.ImportFrom)
                           and any((alias.asname or alias.name) == base.id for alias in item.names)]
            if len(import_rows) == 1:
                # Preserve the predecessor's exact direct-import class proof.
                item = import_rows[0]
                package = module.__package__ or module.__name__.rpartition(".")[0]
                modname = importlib.util.resolve_name("." * item.level + (item.module or ""), package) if item.level else item.module
                imported = sys.modules.get(modname)
                alias = next(alias for alias in item.names if (alias.asname or alias.name) == base.id)
                expected = vars(module).get(base.id)
                if imported is None or expected is not getattr(imported, alias.name, None):
                    raise AdmissionError("class base import identity mismatch")
            else:
                expected = _alias_binding(module, base.id, root)
        elif isinstance(base, ast.Attribute) and isinstance(base.value, ast.Name):
            origin = _alias_binding(module, base.value.id, root)
            if type(origin) is not ModuleType:
                raise AdmissionError("class base origin mismatch")
            expected = _alias_binding(origin, base.attr, root)
        else:
            raise AdmissionError("unsupported class base")
        if type(expected) is not type:
            raise AdmissionError("class base is not a class")
        bases.append(expected)
    if owner.__bases__ != tuple(bases or [object]):
        raise AdmissionError("class bases mismatch")
    class_code = _code_from(compiled, node.name)
    for member in names:
        value = vars(owner).get(member.name)
        decorators = [ast.unparse(x) for x in member.decorator_list]
        if decorators == ["staticmethod"]:
            if type(value) is not staticmethod:
                raise AdmissionError("staticmethod binding mismatch")
            value = value.__func__
        elif decorators:
            raise AdmissionError("unsupported class method decorator")
        if (type(value) is not FunctionType or value.__globals__ is not vars(module)
                or value.__module__ != module.__name__
                or value.__qualname__ != node.name + "." + member.name
                or not _code_equal(value.__code__, _code_from(class_code, member.name))):
            raise AdmissionError("class method code mismatch: " + member.name)
        _check_defaults(value, member, constants, value.__code__.co_filename, owner)


def _expected_hosts(module: ModuleType, tree: ast.Module) -> frozenset[str]:
    initial = [x.value for x in tree.body if isinstance(x, ast.Assign)
               and any(isinstance(t, ast.Name) and t.id == "HOSTS" for t in x.targets)]
    if len(initial) != 1 or not isinstance(initial[0], ast.Call) or len(initial[0].args) != 1:
        raise AdmissionError("HOSTS source shape changed")
    generator = initial[0].args[0]
    if not isinstance(generator, ast.GeneratorExp) or len(generator.generators) != 1:
        raise AdmissionError("HOSTS generator shape changed")
    services = ast.literal_eval(generator.generators[0].iter)
    if not isinstance(services, tuple) or not all(type(x) is str for x in services):
        raise AdmissionError("HOSTS literal services changed")
    globals_ = vars(module)
    source = sys.modules.get("peaso.collectors.gcp_network_catalog")
    if source is None:
        raise AdmissionError("network catalog module missing")
    for name, attr in (("NETWORK_PRIVATE_SERVICES", "PRIVATE_SERVICES"),
                       ("NETWORK_REGIONAL_SERVICES", "REGIONAL"),
                       ("NETWORK_SERVICE_ENDPOINTS", "SERVICE_ENDPOINTS")):
        if globals_.get(name) is not getattr(source, attr, None):
            raise AdmissionError("network catalog binding mismatch")
    derived = {plan["service"] for plan in globals_["NETWORK_PRIVATE_SERVICES"].values()}
    derived |= {plan[0] for plan in globals_["NETWORK_REGIONAL_SERVICES"].values()}
    hosts = {s + ".googleapis.com" for s in services}
    hosts |= {service + ".googleapis.com" for service in derived}
    hosts |= {host for service in derived
              for host in globals_["NETWORK_SERVICE_ENDPOINTS"].get(service, {}).values()}
    if not all(type(x) is str for x in hosts):
        raise AdmissionError("network catalog host type mismatch")
    return frozenset(hosts)


def _check_private_read(value: FunctionType, name: str, tree: ast.Module,
                        compiled: CodeType, constants: dict, module: ModuleType,
                        root: str | Path) -> None:
    if module.__name__ != "peaso.collectors.k8s_selected_log_sample_secret_indicators" or name != "_read":
        raise AdmissionError("unsupported decorated function")
    nodes = [x for x in tree.body if isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef)) and x.name == name]
    helpers = [x for x in tree.body if isinstance(x, ast.FunctionDef) and x.name == "_private_read"]
    if (len(nodes) != 1 or len(helpers) != 1 or len(nodes[0].decorator_list) != 1
            or not isinstance(nodes[0].decorator_list[0], ast.Name)
            or nodes[0].decorator_list[0].id != "_private_read"):
        raise AdmissionError("private read decorator source mismatch")
    helper = vars(module).get("_private_read")
    helper_code = _code_from(compiled, "_private_read")
    if (type(helper) is not FunctionType or helper.__globals__ is not vars(module)
            or helper.__module__ != module.__name__ or helper.__qualname__ != "_private_read"
            or not _code_equal(helper.__code__, helper_code)):
        raise AdmissionError("private read decorator binding mismatch")
    _check_defaults(helper, helpers[0], constants, helper.__code__.co_filename)
    original = getattr(value, "__wrapped__", None)
    wrapper_code = _code_from(helper_code, "wrapped")
    if (type(value) is not FunctionType or type(original) is not FunctionType
            or value.__globals__ is not vars(module) or original.__globals__ is not vars(module)
            or value.__module__ != module.__name__ or original.__module__ != module.__name__
            or value.__name__ != name or original.__name__ != name
            or value.__qualname__ != name or original.__qualname__ != name
            or value.__defaults__ is not None or value.__kwdefaults__ is not None
            or value.__doc__ != original.__doc__
            or not _same(value.__annotations__, original.__annotations__)
            or not _code_equal(value.__code__, wrapper_code)
            or not _code_equal(original.__code__, _code_from(compiled, name))
            or value.__code__.co_freevars != ("function",)
            or value.__closure__ is None or len(value.__closure__) != 1
            or value.__closure__[0].cell_contents is not original
            or set(vars(value)) != {"__wrapped__"}):
        raise AdmissionError("private read wrapper provenance mismatch")
    _check_defaults(original, nodes[0], constants, original.__code__.co_filename)
    _check_globals(helper, tree, compiled, constants, module, root)
    _check_globals(original, tree, compiled, constants, module, root)


def _check_k8s_contextmanager(value: FunctionType, node: ast.FunctionDef,
                              tree: ast.Module, compiled: CodeType, constants: dict,
                              module: ModuleType, root: str | Path) -> None:
    import contextlib
    import sysconfig
    if (module.__name__ != "peaso.collectors.k8s_selected_log_sample_secret_indicators"
            or node.name != "private_native_logs" or len(node.decorator_list) != 1
            or type(node.decorator_list[0]) is not ast.Name
            or node.decorator_list[0].id != "contextmanager"
            or vars(module).get("contextmanager") is not contextlib.contextmanager
            or sys.modules.get("contextlib") is not contextlib):
        raise AdmissionError("unsupported same-module contextmanager")
    stdpath = (Path(sysconfig.get_path("stdlib")).resolve(strict=True) / "contextlib.py").resolve(strict=True)
    decorator = contextlib.contextmanager
    std_code = _code_from(compile(stdpath.read_bytes(), str(stdpath), "exec", dont_inherit=True), "contextmanager")
    if (type(decorator) is not FunctionType or decorator.__globals__ is not vars(contextlib)
            or Path(contextlib.__file__).resolve(strict=True) != stdpath
            or Path(decorator.__code__.co_filename).resolve(strict=True) != stdpath
            or not _code_equal(decorator.__code__, std_code)):
        raise AdmissionError("contextmanager origin mismatch")
    raw = getattr(value, "__wrapped__", None)
    if (type(value) is not FunctionType or type(raw) is not FunctionType
            or vars(module).get(node.name) is not value
            or value.__globals__ is not vars(contextlib)
            or raw.__globals__ is not vars(module)
            or value.__module__ != module.__name__ or raw.__module__ != module.__name__
            or value.__name__ != node.name or raw.__name__ != node.name
            or value.__qualname__ != node.name or raw.__qualname__ != node.name
            or value.__defaults__ is not None or value.__kwdefaults__ is not None
            or not _code_equal(value.__code__, _code_from(std_code, "helper"))
            or not _code_equal(raw.__code__, _code_from(compiled, node.name))
            or value.__code__.co_freevars != ("func",)
            or value.__closure__ is None or len(value.__closure__) != 1
            or value.__closure__[0].cell_contents is not raw
            or set(vars(value)) != {"__wrapped__"}
            or value.__doc__ != raw.__doc__
            or not _same(value.__annotations__, raw.__annotations__)):
        raise AdmissionError("contextmanager wrapper mismatch")
    _check_defaults(raw, node, constants, raw.__code__.co_filename)
    _check_globals(raw, tree, compiled, constants, module, root)


def _check_workload_reviewed_successor(value: FunctionType, node: ast.FunctionDef,
                                       tree: ast.Module, compiled: CodeType, constants: dict,
                                       module: ModuleType, root: str | Path) -> None:
    """Admit the one installed workload source binding and prove both definitions."""
    runtime_name = "peaso.collectors.aws_workload_command_runtime_20261020"
    runtime = sys.modules.get(runtime_name)
    if (module.__name__ != "peaso.collectors.aws_workload_command_source_20261020"
            or node.name != "reviewed_sources" or type(runtime) is not ModuleType
            or vars(runtime).get("source") is not module
            or vars(module).get("reviewed_sources") is not value
            or vars(runtime).get("reviewed_sources") is not value):
        raise AdmissionError("workload reviewed successor binding mismatch")
    historical = vars(runtime).get("_HISTORICAL_REVIEWED_SOURCES")
    if (type(historical) is not FunctionType
            or historical.__module__ != module.__name__
            or historical.__name__ != node.name or historical.__qualname__ != node.name
            or historical.__globals__ is not vars(module)
            or not _code_equal(historical.__code__, _code_from(compiled, node.name))):
        raise AdmissionError("workload historical reviewed function mismatch")
    _check_defaults(historical, node, constants, historical.__code__.co_filename)
    _check_globals(historical, tree, compiled, constants, module, root)
    runtime_tree, runtime_compiled = _alias_source(runtime, root)
    runtime_nodes = [x for x in runtime_tree.body
                     if isinstance(x, ast.FunctionDef) and x.name == node.name]
    if (len(runtime_nodes) != 1 or runtime_nodes[0].decorator_list
            or value.__module__ != runtime_name
            or value.__name__ != node.name or value.__qualname__ != node.name
            or value.__globals__ is not vars(runtime)
            or not _code_equal(value.__code__, _code_from(runtime_compiled, node.name))):
        raise AdmissionError("workload reviewed successor code mismatch")
    runtime_constants = _constants(runtime_tree, runtime.__file__)
    _check_defaults(value, runtime_nodes[0], runtime_constants, value.__code__.co_filename)
    _check_globals(value, runtime_tree, runtime_compiled, runtime_constants, runtime, root)


def _check_globals(fn: FunctionType, tree: ast.Module, compiled: CodeType, constants: dict, module: ModuleType, root: str | Path) -> None:
    imports: dict[str, tuple[str, str | None]] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports[alias.asname or alias.name.split(".")[0]] = (alias.name if alias.asname else alias.name.split(".")[0], None)
        elif isinstance(node, ast.ImportFrom):
            package = module.__package__ or module.__name__.rpartition(".")[0]
            source = importlib.util.resolve_name("." * node.level + (node.module or ""), package) if node.level else node.module
            for alias in node.names:
                if alias.name != "*":
                    imports[alias.asname or alias.name] = (source, alias.name)
    defs = {x.name for x in tree.body if isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
    for name in _globals_used(fn.__code__):
        if name not in fn.__globals__:
            if not hasattr(builtins, name):
                raise AdmissionError("unbound global: " + name)
            continue
        value = fn.__globals__[name]
        if name == "__name__":
            if value != module.__name__:
                raise AdmissionError("module name global mismatch")
        elif name == "__file__":
            relative = module.__name__.replace(".", "/") + ".py"
            if (type(value) is not str or value != module.__file__
                    or Path(value).resolve(strict=True) != _root_path(root, relative)):
                raise AdmissionError("module file global mismatch")
        elif name == "HOSTS" and module.__name__ == "peaso.collectors.gcp":
            if not _same(value, _expected_hosts(module, tree)):
                raise AdmissionError("dynamic HOSTS binding mismatch")
        elif name in constants:
            if not _same(value, constants[name]):
                raise AdmissionError("literal global mismatch: " + name)
        elif name in imports:
            modname, attr = imports[name]
            imported = sys.modules.get(modname)
            if type(value) is ModuleType and value.__name__ in {
                    "peaso.collectors.gcp_selected_object_secret_indicators",
                    "peaso.collectors.gcp_dataproc_referenced_source_secret_indicators",
                    "peaso.collectors.gcp_git_transport",
                    "peaso.collectors.gcp_git_content"}:
                if _alias_binding(module, name, root) is not value:
                    raise AdmissionError("import alias origin mismatch: " + name)
            elif imported is None or value is not (getattr(imported, attr, None) if attr else imported):
                raise AdmissionError("import binding mismatch: " + name)
            _check_helper_import(value, imported, attr, root)
        elif name in defs:
            expected = _code_from(compiled, name) if name != fn.__name__ else fn.__code__
            if type(value) is FunctionType:
                nodes = [x for x in tree.body if isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef)) and x.name == name]
                if len(nodes) != 1:
                    raise AdmissionError("same-module function ambiguity: " + name)
                if nodes[0].decorator_list:
                    if name == "private_native_logs":
                        _check_k8s_contextmanager(value, nodes[0], tree, compiled, constants, module, root)
                    else:
                        _check_private_read(value, name, tree, compiled, constants, module, root)
                else:
                    if (module.__name__ == "peaso.collectors.aws_workload_command_source_20261020"
                            and name == "reviewed_sources"
                            and (not _code_equal(value.__code__, expected)
                                 or value.__globals__ is not module.__dict__)):
                        _check_workload_reviewed_successor(value, nodes[0], tree, compiled,
                                                           constants, module, root)
                    else:
                        if not _code_equal(value.__code__, expected) or value.__globals__ is not module.__dict__:
                            raise AdmissionError("same-module function binding mismatch: " + name)
                        _check_defaults(value, nodes[0], constants, value.__code__.co_filename)
            elif isinstance(value, type):
                nodes = [x for x in tree.body if isinstance(x, ast.ClassDef) and x.name == name]
                if len(nodes) != 1:
                    raise AdmissionError("same-module class ambiguity: " + name)
                _check_class(value, nodes[0], compiled, module, constants, tree, root)
            else:
                raise AdmissionError("definition binding mismatch: " + name)
        else:
            try:
                alias = _alias_binding(module, name, root)
            except AdmissionError as exc:
                raise AdmissionError("unreviewed dynamic global: " + name) from exc
            if value is not alias:
                raise AdmissionError("alias global binding mismatch: " + name)


def trusted_definition(fn: FunctionType | MethodType, root: str | Path) -> dict:
    """Attest a changed top-level function or either reviewed transport request method."""
    bound = fn if type(fn) is MethodType else None
    if bound is not None:
        fn = bound.__func__
    if type(fn) is not FunctionType:
        raise AdmissionError("unsupported callable type")
    _, rows = _receipt()
    module = sys.modules.get(fn.__module__)
    if type(module) is not ModuleType or module.__dict__ is not fn.__globals__:
        raise AdmissionError("module binding mismatch")
    parts = fn.__qualname__.split(".")
    if len(parts) not in (1, 2) or "<locals>" in parts:
        raise AdmissionError("unreviewed callable qualname")
    file = getattr(module, "__file__", None)
    if not isinstance(file, str):
        raise AdmissionError("module has no file")
    base = Path(root).resolve(strict=True)
    try:
        relative = Path(file).resolve(strict=True).relative_to(base).as_posix()
    except ValueError as exc:
        raise AdmissionError("module outside root") from exc
    row = rows.get(relative)
    if row is None or module.__name__ != relative[:-3].replace("/", ".") or not relative.endswith(".py"):
        raise AdmissionError("unreviewed module")
    data, path = _live(root, relative, row)
    if Path(file).resolve(strict=True) != path or Path(fn.__code__.co_filename).resolve(strict=True) != path:
        raise AdmissionError("callable source location mismatch")
    tree = ast.parse(data, filename=str(path))
    compiled = _expected_helper_code(path, data, fn.__code__.co_filename)
    constants = _constants(tree, str(path))
    if len(parts) == 1:
        name = parts[0]
        if vars(module).get(name) is not fn or fn.__name__ != name or bound is not None:
            raise AdmissionError("top-level function identity mismatch")
        nodes = [x for x in tree.body if isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef)) and x.name == name]
        defs = [x for x in row["definitions"] if x["name"] == name]
        if len(nodes) != 1 or len(defs) != 1:
            raise AdmissionError("definition ambiguity")
        node, definition = nodes[0], defs[0]
        hashes = definition
        # One finite current successor; retained epoch definition witnesses do not change.
        successor_rosters = {
            "peaso/collectors/aws_selected_configuration_secret_indicators.py": {"collect_selected"},
            "peaso/collectors/gcp_configuration_secret_indicators.py": {"project_response"},
        }
        if name in successor_rosters.get(relative, ()):
            receipt, _ = _receipt()
            transition = receipt["current_reviewed_files"][relative]
            successors = transition.get("current_definitions")
            if successors is not None:
                if type(successors) is not dict or set(successors) != successor_rosters[relative]:
                    raise AdmissionError("reviewed definition successor roster changed")
                successor = successors[name]
                if (successor["predecessor_sha256"] != definition["after"]
                        or successor["predecessor_ast_sha256"] != definition["after_ast_sha256"]):
                    raise AdmissionError("reviewed definition predecessor witness changed")
                lines = data.splitlines(keepends=True)
                start = min([node.lineno] + [d.lineno for d in node.decorator_list])
                fragment = b"".join(lines[start - 1:node.end_lineno]).decode("utf-8")
                if (_sha(fragment.encode("utf-8")) != successor["current_sha256"]
                        or _ast_hash(node) != successor["current_ast_sha256"]):
                    raise AdmissionError("reviewed definition successor source changed")
                for before, after in successor["exact_replacements"]:
                    if fragment.count(after) != 1:
                        raise AdmissionError("reviewed definition replacement changed")
                    fragment = fragment.replace(after, before, 1)
                for addition in successor["exact_additions"]:
                    if fragment.count(addition) != 1:
                        raise AdmissionError("reviewed definition addition changed")
                    fragment = fragment.replace(addition, "", 1)
                previous = ast.parse(fragment)
                if (len(previous.body) != 1 or type(previous.body[0]) is not ast.FunctionDef
                        or previous.body[0].name != name
                        or _sha(fragment.encode("utf-8")) != definition["after"]
                        or _ast_hash(previous.body[0]) != definition["after_ast_sha256"]):
                    raise AdmissionError("reviewed definition predecessor changed")
                hashes = dict(definition, after=successor["current_sha256"],
                              after_ast_sha256=successor["current_ast_sha256"])
        expected_code = _code_from(compiled, name)
        _check_defaults(fn, node, constants, fn.__code__.co_filename)
    else:
        class_name, method_name = parts
        allowed = {("peaso/collectors/azure.py", "AzureTransport", "request"),
                   ("peaso/collectors/gcp.py", "Transport", "request")}
        if (relative, class_name, method_name) not in allowed or fn.__name__ != method_name:
            raise AdmissionError("unreviewed class method")
        owner = vars(module).get(class_name)
        if type(owner) is not type:
            raise AdmissionError("class owner missing")
        descriptor = vars(owner).get(method_name)
        actual_method = descriptor.__func__ if type(descriptor) is staticmethod else descriptor
        if actual_method is not fn or (bound is not None and type(bound.__self__) is not owner):
            raise AdmissionError("class method binding mismatch")
        classes = [x for x in tree.body if isinstance(x, ast.ClassDef) and x.name == class_name]
        defs = [x for x in row["definitions"] if x["name"] == class_name]
        if len(classes) != 1 or len(defs) != 1 or method_name not in defs[0].get("methods", {}):
            raise AdmissionError("reviewed class ambiguity")
        methods = [x for x in classes[0].body if isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef)) and x.name == method_name]
        if len(methods) != 1:
            raise AdmissionError("reviewed method ambiguity")
        node = methods[0]
        hashes = defs[0]["methods"][method_name]
        _check_class(owner, classes[0], compiled, module, constants, tree, root)
        expected_code = _code_from(_code_from(compiled, class_name), method_name)
    if _source_hash(data, node) != hashes["after"] or _ast_hash(node) != hashes["after_ast_sha256"]:
        raise AdmissionError("definition source mismatch")
    if not _code_equal(fn.__code__, expected_code):
        raise AdmissionError("compiled callable mismatch")
    _check_globals(fn, tree, compiled, constants, module, root)
    if (relative, fn.__qualname__) == (
            "peaso/collectors/gcp_configuration_secret_indicators.py", "project_response"):
        # The reviewed alias helper is reached through identity, one level below
        # the producer's direct globals. Reuse the existing live binding checks.
        _check_globals(vars(module)["identity"], tree, compiled, constants, module, root)
        _check_globals(vars(module)["number_alias"], tree, compiled, constants, module, root)
    qualifier = fn.__qualname__
    return {
        "current": {"path": relative, "name": qualifier, "module": module.__name__, "file_sha256": row["after_sha256"], "source_sha256": hashes["after"], "ast_sha256": hashes["after_ast_sha256"]},
        "historical": {"path": relative, "name": qualifier, "module": module.__name__, "file_sha256": row["before_sha256"], "source_sha256": hashes["before"], "ast_sha256": hashes["before_ast_sha256"]},
    }


def callable_projection(fn: FunctionType | MethodType, row: dict, root: str | Path) -> dict:
    """Project only an exact historical producer row after fresh live proof."""
    proof = trusted_definition(fn, root)
    old, new = proof["historical"], proof["current"]
    if type(row) is not dict:
        raise AdmissionError("foreign historical producer row")
    if row == old:
        return new
    keys = set(row)
    if keys == {"path", "sha256"} and row == {"path": old["path"], "sha256": old["source_sha256"]}:
        return {"path": new["path"], "sha256": new["source_sha256"]}
    required = {"qualname", "sha256"}
    optional = {"module", "path", "module_sha256", "defaults", "kwdefaults", "ast_sha256"}
    if not required <= keys or not keys <= required | optional or not ({"path", "module"} & keys):
        raise AdmissionError("foreign historical callable row shape")
    if (row["qualname"] != old["name"] or row["sha256"] != old["source_sha256"]
            or ("module" in row and row["module"] != old["module"])
            or ("path" in row and row["path"] != old["path"])
            or ("module_sha256" in row and row["module_sha256"] != old["file_sha256"])
            or ("ast_sha256" in row and row["ast_sha256"] != old["ast_sha256"])):
        raise AdmissionError("foreign historical callable row")
    old_defaults, old_kwdefaults = _historical_defaults(old["path"], old["name"])
    actual = fn.__func__ if type(fn) is MethodType else fn
    result = dict(row, sha256=new["source_sha256"])
    if "module_sha256" in result:
        result["module_sha256"] = new["file_sha256"]
    if "ast_sha256" in result:
        result["ast_sha256"] = new["ast_sha256"]
    for key, before, after in (("defaults", old_defaults, actual.__defaults__),
                               ("kwdefaults", old_kwdefaults, actual.__kwdefaults__)):
        if key not in row:
            continue
        if type(row[key]) is str:
            if row[key] != repr(before):
                raise AdmissionError("historical " + key + " repr mismatch")
            result[key] = repr(after)
        else:
            try:
                old_json = json.loads(json.dumps(before, sort_keys=True))
                new_json = json.loads(json.dumps(after, sort_keys=True))
            except (TypeError, ValueError) as exc:
                raise AdmissionError("nonportable " + key) from exc
            if not _same(row[key], old_json):
                raise AdmissionError("historical " + key + " JSON mismatch")
            result[key] = new_json
    return result


def _historical_defaults(relative: str, name: str) -> tuple[object, object]:
    archive = Path(__file__).with_name("private_secret_source_epoch_20261021.zip")
    if _sha(archive.read_bytes()) != _ARCHIVE_SHA256:
        raise AdmissionError("predecessor archive mismatch")
    with zipfile.ZipFile(archive) as z:
        data = z.read(relative)
    row = _receipt()[1][relative]
    if _sha(data) != row["before_sha256"]:
        raise AdmissionError("historical source mismatch")
    tree = ast.parse(data)
    parts = name.split(".")
    nodes = tree.body
    for index, part in enumerate(parts):
        kind = ast.ClassDef if index == 0 and len(parts) == 2 else (ast.FunctionDef, ast.AsyncFunctionDef)
        matches = [x for x in nodes if isinstance(x, kind) and x.name == part]
        if len(matches) != 1:
            raise AdmissionError("historical definition ambiguity")
        node = matches[0]
        nodes = node.body if isinstance(node, ast.ClassDef) else []
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        raise AdmissionError("historical callable missing")
    constants = _constants(tree, relative)
    defaults = tuple(_literal(x, constants, relative) for x in node.args.defaults)
    kw = {arg.arg: _literal(value, constants, relative) for arg, value in zip(node.args.kwonlyargs, node.args.kw_defaults) if value is not None}
    if any(isinstance(x, CodeType) for x in defaults) or any(isinstance(x, CodeType) for x in kw.values()):
        raise AdmissionError("historical callable default repr is unstable")
    return defaults or None, kw or None
