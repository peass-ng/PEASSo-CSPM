"""Exact Azure-package successor over accepted CodeBuild/WB/DF/K8s guards."""
from copy import deepcopy
import ast
import gzip
import hashlib
import inspect
import json
from pathlib import Path
import re
import types
import textwrap
from . import aws_codebuild_buildspec_shared_successor_20261020 as predecessor
original = predecessor.original
PREDECESSOR_REVIEWED_INPUTS = predecessor.PREDECESSOR_REVIEWED_INPUTS
RECEIPT = 'azure_function_package_shared_successor_20261020.json'
RECEIPT_SHA256 = '9bd4b45c79ae86af77ee58853bfe05692d5cf244a11c916756906f281e5f1c99'


def _self(raw):
    result, count = re.subn(rb"(?m)^RECEIPT_SHA256 = '[0-9a-f]{64}'$", b"RECEIPT_SHA256 = '" + b'0' * 64 + b"'", raw)
    if count != 1:
        raise RuntimeError('Azure package shared successor self changed')
    return result


def reviewed_delta(root=None):
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('Azure package shared successor receipt changed')
    receipt = json.loads(raw)
    accepted = predecessor.reviewed_delta(root)
    if receipt['accepted_receipt_sha256'] != predecessor.RECEIPT_SHA256:
        raise RuntimeError('Azure package shared predecessor changed')
    archive = json.loads(gzip.decompress((root / receipt['archive']).read_bytes()))
    for name, row in archive['files'].items():
        old = bytes.fromhex(row['hex'])
        if hashlib.sha256(old).hexdigest() != row['sha256']:
            raise RuntimeError('CodeBuild exact predecessor archive changed')
        if name.startswith('peaso/checks/') and not name.endswith('/__init__.py'):
            if (root / name).read_bytes() != old:
                raise RuntimeError('Azure package historical guard bytes changed')
    for name, digest in receipt['sources'].items():
        path = (root / name).resolve(); data = path.read_bytes()
        if name == receipt['helper_path']:
            data = _self(data)
        if not path.is_relative_to(root / 'peaso') or hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError('Azure package shared source changed')
    if set(receipt['shared_functions']) != set(accepted['shared_functions']):
        raise RuntimeError('Azure package shared function set changed')
    check_additions(root, receipt)
    compiled = {}
    for name, row in receipt['successor_functions'].items():
        if globals().get(name) is not _FUNCTIONS[name]:
            raise RuntimeError('Azure package shared callable replaced')
        original._check_function(_FUNCTIONS[name], row, root, compiled)
    from . import azure_function_package_tde_successor_20261020 as tde
    for name, row in receipt['tde_functions'].items():
        if getattr(tde, name) is not tde._FUNCTIONS[name]:
            raise RuntimeError('Azure package TDE successor callable replaced')
        original._check_function(getattr(tde, name), row, root, compiled)
    from . import azure_function_package_head3_entrypoint_20261020 as entrypoint
    for name, row in receipt['entrypoint_functions'].items():
        if getattr(entrypoint, name) is not entrypoint._FUNCTIONS[name]:
            raise RuntimeError('HEAD3 entrypoint callable replaced')
        original._check_function(getattr(entrypoint, name), row, root, compiled)
    entrypoint.reviewed_entrypoint(root)
    return receipt


def check_additions(root, receipt):
    """Every changed shared file restores byte-for-byte to the accepted epoch."""
    for name, row in receipt['file_deltas'].items():
        raw = (root / name).read_text()
        for before, after in row.get('exact_replacements', []):
            if raw.count(after) != 1:
                raise RuntimeError('Azure package entrypoint replacement changed')
            raw = raw.replace(after, before, 1)
        for addition in row['exact_additions']:
            if raw.count(addition) != 1:
                raise RuntimeError('Azure package exact file addition changed')
            raw = raw.replace(addition, '', 1)
        if hashlib.sha256(raw.encode()).hexdigest() != row['predecessor_sha256']:
            raise RuntimeError('Azure package non-admitted source changed')


def check_aws(function, expected):
    return predecessor.check_aws(function, expected)


def check_shared(fn, historical, name, root, compiled, receipt):
    row = receipt['shared_functions'][name]
    restored = inspect.getsource(inspect.unwrap(fn))
    layers = (receipt, predecessor.reviewed_delta(root),
              predecessor.predecessor.reviewed_delta(root),
              predecessor.predecessor.predecessor.reviewed_delta(root))
    for layer in layers:
        binding = layer['shared_functions'][name]
        if hashlib.sha256(restored.encode()).hexdigest() != binding['current_sha256']:
            raise RuntimeError('Azure package predecessor executing source changed')
        for addition in binding['exact_additions']:
            if restored.count(addition) != 1:
                raise RuntimeError('Azure package inherited exact addition changed')
            restored = restored.replace(addition, '', 1)
        if hashlib.sha256(restored.encode()).hexdigest() != binding.get('predecessor_sha256', binding.get('predecessor', {}).get('sha256')):
            raise RuntimeError('Azure package inherited predecessor changed')
    if hashlib.sha256(restored.encode()).hexdigest() != historical['sha256']:
        raise RuntimeError('Azure package original callable source changed')
    original._check_function(fn, dict(historical, sha256=row['current_sha256']), root, compiled)


def prepared_inputs(root, compiled, successor):
    return predecessor.prepared_inputs(root, compiled, predecessor.reviewed_delta(root))


def reviewed_inputs(root=None):
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    successor = reviewed_delta(root)
    raw = (root / 'peaso/checks' / original.RECEIPT).read_bytes()
    if original.prepared._hash(raw) != original.RECEIPT_SHA256:
        raise RuntimeError('metadata runtime receipt changed')
    receipt = json.loads(raw, object_pairs_hook=original.proof._pairs)
    compiled = {}
    runtime = original.runtime
    if (receipt['check'] != original.CHECK or runtime.CHECK != original.CHECK
            or runtime.KIND != original.prepared.producer.KIND or runtime.OPTION != original.prepared.producer.OPTION
            or runtime.GRANT != '_k8s_selected_metadata_grant'
            or json.dumps(receipt['declaration'], sort_keys=True) != json.dumps(original.candidate.DECLARATION, sort_keys=True)
            or runtime._Grant is not original._GRANT_CLASS or runtime._TOKEN is not original._TOKEN
            or runtime.source is not original.prepared.producer or original.candidate is not original.prepared.candidate
            or original.k8s.TYPES.count(runtime.KIND) != 1 or runtime.KIND in original.k8s.ENDPOINTS
            or runtime.KIND not in original.engine.BULK_STREAM_TYPES['k8s'] or runtime.OPTION not in original.validation.OPTIONS):
        raise RuntimeError('metadata runtime metadata/binding changed')
    for name, expected in receipt['sources'].items():
        path = (root / name).resolve()
        raw = path.read_bytes()
        if name == receipt['helper_path']:
            raw = original._self(raw)
        if not path.is_relative_to(root) or original.prepared._hash(raw) != expected:
            raise RuntimeError('metadata runtime source changed')
    for row in receipt['fixtures']:
        path = (root / row['path']).resolve()
        if not path.is_relative_to(root / 'peaso/checks') or original.prepared._hash(path.read_bytes()) != row['sha256']:
            raise RuntimeError('metadata packaged runtime fixture changed')
    prepared_inputs(root, compiled, successor)
    current = original._runtime()
    alias = original.__name__ + ':reviewed_inputs'
    if original.reviewed_inputs is reviewed_inputs:
        if alias in current:
            raise RuntimeError('metadata runtime successor alias changed')
        current[alias] = PREDECESSOR_REVIEWED_INPUTS
    elif original.reviewed_inputs not in (PREDECESSOR_REVIEWED_INPUTS, predecessor.reviewed_inputs, predecessor.predecessor.reviewed_inputs):
        raise RuntimeError('metadata runtime successor alias replaced')
    if set(current) != set(original._ORIGINALS) or set(current) != set(receipt['functions']):
        raise RuntimeError('metadata runtime callable set changed')
    for name, fn in current.items():
        if fn is not original._ORIGINALS[name]:
            raise RuntimeError('metadata runtime callable replacement')
        if name in successor['shared_functions']:
            check_shared(fn, receipt['functions'][name], name, root, compiled, successor)
        else:
            original._check_function(fn, receipt['functions'][name], root, compiled)
    cases = json.loads((root / 'peaso/checks' / original.CASES).read_bytes(), object_pairs_hook=original.proof._pairs)
    if set(cases) != {original.CHECK}:
        raise RuntimeError('metadata runtime CASES changed')
    for branch in ('pass', 'fail', 'unknown'):
        if original.candidate.evaluate(deepcopy(cases[original.CHECK][branch]), deepcopy(cases[original.CHECK][branch + '_index']))[0] != branch.upper():
            raise RuntimeError('metadata runtime native witness changed')
    return receipt, cases, deepcopy(original.candidate.DECLARATION), original.candidate.evaluate


def install():
    from . import CHECKS, CHECK_ALIASES, register
    from .fixtures import CASES as store
    receipt, cases, declaration, function = reviewed_inputs()
    # The immutable authorize/collect functions import this original module path.
    # Route only its reviewed-input entrypoint; the historical object is retained
    # and attested separately, while this actual successor source is self-pinned.
    original.reviewed_inputs = reviewed_inputs
    ident = original.CHECK
    if ident in CHECK_ALIASES or ident in CHECK_ALIASES.values():
        raise RuntimeError('metadata runtime alias collision')
    found = [check for check in CHECKS if check.id == ident]
    if found:
        if len(found) != 1 or not original._INSTALLED:
            raise RuntimeError('metadata runtime collision')
        original._verify(found[0], receipt)
        if json.dumps(store.get(ident), sort_keys=True) != json.dumps(cases[ident], sort_keys=True):
            raise RuntimeError('metadata runtime CASES replacement')
        return
    if ident in store:
        raise RuntimeError('metadata runtime CASES collision')
    before = tuple(CHECKS)
    try:
        register(ident, 'k8s', declaration['category'], original.runtime.KIND, declaration['title'], declaration['severity'],
                 'security_configuration', declaration['remediation'], dependencies=[original.runtime.KIND], allow_incomplete_failure=True)(function)
        check = CHECKS[-1]
        setattr(check.evaluate, original.MARK, ident)
        original._verify(check, receipt)
        store[ident] = deepcopy(cases[ident])
        original._INSTALLED = (check.evaluate, original.proof._bindings(check.evaluate)['checked'])
    except Exception:
        CHECKS[:] = before
        store.pop(ident, None)
        raise


def install_dataflow(admission):
    """Only reviewed shared admission alias changes; its 119 functions stay exact."""
    receipt = reviewed_delta()
    if admission.shared not in (predecessor.predecessor, predecessor, __import__(__name__, fromlist=[''])):
        raise RuntimeError('CodeBuild Dataflow shared alias replaced')
    old = admission.shared
    admission.shared = __import__(__name__, fromlist=[''])
    try:
        admission.install()
    except Exception:
        admission.shared = old
        raise


def install_bundle():
    """Preflight before registry/alias mutation, then roll back this whole wave."""
    from . import CHECKS
    from .fixtures import CASES
    from . import gcp_workbench_source_runtime_admission_20261020 as workbench
    from . import gcp_dataflow_batch_source_runtime_admission_20261020 as dataflow
    from . import aws_codebuild_buildspec_runtime_admission_20261020 as codebuild
    from . import azure_function_package_integration_admission_20261020 as package
    from . import azure_function_package_tde_successor_20261020 as tde
    from . import gcp_function_secret_page_admission_20261020 as function_pairs
    # This validation has no registry or shared-alias writes.
    package.reviewed_inputs()
    codebuild.reviewed_inputs()
    tde.reviewed_inputs()
    function_pairs.reviewed_inputs()
    ids = {original.CHECK, *workbench.CHECK_IDS, *dataflow.runtime.CHECKS, codebuild.runtime.CHECK, package.runtime.CHECK, *tde.IDS, function_pairs.original.CHECK_ID}
    before = tuple(CHECKS)
    old_cases = {ident: CASES[ident] for ident in ids if ident in CASES}
    old_reviewed, old_installed, old_shared = original.reviewed_inputs, original._INSTALLED, dataflow.shared
    old_package, old_tde = package._INSTALLED, dict(tde.original._INSTALLED)
    try:
        tde.install()
        install()
        workbench.install()
        install_dataflow(dataflow)
        codebuild.install()
        package.install()
        function_pairs.install()
    except Exception:
        CHECKS[:] = before
        for ident in ids:
            if ident in old_cases:
                CASES[ident] = old_cases[ident]
            else:
                CASES.pop(ident, None)
        original.reviewed_inputs, original._INSTALLED, dataflow.shared = old_reviewed, old_installed, old_shared
        package._INSTALLED = old_package
        tde.original._INSTALLED.clear()
        tde.original._INSTALLED.update(old_tde)
        raise

_FUNCTIONS = {name: fn for name, fn in tuple(globals().items()) if isinstance(fn, types.FunctionType) and fn.__globals__ is globals()}
