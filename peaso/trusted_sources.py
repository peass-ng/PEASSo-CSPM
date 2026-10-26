"""Skip pure source self-verification inside a trusted, CI-proven image.

The worker image is built only from a commit whose test suite and image build
ran every source proof with ``PEASO_SOURCE_ATTESTATION=always``; a tree that
fails a proof never becomes an image, and the image is immutable afterwards.
Re-proving the same bytes at every process start only spends CPU.

In ``trusted`` mode this module swaps, in place, the code of the listed
verifiers once their module has executed:

* a *pure* verifier (it only raises or returns ``None``) receives an empty
  body, so its pins, inverse-delta reconstructions, AST/compile comparisons
  and native-case replays never run;
* a verifier that also *returns* what the runtime needs receives a
  constructive-only body that loads the same reviewed artifacts and returns
  the same value without proving them.

Function objects keep their identity, globals, defaults and closure cells, so
every registry entry, alias and binding is the object an ``always`` run
produces.  Constructive work (executing reviewed source into callables,
registry construction) is untouched.  ``always`` and ``once`` never install
this hook, and tests compare the trusted registry and evaluations against
``always``.
"""
import importlib.abc
import importlib.machinery
import sys
import types

from peaso import source_attestation_mode as _mode


def _skip(*args, **kwargs):
    return None


# module -> qualnames whose body becomes ``_skip``.
PURE = {
    'peaso.checks.private_secret_shared_source_successor_20261021': (
        '_check_function', '_private_self', '_dataflow_gcp_delta', 'verify_metadata_only',
    ),
    'peaso.private_secret_source_epoch_20261021': ('_check_globals', '_check_helper_import', '_self'),
    'peaso.checks.azure_metadata_only_tde_admission_successor_20261020': ('_lineage',),
    'peaso.checks.k8s_selected_metadata_runtime_admission_20261020': ('_check_function',),
    'peaso.gcp_private_source_successor_20261021': ('_live_leaf',),
    'peaso.checks.gcp_private_workbench_head3_source_successor_20261021': ('_verify_runtime', '_private_self'),
    'peaso.checks.k8s_annotation_native_source_successor_20261021': ('_helper_proof', '_self_proof'),
}

# module -> {qualname: replacement function}; filled by ``_constructive``.
CONSTRUCTIVE = {}


def _constructive(module, qualname):
    def register(function):
        CONSTRUCTIVE.setdefault(module, {})[qualname] = function
        return function
    return register


# Constructive-only bodies.  Each runs with the *target* module's globals, so
# every free name below resolves in that module, exactly as the original body
# would; the signature is the original one so its defaults still apply.
# Pylint/flake8 cannot see those globals, hence the noqa markers.

@_constructive('peaso.gcp_private_source_successor_20261021', '_private_receipt')
def _gcp_private_receipt(root, source_requests=None):
    root = Path(root).resolve()  # noqa: F821
    receipt = json.loads((root / PRIVATE_RECEIPT).read_bytes())  # noqa: F821
    if source_requests is None:
        return receipt
    _, predecessors = private_source.predecessor_bundle(source_requests, root)  # noqa: F821
    return receipt, predecessors

_SKIP_CODE = _skip.__code__
_PATCHED = set()


def _resolve(module, qualname):
    target = module
    for part in qualname.split('.'):
        target = getattr(target, part)
    return target


def _swap(function, code):
    if (type(function) is not types.FunctionType or function.__code__.co_freevars
            or code.co_freevars):
        raise RuntimeError('trusted source swap target is not a plain function: '
                           + getattr(function, '__qualname__', repr(function)))
    function.__code__ = code


def patch(module):
    """Apply this module's trusted replacements once; return True if any."""
    name = module.__name__
    if name in _PATCHED or (name not in PURE and name not in CONSTRUCTIVE):
        return False
    _PATCHED.add(name)
    for qualname in PURE.get(name, ()):
        _swap(_resolve(module, qualname), _SKIP_CODE)
    for qualname, replacement in CONSTRUCTIVE.get(name, {}).items():
        _swap(_resolve(module, qualname), replacement.__code__)
    return True


class _Loader(importlib.machinery.SourceFileLoader):
    def exec_module(self, module):
        super().exec_module(module)
        patch(module)


class _Finder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname not in PURE and fullname not in CONSTRUCTIVE:
            return None
        spec = importlib.machinery.PathFinder.find_spec(fullname, path, target)
        if spec is not None and type(spec.loader) is importlib.machinery.SourceFileLoader:
            spec.loader = _Loader(spec.loader.name, spec.loader.path)
        return spec


_FINDER = _Finder()


def install():
    """Install the hook in trusted mode only; return True when installed."""
    if not _mode.TRUSTED or _FINDER in sys.meta_path:
        return False
    sys.meta_path.insert(0, _FINDER)
    for name in tuple(PURE) + tuple(CONSTRUCTIVE):
        module = sys.modules.get(name)
        if module is not None:
            patch(module)
    return True


@_constructive('peaso.checks.gcp_private_workbench_head3_source_successor_20261021', 'reviewed_inputs')
def _workbench_head3_reviewed_inputs(root=None, *, verify_cases=True):
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()  # noqa: F821
    receipt = json.loads((root / 'peaso/checks' / original.RECEIPT).read_bytes())  # noqa: F821
    return receipt, json.loads((root / receipt['cases_path']).read_bytes())  # noqa: F821


def _patch_private(module):
    """Apply the table to a private namespace executed from reviewed source."""
    sys.modules['peaso.trusted_sources'].patch(module)


# Kubernetes annotation, kubelet and selected-log successors execute exact
# copies of historical guards in private namespaces and then run their
# installers.  Trusted mode keeps the copies, the registrations, the closure
# rewrites and the CASES writes; it skips the source/shape proofs around them.
_K8S_ANNOTATION = 'peaso.checks.k8s_annotation_native_source_successor_20261021'
_K8S_ANNOTATION_NS = 'peaso.checks._k8s_annotation_native_source_successor_20261021_namespace'
_K8S_KUBELET = 'peaso.checks.k8s_kubelet_configmap_source_successor_20261021'
_K8S_KUBELET_NS = 'peaso.checks._k8s_kubelet_configmap_source_successor_20261021_namespace'
_K8S_LOG = 'peaso.checks.k8s_selected_log_source_successor_20261021'
_K8S_LOG_NS = 'peaso.checks._k8s_selected_log_source_successor_20261021_namespace'
PURE[_K8S_KUBELET_NS] = ('_verify',)
PURE[_K8S_LOG_NS] = ('_verify',)


@_constructive(_K8S_ANNOTATION, '_namespace')
def _k8s_annotation_namespace():
    if _PRIVATE_NAME in sys.modules:  # noqa: F821
        raise RuntimeError('Historical annotation private namespace already occupied')
    module = types.ModuleType(_PRIVATE_NAME)  # noqa: F821
    module.__file__ = str(GUARD)  # noqa: F821
    module.__package__ = 'peaso.checks'
    sys.modules[_PRIVATE_NAME] = module  # noqa: F821
    try:
        exec(compile(GUARD.read_bytes(), str(GUARD), 'exec'), vars(module))  # noqa: F821
        sys.modules['peaso.trusted_sources']._patch_private(module)  # noqa: F821
        return module
    except BaseException:
        sys.modules.pop(_PRIVATE_NAME, None)  # noqa: F821
        raise


@_constructive(_K8S_ANNOTATION, 'install')
def _k8s_annotation_install():
    namespace = _namespace()  # noqa: F821
    try:
        namespace.install()
    except BaseException:
        sys.modules.pop(_PRIVATE_NAME, None)  # noqa: F821
        raise
    return namespace


@_constructive(_K8S_ANNOTATION_NS, '_reviewed_inputs')
def _k8s_annotation_ns_reviewed_inputs():
    root = Path(__file__).resolve().parents[2]  # noqa: F821
    receipt = _source_receipt()  # noqa: F821
    path = (root / receipt['fixtures']['path']).resolve()
    return receipt, json.loads(path.read_text(), object_pairs_hook=_pairs)  # noqa: F821


@_constructive(_K8S_ANNOTATION_NS, 'install')
def _k8s_annotation_ns_install():
    from . import CHECKS
    from . import k8s_annotation_indicators_review_20261020 as candidate
    selected = {}
    for cid in IDS:  # noqa: F821
        matches = [c for c in CHECKS if c.id == cid]
        if len(matches) != 1:
            raise RuntimeError('Annotation predecessor absent or duplicated')
        selected[cid] = matches[0]
    updates = {cid: _successor(check, candidate) for cid, check in selected.items()  # noqa: F821
               if getattr(check.evaluate, MARK, None) is None}  # noqa: F821
    CHECKS[:] = [updates.get(c.id, c) for c in CHECKS]
    _PREDECESSORS.update({cid: old for cid, old in selected.items() if cid in updates})  # noqa: F821


@_constructive(_K8S_KUBELET, '_clone_guard')
def _k8s_kubelet_clone_guard():
    if PRIVATE_NAME in sys.modules:  # noqa: F821
        raise RuntimeError('Kubelet private namespace already occupied')
    module = types.ModuleType(PRIVATE_NAME)  # noqa: F821
    module.__file__ = str(GUARD)  # noqa: F821
    module.__package__ = 'peaso.checks'
    sys.modules[PRIVATE_NAME] = module  # noqa: F821
    try:
        exec(compile(GUARD.read_bytes(), str(GUARD), 'exec'), vars(module))  # noqa: F821
        sys.modules['peaso.trusted_sources']._patch_private(module)  # noqa: F821
        return module
    except BaseException:
        sys.modules.pop(PRIVATE_NAME, None)  # noqa: F821
        raise


@_constructive(_K8S_KUBELET, 'install')
def _k8s_kubelet_install():
    predecessor = sys.modules.get(annotation_successor._PRIVATE_NAME)  # noqa: F821
    if not isinstance(predecessor, types.ModuleType):  # noqa: F821
        raise RuntimeError('Kubelet annotation predecessor proof absent')
    clone = _clone_guard()  # noqa: F821
    clone.proof = predecessor
    try:
        clone.install()
    except BaseException:
        sys.modules.pop(PRIVATE_NAME, None)  # noqa: F821
        raise
    return clone


@_constructive(_K8S_KUBELET_NS, 'reviewed_inputs')
def _k8s_kubelet_ns_reviewed_inputs():
    root = Path(__file__).resolve().parents[2]  # noqa: F821
    receipt = json.loads(Path(__file__).with_name(RECEIPT).read_text(), object_pairs_hook=proof._pairs)  # noqa: F821
    path = (root / receipt['fixture']['path']).resolve()
    return receipt, json.loads(path.read_text(), object_pairs_hook=proof._pairs), {}  # noqa: F821


@_constructive(_K8S_LOG, 'install')
def _k8s_log_install():
    predecessor = sys.modules.get(annotation_successor._PRIVATE_NAME)  # noqa: F821
    if not isinstance(predecessor, types.ModuleType):  # noqa: F821
        raise RuntimeError('Selected log annotation predecessor absent')
    if PRIVATE_NAME in sys.modules:  # noqa: F821
        raise RuntimeError('Selected log private namespace occupied')
    clone = types.ModuleType(PRIVATE_NAME)  # noqa: F821
    clone.__file__ = str(GUARD)  # noqa: F821
    clone.__package__ = 'peaso.checks'
    sys.modules[PRIVATE_NAME] = clone  # noqa: F821
    try:
        exec(compile(GUARD.read_bytes(), str(GUARD), 'exec'), vars(clone))  # noqa: F821
        sys.modules['peaso.trusted_sources']._patch_private(clone)  # noqa: F821
        clone.proof = predecessor
        clone.install()
    except BaseException:
        sys.modules.pop(PRIVATE_NAME, None)  # noqa: F821
        raise
    return clone


@_constructive(_K8S_LOG_NS, 'reviewed_inputs')
def _k8s_log_ns_reviewed_inputs():
    receipt = json.loads(Path(__file__).with_name(RECEIPT).read_text(), object_pairs_hook=proof._pairs)  # noqa: F821
    cases = json.loads(Path(__file__).with_name(CASES_FILE).read_text(), object_pairs_hook=proof._pairs)  # noqa: F821
    return receipt, cases, {}
