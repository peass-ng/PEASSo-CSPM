"""Review-only network inventory delta proof; no imports of the live registry.

No predecessor reads are redirected and no receipt is replaced. Executable as
a standalone file so a blocked package can still be diagnosed without a bypass.
"""
import ast
from copy import deepcopy
import hashlib
import gzip
import importlib.util
import inspect
import json
from pathlib import Path
import re
import sys
import types

RECEIPT = 'peaso/checks/k8s_network_inventory_successor_20261020.json'
RECEIPT_SHA256 = '1a2fdf5f809a3821718a0ba9e0ffb1259b59fd9fbf9086c1994ea41f5eb64cf1'
OLD_JSON = 'peaso/collectors/k8s_network_extensions.json'
NEW_JSON = 'peaso/collectors/k8s_network_route_extensions.json'
NETWORK = 'peaso/collectors/k8s_network_extensions.py'
WORKBENCH = 'peaso/checks/gcp_workbench_shared_hook_successor_20261020.json'
COMBINED = 'peaso/checks/gcp_dataflow_batch_source_runtime_admission_20261020.json'
OLD_SHA256 = '0f4edb682316e4f0c0059af146f14bb6ee819cb03a0677e09825a26c945e615d'
BUNDLE = 'peaso/checks/k8s_network_inventory_successor_20261020_candidates.json.gz'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pairs(rows):
    result = {}
    for key, value in rows:
        if key in result:
            raise ValueError('duplicate_json_key')
        result[key] = value
    return result


def read_json(raw):
    if not isinstance(raw, bytes) or len(raw) > 4 * 1024 * 1024:
        raise ValueError('json_bound')
    return json.loads(raw, object_pairs_hook=pairs)


def under(root, name):
    path = (root / name).resolve()
    if not path.is_relative_to(root) or not name.startswith(('peaso/', 'tests/', 'docs/check-review/')):
        raise ValueError('source_path')
    return path


def normalized_self(raw):
    result, count = re.subn(rb"(?m)^(RECEIPT_SHA256\s*=\s*)'[0-9a-f]{64}'$",
        lambda m: m[1] + b"'" + b'0' * 64 + b"'", raw)
    if count != 1:
        raise ValueError('self_binding')
    return result


def receipt(root):
    raw = under(root, RECEIPT).read_bytes()
    if digest(raw) != RECEIPT_SHA256:
        raise ValueError('proposal_receipt')
    reviewed = read_json(raw)
    for name, row in reviewed['sources'].items():
        raw = under(root, name).read_bytes()
        if row['normalization'] == 'receipt_self':
            raw = normalized_self(raw)
        elif row['normalization'] != 'none':
            raise ValueError('source_normalization')
        if digest(raw) != row['sha256']:
            raise ValueError('proposal_source:' + name)
    return reviewed


def exact_old_json(root, reviewed):
    """Reconstruct bytes only if the original sealed byte digest is reproduced."""
    accepted = read_json(under(root, WORKBENCH).read_bytes())
    old = (json.dumps(accepted['network_resources'], sort_keys=True, indent=2) + '\n').encode()
    if (digest(old) != OLD_SHA256 or accepted['sources'][OLD_JSON] != OLD_SHA256
            or digest(old) != reviewed['old_json_sha256']):
        raise ValueError('unproven_predecessor_bytes')
    return old


def endpoints(resources):
    if not isinstance(resources, dict) or not resources or len(resources) > 128:
        raise ValueError('resource_shape')
    result = {}
    for kind, row in resources.items():
        if (not isinstance(kind, str) or not re.fullmatch('[a-z][a-z0-9_]{1,79}', kind)
                or not isinstance(row, list) or len(row) != 3 or not isinstance(row[0], list)
                or not 1 <= len(row[0]) <= 4 or len(set(row[0])) != len(row[0])
                or any(not isinstance(g, str) or not re.fullmatch('[a-z0-9]+(?:[.-][a-z0-9]+)*', g) for g in row[0])
                or not isinstance(row[1], str) or not re.fullmatch('[a-z][a-z0-9-]{0,79}', row[1])
                or type(row[2]) is not bool):
            raise ValueError('resource_shape')
        for group in row[0]:
            key = (group, row[1])
            if key in result:
                raise ValueError('duplicate_endpoint')
            result[key] = kind
    return result


def native_kinds(root, reviewed):
    path = under(root, 'peaso/collectors/k8s_literal_secret_indicators.py')
    tree = ast.parse(path.read_bytes())
    assignments = [n for n in tree.body if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == 'NATIVE_KINDS' for t in n.targets)]
    if len(assignments) != 1:
        raise ValueError('native_kind_source')
    kinds = ast.literal_eval(assignments[0].value)
    canonical = json.loads(json.dumps(kinds))
    metadata = read_json(under(root, 'peaso/checks/k8s_selected_metadata_secret_admission_20261020.json').read_bytes())
    if canonical != metadata['schema']['kinds'] or canonical != reviewed['selected_native_kinds']:
        raise ValueError('selected_native_kinds')
    return kinds


def assert_disjoint(resources, kinds):
    """Universal group/plural argument, then witnesses for each route shape.

    The pinned matcher is /apis/G/v1[/namespaces/N]/P with fullmatch. Core
    /api routes, named GET suffixes and log suffixes cannot match that grammar.
    For namespaced/all-namespace lists, exact (group, plural) disjointness covers
    every valid namespace; the supported selected kinds use core/apps/batch.
    """
    route_map = endpoints(resources)
    protected = set()
    witnesses = []
    for kind, (version, plural, _) in kinds.items():
        prefix = '/api/v1' if version == 'v1' else '/apis/' + version
        if version != 'v1':
            group, version_name = version.split('/')
            if version_name == 'v1':
                protected.add((group, plural))
        witnesses.extend((prefix + '/' + plural,
            prefix + '/' + plural + '/selected-name',
            prefix + '/namespaces/review/' + plural,
            prefix + '/namespaces/review/' + plural + '/selected-name'))
    witnesses.append('/api/v1/namespaces/review/pods/selected-name/log')
    if set(route_map) & protected:
        raise ValueError('selected_route_overlap')
    return witnesses


def validate_delta(old_raw, new_raw, reviewed, kinds):
    """No generic additive acceptance: only exact approved bytes/entries pass."""
    if digest(old_raw) != OLD_SHA256 or digest(new_raw) != reviewed['new_json_sha256']:
        raise ValueError('network_json_digest')
    old, additions = read_json(old_raw), read_json(new_raw)
    if old != reviewed['old_resources'] or additions != reviewed['approved_additions']:
        raise ValueError('network_exact_entries')
    if set(old) & set(additions):
        raise ValueError('changed_existing_kind')
    old_routes, new_routes = endpoints(old), endpoints(additions)
    if set(old_routes) & set(new_routes):
        raise ValueError('shadowed_existing_endpoint')
    merged = dict(old, **additions)
    routes = assert_disjoint(merged, kinds)
    return merged, routes


def definitions(raw):
    text = raw.decode('utf-8')
    lines = text.splitlines(keepends=True)
    result = {}
    def visit(node, prefix=''):
        for child in ast.iter_child_nodes(node):
            next_prefix = prefix
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = prefix + child.name
                if not isinstance(child, ast.ClassDef):
                    start = min([child.lineno] + [d.lineno for d in child.decorator_list])
                    if name in result:
                        raise ValueError('ambiguous_source_definition')
                    result[name] = ''.join(lines[start - 1:child.end_lineno]).encode()
                next_prefix = name + ('.' if isinstance(child, ast.ClassDef) else '.<locals>.')
            visit(child, next_prefix)
    visit(ast.parse(text))
    return result


def code_shape(value):
    if isinstance(value, types.CodeType):
        return (value.co_code, tuple(code_shape(x) for x in value.co_consts), value.co_names,
                value.co_varnames, value.co_freevars, value.co_cellvars,
                value.co_argcount, value.co_posonlyargcount, value.co_kwonlyargcount,
                value.co_flags, value.co_stacksize, getattr(value, 'co_exceptiontable', b''))
    if isinstance(value, tuple):
        return tuple(code_shape(x) for x in value)
    if isinstance(value, frozenset):
        return frozenset(code_shape(x) for x in value)
    return value


def compiled_definition(raw, qualname, filename):
    matches = []
    def visit(code, prefix=''):
        for child in code.co_consts:
            if isinstance(child, types.CodeType):
                name = prefix + child.co_name
                if name == qualname:
                    matches.append(child)
                # Class definitions do not have CO_NEWLOCALS; functions do.
                suffix = '.<locals>.' if child.co_flags & inspect.CO_NEWLOCALS else '.'
                visit(child, name + suffix)
    visit(compile(raw, filename, 'exec', dont_inherit=True, optimize=sys.flags.optimize))
    if len(matches) != 1:
        raise ValueError('compiled_definition')
    return matches[0]


def executing(function, row, namespace, root, original=None):
    """Check real in-memory code, globals/defaults and optional original identity."""
    native = inspect.unwrap(function)
    raw = under(root, row['path']).read_bytes()
    expected = definitions(raw).get(row['qualname'])
    if (not isinstance(native, types.FunctionType) or native.__globals__ is not vars(namespace)
            or native.__module__ != namespace.__name__ or original is not None and function is not original
            or expected is None or digest(expected) != row['sha256']
            or digest(inspect.getsource(native).encode()) != row['sha256']
            or code_shape(native.__code__) != code_shape(compiled_definition(raw, row['qualname'], str(under(root, row['path']))))
            or json.dumps(native.__defaults__, sort_keys=True) != json.dumps(row['defaults'], sort_keys=True)
            or json.dumps(native.__kwdefaults__, sort_keys=True) != json.dumps(row['kwdefaults'], sort_keys=True)):
        raise ValueError('executing_binding')


def static_runtime119(root, reviewed):
    accepted = read_json(under(root, COMBINED).read_bytes())
    functions = accepted['runtime_functions']
    if len(functions) != 119 or functions != reviewed['runtime119']:
        raise ValueError('runtime119_manifest')
    by_path = {}
    for name, row in functions.items():
        if row['path'] not in by_path:
            by_path[row['path']] = definitions(under(root, row['path']).read_bytes())
        raw = by_path[row['path']].get(row['qualname'])
        if raw is None or digest(raw) != row['sha256']:
            raise ValueError('runtime119_source:' + name)
        compiled_definition(under(root, row['path']).read_bytes(), row['qualname'], row['path'])
    return len(functions)


def load_network(root):
    """Load the actual stdlib-only inventory file without executing registry init."""
    spec = importlib.util.spec_from_file_location('_review_actual_k8s_network_inventory', under(root, NETWORK))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def replace_receipt_constant(raw, expected_old, new):
    old_line = b"RECEIPT_SHA256 = '" + expected_old.encode() + b"'"
    new_line = b"RECEIPT_SHA256 = '" + new.encode() + b"'"
    if raw.count(old_line) != 1:
        raise ValueError('predecessor_receipt_constant')
    return raw.replace(old_line, new_line, 1)


def proposed_files(predecessors, reviewed):
    """Concrete metadata-only successor; no write or install operation exists."""
    wb_path = WORKBENCH
    wb_helper = wb_path[:-5] + '.py'
    df_path = 'peaso/checks/gcp_dataflow_batch_shared_hook_successor_20261020.json'
    df_helper = df_path[:-5] + '.py'
    wb = read_json(predecessors[wb_path])
    wb['sources'][NETWORK] = reviewed['network_source_sha256']
    wb['sources'][NEW_JSON] = reviewed['new_json_sha256']
    wb['network_resources'] = dict(reviewed['old_resources'], **reviewed['approved_additions'])
    wb['network_map_contract'] = reviewed['proposed_map_contract']
    wb_bytes = (json.dumps(wb, indent=2) + '\n').encode()
    df = read_json(predecessors[df_path])
    df['accepted_receipt_sha256'] = digest(wb_bytes)
    df_bytes = (json.dumps(df, indent=2) + '\n').encode()
    return {wb_path: wb_bytes, df_path: df_bytes,
        wb_helper: replace_receipt_constant(predecessors[wb_helper], digest(predecessors[wb_path]), digest(wb_bytes)),
        df_helper: replace_receipt_constant(predecessors[df_helper], digest(predecessors[df_path]), digest(df_bytes))}


def validate_candidates(bundle, reviewed):
    expected_paths = set(reviewed['proposed_existing_edits'])
    if set(bundle['predecessors']) != expected_paths or set(bundle['candidates']) != expected_paths:
        raise ValueError('candidate_file_set')
    predecessors = {}
    for name, row in bundle['predecessors'].items():
        raw = bytes.fromhex(row['hex'])
        if digest(raw) != row['sha256'] or digest(raw) != reviewed['predecessor_hashes'][name]:
            raise ValueError('candidate_predecessor')
        predecessors[name] = raw
    expected = proposed_files(predecessors, reviewed)
    for name, row in bundle['candidates'].items():
        raw = bytes.fromhex(row['hex'])
        if digest(raw) != row['sha256'] or raw != expected[name]:
            raise ValueError('candidate_unapproved_delta')
        if name.endswith('.py'):
            if normalized_self(raw) != normalized_self(predecessors[name]) or definitions(raw) != definitions(predecessors[name]):
                raise ValueError('candidate_changed_function')
    return {'existing_files_proposed': len(expected_paths), 'changed_function_definitions': 0,
            'registry_edits': 0, 'dataflow_runtime_receipt_edits': 0}


def candidate_applicable(root, reviewed):
    """Historical merged-map candidate MUST reject the now-isolated router."""
    if digest(under(root, NETWORK).read_bytes()) != reviewed['network_source_sha256']:
        raise ValueError('stale_network_candidate')
    return True


def validate(root=None, network=None):
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    reviewed = receipt(root)
    old = exact_old_json(root, reviewed)
    if under(root, OLD_JSON).read_bytes() != old:
        raise ValueError('original_json_not_preserved')
    kinds = native_kinds(root, reviewed)
    merged, routes = validate_delta(old, under(root, NEW_JSON).read_bytes(), reviewed, kinds)
    module = load_network(root) if network is None else network
    matcher = read_json(under(root, WORKBENCH).read_bytes())['network_matcher']
    executing(module.match, matcher, module, root)
    if (module.re is not re or module.RESOURCES != reviewed['old_resources']
            or module.BY_ENDPOINT != endpoints(reviewed['old_resources'])):
        raise ValueError('network_runtime_metadata')
    for path in routes:
        if module.match(path) is not None:
            raise ValueError('selected_route_overlap')
    for kind, (groups, plural, namespaced) in reviewed['approved_additions'].items():
        for group in groups:
            for prefix in ('/apis/' + group + '/v1/', '/apis/' + group + '/v1/namespaces/review/'):
                if module.match(prefix + plural) is not None or module.match(prefix + plural + '/selected-name') is not None:
                    raise ValueError('network_route_witness')
    bundle = read_json(gzip.decompress(under(root, BUNDLE).read_bytes()))
    candidate_proof = validate_candidates(bundle, reviewed)
    try:
        candidate_applicable(root, reviewed)
    except ValueError:
        applicability = 'rejected_stale_network_candidate'
    else:
        raise ValueError('expected_isolated_current_network')
    return {'status': 'current_isolation_validated', 'old_entries': len(reviewed['old_resources']),
        'new_entries': len(reviewed['approved_additions']), 'selected_route_witnesses': len(routes),
        'static_runtime119': static_runtime119(root, reviewed),
        'live_runtime119': 'use_validate_live_to_execute_original_guard',
        'registry_changed': False, 'old_receipts_changed': False, 'candidate_proof': candidate_proof,
        'historical_candidate_applicability': applicability}


def validate_live(root=None):
    """Call unchanged production guards through a normal package import."""
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    reviewed = receipt(root)
    result = validate(root)
    from peaso.checks import gcp_dataflow_batch_source_runtime_admission_20261020 as admission
    from peaso.checks import gcp_dataflow_batch_shared_hook_successor_20261020 as shared
    from peaso.collectors import k8s_network_extensions as network
    from peaso.collectors import k8s_network_route_extensions as route
    from peaso.collectors import k8s_network_catalog as catalog
    if admission.shared is not shared:
        raise ValueError('production_shared_identity')
    # Retain and invoke original guards: all source, runtime and identity proofs
    # run in the real package; no replacement function or read redirection.
    accepted, cases, declarations = admission.reviewed_inputs(root)
    if (accepted['runtime_functions'] != reviewed['runtime119']
            or len(admission._bindings()) != 18
            or any(actual is not expected for actual, expected in admission._bindings())):
        raise ValueError('production_runtime119')
    validate(root, network)
    executing(route.match, reviewed['isolated_route_matcher'], route, root)
    if (route.RESOURCES != reviewed['approved_additions'] or route.BY_ENDPOINT != endpoints(route.RESOURCES)
            or route.project is not network.project or route.re is not re):
        raise ValueError('isolated_route_metadata')
    for path in assert_disjoint(dict(network.RESOURCES, **route.RESOURCES), native_kinds(root, reviewed)):
        if route.match(path) is not None or catalog.allowed_path(path):
            raise ValueError('isolated_selected_route_overlap')
    for kind, (groups, plural, _) in route.RESOURCES.items():
        for group in groups:
            for middle in ('/', '/namespaces/review/'):
                path = '/apis/' + group + '/v1' + middle + plural
                if route.match(path) != kind or not catalog.allowed_path(path):
                    raise ValueError('isolated_route_dispatch')
    result.update(live_runtime119='passed_original_guard', imported_identity_pairs=18,
                  isolated_route_entries=len(route.RESOURCES), existing_edits_needed=0)
    return result


if __name__ == '__main__':
    print(json.dumps(validate_live(), sort_keys=True))
