"""Re-pin finite source receipts after a reviewed edit.

Compares every changed tracked file with ``--base`` (default HEAD) and maps
each old digest that is still referenced in the tree to the digest of the
same projection of the edited file: whole bytes, bytes with module-level
digest assignments zeroed, and top-level definition fragments.  The
replacement repeats until no pinned digest changes.

Historical witnesses are never rewritten: whole FROZEN files, individual
FROZEN_DIGESTS, and every JSON string whose pointer names a historical record
(``before``, ``prior``, ``original``, ``immutable``, ``retained`` ... see
HISTORICAL_KEY).  Those fields keep the value they were written with; a current
change is admitted through an explicit current/successor pin instead.  The few
pointers that use a historical word but are runtime-verified pins of a file's
current bytes are listed in CURRENT_PIN_POINTERS.  Python digest literals are
registered in PY_PIN_BLOCKS / CURRENT_PIN_CONSTANTS: current pins there are
refreshed to the digest of the file they name on every run, historical ones
are never rewritten.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import itertools
import os
import json.decoder
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HEX64 = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")
DIGEST_LINE = re.compile(rb"(?m)^(\w+) = (['\"])[0-9a-f]{64}\2$")
# Historical records: their digests describe earlier releases (or inverse
# deltas back to them) and must keep the values they were written with.
FROZEN = frozenset((
    'docs/check-review/azure-network-platform-1-native-review-20261020.json',
    'peaso/private_secret_source_epoch_20261021.json',
    'tests/fixtures/gcp-wave2-final-services-history-20261020/before-compliance_new_sw52.py',
    'tests/fixtures/gcp-wave2-final-services-history-20261020/before-native_only.json',
    'tests/fixtures/gcp-wave2-final-services-history-20261020/predecessor-hashes.json',
    'tests/fixtures/post_dfaf_integration/historical-release-manifests.json',
    'tests/fixtures/post_dfaf_integration/sprint_source_changes.json',
    'tests/test_native_admission_cpu_successor_20261020.py',
    'tests/test_provider_combined_source_bridge_20261020.py',
))
# Whole trees of dated review records and retained predecessor fixtures; the
# same set push_locked.sh reverts after its own re-pin.  A current value a
# runtime verifier needs from one of them lives in a successor field elsewhere.
FROZEN_PREFIXES = (
    'docs/check-review/',
    'docs/gcp-review/',
    'docs/evidence-reviews/history',
    'tests/fixtures/post_dfaf_integration/',
)
FROZEN_NAME = re.compile(r'^tests/fixtures/(?:.*/)?predecessor-hashes\.json$')


def frozen_file(rel: str) -> bool:
    """True for a historical record file the re-pin must never rewrite."""
    return rel in FROZEN or rel.startswith(FROZEN_PREFIXES) or bool(FROZEN_NAME.match(rel))


# Individual historical digests that equal a projection of a file edited later.
# Receipts verify them against an archived predecessor, never the current file,
# so a later edit of that projection must not move them.
FROZEN_DIGESTS = frozenset((
    # peaso/collectors/k8s.py def _sanitize in the archived source epoch predecessor.
    '235505cc366adf66cb10ef7716d5b35ed5686ee27d42ae9b4f8bfb559955ced8',
    # scripts/peaso_deploy.py SOURCE_ATTESTATION_SUCCESSOR predecessors (and the
    # CURRENT_INDEXED_WORKFLOW/CURRENT_AI_RUNTIME/API_DELIVERY pins they equal):
    # infra/aws api.tf, workflow.tf and ai_runtime.tf before the trusted-attestation
    # lines; the deploy contract checks them against the bytes with those lines removed.
    'ab8336af2ce98102c92abe6dfb6df9f4346cc8cee404e469c180c2aa4eb02787',
    '361fef2318aef55d01ba351501cc79a4fa06884d368d380b714f2f42814e57ad',
    '0948bda88c41ea79fd25dc9c2faa656b7d71c9d29012024156017921122834a6',
))
# Sources whose earlier versions are rebuilt from exact inverse-delta receipts.
# Historical records pin their old function fragments; only whole-file and
# zeroed-digest projections of these files move with an edit.
INVERSE_DELTA_SOURCES = frozenset((
    'peaso/secret_scanning.py',
))


# A JSON object key naming a historical record: every digest below it describes
# bytes as they were when the record was written (NEXT-PROVENANCE-1).
HISTORICAL_KEY = re.compile(
    r'(?:^|_)(?:before|prior|predecessors?|original|previous|old|older|archived|immutable|'
    r'historical|history|retained|preserved|preservation|conservation|conserved|legacy|'
    r'origin|baseline|unchanged|protected|inherited|lineage|installed)(?:_|$)')
# Reviewed exceptions: pointers whose key uses a historical word but whose value
# a runtime loader compares with the CURRENT bytes of an in-tree file, so the pin
# must follow that file.  '*' matches one segment, '**' the rest of the pointer.
CURRENT_PIN_POINTERS = (
    # peaso/checks/k8s_annotation_native_admission_20261020.py hashes the legacy receipt file.
    ('lineage', 'predecessor_receipt_sha256'),
    # peaso/gcp_*_source*_2026102*.py compare with predecessor.RECEIPT_SHA256 and the file.
    ('predecessor_receipt_sha256',),
    # peaso/checks/*_shared_successor_20261020.py compare with prior_bridge.RECEIPT_SHA256.
    ('prior_bridge_receipt_sha256',),
    # peaso/checks/*_tde_successor_20261020.py hash each listed predecessor source file.
    ('predecessor_files', '*'),
    # peaso/checks/k8s_annotation_native_source_successor_20261021.py hashes the file.
    ('historical_receipt_sha256',),
    ('historical_guard_sha256',),
    # A producer named after a Security Hub finding history, not a historical record.
    ('producers', 'securityhub_finding_history', '**'),
    # Generated catalog field: peaso.checks.evaluator_contract_fingerprint() of the current engine.
    ('archived_checks', '*', 'clarity_evaluation_contract'),
)


def _plain_key(segment) -> bool:
    """A schema key, not a file path, symbol, digest or list index."""
    return (isinstance(segment, str) and not HEX64.fullmatch(segment)
            and not re.search(r'[/:]|\.[A-Za-z]', segment))


def _matches(pattern, pointer) -> bool:
    for i, want in enumerate(pattern):
        if want == '**':
            return True
        if i >= len(pointer) or (want != '*' and want != pointer[i]):
            return False
    return len(pattern) == len(pointer)


def historical_pointer(pointer) -> bool:
    """True when a JSON pointer (tuple of keys/indices) names a historical witness."""
    if any(_matches(pattern, pointer) for pattern in CURRENT_PIN_POINTERS):
        return False
    return any(_plain_key(seg) and HISTORICAL_KEY.search(seg) for seg in pointer)


_WS = re.compile(r'[ \t\n\r]*')
_SCALAR = re.compile(r'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?|true|false|null')


def json_string_spans(text: str):
    """Yield (start, end, pointer, is_key) for every JSON string token; keys use their own pointer."""
    def ws(i):
        return _WS.match(text, i).end()

    def value(i, pointer):
        i = ws(i)
        ch = text[i]
        if ch == '"':
            _, end = json.decoder.scanstring(text, i + 1)
            yield i, end, pointer, False
            return end
        if ch == '{':
            i = ws(i + 1)
            if text[i] == '}':
                return i + 1
            while True:
                key, end = json.decoder.scanstring(text, i + 1)
                yield i, end, pointer + (key,), True
                i = ws(end)
                assert text[i] == ':'
                i = yield from value(i + 1, pointer + (key,))
                i = ws(i)
                if text[i] == '}':
                    return i + 1
                assert text[i] == ','
                i = ws(i + 1)
        if ch == '[':
            i = ws(i + 1)
            if text[i] == ']':
                return i + 1
            index = 0
            while True:
                i = yield from value(i, pointer + (index,))
                i = ws(i)
                if text[i] == ']':
                    return i + 1
                assert text[i] == ','
                i, index = i + 1, index + 1
        match = _SCALAR.match(text, i)
        if not match:
            raise ValueError(f'invalid JSON at {i}')
        return match.end()

    yield from value(0, ())


# Module-level digest literals in Python files, by (path, NAME).  A literal is
# ``NAME = {...}`` or ``NAME = json.loads(r'''...''')``.
#   'current'    {path: sha256 | {..., 'after_sha256': sha256}} that a verifier
#                compares with the CURRENT bytes of each path: refreshed to the
#                file's digest on every run, so a stale pin cannot rot.  Keys
#                naming history (``before_sha256`` ...) stay frozen.
#   'pointer'    only digests under a historical key stay frozen.
#   'historical' every digest in the literal is a historical witness.
PY_PIN_BLOCKS = {
    ('tests/provider_observation_residual_successors_20261020.py', 'PINNED'): 'current',
    ('tests/test_peaso_azure_evidence_explanations.py', 'PINNED_SUCCESSOR_INPUTS'): 'historical',
    ('tests/test_gcp_current_source_reconciliation_20261020.py', 'RECORD_SUCCESSORS'): 'current',
    ('tests/test_gcp_current_source_reconciliation_20261020.py', 'PREDICATE_SUCCESSORS'): 'pointer',
    ('tests/test_peaso_gcp_remaining_clarity_reviewed.py', 'CURRENT_EXTENSION_SOURCES'): 'current',
    ('tests/test_peaso_gcp_remaining_clarity_reviewed.py', 'EXTENSION_PREDICATE_SUCCESSORS'): 'pointer',
}
# ``NAME = '<sha256>'`` constants that pin the current bytes of one file.
CURRENT_PIN_CONSTANTS = {
    ('tests/test_gcp_current_source_reconciliation_20261020.py', 'REPORT_SHA256'):
        'docs/gcp-review/recheck-20261020/current-source-reconciliation-20261020.json',
    ('tests/test_gcp_current_source_reconciliation_20261020.py', 'CURRENT_RECEIPT_SHA256'):
        'docs/check-review/gcp-current-ledger-source-conservation-20261020.json',
    ('tests/gcp_clarity_combined_successor_20261020.py', 'CURRENT_EXPLANATIONS_SHA256'):
        'peaso/checks/gcp_evidence_explanations.py',
    ('tests/gcp_clarity_combined_successor_20261020.py', 'CURRENT_EXPLANATIONS_SUCCESSOR_SHA256'):
        'peaso/checks/gcp_evidence_explanations_current_20261023.json',
}


def _offset(text: str, starts: list[int], lineno: int, col: int) -> int:
    line = text[starts[lineno - 1]:starts[lineno] if lineno < len(starts) else len(text)]
    return starts[lineno - 1] + len(line.encode('utf-8', 'surrogateescape')[:col].decode('utf-8', 'surrogateescape'))


def py_literal_blocks(rel: str, text: str):
    """Yield (mode, start, end, [(start, end, pointer)]) for each registered literal in ``rel``."""
    names = {name: mode for (path, name), mode in PY_PIN_BLOCKS.items() if path == rel}
    if not names:
        return
    tree = ast.parse(text)
    starts = list(itertools.accumulate([0] + [len(l) for l in text.splitlines(keepends=True)]))

    def span(node):
        return (_offset(text, starts, node.lineno, node.col_offset),
                _offset(text, starts, node.end_lineno, node.end_col_offset))

    def walk(node, pointer):
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    yield from walk(value, pointer + (key.value,))
        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for index, value in enumerate(node.elts):
                yield from walk(value, pointer + (index,))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield (*span(node), pointer)

    for node in tree.body:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
        for target in targets:
            if not (isinstance(target, ast.Name) and target.id in names) or node.value is None:
                continue
            value = node.value
            start, end = span(value)
            if (isinstance(value, ast.Call) and len(value.args) == 1 and isinstance(value.args[0], ast.Constant)
                    and isinstance(value.args[0].value, str)):
                a, b = span(value.args[0])
                literal = text[a:b]
                inner = value.args[0].value
                at = literal.find(inner)
                if at < 0:
                    raise ValueError(f'{rel}:{target.id}: JSON literal must be a raw string')
                strings = [(a + at + s, a + at + e, ptr) for s, e, ptr, is_key in json_string_spans(inner) if not is_key]
            else:
                strings = list(walk(value, ()))
            yield names[target.id], start, end, strings


def _py_frozen_spans(rel: str, text: str) -> list[tuple[int, int]]:
    frozen = []
    for mode, start, end, strings in py_literal_blocks(rel, text):
        if mode == 'historical':
            frozen.append((start, end))
        else:
            frozen += [(s, e) for s, e, pointer in strings if historical_pointer(pointer)]
    return frozen


def refresh_current_pins(rel: str, text: str, root: Path = ROOT) -> str:
    """Set every registered current pin in ``rel`` to the digest of the file it names."""
    edits = []
    for mode, _, _, strings in py_literal_blocks(rel, text):
        if mode != 'current':
            continue
        for s, e, pointer in strings:
            if historical_pointer(pointer) or not isinstance(pointer[0], str):
                continue
            if len(pointer) == 1 or pointer[1:] == ('after_sha256',):
                target = root / pointer[0]
                if target.is_file() and HEX64.fullmatch(text[s + 1:e - 1]):
                    edits.append((s + 1, e - 1, _sha(target.read_bytes())))
    for (path, name), target in CURRENT_PIN_CONSTANTS.items():
        if path != rel or not (root / target).is_file():
            continue
        match = re.search(rf"(?m)^{name} = (['\"])([0-9a-f]{{64}})\1$", text)
        if match:
            edits.append((match.start(2), match.end(2), _sha((root / target).read_bytes())))
    for s, e, digest in sorted(edits, reverse=True):
        text = text[:s] + digest + text[e:]
    return text


def substitute(rel: str, text: str, mapping: dict[str, str]) -> str:
    """Map pinned digests in one file, leaving historical JSON witnesses untouched."""
    if not any(m.group(0) in mapping for m in HEX64.finditer(text)):
        return text
    frozen = _py_frozen_spans(rel, text) if rel.endswith('.py') else []
    if rel.endswith('.json'):
        try:
            frozen = [(start, end) for start, end, pointer, _ in json_string_spans(text)
                      if historical_pointer(pointer)]
        except (ValueError, AssertionError, IndexError):
            frozen = []

    def repl(match):
        pos = match.start()
        if any(start <= pos < end for start, end in frozen):
            return match.group(0)
        return mapping.get(match.group(0), match.group(0))
    return HEX64.sub(repl, text)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _git(*args: str) -> bytes:
    return subprocess.run(['git', *args], cwd=ROOT, check=True, capture_output=True).stdout


_PROJECTIONS: dict[str, dict[str, str]] = {}


def _projections(raw: bytes) -> dict[str, str]:
    """Named projections; equal names compare old and new versions."""
    key = _sha(raw)
    if key not in _PROJECTIONS:
        _PROJECTIONS[key] = _project(raw)
    return _PROJECTIONS[key]


def _project(raw: bytes) -> dict[str, str]:
    rows = {'file': _sha(raw)}
    names = sorted({m.group(1).decode() for m in DIGEST_LINE.finditer(raw)})
    # Receipts zero at most a few sibling digests; bound the subsets so large
    # pinned modules do not hash thousands of combinations every round.
    for size in ((1, 2, 3) if len(names) <= 12 else (1, 2) if len(names) <= 40 else (1,)):
        for subset in itertools.combinations(names, size):
            def zero(match, subset=subset):
                if match.group(1).decode() not in subset:
                    return match.group(0)
                quote = match.group(2)
                return match.group(1) + b' = ' + quote + b'0' * 64 + quote
            rows['zero:' + ','.join(subset)] = _sha(DIGEST_LINE.sub(zero, raw))
    try:
        tree = ast.parse(raw)
    except SyntaxError:
        return rows
    lines = raw.splitlines(keepends=True)

    def walk(nodes, prefix=''):
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                start = min([node.lineno] + [d.lineno for d in node.decorator_list])
                fragment = b''.join(lines[start - 1:node.end_lineno])
                rows['def:' + prefix + node.name] = _sha(fragment)
                plain = b''.join(lines[node.lineno - 1:node.end_lineno])
                rows['plain:' + prefix + node.name] = _sha(plain)
                if isinstance(node, ast.ClassDef):
                    walk(node.body, prefix + node.name + '.')
    walk(tree.body)
    return rows


SUCCESSOR_REFRESH = 'scripts/peaso_reviewed_successors_refresh.py'
SUCCESSOR_OUTPUTS = ('tests/fixtures/reviewed_current_successors_20261026.json.gz',
                     'tests/reviewed_current_successors_20261026.py')


def refresh_reviewed_successors() -> bool:
    """Record current bytes for the two whole-tree conservation tests.

    Their fixture keeps every earlier before/after row; only the current
    after_sha256 moves.  Returns True when the fixture or its pin changed.
    """
    script = ROOT / SUCCESSOR_REFRESH
    if not script.is_file() or not all((ROOT / rel).is_file() for rel in SUCCESSOR_OUTPUTS):
        return False
    before = [(ROOT / rel).read_bytes() for rel in SUCCESSOR_OUTPUTS]
    env = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE='1')
    subprocess.run([sys.executable, str(script)], cwd=ROOT, env=env, check=True, capture_output=True)
    changed = before != [(ROOT / rel).read_bytes() for rel in SUCCESSOR_OUTPUTS]
    if changed:
        print('refreshed reviewed current successors')
    return changed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--base', default='HEAD')
    parser.add_argument('--max-rounds', type=int, default=30)
    parser.add_argument('--prior-tree', help='copy of the tree after an earlier re-pin whose digests must also be mapped')
    args = parser.parse_args()
    tracked = [p for p in _git('ls-files', '-z').decode().split('\0')
               if p and not frozen_file(p) and p.endswith(('.py', '.json', '.txt', '.toml', '.yaml', '.yml', '.md'))]
    seen: dict[str, list[dict[str, str]]] = {}
    for round_ in range(args.max_rounds):
        for rel in sorted({path for path, _ in (*PY_PIN_BLOCKS, *CURRENT_PIN_CONSTANTS)}):
            path = ROOT / rel
            if path.is_file():
                text = path.read_text(encoding='utf-8', errors='surrogateescape')
                updated = refresh_current_pins(rel, text)
                if updated != text:
                    path.write_text(updated, encoding='utf-8', errors='surrogateescape')
                    print(f'round {round_}: refreshed current pins in {rel}')
        changed = [p for p in _git('diff', '--name-only', args.base).decode().split() if (ROOT / p).exists()]
        if args.prior_tree:
            # A file restored to its base still left its snapshot digest behind.
            prior = Path(args.prior_tree)
            changed += sorted({str(p.relative_to(prior)) for p in prior.rglob('*') if p.is_file()}
                              - set(changed))
        mapping: dict[str, str] = {}
        for rel in changed:
            try:
                old_raw = _git('show', f'{args.base}:{rel}')
            except subprocess.CalledProcessError:
                continue
            new = _projections((ROOT / rel).read_bytes())
            if rel not in seen:
                seen[rel] = [_projections(old_raw)]
                # A snapshot of an earlier partial re-pin also left digests behind.
                if args.prior_tree and (Path(args.prior_tree) / rel).is_file():
                    seen[rel].append(_projections((Path(args.prior_tree) / rel).read_bytes()))
            history = seen[rel]
            # Earlier rounds leave intermediate digests behind; map them too.
            for old in history:
                for key, digest in old.items():
                    if rel in INVERSE_DELTA_SOURCES and key.startswith(('def:', 'plain:')):
                        continue
                    if key in new and new[key] != digest and digest not in FROZEN_DIGESTS:
                        mapping[digest] = new[key]
            if history[-1] != new:
                history.append(new)
        if not mapping:
            if refresh_reviewed_successors():
                continue
            return 0
        touched = 0
        for rel in tracked:
            path = ROOT / rel
            if not path.is_file():
                continue
            text = path.read_text(encoding='utf-8', errors='surrogateescape')
            updated = substitute(rel, text, mapping)
            if updated != text:
                path.write_text(updated, encoding='utf-8', errors='surrogateescape')
                touched += 1
                print(f'round {round_}: {rel}')
        if not touched:
            if refresh_reviewed_successors():
                continue
            return 0
    raise SystemExit('re-pin did not converge')


if __name__ == '__main__':
    raise SystemExit(main())
