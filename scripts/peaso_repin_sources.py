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
current bytes are listed in CURRENT_PIN_POINTERS.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import itertools
import json.decoder
import re
import subprocess
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


def substitute(rel: str, text: str, mapping: dict[str, str]) -> str:
    """Map pinned digests in one file, leaving historical JSON witnesses untouched."""
    if not any(m.group(0) in mapping for m in HEX64.finditer(text)):
        return text
    frozen = []
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
                    if key in new and new[key] != digest and digest not in FROZEN_DIGESTS:
                        mapping[digest] = new[key]
            if history[-1] != new:
                history.append(new)
        if not mapping:
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
            return 0
    raise SystemExit('re-pin did not converge')


if __name__ == '__main__':
    raise SystemExit(main())
