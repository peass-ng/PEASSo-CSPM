"""Re-pin finite source receipts after a reviewed edit.

Compares every changed tracked file with ``--base`` (default HEAD) and maps
each old digest that is still referenced in the tree to the digest of the
same projection of the edited file: whole bytes, bytes with module-level
digest assignments zeroed, and top-level definition fragments.  The
replacement repeats until no pinned digest changes.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import itertools
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
    'tests/fixtures/post_dfaf_integration/historical-release-manifests.json',
    'tests/fixtures/post_dfaf_integration/sprint_source_changes.json',
    'tests/test_native_admission_cpu_successor_20261020.py',
))


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
               if p and p not in FROZEN and p.endswith(('.py', '.json', '.txt', '.toml', '.yaml', '.yml', '.md'))]
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
                    if key in new and new[key] != digest:
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
            updated = HEX64.sub(lambda m: mapping.get(m.group(0), m.group(0)), text)
            if updated != text:
                path.write_text(updated, encoding='utf-8', errors='surrogateescape')
                touched += 1
                print(f'round {round_}: {rel}')
        if not touched:
            return 0
    raise SystemExit('re-pin did not converge')


if __name__ == '__main__':
    raise SystemExit(main())
