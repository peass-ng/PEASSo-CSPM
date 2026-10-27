#!/usr/bin/env python3
"""Bind exact 992 zero-disagreement checks to evaluator code and evidence shapes.

This emits no finding IDs, resource identities, evidence values, or secrets.
"""
import argparse
from collections import Counter, defaultdict
import gzip
import hashlib
import inspect
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def read(path):
    body = Path(path).read_bytes()
    return json.loads(gzip.decompress(body) if body.startswith(b"\x1f\x8b") else body)


def code_path(function):
    layers = []
    seen = set()
    while function is not None and id(function) not in seen:
        seen.add(id(function))
        code = getattr(function, "__code__", None)
        if code is not None:
            path = Path(code.co_filename)
            try:
                relative = str(path.resolve().relative_to(ROOT))
            except ValueError:
                relative = path.name
            layers.append(f"{relative}:{code.co_firstlineno}")
        function = getattr(function, "__wrapped__", None)
    return layers


def delegate_path(function, ident):
    base = inspect.unwrap(function)
    delegates = []
    for name, value in base.__globals__.items():
        if not isinstance(value, dict) or ident not in value:
            continue
        target = value[ident]
        if callable(target):
            try:
                digest = hashlib.sha256(inspect.getsource(target).encode()).hexdigest()
            except (OSError, TypeError):
                digest = None
            delegates.append({"registry_map": name, "code_path": code_path(target),
                              "source_sha256": digest})
    return delegates


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("numeric_receipt")
    parser.add_argument("finding_chunks_dir")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    receipt = read(args.numeric_receipt)
    if receipt.get("scan_id") != "992d7b8cbd4340a79e41139ba1a44c1e":
        raise ValueError("wrong scan")
    target = {r["check_id"] for r in receipt["per_check"] if not r["ai_disagreement_count"]}
    from peaso.checks import CHECKS
    registry = {c.id: c for c in CHECKS}
    if target - registry.keys():
        raise ValueError(f"missing registered checks: {sorted(target - registry.keys())}")
    evidence = defaultdict(set)
    evidence_types = defaultdict(lambda: defaultdict(Counter))
    observed = defaultdict(int)
    files = sorted(Path(args.finding_chunks_dir).glob("*.json.gz"))
    if len(files) != 419:
        raise ValueError("expected exact 992 final finding chunks")
    for path in files:
        for finding in read(path)["items"]:
            ident = finding.get("check_id")
            if ident not in target or finding.get("scanner_status", finding.get("status")) != "FAIL":
                continue
            observed[ident] += 1
            value = finding.get("evidence")
            if isinstance(value, dict):
                evidence[ident].update(value)
                for key, actual in value.items():
                    evidence_types[ident][key]["null" if actual is None else type(actual).__name__] += 1
            elif value is not None:
                evidence[ident].add("<non-object evidence>")
    by_id = {r["check_id"]: r for r in receipt["per_check"]}
    rows = []
    for ident in sorted(target):
        check = registry[ident]
        if observed[ident] != by_id[ident]["native_fail_count"]:
            raise ValueError(f"native row count mismatch: {ident}")
        function = inspect.unwrap(check.evaluate)
        try:
            source_hash = hashlib.sha256(inspect.getsource(function).encode()).hexdigest()
        except (OSError, TypeError):
            source_hash = None
        rows.append({"check_id": ident, "native_fail_count": observed[ident],
                     "initial_representatives": by_id[ident]["initial_representatives"],
                     "kind": check.kind, "target": check.target,
                     "dependencies": sorted(check.dependencies),
                     "code_path": code_path(check.evaluate),
                     "delegate_code_path": delegate_path(check.evaluate, ident),
                     "evaluator_source_sha256": source_hash,
                     "evidence_keys": sorted(evidence[ident]),
                     "evidence_type_counts": {key: dict(sorted(counts.items()))
                                              for key, counts in sorted(evidence_types[ident].items())},
                     "decision": "unreviewed", "rationale": ""})
    Path(args.output).write_text(json.dumps({"schema_version": 1,
        "scan_id": receipt["scan_id"], "source_commit": receipt["source_commit"],
        "zero_disagreement_checks": len(rows), "checks": rows}, indent=2) + "\n")
    print(json.dumps({"checks": len(rows), "native_fail_rows": sum(r["native_fail_count"] for r in rows)}))


if __name__ == "__main__":
    main()
