"""Stage reviewed new-check descriptions from provider handoffs for signing.

The output stays under the ledger's ignored .work directory. A supervisor must
verify, publish and hash it in manifest.new_descriptions before compilation.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.peaso_compliance_compile import (DESCRIPTION_FIELDS, PROVIDERS, read_json,
                                              spec_digest, verified_file)



EXTRA_SHARD = re.compile(r"compliance-new-descriptions-(aws|gcp|azure|k8s)-[a-z0-9-]+\.json\Z")


def signed_proposals(ledger_root: Path) -> tuple[dict, dict]:
    manifest = read_json(ledger_root / "manifest.json")
    proposed = {}
    for entry in manifest["slices"].values():
        source, _ = verified_file(ledger_root, entry)
        for framework in source["frameworks"]:
            for requirement in framework["requirements"]:
                for spec in requirement["new_checks"]:
                    previous = proposed.setdefault(spec["id"], spec)
                    if previous != spec:
                        raise ValueError("Conflicting signed proposal: " + spec["id"])
    for entry in manifest.get("native_extensions", []):
        source, _ = verified_file(ledger_root, entry, prefix="native-extensions/")
        for row in source["checks"]:
            spec = row["spec"]
            if spec["id"] in proposed:
                raise ValueError("Duplicate native extension proposal: " + spec["id"])
            proposed[spec["id"]] = spec
    return manifest, proposed


def merge(ledger_root: Path, shard_dir: Path, extra_shards=()) -> dict:
    manifest, proposed = signed_proposals(ledger_root)
    if shard_dir.is_symlink():
        raise ValueError("Description shard directory must not be a symlink")
    published = {}
    if manifest.get("new_descriptions") is not None:
        published, _ = verified_file(ledger_root, manifest["new_descriptions"], prefix="descriptions/")
        if not isinstance(published, dict) or len(published) != manifest["new_descriptions"].get("checks"):
            raise ValueError("Published supplemental descriptions are malformed")
    merged, prose = dict(published), set()
    fields = DESCRIPTION_FIELDS | {"proposed_spec_sha256"}
    for cid, value in published.items():
        if (cid not in proposed or not isinstance(value, dict) or set(value) != fields or
                value["proposed_spec_sha256"] != spec_digest(proposed[cid])):
            raise ValueError("Published supplemental description differs from signed proposal: " + cid)
        prose.add(value["description"])
    sources = [(shard_dir / f"compliance-new-descriptions-{provider}.json", provider, True)
               for provider in sorted(PROVIDERS)]
    for path in extra_shards:
        path = Path(path)
        match = EXTRA_SHARD.fullmatch(path.name)
        if (match is None or path.is_symlink() or path.parent.absolute() != shard_dir.absolute() or
                not path.resolve().is_relative_to(shard_dir.resolve()) or
                not path.is_file() or path in {source[0] for source in sources}):
            raise ValueError("Extra description shard must be an existing named provider file under shard-dir")
        sources.append((path, match.group(1), False))
    for path, provider, base in sources:
        if not path.exists():
            continue
        if path.is_symlink():
            raise ValueError("Description shard must not be a symlink: " + path.name)
        shard = read_json(path)
        if not isinstance(shard, dict):
            raise ValueError("Malformed provider description shard: " + provider)
        for cid, value in shard.items():
            spec = proposed.get(cid)
            if spec is None or spec["provider"] != provider:
                raise ValueError("Duplicate, unsigned or cross-provider description: " + cid)
            if base and cid in published:
                # The supervisor's signed, possibly corrected description is
                # authoritative. An old staging shard cannot override it.
                continue
            if cid in merged:
                raise ValueError("Duplicate, unsigned or cross-provider description: " + cid)
            if not isinstance(value, dict) or set(value) != fields or value["proposed_spec_sha256"] != spec_digest(spec):
                raise ValueError("Description fields or signed spec hash mismatch: " + cid)
            description = value["description"]
            if (not isinstance(description, str) or len(description.strip()) < 60 or
                    description.strip().casefold() == spec["title"].strip().casefold() or
                    description in prose):
                raise ValueError("Empty, copied or duplicate new description: " + cid)
            if (not isinstance(value["evaluated"], list) or not value["evaluated"] or
                    not all(isinstance(field, str) and field.strip() for field in value["evaluated"])):
                raise ValueError("Missing evaluated fields: " + cid)
            if any(not isinstance(value[field], str) or len(value[field].strip()) < 15
                   for field in ("pass_when", "fail_when")):
                raise ValueError("Missing pass/fail criteria: " + cid)
            if value["not_applicable_when"] is not None and not isinstance(value["not_applicable_when"], str):
                raise ValueError("Invalid applicability text: " + cid)
            merged[cid] = value
            prose.add(description)
    return dict(sorted(merged.items()))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger-root", type=Path, required=True)
    parser.add_argument("--shard-dir", type=Path, required=True)
    parser.add_argument("--extra-shard", type=Path, action="append", default=[],
                        help="Explicit additional provider-family description file under shard-dir")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)
    merged = merge(args.ledger_root, args.shard_dir, args.extra_shard)
    if args.write:
        from peaso.checks import CHECKS
        from scripts.peaso_compliance_compile import read_json
        indexed = {row["id"] for row in read_json(args.ledger_root / "inputs/check-index.json")}
        registered = {check.id: check for check in CHECKS}
        actual = set(registered) - indexed
        if set(merged) != actual:
            raise ValueError("Staged descriptions must exactly match newly registered native IDs")
        _, proposed = signed_proposals(args.ledger_root)
        if any((cid not in proposed or registered[cid].provider != proposed[cid]["provider"] or
                registered[cid].severity != proposed[cid]["severity"]) for cid in actual):
            raise ValueError("Registered new check provider/severity differs from signed proposal")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(merged, ensure_ascii=False, separators=(",", ":")) + "\n")
    print(json.dumps({"new_descriptions": len(merged),
                      "staged_output": str(args.output) if args.write else None}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
