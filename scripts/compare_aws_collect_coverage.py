"""Count-only comparison of two full AWS collection snapshots.

Accepts plain JSON or gzip JSON. Resource data and collection identities are
never printed; the output contains counts and an identity-set digest only.
"""
from __future__ import annotations

import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path


COMPLETE = frozenset({"collected", "empty"})
READABLE = COMPLETE | {"partial"}
STATUSES = COMPLETE | {"partial", "denied", "unknown", "malformed", "timeout", "not_collected"}
BINDING = ("service", "account_id", "global")


def _read(path: Path):
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as stream:
        snapshot = json.load(stream)
    if snapshot.get("provider") != "aws" or not isinstance(snapshot.get("collections"), list):
        raise ValueError("expected a full AWS collection snapshot")
    records = {}
    statuses = Counter()
    total_items = 0
    for row in snapshot["collections"]:
        if not isinstance(row, dict) or not all(isinstance(row.get(field), str) for field in ("type", "scope")):
            raise ValueError("malformed AWS collection identity")
        identity = (row["type"], row["scope"])
        if identity in records:
            raise ValueError("duplicate AWS collection identity")
        status = row.get("status")
        if status not in STATUSES or not isinstance(row.get("items"), list):
            raise ValueError("malformed AWS collection status or items")
        records[identity] = (status, tuple(row.get(field) for field in BINDING), len(row["items"]))
        statuses[status] += 1
        total_items += len(row["items"])
    digest = hashlib.sha256(json.dumps(sorted(records), separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    return records, statuses, total_items, digest


def compare(before: Path, after: Path, *, expected_identities=1292, require_zero_incomplete=False):
    prior, prior_statuses, prior_items, prior_digest = _read(before)
    current, current_statuses, current_items, current_digest = _read(after)
    prior_ids, current_ids = set(prior), set(current)
    shared = prior_ids & current_ids
    binding_changes = sum(prior[key][1] != current[key][1] for key in shared)
    status_regressions = sum(prior[key][0] in COMPLETE and current[key][0] not in COMPLETE for key in shared)
    partial_regressions = sum(prior[key][0] == "partial" and current[key][0] not in READABLE for key in shared)
    incomplete = sum(count for status, count in current_statuses.items() if status not in COMPLETE)
    identities_match = not (prior_ids ^ current_ids) and len(current) == expected_identities
    passed = (identities_match and binding_changes == 0 and status_regressions == 0
              and partial_regressions == 0 and (not require_zero_incomplete or incomplete == 0))
    return {
        "passed": passed,
        "expected_identities": expected_identities,
        "before_identities": len(prior),
        "after_identities": len(current),
        "missing_identities": len(prior_ids - current_ids),
        "added_identities": len(current_ids - prior_ids),
        "binding_changes": binding_changes,
        "complete_to_incomplete_regressions": status_regressions,
        "partial_to_unreadable_regressions": partial_regressions,
        "before_incomplete": sum(count for status, count in prior_statuses.items() if status not in COMPLETE),
        "after_incomplete": incomplete,
        "before_statuses": dict(sorted(prior_statuses.items())),
        "after_statuses": dict(sorted(current_statuses.items())),
        "before_items": prior_items,
        "after_items": current_items,
        "before_identity_sha256": prior_digest,
        "after_identity_sha256": current_digest,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--expected-identities", type=int, default=1292)
    parser.add_argument("--require-zero-incomplete", action="store_true")
    args = parser.parse_args()
    result = compare(args.before, args.after, expected_identities=args.expected_identities,
                     require_zero_incomplete=args.require_zero_incomplete)
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
