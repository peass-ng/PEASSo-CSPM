#!/usr/bin/env python3
"""Reconcile one completed scan from retained evidence and explicit review decisions.

Use the existing PEASO_STORAGE configuration. Dry-run is the default; --apply
requires the exact current report reference. No provider/model calls are made.
"""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tenant', required=True)
    parser.add_argument('--scan-id', required=True)
    parser.add_argument('--expected-report', required=True)
    parser.add_argument('--source-version', required=True)
    parser.add_argument('--adjudications', type=Path)
    parser.add_argument('--related-snapshots', type=Path, help='Private JSON array of exact original sealed related snapshots')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    from peaso.storage.runtime import stores
    from peaso.server.config import Settings
    from peaso.ai.reconcile import reconcile_scan
    store, artifacts = stores(Settings())
    decisions = json.loads(args.adjudications.read_text()) if args.adjudications else []
    if not isinstance(decisions, list):
        parser.error('Adjudications must be a JSON array')
    result = reconcile_scan(store, artifacts, args.tenant, args.scan_id, args.expected_report,
        source_version=args.source_version, adjudications=decisions, dry_run=not args.apply,
        related_snapshots=json.loads(args.related_snapshots.read_text()) if args.related_snapshots else None)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
