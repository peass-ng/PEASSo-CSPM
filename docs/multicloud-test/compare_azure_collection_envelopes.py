"""Compare complete collection envelopes without printing private resource data.

Usage: python compare_azure_collection_envelopes.py BEFORE.json AFTER.json
Five generated scan-context fields inside _provenance are excluded, along with
the local read timestamp in typed, read-only effective-network source receipts.
All native properties, collection statuses/errors, and item order are retained.
Collection order alone is normalized because independent jobs may finish earlier.
"""
import collections
import hashlib
import json
from pathlib import Path
import sys


SCAN_FIELDS = frozenset(('credential_context_id', 'customer_context_id',
                         'observed_at', 'transport_context_id', 'capture_id'))


def canonical(snapshot):
    excluded = collections.Counter()

    def visit(value, provenance=False):
        if isinstance(value, dict):
            result = {}
            for key, child in value.items():
                if provenance and key in SCAN_FIELDS:
                    excluded[key] += 1
                else:
                    result[key] = visit(child, provenance or key == '_provenance')
            return result
        if isinstance(value, list):
            return [visit(child, provenance) for child in value]
        return value

    rows = snapshot['collections']
    identities = [(row['type'], row['scope']) for row in rows]
    if len(set(identities)) != len(identities):
        raise ValueError('duplicate collection identity')
    rows = sorted(rows, key=lambda row: (row['type'], row['scope']))
    normalized = []
    for row in rows:
        value = visit(row)
        if row['type'] in {'effective_route', 'security_admin_rule'}:
            for proof in value.get('source_evidence', []):
                if (isinstance(proof, dict) and proof.get('read_only') is True
                        and proof.get('representation') == 'full'
                        and proof.get('source_operation') in {
                            'effectiveRouteTable', 'listNetworkManagerEffectiveSecurityAdminRules'}
                        and 'observed_at' in proof):
                    # NetworkQueries.pages creates this timestamp locally after
                    # each provider read. Keep its exact response digest, native
                    # resource identity, operation and all other receipt fields.
                    del proof['observed_at']
                    excluded['network_source_evidence.observed_at'] += 1
        normalized.append(value)
    raw = json.dumps(normalized, sort_keys=True, separators=(',', ':')).encode()
    return raw, dict(excluded)


def compare(before, after):
    a, excluded_a = canonical(before)
    b, excluded_b = canonical(after)
    return {'complete_collection_envelopes_equal': a == b,
            'before_sha256': hashlib.sha256(a).hexdigest(),
            'after_sha256': hashlib.sha256(b).hexdigest(),
            'before_collections': len(before['collections']),
            'after_collections': len(after['collections']),
            'before_resources': sum(len(row['items']) for row in before['collections']),
            'after_resources': sum(len(row['items']) for row in after['collections']),
            'excluded_before': excluded_a, 'excluded_after': excluded_b,
            'scope': 'Complete collection envelopes; snapshot-level metadata is not compared.'}


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    result = compare(*(json.loads(Path(path).read_text()) for path in sys.argv[1:]))
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result['complete_collection_envelopes_equal'] else 1)
