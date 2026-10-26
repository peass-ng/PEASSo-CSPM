"""Conservative existing-check consumer for bound selected ConfigMap reads."""
from copy import deepcopy
import hashlib
import json
import re

from peaso.collectors.k8s_literal_secret_indicators import KIND, MARKER, MAX_WIRE
from peaso.checks import k8s_literal_secret_review_20261020 as original

SCHEMA = 'k8s-selected-configmap-association-v1'
HEX = re.compile(r'[0-9a-f]{64}\Z')
READ = re.compile(r'k8s-configmap-read-[1-9][0-9]*\Z')
RECEIPT_FIELDS = {'id', 'identity', 'scope_binding', 'cluster_binding',
    'workload_uid_binding', 'workload_version_binding', 'plan_binding',
    'map_binding', 'path_binding', 'selection_binding', 'optional', 'method',
    'status', 'bytes', 'uid_binding', 'version_binding', 'ordinal', 'seal'}


def _seal(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
        allow_nan=False).encode('utf-8')).hexdigest()


def _scope_binding(scope):
    return hashlib.sha256(scope.encode('utf-8')).hexdigest()


def _hex(value):
    return isinstance(value, str) and HEX.fullmatch(value) is not None


def _check(item, index):
    ctx = index['context']
    marker = item[MARKER]
    ident = item['id']
    association = marker['association']
    if (ctx['provider'] != 'k8s' or ctx['metadata'][KIND + '_authorized'] is not True
            or not isinstance(association, dict)
            or set(association) != {'schema', 'plan_binding', 'maps', 'seal'}
            or association['schema'] != SCHEMA or not _hex(association['plan_binding'])
            or not isinstance(association['maps'], list) or not 1 <= len(association['maps']) <= 6
            or not _hex(marker.get('uid_binding')) or not _hex(marker.get('version_binding'))
            or association['seal'] != _seal({'identity': ident,
                'uid_binding': marker['uid_binding'], 'version_binding': marker['version_binding'],
                'cluster_binding': marker['cluster_binding'], 'scope': marker['scope'],
                'literal_count': marker['literal_count'],
                'reference_count': marker['reference_count'],
                'source_requests': marker['source_requests'],
                'schema': association['schema'], 'plan_binding': association['plan_binding'],
                'maps': association['maps']})):
        raise ValueError('association')
    ledger = ctx['metadata'][KIND + '_configmap_receipts']
    if (not isinstance(ledger, list) or not 2 <= len(ledger) <= 16
            or any(not isinstance(r, dict) or set(r) != RECEIPT_FIELDS for r in ledger)
            or len({r['id'] for r in ledger}) != len(ledger)):
        raise ValueError('ledger')
    used, map_bindings, paths = set(), set(), set()
    for entry in association['maps']:
        if (not isinstance(entry, dict)
                or set(entry) != {'map_binding', 'path_binding', 'selection_binding', 'optional', 'requests'}
                or any(not _hex(entry[k]) for k in ('map_binding', 'path_binding', 'selection_binding'))
                or type(entry['optional']) is not bool
                or entry['map_binding'] in map_bindings or entry['path_binding'] in paths
                or not isinstance(entry['requests'], list) or len(entry['requests']) != 2
                or any(not isinstance(ref, str) or not READ.fullmatch(ref) for ref in entry['requests'])):
            raise ValueError('map')
        map_bindings.add(entry['map_binding'])
        paths.add(entry['path_binding'])
        first = None
        for ordinal, ref in enumerate(entry['requests'], 1):
            if ref in used:
                raise ValueError('duplicate request')
            used.add(ref)
            receipt, = [r for r in ledger if r['id'] == ref]
            if (receipt['seal'] != _seal({k: v for k, v in receipt.items() if k != 'seal'})
                    or receipt['identity'] != ident
                    or receipt['scope_binding'] != _scope_binding(ctx['scope'])
                    or receipt['cluster_binding'] != marker['cluster_binding']
                    or receipt['workload_uid_binding'] != marker['uid_binding']
                    or receipt['workload_version_binding'] != marker['version_binding']
                    or receipt['plan_binding'] != association['plan_binding']
                    or any(receipt[k] != entry[k] for k in
                        ('map_binding', 'path_binding', 'selection_binding', 'optional'))
                    or receipt['method'] != 'GET' or type(receipt['ordinal']) is not int
                    or receipt['ordinal'] != ordinal or type(receipt['status']) is not int
                    or receipt['status'] not in (200, 404)
                    or type(receipt['bytes']) is not int
                    or (receipt['status'] == 200 and not 1 <= receipt['bytes'] <= MAX_WIRE)
                    or (receipt['status'] == 404 and (not entry['optional'] or receipt['bytes'] != 0))
                    or (receipt['status'] == 200 and
                        (not _hex(receipt['uid_binding']) or not _hex(receipt['version_binding'])))
                    or (receipt['status'] == 404 and
                        (receipt['uid_binding'] is not None or receipt['version_binding'] is not None))):
                raise ValueError('receipt')
            stable = (receipt['status'], receipt['uid_binding'], receipt['version_binding'],
                receipt['selection_binding'])
            if first is not None and stable != first:
                raise ValueError('changed configmap')
            first = stable
    if len(used) != 2 * len(association['maps']):
        raise ValueError('coverage')
    if {r['id'] for r in ledger if r['identity'] == ident} != used:
        raise ValueError('unowned receipt')


def evaluate(item, index):
    """Keep the legacy branch byte-for-byte unless references need new proof."""
    try:
        legacy = getattr(original, '_evaluate_legacy', original.evaluate)
        marker = item[MARKER]
        ledger = index['context']['metadata'].get(KIND + '_configmap_receipts', [])
        if 'association' not in marker:
            # The collector records ConfigMap read receipts for every workload
            # whose plan names a ConfigMap. Secret, field and resource
            # references are counted but never read, so they keep the legacy
            # verdict; any receipt for this workload without its sealed
            # association is an unproved ConfigMap reference.
            if (not isinstance(ledger, list)
                    or any(isinstance(r, dict) and r.get('identity') == item.get('id') for r in ledger)):
                raise ValueError('unproved reference')
            return legacy(item, index)
        _check(item, index)
        safe_item, safe_index = deepcopy(item), deepcopy(index)
        del safe_item[MARKER]['association']
        own, = [r for r in safe_index['collections'][KIND] if r.get('scope') == safe_index['context']['scope']]
        matching = [i for i, row in enumerate(own['items']) if row == item]
        if len(matching) != 1:
            raise ValueError('selection')
        own['items'][matching[0]] = safe_item
        status, evidence = legacy(safe_item, safe_index)
        if status == 'UNKNOWN' or not evidence.get('complete'):
            raise ValueError('legacy incomplete')
        evidence['coverage'] = 'selected_workload_and_configmap_literals'
        if status == 'FAIL':
            evidence['observed'] = ('A ConfigMap value referenced by this workload resembles a secret.\n'
                'The workload may receive that value through its declared reference.\n'
                'This could expose sensitive data to people with access to the workload.')
        else:
            evidence['observed'] = ('The referenced ConfigMap values have no recognized secret pattern.\n'
                'The workload may receive those values through its declared references.')
        return status, evidence
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        return 'UNKNOWN', {'observed': ('A ConfigMap reference, read, or version for this workload is missing or inconsistent.\n'
            'The referenced values and their possible exposure remain unclear.')}
