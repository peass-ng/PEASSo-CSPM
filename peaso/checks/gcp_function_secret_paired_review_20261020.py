"""Reviewed successor for the exact existing Functions literal-secret check."""
from copy import deepcopy

from .facts import Unavailable, get
from .gcp_function_secret_review_20261019 import CHECK_ID, DECLARATION
from peaso.collectors.gcp_function_secret_indicators import (
    SCHEMA, MARKER, SURFACES, MAX_PAIRS, MAX_FUNCTION_BYTES, MAX_LEAKS, MAX_LOCATIONS, _bound,
)
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION
from peaso.collectors.gcp_function_secret_pairs_20261020 import SCHEMA as PAIRED_SCHEMA


def _evaluate(item, index):
    try:
        scope = get(index, 'context.scope', str)
        if get(index, 'context.provider', str) != 'gcp':
            raise Unavailable('foreign provider')
        name = get(item, 'name', str)
        if not _bound(name, scope, '-', None):
            raise Unavailable('foreign function')
        envelopes = get(index, 'collections.function', list)
        matching = [row for row in envelopes if isinstance(row, dict) and row.get('scope') == scope
                    and row.get('status') == 'collected' and isinstance(row.get('items'), list)
                    and sum(isinstance(native, dict) and native.get('name') == name for native in row['items']) == 1
                    and item in row['items']]
        if len(matching) != 1:
            raise Unavailable('function collection incomplete or ambiguous')
        marker = get(item, MARKER, dict)
        if (set(marker) != {'schema', 'status', 'identity', 'scope', 'complete', 'surfaces', 'leaks', 'verification'}
                or marker['schema'] not in (SCHEMA, PAIRED_SCHEMA) or marker['status'] not in ('collected', 'incomplete')
                or marker['identity'] != name or marker['scope'] != scope
                or type(marker['complete']) is not bool or marker['verification'] != 'not_attempted'):
            raise Unavailable('unbound or unavailable scanner projection')
        surfaces = marker['surfaces']
        if not isinstance(surfaces, list) or [s.get('surface') for s in surfaces if isinstance(s, dict)] != list(SURFACES):
            raise Unavailable('both environment surfaces required')
        paired = marker['schema'] == PAIRED_SCHEMA
        all_complete, completed_by_path, pairs_by_path, paired_leaks = True, {}, {}, []
        for surface in surfaces:
            expected_fields = {'surface', 'pairs', 'bytes', 'complete', 'engines'} | ({'leaks'} if paired else set())
            if (set(surface) != expected_fields
                    or type(surface['pairs']) is not int or not 0 <= surface['pairs'] <= MAX_PAIRS
                    or type(surface['bytes']) is not int or not 1 <= surface['bytes'] <= MAX_FUNCTION_BYTES
                    or type(surface['complete']) is not bool or not isinstance(surface['engines'], list)):
                raise Unavailable('malformed detector coverage')
            engines = surface['engines']
            expected = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
            if (len(engines) != 2 or any(not isinstance(e, dict) or set(e) != {'engine', 'version', 'status'}
                    or e.get('engine') not in expected or e.get('version') != expected.get(e.get('engine'))
                    or e.get('status') not in ('complete', 'unavailable') for e in engines)
                    or {e['engine'] for e in engines} != set(expected)):
                raise Unavailable('both detector identities required')
            complete = all(e['status'] == 'complete' for e in engines)
            if surface['complete'] != complete:
                raise Unavailable('contradictory surface completeness')
            all_complete &= complete
            path = surface['surface'] + '.environmentVariables'
            completed_by_path[path] = {e['engine'] for e in engines if e['status'] == 'complete'}
            pairs_by_path[path] = surface['pairs']
            if paired:
                if not isinstance(surface['leaks'], list) or len(surface['leaks']) > MAX_LEAKS:
                    raise Unavailable('invalid paired leak evidence')
                local_leaks = merge_leaks(surface['leaks'])
                if sum(len(leak['locations']) for leak in local_leaks) > MAX_LOCATIONS:
                    raise Unavailable('paired location bound')
                for leak in local_leaks:
                    if surface['pairs'] == 0:
                        raise Unavailable('hit contradicts empty literal surface')
                    if any(detector['engine'] not in completed_by_path[path] for detector in leak['detectors']):
                        raise Unavailable('paired hit detector unavailable on this surface')
                    if any(loc['path'] != path or set(loc) - {'path', 'line'} for loc in leak['locations']):
                        raise Unavailable('foreign paired content location')
                paired_leaks.extend(local_leaks)
        if marker['complete'] != all_complete or (marker['status'] == 'collected') != all_complete:
            raise Unavailable('contradictory complete scan status')
        if not isinstance(marker['leaks'], list) or len(marker['leaks']) > MAX_LEAKS:
            raise Unavailable('invalid leak evidence')
        leaks = merge_leaks(marker['leaks'])
        if paired and leaks != merge_leaks(paired_leaks):
            raise Unavailable('global leak union contradicts per-surface evidence')
        if sum(len(leak['locations']) for leak in leaks) > MAX_LOCATIONS:
            raise Unavailable('leak location bound')
        for leak in leaks:
            for loc in leak['locations']:
                path = loc['path']
                if path not in completed_by_path or set(loc) - {'path', 'line'}:
                    raise Unavailable('foreign content location')
                if pairs_by_path[path] == 0:
                    raise Unavailable('hit contradicts empty literal surface')
                if not paired and any(detector['engine'] not in completed_by_path[path] for detector in leak['detectors']):
                    raise Unavailable('hit detector unavailable on its environment surface')
        evidence = {'secret_leaks': deepcopy(leaks), 'credential_validation': 'not_attempted',
                    'complete': all_complete, 'surfaces': deepcopy(surfaces)}
        if paired:
            evidence['function_secret_projection_schema'] = PAIRED_SCHEMA
        if leaks:
            observed = 'A likely secret was detected in the function’s literal environment values. The value is hidden; detection did not validate the credential.'
            if not all_complete:
                observed += ' Coverage is incomplete; a completed detector still reported this secret.'
            return 'FAIL', {**evidence, 'observed': observed}
        if not all_complete:
            raise Unavailable('incomplete detector coverage')
        return 'PASS', {**evidence, 'observed': 'Both offline detectors completed without finding a supported secret in the returned runtime and build environment values.'}
    except (Unavailable, KeyError, TypeError, ValueError, AttributeError):
        return 'UNKNOWN', {'observed': 'Literal environment scanning is disabled, incomplete, unreadable or unbound; secret absence could not be assessed.'}


evaluate = _evaluate
