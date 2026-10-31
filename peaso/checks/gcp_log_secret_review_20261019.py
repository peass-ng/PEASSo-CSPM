"""Pure, unregistered predicate for a bounded application-log sample."""
from copy import deepcopy
from datetime import timedelta, datetime, timezone

from .facts import get, Unavailable
from peaso.collectors.gcp_log_secret_indicators import (
    KIND, SCHEMA, SCOPE, PATH, stamp, MAX_ENTRIES, MAX_PAGES, MAX_SAMPLE_BYTES, PAGE_SIZE,
)
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION

CHECK_ID = 'gcp.review.logging.application_log_secret_indicators'
DECLARATION = {'id': CHECK_ID, 'provider': 'gcp', 'category': 'hardening', 'kind': KIND,
    'finding_type': 'secrets', 'severity': 'high', 'dependencies': [KIND], 'requirements': [],
    'title': 'Sampled application log messages have no detected secrets',
    'remediation': 'Remove credentials from application logging and rotate confirmed exposed credentials.',
    'evidence_sentences': ['A likely secret was detected in the sampled application log messages.',
        'The value is hidden; offline detection did not validate the credential.']}


def evaluate(item, index):
    try:
        scope = get(index, 'context.scope', str)
        if get(index, 'context.provider', str) != 'gcp' or not SCOPE.fullmatch(scope):
            raise Unavailable('scope')
        sample = get(item, 'sample', dict)
        if (set(sample) != {'schema', 'scope', 'start', 'end', 'complete', 'entries', 'bytes', 'pages', 'scans', 'leaks', 'verification'}
                or sample['schema'] != SCHEMA or sample['scope'] != scope
                or sample['complete'] is not True or sample['verification'] != 'not_attempted'):
            raise Unavailable('incomplete')
        first, last = stamp(sample['start']), stamp(sample['end'])
        if not timedelta(0) < last - first <= timedelta(hours=1) or last > datetime.now(timezone.utc):
            raise Unavailable('window')
        if get(item, 'name', str) != scope + '/logSecretSamples/' + last.strftime('%Y%m%dT%H%M%S'):
            raise Unavailable('identity')
        collections = get(index, 'collections.' + KIND, list)
        matching = [c for c in collections if isinstance(c, dict) and c.get('scope') == scope]
        if (len(matching) != 1 or matching[0].get('status') != 'collected'
                or not isinstance(matching[0].get('items'), list) or len(matching[0]['items']) != 1
                or matching[0]['items'][0] != item):
            raise Unavailable('collection')
        for field, low, high in [('entries', 0, MAX_ENTRIES), ('bytes', 0, MAX_SAMPLE_BYTES), ('pages', 1, MAX_PAGES)]:
            if type(sample[field]) is not int or not low <= sample[field] <= high:
                raise Unavailable('bound')
        scans = sample['scans']
        if not isinstance(scans, list) or not sample['pages'] <= len(scans) <= MAX_ENTRIES + MAX_PAGES:
            raise Unavailable('scan coverage')
        paths = set()
        counts = {p: [] for p in range(1, sample['pages'] + 1)}
        expected = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        for scan in scans:
            if (not isinstance(scan, dict) or set(scan) != {'path', 'complete', 'engines'}
                    or scan['complete'] is not True or not isinstance(scan['path'], str)
                    or not PATH.fullmatch(scan['path']) or scan['path'] in paths):
                raise Unavailable('scan')
            path = scan['path']
            paths.add(path)
            parts = path.split('/')
            if int(parts[1]) not in counts:
                raise Unavailable('page')
            counts[int(parts[1])].append(0 if parts[2] == 'empty' else int(parts[3]))
            engines = scan['engines']
            if (not isinstance(engines, list) or len(engines) != 2
                    or any(not isinstance(e, dict) or set(e) != {'engine', 'version', 'status'}
                           or e.get('version') != expected.get(e.get('engine'))
                           or e.get('status') != 'complete' for e in engines)
                    or {e['engine'] for e in engines} != set(expected)):
                raise Unavailable('both pinned detectors required')
        for nums in counts.values():
            if nums != [0] and (not nums or sorted(nums) != list(range(1, len(nums) + 1)) or len(nums) > PAGE_SIZE):
                raise Unavailable('message coverage')
        if sum(n != 0 for nums in counts.values() for n in nums) != sample['entries']:
            raise Unavailable('entry coverage')
        if not isinstance(sample['leaks'], list) or len(sample['leaks']) > 256:
            raise Unavailable('leaks')
        leaks = merge_leaks(sample['leaks'])
        if sum(len(x['locations']) for x in leaks) > 512:
            raise Unavailable('locations')
        for leak in leaks:
            for loc in leak['locations']:
                if set(loc) - {'path', 'line'} or loc['path'] not in paths or loc['path'].endswith('/empty'):
                    raise Unavailable('unbound detection')
        evidence = {'secret_leaks': deepcopy(leaks), 'credential_validation': 'not_attempted',
                    'sample': {k: deepcopy(sample[k]) for k in ('scope', 'start', 'end', 'entries', 'pages', 'scans')}}
        if leaks:
            return 'FAIL', {**evidence, 'observed': 'A likely secret was detected in the sampled application log messages. The value is hidden; offline detection did not validate the credential.'}
        return 'PASS', {**evidence, 'observed': 'Both offline detectors found no supported secret in the sampled returned application messages. This does not assess other logs or history.'}
    except (Unavailable, ValueError, KeyError, TypeError, AttributeError, OverflowError):
        return 'UNKNOWN', {'observed': 'Application log sampling is disabled, incomplete, unreadable or unbound; secret absence could not be assessed.'}


def install():
    import gzip
    import json
    from pathlib import Path
    from . import CHECKS, register
    from .fixtures import CASES
    if any(c.id == CHECK_ID for c in CHECKS):
        return
    register(CHECK_ID, 'gcp', 'hardening', KIND, DECLARATION['title'], 'high',
             'security_configuration', DECLARATION['remediation'])(evaluate)
    case = json.loads(gzip.decompress(Path(__file__).with_name(
        'gcp_log_secret_fixtures.json.gz').read_bytes()))['cases'][CHECK_ID]
    CASES[CHECK_ID] = {'missing': {}, 'malformed': None}
    for branch in ('pass', 'fail', 'unknown'):
        CASES[CHECK_ID][branch] = deepcopy(case[branch]['item'])
        CASES[CHECK_ID][branch + '_index'] = deepcopy(case[branch]['index'])
