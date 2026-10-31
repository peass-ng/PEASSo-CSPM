"""Opt-in bounded category indicators; partial association, not Kingfisher parity.

Offline Kingfisher SDK and TruffleHog detection; no external credential
validation, historical branches or older log windows.
AWS GetFile and FilterLogEvents documentation define the acquisition bounds:
https://docs.aws.amazon.com/codecommit/latest/APIReference/API_GetFile.html
https://docs.aws.amazon.com/codecommit/latest/APIReference/API_GetFolder.html
https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_FilterLogEvents.html
"""
import copy
import re
from . import result, unknown
from .facts import Unavailable

REVISION = '1783527c1147f584f30b60f2d7ccc8a53b4a63b7'
KINDS = {'repository': 'codecommit_repository', 'logs': 'log_group'}
IDS = {key: 'aws.review.' + ('codecommit.default_commit_secret_indicators' if key == 'repository' else 'cloudwatch.sampled_log_secret_indicators') for key in KINDS}
CATEGORIES = {'private_key', 'cloud_credential', 'password_assignment', 'secret'}


def _evaluate(item, index, mode):
    try:
        if not isinstance(item, dict) or not isinstance(index, dict):
            raise Unavailable('content evidence malformed')
        context = index['context']
        if context['provider'] != 'aws':
            raise Unavailable('foreign provider')
        account, region = context['scope'].split('/')
        if re.fullmatch('[0-9]{12}', account) is None or not region or region == 'global':
            raise Unavailable('native account/Region scope missing')
        envelopes = index['collections'][KINDS[mode]]
        if not isinstance(envelopes, list):
            raise Unavailable('native collection missing')
        matching = [row for row in envelopes if isinstance(row, dict) and row.get('scope') == context['scope'] and row.get('status') in ('collected', 'partial') and isinstance(row.get('items'), list) and item in row['items']]
        if len(matching) != 1:
            raise Unavailable('native membership unbound')
        sample = item['ContentSecretIndicators']
        if not isinstance(sample, dict) or sample.get('profile') != 'aws-code-log-content-indicators-v1' or sample['scope'] != ('bounded_default_commit_files' if mode == 'repository' else 'bounded_log_window'):
            raise Unavailable('content scope differs')
        if sample['collection_status'] not in ('collected', 'partial'):
            raise Unavailable('content scan disabled, denied or unavailable')
        if sample['region'] != region or sample['account_id'] != account:
            raise Unavailable('foreign account or Region')
        identity = sample['identity']
        if mode == 'repository':
            name = item['repositoryName']
            if sample['repository'] != name or re.fullmatch(r'arn:[a-z0-9-]+:codecommit:' + re.escape(region) + ':' + account + ':' + re.escape(name), identity) is None or item.get('Arn', identity) != identity:
                raise Unavailable('foreign repository')
            if not isinstance(sample['branch'], str) or not sample['branch'] or re.fullmatch('[0-9a-f]{40}', sample['commit']) is None:
                raise Unavailable('default branch/commit unbound')
        else:
            name = item['logGroupName']
            if sample['group'] != name or identity != (item.get('arn') or item.get('logGroupArn')) or re.fullmatch(r'arn:[a-z0-9-]+:logs:' + re.escape(region) + ':' + account + ':log-group:' + re.escape(name) + r'(?::\*)?', identity) is None:
                raise Unavailable('foreign log group')
            start, end = sample['start'], sample['end']
            if type(start) is not int or type(end) is not int or not 0 <= start < end or end-start > 86400000:
                raise Unavailable('log window unbound')
        records = sample['records']
        # Log windows are read to the end: clean events fold into counters and
        # only events needing review keep a record.
        from peaso.collectors.aws_code_log_content_indicators import MAX_LOG_BYTES, MAX_LOG_EVENTS, MAX_LOG_RECORDS
        record_cap, byte_cap = (128, 1048576) if mode == 'repository' else (MAX_LOG_RECORDS, MAX_LOG_BYTES)
        clean_bytes = sample.get('clean_bytes', 0) + sample.get('omitted_bytes', 0) if mode == 'logs' else 0
        inspected_events = sample.get('events_inspected', len(records)) if mode == 'logs' else len(records)
        if not isinstance(records, list) or len(records) > record_cap or type(sample['complete']) is not bool or type(sample['inspected_bytes']) is not int or not 0 <= sample['inspected_bytes'] <= byte_cap or not isinstance(sample['errors'], list):
            raise Unavailable('sample bound malformed')
        if type(clean_bytes) is not int or clean_bytes < 0 or type(inspected_events) is not int or not len(records) <= inspected_events <= MAX_LOG_EVENTS + len(records):
            raise Unavailable('log event accounting malformed')
        witnesses, seen, counted_bytes = [], set(), 0
        for record in records:
            if not isinstance(record, dict) or type(record['readable']) is not bool or not isinstance(record['categories'], list) or any(not isinstance(c, str) or c not in CATEGORIES for c in record['categories']) or not record['readable'] and record['categories']:
                raise Unavailable('content indicator malformed')
            if type(record['size']) is not int or record['size'] < 0 or record['readable'] and record['size'] > 1048576:
                raise Unavailable('record size malformed')
            inspected = record['inspected_bytes']
            if type(inspected) is not int or inspected not in (0, record['size']) or record['readable'] and inspected != record['size']:
                raise Unavailable('record inspection accounting malformed')
            counted_bytes += inspected
            locator = record['path'] if mode == 'repository' else record['timestamp']
            if mode == 'repository':
                if not isinstance(locator, str) or re.fullmatch(r'/codecommit-path/[0-9a-f]{64}', locator) is None or locator in seen:
                    raise Unavailable('file path malformed')
                seen.add(locator)
            elif type(locator) is not int or not start <= locator < end:
                raise Unavailable('log timestamp outside selected window')
            if record['categories']:
                witnesses.append({('path' if mode == 'repository' else 'timestamp'): locator, 'categories': record['categories']})
        if counted_bytes + clean_bytes != sample['inspected_bytes']:
            raise Unavailable('inspected byte accounting differs')
        evidence = {'identity': identity, 'scope': sample['scope'], 'records_inspected': inspected_events,
                    'witnesses': witnesses, 'complete': sample['complete'],
                    'secret_leaks': [dict(leak, locations=[dict(loc, **({'timestamp': record['timestamp']} if mode == 'logs' else {})) for loc in leak['locations']]) for record in records for leak in record.get('leaks', [])],
                    'semantics': 'Offline Kingfisher and TruffleHog plus supplemental indicators; only the stated bounded source is assessed.'}
        if mode == 'repository':
            evidence.update(branch=sample['branch'], commit=sample['commit'])
        else:
            evidence.update(start=start, end=end)
        if witnesses:
            return result(True, **evidence, observed=f'High-confidence secret categories in {len(witnesses)} sampled record(s); review bounded evidence.')
        if matching[0]['status'] != 'collected' or not sample['complete'] or sample['collection_status'] != 'collected' or sample['errors'] or any(not r['readable'] or r.get('scanner_complete') is not True for r in records):
            return unknown('incomplete negative scan', **evidence, observed='No category proved in readable records; incomplete scope requires review.')
        return result(False, **evidence, observed=f'No supported secret categories in {inspected_events} inspected record(s); only declared bounded scope assessed.')
    except (Unavailable, KeyError, TypeError, ValueError, AttributeError):
        return unknown('content evidence missing, disabled, foreign or malformed', observed='Content scan unavailable or unbound; no secret-absence verdict.')


def repository(item, index):
    return _evaluate(item, index, 'repository')


def logs(item, index):
    return _evaluate(item, index, 'logs')


DECLARATIONS = []
ADMISSION_DATA = {'schema_version': 1, 'checks': []}
RUNTIME_CASES = {}
for mode, kind in KINDS.items():
    title = 'Bounded default-commit files have no supported secret indicators' if mode == 'repository' else 'Sampled log window has no supported secret indicators'
    declaration = {'id': IDS[mode], 'provider': 'aws', 'kind': kind, 'category': 'hardening', 'severity': 'high',
                   'control': 'IA-5', 'target': 'resource', 'dependencies': [kind], 'allow_incomplete_failure': True,
                   'title': title, 'remediation': 'Review the indicated file or log source, rotate exposed credentials and remove literal credentials at their source.', 'evaluator': mode}
    DECLARATIONS.append(declaration)
    source = ('codecommit/codecommit_repository_no_secrets/codecommit_repository_no_secrets.py' if mode == 'repository' else 'cloudwatch/cloudwatch_log_group_no_secrets_in_logs/cloudwatch_log_group_no_secrets_in_logs.py')
    sha = '151e0e4de9c1a98e96f3c1a23ba9f85e9c062efbc7ca2e0f15bcc44e8fb22304' if mode == 'repository' else 'b3a651f3371008872c5a263a004be3bf37124f0a26fbcf5523e17fd2538f32ee'
    description = 'Optional content_secret_scans=true. At most128 UTF-8 files/128folders at a bound default commit, every event within24h read to the end (bounded at 200000 events/128MiB per log group); at most1MiB repository bytes. Kingfisher SDK 1.4.0 and TruffleHog 3.92.5 run offline; each leak is deduplicated across engines and source locations. Both must finish for a complete negative result. Raw content never retained. GetFile cannot bound transferred bytes. No historical or unseen-content safety claim.'
    ADMISSION_DATA['checks'].append({'spec': {'id': IDS[mode], 'provider': 'aws', 'resource_kind': kind, 'data_source': 'ContentSecretIndicators', 'predicate': 'Proven category FAIL even on partial sample; negative incomplete/disabled UNKNOWN; complete bounded category-negative PASS only.', 'severity': 'high', 'category': 'hardening', 'title': title, 'description': description, 'remediation_hint': declaration['remediation']}, 'description': {'description': description, 'evaluated': ['ContentSecretIndicators'], 'pass_when': 'Complete declared bounded scope contains no supported category.', 'fail_when': 'Bound native content includes a high-confidence category, even on a partial sample.', 'not_applicable_when': 'Never inferred from disabled or missing content; these remain UNKNOWN.'}, 'sources': [{'url': f'https://github.com/prowler-cloud/prowler/blob/{REVISION}/prowler/providers/aws/services/{source}', 'sha256': sha}], 'requirements': [], 'review_notes': 'Partial corrected association only: bounded dual-engine detection does not imply exhaustive upstream coverage; no validator execution or content retention. No Steampipe SQL secret-content equivalence.', 'function': f'peaso.checks.aws_code_log_content_review_20261019:{mode}'})
    arn = 'arn:aws:codecommit:us-east-1:123456789012:demo' if mode == 'repository' else 'arn:aws:logs:us-east-1:123456789012:log-group:demo:*'
    sample = {'profile': 'aws-code-log-content-indicators-v1', 'identity': arn, 'account_id': '123456789012', 'region': 'us-east-1', 'collection_status': 'collected', 'scope': 'bounded_default_commit_files' if mode == 'repository' else 'bounded_log_window', 'complete': True, 'inspected_bytes': 10, 'errors': [], 'records': [{'path': '/codecommit-path/60e6c092e589ae7ea7cda13ae578d5db44659f1bd209e24be0063a9b1a561705', 'size': 10, 'inspected_bytes': 10, 'readable': True, 'scanner_complete': True, 'categories': []} if mode == 'repository' else {'timestamp': 10, 'size': 10, 'inspected_bytes': 10, 'readable': True, 'scanner_complete': True, 'categories': []}]}
    sample.update({'repository': 'demo', 'branch': 'main', 'commit': 'a'*40} if mode == 'repository' else {'group': 'demo', 'start': 1, 'end': 100})
    positive = {'repositoryName': 'demo', 'Arn': arn} if mode == 'repository' else {'logGroupName': 'demo', 'arn': arn}
    positive['ContentSecretIndicators'] = sample
    negative = copy.deepcopy(positive)
    positive['ContentSecretIndicators']['records'][0]['categories'] = ['private_key']
    def _index(item):
        return {'context': {'provider': 'aws', 'scope': '123456789012/us-east-1'}, 'collections': {kind: [{'type': kind, 'status': 'collected', 'scope': '123456789012/us-east-1', 'account_id': '123456789012', 'region': 'us-east-1', 'items': [item]}]}, kind: [{'data': item}]}
    RUNTIME_CASES[IDS[mode]] = {'pass': negative, 'fail': positive, 'pass_index': _index(negative), 'fail_index': _index(positive), 'missing': {}, 'malformed': None}
