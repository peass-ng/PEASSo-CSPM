"""Default-off selected registry image runtime; credentials remain collector-owned."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from weakref import WeakValueDictionary
from peaso import gcp_image_selection_20261021 as selection_api
CHECK_ID = 'gcp.review.artifact_image.selected_image_vulnerabilities'
KIND = 'artifact_selected_image_vulnerabilities'
OPTION = selection_api.OPTION
ENABLE = selection_api.ENABLE
SERVICE = 'artifactregistry'
GRANT = '_gcp_registry_image_vulnerability_engine_grant'
_SEAL = object()
_ISSUED = WeakValueDictionary()
selections = selection_api.selections

def _selection_hash(targets):
    return hashlib.sha256(json.dumps(targets, sort_keys=True,
                                     separators=(',', ':')).encode()).hexdigest()

class _Grant:
    __slots__ = ('seal', 'scopes', 'selection', 'check', 'enabled', '__weakref__')

    def __init__(self, scopes, targets):
        self.seal = _SEAL
        self.scopes = tuple(scopes)
        self.selection = _selection_hash(targets)
        self.check = CHECK_ID
        self.enabled = True

def issue_engine_grant(options, scopes, named=()):
    """Engine only: issue after actual registry selection of the named check."""
    prior = options.pop(GRANT, None)
    if type(prior) is _Grant and _ISSUED.get(id(prior)) is prior:
        _ISSUED.pop(id(prior))
    if CHECK_ID not in named:
        return
    targets = selections(options, scopes)
    if CHECK_ID not in named or options.get(ENABLE) is not True:
        return
    if not targets:
        raise ValueError('exact_job_image_selectors_required')
    token = _Grant(scopes, targets)
    _ISSUED[id(token)] = token
    options[GRANT] = token

def authorize_collector(options, scopes):
    """Consume once, before credentials, transport, sessions, or scanner I/O."""
    token = options.get(GRANT)
    targets = selections(options, scopes)
    permitted = (type(token) is _Grant and _ISSUED.get(id(token)) is token
        and token.seal is _SEAL and token.scopes == tuple(scopes)
        and token.selection == _selection_hash(targets)
        and token.check == CHECK_ID and token.enabled is True
        and options.get(ENABLE) is True and bool(targets))
    if not permitted:
        raise ValueError('selected_job_image_vulnerability_grant_required')
    _ISSUED.pop(id(token))
    options.pop(GRANT, None)
    return targets


def prepare(options, scopes, wanted):
    if KIND not in wanted:
        return []
    targets = selections(options, scopes)
    if options.get(ENABLE) is not True:
        return []
    if not targets:
        raise ValueError('exact_registry_images_required')
    return authorize_collector(options, scopes)


def collect_selected(transport, *, scope, targets, **kwargs):
    from peaso.checks import gcp_registry_trivy_review_20261021 as review
    from . import gcp_registry_trivy_20261021 as source
    raw = source.collect_native(transport, scope=scope, selectors=targets, enabled=True, **kwargs)
    rows, observations = [], []
    for row in raw['rows']:
        scan = row.get('scan')
        reference = row['immutable_reference']
        record = review.project(reference, scope, scan) if isinstance(scan, dict) else None
        ids = row['source_requests']
        ledger = [deepcopy(r) for r in raw['source_requests'] if r.get('id') in ids]
        status, _ = review.evaluate(record, {'scope':scope,'selections':targets,'source_requests':ledger})
        rows.append({'immutable_reference':reference,'status':status,
                     'complete':row['complete'] and status != 'UNKNOWN',
                     'reason':row['reason'],'vulnerability_record':record,
                     'source_requests':deepcopy(ids),'source_ledger':ledger})
        if isinstance(scan, dict) and 'graph' in scan:
            observations.extend(index_observations(reference, scope, scan))
        else:
            observations.append({'asset_id':reference,'asset_kind':KIND,'provider':'gcp','scope':scope,
                                 'scan':deepcopy(scan)} if isinstance(scan,dict) else None)
    complete = len(rows) == len(targets) and all(r['complete'] for r in rows)
    status = 'FAIL' if any(r['status']=='FAIL' for r in rows) else 'PASS' if complete else 'UNKNOWN'
    return {'kind':KIND,'check_id':CHECK_ID,'status':status,'complete':complete,
            'rows':rows,'observations':observations}


def index_observations(reference, scope, scan):
    """Project verified child scans for the existing image findings table."""
    children = scan.get('graph', {}).get('children', [])
    if not children:
        return [None]
    parent_complete = scan.get('complete') is True
    base = reference.rsplit('@', 1)[0]
    observations = []
    for child in children:
        digest = child['digest']
        findings = [deepcopy(finding) for finding in scan.get('findings', [])
                    if finding.get('image_digest') == digest]
        complete = parent_complete and child['complete'] and child['scan_complete']
        complete = complete and child['database_fresh']
        child_scan = {'image': {'provider':'gcp','scope':scope,
            'immutable_reference':base + '@' + digest, 'manifest_digest':digest,
            'config_digest':child['config']['digest']},
            'status':'FAIL' if findings else 'PASS' if complete else 'UNKNOWN',
            'complete':complete, 'scan_complete':child['scan_complete'],
            'coverage_status':'COMPLETE' if complete else 'UNKNOWN',
            'database':{'fresh':child['database_fresh']}, 'findings':findings}
        observations.append({'asset_id':reference,'asset_kind':KIND,'provider':'gcp',
                             'scope':scope,'scan':child_scan})
    if not parent_complete:
        observations.append(None)  # Preserve missing child coverage in the table.
    return observations


def enrich(collector):
    targets = getattr(collector, 'registry_image_vulnerability_targets', [])
    if not targets:
        return
    from peaso.trivy_database_20261021 import database_lease, DatabaseUnavailable
    from peaso import trivy_container_runner_20261020 as trivy
    import subprocess
    from concurrent.futures import ThreadPoolExecutor
    from contextvars import copy_context
    groups = selection_api.grouped_selections({**collector.options, OPTION: targets}, list(collector.scopes))
    selected_scopes = [scope for scope, references in groups.items() if references]

    def unavailable(scope, references, reason):
        return {'kind': KIND, 'check_id': CHECK_ID, 'status': 'UNKNOWN', 'complete': False,
            'rows': [{'immutable_reference': ref, 'status': 'UNKNOWN', 'complete': False,
                      'reason': reason, 'vulnerability_record': None,
                      'source_requests': [], 'source_ledger': []} for ref in references],
            'observations': [None for _ in references]}

    def collect_scope(scope, cache):
        references = groups[scope]
        try:
            cli = next((path for path in (trivy.DEFAULT_CLI, '/opt/homebrew/bin/trivy')
                        if Path(path).is_file()), trivy.DEFAULT_CLI)
            return collect_selected(collector.transport, scope=scope, targets=references,
                                    db_cache=cache, cli=cli)
        except (DatabaseUnavailable, OSError, subprocess.SubprocessError):
            return unavailable(scope, references, 'database_unavailable')

    results = {}
    try:
        with database_lease(enabled=True) as cache:
            # Each exact native project has its own readers/receipts; share only
            # the read-only database lease and the connector's authenticated transport.
            workers = min(2, len(selected_scopes), max(1, int(collector.options.get('concurrency', 4))))
            if workers > 1:
                with ThreadPoolExecutor(max_workers=workers, thread_name_prefix='gcp-registry-project') as pool:
                    futures = {scope: pool.submit(copy_context().run, collect_scope, scope, cache)
                               for scope in selected_scopes}
                    results = {scope: futures[scope].result() for scope in selected_scopes}
            else:
                results = {scope: collect_scope(scope, cache) for scope in selected_scopes}
    except (DatabaseUnavailable, OSError, subprocess.SubprocessError):
        for scope in selected_scopes:
            results.setdefault(scope, unavailable(scope, groups[scope], 'database_unavailable'))
    rows, observations = [], []
    for scope in collector.scopes:
        result = results.get(scope)
        if result is None:
            collector.collections[(KIND, scope)] = {'type': KIND, 'scope': scope, 'service': SERVICE,
                'status': 'empty', 'coverage_status': 'empty', 'items': [], 'source_requests': []}
            continue
        rows.extend(result['rows']); observations.extend(result['observations'])
        items = [{'name': row['immutable_reference'], '_resource_id': row['immutable_reference'],
                  'native_id': row['immutable_reference'], 'RegistryImageVulnerabilityReview': deepcopy(row)}
                 for row in result['rows']]
        collector.collections[(KIND, scope)] = {'type': KIND, 'scope': scope, 'service': SERVICE,
            'status': 'collected' if result['complete'] else 'partial',
            'coverage_status': 'collected' if result['complete'] else 'partial', 'items': items,
            'source_requests': [rid for row in result['rows'] for rid in row['source_requests']]}
    complete = len(rows) == len(targets) and all(row['complete'] for row in rows)
    collector.registry_image_vulnerability_result = {'kind': KIND, 'check_id': CHECK_ID,
        'status': 'FAIL' if any(row['status'] == 'FAIL' for row in rows) else 'PASS' if complete else 'UNKNOWN',
        'complete': complete, 'rows': rows, 'observations': observations}


def finish_metadata(collector, metadata):
    targets = getattr(collector,'registry_image_vulnerability_targets',[])
    if not targets:
        return
    metadata[OPTION]=list(targets)
    result=getattr(collector,'registry_image_vulnerability_result',None)
    observations=result['observations'] if result is not None else [None for _ in targets]
    old=metadata.get('image_vulnerability_scan',{})
    prior=old.get('observations',[]) if old.get('selected') is True else []
    metadata['image_vulnerability_scan']={'selected':True,'observations':deepcopy(prior+observations)}
