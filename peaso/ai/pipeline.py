"""Bounded post-scan agents. AI errors never discard deterministic results."""
import copy
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from concurrent.futures import CancelledError
from urllib.parse import unquote

from peaso.auth.secrets import redact, secret_values
from .crypto import AICipher
from peaso.server.config import Settings
from .auth import personal_token
from .contracts import validate_actions, validate_network
from . import isolation


def _priorities_have_evidence(report, reviews, network_input):
    """Match action-reference eligibility, excluding unobserved network paths."""
    metadata = report.get('check_meta') or {}
    rejected = {row['finding_id'] for row in reviews if row['verdict'] != 'FAIL'}
    for row in report.get('findings', []):
        if row.get('id') in rejected:
            continue
        status = row.get('status')
        category = row.get('category', (metadata.get(row.get('check_id')) or {}).get('category'))
        if status == 'FAIL' or (status in ('MANUAL', 'UNKNOWN') and
                                (category == 'privesc' or category == 'network' and network_input is not None)):
            return True
    return False


def private_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        from peaso.secret_evidence import without_private_values
        json.dump(without_private_values(value), stream, default=str)


def kill_tree(process):
    import psutil
    try:
        descendants = psutil.Process(process.pid).children(recursive=True)
    except psutil.NoSuchProcess:
        descendants = []
    for child in reversed(descendants):
        try:
            child.kill()
        except psutil.NoSuchProcess:
            pass
    if process.poll() is None:
        process.kill()
    process.wait(timeout=5)


def invoke(stage, platform, entries, token, findings, reviews, timeout, *, cancel_event=None):
    if cancel_event is not None and cancel_event.is_set():
        raise CancelledError()
    if any(entry.get('provider') == 'aws' for entry in entries):
        raise ValueError('aws_live_ai_access_disabled')
    stop_at = time.monotonic() + timeout
    # Chack's Codex backend enables unrestricted shell tools. Refuse to start
    # it in the platform process namespace, even with a clean environment.
    remote = isolation.remote()
    if remote:
        from .fargate import configuration
        configuration()
    else:
        isolation.launcher()
        from .providers import validate_before_launch
        token = validate_before_launch(token)
    categories = {'network': set(), 'priorities': {'hardening', 'exposure'}}
    if stage not in categories:
        raise ValueError('unknown_ai_stage')
    # Enforce the scope again before creating findings.json. A caller error
    # must never send passed, unresolved or unrelated checks to an agent.
    if any(row.get('status') != 'FAIL' or row.get('category') not in categories[stage]
           for row in findings):
        raise ValueError('ai_findings_out_of_scope')
    import psutil  # Require descendant cleanup before starting Chack/Codex.
    del psutil
    with tempfile.TemporaryDirectory(prefix='cspm-ai-') as directory:
        root = Path(directory)
        os.chmod(root, 0o700)
        files = {'credentials': {'version': 2, 'entries': entries}}
        if not remote:
            from .providers import auth_document
            files['codex-auth'] = auth_document(token)
        if stage == 'priorities':
            from .briefing import build
            build(root, platform, findings, reviews, private_json)
        elif stage == 'network':
            from .network import build
            build(root, platform, reviews, private_json)
        for name, data in files.items():
            private_json(root / (name + '.json'), data)
        if remote:
            from .fargate import invoke as invoke_remote
            if cancel_event is None:
                return invoke_remote(stage, root, token, max(.001, stop_at - time.monotonic()))
            def cancellable_sleep(seconds):
                if cancel_event.wait(seconds):
                    raise CancelledError()
            return invoke_remote(stage, root, token, max(.001, stop_at - time.monotonic()),
                                 sleep=cancellable_sleep)
        # Allowlist, never a copy of os.environ: scanner/cloud/platform credentials
        # and default credential discovery locations must not reach the agent.
        env = {'PATH': os.getenv('PATH', '/usr/local/bin:/usr/bin:/bin'), 'HOME': directory,
               'TMPDIR': directory, 'LANG': 'C.UTF-8', 'PYTHONUNBUFFERED': '1',
               'PYTHONPATH': str(Path(__file__).resolve().parents[2]),
               'CODEX_HOME': str(root / '.codex'), 'AWS_EC2_METADATA_DISABLED': 'true'}
        remaining = stop_at - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        command = isolation.wrap_command([sys.executable, '-m', 'peaso.ai.runner', stage], directory)
        from .deadline import ENVIRONMENT_KEY, timeout_seconds
        env[ENVIRONMENT_KEY] = str(timeout_seconds(remaining))
        process = subprocess.Popen(command, cwd=directory,
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            if cancel_event is None:
                process.wait(timeout=max(0, stop_at - time.monotonic()))
            else:
                while process.poll() is None:
                    if cancel_event.is_set():
                        raise CancelledError()
                    remaining = stop_at - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError()
                    try:
                        process.wait(timeout=min(.2, remaining))
                    except subprocess.TimeoutExpired:
                        pass
            if process.returncode == 78:
                from .providers import launch_error
                raise launch_error(token)
            if process.returncode or not (root / 'result.json').is_file():
                raise RuntimeError('agent_failed')
            if (root / 'result.json').stat().st_size > 8_000_000:
                raise ValueError('agent_output_too_large')
            return json.loads((root / 'result.json').read_text())
        finally:
            kill_tree(process)


def invoke_before_deadline(stage, platform, entries, token, findings, reviews, end, limit,
                           *, cancel_event=None):
    from .fargate import TaskStartupError
    for attempt in range(2):
        remaining = end - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        try:
            if cancel_event is None:
                return invoke(stage, platform, entries, token, findings, reviews, min(limit, remaining))
            return invoke(stage, platform, entries, token, findings, reviews, min(limit, remaining),
                          cancel_event=cancel_event)
        except TaskStartupError:
            if attempt:
                raise


def inputs(report):
    from peaso.engine import hydrate_finding
    rows = [hydrate_finding(row, report.get('check_frameworks'), report.get('check_meta'),
        report.get('check_meta_encoding'), report.get('remediation_templates')) for row in report.get('findings', [])]
    failed = [row for row in rows if row.get('status') == 'FAIL']
    hardening = [row for row in failed if row.get('category') == 'hardening']
    def key(row):
        return (row.get('check_id'), row.get('resource_id'), row.get('scope'))
    # Only exact control + resource + scope matches can share a review.
    known = {key(row): row['id'] for row in hardening}
    duplicates = {row['id']: known[key(row)] for row in failed if row.get('category') == 'exposure' and key(row) in known}
    exposure = [row for row in failed if row.get('category') == 'exposure' and row['id'] not in duplicates]
    return hardening, exposure, duplicates


def native_exposure_reviews(exposure, duplicates):
    """Stable native FAIL verdicts for K8s Exposure when its AI stage is off."""
    return [{'finding_id': ident, 'verdict': 'FAIL', 'reason': ''}
            for ident in sorted({row['id'] for row in exposure} | set(duplicates))]


def referenced_strings(value):
    """Exact resource references in this batch, never a whole-account inventory join."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from referenced_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from referenced_strings(item)


def review_context(report, inventory_by_id, findings, *, _references=None, _coverage=None):
    references = set(referenced_strings(findings)) if _references is None else _references
    from .collection_coverage import index, for_findings
    coverage = for_findings(index(report.get('coverage')) if _coverage is None else _coverage, findings)
    scan = {key: report[key] for key in ('provider', 'snapshot_id', 'created_at') if key in report}
    if coverage is not None:
        scan['collection_coverage'] = coverage
    return {'scan': scan,
            'resources': [inventory_by_id[ident] for ident in sorted(references & inventory_by_id.keys())]}


_STATIC_EVIDENCE = None


def _evidence_summary():
    """The reviewed evidence_summary, without importing the native check registry when it is not loaded.

    Review-stage children import nothing from peaso.checks except through this
    call; the hash-pinned static loader runs the same reviewed source bytes and
    returns the same text. Any drift in its pinned closure falls back to native.
    """
    global _STATIC_EVIDENCE
    if 'peaso.checks' not in sys.modules and _STATIC_EVIDENCE is not False:
        if _STATIC_EVIDENCE is None:
            try:
                from peaso.server.evidence_static import evidence_summary, verify_closure
                verify_closure()
                _STATIC_EVIDENCE = evidence_summary
            except ImportError:
                _STATIC_EVIDENCE = False
                return _evidence_summary()
        return _STATIC_EVIDENCE
    from peaso.finding_observation import evidence_summary
    return evidence_summary


def findings_document(scan, findings, resources=(), *, _references=None):
    """Keep each finding's evidence and exact native references in one record."""
    inventory_by_id = {row['id']: row for row in resources}
    items = []
    for position, finding in enumerate(findings):
        references = (set(referenced_strings(finding)) if _references is None
                      else _references[position]) & inventory_by_id.keys()
        observation = _evidence_summary()(finding)
        item = dict(finding, supporting_resources=[inventory_by_id[ident] for ident in sorted(references)])
        if observation:
            item['evidence_summary'] = observation
        items.append(item)
    scan_document = {key: scan[key] for key in ('provider', 'snapshot_id', 'created_at') if key in scan}
    coverage = scan.get('collection_coverage')
    if isinstance(coverage, dict) and isinstance(coverage.get('entries'), list):
        from .collection_coverage import index, for_findings
        bounded = for_findings(index([dict(row, level='collection') for row in coverage['entries']
                                      if isinstance(row, dict)]), findings)
        if bounded is not None:
            bounded['truncated'] = bounded['truncated'] or coverage.get('truncated') is not False
            scan_document['collection_coverage'] = bounded
    return {'scan': scan_document, 'items': items}


# Control-definition fields shared by every finding of one check. Finding
# evidence, targets and resources are never moved out of their own item.
SHARED_CHECK_FIELDS = ('title', 'description', 'rationale', 'remediation', 'frameworks', 'evaluated',
                       'pass_when', 'fail_when', 'not_applicable_when', 'clarity_evaluation_contract',
                       'category', 'service', 'severity', 'finding_type', 'status', 'provider')
_MISSING = object()


def compact_document(document):
    """Write each check's repeated control definition once per reviewer batch.

    A field moves to checks[check_id] only when every item of that check in
    the batch has the same value, so {**checks[item['check_id']], **item}
    restores every item exactly.
    """
    groups = {}
    for item in document['items']:
        check = item.get('check_id')
        if isinstance(check, str):
            groups.setdefault(check, []).append(item)
    checks = {}
    for check, items in groups.items():
        shared = {}
        for field in SHARED_CHECK_FIELDS:
            value = items[0].get(field, _MISSING)
            if value is not _MISSING and all(item.get(field, _MISSING) == value for item in items[1:]):
                shared[field] = value
        if shared:
            checks[check] = shared
    if not checks:
        return document
    items = [{key: value for key, value in item.items() if key not in checks.get(item.get('check_id'), ())}
             if isinstance(item.get('check_id'), str) else item for item in document['items']]
    return {**document, 'checks': checks, 'items': items}


def review_fingerprints(report, inventory_by_id, findings, *, identity, entries):
    """Digest each reviewer's actual per-finding document and its access boundary.

    The access reference identifies the sealed captured credential set; no
    credential value or plaintext finding/resource is saved in stage metadata.
    """
    from .collection_coverage import index
    coverage = index(report.get('coverage'))
    fingerprints = {}
    document_coverage = {}
    for row in findings:
        # Reuse only this row's fresh references, then release them before
        # credential preparation and serialization. Nothing is cached across calls.
        references = set(referenced_strings(row))
        context = review_context(report, inventory_by_id, [row], _references=references,
                                 _coverage=coverage)
        # Coverage normalization depends only on this call's fixed receipts and
        # the finding scope. Prove its canonical form through the ordinary
        # document path once per scope; retain no finding/resource document.
        scope = row.get('scope') if isinstance(row.get('scope'), str) else None
        scan = context['scan']
        if scope in document_coverage:
            scan = {key: value for key, value in scan.items() if key != 'collection_coverage'}
        document = findings_document(scan, [row], context['resources'], _references=(references,))
        if scope not in document_coverage:
            document_coverage[scope] = document['scan'].get('collection_coverage')
        elif document_coverage[scope] is not None:
            document['scan']['collection_coverage'] = document_coverage[scope]
        del references
        # Checkpoint/final snapshot IDs and created_at values name separately
        # serialized views. The caller's complete-section data revision fence
        # supplies their provenance; finding evidence, referenced resources,
        # provider and credential capture/expiry still have to match exactly.
        document['scan'].pop('snapshot_id', None)
        document['scan'].pop('created_at', None)
        access = review_credentials(entries, report['provider'], [row], context)
        boundary_keys = ('format', 'provider', 'scope', 'account_id', 'identity_arn',
                         'audience', 'context_id', 'cluster_id', 'tenant_id',
                         'quota_project', 'target_scopes', 'subscription_ids',
                         'namespaces', 'endpoints', 'capture_policy',
                         'captured_at', 'expires_at')
        boundary = [{key: entry[key] for key in boundary_keys if key in entry}
                    for entry in access]
        payload = {'document': document, 'identity': identity, 'access_boundary': boundary}
        fingerprints[row['id']] = hashlib.sha256(json.dumps(
            payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
    return fingerprints


def review_credentials(entries, provider, findings, context):
    """Select credential contexts and assigned targets for this reviewer batch.

    GCP/Azure OAuth audiences and the resolved Kubernetes cluster are captured
    access contexts, not independently downscopable per-resource credentials.
    """
    from .access import scopes_overlap
    selected = [entry for entry in entries if entry.get('provider') == provider]
    requested_scopes = {row.get('scope') for row in findings + context.get('resources', []) if isinstance(row.get('scope'), str)}
    if not selected:
        # An absent provider access context cannot become selectable by
        # traversing native evidence; keep all supplied-context checks below.
        return []
    accounts = set()
    if provider == 'aws':
        account_reference = re.compile(r'^(?:arn:[^:]+:[^:]*:[^:]*:)?([0-9]{12})(?:/|:|$)')
        for value in referenced_strings([findings, context.get('resources', [])]):
            match = account_reference.match(value)
            if match:
                accounts.add(match.group(1))
    clusters = set()
    selected_clusters = set()
    if provider == 'k8s':
        selected_clusters = {entry.get('cluster_id') for entry in selected if entry.get('cluster_id')}
        if selected_clusters:
            def collect_clusters(value):
                if isinstance(value, dict):
                    if isinstance(value.get('cluster_id'), str):
                        clusters.add(value['cluster_id'])
                    for item in value.values():
                        collect_clusters(item)
                elif isinstance(value, (list, tuple)):
                    for item in value:
                        collect_clusters(item)
                elif isinstance(value, str) and value.startswith('k8s://'):
                    clusters.add(unquote(value[6:].split('/', 1)[0]))
            collect_clusters([findings, context.get('resources', [])])
    out = []
    for entry in selected:
        if provider == 'aws' and entry.get('account_id') not in accounts:
            continue
        if provider == 'k8s' and entry.get('cluster_id'):
            if clusters and entry['cluster_id'] not in clusters:
                continue
            if not clusters and len(selected_clusters) > 1:
                continue  # Namespace alone cannot identify one of several clusters.
        if 'target_scopes' not in entry:
            # Compatibility for old captured artifacts before target bindings.
            out.append(dict(entry))
            continue
        targets = [scope for scope in entry['target_scopes']
                   if any(scopes_overlap(scope, requested) for requested in requested_scopes)
                   or (provider == 'k8s' and (scope == '*' or '*' in requested_scopes))]
        if provider == 'aws' and entry['target_scopes']:
            global_scope = entry['account_id'] + '/global'
            if global_scope in requested_scopes:
                targets = sorted(set(targets) | {global_scope})
        if not targets:
            continue
        if provider == 'k8s' and '*' in targets and '*' not in requested_scopes:
            targets = sorted(requested_scopes)
        narrowed = dict(entry, target_scopes=targets)
        if provider == 'azure':
            narrowed['subscription_ids'] = sorted({scope.split('/')[2] for scope in targets if scope.startswith('/subscriptions/')})
        if provider == 'k8s':
            narrowed['namespaces'] = targets
        out.append(narrowed)
    return out


def available_memory():
    """Available bytes inside the task limit, rather than the host's RAM."""
    import psutil
    available = psutil.virtual_memory().available
    for limit_path, usage_path in (
        ('/sys/fs/cgroup/memory.max', '/sys/fs/cgroup/memory.current'),
        ('/sys/fs/cgroup/memory/memory.limit_in_bytes', '/sys/fs/cgroup/memory/memory.usage_in_bytes'),
    ):
        try:
            limit = int(Path(limit_path).read_text().strip())
            usage = int(Path(usage_path).read_text().strip())
            available = min(available, max(0, limit - usage))
        except (OSError, ValueError):
            continue
    return available


def review_concurrency():
    requested = int(os.getenv('PEASO_AI_MAX_CONCURRENCY', '2'))
    remote = isolation.remote()
    if not 1 <= requested <= (12 if remote else 6):
        raise ValueError('invalid_ai_concurrency')
    # Admission estimate, not an enforced per-process memory limit. Current
    # analyzer usage is already included in the cgroup's used memory. A
    # Fargate agent runs in its own task; locally it only stages its input
    # bundle and polls, so it reserves less than a local agent process. Keep
    # twice the former hosted staging allowance for the larger bounded pool.
    per_agent = (256 if remote else 512) * 1024**2
    capacity = max(0, (available_memory() - 128 * 1024**2) // per_agent)
    return min(requested, capacity)


def review_network(report, entries, token, network, end, *, cancel_event=None):
    """Run the sole pre-Priorities model stage within its memory and time budget."""
    unavailable = {'status': 'unavailable', 'explanation': '', 'findings': [],
                   'reason': 'network_review_unavailable'}
    if review_concurrency() <= 0:
        return unavailable, True
    try:
        if cancel_event is not None and cancel_event.is_set():
            raise CancelledError()
        if end <= time.monotonic():
            raise TimeoutError()
        access = review_credentials(entries, report['provider'], [], {'resources': network['inventory']})
        from .review_groups import stage_limit
        args = ('network', network, access, token, [], [], end, stage_limit('network', isolation.remote()))
        data = (invoke_before_deadline(*args) if cancel_event is None else
                invoke_before_deadline(*args, cancel_event=cancel_event))
        return dict(validate_network(data, network), status='completed'), False
    except Exception:
        return unavailable, True


def selected_stages(selectors, stages=None):
    """Only Network and Priorities use model agents."""
    if stages is not None:
        selected = set(stages) & {'network', 'priorities'}
        if 'priorities' in selected:
            selected.add('network')
        return frozenset(selected)
    categories = set(selectors.get('categories') or ())
    if not categories:
        categories = {'hardening', 'exposure', 'network'}
    selected = set()
    if 'network' in categories and selectors.get('ai_network_enabled', True):
        selected.add('network')
    if selectors.get('ai_priorities_enabled', True):
        selected.add('priorities')
    return frozenset(selected)


def review_scan(report, snapshot, selectors, *, tenant, artifacts, deadline=None, context=None,
                stages=None, reused_stages=None, cancel_event=None):
    """Run remaining AI stages with native FAILs as final Priorities inputs."""
    selected = selected_stages(selectors, stages)
    result = {'version': 1, 'status': 'skipped', 'actions': [],
              'reviews': {'hardening': [], 'exposure': []}, 'limitations': [],
              'duplicates': {}, 'auth_source': None}
    if not selectors.get('ai_enabled', True):
        result['reason'] = 'disabled_for_scan'
        return result
    if not selected:
        result['reason'] = 'no_ai_sections_selected'
        return result
    hardening, exposure, duplicates = inputs(report)
    from .native_final import reviews as native_reviews
    result['reviews']['hardening'] = native_reviews(hardening)
    result['reviews']['exposure'] = native_exposure_reviews(exposure, duplicates)
    result['native_final'] = {
        'hardening': [row['id'] for row in hardening],
        'exposure': [row['finding_id'] for row in result['reviews']['exposure']]}
    result['duplicates'] = duplicates
    result['stage_inputs'] = {'hardening': [], 'exposure': []}
    reviewed = result['reviews']['hardening'] + result['reviews']['exposure']
    result['coverage'] = {'hardening': len(hardening), 'exposure': len(exposure) + len(duplicates),
                          'reviewed': len(reviewed), 'native_final': len(reviewed),
                          'model_reviewed': 0, 'total': len(reviewed)}
    try:
        from peaso.storage.runtime import stores
        settings = Settings()
        if context:
            settings.state_dir = Path(context['state_dir'])
            settings.identity_dir = Path(context['identity_dir'])
        store, _ = stores(settings)
        ai_user = selectors.get('ai_user_id', tenant)
        if ai_user != tenant and store.workspace_role(tenant, ai_user) not in ('write', 'admin'):
            raise PermissionError('ai_owner_no_longer_authorized')
        from .providers import resolve_access, credential_value, review_disabled
        if review_disabled(store, ai_user):
            result['reason'] = 'disabled_for_account'
            return result
        cipher = AICipher(settings.identity_dir)
        token, result['auth_source'] = resolve_access(store, cipher, ai_user,
            auth_mode=settings.auth_mode, token_resolver=personal_token)
        if not isolation.available():
            result.update(status='unavailable', reason='ai_isolation_unavailable')
            result['limitations'].append('Network and Priorities agents were not started: this deployment has no configured isolation launcher.')
            return result
        entries = []
        reference = snapshot.get('metadata', {}).get('ai_access_reference')
        if reference:
            entries = cipher.decrypt(artifacts.get(tenant, reference)['sealed'])['entries']
        from .access import bind_targets, eligible_entries
        entries = bind_targets(eligible_entries(entries, snapshot), snapshot)
        if report.get('provider') == 'aws':
            result['limitations'].append('AWS AI uses captured evidence only; no live AWS credentials are available to AI agents.')
        elif not entries:
            result['limitations'].append('Live cloud credentials are unavailable; AI is limited to captured evidence.')
        from peaso.snapshot import resources
        inventory = resources(snapshot)
        from .review_groups import publish_reserve, stage_limit
        until_deadline = deadline - time.time() if deadline else 0
        end = min(time.monotonic() + int(os.getenv('PEASO_AI_TIMEOUT_SECONDS',
                  '600' if isolation.remote() else '300')),
                  time.monotonic() + max(0, until_deadline - publish_reserve(until_deadline, isolation.remote()))
                  if deadline else float('inf'))
        from .network import prepare, with_findings
        network = prepare(report, inventory, snapshot) if 'network' in selected else None
        prior = (reused_stages or {}).get('network')
        if (network is not None and isinstance(prior, dict) and prior.get('status') == 'completed'
                and isinstance(prior.get('network'), dict) and prior['network'].get('status') == 'completed'):
            try:
                from .contracts import NetworkEvidence, NetworkFinding
                raw_rows = []
                for row in prior['network']['findings']:
                    item = {key: row[key] for key in NetworkFinding.model_fields}
                    item['evidence'] = {key: row['evidence'][key] for key in NetworkEvidence.model_fields}
                    raw_rows.append(item)
                checked = validate_network({'explanation': prior['network']['explanation'],
                                            'findings': raw_rows}, network)
                if checked['findings'] == prior['network']['findings']:
                    result['network'] = copy.deepcopy(prior['network'])
            except (KeyError, TypeError, ValueError):
                pass
        failed_stage = False
        if network is not None and 'network' not in result:
            try:
                review_end = end - min(600 if isolation.remote() else 60,
                    max(0, end - time.monotonic()) * (.3 if isolation.remote() else .2))
                result['network'], failed_stage = review_network(report, entries, token, network,
                    review_end, **({'cancel_event': cancel_event} if cancel_event is not None else {}))
            except Exception:
                failed_stage = True
        result['network'] = result.get('network') or {
            'status': 'not_available', 'explanation': '', 'findings': [],
            'reason': 'network_inventory_unavailable'}
        priorities_report = with_findings(report, result['network']['findings'])
        if 'priorities' in selected and not _priorities_have_evidence(priorities_report, reviewed, network):
            result['limitations'].append(
                'Prioritized recommendations were skipped because collected evidence supports no actionable finding.')
        elif 'priorities' in selected:
            try:
                if end - time.monotonic() <= 0:
                    raise TimeoutError()
                if review_concurrency() == 0:
                    raise MemoryError('ai_memory_headroom_unavailable')
                from peaso.least_privilege import project
                platform = {'report': priorities_report, 'inventory': inventory,
                            'least_privilege': project(report['provider'], inventory, snapshot=snapshot),
                            'network_review': {key: result['network'][key]
                                               for key in ('status', 'explanation')}}
                data = invoke_before_deadline('priorities', platform, entries, token,
                    hardening + exposure, reviewed, end, stage_limit('priorities', isolation.remote()),
                    **({'cancel_event': cancel_event} if cancel_event is not None else {}))
                recommendations = validate_actions(data, priorities_report, reviewed,
                                                    require_assessment=True)
                result['actions'] = recommendations['actions']
                result['limitations'].extend(recommendations['limitations'])
            except Exception:
                failed_stage = True
                result['limitations'].append('Prioritized recommendations could not be completed.')
        result['status'] = 'partial' if failed_stage else 'completed'
        secrets = [credential_value(token), *getattr(getattr(token, 'guard', None), 'secrets', ())] + [value for entry in entries for key, value in entry.items()
            if key in ('token', 'aws_access_key_id', 'aws_secret_access_key', 'aws_session_token') and isinstance(value, str)]
        for entry in entries:
            if entry.get('format') == 'kubeconfig':
                for user in entry['kubeconfig'].get('users', []):
                    secrets.extend(secret_values(user.get('user', {})))
        sanitized = redact(result, tuple(secrets))
        sanitized['network']['explanation'] = sanitized['network']['explanation'][:12000]
        return sanitized
    except Exception:
        result.update(status='unavailable', reason='ai_setup_unavailable', actions=[])
        result['limitations'].append('AI authentication, runtime or scan context is unavailable. Native findings remain final.')
        return result
