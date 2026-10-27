"""Private, encrypted scan evidence; never part of native observations or AI input.

Collection uses one explicit process-local sink shared by collection threads.
Source contexts are thread-local and bounded. Only API/collector identities have
the connector cipher; the analyzer receives neither its key nor plaintext.
"""
from contextlib import contextmanager
from copy import deepcopy
from itertools import islice
import json
import re
import threading

_lock = threading.RLock()
_active = None
_source = threading.local()
MAX_VALUES = 10000
MAX_LOCATIONS = 50000
MAX_BYTES = 64 * 1024 * 1024
MAX_VALUE_BYTES = 2 * 1024 * 1024
SCHEMA = 'private-secret-evidence-v1'
FIELDS = {'resource_id', 'scope', 'path', 'field', 'layer', 'image_digest', 'source', 'location_kind', 'content_lines'}
NAMED_CHECKS = {
    'aws': {'aws.htbp.lambda.env_var_names_not_credentials', 'aws_cis_lambda_database_secrets_manager',
        'aws.c2b.codebuild.no_plaintext_sensitive_env_names', 'aws.nist.codebuild_exact_aws_key_env_names',
        'aws.pci.codebuild.aws_key_environment_vars', 'aws_nist_codebuild_project_plaintext_env_variables_no_sensitive_aws_values',
        'aws.c2b.ecs.no_credential_named_env_vars', 'aws_ecs_task_definition_credential_environment_names',
        'aws_nist_ecs_task_definition_container_environment_no_secret'},
    'gcp': {'gcp.htbp.cloudrun.job_secret_env_from_secret_manager',
        'gcp.htbp.cloudrun.service_secret_env_from_secret_manager', 'gcp.htbp.function.secret_env_from_secret_manager'},
    'k8s': {'k8s.claude.pod.no_literal_secret_env', 'azure_aks_cluster_3_5_1_14_247ebcd'},
    # The existing sw26 secretKeys rule explicitly covers both ACI and AKS Pods.
    'azure': {'azure.claude.container_group_secure_environment_variables', 'azure_aks_cluster_3_5_1_14_247ebcd'},
}
LEGACY_CHECKS = set().union(*NAMED_CHECKS.values()) | {
    'aws.a.ec2.user_data_source_indicators', 'aws_autoscaling_userdata_plaintext_aws_key',
    'aws_cis_ec2_userdata_embedded_secrets', 'aws.c2b.codebuild.source_url_no_credentials',
    'azure.review.devops.visible_clone_urls_without_userinfo',
    'aws.review.lambda_function.package_content_secret_indicators',
    'aws.review.lambda_layer_version.package_content_secret_indicators',
    'aws.review.ecr_repository.package_content_secret_indicators',
}
SECRET_NAME = re.compile(r'(?i)passw(or)?d|passwd|secret|token|api[_-]?key|private[_-]?key|credential|access[_-]?key|conn(ection)?[_-]?str')
REFERENCE_SUFFIX = re.compile(r'(?i)_(url|uri|path|file|name|id|endpoint|host|port|ttl|length|enabled|version|ref|arn)$')


def enabled():
    return _active is not None


@contextmanager
def capture(cipher, *, tenant='cli', scan_id='cli', options=None, selected_checks=None):
    global _active
    sink = Capture(cipher, tenant, scan_id, options, selected_checks)
    with _lock:
        if _active is not None:
            raise RuntimeError('private evidence capture already active')
        _active = sink
    try:
        yield sink
    finally:
        with _lock:
            _active = None
            sink.aliases.clear()


@contextmanager
def source_context(*, native=None, check_ids=None, **fields):
    """Supply only observed native identities/paths, before pseudonymization."""
    if not enabled():
        yield
        return
    previous = getattr(_source, 'fields', {})
    previous_bindings = getattr(_source, 'bindings', ())
    previous_checks = getattr(_source, 'check_ids', ())
    supplied = {k: v for k, v in fields.items() if k in FIELDS and isinstance(v, str) and v}
    fields = {k: v for k, v in supplied.items() if len(v.encode()) <= 16384}
    if len(fields) != len(supplied) and _active is not None:
        _active.incomplete = True
    _source.fields = {**previous, **fields}
    if native is not None:
        _source.bindings = literal_bindings(native)
    if check_ids is not None:
        selected_checks = list(islice(check_ids, 33))
        _source.check_ids = tuple(sorted({value for value in selected_checks if isinstance(value, str) and len(value) <= 256}))[:32]
        if len(selected_checks) > 32 and _active is not None:
            _active.incomplete = True
    try:
        yield
    finally:
        _source.fields = previous
        _source.bindings = previous_bindings
        _source.check_ids = previous_checks


def scan_with_source(scanner, payload, path, *, source, native=None, **kwargs):
    """Explicit adapter keeps existing scanner signatures and public results."""
    with source_context(native=native, **source):
        return scanner(payload, path, **kwargs)


def literal_bindings(value):
    result = []
    def visit(node, path, depth=0):
        if depth > 32 or len(result) >= 4096:
            return
        if isinstance(node, str):
            result.append((path, node))
        elif isinstance(node, dict):
            for key, child in node.items():
                visit(child, path + '[' + json.dumps(str(key)) + ']', depth + 1)
        elif isinstance(node, list):
            for i, child in enumerate(node):
                visit(child, path + '[' + str(i) + ']', depth + 1)
    visit(value, '$')
    return result


def target_source(target, **fields):
    """Original selected native locator, excluding auth and signed HTTP URLs."""
    allowed = {'resource_id', 'resource', 'id', 'name', 'path', 'file_path', 'file', 'object', 'bucket',
        'generation', 'version', 'repository', 'commit', 'digest', 'sha256', 'project_scope', 'profile', 'uri', 'scope', 'namespace', 'cluster_id', 'container', 'container_name', 'pod', 'pod_name', 'previous', 'log_group', 'log_stream', 'table', 'project_id', 'repository_id', 'organization', 'pipeline_id', 'definition_revision', 'commit_sha', 'version_id', 'key', 'service'}
    if isinstance(target, str):
        return {**fields, 'resource_id': target}
    original = {key: value for key, value in target.items() if key in allowed and isinstance(value, (str, int))}
    for key in ('resource_id', 'resource', 'id'):
        if isinstance(target.get(key), str):
            fields['resource_id'] = target[key]
            break
    if 'source' not in fields and original:
        fields['source'] = json.dumps(original, ensure_ascii=False, sort_keys=True)
    if 'path' not in fields:
        for key in ('path', 'file_path', 'file', 'object'):
            if isinstance(target.get(key), str):
                fields['path'] = target[key]
                break
    return fields


def alias_path(alias, original):
    """Remember original TAR names privately before changing their headers."""
    with _lock:
        if _active is not None:
            context = getattr(_source, 'fields', {})
            key = (threading.get_ident(), context.get('resource_id'), context.get('layer'), alias)
            if len(_active.aliases) >= MAX_LOCATIONS:
                _active.incomplete = True
                return
            sealed = _active.cipher.encrypt({'path': original})
            size = len(sealed) - len(_active.aliases.get(key, ''))
            if _active.bytes + _active.alias_bytes + _active.redaction_bytes + size > MAX_BYTES:
                _active.incomplete = True
                return
            _active.aliases[key] = sealed
            _active.alias_bytes += size


def remember_redactions(values):
    """Found secrets stay visible in public output; no scrub set is retained."""
    return


def batched():
    """Seal each touched private record once for a run of remember() calls.

    The capture lock is held for the whole run, so no other thread observes a
    record that is still open. Records are sealed again when the run ends.
    """
    return _Batch(None, _lock)


def remember(value, fingerprint, *, path, line=None, engine, rule, check_ids=(), public_path=None, observed_bytes=True):
    with _lock:
        if _active is None:
            return
        check_ids = set(check_ids) | set(getattr(_source, 'check_ids', ()))
        if check_ids and _active.selected_checks is not None:
            check_ids &= _active.selected_checks
            if not check_ids:
                return
        context = dict(getattr(_source, 'fields', {}))
        location = {**context, 'path': context.get('path', path),
                    'line': line if type(line) is int and line > 0 else None, 'witness_path': path}
        key = (threading.get_ident(), context.get('resource_id'), context.get('layer'), location['path'])
        if key in _active.aliases:
            location['path'] = _active.cipher.decrypt(_active.aliases[key])['path']
        if public_path is not None:
            location['_public_path'] = public_path
        bindings = getattr(_source, 'bindings', ()) if context.get('location_kind') == 'configuration' else ()
        actual = [field for field, text in bindings if value in text]
        if not observed_bytes and not actual and context.get('location_kind') != 'detector_composite':
            location['location_kind'] = 'detector_decoded'
        if location.get('location_kind') in {'detector_composite', 'detector_decoded'}:
            location['detector_input_path'] = location['path']
            location['path'], location['line'] = None, None
            location.pop('field', None)
        if context.get('content_lines', '').isdigit() and location['line'] is not None and location['line'] > int(context['content_lines']):
            location['location_kind'] = 'filename'
            location['line'] = None
        location.pop('content_lines', None)
        if context.get('location_kind') in {'configuration', 'log', 'filename'}:
            location['line'] = None  # Serialized native fields have no file line.
        for field in actual or [None]:
            observed = dict(location, field=field) if field is not None else location
            _active.remember(value, fingerprint, observed, engine, rule, check_ids)
        if public_path is not None:
            for related in _active.related.get(fingerprint, ()):
                row = _active.load(related)
                changed = False
                for loc in row['locations']:
                    if (loc.get('witness_path') == path and loc.get('_public_path') != public_path
                            and all(loc.get(k) == context.get(k) for k in ('resource_id', 'scope', 'layer'))):
                        loc['_public_path'] = public_path
                        changed = True
                if changed:
                    _active.store(related, row)


class _Batch:
    """Open private records once and seal each one when the outermost run ends."""

    def __init__(self, sink, lock=None):
        self.sink, self.lock, self.outer = sink, lock, False

    def __enter__(self):
        if self.lock is not None:
            self.lock.acquire()
            self.sink = _active
        sink = self.sink
        self.outer = sink is not None and sink._open is None
        if self.outer:
            sink._open, sink._open_keys = {}, {}
        return self

    def __exit__(self, kind, error, trace):
        try:
            if self.outer:
                sink = self.sink
                opened, sink._open, sink._open_keys = sink._open, None, {}
                for fingerprint, row in opened.items():
                    sink._seal(fingerprint, row)
        finally:
            if self.lock is not None:
                self.lock.release()
        return False


_OPEN = '\x00open'  # Placeholder while a batched record is not sealed yet.


def _location_key(location):
    return json.dumps(location, sort_keys=True, separators=(',', ':'))


class Capture:
    def __init__(self, cipher, tenant, scan_id, options=None, selected_checks=None):
        self.cipher, self.tenant, self.scan_id = cipher, tenant, scan_id
        self.records, self.aliases, self.related, self.redactions = {}, {}, {}, {}
        self.bytes = self.locations = self.related_count = self.alias_bytes = 0
        self.redaction_bytes = 0
        self.redaction_incomplete = False
        self.incomplete = False
        self.policy_names = policy_names(options)
        self.selected_checks = frozenset(selected_checks) if selected_checks is not None else None
        # Rows opened by batch(); sealed once when the batch ends.
        self._open = None
        self._open_keys = {}
        # fingerprint -> (sealed record, location resource ids). Lets
        # bind_snapshot skip records it cannot change without decrypting them.
        self._meta = {}

    def load(self, fingerprint):
        """Plaintext record: the open batch copy, else one decryption."""
        if self._open is not None and fingerprint in self._open:
            return self._open[fingerprint]
        return self.cipher.decrypt(self.records[fingerprint])

    def store(self, fingerprint, row):
        if self._open is not None:
            self._open[fingerprint] = row
            self.records.setdefault(fingerprint, _OPEN)
            return
        self._seal(fingerprint, row)

    def _seal(self, fingerprint, row):
        sealed = self.records[fingerprint] = self.cipher.encrypt(row)
        self._meta[fingerprint] = (sealed, frozenset(loc.get('resource_id') for loc in row['locations']))

    def batch(self):
        """Callers hold the module lock; nested batches join the outer one."""
        return _Batch(self)

    def retain_redaction(self, value, fingerprint):
        """Found secrets are not scrubbed from public output; nothing to retain."""
        return

    def remember(self, value, fingerprint, location, engine, rule, check_ids):
        size = len(value.encode())
        if (size > MAX_VALUE_BYTES
                or fingerprint not in self.records and len(self.records) >= MAX_VALUES):
            self.incomplete = True
            return
        row = self.load(fingerprint) if fingerprint in self.records else {
            'tenant': self.tenant, 'scan_id': self.scan_id, 'fingerprint': fingerprint,
            'value': value, 'locations': [], 'detectors': [], 'check_ids': []}
        if row['value'] != value:
            raise ValueError('private evidence identity mismatch')
        location = dict(location, _check_ids=sorted(check_ids))
        detector = {'engine': engine, 'rule': rule}
        if self._open is not None:
            # Constant-time membership for a value repeated at many locations.
            keys = self._open_keys.get(fingerprint)
            if keys is None:
                keys = self._open_keys[fingerprint] = {_location_key(loc) for loc in row['locations']}
            location_key = _location_key(location)
            new_location = location_key not in keys
        else:
            keys = location_key = None
            new_location = location not in row['locations']
        additional = ((size if fingerprint not in self.records else 0)
                      + (len(json.dumps(location).encode()) if new_location else 0)
                      + (len(json.dumps(detector).encode()) if detector not in row['detectors'] else 0)
                      + len(json.dumps(sorted(set(check_ids) - set(row['check_ids']))).encode()))
        if (self.bytes + self.alias_bytes + additional > MAX_BYTES
                or new_location and self.locations >= MAX_LOCATIONS):
            self.incomplete = True
            return
        if detector not in row['detectors']:
            row['detectors'].append(detector)
        if new_location:
            row['locations'].append(location)
            self.locations += 1
            if keys is not None:
                keys.add(location_key)
        self.bytes += additional
        row['check_ids'] = sorted(set(row['check_ids']) | set(check_ids))
        self.store(fingerprint, row)

    def document(self):
        resources, scopes = {}, {}
        for fp, sealed in self.records.items():
            for loc in self.cipher.decrypt(sealed)['locations']:
                for key in ('resource_id', '_resource_alias'):
                    if loc.get(key):
                        resources.setdefault(loc[key], set()).add(fp)
                if loc.get('scope'):
                    scopes.setdefault(loc['scope'], set()).add(fp)
        return {'schema': SCHEMA, 'tenant': self.tenant, 'scan_id': self.scan_id,
                'incomplete': self.incomplete, 'records': dict(self.records),
                'index': self.cipher.encrypt({'tenant': self.tenant, 'scan_id': self.scan_id,
                    'resources': {k: sorted(v) for k, v in resources.items()},
                    'scopes': {k: sorted(v) for k, v in scopes.items()},
                    'related': {k: sorted(v) for k, v in self.related.items()}})}

    def _resource_ids(self, fingerprint):
        sealed = self.records[fingerprint]
        cached = self._meta.get(fingerprint)
        if cached is not None and cached[0] is sealed:
            return cached[1], None
        row = self.cipher.decrypt(sealed)
        ids = frozenset(loc.get('resource_id') for loc in row['locations'])
        self._meta[fingerprint] = (sealed, ids)
        return ids, row

    def bind_snapshot(self, snapshot):
        """Resolve unambiguous public witness identities.

        Explicit native contexts win. A shared synthetic path never guesses a
        resource when more than one resource used that path for the same value.
        Only records that a snapshot witness or a native identity can change
        are opened; an unchanged record keeps its sealed form.
        """
        if not self.records:
            # Nothing can bind or change. Keep the structural access failures.
            for collection in snapshot['collections']:
                for item in collection['items']:
                    if isinstance(item, dict):
                        collection['type'], collection['scope']
            return
        from peaso.snapshot import resource_id
        records = self.records
        candidates = {}
        def walk(value, resource):
            if isinstance(value, dict):
                if isinstance(value.get('fingerprint'), str) and value['fingerprint'] in records and isinstance(value.get('locations'), list):
                    for loc in value['locations']:
                        key = (value['fingerprint'], loc.get('path'))
                        ref = {**resource, **{k: loc[k] for k in ('scope', 'layer', 'resource_id') if loc.get(k)}}
                        if ref not in candidates.setdefault(key, []):
                            candidates[key].append(ref)
                for child in value.values():
                    walk(child, resource)
            elif isinstance(value, list):
                for child in value:
                    walk(child, resource)
        # Same identities and de-duplication as peaso.snapshot.resources(),
        # without its read-only copies, digests and ordering.
        selected = {}
        for collection in snapshot['collections']:
            for item in collection['items']:
                if isinstance(item, dict):
                    rid = resource_id(snapshot['provider'], collection['type'], collection['scope'], item)
                    selected[(collection['scope'], collection['type'], rid)] = (rid, collection['scope'], item)
        authorities = {}
        for native_id, scope, native in selected.values():
            for ident in {native_id, *[native.get(k) for k in ('Arn', 'arn', 'id', 'name', 'FunctionArn', 'taskDefinitionArn', 'jobDefinitionArn') if isinstance(native.get(k), str)]}:
                authorities.setdefault(ident, set()).add(scope)
            walk(native, {'resource_id': native_id, 'scope': scope})
        parents_of = {}
        for primary, related in self.related.items():
            for child in related:
                parents_of.setdefault(child, set()).add(primary)
        witnessed = {fp for fp, _ in candidates}
        for fp in list(records):
            parents = {fp} | parents_of.get(fp, set())
            ids, row = self._resource_ids(fp)
            if parents.isdisjoint(witnessed) and ids.isdisjoint(authorities):
                continue
            if row is None:
                row = self.cipher.decrypt(records[fp])
            changed = False
            for loc in row['locations']:
                before = dict(loc)
                scopes = authorities.get(loc.get('resource_id'), ())
                if len(scopes) == 1 and (not loc.get('scope') or loc['scope'] == next(iter(scopes)).rsplit('/', 1)[-1]):
                    loc['scope'] = next(iter(scopes))
                options = []
                for parent in parents:
                    for option in candidates.get((parent, loc.get('_public_path', loc.get('witness_path'))), []):
                        if option not in options:
                            options.append(option)
                exact = [option for option in options if option['resource_id'] == loc.get('resource_id')
                         and (not loc.get('scope') or option['scope'] == loc['scope'])]
                if exact:
                    options = exact
                bound = (len(options) == 1 and (not loc.get('scope') or loc['scope'] == options[0]['scope'])
                    and (not loc.get('resource_id') or options[0]['resource_id'] == loc['resource_id']
                    or str(loc.get('_public_path', '')).startswith(options[0]['resource_id'] + '.')))
                if bound:
                    loc['_canonical_resource_id'], loc['_canonical_scope'] = options[0]['resource_id'], options[0]['scope']
                if not loc.get('resource_id') and len(options) == 1:
                    loc.update(options[0])
                changed |= loc != before
            if changed:
                self._seal(fp, row)


    def public_snapshot(self, snapshot):
        """Bind private witnesses to the snapshot; found secrets stay visible.

        Tenant administrators must see each found value and its location to
        rotate or remove it, so no found value, key or resource identity is
        redacted or aliased here. Stored artifacts remain encrypted at rest.
        """
        if not self.records:
            return snapshot
        with _lock:
            self.bind_snapshot(snapshot)
        return snapshot


# NAME=value or NAME: value, and --name value or --name=value options.
_NAMED_ASSIGNMENT = (
    re.compile(r'''(?m)(?:^|[\s;'"])(?:export\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_.-]{0,127})["']?\s*[:=]\s*["']?(?P<value>[^\s"'#;]{6,512})'''),
    re.compile(r'''(?m)(?:^|\s)--(?P<name>[A-Za-z][A-Za-z0-9_-]{0,127})(?:=|\s+)["']?(?P<value>[^\s"'#;-][^\s"'#;]{5,511})'''))


def legacy_text(text, resource_id=None):
    """Capture only the already-used bounded pattern detector's real matches."""
    if not enabled():
        return
    from peaso.collectors.aws_user_data_secret_indicators import _PRIVATE_KEY, _ACCESS, _SECRET, _PASSWORD
    from peaso.secret_scanning import _fingerprint
    context = {} if not resource_id or resource_id == 'unused' else {'resource_id': resource_id}
    if isinstance(resource_id, str) and resource_id.startswith('i-'):
        context['path'] = 'ec2/user-data'
        context['check_ids'] = {'aws.a.ec2.user_data_source_indicators', 'aws_cis_ec2_userdata_embedded_secrets'}
    with source_context(**context):
        def record(value, rule, offset):
            if reference_literal(value):
                return
            remember(value, _fingerprint(value), path='native-content', line=text[:offset].count('\n') + 1,
                     engine='configuration', rule=rule)
        for match in _PRIVATE_KEY.finditer(text):
            # Prefer the observed original native value over JSON-escaped PEM.
            native = [(field, value) for field, value in getattr(_source, 'bindings', ()) if match[0] in value]
            if native:
                for field, value in native:
                    start = value.find(match[0])
                    end = re.search(r'-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----', value[start:])
                    if end:
                        with source_context(field=field):
                            record(value[start:start + end.end()], 'private_key', match.start())
            else:
                end = re.search(r'-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----', text[match.end():])
                # The private_key category is reported on BEGIN alone. Keep the
                # observed block even when its END marker is missing.
                record(text[match.start():match.end() + end.end()] if end else text[match.start():], 'private_key', match.start())
        if _ACCESS.search(text) and _SECRET.search(text):
            for match in _ACCESS.finditer(text):
                record(match[0], 'cloud_credential', match.start())
            for match in _SECRET.finditer(text):
                record(match[1], 'cloud_credential', match.start(1))
        for match in _PASSWORD.finditer(text):
            value = match[2]
            if (not any(marker in value for marker in ('$', '{{', '}}', '<', '>', '\\'))
                    and not value.lower().startswith(('example', 'your_', 'replace_', 'placeholder'))
                    and re.search(r'[A-Za-z]', value) and re.search(r'[0-9!@#%^&*]', value)):
                record(value, 'password_assignment', match.start(2))
        if context.get('path') == 'ec2/user-data':
            # The user-data check reports secret-named words; keep the literal
            # values assigned to secret-named variables or options.
            for match in (match for pattern in _NAMED_ASSIGNMENT for match in pattern.finditer(text)):
                name, value = match['name'], match['value']
                if (SECRET_NAME.search(name) and not REFERENCE_SUFFIX.search(name)
                        and not any(marker in value for marker in ('$', '{{', '}}', '<', '>', '`'))
                        and not value.lower().startswith(('example', 'your_', 'replace_', 'placeholder', 'changeme'))):
                    record(value, 'secret_named_assignment', match.start('value'))


def native_environment_resources(value, *, provider, method, url, body=None, scope=''):
    """Only existing workload name controls on exact native read routes/fields."""
    if not enabled() or method != 'GET' or body is not None or not isinstance(value, dict):
        return
    from urllib.parse import urlsplit
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or parsed.username or parsed.password or parsed.fragment:
        return
    if provider == 'azure':
        route = re.fullmatch(r'(/subscriptions/[^/]+)(?:/resourceGroups/[^/]+)?/providers/Microsoft\.ContainerInstance/containerGroups(?:/[^/]+)?', parsed.path, re.I)
        if parsed.hostname != 'management.azure.com' or not route:
            return
        scope = route[1]
        rows = value.get('value', [value])
        if not isinstance(rows, list):
            return
        for row in rows[:20000]:
            if not isinstance(row, dict) or str(row.get('type', '')).casefold() != 'microsoft.containerinstance/containergroups':
                continue
            ident = row.get('id', '')
            if not isinstance(ident, str) or not re.fullmatch(re.escape(scope) + r'/resourceGroups/[^/]+/providers/Microsoft\.ContainerInstance/containerGroups/[^/]+', ident, re.I):
                continue
            if (not parsed.path.casefold().endswith('/containergroups') and ident.casefold() != parsed.path.casefold()
                    or '/resourcegroups/' in parsed.path.casefold() and not ident.casefold().startswith(parsed.path.casefold().rsplit('/containergroups', 1)[0] + '/containergroups/')):
                continue
            properties = row.get('properties')
            containers = properties.get('containers', []) if isinstance(properties, dict) else []
            if isinstance(containers, list):
                for i, container in enumerate(containers[:4096]):
                    if isinstance(container, dict) and isinstance(container.get('properties'), dict):
                        named_environment({'environmentVariables': container['properties'].get('environmentVariables', [])},
                            provider='azure', resource_id=ident, scope=scope, path=f'properties.containers[{i}].properties',
                            checks=NAMED_CHECKS['azure'])
        return
    if provider != 'gcp' or not isinstance(scope, str) or not re.fullmatch(r'projects/[^/]+', scope):
        return
    route = re.fullmatch(r'/v2/(' + re.escape(scope) + r'/locations/[^/]+)/(services|jobs|functions)(?:/([^/:]+))?', parsed.path)
    if not route or parsed.hostname != ('cloudfunctions.googleapis.com' if route[2] == 'functions' else 'run.googleapis.com'):
        return
    segment, selected = route[2], route[3]
    rows = [value] if selected else value.get(segment, [])
    if not isinstance(rows, list):
        return
    for row in rows[:20000]:
        if not isinstance(row, dict):
            continue
        ident = row.get('name', '')
        if not isinstance(ident, str) or not re.fullmatch(re.escape(scope) + r'/locations/[^/]+/' + segment + r'/[^/:]+', ident):
            continue
        if selected and ident != parsed.path[4:] or '/locations/-/' not in parsed.path and not ident.startswith(route[1] + '/' + segment + '/'):
            continue
        if segment == 'functions':
            config = row.get('serviceConfig')
            if isinstance(config, dict):
                named_environment({'environmentVariables': config.get('environmentVariables', {})}, provider='gcp',
                    resource_id=ident, scope=scope, path='serviceConfig', checks={'gcp.htbp.function.secret_env_from_secret_manager'})
            continue
        template, path = row.get('template'), 'template'
        if segment == 'jobs' and isinstance(template, dict):
            template, path = template.get('template'), 'template.template'
        containers = template.get('containers', []) if isinstance(template, dict) else []
        if isinstance(containers, list):
            for i, container in enumerate(containers[:4096]):
                if isinstance(container, dict):
                    named_environment({'env': container.get('env', [])}, provider='gcp', resource_id=ident, scope=scope,
                        path=path + f'.containers[{i}]', checks={'gcp.htbp.cloudrun.' + ('job' if segment == 'jobs' else 'service') + '_secret_env_from_secret_manager'})


def pod_environment(item, *, kind, resource_id, scope):
    if not enabled() or kind != 'pod' or not isinstance(item.get('spec'), dict):
        return
    for field in ('containers', 'initContainers', 'ephemeralContainers'):
        rows = item['spec'].get(field, [])
        if isinstance(rows, list):
            for i, container in enumerate(rows[:4096]):
                if isinstance(container, dict):
                    named_environment({'env': container.get('env', [])}, provider='k8s', resource_id=resource_id,
                        scope=scope, path=f'spec.{field}[{i}]', checks=NAMED_CHECKS['k8s'])


def private_reference(tenant, scan_id):
    from peaso.storage.artifacts import prefix, check_reference
    reference = prefix(tenant) + '/' + scan_id + '/secret-evidence-' + '0' * 32 + '.json'
    check_reference(tenant, reference)
    return reference


def value_witness(finding):
    evidence = finding.get('evidence') if isinstance(finding.get('evidence'), dict) else {}
    cid = finding.get('check_id', '')
    return bool(finding.get('secret_fingerprint') or evidence.get('secret_leaks') or cid in LEGACY_CHECKS
                or cid.startswith('aws.review.') and cid.endswith(('configuration_secret_indicators', 'payload_secret_indicators', 'output_secret_indicators')))


def eligible(finding):
    return value_witness(finding) or finding.get('finding_type') == 'secrets'


def canonical_sources(finding, fingerprints):
    sources = {fp: [] for fp in fingerprints}
    rejected = set()
    aggregate = (finding.get('secret_fingerprint') is not None
        and finding.get('resource_id') == 'secret:' + finding['secret_fingerprint']
        and not finding.get('native_resource_id'))
    native = finding.get('native_resource_id') or finding.get('resource_id')
    if str(native).startswith(('secret:', 'check:', 'scope:', 'inventory:', 'aggregate:')):
        native = None
    for leak in (finding.get('evidence') or {}).get('secret_leaks', []):
        if leak.get('fingerprint') in sources:
            for loc in leak.get('locations', []):
                if (loc.get('scope') and finding.get('scope') and loc['scope'] != finding['scope']
                        and not (aggregate and leak['fingerprint'] == finding['secret_fingerprint'])):
                    rejected.add(leak['fingerprint'])
                    continue
                resource = loc.get('resource_id') or native
                if resource and native and not aggregate and resource != native:
                    rejected.add(leak['fingerprint'])
                    continue
                if resource:
                    sources[leak['fingerprint']].append(dict(loc, resource_id=resource, scope=loc.get('scope') or finding.get('scope')))
    if native:
        for fp in sources:
            if not sources[fp] and fp not in rejected:
                sources[fp] = [{'resource_id': native, 'scope': finding.get('scope')}]
    return sources, bool(rejected)


def fingerprint_locations(finding, fingerprint, locations, sources, related):
    allowed = list(sources.get(fingerprint, []))
    for primary in sources:
        if fingerprint in related.get(primary, []):
            allowed.extend(sources[primary])
    checks = set(finding.get('linked_check_ids') or [finding.get('check_id')])
    result, ambiguous = [], False
    for loc in locations:
        if loc.get('_check_ids') and not checks.intersection(loc['_check_ids']):
            continue
        resource = loc.get('_canonical_resource_id_alias') or loc.get('_canonical_resource_id') or loc.get('_resource_alias') or loc.get('resource_id')
        options = []
        for source in allowed:
            scope = loc.get('_canonical_scope_alias') or loc.get('_canonical_scope') or loc.get('scope')
            witness = loc.get('_public_path', loc.get('witness_path'))
            if resource != source['resource_id'] and not (resource is None and source.get('path') and witness == source['path']):
                continue
            if scope and source.get('scope') and scope != source['scope']:
                continue
            if source.get('path') and witness != source['path']:
                continue
            if loc.get('layer') and source.get('layer') and loc['layer'] != source['layer']:
                continue
            if fingerprint in sources and loc.get('line') and source.get('line') and loc['line'] != source['line']:
                continue
            enriched = dict(loc)
            for key in ('resource_id', 'scope', 'layer'):
                if not enriched.get(key) and source.get(key):
                    enriched[key] = source[key]
            if enriched not in options:
                options.append(enriched)
        origins = {(item.get('resource_id'), item.get('scope'), item.get('layer')) for item in options}
        if len(origins) > 1 or resource is None and not origins:
            ambiguous = True
            continue
        if options and options[0] not in result:
            result.append(options[0])
    return result, ambiguous


def details(finding, document, cipher, *, tenant, scan_id, offset=0, page_bytes=None, index=None):
    """Join ONLY after the caller authorizes the scan and the exact finding."""
    if not eligible(finding):
        return None
    if not value_witness(finding):
        return {'status': 'metadata_only', 'matches': [],
                'message': 'This finding describes credential metadata or references; no matched secret value was observed.'}
    unavailable = {'status': 'unavailable', 'matches': [],
        'message': 'Full matched values were not retained for this finding. Run a fresh scan to collect private evidence; metadata-only references cannot supply a secret value.'}
    if not document or document.get('schema') != SCHEMA or (document.get('tenant'), document.get('scan_id')) != (tenant, scan_id):
        return unavailable
    fingerprints = {r.get('fingerprint') for r in (finding.get('evidence') or {}).get('secret_leaks', []) if isinstance(r, dict)}
    if finding.get('secret_fingerprint'):
        fingerprints.add(finding['secret_fingerprint'])
    resources = {finding.get('native_resource_id'), finding.get('resource_id')}
    sources, association_incomplete = canonical_sources(finding, fingerprints)
    related = {}
    matches = []
    records = document.get('records', {})
    if fingerprints:
        candidates = fingerprints & records.keys()
        if 'index' in document:
            index = index if index is not None else private_index(document, cipher, tenant, scan_id)
            related = index.get('related', {})
            candidates |= {linked for fp in fingerprints for linked in related.get(fp, []) if linked in records}
    elif 'index' in document:
        index = index if index is not None else private_index(document, cipher, tenant, scan_id)
        candidates = set()
        for resource in resources - {None}:
            candidates.update(index['resources'].get(resource, []))
        if str(finding.get('resource_id', '')).startswith('scope:'):
            candidates.update(index['scopes'].get(finding.get('scope', ''), []))
    else:
        candidates = records.keys()
    for fingerprint in sorted(candidates):
        sealed = records[fingerprint]
        row = cipher.decrypt(sealed)
        if (row.get('tenant'), row.get('scan_id'), row.get('fingerprint')) != (tenant, scan_id, fingerprint):
            raise ValueError('private evidence scope mismatch')
        locations = row['locations']
        if fingerprints:
            locations, ambiguous = fingerprint_locations(finding, fingerprint, locations, sources, related)
            association_incomplete |= ambiguous
            if not locations:
                continue
        else:
            if finding.get('status') != 'FAIL':
                continue
            if finding['check_id'] == 'aws_autoscaling_userdata_plaintext_aws_key' and not any(d['rule'] == 'cloud_credential' for d in row['detectors']):
                continue
            locations = [loc for loc in locations if finding['check_id'] in loc.get('_check_ids', [])
                         and (not loc.get('scope') or not finding.get('scope') or loc['scope'] == finding['scope'])
                         and ((loc.get('resource_id') in resources - {None} or loc.get('_resource_alias') in resources - {None}) or
                              str(finding.get('resource_id', '')).startswith('scope:') and
                              finding['check_id'] in loc.get('_check_ids', []) and loc.get('scope') == finding.get('scope'))]
            if not locations:
                continue
        # Canonical source records enrich a detector location that already has
        # the original private path; never use a masked path as the real path.
        canonical = [loc for leak in (finding.get('evidence') or {}).get('secret_leaks', [])
                     if leak.get('fingerprint') == fingerprint for loc in leak.get('locations', [])]
        if not canonical and finding.get('secret_fingerprint') == fingerprint:
            canonical = []
        output_locations = []
        for loc in locations:
            enriched = dict(loc)
            enriched.pop('witness_path', None)
            enriched.pop('_check_ids', None)
            enriched.pop('_resource_alias', None)
            enriched.pop('_public_path', None)
            enriched.pop('_canonical_resource_id', None)
            enriched.pop('_canonical_scope', None)
            enriched.pop('_canonical_resource_id_alias', None)
            enriched.pop('_canonical_scope_alias', None)
            if not enriched.get('resource_id') and len({c.get('resource_id') for c in canonical}) == 1:
                enriched.update({k: canonical[0][k] for k in ('resource_id', 'scope', 'layer') if canonical[0].get(k)})
            output_locations.append(enriched)
        matches.append({k: deepcopy(row[k]) for k in ('fingerprint', 'value', 'detectors')} | {'locations': output_locations})
    if not matches:
        if association_incomplete:
            return dict(unavailable, complete=False, message='Private matches could not be bound to this finding\'s exact source. Run a fresh scan with unambiguous source identities.')
        return unavailable
    if page_bytes is not None:
        matches, next_offset, total = page_matches(matches, offset, page_bytes)
        return {'status': 'available', 'matches': matches, 'complete': not (document.get('incomplete', False) or association_incomplete),
                'next_offset': next_offset, 'total_locations': total}
    return {'status': 'available', 'matches': matches, 'complete': not (document.get('incomplete', False) or association_incomplete)}


def load_details(artifacts, cipher, tenant, scan_id, finding, *, offset=0):
    if not eligible(finding):
        return None
    try:
        document = artifacts.get(tenant, private_reference(tenant, scan_id))
        return details(finding, document, cipher, tenant=tenant, scan_id=scan_id, offset=offset, page_bytes=3 * 1024 * 1024)
    except (FileNotFoundError, KeyError):
        return details(finding, None, cipher, tenant=tenant, scan_id=scan_id)
    except Exception:
        # No provider error, secret value, path or cryptographic detail escapes.
        return {'status': 'unavailable', 'matches': [], 'message': 'Private secret evidence is unavailable. Run a fresh scan.'}



def policy_names(options):
    """Only the two existing explicit name policies, bounded and never values."""
    result = {'aws_cis_lambda_database_secrets_manager': set(), 'azure_aks_cluster_3_5_1_14_247ebcd': set()}
    stack = [(options, 0)]; nodes = 0
    while stack:
        node, depth = stack.pop(); nodes += 1
        if nodes > 20000 or depth > 24:
            break
        if isinstance(node, dict):
            names = node.get('approved_database_connection_environment_variable_names')
            if isinstance(names, list):
                result['aws_cis_lambda_database_secrets_manager'].update(n for n in names[:4096] if isinstance(n, str) and len(n) <= 4096)
            policy = node.get('azure_aks_cluster_3_5_1_14_247ebcd')
            if isinstance(policy, dict) and isinstance(policy.get('secretKeys'), list):
                result['azure_aks_cluster_3_5_1_14_247ebcd'].update(n.casefold() for n in policy['secretKeys'][:4096] if isinstance(n, str) and len(n) <= 4096)
            stack.extend((child, depth + 1) for child in node.values() if isinstance(child, (dict, list)))
        elif isinstance(node, list):
            stack.extend((child, depth + 1) for child in node[:4096] if isinstance(child, (dict, list)))
    return result


def literal_name_checks(provider, name):
    """Mirror existing name predicates; no heuristic turns references into values."""
    if not isinstance(name, str):
        return set()
    checks = set()
    if provider == 'aws':
        if re.search(r'(?i)(SECRET_ACCESS_KEY|PASSWORD|PASSWD|PRIVATE_KEY|CLIENT_SECRET)', name) and not re.search(r'(?i)(_ARN|_NAME|_ID|_PARAM|_PARAMETER|_PATH|_REF|_SSM|_FILE|_URI|_LENGTH|_POLICY|_MIN|_MAX)$', name):
            checks.add('aws.htbp.lambda.env_var_names_not_credentials')
        if any(word in name.upper() for word in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'PASSWORD')):
            checks.update({'aws.c2b.codebuild.no_plaintext_sensitive_env_names', 'aws_nist_codebuild_project_plaintext_env_variables_no_sensitive_aws_values'})
        if name.upper() in {'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY'}:
            checks.add('aws.nist.codebuild_exact_aws_key_env_names')
        if name in {'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY'}:
            checks.add('aws.pci.codebuild.aws_key_environment_vars')
        if name in {'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'ECS_ENGINE_AUTH_DATA'}:
            checks.update({'aws.c2b.ecs.no_credential_named_env_vars', 'aws_ecs_task_definition_credential_environment_names', 'aws_nist_ecs_task_definition_container_environment_no_secret'})
        if _active is not None and name in _active.policy_names['aws_cis_lambda_database_secrets_manager']:
            checks.add('aws_cis_lambda_database_secrets_manager')
    elif provider == 'gcp' and SECRET_NAME.search(name) and not REFERENCE_SUFFIX.search(name):
        checks.update(NAMED_CHECKS['gcp'])
    elif provider == 'k8s':
        tokens = [t.upper() for t in re.findall(r'[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+', name)]
        suffixes = {'FILE','PATH','DIR','NAME','REF','TTL','URL','URI','ENDPOINT','TYPE','LENGTH','ID','ENABLED','EXPIRY','EXPIRATION','AUDIENCE','ISSUER','HEADER','LOCATION','MOUNT'}
        if tokens and tokens[-1] not in suffixes and (any(marker in token for token in tokens for marker in ('PASSWORD','PASSWD','PASSPHRASE','SECRET','APIKEY','PRIVATEKEY','CREDENTIAL')) or any(t.endswith('TOKEN') for t in tokens) or any(pair in {('API','KEY'),('PRIVATE','KEY'),('ACCESS','KEY'),('AUTH','KEY'),('SIGNING','KEY')} for pair in zip(tokens, tokens[1:]))):
            checks.add('k8s.claude.pod.no_literal_secret_env')
    elif provider == 'azure':
        # This existing check matches every declared plain value, including MODE.
        checks.add('azure.claude.container_group_secure_environment_variables')
    if provider in {'azure', 'k8s'} and _active is not None and name.casefold() in _active.policy_names['azure_aks_cluster_3_5_1_14_247ebcd']:
        checks.add('azure_aks_cluster_3_5_1_14_247ebcd')
    return checks

def named_literal(name, literal, *, provider, resource_id, scope, path, checks=None):
    if not enabled():
        return
    from peaso.secret_scanning import _fingerprint
    matched = literal_name_checks(provider, name)
    if literal == '':
        matched.discard('k8s.claude.pod.no_literal_secret_env')
    if checks is not None:
        matched &= checks
    if _active is not None and _active.selected_checks is not None:
        matched &= _active.selected_checks
    if isinstance(literal, str) and matched and not reference_literal(literal):
        with source_context(resource_id=resource_id, scope=scope, path=path, field=name, location_kind='configuration'):
            remember(literal, _fingerprint(literal), path=path, engine='configuration',
                     rule='literal_credential_name', check_ids=matched)


def named_mapping(mapping, *, provider, resource_id, scope, path, checks, entry_list=False):
    """A native name selector preserves filtered env entries without fake indices."""
    if not enabled() or not checks:
        return
    for name, literal in mapping.items():
        selector = '[name=' + json.dumps(name) + '].value' if entry_list else '[' + json.dumps(name) + ']'
        named_literal(name, literal, provider=provider, resource_id=resource_id, scope=scope, path=path + selector, checks=checks)


def named_environment(value, *, provider, resource_id, scope='', path='', checks=None):
    """Capture existing name-based literal witnesses, never resolve references.

    The caller invokes this only on native configuration it already reads.
    It does not enable content scans or introduce new provider requests.
    """
    if not enabled() or not isinstance(resource_id, str) or not resource_id or not isinstance(value, dict):
        return
    def record(name, literal, location):
        named_literal(name, literal, provider=provider, resource_id=resource_id, scope=scope, path=location, checks=checks)
    # ListFunctions passes its native function object. Every other caller
    # supplies the exact environment field already selected by its native route.
    if provider == 'aws' and isinstance(value.get('Environment'), dict):
        value = value['Environment']
        path = path + '.Environment' if path else 'Environment'
    for key in ('Variables', 'environmentVariables', 'env', 'environment', 'EnvironmentVariables'):
        child = value.get(key)
        native_path = path + '.' + key if path else key
        if key in {'environmentVariables', 'Variables'} and isinstance(child, dict):
            for name, literal in islice(child.items(), 20000):
                record(name, literal, native_path + '[' + json.dumps(name) + ']')
        if isinstance(child, list):
            for i, entry in enumerate(child[:20000]):
                if (isinstance(entry, dict) and not set(entry) & {'valueFrom', 'valueSource'}
                        and entry.get('type', 'PLAINTEXT') == 'PLAINTEXT'):
                    record(entry.get('name'), entry.get('value'), native_path + '[' + str(i) + '].value')


class EphemeralCipher:
    """Owned CLI export only: key lives for this one invocation."""
    def __init__(self):
        from cryptography.fernet import Fernet
        self.fernet = Fernet(Fernet.generate_key())

    def encrypt(self, value):
        return self.fernet.encrypt(json.dumps(value, separators=(',', ':')).encode()).decode()

    def decrypt(self, value):
        return json.loads(self.fernet.decrypt(value.encode()))


def checks_for_request(request):
    """Use the evaluator's validated selection, including framework selectors."""
    from peaso.engine import _selection
    provider = request.get('connector', request).get('provider')
    return {check.id for check in _selection(provider, request.get('categories'), request.get('checks'), request.get('frameworks'))[1]}


def url_credentials(url, *, resource_id, path, check_id, scope='', source=''):
    """Capture observed URL userinfo only; never decode, resolve or fetch it."""
    if not enabled() or not isinstance(url, str):
        return
    from urllib.parse import urlsplit
    from peaso.secret_scanning import _fingerprint
    try:
        parts = urlsplit(url)
        if parts.scheme not in {'http', 'https', 'ssh'} or not parts.hostname or '@' not in parts.netloc:
            return
        userinfo = parts.netloc.rsplit('@', 1)[0]
        # Preserve exact observed bytes, including percent escapes. A username
        # without a password is still the userinfo matched by the Azure check.
        username, separator, password = userinfo.partition(':')
        observed = password if separator else username
        if observed:
            with source_context(resource_id=resource_id, scope=scope, path=path, source=source, location_kind='configuration'):
                remember(observed, _fingerprint(observed), path=path, engine='configuration',
                         rule='url_userinfo', check_ids={check_id})
    except ValueError:
        return


def export_report(report, sink):
    """Attach plaintext only to explicitly requested, owned CLI JSON details."""
    from peaso.finding_groups import group_report
    grouped = group_report(report)
    document = sink.document()
    for finding in grouped.get('findings', []):
        for observation in finding.get('observations', [finding]):
            private = details(observation, document, sink.cipher, tenant=sink.tenant, scan_id=sink.scan_id)
            if private is not None:
                observation['secret_evidence'] = private
        if finding.get('secret_fingerprint'):
            finding['secret_evidence'] = details(finding, document, sink.cipher, tenant=sink.tenant, scan_id=sink.scan_id)
    return grouped


def without_private_values(value):
    """Defense at AI/public output boundaries; never mutate private detail state."""
    if isinstance(value, dict):
        return {key: without_private_values(child) for key, child in value.items() if key != 'secret_evidence'}
    if isinstance(value, (list, tuple)):
        return [without_private_values(child) for child in value]
    return value


def page_matches(matches, offset, budget):
    """Bound hosted detail pages without truncating any matched value/path."""
    total = sum(len(match['locations']) for match in matches)
    cursor = 0; size = 0; output = []
    for match in matches:
        selected = None
        for location in match['locations']:
            if cursor < offset:
                cursor += 1
                continue
            overhead = {k: v for k, v in match.items() if k != 'locations'}
            cost = len(json.dumps(location, ensure_ascii=False).encode())
            if selected is None:
                cost += len(json.dumps(overhead, ensure_ascii=False).encode()) + 32
            # Capture's maximum value/path sizes ensure one full occurrence fits.
            if output and (size + cost > budget or cursor - offset >= 100):
                return output, cursor, total
            if selected is None:
                selected = dict(overhead, locations=[])
                output.append(selected)
            selected['locations'].append(location)
            size += cost; cursor += 1
    return output, None, total


def reuse_image_layer(leaks, **source):
    """Join only evidence already scanned under this exact native layer digest.

    AWS caches redacted layer projections. Reusing encrypted observations of
    those verified bytes preserves image provenance without rereading a source.
    """
    with _lock:
        if _active is None:
            return
        fingerprints = {leak.get('fingerprint') for leak in leaks}
        fingerprints.update(component for fp in list(fingerprints) for component in _active.related.get(fp, ()))
        with _active.batch():
            for fp in fingerprints:
                if fp not in _active.records:
                    continue
                row = _active.load(fp)
                for location in list(row['locations']):
                    if location.get('layer') != source.get('layer'):
                        continue
                    observed = dict(location, **source)
                    for detector in list(row['detectors']):
                        _active.remember(row['value'], fp, observed, detector['engine'], detector['rule'], location.get('_check_ids', ()))


def load_group_details(artifacts, cipher, tenant, scan_id, findings, *, offset=0):
    """Authorized group detail: exact failed members, one encrypted scan read."""
    selected = [finding for finding in findings if eligible(finding)]
    if not selected:
        return None
    try:
        document = artifacts.get(tenant, private_reference(tenant, scan_id))
    except Exception:
        return details(selected[0], None, cipher, tenant=tenant, scan_id=scan_id)
    matches = {}
    states = []
    try:
        index = private_index(document, cipher, tenant, scan_id) if 'index' in document else None
        for finding in selected:
            private = details(finding, document, cipher, tenant=tenant, scan_id=scan_id, index=index)
            if not private:
                continue
            states.append(private)
            for match in private['matches']:
                existing = matches.get(match['fingerprint'])
                if existing is None:
                    matches[match['fingerprint']] = match
                else:
                    for loc in match['locations']:
                        if loc not in existing['locations']:
                            existing['locations'].append(loc)
        if not matches:
            return states[0] if states else None
        page, next_offset, total = page_matches(list(matches.values()), offset, 3 * 1024 * 1024)
        return {'status': 'available', 'matches': page, 'next_offset': next_offset,
                'total_locations': total, 'complete': not document.get('incomplete', False)
                and all(state.get('complete', True) and state.get('status') != 'unavailable' for state in states)}
    except Exception:
        return {'status': 'unavailable', 'matches': [], 'message': 'Private secret evidence is unavailable. Run a fresh scan.'}


def private_index(document, cipher, tenant, scan_id):
    """One encrypted lookup index; independent of process-local secret HMAC keys."""
    index = cipher.decrypt(document['index'])
    if (index.get('tenant'), index.get('scan_id')) != (tenant, scan_id):
        raise ValueError('private evidence index scope mismatch')
    return index


def reference_literal(value):
    """Recognizable references are not recovered secret-store values."""
    return bool(isinstance(value, str) and (
        re.fullmatch(r'arn:[^:]+:(?:secretsmanager|ssm):[^:]+:[0-9]{12}:(?:secret:|parameter/).+', value)
        or re.fullmatch(r'projects/[^/]+/secrets/[^/]+(?:/versions/[^/]+)?', value)
        or re.fullmatch(r'https://[^/]+\.vault\.azure\.net/secrets/[^/]+(?:/[^/]+)?', value, re.I)
        or re.fullmatch(r'(?:\$\{[^}]+\}|\$\([^)]+\)|\{\{.+\}\})', value)))


def full_match_values(primary, full, *, payload, rule):
    """Transient complete representations/components, also used for redaction."""
    if not isinstance(full, str) or not full:
        return []
    values = [full]
    # The pinned AWS detector emits AccessKeyID:SecretAccessKey. Retain the
    # actual secret component separately when its exact bytes occur in source.
    if rule.casefold() == 'aws' and full.startswith(primary + ':'):
        candidate = full[len(primary) + 1:]
        if re.fullmatch(r'[A-Za-z0-9/+=]{40}', candidate) and candidate.encode() in payload:
            values.append(candidate)
    return values


def remember_full_match(primary, full, *, payload, path, engine, rule):
    """Capture full detector evidence without altering canonical primary HMACs."""
    if not enabled():
        return
    with batched():
        _remember_full_match(primary, full, payload=payload, path=path, engine=engine, rule=rule)


def _remember_full_match(primary, full, *, payload, path, engine, rule):
    from peaso.secret_scanning import _fingerprint
    for value in full_match_values(primary, full, payload=payload, rule=rule):
        start, found = 0, False
        while (position := payload.find(value.encode(), start)) >= 0:
            remember(value, _fingerprint(value), path=path, line=payload[:position].count(b'\n') + 1, engine=engine, rule=rule)
            start, found = position + len(value.encode()), True
            if _active is None or _active.locations >= MAX_LOCATIONS:
                break
        if not found:
            with source_context(location_kind='detector_composite'):
                remember(value, _fingerprint(value), path=path, line=None, engine=engine, rule=rule)
        with _lock:
            if _active is not None:
                primary_fp, value_fp = _fingerprint(primary), _fingerprint(value)
                if value_fp not in _active.records:
                    continue
                linked = _active.related.get(primary_fp, set())
                if value_fp in linked:
                    continue
                if _active.related_count >= MAX_LOCATIONS or primary_fp not in _active.related and len(_active.related) >= MAX_VALUES:
                    _active.incomplete = True
                    continue
                _active.related.setdefault(primary_fp, set()).add(value_fp)
                _active.related_count += 1
