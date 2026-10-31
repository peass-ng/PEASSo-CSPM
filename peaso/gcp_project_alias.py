"""Offline proof for one direct project policy and its CAI numeric alias."""
from dataclasses import dataclass
import json
import re


class AliasUnavailable(ValueError):
    pass


def _guard(obj):
    if not isinstance(obj, dict):
        raise AliasUnavailable('expected native object')
    if 'collection_status' in obj and obj['collection_status'] != 'collected':
        raise AliasUnavailable('incomplete native object')
    cov = obj.get('_coverage', {})
    if not isinstance(cov, dict):
        raise AliasUnavailable('malformed fact coverage')
    if 'collection_status' in cov:
        marker = cov['collection_status']
        if not isinstance(marker, dict) or marker.get('status') != 'collected' or obj.get('collection_status') != 'collected':
            raise AliasUnavailable('unavailable object authority')


def _get(obj, key, kind):
    _guard(obj)
    marker = obj.get('_coverage', {}).get(key)
    if key in obj.get('_coverage', {}):
        if not isinstance(marker, dict) or marker.get('status') not in ('collected', 'empty'):
            raise AliasUnavailable('unavailable fact: ' + key)
    if key not in obj or not (isinstance(obj[key], kind) if kind in (dict, list) else type(obj[key]) is kind):
        raise AliasUnavailable('missing or malformed fact: ' + key)
    value = obj[key]
    if marker is not None and marker['status'] == 'empty' and value not in (None, '', [], {}):
        raise AliasUnavailable('contradictory empty marker: ' + key)
    return value


def _complete(envelope, scope, kind, *, root_collision=False):
    if _get(envelope, 'scope', str) != scope or _get(envelope, 'type', str) != kind:
        raise AliasUnavailable('foreign collection')
    statuses = (_get(envelope, 'status', str), _get(envelope, 'coverage_status', str))
    if statuses != ('collected', 'collected'):
        # The collector retains both observations on an identity collision.
        # This one error can be discharged by the independent proof below;
        # denied reads, pagination failures, and other conflicts cannot.
        if not root_collision or statuses != ('partial', 'partial') or _get(envelope, 'error', dict) != {
                'kind': 'malformed', 'code': 'conflicting_iam_policy_identity'}:
            raise AliasUnavailable('incomplete collection')
    requests = _get(envelope, 'source_requests', list)
    if not requests or any(type(v) is not str or not v for v in requests):
        raise AliasUnavailable('missing collection provenance')
    rows = _get(envelope, 'items', list)
    for row in rows:
        provenance = _get(row, '_provenance', dict)
        if _get(provenance, 'scope', str) != scope:
            raise AliasUnavailable('foreign item provenance')
        refs = _get(provenance, 'source_requests', list)
        if not refs or any(type(v) is not str or not v or v not in requests for v in refs):
            raise AliasUnavailable('unbound item provenance')
    return rows


def _native(value):
    """Verify all retained nested fields before comparing policy content."""
    if isinstance(value, dict):
        _guard(value)
        for key in value.get('_coverage', {}):
            if key not in value:
                raise AliasUnavailable('omitted covered policy field')
            _get(value, key, type(value[key]))
        return {k: _native(_get(value, k, type(v))) for k, v in value.items()
                if k not in ('_coverage', 'collection_status')}
    if isinstance(value, list):
        return [_native(v) for v in value]
    if value is None or type(value) in (str, int, bool):
        return value
    raise AliasUnavailable('non-native policy value')


@dataclass(frozen=True)
class AliasBinding:
    project_number: str
    direct_position: int
    alias_position: int
    source_requests: tuple[str, ...]


def prove_project_alias(scope, project_envelope, policy_envelope, request_ledger):
    """Bind views or raise AliasUnavailable; caller must still evaluate full audit chain.

    Policy set order is compared after native authority and schema validation.
    """
    if type(scope) is not str or not re.fullmatch(r'projects/[a-z0-9][a-z0-9-]*', scope, re.ASCII):
        raise AliasUnavailable('unsupported scope')
    projects = _complete(project_envelope, scope, 'project')
    policies = _complete(policy_envelope, scope, 'iam_policy', root_collision=True)
    if len(projects) != 1:
        raise AliasUnavailable('ambiguous project inventory')
    candidates = [(i, row) for i, row in enumerate(policies) if root_candidate(row)]
    if len(candidates) != 2:
        raise AliasUnavailable('ambiguous or unsupported root inventory')
    project = projects[0]
    project_id = _get(project, 'projectId', str)
    if not re.fullmatch(r'[a-z][a-z0-9-]*[a-z0-9]', project_id, re.ASCII):
        raise AliasUnavailable('unsupported independent project ID')
    number_name = _get(project, 'name', str)
    if not re.fullmatch(r'projects/[1-9][0-9]*', number_name, re.ASCII):
        raise AliasUnavailable('malformed numeric project identity')
    number = number_name.split('/')[1]
    if scope not in ('projects/' + project_id, number_name):
        raise AliasUnavailable('unbound selected project')
    direct_indices = [i for i, p in candidates if _get(p, 'name', str) == scope]
    if len(direct_indices) != 1:
        raise AliasUnavailable('ambiguous direct root')
    direct_pos = direct_indices[0]
    alias_pos = next(i for i, _ in candidates if i != direct_pos)
    direct, alias = policies[direct_pos], policies[alias_pos]
    # A collision elsewhere in the CAI inventory cannot be cleared by proving
    # this root pair. Preserve its partial collection state.
    identities = {}
    for position, item in enumerate(policies):
        identities.setdefault(_get(item, 'native_id', str), []).append(position)
    if any(len(positions) > 1 and set(positions) != {direct_pos, alias_pos}
           for positions in identities.values()):
        raise AliasUnavailable('other policy identity collision')
    allowed = {'name', 'bindings', 'auditConfigs', 'version', 'etag', 'assetType',
               'project', 'folders', '_coverage', '_provenance', '_resource_id',
               'native_id', '_relationships', 'collection_status'}
    if any(set(item) - allowed for item in (direct, alias)):
        raise AliasUnavailable('unsupported policy row schema')
    alias_provenance = _get(alias, '_provenance', dict)
    if 'representation' in alias_provenance or 'representation' in alias_provenance.get('_coverage', {}):
        if _get(alias_provenance, 'representation', str) != 'partial':
            raise AliasUnavailable('CAI projection authority contradictory')
    source_roles = [set(_get(_get(item, '_provenance', dict), 'source_requests', list))
                    for item in (project, direct, alias)]
    if any(source_roles[i] & source_roles[j] for i in range(3) for j in range(i)):
        raise AliasUnavailable('request source roles overlap')
    provenance = _get(direct, '_provenance', dict)
    if _get(provenance, 'representation', str) != 'full':
        raise AliasUnavailable('direct root not authoritative')
    if (_get(alias, 'name', str) not in {
            '//cloudresourcemanager.googleapis.com/' + number_name,
            '//cloudresourcemanager.googleapis.com/projects/' + project_id}
        or _get(alias, 'assetType', str) != 'cloudresourcemanager.googleapis.com/Project'
        or _get(alias, 'project', str) != number_name):
        raise AliasUnavailable('unbound CAI projection identity')
    _validate_binding_content(direct)
    _validate_binding_content(alias)
    for policy in (direct, alias):
        for set_field in ('bindings', 'auditConfigs'):
            if set_field in policy or set_field in policy.get('_coverage', {}):
                _canonical_policy_set(set_field, _native(_get(policy, set_field, list)))
    for key, kind in (('bindings', list), ('auditConfigs', list), ('version', int), ('etag', str)):
        if key in alias.get('_coverage', {}) and key not in alias:
            raise AliasUnavailable('projection field authority unavailable')
        if key not in alias:
            continue
        projected = _native(_get(alias, key, kind))
        if key in direct:
            authoritative = _native(_get(direct, key, kind))
        elif key in ('bindings', 'auditConfigs') and key not in direct.get('_coverage', {}):
            authoritative = []
        else:
            raise AliasUnavailable('cannot compare projected field')
        if key in ('bindings', 'auditConfigs'):
            projected = _canonical_policy_set(key, projected)
            authoritative = _canonical_policy_set(key, authoritative)
        if json.dumps(projected, sort_keys=True) != json.dumps(authoritative, sort_keys=True):
            raise AliasUnavailable('contradictory policy field: ' + key)
    _verify_ledger(scope, project, direct, alias, request_ledger, policy_envelope)
    refs = set().union(*source_roles, _get(policy_envelope, "source_requests", list))
    return AliasBinding(number, direct_pos, alias_pos, tuple(sorted(refs)))


CRM = "https://cloudresourcemanager.googleapis.com"
CAI = "https://cloudasset.googleapis.com"

KNOWN_RESOURCE_PEERS = frozenset({
    "storage.googleapis.com/Bucket",
    "compute.googleapis.com/Instance",
    "pubsub.googleapis.com/Topic",
    "cloudfunctions.googleapis.com/CloudFunction",
    "cloudkms.googleapis.com/KeyRing",
    "cloudkms.googleapis.com/CryptoKey",
})

def root_candidate(row):
    """Keep uncertain and hierarchy rows; exclude only typed resource peers."""
    try:
        name = _get(row, "name", str)
        if not name.strip() or name.count("/") <= 1:
            return True
        coverage = row.get("_coverage", {})
        if "_representation" in row or "_representation" in coverage:
            representation = _get(row, "_representation", str)
        elif "_provenance" in row or "_provenance" in coverage:
            provenance = _get(row, "_provenance", dict)
            representation = (_get(provenance, "representation", str)
                              if "representation" in provenance or "representation" in provenance.get("_coverage", {})
                              else None)
        else:
            representation = None
        if representation == "full":
            return True
        asset_type = _get(row, "assetType", str)
        if asset_type in {"cloudkms.googleapis.com/KeyRing", "cloudkms.googleapis.com/CryptoKey"}:
            # These are resource peers only with a structurally nested KMS
            # name and a readable numeric owning-project marker.
            project = _get(row, "project", str)
            suffix = r"(?:/cryptoKeys/[^/]+)?" if asset_type.endswith("/CryptoKey") else ""
            if (not re.fullmatch(r"projects/[1-9][0-9]*", project, re.ASCII)
                    or not re.fullmatch(r"//cloudkms\.googleapis\.com/projects/[^/]+/locations/[^/]+/keyRings/[^/]+" + suffix,
                                        name, re.ASCII)):
                return True
        if asset_type == "iam.googleapis.com/ServiceAccount":
            # A service account is a resource peer only under its structurally
            # nested IAM name; a project root never has that name.
            return not re.fullmatch(r"//iam\.googleapis\.com/projects/[^/]+/serviceAccounts/[^/]+", name, re.ASCII)
        return asset_type not in KNOWN_RESOURCE_PEERS
    except AliasUnavailable:
        return True


def _validate_binding_content(policy):
    """Policy identity cannot be established from equal malformed bindings."""
    coverage = policy.get('_coverage', {})
    for field, kind in (('version', int), ('etag', str)):
        if field in policy or field in coverage:
            value = _get(policy, field, kind)
            if field == 'version' and value not in (0, 1, 3):
                raise AliasUnavailable('unsupported IAM policy version')
    if 'bindings' not in policy and 'bindings' not in coverage:
        return
    bindings = _native(_get(policy, 'bindings', list))
    for binding in bindings:
        if not isinstance(binding, dict) or set(binding) - {'role', 'members', 'condition'}:
            raise AliasUnavailable('malformed IAM binding')
        role = binding.get('role')
        members = binding.get('members')
        if (not isinstance(role, str) or not re.fullmatch(
                r'(?:roles/[A-Za-z0-9_.]+|(?:projects|organizations)/[^/\s]+/roles/[A-Za-z0-9_.]+)', role)
                or not isinstance(members, list) or not members
                or any(type(member) is not str or not member.strip() or member != member.strip()
                       for member in members)):
            raise AliasUnavailable('malformed IAM binding role or members')
        if 'condition' in binding:
            condition = binding['condition']
            if (not isinstance(condition, dict)
                    or set(condition) - {'expression', 'title', 'description', 'location'}
                    or not isinstance(condition.get('expression'), str)
                    or not condition['expression'].strip()
                    or any(type(value) is not str for value in condition.values())):
                raise AliasUnavailable('malformed IAM binding condition')


def _canonical_policy_set(field, rows):
    """Return comparison-only IAM set copies; never coalesce or rewrite source rows."""
    def strings(values, label):
        if (not isinstance(values, list) or
                any(type(value) is not str or not value.strip() or value != value.strip()
                    for value in values) or len(values) != len(set(values))):
            raise AliasUnavailable('malformed or duplicate ' + label)
        return sorted(values)

    def unique_sorted(values, label):
        keys = [json.dumps(value, sort_keys=True, separators=(',', ':')) for value in values]
        if len(keys) != len(set(keys)):
            raise AliasUnavailable('duplicate ' + label)
        return [value for _, value in sorted(zip(keys, values), key=lambda entry: entry[0])]

    if not isinstance(rows, list):
        raise AliasUnavailable('malformed IAM policy set')
    if field == 'bindings':
        result = []
        for row in rows:
            if not isinstance(row, dict) or set(row) - {'role', 'members', 'condition'}:
                raise AliasUnavailable('malformed IAM binding')
            role = row.get('role')
            if type(role) is not str or not role:
                raise AliasUnavailable('malformed IAM binding role')
            canonical = {'role': role, 'members': strings(row.get('members'), 'IAM members')}
            if 'condition' in row:
                condition = row['condition']
                if (not isinstance(condition, dict)
                        or set(condition) - {'expression', 'title', 'description', 'location'}
                        or type(condition.get('expression')) is not str
                        or not condition['expression'].strip()
                        or any(type(value) is not str for value in condition.values())):
                    raise AliasUnavailable('malformed IAM binding condition')
                canonical['condition'] = dict(condition)
            result.append(canonical)
        return unique_sorted(result, 'IAM binding')
    if field == 'auditConfigs':
        result = []
        for row in rows:
            if (not isinstance(row, dict) or set(row) - {'service', 'auditLogConfigs'}
                    or type(row.get('service')) is not str or not row['service'].strip()
                    or not isinstance(row.get('auditLogConfigs'), list)):
                raise AliasUnavailable('malformed IAM audit config')
            logs = []
            for log in row['auditLogConfigs']:
                if (not isinstance(log, dict) or set(log) - {'logType', 'exemptedMembers'}
                        or type(log.get('logType')) is not str or not log['logType'].strip()):
                    raise AliasUnavailable('malformed IAM audit log config')
                canonical = {'logType': log['logType']}
                if 'exemptedMembers' in log:
                    canonical['exemptedMembers'] = strings(log['exemptedMembers'], 'exempted members')
                logs.append(canonical)
            canonical = {'service': row['service']}
            if 'auditLogConfigs' in row:
                canonical['auditLogConfigs'] = unique_sorted(logs, 'IAM audit log config')
            result.append(canonical)
        return unique_sorted(result, 'IAM audit config')
    raise AliasUnavailable('unsupported IAM policy set')


def _verify_ledger(scope, project, direct, alias, ledger, policy_envelope):
    if not isinstance(ledger, list):
        raise AliasUnavailable("request ledger unavailable")
    refs = {role: _get(_get(item, "_provenance", dict), "source_requests", list)
            for role, item in (("project", project), ("direct", direct), ("alias", alias))}
    inventory_refs = _get(policy_envelope, "source_requests", list)
    if len(inventory_refs) != len(set(inventory_refs)):
        raise AliasUnavailable("duplicate inventory request reference")
    required = set(inventory_refs).union(*refs.values())
    # Index the required evidence once; repeated linear scans of the global
    # ledger for every pagination reference would multiply collection costs.
    index = {}
    for row in ledger:
        if isinstance(row, dict) and type(row.get("id")) is str and row["id"] in required:
            index.setdefault(row["id"], []).append(row)

    def request(ref):
        matches = index.get(ref, [])
        if len(matches) != 1:
            raise AliasUnavailable("request reference missing or duplicated")
        _get(matches[0], "id", str)
        return matches[0]

    by_ref = {}
    for role, values in refs.items():
        if len(values) != len(set(values)):
            raise AliasUnavailable("duplicate item request reference")
        by_ref[role] = [request(ref) for ref in values]

    def exact(row, method, url, query, body=None):
        from urllib.parse import urlsplit
        expected = {"scope": scope, "status": "collected", "http_status": 200,
                    "method": method, "url": url, "operation": urlsplit(url).path, "query": query}
        if any(_get(row, key, type(value)) != value for key, value in expected.items()):
            raise AliasUnavailable("request authority mismatch")
        if body is None:
            if "request" in row:
                raise AliasUnavailable("unexpected request body")
        elif _native(_get(row, "request", dict)) != body:
            raise AliasUnavailable("request body mismatch")

    project_url = f"{CRM}/v3/{scope}"
    get_rows = [row for row in by_ref["project"] if row.get("url") == project_url]
    if len(get_rows) != 1:
        raise AliasUnavailable("one independent project GET required")
    exact(get_rows[0], "GET", project_url, {})
    direct_url = f"{CRM}/v3/{scope}:getIamPolicy"
    cai_url = f"{CAI}/v1/{scope}:searchAllIamPolicies"
    page_sizes = set()

    def direct_read(row):
        exact(row, "POST", direct_url, {}, {"options": {"requestedPolicyVersion": 3}})

    def cai_read(row):
        query = _get(row, "query", dict)
        if (set(query) != {"pageSize"} or type(query["pageSize"]) is not int
                or not 1 <= query["pageSize"] <= 1000):
            raise AliasUnavailable("unfiltered CAI pagination required")
        page_sizes.add(query["pageSize"])
        exact(row, "GET", cai_url, query)

    for row in by_ref["direct"]:
        direct_read(row)
    for row in by_ref["alias"]:
        cai_read(row)
    # Empty pages have no item provenance. They still supply the inventory's
    # completeness and must have the same successful, unfiltered authority.
    for ref in inventory_refs:
        row = request(ref)
        if row.get("url") == direct_url:
            direct_read(row)
        elif row.get("url") == cai_url:
            cai_read(row)
        else:
            raise AliasUnavailable("unsupported project policy inventory request")
    if len(page_sizes) != 1:
        raise AliasUnavailable("inconsistent CAI pagination parameters")
