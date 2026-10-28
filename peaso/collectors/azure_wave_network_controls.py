"""Pure projection of Azure NIC effective-route responses.

This intentionally does not claim subnet coverage or classify Internet-bound
destinations. A caller must establish complete attached-NIC inventory and
route-table coverage before using these rows as evaluator evidence.
"""
from __future__ import annotations

from ipaddress import ip_address, ip_network
import re
from urllib.parse import urlsplit


class RouteEvidenceUnavailable(ValueError):
    """A route response cannot support a defensive conclusion."""


ARM = 'https://management.azure.com'
API_VERSION = '2025-05-01'
NATIVE_TYPES = frozenset({'subnet_effective_route'})
UUID = r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}'
SEGMENT = r'[A-Za-z0-9_.()-]{1,90}'
PUBLIC_WITNESSES = ('1.1.1.1', '8.8.8.8', '9.9.9.9',
                    '2606:4700:4700::1111', '2001:4860:4860::8888')


def required_types(wanted):
    return {'subnet', 'nic', 'vm', 'effective_route'} if NATIVE_TYPES.intersection(wanted) else set()


def _arm_id(value, scope, kind):
    path = {
        'nic': r'Microsoft\.Network/networkInterfaces/' + SEGMENT,
        'subnet': r'Microsoft\.Network/virtualNetworks/' + SEGMENT + r'/subnets/' + SEGMENT,
        'vm': r'Microsoft\.Compute/virtualMachines/' + SEGMENT,
    }[kind]
    if (not isinstance(value, str) or not re.fullmatch(re.escape(scope) +
            r'/resourceGroups/' + SEGMENT + r'/providers/' + path, value, re.I)
            or any(part in ('.', '..') for part in value.split('/'))):
        raise RouteEvidenceUnavailable('foreign or malformed ' + kind + ' ARM identity')
    return value


def project_nic_effective_routes(nic_id: str, pages: list[dict]) -> list[dict]:
    """Normalize a complete response chain from getEffectiveRouteTable.

    Each page has ``request_url`` and ``body``. The caller owns the HTTP
    request and records the URL actually requested, so pagination is checked
    without making a cloud request here.
    """
    scope_match = re.match('/subscriptions/' + UUID, nic_id) if isinstance(nic_id, str) else None
    if scope_match is None:
        raise RouteEvidenceUnavailable('NIC identity unavailable')
    _arm_id(nic_id, scope_match.group(), 'nic')
    if not isinstance(pages, list) or not pages or len(pages) > 32:
        raise RouteEvidenceUnavailable('effective route response absent')
    expected = nic_id.rstrip('/') + '/effectiveRouteTable'
    expected_next: str | None = None
    normalized: list[dict] = []
    seen: set[tuple] = set()
    for position, page in enumerate(pages):
        if not isinstance(page, dict) or not isinstance(page.get('request_url'), str):
            raise RouteEvidenceUnavailable('requested route page URL unavailable')
        actual = page['request_url']
        url = urlsplit(actual)
        if url.scheme != 'https' or url.hostname != 'management.azure.com' or url.username or url.password or url.fragment:
            raise RouteEvidenceUnavailable('route page has foreign URL')
        if position == 0:
            if url.path.casefold() != expected.casefold() or 'api-version=' not in url.query:
                raise RouteEvidenceUnavailable('first response is not NIC effective route table')
        elif actual != expected_next:
            raise RouteEvidenceUnavailable('effective route pagination chain broken')
        if position and not (url.path.casefold() == expected.casefold() or re.fullmatch(
                re.escape(nic_id) + r'/operationResults/' + UUID, url.path, re.I)):
            raise RouteEvidenceUnavailable('foreign NIC effective route continuation')
        body = page.get('body')
        if not isinstance(body, dict) or not isinstance(body.get('value'), list):
            raise RouteEvidenceUnavailable('effective route response malformed')
        for route in body['value']:
            if not isinstance(route, dict) or route.get('state') not in ('Active', 'Invalid'):
                raise RouteEvidenceUnavailable('effective route state unavailable')
            if route['state'] == 'Invalid':
                continue
            prefixes = route.get('addressPrefix')
            hop = route.get('nextHopType')
            addresses = route.get('nextHopIpAddress', [])
            if not isinstance(prefixes, list) or not prefixes or not isinstance(addresses, list):
                raise RouteEvidenceUnavailable('active route prefix or next hop malformed')
            if hop not in ('Internet', 'VirtualAppliance', 'None', 'VirtualNetworkGateway', 'VnetLocal'):
                raise RouteEvidenceUnavailable('active route next hop unsupported')
            if hop == 'VirtualAppliance':
                if len(addresses) != 1 or not isinstance(addresses[0], str):
                    raise RouteEvidenceUnavailable('virtual appliance next hop ambiguous')
                try:
                    address = str(ip_address(addresses[0]))
                except ValueError as exc:
                    raise RouteEvidenceUnavailable('virtual appliance address malformed') from exc
            elif addresses:
                raise RouteEvidenceUnavailable('unexpected next hop address')
            else:
                address = None
            for prefix in prefixes:
                if not isinstance(prefix, str):
                    raise RouteEvidenceUnavailable('effective route prefix malformed')
                try:
                    network = ip_network(prefix, strict=True)
                except ValueError as exc:
                    raise RouteEvidenceUnavailable('effective route prefix malformed') from exc
                key = str(network), hop, address
                if key in seen:
                    raise RouteEvidenceUnavailable('duplicate active effective route')
                seen.add(key)
                normalized.append({'nicId': nic_id, 'destinationPrefix': str(network),
                                   'nextHopType': hop, 'nextHopIpAddress': address,
                                   'sourceOperation': 'networkInterfaces/getEffectiveRouteTable'})
        expected_next = body.get('nextLink')
        if expected_next is not None and (not isinstance(expected_next, str) or not expected_next):
            raise RouteEvidenceUnavailable('route nextLink malformed')
        if expected_next is None and position != len(pages) - 1:
            raise RouteEvidenceUnavailable('unrequested trailing route page')
    if expected_next is not None:
        raise RouteEvidenceUnavailable('effective route pagination incomplete')
    if not normalized:
        raise RouteEvidenceUnavailable('no active effective routes')
    return normalized


def direct_internet_witness(routes: list[dict]) -> dict | None:
    """Find one public destination whose unique longest-prefix route is Internet.

    This is an existential counterexample to universal firewall routing. It is
    neither observed traffic nor proof about any other destination.
    """
    if not isinstance(routes, list) or not routes:
        raise RouteEvidenceUnavailable('active route table absent')
    parsed = []
    for row in routes:
        if not isinstance(row, dict) or row.get('nextHopType') not in (
                'Internet', 'VirtualAppliance', 'None', 'VirtualNetworkGateway', 'VnetLocal'):
            raise RouteEvidenceUnavailable('active route next hop unsupported')
        try:
            network = ip_network(row['destinationPrefix'], strict=True)
        except (KeyError, TypeError, ValueError) as exc:
            raise RouteEvidenceUnavailable('active route prefix malformed') from exc
        parsed.append((network, row))
    for target in PUBLIC_WITNESSES:
        address = ip_address(target)
        assert address.is_global
        matches = [(net, row) for net, row in parsed if address in net]
        if not matches:
            continue
        longest = max(net.prefixlen for net, _ in matches)
        winners = [(net, row) for net, row in matches if net.prefixlen == longest]
        if len(winners) != 1:
            # Equal-prefix effective paths can have ECMP or unspecified
            # preference. They cannot establish a unique Internet next hop.
            continue
        network, row = winners[0]
        if row['nextHopType'] == 'Internet':
            return {'destinationIp': target, 'selectedPrefix': str(network),
                    'nextHopType': 'Internet', 'nicId': row.get('nicId')}
    return None


def _collection(reader, kind, scope):
    from .azure import AzureReadError
    matches = [row for row in reader.collections if row.get('type') == kind and
               isinstance(row.get('scope'), str) and row['scope'].casefold() == scope.casefold()]
    if len(matches) != 1:
        raise AzureReadError('route_prerequisite_unavailable')
    if matches[0].get('status') == 'denied':
        raise AzureReadError('route_prerequisite_denied', 403)
    if matches[0].get('status') not in ('collected', 'empty'):
        raise AzureReadError('route_prerequisite_unavailable')
    rows = matches[0].get('items')
    if not isinstance(rows, list) or (matches[0]['status'] == 'empty' and rows):
        raise RouteEvidenceUnavailable(kind + ' inventory malformed')
    return matches[0]


def _rows_by_id(rows, scope, kind):
    output = {}
    for row in rows:
        rid = _arm_id(row.get('id') if isinstance(row, dict) else None, scope, kind)
        _full_native_detail(row, kind)
        if rid.casefold() in output:
            raise RouteEvidenceUnavailable('duplicate ' + kind + ' identity')
        output[rid.casefold()] = row
    return output


def _full_native_detail(row, kind):
    provenance = row.get('_provenance') if isinstance(row, dict) else None
    if (not isinstance(provenance, dict) or provenance.get('representation') != 'full'
            or provenance.get('source_operation') != 'get'
            or provenance.get('read_only') is not True
            or not isinstance(provenance.get('api_version'), str)
            or not re.fullmatch(r'20[0-9]{2}-[0-9]{2}-[0-9]{2}', provenance['api_version'])):
        raise RouteEvidenceUnavailable(kind + ' full native GET unavailable')


def _attached_nic_subnets(nic, scope):
    nid = _arm_id(nic.get('id'), scope, 'nic')
    _full_native_detail(nic, 'nic')
    props = nic.get('properties')
    if not isinstance(props, dict):
        raise RouteEvidenceUnavailable('NIC properties unavailable')
    vm = props.get('virtualMachine')
    if vm is None:
        return nid, None, []
    if not isinstance(vm, dict):
        raise RouteEvidenceUnavailable('NIC VM attachment malformed')
    vmid = _arm_id(vm.get('id'), scope, 'vm')
    ip_configs = props.get('ipConfigurations')
    if not isinstance(ip_configs, list) or not ip_configs:
        raise RouteEvidenceUnavailable('attached NIC IP configurations unavailable')
    subnets = []
    config_ids = set()
    for config in ip_configs:
        config_id = config.get('id') if isinstance(config, dict) else None
        if (not isinstance(config_id, str) or not re.fullmatch(re.escape(nid) +
                r'/ipConfigurations/' + SEGMENT, config_id, re.I)):
            raise RouteEvidenceUnavailable('NIC IP configuration identity malformed')
        if config_id.casefold() in config_ids:
            raise RouteEvidenceUnavailable('duplicate NIC IP configuration identity')
        config_ids.add(config_id.casefold())
        subnet = config.get('properties', {}).get('subnet') if isinstance(config, dict) else None
        if not isinstance(subnet, dict):
            raise RouteEvidenceUnavailable('attached NIC subnet missing')
        subnets.append(_arm_id(subnet.get('id'), scope, 'subnet'))
    return nid, vmid, subnets


def _native_routes(effective, nic_id):
    """Project rows whose source pages were already read by NetworkQueries."""
    proofs = effective.get('source_evidence')
    if not isinstance(proofs, list):
        raise RouteEvidenceUnavailable('native effective route source proofs absent')
    relevant = [proof for proof in proofs if isinstance(proof, dict) and
                str(proof.get('resource_id', '')).casefold() == nic_id.casefold()]
    if not relevant or any(proof.get('source_operation') != 'effectiveRouteTable' or
                           proof.get('read_only') is not True or
                           proof.get('representation') != 'full' or
                           proof.get('api_version') != API_VERSION or
                           not isinstance(proof.get('response_sha256'), str) or
                           not re.fullmatch(r'[0-9a-f]{64}', proof['response_sha256'])
                           for proof in relevant):
        raise RouteEvidenceUnavailable('native effective route pages unproven')
    raw = []
    for row in effective['items']:
        if not isinstance(row, dict):
            raise RouteEvidenceUnavailable('effective route row malformed')
        parent = row.get('nic_id')
        if not isinstance(parent, str):
            raise RouteEvidenceUnavailable('effective route NIC reference absent')
        if parent.casefold() != nic_id.casefold():
            continue
        rid = row.get('id')
        if not isinstance(rid, str) or not re.fullmatch(re.escape(nic_id) +
                r'/effectiveRoutes/[0-9]+', rid, re.I):
            raise RouteEvidenceUnavailable('effective route row identity malformed')
        provenance = row.get('_provenance')
        if (not isinstance(provenance, dict) or
                provenance.get('source_operation') != 'effectiveRouteTable' or
                provenance.get('read_only') is not True or
                str(provenance.get('nic_id', '')).casefold() != nic_id.casefold()):
            raise RouteEvidenceUnavailable('effective route row provenance unavailable')
        raw.append(row.get('route'))
    if not raw:
        raise RouteEvidenceUnavailable('NIC effective route table empty')
    # Feed the already authenticated, complete native page projection into the
    # existing route-shape parser. This synthetic single page is used only for
    # shape normalization; source_evidence above supplies actual page proof.
    virtual_page = [{'request_url': ARM + nic_id + '/effectiveRouteTable?api-version=' + API_VERSION,
                     'body': {'value': raw}}]
    return project_nic_effective_routes(nic_id, virtual_page)


def collect(reader, scopes, wanted):
    """Project direct-Internet counterexamples from existing read-only facts.

    ``azure_effective_routes_native`` owns route HTTP, LRO and pagination.
    This consumer makes no additional request and cannot emit a PASS fact.
    """
    if not NATIVE_TYPES.intersection(wanted):
        return
    from .azure import _safe_error, AzureReadError
    for scope in scopes:
        if not isinstance(scope, str) or not re.fullmatch('/subscriptions/' + UUID, scope):
            raise RouteEvidenceUnavailable('subscription scope malformed')
        parents = [c for c in reader.collections if c.get('type') == 'subnet' and
                   isinstance(c.get('scope'), str) and (c['scope'].casefold() == scope.casefold() or
                   c['scope'].casefold().startswith(scope.casefold() + '/'))]
        target_scopes = {}
        for parent in parents:
            target_scopes.setdefault(parent['scope'].casefold(), parent['scope'])
        targets = list(target_scopes.values()) or [scope]
        try:
            if not parents:
                vnets = [c for c in reader.collections if c.get('type') == 'vnet' and
                          isinstance(c.get('scope'), str) and c['scope'].casefold() == scope.casefold()]
                if (len(vnets) != 1 or vnets[0].get('status') != 'empty' or
                        vnets[0].get('items') != [] or
                        vnets[0].get('service') not in (None, 'Microsoft.Network')):
                    raise RouteEvidenceUnavailable('subnet parent unavailable')
                parents = [{'type': 'subnet', 'scope': scope, 'service': 'Microsoft.Network',
                            'status': 'empty', 'items': []}]
            seen_parents = set()
            for parent in parents:
                parent_scope = parent['scope']
                key = parent_scope.casefold()
                is_vnet = re.fullmatch(re.escape(scope) + r'/resourceGroups/' + SEGMENT +
                                       r'/providers/Microsoft\.Network/virtualNetworks/' + SEGMENT,
                                       parent_scope, re.I)
                if (key in seen_parents or (key != scope.casefold() and not is_vnet) or
                        parent.get('service') not in (None, 'Microsoft.Network')):
                    raise RouteEvidenceUnavailable('subnet parent incomplete or ambiguous')
                if parent.get('status') == 'denied':
                    raise AzureReadError('route_subnet_parent_denied', 403)
                if parent.get('status') not in ('collected', 'empty'):
                    raise AzureReadError('route_subnet_parent_unavailable')
                if (not isinstance(parent.get('items'), list) or
                        (parent['status'] == 'empty' and parent['items']) or
                        (key == scope.casefold() and
                         (parent['status'] != 'empty' or parent['items']))):
                    raise RouteEvidenceUnavailable('subnet parent incomplete or ambiguous')
                seen_parents.add(key)
            if scope.casefold() in seen_parents and len(seen_parents) != 1:
                raise RouteEvidenceUnavailable('subnet parent authority ambiguous')
            subnets = {}
            for parent in parents:
                for row in parent['items']:
                    sid = _arm_id(row.get('id') if isinstance(row, dict) else None, scope, 'subnet')
                    if sid.casefold() in subnets or sid.casefold().rsplit('/subnets/', 1)[0] != parent['scope'].casefold():
                        raise RouteEvidenceUnavailable('subnet inventory identity ambiguous')
                    subnets[sid.casefold()] = (sid, parent['scope'])
            if not subnets:
                for parent in parents:
                    envelope = {'type': 'subnet_effective_route', 'scope': parent['scope'],
                                'service': 'Microsoft.Network', 'status': 'empty', 'items': []}
                    reader.collections.append(envelope)
                    reader.progress(scope=parent['scope'], settled=envelope)
                continue
            nics = _rows_by_id(_collection(reader, 'nic', scope)['items'], scope, 'nic')
            vms = _rows_by_id(_collection(reader, 'vm', scope)['items'], scope, 'vm')
            effective = _collection(reader, 'effective_route', scope)
            routes_by_subnet = {sid: [] for sid in subnets}
            for nic in nics.values():
                nid, vmid, attached = _attached_nic_subnets(nic, scope)
                relevant = [sid.casefold() for sid in attached if sid.casefold() in subnets]
                if vmid is None or not relevant:
                    continue
                vm = vms.get(vmid.casefold())
                props = vm.get('properties') if isinstance(vm, dict) else None
                links = props.get('networkProfile', {}).get('networkInterfaces') if isinstance(props, dict) else None
                if (not isinstance(links, list) or not any(isinstance(x, dict) and
                        str(x.get('id', '')).casefold() == nid.casefold() for x in links)):
                    raise RouteEvidenceUnavailable('VM does not reciprocally attach NIC')
                routes = _native_routes(effective, nid)
                witness = direct_internet_witness(routes)
                for sid in relevant:
                    routes_by_subnet[sid].append({'nicId': nid, 'vmId': vmid,
                                                  'activeRoutes': routes, 'directInternetWitness': witness})
            by_vnet = {parent['scope'].casefold(): [] for parent in parents}
            for sid, (original, vnet_scope) in subnets.items():
                rows = routes_by_subnet[sid]
                fact = {'id': original + '/providers/PEASO/effectiveRoutes/directInternet',
                        'subnetId': original, 'nicEvidence': rows,
                        '_provenance': {'source_operation': 'networkInterfaces/getEffectiveRouteTable',
                                        'read_only': True, 'nic_inventory_operation': 'get',
                                        'vm_attachment_operation': 'get',
                                        'api_version': API_VERSION},
                        'allAttachedNicsCovered': False, 'exhaustiveInternetDestinations': False}
                by_vnet[vnet_scope.casefold()].append(fact)
            for parent in parents:
                vnet_scope = parent['scope']
                facts = by_vnet[vnet_scope.casefold()]
                with reader.lock:
                    available = (len(facts) if reader.budget.max_items is None else
                                 max(0, reader.budget.max_items - reader.total))
                    limited = len(facts) > available
                    published = facts[:available]
                    envelope = {'type': 'subnet_effective_route', 'scope': vnet_scope,
                                'service': 'Microsoft.Network',
                                'status': 'partial' if limited else 'collected' if published else 'empty',
                                'items': published}
                    if limited:
                        envelope['error'] = {'code': 'resource_limit'}
                    reader.collections.append(envelope)
                    reader.total += len(published)
                reader.progress(scope=vnet_scope, settled=envelope)
        except Exception as exc:
            status, error = _safe_error(exc)
            for target in dict.fromkeys(targets):
                envelope = {'type': 'subnet_effective_route', 'scope': target,
                            'service': 'Microsoft.Network', 'status': status,
                            'items': [], 'error': error}
                reader.collections.append(envelope)
                reader.progress(scope=target, settled=envelope)
