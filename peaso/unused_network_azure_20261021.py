"""Read-only structural Azure network attachment checks.

These predicates describe current ARM references, never traffic or deletion safety.
"""
from __future__ import annotations

import json
from pathlib import Path
import re

from peaso.checks.facts import Unavailable, get, memoized


def _native(index, kind):
    def build():
        context = index.get('context', {})
        scope = context.get('scope')
        if context.get('provider') != 'azure' or not isinstance(scope, str) or not scope.lower().startswith('/subscriptions/'):
            raise Unavailable('Azure subscription authority is unavailable')
        envelopes = index.get('collections', {}).get(kind)
        if not isinstance(envelopes, list) or len(envelopes) != 1:
            raise Unavailable('complete ARM inventory is unavailable: ' + kind)
        envelope = envelopes[0]
        if (envelope.get('type') != kind or str(envelope.get('scope', '')).lower() != scope.lower()
                or envelope.get('service') != 'Microsoft.Network' or envelope.get('status') not in ('collected', 'empty')):
            raise Unavailable('ARM inventory is partial or outside the selected subscription: ' + kind)
        rows, projected = envelope.get('items'), index.get(kind)
        if (not isinstance(rows, list) or not isinstance(projected, list)
                or (envelope['status'] == 'empty') != (not rows)
                or [r.get('data') for r in projected] != rows
                or any(r.get('type') != kind or str(r.get('scope', '')).lower() != scope.lower() for r in projected)):
            raise Unavailable('ARM inventory and resource projection differ: ' + kind)
        seen = set()
        for row in rows:
            rid = get(row, 'id', str).lower()
            if not rid.startswith(scope.lower() + '/') or rid in seen:
                raise Unavailable('foreign or duplicate ARM resource identity: ' + kind)
            seen.add(rid)
        return rows
    return memoized(index, ('unused_network_azure_20261021', kind), build)


def _current(item, index, kind):
    rid = get(item, 'id', str).lower()
    rows = _native(index, kind)
    matches = [row for row in rows if row.get('id', '').lower() == rid]
    if len(matches) != 1 or matches[0] != item:
        raise Unavailable('assessed ARM object is not the captured current object')
    proof = item.get('_provenance')
    if not isinstance(proof, dict) or proof.get('read_only') is not True or proof.get('representation') != 'full' or proof.get('source_operation') != 'get':
        raise Unavailable('complete read-only ARM GET is unavailable')
    # Current collectors stamp capture identity. Enforce any declared capture
    # binding while retaining historical native witnesses without these fields.
    metadata = index.get('context', {}).get('metadata', {})
    envelope = index['collections'][kind][0]
    capture_fields = ('credential_context_id', 'customer_context_id')
    if (any(key in metadata or key in proof for key in capture_fields)
            or any(key in envelope.get('_provenance', {}) for key in capture_fields)):
        _capture(item, envelope, index)
    return rid


def _ref(value, scope):
    if value is None:
        return None
    if not isinstance(value, dict):
        raise Unavailable('ARM reference is malformed')
    rid = get(value, 'id', str)
    if not rid.lower().startswith(scope.lower() + '/'):
        raise Unavailable('ARM reference is outside the selected subscription')
    return rid


def _field(properties, name):
    coverage = properties.get('_coverage', {})
    if name in properties or name in coverage:
        return get(properties, name)
    return None  # A full ARM GET omitted an optional reference.


def route_table(item, index):
    rid = _current(item, index, 'route_table')
    props = get(item, 'properties', dict)
    subnets = _field(props, 'subnets')
    if subnets is None:
        subnets = []
    if not isinstance(subnets, list):
        raise Unavailable('route table subnet references are malformed')
    references = [_ref(row, index['context']['scope']) for row in subnets]
    if any(ref is None for ref in references) or len({r.lower() for r in references}) != len(references):
        raise Unavailable('route table subnet references are incomplete or duplicated')
    return ('PASS' if references else 'FAIL', {'resource_id': rid, 'subnet_references': references,
        'summary': (f'Route table {rid} is referenced by {len(references)} subnet(s).\nThis is an ARM association, not observed route traffic.\nReview current routing before changing the table.'
                    if references else f'Route table {rid} has no subnet references in its complete ARM GET.\nNo current subnet association is declared on this object.\nReview ownership before removal.')})


def nic(item, index):
    rid = _current(item, index, 'nic')
    props = get(item, 'properties', dict)
    scope = index['context']['scope']
    vm = _ref(_field(props, 'virtualMachine'), scope)
    private_endpoint = _ref(_field(props, 'privateEndpoint'), scope)
    private_link_service = _ref(_field(props, 'privateLinkService'), scope)
    hosted = _field(props, 'hostedWorkloads') or []
    if not isinstance(hosted, list) or any(not isinstance(x, str) or not x for x in hosted):
        raise Unavailable('NIC hosted workload references are malformed')
    refs = [x for x in (vm, private_endpoint, private_link_service) if x] + hosted
    return ('PASS' if refs else 'FAIL', {'resource_id': rid, 'owner_references': refs,
        'summary': (f'Network interface {rid} has a VM, private link or hosted workload owner reference.\nThe reference is structural and does not establish traffic.\nVerify the owner before making changes.'
                    if refs else f'Network interface {rid} has no VM, private link or hosted workload owner reference in its complete ARM GET.\nIt has no declared owner in these native fields.\nReview any platform or planned use before removal.')})


def public_ip(item, index):
    rid = _current(item, index, 'public_ip')
    props = get(item, 'properties', dict)
    if get(props, 'provisioningState', str) != 'Succeeded':
        raise Unavailable('public IP provisioning is incomplete')
    references = []
    for field in ('ipConfiguration', 'natGateway', 'linkedPublicIPAddress', 'servicePublicIPAddress', 'publicIPPrefix'):
        value = _field(props, field)
        if value is not None:
            references.append(_ref(value, index['context']['scope']))
    return ('PASS' if references else 'FAIL'), {'resource_id': rid, 'network_references': references,
        'summary': (f'Public IP {rid} has {len(references)} declared network attachment or allocation reference(s).\nThe references are present in its complete ARM GET.\nThis does not establish traffic.' if references else
                    f'Public IP {rid} has no network attachment or allocation reference in its complete ARM GET.\nNo IP configuration, NAT gateway, linked/service public IP or prefix is declared.\nReview the reservation owner before release.')}


def _capture(item, envelope, index):
    metadata = index.get('context', {}).get('metadata', {})
    credential = metadata.get('credential_context_id')
    customer = metadata.get('customer_context_id')
    if (metadata.get('collection') != 'read-only' or not isinstance(credential, str)
            or not re.fullmatch(r'[0-9a-f]{32}', credential)
            or customer != 'scan-local:' + credential):
        raise Unavailable('scan-local Azure credential context is unavailable')
    for source in (item, envelope):
        proof = source.get('_provenance') if isinstance(source, dict) else None
        if (not isinstance(proof, dict) or proof.get('credential_context_id') != credential
                or proof.get('customer_context_id') != customer):
            raise Unavailable('Azure resource is outside the selected credential context')


def _child_current(item, index):
    context_scope = index.get('context', {}).get('scope')
    if index.get('context', {}).get('provider') != 'azure' or not isinstance(context_scope, str):
        raise Unavailable('Azure VNet scope is unavailable')
    rid = get(item, 'id', str)
    pattern = r'(/subscriptions/[0-9a-f-]{36}/resourceGroups/[^/?#%\\\s]+/providers/Microsoft\.Network/virtualNetworks/[^/?#%\\\s]+)/subnets/[^/?#%\\\s]+'
    match = re.fullmatch(pattern, rid, re.I)
    if not match or any(p in ('.', '..') for p in rid.split('/')):
        raise Unavailable('subnet identity is outside the selected subscription')
    parent = match.group(1)
    scope = '/'.join(parent.split('/')[:3])
    if context_scope.casefold() not in (parent.casefold(), scope.casefold()):
        raise Unavailable('subnet is outside selected VNet or subscription')
    child_pattern = re.escape(parent) + r'/subnets/[^/?#%\\\s]+'
    envelopes = [c for c in index.get('collections', {}).get('subnet', [])
                 if str(c.get('scope', '')).casefold() == parent.casefold()]
    if len(envelopes) != 1:
        raise Unavailable('subnet GET collection is unavailable')
    envelope = envelopes[0]
    rows = envelope.get('items')
    if (envelope.get('type') != 'subnet' or envelope.get('service') != 'Microsoft.Network'
            or envelope.get('status') not in ('collected', 'empty') or not isinstance(rows, list)
            or (envelope['status'] == 'empty') != (not rows)
            or len({str(row.get('id', '')).casefold() for row in rows}) != len(rows)
            or any(not re.fullmatch(child_pattern, str(row.get('id', '')), re.I) for row in rows)
            or [r.get('data') for r in index.get('subnet', []) if str(r.get('scope', '')).casefold() == parent.casefold()] != rows
            or len([row for row in rows if row == item]) != 1):
        raise Unavailable('subnet GET collection is incomplete or inconsistent')
    _capture(item, envelope, index)
    proof = get(item, '_provenance', dict)
    if (proof.get('read_only') is not True or proof.get('representation') != 'full'
            or proof.get('source_operation') != 'get' or proof.get('api_version') != '2023-09-01'
            or str(item.get('type', '')).casefold() != 'microsoft.network/virtualnetworks/subnets'):
        raise Unavailable('full native subnet GET is unavailable')
    return rid


def _refs(value, scope):
    if value is None:
        return []
    if not isinstance(value, list):
        raise Unavailable('native reference collection is malformed')
    refs = [_ref(row, scope) for row in value]
    if any(ref is None for ref in refs) or len({ref.casefold() for ref in refs}) != len(refs):
        raise Unavailable('native references are incomplete or duplicated')
    return refs


def subnet(item, index):
    rid = _child_current(item, index)
    props = get(item, 'properties', dict)
    if props.get('provisioningState') not in (None, 'Succeeded'):
        raise Unavailable('subnet provisioning is incomplete')
    scope = '/'.join(index['context']['scope'].split('/')[:3])
    fields = ('ipConfigurations', 'ipConfigurationProfiles', 'privateEndpoints',
              'applicationGatewayIPConfigurations', 'delegations', 'serviceAssociationLinks',
              'resourceNavigationLinks', 'ipAllocations')
    counts = {}
    for field in fields:
        counts[field] = len(_refs(_field(props, field), scope))
    ipam = _field(props, 'ipamPoolPrefixAllocations')
    if ipam is not None:
        if not isinstance(ipam, list):
            raise Unavailable('subnet IPAM allocations are malformed')
        for allocation in ipam:
            if not isinstance(allocation, dict) or not _ref(get(allocation, 'pool', dict), scope):
                raise Unavailable('subnet IPAM allocation is malformed')
    counts['ipamPoolPrefixAllocations'] = len(ipam or [])
    used = sum(counts.values())
    return ('PASS' if used else 'FAIL'), {'resource_id': rid, 'reference_counts': counts,
        'summary': (f'Subnet {rid} has {used} current consumer or reservation declaration(s) in its full ARM GET.\nThese are structural references, not observed traffic.\nReview the owning service before changes.' if used else
                    f'Subnet {rid} has no current consumer or reservation declarations in its full ARM GET.\nNo native IP configuration, private endpoint, delegation, service link, allocation or IPAM reservation is declared.\nReview planned use and ownership before changing it.')}


def load_balancer(item, index):
    rid = _current(item, index, 'load_balancer')
    envelope = index['collections']['load_balancer'][0]
    _capture(item, envelope, index)
    if item['_provenance'].get('api_version') != '2023-09-01' or str(item.get('type', '')).casefold() != 'microsoft.network/loadbalancers':
        raise Unavailable('full native load balancer GET is unavailable')
    props = get(item, 'properties', dict)
    if props.get('provisioningState') not in (None, 'Succeeded'):
        raise Unavailable('load balancer provisioning is incomplete')
    pools = _field(props, 'backendAddressPools')
    if pools is None:
        pools = []
    if not isinstance(pools, list):
        raise Unavailable('backend pools are malformed')
    if not pools:
        return 'NOT_APPLICABLE', {'resource_id': rid, 'summary': f'Load balancer {rid} declares no backend pool.\nThere is no backend pool to assess.'}
    pool_ids = set()
    consumers = set()
    scope = index['context']['scope']
    for field in ('loadBalancingRules', 'outboundRules', 'inboundNatRules'):
        rules = _field(props, field) or []
        if not isinstance(rules, list):
            raise Unavailable('load balancer rules are malformed')
        for rule in rules:
            rule_props = get(rule, 'properties', dict)
            for ref_field in ('backendAddressPool', 'backendAddressPools'):
                value = _field(rule_props, ref_field)
                refs = _refs(value, scope) if ref_field.endswith('Pools') else ([_ref(value, scope)] if value is not None else [])
                consumers.update(ref.casefold() for ref in refs)
    empty = []
    for pool in pools:
        pool_id = get(pool, 'id', str)
        if (not pool_id.casefold().startswith(rid.casefold() + '/backendaddresspools/')
                or pool_id.casefold() in pool_ids):
            raise Unavailable('backend pool identity is malformed or duplicated')
        pool_ids.add(pool_id.casefold())
        details = get(pool, 'properties', dict)
        declared = _refs(_field(details, 'backendIPConfigurations'), scope)
        addresses = _field(details, 'loadBalancerBackendAddresses') or []
        if not isinstance(addresses, list) or any(not isinstance(row, dict) or not row for row in addresses):
            raise Unavailable('backend address declarations are malformed')
        reverse = []
        for field in ('loadBalancingRules', 'outboundRules', 'inboundNatRules'):
            reverse += _refs(_field(details, field), scope)
        single = _field(details, 'outboundRule')
        if single is not None:
            reverse.append(_ref(single, scope))
        if not declared and not addresses and not reverse and pool_id.casefold() not in consumers:
            empty.append(pool_id)
    if consumers - pool_ids:
        raise Unavailable('rule references an unobserved backend pool')
    return ('FAIL' if empty else 'PASS'), {'resource_id': rid, 'unreferenced_empty_pools': empty,
        'backend_pool_count': len(pools), 'summary': (f'Load balancer {rid} has {len(empty)} backend pool(s) without a backend declaration or rule, outbound or NAT consumer.\nThe full parent ARM GET contains no such references for those pools.\nReview planned traffic and ownership before changing them.' if empty else
                    f'Load balancer {rid} has {len(pools)} backend pool(s) with a backend declaration or rule, outbound or NAT consumer.\nThese are current structural declarations, not traffic evidence.\nReview the load balancer configuration before changes.')}


DECLARATIONS = (
    ('azure.network.public_ip_has_network_reference', 'public_ip', 'Public IP address has a network attachment or allocation reference', public_ip),
    ('azure.network.route_table_has_subnet_reference', 'route_table', 'Route table has a subnet association', route_table),
    ('azure.network.nic_has_owner_reference', 'nic', 'Network interface has a VM, private link or hosted workload owner', nic),
    ('azure.network.subnet_has_consumer_or_reservation_reference', 'subnet', 'Subnet has a current consumer or reservation declaration', subnet),
    ('azure.network.load_balancer_backend_pools_have_declaration_or_consumer', 'load_balancer', 'Load balancer backend pools have a backend or consumer declaration', load_balancer),
)


def install(registry):
    from peaso.checks.fixtures import CASES
    path = Path(__file__).with_name('checks') / 'unused_network_azure_20261021_cases.json'
    raw = path.read_bytes()
    cases = json.loads(raw)
    if set(cases) != {row[0] for row in DECLARATIONS}:
        raise ValueError('Azure unused-network case IDs changed')
    for ident, kind, title, predicate in DECLARATIONS:
        registry.register(ident, 'azure', 'hardening', kind, title, 'low', 'Hardening',
            'Confirm the resource owner and live dependencies; update the owning infrastructure definition or remove an obsolete object after review.',
            dependencies=(kind,))(predicate)
        CASES[ident] = cases[ident]
