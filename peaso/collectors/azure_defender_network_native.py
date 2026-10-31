"""Read-only Defender, SQL VM and VPN tunnel metadata on the shared scheduler."""
from __future__ import annotations

from datetime import datetime, timezone
import re

ARM = 'https://management.azure.com'
NATIVE_TYPES = frozenset({'sql_vm', 'security_subassessment', 'server_vulnerability_assessment_setting',
    'virtual_network_gateway_connection', 'arc_vulnerability_assessment_evidence', 'arc_machine'})


def required_types(wanted):
    types = set()
    if 'virtual_network_gateway_connection' in wanted:
        types.add('resource_group')
    if set(wanted) & {'server_vulnerability_assessment_setting', 'arc_vulnerability_assessment_evidence'}:
        types.add('arc_machine')
    return types


def _proof(operation, version):
    return {'source_operation': operation, 'api_version': version, 'read_only': True,
            'representation': 'full', 'observed_at': datetime.now(timezone.utc).isoformat()}


def _resource_id(value, scope, resource_type):
    pattern = re.escape(scope) + r'/resourceGroups/[^/?#\x00-\x20]+/providers/' + re.escape(resource_type) + r'/[^/?#\x00-\x20]+'
    if not isinstance(value, str) or not re.fullmatch(pattern, value, re.I):
        raise ValueError('foreign or malformed native Defender/network identity')
    return value


def _project(raw, scope, kind, version):
    props = raw.get('properties')
    if not isinstance(props, dict):
        raise ValueError('native Defender/network properties unavailable')
    rid = raw.get('id')
    if kind in ('sql_vm', 'arc_machine'):
        rid = _resource_id(rid, scope, 'Microsoft.SqlVirtualMachine/sqlVirtualMachines' if kind == 'sql_vm' else 'Microsoft.HybridCompute/machines')
        if kind == 'sql_vm':
            vm = _resource_id(props.get('virtualMachineResourceId'), scope, 'Microsoft.Compute/virtualMachines')
            safe = {'virtualMachineResourceId': vm}
        else:
            safe = {k: props[k] for k in ('status', 'provisioningState') if k in props}
    else:
        if (not isinstance(rid, str) or not rid.casefold().startswith(scope.casefold() + '/') or
                not re.fullmatch(r'.*/providers/Microsoft.Security/assessments/[^/?#]+/subAssessments/[^/?#]+', rid, re.I)):
            raise ValueError('foreign or malformed native sub-assessment identity')
        match = re.search(r'/providers/Microsoft.Security/assessments/([^/?#]+)/subAssessments/([^/?#]+)$', rid, re.I)
        details, state = props.get('resourceDetails'), props.get('status')
        if not isinstance(details, dict) or not isinstance(state, dict):
            raise ValueError('sub-assessment resource binding or status missing')
        target = details.get('id')
        if not isinstance(target, str) or not target.casefold().startswith(scope.casefold() + '/'):
            raise ValueError('foreign sub-assessment resource binding')
        safe = {'resourceDetails': {'id': target}, 'status': {k: state[k] for k in ('code', 'severity') if k in state}}
        if 'timeGenerated' in props:
            safe['timeGenerated'] = props['timeGenerated']
    row = {'id': rid, 'name': rid.rsplit('/', 1)[-1], 'properties': safe,
           '_provenance': _proof('SqlVirtualMachines_List' if kind == 'sql_vm' else 'Machines_ListBySubscription' if kind == 'arc_machine' else 'SubAssessments_ListAll', version)}
    if kind == 'security_subassessment':
        row['assessment_key'] = match[1]
    return row


_SUBASSESSMENT_QUERY = ("securityresources | where type =~ 'microsoft.security/assessments/subassessments' "
                        "| project id, type, name, properties | order by id asc")


def _list_pages(reader, request, scope, kind, resource_type, version):
    """ARM list pages; sub-assessments fall back to Resource Graph once the ARM list is retired."""
    from .azure import _arm_error_code, _status_code
    url = ARM + scope + '/providers/' + resource_type + '?api-version=' + version
    started = False
    try:
        for page in reader.pages(request, url):
            started = True
            yield page, None
        return
    except Exception as exc:
        # ARM now answers 404 SubAssessmentsDeprecated; the same records stay
        # readable through the securityresources Resource Graph table.
        if (started or kind != 'security_subassessment' or _status_code(exc) not in (404, '404')
                or _arm_error_code(exc) != 'SubAssessmentsDeprecated'):
            raise
    subscription = scope.rsplit('/', 1)[-1]
    body = {'subscriptions': [subscription], 'query': _SUBASSESSMENT_QUERY, 'options': {'resultFormat': 'objectArray', '$top': 1000}}
    for page in reader.pages(request, ARM + '/providers/Microsoft.ResourceGraph/resources?api-version=2024-04-01',
                             body=body, key='data', next_key='$skipToken'):
        yield page, 'ResourceGraph'


def collect(reader, request, scopes, wanted):
    from .azure import AzureReadError, _status_code
    requested = set(wanted)
    needed = requested | required_types(requested)
    jobs = []
    arc_jobs = []
    for scope in scopes:
        for kind, resource_type, version in (
                ('sql_vm', 'Microsoft.SqlVirtualMachine/sqlVirtualMachines', '2023-10-01'),
                ('arc_machine', 'Microsoft.HybridCompute/machines', '2024-07-10'),
                ('security_subassessment', 'Microsoft.Security/subAssessments', '2019-01-01-preview')):
            if kind not in needed:
                continue
            def fetch(scope=scope, kind=kind, resource_type=resource_type, version=version):
                seen = {}
                for page, via in _list_pages(reader, request, scope, kind, resource_type, version):
                    values = []
                    for raw in page:
                        row = _project(raw, scope, kind, version)
                        if via:
                            row['_provenance']['transport'] = via
                        key = row['id'].casefold()
                        # Compare actual source fields, excluding fetch timestamps.
                        value = {k: v for k, v in row.items() if k != '_provenance'}
                        if key in seen and seen[key] != value:
                            raise ValueError('conflicting native Defender identity')
                        seen[key] = value
                        values.append(row)
                    yield values
            jobs.append((kind, scope, resource_type.split('/')[0], fetch))
        if 'server_vulnerability_assessment_setting' in requested:
            def setting(scope=scope):
                rid = scope + '/providers/Microsoft.Security/serverVulnerabilityAssessmentsSettings/azureServersSetting'
                try:
                    raw = reader.call(request, ARM + rid + '?api-version=2023-05-01')
                except Exception as exc:
                    if _status_code(exc) != 404:
                        raise
                    yield [{'id': rid, 'status': 'not_found', 'httpStatus': 404,
                            '_provenance': _proof('ServerVulnerabilityAssessmentsSettings_Get', '2023-05-01')}]
                    return
                if (not isinstance(raw, dict) or str(raw.get('id', '')).casefold() != rid.casefold() or
                        not isinstance(raw.get('properties'), dict)):
                    raise ValueError('vulnerability setting response identity invalid')
                yield [{'id': raw['id'], 'name': 'azureServersSetting', 'kind': raw.get('kind'),
                        'properties': {k: raw['properties'][k] for k in ('selectedProvider',) if k in raw['properties']},
                        '_provenance': _proof('ServerVulnerabilityAssessmentsSettings_Get', '2023-05-01')}]
            jobs.append(('server_vulnerability_assessment_setting', scope, 'Microsoft.Security', setting))
        if 'arc_vulnerability_assessment_evidence' in requested:
            def arc_evidence(scope=scope):
                parents = [c for c in reader.collections if c['type'] == 'arc_machine' and c['scope'].casefold() == scope.casefold()]
                if len(parents) != 1 or parents[0]['status'] not in ('collected', 'empty'):
                    raise AzureReadError('arc_inventory_incomplete')
                if parents[0]['items']:
                    raise AzureReadError('arc_auto_provisioning_not_proven_by_configuration')
                yield []
            arc_jobs.append(('arc_vulnerability_assessment_evidence', scope, 'Microsoft.HybridCompute', arc_evidence))
    reader.run(jobs)
    reader.run(arc_jobs)
    if 'security_subassessment' in requested:
        # This is the time the complete, native current-state response was
        # observed, not a claim about when Defender last scanned a machine.
        for collection in reader.collections:
            if collection['type'] == 'security_assessment' and collection['status'] in ('collected', 'empty'):
                for row in collection['items']:
                    proof = row.get('_provenance')
                    if proof is None:
                        row['_provenance'] = _proof('Assessments_List', '2020-01-01')
                        continue
                    if isinstance(proof, dict) and proof.get('read_only') is True:
                        proof.setdefault('observed_at', datetime.now(timezone.utc).isoformat())
    if 'virtual_network_gateway_connection' in requested:
        _connections(reader, request, scopes)


def _connections(reader, request, scopes):
    """List each native RG once, using the one shared bounded worker pool."""
    from .azure import AzureReadError
    jobs, parents, errors = [], {}, {}
    for scope in scopes:
        sources = [c for c in reader.collections if c['type'] == 'resource_group' and c['scope'].casefold() == scope.casefold()]
        if len(sources) != 1 or sources[0]['status'] not in ('collected', 'empty'):
            errors[scope] = {'code': 'vpn_resource_group_roster_incomplete'}
            continue
        ids = [row.get('id') for row in sources[0]['items']]
        if (any(not isinstance(rid, str) or not re.fullmatch(re.escape(scope) + r'/resourceGroups/[^/?#\x00-\x20]+', rid, re.I) for rid in ids) or
                len(ids) != len(set(rid.casefold() for rid in ids))):
            errors[scope] = {'code': 'vpn_resource_group_identity_invalid'}
            continue
        parents[scope] = ids
        for group in ids:
            def fetch(scope=scope, group=group):
                seen = {}
                for page in reader.pages(request, ARM + group + '/providers/Microsoft.Network/connections?api-version=2025-01-01'):
                    values = []
                    for raw in page:
                        rid = _resource_id(raw.get('id'), scope, 'Microsoft.Network/connections')
                        if not rid.casefold().startswith(group.casefold() + '/'):
                            raise ValueError('VPN connection foreign resource group')
                        props = raw.get('properties')
                        if not isinstance(props, dict):
                            raise ValueError('VPN properties unavailable')
                        safe = {}
                        for key in ('virtualNetworkGateway1', 'virtualNetworkGateway2', 'localNetworkGateway2'):
                            if key in props:
                                value = props[key]
                                safe[key] = {'id': value.get('id')} if isinstance(value, dict) else value
                        for key in ('connectionType', 'connectionStatus', 'provisioningState'):
                            if key in props:
                                safe[key] = props[key]
                        if 'tunnelConnectionStatus' in props:
                            tunnels = props['tunnelConnectionStatus']
                            if not isinstance(tunnels, list) or any(not isinstance(t, dict) for t in tunnels):
                                raise ValueError('VPN tunnel status inventory malformed')
                            safe['tunnelConnectionStatus'] = [{k: t[k] for k in ('tunnel', 'connectionStatus') if k in t} for t in tunnels]
                        row = {'id': rid, 'properties': safe, '_provenance': _proof('VirtualNetworkGatewayConnections_List', '2025-01-01')}
                        if rid.casefold() in seen and seen[rid.casefold()] != safe:
                            raise ValueError('conflicting VPN connection identity')
                        seen[rid.casefold()] = safe
                        values.append(row)
                    yield values
            jobs.append(('_native_vpn_connection_rg', group, 'Microsoft.Network', fetch))
    start = len(reader.collections)
    reader.run(jobs)
    children = reader.collections[start:]
    del reader.collections[start:]
    for scope in scopes:
        expected = parents.get(scope, [])
        selected = [c for c in children if c['scope'] in expected]
        complete = scope not in errors and len(selected) == len(expected) and all(c['status'] in ('collected', 'empty') for c in selected)
        items = [row for c in selected for row in c['items']]
        status = ('collected' if items else 'empty') if complete else 'partial' if items else 'not_collected'
        if not complete and selected and all(c['status'] == 'denied' for c in selected):
            status = 'denied'
        reader.collections.append({'type': 'virtual_network_gateway_connection', 'scope': scope, 'service': 'Microsoft.Network',
            'status': status, 'items': items, 'covered_parent_ids': [c['scope'] for c in selected if c['status'] in ('collected', 'empty')],
            'parent_inventory': 'resource_group', **({} if complete else {'error': errors.get(scope, {'code': 'vpn_group_inventory_incomplete'})})})
