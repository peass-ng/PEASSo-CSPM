"""Join captured internet-facing listener routes to exact running containers."""
from collections import defaultdict
from collections.abc import Mapping
from ipaddress import ip_network
import re
from urllib.parse import urlsplit

CHECK = 'analysis.exposed_container_cves'
RESOURCE_TYPES = frozenset({
    'ecs_task', 'ecs_service', 'elbv2_listener', 'load_balancer_listener', 'load_balancer', 'target_group',
    'pod', 'service', 'endpointslice', 'gke_exposure_pod', 'gke_exposure_service', 'gke_exposure_endpointslice',
    'cloudrun_service', 'container_group', 'container_app', 'container_app_runtime',
})
_IMMUTABLE = re.compile(r'(?:[a-z0-9+.-]+://)?[^@\s]+@(sha256:[a-f0-9]{64})')


def immutable_digest(reference):
    if isinstance(reference, str) and len(reference) <= 2048 and (match := _IMMUTABLE.fullmatch(reference)):
        return match[1]
    return None


def gke_kubernetes_inventory(inventory):
    kinds = {'gke_exposure_pod': 'pod', 'gke_exposure_service': 'service',
             'gke_exposure_endpointslice': 'endpointslice'}
    for row in inventory:
        kind = kinds.get(row.get('type'))
        data = _mapping(row.get('data'))
        if row.get('provider') != 'gcp' or not kind or data.get('inventoryStatus') is not None or not data.get('cluster'):
            continue
        metadata = {'uid': data.get('uid'), 'namespace': data.get('namespace'), 'name': data.get('kubernetesName')}
        normalized = {'metadata': metadata}
        if kind == 'pod':
            normalized.update(spec=data.get('workloadSpec', {}), status=data.get('workloadStatus', {}))
        elif kind == 'service':
            normalized.update(spec=data.get('spec', {}), status=data.get('status', {}))
        else:
            metadata.update(labels={'kubernetes.io/service-name': data.get('serviceName')},
                            ownerReferences=data.get('serviceOwners', ()))
            normalized.update(ports=data.get('ports', ()), endpoints=data.get('podTargets', ()))
        cluster_scope = (row['scope'], data['cluster'])
        yield dict(row, provider='k8s', type=kind, scope=cluster_scope, data=normalized)


def _mapping(value):
    return value if isinstance(value, Mapping) else {}


def _rows(value):
    return [row for row in value if isinstance(row, Mapping)] if isinstance(value, (list, tuple)) else []


def _admits_port(port, protocol, exposures):
    if type(port) is not int or not 1 <= port <= 65535 or not isinstance(protocol, str):
        return False
    prefix = protocol.lower() + '/'
    for exposure in exposures:
        if not isinstance(exposure, str) or not exposure.startswith(prefix):
            continue
        value = exposure[len(prefix):]
        low, separator, high = value.partition('-')
        if value == 'all' or value == str(port):
            return True
        if separator and 1 <= len(low) <= 5 and 1 <= len(high) <= 5 and low.isascii() and low.isdecimal() and high.isascii() and high.isdecimal():
            if int(low) <= port <= int(high):
                return True
    return False


def _public_source(condition):
    values = _mapping(condition.get('SourceIpConfig')).get('Values') or condition.get('Values') or ()
    for value in values:
        try:
            network = ip_network(value, strict=False)
        except (ValueError, TypeError):
            continue
        if network.prefixlen == 0 or network.is_global:
            return True
    return False


def _targets(rule):
    for action in _rows(rule.get('Actions')):
        if action.get('Type') != 'forward':
            continue
        group = action.get('TargetGroupArn')
        weighted = _rows(_mapping(action.get('ForwardConfig')).get('TargetGroups'))
        if weighted:
            for target in weighted:
                weight = target.get('Weight', 1)
                if type(weight) is int and weight > 0:
                    yield target.get('TargetGroupArn')
        elif group:
            yield group


def _listener_authentication(actions):
    config_keys = {'authenticate-oidc': 'AuthenticateOidcConfig',
                   'authenticate-cognito': 'AuthenticateCognitoConfig'}
    modes = []
    for action in _rows(actions):
        field = config_keys.get(action.get('Type'))
        if field:
            mode = action.get('UnauthenticatedRequestMode')
            if mode is None and isinstance(action.get(field), Mapping):
                mode = action[field].get('OnUnauthenticatedRequest', 'authenticate')
            modes.append(mode)
    if any(mode in ('authenticate', 'deny') for mode in modes):
        return 'Listener authentication required'
    if any(mode != 'allow' for mode in modes):
        return 'Listener authentication unverified'
    return None


def _public_listeners(inventory, findings):
    open_endpoints = {}
    for finding in findings:
        if finding.get('check_id') != 'analysis.internet_exposure' or finding.get('status') != 'FAIL':
            continue
        evidence = _mapping(finding.get('evidence'))
        if evidence.get('exposure_kind') == 'load_balancer':
            open_endpoints[finding.get('resource_id')] = (finding['id'], set(evidence.get('exposed_ports') or ()))
    tls = {(row['scope'], row['data'].get('ListenerArn')): _mapping(row['data'].get('MutualAuthentication')).get('Mode')
           for row in inventory if row['type'] in ('elbv2_listener', 'load_balancer_listener')}
    routes = defaultdict(list)
    for row in inventory:
        observed = open_endpoints.get(row['id'])
        if row['type'] != 'load_balancer' or not observed:
            continue
        evidence_id, ports = observed
        data = row['data']
        listeners = _mapping(data.get('Listeners'))
        if data.get('Type') != 'application' or data.get('Scheme') != 'internet-facing' or listeners.get('collection_status') != 'collected':
            continue
        for listener in _rows(listeners.get('items')):
            port, protocol = listener.get('Port'), listener.get('Protocol')
            if protocol not in ('HTTP', 'HTTPS') or not _admits_port(port, 'tcp', ports):
                continue
            rule_set = _mapping(listener.get('Rules'))
            if rule_set.get('collection_status') != 'collected':
                continue
            mode = (_mapping(listener.get('MutualAuthentication')).get('Mode')
                    or tls.get((row['scope'], listener.get('ListenerArn'))))
            for rule in _rows(rule_set.get('items')):
                conditions = _rows(rule.get('Conditions'))
                if any(condition.get('Field') == 'source-ip' and not _public_source(condition) for condition in conditions):
                    continue
                controls = []
                if protocol == 'HTTPS' and mode == 'verify':
                    controls.append('Client certificate required')
                elif protocol == 'HTTPS' and mode != 'off':
                    controls.append('Client-certificate enforcement unverified')
                auth = _listener_authentication(rule.get('Actions'))
                if auth:
                    controls.append(auth)
                if any(condition.get('Field') == 'source-ip' for condition in conditions):
                    controls.append('Source IP restrictions')
                if any(condition.get('Field') == 'host-header' for condition in conditions):
                    controls.append('Rule requires a matching hostname')
                if any(condition.get('Field') == 'path-pattern' for condition in conditions):
                    controls.append('Rule requires a matching URL path')
                for target in sorted({target for target in _targets(rule) if isinstance(target, str)}):
                    routes[row['scope'], target].append({
                        'endpoint': data.get('DNSName') or row['native_id'], 'port': port, 'protocol': protocol,
                        'rule': rule.get('RuleArn'), 'controls': controls, 'finding_id': evidence_id,
                        'kind': 'application_load_balancer',
                    })
    return routes


def _aws_routes(runtime, inventory, findings):
    """Attach a configured internet path with a healthy target bound to the task IP and container port."""
    if not any(row['provider'] == 'aws' for row in runtime):
        return runtime
    routes = _public_listeners(inventory, findings)
    if not routes:
        return runtime
    tasks = {(row['scope'], row['native_id']): row['data'] for row in inventory if row['type'] == 'ecs_task'}
    services = {(row['scope'], row['data'].get('clusterArn'), row['data'].get('serviceName')): row['data']
                for row in inventory if row['type'] == 'ecs_service' and row['data'].get('status') == 'ACTIVE'}
    targets = {(row['scope'], row['data'].get('TargetGroupArn')): row['data']
               for row in inventory if row['type'] == 'target_group'}
    for container in runtime:
        if container['provider'] != 'aws':
            continue
        scope = container['scope']
        task = tasks.get((scope, container['workload']), {})
        group = task.get('group')
        if not isinstance(group, str) or not group.startswith('service:'):
            continue
        service = services.get((scope, task.get('clusterArn'), group.removeprefix('service:')), {})
        addresses = {detail.get('value') for attachment in _rows(task.get('attachments'))
                     if attachment.get('type') == 'ElasticNetworkInterface' and attachment.get('status') == 'ATTACHED'
                     for detail in _rows(attachment.get('details')) if detail.get('name') == 'privateIPv4Address'}
        addresses.discard(None)
        for binding in _rows(service.get('loadBalancers')):
            if binding.get('containerName') != container['container']:
                continue
            target = binding.get('targetGroupArn')
            port = binding.get('containerPort')
            if type(port) is not int or not 1 <= port <= 65535:
                continue
            backend = targets.get((scope, target), {})
            health = _mapping(backend.get('TargetHealth'))
            if backend.get('TargetType') != 'ip' or health.get('collection_status') != 'collected':
                continue
            if not any(_mapping(item.get('TargetHealth')).get('State') == 'healthy'
                       and _mapping(item.get('Target')).get('Id') in addresses
                       and _mapping(item.get('Target')).get('Port') == port
                       for item in _rows(health.get('TargetHealthDescriptions'))):
                continue
            for route in routes.get((scope, target), ()):
                result = dict(route, target_group=target, container_port=port)
                attached = container.setdefault('exposure_routes', [])
                if result not in attached:
                    attached.append(result)
    return runtime


def _k8s_routes(runtime, inventory, findings):
    """Use a public Service's ready EndpointSlice targets and exact Pod ports."""
    services = {}
    for finding in findings:
        if finding.get('check_id') != 'analysis.internet_exposure' or finding.get('status') != 'FAIL':
            continue
        evidence = _mapping(finding.get('evidence'))
        if evidence.get('exposure_kind') in ('service', 'gke_workload'):
            services[finding.get('resource_id')] = (finding['id'], evidence)
    slices = defaultdict(list)
    pods = {}
    pod_addresses = {}
    for row in inventory:
        if row.get('provider') != 'k8s':
            continue
        data = row['data']
        meta = _mapping(data.get('metadata'))
        namespace = meta.get('namespace', 'default')
        if row['type'] == 'pod':
            pods[row['scope'], row['native_id']] = data
            status = _mapping(data.get('status'))
            if any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in _rows(status.get('conditions'))):
                pod_addresses[row['scope'], namespace, meta.get('uid')] = {
                    address.get('ip') for address in _rows(status.get('podIPs'))} | {status.get('podIP')}
        if row['type'] == 'endpointslice':
            name = _mapping(meta.get('labels')).get('kubernetes.io/service-name')
            slices[row['scope'], namespace, name].append(data)
    resolved = defaultdict(list)
    for row in inventory:
        observed = services.get(row['id'])
        if row['type'] != 'service' or not observed:
            continue
        finding_id, evidence = observed
        data = row['data']
        meta, spec = _mapping(data.get('metadata')), _mapping(data.get('spec'))
        if spec.get('type') != 'LoadBalancer':
            continue
        namespace, name, uid = meta.get('namespace', 'default'), meta.get('name'), meta.get('uid')
        if not uid:
            continue
        addresses = {entry.get('ip') or entry.get('hostname')
                     for entry in _rows(_mapping(_mapping(data.get('status')).get('loadBalancer')).get('ingress'))}
        public = addresses & set(evidence.get('public_addresses') or ())
        for slice_data in slices[row['scope'], namespace, name]:
            owner = _rows(_mapping(slice_data.get('metadata')).get('ownerReferences'))
            if not any(ref.get('kind') == 'Service' and ref.get('uid') == uid for ref in owner):
                continue
            for endpoint in _rows(slice_data.get('endpoints')):
                ref = _mapping(endpoint.get('targetRef'))
                conditions = _mapping(endpoint.get('conditions'))
                if (ref.get('kind') != 'Pod' or ref.get('namespace') != namespace or not ref.get('uid')
                        or conditions.get('ready') is not True or conditions.get('serving') is False
                        or conditions.get('terminating') is True):
                    continue
                expected_ips = pod_addresses.get((row['scope'], namespace, ref['uid']), set()) - {None}
                if not expected_ips.intersection(endpoint.get('addresses') or ()):
                    continue
                for backend in _rows(slice_data.get('ports')):
                    for frontend in _rows(spec.get('ports')):
                        protocol = frontend.get('protocol', 'TCP')
                        target = frontend.get('targetPort', frontend.get('port'))
                        if (backend.get('protocol', 'TCP') != protocol
                                or (backend.get('name') or '') != (frontend.get('name') or '')
                                or not _admits_port(frontend.get('port'), protocol, evidence.get('exposed_ports') or ())
                                or type(backend.get('port')) is not int
                                or (type(target) is int and backend['port'] != target)
                                or (type(target) is not int and not isinstance(target, str))):
                            continue
                        for address in sorted(public - {None}):
                            if evidence.get('exposure_kind') == 'gke_workload' and not any(
                                    step.get('layer') == 'gke_cloud_edge' and step.get('decision') == 'allow'
                                    and step.get('public_ip') == address
                                    and _admits_port(frontend['port'], protocol, step.get('ports') or ())
                                    for step in _rows(evidence.get('path'))):
                                continue
                            resolved[row['scope'], ref['uid']].append({
                                'endpoint': address, 'protocol': protocol, 'port': frontend['port'],
                                'container_port': backend['port'], 'kind': 'load_balancer_service',
                                'service': f'{namespace}/{name}', 'finding_id': finding_id,
                                **({'target_port_name': target} if isinstance(target, str) else {}),
                                'controls': (['Source IP restrictions'] if spec.get('loadBalancerSourceRanges') else [])
                                            + ['Pod-level access controls unverified'],
                            })
    for running in runtime:
        if running['provider'] != 'k8s':
            continue
        pod = pods.get((running['scope'], running['workload']), {})
        uid = _mapping(pod.get('metadata')).get('uid')
        containers = _rows(_mapping(pod.get('spec')).get('containers'))
        for route in resolved.get((running['scope'], uid), ()):
            listeners = [container.get('name') for container in containers
                         if any(port.get('containerPort') == route['container_port']
                                and port.get('protocol', 'TCP') == route['protocol']
                                and (not route.get('target_port_name') or port.get('name') == route['target_port_name'])
                                for port in _rows(container.get('ports')))]
            if listeners == [running['container']]:
                attached = running.setdefault('exposure_routes', [])
                if route not in attached:
                    attached.append(route)


def _running_port(container, field):
    ports = _rows(container.get('ports'))
    candidates = [port[field] for port in ports if type(port.get(field)) is int and 1 <= port[field] <= 65535]
    return candidates[0] if len(candidates) == 1 else None


def _revision_name(value, service):
    if not isinstance(value, str) or not isinstance(service, str):
        return None
    short = value.removeprefix(service + '/revisions/')
    return short if re.fullmatch(r'[a-z][a-z0-9-]{0,62}', short) else None


def managed_workloads(inventory):
    """Yield exact serving container declarations and their backend port bindings."""
    apps = {(row['scope'], str(row['native_id']).casefold()): row for row in inventory if row.get('type') == 'container_app'}
    for row in inventory:
        if row.get('type') not in ('container_group', 'cloudrun_service', 'container_app_runtime'):
            continue
        data = row['data']
        props = _mapping(data.get('properties'))
        if row['type'] == 'container_group' and row['provider'] == 'azure':
            containers = _rows(props.get('containers'))
            port_owners = defaultdict(list)
            for container in containers:
                cprops = _mapping(container.get('properties'))
                for port in _rows(cprops.get('ports')):
                    protocol = port.get('protocol', 'TCP')
                    if type(port.get('port')) is int and isinstance(protocol, str):
                        port_owners[protocol.upper(), port['port']].append(container)
            for (protocol, port), owners in port_owners.items():
                if len(owners) != 1 or not 1 <= port <= 65535:
                    continue
                container = owners[0]
                cprops = _mapping(container.get('properties'))
                if _mapping(_mapping(cprops.get('instanceView')).get('currentState')).get('state') == 'Running':
                    yield row, row['native_id'], container.get('name'), cprops.get('image'), port, port, protocol, ()
        if row['type'] == 'cloudrun_service' and row['provider'] == 'gcp':
            service = data.get('name')
            latest = _revision_name(data.get('latestReadyRevision'), service)
            if (not latest or latest != _revision_name(data.get('latestCreatedRevision'), service) or data.get('reconciling') is True
                    or not data.get('generation') or str(data.get('generation')) != str(data.get('observedGeneration'))
                    or not any(type(target.get('percent')) is int and target['percent'] > 0
                               and _revision_name(target.get('revision'), service) == latest
                               for target in _rows(data.get('trafficStatuses')))):
                continue
            containers = _rows(_mapping(data.get('template')).get('containers'))
            listeners = [(container, _running_port(container, 'containerPort')) for container in containers if container.get('ports')]
            if len(listeners) == 1 and listeners[0][1] is not None:
                container, port = listeners[0]
                yield row, f'{service}/revisions/{latest}', container.get('name') or 'ingress container', container.get('image'), 443, port, 'HTTPS', ()
        if row['type'] == 'container_app_runtime' and row['provider'] == 'azure':
            app = apps.get((row['scope'], str(row['native_id']).casefold()))
            if app is None:
                continue
            app_props = _mapping(app['data'].get('properties'))
            ingress = _mapping(_mapping(app_props.get('configuration')).get('ingress'))
            target_port = ingress.get('targetPort')
            if ingress.get('external') is not True or type(target_port) is not int or not 1 <= target_port <= 65535:
                continue
            traffic = _rows(ingress.get('traffic'))
            latest = app_props.get('latestReadyRevisionName')
            targets = {item.get('revisionName') or (latest if item.get('latestRevision') is True else None)
                       for item in traffic if type(item.get('weight')) is int and item['weight'] > 0}
            controls = tuple(filter(None, (
                'Client certificate required' if str(ingress.get('clientCertificateMode', '')).lower() == 'require' else None,
                'Source IP restrictions' if ingress.get('ipSecurityRestrictions') else None,
            )))
            protocol = 'TCP' if ingress.get('transport') == 'tcp' else 'HTTPS'
            frontend = ingress.get('exposedPort') if protocol == 'TCP' else 443
            for revision in _rows(data.get('revisions')):
                ident = revision.get('id')
                active = _mapping(revision.get('properties'))
                if (not isinstance(ident, str) or ident.rsplit('/', 1)[-1] not in targets
                        or active.get('active') is not True or active.get('healthState') != 'Healthy'
                        or type(active.get('replicas')) is not int or active['replicas'] <= 0):
                    continue
                containers = _rows(_mapping(active.get('template')).get('containers'))
                if len(containers) == 1:
                    container = containers[0]
                    yield app, ident, container.get('name'), container.get('image'), frontend, target_port, protocol, controls


def _managed_routes(runtime, inventory, findings):
    public = {row['resource_id']: row for row in findings if row.get('check_id') == 'analysis.internet_exposure'
              and row.get('status') == 'FAIL' and row.get('resource_id')}
    records = {(row['provider'], row['scope'], row['workload'], row['container'], row['digest']): row for row in runtime}
    for resource, workload, container, image, frontend, backend, protocol, controls in managed_workloads(inventory):
        attached = records.get((resource['provider'], resource['scope'], workload, container, immutable_digest(image)))
        observed = public.get(resource['id'])
        if attached is None or not observed:
            continue
        evidence = _mapping(observed.get('evidence'))
        if not _admits_port(frontend, 'TCP' if protocol == 'HTTPS' else protocol, evidence.get('exposed_ports') or ()):
            continue
        access = list(controls)
        if evidence.get('authenticated_endpoint') is True:
            access.append('Authentication required')
        for host in evidence.get('public_addresses') or ():
            if not isinstance(host, str) or not host:
                continue
            if host.startswith('https://'):
                try:
                    host = urlsplit(host).hostname
                except ValueError:
                    continue
            if host:
                route = {'endpoint': host, 'port': frontend, 'protocol': protocol, 'container_port': backend,
                         'kind': resource['type'], 'controls': access, 'finding_id': observed['id']}
                routes = attached.setdefault('exposure_routes', [])
                if route not in routes:
                    routes.append(route)


def enrich_runtime(runtime, inventory, findings):
    if not runtime or not findings:
        return runtime
    _aws_routes(runtime, inventory, findings)
    if any(row['provider'] == 'k8s' for row in runtime):
        _k8s_routes(runtime, inventory, findings)
    if any(row['provider'] == 'gcp' for row in runtime):
        gke_inventory = list(gke_kubernetes_inventory(inventory))
        cluster_scopes = {row['native_id']: row['scope'] for row in gke_inventory
                          if row['type'] == 'pod'}
        gke_runtime = [dict(row, provider='k8s', scope=cluster_scopes[row['workload']])
                       for row in runtime if row['provider'] == 'gcp' and row['workload'] in cluster_scopes
                       and cluster_scopes[row['workload']][0] == row['scope']]
        _k8s_routes(gke_runtime, gke_inventory, findings)
        resolved = {(row['scope'][0], row['workload'], row['container']): row['exposure_routes']
                    for row in gke_runtime if row.get('exposure_routes')}
        for row in runtime:
            if row['provider'] == 'gcp' and (key := (row['scope'], row['workload'], row['container'])) in resolved:
                row['exposure_routes'] = resolved[key]
    _managed_routes(runtime, inventory, findings)
    return runtime


def exposure_findings(snapshot, inventory, routes, evaluated_findings):
    """Emit first-class exposure findings from evaluated advisories and matched routes."""
    from peaso.analysis.common import finding, stable_id
    from peaso.ai.special_report_details import running_images
    from peaso.image_findings import build_report
    from peaso.selected_image_observations_20261021 import metadata_for_report

    runtime = enrich_runtime(running_images(inventory), inventory, routes)
    routed = [row for row in runtime if row.get('exposure_routes')]
    if not routed:
        return []
    metadata = metadata_for_report(snapshot, {'provider': snapshot['provider'], 'snapshot_id': snapshot['snapshot_id'],
                                               'findings': evaluated_findings}) or {}
    images = build_report(metadata.get('observations'), selected=metadata.get('selected', False))
    advisories = defaultdict(dict)
    for row in images['rows']:
        key = (row['vulnerability_id'], row['package'], row['installed_version'])
        advisories[row['image_digest']].setdefault(key, {field: row[field] for field in (
            'vulnerability_id', 'severity', 'package', 'installed_version', 'fixed_versions')})
    assets = {(resource['scope'], resource['native_id']): resource for resource in inventory
              if resource['type'] in RESOURCE_TYPES}
    by_id = {resource['id']: resource for resource in inventory if resource['type'] in RESOURCE_TYPES}
    source = {edge['id']: edge for edge in routes}
    findings = []
    for row in routed:
        matches = list(advisories.get(row['digest'], {}).values())
        if not matches:
            continue
        resource = assets.get((row['scope'], row['workload']))
        if resource is None:
            edge = source[row['exposure_routes'][0]['finding_id']]
            resource = by_id.get(edge['resource_id'])
        if resource is None:
            continue
        counts = {level: sum(item['severity'] == level for item in matches) for level in ('CRITICAL', 'HIGH')}
        counts = {level: count for level, count in counts.items() if count}
        evidence = {'observed': 'An internet-facing route targets a deployed container whose exact image has package advisories.',
                    'container': row['container'], 'workload': row['workload'], 'manifest_digest': row['digest'],
                    'advisory_totals': counts, 'package_advisories': matches[:25],
                    'exposure_routes': row['exposure_routes'], 'risk_state': 'observed_exposure'}
        result = finding(snapshot, resource, 'exposure', CHECK,
            'Internet-facing container runs an image with known vulnerabilities', 'medium', evidence, status='FAIL')
        result.update(id=stable_id(CHECK, resource['id'], row['workload'], row['container'], row['digest']),
                      native_resource_id=row['workload'],
                      evidence_summary=evidence['observed'],
                      remediation='Patch or replace the affected image, redeploy it, and review public access to the container.')
        findings.append(result)
    return findings
