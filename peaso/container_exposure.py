"""Join captured internet-facing listener routes to exact running containers."""
from collections import defaultdict
from collections.abc import Mapping
from ipaddress import ip_network


def _mapping(value):
    return value if isinstance(value, Mapping) else {}


def _rows(value):
    return [row for row in value if isinstance(row, Mapping)] if isinstance(value, (list, tuple)) else []


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
            if type(port) is not int or f'tcp/{port}' not in ports or protocol not in ('HTTP', 'HTTPS'):
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
                auth_configs = {'authenticate-oidc': 'AuthenticateOidcConfig',
                                'authenticate-cognito': 'AuthenticateCognitoConfig'}
                if any(_mapping(action.get(auth_configs[action['Type']])).get('OnUnauthenticatedRequest', 'authenticate')
                       in ('authenticate', 'deny') for action in _rows(rule.get('Actions'))
                       if action.get('Type') in auth_configs):
                    controls.append('Listener authentication required')
                if any(condition.get('Field') == 'source-ip' for condition in conditions):
                    controls.append('Source IP restrictions')
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
        if evidence.get('exposure_kind') == 'service':
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
                        or conditions.get('ready') is not True or conditions.get('terminating') is True):
                    continue
                expected_ips = pod_addresses.get((row['scope'], namespace, ref['uid']), set()) - {None}
                if not expected_ips.intersection(endpoint.get('addresses') or ()):
                    continue
                for backend in _rows(slice_data.get('ports')):
                    for frontend in _rows(spec.get('ports')):
                        protocol = frontend.get('protocol', 'TCP')
                        if (backend.get('protocol', 'TCP') != protocol
                                or (backend.get('name') or '') != (frontend.get('name') or '')
                                or f"{protocol.lower()}/{frontend.get('port')}" not in evidence.get('exposed_ports', ())
                                or type(backend.get('port')) is not int):
                            continue
                        for address in sorted(public - {None}):
                            resolved[row['scope'], ref['uid']].append({
                                'endpoint': address, 'protocol': protocol, 'port': frontend['port'],
                                'container_port': backend['port'], 'kind': 'load_balancer_service',
                                'service': f'{namespace}/{name}', 'finding_id': finding_id,
                                'controls': ['Pod-level access controls unverified'],
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
                                for port in _rows(container.get('ports')))]
            if listeners == [running['container']]:
                attached = running.setdefault('exposure_routes', [])
                if route not in attached:
                    attached.append(route)


def enrich_runtime(runtime, inventory, findings):
    _aws_routes(runtime, inventory, findings)
    if any(row['provider'] == 'k8s' for row in runtime):
        _k8s_routes(runtime, inventory, findings)
    return runtime
