"""Network-only evidence preparation and publication of attributed AI findings."""
from collections import Counter, defaultdict
import re

from .briefing import compact

# Workload configuration is projected to network facts. Never hand over pod
# environment variables, instance user data, application configuration or IAM.
WORKLOAD_FIELDS = {
    'aws': {'InstanceId', 'VpcId', 'SubnetId', 'SecurityGroups', 'NetworkInterfaces', 'PrivateIpAddress',
            'PublicIpAddress', 'PrivateDnsName', 'PublicDnsName', 'Ipv6Address', 'SourceDestCheck',
            'DBInstanceIdentifier', 'DBSubnetGroup', 'VpcSecurityGroups', 'PubliclyAccessible', 'Endpoint',
            'VpcConfig', 'NetworkConfiguration', 'DNSName', 'Scheme', 'AvailabilityZones', 'IpAddressType',
            'Tags', 'TagList', 'FunctionName', 'Description', 'DBClusterIdentifier', 'DBSubnetGroupDetails', 'State'},
    'gcp': {'id', 'name', 'selfLink', 'labels', 'description', 'networkInterfaces', 'tags', 'serviceAccounts', 'networkConfig',
            'privateClusterConfig', 'ipAllocationPolicy', 'masterAuthorizedNetworksConfig'},
    'azure': {'id', 'name', 'type', 'location', 'tags'},
    'k8s': {'apiVersion', 'kind', 'metadata'},
}
WORKLOAD_TYPES = {'instance', 'vm', 'pod', 'node', 'daemonset', 'lambda_function', 'rds_instance',
                  'rds_cluster', 'eks_cluster', 'gke_cluster', 'container', 'function', 'app_service'}

# Purpose hints are separate from network facts. Admit only these native paths,
# scalar descriptions/names, and known purpose label keys; never copy workload
# configuration or arbitrary tag values into the service projection.
PURPOSE_TEXT_PATHS = {
    'aws': (('FunctionName',), ('Description',)),
    'gcp': (('description',),),
}
PURPOSE_LABEL_PATHS = {
    'aws': (('Tags',), ('TagList',), ('tags',), ('Cluster', 'cluster', 'tags')),
    'gcp': (('labels',), ('resourceLabels',)),
    'azure': (('tags',),),
}
PURPOSE_LABEL_KEYS = frozenset({
    'Name', 'name', 'App', 'app', 'Application', 'application', 'Service', 'service',
    'Component', 'component', 'Tier', 'tier', 'Role', 'role', 'Purpose', 'purpose',
    'app.kubernetes.io/name', 'app.kubernetes.io/instance',
    'app.kubernetes.io/component', 'app.kubernetes.io/part-of',
})


def retain_purpose_metadata(source, projected, provider):
    """Restore bounded native metadata without traversing application settings."""
    text_paths = PURPOSE_TEXT_PATHS.get(provider, ())
    for path in (*text_paths, *PURPOSE_LABEL_PATHS.get(provider, ())):
        value = source
        for key in path:
            value = value.get(key) if isinstance(value, dict) else None
        if path in text_paths:
            if not isinstance(value, str):
                continue
        elif isinstance(value, dict):
            value = {key: item for key, item in value.items()
                     if key in PURPOSE_LABEL_KEYS and isinstance(item, str)}
        elif provider == 'aws' and len(path) == 1 and path[0] in {'Tags', 'TagList'} and isinstance(value, list):
            value = [{'Key': item['Key'], 'Value': item['Value']} for item in value
                     if isinstance(item, dict) and isinstance(item.get('Key'), str)
                     and item['Key'] in PURPOSE_LABEL_KEYS and isinstance(item.get('Value'), str)]
        else:
            continue
        target = projected
        for key in path[:-1]:
            target = target.setdefault(key, {})
        target[path[-1]] = value


def without_secrets(value, *, network_projection=False):
    if isinstance(value, dict):
        network_fields = {'managedEnvironmentId', 'environmentId', 'environmentConfig', 'privateEnvironmentConfig', 'enablePrivateEnvironment', 'environmentResourceId', 'integrationServiceEnvironment', 'EnvironmentId', 'EnvironmentName'}
        return {key: without_secrets(item, network_projection=network_projection) for key, item in value.items()
                if (network_projection and key in network_fields) or not re.search(
                    r'password|secret|token|private.?key|pre.?shared|shared.?key|authentication.?key|'
                    r'customerGatewayConfiguration|user.?data|custom.?data|environment|appSettings', key, re.I)}
    if isinstance(value, (list, tuple)):
        return [without_secrets(item, network_projection=network_projection) for item in value]
    return value


def native_network_resource(row):
    from peaso.analysis.network import NETWORK_TYPES
    from peaso.analysis.reachability import REACHABILITY_TYPES
    from peaso.analysis.network_services import SERVICE_TYPES, project_network_data
    from peaso.analysis.network_catalog import CONTROL_TYPES
    if row.get('type') in CONTROL_TYPES.get(row['provider'], set()):
        return dict(row, data=without_secrets(row.get('data', {})))
    if row.get('type') in SERVICE_TYPES.get(row['provider'], set()):
        projected = project_network_data(row.get('data', {}))
        retain_purpose_metadata(row.get('data', {}), projected, row['provider'])
        from peaso.analysis.network_observations import network_observations
        retained = {(fact['path'], repr(fact['value'])) for fact in network_observations(projected)}
        observations = [fact for fact in network_observations(row.get('data', {}))
                        if (fact['path'], repr(fact['value'])) not in retained]
        if observations:
            projected['NetworkAttributes'] = network_observations({'NetworkAttributes': projected.get('NetworkAttributes', []) + observations})
        clean = without_secrets(projected, network_projection=True)
        if row['provider'] == 'gcp' and row['type'] == 'dataflow_network_job':
            environment = projected.get('environment') or {}
            if isinstance(environment, dict) and isinstance(environment.get('workerPools'), list):
                clean['environment'] = {'workerPools': [{k: v for k, v in pool.items()
                    if k in {'network', 'subnetwork', 'ipConfiguration'} and isinstance(v, str)}
                    for pool in environment['workerPools'] if isinstance(pool, dict)]}
        return dict(row, data=clean,
                    ai_projection='network fields only; omitted workload settings are unavailable')
    controls = (NETWORK_TYPES | set().union(*REACHABILITY_TYPES.values())) - WORKLOAD_TYPES
    if row.get('type') in controls:
        return dict(row, data=without_secrets(row.get('data', {})))
    provider, data = row['provider'], row.get('data', {})
    selected = {key: value for key, value in data.items() if key in WORKLOAD_FIELDS.get(provider, set())}
    if provider == 'azure':
        props = data.get('properties') or {}
        selected['properties'] = {key: props[key] for key in ('networkProfile', 'subnet', 'publicNetworkAccess',
            'privateEndpointConnections', 'networkAcls', 'ipConfigurations') if key in props}
    if provider == 'k8s':
        meta = data.get('metadata') or {}
        selected['metadata'] = {key: meta[key] for key in ('name', 'namespace', 'uid', 'labels', 'ownerReferences') if key in meta}
        spec = data.get('spec') or {}
        if row.get('type') == 'daemonset':
            template = spec.get('template') or {}
            selected['template_labels'] = (template.get('metadata') or {}).get('labels', {})
            spec = template.get('spec') or {}
        selected['spec'] = {key: spec[key] for key in ('hostNetwork', 'nodeName', 'podCIDR', 'podCIDRs',
            'dnsPolicy', 'nodeSelector') if key in spec}
        selected['ports'] = data.get('ports') if isinstance(data.get('ports'), list) else [port for container in spec.get('containers', []) for port in container.get('ports', [])]
        status = data.get('status') or {}
        selected['status'] = {key: status[key] for key in ('podIP', 'podIPs', 'hostIP', 'addresses') if key in status}
        from peaso.analysis.network_services import project_network_data
        for key in ('volumes', 'providerID'):
            if key in spec:
                selected['spec'][key] = project_network_data(spec[key])
    from peaso.analysis.network_observations import network_observations
    if isinstance(data.get('NetworkAttributes'), list):
        selected['NetworkAttributes'] = network_observations({'NetworkAttributes': data['NetworkAttributes']})
    retained = {(fact['path'], repr(fact['value'])) for fact in network_observations(selected)}
    additional = [fact for fact in network_observations(data) if (fact['path'], repr(fact['value'])) not in retained]
    if additional:
        selected['NetworkAttributes'] = network_observations({'NetworkAttributes': selected.get('NetworkAttributes', []) + additional})
    return dict(row, data=without_secrets(selected), ai_projection='network fields only; omitted workload settings are unavailable')


def snapshot_context(snapshot):
    """Account context and complete collection receipts; native items are in resources."""
    return {**{key: value for key, value in snapshot.items() if key != 'collections'},
            'collections': [{key: value for key, value in row.items() if key != 'items'}
                            | {'item_count': len(row.get('items', []))}
                            for row in snapshot.get('collections', [])]}


def prepare(report, inventory, snapshot):
    from peaso.analysis.reachability import REACHABILITY_TYPES
    from peaso.analysis.network import NETWORK_TYPES
    from peaso.engine import hydrate_finding
    from .pipeline import referenced_strings
    graph = report.get('graphs', {}).get('network') or {}
    types = REACHABILITY_TYPES.get(report['provider'], set()) | NETWORK_TYPES
    references = set(referenced_strings(graph))
    selected = [native_network_resource(row) for row in inventory
                if row.get('type') in types or row['id'] in references]
    if not inventory and not graph.get('nodes') and not graph.get('edges'):
        return None
    findings = []
    # Keep full native Exposure evidence for deduplication and boundary checks.
    def issue(row):
        return dict(row)
    exposure = {row['id']: issue(row) for row in report.get('exposure_findings', [])
                if row.get('id')}
    for raw in report.get('findings', []):
        row = hydrate_finding(raw, report.get('check_frameworks'), report.get('check_meta'),
            report.get('check_meta_encoding'), report.get('remediation_templates'))
        if row.get('category') == 'network':
            findings.append(row)
        elif row.get('category') == 'exposure':
            exposure[row['id']] = issue(row)
    network_types = types | {node.get('type') for node in graph.get('nodes', [])}
    coverage = [row for row in report.get('coverage', []) if row.get('level') == 'scope'
                or row.get('type') in network_types]
    scoped = {key: report[key] for key in ('provider', 'snapshot_id', 'created_at', 'scopes') if key in report}
    scoped.update(resources=[{key: value for key, value in row.items() if key != 'data'} for row in selected],
                  findings=findings, graphs={'network': graph}, coverage=coverage,
                  exposure_findings=list(exposure.values()))
    return {'report': scoped, 'inventory': selected,
            'source_inventory': inventory, 'source_report': report,
            'snapshot_context': snapshot_context(snapshot)}


def build(root, platform, reviews, write_json):
    from .briefing import build as build_context
    # Enforce the handoff at the file-writing boundary as well as scheduling.
    original = platform
    platform = prepare(platform.get('source_report', platform['report']),
                       platform.get('source_inventory', platform['inventory']), {})
    if platform is not None:
        for key in ('source_inventory', 'source_report', 'snapshot_context'):
            if key in original:
                platform[key] = original[key]
    if platform is None:
        raise ValueError('network_context_unavailable')
    # Projected first reads are backed by complete original source lookups.
    build_context(root, platform, platform['report']['findings'], reviews, write_json)
    write_json(root / 'exposure.json', {'findings': platform['report']['exposure_findings']})
    graph = platform['report']['graphs']['network']
    nodes = graph.get('nodes', [])
    by_id = {row['id']: row for row in nodes}
    groups = defaultdict(list)
    for row in nodes:
        groups[row.get('provider', ''), row.get('scope', ''), row.get('type', 'unknown')].append(row)
    boundaries = {'vpc', 'vnet', 'network', 'subnet', 'subnetwork', 'namespace', 'cluster'}
    edge_groups = defaultdict(list)
    for row in graph.get('edges', []):
        source, target = by_id.get(row.get('source'), {}), by_id.get(row.get('target'), {})
        edge_groups[row.get('type', ''), source.get('type', ''), target.get('type', ''),
                    source.get('scope', ''), target.get('scope', '')].append(row['id'])
    write_json(root / 'topology.json', {
        'version': 1,
        'boundaries': [{key: compact(row[key]) for key in ('id', 'type', 'label', 'scope', 'resource_id', 'native_id', 'unresolved') if key in row}
                       for row in nodes if row.get('type') in boundaries],
        'node_groups': [{'provider': key[0], 'scope': key[1], 'type': key[2], 'count': len(rows),
                         'examples': [row['id'] for row in rows[:3]]} for key, rows in groups.items()],
        'edge_groups': [{'type': key[0], 'source_type': key[1], 'target_type': key[2], 'source_scope': key[3],
                         'target_scope': key[4], 'count': len(ids), 'examples': ids[:3]} for key, ids in edge_groups.items()],
        'resource_counts': dict(Counter(row['type'] for row in platform['inventory'])),
        'semantics': 'Complete boundary list and group catalog; examples are samples. Structural links and rules do not prove reachable flows.'})


def with_findings(report, findings):
    """Return an augmented report without changing deterministic observations."""
    if not findings:
        return report
    known = {row['id'] for row in report.get('findings', [])}
    added = [row for row in findings if row['id'] not in known]
    stats = dict(report.get('stats', {}))
    for key, field, rows in (('by_status', 'status', added),
                             ('by_severity', 'severity', [row for row in added if row['status'] == 'FAIL'])):
        counts = Counter(stats.get(key, {}))
        counts.update(row[field] for row in rows)
        stats[key] = dict(counts)
    stats['finding_count'] = stats.get('finding_count', len(known)) + len(added)
    stats['ai_network_finding_count'] = len(findings)
    return dict(report, findings=report.get('findings', []) + added, stats=stats)
