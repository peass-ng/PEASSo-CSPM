"""Metadata-only discovery for jobs, private services, transit and App Engine."""
import re
import json
from pathlib import Path
from urllib.parse import quote
from .gcp import ReadError
from .gcp_fanout import location_fanout


REGIONAL = {
    "api_gateway": ("apigateway", "v1", "gateways", "gateways"),
    "firebase_apphosting_endpoint": ("firebaseapphosting", "v1", "backends", "backends"),
    "datastream_private_connection": ("datastream", "v1", "privateConnections", "privateConnections"),
    "migration_private_connection": ("datamigration", "v1", "privateConnections", "privateConnections"),
    **{kind: ("networkservices", "v1", segment, segment) for kind, segment in {
        "service_mesh": "meshes", "mesh_gateway": "gateways", "mesh_endpoint_policy": "endpointPolicies",
        "mesh_http_route": "httpRoutes", "mesh_grpc_route": "grpcRoutes", "mesh_tcp_route": "tcpRoutes", "mesh_tls_route": "tlsRoutes"}.items()},
    **{kind: ("networksecurity", "v1", segment, segment) for kind, segment in {
        "server_tls_policy": "serverTlsPolicies", "client_tls_policy": "clientTlsPolicies", "authorization_policy": "authorizationPolicies"}.items()},
    **{kind: ("networksecurity", "v1", segment, segment) for kind, segment in {
        "network_security_address_group": "addressGroups",
        "network_security_client_tls_policy": "clientTlsPolicies",
        "network_security_authorization_policy": "authorizationPolicies",
        "network_security_server_tls_policy": "serverTlsPolicies"}.items()},
    "managed_kafka_cluster": ("managedkafka", "v1", "clusters", "clusters"),
    "memorystore_instance": ("memorystore", "v1", "instances", "instances"),
    "vertex_endpoint": ("aiplatform", "v1", "endpoints", "endpoints"),
    "cloudrun_worker_pool": ("run", "v2", "workerPools", "workerPools"),
    "redis_cluster": ("redis", "v1", "clusters", "clusters"),
    "netapp_storage_pool": ("netapp", "v1", "storagePools", "storagePools"),
    "netapp_volume": ("netapp", "v1", "volumes", "volumes"),
    "service_connection_policy": ("networkconnectivity", "v1", "serviceConnectionPolicies", "serviceConnectionPolicies"),
    "network_connectivity_spoke": ("networkconnectivity", "v1", "spokes", "spokes"),
    "batch_network_job": ("batch", "v1", "jobs", "jobs"),
}
PRIVATE_SERVICES = json.loads(Path(__file__).with_name('gcp_network_private_services.json').read_text())
REGIONAL.update({kind: (p['service'], p['version'], p['segment'], p['key']) for kind, p in PRIVATE_SERVICES.items()
                 if not p.get('project_wide') and not p.get('organization_scoped')})
TYPES = set(REGIONAL) | set(PRIVATE_SERVICES) | {"network_connectivity_hub", "service_networking_connection", "dataflow_network_job", "app_engine_network_version", "dns_record_set", "backend_service_health", "target_pool", "target_instance", "identityplatform_config", "firebase_rules_release", "firebase_database_rules"}
DATAFLOW_FIELDS = "id,name,location,projectId,currentState,type,environment(workerPools(network,subnetwork,ipConfiguration))"
APPENGINE_FIELDS = "versions(id,name,servingStatus,env,network,vpcAccessConnector),nextPageToken"
BATCH_FIELDS = "jobs(name,uid,status(state),allocationPolicy(network,location,instances(instanceTemplate))),nextPageToken,unreachable"
ROUTE_FIELDS = {kind: f"{segment}(name,selfLink,meshes,gateways,rules(action(destinations(serviceName,weight))))" +
    ",nextPageToken,unreachable" for kind, (_, _, segment, _) in REGIONAL.items() if kind.startswith("mesh_") and kind.endswith("_route")}
for _kind in ("mesh_http_route", "mesh_grpc_route"):
    ROUTE_FIELDS[_kind] = ROUTE_FIELDS[_kind].replace("name,selfLink,", "name,selfLink,hostnames,")
IAM_NETWORK_SECURITY = frozenset({
    "network_security_address_group", "network_security_client_tls_policy",
    "network_security_authorization_policy", "ngfw_authz_policy",
    "server_tls_policy", "client_tls_policy", "authorization_policy",
    "network_security_server_tls_policy",
})


SERVICE_ENDPOINTS = json.loads(Path(__file__).with_name('gcp_network_service_endpoints.json').read_text())


def api_root(service, version, location=None):
    host = SERVICE_ENDPOINTS.get(service, {}).get(location, service + '.googleapis.com')
    return f'https://{host}/{version}'


def _location_validations(locations):
    if (not isinstance(locations, list) or len(locations) > 1000 or
            any(not isinstance(x, str) or not re.fullmatch(r'[a-z0-9-]+', x) for x in locations)):
        raise ReadError('malformed', 'invalid_network_service_locations')
    return list(dict.fromkeys(locations))


def locations(collector, scope, kind):
    service, version, _, _ = REGIONAL[kind]
    plan = PRIVATE_SERVICES.get(kind, {})
    explicit = collector.options.get(service + '_network_locations')
    regions = collector.options.get('regions')
    if plan.get('location_kind') == 'global':
        yield ['global'], None
        return
    if explicit is not None:
        yield _location_validations(explicit), None
        return
    if plan.get('location_kind') == 'zone' and regions is not None:
        selected = _location_validations(regions)
        direct = [value for value in selected if re.fullmatch(r'.+-[a-z]', value)]
        broad = [value for value in selected if value not in direct]
        if not broad:
            yield direct, None
            return
        # Discover real Compute zones; do not synthesize zone suffixes. For an
        # organization inventory, an authorized selected project supplies only
        # geographic availability, not an inferred ownership relationship.
        project = scope if scope.startswith('projects/') else next((s for s in getattr(collector, 'scopes', []) if s.startswith('projects/')), None)
        if project is None:
            raise ReadError('unavailable', 'zonal_network_location_project_unavailable')
        discovered = list(direct)
        for page, receipt in collector.pages(f'https://compute.googleapis.com/compute/v1/{project}/zones', project,
                params={'fields': 'items(name,region),nextPageToken'}, page_size_key='maxResults'):
            for row in page:
                region, name = row.get('region', '').rsplit('/', 1)[-1], row.get('name')
                if region in broad and isinstance(name, str):
                    discovered.append(name)
            yield [], receipt
        yield _location_validations(discovered), None
        return
    if regions is not None:
        yield _location_validations(regions), None
        return
    if plan.get('default_location'):
        yield [plan['default_location']], None
        return
    result = []
    locations_version = 'v1' if service == 'run' else version
    # BigQuery Connection's native locations endpoint rejects pageSize; its
    # connection list endpoint keeps pageSize. Keep tokens/errors.
    for page, receipt in collector.pages(api_root(service, locations_version) + f'/{scope}/locations', scope,
            key='locations', page_size_key=None if service == 'bigqueryconnection' else 'pageSize'):
        for row in page:
            location = row.get('locationId') or row.get('name', '').rsplit('/', 1)[-1]
            if plan.get('location_kind') != 'zone' or re.fullmatch(r'.+-[a-z]', str(location)):
                result.append(location)
        yield [], receipt
    yield _location_validations(result), None


def _native_child_name(row, parent, segment, collector, scope):
    name = row.get('name')
    prefix = parent + '/' + segment + '/'
    receipts = []
    # APIs may canonicalize a project ID to its numeric name. Only an
    # independently collected CRM identity can authorize that substitution.
    if isinstance(name, str) and not name.startswith(prefix) and parent.startswith('projects/'):
        parts = name.split('/')
        expected = prefix.split('/')
        if len(parts) == len(expected) and parts[0] == 'projects' and parts[2:-1] == expected[2:-1]:
            binding = collector._data_project_binding(scope, require_alias=True)
            aliases = {binding['project_id'], binding['project_number']}
            if parts[1] in aliases and expected[1] in aliases:
                prefix = '/'.join([*expected[:1], parts[1], *expected[2:]])
                receipts = binding['source_requests']
    suffix = name.removeprefix(prefix) if isinstance(name, str) else ''
    if (not isinstance(name, str) or not name.startswith(prefix) or not suffix or
            suffix in {'.', '..'} or any(c in suffix for c in '/?#%')):
        raise ReadError('malformed', 'network_resource_identity_outside_native_parent')
    return name, receipts


def inventory_pages(collector, scope, plan, parent, root):
    parents, failures = [parent], []
    for ancestor in plan.get('parents', []):
        discovered = []
        for parent_name in parents:
            try:
                for page, receipt in collector.pages(root + '/' + parent_name + '/' + ancestor['segment'], scope, key=ancestor['key'],
                        params={'fields': ancestor['key'] + '(name),nextPageToken'}):
                    yield [], receipt
                    for row in page:
                        name, alias_receipts = _native_child_name(row, parent_name, ancestor['segment'], collector, scope)
                        for alias_receipt in alias_receipts:
                            yield [], alias_receipt
                        discovered.append(name)
            except ReadError as exc:
                failures.append(exc)
        parents = discovered
    for parent_name in parents:
        try:
            for page, receipt in collector.pages(root + '/' + parent_name + '/' + plan['segment'], scope,
                    key=plan['key'], params={'fields': plan['fields']}):
                if not plan.get('hydrate'):
                    yield page, receipt
                    continue
                yield [], receipt
                def detail(row, parent_name=parent_name, receipt=receipt):
                    # Buffer one row's yields so detail GETs run concurrently and
                    # replay in row order with the same failure rows.
                    out = []
                    try:
                        name, alias_receipts = _native_child_name(row, parent_name, plan['segment'], collector, scope)
                        for alias_receipt in alias_receipts:
                            out.append(([], alias_receipt))
                        params = dict(plan.get('get_parameters', {}), fields=plan['get_fields'])
                        for details, detail_receipt in collector.pages(root + '/' + name, scope, single=True, params=params):
                            if len(details) != 1 or details[0].get('name') != name:
                                raise ReadError('malformed', 'network_detail_identity_mismatch')
                            if plan.get('iam_policy'):
                                details = [collector.hydrate(details[0], 'iamPolicy',
                                    root + '/' + name + ':getIamPolicy', scope,
                                    params={'options.requestedPolicyVersion': 3})]
                            out.append((details, detail_receipt))
                    except ReadError as exc:
                        out.append(([dict(row, _coverage={'network_detail': {'status': exc.status, 'reason': 'native_metadata_get_unavailable'}})], getattr(exc, 'request_id', receipt)))
                        return out, exc
                    return out, None
                parallel = getattr(collector, 'parallel', None)
                for out, exc in (parallel(detail, page) if callable(parallel) else [detail(row) for row in page]):
                    if exc is not None:
                        failures.append(exc)
                    yield from out
        except ReadError as exc:
            failures.append(exc)
    if failures:
        raise failures[0]


def regional_pages(collector, scope, kind):
    service, version, segment, key = REGIONAL[kind]
    plan = PRIVATE_SERVICES.get(kind)
    discovered, failures = [], []
    try:
        for available, receipt in locations(collector, scope, kind):
            discovered.extend(available)
            if receipt:
                yield [], receipt
    except ReadError as exc:
        if service not in {'networkservices', 'networksecurity'} or plan and plan.get('location_kind') == 'zone':
            raise
        failures.append(exc)
    if service in {'networkservices', 'networksecurity'} and not (plan and plan.get('location_kind') == 'zone'):
        discovered = ['global', *discovered]
    if not discovered:
        raise failures[0] if failures else ReadError('unavailable', 'network_service_locations_unavailable')
    def location_pages(location):
        root = api_root(service, version, location)
        parent = f'{scope}/locations/{location}'
        if plan:
            return inventory_pages(collector, scope, plan, parent, root)
        mask = BATCH_FIELDS if kind == 'batch_network_job' else ROUTE_FIELDS.get(kind)
        def direct_pages():
            for page, receipt in collector.pages(root + f'/{parent}/{segment}', scope, key=key,
                    params={'fields': mask} if mask else None):
                if kind in IAM_NETWORK_SECURITY:
                    def policy(item):
                        name, _ = _native_child_name(item, parent, segment, collector, scope)
                        return collector.hydrate(item, 'iamPolicy', root + '/' + name + ':getIamPolicy', scope,
                            params={'options.requestedPolicyVersion': 3})
                    parallel = getattr(collector, 'parallel', None)
                    page = parallel(policy, page) if callable(parallel) else [policy(item) for item in page]
                yield page, receipt
        return direct_pages()
    for _location, pages, exc in location_fanout(collector, dict.fromkeys(discovered), location_pages):
        yield from pages
        if exc is not None:
            if exc.error.get('reason') == 'SERVICE_DISABLED':
                raise failures[0] if failures else exc  # project-wide
            failures.append(exc)
    if failures:
        raise failures[0]


def dataflow_jobs(collector, scope):
    base = f"https://dataflow.googleapis.com/v1b3/{scope}"
    for page, receipt in collector.pages(base + "/jobs:aggregated", scope, key="jobs",
            params={"filter": "ACTIVE", "fields": "jobs(id,name,location),nextPageToken,failedLocation"}):
        yield [], receipt
        for job in page:
            jid, location = job.get("id"), job.get("location")
            if not isinstance(jid, str) or not re.fullmatch(r"[a-zA-Z0-9_-]+", jid) or not isinstance(location, str) or not re.fullmatch(r"[a-z0-9-]+", location):
                raise ReadError("malformed", "dataflow_network_identity_missing")
            for details, detail_receipt in collector.pages(base + f"/locations/{location}/jobs/{jid}", scope, single=True,
                    params={"view": "JOB_VIEW_ALL", "fields": DATAFLOW_FIELDS}):
                for item in details:
                    if item.get("id") != jid or item.get("location", location) != location:
                        raise ReadError("malformed", "dataflow_network_identity_mismatch")
                yield [dict(item, name=f"{scope}/locations/{location}/jobs/{jid}") for item in details], detail_receipt


def appengine_versions(collector, scope):
    project = scope.split("/", 1)[1]
    base = f"https://appengine.googleapis.com/v1/apps/{project}/services"
    for services, receipt in collector.pages(base, scope, key="services", params={"fields": "services(id,name),nextPageToken"}):
        yield [], receipt
        for service in services:
            name = service.get("name")
            if not isinstance(name, str) or not re.fullmatch(r"apps/" + re.escape(project) + r"/services/[a-z0-9-]+", name):
                raise ReadError("malformed", "appengine_network_service_identity")
            yield from collector.pages(f"https://appengine.googleapis.com/v1/{name}/versions", scope, key="versions",
                params={"view": "FULL", "fields": APPENGINE_FIELDS})


def private_service_connections(collector, scope):
    for networks, receipt in collector.pages(f"https://compute.googleapis.com/compute/v1/{scope}/global/networks", scope,
            params={"fields": "items(name,selfLink),nextPageToken"}, page_size_key="maxResults"):
        yield [], receipt
        for network in networks:
            name = network.get("name")
            if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9-]+", name):
                raise ReadError("malformed", "private_services_network_identity")
            rid = f"{scope}/global/networks/{name}"
            for page, child_receipt in collector.pages("https://servicenetworking.googleapis.com/v1/services/servicenetworking.googleapis.com/connections",
                    scope, key="connections", params={"network": rid}, page_size_key=None):
                yield [dict(item, name=f"{rid}/serviceNetworking/{item.get('peering', i)}") for i, item in enumerate(page)], child_receipt


def dns_record_sets(collector, scope):
    """Enumerate public/private record identities; read address records only.

    TXT and other arbitrary record bodies are not requested, including in the
    transport cache. Private PSC-specific evidence keeps its existing producer.
    """
    base = f"https://dns.googleapis.com/dns/v1/{scope}/managedZones"
    failures = []
    for zones, receipt in collector.pages(base, scope, key="managedZones", page_size_key="maxResults",
            params={"fields": "managedZones(name),nextPageToken"}):
        yield [], receipt
        for zone in zones:
            zid = zone.get("name")
            if not isinstance(zid, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", zid):
                raise ReadError("malformed", "dns_network_zone_identity")
            endpoint = base + f"/{zid}/rrsets"
            for records, record_receipt in collector.pages(endpoint, scope, key="rrsets", page_size_key="maxResults",
                    params={"fields": "rrsets(name,type,ttl),nextPageToken"}):
                yield [], record_receipt
                for record in records:
                    host, rtype = record.get("name"), record.get("type")
                    if not isinstance(host, str) or len(host) > 254 or not re.fullmatch(r"[A-Za-z0-9_*.-]+\.", host) or not isinstance(rtype, str) or not re.fullmatch(r"[A-Z][A-Z0-9]{0,15}", rtype):
                        raise ReadError("malformed", "dns_network_record_identity")
                    identity = f"//dns.googleapis.com/{scope}/managedZones/{zid}/rrsets/{quote(host, safe='')}/{rtype}"
                    row = dict(record, resource=identity, managedZone=zid)
                    if rtype not in {"A", "AAAA", "CNAME", "NS", "PTR", "MX", "SRV"}:
                        yield [dict(row, _coverage={"rrdatas": {"status": "not_collected", "reason": "non_address_record_body_omitted"}})], record_receipt
                        continue
                    try:
                        found = False
                        for details, detail_receipt in collector.pages(endpoint, scope, key="rrsets", page_size_key="maxResults",
                                params={"name": host, "type": rtype, "fields": "rrsets(name,type,ttl,rrdatas),nextPageToken"}):
                            if any(item.get("name") != host or item.get("type") != rtype for item in details):
                                raise ReadError("malformed", "dns_network_record_identity_mismatch")
                            found = found or bool(details)
                            yield [dict(item, resource=identity, managedZone=zid) for item in details], detail_receipt
                        if not found:
                            raise ReadError("unavailable", "dns_network_record_changed_during_collection")
                    except ReadError as exc:
                        failures.append(exc)
                        yield [dict(row, _coverage={"rrdatas": {"status": exc.status}})], record_receipt
    if failures:
        raise failures[0]


def apigee(collector, scope, kind):
    base = 'https://apigee.googleapis.com/v1/organizations'
    project = scope.removeprefix('projects/')
    # Native project mappings bind visible organizations to the selected scope.
    for organizations, receipt in collector.pages(base, scope, key='organizations', page_size_key=None,
            params={'fields': 'organizations(organization,projectId,projectIds)'}):
        yield [], receipt
        for organization in organizations:
            if organization.get('projectId') != project and project not in organization.get('projectIds', []):
                continue
            name = organization.get('organization')
            if not isinstance(name, str) or not re.fullmatch(r'[a-zA-Z0-9_-]+', name):
                raise ReadError('malformed', 'apigee_organization_identity')
            endpoint = base + '/' + name
            fields = PRIVATE_SERVICES[kind]['fields']
            if kind == 'apigee_organization':
                yield from collector.pages(endpoint, scope, single=True, params={'fields': fields})
            else:
                for items, child_receipt in collector.pages(endpoint + '/instances', scope, key='instances',
                        params={'fields': 'instances(' + fields + '),nextPageToken'}):
                    yield [dict(item, name=f'organizations/{name}/instances/{item["name"]}') for item in items], child_receipt


def backend_service_health(collector, scope):
    """Read native backend health separately from the service configuration."""
    project = scope.split('/', 1)[1]
    base = f'https://compute.googleapis.com/compute/v1/{scope}'
    for items, receipt in collector.pages(base + '/aggregated/backendServices', scope,
            key='backendServices', aggregate='backendServices',
            params={'returnPartialSuccess': 'true'}, page_size_key='maxResults'):
        yield [], receipt
        for item in items:
            link = item.get('selfLink')
            expected = (rf'https://(?:www|compute)\.googleapis\.com/compute/v1/projects/'
                rf'{re.escape(project)}/(?:global|regions/[a-z0-9-]+)/backendServices/[A-Za-z0-9_-]+')
            if not isinstance(link, str) or not re.fullmatch(expected, link):
                continue
            groups = []
            for backend in item.get('backends') or []:
                group = backend.get('group') if isinstance(backend, dict) else None
                if not isinstance(group, str) or not re.fullmatch(
                        r'https://(?:www|compute)\.googleapis\.com/compute/v1/projects/'
                        r'[A-Za-z0-9_-]+/(?:zones|regions)/[a-z0-9-]+/'
                        r'(?:instanceGroups|networkEndpointGroups)/[A-Za-z0-9_-]+', group):
                    groups.append({'group': group, 'collection_status': 'unknown',
                        'error': {'code': 'backend_group_identity_missing'}})
                    continue
                try:
                    result, request_id = collector.read(link + '/getHealth', scope,
                        method='POST', body={'group': group})
                    if (not isinstance(result, dict) or not isinstance(result.get('healthStatus', []), list)
                            or any(not isinstance(status, dict) for status in result.get('healthStatus', []))):
                        raise ReadError('malformed', 'backend_health_malformed')
                    groups.append({'group': group, 'collection_status': 'collected',
                        'source_requests': [request_id], 'healthStatus': [
                            {field: status.get(field) for field in ('instance', 'healthState', 'ipAddress', 'port')
                             if field in status} for status in result.get('healthStatus', [])]})
                except ReadError as exc:
                    groups.append({'group': group, 'collection_status': exc.status,
                        'source_requests': [exc.request_id] if getattr(exc, 'request_id', None) else [],
                        'error': exc.error})
            status = 'collected' if all(group['collection_status'] == 'collected' for group in groups) else 'partial'
            yield [{'name': link, 'backendService': link, 'collection_status': status,
                'groups': groups}], receipt


def compute_forward_targets(collector, scope, kind):
    """One read-only aggregate inventory for legacy passthrough/protocol targets."""
    segment, key = ("targetPools", "targetPools") if kind == "target_pool" else ("targetInstances", "targetInstances")
    endpoint = f"https://compute.googleapis.com/compute/v1/{scope}/aggregated/{segment}"
    yield from collector.pages(endpoint, scope, key=key, aggregate=key,
        params={"returnPartialSuccess": "true"}, page_size_key="maxResults")


def identityplatform_config(collector, scope):
    """Read only the project sign-in controls; omit hash and provider secrets."""
    endpoint = f"https://identitytoolkit.googleapis.com/admin/v2/{scope}/config"
    yield from collector.pages(endpoint, scope, single=True,
        params={"fields": "name,signIn(anonymous(enabled)),client(permissions(disabledUserSignup))"})


def scope_jobs(collector, scope):
    scope_kind = scope.split('/', 1)[0]
    if scope_kind not in {'projects', 'organizations'}:
        return []
    jobs = [(kind, scope, spec[0], lambda kind=kind: regional_pages(collector, scope, kind))
            for kind, spec in REGIONAL.items() if kind in collector.needed
            and PRIVATE_SERVICES.get(kind, {}).get('scope_kind', 'projects') == scope_kind]
    if scope_kind != 'projects':
        return jobs
    if 'backend_service_health' in collector.needed:
        jobs.append(('backend_service_health', scope, 'compute',
            lambda: backend_service_health(collector, scope)))
    for kind in ('target_pool', 'target_instance'):
        if kind in collector.needed:
            jobs.append((kind, scope, 'compute',
                lambda kind=kind: compute_forward_targets(collector, scope, kind)))
    if 'identityplatform_config' in collector.needed:
        jobs.append(('identityplatform_config', scope, 'identitytoolkit',
            lambda: identityplatform_config(collector, scope)))
    if 'firebase_rules_release' in collector.needed:
        from .gcp_firebase_rules_exposure import collection_pages
        jobs.append(('firebase_rules_release', scope, 'firebaserules',
            lambda: collection_pages(collector, scope)))
    if 'firebase_database_rules' in collector.needed:
        from .gcp_firebase_database_exposure import collection_pages
        jobs.append(('firebase_database_rules', scope, 'firebasedatabase',
            lambda: collection_pages(collector, scope)))
    for kind, plan in PRIVATE_SERVICES.items():
        if kind not in collector.needed:
            continue
        if plan.get('project_wide'):
            jobs.append((kind, scope, plan['service'], lambda plan=plan: inventory_pages(
                collector, scope, plan, scope, api_root(plan['service'], plan['version']))))
        elif plan.get('organization_scoped'):
            jobs.append((kind, scope, 'apigee', lambda kind=kind: apigee(collector, scope, kind)))
    for kind, service, fetch in (("dataflow_network_job", "dataflow", dataflow_jobs),
            ("dns_record_set", "dns", dns_record_sets),
            ("app_engine_network_version", "appengine", appengine_versions),
            ("service_networking_connection", "servicenetworking", private_service_connections)):
        if kind in collector.needed:
            jobs.append((kind, scope, service, lambda fetch=fetch: fetch(collector, scope)))
    if "network_connectivity_hub" in collector.needed:
        jobs.append(("network_connectivity_hub", scope, "networkconnectivity", lambda: collector.pages(
            f"https://networkconnectivity.googleapis.com/v1/{scope}/locations/global/hubs", scope, key="hubs")))
    return jobs
