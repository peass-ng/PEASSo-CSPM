"""Metadata-only discovery for jobs, private services, transit and App Engine."""
import re
import json
from itertools import count
from pathlib import Path
from urllib.parse import quote, urlsplit
from .gcp import ReadError
from .gcp_fanout import location_fanout


REGIONAL = {
    "api_gateway": ("apigateway", "v1", "gateways", "gateways"),
    "firebase_apphosting_endpoint": ("firebaseapphosting", "v1", "backends", "backends"),
    "datastream_private_connection": ("datastream", "v1", "privateConnections", "privateConnections"),
    "migration_private_connection": ("datamigration", "v1", "privateConnections", "privateConnections"),
    "migration_job": ("datamigration", "v1", "migrationJobs", "migrationJobs"),
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
    "redis_cluster": ("redis", "v1", "clusters", "clusters"),
    "netapp_storage_pool": ("netapp", "v1", "storagePools", "storagePools"),
    "netapp_volume": ("netapp", "v1", "volumes", "volumes"),
    "service_connection_policy": ("networkconnectivity", "v1", "serviceConnectionPolicies", "serviceConnectionPolicies"),
    "network_connectivity_spoke": ("networkconnectivity", "v1", "spokes", "spokes"),
    "batch_network_job": ("batch", "v1", "jobs", "jobs"),
    "dlp_exposure": ("dlp", "v2", "discoveryConfigs", "discoveryConfigs"),
}
PRIVATE_SERVICES = json.loads(Path(__file__).with_name('gcp_network_private_services.json').read_text())
REGIONAL.update({kind: (p['service'], p['version'], p['segment'], p['key']) for kind, p in PRIVATE_SERVICES.items()
                 if not p.get('project_wide') and not p.get('organization_scoped')})
TYPES = set(REGIONAL) | set(PRIVATE_SERVICES) | {"network_connectivity_hub", "service_networking_connection", "dataflow_network_job", "app_engine_network_version", "dns_record_set", "backend_service_health", "target_pool", "target_instance", "identityplatform_config", "firebase_rules_release", "firebase_database_rules", "pubsub_topic_attachment", "pubsub_schema_iam", "containeranalysis_occurrence", "api_gateway_resource", "cloudtasks_delivery", "dialogflow_es_fulfillment", "lakehouse_resource", "apigee_route"}
DATAFLOW_FIELDS = "id,name,location,projectId,currentState,type,environment(workerPools(network,subnetwork,ipConfiguration))"
APPENGINE_FIELDS = "versions(id,name,servingStatus,env,network,vpcAccessConnector),nextPageToken"
BATCH_FIELDS = "jobs(name,uid,status(state),allocationPolicy(network,location,instances(instanceTemplate))),nextPageToken,unreachable"
ROUTE_FIELDS = {kind: f"{segment}(name,selfLink,meshes,gateways,rules(action(destinations(serviceName,weight))))" +
    ",nextPageToken,unreachable" for kind, (_, _, segment, _) in REGIONAL.items() if kind.startswith("mesh_") and kind.endswith("_route")}
for _kind in ("mesh_http_route", "mesh_grpc_route"):
    ROUTE_FIELDS[_kind] = ROUTE_FIELDS[_kind].replace("name,selfLink,", "name,selfLink,hostnames,")
IAM_NETWORK_SECURITY = frozenset({
    "api_gateway",
    "network_security_address_group", "network_security_client_tls_policy",
    "network_security_authorization_policy", "ngfw_authz_policy",
    "server_tls_policy", "client_tls_policy", "authorization_policy",
    "network_security_server_tls_policy",
})
DMS_KINDS = frozenset({"migration_private_connection", "migration_connection_profile", "migration_job"})
NCC_KINDS = frozenset({"network_connectivity_spoke"})


SERVICE_ENDPOINTS = json.loads(Path(__file__).with_name('gcp_network_service_endpoints.json').read_text())
BACKUPDR_DATA_SOURCE_FIELDS = ('dataSources(name,state,configState,backupBlockedByVaultAccessRestriction,'
    'dataSourceGcpResource(gcpResourcename),backupConfigInfo(lastBackupState,'
    'gcpBackupConfig(backupPlan,backupPlanAssociation))),nextPageToken,unreachable')


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


def _dms_safe_row(kind, row):
    """Keep network and sharing facts, excluding passwords, SSH keys and certificates."""
    if kind == "migration_job":
        safe = {key: row[key] for key in ("name", "state", "phase", "source", "destination",
                "dumpPath", "type") if key in row}
        peering = row.get("vpcPeeringConnectivity")
        if isinstance(peering, dict) and isinstance(peering.get("vpc"), str):
            safe["vpcPeeringConnectivity"] = {"vpc": peering["vpc"]}
        return safe
    if kind == "migration_private_connection":
        return {key: row[key] for key in ("name", "state") if key in row} | {
            key: {sub: row[key][sub] for sub in ("vpc", "vpcName", "subnet", "networkAttachment") if sub in row[key]}
            for key in ("vpcPeeringConfig", "pscInterfaceConfig") if isinstance(row.get(key), dict)}
    safe = {key: row[key] for key in ("name", "state", "role", "provider") if key in row}
    for engine in ("mysql", "postgresql", "sqlserver", "oracle", "cloudsql", "alloydb"):
        profile = row.get(engine)
        if not isinstance(profile, dict):
            continue
        safe[engine] = {key: profile[key] for key in ("host", "port", "cloudSqlId", "cloudSqlProjectId",
            "alloydbClusterId", "publicIp", "privateIp") if key in profile}
        connectivity = next((key for key in ("staticIpConnectivity", "staticServiceIpConnectivity",
            "privateConnectivity", "privateServiceConnectConnectivity", "forwardSshConnectivity")
            if key in profile), None)
        safe[engine]["connectivity"] = connectivity
        if connectivity and isinstance(profile.get(connectivity), dict):
            details = {key: profile[connectivity][key] for key in ("privateConnection", "serviceAttachment",
                       "hostname", "port") if key in profile[connectivity]}
            if details:
                safe[engine]["connectivityDetails"] = details
    return safe


def _netapp_safe_volume(row):
    safe = {key: row[key] for key in ("name", "state", "shareName", "storagePool", "network",
            "protocols", "smbSettings", "activeDirectory", "hasReplication") if key in row}
    export = row.get("exportPolicy")
    if isinstance(export, dict):
        safe["exportPolicy"] = {"rules": [{key: rule[key] for key in
            ("allowedClients", "accessType", "nfsv3", "nfsv4", "kerberos5ReadOnly",
             "kerberos5ReadWrite", "kerberos5iReadOnly", "kerberos5iReadWrite",
             "kerberos5pReadOnly", "kerberos5pReadWrite") if key in rule}
            for rule in (export.get("rules") or []) if isinstance(rule, dict)]}
    safe["mountOptions"] = [{key: option[key] for key in ("protocol", "ipAddress") if key in option}
                            for option in (row.get("mountOptions") or []) if isinstance(option, dict)]
    for section, fields in (("backupConfig", ("backupVault", "scheduledBackupEnabled")),
                            ("cloneDetails", ("sourceVolume", "sourceSnapshot")),
                            ("restoreParameters", ("sourceBackup", "sourceSnapshot")),
                            ("hybridReplicationParameters", ("replication", "peerIpAddresses", "hybridReplicationType")),
                            ("cacheParameters", ("peerIpAddresses", "cacheState"))):
        value = row.get(section)
        if isinstance(value, dict):
            safe[section] = {key: value[key] for key in fields if key in value}
    return safe


def inventory_pages(collector, scope, plan, parent, root):
    projection = {'eventarc_pipeline': _eventarc_pipeline,
                  'agent_registry_interface': _agent_registry_interface,
                  'agent_gateway': _agent_gateway,
                  'vertex_agent_engine': _vertex_agent_engine,
                  'application_integration_template': _application_integration_template,
                  'application_integration_version': _application_integration_version,
                  'visionai_application': _visionai_application,
                  'visionai_cluster': lambda row: {'name': row.get('name')},
                  'visionai_stream': _visionai_stream,
                  'livestream_input': _livestream_input,
                  'livestream_channel': _livestream_channel,
                  'dataform_repository': _dataform_repository,
                  'datastream_connection_profile': _datastream_connection_profile,
                  'datastream_stream': _datastream_stream,
                  'integration_connection': _integration_connection,
                  'video_stitcher_config': _video_stitcher_config}.get(plan.get('projection'))
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
                    key=plan['key'], params={'fields': plan['fields']},
                    transform=projection):
                if not plan.get('hydrate'):
                    if plan.get('projection') == 'integration_connection':
                        page = [dict(item, _coverage={**item.get('_coverage', {}),
                            'network_detail': {'status': 'collected', 'source_requests': [receipt]}}) for item in page]
                    if plan.get('iam_policy'):
                        def policy(item):
                            name, _ = _native_child_name(item, parent_name, plan['segment'], collector, scope)
                            if plan['service'] == 'binaryauthorization':
                                note = item.get('userOwnedGrafeasNote')
                                item = {'name': name, 'userOwnedGrafeasNote': {
                                    'noteReference': note['noteReference']} if isinstance(note, dict)
                                    and isinstance(note.get('noteReference'), str) else {}}
                            if plan.get('iam_method') == 'POST':
                                return collector.hydrate(item, 'iamPolicy', root + '/' + name + ':getIamPolicy', scope,
                                    method='POST', body={'resource': name, 'options': {'requestedPolicyVersion': 3}})
                            if plan.get('iam_method') == 'POST_EMPTY':
                                return collector.hydrate(item, 'iamPolicy', root + '/' + name + ':getIamPolicy', scope,
                                    method='POST', body={}, params={'options.requestedPolicyVersion': 3})
                            return collector.hydrate(item, 'iamPolicy', root + '/' + name + ':getIamPolicy', scope,
                                params={'options.requestedPolicyVersion': 3})
                        parallel = getattr(collector, 'parallel', None)
                        page = parallel(policy, page) if callable(parallel) else [policy(item) for item in page]
                    if plan['segment'] == 'backupVaults':
                        def vault_sources(row):
                            name, _ = _native_child_name(row, parent_name, 'backupVaults', collector, scope)
                            sources = []
                            for data_sources, _ in collector.pages(root + '/' + name + '/dataSources', scope,
                                    key='dataSources', params={'fields': BACKUPDR_DATA_SOURCE_FIELDS}):
                                sources.extend({field: item[field] for field in ('name', 'state', 'configState',
                                    'backupBlockedByVaultAccessRestriction', 'dataSourceGcpResource', 'backupConfigInfo')
                                    if field in item} for item in data_sources)
                            return dict(row, dataSources=sources)
                        parallel = getattr(collector, 'parallel', None)
                        page = parallel(vault_sources, page) if callable(parallel) else [vault_sources(row) for row in page]
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
                        for details, detail_receipt in collector.pages(root + '/' + name, scope, single=True, params=params,
                                transform=projection):
                            if len(details) != 1 or details[0].get('name') != name:
                                raise ReadError('malformed', 'network_detail_identity_mismatch')
                            if plan['service'] == 'datamigration' and plan['segment'] == 'connectionProfiles':
                                details = [collector.hydrate(_dms_safe_row('migration_connection_profile', details[0]),
                                    'iamPolicy', root + '/' + name + ':getIamPolicy', scope,
                                    params={'options.requestedPolicyVersion': 3})]
                            elif plan.get('iam_policy'):
                                if plan.get('iam_method') == 'POST':
                                    details = [collector.hydrate(details[0], 'iamPolicy',
                                        root + '/' + name + ':getIamPolicy', scope, method='POST',
                                        body={'resource': name, 'options': {'requestedPolicyVersion': 3}})]
                                elif plan.get('iam_method') == 'POST_EMPTY':
                                    details = [collector.hydrate(details[0], 'iamPolicy',
                                        root + '/' + name + ':getIamPolicy', scope, method='POST',
                                        body={}, params={'options.requestedPolicyVersion': 3})]
                                else:
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


def _visionai_application(row):
    outputs = row.get('runtimeInfo', {}).get('globalOutputResources', [])
    return {'name': row.get('name'), 'state': row.get('state'),
            'outputResources': [entry.get('outputResource') for entry in outputs
                                if isinstance(entry, dict) and isinstance(entry.get('outputResource'), str)]}


def _agent_gateway(row):
    card = row.get('agentGatewayCard')
    return {'name': row.get('name'), 'agentGatewayCard':
            {'mtlsEndpoint': card.get('mtlsEndpoint')} if isinstance(card, dict) else {}}


def _agent_registry_interface(row):
    origins = []
    for interface in row.get('interfaces', []):
        if isinstance(interface, dict) and isinstance(interface.get('url'), str):
            try:
                parts = urlsplit(interface['url'])
                if parts.scheme in {'http', 'https'} and parts.hostname:
                    origins.append(f'{parts.scheme}://{parts.hostname}' + (f':{parts.port}' if parts.port else ''))
            except ValueError:
                continue
    return {'name': row.get('name'), 'origins': sorted(set(origins))}


def _vertex_agent_engine(row):
    spec = row.get('spec')
    deployment = spec.get('deploymentSpec') if isinstance(spec, dict) else None
    psc = deployment.get('pscInterfaceConfig') if isinstance(deployment, dict) else None
    return {'name': row.get('name'), 'pscInterfaceConfig':
            {'networkAttachment': psc.get('networkAttachment')} if isinstance(psc, dict) else {}}


def _visionai_stream(row):
    return {'name': row.get('name'), 'enableHlsPlayback': row.get('enableHlsPlayback'),
            'mediaWarehouseAsset': row.get('mediaWarehouseAsset')}


def _application_integration_template(row):
    return {'name': row.get('name'), 'visibility': row.get('visibility'),
            'sharedWith': [value for value in row.get('sharedWith', []) if isinstance(value, str)]}


def _application_integration_version(row):
    triggers = row.get('triggerConfigs', [])
    return {'name': row.get('name'), 'state': row.get('state'),
            'triggerTypes': sorted({trigger.get('triggerType') for trigger in triggers
                                    if isinstance(trigger, dict) and isinstance(trigger.get('triggerType'), str)})}


def lakehouse_resources(collector, scope):
    """Iceberg catalog hierarchy with only identity, routing class and direct IAM."""
    root = api_root('biglake', 'v1')
    extension = 'https://biglake.googleapis.com/iceberg/v1/restcatalog/extensions/'
    iceberg = 'https://biglake.googleapis.com/iceberg/v1/restcatalog/v1/'

    def pages(url, key, token_key='next-page-token', **params):
        token, seen = None, set()
        for page_number in count():
            query = dict(params)
            if token:
                query['page-token' if key == 'iceberg-catalogs' else 'pageToken'] = token
            value, receipt = collector.read(url, scope, params=query)
            if not isinstance(value, dict) or not isinstance(value.get(key, []), list):
                raise ReadError('malformed', 'malformed_lakehouse_list')
            if value.get('unreachable'):
                raise ReadError('unavailable', 'lakehouse_unreachable_regions')
            yield value.get(key, []), receipt
            token = value.get(token_key)
            if token is None or token == '':
                return
            if not isinstance(token, str) or token in seen:
                raise ReadError('malformed', 'malformed_lakehouse_pagination')
            seen.add(token)
            if collector.max_pages is not None and page_number + 1 >= collector.max_pages:
                raise ReadError('unavailable', 'page_limit')

    def policy(name, kind, extra=None):
        row = {'name': name, 'resourceKind': kind, **(extra or {})}
        return collector.hydrate(row, 'iamPolicy', root + '/' + name + ':getIamPolicy', scope,
                                 params={'options.requestedPolicyVersion': 3})

    for catalogs, receipt in pages(extension + scope + '/catalogs', 'iceberg-catalogs',
                                    view='CATALOG_VIEW_FULL', **{'page-size': collector.page_size}):
        for catalog in catalogs:
            if not isinstance(catalog, dict):
                raise ReadError('malformed', 'malformed_lakehouse_catalog')
            name = catalog.get('name')
            if (not isinstance(name, str) or not name.startswith(scope + '/catalogs/') or
                    not re.fullmatch(r'[A-Za-z0-9_.-]+', name[len(scope) + len('/catalogs/'):])):
                raise ReadError('malformed', 'lakehouse_catalog_outside_project')
            federation = catalog.get('federated-catalog-options') or {}
            if not isinstance(federation, dict):
                raise ReadError('malformed', 'malformed_lakehouse_federation')
            provider = next((label for field, label in (
                ('unity-catalog-info', 'Databricks'), ('glue-catalog-info', 'AWS Glue'),
                ('snowflake-catalog-info', 'Snowflake'), ('workday-catalog-info', 'Workday'))
                if field in federation), None)
            extra = {'catalogType': catalog.get('catalog-type'),
                     'credentialMode': catalog.get('credential-mode')}
            if provider:
                extra['federatedProvider'] = provider
                extra['privateServiceDirectory'] = bool(federation.get('service-directory-name'))
            yield [policy(name, 'catalog', extra)], receipt
            for namespaces, namespace_receipt in pages(iceberg + name + '/namespaces', 'namespaces',
                                                        pageSize=collector.page_size):
                for namespace in namespaces:
                    if (not isinstance(namespace, list) or len(namespace) != 1 or
                            not isinstance(namespace[0], str) or
                            not re.fullmatch(r'[A-Za-z0-9_.-]+', namespace[0])):
                        raise ReadError('malformed', 'malformed_lakehouse_namespace')
                    namespace_name = name + '/namespaces/' + namespace[0]
                    yield [policy(namespace_name, 'namespace')], namespace_receipt
                    for tables, table_receipt in pages(iceberg + namespace_name + '/tables', 'identifiers',
                                                       pageSize=collector.page_size):
                        for table in tables:
                            if (not isinstance(table, dict) or table.get('namespace') != namespace or
                                    not isinstance(table.get('name'), str) or
                                    not re.fullmatch(r'[A-Za-z0-9_.-]+', table['name'])):
                                raise ReadError('malformed', 'malformed_lakehouse_table')
                            yield [policy(namespace_name + '/tables/' + table['name'], 'table')], table_receipt


def _eventarc_pipeline(row):
    projected = {"name": row.get("name"), "destinations": []}
    destinations = row.get("destinations", [])
    if not isinstance(destinations, list):
        raise ReadError("malformed", "eventarc_pipeline_destinations_invalid")
    for destination in destinations:
        if not isinstance(destination, dict):
            raise ReadError("malformed", "eventarc_pipeline_destination_invalid")
        item = {key: destination[key] for key in ("workflow", "messageBus", "topic") if key in destination}
        network = destination.get("networkConfig")
        if isinstance(network, dict) and isinstance(network.get("networkAttachment"), str):
            item["networkAttachment"] = network["networkAttachment"]
        endpoint = destination.get("httpEndpoint")
        if isinstance(endpoint, dict):
            uri = endpoint.get("uri")
            try:
                parsed = urlsplit(uri) if isinstance(uri, str) else None
                if (not parsed or parsed.scheme != "https" or not parsed.hostname
                        or parsed.username or parsed.password or parsed.port == 0):
                    raise ValueError("invalid endpoint")
                item["httpOrigin"] = parsed.scheme + "://" + parsed.netloc
            except ValueError:
                item["httpOriginStatus"] = "malformed"
        projected["destinations"].append(item)
    return projected


def _livestream_origin(uri, schemes):
    if not isinstance(uri, str):
        return None
    try:
        parsed = urlsplit(uri)
        if parsed.scheme not in schemes or not parsed.hostname or parsed.username or parsed.password:
            return None
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            return None
        host = parsed.hostname
        if ':' in host:
            host = '[' + host + ']'
        return parsed.scheme + '://' + host + (':' + str(port) if port else '')
    except ValueError:
        return None


def _livestream_input(row):
    rules = row.get('securityRules')
    if rules is not None and not isinstance(rules, dict):
        raise ReadError('malformed', 'livestream_input_security_rules_invalid')
    ranges = rules.get('ipRanges') if isinstance(rules, dict) else None
    if ranges is not None and (not isinstance(ranges, list) or
                               any(not isinstance(value, str) for value in ranges)):
        raise ReadError('malformed', 'livestream_input_ip_ranges_invalid')
    return {'name': row.get('name'), 'type': row.get('type'),
            'origin': _livestream_origin(row.get('uri'), {'rtmp', 'srt'}),
            'securityRules': {'ipRanges': ranges} if isinstance(rules, dict) else None}


def _livestream_channel(row):
    projected = {'name': row.get('name'), 'streamingState': row.get('streamingState'),
                 'distributions': []}
    distributions = row.get('distributions', [])
    if not isinstance(distributions, list):
        raise ReadError('malformed', 'livestream_channel_distributions_invalid')
    for distribution in distributions:
        if not isinstance(distribution, dict):
            raise ReadError('malformed', 'livestream_channel_distribution_invalid')
        config = distribution.get('srtPush') or distribution.get('rtmpPush')
        uri = config.get('uri') if isinstance(config, dict) else None
        projected['distributions'].append({
            'state': distribution.get('state'),
            'origin': _livestream_origin(uri, {'rtmp', 'srt'}),
            'protocol': 'srt' if isinstance(distribution.get('srtPush'), dict) else 'rtmp'
            if isinstance(distribution.get('rtmpPush'), dict) else None})
    return projected


def _dataform_repository(row):
    projected = {'name': row.get('name')}
    remote = row.get('gitRemoteSettings')
    if isinstance(remote, dict) and isinstance(remote.get('url'), str):
        url = remote['url']
        try:
            parsed = urlsplit(url)
            if parsed.scheme in {'https', 'ssh'} and parsed.hostname and not parsed.username and not parsed.password:
                projected['gitRemoteOrigin'] = parsed.scheme + '://' + parsed.hostname
            elif re.fullmatch(r'[^@\s]+@[^:\s]+:[^\s]+', url):
                projected['gitRemoteOrigin'] = 'ssh://' + url.split('@', 1)[1].split(':', 1)[0]
            else:
                projected['gitRemoteStatus'] = 'unparsed'
        except ValueError:
            projected['gitRemoteStatus'] = 'unparsed'
    if 'iamPolicy' in row:
        projected['iamPolicy'] = row['iamPolicy']
    return projected


def _datastream_connection_profile(row):
    projected = {'name': row.get('name')}
    for key in ('oracleProfile', 'mysqlProfile', 'postgresqlProfile', 'sqlServerProfile'):
        value = row.get(key)
        if isinstance(value, dict):
            projected[key] = {field: value[field] for field in ('hostname', 'port') if field in value}
    value = row.get('gcsProfile')
    if isinstance(value, dict):
        projected['gcsProfile'] = {field: value[field] for field in ('bucket',) if field in value}
    if isinstance(row.get('staticServiceIpConnectivity'), dict):
        projected['staticServiceIpConnectivity'] = {}
    for key, fields in (('forwardSshConnectivity', ('hostname', 'port')),
                        ('privateConnectivity', ('privateConnection',))):
        value = row.get(key)
        if isinstance(value, dict):
            projected[key] = {field: value[field] for field in fields if field in value}
    return projected


def _datastream_stream(row):
    projected = {'name': row.get('name'), 'state': row.get('state')}
    source = row.get('sourceConfig')
    if isinstance(source, dict):
        projected['sourceConfig'] = {field: source[field] for field in ('sourceConnectionProfile',) if field in source}
    destination = row.get('destinationConfig')
    if isinstance(destination, dict):
        projected['destinationConfig'] = {field: destination[field] for field in ('destinationConnectionProfile',)
                                          if field in destination}
        bq = destination.get('bigqueryDestinationConfig')
        if isinstance(bq, dict):
            projected['destinationConfig']['bigqueryDestinationConfig'] = {
                key: {field: bq[key][field] for field in fields if field in bq[key]}
                for key, fields in (('sourceHierarchyDatasets', ('projectId',)), ('blmtConfig', ('bucket',)))
                if isinstance(bq.get(key), dict)}
    return projected


def _integration_connection(row):
    projected = dict(row)
    for field, endpoint in (('eventingRuntimeData', 'eventsListenerEndpoint'),
                            ('eventingConfig', 'eventsListenerIngressEndpoint')):
        nested = row.get(field)
        if not isinstance(nested, dict) or endpoint not in nested:
            continue
        nested = dict(nested)
        uri = nested.pop(endpoint)
        origin = _livestream_origin(uri, {'http', 'https'})
        if origin:
            nested[endpoint + 'Origin'] = origin
        else:
            nested[endpoint + 'Status'] = 'unparsed'
        projected[field] = nested
    return projected


def _dialogflow_fulfillment(row):
    service = row.get('genericWebService')
    return {'name': row.get('name'), 'enabled': row.get('enabled'),
            'webhookOrigin': _livestream_origin(service.get('uri'), {'https'})
            if isinstance(service, dict) else None,
            'cloudFunction': service.get('isCloudFunction') if isinstance(service, dict) else None}


def _video_stitcher_config(row):
    return {'name': row.get('name'), 'state': row.get('state'),
            'sourceOrigin': _livestream_origin(row.get('sourceUri'), {'http', 'https', 'gs'}),
            'adTagOrigin': _livestream_origin(row.get('adTagUri'), {'http', 'https'})}


def dialogflow_es_fulfillments(collector, scope):
    root = 'https://dialogflow.googleapis.com/v2/'
    for agents, receipt in collector.pages(root + scope + '/agent:search', scope, key='agents',
            params={'fields': 'agents(parent),nextPageToken'}):
        yield [], receipt
        for agent in agents:
            parent = agent.get('parent')
            if parent != scope:
                raise ReadError('malformed', 'dialogflow_agent_parent_outside_scope')
            name = parent + '/agent/fulfillment'
            for rows, detail_receipt in collector.pages(root + name, scope, single=True,
                    params={'fields': 'name,enabled,genericWebService(uri,isCloudFunction)'},
                    transform=_dialogflow_fulfillment):
                if len(rows) != 1 or rows[0].get('name') != name:
                    raise ReadError('malformed', 'dialogflow_fulfillment_identity_mismatch')
                yield [dict(rows[0], environment='draft')], detail_receipt
            for environments, env_receipt in collector.pages(root + parent + '/agent/environments', scope,
                    key='environments', params={'fields': 'environments(name,state,fulfillment(enabled,genericWebService(uri,isCloudFunction))),nextPageToken'}):
                projected = []
                for env in environments:
                    env_name = env.get('name')
                    if not isinstance(env_name, str) or not env_name.startswith(parent + '/agent/environments/'):
                        raise ReadError('malformed', 'dialogflow_environment_identity_mismatch')
                    fulfillment = env.get('fulfillment')
                    if not isinstance(fulfillment, dict):
                        continue
                    projected.append(dict(_dialogflow_fulfillment(fulfillment), name=env_name,
                                          environment=env_name, environmentState=env.get('state')))
                yield projected, env_receipt


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
                if kind in DMS_KINDS:
                    def dms_policy(item):
                        name, _ = _native_child_name(item, parent, segment, collector, scope)
                        safe = _dms_safe_row(kind, item)
                        return collector.hydrate(safe, 'iamPolicy', root + '/' + name + ':getIamPolicy', scope,
                            params={'options.requestedPolicyVersion': 3})
                    parallel = getattr(collector, 'parallel', None)
                    page = parallel(dms_policy, page) if callable(parallel) else [dms_policy(item) for item in page]
                if kind in NCC_KINDS:
                    def ncc_policy(item):
                        name, _ = _native_child_name(item, parent, segment, collector, scope)
                        return collector.hydrate(item, 'iamPolicy', root + '/' + name + ':getIamPolicy', scope,
                            params={'options.requestedPolicyVersion': 3})
                    parallel = getattr(collector, 'parallel', None)
                    page = parallel(ncc_policy, page) if callable(parallel) else [ncc_policy(item) for item in page]
                if kind == 'netapp_volume':
                    def netapp_volume(item):
                        name, _ = _native_child_name(item, parent, segment, collector, scope)
                        safe = _netapp_safe_volume(item)
                        replications = []
                        for rows, _ in collector.pages(root + '/' + name + '/replications', scope,
                                key='replications'):
                            replications.extend({key: row[key] for key in ('name', 'state', 'role', 'mirrorState',
                                'sourceVolume', 'destinationVolume', 'hybridReplicationType', 'healthy') if key in row}
                                for row in rows)
                        safe['replications'] = replications
                        return safe
                    parallel = getattr(collector, 'parallel', None)
                    page = parallel(netapp_volume, page) if callable(parallel) else [netapp_volume(item) for item in page]
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


def pubsub_topic_attachments(collector, scope):
    """Read the names of subscriptions attached to each owned Pub/Sub topic."""
    base = f"https://pubsub.googleapis.com/v1/{scope}/topics"
    for topics, receipt in collector.pages(base, scope, key="topics"):
        yield [], receipt
        def attachments(topic):
            name = topic.get("name")
            if not isinstance(name, str) or not re.fullmatch(re.escape(scope) + r"/topics/[^/]+", name):
                raise ReadError("malformed", "pubsub_topic_attachment_identity")
            url = f"https://pubsub.googleapis.com/v1/{name}/subscriptions"
            names, receipts, seen = [], [], set()
            params = {"pageSize": min(collector.page_size, 1000)}
            try:
                for page in count():
                    response, request_id = collector.read(url, scope, params=params)
                    receipts.append(request_id)
                    if not isinstance(response, dict) or not isinstance(response.get("subscriptions", []), list):
                        raise ReadError("malformed", "pubsub_topic_attachment_response")
                    values = response.get("subscriptions", [])
                    if any(not isinstance(value, str) or not re.fullmatch(
                            r"projects/[^/]+/subscriptions/[^/]+", value) for value in values):
                        raise ReadError("malformed", "pubsub_topic_attachment_name")
                    names.extend(values)
                    token = response.get("nextPageToken")
                    if token is None or token == "":
                        break
                    if not isinstance(token, str) or token in seen:
                        raise ReadError("malformed", "pubsub_topic_attachment_page_token")
                    if collector.max_pages is not None and page + 1 >= collector.max_pages:
                        raise ReadError("unavailable", "page_limit")
                    seen.add(token)
                    params["pageToken"] = token
            except ReadError as exc:
                refs = [*receipts, *([exc.request_id] if getattr(exc, "request_id", None) else [])]
                return {"name": name, "_coverage": {"attachedSubscriptions": {
                    "status": exc.status, "error": exc.error, "source_requests": sorted(set(refs))}}}, receipt
            return {"name": name, "attachedSubscriptions": sorted(set(names)),
                    "_coverage": {"attachedSubscriptions": {"status": "collected", "source_requests": receipts}}}, receipt
        parallel = getattr(collector, "parallel", None)
        rows = parallel(attachments, topics) if callable(parallel) else [attachments(topic) for topic in topics]
        for row, row_receipt in rows:
            yield [row], row_receipt


def pubsub_schema_policies(collector, scope):
    """Search directly attached schema IAM policies without reading definitions."""
    url = f"https://cloudasset.googleapis.com/v1/{scope}:searchAllIamPolicies"
    for policies, receipt in collector.pages(url, scope, key="results",
            params={"assetTypes": ["pubsub.googleapis.com/Schema"]}):
        rows = []
        for entry in policies:
            resource, policy = entry.get("resource"), entry.get("policy")
            prefix = "//pubsub.googleapis.com/"
            if (entry.get("assetType") != "pubsub.googleapis.com/Schema" or
                    not isinstance(resource, str) or not resource.startswith(prefix) or
                    not re.fullmatch(r"projects/[^/]+/schemas/[^/]+", resource[len(prefix):]) or
                    not isinstance(policy, dict) or not isinstance(policy.get("bindings", []), list)):
                raise ReadError("malformed", "pubsub_schema_policy_search_result")
            rows.append({"name": resource[len(prefix):], "iamPolicy": policy,
                "_coverage": {"iamPolicy": {"status": "collected", "source_requests": [receipt]}}})
        yield rows, receipt


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
    """Enumerate record identities; retain bounded public routing facts only.

    TXT record bodies are not requested. HTTPS/SVCB service parameters are
    discarded before snapshot storage. Private PSC evidence has its own reader.
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
                    if rtype not in {"A", "AAAA", "CNAME", "ALIAS", "NS", "PTR", "MX", "SRV", "HTTPS", "SVCB"}:
                        yield [dict(row, _coverage={"rrdatas": {"status": "not_collected", "reason": "non_address_record_body_omitted"}})], record_receipt
                        continue
                    try:
                        found = False
                        def bounded(item):
                            if rtype not in {"HTTPS", "SVCB"}:
                                return item
                            values = item.get("rrdatas")
                            if not isinstance(values, list):
                                return item
                            # Service parameters can contain arbitrary values. A
                            # priority and target name suffice for routing review.
                            return {**item, "rrdatas": [" ".join(value.split()[:2]) if isinstance(value, str)
                                                          else "" for value in values]}
                        fields = ("rrsets(name,type,ttl,rrdatas,routingPolicy),nextPageToken"
                                  if rtype in {"A", "AAAA"} else "rrsets(name,type,ttl,rrdatas),nextPageToken")
                        for details, detail_receipt in collector.pages(endpoint, scope, key="rrsets", page_size_key="maxResults",
                                params={"name": host, "type": rtype, "fields": fields}, transform=bounded):
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


def apigee_routes(collector, scope):
    base = 'https://apigee.googleapis.com/v1/organizations'
    project = scope.removeprefix('projects/')
    for organizations, receipt in collector.pages(base, scope, key='organizations', page_size_key=None,
            params={'fields': 'organizations(organization,projectId,projectIds)'}):
        yield [], receipt
        for organization in organizations:
            if organization.get('projectId') != project and project not in organization.get('projectIds', []):
                continue
            org = organization.get('organization')
            if not isinstance(org, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', org):
                raise ReadError('malformed', 'apigee_organization_identity')
            endpoint = base + '/' + org
            hosts = {}
            for groups, group_receipt in collector.pages(endpoint + '/envgroups', scope, key='environmentGroups',
                    params={'fields': 'environmentGroups(name,hostnames,state),nextPageToken'}):
                yield [], group_receipt
                for group in groups:
                    group_name = group.get('name')
                    if not isinstance(group_name, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', group_name):
                        raise ReadError('malformed', 'apigee_envgroup_identity')
                    if group.get('state') != 'ACTIVE':
                        continue
                    names = group.get('hostnames', [])
                    if not isinstance(names, list) or any(not isinstance(x, str) or
                            not re.fullmatch(r'[A-Za-z0-9.-]+', x) for x in names):
                        raise ReadError('malformed', 'apigee_envgroup_hostname')
                    for attachments, attachment_receipt in collector.pages(
                            endpoint + '/envgroups/' + group_name + '/attachments', scope,
                            key='environmentGroupAttachments', params={'fields': 'environmentGroupAttachments(environment),nextPageToken'}):
                        yield [], attachment_receipt
                        for attachment in attachments:
                            env = attachment.get('environment')
                            if not isinstance(env, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+', env):
                                raise ReadError('malformed', 'apigee_attachment_environment')
                            hosts.setdefault(env, set()).update(names)
            for deployments, deployment_receipt in collector.pages(endpoint + '/deployments', scope,
                    key='deployments', page_size_key=None):
                yield [], deployment_receipt
                for deployment in deployments:
                    env, proxy = deployment.get('environment'), deployment.get('apiProxy')
                    if any(not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+', value)
                           for value in (env, proxy)):
                        raise ReadError('malformed', 'apigee_deployment_identity')
                    name = f'organizations/{org}/environments/{env}/deployments/{proxy}'
                    for details, detail_receipt in collector.pages('https://apigee.googleapis.com/v1/' + name,
                            scope, single=True, params={'fields': 'environment,apiProxy,revision,state,instances(deployedRoutes(envgroup,percentage))'}):
                        detail = details[0]
                        if detail.get('environment') != env or detail.get('apiProxy') != proxy:
                            raise ReadError('malformed', 'apigee_deployment_detail_identity')
                        groups = {route.get('envgroup') for instance in detail.get('instances', [])
                                  if isinstance(instance, dict) for route in instance.get('deployedRoutes', [])
                                  if isinstance(route, dict) and route.get('percentage', 0) > 0}
                        row = {'name': name, 'state': detail.get('state'), 'revision': detail.get('revision'),
                               'hostnames': sorted(hosts.get(env, set())),
                               'deployedEnvgroups': sorted(group for group in groups if isinstance(group, str))}
                        row = collector.hydrate(row, 'iamPolicy',
                            'https://apigee.googleapis.com/v1/' + name + ':getIamPolicy', scope,
                            params={'options.requestedPolicyVersion': 3})
                        yield [row], detail_receipt


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
        params={"fields": "name,signIn(anonymous(enabled),email(enabled),phoneNumber(enabled)),client(permissions(disabledUserSignup))"})


def containeranalysis_occurrences(collector, scope):
    """Read occurrence identities and direct IAM, omitting occurrence content."""
    root = 'https://containeranalysis.googleapis.com/v1/'

    def occurrence_pages(parent):
        for page, receipt in collector.pages(root + parent + '/occurrences', scope,
                key='occurrences', params={'fields': 'occurrences(name),nextPageToken'}):
            def policy(item):
                name, _ = _native_child_name(item, parent, 'occurrences', collector, scope)
                projected = {'name': name, '_representation': 'full'}
                return collector.hydrate(projected, 'iamPolicy', root + name + ':getIamPolicy', scope,
                    method='POST', body={'options': {'requestedPolicyVersion': 3}})
            yield collector.parallel(policy, page), receipt

    yield from occurrence_pages(scope)
    selected = collector.options.get('containeranalysis_locations', collector.options.get('regions'))
    if selected is None:
        selected = []
        for page, receipt in collector.pages(
                'https://artifactregistry.googleapis.com/v1/' + scope + '/locations', scope,
                key='locations', params={'fields': 'locations(name,locationId),nextPageToken'}):
            selected.extend(item.get('locationId') or item['name'].rsplit('/', 1)[-1] for item in page)
            yield [], receipt
    if (not isinstance(selected, list) or len(selected) > 100 or
            any(not isinstance(value, str) or not re.fullmatch(r'[a-z0-9-]+', value)
                for value in selected)):
        raise ValueError('containeranalysis_locations must contain at most 100 location names')
    failures = []
    for _location, pages, exc in location_fanout(collector, dict.fromkeys(selected),
            lambda location: occurrence_pages(scope + '/locations/' + location)):
        yield from pages
        if exc is not None:
            failures.append(exc)
    if failures:
        raise failures[0]


def api_gateway_resources(collector, scope):
    """Read global API and API-config policies without retaining uploaded specs."""
    root = 'https://apigateway.googleapis.com/v1/'
    parent = scope + '/locations/global'
    def complete(data):
        if data.get('unreachableLocations'):
            raise ReadError('unavailable', 'api_gateway_unreachable_locations')
    for apis, receipt in collector.pages(root + parent + '/apis', scope,
            key='apis', params={'fields': 'apis(name),nextPageToken,unreachableLocations'},
            response_validator=complete):
        def api_rows(api):
            name, _ = _native_child_name(api, parent, 'apis', collector, scope)
            policy = collector.hydrate({'name': name, '_representation': 'full'}, 'iamPolicy',
                root + name + ':getIamPolicy', scope, params={'options.requestedPolicyVersion': 3})
            return name, policy
        resolved = collector.parallel(api_rows, apis)
        yield [row for _, row in resolved], receipt
        for name, _ in resolved:
            for configs, config_receipt in collector.pages(root + name + '/configs', scope,
                    key='apiConfigs', params={'fields': 'apiConfigs(name),nextPageToken,unreachableLocations'},
                    response_validator=complete):
                def config_policy(config):
                    config_name, _ = _native_child_name(config, name, 'configs', collector, scope)
                    return collector.hydrate({'name': config_name, '_representation': 'full'}, 'iamPolicy',
                        root + config_name + ':getIamPolicy', scope,
                        params={'options.requestedPolicyVersion': 3})
                yield collector.parallel(config_policy, configs), config_receipt


def cloudtasks_deliveries(collector, scope):
    """List BASIC tasks and keep only queue identity, public-origin inputs, and auth mode."""
    root = 'https://cloudtasks.googleapis.com/v2/'
    selected = collector.options.get('cloudtasks_locations', collector.options.get('regions'))
    if selected is None:
        selected = []
        for page, receipt in collector.pages(root + scope + '/locations', scope, key='locations',
                params={'fields': 'locations(name,locationId),nextPageToken'}):
            selected.extend(item.get('locationId') or item['name'].rsplit('/', 1)[-1] for item in page)
            yield [], receipt
    if (not isinstance(selected, list) or len(selected) > 100 or
            any(not isinstance(value, str) or not re.fullmatch(r'[a-z0-9-]+', value)
                for value in selected)):
        raise ValueError('cloudtasks_locations must contain at most 100 location names')

    def origin(url):
        if not isinstance(url, str):
            return None
        try:
            parsed = urlsplit(url)
            if (parsed.scheme not in ('http', 'https') or not parsed.hostname or
                    parsed.username or parsed.password or
                    parsed.port is not None and not 1 <= parsed.port <= 65535):
                return None
        except ValueError:
            return None
        host = f'[{parsed.hostname.lower()}]' if ':' in parsed.hostname else parsed.hostname.lower()
        return parsed.scheme + '://' + host + (f':{parsed.port}' if parsed.port else '')

    def location_pages(location):
        parent = scope + '/locations/' + location
        for queues, receipt in collector.pages(root + parent + '/queues', scope, key='queues',
                params={'fields': 'queues(name,state,httpTarget(uriOverride(scheme,host,port,uriOverrideEnforceMode),oidcToken(serviceAccountEmail),oauthToken(serviceAccountEmail))),nextPageToken'}):
            for queue in queues:
                name, _ = _native_child_name(queue, parent, 'queues', collector, scope)
                target = queue.get('httpTarget') if isinstance(queue.get('httpTarget'), dict) else {}
                override = target.get('uriOverride') if isinstance(target.get('uriOverride'), dict) else {}
                host = override.get('host')
                scheme = 'http' if override.get('scheme') == 'HTTP' else 'https'
                port = override.get('port')
                override_origin = origin(scheme + '://' + host + (':' + str(port) if port not in (None, '', '0') else '')) if isinstance(host, str) else None
                auth = 'oidc' if isinstance(target.get('oidcToken'), dict) else 'oauth' if isinstance(target.get('oauthToken'), dict) else 'none'
                if override_origin:
                    yield [{'name': name + '/deliveryOverride', 'queue': name, 'queueState': queue.get('state'),
                            'targetOrigin': override_origin, 'deliveryKind': 'queue_override',
                            'overrideMode': override.get('uriOverrideEnforceMode') or 'ALWAYS',
                            'authentication': auth, '_representation': 'full'}], receipt
                for tasks, task_receipt in collector.pages(root + name + '/tasks', scope, key='tasks',
                        params={'responseView': 'BASIC', 'fields': 'tasks(name,httpRequest(url,oidcToken(serviceAccountEmail),oauthToken(serviceAccountEmail))),nextPageToken'}):
                    projected = []
                    for task in tasks:
                        task_name, _ = _native_child_name(task, name, 'tasks', collector, scope)
                        request = task.get('httpRequest') if isinstance(task.get('httpRequest'), dict) else None
                        if request is None:
                            continue  # App Engine tasks route within the queue's project.
                        task_origin = origin(request.get('url'))
                        mode = override.get('uriOverrideEnforceMode') or 'ALWAYS'
                        effective = override_origin if override_origin and mode != 'IF_NOT_EXISTS' else task_origin
                        task_auth = (auth if auth != 'none' else
                            'oidc' if isinstance(request.get('oidcToken'), dict) else
                            'oauth' if isinstance(request.get('oauthToken'), dict) else 'none')
                        projected.append({'name': task_name, 'queue': name, 'queueState': queue.get('state'),
                            'targetOrigin': effective, 'deliveryKind': 'task', 'authentication': task_auth,
                            '_representation': 'full'})
                    yield projected, task_receipt

    failures = []
    for _location, pages, exc in location_fanout(collector, dict.fromkeys(selected), location_pages):
        yield from pages
        if exc is not None:
            failures.append(exc)
    if failures:
        raise failures[0]


def binary_authorization_policy(collector, scope):
    """Keep admission rule trust references, excluding whitelist image patterns."""
    endpoint = f'https://binaryauthorization.googleapis.com/v1/{scope}/policy'
    fields = ('name,defaultAdmissionRule(evaluationMode,enforcementMode,requireAttestationsBy),'
        'clusterAdmissionRules,kubernetesNamespaceAdmissionRules,'
        'kubernetesServiceAccountAdmissionRules,istioServiceIdentityAdmissionRules')
    for rows, request_id in collector.pages(endpoint, scope, single=True, params={'fields': fields}):
        safe_rows = []
        for row in rows:
            safe = {'name': row.get('name', scope + '/policy')}
            for field in ('defaultAdmissionRule', 'clusterAdmissionRules',
                          'kubernetesNamespaceAdmissionRules', 'kubernetesServiceAccountAdmissionRules',
                          'istioServiceIdentityAdmissionRules'):
                value = row.get(field)
                if field == 'defaultAdmissionRule' and isinstance(value, dict):
                    safe[field] = {key: value[key] for key in ('evaluationMode', 'enforcementMode',
                        'requireAttestationsBy') if key in value}
                elif isinstance(value, dict):
                    safe[field] = {name: {key: rule[key] for key in ('evaluationMode', 'enforcementMode',
                        'requireAttestationsBy') if key in rule} for name, rule in value.items()
                        if isinstance(rule, dict)}
            safe_rows.append(safe)
        yield safe_rows, request_id


def binary_authorization_platform_policies(collector, scope):
    """Project only projects that can supply platform-policy attestations."""
    endpoint = f'https://binaryauthorization.googleapis.com/v1/{scope}/platforms/gke/policies'
    for rows, request_id in collector.pages(endpoint, scope, key='platformPolicies'):
        safe_rows = []
        for row in rows:
            trusted = []
            gke = row.get('gkePolicy')
            for set_index, check_set in enumerate((gke.get('checkSets') or []) if isinstance(gke, dict) else []):
                if not isinstance(check_set, dict):
                    continue
                for check_index, check in enumerate(check_set.get('checks') or []):
                    if not isinstance(check, dict):
                        continue
                    for check_type in ('simpleSigningAttestationCheck', 'vulnerabilityCheck'):
                        details = check.get(check_type)
                        if isinstance(details, dict):
                            field = ('containerAnalysisAttestationProjects' if check_type == 'simpleSigningAttestationCheck'
                                     else 'containerAnalysisVulnerabilityProjects')
                            trusted.extend({'project': project, 'checkType': check_type,
                                'checkSetIndex': set_index, 'checkIndex': check_index}
                                for project in (details.get(field) or []) if isinstance(project, str))
                    slsa = check.get('slsaCheck')
                    if isinstance(slsa, dict):
                        for rule in slsa.get('rules') or []:
                            source = rule.get('attestationSource') if isinstance(rule, dict) else None
                            if isinstance(source, dict):
                                trusted.extend({'project': project, 'checkType': 'slsaCheck',
                                    'checkSetIndex': set_index, 'checkIndex': check_index}
                                    for project in source.get('containerAnalysisAttestationProjects') or []
                                    if isinstance(project, str))
            safe_rows.append({'name': row.get('name'), 'trustedProjects': trusted})
        yield safe_rows, request_id


def scope_jobs(collector, scope):
    scope_kind = scope.split('/', 1)[0]
    if scope_kind not in {'projects', 'organizations'}:
        return []
    jobs = [(kind, scope, spec[0], lambda kind=kind: regional_pages(collector, scope, kind))
            for kind, spec in REGIONAL.items() if kind in collector.needed and kind != 'dlp_exposure'
            and PRIVATE_SERVICES.get(kind, {}).get('scope_kind', 'projects') == scope_kind]
    if 'dlp_exposure' in collector.needed:
        from .gcp_dlp_exposure import collection_pages
        jobs.append(('dlp_exposure', scope, 'dlp', lambda: collection_pages(collector, scope)))
    if scope_kind == 'projects' and 'service_extension_exposure' in collector.needed:
        from .gcp_service_extensions_exposure import collection_pages as service_extension_pages
        jobs.append(('service_extension_exposure', scope, 'networkservices',
                     lambda: service_extension_pages(collector, scope)))
    if scope_kind == 'projects' and 'model_armor_exposure' in collector.needed:
        from .gcp_model_armor_exposure import collection_pages as model_armor_pages
        jobs.append(('model_armor_exposure', scope, 'modelarmor',
                     lambda: model_armor_pages(collector, scope)))
    if scope_kind == 'projects' and 'multicloud_exposure' in collector.needed:
        from .gcp_multicloud_exposure import collection_pages as multicloud_pages
        jobs.append(('multicloud_exposure', scope, 'gkemulticloud',
                     lambda: multicloud_pages(collector, scope)))
    if scope_kind == 'projects' and 'sac_exposure' in collector.needed:
        from .gcp_sac_exposure import collection_pages as sac_pages
        jobs.append(('sac_exposure', scope, 'networksecurity',
                     lambda: sac_pages(collector, scope)))
    if scope_kind == 'projects' and 'fraud_defense_exposure' in collector.needed:
        from .gcp_fraud_defense_exposure import collection_pages as fraud_defense_pages
        jobs.append(('fraud_defense_exposure', scope, 'recaptchaenterprise',
                     lambda: fraud_defense_pages(collector, scope)))
    if scope_kind == 'organizations' and 'sovereign_partner_exposure' in collector.needed:
        from .gcp_sovereign_partner_exposure import collection_pages as sovereign_partner_pages
        jobs.append(('sovereign_partner_exposure', scope, 'assuredworkloads',
                     lambda: sovereign_partner_pages(collector, scope)))
    if scope_kind != 'projects':
        return jobs
    if 'containeranalysis_occurrence' in collector.needed:
        jobs.append(('containeranalysis_occurrence', scope, 'containeranalysis',
            lambda: containeranalysis_occurrences(collector, scope)))
    if 'api_gateway_resource' in collector.needed:
        jobs.append(('api_gateway_resource', scope, 'apigateway',
            lambda: api_gateway_resources(collector, scope)))
    if 'cloudtasks_delivery' in collector.needed:
        jobs.append(('cloudtasks_delivery', scope, 'cloudtasks',
            lambda: cloudtasks_deliveries(collector, scope)))
    if 'dialogflow_es_fulfillment' in collector.needed:
        jobs.append(('dialogflow_es_fulfillment', scope, 'dialogflow',
            lambda: dialogflow_es_fulfillments(collector, scope)))
    if 'lakehouse_resource' in collector.needed:
        jobs.append(('lakehouse_resource', scope, 'biglake',
            lambda: lakehouse_resources(collector, scope)))
    if 'apigee_route' in collector.needed:
        jobs.append(('apigee_route', scope, 'apigee',
            lambda: apigee_routes(collector, scope)))
    if 'pubsub_topic_attachment' in collector.needed:
        jobs.append(('pubsub_topic_attachment', scope, 'pubsub',
            lambda: pubsub_topic_attachments(collector, scope)))
    if 'pubsub_schema_iam' in collector.needed:
        jobs.append(('pubsub_schema_iam', scope, 'cloudasset',
            lambda: pubsub_schema_policies(collector, scope)))
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
    if 'binary_authorization_policy' in collector.needed:
        jobs.append(('binary_authorization_policy', scope, 'binaryauthorization',
            lambda: binary_authorization_policy(collector, scope)))
    if 'binary_authorization_platform_policy' in collector.needed:
        jobs.append(('binary_authorization_platform_policy', scope, 'binaryauthorization',
            lambda: binary_authorization_platform_policies(collector, scope)))
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
        def ncc_hubs():
            root = 'https://networkconnectivity.googleapis.com/v1'
            parent = f'{scope}/locations/global'
            for hubs, request_id in collector.pages(f'{root}/{parent}/hubs', scope, key='hubs'):
                def with_spokes(hub):
                    name, _ = _native_child_name(hub, parent, 'hubs', collector, scope)
                    spokes = []
                    for rows, _ in collector.pages(f'{root}/{name}:listSpokes', scope, key='spokes'):
                        spokes.extend({key: row[key] for key in ('name', 'hub', 'state', 'spokeType')
                                       if key in row} for row in rows)
                    safe = {key: hub[key] for key in ('name', 'state', 'policyMode', 'presetTopology',
                            'exportPsc', 'routingVpcs') if key in hub}
                    safe['attachedSpokes'] = spokes
                    return collector.hydrate(safe, 'iamPolicy', f'{root}/{name}:getIamPolicy', scope,
                        params={'options.requestedPolicyVersion': 3})
                yield collector.parallel(with_spokes, hubs), request_id
        jobs.append(("network_connectivity_hub", scope, "networkconnectivity", ncc_hubs))
    return jobs
