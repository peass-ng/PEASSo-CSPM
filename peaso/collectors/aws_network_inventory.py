"""Reviewed native VPC workloads found by the complete AWS API shape audit.

Only the operations in the adjacent manifest can run. Projection happens inside
our SDK client, before the common scheduler retains a response in its cache.
Parent discovery, native pagination and detail failures retain coverage gaps.
"""
import json
from pathlib import Path

PLANS = json.loads(Path(__file__).with_suffix('.json').read_text())
SPECS = {kind: (p['service'], p['operation'], p['key']) for kind, p in PLANS.items()}
NATIVE_IDS = dict.fromkeys(PLANS, 'NetworkResourceId')
READS = {}
READ_IDENTITIES = {}
DETAIL_ENRICHERS = {
    'dsql_cluster': {'service': 'dsql', 'operation': 'get_cluster', 'key': None,
        'arguments': {'identifier': 'identifier'}},
    'mskconnect_connector': {'service': 'kafkaconnect', 'operation': 'describe_connector', 'key': None,
        'arguments': {'connectorArn': 'connectorArn'}},
    'quicksight_vpc_connection': {'service': 'quicksight', 'operation': 'describe_vpc_connection', 'key': 'VPCConnection',
        'arguments': {'AwsAccountId': 'NetworkAccountId', 'VPCConnectionId': 'VPCConnectionId'}},
    'storagegateway_gateway': {'service': 'storagegateway', 'operation': 'describe_vtl_devices', 'key': None,
        'arguments': {'GatewayARN': 'GatewayARN'}, 'tokens': ['Marker', 'Marker']},
}
for plan in PLANS.values():
    for step in [*plan.get('parents', []), plan, *([plan['detail']] if 'detail' in plan else [])]:
        identity = (plan['service'], step['operation'])
        if identity in READS and READS[identity] != step['key']:
            raise ValueError('Conflicting network API response roots')
        READS[identity] = step['key']
        # identity_fields compose the resource id; retained_fields are only
        # kept through metadata projection for downstream evaluation.
        READ_IDENTITIES.setdefault(identity, set()).update([plan['identity'], *plan.get('identity_fields', []),
            *plan.get('retained_fields', []),
            *step.get('exports', {}).values(), *plan.get('detail', {}).get('arguments', {}).values()])
READS.update({(plan['service'], plan['operation']): plan['key'] for plan in DETAIL_ENRICHERS.values()})
READS['ec2', 'describe_vpc_attribute'] = None
READS['sns', 'list_platform_applications'] = 'PlatformApplications'
READS['sns', 'list_endpoints_by_platform_application'] = 'Endpoints'
READS['mailmanager', 'get_rule_set'] = None
READS['mailmanager', 'get_relay'] = None
READS['mediapackagev2', 'get_channel'] = None
READS['mediapackagev2', 'list_harvest_jobs'] = 'Items'
READ_IDENTITIES['mailmanager', 'get_rule_set'] = {'RuleSetId', 'RuleSetArn'}
READ_IDENTITIES['mailmanager', 'get_relay'] = {'RelayId', 'RelayArn'}
READ_IDENTITIES['mediapackagev2', 'get_channel'] = {'Arn', 'ChannelGroupName', 'ChannelName'}
READS['opensearchserverless', 'batch_get_collection'] = None
READ_IDENTITIES['opensearchserverless', 'batch_get_collection'] = {'id', 'name', 'arn', 'status'}
READS['mq', 'describe_shared_resources'] = 'SharedResources'
READ_IDENTITIES['mq', 'describe_shared_resources'] = {'ResourceArn', 'Status', 'Type'}
READS['mq', 'describe_configuration_revision'] = None
READS['opensearch', 'list_applications'] = 'ApplicationSummaries'
READS['opensearch', 'get_application'] = None
READS['opensearch', 'list_vpc_endpoint_access'] = 'AuthorizedPrincipalList'
READS['securitylake', 'list_subscribers'] = 'subscribers'
READS['securitylake', 'get_data_lake_exception_subscription'] = None
for _operation, _root in (("list_memberships", "items"), ("list_cases", "items"),
                          ("get_membership", None), ("get_case", None)):
    READS['security-ir', _operation] = _root
READ_ACTIONS = set(READS)
GLOBAL_TYPES = {'cloudwan_vpc_attachment', 'cloudwan_connect_peer', 'cloudwan_device'}


class MetadataClient:
    def __init__(self, native, service):
        self.native, self.service = native, service

    def __getattr__(self, operation):
        native = getattr(self.native, operation)
        if (self.service, operation) not in READS:
            return native
        root = READS[self.service, operation]
        def read(**arguments):
            from .aws_content_sdk_logging import private_sdk_logs
            from peaso.analysis.network_observations import projected_metadata
            if (self.service, operation) == ('mailmanager', 'get_ingress_point'):
                arguments = {**arguments, 'IncludeTrustStoreContents': 'EXCLUDE'}
            with private_sdk_logs():
                response = native(**arguments)
            if not isinstance(response, dict):
                return {}  # Normal response validation records malformed coverage.
            if (self.service, operation) == ('machinelearning', 'describe_ml_models'):
                from urllib.parse import urlsplit
                models = response.get('Results')
                if not isinstance(models, list) or any(not isinstance(row, dict) for row in models):
                    return {}
                selected = []
                for row in models:
                    endpoint = row.get('EndpointInfo')
                    if not isinstance(endpoint, dict):
                        endpoint = {}
                    url = endpoint.get('EndpointUrl')
                    host = None
                    if isinstance(url, str):
                        try:
                            parsed = urlsplit(url)
                            if (parsed.scheme == 'https' and parsed.hostname and
                                    parsed.port in (None, 443) and not parsed.username and not parsed.password):
                                host = parsed.hostname.lower()
                        except ValueError:
                            pass
                    selected.append({'MLModelId': row.get('MLModelId'),
                                     'EndpointStatus': endpoint.get('EndpointStatus'),
                                     'EndpointHost': host})
                token = response.get('NextToken')
                return {'Results': selected, **({'NextToken': token} if isinstance(token, str) else {})}
            if (self.service, operation) == ('securitylake', 'get_data_lake_exception_subscription'):
                from urllib.parse import urlsplit
                protocol, endpoint = response.get('subscriptionProtocol'), response.get('notificationEndpoint')
                row = {'Protocol': protocol if isinstance(protocol, str) else None}
                if not isinstance(endpoint, str) or not endpoint:
                    row['DestinationType'] = 'UNKNOWN'
                elif endpoint.startswith('arn:'):
                    row['DestinationType'], row['Destination'] = 'AWS_RESOURCE', endpoint
                elif '@' in endpoint and endpoint.count('@') == 1:
                    local, domain = endpoint.rsplit('@', 1)
                    row['DestinationType'] = 'EMAIL' if local and domain and '.' in domain else 'UNKNOWN'
                    if row['DestinationType'] == 'EMAIL':
                        row['Destination'] = domain.lower()
                elif endpoint.startswith('https://'):
                    try:
                        parsed = urlsplit(endpoint)
                        valid = parsed.hostname and parsed.port in (None, 443) and not parsed.username and not parsed.password
                    except ValueError:
                        valid = False
                    row['DestinationType'] = 'HTTPS' if valid else 'UNKNOWN'
                    if valid:
                        row['Destination'] = parsed.hostname.lower()
                elif endpoint.replace('+', '').isdigit():
                    row['DestinationType'] = 'PHONE'
                else:
                    row['DestinationType'] = 'UNKNOWN'
                return row
            if (self.service, operation) == ('securitylake', 'list_subscribers'):
                from urllib.parse import urlsplit
                subscribers = response.get('subscribers')
                if not isinstance(subscribers, list) or any(not isinstance(x, dict) for x in subscribers):
                    return {}
                selected = []
                for entry in subscribers:
                    identity = entry.get('subscriberIdentity')
                    access = entry.get('accessTypes')
                    sources = entry.get('sources')
                    endpoint = entry.get('subscriberEndpoint')
                    row = {key: entry[key] for key in
                           ('subscriberArn', 'subscriberId', 'subscriberStatus', 'roleArn',
                            'resourceShareArn', 's3BucketArn') if isinstance(entry.get(key), str)}
                    row['Principal'] = identity.get('principal') if isinstance(identity, dict) and isinstance(identity.get('principal'), str) else None
                    row['AccessTypes'] = sorted(set(access)) if isinstance(access, list) and all(isinstance(x, str) for x in access) else None
                    row['SourceCount'] = len(sources) if isinstance(sources, list) else None
                    if not endpoint:
                        row['NotificationType'] = 'NONE'
                    elif isinstance(endpoint, str) and endpoint.startswith('arn:'):
                        row['NotificationType'] = 'AWS_RESOURCE'
                        row['NotificationTarget'] = endpoint
                    elif isinstance(endpoint, str):
                        try:
                            parsed = urlsplit(endpoint)
                            valid = (parsed.scheme == 'https' and parsed.hostname and
                                     parsed.port in (None, 443) and not parsed.username and not parsed.password)
                        except ValueError:
                            valid = False
                        row['NotificationType'] = 'HTTPS' if valid else 'UNKNOWN'
                        if valid:
                            row['NotificationTarget'] = parsed.hostname.lower()
                    else:
                        row['NotificationType'] = 'UNKNOWN'
                    selected.append(row)
                token = response.get('nextToken')
                return {'subscribers': selected, **({'nextToken': token} if isinstance(token, str) else {})}
            if self.service == 'opensearch' and operation in (
                    'list_applications', 'get_application', 'list_vpc_endpoint_access'):
                from urllib.parse import urlsplit
                def host(value):
                    if not isinstance(value, str):
                        return None
                    try:
                        parsed = urlsplit(value)
                        return (parsed.hostname.lower() if parsed.scheme == 'https' and parsed.hostname and
                                parsed.port in (None, 443) and not parsed.username and not parsed.password else None)
                    except ValueError:
                        return None
                if operation == 'list_vpc_endpoint_access':
                    principals = response.get('AuthorizedPrincipalList')
                    if not isinstance(principals, list) or any(not isinstance(x, dict) for x in principals):
                        return {}
                    selected = [{key: entry[key] for key in ('PrincipalType', 'Principal')
                                 if isinstance(entry.get(key), str)} for entry in principals]
                    token = response.get('NextToken')
                    return {'AuthorizedPrincipalList': selected,
                            **({'NextToken': token} if isinstance(token, str) else {})}
                if operation == 'list_applications':
                    applications = response.get('ApplicationSummaries')
                    if not isinstance(applications, list) or any(not isinstance(x, dict) for x in applications):
                        return {}
                    selected = []
                    for row in applications:
                        item = {key: row[key] for key in ('id', 'arn', 'status')
                                if isinstance(row.get(key), str)}
                        item['EndpointHost'] = host(row.get('endpoint'))
                        selected.append(item)
                    token = response.get('nextToken')
                    return {'ApplicationSummaries': selected,
                            **({'nextToken': token} if isinstance(token, str) else {})}
                row = {key: response[key] for key in ('id', 'arn', 'status')
                       if isinstance(response.get(key), str)}
                row['EndpointHost'] = host(response.get('endpoint'))
                sources = response.get('dataSources')
                row['DataSources'] = ([{key: item[key] for key in ('dataSourceArn', 'iamRoleForDataSourceArn')
                                        if isinstance(item.get(key), str)} for item in sources]
                                      if isinstance(sources, list) and all(isinstance(item, dict) for item in sources)
                                      else None)
                configs = response.get('appConfigs')
                admins, complete = [], isinstance(configs, list)
                if complete:
                    for config in configs:
                        if not isinstance(config, dict):
                            complete = False
                            break
                        if config.get('key') != 'opensearchDashboards.dashboardAdmin.groups':
                            continue
                        try:
                            values = json.loads(config.get('value'))
                        except (TypeError, ValueError):
                            complete = False
                            break
                        if not isinstance(values, list) or any(not isinstance(x, str) for x in values):
                            complete = False
                            break
                        admins.extend(values)
                row['AdminPrincipals'] = sorted(set(admins)) if complete else None
                return row
            if self.service == 'security-ir':
                from .aws_security_ir_recipients import project_recipients
                if operation in ('list_memberships', 'list_cases'):
                    selected_root = 'items'
                    items = response.get(selected_root)
                    if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
                        return {}
                    fields = (('membershipId', 'membershipArn', 'accountId', 'membershipStatus')
                              if operation == 'list_memberships' else ('caseId', 'caseArn', 'caseStatus'))
                    projected = [{key: item[key] for key in fields if isinstance(item.get(key), str)}
                                 for item in items]
                    token = response.get('nextToken')
                    return {selected_root: projected, **({'nextToken': token} if isinstance(token, str) else {})}
                recipients = project_recipients(response.get('incidentResponseTeam') if operation == 'get_membership'
                                                else response.get('watchers'))
                fields = (('membershipArn', 'membershipStatus') if operation == 'get_membership'
                          else ('caseArn', 'caseStatus'))
                projected = {key: response[key] for key in fields if isinstance(response.get(key), str)}
                projected['RecipientCoverage'] = 'collected' if recipients is not None else 'unresolved'
                if recipients is not None:
                    projected.update(recipients)
                return projected
            if (self.service, operation) == ('mq', 'describe_configuration_revision'):
                from .aws_mq_network_connectors import project_revision
                return project_revision(response)
            if (self.service, operation) == ('neptune-graph', 'list_graphs'):
                graphs = response.get('graphs')
                if not isinstance(graphs, list) or any(not isinstance(row, dict) for row in graphs):
                    return {}
                selected = [{key: row[key] for key in
                             ('id', 'arn', 'status', 'publicConnectivity', 'endpoint')
                             if key in row and isinstance(row[key], (str, bool))} for row in graphs]
                token = response.get('nextToken')
                return {'graphs': selected, **({'nextToken': token} if isinstance(token, str) else {})}
            if (self.service, operation) == ('oam', 'list_links'):
                links = response.get('Items')
                if not isinstance(links, list) or any(not isinstance(row, dict) for row in links):
                    return {}
                selected = []
                for row in links:
                    types = row.get('ResourceTypes')
                    if not isinstance(types, list) or any(not isinstance(item, str) for item in types):
                        return {}
                    selected.append({key: row[key] for key in ('Arn', 'SinkArn')
                                     if isinstance(row.get(key), str)} | {'ResourceTypes': types})
                token = response.get('NextToken')
                return {'Items': selected, **({'NextToken': token} if isinstance(token, str) else {})}
            if self.service == 'osis' and operation in ('list_pipeline_endpoints', 'list_pipeline_endpoint_connections'):
                selected_root = 'PipelineEndpoints' if operation == 'list_pipeline_endpoints' else 'PipelineEndpointConnections'
                items = response.get(selected_root)
                if not isinstance(items, list) or any(not isinstance(row, dict) for row in items):
                    return {}
                keys = ('EndpointId', 'PipelineArn', 'Status', 'VpcId') if operation == 'list_pipeline_endpoints' else (
                    'EndpointId', 'PipelineArn', 'Status', 'VpcEndpointOwner')
                selected = [{key: row[key] for key in keys if isinstance(row.get(key), str)} for row in items]
                token = response.get('NextToken')
                return {selected_root: selected, **({'NextToken': token} if isinstance(token, str) else {})}
            if self.service == 'opensearchserverless' and operation == 'batch_get_collection':
                from peaso.analysis.network_observations import safe_url
                details, errors = response.get('collectionDetails'), response.get('collectionErrorDetails', [])
                if not isinstance(details, list) or not isinstance(errors, list):
                    return {}
                projected = []
                for row in details:
                    if not isinstance(row, dict):
                        return {}
                    item = projected_metadata(row, identity_fields={'id', 'name', 'arn'})
                    for field in ('collectionEndpoint', 'dashboardEndpoint'):
                        if isinstance(row.get(field), str):
                            item[field] = safe_url(row[field])
                    projected.append(item)
                return {'collectionDetails': projected,
                        'collectionErrorDetails': [projected_metadata(row, identity_fields={'id', 'name'})
                                                   for row in errors if isinstance(row, dict)]}
            if (self.service, operation) == ('sns', 'list_platform_applications'):
                apps = response.get('PlatformApplications')
                if not isinstance(apps, list) or any(not isinstance(app, dict) or
                        not isinstance(app.get('PlatformApplicationArn'), str) for app in apps):
                    return {}
                token = response.get('NextToken')
                return {'PlatformApplications': [
                    {'PlatformApplicationArn': app['PlatformApplicationArn']} for app in apps],
                    **({'NextToken': token} if isinstance(token, str) else {})}
            if (self.service, operation) == ('sns', 'list_endpoints_by_platform_application'):
                endpoints = response.get('Endpoints')
                if not isinstance(endpoints, list):
                    return {}
                selected = []
                for endpoint in endpoints:
                    if not isinstance(endpoint, dict) or not isinstance(endpoint.get('EndpointArn'), str):
                        return {}
                    attributes = endpoint.get('Attributes')
                    if not isinstance(attributes, dict) or attributes.get('Enabled') not in ('true', 'false'):
                        return {}
                    selected.append({'EndpointArn': endpoint['EndpointArn'],
                                     'Enabled': attributes['Enabled'] == 'true'})
                token = response.get('NextToken')
                return {'Endpoints': selected, **({'NextToken': token} if isinstance(token, str) else {})}
            if (self.service, operation) == ('mailmanager', 'get_rule_set'):
                rules = response.get('Rules')
                if not isinstance(rules, list):
                    return {}
                def target(body, field):
                    value = body.get(field)
                    return value if isinstance(value, str) else None
                selected = []
                for rule in rules:
                    if not isinstance(rule, dict) or not isinstance(rule.get('Actions'), list):
                        return {}
                    actions = []
                    for action in rule['Actions']:
                        if not isinstance(action, dict):
                            return {}
                        relay = action.get('Relay')
                        if isinstance(relay, dict) and isinstance(relay.get('Relay'), str):
                            actions.append({'Type': 'Relay', 'RelayId': relay['Relay']})
                        elif isinstance(action.get('Send'), dict):
                            actions.append({'Type': 'Send'})
                        elif isinstance(action.get('Bounce'), dict):
                            actions.append({'Type': 'Bounce'})
                        elif isinstance(action.get('ReplaceRecipient'), dict):
                            actions.append({'Type': 'ReplaceRecipient'})
                        elif isinstance(action.get('Archive'), dict):
                            actions.append({'Type': 'Archive', 'ArchiveId': target(action['Archive'], 'TargetArchive')})
                        elif isinstance(action.get('WriteToS3'), dict):
                            actions.append({'Type': 'WriteToS3', 'S3Bucket': target(action['WriteToS3'], 'S3Bucket')})
                        elif isinstance(action.get('DeliverToMailbox'), dict):
                            actions.append({'Type': 'DeliverToMailbox', 'MailboxArn': target(action['DeliverToMailbox'], 'MailboxArn')})
                        elif isinstance(action.get('DeliverToQBusiness'), dict):
                            actions.append({'Type': 'DeliverToQBusiness',
                                            'ApplicationId': target(action['DeliverToQBusiness'], 'ApplicationId')})
                        elif isinstance(action.get('PublishToSns'), dict):
                            actions.append({'Type': 'PublishToSns', 'TopicArn': target(action['PublishToSns'], 'TopicArn')})
                        elif isinstance(action.get('InvokeLambda'), dict):
                            actions.append({'Type': 'InvokeLambda', 'FunctionArn': target(action['InvokeLambda'], 'FunctionArn')})
                        elif isinstance(action.get('Drop'), dict):
                            actions.append({'Type': 'Drop'})
                        elif isinstance(action.get('AddHeader'), dict):
                            actions.append({'Type': 'AddHeader'})
                        else:
                            actions.append({'Type': 'Unreviewed'})
                    selected.append({'Actions': actions})
                return {'RuleSetId': response.get('RuleSetId'), 'RuleSetArn': response.get('RuleSetArn'),
                        'Rules': selected}
            if (self.service, operation) == ('mailmanager', 'get_relay'):
                return {key: response[key] for key in ('RelayId', 'RelayArn', 'ServerName', 'ServerPort')
                        if key in response and isinstance(response[key], (str, int))}
            if (self.service, operation) == ('mediapackagev2', 'get_channel'):
                from .aws_mediapackagev2_exposure import endpoint_host
                endpoints = response.get('IngestEndpoints')
                if not isinstance(endpoints, list):
                    return {}
                hosts = [endpoint_host(item.get('Url')) for item in endpoints if isinstance(item, dict)]
                if len(hosts) != len(endpoints) or any(host is None for host in hosts):
                    return {}
                return {'Arn': response.get('Arn'), 'ChannelGroupName': response.get('ChannelGroupName'),
                        'ChannelName': response.get('ChannelName'), 'Hosts': hosts}
            if (self.service, operation) == ('mediapackagev2', 'list_harvest_jobs'):
                items = response.get('Items')
                if not isinstance(items, list):
                    return {}
                selected = []
                for item in items:
                    if not isinstance(item, dict):
                        return {}
                    destination = item.get('Destination')
                    s3 = destination.get('S3Destination') if isinstance(destination, dict) else None
                    if not isinstance(s3, dict):
                        return {}
                    facts = {key: item.get(key) for key in
                             ('Arn', 'ChannelGroupName', 'ChannelName', 'OriginEndpointName',
                              'HarvestJobName', 'Status')}
                    facts['BucketName'] = s3.get('BucketName')
                    if any(not isinstance(value, str) for value in facts.values()):
                        return {}
                    selected.append(facts)
                token = response.get('NextToken')
                return {'Items': selected, **({'NextToken': token} if isinstance(token, str) else {})}
            body = response.get(root) if root else response
            meta = getattr(self.native, 'meta', None)
            model = getattr(meta, 'service_model', None)
            if model is not None:
                from botocore import xform_name
                api_name = next((name for name in model.operation_names if xform_name(name) == operation), None)
                if api_name:
                    shape = model.operation_model(api_name).output_shape
                    shape = shape.members.get(root) if root and shape else shape
                    body = _native_structure(body, shape)
            if self.service == 'opensearchserverless' and operation == 'get_security_policy' and isinstance(body, dict):
                # AOSS puts its network rules in a JSON string. Decode only
                # this documented network-policy response, before caching it.
                try:
                    policy = json.loads(body.get('policy', ''))
                except (ValueError, TypeError):
                    policy = None
                if not isinstance(policy, list):
                    raise ValueError('malformed_native_network_policy')
                body = dict(body, NetworkPolicy=[_aoss_network_rule(rule) for rule in policy])
            if self.service == 'quicksight' and operation == 'describe_ip_restriction' and isinstance(body, dict):
                import ipaddress
                facts = []
                for field in ('IpRestrictionRuleMap', 'VpcIdRestrictionRuleMap', 'VpcEndpointIdRestrictionRuleMap'):
                    rules = response.get(field, {})
                    if not isinstance(rules, dict):
                        raise ValueError('malformed_native_network_restrictions')
                    for key in rules:
                        if field == 'IpRestrictionRuleMap':
                            try:
                                ipaddress.ip_network(key, strict=False)
                            except (TypeError, ValueError):
                                raise ValueError('malformed_native_network_restrictions') from None
                        else:
                            import re
                            if not isinstance(key, str) or not re.fullmatch(r'(?:vpc|vpce)-[A-Za-z0-9-]+', key):
                                raise ValueError('malformed_native_network_restrictions')
                        facts.append({'path': field + '.' + key, 'name': field + 'Key', 'value': key})
                if type(response.get('Enabled')) is bool:
                    facts.append({'path': 'Enabled', 'name': 'Enabled', 'value': response['Enabled']})
                body = {key: value for key, value in body.items() if key not in
                    {'IpRestrictionRuleMap', 'VpcIdRestrictionRuleMap', 'VpcEndpointIdRestrictionRuleMap'}} | {'NetworkAttributes': facts}
            projected = projected_metadata(body, identity_fields=READ_IDENTITIES.get((self.service, operation), ()))
            if self.service == 'dsql' and operation == 'get_cluster' and isinstance(body, dict):
                projected = {key: body[key] for key in ('identifier', 'arn', 'status', 'endpoint') if key in body}
            if self.service == 'devicefarm' and operation == 'get_run' and isinstance(body, dict):
                # GetRun calls this ARN appUpload, so the generic network
                # projection omits it. Keep only a same-project upload ARN;
                # environment variables and signed URLs remain discarded.
                app = body.get('appUpload')
                if app is not None:
                    run = body.get('arn')
                    if (not isinstance(run, str) or ':run:' not in run or
                            not isinstance(app, str) or
                            not app.startswith(run.split(':run:', 1)[0] + ':upload:' +
                                               run.split(':run:', 1)[1].split('/', 1)[0] + '/') or
                            '/' not in run.split(':run:', 1)[1]):
                        raise ValueError('malformed_devicefarm_run_app_upload')
                    projected['appUpload'] = app
            if self.service == 'emr-containers' and operation == 'list_virtual_clusters' and isinstance(body, list):
                # Keep the EKS namespace needed to bind a job execution role's
                # service-account trust to this exact virtual cluster.
                for raw, row in zip(body, projected):
                    if not isinstance(raw, dict) or not isinstance(row, dict):
                        continue
                    provider = raw.get('containerProvider') or {}
                    if not isinstance(provider, dict) or provider.get('type') != 'EKS':
                        continue
                    info = provider.get('info') or {}
                    eks_info = (info.get('eksInfo') or {}) if isinstance(info, dict) else {}
                    namespace = eks_info.get('namespace') if isinstance(eks_info, dict) else None
                    if isinstance(namespace, str) and namespace:
                        row['EksNamespace'] = namespace
                    if isinstance(provider.get('id'), str) and provider['id']:
                        row['EksClusterName'] = provider['id']
            result = {root: projected} if root else projected
            if not isinstance(result, dict):
                return {}
            return result | {key: response[key] for key in
                ('NextToken', 'nextToken', 'Marker', 'marker', 'NextMarker', 'nextMarker', 'IsTruncated') if key in response}
        return read


def _aoss_network_rule(rule):
    if not isinstance(rule, dict):
        raise ValueError('malformed_native_network_policy')
    result = {}
    if type(rule.get('AllowFromPublic')) is bool:
        result['AllowFromPublic'] = rule['AllowFromPublic']
    for field in ('SourceVPCEs', 'SourceServices'):
        if field in rule:
            if not isinstance(rule[field], list) or any(not isinstance(v, str) for v in rule[field]):
                raise ValueError('malformed_native_network_policy')
            result[field] = rule[field]
    if 'Rules' in rule:
        if not isinstance(rule['Rules'], list):
            raise ValueError('malformed_native_network_policy')
        result['Rules'] = []
        for native in rule['Rules']:
            if (not isinstance(native, dict) or native.get('ResourceType') not in {'collection', 'dashboard'}
                    or not isinstance(native.get('Resource'), list) or any(not isinstance(v, str) for v in native['Resource'])):
                raise ValueError('malformed_native_network_policy')
            result['Rules'].append({'ResourceType': native['ResourceType'], 'Resource': native['Resource']})
    return result


def _native_structure(value, shape):
    """Native structure fields are distinct from arbitrary user dictionary keys.

    SDK maps contain tags, model hyperparameters and application properties.
    Their user-selected keys cannot become network fields by spelling them like
    a VPC ID. Native network structures and lists keep their exact field paths.
    """
    if shape is None:
        return None
    if shape.type_name == 'map':
        return {}
    if shape.type_name == 'structure' and isinstance(value, dict):
        return {key: _native_structure(item, shape.members[key]) for key, item in value.items() if key in shape.members}
    if shape.type_name == 'list' and isinstance(value, list):
        return [_native_structure(item, shape.member) for item in value]
    return value


class MetadataSession:
    def __init__(self, native):
        self.native = native

    def client(self, service, **arguments):
        return MetadataClient(self.native.client(service, **arguments), service)


def _arguments(step, context):
    arguments = dict(step.get('constants', {}))
    for argument, source in step.get('arguments', {}).items():
        value = context.get(source)
        if not isinstance(value, (str, int)) or isinstance(value, bool) or value == '':
            raise ValueError('network_inventory_identity_missing')
        arguments[argument.removesuffix('[]')] = [value] if argument.endswith('[]') else value
    return arguments


def _details(requests, session, service, region, step, arguments):
    # A detail response can itself contain a paginated network list (custom
    # domains, VTL devices). Retain every page, using native SDK token metadata.
    result = requests.pages(session, service, region, step['operation'], '[@]',
                            _tokens=tuple(step['tokens']) if step.get('tokens') else None, **arguments)
    bodies, status = [], result.status
    for page in result.items:
        body = page.get(step['key']) if isinstance(page, dict) and step['key'] else page
        if isinstance(body, list):
            body = body[0] if len(body) == 1 else None
        if not isinstance(body, dict) or not body or set(body) == {'NetworkAttributes'} and not body['NetworkAttributes']:
            status = 'malformed'
        else:
            bodies.append(body)
    if not bodies:
        return None, status if status != 'collected' else 'malformed'
    body = dict(bodies[0])
    if len(bodies) > 1:
        body['NetworkDetailPages'] = bodies
    return body, status


def collect(kind):
    plan = PLANS[kind]
    def fetch(requests, session, region, account):
        from .aws import ReadResult
        if kind == 'agentcore_harness':
            from botocore import xform_name
            model = session.client(plan['service'], region_name=region).meta.service_model
            if not any(xform_name(name) == plan['operation'] for name in model.operation_names):
                return ReadResult([], 'not_collected', {'code': 'sdk_operation_unavailable'})
        session = MetadataSession(session)
        service = plan['service']
        failures, rows = [], []
        def pages(step, context):
            try:
                arguments = _arguments(step, context)
            except ValueError:
                failures.append('malformed')
                return []
            result = requests.pages(session, service, region, step['operation'], '[@]' if step.get('single') else step['key'],
                                    _tokens=tuple(step['tokens']) if step.get('tokens') else None, **arguments)
            if result.status not in {'collected', 'empty'}:
                failures.append(result.status)
            return result.items
        parents = [({'NetworkAccountId': account}, [])]
        for step in plan.get('parents', []):
            discovered = []
            for context, lineage in parents:
                for item in pages(step, context):
                    if isinstance(item, str) and item:
                        item = {'Item': item}
                    if not isinstance(item, dict):
                        failures.append('malformed')
                        continue
                    exported = {target: item.get(source) for target, source in step['exports'].items()}
                    if any(not isinstance(v, str) or not v for v in exported.values()):
                        failures.append('malformed')
                        continue
                    discovered.append((context | exported, lineage + list(exported.values())))
            parents = discovered
        for context, lineage in parents:
            listed = pages(plan, context)
            if plan.get('detail'):
                from .aws_request_pool import prefetch_details
                prefetch_details(requests, session, service, region, plan, context, listed, _arguments, _details)
            for item in listed:
                if isinstance(item, str) and item:
                    item = {'Item': item}
                if not isinstance(item, dict):
                    failures.append('malformed')
                    continue
                if any(item.get(key) != value for key, value in plan.get('match', {}).items()):
                    continue
                summary = item
                detail = plan.get('detail')
                if detail:
                    try:
                        arguments = _arguments(detail, context | item)
                    except ValueError:
                        body, detail_status = None, 'malformed'
                    else:
                        body, detail_status = _details(requests, session, service, region, detail, arguments)
                    if isinstance(body, dict) and plan['identity'] in summary and plan['identity'] in body and summary[plan['identity']] != body[plan['identity']]:
                        body, detail_status = None, 'malformed'
                    if detail_status not in {'collected', 'empty'}:
                        failures.append(detail_status)
                    if isinstance(body, dict):
                        # All persisted facts came from the projected detail API.
                        item = summary | body
                    else:
                        if detail_status in {'collected', 'empty'}:
                            failures.append('malformed')
                        item = dict(summary, _coverage={'network_detail': {'status': failures[-1]}})
                    if detail_status not in {'collected', 'empty'}:
                        item.setdefault('_coverage', {})['network_detail'] = {'status': detail_status}
                native = item.get(plan['identity'])
                if plan.get('identity_fields'):
                    parts = [item.get(key) for key in plan['identity_fields']]
                    if any(not isinstance(part, str) or not part for part in parts):
                        failures.append('malformed')
                        continue
                    native = '/'.join(parts)
                if not isinstance(native, str) or not native:
                    native = next((item.get(key) for key in ('arn', 'Arn', 'ARN', 'id', 'Id', 'Name', 'name', 'Item')
                                   if isinstance(item.get(key), str) and item[key]), None)
                if not native:
                    failures.append('malformed')
                    continue
                # A child name alone cannot identify resources under two parents.
                if kind == 'machinelearning_model':
                    import re
                    if not re.fullmatch(r'[A-Za-z0-9_-]+', native):
                        failures.append('malformed')
                        continue
                    partition = session.native.get_partition_for_region(region)
                    identity = f'arn:{partition}:machinelearning:{region}:{account}:mlmodel/{native}'
                else:
                    identity = native if native.startswith('arn:') else '/'.join([*lineage, native])
                rows.append(dict(item, NetworkResourceId=identity, NetworkParentIds=lineage))
        status = 'partial' if rows and failures else failures[0] if failures else 'collected' if rows else 'empty'
        return ReadResult(rows, status, {'code': 'native_network_inventory_incomplete', 'cause_status': failures[0]} if failures else None)
    return fetch


FETCHERS = {kind: collect(kind) for kind in PLANS}


def aoss_collections(requests, session, region, account):
    """One paginated list plus one endpoint-detail read per 100 owned IDs."""
    from .aws import ReadResult
    service = 'opensearchserverless'
    partition = 'aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'
    session = MetadataSession(session)
    listed = requests.pages(session, service, region, 'list_collections', 'collectionSummaries',
                            _tokens=('nextToken', 'nextToken'))
    if listed.status not in {'collected', 'empty'}:
        return ReadResult([], listed.status, listed.error)
    owned, failures = {}, []
    for row in listed.items:
        if not isinstance(row, dict):
            failures.append('malformed')
            continue
        ident, name, arn = row.get('id'), row.get('name'), row.get('arn')
        if (not isinstance(ident, str) or not ident or not isinstance(name, str) or not name or
                arn != f'arn:{partition}:aoss:{region}:{account}:collection/{ident}'):
            failures.append('malformed')
            continue
        if ident in owned:
            failures.append('malformed')
        else:
            owned[ident] = row
    rows = []
    for start in range(0, len(owned), 100):
        ids = sorted(owned)[start:start + 100]
        detail = requests.detail(session, service, region, 'batch_get_collection', ids=ids)
        if detail.get('collection_status') != 'collected':
            failures.append(detail.get('collection_status', 'malformed'))
            rows.extend(dict(owned[ident], NetworkResourceId=owned[ident]['arn'],
                             _coverage={'network_detail': {'status': detail.get('collection_status', 'malformed')}})
                        for ident in ids)
            continue
        bodies, errors = detail.get('collectionDetails'), detail.get('collectionErrorDetails')
        if not isinstance(bodies, list) or not isinstance(errors, list):
            failures.append('malformed')
            bodies, errors = [], []
        if errors:
            failures.append('partial')
        by_id = {}
        for body in bodies:
            if isinstance(body, dict) and isinstance(body.get('id'), str) and body['id'] in ids and body['id'] not in by_id:
                by_id[body['id']] = body
            else:
                failures.append('malformed')
        for ident in ids:
            summary, body = owned[ident], by_id.get(ident)
            if (body is None or body.get('arn') != summary['arn'] or body.get('name') != summary['name']):
                failures.append('partial')
                rows.append(dict(summary, NetworkResourceId=summary['arn'],
                                 _coverage={'network_detail': {'status': 'partial'}}))
            else:
                rows.append(dict(summary, **body, NetworkResourceId=summary['arn']))
    status = 'partial' if rows and failures else failures[0] if failures else 'collected' if rows else 'empty'
    return ReadResult(rows, status, {'code': 'aoss_collection_inventory_incomplete'} if failures else None)


FETCHERS['aoss_collection'] = aoss_collections


def mailmanager_rule_routes(requests, session, region, account):
    """Read only rule actions attached to owned ingress points and referenced relays."""
    from .aws import ReadResult
    selected = MetadataSession(session)
    listed = requests.pages(selected, 'mailmanager', region, 'list_ingress_points', 'IngressPoints')
    if listed.status not in {'collected', 'empty'}:
        return listed
    rows, failures = [], []
    for summary in listed.items:
        ingress_id = summary.get('IngressPointId') if isinstance(summary, dict) else None
        if not isinstance(ingress_id, str) or not ingress_id:
            failures.append('malformed')
            continue
        detail = requests.detail(selected, 'mailmanager', region, 'get_ingress_point', IngressPointId=ingress_id)
        row = {'IngressPointId': ingress_id}
        if detail.get('collection_status') != 'collected' or detail.get('IngressPointId') != ingress_id:
            row['RuleSet'] = {'collection_status': detail.get('collection_status', 'malformed')
                              if isinstance(detail, dict) else 'malformed'}
            failures.append(row['RuleSet']['collection_status'])
            rows.append(row)
            continue
        row['IngressPointArn'] = detail.get('IngressPointArn')
        row['Status'] = detail.get('Status')
        rule_id = detail.get('RuleSetId')
        if not isinstance(rule_id, str) or not rule_id:
            row['RuleSet'] = {'collection_status': 'malformed'}
            failures.append('malformed')
            rows.append(row)
            continue
        rule_set = requests.detail(selected, 'mailmanager', region, 'get_rule_set', RuleSetId=rule_id)
        if (rule_set.get('collection_status') != 'collected' or rule_set.get('RuleSetId') != rule_id or
                not isinstance(rule_set.get('Rules'), list)):
            row['RuleSet'] = {'collection_status': rule_set.get('collection_status', 'malformed')}
            failures.append(row['RuleSet']['collection_status'])
            rows.append(row)
            continue
        row['RuleSet'] = {'collection_status': 'collected', 'RuleSetId': rule_id,
                          'RuleSetArn': rule_set.get('RuleSetArn'), 'Rules': rule_set['Rules']}
        relay_ids = sorted({action['RelayId'] for rule in rule_set['Rules'] if isinstance(rule, dict)
                            for action in rule.get('Actions', []) if isinstance(rule.get('Actions'), list)
                            if isinstance(action, dict) and action.get('Type') == 'Relay'
                            and isinstance(action.get('RelayId'), str)})
        relays = []
        for relay_id in relay_ids:
            relay = requests.detail(selected, 'mailmanager', region, 'get_relay', RelayId=relay_id)
            if relay.get('collection_status') == 'collected' and relay.get('RelayId') == relay_id:
                relays.append({**{key: relay.get(key) for key in ('RelayId', 'RelayArn', 'ServerName', 'ServerPort')},
                               'collection_status': 'collected'})
            else:
                relays.append({'RelayId': relay_id, 'collection_status': relay.get('collection_status', 'malformed')})
                failures.append(relays[-1]['collection_status'])
        row['Relays'] = relays
        rows.append(row)
    return ReadResult(rows, 'partial' if rows and failures else failures[0] if failures else
                      'collected' if rows else 'empty', {'code': 'mailmanager_rule_inventory_incomplete'} if failures else None)


SPECS['mailmanager_rule_route'] = ('mailmanager', 'list_ingress_points', 'IngressPoints')
NATIVE_IDS['mailmanager_rule_route'] = 'IngressPointId'
FETCHERS['mailmanager_rule_route'] = mailmanager_rule_routes

# Keep the S3 Tables Lake Formation grant read in the existing reviewed AWS
# metadata extension; the primary collector dispatch remains source-pinned.
from . import aws_s3tables_lakeformation as _s3tables_lf
SPECS.update(_s3tables_lf.SPECS)
NATIVE_IDS.update(_s3tables_lf.NATIVE_IDS)
READ_ACTIONS.update(_s3tables_lf.READ_ACTIONS)
FETCHERS.update(_s3tables_lf.FETCHERS)

from . import aws_sns_platform_exposure as _sns_platform_exposure
SPECS.update(_sns_platform_exposure.SPECS)
NATIVE_IDS.update(_sns_platform_exposure.NATIVE_IDS)
READ_ACTIONS.update(_sns_platform_exposure.READ_ACTIONS)
FETCHERS.update(_sns_platform_exposure.FETCHERS)
from . import aws_redshift_datashares as _redshift_datashares
SPECS.update(_redshift_datashares.SPECS)
NATIVE_IDS.update(_redshift_datashares.NATIVE_IDS)
READ_ACTIONS.update(_redshift_datashares.READ_ACTIONS)
FETCHERS.update(_redshift_datashares.FETCHERS)

from . import aws_marketplace_exposure as _marketplace_exposure
SPECS.update(_marketplace_exposure.SPECS)
NATIVE_IDS.update(_marketplace_exposure.NATIVE_IDS)
GLOBAL_TYPES.update(_marketplace_exposure.GLOBAL_TYPES)
READ_ACTIONS.update(_marketplace_exposure.READ_ACTIONS)
FETCHERS.update(_marketplace_exposure.FETCHERS)

from . import aws_mediapackagev2_exposure as _mediapackagev2_exposure
SPECS.update(_mediapackagev2_exposure.SPECS)
NATIVE_IDS.update(_mediapackagev2_exposure.NATIVE_IDS)
READ_ACTIONS.update(_mediapackagev2_exposure.READ_ACTIONS)
FETCHERS.update(_mediapackagev2_exposure.FETCHERS)

from . import aws_security_ir_recipients as _security_ir_recipients
SPECS.update(_security_ir_recipients.SPECS)
NATIVE_IDS.update(_security_ir_recipients.NATIVE_IDS)
READ_ACTIONS.update(_security_ir_recipients.READ_ACTIONS)
FETCHERS.update(_security_ir_recipients.FETCHERS)

from . import aws_opensearch_exposure as _opensearch_exposure
SPECS.update(_opensearch_exposure.SPECS)
NATIVE_IDS.update(_opensearch_exposure.NATIVE_IDS)
READ_ACTIONS.update(_opensearch_exposure.READ_ACTIONS)
FETCHERS.update(_opensearch_exposure.FETCHERS)

from . import aws_securitylake_subscribers as _securitylake_subscribers
SPECS.update(_securitylake_subscribers.SPECS)
NATIVE_IDS.update(_securitylake_subscribers.NATIVE_IDS)
READ_ACTIONS.update(_securitylake_subscribers.READ_ACTIONS)
FETCHERS.update(_securitylake_subscribers.FETCHERS)


def enrich_network_detail(plan):
    def enrich(requests, session, region, items):
        session = MetadataSession(session)
        for row in items:
            arn = row.get('Arn') or row.get('arn') or row.get('ARN')
            context = dict(row, NetworkAccountId=arn.split(':')[4] if isinstance(arn, str) and arn.startswith('arn:') else None)
            try:
                arguments = _arguments(plan, context)
            except ValueError:
                row.setdefault('_coverage', {})['network_audit_detail'] = {'status': 'malformed'}
                continue
            body, detail_status = _details(requests, session, plan['service'], region, plan, arguments)
            if isinstance(body, dict):
                row['NetworkAuditDetails'] = body
            row.setdefault('_coverage', {})['network_audit_detail'] = {'status': detail_status}
        return items
    return enrich


ENRICHERS = {kind: enrich_network_detail(plan) for kind, plan in DETAIL_ENRICHERS.items()}


def vpc_dns_attributes(requests, session, region, items):
    session = MetadataSession(session)
    for row in items:
        native = row.get('VpcId')
        if not isinstance(native, str):
            row.setdefault('_coverage', {})['dns_attributes'] = {'status': 'malformed'}
            continue
        details = []
        for attribute in ('enableDnsSupport', 'enableDnsHostnames'):
            step = {'operation': 'describe_vpc_attribute', 'key': None}
            body, status = _details(requests, session, 'ec2', region, step, {'VpcId': native, 'Attribute': attribute})
            if body and body.get('VpcId') != native:
                body, status = None, 'malformed'
            if body:
                details.append(body)
            row.setdefault('_coverage', {})[attribute] = {'status': status}
        row['NetworkDnsAttributes'] = details
    return items


ENRICHERS['vpc'] = vpc_dns_attributes
