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
            with private_sdk_logs():
                response = native(**arguments)
            if not isinstance(response, dict):
                return {}  # Normal response validation records malformed coverage.
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
                identity = native if native.startswith('arn:') else '/'.join([*lineage, native])
                rows.append(dict(item, NetworkResourceId=identity, NetworkParentIds=lineage))
        status = 'partial' if rows and failures else failures[0] if failures else 'collected' if rows else 'empty'
        return ReadResult(rows, status, {'code': 'native_network_inventory_incomplete', 'cause_status': failures[0]} if failures else None)
    return fetch


FETCHERS = {kind: collect(kind) for kind in PLANS}


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
