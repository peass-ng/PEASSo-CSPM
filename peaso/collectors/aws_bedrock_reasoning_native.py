"""Native AgentAlias configuration evidence; no model invocation/enforcement claim."""
from functools import lru_cache
import re

KIND = 'bedrock_automated_reasoning_policy'
PROFILE = 'bedrock-agent-reasoning-metadata-v1'
PROJECTION_OPERATIONS = frozenset({
    ('bedrock-agent', 'list_agents'), ('bedrock-agent', 'list_agent_aliases'),
    ('bedrock-agent', 'get_agent_alias'), ('bedrock-agent', 'get_agent_version'),
    ('bedrock', 'get_guardrail'), ('bedrock', 'get_automated_reasoning_policy'),
})
READ_ACTIONS = set(PROJECTION_OPERATIONS)
SPECS = {KIND: ('bedrock-agent', 'list_agents', 'agentSummaries')}
NATIVE_IDS = {KIND: 'ApplicationId'}
GLOBAL_TYPES = set()
SEMANTICS = 'Native published AgentAlias configuration and published-policy-version resolution; invocation and enforcement unassessed'
CHAIN = 'ListAgents+ListAgentAliases+GetAgentAlias+GetAgentVersion+GetGuardrail+GetAutomatedReasoningPolicy'
ARN = re.compile(r'arn:(aws(?:-[a-z0-9-]+)?):bedrock:([a-z0-9-]+):([0-9]{12}):(.+)')
ID = re.compile(r'[0-9a-zA-Z]{10}')
VERSION = re.compile(r'[1-9][0-9]{0,4}')
GUARD_VERSION = re.compile(r'[1-9][0-9]{0,7}')
POLICY = re.compile(r'automated-reasoning-policy/([a-z0-9]{12})(?::([1-9][0-9]{0,11}))?')
OK = {'collected', 'empty'}


def _invalid():
    from .aws import ReadFailure
    raise ReadFailure('malformed', 'bedrock_reasoning_metadata_invalid')


@lru_cache(maxsize=6)
def _output_shape(service, operation):
    import botocore.session
    from botocore import xform_name
    model = botocore.session.get_session().get_service_model(service)
    name = next(name for name in model.operation_names if xform_name(name) == operation)
    return model.operation_model(name).output_shape


def _sdk_response(response, service, operation):
    from botocore.validate import validate_parameters
    from botocore.exceptions import ParamValidationError
    if not isinstance(response, dict) or (service, operation) not in PROJECTION_OPERATIONS:
        _invalid()
    try:
        validate_parameters({k: v for k, v in response.items() if k != 'ResponseMetadata'},
                            _output_shape(service, operation))
    except ParamValidationError:
        _invalid()


def _pick(value, keys):
    return {k: value[k] for k in keys if k in value}


def project_response(response, service, operation, arguments):
    """Validate actual SDK shape then discard prompts/text before the Future."""
    _sdk_response(response, service, operation)
    result = {'_metadata_projection': PROFILE}
    if operation in {'list_agents', 'list_agent_aliases'}:
        field = 'agentSummaries' if operation == 'list_agents' else 'agentAliasSummaries'
        keys = ('agentId', 'agentStatus') if operation == 'list_agents' else ('agentAliasId', 'agentAliasStatus')
        result[field] = [_pick(row, keys) for row in response[field]]
        if 'nextToken' in response: result['nextToken'] = response['nextToken']
    elif operation == 'get_agent_alias':
        row = response['agentAlias']
        if row['agentId'] != arguments.get('agentId') or row['agentAliasId'] != arguments.get('agentAliasId'):
            _invalid()
        result['agentAlias'] = _pick(row, ('agentId', 'agentAliasId', 'agentAliasArn', 'agentAliasStatus'))
        result['agentAlias']['routingConfiguration'] = [_pick(route, ('agentVersion',)) for route in row['routingConfiguration']]
    elif operation == 'get_agent_version':
        row = response['agentVersion']
        if row['agentId'] != arguments.get('agentId') or row['version'] != arguments.get('agentVersion'):
            _invalid()
        result['agentVersion'] = _pick(row, ('agentId', 'agentArn', 'version', 'agentStatus', 'guardrailConfiguration'))
    elif operation == 'get_guardrail':
        if (response['version'] != arguments.get('guardrailVersion')
                or arguments.get('guardrailIdentifier') not in {response['guardrailId'], response['guardrailArn']}):
            _invalid()
        result.update(_pick(response, ('guardrailId', 'guardrailArn', 'version', 'status', 'automatedReasoningPolicy')))
        if 'automatedReasoningPolicy' in result:
            policies = result['automatedReasoningPolicy']['policies']
            if not 1 <= len(policies) <= 2 or len(set(policies)) != len(policies): _invalid()
            result['automatedReasoningPolicy'] = {'policies': list(policies)}
    elif operation == 'get_automated_reasoning_policy':
        wanted = arguments.get('policyArn')
        target = ARN.fullmatch(wanted) if isinstance(wanted, str) else None
        resource = POLICY.fullmatch(target[4]) if target else None
        native = ARN.fullmatch(response['policyArn'])
        observed = POLICY.fullmatch(native[4]) if native else None
        if (resource is None or resource[2] is None or observed is None
                or target.groups()[:3] != native.groups()[:3] or resource[1] != observed[1]
                or response['policyId'] != resource[1] or response['version'] != resource[2]
                or observed[2] is not None and observed[2] != resource[2]
                or re.fullmatch(r'[0-9a-z]{128}', response['definitionHash']) is None):
            _invalid()
        # AWS permits an unversioned policyArn response with a separate version;
        # both native components must normalize to the exact requested version.
        result.update(_pick(response, ('policyArn', 'policyId', 'version', 'definitionHash')))
    return result


def _bound(arn, account, region, partition, resource):
    match = ARN.fullmatch(arn) if isinstance(arn, str) else None
    return bool(match and match[1] == partition and match[2] == region and match[3] == account and match[4] == resource)


def _partition(session, region):
    try: return session.get_partition_for_region(region)
    except Exception: return None


def _unknown(account, region, application, reason):
    return {'_resource_id': application, 'ApplicationId': application, 'AccountId': account, 'Region': region,
        '_metadata_projection': PROFILE, 'NativeBinding': 'unavailable', 'UnavailableReason': reason,
        '_provenance': {'source_operation': CHAIN, 'read_only': True, 'semantics': SEMANTICS}}


def _detail(requests, session, region, service, operation, **arguments):
    return requests.detail(session, service, region, operation, _metadata_profile=PROFILE, **arguments)


def _rows(requests, session, region, operation, field, **arguments):
    return requests.pages(session, 'bedrock-agent', region, operation, field, _metadata_profile=PROFILE, **arguments)


def _application(requests, session, region, account, partition, agent, alias):
    application = f'arn:{partition}:bedrock:{region}:{account}:agent-alias/{agent}/{alias}'
    row = _unknown(account, region, application, 'native_binding_unavailable')
    detail = _detail(requests, session, region, 'bedrock-agent', 'get_agent_alias', agentId=agent, agentAliasId=alias)
    if detail.get('collection_status') != 'collected' or detail.get('_metadata_projection') != PROFILE: return row
    native = detail.get('agentAlias', {})
    routes = native.get('routingConfiguration')
    if (native.get('agentId') != agent or native.get('agentAliasId') != alias
            or native.get('agentAliasArn') != application or native.get('agentAliasStatus') != 'PREPARED'
            or not isinstance(routes, list) or len(routes) != 1): return row
    version = routes[0].get('agentVersion')
    if not isinstance(version, str) or VERSION.fullmatch(version) is None: return row
    detail = _detail(requests, session, region, 'bedrock-agent', 'get_agent_version', agentId=agent, agentVersion=version)
    if detail.get('collection_status') != 'collected' or detail.get('_metadata_projection') != PROFILE: return row
    native = detail.get('agentVersion', {})
    if (native.get('agentId') != agent or native.get('version') != version or native.get('agentStatus') != 'PREPARED'
            or not _bound(native.get('agentArn'), account, region, partition, 'agent/' + agent)): return row
    binding = native.get('guardrailConfiguration')
    if not isinstance(binding, dict): return row
    guardrail, gv = binding.get('guardrailIdentifier'), binding.get('guardrailVersion')
    if not isinstance(gv, str) or GUARD_VERSION.fullmatch(gv) is None or not isinstance(guardrail, str): return row
    gid = guardrail
    if guardrail.startswith('arn:'):
        match = ARN.fullmatch(guardrail)
        if not match or not match[4].startswith('guardrail/'): return row
        gid = match[4][len('guardrail/'):]
        if not _bound(guardrail, account, region, partition, 'guardrail/' + gid): return row
    if re.fullmatch(r'[a-z0-9]+', gid) is None: return row
    detail = _detail(requests, session, region, 'bedrock', 'get_guardrail', guardrailIdentifier=guardrail, guardrailVersion=gv)
    if (detail.get('collection_status') != 'collected' or detail.get('_metadata_projection') != PROFILE
            or detail.get('guardrailId') != gid or detail.get('version') != gv or detail.get('status') != 'READY'
            or not _bound(detail.get('guardrailArn'), account, region, partition, 'guardrail/' + gid)): return row
    policies = detail.get('automatedReasoningPolicy', {}).get('policies', [])
    for policy in policies:
        match = ARN.fullmatch(policy) if isinstance(policy, str) else None
        identity = POLICY.fullmatch(match[4]) if match else None
        if (not match or match[1] != partition or match[2] != region or match[3] != account
                or identity is None or identity[2] is None): return row
    row.update({'NativeBinding': 'verified', 'NativePartition': partition, 'NativeAgentId': agent,
        'NativeAliasId': alias, 'NativeAgentVersion': version, 'GuardrailIdentifier': gid,
        'GuardrailVersion': gv, 'NativeGuardrailArn': detail['guardrailArn'], 'NativeGuardrailStatus': 'READY',
        'ConfiguredPolicyVersionArns': list(policies), 'PolicyResolutions': []})
    row.pop('UnavailableReason')
    for arn in policies:
        detail = _detail(requests, session, region, 'bedrock', 'get_automated_reasoning_policy',
                         absent=('ResourceNotFoundException',), policyArn=arn)
        resolution = {'PolicyVersionArn': arn, 'Resolution': 'unavailable'}
        if detail.get('collection_status') == 'collected' and detail.get('_metadata_projection') == PROFILE:
            resolution.update({'Resolution': 'published-version-resolved',
                'NativePolicyArn': detail['policyArn'], 'NativePolicyId': detail['policyId'],
                'NativePolicyVersion': detail['version'], 'DefinitionHash': detail['definitionHash']})
        elif (detail.get('collection_status') == 'empty' and detail.get('absent') is True
                and detail.get('error', {}).get('code') == 'ResourceNotFoundException'):
            resolution.update({'Resolution': 'not_found', 'NativeErrorCode': 'ResourceNotFoundException'})
        row['PolicyResolutions'].append(resolution)
    return row


def collect(requests, session, region, account):
    from .aws import ReadResult
    partition = _partition(session, region)
    if not isinstance(account, str) or re.fullmatch(r'[0-9]{12}', account) is None or not partition:
        return ReadResult([], 'malformed', {'code': 'bedrock_reasoning_scope_invalid'})
    agents = _rows(requests, session, region, 'list_agents', 'agentSummaries')
    if agents.status not in OK: return ReadResult([], agents.status, agents.error)
    if not agents.items:
        return ReadResult([], 'not_collected', {'code': 'bedrock_application_binding_unavailable'})
    from concurrent.futures import ThreadPoolExecutor, Future
    from contextlib import nullcontext
    jobs, seen = [], set()
    def resolved():
        # Preserve native enumeration order, including partial prefixes.
        return [job.result() if isinstance(job, Future) else job for job in jobs]
    manager = ThreadPoolExecutor(max_workers=requests.workers) if requests.workers > 1 else nullcontext(None)
    with manager as pool:
        for agent in agents.items:
            aid = agent.get('agentId') if isinstance(agent, dict) else None
            if not isinstance(aid, str) or ID.fullmatch(aid) is None or aid in seen:
                return ReadResult([], 'malformed', {'code': 'bedrock_agent_identity_invalid'})
            seen.add(aid)
            aliases = _rows(requests, session, region, 'list_agent_aliases', 'agentAliasSummaries', agentId=aid)
            if aliases.status not in OK:
                return ReadResult(resolved(), 'partial' if jobs else aliases.status, aliases.error)
            if not aliases.items:
                jobs.append(_unknown(account, region, f'arn:{partition}:bedrock:{region}:{account}:agent/{aid}', 'published_alias_unavailable'))
            alias_seen = set()
            for alias in aliases.items:
                identifier = alias.get('agentAliasId') if isinstance(alias, dict) else None
                if not isinstance(identifier, str) or ID.fullmatch(identifier) is None or identifier in alias_seen:
                    return ReadResult(resolved(), 'partial' if jobs else 'malformed', {'code': 'bedrock_alias_identity_invalid'})
                alias_seen.add(identifier)
                args = requests, session, region, account, partition, aid, identifier
                jobs.append(pool.submit(_application, *args) if pool else _application(*args))
        return ReadResult(resolved())


FETCHERS = {KIND: collect}


@lru_cache(maxsize=64)
def _partition_for_region(region):
    # Endpoint metadata only; one resolver per region instead of one SDK
    # session per assessed row.
    import botocore.session
    return botocore.session.get_session().get_partition_for_region(region)


def assess(row, account, region):
    """Evaluate the native observation without manufacturing an AWS status."""
    evidence = {'semantics': SEMANTICS, 'application_id': row.get('ApplicationId')}
    def unknown(): return 'UNKNOWN', {**evidence, 'reason': 'native configuration binding or resolution unavailable'}
    proof = row.get('_provenance')
    if (row.get('_metadata_projection') != PROFILE or row.get('AccountId') != account or row.get('Region') != region
            or not isinstance(proof, dict) or proof.get('read_only') is not True
            or proof.get('source_operation') != CHAIN): return unknown()
    if row.get('NativeBinding') != 'verified': return unknown()
    partition = _partition_for_region(region)
    agent, alias, version = row.get('NativeAgentId'), row.get('NativeAliasId'), row.get('NativeAgentVersion')
    gid, gv = row.get('GuardrailIdentifier'), row.get('GuardrailVersion')
    if (not isinstance(agent, str) or ID.fullmatch(agent) is None or not isinstance(alias, str) or ID.fullmatch(alias) is None
            or not isinstance(version, str) or VERSION.fullmatch(version) is None
            or row.get('NativePartition') != partition
            or row.get('ApplicationId') != f'arn:{partition}:bedrock:{region}:{account}:agent-alias/{agent}/{alias}'
            or not isinstance(gid, str) or re.fullmatch(r'[a-z0-9]+', gid) is None
            or not isinstance(gv, str) or GUARD_VERSION.fullmatch(gv) is None
            or row.get('NativeGuardrailStatus') != 'READY'
            or not _bound(row.get('NativeGuardrailArn'), account, region, partition, 'guardrail/' + gid)): return unknown()
    configured, resolutions = row.get('ConfiguredPolicyVersionArns'), row.get('PolicyResolutions')
    if (not isinstance(configured, list) or len(configured) > 2
            or any(not isinstance(a, str) for a in configured) or len(set(configured)) != len(configured)
            or not isinstance(resolutions, list) or len(resolutions) != len(configured)): return unknown()
    failures, unresolved, seen = [], [], set()
    for result in resolutions:
        if not isinstance(result, dict): return unknown()
        arn = result.get('PolicyVersionArn'); parsed = ARN.fullmatch(arn) if isinstance(arn, str) else None
        identity = POLICY.fullmatch(parsed[4]) if parsed else None
        if (not parsed or parsed.groups()[:3] != (partition, region, account) or identity is None or identity[2] is None
                or arn not in configured or arn in seen): return unknown()
        seen.add(arn)
        state = result.get('Resolution')
        if state == 'not_found':
            if set(result) != {'PolicyVersionArn', 'Resolution', 'NativeErrorCode'} or result['NativeErrorCode'] != 'ResourceNotFoundException': return unknown()
            failures.append(arn)
        elif state == 'published-version-resolved':
            if set(result) != {'PolicyVersionArn', 'Resolution', 'NativePolicyArn', 'NativePolicyId', 'NativePolicyVersion', 'DefinitionHash'}: return unknown()
            observed = ARN.fullmatch(result['NativePolicyArn']) if isinstance(result['NativePolicyArn'], str) else None
            policy = POLICY.fullmatch(observed[4]) if observed else None
            if (not observed or observed.groups()[:3] != parsed.groups()[:3] or policy is None
                    or policy[1] != identity[1] or policy[2] is not None and policy[2] != identity[2]
                    or result['NativePolicyId'] != identity[1] or result['NativePolicyVersion'] != identity[2]
                    or not isinstance(result['DefinitionHash'], str) or re.fullmatch(r'[0-9a-z]{128}', result['DefinitionHash']) is None): return unknown()
        elif state == 'unavailable':
            if set(result) != {'PolicyVersionArn', 'Resolution'}: return unknown()
            unresolved.append(arn)
        else: return unknown()
    if seen != set(configured): return unknown()
    evidence.update({'guardrail': row['NativeGuardrailArn'], 'guardrail_version': gv,
        'policy_resolution_semantics': 'published-policy-version-resolved'})
    if not configured: return 'FAIL', {**evidence, 'reason': 'no policy configured in native guardrail version'}
    if failures: return 'FAIL', {**evidence, 'missing_policy_version_arns': sorted(failures)}
    if unresolved: return unknown()
    return 'PASS', {**evidence, 'resolved_policy_version_arns': sorted(configured)}
