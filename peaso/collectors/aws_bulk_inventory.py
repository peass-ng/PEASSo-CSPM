"""Native read-only inventories for the bulk compliance definitions.

All requests use the shared cache, pagination and scan budgets. A failure in
any child listing preserves the parent failure instead of certifying absence.
"""
import json
import hashlib
import re
import ipaddress
from urllib.parse import urlsplit
from .aws_facts_data_identity import _pick

SPECS = {
    'cost_anomaly_monitor': ('ce', 'get_anomaly_monitors', 'AnomalyMonitors'),
    'cost_anomaly_subscription': ('ce', 'get_anomaly_subscriptions', 'AnomalySubscriptions'),
    'backup_restore_job': ('backup', 'list_restore_jobs', 'RestoreJobs'),
    'backup_restore_testing_plan': ('backup', 'list_restore_testing_plans', 'RestoreTestingPlans'),
    'backup_restore_testing_selection': ('backup', 'list_restore_testing_selections', 'RestoreTestingSelections'),
    'organization_delegated_admin': ('organizations', 'list_delegated_administrators', 'DelegatedAdministrators'),
    'organization_service_access': ('organizations', 'list_aws_service_access_for_organization', 'EnabledServicePrincipals'),
    'wafv2_appsync_association': ('wafv2', 'get_web_acl_for_resource', None),
    'resolver_firewall_rule_group_association': ('route53resolver', 'list_firewall_rule_group_associations', 'FirewallRuleGroupAssociations'),
    'resolver_firewall_rule': ('route53resolver', 'list_firewall_rules', 'FirewallRules'),
    'resolver_query_log_config': ('route53resolver', 'list_resolver_query_log_configs', 'ResolverQueryLogConfigs'),
    'resolver_query_log_config_association': ('route53resolver', 'list_resolver_query_log_config_associations', 'ResolverQueryLogConfigAssociations'),
    'log_subscription_filter': ('logs', 'describe_subscription_filters', 'subscriptionFilters'),
    'log_account_subscription_policy': ('logs', 'describe_account_policies', 'accountPolicies'),
    'log_destination': ('logs', 'describe_destinations', 'destinations'),
    'sns_topic_subscription': ('sns', 'list_subscriptions_by_topic', 'Subscriptions'),
    'ec2_instance_type': ('ec2', 'describe_instance_types', 'InstanceTypes'),
    'eks_version_catalog': ('eks', 'describe_cluster_versions', 'clusterVersions'),
    'elbv2_listener': ('elbv2', 'describe_listeners', 'Listeners'),
    'inspector_finding': ('inspector2', 'list_findings', 'findings'),
    'securityhub_finding': ('securityhub', 'get_findings', 'Findings'),
    'wafv2_ip_set': ('wafv2', 'list_ip_sets', 'IPSets'),
}
GLOBAL_TYPES = {'cost_anomaly_monitor', 'cost_anomaly_subscription',
                'organization_delegated_admin', 'organization_service_access'}
NATIVE_IDS = {'cost_anomaly_monitor': 'MonitorArn', 'cost_anomaly_subscription': 'SubscriptionArn',
              'backup_restore_job': 'RestoreJobId', 'backup_restore_testing_plan': 'RestoreTestingPlanArn',
              'backup_restore_testing_selection': 'id', 'organization_delegated_admin': 'Id',
              'organization_service_access': 'ServicePrincipal'}
NATIVE_IDS['wafv2_appsync_association'] = 'ResourceArn'
READ_ACTIONS = {('appsync','list_graphql_apis')}
READ_ACTIONS.update({('route53resolver', 'list_firewall_rule_groups'), ('logs', 'describe_log_groups'), ('elbv2', 'describe_load_balancers')})
READ_ACTIONS.add(('wafv2', 'get_ip_set'))
NATIVE_IDS.update({kind: 'Id' for kind in ('resolver_firewall_rule_group_association', 'resolver_query_log_config', 'resolver_query_log_config_association')})
NATIVE_IDS.update({'resolver_firewall_rule': 'id', 'log_subscription_filter': 'id', 'log_account_subscription_policy': 'id', 'log_destination': 'arn', 'sns_topic_subscription': 'id', 'ec2_instance_type': 'InstanceType', 'eks_version_catalog': 'region', 'elbv2_listener': 'ListenerArn'})
READ_ACTIONS.add(('sns', 'list_topics'))
NATIVE_IDS.update({'inspector_finding': 'findingArn', 'securityhub_finding': 'Id'})
NATIVE_IDS['wafv2_ip_set'] = 'ARN'


def _waf_ip_sets(requests, session, region, account):
    """List and read IP sets; failed or inconsistent details never prove absence."""
    from .aws import ReadResult
    rows, failures, seen = [], [], set()
    partition = 'aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'
    for scope in ['REGIONAL'] + (['CLOUDFRONT'] if region == 'us-east-1' else []):
        read = requests.pages(session, 'wafv2', region, 'list_ip_sets', 'IPSets',
                              _tokens=('NextMarker', 'NextMarker'), Scope=scope, Limit=100)
        if read.status not in ('collected', 'empty'):
            failures.append(read)
        for summary in read.items:
            name, identifier, arn = (summary.get(key) for key in ('Name', 'Id', 'ARN')) if isinstance(summary, dict) else (None, None, None)
            prefix = 'regional' if scope == 'REGIONAL' else 'global'
            if (not isinstance(name, str) or not re.fullmatch(r'[\w-]{1,128}', name, re.ASCII)
                    or not isinstance(identifier, str) or not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}', identifier)
                    or arn != f'arn:{partition}:wafv2:{region}:{account}:{prefix}/ipset/{name}/{identifier}' or arn in seen):
                failures.append(ReadResult([], 'malformed', {'code': 'invalid_waf_ip_set_identity'}))
                continue
            seen.add(arn)
            detail = requests.detail(session, 'wafv2', region, 'get_ip_set', Name=name, Id=identifier, Scope=scope)
            if detail.get('collection_status') != 'collected':
                failures.append(ReadResult([], detail.get('collection_status', 'unknown'), detail.get('error')))
                continue
            item = detail.get('IPSet')
            addresses = item.get('Addresses') if isinstance(item, dict) else None
            try:
                valid = (isinstance(item, dict) and all(item.get(key) == summary.get(key) for key in ('Name', 'Id', 'ARN'))
                         and item.get('IPAddressVersion') in ('IPV4', 'IPV6') and isinstance(addresses, list)
                         and all(isinstance(value, str) and ipaddress.ip_network(value, strict=True).version ==
                                 (4 if item['IPAddressVersion'] == 'IPV4' else 6) for value in addresses)
                         and len(set(addresses)) == len(addresses))
            except ValueError:
                valid = False
            if not valid:
                failures.append(ReadResult([], 'malformed', {'code': 'invalid_waf_ip_set_detail'}))
                continue
            row = _pick(item, ['Name', 'Id', 'ARN', 'IPAddressVersion', 'Addresses'])
            row.update(Scope=scope, _provenance={'source_operation': 'GetIPSet', 'read_only': True})
            rows.append(row)
    return _finish(rows, failures)


def _security_findings(service, operation, expression, identity):
    """Own-account finding metadata; never retain descriptions or payloads.

    Organization administrators may receive other accounts' findings. Both
    the request filter and the returned native identities must bind the scope.
    The older organization-oriented Inspector inventory stays independent.
    """
    def fetch(requests, session, region, account):
        from .aws import ReadResult
        if service == 'inspector2':
            arguments = {'filterCriteria': {
                'awsAccountId': [{'comparison': 'EQUALS', 'value': account}],
                'findingStatus': [{'comparison': 'EQUALS', 'value': 'ACTIVE'}]}}
        else:
            arguments = {'Filters': {
                'AwsAccountId': [{'Comparison': 'EQUALS', 'Value': account}],
                'Region': [{'Comparison': 'EQUALS', 'Value': region}],
                'RecordState': [{'Comparison': 'EQUALS', 'Value': 'ACTIVE'}]}}
        if service == 'securityhub':
            arguments['_metadata_profile'] = 'securityhub-findings-metadata-v1'
        read = requests.pages(session, service, region, operation, expression, **arguments)
        rows, failures, seen = [], [], set()
        if read.status not in ('collected', 'empty'):
            failures.append(read)
        for item in read.items:
            value = item.get(identity) if isinstance(item, dict) else None
            owner = item.get('awsAccountId' if service == 'inspector2' else 'AwsAccountId') if isinstance(item, dict) else None
            valid = isinstance(value, str) and bool(value) and value not in seen and owner == account
            if service == 'inspector2':
                valid = valid and bool(re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:inspector2:' + re.escape(region) + ':' + re.escape(account) + r':finding/[A-Za-z0-9-]+', value or ''))
            else:
                valid = valid and item.get('Region') == region
            if not valid:
                failures.append(ReadResult([], 'malformed', {'code': 'invalid_security_finding_scope_or_identity'}))
                continue
            seen.add(value)
            fields = ('findingArn', 'awsAccountId', 'type', 'status', 'severity', ('packageVulnerabilityDetails', [('cvss', ['version', 'baseScore'])])) if service == 'inspector2' else ('Id', 'AwsAccountId', 'Region', ('Severity', ['Label']), 'CreatedAt', 'UpdatedAt', ('Workflow', ['Status']), 'RecordState')
            row = _pick(item, fields)
            row.update(id=value, AccountId=owner, Region=region)
            rows.append(row)
        return _finish(rows, failures)
    return fetch


def _finish(rows, failures):
    from .aws import ReadResult
    return ReadResult(rows, 'partial' if rows else failures[0].status, failures[0].error) if failures else ReadResult(rows, 'collected' if rows else 'empty')


def _native_list(service, operation, expression, fields, identity, arn_field=None):
    def fetch(requests, session, region, account):
        from .aws import ReadResult
        read = _projected(service, operation, expression, fields)(requests, session, region, account)
        rows, failures, seen = [], [], set()
        if read.status not in ('collected', 'empty'): failures.append(read)
        for row in read.items:
            value = row.get(identity)
            arn = row.get(arn_field) if arn_field else None
            if (not isinstance(value, str) or not value or value in seen
                    or (arn is not None and (not isinstance(arn, str) or not re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:' + re.escape(service) + ':' + re.escape(region) + ':' + re.escape(account) + r':.+', arn)))):
                failures.append(ReadResult([], 'malformed', {'code': 'invalid_native_inventory_identity'})); continue
            seen.add(value)
            rows.append(row)
        return _finish(rows, failures)
    return fetch


def _resolver_rules(requests, session, region, account):
    from .aws import ReadResult
    groups = requests.pages(session, 'route53resolver', region, 'list_firewall_rule_groups', 'FirewallRuleGroups')
    rows, failures, seen = [], [], set()
    if groups.status not in ('collected', 'empty'): failures.append(groups)
    for group in groups.items:
        gid, arn = group.get('Id'), group.get('Arn')
        if (not isinstance(gid, str) or not re.fullmatch(r'rslvr-frg-[A-Za-z0-9-]+', gid) or gid in seen
                or not isinstance(arn, str) or not re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:route53resolver:' + re.escape(region) + ':' + re.escape(account) + ':firewall-rule-group/' + re.escape(gid), arn)):
            failures.append(ReadResult([], 'malformed', {'code': 'invalid_dns_firewall_group'})); continue
        seen.add(gid)
        read = requests.pages(session, 'route53resolver', region, 'list_firewall_rules', 'FirewallRules', FirewallRuleGroupId=gid)
        if read.status not in ('collected', 'empty'): failures.append(read)
        identities = set()
        for item in read.items:
            priority = item.get('Priority')
            if item.get('FirewallRuleGroupId') != gid or type(priority) is not int or priority in identities:
                failures.append(ReadResult([], 'malformed', {'code': 'invalid_dns_firewall_rule'})); continue
            identities.add(priority)
            row = _pick(item, ['FirewallRuleGroupId', 'FirewallDomainListId', 'Action', 'Priority', 'Name', 'Status', 'Qtype', 'BlockResponse', 'CreationTime', 'ModificationTime'])
            row.update(id=gid + '/' + str(priority), _provenance={'source_operation': 'ListFirewallRules', 'read_only': True})
            rows.append(row)
    return _finish(rows, failures)


def _subscriptions(requests, session, region, account):
    """Read filter configuration, never claim that a SIEM received the logs."""
    from .aws import ReadResult
    groups = requests.pages(session, 'logs', region, 'describe_log_groups', 'logGroups')
    rows, failures, seen = [], [], set()
    if groups.status not in ('collected', 'empty'): failures.append(groups)
    for group in groups.items:
        name, arn = group.get('logGroupName'), group.get('logGroupArn', group.get('arn'))
        match = re.fullmatch(r'arn:(aws(?:-[a-z0-9-]+)?):logs:' + re.escape(region) + ':' + re.escape(account) + r':log-group:(.+)', arn) if isinstance(arn, str) else None
        if not isinstance(name, str) or not name or name in seen or not match or match[2] not in (name, name + ':*'):
            failures.append(ReadResult([], 'malformed', {'code': 'invalid_subscription_log_group'})); continue
        seen.add(name)
        canonical = 'arn:' + match[1] + ':logs:' + region + ':' + account + ':log-group:' + name
        read = requests.pages(session, 'logs', region, 'describe_subscription_filters', 'subscriptionFilters', logGroupName=name)
        if read.status not in ('collected', 'empty'): failures.append(read)
        identities = set()
        for item in read.items:
            fid = item.get('filterName')
            if not isinstance(fid, str) or not fid or fid in identities or item.get('logGroupName') != name:
                failures.append(ReadResult([], 'malformed', {'code': 'invalid_subscription_filter'})); continue
            identities.add(fid)
            row = _pick(item, ['filterName', 'logGroupName', 'destinationArn', 'roleArn', 'distribution', 'creationTime'])
            row.update(id=canonical + '/subscription-filter/' + fid, LogGroupArn=canonical,
                       DestinationArn=item.get('destinationArn'), _provenance={'source_operation': 'DescribeSubscriptionFilters', 'read_only': True})
            rows.append(row)
    return _finish(rows, failures)


def _account_subscription_policies(requests, session, region, account):
    """Read the regional account-level subscription, with no log-event access."""
    from .aws import ReadResult
    read = requests.pages(session, 'logs', region, 'describe_account_policies', 'accountPolicies',
                          policyType='SUBSCRIPTION_FILTER_POLICY')
    rows, failures, seen = [], [], set()
    if read.status not in ('collected', 'empty'):
        failures.append(read)
    for item in read.items:
        if not isinstance(item, dict):
            failures.append(ReadResult([], 'malformed', {'code': 'invalid_account_subscription_policy'}))
            continue
        name, owner, document = item.get('policyName'), item.get('accountId'), item.get('policyDocument')
        if (not isinstance(name, str) or not name or name in seen or
                owner not in (None, account) or item.get('policyType') != 'SUBSCRIPTION_FILTER_POLICY'):
            failures.append(ReadResult([], 'malformed', {'code': 'invalid_account_subscription_policy'}))
            continue
        seen.add(name)
        try:
            policy = json.loads(document) if isinstance(document, str) else None
        except (ValueError, TypeError):
            policy = None
        if not isinstance(policy, dict):
            failures.append(ReadResult([], 'malformed', {'code': 'invalid_account_subscription_document'}))
            continue
        rows.append({'id': f'{account}/{region}/log-account-policy/{name}', 'accountId': account,
                     'policyName': name, 'policyType': 'SUBSCRIPTION_FILTER_POLICY',
                     'DestinationArn': policy.get('DestinationArn'),
                     'selectionCriteria': item.get('selectionCriteria'),
                     '_provenance': {'source_operation': 'DescribeAccountPolicies', 'read_only': True}})
    return _finish(rows, failures)


def _sns_topic_subscriptions(requests, session, region, account):
    """Read each owned topic's subscribers without retaining endpoint values."""
    from .aws import ReadResult
    topics = requests.pages(session, 'sns', region, 'list_topics', 'Topics')
    rows, failures, seen_topics, seen_subscriptions = [], [], set(), set()
    if topics.status not in ('collected', 'empty'):
        failures.append(topics)
    partition = 'aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'
    for topic in topics.items:
        arn = topic.get('TopicArn') if isinstance(topic, dict) else None
        match = re.fullmatch(r'arn:' + partition + r':sns:' + re.escape(region) + ':' + re.escape(account) + r':([A-Za-z0-9_-]{1,256}(?:\.fifo)?)', arn) if isinstance(arn, str) else None
        if match is None or arn in seen_topics:
            failures.append(ReadResult([], 'malformed', {'code': 'invalid_sns_topic_identity'}))
            continue
        seen_topics.add(arn)
        read = requests.pages(session, 'sns', region, 'list_subscriptions_by_topic', 'Subscriptions', TopicArn=arn)
        if read.status not in ('collected', 'empty'):
            failures.append(read)
        for item in read.items:
            if not isinstance(item, dict) or item.get('TopicArn') != arn:
                failures.append(ReadResult([], 'malformed', {'code': 'invalid_sns_subscription_topic'}))
                continue
            owner, sub_arn, protocol = item.get('Owner'), item.get('SubscriptionArn'), item.get('Protocol')
            if (not isinstance(owner, str) or not re.fullmatch(r'[0-9]{12}', owner) or
                    not isinstance(protocol, str) or not protocol):
                failures.append(ReadResult([], 'malformed', {'code': 'invalid_sns_subscription_identity'}))
                continue
            if sub_arn == 'PendingConfirmation':
                endpoint = item.get('Endpoint')
                if not isinstance(endpoint, str) or not endpoint:
                    failures.append(ReadResult([], 'malformed', {'code': 'invalid_sns_pending_subscription'}))
                    continue
                identity = arn + '/pending/' + hashlib.sha256(endpoint.encode()).hexdigest()[:16]
            elif isinstance(sub_arn, str) and re.fullmatch(r'arn:' + partition + r':sns:' + re.escape(region) + ':' + owner + ':' + re.escape(match.group(1)) + r':[0-9a-fA-F-]{36}', sub_arn):
                identity = sub_arn
            else:
                failures.append(ReadResult([], 'malformed', {'code': 'invalid_sns_subscription_arn'}))
                continue
            if identity in seen_subscriptions:
                failures.append(ReadResult([], 'malformed', {'code': 'duplicate_sns_subscription'}))
                continue
            seen_subscriptions.add(identity)
            endpoint = item.get('Endpoint')
            endpoint_scope = None
            if protocol in ('http', 'https') and isinstance(endpoint, str):
                try:
                    parsed = urlsplit(endpoint)
                    host = parsed.hostname
                except ValueError:
                    parsed = None
                    host = None
                if parsed and parsed.scheme == protocol and host and not parsed.username and not parsed.password:
                    try:
                        endpoint_scope = 'public_ip' if ipaddress.ip_address(host).is_global else 'private_ip'
                    except ValueError:
                        endpoint_scope = 'dns' if '.' in host and not host.endswith(('.local', '.internal')) else 'local_name'
            elif protocol in ('email', 'email-json', 'sms', 'application'):
                endpoint_scope = 'external_delivery_candidate'
            elif protocol in ('sqs', 'lambda', 'firehose') and isinstance(endpoint, str):
                match_endpoint = re.fullmatch(r'arn:' + partition + r':(?:sqs|lambda|firehose):' +
                    re.escape(region) + r':([0-9]{12}):.+', endpoint)
                endpoint_scope = ('foreign_aws_account' if match_endpoint.group(1) != account else 'own_aws_account') if match_endpoint else 'unknown_aws_account'
            rows.append({'id': identity, 'TopicArn': arn, 'SubscriptionArn': sub_arn,
                         'Owner': owner, 'Protocol': protocol, 'EndpointScope': endpoint_scope,
                         '_provenance': {'source_operation': 'ListSubscriptionsByTopic', 'read_only': True}})
    return _finish(rows, failures)


def _eks_versions(requests, session, region, account):
    from .aws import ReadResult
    read = requests.pages(session, 'eks', region, 'describe_cluster_versions', 'clusterVersions', includeAll=True)
    if read.status not in ('collected', 'empty'): return ReadResult([], read.status, read.error)
    return ReadResult([{'region': region, 'versions': [_pick(row, ['clusterVersion', 'clusterType', 'versionStatus', 'status', 'endOfStandardSupportDate', 'endOfExtendedSupportDate']) for row in read.items],
                        '_provenance': {'source_operation': 'DescribeClusterVersions', 'read_only': True, 'includeAll': True}}], 'collected')


def _listeners(requests, session, region, account):
    from .aws import ReadResult
    parents = requests.pages(session, 'elbv2', region, 'describe_load_balancers', 'LoadBalancers')
    rows, failures, seen = [], [], set()
    if parents.status not in ('collected', 'empty'): failures.append(parents)
    for parent in parents.items:
        arn = parent.get('LoadBalancerArn')
        if not isinstance(arn, str) or not re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:elasticloadbalancing:' + re.escape(region) + ':' + re.escape(account) + r':loadbalancer/(app|net|gwy)/[^/?#]+/[^/?#]+', arn) or arn in seen:
            failures.append(ReadResult([], 'malformed', {'code': 'invalid_listener_load_balancer'})); continue
        seen.add(arn)
        read = requests.pages(session, 'elbv2', region, 'describe_listeners', 'Listeners', LoadBalancerArn=arn)
        if read.status not in ('collected', 'empty'): failures.append(read)
        identities = set()
        for item in read.items:
            rid = item.get('ListenerArn')
            if item.get('LoadBalancerArn') != arn or not isinstance(rid, str) or rid in identities or not rid.startswith(arn.replace(':loadbalancer/', ':listener/') + '/') or not re.fullmatch(r'[A-Za-z0-9-]+', rid.rsplit('/', 1)[-1]):
                failures.append(ReadResult([], 'malformed', {'code': 'invalid_listener_identity'})); continue
            identities.add(rid)
            rows.append(_pick(item, ['ListenerArn', 'LoadBalancerArn', 'Port', 'Protocol', 'SslPolicy', ('MutualAuthentication', ['Mode', 'TrustStoreArn', 'IgnoreClientCertificateExpiry']), ('Certificates', ['CertificateArn', 'IsDefault'])]))
    return _finish(rows, failures)


def _projected(service, operation, expression, fields, *, tokens=None):
    def fetch(requests, session, region, account):
        read = requests.pages(session, service, region, operation, expression, _tokens=tokens)
        read.items = [_pick(row, fields) for row in read.items]
        if service == 'backup' and operation == 'list_restore_jobs':
            for row in read.items:
                row['_provenance'] = {'source_operation': 'ListRestoreJobs', 'read_only': True,
                                      'optional_fields_complete': ['CreatedBy']}
        if service == 'ce' and operation == 'get_anomaly_monitors':
            for row in read.items:
                specification = row.get('MonitorSpecification')
                if isinstance(specification, str):
                    try:
                        decoded = json.loads(specification)
                    except (ValueError, TypeError):
                        continue
                    if isinstance(decoded, dict):row['MonitorSpecification'] = decoded
        return read
    return fetch


def _selections(requests, session, region, account):
    from .aws import ReadResult
    plans = requests.pages(session, 'backup', region, 'list_restore_testing_plans', 'RestoreTestingPlans')
    rows, failures = [], []
    if plans.status not in {'collected', 'empty'}:
        failures.append(plans)
    names = set()
    for plan in plans.items:
        name = plan.get('RestoreTestingPlanName')
        if not isinstance(name, str) or not name or name in names:
            failures.append(ReadResult([], 'malformed', {'code': 'invalid_restore_testing_plan_identity'}))
            continue
        names.add(name)
        read = requests.pages(session, 'backup', region, 'list_restore_testing_selections',
                              'RestoreTestingSelections', RestoreTestingPlanName=name)
        if read.status not in {'collected', 'empty'}:
            failures.append(read)
        for original in read.items:
            row = _pick(original, ['CreationTime', 'IamRoleArn', 'ProtectedResourceType',
                                  'RestoreTestingPlanName', 'RestoreTestingSelectionName', 'ValidationWindowHours'])
            selection = row.get('RestoreTestingSelectionName')
            if row.get('RestoreTestingPlanName') != name or not isinstance(selection, str) or not selection:
                failures.append(ReadResult([], 'malformed', {'code': 'invalid_restore_testing_selection_identity'}))
                continue
            row['id'] = name + '/' + selection
            rows.append(row)
    if failures:
        return ReadResult(rows, 'partial' if rows else failures[0].status, failures[0].error)
    return ReadResult(rows, 'collected' if rows else 'empty')


def _appsync_associations(requests,session,region,account):
    """Native per-resource WAF lookup; only a successful null ACL proves absence.

    https://docs.aws.amazon.com/cli/latest/reference/wafv2/get-web-acl-for-resource.html
    """
    from .aws import ReadResult
    apis=requests.pages(session,'appsync',region,'list_graphql_apis','graphqlApis')
    rows=[];failures=[];seen=set()
    if apis.status not in ('collected','empty'):failures.append(apis)
    for api in apis.items:
        arn=api.get('arn')
        match=re.fullmatch(r'arn:(aws(?:-[a-z0-9-]+)?):appsync:'+re.escape(region)+':'+re.escape(account)+r':apis/[A-Za-z0-9]+',arn)if isinstance(arn,str)else None
        if not match or api.get('apiId') != arn.rsplit('/',1)[-1] or arn in seen:
            failures.append(ReadResult([],'malformed',{'code':'invalid_appsync_api_identity'}));continue
        seen.add(arn)
        response=requests.detail(session,'wafv2',region,'get_web_acl_for_resource',ResourceArn=arn)
        if response.get('collection_status')!='collected':
            failures.append(ReadResult([],response.get('collection_status','unknown'),response.get('error')));continue
        acl=response.get('WebACL')
        if acl is None:
            acl_arn=''
        elif isinstance(acl,dict):
            acl_arn=acl.get('ARN')
            if not isinstance(acl_arn,str) or not re.fullmatch('arn:'+re.escape(match[1])+':wafv2:'+re.escape(region)+':'+re.escape(account)+r':regional/webacl/[^/?#]+/[^/?#]+',acl_arn):
                failures.append(ReadResult([],'malformed',{'code':'invalid_appsync_web_acl_identity'}));continue
        else:
            failures.append(ReadResult([],'malformed',{'code':'invalid_appsync_web_acl_response'}));continue
        rows.append({'ResourceArn':arn,'WebACLArn':acl_arn,
                     '_provenance':{'source_operation':'GetWebACLForResource','read_only':True}})
    if failures:return ReadResult(rows,'partial'if rows else failures[0].status,failures[0].error)
    return ReadResult(rows,'collected'if rows else'empty')


FETCHERS = {
    'cost_anomaly_monitor': _projected('ce', 'get_anomaly_monitors', 'AnomalyMonitors',
        ['MonitorArn', 'MonitorName', 'MonitorType', 'MonitorDimension', 'MonitorSpecification'],
        tokens=('NextPageToken', 'NextPageToken')),
    'cost_anomaly_subscription': _projected('ce', 'get_anomaly_subscriptions', 'AnomalySubscriptions',
        ['SubscriptionArn', 'SubscriptionName', 'AccountId', 'MonitorArnList', 'Frequency', 'Threshold',
         'ThresholdExpression', ('Subscribers', ['Address', 'Type', 'Status'])],
        tokens=('NextPageToken', 'NextPageToken')),
    'backup_restore_job': _projected('backup', 'list_restore_jobs', 'RestoreJobs',
        ['AccountId', 'RestoreJobId', 'RecoveryPointArn', 'SourceResourceArn', 'CreationDate',
         'CompletionDate', 'Status', 'ResourceType', ('CreatedBy', ['RestoreTestingPlanArn']),
         'ValidationStatus', 'DeletionStatus']),
    'backup_restore_testing_plan': _projected('backup', 'list_restore_testing_plans', 'RestoreTestingPlans',
        ['RestoreTestingPlanArn', 'RestoreTestingPlanName', 'CreationTime', 'LastExecutionTime', 'LastUpdateTime']),
    'backup_restore_testing_selection': _selections,
    'organization_delegated_admin': _projected('organizations', 'list_delegated_administrators',
        'DelegatedAdministrators', ['Id', 'Arn', 'Status', 'JoinedMethod', 'JoinedTimestamp', 'DelegationEnabledDate']),
    'organization_service_access': _projected('organizations', 'list_aws_service_access_for_organization',
        'EnabledServicePrincipals', ['ServicePrincipal', 'DateEnabled']),
    'wafv2_appsync_association': _appsync_associations,
    'resolver_firewall_rule_group_association': _native_list('route53resolver', 'list_firewall_rule_group_associations', 'FirewallRuleGroupAssociations', ['Id', 'Arn', 'Name', 'FirewallRuleGroupId', 'VpcId', 'Priority', 'Status', 'MutationProtection'], 'Id', 'Arn'),
    'resolver_firewall_rule': _resolver_rules,
    'resolver_query_log_config': _native_list('route53resolver', 'list_resolver_query_log_configs', 'ResolverQueryLogConfigs', ['Id', 'Arn', 'Name', 'OwnerId', 'DestinationArn', 'Status', 'ShareStatus'], 'Id', 'Arn'),
    'resolver_query_log_config_association': _native_list('route53resolver', 'list_resolver_query_log_config_associations', 'ResolverQueryLogConfigAssociations', ['Id', 'Arn', 'ResolverQueryLogConfigId', 'ResourceId', 'Status', 'Error'], 'Id', 'Arn'),
    'log_subscription_filter': _subscriptions,
    'log_account_subscription_policy': _account_subscription_policies,
    'log_destination': _native_list('logs', 'describe_destinations', 'destinations', ['destinationName', 'targetArn', 'roleArn', 'accessPolicy', 'arn', 'creationTime'], 'arn', 'arn'),
    'sns_topic_subscription': _sns_topic_subscriptions,
    'ec2_instance_type': _native_list('ec2', 'describe_instance_types', 'InstanceTypes', ['InstanceType', 'Hypervisor', 'CurrentGeneration'], 'InstanceType'),
    'eks_version_catalog': _eks_versions,
    'elbv2_listener': _listeners,
    'inspector_finding': _security_findings('inspector2', 'list_findings', 'findings', 'findingArn'),
    'securityhub_finding': _security_findings('securityhub', 'get_findings', 'Findings', 'Id'),
    'wafv2_ip_set': _waf_ip_sets,
}

# Shared Organizations reads retain exact account paths and policy documents.
from . import aws_organizations_native as _organizations_native
SPECS.update(_organizations_native.SPECS)
GLOBAL_TYPES.update(_organizations_native.GLOBAL_TYPES)
NATIVE_IDS.update(_organizations_native.NATIVE_IDS)
READ_ACTIONS.update(_organizations_native.READ_ACTIONS)
FETCHERS.update(_organizations_native.FETCHERS)

from . import aws_apigateway_native as _apigateway_native
SPECS.update(_apigateway_native.SPECS)
NATIVE_IDS.update(_apigateway_native.NATIVE_IDS)
READ_ACTIONS.update(_apigateway_native.READ_ACTIONS)
FETCHERS.update(_apigateway_native.FETCHERS)

from . import aws_identity_metrics_native as _identity_metrics_native
SPECS.update(_identity_metrics_native.SPECS)
GLOBAL_TYPES.update(_identity_metrics_native.GLOBAL_TYPES)
NATIVE_IDS.update(_identity_metrics_native.NATIVE_IDS)
READ_ACTIONS.update(_identity_metrics_native.READ_ACTIONS)
FETCHERS.update(_identity_metrics_native.FETCHERS)

from . import aws_transport_native as _transport_native
SPECS.update(_transport_native.SPECS)
NATIVE_IDS.update(_transport_native.NATIVE_IDS)
READ_ACTIONS.update(_transport_native.READ_ACTIONS)
FETCHERS.update(_transport_native.FETCHERS)

# Native Identity Center assignment/user-status joins.
from . import aws_identity_center_native as _identity_center_native
SPECS.update(_identity_center_native.SPECS)
NATIVE_IDS.update(_identity_center_native.NATIVE_IDS)
READ_ACTIONS.update(_identity_center_native.READ_ACTIONS)
FETCHERS.update(_identity_center_native.FETCHERS)

# Native enabled-region and Shield metric-location evidence.
from . import aws_region_shield_native as _region_shield_native
SPECS.update(_region_shield_native.SPECS)
NATIVE_IDS.update(_region_shield_native.NATIVE_IDS)
READ_ACTIONS.update(_region_shield_native.READ_ACTIONS)
FETCHERS.update(_region_shield_native.FETCHERS)

from . import aws_public_ingress_native as _public_ingress_native
SPECS.update(_public_ingress_native.SPECS)
NATIVE_IDS.update(_public_ingress_native.NATIVE_IDS)
READ_ACTIONS.update(_public_ingress_native.READ_ACTIONS)
FETCHERS.update(_public_ingress_native.FETCHERS)

from . import aws_s3_backup_native as _s3_backup_native
SPECS.update(_s3_backup_native.SPECS)
NATIVE_IDS.update(_s3_backup_native.NATIVE_IDS)
READ_ACTIONS.update(_s3_backup_native.READ_ACTIONS)
GLOBAL_TYPES.update(_s3_backup_native.GLOBAL_TYPES)
FETCHERS.update(_s3_backup_native.FETCHERS)

from . import aws_resource_policy_native as _resource_policy_native
SPECS.update(_resource_policy_native.SPECS)
NATIVE_IDS.update(_resource_policy_native.NATIVE_IDS)
READ_ACTIONS.update(_resource_policy_native.READ_ACTIONS)
FETCHERS.update(_resource_policy_native.FETCHERS)

from . import aws_waf_inventory_native as _waf_inventory_native
SPECS.update(_waf_inventory_native.SPECS)
GLOBAL_TYPES.update(_waf_inventory_native.GLOBAL_TYPES)
NATIVE_IDS.update(_waf_inventory_native.NATIVE_IDS)
READ_ACTIONS.update(_waf_inventory_native.READ_ACTIONS)
FETCHERS.update(_waf_inventory_native.FETCHERS)

from . import aws_kms_enclave_native as _kms_enclave_native
SPECS.update(_kms_enclave_native.SPECS)
NATIVE_IDS.update(_kms_enclave_native.NATIVE_IDS)
FETCHERS.update(_kms_enclave_native.FETCHERS)

from . import aws_ssm_inventory_events_native as _ssm_inventory_events_native
SPECS.update(_ssm_inventory_events_native.SPECS)
NATIVE_IDS.update(_ssm_inventory_events_native.NATIVE_IDS)
FETCHERS.update(_ssm_inventory_events_native.FETCHERS)

from . import aws_priority_tags_native as _priority_tags_native
SPECS.update(_priority_tags_native.SPECS)
NATIVE_IDS.update(_priority_tags_native.NATIVE_IDS)
READ_ACTIONS.update(_priority_tags_native.READ_ACTIONS)
FETCHERS.update(_priority_tags_native.FETCHERS)
