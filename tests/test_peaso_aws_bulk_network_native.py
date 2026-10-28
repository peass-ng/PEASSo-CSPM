"""SDK-validated DNS, logs and regional metadata inventories with honest gaps."""
import copy
import pytest
from test_peaso_aws_bulk_inventory import sdk, ACCOUNT, REGION
from peaso.collectors import aws, aws_bulk_inventory as facts
from peaso.snapshot import make_snapshot
from tests.archived_check_contract import evaluate_snapshot

SCOPE = ACCOUNT + '/' + REGION
GROUP = 'rslvr-frg-12345678901234567'
GROUP_ARN = f'arn:aws:route53resolver:{REGION}:{ACCOUNT}:firewall-rule-group/{GROUP}'
LOG = f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:qa'
DEST = f'arn:aws:firehose:{REGION}:{ACCOUNT}:deliverystream/qa'
BALANCER = f'arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/qa/1234567890123456'
LISTENER = BALANCER.replace(':loadbalancer/', ':listener/') + '/1234567890123456'


def finding_fixture(kind):
 if kind == 'inspector_finding':
  from datetime import datetime, timezone
  return {'findingArn': f'arn:aws:inspector2:{REGION}:{ACCOUNT}:finding/qa-123',
   'awsAccountId': ACCOUNT, 'type': 'PACKAGE_VULNERABILITY', 'status': 'ACTIVE',
   'description': 'private-payload-marker', 'remediation': {'recommendation': {'text': 'private-payload-marker'}},
   'severity': 'HIGH', 'firstObservedAt': datetime(2026, 10, 10, tzinfo=timezone.utc),
   'lastObservedAt': datetime(2026, 10, 11, tzinfo=timezone.utc), 'resources': [{'type': 'AWS_EC2_INSTANCE', 'id': 'i-0123456789abcdef0'}],
   'packageVulnerabilityDetails': {'vulnerabilityId': 'CVE-2026-12345', 'source': 'NVD',
    'cvss': [{'version': '3.1', 'baseScore': 8.1, 'source': 'NVD', 'scoringVector': 'private-payload-marker'}]}}
 return {'SchemaVersion': '2018-10-08', 'Id': 'own-finding',
  'ProductArn': f'arn:aws:securityhub:{REGION}::product/aws/securityhub', 'GeneratorId': 'qa',
  'AwsAccountId': ACCOUNT, 'Region': REGION, 'CreatedAt': '2026-10-10T00:00:00Z',
  'UpdatedAt': '2026-10-10T02:00:00Z', 'Title': 'private-payload-marker',
  'Description': 'private-payload-marker', 'Resources': [], 'RecordState': 'ACTIVE',
  'Severity': {'Label': 'HIGH', 'Original': 'private-payload-marker'}, 'Workflow': {'Status': 'NOTIFIED'}}


def finding_request(kind):
 if kind == 'inspector_finding':
  return {'filterCriteria': {'awsAccountId': [{'comparison': 'EQUALS', 'value': ACCOUNT}],
   'findingStatus': [{'comparison': 'EQUALS', 'value': 'ACTIVE'}]}}
 return {'Filters': {'AwsAccountId': [{'Comparison': 'EQUALS', 'Value': ACCOUNT}],
  'Region': [{'Comparison': 'EQUALS', 'Value': REGION}],
  'RecordState': [{'Comparison': 'EQUALS', 'Value': 'ACTIVE'}]}}


@pytest.mark.parametrize('kind', ['inspector_finding', 'securityhub_finding'])
@pytest.mark.parametrize('state', ['complete', 'empty', 'denied', 'paginated', 'limited', 'duplicate', 'foreign', 'foreign_region'])
def test_security_finding_native_scope_pages_failures_and_payload_exclusion(sdk, kind, state):
 import json
 session, add = sdk;service, operation, key = facts.SPECS[kind];stub=add(service)
 row=finding_fixture(kind);arguments=finding_request(kind);options={'retries':0}
 if state=='foreign':row['awsAccountId' if kind=='inspector_finding' else 'AwsAccountId']='999999999999'
 if state=='foreign_region':
  if kind=='inspector_finding':row['findingArn']=row['findingArn'].replace(REGION,'eu-west-1')
  else:row['Region']='eu-west-1'
 token='nextToken' if kind=='inspector_finding' else 'NextToken'
 if state=='denied':stub.add_client_error(operation,'AccessDeniedException',expected_params=arguments)
 else:
  response={key:[] if state=='empty' else [row,row] if state=='duplicate' else [row]}
  if state in ('paginated','limited'):response[token]='cursor'
  stub.add_response(operation,response,arguments)
  if state=='paginated':stub.add_response(operation,{key:[]},{**arguments,token:'cursor'})
  if state=='limited':options['max_pages']=1
 read=facts.FETCHERS[kind](aws.Requests(options),session,REGION,ACCOUNT)
 expected='collected' if state in ('complete','paginated') else 'empty' if state=='empty' else 'denied' if state=='denied' else 'partial' if state in ('limited','duplicate') else 'malformed'
 assert read.status==expected
 assert 'private-payload-marker' not in json.dumps(read.items,default=str)
 assert all(r['AccountId']==ACCOUNT and r['Region']==REGION for r in read.items)
 stub.assert_no_pending_responses()


@pytest.mark.parametrize('kind', ['inspector_finding', 'securityhub_finding'])
@pytest.mark.parametrize('state', ['pass','fail','missing_policy','denied','foreign_scope','partial'])
def test_native_security_findings_reach_registered_engine_with_explicit_policy(sdk, kind, state):
 session,add=sdk;service,operation,key=facts.SPECS[kind];stub=add(service);row=finding_fixture(kind)
 if state=='fail':
  if kind=='inspector_finding':row['packageVulnerabilityDetails']['cvss'][0]['version']='2.0'
  else:row['Workflow']['Status']='NEW'
 stub.add_response(operation,{key:[row]},finding_request(kind))
 read=facts.FETCHERS[kind](aws.Requests({}),session,REGION,ACCOUNT)
 policy={'approved_cvss_version':'3.1','approved_response_hours':4}
 envelope={'type':kind,'scope':SCOPE,'status':read.status,'items':read.items}
 if state in ('denied','partial'):envelope['status']=state
 if state=='denied':envelope['items']=[]
 if state=='foreign_scope':envelope['scope']='999999999999/'+REGION
 snapshot=make_snapshot('aws',[SCOPE],[envelope],created_at='2026-10-12T00:00:00Z',metadata={} if state=='missing_policy' else {'parameters':policy})
 check='aws_inspector_cvss_version' if kind=='inspector_finding' else 'aws_incident_workflow_sla'
 finding=evaluate_snapshot(snapshot,checks=[check])['findings'][0]
 expected='DENIED' if state=='denied' else 'UNKNOWN'
 if kind=='inspector_finding' and state in ('pass','fail'):expected=state.upper()
 assert finding['status']==expected
 if kind=='securityhub_finding' and state in ('pass','fail'):
  assert 'workflow transition history' in str(finding['evidence'])
 stub.assert_no_pending_responses()

SIMPLE = {
 'resolver_firewall_rule_group_association': ('route53resolver', 'list_firewall_rule_group_associations', 'FirewallRuleGroupAssociations', {'Id': 'rslvr-frgassoc-qa', 'Arn': f'arn:aws:route53resolver:{REGION}:{ACCOUNT}:firewall-rule-group-association/qa', 'FirewallRuleGroupId': GROUP, 'VpcId': 'vpc-qa', 'Status': 'COMPLETE'}),
 'resolver_query_log_config': ('route53resolver', 'list_resolver_query_log_configs', 'ResolverQueryLogConfigs', {'Id': 'rqlc-qa', 'Arn': f'arn:aws:route53resolver:{REGION}:{ACCOUNT}:resolver-query-log-config/qa', 'DestinationArn': LOG, 'Status': 'CREATED'}),
 'resolver_query_log_config_association': ('route53resolver', 'list_resolver_query_log_config_associations', 'ResolverQueryLogConfigAssociations', {'Id': 'rqlca-qa', 'ResolverQueryLogConfigId': 'rqlc-qa', 'ResourceId': 'vpc-qa', 'Status': 'ACTIVE'}),
 'log_destination': ('logs', 'describe_destinations', 'destinations', {'destinationName': 'qa', 'arn': f'arn:aws:logs:{REGION}:{ACCOUNT}:destination:qa', 'targetArn': DEST, 'accessPolicy': '{"Statement":[]}'}),
 'ec2_instance_type': ('ec2', 'describe_instance_types', 'InstanceTypes', {'InstanceType': 't3.small', 'Hypervisor': 'nitro', 'CurrentGeneration': True}),
}

@pytest.mark.parametrize('kind', SIMPLE)
@pytest.mark.parametrize('state', ['complete', 'empty', 'denied', 'paginated', 'limited', 'duplicate', 'missing_id'])
def test_simple_native_shapes_pagination_and_errors(sdk, kind, state):
 session, add = sdk
 service, operation, key, original = SIMPLE[kind]
 stub = add(service); row = copy.deepcopy(original)
 options = {'retries': 0}
 token = 'nextToken' if service == 'logs' else 'NextToken'
 if state == 'missing_id': row.pop(facts.NATIVE_IDS[kind])
 if state == 'denied': stub.add_client_error(operation, 'AccessDeniedException', expected_params={})
 else:
  response = {key: [] if state == 'empty' else [row, row] if state == 'duplicate' else [row]}
  if state in ('paginated', 'limited'): response[token] = 'next'
  stub.add_response(operation, response, {})
  if state == 'limited': options['max_pages'] = 1
  if state == 'paginated': stub.add_response(operation, {key: []}, {token: 'next'})
 read = facts.FETCHERS[kind](aws.Requests(options), session, REGION, ACCOUNT)
 assert read.status == ('empty' if state == 'empty' else 'collected' if state in ('complete', 'paginated') else 'partial' if state in ('limited', 'duplicate') else 'denied' if state == 'denied' else 'malformed')
 if kind == 'log_destination' and state == 'complete':
  assert read.items[0]['accessPolicy'] == row['accessPolicy']
 stub.assert_no_pending_responses()

@pytest.mark.parametrize('action, expected', [('BLOCK', 'PASS'), ('ALLOW', 'FAIL')])
def test_native_dns_firewall_configuration_can_pass_or_fail(sdk, action, expected):
 session, add = sdk; stub = add('route53resolver')
 assoc = SIMPLE['resolver_firewall_rule_group_association'][3]
 stub.add_response('list_firewall_rule_group_associations', {'FirewallRuleGroupAssociations': [assoc]}, {})
 stub.add_response('list_firewall_rule_groups', {'FirewallRuleGroups': [{'Id': GROUP, 'Arn': GROUP_ARN}]}, {})
 stub.add_response('list_firewall_rules', {'FirewallRules': [{'FirewallRuleGroupId': GROUP, 'FirewallDomainListId': 'rslvr-fdl-qa', 'Priority': 100, 'Action': action}]}, {'FirewallRuleGroupId': GROUP})
 req = aws.Requests({}); associations = facts.FETCHERS['resolver_firewall_rule_group_association'](req, session, REGION, ACCOUNT); rules = facts.FETCHERS['resolver_firewall_rule'](req, session, REGION, ACCOUNT)
 collections = [{'type': 'vpc', 'scope': SCOPE, 'status': 'collected', 'items': [{'VpcId': 'vpc-qa'}]}]
 collections.extend({'type': kind, 'scope': SCOPE, 'status': read.status, 'items': read.items} for kind, read in [('resolver_firewall_rule_group_association', associations), ('resolver_firewall_rule', rules)])
 snapshot = make_snapshot('aws', [SCOPE], collections, metadata={'parameters': {'approved_firewall_domain_list_ids': ['rslvr-fdl-qa']}})
 assert evaluate_snapshot(snapshot, checks=['aws_cis_route53_dns_firewall'])['findings'][0]['status'] == expected
 stub.assert_no_pending_responses()

@pytest.mark.parametrize('state', ['empty_parent', 'denied_parent', 'foreign_parent', 'partial_parent', 'denied_child', 'foreign_child', 'duplicate_child'])
def test_resolver_rule_parent_boundaries(sdk, state):
 session, add = sdk; stub = add('route53resolver'); options = {'retries': 0}
 group = {'Id': GROUP, 'Arn': GROUP_ARN}
 if state == 'denied_parent': stub.add_client_error('list_firewall_rule_groups', 'AccessDeniedException', expected_params={})
 else:
  if state == 'foreign_parent': group['Arn'] = GROUP_ARN.replace(ACCOUNT, '999999999999')
  response = {'FirewallRuleGroups': [] if state == 'empty_parent' else [group]}
  if state == 'partial_parent': response['NextToken'] = 'next'; options['max_pages'] = 1
  stub.add_response('list_firewall_rule_groups', response, {})
 if state in ('partial_parent', 'denied_child', 'foreign_child', 'duplicate_child'):
  if state == 'denied_child': stub.add_client_error('list_firewall_rules', 'AccessDeniedException', expected_params={'FirewallRuleGroupId': GROUP})
  else:
   row = {'FirewallRuleGroupId': GROUP if state != 'foreign_child' else GROUP + 'foreign', 'Priority': 100, 'Action': 'BLOCK', 'FirewallDomainListId': 'rslvr-fdl-qa'}
   stub.add_response('list_firewall_rules', {'FirewallRules': [row, row] if state == 'duplicate_child' else [row]}, {'FirewallRuleGroupId': GROUP})
 read = facts.FETCHERS['resolver_firewall_rule'](aws.Requests(options), session, REGION, ACCOUNT)
 assert (read.status == 'empty') if state == 'empty_parent' else (read.status not in ('empty', 'collected'))
 stub.assert_no_pending_responses()

@pytest.mark.parametrize('state', ['complete', 'empty_parent', 'denied_parent', 'foreign_parent', 'partial_parent', 'empty_child', 'denied_child', 'foreign_child', 'duplicate_child'])
def test_log_subscription_native_metadata_and_failure_boundaries(sdk, state):
 session, add = sdk; stub = add('logs'); options = {'retries': 0}
 group = {'logGroupName': 'qa', 'arn': LOG + ':*'}
 if state == 'denied_parent': stub.add_client_error('describe_log_groups', 'AccessDeniedException', expected_params={})
 else:
  if state == 'foreign_parent': group['arn'] = group['arn'].replace(ACCOUNT, '999999999999')
  response = {'logGroups': [] if state == 'empty_parent' else [group]}
  if state == 'partial_parent': response['nextToken'] = 'next'; options['max_pages'] = 1
  stub.add_response('describe_log_groups', response, {})
 if state in ('complete', 'partial_parent', 'empty_child', 'denied_child', 'foreign_child', 'duplicate_child'):
  if state == 'denied_child': stub.add_client_error('describe_subscription_filters', 'AccessDeniedException', expected_params={'logGroupName': 'qa'})
  else:
   row = {'filterName': 'qa', 'logGroupName': 'foreign' if state == 'foreign_child' else 'qa', 'destinationArn': DEST, 'filterPattern': 'sensitive-marker'}
   stub.add_response('describe_subscription_filters', {'subscriptionFilters': [] if state == 'empty_child' else [row, row] if state == 'duplicate_child' else [row]}, {'logGroupName': 'qa'})
 read = facts.FETCHERS['log_subscription_filter'](aws.Requests(options), session, REGION, ACCOUNT)
 if state == 'complete':
  assert read.status == 'collected' and read.items[0]['LogGroupArn'] == LOG and read.items[0]['DestinationArn'] == DEST
  assert 'filterPattern' not in read.items[0]
 elif state in ('empty_parent', 'empty_child'): assert read.status == 'empty'
 else: assert read.status not in ('collected', 'empty')
 stub.assert_no_pending_responses()


@pytest.mark.parametrize('state', ['complete', 'empty', 'denied', 'partial', 'malformed', 'foreign'])
def test_log_account_subscription_policy_native_read(sdk, state):
 import json
 session, add = sdk; stub = add('logs'); options = {'retries': 0}
 policy = {'accountId': ACCOUNT if state != 'foreign' else '999999999999',
           'policyName': 'export', 'policyType': 'SUBSCRIPTION_FILTER_POLICY',
           'policyDocument': json.dumps({'DestinationArn': f'arn:aws:logs:{REGION}:999999999999:destination:partner'}),
           'selectionCriteria': 'LogGroupName NOT IN ["skip"]'}
 if state == 'malformed': policy['policyDocument'] = '{invalid'
 params = {'policyType': 'SUBSCRIPTION_FILTER_POLICY'}
 if state == 'denied': stub.add_client_error('describe_account_policies', 'AccessDeniedException', expected_params=params)
 else:
  response = {'accountPolicies': [] if state == 'empty' else [policy]}
  if state == 'partial': response['nextToken'] = 'next'; options['max_pages'] = 1
  stub.add_response('describe_account_policies', response, params)
 requests = aws.Requests(options)
 read = facts.FETCHERS['log_account_subscription_policy'](requests, session, REGION, ACCOUNT)
 assert read.status == ('collected' if state == 'complete' else 'empty' if state == 'empty' else 'denied' if state == 'denied' else 'partial' if state == 'partial' else 'malformed')
 if state == 'complete':
  assert read.items[0]['DestinationArn'].endswith(':destination:partner')
  assert read.items[0]['selectionCriteria'] == policy['selectionCriteria']
  assert 'policyDocument' not in read.items[0]
 assert requests.calls == 1
 stub.assert_no_pending_responses()


@pytest.mark.parametrize('state', ['confirmed', 'pending', 'empty', 'denied', 'foreign_topic'])
def test_sns_topic_subscriptions_read_by_topic_without_endpoint(sdk, state):
 import json
 session, add = sdk; stub = add('sns')
 topic = f'arn:aws:sns:{REGION}:{ACCOUNT}:events'
 owner = '999988887777'
 subscription = f'arn:aws:sns:{REGION}:{owner}:events:12345678-1234-1234-1234-123456789012'
 listed = topic.replace(ACCOUNT, owner) if state == 'foreign_topic' else topic
 stub.add_response('list_topics', {'Topics': [{'TopicArn': listed}]}, {})
 if state not in ('foreign_topic',):
  if state == 'denied':
   stub.add_client_error('list_subscriptions_by_topic', 'AuthorizationError', expected_params={'TopicArn': topic})
  else:
   item = {'TopicArn': topic, 'Owner': owner, 'Protocol': 'https',
           'SubscriptionArn': 'PendingConfirmation' if state == 'pending' else subscription,
           'Endpoint': 'https://example.invalid/?private-token=do-not-store'}
   stub.add_response('list_subscriptions_by_topic', {'Subscriptions': [] if state == 'empty' else [item]}, {'TopicArn': topic})
 requests = aws.Requests({'retries': 0})
 read = facts.FETCHERS['sns_topic_subscription'](requests, session, REGION, ACCOUNT)
 expected = {'confirmed': 'collected', 'pending': 'collected', 'empty': 'empty',
             'denied': 'unknown', 'foreign_topic': 'malformed'}[state]
 assert read.status == expected
 assert 'private-token' not in json.dumps(read.items)
 if state == 'confirmed': assert read.items[0]['Owner'] == owner and read.items[0]['SubscriptionArn'] == subscription
 if state == 'pending': assert read.items[0]['id'].startswith(topic + '/pending/')
 assert requests.calls == (1 if state == 'foreign_topic' else 2)
 stub.assert_no_pending_responses()

@pytest.mark.parametrize('version_status, allowed, expected', [('STANDARD_SUPPORT', ['STANDARD'], 'PASS'), ('EXTENDED_SUPPORT', ['STANDARD'], 'FAIL'), ('EXTENDED_SUPPORT', ['EXTENDED'], 'PASS'), ('UNSUPPORTED', ['STANDARD', 'EXTENDED'], 'FAIL'), ('FUTURE', ['STANDARD'], 'UNKNOWN')])
def test_eks_native_catalogue_uses_provider_status_without_fabricated_support(version_status, allowed, expected, sdk):
 session, add = sdk; stub = add('eks')
 stub.add_response('describe_cluster_versions', {'clusterVersions': [{'clusterVersion': '1.30', 'versionStatus': version_status}]}, {'includeAll': True})
 read = facts.FETCHERS['eks_version_catalog'](aws.Requests({}), session, REGION, ACCOUNT)
 assert 'supportType' not in read.items[0]['versions'][0]
 cluster = {'name': 'qa', 'Cluster': {'collection_status': 'collected', 'cluster': {'name': 'qa', 'arn': f'arn:aws:eks:{REGION}:{ACCOUNT}:cluster/qa', 'version': '1.30'}}}
 snapshot = make_snapshot('aws', [SCOPE], [{'type': 'eks_cluster', 'scope': SCOPE, 'status': 'collected', 'items': [cluster]}, {'type': 'eks_version_catalog', 'scope': SCOPE, 'status': read.status, 'items': read.items}], metadata={'compliance_policy': {'eks_version_support': {'status': 'collected', 'allowed_support_types': allowed}}})
 assert evaluate_snapshot(snapshot, checks=['aws_eks_cluster_supported_version_catalog'])['findings'][0]['status'] == expected
 stub.assert_no_pending_responses()

@pytest.mark.parametrize('state', ['complete', 'empty_parent', 'denied_parent', 'foreign_parent', 'partial_parent', 'empty_child', 'denied_child', 'foreign_child', 'duplicate_child'])
def test_listener_native_metadata_is_bound_to_real_load_balancer(sdk, state):
 session, add = sdk; stub = add('elbv2'); options = {'retries': 0}
 if state == 'denied_parent': stub.add_client_error('describe_load_balancers', 'AccessDeniedException', expected_params={})
 else:
  response = {'LoadBalancers': [] if state == 'empty_parent' else [{'LoadBalancerArn': BALANCER.replace(ACCOUNT, '999999999999') if state == 'foreign_parent' else BALANCER}]}
  if state == 'partial_parent': response['NextMarker'] = 'next'; options['max_pages'] = 1
  stub.add_response('describe_load_balancers', response, {})
 if state in ('complete', 'partial_parent', 'empty_child', 'denied_child', 'foreign_child', 'duplicate_child'):
  if state == 'denied_child': stub.add_client_error('describe_listeners', 'AccessDeniedException', expected_params={'LoadBalancerArn': BALANCER})
  else:
   row = {'ListenerArn': LISTENER, 'LoadBalancerArn': BALANCER + 'foreign' if state == 'foreign_child' else BALANCER, 'Protocol': 'HTTPS', 'Port': 443, 'MutualAuthentication': {'Mode': 'verify', 'TrustStoreArn': f'arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:truststore/qa/1234567890123456'}}
   stub.add_response('describe_listeners', {'Listeners': [] if state == 'empty_child' else [row, row] if state == 'duplicate_child' else [row]}, {'LoadBalancerArn': BALANCER})
 read = facts.FETCHERS['elbv2_listener'](aws.Requests(options), session, REGION, ACCOUNT)
 if state == 'complete': assert read.status == 'collected' and read.items[0]['MutualAuthentication']['Mode'] == 'verify'
 elif state in ('empty_parent', 'empty_child'): assert read.status == 'empty'
 else: assert read.status not in ('collected', 'empty')
 stub.assert_no_pending_responses()

@pytest.mark.parametrize('foreign', [False, True])
@pytest.mark.parametrize('external_id, expected', [('customer-one', 'PASS'), ('', 'FAIL')])
def test_native_iam_global_scope_is_accepted_only_for_bound_account(external_id, expected, foreign):
 account = '999999999999' if foreign else ACCOUNT
 arn = f'arn:aws:iam::{account}:role/partner'
 role = {'Arn': arn, 'AccountId': account, 'RoleName': 'partner', 'AssumeRolePolicyDocument': {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'AWS': 'arn:aws:iam::222222222222:root'}, 'Action': 'sts:AssumeRole', 'Condition': {'StringEquals': {'sts:ExternalId': external_id}}}]}}
 scope = ACCOUNT + '/global'
 snapshot = make_snapshot('aws', [scope], [{'type': 'iam_role', 'scope': scope, 'status': 'collected', 'items': [role], 'global': True, 'account_id': ACCOUNT}], metadata={'compliance_policy': {'partner_roles': {'status': 'collected', 'customer_roles': [{'role_arn': arn, 'customer_id': 'customer-one'}]}}, 'approved_policy': {'scope': scope, 'checks': {'aws_partner_role_external_id_present': {'customer_role_arns': [arn], 'provider_principal_arns': ['arn:aws:iam::222222222222:root']}}}})
 for cid in ('aws_partner_role_external_id_present', 'aws_partner_role_external_ids_unique'):
  assert evaluate_snapshot(snapshot, checks=[cid])['findings'][0]['status'] == ('UNKNOWN' if foreign else expected)
