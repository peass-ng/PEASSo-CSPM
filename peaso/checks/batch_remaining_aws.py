"""Reviewed AWS pending predicates over complete, read-only collected facts.

Import by the registry only after companion signed mappings are admitted. No API
client or collector is imported here; missing detail and partial pages are UNKNOWN.
"""
from __future__ import annotations

from ipaddress import ip_network
import json
import re

from . import register, result, unknown, statements, array
from .facts import Unavailable, complete_items, get, guard, list_of_objects, memoized, optional

SPECS = {
    'aws_security_group_common_ports_ipv6_all': ('security_group', 'hardening', 'medium', 'Security groups restrict common IPv6 ports', 'Remove world IPv6 ingress on common service ports.', 'scope'),
    'aws_security_group_ssh_ipv6_all': ('security_group', 'hardening', 'medium', 'Security groups restrict IPv6 SSH ingress', 'Restrict IPv6 SSH ingress to approved ranges.', 'scope'),
    'aws_security_group_tcp_udp_ipv6_all': ('security_group', 'hardening', 'medium', 'Security groups restrict IPv6 TCP and UDP ingress', 'Restrict world IPv6 TCP and UDP ingress.', 'scope'),
    'aws_msk_in_cluster_tls_enabled': ('msk_cluster', 'hardening', 'medium', 'MSK broker-to-broker encryption is enabled', 'Enable in-cluster encryption on provisioned MSK clusters.', 'resource'),
    'aws_client_vpn_authentication_configured': ('client_vpn_endpoint', 'hardening', 'medium', 'Client VPN endpoint uses authentication', 'Configure supported Client VPN authentication.', 'resource'),
    'aws.nist.codebuild_exact_aws_key_env_names': ('codebuild_project', 'hardening', 'medium', 'CodeBuild projects avoid plaintext AWS access key variables', 'Use secret references instead of plaintext AWS access key variables.', 'resource'),
    'aws.pci.codebuild.aws_key_environment_vars': ('codebuild_project', 'hardening', 'high', 'CodeBuild projects do not declare static AWS key variables', 'Remove AWS access key environment variables of every type.', 'resource'),
    'aws_g6_ecs_all_containers_logging': ('ecs_task_definition', 'hardening', 'medium', 'All ECS task containers have logging configured', 'Configure logging for each active task container.', 'resource'),
    'aws_ec2_running_instance_cpu_alarm_present': ('instance', 'hardening', 'medium', 'Running EC2 CPU capacity alarm', 'Add an actionable CPUUtilization alarm per running instance.', 'resource'),
    'aws_sqs_queue_depth_alarm_present': ('sqs_queue', 'hardening', 'medium', 'SQS queue backlog alarm', 'Add an actionable queue-depth alarm for each queue.', 'resource'),
    'aws_g6_rds_cluster_members_enhanced_monitoring': ('rds_cluster', 'hardening', 'medium', 'RDS cluster members use Enhanced Monitoring', 'Enable enhanced monitoring for applicable cluster members.', 'resource'),
    'aws_nist_dynamodb_table_encrypted_with_kms': ('dynamodb_table', 'hardening', 'medium', 'DynamoDB table should be encrypted with AWS KMS', 'Use KMS server-side encryption on the table.', 'resource'),
    'aws_route53_hosted_zone_dnssec_enabled': ('route53_zone', 'hardening', 'medium', 'Public Route 53 hosted zone signs DNSSEC', 'Enable DNSSEC signing and an active key-signing key on public hosted zones.', 'resource'),
    'aws_lambda_code_signing_configured': ('lambda_function', 'hardening', 'medium', 'Lambda code signing validates deployed packages', 'Attach a code-signing configuration with approved publishers and Enforce policy.', 'resource'),
    'aws_cis_lightsail_bucket_access_logging': ('lightsail_bucket', 'hardening', 'medium', 'Lightsail storage buckets have request logging', 'Enable access logs to a configured destination bucket.', 'resource'),
    'aws_g6_ecr_public_repositories_absent': ('ecr_repository','exposure','high','Private ECR repository policy has no wildcard AWS principal','Review a literal wildcard AWS principal in the private ECR repository policy.','resource'),
    'aws_ec2_status_alarm': ('instance','hardening','high','EC2 failures trigger status-check alarms','Configure an actionable StatusCheckFailed alarm for each applicable instance.','resource'),
    'aws_cis_lambda_config_recorded': ('lambda_function','hardening','medium','AWS Config records Lambda functions','Enable a running customer-managed AWS Config recorder that includes AWS::Lambda::Function.','resource'),
    'aws_nist_rds_db_instance_and_cluster_enhanced_monitoring_enabled': ('rds_instance','hardening','medium','RDS DB instance and cluster enhanced monitoring should be enabled','Enable Enhanced Monitoring and a monitoring role on each applicable RDS instance.','resource'),
    'aws.nist.all_cloudtrail_destination_bucket_access_logging': ('cloudtrail','hardening','medium','All CloudTrail destination buckets enable S3 access logging','Enable S3 server access logging on each in-account CloudTrail destination bucket.','resource'),
    'aws_g6_all_cloudtrail_destination_bucket_access_logging': ('cloudtrail','hardening','medium','Every CloudTrail destination bucket has access logging','Enable S3 server access logging with a destination bucket and prefix.','resource'),
    'aws_nist_cloudtrail_s3_logging_enabled': ('cloudtrail','hardening','medium','Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket','Enable S3 server access logging on the bucket used by each logging trail.','resource'),
    'aws_kms_imported_key_origin_spec': ('kms_key','hardening','medium','Imported KMS key has approved origin and algorithm','Replace nonconforming imported KMS material with an approved key specification and usage.','resource'),
    'aws.pci.iam.wildcard_action_scoped_resource': ('iam_customer_policy','hardening','high','IAM policies avoid all actions on scoped resources','Scope declared Allow actions to the intended API actions for each resource ARN.','resource'),
    'aws_eventbridge_iam_user_change_alert': ('event_rule','hardening','medium','Alert on IAM user changes','Create enabled CloudTrail EventBridge rules covering each required IAM user and access-key change with a target.','scope'),
    'aws_eventbridge_snapshot_change_alert': ('event_rule','hardening','medium','Alert on snapshot manipulations','Create enabled CloudTrail EventBridge rules covering snapshot create, attribute changes, and deletion with a target.','scope'),
    'aws.nist.cloudtrail_cloudwatch_integration': ('cloudtrail','hardening','medium','Logging CloudTrail trails have a CloudWatch Logs destination','Enable a resolvable CloudWatch Logs destination for each logging home-Region trail.','resource'),
    'aws_g6_cloudtrail_all_trails_cloudwatch_integration': ('cloudtrail','hardening','medium','All CloudTrail trails integrate with CloudWatch Logs','Configure a CloudWatch Logs log group and delivery role for each home-Region trail.','resource'),
    'aws_backup_failure_notification': ('backup_vault','hardening','high','Backup failure notifications are configured','Configure BACKUP_JOB_FAILED notifications to an SNS topic on the backup vault.','resource'),
    'aws_cis_batch_job_cloudwatch_logging': ('batch_job_definition','hardening','medium','Batch jobs send logs to CloudWatch Logs','Configure awslogs and an awslogs-group on every active Batch job container.','resource'),
    'aws.pci.codepipeline.first_stage_single_deploy': ('codepipeline_pipeline','hardening','medium','CodePipeline first deployment stage has one deploy action','Keep at most one Deploy category action in the first deployment stage.','resource'),
    'aws_fedramp_cloudtrail_destination_kms': ('cloudtrail','hardening','medium','CloudTrail and linked log groups use customer-managed KMS keys','Configure enabled customer-managed KMS keys for the trail and any linked CloudWatch log group.','resource'),
    'aws_g6_cloudtrail_kms_destination_join': ('cloudtrail','hardening','medium','CloudTrail and its CloudWatch log destination use CMKs','Configure enabled customer-managed KMS keys for each trail and its configured CloudWatch log group.','resource'),
    'aws_nist_cloudtrail_trail_logs_encrypted_with_kms_cmk': ('cloudtrail','hardening','medium','CloudTrail trail logs should be encrypted with KMS CMK','Configure an enabled customer-managed KMS key on each logging trail and linked log group.','resource'),
    'aws_sns_delivery_failure_alarm_present': ('sns_topic','hardening','medium','SNS delivery failure alarm','Configure an actionable NumberOfNotificationsFailed alarm on each topic with confirmed subscribers.','resource'),
}
KEYS = {'msk_cluster':'ClusterArn','client_vpn_endpoint':'ClientVpnEndpointId',
        'codebuild_project':'name','redshift_cluster':'ClusterIdentifier',
        'ecs_task_definition':'taskDefinitionArn','instance':'InstanceId',
        'sqs_queue':'QueueUrl','rds_cluster':'DBClusterIdentifier',
        'rds_instance':'DBInstanceIdentifier','dynamodb_table':'TableName',
        'route53_zone':'Id','lambda_function':'FunctionArn','lightsail_bucket':'name',
        'ecr_public_repository':'repositoryArn','ecr_repository':'repositoryArn'}
KEYS['config_recorder']='name'
KEYS['cloudtrail']='TrailARN'
KEYS['bucket']='Name'
KEYS['kms_key']='KeyArn'
KEYS['iam_policy']='Arn'
KEYS['log_group']='logGroupName'
KEYS['backup_vault']='BackupVaultName'
KEYS['batch_job_definition']='jobDefinitionArn'
KEYS['codepipeline_pipeline']='name'
KEYS['sns_topic']='TopicArn'
ARN_FIELDS = {'msk_cluster':('ClusterArn','kafka'),
              'lambda_function':('FunctionArn','lambda'),
              'ecs_task_definition':('taskDefinitionArn','ecs'),
              'cloudwatch_alarm':('AlarmArn','cloudwatch'),
              'rds_cluster':('DBClusterArn','rds'),
              'rds_instance':('DBInstanceArn','rds'),
              'dynamodb_table':('TableArn','dynamodb'),
              'lightsail_bucket':('arn','lightsail')}
ARN_FIELDS['kms_key']=('KeyArn','kms')
ARN_FIELDS['event_rule']=('Arn','events')
ARN_FIELDS['batch_job_definition']=('jobDefinitionArn','batch')
ARN_FIELDS['sns_topic']=('TopicArn','sns')


def _scope(index):
    context = get(index, 'context', dict)
    if get(context, 'provider', str) != 'aws':
        raise Unavailable('AWS provider mismatch')
    scope = get(context, 'scope', str)
    if not re.fullmatch(r'[0-9]{12}/[a-z0-9-]+', scope):
        raise Unavailable('AWS account/Region scope unavailable')
    return context, scope


def _rows(index, kind):
    _, scope = _scope(index)
    def build():
        expected_scope=scope.split('/')[0]+'/global' if kind in ('bucket','iam_policy') else scope
        pages = get(index, 'collections', dict).get(kind)
        if not isinstance(pages, list) or len(pages) != 1 or pages[0].get('scope') != expected_scope or pages[0].get('type') != kind or pages[0].get('status') not in ('collected','empty'):
            raise Unavailable('complete same-scope collection unavailable: '+kind)
        if kind in ('bucket','iam_policy') and (pages[0].get('global') is not True or pages[0].get('account_id')!=scope.split('/')[0]):
            raise Unavailable('global AWS inventory account scope unverified')
        items = complete_items(index, kind)
        wrappers = index.get(kind, [])
        if not isinstance(wrappers, list):
            raise Unavailable('malformed AWS projection')
        if any(not isinstance(w, dict) or w.get('provider') not in (None,'aws') or w.get('type') != kind or w.get('scope') != expected_scope for w in wrappers):
            raise Unavailable('foreign or malformed AWS projection')
        if len(items) != len(pages[0].get('items', [])) or items != pages[0]['items']:
            raise Unavailable('AWS collection and projection differ')
        if pages[0]['status']=='empty' and items:
            raise Unavailable('nonempty collection marked empty')
        key = KEYS.get(kind, 'GroupId' if kind=='security_group' else None)
        if key:
            identities = [get(row,key,str) for row in items]
            if any(not value for value in identities) or len(set(identities)) != len(identities):
                raise Unavailable('missing or duplicate AWS identity')
        account,region=scope.split('/')
        if kind in ARN_FIELDS:
            arn_field,service=ARN_FIELDS[kind]
            for row in items:
                if arn_field in row and not get(row,arn_field,str).startswith(f'arn:aws:{service}:{region}:{account}:'):
                    raise Unavailable('foreign AWS resource ARN')
        if kind=='sqs_queue':
            for row in items:
                if not get(row,'QueueUrl',str).startswith(f'https://sqs.{region}.amazonaws.com/{account}/'):
                    raise Unavailable('foreign SQS queue URL')
        if kind=='bucket' and any(get(row,'AccountId',str)!=account for row in items):
            raise Unavailable('foreign S3 bucket owner')
        if kind=='iam_policy' and any(get(row,'AccountId',str)!=account or not get(row,'Arn',str).startswith(f'arn:aws:iam::{account}:policy/') for row in items):
            raise Unavailable('foreign or noncustomer IAM policy')
        if kind=='event_rule' and any(get(row,'EventBusName',str)!='default' for row in items):
            raise Unavailable('nondefault EventBridge bus in default-bus inventory')
        return items
    return memoized(index, ('batch_aws_rows',kind), build)


def _member(item,index,kind):
    key=KEYS[kind]
    identity=get(item,key,str)
    def build():
        return {get(row,key,str):row for row in _rows(index,kind)}
    member_map=memoized(index,('batch_aws_member',kind),build)
    if identity not in member_map or member_map[identity]!=item:
        raise Unavailable('AWS resource not in scoped inventory')
    return identity


def _ipv6_rules(index):
    hits=[]
    for group in _rows(index,'security_group'):
        group_id=get(group,'GroupId',str)
        if 'OwnerId' in group and get(group,'OwnerId',str)!=_scope(index)[1].split('/')[0]:
            raise Unavailable('foreign security group owner')
        for rule in list_of_objects(get(group,'IpPermissions',list)):
            protocol=get(rule,'IpProtocol',str).lower()
            if protocol not in ('-1','tcp','udp','6','17') and not re.fullmatch(r'\d{1,3}',protocol):
                raise Unavailable('unrecognized security-group protocol')
            world=False
            for source in list_of_objects(optional(rule,'Ipv6Ranges',[],list)):
                network=ip_network(get(source,'CidrIpv6',str),strict=False)
                if network.version!=6:raise Unavailable('non-IPv6 ingress range')
                world |= network.prefixlen==0
            if not world:continue
            if protocol in ('-1',): low,high=0,65535
            elif protocol in ('tcp','udp','6','17'):
                low,high=get(rule,'FromPort',int),get(rule,'ToPort',int)
                if not 0<=low<=high<=65535:raise Unavailable('invalid port range')
            else:low,high=None,None
            hits.append((group_id,protocol,low,high))
    return hits


def _security_group(check_id,item,index):
    context,_=_scope(index)
    if item!=context:raise Unavailable('scope target mismatch')
    bad=[]
    for group,protocol,low,high in _ipv6_rules(index):
        if check_id=='aws_security_group_tcp_udp_ipv6_all': matched=protocol in ('-1','tcp','udp','6','17')
        else:
            ports=(22,) if check_id=='aws_security_group_ssh_ipv6_all' else (20,21,22,3306,3389,4333)
            matched=protocol=='-1' or protocol in ('tcp','6') and any(low<=p<=high for p in ports)
        if matched:bad.append({'group_id':group,'protocol':protocol,'from_port':low,'to_port':high})
    return result(bool(bad), offending_rules=bad, semantics='declared IPv6 ingress only')


def _msk(item,index):
    arn=_member(item,index,'msk_cluster');kind=get(item,'ClusterType',str)
    if kind=='SERVERLESS':return 'NOT_APPLICABLE',{'cluster_arn':arn,'reason':'serverless cluster has no provisioned broker field'}
    if kind!='PROVISIONED':return unknown('unrecognized MSK cluster type')
    detail=get(item,'Detail.ClusterInfo',dict)
    if get(detail,'ClusterArn',str)!=arn:raise Unavailable('MSK detail identity mismatch')
    enabled=get(detail,'Provisioned.EncryptionInfo.EncryptionInTransit.InCluster',bool)
    return result(not enabled,cluster_arn=arn,in_cluster_tls=enabled)


def _vpn(item,index):
    identity=_member(item,index,'client_vpn_endpoint');state=get(item,'Status.Code',str)
    if state in ('pending-associate','pending-acceptance','deleting','deleted','failed'):
        return 'NOT_APPLICABLE',{'endpoint_id':identity,'state':state}
    if state!='available':return unknown('unrecognized Client VPN state')
    certificate=optional(item,'ServerCertificateArn','',str)
    options=list_of_objects(optional(item,'AuthenticationOptions',[],list))
    methods=[get(option,'Type',str) for option in options]
    if any(method not in ('certificate-authentication','directory-service-authentication','federated-authentication') for method in methods):
        return unknown('unrecognized Client VPN authentication type')
    return result(not certificate or not methods,endpoint_id=identity,server_certificate_present=bool(certificate),authentication_types=methods)


def _codebuild(item,index,any_type):
    name=_member(item,index,'codebuild_project')
    detail=get(item,'Configuration',dict)
    if get(detail,'collection_status',str)!='collected':raise Unavailable('CodeBuild detail unavailable')
    projects=list_of_objects(get(detail,'projects',list))
    if len(projects)!=1 or get(projects[0],'name',str)!=name:raise Unavailable('CodeBuild detail identity mismatch')
    variables=list_of_objects(get(projects[0],'environment.environmentVariables',list))
    matches=[]
    for variable in variables:
        # CodeBuild documents omitted type as PLAINTEXT in EnvironmentVariable.
        key=get(variable,'name',str);kind=optional(variable,'type','PLAINTEXT',str)
        if kind not in ('PLAINTEXT','PARAMETER_STORE','SECRETS_MANAGER'):raise Unavailable('CodeBuild variable type unrecognized')
        if ((key in ('AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY')) if any_type else (key.upper() in ('AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY') and kind=='PLAINTEXT')):
            matches.append(key)
    return result(bool(matches),project_name=name,matching_variable_names=sorted(set(matches)))


def _ecs(item,index):
    arn=_member(item,index,'ecs_task_definition')
    if get(item,'Definition.collection_status',str)!='collected':
        raise Unavailable('DescribeTaskDefinition detail unavailable')
    detail=get(item,'Definition.taskDefinition',dict)
    if get(detail,'taskDefinitionArn',str)!=arn:raise Unavailable('ECS task detail identity mismatch')
    if get(detail,'status',str)!='ACTIVE':return 'NOT_APPLICABLE',{'task_definition_arn':arn}
    containers=list_of_objects(get(detail,'containerDefinitions',list))
    if not containers:raise Unavailable('ECS task has no container definitions')
    bad=[]
    for container in containers:
        name=get(container,'name',str)
        if not name:raise Unavailable('container identity missing')
        logging=container.get('logConfiguration')
        if logging is None:bad.append(name)
        elif not isinstance(logging,dict):raise Unavailable('malformed log configuration')
        elif not get(logging,'logDriver',str):bad.append(name)
    return result(bool(bad),task_definition_arn=arn,containers_without_log_driver=bad)


def _alarm_match(alarm,namespace,metric,dimension,value):
    if get(alarm,'Namespace',str)!=namespace or get(alarm,'MetricName',str)!=metric:return False
    dimensions=list_of_objects(get(alarm,'Dimensions',list))
    parsed=[(get(row,'Name',str),get(row,'Value',str)) for row in dimensions]
    if parsed!=[(dimension,value)]:return False
    if not get(alarm,'ActionsEnabled',bool):return False
    actions=get(alarm,'AlarmActions',list)
    return isinstance(actions,list) and bool(actions) and all(isinstance(x,str) and x for x in actions)


# Only these two expression forms have a bounded, local namespace proof. A
# non-matching expression remains relevant to every namespace for absence checks.
_INSIGHTS_SCHEMA = re.compile(
    r'\s*SELECT\s+(?:AVG|COUNT|MAX|MIN|SUM)\s*\(\s*(?:[A-Za-z_][A-Za-z0-9_]*|"[A-Za-z_][A-Za-z0-9_]*")\s*\)'
    r'\s+FROM\s+SCHEMA\s*\(\s*"([A-Za-z0-9_./-]+)"'
    r'(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)*\s*\)\s*', re.IGNORECASE)
_MATH_TOKEN = re.compile(r'\s*([A-Za-z][A-Za-z0-9_]*|(?:\d+(?:\.\d*)?|\.\d+)(?:[Ee][+-]?\d+)?|[()+\-*/,])')
_QUERY_ID = re.compile(r'[a-z][A-Za-z0-9_]*\Z')


def _closed_alarm_math(expression, ids):
    """Return local query references for basic arithmetic/FILL; never evaluate it."""
    if not isinstance(expression, str) or not 0 < len(expression) <= 2048:
        return None
    tokens = []
    pos = 0
    while pos < len(expression) and len(tokens) < 256:
        match = _MATH_TOKEN.match(expression, pos)
        if match is None:
            return None
        tokens.append(match.group(1))
        pos = match.end()
    if pos != len(expression) or not tokens:
        return None
    cursor = 0
    refs = set()

    def peek():
        return tokens[cursor] if cursor < len(tokens) else None

    def take(expected=None):
        nonlocal cursor
        token = peek()
        if token is None or expected is not None and token != expected:
            raise ValueError('unsupported math syntax')
        cursor += 1
        return token

    def number():
        token = peek()
        if token in ('+', '-'):
            take()
            token = peek()
        if token is None or not re.fullmatch(r'(?:\d+(?:\.\d*)?|\.\d+)(?:[Ee][+-]?\d+)?', token):
            raise ValueError('unsupported numeric literal')
        take()

    def factor(depth):
        if depth > 32:
            raise ValueError('math nesting limit')
        token = peek()
        if token in ('+', '-'):
            take()
            factor(depth + 1)
        elif token == '(':
            take('(')
            expression_part(depth + 1)
            take(')')
        elif token == 'FILL':
            take('FILL')
            take('(')
            ref = take()
            if ref not in ids:
                raise ValueError('unknown local query')
            refs.add(ref)
            take(',')
            number()
            take(')')
        elif token in ids:
            refs.add(take())
        else:
            number()

    def term(depth):
        factor(depth)
        while peek() in ('*', '/'):
            take()
            factor(depth)

    def expression_part(depth):
        term(depth)
        while peek() in ('+', '-'):
            take()
            term(depth)

    try:
        expression_part(0)
        if cursor != len(tokens) or not refs:
            return None
    except ValueError:
        return None
    return refs


def _alarm_source_namespaces(row):
    """Return bound input namespaces, or None when an alarm could use any."""
    try:
        # Only a genuine omitted direct-metric identity permits a math proof.
        # A retained null, stale field, or field coverage marker is unresolved.
        guard(row)
        coverage = row.get('_coverage', {})
        if any(field in row or field in coverage for field in ('Namespace', 'MetricName')):
            return None
        queries = get(row, 'Metrics', list)
        if not 0 < len(queries) <= 20:
            return None
        by_id = {}
        for query in queries:
            ident = get(query, 'Id', str)
            if not _QUERY_ID.fullmatch(ident) or ident in by_id:
                return None
            stat = optional(query, 'MetricStat', None, dict)
            expression = optional(query, 'Expression', None, str)
            if (stat is None) == (expression is None):
                return None
            # Bound every expression before either SQL or math namespace proof.
            if expression is not None and not 0 < len(expression) <= 2048:
                return None
            by_id[ident] = (stat, expression)
        namespaces = set()
        references = {}
        for ident, (stat, expression) in by_id.items():
            if stat is not None:
                metric = get(stat, 'Metric', dict)
                ns = get(metric, 'Namespace', str)
                name = get(metric, 'MetricName', str)
                dimensions = list_of_objects(optional(metric, 'Dimensions', [], list))
                for dimension in dimensions:
                    get(dimension, 'Name', str)
                    get(dimension, 'Value', str)
                period = get(stat, 'Period', int)
                statistic = get(stat, 'Stat', str)
                if not ns or not name or period <= 0 or not statistic:
                    return None
                namespaces.add(ns)
                references[ident] = set()
            else:
                sql = _INSIGHTS_SCHEMA.fullmatch(expression)
                if sql is not None:
                    namespaces.add(sql.group(1))
                    references[ident] = set()
                else:
                    refs = _closed_alarm_math(expression, by_id)
                    if refs is None:
                        return None
                    references[ident] = refs
    except Unavailable:
        return None
    # Local names must lead to a metric source; cycles and constant-only
    # expressions do not establish a sound namespace boundary.
    completed = set()
    def visit(ident, active):
        if ident in active:
            return False
        if ident in completed:
            return True
        if not all(visit(ref, active | {ident}) for ref in references[ident]):
            return False
        completed.add(ident)
        return True
    if not all(visit(ident, set()) for ident in by_id) or not namespaces:
        return None
    return frozenset(namespaces)


def _alarm(item,index,kind,namespace,metric,dimension,value):
    identity=_member(item,index,kind)
    def build():
        by_metric={}
        unresolved_by_namespace={}
        unresolved_any=[]
        # Validate collection identity/completeness before considering any
        # positive. Unsupported same-namespace alarms block absence only there.
        for row in _rows(index,'cloudwatch_alarm'):
            try:
                ns=get(row,'Namespace',str)
            except Unavailable as exc:
                source_namespaces=_alarm_source_namespaces(row)
                targets=unresolved_any if source_namespaces is None else None
                if targets is not None:
                    targets.append(str(exc))
                else:
                    for source_namespace in source_namespaces:
                        unresolved_by_namespace.setdefault(source_namespace,[]).append(str(exc))
                continue
            if not ns:
                unresolved_any.append('empty metric namespace')
                continue
            if 'Metrics' in row or 'Metrics' in row.get('_coverage', {}):
                unresolved_any.append('mixed or unread metric-data-query alarm')
                continue
            try:
                name=get(row,'MetricName',str)
                dimensions=list_of_objects(get(row,'Dimensions',list))
                parsed=[(get(d,'Name',str),get(d,'Value',str)) for d in dimensions]
                if len(parsed)!=1:continue
                if not get(row,'ActionsEnabled',bool):continue
                actions=get(row,'AlarmActions',list)
                if not actions or any(not isinstance(a,str) or not a for a in actions):continue
                by_metric.setdefault((ns,name,*parsed[0]),[]).append(get(row,'AlarmArn',str))
            except Unavailable as exc:
                unresolved_by_namespace.setdefault(ns,[]).append(str(exc))
        return by_metric,unresolved_by_namespace,unresolved_any
    alarms,by_namespace,unresolved_any=memoized(index,('batch_aws_alarm_map',),build)
    matches=alarms.get((namespace,metric,dimension,value),[])
    unresolved_count=len(unresolved_any)+len(by_namespace.get(namespace,[]))
    if not matches and unresolved_count:
        return unknown('alarm absence cannot be established from unresolved native alarms',
                       unresolved_alarm_count=unresolved_count)
    return result(not matches,resource_id=identity,matching_alarm_arns=matches)


def _cpu(item,index):
    identity=get(item,'InstanceId',str)
    state=get(item,'State.Name',str)
    if state in ('stopped','stopping','terminated','shutting-down','pending'):
        _member(item,index,'instance');return 'NOT_APPLICABLE',{'instance_id':identity,'state':state}
    if state!='running':return unknown('unrecognized EC2 state')
    return _alarm(item,index,'instance','AWS/EC2','CPUUtilization','InstanceId',identity)


def _sqs(item,index):
    url=get(item,'QueueUrl',str);name=url.rsplit('/',1)[-1]
    if not name or not url.startswith('https://'):raise Unavailable('SQS queue URL malformed')
    return _alarm(item,index,'sqs_queue','AWS/SQS','ApproximateNumberOfMessagesVisible','QueueName',name)


def _status_alarm(item,index):
    state=get(item,'State.Name',str)
    if state!='running':return unknown('stopped-instance owner scope not resolved')
    identity=get(item,'InstanceId',str)
    return _alarm(item,index,'instance','AWS/EC2','StatusCheckFailed','InstanceId',identity)


def _rds(item,index):
    identity=_member(item,index,'rds_cluster')
    members=list_of_objects(get(item,'DBClusterMembers',list))
    instances=memoized(index,('batch_aws_member','rds_instance'),lambda:{get(row,'DBInstanceIdentifier',str):row for row in _rows(index,'rds_instance')})
    bad=[]
    for member in members:
        name=get(member,'DBInstanceIdentifier',str)
        if name not in instances:raise Unavailable('RDS cluster member detail unavailable')
        row=instances[name]
        if get(row,'DBInstanceClass',str)=='db.m1.small':continue
        if get(row,'MonitoringInterval',int)==0 or not get(row,'MonitoringRoleArn',str) or not get(row,'EnhancedMonitoringResourceArn',str):bad.append(name)
    return result(bool(bad),cluster_id=identity,noncompliant_members=bad)


def _rds_instance(item,index):
    identity=_member(item,index,'rds_instance')
    def validate_members():
        instances={get(row,'DBInstanceIdentifier',str):row for row in _rows(index,'rds_instance')}
        for cluster in _rows(index,'rds_cluster'):
            cluster_id=get(cluster,'DBClusterIdentifier',str)
            for member in list_of_objects(get(cluster,'DBClusterMembers',list)):
                name=get(member,'DBInstanceIdentifier',str)
                if name not in instances or get(instances[name],'DBClusterIdentifier',str)!=cluster_id:
                    raise Unavailable('RDS cluster member join incomplete or foreign')
        return True
    memoized(index,('batch_aws_rds_members_valid',),validate_members)
    interval=get(item,'MonitoringInterval',int)
    if interval<0:raise Unavailable('invalid RDS monitoring interval')
    role=optional(item,'MonitoringRoleArn','',str)
    resource=optional(item,'EnhancedMonitoringResourceArn','',str)
    return result(interval==0 or not role or not resource,instance_id=identity,monitoring_interval=interval,
                  monitoring_role_present=bool(role),monitoring_resource_present=bool(resource))


def _dynamodb(item,index):
    identity=_member(item,index,'dynamodb_table');detail=get(item,'Table.Table',dict)
    if get(detail,'TableName',str)!=identity:raise Unavailable('DynamoDB table detail identity mismatch')
    from peaso.collectors.aws_config_account_native import region_partition
    account,region=_scope(index)[1].split('/')
    partition=region_partition(region)
    if 'TableArn' in detail:
        if get(detail,'TableArn',str)!=f'arn:{partition}:dynamodb:{region}:{account}:table/{identity}':
            raise Unavailable('DynamoDB table detail ARN identity mismatch')
    if 'SSEDescription' not in detail and 'SSEDescription' not in detail.get('_coverage',{}):
        return result(True,table_name=identity,reason='complete table detail has no KMS SSE description')
    sse=get(detail,'SSEDescription',dict)
    sse_type=get(sse,'SSEType',str);arn=get(sse,'KMSMasterKeyArn',str);state=get(sse,'Status',str)
    if sse_type not in ('KMS','AES256') or state not in ('ENABLED','ENABLING','DISABLING','DISABLED','UPDATING'):
        return unknown('unrecognized DynamoDB encryption state')
    if state in ('ENABLING','DISABLING','UPDATING'):
        return unknown('SSE change in progress',table_name=identity,state=state)
    if arn and not re.fullmatch(rf'arn:{re.escape(str(partition))}:kms:{re.escape(region)}:{account}:key/[A-Za-z0-9_-]+',arn):
        raise Unavailable('DynamoDB KMS key ARN is malformed or outside table scope')
    return result(sse_type!='KMS' or not arn or state!='ENABLED',table_name=identity,sse_type=sse_type,key_arn_present=bool(arn),state=state)


def _dnssec(item,index):
    identity=_member(item,index,'route53_zone')
    private=get(item,'Config.PrivateZone',bool)
    if private:return 'NOT_APPLICABLE',{'zone_id':identity,'reason':'private hosted zone'}
    detail=get(item,'DNSSEC',dict)
    if get(detail,'collection_status',str) not in ('collected','empty') or get(detail,'HostedZoneId',str)!=identity:
        raise Unavailable('Route 53 DNSSEC detail unavailable or foreign')
    state=get(detail,'Status.ServeSignature',str)
    if state not in ('SIGNING','NOT_SIGNING'):return unknown('unrecognized DNSSEC serving state')
    keys=list_of_objects(get(detail,'KeySigningKeys',list))
    statuses=[get(row,'Status',str) for row in keys]
    if any(s not in ('ACTIVE','INACTIVE','DELETING','ACTION_NEEDED') for s in statuses):
        return unknown('unrecognized key-signing state')
    return result(state!='SIGNING' or 'ACTIVE' not in statuses,zone_id=identity,serve_signature=state,key_statuses=statuses)


def _signing(item,index):
    identity=_member(item,index,'lambda_function')
    state=get(item,'Configuration.State',str)
    if state in ('Pending','Inactive','Failed'):
        return 'NOT_APPLICABLE',{'function_arn':identity,'state':state}
    if state!='Active':return unknown('unrecognized Lambda state')
    package=optional(item,'PackageType',None,str)
    configured_package=optional(get(item,'Configuration',dict),'PackageType',None,str)
    if configured_package is not None and package is not None and configured_package!=package:
        return unknown('Lambda package type disagrees with function configuration')
    package=package if package is not None else configured_package
    if package=='Image':
        return 'NOT_APPLICABLE',{'function_arn':identity,'reason':'image package is outside Lambda code signing'}
    if package not in (None,'Zip'):
        return unknown('unrecognized Lambda package type')
    signing=get(item,'CodeSigning',dict)
    if get(signing,'collection_status',str)!='collected':
        raise Unavailable('Lambda code-signing detail unavailable')
    name=get(item,'FunctionName',str) if 'FunctionName' in item else None
    if name is not None and (not name or not identity.endswith(':function:'+name)):
        raise Unavailable('Lambda function name and ARN mismatch')
    # Some successful no-attachment responses omit FunctionName. Accept only
    # exact collector request provenance when both response identities are absent.
    if 'FunctionName' in signing:
        returned=get(signing,'FunctionName',str)
        if name is None or returned not in (name,identity):
            raise Unavailable('Lambda code-signing detail belongs to a foreign function')
    elif 'FunctionArn' not in signing:
        request=signing.get('_request')
        if name is None or request!={'operation':'get_function_code_signing_config','FunctionName':name}:
            raise Unavailable('Lambda code-signing detail identity unavailable')
    if 'FunctionArn' in signing and get(signing,'FunctionArn',str)!=identity:
        raise Unavailable('Lambda code-signing detail belongs to a foreign function')
    config_arn=optional(signing,'CodeSigningConfigArn','',str)
    if not config_arn:return result(True,function_arn=identity,reason='no code-signing config')
    detail=get(item,'CodeSigningConfig',dict)
    if get(detail,'collection_status',str)!='collected':raise Unavailable('code-signing configuration unavailable')
    config=get(detail,'CodeSigningConfig',dict)
    if get(config,'CodeSigningConfigArn',str)!=config_arn:
        raise Unavailable('code-signing configuration identity mismatch')
    publishers=get(config,'AllowedPublishers.SigningProfileVersionArns',list)
    if not isinstance(publishers,list) or any(not isinstance(v,str) or not v for v in publishers):
        raise Unavailable('malformed signing publisher inventory')
    policy=get(config,'CodeSigningPolicies.UntrustedArtifactOnDeployment',str)
    if policy not in ('Enforce','Warn'):return unknown('unrecognized code-signing policy')
    return result(not publishers or policy!='Enforce',function_arn=identity,publisher_count=len(publishers),policy=policy)


def _lightsail(item,index):
    identity=_member(item,index,'lightsail_bucket')
    logging=get(item,'accessLogConfig',dict)
    enabled=get(logging,'enabled',bool)
    destination=optional(logging,'destination','',str)
    return result(not enabled or not destination,bucket_name=identity,enabled=enabled,destination_present=bool(destination))


def _private_ecr_policy(item,index):
    # Pinned Steampipe ecr_repository_prohibit_public_access SQL selects the
    # regional private aws_ecr_repository.policy_std, after plugin canonicalization.
    arn=_member(item,index,'ecr_repository')
    _,scope=_scope(index)
    account,region=scope.split('/')
    name=get(item,'repositoryName',str)
    metadata=get(get(index,'context',dict),'metadata',dict)
    callers=metadata.get('caller_identities',[])
    if 'caller_identities' in metadata:
        if not isinstance(callers,list) or not callers:
            raise Unavailable('private ECR caller identity unavailable')
        partitions={match.group(1) for caller in callers if isinstance(caller,dict) and caller.get('Account')==account
                    for match in [re.fullmatch(r'arn:(aws(?:-us-gov|-cn)?):(?:iam|sts)::'+account+r':.+',str(caller.get('Arn','')))] if match}
        if len(partitions)!=1 or not arn.startswith('arn:'+next(iter(partitions))+':'):
            raise Unavailable('private ECR ARN partition disagrees with caller identity')
    if (get(item,'registryId',str)!=account or not name or
            not re.fullmatch(r'arn:aws(?:-us-gov|-cn)?:ecr:'+re.escape(region)+':'+account+
                             ':repository/'+re.escape(name),arn)):
        raise Unavailable('private ECR repository identity is foreign or malformed')
    policy=get(item,'Policy',dict)
    status=get(policy,'collection_status',str)
    if status=='empty':
        error=policy.get('error')
        if (policy.get('absent') is True and isinstance(error,dict) and
                error.get('code') in (None,'RepositoryPolicyNotFoundException') and
                set(error) <= {'code'} and 'policyText' not in policy):
            return result(False,repository_arn=arn,policy='documented_absent')
        raise Unavailable('private ECR policy absence is not documented')
    if status!='collected':
        raise Unavailable('private ECR policy detail incomplete')
    if get(policy,'registryId',str)!=account or get(policy,'repositoryName',str)!=name:
        raise Unavailable('private ECR policy detail belongs to a foreign repository')
    document=get(policy,'policyText',(str,dict))
    if isinstance(document,str):
        try:document=json.loads(document)
        except ValueError as exc:raise Unavailable('malformed private ECR policy JSON') from exc
    if not isinstance(document,dict) or 'collection_status' in document or '_coverage' in document:
        raise Unavailable('malformed private ECR policy document')
    if any(field in document and not isinstance(document[field],str) for field in ('Version','Id')):
        raise Unavailable('private ECR policy header is malformed')
    statements=document.get('Statement')
    if isinstance(statements,dict):
        statements=[statements]  # policyToCanonical wraps a single Statement.
    if not isinstance(statements,list) or any(not isinstance(row,dict) for row in statements):
        raise Unavailable('private ECR policy Statement is malformed')
    hits=0
    for statement in statements:
        if statement.get('Effect') not in ('Allow','Deny'):
            raise Unavailable('private ECR policy Effect is malformed')
        if 'Sid' in statement and not isinstance(statement['Sid'],str):
            raise Unavailable('private ECR policy Sid is malformed')
        for field in ('NotAction','Resource','NotResource'):
            if field in statement:
                values=statement[field]
                values=[values] if isinstance(values,str) else values
                if not isinstance(values,list) or any(not isinstance(value,str) for value in values):
                    raise Unavailable('private ECR policy '+field+' is malformed')
        if 'NotPrincipal' in statement:
            excluded=statement['NotPrincipal']
            if isinstance(excluded,str):
                if excluded!='*':raise Unavailable('private ECR policy NotPrincipal is malformed')
            elif isinstance(excluded,dict) and excluded:
                for values in excluded.values():
                    values=[values] if isinstance(values,str) else values
                    if not isinstance(values,list) or any(not isinstance(value,str) for value in values):
                        raise Unavailable('private ECR policy NotPrincipal is malformed')
            else:
                raise Unavailable('private ECR policy NotPrincipal is malformed')
        if 'Condition' in statement:
            condition=statement['Condition']
            if not isinstance(condition,dict) or any(
                    not isinstance(operator,str) or not isinstance(clauses,dict) or
                    any(not isinstance(key,str) or not isinstance(value,(str,int,float,bool,list)) or
                        (isinstance(value,list) and any(not isinstance(part,(str,int,float,bool)) for part in value))
                        for key,value in clauses.items()) for operator,clauses in condition.items()):
                raise Unavailable('private ECR policy Condition is malformed')
        principal=statement.get('Principal')
        if isinstance(principal,str):
            if principal!='*':
                raise Unavailable('private ECR policy Principal string is malformed')
            aws_values=['*']  # policyToCanonical maps bare * to AWS: ["*"].
        elif isinstance(principal,dict) and principal and all(
                key in ('AWS','Service','Federated','CanonicalUser') for key in principal):
            for values in principal.values():
                normalized=[values] if isinstance(values,str) else values
                if not isinstance(normalized,list) or any(
                        not isinstance(value,str) or not value for value in normalized):
                    raise Unavailable('private ECR policy Principal value is malformed')
            aws_values=principal.get('AWS',[])
            if isinstance(aws_values,str):
                aws_values=[aws_values]  # Principal.AWS scalar -> array.
            if any('%' in value for value in aws_values):
                # The plugin URL-unescapes before canonicalization; a parsed
                # native document cannot prove whether %2A remains literal.
                raise Unavailable('private ECR principal URL encoding is ambiguous')
        else:
            raise Unavailable('private ECR policy Principal is malformed')
        actions=statement.get('Action')
        if isinstance(actions,str):
            actions=[actions]  # policyToCanonical wraps scalar Action.
        if not isinstance(actions,list) or any(
                not isinstance(value,str) or not value for value in actions):
            raise Unavailable('private ECR policy Action is malformed')
        if statement['Effect']=='Allow' and '*' in aws_values and actions:
            hits+=1
    return result(bool(hits),repository_arn=arn,canonical_wildcard_statements=hits)


def _lambda_config(item,index):
    from .aws_config_recording import (_recording_scope, _run_state, SERVICE_LINKED_PREFIX)
    identity=_member(item,index,'lambda_function')
    rows=_rows(index,'config_recorder')
    customer=[];linked=[]
    for row in rows:
        name=get(row,'name',str)
        principal=optional(row,'servicePrincipal',None,str)
        if principal is not None:
            if not principal:raise Unavailable('empty Config service principal')
            linked.append(name)
        elif name.startswith(SERVICE_LINKED_PREFIX):
            raise Unavailable('Config recorder ownership ambiguous')
        else:customer.append(row)
    if not customer:
        if linked:return unknown('service-linked recorder coverage of Lambda unresolved')
        return result(True,function_arn=identity,reason='no customer-managed recorder')
    if len(customer)!=1:raise Unavailable('multiple customer-managed Config recorders')
    recorder=customer[0];name=get(recorder,'name',str)
    state,last=_run_state(recorder,name)
    if state in ('stopped','failed'):
        return result(True,function_arn=identity,recorder=name,run_state=state)
    group=get(recorder,'recordingGroup',dict)
    coverage,strategy,included,excluded=_recording_scope(group)
    kind='AWS::Lambda::Function'
    if coverage=='all_supported':covers=True
    elif strategy in ('INCLUSION_BY_RESOURCE_TYPES','legacy_selected_types'):covers=kind in included
    elif strategy=='EXCLUSION_BY_RESOURCE_TYPES':covers=kind not in excluded
    else:raise Unavailable('unresolved Config recording strategy')
    if not covers:return result(True,function_arn=identity,recorder=name,recording_scope=coverage)
    if state!='running':return unknown('Config recorder running state unconfirmed',recorder=name,last_status=last)
    return result(False,function_arn=identity,recorder=name,recording_scope=coverage)


def _cloudtrail_bucket_logging(item,index,strict_target=False,logging_only=False):
    trail_arn=_member(item,index,'cloudtrail')
    account,region=_scope(index)[1].split('/')
    home=get(item,'HomeRegion',str)
    if not trail_arn.startswith(f'arn:aws:cloudtrail:{home}:{account}:trail/'):
        raise Unavailable('CloudTrail ARN foreign to account or home Region')
    if home!=region:
        return 'NOT_APPLICABLE',{'trail_arn':trail_arn,'reason':'shadow trail; assess home Region'}
    if logging_only:
        status=get(item,'Status',dict)
        if get(status,'collection_status',str)!='collected':
            raise Unavailable('CloudTrail GetTrailStatus unavailable')
        if not get(status,'IsLogging',bool):
            return 'NOT_APPLICABLE',{'trail_arn':trail_arn,'reason':'trail is not logging'}
    name=get(item,'S3BucketName',str)
    if not name:raise Unavailable('CloudTrail destination bucket missing')
    buckets=memoized(index,('batch_aws_member','bucket'),lambda:{get(row,'Name',str):row for row in _rows(index,'bucket')})
    if name not in buckets:raise Unavailable('CloudTrail destination bucket owner/join unresolved')
    bucket=buckets[name]
    logging=get(bucket,'Logging',dict)
    if get(logging,'collection_status',str)!='collected':
        raise Unavailable('S3 GetBucketLogging unavailable')
    configured=logging.get('LoggingEnabled')
    if configured is not None and not isinstance(configured,dict):
        raise Unavailable('malformed S3 access logging configuration')
    if strict_target and isinstance(configured,dict):
        target=get(configured,'TargetBucket',str)
        prefix=get(configured,'TargetPrefix',str)
        configured=bool(target and prefix)
    return result(not bool(configured),trail_arn=trail_arn,destination_bucket=name,
                  logging_enabled=bool(configured))


def _kms_imported_spec(item,index):
    key_arn=_member(item,index,'kms_key')
    detail=get(item,'Metadata',dict)
    if get(detail,'collection_status',str)!='collected':
        raise Unavailable('KMS DescribeKey unavailable')
    metadata=get(detail,'KeyMetadata',dict)
    if get(metadata,'Arn',str)!=key_arn:
        raise Unavailable('KMS metadata ARN mismatch')
    origin=get(metadata,'Origin',str)
    if origin in ('AWS_KMS','AWS_CLOUDHSM','EXTERNAL_KEY_STORE'):
        return 'NOT_APPLICABLE',{'key_arn':key_arn,'origin':origin}
    if origin!='EXTERNAL':
        return unknown('unrecognized KMS key origin')
    spec=get(metadata,'KeySpec',str)
    usage=get(metadata,'KeyUsage',str)
    approved=spec in ('RSA_2048','RSA_3072','RSA_4096','ECC_NIST_P256') and usage in ('ENCRYPT_DECRYPT','SIGN_VERIFY')
    return result(not approved,key_arn=key_arn,origin=origin,key_spec=spec,key_usage=usage)


def _iam_scoped_wildcard(item,index):
    # This signed predicate selects customer-managed policies. The old
    # GetAccountAuthorizationDetails iam_policy projection also contains
    # AWS-owned policies, so bind each resource to the exact Local universe.
    from .aws_all_policies import _rows as customer_rows

    context=get(index,'context',dict)
    scope=get(context,'scope',str)
    match=re.fullmatch(r'([0-9]{12})/(?:global|[a-z0-9-]+)',scope)
    if get(context,'provider',str)!='aws' or match is None or context.get('Account')!=match.group(1):
        raise Unavailable('customer IAM account authority missing')
    account=match.group(1)
    envelopes=get(index,'collections',dict).get('iam_customer_policy')
    if (not isinstance(envelopes,list) or len(envelopes)!=1 or
            envelopes[0].get('account_id')!=account or envelopes[0].get('global') is not True or
            envelopes[0].get('status') not in ('collected','empty')):
        raise Unavailable('complete customer IAM global inventory unavailable')

    def documents():
        rows=customer_rows(index,account)  # exact envelope/wrapper equality
        found={}
        for row in rows:
            arn=get(row,'Arn',str)
            if (not re.fullmatch(r'arn:(?:aws|aws-cn|aws-us-gov):iam::'+account+r':policy/.+',arn)
                    or get(row,'AccountId',str)!=account or arn in found):
                raise Unavailable('foreign or duplicate customer IAM policy')
            provenance=get(row,'_provenance',dict)
            if (provenance.get('operation')!='iam:ListPolicies' or
                    provenance.get('managed_scope')!='Local' or
                    provenance.get('only_attached') is not False or
                    provenance.get('account_id')!=account or
                    provenance.get('default_operation')!='iam:GetPolicyVersion'):
                raise Unavailable('customer IAM policy universe unproven')
            detail=get(row,'DefaultDocument',dict)
            if (get(detail,'collection_status',str)!='collected' or
                    get(detail,'VersionId',str)!=get(row,'DefaultVersionId',str)):
                raise Unavailable('default IAM policy version unavailable or mismatched')
            document=get(detail,'Document',dict)
            statements(document)  # reject malformed default documents before grading
            found[arn]=(row,document)
        return found

    found=memoized(index,('iam_scoped_customer_defaults',),documents)
    arn=get(item,'Arn',str)
    if arn not in found or found[arn][0]!=item:
        raise Unavailable('customer IAM resource not in exact native inventory')
    matches=0
    for statement in statements(found[arn][1]):
        effect=get(statement,'Effect',str)
        if effect not in ('Allow','Deny'):
            raise Unavailable('unrecognized IAM effect')
        if effect!='Allow':
            continue
        if 'NotResource' in statement:
            raise Unavailable('NotResource statement has different target semantics')
        resources=array(get(statement,'Resource'))
        if not resources or any(not isinstance(value,str) for value in resources):
            raise Unavailable('malformed IAM resource set')
        individual=any(value.startswith('arn:') and '*' not in value and '?' not in value for value in resources)
        if not individual:
            continue
        if 'Action' in statement and 'NotAction' in statement:
            raise Unavailable('ambiguous IAM Action and NotAction')
        if 'Action' in statement:
            actions=array(statement['Action'])
            if not actions or any(not isinstance(value,str) for value in actions):
                raise Unavailable('malformed IAM action set')
            broad=any(value=='*' or value.endswith(':*') for value in actions)
        elif 'NotAction' in statement:
            exclusions=array(statement['NotAction'])
            if not exclusions or any(not isinstance(value,str) for value in exclusions):
                raise Unavailable('malformed IAM NotAction set')
            broad=not any(value in ('*','*:*') for value in exclusions)
        else:
            raise Unavailable('IAM Allow action absent')
        matches+=int(broad)
    return result(bool(matches),policy_arn=arn,broad_scoped_statement_count=matches,
                  semantics='declared customer-managed default policy; no effective permission inference')

_EVENTS={
    'aws_eventbridge_iam_user_change_alert': ('aws.iam','iam.amazonaws.com',
        frozenset(('CreateUser','DeleteUser','UpdateUser','CreateAccessKey','UpdateAccessKey','DeleteAccessKey'))),
    'aws_eventbridge_snapshot_change_alert': ('aws.ec2','ec2.amazonaws.com',
        frozenset(('CreateSnapshot','ModifySnapshotAttribute','DeleteSnapshot'))),
}

def _event_literals(value):
    if not isinstance(value,list) or not value or any(not isinstance(part,str) or not part for part in value):
        raise Unavailable('EventBridge pattern contains unverified matcher')
    return set(value)


def _event_alert(check_id,item,index):
    context,scope=_scope(index)
    if item!=context:raise Unavailable('EventBridge scope target mismatch')
    expected_source,expected_service,required=_EVENTS[check_id]
    account,region=scope.split('/')
    covered=set()
    for rule in _rows(index,'event_rule'):
        state=get(rule,'State',str)
        if state not in ('ENABLED','DISABLED'):
            raise Unavailable('unrecognized EventBridge rule state')
        if state=='DISABLED':continue
        raw=get(rule,'EventPattern',str)
        try:pattern=json.loads(raw)
        except (TypeError,ValueError) as exc:raise Unavailable('malformed EventBridge pattern') from exc
        if not isinstance(pattern,dict) or set(pattern)-{'source','detail-type','detail','account','region'}:
            raise Unavailable('unreviewed EventBridge pattern constraints')
        if 'account' in pattern and account not in _event_literals(pattern['account']):continue
        if 'region' in pattern and region not in _event_literals(pattern['region']):continue
        if 'source' in pattern and expected_source not in _event_literals(pattern['source']):continue
        if 'detail-type' in pattern and 'AWS API Call via CloudTrail' not in _event_literals(pattern['detail-type']):continue
        detail=pattern.get('detail',{})
        if not isinstance(detail,dict) or set(detail)-{'eventSource','eventName'}:
            raise Unavailable('unreviewed EventBridge detail constraints')
        if 'eventSource' in detail and expected_service not in _event_literals(detail['eventSource']):continue
        if 'source' not in pattern and 'eventSource' not in detail:
            raise Unavailable('CloudTrail service origin not established')
        names=_event_literals(detail['eventName']) if 'eventName' in detail else required
        targets=get(rule,'Targets',dict)
        if get(targets,'collection_status',str) not in ('collected','empty'):
            raise Unavailable('EventBridge targets pagination incomplete')
        rows=list_of_objects(get(targets,'items',list))
        if rows and any(not get(target,'Arn',str).startswith('arn:aws:') for target in rows):
            raise Unavailable('malformed EventBridge target ARN')
        if rows:covered.update(required & names)
    missing=sorted(required-covered)
    return result(bool(missing),missing_event_names=missing,covered_event_names=sorted(covered),
                  semantics='default-bus declared CloudTrail rule and target; notification delivery not observed')


def _cloudtrail_logs(item,index,require_logging=False,require_role=False):
    trail_arn=_member(item,index,'cloudtrail')
    account,region=_scope(index)[1].split('/')
    home=get(item,'HomeRegion',str)
    if not trail_arn.startswith(f'arn:aws:cloudtrail:{home}:{account}:trail/'):
        raise Unavailable('foreign CloudTrail ARN')
    if home!=region:
        return 'NOT_APPLICABLE',{'trail_arn':trail_arn,'reason':'shadow trail; assess home Region'}
    if require_logging:
        status=get(item,'Status',dict)
        if get(status,'collection_status',str)!='collected':
            raise Unavailable('CloudTrail GetTrailStatus incomplete')
        logging=get(status,'IsLogging',bool)
    else:
        logging=None
    destination=get(item,'CloudWatchLogsLogGroupArn',str)
    role=optional(item,'CloudWatchLogsRoleArn','',str) if require_role else None
    groups=_log_group_map(index)
    if destination and not destination.startswith(f'arn:aws:logs:{region}:{account}:log-group:'):
        raise Unavailable('foreign CloudWatch destination ARN')
    if role and not role.startswith(f'arn:aws:iam::{account}:role/'):
        raise Unavailable('foreign CloudTrail delivery role ARN')
    resolved=bool(destination and destination.removesuffix(':*') in groups)
    failed=(logging is False if require_logging else False) or not resolved or (require_role and not role)
    return result(bool(failed),trail_arn=trail_arn,cloudwatch_log_group_arn=destination,
                  destination_resolved=resolved,delivery_role_present=bool(role) if require_role else None,
                  is_logging=logging,semantics='configuration join only; delivery freshness not assessed')


def _log_group_map(index):
    account,region=_scope(index)[1].split('/')
    def build():
        groups={}
        for group in _rows(index,'log_group'):
            arn=get(group,'arn',str).removesuffix(':*')
            if not arn.startswith(f'arn:aws:logs:{region}:{account}:log-group:') or arn in groups:
                raise Unavailable('foreign or duplicate CloudWatch log group')
            groups[arn]=group
        return groups
    return memoized(index,('batch_aws_log_group_map_verified',),build)


def _backup_failure(item,index):
    name=_member(item,index,'backup_vault')
    notification=get(item,'Notifications',dict)
    status=get(notification,'collection_status',str)
    if status=='empty' and notification.get('absent') is True:
        return result(True,vault_name=name,reason='native notification configuration absent')
    if status!='collected':
        raise Unavailable('Backup vault notification detail incomplete')
    topic=notification.get('SNSTopicArn','')
    events=notification.get('BackupVaultEvents',[])
    if not isinstance(topic,str) or not isinstance(events,list) or any(not isinstance(event,str) for event in events):
        raise Unavailable('malformed backup event list')
    if topic and not topic.startswith(f"arn:aws:sns:{_scope(index)[1].split('/')[1]}:{_scope(index)[1].split('/')[0]}:"):
        raise Unavailable('foreign backup notification topic')
    return result(not(topic and 'BACKUP_JOB_FAILED' in events),vault_name=name,
                  notification_topic_present=bool(topic),backup_failure_event_present='BACKUP_JOB_FAILED' in events)


def _batch_logging(item,index):
    arn=_member(item,index,'batch_job_definition')
    state=get(item,'status',str)
    if state=='INACTIVE':return 'NOT_APPLICABLE',{'job_definition_arn':arn}
    if state!='ACTIVE':return unknown('unrecognized Batch job definition status')
    containers=[]
    if 'containerProperties' in item:
        containers.append(get(item,'containerProperties',dict))
    if 'nodeProperties' in item:
        for node in list_of_objects(get(item,'nodeProperties.nodeRangeProperties',list)):
            containers.append(get(node,'container',dict))
    if 'ecsProperties' in item:
        for task in list_of_objects(get(item,'ecsProperties.taskProperties',list)):
            containers.extend(list_of_objects(get(task,'containers',list)))
    if not containers:raise Unavailable('Batch container projection missing')
    bad=[]
    for position,container in enumerate(containers):
        logging=container.get('logConfiguration')
        if logging is None:
            bad.append(position);continue
        if not isinstance(logging,dict):
            raise Unavailable('malformed Batch log configuration')
        driver=logging.get('logDriver','')
        if not isinstance(driver,str):
            raise Unavailable('malformed Batch log driver')
        options=logging.get('options',{})
        if not isinstance(options,dict):
            raise Unavailable('malformed Batch log options')
        group=options.get('awslogs-group','') if driver=='awslogs' else ''
        if not isinstance(group,str):
            raise Unavailable('malformed Batch awslogs group')
        if driver!='awslogs' or not group:bad.append(position)
    return result(bool(bad),job_definition_arn=arn,container_count=len(containers),
                  containers_without_awslogs=bad)


def _codepipeline_first_deploy(item,index):
    name=_member(item,index,'codepipeline_pipeline')
    detail=get(item,'Pipeline',dict)
    if get(detail,'collection_status',str)!='collected':
        raise Unavailable('CodePipeline GetPipeline incomplete')
    pipeline=get(detail,'pipeline',dict)
    if get(pipeline,'name',str)!=name:
        raise Unavailable('CodePipeline detail identity mismatch')
    stages=list_of_objects(get(pipeline,'stages',list))
    for position,stage in enumerate(stages):
        actions=list_of_objects(get(stage,'actions',list))
        deploy_count=sum(get(action,'actionTypeId.category',str)=='Deploy' for action in actions)
        if deploy_count:
            return result(deploy_count>1,pipeline_name=name,first_deploy_stage_index=position,
                          deploy_action_count=deploy_count)
    return result(False,pipeline_name=name,first_deploy_stage_index=None,deploy_action_count=0)


def _sns_failure_alarm(item,index):
    arn=_member(item,index,'sns_topic')
    attributes=get(item,'Attributes',dict)
    if get(attributes,'collection_status',str)!='collected':
        raise Unavailable('SNS GetTopicAttributes incomplete')
    values=get(attributes,'Attributes',dict)
    if 'TopicArn' in values and get(values,'TopicArn',str)!=arn:
        raise Unavailable('SNS topic detail identity mismatch')
    count=get(values,'SubscriptionsConfirmed',str)
    if not re.fullmatch(r'[0-9]+',count):
        raise Unavailable('SNS confirmed subscription count malformed')
    if int(count)==0:
        return 'NOT_APPLICABLE',{'topic_arn':arn,'confirmed_subscriptions':0}
    name=arn.rsplit(':',1)[-1]
    return _alarm(item,index,'sns_topic','AWS/SNS','NumberOfNotificationsFailed','TopicName',name)


def _cloudtrail_kms(item,index,active_only=False):
    trail_arn=_member(item,index,'cloudtrail')
    account,region=_scope(index)[1].split('/')
    home=get(item,'HomeRegion',str)
    if not trail_arn.startswith(f'arn:aws:cloudtrail:{home}:{account}:trail/'):
        raise Unavailable('foreign CloudTrail ARN')
    if home!=region:
        return 'NOT_APPLICABLE',{'trail_arn':trail_arn,'reason':'shadow trail; assess home Region'}
    if active_only:
        status=get(item,'Status',dict)
        if get(status,'collection_status',str)!='collected':
            raise Unavailable('CloudTrail GetTrailStatus incomplete')
        if not get(status,'IsLogging',bool):
            return 'NOT_APPLICABLE',{'trail_arn':trail_arn,'reason':'trail is not logging'}
    def key_maps():
        by_arn={};by_id={}
        for key in _rows(index,'kms_key'):
            arn=get(key,'KeyArn',str);key_id=get(key,'KeyId',str)
            if arn in by_arn or key_id in by_id:
                raise Unavailable('duplicate KMS key identity')
            by_arn[arn]=key;by_id[key_id]=key
        return by_arn,by_id
    by_arn,by_id=memoized(index,('batch_aws_kms_maps',),key_maps)
    def key_state(reference):
        if not reference:return False
        if reference.startswith('arn:aws:kms:'):
            if not reference.startswith(f'arn:aws:kms:{region}:{account}:key/'):
                raise Unavailable('foreign or alias KMS ARN')
            key=by_arn.get(reference)
        elif re.fullmatch(r'[a-zA-Z0-9-]{1,128}',reference):
            key=by_id.get(reference)
        else:
            raise Unavailable('unresolved KMS key reference')
        if key is None:
            raise Unavailable('KMS key reference not in complete owned inventory')
        detail=get(key,'Metadata',dict)
        if get(detail,'collection_status',str)!='collected':
            raise Unavailable('KMS DescribeKey incomplete')
        metadata=get(detail,'KeyMetadata',dict)
        if get(metadata,'Arn',str)!=get(key,'KeyArn',str):
            raise Unavailable('KMS detail identity mismatch')
        manager=get(metadata,'KeyManager',str)
        state=get(metadata,'KeyState',str)
        if manager not in ('AWS','CUSTOMER') or not state:
            raise Unavailable('unrecognized KMS manager or state')
        return manager=='CUSTOMER' and state=='Enabled'
    trail_key=get(item,'KmsKeyId',str)
    trail_good=key_state(trail_key)
    destination=get(item,'CloudWatchLogsLogGroupArn',str)
    log_good=None
    if destination:
        if not destination.startswith(f'arn:aws:logs:{region}:{account}:log-group:'):
            raise Unavailable('foreign CloudWatch destination ARN')
        group=_log_group_map(index).get(destination.removesuffix(':*'))
        if group is None:
            raise Unavailable('CloudWatch destination log group unresolved')
        log_good=key_state(group.get('kmsKeyId',''))
    return result(not trail_good or log_good is False,trail_arn=trail_arn,
                  trail_customer_key_enabled=trail_good,
                  destination_log_group_present=bool(destination),
                  destination_customer_key_enabled=log_good,
                  semantics='configuration key metadata only; no log delivery or cryptographic use inferred')

EVALUATORS={
 'aws_msk_in_cluster_tls_enabled':_msk,
 'aws_client_vpn_authentication_configured':_vpn,
 'aws.nist.codebuild_exact_aws_key_env_names':lambda item,index:_codebuild(item,index,False),
 'aws.pci.codebuild.aws_key_environment_vars':lambda item,index:_codebuild(item,index,True),
 'aws_g6_ecs_all_containers_logging':_ecs,
 'aws_ec2_running_instance_cpu_alarm_present':_cpu,
 'aws_sqs_queue_depth_alarm_present':_sqs,
 'aws_g6_rds_cluster_members_enhanced_monitoring':_rds,
 'aws_nist_dynamodb_table_encrypted_with_kms':_dynamodb,
 'aws_route53_hosted_zone_dnssec_enabled':_dnssec,
 'aws_lambda_code_signing_configured':_signing,
 'aws_cis_lightsail_bucket_access_logging':_lightsail,
 'aws_g6_ecr_public_repositories_absent':_private_ecr_policy,
 'aws_ec2_status_alarm':_status_alarm,
 'aws_cis_lambda_config_recorded':_lambda_config,
 'aws_nist_rds_db_instance_and_cluster_enhanced_monitoring_enabled':_rds_instance,
 'aws.nist.all_cloudtrail_destination_bucket_access_logging':_cloudtrail_bucket_logging,
 'aws_g6_all_cloudtrail_destination_bucket_access_logging':lambda item,index:_cloudtrail_bucket_logging(item,index,strict_target=True),
 'aws_nist_cloudtrail_s3_logging_enabled':lambda item,index:_cloudtrail_bucket_logging(item,index,logging_only=True),
 'aws_kms_imported_key_origin_spec':_kms_imported_spec,
 'aws.pci.iam.wildcard_action_scoped_resource':_iam_scoped_wildcard,
 'aws_eventbridge_iam_user_change_alert':lambda item,index:_event_alert('aws_eventbridge_iam_user_change_alert',item,index),
 'aws_eventbridge_snapshot_change_alert':lambda item,index:_event_alert('aws_eventbridge_snapshot_change_alert',item,index),
 'aws.nist.cloudtrail_cloudwatch_integration':lambda item,index:_cloudtrail_logs(item,index,require_logging=True),
 'aws_g6_cloudtrail_all_trails_cloudwatch_integration':lambda item,index:_cloudtrail_logs(item,index,require_role=True),
 'aws_backup_failure_notification':_backup_failure,
 'aws_cis_batch_job_cloudwatch_logging':_batch_logging,
 'aws.pci.codepipeline.first_stage_single_deploy':_codepipeline_first_deploy,
 'aws_fedramp_cloudtrail_destination_kms':lambda item,index:_cloudtrail_kms(item,index,active_only=True),
 'aws_g6_cloudtrail_kms_destination_join':_cloudtrail_kms,
 'aws_nist_cloudtrail_trail_logs_encrypted_with_kms_cmk':lambda item,index:_cloudtrail_kms(item,index,active_only=True),
 'aws_sns_delivery_failure_alarm_present':_sns_failure_alarm,
}
for _id,(_kind,_category,_severity,_title,_remediation,_target) in SPECS.items():
    @register(_id,'aws',_category,_kind,_title,_severity,'CM-6',_remediation,target=_target,
              dependencies=[_kind]+(['cloudwatch_alarm'] if _id in ('aws_ec2_running_instance_cpu_alarm_present','aws_ec2_status_alarm','aws_sqs_queue_depth_alarm_present','aws_sns_delivery_failure_alarm_present') else ['rds_instance'] if _id=='aws_g6_rds_cluster_members_enhanced_monitoring' else ['rds_cluster'] if _id=='aws_nist_rds_db_instance_and_cluster_enhanced_monitoring_enabled' else ['config_recorder'] if _id=='aws_cis_lambda_config_recorded' else ['bucket'] if _id in ('aws.nist.all_cloudtrail_destination_bucket_access_logging','aws_g6_all_cloudtrail_destination_bucket_access_logging','aws_nist_cloudtrail_s3_logging_enabled') else ['log_group'] if _id in ('aws.nist.cloudtrail_cloudwatch_integration','aws_g6_cloudtrail_all_trails_cloudwatch_integration') else ['kms_key','log_group'] if _id in ('aws_fedramp_cloudtrail_destination_kms','aws_g6_cloudtrail_kms_destination_join','aws_nist_cloudtrail_trail_logs_encrypted_with_kms_cmk') else []))
    def _evaluate(item,index,_id=_id):
        if _id.startswith('aws_security_group_'):return _security_group(_id,item,index)
        return EVALUATORS[_id](item,index)
    _evaluate.__name__=_id.replace('.','_')
