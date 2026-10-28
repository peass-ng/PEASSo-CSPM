"""Read-only native facts needed to resolve observed recheck disagreements."""
from copy import deepcopy
import json
import re
from urllib.parse import urlsplit

SPECS = {'scheduler_schedule': ('scheduler', 'list_schedules', 'Schedules')}
NATIVE_IDS = {'scheduler_schedule': 'Arn'}
READ_ACTIONS = {('ec2', 'describe_instance_types'), ('scheduler', 'get_schedule'),
                ('scheduler', 'list_schedules'), ('sqs', 'list_dead_letter_source_queues'),
                ('neptune', 'describe_db_clusters'), ('docdb', 'describe_db_clusters'), ('docdb', 'describe_db_instances')}


def _database(service, operation, expression, engine):
    def fetch(requests, session, region, account):
        from .aws import ReadResult
        args = {'Filters': [{'Name': 'engine', 'Values': [engine]}]} if engine else {}
        read = requests.pages(session, service, region, operation, expression, **args)
        # Apply the same engine constraint locally, including for API-compatible
        # endpoints that return resources of other database services.
        if any(not isinstance(row, dict) or (engine and not isinstance(row.get('Engine'), str)) for row in read.items):
            return ReadResult(read.items, 'partial' if read.items else 'malformed', {'code': 'db_engine_identity_missing'})
        items = [row for row in read.items if (row['Engine'] == engine if engine else row.get('Engine') not in {'docdb', 'neptune'})]
        return ReadResult(items, ('collected' if items else 'empty') if read.status in ('collected', 'empty') else read.status, read.error)
    return fetch


def instances(requests, session, region, items):
    if not getattr(requests, 'ebs_optimization_facts_requested', True):
        return items
    output = []
    for native in items:
        row = deepcopy(native)
        kind = row.get('InstanceType')
        if row.get('EbsOptimized') is False and isinstance(kind, str) and kind:
            read = requests.pages(session, 'ec2', region, 'describe_instance_types', 'InstanceTypes', InstanceTypes=[kind])
            matching = [value for value in read.items if isinstance(value, dict) and value.get('InstanceType') == kind]
            if read.status == 'collected' and len(matching) == 1:
                row['InstanceTypeInfo'] = {'InstanceType': kind, 'EbsInfo': matching[0].get('EbsInfo', {}),
                    '_provenance': {'source_operation': 'ec2:DescribeInstanceTypes', 'read_only': True}}
            else:
                row.setdefault('_coverage', {})['InstanceTypeInfo'] = {'status': read.status, 'reason': 'instance_type_support_unavailable'}
        output.append(row)
    return output


def queues(requests, session, region, items):
    if not getattr(requests, 'sqs_dead_letter_sources_requested', True):
        return items
    output = []
    for native in items:
        row = deepcopy(native)
        url = row.get('QueueUrl')
        if isinstance(url, str) and url:
            read = requests.pages(session, 'sqs', region, 'list_dead_letter_source_queues', 'queueUrls || `[]`', QueueUrl=url, MaxResults=1000)
            row['DeadLetterSourceQueues'] = {'collection_status': read.status, 'items': read.items,
                '_provenance': {'source_operation': 'sqs:ListDeadLetterSourceQueues', 'read_only': True}}
        output.append(row)
    return output


def schedules(requests, session, region, account):
    from .aws import ReadResult
    read = requests.pages(session, 'scheduler', region, 'list_schedules', 'Schedules')
    output, failures = [], []
    for native in read.items:
        if not isinstance(native, dict) or not isinstance(native.get('Name'), str) or not isinstance(native.get('GroupName'), str):
            failures.append('malformed_schedule_identity')
            continue
        detail = requests.detail(session, 'scheduler', region, 'get_schedule', Name=native['Name'], GroupName=native['GroupName'])
        if detail.get('collection_status') not in ('collected', None) or detail.get('error'):
            failures.append('schedule_detail_unavailable')
            continue
        target = detail.get('Target') or {}
        row = {k: detail[k] for k in ('Arn', 'Name', 'GroupName', 'State', 'KmsKeyArn') if k in detail}
        row['Target'] = {k: target[k] for k in ('Arn', 'RoleArn', 'DeadLetterConfig') if k in target}
        if isinstance(target.get('Arn'), str) and ':aws-sdk:' in target['Arn']:
            row['Target']['InputRecipient'] = _schedule_input_recipient(target['Arn'], target.get('Input'))
        row['_provenance'] = {'source_operation': 'scheduler:GetSchedule', 'read_only': True,
                              'kms_key_arn_observed': True}
        output.append(row)
    status = 'partial' if failures else read.status
    return ReadResult(output, status, {'code': failures[0]} if failures else read.error)


def _schedule_input_recipient(target_arn, raw_input):
    """Project universal-target destination identity, never its payload."""
    match = re.fullmatch(r'arn:aws(?:-cn|-us-gov)?:scheduler:::aws-sdk:([a-z0-9-]+):([A-Za-z0-9]+)', target_arn)
    if not match or not isinstance(raw_input, str):
        return {'collection_status': 'unresolved'}
    try:
        value = json.loads(raw_input)
    except (ValueError, TypeError):
        return {'collection_status': 'malformed'}
    if not isinstance(value, dict):
        return {'collection_status': 'malformed'}
    service, action = match.group(1), match.group(2).lower()
    arn_fields = {('lambda', 'invoke'): 'FunctionName', ('sfn', 'startexecution'): 'StateMachineArn',
                  ('sns', 'publish'): 'TopicArn'}
    key = arn_fields.get((service, action))
    if key:
        recipient = value.get(key)
        if isinstance(recipient, str) and recipient.startswith('arn:'):
            return {'collection_status': 'collected', 'Arn': recipient}
        if service == 'sns' and isinstance(value.get('PhoneNumber'), str) and value['PhoneNumber']:
            return {'collection_status': 'collected', 'PhoneRecipient': True}
        return {'collection_status': 'unresolved'}
    if (service, action) == ('sqs', 'sendmessage'):
        url = value.get('QueueUrl')
        try:
            parsed = urlsplit(url) if isinstance(url, str) else None
        except ValueError:
            parsed = None
        path = parsed.path.split('/') if parsed is not None else []
        if (parsed is not None and parsed.scheme == 'https' and parsed.hostname and
                parsed.hostname.endswith('.amazonaws.com') and len(path) >= 3 and
                re.fullmatch(r'[0-9]{12}', path[1])):
            return {'collection_status': 'collected', 'AccountId': path[1]}
        return {'collection_status': 'unresolved'}
    return {'collection_status': 'unsupported'}


FETCHERS = {'rds_cluster': _database('rds', 'describe_db_clusters', 'DBClusters', None),
            'rds_instance': _database('rds', 'describe_db_instances', 'DBInstances', None),
            'neptune_cluster': _database('neptune', 'describe_db_clusters', 'DBClusters', 'neptune'),
            'docdb_cluster': _database('docdb', 'describe_db_clusters', 'DBClusters', 'docdb'),
            'docdb_instance': _database('docdb', 'describe_db_instances', 'DBInstances', 'docdb'),
            'scheduler_schedule': schedules}
ENRICHERS = {'instance': instances, 'sqs_queue': queues}
