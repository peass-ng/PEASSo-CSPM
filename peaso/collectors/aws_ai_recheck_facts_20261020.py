"""Read-only native facts needed to resolve observed recheck disagreements."""
from copy import deepcopy

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
        row['_provenance'] = {'source_operation': 'scheduler:GetSchedule', 'read_only': True,
                              'kms_key_arn_observed': True}
        output.append(row)
    status = 'partial' if failures else read.status
    return ReadResult(output, status, {'code': failures[0]} if failures else read.error)


FETCHERS = {'rds_cluster': _database('rds', 'describe_db_clusters', 'DBClusters', None),
            'rds_instance': _database('rds', 'describe_db_instances', 'DBInstances', None),
            'neptune_cluster': _database('neptune', 'describe_db_clusters', 'DBClusters', 'neptune'),
            'docdb_cluster': _database('docdb', 'describe_db_clusters', 'DBClusters', 'docdb'),
            'docdb_instance': _database('docdb', 'describe_db_instances', 'DBInstances', 'docdb'),
            'scheduler_schedule': schedules}
ENRICHERS = {'instance': instances, 'sqs_queue': queues}
