"""Read-only Scheduler target recipient projection from one GetSchedule response."""
import json
import re
from urllib.parse import urlsplit


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

