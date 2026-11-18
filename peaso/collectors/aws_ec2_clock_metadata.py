"""Read the check's exact CWAgent/time_offset stream; never configure an agent."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import math
import re

READ_ACTIONS = {('cloudwatch', 'get_metric_statistics')}


def _sample(response, instance, start, end):
    if response.get('collection_status') != 'collected':
        return response
    if response.get('Label') != 'time_offset' or not isinstance(response.get('Datapoints'), list):
        return {'collection_status': 'malformed', 'error': {'code': 'clock_metric_response_invalid'}}
    samples = response['Datapoints']
    if not samples:
        return {'collection_status': 'empty', 'InstanceId': instance, 'Namespace': 'CWAgent', 'MetricName': 'time_offset',
                'WindowStart': start.isoformat(), 'WindowEnd': end.isoformat(),
                'error': {'code': 'no_exact_clock_metric_datapoints'},
                '_provenance': {'source_operation': 'cloudwatch:GetMetricStatistics', 'dimensions': [{'Name': 'InstanceId', 'Value': instance}], 'unit': 'Milliseconds', 'period_seconds': 300}}
    if len(samples) > 1440:
        return {'collection_status': 'partial', 'error': {'code': 'clock_metric_datapoint_limit'}}
    values = []
    for row in samples:
        if not isinstance(row, dict):
            return {'collection_status': 'malformed', 'error': {'code': 'clock_metric_datapoint_invalid'}}
        stamp = row.get('Timestamp')
        if isinstance(stamp, str):
            try:
                stamp = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
            except ValueError:
                stamp = None
        numbers = [row.get('Minimum'), row.get('Maximum')]
        if (not isinstance(stamp, datetime) or stamp.tzinfo is None or not start <= stamp < end
                or row.get('Unit') != 'Milliseconds'
                or any(type(n) not in (float, int) or not math.isfinite(n) for n in numbers)
                or numbers[0] > numbers[1]):
            return {'collection_status': 'malformed', 'error': {'code': 'clock_metric_datapoint_invalid'}}
        values.append((stamp, max(numbers, key=abs)))
    latest = max(stamp for stamp, _ in values)
    value = max((number for stamp, number in values if stamp == latest), key=abs)
    return {'collection_status': 'collected', 'InstanceId': instance,
            'Namespace': 'CWAgent', 'MetricName': 'time_offset',
            'Timestamp': latest.astimezone(timezone.utc).isoformat(),
            'ValueMilliseconds': value,
            '_provenance': {'source_operation': 'cloudwatch:GetMetricStatistics',
                            'dimensions': [{'Name': 'InstanceId', 'Value': instance}],
                            'unit': 'Milliseconds', 'period_seconds': 300}}


def enrich(requests, session, region, items):
    if getattr(requests, 'ec2_clock_metric_requested', True) is not True:
        return items
    output = []
    for original in items:
        item = deepcopy(original)
        identity = item.get('InstanceId')
        if item.get('State', {}).get('Name') != 'running':
            output.append(item)
            continue
        if not isinstance(identity, str) or re.fullmatch(r'i-[0-9a-f]{8,17}', identity) is None:
            item['TimeOffset'] = {'collection_status': 'malformed', 'error': {'code': 'clock_instance_identity_invalid'}}
        else:
            end = requests.observed_at
            # Match the API's documented minute rounding for recent data.
            start = (end - timedelta(days=1)).replace(second=0, microsecond=0)
            response = requests.detail(session, 'cloudwatch', region, 'get_metric_statistics',
                Namespace='CWAgent', MetricName='time_offset',
                Dimensions=[{'Name': 'InstanceId', 'Value': identity}],
                StartTime=start, EndTime=end, Period=300,
                Statistics=['Minimum', 'Maximum'], Unit='Milliseconds')
            item['TimeOffset'] = _sample(response, identity, start, end)
        output.append(item)
    return output


ENRICHERS = {'instance': enrich}
