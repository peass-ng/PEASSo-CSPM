"""Bound Beanstalk environment/LB metadata; no writes, log requests or payload reads.

Managed rotated-log paths are documented configuration resolution, not proof of
successful delivery, bucket existence, instance log coverage or retention.
"""
from copy import deepcopy
import re

READ_ACTIONS = {
    ('elasticbeanstalk', 'describe_environment_resources'),
    ('elbv2', 'describe_load_balancers'), ('elbv2', 'describe_listeners'),
    ('elbv2', 'describe_load_balancer_attributes'),
    ('elb', 'describe_load_balancers'), ('elb', 'describe_load_balancer_attributes'),
}
HOSTMANAGER = ('aws:elasticbeanstalk:hostmanager', 'LogPublicationControl')
LB_TYPE = ('aws:elasticbeanstalk:environment', 'LoadBalancerType')
RUNTIME_OPTIONS = {HOSTMANAGER: {'true', 'false'}, LB_TYPE: {'classic', 'application', 'network'}}
LOG_PATH_DOC = 'https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/using-features.logging.html'


def configuration_options_complete(options):
    """Raw pre-cache validity marker; filtering must never invent a false default."""
    if not isinstance(options, list):
        return False
    seen = set()
    for option in options:
        if not isinstance(option, dict) or not isinstance(option.get('Namespace'), str) or not isinstance(option.get('OptionName'), str):
            return False
        pair = option['Namespace'], option['OptionName']
        if pair in RUNTIME_OPTIONS:
            if pair in seen or option.get('ResourceName') or not isinstance(option.get('Value'), str) or option['Value'] not in RUNTIME_OPTIONS[pair]:
                return False
            seen.add(pair)
    return True


def _failure(status='malformed', reason='native_response_not_bound'):
    return {'collection_status': status, 'reason': reason}


def _identity(item, region):
    arn = item.get('EnvironmentArn')
    match = re.fullmatch(r'arn:(aws|aws-cn|aws-us-gov):elasticbeanstalk:([a-z0-9-]+):([0-9]{12}):environment/([^/]+)/([^/]+)', arn if isinstance(arn, str) else '')
    if (not match or match[2] != region or match[4] != item.get('ApplicationName') or match[5] != item.get('EnvironmentName')
            or item.get('AccountId', match[3]) != match[3]
            or not re.fullmatch(r'e-[a-z0-9]{1,40}', item.get('EnvironmentId', '') if isinstance(item.get('EnvironmentId'), str) else '')):
        return None
    partition = 'aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'
    if partition != match[1]:
        return None
    return match[1], match[3]


def _options(item, response):
    settings = response.get('ConfigurationSettings')
    if (response.get('collection_status') != 'collected' or not isinstance(settings, list) or len(settings) != 1
            or not isinstance(settings[0], dict)):
        return None
    setting = settings[0]
    if (setting.get('ApplicationName') != item.get('ApplicationName') or setting.get('EnvironmentName') != item.get('EnvironmentName')
            or setting.get('DeploymentStatus', 'deployed') != 'deployed'
            or setting.get('BeanstalkRuntimeOptionsComplete') is not True
            or not configuration_options_complete(setting.get('OptionSettings'))):
        return None
    return {(row['Namespace'], row['OptionName']): row['Value'] for row in setting['OptionSettings']
            if (row['Namespace'], row['OptionName']) in RUNTIME_OPTIONS}


def _scoped_arn(value, partition, account, region, resource):
    prefix = f'arn:{partition}:elasticloadbalancing:{region}:{account}:{resource}'
    return isinstance(value, str) and re.fullmatch(re.escape(prefix) + r'[0-9a-f]{16}', value) is not None


def _certificate(value, partition, account, region):
    return isinstance(value, str) and (re.fullmatch(re.escape(f'arn:{partition}:acm:{region}:{account}:certificate/') + r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value) is not None
        or re.fullmatch(re.escape(f'arn:{partition}:iam::{account}:server-certificate/') + r'[^\s]+', value) is not None)


def _v2(requests, session, region, name, kind, partition, account):
    output = {'Name': name}
    read = requests.pages(session, 'elbv2', region, 'describe_load_balancers', 'LoadBalancers', Names=[name])
    if read.status != 'collected' or len(read.items) != 1:
        return output
    lb = read.items[0]
    if not isinstance(lb, dict) or lb.get('LoadBalancerName') != name or lb.get('Type') != kind:
        return output
    arn = lb.get('LoadBalancerArn')
    resource = ('app/' if kind == 'application' else 'net/') + name + '/'
    if not _scoped_arn(arn, partition, account, region, 'loadbalancer/' + resource):
        return output
    output.update(Type=kind, LoadBalancerArn=arn)
    listeners = requests.pages(session, 'elbv2', region, 'describe_listeners', 'Listeners', LoadBalancerArn=arn)
    projected = []
    if listeners.status in {'collected', 'empty'}:
        seen = set()
        for listener in listeners.items:
            if (not isinstance(listener, dict) or listener.get('LoadBalancerArn') != arn
                    or not isinstance(listener.get('ListenerArn'), str)
                    or not re.fullmatch(re.escape(arn.replace(':loadbalancer/', ':listener/') + '/') + r'[0-9a-f]{16}', listener['ListenerArn'])
                    or listener['ListenerArn'] in seen):
                break
            seen.add(listener['ListenerArn'])
            row = {key: deepcopy(listener[key]) for key in ('Protocol', 'Port', 'ListenerArn') if key in listener}
            if 'Certificates' in listener:
                certs = listener['Certificates']
                if not isinstance(certs, list) or any(not isinstance(c, dict) or not _certificate(c.get('CertificateArn'), partition, account, region) for c in certs):
                    break
                row['Certificates'] = [{'CertificateArn': c['CertificateArn']} for c in certs]
            if 'DefaultActions' in listener:
                actions = listener['DefaultActions']
                if not isinstance(actions, list) or any(not isinstance(a, dict) or not isinstance(a.get('Type'), str) for a in actions):
                    break
                row['DefaultActions'] = [{'Type': a['Type'], **({'RedirectConfig': {'Protocol': a['RedirectConfig'].get('Protocol')}}
                    if isinstance(a.get('RedirectConfig'), dict) else {})} for a in actions]
            projected.append(row)
        else:
            output['Listeners'] = projected
    attributes = requests.detail(session, 'elbv2', region, 'describe_load_balancer_attributes', LoadBalancerArn=arn)
    if attributes.get('collection_status') == 'collected' and isinstance(attributes.get('Attributes'), list):
        output['Attributes'] = [{'Key': a.get('Key'), 'Value': a.get('Value')} for a in attributes['Attributes']
                                if isinstance(a, dict) and a.get('Key') == 'access_logs.s3.enabled']
    return output


def _classic(requests, session, region, name, partition, account):
    output = {'Name': name}
    read = requests.pages(session, 'elb', region, 'describe_load_balancers', 'LoadBalancerDescriptions', LoadBalancerNames=[name])
    if read.status != 'collected' or len(read.items) != 1:
        return output
    lb = read.items[0]
    if not isinstance(lb, dict) or lb.get('LoadBalancerName') != name:
        return output
    output['Type'] = 'classic'
    descriptions = lb.get('ListenerDescriptions')
    if isinstance(descriptions, list):
        projected = []
        for description in descriptions:
            listener = description.get('Listener') if isinstance(description, dict) else None
            if not isinstance(listener, dict):
                break
            row = {key: deepcopy(listener[key]) for key in ('Protocol', 'SSLCertificateId') if key in listener}
            if 'SSLCertificateId' in row and not _certificate(row['SSLCertificateId'], partition, account, region):
                break
            # Classic ELB has no redirect actions: a plaintext listener cannot
            # be a native HTTP-to-HTTPS redirect. Do not invent missing TLS.
            row['DefaultActions'] = []
            projected.append(row)
        else:
            output['Listeners'] = projected
    attrs = requests.detail(session, 'elb', region, 'describe_load_balancer_attributes', LoadBalancerName=name)
    if attrs.get('collection_status') == 'collected':
        value = attrs.get('LoadBalancerAttributes')
        access = value.get('AccessLog') if isinstance(value, dict) else None
        if isinstance(access, dict) and type(access.get('Enabled')) is bool:
            output['LoadBalancerAttributes'] = {'AccessLog': {'Enabled': access['Enabled']}}
    return output


def enrich_environment(requests, session, region, item, configuration_response):
    """Called once from the existing config enricher; all reads share Requests."""
    identity = _identity(item, region)
    options = _options(item, configuration_response) if identity else None
    item.setdefault('Configuration', {})['hostmanager_options_complete'] = options is not None
    item['S3LogDestination'] = _failure('not_collected', 'managed_path_unresolved')
    item['EnvironmentResources'] = _failure()
    item['AssociatedLoadBalancers'] = []
    if identity is None:
        return item
    partition, account = identity
    if options is not None and partition == 'aws':
        item['S3LogDestination'] = {'collection_status': 'collected', 'resolved': True,
            'bucket': f'elasticbeanstalk-{region}-{account}',
            'prefix': f"resources/environments/logs/publish/{item['EnvironmentId']}/",
            'source': 'documented_managed_path', 'documentation': LOG_PATH_DOC,
            'delivery_observed': False, 'retention_assessed': False}
    if item.get('Status') in {'Terminating', 'Terminated'}:
        return item
    response = requests.detail(session, 'elasticbeanstalk', region, 'describe_environment_resources',
                               EnvironmentId=item['EnvironmentId'], EnvironmentName=item['EnvironmentName'])
    resources = response.get('EnvironmentResources')
    if response.get('collection_status') != 'collected':
        item['EnvironmentResources'] = _failure(response.get('collection_status', 'malformed'), 'association_read_unavailable')
        return item
    if not isinstance(resources, dict) or resources.get('EnvironmentName') != item['EnvironmentName']:
        return item
    lbs = resources.get('LoadBalancers')
    if (not isinstance(lbs, list) or any(not isinstance(lb, dict) or not isinstance(lb.get('Name'), str)
            or not re.fullmatch(r'[A-Za-z0-9-]{1,32}', lb['Name']) for lb in lbs)):
        return item
    names = [lb['Name'] for lb in lbs]
    if len(names) != len(set(names)):
        return item
    instances = resources.get('Instances')
    if instances is not None and (not isinstance(instances, list) or any(not isinstance(instance, dict) or
            not re.fullmatch(r'i-[0-9a-f]+', instance.get('Id', '') if isinstance(instance.get('Id'), str) else '')
            for instance in instances)):
        return item
    item['EnvironmentResources'] = {'collection_status': 'collected', 'EnvironmentName': item['EnvironmentName'],
        'LoadBalancers': [{'Name': name} for name in names],
        'Instances': [{'Id': instance['Id']} for instance in instances] if isinstance(instances, list) else None,
        'source_operation': 'elasticbeanstalk:DescribeEnvironmentResources'}
    if options is None:
        return item
    # AWS documents classic as the default only on complete configuration.
    kind = options.get(LB_TYPE, 'classic')
    for name in names:
        if kind == 'classic':
            item['AssociatedLoadBalancers'].append(_classic(requests, session, region, name, partition, account))
        else:
            item['AssociatedLoadBalancers'].append(_v2(requests, session, region, name, kind, partition, account))
    return item
