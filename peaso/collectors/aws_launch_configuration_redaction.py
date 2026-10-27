"""Inspect literal key pairs before caching Auto Scaling response metadata.

The native API returns base64 user data (16 KiB maximum). Decode failure or
an access key with an unresolved secret representation remains UNKNOWN.
Source: https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_LaunchConfiguration.html
"""
import base64
import re

ACCESS = re.compile(r'(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])')
SECRET = re.compile(r'''(?ix)(?:aws_secret_access_key|awsSecretAccessKey|secretAccessKey)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])''')


def indicators(encoded):
    if encoded is None or encoded == '':
        return {'InspectionStatus': 'collected', 'HasAwsKeyPair': False}
    try:
        if not isinstance(encoded, str) or len(encoded) > 32768:
            raise ValueError
        raw = base64.b64decode(encoded.replace('\r', '').replace('\n', ''), validate=True)
        if len(raw) > 16384:
            raise ValueError
        text = raw.decode('utf-8')
    except (ValueError, UnicodeError):
        return {'InspectionStatus': 'decode_failed'}
    access = bool(ACCESS.search(text))
    if access and not SECRET.search(text):
        return {'InspectionStatus': 'unresolved_key_pair'}
    return {'InspectionStatus': 'collected', 'HasAwsKeyPair': access}


def _remember_key_pair(row):
    """The key-pair check failed on text the payload reader rejected. Keep the
    exact access key and secret it matched in private evidence."""
    from peaso.secret_evidence import enabled, remember, source_context
    from peaso.secret_scanning import _fingerprint
    arn = row.get('LaunchConfigurationARN')
    match = re.fullmatch(r'arn:(?:aws|aws-cn|aws-us-gov):autoscaling:([a-z0-9-]+):([0-9]{12}):launchConfiguration:[^:]+:launchConfigurationName/.+', arn) if isinstance(arn, str) else None
    if not enabled() or match is None:
        return
    text = base64.b64decode(row['UserData'].replace('\r', '').replace('\n', ''), validate=True).decode('utf-8')
    values = [(found[0], found.start()) for found in ACCESS.finditer(text)] + [(found[1], found.start(1)) for found in SECRET.finditer(text)]
    with source_context(resource_id=arn, scope=match[2] + '/' + match[1], path='UserData',
                        check_ids={'aws_autoscaling_userdata_plaintext_aws_key'},
                        source='autoscaling:DescribeLaunchConfigurations'):
        for value, offset in values:
            remember(value, _fingerprint(value), path='UserData', line=text[:offset].count('\n') + 1,
                     engine='configuration', rule='cloud_credential')


def project_response(response):
    from .aws_b_services import _metadata
    if not isinstance(response, dict) or not isinstance(response.get('LaunchConfigurations'), list):
        from .aws import ReadFailure
        raise ReadFailure('malformed', 'invalid_launch_configuration_response')
    rows = []
    for row in response['LaunchConfigurations']:
        if not isinstance(row, dict):
            from .aws import ReadFailure
            raise ReadFailure('malformed', 'invalid_launch_configuration_row')
        safe = _metadata(row)
        safe['UserDataIndicators'] = indicators(row.get('UserData'))
        from .aws_configuration_payload_secret_indicators import launch_configuration_indicator
        safe['PayloadSecretIndicators'] = launch_configuration_indicator(row)
        if (safe['UserDataIndicators'].get('HasAwsKeyPair')
                and safe['PayloadSecretIndicators'].get('collection_status') != 'collected'):
            _remember_key_pair(row)
        rows.append(safe)
    return {**_metadata(response), 'LaunchConfigurations': rows}
