"""Readable identifiers for resources attributed to compiled findings."""
import re

_DETECTOR_ID = re.compile(r'[0-9a-f]{32}')
_AWS_REGION_SCOPE = re.compile(r'([0-9]{12})/([a-z]{2}-[a-z0-9-]+-[0-9]+)')


def is_detector_id(value):
    return isinstance(value, str) and _DETECTOR_ID.fullmatch(value) is not None


def guardduty_detector_arn(value, finding, *, resource_type=None):
    check = finding.get('check_id') or ''
    if not is_detector_id(value) or finding.get('provider') not in (None, 'aws') or not check.startswith('aws.'):
        return None
    if resource_type is not None:
        if resource_type != 'guardduty_detector':
            return None
    elif '.guardduty.' not in check:
        return None
    scope = _AWS_REGION_SCOPE.fullmatch(finding.get('scope') or '')
    if not scope or '-iso' in scope[2]:
        return None
    from peaso.aws_image_selection_20261021 import partition
    account, region = scope.groups()
    return f'arn:{partition(region)}:guardduty:{region}:{account}:detector/{value}'
