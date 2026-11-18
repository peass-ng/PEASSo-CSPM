"""Backup Resources OR legacy tags, AND Conditions, with exclusions and unknown tags."""
import pytest
from peaso.checks.aws_backup_selection import matches

ARN = 'arn:aws:rds:us-east-1:123456789012:db:database'


def condition(operator='StringEquals', value='true'):
    return {operator: [{'ConditionKey': 'aws:ResourceTag/backup', 'ConditionValue': value}]}


@pytest.mark.parametrize('tags,expected', [({'backup': 'true'}, True), ({'backup': 'false'}, False), ({}, False), (None, None)])
def test_rds_wildcard_with_exact_native_tag_condition(tags, expected):
    body = {'Resources': ['arn:aws:rds:*:*:db:*'], 'Conditions': condition()}
    assert matches(body, ARN, tags) is expected


def test_exclusions_dominate_and_legacy_tag_inclusion_is_or_then_refined_by_and():
    assert matches({'Resources': ['*'], 'NotResources': ['arn:aws:rds:*']}, ARN, None) is False
    body = {'Resources': ['arn:aws:s3:::*'], 'ListOfTags': [{'ConditionType': 'STRINGEQUALS', 'ConditionKey': 'backup', 'ConditionValue': 'true'}],
            'Conditions': {'StringNotEquals': [{'ConditionKey': 'aws:ResourceTag/stage', 'ConditionValue': 'test'}]}}
    assert matches(body, ARN, {'backup': 'true', 'stage': 'prod'}) is True
    assert matches(body, ARN, {'backup': 'true', 'stage': 'test'}) is False
    assert matches(body, ARN, None) is None


def test_other_service_arn_cannot_select_s3_even_when_tag_context_is_unavailable():
    body = {'Resources': ['arn:aws:rds:*:*:db:*'], 'Conditions': condition()}
    assert matches(body, 'arn:aws:s3:::bucket', None) is False


def test_stringlike_uses_aws_wildcards_without_shell_bracket_expansion():
    assert matches({'Resources': ['*'], 'Conditions': condition('StringLike', 'prod*')}, ARN, {'backup': 'production'}) is True
    assert matches({'Resources': ['*'], 'Conditions': condition('StringLike', 'prod[ab]')}, ARN, {'backup': 'proda'}) is False
