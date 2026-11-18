"""Offline AWS Backup ARN/tag selection algebra over complete native facts.

https://docs.aws.amazon.com/aws-backup/latest/devguide/assigning-resources-json.html
Resources and ListOfTags form the inclusion OR; Conditions refine it with AND;
NotResources removes matching ARNs. Unreadable tags never establish a match.
"""
import re
from .facts import Unavailable, get, optional, list_of_objects


def arn_matches(pattern, arn):
    if not isinstance(pattern, str) or not pattern or not (pattern == "*" or pattern.startswith("arn:")):
        raise Unavailable("Backup selection ARN pattern malformed")
    return re.fullmatch(re.escape(pattern).replace(r"\*", ".*").replace(r"\?", "."), arn) is not None


def _strings(body, field):
    values = optional(body, field, [], list)
    if any(not isinstance(value, str) or not value for value in values):
        raise Unavailable("Backup selection resource list malformed")
    return values


def _tag(condition, tags, operator, legacy=False):
    key, value = get(condition, "ConditionKey", str), get(condition, "ConditionValue", str)
    if not key:
        raise Unavailable("Backup selection tag key empty")
    if not legacy:
        if not key.startswith("aws:ResourceTag/") or not key.removeprefix("aws:ResourceTag/"):
            raise Unavailable("Backup selection condition key unsupported")
        key = key.removeprefix("aws:ResourceTag/")
    if tags is None:
        return None
    current = tags.get(key)
    if operator in ("StringLike", "StringNotLike"):
        matched = current is not None and re.fullmatch(re.escape(value).replace(r"\*", ".*").replace(r"\?", "."), current) is not None
    else:
        matched = current is not None and current == value
    return not matched if operator in ("StringNotEquals", "StringNotLike") else matched


def matches(body, arn, tags=None):
    resources, excluded = _strings(body, "Resources"), _strings(body, "NotResources")
    if any(arn_matches(pattern, arn) for pattern in excluded):
        return False
    arn_hit = any(arn_matches(pattern, arn) for pattern in resources)
    legacy = list_of_objects(optional(body, "ListOfTags", [], list))
    tag_results = []
    for condition in legacy:
        if get(condition, "ConditionType", str) not in {"STRINGEQUALS", "StringEquals"}:
            raise Unavailable("Backup ListOfTags operator unsupported")
        tag_results.append(_tag(condition, tags, "StringEquals", legacy=True))
    included = True if arn_hit or any(value is True for value in tag_results) else None if any(value is None for value in tag_results) else False
    conditions = optional(body, "Conditions", {}, dict)
    if not resources and not legacy:
        if "Resources" in body and not conditions:
            return False
        return None  # Implicit all-resource selection also depends on service opt-in.
    if included is False:
        return False
    for operator, rows in conditions.items():
        if operator not in {"StringEquals", "StringNotEquals", "StringLike", "StringNotLike"}:
            raise Unavailable("Backup Conditions operator unsupported")
        for condition in list_of_objects(rows):
            hit = _tag(condition, tags, operator)
            if hit is False:
                return False
            if hit is None:
                included = None
    return included
