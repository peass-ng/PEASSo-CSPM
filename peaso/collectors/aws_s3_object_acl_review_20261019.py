"""Bounded, read-only current-object ACL sample for existing global bucket facts.

Pending root registration: chain ENRICHERS['bucket']; allow the two READ_ACTIONS
below and s3:ListBucket / s3:GetObjectAcl in the customer role. No object payload,
version history, policy simulator, authentication probe or write is requested.
"""
from __future__ import annotations

import copy
import re

READ_ACTIONS = {('s3', 'list_objects_v2'), ('s3', 'get_object_acl')}
DEFAULT_LIMIT = 20
PERMISSIONS = {'READ', 'WRITE', 'READ_ACP', 'WRITE_ACP', 'FULL_CONTROL'}


def bucket_region(item):
    coverage = item.get('_coverage', {})
    if not isinstance(coverage, dict) or ('Location' in coverage and (
            not isinstance(coverage['Location'], dict) or coverage['Location'].get('status') != 'collected')):
        raise ValueError('bucket_location_unavailable')
    location = item.get('Location')
    if not isinstance(location, dict) or location.get('collection_status') != 'collected':
        raise ValueError('bucket_location_unavailable')
    selected = location.get('LocationConstraint')
    proof = location.get('_coverage', {})
    if not isinstance(proof, dict):
        raise ValueError('bucket_location_malformed')
    if 'LocationConstraint' in proof:
        marker = proof['LocationConstraint']
        if (not isinstance(marker, dict) or marker.get('status') not in ('collected', 'empty') or
                marker['status'] == 'empty' and selected is not None or
                marker['status'] == 'collected' and 'LocationConstraint' not in location):
            raise ValueError('bucket_location_unavailable')
    if selected is None:
        return 'us-east-1'
    if selected == 'EU':
        return 'eu-west-1'
    if not isinstance(selected, str) or re.fullmatch(r'[a-z][a-z0-9]+(?:-[a-z0-9]+)+-\d+', selected) is None:
        raise ValueError('bucket_location_malformed')
    return selected


def _grants(response):
    """Retain exact public grant fields, omit owner IDs/emails/display names."""
    grants = response.get('Grants') if isinstance(response, dict) else None
    if not isinstance(grants, list) or not grants:
        raise ValueError('object_acl_grants_missing_or_empty')
    out, malformed = [], False
    for grant in grants:
        if not isinstance(grant, dict) or grant.get('Permission') not in PERMISSIONS:
            malformed = True
            continue
        principal = grant.get('Grantee')
        if not isinstance(principal, dict):
            malformed = True
            continue
        kind = principal.get('Type')
        if kind == 'Group':
            if not isinstance(principal.get('URI'), str) or not principal['URI']:
                malformed = True
                continue
            selected = {'Type': kind, 'URI': principal['URI']}
        elif kind in ('CanonicalUser', 'AmazonCustomerByEmail'):
            required = 'ID' if kind == 'CanonicalUser' else 'EmailAddress'
            if not isinstance(principal.get(required), str) or not principal[required]:
                malformed = True
                continue
            selected = {'Type': kind}
        else:
            malformed = True
            continue
        out.append({'Permission': grant['Permission'], 'Grantee': selected})
    return out, malformed


def sample_bucket(requests, session, item, *, limit=DEFAULT_LIMIT):
    """At most limit current-object ACL reads; pagination also has a finite cap."""
    from .aws import _failure
    from .aws_request_pool import run_all
    sample = {'collection_status': 'not_collected', 'bucket': item.get('Name') if isinstance(item, dict) else None, 'region': None,
              'limit': limit, 'sampled_count': 0, 'listing_complete': False, 'truncated': False,
              'objects': [], 'errors': [], 'scope': 'sampled_current_object_acls_only'}
    sample['selection_method'] = 'first_keys_from_ListObjectsV2_not_random'
    if not isinstance(item, dict):
        sample.update(collection_status='malformed', errors=[{'code': 'bucket_shape_malformed'}])
        return sample
    if type(limit) is not int or not 1 <= limit <= DEFAULT_LIMIT:
        sample.update(collection_status='malformed', errors=[{'code': 'invalid_sample_limit'}])
        return sample
    try:
        name = item.get('Name')
        if not isinstance(name, str) or not name or len(name) > 63 or '/' in name or ':' in name:
            raise ValueError('bucket_name_malformed')
        if name.endswith('--x-s3'):
            raise ValueError('directory_bucket_not_supported_by_acl_sampling')
        selected = bucket_region(item)
        sample['region'] = selected
    except ValueError as exc:
        sample.update(collection_status='not_collected', errors=[{'code': str(exc)}])
        return sample

    # Bound both listed keys and empty/truncated listing pages. Requests.call
    # additionally enforces the scan-wide call/retry/deadline budgets and cache.
    max_pages = min(getattr(requests, 'max_pages', None) or limit, limit)
    token, seen_tokens, seen_keys = None, set(), set()
    failed = False
    for _page in range(max_pages):
        remaining = limit - len(sample['objects'])
        arguments = {'Bucket': name, 'MaxKeys': remaining}
        if token is not None:
            arguments['ContinuationToken'] = token
        try:
            response = requests.call(session, 's3', selected, 'list_objects_v2', **arguments)
            if (not isinstance(response, dict) or type(response.get('IsTruncated')) is not bool or
                    response.get('Name', name) != name or response.get('CommonPrefixes')):
                raise ValueError('object_list_malformed')
            keys = response.get('Contents', [])
            if not isinstance(keys, list) or len(keys) > remaining:
                raise ValueError('object_list_exceeds_requested_limit_or_malformed')
            if 'KeyCount' in response and (type(response['KeyCount']) is not int or response['KeyCount'] != len(keys)):
                raise ValueError('object_list_key_count_mismatch')
            more = response['IsTruncated']
            next_token = response.get('NextContinuationToken')
            if more and (not isinstance(next_token, str) or not next_token or next_token in seen_tokens):
                raise ValueError('object_list_continuation_missing_or_repeated')
            if not more and next_token:
                raise ValueError('object_list_completion_contradicts_continuation')
        except Exception as exc:
            failure = _failure(exc)
            status = 'malformed' if isinstance(exc, ValueError) else failure.status
            code = str(exc) if isinstance(exc, ValueError) else failure.code
            sample['errors'].append({'operation': 'ListObjectsV2', 'status': status, 'code': code})
            sample['collection_status'] = 'partial' if sample['objects'] else status
            return sample

        sample['listing_complete'] = not more
        page_objects = []
        for row in keys:
            key = row.get('Key') if isinstance(row, dict) else None
            try:
                valid_key = isinstance(key, str) and bool(key) and len(key.encode('utf-8')) <= 1024 and key not in seen_keys
            except UnicodeError:
                valid_key = False
            if not valid_key:
                failed = True
                sample['errors'].append({'operation': 'ListObjectsV2', 'status': 'malformed', 'code': 'object_key_missing_or_duplicate'})
                continue
            seen_keys.add(key)
            obj = {'Key': key, 'collection_status': 'not_collected', 'Grants': []}
            sample['objects'].append(obj)
            sample['sampled_count'] = len(sample['objects'])
            page_objects.append(obj)
        # The page's object ACL reads are independent; run them concurrently
        # and apply each outcome in key order exactly as the serial loop did.
        outcomes = run_all(requests, [lambda key=obj['Key']: requests.call(
            session, 's3', selected, 'get_object_acl', Bucket=name, Key=key) for obj in page_objects])
        for obj, (ok, value) in zip(page_objects, outcomes):
            try:
                if not ok:
                    raise value
                obj['Grants'], malformed = _grants(value)
                obj['collection_status'] = 'partial' if malformed else 'collected'
                if malformed:
                    failed = True
                    obj['error'] = {'code': 'object_acl_contains_malformed_grants'}
            except Exception as exc:
                failure = _failure(exc)
                obj['collection_status'] = 'malformed' if isinstance(exc, ValueError) else failure.status
                obj['error'] = {'code': str(exc) if isinstance(exc, ValueError) else failure.code}
                failed = True
        sample['truncated'] = more
        if failed:
            sample['collection_status'] = 'partial'
            return sample
        if not more:
            sample.update(collection_status='collected' if sample['objects'] else 'empty', listing_complete=True)
            return sample
        if len(sample['objects']) >= limit:
            sample.update(collection_status='partial')
            sample['errors'].append({'code': 'sample_limit', 'status': 'not_collected'})
            return sample
        seen_tokens.add(next_token)
        token = next_token
    sample.update(collection_status='partial' if sample['objects'] else 'not_collected', truncated=True)
    sample['errors'].append({'code': 'listing_page_limit', 'status': 'not_collected'})
    return sample


def enrich(requests, session, region, items):
    """Chain on the existing global bucket inventory, never regional discovery."""
    out = []
    for item in items:
        safe = copy.deepcopy(item)
        if not isinstance(safe, dict):
            out.append(safe)
            continue
        safe['ObjectAclSample'] = sample_bucket(requests, session, safe,
                                                limit=getattr(requests, 's3_object_acl_sample_limit', DEFAULT_LIMIT))
        out.append(safe)
    return out


ENRICHERS = {'bucket': enrich}
