"""Deployed REST methods and effective stage WAF associations, without invocation."""
from __future__ import annotations

import re
from urllib.parse import quote

SPECS = {'rest_api_method': ('apigateway', 'get_deployment', None),
         'stage_waf_association': ('wafv2', 'get_web_acl_for_resource', None)}
NATIVE_IDS = {'rest_api_method': 'id', 'stage_waf_association': 'stageArn'}
READ_ACTIONS = {('apigateway', 'get_rest_apis'), ('apigateway', 'get_stages'),
                ('apigateway', 'get_deployment'), ('wafv2', 'get_web_acl_for_resource')}


def _result(rows=(), status=None, code=None):
    from .aws import ReadResult
    rows = list(rows)
    return ReadResult(rows, status or ('collected' if rows else 'empty'), {'code': code} if code else None)


def _stages(requests, session, region, account):
    from .aws_b_services import FETCHERS
    read = FETCHERS['rest_api_stage'](requests, session, region, account)
    if read.status not in ('collected', 'empty'):
        return [], read
    partition = session.get_partition_for_region(region)
    seen, stages = set(), []
    for row in read.items:
        api, name = row.get('ParentApiId'), row.get('stageName')
        if (not isinstance(api, str) or not re.fullmatch(r'[a-z0-9]{1,32}', api)
                or not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', name)):
            return [], _result([], 'malformed', 'apigateway_stage_identity_invalid')
        arn = f'arn:{partition}:apigateway:{region}::/restapis/{api}/stages/{name}'
        if row.get('id') != arn or arn in seen:
            return [], _result([], 'malformed', 'apigateway_stage_identity_invalid')
        seen.add(arn)
        stages.append(row)
    return stages, None


def deployed_methods(requests, session, region, account):
    stages, failure = _stages(requests, session, region, account)
    if failure:
        return failure
    rows = []
    for stage in stages:
        api, deployment = stage['ParentApiId'], stage.get('deploymentId')
        if not isinstance(deployment, str) or not re.fullmatch(r'[a-z0-9]{1,32}', deployment):
            return _result(rows, 'partial' if rows else 'malformed', 'apigateway_stage_deployment_unavailable')
        # A percentage canary may execute a second deployment. A single summary
        # cannot establish all methods deployed on that stage.
        canary = stage.get('canarySettings')
        if canary is not None:
            if not isinstance(canary, dict) or type(canary.get('percentTraffic', 0)) not in (int, float):
                return _result(rows, 'partial' if rows else 'malformed', 'apigateway_canary_settings_invalid')
            if canary.get('percentTraffic', 0) != 0:
                return _result(rows, 'partial' if rows else 'not_collected', 'apigateway_canary_deployment_unresolved')
        response = requests.detail(session, 'apigateway', region, 'get_deployment',
                                   restApiId=api, deploymentId=deployment, embed=['apisummary'])
        if response.get('collection_status') != 'collected':
            return _result(rows, 'partial' if rows else response.get('collection_status', 'unknown'),
                           response.get('error', {}).get('code', 'apigateway_deployment_read_incomplete'))
        summary = response.get('apiSummary')
        if response.get('id') != deployment or not isinstance(summary, dict):
            return _result(rows, 'partial' if rows else 'malformed', 'apigateway_deployment_summary_invalid')
        if not summary:
            # API Gateway cannot deploy an API with no methods. An omitted
            # embedded summary must not be confused with verified no routes.
            return _result(rows, 'partial' if rows else 'malformed', 'apigateway_deployment_summary_empty')
        for path, methods in summary.items():
            if (not isinstance(path, str) or len(path) > 4096 or not path.startswith('/')
                    or not isinstance(methods, dict) or not methods):
                return _result(rows, 'partial' if rows else 'malformed', 'apigateway_deployment_route_invalid')
            for method, declaration in methods.items():
                if method not in ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'ANY') or not isinstance(declaration, dict):
                    return _result(rows, 'partial' if rows else 'malformed', 'apigateway_deployment_method_invalid')
                rows.append({'id': stage['id'] + '/deployed-method/' + quote(path + '/' + method, safe=''),
                    'stageArn': stage['id'], 'restApiId': api, 'deploymentId': deployment,
                    'resourcePath': path, 'httpMethod': method, 'methodSettingKey': path + '/' + method,
                    'authorizationType': declaration.get('authorizationType'),
                    'apiKeyRequired': declaration.get('apiKeyRequired'),
                    '_provenance': {'source_operation': 'GetDeployment', 'read_only': True,
                        'embed': 'apisummary', 'stage_deployment_join_verified': True}})
    return _result(rows)


def stage_waf(requests, session, region, account):
    stages, failure = _stages(requests, session, region, account)
    if failure:
        return failure
    rows = []
    partition = session.get_partition_for_region(region)
    for stage in stages:
        arn = stage['id']
        response = requests.detail(session, 'wafv2', region, 'get_web_acl_for_resource', ResourceArn=arn)
        if response.get('collection_status') != 'collected':
            return _result(rows, 'partial' if rows else response.get('collection_status', 'unknown'),
                           response.get('error', {}).get('code', 'apigateway_waf_association_incomplete'))
        acl = response.get('WebACL')
        value = ''
        if acl is not None:
            if (not isinstance(acl, dict) or not isinstance(acl.get('ARN'), str)
                    or not re.fullmatch('arn:' + re.escape(partition) + ':wafv2:' + re.escape(region)
                        + ':' + re.escape(account) + r':regional/webacl/[A-Za-z0-9_-]{1,128}/[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}', acl['ARN'])
                    or not isinstance(acl.get('Id'), str) or acl['ARN'].rsplit('/', 1)[-1] != acl['Id']):
                return _result(rows, 'partial' if rows else 'malformed', 'apigateway_waf_identity_invalid')
            value = acl['ARN']
        rows.append({'stageArn': arn, 'webAclArn': value,
            '_provenance': {'source_operation': 'GetWebACLForResource', 'read_only': True,
                            'resource_arn': arn, 'absence_verified': acl is None}})
    return _result(rows)


FETCHERS = {'rest_api_method': deployed_methods, 'stage_waf_association': stage_waf}
