"""API taxonomy lookup without installing native evaluators.

The signed aliases are build-checked against the native registrar.
This successor changes presentation metadata lookup only. It never supplies
observations, verdicts, expected contexts, or source-read authorization.
"""
from functools import lru_cache
import json
from pathlib import Path
from types import MappingProxyType

REGISTRY_PATH = Path(__file__).resolve().parent / 'checks/finding_types.json'
MAX_REGISTRY_BYTES = 1024 * 1024
ALIASES = MappingProxyType({
    'gcp.compute.os_login': 'gcp.ports.compute_oslogin_metadata_precedence',
    'gcp.sql.require_tls': 'gcp.ports.sql_instance_require_ssl_enabled',
    'aws_fedramp_rds_cluster_members_enhanced_monitoring': 'aws.nist.rds_cluster_member_enhanced_monitoring',
    'aws_g6_redshift_automatic_version_upgrade': 'aws.cb.redshift.allow_version_upgrade',
    'aws.pci.cloudtrail.authentication_events': 'aws.gap.cloudtrail.region_logging_management_events',
    'aws.a.cloudwatch.cross_account_role_absent': 'aws.claude2_a.cloudwatch.cross_account_sharing_role_absent',
    'aws.a.s3.bucket_account_public_blocks': 'aws.s3.public_access_block',
    'aws.b.redshift.no_public_endpoint': 'aws.cb.redshift.not_publicly_accessible',
    'aws.c2b.ecs.service_no_public_ip': 'aws.c2b.ecs.awsvpc_service_no_public_ip',
    'aws.c2b.elasticache.cluster_public_subnet': 'aws.c2b.elasticache.cluster_public_subnet_prowler',
    'aws.cb.sns.policy_prohibit_public_access_perimeter': 'aws.cb.sns.policy_no_unrestricted_wildcard',
    'azure.claude.aks_authorized_ip_ranges': 'azure.aks.api_server_restricted',
})


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate taxonomy key')
        result[key] = value
    return result


@lru_cache(maxsize=1)
def _checks():
    with REGISTRY_PATH.open('rb') as stream:
        raw = stream.read(MAX_REGISTRY_BYTES + 1)
    if len(raw) > MAX_REGISTRY_BYTES:
        raise ValueError('API taxonomy registry is too large')
    data = json.loads(raw, object_pairs_hook=_pairs)
    ids = [row['id'] for row in data['types']]
    checks = data['checks']
    if (data.get('schema_version') != 1 or len(ids) != len(set(ids))
            or 'unclassified' in ids or type(checks) is not dict
            or any(type(key) is not str or value not in ids for key, value in checks.items())
            or any(target not in checks or alias in checks for alias, target in ALIASES.items())):
        raise ValueError('Invalid API finding type taxonomy')
    return MappingProxyType(checks)


def type_for(check_id, category=None):
    value = _checks().get(ALIASES.get(check_id, check_id))
    return value or ('permissions' if category == 'privesc' else 'unclassified')


def install():
    from peaso import finding_types
    finding_types.type_for = type_for


SCOPE_PATH = Path(__file__).resolve().parent / 'checks/hacktricks_scope.json'


@lru_cache(maxsize=1)
def _scope():
    with SCOPE_PATH.open('rb') as stream:
        raw = stream.read(MAX_REGISTRY_BYTES + 1)
    if len(raw) > MAX_REGISTRY_BYTES:
        raise ValueError('Checklist presentation source is too large')
    data = json.loads(raw, object_pairs_hook=_pairs)
    if data.get('schema_version') != 1:
        raise ValueError('Unsupported HackTricks checklist review')
    for check_id, row in data['checks'].items():
        if row['decision'] not in ('include', 'exclude', 'pending') or row['group'] not in data['groups']:
            raise ValueError('Invalid HackTricks checklist decision: ' + check_id)
    return MappingProxyType({cid: row['decision'] for cid, row in data['checks'].items()})


def includes_in_hacktricks(check_id):
    return _scope().get(ALIASES.get(check_id, check_id)) == 'include'
