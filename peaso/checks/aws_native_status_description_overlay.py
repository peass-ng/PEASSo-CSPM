"""Current AWS descriptions and remediation over frozen reviewed rows."""
from copy import deepcopy

VERSION = "aws-native-status-description-remediation-v1"
ROWS = {'aws.a.cloudtrail.bucket_access_logging': {'description_base_sha256': '7ce37a6fc8ba780c8b63019820a1a051304cca07991136997acf72aaa516f6be',
                                            'description_fields': {'description': 'For every CloudTrail '
                                                                                  'trail, joins the '
                                                                                  "trail's S3BucketName "
                                                                                  'to the same-account '
                                                                                  'bucket inventory and '
                                                                                  'FAILs when that '
                                                                                  'destination bucket '
                                                                                  'has no server access '
                                                                                  'logging (no '
                                                                                  'Logging.LoggingEnabled.TargetBucket). '
                                                                                  'A destination absent '
                                                                                  'from a complete '
                                                                                  'same-account '
                                                                                  'inventory is UNKNOWN '
                                                                                  'until its settings '
                                                                                  'are read; missing '
                                                                                  'access logs on the '
                                                                                  'log bucket leave '
                                                                                  'reads, deletions or '
                                                                                  'tampering without an '
                                                                                  'access record.'},
                                            'remediation_base_sha256': '688f637ac5331f566ff1bbe12f3172760146d047c8d25107b0dd8bb804a5a9d0',
                                            'remediation_fields': {'caveats': ['An unverified '
                                                                               'destination is UNKNOWN; '
                                                                               'an absent target on a '
                                                                               'successful bucket '
                                                                               'response is a known '
                                                                               'failure.',
                                                                               'The trail bucket name '
                                                                               'is never inferred from '
                                                                               'the trail ARN; verify '
                                                                               'the native S3BucketName '
                                                                               'and account scope '
                                                                               'before replacing '
                                                                               '<TRAIL_BUCKET_NAME>.']}},
 'aws.a.cloudtrail.bucket_mfa_delete': {'description_base_sha256': 'fecc1e74d375e6b7563413020cf64006e6e5a394a34b937122eba540eed09f33',
                                        'description_fields': {'description': 'For CloudTrail trails '
                                                                              'that are currently '
                                                                              'logging, joins the '
                                                                              'destination S3 bucket '
                                                                              'from the same-account '
                                                                              'inventory and FAILs when '
                                                                              'its versioning '
                                                                              'configuration does not '
                                                                              'report '
                                                                              'MFADelete=Enabled. A '
                                                                              'destination absent from '
                                                                              'complete same-account '
                                                                              'inventory is UNKNOWN '
                                                                              'until its settings are '
                                                                              'read; without MFA '
                                                                              'Delete, a principal with '
                                                                              'sufficient S3 '
                                                                              'permissions can erase '
                                                                              'audit evidence.',
                                                               'not_applicable_when': 'NOT_APPLICABLE '
                                                                                      'when '
                                                                                      'Status.IsLogging '
                                                                                      'is false; an '
                                                                                      'unverified '
                                                                                      'destination '
                                                                                      'returns '
                                                                                      'UNKNOWN.'},
                                        'remediation_base_sha256': 'b7c94ffd952806a8ec11dcb830f773ab2630051693bf8f0fa2f25919aeda2934',
                                        'remediation_fields': {'caveats': ['A nonlogging trail is '
                                                                           'NOT_APPLICABLE; a bucket '
                                                                           'outside verified snapshot '
                                                                           'scope is UNKNOWN, not proof '
                                                                           'its MFA Delete is disabled.',
                                                                           'The trail bucket name is '
                                                                           'never inferred from the '
                                                                           'trail ARN; verify the '
                                                                           'native S3BucketName and '
                                                                           'account scope before '
                                                                           'replacing '
                                                                           '<TRAIL_BUCKET_NAME>.']}},
 'aws.a.iam.attached_policy_no_star_star': {'description_base_sha256': '33e709cda088f2605d34cdb34c01289c0f526391d70b339aeb8f90b8cb21f150',
                                            'description_fields': {'description': 'For customer-managed '
                                                                                  'IAM policies '
                                                                                  'attached to at least '
                                                                                  'one principal '
                                                                                  '(AttachmentCount > '
                                                                                  '0), inspects the '
                                                                                  'default policy '
                                                                                  'version and FAILs '
                                                                                  'when any Allow '
                                                                                  'statement combines '
                                                                                  "Resource '*' with "
                                                                                  "Action '*' or '*:*'. "
                                                                                  'AWS-managed policies '
                                                                                  'are assessed by a '
                                                                                  'separate native '
                                                                                  'check and are '
                                                                                  'NOT_APPLICABLE here.',
                                                                   'not_applicable_when': 'NOT_APPLICABLE '
                                                                                          'when '
                                                                                          'AttachmentCount '
                                                                                          'is zero or '
                                                                                          'the policy '
                                                                                          'is '
                                                                                          'AWS-managed.'},
                                            'remediation_base_sha256': '40dcfd3574d92a31b769b6cb17ea4a615cfd38b8a1e1daafd50e7df9e07a3c83',
                                            'remediation_fields': {'caveats': ['This source checks '
                                                                               'declared explicit '
                                                                               'Action/Resource '
                                                                               'literals, including '
                                                                               'conditioned statements; '
                                                                               'it does not simulate '
                                                                               'denies, boundaries or '
                                                                               'effective access.',
                                                                               'AWS-managed policies '
                                                                               'are NOT_APPLICABLE in '
                                                                               'this customer-managed '
                                                                               'evaluator; the separate '
                                                                               'AWS-managed '
                                                                               'attached-policy check '
                                                                               'assesses their declared '
                                                                               'administrator '
                                                                               'grants.']}}}


def description(check_id, original):
    row = ROWS.get(check_id)
    if row is None:
        return deepcopy(original)
    current = deepcopy(original) if isinstance(original, dict) else {}
    current.update(deepcopy(row["description_fields"]))
    current["description_correction"] = {"version": VERSION,
        "base_row_sha256": row["description_base_sha256"],
        "source_relationship": "Current native UNKNOWN and NOT_APPLICABLE branches supersede frozen descriptive prose; signed descriptions remain immutable."}
    return current


def remediation(check_id, original):
    row = ROWS.get(check_id)
    if row is None:
        return deepcopy(original)
    current = deepcopy(original) if isinstance(original, dict) else {}
    current.update(deepcopy(row["remediation_fields"]))
    current["source_correction"] = {"version": VERSION,
        "base_row_sha256": row["remediation_base_sha256"],
        "source_relationship": "Current native UNKNOWN and NOT_APPLICABLE branches supersede frozen remediation caveats."}
    return current


def validate_rows(checks):
    for check_id in ROWS:
        description(check_id, checks.get(check_id))
