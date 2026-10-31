"""Public descriptions for native rotation and archive configuration.

Original signed packs remain unchanged; configuration evidence is not runtime assurance.
"""
from copy import deepcopy

VERSION = "native-rotation-archive-description-overlay-v2"
OFFICIAL_REFERENCES = [
 "https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_schedule.html",
 "https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_managed.html",
 "https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html",
 "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_DescribeTrails.html",
]
ROWS = {'aws_log_archive_immutable': {'base_row_sha256': '5c08fccafa55ffde6e96406865003598e630ff59ab3b1f2a4c10c03d78dcd73b',
                               'fields': {'description': 'Evaluates versioning and S3 Object Lock '
                                                         'default retention configuration on '
                                                         'captured buckets used by visible '
                                                         'CloudTrail trails. Destination matching '
                                                         'requires complete account-wide trail '
                                                         'discovery. This does not prove existing '
                                                         'objects are locked, log delivery '
                                                         'succeeds, or inaccessible cross-account '
                                                         'buckets are protected.',
                                          'evaluated': ['account-global bucket.Name',
                                                        'cloudtrail_account_inventory with '
                                                        'complete enabled-Region and '
                                                        'caller/capture binding',
                                                        'cloudtrail.S3BucketName',
                                                        'bucket.Versioning.Status',
                                                        'bucket.ObjectLock.ObjectLockConfiguration.ObjectLockEnabled',
                                                        'bucket.ObjectLock.ObjectLockConfiguration.Rule.DefaultRetention.Mode, '
                                                        'Days or Years'],
                                          'pass_when': 'PASS when a proven destination bucket has '
                                                       'enabled versioning, enabled Object Lock, '
                                                       'and one valid default retention period in '
                                                       'GOVERNANCE or COMPLIANCE mode.',
                                          'fail_when': 'FAIL when complete readable '
                                                       'destination-bucket configuration proves '
                                                       'versioning or default Object Lock '
                                                       'retention absent; unreadable, partial, '
                                                       'conflicting, or malformed evidence is '
                                                       'UNKNOWN.',
                                          'not_applicable_when': 'Complete account-wide visible '
                                                                 'trail inventory proves that this '
                                                                 'captured bucket is not a '
                                                                 'CloudTrail destination.'}},
 'aws_nist_secretsmanager_secret_automatic_rotation_enabled': {'base_row_sha256': 'cbaa204a47494d1a0cd5dc14fda9a373bc08252b64c6b78c1cf3f77e78242eb4',
                                                               'fields': {'description': 'Evaluates '
                                                                                         'Secrets '
                                                                                         'Manager '
                                                                                         'automatic '
                                                                                         'rotation '
                                                                                         'configuration '
                                                                                         'from '
                                                                                         'identity-bound '
                                                                                         'DescribeSecret '
                                                                                         'metadata. '
                                                                                         'RDS-managed '
                                                                                         'rotation '
                                                                                         'does not '
                                                                                         'require '
                                                                                         'a '
                                                                                         'Lambda. '
                                                                                         'This '
                                                                                         'does not '
                                                                                         'prove a '
                                                                                         'rotation '
                                                                                         'completed, '
                                                                                         'credential '
                                                                                         'rollover '
                                                                                         'succeeded, '
                                                                                         'or '
                                                                                         'Lambda '
                                                                                         'invocation '
                                                                                         'permissions '
                                                                                         'are '
                                                                                         'correct. '
                                                                                         'Unsupported '
                                                                                         'schedule '
                                                                                         'forms '
                                                                                         'remain '
                                                                                         'UNKNOWN.',
                                                                          'evaluated': ['secret.ARN '
                                                                                        'bound to '
                                                                                        'native '
                                                                                        'DescribeSecret',
                                                                                        'secret.RotationEnabled',
                                                                                        'secret.RotationRules.AutomaticallyAfterDays '
                                                                                        'or '
                                                                                        'ScheduleExpression',
                                                                                        'secret.OwningService',
                                                                                        'secret.RotationLambdaARN'],
                                                                          'pass_when': 'PASS when '
                                                                                       'enabled '
                                                                                       'rotation '
                                                                                       'and a '
                                                                                       'valid '
                                                                                       'schedule '
                                                                                       'are '
                                                                                       'readable, '
                                                                                       'with a '
                                                                                       'bound '
                                                                                       'rotation '
                                                                                       'Lambda or '
                                                                                       'native '
                                                                                       'RDS-managed '
                                                                                       'owner that '
                                                                                       'does not '
                                                                                       'require '
                                                                                       'one.',
                                                                          'fail_when': 'FAIL for '
                                                                                       'disabled '
                                                                                       'rotation, '
                                                                                       'proven '
                                                                                       'absent '
                                                                                       'schedule, '
                                                                                       'or a '
                                                                                       'proven '
                                                                                       'required '
                                                                                       'but '
                                                                                       'missing '
                                                                                       'rotation '
                                                                                       'Lambda; '
                                                                                       'incomplete, '
                                                                                       'malformed, '
                                                                                       'contradictory, '
                                                                                       'or denied '
                                                                                       'evidence '
                                                                                       'remains '
                                                                                       'UNKNOWN.',
                                                                          'not_applicable_when': None}}}

def description(check_id, original):
    row = ROWS.get(check_id)
    if row is None:
        return deepcopy(original)
    value = deepcopy(original) if isinstance(original, dict) else {}
    value.update(deepcopy(row["fields"]))
    value["description_correction"] = {"version": VERSION, "base_row_sha256": row["base_row_sha256"],
        "source_relationship": "native configuration and complete destination joins; not runtime success or existing object retention proof",
        "official_references": list(OFFICIAL_REFERENCES)}
    return value

def validate_rows(checks):
    for check_id in ROWS:
        description(check_id, checks.get(check_id))
