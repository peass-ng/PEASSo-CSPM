"""Versioned ECS description corrections for classic native checks.

The compiled description pack remains immutable. These checks have no signed
new-check proposal, so this overlay makes no signed-spec claim.
"""
from copy import deepcopy

VERSION = "ecs-uid-description-overlay-v2"
SOURCE_RELATIONSHIP = "corrected, stronger Linux declaration predicate; partial mapping to pinned SQL; no effective process UID proof"
OFFICIAL_REFERENCES = [
    "https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ContainerDefinition.html",
    "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters_ec2.html",
]
ROWS = {'aws.b.ecs.declared_nonroot_users': {'base_row_sha256': 'a0d77731dfd8c8121a47565cfe4aff302a2b21118753972cdd215d8c981cced9',
                                      'fields': {'description': 'For Linux ECS task definitions, '
                                                                'FAIL if any container declares '
                                                                'literal root or numeric UID 0. '
                                                                'PASS only when every container '
                                                                'declares a valid nonzero numeric '
                                                                "UID in Docker's supported range. "
                                                                'Named, omitted, malformed, and '
                                                                'out-of-range users are UNKNOWN '
                                                                'without UID proof. Windows or '
                                                                'unknown OS family is UNKNOWN '
                                                                'because the ECS user parameter is '
                                                                'unsupported on Windows; an '
                                                                'omitted RuntimePlatform defaults '
                                                                'to LINUX only on a successful '
                                                                'ARN-bound DescribeTaskDefinition '
                                                                'result. This checks declared '
                                                                'startup UID, not effective '
                                                                'runtime process identity or group '
                                                                'privileges.',
                                                 'evaluated': ['Definition.taskDefinition.runtimePlatform.operatingSystemFamily',
                                                               'Definition.taskDefinition.containerDefinitions[].user',
                                                               'Definition.collection_status and '
                                                               'matching taskDefinitionArn for '
                                                               'documented LINUX default'],
                                                 'fail_when': 'FAIL for a proved Linux task when '
                                                              'any container declares literal root '
                                                              'or numeric UID 0.',
                                                 'not_applicable_when': None,
                                                 'pass_when': 'PASS for an explicit LINUX task, or '
                                                              'an ARN-bound successful '
                                                              'DescribeTaskDefinition with '
                                                              'documented LINUX default, when '
                                                              'every container declares a valid '
                                                              'nonzero numeric UID (1 through '
                                                              '2147483647). A group suffix does '
                                                              'not establish the user UID.'}},
 'aws.b.ecs.host_network_nonprivileged': {'base_row_sha256': 'f0ba8b192f4c7ef7f15a00f936989b7964ed80375fec199ef3447d2caeafa209',
                                          'fields': {'description': 'For host-network Linux ECS '
                                                                    'task definitions, FAIL if any '
                                                                    'container is privileged or '
                                                                    'declares literal root/numeric '
                                                                    'UID 0. PASS only when every '
                                                                    'container is explicitly '
                                                                    'nonprivileged and declares a '
                                                                    'valid nonzero numeric UID. '
                                                                    'Named, omitted, malformed, or '
                                                                    'out-of-range users remain '
                                                                    'UNKNOWN absent a proved '
                                                                    'failure. Windows or unknown '
                                                                    'OS family is UNKNOWN for host '
                                                                    'mode; an omitted '
                                                                    'RuntimePlatform defaults to '
                                                                    'LINUX only on a successful '
                                                                    'ARN-bound '
                                                                    'DescribeTaskDefinition '
                                                                    'result. This is declaration '
                                                                    'evidence, not runtime process '
                                                                    'identity.',
                                                     'evaluated': ['Definition.taskDefinition.runtimePlatform.operatingSystemFamily',
                                                                   'Definition.taskDefinition.networkMode',
                                                                   '...containerDefinitions[].privileged',
                                                                   '...containerDefinitions[].user',
                                                                   'Definition.collection_status '
                                                                   'and matching taskDefinitionArn '
                                                                   'for documented LINUX default'],
                                                     'fail_when': 'FAIL for a proved Linux '
                                                                  'host-mode task when a container '
                                                                  'is privileged or declares '
                                                                  'root/numeric UID 0.',
                                                     'not_applicable_when': 'networkMode is none, '
                                                                            'bridge or awsvpc.',
                                                     'pass_when': 'PASS for an explicit or '
                                                                  'ARN-bound default Linux '
                                                                  'host-mode task when no '
                                                                  'container is privileged and '
                                                                  'every container declares a '
                                                                  'valid nonzero numeric UID.'}}}


def description(check_id, original):
    """Apply the reviewed correction over the compiled row."""
    correction = ROWS.get(check_id)
    if correction is None:
        return deepcopy(original)
    value = deepcopy(original) if isinstance(original, dict) else {}
    value.update(deepcopy(correction["fields"]))
    value["description_correction"] = {"version": VERSION,
        "base_row_sha256": correction["base_row_sha256"],
        "source_relationship": SOURCE_RELATIONSHIP,
        "official_references": list(OFFICIAL_REFERENCES)}
    return value


def validate_rows(checks):
    """Materializer gate for both ECS description rows."""
    for check_id in ROWS:
        description(check_id, checks.get(check_id))
