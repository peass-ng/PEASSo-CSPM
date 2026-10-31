"""Versioned launch-configuration public-IP description corrections.

The compiled description pack remains immutable. These checks have no signed
new-check proposal, so this overlay makes no signed-spec claim.
"""
from copy import deepcopy

VERSION = "aws-launch-ip-description-overlay-v2"
SOURCE_RELATIONSHIP = "corrected native omission semantics; subnet inheritance is unresolved rather than disabled; configuration proof only"
OFFICIAL_REFERENCES = [
    "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_LaunchConfiguration.html",
    "https://docs.aws.amazon.com/autoscaling/ec2/userguide/create-launch-config.html",
]
ROWS = {'aws.c2b.autoscaling.group_lc_no_public_ip': {'base_row_sha256': '5a9c3cbce9758cbd5f18cd9100d3e2ecc095f61633468ca7d4325adf121eb17b',
                                               'fields': {'description': 'For Auto Scaling groups '
                                                                         'using a uniquely joined '
                                                                         'launch configuration, '
                                                                         'checks the explicit '
                                                                         'AssociatePublicIpAddress '
                                                                         'setting: true is FAIL '
                                                                         'and false is PASS. '
                                                                         'Omission inherits subnet '
                                                                         'public-IP assignment and '
                                                                         'remains UNKNOWN without '
                                                                         'effective subnet '
                                                                         'evidence. This assesses '
                                                                         'launch configuration, '
                                                                         'not existing instance '
                                                                         'addresses or Internet '
                                                                         'reachability.',
                                                          'fail_when': 'FAIL when '
                                                                       'AssociatePublicIpAddress '
                                                                       'is explicitly true.',
                                                          'pass_when': 'PASS only when the joined '
                                                                       "launch configuration's "
                                                                       'AssociatePublicIpAddress '
                                                                       'is explicitly false.'}},
 'aws.c2b.autoscaling.lc_no_public_ip': {'base_row_sha256': '5798d2b89203dd7f6ec34aefbbcae9ff87aad1fb03126c36af4f1619d48010c3',
                                         'fields': {'description': 'For each collected launch '
                                                                   'configuration, checks the '
                                                                   'explicit '
                                                                   'AssociatePublicIpAddress '
                                                                   'setting: true is FAIL and '
                                                                   'false is PASS. Omission '
                                                                   'inherits subnet public-IP '
                                                                   'assignment and remains UNKNOWN '
                                                                   'without effective subnet '
                                                                   'evidence. This assesses launch '
                                                                   'configuration, not existing '
                                                                   'instance addresses or Internet '
                                                                   'reachability.',
                                                    'fail_when': 'FAIL when '
                                                                 'AssociatePublicIpAddress is '
                                                                 'explicitly true.',
                                                    'pass_when': 'PASS only when the launch '
                                                                 "configuration's "
                                                                 'AssociatePublicIpAddress is '
                                                                 'explicitly false.'}}}

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
    """Materializer gate for both launch-configuration description rows."""
    for check_id in ROWS:
        description(check_id, checks.get(check_id))
