"""Versioned native CloudTrail management selector description.

The compiled description pack remains immutable. These checks have no signed
new-check proposal, so this overlay makes no signed-spec claim.
"""
from copy import deepcopy

VERSION = "cloudtrail-management-description-overlay-v2"
SOURCE_RELATIONSHIP = "bounded native selector-configuration evaluation, not proof of event delivery or regional coverage"
OFFICIAL_REFERENCES = [
    "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_AdvancedFieldSelector.html",
    "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-events-with-cloudtrail.html",
]
ROWS = {'aws.cloudtrail.management_events': {'base_row_sha256': '851e408acb96e31b553001a6f335bd0126c67aa19b8f42362818bfb0f4a0055b',
                                      'fields': {'description': 'Evaluates captured basic or '
                                                                'supported advanced management '
                                                                'selectors for one CloudTrail '
                                                                'trail. Proved read/write coverage '
                                                                'is PASS; supported incomplete '
                                                                'coverage is FAIL; unreadable or '
                                                                'unresolved selectors are UNKNOWN. '
                                                                'This is selector configuration '
                                                                'evidence, not logging status, '
                                                                'delivery, regional completeness, '
                                                                'or observed event coverage.',
                                                 'evaluated': ['cloudtrail.TrailARN matched to '
                                                               'native GetEventSelectors TrailARN',
                                                               'cloudtrail.EventSelectors.EventSelectors[].IncludeManagementEvents',
                                                               'cloudtrail.EventSelectors.EventSelectors[].ReadWriteType',
                                                               'cloudtrail.EventSelectors.EventSelectors[].ExcludeManagementEventSources',
                                                               'cloudtrail.EventSelectors.AdvancedEventSelectors'],
                                                 'fail_when': 'FAIL when readable supported '
                                                              'selectors establish that full '
                                                              'management coverage is absent; '
                                                              'unsupported, malformed, or denied '
                                                              'selector evidence is UNKNOWN unless '
                                                              'a separate selector independently '
                                                              'proves full coverage.',
                                                 'not_applicable_when': None,
                                                 'pass_when': 'PASS when a basic selector includes '
                                                              'all management events with no '
                                                              'excluded management sources, or '
                                                              'when the union of advanced '
                                                              'management selectors proves read '
                                                              'and write coverage across all '
                                                              'management source domains, '
                                                              'including complementary supported '
                                                              'source exclusions.'}}}

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
    """Materializer gate for the original CloudTrail description row."""
    for check_id in ROWS:
        description(check_id, checks.get(check_id))


REMEDIATION_VERSION = "cloudtrail-management-remediation-overlay-v1"
REMEDIATION_BASE_SHA256 = "947f2ead115e93140f502bd9bf321f4253bd18941b22ce1ef15a925ec1fc3b4d"


def remediation(original):
    """Correct only the exact previously reviewed template; preserve its source."""
    if not isinstance(original, dict):
        raise ValueError("CloudTrail original remediation row is unavailable")
    value = deepcopy(original)
    value["summary"] = ("Configure basic or supported advanced selectors to include both read and write "
                        "management events without gaps in management event sources.")
    value["steps"] = [
        "Read GetEventSelectors for the exact trail ARN and inspect its basic or advanced selector family.",
        "In the owning declaration, configure complete read/write management coverage; preserve required data-event selectors and review exclusions before applying a change.",
        "Read the selectors again and rerun aws.cloudtrail.management_events. Unsupported or unreadable selector evidence remains UNKNOWN.",
    ]
    value["caveats"] = [
        "Selector configuration does not prove that logging is active, delivery succeeds, or every region is covered.",
        "Supported advanced management selector unions are evaluated automatically; unsupported fields and operators remain UNKNOWN unless an independent selector proves full coverage.",
        "Do not replace existing advanced selectors with basic selectors without reviewing required data events and dependent services.",
    ]
    value["field_binding"]["path"] += ", EventSelectors.AdvancedEventSelectors, TrailARN"
    value["iac"]["code"] = ("Update the existing CloudTrail declaration with complete basic or supported advanced management selectors. "
                            "Preserve required data-event selectors, review exclusions and the plan, then verify the selector configuration after applying the approved change.")
    value["references"] += [{"title": "CloudTrail advanced field selectors", "url": OFFICIAL_REFERENCES[0]}]
    value["source_correction"] = {"version": REMEDIATION_VERSION, "base_row_sha256": REMEDIATION_BASE_SHA256,
                                  "source_relationship": SOURCE_RELATIONSHIP}
    return value
