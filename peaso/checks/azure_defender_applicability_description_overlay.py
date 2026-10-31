"""Current descriptions for two existing Azure Defender controls.

The compiled reviewed descriptions and historical requirement mappings stay intact.
These controls have no signed new-check proposal specification.
"""
from copy import deepcopy

VERSION = "azure-defender-native-applicability-v1"
ROWS = {
    "azure.claude.defender_default_initiative_no_disabled_effects": {
        "base_row_sha256": "101e876171a5abb15c668b5151b95d282523478467c94ea15b49e55aa848caf6",
        "base_catalog_row_sha256": "5a8adb1d13c9f6556f1094b6481b71b98fa04f5ae39e9dcadf9719f5c809d5fd",
        "official_references": [
            "https://learn.microsoft.com/en-us/rest/api/policy-authorization/policy-assignments/list?view=rest-policy-authorization-2026-06-01",
            "https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/resource-name-rules",
        ],
        "source_relationship": "The historical no-assignment MANUAL branch asked for management-group inheritance review. An unfiltered, complete subscription PolicyAssignments_List already includes applicable inherited assignments; a complete list with no effective SecurityCenterBuiltIn assignment proves this assignment-specific parameter check inapplicable. ARM resource names are case-insensitive, so the named assignment is matched without case sensitivity.",
        "fields": {
            "description": "For a subscription, inspect applicable SecurityCenterBuiltIn assignments from the complete unfiltered policy-assignment list, including management-group inheritance and case-insensitive ARM resource names. A Disabled parameter fails; an assigned initiative with no Disabled parameters passes. No applicable named assignment is NOT_APPLICABLE, without asserting whether Defender for Cloud or another initiative is enabled. Incomplete or malformed native evidence remains UNKNOWN or DENIED.",
            "evaluated": ["complete unfiltered subscription policy_assignment inventory", "case-insensitive effective SecurityCenterBuiltIn assignment identity, scope, and native List binding", "policy_assignment.properties.parameters.*.value"],
            "pass_when": "At least one applicable SecurityCenterBuiltIn assignment exists and none of its parameters has value Disabled.",
            "fail_when": "An applicable SecurityCenterBuiltIn assignment has a parameter with value Disabled.",
            "not_applicable_when": "The anchor is not a subscription, or the complete effective assignment inventory contains no applicable SecurityCenterBuiltIn assignment.",
        },
    },
    "azure.claude.defender_iot_security_solution_enabled": {
        "base_row_sha256": "aa1149f7fa721553d8d0957e9a94582c90b1d418b76a7e077bc9c46f2e25b53d",
        "base_catalog_row_sha256": "40931cf02dd031c212c0eb4651cdf13f99a56ef8d4953ad16fea2daca3e662b0",
        "official_references": [
            "https://learn.microsoft.com/en-us/rest/api/defenderforcloud/iot-security-solution/list-by-subscription?view=rest-defenderforcloud-2019-08-01",
            "https://learn.microsoft.com/en-us/rest/api/iothub/iot-hub-resource/list-by-subscription?view=rest-iothub-2023-06-30",
            "https://learn.microsoft.com/en-us/azure/defender-for-iot/device-builders/quickstart-onboard-iot-hub",
        ],
        "source_relationship": "The historical empty-solution MANUAL branch lacked a native IoT Hub applicability join. Complete empty solution and hub inventories prove no in-subscription subject; existing hubs with no selected-subscription solution still lack native cross-subscription solution binding evidence.",
        "fields": {
            "description": "For a subscription, inspect the complete IoT security solution and IoT Hub inventories. An observed Disabled solution fails, and all observed Enabled solutions pass when both inventories are complete. If both inventories are empty, this solution-specific check is NOT_APPLICABLE. If hubs exist but the local solution list is empty, cross-subscription solution binding is unavailable and the result is UNKNOWN; incomplete positive evidence cannot pass.",
            "evaluated": ["complete subscription iot_security_solution inventory", "complete subscription iot_hub inventory", "iot_security_solution.properties.status", "native cross-subscription solution-to-hub binding (currently unavailable for the empty-local-solution, present-hub case)"],
            "pass_when": "At least one IoT security solution exists, every observed solution is Enabled, and both scoped inventories are complete.",
            "fail_when": "Any observed IoT security solution is Disabled, even if the hub inventory is incomplete.",
            "not_applicable_when": "The anchor is not a subscription, or complete native inventories contain no IoT security solution and no IoT Hub.",
        },
    },
}


def description(check_id, original):
    row = ROWS.get(check_id)
    if row is None:
        return deepcopy(original)
    corrected = deepcopy(original) if isinstance(original, dict) else {}
    corrected.update(deepcopy(row["fields"]))
    corrected["description_correction"] = {
        "version": VERSION,
        "base_row_sha256": row["base_row_sha256"],
        "base_catalog_row_sha256": row["base_catalog_row_sha256"],
        "source_relationship": row["source_relationship"],
        "official_references": list(row["official_references"]),
        "signed_spec_status": "no_signed_new_check_proposal; frozen compiled descriptions unchanged",
    }
    return corrected


def validate_rows(checks):
    for check_id in ROWS:
        description(check_id, checks.get(check_id))
