"""Pure account-wide AWS Config proof from existing read-only collector facts."""
from __future__ import annotations

import re

# Conservative known partition/Region shapes. Unknown regions remain unavailable
# to the evaluator, which must run without optional cloud SDK packages.
_COMMERCIAL = re.compile(
    r"(?:us-(?:east|west)|eu-(?:central|north|south|west)|"
    r"ap-(?:east|northeast|south|southeast)|ca-(?:central|west)|"
    r"sa-east|me-(?:central|south)|af-south|il-central|mx-central)-[0-9]+"
)
_CHINA = re.compile(r"cn-(?:north|northwest)-[0-9]+")
_GOV = re.compile(r"us-gov-(?:east|west)-[0-9]+")


def region_partition(name):
    """Recognize only known partition Region shapes without SDK or network."""
    if not isinstance(name, str):
        return None
    if _COMMERCIAL.fullmatch(name):
        return "aws"
    if _CHINA.fullmatch(name):
        return "aws-cn"
    if _GOV.fullmatch(name):
        return "aws-us-gov"
    return None

KIND = "config_account_region_coverage"
_REGION = re.compile(r"[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+")
_CALLER = re.compile(r"arn:([^:]+):(iam|sts)::([0-9]{12}):.+")
_STATES = {"opted-in", "not-opted-in", "opt-in-not-required"}
_GOOD = {"collected", "empty"}


def derive(account, identity, discoveries, collections, captured_at):
    """Return (items, status, error); never infer coverage from a partial read."""
    def bad(status, code):
        return [], status, {"code": code}

    if not isinstance(account, str) or re.fullmatch(r"[0-9]{12}", account) is None:
        return bad("malformed", "config_account_identity_invalid")
    caller = _CALLER.fullmatch(identity.get("Arn", "")) if isinstance(identity, dict) else None
    if (not caller or identity.get("Account") != account or caller.group(3) != account):
        return bad("malformed", "config_caller_identity_mismatch")
    matching = [row for row in discoveries if isinstance(row, dict) and row.get("account_id") == account]
    if len(matching) != 1:
        return bad("not_collected" if not matching else "malformed", "config_region_discovery_missing_or_duplicate")
    proof = matching[0]
    if proof.get("status") != "collected":
        state = proof.get("status")
        return bad(state if state in {"denied", "partial", "malformed", "timeout", "not_collected"} else "not_collected",
                   "config_region_discovery_incomplete")
    if (proof.get("scope") != account + "/global" or proof.get("caller_account_id") != account
            or proof.get("partition") != caller.group(1) or proof.get("source_operation") != "ec2:DescribeRegions"
            or proof.get("all_regions") is not True or proof.get("read_only") is not True
            or proof.get("observed_at") != captured_at):
        return bad("malformed", "config_region_discovery_provenance_mismatch")
    raw = proof.get("raw_regions")
    if not isinstance(raw, list) or not raw:
        return bad("malformed", "config_region_discovery_empty_or_malformed")
    seen, enabled = set(), []
    for row in raw:
        if not isinstance(row, dict):
            return bad("malformed", "config_region_row_malformed")
        name, state = row.get("RegionName"), row.get("OptInStatus")
        if (not isinstance(name, str) or not _REGION.fullmatch(name) or region_partition(name) != caller.group(1)
                or name in seen or state not in _STATES):
            return bad("malformed", "config_region_row_duplicate_or_conflicting")
        seen.add(name)
        if state != "not-opted-in":
            enabled.append(name)
    # Regions an Organizations SCP denies were excluded from the scan; they
    # cannot hold Config recorders, so they leave the required set too.
    denied = proof.get("scp_denied_regions", [])
    if not isinstance(denied, list) or any(region not in enabled for region in denied):
        return bad("malformed", "config_region_scp_exclusion_malformed")
    enabled = [region for region in enabled if region not in denied]
    if not enabled or sorted(enabled) != proof.get("regions"):
        return bad("malformed", "config_enabled_region_projection_mismatch")
    joined = []
    for region in sorted(enabled):
        entries = {"RegionName": region}
        for kind, field in (("config_recorder", "Recorders"),
                            ("config_delivery_channel", "DeliveryChannels")):
            matches = [row for row in collections if isinstance(row, dict)
                       and row.get("type") == kind and row.get("scope") == account + "/" + region]
            if len(matches) != 1:
                return bad("not_collected" if not matches else "malformed", "config_regional_inventory_missing_or_duplicate")
            envelope = matches[0]
            state, items = envelope.get("status"), envelope.get("items")
            if (envelope.get("account_id") != account or envelope.get("global") is not False
                    or not isinstance(items, list) or (state == "empty" and items)
                    or (state == "collected" and not items)):
                return bad("malformed", "config_regional_inventory_identity_or_shape_mismatch")
            if state not in _GOOD:
                return bad(state if state in {"denied", "partial", "malformed", "timeout", "not_collected"} else "malformed",
                           "config_regional_inventory_incomplete")
            if any(not isinstance(item, dict) or item.get("AccountId") != account
                   or item.get("Region") != region for item in items):
                return bad("malformed", "config_regional_item_foreign_or_unbound")
            entries[field] = items
        joined.append(entries)
    return [{"id": account, "AccountId": account,
             "Discovery": {"scope": proof["scope"], "caller_account_id": account,
                           "caller_arn": identity["Arn"], "partition": caller.group(1),
                           "source_operation": proof["source_operation"], "all_regions": True,
                           "read_only": True, "observed_at": captured_at,
                           "raw_regions": raw, "regions": sorted(enabled),
                           **({"scp_denied_regions": sorted(denied)} if denied else {})},
             "Regions": joined,
             "_provenance": {"read_only": True, "account_global_complete": True,
                             "source_operation": "ec2:DescribeRegions+config:DescribeConfigurationRecorders+config:DescribeDeliveryChannels+config:DescribeConfigurationRecorderStatus",
                             "observed_at": captured_at}}], "collected", None
