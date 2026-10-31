"""AWS Config all-supported recording, evaluated per collected account/Region scope.

Signed proposal aws_config_all_resources_recorded, admitted under the revised
signed spec PROPOSED_SPEC_SHA256. It supersedes the original proposal
SUPERSEDED_SPEC_SHA256. Evaluates one account/region scope from the existing config_recorder
collection (config:DescribeConfigurationRecorders without arguments, i.e. the
customer managed recorder, plus per-name config:DescribeConfigurationRecorderStatus).

Verdict per selected region, never account-wide:
- FAIL: complete empty customer-managed inventory, a stopped or Failure recorder,
  or an explicitly restricted recording group (INCLUSION_BY_RESOURCE_TYPES,
  EXCLUSION_BY_RESOURCE_TYPES with listed types, legacy allSupported=false).
- PASS: the one customer-managed recorder is recording, lastStatus=Success and
  records all supported types (allSupported=true, strategy absent or
  ALL_SUPPORTED_RESOURCE_TYPES, no listed/excluded types).
- UNKNOWN: denied/partial inventory, missing/ambiguous status, Pending or
  NotApplicable lastStatus, unrecognized enums, contradictory group fields,
  duplicate customer-managed recorders.
Service-linked recorders (servicePrincipal) record a linked service's scope only:
they never qualify and never fail the region by themselves.
"""
from __future__ import annotations

from . import register, result, unknown
from .facts import Unavailable, get, list_of_objects, optional
from .aws_a_facts import complete_items, scope_subject

CHECK_ID = "aws_config_all_resources_recorded"
PROPOSED_SPEC_SHA256 = "1e764e3f7419f6fba0cee7eb95a629796b7f57ac354fdd251f6760075600300e"
SUPERSEDED_SPEC_SHA256 = "8f9c88b17914eac7d06deb0244eac58e022ec1c72e5d4c6e9b2013902935b353"
TITLE = "AWS Config records all supported resources"
REMEDIATION = "Enable an AWS Config recorder in each Region, set allSupported=true with no excluded types, and start recording."
RECORDER_STATES = {"Pending", "Success", "Failure", "NotApplicable"}
STRATEGIES = {"ALL_SUPPORTED_RESOURCE_TYPES", "INCLUSION_BY_RESOURCE_TYPES", "EXCLUSION_BY_RESOURCE_TYPES"}
SERVICE_LINKED_PREFIX = "AWSConfigurationRecorderFor"


def _type_list(parent, label):
    """Documented omission is an empty list; explicit non-collected coverage stays unresolved."""
    values = optional(parent, "resourceTypes", [], list)
    if any(not isinstance(value, str) or not value for value in values):
        raise Unavailable("malformed Config resource type list: " + label)
    return values


def _recording_scope(group):
    all_supported = get(group, "allSupported", bool)
    included = _type_list(group, "resourceTypes")
    excluded = _type_list(optional(group, "exclusionByResourceTypes", {}, dict), "exclusionByResourceTypes")
    strategy_group = optional(group, "recordingStrategy", None, dict)
    strategy = None if strategy_group is None else get(strategy_group, "useOnly", str)
    if strategy is not None and strategy not in STRATEGIES:
        raise Unavailable("unrecognized Config recording strategy")
    if strategy == "INCLUSION_BY_RESOURCE_TYPES":
        # The API requires listed types for inclusion; an empty/omitted list is unresolved, not a proved restriction.
        if not included:
            raise Unavailable("inclusion strategy without explicit included types")
        return "restricted", strategy, included, excluded
    if strategy == "EXCLUSION_BY_RESOURCE_TYPES":
        # The exclusion strategy overrides allSupported; listed types are an explicit gap.
        if not excluded:
            raise Unavailable("exclusion strategy without explicit excluded types")
        return "restricted", strategy, included, excluded
    if strategy == "ALL_SUPPORTED_RESOURCE_TYPES" and (not all_supported or included or excluded):
        raise Unavailable("contradictory all-supported recording group")
    if strategy is None:
        # Pre-strategy API shape: allSupported is the only authority.
        if all_supported and (included or excluded):
            raise Unavailable("contradictory legacy recording group")
        if not all_supported:
            if not included:
                raise Unavailable("legacy selected-types group without listed types")
            return "restricted", "legacy_selected_types", included, excluded
    return "all_supported", strategy or "legacy_all_supported", included, excluded


def _observed(row, group):
    """Reported facts outside the signed predicate; unreadable values never change the verdict."""
    facts = {}
    for label, parent, path in (("include_global_resource_types", group, "includeGlobalResourceTypes"),
            ("recording_frequency", row, "recordingMode.recordingFrequency")):
        if path.split(".", 1)[0] not in parent and path.split(".", 1)[0] not in parent.get("_coverage", {}):
            facts[label] = "absent"
            continue
        try:
            value = get(parent, path)
        except Unavailable:
            value = "unavailable"
        facts[label] = value if isinstance(value, (str, bool)) else "malformed"
    return facts


def _run_state(row, name):
    statuses = list_of_objects(get(row, "Status.ConfigurationRecordersStatus", list))
    matching = [status for status in statuses if get(status, "name", str) == name]
    if len(matching) != 1:
        raise Unavailable("recorder status missing or ambiguous")
    status = matching[0]
    recording = get(status, "recording", bool)
    if not recording:
        # A stopped recorder is explicit; a never-started recorder may omit lastStatus.
        return "stopped", status.get("lastStatus") if isinstance(status.get("lastStatus"), str) else None
    last = get(status, "lastStatus", str)
    if last not in RECORDER_STATES:
        raise Unavailable("unrecognized native Config recorder state")
    return {"Success": "running", "Failure": "failed"}.get(last, "unconfirmed"), last


def _region_authority(index, scope):
    """Report, never assume, whether this region came from authoritative ec2:DescribeRegions discovery."""
    account, region = scope.split("/", 1)
    context = index.get("context") if isinstance(index, dict) else None
    metadata = context.get("metadata") if isinstance(context, dict) else None
    rows = metadata.get("region_discovery") if isinstance(metadata, dict) else None
    if not isinstance(rows, list):
        return "not_proven"
    for row in rows:
        if isinstance(row, dict) and row.get("account_id") == account:
            if row.get("status") == "collected" and isinstance(row.get("regions"), list):
                return "discovered_enabled_region" if region in row["regions"] else "outside_discovered_enabled_regions"
            return "discovery_incomplete"
    return "not_proven"


@register(CHECK_ID, "aws", "hardening", "config_recorder", TITLE, "medium", "CM-8", REMEDIATION,
    target="scope", dependencies=["config_recorder"])
def config_all_supported(item, index):
    scope = scope_subject(item)
    rows = complete_items(index, "config_recorder", scope)
    common = {"scope": scope, "account_wide_claim": False, "region_inventory": _region_authority(index, scope)}
    customer, linked = [], []
    for row in rows:
        name = get(row, "name", str)
        if not name:
            raise Unavailable("Config recorder name missing")
        principal = optional(row, "servicePrincipal", None, str)
        if principal is not None:
            if not principal:
                raise Unavailable("empty servicePrincipal cannot establish recorder ownership")
            linked.append({"name": name, "service_principal": principal})
        elif name.startswith(SERVICE_LINKED_PREFIX):
            return unknown("recorder ownership ambiguous: service-linked name without servicePrincipal", recorder=name, **common)
        else:
            customer.append((name, row))
    if not customer:
        return result(True, recorder="absent", service_linked_recorders=linked,
            semantics="Complete regional inventory has no customer-managed recorder; service-linked recorders do not record all supported types", **common)
    if len(customer) != 1:
        return unknown("multiple customer-managed recorders in one region", recorders=[name for name, _ in customer], **common)
    name, row = customer[0]
    run, last = _run_state(row, name)
    base = {"recorder": name, "run_state": run, "last_status": last, "service_linked_recorders": linked, **common}
    if run in {"stopped", "failed"}:
        return result(True, **base)
    group = get(row, "recordingGroup", dict)
    coverage, strategy, included, excluded = _recording_scope(group)
    evidence = {**base, "recording_scope": coverage, "strategy": strategy,
        "included_types": len(included), "excluded_types": sorted(excluded), "observed": _observed(row, group)}
    if coverage == "restricted":
        return result(True, **evidence)
    if run != "running":
        return unknown("recorder running state unconfirmed (lastStatus " + str(last) + ")", **evidence)
    return result(False, **evidence)
