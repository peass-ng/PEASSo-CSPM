"""claude2_gcp partition: shard integrity, fixture outcomes and log-metric false-positive semantics."""
from peaso.checks.hacktricks_scope import includes
import copy
import json
from pathlib import Path

import pytest

from peaso.checks import CHECKS, HACKTRICKS
from peaso.checks.claude2_gcp_common import CHECK_IDS, PREFIX, scope_index
from peaso.checks.claude2_gcp_logfilter import verdict, parse, FilterError
from peaso.checks.claude2_gcp_logging import EVENTS, CIS_FILTERS, METRIC_IDS, CHANNEL_KIND
from peaso.checks.fixtures import CASES
import peaso.checks.claude2_gcp  # noqa: F401  (registration side effect)

PACK = Path(__file__).resolve().parent.parent / "peaso" / "rulepacks"
REVIEWED = json.loads((PACK / "reviewed_claude2_gcp.json").read_text())
REGISTRY = {check.id: check for check in CHECKS}


def run(check_id, item, index=None):
    data, scoped = copy.deepcopy(item), copy.deepcopy(index or {})
    status = REGISTRY[check_id].evaluate(data, scoped)[0]
    assert data == item and scoped == (index or {}), "evaluators must not mutate facts"
    return status


# --- Shard integrity -----------------------------------------------------------------------------------------

def test_rows_reference_registered_predicates():
    for key, entry in REVIEWED.items():
        assert entry["disposition"] in ("ported", "merged"), key
        assert entry["reason"] and entry["official_docs"] and entry["source_review"], key
        assert entry["native_checks"] and all(c in REGISTRY for c in entry["native_checks"]), key
        if entry["disposition"] == "ported":
            assert all(c.startswith(PREFIX) for c in entry["native_checks"]), key


def test_every_predicate_is_claimed():
    claimed = {c for entry in REVIEWED.values() for c in entry["native_checks"]}
    assert set(CHECK_IDS) <= claimed and len(CHECK_IDS) == len(set(CHECK_IDS)) == 17


@pytest.mark.parametrize("check_id", CHECK_IDS)
def test_predicate_contract_and_fixtures(check_id):
    check = REGISTRY[check_id]
    assert check.provider == "gcp" and (HACKTRICKS in check.frameworks) == includes(check.id) and check.remediation and check.dependencies
    cases = CASES[check_id]
    assert "pass" in cases and "fail" in cases and ("unknown" in cases or "malformed" in cases)
    for name, expected in (("pass", "PASS"), ("fail", "FAIL"), ("manual", "MANUAL"), ("unknown", "UNKNOWN"),
                           ("not_applicable", "NOT_APPLICABLE")):
        if name in cases:
            assert run(check_id, cases[name], cases.get(name + "_index", cases.get("pass_index"))) == expected, name
    for name in ("missing", "malformed"):
        assert run(check_id, cases[name], cases.get("pass_index")) == "UNKNOWN", name
    for value in ({}, None, [], {"collection_status": "denied"}, {"_provenance": {"x": 1}}):
        assert check.evaluate(value, {})[0] == "UNKNOWN"


# --- Logging query language semantics -------------------------------------------------------------------------

FW = EVENTS["firewall_rule_changes"]("p")
ROUTE = EVENTS["route_changes"]("p")


@pytest.mark.parametrize("name", sorted(CIS_FILTERS))
def test_cis_reference_filters_fully_match(name):
    assert verdict(CIS_FILTERS[name], EVENTS[name]("p"))[0] == "full"


@pytest.mark.parametrize("text,expected", [
    # OR binds tighter than AND, so the unparenthesized form still means type AND (delete OR insert).
    ('resource.type="gce_route" AND protoPayload.methodName:"compute.routes.delete" OR protoPayload.methodName:"compute.routes.insert"', "full"),
    # Reordered, implicit AND, value group, snake_case and extra whitespace.
    ('proto_payload.method_name : ( "compute.routes.insert" OR "compute.routes.delete" )   resource.type = gce_route', "full"),
    ('protoPayload.serviceName="compute.googleapis.com"', "full"),  # broader filter still captures every change
    ('resource.type="gce_route" AND protoPayload.methodName:"compute.routes.delete"', "partial"),
    ('resource.type="gce_route" -protoPayload.methodName:"insert"', "partial"),
    ('resource.type="gce_instance"', "none"),
    ('jsonPayload.event="route"', "none"),
    ('severity>=ERROR AND resource.type="gce_route"', "none"),
    ('resource.type="GCE_ROUTE"', "partial"),  # case-sensitivity of '=' is not assumed
    ('resource.type="gce_route" AND (', "partial"),  # unparsable -> uncertain, never a non-match
    ('log_id("cloudaudit.googleapis.com/activity") resource.type=gce_route', "full"),
    ('resource.type=~"^gce_(route|network)$"', "full"),
])
def test_route_filter_semantics(text, expected):
    assert verdict(text, ROUTE)[0] == expected


def test_cis_v120_network_filter_without_v1_methods_is_partial():
    legacy = ('resource.type=gce_network AND protoPayload.methodName="beta.compute.networks.insert" OR '
              'protoPayload.methodName="beta.compute.networks.patch" OR protoPayload.methodName="v1.compute.networks.delete" OR '
              'protoPayload.methodName="v1.compute.networks.removePeering" OR protoPayload.methodName="v1.compute.networks.addPeering"')
    assert verdict(legacy, EVENTS["network_changes"]("p"))[0] == "partial"


def test_ownership_bare_terms_and_repeated_deltas():
    events = EVENTS["project_ownership_changes"]("p")
    only_deltas = ('protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD" AND '
                   'protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner"')
    assert verdict(only_deltas, events)[0] == "partial"
    assert verdict('protoPayload.serviceName="cloudresourcemanager.googleapis.com" AND ProjectOwnership', events)[0] == "partial"


def test_parser_rejects_malformed():
    for text in ("", '"unterminated', "a = ", "(a OR b"):
        with pytest.raises(FilterError):
            parse(text)
    assert verdict('"quoted"=x', FW)[0] == "partial"


# --- Metric/alert predicate gating ----------------------------------------------------------------------------

ROUTE_ID = METRIC_IDS["route_changes"]
LOCAL = {"name": "projects/123", "projectId": "p", "_ancestry": [{"resourceId": {"type": "project", "id": "p"}}]}
ORG = {**LOCAL, "_ancestry": LOCAL["_ancestry"] + [{"resourceId": {"type": "organization", "id": "9"}}]}
METRIC = {"name": "projects/p/metrics/m", "filter": CIS_FILTERS["route_changes"], "metricDescriptor": {"type": "logging.googleapis.com/user/m", "metricKind": "DELTA", "valueType": "INT64"}}
THRESHOLD = {"conditionThreshold": {"filter": 'metric.type="logging.googleapis.com/user/m" resource.type="gce_route"',
    "comparison": "COMPARISON_GT", "thresholdValue": 0, "duration": "0s"}}
ALERT = {"name": "projects/p/alertPolicies/a", "enabled": True, "notificationChannels": ["projects/p/notificationChannels/1"],
         "conditions": [THRESHOLD]}
CHANNEL = {"name": "projects/p/notificationChannels/1", "type": "email", "enabled": True}
SINK = {"name": "projects/p/sinks/_Required", "destination": "logging.googleapis.com/projects/p/locations/global/buckets/_Required"}


def index(metrics=(METRIC,), alerts=(ALERT,), channels=(CHANNEL,), sinks=(SINK,), **drop):
    kinds = {"logging_metric": list(metrics), "monitoring_alert_policy": list(alerts), CHANNEL_KIND: list(channels), "log_sink": list(sinks)}
    return scope_index({k: v for k, v in kinds.items() if k not in drop})


def test_pass_requires_enabled_alert_and_enabled_channel():
    assert run(ROUTE_ID, LOCAL, index()) == "PASS"
    local_scope = {**LOCAL, "_monitoring_metrics_scopes": ["locations/global/metricsScopes/p"]}
    assert run(ROUTE_ID, LOCAL, index(alerts=[{**ALERT, "enabled": False}])) == "MANUAL"  # alert may live in a scoping project
    assert run(ROUTE_ID, local_scope, index(alerts=[{**ALERT, "enabled": False}])) == "FAIL"
    assert run(ROUTE_ID, local_scope, index(alerts=[{**ALERT, "notificationChannels": []}])) == "FAIL"
    assert run(ROUTE_ID, local_scope, index(channels=[{**CHANNEL, "enabled": False}])) == "FAIL"
    assert run(ROUTE_ID, LOCAL, index(**{CHANNEL_KIND: True})) == "UNKNOWN"
    assert run(ROUTE_ID, {**LOCAL, "_monitoring_metrics_scopes": ["locations/global/metricsScopes/host"]},
               index(alerts=[{**ALERT, "enabled": False}])) == "MANUAL"


def test_equivalent_filter_without_parentheses_passes():
    reworded = {**METRIC, "filter": 'resource.type = "gce_route" AND protoPayload.methodName:"compute.routes.insert" OR '
                                    'protoPayload.methodName:"compute.routes.delete"'}
    assert run(ROUTE_ID, LOCAL, index(metrics=[reworded])) == "PASS"


def test_incomplete_or_disabled_metric_never_passes():
    partial = {**METRIC, "filter": 'resource.type="gce_route" AND protoPayload.methodName:"compute.routes.delete"'}
    assert run(ROUTE_ID, LOCAL, index(metrics=[partial])) == "MANUAL"
    assert run(ROUTE_ID, LOCAL, index(metrics=[{**METRIC, "disabled": True}])) == "FAIL"
    assert run(ROUTE_ID, LOCAL, index(metrics=[{**METRIC, "bucketName": "projects/p/locations/global/buckets/b"}])) == "MANUAL"


def test_uncertain_alert_links_are_manual():
    mql = {**ALERT, "conditions": [{"conditionMonitoringQueryLanguage": {"query": "fetch global::logging.googleapis.com/user/m"}}]}
    assert run(ROUTE_ID, LOCAL, index(alerts=[mql])) == "MANUAL"
    combined = {**ALERT, "combiner": "AND", "conditions": [THRESHOLD, {"conditionThreshold": {"filter": 'metric.type="x"'}}]}
    assert run(ROUTE_ID, LOCAL, index(alerts=[combined])) == "MANUAL"
    absent = {**ALERT, "conditions": [{"conditionAbsent": THRESHOLD["conditionThreshold"]}]}
    assert run(ROUTE_ID, LOCAL, index(alerts=[absent])) == "MANUAL"  # metric exists, no threshold alert, scope unproven
    log_match = {**ALERT, "conditions": [{"conditionMatchedLog": {"filter": CIS_FILTERS["route_changes"]}}]}
    assert run(ROUTE_ID, LOCAL, index(metrics=[], alerts=[log_match])) == "MANUAL"
    prefix = {**ALERT, "conditions": [{"conditionThreshold": {"filter": 'metric.type="logging.googleapis.com/user/m2"'}}]}
    assert run(ROUTE_ID, LOCAL, index(metrics=[METRIC], alerts=[prefix])) == "MANUAL"


def test_inherited_configuration_is_manual_or_unknown_never_fail():
    empty = index(metrics=[], alerts=[])
    assert run(ROUTE_ID, LOCAL, empty) == "FAIL"
    assert run(ROUTE_ID, ORG, empty) == "MANUAL"
    assert run(ROUTE_ID, {**ORG, "_inherited_sinks": []}, empty) == "FAIL"
    aggregated = {"name": "organizations/9/sinks/central", "includeChildren": True,
                  "destination": "logging.googleapis.com/projects/central/locations/global/buckets/b"}
    assert run(ROUTE_ID, {**ORG, "_inherited_sinks": [aggregated]}, empty) == "MANUAL"
    assert run(ROUTE_ID, {"name": "projects/123", "projectId": "p"}, empty) == "UNKNOWN"
    assert run(ROUTE_ID, {"name": "projects/123", "projectId": "p", "parent": "folders/5"}, empty) == "MANUAL"
    routed = {"name": "projects/p/sinks/out", "destination": "logging.googleapis.com/projects/other/locations/global/buckets/b"}
    assert run(ROUTE_ID, LOCAL, index(metrics=[], alerts=[], sinks=[SINK, routed])) == "MANUAL"
    assert run(ROUTE_ID, LOCAL, index(metrics=[], alerts=[], log_sink=True)) == "UNKNOWN"
    assert run(ROUTE_ID, LOCAL, index(logging_metric=True)) == "UNKNOWN"
    assert run(ROUTE_ID, LOCAL, index(monitoring_alert_policy=True)) == "UNKNOWN"


def test_metrics_in_other_projects_are_ignored():
    foreign = {**METRIC, "name": "projects/other/metrics/m"}
    assert run(ROUTE_ID, LOCAL, index(metrics=[foreign])) == "FAIL"
    numbered = {**METRIC, "name": "projects/123/metrics/m"}
    assert run(ROUTE_ID, LOCAL, index(metrics=[numbered])) == "PASS"


def test_custom_role_variants_differ_on_undelete():
    three = {**METRIC, "filter": CIS_FILTERS["custom_role_changes"]}
    role_alert = {**ALERT, "conditions": [{"conditionThreshold": {**THRESHOLD["conditionThreshold"],
        "filter": THRESHOLD["conditionThreshold"]["filter"].replace("gce_route", "iam_role")}}]}
    assert run(METRIC_IDS["custom_role_changes"], LOCAL, index(metrics=[three], alerts=[role_alert])) == "PASS"
    assert run(METRIC_IDS["custom_role_changes_with_undelete"], LOCAL, index(metrics=[three], alerts=[role_alert])) == "MANUAL"


# --- 2.2 sinks ------------------------------------------------------------------------------------------------

SINK_ID = PREFIX + "logging.sink_all_log_entries"
DEFAULT = {"name": "projects/p/sinks/_Default", "filter": 'NOT LOG_ID("cloudaudit.googleapis.com/activity")', "destination": "x"}


def test_sink_all_entries_inheritance_and_exclusions():
    everything = {"name": "projects/p/sinks/all", "destination": "storage.googleapis.com/archive"}
    assert run(SINK_ID, LOCAL, scope_index({"log_sink": [DEFAULT, everything]})) == "PASS"
    assert run(SINK_ID, LOCAL, scope_index({"log_sink": [DEFAULT, {**everything, "disabled": True}]})) == "FAIL"
    excluded = {**everything, "exclusions": [{"name": "drop", "filter": "severity<WARNING"}]}
    assert run(SINK_ID, LOCAL, scope_index({"log_sink": [DEFAULT, excluded]})) == "MANUAL"
    assert run(SINK_ID, ORG, scope_index({"log_sink": [DEFAULT]})) == "MANUAL"
    org_sink = {"name": "organizations/9/sinks/all", "includeChildren": True, "destination": "bigquery.googleapis.com/projects/c/datasets/d"}
    assert run(SINK_ID, {**ORG, "_inherited_sinks": [org_sink]}, scope_index({"log_sink": [DEFAULT]})) == "PASS"
    assert run(SINK_ID, {**ORG, "_inherited_sinks": [{**org_sink, "includeChildren": False}]}, scope_index({"log_sink": [DEFAULT]})) == "FAIL"
    assert run(SINK_ID, LOCAL, {"collections": {"log_sink": [{"scope": "projects/p", "status": "denied"}]}}) == "UNKNOWN"


# --- Services -------------------------------------------------------------------------------------------------

RUN = "projects/p/locations/us-central1/services/fn"


def test_function_and_run_public_access():
    fn = PREFIX + "function.not_publicly_accessible"
    gen1 = {"environment": "GEN_1", "iamPolicy": {"bindings": [{"role": "roles/cloudfunctions.invoker", "members": ["allUsers"]}]}}
    assert run(fn, gen1) == "FAIL"
    assert run(fn, {**gen1, "iamPolicy": {"bindings": []}}) == "PASS"
    disabled = scope_index({"cloudrun_service": [{"name": RUN, "invokerIamDisabled": True, "iamPolicy": {"bindings": []}}]})
    assert run(fn, {"environment": "GEN_2", "serviceConfig": {"service": RUN}, "iamPolicy": {"bindings": []}}, disabled) == "FAIL"
    run_id = PREFIX + "cloudrun_service.invoker_not_public"
    assert run(run_id, {"name": RUN, "invokerIamDisabled": True, "iamPolicy": {"bindings": []}}) == "FAIL"
    assert run(run_id, {"name": RUN, "iamPolicy": {"bindings": [{"role": "roles/run.viewer", "members": ["allUsers"]}]}}) == "MANUAL"


def test_api_key_boundary_and_sql_addresses():
    key = PREFIX + "api_key.created_within_90_days"
    at = {"_provenance": {"collected_at": "2026-10-10T00:00:00Z"}}
    assert run(key, {"createTime": "2026-07-12T00:00:00Z", **at}) == "PASS"  # exactly 90 days
    assert run(key, {"createTime": "2026-07-11T00:00:00Z", **at}) == "FAIL"  # 91 days
    sql = PREFIX + "sql_instance.only_private_ip_addresses"
    assert run(sql, {"backendType": "SECOND_GEN", "ipAddresses": [{"type": "PRIMARY"}]}) == "FAIL"
    assert run(sql, {"backendType": "SECOND_GEN"}) == "PASS"


def test_function_ingress_and_vpc():
    ingress = PREFIX + "function.ingress_not_allow_all"
    assert run(ingress, {"serviceConfig": {"ingressSettings": "ALLOW_INTERNAL_AND_GCLB"}}) == "PASS"
    vpc = PREFIX + "function.vpc_connector_configured"
    assert run(vpc, {"environment": "GEN_1", "serviceConfig": {}}) == "FAIL"
    assert run(vpc, {"environment": "GEN_1", "serviceConfig": {"directVpcNetworkInterface": [{"network": "n"}]}}) == "MANUAL"
