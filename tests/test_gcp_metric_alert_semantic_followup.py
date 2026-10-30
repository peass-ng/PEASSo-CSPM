"""Direct native semantic regressions, with no registry or fixture mutation."""
from copy import deepcopy

from peaso.checks import gcp_metric_alert_native as native
from peaso.checks.facts import Unavailable

PROJECT = {"projectId": "p", "name": "projects/123"}
REFERENCE = 'resource.type="iam_role" AND (protoPayload.methodName="google.iam.admin.v1.CreateRole" OR protoPayload.methodName="google.iam.admin.v1.DeleteRole" OR protoPayload.methodName="google.iam.admin.v1.UpdateRole")'
TYPE = "logging.googleapis.com/user/m"


def rows():
    return {
        "logging_metric": [{"name": "projects/p/metrics/m", "filter": REFERENCE,
                            "metricDescriptor": {"type": TYPE}}],
        "monitoring_alert_policy": [{"name": "projects/123/alertPolicies/a", "enabled": True,
            "conditions": [{"conditionThreshold": {"filter": f'metric.type="{TYPE}" resource.type="global"'}}]}],
    }


def evaluate(monkeypatch, data):
    monkeypatch.setattr(native, "complete_items", lambda index, kind: deepcopy(data[kind]))
    return native.evaluate_metric_alert_native(PROJECT, {}, REFERENCE)


def assert_unavailable(function, *args):
    try:
        function(*args)
    except Unavailable:
        return
    raise AssertionError("Expected UNKNOWN-worthy syntax")


def test_reference_boolean_order_grouping_and_implicit_and():
    reordered = '(protoPayload.methodName="google.iam.admin.v1.UpdateRole" OR protoPayload.methodName="google.iam.admin.v1.CreateRole" OR protoPayload.methodName="google.iam.admin.v1.DeleteRole") resource.type=iam_role'
    assert native.reference_filter_matches(reordered, REFERENCE)
    assert native.reference_filter_matches("(" + REFERENCE + ")", REFERENCE)


def test_negated_narrowed_and_incomplete_or_branches_are_not_reference():
    for expression in (
        "NOT (" + REFERENCE + ")",
        "- (" + REFERENCE + ")",
        REFERENCE + ' AND severity="ERROR"',
        REFERENCE[:-1] + ' AND severity="ERROR")',
        REFERENCE.replace(' OR protoPayload.methodName="google.iam.admin.v1.UpdateRole"', ''),
        REFERENCE + ' OR protoPayload.methodName="other"',
        REFERENCE[:-1],
        REFERENCE + ' AND',
        'textPayload:"' + REFERENCE.replace('"', '\\"') + '"',
    ):
        assert_unavailable(native.reference_filter_matches, expression, REFERENCE)


def test_unescaped_regex_dots_are_not_literal_filter_comparisons():
    ref = 'protoPayload.methodName="cloudsql.instances.update"'
    assert_unavailable(native.reference_filter_matches,
                       ref.replace("cloudsql.instances", "cloudsqlXinstances"), ref)
    ref = 'protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*'
    assert_unavailable(native.reference_filter_matches,
                       ref.replace("serviceData.policyDelta", "serviceDataXpolicyDelta"), ref)


def test_logging_or_precedes_and_for_pinned_ownership_expression():
    assert native._expression('a="1" AND b="2" OR c="3"') == native._expression('a="1" AND (b="2" OR c="3")')
    assert native._expression('a="1" AND b="2" OR c="3"') != native._expression('(a="1" AND b="2") OR c="3"')


def test_enabled_same_project_native_metric_and_threshold_pass(monkeypatch):
    status, evidence = evaluate(monkeypatch, rows())
    assert status == "PASS"
    assert evidence["matching_metrics"] == [TYPE]
    assert evidence["alerting"] == [{"alert": "projects/123/alertPolicies/a", "metric_type": TYPE}]
    assert "delivery" in evidence["semantics"]


def test_absence_is_association_without_event_trigger_claim(monkeypatch):
    data = rows()
    body = data["monitoring_alert_policy"][0]["conditions"][0].pop("conditionThreshold")
    data["monitoring_alert_policy"][0]["conditions"][0]["conditionAbsent"] = body
    assert evaluate(monkeypatch, data)[0] == "PASS"


def test_threshold_configuration_is_not_invented_event_policy(monkeypatch):
    data = rows()
    data["monitoring_alert_policy"][0]["conditions"][0]["conditionThreshold"].update(
        comparison="COMPARISON_LT", thresholdValue=7, duration="600s")
    assert evaluate(monkeypatch, data)[0] == "PASS"


def test_negation_foreign_project_and_unrelated_type_cannot_pass(monkeypatch):
    expressions = [
        (f'NOT metric.type="{TYPE}"', "UNKNOWN"),
        (f'metric.type="{TYPE}" AND resource.labels.project_id="foreign"', "FAIL"),
        (f'metric.type="{TYPE}" AND project="foreign"', "FAIL"),
        ('metric.type="logging.googleapis.com/user/unrelated"', "FAIL"),
        (f'metric.type="{TYPE}" AND metric.type="unrelated"', "FAIL"),
        (f'metric.type="{TYPE}" OR metric.type="unrelated"', "UNKNOWN"),
        (f'metric.type="{TYPE}" AND resource.labels.zone="only-one"', "UNKNOWN"),
        (f'metric.type="{TYPE}" AND resource.type="global" AND resource.type="gce_instance"', "FAIL"),
    ]
    for expression, expected in expressions:
        data = rows()
        data["monitoring_alert_policy"][0]["conditions"][0]["conditionThreshold"]["filter"] = expression
        assert evaluate(monkeypatch, data)[0] == expected


def test_mql_text_mentions_and_condition_union_are_unknown(monkeypatch):
    for condition in (
        {"conditionMonitoringQueryLanguage": {"query": f'# metric.type="{TYPE}"\nfetch global | metric "unrelated"'}},
        {"conditionPrometheusQueryLanguage": {"query": f'metric.type="{TYPE}"'}},
        {"conditionThreshold": {"filter": f'metric.type="{TYPE}"'},
         "conditionAbsent": {"filter": f'metric.type="{TYPE}"'}},
    ):
        data = rows()
        data["monitoring_alert_policy"][0]["conditions"] = [condition]
        assert evaluate(monkeypatch, data)[0] == "UNKNOWN"


def test_disabled_foreign_and_invalid_policies_fail(monkeypatch):
    for mutation in ({"enabled": False}, {"name": "projects/foreign/alertPolicies/a"},
                     {"validity": {"code": 3, "message": "Invalid filter"}}):
        data = rows()
        data["monitoring_alert_policy"][0].update(mutation)
        assert evaluate(monkeypatch, data)[0] == "FAIL"
    for mutation in ({"disabled": True}, {"name": "projects/foreign/metrics/m"}):
        data = rows()
        data["logging_metric"][0].update(mutation)
        assert evaluate(monkeypatch, data)[0] == "FAIL"


def test_missing_enabled_and_malformed_disable_flags_stay_unknown(monkeypatch):
    data = rows()
    del data["monitoring_alert_policy"][0]["enabled"]
    assert evaluate(monkeypatch, data)[0] == "UNKNOWN"
    for disabled in ("false", None, 0):
        data = rows()
        data["logging_metric"][0]["disabled"] = disabled
        assert evaluate(monkeypatch, data)[0] == "UNKNOWN"


def test_bucket_scope_and_wrong_descriptor_are_unknown(monkeypatch):
    for mutation in ({"bucketName": "projects/p/locations/global/buckets/one"},
                     {"metricDescriptor": {"type": "custom.googleapis.com/unrelated"}},
                     {"name": "m"}):
        data = rows()
        data["logging_metric"][0].update(mutation)
        assert evaluate(monkeypatch, data)[0] == "UNKNOWN"


def test_complete_empty_rosters_fail_and_unavailable_inventory_propagates(monkeypatch):
    assert evaluate(monkeypatch, {"logging_metric": [], "monitoring_alert_policy": []})[0] == "FAIL"
    monkeypatch.undo()
    assert_unavailable(native.evaluate_metric_alert_native, PROJECT, {}, REFERENCE)


def test_uncertain_alternative_does_not_hide_a_proven_positive(monkeypatch):
    data = rows()
    data["logging_metric"].append({"name": "projects/p/metrics/complex", "filter": "SEARCH(\"x\")"})
    assert evaluate(monkeypatch, data)[0] == "PASS"


def test_all_existing_reference_filters_are_accepted():
    from peaso.checks.claude_gcp_k8s_iam import SAMPLE_FILTERS as references
    assert references
    for reference in references.values():
        assert native.reference_filter_matches(reference, reference)


def test_selector_requires_native_resource_type_and_consistent_project_labels(monkeypatch):
    for expression, expected in (
        (f'metric.type="{TYPE}"', "UNKNOWN"),
        (f'metric.type="{TYPE}" resource.type=""', "UNKNOWN"),
        (f'metric.type="{TYPE}" resource.type=global', "UNKNOWN"),
        (f'metric.type="{TYPE}" resource.type="global" project=123', "PASS"),
        (f'metric.type="{TYPE}" resource.type="global" resource.labels.project_id="p"', "PASS"),
        (f'metric.type="{TYPE}" resource.type="global" resource.labels.project_id="p" resource.labels.project_id="123"', "FAIL"),
    ):
        data = rows()
        data["monitoring_alert_policy"][0]["conditions"][0]["conditionThreshold"]["filter"] = expression
        assert evaluate(monkeypatch, data)[0] == expected


def test_collector_raw_metric_identifier_is_not_url_decoded(monkeypatch):
    data = rows()
    data["logging_metric"][0].update(name="projects/p/metrics/m%2Fraw", metricId="m%2Fraw",
                                    metricDescriptor={"type": "logging.googleapis.com/user/m%2Fraw"})
    body = data["monitoring_alert_policy"][0]["conditions"][0]["conditionThreshold"]
    body["filter"] = body["filter"].replace(TYPE, "logging.googleapis.com/user/m%2Fraw")
    assert evaluate(monkeypatch, data)[0] == "PASS"


def test_installed_native_collector_and_engine_preserve_deciding_filter_semantics():
    from peaso.engine import evaluate_snapshot
    from peaso.checks.claude_gcp_k8s_iam import SAMPLE_FILTERS
    from tests.test_peaso_collectors_gcp import snapshot
    cid = 'gcp.claude.logging.metric_alert_custom_role_changes'
    reference = SAMPLE_FILTERS['custom_role_changes']
    for kind, expected in [('reference','PASS'),('negated','UNKNOWN'),('foreign_selector','FAIL'),('mql','UNKNOWN'),('invalid','FAIL')]:
        metric = {'name':'m','filter':('NOT ('+reference+')') if kind=='negated' else reference,
                  'metricDescriptor':{'type':TYPE}}
        condition = {'conditionThreshold':{'filter':'metric.type="'+TYPE+'" resource.type="global"'+(' project="foreign"' if kind=='foreign_selector' else '')}}
        if kind=='mql':condition={'conditionMonitoringQueryLanguage':{'query':'# metric.type="'+TYPE+'"'}}
        policy={'name':'projects/123/alertPolicies/a','enabled':True,'conditions':[condition]}
        if kind=='invalid':policy['validity']={'code':3}
        def resolve(request):
            url=request['url']
            if url.endswith('/metrics'):return {'metrics':[deepcopy(metric)]}
            if url.endswith('/alertPolicies'):return {'alertPolicies':[deepcopy(policy)]}
            if url=='https://cloudresourcemanager.googleapis.com/v3/projects/p-one':return {'name':'projects/123','projectId':'p-one','state':'ACTIVE'}
            assert url=='https://compute.googleapis.com/compute/v1/projects/p-one',url
            return {'name':'p-one','id':'123'}
        captured, transport=snapshot(['project','logging_metric','monitoring_alert_policy'],resolve,metrics_scopes=False)
        findings=evaluate_snapshot(captured,checks=[cid])['findings']
        assert len(findings)==1 and findings[0]['status']==expected,(kind,findings)
        assert len(transport.requests)==4
        assert {r['method'] for r in transport.requests}=={'GET'}


def test_unrelated_project_resource_name_is_not_a_native_alias(monkeypatch):
    from peaso.checks.facts import Unavailable
    data=rows()
    monkeypatch.setattr(native,'complete_items',lambda index,kind:deepcopy(data[kind]))
    try:
        native.evaluate_metric_alert_native({'projectId':'p','name':'projects/foreign'},{},REFERENCE)
    except Unavailable:
        return
    raise AssertionError('An unrelated project resource name cannot prove a local numeric alias')
