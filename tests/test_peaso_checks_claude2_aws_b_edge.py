from copy import deepcopy

import pytest

from peaso.checks import evaluate_check
from peaso.checks import claude2_aws_b_edge as edge
from peaso.checks.claude2_aws_b_common import IDS
from peaso.checks.claude2_aws_b_common import IDS, ROWS


REDIRECT = {"Type": "redirect", "RedirectConfig": {"Protocol": "HTTPS", "Port": "443", "StatusCode": "HTTP_301"}}
FORWARD = {"Type": "forward", "TargetGroupArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/app/1"}
CHECK = "aws.c2b.elbv2.http_listeners_redirect_https"
DEFAULT_CHECK = "aws.c2b.elbv2.alb_http_redirect_default"


def _rule(default, action):
    return {"RuleArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:listener-rule/app/1/" + ("default" if default else "conditional"),
            "IsDefault": default, "Actions": [deepcopy(action)]}


def _http_listener(port, default_action, rules):
    return {"ListenerArn": f"arn:aws:elasticloadbalancing:us-east-1:111122223333:listener/app/1/{port}",
            "Protocol": "HTTP", "Port": port, "DefaultActions": [deepcopy(default_action)],
            "Rules": {"collection_status": "collected", "items": deepcopy(rules)}}


def _alb(*listeners):
    return {"LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/1",
            "Type": "application", "Listeners": {"collection_status": "collected", "items": list(listeners)}}


def _status(item, check=CHECK):
    return evaluate_check(check, item)[0]


def test_collector_facts_reference_registered_edge_checks():
    for fact in edge.COLLECTOR_FACTS:
        assert set(fact) == {"kind", "api", "fields", "checks"}
        assert fact["fields"] and fact["checks"]
        assert all(cid in IDS for cid in fact["checks"]), fact


def test_conditional_redirect_cannot_hide_default_http_forward():
    item = _alb(_http_listener(80, FORWARD, [_rule(False, REDIRECT), _rule(True, FORWARD)]))
    assert _status(item) == "FAIL"
    assert _status(item, DEFAULT_CHECK) == "FAIL"


def test_default_redirect_cannot_hide_conditional_http_forward():
    item = _alb(_http_listener(80, REDIRECT, [_rule(False, FORWARD), _rule(True, REDIRECT)]))
    assert _status(item) == "FAIL"
    assert _status(item, DEFAULT_CHECK) == "PASS"


def test_every_http_listener_must_redirect():
    good = _http_listener(80, REDIRECT, [_rule(True, REDIRECT)])
    bad = _http_listener(8080, FORWARD, [_rule(True, FORWARD)])
    assert _status(_alb(good, bad)) == "FAIL"
    assert _status(_alb(bad, good)) == "FAIL"
    assert _status(_alb(good, _http_listener(8080, REDIRECT, [_rule(True, REDIRECT)]))) == "PASS"


def test_complete_redirect_rules_and_tls_only_pass():
    http = _http_listener(80, REDIRECT, [_rule(False, REDIRECT), _rule(True, REDIRECT)])
    https = {"ListenerArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:listener/app/1/443",
             "Protocol": "HTTPS", "Port": 443, "DefaultActions": [deepcopy(FORWARD)]}
    assert _status(_alb(http, https)) == "PASS"
    assert _status(_alb(https)) == "PASS"


@pytest.mark.parametrize("protocol", ["#{protocol}", "HTTP", None])
def test_redirect_that_retains_http_protocol_does_not_pass(protocol):
    action = deepcopy(REDIRECT)
    if protocol is None:
        del action["RedirectConfig"]["Protocol"]
    else:
        action["RedirectConfig"]["Protocol"] = protocol
    assert _status(_alb(_http_listener(80, action, [_rule(True, action)]))) == "FAIL"


@pytest.mark.parametrize("damage", ["missing", "invalid"])
def test_incomplete_listener_protocol_is_unknown_without_hiding_known_failure(damage):
    incomplete = _http_listener(80, REDIRECT, [_rule(True, REDIRECT)])
    if damage == "missing":
        del incomplete["Protocol"]
    else:
        incomplete["Protocol"] = "TLS"
    bad = _http_listener(8080, FORWARD, [_rule(True, FORWARD)])
    assert _status(_alb(incomplete)) == "UNKNOWN"
    assert _status(_alb(incomplete, bad)) == "FAIL"
    assert _status(_alb(bad, incomplete)) == "FAIL"


@pytest.mark.parametrize("damage", ["missing_rules", "denied_rules", "partial_rules", "missing_default_rule",
                                  "duplicate_default_rule", "missing_is_default", "missing_actions", "missing_default_actions",
                                  "inconsistent_default", "missing_rule_items", "malformed_redirect"])
def test_incomplete_or_inconsistent_rule_evidence_is_unknown(damage):
    listener = _http_listener(80, REDIRECT, [_rule(True, REDIRECT)])
    if damage == "missing_rules":
        del listener["Rules"]
    elif damage == "denied_rules":
        listener["Rules"] = {"collection_status": "denied", "error": {"code": "AccessDenied"}}
    elif damage == "partial_rules":
        listener["Rules"]["collection_status"] = "partial"
    elif damage == "missing_default_rule":
        listener["Rules"]["items"] = [_rule(False, REDIRECT)]
    elif damage == "duplicate_default_rule":
        listener["Rules"]["items"].append(_rule(True, REDIRECT))
    elif damage == "missing_is_default":
        del listener["Rules"]["items"][0]["IsDefault"]
    elif damage == "missing_actions":
        del listener["Rules"]["items"][0]["Actions"]
    elif damage == "missing_default_actions":
        del listener["DefaultActions"]
    elif damage == "inconsistent_default":
        listener["Rules"]["items"][0]["Actions"] = [deepcopy(FORWARD)]
    elif damage == "malformed_redirect":
        listener["Rules"]["items"][0]["Actions"][0]["RedirectConfig"]["Protocol"] = "FTP"
    else:
        del listener["Rules"]["items"]
    assert _status(_alb(listener)) == "UNKNOWN"


def test_unknown_on_one_http_listener_does_not_become_pass_from_another():
    complete = _http_listener(80, REDIRECT, [_rule(True, REDIRECT)])
    incomplete = _http_listener(8080, REDIRECT, [_rule(True, REDIRECT)])
    incomplete["Rules"]["collection_status"] = "partial"
    assert _status(_alb(complete, incomplete)) == "UNKNOWN"


CF_CHECK = "aws.c2b.cloudfront.origin_traffic_encrypted"


def _cf_origin(oid, policy="https-only"):
    return {"Id": oid, "CustomOriginConfig": {"OriginProtocolPolicy": policy}}


def _cf_behavior(target, viewer):
    return {"TargetOriginId": target, "ViewerProtocolPolicy": viewer}


def _cf_distribution(default, additional=(), origins=None):
    origins = [_cf_origin("web")] if origins is None else origins
    return {"Config": {"DistributionConfig": {
        "CallerReference": "origin-traffic-test",
        "Origins": {"Quantity": len(origins), "Items": origins},
        "DefaultCacheBehavior": default,
        "CacheBehaviors": {"Quantity": len(additional), "Items": list(additional)},
    }}}


def _cf_status(item):
    return evaluate_check(CF_CHECK, item)[0]


@pytest.mark.parametrize("reverse", [False, True])
def test_origin_traffic_checks_every_targeted_behavior_in_either_order(reverse):
    safe = _cf_behavior("web", "redirect-to-https")
    unsafe = _cf_behavior("web", "allow-all")
    default, extra = (unsafe, safe) if reverse else (safe, unsafe)
    item = _cf_distribution(default, [extra], [_cf_origin("web", "match-viewer")])
    assert _cf_status(item) == "FAIL"


def test_origin_traffic_ignores_unused_origin_and_passes_complete_https():
    item = _cf_distribution(_cf_behavior("web", "https-only"),
                            [_cf_behavior("web", "redirect-to-https")],
                            [_cf_origin("web", "match-viewer"), _cf_origin("unused", "http-only")])
    assert _cf_status(item) == "PASS"


@pytest.mark.parametrize("damage", ["missing_target", "unknown_target", "group_target", "group_present",
                                  "bad_quantity", "missing_quantity", "missing_items", "duplicate_origin",
                                  "missing_behaviors", "denied_behaviors", "partial_behavior",
                                  "denied_origin", "bad_origin_quantity", "contradictory_origin",
                                  "missing_origin_config", "denied_viewer_policy"])
def test_origin_traffic_incomplete_or_unsupported_evidence_is_unknown(damage):
    item = _cf_distribution(_cf_behavior("web", "https-only"))
    data = item["Config"]["DistributionConfig"]
    if damage == "missing_target":
        del data["DefaultCacheBehavior"]["TargetOriginId"]
    elif damage == "unknown_target":
        data["DefaultCacheBehavior"]["TargetOriginId"] = "missing"
    elif damage == "group_target":
        data["DefaultCacheBehavior"]["TargetOriginId"] = "group"
    elif damage == "group_present":
        data["OriginGroups"] = {"Quantity": 1, "Items": [{"Id": "group"}]}
    elif damage == "bad_quantity":
        data["CacheBehaviors"]["Quantity"] = 1
    elif damage == "missing_quantity":
        del data["CacheBehaviors"]["Quantity"]
    elif damage == "missing_items":
        data["CacheBehaviors"] = {"Quantity": 1}
    elif damage == "duplicate_origin":
        data["Origins"] = {"Quantity": 2, "Items": [_cf_origin("web"), _cf_origin("web")]}
    elif damage == "missing_behaviors":
        del data["CacheBehaviors"]
    elif damage == "denied_behaviors":
        data["CacheBehaviors"] = {"collection_status": "denied"}
    elif damage == "partial_behavior":
        data["CacheBehaviors"] = {"Quantity": 1, "Items": [{"TargetOriginId": "web"}]}
    elif damage == "denied_origin":
        data["Origins"] = {"collection_status": "denied"}
    elif damage == "bad_origin_quantity":
        data["Origins"]["Quantity"] = 2
    elif damage == "contradictory_origin":
        data["Origins"]["Items"][0]["S3OriginConfig"] = {"OriginAccessIdentity": ""}
    elif damage == "missing_origin_config":
        del data["Origins"]["Items"][0]["CustomOriginConfig"]
    else:
        data["DefaultCacheBehavior"]["_coverage"] = {"ViewerProtocolPolicy": {"status": "denied"}}
    assert _cf_status(item) == "UNKNOWN"


def test_origin_traffic_s3_viewer_policy_source_parity():
    s3 = {"Id": "bucket", "S3OriginConfig": {"OriginAccessIdentity": ""}, "OriginAccessControlId": "oac"}
    item = _cf_distribution(_cf_behavior("bucket", "allow-all"), origins=[s3])
    assert _cf_status(item) == "FAIL"
    item["Config"]["DistributionConfig"]["DefaultCacheBehavior"]["ViewerProtocolPolicy"] = "https-only"
    assert _cf_status(item) == "PASS"


@pytest.mark.parametrize("damage", ["denied", "malformed"])
def test_origin_traffic_insecure_default_survives_unrelated_behavior_damage(damage):
    item = _cf_distribution(_cf_behavior("web", "https-only"),
                            [_cf_behavior("safe", "https-only")],
                            [_cf_origin("web", "http-only"), _cf_origin("safe")])
    extra = item["Config"]["DistributionConfig"]["CacheBehaviors"]
    if damage == "denied":
        extra["_coverage"] = {"Items": {"status": "denied"}}
    else:
        extra["Items"] = [{"ViewerProtocolPolicy": "https-only"}]
    assert _cf_status(item) == "FAIL"


@pytest.mark.parametrize("reverse", [False, True])
def test_origin_traffic_known_insecure_extra_survives_another_unknown(reverse):
    bad = _cf_behavior("bad", "allow-all")
    incomplete = {"ViewerProtocolPolicy": "https-only"}
    extras = [incomplete, bad] if reverse else [bad, incomplete]
    item = _cf_distribution(_cf_behavior("safe", "https-only"), extras,
                            [_cf_origin("safe"), _cf_origin("bad", "match-viewer")])
    assert _cf_status(item) == "FAIL"


def test_origin_traffic_safe_default_and_unknown_extra_is_unknown():
    item = _cf_distribution(_cf_behavior("safe", "https-only"),
                            [{"ViewerProtocolPolicy": "https-only"}], [_cf_origin("safe")])
    assert _cf_status(item) == "UNKNOWN"


def test_origin_traffic_duplicate_insecure_target_is_ambiguous():
    item = _cf_distribution(_cf_behavior("web", "allow-all"), origins=[
        _cf_origin("web", "match-viewer"), _cf_origin("web", "match-viewer")])
    assert _cf_status(item) == "UNKNOWN"


@pytest.mark.parametrize("group", [{"Quantity": 1, "Items": [{"Id": "failover"}]},
                                   {"Quantity": 1, "Items": [{"Id": "web"}]},
                                   {"Quantity": 1}])
def test_origin_traffic_group_presence_requires_proven_direct_binding(group):
    item = _cf_distribution(_cf_behavior("web", "https-only"),
                            origins=[_cf_origin("web", "http-only")])
    item["Config"]["DistributionConfig"]["OriginGroups"] = group
    expected = "FAIL" if group.get("Items", [{}])[0].get("Id") == "failover" else "UNKNOWN"
    assert _cf_status(item) == expected


def test_origin_traffic_all_used_https_is_pass():
    item = _cf_distribution(_cf_behavior("safe", "https-only"),
                            [_cf_behavior("other", "redirect-to-https")],
                            [_cf_origin("safe", "https-only"), _cf_origin("other", "match-viewer")])
    item["Config"]["DistributionConfig"]["OriginGroups"] = {"Quantity": 0}
    assert _cf_status(item) == "PASS"
