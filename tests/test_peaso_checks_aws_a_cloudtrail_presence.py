"""Complete regional/account absence, shadow/home and organization join variants."""
import copy
import pytest
from peaso.checks import CHECKS, aws_a_cloudtrail_presence as rules
from peaso.checks.fixtures import CASES
from peaso.checks.aws_a_facts import scope_fixture

REGISTRY = {c.id:c for c in CHECKS if c.id in rules.NATIVE_IDS}


@pytest.mark.parametrize("cid", rules.NATIVE_IDS)
def test_scope_presence_real_states_and_purity(cid):
    cases = CASES[cid]
    for state, expected in (("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"), ("malformed", "UNKNOWN")):
        item,index = copy.deepcopy(cases[state]),copy.deepcopy(cases.get(state+"_index",cases["index"]));before=copy.deepcopy((item,index))
        assert REGISTRY[cid].evaluate(item,index)[0]==expected
        assert (item,index)==before
    assert REGISTRY[cid].evaluate(rules.SUBJECT,scope_fixture(REGISTRY[cid].kind,[],status="denied"))[0]=="UNKNOWN"


def test_regional_shadow_logging_satisfies_regional_scope_but_not_home_account_source():
    shadow={**rules.TRAIL,"SourceRegion":"eu-west-1"}
    assert REGISTRY["aws.a.cloudtrail.region_has_logging"].evaluate(rules.SUBJECT,scope_fixture("cloudtrail",[shadow]))[0]=="PASS"
    assert REGISTRY["aws.a.cloudtrail.account_has_home_logging"].evaluate(rules.SUBJECT,scope_fixture("cloudtrail_account_inventory",[shadow]))[0]=="FAIL"


def test_organization_join_manual_and_failed_rows_are_not_existential_shortcut():
    check=REGISTRY["aws.a.cloudtrail.account_has_logging_multiregion"]
    org={**rules.TRAIL,"SourceRegion":"eu-west-1","IsOrganizationTrail":True}
    assert check.evaluate(rules.SUBJECT,scope_fixture(check.kind,[org]))[0]=="PASS"
    assert check.evaluate(rules.SUBJECT,scope_fixture(check.kind,[org,{**org,"Status":{"IsLogging":False}}]))[0]=="FAIL"
    assert check.evaluate(rules.SUBJECT,scope_fixture(check.kind,[{**org,"Status":{"collection_status":"denied"}}]))[0]=="MANUAL"
    assert check.evaluate(rules.SUBJECT,scope_fixture(check.kind,[org,{**org,"IsMultiRegionTrail":False}]))[0]=="FAIL"
    assert check.evaluate(rules.SUBJECT,scope_fixture(check.kind,[rules.TRAIL,{**org,"IsMultiRegionTrail":False}]))[0]=="PASS"


def test_account_global_fact_requires_complete_enabled_region_discovery(monkeypatch):
    boto3=pytest.importorskip("boto3")
    from botocore.stub import Stubber
    from peaso.collectors import aws
    session=boto3.Session(aws_access_key_id="inert",aws_secret_access_key="inert",region_name="us-east-1")
    clients={service:session.client(service,region_name="us-east-1") for service in ("sts","ec2","cloudtrail")};stubs={k:Stubber(v) for k,v in clients.items()}
    monkeypatch.setattr(aws,"_session",lambda *args:(session,"inert"));monkeypatch.setattr(aws.Requests,"client",lambda self,context,service,region:clients[service])
    stubs["sts"].add_response("get_caller_identity",{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/inert","UserId":"INERT"},{})
    stubs["ec2"].add_response("describe_regions",{"Regions":[{"RegionName":"us-east-1","OptInStatus":"opt-in-not-required"}]},{"AllRegions":True})
    stubs["cloudtrail"].add_response("describe_trails",{"trailList":[]},{"includeShadowTrails":True})
    with stubs["sts"],stubs["ec2"],stubs["cloudtrail"]:
        s=aws.collect({"provider":"aws","scopes":["123456789012"]},["cloudtrail_account_inventory"])
        env=next(c for c in s["collections"] if c["type"]=="cloudtrail_account_inventory")
        assert env["status"]=="empty" and env["global"] is True and env["account_id"]=="123456789012"
        assert s["metadata"]["calls"]==3
        for stub in stubs.values():stub.assert_no_pending_responses()


def _explicit_region_collect(monkeypatch, regions_response, trail_reads):
    boto3=pytest.importorskip("boto3")
    from botocore.stub import Stubber
    from peaso.collectors import aws
    session=boto3.Session(aws_access_key_id="inert",aws_secret_access_key="inert",region_name="us-east-1")
    clients={service:session.client(service,region_name="us-east-1") for service in ("sts","ec2","cloudtrail")};stubs={k:Stubber(v) for k,v in clients.items()}
    monkeypatch.setattr(aws,"_session",lambda *args:(session,"inert"));monkeypatch.setattr(aws.Requests,"client",lambda self,context,service,region:clients[service])
    stubs["sts"].add_response("get_caller_identity",{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/inert","UserId":"INERT"},{})
    if regions_response is None:
        stubs["ec2"].add_client_error("describe_regions","UnauthorizedOperation",http_status_code=403)
    else:
        stubs["ec2"].add_response("describe_regions",{"Regions":regions_response},{"AllRegions":True})
    for _ in range(trail_reads):
        stubs["cloudtrail"].add_response("describe_trails",{"trailList":[]},{"includeShadowTrails":True})
    with stubs["sts"],stubs["ec2"],stubs["cloudtrail"]:
        s=aws.collect({"provider":"aws","scopes":["us-east-1"]},["cloudtrail_account_inventory"])
        for stub in stubs.values():stub.assert_no_pending_responses()
    return s


def test_explicit_region_list_still_reads_account_wide_trails_in_every_enabled_region(monkeypatch):
    enabled=[{"RegionName":"us-east-1","OptInStatus":"opt-in-not-required"},{"RegionName":"eu-west-1","OptInStatus":"opt-in-not-required"},
             {"RegionName":"ap-east-1","OptInStatus":"not-opted-in"}]
    s=_explicit_region_collect(monkeypatch,enabled,2)
    env=next(c for c in s["collections"] if c["type"]=="cloudtrail_account_inventory")
    assert env["status"]=="empty" and env["global"] is True
    assert s["metadata"]["account_wide_regions"]=={"123456789012":["eu-west-1","us-east-1"]}
    assert not any(c["scope"].endswith("/eu-west-1") for c in s["collections"])


def test_explicit_region_list_without_region_discovery_does_not_fabricate_absence(monkeypatch):
    s=_explicit_region_collect(monkeypatch,None,0)
    env=next(c for c in s["collections"] if c["type"]=="cloudtrail_account_inventory")
    assert env["status"]=="not_collected" and env["error"]["code"]=="full_account_region_coverage_not_proven"
