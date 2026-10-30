"""Alias projection preserves complete native facts without an extra outer copy."""
import copy
from types import SimpleNamespace
import pytest
from peaso.collectors import bulk_evidence as original
from peaso.snapshot import make_snapshot

@pytest.mark.parametrize("provider,source,alias,row",[("aws","bucket","s3_bucket",{"Name":"fixture","nested":{"items":[1]}}),("aws","log_subscription_filter","cloudwatch_subscription_filter",{"filterName":"fixture","nested":{"items":[1]}}),("azure","sql_server","database_server",{"id":"fixture","defaultCredentialAssessment":"private","nested":{"items":[1]}}),("azure","app_service","web_app",{"id":"fixture","workloadSecrets":"private","nested":{"items":[1]}})])
def test_copy_independence(provider,source,alias,row):
 snapshot=make_snapshot(provider,["scope"],[{"type":source,"scope":"scope","status":"collected","items":[row]}],created_at="2026-10-24T00:00:00Z",metadata={"nested":{"value":[1]}})
 before=copy.deepcopy(snapshot); module=SimpleNamespace(SUPPORTED_TYPES={source},collect=lambda *_:snapshot)
 connector={"provider":provider,"options":{"compliance_parameters":{"nested":{"value":[1]}}}}
 actual=original.collect(module,connector,[alias])
 assert snapshot==before
 native=next(c for c in actual["collections"] if c["type"]==source); projection=next(c for c in actual["collections"] if c["type"]==alias)
 projection["items"][0]["nested"]["items"].append(2); assert native["items"][0]["nested"]["items"]==[1]
 native["items"][0]["nested"]["items"].append(3);actual["metadata"]["parameters"]["nested"]["value"].append(2)
 assert snapshot==before;assert connector["options"]["compliance_parameters"]["nested"]["value"]==[1]

@pytest.mark.parametrize("status",["denied","partial"])
def test_failure_statuses_preserved(status):
 rows=[{"Name":"fixture"}]if status=="partial"else []
 snapshot=make_snapshot("aws",["scope"],[{"type":"bucket","scope":"scope","status":status,"items":rows,"error":{"code":"FixtureFailure"}}],created_at="2026-10-24T00:00:00Z")
 module=SimpleNamespace(AWS_TYPES={"bucket"},collect=lambda *_:snapshot)
 args=(module,{"provider":"aws","options":{}},["s3_bucket"])
 result=original.collect(*args)
 alias=next(c for c in result["collections"] if c["type"]=="s3_bucket")
 assert alias["status"]==status and alias.get("error")
 assert len(alias["items"])==len(rows)
