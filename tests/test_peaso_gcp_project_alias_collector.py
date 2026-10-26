"""Native project IAM observations and conservative alias annotation."""
from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.collectors import gcp
from peaso.snapshot import validate


SCOPE = "projects/fixture-project"
NUMBER = "projects/12345"
CAI_NAME = "//cloudresourcemanager.googleapis.com/" + NUMBER
CONFIGS = [{"service": "allServices", "auditLogConfigs": [{"logType": "DATA_READ"}]}]


class Transport:
    def __init__(self, *, numeric=False, cai_policy=None, duplicate=False, peer=False,
                 peer_duplicate=False, empty_ancestry=False, ancestor_rows=None,
                 project_id="fixture-project", direct=None):
        self.scope = NUMBER if numeric else SCOPE
        self.cai_policy = {} if cai_policy is None else cai_policy
        self.duplicate = duplicate
        self.peer = peer
        self.peer_duplicate = peer_duplicate
        self.empty_ancestry = empty_ancestry
        self.ancestor_rows = ancestor_rows
        self.project_id = project_id
        self.direct = {"bindings": [], "auditConfigs": deepcopy(CONFIGS)} if direct is None else direct
        self.calls = 0
        self.evidence = []

    def request(self, method, url, **kwargs):
        self.calls += 1
        request_id = f"request-{self.calls}"
        from urllib.parse import urlsplit
        evidence = {"id": request_id, "method": method, "url": url,
                    "scope": kwargs.get("scope"), "status": "collected", "http_status": 200,
                    "operation": urlsplit(url).path, "query": kwargs.get("params") or {}}
        if kwargs.get("body"):
            evidence["request"] = deepcopy(kwargs["body"])
        self.evidence.append(evidence)
        if url.endswith(":getAncestry"):
            rows = [] if self.empty_ancestry else [
                {"resourceId": {"type": "project", "id": "12345"}}]
            data = {"ancestor": deepcopy(self.ancestor_rows) if self.ancestor_rows is not None else rows}
        elif url.endswith(":getIamPolicy"):
            data = deepcopy(self.direct)
        elif url.endswith(":searchAllIamPolicies"):
            view = {"resource": CAI_NAME, "assetType": "cloudresourcemanager.googleapis.com/Project",
                    "project": NUMBER, "policy": deepcopy(self.cai_policy)}
            rows = [view]
            if self.duplicate:
                rows.append(deepcopy(view))
            if self.peer or self.peer_duplicate:
                rows.append({"resource": "//storage.googleapis.com/projects/12345/buckets/peer",
                    "assetType": "storage.googleapis.com/Bucket", "project": NUMBER,
                    "policy": {"bindings": []}})
            if self.peer_duplicate:
                rows.append({"resource": "//storage.googleapis.com/projects/12345/buckets/peer",
                    "assetType": "storage.googleapis.com/Bucket", "project": NUMBER,
                    "policy": {"bindings": [{"role": "roles/viewer", "members": ["user:peer@example.invalid"]}]}})
            data = {"results": rows}
        elif url.endswith("/v3/" + self.scope):
            data = {"name": NUMBER, "projectId": self.project_id, "projectNumber": "12345"}
        else:
            data = {}
        return data, request_id


def collect(transport, *, inherited=True):
    connector = {"provider": "gcp", "scopes": [transport.scope], "options": {
        "inventories": ["iam_policy"], "include_inherited": inherited,
        "metrics_scopes": False, "concurrency": 1}}
    result = gcp.GCPCollector(connector, transport=transport).collect()
    assert validate(result) == result
    return result


def inventory(result, kind):
    return next(row for row in result["collections"] if row["type"] == kind)


def test_scope_jobs_collects_project_support_and_raw_cai_omission():
    transport = Transport(cai_policy={}, direct={"auditConfigs": deepcopy(CONFIGS)})
    result = collect(transport)
    policies = inventory(result, "iam_policy")
    assert len(policies["items"]) == 2
    direct = next(row for row in policies["items"] if row["_provenance"]["representation"] == "full")
    cai = next(row for row in policies["items"] if row["_provenance"]["representation"] == "partial")
    assert direct["bindings"] == []  # full getIamPolicy documented omitted default
    assert "bindings" not in cai  # a CAI projection must retain raw omission
    assert direct["_provenance"]["representation"] == "full"
    assert cai["_provenance"]["representation"] == "partial"
    assert direct["_coverage"]["effectiveAuditConfigs"]["status"] == "collected"
    assert inventory(result, "project")["items"][0]["projectId"] == "fixture-project"


def test_numeric_scope_preserves_both_native_observations_and_provenance():
    transport = Transport(numeric=True, cai_policy={"bindings": []})
    result = collect(transport)
    rows = inventory(result, "iam_policy")["items"]
    assert len(rows) == 2
    assert inventory(result, "iam_policy")["coverage_status"] == "collected"
    assert len({row["_resource_id"] for row in rows}) == 2
    assert {row["native_id"] for row in rows} == {CAI_NAME}
    assert {row["_provenance"]["representation"] for row in rows} == {"full", "partial"}
    assert all(row["_provenance"]["source_requests"] for row in rows)
    root = next(row for row in rows if row["_provenance"]["representation"] == "full")
    assert root["_coverage"]["effectiveAuditConfigs"]["status"] == "collected"
    assert inventory(result, "project")["items"][0]["projectId"] == "fixture-project"


def test_resource_peer_stays_visible_without_root_ambiguity():
    result = collect(Transport(cai_policy={"bindings": []}, peer=True))
    rows = inventory(result, "iam_policy")["items"]
    assert len(rows) == 3
    assert any(row.get("assetType") == "storage.googleapis.com/Bucket" for row in rows)
    root = next(row for row in rows if row["name"] == SCOPE)
    assert root["_coverage"]["effectiveAuditConfigs"]["status"] == "collected"


def test_duplicate_cai_observations_keep_root_ambiguous():
    result = collect(Transport(cai_policy={"bindings": []}, duplicate=True))
    rows = inventory(result, "iam_policy")["items"]
    assert len(rows) == 3
    assert len({row["_resource_id"] for row in rows}) == 3
    envelope = inventory(result, "iam_policy")
    assert envelope["coverage_status"] == "partial"
    assert envelope["error"]["code"] == "conflicting_iam_policy_identity"
    root = next(row for row in rows if row["name"] == SCOPE)
    assert root["_coverage"]["effectiveAuditConfigs"]["status"] == "partial"
    assert SCOPE in root["_coverage"]["effectiveAuditConfigs"]["malformed_scopes"]


@pytest.mark.parametrize("policy", [[], {"policy": {"bindings": []}}, {"bindings": "bad"}])
def test_malformed_cai_policy_keeps_direct_root_incomplete(policy):
    result = collect(Transport(cai_policy=policy))
    envelope = inventory(result, "iam_policy")
    assert envelope["coverage_status"] == "partial"
    assert envelope["source_requests"]
    root = next(row for row in envelope["items"] if row["_provenance"]["representation"] == "full")
    assert root["_coverage"]["effectiveAuditConfigs"]["status"] == "partial"


def test_project_hydration_and_ancestry_requests_are_in_envelope_provenance():
    transport = Transport(cai_policy={"bindings": []})
    result = collect(transport)
    project = inventory(result, "project")
    refs = set(project["source_requests"])
    assert set(project["items"][0]["_provenance"]["source_requests"]) <= refs
    assert any(ref for ref in refs if next(row for row in transport.evidence if row["id"] == ref)["url"].endswith(":getAncestry"))


def test_unbound_project_identity_does_not_exclude_cai_root():
    result = collect(Transport(cai_policy={"bindings": []}, project_id="different-project"))
    rows = inventory(result, "iam_policy")["items"]
    assert len(rows) == 2
    root = next(row for row in rows if row["name"] == SCOPE)
    assert root["_coverage"]["effectiveAuditConfigs"]["status"] == "partial"
    assert SCOPE in root["_coverage"]["effectiveAuditConfigs"]["malformed_scopes"]
    assert all(row["type"] != "project" for row in result["collections"])


def test_conflicting_typed_resource_peer_observations_make_inventory_partial():
    result = collect(Transport(cai_policy={"bindings": []}, peer_duplicate=True))
    envelope = inventory(result, "iam_policy")
    peers = [row for row in envelope["items"] if row.get("assetType") == "storage.googleapis.com/Bucket"]
    assert len(peers) == 2
    assert {row["native_id"] for row in peers} == {"//storage.googleapis.com/projects/12345/buckets/peer"}
    assert len({row["_resource_id"] for row in peers}) == 2
    assert envelope["coverage_status"] == "partial"
    assert envelope["error"]["code"] == "conflicting_iam_policy_identity"
    root = next(row for row in envelope["items"] if row["name"] == SCOPE)
    assert root["_coverage"]["effectiveAuditConfigs"]["status"] == "partial"


def test_conflicting_direct_root_observations_make_inventory_partial():
    collector = gcp.GCPCollector({"provider": "gcp", "scopes": [SCOPE],
        "options": {"inventories": ["iam_policy"], "include_inherited": False}}, transport=Transport())
    def first():
        yield [{"name": SCOPE, "bindings": [], "_representation": "full"}], "direct-one"
    def second():
        yield [{"name": SCOPE, "bindings": [{"role": "roles/viewer", "members": ["user:x@example.invalid"]}],
                "_representation": "full"}], "direct-two"
    collector.add("iam_policy", SCOPE, "iam", first)
    envelope = collector.add("iam_policy", SCOPE, "iam", second)
    assert len(envelope["items"]) == 2
    assert {row["native_id"] for row in envelope["items"]} == {
        "//cloudresourcemanager.googleapis.com/" + SCOPE}
    assert envelope["coverage_status"] == "partial"
    assert envelope["error"]["code"] == "conflicting_iam_policy_identity"
    assert envelope["source_requests"] == ["direct-one", "direct-two"]


@pytest.mark.parametrize("source,policy", [
    ("direct", {"name": "projects/forged", "bindings": []}),
    ("direct", {"_provenance": {"representation": "full"}}),
    ("cai", {"name": SCOPE, "bindings": []}),
    ("cai", {"native_id": "//forged", "bindings": []}),
    ("cai", {"unsupported": True}),
])
def test_provider_policy_cannot_override_identity_or_collector_metadata(source, policy):
    transport = Transport(cai_policy=policy if source == "cai" else {"bindings": []},
                          direct=policy if source == "direct" else None)
    result = collect(transport)
    envelope = inventory(result, "iam_policy")
    assert envelope["coverage_status"] == "partial"
    assert envelope["error"]["kind"] == "malformed"
    assert all(row.get("name") != "projects/forged" and row.get("native_id") != "//forged"
               for row in envelope["items"])


def test_empty_native_ancestry_cannot_certify_parentless_project():
    result = collect(Transport(cai_policy={"bindings": []}, empty_ancestry=True))
    root = next(row for row in inventory(result, "iam_policy")["items"] if row["name"] == SCOPE)
    coverage = root["_coverage"]["effectiveAuditConfigs"]
    assert coverage["status"] == "partial"
    assert coverage["ancestry_known"] is False
    assert result["metadata"]["scope_coverage"]
    assert any(row.get("error", {}).get("code") == "malformed_ancestry"
               for row in result["metadata"]["scope_coverage"])


@pytest.mark.parametrize("rows", [
    [{"resourceId": {"type": "project", "id": "99999"}}],
    [{"resourceId": {"type": "folder", "id": "12"}}],
    [{"resourceId": {"type": "project", "id": "12345"}},
     {"resourceId": {"type": "project", "id": "12345"}}],
    [{"resourceId": {"type": "project", "id": "12345"}},
     {"resourceId": {"type": "organization", "id": "34"}},
     {"resourceId": {"type": "folder", "id": "12"}}],
])
def test_malformed_native_ancestry_never_certifies_complete_chain(rows):
    result = collect(Transport(cai_policy={"bindings": []}, ancestor_rows=rows))
    project_policies = next(row for row in result["collections"]
                            if row["type"] == "iam_policy" and row["scope"] == SCOPE)
    root = next(row for row in project_policies["items"] if row["name"] == SCOPE)
    coverage = root["_coverage"]["effectiveAuditConfigs"]
    assert coverage["status"] == "partial"
    assert coverage["ancestry_known"] is False
    assert any(row.get("error", {}).get("code") == "malformed_ancestry"
               for row in result["metadata"]["scope_coverage"])


def test_identical_direct_root_pages_merge_request_references():
    collector = gcp.GCPCollector({"provider": "gcp", "scopes": [SCOPE],
        "options": {"inventories": ["iam_policy"], "include_inherited": False}}, transport=Transport())
    root = {"name": SCOPE, "bindings": [], "_representation": "full"}
    envelope = collector.envelope("iam_policy", SCOPE, "iam", lambda: iter([
        ([root], "page-one"), ([deepcopy(root)], "page-two")]))
    assert envelope["coverage_status"] == "collected"
    assert len(envelope["items"]) == 1
    assert envelope["source_requests"] == ["page-one", "page-two"]
    assert envelope["items"][0]["_provenance"]["source_requests"] == ["page-one", "page-two"]


# Native REST roles.get has no view query; roles.list still needs FULL.
import unittest
from urllib.parse import urlsplit

class _BuiltinGetNativeAPI:
 def __init__(self):self.calls=0;self.evidence=[];self.reads=[]
 def request(self,method,url,**kw):
  assert method=='GET';params=kw.get('params') or {};self.reads.append((url,params));self.calls+=1;ident='request-'+str(self.calls);path=urlsplit(url).path
  self.evidence.append({'id':ident,'method':method,'url':url,'scope':kw['scope'],'operation':path,'query':params,'status':'collected','http_status':200})
  if path.startswith('/v1/roles/'):
   if params:raise gcp.ReadError('unavailable','api_error',http_status=400)
   return {'name':path[4:],'title':'Synthetic role','includedPermissions':['compute.instances.get','iam.serviceAccounts.get']},ident
  assert params.get('view')=='FULL' and params.get('showDeleted')=='true';return {'roles':[]},ident
class TestBuiltinRoleGetQueryContract(unittest.TestCase):
 def reader(self,scope):
  api=_BuiltinGetNativeAPI();c=gcp.GCPCollector({'provider':'gcp','name':'exact regression','scopes':[scope],'auth':{'token':'synthetic-never-used'},'options':{}},requirements=['iam_role_builtin','iam_role'],transport=api);return c,api
 def test_all_three_scope_forms_use_get_without_list_only_view(self):
  for scope,count in [('projects/fixture-project',18),('folders/12345',1),('organizations/12345',4)]:
   with self.subTest(scope=scope):
    c,api=self.reader(scope);jobs=[j for j in c.scope_jobs(scope) if j[0]=='iam_role_builtin'];self.assertEqual(len(jobs),1)
    batches=list(jobs[0][3]());self.assertEqual(len(batches),count);self.assertEqual(len(api.reads),count);self.assertTrue(all(not q for _,q in api.reads));self.assertTrue(all(row['includedPermissions'] for rows,_ in batches for row in rows))
 def test_custom_role_listing_still_requests_all_permissions(self):
  for scope in ['projects/fixture-project','organizations/12345']:
   with self.subTest(scope=scope):
    c,api=self.reader(scope);jobs=[j for j in c.scope_jobs(scope) if j[0]=='iam_role'];self.assertEqual(len(jobs),1);list(jobs[0][3]());self.assertEqual(api.reads[0][1]['view'],'FULL');self.assertEqual(api.reads[0][1]['showDeleted'],'true')
