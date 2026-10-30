"""Signed file-metadata checks require attested complete node/path sets."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from peaso.checks import evaluate_check
from peaso.checks import compliance_new_k8s_file_metadata as checks
from peaso.collectors.k8s import FILE_METADATA_SELECTORS, K8sReadError, collect
from tests.archived_check_contract import evaluate_snapshot
from peaso.checks import CHECKS, evaluate_check

NOW = datetime.now(timezone.utc).isoformat()
NODES = (("node-a", "uid-a"), ("node-b", "uid-b"))
PATH = "/etc/kubernetes/admin.conf"


@pytest.fixture(autouse=True)
def current_test_evidence_time(monkeypatch):
    # Collection can precede execution by more than the unchanged 600-second
    # evidence lifetime. Keep the fixture and collector on the same test clock.
    fixed = datetime.fromisoformat(NOW)
    class EvidenceDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed.astimezone(tz) if tz else fixed.replace(tzinfo=None)
    monkeypatch.setattr("peaso.collectors.k8s.datetime", EvidenceDateTime)
    monkeypatch.setitem(globals(), "datetime", EvidenceDateTime)


class NodeAPI:
    server = "https://fixture.invalid"
    api_client = SimpleNamespace(configuration=SimpleNamespace(host=server))

    def __init__(self, nodes=NODES, denied=False):
        self.nodes, self.denied, self.calls = nodes, denied, []

    def get_json(self, path, params=None):
        self.calls.append((path, dict(params or {})))
        if self.denied:
            raise K8sReadError("permission_denied", 403)
        assert path == "/api/v1/nodes"
        page = int((params or {}).get("continue", "0"))
        name, uid = self.nodes[page]
        return {"metadata": {"resourceVersion": "7", **({"continue": str(page + 1)} if page + 1 < len(self.nodes) else {})},
                "items": [{"metadata": {"name": name, "uid": uid}}]}


def manifest(path=PATH, *, observed_at=None, node_ids=NODES):
    if observed_at is None:
        observed_at = NOW
    nodes = []
    for name, uid in node_ids:
        selectors = {selector: {"applicable": False, "reason": "owner attests this path family is not deployed on this node"}
                     for selector in FILE_METADATA_SELECTORS}
        if name == "node-a":
            selectors[path] = {"applicable": True, "enumeration_complete": True, "paths": [path]}
        nodes.append({"name": name, "uid": uid, "selectors": selectors})
    return {"status": "complete", "cluster_id": "fixture", "observed_at": observed_at, "nodes": nodes}


def request(*, rows=None, coverage=None, max_age=600, max_pages=None, scopes=None):
    if rows is None:
        rows = [{"path": PATH, "node_name": "node-a", "node_uid": "uid-a", "observed_at": NOW,
                 "symlink_status": "not_symlink", "mode": 0o600, "uid": 0, "gid": 0}]
    options = {"inventories": ["file_metadata"], "metadata_evidence": {"file_metadata": rows},
               "file_metadata_policy": {"max_age_seconds": max_age}}
    if coverage is not False:
        options["metadata_evidence_coverage"] = {"file_metadata": coverage if coverage is not None else manifest()}
    if max_pages is not None:
        options["max_pages"] = max_pages
    return {"provider": "k8s", "options": options, "auth": {"cluster_id": "fixture"},
            **({"scopes": scopes} if scopes is not None else {})}


def snapshot(**kwargs):
    api = kwargs.pop("api", NodeAPI())
    return collect(request(**kwargs), api=api), api


def test_all_25_registered_scope_rules_have_distinct_signed_thresholds_and_fixtures():
    for cid in checks.IDS:
        cases = checks.CASES[cid]
        assert evaluate_check(cid, cases["pass"], cases["pass_index"])[0] == "PASS", cid
        assert evaluate_check(cid, cases["fail"], cases["fail_index"])[0] == "FAIL", cid
        assert evaluate_check(cid, {}, cases["pass_index"])[0] == "UNKNOWN", cid


def test_actual_paged_node_and_supplied_file_coverage_end_to_end():
    result, api = snapshot()
    cov = result["metadata"]["file_metadata_coverage"]
    assert cov["status"] == "attested_complete" and cov["runtime_verified"] is False
    assert cov["node_count"] == 2 and len(cov["selector_paths"][PATH]) == 1
    assert [path for path, _ in api.calls] == ["/api/v1/nodes", "/api/v1/nodes"]
    assert api.calls[1][1]["continue"] == "1"
    assert sum(c["type"] == "node" for c in result["collections"]) == 1
    row = next(c["items"][0] for c in result["collections"] if c["type"] == "file_metadata")
    assert row["provenance"]["runtime_verified"] is False and row["id"].endswith("%2Fetc%2Fkubernetes%2Fadmin.conf")
    report = evaluate_snapshot(result, checks=["k8s.cis.file_admin_conf_mode_600"])
    assert report["stats"]["by_status"] == {"PASS": 1}
    assert report["findings"][0]["evidence"]["assessed_file_count"] == 1


def test_namespace_restricted_scan_uses_same_actual_node_and_file_scope():
    result, _ = snapshot(scopes=["apps"])
    assert {(c["type"], c["scope"]) for c in result["collections"]} == {
        ("node", "apps"), ("file_metadata", "apps")}
    report = evaluate_snapshot(result, checks=["k8s.cis.file_admin_conf_mode_600"])
    assert report["stats"]["by_status"] == {"PASS": 1}
    assert report["findings"][0]["scope"] == "apps"


@pytest.mark.parametrize("mutator,reason", [
    (lambda rows, cov: rows.clear(), "selector_paths_exceed_observed_files"),
    (lambda rows, cov: rows[0].update(node_uid="old-uid"), "file_identity_unresolved"),
    (lambda rows, cov: rows.append(deepcopy(rows[0])), "duplicate_node_path"),
    (lambda rows, cov: cov["nodes"][0]["selectors"][PATH].update(paths=[]), "selector_paths_incomplete"),
    (lambda rows, cov: cov["nodes"][0]["selectors"][PATH].update(enumeration_complete=False), "selector_paths_incomplete"),
    (lambda rows, cov: cov["nodes"][0]["selectors"][PATH].update(paths=["/etc/kubernetes/../admin.conf"]), "selector_paths_malformed"),
])
def test_missing_duplicate_foreign_or_incomplete_attestation_unknown(mutator, reason):
    rows = request()["options"]["metadata_evidence"]["file_metadata"]
    cov = manifest()
    mutator(rows, cov)
    result, _ = snapshot(rows=rows, coverage=cov)
    assert result["metadata"]["file_metadata_coverage"]["status"] == "unknown"
    assert result["metadata"]["file_metadata_coverage"]["reason"] == reason


def test_denied_truncated_stale_and_empty_applicability_unknown():
    denied, _ = snapshot(api=NodeAPI(denied=True))
    assert denied["metadata"]["file_metadata_coverage"]["status"] == "unknown"
    truncated, _ = snapshot(max_pages=1)
    assert truncated["metadata"]["file_metadata_coverage"]["status"] == "unknown"
    stale, _ = snapshot(coverage=manifest(observed_at=(datetime.now(timezone.utc)-timedelta(hours=2)).isoformat()))
    assert stale["metadata"]["file_metadata_coverage"]["status"] == "unknown"
    empty_manifest = manifest()
    empty_manifest["nodes"][0]["selectors"][PATH] = {"applicable": False, "reason": "owner reports no file"}
    no_rows, _ = snapshot(rows=[], coverage=empty_manifest)
    assert no_rows["metadata"]["file_metadata_coverage"]["status"] == "attested_complete"
    report = evaluate_snapshot(no_rows, checks=["k8s.cis.file_admin_conf_mode_600"])
    assert report["stats"]["by_status"] == {"UNKNOWN": 1}


def test_glob_requires_all_attested_paths_and_overlap_is_selector_specific():
    selector = "/etc/kubernetes/pki/*.crt"
    original = manifest()
    original["nodes"][0]["selectors"][PATH] = {"applicable": False, "reason": "owner reports no admin.conf"}
    original["nodes"][0]["selectors"][selector] = {"applicable": True, "enumeration_complete": True,
                                                     "paths": ["/etc/kubernetes/pki/a.crt", "/etc/kubernetes/pki/b.crt"]}
    rows = [{"path": path, "node_name": "node-a", "node_uid": "uid-a", "observed_at": NOW,
             "symlink_status": "not_symlink", "mode": 0o600 if path.endswith("a.crt") else 0o644,
             "uid": 0, "gid": 0} for path in original["nodes"][0]["selectors"][selector]["paths"]]
    result, _ = snapshot(rows=rows, coverage=original)
    assert result["metadata"]["file_metadata_coverage"]["status"] == "attested_complete"
    report = evaluate_snapshot(result, checks=["k8s.cis.file_pki_crt_mode_600"])
    assert report["stats"]["by_status"] == {"FAIL": 1}
    assert report["findings"][0]["evidence"]["failing_count"] == 1
    assert report["findings"][0]["evidence"]["failing_files"][0]["path"].endswith("b.crt")
    rows.append({**rows[0], "path": "/etc/kubernetes/pki/extra.crt"})
    added, _ = snapshot(rows=rows, coverage=original)
    assert added["metadata"]["file_metadata_coverage"]["reason"] == "observed_path_omitted_from_manifest"


def test_unresolved_symlink_and_owner_types_never_pass():
    cid = "k8s.cis.file_admin_conf_owner"
    item = checks.CASES[cid]["pass"]
    index = deepcopy(checks.CASES[cid]["pass_index"])
    index["file_metadata"][0]["data"]["symlink_status"] = "symlink"
    assert evaluate_check(cid, item, index)[0] == "UNKNOWN"
    index["file_metadata"][0]["data"]["symlink_status"] = "not_symlink"
    index["file_metadata"][0]["data"]["gid"] = True
    assert evaluate_check(cid, item, index)[0] == "UNKNOWN"
    index["file_metadata"][0]["data"]["uid"] = 0
    index["file_metadata"][0]["data"]["gid"] = 1000
    assert evaluate_check(cid, item, index)[0] == "FAIL"


def test_malformed_offline_attestation_path_cannot_satisfy_fixed_selector():
    cid = "k8s.cis.file_admin_conf_mode_600"
    item = deepcopy(checks.CASES[cid]["pass"])
    index = deepcopy(checks.CASES[cid]["pass_index"])
    item["metadata"]["file_metadata_coverage"]["selector_paths"][PATH][0]["path"] = "/tmp/admin.conf"
    index["file_metadata"][0]["data"]["path"] = "/tmp/admin.conf"
    assert evaluate_check(cid, item, index)[0] == "UNKNOWN"


def test_legacy_supplied_string_mode_is_preserved_without_attested_pass():
    api = NodeAPI()
    legacy = request(rows=[{"path": "/var/lib/kubelet/config.yaml", "mode": "600", "uid": 0, "gid": 0}],
                     coverage=False)
    result = collect(legacy, api=api)
    row = next(c["items"][0] for c in result["collections"] if c["type"] == "file_metadata")
    assert row["mode"] == "600" and api.calls == []
    assert result["metadata"]["file_metadata_coverage"]["status"] == "unknown"
