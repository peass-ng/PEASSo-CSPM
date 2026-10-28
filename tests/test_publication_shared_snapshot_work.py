"""Native and final publications of one analyzer share snapshot-only artifacts exactly."""
import copy

import peaso.least_privilege as least_privilege
from peaso import snapshot as native
from peaso.engine import evaluate_snapshot
from peaso.storage import reports
from peaso.storage.artifacts import FileArtifacts, check_reference
from peaso.worker import redact_report

TENANT, IDENT = "owner", "a" * 32


def fixture():
    scope = "123456789012/us-east-1"
    snapshot = native.make_snapshot("aws", [scope], [
        {"type": "bucket", "scope": scope, "status": "collected",
         "items": [{"Name": "synthetic-one"}, {"Name": "synthetic-two"}]},
        {"type": "security_group", "scope": scope, "status": "collected",
         "items": [{"GroupId": "sg-1", "IpPermissions": []}]},
        {"type": "iam_role", "scope": scope, "status": "collected", "items": [{
            "Arn": "arn:aws:iam::123456789012:role/synthetic", "RoleName": "synthetic",
            "AssumeRolePolicyDocument": {"Statement": []},
            "RolePolicyList": [{"PolicyName": "inline", "PolicyDocument": {
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}]}]}],
        created_at="2026-01-01T00:00:00+00:00")
    report = redact_report(evaluate_snapshot(snapshot, checks=["aws.s3.default_encryption"],
                                             categories=["hardening"], include_not_applicable=False))
    return report, snapshot


def normalize(value, store):
    if isinstance(value, str):
        try:
            check_reference(TENANT, value)
        except (ValueError, TypeError):
            return value
        return store.get_text(TENANT, value) if value.endswith(".md") else normalize(store.get(TENANT, value), store)
    if isinstance(value, list):
        return [normalize(item, store) for item in value]
    if isinstance(value, dict):
        return {key: normalize(item, store) for key, item in value.items()}
    return value


def counting(monkeypatch):
    calls = {"chunks": 0, "least": 0, "network": 0}
    chunks, project, network = reports.resource_chunks, least_privilege.project, reports._network_projection

    def counted_chunks(*a, **kw):
        calls["chunks"] += 1
        return chunks(*a, **kw)

    def counted_project(*a, **kw):
        calls["least"] += 1
        return project(*a, **kw)

    def counted_network(*a, **kw):
        calls["network"] += 1
        return network(*a, **kw)

    monkeypatch.setattr(reports, "resource_chunks", counted_chunks)
    monkeypatch.setattr(least_privilege, "project", counted_project)
    monkeypatch.setattr(reports, "_network_projection", counted_network)
    return calls


def final(report):
    value = copy.deepcopy(report)
    value["ai"] = {"status": "completed", "reason": None}
    value["publication"] = {"state": "final"}
    return value


def test_final_publication_reuses_snapshot_artifacts_and_matches_uncached(tmp_path, monkeypatch):
    report, snapshot = fixture()
    calls = counting(monkeypatch)
    shared_store, plain_store = FileArtifacts(tmp_path / "shared"), FileArtifacts(tmp_path / "plain")
    shared = {}
    native_ref = reports.publish_report(shared_store, TENANT, IDENT, dict(report, publication={"state": "partial"}),
                                        snapshot, _shared=shared)
    assert calls == {"chunks": 1, "least": 1, "network": 1}
    final_ref = reports.publish_report(shared_store, TENANT, IDENT, final(report), snapshot, _shared=shared)
    assert calls == {"chunks": 1, "least": 1, "network": 1}, "final bundle must reuse snapshot-only work"
    plain_ref = reports.publish_report(plain_store, TENANT, IDENT, final(report), snapshot)
    shared_manifest = shared_store.get(TENANT, final_ref)
    native_manifest = shared_store.get(TENANT, native_ref)
    for key in ("resource_chunks", "least_privilege", "least_privilege_permission_inputs", "network_snapshot"):
        assert shared_manifest[key] == native_manifest[key]
    assert shared_manifest["report_markdown"] == native_manifest["report_markdown"]
    assert list(shared_manifest) == list(plain_store.get(TENANT, plain_ref))
    assert normalize(shared_manifest, shared_store) == normalize(plain_store.get(TENANT, plain_ref), plain_store)


def test_changed_resource_set_or_snapshot_rebuilds(tmp_path, monkeypatch):
    report, snapshot = fixture()
    calls = counting(monkeypatch)
    store, shared = FileArtifacts(tmp_path), {}
    original = reports.publish_report(store, TENANT, IDENT, report, snapshot, _shared=shared)
    narrowed = final(report)
    narrowed["resources"] = [row for row in narrowed["resources"] if row["type"] == "bucket"]
    ref = reports.publish_report(store, TENANT, IDENT, narrowed, snapshot, _shared=shared)
    assert calls == {"chunks": 2, "least": 1, "network": 1}
    assert store.get(TENANT, ref)["report_markdown"] != store.get(TENANT, original)["report_markdown"]
    ids = [item["id"] for chunk in normalize(store.get(TENANT, ref), store)["resource_chunks"]
           for item in chunk["reference"]["items"]]
    assert ids == sorted(row["id"] for row in narrowed["resources"])
    # Another snapshot object (even with equal content) never reuses entries.
    reports.publish_report(store, TENANT, IDENT, report, copy.deepcopy(snapshot), _shared=shared)
    assert calls == {"chunks": 3, "least": 2, "network": 2}
    # An in-place restructure of the same object is detected.
    other = copy.deepcopy(snapshot)
    reports.publish_report(store, TENANT, IDENT, report, other, _shared=shared)
    other["collections"][0]["items"] = list(other["collections"][0]["items"])
    reports.publish_report(store, TENANT, IDENT, report, other, _shared=shared)
    assert calls["least"] == 4


def test_without_shared_state_every_publication_computes(tmp_path, monkeypatch):
    report, snapshot = fixture()
    calls = counting(monkeypatch)
    store = FileArtifacts(tmp_path)
    reports.publish_report(store, TENANT, IDENT, report, snapshot)
    reports.publish_report(store, TENANT, IDENT, final(report), snapshot)
    assert calls == {"chunks": 2, "least": 2, "network": 2}
