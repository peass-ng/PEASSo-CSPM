"""Several Synapse workspaces in one subscription yield one evidence collection."""
from peaso import snapshot
from peaso.collectors import azure_application_compute_2_native as native

SUB = "/subscriptions/00000000-0000-0000-0000-000000000001"
RG = SUB + "/resourceGroups/rg"


def _workspace(name):
    return {"id": f"{RG}/providers/Microsoft.Synapse/workspaces/{name}", "type": "Microsoft.Synapse/workspaces"}


def _endpoint(name):
    return f"{RG}/providers/Microsoft.Network/privateEndpoints/{name}"


class Reader:
    def __init__(self, fail=()):
        self.collections = []
        self.fail = set(fail)

    def pages(self, request, url):
        rid = url.split("/privateEndpointConnections")[0][len(native.ARM):]
        name = rid.rsplit("/", 1)[1]
        if name in self.fail:
            raise PermissionError("denied")
        yield [{"id": f"{rid}/privateEndpointConnections/c-{name}",
                "type": "Microsoft.Synapse/workspaces/privateEndpointConnections",
                "properties": {"privateEndpoint": {"id": _endpoint("pe-" + name)},
                               "privateLinkServiceConnectionState": {"status": "Approved"}}}]

    def call(self, request, url):
        eid = url.split("?")[0][len(native.ARM):]
        name = eid.rsplit("/", 1)[1][3:]
        target = f"{RG}/providers/Microsoft.Synapse/workspaces/{name}"
        return {"id": eid, "type": "Microsoft.Network/privateEndpoints",
                "properties": {"provisioningState": "Succeeded", "privateLinkServiceConnections": [
                    {"id": eid + "/privateLinkServiceConnections/l",
                     "properties": {"privateLinkServiceId": target, "groupIds": ["Sql"],
                                    "privateLinkServiceConnectionState": {"status": "Approved"}}}]}}

    def _read(self, job):
        kind, scope, service, fetch = job
        try:
            items = [item for page in fetch() for item in page]
        except PermissionError:
            return {"status": "denied", "items": [], "error": {"code": "AuthorizationFailed"}}
        except ValueError:
            return {"status": "unknown", "items": [], "error": {"code": "native_unresolved"}}
        return {"status": "collected" if items else "empty", "items": items}


def _run(names, fail=()):
    reader = Reader(fail)
    workspaces = [{"type": "synapse_workspace", "scope": SUB, "status": "collected", "items": [_workspace(n) for n in names]}]
    native.collect_synapse_sql_private_endpoints(reader, None, workspaces, {native.KIND})
    return reader.collections


def _validate(collections):
    snapshot.make_snapshot("azure", [SUB], collections, created_at="2026-10-26T00:00:00+00:00")


def test_single_workspace_record_is_unchanged():
    (record,) = _run(["one"])
    assert record["status"] == "collected"
    assert [item["id"] for item in record["items"]] == [_workspace("one")["id"]]
    assert set(record) == {"type", "scope", "service", "status", "items"}
    _validate([record])


def test_several_workspaces_share_one_collection():
    collections = _run(["one", "two", "three"])
    assert len(collections) == 1
    (record,) = collections
    assert record["type"] == native.KIND and record["scope"] == SUB and record["status"] == "collected"
    assert [item["id"] for item in record["items"]] == [_workspace(n)["id"] for n in ("one", "two", "three")]
    assert record["items"][1]["resolved_private_endpoint_ids"] == [_endpoint("pe-two")]
    _validate(collections)


def test_one_failed_workspace_marks_the_collection_partial():
    (record,) = _run(["one", "two"], fail={"two"})
    assert record["status"] == "partial"
    assert [item["id"] for item in record["items"]] == [_workspace("one")["id"]]
    assert record["error"] == {"code": "native_unresolved"}
    _validate([record])


def test_all_failed_workspaces_keep_the_failure_status():
    (record,) = _run(["one", "two"], fail={"one", "two"})
    assert record["status"] == "unknown" and record["items"] == []
    assert record["error"] == {"code": "native_unresolved"}
    _validate([record])
