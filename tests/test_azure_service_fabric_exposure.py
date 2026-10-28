"""Classic and managed Service Fabric public control endpoints."""

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure_service_fabric_native as native
from peaso.snapshot import make_snapshot, resources


ARM = "https://management.azure.com"
SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"


def test_cluster_lists_project_only_public_endpoint_facts():
    class Reader:
        def __init__(self):
            self.collections = []
            self.urls = []

        def pages(self, request, url):
            self.urls.append(url)
            managed = "/managedClusters?" in url
            kind = "managedClusters" if managed else "clusters"
            props = ({"provisioningState": "Succeeded", "fqdn": "cluster.eastus.cloudapp.azure.com",
                      "ipv4Address": "8.8.8.8", "clientConnectionPort": 19000,
                      "httpGatewayConnectionPort": 19080, "adminPassword": "drop-me"} if managed else
                     {"provisioningState": "Succeeded",
                      "managementEndpoint": "https://cluster.eastus.cloudapp.azure.com:19080/admin?drop=me",
                      "nodeTypes": [{"clientConnectionEndpointPort": "19000"}], "secret": "drop-me"})
            yield [{"id": SCOPE + "/resourceGroups/rg/providers/Microsoft.ServiceFabric/" + kind + "/cluster",
                    "name": "cluster", "type": "Microsoft.ServiceFabric/" + kind, "properties": props}]

        def run(self, jobs):
            for kind, scope, service, fetch in jobs:
                self.collections.append({"type": kind, "scope": scope, "service": service,
                                         "status": "collected", "items": [item for page in fetch() for item in page]})

    reader = Reader()
    native.collect(reader, lambda _: None, [SCOPE], set(native.KINDS), ARM)
    assert len(reader.urls) == 2
    assert "drop-me" not in str(reader.collections) and "drop=me" not in str(reader.collections)
    snap = make_snapshot("azure", [SCOPE], reader.collections)
    findings = {a.resource["type"]: a for a in assess(snap, resources(snap))}
    for kind in native.KINDS:
        assert findings[kind].verdict() == "UNKNOWN"
        assert findings[kind].addresses == ["cluster.eastus.cloudapp.azure.com"]
        assert findings[kind].ports
