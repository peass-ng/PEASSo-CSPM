"""ARO public API/ingress detection uses cached ARM detail without saving secrets."""
from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import resources


SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
CLUSTER = SCOPE + "/resourceGroups/rg/providers/Microsoft.RedHatOpenShift/openShiftClusters/aro"
BASE = "https://management.azure.com"


def _scan(api="Public", ingress="Public", malformed=False):
    secret = "pull-secret-must-not-appear"
    row = {"id": CLUSTER, "name": "aro", "type": "Microsoft.RedHatOpenShift/openShiftClusters",
           "properties": {"provisioningState": "Succeeded",
                          "apiserverProfile": {"visibility": api,
                                               "url": "https://api.cluster.aroapp.io:6443/" if not malformed else "https://api.cluster.aroapp.io:bad/"},
                          "ingressProfiles": [{"name": "default", "visibility": ingress, "ip": "203.0.113.10"}],
                          "clusterProfile": {"domain": "cluster.aroapp.io", "pullSecret": secret},
                          "servicePrincipalProfile": {"clientId": "safe", "clientSecret": secret}}}

    class Transport:
        tenant = verified_tenant = None
        def __init__(self): self.calls = []
        def request(self, url, *, body=None, audience=azure.ARM):
            self.calls.append(url)
            assert body is None and url.startswith(BASE)
            path = url[len(BASE):].split("?", 1)[0]
            if path == CLUSTER:
                return row
            if path == SCOPE + "/providers/Microsoft.RedHatOpenShift/openShiftClusters":
                return {"value": [{"id": CLUSTER, "name": "aro", "type": row["type"]}]}
            return {"value": []}

    transport = Transport()
    snapshot = azure.collect({"scopes": [SCOPE], "auth": {}, "options": {"concurrency": 1, "retries": 0}},
                             requirements=["openshift_cluster"], transport=transport)
    findings = assess(snapshot, resources(snapshot))
    return snapshot, findings, transport, secret


def test_public_api_and_ingress_ports_with_secret_free_snapshot():
    snapshot, findings, transport, secret = _scan()
    assert len(findings) == 1 and findings[0].verdict() == "FAIL"
    assert findings[0].ports == {"tcp": ((80, 80), (443, 443), (6443, 6443))}
    assert secret not in repr(snapshot)
    assert len(transport.calls) == len(set(transport.calls))
    assert sum(url.startswith(BASE + CLUSTER + "?") for url in transport.calls) == 1


def test_private_cluster_has_no_public_frontend():
    _, findings, _, _ = _scan(api="Private", ingress="Private")
    assert len(findings) == 1 and findings[0].verdict() == "PASS"


def test_malformed_public_api_url_remains_unknown():
    _, findings, _, _ = _scan(ingress="Private", malformed=True)
    assert len(findings) == 1 and findings[0].verdict() == "UNKNOWN"
