"""Hosted OpenShift public API CIDRs and default ingress from read-only ARM GET."""
from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import resources


SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
CLUSTER = SCOPE + "/resourceGroups/rg/providers/Microsoft.RedHatOpenShift/hcpOpenShiftClusters/hcp"
BASE = "https://management.azure.com"


def _scan(visibility="Public", cidrs=None, ingress="Public", url="https://api.hcp.example:443"):
    secret = "secret-hcp-credential"
    detail = {"id": CLUSTER, "name": "hcp", "type": "Microsoft.RedHatOpenShift/hcpOpenShiftClusters",
              "properties": {"provisioningState": "Succeeded",
                             "api": {"visibility": visibility, "url": url,
                                     "authorizedCidrs": [] if cidrs is None else cidrs},
                             "ingress": {"type": ingress},
                             "platform": {"clientSecret": secret}}}

    class Transport:
        tenant = verified_tenant = None
        def __init__(self): self.calls = []
        def request(self, url, *, body=None, audience=azure.ARM):
            self.calls.append(url)
            assert body is None and url.startswith(BASE)
            path = url[len(BASE):].split("?", 1)[0]
            if path == CLUSTER:
                return detail
            if path == SCOPE + "/providers/Microsoft.RedHatOpenShift/hcpOpenShiftClusters":
                return {"value": [{"id": CLUSTER, "name": "hcp", "type": detail["type"]}]}
            return {"value": []}

    transport = Transport()
    snapshot = azure.collect({"scopes": [SCOPE], "auth": {}, "options": {"concurrency": 1, "retries": 0}},
                             requirements=["openshift_hcp_cluster"], transport=transport)
    findings = assess(snapshot, resources(snapshot))
    return snapshot, findings, transport, secret


def test_public_api_and_default_ingress_without_secret_or_duplicate_get():
    snapshot, findings, transport, secret = _scan()
    assert len(findings) == 1 and findings[0].verdict() == "FAIL"
    assert findings[0].ports == {"tcp": ((80, 80), (443, 443))}
    assert secret not in repr(snapshot)
    assert len(transport.calls) == len(set(transport.calls))
    assert sum(url.startswith(BASE + CLUSTER + "?") for url in transport.calls) == 1


def test_private_api_and_ingress_pass():
    _, findings, _, _ = _scan(visibility="Private", ingress="Private")
    assert len(findings) == 1 and findings[0].verdict() == "PASS"


def test_public_api_restricted_to_private_cidrs_passes():
    _, findings, _, _ = _scan(cidrs=["10.0.0.0/8"], ingress="Disabled")
    assert len(findings) == 1 and findings[0].verdict() == "PASS"
    _, findings, _, _ = _scan(cidrs=["8.8.8.0/24"], ingress="Disabled")
    assert findings[0].verdict() == "FAIL" and findings[0].ports == {"tcp": ((443, 443),)}


def test_malformed_allow_list_or_api_url_is_unknown():
    _, findings, _, _ = _scan(cidrs=["not-a-cidr"], ingress="Private")
    assert findings[0].verdict() == "UNKNOWN"
    _, findings, _, _ = _scan(ingress="Private", url="https://api.hcp.example:bad")
    assert findings[0].verdict() == "UNKNOWN"
