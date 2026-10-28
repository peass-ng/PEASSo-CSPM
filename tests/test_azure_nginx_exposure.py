"""NGINX configuration is reduced to listener ports before snapshot persistence."""
import base64

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import resources


SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
DEPLOYMENT = SCOPE + "/resourceGroups/rg/providers/Nginx.NginxPlus/nginxDeployments/proxy"
PIP = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/proxy"
CONFIG = DEPLOYMENT + "/configurations/default"
BASE = "https://management.azure.com"


def _scan(config_text="http { server { listen 8443 ssl; } }", public=True, package=False):
    secret = "hidden-password-from-config"
    payload = config_text + "\n# " + secret
    deployment = {"id": DEPLOYMENT, "name": "proxy", "type": "Nginx.NginxPlus/nginxDeployments",
                  "properties": {"provisioningState": "Succeeded", "networkProfile": {
                      "frontEndIPConfiguration": {"publicIPAddresses": [{"id": PIP}] if public else []}}}}
    configuration = {"id": CONFIG, "name": "default", "type": "Nginx.NginxPlus/nginxDeployments/configurations",
                     "properties": {"rootFile": "/etc/nginx/nginx.conf", "files": [{"virtualPath": "/etc/nginx/nginx.conf",
                         "content": base64.b64encode(payload.encode()).decode()}],
                         **({"package": {"data": "opaque"}} if package else {})}}
    pages = {SCOPE + "/providers/Nginx.NginxPlus/nginxDeployments": [deployment],
             DEPLOYMENT + "/configurations": [configuration]}

    class Transport:
        tenant = verified_tenant = None
        def __init__(self):
            self.calls = []
        def request(self, url, *, body=None, audience=azure.ARM):
            self.calls.append(url)
            assert url.startswith(BASE) and body is None
            path = url[len(BASE):].split("?", 1)[0]
            assert path in pages
            return {"value": pages[path]}

    transport = Transport()
    snapshot = azure.collect({"scopes": [SCOPE], "auth": {}, "options": {"concurrency": 1, "retries": 0}},
                             requirements=["nginx_deployment"], transport=transport)
    findings = assess(snapshot, resources(snapshot))
    return snapshot, findings, transport, secret


def test_public_frontend_configured_listener_and_no_secret_persistence():
    snapshot, findings, transport, secret = _scan()
    assert len(findings) == 1
    assert findings[0].verdict() == "FAIL"
    assert findings[0].ports == {"tcp": ((8443, 8443),)}
    nginx_calls = [url for url in transport.calls if "Nginx.NginxPlus" in url]
    assert len(nginx_calls) == len(set(nginx_calls)) == 3
    assert secret not in repr(snapshot)
    nginx_row, = [item for collection in snapshot["collections"] if collection["type"] == "nginx_deployment"
                  for item in collection["items"]]
    assert "content" not in repr(nginx_row)


def test_private_frontend_and_unresolved_package():
    _, findings, _, _ = _scan(public=False)
    assert findings[0].verdict() == "PASS"
    _, findings, _, _ = _scan(package=True)
    assert findings[0].verdict() == "UNKNOWN"


def test_missing_include_keeps_listener_uncertain():
    _, findings, _, _ = _scan("http { include /etc/nginx/sites/*.conf; server { listen 80; } }")
    assert findings[0].verdict() == "UNKNOWN"
    assert findings[0].ports == {"tcp": ((80, 80),)}
