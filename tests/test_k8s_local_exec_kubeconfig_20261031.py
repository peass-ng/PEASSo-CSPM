"""Local CLI scans run the selected context's exec credential plugin; hosted scans never do."""
import json
import os
import stat
import sys
from types import SimpleNamespace

import pytest

from peaso.collectors import k8s


def plugin(tmp_path, expiry):
    counter = tmp_path / "runs"
    script = tmp_path / "fake-auth-plugin"
    script.write_text(f"""#!{sys.executable}
import json, os, pathlib
p = pathlib.Path({str(counter)!r}); n = int(p.read_text()) + 1 if p.exists() else 1; p.write_text(str(n))
info = json.loads(os.environ["KUBERNETES_EXEC_INFO"])
assert info["spec"]["interactive"] is False and os.environ["PLUGIN_FLAG"] == "on"
print(json.dumps({{"apiVersion": info["apiVersion"], "kind": "ExecCredential",
                  "status": {{"token": "exec-token-%d" % n, "expirationTimestamp": {expiry!r}}}}}))
""")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script, counter


def kubeconfig(tmp_path, script):
    doc = {"apiVersion": "v1", "kind": "Config", "current-context": "selected",
           "clusters": [{"name": "c", "cluster": {"server": "https://cluster.example"}}],
           "contexts": [{"name": "selected", "context": {"cluster": "c", "user": "plugin"}},
                        {"name": "other", "context": {"cluster": "c", "user": "unrelated"}}],
           "users": [{"name": "plugin", "user": {"exec": {
                         "apiVersion": "client.authentication.k8s.io/v1beta1", "command": str(script),
                         "env": [{"name": "PLUGIN_FLAG", "value": "on"}]}}},
                     {"name": "unrelated", "user": {"auth-provider": {"name": "never-used"}}}]}
    path = tmp_path / "config"
    path.write_text(json.dumps(doc))
    return path, doc


@pytest.fixture
def configurations(monkeypatch):
    from kubernetes import client
    seen = []
    monkeypatch.setattr(client, "ApiClient", lambda cfg: seen.append(cfg) or SimpleNamespace(close=lambda: None, configuration=cfg))
    monkeypatch.setattr(k8s, "_wrap_client", lambda obj, *args: obj)
    return seen


def test_local_kubeconfig_runs_selected_exec_plugin_and_ignores_other_users(tmp_path, configurations):
    script, runs = plugin(tmp_path, "2999-01-01T00:00:00Z")
    path, _ = kubeconfig(tmp_path, script)
    k8s._new_api({"method": "kubeconfig", "kubeconfig": str(path), "context": "selected"})
    cfg = configurations[-1]
    assert cfg.get_api_key_with_prefix("authorization") == "Bearer exec-token-1"
    cfg.get_api_key_with_prefix("authorization")
    assert runs.read_text() == "1"  # unexpired credential is reused


def test_expired_exec_credential_is_renewed_before_use(tmp_path, configurations):
    script, runs = plugin(tmp_path, "2000-01-01T00:00:00Z")
    path, _ = kubeconfig(tmp_path, script)
    k8s._new_api({"method": "kubeconfig", "kubeconfig": str(path), "context": "selected"})
    assert configurations[-1].get_api_key_with_prefix("authorization") == "Bearer exec-token-2"


def test_failing_exec_plugin_is_named(tmp_path):
    path, _ = kubeconfig(tmp_path, "/bin/false")
    snap = k8s.collect({"provider": "k8s", "auth": {"method": "kubeconfig", "kubeconfig": str(path)},
                        "options": {"inventories": ["pod"]}})
    assert {c["error"]["code"] for c in snap["collections"] if c["type"] == "pod"} == {"kubeconfig_exec_or_file_credentials_unsupported"}


def test_hosted_scan_never_runs_an_exec_plugin(tmp_path):
    script, runs = plugin(tmp_path, "2999-01-01T00:00:00Z")
    _, doc = kubeconfig(tmp_path, script)
    with pytest.raises(ValueError):
        k8s.hosted_auth({"method": "inline", "kubeconfig_data": doc, "context": "selected"})
    with pytest.raises(ValueError):
        k8s.hosted_auth({"method": "kubeconfig", "kubeconfig": str(tmp_path / "config")})
    assert not runs.exists()
