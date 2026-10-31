"""A webhook served on the node's loopback or a private address is not a third-party receiver."""
import pytest

from peaso.engine import evaluate_snapshot
from tests.test_peaso_analysis_internet_exposure import CHECK, coll, k8s


def webhook(url):
    return {"metadata": {"name": "managed"}, "webhooks": [{"name": "w.example", "clientConfig": {"url": url}}]}


@pytest.mark.parametrize("url", ["https://localhost:5443/validate", "https://127.0.0.1:9443/x",
                                 "https://[::1]:443/x", "https://10.0.0.5/x"])
def test_local_webhook_is_not_reported_as_external_receiver(url):
    report = evaluate_snapshot(k8s(coll("admission_configuration", [webhook(url)], scope="cluster")), checks=[CHECK])
    assert not [f for f in report["findings"] if f["check_id"] == CHECK
                and f["evidence"].get("exposure_kind") == "third_party_data"]


def test_unresolved_exposure_unknown_names_the_open_layer():
    report = evaluate_snapshot(k8s(coll("admission_configuration", [webhook("https://hooks.example.com/x")], scope="cluster")), checks=[CHECK])
    found = [f for f in report["findings"] if f["check_id"] == CHECK and f["status"] == "UNKNOWN"
             and f["evidence"].get("exposure_kind") == "third_party_data"]
    assert found and all(f["evidence"]["reason"].startswith("unresolved_layers: backend") for f in found)
