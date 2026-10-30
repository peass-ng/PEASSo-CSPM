"""GCP/K8s corrected native merges carry a per-row same-requirement verification; failed rows stay rejected."""
import json
from pathlib import Path



PACK = Path(__file__).resolve().parent.parent / "peaso" / "rulepacks"
def manifest():
    return {r["check_id"]: r for r in json.loads((PACK / "upstream_manifest.json").read_text())["checks"]}


def _verified_merge(row):
    v = row.get("native_equivalence_verification")
    return bool(row.get("disposition") == "merged" and row.get("review_classification") == "corrected_native_merge" and v
                and v.get("verdict") == "same_control_requirement" and v.get("target_native_checks") == row["native_checks"] and row["native_checks"]
                and all(v.get(k) for k in ("resource", "property", "pass_condition", "upstream_defect_only", "query_id"))
                and row.get("upstream_defect", {}).get("reason"))


def test_wrong_component_rows_stay_rejected():
    rows = manifest()
    key = "kubernetes-compliance.control.pod_container_argument_kubelet_terminated_pod_gc_threshold_configured"
    assert rows[key]["disposition"] == "rejected" and rows[key]["native_checks"] == [], key


def test_all_ports_row_maps_to_internet_tcp_udp_native():
    row = manifest()["gcp-compliance.control.restrict_firewall_rule_world_open_tcp_udp_all_ports"]
    assert _verified_merge(row) and row["native_checks"] == ["gcp.claude.firewall.public_ingress_tcp_udp"]
    similar = {s["native_check"] for s in row["native_equivalence_verification"]["rejected_similar_natives"]}
    assert {"gcp.compute.restrict_internet_ingress", "gcp.ports.compute_firewall_rule_rdp_access_restricted"} <= similar


def test_repointed_and_resource_trimmed_merges():
    rows = manifest()
    api = rows["prowler.gcp.apikeys_api_restrictions_configured"]
    assert api["native_checks"] == ["gcp.ports.iam_api_key_restricts_apis"]
    assert api["native_equivalence_verification"]["rejected_similar_natives"][0]["native_check"] == "gcp.ports.api_key_meaningful_restrictions"
    for key in ("pod_service_account_token_disabled", "cis_v170_5_1_6", "cis_kube_v120_v100_5_1_6"):
        assert rows["kubernetes-compliance.control." + key]["native_checks"] == ["k8s.pod.restrict_token_automount"]
    assert rows["kubernetes-compliance.control.service_account_token_disabled"]["native_checks"] == ["k8s.serviceaccount.disable_automount"]
