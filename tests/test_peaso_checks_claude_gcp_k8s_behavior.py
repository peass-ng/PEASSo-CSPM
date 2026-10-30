"""Behavior fixtures for the claude_gcp_k8s compute, IAM and Kubernetes predicates."""
import copy
import json
from pathlib import Path

import pytest

import peaso.checks.claude_gcp_k8s  # noqa: F401
from peaso.checks import CHECKS
from peaso.checks.claude_gcp_k8s_common import container, fw, gid, kid, pod_case
from peaso.checks.claude_gcp_k8s_compute import COMPUTE_IDS
from peaso.checks.claude_gcp_k8s_iam import IAM_IDS
from peaso.checks.claude_gcp_k8s_k8s import K8S_IDS, RULE
from peaso.checks.fixtures import CASES

REGISTRY = {check.id: check for check in CHECKS}
GROUP = sorted(COMPUTE_IDS + IAM_IDS + K8S_IDS)
# Native activity checks whose dependency proof is bound to the identity item.
RESOURCE_BOUND = {'gcp.claude.service_account.recently_used', 'gcp.claude.service_account_key.recently_used'}


def run(check_id, item, index=None):
    data, scoped = copy.deepcopy(item), copy.deepcopy(index or {})
    status = REGISTRY[check_id].evaluate(data, scoped)[0]
    assert data == item and scoped == (index or {}), "evaluators must not mutate facts"
    return status


def test_groups_registered_and_disjoint():
    assert len(GROUP) == len(set(GROUP)) == 209
    assert all(c.startswith(("gcp.claude.", "k8s.claude.")) for c in GROUP)


@pytest.mark.parametrize("check_id", GROUP)
def test_documented_outcomes(check_id, monkeypatch):
    from tests.aws_k8s_current_native_inputs_20261020 import annotation_current_cases
    cases = annotation_current_cases(check_id, CASES[check_id])
    if check_id in {'gcp.claude.bigquery_dataset.no_gmail_access', 'gcp.claude.bigquery_dataset.no_googlegroups_access'}:
        # Historical fail rows contain non-mailbox text and remain UNKNOWN.
        # Replay already-reviewed real native mailbox observations separately.
        current = json.loads((Path(__file__).parent/'fixtures/gcp-prior-bounded-native-successor-20261020.json').read_text())
        rows = [row for row in current['cases'] if row['check_id'] == check_id]
        assert {row['expected_status'] for row in rows} == {'PASS', 'FAIL', 'UNKNOWN'}
        cases = copy.deepcopy(cases)
        for row in rows:
            branch = row['expected_status'].lower()
            cases[branch] = copy.deepcopy(row['item'])
            cases[branch + '_index'] = copy.deepcopy(row['index'])
    if check_id == 'gcp.claude.firewall.default_rules_not_open':
        # 45112721 binds default-named rules to the evaluated project's default VPC.
        # The reviewed successor supplies the projects/p scope those items declare.
        from tests.generic_k8s_behavior_successors_20261020 import current_cases
        cases = current_cases(REGISTRY[check_id], cases)
    if "index" in cases:
        # 120406f2 native cases keep a generic index only for the missing item;
        # every evaluated state still carries its own <case>_index.
        assert check_id in RESOURCE_BOUND, "scope fixtures must use <case>_index"
        assert all(name + "_index" in cases for name in ("pass", "fail", "unknown", "not_applicable", "manual")
                   if name in cases), "scope fixtures must use <case>_index"
    for name, expected in (("pass", "PASS"), ("fail", "FAIL"), ("manual", "MANUAL"), ("unknown", "UNKNOWN"),
                           ("not_applicable", "NOT_APPLICABLE")):
        if name in cases:
            index = cases.get(name + "_index", cases.get("pass_index"))
            from peaso.checks import k8s_annotation_indicators_review_20261020 as annotation
            if name == 'not_applicable' and check_id in annotation.PSP_IDS:
                assert run(check_id, cases[name], index) == 'UNKNOWN'
                from tests.aws_k8s_current_native_inputs_20261020 import assert_modern_psp_native_applicability
                assert_modern_psp_native_applicability(check_id, monkeypatch)
            else:
                assert run(check_id, cases[name], index) == expected, name
    for name in ("missing", "malformed"):
        if name in cases:
            assert run(check_id, cases[name], cases.get("index", cases.get("pass_index"))) == "UNKNOWN", name
    for unknown in ({}, None, [], {"collection_status": "denied"}, {"_provenance": {"x": 1}}):
        assert REGISTRY[check_id].evaluate(unknown, {})[0] == "UNKNOWN"


@pytest.mark.parametrize("check_id", [c for c in GROUP if "pass_index" in CASES[c] and "pass" in CASES[c]])
def test_uncollected_dependency_is_unknown(check_id):
    cases = CASES[check_id]
    if check_id in RESOURCE_BOUND:
        # 120406f2 binds activity to the identity's own _coverage and request
        # references; a resource-only evaluation needs no scope index. An
        # uncollected activity read is the dependency and must not pass.
        item = copy.deepcopy(cases["pass"])
        item["_coverage"]["_activity"]["status"] = "denied"
        assert run(check_id, item, {}) == "DENIED"
        assert run(check_id, item, cases["pass_index"]) == "DENIED"
        del item["_coverage"]["_activity"]
        assert run(check_id, item, cases["pass_index"]) == "UNKNOWN"
        # Its pass_index only shares the insight inventory, which is not a dependency.
        assert set(cases["pass_index"].get("collections", {})).isdisjoint(REGISTRY[check_id].dependencies)
        return
    assert run(check_id, cases["pass"], {}) == "UNKNOWN"
    partial = copy.deepcopy(cases["pass_index"])
    if partial.get("collections"):
        for envelopes in partial["collections"].values():
            envelopes[0]["status"] = "denied"
        assert run(check_id, cases["pass"], partial) == "UNKNOWN"


# --- GCP firewall semantics ---------------------------------------------------------------------------------

def test_firewall_port_ranges_protocols_and_sources():
    mysql = gid("firewall.public_ingress_mysql_db_port_3306")
    assert run(mysql, fw(["0.0.0.0/0"], [{"IPProtocol": "tcp", "ports": ["3000-4000"]}])) == "FAIL"
    assert run(mysql, fw(["0.0.0.0/0"], [{"IPProtocol": "all"}])) == "FAIL"
    assert run(mysql, fw(["0.0.0.0/0"], [{"IPProtocol": "6"}])) == "FAIL"
    assert run(mysql, fw(["10.0.0.0/8"], [{"IPProtocol": "tcp", "ports": ["3306"]}])) == "PASS"
    assert run(mysql, fw(["0.0.0.0/0"], [{"IPProtocol": "udp", "ports": ["3306"]}])) == "FAIL"  # upstream covers tcp and udp
    assert run(mysql, fw(["0.0.0.0/0"], [{"IPProtocol": "icmp"}])) == "PASS"
    tcp_only = gid("firewall.public_ingress_tcp_port_9090")
    assert run(tcp_only, fw(["::/0"], [{"IPProtocol": "tcp", "ports": ["9090"]}])) == "FAIL"
    assert run(tcp_only, fw(["0.0.0.0/0"], [{"IPProtocol": "udp", "ports": ["9090"]}])) == "PASS"
    # Omitted sourceRanges default to 0.0.0.0/0 only when no source tags or service accounts are declared.
    assert run(mysql, fw(None, [{"IPProtocol": "tcp", "ports": ["3306"]}])) == "FAIL"
    assert run(mysql, fw(None, [{"IPProtocol": "tcp", "ports": ["3306"]}], sourceTags=["web"])) == "PASS"
    assert run(mysql, fw(["0.0.0.0/0"], [{"IPProtocol": "tcp", "ports": ["3306"]}], disabled=True)) == "NOT_APPLICABLE"
    assert run(mysql, fw(["0.0.0.0/0"], [{"IPProtocol": "tcp", "ports": ["3306"]}], direction="EGRESS")) == "NOT_APPLICABLE"
    assert run(mysql, fw(["0.0.0.0/0"], [{"IPProtocol": "tcp", "ports": ["abc"]}])) == "UNKNOWN"


# --- Kubernetes semantics -----------------------------------------------------------------------------------

def test_rbac_wildcards_and_api_groups():
    bind = kid("clusterrole.no_bind")
    assert run(bind, RULE(["rbac.authorization.k8s.io"], ["clusterroles"], ["bind"])) == "FAIL"
    assert run(bind, RULE(["*"], ["*"], ["*"])) == "FAIL"
    assert run(bind, RULE([""], ["clusterroles"], ["bind"])) == "PASS"
    secrets = kid("role.no_secret_read")
    assert run(secrets, RULE([""], ["secrets"], ["list"])) == "FAIL"
    assert run(secrets, RULE([""], ["secret"], ["list"])) == "PASS"
    assert run(secrets, RULE(["apps"], ["secrets"], ["get"])) == "PASS"


def test_probes_ignore_init_containers():
    probe = kid("pod.liveness_probe_configured")
    ready = container("app", livenessProbe={"httpGet": {"path": "/", "port": 8080}})
    item = pod_case(ready, initContainers=[container("init")])
    assert run(probe, item) == "PASS"
    assert run(probe, pod_case(ready, container("sidecar"))) == "FAIL"


def test_no_human_bindings_skip_reserved_system_subjects():
    """GKE live QA: system:masters / system:kube-controller-manager / system:gke-* are control-plane identities."""
    cid = kid("clusterrolebinding.no_human_serviceaccount_token_create")
    index = CASES[cid]["fail_index"]
    def binding(*subjects):
        return {"metadata": {"name": "b"}, "roleRef": {"kind": "ClusterRole", "name": "r"}, "subjects": list(subjects)}
    for name, kind in (("system:masters", "Group"), ("system:kube-controller-manager", "User"), ("system:gke-common-webhooks", "User")):
        assert run(cid, binding({"kind": kind, "name": name}), index) == "NOT_APPLICABLE", name
    for name, kind in (("system:authenticated", "Group"), ("system:serviceaccounts", "Group"), ("system:serviceaccounts:apps", "Group"),
                       ("system:serviceaccount:apps:ci", "User"), ("alice@example.com", "User")):
        assert run(cid, binding({"kind": kind, "name": name}), index) == "FAIL", name
    assert run(cid, binding({"kind": "Group", "name": "system:masters"}, {"kind": "User", "name": "bob"}), index) == "FAIL"
