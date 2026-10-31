"""Kubelet firewall checks keep resolving under their retired upstream-derived ids."""
import pytest

from peaso.checks import evaluate_check
from peaso.engine import _selection

RENAMED = {
    "gcp.claude.firewall.public_ingress_postgresql_port_10250": ("gcp.claude.firewall.public_ingress_kubelet_port_10250", "10250"),
    "gcp.claude.firewall.public_ingress_postgresql_port_10255":
        ("gcp.claude.firewall.public_ingress_kubelet_read_only_port_10255", "10255"),
}


def rule(sources, port):
    return {"name": "kubelet", "direction": "INGRESS", "sourceRanges": sources, "allowed": [{"IPProtocol": "tcp", "ports": [port]}]}


@pytest.mark.parametrize("retired", sorted(RENAMED))
def test_world_open_kubelet_port_fails_under_current_and_retired_id(retired):
    current, port = RENAMED[retired]
    for cid in (current, retired):
        assert evaluate_check(cid, rule(["0.0.0.0/0"], port), {})[0] == "FAIL"
        assert evaluate_check(cid, rule(["10.0.0.0/8"], port), {})[0] == "PASS"


def test_selecting_retired_id_runs_the_current_check_once():
    _, selected = _selection("gcp", None, [*RENAMED, *(current for current, _ in RENAMED.values())], None)
    assert sorted(c.id for c in selected) == sorted(current for current, _ in RENAMED.values())
