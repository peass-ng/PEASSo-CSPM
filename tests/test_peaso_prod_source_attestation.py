"""Production Lambdas and ECS tasks run with PEASO_SOURCE_ATTESTATION=trusted.

The deploy contract accepts the trusted lines only as the reviewed exact
successor of the previously pinned Terraform, and expects the variable in
every API and worker environment it verifies.
"""
import hashlib
from pathlib import Path

import pytest

from scripts import peaso_deploy as deploy

INFRA = Path(__file__).resolve().parents[1] / "infra/aws"


def test_terraform_sets_trusted_for_every_runtime():
    for name in ("api.tf", "workflow.tf", "ai_runtime.tf"):
        digest, addition, _ = deploy.SOURCE_ATTESTATION_SUCCESSOR[name]
        raw = (INFRA / name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == digest
        assert raw.count(addition) == 1 and b'"trusted"' in addition


def test_successor_reconstructs_the_reviewed_predecessors():
    current = {name: hashlib.sha256((INFRA / name).read_bytes()).hexdigest()
               for name in deploy.SOURCE_ATTESTATION_SUCCESSOR}
    restored = deploy.source_attestation_predecessors(dict(current, **{"other.tf": "x"}))
    assert restored["other.tf"] == "x"
    assert restored["api.tf"] == deploy.API_DELIVERY_SOURCE["api.tf"][2]
    assert restored["workflow.tf"] == deploy.AI_OFF_WORKFLOW_SHA256
    assert restored["ai_runtime.tf"] == deploy.CAP12_AI_RUNTIME_SHA256
    for name in current:
        assert hashlib.sha256(deploy.runtime_source(name, current)).hexdigest() == restored[name]


def test_a_changed_successor_fails_closed(monkeypatch, tmp_path):
    for name in deploy.SOURCE_ATTESTATION_SUCCESSOR:
        (tmp_path / name).write_bytes((INFRA / name).read_bytes())
    digest, addition, _ = deploy.SOURCE_ATTESTATION_SUCCESSOR["api.tf"]
    (tmp_path / "api.tf").write_bytes((INFRA / "api.tf").read_bytes().replace(addition, addition * 2))
    monkeypatch.setattr(deploy, "INFRA", tmp_path)
    with pytest.raises(RuntimeError, match="Source attestation successor"):
        deploy.source_attestation_predecessors({"api.tf": digest})
