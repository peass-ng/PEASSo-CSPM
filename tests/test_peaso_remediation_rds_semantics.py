"""Reviewed RDS guidance follows the exact native route and Backtrack predicates."""
from __future__ import annotations

import json
import inspect
from pathlib import Path
import shlex

import botocore.session
from botocore import xform_name

from peaso.checks import CHECKS
from peaso.remediation import details_for, template


ROOT = Path(__file__).resolve().parents[1]
SHARD = ROOT / "peaso/rulepacks/remediation_aws_families_reviewed.json"
IDS = (
    "aws.cb.rds.instance_no_public_subnet",
    "aws.cb.rds.cluster_backtrack_window_positive",
    "aws.cb.rds.aurora_backtracking_configured",
)


def reviewed():
    return json.loads(SHARD.read_text())




def test_subnet_guidance_distinguishes_nat_from_direct_internet_gateway():
    row = reviewed()[IDS[0]]
    assert "DBSubnetGroup.Subnets" in row["field_binding"]["path"]
    assert "route_table.Routes[*].GatewayId" in row["field_binding"]["path"]
    assert "route_table.Routes[*].NatGatewayId (nonfailing alternate target)" in row["field_binding"]["path"]
    assert "NatGatewayId=nat-*" in " ".join(row["steps"])
    assert "does not fail" in " ".join(row["caveats"])
    assert "0.0.0.0/0" in row["summary"] or "IPv4 default route" in row["summary"]
    assert any("migration" in step.lower() for step in row["steps"])


def test_backtrack_guidance_requires_positive_window_and_supported_scope():
    rows = reviewed()
    for cid in IDS[1:]:
        row = rows[cid]
        binding = row["field_binding"]["path"]
        assert all(field in binding for field in ("DBClusterArn.Region", "EngineVersion", "BacktrackWindow"))
        assert "BacktrackWindow=0" in row["summary"]
        assert "fails this predicate" in " ".join(row["caveats"])
        assert "NOT_APPLICABLE" in " ".join(row["caveats"])
        assert "UNKNOWN" in " ".join(row["caveats"])
        assert any("replacement" in step.lower() or "snapshot-restored" in step.lower() for step in row["steps"])
        assert "do not claim in-place activation" in row["iac"]["code"]


def test_commands_are_inspection_only_and_bind_safe_identity_only():
    rows = reviewed()
    sdk = botocore.session.get_session()
    for cid in IDS:
        for command in rows[cid]["cli"]:
            tokens = shlex.split(command["code"])
            assert tokens[:2] in (["aws", "rds"], ["aws", "ec2"])
            assert tokens[2].startswith("describe-")
            assert command["shell"] == "bash"
            service = sdk.get_service_model(tokens[1])
            operation = next(name for name in service.operation_names if xform_name(name, "-") == tokens[2])
            allowed = {"--" + xform_name(name, "-") for name in service.operation_model(operation).input_shape.members}
            options = {token for token in tokens[3:] if token.startswith("--")}
            assert options - {"--region"} <= allowed
        finding = {"provider": "aws", "check_id": cid, "scope": "111111111111/us-east-1",
                   "resource_name": "db-reviewed"}
        bound = details_for(cid, finding)["cli"]
        assert all("--region us-east-1" in command["code"] for command in bound)
        assert "<RESOURCE_NAME>" not in bound[0]["code"]
        hostile = {**finding, "resource_name": "$(untrusted-command)"}
        assert "<RESOURCE_NAME>" in details_for(cid, hostile)["cli"][0]["code"]
