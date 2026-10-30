"""Real-source contracts for the thirty reviewed customer-facing copy changes."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from peaso.checks import CHECK_ALIASES, CHECKS
from peaso.checks.finding_clarity_reviewed import ROWS, _digest, description, remediation

PACK = Path(__file__).resolve().parents[1] / "peaso/rulepacks"


@pytest.fixture(scope="module")
def source_rows():
    descriptions = json.loads((PACK / "check_descriptions.json").read_text())["checks"]
    remediations = {}
    for path in PACK.glob("remediation*.json"):
        packed = json.loads(path.read_text())
        if not isinstance(packed, dict):
            continue
        for check_id, row in packed.items():
            if check_id in ROWS and isinstance(row, dict):
                if _digest(row) == ROWS[check_id]["remediation_base_sha256"]:
                    remediations[check_id] = row
    return descriptions, remediations


def test_reviewed_ids_are_exactly_thirty_registered_checks():
    assert len(ROWS) == 30
    registered = {check.id for check in CHECKS}
    # fe6f7901 (#104) retired this exact overlapping id as an alias of its
    # surviving native; its reviewed copy row is kept as history.
    retired = {"aws.c2b.elasticache.cluster_public_subnet": "aws.c2b.elasticache.cluster_public_subnet_prowler"}
    assert set(ROWS) - registered == set(retired)
    assert all(CHECK_ALIASES[old] == new and new in registered for old, new in retired.items())


@pytest.mark.parametrize("check_id", sorted(ROWS))
def test_description_preserves_actual_evaluation_contract(check_id, source_rows):
    original = source_rows[0][check_id]
    before = deepcopy(original)
    actual = description(check_id, original)
    assert original == before
    assert actual["description"] == ROWS[check_id]["description_fields"]["description"]
    assert len(actual["description"].split()) <= 40
    assert {k: v for k, v in actual.items() if k != "description"} == {
        k: v for k, v in original.items() if k != "description"}


@pytest.mark.parametrize("check_id", sorted(ROWS))
def test_remediation_preserves_references_commands_and_bindings(check_id, source_rows):
    original = source_rows[1][check_id]
    before = deepcopy(original)
    actual = remediation(check_id, original)
    assert original == before
    assert 1 <= len(actual["steps"]) <= 2
    expected_caveats = {"aws.cb.kafka.latest_version": 2,
                        "aws.cb.rds.instance_iam_auth_all_engines": 3}
    assert len(actual["caveats"]) == expected_caveats.get(check_id, 1)
    cautions = " ".join(actual["caveats"])
    if check_id == "aws.cb.kafka.latest_version":
        assert all(clause in cautions for clause in (
            "fresh DescribeClusterV2 Version concurrency token", "client compatibility",
            "broker availability", "maintenance timing", "rollback"))
    if check_id == "aws.cb.rds.instance_iam_auth_all_engines":
        assert all(clause in cautions for clause in (
            "capability evidence is UNKNOWN", "do not change clustered instances",
            "RDS on Outposts", "database users, TLS, token refresh and connection pooling",
            "maintenance window", "immediate application is separately reviewed"))
    assert len(actual["summary"].split()) <= 40
    changed = {"summary", "steps", "caveats"}
    assert {k: v for k, v in actual.items() if k not in changed} == {
        k: v for k, v in original.items() if k not in changed}


@pytest.mark.parametrize("check_id", sorted(ROWS))
@pytest.mark.parametrize("kind, apply", [("description", description), ("remediation", remediation)])
def test_stale_source_fails_closed(check_id, kind, apply, source_rows):
    original = deepcopy(source_rows[0 if kind == "description" else 1][check_id])
    original["description" if kind == "description" else "summary"] = "Unreviewed source changed."
    with pytest.raises(ValueError, match="Reviewed finding clarity base changed"):
        apply(check_id, original)


def test_unowned_check_is_preserved_without_sharing_mutable_state():
    original = {"description": "Keep this exact text.", "evaluated": ["specific.field"]}
    actual = description("unowned.check", original)
    assert actual == original
    actual["evaluated"].append("different")
    assert original["evaluated"] == ["specific.field"]
    assert description("unowned.check", None) is None


def test_semantic_exceptions_are_explicit_in_customer_copy(source_rows):
    def result(cid):
        return remediation(cid, source_rows[1][cid])
    assert "does not establish" in result("aws.c2b.elbv2.listeners_secure_protocol")["caveats"][0]
    assert "pass-through" in result("aws.c2b.elbv2.listeners_secure_protocol")["caveats"][0]
    assert "does not prove plaintext" in result("aws.c2b.elasticache.cmk_enabled")["caveats"][0]
    assert "External identity" in result("aws.c2b.es.internal_user_database_enabled")["caveats"][0]
    assert "OUTGOING" in result("gcp.ports.sql_private_ip_assignments")["caveats"][0]
    assert "ROTATE" in result("aws.c2b.elasticache.redis_auth_pre6")["caveats"][0]
