"""GameLift host access reaches only an exact, active, shared-file fleet role."""

from dataclasses import dataclass
import json
from pathlib import Path
import runpy

from peaso.privesc import schema, versioned_catalog
from peaso.privesc.effective_permissions.aws import AwsModel
from peaso.privesc.evaluator import Evaluator
from scripts.peaso_deploy_customer_policy import build_policy
from tests.test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, allow, aws_snap, col, role, role_arn, user,
)


FLEET_ID = "fleet-a1b2c3d4"
FLEET_ARN = f"arn:aws:gamelift:{REGION}::fleet/{FLEET_ID}"
IAM_FLEET_ARN = f"arn:aws:gamelift:{REGION}:{ACCOUNT}:fleet/{FLEET_ID}"
TARGET = role_arn("FleetRole")
TECHNIQUE = "aws-gamelift-getcomputeaccess-shared-fleet-role"
PRECONDITION = "gamelift_existing_shared_fleet_role_shell"


@dataclass
class ReadResult:
    items: list
    status: str = "collected"
    error: dict | None = None


def test_collector_keeps_fleet_role_and_compute_metadata_only():
    module = runpy.run_path(str(Path(__file__).resolve().parents[1] / "peaso/collectors/aws_facts_ext.py"))
    module["_gamelift_ec2_computes"].__globals__["_aws"] = lambda: type("Aws", (), {"ReadResult": ReadResult})

    class Requests:
        def pages(self, _session, service, region, operation, _key, **kwargs):
            assert service == "gamelift" and region == REGION
            if operation == "list_fleets":
                return ReadResult([FLEET_ID])
            if operation == "describe_fleet_attributes":
                assert kwargs == {"FleetIds": [FLEET_ID]}
                return ReadResult([{"FleetId": FLEET_ID, "FleetArn": FLEET_ARN, "ComputeType": "EC2",
                                    "Status": "ACTIVE", "InstanceRoleArn": TARGET,
                                    "InstanceRoleCredentialsProvider": "SHARED_CREDENTIAL_FILE",
                                    "Secret": "must-not-collect"}])
            assert kwargs == {"FleetId": FLEET_ID}
            if operation == "describe_fleet_port_settings":
                return ReadResult([{"FromPort": 7777, "ToPort": 7777, "IpRange": "0.0.0.0/0", "Protocol": "UDP",
                                    "Secret": "must-not-collect"}])
            assert operation == "list_compute"
            return ReadResult([{"FleetId": FLEET_ID, "ComputeName": "i-123", "ComputeStatus": "Active",
                                "Secret": "must-not-collect"}])

    result = module["_gamelift_ec2_computes"](Requests(), object(), REGION, ACCOUNT)
    assert result.status == "collected"
    assert result.items[0]["InstanceRoleArn"] == TARGET
    assert result.items[0]["Computes"]["items"][0]["ComputeName"] == "i-123"
    assert result.items[0]["InboundPermissions"]["items"] == [{"FromPort": 7777, "ToPort": 7777, "IpRange": "0.0.0.0/0", "Protocol": "UDP"}]
    assert "Secret" not in str(result.items)


def test_collector_skips_container_fleets_and_accepts_accountful_ec2_arn():
    module = runpy.run_path(str(Path(__file__).resolve().parents[1] / "peaso/collectors/aws_facts_ext.py"))
    module["_gamelift_ec2_computes"].__globals__["_aws"] = lambda: type("Aws", (), {"ReadResult": ReadResult})

    class Requests:
        def pages(self, _session, _service, _region, operation, _key, **kwargs):
            if operation == "list_fleets":
                return ReadResult(["containerfleet-other", FLEET_ID])
            assert "containerfleet" not in str(kwargs)
            if operation == "describe_fleet_attributes":
                return ReadResult([{"FleetId": FLEET_ID, "FleetArn": IAM_FLEET_ARN,
                                    "ComputeType": "EC2", "Status": "ACTIVE"}])
            return ReadResult([{"FleetId": FLEET_ID, "FleetArn": IAM_FLEET_ARN,
                                "ComputeName": "i-123", "ComputeStatus": "ACTIVE"}])

    result = module["_gamelift_ec2_computes"](Requests(), object(), REGION, ACCOUNT)
    assert result.status == "collected" and [row["FleetArn"] for row in result.items] == [IAM_FLEET_ARN]


def _model(*, grant=IAM_FLEET_ARN, provider="SHARED_CREDENTIAL_FILE", compute_status="Active",
           fleet_status="ACTIVE", collection_status="collected"):
    fleet = {"FleetId": FLEET_ID, "FleetArn": FLEET_ARN, "ComputeType": "EC2",
             "Status": fleet_status, "InstanceRoleArn": TARGET,
             "InstanceRoleCredentialsProvider": provider,
             "Computes": {"collection_status": collection_status,
                          "items": [{"FleetId": FLEET_ID, "ComputeName": "i-123",
                                     "ComputeStatus": compute_status}]}}
    snap = aws_snap([user("alice", allow("gamelift:GetComputeAccess", resource=grant))],
                    [role("FleetRole", "gamelift.amazonaws.com")],
                    [col("gamelift_ec2_compute", [fleet])])
    return AwsModel(snap)


def _verdict(model):
    return model.precondition(PRECONDITION, {TARGET: model.principals[TARGET]}, model.principals[ALICE]).get(TARGET)


def test_exact_fleet_grant_and_shared_credentials_reach_role():
    model = _model()
    assert _verdict(model) == ("conditional", "gamelift_active_ec2_shared_role_shell")
    entry = next(x for x in schema.load_catalog(schema.CATALOG_DIR)["entries"] if x["id"] == TECHNIQUE)
    assert {target for edge in Evaluator(model, [entry], include_unknown=False).run()
            if edge.source.id == ALICE for target in edge.targets} == {TARGET}


def test_other_fleet_default_provider_or_inactive_compute_do_not_reach_role():
    entry = next(x for x in schema.load_catalog(schema.CATALOG_DIR)["entries"] if x["id"] == TECHNIQUE)
    for model in (_model(grant=IAM_FLEET_ARN + "-other"), _model(provider=None),
                  _model(compute_status="IMPAIRED"), _model(fleet_status="TERMINATING")):
        assert _verdict(model) is None
        assert not [edge for edge in Evaluator(model, [entry], include_unknown=False).run()
                    if edge.source.id == ALICE and TARGET in edge.targets]


def test_incomplete_compute_read_stays_unresolved():
    assert _verdict(_model(collection_status="access_denied"))[0] == "unknown"


def test_previous_catalog_binding_retains_exact_688_entries():
    current = versioned_catalog.current_binding()
    entries, state = versioned_catalog.lookup_entries([TECHNIQUE], current)
    assert state == "exact_strict_privesc" and entries[TECHNIQUE]["preconditions"] == [PRECONDITION]
    old = dict(current, manifest_sha256=versioned_catalog.GAMELIFT_SHARED_688_PREVIOUS_MANIFEST,
               effective_tree_sha256=versioned_catalog.GAMELIFT_SHARED_688_PREVIOUS_TREE)
    entries, state = versioned_catalog.lookup_entries([TECHNIQUE], old)
    assert state == "exact_previous_current" and TECHNIQUE not in entries


def test_customer_setup_policy_includes_all_game_lift_inventory_reads():
    operations = {("gamelift", operation) for operation in
                  ("list_fleets", "describe_fleet_attributes", "list_compute")}
    required = {"gamelift:ListFleets", "gamelift:DescribeFleetAttributes", "gamelift:ListCompute"}
    generated = build_policy(operations, include_credential_report_generation=False)
    assert required <= set(generated["Statement"][0]["Action"])
    template = json.loads((Path(__file__).resolve().parents[1] / "infra/aws/customer-role.json").read_text())
    static = {action for resource in template["Resources"].values()
              if resource.get("Type") == "AWS::IAM::ManagedPolicy"
              for statement in resource["Properties"]["PolicyDocument"]["Statement"]
              for action in ([statement["Action"]] if isinstance(statement["Action"], str) else statement["Action"])}
    assert required <= static


def _new_fleet_model(*, build_region=REGION, fleet_region=REGION,
                     pass_service="gamelift.amazonaws.com", create_build=True,
                     create_fleet=True, container_only=False,
                     build_resource="*", fleet_resource="*"):
    statements = []
    if create_build:
        statements.append({**allow("gamelift:CreateBuild", resource=build_resource),
                           "Condition": {"StringEquals": {"aws:RequestedRegion": build_region}}})
    if create_fleet:
        action = "gamelift:CreateContainerFleet" if container_only else "gamelift:CreateFleet"
        statements.append({**allow(action, resource=fleet_resource),
                           "Condition": {"StringEquals": {"aws:RequestedRegion": fleet_region}}})
    statements.append({**allow("iam:PassRole", resource=TARGET),
                       "Condition": {"StringEquals": {"iam:PassedToService": pass_service}}})
    return AwsModel(aws_snap([user("alice", *statements)], [role("FleetRole", "gamelift.amazonaws.com")]))


def test_new_fleet_route_binds_build_fleet_and_passrole_in_one_region():
    model = _new_fleet_model()
    entry = next(x for x in schema.load_catalog(schema.CATALOG_DIR)["entries"]
                 if x["id"] == "aws-gamelift-passrole-createfleet")
    assert model.precondition("gamelift_new_controlled_build_fleet_role",
                              {TARGET: model.principals[TARGET]}, model.principals[ALICE]) == {
                                  TARGET: ("conditional", "gamelift_new_build_uploaded_to_new_ec2_fleet")}
    assert {target for edge in Evaluator(model, [entry], include_unknown=False).run()
            if edge.source.id == ALICE for target in edge.targets} == {TARGET}


def test_new_fleet_route_does_not_mix_regions_or_passrole_service():
    entry = next(x for x in schema.load_catalog(schema.CATALOG_DIR)["entries"]
                 if x["id"] == "aws-gamelift-passrole-createfleet")
    for model in (_new_fleet_model(build_region="eu-west-1"),
                  _new_fleet_model(pass_service="ec2.amazonaws.com"),
                  _new_fleet_model(create_build=False)):
        assert not [edge for edge in Evaluator(model, [entry], include_unknown=False).run()
                    if edge.source.id == ALICE and TARGET in edge.targets]
    container = _new_fleet_model(container_only=True)
    assert container.precondition("gamelift_new_controlled_build_fleet_role",
                                  {TARGET: container.principals[TARGET]}, container.principals[ALICE])[TARGET][0] == "unknown"


def test_new_fleet_global_create_actions_reject_scoped_resource_grants():
    entry = next(x for x in schema.load_catalog(schema.CATALOG_DIR)["entries"]
                 if x["id"] == "aws-gamelift-passrole-createfleet")
    for model in (_new_fleet_model(build_resource=f"arn:aws:gamelift:{REGION}:{ACCOUNT}:build/build-1"),
                  _new_fleet_model(fleet_resource=f"arn:aws:gamelift:{REGION}:{ACCOUNT}:fleet/fleet-1")):
        assert not [edge for edge in Evaluator(model, [entry], include_unknown=False).run()
                    if edge.source.id == ALICE and TARGET in edge.targets]


def test_previous_game_lift_fleet_catalog_binding_keeps_original_meaning():
    current = versioned_catalog.current_binding()
    old = dict(current, manifest_sha256=versioned_catalog.GAMELIFT_SHELL_689_PREVIOUS_MANIFEST,
               effective_tree_sha256=versioned_catalog.GAMELIFT_SHELL_689_PREVIOUS_TREE)
    entries, state = versioned_catalog.lookup_entries(["aws-gamelift-passrole-createfleet"], old)
    assert state == "exact_previous_current"
    assert not entries["aws-gamelift-passrole-createfleet"].get("preconditions")
