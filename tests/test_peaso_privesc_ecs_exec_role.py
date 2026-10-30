"""ECS Exec reaches only the task role of a ready, authorized container."""
import sys
import types

import pytest

from tests.test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, allow, assert_unresolved, aws_snap, col, reached,
    real, role, role_arn, user,
)


TECHNIQUE = "aws-ecs-executecommand"
CLUSTER = f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/prod"
TASK = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task/prod/abc"
TARGET = role_arn("task")
CHANNELS = ("ssmmessages:CreateControlChannel", "ssmmessages:CreateDataChannel",
            "ssmmessages:OpenControlChannel", "ssmmessages:OpenDataChannel")


def snapshot(*, grant=(CLUSTER, TASK), agent="RUNNING", enabled=True, task_role=TARGET,
             task_status="RUNNING", inventory="collected", channels=CHANNELS, kms_key=None):
    cluster = {"clusterArn": CLUSTER, "status": "ACTIVE",
               "Configuration": {"clusters": [{"clusterArn": CLUSTER, "status": "ACTIVE",
                                               "configuration": {"executeCommandConfiguration": {
                                                   **({"kmsKeyId": kms_key} if kms_key else {})}}}]}}
    task = {"taskArn": TASK, "clusterArn": CLUSTER, "taskRoleArn": task_role,
            "lastStatus": task_status, "enableExecuteCommand": enabled,
            "containers": [{"name": "app", "lastStatus": "RUNNING", "managedAgents": [
                {"name": "ExecuteCommandAgent", "lastStatus": agent}]}]}
    source = user("alice", allow("ecs:ExecuteCommand", resource=list(grant)))
    target = role("task", "ecs-tasks.amazonaws.com", allow(*channels) if channels else allow("s3:ListAllMyBuckets"))
    return aws_snap([source], [target], [col("ecs_cluster", [cluster]),
                                          col("ecs_task", [task] if inventory == "collected" else [], inventory)])


@pytest.fixture(autouse=True)
def avoid_unrelated_check_import(monkeypatch):
    exposure = types.ModuleType("peaso.principal_exposure")
    exposure.annotate_privesc = lambda snapshot, graph, findings, model, inventory=None: None
    monkeypatch.setitem(sys.modules, exposure.__name__, exposure)


def test_exact_running_task_and_two_resource_grants_reach_its_role():
    result = real(snapshot(), TECHNIQUE, include_unknown=True)
    assert reached(result, ALICE, TECHNIQUE) == {TARGET: "conditional"}


@pytest.mark.parametrize("change", (
    {"grant": (CLUSTER,)}, {"grant": (TASK,)}, {"agent": "STOPPED"},
    {"enabled": False}, {"task_role": role_arn("different")},
    {"task_status": "STOPPED"}, {"channels": ()},
))
def test_missing_exact_task_authorization_or_ready_agent_is_not_a_role_edge(change):
    result = real(snapshot(**change), TECHNIQUE, include_unknown=True)
    assert TARGET not in reached(result, ALICE, TECHNIQUE)


def test_missing_task_inventory_is_unresolved():
    result = real(snapshot(inventory="access_denied"), TECHNIQUE, include_unknown=True)
    assert TARGET not in reached(result, ALICE, TECHNIQUE)
    assert_unresolved(result, ALICE, TECHNIQUE)


def test_custom_exec_kms_key_needs_separate_permissions():
    kms_key = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/01234567-89ab-cdef-0123-456789abcdef"
    result = real(snapshot(kms_key=kms_key), TECHNIQUE, include_unknown=True)
    assert TARGET not in reached(result, ALICE, TECHNIQUE)
    assert_unresolved(result, ALICE, TECHNIQUE)


def test_readonly_root_container_is_not_an_exec_route():
    snap = snapshot()
    definition = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/prod:1"
    snap["collections"][-1]["items"][0]["taskDefinitionArn"] = definition
    snap["collections"].append({"type": "ecs_task_definition", "scope": f"{ACCOUNT}/{REGION}",
                                "service": "ecs", "status": "collected", "error": None,
                                "items": [{"taskDefinitionArn": definition, "Definition": {"taskDefinition": {
                                    "taskDefinitionArn": definition, "taskRoleArn": TARGET,
                                    "containerDefinitions": [{"name": "app", "readonlyRootFilesystem": True}]}}}]})
    assert TARGET not in reached(real(snap, TECHNIQUE, include_unknown=True), ALICE, TECHNIQUE)
