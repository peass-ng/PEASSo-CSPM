"""ECS container instance checks apply only to evidenced EC2 capacity and hosts."""
import copy

import pytest

from peaso.checks import CHECKS
from peaso.checks import claude2_aws_b_compute as ecs
from peaso.checks.claude2_aws_b_common import indexes, inventory


CLUSTER_CHECK = "aws.c2b.ecs.cluster_has_registered_instances"
VPC_CHECK = "aws.c2b.ecs.container_instance_in_vpc"
CHECK_BY_ID = {check.id: check for check in CHECKS}


def run(check_id, item, index=None):
    original_item, original_index = copy.deepcopy(item), copy.deepcopy(index or {})
    status, evidence = CHECK_BY_ID[check_id].evaluate(item, index or {})
    assert item == original_item and (index or {}) == original_index
    return status, evidence


def cluster_index(services=(), tasks=(), *, service_status=None, task_status=None):
    return indexes(inventory("ecs_service", list(services), service_status),
                   inventory("ecs_task", list(tasks), task_status))


def service(launch="FARGATE", desired=1, cluster=ecs.CL, **fields):
    row = {"clusterArn": cluster, "desiredCount": desired, **fields}
    if launch is not None:
        row["launchType"] = launch
    return row


def task(launch="FARGATE", status="RUNNING", cluster=ecs.CL, **fields):
    return {"clusterArn": cluster, "launchType": launch, "lastStatus": status, **fields}


def zero_cluster(**fields):
    return ecs._cl(registeredContainerInstancesCount=0, **fields)


def test_positive_registration_count_is_inventory_only():
    status, evidence = run(CLUSTER_CHECK, ecs._cl(registeredContainerInstancesCount=2))
    assert status == "PASS"
    assert evidence["readiness"] == "not established by registration count"


@pytest.mark.parametrize("index", [
    cluster_index(services=[service()]),
    cluster_index(tasks=[task()]),
    cluster_index(services=[service(launch=None, capacityProviderStrategy=[{"capacityProvider": "FARGATE", "weight": 1}])]),
    cluster_index(services=[service(launch=None, capacityProviderStrategy=[])], tasks=[task()]),
])
def test_proven_active_fargate_only_with_zero_registered_instances_is_not_applicable(index):
    cluster = zero_cluster(defaultCapacityProviderStrategy=[{"capacityProvider": "FARGATE_SPOT", "weight": 1}])
    assert run(CLUSTER_CHECK, cluster, index)[0] == "NOT_APPLICABLE"


def test_ec2_service_demand_or_pending_ec2_task_with_zero_instances_is_a_deficit():
    status, evidence = run(CLUSTER_CHECK, zero_cluster(), cluster_index(services=[service("EC2")]))
    assert status == "FAIL" and evidence["ec2_services"] == 1
    status, evidence = run(CLUSTER_CHECK, zero_cluster(), cluster_index(tasks=[task("EC2", "PENDING")]))
    assert status == "FAIL" and evidence["pending_ec2_tasks"] == 1


@pytest.mark.parametrize("index", [
    cluster_index(),
    cluster_index(services=[service("EC2", desired=0)]),
    cluster_index(services=[service(), service(launch=None, capacityProviderStrategy=[{"capacityProvider": "asg-provider", "weight": 1}])]),
    cluster_index(services=[service()], tasks=[task("EC2", "RUNNING")]),
    cluster_index(services=[service()], task_status="denied"),
    cluster_index(services=[service()], service_status="partial"),
])
def test_empty_mixed_inconsistent_or_incomplete_capacity_is_unknown(index):
    assert run(CLUSTER_CHECK, zero_cluster(capacityProviders=["FARGATE", "asg-provider"]), index)[0] == "UNKNOWN"


def test_provider_presence_and_other_cluster_workloads_do_not_prove_this_cluster_demand():
    index = cluster_index(services=[service("EC2", cluster="arn:aws:ecs:us-east-1:222222222222:cluster/c")])
    assert run(CLUSTER_CHECK, zero_cluster(capacityProviders=["asg-provider"]), index)[0] == "UNKNOWN"


@pytest.mark.parametrize("index,expected", [
    (inventory("instance", [ecs._ec2()]), "PASS"),
    (inventory("instance", [ecs._ec2(VpcId=None)]), "UNKNOWN"),
    (inventory("instance", [ecs._ec2(VpcId="vpc-not-hex")]), "UNKNOWN"),
    (inventory("instance", [{"InstanceId": "i-1"}]), "UNKNOWN"),
    (inventory("instance", [], "denied"), "UNKNOWN"),
    (inventory("instance", []), "UNKNOWN"),
])
def test_ec2_host_vpc_must_be_observed_without_treating_missing_as_classic_exposure(index, expected):
    assert run(VPC_CHECK, ecs._ci(), index)[0] == expected


def test_external_ssm_host_is_not_ec2_vpc_check_and_unknown_host_is_unresolved():
    assert run(VPC_CHECK, ecs._ci(ec2InstanceId="mi-0123456789abcdef0"))[0] == "NOT_APPLICABLE"
    assert run(VPC_CHECK, ecs._ci(ec2InstanceId="mi-not-an-id"))[0] == "UNKNOWN"
    assert run(VPC_CHECK, ecs._ci(ec2InstanceId="other-1"))[0] == "UNKNOWN"
    assert run(VPC_CHECK, ecs._ci(ec2InstanceId=None))[0] == "UNKNOWN"
