"""Aurora endpoint inventory is a bounded read-only metadata projection."""
import jmespath
import json
from pathlib import Path

from peaso.collectors import aws
from scripts.peaso_deploy_customer_policy import build_policy, policy_size


def test_rds_cluster_endpoint_collection_is_read_only_paginated_and_projected():
    service, operation, expression = aws.SPECS["rds_cluster_endpoint"]
    assert (service, operation) == ("rds", "describe_db_cluster_endpoints")
    assert (service, operation) in aws.READ_ACTIONS
    assert aws._NATIVE_IDS["rds_cluster_endpoint"] == "DBClusterEndpointIdentifier"
    page = {"DBClusterEndpoints": [{"DBClusterEndpointIdentifier": "cluster-ro",
              "DBClusterIdentifier": "cluster", "Endpoint": "cluster-ro.example.amazonaws.com",
              "EndpointType": "READER", "Status": "available", "StaticMembers": [],
              "ExcludedMembers": [], "UnrelatedCredential": "inert-secret"}], "Marker": "next-page"}
    projected = jmespath.search(expression, page)
    assert projected[0]["Endpoint"] == "cluster-ro.example.amazonaws.com"
    assert projected[0]["StaticMembers"] == []
    assert "UnrelatedCredential" not in projected[0]
    assert page["Marker"] == "next-page"


def test_rds_cluster_endpoint_customer_role_has_reviewed_read_action():
    action = "rds:DescribeDBClusterEndpoints"
    assert action in json.dumps(build_policy({("rds", "describe_db_cluster_endpoints")}))
    template = json.loads((Path(__file__).resolve().parents[1] / "infra/aws/customer-role.json").read_text())
    policies = [row["Properties"]["PolicyDocument"] for row in template["Resources"].values()
                if row.get("Type") == "AWS::IAM::ManagedPolicy"]
    assert any(action in statement.get("Action", []) for policy in policies for statement in policy["Statement"])
    assert policy_size(policies[0]) <= 6144
