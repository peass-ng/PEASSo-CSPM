"""Catch duplicate and cross-service exposure evaluators before source admission.

The big exposure union once contained two definitions for several names. Python
silently used the later one, including bodies copied from unrelated services.
This test reads source only, so it also runs when source admission is stale.
"""

import ast
from collections import Counter
from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1] / "peaso/analysis/internet_exposure.py"


def _definitions():
    tree = ast.parse(SOURCE.read_text(), filename=str(SOURCE))
    return [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]


def test_exposure_top_level_definitions_are_unique():
    names = Counter(node.name for node in _definitions())
    duplicates = sorted(name for name, count in names.items() if count > 1)
    assert duplicates == [], f"shadowed exposure source definitions: {duplicates}"


def test_repaired_exposure_functions_keep_service_bounded_source():
    """Small semantic anchors from reviewed service inputs, not full body copies."""
    source = SOURCE.read_text()
    definitions = {node.name: node for node in _definitions()}
    profiles = {
        "_aws_transfer_server": (("ServerId", "EndpointType"), ("BudgetName", "ApiId")),
        "_aws_elbv2": (("Scheme", "DNSName"), ("Notification Topic ARN", "lambda:getlayerversion")),
        "_aws_redshift": (("PubliclyAccessible",), ("BudgetName", "ApiId")),
        "_public_policy": (("Statement", "Principal"), ("StackSetId",)),
        "_opensearch_http_policy": (("es:eshttp", "Statement"), ("BudgetName", "ApiId")),
        "_aws_opensearch": (("DomainEndpointOptions",), ("Beanstalk", "BudgetName")),
        "_aws_lambda_url": (("FunctionUrl",), ("ApiEndpoint", "BudgetName")),
        "_aws_ec2_share": (("ec2_image", "ebs_snapshot"), ("BudgetName", "ApiId")),
        "_aws_sqs_foreign_receive": (("QueueUrl", "Policy"), ("ApiEndpoint", "BudgetName")),
        "_aws_sns_foreign_subscription": (("PendingConfirmation",), ("BudgetName", "ApiId")),
        "_azure_attestation_provider": (("publicNetworkAccess",), ("BudgetName", "ApiId")),
        "_azure_cost_export": (("resourceId",), ("BudgetName", "ApiId")),
        "_azure_managed_application": (("managementMode",), ("BudgetName", "ApiId")),
    }
    for name, (required, foreign) in profiles.items():
        assert name in definitions, f"missing reviewed exposure evaluator: {name}"
        body = ast.get_source_segment(source, definitions[name])
        assert all(token in body for token in required), f"{name} lost its service inputs"
        assert not any(token in body for token in foreign), f"{name} contains foreign service source"
    policy = definitions["_public_policy"]
    assert not any(
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Assessment"
        for node in ast.walk(policy)
    ), "policy parser must not contain a resource evaluator"
