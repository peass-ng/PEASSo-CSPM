"""A metadata search action does not leave a mixed native policy grant unclassified."""
from peaso.analysis.iam import grants


def test_registry_metadata_search_keeps_sensitive_reads_high_and_unknown_actions_unknown():
    def evaluate(actions):
        resource = {"provider": "aws", "type": "iam_policy", "data": {"PolicyVersionList": [
            {"IsDefaultVersion": True, "Document": {"Statement": [{"Effect": "Allow", "Action": actions, "Resource": "resource"}]}}]}}
        grant, = grants(resource)
        return grant
    actual = evaluate(["bedrock-agentcore:searchRegistryRecords", "secretsmanager:GetSecretValue"])
    assert actual["criticality_state"] == "rule_based" and actual["severity"] == "high"
    assert evaluate(["unreviewed-service:UnknownRegistryOperation"])["criticality_state"] == "unknown"
