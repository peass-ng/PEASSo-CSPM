import json
from pathlib import Path

from scripts.peaso_deploy_customer_policy import split_policy

ROOT = Path(__file__).resolve().parents[1]


def _sids_unique(document):
    sids = [statement.get("Sid") for statement in document["Statement"] if statement.get("Sid")]
    return len(sids) == len(set(sids))


def test_partitioned_statements_in_one_document_get_distinct_sids():
    policy = {"Version": "2012-10-17", "Statement": [
        {"Sid": "A", "Effect": "Allow", "Action": ["s3:ListBuckets", "s3:GetBucketTagging"], "Resource": "*"},
        {"Sid": "B", "Effect": "Allow", "Action": ["ec2:DescribeA", "ec2:DescribeB"],
         "Resource": "arn:aws:ec2:*:111111111111:client-vpn-endpoint/*"},
    ]}
    documents = split_policy(policy)
    assert len(documents) == 1
    assert len(documents[0]["Statement"]) == 2
    assert _sids_unique(documents[0])
    assert all(sid.isalnum() for sid in (s["Sid"] for s in documents[0]["Statement"]))


def test_published_customer_role_policies_have_unique_sids():
    template = json.loads((ROOT / "infra/aws/customer-role.json").read_text())
    documents = [resource["Properties"]["PolicyDocument"] for resource in template["Resources"].values()
                 if "PolicyDocument" in resource.get("Properties", {})]
    documents += [item["PolicyDocument"] for item in
                  template["Resources"]["AuditRole"]["Properties"].get("Policies", [])]
    assert documents and all(_sids_unique(document) for document in documents)
