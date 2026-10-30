"""Runtime guard for the distinct exposure handlers joined in the big wave."""


from peaso.analysis.internet_exposure import assess


def _resource(kind, data, scope="111122223333/us-east-1"):
    return {"id": kind, "type": kind, "scope": scope, "data": data}


def test_assess_accepts_related_snapshots_for_every_provider():
    for provider in ("aws", "gcp", "azure", "k8s"):
        assert assess({"provider": provider}, [], related_snapshots=()) == []


def test_aws_ram_and_lambda_layer_keep_distinct_assessments():
    account = "111122223333"
    region = "us-east-1"
    share = _resource("ram_resource_share", {
        "resourceShareArn": f"arn:aws:ram:{region}:{account}:resource-share/share-1",
        "status": "ACTIVE",
        "ResourceAssociations": {"collection_status": "collected", "resourceShareAssociations": [{
            "associatedEntity": f"arn:aws:ec2:{region}:{account}:subnet/subnet-1", "status": "ASSOCIATED"}]},
        "PrincipalAssociations": {"collection_status": "collected", "resourceShareAssociations": [{
            "associatedEntity": "999988887777", "status": "ASSOCIATED", "external": True}]},
    })
    layer = _resource("lambda_layer_version", {
        "LayerName": "shared", "Version": 1,
        "LayerArn": f"arn:aws:lambda:{region}:{account}:layer:shared",
        "LayerVersionArn": f"arn:aws:lambda:{region}:{account}:layer:shared:1",
        "Policy": {"collection_status": "collected", "Policy": {
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": "999988887777"},
                           "Action": "lambda:GetLayerVersion",
                           "Resource": f"arn:aws:lambda:{region}:{account}:layer:shared:1"}]}}
    })
    result = assess({"provider": "aws"}, [share, layer])
    assert {(a.resource["type"], a.kind, a.verdict()) for a in result} == {
        ("ram_resource_share", "external_share", "FAIL"),
        ("lambda_layer_version", "external_layer_share", "FAIL"),
    }


def test_aws_backup_plan_and_vault_retain_both_distinct_paths():
    account = "111122223333"
    region = "us-east-1"
    plan = _resource("backup_plan", {"BackupPlanId": "p",
        "BackupPlanArn": f"arn:aws:backup:{region}:{account}:plan:p"})
    vault = _resource("backup_vault", {"BackupVaultName": "vv",
        "BackupVaultArn": f"arn:aws:backup:{region}:{account}:backup-vault:vv",
        "VaultType": "LOGICALLY_AIR_GAPPED_BACKUP_VAULT"})
    result = assess({"provider": "aws"}, [plan, vault])
    assert {(a.resource["type"], a.kind) for a in result} == {
        ("backup_plan", "external_share"),
        ("backup_plan", "external_backup_copy_plan"),
        ("backup_vault", "external_share"),
        ("backup_vault", "external_generic_policy_grant"),
    }


def test_cloudformation_stack_instance_and_gcp_kafka_dispatch():
    aws_result = assess({"provider": "aws"}, [_resource("cloudformation_stack_instance", {})])
    gcp_result = assess({"provider": "gcp"}, [_resource("managed_kafka_cluster", {}, "p/us-central1")])
    assert all(row.resource["type"] == "cloudformation_stack_instance" for row in aws_result)
    assert all(row.resource["type"] == "managed_kafka_cluster" for row in gcp_result)
