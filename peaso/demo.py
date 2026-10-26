"""Small deterministic native snapshots for offline CLI review; no cloud credentials."""
from .snapshot import make_snapshot


def demo_snapshot(provider):
    # Canonical native scopes: the worker's public snapshot adapter rejects anything else.
    scope = {"aws": "111111111111/us-east-1", "gcp": "projects/demo-project", "azure": "/subscriptions/demo-subscription", "k8s": "*"}[provider]
    facts = {
      "aws": {
        "iam_policy": [{"Arn": "arn:aws:iam::111111111111:policy/ReviewedRead", "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": "arn:aws:s3:::demo-private"}]}},
                       {"Arn": "arn:aws:iam::111111111111:policy/Overbroad", "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}],
        "iam_role": [{"Arn": "arn:aws:iam::111111111111:role/Demo", "RoleName": "Demo", "AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}, "AttachedManagedPolicies": [{"PolicyArn": "arn:aws:iam::111111111111:policy/Overbroad"}]}],
        "vpc": [{"VpcId": "vpc-demo", "CidrBlock": "10.0.0.0/16"}],
        "subnet": [{"SubnetId": "subnet-demo", "VpcId": "vpc-demo", "CidrBlock": "10.0.1.0/24"}],
        "security_group": [{"GroupId": "sg-private", "VpcId": "vpc-demo", "IpPermissions": []}, {"GroupId": "sg-public", "VpcId": "vpc-demo", "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}],
        "instance": [{"InstanceId": "i-demo", "VpcId": "vpc-demo", "SubnetId": "subnet-demo", "SecurityGroups": [{"GroupId": "sg-public"}], "MetadataOptions": {"HttpEndpoint": "enabled", "HttpTokens": "required"}}],
        "route_table": [],
        "bucket": [{"Name": "demo-private", "PublicAccessBlock": {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}, "Encryption": {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}},
                   {"Name": "demo-unreviewed", "PublicAccessBlock": {"absent": True}, "Encryption": {"collection_status": "denied", "error": {"code": "AccessDenied"}}}],
      },
      "gcp": {
        "iam_policy": [{"name": "demo-project", "bindings": [{"role": "roles/viewer", "members": ["user:auditor@example.test"]}, {"role": "roles/editor", "members": ["serviceAccount:demo@demo-project.iam.gserviceaccount.com"]}]}],
        "network": [{"name": "demo-network", "selfLink": "https://www.googleapis.com/compute/v1/projects/demo-project/global/networks/demo-network"}],
        "subnetwork": [{"name": "demo-subnet", "network": "https://www.googleapis.com/compute/v1/projects/demo-project/global/networks/demo-network", "ipCidrRange": "10.1.0.0/24"}],
        "firewall": [{"name": "private-rule", "network": "https://www.googleapis.com/compute/v1/projects/demo-project/global/networks/demo-network", "direction": "INGRESS", "sourceRanges": ["10.1.0.0/24"], "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}]}],
        "bucket": [{"name": "demo-bucket", "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}, "publicAccessPrevention": "inherited"}}],
        "instance": []
      },
      "azure": {
        "storage_account": [{"id": "/subscriptions/demo-subscription/resourceGroups/demo/providers/Microsoft.Storage/storageAccounts/demo", "name": "demo", "properties": {"supportsHttpsTrafficOnly": True, "allowBlobPublicAccess": False, "minimumTlsVersion": "TLS1_2"}}],
        "role_definition": [{"id": "/subscriptions/demo-subscription/providers/Microsoft.Authorization/roleDefinitions/custom", "properties": {"type": "CustomRole", "permissions": [{"actions": ["Microsoft.Resources/subscriptions/resourceGroups/read"], "notActions": []}], "assignableScopes": ["/subscriptions/demo-subscription"]}}],
        "role_assignment": [{"id": "/subscriptions/demo-subscription/providers/Microsoft.Authorization/roleAssignments/demo", "properties": {"principalId": "demo-principal", "principalType": "User", "roleDefinitionId": "/subscriptions/demo-subscription/providers/Microsoft.Authorization/roleDefinitions/custom", "scope": "/subscriptions/demo-subscription"}}],
        "vnet": [{"id": "/subscriptions/demo-subscription/resourceGroups/demo/providers/Microsoft.Network/virtualNetworks/demo", "properties": {"addressSpace": {"addressPrefixes": ["10.2.0.0/16"]}}}],
        "nsg": [{"id": "/subscriptions/demo-subscription/resourceGroups/demo/providers/Microsoft.Network/networkSecurityGroups/demo", "properties": {"securityRules": [{"name": "public-web", "properties": {"direction": "Inbound", "access": "Allow", "sourceAddressPrefix": "Internet", "destinationPortRange": "443", "protocol": "Tcp", "priority": 100}}]}}],
        "nic": [], "vm": []
      },
      "k8s": {
        "namespace": [{"metadata": {"name": "demo"}}],
        "role": [{"metadata": {"name": "reader", "namespace": "demo"}, "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}]}],
        "rolebinding": [{"metadata": {"name": "reader", "namespace": "demo"}, "roleRef": {"kind": "Role", "name": "reader", "apiGroup": "rbac.authorization.k8s.io"}, "subjects": [{"kind": "ServiceAccount", "name": "demo", "namespace": "demo"}]}],
        "serviceaccount": [{"metadata": {"name": "demo", "namespace": "demo"}}],
        "clusterrole": [], "clusterrolebinding": [],
        "pod": [{"metadata": {"name": "private", "namespace": "demo"}, "spec": {"containers": [{"name": "web", "securityContext": {"privileged": False}}], "serviceAccountName": "demo"}},
                {"metadata": {"name": "unreviewed", "namespace": "demo"}, "spec": {"containers": [{"name": "web", "securityContext": {"privileged": True}}], "hostNetwork": True, "serviceAccountName": "demo"}}],
        "service": [{"metadata": {"name": "web", "namespace": "demo"}, "spec": {"type": "ClusterIP", "selector": {"app": "web"}, "ports": [{"port": 443}]}}],
        "networkpolicy": []
      }
    }[provider]
    collections = [{"type": kind, "scope": scope, "service": kind, "status": "collected" if items else "empty", "items": items} for kind, items in facts.items()]
    # One denied audit read per provider, using that provider's registered type.
    audit = {"aws": "cloudtrail_event", "gcp": "activity", "azure": "activity_log"}.get(provider)
    if audit:
        collections.append({"type": audit, "scope": scope, "service": "audit", "status": "denied", "items": [], "error": {"code": "demo_permission_denied"}})
    return make_snapshot(provider, [scope], collections, created_at="2026-10-10T00:00:00+00:00", metadata={"source": "offline_demo", "not_live_cloud_evidence": True})
