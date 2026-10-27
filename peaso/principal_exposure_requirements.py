"""Collection requirements for principal entry-point context."""
REQUIRED_TYPES = {
    "aws": {"iam_role", "iam_policy", "iam_instance_profile", "organization_account", "organization", "instance", "network_interface", "lambda_function", "rest_api", "rest_api_method", "apigateway_domain_name", "http_api", "http_api_stage", "apigatewayv2_domain_name", "ecs_task", "ecs_task_definition", "ecs_service", "load_balancer", "target_group", "security_group", "subnet", "route_table", "network_acl", "internet_gateway"},
    "gcp": {"project", "organization", "iam_policy", "iam_role", "service_account", "workload_identity_provider", "instance", "firewall", "firewall_policy", "cloudrun_service", "function", "backend_service_health"},
    "azure": {"tenant", "subscription", "directory_user", "directory_group", "directory_service_principal", "directory_application", "directory_federated_credential", "managed_identity", "managed_identity_federated_credential", "role_assignment", "role_definition", "vm", "nic", "public_ip", "subnet", "nsg", "app_service", "app_service_config", "container_group", "resource_graph"},
    "k8s": {"serviceaccount", "role", "clusterrole", "rolebinding", "clusterrolebinding", "pod", "service", "ingress", "node", "networkpolicy", "endpointslice"},
}
