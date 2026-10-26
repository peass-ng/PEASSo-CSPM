"""Evidence-bound entry points into identities, shared by both principal views.

Trust declarations are potential access, not proof that a caller can authenticate.
Internet workload paths require a separate application compromise to obtain identity.
"""
from __future__ import annotations

from collections import defaultdict
from fnmatch import fnmatchcase

from peaso.analysis.common import as_list, externality, native_id, with_analysis_context
from peaso.analysis.iam import assume_role_document, grants
from peaso.analysis.internet_exposure import assess, describe, ports_of, Assessment, pset, union, _internet, _public_ip
from peaso.analysis.trust import restrictive_conditions, aws_federated_trust, _k8s_self_info_binding

LIMITATIONS = [
    "External means outside the scanned or explicitly trusted boundary; ownership and business approval are not inferred.",
    "Trust and impersonation grants remain subject to caller permissions, conditions, denies and provider guardrails.",
    "Internet workload exposure requires an application compromise to obtain its identity; no exploit or traffic probe was performed.",
    "Missing identity, federation, backend or network inventory leaves exposure unresolved; absence of a signal does not establish isolation.",
]
# Include the path inventories even when only Least Privilege or Privesc is selected.
from peaso.principal_exposure_requirements import REQUIRED_TYPES

RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def increased(severity, signals):
    if not any(s["state"] == "declared" for s in signals):
        return severity
    return {"high": "critical", "medium": "high", "low": "medium"}.get(severity, severity)


def canonical(provider, value, scope=""):
    value = str(value or "")
    if provider == "azure":
        return value.lower()
    if provider == "gcp" and "@" in value and ":" not in value:
        return "serviceAccount:" + value
    if provider == "k8s" and value.startswith("system:serviceaccount:"):
        return f"{scope}|{value}"
    return value


def _cluster(row):
    data = row.get("data", {})
    return str((data.get("provenance") or {}).get("cluster_id") or (data.get("metadata") or {}).get("cluster_id") or row.get("scope", "cluster").split("/", 1)[0])


@with_analysis_context
def project(snapshot, resources):
    """Return principal records with reproducible native evidence and explicit uncertainty."""
    provider = snapshot["provider"]
    resources = list(resources)
    by_type = defaultdict(list)
    resources = [row for row in resources if isinstance(row.get("data"), dict)]
    for row in resources:
        by_type[row["type"]].append(row)
    output = {}
    from peaso.analysis.evidence_accumulator import EvidenceAccumulator
    accumulated = EvidenceAccumulator()

    def record(identity, row, label=None):
        key = canonical(provider, identity, _cluster(row) if provider == "k8s" else row.get("scope", ""))
        if not identity:
            return None
        card = output.setdefault(key, {"principal": str(identity), "label": label or str(identity),
            "scopes": [], "exposures": [], "base_severity": "info", "grant_reviews": []})
        accumulated.append(card["scopes"], row.get("scope", ""), 'scope')
        return card

    def signal(identity, row, kind, state, **evidence):
        card = record(identity, row)
        if card is None:
            return
        item = {"kind": kind, "state": state, "resource_id": row.get("id", str(native_id(row))),
            "scope": row.get("scope", ""), **evidence}
        accumulated.append(card["exposures"], item, 'signal')

    def review(identity, row, values=None, source_row=None, via_group=None):
        values = grants(row) if values is None else values
        high = [g for g in values if g.get("allowed_declaration") and RANK.get(g.get("severity"), 4) <= 1]
        if high and identity:
            card = record(identity, row)
            card["base_severity"] = min([card["base_severity"]] + [g["severity"] for g in high], key=RANK.get)
            grant_source = source_row or row
            detail = {"resource_id": row.get("id", str(native_id(row))), "scope": row.get("scope", ""),
                "grant_source_id": grant_source.get("id", str(native_id(grant_source))),
                "grant_count": len(high), "grants": high[:3]}
            if via_group:
                detail["via_group"] = via_group
            accumulated.append(card["grant_reviews"], detail, 'review')

    if provider == "aws":
        policies_by_arn = defaultdict(list)
        for policy_row in by_type["iam_policy"]:
            arn = policy_row["data"].get("Arn")
            if isinstance(arn, str) and arn:
                policies_by_arn[arn].append((policy_row, grants(policy_row)))
        for row in by_type["iam_role"] + by_type["iam_user"]:
            data = row["data"]
            identity = data.get("Arn")
            record(identity, row, data.get("RoleName") or data.get("UserName"))
            review(identity, row)
            attached = {p.get("PolicyArn") for p in data.get("AttachedManagedPolicies") or []
                if isinstance(p, dict) and isinstance(p.get("PolicyArn"), str) and p["PolicyArn"]}
            for policy_arn in sorted(attached):
                for policy_row, policy_grants in policies_by_arn.get(policy_arn, ()):
                    review(identity, row, policy_grants, source_row=policy_row)
            federation_review = aws_federated_trust(snapshot, row)
            unpinned = {(r["federated_principal"], r["statement"]) for r in federation_review[2]["federated_trusts"]
                        if r.get("multi_tenant_issuer") and any(p.get("severity") not in {"low", "review"} for p in r["problems"])} if federation_review else set()
            policy = assume_role_document(row) or {}
            for statement_index, statement in enumerate(as_list(policy.get("Statement"))):
                if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
                    continue
                if not any(fnmatchcase(action, str(pattern).lower()) for pattern in as_list(statement.get("Action"))
                           for action in ("sts:assumerole", "sts:assumerolewithwebidentity", "sts:assumerolewithsaml")):
                    continue
                principal = statement.get("Principal")
                entries = principal.items() if isinstance(principal, dict) else [("AWS", principal)]
                for kind, members in entries:
                    for member in as_list(members):
                        classification = externality(snapshot, member)
                        federation = kind == "Federated"
                        if kind == "Service" or not federation and classification not in {"external", "public", "unknown"}:
                            continue
                        condition = statement.get("Condition")
                        state = "conditional" if condition or federation else "unknown" if classification == "unknown" else "declared"
                        if federation and (member, f"AssumeRolePolicyDocument.Statement[{statement_index}]") in unpinned and not restrictive_conditions(condition):
                            state = "declared"
                        signal(identity, row, "federated_trust" if federation else "external_assumption", state,
                            caller=member, classification=classification, conditions=condition,
                            restrictions=restrictive_conditions(condition), grant=statement)
    elif provider == "gcp":
        # Impersonation can be inherited from project/folder/org policies as well as SA policies.
        impersonation = {"roles/iam.serviceAccountTokenCreator", "roles/iam.workloadIdentityUser", "roles/iam.serviceAccountUser", "roles/owner", "roles/editor"}
        role_definitions = {r["data"].get("name"): r for r in by_type["iam_role"] if r["data"].get("name")}
        for row in by_type["iam_role"]:
            data = row["data"]
            if set(data.get("includedPermissions") or []) & {"iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.signJwt", "iam.serviceAccounts.signBlob", "iam.serviceAccounts.actAs"}:
                impersonation.add(data.get("name"))
        accounts = by_type["service_account"]
        from peaso.analysis.cloud_workload_index import CloudWorkloadIndex
        account_targets = CloudWorkloadIndex(by_type)
        for row in accounts:
            record(row["data"].get("email"), row, row["data"].get("displayName"))
        for row in resources:
            data = row["data"]
            policy = data.get("iamPolicy", data.get("policy", data))
            if not isinstance(policy, dict):
                continue
            for binding in policy.get("bindings") or []:
                if not isinstance(binding, dict):
                    continue
                role = binding.get("role")
                for member in binding.get("members") or []:
                    if role in {"roles/owner", "roles/editor"}:
                        review(member, row, [{"severity": "high", "allowed_declaration": True,
                            "path": "bindings", "native_grant": binding}])
                    elif role in role_definitions:
                        definition = role_definitions[role]
                        review(member, row, grants(definition), source_row=definition)
                    if role not in impersonation:
                        continue
                    classification = externality(snapshot, member)
                    federation = str(member).startswith(("principal://", "principalSet://"))
                    if classification not in {"external", "public", "unknown"} and not federation:
                        continue
                    # Scope ancestry must be collected; never apply an unrelated project grant.
                    if row['type'] == 'service_account':
                        targets = [row]
                    else:
                        target_keys = [('scope', row['scope'])]
                        if row['type'] in {'organization', 'folder'}:
                            target_keys.append(('ancestor', row['scope']))
                        candidates = account_targets.candidates('service_account', 'gcp_account_scope', target_keys)
                        targets = [sa for sa in candidates if sa['scope'] == row['scope']
                            or row['type'] in {'organization', 'folder'} and row['scope'] in as_list(sa['data'].get('ancestors'))]
                    for target in targets:
                        state = "conditional" if binding.get("condition") or federation or target["data"].get("disabled") is True or role == "roles/iam.serviceAccountUser" else "unknown" if classification == "unknown" else "declared"
                        signal(target["data"].get("email"), row, "federated_trust" if federation else "external_impersonation", state,
                            caller=member, classification=classification, role=role, conditions=binding.get("condition"),
                            target_resource=target.get("id"), requires_workload_control=role == "roles/iam.serviceAccountUser")
    elif provider == "azure":
        from peaso.analysis.azure_federation_index import AzureFederationIndex
        federation_targets = AzureFederationIndex(by_type)
        definitions = {str(r["data"].get("name", "")).rsplit("/", 1)[-1].lower(): r for r in by_type["role_definition"]}
        for row in by_type["directory_user"] + by_type["directory_service_principal"]:
            data = row["data"]
            identity = data.get("id")
            record(identity, row, data.get("displayName") or data.get("userPrincipalName"))
            if externality(snapshot, identity) == "external":
                signal(identity, row, "external_identity", "conditional" if data.get("accountEnabled") is False else "declared", owner_tenant=data.get("appOwnerOrganizationId"), user_type=data.get("userType"), account_enabled=data.get("accountEnabled"))
        for row in by_type["role_assignment"]:
            props = row["data"].get("properties") or {}
            definition = definitions.get(str(props.get("roleDefinitionId", "")).rsplit("/", 1)[-1].lower())
            if definition:
                review(props.get("principalId"), row, grants(definition), source_row=definition)
        for row in by_type["directory_federated_credential"] + by_type["managed_identity_federated_credential"]:
            data = row["data"]
            props = data.get("properties", data)
            targets = [r["data"].get("id") for r in federation_targets.service_principals(data) if data.get("appId") and r["data"].get("appId") == data["appId"]]
            parent = str(data.get("id", "")).lower().split("/federatedidentitycredentials/")[0]
            targets += [r["data"].get("properties", {}).get("principalId") for r in federation_targets.managed_identities(data, parent) if str(r["data"].get("id", "")).lower() == parent]
            for identity in targets:
                signal(identity, row, "federated_trust", "conditional", issuer=props.get("issuer"), subject=props.get("subject"), audiences=props.get("audiences"), classification="ownership_unverified")
    elif provider == "k8s":
        from peaso.analysis.k8s_impersonation_index import K8sImpersonationIndex
        impersonation_accounts = K8sImpersonationIndex(by_type['serviceaccount'], _cluster)
        roles = {(_cluster(r), r["type"], r["data"].get("metadata", {}).get("namespace", "default"), r["data"].get("metadata", {}).get("name")): r
                 for r in by_type["role"] + by_type["clusterrole"]}
        accounts_by_cluster = defaultdict(list)
        accounts_by_namespace = defaultdict(list)
        for sa in by_type["serviceaccount"]:
            sa_namespace = sa["data"].get("metadata", {}).get("namespace", "default")
            accounts_by_cluster[_cluster(sa)].append(sa)
            accounts_by_namespace[(_cluster(sa), sa_namespace)].append(sa)
        for row in by_type["rolebinding"] + by_type["clusterrolebinding"]:
            if _k8s_self_info_binding(snapshot, row):
                continue
            data = row["data"]
            meta, ref = data.get("metadata", {}), data.get("roleRef", {})
            namespace = meta.get("namespace", "default")
            role = roles.get((_cluster(row), str(ref.get("kind", "")).lower(), namespace if ref.get("kind") == "Role" else "default", ref.get("name")))
            for subject in data.get("subjects") or []:
                identity = f"system:serviceaccount:{subject.get('namespace', namespace)}:{subject.get('name')}" if subject.get("kind") == "ServiceAccount" else subject.get("name")
                if role:
                    review(identity, row, grants(role), source_row=role)
                    # Kubernetes authenticates a ServiceAccount with these built-in groups.
                    if subject.get("kind") == "Group" and isinstance(identity, str) and (
                            identity in {"system:serviceaccounts", "system:authenticated"}
                            or identity.startswith("system:serviceaccounts:")):
                        candidates = (accounts_by_cluster[_cluster(row)] if identity in {
                            "system:serviceaccounts", "system:authenticated"} else
                            accounts_by_namespace[(_cluster(row), identity.removeprefix("system:serviceaccounts:"))])
                        for sa in candidates:
                            sa_namespace = sa["data"].get("metadata", {}).get("namespace", "default")
                            sa_name = sa["data"].get("metadata", {}).get("name")
                            if sa_name:
                                review(f"system:serviceaccount:{sa_namespace}:{sa_name}", row,
                                    grants(role), source_row=role, via_group=identity)
                classification = externality(snapshot, identity)
                if classification in {"external", "public", "everyone_authenticated", "unknown"}:
                    state = "unknown" if classification == "unknown" else "declared"
                    signal(identity, row, "external_identity", state, classification=classification, role_ref=ref)
                    for rule in role["data"].get("rules") or [] if role else []:
                        if not set(rule.get("verbs") or []) & {"impersonate", "*"} or not set(rule.get("resources") or []) & {"serviceaccounts", "*"} or not set(rule.get("apiGroups") or []) & {"", "*"}:
                            continue
                        for sa in impersonation_accounts.candidates(row, namespace, rule.get('resourceNames')):
                            meta = sa["data"].get("metadata") or {}
                            sa_ns = meta.get("namespace", "default")
                            names = rule.get("resourceNames")
                            if _cluster(sa) != _cluster(row) or row["type"] == "rolebinding" and sa_ns != namespace or names and meta.get("name") not in names:
                                continue
                            signal(f"system:serviceaccount:{sa_ns}:{meta.get('name')}", sa, "external_impersonation", state,
                                caller=identity, classification=classification, role_ref=ref, binding_resource=row.get("id"), rule=rule)

    _workloads(snapshot, resources, by_type, signal)
    for card in output.values():
        base = card["base_severity"]
        if card["exposures"] and base == "info":
            base = "medium"
        card["base_severity"] = base
        card["severity"] = increased(base, card["exposures"])
    return output


def _workloads(snapshot, resources, by_type, signal):
    provider = snapshot["provider"]
    if provider == 'k8s':
        from peaso.analysis.k8s_workload_index import K8sWorkloadIndex
        k8s_workloads = K8sWorkloadIndex(snapshot, by_type, _cluster)
    from peaso.analysis.cloud_workload_index import CloudWorkloadIndex, compute_path
    cloud_workloads = CloudWorkloadIndex(by_type)
    profiles = {r["data"].get("Arn"): r["data"] for r in by_type["iam_instance_profile"]}
    # IAM role inventory embeds instance profiles on some collector versions.
    for role in by_type["iam_role"]:
        for profile in role["data"].get("InstanceProfileList") or []:
            profiles.setdefault(profile.get("Arn"), {**profile, "Roles": [role["data"]]})

    def identities(row):
        data = row["data"]
        if provider == "aws":
            if row["type"] == "lambda_function":
                return [data.get("Role")]
            if row["type"] == "ecs_task":
                definition = next((r["data"] for r in cloud_workloads.candidates("ecs_task_definition", "taskDefinitionArn", [data.get("taskDefinitionArn")]) if r["data"].get("taskDefinitionArn") == data.get("taskDefinitionArn")), {})
                return [data.get("taskRoleArn") or definition.get("taskRoleArn")]
            profile = profiles.get((data.get("IamInstanceProfile") or {}).get("Arn"), {})
            return [r.get("Arn") for r in profile.get("Roles") or []]
        if provider == "gcp":
            if row["type"] == "instance":
                return [sa.get("email") for sa in data.get("serviceAccounts") or []]
            config = data.get("serviceConfig") or data.get("template") or data
            return [config.get("serviceAccount") or config.get("serviceAccountEmail")]
        if provider == "azure":
            identity = data.get("identity") or {}
            result = [identity.get("principalId")]
            for ident, props in (identity.get("userAssignedIdentities") or {}).items():
                result.append(props.get("principalId"))
                if not props.get("principalId"):
                    result.extend(r["data"].get("properties", {}).get("principalId") for r in cloud_workloads.candidates("managed_identity", "id", [ident], lower=True) if str(r["data"].get("id", "")).lower() == ident.lower())
            return result
        return []

    assessments = assess(snapshot, resources)
    if provider == "azure":
        assessments = [*assessments, *_azure_containers(by_type)]
    for assessment in assessments:
        auth_public_api = (provider == "aws" and assessment.resource["type"] == "http_api"
            and assessment.authenticated and bool(assessment.addresses)
            and any(step.get("layer") == "route" and step.get("decision") == "allow" for step in assessment.path))
        if (assessment.verdict() == "PASS" and not auth_public_api) or assessment.data_exposure or assessment.kind in {"control_plane", "external_share"}:
            continue
        row = assessment.resource
        targets = [row]
        backend_evidence = {}
        azure_target_routes = {}
        if provider == "k8s":
            services = [row] if row["type"] == "service" else []
            if row["type"] == "ingress":
                spec = row["data"].get("spec", {})
                backends = [spec.get("defaultBackend", {})] + [p.get("backend", {}) for rule in spec.get("rules") or [] for p in (rule.get("http") or {}).get("paths") or []]
                service_ports = []
                for backend in backends:
                    service = backend.get("service") if isinstance(backend, dict) else None
                    if not isinstance(service, dict) or not isinstance(service.get("name"), str):
                        continue
                    port = service.get("port")
                    if isinstance(port, dict):
                        service_ports.append((service["name"], port.get("number"), port.get("name")))

                def matching_service_port(service, number, port_name):
                    return any((isinstance(number, int) and not isinstance(number, bool) and port.get("port") == number)
                        or (isinstance(port_name, str) and port_name and port.get("name") == port_name)
                        for port in (service["data"].get("spec") or {}).get("ports") or [] if isinstance(port, dict))

                services = [s for s in k8s_workloads.candidates('service', row, names=[name for name, _, _ in service_ports]) if _cluster(s) == _cluster(row)
                    and s["data"].get("metadata", {}).get("namespace", "default") == row["data"].get("metadata", {}).get("namespace", "default")
                    and any(name == s["data"].get("metadata", {}).get("name")
                        and matching_service_port(s, number, port_name)
                        for name, number, port_name in service_ports)]
            targets = [pod for service in services for pod in k8s_workloads.pods(service)]
        elif provider == "azure" and row["type"] == "nic":
            vm_id = ((row["data"].get("properties") or {}).get("virtualMachine") or {}).get("id")
            targets = [vm for vm in cloud_workloads.candidates("vm", "id", [vm_id], lower=True) if vm_id and str(vm["data"].get("id", "")).lower() == vm_id.lower()]
        elif provider == "azure" and row["type"] == "load_balancer":
            routes = [route for step in assessment.path if step.get("layer") == "backend"
                and step.get("decision") == "allow" for route in step.get("routes", [])
                if isinstance(route, dict)]
            for route in routes:
                nic = next((nic for nic in cloud_workloads.candidates("nic", "id", [route.get("nic_id")], wrapper=True) if nic["id"] == route.get("nic_id")), None)
                vm_id = ((nic["data"].get("properties") or {}).get("virtualMachine") or {}).get("id") if nic else None
                vm = next((vm for vm in cloud_workloads.candidates("vm", "id", [str(vm_id)], lower=True) if vm_id and vm["data"].get("id")
                    and str(vm["data"]["id"]).lower() == str(vm_id).lower()), None)
                if vm:
                    azure_target_routes.setdefault(vm["id"], []).append(route)
            targets = [vm for vm in cloud_workloads.candidates("vm", "id", azure_target_routes, wrapper=True) if vm["id"] in azure_target_routes]
        elif provider == "gcp" and row["type"] == "forwarding_rule":
            health_by_service = {compute_path(health["data"].get("backendService")): health["data"]
                for health in by_type["backend_service_health"]
                if health["scope"] == row["scope"] and health["data"].get("backendService")}
            services = {compute_path(item.get("backend_service")) for step in assessment.path
                if step.get("layer") == "cloud_armor"
                for item in step.get("unprotected", []) if isinstance(item, dict)}
            for backend in cloud_workloads.candidates("backend_service", "gcp_backend_path",
                                                      [(row["scope"], service) for service in services]):
                if backend["scope"] != row["scope"] or compute_path(backend["data"].get("selfLink")) not in services:
                    continue
                embedded_health = backend["data"].get("BackendHealth")
                health = (embedded_health if isinstance(embedded_health, dict) else
                          health_by_service.get(compute_path(backend["data"].get("selfLink")))) or {}
                for group in health.get("groups") or []:
                    if group.get("collection_status") != "collected":
                        continue
                    for status in group.get("healthStatus") or []:
                        instance_path = compute_path(status.get("instance")) if isinstance(status, dict) else None
                        if instance_path and status.get("healthState") == "HEALTHY":
                            backend_evidence[instance_path] = {"backend_service": backend["data"].get("selfLink"),
                                "group": group.get("group"), "health_state": "HEALTHY",
                                "source_requests": group.get("source_requests", [])}
            targets = [instance for instance in cloud_workloads.candidates(
                "instance", "gcp_running_instance_path", [(row["scope"], path) for path in backend_evidence])
                if instance["scope"] == row["scope"]
                and instance["data"].get("status") == "RUNNING"
                and compute_path(instance["data"].get("selfLink")) in backend_evidence]
        elif provider == "aws" and row["type"] == "network_interface":
            instance = (row["data"].get("Attachment") or {}).get("InstanceId")
            targets = [vm for vm in cloud_workloads.candidates("instance", "InstanceId", [instance]) if instance and vm["data"].get("InstanceId") == instance]
            eni = row["data"].get("NetworkInterfaceId")
            targets += [task for task in cloud_workloads.candidates("ecs_task", "running_task_eni", [eni]) if eni and task["data"].get("lastStatus") == "RUNNING" and any(
                d.get("name") == "networkInterfaceId" and d.get("value") == eni
                for attachment in task["data"].get("attachments") or [] for d in attachment.get("details") or [])]
        if provider == "aws" and row["type"] == "load_balancer":
            lb_arn = row["data"].get("LoadBalancerArn")
            tgs = {t["data"].get("TargetGroupArn") for t in cloud_workloads.candidates("target_group", "target_group_lb", [lb_arn]) if lb_arn and lb_arn in (t["data"].get("LoadBalancerArns") or [])}
            service_defs = {s["data"].get("taskDefinition") for s in cloud_workloads.candidates("ecs_service", "ecs_service_target_group", tgs) if any(b.get("targetGroupArn") in tgs for b in s["data"].get("loadBalancers") or [])}
            targets = [task for task in cloud_workloads.candidates("ecs_task", "running_task_definition", service_defs) if task["data"].get("lastStatus") == "RUNNING" and task["data"].get("taskDefinitionArn") in service_defs]
            lb_tasks = CloudWorkloadIndex({"ecs_task": targets})
            confirmed_targets = set()
            listeners = (row["data"].get("Listeners") or {}).get("items") or []
            public_ports = {port for protocol, port in ports_of(assessment.ports or {}) if protocol == "tcp"}
            forwards = {}
            for listener in listeners:
                if not isinstance(listener, dict) or listener.get("Port") not in public_ports:
                    continue
                actions = [(action, None, []) for action in listener.get("DefaultActions") or []]
                rules = listener.get("Rules") if isinstance(listener.get("Rules"), dict) else {}
                if rules.get("collection_status") == "collected":
                    for rule in rules.get("items") or []:
                        if not isinstance(rule, dict) or not isinstance(rule.get("Conditions"), list):
                            continue
                        conditions = rule["Conditions"]
                        if any(not isinstance(condition, dict) or condition.get("Field") not in {
                            "source-ip", "host-header", "http-request-method", "path-pattern", "http-header", "query-string"}
                            for condition in conditions):
                            continue
                        source_ranges = [value for condition in conditions if condition.get("Field") == "source-ip"
                            for value in condition.get("Values") or []]
                        if any(condition.get("Field") == "source-ip" for condition in conditions) and not any(
                            _internet(value) for value in source_ranges):
                            continue
                        actions.extend((action, rule.get("RuleArn"), source_ranges)
                            for action in rule.get("Actions") or [])
                for action, rule_arn, source_ranges in actions:
                    if not isinstance(action, dict) or action.get("Type") != "forward":
                        continue
                    source = {"listener_port": listener["Port"], "listener_arn": listener.get("ListenerArn"),
                        "rule_arn": rule_arn, "source_ranges": source_ranges}
                    groups = (action.get("ForwardConfig") or {}).get("TargetGroups") or []
                    for group in groups:
                        if isinstance(group, dict) and group.get("TargetGroupArn") and group.get("Weight", 1) not in (0, "0"):
                            forwards.setdefault(group["TargetGroupArn"], source)
                    if not groups and action.get("TargetGroupArn"):
                        forwards.setdefault(action["TargetGroupArn"], source)
            for tg in cloud_workloads.candidates("target_group", "TargetGroupArn", forwards):
                tg_data = tg["data"]
                tg_arn = tg_data.get("TargetGroupArn")
                if (row["data"].get("Type") != "application" or tg_arn not in forwards
                        or tg_arn not in tgs or tg_data.get("TargetType") != "ip"):
                    continue
                health = tg_data.get("TargetHealth") or {}
                if health.get("collection_status") != "collected":
                    continue
                # Keep the native target IP and port together; a healthy sibling target
                # does not establish the route to this task.
                healthy_targets = {((item.get("Target") or {}).get("Id"), (item.get("Target") or {}).get("Port"))
                    for item in health.get("TargetHealthDescriptions") or [] if isinstance(item, dict)
                    and (item.get("TargetHealth") or {}).get("State") == "healthy"}
                for service in cloud_workloads.candidates("ecs_service", "ecs_service_target_group", [tg_arn]):
                    svc = service["data"]
                    ports = {binding.get("containerPort") for binding in svc.get("loadBalancers") or []
                        if isinstance(binding, dict) and binding.get("targetGroupArn") == tg_arn}
                    if not ports:
                        continue
                    for task in lb_tasks.candidates("ecs_task", "taskDefinitionArn", [svc.get("taskDefinition")]):
                        task_data = task["data"]
                        if task_data.get("taskDefinitionArn") != svc.get("taskDefinition") or task_data.get("group") != "service:" + str(svc.get("serviceName")):
                            continue
                        eni_ids = {detail.get("value") for attachment in task_data.get("attachments") or []
                            for detail in attachment.get("details") or [] if detail.get("name") == "networkInterfaceId"}
                        match = next(((eni["data"].get("PrivateIpAddress"), port) for eni in cloud_workloads.candidates("network_interface", "NetworkInterfaceId", eni_ids)
                            if eni["data"].get("NetworkInterfaceId") in eni_ids for port in ports
                            if (eni["data"].get("PrivateIpAddress"), port) in healthy_targets), None)
                        if match:
                            confirmed_targets.add(task["id"])
                            backend_evidence.setdefault(task["id"], {"target_group": tg_arn,
                                "healthy_target": {"ip": match[0], "port": match[1]},
                                "ecs_service": svc.get("serviceName"), **forwards[tg_arn]})
        if provider == "aws" and row["type"] == "rest_api":
            def base_lambda_arn(value):
                if not isinstance(value, str) or ":function:" not in value:
                    return None
                prefix, name = value.split(":function:", 1)
                return prefix + ":function:" + name.split(":", 1)[0]

            api_id = row["data"].get("id")
            domain_stages = {mapping.get("stage") for domain in by_type["apigateway_domain_name"]
                if domain["scope"] == row["scope"]
                and any(kind in {"REGIONAL", "EDGE"} for kind in
                    ((domain["data"].get("endpointConfiguration") or {}).get("types") or []))
                and "ROUTING_RULE" not in str(domain["data"].get("routingMode", ""))
                for mapping in ((domain["data"].get("BasePathMappings") or {}).get("items") or [])
                if isinstance(mapping, dict) and mapping.get("restApiId") == api_id}
            deployed = {(method["data"].get("resourcePath"), method["data"].get("httpMethod"))
                for method in by_type["rest_api_method"] if method["scope"] == row["scope"]
                and method["data"].get("restApiId") == api_id
                and (row["data"].get("disableExecuteApiEndpoint") is not True or
                    str(method["data"].get("stageArn", "")).rsplit("/stages/", 1)[-1] in domain_stages)}
            integrations = {base_lambda_arn(method.get("integrationLambdaArn"))
                for method in row["data"].get("Methods") or [] if isinstance(method, dict)
                and (method.get("path"), method.get("httpMethod")) in deployed}
            integrations.discard(None)
            targets = [function for function in by_type["lambda_function"]
                if base_lambda_arn(function["data"].get("FunctionArn")) in integrations]
        if provider == "aws" and row["type"] == "http_api":
            def collected_items(value):
                if isinstance(value, dict):
                    if value.get("collection_status") not in (None, "collected"):
                        return []
                    value = value.get("items")
                return value if isinstance(value, list) else []

            def base_lambda_arn(value):
                if not isinstance(value, str) or ":function:" not in value:
                    return None
                prefix, name = value.split(":function:", 1)
                return prefix + ":function:" + name.split(":", 1)[0]

            api_id = row["data"].get("ApiId")
            domain_stages = {mapping.get("Stage") for domain in by_type["apigatewayv2_domain_name"]
                if domain["scope"] == row["scope"]
                and "ROUTING_RULE" not in str(domain["data"].get("RoutingMode", ""))
                and any(isinstance(config, dict) and config.get("EndpointType") in {"REGIONAL", "EDGE"}
                    for config in (domain["data"].get("DomainNameConfigurations") or []))
                for mapping in collected_items(domain["data"].get("ApiMappings"))
                if isinstance(mapping, dict) and mapping.get("ApiId") == api_id}
            stages = {stage["data"].get("StageName") for stage in by_type["http_api_stage"]
                if stage["scope"] == row["scope"] and stage["data"].get("ParentApiId") == api_id
                and stage["data"].get("AutoDeploy") is True
                and (row["data"].get("DisableExecuteApiEndpoint") is not True
                    or stage["data"].get("StageName") in domain_stages)}
            integration_arns = {integration.get("IntegrationId"): base_lambda_arn(integration.get("integrationLambdaArn"))
                for integration in collected_items(row["data"].get("Integrations"))
                if isinstance(integration, dict)}
            integrations = {integration_arns.get(str(route.get("Target", "")).removeprefix("integrations/"))
                for route in collected_items(row["data"].get("Routes"))
                if isinstance(route, dict) and route.get("Target") and stages}
            integrations.discard(None)
            targets = [function for function in by_type["lambda_function"]
                if base_lambda_arn(function["data"].get("FunctionArn")) in integrations]
        state = "declared" if (assessment.verdict() == "FAIL" or auth_public_api) and not assessment.unresolved and not assessment.dormant and assessment.addresses else "unknown"
        if provider == "aws" and row["type"] == "load_balancer":
            state = "unknown" if not confirmed_targets else state
        path_state = state
        for target in targets:
            state = path_state
            if provider == "aws" and row["type"] == "load_balancer" and target["id"] not in confirmed_targets:
                state = "unknown"
            identity_gaps = []
            if provider == "k8s" and (target["data"].get("metadata", {}).get("deletionTimestamp") or target["data"].get("status", {}).get("phase") in {"Succeeded", "Failed"}):
                continue
            ids = identities(target)
            token_available = None
            if provider == "k8s":
                from peaso.analysis.network import _k8s_matches, _k8s_selector_requirements
                spec = target["data"].get("spec") or {}
                meta = target["data"].get("metadata") or {}
                namespace, name = meta.get("namespace", "default"), spec.get("serviceAccountName", "default")
                ids = [f"system:serviceaccount:{namespace}:{name}"]
                sa = next((s for s in k8s_workloads.candidates('serviceaccount', target, names=[name]) if _cluster(s) == _cluster(target)
                    and s["data"].get("metadata", {}).get("namespace", "default") == namespace and s["data"].get("metadata", {}).get("name") == name), None)
                token_available = spec.get("automountServiceAccountToken", sa["data"].get("automountServiceAccountToken", True) if sa else True)
                policies_complete = k8s_workloads.complete_policies(target['scope'])
                if not policies_complete:
                    state = "unknown"
                    identity_gaps.append({"layer": "networkpolicy", "reason": "NetworkPolicy inventory is incomplete"})
                if sa is None and "automountServiceAccountToken" not in spec:
                    state = "unknown"
                    identity_gaps.append({"layer": "identity", "reason": "ServiceAccount automount setting is not collected"})
                selected_ingress_policy = False
                open_ingress_policy = False
                for policy in k8s_workloads.candidates('networkpolicy', target):
                    if _cluster(policy) != _cluster(target) or policy["data"].get("metadata", {}).get("namespace", "default") != namespace:
                        continue
                    policy_spec = policy["data"].get("spec") or {}
                    if "Ingress" not in (policy_spec.get("policyTypes") or ["Ingress"]):
                        continue
                    requirements, reason = _k8s_selector_requirements(policy_spec.get("podSelector", {}), "networkpolicy")
                    if reason:
                        state = "unknown"
                        identity_gaps.append({"layer": "networkpolicy", "reason": f"NetworkPolicy pod selector {reason}"})
                    elif _k8s_matches(meta.get("labels") or {}, requirements):
                        selected_ingress_policy = True
                        # An empty ingress rule allows every source and port.
                        # Such a policy cannot restrict the service's public path.
                        open_ingress_policy |= any(isinstance(rule, dict) and not rule.get("from") and not rule.get("ports")
                            for rule in as_list(policy_spec.get("ingress")))
                if selected_ingress_policy and not open_ingress_policy and state == "declared":
                    state = "conditional"
                mounted = {mount.get("name") for container in list(spec.get("containers") or []) + list(spec.get("initContainers") or []) + list(spec.get("ephemeralContainers") or []) for mount in container.get("volumeMounts") or []}
                projected = any("serviceAccountToken" in source for volume in spec.get("volumes") or [] if volume.get("name") in mounted
                                for source in (volume.get("projected") or {}).get("sources") or [])
                if token_available is False and not projected:
                    continue
            for identity in ids:
                if identity:
                    target_routes = azure_target_routes.get(target["id"], [])
                    signal(identity, target, "internet_workload", state, endpoint_resource=row.get("id"),
                        workload_resource=target.get("id"),
                        ports=list(dict.fromkeys(port for route in target_routes for port in route.get("frontend_ports", [])))
                            if provider == "azure" and row["type"] == "load_balancer" else describe(assessment.ports or {}),
                        public_addresses=list(dict.fromkeys(route["public_ip"] for route in target_routes if route.get("public_ip")))
                            if provider == "azure" and row["type"] == "load_balancer" else assessment.addresses,
                        unresolved=assessment.unresolved + identity_gaps + ([{"layer": "endpoint", "reason": "No public endpoint address observed"}] if not assessment.addresses else []) + ([{"layer": "backend", "reason": "Target routing and health require resolution"}] if provider == "aws" and row["type"] == "load_balancer" and target["id"] not in confirmed_targets else []),
                        path=assessment.path, requires_application_compromise=True,
                        token_automount=token_available,
                        **({"backend_evidence": backend_evidence[compute_path(target["data"].get("selfLink"))]}
                            if provider == "gcp" and row["type"] == "forwarding_rule" else
                            {"backend_evidence": backend_evidence[target["id"]]}
                            if provider == "aws" and row["type"] == "load_balancer" and target["id"] in backend_evidence else
                            {"backend_evidence": target_routes} if provider == "azure" and row["type"] == "load_balancer" else {}),
                        limitations=["Application compromise required; network policy enforcement and downstream backend reachability are not proven."] if provider == "k8s" else [])


@with_analysis_context
def exposed_privileged_findings(snapshot, resources):
    """Join an observed public workload path to a high-impact runtime grant.

    A public declaration alone and a broad policy alone remain separate facts.
    Only a resolved workload identity and a declared path produce a failure.
    """
    from peaso.analysis.common import finding, source, stable_id

    resources = list(resources)
    by_id = {row["id"]: row for row in resources}
    output = []
    for card in project(snapshot, resources).values():
        reviews = card["grant_reviews"]
        if not reviews:
            continue
        workloads = {}
        for exposure in card["exposures"]:
            if exposure.get("kind") != "internet_workload" or exposure.get("state") != "declared":
                continue
            workload_id = exposure.get("workload_resource")
            if workload_id in by_id:
                workloads.setdefault(workload_id, []).append(exposure)
        for workload_id, paths in workloads.items():
            workload = by_id[workload_id]
            match = next(((grant, review) for review in reviews for grant in review.get("grants", [])
                if grant.get("allowed_declaration") and RANK.get(grant.get("severity"), 4) <= 1), None)
            if match is None:
                continue
            sample, grant_review = match
            native = sample.get("native_grant")
            label = "high-impact permissions"
            if isinstance(native, dict):
                label = (native.get("role") or native.get("Action") or native.get("actions") or
                    native.get("dataActions") or native.get("verbs") or label)
            elif isinstance(native, str):
                label = native
            if isinstance(label, list):
                label = ", ".join(str(value) for value in label[:3])
            label = str(label)[:160]
            addresses = list(dict.fromkeys(str(address) for path in paths
                for address in path.get("public_addresses", []) if address))
            ports = list(dict.fromkeys(str(port) for path in paths for port in path.get("ports", []) if port))
            endpoint = ", ".join(addresses[:2])
            if not endpoint:
                continue
            name = native_id(workload)
            principal = card["principal"]
            grant_line = (f"That identity belongs to {grant_review['via_group']}, which has a declared high-impact grant for {label}."
                if grant_review.get("via_group") else f"That identity has a declared high-impact grant for {label}.")
            observation = (f"{name} is linked to a public endpoint configured at {endpoint}" +
                (f" on {', '.join(ports[:3])}." if ports else ".") + "\n" +
                f"The workload uses {principal} as its runtime identity.\n" +
                grant_line + "\n" +
                "If the public workload is compromised, those permissions could be used against the resources they cover, which may affect users or their data.")
            evidence = {"source": source(snapshot, workload, "data"), "principal": principal,
                "endpoints": [{"resource_id": path.get("endpoint_resource"),
                    "public_addresses": path.get("public_addresses", []), "ports": path.get("ports", []),
                    "path": path.get("path", []),
                    **({"backend_evidence": path["backend_evidence"]} if path.get("backend_evidence") else {})} for path in paths],
                "grant_sources": reviews, "requires_application_compromise": True,
                "effective_permission": "not_proven", "risk_state": "conditional"}
            current = finding(snapshot, workload, "exposure", "analysis.exposed_privileged_workload",
                "Public workload uses a privileged identity", "high", evidence, status="FAIL")
            current["id"] = stable_id("exposure", "analysis.exposed_privileged_workload", workload_id, principal)
            current["evidence_summary"] = observation
            current["remediation"] = ("Limit the workload identity to the permissions its work needs, and restrict "
                "the public entry point or require authentication where the service allows it. Test the intended path afterward.")
            output.append(current)
    return output


def _azure_containers(by_type):
    """Native ACI and Resource Graph Container Apps; missing environment data stays unknown."""
    rows = by_type["container_group"] + by_type["resource_graph"]
    environments = {str(r["data"].get("id", "")).lower(): r["data"].get("properties", {})
                    for r in by_type["resource_graph"] if str(r["data"].get("type", "")).lower() == "microsoft.app/managedenvironments"}
    seen = set()
    for row in rows:
        data = row["data"]
        rid = str(data.get("id", "")).lower()
        if rid in seen:
            continue
        kind = str(data.get("type", "")).lower()
        props = data.get("properties") or {}
        a = Assessment(row, "container")
        if kind == "microsoft.app/containerapps":
            ingress = (props.get("configuration") or {}).get("ingress") or {}
            if ingress.get("external") is not True:
                continue
            env_id = props.get("environmentId") or props.get("managedEnvironmentId")
            environment = environments.get(str(env_id or "").lower())
            if environment and (str(environment.get("publicNetworkAccess", "")).lower() == "disabled" or (environment.get("vnetConfiguration") or {}).get("internal") is True):
                continue
            a.addresses = [ingress["fqdn"]] if ingress.get("fqdn") else []
            if ingress.get("transport") == "tcp":
                port = ingress.get("exposedPort")
                if not isinstance(port, int):
                    a.gap("listener", "Container App exposed TCP port is missing")
                else:
                    a.ports = pset("tcp", port, port)
            else:
                a.ports = pset("tcp", 443, 443)
                if ingress.get("allowInsecure") is True:
                    a.ports = union(a.ports, pset("tcp", 80, 80))
            if environment is None:
                a.gap("inventory", "Container App environment public access configuration is not collected")
            if ingress.get("ipSecurityRestrictions") or ingress.get("clientCertificateMode") == "require":
                a.gap("authorization", "Container App source or client certificate restrictions require evaluation")
            a.step("container_ingress", "allow", external=True, environment_id=env_id)
        elif row["type"] == "container_group" or kind == "microsoft.containerinstance/containergroups":
            address = props.get("ipAddress") or {}
            if address.get("type") != "Public" or not _public_ip(address.get("ip")):
                continue
            a.addresses = [address["ip"]]
            a.ports = {}
            for port in address.get("ports") or []:
                if isinstance(port.get("port"), int):
                    a.ports = union(a.ports, pset(port.get("protocol", "TCP"), port["port"], port["port"]) or {})
            a.step("container_ingress", "allow", public_ip=address["ip"])
        else:
            continue
        if props.get("provisioningState") != "Succeeded":
            a.gap("inventory", "Container provisioning has not been confirmed successful")
        seen.add(rid)
        yield a


def annotate_privesc(snapshot, graph, findings, model, inventory=None):
    """Attach entry points without adding assumption/compromise edges or changing confidence.

    ``inventory`` is resources(snapshot) when the caller already built it for
    this unchanged snapshot (the engine does); None rebuilds it here.
    """
    from peaso.snapshot import resources
    cards = project(snapshot, resources(snapshot) if inventory is None else inventory)
    matched = {}
    for node in model.principals.values():
        identity = node.attrs.get("arn") or node.attrs.get("member") or node.attrs.get("email") or node.attrs.get("user") or node.id
        card = cards.get(canonical(node.provider, identity, node.attrs.get("cluster", node.scope)))
        if card and card["exposures"]:
            matched[node.id] = card
    for node in graph["nodes"]:
        card = matched.get(node["id"])
        if card:
            node["exposures"] = card["exposures"]
        elif node.get("members"):
            node["exposed_member_count"] = sum(m in matched for m in node["members"])
            for sample in node.get("member_sample") or []:
                if sample["id"] in matched:
                    sample["exposures"] = matched[sample["id"]]["exposures"]
    adjusted = {}
    for finding in findings:
        card = matched.get(finding.get("resource_id"))
        if not card:
            continue
        evidence = finding.setdefault("evidence", {})
        evidence["principal_exposures"] = card["exposures"]
        base = finding["severity"]
        finding["base_severity"] = base
        if finding.get("status") != "UNKNOWN":
            finding["severity"] = increased(base, card["exposures"])
        if finding["severity"] != base:
            evidence["severity_adjustment"] = "Raised one tier because the source principal has a declared external or internet workload entry point."
        adjusted[finding["id"]] = finding["severity"]
    for edge in graph["edges"]:
        for detail in edge.get("technique_details") or []:
            if detail.get("finding") in adjusted:
                detail["base_severity"] = detail.get("severity")
                detail["severity"] = adjusted[detail["finding"]]
