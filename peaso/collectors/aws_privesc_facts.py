"""Read-only AWS facts consumed by the privilege-escalation evaluator.

ECS placement (container instances, running tasks), IAM identity providers,
the organization tree (account -> OU -> root paths), EMR clusters and Service
Catalog launch constraints. Every request is a list/describe/get metadata read
on the shared scan scheduler; outputs are explicit field allowlists, so task
overrides, container environment, Kerberos passwords and EMR application
configuration properties never reach a snapshot.
"""
from __future__ import annotations

import copy
import json

OK = ("collected", "empty")

SPECS = {
    "ecs_container_instance": ("ecs", "list_container_instances", "containerInstanceArns"),
    "ecs_task": ("ecs", "list_tasks", "taskArns"),
    "iam_saml_provider": ("iam", "list_saml_providers", "SAMLProviderList"),
    "iam_oidc_provider": ("iam", "list_open_id_connect_providers", "OpenIDConnectProviderList"),
    "emr_cluster": ("emr", "list_clusters", "Clusters"),
    "servicecatalog_portfolio": ("servicecatalog", "list_portfolios", "PortfolioDetails"),
    # Read by the rcp_policy fetcher along the account's OU path (the spec labels its service only).
    "rcp_policy": ("organizations", "list_policies_for_target", "Policies"),
}
NATIVE_IDS = {
    "ecs_container_instance": "containerInstanceArn", "ecs_task": "taskArn",
    "iam_saml_provider": "Arn", "iam_oidc_provider": "Arn",
    "emr_cluster": "ClusterArn", "servicecatalog_portfolio": "ARN", "rcp_policy": "AttachmentId",
}
GLOBAL_TYPES = {"iam_saml_provider", "iam_oidc_provider", "rcp_policy"}
READ_ACTIONS = {
    ("emr", "list_instances"),
    ("ecs", "list_clusters"), ("ecs", "describe_container_instances"), ("ecs", "describe_tasks"),
    ("iam", "get_open_id_connect_provider"),
    ("organizations", "list_roots"), ("organizations", "list_organizational_units_for_parent"),
    ("organizations", "list_accounts_for_parent"),
    ("emr", "describe_cluster"),
    ("servicecatalog", "list_constraints_for_portfolio"), ("servicecatalog", "describe_constraint"),
    ("servicecatalog", "describe_portfolio_shares"),
    ("organizations", "list_policies_for_target"), ("organizations", "describe_policy"), ("organizations", "list_parents"),
}
# Typed provider answers that prove no RCP can apply (not a visibility failure).
_RCP_ABSENT = {"AWSOrganizationsNotInUseException", "PolicyTypeNotEnabledException"}

BATCH = 100
SHARE_TYPES = ("ACCOUNT", "ORGANIZATION", "ORGANIZATIONAL_UNIT", "ORGANIZATION_MEMBER_ACCOUNT")
_CI_FIELDS = ("containerInstanceArn", "ec2InstanceId", "status", "statusReason", "agentConnected", "agentUpdateStatus",
    "runningTasksCount", "pendingTasksCount", "capacityProviderName", "registeredAt", "versionInfo")
_TASK_FIELDS = ("taskArn", "taskDefinitionArn", "clusterArn", "containerInstanceArn", "launchType", "capacityProviderName",
    "taskRoleArn", "executionRoleArn",
    "lastStatus", "desiredStatus", "group", "platformVersion", "platformFamily", "enableExecuteCommand", "availabilityZone",
    "createdAt", "startedAt", "connectivity", "healthStatus")
_ENI_DETAILS = {"subnetId", "networkInterfaceId", "privateIPv4Address", "privateDnsName", "macAddress", "ipv6Address"}
_EMR_FIELDS = ("Id", "Name", "ClusterArn", "Status", "SecurityConfiguration", "MasterPublicDnsName", "ServiceRole",
    "AutoScalingRole", "LogUri", "LogEncryptionKmsKeyId", "ReleaseLabel", "TerminationProtected", "VisibleToAllUsers",
    "AutoTerminate", "InstanceCollectionType", "NormalizedInstanceHours", "ScaleDownBehavior", "StepConcurrencyLevel",
    "OSReleaseLabel", "EbsRootVolumeSize", "CustomAmiId", "RepoUpgradeOnBoot", "Applications", "Tags",
    "PlacementGroups", "OutpostArn", "UnhealthyNodeReplacement", "ExtendedSupport")
_EC2_ATTRIBUTE_FIELDS = ("Ec2KeyName", "Ec2SubnetId", "RequestedEc2SubnetIds", "Ec2AvailabilityZone", "RequestedEc2AvailabilityZones",
    "IamInstanceProfile", "EmrManagedMasterSecurityGroup", "EmrManagedSlaveSecurityGroup", "ServiceAccessSecurityGroup",
    "AdditionalMasterSecurityGroups", "AdditionalSlaveSecurityGroups")


def _result():
    from .aws import ReadResult
    return ReadResult


def _failure_of(read, default):
    error = read.error or {}
    return error.get("cause_status", read.status), error.get("code", default)


def _finish(items, failure):
    ReadResult = _result()
    if failure:
        status, code = failure
        return ReadResult(items, "partial" if items else status, {"code": code, "cause_status": status})
    return ReadResult(items, "collected" if items else "empty")


def _child(read):
    out = {"collection_status": read.status, "items": read.items}
    if read.error:
        out["error"] = read.error
    return out


def _clusters(requests, session, region):
    # Identical to the ecs_cluster inventory read: served by the single-flight cache.
    return requests.pages(session, "ecs", region, "list_clusters", "clusterArns")


def _describe_batches(requests, session, region, operation, key, cluster, arns, argument):
    """Batched ecs Describe* (100 ARNs per call); per-ARN failures are incompleteness."""
    from .aws import _failure
    rows, failure = [], None
    for offset in range(0, len(arns), BATCH):
        chunk = arns[offset:offset + BATCH]
        try:
            response = requests.call(session, "ecs", region, operation, cluster=cluster, **{argument: chunk})
        except Exception as exc:
            error = _failure(exc)
            failure = (error.status, error.code)
            continue
        found = response.get(key)
        if not isinstance(found, list):
            failure = ("malformed", "malformed_response")
            continue
        if key == "containerInstances":
            requested = set(chunk)
            identities = [row.get("containerInstanceArn") if isinstance(row, dict) else None for row in found]
            if (any(not isinstance(value, str) or value not in requested for value in identities)
                    or len(set(identities)) != len(identities) or set(identities) != requested):
                failure = ("malformed", "ecs_container_instance_identity_incomplete")
                continue
        rows.extend(row for row in found if isinstance(row, dict))
        if response.get("failures"):
            failure = ("partial", "describe_reported_failures")
    return rows, failure


def _ecs_per_cluster(kind):
    list_operation, list_key = ("list_container_instances", "containerInstanceArns") if kind == "ecs_container_instance" else ("list_tasks", "taskArns")
    describe, describe_key, argument = (("describe_container_instances", "containerInstances", "containerInstances")
        if kind == "ecs_container_instance" else ("describe_tasks", "tasks", "tasks"))

    def fetch(requests, session, region, account):
        clusters = _clusters(requests, session, region)
        if clusters.status not in OK:
            return _result()([], clusters.status, clusters.error)
        items, failure = [], None
        for cluster in clusters.items:
            if not isinstance(cluster, str):
                failure = ("malformed", "malformed_cluster_arn")
                continue
            listed = requests.pages(session, "ecs", region, list_operation, list_key, cluster=cluster)
            if listed.status not in OK:
                failure = _failure_of(listed, "ecs_listing_incomplete")
            arns = [arn for arn in listed.items if isinstance(arn, str)]
            rows, problem = _describe_batches(requests, session, region, describe, describe_key, cluster, arns, argument)
            failure = problem or failure
            for row in rows:
                if kind == "ecs_container_instance":
                    item = {key: copy.deepcopy(row[key]) for key in _CI_FIELDS if key in row}
                else:
                    item = {key: copy.deepcopy(row[key]) for key in _TASK_FIELDS if key in row}
                    overrides = row.get("overrides") if isinstance(row.get("overrides"), dict) else {}
                    # Only the role overrides; containerOverrides (environment, command) are discarded.
                    item["overrides"] = {key: overrides[key] for key in ("taskRoleArn", "executionRoleArn") if isinstance(overrides.get(key), str)}
                    if isinstance(row.get("containers"), list):
                        item["containers"] = [{
                            "name": container.get("name"),
                            "lastStatus": container.get("lastStatus"),
                            **({"imageDigest": container["imageDigest"]} if isinstance(container.get("imageDigest"), str) else {}),
                            "managedAgents": [{"name": agent.get("name"), "lastStatus": agent.get("lastStatus")}
                                              for agent in container.get("managedAgents", [])
                                              if isinstance(agent, dict)],
                        } for container in row["containers"] if isinstance(container, dict)]
                    item["attachments"] = [{"type": a.get("type"), "status": a.get("status"),
                        "details": [d for d in a.get("details", []) if isinstance(d, dict) and d.get("name") in _ENI_DETAILS]}
                        for a in row.get("attachments", []) if isinstance(a, dict)]
                item["clusterArn"] = cluster
                item["_provenance"] = {"operation": "ecs:" + describe, "cluster": cluster, "read_only": True}
                items.append(item)
        return _finish(items, failure)
    return fetch


def _oidc_providers(requests, session, region, items):
    output = []
    for original in items:
        item = copy.deepcopy(original)
        arn = item.get("Arn")
        if isinstance(arn, str):
            detail = requests.detail(session, "iam", region, "get_open_id_connect_provider", OpenIDConnectProviderArn=arn,
                absent=("NoSuchEntity",))
            item["Provider"] = {key: detail[key] for key in ("collection_status", "absent", "error", "Url", "ClientIDList", "ThumbprintList", "CreateDate", "Tags") if key in detail}
            if detail.get("collection_status") == "collected":
                for key in ("Url", "ClientIDList"):
                    if key in detail:
                        item[key] = copy.deepcopy(detail[key])
        output.append(item)
    return output


def _emr_clusters(requests, session, region, items):
    output = []
    for original in items:
        item = {key: copy.deepcopy(original[key]) for key in ("Id", "Name", "ClusterArn", "Status", "NormalizedInstanceHours", "OutpostArn") if key in original}
        cluster_id = item.get("Id")
        if isinstance(cluster_id, str):
            detail = requests.detail(session, "emr", region, "describe_cluster", ClusterId=cluster_id)
            container = {key: detail[key] for key in ("collection_status", "absent", "error") if key in detail}
            body = detail.get("Cluster")
            if isinstance(body, dict):
                projected = {key: copy.deepcopy(body[key]) for key in _EMR_FIELDS if key in body}
                attributes = body.get("Ec2InstanceAttributes")
                if isinstance(attributes, dict):
                    projected["Ec2InstanceAttributes"] = {key: copy.deepcopy(attributes[key]) for key in _EC2_ATTRIBUTE_FIELDS if key in attributes}
                kerberos = body.get("KerberosAttributes")
                if isinstance(kerberos, dict):
                    # Presence and realm only; KDC/cross-realm/AD join passwords are never kept.
                    projected["KerberosAttributes"] = {key: kerberos[key] for key in ("Realm", "ADDomainJoinUser") if isinstance(kerberos.get(key), str)}
                if isinstance(body.get("Configurations"), list):
                    projected["ConfigurationClassifications"] = sorted({c.get("Classification") for c in body["Configurations"]
                        if isinstance(c, dict) and isinstance(c.get("Classification"), str)})
                container["Cluster"] = projected
            elif detail.get("collection_status") == "collected":
                container = {"collection_status": "malformed", "error": {"code": "missing_cluster_detail"}}
            item["Cluster"] = container
            state = item.get("Status", {}).get("State")
            if state in ("RUNNING", "WAITING"):
                collection_type = (container.get("Cluster") or {}).get("InstanceCollectionType")
                filters = {"InstanceFleetType": "MASTER"} if collection_type == "INSTANCE_FLEET" else {"InstanceGroupTypes": ["MASTER"]}
                masters = requests.pages(session, "emr", region, "list_instances", "Instances", ClusterId=cluster_id, InstanceStates=["RUNNING"], **filters)
                rows = [{key: copy.deepcopy(row[key]) for key in ("Id", "Ec2InstanceId", "PublicDnsName", "PrivateDnsName", "Status") if key in row} for row in masters.items]
                item["MasterInstances"] = {"collection_status": masters.status, "complete": masters.status in ("collected", "empty"), "items": rows}
                if masters.error: item["MasterInstances"]["error"] = masters.error
                if len(rows) == 1 and isinstance(rows[0].get("Ec2InstanceId"), str):
                    item["MasterInstances"]["PrimaryEc2InstanceId"] = rows[0]["Ec2InstanceId"]
                else:
                    dns = (container.get("Cluster") or {}).get("MasterPublicDnsName")
                    primary = [row for row in rows if isinstance(dns, str) and dns and dns in (row.get("PublicDnsName"), row.get("PrivateDnsName"))]
                    if len(primary) == 1: item["MasterInstances"]["PrimaryEc2InstanceId"] = primary[0].get("Ec2InstanceId")
        output.append(item)
    return output


def _launch_parameters(raw):
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (TypeError, ValueError):
            return None
    if not isinstance(raw, dict):
        return None
    return {key: raw[key] for key in ("RoleArn", "LocalRoleName") if isinstance(raw.get(key), str)}


def _portfolios(requests, session, region, items):
    output = []
    for original in items:
        item = copy.deepcopy(original)
        portfolio = item.get("Id")
        if not isinstance(portfolio, str):
            output.append(item)
            continue
        constraints = requests.pages(session, "servicecatalog", region, "list_constraints_for_portfolio", "ConstraintDetails", PortfolioId=portfolio)
        rows, failure = [], None
        for constraint in constraints.items:
            if not isinstance(constraint, dict):
                continue
            row = {key: constraint[key] for key in ("ConstraintId", "Type", "Owner", "ProductId", "PortfolioId") if key in constraint}
            if str(constraint.get("Type", "")).upper() == "LAUNCH" and isinstance(constraint.get("ConstraintId"), str):
                detail = requests.detail(session, "servicecatalog", region, "describe_constraint", Id=constraint["ConstraintId"])
                if detail.get("collection_status") == "collected":
                    parameters = _launch_parameters(detail.get("ConstraintParameters"))
                    if parameters is None:
                        failure = ("malformed", "malformed_launch_constraint_parameters")
                        row["ConstraintParameters"] = {"collection_status": "malformed"}
                    else:
                        row["ConstraintParameters"] = parameters
                else:
                    failure = (detail.get("collection_status", "unknown"), (detail.get("error") or {}).get("code", "launch_constraint_unavailable"))
                    row["ConstraintParameters"] = {"collection_status": detail.get("collection_status", "unknown")}
            rows.append(row)
        if constraints.status not in OK:
            failure = _failure_of(constraints, "constraint_listing_incomplete")
        item["Constraints"] = {"collection_status": constraints.status if failure is None or constraints.status not in OK else "partial", "items": rows}
        if failure:
            item["Constraints"]["error"] = {"code": failure[1], "cause_status": failure[0]}
        shares = {}
        for share_type in SHARE_TYPES:
            read = requests.pages(session, "servicecatalog", region, "describe_portfolio_shares", "PortfolioShareDetails",
                _tokens=("PageToken", "NextPageToken"), PortfolioId=portfolio, Type=share_type)
            entry = {"collection_status": read.status, "PortfolioShareDetails": [
                {key: share[key] for key in ("PrincipalId", "Type", "Accepted", "ShareTagOptions", "SharePrincipals") if key in share}
                for share in read.items if isinstance(share, dict)]}
            if read.error:
                entry["error"] = read.error
            shares[share_type] = entry
        item["Shares"] = shares
        output.append(item)
    return output


def _organization_tree(requests, session, region):
    """account id -> parent chain [{Id, Type, Name}] from the immediate parent up to the root."""
    roots = requests.pages(session, "organizations", region, "list_roots", "Roots")
    if roots.status not in OK:
        return {}, _failure_of(roots, "organization_root_unavailable")
    paths, failure, seen = {}, None, set()
    queue = [(root["Id"], [{"Id": root["Id"], "Type": "ROOT", **({"Name": root["Name"]} if isinstance(root.get("Name"), str) else {})}])
        for root in roots.items if isinstance(root, dict) and isinstance(root.get("Id"), str)]
    if len(queue) != len(roots.items) or not queue:
        failure = ("malformed", "malformed_organization_root")
    while queue:
        parent, chain = queue.pop(0)
        if parent in seen:
            failure = ("malformed", "organization_tree_cycle")
            continue
        seen.add(parent)
        accounts = requests.pages(session, "organizations", region, "list_accounts_for_parent", "Accounts", ParentId=parent)
        if accounts.status not in OK:
            failure = _failure_of(accounts, "organization_tree_incomplete")
        for account in accounts.items:
            if isinstance(account, dict) and isinstance(account.get("Id"), str):
                paths[account["Id"]] = chain
        units = requests.pages(session, "organizations", region, "list_organizational_units_for_parent", "OrganizationalUnits", ParentId=parent)
        if units.status not in OK:
            failure = _failure_of(units, "organization_tree_incomplete")
        for unit in units.items:
            if isinstance(unit, dict) and isinstance(unit.get("Id"), str):
                node = {"Id": unit["Id"], "Type": "ORGANIZATIONAL_UNIT", **({"Name": unit["Name"]} if isinstance(unit.get("Name"), str) else {})}
                queue.append((unit["Id"], [node, *chain]))
    return paths, failure


def _organization_accounts(requests, session, region, items):
    """Attach each account's observed OU parent path; an unread path is never guessed."""
    try:
        paths, failure = _organization_tree(requests, session, region)
    except Exception as exc:  # never discard the ListAccounts evidence
        from .aws import _failure
        error = _failure(exc)
        paths, failure = {}, (error.status, error.code)
    output = []
    for original in items:
        item = copy.deepcopy(original)
        chain = paths.get(item.get("Id"))
        if chain:
            item["ParentId"], item["ParentType"] = chain[0]["Id"], chain[0]["Type"]
            item["ParentPath"] = [item["Id"], *[node["Id"] for node in chain]]
            item["OrganizationPath"] = copy.deepcopy(chain)
            item["Parents"] = {"collection_status": "collected", "items": [copy.deepcopy(chain[0])]}
        elif failure:
            item["Parents"] = {"collection_status": failure[0], "error": {"code": failure[1]}}
        else:
            item["Parents"] = {"collection_status": "unknown", "error": {"code": "account_not_found_in_organization_tree"}}
        output.append(item)
    return output


def _rcp_policies(requests, session, region, account):
    """Resource control policies attached to the account, its OUs and the root: one row per (policy, target).

    TargetId is the real attachment target, so the evaluator applies each RCP at its own organization level.
    Same path walk as SCPs (list_parents is shared through the request cache); never inferred."""
    import re
    from .aws import _policy
    ReadResult = _result()
    target, path, seen, rows, documents, failure = {"Id": account, "Type": "ACCOUNT"}, [], {account}, [], {}, None
    while True:
        path.append(target)
        attached = requests.pages(session, "organizations", region, "list_policies_for_target", "Policies",
            TargetId=target["Id"], Filter="RESOURCE_CONTROL_POLICY")
        code = (attached.error or {}).get("code")
        if attached.status not in OK:
            if code in _RCP_ABSENT and not rows:
                return ReadResult([], "empty", {"code": code})
            failure = _failure_of(attached, "rcp_attachment_collection_incomplete")
            break
        for summary in attached.items:
            if not isinstance(summary, dict) or not isinstance(summary.get("Id"), str):
                failure = ("malformed", "malformed_rcp_policy")
                continue
            pid = summary["Id"]
            if pid not in documents:
                detail = requests.detail(session, "organizations", region, "describe_policy", PolicyId=pid)
                content = (detail.get("Policy") or {}).get("Content") if isinstance(detail.get("Policy"), dict) else None
                if detail.get("collection_status") not in (None, "collected"):
                    failure = (detail["collection_status"], (detail.get("error") or {}).get("code", "rcp_document_unavailable"))
                    content = None
                elif content is None:
                    failure = ("malformed", "missing_rcp_document")
                else:
                    content = _policy(content)
                    if not isinstance(content, dict) or not isinstance(content.get("Statement"), (list, dict)):
                        failure, content = ("malformed", "malformed_rcp_document"), None
                documents[pid] = content
            rows.append({"Id": pid, "Name": summary.get("Name"), "Arn": summary.get("Arn"), "AwsManaged": summary.get("AwsManaged"),
                "Type": "RESOURCE_CONTROL_POLICY", "TargetId": target["Id"], "TargetType": target["Type"],
                "AttachmentId": pid + "@" + target["Id"], "Detail": {"collection_status": "collected" if documents[pid] is not None else "unknown",
                    "Policy": {"Content": copy.deepcopy(documents[pid])}}})
        if target["Type"] == "ROOT":
            break
        parents = requests.pages(session, "organizations", region, "list_parents", "Parents", ChildId=target["Id"])
        if parents.status not in OK:
            failure = _failure_of(parents, "organization_parent_visibility_incomplete")
            break
        parent = parents.items[0] if len(parents.items) == 1 and isinstance(parents.items[0], dict) else {}
        parent_id, parent_type = parent.get("Id"), parent.get("Type")
        if not (isinstance(parent_id, str) and parent_type in {"ROOT", "ORGANIZATIONAL_UNIT"} and re.fullmatch(
                r"r-[a-z0-9]+" if parent_type == "ROOT" else r"ou-[a-z0-9]+-[a-z0-9]+", parent_id)):
            failure = ("malformed", "malformed_organization_parent")
            break
        if parent_id in seen:
            failure = ("malformed", "organization_parent_cycle")
            break
        seen.add(parent_id)
        target = {"Id": parent_id, "Type": parent_type}
    complete = failure is None and path[-1]["Type"] == "ROOT"
    for row in rows:
        row["ParentPath"] = copy.deepcopy(path)
        row["InheritanceComplete"] = complete
    if failure:
        return ReadResult(rows, "partial" if rows else failure[0], {"code": failure[1], "cause_status": failure[0]})
    return ReadResult(rows, "collected" if rows else "empty")


FETCHERS = {
    "rcp_policy": _rcp_policies,
    "ecs_container_instance": _ecs_per_cluster("ecs_container_instance"),
    "ecs_task": _ecs_per_cluster("ecs_task"),
}
ENRICHERS = {
    "iam_oidc_provider": _oidc_providers,
    "emr_cluster": _emr_clusters,
    "servicecatalog_portfolio": _portfolios,
    "organization_account": _organization_accounts,
}
