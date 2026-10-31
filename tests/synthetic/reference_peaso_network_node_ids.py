"""Exact predecessor topology builder for complete network workflow parity."""
from types import FunctionType

def original_builder():
    from peaso.analysis import network
    return FunctionType(literal_build_network.__code__, vars(network), 'build_network')


def literal_build_network(snapshot, resources):
    selected = [r for r in resources if r["type"] in NETWORK_TYPES]
    nodes = {node_id(r): node(r) for r in selected}
    from .network_observations import network_observations
    for resource in selected:
        observations = network_observations(resource["data"])
        if observations:
            nodes[node_id(resource)]["network_attributes"] = observations
    lookup = {}
    azure_ids = {}
    endpoint_services = {}
    k8s_pods, k8s_owners, pod_context_gaps = {}, {}, set()
    pod_status = {c["scope"]: c["status"] for c in snapshot["collections"] if c["type"] == "pod"}
    for resource in selected:
        data = _object(resource["data"])
        if resource["type"] in {"rds_instance", "rds_cluster", "lambda_function", "eks_cluster", "gke_cluster"} and not _managed_network_facts(resource):
            nodes[node_id(resource)]["evidence"]["placement_status"] = "unknown"
            nodes[node_id(resource)]["evidence"]["placement_reason"] = "native_network_attachment_or_endpoint_facts_missing"
        if resource["provider"] == "k8s":
            cluster, namespace = _k8s_context(snapshot, resource)
            if resource["type"] == "pod" and cluster and namespace:
                k8s_pods.setdefault((resource["scope"], cluster, namespace), []).append(resource)
            elif resource["type"] == "pod":
                pod_context_gaps.add(resource["scope"])
            if cluster and (resource["type"] == "node" or resource["type"] == "pod" and namespace):
                for alias in {str(native_id(resource)), data.get("id") if isinstance(data.get("id"), str) else None} - {None}:
                    k8s_owners.setdefault((resource["scope"], cluster, alias), []).append(resource)
        aliases = [native_id(resource), data.get("id"), data.get("selfLink"), data.get("name"),
                   _object(data.get("metadata")).get("name")]
        if resource["provider"] == "aws":
            aliases += [data.get(key) for key in ("FileSystemId", "Id", "SubnetGroupName", "CacheSubnetGroupName", "ClusterSubnetGroupName", "DBSubnetGroupName", "EndpointConfigName", "ModelName", "Arn", "arn", "ARN")]
            if resource["type"] == "vpc_endpoint_service" and isinstance(data.get("ServiceName"), str):
                endpoint_services.setdefault(data["ServiceName"], []).append(node_id(resource))
        if resource["provider"] == "gcp":
            for alias in list(aliases):
                if normalized := gcp_ref(alias, resource["type"], resource):
                    aliases.append(normalized[0])
        for alias in aliases:
            if alias:
                if resource["provider"] == "azure" and isinstance(alias, str) and alias.startswith("/"):
                    azure_ids.setdefault((resource["type"], alias.casefold()), set()).add(node_id(resource))
                lookup[(resource["scope"].casefold() if resource["provider"] == "azure" else resource["scope"],
                        resource["type"], str(alias).casefold() if resource["provider"] == "azure" else str(alias))] = node_id(resource)
    edges = []
    pod_index = _K8sPodIndex(k8s_pods)
    for resource in selected:
        src = node_id(resource)
        if resource["provider"] == "gcp" and resource["type"] == "instance":
            for i, interface in enumerate(as_list(resource["data"].get("networkInterfaces"))):
                if not isinstance(interface, dict):
                    continue
                rid = f"{native_id(resource)}/networkInterfaces/{i}"
                dst = stable_id("gcp", resource["scope"], "network_interface", rid)
                nodes[dst] = {"id": dst, "native_id": rid, "resource_id": gcp_interface_resource_id(resource, i),
                    "label": str(interface.get("name", f"interface {i}")), "type": "network_interface",
                    "provider": "gcp", "scope": resource["scope"],
                    "evidence": {"native_resource": interface, "source": source(snapshot, resource, f"networkInterfaces[{i}]")}}
                edges.append(relationship(src, dst, "attached_interface", source(snapshot, resource, f"networkInterfaces[{i}]")))
                embedded = {**resource, "type": "network_interface", "native_id": rid, "data": interface}
                for path, kind, ref, scope, relation in references(embedded):
                    scope = scope or resource["scope"]
                    target = lookup.get((scope, kind, str(ref))) or stable_id("gcp", scope, kind, ref)
                    nodes.setdefault(target, {"id": target, "label": str(ref), "native_id": str(ref), "resource_id": None,
                        "type": kind, "provider": "gcp", "scope": scope, "evidence": {"inventory_status": "reference_only"}})
                    edges.append(relationship(dst, target, relation, source(snapshot, resource, f"networkInterfaces[{i}].{path}")))
        for path, kind, rid, scope, relation in references(resource):
            scope = scope or resource["scope"]
            key = (scope.casefold() if resource["provider"] == "azure" else scope,
                   kind, str(rid).casefold() if resource["provider"] == "azure" else str(rid))
            dst = lookup.get(key)
            if resource["provider"] == "azure" and dst is None:
                matches = azure_ids.get((kind, str(rid).casefold()), set())
                if len(matches) == 1:
                    dst = next(iter(matches))
            if kind == "endpoint_service_reference" and len(endpoint_services.get(rid, [])) == 1:
                dst = endpoint_services[rid][0]
            if dst is None:
                dst = stable_id(resource["provider"], scope, kind, rid)
                nodes.setdefault(dst, {"id": dst, "label": str(rid), "resource_id": None,
                    "native_id": str(rid), "type": kind, "provider": resource["provider"], "scope": scope,
                    "evidence": {"inventory_status": "reference_only", "uncertainty": "Referenced resource was not collected in this scope"}})
            if dst != src:
                edges.append(relationship(src, dst, relation, source(snapshot, resource, path)))
        if resource["provider"] == "k8s" and resource["type"] in {"service", "networkpolicy"}:
            _k8s_workload_selector(snapshot, resource, k8s_pods, nodes, edges, pod_status, pod_context_gaps, pod_index)
        if resource["provider"] == "k8s" and resource["type"] == "network_interface":
            _k8s_interface(snapshot, resource, k8s_owners, nodes, edges)
        for path, rule, semantics in public_rules(resource):
            dst = stable_id(resource["provider"], resource["scope"], "internet_source")
            nodes.setdefault(dst, {"id": dst, "label": "Unrestricted source selector", "type": "internet_source",
                "provider": resource["provider"], "scope": resource["scope"], "evidence": {"reachability": "unknown"}})
            edges.append(relationship(dst, src, "rule_candidate", {"source": source(snapshot, resource, path),
                "native_rule": rule, "uncertainty": semantics,
                "reachability": "unknown", "telemetry": "not_collected"}, layer="modeled_rule", confidence="low"))
    _k8s_storage_links(snapshot, selected, nodes, edges)
    from .k8s_network_links import add_links
    add_links(snapshot, selected, nodes, edges, _k8s_context)
    _ecs_service_tasks(snapshot, selected, edges)
    # The managed-service and generic attachment readers can observe the same
    # native field. Graph identities (and the AI evidence database) are unique.
    edges = list({edge["id"]: edge for edge in edges}.values())
    # Parent IDs are layout hints derived from observed containment only.
    # Policies/peering/route adjacency cannot establish workload containment.
    parent_ranks = {"subnet": 0, "subnetwork": 0, "namespace": 0, "vpc": 1, "vnet": 1, "network": 1}
    candidates = {}
    for edge in edges:
        if edge["type"] == "contains":
            candidates.setdefault(edge["target"], []).append((0, edge["source"], edge["id"]))
        elif edge["type"] in {"associated_with", "contained_in_namespace"}:
            target = nodes[edge["target"]]
            if target["type"] in parent_ranks:
                candidates.setdefault(edge["source"], []).append((parent_ranks[target["type"]], target["id"], edge["id"]))
    for nid, current in nodes.items():
        # Synthetic selector nodes have no native cloud identity.
        current.setdefault("native_id", None)
        current.setdefault("native_kind", current["type"])
        current.setdefault("provider_specific", {"native_kind": current["type"]})
        current["display_group"] = "namespace" if current["type"] == "namespace" else "network" if current["type"] in {"vpc", "vnet", "network"} else "resource"
        parents = candidates.get(nid, [])
        if parents:
            best_rank = min(x[0] for x in parents)
            best = {parent for rank, parent, _ in parents if rank == best_rank}
            if len(best) == 1:
                current["parent_id"] = next(iter(best))
                current["parent_edge_refs"] = sorted(eid for rank, parent, eid in parents if rank == best_rank)
            else:
                current["parent_candidates"] = sorted(best)
        if current["provider"] == "gcp" and current["type"] == "network":
            current["provider_specific"]["network_scope"] = "global"
    return {"nodes": sorted(nodes.values(), key=lambda row: row["id"]),
            "edges": sorted(edges, key=lambda row: row["id"]),
            "semantics": "Structural inventory and conditional rule candidates; telemetry and routed reachability are not inferred"}
