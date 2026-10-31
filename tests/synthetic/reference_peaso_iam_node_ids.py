"""Original IAM graph builder retained as a performance/parity reference."""
from types import FunctionType
from peaso.analysis.iam import (
    IAM_TYPES, MANAGED_SCOPE, _attach_card, _managed_aliases, _resource_policy_documents, as_list, defaultdict, externality, native_id, node, node_id, principals, relationship, source, stable_id,
)

def _reference_build_iam(snapshot, resources, *, defer_types=()):
    """defer_types: native definition types whose cards are built only when the node gets an edge (the
    engine folds edge-less definitions into aggregates, so their cards would be discarded)."""
    selected = [r for r in resources if r["type"] in IAM_TYPES or list(principals(r))
                or (r["type"] == "pod" and r["data"].get("spec", {}).get("serviceAccountName"))]
    alias, merged = _managed_aliases(snapshot, selected)
    ident = lambda r: alias.get(node_id(r), node_id(r))
    # Non-canonical copies of a deduplicated definition: same declared grants, folded into one node.
    folded = {node_id(r) for canonical, same in merged.values() for r in same if r is not canonical}
    nodes = {}
    for r in selected:
        if node_id(r) in folded:
            continue
        current = nodes[ident(r)] = node(r)
        if ident(r) in merged:
            canonical, same = merged[ident(r)]
            current.update(id=ident(r), scope=MANAGED_SCOPE, provider_managed=True, native_scope=canonical["scope"],
                           scope_refs={s["scope"]: s.get("id", native_id(s)) for s in same})
    edges = []
    observed_bindings = {}
    lookup = {}
    deferred = {}
    for resource in selected:  # folded copies included: their per-scope names resolve to the canonical node
        data = resource["data"]
        meta = data.get("metadata", {})
        names = [native_id(resource), data.get("UserName"), data.get("GroupName"), data.get("RoleName"), data.get("name"), data.get("email"), data.get("id"),
                 f"{meta.get('namespace', '_cluster')}/{meta['name']}" if meta.get("name") else None]
        for name in names:
            if name:
                lookup[(resource["scope"], resource["type"], str(name))] = ident(resource)
    selected = [r for r in selected if node_id(r) not in folded]
    by_kind_name = defaultdict(list)  # (kind, name) -> [(scope, node id)]: O(1) cross-scope resolution
    for (lscope, lkind, lname), value in lookup.items():
        by_kind_name[(lkind, lname)].append((lscope, value))

    principal_scopes = defaultdict(set)

    def reference(resource, kind, rid, *, refscope=None, classification="unknown"):
        scope = refscope or resource["scope"]
        key = (scope, kind, str(rid))
        target = lookup.get(key)
        if target:
            return target
        if kind == "principal":
            raw = str(rid)
            if raw.startswith("system:serviceaccount:"):
                parts = raw.split(":")
                alias = f"{parts[2]}/{parts[3]}" if len(parts) == 4 else raw
                principal_kinds = {"serviceaccount"}
            else:
                alias = raw.split(":", 1)[1] if raw.startswith(("user:", "group:", "serviceAccount:")) else raw
                principal_kinds = {"iam_user", "iam_role", "iam_group", "service_account", "directory_user", "directory_group", "directory_service_principal"}
            candidates = {value for pkind in principal_kinds for _, value in by_kind_name.get((pkind, alias), ())}
            if len(candidates) == 1:
                return candidates.pop()
        if (kind == "iam_policy" and str(rid).startswith("arn:")) or kind in {"role_definition", "iam_role"}:
            candidates = {value for _, value in by_kind_name.get((kind, str(rid)), ())}
            if len(candidates) == 1:
                return candidates.pop()
        if kind == "role_definition" and snapshot["provider"] == "azure" and "/roledefinitions/" in str(rid).lower():
            # Assignments cite a scope-qualified definition ID; built-ins are collected
            # once at "/" and keyed by their GUID name. Prefer a same-scope custom copy.
            found = by_kind_name.get((kind, _azure_role_guid(rid)), ())
            candidates = {value for lscope, value in found if lscope == scope} or {value for _, value in found}
            if len(candidates) == 1:
                return candidates.pop()
        if _managed_name(snapshot["provider"], kind, rid):
            scope = MANAGED_SCOPE  # uncollected provider-managed definition: one reference node, not one per scope
        principal = kind in PRINCIPAL_KINDS and snapshot["provider"] in PRINCIPAL_GLOBAL_PROVIDERS
        if principal:
            # A cloud principal identifier names one identity wherever it is granted: one reference node;
            # the scope of each grant stays on its edge evidence (and in referenced_scopes).
            scope = PRINCIPAL_SCOPE
        target = stable_id(snapshot["provider"], scope, kind, rid)
        annotation = {"state": "unknown" if classification == "unknown" else
                      "observed" if classification == "allowlisted" else "conditional",
                      "classification": classification}
        current = nodes.get(target)
        if current is None:
            nodes[target] = {"id": target, "label": str(rid), "resource_id": str(rid),
                "type": kind, "provider": snapshot["provider"], "scope": scope,
                "evidence": {"inventory_status": "reference_only"}, "risk_annotations": [annotation]}
        elif principal and annotation not in current["risk_annotations"]:
            current["risk_annotations"].append(annotation)  # classification can depend on per-grant tenant facts
        if principal:
            principal_scopes[target].add(str(resource["scope"]))
        return target

    for resource in selected:
        src, data = ident(resource), resource["data"]
        card = nodes[src]
        if resource["type"] in defer_types:
            deferred[src] = resource
        else:
            _attach_card(snapshot, card, resource)
        for i, group in enumerate(as_list(data.get("GroupList"))):
            dst = reference(resource, "iam_group", group)
            edges.append(relationship(src, dst, "member_of", source(snapshot, resource, f"GroupList[{i}]")))
        for i, member in enumerate(as_list(data.get("members"))):
            if isinstance(member, dict):
                member = member.get("id", member.get("name"))
            if member:
                dst = reference(resource, "principal", member)
                edges.append(relationship(dst, src, "member_of", source(snapshot, resource, f"members[{i}]")))
        for i, policy in enumerate(as_list(data.get("AttachedManagedPolicies"))):
            if isinstance(policy, dict) and policy.get("PolicyArn"):
                dst = reference(resource, "iam_policy", policy["PolicyArn"])
                edges.append(relationship(src, dst, "attached_policy", source(snapshot, resource, f"AttachedManagedPolicies[{i}]")))
        for path, doc in _resource_policy_documents(resource):
            if path == "AssumeRolePolicyDocument" or path in {"Document", "PolicyDocument"}:
                continue
            dst = reference(resource, "policy_document", stable_id(native_id(resource), path))
            # Schema 1.1 references the document inside the native resource (source.resource_id + path);
            # peaso.engine.expand_report() restores evidence.native_document.
            nodes[dst]["evidence"] = {"source": source(snapshot, resource, path), "native_document_ref": path}
            edges.append(relationship(src, dst, "inline_policy", source(snapshot, resource, path)))
        props = data.get("properties", data)
        if resource["type"] == "pod" and data.get("spec", {}).get("serviceAccountName"):
            name = f"{data.get('metadata', {}).get('namespace', 'default')}/{data['spec']['serviceAccountName']}"
            dst = reference(resource, "serviceaccount", name)
            edges.append(relationship(src, dst, "workload_identity", source(snapshot, resource, "spec.serviceAccountName")))
        if resource["type"] == "directory_membership" and "/groups/" in resource["scope"]:
            group_id = resource["scope"].split("/groups/", 1)[1]
            group = reference(resource, "principal", group_id)
            member = reference(resource, "principal", data.get("id", native_id(resource)))
            edges.append(relationship(member, group, "member_of", source(snapshot, resource, "id")))
        if props.get("roleDefinitionId"):
            definition_kind = "directory_role_definition" if resource["type"] == "directory_role_assignment" else "role_definition"
            dst = reference(resource, definition_kind, props["roleDefinitionId"])
            edges.append(relationship(src, dst, "role_definition", source(snapshot, resource, "properties.roleDefinitionId")))
        if resource["type"] in {"role_assignment", "directory_role_assignment"}:
            scope = props.get("scope", props.get("directoryScopeId"))
            if scope:
                dst = reference(resource, "authorization_scope", scope)
                nodes[dst]["evidence"] = {"source": source(snapshot, resource, "properties.scope"),
                    "native_scope": scope, "effective_access": "unknown"}
                edges.append(relationship(src, dst, "declared_scope", source(snapshot, resource, "properties.scope")))
        if resource["provider"] == "gcp":
            for i, binding in enumerate(as_list(data.get("bindings"))):
                if isinstance(binding, dict) and binding.get("role"):
                    dst = reference(resource, "iam_role", binding["role"])
                    edges.append(relationship(src, dst, "role_definition", source(snapshot, resource, f"bindings[{i}].role")))
        role = data.get("roleRef", {})
        if role.get("name"):
            kind = "clusterrole" if role.get("kind") == "ClusterRole" else "role"
            name = f"{data.get('metadata', {}).get('namespace', '_cluster')}/{role['name']}" if kind == "role" else f"_cluster/{role['name']}"
            refscope = resource["scope"]
            if kind == "clusterrole":
                candidates = by_kind_name.get((kind, name), [])
                if len(candidates) == 1:
                    refscope = candidates[0][0]
            dst = reference(resource, kind, name, refscope=refscope)
            edges.append(relationship(src, dst, "role_binding", source(snapshot, resource, "roleRef")))
        for identity, path, fact, kind in principals(resource):
            classification = externality(snapshot, identity, tenant=fact.get("tenantId"))
            everyone = classification in {"public", "everyone_authenticated"}
            dst = reference(resource, "everyone" if everyone else "principal", identity, classification=classification)
            risk_state = "unknown" if classification == "unknown" else "conditional" if classification != "allowlisted" else "observed"
            evidence = {"source": source(snapshot, resource, path), "native_fact": fact,
                "classification": classification, "risk_state": risk_state, "effective_access": "unknown"}
            kind = "trust" if "AssumeRolePolicyDocument" in path else "declared_grant"
            edges.append(relationship(dst, src, kind, evidence))
            observed_bindings.setdefault(dst, []).append({"resource_node": src, "type": kind,
                "source": evidence["source"], "native_fact": fact})
            if classification in {"external", "public", "everyone_authenticated"}:
                card["risk_annotations"].append({"state": "conditional", "type": "external_trust", "classification": classification})
    if deferred:
        linked = {e["source"] for e in edges} | {e["target"] for e in edges}
        for nid, resource in deferred.items():
            if nid in linked:
                _attach_card(snapshot, nodes[nid], resource)
    # Propagate only a conditional review marker along observed attachment /
    # membership facts. This is not transitive permission or chain discovery.
    for nid, facts in observed_bindings.items():
        card = nodes[nid].setdefault("card", {"source_grants": [], "grant_count": 0, "trust": None,
            "usage": {"observations": {}, "window": snapshot.get("metadata", {}).get("usage_window", snapshot.get("metadata", {}).get("activity_window")),
                      "completeness": "unknown", "safe_to_remove": False,
                      "uncertainty": "Principal telemetry is not established by policy or binding evidence"},
            "effective_access": "unknown"})
        card["observed_bindings"] = facts
    declared_high = {nid for nid, current in nodes.items()
                     if any(x.get("type") == "high_risk_grant" and x.get("state") == "conditional"
                            for x in current.get("risk_annotations", []))}
    for edge in edges:
        if edge["type"] not in {"attached_policy", "member_of", "role_definition", "role_binding", "declared_grant"}:
            continue
        target = nodes[edge["target"]]
        if edge["target"] in declared_high:
            nodes[edge["source"]]["risk_annotations"].append({"state": "derived", "type": "high_risk_grant",
                "basis": edge["id"], "effective_access": "unknown"})
            # A reference, not a copy: the grants live once, on source_node's card (grant_count of them;
            # the complete list via the source_node card.detail_ref).
            target_card = target.get("card", {})
            nodes[edge["source"]].setdefault("card", {}).setdefault("referenced_grants", []).append(
                {"source_node": target["id"], "edge_ref": edge["id"],
                 "grant_count": target_card.get("grant_count", len(target_card.get("source_grants", [])))})
    for nid, scopes in principal_scopes.items():
        nodes[nid]["referenced_scopes"] = sorted(scopes)
    return {"nodes": list(nodes.values()), "edges": edges,
            "semantics": "Observed declarations and conditional risk review; no effective-access or exploit-chain claims"}


def original_builder():
    from peaso.analysis import iam
    builder = FunctionType(_reference_build_iam.__code__, vars(iam), 'build_iam',
                        _reference_build_iam.__defaults__, closure=_reference_build_iam.__closure__)
    builder.__kwdefaults__ = dict(_reference_build_iam.__kwdefaults__)
    return builder
