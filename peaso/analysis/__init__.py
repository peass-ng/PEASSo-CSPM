"""Offline defensive IAM, least-privilege, exposure, and network projections."""
from __future__ import annotations

from .common import FRAMEWORKS, RANK, analysis_context, finding, frameworks_for, node, source, with_analysis_context
from .iam import IAM_TYPES, azure_assignment_reviews, build_iam, review_findings
from .network import NETWORK_TYPES, build_network, exposure_findings
from .projection import collapse_unreferenced_definitions, expand_projected_node, filter_graph, page_graph, project_graph, stored_aggregate_members
from .reachability import REACHABILITY_TYPES, evaluate_reachability, evaluate_reachability_batch, evaluate_reachability_matrix, evaluate_reachability_grid, network_snapshot
from .internet_exposure import EXPOSURE_TYPES, annotate_network, federated_findings, internet_findings

def __getattr__(name):
    if name not in {'REQUIRED_TYPES', 'ANALYSIS_CHECKS'}:
        raise AttributeError(f'module {__name__!r} has no attribute {name!r}')
    from importlib import import_module
    metadata = import_module('.catalog', __name__)
    # Cache only after the complete original metadata initialization succeeds.
    globals().setdefault('REQUIRED_TYPES', metadata.REQUIRED_TYPES)
    globals().setdefault('ANALYSIS_CHECKS', metadata.ANALYSIS_CHECKS)
    return globals()[name]


def __dir__():
    return sorted(set(globals()) | {'REQUIRED_TYPES', 'ANALYSIS_CHECKS'})


def privesc_required_types(provider):
    """Collection types the privesc evaluator needs for a provider: the floor above plus every supported
    type its model reads (see privesc_requirements). Strings that are not collection types are dropped."""
    from peaso.collectors import supported_types
    from .privesc_requirements import privesc_collection_types
    from peaso.analysis import REQUIRED_TYPES
    floor = set(REQUIRED_TYPES.get(provider, {}).get("privesc", []))
    return sorted(floor | (privesc_collection_types(provider) & set(supported_types(provider))))


# These projections can only ask a person to judge a declaration. Keep their
# identity for archived reports, but exclude them from hosted scan selection and
# the public runnable catalog.
MANUAL_ONLY_ANALYSIS_CHECK_IDS = frozenset({
    "analysis.grant_review", "analysis.inactive_identity", "analysis.network_review",
})



@with_analysis_context
def analyze_findings(snapshot, resources=None, index=None, *, include_manual_only=True, categories=None,
                     related_snapshots=()):
    """Run only the requested projection categories; None retains the full library default.

    Principal exposure and permission coverage share the native grant review.
    Its findings are filtered after the existing exception handling and deduplication.
    Independent exposure projections and inventory coverage are dispatched separately.
    """
    selected = {"least_privilege", "exposure"} if categories is None else set(categories)
    from peaso.principal_exposure import exposed_privileged_findings
    if resources is None:
        from peaso.snapshot import resources as snapshot_resources
        resources = snapshot_resources(snapshot)
    results = []
    for resource in resources if selected & {"least_privilege", "exposure"} else ():
        try:
            results.extend(review_findings(snapshot, [resource], include_manual_only=include_manual_only))
            if include_manual_only and "exposure" in selected:
                results.extend(exposure_findings(snapshot, [resource]))
        except (TypeError, AttributeError, KeyError, ValueError, IndexError):
            results.append(finding(snapshot, resource, "least_privilege", "analysis.coverage",
                "Malformed native fact requires review", "info",
                {"source": source(snapshot, resource, "data"), "reason": "malformed_native_fact", "risk_state": "unknown"}, status="UNKNOWN"))
    # Azure least-privilege review is per assignment (cross-resource: assignment -> definition by GUID).
    if include_manual_only and "least_privilege" in selected:
        try:
            results.extend(azure_assignment_reviews(snapshot, resources))
        except (TypeError, AttributeError, KeyError, ValueError, IndexError):
            placeholder = {"id": "inventory:azure_assignment_reviews", "type": "inventory", "scope": (snapshot["scopes"] or ["global"])[0],
                           "provider": snapshot["provider"], "service": "iam", "data": {}}
            results.append(finding(snapshot, placeholder, "least_privilege", "analysis.coverage", "Assignment grant review failed on malformed facts", "info",
                {"reason": "malformed_native_fact", "risk_state": "unknown"}, status="UNKNOWN"))
    for derived_findings in (internet_findings, federated_findings, exposed_privileged_findings) if "exposure" in selected else ():
        try:
            results.extend(derived_findings(snapshot, resources, related_snapshots=related_snapshots)
                           if derived_findings is internet_findings else derived_findings(snapshot, resources))
        except (TypeError, AttributeError, KeyError, ValueError, IndexError):
            placeholder = {"id": "inventory:" + derived_findings.__name__, "type": "inventory", "scope": (snapshot["scopes"] or ["global"])[0],
                           "provider": snapshot["provider"], "service": "exposure", "data": {}}
            results.append(finding(snapshot, placeholder, "exposure", "analysis.internet_exposure", "Exposure analysis failed on malformed facts", "info",
                {"reason": "malformed_native_fact", "risk_state": "unknown"}, status="UNKNOWN"))
    # Unknown coverage never becomes a clean bill of health. Empty, completely
    # enumerated collections are not equivalent to missing/denied collections.
    expected = ()
    if "least_privilege" in selected:
        from peaso.analysis import REQUIRED_TYPES
        expected = REQUIRED_TYPES[snapshot["provider"]]["least_privilege"]
    for scope in snapshot["scopes"] if "least_privilege" in selected else ():
        # An account-global AWS inventory (IAM) is collected once for the account and covers every
        # regional scope of that account; only its absence or failure is a gap.
        account = scope.split("/", 1)[0] if snapshot["provider"] == "aws" else None
        present = {c["type"]: c for c in snapshot["collections"] if account and c.get("global") is True
                   and c.get("account_id") == account and c["scope"].split("/", 1)[0] == account}
        present.update({c["type"]: c for c in snapshot["collections"] if c["scope"] == scope})
        if snapshot["provider"] == "azure":
            # Entra inventories live at the tenant scope and per-parent reads (a site's
            # config, a group's members) below the subscription; both cover this scope.
            prefix = scope.casefold().rstrip("/") + "/"
            for c in snapshot["collections"]:
                if c["type"] in present and c["scope"] == scope:
                    continue
                if c["scope"].startswith("/tenants/") or c["scope"].casefold().startswith(prefix):
                    held = present.get(c["type"])
                    if held is None or held.get("status") in {"collected", "empty"}:
                        present[c["type"]] = c
        gaps =[{"type": kind, "status": present.get(kind, {}).get("status", "not_collected")}
                for kind in expected if present.get(kind, {}).get("status") not in {"collected", "empty"}]
        if gaps:
            placeholder = {"id": "inventory", "type": "inventory", "scope": scope,
                           "provider": snapshot["provider"], "service": "iam", "data": {}}
            gap_status = "DENIED" if any(gap["status"] == "denied" for gap in gaps) else "UNKNOWN"
            results.append(finding(snapshot, placeholder, "least_privilege", "analysis.coverage",
                "Analysis inventory context incomplete", "info", {"gaps": gaps, "risk_state": "unknown"}, status=gap_status))
    from .exposure_dedup import deduplicate_principal_exposure
    return sorted((f for f in deduplicate_principal_exposure(results) if f["category"] in selected),
                  key=lambda f: (RANK[f["severity"]], f["check_id"], f["scope"], f["resource_id"]))


@with_analysis_context
def build_graphs(snapshot, resources, index=None, *, max_nodes=500, collapse_unreferenced=False, graph_kinds=None):
    """collapse_unreferenced: the caller folds edge-less definition nodes (projection.collapse_unreferenced_definitions),
    so their IAM cards are not built."""
    from functools import partial
    from .projection import UNREFERENCED_DEFINITION_TYPES
    defer = frozenset(UNREFERENCED_DEFINITION_TYPES.get(snapshot.get("provider"), ())) if collapse_unreferenced else frozenset()
    graphs = {}
    for kind, builder in (("network", build_network), ("iam", partial(build_iam, defer_types=defer))):
        if graph_kinds is not None and kind not in graph_kinds:
            continue
        try:
            graph = builder(snapshot, resources)
        except (TypeError, AttributeError, KeyError, ValueError, IndexError):
            # Malformed provider facts must not suppress the whole report or
            # turn lack of modeled relationships into a safe-access assertion.
            graph = {"nodes": [], "edges": [], "status": "partial", "uncertainty": "Some native facts are malformed; cross-resource associations may be incomplete"}
            merged_nodes, merged_edges = {}, {}
            for resource in resources:
                try:
                    partial = builder(snapshot, [resource])
                except (TypeError, AttributeError, KeyError, ValueError, IndexError):
                    partial = {"nodes": [node(resource)], "edges": []}
                    partial["nodes"][0]["evidence"]["analysis_status"] = "malformed"
                for current in partial["nodes"]:
                    evidence = current.get("evidence", {})
                    if current["id"] not in merged_nodes or evidence.get("native_resource") or evidence.get("native_resource_ref"):
                        merged_nodes[current["id"]] = current
                merged_edges.update({e["id"]: e for e in partial["edges"]})
            graph.update(nodes=list(merged_nodes.values()), edges=list(merged_edges.values()))
        if kind == "network":
            try:
                graph = annotate_network(graph, snapshot, resources)
            except (TypeError, AttributeError, KeyError, ValueError, IndexError):
                graph = {**graph, "status": "partial"}
        # max_nodes=None keeps the complete graph (the engine's report path) without a projection pass.
        graphs[kind] = project_graph(graph, max_nodes) if max_nodes is not None else {
            **graph, "projection": {"collapsed": False, "node_count": len(graph["nodes"]), "edge_count": len(graph["edges"])}}
    return graphs


def analyze(snapshot, categories=None, *, related_snapshots=()):
    from peaso.snapshot import resources, validate
    snapshot = validate(snapshot, read_only=True)
    inventory = resources(snapshot)
    with analysis_context(snapshot):
        findings = analyze_findings(snapshot, inventory, related_snapshots=related_snapshots)
        graphs = build_graphs(snapshot, inventory)
    selected = set(categories) if categories is not None else {"least_privilege", "exposure", "iam_graph", "network"}
    return {"findings": [f for f in findings if f["category"] in selected],
            "graphs": {"network": graphs["network"] if "network" in selected else {"nodes": [], "edges": []},
                       "iam": graphs["iam"] if "iam_graph" in selected else {"nodes": [], "edges": []}},
            "resources": inventory}


__all__ = ["analyze", "analyze_findings", "analysis_context", "build_graphs", "collapse_unreferenced_definitions", "filter_graph", "project_graph", "page_graph", "expand_projected_node", "stored_aggregate_members", "ANALYSIS_CHECKS", "REQUIRED_TYPES", "privesc_required_types", "evaluate_reachability", "evaluate_reachability_batch", "evaluate_reachability_matrix", "evaluate_reachability_grid", "network_snapshot", "REACHABILITY_TYPES"]
