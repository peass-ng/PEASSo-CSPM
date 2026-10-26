"""Read-only, bounded effective-route and security-admin inventories."""
from __future__ import annotations

from .azure_nsg_ingress_native import NetworkQueries

_NATIVE_PAGES = NetworkQueries.pages


def collect(reader, transport, scopes, wanted):
    if not {"effective_route", "security_admin_rule"}.intersection(wanted):
        return
    from .azure import AzureReadError, ordered_parallel

    jobs = []
    proofs = {}
    for scope in scopes:
        for kind, parent_kind, query_kind, suffix, field in (
            ("effective_route", "nic", "routes", "effectiveRoutes", "nic_id"),
            ("security_admin_rule", "vnet", "admin", "effectiveSecurityAdminRules", "vnet_id"),
        ):
            if kind not in wanted:
                continue
            parents = [c for c in reader.collections if c["type"] == parent_kind and c["scope"] == scope]
            if len(parents) != 1 or parents[0]["status"] not in {"collected", "empty"}:
                reader.unavailable(kind, scope, "Microsoft.Network", AzureReadError(parent_kind + "_inventory_incomplete"))
                continue
            parent_ids = [item["id"] for item in parents[0]["items"]]

            def pages(scope=scope, parent_ids=parent_ids, query_kind=query_kind, suffix=suffix, field=field, kind=kind):
                query = NetworkQueries(reader, transport, scope)

                def rows(parent_id, page, index):
                    output = []
                    for value in page:
                        output.append({"id": f"{parent_id}/{suffix}/{index}", field: parent_id,
                            "rule" if query_kind == "admin" else "route": value,
                            "_provenance": {"source_operation": "listNetworkManagerEffectiveSecurityAdminRules"
                                if query_kind == "admin" else "effectiveRouteTable", "read_only": True,
                                field: parent_id}})
                        index += 1
                    return output, index

                def parent_pages(parent_id):
                    # Each parent keeps its own page and proof order; the shared
                    # query budget stays one per selected subscription.
                    outputs, sink, index = [], [], 0
                    try:
                        for page in query.pages(query_kind, parent_id, proof_sink=sink):
                            output, index = rows(parent_id, page, index)
                            outputs.append(output)
                    except Exception as exc:
                        return outputs, sink, exc
                    return outputs, sink, None

                try:
                    if type(query).pages is not _NATIVE_PAGES or len(parent_ids) <= 1:
                        # Substituted query objects keep the original serial contract.
                        for parent_id in parent_ids:
                            index = 0
                            for page in query.pages(query_kind, parent_id):
                                output, index = rows(parent_id, page, index)
                                yield output
                        return
                    # Independent per-parent LRO queries run bounded in parallel;
                    # results are replayed in inventory order and stop at the
                    # first failed parent exactly as the serial read did.
                    results = ordered_parallel(reader, parent_pages, parent_ids, limit=8)
                    for ok, value in results:
                        if not ok:
                            raise value
                        outputs, sink, failure = value
                        # query.pages records one proof immediately before each page.
                        for proof, output in zip(sink, outputs):
                            query.proofs.append(proof)
                            yield output
                        query.proofs.extend(sink[len(outputs):])
                        if failure is not None:
                            raise failure
                finally:
                    proofs[(kind, scope)] = list(query.proofs)

            jobs.append((kind, scope, "Microsoft.Network", pages))
    if jobs:
        reader.run(jobs)
    for collection in reader.collections:
        key = (collection["type"], collection["scope"])
        if key in proofs:
            collection["source_evidence"] = proofs[key]
