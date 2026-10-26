"""Read-only, bounded effective-route and security-admin inventories."""
from __future__ import annotations

import threading

from .azure_nsg_ingress_native import NetworkQueries, unavailable

_NATIVE_PAGES = NetworkQueries.pages
_CALLS, _BYTES, _RESPONSE_BYTES = 300, 32 * 1024 * 1024, 8 * 1024 * 1024


class _Deferred(Exception):
    """A later parent found the shared budget spent; it reruns in inventory order."""


class _OrderedBudget:
    """Charge one subscription's shared query budget in inventory order.

    The serial read gave each parent the calls and bytes left by the parents
    before it. Concurrent parents keep that allocation: a parent is refused
    only when the parents up to and including itself spent the budget, and a
    later parent that finds the shared total spent is deferred (never blocked
    while holding a fan-out slot) and reruns serially after the parallel phase.
    The collector replays recorded per-call usage in inventory order to cut
    output exactly where the serial read stopped.
    """
    def __init__(self, query, count):
        self.lock = threading.Lock()
        self.calls, self.bytes = [0] * count, [0] * count
        self.sizes = [[] for _ in range(count)]
        self.done, self.head, self.serial, self.local = [False] * count, 0, False, threading.local()

    def bind(self, index):
        self.local.index = index

    def admit(self, query):
        index = getattr(self.local, "index", None)
        if index is None:
            return False
        with self.lock:
            if query.clock() - query.started >= 120 or sum(self.calls[:index + 1]) >= _CALLS:
                unavailable("network_query_budget")
            if not (self.serial or index == self.head or (query.calls < _CALLS and query.bytes <= _BYTES)):
                raise _Deferred()
            self.calls[index] += 1
            self.sizes[index].append(0)
            query.calls += 1
            return True

    def spent(self, query, size):
        index = getattr(self.local, "index", None)
        if index is None:
            return None
        with self.lock:
            self.sizes[index][-1] = size
            self.bytes[index] += size
            query.bytes += size
            return sum(self.bytes[:index + 1])

    def defer(self, index):
        with self.lock:
            self.calls[index], self.bytes[index], self.sizes[index] = 0, 0, []

    def finish(self, index):
        with self.lock:
            self.done[index] = True
            while self.head < len(self.done) and self.done[self.head]:
                self.head += 1


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

                ledger = None

                def parent_pages(job):
                    # Each parent keeps its own page and proof order; the shared
                    # query budget stays one per selected subscription.
                    position, parent_id = job
                    outputs, sink, marks, index = [], [], [], 0
                    ledger.bind(position)
                    try:
                        for page in query.pages(query_kind, parent_id, proof_sink=sink):
                            output, index = rows(parent_id, page, index)
                            outputs.append(output)
                            marks.append(ledger.calls[position])
                    except _Deferred:
                        ledger.defer(position)
                        return None
                    except Exception as exc:
                        return outputs, sink, exc, marks, ledger.sizes[position]
                    finally:
                        ledger.bind(None)
                        ledger.finish(position)
                    return outputs, sink, None, marks, ledger.sizes[position]

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
                    ledger = query.ledger = _OrderedBudget(query, len(parent_ids))
                    results = ordered_parallel(reader, parent_pages, list(enumerate(parent_ids)), limit=8)
                    calls = spent = 0
                    ledger.serial = True
                    for position, (ok, value) in enumerate(results):
                        if not ok:
                            raise value
                        if value is None:
                            # Deferred parents rerun alone, after every earlier parent.
                            value = parent_pages((position, parent_ids[position]))
                        outputs, sink, failure, marks, sizes = value
                        # Replay the serial budget: the first call it would have
                        # refused ends the read after the pages completed before it.
                        cut = None
                        for number, size in enumerate(sizes):
                            if calls >= _CALLS:
                                cut = number, "network_query_budget"
                                break
                            calls, spent = calls + 1, spent + size
                            if size > _RESPONSE_BYTES or spent > _BYTES:
                                cut = number, "network_query_body_budget"
                                break
                        keep = len(outputs) if cut is None else sum(1 for mark in marks if mark <= cut[0])
                        # query.pages records one proof immediately before each page.
                        for proof, output in zip(sink[:keep], outputs[:keep]):
                            query.proofs.append(proof)
                            yield output
                        if cut is not None:
                            raise AzureReadError(cut[1])
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
