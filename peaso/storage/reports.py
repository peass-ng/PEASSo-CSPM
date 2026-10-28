"""Publish complete downloads plus bounded indexes for large report APIs."""
import copy
import hashlib
import json
import tempfile
from collections import Counter
from peaso.reports import render_markdown, write_markdown
from peaso.runtime_metrics import span as _runtime_span
from peaso.snapshot import FrozenDict, FrozenList

CHUNK_BYTES = 2 * 1024 * 1024
_SUMMARY_FIELDS = frozenset({"id", "category", "check_id", "title", "provider", "service", "resource_id",
    "native_resource_id", "resource_name", "scope", "region", "severity", "status", "frameworks", "remediation",
    "automated", "secret_fingerprint", "linked_check_ids", "scanner_status", "ai_review"})
_SUMMARY_LIMITS = {"title": 400, "resource_id": 1000, "scope": 500, "remediation": 1000,
    "service": 100, "check_id": 200, "category": 100, "provider": 30}

_SECRET_SUMMARY_FIELDS = _SUMMARY_FIELDS | {"evidence_summary"}

def chunks(items):
    group, size = [], 2
    for item in items:
        encoded_size = len(json.dumps(item, separators=(",", ":"), ensure_ascii=False).encode()) + 1
        if group and (size + encoded_size > CHUNK_BYTES or len(group) >= 250):
            yield group
            group, size = [], 2
        group.append(item)
        size += encoded_size
    if group:
        yield group


def _json_bytes(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def _encoded_chunks(items):
    """Already encoded rows, with exactly the ordinary chunk boundaries."""
    group, bodies, size = [], [], 2
    for item, body in items:
        encoded_size = len(body) + 1
        if group and (size + encoded_size > CHUNK_BYTES or len(group) >= 250):
            yield group, b'{"items":[' + b','.join(bodies) + b']}'
            group, bodies, size = [], [], 2
        group.append(item)
        bodies.append(body)
        size += encoded_size
    if group:
        yield group, b'{"items":[' + b','.join(bodies) + b']}'


def _artifact_chunks(artifacts, items, *, preencoded=False):
    if callable(getattr(artifacts, '_put_json_bytes', None)):
        source = items if preencoded else ((item, _json_bytes(item)) for item in items)
        yield from _encoded_chunks(source)
    else:
        for group in chunks(items):
            yield group, None


def _put_chunk(artifacts, tenant, ident, kind, group, body):
    if body is not None:
        return artifacts._put_json_bytes(tenant, ident, kind, body)
    return artifacts.put(tenant, ident, kind, {'items': group})


def _prepared_findings(artifacts, tenant, ident, findings, *, check_frameworks=None, check_meta=None,
                       check_meta_encoding=None, remediation_templates=None):
    from peaso.engine import hydrate_finding
    encoded = callable(getattr(artifacts, '_put_json_bytes', None))
    for finding in sorted(findings, key=lambda x: x['id']):
        body = _json_bytes(finding) if encoded else None
        # Legacy detail placement uses default JSON escaping/separators.
        # Six times compact UTF-8 size safely bounds that size (non-ASCII
        # escapes expand at most threefold, plus separator whitespace).
        # Only potentially large rows need the second legacy encoding.
        large = (not encoded or len(body) * 6 > CHUNK_BYTES) and len(json.dumps(finding).encode()) > CHUNK_BYTES
        if large:
            reference = artifacts.put(tenant, ident, 'detail', hydrate_finding(
                finding, check_frameworks, check_meta, check_meta_encoding, remediation_templates))
            finding = dict(finding_summary(finding), _detail_reference=reference)
            body = _json_bytes(finding) if encoded else None
        yield (finding, body) if encoded else finding


INDEX_CHUNK_ROWS = 5000


class _FindingIndexWriter:
    """Pack complete summaries independently of evidence-sized detail chunks.

    Keep one bounded JSON chunk in memory. Oversized individual rows retain
    the ordinary artifact chunker's singleton behavior; no fields are omitted.
    The caller publishes the manifest only after all writes have succeeded.
    """
    def __init__(self, artifacts, tenant, ident):
        self.artifacts, self.tenant, self.ident = artifacts, tenant, ident
        self.chunks, self.items, self.bodies = [], [], []
        self.size = 2

    def add(self, finding):
        summary = finding_summary(finding)
        body = _json_bytes(summary)
        size = len(body) + 1
        if self.items and (self.size + size > CHUNK_BYTES or len(self.items) >= INDEX_CHUNK_ROWS):
            self.flush()
        self.items.append(summary)
        self.bodies.append(body)
        self.size += size

    def flush(self):
        if not self.items:
            return
        encoded = callable(getattr(self.artifacts, '_put_json_bytes', None))
        body = b'{"items":[' + b','.join(self.bodies) + b']}' if encoded else None
        reference = _put_chunk(self.artifacts, self.tenant, self.ident,
                               'finding-index', self.items, body)
        self.chunks.append({'reference': reference, 'count': len(self.items)})
        self.items, self.bodies, self.size = [], [], 2


def finding_summary(finding):
    fields = _SECRET_SUMMARY_FIELDS if finding.get("secret_fingerprint") else _SUMMARY_FIELDS
    value = {k: v for k, v in finding.items() if k in fields}
    if "finding_type" in finding:
        value["finding_type"] = finding["finding_type"]
    truncated = False
    for key, item in value.items():
        if isinstance(item, str):
            maximum = _SUMMARY_LIMITS.get(key, 2000)
            if len(item) > maximum:
                value[key] = item[:maximum] + " [Full value available in finding detail]"
                truncated = True
    if truncated:
        value["summary_truncated"] = True
    value["detail_available"] = True
    return value


MEMBER_CAP = 200


def _cap_members(node, member_cap):
    members = node.get("members")
    if isinstance(members, list) and len(members) > member_cap:
        return dict(node, members=members[:member_cap], members_total=len(members), members_truncated=True)
    return node


def privesc_projection(graph, max_nodes, member_cap=MEMBER_CAP):
    """Bounded view of an (already aggregated) privesc graph that truncates whole edges, never aggregates.

    Edges are kept in order while both endpoints fit in max_nodes; aggregate member lists are capped at
    member_cap (members_total keeps the count; GET .../graphs/privesc/aggregates/{id}/members pages them).
    """
    nodes = {node["id"]: node for node in graph.get("nodes", [])}
    if len(nodes) <= max_nodes:
        if not any(len(n.get("members") or []) > member_cap for n in nodes.values()):
            return graph
        return dict(graph, nodes=[_cap_members(n, member_cap) for n in graph.get("nodes", [])])
    rank = {"derived": 0, "conditional": 1, "unknown": 2}
    kept, edges = {}, []
    for edge in sorted(graph.get("edges", []), key=lambda e: (rank.get(e.get("confidence"), 3), e.get("id", ""))):
        new = [n for n in (edge["source"], edge["target"]) if n not in kept]
        if len(kept) + len(new) > max_nodes:
            continue
        for node_id in new:
            kept[node_id] = _cap_members(nodes.get(node_id, {"id": node_id, "label": node_id, "kind": "principal"}), member_cap)
        edges.append(edge)
    return {"nodes": list(kept.values()), "edges": edges, "truncated": True,
            "total_nodes": len(nodes), "total_edges": len(graph.get("edges", [])),
            "projection": "whole-edge truncation of the aggregated privesc graph; download the complete report for every edge"}


def resource_chunks(artifacts, tenant, ident, report, snapshot, *, _inventory=None):
    """Native items for report schema 1.1 (resources[].data is omitted from the report), sorted by id
    so GET /api/scans/{id}/resources/{resource_id} reads a single bounded chunk.
    Internal prepared inventory must belong to this snapshot and publication.
    """
    from peaso.snapshot import resources
    wanted = {r["id"] for r in report.get("resources", [])}
    ordered = sorted((r for r in (resources(snapshot) if _inventory is None else _inventory)
                      if r["id"] in wanted), key=lambda r: r["id"])
    # Keep only references in the sort buffer; construct one chunk's output
    # rows at a time instead of retaining a second full inventory of dicts.
    items = ({"id": r["id"], "native_id": r["native_id"], "type": r["type"], "scope": r["scope"], "data": r["data"]}
             for r in ordered)
    out = []
    for group, body in _artifact_chunks(artifacts, items):
        out.append({"reference": _put_chunk(artifacts, tenant, ident, "resources", group, body),
                    "first_id": group[0]["id"], "last_id": group[-1]["id"], "count": len(group)})
    return out


def _network_projection(snapshot, report_snapshot_id):
    """Sealed network dependency projection bound to the report's snapshot.

    Only the reachability collections are projected. Validating (and freezing)
    the complete native inventory first only re-proved the source digest, which
    the projection never carries: its original_snapshot_id is the report's own
    binding. The sealed artifact is byte-identical to projecting the full input.
    """
    from peaso.analysis.reachability import REACHABILITY_TYPES, network_snapshot
    from peaso.snapshot import seal
    wanted = REACHABILITY_TYPES.get(snapshot.get("provider"))
    if wanted is not None and isinstance(snapshot.get("collections"), list):
        source = {key: value for key, value in snapshot.items() if key != "snapshot_id"}
        source["collections"] = [row for row in snapshot["collections"]
                                 if isinstance(row, dict) and row.get("type") in wanted]
    else:
        source = snapshot
    scoped = network_snapshot(source)
    # Imported ancestor metadata never controls report authorization or binding.
    scoped["metadata"]["original_snapshot_id"] = report_snapshot_id
    # network_snapshot returns a fresh document owned here.
    return seal(scoped, owned=True)


def publish_report(artifacts, tenant, ident, report, snapshot=None, *, _shared=None):
    """_shared: internal dict one analyzer owns for one snapshot and scan.

    Snapshot-derived artifacts that do not depend on the report's findings
    (resource chunks for the same resource set, least privilege, network
    projection) are published once and their durable references reused by
    later publications of the same snapshot, report binding and scan.
    """
    shared = {} if _shared is None else {"_shared": _shared}
    batch = getattr(artifacts, "batch", None)
    if not callable(batch):
        return _publish_report(artifacts, tenant, ident, report, snapshot, **shared)
    with batch() as publisher:
        return _publish_report(publisher, tenant, ident, report, snapshot, **shared)


def _snapshot_shape(snapshot):
    """Cheap guard that the shared snapshot object was not restructured in place."""
    if not isinstance(snapshot, dict):
        return None
    rows = snapshot.get("collections")
    return (snapshot.get("snapshot_id"), tuple(
        (row.get("type"), row.get("scope"), row.get("status"), id(row.get("items")), len(row.get("items") or ()))
        for row in rows if isinstance(row, dict)) if isinstance(rows, list) else None)


def _shared_value(shared, owner, name, key, build):
    """Reuse a published value for the exact owner snapshot, scan and key."""
    if shared is None:
        return build()
    if shared.get("_owner") is not owner[0] or shared.get("_scope") != owner[1:]:
        shared.clear()
        shared.update(_owner=owner[0], _scope=owner[1:])
    hit = shared.get(name)
    if hit is not None and hit[0] == key:
        return copy.deepcopy(hit[1])
    value = build()
    shared[name] = (key, copy.deepcopy(value))
    return value


def _resource_section_key(snapshot, body):
    """Key the rendered inventory to frozen facts and their mutable envelope."""
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("collections"), list):
        return None
    collections = snapshot["collections"]
    if not all(type(row) is dict and type(row.get("items")) is FrozenList and
               all(type(item) is FrozenDict for item in row["items"])
               for row in collections):
        return None
    metadata = json.dumps([snapshot.get("provider"),
                           [(row.get("type"), row.get("scope"), row.get("service")) for row in collections]],
                          separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    digest = hashlib.sha256()
    digest.update(len(body).to_bytes(8, "big"))
    digest.update(body)
    digest.update(metadata)
    return digest.hexdigest()


def _publish_report(artifacts, tenant, ident, report, snapshot=None, *, _shared=None):
    from peaso.secret_evidence import without_private_values
    with _runtime_span("publication.normalize.private"):
        report = without_private_values(report)
    # Optional image scans have a separately scoped safe artifact. Keep raw
    # scanner/transport DTOs out of public report summaries and downloads.
    report = dict(report)
    if isinstance(report.get("snapshot_metadata"), dict):
        report["snapshot_metadata"] = {key: value for key, value in report["snapshot_metadata"].items()
            if key != "image_vulnerability_scan"}
    from peaso.finding_groups import group_report
    from peaso.ai.finding_reviews import apply_report_reviews
    with _runtime_span("publication.normalize.reviews"):
        report = apply_report_reviews(report)
    with _runtime_span("publication.normalize.group"):
        presented = group_report(report)
    json_reference = artifacts.put(tenant, ident, "report", presented)
    from peaso.engine import REPORT_SCHEMA_VERSION, expand_report
    embeddable = snapshot is not None and report.get("schema_version") == REPORT_SCHEMA_VERSION and snapshot.get("snapshot_id") == report.get("snapshot_id")
    owner = (snapshot, tenant, ident, report.get("snapshot_id"), report.get("provider"), _snapshot_shape(snapshot))
    # Prepare inventory only when a projection needs it. A final report can
    # reuse all snapshot-derived artifacts without rebuilding this large view.
    inventory = None
    def get_inventory():
        nonlocal inventory
        if inventory is not None:
            return inventory
        from peaso.snapshot import resources as snapshot_resources
        with _runtime_span("publication.inventory"):
            inventory = snapshot_resources(snapshot)
        return inventory
    def publish_markdown():
        # The Markdown download keeps native configuration facts inline (schema 1.0 view).
        stream_writer = getattr(artifacts, "put_text_file", None)
        section = None
        if resource_signature is not None and _shared is not None:
            cached = _shared.get("_markdown_resource_section")
            section = (dict(cached) if cached is not None and
                       cached.get("resource_signature") == resource_signature and
                       not cached["source"].closed else {})
        cached_graphs = _shared.get("_markdown_expanded_graphs") if _shared is not None else None
        reuse_expansion = (embeddable and section is not None and "source" in section and
                           cached_graphs is not None and cached_graphs[0] == graph_signature)
        with _runtime_span("publication.expand_native"):
            if reuse_expansion:
                # The resource section is copied verbatim below. Hydrate the
                # changed findings without reconstructing the native inventory;
                # graph input bytes must also match the previous expansion.
                from peaso.engine import SCHEMA_VERSION, hydrate_frameworks
                markdown_view = {key: value for key, value in hydrate_frameworks(presented).items()
                                 if key != "native_data"}
                markdown_view.update(schema_version=SCHEMA_VERSION, resources=(), graphs=cached_graphs[1])
            else:
                markdown_view = expand_report(presented, snapshot, _inventory=get_inventory()) if embeddable else presented
                if embeddable and _shared is not None and graph_signature is not None and section is not None and callable(stream_writer):
                    _shared["_markdown_expanded_graphs"] = (graph_signature, markdown_view["graphs"])
        if callable(stream_writer):
            # Keep the full native download without document-sized string/UTF-8/
            # compression copies. The owned disk file survives until durable upload.
            markdown = tempfile.TemporaryFile(mode="w+b")
            try:
                with _runtime_span("publication.markdown"):
                    write_markdown(markdown_view, markdown, _resource_section=section)
                del markdown_view
                reference = stream_writer(tenant, ident, "markdown", markdown)
                if section is not None and "source" not in section:
                    section["source"] = markdown
                    section["resource_signature"] = resource_signature
                    previous = _shared.get("_markdown_resource_section")
                    _shared["_markdown_resource_section"] = section
                    if previous is not None:
                        previous["source"].close()
                    markdown = None
                return reference
            finally:
                if markdown is not None:
                    markdown.close()
        else:
            with _runtime_span("publication.markdown"):
                markdown = render_markdown(markdown_view)
            del markdown_view
            reference = artifacts.put_text(tenant, ident, "markdown", markdown)
            del markdown
            return reference

    markdown_signature = resource_signature = graph_signature = None
    if _shared is not None:
        # AI metadata and publication state are not rendered in Markdown. A
        # digest of every other sanitized report field prevents reuse when AI
        # adds findings or changes any rendered evidence.
        try:
            digest = hashlib.sha256()
            for key in sorted(report):
                if key in ("ai", "publication"):
                    continue
                if type(key) is not str:
                    raise TypeError("report key must be a string")
                name = key.encode("utf-8")
                body = json.dumps(report[key], sort_keys=True, separators=(",", ":"),
                                  ensure_ascii=False, allow_nan=False).encode()
                if key == "resources":
                    resource_signature = _resource_section_key(snapshot, body)
                elif key == "graphs":
                    graph_signature = hashlib.sha256(body).hexdigest()
                digest.update(len(name).to_bytes(8, "big"))
                digest.update(name)
                digest.update(len(body).to_bytes(8, "big"))
                digest.update(body)
                del body
            markdown_signature = digest.hexdigest()
        except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError):
            resource_signature = None
    markdown_reference = (_shared_value(_shared, owner, "markdown", markdown_signature, publish_markdown)
                          if markdown_signature is not None else publish_markdown())
    manifest = {"bundle_version": 1, "report_grouping": "check-v1", "report_json": json_reference, "report_markdown": markdown_reference,
                "summary": {k: v for k, v in report.items() if k not in {"resources", "findings", "coverage", "graphs", "snapshot", "check_frameworks", "check_meta", "check_meta_encoding", "remediation_templates"}},
                "finding_chunks": [], "finding_index_chunks": [], "coverage_chunks": [], "coverage_chunk_counts": [],
                "graphs": {}, "finding_count": len(report.get("findings", [])), "finding_group_count": len(presented.get("findings", [])), "observation_count": len(report.get("findings", [])), "coverage_count": len(report.get("coverage", []))}
    from peaso.image_findings_storage import attach_to_manifest
    metadata = snapshot.get("metadata", {}) if isinstance(snapshot, dict) else {}
    from peaso.selected_image_observations_20261021 import metadata_for_report
    with _runtime_span("publication.normalize.private"):
        image_metadata = metadata_for_report(snapshot, report) if isinstance(snapshot, dict) else None
        manifest = attach_to_manifest(manifest, artifacts, tenant, ident, image_metadata)
    if isinstance(report.get("ai"), dict):
        manifest["ai_review"] = artifacts.put(tenant, ident, "ai-review", report["ai"])
        manifest["summary"]["ai"] = {key: report["ai"][key] for key in ("status", "reason", "coverage", "auth_source") if key in report["ai"]}
    # Bind future technique-card lookups to the exact report catalog and the
    # tenant-scoped artifact. Old manifests have no binding and use an explicit
    # legacy-unversioned lookup status instead of today's catalog semantics.
    if isinstance(report.get("privesc_catalog"), dict):
        manifest["privesc_catalog"] = {**report["privesc_catalog"], "tenant_id": tenant}
    # Labels and per-check fields (title, remediation, service, category, severity) are stored once per
    # check (report check_frameworks / check_meta); chunks and the index keep only explicit per-finding
    # overrides and the API hydrates/filters with these maps at serve time.
    check_frameworks = report.get("check_frameworks") if isinstance(report.get("check_frameworks"), dict) else {}
    check_meta = report.get("check_meta") if isinstance(report.get("check_meta"), dict) else {}
    def category(finding):
        return finding["category"] if "category" in finding else (check_meta.get(finding.get("check_id")) or {}).get("category")
    manifest["summary"]["stats"] = dict(report.get("stats", {}), by_category=dict(Counter(category(item) for item in report.get("findings", []))))
    manifest["summary"]["coverage_summary"] = {"total": len(report.get("coverage", [])), "by_status": dict(Counter(item["status"] for item in report.get("coverage", [])))}
    from peaso.checks.catalog import framework_catalog
    manifest["framework_filters"] = {version["id"]: version.get("native_check_ids", []) for version in framework_catalog() if version["provider"] in {report["provider"], "all"}}
    manifest["check_frameworks"] = check_frameworks
    manifest["check_meta"] = check_meta
    if "check_meta_encoding" in report:
        manifest["check_meta_encoding"] = report["check_meta_encoding"]
    manifest["remediation_templates"] = report.get("remediation_templates", {})
    encoded = callable(getattr(artifacts, '_put_json_bytes', None))
    def publish_findings():
        with _runtime_span("publication.chunk.findings"):
            prepared = _prepared_findings(artifacts, tenant, ident, report.get('findings', []),
                check_frameworks=check_frameworks, check_meta=check_meta, check_meta_encoding=report.get('check_meta_encoding'),
                remediation_templates=report.get('remediation_templates'))
            if not encoded:
                # Preserve the existing detail-write order for legacy/custom stores.
                prepared = list(prepared)
            index = _FindingIndexWriter(artifacts, tenant, ident)
            chunks = []
            for group, body in _artifact_chunks(artifacts, prepared, preencoded=encoded):
                detail = _put_chunk(artifacts, tenant, ident, "findings", group, body)
                chunks.append({"reference": detail, "first_id": group[0]["id"], "last_id": group[-1]["id"], "count": len(group)})
                for item in group:
                    index.add(item)
            index.flush()
            return chunks, index.chunks
    manifest["finding_chunks"], manifest["finding_index_chunks"] = _shared_value(
        _shared if markdown_signature is not None else None,
        owner, "finding_artifacts", markdown_signature, publish_findings)

    def publish_coverage():
        with _runtime_span("publication.chunk.coverage"):
            chunks, counts = [], []
            for group, body in _artifact_chunks(artifacts, report.get("coverage", [])):
                chunks.append(_put_chunk(artifacts, tenant, ident, "coverage", group, body))
                counts.append(len(group))
            return chunks, counts
    manifest["coverage_chunks"], manifest["coverage_chunk_counts"] = _shared_value(
        _shared if markdown_signature is not None else None,
        owner, "coverage_artifacts", markdown_signature, publish_coverage)
    if embeddable:
        from peaso.least_privilege import project as project_least_privilege
        # The same immutable inventory was used for Markdown above. No state
        # survives this publication or crosses a snapshot revision.
        with _runtime_span("publication.chunk.resources"):
            wanted = hashlib.sha256(json.dumps(sorted(str(row.get("id")) for row in report.get("resources", [])
                                                      if isinstance(row, dict))).encode()).hexdigest()
            manifest["resource_chunks"] = _shared_value(_shared, owner, "resource_chunks", wanted,
                lambda: resource_chunks(artifacts, tenant, ident, report, snapshot, _inventory=get_inventory()))
        def least_privilege():
            refs = {}
            with _runtime_span("publication.projection.least_privilege"):
                current_inventory = get_inventory()
                projection = project_least_privilege(report["provider"], current_inventory, snapshot=snapshot)
                if report['provider'] == 'aws':
                    from peaso.least_privilege_permissions import permission_input_filter
                    selected = permission_input_filter('aws', projection['items'])
                    refs['least_privilege_permission_inputs'] = artifacts.put(tenant, ident, 'least-privilege', {
                        'snapshot_id': report['snapshot_id'], 'provider': 'aws',
                        'items': [row for row in current_inventory if selected(row)]})
            refs["least_privilege"] = artifacts.put(tenant, ident, "least-privilege", projection)
            return refs
        refs = _shared_value(_shared, owner, "least_privilege", None, least_privilege)
        del inventory
        if 'least_privilege_permission_inputs' in refs:
            manifest['least_privilege_permission_inputs'] = refs['least_privilege_permission_inputs']
        manifest["least_privilege"] = refs["least_privilege"]
    def publish_graphs():
        with _runtime_span("publication.projection.graphs"):
            graphs = {}
            for kind in ("network", "iam"):
                graph = report.get("graphs", {}).get(kind, {"nodes": [], "edges": []})
                graphs[kind] = artifacts.put(tenant, ident, "graph-" + kind, graph)
            from peaso.analysis import project_graph
            projections = {kind: artifacts.put(tenant, ident, "graph-" + kind, project_graph(report.get("graphs", {}).get(kind, {"nodes": [], "edges": []}), 500)) for kind in ("network", "iam")}
            # The privesc map is already aggregated: never pass it through project_graph (it would drop aggregates).
            privesc_graph = report.get("graphs", {}).get("privesc", {"nodes": [], "edges": []})
            graphs["privesc"] = artifacts.put(tenant, ident, "graph-privesc", privesc_graph)
            projections["privesc"] = artifacts.put(tenant, ident, "graph-privesc", privesc_projection(privesc_graph, 500))
            return graphs, projections
    manifest["graphs"], manifest["graph_projections"] = _shared_value(
        _shared if markdown_signature is not None else None,
        owner, "graph_artifacts", markdown_signature, publish_graphs)
    if snapshot is not None:
        with _runtime_span("publication.projection.network_snapshot"):
            manifest["network_snapshot"] = _shared_value(_shared, owner, "network_snapshot", None,
                lambda: artifacts.put(tenant, ident, "network-snapshot",
                                      _network_projection(snapshot, report["snapshot_id"])))
    with _runtime_span("publication.manifest.commit"):
        return artifacts.put(tenant, ident, "manifest", manifest)
