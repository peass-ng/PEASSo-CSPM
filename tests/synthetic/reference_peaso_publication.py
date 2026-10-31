"""Predecessor complete report publisher retained for content and performance parity."""
from types import FunctionType

def _original_resource_chunks(artifacts, tenant, ident, report, snapshot):
    """Native items for report schema 1.1 (resources[].data is omitted from the report), sorted by id
    so GET /api/scans/{id}/resources/{resource_id} reads a single bounded chunk."""
    from peaso.snapshot import resources
    wanted = {r["id"] for r in report.get("resources", [])}
    items = sorted(({"id": r["id"], "native_id": r["native_id"], "type": r["type"], "scope": r["scope"], "data": r["data"]}
                    for r in resources(snapshot) if r["id"] in wanted), key=lambda r: r["id"])
    out = []
    for group in chunks(items):
        out.append({"reference": artifacts.put(tenant, ident, "resources", {"items": group}),
                    "first_id": group[0]["id"], "last_id": group[-1]["id"], "count": len(group)})
    return out

def _original_publish_report(artifacts, tenant, ident, report, snapshot=None):
    from peaso.secret_evidence import without_private_values
    report = without_private_values(report)
    # Optional image scans have a separately scoped safe artifact. Keep raw
    # scanner/transport DTOs out of public report summaries and downloads.
    report = dict(report)
    if isinstance(report.get("snapshot_metadata"), dict):
        report["snapshot_metadata"] = {key: value for key, value in report["snapshot_metadata"].items()
            if key != "image_vulnerability_scan"}
    from peaso.finding_groups import group_report
    from peaso.ai.finding_reviews import apply_report_reviews
    report = apply_report_reviews(report)
    presented = group_report(report)
    json_reference = artifacts.put(tenant, ident, "report", presented)
    from peaso.engine import REPORT_SCHEMA_VERSION, expand_report
    embeddable = snapshot is not None and report.get("schema_version") == REPORT_SCHEMA_VERSION and snapshot.get("snapshot_id") == report.get("snapshot_id")
    # The Markdown download keeps native configuration facts inline (schema 1.0 view).
    markdown_reference = artifacts.put_text(tenant, ident, "markdown", render_markdown(expand_report(presented, snapshot) if embeddable else presented))
    manifest = {"bundle_version": 1, "report_grouping": "check-v1", "report_json": json_reference, "report_markdown": markdown_reference,
                "summary": {k: v for k, v in report.items() if k not in {"resources", "findings", "coverage", "graphs", "snapshot", "check_frameworks", "check_meta", "check_meta_encoding", "remediation_templates"}},
                "finding_chunks": [], "coverage_chunks": [], "coverage_chunk_counts": [],
                "graphs": {}, "finding_count": len(report.get("findings", [])), "finding_group_count": len(presented.get("findings", [])), "observation_count": len(report.get("findings", [])), "coverage_count": len(report.get("coverage", []))}
    from peaso.image_findings_storage import attach_to_manifest
    metadata = snapshot.get("metadata", {}) if isinstance(snapshot, dict) else {}
    from peaso.selected_image_observations_20261021 import metadata_for_report
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
    from peaso.engine import hydrate_finding
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
    findings = []
    for finding in sorted(report.get("findings", []), key=lambda x: x["id"]):
        if len(json.dumps(finding).encode()) > CHUNK_BYTES:
            # A presigned detail download is served as stored, so it carries its labels and per-check fields.
            reference = artifacts.put(tenant, ident, "detail", hydrate_finding(
                finding, check_frameworks, check_meta, report.get("check_meta_encoding"),
                report.get("remediation_templates")))
            finding = dict(finding_summary(finding), _detail_reference=reference)
        findings.append(finding)
    for group in chunks(findings):
        detail = artifacts.put(tenant, ident, "findings", {"items": group})
        index = artifacts.put(tenant, ident, "finding-index", {"items": [finding_summary(item) for item in group]})
        manifest["finding_chunks"].append({"reference": detail, "index_reference": index, "first_id": group[0]["id"], "last_id": group[-1]["id"], "count": len(group)})
    for group in chunks(report.get("coverage", [])):
        manifest["coverage_chunks"].append(artifacts.put(tenant, ident, "coverage", {"items": group}))
        manifest["coverage_chunk_counts"].append(len(group))
    if embeddable:
        manifest["resource_chunks"] = resource_chunks(artifacts, tenant, ident, report, snapshot)
        from peaso.least_privilege import project as project_least_privilege
        from peaso.snapshot import resources as snapshot_resources
        projection = project_least_privilege(report["provider"], snapshot_resources(snapshot), snapshot=snapshot)
        manifest["least_privilege"] = artifacts.put(tenant, ident, "least-privilege", projection)
    for kind in ("network", "iam"):
        graph = report.get("graphs", {}).get(kind, {"nodes": [], "edges": []})
        manifest["graphs"][kind] = artifacts.put(tenant, ident, "graph-" + kind, graph)
    from peaso.analysis import project_graph
    manifest["graph_projections"] = {kind: artifacts.put(tenant, ident, "graph-" + kind, project_graph(report.get("graphs", {}).get(kind, {"nodes": [], "edges": []}), 500)) for kind in ("network", "iam")}
    # The privesc map is already aggregated: never pass it through project_graph (it would drop aggregates).
    privesc_graph = report.get("graphs", {}).get("privesc", {"nodes": [], "edges": []})
    manifest["graphs"]["privesc"] = artifacts.put(tenant, ident, "graph-privesc", privesc_graph)
    manifest["graph_projections"]["privesc"] = artifacts.put(tenant, ident, "graph-privesc", privesc_projection(privesc_graph, 500))
    if snapshot is not None:
        from peaso.analysis.reachability import network_snapshot
        from peaso.snapshot import seal
        scoped = network_snapshot(snapshot)
        # Imported ancestor metadata never controls report authorization or binding.
        scoped["metadata"]["original_snapshot_id"] = report["snapshot_id"]
        manifest["network_snapshot"] = artifacts.put(tenant, ident, "network-snapshot", seal(scoped))
    return artifacts.put(tenant, ident, "manifest", manifest)

def original_publisher():
    from peaso.storage import reports
    namespace = dict(vars(reports))
    namespace['resource_chunks'] = FunctionType(_original_resource_chunks.__code__, namespace,
        argdefs=_original_resource_chunks.__defaults__)
    return FunctionType(_original_publish_report.__code__, namespace,
        argdefs=_original_publish_report.__defaults__)
