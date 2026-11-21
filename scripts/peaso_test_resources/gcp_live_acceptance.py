"""Private snapshot summaries and bounded, read-only GCP live acceptance."""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from peaso.snapshot import canonical, resources, validate
from scripts.peaso_test_resources.gke_session_guard import ACCOUNT, CATEGORIES, PROJECT, ZONE, SessionError, private_write

LIVE_INVENTORIES = ["project", "organization", "network"]


def field_coverage(collections):
    return [detail for c in collections for item in c["items"]
            if isinstance(item.get("_coverage"), dict) for detail in item["_coverage"].values()
            if isinstance(detail, dict)]


def discover_scopes(directory, account):
    """Pin discovery to one identity; never inherit process impersonation."""
    environment = dict(os.environ, CLOUDSDK_CORE_ACCOUNT=account,
                       CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT="", CLOUDSDK_CORE_DISABLE_PROMPTS="1")
    scopes = []
    for kind in ("projects", "organizations"):
        command = ["gcloud", kind, "list", "--account", account, "--format=json", "--quiet"]
        try:
            result = subprocess.run(command, env=environment, capture_output=True, text=True, check=True, timeout=60)
            rows = json.loads(result.stdout)
            if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                raise ValueError("invalid_discovery")
            selected = (["projects/" + row["projectId"] for row in rows if row.get("lifecycleState") == "ACTIVE"]
                        if kind == "projects" else [row["name"] for row in rows])
            if any(not isinstance(scope, str) or not scope.startswith(kind + "/") or len(scope.split("/")) != 2 for scope in selected):
                raise ValueError("invalid_discovery")
        except (OSError, subprocess.SubprocessError, ValueError, TypeError, KeyError):
            raise SessionError(kind + "_discovery_failed") from None
        private_write(directory / ("accessible-" + kind + ".json"), rows)
        scopes.extend(selected)
    if not scopes:
        raise SessionError("no_accessible_scopes")
    return list(dict.fromkeys(scopes))


def acceptance_status(snapshot, scopes):
    """Readability and accounting gates, not universal inventory completeness."""
    collections = snapshot["collections"]
    attempted = {c["scope"] for c in collections}
    readable = {c["scope"] for c in collections if c["status"] in {"collected", "empty", "partial"}}
    missing = sorted(set(scopes) - attempted)
    unreadable = sorted(set(scopes) - readable)
    expected = {(kind, scope) for scope in scopes for kind in
                (["project", "network"] if scope.startswith("projects/") else ["organization"])}
    missing_inventories = sorted(expected - {(c["type"], c["scope"]) for c in collections})
    truncated = [c for c in collections if c["status"] == "partial"]
    scope_errors = snapshot.get("metadata", {}).get("scope_coverage", [])
    fatal_codes = {"credential_initialization_failed", "credential_refresh_failed", "gcloud_auth_failed",
                   "gcloud_identity_missing", "call_limit", "resource_limit", "page_limit", "execution_deadline"}
    evidence = collections + snapshot.get("metadata", {}).get("source_requests", []) + field_coverage(collections)
    fatal = sorted({c.get("error", {}).get("code") for c in evidence if c.get("error", {}).get("code") in fatal_codes})
    passed = not (missing or missing_inventories or unreadable or truncated or scope_errors or fatal)
    return {"outcome": "passed" if passed else "failed", "all_discovered_scopes_attempted": not missing,
            "all_discovered_scopes_readable": not unreadable, "missing_scopes": missing,
            "unreadable_scopes": unreadable, "missing_inventories": missing_inventories,
            "partial_collections": len(truncated), "fatal_error_codes": fatal,
            "scope_errors": scope_errors,
            "semantics": "Bounded selected native APIs across discovered scopes; per-API denials remain explicit, not universal cloud coverage"}


def collect_live(directory, account=ACCOUNT):
    from peaso.collectors import gcp
    from peaso.progress import ProgressReporter
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    if (directory / "gcp-live-snapshot.json").exists():
        raise SessionError("live_evidence_already_exists")
    scopes = discover_scopes(directory, account)
    connector = {"provider": "gcp", "scopes": scopes,
                 "auth": {"method": "gcloud", "account": account, "impersonate_service_account": ""},
                 "options": {"inventories": LIVE_INVENTORIES, "include_inherited": False, "metrics_scopes": False,
                             "concurrency": 2, "timeout": 10, "retries": 0, "page_size": 1000,
                             "max_calls": 1000, "max_resources": 10000}}
    private_write(directory / "gcp-live-request.json", connector)
    before = source_hashes()["gcp.py"]
    start = time.monotonic()
    with ProgressReporter(provider="gcp"):
        snapshot = validate(gcp.collect(connector))
    private_write(directory / "gcp-live-snapshot.json", canonical(snapshot))
    gate = acceptance_status(snapshot, scopes)
    after = source_hashes()["gcp.py"]
    if before != after:
        gate["outcome"] = "failed"
        gate["source_changed_during_collection"] = True
    summary = {**summarize(snapshot), "acceptance": gate, "evidence_mode": "live-gcloud",
               "selected_inventories": LIVE_INVENTORIES, "requested_scope_count": len(scopes),
               "project_count": sum(s.startswith("projects/") for s in scopes),
               "organization_count": sum(s.startswith("organizations/") for s in scopes),
               "source_hash_before": before, "source_hash_after": after,
               "collection_seconds": round(time.monotonic() - start, 3), "feature_evaluation": "none; collector-only"}
    private_write(directory / "gcp-live-summary.json", summary)
    return summary


def source_hashes():
    root = Path(__file__).resolve().parents[2]
    return {name: hashlib.sha256((root / "peaso" / "collectors" / name).read_bytes()).hexdigest() for name in ["gcp.py", "k8s.py"]}


def summarize(snapshot):
    snapshot = validate(snapshot)
    collections = snapshot["collections"]
    metadata = snapshot.get("metadata", {})
    requests = metadata.get("source_requests", [])
    fields = field_coverage(collections)
    errors = Counter(c.get("error", {}).get("code", "") for c in collections if c.get("error"))
    return {"provider": snapshot["provider"], "snapshot_id": snapshot["snapshot_id"], "created_at": snapshot["created_at"],
            "scopes": snapshot["scopes"], "resolved_scopes": metadata.get("resolved_scopes", snapshot["scopes"]),
            "resources": sum(len(c["items"]) for c in collections), "collections": len(collections),
            "collection_statuses": dict(Counter(c["status"] for c in collections)), "error_codes": dict(errors),
            "request_statuses": dict(Counter(r.get("status", "unknown") for r in requests)),
            "http_statuses": dict(Counter(str(r["http_status"]) for r in requests if r.get("http_status") is not None)),
            "request_error_codes": dict(Counter(r["error"].get("code", "unknown") for r in requests if r.get("error"))),
            "request_error_reasons": dict(Counter(r["error"].get("reason", "unknown") for r in requests if r.get("error"))),
            "field_coverage_statuses": dict(Counter(f.get("status", "unknown") for f in fields)),
            "field_error_reasons": dict(Counter(f["error"].get("reason", "unknown") for f in fields if f.get("error"))),
            "coverage_statuses": dict(Counter(c.get("coverage_status", c["status"]) for c in collections)),
            "service_coverage": {service: {"statuses": dict(Counter(c.get("coverage_status", c["status"]) for c in collections if c.get("service", c["type"]) == service)),
                                           "types": sorted({c["type"] for c in collections if c.get("service", c["type"]) == service})}
                                 for service in sorted({c.get("service", c["type"]) for c in collections})},
            "api_error_evidence": [{"type": c["type"], "scope": c["scope"], "service": c.get("service", c["type"]),
                                    "status": c["status"], "coverage_status": c.get("coverage_status", c["status"]),
                                    "error": c.get("error"), "source_requests": c.get("source_requests", [])}
                                   for c in collections if c.get("error")],
            "intentional_limits": metadata.get("intentional_limits", {}),
            "scope_errors": metadata.get("scope_errors", metadata.get("scope_coverage", [])),
            "types": sorted({c["type"] for c in collections}),
            "scope_coverage": [{"scope": scope, "resources": sum(len(c["items"]) for c in collections if c["scope"] == scope),
                                "statuses": dict(Counter(c["status"] for c in collections if c["scope"] == scope))}
                               for scope in sorted({c["scope"] for c in collections})],
            "requests": len(metadata.get("source_requests", [])),
            "http_attempts": metadata.get("http_attempts", sum(r.get("http_attempts", 0) for r in metadata.get("source_requests", []))),
            "scope_coverage_metadata": metadata.get("scope_coverage")}


def ordinary_joins(gcp_snapshot, k8s_snapshot, namespace):
    """Exact declared identity and providerID joins, without access/reachability claims."""
    cloud = resources(gcp_snapshot)
    kube = resources(k8s_snapshot)
    accounts = {r["data"].get("email"): r for r in cloud if r["type"] == "service_account"}
    instances = {r["data"].get("selfLink"): r for r in cloud if r["type"] == "instance"}
    joins = []
    for resource in kube:
        item = resource["data"]
        if resource["type"] == "serviceaccount" and item.get("metadata", {}).get("namespace") == namespace:
            ref = item.get("metadata", {}).get("annotations", {}).get("iam.gke.io/gcp-service-account")
            if ref:
                target = accounts.get(ref)
                joins.append({"kind": "declared_workload_identity", "source": resource["id"], "target": target["id"] if target else None,
                              "reference": ref, "source_field": "metadata.annotations.iam.gke.io/gcp-service-account",
                              "semantics": "Declared annotation metadata only; IAM trust, token issuance and effective access unverified"})
        if resource["type"] == "node":
            ref = item.get("spec", {}).get("providerID", "")
            if ref.startswith("gce://"):
                parts = ref.removeprefix("gce://").split("/")
                if len(parts) == 3:
                    link = "https://www.googleapis.com/compute/v1/projects/" + parts[0] + "/zones/" + parts[1] + "/instances/" + parts[2]
                    target = instances.get(link)
                    joins.append({"kind": "node_compute_instance", "source": resource["id"], "target": target["id"] if target else None,
                                  "reference": ref, "source_field": "spec.providerID", "semantics": "Declared infrastructure identity; no routing inference"})
    return joins


def fixture_findings(snapshot, report):
    identities = {r["data"].get("metadata", {}).get("name"): r["id"] for r in resources(snapshot) if r["type"] == "pod"}
    expected = [("qa-pass", "k8s.pod.read_only_root", "PASS"), ("qa-review", "k8s.pod.read_only_root", "FAIL"),
                ("qa-review", "k8s.pod.restrict_token_automount", "UNKNOWN"), ("qa-pass", "k8s.pod.no_privilege_escalation", "PASS")]
    actual = []
    for name, check_id, status in expected:
        rid = identities.get(name)
        findings = [f for f in report["findings"] if f["resource_id"] == rid and f["check_id"] == check_id]
        got = [f["status"] for f in findings]
        actual.append({"pod": name, "check_id": check_id, "expected": status, "actual": got})
        if got != [status]:
            raise SessionError("expected_fixture_finding_missing:" + name + ":" + check_id)
    return actual


def collect_gke(session):
    # Never replace a successful captured scan with a later teardown response.
    # Verification failures must be investigated offline against that capture.
    if any((session.directory / name).exists() for name in ["gke-gcp-snapshot.json", "gke-k8s-snapshot.json", "gke-report.json"]):
        raise SessionError("gke_evidence_already_exists_use_offline_verification")
    from peaso.collectors import gcp
    from peaso.engine import evaluate_snapshot, expand_report
    from peaso.finding_groups import group_report
    from peaso.least_privilege import project
    from peaso.reports import render_markdown
    from peaso.secret_evidence import without_private_values
    before = source_hashes()
    start = time.monotonic()
    cloud = gcp.collect({"provider": "gcp", "scopes": [PROJECT], "auth": {"method": "gcloud", "account": session.data["account"], "impersonate_service_account": ""},
                         "options": {"inventories": ["gke_cluster", "service_account", "instance", "network", "subnetwork", "firewall", "route", "shared_vpc"],
                                     "project_restrictions": [PROJECT], "include_inherited": False, "concurrency": 4, "timeout": 15, "retries": 1}})
    cloud = validate(cloud)
    private_write(session.directory / "gke-gcp-snapshot.json", canonical(cloud))
    cluster = [item for c in cloud["collections"] if c["type"] == "gke_cluster" for item in c["items"] if item.get("name") == session.data["cluster"]]
    if len(cluster) != 1 or cluster[0].get("workloadIdentityConfig", {}).get("workloadPool") != PROJECT + ".svc.id.goog":
        raise SessionError("actual_gke_workload_pool_not_collected")
    cloud_seconds = time.monotonic() - start
    request = {"connector": {"provider": "k8s", "name": "owned-gke-native-acceptance", "scopes": [session.data["namespace"]],
                             "auth": {"method": "kubeconfig", "kubeconfig": str(session.kubeconfig),
                                      "context": "gke_" + PROJECT + "_" + ZONE + "_" + session.data["cluster"]},
                             "options": {"inventories": ["pod", "node", "serviceaccount", "namespace", "service", "networkpolicy", "role", "rolebinding",
                                                            "endpointslice", "network_interface", "api_discovery"], "concurrency": 4, "timeout": 20, "retries": 1}},
               "categories": CATEGORIES}
    path = session.directory / "gke-request.json"
    private_write(path, request)
    start = time.monotonic()
    command = [sys.executable, "-m", "peaso.cli", "scan", "--provider", "k8s", "--request", str(path), "--categories", *CATEGORIES,
               "--snapshot-output", str(session.directory / "gke-k8s-snapshot.json"), "--output", str(session.directory / "gke-report.json"), "--embed-native"]
    result = subprocess.run(command, env=session.env, capture_output=True, text=True, timeout=300)
    private_write(session.directory / "gke-cli-progress.log", result.stderr)
    if result.returncode:
        raise SessionError("native_k8s_cli_scan_failed")
    cli_seconds = time.monotonic() - start
    kube = validate(json.loads((session.directory / "gke-k8s-snapshot.json").read_text()))
    from peaso.engine import hydrate_frameworks  # per-check fields live in check_meta (schema 1.1)
    cli_report = json.loads((session.directory / "gke-report.json").read_text())
    report = hydrate_frameworks(cli_report)
    for artifact in ["gke-k8s-snapshot.json", "gke-report.json"]:
        os.chmod(session.directory / artifact, 0o600)
    if any(f["category"] not in CATEGORIES for f in report["findings"]) or report.get("graphs", {}).get("privesc", {}).get("nodes"):
        raise SessionError("unexpected_feature_execution")
    start = time.monotonic()
    offline = evaluate_snapshot(kube, categories=CATEGORIES, include_not_applicable=False)
    expanded = expand_report(offline, kube)
    if "least_privilege" in expanded["stats"].get("categories", []):
        expanded["least_privilege"] = project(kube["provider"], resources(kube), snapshot=kube)
    expected_cli = group_report(without_private_values(expanded))
    actual_cli = {key: value for key, value in cli_report.items() if key not in ("snapshot", "timings")}
    if canonical(expected_cli) != canonical(actual_cli):
        raise SessionError("offline_report_differs_from_live_cli")
    evaluation_seconds = time.monotonic() - start
    markdown = render_markdown(expanded)
    private_write(session.directory / "gke-report.md", markdown)
    expected = fixture_findings(kube, expanded)
    joins = ordinary_joins(cloud, kube, session.data["namespace"])
    private_write(session.directory / "gke-joins.json", joins)
    if not any(x["kind"] == "declared_workload_identity" and x["target"] for x in joins) or not any(x["kind"] == "node_compute_instance" and x["target"] for x in joins):
        raise SessionError("native_cross_provider_join_missing")
    if source_hashes() != before:
        raise SessionError("collector_changed_during_live_acceptance")
    summary = {"gcp": summarize(cloud), "k8s": summarize(kube), "source_hashes": before,
               "gcp_collection_seconds": round(cloud_seconds, 3), "k8s_cli_seconds": round(cli_seconds, 3),
               "offline_evaluation_seconds": round(evaluation_seconds, 3), "offline_identical": True,
               "categories": CATEGORIES, "fixture_expectations": expected, "joins": joins,
               "findings": dict(Counter(f["status"] for f in expanded["findings"])),
               "json_bytes": (session.directory / "gke-report.json").stat().st_size, "markdown_bytes": len(markdown.encode()),
               "credential_material_collected": False, "workload_cloud_access_tested": False}
    private_write(session.directory / "gke-summary.json", summary)
    print(json.dumps({"gke_acceptance": "passed", "gcp_snapshot_id": cloud["snapshot_id"], "k8s_snapshot_id": kube["snapshot_id"], "expected_findings": expected, "join_count": len(joins)}))


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot", nargs="?")
    parser.add_argument("--output")
    parser.add_argument("--live", action="store_true", help="bounded read-only collection of all gcloud-discovered projects/organizations")
    parser.add_argument("--directory", help="private evidence directory for --live")
    parser.add_argument("--account", default=ACCOUNT)
    args = parser.parse_args()
    if args.live:
        if args.snapshot or args.output or not args.directory:
            parser.error("--live requires --directory and excludes snapshot/--output")
        try:
            summary = collect_live(args.directory, args.account)
        except SessionError as exc:
            print("gcp acceptance: " + str(exc), file=sys.stderr)
            return 1
        print(json.dumps({k: summary[k] for k in ("evidence_mode", "project_count", "organization_count", "requested_scope_count",
                         "collection_seconds", "resources", "collection_statuses", "error_codes", "request_error_reasons",
                         "field_error_reasons", "acceptance")}, indent=2))
        return 0 if summary["acceptance"]["outcome"] == "passed" else 1
    if not args.snapshot or not args.output or args.directory:
        parser.error("snapshot summary requires snapshot and --output")
    original = Path(args.snapshot).read_bytes()
    summary = summarize(json.loads(original))
    summary["source_file_sha256"] = hashlib.sha256(original).hexdigest()
    private_write(Path(args.output), summary)
    print(json.dumps({k: v for k, v in summary.items() if k not in {"scope_coverage", "scopes", "resolved_scopes", "scope_coverage_metadata"}}, indent=2))


if __name__ == "__main__":
    raise SystemExit(main())
