"""One-shot scan, collect, evaluate, report and diff commands."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
from .engine import collect_snapshot, evaluate_snapshot, expand_report, diff_reports, get_catalog, REPORT_SCHEMA_VERSION
from .reports import render_markdown
from .progress import ProgressReporter
from .snapshot import nothing_readable


def _load(path):
    from contextlib import nullcontext
    with (nullcontext(sys.stdin) if str(path) == "-" else open(path, encoding="utf-8")) as stream:
        if str(path).endswith((".yaml", ".yml")):
            import yaml
            value = yaml.safe_load(stream)
        else:
            value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError("input must contain an object")
    return value


def _write(value, destination, format, *, include_private=False):
    if not include_private:
        from .secret_evidence import without_private_values
        value = without_private_values(value)
    from .finding_groups import group_report
    value = group_report(value)
    text = render_markdown(value) if format == "markdown" else json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if destination:
        path = Path(destination).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(text)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    else:
        sys.stdout.write(text)


def _selectors(parser):
    parser.add_argument("--categories", nargs="+", help="Select catalog categories (see catalog for the complete list)")
    parser.add_argument("--checks", nargs="+", help="native check IDs, 'privesc', or privesc technique IDs")
    parser.add_argument("--frameworks", nargs="+", help="hacktricks nist_800_53, or full framework names")


def _output(parser):
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--output", "-o")


def _embed(parser):
    parser.add_argument("--embed-native", action="store_true",
                        help="emit report schema 1.0 with native items embedded in resources and graph nodes (larger output)")
    parser.add_argument("--include-not-applicable", action="store_true",
                        help="keep per-resource NOT_APPLICABLE / EMPTY rows in findings (default: per-check counts in finding_aggregates)")


def _related(parser):
    parser.add_argument("--related-snapshot", action="append", default=[], dest="related_snapshots", metavar="PATH",
                        help="snapshot JSON of a related provider, e.g. the cloud account/project of a K8s cluster "
                             "(repeatable); joined read-only by the privesc evaluator for cross-provider paths")


def _content_file_routes(auth, options):
    """Keep selected content inputs in options and private credentials in auth."""
    if not isinstance(auth, dict) or not isinstance(options, dict):
        raise ValueError("connector auth and options must be objects")
    if any(isinstance(key, str) and key.startswith("selected_") for key in auth):
        raise ValueError("selected content targets must be in connector options")
    if any(key in options for key in ("registry_auth", "gke_image_kubernetes", "aks_workloads",
                                       "registry_auth_document", "image_pull_secret")):
        raise ValueError("content credentials must be in connector auth")

def _expanded(report, snapshot=None):
    """Markdown and --embed-native need native data inline; a 1.1 report without its snapshot is left as is."""
    if not isinstance(report, dict) or report.get("schema_version") != REPORT_SCHEMA_VERSION:
        return report
    snapshot = snapshot if snapshot is not None else report.get("snapshot")
    return expand_report(report, snapshot) if isinstance(snapshot, dict) and snapshot.get("snapshot_id") == report.get("snapshot_id") else report


def build_parser():
    parser = argparse.ArgumentParser(prog="hacktricks-cspm", description="Read-only cloud inventory and offline defensive security review")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("scan", "collect"):
        command = commands.add_parser(name)
        command.add_argument("--request", help="JSON/YAML scan request containing connector; - reads JSON from stdin")
        command.add_argument("--provider", choices=("aws", "gcp", "azure", "k8s"))
        command.add_argument("--name", default="cli")
        command.add_argument("--scopes", nargs="+", help="account/project/subscription or cluster namespace selection")
        command.add_argument("--auth-file", help="private JSON/YAML connector auth object; - reads JSON from stdin; SDK default credentials when omitted")
        command.add_argument("--options-file", help="JSON/YAML collection settings and optional explicit limits")
        command.add_argument("--profile", help="AWS profile")
        command.add_argument("--context", help="Kubernetes kubeconfig context")
        command.add_argument("--demo", action="store_true", help="deterministic offline sample, no cloud calls")
        command.add_argument("--snapshot", help="offline snapshot JSON input, no cloud calls")
        command.add_argument("--snapshot-output", help="save collected immutable snapshot JSON")
        command.add_argument("--quiet", action="store_true", help="suppress stderr progress updates")
        command.add_argument("--embed-snapshot", action="store_true",
                             help="also embed the collected snapshot in the scan report (default: referenced by snapshot_id; see --snapshot-output)")
        if name == 'scan':
            command.add_argument('--include-secret-values', action='store_true',
                                 help='include private matched values in an owned JSON --output file; fresh live scans only')
        _selectors(command)
        _output(command)
        _embed(command)
        _related(command)
    command = commands.add_parser("evaluate")
    command.add_argument("snapshot")
    command.add_argument("--quiet", action="store_true", help="suppress stderr progress updates")
    _selectors(command)
    _output(command)
    _embed(command)
    _related(command)
    command = commands.add_parser("report")
    command.add_argument("report")
    _output(command)
    command.set_defaults(format="markdown")
    command = commands.add_parser("diff")
    command.add_argument("before")
    command.add_argument("after")
    _selectors(command)
    _output(command)
    command = commands.add_parser("catalog")
    _output(command)
    return parser


def _execute(args, selectors):
    related = [_load(path) for path in getattr(args, "related_snapshots", None) or []]
    if args.command in ("scan", "collect"):
        request = _load(args.request) if args.request else {}
        connector = request.setdefault("connector", {})
        if not isinstance(connector, dict):
            raise ValueError("connector must be an object")
        if args.provider:
            connector["provider"] = args.provider
        if args.name != "cli" or "name" not in connector:
            connector["name"] = args.name
        if args.scopes:
            connector["scopes"] = args.scopes
        auth = connector.setdefault("auth", {})
        options = connector.setdefault("options", {})
        _content_file_routes(auth, options)
        if args.auth_file:
            auth.update(_load(args.auth_file))
        if args.options_file:
            options.update(_load(args.options_file))
        if args.profile:
            auth["profile"] = args.profile
        if args.context:
            auth["context"] = args.context
        if args.demo:
            options["demo"] = True
        _content_file_routes(auth, options)
        if connector.get("provider") == "gcp" and auth.get("method") == "platform-service-account" and not (args.demo or args.snapshot):
            from .gcp_platform import load_service_account
            auth["sa_json"] = load_service_account(os.getenv("PEASO_GCP_PLATFORM_SA_SECRET_ARN", ""))
        if args.snapshot:
            snapshot = _load(args.snapshot)
            connector.setdefault("provider", snapshot.get("provider"))
            options["snapshot"] = snapshot
        for key, value in selectors.items():
            if value is not None:
                request[key] = value
        from .content_scan_selection import normalize_request, capture_checks, effective_options
        request = normalize_request(request)
        effective_selectors = {key: request.get(key) for key in ("categories", "checks", "frameworks", "content_checks")}
        include = bool(args.include_not_applicable)
        if args.command == 'scan':
            request['include_not_applicable'] = include
            if related:
                request['related_snapshots'] = related
        from .secret_evidence import capture, EphemeralCipher
        with capture(EphemeralCipher(), options=effective_options(request), selected_checks=capture_checks(request)) as secret_capture:
            snapshot = collect_snapshot(request)
        snapshot = secret_capture.public_snapshot(snapshot)
        if args.command == 'scan':
            timings = {}
            value = evaluate_snapshot(snapshot, **effective_selectors, timings=timings,
                include_not_applicable=include, related_snapshots=related)
            if timings:
                value['timings'] = timings
        else:
            value = snapshot
        if args.snapshot_output:
            _write(snapshot, args.snapshot_output, "json")
        if args.command == "collect" and args.format == "markdown":
            value = _expanded(evaluate_snapshot(snapshot, **effective_selectors, include_not_applicable=include, related_snapshots=related), snapshot)
        elif args.command == "scan":
            if args.embed_native or args.format == "markdown":
                value = _expanded(value, snapshot)
            if args.embed_snapshot:
                value["snapshot"] = snapshot
    elif args.command == "evaluate":
        snapshot = _load(args.snapshot)
        value = evaluate_snapshot(snapshot, **selectors, include_not_applicable=bool(args.include_not_applicable), related_snapshots=related)
        if args.embed_native or args.format == "markdown":
            value = _expanded(value, snapshot)
    elif args.command == "report":
        value = _expanded(_load(args.report))
    elif args.command == "diff":
        before, after = _load(args.before), _load(args.after)
        if "collections" in before:
            before = evaluate_snapshot(before, **selectors)
        if "collections" in after:
            after = evaluate_snapshot(after, **selectors)
        value = diff_reports(before, after)
    else:
        value = get_catalog()
    if args.command in ("scan", "evaluate") and "least_privilege" in value.get("stats", {}).get("categories", []):
        from .least_privilege import project
        from .snapshot import resources
        value["least_privilege"] = project(snapshot["provider"], resources(snapshot), snapshot=snapshot)
    if args.command == 'scan' and args.include_secret_values:
        from .secret_evidence import export_report
        value = export_report(value, secret_capture)
    _write(value, args.output, args.format, include_private=bool(getattr(args, 'include_secret_values', False)))
    if args.command in ("scan", "collect") and snapshot is not None and nothing_readable(snapshot):
        codes = sorted({str((c.get("error") or {}).get("code")) for c in snapshot.get("collections", []) if c.get("error")})
        print("hacktricks-cspm: no collection could be read with the supplied credentials (" + ", ".join(codes or ["no collections"]) +
              "); the report contains no assessment. Check the auth method (e.g. --auth-file) and credentials.", file=sys.stderr)
        return 3
    return 0


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, 'include_secret_values', False) and (args.format != 'json' or not args.output or args.output == '-'):
        parser.error('--include-secret-values requires a JSON --output file')
    selectors = {key: getattr(args, key, None) for key in ("categories", "checks", "frameworks")}
    received = []
    try:
        from .cancellation import collection_cancellation
        active = args.command in ("scan", "collect", "evaluate")
        with collection_cancellation() as received, ProgressReporter(quiet=not active or getattr(args, "quiet", False), provider=getattr(args, "provider", None)):
            code = _execute(args, selectors)
            return 128 + received[0] if received else code
    except KeyboardInterrupt:
        print("hacktricks-cspm: scan cancelled; provider cleanup completed.", file=sys.stderr)
        return 128 + received[0] if received else 130
    except Exception as exc:
        message = "unable to process the request; check input files, selectors and credentials."
        if isinstance(exc, ValueError) and str(exc).startswith("check requires external policy or manual evidence"):
            message = "selected check requires external policy or manual evidence and cannot run automatically."
        print(f"hacktricks-cspm: {type(exc).__name__}: {message}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
