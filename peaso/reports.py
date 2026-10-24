"""Complete Markdown exports of inventory, evidence, coverage and defensive graphs."""
from __future__ import annotations
import html
import json
import re
from urllib.parse import urlsplit


def _text(value):
    return html.escape(str(value), quote=False).replace("|", "\\|").replace("\n", "<br>")


def _remediation_text(value):
    escaped = html.escape(str(value), quote=False)
    return re.sub(r"([\\`*_{}\[\]()#+.!|<>])", r"\\\1", escaped).replace("\n", "<br>")


class _RemediationTextMemo:
    """Render-local escaping memo for exact immutable strings only.

    Bounded admission never limits output. Subclasses and other values retain
    the original conversion/escaping path, including its errors and side effects.
    """
    def __init__(self):
        self.entries = {}
        self.bytes = 0

    def __call__(self, value):
        if type(value) is not str or len(value) > 4096:
            return _remediation_text(value)
        cached = self.entries.get(value)
        if cached is not None:
            return cached
        escaped = _remediation_text(value)
        if len(self.entries) < 1024:
            size = len(value.encode("utf-8", errors="surrogatepass")) + len(escaped.encode("utf-8", errors="surrogatepass"))
            if self.bytes + size <= 1024 * 1024:
                self.entries[value] = escaped
                self.bytes += size
        return escaped


from peaso.snapshot import FrozenDict as _JSONFrozenDict, FrozenList as _JSONFrozenList

# The optional native JSON encoder is already supplied by supported Pydantic
# runtimes. Older installations retain the exact stdlib path below.
try:
    from pydantic_core import to_json as _core_pretty_json
except ImportError:
    _core_pretty_json = None
if _core_pretty_json is not None:
    try:
        if _core_pretty_json({'a': 'é'}, indent=2, ensure_ascii=False).decode('utf-8') != json.dumps(
                {'a': 'é'}, indent=2, sort_keys=True, ensure_ascii=False):
            _core_pretty_json = None
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        _core_pretty_json = None


def _strict_pretty_tree(value, active, depth=0):
    # Sorting plain trees once avoids the interpreted pretty-JSON encoder.
    # Exact immutable snapshot views have the same JSON representation; other
    # subclasses, coercions, floats and unusual values keep stdlib semantics.
    kind = type(value)
    if kind is str:
        value.encode('utf-8')  # lone surrogates require the original encoder
        return value
    if value is None or kind is bool:
        return value
    if kind is int:
        if not -(1 << 63) <= value < (1 << 64):
            raise ValueError('stdlib JSON integer handling required')
        return value
    if kind not in (dict, list, _JSONFrozenDict, _JSONFrozenList) or depth >= 64:
        raise ValueError('stdlib JSON encoding required')
    identity = id(value)
    if identity in active:
        raise ValueError('stdlib JSON cycle handling required')
    active.add(identity)
    try:
        if kind is dict or kind is _JSONFrozenDict:
            keys = list(value)
            for key in keys:
                if type(key) is not str:
                    raise ValueError('stdlib JSON key handling required')
                key.encode('utf-8')
            return {key: _strict_pretty_tree(value[key], active, depth + 1) for key in sorted(keys)}
        return [_strict_pretty_tree(item, active, depth + 1) for item in value]
    finally:
        active.remove(identity)


def _pretty_json(value):
    if _core_pretty_json is not None:
        try:
            return _core_pretty_json(_strict_pretty_tree(value, set()),
                                     indent=2, ensure_ascii=False).decode('utf-8')
        except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
            pass
    # Keep the original output and exceptions for every unsupported value.
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)


def _json_block(value):
    text = _pretty_json(value)
    longest = max((len(m.group()) for m in re.finditer(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return [fence + "json", text, fence, ""]


def _remediation_lines(finding, templates, *, shared=True, bound=True, _escape=None):
    """Readable guidance from a reviewed template, with legacy string fallback."""
    from peaso.remediation import bind_command, exposure_details
    escape = _remediation_text if _escape is None else _escape
    detail = finding.get("remediation_details")
    if not isinstance(detail, dict):
        detail = templates.get(finding.get("check_id")) if isinstance(templates, dict) else None
    if not isinstance(detail, dict):
        return ["Remediation: " + _text(finding.get("remediation", "")), ""] if shared else []
    detail = exposure_details(finding, detail)
    lines = ["#### Defensive remediation", "", escape(detail.get("summary") or finding.get("remediation", "")), ""] if shared else []
    steps = detail.get("steps") or []
    if shared:
        for index, step in enumerate(steps, 1):
            lines.append(f"{index}. {escape(step)}")
        if steps:
            lines.append("")
    for command in (detail.get("cli") or []) if bound else []:
        if not isinstance(command, dict) or not isinstance(command.get("code"), str):
            continue
        code = bind_command(command["code"], finding)
        fence = "`" * max(3, max((len(run) for run in re.findall(r"`+", code)), default=0) + 1)
        lines.extend(["**" + escape(command.get("label", "Command example")) + "**", "", fence + "bash", code, fence, ""])
    if shared and isinstance(detail.get("iac"), dict):
        iac = detail["iac"]
        code = str(iac.get("code", ""))
        fence = "`" * max(3, max((len(run) for run in re.findall(r"`+", code)), default=0) + 1)
        lines.extend(["**Infrastructure as code: " + escape(iac.get("label", "Reviewed declaration")) + "**", "",
                      fence + str(iac.get("language", "text")), code, fence, ""])
    if shared and detail.get("caveats"):
        lines.append("**Before changing this**")
        lines.extend("- " + escape(caveat) for caveat in detail["caveats"])
        lines.append("")
    if shared and detail.get("references"):
        lines.append("**References**")
        for reference in detail["references"]:
            url = reference.get("url", "") if isinstance(reference, dict) else ""
            if isinstance(url, str) and urlsplit(url).scheme == "https" and urlsplit(url).netloc:
                lines.append("- [" + escape(reference.get("title", "Official documentation")) + "](" + url + ")")
        lines.append("")
    return lines


def _guidance_fields(finding, templates):
    from peaso.remediation import exposure_details
    detail = finding.get("remediation_details")
    if not isinstance(detail, dict):
        detail = templates.get(finding.get("check_id")) if isinstance(templates, dict) else None
    detail = exposure_details(finding, detail)
    return {
        "check_id": finding.get("check_id"),
        "description": finding.get("description"),
        "evaluated": finding.get("evaluated"),
        "pass_when": finding.get("pass_when"),
        "fail_when": finding.get("fail_when"),
        "not_applicable_when": finding.get("not_applicable_when"),
        "remediation_details": detail if isinstance(detail, dict) else None,
        "remediation": finding.get("remediation") if isinstance(detail, dict) and not detail.get("summary") else None,
    }


def _description_lines(finding):
    if not finding.get("description"):
        return []
    lines = ["#### What this check evaluates", "", _remediation_text(finding["description"]), ""]
    if isinstance(finding.get("evaluated"), list):
        lines.extend(["Fields read:", *["- " + _remediation_text(field) for field in finding["evaluated"]], ""])
    for key, label in (("pass_when", "Pass"), ("fail_when", "Fail"), ("not_applicable_when", "Not applicable")):
        if finding.get(key):
            lines.append(f"- **{label}:** {_remediation_text(finding[key])}")
    lines.append("")
    return lines


def render_markdown(report):
    if not isinstance(report, dict):
        raise ValueError("report must be an object")
    if "added" in report and "changed" in report:
        return _render_diff(report)
    from peaso.engine import hydrate_frameworks
    report = hydrate_frameworks(report)
    if "checks" in report and "findings" not in report:
        return "\n".join(["# Peaso native check catalog", "", *_json_block(report)]).rstrip() + "\n"
    lines = ["# Peaso security snapshot report", "",
        f"Provider: **{_text(report.get('provider', 'unknown'))}**  ",
        "Scopes: " + ", ".join(_text(s) for s in report.get("scopes", [])) + "  ",
        "Snapshot: " + _text(report.get("snapshot_id", "unknown")) + "  ",
        "Collected: " + _text(report.get("created_at", "unknown")), "", "## Summary", ""]
    lines.extend(_json_block(report.get("stats", {})))
    lines.extend(["## Coverage", "", "| Level | Check / inventory | Scope | Status | Reason |", "| --- | --- | --- | --- | --- |"])
    for row in report.get("coverage", []):
        lines.append("| " + " | ".join(_text(row.get(k, "")) for k in ("level", "check_id" if row.get("check_id") else "framework_id" if row.get("framework_id") else "type", "scope", "status", "reason")) + " |")
    lines.extend(["", "Detailed coverage:", ""])
    lines.extend(_json_block(report.get("coverage", [])))
    if report.get("framework_versions"):
        lines.extend(["## Framework checklist versions", ""])
        lines.extend(_json_block([{k: v for k, v in row.items() if k != "native_check_ids"} if isinstance(row, dict) else row for row in report["framework_versions"]]))
    if report.get("snapshot_metadata"):
        lines.extend(["## Snapshot provenance and collection plan", ""])
        lines.extend(_json_block(report["snapshot_metadata"]))
    if "privesc" in report.get("stats", {}) or (report.get("graphs", {}).get("privesc") or {}).get("nodes"):
        lines.extend(_privesc_section(report))
    templates = report.get("remediation_templates")
    remediation_text = _RemediationTextMemo()
    guidance = {}
    finding_guidance = []
    for finding in report.get("findings", []):
        fields = _guidance_fields(finding, templates)
        shared = fields["remediation_details"] is None
        if not fields["description"] and fields["remediation_details"] is None:
            finding_guidance.append((None, shared))
            continue
        key = json.dumps(fields, sort_keys=True, ensure_ascii=False)
        if key not in guidance:
            guidance[key] = (f"check-guidance-{len(guidance) + 1}", finding, shared)
        finding_guidance.append((guidance[key][0], shared))
    if guidance:
        lines.extend(["## Check guidance", "", "Reviewed check meaning and shared remediation appear once here. Each finding below links to its exact guidance and keeps its own evidence and bound commands.", ""])
        for anchor, finding, shared in guidance.values():
            lines.extend([f'<a id="{anchor}"></a>', f"### {_text(finding.get('check_id'))}", ""])
            lines.extend(_description_lines(finding))
            if not shared:
                lines.extend(_remediation_lines(finding, templates, bound=False, _escape=remediation_text))
    lines.extend(["", "Empty and denied inventory are recorded separately from security passes. Unknown and manual results require further evidence.", "", "## Findings", ""])
    for finding, (anchor, shared) in zip(report.get("findings", []), finding_guidance):
        lines.extend([f"### {_text(finding.get('status'))}: {_text(finding.get('title'))}", "",
            "- Finding ID: " + _text(finding.get("id", "")),
            "- Check: " + _text(finding.get("check_id")), "- Category: " + _text(finding.get("category")),
            "- Severity: " + _text(finding.get("severity")), "- Resource: " + _text(finding.get("resource_name", finding.get("resource_id"))),
            "- Native resource ID: " + _text(finding.get("native_resource_id", finding.get("resource_id"))),
            "- Stable resource ID: " + _text(finding.get("resource_id")),
            "- Scope: " + _text(finding.get("scope")), "- Frameworks: " + ", ".join(_text(f) for f in finding.get("frameworks", [])),
            "- Message: " + _text(finding.get("message", "")), ""])
        if anchor is not None:
            lines.extend([f"- Check guidance: [reviewed meaning and remediation](#{anchor})", ""])
        if finding.get("grouped"):
            from peaso.finding_groups import placement
            from peaso.finding_observation import evidence_summary
            lines.extend(["Observed evidence:", "", _text(finding.get("evidence_summary", "")), "",
                "| Asset | Account / project / subscription | Region | Result | Evidence |",
                "| --- | --- | --- | --- | --- |"])
            for member in finding.get("observations", []):
                account, region = placement(member)
                observation = member.get("evidence_summary") or evidence_summary(member) or f"Recorded result: {member.get('status', 'UNKNOWN')}."
                asset = member.get("resource_name") or member.get("native_resource_id") or member.get("resource_id", "")
                lines.append("| " + " | ".join(_text(value) for value in (asset, account, region or "Global / not regional", member.get("status"), observation)) + " |")
            lines.extend(["", "<details><summary>Technical evidence for all observations</summary>", ""])
            lines.extend(_json_block(finding.get("observations", [])))
            lines.extend(["", "</details>", ""])
        else:
            lines.extend(["Evidence:", ""])
            lines.extend(_json_block(finding.get("evidence", {})))
        lines.extend(_remediation_lines(finding, templates, shared=shared, _escape=remediation_text))
    aggregates = report.get("finding_aggregates") or []
    if aggregates:
        lines.extend(["## Aggregated not-applicable and empty results", "",
                      "Per-resource rows with these statuses are counted per check; rerun with --include-not-applicable to list them.", "",
                      "| Status | Check | Title | Count | Scopes | Sample resources |", "| --- | --- | --- | --- | --- | --- |"])
        for row in aggregates:
            lines.append("| " + " | ".join(_text(v) for v in (row.get("status"), row.get("check_id"), row.get("title"), row.get("count"),
                         len(row.get("scopes") or {}), ", ".join(str(x) for x in row.get("sample_resource_ids") or []))) + " |")
        lines.append("")
    lines.extend(["## Resource inventory", "", "Native configuration facts are retained below. No data-plane secrets or object contents are collected.", ""])
    for resource in report.get("resources", []):
        lines.extend(["### " + _text(resource.get("type")) + ": " + _text(resource.get("id")), "", "Scope: " + _text(resource.get("scope")), ""])
        lines.extend(_json_block(resource))
    lines.extend(["## Defensive relationship graphs", "", "Edges record observed configuration references and declared IAM grants. They do not establish effective access or network reachability.", ""])
    for name, graph in report.get("graphs", {}).items():
        lines.extend(["### " + _text(name), ""])
        lines.extend(_json_block(graph))
    return "\n".join(lines).rstrip() + "\n"


def _render_diff(report):
    lines = ["# Peaso snapshot difference", "", "Provider: " + _text(report.get("provider")), "",
        "Before: " + _text(report.get("before_snapshot_id")), "After: " + _text(report.get("after_snapshot_id")), ""]
    lines.extend(_json_block(report.get("stats", {})))
    for name in ("added", "removed", "changed", "coverage_before", "coverage_after"):
        lines.extend(["## " + name.replace("_", " ").title(), ""])
        lines.extend(_json_block(report.get(name, [])))
    return "\n".join(lines).rstrip() + "\n"


PRIVESC_ADMIN_LIMIT = 25
PRIVESC_PATH_LIMIT = 10
PRIVESC_PATH_CANDIDATES = 200
PRIVESC_BROAD_LIMIT = 15
PRIVESC_GAP_LIMIT = 30
PRIVESC_EVIDENCE_LIMIT = 3


def _short(value, limit=200):
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "..."


def _omitted(total, shown):
    return [f"_{total - shown} more omitted; the complete list is in the JSON report._", ""] if total > shown else []


def _privesc_evidence(edge):
    refs = (edge or {}).get("evidence_refs") or []
    parts = []
    for ref in refs[:PRIVESC_EVIDENCE_LIMIT]:
        if not isinstance(ref, dict):
            continue
        keys = ("policy_name", "policy", "statement", "sid") if "policy_name" in ref or "statement" in ref else \
            ("role", "binding", "policy", "condition", "assignment", "scope", "via", "namespace")
        parts.append(", ".join(f"{key}={_short(ref[key], 120)}" for key in keys if ref.get(key) not in (None, "", [])))
    if len(refs) > PRIVESC_EVIDENCE_LIMIT:
        parts.append(f"+{len(refs) - PRIVESC_EVIDENCE_LIMIT} more")
    return "; ".join(p for p in parts if p) or "not recorded"


def _privesc_section(report):
    """Bounded human summary of the privilege-escalation map; the full graph stays in the JSON report."""
    try:
        from peaso.privesc import queries
    except ImportError:
        return ["## Privilege Escalation", "", "The privesc query module is not installed; see the JSON report graph `privesc`.", ""]
    graph = (report.get("graphs") or {}).get("privesc") or {"nodes": [], "edges": []}
    stats = (report.get("stats") or {}).get("privesc") or {}
    findings = [f for f in report.get("findings", []) if f.get("category") == "privesc"]
    by_id = {f.get("id"): f for f in findings}
    nodes = {n["id"]: n for n in graph.get("nodes", [])}
    edges = {e["id"]: e for e in graph.get("edges", [])}
    label = lambda node_id: _text(_short((nodes.get(node_id) or {}).get("label") or node_id, 120))
    status_counts, severity_counts = {}, {}
    for finding in findings:
        status_counts[finding.get("status")] = status_counts.get(finding.get("status"), 0) + 1
        if finding.get("status") == "FAIL":
            severity_counts[finding.get("severity")] = severity_counts.get(finding.get("severity"), 0) + 1
    lines = ["## Privilege Escalation", "",
             "Paths are derived offline from collected policies, bindings and the technique catalog. They are not exploited; "
             "`conditional` and `unknown` edges need owner review.", ""]
    if stats.get("error"):
        lines.extend([f"Evaluation failed ({_text(stats['error'])}); see coverage. No privesc result is a pass.", ""])
    try:
        admins = queries.reach_admin(graph, max_depth=6)
        broad = queries.broad_reach(graph, min_targets=50)
    except (KeyError, TypeError, ValueError):
        admins, broad = [], []
    lines.extend(["| Metric | Value |", "| --- | --- |"])
    for key, value in (("Techniques evaluated", stats.get("techniques")), ("Principals", stats.get("principals")),
                       ("Nodes", stats.get("nodes", len(nodes))), ("Edges", stats.get("edges", len(edges))),
                       ("Edges by confidence", stats.get("edges_by_confidence")), ("Findings by status", status_counts),
                       ("Failing findings by severity", severity_counts), ("Principals already admin-equivalent", stats.get("admin_principals")),
                       ("Principals reaching admin-equivalent", len({row["principal"] for row in admins})),
                       ("Evaluation time (s)", ((report.get("timings") or {}).get("privesc") or {}).get("engine_seconds"))):
        if value is not None:
            lines.append(f"| {key} | {_text(json.dumps(value, sort_keys=True) if isinstance(value, dict) else value)} |")
    lines.append("")
    lines.extend(["### Principals reaching admin-equivalent", ""])
    if admins:
        lines.extend(["| Principal | Type | Reaches | Hops | Confidence |", "| --- | --- | --- | --- | --- |"])
        for row in admins[:PRIVESC_ADMIN_LIMIT]:
            lines.append(f"| {_text(_short(row.get('label') or row['principal'], 120))} | {_text(row.get('type') or '')} | "
                         f"{_text(_short(row.get('admin_label') or row.get('admin'), 120))} | {row.get('distance')} | {_text(row.get('confidence'))} |")
        lines.append("")
        lines.extend(_omitted(len(admins), min(len(admins), PRIVESC_ADMIN_LIMIT)))
    else:
        lines.extend(["No principal reaches an admin-equivalent scope through the evaluated techniques.", ""])
    lines.extend(["### Top escalation paths", "",
                  "Escalations through a catalog technique are listed before principals that already hold admin-equivalent grants.", ""])
    rank = {"derived": 0, "conditional": 1, "unknown": 2}
    candidates = []
    for row in admins[:PRIVESC_PATH_CANDIDATES]:
        try:
            paths = queries.shortest_paths(graph, row["principal"], max_depth=6, limit=1)
        except (KeyError, TypeError, ValueError):
            paths = []
        if paths:
            path = paths[0]
            already_admin = all(set(step.get("techniques") or []) <= {"admin-equivalent"} for step in path["steps"] if step["via"] == "edge")
            candidates.append(((already_admin, rank.get(path["confidence"], 3), path["length"], path["source"]), path))
    candidates.sort(key=lambda item: item[0])
    shown = 0
    for _, path in candidates[:PRIVESC_PATH_LIMIT]:
        shown += 1
        lines.extend([f"{shown}. **{label(path['source'])}** -> **{label(path['target'])}** "
                      f"({path['length']} hop(s), {_text(path['confidence'])})", ""])
        for step in path["steps"]:
            if step["via"] == "membership":
                lines.append(f"   - {label(step['from'])} includes {label(step['to'])} (aggregate membership)")
                continue
            edge = edges.get(step.get("edge")) or {}
            finding = next((by_id[f] for f in edge.get("findings", []) if f in by_id), None)
            lines.append(f"   - {label(step['from'])} -> {label(step['to'])}: technique "
                         f"`{_text(', '.join(step.get('techniques') or []))}`, {_text(step.get('confidence'))}")
            lines.append(f"     - Evidence: {_text(_privesc_evidence(edge))}")
            if finding and finding.get("remediation"):
                lines.append(f"     - Mitigation: {_text(_short(finding['remediation'], 400))}")
        lines.append("")
    if not shown:
        lines.extend(["No admin-reaching path to show.", ""])
    lines.extend(_omitted(len(candidates), shown))
    lines.extend(["### Techniques with broad reach", "",
                  "Principals whose direct edges reach at least 50 principals, an aggregate of every candidate, or an admin scope.", ""])
    if broad:
        lines.extend(["| Principal | Reached | Admin | Techniques | Aggregates |", "| --- | --- | --- | --- | --- |"])
        out_edges = {}
        for edge in graph.get("edges", []):
            out_edges.setdefault(edge["source"], []).append(edge)
        for row in broad[:PRIVESC_BROAD_LIMIT]:
            techniques = sorted({t for e in out_edges.get(row["principal"], []) for t in e.get("techniques", []) if t != "admin-equivalent"})
            aggregates = [label(a) for a in row.get("aggregates", [])[:3]]
            lines.append(f"| {_text(_short(row.get('label') or row['principal'], 120))} | {row.get('reached')} | {'yes' if row.get('admin') else 'no'} | "
                         f"{_text(_short(', '.join(techniques[:5]) + (' ...' if len(techniques) > 5 else ''), 300))} | "
                         f"{'; '.join(aggregates)}{' ...' if len(row.get('aggregates', [])) > 3 else ''} |")
        lines.append("")
        lines.extend(_omitted(len(broad), min(len(broad), PRIVESC_BROAD_LIMIT)))
    else:
        lines.extend(["No principal with broad reach.", ""])
    gaps = [c for c in report.get("coverage", []) if c.get("level") == "privesc" or (c.get("level") == "check" and c.get("type") == "privesc" and c.get("status") != "evaluated")]
    unknown = status_counts.get("UNKNOWN", 0)
    lines.extend(["### Unknowns and coverage gaps", "",
                  f"{unknown} privesc finding(s) are UNKNOWN because required facts were missing. Missing data is never treated as absence.", ""])
    if gaps:
        lines.extend(["| Kind | Scope | Status | Reason | Impact |", "| --- | --- | --- | --- | --- |"])
        for row in gaps[:PRIVESC_GAP_LIMIT]:
            lines.append("| " + " | ".join(_text(_short(row.get(k, ""), 200)) for k in ("kind", "scope", "status", "reason", "impact")) + " |")
        lines.append("")
        lines.extend(_omitted(len(gaps), min(len(gaps), PRIVESC_GAP_LIMIT)))
    return lines
