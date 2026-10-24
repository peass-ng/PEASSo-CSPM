"""Reproduce/validate the reference manifest without running any upstream code.

Sources are local checkouts at the exact revisions in rulepacks/sources.json.
Only explicit reviewed associations in reviewed.json can become supported.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import sys
import gzip

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
PACK = ROOT / "peaso" / "rulepacks"
TOKEN = re.compile(r'(?P<heredoc><<-?(?P<label>[A-Za-z_]\w*)[^\n]*\n.*?^\s*(?P=label)\s*$)|"(?:\\.|[^"\\])*"|/\*.*?\*/|//[^\n]*|\#[^\n]*|[{}]', re.M | re.S)


def blocks(text):
    for match in re.finditer(r'^(control|benchmark|query)\s+"([^"]+)"\s*\{', text, re.M):
        depth = 1
        for token in TOKEN.finditer(text, match.end()):
            depth += (token[0] == "{") - (token[0] == "}")
            if depth == 0:
                yield match[1], match[2], text[match.end():token.start()], text[:match.start()].count("\n") + 1
                break
        else:
            raise ValueError("unterminated source block " + match[2])


def quoted(body, key):
    match = re.search(r'^\s*' + re.escape(key) + r'\s*=\s*("(?:\\.|[^"\\])*")', body, re.M)
    return json.loads(match[1]) if match else ""


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def source_fingerprint(directory):
    """Bind the parsed reference corpus to its pinned archive, including license."""
    if directory.name == "prowler":
        files = [p for base in (directory / "prowler" / "providers", directory / "prowler" / "compliance")
            for p in base.rglob("*") if p.is_file() and p.suffix in (".py", ".json")]
    else:
        files = list(directory.rglob("*.pp"))
    files.append(directory / "LICENSE")
    digest = hashlib.sha256()
    for path in sorted(files):
        digest.update(str(path.relative_to(directory)).encode() + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def read_json(path):
    return json.loads(path.read_text())


def prowler_rows(directory, source):
    compliance = defaultdict(list)
    provider_names = {path.name: "k8s" if path.name == "kubernetes" else path.name
        for path in (directory / "prowler" / "providers").iterdir() if path.is_dir() and (path / "services").exists()}
    for provider in provider_names:
        for path in sorted((directory / "prowler" / "compliance" / provider).glob("*.json")):
            data = read_json(path)
            for requirement in data.get("Requirements", []):
                for check_id in requirement.get("Checks", []):
                    compliance[(provider, check_id)].append({"framework": data.get("Name", path.stem),
                        "framework_id": path.stem, "framework_family": data.get("Framework"), "version": data.get("Version") or source["revision"], "declared_version": data.get("Version"),
                        "control_id": str(requirement["Id"]), "source": str(path.relative_to(directory))})
    result = []
    found = set()
    for provider, native_provider in provider_names.items():
        for path in sorted((directory / "prowler" / "providers" / provider / "services").rglob("*.metadata.json")):
            data = read_json(path)
            cid = data["CheckID"]
            found.add((provider, cid))
            code = path.with_name(cid + ".py")
            result.append({"check_id": "prowler." + provider + "." + cid, "upstream_id": cid, "provider": native_provider,
                "title": data.get("CheckTitle"), "service": data.get("ServiceName"), "severity": data.get("Severity"), "catalog_entry_type": "definition",
                "rationale": data.get("Risk", ""), "dependencies": data.get("DependsOn", []),
                "source": "https://github.com/" + source["repository"] + "/blob/" + source["revision"] + "/" + str(path.relative_to(directory)),
                "revision": source["revision"], "repository": source["repository"], "license": source["license"],
                "upstream_evaluator": {"language": "python", "version": source["revision"], "sha256": sha(code.read_text()) if code.exists() else None,
                    "source_path": str(code.relative_to(directory))}, "frameworks": compliance[(provider, cid)]})
    # Preserve mappings to retired/missing definitions; never invent executable checks.
    for (provider, cid), mappings in sorted(compliance.items()):
        if (provider, cid) not in found:
            result.append({"check_id": "prowler." + provider + "." + cid, "upstream_id": cid, "provider": provider_names[provider],
                "title": "Compliance reference without current definition", "service": "unknown", "severity": "unknown", "catalog_entry_type": "unresolved_compliance_reference", "rationale": "Referenced by compliance mapping at pinned revision but no metadata definition exists", "dependencies": [],
                "source": "https://github.com/" + source["repository"] + "/tree/" + source["revision"] + "/prowler/compliance/" + provider,
                "revision": source["revision"], "repository": source["repository"], "license": source["license"],
                "upstream_evaluator": {"language": "python", "version": source["revision"], "sha256": None}, "frameworks": mappings})
    return result


def turbot_rows(directory, source):
    definitions = defaultdict(dict)
    for path in sorted(directory.rglob("*.pp")):
        for kind, name, body, line in blocks(path.read_text()):
            if name in definitions[kind]:
                raise ValueError("duplicate " + kind + ": " + name)
            definitions[kind][name] = {"body": body, "path": str(path.relative_to(directory)), "line": line}
    parents = defaultdict(set)
    for name, block in definitions["benchmark"].items():
        children = re.search(r'children\s*=\s*\[(.*?)\]', block["body"], re.S)
        if children:
            for kind, child in re.findall(r'\b(benchmark|control)\.([\w]+)', children[1]):
                parents[(kind, child)].add(name)
    def ancestors(kind, name):
        seen, todo = set(), list(parents[(kind, name)])
        while todo:
            current = todo.pop()
            if current not in seen:
                seen.add(current)
                todo.extend(parents[("benchmark", current)])
        return sorted(seen)
    suite = directory.name.removeprefix("steampipe-mod-")
    provider = suite.split("-")[0]
    result = []
    for name, block in sorted(definitions["control"].items()):
        body = block["body"]
        refs = sorted(set(re.findall(r'\bquery\.([\w]+)', body)))
        query_bodies = [definitions["query"][ref]["body"] for ref in refs if ref in definitions["query"]]
        sql = "\n".join(query_bodies) if query_bodies else body
        dependencies = sorted(set(re.findall(r'\b(?:from|join)\s+((?:aws|gcp|azure|azuread|kubernetes)_[\w]+)', sql, re.I)))
        lineage = ancestors("control", name)
        roots = [b for b in lineage if not parents[("benchmark", b)]]
        framework_roots = [b for b in roots if b != "all_controls"]
        mappings = []
        for b in framework_roots:
            framework = quoted(definitions["benchmark"][b]["body"], "title") or b
            # Preserve all ancestor IDs without turning sections/headings into frameworks.
            branch = [a for a in lineage if a == b or b in ancestors("benchmark", a)]
            version_match = re.search(r"\bv?(\d+\.\d+(?:\.\d+)*)\b", framework)
            revision_match = re.search(r"\b(?:Revision|Rev\.?)\s+(\d+)\b", framework, re.I)
            integer_version = re.search(r"\bv(\d+)\b", framework, re.I)
            edition_year = re.search(r"\b((?:19|20)\d{2})\b", framework)
            declared_version = (version_match[1] if version_match else revision_match[0] if revision_match else
                integer_version[1] if integer_version else edition_year[1] if edition_year else None)
            mappings.append({"framework": framework, "framework_family": framework_family(b, framework),
                "framework_id": suite + ".benchmark." + b, "control_id": suite + ".control." + name,
                "benchmark_ids": [suite + ".benchmark." + a for a in branch],
                "version": declared_version or source["revision"], "declared_version": declared_version,
                "source_revision": source["revision"], "source": definitions["benchmark"][b]["path"]})
        result.append({"check_id": suite + ".control." + name, "upstream_id": name, "provider": "k8s" if provider == "kubernetes" else provider,
            "title": quoted(body, "title"), "service": quoted(body, "service") or "unknown", "severity": "unspecified", "catalog_entry_type": "definition",
            "rationale": quoted(body, "description"), "dependencies": dependencies,
            "source": "https://github.com/" + source["repository"] + "/blob/" + source["revision"] + "/" + block["path"] + "#L" + str(block["line"]),
            "revision": source["revision"], "repository": source["repository"], "license": source["license"],
            "upstream_evaluator": {"language": "sql", "version": source["revision"], "sha256": sha(sql), "query_ids": refs,
                "query_sources": [definitions["query"][ref]["path"] for ref in refs if ref in definitions["query"]]}, "frameworks": mappings,
            "upstream_benchmark_ids": [suite + ".benchmark." + b for b in lineage],
            "upstream_control_tags": {m[1]: json.loads(m[2]) for m in re.finditer(r'\b([\w]+)\s*=\s*("(?:\\.|[^"\\])*")', body)}})
    return result


def framework_family(identifier, title):
    if identifier.startswith(("nist_800_53", "nist_sp_800_53")):
        return "NIST 800-53"
    if identifier.startswith("cis_") or identifier == "cis":
        return "CIS"
    if identifier.startswith("pci_"):
        return "PCI DSS"
    if identifier.startswith("soc_2"):
        return "SOC 2"
    if identifier.startswith("hipaa"):
        return "HIPAA"
    if identifier.startswith("nist_csf"):
        return "NIST CSF"
    if identifier.startswith("iso27001") or identifier.startswith("iso_27001"):
        return "ISO 27001"
    return title


def build(sources_root):
    from peaso.checks import CHECKS
    registry = {c.id: c for c in CHECKS}
    sources = read_json(PACK / "sources.json")
    reviewed = {}
    active = PACK / "active_reviews.json"
    registry_config = read_json(active) if active.exists() else {}
    paths = [PACK / name for name in registry_config["shards"]] if active.exists() else sorted(PACK.glob("reviewed*.json"))
    for path in paths:
        shard = read_json(path)
        excluded = registry_config.get("deferred_source_ids", {}).get(path.name, {})
        shard = {key: value for key, value in shard.items() if key not in excluded}
        duplicate = set(reviewed).intersection(shard)
        for key in duplicate:
            lead_supersession = registry_config.get("pending_supersessions", {}).get(path.name, {}).get(key)
            if (shard[key].get("supersedes") != key and not lead_supersession) or reviewed[key]["disposition"] != "pending":
                raise ValueError("duplicate review ownership requires explicit supersedes of pending row: " + key)
            shard[key] = {**shard[key], "review_history": [reviewed[key]], **({"lead_supersession_reason": lead_supersession} if lead_supersession else {})}
        reviewed.update(shard)
    rows = []
    for source in sources["sources"]:
        directory = sources_root / source["repository"].split("/")[-1]
        license_file = directory / "LICENSE"
        if not license_file.exists() or "Apache License" not in license_file.read_text()[:1000]:
            raise ValueError("verify source license: " + str(directory))
        if source.get("reference_tree_sha256") and source_fingerprint(directory) != source["reference_tree_sha256"]:
            raise ValueError("reference source corpus differs from pinned archive: " + str(directory))
        rows.extend(prowler_rows(directory, source) if source["repository"] == "prowler-cloud/prowler" else turbot_rows(directory, source))
    matched_reviews = set()
    for row in rows:
        key = row["check_id"]
        review = reviewed.get(key)
        # A reviewed query association applies to every framework control using ONLY that predicate.
        if review is None and len(row["upstream_evaluator"].get("query_ids", [])) == 1:
            query_key = row["repository"].split("/")[-1].removeprefix("steampipe-mod-") + ".query." + row["upstream_evaluator"]["query_ids"][0]
            review = reviewed.get(query_key)
            if review is not None:
                matched_reviews.add(query_key)
        if review is not None:
            matched_reviews.add(key)
            row.update(review)
        else:
            row.update(disposition="pending", native_checks=[], reason="Not yet reviewed/ported; native facts, version applicability and predicate equivalence require review")
        row["runtime_provider_supported"] = row["provider"] in ("aws", "gcp", "azure", "k8s")
        if not row["runtime_provider_supported"]:
            row.update(disposition="out_of_scope", native_checks=[])
            row["reason"] = "Reference inventory retained; provider is outside the current four-provider runtime and no predicate is implemented"
        unregistered = [cid for cid in row["native_checks"] if cid not in registry]
        if unregistered:
            raise ValueError("review shard references unregistered native checks; finish registry integration first: " + ", ".join(unregistered))
        row["expected_cost"] = {"cloud_calls_at_evaluation": 0 if row["native_checks"] else None, "snapshot": "linear in applicable resources" if row["native_checks"] else "not implemented"}
        row["native_evaluators"] = [{"check_id": cid, "version": "1.0.0", "language": "python", "entrypoint": "peaso.checks:evaluate_check", "dependencies": registry[cid].dependencies} for cid in row["native_checks"]]
    unmatched = sorted(set(reviewed) - matched_reviews)
    if unmatched:
        raise ValueError("reviewed IDs absent from pinned source: " + ", ".join(unmatched))
    return {"schema_version": "1.1", "reviewed_at": sources["reviewed_at"], "sources": sources["sources"], "checks": sorted(rows, key=lambda r: r["check_id"])}


def validate_manifest(data):
    from peaso.checks import CHECKS, HACKTRICKS, resolve_check_id
    registry = {c.id: c for c in CHECKS}
    ids = set()
    for row in data["checks"]:
        if row["check_id"] in ids:
            raise ValueError("duplicate upstream check ID")
        ids.add(row["check_id"])
        if row["disposition"] not in ("ported", "merged", "rejected", "pending", "out_of_scope") or not row["reason"]:
            raise ValueError("explicit review disposition/reason required")
        if row["disposition"] == "out_of_scope" and row.get("runtime_provider_supported", True):
            raise ValueError("target provider cannot be marked out_of_scope")
        if row.get("review_classification") == "manual_attestation":
            if row["disposition"] != "rejected" or row["native_checks"] or not isinstance(row.get("manual_requirement"), dict) or not row["manual_requirement"].get("question"):
                raise ValueError("manual attestation requires source question and rejection as automated check")
        if row["disposition"] in ("ported", "merged"):
            # The pinned upstream manifest retains historical native IDs.
            # Exact duplicate aliases still require their registered survivor;
            # arbitrary missing IDs remain an error.
            if not row["native_checks"] or any(resolve_check_id(cid) not in registry for cid in row["native_checks"]):
                raise ValueError("supported reference requires real native evaluator")
        elif row["native_checks"]:
            raise ValueError("pending/rejected reference must not claim support")
        if not re.fullmatch("[0-9a-f]{40}", row["revision"]) or not row["license"] or not row["source"].startswith("https://github.com/"):
            raise ValueError("pinned source/license required")
        for mapping in row["frameworks"]:
            if not mapping.get("framework") or not mapping.get("framework_id") or not mapping.get("control_id") or not mapping.get("version"):
                raise ValueError("framework/control/version mapping required")
    from peaso.checks.catalog import display_names_from_rows, raw_framework_catalog
    display = display_names_from_rows(raw_framework_catalog(data))
    canonical = set(display.values()) | {HACKTRICKS}
    from peaso.analysis import ANALYSIS_CHECKS
    from peaso.checks.hacktricks_scope import includes, validate_review
    validate_review([check.id for check in CHECKS] + [check["id"] for check in ANALYSIS_CHECKS])
    for check in CHECKS:
        public = check.public()
        if (HACKTRICKS in public["frameworks"]) != includes(check.id) or not public["dependencies"]:
            raise ValueError("native check needs reviewed checklist membership and dependencies")
        # One canonical display name per framework version; family slugs are filter aliases, never labels.
        if not set(public["frameworks"]) <= canonical or any(display[fid] not in public["frameworks"] for fid in public["framework_ids"] if fid in display):
            raise ValueError("non-canonical framework labels on " + check.id)
    totals = Counter(r["disposition"] for r in data["checks"])
    return {"native_checks": len(CHECKS), "upstream_total": len(ids), "entry_types": dict(Counter(r.get("catalog_entry_type", "definition") for r in data["checks"])), "dispositions": {key: totals[key] for key in ("ported", "merged", "rejected", "pending", "out_of_scope")},
        "outside_runtime_provider_scope": sum(not r.get("runtime_provider_supported", True) for r in data["checks"]),
        "by_provider": {provider: dict(Counter(r["disposition"] for r in data["checks"] if r["provider"] == provider)) for provider in ("aws", "gcp", "azure", "k8s")}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources-root", type=Path)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--benchmark", action="store_true")
    args = parser.parse_args()
    if args.benchmark:
        from peaso.checks.batch import benchmark
        print(json.dumps(benchmark(), indent=2))
        return
    if args.write:
        if not args.sources_root:
            parser.error("--write requires --sources-root pinned reference checkouts")
        data = build(args.sources_root)
        validate_manifest(data)
        serialized = json.dumps(data, separators=(",", ":"), ensure_ascii=False) + "\n"
        (PACK / "upstream_manifest.json").write_text(serialized)
        (PACK / "upstream_manifest.json.gz").write_bytes(gzip.compress(serialized.encode(), mtime=0))
        from peaso.checks.catalog import clear_caches, framework_catalog, runtime_metadata, manual_requirements
        runtime = runtime_metadata(data)
        (PACK / "runtime_metadata.json").write_text(json.dumps(runtime, separators=(",", ":"), ensure_ascii=False) + "\n")
        summary = {**runtime["coverage"], "phase": "expansion_in_progress" if runtime["coverage"]["upstream"]["pending"] else "review_complete"}
        (PACK / "catalog_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        clear_caches()
        from peaso.checks import CHECKS
        (PACK / "native_catalog.json").write_text(json.dumps({"schema_version": "1.0", "evaluator_version": "1.0.0", "checks": [c.public() for c in CHECKS]}, ensure_ascii=False, separators=(",", ":")) + "\n")
        (PACK / "framework_catalog.json").write_text(json.dumps({"schema_version": "1.0", "frameworks": framework_catalog()}, indent=2) + "\n")
        (PACK / "manual_catalog.json").write_text(json.dumps({"schema_version": "1.1", "requirements": manual_requirements()}, indent=2) + "\n")
    else:
        data = read_json(PACK / "upstream_manifest.json")
    print(json.dumps(validate_manifest(data), indent=2))


if __name__ == "__main__":
    main()
