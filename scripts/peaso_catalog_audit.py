"""Audit materialized native coverage without executing collectors or evaluators.

This establishes catalog consistency, not predicate correctness or certification.
Source identifiers and compliance control mappings remain distinct from native
predicate counts. A concurrent edit invalidates the capture rather than silently
mixing generations of the catalogs.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

PROVIDERS = ("aws", "azure", "gcp", "k8s")
DISPOSITIONS = {"ported", "merged", "pending", "rejected", "out_of_scope"}
SUPPORTED = {"ported", "merged"}
FILES = ("upstream_manifest.json", "native_catalog.json", "runtime_metadata.json",
         "framework_catalog.json", "manual_catalog.json", "catalog_summary.json")
COMPLIANCE_FILES = ("compliance_requirements.json", "check_descriptions.json", "compliance_lookup.json")
HACKTRICKS = "HackTricks Cloud Best Practices"


def reviewed_correction_matches(check_id, correction):
    """Recognize exact admitted errata, never an arbitrary new format/version.

    The runtime and materializer already validate these successors against their
    original signed proposals. Their provenance formats differ from the first
    generic erratum format; require the complete same spec and proof here too.
    """
    from peaso.checks import (aws_apigateway_logging_source_correction,
                              aws_ecr_source_correction,
                              aws_pci_iam_scoped_source_correction)
    for module in (aws_apigateway_logging_source_correction,
                   aws_ecr_source_correction, aws_pci_iam_scoped_source_correction):
        if check_id == module.CHECK_ID:
            return correction == {"spec": module.CORRECTED_SPEC,
                                  "provenance": module.correction_provenance()}
    if check_id == "gcp.apikeys.active_service_restrictions":
        from peaso.checks.gcp_api_key_service_names_native import (
            PRIOR_SPEC_SHA256, source_correction)
        spec, provenance = source_correction(PRIOR_SPEC_SHA256)
        return correction == {"spec": spec, "provenance": provenance}
    return None


def audit_documents(documents):
    """Return deterministic evidence and errors for one captured catalog set."""
    issues = []

    def issue(code, **details):
        issues.append({"code": code, **details})

    rows = documents["upstream_manifest.json"]["checks"]
    active_checks = documents["native_catalog.json"]["checks"]
    archived_checks = documents["native_catalog.json"].get("archived_checks", [])
    excluded_controls = documents["native_catalog.json"].get("excluded_controls", {})
    active_ids = {check["id"] for check in active_checks}
    archived_ids = {check["id"] for check in archived_checks}
    if archived_ids != set(excluded_controls) or active_ids.intersection(archived_ids):
        issue("invalid_native_only_admission_partition")
    for cid, admission in excluded_controls.items():
        if not isinstance(admission, dict) or not all(isinstance(admission.get(key), str) and admission[key].strip() for key in ("reason", "source")):
            issue("missing_native_only_exclusion_evidence", native_id=cid)
    # Source mappings retain archived definitions; active selectors never include them.
    checks = active_checks + archived_checks
    reviewed = documents.get("compliance_requirements.json")
    if reviewed is None and (documents["native_catalog.json"].get("compliance_source_manifest_sha256") or
                            documents["framework_catalog.json"].get("compliance_source_manifest_sha256") or
                            documents["runtime_metadata.json"].get("compliance") or
                            documents.get("check_descriptions.json")):
        issue("incomplete_compiled_compliance_metadata")
    reviewed_framework_ids = {version["id"] for version in reviewed.get("frameworks", [])} if reviewed else set()
    runtime = documents["runtime_metadata.json"]
    native = {c["id"]: c for c in checks}
    from peaso.finding_priority import source_priority
    for cid, row in native.items():
        if "severity_review" in row:
            try:
                source_priority(row)
            except ValueError:
                issue("invalid_reviewed_priority_provenance", native_id=cid)
    source = {r["check_id"]: r for r in rows}
    for name, identifiers in (("native", [c["id"] for c in checks]),
                              ("source", [r["check_id"] for r in rows])):
        for identifier, count in sorted(Counter(identifiers).items()):
            if count != 1:
                issue("duplicate_id", catalog=name, id=identifier, count=count)

    counts = Counter(r.get("disposition") for r in rows)
    manual = {r["check_id"] for r in rows if r.get("manual_requirement")}
    actual = {"native_checks": len(native), "upstream_total": len(rows),
              "upstream": {state: counts[state] for state in sorted(DISPOSITIONS)},
              "supported_upstream": sum(counts[s] for s in SUPPORTED),
              "manual_requirements": len(manual),
              "rejected_invalid_predicates": sum(r.get("disposition") == "rejected"
                  and not r.get("manual_requirement") for r in rows),
              "outside_runtime_provider_scope": counts["out_of_scope"],
              "runtime_scope_upstream_total": sum(r["provider"] in PROVIDERS for r in rows)}
    for name, summary in (("catalog_summary.json", documents["catalog_summary.json"]),
                          ("runtime_metadata.json", documents["runtime_metadata.json"]["coverage"])):
        for field, expected in actual.items():
            observed = summary.get(field)
            # Explicit zero and an absent Counter key mean the same count.
            # Materializers retain pending=0 after the backlog is completed.
            matches = ({k: v for k, v in observed.items() if v != 0} ==
                       {k: v for k, v in expected.items() if v != 0}) if field == "upstream" and isinstance(observed, dict) else observed == expected
            if not matches:
                issue("stale_summary", catalog=name, field=field,
                      expected=expected, observed=observed)

    framework_refs = defaultdict(set)
    framework_native = defaultdict(set)
    framework_control_keys = defaultdict(set)
    source_mappings = runtime.get("mappings") if reviewed else None
    if reviewed and not isinstance(source_mappings, dict):
        issue("missing_source_reference_index")
    native_control_keys = {}
    for cid, check in native.items():
        native_control_keys[cid] = {(control.get("framework_id"), str(control.get("control_id", "")),
                                    str(control.get("version", "")))
            for group in check.get("mapping", {}).values() if isinstance(group, dict)
            for control in group.get("controls", [])}
    for row in rows:
        sid, provider, disposition = row["check_id"], row["provider"], row.get("disposition")
        ids = row.get("native_checks") or []
        if disposition not in DISPOSITIONS:
            issue("unknown_disposition", source_id=sid, observed=disposition)
        if provider not in PROVIDERS and disposition != "out_of_scope":
            issue("unsupported_provider_in_scope", source_id=sid, provider=provider)
        if provider in PROVIDERS and disposition == "out_of_scope":
            issue("target_provider_out_of_scope", source_id=sid, provider=provider)
        if not isinstance(row.get("reason"), str) or not row["reason"].strip():
            issue("missing_review_reason", source_id=sid)
        if disposition in SUPPORTED and not ids:
            issue("supported_without_predicate", source_id=sid)
        if disposition in SUPPORTED:
            for cid in ids:
                if cid not in native:
                    issue("missing_native_predicate", source_id=sid, native_id=cid)
                elif native[cid]["provider"] != provider:
                    issue("provider_mismatch", source_id=sid, native_id=cid)
            if row.get("expected_cost", {}).get("cloud_calls_at_evaluation") != 0:
                issue("evaluation_requires_cloud_calls", source_id=sid)
        for mapping in row.get("frameworks", []):
            fid = mapping.get("framework_id")
            if not fid:
                issue("mapping_missing_framework_id", source_id=sid)
                continue
            framework_refs[fid].add(sid)
            framework_control_keys[fid].add((str(mapping.get("control_id", "")),
                                            str(mapping.get("version", ""))))
            if disposition in SUPPORTED:
                framework_native[fid].update(ids)
                for cid in ids:
                    key = (fid, str(mapping.get("control_id", "")), str(mapping.get("version", "")))
                    if reviewed:
                        references = source_mappings.get(cid, []) if isinstance(source_mappings, dict) else []
                        matching = [ref for ref in references if ref.get("check_id") == sid]
                        if not matching:
                            issue("lost_source_reference", source_id=sid, native_id=cid)
                        elif key not in {(refmap.get("framework_id"), str(refmap.get("control_id", "")),
                                          str(refmap.get("version", "")))
                                         for ref in matching for refmap in ref.get("frameworks", [])}:
                            issue("lost_source_control_reference", source_id=sid, native_id=cid,
                                  framework_id=fid, control_id=key[1], version=key[2])
                    elif cid in native:
                        if fid not in native[cid].get("framework_ids", []):
                            issue("lost_framework_mapping", source_id=sid, native_id=cid, framework_id=fid)
                        if key not in native_control_keys[cid]:
                            issue("lost_control_mapping", source_id=sid, native_id=cid, framework_id=fid,
                                  control_id=key[1], version=key[2])

    for check in checks:
        cid = check["id"]
        if check["provider"] not in PROVIDERS:
            issue("unsupported_native_provider", native_id=cid)
        from peaso.checks.hacktricks_scope import includes, review
        if cid not in review()["checks"]:
            issue("unreviewed_hacktricks_membership", native_id=cid)
        if includes(cid) and HACKTRICKS not in check.get("frameworks", []):
            issue("missing_hacktricks_mapping", native_id=cid)
        if not includes(cid) and (HACKTRICKS in check.get("frameworks", []) or HACKTRICKS in check.get("mapping", {})):
            issue("unexpected_hacktricks_mapping", native_id=cid)
        if check.get("expected_cost", {}).get("cloud_calls") != 0:
            issue("native_evaluation_requires_cloud_calls", native_id=cid)
        if not check.get("dependencies"):
            issue("missing_collection_dependencies", native_id=cid)

    declared_manual = {m["id"] for m in documents["manual_catalog.json"]["requirements"]}
    if declared_manual != manual:
        issue("manual_catalog_mismatch", missing=sorted(manual - declared_manual),
              unexpected=sorted(declared_manual - manual))
    frameworks = []
    declared_frameworks = {f["id"]: f for f in documents["framework_catalog.json"]["frameworks"]}
    for fid, ids in sorted(framework_refs.items()):
        counter = Counter(source[sid]["disposition"] for sid in ids)
        f = declared_frameworks.get(fid)
        if f is None:
            issue("missing_framework", framework_id=fid)
        else:
            source_count_field = ("source_supported_native_checks" if fid in reviewed_framework_ids or "source_supported_native_checks" in f
                                  else "supported_native_checks")
            expected = {"source_checks": len(ids), "pending_source_checks": counter["pending"],
                        source_count_field: len(framework_native[fid])}
            for key, value in expected.items():
                if f.get(key) != value:
                    issue("stale_framework", framework_id=fid, field=key,
                          expected=value, observed=f.get(key))
        frameworks.append({"id": fid, "provider": f.get("provider") if f else None,
                           "source_references": len(ids), "control_version_pairs": len(framework_control_keys[fid]),
                           "native_predicates": len(framework_native[fid]), "dispositions": dict(counter),
                           "coverage_complete": counter["pending"] == 0,
                           "automated_reference_fraction": round(sum(counter[s] for s in SUPPORTED) / len(ids), 4)})
    if reviewed:
        from scripts.peaso_compliance_compile import lookup_index
        lookup = documents.get("compliance_lookup.json")
        if not isinstance(lookup, dict) or lookup_index(reviewed, lookup.get("full_pack_sha256", "")) != lookup:
            issue("stale_or_missing_compliance_lookup")
        source_hash = reviewed.get("source_manifest_sha256")
        for name, observed in (("native_catalog.json", documents["native_catalog.json"].get("compliance_source_manifest_sha256")),
                               ("framework_catalog.json", documents["framework_catalog.json"].get("compliance_source_manifest_sha256")),
                               ("runtime_metadata.json", runtime.get("compliance", {}).get("source_manifest_sha256"))):
            if not isinstance(source_hash, str) or observed != source_hash:
                issue("compliance_pack_hash_mismatch", catalog=name, expected=source_hash, observed=observed)
        prose = documents.get("check_descriptions.json")
        if not isinstance(prose, dict) or prose.get("source_manifest_sha256") != source_hash:
            issue("compliance_description_pack_mismatch")
        elif not set(native) <= set(prose.get("checks", {})):
            issue("missing_reviewed_native_descriptions", ids=sorted(set(native) - set(prose["checks"])))
        versions = {row["id"]: row for row in reviewed.get("frameworks", [])}
        for framework in frameworks:
            version = versions.get(framework["id"])
            if version is None:
                continue
            states = Counter(item.get("runtime_status") for item in version["requirements"])
            pending = sum(bool(item.get("pending_checks")) for item in version["requirements"])
            framework["source_reference_coverage_complete"] = framework["coverage_complete"]
            framework["coverage_complete"] = (framework["coverage_complete"] and pending == 0 and
                                              states["partial"] == 0 and states["not_assessed"] == 0)
            framework["requirements_by_status"] = dict(states)
        reverse = reviewed.get("by_check", {})
        proposals = {spec["id"]: spec for spec in reviewed.get("proposed_checks", [])}
        for cid, spec in proposals.items():
            if cid not in native:
                continue
            canonical = json.dumps(spec, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
            expected_provenance = {"signed_spec_sha256": hashlib.sha256(canonical).hexdigest(),
                                   "signed_provider": spec["provider"], "signed_severity": spec["severity"],
                                   "signed_category": spec["category"],
                                   "signed_resource_kind": spec["resource_kind"],
                                   "source_manifest_sha256": source_hash}
            correction = documents["native_catalog.json"].get("source_corrections", {}).get(cid)
            if correction is not None:
                spec_now = correction.get("spec", {})
                provenance = correction.get("provenance", {})
                canonical_now = json.dumps(spec_now, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
                current_digest = hashlib.sha256(canonical_now).hexdigest()
                predicate_digest = hashlib.sha256(str(spec_now.get("predicate", "")).encode()).hexdigest()
                valid = (spec_now.get("id") == cid and spec_now.get("provider") == spec["provider"]
                         and spec_now.get("severity") == spec["severity"]
                         and provenance.get("version") == "peaso-source-correction-v1"
                         and provenance.get("status") == "source_erratum_successor"
                         and provenance.get("prior_frozen_status") == "historical_superseded_for_this_check"
                         and provenance.get("prior_frozen_signed_spec_sha256") == expected_provenance["signed_spec_sha256"]
                         and provenance.get("current_canonical_spec_sha256") == current_digest
                         and provenance.get("current_predicate_sha256") == predicate_digest
                         and isinstance(provenance.get("source_url"), str) and provenance["source_url"].startswith("https://")
                         and native[cid].get("source_correction") == provenance)
                admitted = reviewed_correction_matches(cid, correction)
                if admitted is not None:
                    valid = (admitted and provenance.get("prior_frozen_signed_spec_sha256") ==
                             expected_provenance["signed_spec_sha256"] and
                             native[cid].get("source_correction", native[cid].get("proposal_provenance", {}).get("source_correction")) == provenance)
                if not valid:
                    issue("invalid_source_correction_provenance", native_id=cid)
                else:
                    expected_provenance["signed_spec_status"] = "historical_superseded_for_this_check"
                    expected_provenance["source_correction"] = provenance
            if native[cid].get("proposal_provenance") != expected_provenance:
                issue("missing_signed_proposal_provenance", native_id=cid)
            if native[cid].get("provider") != spec["provider"]:
                issue("signed_proposal_provider_mismatch", native_id=cid)
            from peaso.finding_priority import source_priority
            try:
                source_severity = source_priority(native[cid])
            except ValueError:
                issue("invalid_reviewed_priority_provenance", native_id=cid)
            else:
                if source_severity != spec["severity"]:
                    issue("signed_proposal_severity_mismatch", native_id=cid)
        if not isinstance(reverse, dict) or not isinstance(versions, dict):
            issue("malformed_reviewed_requirement_index")
        else:
            forward = {(fid, row["requirement_id"], cid)
                       for fid, version in versions.items() for row in version["requirements"]
                       for cid in row["native_checks"]}
            backward = {(tag["framework_id"], tag["requirement_id"], cid)
                        for cid, tags in reverse.items() for tag in tags}
            if forward != backward:
                issue("reviewed_requirement_mapping_not_bidirectional")
            reviewed_native = defaultdict(set)
            for cid, tags in reverse.items():
                for tag in tags:
                    reviewed_native[tag["framework_id"]].add(cid)
                if cid not in native:
                    issue("reviewed_requirement_check_absent", native_id=cid)
                    continue
                actual_tags = native[cid].get("requirement_controls", [])
                if actual_tags != tags:
                    issue("stale_reviewed_check_tags", native_id=cid)
                expected_ids = sorted({tag["framework_id"] for tag in tags})
                if native[cid].get("framework_ids") != expected_ids:
                    issue("stale_reviewed_check_frameworks", native_id=cid)
                control_keys = {(control.get("framework_id"), str(control.get("control_id", "")))
                                for group in native[cid].get("mapping", {}).values() if isinstance(group, dict)
                                for control in group.get("controls", [])}
                if {(tag["framework_id"], tag["requirement_id"]) for tag in tags} - control_keys:
                    issue("lost_reviewed_control_mapping", native_id=cid)
            for fid, version in versions.items():
                row = declared_frameworks.get(fid)
                if row is None:
                    issue("missing_reviewed_framework", framework_id=fid)
                    continue
                expected_active = reviewed_native[fid].intersection(active_ids)
                if row.get("native_check_ids") != sorted(expected_active) or row.get("supported_native_checks") != len(expected_active):
                    issue("stale_reviewed_framework_checks", framework_id=fid)
                if row.get("requirements_total") != version.get("requirements_total"):
                    issue("stale_reviewed_framework_requirements", framework_id=fid)
                expected_pending = sum(bool(item.get("pending_checks")) for item in version["requirements"])
                if row.get("pending_automatable_requirements") != expected_pending:
                    issue("stale_reviewed_framework_pending", framework_id=fid)
                expected_states = dict(Counter(item.get("runtime_status") for item in version["requirements"]))
                if row.get("requirements_by_status") != expected_states:
                    issue("stale_reviewed_framework_statuses", framework_id=fid)
    declared_active = documents["catalog_summary.json"].get("active_native_checks")
    if declared_active is not None and declared_active != len(active_ids):
        issue("stale_active_native_summary", expected=len(active_ids), observed=declared_active)
    providers = {}
    for provider in PROVIDERS:
        own = [r for r in rows if r["provider"] == provider]
        pending_services = Counter(r.get("service") or "unknown" for r in own if r["disposition"] == "pending")
        providers[provider] = {"native_predicates": sum(c["provider"] == provider for c in native.values()),
            "source_references": len(own), "dispositions": dict(Counter(r["disposition"] for r in own)),
            "pending_services": dict(sorted(pending_services.items(), key=lambda p: (-p[1], p[0])))}
    pending_requirements = (sum(bool(item.get("pending_checks")) for version in reviewed.get("frameworks", [])
                                for item in version.get("requirements", [])) if reviewed else None)
    source_complete = counts["pending"] == 0
    reviewed_states = Counter(item.get("runtime_status") for version in reviewed.get("frameworks", [])
                              for item in version.get("requirements", [])) if reviewed else Counter()
    implementation_complete = source_complete and pending_requirements in (None, 0)
    requirement_complete = (implementation_complete and reviewed_states["partial"] == 0 and
                            reviewed_states["not_assessed"] == 0)
    return {"schema_version": "1.0", "scope": "native configuration catalog metadata only",
            "catalog_consistent": not issues, "coverage_complete": requirement_complete,
            "active_native_checks": len(active_ids), "archived_native_checks": len(archived_ids),
            "automation_implementation_complete": implementation_complete,
            "source_reference_coverage_complete": source_complete,
            "pending_automatable_requirements": pending_requirements,
            "reviewed_requirement_states": dict(reviewed_states) if reviewed else None,
            "counts": actual, "providers": providers, "frameworks": frameworks,
            "issues": issues,
            "limitations": ["A supported mapping does not prove predicate equivalence or complete collection.",
                            "Reviewed manual controls remain manual; rejected predicates are not automated checks.",
                            "Partial and not-assessed requirement states remain incomplete even when all proposed check IDs are registered.",
                            "This audit does not establish certification, exhaustive service coverage or zero false positives."]}


def audit_directory(directory):
    directory = Path(directory)
    payloads = {name: (directory / name).read_bytes() for name in FILES}
    for name in COMPLIANCE_FILES:
        if (directory / name).exists():
            payloads[name] = (directory / name).read_bytes()
    gz = directory / "upstream_manifest.json.gz"
    if gz.exists():
        payloads[gz.name] = gz.read_bytes()
    report = audit_documents({name: json.loads(data) for name, data in payloads.items()
                              if name in FILES or name in COMPLIANCE_FILES})
    if "compliance_lookup.json" in payloads and "compliance_requirements.json" in payloads:
        lookup = json.loads(payloads["compliance_lookup.json"])
        if hashlib.sha256(payloads["compliance_requirements.json"]).hexdigest() != lookup.get("full_pack_sha256"):
            report["issues"].append({"code": "compliance_lookup_full_pack_hash_mismatch"})
    if 0 < sum(name in payloads for name in COMPLIANCE_FILES) < len(COMPLIANCE_FILES):
        report["issues"].append({"code": "incomplete_compiled_compliance_metadata"})
    if gz.name in payloads and gzip.decompress(payloads[gz.name]) != payloads["upstream_manifest.json"]:
        report["issues"].append({"code": "compressed_manifest_mismatch"})
    changed = [name for name, data in payloads.items() if (directory / name).read_bytes() != data]
    if changed:
        report["issues"].append({"code": "concurrent_catalog_edit", "files": changed})
    report["catalog_consistent"] = not report["issues"]
    report["capture_stable"] = not changed
    report["input_sha256"] = {name: hashlib.sha256(data).hexdigest() for name, data in payloads.items()}
    report["captured_at"] = datetime.now(timezone.utc).isoformat()
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rulepacks", type=Path, default=Path(__file__).resolve().parents[1] / "peaso/rulepacks")
    parser.add_argument("--require-complete", action="store_true",
                        help="Fail on pending source references, proposed checks, or partial/not-assessed reviewed requirements.")
    args = parser.parse_args(argv)
    report = audit_directory(args.rulepacks)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["catalog_consistent"] and (report["coverage_complete"] or not args.require_complete) else 1


if __name__ == "__main__":
    raise SystemExit(main())
