"""Collapse repeated account-global principal declarations collected per region.

Only identical declarations on the same native resource are merged. Different
statements, conditions, or results remain separate findings.
"""
from __future__ import annotations

import json


def _regionless(evidence):
    # Global policies are read from each Region; the reading Region is not
    # part of the declaration itself.
    if not isinstance(evidence, dict):
        return evidence
    return {key: value for key, value in evidence.items() if key not in {"collection_region", "source_region"}}


def _declaration(finding):
    if finding.get("check_id") != "analysis.principal_exposure" or finding.get("provider") != "aws":
        return None
    evidence = finding.get("evidence") or {}
    principals = evidence.get("principals") or []
    if not principals or not all(isinstance(row, dict) for row in principals):
        return None
    sources = [row.get("source") or {} for row in principals]
    native = {(row.get("resource_type"), row.get("resource_id")) for row in sources}
    if len(native) != 1 or not next(iter(native))[1]:
        return None
    declarations = [{**{key: value for key, value in row.items() if key != "source"},
        "source": {key: _regionless(value) if key == "request_evidence" else value
            for key, value in (row.get("source") or {}).items()
            if key not in {"scope", "snapshot_id"}}} for row in principals]
    rest = {key: value for key, value in evidence.items() if key not in {"principals", "observed_scopes"}}
    return (finding.get("status"), next(iter(native)),
        json.dumps(declarations, sort_keys=True, default=str), json.dumps(rest, sort_keys=True, default=str))


def deduplicate_principal_exposure(findings):
    kept, seen = [], {}
    for finding in findings:
        key = _declaration(finding)
        if key is None or key not in seen:
            kept.append(finding)
            if key is not None:
                seen[key] = finding
            continue
        original = seen[key]
        scopes = original["evidence"].setdefault("observed_scopes", [original["scope"]])
        if finding["scope"] not in scopes:
            scopes.append(finding["scope"])
    return kept
