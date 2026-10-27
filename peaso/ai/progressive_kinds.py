"""Conservative AWS native-kind cohorts for progressive Hardening review."""

import hashlib
import json

from .review_groups import plan


WINDOW_SIZE = 40
_PREFIX = "hardening_w_"


def stage_key(leader_ids):
    """Keep the durable stage name inside both store implementations' grammar."""
    payload = json.dumps(sorted(leader_ids), separators=(",", ":")).encode()
    return _PREFIX + hashlib.sha256(payload).hexdigest()[:20]


def candidate_kinds(report, snapshot, selectors):
    """Return native kinds with complete AWS prerequisites and useful AI work.

    A partial checkpoint already evaluates only ready native checks, but one
    Region's envelope does not close that kind in every requested Region. The
    explicit per-kind scope test prevents a later Region from changing group
    membership after a reviewer starts. Dynamic scopes and analysis checks are
    left for final review.
    """
    if report.get("provider") != "aws" or snapshot.get("provider") != "aws":
        return {}
    metadata = snapshot.get("metadata", {})
    incremental = metadata.get("incremental", {})
    scopes = metadata.get("requested_scopes")
    if (not isinstance(incremental, dict) or incremental.get("phase") != "collecting"
            or not isinstance(scopes, list) or not scopes
            or any(not isinstance(scope, str) or "/" not in scope for scope in scopes)):
        return {}
    from peaso.collectors.aws import GLOBAL_TYPES
    from peaso.engine import CATEGORIES, _selection
    content_checks = selectors.get("content_checks") or []
    categories = (selectors.get("categories", []) if content_checks else
                  selectors.get("categories") or list(CATEGORIES))
    _, checks = _selection("aws", categories, selectors.get("checks"),
                           selectors.get("frameworks"),
                           content_checks=content_checks)
    hardening = {check.id: check for check in checks if check.category == "hardening"}
    present = {(row.get("type"), row.get("scope")) for row in snapshot.get("collections", [])
               if row.get("status") in {"collected", "empty"}}
    global_scopes = {scope.split("/", 1)[0] + "/global" for scope in scopes}

    def complete(kind):
        expected = global_scopes if kind in GLOBAL_TYPES else set(scopes)
        return all((kind, scope) in present for scope in expected)

    by_kind = {}
    for check in hardening.values():
        if all(complete(kind) for kind in {check.kind, *check.dependencies}):
            by_kind.setdefault(check.kind, set()).add(check.id)
    findings = report.get("findings", [])
    return {kind: check_ids for kind, check_ids in by_kind.items()
            if any(row.get("check_id") in check_ids and row.get("category") == "hardening"
                   and row.get("status") == "FAIL" for row in findings)}


def full_windows(report, kinds, reviewed_ids=(), *, size=WINDOW_SIZE):
    """Pack only whole equivalent groups from closed kinds into full windows.

    An incomplete tail remains for final review. Each dispatched window has
    exactly ``size`` representative items, so splitting by native-kind
    settlement does not itself add initial model calls.
    """
    eligible = set().union(*kinds.values()) if kinds else set()
    rows = [row for row in report.get("findings", []) if row.get("check_id") in eligible
            and row.get("category") == "hardening" and row.get("status") == "FAIL"]
    leaders, members = plan(rows)
    done = set(reviewed_ids)
    groups = [(leader, [leader, *members.get(leader["id"], ())]) for leader in leaders
              if not any(row["id"] in done for row in [leader, *members.get(leader["id"], ())])]
    windows = []
    for start in range(0, len(groups) - len(groups) % size, size):
        selected = groups[start:start + size]
        leader_ids = [leader["id"] for leader, _ in selected]
        selected_ids = {row["id"] for _, group in selected for row in group}
        windows.append((stage_key(leader_ids), leader_ids, selected_ids))
    return windows


def window_report(report, selected_ids):
    """Preserve complete group members and their original finding order."""
    return dict(report, findings=[row for row in report.get("findings", [])
        if row.get("id") in selected_ids])


def review_group_signatures(rows):
    """Bind copied representative verdicts to the exact final member set."""
    representatives, members = plan(rows)
    signatures = {}
    for leader in representatives:
        group = [leader, *members.get(leader["id"], ())]
        digest = hashlib.sha256("\0".join(sorted(row["id"] for row in group)).encode()).hexdigest()
        for row in group:
            signatures[row["id"]] = digest
    return signatures


def reusable_windows(artifacts, tenant, sections, stage_results):
    """Merge completed whole-group windows for final per-finding proof checks.

    The caller passes this synthetic prior into ``review_scan``. Its final
    finding fingerprints and group signatures decide every individual reuse;
    a missing or invalid window simply leaves those findings for fresh review.
    """
    if sections.get("hardening", {}).get("status") != "complete":
        return None
    reviews, fingerprints, signatures, identifiers = [], {}, {}, set()
    for stage, row in sorted((stage, row) for stage, row in (stage_results or {}).items()
                             if stage.startswith("hardening_w_") and isinstance(row, dict)):
        try:
            artifact = artifacts.get(tenant, row["result_ref"])
            result = artifact["result"]
            stage_inputs = result["stage_inputs"]["hardening"]
            proof = result["review_fingerprints"]["hardening"]
            groups = result["review_group_signatures"]["hardening"]
            values = result["reviews"]["hardening"]
            leaders = artifact["leader_ids"]
            if (artifact["stage"] != stage or artifact["data_revision"] != row["data_revision"]
                    or type(artifact.get("source_revision")) is not int
                    or result.get("status") != "completed" or not artifact.get("checkpoint_snapshot_id")
                    or not isinstance(leaders, list) or not leaders or len(leaders) % WINDOW_SIZE
                    or not isinstance(stage_inputs, list) or set(stage_inputs) != set(proof)
                    or set(stage_inputs) != set(groups) or not set(leaders) <= set(stage_inputs)
                    or len(stage_inputs) != len(set(stage_inputs))
                    or set(stage_inputs) != {value["finding_id"] for value in values}
                    or identifiers.intersection(stage_inputs)):
                continue
        except (KeyError, TypeError, ValueError, OSError):
            continue
        identifiers.update(stage_inputs)
        reviews.extend(values)
        fingerprints.update(proof)
        signatures.update(groups)
    if not identifiers:
        return None
    return {"status": "completed", "early_kind": True,
        "review_fingerprint_version": 2,
        "stage_inputs": {"hardening": sorted(identifiers)},
        "review_fingerprints": {"hardening": fingerprints},
        "review_group_signatures": {"hardening": signatures},
        "reviews": {"hardening": reviews, "exposure": []}}
