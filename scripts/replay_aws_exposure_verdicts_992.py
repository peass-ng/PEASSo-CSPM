"""Numeric-only replay of the six saved AWS Exposure AI disagreement checks.

Reads the exact local 992 gzip inputs. Never writes resource IDs, policy bodies,
review reasons or finding evidence to the receipt.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import gzip
import hashlib
import json
from pathlib import Path

CHECK_IDS = (
    "analysis.principal_exposure",
    "aws.cb.ssm.block_public_document_sharing",
    "aws.claude_a.iam.prowler_role_service_trust_bound_to_account",
    "aws.claude_a.vpc.in_use_subnet_no_auto_public_ip",
    "aws.claude_a.vpc.sg_no_public_ip_any_port",
    "aws.claude_a.vpc.sg_no_world_any_port_on_customer_enis",
)


def _read(receipt, name):
    spec = receipt["objects"][name]
    path = Path(spec["local_path"])
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != spec["sha256"]:
        raise ValueError(f"{name} local SHA256 does not match source receipt")
    with gzip.open(path, "rt") as stream:
        return json.load(stream)


def _observations(report):
    return {row["id"]: row for group in report["findings"] if group.get("category") == "exposure"
            for row in group.get("observations") or [group] if row.get("check_id") in CHECK_IDS}


def replay(source_receipt):
    from peaso.analysis import analysis_context
    from peaso.analysis.iam import review_findings
    from peaso.checks import CHECKS
    from peaso.checks.facts import MemoIndex
    from peaso.snapshot import resource_id

    receipt = json.loads(Path(source_receipt).read_text())
    snapshot = _read(receipt, "snapshot")
    pre = _read(receipt, "pre_ai_report")
    final = _read(receipt, "final_report")
    if snapshot["snapshot_id"] != pre["snapshot_id"] or pre["snapshot_id"] != final["snapshot_id"]:
        raise ValueError("replay inputs have different snapshot IDs")

    observations = _observations(pre)
    wanted_ids = {row["resource_id"] for row in observations.values()}
    report_resources = {row["id"]: row for row in pre["resources"] if row["id"] in wanted_ids}
    checks = {check.id: check for check in CHECKS if check.id in CHECK_IDS}
    needed_types = {kind for check in checks.values() for kind in (check.kind, *check.dependencies)}
    needed_types.update(row["type"] for row in report_resources.values())
    needed_types.add("aws_resource_policy")
    selected = [c for c in snapshot["collections"] if c["type"] in needed_types]
    raw = {}
    for collection in selected:
        for item in collection["items"]:
            key = (collection["scope"], collection["type"], resource_id("aws", collection["type"], collection["scope"], item))
            raw[key] = item

    scopes = {row["scope"] for row in report_resources.values()} | {row["scope"] for row in observations.values()}
    indexes = {}
    for scope in scopes:
        account = scope.split("/", 1)[0]
        relevant = [c for c in selected if c["scope"] == scope or
                    c.get("global") is True and c.get("account_id") == account]
        by_type = defaultdict(list)
        envelopes = defaultdict(list)
        for collection in relevant:
            kind = collection["type"]
            envelopes[kind].append(collection)
            for item in collection["items"]:
                by_type[kind].append({"type": kind, "scope": collection["scope"], "data": item,
                                      "native_id": resource_id("aws", kind, collection["scope"], item)})
        index = MemoIndex(by_type)
        index["collections"] = dict(envelopes)
        index["context"] = {"provider": "aws", "scope": scope, "_scope": scope,
                            "Account": account, "created_at": snapshot["created_at"],
                            "snapshot_id": snapshot["snapshot_id"], "metadata": snapshot.get("metadata", {})}
        indexes[scope] = index

    current = {}
    with analysis_context(snapshot):
        for finding_id, row in observations.items():
            resource = report_resources.get(row["resource_id"])
            if resource is None:
                if row["check_id"] == "aws.cb.ssm.block_public_document_sharing":
                    resource = {"scope": row["scope"], "type": "ssm_service_settings", "native_id": "scope"}
                else:
                    raise ValueError("resource reference missing in pre-AI report")
            scope, kind = resource["scope"], resource["type"]
            item = raw.get((scope, kind, resource["native_id"]))
            cid = row["check_id"]
            if cid == "analysis.principal_exposure":
                if item is None:
                    raise ValueError("principal resource missing from snapshot")
                wrapped = dict(resource, data=item)
                found = [f for f in review_findings(snapshot, [wrapped]) if f["check_id"] == cid]
                status = found[0]["status"] if len(found) == 1 else "ABSENT" if not found else "AMBIGUOUS"
            else:
                check = checks[cid]
                if check.target == "scope":
                    item = {"scope": scope}
                if item is None:
                    raise ValueError("check resource missing from snapshot")
                status, _ = check.evaluate(item, indexes[scope])
            current[finding_id] = status

    reviews = {r["finding_id"]: r["verdict"] for r in final["ai"]["reviews"]["exposure"]
               if r["finding_id"] in observations}
    by_check = {}
    for cid in CHECK_IDS:
        rows = {fid: row for fid, row in observations.items() if row["check_id"] == cid}
        changed = {fid: verdict for fid, verdict in reviews.items() if fid in rows and verdict != rows[fid]["status"]}
        unchanged = {fid: verdict for fid, verdict in reviews.items() if fid in rows and verdict == rows[fid]["status"]}
        by_check[cid] = {
            "pre_observations": len(rows), "saved_reviews": sum(fid in reviews for fid in rows),
            "ai_changed": len(changed),
            "changed_replay_transitions": dict(sorted(Counter(f"{rows[fid]['status']}->{current[fid]}" for fid in changed).items())),
            "changed_ai_parity": sum(current[fid] == verdict for fid, verdict in changed.items()),
            "changed_ai_mismatch": sum(current[fid] != verdict for fid, verdict in changed.items()),
            "unchanged_reviewed_native_changes": sum(current[fid] != rows[fid]["status"] for fid in unchanged),
            "unreviewed_native_changes": sum(current[fid] != row["status"] for fid, row in rows.items() if fid not in reviews),
            "current_statuses": dict(sorted(Counter(current[fid] for fid in rows).items())),
        }
    context = {"in_use_subnets_with_native_eni": 0, "in_use_subnet_eni_min": None,
               "in_use_subnet_eni_max": None, "customer_sgs_with_native_customer_eni": 0,
               "ssm_scopes_with_exact_enable_setting": 0}
    subnet_counts = []
    for fid, verdict in reviews.items():
        row = observations[fid]
        if verdict == row["status"]:
            continue
        cid = row["check_id"]
        resource = report_resources.get(row["resource_id"])
        scope = resource["scope"] if resource else row["scope"]
        index = indexes[scope]
        if cid == "aws.claude_a.vpc.in_use_subnet_no_auto_public_ip":
            count = sum(eni["data"].get("SubnetId") == resource["native_id"] for eni in index.get("network_interface", []))
            subnet_counts.append(count)
            context["in_use_subnets_with_native_eni"] += count > 0
        elif cid == "aws.claude_a.vpc.sg_no_world_any_port_on_customer_enis":
            count = sum(any(g.get("GroupId") == resource["native_id"] for g in eni["data"].get("Groups", []) if isinstance(g, dict))
                        and eni["data"].get("InterfaceType") not in ("api_gateway_managed", "vpc_endpoint")
                        and (eni["data"].get("Attachment") or {}).get("InstanceOwnerId") != "amazon-elb"
                        for eni in index.get("network_interface", []))
            context["customer_sgs_with_native_customer_eni"] += count > 0
        elif cid == "aws.cb.ssm.block_public_document_sharing":
            count = sum(setting["data"].get("ServiceSetting", {}).get("SettingId") ==
                        "/ssm/documents/console/public-sharing-permission" and
                        setting["data"].get("ServiceSetting", {}).get("SettingValue") == "Enable"
                        for setting in index.get("ssm_service_settings", []))
            context["ssm_scopes_with_exact_enable_setting"] += count == 1
    if subnet_counts:
        context["in_use_subnet_eni_min"] = min(subnet_counts)
        context["in_use_subnet_eni_max"] = max(subnet_counts)
    return {"schema": "aws-exposure-six-check-replay-v1",
            "source_commit": receipt["source_commit"], "replay_check_ids": list(CHECK_IDS),
            "pre_observations": len(observations), "saved_reviews": len(reviews),
            "ai_changed": sum(x["ai_changed"] for x in by_check.values()),
            "changed_ai_parity": sum(x["changed_ai_parity"] for x in by_check.values()),
            "changed_ai_mismatch": sum(x["changed_ai_mismatch"] for x in by_check.values()),
            "unchanged_reviewed_native_changes": sum(x["unchanged_reviewed_native_changes"] for x in by_check.values()),
            "unreviewed_native_changes": sum(x["unreviewed_native_changes"] for x in by_check.values()),
            "checks": by_check, "mismatch_recorded_context": context}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-receipt", default="/Users/carlospolop/peaso-work/replay/source-receipt.json")
    parser.add_argument("--output", default="outputs/aws-exposure-six-check-replay-992.json")
    args = parser.parse_args()
    result = replay(args.source_receipt)
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: result[key] for key in ("pre_observations", "saved_reviews", "ai_changed", "changed_ai_parity",
                                                    "changed_ai_mismatch", "unchanged_reviewed_native_changes", "unreviewed_native_changes")}, sort_keys=True))


if __name__ == "__main__":
    main()
