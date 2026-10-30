"""Guard the evaluator-reviewed native AWS remediation shard."""

import json
import hashlib
from collections import Counter
from pathlib import Path
import re
import shlex

from botocore import xform_name
import botocore.session

from peaso.checks import CHECKS
from peaso.checks.claude2_aws_b_common import DOCS as C2B_DOCS
from peaso.remediation import template
from scripts.peaso_compliance_compile import spec_digest
from scripts.peaso_compliance_merge_new import signed_proposals
from tests.release_successor_history import historical_bytes


ROOT = Path(__file__).resolve().parents[1]
SHARD = ROOT / "peaso/rulepacks/remediation_aws_reviewed.json"
CENTRAL = ROOT / "peaso/rulepacks/remediation_details.json"
CURATED = ROOT / "peaso/rulepacks/remediation_curated.json"


def reviewed():
    return json.loads(SHARD.read_text())



def shard_before_reference_titles(path="peaso/rulepacks/remediation_aws_reviewed.json",
                                   rows_count=271, ensure_ascii=True):
    """Exact shard bytes before the reviewed documentation-label overlay (98b81b17).

    Each shard keeps its own encoding: ASCII-escaped for the central shard and
    literal UTF-8 for the family shard.
    """
    raw = (ROOT / path).read_bytes()
    data = json.loads(raw)
    assert (json.dumps(data, indent=2, ensure_ascii=ensure_ascii) + "\n").encode() == raw
    overlay = json.loads((ROOT / "tests/fixtures/remediation_reference_title_overlay.json").read_text())
    assert overlay["schema_version"] == 1
    rows = overlay["sources"][path]
    assert len(rows) == rows_count
    for row in rows:
        reference = data[row["id"]]["references"][row["index"]]
        assert reference == {"title": row["new_title"], "url": row["url"]}, row
        reference["title"] = row["old_title"]
    return (json.dumps(data, indent=2, ensure_ascii=ensure_ascii) + "\n").encode()

def test_reviewed_entries_are_assigned_native_checks_with_exact_kind():
    from tests.release_successor_history import registered_before_bulk
    checks = {check.id: check for check in registered_before_bulk(CHECKS)}
    central = json.loads(CENTRAL.read_text())
    central.update(json.loads(CURATED.read_text()))
    already_approved = {key for key, value in central.items() if value.get("review_status") == "approved"}
    # This deterministic partition is sourced from the registered native IDs.
    # The other AWS helper shard owns aws.claude_a.* and aws.cb.*; central
    # approved entries own themselves. No private .cache assignment is needed.
    batch = json.loads((ROOT / "peaso/rulepacks/remediation_compliance_batch_remaining_aws.json").read_text())
    batch_pending = {check_id for check_id, check in checks.items()
                     if check.evaluate.__module__ == "peaso.checks.batch_remaining_aws"
                     and check_id.startswith("aws.")}
    assert batch_pending == {
        "aws.nist.all_cloudtrail_destination_bucket_access_logging",
        "aws.nist.cloudtrail_cloudwatch_integration",
        "aws.nist.codebuild_exact_aws_key_env_names",
        "aws.pci.codebuild.aws_key_environment_vars",
        "aws.pci.codepipeline.first_stage_single_deploy",
        "aws.pci.iam.wildcard_action_scoped_resource",
    }
    successor_id = "aws.pci.vpc.peering_dns_resolution"
    assert successor_id in checks and successor_id not in batch_pending
    successor = checks[successor_id]
    assert successor.evaluate.__module__ == "peaso.checks.post_dfaf_aws"
    assert (successor.provider, successor.kind, successor.target) == (
        "aws", "vpc_peering_connection", "resource")
    signed_rows = [row for row in json.loads(
        (ROOT / "docs/compliance-ledgers/new-checks-aws.json").read_text())
        if row["id"] == successor_id]
    assert len(signed_rows) == 1
    signed = signed_rows[0]
    signed_fields = ("id", "provider", "resource_kind", "data_source", "predicate",
                     "severity", "category", "title", "description", "remediation_hint")
    signed_spec = {key: signed[key] for key in signed_fields}
    signed_sha = hashlib.sha256(json.dumps(signed_spec, sort_keys=True,
        separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    assert signed_sha == "befa2b7f74cd08c76208b4e7c7a77593486a95a418fe4719b563068b72ac24b5"
    assert signed["resource_kind"] == successor.kind
    assert successor_id in batch and successor_id not in already_approved
    assert batch[successor_id]["review_status"] == "source_bound_pending_review"
    assert batch[successor_id]["proposed_spec_sha256"] == signed_sha
    assert batch[successor_id]["summary"] == signed["remediation_hint"]
    from tests.reviewed_guidance_presentation import assert_reviewed_text_only_admission
    assert_reviewed_text_only_admission(successor_id)
    next20 = {
        "aws_backup_plan_rule_required_frequency": "backup_plan",
        "aws_cis_elbv2_only_tls_listeners": "load_balancer",
    }
    _, signed_next20 = signed_proposals(ROOT / "docs/compliance-ledgers")
    for check_id, kind in next20.items():
        check = checks[check_id]
        signed_spec = signed_next20[check_id]
        assert (check.provider, check.kind, check.evaluate.__module__) == (
            "aws", kind, "peaso.checks.next20_aws")
        assert signed_spec["resource_kind"] == kind
        assert batch[check_id]["proposed_spec_sha256"] == spec_digest(signed_spec)
        assert batch[check_id]["summary"] == signed_spec["remediation_hint"]
        assert batch[check_id]["review_status"] == "source_bound_pending_review"
        if check_id == "aws_backup_plan_rule_required_frequency":
            assert template(check_id) is None  # Archived operator-specific frequency baseline.
        else:
            assert_reviewed_text_only_admission(check_id)
    next_group_pending = {"aws.nist.rds_cluster_member_enhanced_monitoring", "aws.pci.secretsmanager.kms_encryption_any"}
    _, signed_next_group = signed_proposals(ROOT / "docs/compliance-ledgers")
    for check_id in next_group_pending:
        assert check_id in checks
        assert batch[check_id]["proposed_spec_sha256"] == spec_digest(signed_next_group[check_id])
        assert_reviewed_text_only_admission(check_id)
    pending = batch_pending | {successor_id} | set(next20) | next_group_pending
    assert len(pending) == 11 and pending <= set(batch)
    assert all(batch[cid]["review_status"] == "source_bound_pending_review" for cid in pending)
    assigned = {check_id for check_id in checks if check_id.startswith("aws.")
                and not check_id.startswith(("aws.claude_a.", "aws.cb."))
                and check_id not in already_approved and check_id not in pending
                and check_id not in {"aws.nist.all_iam_policies_no_star_star", "aws.nist.all_managed_policies_no_service_wildcard", "aws.nist.emr_master_nodes_no_public_ip"}}
    entries = reviewed()
    assert len(entries) == len(assigned) == 622
    assert len(assigned | set(next20)) == 624
    assert not set(entries) & set(next20)
    assert hashlib.sha256(shard_before_reference_titles()).hexdigest() == "b19eef2e094da960355bfa3d1a78a2f4618742aa7d1eda18c4e0da1fe857fa8c"
    assert {check_id for check_id in checks if check_id.startswith("aws.b.")} <= set(entries)
    assert {check_id for check_id in checks if check_id.startswith("aws.a.")} <= set(entries)
    assert {check_id for check_id in checks if check_id.startswith("aws.htbp.")} <= set(entries)
    assert {check_id for check_id in checks if check_id.startswith("aws.claude2_a.")} <= set(entries)
    assert {check_id for check_id in checks if check_id.startswith("aws.gap.")} <= set(entries) | already_approved
    assert {check_id for check_id in checks if check_id.startswith("aws.c2b.")} <= set(entries)
    assert set(entries) == assigned
    assert not set(entries) & already_approved
    for check_id, entry in entries.items():
        assert check_id.startswith("aws.") and check_id in checks
        assert entry["review_status"] in {"approved", "draft"}
        binding = entry["field_binding"]
        assert binding["kind"] == checks[check_id].kind
        assert binding["target"] == checks[check_id].target
        assert any(binding.get(field) for field in ("field", "fields", "path", "predicate", "label"))
        expected = entry if entry["review_status"] == "approved" else None
        if check_id == "aws.cloudtrail.management_events":
            from peaso.checks.cloudtrail_management_description_overlay import remediation
            expected = remediation(entry)
        if check_id in ("aws.a.cloudtrail.bucket_access_logging", "aws.a.cloudtrail.bucket_mfa_delete",
                        "aws.a.iam.attached_policy_no_star_star"):
            from peaso.checks.aws_native_status_description_overlay import remediation
            expected = remediation(check_id, entry)
        from tests.reviewed_guidance_presentation import assert_approved_presentation, assert_reviewed_text_only_admission
        if expected is not None:
            assert_approved_presentation(check_id, expected)
        else:
            assert check_id in {'aws.pci.apigateway.all_methods_cache_encrypted', 'aws.pci.apigateway.all_methods_logging'}
            assert_reviewed_text_only_admission(check_id)


def test_api_gateway_stage_entries_match_signed_native_predicates_and_preserve_legacy_bytes():
    entries = reviewed()
    checks = {check.id: check for check in CHECKS}
    expected = {
        "aws.pci.apigateway.all_methods_cache_encrypted": (
            "38d3fa49e17972ee0d4d0b00c89debfb863a76f72d30e7a165af7332702fa029",
            "cacheClusterEnabled", "unencrypted_enabled_overrides"),
        "aws.pci.apigateway.all_methods_logging": (
            "e9aa2380393b6fc8c69c68b574b2e0a2baed8bd4e9b5cc6aa4d254af5a42a5f3",
            "loggingLevel", "unsafe_method_overrides"),
    }
    read_only = [{"code": "aws apigateway get-stage --rest-api-id <REST_API_ID> --stage-name <RESOURCE_NAME> --region <REGION>",
                  "label": "Inspect the exact REST API stage settings (read only)", "shell": "bash"}]
    for check_id, (spec_sha, observed_field, fail_evidence) in expected.items():
        entry, check = entries[check_id], checks[check_id]
        binding = entry["field_binding"]
        assert entry["review_status"] == "draft"
        from tests.reviewed_guidance_presentation import assert_reviewed_text_only_admission
        current=assert_reviewed_text_only_admission(check_id)
        assert current["field_binding"]==binding
        assert "UNKNOWN" in " ".join(current["caveats"])
        assert entry["proposed_spec_sha256"] == spec_sha
        assert binding["evaluator_family"] == check.evaluate.__module__
        assert binding["kind"] == check.kind == "rest_api_stage"
        assert binding["target"] == check.target == "resource"
        assert observed_field in binding["path"] and "_provenance.source_operation" in binding["path"]
        assert "stage_arn" in binding["observed_fail_evidence"]
        assert fail_evidence in binding["observed_fail_evidence"]
        assert spec_sha in binding["source_note"] and "GetStages" in binding["source_note"]
        assert entry["cli"] == read_only
        assert entry["steps"] and entry["caveats"] and entry["references"]

    # Reverse the two source-bound WAFv2 reviews first. This reproduces the
    # exact 620-entry pre-WAF shard, so every older raw-byte overlay remains
    # independently pinned below.
    current_raw = shard_before_reference_titles()
    waf_start = current_raw.index(b',\n  "aws.pci.wafv2.rule_group_metrics": {')
    waf_end = current_raw.rfind(b'\n}\n')
    assert current_raw[waf_end:] == b'\n}\n'
    waf_only = b'{\n' + current_raw[waf_start + 2:waf_end] + b'\n}'
    assert set(json.loads(waf_only)) == {
        "aws.pci.wafv2.rule_group_metrics", "aws.pci.wafv2.rule_group_nonempty"}
    raw = current_raw[:waf_start] + current_raw[waf_end:]
    assert hashlib.sha256(raw).hexdigest() == "4168fa5be5df6a8094fd0fad5a790a0f7b7e8bfb50263e8c2bc7b2f811f55146"
    # This older shard grew by one contiguous API Gateway insertion before
    # its root closing brace. Removing it reproduces the exact legacy bytes.
    start = raw.index(b',\n  "aws.pci.apigateway.all_methods_cache_encrypted": {')
    end = raw.rfind(b'\n}\n')
    assert start < end and raw[end:] == b'\n}\n'
    assert set(json.loads(raw[start + 2:end].join((b'{\n', b'\n}')))) == set(expected)
    legacy = raw[:start] + raw[end:]
    overlay = json.loads((ROOT / "tests/fixtures/remediation_aws_reviewed_overlay.json").read_text())
    assert overlay["schema_version"] == 1
    sources = overlay["sources"]
    assert set(sources) == {"peaso/rulepacks/remediation_aws_reviewed.json",
                            "peaso/rulepacks/remediation_aws_families_reviewed.json"}
    assert sum(len(spec["fields"]) for spec in sources.values()) == 69
    assert len({row["id"] for spec in sources.values() for row in spec["fields"]}) == 20
    # Reverse this one-ID Cognito correction before the earlier CloudFront
    # secondary correction and the original 69-field/20-ID overlay. All
    # historical raw-byte and source-conservation assertions remain below.
    tertiary = overlay["tertiary"]
    assert tertiary["path"] == "peaso/rulepacks/remediation_aws_reviewed.json"
    assert tertiary["id"] == "aws.htbp.cognito.client_no_writable_authorization_attributes"
    assert hashlib.sha256(raw).hexdigest() == tertiary["post_sha256"]
    current = json.loads(raw)
    assert current[tertiary["id"]] == tertiary["new"]
    current[tertiary["id"]] = tertiary["old"]
    second_layer = (json.dumps(current, indent=2, ensure_ascii=True) + "\n").encode()
    assert hashlib.sha256(second_layer).hexdigest() == tertiary["pre_sha256"]
    secondary = overlay["secondary"]
    assert secondary["path"] == "peaso/rulepacks/remediation_aws_reviewed.json"
    assert secondary["id"] == "aws.c2b.cloudfront.origin_traffic_encrypted"
    assert hashlib.sha256(second_layer).hexdigest() == secondary["post_sha256"]
    corrected = json.loads(second_layer)
    assert corrected[secondary["id"]] == secondary["new"]
    corrected[secondary["id"]] = secondary["old"]
    first_layer = (json.dumps(corrected, indent=2, ensure_ascii=True) + "\n").encode()
    assert hashlib.sha256(first_layer).hexdigest() == secondary["pre_sha256"]
    start_first = first_layer.index(b',\n  "aws.pci.apigateway.all_methods_cache_encrypted": {')
    end_first = first_layer.rfind(b'\n}\n')
    assert hashlib.sha256(first_layer[:start_first] + first_layer[end_first:]).hexdigest() == "a196c74c65640189dd262223b109cd08ebdaf0e01f66294699321ff4f7d936bf"
    # Reverse the separately approved IAM source-line repin before the
    # original 20-ID authoring overlay. This layer changes source-proof
    # anchors only; the prior raw family bytes remain independently pinned.
    repin = overlay["source_anchor_repin"]
    assert repin["path"] == "peaso/rulepacks/remediation_aws_families_reviewed.json"
    assert repin["source_path"] == "peaso/checks/claude_aws_a_iam.py"
    historical_iam = historical_bytes(
        ROOT / "infra/aws/build/peaso-source-414e037b411d4e5abd0a214fc67b4b8bd96aede52dc843cf23748054f4dfbe6d.zip",
        repin["source_path"])
    assert hashlib.sha256(historical_iam).hexdigest() == repin["source_sha256"]
    # Retain the exact accepted source digest without claiming a full replay
    # of the unpublished local 706b archive.
    from tests.release_successor_history import _source414_reviewed_baseline
    current_iam = (ROOT / repin["source_path"]).read_bytes()
    # The successor contains only four explicitly reversible evidence additions;
    # reconstruct the exact original bytes instead of silently repinning them.
    restored_iam = _source414_reviewed_baseline(repin["source_path"], current_iam,
        "2002c02d63715d2b878d6405ca2bd7df87d02d7832e424b5bd1964c113a96423")
    assert hashlib.sha256(restored_iam).hexdigest() == "2002c02d63715d2b878d6405ca2bd7df87d02d7832e424b5bd1964c113a96423"
    family_raw = shard_before_reference_titles(repin["path"], 244, ensure_ascii=False)
    assert hashlib.sha256(family_raw).hexdigest() == repin["post_sha256"]
    family_prior = json.loads(family_raw)
    assert len(repin["fields"]) == 66
    assert len({row["id"] for row in repin["fields"]}) == 61
    for row in repin["fields"]:
        assert row["field"].startswith("source_proof.")
        assert row["field"].split(".")[-1] in {"evaluator", "helper_evaluator", "source_tuple_line"}
        value = family_prior[row["id"]]
        for part in row["field"].split(".")[:-1]:
            value = value[part]
        leaf = row["field"].split(".")[-1]
        assert value[leaf] == row["new"], (row["id"], row["field"])
        value[leaf] = row["old"]
    family_prior_raw = (json.dumps(family_prior, indent=2, ensure_ascii=False) + "\n").encode()
    assert hashlib.sha256(family_prior_raw).hexdigest() == repin["pre_sha256"]

    # Reverse exactly the approved 20-ID source overlay in both authoring shards.
    for name, spec in sources.items():
        current = first_layer if name == secondary["path"] else family_prior_raw
        assert hashlib.sha256(current).hexdigest() == spec["post_sha256"]
        restored = json.loads(current)
        for row in spec["fields"]:
            value = restored[row["id"]]
            for part in row["field"].split(".")[:-1]:
                value = value[part]
            leaf = row["field"].split(".")[-1]
            assert value[leaf] == row["new"], (row["id"], row["field"])
            value[leaf] = row["old"]
        historical = (json.dumps(restored, indent=2, ensure_ascii=spec["ensure_ascii"]) + "\n").encode()
        assert hashlib.sha256(historical).hexdigest() == spec["pre_sha256"]
        if name == "peaso/rulepacks/remediation_aws_reviewed.json":
            start_old = historical.index(b',\n  "aws.pci.apigateway.all_methods_cache_encrypted": {')
            end_old = historical.rfind(b'\n}\n')
            assert hashlib.sha256(historical[:start_old] + historical[end_old:]).hexdigest() == overlay["historical_legacy_sha256"]


def test_wafv2_reviews_match_signed_predicates_and_do_not_invent_rule_policy():
    entries = reviewed()
    checks = {check.id: check for check in CHECKS}
    ledger = {row["id"]: row for row in json.loads(
        (ROOT / "docs/compliance-ledgers/new-checks-aws.json").read_text())}
    expected = {
        "aws.pci.wafv2.rule_group_metrics": (
            "68c0870a052157b9277dc9889347264ae416c566e9b89feb341689648447876b",
            "RuleGroup.VisibilityConfig.CloudWatchMetricsEnabled", 9, ":105"),
        "aws.pci.wafv2.rule_group_nonempty": (
            "0c3e8decee40fc7c33a486fc596b80795e8fc95f0894c2817160622b9b5e705e",
            "RuleGroup.Rules[]", 2, ":113"),
    }
    for check_id, (digest, field, control_count, source_line) in expected.items():
        entry, check, signed = entries[check_id], checks[check_id], ledger[check_id]
        binding = entry["field_binding"]
        assert entry["review_status"] == "approved"
        from tests.reviewed_guidance_presentation import assert_approved_presentation
        current=assert_approved_presentation(check_id,entry)
        if check_id.endswith("metrics"):
            assert "fresh lock token" in " ".join(current["caveats"])
            assert "preserve all rules" in " ".join(current["caveats"])
        else:
            assert "no approved rule baseline" in " ".join(current["caveats"])
        assert entry["proposed_spec_sha256"] == digest
        assert (binding["evaluator_family"], binding["kind"], binding["target"]) == (
            check.evaluate.__module__, check.kind, check.target)
        assert binding["kind"] == signed["resource_kind"] == "wafv2_rule_group"
        assert field in binding["path"] and field == entry["source_proof"]["evaluated_field"]
        assert entry["source_proof"]["evaluator"].endswith(source_line)
        assert digest in binding["source_note"]
        assert len(signed["requirements"]) == control_count
        assert all(row["requirement_id"] in binding["source_note"] for row in signed["requirements"])
        assert entry["cli"] == [{
            "code": "aws wafv2 get-rule-group --arn <RESOURCE_ARN> --region <REGION>",
            "label": "Inspect the exact scoped rule group (read only)", "shell": "bash"}]
        assert "complete" in " ".join(entry["steps"]).lower()
        assert "token" in " ".join(entry["steps"])
    assert "no approved rule baseline" in " ".join(entries[
        "aws.pci.wafv2.rule_group_nonempty"]["caveats"])


def test_issued_acm_closed_30_day_remediation_matches_its_registered_predicate():
    check_id = "aws.nist.acm_all_certificates_expiry_30_days"
    check = next(check for check in CHECKS if check.id == check_id)
    entry = reviewed()[check_id]
    binding = entry["field_binding"]
    assert check.evaluate.__name__ == "nist_issued_closed"
    assert binding["evaluator_family"] == check.evaluate.__module__
    assert binding["kind"] == check.kind == "acm_certificate"
    assert binding["target"] == check.target == "resource"
    assert "Certificate.Certificate.Status" in binding["path"]
    assert "Certificate.Certificate.NotAfter" in binding["path"]
    assert "context.created_at" in binding["path"]
    assert "fc9beba778f553a3cb4e02a899bd8bf06a87e8817d37ea5cf23a95adb6ddb16e" in binding["source_note"]
    assert "at or before" in binding["source_note"] and "ISSUED" in binding["source_note"]
    assert entry["cli"] == [{"code": "aws acm describe-certificate --certificate-arn <RESOURCE_ARN> --region <REGION>",
                             "label": "Inspect exact ACM certificate metadata (read only)", "shell": "bash"}]
    assert "NOT_APPLICABLE" in entry["steps"][-1] and "UNKNOWN" in entry["steps"][-1]


def test_c2b_remediation_tracks_its_implemented_predicate_and_source():
    checks = {check.id: check for check in CHECKS}
    entries = reviewed()
    for check_id in C2B_DOCS:
        entry = entries[check_id]
        check = checks[check_id]
        assert entry["field_binding"]["evaluator_family"] == check.evaluate.__module__
        assert entry["field_binding"]["path"]
        assert entry["steps"] and entry["references"]
    assert "MANUAL" in " ".join(entries["aws.c2b.directoryservice.shared_accounts_review"]["caveats"])
    assert "third-party" in " ".join(entries["aws.c2b.eks.vpc_cni_network_policy"]["caveats"])
    assert "corrected" in " ".join(entries["aws.c2b.emr.block_public_access_only_port_22"]["caveats"]).lower()


def test_each_review_has_specific_setting_steps_primary_reference_and_inspection():
    entries = reviewed()
    repetitions = Counter(entry["summary"] for entry in entries.values())
    assert max(repetitions.values()) == 1
    for check_id, entry in entries.items():
        assert check_id not in entry["summary"]
        assert 1 <= len(entry["steps"]) <= 5
        assert all(step.strip() and len(step) > 30 for step in entry["steps"])
        assert not any(step.startswith("Review the declared setting and configure it") for step in entry["steps"])
        assert entry["references"]
        assert all(row["url"].startswith("https://docs.aws.amazon.com/") for row in entry["references"])
        assert entry["cli"] and entry["cli"][0]["code"].startswith("aws ")
        assert entry["caveats"]
        if "iac" in entry:
            assert entry["iac"]["code"]
        for command in entry["cli"]:
            assert command["shell"] == "bash"
            assert not re.search(r"\$\(|`|\b--profile\b", command["code"])
            placeholders = set(re.findall(r"<([A-Z][A-Z0-9_]*)>", command["code"]))
            safe_identity = {"RESOURCE_ID", "RESOURCE_ARN", "RESOURCE_NAME", "REGION", "ACCOUNT_ID"}
            manual_inputs = {
                "RESOURCE_ID", "RESOURCE_ARN", "RESOURCE_NAME", "BUCKET_NAME", "REPOSITORY_NAME",
                "REGION", "APPROVED_RETENTION_DAYS", "REPLACEMENT_POLICY_FILE",
                "DETECTOR_ID", "QUEUE_URL",
                "KMS_KEY_ARN",
                "TRAIL_BUCKET_NAME", "DEFAULT_VERSION_ID",
                "LOG_GROUP_NAME", "WINDOW_START", "WINDOW_END",
                "KEY_ARN", "VERSION_NUMBER",
                "CLUSTER_ARN", "APPLICATION_NAME", "SERVICE_NAME", "EC2_INSTANCE_ID", "VOLUME_ID",
                "TRAIL_NAME", "LISTENER_ARN", "WEB_ACL_ARN", "ACM_CERT_ARN", "REST_API_ID", "ROUTE_ID",
                "API_NAME", "CURRENT_AUTH_TYPE", "CLIENT_ID", "USER_NAME", "SHARED_ACCOUNT_ID",
                "SNS_TOPIC_NAME", "DOMAIN_NAME", "PACKAGE_FORMAT", "PACKAGE_NAME", "CREDENTIAL_ID",
                "DATA_SOURCE_ID", "IMAGE_DIGEST", "PARAMETER_GROUP_NAME", "SECURITY_CONFIGURATION_NAME",
                "SUBNET_GROUP_NAME", "VAULT_NAME", "SUBNET_ID", "PRIMARY_INSTANCE_ID", "SECURITY_GROUP_ID",
                "ORIGIN_BUCKET_NAME", "BACKUP_PLAN_ID", "LOG_GROUP_ARN", "STATEMENT_ID", "CURRENT_ETAG",
                "APPROVED_ACCOUNT_ID", "APPROVED_LAYER_ARNS", "APPROVED_RUNTIME", "APPROVED_SUBNET_IDS",
                "APPROVED_K8S_VERSION", "METHOD_RESOURCE_ID", "HTTP_METHOD", "APPROVED_AUTH_TYPE",
                "AUTHORIZER_ID", "APPROVED_INSTANCE_ID", "LISTENER_PORT", "NEW_SNAPSHOT_ID", "WEB_ACL_ID",
                "REVIEWED_SECURITY_GROUP_IDS",
                "AFFECTED_GROUP_ID", "REVIEWED_WORLD_OPEN_RULE_ID", "REVIEWED_EGRESS_PERMISSIONS_JSON",
                "REVIEWED_CLIENT_TOKEN",
                "REVIEWED_CACHE_TYPE", "REVIEWED_CACHING_BEHAVIOR", "REVIEWED_TTL_SECONDS",
                "APPROVED_UID", "APPROVED_GID", "REVIEWED_ROOT_DIRECTORY_JSON",
                "APPROVED_SECOND_AZ_SUBNET_ID",
                "FILE_SYSTEM_ID", "REVIEWED_ACCESS_POINT_JSON",
                "REVIEWED_DAX_CLUSTER_JSON", "REVIEWED_NODE_COUNT", "REVIEWED_AZ_LIST",
                "REVIEWED_SNAPSHOT_ID", "REVIEWED_DS_CERTIFICATE_JSON", "REVIEWED_OLD_CERT_ID",
                "AFFECTED_SUBNET_ID", "REVIEWED_VPC_ID", "REVIEWED_DMS_CERTIFICATE_JSON",
                "REVIEWED_ENDPOINT_ARN", "NEW_CERTIFICATE_ARN", "NEW_REPLICA_IDENTIFIER",
                "REVIEWED_INSTANCE_CLASS", "REVIEWED_SECOND_AZ", "SOURCE_CLUSTER_ID",
                "REVIEWED_DOCDB_RESTORE_JSON", "REVIEWED_DOCDB_INSTANCE_JSON",
                "REVIEWED_HTTPS_LISTENERS_JSON", "REVIEWED_OLD_LISTENER_PORTS",
                "REVIEWED_BEDROCK_DATA_SOURCE_JSON", "REVIEWED_LOG_BUCKET_NAME",
                "REVIEWED_LOG_GROUP_NAME", "REVIEWED_BUCKET_ENCRYPTION_JSON",
                "REVIEWED_KMS_KEY_ARN",
                "CONTAINER_INSTANCE_ARN", "REVIEWED_SNAPSHOT_DESCRIPTION",
                "REVIEWED_AVAILABILITY_ZONE", "REVIEWED_ECS_TASK_SET_JSON",
                "REVIEWED_SECURITY_GROUP_ID",
                "REVIEWED_AUTH_UPDATE_JSON",
                "FMS_POLICY_ID", "MEMBER_ACCOUNT_ID",
                "REVIEWED_OS_VPC_DOMAIN_JSON", "REVIEWED_OS_SECURITY_JSON",
                "NEW_SECURITY_CONFIGURATION_NAME", "REVIEWED_EMR_SECURITY_CONFIGURATION_JSON",
                "REVIEWED_EMR_CLUSTER_JSON",
                "REVIEWED_ELBV2_LISTENER_JSON", "REVIEWED_INTERNAL_ELBV2_JSON",
                "REVIEWED_ELASTICACHE_REPLACEMENT_JSON",
                "REVIEWED_BEDROCK_CUSTOMIZATION_JSON", "REVIEWED_BEDROCK_IMPORT_JSON",
                "STOPPED_SOURCE_SERVER_ID",
                    "REVIEWED_EC2_SERVICE_ARN",
            }
            assert placeholders <= safe_identity | manual_inputs | {
                "REVIEWED_" + suffix for suffix in (
                    "CORS_JSON", "TASK_DEFINITION_JSON", "SERVICE_UPDATE_JSON", "ENCRYPTION_JSON", "ADDON_JSON",
                    "DISTRIBUTION_JSON", "STAGE_PATCH_JSON", "API_PATCH_JSON", "LOG_CONFIG_JSON",
                    "WORKGROUP_JSON", "BACKUP_PLAN_JSON", "POLICY_FILE", "MONGODB_SETTINGS_JSON",
                    "NEPTUNE_SETTINGS_JSON", "REDIS_SETTINGS_JSON", "TASK_SETTINGS_JSON", "PARAMETERS_JSON",
                    "MIXED_INSTANCES_JSON", "LAUNCH_TEMPLATE_JSON", "TAGS_JSON", "BLOCK_PUBLIC_ACCESS_JSON",
                    "LOG_PUBLISHING_JSON", "GUARDRAIL_JSON", "AGENT_JSON", "PROMPT_JSON", "LOGGING_JSON",
                    "CLIENT_JSON", "RADIUS_JSON", "ENVIRONMENT_JSON", "EXPORT_JSON", "LOGS_JSON",
                    "WEBHOOK_FILTERS_JSON", "SCANNING_RULES_JSON",
                    "METHOD_PATCH_JSON", "AUTHORIZER_JSON", "GRAPHQL_API_JSON", "REPORT_PLAN_JSON",
                    "ENDPOINT_JSON", "STACK_UPDATE_JSON", "SOURCE_JSON", "LIFECYCLE_POLICY_JSON",
                    "ACTIONS_JSON", "LISTENER_JSON", "EVENT_SELECTORS_JSON", "SELECTION_JSON",
                )
            }, (check_id, placeholders)


def test_immutability_and_source_scope_are_preserved():
    entries = reviewed()
    assert "replacement" in " ".join(entries["aws.rds.encryption"]["steps"]).lower()
    assert "replacement" in " ".join(entries["aws.ebs.encryption"]["steps"]).lower()
    assert "account-level" in " ".join(entries["aws.s3.public_access_block"]["steps"])
    assert "S3 encrypts new objects by default" in " ".join(entries["aws.s3.default_encryption"]["caveats"])
    assert "manual" in " ".join(entries["aws.s3.no_public_acl"]["caveats"]).lower()
    assert "version" in " ".join(entries["aws.eks.secrets_encryption"]["steps"]).lower()
    assert "zero" in " ".join(entries["aws.b.lambda.reserved_concurrency"]["caveats"]).lower()
    assert "DynamoDB-owned default encryption" in " ".join(entries["aws.b.dynamodb.kms_description"]["caveats"])
    assert "UNKNOWN" in " ".join(entries["aws.b.ecs.declared_nonroot_users"]["caveats"])
    assert "MANUAL" in " ".join(entries["aws.b.acm.pending_validation_review"]["caveats"])
    assert "not proof" in " ".join(entries["aws.b.rds_instance.nondefault_admin"]["caveats"])
    assert "does not prove physical possession" in " ".join(entries["aws.a.iam.root_hardware_mfa"]["caveats"])
    assert "UNKNOWN" in " ".join(template("aws.a.cloudtrail.bucket_mfa_delete")["caveats"])
    assert "not proof of effective public access" in " ".join(entries["aws.a.cloudtrail.joined_bucket_declared_public_grants"]["caveats"])
    assert "never collected" in " ".join(entries["aws.htbp.lambda.env_var_names_not_credentials"]["caveats"])
    assert "MANUAL" in " ".join(entries["aws.htbp.ecr.registry_policy_trust_boundary"]["caveats"])
    assert "not proof of malicious intent" in " ".join(entries["aws.claude2_a.cloudtrail.threat_detection_enumeration"]["caveats"])
    assert "confirmed SNS subscription" in entries["aws.gap.cloudwatch.cis_alarm.root_account_usage"]["summary"]
    assert "not a proof of effective public write" in " ".join(entries["aws.gap.s3.no_public_write_acl_or_policy"]["caveats"])
    assert "does not establish a concrete attack path" in " ".join(entries["aws.gap.ec2.instance_no_iam_role_with_management_level_access"]["caveats"])
    assert entries["aws.gap.ec2.instance_no_iam_passrole_and_lambda_invoke_function_access"]["field_binding"]["predicate"].startswith("all_of:")
    assert "--cluster <CLUSTER_ARN>" in entries["aws.c2b.ecs.service_no_public_ip"]["cli"][0]["code"]
    assert "--application-name <APPLICATION_NAME>" in entries["aws.c2b.codedeploy.lambda_not_all_at_once"]["cli"][0]["code"]
    assert "get-function-configuration" in entries["aws.c2b.lambda.env_vars_cmk"]["cli"][0]["code"]
    assert "Environment.Variables" not in entries["aws.c2b.lambda.env_vars_cmk"]["cli"][0]["code"]
    assert "MANUAL" in " ".join(entries["aws.c2b.directoryservice.shared_accounts_review"]["caveats"])


def test_c2b_command_scope_and_actionable_families():
    entries = reviewed()
    global_endpoints = {"iam", "cloudfront", "s3api"}
    for check_id, entry in entries.items():
        if not check_id.startswith("aws.c2b."):
            continue
        assert "Prowler:" not in entry["summary"] and "Steampipe:" not in entry["summary"]
        assert "Apply through the existing Terraform/CloudFormation" not in entry.get("iac", {}).get("code", "")
        for command in entry["cli"]:
            words = shlex.split(command["code"])
            if words[1] not in global_endpoints:
                assert "--region" in words, (check_id, command["code"])
    assert "--cluster <CLUSTER_ARN>" in entries["aws.c2b.ecs.service_no_public_ip"]["cli"][0]["code"]
    assert "--application-name <APPLICATION_NAME>" in entries["aws.c2b.codedeploy.lambda_not_all_at_once"]["cli"][0]["code"]
    assert any("update-project-visibility" in c["code"] for c in entries["aws.c2b.codebuild.project_private"]["cli"])
    assert any("update-fleet" in c["code"] for c in entries["aws.c2b.appstream.no_default_internet"]["cli"])
    assert any("update-work-group" in c["code"] for c in entries["aws.c2b.athena.enforce_configuration"]["cli"])
    assert any("get-function-configuration" in c["code"] for c in entries["aws.c2b.lambda.env_vars_cmk"]["cli"])
    assert all("--region" not in c["code"] for c in entries["aws.c2b.cloudfront.custom_ssl_certificate"]["cli"])


def test_inspection_cli_names_and_required_flags_exist_in_aws_api_model():
    session = botocore.session.get_session()
    aliases = {"s3api": "s3", "configservice": "config"}
    for check_id, entry in reviewed().items():
        for command in entry["cli"]:
            words = shlex.split(command["code"])
            model = session.get_service_model(aliases.get(words[1], words[1]))
            operation = next((name for name in model.operation_names if xform_name(name, "-") == words[2]), None)
            if words[1:3] == ["emr", "create-cluster"]:
                # The AWS CLI exposes RunJobFlow as the high-level create-cluster command.
                operation = "RunJobFlow"
            assert operation, (check_id, command["code"])
            shape = model.operation_model(operation).input_shape
            if check_id.startswith("aws.c2b."):
                allowed = {"--cli-input-json", "--query", "--region", "--output", "--page-size"}
                for member, member_shape in (shape.members if shape else {}).items():
                    flag = "--" + xform_name(member, "-")
                    allowed.add(flag)
                    if member_shape.type_name == "boolean":
                        allowed.add("--no-" + xform_name(member, "-"))
                    if words[1:3] == ["ec2", "modify-subnet-attribute"] and member == "MapPublicIpOnLaunch":
                        # CLI renders this structure-valued EC2 switch as a boolean pair.
                        allowed.add("--no-map-public-ip-on-launch")
                assert {word for word in words[3:] if word.startswith("--")} <= allowed, (check_id, command["code"])
            if "--cli-input-json" in words:
                continue  # The complete owner-reviewed request supplies required API members.
            for member in (shape.required_members if shape else []):
                # AWS CLI's paginated list-user-pools supplies MaxResults through
                # --page-size rather than exposing the API member as a CLI flag.
                if words[1:3] == ["cognito-idp", "list-user-pools"] and member == "MaxResults":
                    continue
                assert "--" + xform_name(member, "-") in words, (check_id, member)


def test_customer_summaries_do_not_expose_evaluator_provenance():
    entries = reviewed()
    for check_id, entry in entries.items():
        assert not re.search(r"(?i)\b(evaluator|Prowler|Steampipe|upstream)\b", entry["summary"]), check_id
    assert "active state" in entries["aws.a.accessanalyzer.region_active"]["summary"]
    assert "BLOCK" in entries["aws.c2b.codeartifact.internal_packages_block_upstream"]["summary"]
    assert "source_note" in entries["aws.a.accessanalyzer.region_active"]["field_binding"]


def test_acm_expiry_review_branches_on_certificate_type_and_eligibility():
    entry = reviewed()["aws.c2b.acm.in_use_not_expiring_7_days"]
    text = " ".join(entry["steps"])
    assert all(token in text for token in (
        "Type", "Status", "NotAfter", "InUseBy", "RenewalEligibility",
        "Amazon-issued public", "ACM-issued private", "IMPORTED",
        "Reimport certificate", "more than seven days",
    ))
    assert "private key" in text and "private key" not in " ".join(command["code"] for command in entry["cli"])
    assert "previously exported" in entry["cli"][1]["label"]
    assert "renew-certificate" in entry["cli"][1]["code"]
    assert "an IaC declaration alone does not rotate it" in entry["iac"]["code"]
    assert "NOT_APPLICABLE" in " ".join(entry["caveats"])
    assert "UNKNOWN" in " ".join(entry["caveats"])
    assert any("import-reimport.html" in ref["url"] for ref in entry["references"])


def test_ecs_review_respects_fargate_fact_and_controller_specific_replacement():
    entries = reviewed()
    registered = entries["aws.c2b.ecs.cluster_has_registered_instances"]
    assert registered["review_status"] == "approved"
    assert "desiredCount>0 launchType=EC2" in registered["field_binding"]["path"]
    assert "Fargate-only NOT_APPLICABLE" in registered["field_binding"]["path"]
    assert "unresolved UNKNOWN" in registered["field_binding"]["path"]
    assert "Fargate-only" in " ".join(registered["caveats"])
    assert "does not prove agent connectivity" in " ".join(registered["caveats"])
    in_vpc = entries["aws.c2b.ecs.container_instance_in_vpc"]
    assert in_vpc["review_status"] == "approved"
    assert "no FAIL branch" in in_vpc["field_binding"]["path"]
    assert "mi-* NOT_APPLICABLE" in in_vpc["field_binding"]["path"]
    assert "missing/denied/null/malformed UNKNOWN" in in_vpc["field_binding"]["path"]
    assert "retired" in " ".join(in_vpc["caveats"])
    encrypted = entries["aws.c2b.ecs.cluster_instance_volumes_encrypted"]
    assert "existing volumes" in " ".join(encrypted["steps"])
    assert any("create-volume" in command["code"] and "--encrypted" in command["code"]
               for command in encrypted["cli"])
    task_set = entries["aws.c2b.ecs.task_set_no_public_ip"]
    assert "EXTERNAL" in " ".join(task_set["steps"])
    assert "CODE_DEPLOY" in " ".join(task_set["steps"])
    assert "UpdateTaskSet only changes scale" in " ".join(task_set["steps"])
    assert any("create-task-set" in command["code"] for command in task_set["cli"])


def test_eks_additional_security_group_count_uses_supported_cluster_update():
    entry = reviewed()["aws.c2b.eks.single_security_group"]
    assert "additional" in entry["summary"]
    assert "clusterSecurityGroupId is separate" in " ".join(entry["caveats"])
    assert any("update-cluster-config" in command["code"] and
               "securityGroupIds=<REVIEWED_SECURITY_GROUP_ID>" in command["code"]
               for command in entry["cli"])
    assert "asynchronous" in " ".join(entry["steps"])


def test_pre6_redis_auth_is_staged_only_for_eligible_tls_group_without_token_leak():
    entry = reviewed()["aws.c2b.elasticache.redis_auth_pre6"]
    steps = " ".join(entry["steps"])
    assert all(term in steps for term in ("5.0.6", "TLS", "ROTATE", "SET", "client", "NOT_APPLICABLE"))
    commands = " ".join(command["code"] for command in entry["cli"])
    assert "modify-replication-group --cli-input-json file://<REVIEWED_AUTH_UPDATE_JSON>" in commands
    assert "--auth-token" not in commands
    assert "secret" in " ".join(entry["caveats"]).lower()


def test_ecr_latest_image_guidance_uses_corrected_complete_exact_digest_facts():
    entry = reviewed()["aws.c2b.ecr.latest_image_no_medium_plus_findings"]
    steps = " ".join(entry["steps"])
    assert all(term in steps for term in ("imageDigest", "DescribeImageScanFindings", "COMPLETE",
                                          "aggregate count map", "completion time", "UNKNOWN"))
    assert "ScanFindings" in entry["field_binding"]["path"]
    assert "scan_completed_at" in entry["field_binding"]["observed_fail_evidence"]
    assert "clean result cannot be inferred from DescribeImages alone" in " ".join(entry["caveats"])


def test_eks_cluster_security_group_guidance_matches_presence_and_platform_states():
    entry = reviewed()["aws.c2b.eks.cluster_security_group_present"]
    assert entry["review_status"] == "approved"
    steps = " ".join(entry["steps"])
    caveats = " ".join(entry["caveats"])
    assert "clusterSecurityGroupId" in steps
    assert "Kubernetes NetworkPolicy" in steps
    assert "UNKNOWN" in steps and "NOT_APPLICABLE" in steps
    assert "1.14-eks.3" in caveats
    assert "automatically" in caveats and "replacement" in caveats


def test_msk_version_guidance_uses_cluster_specific_targets_and_current_token():
    family = json.loads((ROOT / "peaso/rulepacks/remediation_aws_families_reviewed.json").read_text())
    entry = family["aws.cb.kafka.latest_version"]
    from tests.reviewed_guidance_presentation import assert_approved_presentation
    current=assert_approved_presentation("aws.cb.kafka.latest_version",entry)
    assert "fresh DescribeClusterV2 Version" in " ".join(current["caveats"])
    assert "compatible target returned for this cluster" in " ".join(current["caveats"])
    assert entry["review_status"] == "approved"
    binding = entry["field_binding"]
    assert binding["kind"] == "msk_cluster" and binding["target"] == "resource"
    assert "ClusterArn GetCompatibleKafkaVersions SourceVersion/TargetVersions" in binding["path"]
    assert "ListKafkaVersions Status" in binding["path"]
    steps = " ".join(entry["steps"])
    caveats = " ".join(entry["caveats"])
    assert "deprecated current version fails independently" in steps
    assert "newer ACTIVE target returned for this cluster" in steps
    assert "no valid compatible target" in steps and "fabricating an upgrade path" in steps
    assert "UNKNOWN" in steps and "client compatibility" in steps
    assert "not the Apache Kafka version string" in caveats
    assert "--cluster-arn <RESOURCE_ARN>" in entry["cli"][2]["code"]
    assert "--current-version <CURRENT_CLUSTER_VERSION>" in entry["cli"][3]["code"]
    assert "--target-kafka-version <REVIEWED_COMPATIBLE_ACTIVE_KAFKA_VERSION>" in entry["cli"][3]["code"]


def test_rds_audit_and_tls_guidance_uses_engine_specific_parameter_values():
    family = json.loads((ROOT / "peaso/rulepacks/remediation_aws_families_reviewed.json").read_text())
    audit = family["aws.cb.rds.aurora_mysql_server_audit_logging"]
    instance = family["aws.cb.rds.instance_tls_parameters"]
    maria = family["aws.cb.rds.mariadb_require_secure_transport"]
    for check_id, entry in (("aws.cb.rds.aurora_mysql_server_audit_logging", audit),
                            ("aws.cb.rds.instance_tls_parameters", instance),
                            ("aws.cb.rds.mariadb_require_secure_transport", maria)):
        assert entry["review_status"] == "approved"
        from tests.reviewed_guidance_presentation import assert_approved_presentation
        assert_approved_presentation(check_id,entry)
        assert entry["source_proof"]["evaluator"].startswith("peaso/checks/claude_aws_b_db.py:")
        assert "UNKNOWN" in " ".join(entry["steps"] + entry["caveats"])
        assert "--cli-input-json file://<REVIEWED_RDS_" in entry["cli"][-1]["code"]
    assert "server_audit_logging ON/1" in audit["field_binding"]["path"]
    assert "server_audit_events" in audit["field_binding"]["path"]
    assert "QUERY_DCL" in " ".join(audit["steps"])
    assert "no spaces" in " ".join(audit["steps"])
    assert "not log generation" in " ".join(audit["caveats"])
    assert "DBClusterIdentifier absent" in instance["field_binding"]["path"]
    assert "rds.force_ssl=1 OR require_secure_transport ON/1 by engine" in instance["field_binding"]["path"]
    assert "universal reboot" in " ".join(instance["caveats"])
    assert "EngineVersion>=10.5" in maria["field_binding"]["path"]
    assert "require_secure_transport ON/1" in maria["field_binding"]["path"]
    assert "no instance reboot for this parameter update" in " ".join(maria["steps"])


def test_rds_instance_iam_auth_guidance_requires_exact_supported_standalone_option():
    family = json.loads((ROOT / "peaso/rulepacks/remediation_aws_families_reviewed.json").read_text())
    check_id = "aws.cb.rds.instance_iam_auth_all_engines"
    entry = family[check_id]
    from tests.reviewed_guidance_presentation import assert_approved_presentation
    current=assert_approved_presentation(check_id,entry)
    assert "conflicting" in " ".join(current["caveats"])
    assert "maintenance window" in " ".join(current["caveats"])
    assert entry["review_status"] == "approved"
    assert entry["source_proof"]["evaluator"] == "peaso/checks/claude_aws_b_db.py:515"
    path = entry["field_binding"]["path"]
    for field in ("DBClusterIdentifier", "SubnetOutpost.Arn", "EngineVersion", "DBInstanceClass",
                  "SupportsIAMDatabaseAuthentication=true"):
        assert field in path
    steps = " ".join(entry["steps"])
    caveats = " ".join(entry["caveats"])
    assert "UNKNOWN" in steps and "UNKNOWN" in caveats
    assert "maintenance window" in steps
    assert "observed true flag can pass" in caveats
    assert "RDS on Outposts" in caveats
    assert all("--apply-immediately" not in command["code"] for command in entry["cli"])
    assert any("describe-orderable-db-instance-options" in command["code"] for command in entry["cli"])
    assert any("--enable-iam-database-authentication" in command["code"] for command in entry["cli"])


def test_fms_scope_guidance_separates_missing_evaluation_from_violation():
    entry = reviewed()["aws.c2b.fms.policies_compliant"]
    assert entry["field_binding"]["target"] == "scope"
    assert "EvaluationResults[]" in entry["field_binding"]["path"]
    assert "every returned policy/member" in entry["field_binding"]["path"]
    assert "incomplete_evaluations[] may coexist" in entry["field_binding"]["observed_fail_evidence"]
    assert "does not prove that every organization account was returned" in " ".join(entry["caveats"])
    assert "Do not enable automatic FMS remediation" in " ".join(entry["steps"])
    assert any("get-compliance-detail" in command["code"] and
               "--member-account <MEMBER_ACCOUNT_ID>" in command["code"]
               for command in entry["cli"])


def test_opensearch_vpc_replacement_and_internal_user_policy_conflict():
    entries = reviewed()
    vpc = entries["aws.c2b.es.in_vpc"]
    assert "separate VPC-access domain" in " ".join(vpc["steps"])
    assert "cannot change in place" in " ".join(vpc["caveats"])
    assert any("create-domain --cli-input-json file://<REVIEWED_OS_VPC_DOMAIN_JSON>" in command["code"]
               for command in vpc["cli"])
    internal = entries["aws.c2b.es.internal_user_database_enabled"]
    assert "opposite" in " ".join(internal["steps"])
    assert "secret" in " ".join(internal["caveats"]).lower()
    assert all("MasterUserPassword" not in command["code"] for command in internal["cli"])


def test_emr_public_ingress_removes_only_verified_rule_on_joined_group():
    entry = reviewed()["aws.c2b.emr.cluster_not_publicly_accessible"]
    commands = " ".join(command["code"] for command in entry["cli"])
    assert "describe-security-group-rules" in commands
    assert "revoke-security-group-ingress --group-id <AFFECTED_GROUP_ID>" in commands
    assert "--security-group-rule-ids <REVIEWED_WORLD_OPEN_RULE_ID>" in commands
    assert "full 0-65535" in " ".join(entry["steps"])
    assert "shared" in " ".join(entry["caveats"])


def test_emr_encryption_configurations_require_new_named_config_and_cluster_cutover():
    entries = reviewed()
    cluster_ids = (
        "cluster_at_rest_encryption", "cluster_in_transit_encryption",
        "cluster_at_rest_cse_custom", "cluster_at_rest_sse_kms",
        "cluster_local_disk_cmk", "cluster_local_disk_encryption",
    )
    for suffix in cluster_ids:
        entry = entries["aws.c2b.emr." + suffix]
        assert "Cluster.Cluster.SecurityConfiguration -> joined" in entry["field_binding"]["path"]
        assert "new security configuration" in " ".join(entry["steps"])
        assert "replacement EMR capacity" in " ".join(entry["steps"])
        assert any("create-security-configuration" in command["code"] for command in entry["cli"])
    assert "mutually exclusive" in " ".join(entries["aws.c2b.emr.cluster_at_rest_cse_custom"]["caveats"])
    assert "AwsKms does not satisfy" in " ".join(entries["aws.c2b.emr.cluster_local_disk_cmk"]["steps"])
    for suffix in ("security_configuration_at_rest", "security_configuration_in_transit"):
        entry = entries["aws.c2b.emr." + suffix]
        assert "Configuration.SecurityConfiguration.EncryptionConfiguration." in entry["field_binding"]["path"]
        assert "old configuration" in " ".join(entry["steps"])


def test_emr_launch_time_guidance_does_not_claim_subnet_flag_fixes_current_node():
    entries = reviewed()
    kerberos = entries["aws.c2b.emr.cluster_kerberos_enabled"]
    assert "KerberosAttributes" in " ".join(kerberos["steps"])
    assert "passwords" in " ".join(kerberos["caveats"])
    assert all("KdcAdminPassword" not in command["code"] for command in kerberos["cli"])
    attached = entries["aws.c2b.emr.cluster_security_configuration"]
    assert "does not validate encryption" in " ".join(attached["caveats"])
    public_dns = entries["aws.c2b.emr.master_no_public_dns"]
    assert "DNS suffix alone" in " ".join(public_dns["steps"])
    subnet = entries["aws.c2b.emr.master_subnet_no_auto_public_ip"]
    assert "affects future launches only" in " ".join(subnet["steps"])
    assert any("modify-subnet-attribute --subnet-id <AFFECTED_SUBNET_ID>" in command["code"] and
               "--no-map-public-ip-on-launch" in command["code"] for command in subnet["cli"])
    assert "future-launch subnet setting" in " ".join(subnet["caveats"])


def test_backup_vault_key_guidance_matches_observed_metadata_only():
    entry = reviewed()["aws.c2b.backup.vault_encrypted"]
    assert entry["review_status"] == "approved"
    assert "ListBackupVaults" in entry["field_binding"]["path"]
    assert "DescribeBackupVault" in entry["field_binding"]["path"]
    assert "no supported unencrypted-vault FAIL branch" in " ".join(entry["caveats"])
    assert "each recovery point IsEncrypted" in " ".join(entry["steps"])
    assert all("create-backup-vault" not in command["code"] for command in entry["cli"])


def test_elbv2_ingress_listener_and_scheme_repairs_track_distinct_predicates():
    entries = reviewed()
    ingress = entries["aws.c2b.elbv2.internet_facing_open_sg"]
    assert "Scheme=internet-facing" in ingress["field_binding"]["path"]
    assert "full TCP 0-65535" in " ".join(ingress["steps"])
    assert "HTTPS/443 open to the world is not itself a failure" in " ".join(ingress["steps"])
    assert any("revoke-security-group-ingress" in c["code"] and
               "<REVIEWED_WORLD_OPEN_RULE_ID>" in c["code"] for c in ingress["cli"])
    listeners = entries["aws.c2b.elbv2.listeners_secure_protocol"]
    assert "HTTP-to-HTTPS redirect" in " ".join(listeners["steps"])
    assert "TCP pass-through" in " ".join(listeners["steps"])
    assert any("modify-listener --cli-input-json" in c["code"] for c in listeners["cli"])
    scheme = entries["aws.c2b.elbv2.not_internet_facing"]
    assert "scheme-only" in " ".join(scheme["caveats"])
    assert "replacement" in " ".join(scheme["caveats"])
    assert any("create-load-balancer --cli-input-json" in c["code"] for c in scheme["cli"])


def test_elasticache_key_guidance_separates_disabled_key_and_immutable_group():
    entry = reviewed()["aws.c2b.elasticache.cmk_enabled"]
    assert "AtRestEncryptionEnabled" in entry["field_binding"]["path"]
    assert "KeyManager" in " ".join(entry["caveats"])
    assert "StorageEncryptionType" in " ".join(entry["steps"])
    assert any("kms enable-key" in command["code"] for command in entry["cli"])
    assert any("elasticache create-replication-group --cli-input-json" in command["code"]
               for command in entry["cli"])


def test_bedrock_custom_model_key_guidance_branches_on_model_origin():
    entry = reviewed()["aws.c2b.bedrock.custom_model_cmk"]
    assert entry["field_binding"]["path"] == "Model.modelKmsKeyArn (GetCustomModel detail)"
    assert "customizationType" in " ".join(entry["steps"])
    assert "customModelKmsKeyId" in " ".join(entry["steps"])
    assert "modelKmsKeyArn" in " ".join(entry["steps"])
    assert any("create-model-customization-job --cli-input-json" in c["code"] for c in entry["cli"])
    assert any("create-custom-model --cli-input-json" in c["code"] for c in entry["cli"])
    assert "does not imply same-Region re-encryption" in " ".join(entry["caveats"])


def test_drs_guidance_tracks_current_source_replication_not_historical_jobs():
    entry = reviewed()["aws.c2b.drs.region_has_job"]
    assert entry["review_status"] == "approved"
    assert entry["field_binding"]["kind"] == "drs_source_server"
    assert "dataReplicationInfo.dataReplicationState" in entry["field_binding"]["path"]
    assert "DescribeJobs history" in " ".join(entry["caveats"])
    assert "NOT_APPLICABLE" in " ".join(entry["steps"])
    assert any("start-replication --source-server-id <STOPPED_SOURCE_SERVER_ID>" in c["code"]
               for c in entry["cli"])
    assert "billing" in " ".join(entry["caveats"])
    assert all("start-recovery" not in c["code"] for c in entry["cli"])
