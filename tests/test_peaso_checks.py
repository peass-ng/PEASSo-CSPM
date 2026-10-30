"""Native registry behavior over immutable provider facts, with no credentials."""
import copy
import json
from pathlib import Path
import pytest
from peaso.checks import CHECKS, HACKTRICKS
from peaso.checks.fixtures import CASES
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot
from peaso.engine import hydrate_frameworks

_bulk_cases = json.loads((Path(__file__).parent / 'fixtures/bulk_pending_behavior.json').read_text())
_bulk_ids = set(json.loads((Path(__file__).resolve().parents[1] / 'peaso/checks/bulk_pending.json').read_text())['checks'])
assert set(_bulk_cases) == _bulk_ids, 'bulk behavior fixture IDs must match admitted definitions'
# These two historical cases used the superseded All/inline marker contract.
# Reuse the pinned customer-policy cases after their source-correction successor.
_customer_cases = json.loads((Path(__file__).resolve().parents[1] /
                              'peaso/checks/aws_all_policies_fixtures.json').read_text())
_bulk_cases['aws_fedramp_iam_all_policies_no_admin_star'] = copy.deepcopy(
    _customer_cases['aws.nist.all_iam_policies_no_star_star'])
_bulk_cases['aws_fedramp_iam_all_policies_no_service_wildcard'] = copy.deepcopy(
    _customer_cases['aws.nist.all_managed_policies_no_service_wildcard'])
# The historical resource-policy PASS used o-approved, which is not a valid
# AWS Organizations ID. Correct the synthetic caller boundary and both index
# projections; preserve the archived input and the TLS-only FAIL unchanged.
_resource_policy_case = _bulk_cases['aws_cis_aws_resource_policy_unrestricted_principal']
for _policy_item in (
    _resource_policy_case['pass'],
    _resource_policy_case['pass_index']['collections']['aws_resource_policy'][0]['items'][0],
    _resource_policy_case['pass_index']['aws_resource_policy'][0]['data'],
):
    _policy_item['Policy']['Statement'][0]['Condition']['StringEquals']['aws:PrincipalOrgID'] = 'o-1234567890'
del _resource_policy_case, _policy_item
CASES.update(_bulk_cases)
# ECS logging now fails closed unless DescribeTaskDefinition detail is recorded
# as collected (the collector's _detail status). Keep the archived central case
# and add that native status to every detail projection of its successor.
def _with_collected_ecs_detail(value):
    if isinstance(value, dict):
        value = {key: _with_collected_ecs_detail(item) for key, item in value.items()}
        if isinstance(value.get('Definition'), dict) and 'taskDefinition' in value['Definition']:
            value['Definition'] = {'collection_status': 'collected', **value['Definition']}
        return value
    if isinstance(value, list):
        return [_with_collected_ecs_detail(item) for item in value]
    return value
CASES['aws_g6_ecs_all_containers_logging'] = _with_collected_ecs_detail(CASES['aws_g6_ecs_all_containers_logging'])


PAB = {key: True for key in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}
BASE = {
 "aws.iam.no_full_admin": ({"PolicyDocument": {"Statement": []}}, {"PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}),
 "aws.iam.restrict_public_trust": ({"AssumeRolePolicyDocument": {"Statement": []}}, {"AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}}),
 "aws.iam.console_mfa": ({"LoginProfile": {"LoginProfile": {"UserName": "alice"}}, "MFADevices": {"collection_status": "collected", "items": [{"SerialNumber": "mfa"}]}}, {"LoginProfile": {"LoginProfile": {"UserName": "alice"}}, "MFADevices": {"collection_status": "empty", "items": []}}),
 "aws.s3.public_access_block": ({"PublicAccessBlock": {"PublicAccessBlockConfiguration": PAB}}, {"PublicAccessBlock": {"PublicAccessBlockConfiguration": {**PAB, "IgnorePublicAcls": False}}}),
 "aws.ec2.restrict_internet_ingress": ({"IpPermissions": []}, {"IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}),
 "aws.ec2.imdsv2": ({"MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"}}, {"MetadataOptions": {"HttpTokens": "optional", "HttpEndpoint": "enabled"}}),
 "gcp.iam.restrict_public_members": ({"bindings": []}, {"bindings": [{"role": "roles/viewer", "members": ["allUsers"]}]}),
 "gcp.iam.avoid_basic_roles": ({"bindings": []}, {"bindings": [{"role": "roles/editor", "members": ["user:a@example.com"]}]}),
 "gcp.storage.uniform_access": ({"iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}}}, {"iamConfiguration": {"uniformBucketLevelAccess": {"enabled": False}}}),
 "gcp.compute.restrict_internet_ingress": ({"direction": "INGRESS", "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}], "sourceRanges": ["10.0.0.0/8"]}, {"direction": "INGRESS", "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}], "sourceRanges": ["0.0.0.0/0"]}),
 "gcp.compute.no_external_ip": ({"networkInterfaces": []}, {"networkInterfaces": [{"accessConfigs": [{"natIP": "203.0.113.1"}]}]}),
 "azure.storage.https_only": ({"properties": {"supportsHttpsTrafficOnly": True}}, {"properties": {"supportsHttpsTrafficOnly": False}}),
 "azure.storage.no_blob_public_access": ({"properties": {"allowBlobPublicAccess": False}}, {"properties": {"allowBlobPublicAccess": True}}),
 "azure.storage.minimum_tls": ({"properties": {"minimumTlsVersion": "TLS1_2"}}, {"properties": {"minimumTlsVersion": "TLS1_0"}}),
 "azure.iam.review_owner_assignment": ({"properties": {"roleDefinitionId": "/roles/reader", "principalId": "alice"}}, {"properties": {"roleDefinitionId": "/roles/8e3af657-a8ff-443c-a75c-2fe8c4bcb635", "principalId": "alice"}}),
 "azure.iam.no_full_custom_role": ({"properties": {"type": "CustomRole", "permissions": [{"actions": ["Microsoft.Storage/storageAccounts/read"]}]}}, {"properties": {"type": "CustomRole", "permissions": [{"actions": ["*"]}]}}),
 "azure.network.restrict_internet_ingress": ({"properties": {"securityRules": []}}, {"properties": {"securityRules": [{"properties": {"direction": "Inbound", "access": "Allow", "sourceAddressPrefix": "Internet", "destinationPortRange": "22", "protocol": "Tcp"}}]}}),
 "k8s.rbac.role_no_wildcards": ({"rules": []}, {"rules": [{"verbs": ["*"], "resources": ["pods"], "apiGroups": [""]}]}),
 "k8s.rbac.no_wildcards": ({"rules": []}, {"rules": [{"verbs": ["*"], "resources": ["pods"], "apiGroups": [""]}]}),
 "k8s.rbac.review_namespaced_subjects": ({"roleRef": {"kind": "Role", "name": "view"}, "subjects": []}, {"roleRef": {"kind": "Role", "name": "view"}, "subjects": [{"kind": "Group", "name": "system:authenticated"}]}),
 "k8s.rbac.review_broad_subjects": ({"roleRef": {"kind": "ClusterRole", "name": "view"}, "subjects": []}, {"roleRef": {"kind": "ClusterRole", "name": "view"}, "subjects": [{"kind": "Group", "name": "system:authenticated"}]}),
 "k8s.pod.no_privileged_containers": ({"spec": {"containers": [{"name": "app", "securityContext": {"privileged": False}}]}}, {"spec": {"containers": [{"name": "app", "securityContext": {"privileged": True}}]}}),
 "k8s.pod.no_host_namespaces": ({"spec": {"hostPID": False}}, {"spec": {"hostPID": True}}),
 "k8s.service.review_public_type": ({"spec": {"type": "ClusterIP"}}, {"spec": {"type": "LoadBalancer"}}),
}
for cid, (passing, failing) in BASE.items():
    CASES[cid] = {"pass": passing, "fail": failing}
# Effective S3 BPA = bucket OR account (s3control); missing account BPA is UNKNOWN, not FAIL.
CASES["aws.s3.public_access_block"]["fail_index"] = {"collections": {"s3_account_public_access_block": [{"scope": "a/r", "status": "empty", "items": []}]}}
CASES["aws.s3.public_access_block"]["unknown"] = {"PublicAccessBlock": {"PublicAccessBlockConfiguration": {**PAB, "IgnorePublicAcls": False}}}
CASES["aws.s3.default_encryption"] = {"pass": {"Encryption": {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}}, "unknown": {"Encryption": {"absent": True}}}
CASES["gcp.storage.public_access_prevention"] = {"pass": {"iamConfiguration": {"publicAccessPrevention": "enforced"}}, "unknown": {"iamConfiguration": {"publicAccessPrevention": "inherited"}}}
# An inherited setting is unenforced when the same project's complete effective policy says false.
CASES["gcp.storage.public_access_prevention"].update({
    "fail": {"iamConfiguration": {"publicAccessPrevention": "inherited"}},
    "fail_index": {
        "context": {"provider": "gcp", "scope": "projects/p"},
        "collections": {"org_policy_effective": [{"scope": "projects/p", "status": "collected"}]},
        "org_policy_effective": [{"scope": "projects/p", "data": {
            "name": "projects/p/policies/storage.publicAccessPrevention",
            "constraint": "storage.publicAccessPrevention",
            "spec": {"rules": [{"enforce": False}]},
        }}],
    },
})
CASES["k8s.network.namespace_policy_inventory"] = {"manual": {"metadata": {"name": "apps"}}, "fail": {"metadata": {"name": "empty"}}, "index": {"collections": {"networkpolicy": [{"scope": "apps", "status": "collected", "items": [{"metadata": {"namespace": "apps"}}]}, {"scope": "empty", "status": "empty", "items": []}]}, "networkpolicy": [{"data": {"metadata": {"namespace": "apps"}}}]}}


# These older minimal positive examples predate the named native authority
# requirements. They must remain unresolved; directed successor tests exercise
# complete positive evidence for controls that are still active.
STALE_PASS_CASES = {
    "aws.pci.classic_elb.custom_ssl_policy",
    "aws.pci.classic_elb.predefined_ssl_policy",
    "aws_cis_organization_units_environment_sensitivity",
    "aws_g6_ecs_fargate_storage_encryption",
    "aws_log_archive_immutable",
    "aws_nist_apigateway_stage_logging_enabled",
    "aws_nist_cloudtrail_trail_integrated_with_logs",
    "aws_nist_config_enabled_all_regions",
    "azure.gap.compute_vm_adaptive_application_controls_enabled",
    "azure.gap.iam_user_with_read_permission_on_subscription_mfa_enabled",
    "azure.gap.kubernetes_cluster_container_use_allowed_apparmor_profile",
    "azure.gap.network_subnet_protected_by_firewall",
    "azure.other.backup_restore_evidence",
    "azure.other.database_backup_alert",
    "azure.other.enumeration_logging",
    "azure.other.infrastructure_configuration_backup",
    "azure.other.nsg_port_protocol_assignment",
    "azure_c5_ops_05_04ac",
    "azure_c5_ops_07_01b",
    "azure_c5_ops_08_01b",
    "azure_c5_ops_13_03b",
}
STALE_FAIL_CASES = {
    "aws.pci.classic_elb.predefined_ssl_policy",
    "aws_cis_organization_units_environment_sensitivity",
    "aws_g6_ecs_fargate_storage_encryption",
    "aws_log_archive_immutable",
    "aws_nist_apigateway_stage_logging_enabled",
    "aws_nist_config_enabled_all_regions",
    "azure.gap.kubernetes_cluster_container_use_allowed_apparmor_profile",
    "azure.gap.network_subnet_protected_by_firewall",
    "azure.other.backup_restore_evidence",
    "azure.other.database_backup_alert",
    "azure.other.enumeration_logging",
    "azure.other.nsg_port_protocol_assignment",
    "azure_c5_ops_05_04ac",
    "azure_c5_ops_08_01b",
}


_gcp_native_cases = {}
for _native_case in (json.loads((Path(__file__).parent /
        'fixtures/gcp-native-review-behavior.json').read_text())['cases'] +
        json.loads((Path(__file__).parent / 'fixtures/gcp-alert-native-successor-20261020.json').read_text())['cases'] +
        json.loads((Path(__file__).parent / 'fixtures/gcp-compute-native-successor-20261020.json').read_text())['cases'] +
        json.loads((Path(__file__).parent / 'fixtures/gcp-final-services-native-successor-20261020.json').read_text())['cases'] +
        json.loads((Path(__file__).parent / 'fixtures/gcp-prior-bounded-native-successor-20261020.json').read_text())['cases'] +
        json.loads((Path(__file__).parent / 'fixtures/gcp-native57-native-successor-20261020.json').read_text())['cases']):
    _branch = {'PASS': 'pass', 'FAIL': 'fail', 'UNKNOWN': 'unknown'}[_native_case['expected_status']]
    _current = _gcp_native_cases.setdefault(_native_case['check_id'], {})
    _current.setdefault(_branch, _native_case['item'])
    _current.setdefault(_branch + '_index', _native_case['index'])


@pytest.mark.parametrize("check", CHECKS, ids=lambda c: c.id)
def test_every_check_has_behavior_fixtures(check, request):
    from tests.generic_k8s_behavior_successors_20261020 import (
        WORKLOAD, JOB_IMAGE, current_cases as native_successor_cases, dependency_state,
        assert_workload_native_behavior)
    if check.id == WORKLOAD:
        # This signed native addition deliberately has no fabricated CASES row.
        # Exercise its real SDK clean/empty tests and captured FAIL instead.
        assert_workload_native_behavior(check, request.getfixturevalue('monkeypatch'))
    else:
        assert check.id in CASES or check.id == JOB_IMAGE, "registered checks cannot claim support without fixtures"
    # Keep the historical release fixtures intact. Current behavior uses the
    # complete native producer cases after the customer/ancestor binding fixes.
    cases = _gcp_native_cases.get(check.id, CASES.get(check.id, {}))
    if check.provider == 'azure':
        from tests.azure_native_successor_inputs_20261020 import current_cases
        cases = current_cases(check.id, cases)
    cases = native_successor_cases(check, cases)
    index = cases.get("index", {})
    source_bound_unknown_fails = {
        # An unbound HTTP probe does not establish ownership or bucket existence.
        "aws.c2b.cloudfront.s3_origin_bucket_exists",
        "aws.claude_a.networkfirewall.in_vpc",
        "aws.c2b.ecs.container_instance_in_vpc",
        "aws.c2b.eks.cluster_security_group_present",
        "aws.c2b.backup.vault_encrypted",
        "aws.a.iam.console_key_created_at_setup",
    }
    for name, expected in (("pass", "PASS"), ("fail", "FAIL"), ("manual", "MANUAL"), ("unknown", "UNKNOWN")):
        if name in cases:
            if name == "fail" and cases.get("fail_expect") is not None:
                assert check.id in source_bound_unknown_fails
                assert cases["fail_expect"] == "UNKNOWN"
                expected = "UNKNOWN"
            if (name == "pass" and check.id in STALE_PASS_CASES) or \
                    (name == "fail" and check.id in STALE_FAIL_CASES):
                expected = "UNKNOWN"
            data = copy.deepcopy(cases[name])
            before = copy.deepcopy(data)
            state_index = cases.get(name + "_index", cases.get("case_indices", {}).get(name, index))
            scoped = copy.deepcopy(state_index)
            before_index = dependency_state(check.id, scoped)
            assert check.evaluate(data, scoped)[0] == expected
            assert data == before, "evaluators must not mutate native snapshot facts"
            assert dependency_state(check.id, scoped) == before_index, "evaluators must not mutate scoped dependency facts"
    assert check.evaluate(cases.get("missing", {}), index)[0] == "UNKNOWN"
    assert check.evaluate(cases.get("malformed", None), index)[0] == "UNKNOWN"
    # The age-aware current-role evaluator preserves an explicit native denial.
    # Other predicates retain their existing UNKNOWN contract for this shape.
    denied_status = "DENIED" if check.id == "aws.claude_a.iam.role_used_within_60_days" else "UNKNOWN"
    assert check.evaluate({"collection_status": "denied"}, index)[0] == denied_status
    from peaso.checks.hacktricks_scope import includes
    assert (HACKTRICKS in check.frameworks) == includes(check.id)


@pytest.mark.parametrize('field', ['snapshot', 'expected', 'scope', 'identity', 'collections'])
def test_package_dependency_comparison_detects_owner_or_fact_mutation(field):
    from peaso import azure_function_package_index_20261020 as owner
    from tests.generic_k8s_behavior_successors_20261020 import PACKAGE, dependency_state
    index = copy.deepcopy(CASES[PACKAGE]['pass_index'])
    before = dependency_state(PACKAGE, index)
    admitted = index[owner.INDEX_KEY]
    if field == 'snapshot':
        admitted.snapshot['provider'] = 'foreign'
    elif field == 'expected':
        admitted.expected['provider'] = 'foreign'
    elif field == 'scope':
        admitted.scope += '/foreign'
    elif field == 'identity':
        index[owner.INDEX_KEY] = copy.deepcopy(admitted)
    else:
        index['collections'].clear()
    assert dependency_state(PACKAGE, index) != before


@pytest.mark.parametrize("check", CHECKS, ids=lambda c: c.id)
@pytest.mark.parametrize("collection_status,expected", [("denied", "DENIED"), ("unknown", "UNKNOWN"), ("malformed", "UNKNOWN"), ("empty", "EMPTY")])
def test_unavailable_inventory_never_passes(check, collection_status, expected):
    kinds = check.dependencies if check.target == "scope" else [check.kind]
    snapshot = make_snapshot(check.provider, ["test-scope"], [{"type": kind, "scope": "test-scope", "service": "test", "status": collection_status, "items": []} for kind in dict.fromkeys(kinds)])
    report = evaluate_snapshot(snapshot, categories=[check.category], checks=[check.id])
    if collection_status == 'empty':
        from peaso.checks.k8s_kubelet_configmap_admission_20261020 import IDS
        if check.id in IDS:
            from tests.generic_k8s_behavior_successors_20261020 import assert_kubelet_empty_contract
            finding, = report['findings']
            assert_kubelet_empty_contract(check, finding)
            assert 'PASS' not in report['stats']['by_status']
            return
    if check.target == "scope" and collection_status == "empty":
        # A complete empty dependency is evaluated as a reviewed absence fact.
        # Per-rule pass/fail indexes above assert the actual intended predicate.
        assert all(row["status"] != "EMPTY" for row in report["findings"])
        return
    assert report["findings"][0]["status"] == expected
    assert "PASS" not in report["stats"]["by_status"]


def test_partial_inventory_carries_resource_evidence_and_unknown_remainder():
    snapshot = make_snapshot("aws", ["us-east-1"], [{"type": "ebs_volume", "scope": "us-east-1", "status": "partial", "service": "ec2", "items": [{"VolumeId": "vol-a", "Encrypted": True}], "error": {"code": "page_limit"}}])
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=["aws.ebs.encryption"])
    assert report["stats"]["by_status"] == {"PASS": 1, "UNKNOWN": 1}
    assert report["stats"]["coverage_complete"] is False


def test_nested_denied_and_malformed_are_unknown():
    registry = {c.id: c for c in CHECKS}
    assert registry["aws.iam.console_mfa"].evaluate({"LoginProfile": {"collection_status": "denied"}, "MFADevices": []}, {})[0] == "UNKNOWN"
    assert registry["gcp.storage.no_public_iam"].evaluate({"iamPolicy": {"bindings": []}, "_coverage": {"iamPolicy": {"status": "denied"}}}, {})[0] == "UNKNOWN"
    assert registry["aws.cloudtrail.logging"].evaluate({"Status": {"collection_status": "denied", "IsLogging": False}}, {})[0] == "UNKNOWN"
    assert registry["azure.network.restrict_internet_ingress"].evaluate({"properties": {"securityRules": [{}]}}, {})[0] == "UNKNOWN"
    assert registry["aws.iam.restrict_public_trust"].evaluate({"AssumeRolePolicyDocument": {"Statement": [{"Principal": "*"}]}}, {})[0] == "UNKNOWN"


def test_pod_init_ephemeral_inheritance_and_purity():
    registry = {c.id: c for c in CHECKS}
    data = {"spec": {"securityContext": {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}}, "containers": [{"name": "app"}], "initContainers": [{"name": "init"}], "ephemeralContainers": [{"name": "debug", "securityContext": {"runAsUser": 0}}]}}
    before = copy.deepcopy(data)
    assert registry["k8s.pod.non_root"].evaluate(data, {}) == ("FAIL", {"containers_needing_review": ["debug"], "semantics": "Native pod configuration; admission policy and runtime enforcement are separate"})
    assert registry["k8s.pod.seccomp"].evaluate(data, {})[0] == "PASS"
    assert data == before


def test_framework_union_evaluates_predicate_once():
    check = next(c for c in CHECKS if c.id == "aws.ebs.encryption")
    tags = check.frameworks
    snapshot = make_snapshot("aws", ["us-east-1"], [{"type": check.kind, "scope": "us-east-1", "service": "ec2", "status": "collected", "items": [{"VolumeId": "vol-a", "Encrypted": True}]}])
    result = evaluate_snapshot(snapshot, categories=["hardening"], checks=[check.id], frameworks=tags)
    assert len(result["findings"]) == 1
    assert hydrate_frameworks(result)["findings"][0]["frameworks"] == tags


def test_manifest_validator_and_mapping_conservation():
    from peaso.checks import resolve_check_id
    from scripts.peaso_review_catalog import validate_manifest
    from peaso.checks.catalog import manifest
    from tests.compliance_source_conservation import assert_source_frameworks_conserved
    data = manifest()
    stats = validate_manifest(data)
    assert stats["upstream_total"] > stats["native_checks"]
    registry = {c.id: c for c in CHECKS}
    for row in data["checks"]:
        if row["disposition"] in ("ported", "merged"):
            for cid in row["native_checks"]:
                assert resolve_check_id(cid) in registry, (row["check_id"], cid)
                assert_source_frameworks_conserved(row, cid)
        else:
            assert not row["native_checks"]


def test_no_blanket_nist_tags():
    from peaso.checks.catalog import framework_display_names, requirement_tags_for
    check = next(c for c in CHECKS if c.id == "k8s.namespace.restricted_admission")
    signed_tags = requirement_tags_for(check.id)
    display = framework_display_names()
    reviewed = {display[tag["framework_id"]] for tag in signed_tags}
    assert any(tag["framework_id"].startswith("cis_") for tag in signed_tags)
    assert set(check.frameworks) == {HACKTRICKS} | reviewed
    assert not {name for name in check.frameworks if "NIST" in name.upper()} - reviewed


def test_framework_catalog_contains_families_and_preserves_control_tree():
    from peaso.engine import get_catalog
    from peaso.checks.catalog import manifest
    from peaso.checks.catalog import framework_display_names
    names = [f["name"] for f in get_catalog()["frameworks"]]
    # Labels are one canonical display name per framework version (never family slugs or controls).
    assert len(names) < 250
    assert set(names) <= set(framework_display_names().values()) | {HACKTRICKS}
    assert not {"Pod", "Storage", "Account", "Your Data", "All AWS Compliance Controls"}.intersection(names)
    assert not any(name.startswith(("1.2.1.a ", "PR.AC-", "AC-2 ")) for name in names)
    for row in manifest()["checks"]:
        for mapping in row["frameworks"]:
            if row["repository"].startswith("turbot/"):
                assert mapping["framework_id"] in mapping["benchmark_ids"]


def test_current_provider_semantic_exceptions():
    registry = {c.id: c for c in CHECKS}
    assert registry["gcp.gke.network_policy"].evaluate({"networkConfig": {"datapathProvider": "ADVANCED_DATAPATH"}, "networkPolicy": {"enabled": False}}, {})[0] == "PASS"
    assert registry["gcp.gke.network_policy"].evaluate({"networkConfig": {"datapathProvider": "ADVANCED_DATAPATH"}, "_coverage": {"networkConfig": {"status": "denied"}}}, {})[0] == "UNKNOWN"
    assert registry["azure.aks.network_policy"].evaluate({"properties": {"networkProfile": {"networkDataplane": "cilium", "networkPolicy": "none"}}}, {})[0] == "PASS"
    assert registry["azure.storage.minimum_tls"].evaluate({"properties": {"minimumTlsVersion": "TLS1_3"}}, {})[0] == "UNKNOWN"
    assert registry["gcp.storage.public_access_prevention"].evaluate({"iamConfiguration": {"publicAccessPrevention": "unspecified"}}, {})[0] == "UNKNOWN"
    assert registry["aws.iam.root_mfa"].evaluate({"user": "<root_account>", "password_enabled": "false", "access_key_1_active": "false", "access_key_2_active": "false", "mfa_active": "false"}, {})[0] == "NOT_APPLICABLE"


def test_namespace_policy_qualified_scope_cannot_invent_missing_coverage():
    check = next(c for c in CHECKS if c.id == "k8s.network.namespace_policy_inventory")
    native = {"metadata": {"name": "apps"}}
    foreign = {"collections": {"networkpolicy": [{"scope": "cluster/other", "status": "empty"}]}}
    assert check.evaluate(native, foreign)[0] == "UNKNOWN"
    own = {"collections": {"networkpolicy": [{"scope": "cluster/apps", "status": "empty", "items": []}]}}
    assert check.evaluate(native, own)[0] == "FAIL"
    # A status label alone cannot prove the policy inventory was returned.
    missing_items = {"collections": {"networkpolicy": [{"scope": "cluster/apps", "status": "empty"}]}}
    assert check.evaluate(native, missing_items)[0] == "UNKNOWN"


def test_specific_framework_versions_preserve_ids_and_pending_status():
    from peaso.checks.catalog import framework_catalog
    versions = framework_catalog()
    assert len({entry["id"] for entry in versions}) == len(versions)
    assert {entry["status"] for entry in versions} <= {"pending", "partially_supported", "supported", "out_of_scope"}
    assert any(entry["status"] == "partially_supported" for entry in versions)
    for entry in versions:
        assert entry["id"] and entry["version"] and entry["source_revision"]
        assert entry["supported_native_checks"] == len(entry["native_check_ids"])
        if entry["status"] in ("pending", "out_of_scope"):
            assert entry["supported_native_checks"] == 0
        if entry["status"] == "out_of_scope":
            assert entry["provider"] not in ("aws", "gcp", "azure", "k8s")
    check = next(c for c in CHECKS if c.id == "aws.ebs.encryption")
    assert check.framework_ids
    available = {entry["id"] for entry in versions}
    assert set(check.framework_ids).issubset(available)


def test_engine_accepts_specific_checklist_id_and_marks_unported_controls():
    from peaso.checks.catalog import framework_catalog
    check = next(c for c in CHECKS if c.id == "aws.ebs.encryption")
    versions = framework_catalog()
    specific = next((row for row in versions if row["id"] in check.framework_ids and row["pending_source_checks"]), None)
    if specific is None:
        # Every in-scope source reference is reviewed, so no checklist carries unported controls any more.
        assert not any(row["pending_source_checks"] for row in versions if row["provider"] in ("aws", "gcp", "azure", "k8s"))
        specific = next(row for row in versions if row["id"] in check.framework_ids and len(row["native_check_ids"]) > 1)
    snapshot = make_snapshot("aws", ["us-east-1"], [{"type": "ebs_volume", "scope": "us-east-1", "service": "ec2", "status": "collected", "items": [{"VolumeId": "vol-a", "Encrypted": True}]}])
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=[check.id], frameworks=[specific["id"]])
    assert sum(row["status"] == "PASS" for row in report["findings"]) == 1
    assert report["stats"]["coverage_complete"] is (not specific["pending_source_checks"])
    assert report["framework_versions"][0]["id"] == specific["id"]


def test_runtime_catalog_does_not_load_pending_audit_definitions(monkeypatch):
    import peaso.checks.catalog as catalog_module
    from peaso.engine import get_catalog
    def unexpected_audit_read():
        raise AssertionError("runtime path inflated the audit manifest")
    monkeypatch.setattr(catalog_module, "manifest", unexpected_audit_read)
    catalog_module._runtime.cache_clear()
    catalog_module._mappings.cache_clear()
    result = get_catalog()
    assert result["checks"]
    assert result["upstream_coverage"]["runtime_scope_upstream_total"] == 5846
    assert result["manual_requirements"] == []
    assert catalog_module.manual_requirements()  # Retained source references, outside scan scope.
