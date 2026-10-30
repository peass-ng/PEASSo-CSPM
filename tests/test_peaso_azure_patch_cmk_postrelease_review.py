# Historical fixture contracts; current native admission is tested separately.
"""Inert registered-runtime regression probes for Azure PCI patch evidence binding."""

from copy import deepcopy

import pytest

from peaso.collectors import azure, collect_live
from tests.archived_check_contract import evaluate_snapshot, plan_collection
from peaso.snapshot import make_snapshot
from tests.test_peaso_azure_patch_installation_hosted_pipeline import (
    CHECK, OPERATION, SCOPE, VM, NativeAPI, options,
)


class AlteredPatchAPI(NativeAPI):
    def request(self, url, *, body=None, audience=None):
        if "/instanceView?" in url and self.mode == "denied_installation_view":
            self.calls.append((url, deepcopy(body)))
            raise azure.AzureReadError("fixture_denied", 403)
        response = super().request(url, body=body, audience=audience)
        if "/instanceView?" in url:
            patch = response["patchStatus"]
            if self.mode == "missing_installation_summary":
                patch.pop("lastPatchInstallationSummary")
            elif self.mode == "partial_installation_summary":
                patch["lastPatchInstallationSummary"].pop("installationActivityId")
            elif self.mode == "assessment_before_installation":
                patch["availablePatchSummary"]["lastModifiedTime"] = self.times[0]
        return response


def pci_finding(monkeypatch, *, mode="complete", record_operation=OPERATION,
                record_status="COMPLIANT", require_actual=False, native_result_mode="complete",
                actual_coverage=None, vm_provenance_marker=None):
    # The approved native read and PCI record share one inert scan capture.
    api_mode = native_result_mode if native_result_mode in ("missing_result", "denied") else mode
    api = AlteredPatchAPI(api_mode)
    monkeypatch.setattr(azure, "AzureTransportExposure", lambda auth: api)
    config = options()
    config["compliance_policy"]["checks"][CHECK]["requirePciCompliance"] = True
    config["compliance_policy"]["checks"][CHECK]["requireActualInstallation"] = require_actual
    if actual_coverage is not None:
        config["compliance_policy"]["checks"][CHECK]["_coverage"] = {
            "requireActualInstallation": actual_coverage}
    connector = {"provider": "azure", "scopes": [SCOPE],
                 "auth": {"method": "token", "arm_token": "inert"}, "options": config}
    snapshot = collect_live(
        connector, plan_collection({"connector": connector, "checks": [CHECK]}),
    )
    metadata = deepcopy(snapshot["metadata"])
    observed_at = snapshot["created_at"]
    capture = {field: metadata[field] for field in
               ("credential_context_id", "customer_context_id")}
    record = {
        "id": VM + "/providers/Microsoft.ComplianceEvidence/patch/evidence",
        "vm_id": VM, "operationId": record_operation,
        "installedAt": api.times[1], "status": record_status,
        "_provenance": {"read_only": True,
                        "source_operation": "ExternalPatchCompliance_Read",
                        "observed_at": observed_at, **capture},
    }
    collections = [deepcopy(c) for c in snapshot["collections"]
                   if c["type"] != "vm_patch_installation_compliance"]
    collections.append({
        "type": "vm_patch_installation_compliance", "scope": SCOPE,
        "service": "external", "status": "collected", "items": [record],
        "_provenance": capture,
    })
    if native_result_mode == "mismatched":
        result = next(c for c in collections if c["type"] == "vm_patch_installation_result")
        result["items"][0]["properties"]["installationActivityId"] = "other-operation"
    elif native_result_mode == "installed_zero":
        vm = next(c for c in collections if c["type"] == "vm")["items"][0]
        vm["instanceView"]["patchStatus"]["lastPatchInstallationSummary"]["installedPatchCount"] = 0
        result = next(c for c in collections if c["type"] == "vm_patch_installation_result")
        result["items"][0]["properties"]["installedPatchCount"] = 0
    elif native_result_mode == "reboot_pending":
        vm = next(c for c in collections if c["type"] == "vm")["items"][0]
        vm["instanceView"]["patchStatus"]["availablePatchSummary"]["rebootPending"] = True
    if vm_provenance_marker is not None:
        vm = next(c for c in collections if c["type"] == "vm")["items"][0]
        vm.setdefault("_coverage", {})["_provenance"] = vm_provenance_marker
    evidenced = make_snapshot("azure", [SCOPE], collections, metadata=metadata,
                              created_at=observed_at)
    finding = next(row for row in evaluate_snapshot(evidenced, checks=[CHECK])["findings"]
                   if row["check_id"] == CHECK)
    return finding, snapshot, api


@pytest.mark.parametrize("record_operation,record_status,expected", [
    (OPERATION, "COMPLIANT", "PASS"),
    (OPERATION, "NON_COMPLIANT", "FAIL"),
    ("older-unrelated-operation", "COMPLIANT", "UNKNOWN"),
    ("older-unrelated-operation", "NON_COMPLIANT", "UNKNOWN"),
])
def test_pci_compliance_must_join_latest_native_vm_operation(
    monkeypatch, record_operation, record_status, expected,
):
    finding, snapshot, _ = pci_finding(
        monkeypatch, record_operation=record_operation, record_status=record_status,
    )
    vm = next(c for c in snapshot["collections"] if c["type"] == "vm")["items"][0]
    latest_operation = vm["instanceView"]["patchStatus"]["lastPatchInstallationSummary"]["installationActivityId"]
    assert latest_operation == OPERATION
    assert finding["status"] == expected, finding


@pytest.mark.parametrize("mode", [
    "missing_installation_summary", "partial_installation_summary",
    "denied_installation_view", "assessment_before_installation",
])
def test_pci_requires_complete_native_operation_and_later_assessment(monkeypatch, mode):
    finding, _, api = pci_finding(monkeypatch, mode=mode)
    assert finding["status"] == "UNKNOWN", finding
    assert any("/instanceView?" in url for url, _ in api.calls)


def test_measured_missing_security_patches_still_fail_before_pci_join(monkeypatch):
    finding, _, _ = pci_finding(
        monkeypatch, mode="missing_patches", record_operation="older-unrelated-operation",
    )
    assert finding["status"] == "FAIL", finding
    assert finding["evidence"]["critical_and_security_patch_count"] == 1


@pytest.mark.parametrize("native_result_mode,expected", [
    ("complete", "PASS"),
    ("missing_result", "UNKNOWN"),
    ("denied", "UNKNOWN"),
    ("mismatched", "UNKNOWN"),
    ("installed_zero", "UNKNOWN"),
    ("reboot_pending", "UNKNOWN"),
])
def test_combined_pci_and_actual_installation_require_both_proofs(
    monkeypatch, native_result_mode, expected,
):
    finding, _, api = pci_finding(
        monkeypatch, require_actual=True, native_result_mode=native_result_mode,
    )
    assert finding["status"] == expected, finding
    arg_calls = [body for _, body in api.calls if isinstance(body, dict)
                 and "patchinstallationresources" in body.get("query", "")]
    assert arg_calls
    if native_result_mode == "complete":
        assert finding["evidence"]["post_installation_status"] == "COMPLIANT"
        assert finding["evidence"]["require_pci_compliance"] is True
        assert finding["evidence"]["native_installation"]["installed_patch_count"] == 2


def test_complete_pci_noncompliance_fails_even_if_actual_result_missing(monkeypatch):
    finding, _, _ = pci_finding(
        monkeypatch, require_actual=True, native_result_mode="missing_result",
        record_status="NON_COMPLIANT",
    )
    assert finding["status"] == "FAIL", finding
    assert finding["evidence"]["post_installation_status"] == "NON_COMPLIANT"


def test_measured_missing_patches_fail_with_both_requirements(monkeypatch):
    finding, _, _ = pci_finding(
        monkeypatch, mode="missing_patches", require_actual=True,
        record_operation="older-unrelated-operation",
    )
    assert finding["status"] == "FAIL", finding
    assert finding["evidence"]["critical_and_security_patch_count"] == 1


@pytest.mark.parametrize("policy_shape,expected_arg_read", [
    ("non_pci_actual", True),
    ("pci_actual", True),
    ("actual_false", False),
    ("actual_malformed", False),
    ("pci_malformed", False),
    ("policy_denied", False),
    ("foreign_scope", False),
    ("policy_missing", False),
])
def test_native_result_approval_gate_preserves_policy_authority(
    monkeypatch, policy_shape, expected_arg_read,
):
    api = AlteredPatchAPI("complete")
    monkeypatch.setattr(azure, "AzureTransportExposure", lambda auth: api)
    config = options()
    policy = config["compliance_policy"]
    review = policy["checks"][CHECK]
    if policy_shape == "pci_actual":
        review["requirePciCompliance"] = True
    elif policy_shape == "actual_false":
        review["requireActualInstallation"] = False
    elif policy_shape == "actual_malformed":
        review["requireActualInstallation"] = "true"
    elif policy_shape == "pci_malformed":
        review["requirePciCompliance"] = 1
    elif policy_shape == "policy_denied":
        policy["status"] = "denied"
    elif policy_shape == "foreign_scope":
        policy["scope"] = "/subscriptions/foreign"
    elif policy_shape == "policy_missing":
        config.pop("compliance_policy")
    connector = {"provider": "azure", "scopes": [SCOPE],
                 "auth": {"method": "token", "arm_token": "inert"}, "options": config}
    collected = collect_live(
        connector, plan_collection({"connector": connector, "checks": [CHECK]}),
    )
    assert any(c["type"] == "vm_patch_installation_result" for c in collected["collections"])
    arg_calls = [body for _, body in api.calls if isinstance(body, dict)
                 and "patchinstallationresources" in body.get("query", "")]
    assert bool(arg_calls) is expected_arg_read


@pytest.mark.parametrize("marker", [
    {"status": "denied"}, {"status": "partial"}, {"status": "unavailable"},
    {"status": "collected"},
])
def test_optional_installation_requirement_honors_field_coverage(monkeypatch, marker):
    finding, _, _ = pci_finding(monkeypatch, require_actual=False, actual_coverage=marker)
    expected = "PASS" if marker["status"] == "collected" else "UNKNOWN"
    assert finding["status"] == expected, finding


@pytest.mark.parametrize("marker", [{"status": "denied"}, {"status": "partial"},
                                  {"status": "collected"}])
def test_patch_capture_provenance_honors_parent_field_coverage(monkeypatch, marker):
    finding, _, _ = pci_finding(monkeypatch, vm_provenance_marker=marker)
    expected = "PASS" if marker["status"] == "collected" else "UNKNOWN"
    assert finding["status"] == expected, finding
