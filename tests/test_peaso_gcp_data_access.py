# Historical archived-check predicate/collector contract; product selection rejects these IDs.
"""Offline historical evaluator proof of the owner-scoped GCP Data Access proposal."""

import copy
import json
import unittest
from pathlib import Path

from peaso.checks import gcp_data_access as native
from peaso.gcp_data_access_policy import OPTION, malformed_direct_principal, normalize_owner_policy
from peaso.checks import CHECKS
from peaso.collectors import gcp
from tests.gcp_archived_native_contract import evaluate_historical_snapshot
from peaso.snapshot import make_snapshot


PROJECT = "projects/fixture"
ORG = "organizations/34"
PRINCIPAL = "user:auditor@example.test"


def config(service, kind, exempt=()):
    return {"service": service, "auditLogConfigs": [{"logType": kind, "exemptedMembers": list(exempt)}]}


def policy(scope, configs=...):
    row = {"name": scope, "_provenance": {"source_requests": ["request:" + scope]}}
    if configs is not ...:
        row["auditConfigs"] = copy.deepcopy(list(configs) if isinstance(configs, tuple) else configs)
    return row


def owner(service, scope=PROJECT, **changes):
    row = {"status": "approved", "scope": scope, "service": service,
           "source_ref": "owner-approved-fixture", "principals": [PRINCIPAL]}
    row.update(changes)
    return row


def report(check_id, *, project=(), organization=(), ancestry=True, owner_rows=...,
           org_available=True, project_status="collected", raw_owner_rows=False):
    service = native.CHECK_SERVICES[check_id]
    collector = gcp.GCPCollector.__new__(gcp.GCPCollector)
    collector.ancestry_source_requests = {}
    collector.needed = {"iam_policy"}
    collector.ancestry = {PROJECT: [{"resourceId": {"type": "organization", "id": "34"}}] if ancestry else []}
    collector.collections = {("iam_policy", PROJECT): {"items": [policy(PROJECT, project)]}}
    if org_available and ancestry:
        collector.collections[("iam_policy", ORG)] = {"items": [policy(ORG, organization)]}
    collector.annotate_effective_audit()
    item = collector.collections[("iam_policy", PROJECT)]["items"][0]
    rows = [owner(service)] if owner_rows is ... else owner_rows
    metadata = ({OPTION: rows if raw_owner_rows else normalize_owner_policy(rows, [PROJECT])}
                if rows is not None else {})
    snapshot = make_snapshot("gcp", [PROJECT], [{"type": "iam_policy", "scope": PROJECT,
        "status": project_status, "items": [item]}], metadata=metadata)
    result = evaluate_historical_snapshot(snapshot, checks=[check_id], categories=["hardening"])
    matches = [finding for finding in result["findings"] if finding["check_id"] == check_id
               and not finding["resource_id"].startswith("inventory:")]
    assert len(matches) == 1
    return matches[0], snapshot


class NativeIntakeTests(unittest.TestCase):
    def test_registered_spec_fields_match_signed_entries_and_companion(self):
        registered = {check.id: check for check in CHECKS
                      if check.id in native.CHECK_SERVICES}
        self.assertEqual(set(registered), set(native.CHECK_SERVICES))
        for check_id, check in registered.items():
            self.assertEqual((check.provider, check.category, check.kind, check.severity, check.control),
                             ("gcp", "hardening", "iam_policy", "medium", "AU-2"))

    def test_complete_inherited_service_and_allservices_union_passes_both_ids(self):
        for check_id, service in native.CHECK_SERVICES.items():
            with self.subTest(check_id=check_id):
                finding, snapshot = report(check_id, project=[config(service, "DATA_WRITE")],
                    organization=[config("allServices", "DATA_READ")])
                self.assertEqual(finding["status"], "PASS")
                self.assertEqual(finding["evidence"]["enabled_types"], ["DATA_READ", "DATA_WRITE"])
                self.assertEqual(finding["evidence"]["principal_source_ref"], "owner-approved-fixture")
                self.assertEqual(finding["evidence"]["source_requests"], ["request:" + ORG, "request:" + PROJECT])
                self.assertEqual(snapshot["metadata"][OPTION][0]["service"], service)
                self.assertIn("log delivery and method coverage unverified", finding["evidence"]["claim"])

    def test_complete_missing_type_fails_both_ids(self):
        for check_id, service in native.CHECK_SERVICES.items():
            with self.subTest(check_id=check_id):
                finding, _ = report(check_id, organization=[config(service, "DATA_READ")])
                self.assertEqual(finding["status"], "FAIL")
                self.assertEqual(finding["evidence"]["missing_types"], ["DATA_WRITE"])

    def test_ancestor_exemption_cannot_be_cancelled_by_project_service(self):
        for check_id, service in native.CHECK_SERVICES.items():
            with self.subTest(check_id=check_id):
                finding, _ = report(check_id, project=[config(service, "DATA_READ"), config(service, "DATA_WRITE")],
                    organization=[config("allServices", "DATA_READ", [PRINCIPAL])])
                self.assertEqual(finding["status"], "FAIL")
                self.assertEqual(finding["evidence"]["exempted_required"], [PRINCIPAL])

    def test_missing_or_foreign_owner_policy_is_unknown(self):
        check_id = "gcp_pci_iam_policy_ca1281da7ab2"
        service = native.CHECK_SERVICES[check_id]
        configured = [config(service, "DATA_READ"), config(service, "DATA_WRITE")]
        for rows in (None, [], [owner("pubsub.googleapis.com")],
                     [owner(service, source_ref="")]):
            with self.subTest(rows=rows):
                if rows and rows[0]["source_ref"] == "":
                    with self.assertRaises(ValueError):
                        normalize_owner_policy(rows, [PROJECT])
                else:
                    finding, _ = report(check_id, project=configured, owner_rows=rows)
                    self.assertEqual(finding["status"], "UNKNOWN")

    def test_denied_or_malformed_ancestor_is_unknown_even_with_project_types(self):
        check_id = "gcp_pci_iam_policy_ca1281da7ab2"
        service = native.CHECK_SERVICES[check_id]
        configured = [config(service, "DATA_READ"), config(service, "DATA_WRITE")]
        denied, _ = report(check_id, project=configured, org_available=False)
        malformed, snapshot = report(check_id, project=configured, organization={"bad": "shape"})
        self.assertEqual(denied["status"], "UNKNOWN")
        self.assertEqual(malformed["status"], "UNKNOWN")
        item = snapshot["collections"][0]["items"][0]
        self.assertEqual(item["effectiveAuditConfigs"][1]["auditConfigs"], {"bad": "shape"})
        self.assertEqual(item["_coverage"]["effectiveAuditConfigs"]["malformed_scopes"], [ORG])

    def test_partial_project_collection_is_unknown(self):
        check_id = "gcp_pci_iam_policy_9a8ce875703d"
        service = native.CHECK_SERVICES[check_id]
        finding, _ = report(check_id, project=[config(service, "DATA_READ"), config(service, "DATA_WRITE")],
                            project_status="partial")
        self.assertEqual(finding["status"], "UNKNOWN")

    def test_ambiguous_group_exemption_is_unknown(self):
        check_id = "gcp_pci_iam_policy_9a8ce875703d"
        service = native.CHECK_SERVICES[check_id]
        finding, _ = report(check_id, project=[config(service, "DATA_READ", ["group:auditors@example.test"]),
            config(service, "DATA_WRITE")])
        self.assertEqual(finding["status"], "UNKNOWN")

    def test_required_group_with_exempted_direct_member_is_unknown_for_both_types_and_ids(self):
        required = "group:team@example.test"
        exempted = "user:alice@example.test"
        for check_id, service in native.CHECK_SERVICES.items():
            for exempted_type in ("DATA_READ", "DATA_WRITE"):
                with self.subTest(check_id=check_id, exempted_type=exempted_type):
                    configs = [config(service, kind, [exempted] if kind == exempted_type else [])
                               for kind in sorted(native.REQUIRED_TYPES)]
                    finding, _ = report(check_id, project=configs,
                        owner_rows=[owner(service, principals=[required])])
                    self.assertEqual(finding["status"], "UNKNOWN")
                    self.assertEqual(finding["evidence"]["unresolved_required_principals"], [required])

    def test_required_group_domain_or_principal_set_needs_membership_proof_even_without_exemptions(self):
        for check_id, service in native.CHECK_SERVICES.items():
            for principal in ("group:team@example.test", "domain:example.test",
                              "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/*"):
                with self.subTest(check_id=check_id, principal=principal):
                    finding, _ = report(check_id, project=[config(service, "DATA_READ"),
                        config(service, "DATA_WRITE")], owner_rows=[owner(service, principals=[principal])])
                    self.assertEqual(finding["status"], "UNKNOWN")
                    self.assertEqual(finding["evidence"]["unresolved_required_principals"], [principal])

    def test_malformed_direct_required_principals_are_rejected_and_never_pass_snapshot(self):
        malformed = ("user:", "serviceAccount:", "user:alice@", "serviceAccount:@example.test",
                     "user:alice example@example.test", "serviceAccount:alice\x00@example.test",
                     "user:alice\u200b@example.test")
        for check_id, service in native.CHECK_SERVICES.items():
            configured = [config(service, "DATA_READ"), config(service, "DATA_WRITE")]
            for principal in malformed:
                with self.subTest(check_id=check_id, principal=principal):
                    self.assertTrue(malformed_direct_principal(principal))
                    owner_row = owner(service, principals=[principal])
                    with self.assertRaises(ValueError):
                        normalize_owner_policy([owner_row], [PROJECT])
                    finding, _ = report(check_id, project=configured, owner_rows=[owner_row],
                                        raw_owner_rows=True)
                    self.assertEqual(finding["status"], "UNKNOWN")

    def test_malformed_direct_exemptions_are_unknown_for_both_signed_services(self):
        for check_id, service in native.CHECK_SERVICES.items():
            for malformed in ("user:", "serviceAccount:", "user:alice@",
                              "serviceAccount:alice\t@example.test"):
                with self.subTest(check_id=check_id, exemption=malformed):
                    finding, _ = report(check_id, project=[config(service, "DATA_READ", [malformed]),
                        config(service, "DATA_WRITE")])
                    self.assertEqual(finding["status"], "UNKNOWN")
                    self.assertEqual(finding["evidence"]["reason"], "malformed exemption list")

    def test_valid_direct_user_and_service_account_keep_complete_pass(self):
        for check_id, service in native.CHECK_SERVICES.items():
            for principal in ("user:alice@example.test",
                              "serviceAccount:collector@project.iam.gserviceaccount.com"):
                with self.subTest(check_id=check_id, principal=principal):
                    self.assertFalse(malformed_direct_principal(principal))
                    finding, _ = report(check_id, project=[config(service, "DATA_READ"),
                        config(service, "DATA_WRITE")], owner_rows=[owner(service, principals=[principal])])
                    self.assertEqual(finding["status"], "PASS")

    def test_known_parentless_empty_policy_fails_only_with_approved_owner_input(self):
        check_id = "gcp_pci_iam_policy_ca1281da7ab2"
        finding, _ = report(check_id, ancestry=False, project=())
        self.assertEqual(finding["status"], "FAIL")
        finding, _ = report(check_id, ancestry=False, project=(), owner_rows=None)
        self.assertEqual(finding["status"], "UNKNOWN")

    def test_policy_intake_rejects_duplicate_foreign_and_unapproved_declarations(self):
        base = owner("spanner.googleapis.com")
        for rows in ([base, base], [owner("spanner.googleapis.com", scope="projects/foreign")],
                     [owner("spanner.googleapis.com", status="draft")],
                     [owner("spanner.googleapis.com", principals=[])],
                     [owner("storage.googleapis.com")]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                normalize_owner_policy(rows, [PROJECT])


if __name__ == "__main__":
    unittest.main()
