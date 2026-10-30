"""Isolated signed Azure contracts. Run this file alone with --noconftest."""
from __future__ import annotations

import base64
import copy
import hashlib
import importlib
import json

import pytest

from peaso.checks import CHECKS
from tests.compliance_draft_isolation import staged_registry

_prior_checks = tuple(CHECKS)
with staged_registry(("compliance_new_sw23",)):
    sw = importlib.import_module("peaso.checks.compliance_new_sw23")
# Keep the candidate's evaluator references and restore every runtime object,
# including IDs temporarily replaced by the isolated registrar sandbox.
CHECKS[:] = _prior_checks

SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
ACCOUNT = SCOPE + "/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/logs"
SERVICE = SCOPE + "/resourceGroups/rg/providers/Microsoft.ApiManagement/service/gateway"
CONTAINER = ACCOUNT + "/blobServices/default/containers/logs"
API = SERVICE + "/apis/orders"
NOW = "2026-10-12T12:00:00+00:00"
START = "2026-10-12T11:00:00+00:00"
CONTENT = base64.b64encode(b"immutable log bytes").decode()
HASH = hashlib.sha256(b"immutable log bytes").hexdigest()
KEY_URI = "https://approved.vault.azure.net/keys/archive/1234567890abcdef"


def children(rows):
    return {"collection_status": "collected" if rows else "empty", "items": rows}


def container(**values):
    return {"id": CONTAINER, **values}


def retention(*, present=True, state="Locked", days=90):
    return {"read_complete": True, "inheritance_resolved": True, "present": present,
            "properties": {"state": state, "immutabilityPeriodSinceCreationInDays": days}}


def lifecycle_rule(*, name="delete", prefixes=None, days=30, tags=None, target="baseBlob"):
    age = "daysAfterModificationGreaterThan" if target == "baseBlob" else "daysAfterCreationGreaterThan"
    return {"name": name, "type": "Lifecycle", "enabled": True,
            "definition": {"filters": {"blobTypes": ["blockBlob"],
                "prefixMatch": ["logs/"] if prefixes is None else prefixes,
                "blobIndexMatch": [] if tags is None else tags},
                "actions": {target: {"delete": {age: days}}}}}


def management(rules):
    return {"read_complete": True, "properties": {"policy": {"rules": rules}}}


def api(**values):
    return {"id": API, "properties": {"type": "http", "protocols": ["https"]}, **values}


@pytest.fixture(scope="module")
def signing_key():
    from cryptography.hazmat.primitives.asymmetric import rsa
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def signed_container(key, *, completeness=True):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    public = key.public_key()
    numbers = public.public_numbers()

    def encode(value):
        return base64.urlsafe_b64encode(value.to_bytes((value.bit_length() + 7) // 8, "big")).decode().rstrip("=")

    payload = {"container_id": CONTAINER, "window_start": START, "window_end": NOW,
               "entries": [{"blobName": "event-1", "versionId": "v1", "sequence": 1, "sha256": HASH}]}
    if not completeness:
        payload.pop("window_start")
        payload.pop("window_end")
        payload["entries"][0].pop("sequence")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    signature = key.sign(canonical, padding.PKCS1v15(), hashes.SHA256())
    fingerprint = hashlib.sha256(public.public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    return container(listing_complete=True, point_in_time_consistent=True, manifest_generation_complete=True,
        manifest={"payload": payload, "kid": KEY_URI, "algorithm": "RS256",
                  "signature_base64": base64.b64encode(signature).decode()},
        trusted_key={"kid": KEY_URI, "pinned_spki_sha256": fingerprint,
                     "jwk": {"kty": "RSA", "kid": KEY_URI, "n": encode(numbers.n), "e": encode(numbers.e)}},
        blobs=children([{"blobName": "event-1", "versionId": "v1", "content_base64": CONTENT,
                         "read_complete": True, "version_consistent": True}]),
        baseline={"independently_established": True, "complete": True, "window_start": START,
                  "window_end": NOW, "expected_sequences": [1]})



def backup_validation(export, *, usable=True, tested_at=None):
    restore = export["restore"]
    tested_at = tested_at or restore["tested_at"]
    bound = {"scope_id": SCOPE.casefold(), "resource_id": SERVICE.casefold(),
             "artifact_uri": export["artifact"]["uri"], "artifact_sha256": export["artifact"]["sha256"],
             "export_completed_at": export["completed_at"], "tested_at": tested_at,
             "source_id": "approved-offline-restore-ledger", "method": "isolated-config-parse"}
    report = {**bound, "restored_resource_id": SERVICE.casefold(), "usable": usable,
              "recovered_configuration_sha256": HASH}
    raw = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    return {**bound, "_provenance": {"source_operation": "ExternalRestoreValidation_Read",
                "source_id": bound["source_id"], "representation": "full", "read_only": True,
                "captured_at": NOW, "observed_at": NOW},
            "result_artifact": {"uri": "https://approved.example/restore/results/one", "read_complete": True,
                "content_base64": base64.b64encode(raw).decode(), "sha256": hashlib.sha256(raw).hexdigest()}}


def siem_bindings(ev):
    ev["approved_delivery_source_id"] = "approved-siem-delivery-ledger"
    ev["approved_hash_source_id"] = "approved-siem-hash-audit"
    for container_row in ev["containers"]["items"]:
        source = container_row["source_event_ids"]
        destination = container_row["destination_event_ids"]
        digest = lambda values: hashlib.sha256(json.dumps(sorted(values), separators=(",", ":"),
            ensure_ascii=False).encode()).hexdigest()
        container_row["observation"] = {"account_id": ACCOUNT.casefold(),
            "container_id": container_row["id"].casefold(), "window_start": ev["window_start"],
            "window_end": ev["window_end"], "source_count": container_row["source_count"],
            "destination_count": container_row["destination_count"],
            "source_event_ids_sha256": digest(source),
            "destination_event_ids_sha256": digest(destination),
            "clock_synchronized": container_row["clock_synchronized"],
            "_provenance": {"source_operation": "ExternalSiemObservation_Read",
                "source_id": ev["approved_delivery_source_id"], "read_only": True,
                "complete": True, "captured_at": NOW, "observed_at": NOW}}
        for record in container_row["hash_records"]["items"]:
            record.update(container_id=container_row["id"].casefold(),
                window_start=ev["window_start"], window_end=ev["window_end"],
                source_event_id=record["event_id"], destination_event_id=record["event_id"],
                _provenance={"source_operation": "ExternalSiemHashComparison_Read",
                    "source_id": ev["approved_hash_source_id"], "read_only": True,
                    "captured_at": NOW, "observed_at": NOW})

def fixture(cid, signing_key=None):
    row = {"id": SERVICE if sw.SPECS[cid]["resource_kind"] == "api_management" else ACCOUNT,
           "properties": {"sasPolicy": {"sasExpirationPeriod": "00.01:00:00", "expirationAction": "Block"}},
           "_provenance": {"representation": "full", "source_operation": "get"}}
    if cid == sw.SAS:
        ev = {"issuer_inventory_complete": True, "service_exceptions_resolved": True,
              "stored_policies_resolved": True, "tokens": children([{
                  "issuance_id": "issuer-1", "account_id": ACCOUNT, "kind": "service",
                  "validity_resolved": True, "exception_resolved": True, "active": True,
                  "effective_start": "2026-10-12T11:30:00+00:00", "effective_expiry": "2026-10-12T12:30:00+00:00"}])}
    elif cid == sw.AUDIT:
        ev = {"audit_scope_authoritative": True, "category_support_resolved": True,
              "observation_complete": True, "is_audit_account": True,
              "events": children([{"operation": op, "source_account_id": ACCOUNT,
                  "delivery_measured": True, "sink_identity_resolved": True, "sink_security_measured": True,
                  "captured": True, "delivered": True, "sink": {"id": ACCOUNT + "-separate",
                      "approved": True, "retention_verified": True, "access_controls_verified": True}}
                  for op in ("read", "write", "delete")])}
    elif cid == sw.UNIFORM:
        ev = {"sas_issuance_authoritative": True, "permission_semantics_resolved": True,
              "hns_acls_complete": True, "containers": children([container(allowed_permissions=["reader:read"],
                  objects=children([{"name": "event-1", "all_sas_grants_resolved": True,
                      "effective_acl_resolved": True, "effective_permissions": ["reader:read"]}]))])}
    elif cid == sw.BACKUP:
        ev = {"required_inventory_authoritative": True, "manifest_complete": True, "retention_measured": True,
              "policy": {"maximum_age_hours": 24, "retention_days": 30, "restore_interval_days": 30,
                         "approved_restore_validation_source_id": "approved-offline-restore-ledger",
                         "approved_restore_validation_method": "isolated-config-parse"},
              "required_resources": children([{"id": SERVICE}]), "exports": children([{
                  "resource_id": SERVICE, "successful": True, "completed_at": START,
                  "artifact": {"uri": "https://logs.blob.core.windows.net/backups/config", "read_complete": True,
                      "content_base64": CONTENT, "sha256": HASH, "retained_until": "2027-01-01T12:00:00+00:00"},
                  "restore": {"tested_at": NOW, "successful": True, "artifact_sha256": HASH}}])}
        export = ev["exports"]["items"][0]
        export["restore"]["validation"] = backup_validation(export)
    elif cid in (sw.INTEGRITY, sw.COMPLETENESS):
        ev = {"protected_scope_authoritative": True,
              "containers": children([signed_container(signing_key, completeness=cid == sw.COMPLETENESS)])}
    elif cid == sw.GEO:
        ev = {"classified_inventory_complete": True, "all_storage_and_processing_services_covered": True,
              "region_mapping_resolved": True, "policy_inheritance_resolved": True,
              "approved_eu_regions": ["westeurope", "northeurope"], "customer_data_resources": children([
                  {"id": ACCOUNT, "primary_replica_processing_locations_complete": True,
                   "restriction_policy_measured": True, "locations": ["westeurope", "northeurope"],
                   "effective_restriction_assigned": True, "restriction_compliant": True},
                  {"id": SERVICE, "primary_replica_processing_locations_complete": True,
                   "restriction_policy_measured": True, "locations": ["westeurope"],
                   "effective_restriction_assigned": True, "restriction_compliant": True}])}
    elif cid == sw.LIFECYCLE:
        ev = {"protected_scope_authoritative": True, "version_snapshot_protection_resolved": True,
              "overlap_resolved": True, "management_policy": management([lifecycle_rule()]),
              "protected_prefixes": children([{"prefix": "logs/", "minimum_retention_days": 7,
                                               "maximum_deletion_days": 90}])}
    elif cid == sw.SIEM:
        ev = {"archive_scope_authoritative": True, "observation_window_complete": True,
              "approved_retention_days": 30, "window_start": START, "window_end": NOW,
              "containers": children([container(immutability_policy=retention(), ingestion_inventory_complete=True,
                  delivery_counts_measured=True, clock_sync_measured=True, copy_hash_inventory_complete=True,
                  source_count=1, destination_count=1, clock_synchronized=True,
                  source_event_ids=["event-1"], destination_event_ids=["event-1"],
                  hash_records=children([{"event_id": "event-1", "original_sha256": HASH, "copy_sha256": HASH}]))])}
        siem_bindings(ev)
    elif cid == sw.IMMUTABLE:
        ev = {"account_read_complete": True, "containers": children([container(container_read_complete=True,
              default_version_policy_support_resolved=True, effective_default_policy={**retention(),
                  "new_writes_inherit": True, "source_kind": "container_time",
                  "source_id": CONTAINER + "/immutabilityPolicies/default"})])}
    elif cid == sw.VERSION_LIFECYCLE:
        ev = {"versioning_read_complete": True, "blob_service": {"properties": {"isVersioningEnabled": True}},
              "management_policy": management([lifecycle_rule(target="version")]),
              "containers": children([container(blob_population_complete=True, blob_tags_complete=True,
                  required_scope_authoritative=True, required_objects=children([{
                      "identity": "event-1:v1", "path": "logs/event-1", "kind": "version",
                      "blobType": "blockBlob", "tags": {}}]))])}
    elif cid == sw.KEYS:
        key = {"source": "Microsoft.KeyVault", "key_uri": KEY_URI}
        ev = {"account_key_resolved": True, "encryption_scopes_complete": True,
              "containers": children([container(default_scope_resolved=True, override_use_resolved=True,
                  historical_blob_keys_resolved=True, effective_default_key=key, denyEncryptionScopeOverride=True,
                  permitted_write_keys=children([key]), blobs=children([{"identity": "event-1:v1",
                      "scope_resolved": True, "key_resolved": True, "effective_key": key}]))])}
    elif cid == sw.PROTOCOLS:
        ev = {"revision_coverage_complete": True, "apis": children([api(frozen_protocol_policy={
              "frozen": True, "scope_resolved": True, "expected_endpoint_type": "https",
              "forbidden_protocols": ["http"]})])}
    elif cid == sw.DIAGNOSTICS:
        logger_id = SERVICE + "/loggers/insights"
        ev = {"revision_coverage_complete": True, "apis": children([api(diagnostics=children([{
                  "id": API + "/diagnostics/insights", "properties": {"loggerId": logger_id,
                  "sampling": {"percentage": 100}, "alwaysLog": None}}]))]),
              "loggers": children([{"id": logger_id, "properties": {"loggerType": "applicationInsights"},
                  "credentials_measured": True, "usable": True}])}
    elif cid == sw.WAF:
        ev = {"revision_coverage_complete": True, "apis": children([api()]),
              "service_get_complete": True, "gateway_hostnames_complete": True, "dns_complete": True,
              "alternate_endpoints_complete": True, "origin_restrictions_resolved": True,
              "route_matching_complete": True, "gateway_hostnames": ["gateway.azure-api.net"],
              "direct_ingress_blocked": True, "reachable_paths": children([{
                  "path_id": "orders-native", "api_id": API, "hostname": "gateway.azure-api.net",
                  "dns_origin_route_chain_measured": True, "all_matching_routes_resolved": True,
                  "reachability_measured": True, "reachable": True, "direct_apim_ingress": False,
                  "waf": {"effective_policy_measured": True, "attached": True,
                      "enabled": True, "mode": "Prevention"}}])}
    else:
        raise AssertionError(cid)
    return row, ev


def index(cid, row, ev):
    kind = sw.SPECS[cid]["resource_kind"]
    evidence_kind = sw.EVIDENCE_KINDS[cid]
    fact = {"id": row["id"] + "/complianceEvidence/sw23", "parent_id": row["id"],
            "_provenance": {"schema_version": 1, "read_only": True, "policy_approved": True,
                            "complete": True, "captured_at": NOW}, "payload": ev}
    groups = {kind: [row], evidence_kind: [fact]}
    return {"context": {"provider": "azure", "scope": SCOPE, "created_at": NOW},
            "collections": {kind: [{"type": kind, "scope": SCOPE, "status": "collected", "items": rows}]
                            for kind, rows in groups.items()},
            **{kind: [{"type": kind, "scope": SCOPE, "data": item} for item in rows]
               for kind, rows in groups.items()}}


def evaluate(cid, row, ev):
    return sw.EVALUATORS[cid](row, index(cid, row, ev))[0]


def make_bad(cid, row, ev):
    c = ev.get("containers", {}).get("items", [{}])[0]
    if cid == sw.SAS:
        ev["tokens"]["items"][0]["effective_start"] = "2026-10-12T10:00:00+00:00"
    elif cid == sw.AUDIT:
        ev["events"]["items"][0]["sink"]["id"] = ACCOUNT
    elif cid == sw.UNIFORM:
        c["objects"]["items"][0]["effective_permissions"] = ["writer:write"]
    elif cid == sw.BACKUP:
        ev["exports"] = children([])
    elif cid in (sw.INTEGRITY, sw.COMPLETENESS):
        c["blobs"] = children([])
    elif cid == sw.GEO:
        ev["customer_data_resources"]["items"][1]["locations"] = ["eastus"]
    elif cid == sw.LIFECYCLE:
        ev["management_policy"]["properties"]["policy"]["rules"].append(lifecycle_rule(name="early", days=1))
    elif cid == sw.SIEM:
        c["immutability_policy"]["properties"]["state"] = "Unlocked"
    elif cid == sw.IMMUTABLE:
        c["effective_default_policy"]["present"] = False
    elif cid == sw.VERSION_LIFECYCLE:
        ev["management_policy"] = management([])
    elif cid == sw.KEYS:
        c["blobs"]["items"][0]["effective_key"] = {"source": "Microsoft.Storage"}
    elif cid == sw.PROTOCOLS:
        ev["apis"]["items"][0]["properties"]["protocols"] = ["http"]
    elif cid == sw.DIAGNOSTICS:
        ev["apis"]["items"][0]["diagnostics"] = children([])
    elif cid == sw.WAF:
        ev["reachable_paths"]["items"][0]["direct_apim_ingress"] = True
        ev["direct_ingress_blocked"] = False


@pytest.mark.parametrize("cid", sw.IDS)
def test_pass_fail(cid, signing_key):
    row, ev = fixture(cid, signing_key)
    assert evaluate(cid, row, ev) == "PASS"
    make_bad(cid, row, ev)
    assert evaluate(cid, row, ev) == "FAIL"


@pytest.mark.parametrize("cid", sw.IDS)
def test_missing_fact(cid, signing_key):
    row, ev = fixture(cid, signing_key)
    facts = index(cid, row, ev)
    del facts["collections"][sw.EVIDENCE_KINDS[cid]]
    assert sw.EVALUATORS[cid](row, facts)[0] == "UNKNOWN"
    assert evaluate(cid, row, {}) == "UNKNOWN"


@pytest.mark.parametrize("cid", sw.IDS)
def test_incomplete_inventory(cid, signing_key):
    row, ev = fixture(cid, signing_key)
    make_bad(cid, row, ev)
    for kind in (sw.SPECS[cid]["resource_kind"], sw.EVIDENCE_KINDS[cid]):
        for status in ("partial", "denied", "not_collected"):
            facts = index(cid, row, ev)
            facts["collections"][kind][0]["status"] = status
            assert sw.EVALUATORS[cid](row, facts)[0] == "UNKNOWN"


@pytest.mark.parametrize("cid", sw.IDS)
def test_malformed_and_coverage(cid, signing_key):
    row, ev = fixture(cid, signing_key)
    facts = index(cid, row, ev)
    fact = facts[sw.EVIDENCE_KINDS[cid]][0]["data"]
    fact["_provenance"]["schema_version"] = True
    assert sw.EVALUATORS[cid](row, facts)[0] == "UNKNOWN"
    fact["_provenance"]["schema_version"] = 1
    fact["_coverage"] = {"payload": {"status": "denied"}}
    assert sw.EVALUATORS[cid](row, facts)[0] == "UNKNOWN"
    fact.pop("_coverage")
    fact["payload"] = []
    assert sw.EVALUATORS[cid](row, facts)[0] == "UNKNOWN"
    assert sw.EVALUATORS[cid]({}, facts)[0] == "UNKNOWN"


@pytest.mark.parametrize("cid", sw.IDS)
def test_foreign_scope_duplicate_and_projection(cid, signing_key):
    row, ev = fixture(cid, signing_key)
    for mutate in (
        lambda facts: facts["context"].update(provider="aws"),
        lambda facts: facts["context"].update(scope=SCOPE.replace("1111", "2222")),
        lambda facts: facts["collections"][sw.EVIDENCE_KINDS[cid]][0].update(scope=ACCOUNT),
        lambda facts: facts[sw.EVIDENCE_KINDS[cid]][0].update(scope=ACCOUNT),
        lambda facts: facts[sw.EVIDENCE_KINDS[cid]][0]["data"].update(parent_id=ACCOUNT + "-foreign"),
        lambda facts: facts[sw.EVIDENCE_KINDS[cid]][0]["data"]["_provenance"].update(captured_at=START),
    ):
        facts = index(cid, row, copy.deepcopy(ev))
        mutate(facts)
        assert sw.EVALUATORS[cid](row, facts)[0] == "UNKNOWN"
    facts = index(cid, row, ev)
    kind = sw.EVIDENCE_KINDS[cid]
    facts[kind].append(copy.deepcopy(facts[kind][0]))
    facts["collections"][kind][0]["items"].append(copy.deepcopy(facts[kind][0]["data"]))
    assert sw.EVALUATORS[cid](row, facts)[0] == "UNKNOWN"
    facts = index(cid, row, ev)
    facts["collections"][kind][0]["items"] = []
    assert sw.EVALUATORS[cid](row, facts)[0] == "UNKNOWN"


@pytest.mark.parametrize("cid", [cid for cid in sw.IDS if cid != sw.SAS])
def test_not_applicable(cid, signing_key):
    row, ev = fixture(cid, signing_key)
    if cid == sw.AUDIT:
        ev["is_audit_account"] = False
    elif cid == sw.BACKUP:
        ev["required_resources"] = children([])
        ev["empty_scope_approved"] = True
    elif cid == sw.GEO:
        ev["customer_data_resources"] = children([])
        ev["empty_scope_approved"] = True
    elif cid == sw.LIFECYCLE:
        ev["protected_prefixes"] = children([])
    elif cid in (sw.PROTOCOLS, sw.WAF, sw.DIAGNOSTICS):
        ev["apis"] = children([])
    else:
        ev["containers"] = children([])
    assert evaluate(cid, row, ev) == "NOT_APPLICABLE"


def test_sas_enforcement_defaults_actual_issued_interval_and_unresolved_tokens():
    row, ev = fixture(sw.SAS)
    row["properties"]["sasPolicy"].pop("expirationAction")
    assert evaluate(sw.SAS, row, {}) == "FAIL"  # full GET, documented Log default
    row["properties"].pop("sasPolicy")
    assert evaluate(sw.SAS, row, {}) == "FAIL"
    row, ev = fixture(sw.SAS)
    row["properties"]["sasPolicy"]["sasExpirationPeriod"] = "00.01:00:01"
    assert evaluate(sw.SAS, row, {}) == "FAIL"
    for value in ("01:00:00", "00.25:00:00", "00.01:60:00", "00.01:00:60", "garbage"):
        row["properties"]["sasPolicy"]["sasExpirationPeriod"] = value
        assert evaluate(sw.SAS, row, ev) == "UNKNOWN"
    row, ev = fixture(sw.SAS)
    row["properties"]["sasPolicy"]["expirationAction"] = "Future"
    assert evaluate(sw.SAS, row, ev) == "UNKNOWN"
    row, ev = fixture(sw.SAS)
    ev["stored_policies_resolved"] = False
    assert evaluate(sw.SAS, row, ev) == "UNKNOWN"
    row, ev = fixture(sw.SAS)
    ev["tokens"]["items"][0]["kind"] = "stored_policy"
    assert evaluate(sw.SAS, row, ev) == "PASS"
    ev["tokens"]["items"][0]["validity_resolved"] = False
    assert evaluate(sw.SAS, row, ev) == "UNKNOWN"


def test_audit_delivery_secure_sink_and_uniform_sas_authority_limits():
    row, ev = fixture(sw.AUDIT)
    ev["events"]["items"][0]["captured"] = False
    assert evaluate(sw.AUDIT, row, ev) == "FAIL"
    row, ev = fixture(sw.AUDIT)
    ev["events"]["items"][0]["delivered"] = False
    assert evaluate(sw.AUDIT, row, ev) == "UNKNOWN"
    ev["events"]["items"][0]["delivered"] = True
    ev["events"]["items"][0]["sink"]["retention_verified"] = False
    assert evaluate(sw.AUDIT, row, ev) == "UNKNOWN"
    row, ev = fixture(sw.UNIFORM)
    ev["sas_issuance_authoritative"] = False
    assert evaluate(sw.UNIFORM, row, ev) == "UNKNOWN"
    row, ev = fixture(sw.UNIFORM)
    ev["containers"]["items"][0]["objects"]["collection_status"] = "partial"
    assert evaluate(sw.UNIFORM, row, ev) == "UNKNOWN"


def test_backup_freshness_retention_hash_restore_and_empty_scope():
    for field, value in (("completed_at", "2026-10-10T11:00:00+00:00"), ("successful", False)):
        row, ev = fixture(sw.BACKUP)
        ev["exports"]["items"][0][field] = value
        assert evaluate(sw.BACKUP, row, ev) == "FAIL"
    for category, field, value in (
        ("artifact", "sha256", "0" * 64),
        ("artifact", "retained_until", NOW),
        ("restore", "successful", False),
        ("restore", "tested_at", START),
    ):
        row, ev = fixture(sw.BACKUP)
        export = ev["exports"]["items"][0]
        export[category][field] = value
        if category == "restore" and field == "successful":
            export["restore"]["validation"] = backup_validation(export, usable=False)
        if category == "restore" and field == "tested_at":
            ev["policy"]["restore_interval_days"] = 0.01
            export["restore"]["validation"] = backup_validation(export)
        assert evaluate(sw.BACKUP, row, ev) == "FAIL"
    row, ev = fixture(sw.BACKUP)
    ev["exports"]["items"][0]["artifact"]["read_complete"] = False
    assert evaluate(sw.BACKUP, row, ev) == "UNKNOWN"
    ev["required_resources"] = children([])
    ev["empty_scope_approved"] = False
    assert evaluate(sw.BACKUP, row, ev) == "UNKNOWN"


def test_manifest_signature_pin_algorithm_bytes_and_independent_baseline(signing_key):
    for cid in (sw.INTEGRITY, sw.COMPLETENESS):
        row, ev = fixture(cid, signing_key)
        c = ev["containers"]["items"][0]
        c["blobs"]["items"][0]["content_base64"] = base64.b64encode(b"changed").decode()
        assert evaluate(cid, row, ev) == "FAIL"
        c["blobs"]["items"][0]["read_complete"] = False
        assert evaluate(cid, row, ev) == "UNKNOWN"
        row, ev = fixture(cid, signing_key)
        c = ev["containers"]["items"][0]
        c["trusted_key"]["pinned_spki_sha256"] = "0" * 64
        assert evaluate(cid, row, ev) == "UNKNOWN"
        row, ev = fixture(cid, signing_key)
        c = ev["containers"]["items"][0]
        c["manifest"]["algorithm"] = "HS256"
        assert evaluate(cid, row, ev) == "UNKNOWN"
        row, ev = fixture(cid, signing_key)
        c = ev["containers"]["items"][0]
        c["manifest"]["signature_base64"] = base64.b64encode(b"invalid signature").decode()
        assert evaluate(cid, row, ev) == ("FAIL" if cid == sw.INTEGRITY else "UNKNOWN")
    row, ev = fixture(sw.INTEGRITY, signing_key)
    c = ev["containers"]["items"][0]
    c["blobs"]["items"].append({**c["blobs"]["items"][0], "blobName": "extra"})
    assert evaluate(sw.INTEGRITY, row, ev) == "FAIL"
    row, ev = fixture(sw.COMPLETENESS, signing_key)
    c = ev["containers"]["items"][0]
    c["baseline"]["expected_sequences"] = [1, 2]
    assert evaluate(sw.COMPLETENESS, row, ev) == "FAIL"
    c["baseline"]["independently_established"] = False
    assert evaluate(sw.COMPLETENESS, row, ev) == "UNKNOWN"


def test_geo_processing_replicas_policy_and_complete_classification():
    for field, value in (("locations", ["eastus"]), ("effective_restriction_assigned", False),
                         ("restriction_compliant", False)):
        row, ev = fixture(sw.GEO)
        ev["customer_data_resources"]["items"][1][field] = value
        assert evaluate(sw.GEO, row, ev) == "FAIL"
    row, ev = fixture(sw.GEO)
    ev["all_storage_and_processing_services_covered"] = False
    assert evaluate(sw.GEO, row, ev) == "UNKNOWN"
    row, ev = fixture(sw.GEO)
    ev["customer_data_resources"]["items"][0]["primary_replica_processing_locations_complete"] = False
    assert evaluate(sw.GEO, row, ev) == "UNKNOWN"


def test_lifecycle_overlapping_early_delete_narrow_prefix_tags_and_dates():
    row, ev = fixture(sw.LIFECYCLE)
    rules = ev["management_policy"]["properties"]["policy"]["rules"]
    rules.append(lifecycle_rule(name="early-overlap", prefixes=["logs/sub/"], days=1))
    assert evaluate(sw.LIFECYCLE, row, ev) == "FAIL"
    rules[1]["enabled"] = False
    assert evaluate(sw.LIFECYCLE, row, ev) == "PASS"
    rules[1]["enabled"] = True
    rules[1]["definition"]["filters"]["prefixMatch"] = ["other/"]
    assert evaluate(sw.LIFECYCLE, row, ev) == "PASS"
    rules[0]["definition"]["filters"]["prefixMatch"] = ["logs/sub/"]
    assert evaluate(sw.LIFECYCLE, row, ev) == "FAIL"
    rules[0]["definition"]["filters"]["prefixMatch"] = ["logs/"]
    rules[0]["definition"]["filters"]["blobIndexMatch"] = [{"name": "protected", "op": "==", "value": "true"}]
    assert evaluate(sw.LIFECYCLE, row, ev) == "UNKNOWN"
    rules[0]["definition"]["filters"]["blobIndexMatch"] = []
    rules[0]["definition"]["actions"]["baseBlob"]["delete"] = {"daysAfterCreationGreaterThan": 30}
    assert evaluate(sw.LIFECYCLE, row, ev) == "UNKNOWN"


def test_immutability_default_inheritance_positive_period_and_unlocked_predicate():
    row, ev = fixture(sw.IMMUTABLE)
    policy = ev["containers"]["items"][0]["effective_default_policy"]
    policy["properties"]["state"] = "Unlocked"
    assert evaluate(sw.IMMUTABLE, row, ev) == "PASS"  # signed predicate requires positive default, not Locked
    policy["properties"]["immutabilityPeriodSinceCreationInDays"] = 0
    assert evaluate(sw.IMMUTABLE, row, ev) == "FAIL"
    policy["properties"]["immutabilityPeriodSinceCreationInDays"] = 90
    policy["new_writes_inherit"] = False
    assert evaluate(sw.IMMUTABLE, row, ev) == "FAIL"
    policy["inheritance_resolved"] = False
    assert evaluate(sw.IMMUTABLE, row, ev) == "UNKNOWN"


def test_version_lifecycle_case_sensitive_prefix_tags_supported_action_and_population():
    for prefix in ("other/", "Logs/", "logs/sub/"):
        row, ev = fixture(sw.VERSION_LIFECYCLE)
        ev["management_policy"] = management([lifecycle_rule(prefixes=[prefix], target="version")])
        assert evaluate(sw.VERSION_LIFECYCLE, row, ev) == "FAIL"
    row, ev = fixture(sw.VERSION_LIFECYCLE)
    ev["management_policy"] = management([lifecycle_rule(target="version", tags=[{"name": "retention", "op": "==", "value": "required"}])])
    assert evaluate(sw.VERSION_LIFECYCLE, row, ev) == "FAIL"
    ev["containers"]["items"][0]["required_objects"]["items"][0]["tags"] = {"retention": "required"}
    assert evaluate(sw.VERSION_LIFECYCLE, row, ev) == "PASS"
    ev["containers"]["items"][0]["blob_tags_complete"] = False
    assert evaluate(sw.VERSION_LIFECYCLE, row, ev) == "UNKNOWN"
    row, ev = fixture(sw.VERSION_LIFECYCLE)
    ev["management_policy"]["properties"]["policy"]["rules"][0]["definition"]["actions"] = {"version": {"future": {"days": 1}}}
    assert evaluate(sw.VERSION_LIFECYCLE, row, ev) == "UNKNOWN"
    ev["blob_service"]["properties"]["isVersioningEnabled"] = False
    assert evaluate(sw.VERSION_LIFECYCLE, row, ev) == "NOT_APPLICABLE"


def test_keyvault_default_cannot_mask_historical_blob_or_permitted_overrides():
    row, ev = fixture(sw.KEYS)
    c = ev["containers"]["items"][0]
    c["blobs"]["items"][0]["effective_key"] = {"source": "Microsoft.Storage"}
    assert evaluate(sw.KEYS, row, ev) == "FAIL"
    c["historical_blob_keys_resolved"] = False
    assert evaluate(sw.KEYS, row, ev) == "UNKNOWN"
    row, ev = fixture(sw.KEYS)
    c = ev["containers"]["items"][0]
    c["denyEncryptionScopeOverride"] = False
    c["permitted_write_keys"]["items"].append({"source": "Microsoft.Storage"})
    assert evaluate(sw.KEYS, row, ev) == "UNKNOWN"
    c["effective_default_key"] = {"source": "Microsoft.Storage"}
    c["denyEncryptionScopeOverride"] = True
    c["permitted_write_keys"] = children([{"source": "Microsoft.Storage"}])
    assert evaluate(sw.KEYS, row, ev) == "FAIL"


def test_siem_locked_retention_delivery_clock_and_hash_conjunction():
    for field, value in (("source_count", 2), ("clock_synchronized", False)):
        row, ev = fixture(sw.SIEM)
        ev["containers"]["items"][0][field] = value
        if field == "source_count":
            ev["containers"]["items"][0]["source_event_ids"].append("event-missing")
        siem_bindings(ev)
        assert evaluate(sw.SIEM, row, ev) == "FAIL"
    row, ev = fixture(sw.SIEM)
    c = ev["containers"]["items"][0]
    c["hash_records"]["items"][0]["copy_sha256"] = "0" * 64
    assert evaluate(sw.SIEM, row, ev) == "FAIL"
    c["copy_hash_inventory_complete"] = False
    assert evaluate(sw.SIEM, row, ev) == "UNKNOWN"


def test_siem_equal_counts_do_not_mask_missing_source_event():
    row, ev = fixture(sw.SIEM)
    c = ev["containers"]["items"][0]
    c["source_event_ids"] = ["event-missing"]
    siem_bindings(ev)
    assert evaluate(sw.SIEM, row, ev) == "FAIL"
    c["source_count"] = 2
    siem_bindings(ev)
    assert evaluate(sw.SIEM, row, ev) == "UNKNOWN"


def test_apim_protocols_rule_parameter_enum_and_empty_pages():
    row, ev = fixture(sw.PROTOCOLS)
    a = ev["apis"]["items"][0]
    a["properties"]["protocols"] = ["https", "http"]
    assert evaluate(sw.PROTOCOLS, row, ev) == "FAIL"
    a["properties"]["protocols"] = ["grpc"]
    assert evaluate(sw.PROTOCOLS, row, ev) == "UNKNOWN"
    a["properties"]["protocols"] = ["https"]
    a["frozen_protocol_policy"]["expected_endpoint_type"] = "grpc"
    assert evaluate(sw.PROTOCOLS, row, ev) == "UNKNOWN"
    a.pop("frozen_protocol_policy")
    assert evaluate(sw.PROTOCOLS, row, ev) == "UNKNOWN"


def test_apim_traces_logger_join_sampling_alwayslog_and_credentials():
    row, ev = fixture(sw.DIAGNOSTICS)
    props = ev["apis"]["items"][0]["diagnostics"]["items"][0]["properties"]
    props["sampling"]["percentage"] = 0
    assert evaluate(sw.DIAGNOSTICS, row, ev) == "FAIL"
    props["alwaysLog"] = "allErrors"
    assert evaluate(sw.DIAGNOSTICS, row, ev) == "PASS"
    ev["loggers"]["items"][0]["usable"] = False
    assert evaluate(sw.DIAGNOSTICS, row, ev) == "FAIL"
    ev["loggers"]["items"][0]["credentials_measured"] = False
    assert evaluate(sw.DIAGNOSTICS, row, ev) == "UNKNOWN"
    row, ev = fixture(sw.DIAGNOSTICS)
    ev["loggers"] = children([])
    assert evaluate(sw.DIAGNOSTICS, row, ev) == "FAIL"
    row, ev = fixture(sw.DIAGNOSTICS)
    ev["apis"]["items"][0]["diagnostics"]["collection_status"] = "partial"
    assert evaluate(sw.DIAGNOSTICS, row, ev) == "UNKNOWN"


def test_odata_rest_diagnostics_and_nonrest_scope():
    row, ev = fixture(sw.DIAGNOSTICS)
    ev["apis"]["items"][0]["properties"]["type"] = "odata"
    assert evaluate(sw.DIAGNOSTICS, row, ev) == "PASS"
    ev["apis"]["items"][0]["diagnostics"] = children([])
    assert evaluate(sw.DIAGNOSTICS, row, ev) == "FAIL"
    ev["apis"]["items"][0]["properties"]["type"] = "grpc"
    assert evaluate(sw.DIAGNOSTICS, row, ev) == "NOT_APPLICABLE"


def test_default_immutable_inherited_scope_and_native_integer_period():
    row, ev = fixture(sw.IMMUTABLE)
    policy = ev["containers"]["items"][0]["effective_default_policy"]
    policy.update(source_kind="account_version_default", source_id=ACCOUNT)
    assert evaluate(sw.IMMUTABLE, row, ev) == "PASS"
    policy["source_id"] = ACCOUNT + "-foreign"
    assert evaluate(sw.IMMUTABLE, row, ev) == "UNKNOWN"
    policy["source_id"] = ACCOUNT
    policy["properties"]["immutabilityPeriodSinceCreationInDays"] = 90.5
    assert evaluate(sw.IMMUTABLE, row, ev) == "UNKNOWN"


@pytest.mark.parametrize("cid", sw.IDS)
def test_denied_child_fields_cannot_be_hidden_by_absence_or_failure(cid, signing_key):
    row, ev = fixture(cid, signing_key)
    make_bad(cid, row, ev)
    ev["_coverage"] = {"unreadable_child": {"status": "denied"}}
    assert evaluate(cid, row, ev) == "UNKNOWN"


def test_native_delete_age_is_integer_and_append_blob_cannot_tier():
    row, ev = fixture(sw.LIFECYCLE)
    ev["management_policy"] = management([lifecycle_rule(days=1.5)])
    assert evaluate(sw.LIFECYCLE, row, ev) == "UNKNOWN"
    row, ev = fixture(sw.VERSION_LIFECYCLE)
    rule = lifecycle_rule(target="version")
    rule["definition"]["filters"]["blobTypes"] = ["appendBlob"]
    rule["definition"]["actions"] = {"version": {"tierToCool": {"daysAfterCreationGreaterThan": 30}}}
    ev["management_policy"] = management([rule])
    ev["containers"]["items"][0]["required_objects"]["items"][0]["blobType"] = "appendBlob"
    assert evaluate(sw.VERSION_LIFECYCLE, row, ev) == "FAIL"


def test_waf_detection_custom_hostname_direct_path_and_unmeasured_dns():
    row, ev = fixture(sw.WAF)
    ev["reachable_paths"]["items"][0]["waf"]["mode"] = "Detection"
    assert evaluate(sw.WAF, row, ev) == "FAIL"
    ev["dns_complete"] = False
    assert evaluate(sw.WAF, row, ev) == "UNKNOWN"
    row, ev = fixture(sw.WAF)
    ev["gateway_hostnames"].append("custom.example.com")
    assert evaluate(sw.WAF, row, ev) == "UNKNOWN"
    alternate = copy.deepcopy(ev["reachable_paths"]["items"][0])
    alternate.update(path_id="orders-custom", hostname="custom.example.com", direct_apim_ingress=True)
    ev["reachable_paths"]["items"].append(alternate)
    assert evaluate(sw.WAF, row, ev) == "FAIL"
    row, ev = fixture(sw.WAF)
    ev["direct_ingress_blocked"] = False
    assert evaluate(sw.WAF, row, ev) == "UNKNOWN"


@pytest.mark.parametrize("cid", sw.IDS)
def test_evaluation_is_immutable(cid, signing_key):
    row, ev = fixture(cid, signing_key)
    facts = index(cid, row, ev)
    original = copy.deepcopy((row, facts))
    assert sw.EVALUATORS[cid](row, facts)[0] == "PASS"
    assert sw.EVALUATORS[cid](row, facts)[0] == "PASS"
    assert (row, facts) == original


def test_backup_bare_restore_boolean_is_not_validation():
    row, evidence = fixture(sw.BACKUP)
    evidence["exports"]["items"][0]["restore"].pop("validation")
    assert evaluate(sw.BACKUP, row, evidence) == "UNKNOWN"


def test_backup_independent_restored_configuration_result_passes():
    row, evidence = fixture(sw.BACKUP)
    assert evaluate(sw.BACKUP, row, evidence) == "PASS"


@pytest.mark.parametrize("mutation", [
    "foreign_scope", "foreign_resource", "different_artifact", "wrong_method",
    "wrong_source", "future_observation", "altered_result", "duplicate_result_field",
    "missing_approval",
])
def test_backup_unbound_or_unapproved_validation_is_unknown(mutation):
    row, evidence = fixture(sw.BACKUP)
    export = evidence["exports"]["items"][0]
    validation = export["restore"]["validation"]
    if mutation == "foreign_scope":
        validation["scope_id"] = "/subscriptions/22222222-2222-2222-2222-222222222222"
    elif mutation == "foreign_resource":
        validation["resource_id"] = ACCOUNT.casefold()
    elif mutation == "different_artifact":
        validation["artifact_sha256"] = "0" * 64
    elif mutation == "wrong_method":
        validation["method"] = "unapproved-method"
    elif mutation == "wrong_source":
        validation["_provenance"]["source_id"] = "foreign-ledger"
    elif mutation == "future_observation":
        validation["_provenance"]["observed_at"] = "2026-10-13T12:00:00+00:00"
    elif mutation == "altered_result":
        validation["result_artifact"]["sha256"] = "0" * 64
    elif mutation == "duplicate_result_field":
        result = validation["result_artifact"]
        raw = base64.b64decode(result["content_base64"])
        raw = raw[:-1] + b',"usable":true}'
        result["content_base64"] = base64.b64encode(raw).decode()
        result["sha256"] = hashlib.sha256(raw).hexdigest()
    else:
        evidence["policy"].pop("approved_restore_validation_source_id")
    assert evaluate(sw.BACKUP, row, evidence) == "UNKNOWN"


def test_backup_independently_measured_unusable_restore_fails():
    row, evidence = fixture(sw.BACKUP)
    export = evidence["exports"]["items"][0]
    export["restore"]["successful"] = False
    export["restore"]["validation"] = backup_validation(export, usable=False)
    assert evaluate(sw.BACKUP, row, evidence) == "FAIL"


def test_backup_measured_corrupt_export_precedes_missing_restore_validation():
    row, evidence = fixture(sw.BACKUP)
    export = evidence["exports"]["items"][0]
    export["artifact"]["sha256"] = "0" * 64
    export["restore"].pop("validation")
    assert evaluate(sw.BACKUP, row, evidence) == "FAIL"


def test_siem_foreign_hash_record_cannot_prove_this_window():
    row, ev = fixture(sw.SIEM)
    record = ev["containers"]["items"][0]["hash_records"]["items"][0]
    record["window_start"] = "2026-10-11T11:00:00+00:00"
    record["window_end"] = "2026-10-11T12:00:00+00:00"
    record["container_id"] = ACCOUNT + "/blobServices/default/containers/other"
    assert evaluate(sw.SIEM, row, ev) == "UNKNOWN"


def test_siem_measured_tamper_survives_other_container_missing_hash_inventory():
    row, ev = fixture(sw.SIEM)
    first = ev["containers"]["items"][0]
    first["hash_records"]["items"][0]["copy_sha256"] = "0" * 64
    second = copy.deepcopy(first)
    second["id"] = ACCOUNT + "/blobServices/default/containers/other"
    second["copy_hash_inventory_complete"] = False
    ev["containers"]["items"].append(second)
    assert evaluate(sw.SIEM, row, ev) == "FAIL"


@pytest.mark.parametrize("mutation", [
    "missing_delivery_approval", "foreign_observation_container", "wrong_observation_window",
    "wrong_source_identity_digest", "stale_observation_capture", "wrong_hash_source_event",
    "foreign_hash_container", "future_hash_observation",
])
def test_siem_external_observation_binding_is_required(mutation):
    row, ev = fixture(sw.SIEM)
    c = ev["containers"]["items"][0]
    observation = c["observation"]
    record = c["hash_records"]["items"][0]
    if mutation == "missing_delivery_approval":
        ev.pop("approved_delivery_source_id")
    elif mutation == "foreign_observation_container":
        observation["container_id"] = ACCOUNT + "/blobServices/default/containers/other"
    elif mutation == "wrong_observation_window":
        observation["window_start"] = "2026-10-11T11:00:00+00:00"
    elif mutation == "wrong_source_identity_digest":
        observation["source_event_ids_sha256"] = "0" * 64
    elif mutation == "stale_observation_capture":
        observation["_provenance"]["captured_at"] = START
    elif mutation == "wrong_hash_source_event":
        record["source_event_id"] = "another-event"
    elif mutation == "foreign_hash_container":
        record["container_id"] = ACCOUNT + "/blobServices/default/containers/other"
    else:
        record["_provenance"]["observed_at"] = "2026-10-13T12:00:00+00:00"
    assert evaluate(sw.SIEM, row, ev) == "UNKNOWN"


def test_siem_known_unlocked_archive_fails_with_other_archive_unresolved():
    row, ev = fixture(sw.SIEM)
    first = ev["containers"]["items"][0]
    first["immutability_policy"]["properties"]["state"] = "Unlocked"
    second = copy.deepcopy(first)
    second["id"] = ACCOUNT + "/blobServices/default/containers/other"
    second["immutability_policy"]["read_complete"] = False
    ev["containers"]["items"].append(second)
    assert evaluate(sw.SIEM, row, ev) == "FAIL"


def test_siem_measured_tamper_survives_other_partial_hash_collection():
    row, ev = fixture(sw.SIEM)
    first = ev["containers"]["items"][0]
    first["hash_records"]["items"][0]["copy_sha256"] = "0" * 64
    second = copy.deepcopy(first)
    second["id"] = ACCOUNT + "/blobServices/default/containers/other"
    second["hash_records"]["collection_status"] = "partial"
    ev["containers"]["items"].append(second)
    assert evaluate(sw.SIEM, row, ev) == "FAIL"


# Scoped external APIM diagnostic precedence; all inputs are inert fixtures.
def _evaluate(row, evidence):
    # The isolated staged registrar exposes the same signed registered callback.
    return sw.EVALUATORS[sw.DIAGNOSTICS](row, index(sw.DIAGNOSTICS, row, evidence))


def _unknown_logger(evidence):
    logger = evidence["loggers"]["items"][0]
    logger["credentials_measured"] = False
    logger.pop("usable")


@pytest.mark.parametrize("missing_first", [True, False])
def test_missing_diagnostic_beats_peer_unknown_logger(missing_first):
    row, evidence = fixture(sw.DIAGNOSTICS)
    _unknown_logger(evidence)
    missing = copy.deepcopy(evidence["apis"]["items"][0])
    missing["id"] = SERVICE + "/apis/missing"
    missing["diagnostics"] = children([])
    peer = evidence["apis"]["items"][0]
    evidence["apis"] = children([missing, peer] if missing_first else [peer, missing])
    status, detail = _evaluate(row, evidence)
    assert status == "FAIL"
    assert detail["rest_apis_without_usable_tracing_diagnostic"] == [missing["id"]]


def test_missing_diagnostic_ignores_unused_unmeasured_logger():
    row, evidence = fixture(sw.DIAGNOSTICS)
    evidence["apis"]["items"][0]["diagnostics"] = children([])
    _unknown_logger(evidence)
    assert _evaluate(row, evidence)[0] == "FAIL"


@pytest.mark.parametrize("mode,expected", [
    ("referenced_unknown", "UNKNOWN"),
    ("unknown_sampling", "UNKNOWN"),
    ("absent_logger", "FAIL"),
    ("disabled_trace", "FAIL"),
    ("usable_with_unused_unknown", "PASS"),
])
def test_candidate_three_valued_results(mode, expected):
    row, evidence = fixture(sw.DIAGNOSTICS)
    diagnostic = evidence["apis"]["items"][0]["diagnostics"]["items"][0]
    if mode == "referenced_unknown":
        _unknown_logger(evidence)
    elif mode == "unknown_sampling":
        diagnostic["properties"]["sampling"].pop("percentage")
    elif mode == "absent_logger":
        diagnostic["properties"]["loggerId"] = SERVICE + "/loggers/deleted"
        _unknown_logger(evidence)
    elif mode == "disabled_trace":
        diagnostic["properties"]["sampling"]["percentage"] = 0
        _unknown_logger(evidence)
    else:
        extra = copy.deepcopy(evidence["loggers"]["items"][0])
        extra["id"] = SERVICE + "/loggers/unused"
        extra["credentials_measured"] = False
        extra.pop("usable")
        evidence["loggers"]["items"].append(extra)
    assert _evaluate(row, evidence)[0] == expected


@pytest.mark.parametrize("mode", ["foreign_api", "duplicate_api", "foreign_logger",
    "duplicate_logger", "foreign_diagnostic", "duplicate_diagnostic", "foreign_reference"])
def test_invalid_identity_stays_unknown_even_with_missing_diagnostic(mode):
    row, evidence = fixture(sw.DIAGNOSTICS)
    original = evidence["apis"]["items"][0]
    missing = copy.deepcopy(original)
    missing["id"] = SERVICE + "/apis/missing"
    missing["diagnostics"] = children([])
    evidence["apis"]["items"].append(missing)
    diagnostic = original["diagnostics"]["items"][0]
    if mode == "foreign_api":
        original["id"] = SERVICE + "-other/apis/orders"
    elif mode == "duplicate_api":
        missing["id"] = original["id"]
    elif mode == "foreign_logger":
        evidence["loggers"]["items"][0]["id"] = SERVICE + "-other/loggers/insights"
    elif mode == "duplicate_logger":
        evidence["loggers"]["items"].append(copy.deepcopy(evidence["loggers"]["items"][0]))
    elif mode == "foreign_diagnostic":
        diagnostic["id"] = SERVICE + "/apis/other/diagnostics/insights"
    elif mode == "duplicate_diagnostic":
        original["diagnostics"]["items"].append(copy.deepcopy(diagnostic))
    else:
        diagnostic["properties"]["loggerId"] = SERVICE + "-other/loggers/insights"
    assert _evaluate(row, evidence)[0] == "UNKNOWN"
