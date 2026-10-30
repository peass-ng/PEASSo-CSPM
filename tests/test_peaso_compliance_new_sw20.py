"""Isolated tests for all fifteen signed Azure sw20 predicates."""
from __future__ import annotations

import base64
import copy
import importlib
from datetime import datetime, timedelta, timezone
from functools import lru_cache

import pytest

import peaso.checks as registry

_before = list(registry.CHECKS)
try:
    sw = importlib.import_module("peaso.checks.compliance_new_sw20")
    LOCAL = {c.id: c for c in registry.CHECKS if c.id in sw.IDS}
finally:
    registry.CHECKS[:] = _before

SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
FOREIGN = "/subscriptions/22222222-2222-2222-2222-222222222222"
NOW = datetime(2026, 10, 12, 12, tzinfo=timezone.utc)
STAMP = NOW.isoformat()
VMSS = SCOPE + "/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/vmss"
GW = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/gw"
DCR = SCOPE + "/resourceGroups/rg/providers/Microsoft.Insights/dataCollectionRules/dcr"
VAULT = SCOPE + "/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault"
ALERT = SCOPE + "/resourceGroups/rg/providers/Microsoft.Insights/scheduledQueryRules/flood"
WORKSPACE = SCOPE + "/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/logs"
PURVIEW = SCOPE + "/resourceGroups/rg/providers/Microsoft.Purview/accounts/catalog"
TENANT = "tenant-1"


def provenance(operation, **kwargs):
    return {"source_operation": operation, "read_only": True, **kwargs}


def resolved(*fields):
    return {"resolution": {field: "complete" for field in fields}, "source_evidence_ids": ["evidence-1"]}


def detail(parent, operation, rows):
    return {"parent_id": parent, "collection_status": "collected" if rows else "empty",
            "items": rows, "_provenance": provenance(operation)}


def native(rid, typ, **fields):
    return {"id": rid, "type": typ, **fields}


def external(rid, **fields):
    return {"id": rid, "subscription_id": SCOPE, **fields}


def policy():
    return {"status": "collected", "scope": SCOPE, "observed_at": STAMP, "max_age_seconds": 86400,
            "parameters": {"upgradeEligibilityMaxAgeSeconds": 3600,
                "requiredOsVulnerabilityAssessmentKeys": ["os-key"], "assessmentMaxAgeSeconds": 3600,
                "endpointProtectionAssessmentKey": "endpoint-key", "endpointProtectionMaxAgeSeconds": 3600,
                "requiredManagementSignInContexts": ["browser", "cli"], "mfaAuthenticationStrengthIds": ["mfa-strength"],
                "identityEvidenceMaxAgeSeconds": 3600, "federationLookbackDays": 30,
                "approvedFederatedIssuerIds": ["approved-idp"], "federationConfigMaxAgeSeconds": 3600,
                "tlsObservationMaxAgeSeconds": 3600, "approvedTlsServiceInventory": ["applicationGateway", "appService"],
                "metricFloodThreshold": 100, "metricFloodWindowSeconds": 60, "approvedMetricWorkspaces": [WORKSPACE],
                "metricEvidenceMaxAgeSeconds": 3600, "streamAuthEvidenceMaxAgeSeconds": 3600,
                "approvedPredefinedSslPolicyName": "AppGwSslPolicy20220101S", "expirationWithinDays": 30,
                "purviewRequiredSources": {PURVIEW: ["source-a"]}, "requiredSensitiveClassificationRules": ["credit-card"],
                "purviewScanRecencySeconds": 86400}}


def scope_coverage(kind, check_id):
    operations = {
        "vault_certificate": ("public_tls_universe_inventory_read", ["exposedPorts", "activeBindings", "pagination"]),
        "application_gateway_and_frontdoor": ("gateway_frontdoor_inventory_read", ["applicationGateways", "classicFrontDoors", "exposedHostnames", "pagination"]),
        "key_vault_certificate": ("vault_current_certificate_inventory_read", ["vaults", "certificatePages", "currentVersions"]),
        "data_collection_rule": ("metric_source_universe_inventory_read", ["customMetricSources", "pagination"]) if check_id == sw.RATE else
            ("stream_universe_inventory_read", ["metricTraceTypes", "pagination"])}
    if kind not in operations:
        return None
    operation, fields = operations[kind]
    return {"scope": SCOPE, "_provenance": provenance(operation), **resolved(*fields),
            "covered_services": ["applicationGateway", "appService"]}


def index(data, check_id):
    output = {"context": {"provider": "azure", "scope": SCOPE, "created_at": STAMP,
                         "metadata": {"tenant_id": TENANT, "compliance_policy": policy()}}, "collections": {}}
    for kind, rows in data.items():
        envelope = {"type": kind, "scope": SCOPE, "status": "collected" if rows else "empty", "items": rows}
        coverage = scope_coverage(kind, check_id)
        if coverage:
            envelope["scopeCoverage"] = coverage
        if kind == "entra_user" and check_id == sw.MFA:
            envelope["scopeCoverage"] = {
                "scope": SCOPE, "managedTenantId": TENANT, "delegatedTenantIds": [],
                "principal_ids": [row["id"] for row in rows], "observed_at": STAMP,
                "_provenance": provenance("subscription_effective_principal_universe_read"),
                **resolved("directRoleAssignments", "inheritedGrants", "transitiveGroups", "activePim",
                    "conditionalGrants", "lighthouseDelegations", "managedApplicationAccess", "principalClassification")}
        output["collections"][kind] = [envelope]
        output[kind] = [{"type": kind, "scope": SCOPE, "data": row} for row in rows]
    return output


def evaluate(check_id, idx):
    return LOCAL[check_id].evaluate(idx["context"], idx)


def user():
    return external("user-1", tenant_id=TENANT, human=True, accountEnabled=True,
                    source_subject_id="subject-1", source_idp_id="approved-idp", domain_name="example.org")


def assessment(key, category, code="Healthy"):
    return native(VMSS + "/providers/Microsoft.Security/assessments/" + key, "Microsoft.Security/assessments",
                  name=key, properties={"resourceDetails": {"id": VMSS}, "status": {"code": code}},
                  observed_at=STAMP, assessmentMetadata={"key": key, "category": category,
                    "resource_type": "Microsoft.Compute/virtualMachineScaleSets", "_provenance": provenance("assessment_metadata_get")})


@lru_cache(maxsize=3)
def certificate_der(bits):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    from cryptography.x509.oid import NameOID
    private = ec.generate_private_key(ec.SECP256R1()) if bits == "ec" else rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.org")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(private.public_key()).serial_number(1)
            .not_valid_before(NOW - timedelta(days=1)).not_valid_after(NOW + timedelta(days=100)).sign(private, hashes.SHA256()))
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


def current_certificate(bits=2048):
    return native(VAULT + "/certificates/cert", "Microsoft.KeyVault/vaults/certificates", parent_id=VAULT,
        name="cert", vault_uri="https://vault.vault.azure.net", currentCertificate={
            "id": "https://vault.vault.azure.net/certificates/cert/version-1", "cer": certificate_der(bits),
            "attributes": {"enabled": True, "exp": int((NOW + timedelta(days=100)).timestamp())},
            "_provenance": provenance("certificates_get_current", request_uri="https://vault.vault.azure.net/certificates/cert", representation="full")})


def build(check_id, bad=False):
    data = {}
    if check_id == sw.UPGRADE:
        image = {"publisher": "MicrosoftWindowsServer", "offer": "WindowsServer", "sku": "2022-datacenter", "version": "latest"}
        row = native(VMSS, "Microsoft.Compute/virtualMachineScaleSets", properties={
            "virtualMachineProfile": {"storageProfile": {"imageReference": image}},
            "upgradePolicy": {"mode": "Rolling", "automaticOSUpgradePolicy": {"enableAutomaticOSUpgrade": not bad}}},
            automaticOSUpgradeEligibility={"resource_id": VMSS, "imageReference": image, "upgradeMode": "Rolling",
                "supported": True, "basis": "documented platform image capability", "observed_at": STAMP,
                "_provenance": provenance("platform_image_upgrade_capability")})
        data = {"vm_scale_set": [row]}
    elif check_id in {sw.ENDPOINT, sw.VULNERABILITY}:
        row = native(VMSS, "Microsoft.Compute/virtualMachineScaleSets")
        if check_id == sw.ENDPOINT:
            iid = VMSS + "/virtualMachines/0"
            row["instances"] = detail(VMSS, "virtual_machine_scale_set_vms_list", [{"id": iid,
                "endpointProtection": {"resource_id": iid, "applicable": True, "installed": not bad,
                    "observed_at": STAMP, "_provenance": provenance("endpoint_agent_health_read")}}])
            data = {"vm_scale_set": [row], "security_assessment": [assessment("endpoint-key", "endpoint-protection")]}
        else:
            data = {"vm_scale_set": [row], "security_assessment": [assessment("os-key", "os-vulnerability", "Unhealthy" if bad else "Healthy")]}
    elif check_id == sw.MFA:
        row = user()
        row["effectiveSubscriptionGrants"] = {"subscription_id": SCOPE, "principal_id": row["id"], "privileges": ["read"],
            "observed_at": STAMP, "_provenance": provenance("effective_subscription_authorization_read"),
            **resolved("roleAssignments", "roleDefinitions", "inheritedGrants", "transitiveGroups", "activePim", "conditions")}
        decisions = [{"context_id": ctx, "principal_id": row["id"], "subscription_id": SCOPE, "observed_at": STAMP,
            **resolved("conditionalAccess", "conditions", "exclusions", "securityDefaults", "authenticationStrengths"),
            "allowed_paths": [{"required_controls": [] if bad and ctx == "cli" else ["mfa"], "required_authentication_strength_ids": []}]}
            for ctx in ("browser", "cli")]
        row["managementSignInDecisions"] = detail(row["id"], "effective_management_signin_policy_read", decisions)
        data = {"entra_user": [row]}
    elif check_id == sw.DISABLED:
        row = user()
        row["accountEnabled"] = bad
        row["cloudAccessRemoval"] = {"principal_id": row["id"], "identity_active": bad, "effective_policies_active": False,
            "observed_at": STAMP, "identity_inactive_at": (NOW - timedelta(hours=30)).isoformat(),
            "effective_policies_inactive_at": (NOW - timedelta(hours=28)).isoformat(),
            "_provenance": provenance("cloud_identity_access_history_read"),
            **resolved("identityMapping", "usersAndDeletedItems", "directoryRoles", "armRoles", "transitiveGroups", "cloudPolicies", "auditHistory")}
        event = external("event-1", event_type="disable", event_time=(NOW - timedelta(hours=36)).isoformat(),
            source_subject_id="subject-1", source_idp_id="approved-idp", _provenance=provenance("authoritative_idp_identity_events"))
        data = {"entra_user": [row], "idp_identity_event": [event]}
    elif check_id == sw.FEDERATED:
        row = user()
        event = {"id": "signin-1", "userId": row["id"], "createdDateTime": STAMP, "correlationId": "correlation-1", "status": {"errorCode": 0}}
        history = external("history-1", user_id=row["id"], retained_from=(NOW - timedelta(days=30)).isoformat(), retained_until=STAMP,
            _provenance=provenance("correlated_signin_idp_history_read"), **resolved("signInPages", "idpPages", "humanClassification", "stableCorrelation"),
            signIns=[event], authenticationEvidence=[{"signInId": event["id"], "userId": row["id"], "correlationId": event["correlationId"],
                "event_time": STAMP, "issuer_id": "other-idp" if bad else "approved-idp", "authentication_kind": "direct" if bad else "federated",
                "_provenance": provenance("documented_authentication_issuer_evidence")}])
        domain = external("domain-1", domain_name="example.org", authenticationType="Federated", issuer_id="approved-idp",
            observed_at=STAMP, _provenance=provenance("domain_federation_configuration_list"))
        data = {"entra_user": [row], "human_signin_history": [history], "domain_federation": [domain]}
    elif check_id in {sw.ROTATE180, sw.ROTATE90}:
        age = 181 if check_id == sw.ROTATE180 else 91
        row = external("https-endpoint-1", service_type="appService", exposed=True, hostname="example.org", port=443, binding_status="active", thumbprint="thumb-1", serial="serial-1",
            enabled=True, observed_at=STAMP, _provenance=provenance("exposed_tls_endpoint_certificate_observation"))
        issued = external("issuance-1", thumbprint="thumb-1", serial="serial-1", authority="ca_issuance_record",
            issued_at=(NOW - timedelta(days=age if bad else 10)).isoformat(), _provenance=provenance("authoritative_certificate_issuance_read"))
        data = {"vault_certificate": [row], "certificate_issuance": [issued]}
    elif check_id == sw.RATE:
        source = {"id": "source-1", "custom": True, "floodControls": {"source_id": "source-1", "observed_at": STAMP,
            "_provenance": provenance("metric_throttle_alert_telemetry_read"),
            **resolved("rateLimitConfiguration", "alertInventory", "querySemantics", "actionDelivery", "floodTelemetry"),
            "rate_limit_enabled": not bad, "alert_present": True, "threshold": 100, "window_seconds": 60,
            "received_count": 1000, "ingested_count": 100, "alert_id": ALERT, "verified_query": "source-specific verified query",
            "action_group_id": "action-1", "action_reachable": True, "alert_fired": True}}
        row = native(DCR, "Microsoft.Insights/dataCollectionRules", metricSources=detail(DCR, "custom_metric_source_inventory_read", [source]))
        alert = native(ALERT, "Microsoft.Insights/scheduledQueryRules", properties={"enabled": True, "scopes": [WORKSPACE], "windowSize": "PT1M",
            "criteria": {"allOf": [{"query": "source-specific verified query", "threshold": 100, "operator": "GreaterThan"}]}, "actions": {"actionGroups": ["action-1"]}})
        data = {"data_collection_rule": [row], "scheduled_query_rule": [alert]}
    elif check_id == sw.AUTH:
        observations = [{"credential_kind": kind, "stream_name": "metric-a", "endpoint": "https://ingest.example.org", "request_id": "request-" + kind,
            "accepted": kind == "authorized" or bad and kind == "anonymous", "principal_id": "publisher-1", "authorized_stream_types": ["metric-a"] if kind == "authorized" else ["metric-b"]}
            for kind in ("authorized", "anonymous", "wrong_type")]
        stream = {"name": "metric-a", "signal_type": "metric", "authenticationEvidence": {"stream_name": "metric-a", "rule_id": DCR,
            "ingestion_endpoint": "https://ingest.example.org", "observed_at": STAMP, "_provenance": provenance("ingestion_authentication_logs_read"),
            **resolved("streamScope", "credentialTypeMapping", "dataPlaneObservations"), "observations": observations}}
        row = native(DCR, "Microsoft.Insights/dataCollectionRules", streamInventory=detail(DCR, "metric_trace_stream_inventory_read", [stream]))
        data = {"data_collection_rule": [row]}
    elif check_id == sw.HTTPS:
        endpoint = {"hostname": "example.org", "listener_id": GW + "/httpListeners/https", "exposed": True, "https_configured": True,
            "certificate_bound": True, "thumbprint": "thumb-1", **resolved("hostname", "effectiveRouting", "httpsBinding", "certificateMaterial"),
            "tlsObservation": {"hostname": "example.org", "listener_id": GW + "/httpListeners/https", "observed_at": STAMP,
                "_provenance": provenance("tls_handshake_validation_read"), "reachable": True, "thumbprint": "thumb-1", "chain_valid": True,
                "hostname_valid": True, "time_valid": not bad, "handshake_valid": True}}
        row = native(GW, "Microsoft.Network/applicationGateways", exposedEndpoints=detail(GW, "gateway_exposed_endpoint_inventory_read", [endpoint]))
        data = {"application_gateway_and_frontdoor": [row]}
    elif check_id == sw.SSL:
        row = native(GW, "Microsoft.Network/applicationGateways", properties={"httpListeners": [{"id": GW + "/httpListeners/https",
            "properties": {"protocol": "Https", "sslProfile": None}}], "sslProfiles": [],
            "sslPolicy": {"policyType": "Predefined", "policyName": "other-policy" if bad else "AppGwSslPolicy20220101S"}})
        data = {"application_gateway_and_frontdoor": [row]}
    elif check_id in {sw.RSA, sw.EXPIRY}:
        row = current_certificate(1024 if bad and check_id == sw.RSA else 2048)
        if bad and check_id == sw.EXPIRY:
            row["currentCertificate"]["attributes"]["exp"] = int((NOW + timedelta(days=30)).timestamp())
        data = {"key_vault_certificate": [row]}
    elif check_id == sw.PURVIEW:
        source_id = PURVIEW + "/dataSources/source-a"
        scan_id = source_id + "/scans/scan-a"
        scan = {"id": scan_id, "properties": {"enabled": not bad, "recurring": True,
            "schedule": {"recurrence": "Day", "interval": 1, "next_run_at": (NOW + timedelta(hours=12)).isoformat()}},
            "classificationRuleset": {"scan_id": scan_id, "collection_status": "collected", "classification_rules": ["credit-card"],
                "_provenance": provenance("purview_scan_ruleset_read")},
            "runs": detail(scan_id, "purview_scan_history_list", [{"id": "run-1", "status": "Succeeded", "started_at": (NOW - timedelta(hours=2)).isoformat(),
                "completed_at": (NOW - timedelta(hours=1)).isoformat()}])}
        source = {"id": source_id, "name": "source-a", "scans": detail(source_id, "purview_scans_list_by_data_source", [scan])}
        row = native(PURVIEW, "Microsoft.Purview/accounts", accountApplicability={"account_id": PURVIEW, "account_type": "administrator",
            "_provenance": provenance("purview_account_applicability_read")}, dataSources=detail(PURVIEW, "purview_data_sources_list", [source]))
        data = {"purview_account": [row]}
    else:
        raise AssertionError(check_id)
    return index(data, check_id)


@pytest.mark.parametrize("check_id", sw.IDS)
def test_pass_and_positive_fail(check_id):
    assert evaluate(check_id, build(check_id))[0] == "PASS"
    assert evaluate(check_id, build(check_id, bad=True))[0] == "FAIL"


@pytest.mark.parametrize("check_id", sw.IDS)
def test_missing_incomplete_malformed_foreign_facts_unknown(check_id):
    primary = LOCAL[check_id].dependencies[0]
    idx = build(check_id)
    del idx["collections"][primary]
    assert evaluate(check_id, idx)[0] == "UNKNOWN"
    for status in ("partial", "denied", "error", "not_collected"):
        idx = build(check_id, bad=True)
        idx["collections"][primary][0]["status"] = status
        assert evaluate(check_id, idx)[0] == "UNKNOWN"
    idx = build(check_id)
    idx[primary][0]["data"]["id"] = 42
    assert evaluate(check_id, idx)[0] == "UNKNOWN"
    idx = build(check_id)
    idx["collections"][primary][0]["scope"] = FOREIGN
    assert evaluate(check_id, idx)[0] == "UNKNOWN"
    idx = build(check_id)
    idx[primary][0]["scope"] = FOREIGN
    assert evaluate(check_id, idx)[0] == "UNKNOWN"
    idx = build(check_id)
    idx["context"]["provider"] = "aws"
    assert evaluate(check_id, idx)[0] == "UNKNOWN"
    idx = build(check_id)
    subject = dict(idx["context"], scope=FOREIGN)
    assert LOCAL[check_id].evaluate(subject, idx)[0] == "UNKNOWN"
    idx = build(check_id)
    fact_kind = "security_assessment" if check_id == sw.VULNERABILITY else primary
    row = idx[fact_kind][0]["data"]
    for key in list(row):
        if key not in {"id", "subscription_id", "type"}:
            del row[key]
    assert evaluate(check_id, idx)[0] == "UNKNOWN"


@pytest.mark.parametrize("check_id", sw.IDS)
def test_complete_empty_scope(check_id):
    idx = index({kind: [] for kind in LOCAL[check_id].dependencies}, check_id)
    expected = "PASS" if check_id in {sw.ROTATE180, sw.ROTATE90} else "UNKNOWN" if check_id == sw.FEDERATED else "NOT_APPLICABLE"
    assert evaluate(check_id, idx)[0] == expected


def first(idx, kind):
    return idx[kind][0]["data"]


def test_vmss_eligibility_and_fail_before_unknown():
    idx = build(sw.UPGRADE)
    first(idx, "vm_scale_set")["automaticOSUpgradeEligibility"]["supported"] = False
    assert evaluate(sw.UPGRADE, idx)[0] == "NOT_APPLICABLE"
    idx = build(sw.UPGRADE)
    first(idx, "vm_scale_set")["automaticOSUpgradeEligibility"]["imageReference"] = {}
    assert evaluate(sw.UPGRADE, idx)[0] == "UNKNOWN"
    idx = build(sw.UPGRADE, bad=True)
    unresolved = copy.deepcopy(first(idx, "vm_scale_set"))
    unresolved["id"] = VMSS + "-other"
    unresolved.pop("automaticOSUpgradeEligibility")
    idx["collections"]["vm_scale_set"][0]["items"].insert(0, unresolved)
    idx["vm_scale_set"].insert(0, {"type": "vm_scale_set", "scope": SCOPE, "data": unresolved})
    assert evaluate(sw.UPGRADE, idx)[0] == "FAIL"


def test_endpoint_parent_health_not_installation_and_contract():
    idx = build(sw.ENDPOINT)
    row = first(idx, "vm_scale_set")
    row["instances"]["items"][0].pop("endpointProtection")
    assert evaluate(sw.ENDPOINT, idx)[0] == "UNKNOWN"
    fact = first(idx, "security_assessment")
    fact["fullInstanceCoverage"] = {"assessment_id": fact["id"], "covered_instance_ids": [VMSS + "/virtualMachines/0"],
        "confirms_agent_installation": True, "contract_reference": "documented-contract", "observed_at": STAMP,
        "_provenance": provenance("documented_endpoint_assessment_instance_contract")}
    assert evaluate(sw.ENDPOINT, idx)[0] == "PASS"
    fact["fullInstanceCoverage"]["covered_instance_ids"] = []
    assert evaluate(sw.ENDPOINT, idx)[0] == "UNKNOWN"
    idx = build(sw.ENDPOINT)
    first(idx, "security_assessment")["properties"]["status"]["code"] = "Unhealthy"
    assert evaluate(sw.ENDPOINT, idx)[0] == "FAIL"
    idx = build(sw.ENDPOINT)
    agent = first(idx, "vm_scale_set")["instances"]["items"][0]["endpointProtection"]
    agent["applicable"] = False
    assert evaluate(sw.ENDPOINT, idx)[0] == "UNKNOWN"
    agent["not_applicable_reason"] = "independently verified unsupported OS"
    assert evaluate(sw.ENDPOINT, idx)[0] == "NOT_APPLICABLE"


@pytest.mark.parametrize("check_id", [sw.ENDPOINT, sw.VULNERABILITY])
def test_assessment_stale_conflicting_and_wrong_category(check_id):
    for mutation in ("stale", "category", "scope", "duplicate", "unknown_status"):
        idx = build(check_id)
        fact = first(idx, "security_assessment")
        if mutation == "stale":
            fact["observed_at"] = (NOW - timedelta(days=1)).isoformat()
        elif mutation == "category":
            fact["assessmentMetadata"]["category"] = "security-configuration"
        elif mutation == "scope":
            fact["assessmentMetadata"]["resource_type"] = "Microsoft.Compute/virtualMachines"
        elif mutation == "duplicate":
            idx["security_assessment"].append(copy.deepcopy(idx["security_assessment"][0]))
            idx["collections"]["security_assessment"][0]["items"].append(copy.deepcopy(fact))
        else:
            fact["properties"]["status"]["code"] = "future-status"
        assert evaluate(check_id, idx)[0] == "UNKNOWN"


def test_mfa_registration_or_group_gap_never_passes():
    idx = build(sw.MFA)
    row = first(idx, "entra_user")
    row["isMfaRegistered"] = True
    row["effectiveSubscriptionGrants"]["resolution"]["transitiveGroups"] = "missing"
    assert evaluate(sw.MFA, idx)[0] == "UNKNOWN"
    idx = build(sw.MFA)
    row = first(idx, "entra_user")
    row["effectiveSubscriptionGrants"]["privileges"] = []
    assert evaluate(sw.MFA, idx)[0] == "NOT_APPLICABLE"
    idx = build(sw.MFA)
    paths = first(idx, "entra_user")["managementSignInDecisions"]["items"][0]["allowed_paths"]
    paths.append({"required_controls": ["compliantDevice"], "required_authentication_strength_ids": []})
    assert evaluate(sw.MFA, idx)[0] == "FAIL"
    idx = build(sw.MFA)
    for fact in first(idx, "entra_user")["managementSignInDecisions"]["items"]:
        fact["allowed_paths"] = [{"required_controls": [], "required_authentication_strength_ids": ["mfa-strength"]}]
    assert evaluate(sw.MFA, idx)[0] == "PASS"


def test_disabled_identity_external_deadline_and_missing_history():
    idx = build(sw.DISABLED)
    first(idx, "idp_identity_event")["event_time"] = (NOW - timedelta(hours=23)).isoformat()
    assert evaluate(sw.DISABLED, idx)[0] == "UNKNOWN"
    idx = build(sw.DISABLED)
    history = first(idx, "entra_user")["cloudAccessRemoval"]
    history.pop("identity_inactive_at")
    assert evaluate(sw.DISABLED, idx)[0] == "UNKNOWN"
    idx = build(sw.DISABLED)
    first(idx, "entra_user")["cloudAccessRemoval"]["effective_policies_inactive_at"] = (NOW - timedelta(hours=1)).isoformat()
    assert evaluate(sw.DISABLED, idx)[0] == "FAIL"
    idx = build(sw.DISABLED)
    first(idx, "entra_user")["cloudAccessRemoval"]["effective_policies_active"] = True
    assert evaluate(sw.DISABLED, idx)[0] == "FAIL"


def test_federation_retention_no_observations_and_correlation():
    for mutation in ("retention", "correlation", "no_events", "token_issuer_only"):
        idx = build(sw.FEDERATED)
        history = first(idx, "human_signin_history")
        if mutation == "retention":
            history["retained_from"] = (NOW - timedelta(days=29)).isoformat()
        elif mutation == "correlation":
            history["authenticationEvidence"][0]["correlationId"] = "another-event"
        elif mutation == "no_events":
            history["signIns"] = []
        else:
            history["authenticationEvidence"] = []
            history["signIns"][0]["tokenIssuerName"] = "approved-idp"
        assert evaluate(sw.FEDERATED, idx)[0] == "UNKNOWN"


@pytest.mark.parametrize("check_id,days", [(sw.ROTATE180, 180), (sw.ROTATE90, 90)])
def test_certificate_rotation_issuance_boundary_and_universe(check_id, days):
    idx = build(check_id)
    first(idx, "certificate_issuance")["issued_at"] = (NOW - timedelta(days=days)).isoformat()
    assert evaluate(check_id, idx)[0] == "PASS"
    first(idx, "certificate_issuance")["issued_at"] = (NOW - timedelta(days=days, seconds=1)).isoformat()
    assert evaluate(check_id, idx)[0] == "FAIL"
    idx = build(check_id)
    first(idx, "certificate_issuance")["authority"] = "key_vault_attributes_created"
    assert evaluate(check_id, idx)[0] == "UNKNOWN"
    idx = build(check_id)
    first(idx, "vault_certificate")["thumbprint"] = "unmatched"
    assert evaluate(check_id, idx)[0] == "UNKNOWN"
    idx = build(check_id)
    idx["collections"]["vault_certificate"][0]["scopeCoverage"]["covered_services"] = ["appService"]
    assert evaluate(check_id, idx)[0] == "UNKNOWN"
    idx = build(check_id, bad=True)
    first(idx, "vault_certificate")["service_type"] = "outside-approved-services"
    assert evaluate(check_id, idx)[0] == "UNKNOWN"


def test_metric_alert_alone_does_not_pass():
    idx = build(sw.RATE)
    fact = first(idx, "data_collection_rule")["metricSources"]["items"][0]["floodControls"]
    del fact["ingested_count"]
    assert evaluate(sw.RATE, idx)[0] == "UNKNOWN"
    idx = build(sw.RATE)
    first(idx, "data_collection_rule")["metricSources"]["items"][0]["floodControls"]["ingested_count"] = 1000
    assert evaluate(sw.RATE, idx)[0] == "FAIL"
    idx = build(sw.RATE)
    first(idx, "scheduled_query_rule")["properties"]["enabled"] = False
    assert evaluate(sw.RATE, idx)[0] == "FAIL"
    idx = build(sw.RATE)
    first(idx, "data_collection_rule")["metricSources"]["items"][0]["floodControls"]["resolution"]["querySemantics"] = "missing"
    assert evaluate(sw.RATE, idx)[0] == "UNKNOWN"
    idx = build(sw.RATE)
    criterion = first(idx, "scheduled_query_rule")["properties"]["criteria"]["allOf"][0]
    criterion["threshold"] = 100.0
    assert evaluate(sw.RATE, idx)[0] == "PASS"
    criterion["threshold"] = float("nan")
    assert evaluate(sw.RATE, idx)[0] == "UNKNOWN"


def test_stream_wrong_type_and_missing_positive_control():
    idx = build(sw.AUTH)
    observations = first(idx, "data_collection_rule")["streamInventory"]["items"][0]["authenticationEvidence"]["observations"]
    observations[2]["accepted"] = True
    assert evaluate(sw.AUTH, idx)[0] == "FAIL"
    idx = build(sw.AUTH)
    observations = first(idx, "data_collection_rule")["streamInventory"]["items"][0]["authenticationEvidence"]["observations"]
    observations.pop(0)
    assert evaluate(sw.AUTH, idx)[0] == "UNKNOWN"


def test_gateway_tls_redirect_alone_unreachable_and_invalid_chain():
    idx = build(sw.HTTPS)
    ep = first(idx, "application_gateway_and_frontdoor")["exposedEndpoints"]["items"][0]
    ep["redirects_to_https"] = True
    ep.pop("tlsObservation")
    assert evaluate(sw.HTTPS, idx)[0] == "UNKNOWN"
    idx = build(sw.HTTPS)
    ep = first(idx, "application_gateway_and_frontdoor")["exposedEndpoints"]["items"][0]
    ep["https_configured"] = False
    assert evaluate(sw.HTTPS, idx)[0] == "FAIL"
    idx = build(sw.HTTPS)
    ep = first(idx, "application_gateway_and_frontdoor")["exposedEndpoints"]["items"][0]
    ep["tlsObservation"]["reachable"] = False
    assert evaluate(sw.HTTPS, idx)[0] == "UNKNOWN"
    ep["tlsObservation"]["reachable"] = True
    ep["tlsObservation"]["chain_valid"] = False
    assert evaluate(sw.HTTPS, idx)[0] == "FAIL"
    idx = build(sw.HTTPS)
    ep = first(idx, "application_gateway_and_frontdoor")["exposedEndpoints"]["items"][0]
    ep["listener_id"] = ep["listener_id"].replace(SCOPE, FOREIGN)
    ep["tlsObservation"]["listener_id"] = ep["listener_id"]
    assert evaluate(sw.HTTPS, idx)[0] == "UNKNOWN"


def test_ssl_profile_inheritance_custom_and_frontdoor_unknown():
    idx = build(sw.SSL)
    row = first(idx, "application_gateway_and_frontdoor")
    profile_id = GW + "/sslProfiles/profile"
    row["properties"]["httpListeners"][0]["properties"]["sslProfile"] = {"id": profile_id}
    row["properties"]["sslProfiles"] = [{"id": profile_id, "properties": {"sslPolicy": {"policyType": "CustomV2"}}}]
    assert evaluate(sw.SSL, idx)[0] == "FAIL"
    row["properties"]["sslProfiles"] = []
    assert evaluate(sw.SSL, idx)[0] == "UNKNOWN"
    idx = build(sw.SSL)
    first(idx, "application_gateway_and_frontdoor")["properties"]["httpListeners"][0]["properties"]["protocol"] = "Http"
    assert evaluate(sw.SSL, idx)[0] == "NOT_APPLICABLE"
    fd = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/frontDoors/fd"
    row = native(fd, "Microsoft.Network/frontDoors", properties={"frontendEndpoints": [{"id": fd + "/frontendEndpoints/ep"}],
        "routingRules": [{"id": fd + "/routingRules/rule", "properties": {"acceptedProtocols": ["Https"], "frontendEndpoints": [{"id": fd + "/frontendEndpoints/ep"}]}}]})
    assert evaluate(sw.SSL, index({"application_gateway_and_frontdoor": [row]}, sw.SSL))[0] == "UNKNOWN"


def test_issued_rsa_not_future_policy_and_ec_not_applicable():
    idx = build(sw.RSA, bad=True)
    first(idx, "key_vault_certificate")["policy"] = {"key_props": {"key_size": 4096}}
    assert evaluate(sw.RSA, idx)[0] == "FAIL"
    idx = index({"key_vault_certificate": [current_certificate("ec")]}, sw.RSA)
    assert evaluate(sw.RSA, idx)[0] == "NOT_APPLICABLE"
    idx = build(sw.RSA)
    first(idx, "key_vault_certificate")["currentCertificate"]["cer"] = "not-base64"
    assert evaluate(sw.RSA, idx)[0] == "UNKNOWN"


def test_unsupported_x509_algorithm_remains_unknown(monkeypatch):
    from cryptography import x509
    from cryptography.exceptions import UnsupportedAlgorithm
    idx = build(sw.RSA)
    def unsupported(_der):
        raise UnsupportedAlgorithm("unsupported certificate algorithm")
    monkeypatch.setattr(x509, "load_der_x509_certificate", unsupported)
    assert evaluate(sw.RSA, idx)[0] == "UNKNOWN"


def test_certificate_expiry_missing_disabled_masked_and_no_threshold():
    idx = build(sw.EXPIRY)
    attrs = first(idx, "key_vault_certificate")["currentCertificate"]["attributes"]
    attrs.pop("exp")
    assert evaluate(sw.EXPIRY, idx)[0] == "FAIL"
    attrs["_coverage"] = {"exp": {"status": "denied"}}
    assert evaluate(sw.EXPIRY, idx)[0] == "UNKNOWN"
    attrs.pop("_coverage")
    attrs["enabled"] = False
    assert evaluate(sw.EXPIRY, idx)[0] == "NOT_APPLICABLE"
    idx = build(sw.EXPIRY)
    idx["context"]["metadata"]["compliance_policy"]["parameters"].pop("expirationWithinDays")
    assert evaluate(sw.EXPIRY, idx)[0] == "UNKNOWN"
    idx = build(sw.EXPIRY)
    first(idx, "key_vault_certificate")["currentCertificate"]["attributes"]["exp"] = True
    assert evaluate(sw.EXPIRY, idx)[0] == "UNKNOWN"


def test_purview_member_rules_runs_and_alternative_scan():
    idx = build(sw.PURVIEW)
    row = first(idx, "purview_account")
    row["accountApplicability"]["account_type"] = "member"
    assert evaluate(sw.PURVIEW, idx)[0] == "NOT_APPLICABLE"
    idx = build(sw.PURVIEW)
    scans = first(idx, "purview_account")["dataSources"]["items"][0]["scans"]["items"]
    scans[0]["classificationRuleset"]["classification_rules"] = []
    assert evaluate(sw.PURVIEW, idx)[0] == "FAIL"
    idx = build(sw.PURVIEW)
    scans = first(idx, "purview_account")["dataSources"]["items"][0]["scans"]["items"]
    scans[0]["runs"]["items"][0]["completed_at"] = (NOW - timedelta(days=2)).isoformat()
    scans[0]["runs"]["items"][0]["started_at"] = (NOW - timedelta(days=2, hours=1)).isoformat()
    assert evaluate(sw.PURVIEW, idx)[0] == "FAIL"
    idx = build(sw.PURVIEW)
    scans = first(idx, "purview_account")["dataSources"]["items"][0]["scans"]["items"]
    alternative = copy.deepcopy(scans[0])
    alternative["id"] += "-obsolete"
    alternative["classificationRuleset"]["scan_id"] = alternative["id"]
    alternative["runs"]["parent_id"] = alternative["id"]
    alternative["properties"]["enabled"] = False
    scans.append(alternative)
    assert evaluate(sw.PURVIEW, idx)[0] == "PASS"


@pytest.mark.parametrize("check_id", sw.IDS)
def test_duplicate_or_divergent_projection_never_grades(check_id):
    kind = LOCAL[check_id].dependencies[0]
    idx = build(check_id, bad=True)
    idx[kind].append(copy.deepcopy(idx[kind][0]))
    idx["collections"][kind][0]["items"].append(copy.deepcopy(first(idx, kind)))
    assert evaluate(check_id, idx)[0] == "UNKNOWN"
    idx = build(check_id, bad=True)
    idx["collections"][kind][0]["items"] = []
    assert evaluate(check_id, idx)[0] == "UNKNOWN"


@pytest.mark.parametrize("check_id", sw.IDS)
def test_missing_secondary_inventory_or_foreign_policy_unknown(check_id):
    idx = build(check_id)
    if len(LOCAL[check_id].dependencies) > 1:
        idx["collections"].pop(LOCAL[check_id].dependencies[-1])
        assert evaluate(check_id, idx)[0] == "UNKNOWN"
    idx = build(check_id)
    # RSA measures the issued key directly and requires no owner parameter.
    if check_id != sw.RSA:
        idx["context"]["metadata"]["compliance_policy"]["scope"] = FOREIGN
        assert evaluate(check_id, idx)[0] == "UNKNOWN"


def test_os_vulnerability_ignores_unrelated_vm_assessment():
    idx = build(sw.VULNERABILITY)
    vm = SCOPE + "/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/unrelated"
    other = copy.deepcopy(first(idx, "security_assessment"))
    other["id"] = vm + "/providers/Microsoft.Security/assessments/os-key"
    other["properties"]["resourceDetails"]["id"] = vm
    other["properties"]["status"]["code"] = "Unhealthy"
    other["assessmentMetadata"]["resource_type"] = "Microsoft.Compute/virtualMachines"
    idx["security_assessment"].append({"type": "security_assessment", "scope": SCOPE, "data": other})
    idx["collections"]["security_assessment"][0]["items"].append(other)
    assert evaluate(sw.VULNERABILITY, idx)[0] == "PASS"
    fact = first(idx, "security_assessment")
    fact["properties"]["status"]["code"] = "NotApplicable"
    assert evaluate(sw.VULNERABILITY, idx)[0] == "UNKNOWN"


def test_foreign_current_version_cannot_use_safe_policy_or_expiry():
    for check_id in (sw.RSA, sw.EXPIRY):
        idx = build(check_id)
        first(idx, "key_vault_certificate")["currentCertificate"]["id"] = "https://foreign.vault.azure.net/certificates/cert/version-1"
        assert evaluate(check_id, idx)[0] == "UNKNOWN"
        idx = build(check_id)
        first(idx, "key_vault_certificate")["currentCertificate"]["_provenance"]["representation"] = "partial"
        assert evaluate(check_id, idx)[0] == "UNKNOWN"


def test_purview_unavailable_history_and_pending_run_unknown():
    idx = build(sw.PURVIEW)
    scan = first(idx, "purview_account")["dataSources"]["items"][0]["scans"]["items"][0]
    scan["runs"]["collection_status"] = "partial"
    assert evaluate(sw.PURVIEW, idx)[0] == "UNKNOWN"
    idx = build(sw.PURVIEW)
    scan = first(idx, "purview_account")["dataSources"]["items"][0]["scans"]["items"][0]
    scan["runs"]["items"][0]["status"] = "InProgress"
    assert evaluate(sw.PURVIEW, idx)[0] == "UNKNOWN"
    idx = build(sw.PURVIEW)
    source = first(idx, "purview_account")["dataSources"]["items"][0]
    source["id"] = source["id"].replace(SCOPE, FOREIGN)
    source["scans"]["parent_id"] = source["id"]
    assert evaluate(sw.PURVIEW, idx)[0] == "UNKNOWN"


import hashlib
from cryptography import x509

@pytest.mark.parametrize("check_id", [sw.ROTATE90, sw.ROTATE180])
@pytest.mark.parametrize("case,expected", [
    ("not_before_authority", "UNKNOWN"),
    ("wrong_thumbprint", "UNKNOWN"),
    ("wrong_serial", "UNKNOWN"),
    ("malformed_der", "UNKNOWN"),
    ("matched_leaf", "PASS"),
    ("matched_overdue", "FAIL"),
])
def test_observed_leaf_and_independent_issuance(check_id, case, expected):
    idx = build(check_id)
    endpoint = first(idx, "vault_certificate")
    issuance = first(idx, "certificate_issuance")
    der = base64.b64decode(certificate_der(2048))
    cert = x509.load_der_x509_certificate(der)
    thumb = hashlib.sha1(der).hexdigest()
    serial = format(cert.serial_number, "x")
    endpoint["served_leaf_der"] = base64.b64encode(der).decode()
    endpoint["thumbprint"] = thumb
    endpoint["serial"] = serial
    issuance["thumbprint"] = thumb
    issuance["serial"] = serial
    if case == "not_before_authority":
        issuance["authority"] = "x509_not_before"
    elif case == "wrong_thumbprint":
        endpoint["thumbprint"] = issuance["thumbprint"] = "0" * 40
    elif case == "wrong_serial":
        endpoint["serial"] = issuance["serial"] = "ff"
    elif case == "malformed_der":
        endpoint["served_leaf_der"] = base64.b64encode(b"not a certificate").decode()
    elif case == "matched_overdue":
        age = 91 if check_id == sw.ROTATE90 else 181
        issuance["issued_at"] = (NOW - timedelta(days=age)).isoformat()
    assert evaluate(check_id, idx)[0] == expected


@pytest.mark.parametrize("case,expected", [
    ("late_identity", "FAIL"),
    ("late_policy", "FAIL"),
    ("exact_deadline", "PASS"),
    ("one_second_late", "FAIL"),
    ("already_inactive", "PASS"),
    ("missing_disable_time", "UNKNOWN"),
    ("still_enabled", "FAIL"),
    ("pending_deadline", "UNKNOWN"),
    ("foreign_tenant", "UNKNOWN"),
    ("wrong_idp_mapping", "UNKNOWN"),
    ("future_upstream_event", "UNKNOWN"),
    ("duplicate_upstream_event", "UNKNOWN"),
])
def test_disabled_identity_dated_lifecycle_boundaries(case, expected):
    idx = build(sw.DISABLED)
    user_row = first(idx, "entra_user")
    event = first(idx, "idp_identity_event")
    history = user_row["cloudAccessRemoval"]
    deadline = NOW - timedelta(hours=12)
    if case == "late_identity":
        history["identity_inactive_at"] = (NOW - timedelta(hours=1)).isoformat()
    elif case == "late_policy":
        history["effective_policies_inactive_at"] = (NOW - timedelta(hours=1)).isoformat()
    elif case == "exact_deadline":
        history["identity_inactive_at"] = deadline.isoformat()
        history["effective_policies_inactive_at"] = deadline.isoformat()
        event["event_time"] = (NOW - timedelta(hours=36)).isoformat()
    elif case == "one_second_late":
        history["identity_inactive_at"] = (deadline + timedelta(seconds=1)).isoformat()
    elif case == "already_inactive":
        history["identity_inactive_at"] = (NOW - timedelta(hours=40)).isoformat()
        history["effective_policies_inactive_at"] = (NOW - timedelta(hours=39)).isoformat()
    elif case == "missing_disable_time":
        history.pop("identity_inactive_at")
    elif case == "still_enabled":
        user_row["accountEnabled"] = True
        history["identity_active"] = True
    elif case == "pending_deadline":
        event["event_time"] = (NOW - timedelta(hours=23)).isoformat()
    elif case == "foreign_tenant":
        user_row["tenant_id"] = "foreign-tenant"
    elif case == "wrong_idp_mapping":
        event["source_idp_id"] = "other-idp"
    elif case == "future_upstream_event":
        event["event_time"] = (NOW + timedelta(seconds=1)).isoformat()
    elif case == "duplicate_upstream_event":
        duplicate = copy.deepcopy(event)
        duplicate["id"] = "event-2"
        idx["collections"]["idp_identity_event"][0]["items"].append(duplicate)
        idx["idp_identity_event"].append({"type": "idp_identity_event", "scope": SCOPE, "data": duplicate})
    assert evaluate(sw.DISABLED, idx)[0] == expected
