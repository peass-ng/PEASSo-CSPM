"""claude_azure DATA group: Defender for Cloud, Service Bus, Service Fabric, SignalR, Spring Apps, SQL,
Storage, Storage Sync, Stream Analytics, Synapse, WAF policies and AI Search.

Every predicate reads ARM-native facts strictly; missing, denied or malformed facts are UNKNOWN and
explicit skip branches are NOT_APPLICABLE. Facts the collector does not gather yet are documented in
scratchpad facts_data.md and stay UNKNOWN until collected.
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from ipaddress import collapse_addresses, ip_network
import re
from urllib.parse import urlparse
from .claude_azure_common import *  # noqa: F401,F403
from .claude_azure_common import CHECK_IDS

_START = len(CHECK_IDS)
SCOPE = {"scope": "/subscriptions/s"}


def _subscription(item):
    """Scope predicates apply to a subscription anchor only; other anchors are NOT_APPLICABLE."""
    scope = get(item, "scope", str)
    return scope.startswith("/subscriptions/") and len(scope.rstrip("/").split("/")) == 3


def _na(reason, **evidence):
    return "NOT_APPLICABLE", {"reason": reason, **evidence}


def _manual(reason, **evidence):
    return "MANUAL", {"reason": reason, **evidence}


def _scope_check(slug, kind, title, dependencies=None, **kwargs):
    deps = list(dependencies or [kind])
    decorator = claude(slug, kind, title, target="scope", dependencies=deps, **kwargs)

    def wrap(function):
        def evaluate(item, index):
            if not _subscription(item):
                return _na("Subscription predicate does not apply to a tenant or management-group anchor")
            return function(item, index)
        evaluate.__name__ = function.__name__
        return decorator(evaluate)
    return wrap


def _bool(item, path):
    return get(item, path, bool)


def _nonempty_str(value):
    return isinstance(value, str) and bool(value.strip())


# --- Diagnostic settings (embedded list; UNKNOWN until collected) ------------------------------------------

def _logging_enabled(item):
    settings = diagnostic_settings(item)
    enabled = [get(s, "name", str) for s in settings if any(_bool(log, "enabled") for log in diagnostic_logs(s))]
    return result(not enabled, settings_with_enabled_logs=enabled, setting_count=len(settings),
                  semantics="Any enabled resource-log category in a diagnostic setting; destination health is separate")


def _diag_check(slug, kind, title):
    @claude(slug, kind, title, severity="medium", control="AU-12",
            remediation="Create a diagnostic setting that sends the resource logs to Log Analytics, Storage or Event Hubs.")
    def evaluate(item, index):
        return _logging_enabled(item)
    evaluate.__name__ = "claude_" + slug
    CASES[cid(slug)] = {"pass": diag_case(diag_log("OperationalLogs")), "fail": diag_case(diag_log("OperationalLogs", enabled=False)),
                        "missing": {}, "malformed": {"diagnosticSettings": [None]}}


_diag_check("search_service_logging_enabled", "search_service", "Search service sends resource logs to a diagnostic setting")
_diag_check("servicebus_namespace_logging_enabled", "servicebus_namespace", "Service Bus namespace sends resource logs to a diagnostic setting")
_diag_check("stream_analytics_job_logging_enabled", "stream_analytics_job", "Stream Analytics job sends resource logs to a diagnostic setting")


@claude("search_service_replica_count_above_3", "search_service", "Search service runs more than three replicas", severity="low", control="CP-10")
def search_replicas(item, index):
    count = get(item, "properties.replicaCount", int)
    if count < 0:
        return unknown("negative replica count")
    return result(count <= 3, replica_count=count, semantics="Upstream requires strictly more than three replicas")
CASES[cid("search_service_replica_count_above_3")] = {"pass": nest("properties.replicaCount", 4), "fail": nest("properties.replicaCount", 3)}


# --- Defender for Cloud: contacts ---------------------------------------------------------------------------

def _contact(name="default", emails="sec@example.com", state="On", roles=("Owner",), sources=None):
    return {"id": "/subscriptions/s/providers/Microsoft.Security/securityContacts/" + name, "name": name,
            "properties": {"emails": emails, "notificationsByRole": {"state": state, "roles": list(roles)},
                           "notificationsSources": list(sources or [])}}


def _emails(item):
    return [x.strip() for x in get(item, "properties.emails", str).split(";") if x.strip()]


@claude("defender_contact_has_email", "security_contact", "Defender security contact lists at least one email address", control="IR-6")
def contact_has_email(item, index):
    emails = _emails(item)
    return result(not emails, email_count=len(emails))
CASES[cid("defender_contact_has_email")] = {"pass": _contact(), "fail": _contact(emails="")}


RISK_LEVELS = ("Low", "Medium", "High", "Critical")


@claude("defender_attack_path_notifications", "security_contact", "Defender contact receives attack-path notifications at High risk or lower", control="IR-6")
def attack_path(item, index):
    sources = list_of_objects(get(item, "properties.notificationsSources", list))
    levels = [get(s, "minimalRiskLevel") for s in sources if get(s, "sourceType", str) == "AttackPath"]
    if not levels:
        return result(True, attack_path_source=False, semantics="No AttackPath notification source is configured")
    if any(level not in RISK_LEVELS for level in levels):
        return unknown("unrecognized attack-path minimal risk level")
    best = min(RISK_LEVELS.index(level) for level in levels)
    return result(best > RISK_LEVELS.index("High"), minimal_risk_level=RISK_LEVELS[best])
CASES[cid("defender_attack_path_notifications")] = {
    "pass": _contact(sources=[{"sourceType": "AttackPath", "minimalRiskLevel": "High"}]),
    "fail": _contact(sources=[{"sourceType": "AttackPath", "minimalRiskLevel": "Critical"}])}


@_scope_check("defender_security_contact_email_configured", "security_contact", "Subscription has a Defender security contact with email configured", control="IR-6")
def contact_email_configured(item, index):
    contacts = scoped(index, "security_contact")
    names = [get(c, "name", str) for c in contacts]
    if any(name != "default" for name in names):
        return result(False, contacts=names, semantics="Upstream treats any non-default contact as configured")
    defaults = [c for c in contacts if get(c, "name", str) == "default"]
    has_email = len(defaults) == 1 and bool(_emails(defaults[0]))
    return result(not has_email, contacts=names, default_has_email=has_email)
CASES[cid("defender_security_contact_email_configured")] = {
    "pass": SCOPE, "fail": SCOPE,
    "pass_index": scope_index({"security_contact": [_contact()]}),
    "fail_index": scope_index({"security_contact": [_contact(emails="")]})}


@_scope_check("defender_alert_notifications_high", "security_contact", "Subscription contacts receive role notifications and High-severity alert emails", control="IR-6")
def notify_alerts(item, index):
    contacts = scoped(index, "security_contact")
    role_on = alert_high = False
    for contact in contacts:
        state = get(contact, "properties.notificationsByRole.state", str)
        if state not in ("On", "Off"):
            return unknown("unrecognized role notification state")
        role_on = role_on or state == "On"
        sources = list_of_objects(get(contact, "properties.notificationsSources", list))
        alert_high = alert_high or any(get(s, "sourceType", str) == "Alert" and s.get("minimalSeverity") == "High" for s in sources)
    return result(not (role_on and alert_high), role_notifications_on=role_on, alert_minimal_severity_high=alert_high,
                  semantics="Upstream requires the Alert source minimal severity to be exactly High")
CASES[cid("defender_alert_notifications_high")] = {
    "pass": SCOPE, "fail": SCOPE,
    "pass_index": scope_index({"security_contact": [_contact(sources=[{"sourceType": "Alert", "minimalSeverity": "High"}])]}),
    "fail_index": scope_index({"security_contact": [_contact(sources=[{"sourceType": "Alert", "minimalSeverity": "Low"}])]})}


@_scope_check("defender_alerts_to_owner", "security_contact", "Subscription contact notifies the Owner role about alerts", control="IR-6")
def alerts_owner(item, index):
    contacts = scoped(index, "security_contact")
    ok = False
    for contact in contacts:
        state = get(contact, "properties.notificationsByRole.state", str)
        roles = get(contact, "properties.notificationsByRole.roles", list)
        if any(not isinstance(role, str) for role in roles):
            return unknown("malformed notification roles")
        ok = ok or (state == "On" and "Owner" in roles)
    return result(not ok, owner_notified=ok, contact_count=len(contacts))
CASES[cid("defender_alerts_to_owner")] = {
    "pass": SCOPE, "fail": SCOPE,
    "pass_index": scope_index({"security_contact": [_contact()]}),
    "fail_index": scope_index({"security_contact": [_contact(roles=("AccountAdmin",))]})}


# --- Defender for Cloud: pricing plans ---------------------------------------------------------------------

def _pricing_row(name, tier="Standard", deprecated=None, extensions=None):
    props = {"pricingTier": tier}
    if deprecated is not None:
        props["deprecated"] = deprecated
    if extensions is not None:
        props["extensions"] = extensions
    return {"id": "/subscriptions/s/providers/Microsoft.Security/pricings/" + name, "name": name, "properties": props}


def _pricings(index):
    rows = {}
    for row in scoped(index, "security_pricing"):
        name = get(row, "name", str)
        if name in rows:
            raise Unavailable("ambiguous Defender pricing identity")
        rows[name] = row
    return rows


def _tier(row):
    tier = get(row, "properties.pricingTier", str)
    if tier not in ("Standard", "Free"):
        raise Unavailable("unrecognized Defender pricing tier")
    return tier


def _deprecated(row):
    return optional(get(row, "properties", dict), "deprecated", False, bool)


def _plan_check(slug, plan):
    @_scope_check(slug, "security_pricing", "Defender " + plan + " plan is Standard where the plan is still offered", control="SI-4",
                  remediation="Enable the intended Defender plan; deprecated legacy plans are replaced by the plan named in replacedBy.")
    def evaluate(item, index):
        rows = _pricings(index)
        if plan not in rows:
            return _na("Plan is absent from the complete pricing list", plan=plan)
        row = rows[plan]
        if _deprecated(row):
            return _na("Plan is deprecated by Microsoft", plan=plan, replaced_by=get(row, "properties").get("replacedBy"))
        tier = _tier(row)
        return result(tier != "Standard", plan=plan, pricing_tier=tier)
    evaluate.__name__ = "claude_" + slug
    CASES[cid(slug)] = {"pass": SCOPE, "fail": SCOPE,
                        "pass_index": scope_index({"security_pricing": [_pricing_row(plan)]}),
                        "fail_index": scope_index({"security_pricing": [_pricing_row(plan, "Free")]})}


_plan_check("defender_container_registry_plan_standard", "ContainerRegistry")
_plan_check("defender_dns_plan_standard", "Dns")
_plan_check("defender_kubernetes_plan_standard", "KubernetesService")


@claude("defender_plan_standard_any", "security_pricing", "Defender plan is Standard unless Microsoft deprecated it", control="SI-4")
def plan_standard_any(item, index):
    get(item, "name", str)
    if _deprecated(item):
        return _na("Plan is deprecated by Microsoft", plan=item["name"])
    tier = _tier(item)
    return result(tier != "Standard", plan=item["name"], pricing_tier=tier)
CASES[cid("defender_plan_standard_any")] = {"pass": _pricing_row("Discovery"), "fail": _pricing_row("Discovery", "Free")}


DB_PLANS = ("SqlServers", "SqlServerVirtualMachines", "OpenSourceRelationalDatabases", "CosmosDbs")


@_scope_check("defender_database_plans_standard", "security_pricing", "All four Defender database plans are Standard when offered", control="SI-4")
def database_plans(item, index):
    rows = _pricings(index)
    missing = [name for name in DB_PLANS if name not in rows]
    if missing:
        return _na("Pinned Prowler logic reports only when all four database plans are listed", missing_plans=missing)
    tiers = {name: _tier(rows[name]) for name in DB_PLANS}
    return result(any(t != "Standard" for t in tiers.values()), pricing_tiers=tiers)
CASES[cid("defender_database_plans_standard")] = {
    "pass": SCOPE, "fail": SCOPE,
    "pass_index": scope_index({"security_pricing": [_pricing_row(n) for n in DB_PLANS]}),
    "fail_index": scope_index({"security_pricing": [_pricing_row(n, "Free" if n == "CosmosDbs" else "Standard") for n in DB_PLANS]})}


@_scope_check("defender_container_registry_vulnerability_scanning", "security_pricing", "Defender for Containers registry vulnerability assessment extension is enabled", control="RA-5")
def container_scanning(item, index):
    rows = _pricings(index)
    if "Containers" not in rows:
        return _na("Containers plan is absent from the complete pricing list")
    row = rows["Containers"]
    if _tier(row) == "Free":
        return result(True, pricing_tier="Free", semantics="Registry vulnerability assessment requires the Standard Containers plan")
    extensions = list_of_objects(get(row, "properties.extensions", list))
    states = [get(e, "isEnabled", str) for e in extensions if get(e, "name", str) == "ContainerRegistriesVulnerabilityAssessments"]
    if any(state not in ("True", "False") for state in states):
        return unknown("unrecognized extension state")
    return result("True" not in states, extension_states=states)
_ext = lambda value: [{"name": "ContainerRegistriesVulnerabilityAssessments", "isEnabled": value}]
CASES[cid("defender_container_registry_vulnerability_scanning")] = {
    "pass": SCOPE, "fail": SCOPE,
    "pass_index": scope_index({"security_pricing": [_pricing_row("Containers", extensions=_ext("True"))]}),
    "fail_index": scope_index({"security_pricing": [_pricing_row("Containers", extensions=_ext("False"))]})}


# --- Defender for Cloud: policy, assessments, IoT ----------------------------------------------------------

@_scope_check("defender_default_initiative_no_disabled_effects", "policy_assignment", "Defender for Cloud default initiative sets no parameter to Disabled", control="CM-6")
def asc_default(item, index):
    rows = subscription_builtin_assignments(index, get(item, "scope", str))
    if not rows:
        return _na("No SecurityCenterBuiltIn assignment applies to this subscription in the complete policy assignment list")
    disabled = []
    for row in rows:
        parameters = optional(get(row, "properties", dict), "parameters", {}, dict)
        for key, value in parameters.items():
            if not isinstance(value, dict):
                return unknown("malformed policy assignment parameter")
            if value.get("value") == "Disabled":
                disabled.append(key)
    return result(bool(disabled), disabled_parameters=sorted(disabled),
                  semantics="Upstream count(value='Disabled') counts every non-null comparison; the intended any-Disabled predicate is evaluated")
_assignment = lambda value: {"id": "/subscriptions/s/providers/Microsoft.Authorization/policyAssignments/SecurityCenterBuiltIn",
                             "name": "SecurityCenterBuiltIn", "properties": {"scope": "/subscriptions/s", "parameters": {"systemUpdatesMonitoringEffect": {"value": value}}}}
CASES[cid("defender_default_initiative_no_disabled_effects")] = {
    "pass": SCOPE, "fail": SCOPE,
    "pass_index": scope_index({"policy_assignment": [_assignment("AuditIfNotExists")]}),
    "fail_index": scope_index({"policy_assignment": [_assignment("Disabled")]})}


ASSESSMENT_STATES = ("Healthy", "Unhealthy", "NotApplicable")


def _assessment_states(index, name):
    states = []
    for row in scoped(index, "security_assessment"):
        if get(row, "properties.displayName", str) == name:
            state = get(row, "properties.status.code", str)
            if state not in ASSESSMENT_STATES:
                raise Unavailable("unrecognized assessment status")
            states.append(state)
    return states


def _assessment(name, code):
    return {"id": "/subscriptions/s/resourceGroups/r/providers/Microsoft.Compute/virtualMachines/v/providers/Microsoft.Security/assessments/" + "".join(ch for ch in name if ch.isalnum())[:32],
            "name": "a", "properties": {"displayName": name, "status": {"code": code}}}


def _assessment_check(slug, names, title, *, ignore_not_applicable=False, control="SI-2"):
    names = tuple(names)

    @_scope_check(slug, "security_assessment", title, control=control,
                  remediation="Remediate the unhealthy Defender for Cloud recommendation on the affected resources.")
    def evaluate(item, index):
        by_name = {name: _assessment_states(index, name) for name in names}
        # Keep the factory option for compatibility. NotApplicable means an
        # assessment did not happen (including OffByPolicy), not a healthy or
        # independently inapplicable resource.
        unhealthy = {name: states.count("Unhealthy") for name, states in by_name.items() if "Unhealthy" in states}
        if unhealthy:
            return result(True, unhealthy_counts=unhealthy, assessments=list(names),
                          observed="Defender reports Unhealthy for at least one selected recommendation.")
        absent = [name for name, states in by_name.items() if not states]
        unassessed = [name for name, states in by_name.items() if "NotApplicable" in states]
        if absent or unassessed:
            return unknown("Named Defender assessment did not report a health result",
                           absent=absent, unassessed=unassessed,
                           observed="Defender has not assessed one or more selected recommendations, so their health is unknown.")
        return result(False, unhealthy_counts={}, assessments=list(names),
                      observed="Defender reports Healthy for the selected assessments.")
    evaluate.__name__ = "claude_" + slug
    CASES[cid(slug)] = {"pass": SCOPE, "fail": SCOPE,
                        "pass_index": scope_index({"security_assessment": [_assessment(n, "Healthy") for n in names]}),
                        "fail_index": scope_index({"security_assessment": [_assessment(n, "Unhealthy") for n in names]})}


_assessment_check("defender_assessment_endpoint_protection", ["Install endpoint protection solution on virtual machines"],
                  "Defender endpoint-protection assessment has no unhealthy machines", control="SI-3")
_assessment_check("defender_assessment_vulnerability_solution", ["Machines should have a vulnerability assessment solution"],
                  "Defender vulnerability-assessment-solution assessment has no unhealthy machines", control="RA-5")
_assessment_check("defender_assessment_running_images_vulnerabilities",
                  ["Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management)"],
                  "Defender running container image vulnerability assessment has no unhealthy images", ignore_not_applicable=True, control="RA-5")
_assessment_check("defender_assessment_system_updates",
                  ["Log Analytics agent should be installed on virtual machines",
                   "Machines should be configured to periodically check for missing system updates",
                   "System updates should be installed on your machines"],
                  "Defender system-update assessments have no unhealthy machines")


@_scope_check("defender_iot_security_solution_enabled", "iot_security_solution", "Defender for IoT security solutions are enabled", dependencies=["iot_security_solution", "iot_hub"], allow_incomplete_failure=True, control="SI-4")
def iot_solutions(item, index):
    rows = scoped(index, "iot_security_solution")
    if not rows:
        hubs = scoped(index, "iot_hub")
        if not hubs:
            return _na("No IoT security solution or IoT Hub exists in the complete subscription inventories")
        return unknown("IoT Hubs exist, but the selected subscription's solution list cannot prove whether another subscription's solution covers them",
                       iot_hub_ids=[get(hub, "id", str) for hub in hubs],
                       missing_native_evidence="complete cross-subscription IoT security solution inventory and hub binding")
    states = [get(r, "properties.status", str) for r in rows]
    if any(state not in ("Enabled", "Disabled") for state in states):
        return unknown("unrecognized IoT security solution status")
    return result("Disabled" in states, statuses=states)
_iot = lambda status: {"id": "/subscriptions/s/resourceGroups/r/providers/Microsoft.Security/iotSecuritySolutions/i", "name": "i", "properties": {"status": status}}
CASES[cid("defender_iot_security_solution_enabled")] = {
    "pass": SCOPE, "fail": SCOPE,
    "pass_index": scope_index({"iot_security_solution": [_iot("Enabled")], "iot_hub": []}),
    "fail_index": scope_index({"iot_security_solution": [_iot("Disabled")], "iot_hub": []})}


# --- Service Bus -------------------------------------------------------------------------------------------

def _sb(tier="Premium", status="Active", **properties):
    return {"sku": {"name": tier, "tier": tier}, "properties": {"status": status, **properties}}


def _sb_tier(item):
    return enum(item, "sku.tier", ("Basic", "Standard", "Premium"))


@claude("servicebus_namespace_private_link", "servicebus_namespace", "Premium Service Bus namespace has an approved private endpoint", control="SC-7", category="network")
def servicebus_private_link(item, index):
    if _sb_tier(item) != "Premium":
        return _na("Private endpoints require the Premium tier")
    if get(item, "properties.privateEndpointConnections") is None:
        return _manual("Provider reports no private endpoint connection information")
    states = private_link_states(item)
    return result("Approved" not in states, connection_states=states)
CASES[cid("servicebus_namespace_private_link")] = {
    "pass": _sb(privateEndpointConnections=approved_private_link_case()["properties"]["privateEndpointConnections"]),
    "fail": _sb(privateEndpointConnections=[]), "manual": _sb(privateEndpointConnections=None)}


@claude("servicebus_namespace_local_auth_disabled", "servicebus_namespace", "Active Service Bus namespace disables SAS local authentication", control="IA-2")
def servicebus_local_auth(item, index):
    status = get(item, "properties.status", str)
    disabled = get(item, "properties.disableLocalAuth", bool)
    if status != "Active":
        return _na("Namespace is not Active", status=status)
    return result(not disabled, disable_local_auth=disabled)
CASES[cid("servicebus_namespace_local_auth_disabled")] = {"pass": _sb(disableLocalAuth=True), "fail": _sb(disableLocalAuth=False)}


@claude("servicebus_namespace_network_restricted", "servicebus_namespace", "Active Premium Service Bus namespace declares restricted public-network access", control="SC-7", category="network")
def servicebus_network(item, index):
    tier = _sb_tier(item)
    status = get(item, "properties.status", str)
    if status not in ("Active", "Disabled", "Disabling", "Activating", "Creating", "Unknown"):
        return unknown("unrecognized Service Bus namespace status", status=status)
    if status == "Unknown":
        return unknown("provider reports unknown Service Bus namespace status", status=status)
    if tier != "Premium" or status != "Active":
        return _na("Pinned source evaluates Active Premium namespaces only; Standard IP filtering is outside this check", tier=tier, status=status)
    coverage = item.get("_coverage", {})
    if isinstance(coverage, dict) and "networkRuleSet" in coverage:
        field_coverage = coverage["networkRuleSet"]
        if not isinstance(field_coverage, dict) or field_coverage.get("status") != "collected":
            return unknown("network rule set was not completely collected", network_rule_set_coverage=field_coverage)
    ruleset = get(item, "networkRuleSet.properties", dict)
    public = enum(item, "networkRuleSet.properties.publicNetworkAccess", ("Enabled", "Disabled"))
    namespace_public = item.get("properties", {}).get("publicNetworkAccess")
    if namespace_public is not None and namespace_public != public:
        return unknown("namespace and network rule set public-network settings disagree",
                       namespace_public_network_access=namespace_public, rule_set_public_network_access=public)
    trusted = ruleset.get("trustedServiceAccessEnabled")
    if trusted is not None and not isinstance(trusted, bool):
        return unknown("malformed trusted-service bypass setting")
    if public == "Disabled":
        return result(False, public_network_access=public, trusted_service_access_enabled=trusted,
                      semantics="Public network access is disabled by configuration; private endpoint availability and runtime reachability are separate")
    action = enum(item, "networkRuleSet.properties.defaultAction", ("Allow", "Deny"))
    if action == "Allow":
        return result(True, default_action=action, public_network_access=public,
                      semantics="Default Allow does not enforce IP or virtual-network filters; authentication is assessed separately")
    ip_rules = get(ruleset, "ipRules", list)
    vnet_rules = get(ruleset, "virtualNetworkRules", list)
    allowed_ips = []
    for rule in ip_rules:
        if not isinstance(rule, dict) or rule.get("action", "Allow") != "Allow" or not _nonempty_str(rule.get("ipMask")):
            return unknown("malformed or unsupported Service Bus IP rule")
        try:
            network = ip_network(rule["ipMask"], strict=False)
        except ValueError:
            return unknown("malformed Service Bus IP range")
        if network.version != 4:
            return unknown("unsupported non-IPv4 Service Bus IP rule")
        allowed_ips.append(network)
    subnets = []
    for rule in vnet_rules:
        subnet = rule.get("subnet") if isinstance(rule, dict) else None
        subnet_id = subnet.get("id") if isinstance(subnet, dict) else None
        if not _nonempty_str(subnet_id) or not _servicebus_subnet_id(subnet_id):
            return unknown("malformed Service Bus virtual-network subnet reference")
        subnets.append(subnet_id)
    evidence = {"default_action": action, "public_network_access": public,
                "ip_rule_count": len(ip_rules), "virtual_network_rule_count": len(vnet_rules),
                "trusted_service_access_enabled": trusted,
                "semantics": "Declared namespace network restriction only; trusted-service bypass, rule ownership and runtime reachability are separate"}
    if not allowed_ips and not subnets:
        return "FAIL", {**evidence, "reason": "Default Deny with no IP or virtual-network rule does not restrict public traffic"}
    if any(network.prefixlen == 0 for network in collapse_addresses(allowed_ips)):
        return "FAIL", {**evidence, "reason": "Declared IPv4 allow rules collectively include the entire public address space"}
    return "PASS", evidence


def _servicebus_subnet_id(value):
    parts = value.strip("/").split("/")
    return (len(parts) == 10 and parts[0].casefold() == "subscriptions" and bool(parts[1])
            and parts[2].casefold() == "resourcegroups" and bool(parts[3])
            and parts[4].casefold() == "providers" and parts[5].casefold() == "microsoft.network"
            and parts[6].casefold() == "virtualnetworks" and bool(parts[7])
            and parts[8].casefold() == "subnets" and bool(parts[9]))


_nrs = lambda action, public, ip_rules, vnet_rules: {**_sb(), "networkRuleSet": {"properties": {
    "defaultAction": action, "publicNetworkAccess": public,
    "ipRules": ip_rules, "virtualNetworkRules": vnet_rules}}}
CASES[cid("servicebus_namespace_network_restricted")] = {
    "pass": _nrs("Deny", "Enabled", [{"ipMask": "192.0.2.0/24", "action": "Allow"}], []),
    "fail": _nrs("Deny", "Enabled", [], [])}


@claude("servicebus_premium_namespace_cmk", "servicebus_namespace", "Premium Service Bus namespace encrypts with a customer-managed key", control="SC-28")
def servicebus_cmk(item, index):
    if _sb_tier(item) != "Premium":
        return _na("Customer-managed keys require the Premium tier")
    encryption = optional(get(item, "properties", dict), "encryption", None)
    source = None if encryption is None else get(encryption, "keySource", str)
    return result(source != "Microsoft.KeyVault", key_source=source,
                  semantics="ARM omits properties.encryption when platform-managed keys are used")
CASES[cid("servicebus_premium_namespace_cmk")] = {"pass": _sb(encryption={"keySource": "Microsoft.KeyVault"}), "fail": _sb()}


@claude("servicebus_premium_namespace_vnet_rules", "servicebus_namespace", "Premium Service Bus namespace declares virtual network rules with subnets", control="SC-7", category="network")
def servicebus_vnet(item, index):
    if _sb_tier(item) != "Premium":
        return _na("Virtual network rules require the Premium tier")
    rules = list_of_objects(get(item, "networkRuleSet.properties.virtualNetworkRules", list))
    subnets = [get(r, "subnet", dict).get("id") for r in rules]
    return result(not rules or any(not _nonempty_str(s) for s in subnets), virtual_network_rule_count=len(rules),
                  semantics="Intended per-namespace predicate; the upstream cross join compares unrelated namespace names")
_vnet = lambda rules: {**_sb(), "networkRuleSet": {"properties": {"virtualNetworkRules": rules}}}
CASES[cid("servicebus_premium_namespace_vnet_rules")] = {"pass": _vnet([{"subnet": {"id": "/subscriptions/s/x/subnets/a"}}]), "fail": _vnet([])}


# --- Service Fabric, SignalR, Spring Apps -------------------------------------------------------------------

@claude("servicefabric_cluster_entra_auth", "service_fabric_cluster", "Service Fabric cluster configures Microsoft Entra client authentication", control="IA-2")
def fabric_aad(item, index):
    aad = optional(get(item, "properties", dict), "azureActiveDirectory", None)
    if aad is not None and not isinstance(aad, dict):
        return unknown("malformed azureActiveDirectory")
    if aad is not None:
        for name in ("tenantId", "clusterApplication", "clientApplication"):
            if name == "clientApplication" and name not in aad:
                continue
            value = aad.get(name)
            if not isinstance(value, str) or re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", value) is None:
                return unknown("incomplete or malformed Entra application identity", field=name)
    return result(aad is None, entra_configured=aad is not None)
CASES[cid("servicefabric_cluster_entra_auth")] = {"pass": {"properties": {"azureActiveDirectory": {"tenantId": "t", "clusterApplication": "a"}}},
                                                  "fail": {"properties": {"azureActiveDirectory": None}}}


@claude("servicefabric_cluster_encrypt_and_sign", "service_fabric_cluster", "Service Fabric cluster protection level is EncryptAndSign", control="SC-8")
def fabric_protection(item, index):
    sections = list_of_objects(optional(get(item, "properties", dict), "fabricSettings", [], list))
    values = [get(parameter, "value", str) for section in sections
              if get(section, "name", str) == "Security"
              for parameter in list_of_objects(get(section, "parameters", list))
              if get(parameter, "name", str) == "ClusterProtectionLevel"]
    if len(values) > 1 or values and values[0] not in ("None", "Sign", "EncryptAndSign"):
        return unknown("ambiguous or unrecognized ClusterProtectionLevel")
    configured = values[0] if values else None
    return result(configured != "EncryptAndSign", cluster_protection_level=configured)

_fabric = lambda value: {"properties": {"fabricSettings": [{"name": "Security", "parameters": [{"name": "ClusterProtectionLevel", "value": value}]}]}}
CASES[cid("servicefabric_cluster_encrypt_and_sign")] = {"pass": _fabric("EncryptAndSign"), "fail": _fabric("None")}


setting("signalr_service_no_free_tier", "signalr_service", "sku.tier", ("Standard", "Premium"), ("Free",),
        "SignalR service does not use the Free tier", severity="low", control="CP-10")


@claude("signalr_service_private_link", "signalr_service", "Non-Free SignalR service has an approved private endpoint", control="SC-7", category="network")
def signalr_pl(item, index):
    tier = enum(item, "sku.tier", ("Free", "Standard", "Premium"))
    if tier == "Free":
        return _na("Private endpoints are not available on the Free tier")
    states = private_link_states(item)
    return result("Approved" not in states, connection_states=states)
CASES[cid("signalr_service_private_link")] = {"pass": {"sku": {"tier": "Standard"}, **approved_private_link_case()},
                                              "fail": {"sku": {"tier": "Standard"}, "properties": {"privateEndpointConnections": []}}}


@claude("spring_cloud_service_vnet_injection", "spring_cloud_service", "Standard Azure Spring Apps service is deployed into a virtual network", control="SC-7", category="network")
def spring_vnet(item, index):
    tier = get(item, "sku.tier", str)
    if tier != "Standard":
        return _na("Upstream evaluates the Standard tier only", tier=tier)
    profile = optional(get(item, "properties", dict), "networkProfile", {}, dict)
    subnet = optional(profile, "serviceRuntimeSubnetId", None)
    return result(not _nonempty_str(subnet), service_runtime_subnet=subnet)
CASES[cid("spring_cloud_service_vnet_injection")] = {"pass": {"sku": {"tier": "Standard"}, "properties": {"networkProfile": {"serviceRuntimeSubnetId": "/subscriptions/s/x/subnets/rt"}}},
                                                     "fail": {"sku": {"tier": "Standard"}, "properties": {"networkProfile": {}}}}


# --- SQL ---------------------------------------------------------------------------------------------------

def _fw_range(item):
    import ipaddress
    start = ipaddress.ip_address(get(item, "properties.startIpAddress", str))
    end = ipaddress.ip_address(get(item, "properties.endIpAddress", str))
    if start.version != 4 or end.version != 4 or int(start) > int(end):
        raise Unavailable("malformed SQL firewall range")
    return str(start), str(end)


@claude("sql_firewall_no_internet_or_azure_services", "sql_firewall_rule", "SQL firewall rule allows neither all Azure services nor the whole internet", severity="high", control="SC-7", category="exposure")
def sql_fw_internet(item, index):
    start, end = _fw_range(item)
    return result(start == "0.0.0.0" and end in ("0.0.0.0", "255.255.255.255"), start_ip=start, end_ip=end)
_fw = lambda s, e: {"properties": {"startIpAddress": s, "endIpAddress": e}}
CASES[cid("sql_firewall_no_internet_or_azure_services")] = {"pass": _fw("10.0.0.1", "10.0.0.9"), "fail": _fw("0.0.0.0", "0.0.0.0")}


@claude("sql_firewall_no_full_range", "sql_firewall_rule", "SQL firewall rule does not span 0.0.0.0-255.255.255.255", severity="high", control="SC-7", category="exposure")
def sql_fw_full(item, index):
    start, end = _fw_range(item)
    return result(start == "0.0.0.0" and end == "255.255.255.255", start_ip=start, end_ip=end)
CASES[cid("sql_firewall_no_full_range")] = {"pass": _fw("0.0.0.0", "0.0.0.0"), "fail": _fw("0.0.0.0", "255.255.255.255")}


@claude("sql_database_long_term_retention", "sql_database_ltr_policy", "User SQL database configures long-term backup retention", control="CP-9")
def sql_ltr(item, index):
    if get(item, "parent_id", str).rsplit("/", 1)[-1].lower() == "master":
        return _na("System master database is excluded upstream")
    values = {k: get(item, "properties." + k, str) for k in ("weeklyRetention", "monthlyRetention", "yearlyRetention")}
    from .azure_policy_periods import positive_duration
    enabled = [positive_duration(value) for value in values.values()]
    return result(not any(enabled), retention=values)
_ltr = lambda w: {"parent_id": "/s/servers/a/databases/app", "properties": {"weeklyRetention": w, "monthlyRetention": "PT0S", "yearlyRetention": "PT0S"}}
CASES[cid("sql_database_long_term_retention")] = {"pass": _ltr("P4W"), "fail": _ltr("PT0S")}


def _when(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@claude("sql_database_va_findings_resolved", "sql_database", "Latest SQL vulnerability assessment scan has no failed checks", control="RA-5")
def sql_va_findings(item, index):
    if get(item, "name", str).lower() == "master":
        return _na("System master database is excluded upstream")
    scans = list_of_objects(get(item, "vulnerabilityAssessmentScans", list))
    if not scans:
        return _manual("No vulnerability assessment scan records exist for this database")
    latest = max(scans, key=lambda s: _when(get(s, "properties.endTime", str)))
    state = get(latest, "properties.state", str)
    if state not in ("Passed", "Failed"):
        return unknown("latest vulnerability scan did not complete successfully", latest_scan_state=state)
    properties = get(latest, "properties", dict)
    errors = list_of_objects(get(properties, "errors", list)) if "errors" in properties else []
    if errors:
        return unknown("latest vulnerability scan reports execution errors", latest_scan_state=state)
    failed = get(latest, "properties.numberOfFailedSecurityChecks", int)
    if failed < 0:
        return unknown("negative vulnerability assessment failed-check count")
    if (state == "Failed") != (failed > 0):
        return unknown("scan completion state contradicts failed-check count", latest_scan_state=state)
    return result(failed > 0, latest_scan_end=latest["properties"]["endTime"], failed_checks=failed,
                  semantics="Latest scan per database; upstream's global LIMIT 1 is not reproduced")
_scan = lambda n: {"name": "app", "vulnerabilityAssessmentScans": [{"properties": {"endTime": "2026-01-01T00:00:00Z", "numberOfFailedSecurityChecks": 9}},
                                                                   {"properties": {"endTime": "2026-02-01T00:00:00Z", "numberOfFailedSecurityChecks": n}}]}
CASES[cid("sql_database_va_findings_resolved")] = {"pass": _scan(0), "fail": _scan(2), "manual": {"name": "app", "vulnerabilityAssessmentScans": []}}


@claude("sql_server_entra_admin", "sql_server", "SQL server has a Microsoft Entra administrator", severity="high", control="IA-2")
def sql_entra_admin(item, index):
    admins = list_of_objects(get(item, "serverAdministrators", list))
    types = [get(a, "properties.administratorType", str) for a in admins]
    return result("ActiveDirectory" not in types, administrator_types=types)
CASES[cid("sql_server_entra_admin")] = {"pass": {"serverAdministrators": [{"properties": {"administratorType": "ActiveDirectory", "login": "dba"}}]},
                                        "fail": {"serverAdministrators": []}}


@claude("sql_server_private_link", "sql_server", "SQL server has an approved private endpoint", control="SC-7", category="network")
def sql_pl(item, index):
    states = private_link_states(item)
    return result("Approved" not in states, connection_states=states)
CASES[cid("sql_server_private_link")] = {"pass": approved_private_link_case(), "fail": nest("properties.privateEndpointConnections", [])}


@claude("sql_server_vnet_rules", "sql_server", "SQL server declares a virtual network rule", control="SC-7", category="network")
def sql_vnet(item, index):
    rules = list_of_objects(get(item, "virtualNetworkRules", list))
    subnets = [get(r, "properties.virtualNetworkSubnetId", str) for r in rules]
    return result(not subnets, subnets=subnets)
CASES[cid("sql_server_vnet_rules")] = {"pass": {"virtualNetworkRules": [{"properties": {"virtualNetworkSubnetId": "/subscriptions/s/x/subnets/a"}}]},
                                       "fail": {"virtualNetworkRules": []}}


_SQL_TLS_DEFAULT_REVIEWED_FROM = datetime(2026, 10, 12, tzinfo=timezone.utc)
_SQL_TLS_DEFAULT_REVIEWED_UNTIL = _SQL_TLS_DEFAULT_REVIEWED_FROM + timedelta(days=365)


@claude("sql_server_minimal_tls_12", "sql_server", "SQL server declares TLS 1.2+ or uses the reviewed TLS 1.2+ provider default",
        severity="high", control="SC-8",
        remediation="Review the observed SQL minimum TLS value and client requirements with the server owner; change an explicit older setting only when approved. The current provider default already permits TLS 1.2+ and cannot be restored after an explicit minimum is set.")
def sql_server_minimal_tls(item, index):
    configured = get(item, "properties.minimalTlsVersion", str)
    if configured in ("1.2", "1.3"):
        return result(False, configured_minimal_tls_version=configured,
                      semantics="Explicit declared minimum; negotiated connections are not probed")
    if configured in ("1.0", "1.1"):
        return result(True, configured_minimal_tls_version=configured,
                      semantics="Stale explicit minimum below 1.2; this is not proof that Azure currently negotiates retired TLS")
    if configured != "None":
        return unknown("unrecognized SQL minimum TLS version", configured_minimal_tls_version=configured)
    provenance = item.get("_provenance")
    if provenance is not None and not isinstance(provenance, dict):
        return unknown("malformed SQL observation provenance")
    observed = provenance.get("collected_at") if isinstance(provenance, dict) and "collected_at" in provenance else None
    if observed is None:
        context = index.get("context") if isinstance(index, dict) else None
        observed = context.get("created_at") if isinstance(context, dict) else None
    if not isinstance(observed, str):
        return unknown("snapshot observation date unavailable for provider-default TLS interpretation",
                       configured_minimal_tls_version=configured)
    try:
        captured = datetime.fromisoformat(observed.replace("Z", "+00:00"))
    except ValueError:
        return unknown("malformed SQL snapshot observation date", configured_minimal_tls_version=configured)
    if captured.tzinfo is None:
        return unknown("SQL snapshot observation date has no timezone", configured_minimal_tls_version=configured)
    captured = captured.astimezone(timezone.utc)
    if not (_SQL_TLS_DEFAULT_REVIEWED_FROM <= captured <= _SQL_TLS_DEFAULT_REVIEWED_UNTIL):
        return unknown("provider-default TLS behavior is outside the reviewed observation window",
                       configured_minimal_tls_version=configured, observed_at=captured.isoformat(),
                       reviewed_from=_SQL_TLS_DEFAULT_REVIEWED_FROM.date().isoformat(),
                       reviewed_until=_SQL_TLS_DEFAULT_REVIEWED_UNTIL.date().isoformat())
    return result(False, configured_minimal_tls_version=configured, observed_at=captured.isoformat(),
                  effective_provider_minimum="TLS 1.2", explicit_minimum_declared=False,
                  provider_default_reviewed_as_of=_SQL_TLS_DEFAULT_REVIEWED_FROM.date().isoformat(),
                  semantics="Current Azure SQL Database provider default allows TLS 1.2+; explicit-setting policy and client negotiation are separate")


CASES[cid("sql_server_minimal_tls_12")] = {
    "pass": {"properties": {"minimalTlsVersion": "1.2"}},
    "fail": {"properties": {"minimalTlsVersion": "1.1"}},
    "missing": {}, "malformed": {"properties": {"minimalTlsVersion": None}}}


@claude("sql_audit_storage_retention_90", "sql_audit", "Enabled SQL auditing to storage retains logs 90+ days or unlimited", control="AU-11")
def sql_audit_storage(item, index):
    state = enum(item, "properties.state", ("Enabled", "Disabled"))
    endpoint = optional(get(item, "properties", dict), "storageEndpoint", None)
    if state != "Enabled" or not _nonempty_str(endpoint):
        return _na("Auditing to a storage account is not enabled", state=state)
    days = get(item, "properties.retentionDays", int)
    return result(days != 0 and days < 90, retention_days=days)
_audit = lambda state, days, endpoint="https://a.blob.core.windows.net/": {"properties": {"state": state, "retentionDays": days, "storageEndpoint": endpoint}}
CASES[cid("sql_audit_storage_retention_90")] = {"pass": _audit("Enabled", 0), "fail": _audit("Enabled", 30)}


@claude("sql_audit_retention_over_90", "sql_audit", "SQL auditing is enabled with retention above 90 days or unlimited", control="AU-11")
def sql_audit_over_90(item, index):
    state = enum(item, "properties.state", ("Enabled", "Disabled"))
    if state == "Disabled":
        return result(True, state=state)
    days = get(item, "properties.retentionDays", int)
    return result(days != 0 and days <= 90, retention_days=days,
                  semantics="Retention 0 means unlimited and passes; Prowler's <=90 comparison would fail it")
CASES[cid("sql_audit_retention_over_90")] = {"pass": _audit("Enabled", 91), "fail": _audit("Enabled", 90)}


def _va_classic(item):
    path = optional(get(item, "properties", dict), "storageContainerPath", None)
    if path is not None and not isinstance(path, str):
        raise Unavailable("malformed storageContainerPath")
    return _nonempty_str(path)


@claude("sql_server_vulnerability_assessment_enabled", "sql_vulnerability_assessment", "SQL server vulnerability assessment is configured", control="RA-5")
def sql_va_enabled(item, index):
    if _va_classic(item):
        return result(False, configuration="classic")
    express = optional(item, "expressVulnerabilityAssessment", None)
    if express is None:
        return _manual("Classic VA storage is not configured and express configuration was not collected")
    state = enum(express, "properties.state", ("Enabled", "Disabled"))
    return result(state != "Enabled", configuration="express", state=state)
_va = lambda **rs: {"properties": {"storageContainerPath": "https://a.blob.core.windows.net/va", "recurringScans": {"isEnabled": True, "emailSubscriptionAdmins": True, "emails": ["a@example.com"], **rs}}}
CASES[cid("sql_server_vulnerability_assessment_enabled")] = {
    "pass": _va(), "fail": {"properties": {"storageContainerPath": ""}, "expressVulnerabilityAssessment": {"properties": {"state": "Disabled"}}},
    "manual": {"properties": {"storageContainerPath": ""}}}


def _va_check(slug, title, predicate):
    @claude(slug, "sql_vulnerability_assessment", title, control="RA-5")
    def evaluate(item, index):
        if not _va_classic(item):
            return _na("Recurring-scan settings apply to the classic storage-based VA configuration")
        scans = get(item, "properties.recurringScans", dict)
        return predicate(scans)
    evaluate.__name__ = "claude_" + slug
    return evaluate


def _emails_list(scans):
    emails = get(scans, "emails", list)
    if any(not isinstance(e, str) for e in emails):
        raise Unavailable("malformed VA emails")
    return [e for e in emails if e.strip()]


_va_check("sql_va_recurring_scans", "SQL vulnerability assessment recurring scans are enabled",
          lambda s: result(not get(s, "isEnabled", bool), recurring_scans=s["isEnabled"]))
CASES[cid("sql_va_recurring_scans")] = {"pass": _va(), "fail": _va(isEnabled=False)}
_va_check("sql_va_notify_admins", "SQL vulnerability assessment emails subscription admins",
          lambda s: result(not get(s, "emailSubscriptionAdmins", bool), email_subscription_admins=s["emailSubscriptionAdmins"]))
CASES[cid("sql_va_notify_admins")] = {"pass": _va(), "fail": _va(emailSubscriptionAdmins=False)}
_va_check("sql_va_report_emails", "SQL vulnerability assessment sends scan reports to listed emails",
          lambda s: result(not _emails_list(s), email_count=len(_emails_list(s))))
CASES[cid("sql_va_report_emails")] = {"pass": _va(), "fail": _va(emails=[])}
_va_check("sql_va_reports_configured", "SQL vulnerability assessment scan reports reach admins or listed emails",
          lambda s: result(not (get(s, "emailSubscriptionAdmins", bool) or _emails_list(s)), email_subscription_admins=s["emailSubscriptionAdmins"]))
CASES[cid("sql_va_reports_configured")] = {"pass": _va(emailSubscriptionAdmins=False), "fail": _va(emailSubscriptionAdmins=False, emails=[])}


setting("sql_tde_protector_cmk", "sql_encryption_protector", "properties.serverKeyType", ("AzureKeyVault",), ("ServiceManaged",),
        "SQL server TDE protector uses a customer-managed Key Vault key", control="SC-28")


# --- Storage accounts --------------------------------------------------------------------------------------

setting("storage_account_cmk", "storage_account", "properties.encryption.keySource", ("Microsoft.Keyvault",), ("Microsoft.Storage",),
        "Storage account encrypts with a customer-managed key", control="SC-28")
setting("storage_account_geo_redundant", "storage_account", "sku.name",
        ("Standard_GRS", "Standard_RAGRS", "Standard_GZRS", "Standard_RAGZRS"),
        ("Standard_LRS", "Standard_ZRS", "Premium_LRS", "Premium_ZRS", "StandardV2_LRS", "StandardV2_ZRS", "PremiumV2_LRS", "PremiumV2_ZRS"),
        "Storage account uses geo-redundant replication", severity="low", control="CP-9")


def _key_period(item):
    policy = optional(get(item, "properties", dict), "keyPolicy", None)
    return None if policy is None else get(policy, "keyExpirationPeriodInDays", int)


@claude("storage_key_expiration_policy_90", "storage_account", "Storage key expiration policy is exactly 90 days", control="IA-5")
def key_policy_90(item, index):
    days = _key_period(item)
    return result(days != 90, key_expiration_period_days=days)
CASES[cid("storage_key_expiration_policy_90")] = {"pass": nest("properties.keyPolicy.keyExpirationPeriodInDays", 90), "fail": {"properties": {}}}


@claude("storage_key_expiration_policy_max_90", "storage_account", "Storage key expiration policy is at most 90 days", control="IA-5")
def key_policy_max_90(item, index):
    days = _key_period(item)
    if days is not None and days < 0:
        raise Unavailable("key expiration period cannot be negative")
    return result(not days or days > 90, key_expiration_period_days=days)
CASES[cid("storage_key_expiration_policy_max_90")] = {"pass": nest("properties.keyPolicy.keyExpirationPeriodInDays", 60), "fail": nest("properties.keyPolicy.keyExpirationPeriodInDays", 180)}


@claude("storage_access_keys_rotated_90", "storage_account", "Storage account access keys were regenerated within 90 days", control="IA-5")
def keys_rotated(item, index):
    created = get(item, "properties.keyCreationTime", dict)
    context = optional(index, "context", None)
    now = _when(get(context, "created_at", str)) if context is not None else datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise Unavailable("scan capture time lacks a timezone")
    ages, seconds, timestamps = {}, {}, {}
    for key in ("key1", "key2"):
        value = _when(get(created, key, str))
        if value.tzinfo is None or value.utcoffset() is None or value > now:
            raise Unavailable("key creation time lacks a timezone or is after capture")
        seconds[key] = (now - value).total_seconds()
        ages[key] = seconds[key] / 86400
        timestamps[key] = get(created, key, str)
    return result(any(age > 90 * 86400 for age in seconds.values()), key_age_days=ages,
                  key_age_seconds=seconds, threshold_seconds=90 * 86400,
                  captured_at=now.isoformat(), key_creation_time=timestamps,
                  time_source="scan_capture" if context is not None else "evaluation_clock")
_recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
_old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
CASES[cid("storage_access_keys_rotated_90")] = {"pass": nest("properties.keyCreationTime", {"key1": _recent, "key2": _recent}),
                                                "fail": nest("properties.keyCreationTime", {"key1": _recent, "key2": _old})}


@claude("storage_trusted_azure_services_bypass", "storage_account", "Storage network rules let trusted Azure services bypass", severity="low", control="SC-7", category="network")
def trusted_services(item, index):
    bypass = [x.strip() for x in get(item, "properties.networkAcls.bypass", str).split(",")]
    return result("AzureServices" not in bypass, bypass=bypass)
CASES[cid("storage_trusted_azure_services_bypass")] = {"pass": nest("properties.networkAcls.bypass", "Logging, AzureServices"), "fail": nest("properties.networkAcls.bypass", "None")}


@claude("storage_vnet_service_endpoint_rules", "storage_account", "Storage account denies by default and declares virtual network rules", control="SC-7", category="network")
def storage_vnet(item, index):
    action = enum(item, "properties.networkAcls.defaultAction", ("Allow", "Deny"))
    rules = list_of_objects(get(item, "properties.networkAcls.virtualNetworkRules", list))
    return result(action != "Deny" or not rules, default_action=action, virtual_network_rule_count=len(rules),
                  semantics="Intended per-account predicate; the upstream subnet cross join is not reproduced")
_acl = lambda action, rules: {"properties": {"networkAcls": {"defaultAction": action, "virtualNetworkRules": rules}}}
CASES[cid("storage_vnet_service_endpoint_rules")] = {"pass": _acl("Deny", [{"id": "/subscriptions/s/x/subnets/a", "action": "Allow"}]), "fail": _acl("Allow", [])}


@claude("storage_private_link_all_approved", "storage_account", "Storage account has private endpoints and all are approved", control="SC-7", category="network")
def storage_pl_all(item, index):
    states = private_link_states(item)
    return result(not states or any(s != "Approved" for s in states), connection_states=states)
CASES[cid("storage_private_link_all_approved")] = {"pass": approved_private_link_case(), "fail": nest("properties.privateEndpointConnections", [])}


@claude("storage_private_endpoint_present", "storage_account", "Storage account has at least one private endpoint connection", control="SC-7", category="network")
def storage_pl_any(item, index):
    states = private_link_states(item)
    return result(not states, connection_states=states)
CASES[cid("storage_private_endpoint_present")] = {"pass": approved_private_link_case(), "fail": nest("properties.privateEndpointConnections", [])}


def _premium(item):
    return get(item, "sku.tier", str).lower() == "premium"


def _log_service_check(slug, service, title, skip, reader):
    @claude(slug, "storage_account", title, control="AU-12")
    def evaluate(item, index):
        if skip(item):
            return _na("Premium account is excluded upstream", service=service)
        flags = reader(item, service)
        return result(not all(flags.values()), service=service, **flags)
    evaluate.__name__ = "claude_" + slug
    return evaluate


def _classic_flags(item, service):
    return {op: get(item, "serviceAnalyticsLogging." + service + "." + op, bool) for op in ("read", "write", "delete")}


def _diag_flags(item, service):
    settings = list_of_objects(get(item, "serviceDiagnosticSettings." + service, list))
    flags = {"read": False, "write": False, "delete": False}
    for s in settings:
        for log in diagnostic_logs(s):
            if not _bool(log, "enabled"):
                continue
            category, group = log.get("category"), log.get("categoryGroup")
            if group == "allLogs":
                flags = dict.fromkeys(flags, True)
            elif category in ("StorageRead", "StorageWrite", "StorageDelete"):
                flags[category[7:].lower()] = True
    return flags


_blob_skip = lambda item: _premium(item) and get(item, "kind", str) in ("StorageV2", "FileStorage")
for _svc, _skip in (("blob", _blob_skip), ("queue", _premium), ("table", _premium)):
    _log_service_check("storage_" + _svc + "_classic_logging", _svc, "Storage " + _svc + " service classic logging records read, write and delete", _skip, _classic_flags)
    CASES[cid("storage_" + _svc + "_classic_logging")] = {
        "pass": {"sku": {"tier": "Standard"}, "kind": "StorageV2", "serviceAnalyticsLogging": {_svc: {"read": True, "write": True, "delete": True}}},
        "fail": {"sku": {"tier": "Standard"}, "kind": "StorageV2", "serviceAnalyticsLogging": {_svc: {"read": True, "write": False, "delete": True}}}}
    _log_service_check("storage_" + _svc + "_diagnostic_logging", _svc, "Storage " + _svc + " service diagnostic setting logs read, write and delete", _skip, _diag_flags)
    CASES[cid("storage_" + _svc + "_diagnostic_logging")] = {
        "pass": {"sku": {"tier": "Standard"}, "kind": "StorageV2", "serviceDiagnosticSettings": {_svc: diag_case(diag_log("StorageRead"), diag_log("StorageWrite"), diag_log("StorageDelete"))["diagnosticSettings"]}},
        "fail": {"sku": {"tier": "Standard"}, "kind": "StorageV2", "serviceDiagnosticSettings": {_svc: []}}}


def _storage_account_identity(account, scope):
    """Validate every inventory identity without requiring an unused service."""
    rid = get(account, "id", str)
    pattern = re.escape(scope) + r"/resourceGroups/[^/?#%\\\s]+/providers/Microsoft\.Storage/storageAccounts/([a-z0-9]{3,24})"
    match = re.fullmatch(pattern, rid, re.I)
    if (match is None or any(part in (".", "..") for part in rid.split("/"))
            or get(account, "type", str).casefold() != "microsoft.storage/storageaccounts"
            or get(account, "name", str).casefold() != match.group(1).casefold()):
        raise Unavailable("VHD backing account native identity unresolved")
    proof = get(account, "_provenance", dict)
    if (proof.get("representation") != "full" or proof.get("source_operation") != "get"
            or proof.get("read_only") is not True or proof.get("api_version") not in ("2023-05-01", "2026-06-01")):
        raise Unavailable("VHD backing account full GET unavailable")
    get(account, "properties", dict)
    return match.group(1).lower()


def _storage_blob_origin(account, scope):
    """Require a native Blob endpoint only for an actual backing candidate."""
    name = _storage_account_identity(account, scope)
    endpoint = urlparse(get(account, "properties.primaryEndpoints.blob", str))
    if (endpoint.scheme != "https" or endpoint.hostname != name + ".blob.core.windows.net"
            or endpoint.username is not None or endpoint.password is not None or endpoint.port not in (None, 443)
            or endpoint.netloc.lower() not in (endpoint.hostname, endpoint.hostname + ":443")
            or endpoint.path not in ("", "/") or endpoint.query or endpoint.fragment):
        raise Unavailable("VHD backing account Blob endpoint unsupported or contradictory")
    return endpoint.hostname, endpoint.port or 443


@_scope_check("storage_vhd_accounts_cmk", "storage_account", "Storage accounts hosting unmanaged VM OS disks use customer-managed keys",
              dependencies=["storage_account", "vm"], control="SC-28")
def vhd_cmk(item, index):
    scope = get(item, "scope", str)
    if re.fullmatch(r"/subscriptions/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", scope, re.I) is None:
        raise Unavailable("VHD selected subscription identity malformed")
    context = optional(index, "context", None)
    if context is not None and get(context, "scope", str).casefold() != scope.casefold():
        raise Unavailable("VHD selected subscription context differs")
    accounts, names = {}, set()
    for account in scoped(index, "storage_account"):
        name = _storage_account_identity(account, scope)
        if name in names:
            raise Unavailable("storage account inventory identity ambiguous")
        names.add(name)
        # These are lookup candidates only. A matching canonical name never
        # substitutes for the actual full native endpoint proof below.
        hosts = {name + ".blob.core.windows.net"}
        try:
            endpoint = urlparse(get(account, "properties.primaryEndpoints.blob", str))
            if endpoint.scheme == "https" and endpoint.hostname and endpoint.port in (None, 443):
                hosts.add(endpoint.hostname)
        except (Unavailable, ValueError):
            pass  # An unrelated FileStorage account need not expose Blob.
        for host in hosts:
            accounts.setdefault(host, []).append(account)
    offending, unresolved, vhd_count = [], [], 0
    for vm in scoped(index, "vm"):
        vm_id = get(vm, "id", str)
        if (re.fullmatch(re.escape(scope) + r"/resourceGroups/[^/?#%\\\s]+/providers/Microsoft\.Compute/virtualMachines/[^/?#%\\\s]+", vm_id, re.I) is None
                or any(part in (".", "..") for part in vm_id.split("/"))
                or get(vm, "type", str).casefold() != "microsoft.compute/virtualmachines"
                or get(vm, "_provenance.representation", str) != "full"
                or get(vm, "_provenance.source_operation", str) != "get"
                or get(vm, "_provenance.read_only", bool) is not True
                or get(vm, "_provenance.api_version", str) != "2023-09-01"):
            raise Unavailable("VHD VM full scoped identity unresolved")
        disk = get(vm, "properties.storageProfile.osDisk", dict)
        if disk.get("managedDisk") is not None:
            managed_id = get(disk, "managedDisk.id", str)
            if ("vhd" in disk or any(part in (".", "..") for part in managed_id.split("/"))
                    or not re.fullmatch(re.escape(scope) + r"/resourceGroups/[^/?#%\\\s]+/providers/Microsoft\.Compute/disks/[^/?#%\\\s]+", managed_id, re.I)):
                raise Unavailable("VM disk attachment identity contradictory or foreign")
            continue
        vhd_count += 1
        uri = urlparse(get(disk, "vhd.uri", str))
        if (uri.scheme != "https" or not uri.hostname or uri.username is not None or uri.password is not None
                or uri.port not in (None, 443) or uri.query or uri.fragment
                or uri.netloc.lower() not in (uri.hostname, uri.hostname + ":443")
                or len(uri.path.strip("/").split("/")) < 2 or any(part in (".", "..") for part in uri.path.split("/"))):
            unresolved.append("unsupported VHD URI origin")
            continue
        candidates = accounts.get(uri.hostname, [])
        if len(candidates) != 1:
            unresolved.append(uri.hostname)
        else:
            account = candidates[0]
            if _storage_blob_origin(account, scope) != (uri.hostname, uri.port or 443):
                raise Unavailable("VHD native Blob origin differs from backing reference")
            source = get(account, "properties.encryption.keySource", str).casefold()
            if source not in ("microsoft.storage", "microsoft.keyvault"):
                raise Unavailable("unrecognized VHD storage key source")
            if source == "microsoft.storage":
                offending.append(account["name"])
    if offending:
        return result(True, platform_key_vhd_accounts=sorted(set(offending)), unmanaged_os_vhd_count=vhd_count)
    if unresolved:
        return unknown("VHD host account is outside the collected inventory", hosts=unresolved)
    return result(False, platform_key_vhd_accounts=[], unmanaged_os_vhd_count=vhd_count,
                  semantics="Full native same-subscription account GET and exact HTTPS Blob origin; key-source configuration only" if vhd_count else "Complete native VM inventory declares no unmanaged OS VHD")
_vhd_vm = {"id": "/subscriptions/s/v", "properties": {"storageProfile": {"osDisk": {"vhd": {"uri": "https://disks.blob.core.windows.net/vhds/os.vhd"}}}}}
_acct = lambda source: {"id": "/subscriptions/s/a", "name": "disks", "properties": {"encryption": {"keySource": source}}}
CASES[cid("storage_vhd_accounts_cmk")] = {
    "pass": SCOPE, "fail": SCOPE,
    "pass_index": scope_index({"storage_account": [_acct("Microsoft.Keyvault")], "vm": [_vhd_vm]}),
    "fail_index": scope_index({"storage_account": [_acct("Microsoft.Storage")], "vm": [_vhd_vm]})}


# --- Storage services, containers, encryption scopes --------------------------------------------------------

def _service(item):
    kind = get(item, "type", str).lower().rsplit("/", 1)[-1]
    if kind not in ("blobservices", "fileservices", "queueservices", "tableservices"):
        raise Unavailable("unrecognized storage service type")
    return kind[:-8]


def _service_check(slug, service, title, predicate, control="CP-9"):
    @claude(slug, "storage_service", title, control=control)
    def evaluate(item, index):
        if _service(item) != service:
            return _na("Predicate applies to the " + service + " service")
        return predicate(item)
    evaluate.__name__ = "claude_" + slug
    return evaluate


def _policy_days(item, path, low, high):
    enabled = get(item, path + ".enabled", bool)
    if not enabled:
        return False, None
    days = get(item, path + ".days", int)
    return low <= days <= high, days


def _blob_container_soft_delete(item):
    blob_ok, blob_days = _policy_days(item, "properties.deleteRetentionPolicy", 7, 365)
    cont_ok, cont_days = _policy_days(item, "properties.containerDeleteRetentionPolicy", 7, 365)
    return result(not (blob_ok and cont_ok), blob_retention_days=blob_days, container_retention_days=cont_days)


BLOB = "Microsoft.Storage/storageAccounts/blobServices"
FILE = "Microsoft.Storage/storageAccounts/fileServices"
_service_check("storage_blob_and_container_soft_delete_7_365", "blob", "Blob and container soft delete are enabled with 7-365 day retention", _blob_container_soft_delete)
CASES[cid("storage_blob_and_container_soft_delete_7_365")] = {
    "pass": {"type": BLOB, "properties": {"deleteRetentionPolicy": {"enabled": True, "days": 7}, "containerDeleteRetentionPolicy": {"enabled": True, "days": 30}}},
    "fail": {"type": BLOB, "properties": {"deleteRetentionPolicy": {"enabled": True, "days": 7}, "containerDeleteRetentionPolicy": {"enabled": False}}}}
_service_check("storage_blob_soft_delete_enabled", "blob", "Blob soft delete is enabled",
               lambda item: result(not get(item, "properties.deleteRetentionPolicy.enabled", bool), enabled=item["properties"]["deleteRetentionPolicy"]["enabled"]))
CASES[cid("storage_blob_soft_delete_enabled")] = {"pass": {"type": BLOB, "properties": {"deleteRetentionPolicy": {"enabled": True}}},
                                                  "fail": {"type": BLOB, "properties": {"deleteRetentionPolicy": {"enabled": False}}}}
_service_check("storage_file_share_soft_delete_enabled", "file", "File share soft delete is enabled",
               lambda item: result(not get(item, "properties.shareDeleteRetentionPolicy.enabled", bool), enabled=item["properties"]["shareDeleteRetentionPolicy"]["enabled"]))
CASES[cid("storage_file_share_soft_delete_enabled")] = {"pass": {"type": FILE, "properties": {"shareDeleteRetentionPolicy": {"enabled": True}}},
                                                        "fail": {"type": FILE, "properties": {"shareDeleteRetentionPolicy": {"enabled": False}}}}


def _share_soft_delete_days(item):
    shares = list_of_objects(get(item, "shares", list))
    if not shares:
        return _na("Storage account has no file shares")
    ok, days = _policy_days(item, "properties.shareDeleteRetentionPolicy", 1, 365)
    return result(not ok, retention_days=days, share_count=len(shares))


_service_check("storage_file_share_soft_delete_1_365", "file", "File share soft delete is enabled with 1-365 day retention", _share_soft_delete_days)
CASES[cid("storage_file_share_soft_delete_1_365")] = {
    "pass": {"type": FILE, "shares": [{"name": "s"}], "properties": {"shareDeleteRetentionPolicy": {"enabled": True, "days": 7}}},
    "fail": {"type": FILE, "shares": [{"name": "s"}], "properties": {"shareDeleteRetentionPolicy": {"enabled": False}}}}


def _smb_set(item, field):
    smb = get(item, "properties.protocolSettings.smb", dict)
    value = smb.get(field)
    if value is None:
        return None
    if not isinstance(value, str):
        raise Unavailable("malformed SMB " + field)
    return sorted({x.strip() for x in value.split(";") if x.strip()})


def _smb_check(slug, field, wanted, title):
    def predicate(item):
        values = _smb_set(item, field)
        return result(values != [wanted], configured=values,
                      semantics="Unset means the service default, which permits every supported value")
    _service_check(slug, "file", title, predicate, control="SC-8")
    _smb = lambda v: {"type": FILE, "properties": {"protocolSettings": {"smb": {field: v}}}}
    CASES[cid(slug)] = {"pass": _smb(wanted + ";"), "fail": _smb("AES-128-CCM;AES-128-GCM;AES-256-GCM;" if field == "channelEncryption" else "SMB3.0;SMB3.1.1;")}


_smb_check("storage_smb_channel_encryption_aes_256_gcm", "channelEncryption", "AES-256-GCM", "File service allows only AES-256-GCM SMB channel encryption")
_smb_check("storage_smb_version_3_1_1", "versions", "SMB3.1.1", "File service allows only SMB 3.1.1")


@claude("storage_container_no_public_access", "storage_container", "Blob container public access level is None", severity="high", control="AC-3", category="exposure")
def container_public(item, index):
    level = enum(item, "properties.publicAccess", ("None", "Blob", "Container"))
    return result(level != "None", public_access=level, semantics="Container ACL; account-level allowBlobPublicAccess is a separate check")
CASES[cid("storage_container_no_public_access")] = {"pass": nest("properties.publicAccess", "None"), "fail": nest("properties.publicAccess", "Container")}


@claude("storage_encryption_scope_cmk", "storage_encryption_scope", "Storage encryption scope uses a customer-managed Key Vault key", control="SC-28")
def encryption_scope(item, index):
    source = get(item, "properties.source", str)
    if source.lower() not in ("microsoft.keyvault", "microsoft.storage"):
        return unknown("unrecognized encryption scope source")
    return result(source.lower() != "microsoft.keyvault", source=source)
CASES[cid("storage_encryption_scope_cmk")] = {"pass": nest("properties.source", "Microsoft.KeyVault"), "fail": nest("properties.source", "Microsoft.Storage")}


@claude("storage_sync_private_link", "storage_sync_service", "Storage Sync service restricts traffic to private endpoints", control="SC-7", category="network")
def storage_sync(item, index):
    policy = enum(item, "properties.incomingTrafficPolicy", ("AllowAllTraffic", "AllowVirtualNetworksOnly"))
    states = private_link_states(item)
    return result(policy == "AllowAllTraffic" or "Approved" not in states, incoming_traffic_policy=policy, connection_states=states)
_sync = lambda policy: {"properties": {"incomingTrafficPolicy": policy, **approved_private_link_case()["properties"]}}
CASES[cid("storage_sync_private_link")] = {"pass": _sync("AllowVirtualNetworksOnly"), "fail": _sync("AllowAllTraffic")}


# --- Synapse ----------------------------------------------------------------------------------------------

@claude("synapse_workspace_exfiltration_protection", "synapse_workspace", "Synapse workspace managed VNet prevents data exfiltration", control="AC-4", category="network")
def synapse_exfil(item, index):
    settings = optional(get(item, "properties", dict), "managedVirtualNetworkSettings", None)
    value = None if settings is None else get(settings, "preventDataExfiltration", bool)
    return result(value is not True, prevent_data_exfiltration=value)
CASES[cid("synapse_workspace_exfiltration_protection")] = {"pass": nest("properties.managedVirtualNetworkSettings.preventDataExfiltration", True),
                                                           "fail": nest("properties.managedVirtualNetworkSettings.preventDataExfiltration", False)}


@claude("synapse_workspace_cmk", "synapse_workspace", "Synapse workspace encrypts with a customer-managed key", control="SC-28")
def synapse_cmk(item, index):
    encryption = optional(get(item, "properties", dict), "encryption", {}, dict)
    cmk = optional(encryption, "cmk", None)
    name = None if cmk is None else optional(get(cmk, "key", dict), "name", None)
    return result(not _nonempty_str(name), cmk_key_name=name)
CASES[cid("synapse_workspace_cmk")] = {"pass": nest("properties.encryption.cmk.key.name", "k"), "fail": nest("properties.encryption", {"doubleEncryptionEnabled": False})}


@claude("synapse_workspace_private_link", "synapse_workspace", "Synapse workspace has an approved private endpoint", control="SC-7", category="network")
def synapse_pl(item, index):
    states = private_link_states(item)
    return result("Approved" not in states, connection_states=states)
CASES[cid("synapse_workspace_private_link")] = {"pass": approved_private_link_case(), "fail": nest("properties.privateEndpointConnections", [])}


@claude("synapse_workspace_vulnerability_assessment", "synapse_workspace", "Synapse workspace SQL vulnerability assessment recurring scans are enabled", control="RA-5")
def synapse_va(item, index):
    # The upstream workspace criterion uses the workspace-managed SQL server
    # policy. Dedicated-pool policies attest a different native resource.
    rows = list_of_objects(get(item, "workspaceVulnerabilityAssessments", list))
    rid = get(item, "id", str)
    expected = (rid + "/vulnerabilityAssessments/default").casefold()
    if len(rows) > 1:
        raise Unavailable("duplicate workspace vulnerability assessment")
    enabled = []
    for row in rows:
        if (get(row, "id", str).casefold() != expected or
                get(row, "parent_id", str).casefold() != rid.casefold() or
                get(row, "type", str).casefold() != "microsoft.synapse/workspaces/vulnerabilityassessments"):
            raise Unavailable("foreign workspace vulnerability assessment")
        enabled.append(get(row, "properties.recurringScans.isEnabled", bool))
    return result(True not in enabled, recurring_scans=enabled,
                  semantics="Workspace managed SQL server recurring-scan policy; pool policies and scan results are separate")
CASES[cid("synapse_workspace_vulnerability_assessment")] = {"pass": {"sqlVulnerabilityAssessments": [{"properties": {"recurringScans": {"isEnabled": True}}}]},
                                                            "fail": {"sqlVulnerabilityAssessments": []}}


# --- Web application firewall policies --------------------------------------------------------------------

@claude("waf_policy_bot_protection", "web_application_firewall_policy", "WAF policy enables the bot manager rule set without disabled rules", control="SC-7", category="network")
def waf_bot(item, index):
    sets = [s for s in list_of_objects(get(item, "properties.managedRules.managedRuleSets", list)) if get(s, "ruleSetType", str) == "Microsoft_BotManagerRuleSet"]
    disabled = []
    for rule_set in sets:
        for group in list_of_objects(optional(rule_set, "ruleGroupOverrides", [], list)):
            for rule in list_of_objects(optional(group, "rules", [], list)):
                if str(rule.get("state", "")).lower() == "disabled":
                    disabled.append(rule.get("ruleId"))
    return result(not sets or bool(disabled), bot_rule_set=bool(sets), disabled_rules=disabled)
_waf = lambda sets: {"properties": {"managedRules": {"managedRuleSets": sets}}}
CASES[cid("waf_policy_bot_protection")] = {"pass": _waf([{"ruleSetType": "Microsoft_BotManagerRuleSet", "ruleSetVersion": "1.0"}]),
                                           "fail": _waf([{"ruleSetType": "OWASP", "ruleSetVersion": "3.2"}])}

setting("waf_policy_request_body_inspection", "web_application_firewall_policy", "properties.policySettings.requestBodyCheck", (True,), (False,),
        "WAF policy inspects request bodies", control="SC-7")


DATA_IDS = list(CHECK_IDS[_START:])
