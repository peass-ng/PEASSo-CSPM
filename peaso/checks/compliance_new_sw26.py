"""Signed Azure compliance checks; conservative snapshot evaluation (sw26)."""
from __future__ import annotations

import re
from dataclasses import replace
from datetime import datetime, timezone
from urllib.parse import quote
from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, optional, list_of_objects

SPECS = {'azure.gap.kubernetes_cluster_pods_and_containers_uses_approved_user_and_group_id': {'provider': 'azure',
                                                                                      'resource_kind': 'pod',
                                                                                      'category': 'hardening',
                                                                                      'severity': 'medium',
                                                                                      'title': 'Use approved '
                                                                                               'pod and '
                                                                                               'container '
                                                                                               'identities',
                                                                                      'remediation_hint': 'Set '
                                                                                                          'approved '
                                                                                                          'runAsUser, '
                                                                                                          'runAsGroup, '
                                                                                                          'fsGroup '
                                                                                                          'and '
                                                                                                          'supplementalGroups '
                                                                                                          'on '
                                                                                                          'Pod '
                                                                                                          'templates '
                                                                                                          'and '
                                                                                                          'containers; '
                                                                                                          'enforce '
                                                                                                          'a '
                                                                                                          'supplementalGroupsPolicy '
                                                                                                          'that '
                                                                                                          'prevents '
                                                                                                          'unapproved '
                                                                                                          'inherited '
                                                                                                          'groups.',
                                                                                      'proposed_spec_sha256': '918e21532c03be7cdf3983a94af8e143ea838144aa5743ee7770935d05a0ae25'},
 'azure.gap.appservice_api_app_latest_tls_version': {'provider': 'azure',
                                                     'resource_kind': 'app_service_config',
                                                     'category': 'encryption',
                                                     'severity': 'medium',
                                                     'title': 'API apps require the approved minimum inbound '
                                                              'TLS version',
                                                     'remediation_hint': 'In each affected App Service or '
                                                                         'Function App > Configuration > '
                                                                         'General settings, set Minimum '
                                                                         'inbound TLS version to the '
                                                                         'approved latest supported version.',
                                                     'proposed_spec_sha256': '3bc266b2ac9d2a952e738cf486cae0344dfda6596aa523e254dbee606a95eb30'},
 'azure.other.app_latest_tls': {'provider': 'azure',
                                'resource_kind': 'app_service_config',
                                'category': 'encryption',
                                'severity': 'medium',
                                'title': 'Require the approved App Service TLS minimum',
                                'remediation_hint': 'Set the App Service minimum incoming TLS version to the '
                                                    'latest supported secure version for its runtime and '
                                                    'meet the organization minimum.',
                                'proposed_spec_sha256': '5f4533b6d835c6443ad6a8abc37a8b175eeedb49f59dd8b792d02ea87db75327'},
 'azure_c5_pi_01_02ac': {'provider': 'azure',
                         'resource_kind': 'app_service_config',
                         'category': 'hardening',
                         'severity': 'medium',
                         'title': 'Customer-federated apps require Entra authentication',
                         'remediation_hint': 'Configure App Service Authentication with required sign-in, no '
                                             'unauthenticated bypass paths, and a valid Microsoft Entra '
                                             'provider; document the customer identity-provider '
                                             'protocol/interface for C5 PI-01.02AC.',
                         'proposed_spec_sha256': 'eb8b059e5087a0bc2b59b3f7469ef5a4b856a1a18729e21331bde8e1e4dff307'},
 'azure.other.enumeration_logging': {'provider': 'azure',
                                     'resource_kind': 'diagnostic_setting',
                                     'category': 'logging',
                                     'severity': 'medium',
                                     'title': 'Enumeration events are logged',
                                     'remediation_hint': 'Enable the provider’s supported enumeration audit '
                                                         'category, route it to an approved sink, and verify '
                                                         'retained records include identity, time and '
                                                         'activity nature with a test event.',
                                     'proposed_spec_sha256': '60731392ee11f8f240ea838279c755d20440d071048da7495ef1c7dcd9447037'},
 'azure.other.log_writer_separation': {'provider': 'azure',
                                       'resource_kind': 'diagnostic_setting',
                                       'category': 'hardening',
                                       'severity': 'high',
                                       'title': 'Log writers cannot read or delete their logs',
                                       'remediation_hint': 'At each Log Analytics workspace or storage sink, '
                                                           'remove source identities from '
                                                           'data-reader/deleter roles and shared-key/SAS '
                                                           'paths; grant only the write permissions needed '
                                                           'for export.',
                                       'proposed_spec_sha256': '601235315b159b74d2e01281c3dd1e43f93da2fbdd58540e30865d1f8fda3e3b'},
 'azure.other.blob_uniform_deny': {'provider': 'azure',
                                   'resource_kind': 'storage_container',
                                   'category': 'hardening',
                                   'severity': 'high',
                                   'title': 'Denied principals cannot read objects in protected Blob '
                                            'containers',
                                   'remediation_hint': 'Remove effective Blob read grants, ACLs, issued SAS '
                                                       'and shared-key access for denied principals '
                                                       'throughout each protected container; verify '
                                                       'object-level access is denied.',
                                   'proposed_spec_sha256': 'c1604f71ac2e5ec427a6b6cc4c9e4acf6048506f802a270ae14fe9329819a744'},
 'azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_3f8ed7f': {'provider': 'azure',
                                                                                                  'resource_kind': 'storage_container',
                                                                                                  'category': 'hardening',
                                                                                                  'severity': 'high',
                                                                                                  'title': 'Restrict '
                                                                                                           'cross-tenant '
                                                                                                           'Blob '
                                                                                                           'container '
                                                                                                           'access',
                                                                                                  'remediation_hint': 'Remove '
                                                                                                                      'cross-tenant '
                                                                                                                      'grants '
                                                                                                                      'outside '
                                                                                                                      'the '
                                                                                                                      'approved '
                                                                                                                      'storage-account '
                                                                                                                      'policy, '
                                                                                                                      'disable '
                                                                                                                      'public '
                                                                                                                      'container '
                                                                                                                      'access, '
                                                                                                                      'and '
                                                                                                                      'constrain '
                                                                                                                      'or '
                                                                                                                      'revoke '
                                                                                                                      'SAS '
                                                                                                                      'and '
                                                                                                                      'shared-key '
                                                                                                                      'paths.',
                                                                                                  'proposed_spec_sha256': '5d8f17a7cb9a340138cd28a288bba5bb8cc9defbaa03b92f1ce0c5bddc48c465'},
 'azure_cdn_profile_10_3_4_1_4e40487': {'provider': 'azure',
                                        'resource_kind': 'cdn_profile',
                                        'category': 'identity',
                                        'severity': 'medium',
                                        'title': 'Azure Front Door Blob origins use managed identity '
                                                 'authentication',
                                        'remediation_hint': 'Use a Blob Storage container origin and '
                                                            'configure supported managed-identity origin '
                                                            'authentication with Storage Blob Data Reader on '
                                                            'that account.',
                                        'proposed_spec_sha256': '51a75f1cea4b66d38f8dd9df1d798977d2fab371819ba48f20f5e536dcd9edc1'},
 'azure_cdn_profile_1_2_8_5_ed953a0': {'provider': 'azure',
                                       'resource_kind': 'cdn_profile',
                                       'category': 'encryption',
                                       'severity': 'medium',
                                       'title': 'CDN custom domains use customer-managed certificates',
                                       'remediation_hint': 'CDN endpoint > Custom domains > HTTPS: select '
                                                           'customer-managed certificate from Key Vault, '
                                                           'grant CDN access, enable HTTPS and wait for '
                                                           'provisioningState=Enabled.',
                                       'proposed_spec_sha256': '80da05fc1f12fd8897d0e2c0c4513a8fb16070890e6b993f802f7879a03dc35e'},
 'azure_aks_cluster_1_4_5_2_3ac7b3c': {'provider': 'azure',
                                       'resource_kind': 'container_group_and_aks_pod',
                                       'category': 'hardening',
                                       'severity': 'high',
                                       'title': 'Disallow host PID namespace sharing in AKS pods',
                                       'remediation_hint': 'Update the pod or workload manifest to set '
                                                           'spec.hostPID: false, redeploy it, and enforce '
                                                           'with Azure Policy for Kubernetes or admission '
                                                           'policy.',
                                       'proposed_spec_sha256': 'e515a004dbe4d14bc76e7df72c01a77a0348326de2875b90292cd450086e2914'},
 'azure_aks_cluster_3_5_1_14_247ebcd': {'provider': 'azure',
                                        'resource_kind': 'container_group_and_aks_pod',
                                        'category': 'hardening',
                                        'severity': 'high',
                                        'title': 'AKS and Container Instances do not expose named secrets as '
                                                 'literal environment values',
                                        'remediation_hint': 'Move named secrets to Kubernetes Secrets, Key '
                                                            'Vault or another approved secure source; '
                                                            'reference them from Pod/ACI definitions and '
                                                            'remove literal secret values.',
                                        'proposed_spec_sha256': 'e7d1fe2f362221f038079f6911579918a275002d45f5aa503bf7c87697417a20'},
 'azure_role_assignment_aks_cluster_rbac_enabled_1c8eacd': {'provider': 'azure',
                                                            'resource_kind': 'role_definition',
                                                            'category': 'least_privilege',
                                                            'severity': 'medium',
                                                            'title': 'Custom Azure RBAC roles avoid '
                                                                     'provider-wide action wildcards',
                                                            'remediation_hint': 'Replace every custom-role '
                                                                                'service-wide wildcard in '
                                                                                'actions or dataActions with '
                                                                                'named permissions; account '
                                                                                'for notActions and '
                                                                                'notDataActions.',
                                                            'proposed_spec_sha256': 'c6316b3353c1d6f6b9a7580ab447108f822420eda3d9a367fb50c553cca0f125'},
 'azure_vault_keyvault_rbac_enabled_0179c48': {'provider': 'azure',
                                               'resource_kind': 'role_definition',
                                               'category': 'encryption',
                                               'severity': 'medium',
                                               'title': 'Custom RBAC roles exclude prohibited Key Vault '
                                                        'actions',
                                               'remediation_hint': 'Azure portal > Subscriptions/Key Vault > '
                                                                   'Access control (IAM) > Roles: edit '
                                                                   'custom role JSON to remove prohibited '
                                                                   'Microsoft.KeyVault actions/dataActions '
                                                                   'and narrow assignableScopes/assignments.',
                                               'proposed_spec_sha256': '6a7fb697eaff211d8c7caf48dcb15903db6de5cb9cf7408627ceb4a190c22a52'},
 'azure_c5_dev_08_02b': {'provider': 'azure',
                         'resource_kind': 'activity_log',
                         'category': 'hardening',
                         'severity': 'medium',
                         'title': 'Production component changes are attributable and logged',
                         'remediation_hint': 'Restore complete production change and Activity Log capture, '
                                             'correlate each change to the contributing person/service '
                                             'identity, and repair missing audit fields or deployment '
                                             'records.',
                         'proposed_spec_sha256': 'ae76068a09b4f8bf3049933dd78cf1d40f7840f1543ce556f9a5171e4b565b75'}}


_ACCEPTED = {"hardening", "exposure", "least_privilege", "iam_graph", "network"}
_SCOPE = re.compile(r"/subscriptions/[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$", re.I)
_TLS = {"1.0": 10, "1.1": 11, "1.2": 12, "1.3": 13}


def signed(check_id, *dependencies):
    spec = SPECS[check_id]
    def decorate(function):
        category = spec["category"]
        registered = register(check_id, "azure", category if category in _ACCEPTED else "hardening",
                              spec["resource_kind"], spec["title"], spec["severity"], "CM-6",
                              spec["remediation_hint"], target="scope", dependencies=list(dependencies))(function)
        if category not in _ACCEPTED:
            CHECKS[-1] = replace(CHECKS[-1], category=category)
        return registered
    return decorate


def _scope(index):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "azure":
        raise Unavailable("foreign provider")
    scope = get(context, "scope", str)
    if not _SCOPE.fullmatch(scope):
        raise Unavailable("invalid subscription scope")
    return scope.casefold()


def _rows(index, kind):
    scope = _scope(index)
    envelopes = get(index, "collections", dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable("missing or ambiguous scoped collection: " + kind)
    envelope = envelopes[0]
    if get(envelope, "type", str) != kind or get(envelope, "scope", str).casefold() != scope:
        raise Unavailable("foreign collection: " + kind)
    rows = complete_items(index, kind)
    native = get(envelope, "items", list)
    wrappers = get(index, kind, list)
    if rows != native or len(rows) != len(wrappers) or (get(envelope, "status", str) == "empty") != (not rows):
        raise Unavailable("inconsistent collection projection: " + kind)
    seen = set()
    for row, wrapper in zip(rows, wrappers):
        if get(wrapper, "type", str) != kind or get(wrapper, "scope", str).casefold() != scope or get(wrapper, "data", dict) != row:
            raise Unavailable("foreign or malformed resource wrapper")
        rid = get(row, "id", str)
        if not rid or rid.casefold() in seen:
            raise Unavailable("missing or duplicate resource identity")
        seen.add(rid.casefold())
        if kind == "pod" and rid.startswith("k8s://"):
            cluster = get(row, "_provenance.cluster_id", str)
            namespace = get(row, "metadata.namespace", str)
            uid = get(row, "metadata.uid", str)
            if (not re.fullmatch(re.escape(scope) + r"/resourcegroups/[^/]+/providers/microsoft\.containerservice/managedclusters/[^/]+", cluster.casefold())
                    or cluster != cluster.casefold()
                    or get(row, "provenance.cluster_id", str) != cluster
                    or get(row, "provenance.namespace", str) != namespace
                    or get(row, "provenance.uid", str) != uid
                    or get(row, "_provenance.source_operation", str) != "list_pods"
                    or rid != "k8s://" + "/".join(quote(x, safe="") for x in (cluster, "pod", namespace, uid))):
                raise Unavailable("foreign or malformed AKS pod identity")
        elif kind != "activity_log" and not rid.casefold().startswith(scope + "/"):
            raise Unavailable("foreign resource identity")
        if kind == "activity_log":
            target = get(row, "resourceId", str)
            if not target.casefold().startswith(scope + "/"):
                raise Unavailable("foreign activity target")
    return rows


def _policy(index, check_id):
    scope = _scope(index)
    entry = get(index, "context.metadata.compliance_policy.sw26", dict)
    if get(entry, "scope", str).casefold() != scope or get(entry, "status", str) != "collected":
        raise Unavailable("policy unavailable or foreign")
    coverage = entry.get('_coverage', {})
    if check_id in coverage:
        state = coverage[check_id]
        if not isinstance(state, dict) or state.get('status') != 'collected':
            raise Unavailable('per-check policy coverage unavailable')
    policy = entry.get(check_id)
    if not isinstance(policy, dict):
        raise Unavailable("check policy unavailable")
    return policy


def _target(item, index):
    if get(item, "scope", str).casefold() != _scope(index):
        raise Unavailable("foreign scope target")


def _state(value, allowed):
    if value not in allowed:
        raise Unavailable("unrecognized state")
    return value


def _list(value, typ=str):
    if not isinstance(value, list) or any(type(x) is not typ if typ in (int, bool) else not isinstance(x, typ) for x in value):
        raise Unavailable("malformed list")
    return value


def _ids(values):
    return {x.casefold() for x in _list(values) if x}


def _when(value):
    if not isinstance(value, str):
        raise Unavailable("missing timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Unavailable("invalid timestamp") from exc
    if parsed.utcoffset() is None:
        raise Unavailable("timestamp lacks timezone")
    return parsed.astimezone(timezone.utc)


def _tls_policy(index, cid):
    policy = _policy(index, cid)
    captured = _when(get(index, "context.created_at", str))
    if _when(get(policy, "valid_until", str)) < captured:
        raise Unavailable("supported TLS policy stale")
    latest = _TLS.get(get(policy, "latest_supported", str))
    minimum = _TLS.get(get(policy, "organization_minimum", str))
    if latest is None or minimum is None or minimum > latest:
        raise Unavailable("unsupported TLS policy")
    return max(latest, minimum)


def _site_configs(index):
    sites = _rows(index, "app_service")
    configs = _rows(index, "app_service_config")
    by_parent = {}
    for config in configs:
        parent = get(config, "parent_id", str).casefold()
        if parent in by_parent or get(config, "id", str).casefold() != parent + "/config/web":
            raise Unavailable("ambiguous or foreign site config")
        by_parent[parent] = config
    site_ids = {get(site, "id", str).casefold() for site in sites}
    if not set(by_parent) <= site_ids:
        raise Unavailable("orphan site config")
    return sites, by_parent


def _tls_results(index, cid, *, api_only):
    floor = _tls_policy(index, cid)
    policy = _policy(index, cid)
    sites, configs = _site_configs(index)
    bad, applicable = [], []
    for site in sites:
        rid = get(site, "id", str).casefold()
        kind = get(site, "kind", str).casefold()
        if api_only and not any(token in kind for token in ("app", "functionapi")):
            continue
        if not kind or "site" not in kind and "app" not in kind and "function" not in kind:
            raise Unavailable("unsupported App Service kind")
        config = configs.get(rid)
        if config is None:
            raise Unavailable("site config missing")
        required = floor
        if cid == "azure.other.app_latest_tls":
            runtime = get(site, "runtimeId", str)
            versions = get(policy, "supportedTlsByRuntime", dict)
            supported = _TLS.get(versions.get(runtime))
            minimum = _TLS.get(get(policy, "organization_minimum", str))
            if supported is None or minimum is None:
                raise Unavailable("runtime-specific supported TLS version unresolved")
            required = max(supported, minimum)
        version = _TLS.get(get(config, "properties.minTlsVersion", str))
        if version is None:
            raise Unavailable("unrecognized site TLS token")
        applicable.append(rid)
        if version < required:
            bad.append(rid)
        if cid == "azure.other.app_latest_tls" and get(policy, "scm_in_scope", bool):
            scm = _TLS.get(get(config, "properties.scmMinTlsVersion", str))
            if scm is None:
                raise Unavailable("SCM TLS setting unavailable")
            if scm < required:
                bad.append(rid + ":scm")
    if not applicable:
        return "NOT_APPLICABLE", {"reason": "no applicable sites in complete inventory"}
    return result(bool(bad), affected_sites=bad, checked_sites=applicable, required_tls=floor)


@signed("azure.gap.appservice_api_app_latest_tls_version", "app_service", "app_service_config")
def api_app_tls(item, index):
    _target(item, index)
    return _tls_results(index, "azure.gap.appservice_api_app_latest_tls_version", api_only=True)


@signed("azure.other.app_latest_tls", "app_service", "app_service_config")
def app_latest_tls(item, index):
    _target(item, index)
    # Runtime-specific support and SCM coverage must be attested in the policy.
    policy = _policy(index, "azure.other.app_latest_tls")
    if (get(policy, "runtime_support_complete", bool) is not True or
            not get(policy, "supported_version_source", str)):
        raise Unavailable("runtime support or SCM endpoint coverage unresolved")
    return _tls_results(index, "azure.other.app_latest_tls", api_only=False)


@signed("azure_c5_pi_01_02ac", "app_service")
def customer_federation(item, index):
    _target(item, index)
    cid = "azure_c5_pi_01_02ac"
    policy = _policy(index, cid)
    required = _ids(get(policy, "customer_federated_app_ids", list))
    sites = {get(row, "id", str).casefold(): row for row in _rows(index, "app_service")}
    if not required:
        return "NOT_APPLICABLE", {"reason": "no customer-federated apps in complete policy"}
    if not required <= sites.keys():
        raise Unavailable("customer-federated app absent from site inventory")
    bad = []
    for rid in sorted(required):
        auth = get(sites[rid], "authSettingsV2.properties", dict)
        platform = get(auth, "platform.enabled", bool)
        require = get(auth, "globalValidation.requireAuthentication", bool)
        paths = _list(get(auth, "globalValidation.excludedPaths", list))
        provider = get(auth, "identityProviders.azureActiveDirectory", dict)
        enabled = get(provider, "enabled", bool)
        registration = get(provider, "registration.clientId", str)
        interface = get(policy, "interfaces", dict).get(rid)
        if not isinstance(interface, dict) or get(interface, "status", str) != "collected":
            raise Unavailable("federated interface evidence unavailable")
        protocol = get(interface, "protocol", str)
        if protocol not in ("OIDC", "SAML"):
            raise Unavailable("unsupported federation protocol")
        tested = get(interface, "tested", bool)
        present = get(interface, "present", bool)
        if not platform or not require or paths or not enabled or not registration or not present:
            bad.append(rid)
        elif not tested:
            raise Unavailable("federated interface test missing")
    return result(bool(bad), affected_sites=bad, checked_sites=sorted(required))


@signed("azure_cdn_profile_1_2_8_5_ed953a0", "cdn_profile")
def cdn_customer_cert(item, index):
    _target(item, index)
    profiles = _rows(index, "cdn_profile")
    bad, checked = [], []
    for profile in profiles:
        sku = get(profile, "sku.name", str)
        afd = sku in {"Standard_AzureFrontDoor", "Premium_AzureFrontDoor"}
        if not afd and sku not in {"Standard_Verizon", "Premium_Verizon", "Standard_Microsoft", "Standard_Akamai", "Standard_ChinaCdn"}:
            raise Unavailable("unsupported CDN profile type")
        domains = list_of_objects(get(profile, "customDomains", list))
        if get(profile, "_coverage.customDomains.status", str) not in ("collected", "empty"):
            raise Unavailable("custom domain paging incomplete")
        for domain in domains:
            did = get(domain, "id", str)
            if afd:
                if not did.casefold().startswith(get(profile, "id", str).casefold() + "/customdomains/"):
                    raise Unavailable("foreign Front Door custom domain")
                props = get(domain, "properties", dict)
                if (get(props, "provisioningState", str) != "Succeeded" or
                        get(props, "deploymentStatus", str) != "Succeeded" or
                        get(props, "domainValidationState", str) != "Approved"):
                    raise Unavailable("Front Door certificate activation unresolved")
                certificate_type = get(props, "tlsSettings.certificateType", str)
                _state(certificate_type, {"ManagedCertificate", "CustomerCertificate"})
                checked.append(did)
                if certificate_type != "CustomerCertificate":
                    bad.append(did)
                continue
            if not did.casefold().startswith(get(profile, "id", str).casefold() + "/endpoints/"):
                raise Unavailable("foreign CDN custom domain")
            state = get(domain, "properties.customHttpsProvisioningState", str)
            _state(state, {"Enabled", "Disabled", "Enabling", "Disabling", "Failed"})
            source = get(domain, "properties.customHttpsParameters.certificateSource", str)
            _state(source, {"Cdn", "AzureKeyVault"})
            checked.append(did)
            if state in {"Disabled", "Failed"} or source == "Cdn":
                bad.append(did)
            elif state != "Enabled":
                raise Unavailable("CDN HTTPS provisioning transitional")
    if not checked:
        return "NOT_APPLICABLE", {"reason": "no applicable custom domains"}
    return result(bool(bad), affected_domains=bad, checked_domains=checked)


def _ranges(value):
    rows = list_of_objects(value)
    if not rows:
        raise Unavailable("approved ID ranges absent")
    pairs = []
    for row in rows:
        lo, hi = get(row, "min", int), get(row, "max", int)
        if lo < 0 or hi < lo:
            raise Unavailable("invalid approved ID range")
        pairs.append((lo, hi))
    return pairs


def _approved(value, ranges):
    if type(value) is not int or value < 0:
        raise Unavailable("effective user/group ID unavailable")
    return any(lo <= value <= hi for lo, hi in ranges)


@signed("azure.gap.kubernetes_cluster_pods_and_containers_uses_approved_user_and_group_id", "pod")
def pod_identity(item, index):
    _target(item, index)
    cid = "azure.gap.kubernetes_cluster_pods_and_containers_uses_approved_user_and_group_id"
    policy = _policy(index, cid)
    uids = _ranges(get(policy, "approved_uid_ranges", list))
    gids = _ranges(get(policy, "approved_gid_ranges", list))
    pods = _rows(index, "pod")
    bad, linux = [], []
    for pod in pods:
        rid = get(pod, "id", str)
        # Kubernetes treats a Pod without spec.os as a Linux Pod.
        os_name = optional(optional(get(pod, "spec", dict), "os", {}, dict), "name", "linux", str)
        if os_name == "windows":
            continue
        if os_name != "linux":
            raise Unavailable("pod OS applicability unresolved")
        linux.append(rid)
        security = get(pod, "spec.securityContext", dict)
        fs = get(security, "effectiveFsGroup", int)
        groups = _list(get(security, "effectiveSupplementalGroups", list), int)
        if get(security, "supplementalGroupsPolicy", str) not in ("Strict", "Merge"):
            raise Unavailable("supplemental group policy unresolved")
        if not _approved(fs, gids) or any(not _approved(group, gids) for group in groups):
            bad.append(rid)
        for field in ("containers", "initContainers", "ephemeralContainers"):
            for container in list_of_objects(get(pod, "spec." + field, list)):
                name = get(container, "name", str)
                uid = get(container, "effectiveIdentity.uid", int)
                gid = get(container, "effectiveIdentity.gid", int)
                effective_groups = _list(get(container, "effectiveIdentity.supplementalGroups", list), int)
                if not _approved(uid, uids) or not _approved(gid, gids) or any(not _approved(g, gids) for g in effective_groups):
                    bad.append(rid + ":" + name)
    if not linux:
        return "NOT_APPLICABLE", {"reason": "no Linux pods in complete inventory"}
    return result(bool(bad), affected=bad, checked_linux_pods=linux)


@signed("azure_aks_cluster_1_4_5_2_3ac7b3c", "pod", "container_group")
def host_pid(item, index):
    _target(item, index)
    pods = _rows(index, "pod")
    groups = _rows(index, "container_group")
    bad = []
    for pod in pods:
        rid = get(pod, "id", str)
        # The Kubernetes API defaults an omitted hostPID to false only on a full pod representation.
        representation = get(pod, "_provenance.representation", str)
        if representation != "full":
            raise Unavailable("pod representation incomplete")
        spec = get(pod, "spec", dict)
        host = optional(spec, "hostPID", False, bool)
        if host:
            bad.append(rid)
    unresolved_aci = False
    for group in groups:
        try:
            if get(group, "hostProcessEvidence.status", str) != "collected":
                unresolved_aci = True
                continue
            sharing = get(group, "hostProcessEvidence.sharesHostPid", bool)
        except Unavailable:
            unresolved_aci = True
            continue
        if sharing:
            bad.append(get(group, "id", str))
    if bad:
        return result(True, affected=bad, checked_pods=len(pods), checked_aci=len(groups))
    if unresolved_aci:
        raise Unavailable("ACI host process sharing evidence unavailable")
    if not pods and not groups:
        return "NOT_APPLICABLE", {"reason": "no applicable pods or ACI groups"}
    return result(bool(bad), affected=bad, checked_pods=len(pods), checked_aci=len(groups))


@signed("azure_aks_cluster_3_5_1_14_247ebcd", "pod", "container_group")
def literal_secret_env(item, index):
    _target(item, index)
    policy = _policy(index, "azure_aks_cluster_3_5_1_14_247ebcd")
    keys = {key.casefold() for key in _list(get(policy, "secretKeys", list)) if key}
    if not keys:
        raise Unavailable("secret-key policy absent")
    pods, groups = _rows(index, "pod"), _rows(index, "container_group")
    bad, matching = [], []
    for pod in pods:
        if get(pod, "_provenance.representation", str) != "full":
            raise Unavailable("pod representation incomplete")
        for field in ("containers", "initContainers", "ephemeralContainers"):
            for container in list_of_objects(get(pod, "spec." + field, list)):
                for env in list_of_objects(get(container, "env", list)):
                    name = get(env, "name", str)
                    if name.casefold() not in keys:
                        continue
                    ref = get(pod, "id", str) + ":" + get(container, "name", str) + ":" + name
                    matching.append(ref)
                    if "value" in env:
                        get(env, "value", str)
                        bad.append(ref)
                    else:
                        source = get(env, "valueFrom", dict)
                        if "secretKeyRef" in source:
                            secret = get(source, "secretKeyRef", dict)
                            if not get(secret, "name", str) or not get(secret, "key", str):
                                raise Unavailable("unresolved Kubernetes secret reference")
                        elif (get(env, "externalSecretEvidence.status", str) != "collected" or
                              get(env, "externalSecretEvidence.approved", bool) is not True):
                            raise Unavailable("external Kubernetes secret source unresolved")
    for group in groups:
        for container in list_of_objects(get(group, "properties.containers", list)):
            for env in list_of_objects(get(container, "properties.environmentVariables", list)):
                name = get(env, "name", str)
                if name.casefold() not in keys:
                    continue
                ref = get(group, "id", str) + ":" + get(container, "name", str) + ":" + name
                matching.append(ref)
                if "value" in env:
                    get(env, "value", str)
                    bad.append(ref)
                elif get(env, "secureReferenceEvidence.status", str) != "collected" or get(env, "secureReferenceEvidence.approved", bool) is not True:
                    raise Unavailable("ACI secure reference unresolved")
    return result(bool(bad), affected=bad, matching_keys=matching)


def _complete_paths(entry, required):
    if get(entry, "status", str) != "collected":
        raise Unavailable("access-path assessment incomplete")
    paths = get(entry, "paths", dict)
    observed = {}
    for name in required:
        row = get(paths, name, dict)
        if get(row, "status", str) != "collected":
            raise Unavailable("access path unresolved: " + name)
        observed[name] = get(row, "effective_access", bool)
    return observed


@signed("azure.other.blob_uniform_deny", "storage_container")
def blob_uniform_deny(item, index):
    _target(item, index)
    policy = _policy(index, "azure.other.blob_uniform_deny")
    protected = _ids(get(policy, "protectedContainerIds", list))
    denied = _ids(get(policy, "deniedPrincipalIds", list))
    containers = {get(x, "id", str).casefold(): x for x in _rows(index, "storage_container")}
    if not protected:
        return "NOT_APPLICABLE", {"reason": "no protected containers"}
    if not denied or not protected <= containers.keys():
        raise Unavailable("denied principals or protected container inventory unresolved")
    bad = []
    for rid in sorted(protected):
        matrix = get(containers[rid], "effectiveBlobRead", dict)
        for principal in sorted(denied):
            entry = get(matrix, principal, dict)
            if get(entry, "principalId", str).casefold() != principal or get(entry, "containerId", str).casefold() != rid:
                raise Unavailable("foreign Blob access assessment")
            paths = _complete_paths(entry, ("rbac", "container_acl", "hns_acl", "sas", "account_key", "data_plane"))
            if any(paths.values()):
                bad.append({"container": rid, "principal": principal})
    return result(bool(bad), effective_readers=bad)


@signed("azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_3f8ed7f", "storage_container")
def cross_tenant_blob(item, index):
    _target(item, index)
    policy = _policy(index, "azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_3f8ed7f")
    allowed = _ids(get(policy, "approvedTenantIds", list))
    if not allowed:
        raise Unavailable("approved tenant policy absent")
    containers = _rows(index, "storage_container")
    if not containers:
        return "NOT_APPLICABLE", {"reason": "no storage containers"}
    bad = []
    for container in containers:
        rid = get(container, "id", str)
        public = _state(get(container, "properties.publicAccess", str), {"None", "Blob", "Container"})
        if public != "None":
            bad.append({"container": rid, "path": "public"})
        assessment = get(container, "crossTenantAccess", dict)
        if get(assessment, "status", str) != "collected":
            raise Unavailable("cross-tenant access assessment incomplete")
        for row in list_of_objects(get(assessment, "principals", list)):
            tenant = get(row, "homeTenantId", str).casefold()
            paths = _complete_paths(row, ("rbac", "acl", "sas", "account_key", "data_plane"))
            if tenant not in allowed and any(paths.values()):
                bad.append({"container": rid, "tenant": tenant})
        if get(assessment, "allPrincipalPathsEnumerated", bool) is not True:
            raise Unavailable("SAS/key or principal coverage incomplete")
    return result(bool(bad), disallowed_access=bad)


@signed("azure.other.log_writer_separation", "diagnostic_setting")
def log_writer_separation(item, index):
    _target(item, index)
    policy = _policy(index, "azure.other.log_writer_separation")
    sources = _ids(get(policy, "sourceWorkloadPrincipalIds", list))
    if not sources:
        raise Unavailable("source workload policy absent")
    settings = _rows(index, "diagnostic_setting")
    if not settings:
        raise Unavailable("no diagnostic sinks prove log isolation")
    bad = []
    for setting in settings:
        rid = get(setting, "id", str)
        sinks = list_of_objects(get(setting, "resolvedSinks", list))
        if not sinks:
            raise Unavailable("diagnostic sink unresolved")
        for sink in sinks:
            sink_id = get(sink, "id", str)
            if get(sink, "status", str) != "collected":
                raise Unavailable("log sink unresolved")
            access = get(sink, "sourceAccess", dict)
            for principal in sources:
                entry = get(access, principal, dict)
                if get(entry, "principalId", str).casefold() != principal or get(entry, "sinkId", str).casefold() != sink_id.casefold():
                    raise Unavailable("foreign log sink access assessment")
                paths = _complete_paths(entry, ("rbac", "groups", "workspace", "storage_acl", "sas", "shared_key", "alternate"))
                if any(paths.values()):
                    bad.append({"setting": rid, "sink": sink_id, "principal": principal})
    return result(bool(bad), source_log_access=bad)


def _enumeration_identity(value, label):
    if not isinstance(value, str) or not value or value != value.strip():
        raise Unavailable(label + " missing or malformed")
    return value


def _enumeration_source(index, kind, policy, start, end, captured, source_id, operation, sink_id=None):
    """External complete-window observation, never inferred from ARM diagnostics."""
    envelopes = get(index, "collections", dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable("independent enumeration source collection missing")
    proof = get(envelopes[0], "_provenance", dict)
    metadata = get(index, "context.metadata", dict)
    for field in ("credential_context_id", "customer_context_id"):
        if _enumeration_identity(get(proof, field, str), field) != _enumeration_identity(get(metadata, field, str), field):
            raise Unavailable("enumeration source capture/customer mismatch")
    if (get(proof, "sourceOperation", str) != operation
            or get(proof, "readOnly", bool) is not True
            or get(proof, "sourceId", str) != source_id
            or get(proof, "scope", str).casefold() != _scope(index)):
        raise Unavailable("enumeration independent source authority unresolved")
    _enumeration_identity(get(proof, "observer", str), "observer")
    _enumeration_identity(get(proof, "authorizationDocumentId", str), "authorization document")
    coverage = get(proof, "coverage", dict)
    if (get(coverage, "status", str) != "complete"
            or _when(get(coverage, "windowStart", str)) != start
            or _when(get(coverage, "windowEnd", str)) != end):
        raise Unavailable("enumeration source window incomplete or foreign")
    observed = _when(get(proof, "observedAt", str))
    if not end <= observed <= captured:
        raise Unavailable("enumeration source observation stale or future")
    if sink_id is not None and get(proof, "sinkId", str).casefold() != sink_id.casefold():
        raise Unavailable("enumeration persisted source sink mismatch")


@signed("azure.other.enumeration_logging", "diagnostic_setting", "enumeration_event", "enumeration_log_record")
def enumeration_logging(item, index):
    _target(item, index)
    policy = _policy(index, "azure.other.enumeration_logging")
    start = _when(get(policy, "window_start", str))
    end = _when(get(policy, "window_end", str))
    captured = _when(get(index, "context.created_at", str))
    delay = get(policy, "delivery_delay_seconds", int)
    if type(delay) is not int or delay < 0 or not start < end or end.timestamp() + delay > captured.timestamp():
        raise Unavailable("observation or delivery window unresolved")
    event_source = _enumeration_identity(get(policy, "eventSourceId", str), "event source")
    log_source = _enumeration_identity(get(policy, "logSourceId", str), "log source")
    if event_source == log_source:
        raise Unavailable("enumeration event and persisted-log sources not independent")
    approved_sinks = get(policy, "approvedSinkIds", list)
    if (not approved_sinks or any(not isinstance(s, str) or not s or s != s.strip() for s in approved_sinks)
            or len({s.casefold() for s in approved_sinks}) != len(approved_sinks)):
        raise Unavailable("approved enumeration sink identity unresolved")
    sink_id = _enumeration_identity(get(policy, "observedSinkId", str), "observed sink")
    if sink_id.casefold() not in {s.casefold() for s in approved_sinks}:
        raise Unavailable("enumeration observed sink not approved")
    _rows(index, "diagnostic_setting")
    events = _rows(index, "enumeration_event")
    records = _rows(index, "enumeration_log_record")
    _enumeration_source(index, "enumeration_event", policy, start, end, captured,
                        event_source, "external_independent_event_inventory")
    log_end = datetime.fromtimestamp(end.timestamp() + delay, timezone.utc)
    _enumeration_source(index, "enumeration_log_record", policy, start, log_end, captured,
                        log_source, "external_persisted_sink_read", sink_id)
    if not events:
        return unknown("no independent enumeration events to verify")
    by_event = {}
    for row in records:
        eid = _enumeration_identity(get(row, "eventId", str), "persisted event identity")
        if eid in by_event:
            raise Unavailable("duplicate persisted enumeration record")
        if get(row, "sinkId", str).casefold() != sink_id.casefold():
            raise Unavailable("persisted enumeration record has foreign sink")
        by_event[eid] = row
    bad = []
    seen_event_ids = set()
    for event in events:
        eid = _enumeration_identity(get(event, "eventId", str), "independent event identity")
        if eid in seen_event_ids:
            raise Unavailable("duplicate independent enumeration event identity")
        seen_event_ids.add(eid)
        occurred = _when(get(event, "timestamp", str))
        if not start <= occurred < end:
            raise Unavailable("enumeration event outside observation window")
        identity = _enumeration_identity(get(event, "clientIdentity", str), "event client identity")
        nature = _enumeration_identity(get(event, "activityNature", str), "event nature")
        record = by_event.get(eid)
        if record is None:
            bad.append(eid)
            continue
        if "resourceId" in event or "resourceId" in record:
            event_resource = _enumeration_identity(get(event, "resourceId", str), "event resource identity")
            record_resource = _enumeration_identity(get(record, "resourceId", str), "persisted resource identity")
            if (not event_resource.casefold().startswith(_scope(index) + "/")
                    or record_resource.casefold() != event_resource.casefold()):
                raise Unavailable("enumeration event resource correlation unresolved")
        persisted = _when(get(record, "persistedAt", str))
        if not occurred <= persisted <= captured:
            raise Unavailable("persisted enumeration observation time inconsistent")
        if (get(record, "clientIdentity", str) != identity or
                _when(get(record, "timestamp", str)) != occurred or
                get(record, "activityNature", str) != nature or
                persisted.timestamp() > occurred.timestamp() + delay):
            bad.append(eid)
    return result(bool(bad), unmatched_events=bad, checked_events=len(events), observed_sink_id=sink_id)


def _permission_patterns(role):
    if get(role, "properties.type", str) != "CustomRole":
        return []
    scopes = _list(get(role, "properties.assignableScopes", list))
    if not scopes:
        raise Unavailable("custom role assignable scopes absent")
    out = []
    for permission in list_of_objects(get(role, "properties.permissions", list)):
        for positive, negative in (("actions", "notActions"), ("dataActions", "notDataActions")):
            grants = _list(get(permission, positive, list))
            excluded = _list(get(permission, negative, list))
            out.append((positive, grants, excluded))
    return out


def _operation_catalog(index, cid):
    policy = _policy(index, cid)
    if get(policy, "operationCatalogStatus", str) != "collected":
        raise Unavailable("provider operation catalog incomplete")
    operations = _list(get(policy, "providerOperations", list))
    if not operations:
        raise Unavailable("provider operation catalog empty")
    return policy, operations


def _effective(grant, excluded, operation):
    import fnmatch
    return (fnmatch.fnmatchcase(operation.casefold(), grant.casefold()) and
            not any(fnmatch.fnmatchcase(operation.casefold(), pattern.casefold()) for pattern in excluded))


@signed("azure_role_assignment_aks_cluster_rbac_enabled_1c8eacd", "role_definition")
def custom_role_wildcards(item, index):
    _target(item, index)
    cid = "azure_role_assignment_aks_cluster_rbac_enabled_1c8eacd"
    policy, operations = _operation_catalog(index, cid)
    protected = _ids(get(policy, "protectedScopes", list))
    if not protected:
        raise Unavailable("protected scope policy absent")
    roles = _rows(index, "role_definition")
    bad = []
    for role in roles:
        rid = get(role, "id", str)
        patterns = _permission_patterns(role)
        if not patterns:
            continue
        scopes = _ids(get(role, "properties.assignableScopes", list))
        if not any(any(protected_scope.startswith(scope) or scope.startswith(protected_scope)
                       for scope in scopes) for protected_scope in protected):
            continue
        for family, grants, excluded in patterns:
            for grant in grants:
                if not grant.endswith("/*") and grant != "*":
                    continue
                prefix = grant[:-2].casefold() if grant != "*" else ""
                matching = [op for op in operations if op.casefold().startswith(prefix + "/") or grant == "*"]
                if matching and all(_effective(grant, excluded, op) for op in matching):
                    bad.append({"role": rid, "permission": grant, "family": family})
    return result(bool(bad), provider_wildcards=bad, checked_roles=len(roles))


@signed("azure_vault_keyvault_rbac_enabled_0179c48", "role_definition", "role_assignment")
def keyvault_blocked_actions(item, index):
    _target(item, index)
    cid = "azure_vault_keyvault_rbac_enabled_0179c48"
    policy, operations = _operation_catalog(index, cid)
    blocked = _list(get(policy, "blockedKeyVaultActions", list))
    protected = _ids(get(policy, "protectedVaultIds", list))
    if not blocked or not protected:
        raise Unavailable("blocked Key Vault action or vault policy absent")
    roles = {get(row, "id", str).casefold(): row for row in _rows(index, "role_definition")}
    assignments = _rows(index, "role_assignment")
    relevant = set()
    for assignment in assignments:
        assigned_scope = get(assignment, "properties.scope", str).casefold()
        if not any(vault.startswith(assigned_scope) or assigned_scope.startswith(vault) for vault in protected):
            continue
        if get(assignment, "properties.conditionVersion", str) not in ("", "2.0") or get(assignment, "properties.condition", str):
            raise Unavailable("conditional role assignment unresolved")
        role_id = get(assignment, "properties.roleDefinitionId", str).casefold()
        if role_id not in roles:
            raise Unavailable("assigned custom role definition missing")
        relevant.add(role_id)
    bad = []
    for role_id in relevant:
        for family, grants, excluded in _permission_patterns(roles[role_id]):
            for action in blocked:
                matched = [op for op in operations if _effective(action, [], op)]
                if not matched:
                    raise Unavailable("blocked action absent from operation catalog")
                if any(any(_effective(grant, excluded, op) for grant in grants) for op in matched):
                    bad.append({"role": role_id, "blocked_action": action, "family": family})
    return result(bool(bad), prohibited_actions=bad, checked_assigned_roles=len(relevant))


@signed("azure_cdn_profile_10_3_4_1_4e40487", "cdn_profile")
def frontdoor_blob_identity(item, index):
    _target(item, index)
    profiles = _rows(index, "cdn_profile")
    bad, checked = [], []
    for profile in profiles:
        sku = get(profile, "sku.name", str)
        if sku in {"Standard_Verizon", "Premium_Verizon", "Standard_Microsoft", "Standard_Akamai", "Standard_ChinaCdn"}:
            continue
        if sku not in ("Standard_AzureFrontDoor", "Premium_AzureFrontDoor"):
            raise Unavailable("unsupported Front Door product generation")
        identity_config = get(profile, "identity", dict)
        if get(profile, "_coverage.routes.status", str) not in ("collected", "empty"):
            raise Unavailable("Front Door route paging incomplete")
        routes = list_of_objects(get(profile, "routes", list))
        groups = {get(x, "id", str).casefold(): x for x in list_of_objects(get(profile, "originGroups", list))}
        if get(profile, "_coverage.originGroups.status", str) not in ("collected", "empty"):
            raise Unavailable("origin group paging incomplete")
        for route in routes:
            group_id = get(route, "properties.originGroup.id", str).casefold()
            group = groups.get(group_id)
            if group is None:
                raise Unavailable("route origin group unresolved")
            prereq = get(route, "originAuthenticationPrerequisites", dict)
            if get(prereq, "status", str) != "collected":
                raise Unavailable("Front Door origin authentication prerequisites unresolved")
            for origin in list_of_objects(get(group, "origins", list)):
                container = get(origin, "blobContainerEvidence", dict)
                if get(container, "status", str) != "collected":
                    raise Unavailable("Blob origin identity unresolved")
                applies = get(container, "isContainer", bool)
                required = get(container, "requiredByPolicy", bool)
                if not applies:
                    if required:
                        rid = get(origin, "id", str)
                        checked.append(rid)
                        bad.append(rid)
                    continue
                rid = get(origin, "id", str)
                checked.append(rid)
                properties = get(group, "properties", dict)
                auth = properties.get("authentication")
                if auth is None:
                    if get(group, "_provenance.representation", str) != "full":
                        raise Unavailable("origin authentication availability unresolved")
                    bad.append(rid)
                    continue
                if not isinstance(auth, dict):
                    raise Unavailable("malformed origin authentication")
                mode = get(auth, "type", str)
                scope = get(auth, "scope", str)
                if mode == "SystemAssignedIdentity":
                    if "SystemAssigned" not in get(identity_config, "type", str):
                        raise Unavailable("system identity not enabled on profile")
                    principal = get(identity_config, "principalId", str)
                elif mode == "UserAssignedIdentity":
                    user_id = get(auth, "userAssignedIdentity.id", str).casefold()
                    identities = get(identity_config, "userAssignedIdentities", dict)
                    if user_id not in {key.casefold() for key in identities}:
                        raise Unavailable("user identity not assigned to profile")
                    principal = get(next(value for key, value in identities.items() if key.casefold() == user_id),
                                    "principalId", str)
                else:
                    raise Unavailable("unsupported origin authentication type")
                rbac = get(origin, "blobRbacEvidence", dict)
                if get(rbac, "status", str) != "collected" or get(rbac, "principalId", str) != principal:
                    raise Unavailable("Blob RBAC unresolved")
                if (scope != "https://storage.azure.com/.default" or
                    optional(auth, "tokenDestinationHeader", "Authorization", str) != "Authorization" or
                    get(prereq, "forwardingHttpsOnly", bool) is not True or
                    get(prereq, "originGroupProbeHttps", bool) is not True or
                    get(prereq, "noPrivateLink", bool) is not True or
                    get(rbac, "dataReader", bool) is not True):
                    bad.append(rid)
    if not checked:
        return "NOT_APPLICABLE", {"reason": "no Blob container origins"}
    return result(bool(bad), affected_origins=bad, checked_origins=checked)


@signed("azure_c5_dev_08_02b", "activity_log", "production_change")
def production_change_attribution(item, index):
    _target(item, index)
    policy = _policy(index, "azure_c5_dev_08_02b")
    start, end = _when(get(policy, "window_start", str)), _when(get(policy, "window_end", str))
    if not start < end:
        raise Unavailable("invalid production change window")
    if end > _when(get(index, "context.created_at", str)):
        raise Unavailable("production change window has not closed at snapshot capture")
    from peaso.collectors.azure_wave_change_native import (
        ActivityCoverageError, validate_native_activity_if_present,
    )
    try:
        validate_native_activity_if_present(
            index, _scope(index), policy["window_start"], policy["window_end"]
        )
    except ActivityCoverageError as exc:
        raise Unavailable(str(exc)) from exc
    protected = _ids(get(policy, "productionResourceIds", list))
    if not protected:
        raise Unavailable("production resource policy absent")
    if any(not rid.startswith(_scope(index) + "/") for rid in protected):
        raise Unavailable("foreign production resource policy")
    activity = _rows(index, "activity_log")
    changes = _rows(index, "production_change")
    if not changes:
        return unknown("zero production changes cannot prove complete attribution")
    if get(policy, "dataPlaneChangesComplete", bool) is not True:
        raise Unavailable("data-plane change inventory incomplete")
    by_correlation = {}
    for row in activity:
        cid = get(row, "correlationId", str)
        if not cid.strip():
            raise Unavailable("Activity Log correlation identity absent")
        rid = get(row, "resourceId", str).casefold()
        key = (cid, rid)
        if key in by_correlation:
            raise Unavailable("ambiguous production Activity Log join")
        by_correlation[key] = row
    scoped_changes = []
    for change in changes:
        rid = get(change, "resourceId", str).casefold()
        when = _when(get(change, "timestamp", str))
        if rid not in protected or not start <= when < end:
            raise Unavailable("production change scope or time unresolved")
        cid = get(change, "correlationId", str)
        if not cid.strip():
            raise Unavailable("production change correlation identity absent")
        scoped_changes.append((change, rid, when, cid, get(change, "id", str)))
    bad = []
    unresolved = []
    for change, rid, when, cid, change_id in scoped_changes:
        try:
            state = get(change, "status", str)
        except Unavailable:
            unresolved.append(change_id)
            continue
        if state != "Succeeded":
            unresolved.append(change_id)
            continue
        actor = optional(change, "actorId", "", str)
        log = by_correlation.get((cid, rid))
        if not actor.strip() or log is None:
            bad.append(change_id)
            continue
        if (optional(log, "caller", "", str) != actor or
                get(log, "operationName.value", str).split("/")[-1].casefold() not in ("write", "delete") or
                get(log, "status.value", str) != "Succeeded" or
                _when(get(log, "eventTimestamp", str)) != when):
            bad.append(change_id)
    details = {"unattributed_changes": bad, "unresolved_changes": unresolved,
               "checked_changes": len(changes)}
    if bad:
        return result(True, **details)
    if unresolved:
        return unknown("change success state unresolved", **details)
    return result(False, **details)
