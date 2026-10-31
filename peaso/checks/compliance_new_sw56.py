"""Signed Kubernetes admission and image checks (sw56).

Admission decisions use only recognized CEL declarations and complete, cluster-bound
API inventories. Unknown CEL semantics never establish enforcement or absence.
"""
from __future__ import annotations

import json
import re
from dataclasses import replace
from datetime import datetime

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, memoized

SPECS = {'k8s.cis.admission_allowprivilegeescalation': {'category': 'hardening',
                                                'hint': 'Create a ValidatingAdmissionPolicy and binding with '
                                                        'a CEL validation equivalent to '
                                                        '`object.spec.containers.all(c, '
                                                        'c.securityContext.allowPrivilegeEscalation == '
                                                        'false)` and validationActions: [Deny], or set Pod '
                                                        'Security Admission enforce=restricted where it '
                                                        'covers this field; allowPrivilegeEscalation false '
                                                        'on each container.',
                                                'kind': 'admission_policy',
                                                'severity': 'medium',
                                                'sha': '224b0185859bb6795c15b22156573eb0b82583bc0f6bbf44a26cd95db14b4603',
                                                'title': 'Admission forbids allowPrivilegeEscalation'},
 'k8s.cis.admission_capabilities_add': {'category': 'hardening',
                                        'hint': 'Create a ValidatingAdmissionPolicy and binding with a CEL '
                                                'validation equivalent to `object.spec.containers.all(c, '
                                                '!has(c.securityContext.capabilities.add) || '
                                                'size(c.securityContext.capabilities.add)==0)` and '
                                                'validationActions: [Deny], or set Pod Security Admission '
                                                'enforce=restricted where it covers this field; drop ALL and '
                                                'add no capabilities.',
                                        'kind': 'admission_policy',
                                        'severity': 'medium',
                                        'sha': '502451c92f88a516a9b31c57950f963c053bfbd89f153e3b8201ec91e72ebc94',
                                        'title': 'Admission forbids capabilities.add'},
 'k8s.cis.admission_capabilities_add_net_raw': {'category': 'hardening',
                                                'hint': 'Create a ValidatingAdmissionPolicy and binding with '
                                                        'a CEL validation equivalent to '
                                                        '`object.spec.containers.all(c, '
                                                        '!has(c.securityContext.capabilities.add) || '
                                                        '!c.securityContext.capabilities.add.exists(x, '
                                                        'x=="NET_RAW"))` and validationActions: [Deny], or '
                                                        'set Pod Security Admission enforce=restricted where '
                                                        'it covers this field; remove NET_RAW from '
                                                        'capabilities.add.',
                                                'kind': 'admission_policy',
                                                'severity': 'medium',
                                                'sha': 'bc46b030150b9b266865ec8e3472a53e801ce019cfacfc7cf2afa0dae32af805',
                                                'title': 'Admission forbids capabilities.add NET_RAW'},
 'k8s.cis.admission_capabilities_drop': {'category': 'hardening',
                                         'hint': 'Create a ValidatingAdmissionPolicy and binding with a CEL '
                                                 'validation equivalent to `object.spec.containers.all(c, '
                                                 'has(c.securityContext.capabilities.drop) && '
                                                 'c.securityContext.capabilities.drop.exists(x, x=="ALL"))` '
                                                 'and validationActions: [Deny], or set Pod Security '
                                                 'Admission enforce=restricted where it covers this field; '
                                                 'drop ALL capabilities.',
                                         'kind': 'admission_policy',
                                         'severity': 'medium',
                                         'sha': '7d25a97fd22258704b1133f3781e153f90e68d0e0b2d947186b39ff91c2ac477',
                                         'title': 'Admission forbids capabilities.drop'},
 'k8s.cis.admission_container_ports_hostport': {'category': 'hardening',
                                                'hint': 'Create a ValidatingAdmissionPolicy and binding with '
                                                        'a CEL validation equivalent to '
                                                        '`object.spec.containers.all(c, !has(c.ports) || '
                                                        'c.ports.all(p, !has(p.hostPort) || p.hostPort==0))` '
                                                        'and validationActions: [Deny], or set Pod Security '
                                                        'Admission enforce=restricted where it covers this '
                                                        'field; remove hostPort from containers.',
                                                'kind': 'admission_policy',
                                                'severity': 'medium',
                                                'sha': 'ac0ae88d83753ba169adf90a5e0258ed3ca5d6b5d2569871d9b313d70cad1d10',
                                                'title': 'Admission forbids container ports.hostPort'},
 'k8s.cis.admission_hostipc': {'category': 'hardening',
                               'hint': 'Create a ValidatingAdmissionPolicy and binding with a CEL validation '
                                       'equivalent to `!has(object.spec.hostIPC) || '
                                       'object.spec.hostIPC==false` and validationActions: [Deny], or set '
                                       'Pod Security Admission enforce=restricted where it covers this '
                                       'field; set hostIPC false.',
                               'kind': 'admission_policy',
                               'severity': 'medium',
                               'sha': 'b4fed62a3fd79c8d22b790ac52a938db52ec47ccbd01de3a5d4c90356cad38b1',
                               'title': 'Admission forbids hostIPC'},
 'k8s.cis.admission_hostnetwork': {'category': 'hardening',
                                   'hint': 'Create a ValidatingAdmissionPolicy and binding with a CEL '
                                           'validation equivalent to `!has(object.spec.hostNetwork) || '
                                           'object.spec.hostNetwork==false` and validationActions: [Deny], '
                                           'or set Pod Security Admission enforce=restricted where it covers '
                                           'this field; set hostNetwork false.',
                                   'kind': 'admission_policy',
                                   'severity': 'medium',
                                   'sha': '48b7f83cbb2a87a2bd38f58ba30d2da1d20354f5de041862066375ee2754dd14',
                                   'title': 'Admission forbids hostNetwork'},
 'k8s.cis.admission_hostpath': {'category': 'hardening',
                                'hint': 'Create a ValidatingAdmissionPolicy and binding with a CEL '
                                        'validation equivalent to `!has(object.spec.volumes) || '
                                        'object.spec.volumes.all(v, !has(v.hostPath))` and '
                                        'validationActions: [Deny], or set Pod Security Admission '
                                        'enforce=restricted where it covers this field; replace hostPath '
                                        'with a PVC or other scoped volume.',
                                'kind': 'admission_policy',
                                'severity': 'medium',
                                'sha': 'ecbc26cb67678979aa2fd58e5621e7ca68db1f70c06791708052b417fd85119d',
                                'title': 'Admission denies HostPath volumes'},
 'k8s.cis.admission_hostpid': {'category': 'hardening',
                               'hint': 'Create a ValidatingAdmissionPolicy and binding with a CEL validation '
                                       'equivalent to `!has(object.spec.hostPID) || '
                                       'object.spec.hostPID==false` and validationActions: [Deny], or set '
                                       'Pod Security Admission enforce=restricted where it covers this '
                                       'field; set hostPID false.',
                               'kind': 'admission_policy',
                               'severity': 'medium',
                               'sha': 'd05850dd8a18c0b560b144eaa089b283e5a25781ca1b5d07f8a2bcf461c3dbdb',
                               'title': 'Admission forbids hostPID'},
 'k8s.cis.admission_privileged': {'category': 'hardening',
                                  'hint': 'Create a ValidatingAdmissionPolicy and binding with a CEL '
                                          'validation equivalent to `object.spec.containers.all(c, '
                                          '!has(c.securityContext.privileged) || '
                                          'c.securityContext.privileged==false)` and validationActions: '
                                          '[Deny], or set Pod Security Admission enforce=restricted where it '
                                          'covers this field; set securityContext.privileged false.',
                                  'kind': 'admission_policy',
                                  'severity': 'medium',
                                  'sha': '3590c293438808fd2a04cdccb8f7d5aade58da2fcd345220429e35a89a0ba490',
                                  'title': 'Admission forbids privileged'},
 'k8s.cis.admission_runasnonroot': {'category': 'hardening',
                                    'hint': 'Create a ValidatingAdmissionPolicy and binding with a CEL '
                                            'validation equivalent to `object.spec.containers.all(c, '
                                            '(has(c.securityContext.runAsNonRoot) && '
                                            'c.securityContext.runAsNonRoot==true) || '
                                            '(!has(c.securityContext.runAsNonRoot) && '
                                            'has(object.spec.securityContext.runAsNonRoot) && '
                                            'object.spec.securityContext.runAsNonRoot==true))` and '
                                            'validationActions: [Deny], or set Pod Security Admission '
                                            'enforce=restricted where it covers this field; set runAsNonRoot '
                                            'true on the Pod or every container.',
                                    'kind': 'admission_policy',
                                    'severity': 'medium',
                                    'sha': '03d949524241f82fda7020314de41f5457dad3b3c4f86537573b0253d561ba7f',
                                    'title': 'Admission forbids runAsNonRoot'},
 'k8s.cis.admission_windowsoptions_hostprocess': {'category': 'hardening',
                                                  'hint': 'Create a ValidatingAdmissionPolicy and binding '
                                                          'with a CEL validation equivalent to '
                                                          '`object.spec.containers.all(c, '
                                                          '!has(c.securityContext.windowsOptions.hostProcess) '
                                                          '|| '
                                                          'c.securityContext.windowsOptions.hostProcess==false)` '
                                                          'and validationActions: [Deny], or set Pod '
                                                          'Security Admission enforce=restricted where it '
                                                          'covers this field; set windowsOptions.hostProcess '
                                                          'false.',
                                                  'kind': 'admission_policy',
                                                  'severity': 'medium',
                                                  'sha': 'd0812f3ec7685b2ed65fe5df66f4880e577731d0cd83ee8b4588c33cc71a2190',
                                                  'title': 'Admission forbids windowsOptions.hostProcess'},
 'k8s.cis.configure_image_provenance_using_imagepolicywebhook_admission_controller': {'category': 'supply_chain',
                                                                                      'hint': 'Add '
                                                                                              'ImagePolicyWebhook '
                                                                                              'to '
                                                                                              'kube-apiserver '
                                                                                              '--enable-admission-plugins '
                                                                                              'and set '
                                                                                              '--admission-control-config-file '
                                                                                              'to a readable '
                                                                                              'AdmissionConfiguration '
                                                                                              'containing '
                                                                                              'its '
                                                                                              'kubeConfigFile.',
                                                                                      'kind': 'pod',
                                                                                      'severity': 'medium',
                                                                                      'sha': 'bdcb6fdc5758d8deee371b9c7e82e70f4b40f753e6a33f3c5ad8f9e93009bd85',
                                                                                      'title': 'Configure '
                                                                                               'Image '
                                                                                               'Provenance '
                                                                                               'using '
                                                                                               'ImagePolicyWebhook '
                                                                                               'admission '
                                                                                               'controller'},
 'k8s_approved_image_installation': {'category': 'supply_chain',
                                     'hint': 'Pin Pod images to approved registry digests and bind a '
                                             'ValidatingAdmissionPolicy with validationActions: [Deny] for '
                                             'Pod CREATE and UPDATE across the target namespaces.',
                                     'kind': 'pod',
                                     'severity': 'high',
                                     'sha': '91c5faf48c6a380644bb003b65d9ee28c589209cdea2fefa3f5a26df035278ef',
                                     'title': 'Check authorized Kubernetes image installation'},
 'k8s_pod_secret_pod_rule_non_compliant_fcdc38e543': {'category': 'supply_chain',
                                                      'hint': 'Create a docker-registry Secret in the Pod '
                                                              'namespace and add its name under '
                                                              'spec.imagePullSecrets in the Pod template.',
                                                      'kind': 'pod',
                                                      'severity': 'medium',
                                                      'sha': '8db5eb07fc7feb29f1f9696419846cf035b624125f2286d9c9d1e059a8c00809',
                                                      'title': 'Core'}}
IDS = tuple(SPECS)
ADMISSION_IDS = tuple(key for key in IDS if key.startswith("k8s.cis.admission_"))
PROVENANCE_ID = "k8s.cis.configure_image_provenance_using_imagepolicywebhook_admission_controller"
APPROVED_ID = "k8s_approved_image_installation"
SECRET_ID = "k8s_pod_secret_pod_rule_non_compliant_fcdc38e543"


def _context(index):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "k8s":
        raise Unavailable("foreign provider")
    scope = get(context, "scope", str)
    cluster = get(context, "metadata.cluster_id", str)
    if not scope or not cluster:
        raise Unavailable("snapshot scope or cluster identity absent")
    return context, scope, cluster


def _inventory(index, kind):
    _, scope, cluster = _context(index)
    envelopes = get(index, "collections", dict).get(kind)
    if not isinstance(envelopes, list) or not envelopes or any(
            not isinstance(envelope, dict) or envelope.get("scope") != scope or
            envelope.get("type") != kind for envelope in envelopes):
        raise Unavailable("missing or foreign scoped " + kind + " inventory")
    rows = complete_items(index, kind)
    declared_count = sum(len(get(envelope, "items", list)) for envelope in envelopes)
    if declared_count != len(rows):
        raise Unavailable("deduplicated or inconsistent " + kind + " inventory")
    seen_pods = set()
    for row in rows:
        if get(row, "provenance.cluster_id", str) != cluster:
            raise Unavailable("foreign cluster in " + kind + " inventory")
        if kind == "pod":
            # Items of a typed Pod list carry no per-item kind; only a declared foreign kind is rejected.
            if row.get("kind", "Pod") != "Pod":
                raise Unavailable("Pod inventory contains a foreign resource kind")
            namespace = get(row, "metadata.namespace", str)
            uid = get(row, "metadata.uid", str)
            if not namespace or not uid or (namespace, uid) in seen_pods or (scope != "*" and scope != namespace):
                raise Unavailable("Pod identity duplicated, malformed, or outside scope")
            seen_pods.add((namespace, uid))
    return rows


def _member(item, index, kind):
    rows = _inventory(index, kind)
    if not any(row is item or row == item for row in rows):
        raise Unavailable("target absent from complete " + kind + " inventory")
    return rows


def _full(item):
    return get(item, "provenance.evidence", str) == "read-only list"


def _native_optional(item, key, default, expected, *, source):
    coverage = item.get("_coverage", {})
    if not isinstance(coverage, dict):
        raise Unavailable("field coverage malformed")
    if key in item or key in coverage:
        return get(item, key, expected)
    if _full(source):
        return default
    raise Unavailable("omitted field without full native representation: " + key)


def _named(item, kind):
    if get(item, "kind", str) != kind:
        raise Unavailable("unexpected admission resource kind")
    name = get(item, "metadata.name", str)
    if not name:
        raise Unavailable("admission resource name empty")
    return name


def _namespaces(index):
    rows = _inventory(index, "namespace")
    seen = set()
    result_rows = []
    for row in rows:
        if row.get("kind", "Namespace") != "Namespace":  # Typed list items carry no kind.
            raise Unavailable("Namespace inventory contains a foreign resource kind")
        name = get(row, "metadata.name", str)
        if not name or name in seen:
            raise Unavailable("Namespace identity malformed or duplicated")
        seen.add(name)
        metadata = get(row, "metadata", dict)
        labels = _native_optional(metadata, "labels", {}, dict, source=row)
        if any(not isinstance(key, str) or not isinstance(value, str) for key, value in labels.items()):
            raise Unavailable("Namespace labels malformed")
        result_rows.append((name, labels))
    return result_rows


def _admission_rows(index):
    rows = _inventory(index, "admission_policy")
    policies, bindings, seen = {}, [], set()
    for row in rows:
        kind = get(row, "kind", str)
        name = get(row, "metadata.name", str)
        if not name or (kind, name) in seen:
            raise Unavailable("admission policy identity malformed or duplicated")
        seen.add((kind, name))
        if kind == "ValidatingAdmissionPolicy":
            policies[name] = row
        elif kind == "ValidatingAdmissionPolicyBinding":
            bindings.append(row)
        elif kind not in ("MutatingAdmissionPolicy", "MutatingAdmissionPolicyBinding"):
            raise Unavailable("unrecognized admission policy kind")
    return policies, bindings


def _selector(selector, labels, *, source, pod_selector=False):
    if not isinstance(selector, dict):
        raise Unavailable("admission selector malformed")
    if selector.get("matchExpressions"):
        return None
    expressions = _native_optional(selector, "matchExpressions", [], list, source=source)
    if expressions:
        return None
    required = _native_optional(selector, "matchLabels", {}, dict, source=source)
    if any(not isinstance(key, str) or not key or not isinstance(value, str) for key, value in required.items()):
        raise Unavailable("admission selector labels malformed")
    if pod_selector and required:
        return None  # Pod labels cannot be universally established from Namespace labels.
    return all(labels.get(key) == value for key, value in required.items())


def _rules_match(rules, *, source):
    if not isinstance(rules, list):
        raise Unavailable("admission resourceRules malformed")
    if not rules:
        raise Unavailable("empty admission resourceRules semantics unresolved")
    covered = set()
    for rule in rules:
        if not isinstance(rule, dict):
            raise Unavailable("admission resource rule malformed")
        groups = get(rule, "apiGroups", list)
        versions = get(rule, "apiVersions", list)
        resources = get(rule, "resources", list)
        operations = get(rule, "operations", list)
        if any(not isinstance(values, list) or any(not isinstance(value, str) for value in values) for values in
               (groups, versions, resources, operations)):
            raise Unavailable("admission resource rule values malformed")
        scope = _native_optional(rule, "scope", "*", str, source=source)
        if scope not in ("*", "Namespaced", "Cluster"):
            raise Unavailable("admission resource rule scope malformed")
        if (("" in groups or "*" in groups) and ("v1" in versions or "*" in versions) and
                ("pods" in resources or "*" in resources) and scope in ("*", "Namespaced")):
            covered.update(operation for operation in ("CREATE", "UPDATE") if operation in operations or "*" in operations)
    return covered == {"CREATE", "UPDATE"}


def _match_resources(match, labels, *, source):
    if not isinstance(match, dict):
        raise Unavailable("binding matchResources malformed")
    if _native_optional(match, "excludeResourceRules", [], list, source=source):
        return None
    namespace = _native_optional(match, "namespaceSelector", {}, dict, source=source)
    object_selector = _native_optional(match, "objectSelector", {}, dict, source=source)
    selected = _selector(namespace, labels, source=source)
    if selected is not True:
        return selected
    selected = _selector(object_selector, {}, source=source, pod_selector=True)
    if selected is not True:
        return selected
    rules = _native_optional(match, "resourceRules", None, (list, type(None)), source=source)
    return True if rules is None else _rules_match(rules, source=source)


def _policy_match(policy, labels):
    spec = get(policy, "spec", dict)
    if _native_optional(spec, "paramKind", None, (dict, type(None)), source=policy) is not None:
        return None
    if _native_optional(spec, "matchConditions", [], list, source=policy):
        return None
    failure = _native_optional(spec, "failurePolicy", "Fail", str, source=policy)
    if failure not in ("Fail", "Ignore"):
        raise Unavailable("failurePolicy malformed")
    if failure != "Fail":
        return None
    constraints = get(spec, "matchConstraints", dict)
    get(constraints, "resourceRules", list)
    return _match_resources(constraints, labels, source=policy)


def _bound_expressions(index, namespace, labels):
    policies, bindings = _admission_rows(index)
    matched, uncertain = [], False
    for binding in bindings:
        spec = get(binding, "spec", dict)
        name = get(spec, "policyName", str)
        actions = get(spec, "validationActions", list)
        if not name or any(action not in ("Deny", "Warn", "Audit") for action in actions):
            raise Unavailable("binding policy name or actions malformed")
        if "Deny" not in actions:
            continue
        if _native_optional(spec, "paramRef", None, (dict, type(None)), source=binding) is not None:
            uncertain = True
            continue
        policy = policies.get(name)
        if policy is None:
            uncertain = True
            continue
        match = _native_optional(spec, "matchResources", {}, dict, source=binding)
        applicable = _match_resources(match, labels, source=binding)
        if applicable is False:
            continue
        if applicable is None:
            uncertain = True
            continue
        applicable = _policy_match(policy, labels)
        if applicable is False:
            continue
        if applicable is None:
            uncertain = True
            continue
        validations = get(policy, "spec.validations", list)
        if not validations:
            uncertain = True
            continue
        expressions = []
        for validation in validations:
            expression = get(validation, "expression", str)
            if not expression:
                raise Unavailable("empty CEL validation expression")
            expressions.append(expression)
        matched.append((name, expressions))
    return matched, uncertain


def _compact(expression):
    # Ignore whitespace in CEL syntax, never inside string literals.
    compact = []
    quote = None
    escaped = False
    for char in expression:
        if quote is not None:
            compact.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in ('"', "'"):
            quote = char
            compact.append(char)
        elif not char.isspace():
            compact.append(char)
    if quote is not None:
        raise Unavailable("CEL string literal malformed")
    return "".join(compact)


def _all_containers(test):
    return " && ".join((
        f"object.spec.containers.all(c, {test})",
        f"(!has(object.spec.initContainers) || object.spec.initContainers.all(c, {test}))",
        f"(!has(object.spec.ephemeralContainers) || object.spec.ephemeralContainers.all(c, {test}))",
    ))


CONTAINER_TESTS = {
    "allowprivilegeescalation": "has(c.securityContext) && has(c.securityContext.allowPrivilegeEscalation) && c.securityContext.allowPrivilegeEscalation == false",
    "capabilities_add": "!has(c.securityContext) || !has(c.securityContext.capabilities) || !has(c.securityContext.capabilities.add) || size(c.securityContext.capabilities.add) == 0",
    "capabilities_add_net_raw": '!has(c.securityContext) || !has(c.securityContext.capabilities) || !has(c.securityContext.capabilities.add) || !c.securityContext.capabilities.add.exists(x, x == "NET_RAW")',
    "capabilities_drop": 'has(c.securityContext) && has(c.securityContext.capabilities) && has(c.securityContext.capabilities.drop) && c.securityContext.capabilities.drop.exists(x, x == "ALL")',
    "container_ports_hostport": "!has(c.ports) || c.ports.all(p, !has(p.hostPort) || p.hostPort == 0)",
    "privileged": "!has(c.securityContext) || !has(c.securityContext.privileged) || c.securityContext.privileged == false",
    "runasnonroot": "((has(c.securityContext) && has(c.securityContext.runAsNonRoot)) ? c.securityContext.runAsNonRoot == true : (has(object.spec.securityContext) && has(object.spec.securityContext.runAsNonRoot) && object.spec.securityContext.runAsNonRoot == true))",
    "windowsoptions_hostprocess": "!has(c.securityContext) || !has(c.securityContext.windowsOptions) || !has(c.securityContext.windowsOptions.hostProcess) || c.securityContext.windowsOptions.hostProcess == false",
}
HOST_TESTS = {
    "hostipc": "!has(object.spec.hostIPC) || object.spec.hostIPC == false",
    "hostnetwork": "!has(object.spec.hostNetwork) || object.spec.hostNetwork == false",
    "hostpid": "!has(object.spec.hostPID) || object.spec.hostPID == false",
    "hostpath": "!has(object.spec.volumes) || object.spec.volumes.all(v, !has(v.hostPath))",
}


def _required_cel(suffix):
    if suffix in HOST_TESTS:
        return HOST_TESTS[suffix]
    test = CONTAINER_TESTS[suffix]
    expression = _all_containers(test)
    if suffix == "windowsoptions_hostprocess":
        return "(!has(object.spec.securityContext) || !has(object.spec.securityContext.windowsOptions) || !has(object.spec.securityContext.windowsOptions.hostProcess) || object.spec.securityContext.windowsOptions.hostProcess == false) && " + expression
    return expression


def _admission_check(check_id, item, index):
    _, scope, _ = _context(index)
    if get(item, "scope", str) != scope:
        raise Unavailable("foreign admission scope target")
    namespaces = _namespaces(index)
    if not namespaces:
        return "NOT_APPLICABLE", {"reason": "complete Namespace inventory is empty"}
    required = _compact(_required_cel(check_id.removeprefix("k8s.cis.admission_")))
    missing, uncertain, covered = [], [], []
    for namespace, labels in namespaces:
        matches, possible = _bound_expressions(index, namespace, labels)
        if any(required in {_compact(expression) for expression in expressions} for _, expressions in matches):
            covered.append(namespace)
        elif possible or matches:
            uncertain.append(namespace)
        else:
            missing.append(namespace)
    if missing:
        return result(True, namespaces_without_binding=missing, covered_namespaces=covered,
                      semantics="No Deny binding with applicable Pod CREATE and UPDATE coverage")
    if uncertain:
        return unknown("CEL semantics or binding coverage unresolved", namespaces=uncertain)
    return result(False, covered_namespaces=covered, cel_subset="literal recognized expression")


def _operator_policy(index):
    context, _, cluster = _context(index)
    policy = get(context, "metadata.compliance_policy", dict)
    if get(policy, "status", str) != "collected" or get(policy, "cluster_id", str) != cluster:
        raise Unavailable("owner image policy unavailable or foreign cluster")
    if "observed_at" in policy or "max_age_seconds" in policy:
        observed = get(policy, "observed_at", str)
        age = get(policy, "max_age_seconds", int)
        capture = get(context, "created_at", str)
        try:
            one = datetime.fromisoformat(capture.replace("Z", "+00:00"))
            two = datetime.fromisoformat(observed.replace("Z", "+00:00"))
            if one.tzinfo is None or one.utcoffset() is None or two.tzinfo is None or two.utcoffset() is None:
                raise ValueError("timezone absent")
            elapsed = (one - two).total_seconds()
        except ValueError as exc:
            raise Unavailable("owner image policy timestamp malformed") from exc
        if age <= 0 or not 0 <= elapsed <= age:
            raise Unavailable("owner image policy stale or future")
    approved = get(policy, "approved_images", list)
    if not approved or any(not isinstance(image, str) or not re.fullmatch(
            r"[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?/[a-zA-Z0-9._/-]+@sha256:[a-f0-9]{64}", image)
            for image in approved) or len(set(approved)) != len(approved):
        raise Unavailable("approved image registry/digest set malformed")
    return sorted(approved)


def _image_cel(images):
    approved = "[" + ", ".join(json.dumps(image) for image in images) + "]"
    return _all_containers(f"c.image in {approved}")


def _approved_image(item, index):
    _member(item, index, "pod")
    images = _operator_policy(index)
    spec = get(item, "spec", dict)
    observed = []
    for field in ("containers", "initContainers", "ephemeralContainers"):
        rows = get(spec, field, list) if field == "containers" else _native_optional(
            spec, field, [], list, source=item)
        if field == "containers" and not rows:
            raise Unavailable("Pod has no containers")
        for container in rows:
            image = get(container, "image", str)
            if not image:
                raise Unavailable("Pod image empty")
            observed.append(image)
    unapproved = sorted(set(observed) - set(images))
    if unapproved:
        return result(True, unapproved_images=unapproved, semantics="declared Pod image outside owner allowlist")
    namespace = get(item, "metadata.namespace", str)
    if not namespace:
        raise Unavailable("Pod namespace absent")
    names = dict(_namespaces(index))
    if namespace not in names:
        raise Unavailable("Pod Namespace absent from complete inventory")
    matches, possible = _bound_expressions(index, namespace, names[namespace])
    required = _compact(_image_cel(images))
    if any(required in {_compact(expression) for expression in expressions} for _, expressions in matches):
        return result(False, approved_images=observed, namespace=namespace)
    if possible or matches:
        return unknown("image admission CEL semantics or binding coverage unresolved")
    return result(True, reason="no Deny binding enforcing approved images on Pod CREATE and UPDATE", namespace=namespace)


def _image_provenance(item, index):
    _member(item, index, "pod")
    spec = get(item, "spec", dict)
    containers = get(spec, "containers", list)
    if not containers or any(not isinstance(row, dict) for row in containers):
        raise Unavailable("Pod container declaration malformed")
    matched, ambiguous = [], False
    for container in containers:
        config = _native_optional(container, "_component_config", None, (dict, type(None)), source=item)
        if config is None:
            ambiguous = True
            continue
        component = get(config, "component", (str, type(None)))
        if component == "kube-apiserver":
            if get(config, "flags_complete", bool) is not True:
                raise Unavailable("API server flags incomplete")
            matched.append(config)
        elif component is None and config.get("component_identification") != "ordinary_command":
            ambiguous = True
    if ambiguous or len(matched) > 1:
        return unknown("kube-apiserver component identification incomplete or ambiguous")
    if not matched:
        return "NOT_APPLICABLE", {"reason": "Pod is not an identified kube-apiserver"}
    flags = get(matched[0], "flags", dict)
    def plugins(name):
        value = get(flags, name, str)
        parts = value.split(",")
        if any(not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", part) for part in parts) or len(parts) != len(set(parts)):
            raise Unavailable("admission plugin flag malformed")
        return set(parts)
    enabled, disabled = plugins("enable-admission-plugins"), plugins("disable-admission-plugins")
    if "ImagePolicyWebhook" not in enabled or "ImagePolicyWebhook" in disabled:
        return result(True, reason="ImagePolicyWebhook explicitly disabled")
    path = flags.get("admission-control-config-file")
    if path is None:
        return unknown("admission-control-config-file not projected by current collector")
    if not isinstance(path, str) or not path:
        raise Unavailable("admission control config path malformed")
    if not path.startswith("/") or ".." in path.split("/"):
        return result(True, reason="admission control config path is not absolute and normalized")
    files = _inventory(index, "admission_configuration_file")
    pod_uid = get(item, "metadata.uid", str)
    matching = [row for row in files if get(row, "pod_uid", str) == pod_uid and get(row, "path", str) == path]
    if len(matching) != 1:
        raise Unavailable("admission file content not verified for API server Pod and path")
    file = matching[0]
    if get(file, "verification_status", str) != "verified":
        raise Unavailable("admission file content unverified")
    plugins = get(file, "plugins", list)
    if any(not isinstance(plugin, dict) for plugin in plugins):
        raise Unavailable("admission plugin configuration malformed")
    webhook = [plugin for plugin in plugins if get(plugin, "name", str) == "ImagePolicyWebhook"]
    if not webhook:
        return result(True, reason="ImagePolicyWebhook plugin configuration absent")
    if len(webhook) > 1:
        raise Unavailable("ambiguous duplicate ImagePolicyWebhook plugin configuration")
    kubeconfig = get(webhook[0], "configuration.kubeConfigFile", str)
    if not kubeconfig.startswith("/") or ".." in kubeconfig.split("/"):
        return result(True, reason="ImagePolicyWebhook kubeConfigFile path invalid")
    return result(False, admission_config_path=path, webhook_kubeconfig_path=kubeconfig,
                  semantics="verified admission file declaration; webhook endpoint health unassessed")


def _pod_secret(item, index):
    _member(item, index, "pod")
    spec = get(item, "spec", dict)
    secrets = _native_optional(spec, "imagePullSecrets", [], list, source=item)
    if any(not isinstance(entry, dict) for entry in secrets):
        raise Unavailable("imagePullSecrets malformed")
    names = [get(entry, "name", str) for entry in secrets]
    if any(not name for name in names):
        raise Unavailable("imagePullSecrets entry name empty")
    return result(not names, image_pull_secret_names=names, semantics="PodSpec references only; Secret existence unassessed")


for _id, _spec in SPECS.items():
    _deps = (["admission_policy", "namespace"] if _id in ADMISSION_IDS else
             ["pod", "namespace", "admission_policy"] if _id == APPROVED_ID else
             ["pod", "admission_configuration_file"] if _id == PROVENANCE_ID else ["pod"])
    _target = "scope" if _id in ADMISSION_IDS else "resource"
    _native_category = _spec["category"] if _spec["category"] in {
        "hardening", "exposure", "least_privilege", "iam_graph", "network"} else "hardening"
    @register(_id, "k8s", _native_category, _spec["kind"], _spec["title"],
              _spec["severity"], "CM-6", _spec["hint"], target=_target, dependencies=_deps)
    def _evaluate(item, index, check_id=_id):
        if check_id in ADMISSION_IDS:
            return _admission_check(check_id, item, index)
        if check_id == APPROVED_ID:
            return _approved_image(item, index)
        if check_id == PROVENANCE_ID:
            return _image_provenance(item, index)
        return _pod_secret(item, index)
    _evaluate.__name__ = _id.replace(".", "_")
    if _native_category != _spec["category"]:
        CHECKS[-1] = replace(CHECKS[-1], category=_spec["category"])
