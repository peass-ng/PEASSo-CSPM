"""Signed, snapshot-only remaining K8S native checks.

Adapted from the unimported sw draft families; each family is isolated in a
lexical namespace, and only the exact pending signed IDs are registered.
The companion disposition and focused fixtures document admission boundaries.
"""
# Source family: compliance_new_sw10.py
def _load_10():
    _ALLOWED = {'k8s.cis.consider_external_secret_storage', 'k8s.cis.controller_manager_rotate_kubelet_server_certificate_true', 'k8s.cis.the_eventrecordqps_argument_is_set_to_a_level_which_ensures_appropriate_event_capture', 'k8s.cis.the_kube_proxy_metrics_service_is_bound_to_localhost', 'k8s.cis.the_request_timeout_argument_is_set_as_appropriate', 'k8s.cis.the_service_account_extend_token_expiration_parameter_is_set_to_false', 'k8s_cluster_version_at_least_oldest_supported', 'k8s_cluster_version_supported', 'k8s_pod_pod_deployed_specific_namespace_its_76714f9dfe', 'k8s_pod_pod_deployed_within_specific_namespace_3790c81f90', 'k8s_pod_pod_deployed_within_specific_namespace_62bb9e62c0', 'k8s_pod_pod_running_within_specific_namespace_0f3d581358', 'k8s_pod_serviceaccount_has_rbac_binding'}
    'Conservative signed Kubernetes compliance predicates (sw10).\n\nOnly complete, scope-bound inventories may establish absence. Operator policy\nis cluster-bound; facts that the current collector omits remain UNKNOWN.\n'
    import ipaddress
    import json
    import re
    from collections import Counter
    from datetime import datetime
    from decimal import Decimal, localcontext
    from . import register, result, unknown
    from .facts import Unavailable, complete_items, get, optional
    SPECS = {'k8s.cis.consider_external_secret_storage': {'resource_kind': 'pod', 'category': 'hardening', 'severity': 'medium', 'title': 'Consider external secret storage', 'remediation_hint': 'Install a CSI Secrets Store driver, configure SecretProviderClass for the external store, and replace direct Secret volumes or environment references in the Pod spec where supported.'}, 'k8s.cis.controller_manager_rotate_kubelet_server_certificate_true': {'resource_kind': 'pod', 'category': 'hardening', 'severity': 'medium', 'title': 'kube-controller-manager enables RotateKubeletServerCertificate', 'remediation_hint': 'Set --feature-gates=RotateKubeletServerCertificate=true on kube-controller-manager and roll out its static Pod manifest.'}, 'k8s.cis.the_kube_proxy_metrics_service_is_bound_to_localhost': {'resource_kind': 'pod', 'category': 'network', 'severity': 'medium', 'title': 'Ensure that the kube-proxy metrics service is bound to localhost', 'remediation_hint': 'Set kube-proxy --metrics-bind-address=127.0.0.1:10249 (or [::1]:10249) in its DaemonSet or component configuration.'}, 'k8s.cis.the_request_timeout_argument_is_set_as_appropriate': {'resource_kind': 'pod', 'category': 'hardening', 'severity': 'medium', 'title': 'Ensure that the --request-timeout argument is set as appropriate', 'remediation_hint': 'Set kube-apiserver --request-timeout to a positive duration no greater than the approved maximum in the static Pod manifest.'}, 'k8s.cis.the_service_account_extend_token_expiration_parameter_is_set_to_false': {'resource_kind': 'pod', 'category': 'hardening', 'severity': 'medium', 'title': 'Ensure that the --service-account-extend-token-expiration parameter is set to false', 'remediation_hint': 'Set kube-apiserver --service-account-extend-token-expiration=false in the static Pod manifest.'}, 'k8s_pod_pod_deployed_specific_namespace_its_76714f9dfe': {'resource_kind': 'pod', 'category': 'hardening', 'severity': 'medium', 'title': 'Core', 'remediation_hint': 'Move the workload manifest to an approved namespace and set nodeSelector or nodeAffinity to the approved node pool labels.'}, 'k8s_pod_pod_deployed_within_specific_namespace_0daa0bd46b': {'resource_kind': 'pod', 'category': 'hardening', 'severity': 'medium', 'title': 'Core', 'remediation_hint': 'Set metadata.namespace in the Pod or controller manifest to an approved namespace and apply it there.'}, 'k8s_pod_pod_deployed_within_specific_namespace_3790c81f90': {'resource_kind': 'pod', 'category': 'hardening', 'severity': 'medium', 'title': 'Core', 'remediation_hint': 'Set metadata.namespace to an approved namespace and spec.nodeSelector to the required node pool key/value pairs.'}, 'k8s_pod_pod_deployed_within_specific_namespace_62bb9e62c0': {'resource_kind': 'pod', 'category': 'hardening', 'severity': 'medium', 'title': 'Core', 'remediation_hint': 'Set metadata.namespace to an approved namespace and add the required metadata.labels to the Pod template.'}, 'k8s_pod_pod_running_within_specific_namespace_0f3d581358': {'resource_kind': 'pod', 'category': 'hardening', 'severity': 'medium', 'title': 'Core', 'remediation_hint': 'Fix the Pod scheduling or readiness failure, place the workload in an approved namespace, and set the required Pod template labels.'}, 'k8s_pod_serviceaccount_has_rbac_binding': {'resource_kind': 'pod', 'category': 'least_privilege', 'severity': 'medium', 'title': 'Pod ServiceAccount has RBAC binding', 'remediation_hint': 'Create a namespace scoped RoleBinding for the Pod’s effective spec.serviceAccountName and the minimum required Role.'}, 'k8s_networkpolicy_has_ingress_rules': {'resource_kind': 'networkpolicy', 'category': 'network', 'severity': 'medium', 'title': 'NetworkPolicy declares an ingress rule', 'remediation_hint': 'Add a spec.ingress rule with reviewed from peers and ports to the NetworkPolicy.'}, 'k8s_networkpolicy_network_policy_associated_podselectors_that_92dbc93b4c': {'resource_kind': 'networkpolicy', 'category': 'network', 'severity': 'medium', 'title': 'Core', 'remediation_hint': 'Set spec.podSelector.matchLabels or matchExpressions to the intended workload labels.'}, 'k8s_cluster_version_at_least_oldest_supported': {'resource_kind': 'cluster', 'category': 'hardening', 'severity': 'medium', 'title': 'Checks if a Kubernetes cluster is running a supported version. This rule is NON_COMPLIANT if the cluster is running an u', 'remediation_hint': 'Upgrade the control plane and nodes to Kubernetes oldestVersionSupported or later using the cluster provider or kubeadm upgrade plan.'}, 'k8s_cluster_version_supported': {'resource_kind': 'cluster', 'category': 'hardening', 'severity': 'high', 'title': 'Checks if a Kubernetes cluster is running a supported version. This rule is NON_COMPLIANT if the cluster is running an u', 'remediation_hint': 'Upgrade the control plane and nodes to a supported Kubernetes release above oldestVersionSupported using the cluster provider or kubeadm upgrade plan.'}, 'k8s.cis.namespace_has_networkpolicy': {'resource_kind': 'namespace', 'category': 'network', 'severity': 'medium', 'title': 'Every namespace has a NetworkPolicy', 'remediation_hint': 'Create a NetworkPolicy in each application namespace with a podSelector and explicit ingress and egress rules, beginning with a default deny policy.'}, 'k8s.cis.the_eventrecordqps_argument_is_set_to_a_level_which_ensures_appropriate_event_capture': {'resource_kind': 'component_configuration', 'category': 'hardening', 'severity': 'medium', 'title': 'Ensure that the eventRecordQPS argument is set to a level which ensures appropriate event capture', 'remediation_hint': 'Set eventRecordQPS in each kubelet configuration to at least the organization’s approved minimum, then restart kubelet.'}, 'k8s_service_external_traffic_policy_matches_required': {'resource_kind': 'service', 'category': 'network', 'severity': 'medium', 'title': 'LoadBalancer external traffic policy matches required value', 'remediation_hint': 'Set spec.externalTrafficPolicy to required_external_traffic_policy (Local or Cluster) on each selected LoadBalancer Service manifest.'}, 'k8s_ingress_ingress_has_any_associated_ingress_93579100f9': {'resource_kind': 'ingress', 'category': 'network', 'severity': 'medium', 'title': 'Checks whether a Kubernetes Ingress resource has any associated Ingress rules for routing traffic', 'remediation_hint': 'Add a spec.rules entry with an explicit host and HTTP path to the Ingress manifest.'}, 'k8s_response_team_required_binding': {'resource_kind': 'rolebinding,clusterrolebinding', 'category': 'least_privilege', 'severity': 'medium', 'title': 'Response team has required RBAC binding', 'remediation_hint': 'Create a RoleBinding or ClusterRoleBinding for the required response team subject and required Role or ClusterRole within an allowed namespace.'}}
    SPECS = {k: v for k, v in SPECS.items() if k in _ALLOWED}

    def _inventory(index, kind):
        context = get(index, 'context', dict)
        if get(context, 'provider', str) != 'k8s':
            raise Unavailable('foreign provider')
        scope = get(context, 'scope', str)
        if not scope:
            raise Unavailable('snapshot scope missing')
        cluster = get(context, 'metadata.cluster_id', str)
        if not cluster:
            raise Unavailable('snapshot cluster identity missing')
        pages = get(index, 'collections', dict).get(kind)
        if not isinstance(pages, list) or not pages:
            raise Unavailable('dependency not collected: ' + kind)
        for page in pages:
            if not isinstance(page, dict) or page.get('scope') != scope or page.get('type') != kind or (page.get('status') not in ('collected', 'empty')):
                raise Unavailable('incomplete or foreign-scope ' + kind + ' inventory')
            if page['status'] == 'empty' and get(page, 'items', list):
                raise Unavailable('empty inventory contains resources')
        wrappers = get(index, kind, list)
        for wrapper in wrappers:
            if get(wrapper, 'scope', str) != scope or get(wrapper, 'type', str) != kind:
                raise Unavailable('foreign-scope resource in ' + kind)
            if 'provider' in wrapper and get(wrapper, 'provider', str) != 'k8s':
                raise Unavailable('foreign-provider resource in ' + kind)
        rows = complete_items(index, kind)
        native = [item for page in pages for item in get(page, 'items', list)]
        try:
            if Counter((json.dumps(x, sort_keys=True) for x in rows)) != Counter((json.dumps(x, sort_keys=True) for x in native)):
                raise Unavailable('inventory content mismatch')
        except (TypeError, ValueError) as exc:
            raise Unavailable('inventory content malformed') from exc
        identities = set()
        namespaced = kind in {'pod', 'networkpolicy', 'service', 'ingress', 'rolebinding'}
        for row in rows:
            provenance = optional(row, 'provenance', {}, dict)
            if 'cluster_id' in provenance and get(provenance, 'cluster_id', str) != cluster:
                raise Unavailable('foreign cluster in ' + kind)
            if namespaced or kind in {'namespace', 'node', 'clusterrolebinding'}:
                name = get(row, 'metadata.name', str)
                namespace = get(row, 'metadata.namespace', str) if namespaced else None
                if not name or (namespaced and (not namespace)):
                    raise Unavailable('resource identity malformed in ' + kind)
                if not namespaced and optional(get(row, 'metadata', dict), 'namespace', None) not in (None, ''):
                    raise Unavailable('cluster resource has a namespace')
                if scope != '*' and (namespaced and namespace != scope or (kind == 'namespace' and name != scope)):
                    raise Unavailable('foreign namespace in ' + kind)
                identity = (namespace, name)
                if identity in identities:
                    raise Unavailable('duplicate resource identity in ' + kind)
                identities.add(identity)
        return rows

    def _member(item, index, kind):
        rows = _inventory(index, kind)
        if not any((row == item for row in rows)):
            raise Unavailable('item not present in complete inventory')
        return rows

    def _policy(index, key, expected):
        context = get(index, 'context', dict)
        meta = get(context, 'metadata', dict)
        policy = get(meta, 'compliance_policy', dict)
        if get(policy, 'status', str) != 'collected' or get(policy, 'cluster_id', str) != get(meta, 'cluster_id', str):
            raise Unavailable('operator policy unavailable or foreign cluster')
        if 'observed_at' in policy or 'max_age_seconds' in policy:
            observed = get(policy, 'observed_at', str)
            age = get(policy, 'max_age_seconds', int)
            capture = get(context, 'created_at', str)
            if not all((re.fullmatch('\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:Z|\\+00:00)', value) for value in (observed, capture))):
                raise Unavailable('policy observation timestamp malformed')
            try:
                delta = (datetime.fromisoformat(capture.replace('Z', '+00:00')) - datetime.fromisoformat(observed.replace('Z', '+00:00'))).total_seconds()
            except ValueError as exc:
                raise Unavailable('policy observation timestamp malformed') from exc
            if age <= 0 or not 0 <= delta <= age:
                raise Unavailable('operator policy stale or future')
        return get(policy, key, expected)

    def _attested_coverage(index, key):
        context = get(index, 'context', dict)
        meta = get(context, 'metadata', dict)
        coverage = get(meta, key, dict)
        if get(coverage, 'status', str) != 'attested_complete' or get(coverage, 'cluster_id', str) != get(meta, 'cluster_id', str):
            raise Unavailable('component coverage not attested complete')
        if get(coverage, 'node_count', int) <= 0 or get(coverage, 'max_age_seconds', int) <= 0:
            raise Unavailable('component coverage bounds malformed')
        observed, capture = (get(coverage, 'observed_at', str), get(context, 'created_at', str))
        if not all((re.fullmatch('\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:Z|\\+00:00)', value) for value in (observed, capture))):
            raise Unavailable('component coverage timestamp malformed')
        elapsed = (datetime.fromisoformat(capture.replace('Z', '+00:00')) - datetime.fromisoformat(observed.replace('Z', '+00:00'))).total_seconds()
        if not 0 <= elapsed <= coverage['max_age_seconds']:
            raise Unavailable('component coverage stale or future')

    def _string_set(index, key):
        values = _policy(index, key, list)
        if not values or any((not isinstance(x, str) or len(x) > 63 or (not re.fullmatch('[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', x) and (not (key == 'allowed_namespaces' and x == '*'))) for x in values)) or len(values) != len(set(values)):
            raise Unavailable('operator string set malformed: ' + key)
        return set(values)

    def _selector(index, key):
        value = _policy(index, key, dict)
        if not value or any((not _label_key(k) or not _label_value(v) for k, v in value.items())):
            raise Unavailable('operator selector malformed: ' + key)
        return value

    def _label_key(value):
        if not isinstance(value, str) or len(value) > 253:
            return False
        prefix, sep, name = value.rpartition('/')
        return bool(name) and len(name) <= 63 and (re.fullmatch('[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?', name) is not None) and (not sep or (bool(prefix) and all((len(part) <= 63 and re.fullmatch('[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', part) for part in prefix.split('.')))))

    def _label_value(value):
        return isinstance(value, str) and len(value) <= 63 and (not value or re.fullmatch('[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?', value) is not None)

    def _labels(item, path):
        parent, key = path.rsplit('.', 1)
        obj = _native_optional(get(item, parent, dict), key, {}, dict, source=item)
        if any((not _label_key(k) or not _label_value(v) for k, v in obj.items())):
            raise Unavailable('labels malformed')
        return obj

    def _full_native(item):
        return optional(optional(item, 'provenance', {}, dict), 'evidence', None, str) == 'read-only list'

    def _native_optional(item, key, default, expected, *, source=None):
        if key in item or key in item.get('_coverage', {}):
            return get(item, key, expected)
        if _full_native(item if source is None else source):
            return default
        raise Unavailable('omitted field without full native list provenance: ' + key)

    def _pod_name(item):
        name = get(item, 'metadata.name', str)
        namespace = get(item, 'metadata.namespace', str)
        if not name or not namespace:
            raise Unavailable('Pod identity malformed')
        return (namespace, name)

    def _component(item, expected):
        spec = get(item, 'spec', dict)
        containers = get(spec, 'containers', list)
        if not containers or any((not isinstance(x, dict) for x in containers)):
            raise Unavailable('Pod containers malformed')
        observed = []
        unresolved = False
        for container in containers:
            config = container.get('_component_config')
            if config is None:
                unresolved = True
                continue
            if not isinstance(config, dict):
                raise Unavailable('component projection malformed')
            component = get(config, 'component')
            if component not in (None, 'kube-apiserver', 'kube-controller-manager', 'kube-scheduler', 'kubelet', 'kube-proxy', 'etcd'):
                raise Unavailable('component identity malformed')
            if component is not None or config.get('component_identification') == 'ordinary_command':
                if get(config, 'flags_complete', bool) is not True:
                    raise Unavailable('component flags incomplete')
            if component == expected:
                if get(config, 'flags_complete', bool) is not True:
                    raise Unavailable('component flags incomplete')
                observed.append(config)
            elif component is None and config.get('component_identification') != 'ordinary_command':
                unresolved = True
        if unresolved:
            raise Unavailable('component inventory not proven complete')
        if not observed:
            return None
        if len(observed) != 1:
            raise Unavailable('ambiguous component declaration')
        return get(observed[0], 'flags', dict)

    def _flag_list(flags, name):
        value = get(flags, name, str)
        if not value or any((not re.fullmatch('[A-Za-z][A-Za-z0-9-]*', token) for token in value.split(','))):
            raise Unavailable('component flag list malformed')
        return set(value.split(','))

    def _subjects(binding, binding_kind):
        subjects = _native_optional(binding, 'subjects', [], list)
        for subject in subjects:
            kind = get(subject, 'kind', str)
            name = get(subject, 'name', str)
            if kind not in ('User', 'Group', 'ServiceAccount') or not name:
                raise Unavailable('RBAC subject malformed')
            if kind == 'ServiceAccount':
                namespace = _native_optional(subject, 'namespace', get(binding, 'metadata.namespace', str) if binding_kind == 'rolebinding' else None, str, source=binding)
                if not namespace:
                    raise Unavailable('ServiceAccount subject namespace unavailable')
        return subjects

    def _duration_seconds(value):
        if value in ('0', '+0', '-0'):
            return Decimal(0)
        match = re.fullmatch('([+-]?)((?:(?:[0-9]+(?:\\.[0-9]*)?|\\.[0-9]+)(?:ns|us|ms|s|m|h))+)', value)
        if not match:
            raise Unavailable('request timeout malformed')
        units = {'ns': 1, 'us': 1000, 'ms': 1000000, 's': 1000000000, 'm': 60000000000, 'h': 3600000000000}
        with localcontext() as precision:
            precision.prec = len(value) + 30
            nanoseconds = sum((int(Decimal(number) * units[unit]) for number, unit in re.findall('([0-9]+(?:\\.[0-9]*)?|\\.[0-9]+)(ns|us|ms|s|m|h)', match[2])))
        if match[1] == '-':
            nanoseconds = -nanoseconds
        if not -(1 << 63) <= nanoseconds < 1 << 63:
            raise Unavailable('request timeout outside Go duration range')
        return Decimal(nanoseconds) / 1000000000

    def _pod_evaluator(check_id, item, index):
        _member(item, index, 'pod')
        namespace, name = _pod_name(item)
        if check_id == 'k8s_pod_secret_pod_rule_non_compliant_fcdc38e543':
            spec = get(item, 'spec', dict)
            if 'imagePullSecrets' not in spec:
                if item.get('provenance', {}).get('evidence') != 'read-only list':
                    return unknown('imagePullSecrets absent without full Pod representation')
                secrets = []
            else:
                secrets = get(spec, 'imagePullSecrets', list)
            if any((not isinstance(x, dict) or not isinstance(x.get('name'), str) for x in secrets)):
                raise Unavailable('imagePullSecrets malformed')
            return result(not any((x['name'] for x in secrets)), namespace=namespace, pod=name)
        if check_id in NAMESPACE_POD_IDS:
            allowed = _string_set(index, 'approved_namespaces')
            failed = namespace not in allowed
            if check_id == POD_NODE_POOL_ID:
                selector = _selector(index, 'approved_node_pool_selector')
                node_name = get(item, 'spec.nodeName', str)
                if not node_name:
                    return unknown('Pod is not bound to a Node')
                nodes = _inventory(index, 'node')
                matches = [x for x in nodes if get(x, 'metadata.name', str) == node_name]
                if len(matches) != 1:
                    return unknown('bound Node absent or ambiguous')
                labels = _labels(matches[0], 'metadata.labels')
                failed |= any((labels.get(k) != v for k, v in selector.items()))
            if check_id == POD_NODE_SELECTOR_ID:
                selector = _selector(index, 'approved_node_selector')
                labels = _labels(item, 'spec.nodeSelector')
                failed |= any((labels.get(k) != v for k, v in selector.items()))
            if check_id in (POD_LABEL_ID, POD_RUNNING_ID):
                selector = _selector(index, 'approved_label_selector')
                labels = _labels(item, 'metadata.labels')
                failed |= any((labels.get(k) != v for k, v in selector.items()))
            if check_id == POD_RUNNING_ID:
                phase = get(item, 'status.phase', str)
                if phase not in {'Pending', 'Running', 'Succeeded', 'Failed', 'Unknown'}:
                    raise Unavailable('Pod phase unrecognized')
                failed |= phase != 'Running'
            return result(failed, namespace=namespace, pod=name)
        if check_id == 'k8s_pod_serviceaccount_has_rbac_binding':
            spec = get(item, 'spec', dict)
            sa = _native_optional(spec, 'serviceAccountName', 'default', str, source=item)
            if not sa and _full_native(item):
                sa = 'default'
            if not sa:
                raise Unavailable('ServiceAccount name malformed')
            bindings = [(binding_kind, binding) for binding_kind in ('rolebinding', 'clusterrolebinding') for binding in _inventory(index, binding_kind)]
            matched = False
            for binding_kind, binding in bindings:
                binding_ns = get(binding, 'metadata.namespace', str) if binding_kind == 'rolebinding' else None
                subjects = _subjects(binding, binding_kind)
                for subject in subjects:
                    if not isinstance(subject, dict):
                        raise Unavailable('RBAC subject malformed')
                    kind = get(subject, 'kind', str)
                    subject_name = get(subject, 'name', str)
                    if kind == 'ServiceAccount':
                        subject_ns = _native_optional(subject, 'namespace', binding_ns, str, source=binding)
                        if subject_ns == namespace and subject_name == sa and (binding_ns is None or binding_ns == namespace):
                            matched = True
            return result(not matched, namespace=namespace, pod=name, service_account=sa, matching_serviceaccount_binding=matched)
        if check_id == 'k8s.cis.consider_external_secret_storage':
            spec = get(item, 'spec', dict)
            if not _full_native(item):
                return unknown('full PodSpec provenance unavailable')
            volumes = optional(spec, 'volumes', [], list)
            containers = get(spec, 'containers', list)
            if not containers or any((not isinstance(x, dict) for x in containers)):
                raise Unavailable('Pod containers malformed')
            secret = False
            csi = False
            for volume in volumes:
                if not isinstance(volume, dict):
                    raise Unavailable('volume malformed')
                if 'secret' in volume:
                    if not get(volume, 'secret.secretName', str):
                        raise Unavailable('Secret name malformed')
                    secret = True
                if 'csi' in volume:
                    driver = get(volume, 'csi.driver', str)
                    if not driver:
                        raise Unavailable('CSI driver malformed')
                    csi |= driver == 'secrets-store.csi.k8s.io'
                for key in ('secret', 'csi'):
                    if key in volume.get('_coverage', {}):
                        get(volume, key, dict)
            for container in containers:
                for entry in optional(container, 'env', [], list):
                    if not isinstance(entry, dict):
                        raise Unavailable('environment entry malformed')
                    if 'valueFrom' in entry or 'valueFrom' in entry.get('_coverage', {}):
                        source = get(entry, 'valueFrom', dict)
                        if 'secretKeyRef' in source or 'secretKeyRef' in source.get('_coverage', {}):
                            if not get(source, 'secretKeyRef.name', str):
                                raise Unavailable('Secret name malformed')
                            secret = True
                for entry in optional(container, 'envFrom', [], list):
                    if not isinstance(entry, dict):
                        raise Unavailable('environment source malformed')
                    if 'secretRef' in entry or 'secretRef' in entry.get('_coverage', {}):
                        if not get(entry, 'secretRef.name', str):
                            raise Unavailable('Secret name malformed')
                        secret = True
            if not secret:
                return ('NOT_APPLICABLE', {'reason': 'Pod declares no native Secret reference'})
            return result(not csi, namespace=namespace, pod=name, semantics='Pod declaration only', native_secret_reference=True, secrets_store_csi_declared=csi)
        component = COMPONENT_POD_IDS.get(check_id)
        if component:
            flags = _component(item, component)
            if flags is None:
                return ('NOT_APPLICABLE', {'reason': 'Pod has no applicable component declaration'})
            if check_id == 'k8s.cis.controller_manager_rotate_kubelet_server_certificate_true':
                gates = get(flags, 'feature-gates', str)
                pairs = dict()
                for token in gates.split(','):
                    key, sep, value = token.partition('=')
                    if not sep or not key or value not in ('true', 'false') or (key in pairs):
                        raise Unavailable('feature gates malformed')
                    pairs[key] = value
                if 'RotateKubeletServerCertificate' not in pairs:
                    return unknown('RotateKubeletServerCertificate declaration missing')
                return result(pairs['RotateKubeletServerCertificate'] != 'true', rotate_kubelet_server_certificate=pairs['RotateKubeletServerCertificate'])
            if check_id == 'k8s.cis.the_service_account_extend_token_expiration_parameter_is_set_to_false':
                value = get(flags, 'service-account-extend-token-expiration', str)
                if value not in ('true', 'false'):
                    raise Unavailable('boolean component flag malformed')
                return result(value != 'false', extend_serviceaccount_token_expiration=value)
            if check_id == 'k8s.cis.the_request_timeout_argument_is_set_as_appropriate':
                maximum = _policy(index, 'approved_max_request_timeout', int)
                if not 0 < maximum < 1 << 63:
                    raise Unavailable('approved timeout malformed')
                value = get(flags, 'request-timeout', str)
                seconds = _duration_seconds(value)
                return result(not 0 < seconds <= maximum, seconds=float(seconds), approved_max_seconds=maximum)
            if check_id == 'k8s.cis.the_kube_proxy_metrics_service_is_bound_to_localhost':
                if get(get(index, 'context', dict), 'scope', str) != '*':
                    raise Unavailable('kube-proxy requires cluster-wide Pod coverage')
                _attested_coverage(index, 'kube_proxy_pod_coverage')
                value = get(flags, 'metrics-bind-address', str)
                endpoint = re.fullmatch('(?:\\[([^\\[\\]]+)\\]|([^:\\[\\]]+)):([0-9]+)', value)
                if not endpoint:
                    raise Unavailable('metrics bind address malformed')
                try:
                    host = endpoint[1] or endpoint[2]
                    port = int(endpoint[3])
                    ip = ipaddress.ip_address(host)
                except (ValueError, IndexError) as exc:
                    raise Unavailable('metrics bind address malformed') from exc
                if not 0 <= port <= 65535:
                    raise Unavailable('metrics bind port malformed')
                return result(str(ip) not in ('127.0.0.1', '::1'), address=value)
            if check_id == 'k8s.cis.configure_image_provenance_using_imagepolicywebhook_admission_controller':
                enabled = _flag_list(flags, 'enable-admission-plugins')
                disabled = _flag_list(flags, 'disable-admission-plugins')
                if 'ImagePolicyWebhook' not in enabled or 'ImagePolicyWebhook' in disabled:
                    return result(True, reason='ImagePolicyWebhook disabled in explicit flags')
                path = get(flags, 'admission-control-config-file', str)
                if not path.startswith('/') or not path.strip():
                    return result(True, reason='admission control config path invalid')
                return unknown('admission control file content has not been verified')
        raise Unavailable('unhandled Pod check')

    def _networkpolicy_evaluator(check_id, item, index):
        _member(item, index, 'networkpolicy')
        spec = get(item, 'spec', dict)
        if check_id == 'k8s_networkpolicy_has_ingress_rules':
            rules = _native_optional(spec, 'ingress', [], list, source=item)
            if any((not isinstance(x, dict) for x in rules)):
                raise Unavailable('ingress rules malformed')
            return result(len(rules) == 0, ingress_rule_count=len(rules))
        if check_id == 'k8s_networkpolicy_network_policy_associated_podselectors_that_92dbc93b4c':
            selector = get(spec, 'podSelector', dict)
            labels = _native_optional(selector, 'matchLabels', {}, dict, source=item)
            expressions = _native_optional(selector, 'matchExpressions', [], list, source=item)
            if any((not _label_key(k) or not _label_value(v) for k, v in labels.items())):
                raise Unavailable('matchLabels malformed')
            for expression in expressions:
                key = get(expression, 'key', str)
                operator = get(expression, 'operator', str)
                if not _label_key(key) or operator not in ('In', 'NotIn', 'Exists', 'DoesNotExist'):
                    raise Unavailable('matchExpressions malformed')
                values = _native_optional(expression, 'values', [], list, source=item)
                if any((not _label_value(value) for value in values)) or (operator in ('In', 'NotIn')) != bool(values):
                    raise Unavailable('matchExpressions values malformed')
            return result(not labels and (not expressions), selector_label_count=len(labels), selector_expression_count=len(expressions))
        raise Unavailable('unhandled NetworkPolicy check')

    def _scope_evaluator(check_id, item, index):
        if get(item, 'scope', str) != get(get(index, 'context', dict), 'scope', str):
            raise Unavailable('foreign scope target')
        if check_id in VERSION_IDS:
            rows = _inventory(index, 'api_discovery')
            if len(rows) != 1:
                raise Unavailable('API discovery ambiguous')
            observed = get(rows[0], 'serverVersion.gitVersion', str)
            oldest = _policy(index, 'oldestVersionSupported', str)

            def semver(value):
                match = re.fullmatch('v?(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?(?:\\+([0-9A-Za-z.-]+))?', value)
                if not match or len(value) > 253 or (match[5] is not None and any((not part for part in match[5].split('.')))):
                    raise Unavailable('Kubernetes semver malformed')
                prerelease = match[4]
                if prerelease is None:
                    suffix = (1, ())
                else:
                    parts = prerelease.split('.')
                    if any((not part or (part.isdigit() and len(part) > 1 and (part[0] == '0')) for part in parts)):
                        raise Unavailable('Kubernetes semver prerelease malformed')
                    suffix = (0, tuple(((0, int(part)) if part.isdigit() else (1, part) for part in parts)))
                return tuple(map(int, match.groups()[:3])) + suffix
            current, floor = (semver(observed), semver(oldest))
            return result(current < floor if check_id.endswith('at_least_oldest_supported') else current <= floor, observed=observed, oldest=oldest)
        if check_id == 'k8s_response_team_required_binding':
            namespaces = _string_set(index, 'allowed_namespaces')
            subject_kind = _policy(index, 'required_subject_kind', str)
            subject_name = _policy(index, 'required_subject_name', str)
            role_kind = _policy(index, 'required_role_kind', str)
            role_name = _policy(index, 'required_role_name', str)
            if subject_kind not in ('User', 'Group', 'ServiceAccount') or role_kind not in ('Role', 'ClusterRole') or any((not 0 < len(value) <= 253 or re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:@/-]*', value) is None for value in (subject_name, role_name))):
                raise Unavailable('required binding policy malformed')
            bindings = [(binding_kind, row) for binding_kind in ('rolebinding', 'clusterrolebinding') for row in _inventory(index, binding_kind)]
            matched = False
            for binding_kind, row in bindings:
                binding_ns = get(row, 'metadata.namespace', str) if binding_kind == 'rolebinding' else '*'
                role = (get(row, 'roleRef.kind', str), get(row, 'roleRef.name', str))
                if role[0] not in ('Role', 'ClusterRole') or not role[1] or (binding_kind == 'clusterrolebinding' and role[0] != 'ClusterRole'):
                    raise Unavailable('RBAC role reference malformed')
                subjects = _subjects(row, binding_kind)
                for subject in subjects:
                    if not isinstance(subject, dict):
                        raise Unavailable('subject malformed')
                    kind = get(subject, 'kind', str)
                    name = get(subject, 'name', str)
                    if binding_ns in namespaces and role == (role_kind, role_name) and (kind == subject_kind) and (name == subject_name):
                        matched = True
            return result(not matched)
        raise Unavailable('unhandled scope check')

    def _resource_evaluator(check_id, item, index):
        kind = SPECS[check_id]['resource_kind']
        if kind == 'pod':
            return _pod_evaluator(check_id, item, index)
        if kind == 'networkpolicy':
            return _networkpolicy_evaluator(check_id, item, index)
        if kind == 'namespace':
            _member(item, index, 'namespace')
            name = get(item, 'metadata.name', str)
            if not name:
                raise Unavailable('Namespace identity malformed')
            if check_id == 'k8s.cis.namespace_has_networkpolicy':
                system = _string_set(index, 'system_namespaces')
                if name in system:
                    return ('NOT_APPLICABLE', {'reason': 'configured system namespace'})
                policies = _inventory(index, 'networkpolicy')
                names = [get(row, 'metadata.namespace', str) for row in policies]
                return result(name not in names, namespace=name)
        if kind == 'component_configuration':
            _member(item, index, 'component_configuration')
            if check_id == 'k8s.cis.the_eventrecordqps_argument_is_set_to_a_level_which_ensures_appropriate_event_capture':
                if get(item, 'component', str) != 'kubelet':
                    return ('NOT_APPLICABLE', {'reason': 'not kubelet configuration'})
                _attested_coverage(index, 'component_configuration_coverage')
                threshold = _policy(index, 'approved_min_event_qps', int)
                if not 0 <= threshold < 1 << 63:
                    raise Unavailable('event QPS threshold malformed')
                qps = get(item, 'configuration.eventRecordQPS', int)
                if not 0 <= qps < 1 << 31:
                    raise Unavailable('event QPS declaration malformed')
                return result(qps < threshold, observed=qps, required=threshold)
        if kind == 'clusterrolebinding':
            _member(item, index, 'clusterrolebinding')
            if check_id == 'k8s.cis.avoid_use_of_system_masters_group':
                all_bindings = _inventory(index, 'clusterrolebinding') + _inventory(index, 'rolebinding')
                for binding in all_bindings:
                    for subject in optional(binding, 'subjects', [], list):
                        if not isinstance(subject, dict):
                            raise Unavailable('RBAC subject malformed')
                        if get(subject, 'kind', str) == 'Group' and get(subject, 'name', str) == 'system:masters':
                            return result(True, reason='observed binding to system:masters')
                return unknown('certificate and provider identity group membership not observed')
        if kind == 'service':
            _member(item, index, 'service')
            if check_id == 'k8s_service_external_traffic_policy_matches_required':
                names = _string_set(index, 'in_scope_service_names')
                required = _policy(index, 'required_external_traffic_policy', str)
                if required not in ('Cluster', 'Local'):
                    raise Unavailable('external traffic policy malformed')
                name = get(item, 'metadata.name', str)
                spec = get(item, 'spec', dict)
                service_type = _native_optional(spec, 'type', 'ClusterIP', str, source=item)
                if service_type not in ('ClusterIP', 'NodePort', 'LoadBalancer', 'ExternalName'):
                    raise Unavailable('Service type unrecognized')
                if name not in names or service_type != 'LoadBalancer':
                    return ('NOT_APPLICABLE', {'reason': 'Service outside selected LoadBalancer set'})
                observed = _native_optional(spec, 'externalTrafficPolicy', 'Cluster', str, source=item)
                if observed not in ('Cluster', 'Local'):
                    raise Unavailable('external traffic policy unrecognized')
                return result(observed != required, observed=observed, required=required)
        if kind == 'ingress':
            _member(item, index, 'ingress')
            if check_id == 'k8s_ingress_ingress_has_any_associated_ingress_93579100f9':
                rules = _native_optional(get(item, 'spec', dict), 'rules', [], list, source=item)
                if any((not isinstance(row, dict) for row in rules)):
                    raise Unavailable('Ingress rules malformed')
                return result(len(rules) == 0, rule_count=len(rules))
        raise Unavailable('unhandled check')
    POD_NODE_POOL_ID = 'k8s_pod_pod_deployed_specific_namespace_its_76714f9dfe'
    POD_NODE_SELECTOR_ID = 'k8s_pod_pod_deployed_within_specific_namespace_3790c81f90'
    POD_LABEL_ID = 'k8s_pod_pod_deployed_within_specific_namespace_62bb9e62c0'
    POD_RUNNING_ID = 'k8s_pod_pod_running_within_specific_namespace_0f3d581358'
    NAMESPACE_POD_IDS = {POD_NODE_POOL_ID, 'k8s_pod_pod_deployed_within_specific_namespace_0daa0bd46b', POD_NODE_SELECTOR_ID, POD_LABEL_ID, POD_RUNNING_ID}
    COMPONENT_POD_IDS = {'k8s.cis.controller_manager_rotate_kubelet_server_certificate_true': 'kube-controller-manager', 'k8s.cis.the_service_account_extend_token_expiration_parameter_is_set_to_false': 'kube-apiserver', 'k8s.cis.the_request_timeout_argument_is_set_as_appropriate': 'kube-apiserver', 'k8s.cis.the_kube_proxy_metrics_service_is_bound_to_localhost': 'kube-proxy', 'k8s.cis.configure_image_provenance_using_imagepolicywebhook_admission_controller': 'kube-apiserver'}
    VERSION_IDS = {'k8s_cluster_version_at_least_oldest_supported', 'k8s_cluster_version_supported'}
    DEPENDENCIES = {POD_NODE_POOL_ID: ['pod', 'node'], 'k8s_pod_serviceaccount_has_rbac_binding': ['pod', 'rolebinding', 'clusterrolebinding'], 'k8s.cis.namespace_has_networkpolicy': ['namespace', 'networkpolicy'], 'k8s.cis.avoid_use_of_system_masters_group': ['clusterrolebinding', 'rolebinding'], 'k8s_response_team_required_binding': ['rolebinding', 'clusterrolebinding']}
    DEPENDENCIES.update({'k8s_cluster_version_at_least_oldest_supported': ['api_discovery'], 'k8s_cluster_version_supported': ['api_discovery']})
    for _id, _spec in SPECS.items():
        _kind = 'api_discovery' if _id in VERSION_IDS else _spec['resource_kind']
        _target = 'scope' if _id in VERSION_IDS or _id == 'k8s_response_team_required_binding' else 'resource'
        _dependencies = DEPENDENCIES.get(_id, [_kind])

        @register(_id, 'k8s', _spec['category'], _kind, _spec['title'], _spec['severity'], 'CM-6', _spec['remediation_hint'], target=_target, dependencies=_dependencies)
        def _evaluate(item, index, check_id=_id, target=_target):
            return _scope_evaluator(check_id, item, index) if target == 'scope' else _resource_evaluator(check_id, item, index)
    from .facts import memoized as _batch_memoized
    _base_inventory = _inventory

    def _inventory(index, kind):
        return _batch_memoized(index, ('batch_sw10_inventory', kind, index.get('context', {}).get('scope')), lambda: _base_inventory(index, kind))

    def _member(item, index, kind):
        rows = _inventory(index, kind)
        fingerprints = _batch_memoized(index, ('batch_sw10_members', kind, index.get('context', {}).get('scope')), lambda: Counter((json.dumps(row, sort_keys=True) for row in rows)))
        try:
            identity = json.dumps(item, sort_keys=True)
        except (TypeError, ValueError) as exc:
            raise Unavailable('item malformed') from exc
        if fingerprints[identity] < 1:
            raise Unavailable('item not present in complete inventory')
        return rows
_load_10()

# Source family: compliance_new_sw56.py
def _load_56():
    _ALLOWED = {'k8s.cis.admission_allowprivilegeescalation', 'k8s.cis.admission_capabilities_add', 'k8s.cis.admission_capabilities_add_net_raw', 'k8s.cis.admission_capabilities_drop', 'k8s.cis.admission_container_ports_hostport', 'k8s.cis.admission_hostipc', 'k8s.cis.admission_hostnetwork', 'k8s.cis.admission_hostpath', 'k8s.cis.admission_hostpid', 'k8s.cis.admission_privileged', 'k8s.cis.admission_runasnonroot', 'k8s.cis.admission_windowsoptions_hostprocess', 'k8s_approved_image_installation'}
    'Signed Kubernetes admission and image checks (sw56).\n\nAdmission decisions use only recognized CEL declarations and complete, cluster-bound\nAPI inventories. Unknown CEL semantics never establish enforcement or absence.\n'
    import json
    import re
    from dataclasses import replace
    from datetime import datetime
    from . import CHECKS, register, result, unknown
    from .facts import Unavailable, complete_items, get, memoized
    SPECS = {'k8s.cis.admission_allowprivilegeescalation': {'category': 'hardening', 'hint': 'Create a ValidatingAdmissionPolicy and binding with a CEL validation equivalent to `object.spec.containers.all(c, c.securityContext.allowPrivilegeEscalation == false)` and validationActions: [Deny], or set Pod Security Admission enforce=restricted where it covers this field; allowPrivilegeEscalation false on each container.', 'kind': 'admission_policy', 'severity': 'medium', 'sha': '224b0185859bb6795c15b22156573eb0b82583bc0f6bbf44a26cd95db14b4603', 'title': 'Admission forbids allowPrivilegeEscalation'}, 'k8s.cis.admission_capabilities_add': {'category': 'hardening', 'hint': 'Create a ValidatingAdmissionPolicy and binding with a CEL validation equivalent to `object.spec.containers.all(c, !has(c.securityContext.capabilities.add) || size(c.securityContext.capabilities.add)==0)` and validationActions: [Deny], or set Pod Security Admission enforce=restricted where it covers this field; drop ALL and add no capabilities.', 'kind': 'admission_policy', 'severity': 'medium', 'sha': '502451c92f88a516a9b31c57950f963c053bfbd89f153e3b8201ec91e72ebc94', 'title': 'Admission forbids capabilities.add'}, 'k8s.cis.admission_capabilities_add_net_raw': {'category': 'hardening', 'hint': 'Create a ValidatingAdmissionPolicy and binding with a CEL validation equivalent to `object.spec.containers.all(c, !has(c.securityContext.capabilities.add) || !c.securityContext.capabilities.add.exists(x, x=="NET_RAW"))` and validationActions: [Deny], or set Pod Security Admission enforce=restricted where it covers this field; remove NET_RAW from capabilities.add.', 'kind': 'admission_policy', 'severity': 'medium', 'sha': 'bc46b030150b9b266865ec8e3472a53e801ce019cfacfc7cf2afa0dae32af805', 'title': 'Admission forbids capabilities.add NET_RAW'}, 'k8s.cis.admission_capabilities_drop': {'category': 'hardening', 'hint': 'Create a ValidatingAdmissionPolicy and binding with a CEL validation equivalent to `object.spec.containers.all(c, has(c.securityContext.capabilities.drop) && c.securityContext.capabilities.drop.exists(x, x=="ALL"))` and validationActions: [Deny], or set Pod Security Admission enforce=restricted where it covers this field; drop ALL capabilities.', 'kind': 'admission_policy', 'severity': 'medium', 'sha': '7d25a97fd22258704b1133f3781e153f90e68d0e0b2d947186b39ff91c2ac477', 'title': 'Admission forbids capabilities.drop'}, 'k8s.cis.admission_container_ports_hostport': {'category': 'hardening', 'hint': 'Create a ValidatingAdmissionPolicy and binding with a CEL validation equivalent to `object.spec.containers.all(c, !has(c.ports) || c.ports.all(p, !has(p.hostPort) || p.hostPort==0))` and validationActions: [Deny], or set Pod Security Admission enforce=restricted where it covers this field; remove hostPort from containers.', 'kind': 'admission_policy', 'severity': 'medium', 'sha': 'ac0ae88d83753ba169adf90a5e0258ed3ca5d6b5d2569871d9b313d70cad1d10', 'title': 'Admission forbids container ports.hostPort'}, 'k8s.cis.admission_hostipc': {'category': 'hardening', 'hint': 'Create a ValidatingAdmissionPolicy and binding with a CEL validation equivalent to `!has(object.spec.hostIPC) || object.spec.hostIPC==false` and validationActions: [Deny], or set Pod Security Admission enforce=restricted where it covers this field; set hostIPC false.', 'kind': 'admission_policy', 'severity': 'medium', 'sha': 'b4fed62a3fd79c8d22b790ac52a938db52ec47ccbd01de3a5d4c90356cad38b1', 'title': 'Admission forbids hostIPC'}, 'k8s.cis.admission_hostnetwork': {'category': 'hardening', 'hint': 'Create a ValidatingAdmissionPolicy and binding with a CEL validation equivalent to `!has(object.spec.hostNetwork) || object.spec.hostNetwork==false` and validationActions: [Deny], or set Pod Security Admission enforce=restricted where it covers this field; set hostNetwork false.', 'kind': 'admission_policy', 'severity': 'medium', 'sha': '48b7f83cbb2a87a2bd38f58ba30d2da1d20354f5de041862066375ee2754dd14', 'title': 'Admission forbids hostNetwork'}, 'k8s.cis.admission_hostpath': {'category': 'hardening', 'hint': 'Create a ValidatingAdmissionPolicy and binding with a CEL validation equivalent to `!has(object.spec.volumes) || object.spec.volumes.all(v, !has(v.hostPath))` and validationActions: [Deny], or set Pod Security Admission enforce=restricted where it covers this field; replace hostPath with a PVC or other scoped volume.', 'kind': 'admission_policy', 'severity': 'medium', 'sha': 'ecbc26cb67678979aa2fd58e5621e7ca68db1f70c06791708052b417fd85119d', 'title': 'Admission denies HostPath volumes'}, 'k8s.cis.admission_hostpid': {'category': 'hardening', 'hint': 'Create a ValidatingAdmissionPolicy and binding with a CEL validation equivalent to `!has(object.spec.hostPID) || object.spec.hostPID==false` and validationActions: [Deny], or set Pod Security Admission enforce=restricted where it covers this field; set hostPID false.', 'kind': 'admission_policy', 'severity': 'medium', 'sha': 'd05850dd8a18c0b560b144eaa089b283e5a25781ca1b5d07f8a2bcf461c3dbdb', 'title': 'Admission forbids hostPID'}, 'k8s.cis.admission_privileged': {'category': 'hardening', 'hint': 'Create a ValidatingAdmissionPolicy and binding with a CEL validation equivalent to `object.spec.containers.all(c, !has(c.securityContext.privileged) || c.securityContext.privileged==false)` and validationActions: [Deny], or set Pod Security Admission enforce=restricted where it covers this field; set securityContext.privileged false.', 'kind': 'admission_policy', 'severity': 'medium', 'sha': '3590c293438808fd2a04cdccb8f7d5aade58da2fcd345220429e35a89a0ba490', 'title': 'Admission forbids privileged'}, 'k8s.cis.admission_runasnonroot': {'category': 'hardening', 'hint': 'Create a ValidatingAdmissionPolicy and binding with a CEL validation equivalent to `object.spec.containers.all(c, (has(c.securityContext.runAsNonRoot) && c.securityContext.runAsNonRoot==true) || (!has(c.securityContext.runAsNonRoot) && has(object.spec.securityContext.runAsNonRoot) && object.spec.securityContext.runAsNonRoot==true))` and validationActions: [Deny], or set Pod Security Admission enforce=restricted where it covers this field; set runAsNonRoot true on the Pod or every container.', 'kind': 'admission_policy', 'severity': 'medium', 'sha': '03d949524241f82fda7020314de41f5457dad3b3c4f86537573b0253d561ba7f', 'title': 'Admission forbids runAsNonRoot'}, 'k8s.cis.admission_windowsoptions_hostprocess': {'category': 'hardening', 'hint': 'Create a ValidatingAdmissionPolicy and binding with a CEL validation equivalent to `object.spec.containers.all(c, !has(c.securityContext.windowsOptions.hostProcess) || c.securityContext.windowsOptions.hostProcess==false)` and validationActions: [Deny], or set Pod Security Admission enforce=restricted where it covers this field; set windowsOptions.hostProcess false.', 'kind': 'admission_policy', 'severity': 'medium', 'sha': 'd0812f3ec7685b2ed65fe5df66f4880e577731d0cd83ee8b4588c33cc71a2190', 'title': 'Admission forbids windowsOptions.hostProcess'}, 'k8s.cis.configure_image_provenance_using_imagepolicywebhook_admission_controller': {'category': 'supply_chain', 'hint': 'Add ImagePolicyWebhook to kube-apiserver --enable-admission-plugins and set --admission-control-config-file to a readable AdmissionConfiguration containing its kubeConfigFile.', 'kind': 'pod', 'severity': 'medium', 'sha': 'bdcb6fdc5758d8deee371b9c7e82e70f4b40f753e6a33f3c5ad8f9e93009bd85', 'title': 'Configure Image Provenance using ImagePolicyWebhook admission controller'}, 'k8s_approved_image_installation': {'category': 'supply_chain', 'hint': 'Pin Pod images to approved registry digests and bind a ValidatingAdmissionPolicy with validationActions: [Deny] for Pod CREATE and UPDATE across the target namespaces.', 'kind': 'pod', 'severity': 'high', 'sha': '91c5faf48c6a380644bb003b65d9ee28c589209cdea2fefa3f5a26df035278ef', 'title': 'Check authorized Kubernetes image installation'}, 'k8s_pod_secret_pod_rule_non_compliant_fcdc38e543': {'category': 'supply_chain', 'hint': 'Create a docker-registry Secret in the Pod namespace and add its name under spec.imagePullSecrets in the Pod template.', 'kind': 'pod', 'severity': 'medium', 'sha': '8db5eb07fc7feb29f1f9696419846cf035b624125f2286d9c9d1e059a8c00809', 'title': 'Core'}}
    SPECS = {k: v for k, v in SPECS.items() if k in _ALLOWED}
    IDS = tuple(SPECS)
    ADMISSION_IDS = tuple((key for key in IDS if key.startswith('k8s.cis.admission_')))
    PROVENANCE_ID = 'k8s.cis.configure_image_provenance_using_imagepolicywebhook_admission_controller'
    APPROVED_ID = 'k8s_approved_image_installation'
    SECRET_ID = 'k8s_pod_secret_pod_rule_non_compliant_fcdc38e543'

    def _context(index):
        context = get(index, 'context', dict)
        if get(context, 'provider', str) != 'k8s':
            raise Unavailable('foreign provider')
        scope = get(context, 'scope', str)
        cluster = get(context, 'metadata.cluster_id', str)
        if not scope or not cluster:
            raise Unavailable('snapshot scope or cluster identity absent')
        return (context, scope, cluster)

    def _inventory(index, kind):
        _, scope, cluster = _context(index)
        envelopes = get(index, 'collections', dict).get(kind)
        if not isinstance(envelopes, list) or not envelopes or any((not isinstance(envelope, dict) or envelope.get('scope') != scope or envelope.get('type') != kind for envelope in envelopes)):
            raise Unavailable('missing or foreign scoped ' + kind + ' inventory')
        rows = complete_items(index, kind)
        declared_count = sum((len(get(envelope, 'items', list)) for envelope in envelopes))
        if declared_count != len(rows):
            raise Unavailable('deduplicated or inconsistent ' + kind + ' inventory')
        seen_pods = set()
        for row in rows:
            if get(row, 'provenance.cluster_id', str) != cluster:
                raise Unavailable('foreign cluster in ' + kind + ' inventory')
            if kind == 'pod':
                # Items of a typed Pod list carry no per-item kind; only a declared foreign kind is rejected.
                if row.get('kind', 'Pod') != 'Pod':
                    raise Unavailable('Pod inventory contains a foreign resource kind')
                namespace = get(row, 'metadata.namespace', str)
                uid = get(row, 'metadata.uid', str)
                if not namespace or not uid or (namespace, uid) in seen_pods or (scope != '*' and scope != namespace):
                    raise Unavailable('Pod identity duplicated, malformed, or outside scope')
                seen_pods.add((namespace, uid))
        return rows

    def _member(item, index, kind):
        rows = _inventory(index, kind)
        if not any((row is item or row == item for row in rows)):
            raise Unavailable('target absent from complete ' + kind + ' inventory')
        return rows

    def _full(item):
        return get(item, 'provenance.evidence', str) == 'read-only list'

    def _native_optional(item, key, default, expected, *, source):
        coverage = item.get('_coverage', {})
        if not isinstance(coverage, dict):
            raise Unavailable('field coverage malformed')
        if key in item or key in coverage:
            return get(item, key, expected)
        if _full(source):
            return default
        raise Unavailable('omitted field without full native representation: ' + key)

    def _named(item, kind):
        if get(item, 'kind', str) != kind:
            raise Unavailable('unexpected admission resource kind')
        name = get(item, 'metadata.name', str)
        if not name:
            raise Unavailable('admission resource name empty')
        return name

    def _namespaces(index):
        rows = _inventory(index, 'namespace')
        seen = set()
        result_rows = []
        for row in rows:
            if row.get('kind', 'Namespace') != 'Namespace':  # Typed list items carry no kind.
                raise Unavailable('Namespace inventory contains a foreign resource kind')
            name = get(row, 'metadata.name', str)
            if not name or name in seen:
                raise Unavailable('Namespace identity malformed or duplicated')
            seen.add(name)
            metadata = get(row, 'metadata', dict)
            labels = _native_optional(metadata, 'labels', {}, dict, source=row)
            if any((not isinstance(key, str) or not isinstance(value, str) for key, value in labels.items())):
                raise Unavailable('Namespace labels malformed')
            result_rows.append((name, labels))
        return result_rows

    def _admission_rows(index):
        rows = _inventory(index, 'admission_policy')
        policies, bindings, seen = ({}, [], set())
        for row in rows:
            kind = get(row, 'kind', str)
            name = get(row, 'metadata.name', str)
            if not name or (kind, name) in seen:
                raise Unavailable('admission policy identity malformed or duplicated')
            seen.add((kind, name))
            if kind == 'ValidatingAdmissionPolicy':
                policies[name] = row
            elif kind == 'ValidatingAdmissionPolicyBinding':
                bindings.append(row)
            elif kind not in ('MutatingAdmissionPolicy', 'MutatingAdmissionPolicyBinding'):
                raise Unavailable('unrecognized admission policy kind')
        return (policies, bindings)

    def _selector(selector, labels, *, source, pod_selector=False):
        if not isinstance(selector, dict):
            raise Unavailable('admission selector malformed')
        if selector.get('matchExpressions'):
            return None
        expressions = _native_optional(selector, 'matchExpressions', [], list, source=source)
        if expressions:
            return None
        required = _native_optional(selector, 'matchLabels', {}, dict, source=source)
        if any((not isinstance(key, str) or not key or (not isinstance(value, str)) for key, value in required.items())):
            raise Unavailable('admission selector labels malformed')
        if pod_selector and required:
            return None
        return all((labels.get(key) == value for key, value in required.items()))

    def _rules_match(rules, *, source):
        if not isinstance(rules, list):
            raise Unavailable('admission resourceRules malformed')
        if not rules:
            raise Unavailable('empty admission resourceRules semantics unresolved')
        covered = set()
        for rule in rules:
            if not isinstance(rule, dict):
                raise Unavailable('admission resource rule malformed')
            groups = get(rule, 'apiGroups', list)
            versions = get(rule, 'apiVersions', list)
            resources = get(rule, 'resources', list)
            operations = get(rule, 'operations', list)
            if any((not isinstance(values, list) or any((not isinstance(value, str) for value in values)) for values in (groups, versions, resources, operations))):
                raise Unavailable('admission resource rule values malformed')
            scope = _native_optional(rule, 'scope', '*', str, source=source)
            if scope not in ('*', 'Namespaced', 'Cluster'):
                raise Unavailable('admission resource rule scope malformed')
            if ('' in groups or '*' in groups) and ('v1' in versions or '*' in versions) and ('pods' in resources or '*' in resources) and (scope in ('*', 'Namespaced')):
                covered.update((operation for operation in ('CREATE', 'UPDATE') if operation in operations or '*' in operations))
        return covered == {'CREATE', 'UPDATE'}

    def _match_resources(match, labels, *, source):
        if not isinstance(match, dict):
            raise Unavailable('binding matchResources malformed')
        if _native_optional(match, 'excludeResourceRules', [], list, source=source):
            return None
        namespace = _native_optional(match, 'namespaceSelector', {}, dict, source=source)
        object_selector = _native_optional(match, 'objectSelector', {}, dict, source=source)
        selected = _selector(namespace, labels, source=source)
        if selected is not True:
            return selected
        selected = _selector(object_selector, {}, source=source, pod_selector=True)
        if selected is not True:
            return selected
        rules = _native_optional(match, 'resourceRules', None, (list, type(None)), source=source)
        return True if rules is None else _rules_match(rules, source=source)

    def _policy_match(policy, labels):
        spec = get(policy, 'spec', dict)
        if _native_optional(spec, 'paramKind', None, (dict, type(None)), source=policy) is not None:
            return None
        if _native_optional(spec, 'matchConditions', [], list, source=policy):
            return None
        failure = _native_optional(spec, 'failurePolicy', 'Fail', str, source=policy)
        if failure not in ('Fail', 'Ignore'):
            raise Unavailable('failurePolicy malformed')
        if failure != 'Fail':
            return None
        constraints = get(spec, 'matchConstraints', dict)
        get(constraints, 'resourceRules', list)
        return _match_resources(constraints, labels, source=policy)

    def _bound_expressions(index, namespace, labels):
        policies, bindings = _admission_rows(index)
        matched, uncertain = ([], False)
        for binding in bindings:
            spec = get(binding, 'spec', dict)
            name = get(spec, 'policyName', str)
            actions = get(spec, 'validationActions', list)
            if not name or any((action not in ('Deny', 'Warn', 'Audit') for action in actions)):
                raise Unavailable('binding policy name or actions malformed')
            if 'Deny' not in actions:
                continue
            if _native_optional(spec, 'paramRef', None, (dict, type(None)), source=binding) is not None:
                uncertain = True
                continue
            policy = policies.get(name)
            if policy is None:
                uncertain = True
                continue
            match = _native_optional(spec, 'matchResources', {}, dict, source=binding)
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
            validations = get(policy, 'spec.validations', list)
            if not validations:
                uncertain = True
                continue
            expressions = []
            for validation in validations:
                expression = get(validation, 'expression', str)
                if not expression:
                    raise Unavailable('empty CEL validation expression')
                expressions.append(expression)
            matched.append((name, expressions))
        return (matched, uncertain)

    def _compact(expression):
        compact = []
        quote = None
        escaped = False
        for char in expression:
            if quote is not None:
                compact.append(char)
                if escaped:
                    escaped = False
                elif char == '\\':
                    escaped = True
                elif char == quote:
                    quote = None
            elif char in ('"', "'"):
                quote = char
                compact.append(char)
            elif not char.isspace():
                compact.append(char)
        if quote is not None:
            raise Unavailable('CEL string literal malformed')
        return ''.join(compact)

    def _all_containers(test):
        return ' && '.join((f'object.spec.containers.all(c, {test})', f'(!has(object.spec.initContainers) || object.spec.initContainers.all(c, {test}))', f'(!has(object.spec.ephemeralContainers) || object.spec.ephemeralContainers.all(c, {test}))'))
    CONTAINER_TESTS = {'allowprivilegeescalation': 'has(c.securityContext) && has(c.securityContext.allowPrivilegeEscalation) && c.securityContext.allowPrivilegeEscalation == false', 'capabilities_add': '!has(c.securityContext) || !has(c.securityContext.capabilities) || !has(c.securityContext.capabilities.add) || size(c.securityContext.capabilities.add) == 0', 'capabilities_add_net_raw': '!has(c.securityContext) || !has(c.securityContext.capabilities) || !has(c.securityContext.capabilities.add) || !c.securityContext.capabilities.add.exists(x, x == "NET_RAW")', 'capabilities_drop': 'has(c.securityContext) && has(c.securityContext.capabilities) && has(c.securityContext.capabilities.drop) && c.securityContext.capabilities.drop.exists(x, x == "ALL")', 'container_ports_hostport': '!has(c.ports) || c.ports.all(p, !has(p.hostPort) || p.hostPort == 0)', 'privileged': '!has(c.securityContext) || !has(c.securityContext.privileged) || c.securityContext.privileged == false', 'runasnonroot': '((has(c.securityContext) && has(c.securityContext.runAsNonRoot)) ? c.securityContext.runAsNonRoot == true : (has(object.spec.securityContext) && has(object.spec.securityContext.runAsNonRoot) && object.spec.securityContext.runAsNonRoot == true))', 'windowsoptions_hostprocess': '!has(c.securityContext) || !has(c.securityContext.windowsOptions) || !has(c.securityContext.windowsOptions.hostProcess) || c.securityContext.windowsOptions.hostProcess == false'}
    HOST_TESTS = {'hostipc': '!has(object.spec.hostIPC) || object.spec.hostIPC == false', 'hostnetwork': '!has(object.spec.hostNetwork) || object.spec.hostNetwork == false', 'hostpid': '!has(object.spec.hostPID) || object.spec.hostPID == false', 'hostpath': '!has(object.spec.volumes) || object.spec.volumes.all(v, !has(v.hostPath))'}

    def _required_cel(suffix):
        if suffix in HOST_TESTS:
            return HOST_TESTS[suffix]
        test = CONTAINER_TESTS[suffix]
        expression = _all_containers(test)
        if suffix == 'windowsoptions_hostprocess':
            return '(!has(object.spec.securityContext) || !has(object.spec.securityContext.windowsOptions) || !has(object.spec.securityContext.windowsOptions.hostProcess) || object.spec.securityContext.windowsOptions.hostProcess == false) && ' + expression
        return expression

    def _admission_check(check_id, item, index):
        _, scope, _ = _context(index)
        if get(item, 'scope', str) != scope:
            raise Unavailable('foreign admission scope target')
        namespaces = _namespaces(index)
        if not namespaces:
            return ('NOT_APPLICABLE', {'reason': 'complete Namespace inventory is empty'})
        required = _compact(_required_cel(check_id.removeprefix('k8s.cis.admission_')))
        missing, uncertain, covered = ([], [], [])
        for namespace, labels in namespaces:
            matches, possible = _bound_expressions(index, namespace, labels)
            if any((required in {_compact(expression) for expression in expressions} for _, expressions in matches)):
                covered.append(namespace)
            elif possible or matches:
                uncertain.append(namespace)
            else:
                missing.append(namespace)
        if missing:
            return result(True, namespaces_without_binding=missing, covered_namespaces=covered, semantics='No Deny binding with applicable Pod CREATE and UPDATE coverage')
        if uncertain:
            return unknown('CEL semantics or binding coverage unresolved', namespaces=uncertain)
        return result(False, covered_namespaces=covered, cel_subset='literal recognized expression')

    def _operator_policy(index):
        context, _, cluster = _context(index)
        policy = get(context, 'metadata.compliance_policy', dict)
        if get(policy, 'status', str) != 'collected' or get(policy, 'cluster_id', str) != cluster:
            raise Unavailable('owner image policy unavailable or foreign cluster')
        if 'observed_at' in policy or 'max_age_seconds' in policy:
            observed = get(policy, 'observed_at', str)
            age = get(policy, 'max_age_seconds', int)
            capture = get(context, 'created_at', str)
            try:
                one = datetime.fromisoformat(capture.replace('Z', '+00:00'))
                two = datetime.fromisoformat(observed.replace('Z', '+00:00'))
                if one.tzinfo is None or one.utcoffset() is None or two.tzinfo is None or (two.utcoffset() is None):
                    raise ValueError('timezone absent')
                elapsed = (one - two).total_seconds()
            except ValueError as exc:
                raise Unavailable('owner image policy timestamp malformed') from exc
            if age <= 0 or not 0 <= elapsed <= age:
                raise Unavailable('owner image policy stale or future')
        approved = get(policy, 'approved_images', list)
        if not approved or any((not isinstance(image, str) or not re.fullmatch('[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?/[a-zA-Z0-9._/-]+@sha256:[a-f0-9]{64}', image) for image in approved)) or len(set(approved)) != len(approved):
            raise Unavailable('approved image registry/digest set malformed')
        return sorted(approved)

    def _image_cel(images):
        approved = '[' + ', '.join((json.dumps(image) for image in images)) + ']'
        return _all_containers(f'c.image in {approved}')

    def _approved_image(item, index):
        _member(item, index, 'pod')
        images = _operator_policy(index)
        spec = get(item, 'spec', dict)
        observed = []
        for field in ('containers', 'initContainers', 'ephemeralContainers'):
            rows = get(spec, field, list) if field == 'containers' else _native_optional(spec, field, [], list, source=item)
            if field == 'containers' and (not rows):
                raise Unavailable('Pod has no containers')
            for container in rows:
                image = get(container, 'image', str)
                if not image:
                    raise Unavailable('Pod image empty')
                observed.append(image)
        unapproved = sorted(set(observed) - set(images))
        if unapproved:
            return result(True, unapproved_images=unapproved, semantics='declared Pod image outside owner allowlist')
        namespace = get(item, 'metadata.namespace', str)
        if not namespace:
            raise Unavailable('Pod namespace absent')
        names = dict(_namespaces(index))
        if namespace not in names:
            raise Unavailable('Pod Namespace absent from complete inventory')
        matches, possible = _bound_expressions(index, namespace, names[namespace])
        required = _compact(_image_cel(images))
        if any((required in {_compact(expression) for expression in expressions} for _, expressions in matches)):
            return result(False, approved_images=observed, namespace=namespace)
        if possible or matches:
            return unknown('image admission CEL semantics or binding coverage unresolved')
        return result(True, reason='no Deny binding enforcing approved images on Pod CREATE and UPDATE', namespace=namespace)

    def _image_provenance(item, index):
        _member(item, index, 'pod')
        spec = get(item, 'spec', dict)
        containers = get(spec, 'containers', list)
        if not containers or any((not isinstance(row, dict) for row in containers)):
            raise Unavailable('Pod container declaration malformed')
        matched, ambiguous = ([], False)
        for container in containers:
            config = _native_optional(container, '_component_config', None, (dict, type(None)), source=item)
            if config is None:
                ambiguous = True
                continue
            component = get(config, 'component', (str, type(None)))
            if component == 'kube-apiserver':
                if get(config, 'flags_complete', bool) is not True:
                    raise Unavailable('API server flags incomplete')
                matched.append(config)
            elif component is None and config.get('component_identification') != 'ordinary_command':
                ambiguous = True
        if ambiguous or len(matched) > 1:
            return unknown('kube-apiserver component identification incomplete or ambiguous')
        if not matched:
            return ('NOT_APPLICABLE', {'reason': 'Pod is not an identified kube-apiserver'})
        flags = get(matched[0], 'flags', dict)

        def plugins(name):
            value = get(flags, name, str)
            parts = value.split(',')
            if any((not re.fullmatch('[A-Za-z][A-Za-z0-9-]*', part) for part in parts)) or len(parts) != len(set(parts)):
                raise Unavailable('admission plugin flag malformed')
            return set(parts)
        enabled, disabled = (plugins('enable-admission-plugins'), plugins('disable-admission-plugins'))
        if 'ImagePolicyWebhook' not in enabled or 'ImagePolicyWebhook' in disabled:
            return result(True, reason='ImagePolicyWebhook explicitly disabled')
        path = flags.get('admission-control-config-file')
        if path is None:
            return unknown('admission-control-config-file not projected by current collector')
        if not isinstance(path, str) or not path:
            raise Unavailable('admission control config path malformed')
        if not path.startswith('/') or '..' in path.split('/'):
            return result(True, reason='admission control config path is not absolute and normalized')
        files = _inventory(index, 'admission_configuration_file')
        pod_uid = get(item, 'metadata.uid', str)
        matching = [row for row in files if get(row, 'pod_uid', str) == pod_uid and get(row, 'path', str) == path]
        if len(matching) != 1:
            raise Unavailable('admission file content not verified for API server Pod and path')
        file = matching[0]
        if get(file, 'verification_status', str) != 'verified':
            raise Unavailable('admission file content unverified')
        plugins = get(file, 'plugins', list)
        if any((not isinstance(plugin, dict) for plugin in plugins)):
            raise Unavailable('admission plugin configuration malformed')
        webhook = [plugin for plugin in plugins if get(plugin, 'name', str) == 'ImagePolicyWebhook']
        if not webhook:
            return result(True, reason='ImagePolicyWebhook plugin configuration absent')
        if len(webhook) > 1:
            raise Unavailable('ambiguous duplicate ImagePolicyWebhook plugin configuration')
        kubeconfig = get(webhook[0], 'configuration.kubeConfigFile', str)
        if not kubeconfig.startswith('/') or '..' in kubeconfig.split('/'):
            return result(True, reason='ImagePolicyWebhook kubeConfigFile path invalid')
        return result(False, admission_config_path=path, webhook_kubeconfig_path=kubeconfig, semantics='verified admission file declaration; webhook endpoint health unassessed')

    def _pod_secret(item, index):
        _member(item, index, 'pod')
        spec = get(item, 'spec', dict)
        secrets = _native_optional(spec, 'imagePullSecrets', [], list, source=item)
        if any((not isinstance(entry, dict) for entry in secrets)):
            raise Unavailable('imagePullSecrets malformed')
        names = [get(entry, 'name', str) for entry in secrets]
        if any((not name for name in names)):
            raise Unavailable('imagePullSecrets entry name empty')
        return result(not names, image_pull_secret_names=names, semantics='PodSpec references only; Secret existence unassessed')
    for _id, _spec in SPECS.items():
        _deps = ['admission_policy', 'namespace'] if _id in ADMISSION_IDS else ['pod', 'namespace', 'admission_policy'] if _id == APPROVED_ID else ['pod', 'admission_configuration_file'] if _id == PROVENANCE_ID else ['pod']
        _target = 'scope' if _id in ADMISSION_IDS else 'resource'
        _native_category = _spec['category'] if _spec['category'] in {'hardening', 'exposure', 'least_privilege', 'iam_graph', 'network'} else 'hardening'

        @register(_id, 'k8s', _native_category, _spec['kind'], _spec['title'], _spec['severity'], 'CM-6', _spec['hint'], target=_target, dependencies=_deps)
        def _evaluate(item, index, check_id=_id):
            if check_id in ADMISSION_IDS:
                return _admission_check(check_id, item, index)
            if check_id == APPROVED_ID:
                return _approved_image(item, index)
            if check_id == PROVENANCE_ID:
                return _image_provenance(item, index)
            return _pod_secret(item, index)
        _evaluate.__name__ = _id.replace('.', '_')
        if _native_category != _spec['category']:
            pass
    from .facts import memoized as _batch_memoized
    from collections import Counter as _batch_Counter
    _base_inventory = _inventory

    def _inventory(index, kind):
        return _batch_memoized(index, ('batch_sw56_inventory', kind, index.get('context', {}).get('scope')), lambda: _base_inventory(index, kind))

    def _member(item, index, kind):
        rows = _inventory(index, kind)
        fingerprints = _batch_memoized(index, ('batch_sw56_members', kind, index.get('context', {}).get('scope')), lambda: _batch_Counter((json.dumps(row, sort_keys=True) for row in rows)))
        try:
            identity = json.dumps(item, sort_keys=True)
        except (TypeError, ValueError) as exc:
            raise Unavailable('item malformed') from exc
        if fingerprints[identity] < 1:
            raise Unavailable('target absent from complete ' + kind + ' inventory')
        return rows
_load_56()

# Source family: compliance_new_sw57.py
def _load_57():
    _ALLOWED = {'k8s.cis.file_pki_owner', 'k8s.cis.file_var_lib_etcd_owner', 'k8s.cis.psp_binding_enforced', 'k8s.cis.the_ipaddressdeny_is_set_to_any', 'k8s_cluster_appropriate_set_procedures_information_labelling_should_e24bda19', 'k8s_environment_separation', 'k8s_networkpolicy_cluster_has_network_policies_that_1fd253608e', 'k8s_networkpolicy_cluster_has_network_policies_that_24d2fc90b0', 'k8s_networkpolicy_has_ingress_or_egress_rules', 'k8s_networkpolicy_world_ingress_authorized_ports', 'k8s_persistentvolume_persistentvolumeclaims_pvc_permissions_do_not_allow_00af04b0', 'k8s_privileged_utility_access'}
    'Signed Kubernetes defensive checks for swarm slice 57.\n\nOnly complete, cluster-bound snapshot facts can establish PASS or FAIL.\n'
    import ipaddress
    import json
    import re
    from collections import Counter
    from dataclasses import replace
    from datetime import datetime
    from . import CHECKS, register, result, unknown
    from .facts import Unavailable, complete_items, get
    SPECS = {'k8s_networkpolicy_cluster_has_network_policies_that_1fd253608e': {'resource_kind': 'networkpolicy', 'category': 'network', 'severity': 'medium', 'title': 'Core', 'remediation_hint': 'Narrow spec.ingress[].from[].ipBlock.cidr to trusted ranges or limit spec.ingress[].ports to the approved protocol/port pairs.', 'sha': 'a1e4fc801622d32658ead5ed6097263ed610377465469826b8aa54a9e4d16ef4'}, 'k8s_networkpolicy_cluster_has_network_policies_that_24d2fc90b0': {'resource_kind': 'networkpolicy', 'category': 'network', 'severity': 'medium', 'title': 'Checks if a Kubernetes Cluster has network policies that restrict public access', 'remediation_hint': 'Remove non-22 entries from spec.ingress[].ports and set protocol: TCP, port: 22 in the NetworkPolicy manifest.', 'sha': 'f14ac3e21c2f054c5ffbe104e1aa81188fc062af4085a877df75972e18299e37'}, 'k8s_networkpolicy_has_ingress_or_egress_rules': {'resource_kind': 'networkpolicy', 'category': 'network', 'severity': 'medium', 'title': 'NetworkPolicy isolation declaration agrees with approved intent', 'remediation_hint': 'Review the selected Pods, policyTypes, owner-approved allow or deny intent, and CNI enforcement before changing NetworkPolicy rules; retain intentional default-deny policies.', 'sha': '52d8472088c73ca7c64893c85b2bd371da4ec3a9d0e7fa662db52972b8809044'}, 'k8s_networkpolicy_world_ingress_authorized_ports': {'resource_kind': 'networkpolicy', 'category': 'network', 'severity': 'medium', 'title': 'Core', 'remediation_hint': 'Set ingress.ports to the approved protocol/port pairs for any rule with 0.0.0.0/0 or ::/0 in ingress.from.', 'sha': 'd34626295c73711c17c982ee63c46e927173a0523eff20b24c56445313ff8b5a'}, 'k8s_cluster_clocks_information_processing_systems_used_by_82e06ff4': {'resource_kind': 'cluster', 'category': 'hardening', 'severity': 'medium', 'title': 'Clock Synchronisation', 'remediation_hint': 'Configure chronyd or the node time synchronization service against approved NTP sources and verify each node clock is within the approved tolerance.', 'sha': 'f5867aec50ad5c0bf5936aef9ee480dee26039b183ae0bd10989df7936b2fdc0'}, 'k8s_privileged_utility_access': {'resource_kind': 'cluster', 'category': 'least_privilege', 'severity': 'high', 'title': 'Restrict Kubernetes privileged utilities', 'remediation_hint': 'Remove unapproved RBAC grants for pods/exec create and pods/ephemeralcontainers update, and restrict privileged utility Pods to authorized namespaces.', 'sha': 'c054b202fe5061aaa34f915bc869ce7c2918ac3fc008d361a604f1b80a567265'}, 'k8s_cluster_appropriate_set_procedures_information_labelling_should_e24bda19': {'resource_kind': 'namespace', 'category': 'hardening', 'severity': 'medium', 'title': 'Classification Of Information', 'remediation_hint': 'Set metadata.labels[classification_label_key] to an approved classification value in each Namespace, Secret, Pod and Deployment manifest or template.', 'sha': '5d91d17cc2bffa0f4ef62fcbb2b736d77b2b1f606f1adc0d6c274ca7659aae20'}, 'k8s_environment_separation': {'resource_kind': 'namespace', 'category': 'network', 'severity': 'medium', 'title': 'Check declared environment segregation', 'remediation_hint': 'Label each namespace with the approved environment, remove cross-environment RoleBindings, and replace cross-environment NetworkPolicy peers with approved namespaceSelectors.', 'sha': 'a51276c77a8c5288c658a5ec27924674b10de33a59cd02e352f7371b160280e1'}, 'k8s.cis.file_pki_owner': {'resource_kind': 'file_metadata', 'category': 'hardening', 'severity': 'medium', 'title': 'Ensure that the Kubernetes PKI directory and file ownership is set to root:root', 'remediation_hint': 'On each control-plane node, run `chown -R root:root /etc/kubernetes/pki` after verifying PKI ownership requirements.', 'sha': 'a69344c8ffa20787da6391fb359154874af550438f0a4af9c62af06e098a96bc'}, 'k8s.cis.file_var_lib_etcd_owner': {'resource_kind': 'file_metadata', 'category': 'hardening', 'severity': 'medium', 'title': 'Ensure that the etcd data directory ownership is set to etcd:etcd', 'remediation_hint': 'On each etcd node, resolve the local etcd UID and GID and run `chown etcd:etcd /var/lib/etcd`; verify the service account configured for that node.', 'sha': '842f7718dc226a855b09f288f950c8fca39e6b87c2ce527e8c8fa7d049e03d30'}, 'k8s.cis.the_ipaddressdeny_is_set_to_any': {'resource_kind': 'component_configuration', 'category': 'network', 'severity': 'medium', 'title': 'Ensure that the --IPAddressDeny is set to any', 'remediation_hint': 'Set the Windows node IPAddressDeny policy value to Any using the node management policy, then confirm it on each Windows node.', 'sha': '1222f065246cd126adf46368717e85fcd62d2e323e3c42bcd20b6066f92b7f7b'}, 'k8s.cis.avoid_use_of_system_masters_group': {'resource_kind': 'clusterrolebinding', 'category': 'iam', 'severity': 'high', 'title': 'Avoid use of system:masters group', 'remediation_hint': 'Remove system:masters subjects from RoleBindings and ClusterRoleBindings; grant a narrowly scoped Role or ClusterRole to named groups instead.', 'sha': '889fa81459bc8e70895673a3e4f0a61fdc4ae8496de8faf1fb16ce642ee50c72'}, 'k8s.cis.psp_binding_enforced': {'resource_kind': 'clusterrolebinding', 'category': 'hardening', 'severity': 'medium', 'title': 'Legacy PodSecurityPolicy is bound and usable', 'remediation_hint': 'On Kubernetes versions serving PSP, bind each workload ServiceAccount to an approved restrictive PodSecurityPolicy using an RBAC Role with `use` on that policy; migrate to Pod Security Admission before upgrading.', 'sha': 'ae51b4bfae6f423bbbbc7333b75bee293f5eba2eed515a9a8d48151e20eb586e'}, 'k8s_persistentvolume_persistentvolumeclaims_pvc_permissions_do_not_allow_00af04b0': {'resource_kind': 'role,clusterrole', 'category': 'least_privilege', 'severity': 'high', 'title': 'Checks if your Kubernetes PersistentVolumeClaims (PVC) permissions do not allow other inter-namespace access except for the control namespace policy that you pr', 'remediation_hint': 'Remove the offending RoleBinding or ClusterRoleBinding, or replace it with a namespace-scoped Role limited to approved ServiceAccounts and PVC verbs.', 'sha': '37a23a1e881ce9809dfe8083fd165ff12fa76860e5090353a9acf4b19c3900a3'}}
    SPECS = {k: v for k, v in SPECS.items() if k in _ALLOWED}

    def _context(index):
        context = get(index, 'context', dict)
        if get(context, 'provider', str) != 'k8s':
            raise Unavailable('foreign provider')
        scope = get(context, 'scope', str)
        cluster = get(context, 'metadata.cluster_id', str)
        if not scope or not cluster:
            raise Unavailable('scope or cluster identity missing')
        return (context, scope, cluster)

    def _inventory(index, kind):
        _, scope, cluster = _context(index)
        pages = get(get(index, 'collections', dict), kind, list)
        if not pages or any((not isinstance(p, dict) or p.get('type') != kind or p.get('scope') != scope or (p.get('status') not in ('collected', 'empty')) for p in pages)):
            raise Unavailable('incomplete or foreign-scope ' + kind + ' inventory')
        wrappers = get(index, kind, list)
        if any((not isinstance(w, dict) or w.get('type') != kind or w.get('scope') != scope or (w.get('provider', 'k8s') != 'k8s') for w in wrappers)):
            raise Unavailable('foreign-scope ' + kind + ' resource')
        rows = complete_items(index, kind)
        if len(rows) != len(wrappers) or sum((len(get(p, 'items', list)) for p in pages)) != len(rows):
            raise Unavailable('inventory content mismatch')
        page_rows = [v for p in pages for v in get(p, 'items', list)]
        if any((not isinstance(v, dict) for v in page_rows)):
            raise Unavailable('malformed inventory item')
        try:
            if Counter((json.dumps(v, sort_keys=True) for v in rows)) != Counter((json.dumps(v, sort_keys=True) for v in page_rows)):
                raise Unavailable('inventory content mismatch')
        except (TypeError, ValueError) as exc:
            raise Unavailable('inventory content malformed') from exc
        identities = set()
        for row in rows:
            provenance = row.get('provenance', {})
            if not isinstance(provenance, dict) or provenance.get('cluster_id') != cluster:
                raise Unavailable('foreign cluster or missing provenance')
            if kind in ('networkpolicy', 'role', 'rolebinding', 'pod', 'deployment', 'secret_metadata'):
                ns = get(row, 'metadata.namespace', str)
                if not ns or (scope != '*' and ns != scope):
                    raise Unavailable('foreign namespace in ' + kind)
            else:
                ns = None
            if kind in ('networkpolicy', 'role', 'rolebinding', 'pod', 'deployment', 'secret_metadata', 'namespace', 'node', 'clusterrole', 'clusterrolebinding', 'podsecuritypolicy'):
                name = get(row, 'metadata.name', str)
                identity = (ns, name)
                if not name or identity in identities or (kind == 'namespace' and scope != '*' and (name != scope)):
                    raise Unavailable('duplicate, malformed or foreign-scope resource identity')
                identities.add(identity)
        return rows

    def _member(item, index, kind):
        rows = _inventory(index, kind)
        if item not in rows:
            raise Unavailable('resource not in complete inventory')
        return rows

    def _opt(obj, key, default, source):
        if key in obj or key in obj.get('_coverage', {}):
            return get(obj, key)
        if get(source, 'provenance.evidence', str) == 'read-only list':
            return default
        raise Unavailable('omitted field in partial representation: ' + key)

    def _policy(index, key, expected):
        context, _, cluster = _context(index)
        p = get(context, 'metadata.compliance_policy', dict)
        if get(p, 'status', str) != 'collected' or get(p, 'cluster_id', str) != cluster:
            raise Unavailable('owner policy absent or foreign cluster')
        if 'observed_at' in p or 'max_age_seconds' in p:
            at = get(p, 'observed_at', str)
            age = get(p, 'max_age_seconds', int)
            captured = get(context, 'created_at', str)
            try:
                a, b = (datetime.fromisoformat(s.replace('Z', '+00:00')) for s in (at, captured))
                if a.utcoffset() is None or b.utcoffset() is None or age <= 0 or (not 0 <= (b - a).total_seconds() <= age):
                    raise ValueError('stale policy')
            except ValueError as exc:
                raise Unavailable('owner policy freshness unresolved') from exc
        return get(p, key, expected)

    def _strings(index, key):
        values = _policy(index, key, list)
        if any((not isinstance(v, str) or not v for v in values)) or len(set(values)) != len(values):
            raise Unavailable('malformed owner list: ' + key)
        return set(values)

    def _enforcement(index, *, union=False):
        _, scope, cluster = _context(index)
        evidence = get(index, 'context.metadata.network_policy_enforcement', dict)
        if evidence.get('status') != 'verified' or evidence.get('cluster_id') != cluster or evidence.get('scope') != scope:
            raise Unavailable('CNI enforcement unavailable or foreign scope')
        if union and evidence.get('policy_union_complete') is not True:
            raise Unavailable('NetworkPolicy union coverage unresolved')
        return evidence

    def _ports(index, key):
        values = _policy(index, key, list)
        if not values:
            raise Unavailable('empty approved ports')
        out = set()
        for v in values:
            proto, port = (get(v, 'protocol', str), get(v, 'port'))
            if proto not in ('TCP', 'UDP', 'SCTP') or isinstance(port, bool) or (not (type(port) is int and 1 <= port <= 65535 or (isinstance(port, str) and port))):
                raise Unavailable('malformed approved port')
            if (proto, port) in out:
                raise Unavailable('duplicate approved port')
            out.add((proto, port))
        return out

    def _selector(selector, source):
        if not isinstance(selector, dict):
            raise Unavailable('Kubernetes selector malformed')
        labels = _opt(selector, 'matchLabels', {}, source)
        expressions = _opt(selector, 'matchExpressions', [], source)
        if not isinstance(labels, dict) or any((not isinstance(k, str) or not k or (not isinstance(v, str)) for k, v in labels.items())) or (not isinstance(expressions, list)):
            raise Unavailable('Kubernetes selector malformed')
        for expression in expressions:
            key = get(expression, 'key', str)
            operator = get(expression, 'operator', str)
            values = _opt(expression, 'values', [], source)
            if not key or operator not in ('In', 'NotIn', 'Exists', 'DoesNotExist') or (not isinstance(values, list)) or any((not isinstance(v, str) for v in values)) or ((operator in ('In', 'NotIn')) != bool(values)):
                raise Unavailable('Kubernetes selector expression malformed')
        return (labels, expressions)

    def _rules(item):
        spec = get(item, 'spec', dict)
        _selector(get(spec, 'podSelector', dict), item)
        implicit_egress = _opt(spec, 'egress', [], item)
        types = _opt(spec, 'policyTypes', ['Ingress', 'Egress'] if implicit_egress else ['Ingress'], item)
        if not isinstance(types, list) or not types or any((t not in ('Ingress', 'Egress') for t in types)) or (len(set(types)) != len(types)):
            raise Unavailable('policyTypes malformed')
        ingress = _opt(spec, 'ingress', [], item)
        egress = _opt(spec, 'egress', [], item)
        if not isinstance(ingress, list) or not isinstance(egress, list) or any((not isinstance(r, dict) for r in ingress + egress)):
            raise Unavailable('NetworkPolicy rules malformed')
        return (types, ingress, egress)

    def _public(cidr):
        try:
            network = ipaddress.ip_network(cidr, strict=True)
        except ValueError as exc:
            raise Unavailable('invalid ipBlock CIDR') from exc
        if network.prefixlen == 0:
            return True
        if network.is_global:
            return True
        if network.is_private or network.is_loopback or network.is_link_local:
            return False
        raise Unavailable('public range cannot be established')

    def _peer_public(rule, source):
        peers = _opt(rule, 'from', None, source)
        if peers is None or peers == []:
            return True
        if not isinstance(peers, list):
            raise Unavailable('ingress peers malformed')
        seen = False
        for peer in peers:
            if not isinstance(peer, dict):
                raise Unavailable('ingress peer malformed')
            if 'ipBlock' in peer:
                block = get(peer, 'ipBlock', dict)
                cidr = get(block, 'cidr', str)
                exceptions = _opt(block, 'except', [], source)
                if not isinstance(exceptions, list) or any((not isinstance(x, str) for x in exceptions)):
                    raise Unavailable('ipBlock exceptions malformed')
                try:
                    parent = ipaddress.ip_network(cidr, strict=True)
                    if any((not ipaddress.ip_network(x, strict=True).subnet_of(parent) for x in exceptions)):
                        raise ValueError('exception outside parent')
                except ValueError as exc:
                    raise Unavailable('ipBlock exceptions malformed') from exc
                if exceptions and _public(cidr):
                    raise Unavailable('ipBlock public range after exceptions unresolved')
                seen |= _public(cidr)
            elif 'namespaceSelector' in peer or 'podSelector' in peer:
                if 'namespaceSelector' in peer:
                    _selector(get(peer, 'namespaceSelector', dict), source)
                if 'podSelector' in peer:
                    _selector(get(peer, 'podSelector', dict), source)
            else:
                raise Unavailable('unrecognized ingress peer')
        return seen

    def _explicit_public(rule, source):
        peers = _opt(rule, 'from', [], source)
        if not isinstance(peers, list):
            raise Unavailable('ingress peers malformed')
        found = False
        for peer in peers:
            if not isinstance(peer, dict):
                raise Unavailable('ingress peer malformed')
            if 'ipBlock' in peer:
                block = get(peer, 'ipBlock', dict)
                cidr = get(block, 'cidr', str)
                exceptions = _opt(block, 'except', [], source)
                if not isinstance(exceptions, list) or any((not isinstance(x, str) for x in exceptions)):
                    raise Unavailable('ipBlock exceptions malformed')
                try:
                    parent = ipaddress.ip_network(cidr, strict=True)
                    if any((not ipaddress.ip_network(x, strict=True).subnet_of(parent) for x in exceptions)):
                        raise ValueError('exception outside parent')
                except ValueError as exc:
                    raise Unavailable('ipBlock exceptions malformed') from exc
                if exceptions and _public(cidr):
                    raise Unavailable('ipBlock public range after exceptions unresolved')
                found |= _public(cidr)
            elif 'namespaceSelector' in peer or 'podSelector' in peer:
                if 'namespaceSelector' in peer:
                    _selector(get(peer, 'namespaceSelector', dict), source)
                if 'podSelector' in peer:
                    _selector(get(peer, 'podSelector', dict), source)
            else:
                raise Unavailable('unrecognized ingress peer')
        return found

    def _port_pairs(rule, source):
        ports = _opt(rule, 'ports', None, source)
        if ports is None or ports == []:
            return None
        if not isinstance(ports, list):
            raise Unavailable('ingress ports malformed')
        pairs = set()
        for p in ports:
            if not isinstance(p, dict):
                raise Unavailable('ingress port malformed')
            proto = _opt(p, 'protocol', 'TCP', source)
            port = get(p, 'port')
            if proto not in ('TCP', 'UDP', 'SCTP') or isinstance(port, bool) or (not (type(port) is int and 1 <= port <= 65535 or (isinstance(port, str) and port))):
                raise Unavailable('ingress protocol or port malformed')
            if 'endPort' in p:
                end = get(p, 'endPort', int)
                if type(port) is not int or end < port or end > 65535:
                    raise Unavailable('ingress port range malformed')
                if end - port > 4096:
                    raise Unavailable('ingress port range too broad to enumerate')
                pairs.update(((proto, x) for x in range(port, end + 1)))
            else:
                pairs.add((proto, port))
        return pairs

    def _network(item, index, check_id):
        _member(item, index, 'networkpolicy')
        types, ingress, egress = _rules(item)
        if check_id.endswith('1fd253608e') or check_id.endswith('world_ingress_authorized_ports'):
            approved = _ports(index, 'allowed_public_ports' if check_id.endswith('1fd253608e') else 'allowed_ports')
            bad = []
            for n, rule in enumerate(ingress):
                if _explicit_public(rule, item) if check_id.endswith('1fd253608e') else _peer_public(rule, item):
                    ports = _port_pairs(rule, item)
                    if ports is None or not ports <= approved:
                        bad.append(n)
            return result(bool(bad), offending_ingress_rules=bad)
        if check_id.endswith('24d2fc90b0'):
            _enforcement(index, union=True)
            rows = _inventory(index, 'networkpolicy')
            if not rows:
                return unknown('no applicable policy exists')
            bad = []
            applicable = 0
            for policy in rows:
                ptypes, prules, _ = _rules(policy)
                if 'Ingress' not in ptypes:
                    continue
                applicable += 1
                for n, rule in enumerate(prules):
                    if _peer_public(rule, policy):
                        ports = _port_pairs(rule, policy)
                        if ports is None or any((pair != ('TCP', 22) for pair in ports)):
                            bad.append((get(policy, 'metadata.name', str), n))
            if not applicable:
                return unknown('no applicable ingress policy exists')
            return result(bool(bad), offending_rules=bad)
        approved = _policy(index, 'network_policy_intent', dict)
        _enforcement(index)
        key = get(item, 'metadata.namespace', str) + '/' + get(item, 'metadata.name', str)
        expected = approved.get(key)
        if not isinstance(expected, dict):
            raise Unavailable('owner NetworkPolicy intent missing for policy')
        expected_types = get(expected, 'policyTypes', list)
        expected_ingress = get(expected, 'ingress', list)
        expected_egress = get(expected, 'egress', list)
        if any((t not in ('Ingress', 'Egress') for t in expected_types)) or any((not isinstance(x, dict) for x in expected_ingress + expected_egress)):
            raise Unavailable('owner NetworkPolicy intent malformed')
        if set(types) != set(expected_types) or bool(ingress) != bool(expected_ingress) or bool(egress) != bool(expected_egress):
            return result(True, policy=key, semantics='definite isolation or allow-rule presence deviation')
        if ingress != expected_ingress or egress != expected_egress:
            return unknown('allow-rule semantic equivalence unresolved', policy=key)
        return result(False, policy=key, semantics='exact approved declaration and attested CNI enforcement')

    def _bindings(index):
        bindings = []
        for kind in ('rolebinding', 'clusterrolebinding'):
            for row in _inventory(index, kind):
                namespace = get(row, 'metadata.namespace', str) if kind == 'rolebinding' else '*'
                ref = get(row, 'roleRef', dict)
                refkind, name = (get(ref, 'kind', str), get(ref, 'name', str))
                if refkind not in ('Role', 'ClusterRole') or not name or (kind == 'clusterrolebinding' and refkind != 'ClusterRole'):
                    raise Unavailable('binding roleRef malformed')
                subjects = _opt(row, 'subjects', [], row)
                if not isinstance(subjects, list):
                    raise Unavailable('binding subjects malformed')
                normalized = []
                for s in subjects:
                    sk, sn = (get(s, 'kind', str), get(s, 'name', str))
                    if sk not in ('ServiceAccount', 'User', 'Group') or not sn:
                        raise Unavailable('binding subject malformed')
                    sns = get(s, 'namespace', str) if sk == 'ServiceAccount' and 'namespace' in s else namespace
                    if sk == 'ServiceAccount' and (not sns or sns == '*'):
                        raise Unavailable('ServiceAccount namespace unresolved')
                    normalized.append((sk, sn, sns))
                bindings.append((kind, namespace, refkind, name, normalized))
        return bindings

    def _roles(index):
        out = {}
        for kind in ('role', 'clusterrole'):
            for row in _inventory(index, kind):
                ns = get(row, 'metadata.namespace', str) if kind == 'role' else '*'
                name = get(row, 'metadata.name', str)
                key = (kind, ns, name)
                if not name or key in out:
                    raise Unavailable('duplicate or malformed RBAC role identity')
                rules = _opt(row, 'rules', [], row)
                if not isinstance(rules, list) or any((not isinstance(r, dict) for r in rules)):
                    raise Unavailable('RBAC rules malformed')
                out[key] = rules
        return out

    def _effective(index):
        roles = _roles(index)
        for binding_kind, ns, refkind, name, subjects in _bindings(index):
            key = ('role' if refkind == 'Role' else 'clusterrole', ns if refkind == 'Role' else '*', name)
            if key not in roles:
                raise Unavailable('binding roleRef unresolved')
            yield (binding_kind, ns, subjects, roles[key])

    def _rule_grants(rule, resource, verb, group=''):
        groups = get(rule, 'apiGroups', list)
        resources = get(rule, 'resources', list)
        verbs = get(rule, 'verbs', list)
        if any((not isinstance(v, str) for v in groups)) or any((not isinstance(v, str) or not v for seq in (resources, verbs) for v in seq)):
            raise Unavailable('RBAC rule malformed')
        return (group in groups or '*' in groups) and (resource in resources or '*' in resources) and (verb in verbs or '*' in verbs)

    def _privileged(index):
        allowed_subjects = _strings(index, 'authorized_subjects')
        allowed_namespaces = _strings(index, 'authorized_utility_namespaces')
        utility_pods = _strings(index, 'privileged_utility_pods')
        if any((re.fullmatch('[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', ns) is None for ns in allowed_namespaces)) or any(('/' not in value or not all(value.split('/', 1)) for value in utility_pods)) or any((not re.fullmatch('(?:ServiceAccount:[^/]+/[^/]+|User:.+|Group:.+)', value) for value in allowed_subjects)):
            raise Unavailable('utility authorization policy malformed')
        bad = []
        for _, ns, subjects, rules in _effective(index):
            if any((_rule_grants(rule, 'pods/exec', 'create') or _rule_grants(rule, 'pods/ephemeralcontainers', 'update') for rule in rules)):
                for kind, name, sns in subjects:
                    identity = f'{kind}:{sns}/{name}' if kind == 'ServiceAccount' else f'{kind}:{name}'
                    if identity not in allowed_subjects:
                        bad.append(identity)
        for pod in _inventory(index, 'pod'):
            ns = get(pod, 'metadata.namespace', str)
            containers = list(get(pod, 'spec.containers', list))
            if not containers or any((not isinstance(c, dict) for c in containers)):
                raise Unavailable('Pod containers malformed')
            privileged = False
            for field in ('initContainers', 'ephemeralContainers'):
                extra = _opt(get(pod, 'spec', dict), field, [], pod)
                if not isinstance(extra, list) or any((not isinstance(c, dict) for c in extra)):
                    raise Unavailable('Pod auxiliary containers malformed')
                containers += extra
            for c in containers:
                sc = _opt(c, 'securityContext', {}, pod)
                if not isinstance(sc, dict):
                    raise Unavailable('container securityContext malformed')
                value = _opt(sc, 'privileged', False, pod)
                if type(value) is not bool:
                    raise Unavailable('container privileged malformed')
                privileged |= value
            if privileged and ns + '/' + get(pod, 'metadata.name', str) in utility_pods and (ns not in allowed_namespaces):
                bad.append('Pod:' + ns + '/' + get(pod, 'metadata.name', str))
        return result(bool(bad), unauthorized=sorted(set(bad)))

    def _labels(item, source):
        meta = get(item, 'metadata', dict)
        labels = _opt(meta, 'labels', {}, source)
        if not isinstance(labels, dict) or any((not isinstance(k, str) or not isinstance(v, str) for k, v in labels.items())):
            raise Unavailable('metadata labels malformed')
        return labels

    def _classification(item, index):
        _member(item, index, 'namespace')
        key = _policy(index, 'classification_label_key', str)
        approved = _strings(index, 'approved_values')
        if not key or not approved or re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]*(?:/[A-Za-z0-9][A-Za-z0-9_.-]*)?', key) is None:
            raise Unavailable('classification policy malformed')
        bad = []
        for kind in ('namespace', 'secret_metadata', 'pod', 'deployment'):
            for row in _inventory(index, kind):
                name = get(row, 'metadata.name', str)
                if _labels(row, row).get(key) not in approved:
                    bad.append(kind + ':' + name)
        return result(bool(bad), unlabeled_or_unapproved=bad)

    def _environment(item, index):
        _member(item, index, 'namespace')
        matrix = _policy(index, 'environment_matrix', dict)
        key = get(matrix, 'environment_key', str)
        assignments = get(matrix, 'namespaces', dict)
        allowed = get(matrix, 'allowed_cross_environment', list)
        subject_environments = get(matrix, 'subject_environments', dict)
        if not key or any((not isinstance(k, str) or not isinstance(v, str) for k, v in assignments.items())) or any((not isinstance(k, str) or not isinstance(v, str) for k, v in subject_environments.items())) or any((not isinstance(x, list) or len(x) != 2 or any((not isinstance(y, str) for y in x)) for x in allowed)):
            raise Unavailable('environment matrix malformed')
        _enforcement(index)
        namespaces = _inventory(index, 'namespace')
        actual = {}
        bad = []
        for ns in namespaces:
            name = get(ns, 'metadata.name', str)
            if name not in assignments or name in actual:
                raise Unavailable('namespace environment assignment missing or duplicate')
            actual[name] = _labels(ns, ns)
            if actual[name].get(key) != assignments[name]:
                bad.append('label:' + name)
        environments = set(assignments.values())
        if not environments or any((value not in environments for value in subject_environments.values())) or any((a not in environments or b not in environments for a, b in allowed)):
            raise Unavailable('environment matrix references unknown environment')
        if _context(index)[1] == '*' and set(assignments) != set(actual):
            raise Unavailable('environment matrix namespace coverage incomplete')
        permits = {tuple(pair) for pair in allowed}
        for _, target, subjects, _ in _effective(index):
            for kind, name, origin in subjects:
                if kind == 'ServiceAccount':
                    if origin not in assignments:
                        raise Unavailable('ServiceAccount environment unresolved')
                    source_env = assignments[origin]
                else:
                    identity = kind + ':' + name
                    if identity not in subject_environments:
                        raise Unavailable('User or Group environment unresolved')
                    source_env = subject_environments[identity]
                targets = set(assignments.values()) if target == '*' else {assignments[target]} if target in assignments else None
                if targets is None:
                    raise Unavailable('binding target environment unresolved')
                for target_env in targets:
                    if source_env != target_env and (source_env, target_env) not in permits:
                        bad.append('binding:' + kind + ':' + name + '->' + target_env)
        for policy in _inventory(index, 'networkpolicy'):
            ns = get(policy, 'metadata.namespace', str)
            _, ingress, egress = _rules(policy)
            for rules, direction in ((ingress, 'from'), (egress, 'to')):
                for rule in rules:
                    peers = _opt(rule, direction, [], policy)
                    if not isinstance(peers, list):
                        raise Unavailable('NetworkPolicy peers malformed')
                    for peer in peers:
                        if not isinstance(peer, dict):
                            raise Unavailable('NetworkPolicy peer malformed')
                        if 'namespaceSelector' in peer:
                            selector = get(peer, 'namespaceSelector', dict)
                            labels = _opt(selector, 'matchLabels', {}, policy)
                            expressions = _opt(selector, 'matchExpressions', [], policy)
                            if expressions or not isinstance(labels, dict) or key not in labels:
                                raise Unavailable('namespaceSelector environment unresolved')
                            selected = labels[key]
                            if selected not in set(assignments.values()):
                                raise Unavailable('unknown selected environment')
                            source_env, target_env = (selected, assignments[ns]) if direction == 'from' else (assignments[ns], selected)
                            if source_env != target_env and (source_env, target_env) not in permits:
                                bad.append('networkpolicy:' + source_env + '->' + target_env)
        return result(bool(bad), deviations=bad)

    def _file(item, index, check_id):
        _member(item, index, 'file_metadata')
        coverage = get(index, 'context.metadata.file_metadata_coverage', dict)
        _, _, cluster = _context(index)
        if coverage.get('status') != 'attested_complete' or coverage.get('cluster_id') != cluster:
            return unknown('per-node file coverage incomplete')
        if check_id.endswith('file_pki_owner'):
            recursive = get(index, 'context.metadata.file_metadata_recursive_coverage', dict)
            if recursive.get('status') != 'attested_complete' or recursive.get('cluster_id') != cluster or recursive.get('path') != '/etc/kubernetes/pki':
                return unknown('recursive PKI directory coverage incomplete')
        path = get(item, 'path', str)
        node = get(item, 'node_name', str)
        if not path.startswith('/') or not node:
            raise Unavailable('file identity malformed')
        if check_id.endswith('file_pki_owner'):
            if path != '/etc/kubernetes/pki' and (not path.startswith('/etc/kubernetes/pki/')):
                return ('NOT_APPLICABLE', {'reason': 'outside Kubernetes PKI tree'})
            uid, gid = (get(item, 'uid', int), get(item, 'gid', int))
            return result(uid != 0 or gid != 0, path=path, node=node, uid=uid, gid=gid)
        if path != '/var/lib/etcd':
            return ('NOT_APPLICABLE', {'reason': 'outside etcd data directory'})
        identities = _policy(index, 'resolved_etcd_accounts', dict)
        account = identities.get(node)
        if not isinstance(account, dict):
            raise Unavailable('node-local etcd account resolution missing')
        expected_uid, expected_gid = (get(account, 'uid', int), get(account, 'gid', int))
        if expected_uid < 0 or expected_gid < 0:
            raise Unavailable('resolved etcd account malformed')
        uid, gid = (get(item, 'uid', int), get(item, 'gid', int))
        return result(uid != expected_uid or gid != expected_gid, path=path, node=node, uid=uid, gid=gid)

    def _files_scope(index, check_id):
        rows = _inventory(index, 'file_metadata')
        coverage = get(index, 'context.metadata.file_metadata_coverage', dict)
        _, _, cluster = _context(index)
        if coverage.get('status') != 'attested_complete' or coverage.get('cluster_id') != cluster:
            return unknown('per-node file coverage incomplete')
        if check_id.endswith('file_pki_owner'):
            recursive = get(index, 'context.metadata.file_metadata_recursive_coverage', dict)
            if recursive.get('status') != 'attested_complete' or recursive.get('cluster_id') != cluster or recursive.get('path') != '/etc/kubernetes/pki' or (recursive.get('enumeration_complete') is not True):
                return unknown('recursive PKI directory coverage incomplete')
            expected = get(recursive, 'applicable_nodes', list)
            if any((not isinstance(name, str) or not name for name in expected)) or len(set(expected)) != len(expected):
                raise Unavailable('recursive PKI node coverage malformed')
            target = [row for row in rows if get(row, 'path', str) == '/etc/kubernetes/pki' or get(row, 'path', str).startswith('/etc/kubernetes/pki/')]
            observed_roots = {get(row, 'node_name', str) for row in target if get(row, 'path', str) == '/etc/kubernetes/pki'}
            if observed_roots != set(expected) or any((get(row, 'node_name', str) not in expected for row in target)):
                return unknown('PKI root or per-node recursive file coverage missing')
        else:
            paths = get(coverage, 'selector_paths', dict)
            if '/var/lib/etcd' not in paths:
                return unknown('etcd selector path coverage missing')
            expected_rows = get(paths, '/var/lib/etcd', list)
            expected = set()
            for row in expected_rows:
                name = get(row, 'node_name', str)
                if not name or name in expected or get(row, 'path', str) != '/var/lib/etcd':
                    raise Unavailable('etcd per-node selector coverage malformed')
                expected.add(name)
            target = [row for row in rows if get(row, 'path', str) == '/var/lib/etcd']
            observed = [get(row, 'node_name', str) for row in target]
            if set(observed) != expected or len(observed) != len(set(observed)):
                return unknown('etcd path missing for an applicable node')
        if not target:
            return ('NOT_APPLICABLE', {'reason': 'no applicable file path in attested node coverage'})
        failed = []
        for row in target:
            status, evidence = _file(row, index, check_id)
            if status == 'UNKNOWN':
                return (status, evidence)
            if status == 'FAIL':
                failed.append({'node': evidence['node'], 'path': evidence['path']})
        return result(bool(failed), offending_files=failed, assessed_files=len(target))

    def _version(index):
        rows = _inventory(index, 'api_discovery')
        if len(rows) != 1:
            raise Unavailable('API discovery ambiguous')
        version = get(rows[0], 'serverVersion.gitVersion', str)
        match = re.fullmatch('v?(\\d+)\\.(\\d+)\\.(\\d+)(?:[-+][0-9A-Za-z.\\-]+)?', version)
        if not match:
            raise Unavailable('Kubernetes server version malformed')
        return tuple(map(int, match.groups()))

    def _psp(index):
        if _version(index) >= (1, 25, 0):
            return ('NOT_APPLICABLE', {'reason': 'PodSecurityPolicy removed in Kubernetes 1.25+'})
        policies = _inventory(index, 'podsecuritypolicy')
        names = {get(p, 'metadata.name', str) for p in policies}
        if len(names) != len(policies):
            raise Unavailable('PodSecurityPolicy identity duplicate')
        grants = {}
        for _, ns, subjects, rules in _effective(index):
            can_create = any((_rule_grants(rule, 'pods', 'create') for rule in rules))
            can_use = set()
            for rule in rules:
                if _rule_grants(rule, 'podsecuritypolicies', 'use', 'policy'):
                    resource_names = get(rule, 'resourceNames', list) if 'resourceNames' in rule or 'resourceNames' in rule.get('_coverage', {}) else []
                    if any((not isinstance(n, str) or not n for n in resource_names)):
                        raise Unavailable('PSP resourceNames malformed')
                    can_use.update(resource_names or names)
            targets = {get(row, 'metadata.name', str) for row in _inventory(index, 'namespace')} if ns == '*' else {ns}
            for kind, name, sns in subjects:
                if kind != 'ServiceAccount':
                    continue
                for target in targets:
                    entry = grants.setdefault((sns, name, target), {'create': False, 'use': set()})
                    entry['create'] |= can_create
                    entry['use'].update(can_use & names)
        missing = sorted((f'{ns}/{name}->{target}' for (ns, name, target), grants_for_subject in grants.items() if grants_for_subject['create'] and (not grants_for_subject['use'])))
        return result(bool(missing), service_accounts_without_psp=missing)

    def _masters(index):
        bad = []
        for kind in ('rolebinding', 'clusterrolebinding'):
            for binding in _inventory(index, kind):
                subjects = _opt(binding, 'subjects', [], binding)
                if not isinstance(subjects, list):
                    raise Unavailable('binding subjects malformed')
                for subject in subjects:
                    if get(subject, 'kind', str) == 'Group' and get(subject, 'name', str) == 'system:masters':
                        bad.append(kind + ':' + get(binding, 'metadata.name', str))
        if bad:
            return result(True, observed_bindings=bad)
        coverage = get(index, 'context.metadata.identity_group_coverage', dict)
        _, _, cluster = _context(index)
        if coverage.get('status') == 'attested_complete' and coverage.get('cluster_id') == cluster and (coverage.get('certificate_and_provider_memberships_complete') is True) and (coverage.get('system_masters_subject_count') == 0):
            return result(False, observed_bindings=[], semantics='binding and attested identity membership inventory')
        return unknown('certificate and provider identity memberships are not observed')

    def _pvc(index):
        controls = _strings(index, 'approved_control_namespaces')
        if any((re.fullmatch('[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', name) is None for name in controls)):
            raise Unavailable('approved control namespace malformed')
        bad = []
        for _, target, subjects, rules in _effective(index):
            pvc = any((_rule_grants(rule, 'persistentvolumeclaims', verb) for rule in rules for verb in ('get', 'list', 'watch', 'create', 'update', 'patch', 'delete', 'deletecollection')))
            if not pvc:
                continue
            for kind, name, origin in subjects:
                if kind != 'ServiceAccount':
                    continue
                if target == '*':
                    namespaces = {get(ns, 'metadata.name', str) for ns in _inventory(index, 'namespace')}
                    targets = namespaces - {origin} - controls
                else:
                    targets = {target} - {origin} - controls
                for ns in targets:
                    bad.append(f'{origin}/{name}->{ns}')
        return result(bool(bad), unauthorized_cross_namespace_pvc_grants=sorted(set(bad)))

    def _windows(index):
        nodes = _inventory(index, 'node')
        windows = {}
        for node in nodes:
            name = get(node, 'metadata.name', str)
            os = get(node, 'status.nodeInfo.operatingSystem', str)
            if os not in ('linux', 'windows') or name in windows:
                raise Unavailable('node OS or identity malformed')
            if os == 'windows':
                windows[name] = node
        if not windows:
            return ('NOT_APPLICABLE', {'reason': 'no Windows nodes in complete Node inventory'})
        configs = _inventory(index, 'component_configuration')
        observed = {}
        for config in configs:
            if get(config, 'component', str) != 'kubelet':
                continue
            name = get(config, 'node_name', str)
            if name in observed:
                raise Unavailable('duplicate component configuration')
            if name in windows:
                observed[name] = get(config, 'configuration.IPAddressDeny', str)
        if set(observed) != set(windows):
            raise Unavailable('Windows node configuration unavailable')
        if any((not value for value in observed.values())):
            raise Unavailable('Windows IPAddressDeny malformed')
        return result(any((value != 'Any' for value in observed.values())), observed=observed)

    def _clock(index):
        tolerance = _policy(index, 'approved_clock_skew', int)
        if tolerance < 0 or tolerance > 86400:
            raise Unavailable('approved clock skew malformed')
        nodes = _inventory(index, 'node')
        clocks = _inventory(index, 'node_clock')
        by_node = {}
        for clock in clocks:
            name = get(clock, 'node_name', str)
            if name in by_node:
                raise Unavailable('duplicate node clock fact')
            by_node[name] = clock
        names = {get(node, 'metadata.name', str) for node in nodes}
        if not names or set(by_node) != names:
            raise Unavailable('node clock coverage missing or foreign')
        bad = []
        for name, clock in by_node.items():
            if get(clock, 'source_operation', str) != 'GET /api/v1/nodes/{name}/proxy/healthz' or get(clock, 'node_response_verified', bool) is not True or get(clock, 'trusted_clock_verified', bool) is not True:
                raise Unavailable('node proxy or trusted clock source unverified')
            header = get(clock, 'date_header', str)
            utc = get(clock, 'trusted_utc_at_response', str)
            try:
                from email.utils import parsedate_to_datetime
                observed = parsedate_to_datetime(header)
                trusted = datetime.fromisoformat(utc.replace('Z', '+00:00'))
                if observed.utcoffset() is None or trusted.utcoffset() is None:
                    raise ValueError('timezone missing')
            except ValueError as exc:
                raise Unavailable('node clock timestamps malformed') from exc
            if abs((observed - trusted).total_seconds()) > tolerance:
                bad.append(name)
        return result(bool(bad), out_of_tolerance_nodes=bad, approved_clock_skew_seconds=tolerance)

    def _evaluate(check_id, item, index):
        if check_id.startswith('k8s_networkpolicy_'):
            return _network(item, index, check_id)
        if check_id == 'k8s_cluster_clocks_information_processing_systems_used_by_82e06ff4':
            return _clock(index)
        if check_id == 'k8s_privileged_utility_access':
            return _privileged(index)
        if check_id == 'k8s_cluster_appropriate_set_procedures_information_labelling_should_e24bda19':
            return _classification(item, index)
        if check_id == 'k8s_environment_separation':
            return _environment(item, index)
        if check_id in ('k8s.cis.file_pki_owner', 'k8s.cis.file_var_lib_etcd_owner'):
            return _files_scope(index, check_id)
        if check_id == 'k8s.cis.the_ipaddressdeny_is_set_to_any':
            return _windows(index)
        if check_id == 'k8s.cis.avoid_use_of_system_masters_group':
            return _masters(index)
        if check_id == 'k8s.cis.psp_binding_enforced':
            return _psp(index)
        if check_id == 'k8s_persistentvolume_persistentvolumeclaims_pvc_permissions_do_not_allow_00af04b0':
            return _pvc(index)
        raise Unavailable('unknown check id')
    DEPENDENCIES = {'k8s_cluster_clocks_information_processing_systems_used_by_82e06ff4': ('node', 'node_clock'), 'k8s_privileged_utility_access': ('role', 'clusterrole', 'rolebinding', 'clusterrolebinding', 'pod'), 'k8s_cluster_appropriate_set_procedures_information_labelling_should_e24bda19': ('namespace', 'secret_metadata', 'pod', 'deployment'), 'k8s_environment_separation': ('namespace', 'role', 'clusterrole', 'rolebinding', 'clusterrolebinding', 'networkpolicy'), 'k8s.cis.the_ipaddressdeny_is_set_to_any': ('node',), 'k8s.cis.avoid_use_of_system_masters_group': ('rolebinding', 'clusterrolebinding'), 'k8s.cis.psp_binding_enforced': ('api_discovery',), 'k8s_persistentvolume_persistentvolumeclaims_pvc_permissions_do_not_allow_00af04b0': ('role', 'clusterrole', 'rolebinding', 'clusterrolebinding', 'namespace')}
    SCOPE_IDS = {'k8s_cluster_clocks_information_processing_systems_used_by_82e06ff4', 'k8s_privileged_utility_access', 'k8s.cis.file_pki_owner', 'k8s.cis.file_var_lib_etcd_owner', 'k8s.cis.the_ipaddressdeny_is_set_to_any', 'k8s.cis.avoid_use_of_system_masters_group', 'k8s.cis.psp_binding_enforced', 'k8s_persistentvolume_persistentvolumeclaims_pvc_permissions_do_not_allow_00af04b0'}
    for _id, _spec in SPECS.items():
        _kind = 'role' if _id in {'k8s_privileged_utility_access', 'k8s_persistentvolume_persistentvolumeclaims_pvc_permissions_do_not_allow_00af04b0'} else _spec['resource_kind']
        _deps = DEPENDENCIES.get(_id, (_kind,))

        @register(_id, 'k8s', 'iam_graph' if _spec['category'] == 'iam' else _spec['category'], _kind, _spec['title'], _spec['severity'], 'CM-6', _spec['remediation_hint'], target='scope' if _id in SCOPE_IDS else 'resource', dependencies=_deps)
        def evaluate_sw57(item, index, check_id=_id):
            return _evaluate(check_id, item, index)
        if _spec['category'] == 'iam':
            pass
    from .facts import memoized as _batch_memoized
    from collections import Counter as _batch_Counter
    _base_inventory = _inventory

    def _inventory(index, kind):
        return _batch_memoized(index, ('batch_sw57_inventory', kind, index.get('context', {}).get('scope')), lambda: _base_inventory(index, kind))

    def _member(item, index, kind):
        rows = _inventory(index, kind)
        fingerprints = _batch_memoized(index, ('batch_sw57_members', kind, index.get('context', {}).get('scope')), lambda: _batch_Counter((json.dumps(row, sort_keys=True) for row in rows)))
        try:
            identity = json.dumps(item, sort_keys=True)
        except (TypeError, ValueError) as exc:
            raise Unavailable('item malformed') from exc
        if fingerprints[identity] < 1:
            raise Unavailable('resource not in complete inventory')
        return rows
_load_57()


# Source-bound kubelet declaration; runtime certificate rotation is separate.
from . import register as _register_remaining, result as _result_remaining
from .facts import get as _get_remaining
from .compliance_new_k8s_component import _observed_declaration as _observed_kubelet_declaration, _applicability as _kubelet_applicability

@_register_remaining('k8s.cis.kubelet_rotate_kubelet_server_certificate_true',
    'k8s', 'hardening', 'component_configuration',
    'Observed kubelet declares RotateKubeletServerCertificate enabled', 'medium', 'CM-6',
    'Set the kubelet feature gate explicitly when applicable and verify serving TLS bootstrap and certificate approval separately.',
    dependencies=['component_configuration'])
def kubelet_server_certificate_rotation_declaration(item, index):
    component = _get_remaining(item, 'component', str)
    if component != 'kubelet':
        return 'NOT_APPLICABLE', {'reason': 'feature gate applies to kubelet configuration', 'observed_component': component}
    applicability = _kubelet_applicability(item, 7)
    if applicability is not None:
        return applicability
    enabled = _get_remaining(item, 'configuration.featureGates.RotateKubeletServerCertificate', bool)
    return _observed_kubelet_declaration(item, index,
        _result_remaining(not enabled, configured_rotation_gate=enabled,
            semantics='One operator-supplied kubelet feature-gate declaration; runtime bootstrap, CSR approval, certificates and all-node coverage unproved'))
