#!/usr/bin/env python3
"""Compare provider catalogs, complete combinations and a Kubernetes RBAC matrix."""
from __future__ import annotations

import argparse
import importlib.util
import itertools
import sys
from pathlib import Path

import yaml

try:
    from . import permission_risk_classifier as blue
except ImportError:
    import permission_risk_classifier as blue


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def check(root: Path) -> dict[str, int]:
    repo = Path(__file__).resolve().parent.parent
    cloud = load_module('cloudpeass_parity_classifier', root / 'src/CloudPEASS/permission_risk_classifier.py')
    counts = {}
    for provider in ('aws', 'gcp', 'azure'):
        catalog = yaml.safe_load((repo / f'{provider}_permissions_cat.yaml').read_text())
        catalog_sets = {level: set(values) for level, values in catalog.items()}
        catalog_permissions = set().union(*catalog_sets.values())
        permissions = set(catalog_permissions)
        permissions.update(cloud._load_yaml(provider).get('severity_overrides', {}))
        permissions.update(cloud._load_yaml(provider).get('non_permission_identifiers', []))
        combinations = cloud.load_criticality_combinations(provider)
        assert combinations == blue.load_criticality_combinations(provider), provider
        permissions.update(p for combos in combinations.values() for combo in combos for p in combo)
        for permission in sorted(permissions):
            variants = (permission, permission.upper(), permission.lower()) if provider in {'aws', 'azure'} else (permission,)
            for variant in variants:
                actual = blue.classify_permission(provider, variant, unknown_default='medium')
                expected = cloud.classify_permission(provider, variant, unknown_default='medium')
                assert actual == expected, (provider, variant, expected, actual)
            assert permission in catalog_sets[blue.classify_permission(provider, permission, unknown_default='medium')] or permission not in catalog_permissions, (provider, permission, 'stale catalog')
        for combos in combinations.values():
            for combo in combos:
                assert cloud.classify_all(provider, combo, 'medium') == blue.classify_all(provider, combo, 'medium'), (provider, combo)
                if len(combo) > 1:
                    assert cloud.classify_all(provider, combo[:-1], 'medium') == blue.classify_all(provider, combo[:-1], 'medium'), (provider, combo[:-1])
        counts[provider] = len(permissions)

    sys.path.insert(0, str(root))
    from src.k8s.models import PermissionKey
    from src.k8s.risks import classify_permission as cloud_k8s
    sys.path.insert(0, str(repo))
    from bluepeass.k8s import classify_permission as blue_k8s
    groups = ('', '*', 'apps', 'batch', 'policy', 'rbac.authorization.k8s.io', 'certificates.k8s.io', 'authentication.k8s.io', 'admissionregistration.k8s.io', 'apiextensions.k8s.io', 'example.test')
    groups += ('networking.k8s.io', 'gateway.networking.k8s.io', 'discovery.k8s.io', 'extensions', 'constraints.gatekeeper.sh', 'kyverno.io', 'storage.k8s.io')
    resources = ('*', 'secrets', 'serviceaccounts', 'serviceaccounts/token', 'pods', 'pods/exec', 'pods/attach', 'pods/status', 'nodes/proxy', 'nodes/status', 'daemonsets/status', 'replicasets/status', 'poddisruptionbudgets/status', 'customresourcedefinitions/status', 'clusterroles', 'roles', 'rolebindings', 'clusterrolebindings', 'certificatesigningrequests', 'certificatesigningrequests/approval', 'signers', 'users', 'groups', 'configmaps', 'services/status', 'mutatingwebhookconfigurations')
    resources += ('pods/log', 'pods/proxy', 'pods/portforward', 'pods/ephemeralcontainers', 'pods/binding', 'pods/eviction', 'bindings', 'deployments', 'deployments/scale', 'daemonsets', 'statefulsets', 'replicasets', 'replicationcontrollers', 'jobs', 'cronjobs', 'namespaces', 'namespaces/status', 'nodes', 'nodes/checkpoint', 'services', 'services/proxy', 'endpoints', 'endpointslices', 'ingresses', 'ingresses/status', 'httproutes', 'networkpolicies', 'persistentvolumes', 'persistentvolumeclaims', 'clustertrustbundles', 'certificatesigningrequests/status', 'validatingadmissionpolicies', 'validatingadmissionpolicybindings', 'mutatingadmissionpolicies', 'mutatingadmissionpolicybindings', 'validatingwebhookconfigurations', 'uids', 'userextras', 'podsecuritypolicies', 'securitycontextconstraints', 'selfsubjectaccessreviews', 'subjectaccessreviews', 'tokenreviews', 'policyreports', 'clusterpolicies', 'storageclasses')
    verbs = ('get', 'list', 'watch', 'create', 'patch', 'update', 'delete', 'deletecollection', 'bind', 'escalate', 'impersonate', 'approve', 'sign', '*', 'impersonate-on:user-info:get')
    verbs += ('attest', 'use', 'impersonate:user-info', 'impersonate:serviceaccount', 'impersonate:arbitrary-node', 'impersonate-on:user-info:create', 'request-serviceaccounts-token-audience')
    n = 0
    for group, resource, verb in itertools.product(groups, resources, verbs):
        base, _, sub = resource.partition('/')
        for name in ('', 'restricted-name'):
            key = PermissionKey(verb, group=group, resource=base, subresource=sub, name=name)
            record = dict(api_group=group, resource=resource, verb=verb, name=name)
            assert cloud_k8s(key) == blue_k8s(record), (record, cloud_k8s(key), blue_k8s(record))
            n += 1
    for path in ('/api', '/apis/*', '/metrics', '/debug/*', '/logs', '/healthz'):
        assert cloud_k8s(PermissionKey('get', non_resource_url=path)) == blue_k8s(dict(api_group='nonResourceURL', resource=path, verb='get'))
        n += 1
    counts['k8s'] = n
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cloudpeass-root', type=Path, required=True)
    args = parser.parse_args()
    print('Parity passed:', check(args.cloudpeass_root.resolve()))


if __name__ == '__main__':
    main()
