"""Kubernetes structural network consumers from read-only native lists."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from peaso.checks.facts import Unavailable, memoized
from peaso.unused_iam_k8s import _selector_matches


def _available(value, fields):
    if not isinstance(value, dict):
        raise Unavailable('native object field is malformed')
    coverage = value.get('_coverage', {})
    if not isinstance(coverage, dict):
        raise Unavailable('native field coverage is malformed')
    for field in fields:
        if field in coverage and (not isinstance(coverage[field], dict) or coverage[field].get('status') not in ('collected', 'empty')):
            raise Unavailable('native field is unavailable: ' + field)


def _rows(index, kind):
    def build():
        context = index.get('context', {})
        cluster = context.get('metadata', {}).get('cluster_id')
        scope = context.get('scope')
        if context.get('provider') != 'k8s' or not isinstance(scope, str) or not isinstance(cluster, str) or not cluster:
            raise Unavailable('Kubernetes cluster authority is unavailable')
        envelopes = index.get('collections', {}).get(kind)
        if not isinstance(envelopes, list) or len(envelopes) != 1:
            raise Unavailable('native inventory is unavailable: ' + kind)
        envelope = envelopes[0]
        if envelope.get('type') != kind or envelope.get('scope') != scope or envelope.get('service') != 'kubernetes':
            raise Unavailable('native inventory is outside the selected cluster or scope')
        rows, projected = envelope.get('items'), index.get(kind)
        if (not isinstance(rows, list) or not isinstance(projected, list)
                or len(rows) != len(projected) or [r.get('data') for r in projected] != rows
                or any(r.get('type') != kind or r.get('scope') != scope for r in projected)):
            raise Unavailable('native inventory and resource projection differ: ' + kind)
        if envelope.get('status') not in ('collected', 'empty', 'partial'):
            raise Unavailable('native inventory is unavailable: ' + kind)
        if envelope.get('status') == 'empty' and rows:
            raise Unavailable('empty inventory contains objects')
        seen = set()
        for row in rows:
            _available(row, ('metadata', 'spec', 'provenance'))
            meta, proof = row.get('metadata'), row.get('provenance')
            _available(meta, ('name', 'namespace', 'uid', 'labels', 'ownerReferences'))
            if (not isinstance(meta, dict) or not isinstance(proof, dict)
                    or not all(isinstance(meta.get(key), str) and meta[key] for key in ('name', 'uid', 'namespace'))
                    or proof.get('cluster_id') != cluster or proof.get('uid') != meta['uid']
                    or proof.get('namespace') != meta['namespace'] or proof.get('evidence') != 'read-only list'
                    or scope != '*' and meta['namespace'] != scope):
                raise Unavailable('foreign or unbound Kubernetes object: ' + kind)
            key = meta['namespace'], meta['name']
            if key in seen:
                raise Unavailable('duplicate Kubernetes object: ' + kind)
            seen.add(key)
        return rows, envelope['status'] in ('collected', 'empty')
    return memoized(index, ('unused_network_k8s_20261021', kind), build)


def _current(item, index, kind):
    rows, _ = _rows(index, kind)
    meta = item.get('metadata', {})
    if not isinstance(meta, dict) or not any(row == item and row.get('metadata', {}).get('uid') == meta.get('uid') for row in rows):
        raise Unavailable('assessed Kubernetes object is not the captured current object')
    return meta


def _complete(complete, kind):
    if not complete:
        raise Unavailable('absence cannot be inferred from partial inventory: ' + kind)


def _summary(name, fact, limit):
    return f'{name}: {fact}\nThis is a current API declaration, not observed traffic.\n{limit}'


def service(item, index):
    meta = _current(item, index, 'service')
    spec = item.get('spec')
    if not isinstance(spec, dict):
        raise Unavailable('Service spec is unavailable')
    _available(spec, ('type', 'selector'))
    name, namespace = meta['name'], meta['namespace']
    if spec.get('type') == 'ExternalName':
        return 'NOT_APPLICABLE', {'summary': _summary(name, 'ExternalName resolves an external DNS name.', 'Local Pod and EndpointSlice inventory does not define its use.')}
    selector = spec.get('selector')
    if selector is None or selector == {}:
        return 'NOT_APPLICABLE', {'summary': _summary(name, 'Service has no Pod selector.', 'Manually managed Endpoints or EndpointSlices may supply its backends.')}
    if not isinstance(selector, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in selector.items()):
        raise Unavailable('Service selector is malformed')
    pods, pods_complete = _rows(index, 'pod')
    matches = [p['metadata']['name'] for p in pods if p['metadata']['namespace'] == namespace and all(p['metadata'].get('labels', {}).get(k) == v for k, v in selector.items())]
    if matches:
        return 'PASS', {'selected_pods': matches[:20], 'summary': _summary(name, f'Service selector matches {len(matches)} current Pod(s).', 'Pod readiness and traffic are separate.')}
    slices, slices_complete = _rows(index, 'endpointslice')
    linked = []
    uncertain = False
    for slice_ in slices:
        smeta = slice_['metadata']
        if smeta['namespace'] != namespace or smeta.get('labels', {}).get('kubernetes.io/service-name') != name:
            continue
        owners = smeta.get('ownerReferences', [])
        if not isinstance(owners, list):
            raise Unavailable('EndpointSlice owners are malformed')
        if any(not isinstance(owner, dict) for owner in owners):
            raise Unavailable('EndpointSlice owner is malformed')
        if any(owner.get('kind') == 'Service' and owner.get('name') == name and owner.get('uid') != meta['uid'] for owner in owners):
            uncertain = True
            continue
        try:
            _available(slice_, ('endpoints',))
        except Unavailable:
            uncertain = True
            continue
        endpoints = slice_.get('endpoints')
        if not isinstance(endpoints, list):
            uncertain = True
            continue
        for endpoint in endpoints:
            if not isinstance(endpoint, dict) or not isinstance(endpoint.get('addresses'), list):
                uncertain = True
                continue
            if any(isinstance(address, str) and address for address in endpoint['addresses']):
                linked.append(smeta['name'])
                break
            if endpoint['addresses']:
                uncertain = True
    if linked:
        return 'PASS', {'endpoint_slices': linked[:20], 'summary': _summary(name, f'{len(linked)} EndpointSlice(s) declare backend addresses for this Service.', 'Endpoint readiness and client use are separate.')}
    if uncertain:
        raise Unavailable('linked EndpointSlice backend or owner evidence is incomplete')
    _complete(pods_complete, 'pod')
    _complete(slices_complete, 'endpointslice')
    return 'FAIL', {'summary': _summary(name, 'selector matches no current Pods and no EndpointSlice declares backend addresses.', 'This can be intentional during scale-to-zero or rollout; it does not prove the Service is unused.')}


def endpoints(item, index):
    meta = _current(item, index, 'endpoints')
    _available(meta, ('labels', 'ownerReferences'))
    labels, owners = meta.get('labels', {}), meta.get('ownerReferences', [])
    if not isinstance(labels, dict) or not isinstance(owners, list):
        raise Unavailable('Endpoints management identity is malformed')
    managed = labels.get('endpoints.kubernetes.io/managed-by')
    if managed is not None and not isinstance(managed, str):
        raise Unavailable('Endpoints manager label is malformed')
    if managed != 'endpoint-controller':
        return 'NOT_APPLICABLE', {'summary': _summary(meta['name'], 'Endpoints is not marked as Kubernetes endpoint-controller managed.', 'Custom or unmarked Endpoints may have independent consumers.')}
    if any(not isinstance(owner, dict) for owner in owners):
        raise Unavailable('Endpoints owner reference is malformed')
    service_owners = [owner for owner in owners if owner.get('apiVersion') == 'v1' and owner.get('kind') == 'Service' and owner.get('controller') is True]
    if len(service_owners) != 1:
        return 'NOT_APPLICABLE', {'summary': _summary(meta['name'], 'Endpoints has no unique controlling v1 Service owner.', 'A name alone does not establish a dangling Service reference.')}
    owner = service_owners[0]
    if owner.get('name') != meta['name'] or not isinstance(owner.get('uid'), str) or not owner['uid']:
        raise Unavailable('Endpoints owner is not bound to its same-name Service UID')
    services, complete = _rows(index, 'service')
    matches = [service for service in services if service['metadata']['namespace'] == meta['namespace'] and service['metadata']['name'] == owner['name']]
    if matches:
        if matches[0]['metadata']['uid'] != owner['uid']:
            raise Unavailable('Endpoints owner UID differs from current Service UID')
        return 'PASS', {'service_name': owner['name'], 'summary': _summary(meta['name'], 'controller-managed Endpoints owner matches the current same-namespace Service UID.', 'Endpoint addresses and client traffic are separate.')}
    _complete(complete, 'service')
    return 'FAIL', {'service_name': owner['name'], 'summary': _summary(meta['name'], 'controller-managed Endpoints owner names an absent same-namespace Service.', 'Confirm controller state and intended consumers before removal.')}


def ingress(item, index):
    meta = _current(item, index, 'ingress')
    spec = item.get('spec')
    if not isinstance(spec, dict):
        raise Unavailable('Ingress spec is unavailable')
    _available(spec, ('defaultBackend', 'rules'))
    backends = []
    if spec.get('defaultBackend') is not None:
        backends.append(spec['defaultBackend'])
    rules = spec.get('rules', [])
    if not isinstance(rules, list):
        raise Unavailable('Ingress rules are malformed')
    for rule in rules:
        if not isinstance(rule, dict):
            raise Unavailable('Ingress rule is malformed')
        http = rule.get('http') or {}
        paths = http.get('paths', []) if isinstance(http, dict) else None
        if not isinstance(paths, list):
            raise Unavailable('Ingress HTTP paths are malformed')
        if any(not isinstance(path, dict) for path in paths):
            raise Unavailable('Ingress HTTP path is malformed')
        backends.extend(path.get('backend') for path in paths)
    names = []
    for backend in backends:
        if not isinstance(backend, dict):
            raise Unavailable('Ingress backend is malformed')
        if 'resource' in backend:
            continue
        service_ref = backend.get('service')
        if not isinstance(service_ref, dict) or not isinstance(service_ref.get('name'), str) or not service_ref['name']:
            raise Unavailable('Ingress Service backend is malformed')
        names.append(service_ref['name'])
    if not names:
        return 'NOT_APPLICABLE', {'summary': _summary(meta['name'], 'Ingress has no native Service backend.', 'Resource backends and controller defaults require separate review.')}
    services, complete = _rows(index, 'service')
    available = {s['metadata']['name'] for s in services if s['metadata']['namespace'] == meta['namespace']}
    missing = sorted(set(names) - available)
    if missing:
        _complete(complete, 'service')
        return 'FAIL', {'missing_services': missing, 'summary': _summary(meta['name'], f'Ingress references missing same-namespace Service(s): {", ".join(missing)}.', 'Ingress controller reconciliation is separate.')}
    return 'PASS', {'service_backends': sorted(set(names)), 'summary': _summary(meta['name'], 'every native Service backend resolves in this namespace.', 'This does not prove controller routing or endpoint readiness.')}


def endpointslice(item, index):
    meta = _current(item, index, 'endpointslice')
    labels = meta.get('labels', {})
    if not isinstance(labels, dict):
        raise Unavailable('EndpointSlice labels are malformed')
    name = labels.get('kubernetes.io/service-name')
    if name is None:
        return 'NOT_APPLICABLE', {'summary': _summary(meta['name'], 'EndpointSlice has no native Service-name label.', 'Custom controllers may use standalone slices; no unused claim follows.')}
    if not isinstance(name, str) or not name:
        raise Unavailable('EndpointSlice Service-name label is malformed')
    services, complete = _rows(index, 'service')
    matches = [s for s in services if s['metadata']['namespace'] == meta['namespace'] and s['metadata']['name'] == name]
    if matches:
        owners = meta.get('ownerReferences', [])
        if not isinstance(owners, list):
            raise Unavailable('EndpointSlice owners are malformed')
        for owner in owners:
            if not isinstance(owner, dict):
                raise Unavailable('EndpointSlice owner is malformed')
            if owner.get('kind') == 'Service' and owner.get('name') == name and owner.get('uid') != matches[0]['metadata']['uid']:
                raise Unavailable('EndpointSlice Service owner UID does not match the current Service')
        return 'PASS', {'service_name': name, 'summary': _summary(meta['name'], f'EndpointSlice names current same-namespace Service {name}.', 'Endpoint readiness and traffic are separate.')}
    _complete(complete, 'service')
    return 'FAIL', {'service_name': name, 'summary': _summary(meta['name'], f'EndpointSlice names absent same-namespace Service {name}.', 'A custom consumer may still watch this slice; review its manager before removal.')}


def networkpolicy(item, index):
    meta = _current(item, index, 'networkpolicy')
    spec = item.get('spec')
    if not isinstance(spec, dict) or not isinstance(spec.get('podSelector'), dict):
        raise Unavailable('NetworkPolicy podSelector is unavailable')
    _available(spec, ('podSelector',))
    selector = spec['podSelector']
    # Validate expression syntax even when the current Pod inventory is empty.
    _selector_matches(selector, {})
    pods, complete = _rows(index, 'pod')
    matches = [p['metadata']['name'] for p in pods if p['metadata']['namespace'] == meta['namespace']
               and _selector_matches(selector, p['metadata'].get('labels', {}))]
    if matches:
        return 'PASS', {'selected_pods': matches[:20], 'summary': _summary(meta['name'], f'NetworkPolicy selects {len(matches)} current Pod(s) in its namespace.', 'CNI enforcement and traffic are separate.')}
    _complete(complete, 'pod')
    return 'FAIL', {'summary': _summary(meta['name'], 'NetworkPolicy selects no current Pods in its namespace.', 'This can be intentional for future Pods; it does not prove the policy is unused.')}


DECLARATIONS = (
    ('k8s.network.service_has_current_backend_declaration', 'service', 'Service has a current Pod or EndpointSlice backend declaration', service, ('service', 'pod', 'endpointslice')),
    ('k8s.network.endpoints_controller_service_reference_resolves', 'endpoints', 'Controller-managed Endpoints Service owner resolves in its namespace', endpoints, ('endpoints', 'service')),
    ('k8s.network.endpointslice_service_reference_resolves', 'endpointslice', 'EndpointSlice Service-name label resolves in its namespace', endpointslice, ('endpointslice', 'service')),
    ('k8s.network.ingress_service_backends_resolve', 'ingress', 'Ingress Service backends resolve in the same namespace', ingress, ('ingress', 'service')),
    ('k8s.network.networkpolicy_selects_current_pod', 'networkpolicy', 'NetworkPolicy selects a current Pod in its namespace', networkpolicy, ('networkpolicy', 'pod')),
)
CASES_SHA256 = 'c7e22c01a3069b74ba135c321f243eef56716bf4399b8d11284722f2918b06e0'


def install(registry):
    from peaso.checks.fixtures import CASES
    raw = (Path(__file__).with_name('checks') / 'unused_network_k8s_20261021_cases.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != CASES_SHA256:
        raise ValueError('Kubernetes unused-network cases changed')
    cases = json.loads(raw)
    if set(cases) != {row[0] for row in DECLARATIONS}:
        raise ValueError('Kubernetes unused-network case IDs changed')
    for ident, kind, title, predicate, dependencies in DECLARATIONS:
        registry.register(ident, 'k8s', 'hardening', kind, title, 'low', 'Hardening',
            'Review the owning workload and desired routing or policy; update the declaration through its normal controller or infrastructure source after confirming intent.',
            dependencies=dependencies, allow_incomplete_failure=True)(predicate)
        CASES[ident] = cases[ident]
