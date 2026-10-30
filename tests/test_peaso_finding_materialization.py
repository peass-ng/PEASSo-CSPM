"""Finding metadata reuse: registered predecessor parity and bounded lifetime."""
import gc
import weakref
from types import SimpleNamespace
import pytest
from peaso import engine
from peaso.checks import CHECKS

# Frozen predecessor function from engine.py SHA14fdc91a8535; normal source
# admission above runs before this independent comparison oracle is compiled.
PREDECESSOR = 'def _finding(check, provider, scope, rid, service, status, evidence, frameworks=None):\n    from .finding_types import type_for\n    from .finding_priority import effective_priority\n    from .check_services import service_for_check\n    service = service_for_check(check.id, provider, check.kind, service)\n    current = {"id": digest([provider, scope, rid, check.id]), "category": check.category, "check_id": check.id,\n        "finding_type": type_for(check.id),\n        "title": check.title, "provider": provider, "service": service, "resource_id": rid, "scope": scope,\n        "severity": effective_priority(check.id, check.severity), "status": status, "frameworks": list(check.frameworks if frameworks is None else frameworks),\n        "evidence": evidence, "remediation": check.remediation}\n    if provider == "aws":\n        from .checks.aws_finding_priority import contextual_severity as aws_contextual_severity\n        from .checks.aws_compute_storage_priority import contextual_severity as compute_contextual_severity\n        current["severity"] = compute_contextual_severity(current, aws_contextual_severity(current, current["severity"]))\n    if provider == "azure":\n        from .checks.azure_finding_priority import contextual_severity\n        current["severity"] = contextual_severity(current, current["severity"])\n    return current'
namespace = {'__package__': 'peaso', 'digest': engine.digest}
exec(compile(PREDECESSOR, '<predecessor-finding>', 'exec'), namespace)
predecessor = namespace['_finding']


@pytest.mark.parametrize('cid, provider, evidence_key, values', [
    ('aws.ec2.restrict_internet_ingress', 'aws', 'internet_ingress',
     [[{'protocol': 'tcp', 'from_port': 80, 'to_port': 80}], [{'protocol': 'tcp', 'from_port': 22, 'to_port': 22}]]),
    ('aws.cb.lightsail.ssh_restricted', 'aws', 'open_ports', [[80], [22]]),
    ('azure.claude.vm_nic_nsg_internet_tcp_ingress', 'azure', 'internet_allow_rules',
     [[{'ports': ['443']}], [{'ports': ['22']}]])])
def test_one_factory_keeps_contextual_priority_per_finding(cid, provider, evidence_key, values):
    check = next(c for c in CHECKS if c.id == cid)
    emit = engine._finding_factory(check, provider, [])
    for value in values * 2:
        evidence = {evidence_key: value}
        actual = emit('scope', 'resource', 'service', 'FAIL', evidence)
        assert actual == predecessor(check, provider, 'scope', 'resource', 'service', 'FAIL', evidence, [])


def test_lazy_metadata_reuse_is_limited_to_one_factory(monkeypatch):
    from peaso import finding_types, finding_priority, check_services
    calls = {'type': 0, 'priority': 0, 'service': 0}
    def type_for(cid):
        calls['type'] += 1
        return 'synthetic'
    def priority(cid, value):
        calls['priority'] += 1
        return value
    def service_for(*args):
        calls['service'] += 1
        return args[-1]
    monkeypatch.setattr(finding_types, 'type_for', type_for)
    monkeypatch.setattr(finding_priority, 'effective_priority', priority)
    monkeypatch.setattr(check_services, 'service_for_check', service_for)
    check = SimpleNamespace(id='fixture', kind='fixture', title='Fixture', category='hardening', severity='low', frameworks=[], remediation='Fixture')
    emit = engine._finding_factory(check, 'gcp', [])
    assert calls == {'type': 0, 'priority': 0, 'service': 0}
    for number in range(400):
        for service in ('a', 'b'):
            assert emit('scope', str(number), service, 'PASS', {})['service'] == service
    assert calls == {'type': 1, 'priority': 1, 'service': 2}
    engine._finding_factory(check, 'gcp', [])('scope', 'new', 'a', 'PASS', {})
    assert calls == {'type': 2, 'priority': 2, 'service': 3}
    for number in range(400):
        assert emit('scope', 'resource', f'service-{number}', 'PASS', {})['service'] == f'service-{number}'
    # New service labels beyond the fixed cache bound still resolve correctly.
    previous = calls['service']
    for number in range(400):
        emit('scope', 'resource', f'service-{number}', 'PASS', {})
    assert 300 < calls['service'] - previous < 400


def test_metadata_failures_are_not_cached(monkeypatch):
    from peaso import finding_types
    real = finding_types.type_for
    calls = []
    def fail_once(cid):
        calls.append(cid)
        if len(calls) == 1:
            raise ValueError('synthetic metadata failure')
        return real(cid)
    monkeypatch.setattr(finding_types, 'type_for', fail_once)
    check = next(c for c in CHECKS if c.provider == 'gcp')
    emit = engine._finding_factory(check, 'gcp', [])
    with pytest.raises(ValueError, match='synthetic metadata failure'):
        emit('scope', 'resource', 'service', 'PASS', {})
    assert emit('scope', 'resource', 'service', 'PASS', {})
    assert len(calls) == 2


def test_factory_does_not_retain_evidence_or_share_output_lists():
    class Evidence(dict):
        pass
    check = next(c for c in CHECKS if c.provider == 'gcp')
    labels = ['Synthetic']
    emit = engine._finding_factory(check, 'gcp', labels)
    evidence = Evidence(synthetic=True)
    weak = weakref.ref(evidence)
    first = emit('scope', 'first', None, 'FAIL', evidence)
    second = emit('scope', 'second', None, 'PASS', {})
    assert first == predecessor(check, 'gcp', 'scope', 'first', None, 'FAIL', evidence, labels)
    first['frameworks'].append('local mutation')
    assert second['frameworks'] == labels == ['Synthetic']
    del first, evidence
    gc.collect()
    assert weak() is None


def test_factory_keeps_service_id_and_metadata_exception_order(monkeypatch):
    from peaso import finding_types, check_services
    state = {'service_error': True, 'type_calls': 0}
    def service_for(*args):
        if state['service_error']:
            raise ValueError('service first')
        return args[-1]
    def type_for(cid):
        state['type_calls'] += 1
        raise RuntimeError('type after ID')
    monkeypatch.setattr(check_services, 'service_for_check', service_for)
    monkeypatch.setattr(finding_types, 'type_for', type_for)
    check = SimpleNamespace(id='fixture', kind='fixture', title='Fixture', category='hardening', severity='low', frameworks=[], remediation='Fixture')
    emit = engine._finding_factory(check, 'gcp', [])
    with pytest.raises(ValueError, match='service first'):
        emit('scope', object(), 'service', 'PASS', {})
    assert state['type_calls'] == 0
    state['service_error'] = False
    with pytest.raises(TypeError):
        emit('scope', object(), 'service', 'PASS', {})
    assert state['type_calls'] == 0
    with pytest.raises(RuntimeError, match='type after ID'):
        emit('scope', 'resource', 'service', 'PASS', {})
    assert state['type_calls'] == 1
