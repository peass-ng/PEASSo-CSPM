"""Domain view reuse preserves live trust changes and ordinary set operations."""
import copy
import operator
import pickle
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from tests.synthetic.benchmark_peaso_trust_domains import gcp_snapshot as synthetic_snapshot, run_stage
from tests.synthetic.benchmark_peaso_trust_domains import synthetic_snapshot as provider_snapshot
from peaso.analysis import trust, trust_domains
from peaso.analysis.common import analysis_context
from peaso.snapshot import digest, resources


@pytest.mark.parametrize('operation,args', [
    ('add', ('OUTSIDE.EXAMPLE',)), ('clear', ()), ('discard', ('CORP.EXAMPLE',)),
    ('remove', ('CORP.EXAMPLE',)), ('update', (['OUTSIDE.EXAMPLE'],)),
    ('difference_update', ({'CORP.EXAMPLE'},)), ('intersection_update', ({'CORP.EXAMPLE'},)),
    ('symmetric_difference_update', ({'CORP.EXAMPLE', 'OUTSIDE.EXAMPLE'},)),
    ('__ior__', ({'OUTSIDE.EXAMPLE'},)), ('__iand__', ({'CORP.EXAMPLE'},)),
    ('__ixor__', ({'CORP.EXAMPLE', 'OUTSIDE.EXAMPLE'},)), ('__isub__', ({'CORP.EXAMPLE'},)),
    ('__init__', (['OUTSIDE.EXAMPLE'],)),
])
def test_each_mutating_set_api_invalidates_its_lowercase_view(operation, args):
    domains = trust_domains.OwnedDomains(['CORP.EXAMPLE', 'PARTNER.EXAMPLE'])
    expected = set(domains)
    first = trust_domains.normalized(domains)
    result = getattr(domains, operation)(*args)
    wanted = getattr(expected, operation)(*args)
    assert domains == expected
    if wanted is expected:
        assert result is domains
    else:
        assert result == wanted
    assert trust_domains.normalized(domains) == {value.lower() for value in expected}
    assert trust_domains.normalized(domains) is not first


def test_pop_and_no_op_mutations_preserve_set_contracts():
    domains = trust_domains.OwnedDomains(['ONE.EXAMPLE'])
    first = trust_domains.normalized(domains)
    assert first is trust_domains.normalized(domains)
    assert domains.pop() == 'ONE.EXAMPLE'
    assert trust_domains.normalized(domains) == set()
    with pytest.raises(KeyError):
        domains.pop()
    domains.discard('missing')
    domains.clear()
    assert trust_domains.normalized(domains) == set()


def test_partial_update_failure_preserves_the_newly_recorded_domains():
    domains = trust_domains.OwnedDomains(['CORP.EXAMPLE'])
    trust_domains.normalized(domains)

    def values():
        yield 'OUTSIDE.EXAMPLE'
        raise ValueError('incomplete iterable')

    with pytest.raises(ValueError, match='incomplete iterable'):
        domains.update(values())
    assert trust_domains.normalized(domains) == {'corp.example', 'outside.example'}
    assert domains._mutating == 0


def test_reentrant_iterables_can_inspect_intermediate_updates_from_another_thread():
    domains = trust_domains.OwnedDomains(['CORP.EXAMPLE'])
    trust_domains.normalized(domains)
    with ThreadPoolExecutor(max_workers=1) as pool:
        def values():
            yield 'OUTSIDE.EXAMPLE'
            first = pool.submit(trust_domains.normalized, domains).result(timeout=3)
            assert first == {'corp.example', 'outside.example'}
            domains.add('PARTNER.EXAMPLE')
            yield 'LAST.EXAMPLE'
            second = pool.submit(trust_domains.normalized, domains).result(timeout=3)
            assert second == {'corp.example', 'outside.example', 'partner.example', 'last.example'}
        domains.update(values())
    assert trust_domains.normalized(domains) == {value.lower() for value in domains}


def test_normalization_in_flight_cannot_publish_a_view_from_before_a_mutation(monkeypatch):
    domains = trust_domains.OwnedDomains(['CORP.EXAMPLE'])
    entered, release = threading.Event(), threading.Event()

    def paused(values):
        result = frozenset(values)
        entered.set()
        assert release.wait(3)
        return result

    monkeypatch.setattr(trust_domains, 'frozenset', paused, raising=False)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(trust_domains.normalized, domains)
        try:
            assert entered.wait(3)
            domains.add('OUTSIDE.EXAMPLE')
        finally:
            release.set()
        assert pending.result(timeout=3) == {'corp.example'}
    assert domains._lowered is None
    assert trust_domains.normalized(domains) == {'corp.example', 'outside.example'}


def test_string_subclasses_and_replacement_sets_are_normalized_on_every_call():
    class ChangingDomain(str):
        current = 'outside.example'
        def lower(self):
            return self.current

    value = ChangingDomain('recorded.example')
    domains = trust_domains.OwnedDomains([value])
    assert trust_domains.normalized(domains) == {'outside.example'}
    value.current = 'corp.example'
    assert trust_domains.normalized(domains) == {'corp.example'}
    assert domains._lowered is None
    ordinary = {'CORP.EXAMPLE'}
    assert trust_domains.normalized(ordinary) == {'corp.example'}
    ordinary.add('OUTSIDE.EXAMPLE')
    assert trust_domains.normalized(ordinary) == {'corp.example', 'outside.example'}


@pytest.mark.parametrize('provider', ['gcp', 'k8s'])
def test_classification_reads_live_domain_and_scope_changes(provider):
    snapshot = synthetic_snapshot(2, 1)
    snapshot['provider'] = provider
    principal = 'user:person@outside.example' if provider == 'gcp' else 'person@outside.example'
    with analysis_context(snapshot):
        boundary = trust.trusted_scopes(snapshot)
        assert type(boundary['domains']) is trust_domains.OwnedDomains
        assert trust.classify(snapshot, principal) == 'external'
        boundary['domains'].add('OUTSIDE.EXAMPLE')
        assert trust.classify(snapshot, principal) == 'allowlisted'
        boundary['domains'].remove('OUTSIDE.EXAMPLE')
        assert trust.classify(snapshot, principal) == 'external'
        boundary['domains'] = {'OUTSIDE.EXAMPLE'}
        assert trust.classify(snapshot, principal) == 'allowlisted'
        boundary['domains'].clear()
        assert trust.classify(snapshot, principal) == 'unknown'
        if provider == 'gcp':
            boundary['ids'].add('outside-project')
            assert trust.classify(snapshot, principal, scope='outside-project') == 'allowlisted'
            boundary['ids'].remove('outside-project')
            assert trust.classify(snapshot, principal, scope='outside-project') == 'external'


def test_unshared_boundaries_keep_ordinary_sets_and_copies_need_no_lock_state():
    snapshot = synthetic_snapshot(1, 4)
    assert type(trust.trusted_scopes(snapshot)['domains']) is set
    domains = trust_domains.OwnedDomains(['CORP.EXAMPLE'])
    trust_domains.normalized(domains)
    for result in (domains.copy(), copy.copy(domains), copy.deepcopy(domains), pickle.loads(pickle.dumps(domains))):
        assert type(result) is set and result == {'CORP.EXAMPLE'}
        result.add('OUTSIDE.EXAMPLE')
        assert 'OUTSIDE.EXAMPLE' not in domains


@pytest.mark.parametrize('provider', ['gcp', 'k8s'])
@pytest.mark.parametrize('domains', [0, 1, 12, 64])
def test_complete_iam_findings_graph_and_principal_cards_match_fresh_normalization(monkeypatch, domains, provider):
    snapshot = provider_snapshot(provider, 15, domains)
    rows, before = resources(snapshot), digest(snapshot)
    actual = run_stage(snapshot, rows)
    monkeypatch.setattr(trust, 'normalized_domains', lambda values: {value.lower() for value in values})
    assert actual == run_stage(snapshot, rows)
    assert digest(snapshot) == before


@pytest.mark.parametrize('operation', [operator.ior, operator.iand, operator.ixor, operator.isub])
def test_inplace_operators_still_reject_non_sets(operation):
    domains = trust_domains.OwnedDomains(['CORP.EXAMPLE'])
    trust_domains.normalized(domains)
    with pytest.raises(TypeError):
        operation(domains, ['OUTSIDE.EXAMPLE'])
    assert trust_domains.normalized(domains) == {'corp.example'}
