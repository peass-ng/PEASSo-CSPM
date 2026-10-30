"""Normal native admission, original metadata contract and fail-closed epoch proofs."""
import copy
from pathlib import Path
import types
import pytest
from peaso.collectors import azure
from tests.shared_admission_epoch_compatibility_20261020 import active_shared
bridge = active_shared()
from tests.test_peaso_azure_tls_owner_policy import options, owner, SCOPE, FOREIGN

ROOT = Path(__file__).resolve().parents[1]
TENANT = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'


class Inert:
    tenant = verified_tenant = TENANT
    def request(self, *a, **k): raise AssertionError('No native IO allowed')


@pytest.mark.parametrize('case', ['tls', 'namespaces', 'scope', 'invalid_scope', 'window', 'package', 'wildcard', 'hosted'])
def test_supplied8_metadata_only_cases_through_normal_admitted_collect(case, monkeypatch):
    constructions = []
    def forbidden(*a, **k): constructions.append((a, k)); raise AssertionError('Transport construction forbidden')
    monkeypatch.setattr(azure, 'AzureTransportExposure', forbidden)
    supplied = options() if case in ('tls', 'namespaces', 'scope') else {'activity_days': 0} if case == 'window' else {'hosted': True} if case == 'hosted' else {}
    raw_policy = {'sw03': {'status': 'collected', 'scope': SCOPE, 'legacyAgentBaseline': {'required': False}}, 'sw33': {'status': 'collected', 'scope': SCOPE, 'databricksAccount': {'accountId': TENANT}}}
    if case == 'namespaces': supplied['compliance_policy'] = copy.deepcopy(raw_policy)
    before = copy.deepcopy(supplied)
    scopes = [FOREIGN] if case == 'scope' else ['sub/../../other'] if case == 'invalid_scope' else ['*'] if case == 'wildcard' else [SCOPE]
    requirements = [azure.package_source.KIND] if case == 'package' else []
    if case in ('scope', 'invalid_scope', 'window'):
        with pytest.raises(ValueError): azure.collect({'auth': {}, 'scopes': scopes, 'options': supplied}, requirements=requirements)
    else:
        kw = {} if case == 'hosted' else {'transport': Inert()}
        value = azure.collect({'auth': {}, 'scopes': scopes, 'options': supplied}, requirements=requirements, **kw)
        assert value['metadata']['calls'] == 0 and value['collections'] == []
        assert value['metadata']['omitted_inventories']
        if case == 'tls': assert value['metadata']['compliance_policy'] == owner()
        if case == 'namespaces': assert value['metadata']['compliance_policy'] == {**raw_policy, **owner()}
        if case == 'hosted': assert value['metadata']['tenant_verified'] is False
    assert not constructions and supplied == before


@pytest.mark.parametrize('requirements', [[], [azure.package_source.KIND]])
def test_empty_ungranted_selection_cannot_expand_into_dependency_reads(requirements, monkeypatch):
    from peaso.collectors import azure_disclosure_native
    monkeypatch.setattr(azure_disclosure_native, 'required_types', lambda options: {'subscription', 'app_service'})
    def forbidden(*a, **k): raise AssertionError('No dependency or credential IO')
    monkeypatch.setattr(azure, 'AzureTransportExposure', forbidden)
    supplied = {}
    value = azure.collect({'auth': {}, 'scopes': [SCOPE], 'options': supplied}, requirements=requirements)
    assert value['metadata']['calls'] == 0 and value['collections'] == [] and supplied == {}


@pytest.mark.parametrize('denied', [False, True])
def test_active_selection_retains_one_read_and_exact_owner_authority(denied):
    class Transport:
        tenant = verified_tenant = TENANT
        def __init__(self): self.calls = []
        def request(self, url, **kwargs):
            self.calls.append((url, kwargs))
            assert url == azure.ARM + SCOPE + '?api-version=2022-12-01'
            if denied: raise ValueError('deliberate denial')
            return {'id': SCOPE, 'subscriptionId': SCOPE.rsplit('/', 1)[-1], 'tenantId': TENANT}
    transport = Transport(); supplied = options(); before = copy.deepcopy(supplied)
    value = azure.collect({'auth': {}, 'scopes': [SCOPE], 'options': supplied}, requirements=['subscription'], transport=transport)
    assert len(transport.calls) == value['metadata']['calls'] == 1
    assert value['metadata']['compliance_policy'] == owner() and supplied == before
    rows = [row for row in value['collections'] if row['type'] == 'subscription']
    assert len(rows) == 1 and rows[0]['status'] == ('malformed' if denied else 'collected')


@pytest.mark.parametrize('mutation', ['identity', 'code', 'defaults', 'kwdefaults', 'globals', 'snapshot'])
def test_collect_code_defaults_global_and_identity_tamper_rejected(mutation, monkeypatch):
    bridge.verify_metadata_only(ROOT)
    function = azure.collect
    if mutation in ('identity', 'globals'):
        namespace = dict(vars(azure)) if mutation == 'globals' else vars(azure)
        replacement = types.FunctionType(function.__code__, namespace, function.__name__, function.__defaults__)
        replacement.__kwdefaults__ = function.__kwdefaults__
        monkeypatch.setattr(azure, 'collect', replacement)
        if mutation == 'globals': monkeypatch.setattr(bridge, '_METADATA_COLLECT', replacement)
    elif mutation == 'snapshot': monkeypatch.setattr(bridge, '_METADATA_COLLECT', lambda *a: None)
    elif mutation == 'code': monkeypatch.setattr(function, '__code__', function.__code__.replace(co_consts=function.__code__.co_consts + ('changed',)))
    elif mutation == 'defaults': monkeypatch.setattr(function, '__defaults__', ('changed',))
    else: monkeypatch.setattr(function, '__kwdefaults__', {'transport': 'changed'})
    with pytest.raises(RuntimeError): bridge.verify_metadata_only(ROOT)


