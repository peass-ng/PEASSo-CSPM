"""Named optional content selection through real planning and Requests binding.

No provider SDK/network calls: collect_live enters aws.collect only as far as its
real Requests selection assignment, then supplies an empty signed snapshot.
"""
from copy import deepcopy
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from peaso import collectors, engine
from peaso.collectors import aws
from peaso.server.validation import validate_connector
from peaso.snapshot import make_snapshot

SCOPE = '123456789012/us-east-1'
CONTENT = {
    'aws.review.codecommit.default_commit_secret_indicators': 'codecommit_repository',
    'aws.review.cloudwatch.sampled_log_secret_indicators': 'log_group',
    'aws.review.lambda_function.package_content_secret_indicators': 'lambda_function',
    'aws.review.lambda_layer_version.package_content_secret_indicators': 'lambda_layer_version',
    'aws.review.ecr_repository.package_content_secret_indicators': 'ecr_repository',
}
IDS = list(CONTENT)
KINDS = frozenset(CONTENT.values())


@pytest.fixture
def boundary(monkeypatch):
    """Preserve engine, plan_collection and aws.collect option validation intact."""
    observations = []
    original = aws.Requests

    class Bound(Exception):
        pass

    class Requests(original):
        def __setattr__(self, name, value):
            super().__setattr__(name, value)
            if name == 'content_secret_scan_kinds':
                observations[-1]['bound_kinds'] = value
                observations[-1]['enabled'] = self.content_secret_scans
                raise Bound

    def collect_live(connector, requirements):
        observations.append({'connector': deepcopy(connector), 'requirements': deepcopy(requirements)})
        try:
            aws.collect(connector, requirements)
        except Bound:
            return make_snapshot('aws', connector['scopes'], [])
        pytest.fail('AWS collection unexpectedly passed the no-cloud boundary')

    monkeypatch.setattr(aws, 'Requests', Requests)
    monkeypatch.setattr(collectors, 'collect_live', collect_live)
    monkeypatch.setattr(aws, '_session', lambda *a, **kw: pytest.fail('No SDK/session calls permitted'))
    return observations


def request(*, enabled=True, options=None, **selection):
    return {'connector': {'provider': 'aws', 'scopes': [SCOPE],
            'options': {'content_secret_scans': enabled, **(options or {})}}, **selection}


@pytest.mark.parametrize('selection', [
    {}, {'checks': []}, {'categories': ['hardening']}, {'frameworks': ['hacktricks']},
    {'categories': ['hardening'], 'frameworks': ['hacktricks']},
])
def test_broad_selection_never_enables_content_kinds_even_when_option_true(boundary, selection):
    req = request(**selection)
    original = deepcopy(req)
    _, selected = engine._selection('aws', req.get('categories'), req.get('checks'), req.get('frameworks'))
    assert set(CONTENT) <= {c.id for c in selected}  # Not a vacuous filter exclusion.
    snapshot = engine.collect_snapshot(req)
    row = boundary[0]
    assert row['connector']['options']['_content_secret_scan_kinds'] == []
    assert row['bound_kinds'] == frozenset()
    assert row['enabled'] is True
    assert KINDS <= set(row['requirements'])
    assert snapshot['metadata']['collection_plan']['requirements'] == row['requirements']
    assert req == original


@pytest.mark.parametrize('named', [[i] for i in IDS] + [[IDS[0], IDS[2]], IDS, [IDS[3], IDS[3]]])
@pytest.mark.parametrize('enabled', [True, False])
def test_named_subset_binds_only_exact_matching_kinds(boundary, named, enabled):
    req = request(enabled=enabled, checks=named)
    engine.collect_snapshot(req)
    row = boundary[0]
    expected = {CONTENT[i] for i in named}
    assert row['connector']['options']['_content_secret_scan_kinds'] == sorted(expected)
    assert row['bound_kinds'] == frozenset(expected)
    assert row['enabled'] is enabled
    assert expected <= set(row['requirements'])
    assert not (KINDS - expected) & set(row['requirements'])


@pytest.mark.parametrize('spoof', [list(KINDS), 'lambda_function', {'lambda_function': True}, None, 123])
@pytest.mark.parametrize('named', [None, [IDS[1]]])
def test_engine_overwrites_untrusted_internal_selection(boundary, spoof, named):
    req = request(options={'_content_secret_scan_kinds': spoof}, **({'checks': named} if named else {}))
    original = deepcopy(req)
    engine.collect_snapshot(req)
    expected = {CONTENT[i] for i in named or []}
    assert boundary[0]['bound_kinds'] == frozenset(expected)
    assert boundary[0]['connector']['options']['_content_secret_scan_kinds'] == sorted(expected)
    assert req == original


def test_other_check_on_same_lambda_kind_does_not_authorize_content(boundary):
    engine.collect_snapshot(request(checks=['aws.review.lambda.configuration_secret_indicators']))
    assert 'lambda_function' in boundary[0]['requirements']
    assert boundary[0]['bound_kinds'] == frozenset()


def test_named_check_excluded_by_category_does_not_authorize_content(boundary):
    engine.collect_snapshot(request(checks=[IDS[2]], categories=['encryption']))
    assert boundary[0]['bound_kinds'] == frozenset()


@pytest.mark.parametrize('value', [None, 0, 1, 'true', 'false', [], {}])
def test_real_collect_rejects_non_boolean_content_flag_before_sdk(boundary, value):
    with pytest.raises(ValueError, match='content_secret_scans must be a boolean'):
        engine.collect_snapshot(request(enabled=value, checks=[IDS[2]]))
    # Engine preflight now rejects before entering the collector boundary.
    assert boundary == []


def test_default_flag_false_even_when_check_explicitly_named(boundary):
    req = request(checks=[IDS[2]])
    del req['connector']['options']['content_secret_scans']
    engine.collect_snapshot(req)
    assert boundary[0]['enabled'] is False
    assert boundary[0]['bound_kinds'] == frozenset({'lambda_function'})


@pytest.mark.parametrize('kind', sorted(KINDS))
@pytest.mark.parametrize('selected', [frozenset(), frozenset({'log_group'}), KINDS])
def test_explicit_wrapper_skips_unselected_without_changing_other_enrichers(kind, selected):
    calls, rows = [], [{'native': 'resource'}]
    def ordinary(requests, session, region, items):
        calls.append('ordinary')
        return [dict(item, ordinary=True) for item in items]
    def content(requests, session, region, items):
        calls.append(kind)
        return [dict(item, optional_content=True) for item in items]
    pipeline = aws._chain(ordinary, aws._explicit_content_enricher(kind, content))
    result = pipeline(SimpleNamespace(content_secret_scan_kinds=selected), None, 'us-east-1', rows)
    assert calls == ['ordinary'] + ([kind] if kind in selected else [])
    assert result == [{'native': 'resource', 'ordinary': True, **({'optional_content': True} if kind in selected else {})}]
    assert rows == [{'native': 'resource'}]


def test_unselected_wrapper_returns_same_native_items_without_optional_call():
    rows = [{'native': 'resource'}]
    def prohibited(*args): pytest.fail('unselected optional enricher must not execute')
    wrapped = aws._explicit_content_enricher('lambda_function', prohibited)
    assert wrapped(SimpleNamespace(content_secret_scan_kinds=frozenset({'log_group'})), None, 'us-east-1', rows) is rows


def _wrappers(function):
    closure = dict(zip(function.__code__.co_freevars, [cell.cell_contents for cell in function.__closure__ or ()]))
    if set(closure) == {'kind', 'function'}:
        yield function, closure
    # 'enricher' is the reviewed inner function of the ECR repository lanes wrapper.
    for name in ('first', 'second', 'enricher'):
        if name in closure:
            yield from _wrappers(closure[name])


@pytest.mark.parametrize('kind', sorted(KINDS))
def test_actual_loaded_optional_enrichers_have_exact_kind_wrapper(kind):
    from peaso.collectors import aws_package_content_indicators as packages, aws_code_log_content_indicators as logs
    expected = {**packages.ENRICHERS, **logs.ENRICHERS}
    wrappers = list(_wrappers(aws.ENRICHERS[kind]))
    assert len(wrappers) == 1
    function, binding = wrappers[0]
    assert binding == {'kind': kind, 'function': expected[kind]}
    rows = [{'native': 'resource'}]
    # Execute the actual loader-installed wrapper, bypassing preceding metadata
    # enrichers only, to prove it does not touch malformed unselected resources.
    assert function(SimpleNamespace(content_secret_scan_kinds=frozenset()), None, 'us-east-1', rows) is rows
    # A selected kind reaches the real content enricher, while its independent
    # default-false gate still prohibits content APIs.
    result = function(SimpleNamespace(content_secret_scan_kinds=frozenset({kind}), content_secret_scans=False),
                      None, 'us-east-1', rows)
    field = 'PackageContentSource' if kind in packages.ENRICHERS else 'ContentSecretIndicators'
    assert field in result[0]
    assert result[0][field]['collection_status'] == 'not_collected'
    assert rows == [{'native': 'resource'}]


@pytest.mark.parametrize('enabled', [True, False])
@pytest.mark.parametrize('auth_mode', ['local', 'cognito'])
def test_hosted_validation_accepts_aws_boolean(enabled, auth_mode):
    auth = {'method': 'assume_role', 'role_arn': 'arn:aws:iam::123456789012:role/reader', 'external_id': 'peaso-synthetic-external'}
    validate_connector('aws', auth, {'content_secret_scans': enabled}, SimpleNamespace(auth_mode=auth_mode),
                       server_external_id=True, scopes=[SCOPE])


@pytest.mark.parametrize('value', [None, 0, 1, 'true', 'false', [], {}])
@pytest.mark.parametrize('auth_mode', ['local', 'cognito'])
def test_hosted_validation_rejects_non_boolean_aws_option(value, auth_mode):
    with pytest.raises(HTTPException) as caught:
        validate_connector('aws', {}, {'content_secret_scans': value}, SimpleNamespace(auth_mode=auth_mode))
    assert caught.value.status_code == 422
    assert caught.value.detail == 'content_secret_scans must be a supported provider boolean option'


@pytest.mark.parametrize('provider', ['local', 'unsupported'])
@pytest.mark.parametrize('enabled', [True, False])
@pytest.mark.parametrize('auth_mode', ['local', 'cognito'])
def test_hosted_validation_rejects_option_on_unsupported_providers(provider, enabled, auth_mode):
    with pytest.raises(HTTPException) as caught:
        validate_connector(provider, {}, {'content_secret_scans': enabled}, SimpleNamespace(auth_mode=auth_mode))
    assert caught.value.status_code == 422
    assert caught.value.detail == 'content_secret_scans must be a supported provider boolean option'


def test_hosted_rejects_spoofed_internal_selection_even_for_valid_aws_flag():
    with pytest.raises(HTTPException) as caught:
        validate_connector('aws', {}, {'content_secret_scans': True, '_content_secret_scan_kinds': list(KINDS)},
                           SimpleNamespace(auth_mode='cognito'))
    assert caught.value.status_code == 422
    assert 'Unsupported hosted connector field' in caught.value.detail
