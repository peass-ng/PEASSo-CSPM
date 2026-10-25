"""Native routing survives content redaction; no payload exemption or cloud IO."""
import copy
from types import SimpleNamespace
import pytest
from peaso.auth.secrets import Redactor
from peaso.snapshot import make_snapshot, seal, validate
from peaso.snapshot_public_identity import public_snapshot_adapter


def privacy(values):
    def callback(snapshot):
        redactor = Redactor(values)
        def keys(value):
            if isinstance(value, dict):
                return {redactor(str(k)): keys(v) for k, v in value.items()}
            if isinstance(value, list):
                return [keys(v) for v in value]
            return value
        return seal(keys(redactor(snapshot)))
    return callback


@pytest.mark.parametrize('provider,kind,scope', [
    ('aws', 'iam_password_policy', '123456789012/global'),
    ('gcp', 'bucket', 'projects/example-project'),
    ('azure', 'role_assignment', '/subscriptions/11111111-1111-1111-1111-111111111111'),
    ('k8s', 'configmap_metadata', 'production'),
])
def test_registered_identity_preserved_but_payload_service_and_error_redacted(provider, kind, scope):
    # Public synthetic values intentionally overlap routing names.
    values = [kind, scope, 'confidential-payload', 'provider-service', 'specific-error']
    raw = make_snapshot(provider, [scope], [{'type': kind, 'scope': scope,
        'service': 'provider-service', 'status': 'partial',
        'items': [{'value_text': 'confidential-payload', 'type': kind, 'scope': scope}],
        'error': {'code': 'specific-error', 'message': 'confidential-payload'}}])
    before = copy.deepcopy(raw)
    wrapped = public_snapshot_adapter(privacy(values), provider=provider, trusted_scopes=[scope])
    public = validate(wrapped(raw))
    assert raw == before
    assert public['scopes'] == [scope]
    row = public['collections'][0]
    assert (row['type'], row['scope']) == (kind, scope)
    assert row['status'] == 'partial'
    assert row['service'] == '[REDACTED]'
    assert row['items'] == [{'value_text': '[REDACTED]', 'type': '[REDACTED]', 'scope': '[REDACTED]'}]
    assert row['error'] == {'code': '[REDACTED]', 'message': '[REDACTED]'}


def test_late_detected_value_replay_retains_single_canonical_envelope(monkeypatch):
    from peaso import engine
    from peaso.incremental import CheckpointSession
    selected = SimpleNamespace(id='test.password', kind='iam_password_policy', category='hardening', dependencies=())
    monkeypatch.setattr(engine, '_selection', lambda *a, **kw: (['hardening'], [selected]))
    monkeypatch.setattr(engine, '_analysis_selection', lambda *a, **kw: [])
    monkeypatch.setattr(engine, '_privesc_selected', lambda *a, **kw: None)
    monkeypatch.setattr(engine, 'plan_collection', lambda *a, **kw: ['iam_password_policy'])
    values = []
    wrapper = public_snapshot_adapter(privacy(values), provider='aws')
    durable = []
    session = CheckpointSession({'connector': {'provider': 'aws', 'scopes': ['123456789012/us-east-1']},
        'categories': ['hardening'], 'checks': []},
        lambda snapshot, report, sequence: durable.append(copy.deepcopy(snapshot)),
        wrapper, batch_size=1, interval=10000, batch_interval=10000)
    monkeypatch.setattr(session, '_maybe_publish', lambda **kw: None)
    row = {'type': 'iam_password_policy', 'scope': '123456789012/global', 'service': 'iam',
           'status': 'partial', 'items': [{'PasswordPolicy': {'MinimumPasswordLength': 12}, 'note': 'password'}],
           'error': {'code': 'limited_context'}}
    try:
        session.on_collection(copy.deepcopy(row))
        values.append('password')
        session.on_collection(copy.deepcopy(row))
        session.finish_collection()
        assert len(session.collections) == 1
        assert next(iter(session.collections)) == ('iam_password_policy', '123456789012/global')
        cumulative = validate(wrapper(session._snapshot(list(session.collections.values()))))
        assert len(cumulative['collections']) == 1
        result = cumulative['collections'][0]
        assert result['type'] == row['type'] and result['scope'] == row['scope']
        assert result['items'][0]['note'] == '[REDACTED]'
        assert result['items'][0]['PasswordPolicy'] == {'MinimumPasswordLength': 12}
        assert result['status'] == 'partial' and result['error'] == row['error']
        assert all(len(s['collections']) == 1 for s in durable)
    finally:
        session.close()


def test_two_distinct_native_kinds_never_collapse():
    scope = '123456789012/global'
    raw = make_snapshot('aws', [scope], [
        {'type': kind, 'scope': scope, 'status': 'collected', 'items': [{'id': kind}]}
        for kind in ['iam_customer_policy', 'iam_managed_policy']])
    public = validate(public_snapshot_adapter(privacy(['customer', 'managed']), provider='aws')(raw))
    assert [c['type'] for c in public['collections']] == ['iam_customer_policy', 'iam_managed_policy']
    assert [c['items'][0]['id'] for c in public['collections']] == ['iam_[REDACTED]_policy'] * 2


def test_arbitrary_unregistered_type_is_not_exempted():
    raw = make_snapshot('aws', ['123456789012/global'], [
        {'type': 'sensitive-user-chosen-value', 'scope': '123456789012/global', 'status': 'empty', 'items': []}])
    with pytest.raises(ValueError, match='Unregistered native collection type'):
        public_snapshot_adapter(privacy(['sensitive-user-chosen-value']), provider='aws')(raw)


@pytest.mark.parametrize('scope', ['https://credentials.example.invalid/token', 'secret value', '../secret'])
def test_noncanonical_scope_is_not_exempted(scope):
    raw = make_snapshot('aws', [scope], [{'type': 'iam_password_policy', 'scope': scope, 'status': 'empty', 'items': []}])
    with pytest.raises(ValueError, match='Invalid native snapshot scope'):
        public_snapshot_adapter(privacy([scope]), provider='aws')(raw)


def test_privacy_callback_cardinality_change_fails_closed():
    raw = make_snapshot('aws', ['123456789012/global'], [
        {'type': 'iam_password_policy', 'scope': '123456789012/global', 'status': 'empty', 'items': []}])
    with pytest.raises(ValueError, match='cardinality'):
        public_snapshot_adapter(lambda s: {**s, 'collections': []}, provider='aws')(raw)


def test_no_change_fast_path_returns_callback_result_without_input_mutation():
    raw = make_snapshot('aws', ['123456789012/global'], [
        {'type': 'iam_password_policy', 'scope': '123456789012/global', 'status': 'empty', 'items': []}])
    result = public_snapshot_adapter(lambda s: s, provider='aws')(raw)
    assert result is raw


@pytest.mark.parametrize('scope', ['gke_proj_zone_cluster', 'arn:aws:eks:us-east-1:123456789012:cluster/example', 'selected/context:one'])
def test_exact_validated_kubernetes_contexts_preserved(scope):
    raw = make_snapshot('k8s', [scope], [{'type': 'pod', 'scope': scope, 'status': 'empty', 'items': []}])
    wrapped = public_snapshot_adapter(privacy([scope]), provider='k8s', trusted_scopes=[scope])
    assert validate(wrapped(raw))['collections'][0]['scope'] == scope
    with pytest.raises(ValueError, match='Invalid native snapshot scope'):
        public_snapshot_adapter(privacy([scope]), provider='k8s', trusted_scopes=['other/context'])(raw)


@pytest.mark.parametrize('scope', ['bad\x00context', 'x' * 2049, 'bad\ncontext'])
def test_unbounded_or_control_contexts_rejected(scope):
    with pytest.raises(ValueError, match='Invalid trusted native scope'):
        public_snapshot_adapter(seal, provider='k8s', trusted_scopes=[scope])


def test_provable_canonical_reordering_fails_closed():
    scope = '123456789012/global'
    raw = make_snapshot('aws', [scope], [
        {'type': kind, 'scope': scope, 'status': 'empty', 'items': []}
        for kind in ['iam_customer_policy', 'iam_managed_policy']])
    def reordered(snapshot):
        public = copy.deepcopy(snapshot)
        public['collections'].reverse()
        return seal(public)
    with pytest.raises(ValueError, match='reordered'):
        public_snapshot_adapter(reordered, provider='aws')(raw)


def test_native_gcp_ancestor_and_azure_uppercase_resource_group_scopes():
    for provider, kind, scope, supporting in [
        ('gcp', 'iam_usage_activity', 'projects/example-project', 'folders/123456789'),
        ('azure', 'iam_usage_activity', '/subscriptions/11111111-1111-1111-1111-111111111111',
         '/SUBSCRIPTIONS/11111111-1111-1111-1111-111111111111/RESOURCEGROUPS/Example.Group')]:
        raw = make_snapshot(provider, [scope], [{'type': kind, 'scope': supporting, 'status': 'empty', 'items': []}])
        assert validate(public_snapshot_adapter(seal, provider=provider)(raw))['collections'][0]['scope'] == supporting


def test_reviewed_global_node_clock_and_exact_azure_intermediate_jobs():
    raw = make_snapshot('k8s', ['gke_proj_zone_cluster'], [
        {'type': 'node_clock', 'scope': '*', 'status': 'empty', 'items': []}])
    assert validate(public_snapshot_adapter(seal, provider='k8s', trusted_scopes=['gke_proj_zone_cluster'])(raw))['collections'][0]['scope'] == '*'
    bad = make_snapshot('k8s', ['gke_proj_zone_cluster'], [
        {'type': 'pod', 'scope': '*', 'status': 'empty', 'items': []}])
    with pytest.raises(ValueError, match='outside the snapshot'):
        public_snapshot_adapter(seal, provider='k8s', trusted_scopes=['gke_proj_zone_cluster'])(bad)
    for kind, scope in [
        ('_native_vpn_connection_rg', '/subscriptions/11111111-1111-1111-1111-111111111111/RESOURCEGROUPS/Example'),
        ('_native_access_review_instance', '/tenants/11111111-1111-1111-1111-111111111111/22222222-2222-2222-2222-222222222222'),
        ('_native_access_review_decision', '/tenants/11111111-1111-1111-1111-111111111111/22222222-2222-2222-2222-222222222222')]:
        s = make_snapshot('azure', [scope], [{'type': kind, 'scope': scope, 'status': 'empty', 'items': []}])
        assert validate(public_snapshot_adapter(seal, provider='azure')(s))['collections'][0]['type'] == kind


@pytest.mark.parametrize('scope', [
    '/tenants/11111111-1111-1111-1111-111111111111/servicePrincipals/22222222-2222-2222-2222-222222222222',
    '/tenants/11111111-1111-1111-1111-111111111111/applications/22222222-2222-2222-2222-222222222222',
    '/subscriptions/11111111-1111-1111-1111-111111111111/RESOURCEGROUPS/Example/providers/Microsoft.Network/virtualNetworks/vnet/subnets/subnet',
    '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/Example/providers/Microsoft.Compute/virtualMachines/vm/providers/Microsoft.Insights/diagnosticSettings/setting',
])
def test_native_azure_resource_and_graph_parent_scope_routing(scope):
    raw = make_snapshot('azure', [scope], [{'type': 'diagnostic_setting', 'scope': scope, 'status': 'empty', 'items': []}])
    assert validate(public_snapshot_adapter(privacy([scope]), provider='azure')(raw))['collections'][0]['scope'] == scope


def test_aws_account_root_preserves_bound_regional_and_global_collections():
    account = '123456789012'
    raw = make_snapshot('aws', [account], [
        {'type': 'vpc', 'scope': account + '/us-east-1', 'status': 'empty', 'items': []},
        {'type': 'vpc', 'scope': account + '/us-west-2', 'status': 'empty', 'items': []},
        {'type': 'iam_password_policy', 'scope': account + '/global', 'status': 'empty', 'items': []}])
    public = validate(public_snapshot_adapter(privacy([account]), provider='aws')(raw))
    assert public['scopes'] == [account]
    assert [row['scope'] for row in public['collections']] == [row['scope'] for row in raw['collections']]


def test_aws_region_scope_does_not_authorize_another_region():
    raw = make_snapshot('aws', ['123456789012/us-east-1'], [
        {'type': 'vpc', 'scope': '123456789012/us-west-2', 'status': 'empty', 'items': []}])
    with pytest.raises(ValueError, match='outside the snapshot'):
        public_snapshot_adapter(seal, provider='aws')(raw)


def test_aws_account_root_does_not_authorize_a_foreign_account():
    for scope in ('999999999999/us-east-1', '999999999999/global'):
        raw = make_snapshot('aws', ['123456789012'], [
            {'type': 'vpc', 'scope': scope, 'status': 'empty', 'items': []}])
        with pytest.raises(ValueError, match='outside the snapshot'):
            public_snapshot_adapter(seal, provider='aws')(raw)
