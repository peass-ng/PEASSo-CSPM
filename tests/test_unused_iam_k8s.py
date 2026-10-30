from copy import deepcopy

import pytest

from peaso import unused_iam_k8s as subject

SCOPE = '*'
CLUSTER = 'synthetic-cluster'


def obj(name, namespace=None, **extra):
    meta = {'name': name, 'uid': 'uid-' + name, 'creationTimestamp': '2025-01-01T00:00:00Z'}
    if namespace is not None:
        meta['namespace'] = namespace
    result = {'metadata': meta, 'provenance': {'cluster_id': CLUSTER, 'uid': meta['uid'], 'evidence': 'read-only list'}}
    result.update(extra)
    return result


def capture(**inventory):
    result = {'context': {'provider': 'k8s', 'scope': SCOPE, 'created_at': '2026-10-21T12:00:00Z',
                          'metadata': {'cluster_id': CLUSTER}}, 'collections': {}}
    for kind, rows in inventory.items():
        result[kind] = [{'type': kind, 'scope': SCOPE, 'data': row} for row in rows]
        result['collections'][kind] = [{'type': kind, 'service': 'kubernetes', 'scope': SCOPE,
                                        'status': 'collected' if rows else 'empty', 'items': rows}]
    return result


def binding(name='binding', namespace='app', role='reader', role_kind='Role', subjects=None):
    return obj(name, namespace, roleRef={'apiGroup': subject.GROUP, 'kind': role_kind, 'name': role},
               subjects=subjects if subjects is not None else [{'kind': 'ServiceAccount', 'name': 'worker', 'namespace': 'app'}])


def test_role_with_no_binding_fails_and_named_binding_passes():
    role = obj('reader', 'app')
    assert subject.evaluate_role(role, capture(role=[role], rolebinding=[]))[0] == 'FAIL'
    result = subject.evaluate_role(role, capture(role=[role], rolebinding=[binding()]))
    assert result[0] == 'PASS'
    assert result[1]['consumers'][0]['name'] == 'binding'


def test_same_role_name_in_other_namespace_is_not_a_consumer():
    role = obj('reader', 'app')
    assert subject.evaluate_role(role, capture(role=[role], rolebinding=[binding(namespace='other')]))[0] == 'FAIL'


def test_empty_binding_does_not_make_role_used():
    role = obj('reader', 'app')
    assert subject.evaluate_role(role, capture(role=[role], rolebinding=[binding(subjects=[])]))[0] == 'FAIL'


@pytest.mark.parametrize('kind', ['role', 'rolebinding'])
def test_denied_role_dependency_is_unknown(kind):
    role = obj('reader', 'app')
    index = capture(role=[role], rolebinding=[])
    index['collections'][kind][0]['status'] = 'denied'
    assert subject.evaluate_role(role, index)[0] == 'UNKNOWN'


def test_role_projection_mismatch_is_unknown():
    role = obj('reader', 'app')
    index = capture(role=[role], rolebinding=[])
    index['role'] = []
    assert subject.evaluate_role(role, index)[0] == 'UNKNOWN'


def test_foreign_cluster_is_unknown_even_if_namespace_matches():
    role = obj('reader', 'app')
    role['provenance']['cluster_id'] = 'foreign-cluster'
    assert subject.evaluate_role(role, capture(role=[role], rolebinding=[]))[0] == 'UNKNOWN'


def test_recreated_assessed_role_is_not_same_native_object():
    role = obj('reader', 'app')
    changed = deepcopy(role)
    changed['metadata']['uid'] = 'recreated'
    assert subject.evaluate_role(changed, capture(role=[role], rolebinding=[]))[0] == 'UNKNOWN'


@pytest.mark.parametrize('selector', [
    {'matchLabels': {'aggregate': 'yes'}},
    {'matchExpressions': [{'key': 'aggregate', 'operator': 'In', 'values': ['yes']}]},
    {'matchExpressions': [{'key': 'aggregate', 'operator': 'NotIn', 'values': ['no']}]},
    {'matchExpressions': [{'key': 'aggregate', 'operator': 'Exists'}]},
    {'matchExpressions': [{'key': 'absent', 'operator': 'DoesNotExist'}]},
    {},
])
def test_aggregation_is_a_real_declared_consumer(selector):
    role = obj('reader')
    role['metadata']['labels'] = {'aggregate': 'yes'}
    aggregate = obj('combined', aggregationRule={'clusterRoleSelectors': [selector]})
    index = capture(clusterrole=[role, aggregate], rolebinding=[], clusterrolebinding=[])
    status, evidence = subject.evaluate_clusterrole(role, index)
    assert status == 'PASS'
    assert evidence['consumers'] == [{'kind': 'aggregated_clusterrole', 'name': 'combined'}]


def test_clusterrole_with_no_binding_and_no_aggregation_fails():
    role = obj('reader')
    assert subject.evaluate_clusterrole(role, capture(clusterrole=[role], rolebinding=[], clusterrolebinding=[]))[0] == 'FAIL'


def test_rolebinding_to_clusterrole_counts():
    role = obj('reader')
    assert subject.evaluate_clusterrole(role, capture(clusterrole=[role], rolebinding=[binding(role_kind='ClusterRole')], clusterrolebinding=[]))[0] == 'PASS'


def test_bad_selector_cannot_make_clusterrole_unused():
    role = obj('reader')
    aggregate = obj('combined', aggregationRule={'clusterRoleSelectors': [{'matchExpressions': [{'key': 'x', 'operator': 'Unknown'}]}]})
    assert subject.evaluate_clusterrole(role, capture(clusterrole=[role, aggregate], rolebinding=[], clusterrolebinding=[]))[0] == 'UNKNOWN'


def test_missing_serviceaccount_and_empty_bindings_fail():
    row = binding()
    assert subject.evaluate_rolebinding(row, capture(rolebinding=[row], serviceaccount=[]))[0] == 'FAIL'
    row = binding(subjects=[])
    assert subject.evaluate_rolebinding(row, capture(rolebinding=[row], serviceaccount=[]))[0] == 'FAIL'


def test_existing_serviceaccount_passes():
    row = binding()
    assert subject.evaluate_rolebinding(row, capture(rolebinding=[row], serviceaccount=[obj('worker', 'app')]))[0] == 'PASS'


def test_external_user_is_unknown_and_not_a_missing_serviceaccount():
    row = binding(subjects=[{'kind': 'User', 'apiGroup': subject.GROUP, 'name': 'external-user'}])
    assert subject.evaluate_rolebinding(row, capture(rolebinding=[row], serviceaccount=[]))[0] == 'UNKNOWN'


def test_confirmed_missing_subject_survives_unresolved_external_subject():
    row = binding()
    row['subjects'].append({'kind': 'Group', 'apiGroup': subject.GROUP, 'name': 'external-group'})
    assert subject.evaluate_rolebinding(row, capture(rolebinding=[row], serviceaccount=[]))[0] == 'FAIL'


def test_cluster_binding_requires_explicit_serviceaccount_namespace():
    row = binding(namespace=None, role_kind='ClusterRole', subjects=[{'kind': 'ServiceAccount', 'name': 'worker'}])
    assert subject.evaluate_clusterrolebinding(row, capture(clusterrolebinding=[row], serviceaccount=[]))[0] == 'UNKNOWN'


def test_native_token_metadata_is_joined_to_matching_account():
    account = obj('worker', 'app', secrets=[{'name': 'legacy'}])
    secret = obj('legacy', 'app', type='kubernetes.io/service-account-token')
    secret['metadata'].update(annotations={'kubernetes.io/service-account.name': 'worker',
                                         'kubernetes.io/service-account.uid': account['metadata']['uid']},
                              labels={'kubernetes.io/legacy-token-last-used': '2026-01-01'})
    index = capture(secret_metadata=[secret], serviceaccount=[account])
    assert subject.evaluate_token(secret, index)[0] == 'FAIL'
    secret['metadata']['labels']['kubernetes.io/legacy-token-last-used'] = '2026-10-20'
    assert subject.evaluate_token(secret, index)[0] == 'PASS'
    account['metadata']['uid'] = 'recreated-sa'
    account['provenance']['uid'] = 'recreated-sa'
    assert subject.evaluate_token(secret, index)[0] == 'UNKNOWN'


def test_install_uses_normal_hardening_registration_and_explicit_dependencies():
    class Recorder:
        def __init__(self): self.rows = []
        def register(self, *args, **kwargs):
            def apply(evaluate):
                self.rows.append((args, kwargs, evaluate))
                return evaluate
            return apply
    registry = Recorder()
    subject.install(registry)
    assert len(registry.rows) == 6
    assert all(args[1:3] == ('k8s', 'hardening') and kwargs['dependencies'] for args, kwargs, evaluate in registry.rows)
    assert {evaluate.__name__ for args, kwargs, evaluate in registry.rows} == {
        'evaluate_account', 'evaluate_role', 'evaluate_clusterrole', 'evaluate_rolebinding', 'evaluate_clusterrolebinding', 'evaluate_token'}



def account_capture(account, **extra):
    rows = {kind: [] for kind in subject.WORKLOAD_PATHS}
    rows.update(serviceaccount=[account], rolebinding=[], clusterrolebinding=[], secret_metadata=[])
    rows.update(extra)
    return capture(**rows)


def test_unreferenced_serviceaccount_fails_without_claiming_authentication_inactivity():
    account = obj('worker', 'app')
    status, evidence = subject.evaluate_account(account, account_capture(account))
    assert status == 'FAIL'
    assert 'External clients may still use this identity' in evidence['summary']
    assert 'days_since_last_successful_use' not in evidence


def test_serviceaccount_consumed_by_workload_template_passes():
    account = obj('worker', 'app')
    workload = obj('api', 'app', spec={'template': {'spec': {'serviceAccountName': 'worker'}}})
    assert subject.evaluate_account(account, account_capture(account, deployment=[workload]))[0] == 'PASS'


def test_missing_controller_inventory_is_unknown_not_unreferenced():
    account = obj('worker', 'app')
    index = account_capture(account)
    del index['collections']['cronjob']
    assert subject.evaluate_account(account, index)[0] == 'UNKNOWN'


def test_serviceaccount_group_binding_is_a_declared_consumer():
    account = obj('worker', 'app')
    row = binding(subjects=[{'kind': 'Group', 'apiGroup': subject.GROUP, 'name': 'system:serviceaccounts:app'}])
    assert subject.evaluate_account(account, account_capture(account, rolebinding=[row]))[0] == 'PASS'


def test_workload_identity_annotation_is_not_an_unreferenced_account():
    account = obj('worker', 'app')
    account['metadata']['annotations'] = {'iam.gke.io/gcp-service-account': 'worker@example.invalid'}
    assert subject.evaluate_account(account, account_capture(account))[0] == 'PASS'


def test_malformed_consumer_subject_cannot_turn_role_into_pass():
    role = obj('reader', 'app')
    assert subject.evaluate_role(role, capture(role=[role], rolebinding=[binding(subjects=[{}])]))[0] == 'UNKNOWN'


def test_registered_native_cases_and_hacktricks_membership():
    from peaso.checks import CHECKS
    from peaso.checks.fixtures import CASES
    by_id = {check.id: check for check in CHECKS}
    for ident, kind, title, predicate, dependencies in subject.DECLARATIONS:
        check = by_id[ident]
        assert check.category == 'hardening'
        assert 'HackTricks Cloud Best Practices' in check.frameworks
        case = CASES[ident]
        assert check.evaluate(case['pass'], deepcopy(case['pass_index']))[0] == 'PASS', ident
        assert check.evaluate(case['fail'], deepcopy(case['fail_index']))[0] == 'FAIL', ident
        assert check.evaluate({}, deepcopy(case['index']))[0] == 'UNKNOWN', ident


def test_existing_unused_controls_are_selected_in_hardening_without_changing_identity():
    from peaso.checks import CHECKS
    from peaso.unused_iam_hardening import ROUTED_IDS
    from peaso.checks.native_only import automated_checks
    active = {check.id: check for check in automated_checks(CHECKS)}
    for ident in ROUTED_IDS:
        assert active[ident].category == 'hardening'
        assert 'HackTricks Cloud Best Practices' in active[ident].frameworks


@pytest.mark.parametrize('ident', [row[0] for row in subject.DECLARATIONS])
def test_normal_engine_emits_unused_iam_hardening_finding(ident):
    from peaso.checks.fixtures import CASES
    from peaso.engine import evaluate_snapshot, hydrate_frameworks
    from peaso.snapshot import make_snapshot
    case = CASES[ident]
    index = case['fail_index']
    collections = [deepcopy(row) for rows in index['collections'].values() for row in rows]
    snapshot = make_snapshot('k8s', ['*'], collections,
        created_at=index['context']['created_at'], metadata={'cluster_id': CLUSTER})
    report = hydrate_frameworks(evaluate_snapshot(snapshot, categories=['hardening'], checks=[ident]))
    findings = [row for row in report['findings'] if row['check_id'] == ident]
    assert len(findings) == 1, report
    assert findings[0]['category'] == 'hardening'
    assert findings[0]['status'] == 'FAIL', findings[0]
    hydrated = hydrate_frameworks(report)
    finding = next(row for row in hydrated['findings'] if row['check_id'] == ident)
    assert 'HackTricks Cloud Best Practices' in finding['frameworks']




def test_bounded_formal_mappings_keep_partial_assurance():
    from peaso.checks import CHECKS
    from peaso.checks.catalog import requirement_tags_for
    expected = {
        'k8s.iam.role_has_declared_consumers': '8.2.6.1',
        'k8s.iam.clusterrole_has_declared_consumers': '8.2.6.1',
        'k8s.iam.legacy_serviceaccount_token_recently_used': '8.2.6.2',
    }
    for ident, requirement in expected.items():
        tags = requirement_tags_for(ident)
        tag = next(t for t in tags if t['framework_id'] == 'pci_4.0_kubernetes' and t['requirement_id'] == requirement)
        assert tag['decision'] == 'PARTIAL'
        assert tag['runtime_status'] == 'partial'



def test_explicitly_unavailable_annotations_do_not_make_serviceaccount_unreferenced():
    account = obj('worker', 'app')
    account['metadata']['_coverage'] = {'annotations': {'status': 'denied'}}
    assert subject.evaluate_account(account, account_capture(account))[0] == 'UNKNOWN'


def test_unavailable_subject_projection_is_not_an_empty_binding():
    row = binding(subjects=[])
    row['_coverage'] = {'subjects': {'status': 'partial'}}
    assert subject.evaluate_rolebinding(row, capture(rolebinding=[row], serviceaccount=[]))[0] == 'UNKNOWN'
