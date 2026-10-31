"""Compare broad GCP target evaluation with its previous unpruned implementation."""
import copy
from unittest.mock import patch

import pytest

from tests.synthetic.benchmark_peaso_permission_prefilter import run_stage, synthetic_snapshot
from tests.synthetic.benchmark_peaso_gcp_permissions import ReferenceGcpModel
from peaso.privesc.effective_permissions import AllTargets, Node
from peaso.privesc.effective_permissions.gcp import GcpModel


def snapshot_with_grants(mode):
    snapshot = synthetic_snapshot('gcp', 3)
    cols = snapshot['collections']
    first_resource = next(c['items'][0]['name'] for c in cols if c['type'] == 'service_account')
    for collection in list(cols):
        if collection['type'] == 'project':
            collection['items'][0].update(name='projects/' + str(100 + int(collection['scope'].rsplit('-', 1)[-1])),
                _ancestry=[{'resourceId': {'type': 'folder', 'id': '10'}},
                           {'resourceId': {'type': 'organization', 'id': '20'}}])
        if collection['type'] == 'service_account':
            second = copy.deepcopy(collection['items'][0])
            second['email'] = second['email'].replace('runtime@', 'other@')
            second['name'] = second['name'].replace('runtime@', 'other@')
            collection['items'].append(second)
    root = {'folder': 'folders/10', 'organization': 'organizations/20',
            'resource': first_resource, 'cross_project': 'projects/benchmark-2'}.get(mode, 'projects/benchmark-0')
    binding = {'role': 'roles/iam.serviceAccountAdmin', 'members': ['user:user-0@benchmark.invalid']}
    if mode == 'public':
        binding['members'] = ['allAuthenticatedUsers']
    if mode.startswith('condition'):
        binding['condition'] = {'expression': {
            'condition_true': 'resource.name.startsWith("projects/benchmark-0/")',
            'condition_false': 'resource.name.startsWith("projects/other/")',
            'condition_unknown': 'resource.matchTag("123/env", "prod")',
            'condition_resource': 'resource.name == "' + first_resource + '"',
        }[mode]}
        # Remove the ordinary unconditional grant on that project.
        next(c for c in cols if c['type'] == 'iam_policy')['items'][0]['bindings'] = []
    cols.append({'type': 'iam_policy', 'scope': root, 'status': 'collected',
                 'items': [{'name': root, 'bindings': [binding]}]})
    if mode == 'deny':
        for collection in cols:
            if collection['type'] == 'iam_deny_policy' and collection['scope'] == 'projects/benchmark-0':
                collection.update(status='collected', items=[{'name': collection['scope'] + '/denyPolicies/block',
                    'rules': [{'denyRule': {'deniedPermissions': ['iam.googleapis.com/serviceAccounts.setIamPolicy'],
                        'deniedPrincipals': ['user:user-0@benchmark.invalid']}}]}])
    if mode == 'missing_deny':
        snapshot['collections'] = [c for c in cols if c['type'] != 'iam_deny_policy']
    return snapshot


def fingerprint(result, candidates):
    if isinstance(result, AllTargets):
        result = {target.id: result.grant for target in candidates}
    return {key: (grant.confidence, grant.refs, grant.conditions, grant.permission_refs)
            for key, grant in result.items()}


@pytest.mark.parametrize('mode', ['project', 'folder', 'organization', 'resource', 'cross_project', 'public',
    'condition_true', 'condition_false', 'condition_unknown', 'condition_resource', 'deny', 'missing_deny'])
@pytest.mark.parametrize('template,localized', [('{target.email}', False), ('{target.id}', False),
    ('{target.resource}', False), (None, True), ('{source.scope}', False), (None, False)])
def test_all_sources_and_targets_match_previous_implementation(mode, template, localized):
    snapshot = snapshot_with_grants(mode)
    before, after = ReferenceGcpModel(snapshot), GcpModel(snapshot)
    targets = list(after.sas.values())
    # A missing target field must preserve ANY and its unknown-confidence floor.
    targets.append(Node('missing-resource', 'gcp_scope_owner', 'gcp', 'projects/missing', 'missing'))
    for principal in after.sources():
        for permission in ('iam.serviceAccounts.setIamPolicy', 'iam.serviceAccounts.get', 'storage.objects.get'):
            req = {'permission': permission}
            expected = before.check_targets(before.principals[principal.id], req, template, targets, localized)
            actual = after.check_targets(principal, req, template, targets, localized)
            assert fingerprint(actual, targets) == fingerprint(expected, targets)
            assert isinstance(actual, AllTargets) == isinstance(expected, AllTargets)


@pytest.mark.parametrize('include_unknown', [False, True])
@pytest.mark.parametrize('mode', ['folder', 'resource', 'cross_project', 'condition_resource', 'deny', 'missing_deny'])
def test_whole_native_stage_matches_previous_implementation(mode, include_unknown):
    snapshot = snapshot_with_grants(mode)
    original = copy.deepcopy(snapshot)
    expected = run_stage(snapshot, model_class=ReferenceGcpModel, include_unknown=include_unknown)
    assert run_stage(snapshot, include_unknown=include_unknown) == expected
    assert snapshot == original


def test_shared_resolution_avoids_unrelated_permission_checks():
    model = GcpModel(synthetic_snapshot('gcp', 30))
    targets = list(model.sas.values())
    users = [p for p in model.sources() if p.kind == 'gcp_user']
    with patch.object(model, 'resolve', wraps=model.resolve) as resolve, \
         patch.object(model, 'cached_check', wraps=model.cached_check) as check:
        for permission in ('iam.serviceAccounts.setIamPolicy', 'iam.serviceAccounts.get'):
            for user in users:
                result = model.check_targets(user, {'permission': permission}, '{target.email}', targets)
                assert not isinstance(result, AllTargets) and len(result) == 1
        assert resolve.call_count == len(targets)
        assert check.call_count == 2 * len(users)


def test_changed_target_attributes_do_not_reuse_old_resolution():
    model = GcpModel(synthetic_snapshot('gcp', 2))
    user = model.principals['user:user-0@benchmark.invalid']
    target, other = list(model.sas.values())
    req = {'permission': 'iam.serviceAccounts.setIamPolicy'}
    assert isinstance(model.check_targets(user, req, '{target.email}', [target]), AllTargets)
    target.attrs['resource'] = other.attrs['resource']
    assert model.check_targets(user, req, '{target.email}', [target]) == {}
