"""Scope indexes nominate rows; original ancestry predicates remain authoritative."""
from collections import defaultdict
import json
from unittest.mock import patch

import pytest

from tests.synthetic.benchmark_peaso_cloud_workloads import LinearCloudWorkloads
from peaso.analysis import cloud_workload_index as indexed
from peaso.analysis.common import as_list
from peaso.principal_exposure import project
from peaso.snapshot import digest, make_snapshot, resources


def outcome(function):
    try:
        return 'value',function()
    except (KeyError,TypeError,AttributeError) as error:
        return 'error',type(error)


@pytest.mark.parametrize('scope', ['projects/home','folders/one','organizations/one','missing',None,[],{}])
@pytest.mark.parametrize('inherited', [False,True])
def test_scope_ancestry_duplicates_and_malformed_facts_match_literal(scope,inherited):
    rows=[{'scope':'projects/home','data':{'ancestors':['folders/one','organizations/one']}},
        {'scope':'projects/foreign','data':{'ancestors':['folders/one','folders/one']}},
        {'scope':'projects/unrelated','data':{'ancestors':[['nested'],{}]}},
        {'scope':'projects/bad','data':None}, {'scope':None,'data':{}},
        {'scope':[],'data':{'ancestors':None}}]
    rows.append(rows[0])
    owner=indexed.CloudWorkloadIndex(defaultdict(list,service_account=rows))
    keys=[('scope',scope)]+([('ancestor',scope)] if inherited else [])
    def matches(source):
        return [row for row in source if row['scope']==scope
            or inherited and scope in as_list(row['data'].get('ancestors'))]
    assert outcome(lambda:matches(owner.candidates('service_account','gcp_account_scope',keys)))==outcome(lambda:matches(rows))


def test_scope_index_capacity_falls_back_to_every_recorded_account():
    rows=[{'scope':f'projects/{i}','data':{'ancestors':['organizations/one']}} for i in range(100)]
    with patch.object(indexed,'MAX_KEYS',2):
        owner=indexed.CloudWorkloadIndex(defaultdict(list,service_account=rows))
    assert owner.candidates('service_account','gcp_account_scope',[('scope','projects/99')]) is rows
    assert owner.candidates('service_account','gcp_account_scope',[('ancestor','organizations/one')]) is rows
    assert owner.budget==[0]


def hierarchy_snapshot():
    cols = []
    for i in range(3):
        scope = f'projects/p-{i}'
        cols.append({'type': 'service_account', 'scope': scope, 'status': 'collected', 'items': [
            {'name': scope + f'/serviceAccounts/workload-{j}', 'email': f'workload-{j}@p-{i}.iam.gserviceaccount.com',
             'disabled': j == 1, 'ancestors': ['folders/one', 'organizations/one', 'folders/one'] if i != 2 else []}
            for j in range(2)]})
        cols.append({'type': 'iam_policy', 'scope': scope, 'status': 'collected', 'items': [{'name': scope,
            'bindings': [{'role': role, 'members': ['allUsers', 'allAuthenticatedUsers', 'user:external@foreign.invalid'],
                         **({'condition': {'expression': 'request.time < timestamp("2999-01-01T00:00:00Z")'}}
                            if role.endswith('User') else {})}
                for role in ('roles/iam.serviceAccountTokenCreator', 'roles/iam.serviceAccountUser')]}]})
    for kind, scope in (('folder', 'folders/one'), ('organization', 'organizations/one'), ('folder', 'folders/unrelated')):
        cols.append({'type': kind, 'scope': scope, 'status': 'collected', 'items': [{'name': scope,
            'iamPolicy': {'bindings': [{'role': 'roles/iam.workloadIdentityUser',
                'members': ['principal://iam.googleapis.com/projects/42/locations/global/workloadIdentityPools/p/subject/s']}]}}]})
    # Exact SA policy must not broaden to other accounts in the project.
    cols[0]['items'][0]['iamPolicy'] = {'bindings': [{'role': 'roles/iam.serviceAccountTokenCreator',
        'members': ['user:direct@foreign.invalid']}]}
    return make_snapshot('gcp', [c['scope'] for c in cols], cols)



def test_complete_hierarchy_projection_keeps_conditions_direct_policies_and_order():
    snapshot=hierarchy_snapshot()
    inventory,before=resources(snapshot),digest(snapshot)
    with patch.object(indexed,'CloudWorkloadIndex',LinearCloudWorkloads):
        expected=project(snapshot,inventory)
    actual=project(snapshot,inventory)
    assert json.dumps(actual)==json.dumps(expected)
    assert digest(snapshot)==before
    for card in actual.values():
        assert not any(signal['scope']=='folders/unrelated' for signal in card['exposures'])
    direct=[signal for card in actual.values() for signal in card['exposures'] if signal.get('caller')=='user:direct@foreign.invalid']
    assert len(direct)==1
