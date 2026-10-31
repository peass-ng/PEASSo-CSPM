"""Runtime joins retain native evidence, ordering and malformed-data behavior."""
from collections import defaultdict
import copy
import gc
from unittest.mock import patch
import weakref

import pytest

from tests.synthetic.benchmark_peaso_cloud_workloads import LinearCloudWorkloads, synthetic_snapshot
from peaso.analysis import cloud_workload_index as indexed
from peaso.principal_exposure import project
from peaso.snapshot import resources, seal, validate


def outcome(function):
    try:
        return 'value', function()
    except (KeyError, TypeError, AttributeError) as error:
        return 'error', type(error)


@pytest.mark.parametrize('lower,wrapper', [(False, False), (True, False), (False, True)])
@pytest.mark.parametrize('query', ['match', 'MATCH', '', None, 0, [], {'id': 'match'}])
def test_candidates_preserve_literal_scalar_join_and_first_match(lower, wrapper, query):
    rows = [{'id': value, 'data': {'id': value}} for value in ('before', 'MATCH', None, '', 'match', [], {'id': 'match'})]
    rows += [{'id': 'malformed', 'data': None}, rows[4], {}]
    owner = indexed.CloudWorkloadIndex(defaultdict(list, vm=rows))

    def predicate(row):
        if wrapper:
            return row['id'] == query
        if lower:
            return str(row['data'].get('id', '')).lower() == query.lower()
        return row['data'].get('id') == query

    for first in (False, True):
        def match(source):
            matches = (row for row in source if predicate(row))
            return next(matches, None) if first else list(matches)
        assert outcome(lambda: match(owner.candidates('vm', 'id', [query], lower=lower, wrapper=wrapper))) == outcome(lambda: match(rows))


@pytest.mark.parametrize('eni', ['match', 'absent', None, [], {}])
def test_task_eni_candidates_preserve_short_circuits_and_malformed_attachments(eni):
    rows = [{'data': {'lastStatus': 'STOPPED', 'attachments': [None]}},
            {'data': {'lastStatus': 'RUNNING', 'attachments': [{'details': [
                {'name': 'networkInterfaceId', 'value': 'match'}, None]}]}},
            {'data': {'lastStatus': 'RUNNING', 'attachments': [None]}}]
    owner = indexed.CloudWorkloadIndex(defaultdict(list, ecs_task=rows))

    def match(source):
        return [task for task in source if eni and task['data'].get('lastStatus') == 'RUNNING' and any(
            d.get('name') == 'networkInterfaceId' and d.get('value') == eni
            for a in task['data'].get('attachments') or [] for d in a.get('details') or [])]

    assert outcome(lambda: match(owner.candidates('ecs_task', 'running_task_eni', [eni]))) == outcome(lambda: match(rows))


def test_order_duplicates_budget_and_reuse():
    rows = [{'data': {'id': value}} for value in ('a', 'b', 'a')]
    rows.append(rows[0])
    owner = indexed.CloudWorkloadIndex(defaultdict(list, vm=rows))
    assert owner.candidates('vm', 'id', ['b', 'a', 'b']) == rows
    assert owner.budget[0] == indexed.MAX_KEYS - 4
    assert owner.candidates('vm', 'id', ['a']) == [rows[0], rows[2], rows[3]]
    assert owner.budget[0] == indexed.MAX_KEYS - 4
    with patch.object(indexed, 'MAX_KEYS', 2):
        limited = indexed.CloudWorkloadIndex(defaultdict(list, vm=rows))
    assert limited.candidates('vm', 'id', ['a']) is rows
    assert limited.candidates('vm', 'id', ['absent']) is rows
    assert limited.budget == [0]


def test_large_attachment_relation_falls_back_without_dropping_matches():
    row = {'data': {'lastStatus': 'RUNNING', 'attachments': [{'details': [
        {'name': 'networkInterfaceId', 'value': f'eni-{i}'} for i in range(100)]}]}}
    with patch.object(indexed, 'MAX_KEYS', 3):
        owner = indexed.CloudWorkloadIndex(defaultdict(list, ecs_task=[row]))
    assert owner.candidates('ecs_task', 'running_task_eni', ['eni-99']) == [row]
    assert owner.budget == [0]
    assert owner.indexes[('ecs_task', 'running_task_eni', False, False)] is None


def test_no_owner_cycle_when_analysis_disables_garbage_collection():
    enabled = gc.isenabled()
    gc.disable()
    try:
        owner = indexed.CloudWorkloadIndex(defaultdict(list, vm=[{'data': {'id': 'a'}}]))
        owner.candidates('vm', 'id', ['a'])
        reference = weakref.ref(owner)
        del owner
        assert reference() is None
    finally:
        if enabled:
            gc.enable()


@pytest.mark.parametrize('provider', ['aws', 'azure'])
@pytest.mark.parametrize('mutation', ['none', 'missing_identity', 'missing_link', 'duplicate', 'capacity'])
def test_complete_projection_matches_original_joins(provider, mutation):
    snapshot = synthetic_snapshot(provider, 8)
    collections = {c['type']: c for c in snapshot['collections']}
    if mutation == 'missing_identity':
        if provider == 'aws':
            collections['ecs_task_definition']['items'].pop()
        else:
            collections['managed_identity']['items'].pop()
    elif mutation == 'missing_link':
        if provider == 'aws':
            collections['ecs_task']['items'][-1]['attachments'] = []
        else:
            collections['nic']['items'][-1]['properties']['virtualMachine'] = {}
    elif mutation == 'duplicate':
        kind = 'ecs_task_definition' if provider == 'aws' else 'vm'
        collections[kind]['items'].append(copy.deepcopy(collections[kind]['items'][0]))
    snapshot = validate(seal(snapshot))
    inventory = resources(snapshot)
    before = copy.deepcopy(snapshot)
    with patch.object(indexed, 'CloudWorkloadIndex', LinearCloudWorkloads):
        expected = project(snapshot, inventory)
    with patch.object(indexed, 'MAX_KEYS', 1 if mutation == 'capacity' else indexed.MAX_KEYS):
        actual = project(snapshot, inventory)
    assert actual == expected
    assert snapshot == before
    assert len(actual) >= 7


@pytest.mark.parametrize('provider', ['aws', 'azure'])
def test_whole_privilege_pipeline_preserves_exposure_annotations_and_graph(provider):
    from peaso.privesc import analyze

    snapshot = synthetic_snapshot(provider, 4)
    scope = snapshot['scopes'][0]
    if provider == 'aws':
        facts = {'iam_role': [{'Arn': f'arn:aws:iam::111122223333:role/task-{i}',
            'RoleName': f'task-{i}', 'AssumeRolePolicyDocument': {'Statement': []},
            'RolePolicyList': [{'PolicyName': 'admin', 'PolicyDocument': {'Statement': [
                {'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}}]} for i in range(4)]}
    else:
        definition = scope + '/providers/Microsoft.Authorization/roleDefinitions/owner'
        facts = {'role_definition': [{'id': definition, 'name': 'owner', 'properties': {
                    'roleName': 'Owner', 'permissions': [{'actions': ['*'], 'dataActions': []}]}}],
                 'role_assignment': [{'id': f'{scope}/providers/Microsoft.Authorization/roleAssignments/{i}',
                    'properties': {'principalId': f'identity-{i}', 'roleDefinitionId': definition,
                                   'scope': scope}} for i in range(4)]}
    snapshot['collections'].extend({'type': kind, 'scope': scope, 'status': 'collected', 'items': items}
                                   for kind, items in facts.items())
    snapshot = validate(seal(snapshot))
    before = copy.deepcopy(snapshot)
    with patch.object(indexed, 'CloudWorkloadIndex', LinearCloudWorkloads):
        expected = analyze(snapshot)
    actual = analyze(snapshot)
    expected['stats'].pop('timing_seconds')
    actual['stats'].pop('timing_seconds')
    assert actual == expected
    assert snapshot == before
    assert actual['graph']['nodes']
