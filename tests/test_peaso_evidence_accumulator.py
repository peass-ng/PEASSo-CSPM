"""Ordered evidence stays complete while small principal cards stay inexpensive."""
import gc
import json
from unittest.mock import patch
import weakref

import pytest

from tests.synthetic.benchmark_peaso_iam_action_profiles import run_stage
from tests.synthetic.benchmark_peaso_trust_domains import gcp_snapshot
from peaso.analysis import evidence_accumulator as indexed
from peaso.principal_exposure import project
from peaso.snapshot import digest, resources, seal, validate


class LiteralEvidence:
    def append(self, rows, item, kind):
        if item not in rows:
            rows.append(item)


def evidence(kind, value, condition=False):
    if kind == 'scope':
        return value
    if kind == 'review':
        return {'resource_id': value, 'scope': 'home', 'grant_source_id': 'source', 'grant_count': 1,
            'grants': [{'native_grant': {'Condition': condition}}], 'via_group': 'group' if condition else None}
    return {'kind': 'internet_workload', 'state': 'declared', 'resource_id': value, 'scope': 'home',
        'endpoint_resource': 'endpoint', 'caller': 'caller', 'native': {'Condition': condition}}


@pytest.mark.parametrize('kind', ['scope', 'review', 'signal'])
@pytest.mark.parametrize('limit,sequences', [(200000,8192), (1,8192), (0,8192), (200000,0)])
def test_exact_equality_order_aliases_and_fallbacks(kind, limit, sequences):
    with patch.object(indexed, 'MAX_KEYS', limit), patch.object(indexed, 'MAX_SEQUENCES', sequences):
        accumulator=indexed.EvidenceAccumulator()
    actual,expected=[],[]
    values=[evidence(kind,str(i)) for i in range(24)]
    values += [evidence(kind,'one'),evidence(kind,'one',True),evidence(kind,None),
        evidence(kind,['unhashable']),evidence(kind,'1'),evidence(kind,'1',True)]*3
    for item in values:
        if item not in expected:
            expected.append(item)
        accumulator.append(actual,item,kind)
        assert actual==expected
        assert all(left is right for left,right in zip(actual,expected))
    assert accumulator.remaining>=0 and len(accumulator.indexes)<=sequences


def test_many_small_principal_cards_do_not_consume_index_admission():
    accumulator=indexed.EvidenceAccumulator()
    lists=[[] for _ in range(1000)]
    for rows in lists:
        for _ in range(3):
            accumulator.append(rows,'home','scope')
    assert all(rows==['home'] for rows in lists)
    assert accumulator.remaining==indexed.MAX_KEYS
    assert not accumulator.indexes


def test_preexisting_lists_and_completed_owners_do_not_form_gc_cycles():
    enabled=gc.isenabled()
    gc.disable()
    try:
        accumulator=indexed.EvidenceAccumulator()
        rows=[str(i) for i in range(20)]
        accumulator.append(rows,'19','scope')
        accumulator.append(rows,'20','scope')
        assert rows==[str(i) for i in range(21)]
        reference=weakref.ref(accumulator)
        del accumulator
        assert reference() is None
    finally:
        if enabled:
            gc.enable()


def test_complete_shared_identity_iam_stage_matches_literal_evidence():
    snapshot=gcp_snapshot(30,16)
    inventory,before=resources(snapshot),digest(snapshot)
    with patch.object(indexed,'EvidenceAccumulator',LiteralEvidence):
        expected=run_stage(snapshot,inventory)
    actual=run_stage(snapshot,inventory)
    assert json.dumps(actual)==json.dumps(expected)
    assert digest(snapshot)==before
    assert all(len(card['scopes'])==30 for card in actual['principals'].values())


def test_shared_runtime_role_keeps_every_recorded_workload_signal():
    from tests.synthetic.benchmark_peaso_cloud_workloads import synthetic_snapshot
    snapshot=synthetic_snapshot('aws',20)
    for collection in snapshot['collections']:
        if collection['type']=='ecs_task_definition':
            for definition in collection['items']:
                definition['taskRoleArn']='arn:aws:iam::111122223333:role/shared-runtime'
    snapshot=validate(seal(snapshot))
    inventory=resources(snapshot)
    with patch.object(indexed,'EvidenceAccumulator',LiteralEvidence):
        expected=project(snapshot,inventory)
    actual=project(snapshot,inventory)
    assert actual==expected and len(actual)==1
    assert len(next(iter(actual.values()))['exposures'])==20
