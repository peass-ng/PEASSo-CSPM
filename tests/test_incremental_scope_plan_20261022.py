"""Private discovery authority, section revisions and scan isolation; no cloud."""
import copy
from concurrent.futures import ThreadPoolExecutor

import pytest

from peaso.collection_events import emit_scope_plan, scope_plan_callback
from peaso.incremental import CheckpointSession
from peaso.snapshot import make_snapshot, seal


A = '123456789012'
B = '999999999999'
SCOPE = A + '/us-east-1'


def session_for_test(monkeypatch, checkpoints, *, scopes=()):
    from peaso import engine
    from types import SimpleNamespace
    native = [SimpleNamespace(id='native', kind='vpc', category='network', dependencies=()),
              SimpleNamespace(id='image', kind='image_vulnerabilities', category='vulnerability', dependencies=())]
    monkeypatch.setattr(engine, '_selection', lambda *args, content_checks=None: (['network', 'vulnerability'], native))
    monkeypatch.setattr(engine, '_analysis_selection', lambda *args: [])
    monkeypatch.setattr(engine, '_privesc_selected', lambda *args: None)
    monkeypatch.setattr(engine, 'plan_collection', lambda *args: ['vpc', 'iam_role', 'image_vulnerabilities'])
    # Exercise the real session and states while keeping the catalog out of the
    # fixture. Evaluation has its own real-native regression below.
    monkeypatch.setattr(engine, 'evaluate_snapshot', lambda snapshot, **kwargs: {
        'findings': [], 'coverage': [], 'stats': {}})
    session = CheckpointSession({'connector': {'provider': 'aws', 'scopes': list(scopes)},
        'categories': ['network', 'vulnerability'], 'checks': ['native', 'image']},
        lambda snapshot, report, sequence: checkpoints.append((copy.deepcopy(snapshot), report, sequence)),
        seal, batch_interval=100, interval=100)
    session.section_dependencies = {'network': {'vpc', 'iam_role'}, 'images': {'image_vulnerabilities'}}
    return session


def settle(session, kind, scope, status='empty'):
    session.on_collection({'type': kind, 'scope': scope, 'status': status, 'items': []})


def test_auto_scope_completion_waits_for_authority_and_every_exact_pair(monkeypatch):
    checkpoints = []
    session = session_for_test(monkeypatch, checkpoints)
    try:
        settle(session, 'vpc', SCOPE)
        settle(session, 'iam_role', A + '/global', 'denied')
        assert session.sections()['network']['status'] == 'running'
        plan = (SCOPE, A + '/eu-west-1', B + '/ap-south-1')
        session.on_scope_plan(plan)
        assert session.sections()['network']['status'] == 'running'
        settle(session, 'vpc', A + '/eu-west-1', 'partial')
        settle(session, 'vpc', B + '/ap-south-1', 'unknown')
        assert session.sections()['network']['status'] == 'running'
        settle(session, 'iam_role', B + '/global', 'denied')
        sections = session.sections()
        assert sections['network']['status'] == 'complete'
        assert sections['network']['expected_collections'] == 5
        assert sections['network']['completed_collections'] == 5
        assert sections['images']['status'] == 'running'
        assert not session.collection_finished
        revision = sections['network']['data_revision']
        settle(session, 'vpc', SCOPE, 'denied')
        revised = session.sections()['network']
        assert revised['status'] == 'complete' and revised['data_revision'] > revision
        assert session.collections[('vpc', SCOPE)]['status'] == 'denied'
        sequence = session.sequence
        session.on_scope_plan(tuple(reversed(plan)))
        assert session.sequence == sequence
        with pytest.raises(ValueError, match='changed'):
            session.on_scope_plan((SCOPE,))
    finally:
        session.close()


def test_restored_facts_do_not_restore_discovery_authority(monkeypatch):
    checkpoints = []
    session = session_for_test(monkeypatch, checkpoints)
    delta = make_snapshot('aws', [SCOPE], [
        {'type': 'vpc', 'scope': SCOPE, 'status': 'empty', 'items': []},
        {'type': 'iam_role', 'scope': A + '/global', 'status': 'denied', 'items': []}],
        metadata={'incremental': {'sequence': 2, 'batch_revisions': [1, 2]},
                  'sections': {'network': {'status': 'complete'}}})
    try:
        session.restore([delta], 2)
        assert session.sections()['network']['status'] == 'running'
        session.on_scope_plan((SCOPE,))
        assert session.sections()['network']['status'] == 'complete'
        assert session.sequence == 3
        assert session.sections()['network']['data_revision'] == 2
        assert checkpoints[0][0]['metadata']['incremental']['data_revision'] == 2
        session.flush()
        assert checkpoints[-1][0]['metadata']['sections']['network']['status'] == 'complete'
    finally:
        session.close()


def test_exact_scope_plan_is_persisted_only_after_native_discovery(monkeypatch):
    checkpoints = []
    session = session_for_test(monkeypatch, checkpoints)
    try:
        settle(session, 'vpc', SCOPE)
        session.sections()
        assert checkpoints and all('scope_plan' not in row[0]['metadata']['incremental']
                                   for row in checkpoints)
        plan = (B + '/ap-south-1', SCOPE)
        session.on_scope_plan(plan)
        assert checkpoints[-1][0]['metadata']['incremental']['scope_plan'] == sorted(plan)
        settle(session, 'vpc', B + '/ap-south-1')
        session.flush()
        assert checkpoints[-1][0]['metadata']['incremental']['scope_plan'] == sorted(plan)
        assert session.scope_plan == tuple(sorted(plan))
    finally:
        session.close()


@pytest.mark.parametrize('plan', [[], (), ('*',), (A,), (A + '/global',), (SCOPE, SCOPE)])
def test_scope_plan_rejects_non_exact_or_mutable_input(monkeypatch, plan):
    session = session_for_test(monkeypatch, [])
    try:
        with pytest.raises(ValueError, match='Invalid native scope plan'):
            session.on_scope_plan(plan)
        assert session.effective_scopes == []
    finally:
        session.close()


def test_scope_callback_is_context_local_restored_and_ignores_connector_options(monkeypatch):
    from peaso import engine, collectors
    plans, nested = [], []
    with scope_plan_callback(plans.append):
        with scope_plan_callback(nested.append):
            emit_scope_plan((SCOPE,))
        emit_scope_plan((B + '/eu-west-1',))
        with ThreadPoolExecutor(1) as pool:
            pool.submit(emit_scope_plan, ('foreign-thread',)).result()
    emit_scope_plan(('outside',))
    assert plans == [(B + '/eu-west-1',)] and nested == [(SCOPE,)]

    def collect(connector, requirements):
        emit_scope_plan((SCOPE,))
        return make_snapshot('aws', [SCOPE], [])
    monkeypatch.setattr(collectors, 'collect_live', collect)
    request = {'connector': {'provider': 'aws', 'scopes': [], 'options': {
        '_scope_plan_callback': nested.append}}, 'categories': ['hardening'],
        'checks': ['aws.s3.default_encryption'], '_scope_plan_callback': plans.append}
    engine.collect_snapshot(request)
    assert plans[-1] == (SCOPE,) and len(nested) == 1
    request.pop('_scope_plan_callback')
    engine.collect_snapshot(request)
    assert len(plans) == 2


def test_auto_scope_denied_native_never_becomes_pass():
    checkpoints = []
    session = CheckpointSession({'connector': {'provider': 'aws', 'scopes': []},
        'categories': ['hardening'], 'checks': ['aws.s3.default_encryption']},
        lambda snapshot, report, sequence: checkpoints.append((snapshot, report)), seal,
        batch_interval=100)
    try:
        session.on_scope_plan((SCOPE,))
        settle(session, 'bucket', A + '/global', 'denied')
        report = session.flush()
        assert session.sections()['hardening']['status'] == 'complete'
        # Keep the existing conservative partial filter: it may suppress a
        # DENIED finding, but neither completion nor discovery can turn it into
        # PASS/EMPTY. The underlying sealed facts retain their native denial.
        assert {row['status'] for row in report['findings']} <= {'UNKNOWN', 'DENIED'}
        assert session.collections[('bucket', A + '/global')]['status'] == 'denied'
        from peaso.engine import evaluate_snapshot
        native = evaluate_snapshot(checkpoints[-1][0], categories=['hardening'],
            checks=['aws.s3.default_encryption'])
        assert native['findings'] and {row['status'] for row in native['findings']} == {'DENIED'}
        assert report['stats']['coverage_complete'] is False
        assert session.collection_finished is False
    finally:
        session.close()
