"""Equivalent-finding reviewer groups, balanced batches and hosted AI budgets."""
import base64
import json
import time
from types import SimpleNamespace

import pytest

from peaso.ai import auth, pipeline
from peaso.ai.review_groups import chunks, expand, group_key, plan, publish_reserve, stage_limit
from peaso.server.config import Settings
from peaso.storage import FileArtifacts, SQLiteStore


def finding(ident, resource, evidence, *, check='k8s.pod.privileged', scope='*', category='hardening'):
    return dict(id=ident, check_id=check, category=category, resource_id=resource, resource_name=resource,
                scope=scope, status='FAIL', provider='k8s', evidence=evidence)


def review(ident, verdict='FAIL'):
    return dict(finding_id=ident, verdict=verdict,
                reason='' if verdict == 'FAIL' else 'Captured configuration shows the control is not applicable here.')


def replicas(count, **kwargs):
    # Same setting on every replica; the evidence names each replica itself.
    return [finding(f'h{i}', f'web-{i:03}', {'pod': f'web-{i:03}', 'privileged': True}, **kwargs)
            for i in range(count)]


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    monkeypatch.setattr('peaso.ai.providers.validate_access', lambda access: access)
    monkeypatch.setattr('peaso.ai.providers.validate_before_launch', lambda access: access)
    monkeypatch.setattr(pipeline.isolation, 'launcher', lambda: '/mock/isolation-launcher')
    monkeypatch.setattr(pipeline.isolation, 'available', lambda: True)
    monkeypatch.setattr(pipeline.isolation, 'wrap_command', lambda argv, workspace: argv)
    monkeypatch.setattr(pipeline, 'available_memory', lambda: 4 * 1024**3)
    monkeypatch.setenv('PEASO_AI_MAX_CONCURRENCY', '2')


def test_groups_need_identical_evidence_check_scope_and_type():
    rows = replicas(3)
    rows.append(finding('other-check', 'web-900', {'pod': 'web-900', 'privileged': True}, check='k8s.pod.host_pid'))
    rows.append(finding('other-scope', 'web-901', {'pod': 'web-901', 'privileged': True}, scope='ns/prod'))
    rows.append(finding('other-value', 'web-902', {'pod': 'web-902', 'privileged': 'partial'}))
    rows.append(dict(finding('other-type', 'web-903', {'pod': 'web-903', 'privileged': True}),
                     resource_type='daemonset'))
    rows.append(finding('foreign-name', 'web-904', {'pod': 'web-000', 'privileged': True}))
    representatives, members = plan(rows)
    assert [row['id'] for row in representatives] == ['h0', 'other-check', 'other-scope', 'other-value',
                                                      'other-type', 'foreign-name']
    assert {key: [row['id'] for row in value] for key, value in members.items()} == {'h0': ['h1', 'h2']}


@pytest.mark.parametrize('evidence', [None, {}, [], ''])
def test_findings_without_evidence_are_never_grouped(evidence):
    rows = [finding(f'h{i}', f'r{i}', evidence) for i in range(3)]
    assert group_key(rows[0]) is None
    representatives, members = plan(rows)
    assert representatives == rows and members == {}


def test_batches_are_balanced_and_never_exceed_forty():
    assert [len(part) for part in chunks(range(41))] == [21, 20]
    assert [len(part) for part in chunks(range(80))] == [40, 40]
    assert [len(part) for part in chunks(range(307))] == [39, 39, 39, 38, 38, 38, 38, 38]
    assert sum(chunks(range(307)), []) == list(range(307)) and chunks([]) == []


def test_only_confirmed_failures_are_copied_to_group_members():
    members = {'a': [{'id': 'a1'}, {'id': 'a2'}], 'b': [{'id': 'b1'}]}
    rows, recheck = expand([review('a'), review('b', 'NOT_APPLICABLE'), review('c', 'PASS')], members)
    assert rows == [review('a'), review('a1'), review('a2'), review('b', 'NOT_APPLICABLE'), review('c', 'PASS')]
    assert recheck == [{'id': 'b1'}]


def test_equivalent_replicas_cost_one_reviewer_item_and_keep_every_result(monkeypatch):
    rows = replicas(120)
    calls = []
    def invoke(stage, platform, entries, token, findings, reviews, timeout):
        calls.append([row['id'] for row in findings])
        return {'items': [review(row['id']) for row in findings]}
    monkeypatch.setattr(pipeline, 'invoke', invoke)
    output, failed = pipeline.review_batches({'provider': 'k8s'}, {}, [], 'token', rows, [],
                                             time.monotonic() + 60)
    assert calls == [['h0']] and failed is False
    assert output['hardening'] == [review(row['id']) for row in rows]


def test_unconfirmed_representative_sends_every_member_to_its_own_review(monkeypatch):
    rows = replicas(45)
    calls = []
    def invoke(stage, platform, entries, token, findings, reviews, timeout):
        calls.append([row['id'] for row in findings])
        # The representative and one other replica are not applicable.
        return {'items': [review(row['id'], 'NOT_APPLICABLE' if row['id'] in ('h0', 'h7') else 'FAIL')
                          for row in findings]}
    monkeypatch.setattr(pipeline, 'invoke', invoke)
    output, failed = pipeline.review_batches({'provider': 'k8s'}, {}, [], 'token', rows, [],
                                             time.monotonic() + 60)
    assert calls[0] == ['h0'] and failed is False
    assert sorted(len(call) for call in calls[1:]) == [22, 22]
    assert sorted(ident for call in calls[1:] for ident in call) == sorted(f'h{i}' for i in range(1, 45))
    assert [row['finding_id'] for row in output['hardening']] == [row['id'] for row in rows]
    assert {row['finding_id'] for row in output['hardening'] if row['verdict'] != 'FAIL'} == {'h0', 'h7'}


def test_failed_representative_marks_its_whole_group_unknown(monkeypatch):
    rows = replicas(5)
    solo = [finding('solo', 'db', {'pod': 'db', 'host_network': True}, check='k8s.pod.host_network',
                    category='exposure')]
    def invoke(stage, platform, entries, token, findings, reviews, timeout):
        if findings[0]['id'] == 'h0':
            raise RuntimeError('agent_failed')
        return {'items': [review(row['id']) for row in findings]}
    monkeypatch.setattr(pipeline, 'invoke', invoke)
    output, failed = pipeline.review_batches({'provider': 'k8s'}, {}, [], 'token', rows, solo,
                                             time.monotonic() + 60)
    assert failed is True
    assert [row['verdict'] for row in output['hardening']] == ['UNKNOWN'] * 5
    assert output['exposure'] == [review('solo')]


def test_members_left_by_the_deadline_stay_unknown(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(pipeline.time, 'monotonic', lambda: clock[0])
    rows = replicas(3)
    def invoke(stage, platform, entries, token, findings, reviews, timeout):
        clock[0] = 200.0
        return {'items': [review(row['id'], 'PASS') for row in findings]}
    monkeypatch.setattr(pipeline, 'invoke', invoke)
    output, failed = pipeline.review_batches({'provider': 'k8s'}, {}, [], 'token', rows, [], 150)
    assert failed is True
    assert [row['verdict'] for row in output['hardening']] == ['PASS', 'UNKNOWN', 'UNKNOWN']


def test_hosted_budgets_reserve_final_publication_and_allow_long_holistic_stages():
    assert publish_reserve(2400, True) == 300 and publish_reserve(400, True) == 100
    assert publish_reserve(20, True) == 10 and publish_reserve(5000, False) == 10
    assert stage_limit('priorities', True) == 1500 and stage_limit('network', True) == 900
    assert stage_limit('hardening', True) == 480 and stage_limit('exposure', False) == 120
    assert max(stage_limit(stage, True) for stage in ('priorities', 'network', 'hardening')) <= 1800


@pytest.fixture
def environment(tmp_path, monkeypatch):
    settings = Settings(state_dir=tmp_path/'state', identity_dir=tmp_path/'identity')
    store, artifacts = SQLiteStore(settings.state_dir), FileArtifacts(tmp_path/'artifacts')
    claims = {'exp': time.time() + 3600, 'https://api.openai.com/auth': {'chatgpt_account_id': 'test'}}
    value = 'header.' + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=') + '.signature'
    monkeypatch.setattr(pipeline, 'Settings', lambda: settings)
    monkeypatch.setattr('peaso.storage.runtime.stores', lambda _: (store, artifacts))
    monkeypatch.setattr(auth, 'default_token', lambda: value)
    monkeypatch.setattr('peaso.least_privilege.project', lambda *a, **k: {'items': []})
    monkeypatch.setattr('peaso.snapshot.resources', lambda _: [])
    return artifacts


def test_slow_reviews_leave_priorities_the_remaining_budget_and_publication_time(environment, monkeypatch):
    # Regression: Kubernetes priorities had 1500 s of budget left after the
    # reviewers but were cut off by a fixed 600 s per-call ceiling.
    clock = [0.0]
    monkeypatch.setattr(pipeline, 'time', SimpleNamespace(monotonic=lambda: clock[0], time=lambda: 1000.0))
    monkeypatch.setattr(pipeline.isolation, 'remote', lambda: True)
    monkeypatch.setenv('PEASO_AI_TIMEOUT_SECONDS', '3000')
    report = {'provider': 'k8s', 'findings': replicas(1), 'graphs': {}}
    seen = {}
    def reviews(*args, network=None):
        seen['review_end'] = args[-1]
        clock[0] = 1460.0
        return {'hardening': [review('h0')], 'exposure': []}, False
    def invoke(stage, platform, entries, token, findings, reviews, timeout):
        assert stage == 'priorities'
        seen['priorities'] = timeout
        return {'actions': [], 'limitations': []}
    monkeypatch.setattr(pipeline, 'review_batches', reviews)
    monkeypatch.setattr(pipeline, 'invoke', invoke)
    value = pipeline.review_scan(report, {}, {}, tenant='alice', artifacts=environment, deadline=1000.0 + 3600)
    assert value['status'] == 'completed', value
    assert seen['priorities'] == 1500
    # Deadline 3600 s away: 300 s stay reserved for the final publication.
    tight = {}
    clock[0] = 0.0
    def tight_reviews(*args, network=None):
        tight['review_end'] = args[-1]
        return {'hardening': [review('h0')], 'exposure': []}, False
    def tight_invoke(stage, platform, entries, token, findings, reviews, timeout):
        tight['priorities'] = timeout
        return {'actions': [], 'limitations': []}
    monkeypatch.setattr(pipeline, 'review_batches', tight_reviews)
    monkeypatch.setattr(pipeline, 'invoke', tight_invoke)
    value = pipeline.review_scan(report, {}, {}, tenant='alice', artifacts=environment, deadline=1000.0 + 2000)
    assert value['status'] == 'completed', value
    assert tight['priorities'] == 1500 and tight['review_end'] == 1700 - 510
