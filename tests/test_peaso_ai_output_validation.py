"""Bounded same-model output correction within the original deadline."""
import json
from pathlib import Path
import sqlite3
import sys
from types import SimpleNamespace
import pytest
from peaso.ai import deadline, output_validation, runner


def inputs(tmp_path, monkeypatch, outputs, clock=None):
    monkeypatch.setattr(runner, 'validate_runtime', lambda *args: None)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, 'argv', ['runner', 'priorities'])
    monkeypatch.setenv(deadline.ENVIRONMENT_KEY, '520')
    monkeypatch.delenv('PEASO_AI_MODEL_RELAY', raising=False)
    (tmp_path/'codex-auth.json').write_text('{"access_token":"task-capability"}')
    (tmp_path/'credentials.json').write_text('{"entries":[]}')
    with sqlite3.connect(tmp_path/'context.sqlite') as db:
        db.execute('CREATE TABLE records(domain TEXT,id TEXT,detail TEXT)')
        db.execute('INSERT INTO records VALUES(?,?,?)', ('findings', 'assigned', json.dumps({
            'finding': {'id': 'assigned', 'status': 'FAIL', 'category': 'hardening'},
            'review': None})))
    config = SimpleNamespace(agent=SimpleNamespace(max_runtime_minutes=5, max_turns=30,
        primary='OPENAI_BEST_QUALITY', thinking_effort='high'), credentials=SimpleNamespace())
    calls = []
    class Chack:
        def __init__(self, config): self.config = config
        def run(self, *args, **kwargs):
            calls.append({'text': args[1], 'minutes': self.config.agent.max_runtime_minutes,
                          'max_turns': self.config.agent.max_turns,
                          'primary': self.config.agent.primary, 'thinking': self.config.agent.thinking_effort})
            if clock is not None: clock[0] += 150
            return SimpleNamespace(error='', output=json.dumps(outputs[min(len(calls)-1, len(outputs)-1)]))
    monkeypatch.setitem(sys.modules, 'chack_agent', SimpleNamespace(Chack=Chack, load_config=lambda _:config))
    return calls


def review(ident):
    return {'actions': [{'rank': 1, 'title': 'Review native finding',
        'finding_ids': [ident], 'severity': 'high', 'effort': 'medium',
        'rationale': 'The recorded native failure needs a bounded remediation plan.',
        'steps': ['Validate the owner and apply the selected configuration.'],
        'verification': 'Check the resulting native configuration.'}], 'limitations': []}


def test_invalid_reference_is_corrected_against_original_inputs_with_remaining_budget(tmp_path, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(runner, 'time', SimpleNamespace(monotonic=lambda:clock[0]))
    calls = inputs(tmp_path, monkeypatch, [review('invented'), review('assigned')], clock)
    runner.main()
    assert len(calls) == 2 and [v['minutes'] for v in calls] == [9, 7]
    assert 'validation-feedback.json' in calls[1]['text']
    assert json.loads((tmp_path/'result.json').read_text()) == review('assigned')
    assert json.loads((tmp_path/'validation-feedback.json').read_text()) == {'code':'unknown_action_reference'}
    assert (tmp_path/'candidate-output.json').stat().st_mode & 0o777 == 0o600


def test_repeated_invalid_output_is_never_published(tmp_path, monkeypatch, capsys):
    calls = inputs(tmp_path, monkeypatch, [review('invented')])
    assert runner.entrypoint() == 65
    assert len(calls) == 3 and not (tmp_path/'result.json').exists()
    assert capsys.readouterr() == ('', '')


def test_credentials_are_rechecked_before_constructing_a_repair_agent(tmp_path, monkeypatch):
    from peaso.ai.providers import ConfigurationError
    calls = inputs(tmp_path, monkeypatch, [review('invented'), review('assigned')])
    probes = []
    def validate(*args):
        probes.append(True)
        if len(probes) == 2:
            raise ConfigurationError('Credential no longer permits inference.')
    monkeypatch.setattr(runner, 'validate_runtime', validate)
    assert runner.entrypoint() == 78
    assert len(probes) == 2 and len(calls) == 1
    assert not (tmp_path/'result.json').exists()


def test_correction_stops_when_original_deadline_is_spent(tmp_path, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(runner, 'time', SimpleNamespace(monotonic=lambda:clock[0]))
    calls = inputs(tmp_path, monkeypatch, [review('invented')], clock)
    monkeypatch.setenv(deadline.ENVIRONMENT_KEY, '120')
    assert runner.entrypoint() == 124
    assert len(calls) == 1 and not (tmp_path/'result.json').exists()


def test_feedback_excludes_error_bodies_and_validation_inputs():
    assert output_validation.feedback(ValueError('DO_NOT_LOG_SECRET')) == {'code':'invalid_output'}
    from peaso.ai.contracts import Recommendations
    with pytest.raises(ValueError) as error: Recommendations.model_validate({'actions':'DO_NOT_LOG_SECRET','limitations':[]})
    assert 'DO_NOT_LOG_SECRET' not in json.dumps(output_validation.feedback(error.value))


def test_context_capture_accepts_qualified_native_manual_paths_and_rejects_foreign_refs(tmp_path):
    with sqlite3.connect(tmp_path/'context.sqlite') as db:
        db.execute('CREATE TABLE records(domain TEXT,id TEXT,detail TEXT)')
        db.execute('INSERT INTO records VALUES(?,?,?)', ('resources','r1','{}'))
        db.execute('INSERT INTO records VALUES(?,?,?)', ('findings','f1',json.dumps({'finding':{
            'id':'f1','category':'privesc','status':'MANUAL','resource_id':'r1'},'review':None})))
    original = output_validation.context('priorities', tmp_path)
    action = {'rank':1,'title':'Review conditional privilege','finding_ids':['f1'],
        'severity':'high','effort':'medium',
        'rationale':'Declared grants warrant owner review; effective reachability remains conditional.',
        'steps':['Validate required access before scoping the grant.'],'verification':'Read the resulting policy and retained dependencies.'}
    output_validation.validate('priorities', {'actions':[action],'limitations':[]}, original)
    with pytest.raises(ValueError, match='unknown_action_reference'):
        output_validation.validate('priorities', {'actions':[action|{'finding_ids':['foreign']}],'limitations':[]}, original)


def test_priorities_unused_resources_do_not_apply_a_foreign_row_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(output_validation, 'MAX_ROWS', 2)
    with sqlite3.connect(tmp_path/'context.sqlite') as db:
        db.execute('CREATE TABLE records(domain TEXT,id TEXT,detail TEXT)')
        db.executemany('INSERT INTO records VALUES(?,?,?)',
            [('resources', 'r'+str(i), '{}') for i in range(3)])
        db.execute('INSERT INTO records VALUES(?,?,?)', ('findings','f1',json.dumps({'finding':{
            'id':'f1','category':'hardening','status':'FAIL'},'review':None})))
    original = output_validation.context('priorities', tmp_path)
    assert original == {'report': {'findings': [{'id':'f1','category':'hardening','status':'FAIL'}]}, 'reviews': []}
    with pytest.raises(output_validation.InvalidAgentOutput, match='agent_context_limit'):
        output_validation.context('network', tmp_path)
    with sqlite3.connect(tmp_path/'context.sqlite') as db:
        db.executemany('INSERT INTO records VALUES(?,?,?)', [('findings','f'+str(i),json.dumps({
            'finding':{'id':'f'+str(i),'category':'hardening','status':'FAIL'},'review':None})) for i in (2,3)])
    with pytest.raises(output_validation.InvalidAgentOutput, match='agent_context_limit'):
        output_validation.context('priorities', tmp_path)


def test_network_output_binds_resource_and_graph_references(tmp_path):
    with sqlite3.connect(tmp_path/'context.sqlite') as db:
        db.execute('CREATE TABLE records(domain TEXT,id TEXT,detail TEXT)')
        db.execute('INSERT INTO records VALUES(?,?,?)', ('resources','r1',json.dumps({'id':'r1','provider':'aws','scope':'test/us-east-1'})))
        db.execute('INSERT INTO records VALUES(?,?,?)', ('network_nodes','n1','{}'))
    original = output_validation.context('network', tmp_path)
    row = {'title':'Review broad access','description':'Observed broad rule warrants owner review.',
        'rationale':'Required traffic is not confirmed.','resource_id':'r1','severity':'medium','status':'MANUAL',
        'evidence':{'summary':'Captured rule.','resource_ids':['r1'],'graph_refs':['n1'],
                    'observations':['The captured rule permits a broad source.']},
        'remediation':'Validate dependencies and narrow the source.','verification':'Read the resulting effective configuration.'}
    data = {'explanation':'Captured network reviewed.','findings':[row]}
    assert output_validation.validate('network', data, original) == data
    with pytest.raises(ValueError, match='unknown_network_reference'):
        output_validation.validate('network', data|{'findings':[row|{'resource_id':'foreign'}]}, original)


def test_semantic_schema_error_can_be_corrected_without_changing_verdict(tmp_path, monkeypatch):
    bad = review('assigned')
    bad['actions'][0]['steps'] = []
    calls = inputs(tmp_path, monkeypatch, [bad, review('assigned')])
    runner.main()
    assert len(calls) == 2
    assert json.loads((tmp_path/'result.json').read_text()) == review('assigned')
    assert json.loads((tmp_path/'validation-feedback.json').read_text())['fields']


def test_second_priorities_correction_uses_latest_candidate_and_full_original_inputs(tmp_path, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(runner, 'time', SimpleNamespace(monotonic=lambda: clock[0]))
    malformed = review('assigned')
    malformed['actions'][0]['steps'] = []
    calls = inputs(tmp_path, monkeypatch, [review('foreign'), malformed, review('assigned')], clock)
    original = (tmp_path/'context.sqlite').read_bytes()
    runner.main()
    assert len(calls) == 3 and [call['minutes'] for call in calls] == [9, 7, 4]
    assert all((call['primary'], call['thinking'], call['max_turns']) ==
               ('OPENAI_BEST_QUALITY', 'high', 30) for call in calls)
    assert json.loads((tmp_path/'result.json').read_text()) == review('assigned')
    assert json.loads((tmp_path/'candidate-output.json').read_text()) == malformed
    feedback = json.loads((tmp_path/'validation-feedback.json').read_text())
    assert feedback['code'] == 'invalid_output'
    assert {'type': 'too_short', 'path': ['actions', 0, 'steps']} in feedback['fields']
    assert (tmp_path/'context.sqlite').read_bytes() == original
    assert all('validation-feedback.json' in call['text'] for call in calls[1:])
    assert (tmp_path/'candidate-output.json').stat().st_mode & 0o777 == 0o600
    assert (tmp_path/'validation-feedback.json').stat().st_mode & 0o777 == 0o600


def test_second_correction_cannot_extend_deadline_or_revalidate_after_it(tmp_path, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(runner, 'time', SimpleNamespace(monotonic=lambda: clock[0]))
    calls = inputs(tmp_path, monkeypatch, [review('foreign')], clock)
    monkeypatch.setenv(deadline.ENVIRONMENT_KEY, '250')
    probes = []
    monkeypatch.setattr(runner, 'validate_runtime', lambda *args: probes.append(True))
    assert runner.entrypoint() == 124
    assert len(calls) == 2 and len(probes) == 2
    assert not (tmp_path/'result.json').exists()


def test_credential_revalidation_cannot_start_a_correction_with_stale_time_budget(tmp_path, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(runner, 'time', SimpleNamespace(monotonic=lambda: clock[0]))
    calls = inputs(tmp_path, monkeypatch, [review('foreign')], clock)
    probes = []
    def validate(*args):
        probes.append(True)
        if len(probes) == 3:
            clock[0] += 300
    monkeypatch.setattr(runner, 'validate_runtime', validate)
    assert runner.entrypoint() == 124
    assert len(calls) == 2 and len(probes) == 3
    assert not (tmp_path/'result.json').exists()


def test_network_retains_one_correction(tmp_path, monkeypatch):
    calls = inputs(tmp_path, monkeypatch, [review('foreign')])
    monkeypatch.setattr(sys, 'argv', ['runner', 'network'])
    assert runner.entrypoint() == 65
    assert len(calls) == 2 and not (tmp_path/'result.json').exists()


def test_valid_second_correction_returning_after_original_deadline_is_not_published(tmp_path, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(runner, 'time', SimpleNamespace(monotonic=lambda: clock[0]))
    malformed = review('assigned')
    malformed['actions'][0]['steps'] = []
    calls = inputs(tmp_path, monkeypatch, [review('foreign'), malformed, review('assigned')], clock)
    monkeypatch.setenv(deadline.ENVIRONMENT_KEY, '400')
    assert runner.entrypoint() == 124
    assert len(calls) == 3 and not (tmp_path/'result.json').exists()


def test_task_runtime_reports_only_a_fixed_invalid_output_code(monkeypatch, capsys):
    import requests
    from peaso.ai import task_runtime
    monkeypatch.setattr(sys, 'argv', ['task-runtime','agent'])
    monkeypatch.setattr(requests, 'get', lambda *a, **k: SimpleNamespace(
        raise_for_status=lambda:None, json=lambda:{'stage':'priorities'}))
    def fail(_): raise output_validation.InvalidAgentOutput('DO_NOT_LOG_SECRET')
    monkeypatch.setattr(task_runtime, 'run_agent', fail)
    with pytest.raises(SystemExit) as stopped: task_runtime.main()
    assert stopped.value.code == 65
    assert capsys.readouterr() == ('', 'ai_agent_failure=invalid_output\n')


def test_corrections_continue_the_same_agent_session(tmp_path, monkeypatch):
    malformed = review('assigned')
    malformed['actions'][0]['steps'] = []
    calls = inputs(tmp_path, monkeypatch, [review('foreign'), malformed, review('assigned')])
    agents = []
    original = sys.modules['chack_agent'].Chack
    class Tracked(original):
        def __init__(self, config):
            super().__init__(config); agents.append(self)
    monkeypatch.setattr(sys.modules['chack_agent'], 'Chack', Tracked)
    runner.main()
    assert len(calls) == 3 and len(agents) == 1
    assert json.loads((tmp_path/'result.json').read_text()) == review('assigned')


def test_unresumable_correction_falls_back_to_a_fresh_agent_within_the_deadline(tmp_path, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(runner, 'time', SimpleNamespace(monotonic=lambda: clock[0]))
    calls = inputs(tmp_path, monkeypatch, [review('foreign'), review('assigned')], clock)
    agents = []
    original = sys.modules['chack_agent'].Chack
    class Resume(original):
        def __init__(self, config):
            super().__init__(config); agents.append(self); self.runs = 0
        def run(self, *args, **kwargs):
            self.runs += 1
            if self.runs > 1:
                clock[0] += 10
                return SimpleNamespace(error='resume_failed', output='')
            return super().run(*args, **kwargs)
    monkeypatch.setattr(sys.modules['chack_agent'], 'Chack', Resume)
    runner.main()
    assert len(agents) == 2 and [agent.runs for agent in agents] == [2, 1]
    assert [call['minutes'] for call in calls] == [9, 6]
    assert all((call['primary'], call['thinking'], call['max_turns']) ==
               ('OPENAI_BEST_QUALITY', 'high', 30) for call in calls)
    assert 'validation-feedback.json' in calls[1]['text']
    assert json.loads((tmp_path/'result.json').read_text()) == review('assigned')


def test_failed_fresh_fallback_is_never_published(tmp_path, monkeypatch):
    calls = inputs(tmp_path, monkeypatch, [review('foreign')])
    original = sys.modules['chack_agent'].Chack
    class Broken(original):
        def run(self, *args, **kwargs):
            result = super().run(*args, **kwargs)
            return result if len(calls) == 1 else SimpleNamespace(error='failed', output='')
    monkeypatch.setattr(sys.modules['chack_agent'], 'Chack', Broken)
    with pytest.raises(RuntimeError, match='agent_failed'):
        runner.main()
    assert len(calls) == 3 and not (tmp_path/'result.json').exists()
