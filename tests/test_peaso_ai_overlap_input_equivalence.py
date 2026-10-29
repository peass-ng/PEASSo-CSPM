"""Startup overlap must deliver the same full evidence as eager preparation."""
import hashlib
from pathlib import Path

from peaso.ai import briefing, fargate, output_validation, pipeline


def test_deferred_k8s_workspace_matches_eager_full_data_and_validates_actions(tmp_path, monkeypatch):
    finding = {'id': 'native-finding', 'check_id': 'k8s.native-control',
               'provider': 'k8s', 'category': 'hardening', 'status': 'FAIL',
               'severity': 'high', 'resource_id': 'resource', 'scope': 'default',
               'evidence': {'complete_native_value': 'full evidence ' * 15000}}
    resource = {'id': 'resource', 'native_id': 'native-resource', 'provider': 'k8s',
                'scope': 'default', 'type': 'pod', 'data': {'all_properties': ['a', 'b']}}
    platform = {'report': {'provider': 'k8s', 'findings': [finding], 'graphs': {}},
                'inventory': [resource], 'source_inventory': [resource],
                'snapshot_context': {'metadata': {'complete_source': ['x', 'y']}},
                'least_privilege': {'items': []},
                'network_review': {'status': 'completed', 'explanation': 'Recorded boundary.', 'findings': []}}
    reviews = [{'finding_id': finding['id'], 'verdict': 'FAIL', 'reason': ''}]
    answer = {'actions': [{'rank': 1, 'severity': 'high', 'effort': 'low',
                          'title': 'Correct the captured native setting', 'finding_ids': [finding['id']],
                          'rationale': 'The complete native evidence establishes the weak setting.',
                          'steps': ['Apply the documented setting after checking workload dependencies.'],
                          'verification': 'Read the setting and confirm required workload behavior.'}],
              'limitations': []}
    eager = tmp_path / 'eager'
    eager.mkdir()
    # The workspace construction sequence before b08e8557.
    briefing.build(eager, platform, [finding], reviews, pipeline.private_json)
    pipeline.private_json(eager / 'credentials.json', {'version': 2, 'entries': []})

    def fingerprints(root):
        return {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in Path(root).iterdir()}

    expected = fingerprints(eager)
    started, projected, prepared = [], [], []

    def deferred_platform():
        assert started == [True]
        projected.append(True)
        return platform

    def invoke_remote(stage, root, token, timeout, *, prepare):
        assert stage == 'priorities' and timeout <= 1500
        assert not projected and not list(root.iterdir())
        started.append(True)  # No provider/task/model call is made.
        prepare()
        assert projected == [True] and prepared == [True]
        assert fingerprints(root) == expected
        # Both validators receive the same exact original finding references,
        # even when large evidence is backed by lossless SQLite fragments.
        original = output_validation.context('priorities', root)
        output_validation.validate('priorities', answer, original)
        return answer

    monkeypatch.setattr(pipeline.isolation, 'remote', lambda: True)
    monkeypatch.setattr(fargate, 'configuration', lambda: {})
    monkeypatch.setattr(fargate, 'invoke', invoke_remote)
    result = pipeline.invoke('priorities', deferred_platform, [], 'synthetic-capability',
                             [finding], reviews, 1500, on_prepared=lambda: prepared.append(True))
    assert result == answer
