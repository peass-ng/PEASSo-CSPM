"""Compare eager/deferred input delivery with a saved completed K8s answer.

No model, SDK or task is called. All socket connections are blocked. The two
historical invokes use the current full workspace builder; this isolates the
overlap plumbing and is not a replay of historical model behavior.
"""
import argparse
import copy
import gzip
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import time
import types
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def load(path):
    raw = path.read_bytes()
    return json.loads(gzip.decompress(raw) if raw.startswith(b'\x1f\x8b') else raw)


def replay(snapshot_path, report_path):
    from peaso.ai import pipeline, fargate, output_validation
    from peaso.ai.network import with_findings, snapshot_context
    from peaso.least_privilege import project
    from peaso.snapshot import frozen_view, resources
    from peaso.engine import evaluate_snapshot

    snapshot = frozen_view(load(snapshot_path))
    saved = load(report_path)
    assert saved['provider'] == 'k8s' and saved['ai']['status'] == 'completed'
    assert saved['ai']['actions'], 'completed_baseline_actions_required'
    network = saved['ai']['network']
    answer = {key: saved['ai'][key] for key in ('actions', 'limitations')}
    reviews = saved['ai']['reviews']['hardening'] + saved['ai']['reviews']['exposure']
    report = with_findings(evaluate_snapshot(snapshot, include_not_applicable=False), network['findings'])
    inventory = resources(snapshot)
    hardening, exposure, _ = pipeline.inputs(report)

    def platform():
        return {'report': report, 'inventory': inventory,
                'snapshot_context': snapshot_context(snapshot),
                'least_privilege': project('k8s', inventory, snapshot=snapshot),
                'network_review': network}

    root = Path(__file__).resolve().parents[1]
    historical = subprocess.check_output(['git', 'show', 'b08e8557^:peaso/ai/pipeline.py'], cwd=root)
    predecessor = types.ModuleType('peaso.ai._overlap_predecessor_replay')
    exec(compile(historical, 'before_overlap_pipeline', 'exec'), predecessor.__dict__)
    runs = []
    for label, module, lazy in (('before_b08', predecessor, False),
                                ('after_b08_eager', pipeline, False),
                                ('after_b58_lazy', pipeline, True)):
        state = {}
        value = platform if lazy else platform()

        def invoke_remote(stage, workspace, token, timeout, **kwargs):
            state['prepare_callback'] = callable(kwargs.get('prepare'))
            if kwargs.get('prepare'):
                kwargs['prepare']()
            original = output_validation.context('priorities', workspace)
            output_validation.validate('priorities', answer, original)
            state['files'] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                              for path in workspace.iterdir()}
            state['actions'] = len(answer['actions'])
            return copy.deepcopy(answer)

        with (patch.object(module.isolation, 'remote', return_value=True),
              patch.object(fargate, 'configuration', return_value={}),
              patch.object(fargate, 'invoke', side_effect=invoke_remote)):
            start = time.monotonic()
            result = module.invoke('priorities', value, [], 'synthetic-capability',
                                   hardening + exposure, reviews, 1500)
            state['wall_s'] = time.monotonic() - start
            assert result == answer
        runs.append({'revision_mode': label, **state})
    assert all(run['files'] == runs[0]['files'] for run in runs)
    return {'runs': runs, 'workspace_files_identical': True,
            'actions_validated': len(answer['actions']), 'native_finding_count': len(report['findings']),
            'source_sha256': {'report': hashlib.sha256(report_path.read_bytes()).hexdigest(),
                              'snapshot': hashlib.sha256(snapshot_path.read_bytes()).hexdigest(),
                              'pre_b08_pipeline': hashlib.sha256(historical).hexdigest(),
                              'current_pipeline': hashlib.sha256(Path(pipeline.__file__).read_bytes()).hexdigest()},
            'provider_calls': 0, 'model_calls': 0,
            'limitations': ['Historical completed answer, not the failed d4cf candidate output.',
                            'Current complete builder is used for each historical invoke.',
                            'Synthetic capability and empty live credentials; no real task startup or network transport.',
                            'This does not establish the cause of the d4cf failure.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path)
    parser.add_argument('report', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()

    def denied(*args, **kwargs):
        raise AssertionError('offline_network_attempt')

    with patch.object(socket.socket, 'connect', denied), patch.object(socket, 'create_connection', denied):
        result = replay(args.snapshot, args.report)
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps({'workspace_files_identical': True, 'actions_validated': result['actions_validated'],
                      'provider_calls': 0, 'model_calls': 0}))


if __name__ == '__main__':
    main()
