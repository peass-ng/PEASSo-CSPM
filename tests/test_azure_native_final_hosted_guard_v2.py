"""A model launch must require the exact, standalone root release marker."""

import sys

import pytest

from scripts import run_azure_native_final_hosted_a79_v2 as runner


def test_exact_release_line_only(tmp_path, monkeypatch):
    findings = tmp_path / 'findings.txt'
    monkeypatch.setattr(runner, 'FINDINGS', findings)
    findings.write_text('prefix_' + runner.RELEASE + '\n' + runner.RELEASE + ' \n')
    assert runner.released() is False
    findings.write_text('prior work\n' + runner.RELEASE + '\n')
    assert runner.released() is True


def test_launch_refuses_before_preparation_or_model_inputs(tmp_path, monkeypatch):
    findings = tmp_path / 'findings.txt'
    findings.write_text('')
    monkeypatch.setattr(runner, 'FINDINGS', findings)
    monkeypatch.setattr(sys, 'argv', ['run_azure_native_final_hosted_a79_v2.py', '--launch'])
    monkeypatch.setattr(runner, 'prepare', lambda **kwargs: pytest.fail('prepared before release'))
    monkeypatch.setattr(runner, 'image_ready', lambda: pytest.fail('inspected image before release'))
    with pytest.raises(PermissionError, match='root_model_slot_not_released'):
        runner.main()


def test_pair_receipt_counts_native_substitution():
    common = {'report': {'snapshot_id': 'saved'}, 'native_ids': ['n']}
    baseline = {'reviews': [{'finding_id': 'n', 'verdict': 'UNKNOWN', 'reason': 'missing'},
                            {'finding_id': 'a', 'verdict': 'FAIL', 'reason': ''}],
                'model_calls': 2, 'input_tokens': 100, 'wall_seconds': 3}
    candidate = {'reviews': [{'finding_id': 'a', 'verdict': 'FAIL', 'reason': ''}],
                 'model_calls': 1, 'input_tokens': 40, 'wall_seconds': 2}
    result = runner.summarize_pair(common, baseline, candidate)
    assert result['combined_review_ids'] == 2
    assert result['verdict_difference_ids'] == ['n']
    assert result['action_parity_evaluated'] is False
