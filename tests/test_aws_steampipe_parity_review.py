"""Provenance and fail-closed behavior of the bounded static parity audit."""
import copy
import hashlib
import json

import pytest

from scripts.audit_aws_steampipe_parity import audit, corpus, rejection_verdict, selected_files


def cached_source(tmp_path):
    for name in ('compliance', 'perimeter'):
        directory = tmp_path / ('steampipe-mod-aws-' + name)
        directory.mkdir()
        data = b'control "example" {\n title = "Example"\n sql = "select 1"\n}\n'
        (directory / 'mod.pp').write_bytes(data)
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        (tmp_path / (name + '-head.json')).write_text(json.dumps({
            'sha': 'a' * 40, 'commit': {'tree': {'sha': 'b' * 40}}}))
        (tmp_path / (name + '-tree.json')).write_text(json.dumps({
            'sha': 'b' * 40, 'truncated': False, 'tree': [
                {'path': 'mod.pp', 'type': 'blob', 'size': len(data), 'sha': blob}]}))


def test_cached_corpus_checks_every_git_blob_and_control(tmp_path):
    cached_source(tmp_path)
    upstreams = corpus(tmp_path)
    assert [len(rows) for _source, rows, _definitions, _metadata in upstreams] == [1, 1]
    (tmp_path / 'steampipe-mod-aws-compliance/mod.pp').write_text('altered')
    with pytest.raises(ValueError, match='differs from pinned Git tree'):
        corpus(tmp_path)


def test_offline_missing_source_never_fetches(tmp_path, monkeypatch):
    cached_source(tmp_path)
    (tmp_path / 'steampipe-mod-aws-compliance/mod.pp').unlink()
    monkeypatch.setattr('scripts.audit_aws_steampipe_parity.fetch',
                        lambda *_: pytest.fail('offline audit attempted network'))
    with pytest.raises(ValueError, match='missing cached source'):
        corpus(tmp_path)


def test_incomplete_or_unbounded_tree_cannot_claim_parity():
    with pytest.raises(ValueError, match='truncated'):
        selected_files({'truncated': True})
    with pytest.raises(ValueError, match='budget'):
        selected_files({'tree': [{'type': 'blob', 'path': 'huge.pp', 'size': 8_000_001}]})
    with pytest.raises(ValueError, match='unsafe'):
        selected_files({'tree': [{'type': 'blob', 'path': '../bad.pp', 'size': 1}]})


def test_archived_implementation_is_not_active_coverage(tmp_path):
    cached_source(tmp_path)
    upstreams = corpus(tmp_path)
    rows = [copy.deepcopy(row) for _source, controls, *_rest in upstreams for row in controls]
    for row in rows:
        row.update(disposition='ported', native_checks=['aws.retired'])
    result = audit(upstreams, {'checks': rows}, {
        'checks': [], 'archived_checks': [{'id': 'aws.retired'}],
        'excluded_controls': {'aws.retired': {'reason': 'Requires customer trust list'}}},
        {'requirements': []}, {})
    assert result['summary']['control_count'] == 2
    for record in result['records']:
        assert record['validity_verdict'] == 'stale_automatic_coverage_archived_native'
        assert record['active_native'] == []
        assert record['archived_native'][0]['id'] == 'aws.retired'


def test_changed_source_is_reported_not_silently_accepted(tmp_path):
    cached_source(tmp_path)
    upstreams = corpus(tmp_path)
    rows = [copy.deepcopy(row) for _source, controls, *_rest in upstreams for row in controls]
    rows[0]['title'] = 'stale title'
    result = audit(upstreams, {'checks': rows}, {'checks': []}, {'requirements': []}, {})
    assert result['records'][0]['manifest_mismatches'] == ['title']
    assert result['records'][0]['validity_verdict'] == 'stale_manifest_source_or_lineage'


def test_rejections_require_individual_source_evidence():
    assert rejection_verdict('unknown', [], 'select 1', True)[0] == 'uncertain_rejection_requires_review'
    assert rejection_verdict('manual', ['manual_control'], 'Manual verification required', True)[0] == 'justified_manual_only'
    assert rejection_verdict('manual', ['manual_control'], 'Manual verification required', False)[0] == 'missing_manual_lineage'
    assert rejection_verdict('trust', [], 'param "trusted_accounts" { } select \'info\'', True)[0] == 'justified_customer_trust_input'
    assert rejection_verdict('ec2_instance_no_high_level_finding_in_inspector_scan', [], '', True)[0] == 'justified_retired_service'
