"""Parity audit must fail closed and distinguish mapping from runtime support."""
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location('aws_parity_audit', Path(__file__).parents[1] / 'scripts/audit_aws_prowler_parity.py')
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


@pytest.fixture
def source(tmp_path):
    root, cache = tmp_path / 'repo', tmp_path / 'cache'
    pack = root / 'peaso/rulepacks'
    dump(pack / 'upstream_manifest.json', {'sources': [{'repository': audit.REPO, 'revision': 'old'}], 'checks': [
        {'repository': audit.REPO, 'provider': 'aws', 'upstream_id': 'test_check', 'disposition': 'ported',
         'native_checks': ['aws.test'], 'frameworks': [{'framework_id': 'cis_test_aws', 'control_id': '1'}]}]})
    dump(pack / 'native_catalog.json', {'checks': [], 'archived_checks': [{'id': 'aws.test'}],
        'excluded_controls': {'aws.test': {'reason': 'requires customer configuration'}}})
    files = {audit.PREFIX + 'test/test_check/test_check.metadata.json': {'CheckID': 'test_check'},
        'prowler/compliance/aws/cis_test_aws.json': {'Requirements': [{'Id': '1', 'Checks': ['test_check']}]}}
    entries = []
    for path, value in files.items():
        dump(cache / path, value)
        raw = (cache / path).read_bytes()
        entries.append({'path': path, 'sha': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()})
    dump(cache / 'tree.json', {'truncated': False, 'tree': entries})
    dump(cache / 'revision.json', {'revision': 'new'})
    return root, cache


def test_archived_mapping_is_never_supported_even_if_runtime_registered(source):
    root, cache = source
    row = audit.audit(root, cache, {'aws.test': {'path': 'test.py'}})['checks'][0]
    assert row['disposition'] == 'unresolved_no_active_native'
    assert row['active_native_checks'] == []
    assert row['archived_native_checks']['aws.test']['reason']


def test_missing_runtime_is_not_supported(source):
    root, cache = source
    pack = root / 'peaso/rulepacks/native_catalog.json'
    dump(pack, {'checks': [{'id': 'aws.test'}]})
    assert audit.audit(root, cache, {})['checks'][0]['active_native_checks'] == []


def test_active_predicate_trace_does_not_claim_equivalence(source):
    root, cache = source
    dump(root / 'peaso/rulepacks/native_catalog.json', {'checks': [{'id': 'aws.test', 'requirement_controls': []}]})
    row = audit.audit(root, cache, {'aws.test': {'path': 'test.py', 'line': 9}})['checks'][0]
    assert row['disposition'] == 'mapped_predicate_equivalence_unverified'
    assert row['native_predicates']['aws.test']['line'] == 9
    assert row['active_native_requirement_references_missing'] == [('cis_test_aws', '1')]


def test_exact_control_drift_in_both_directions(source):
    root, cache = source
    pack = root / 'peaso/rulepacks/upstream_manifest.json'
    value = audit.read(pack)
    value['checks'][0]['frameworks'][0]['control_id'] = '2'
    dump(pack, value)
    row = audit.audit(root, cache, {})['checks'][0]
    assert row['manifest_compliance_missing'] == [('cis_test_aws', '1')]
    assert row['manifest_compliance_stale'] == [('cis_test_aws', '2')]


def test_git_blob_integrity_and_incomplete_cache(source):
    root, cache = source
    path = next(cache.glob('prowler/providers/aws/services/*/*/*.json'))
    path.write_text('{}')
    with pytest.raises(ValueError, match='pinned Git tree'):
        audit.audit(root, cache, {})
    path.unlink()
    with pytest.raises(FileNotFoundError):
        audit.audit(root, cache, {})


def test_truncated_tree_rejected(source):
    root, cache = source
    tree = audit.read(cache / 'tree.json')
    tree['truncated'] = True
    dump(cache / 'tree.json', tree)
    with pytest.raises(ValueError, match='truncated'):
        audit.audit(root, cache, {})


def test_nested_compliance_and_status_assignments():
    result = audit.compliance_index({'cis': {'Requirements': [{'Id': '1', 'Requirements': [{'Id': '1.1', 'Checks': ['a']}]}]}})
    assert result['a'] == {('cis', '1.1')}
    assert audit.status_assignments('report.status = "MANUAL"\nreport.status_extended = "PASS"') == ['MANUAL']
    assert audit.status_assignments('report.status = "PASS"\nif missing:\n report.status = "MANUAL"') == ['MANUAL', 'PASS']
