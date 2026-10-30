"""Exhaustive AWS copy accounting and replay of actual native-test witnesses.

The fixture was captured while 19,942 native tests passed. Each exact evaluator
and description remains source-bound here; verdicts and evidence are immutable.
"""
from copy import deepcopy
import ast
import gzip
import hashlib
import inspect
import json
from pathlib import Path

import pytest

from peaso.checks import CHECKS, CHECK_ALIASES
from peaso.checks.fixtures import CASES as NATIVE_CASES
from peaso.checks.catalog import description_for
from peaso.checks.aws_evidence_explanations import evidence_summary, review_rows, reviewed_explanation
from peaso.checks.aws_current_evidence_20261022 import CURRENT_IDS
from peaso.checks.aws_natural_evidence import complete_explanation
from peaso.checks.aws_review_20261019 import MODULES
from importlib import import_module

ROOT = Path(__file__).resolve().parents[1]
CHECK_BY_ID = {c.id: c for c in CHECKS if c.provider == 'aws'}
ROWS = review_rows()
# aws.json is the historical review ledger.  Later reviewed edits only moved
# current pins inside it; each is listed with its historical value and the file
# whose current bytes it must match, so the ledger is read back at its epoch.
LEDGER_CURRENT_PINS = {
    ('checks', 'aws.review.workload.selected_command_literal_secret_indicators', 'runtime_receipt', 'sha256'): {
        'historical': 'b4bc249947fb0ec67f24a59ba55df4ac8baa5f674d9055d904631394fec4d791',
        'current_of': 'docs/check-review/aws-workload-command-runtime-20261020.json',
        'commit': '5826f6d2'},
}


def _historical_ledger_bytes():
    raw = (ROOT / 'docs/evidence-reviews/aws.json').read_bytes()
    current = json.loads(raw)
    for pointer, pin in LEDGER_CURRENT_PINS.items():
        value = current
        for key in pointer:
            value = value[key]
        assert value == hashlib.sha256((ROOT / pin['current_of']).read_bytes()).hexdigest(), pointer
        if value != pin['historical']:
            needle = b'"' + pointer[-1].encode() + b'": "' + value.encode() + b'"'
            assert raw.count(needle) == 1 and raw.count(value.encode()) == 1, pointer
            raw = raw.replace(needle, b'"' + pointer[-1].encode() + b'": "' + pin['historical'].encode() + b'"')
    return raw


LEDGER_RAW = _historical_ledger_bytes()
LEDGER = json.loads(LEDGER_RAW)
CURRENT = json.loads((ROOT / 'docs/evidence-reviews/aws-current-successor-20261022.json').read_text())
HISTORICAL_SUCCESSOR = json.loads((ROOT / 'docs/evidence-reviews/aws-historical-successor-20261022.json').read_text())
CASES = json.loads(gzip.decompress((ROOT / 'tests/fixtures/aws_evidence_review.json.gz').read_bytes()))
from tests.aws_late_native_contracts_20261020 import IDS as LATE_IDS, CONTRACTS, assert_contract

STATUSES = ('PASS', 'FAIL', 'UNKNOWN', 'DENIED', 'MANUAL', 'EMPTY', 'NOT_APPLICABLE')
EXTENSION_IDS = {row['spec']['id'] for name in MODULES
                 for row in import_module('peaso.checks.' + name).ADMISSION_DATA['checks']}
LATE_CONFIGURATION = 'aws.review.configuration.selected_content_secret_indicators'


def assert_late_contract(cid):
    check = CHECK_BY_ID[cid]
    if cid != LATE_CONFIGURATION:
        assert_contract(cid, check, LEDGER['checks'][cid], ROWS[cid], description_for(cid))
        return
    # The immutable old callable is reconstructed through the accepted finite
    # source transition. Its predicate pin remains the original historical hash.
    from peaso import private_secret_source_epoch_20261021 as epoch
    old = CONTRACTS[cid]
    relative = 'peaso/checks/aws_selected_configuration_secret_review_20261020.py'
    raw = (ROOT / relative).read_bytes()
    successor = CURRENT['late_configuration_successor']
    assert hashlib.sha256(raw).hexdigest() == successor['current_source_sha256']
    before = epoch.predecessor_bytes(relative, raw, old['files'][relative], ROOT)
    assert hashlib.sha256(before).hexdigest() == old['files'][relative]
    node, = (item for item in ast.parse(before).body if isinstance(item, ast.FunctionDef) and item.name == 'evaluate')
    source = ''.join(before.decode().splitlines(keepends=True)[node.lineno - 1:node.end_lineno])
    assert hashlib.sha256(source.encode()).hexdigest() == old['predicate']
    assert hashlib.sha256(inspect.getsource(inspect.unwrap(check.evaluate)).encode()).hexdigest() == successor['current_evaluator_sha256']
    assert _digest(description_for(cid)) == old['description']
    assert _digest(ROWS[cid]) == old['copy']
    assert _digest(LEDGER['checks'][cid]) == old['ledger']
    for path, sha in old['files'].items():
        if path != relative:
            assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == sha
    cases = json.loads((ROOT / LEDGER['checks'][cid]['fixture_source']).read_text())[cid]
    for branch in ('pass', 'fail', 'unknown'):
        item = deepcopy(cases[branch])
        index = deepcopy(cases.get(branch + '_index', cases.get('index', {})))
        before_case = deepcopy((item, index))
        assert check.evaluate(item, index)[0] == branch.upper()
        assert (item, index) == before_case


def test_every_registered_aws_check_and_retired_alias_has_source_review_and_real_native_witnesses():
    aliases = {old for old, new in CHECK_ALIASES.items() if new in CHECK_BY_ID}
    historical = set(CASES) | LATE_IDS
    historical_review = set(LEDGER['checks'])
    retired = set(CURRENT['retired_aliases'])
    assert retired == historical_review - set(CHECK_BY_ID) == aliases
    assert historical_review - historical == retired - historical
    assert CURRENT_IDS == set(CURRENT['current_checks']) == set(CHECK_BY_ID) - historical
    assert set(CHECK_BY_ID) == historical - retired | CURRENT_IDS
    assert not set(CASES) & LATE_IDS
    assert set(CHECK_BY_ID) | aliases == set(ROWS) == historical_review | CURRENT_IDS
    assert CURRENT['retired_aliases'] == {old: CHECK_ALIASES[old] for old in retired}
    assert CURRENT['base_commit'] == 'e7510bc898183fd9f478d0cb511c37aed8db4286'
    assert hashlib.sha256(LEDGER_RAW).hexdigest() == CURRENT['historical_ledger_sha256']
    assert HISTORICAL_SUCCESSOR['historical_ledger_sha256'] == CURRENT['historical_ledger_sha256']
    assert hashlib.sha256((ROOT / 'tests/fixtures/aws_evidence_review.json.gz').read_bytes()).hexdigest() == HISTORICAL_SUCCESSOR['historical_fixture_sha256']
    assert set(HISTORICAL_SUCCESSOR['reviewed_current_native_contracts']) == {
        'aws.a.iam.unused_credentials_45_days',
        'aws.a.iam.unused_credentials_90_days',
        'aws.claude_a.accessanalyzer.active_without_findings',
        'aws.claude_a.iam.access_keys_used_45',
        'aws.claude_a.iam.console_password_used_45',
        'aws.claude_a.iam.prowler_console_password_used_45',
        # 5768474c: only a conditioned service trust is in scope.
        'aws.claude_a.iam.prowler_role_service_trust_bound_to_account',
        'aws.claude_a.iam.role_used_within_60_days',
        # a9d62a01: ownership controls are decided only from collected detail.
        'aws.claude_a.s3.prowler_acl_disabled',
        'aws.claude_a.vpc.sg_in_use_anywhere',
        'aws.claude_a.vpc.sg_no_world_any_port_on_customer_enis',
        'aws.gap.iam.active_keys_used_within_45_days',
    }
    assert set(HISTORICAL_SUCCESSOR['reviewed_current_summary_witnesses']) == {
        'aws.a.iam.unused_credentials_45_days',
        'aws.a.iam.unused_credentials_90_days',
        'aws.gap.iam.active_keys_used_within_45_days',
    }
    assert set(HISTORICAL_SUCCESSOR['reviewed_retired_alias_copy']) == {
        'aws.a.cloudwatch.cross_account_role_absent',
        'aws.a.s3.bucket_account_public_blocks',
        'aws.b.redshift.no_public_endpoint',
    }
    assert hashlib.sha256((ROOT / 'peaso/checks/aws_current_evidence_20261022.py').read_bytes()).hexdigest() == CURRENT['summary_source_sha256']
    assert sum(len(rows) for cid, rows in CASES.items() if cid not in EXTENSION_IDS) == 8882
    assert all(len(CASES[cid]) >= 4 for cid in EXTENSION_IDS)
    assert all(ROWS[cid]['review_status'] == 'source_reviewed_and_native_replayed' for cid in set(ROWS) - LATE_IDS)
    assert all(ROWS[cid]['purpose'] and ROWS[cid]['fields'] is not None for cid in set(ROWS) - LATE_IDS)
    for cid in LATE_IDS:
        assert_late_contract(cid)


@pytest.mark.parametrize('cid', sorted(CHECK_BY_ID))
def test_exact_evaluator_and_requirement_contract_match_the_review(cid):
    if cid in CURRENT_IDS:
        assert_current_contract(cid)
        return
    if cid in HISTORICAL_SUCCESSOR['reviewed_current_native_contracts']:
        assert_historical_successor_contract(cid)
        return
    row = LEDGER['checks'][cid]
    if cid in LATE_IDS:
        assert_late_contract(cid)
        return
    function = inspect.unwrap(CHECK_BY_ID[cid].evaluate)
    assert hashlib.sha256(inspect.getsource(function).encode()).hexdigest() == row['evaluator_sha256']
    if cid in EXTENSION_IDS:
        target = getattr(function, 'reviewed_target', function)
        assert hashlib.sha256(inspect.getsource(target).encode()).hexdigest() == row['target_sha256']
    contract = json.dumps(description_for(cid), sort_keys=True, separators=(',', ':')).encode()
    assert hashlib.sha256(contract).hexdigest() == row['description_contract_sha256']
    assert ROWS[cid]['purpose'] == row['purpose']
    assert row['fixture_count'] == len(CASES[cid])
    assert row['missing_fixture_ids'] == []


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def assert_historical_successor_contract(cid):
    """Bind changed native behavior while preserving the earlier review record."""
    row = HISTORICAL_SUCCESSOR['reviewed_current_native_contracts'][cid]
    historical = LEDGER['checks'][cid]
    function = inspect.unwrap(CHECK_BY_ID[cid].evaluate)
    assert Path(inspect.getsourcefile(function)).resolve().relative_to(ROOT).as_posix() == row['source']
    assert hashlib.sha256(inspect.getsource(function).encode()).hexdigest() == row['evaluator_sha256']
    if cid in EXTENSION_IDS:
        target = getattr(function, 'reviewed_target', function)
        assert hashlib.sha256(inspect.getsource(target).encode()).hexdigest() == row['target_sha256']
    assert _digest(description_for(cid)) == row['description_contract_sha256']
    assert ROWS[cid]['purpose'] == historical['purpose']
    assert historical['fixture_count'] == len(CASES[cid])
    assert historical['missing_fixture_ids'] == []
    assert set(row['native_witnesses']) == {'pass', 'fail', 'unknown'}
    for branch, expected in row['native_witnesses'].items():
        cases = NATIVE_CASES[cid]
        item = deepcopy(cases.get(branch))
        index = deepcopy(cases.get(branch + '_index', cases.get('index', {})))
        before = deepcopy((item, index))
        assert _digest([item, index]) == expected['case_sha256']
        status, evidence = CHECK_BY_ID[cid].evaluate(item, index)
        assert (item, index) == before
        assert status == expected['status'] == branch.upper()
        assert _digest(evidence) == expected['evidence_sha256']
        before_evidence = deepcopy(evidence)
        summary = evidence_summary(dict(provider='aws', check_id=cid, status=status, evidence=evidence))
        assert evidence == before_evidence
        assert hashlib.sha256(summary.encode()).hexdigest() == expected['summary_sha256']


def assert_current_contract(cid):
    row = CURRENT['current_checks'][cid]
    function = inspect.unwrap(CHECK_BY_ID[cid].evaluate)
    assert Path(inspect.getsourcefile(function)).resolve().relative_to(ROOT).as_posix() == row['source']
    assert hashlib.sha256(inspect.getsource(function).encode()).hexdigest() == row['evaluator_sha256']
    assert _digest(description_for(cid)) == row['description_contract_sha256']
    assert _digest(ROWS[cid]) == row['copy_row_sha256']
    fixture = ROOT / row['fixture_source']
    assert hashlib.sha256(fixture.read_bytes()).hexdigest() == row['fixture_sha256']
    saved = json.loads(fixture.read_text())[row['fixture_key']]
    assert saved == NATIVE_CASES[cid]
    for branch in ('pass', 'fail', 'unknown'):
        witness = row['native_witnesses'][branch]
        case = witness['case']
        item = deepcopy(saved[case])
        index = deepcopy(saved.get(case + '_index', saved.get('index', {})))
        before = deepcopy((item, index))
        status, evidence = CHECK_BY_ID[cid].evaluate(item, index)
        assert (item, index) == before
        assert status == witness['status'] == branch.upper()
        assert _digest(evidence) == witness['evidence_sha256']
        before_evidence = deepcopy(evidence)
        summary = evidence_summary(dict(provider='aws', check_id=cid, status=status, evidence=evidence))
        assert evidence == before_evidence
        assert summary and len(summary.splitlines()) == 3
        assert all(line.endswith('.') for line in summary.splitlines())
        _assert_current_first_line(cid, branch, evidence, summary.splitlines()[0])
        assert 'values hidden' not in summary
        assert hashlib.sha256(summary.encode()).hexdigest() == witness['summary_sha256']
    for status in STATUSES:
        for evidence in ({}, {'unrelated': True}):
            summary = evidence_summary(dict(provider='aws', check_id=cid, status=status, evidence=evidence))
            lines = summary.splitlines()
            assert len(lines) == 3 and all(line.endswith('.') for line in lines)
            assert any(word in lines[0] for word in ('unavailable', 'not recorded', 'lacks', 'were not recorded'))


def _assert_current_first_line(cid, branch, evidence, first):
    if cid.startswith('aws.review.'):
        if branch == 'unknown':
            assert 'lacks' in first and 'unclear' not in first
            return
        if branch == 'pass':
            assert 'no detected' in first
            return
        assert branch == 'fail' and not any(word in first for word in ('unavailable', 'unclear', 'lacks'))
        if 'vulnerabilities' in cid:
            findings = evidence.get('Vulnerabilities', evidence.get('vulnerabilities'))
            assert isinstance(findings, list) and findings
            assert f'{len(findings)} recorded' in first
            assert any(finding['vulnerability_id'] in first for finding in findings)
        else:
            leaks = evidence['secret_leaks']
            assert isinstance(leaks, list) and leaks
            assert f'{len(leaks)} detected' in first and 'indicator' in first
            rules = {detector.get('rule') for leak in leaks for detector in leak['detectors']}
            if rules & {'github-pat', 'betterleaks.github-pat'}:
                assert 'GitHub token indicator' in first
            locations = [loc for leak in leaks for loc in leak['locations']]
            assert locations
            if cid == 'aws.review.ecr_public.selected_image_secret_indicators':
                assert 'image layer file' in first and 'image manifest' in first
            elif cid == 'aws.review.workload.selected_image_secret_indicators':
                assert 'image config' in first
            else:
                assert 'selected S3 source text' in first
        return
    if branch == 'unknown':
        assert any(word in first for word in ('unavailable', 'not recorded', 'were not recorded'))
        return
    if cid == 'aws.iam.group_inline_policies_have_members':
        assert f"{len(evidence['inline_policies'])} inline policies" in first
        assert f"{len(evidence['member_identities'])} recorded user members" in first
        return
    field = ('consumer_accounts' if 'permission_set' in cid else
             'role_consumers' if 'provider_has_role_consumer' in cid else
             'load_balancer_arns' if 'target_group' in cid else 'associations')
    assert f'{len(evidence[field])} recorded' in first


def test_current_secret_summary_does_not_copy_raw_values_or_untrusted_paths():
    cid = 'aws.review.workload.selected_image_secret_indicators'
    evidence = {'secret_leaks': [{'value': 'PRIVATE-SENTINEL', 'locations': [{'path': 'PRIVATE-SENTINEL'}]}]}
    before = deepcopy(evidence)
    summary = evidence_summary(dict(provider='aws', check_id=cid, status='FAIL', evidence=evidence))
    assert '1 detected secret indicator in 1 recorded content location' in summary.splitlines()[0]
    assert 'PRIVATE-SENTINEL' not in summary
    assert evidence == before


@pytest.mark.parametrize('cid', sorted(CURRENT_IDS))
def test_current_successor_replays_exact_native_witnesses(cid):
    assert_current_contract(cid)


@pytest.mark.parametrize('cid', sorted(CASES))
def test_all_captured_success_failure_partial_and_inapplicable_witnesses(cid):
    successors = HISTORICAL_SUCCESSOR['reviewed_current_summary_witnesses'].get(cid, {})
    seen = set()
    for index, case in enumerate(CASES[cid]):
        finding = dict(provider='aws', check_id=cid, status=case['status'], evidence=deepcopy(case['evidence']))
        before = deepcopy(finding)
        summary = evidence_summary(finding)
        successor = successors.get(str(index))
        if successor is None:
            assert summary == case['summary']
        else:
            seen.add(str(index))
            assert case['status'] == successor['status']
            assert _digest(case['evidence']) == successor['evidence_sha256']
            assert hashlib.sha256(case['summary'].encode()).hexdigest() == successor['historical_summary_sha256']
            assert hashlib.sha256(summary.encode()).hexdigest() == successor['current_summary_sha256']
        assert len(summary) <= 250
        complete = complete_explanation(finding)
        assert summary == complete or ROWS[cid]['purpose'] in summary
        assert not summary.startswith(('{', '[')) and '\n' not in summary
        assert 'All of:' not in summary and 'quantifier' not in summary
        if summary != complete:
            assert reviewed_explanation(cid, summary, finding['status']) == summary
        assert finding == before
    assert seen == set(successors)


@pytest.mark.parametrize('cid', sorted(CHECK_BY_ID))
def test_every_status_with_absent_or_unrelated_evidence_is_explicitly_unclaimed(cid):
    for status in STATUSES:
        for evidence in ({}, {'unrelated': True}):
            summary = evidence_summary(dict(provider='aws', check_id=cid, status=status, evidence=evidence))
            complete = complete_explanation(dict(provider='aws', check_id=cid, status=status, evidence=evidence))
            if cid in CURRENT_IDS:
                assert summary and len(summary.splitlines()) == 3
                assert any(word in summary.splitlines()[0] for word in ('unavailable', 'not recorded', 'lacks', 'were not recorded'))
                continue
            assert summary and (summary == complete or ROWS[cid]['purpose'] in summary)
            assert any(text in summary for text in ('No usable deciding evidence', 'Required evidence is unavailable',
                                                     'outside the control’s applicability', 'No applicable resources',
                                                     'could not be checked', 'cannot confirm whether root keys exist'))
            assert not summary.startswith(('The policy grants', 'The function has', 'Automatic rotation is enabled'))


def test_retired_equivalent_ids_reuse_the_survivor_native_value_interpretation():
    for old, new in CHECK_ALIASES.items():
        if new not in CHECK_BY_ID:
            continue
        successor = HISTORICAL_SUCCESSOR['reviewed_retired_alias_copy'].get(old)
        if successor is not None:
            assert successor['survivor_id'] == new
            assert set(successor['witnesses']) == {str(i) for i in range(len(CASES[new]))}
        for index, case in enumerate(CASES[new]):
            finding = dict(provider='aws', status=case['status'], evidence=case['evidence'])
            historical_summary = evidence_summary(dict(finding, check_id=old))
            survivor_summary = evidence_summary(dict(finding, check_id=new))
            if successor is None:
                assert historical_summary == survivor_summary
                continue
            witness = successor['witnesses'][str(index)]
            assert witness['status'] == case['status']
            assert _digest(case['evidence']) == witness['evidence_sha256']
            assert hashlib.sha256(historical_summary.encode()).hexdigest() == witness['historical_alias_summary_sha256']
            assert hashlib.sha256(survivor_summary.encode()).hexdigest() == witness['survivor_summary_sha256']
            assert historical_summary != survivor_summary


def test_invalid_identifiers_and_foreign_provider_do_not_get_aws_copy():
    for cid in (None, {}, [], 'aws.not-reviewed'):
        assert evidence_summary(dict(provider='aws', check_id=cid, status='FAIL', evidence={})) is None
    assert evidence_summary(dict(provider='gcp', check_id='aws.iam.console_mfa', status='FAIL', evidence={})) is None
