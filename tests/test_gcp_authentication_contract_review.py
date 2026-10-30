"""Unsupported login classification is archived, never supplied by failed RPCs."""

import pytest

from peaso import engine
from peaso.checks import CHECKS
from peaso.checks.native_only import exclusions
from peaso.snapshot import make_snapshot
from tests.test_gcp_audit_native import collect, event

CID = 'gcp_logging_detect_t1110'


def test_unsupported_exact_contract_is_archived_without_inventing_a_successor():
    row = exclusions()[CID]
    assert row['disposition'] == 'unsupported_exact_contract'
    assert row['mandatory_external_fields'] == []
    assert row['native_alternatives'] == []
    assert CID in {check.id for check in CHECKS}
    assert CID not in {check.id for check in engine._registry()}
    assert CID not in {check['id'] for check in engine.get_catalog()['checks']}


@pytest.mark.parametrize('selector', ['default', 'framework', 'explicit_collection', 'explicit_evaluation'])
def test_public_selectors_cannot_execute_the_unsupported_login_contract(selector):
    if selector in ('default', 'framework'):
        _, checks = engine._selection('gcp', None, None,
                                      ['HackTricks Cloud Best Practices'] if selector == 'framework' else None)
        assert CID not in {check.id for check in checks}
    elif selector == 'explicit_collection':
        with pytest.raises(ValueError):
            engine.plan_collection({'connector': {'provider': 'gcp'}, 'checks': [CID]})
    else:
        with pytest.raises(ValueError):
            engine.evaluate_snapshot(make_snapshot('gcp', ['projects/test-project'], []), checks=[CID])


def test_native_permission_denied_rpc_is_not_relabelled_as_login_failure():
    native, transport = collect([{'entries': [event(code=7)]}])
    envelope = next(row for row in native['collections'] if row['type'] == 'audit_log')
    assert 'authentication_events' not in envelope['audit_coverage']
    assert 'complete' not in envelope['audit_coverage']
    assert all('authenticationEvent' not in row for row in envelope['items'])
    assert 'google.login.LoginService.loginFailure' not in transport.calls[0][2]['filter']
