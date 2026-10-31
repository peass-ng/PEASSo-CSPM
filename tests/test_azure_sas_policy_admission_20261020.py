"""Current public evaluation and atomic admission of native SAS policy facts."""
from dataclasses import replace
import pytest
from peaso import checks,engine
from peaso.checks import azure_sas_policy_declaration_admission_20261020 as admission
from peaso.checks import azure_sas_expiry_policy_declaration_proposal_20261020 as candidate
from tests.test_azure_sas_expiry_policy_declaration_20261020 import capture,offline

@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    offline.__wrapped__(monkeypatch)

@pytest.mark.parametrize('action,status',[('Block','PASS'),('Log','FAIL'),('Future','UNKNOWN')])
def test_actual_native_capture_through_public_engine(monkeypatch,action,status):
    item,index,http=capture(monkeypatch,{'sasExpirationPeriod':'3.00:00:00','expirationAction':action})
    snapshot=http.snapshot  # Exact collector output, including its native scopes.
    report=engine.evaluate_snapshot(snapshot,checks=[candidate.CHECK],include_not_applicable=True)
    findings=[r for r in report['findings']if r['check_id']==candidate.CHECK]
    assert len(findings)==1 and findings[0]['status']==status,findings
    assert findings[0]['evidence']['token_issuance_verified']is False


def test_install_is_idempotent_preserving_existing_checks():
    before=tuple(checks.CHECKS)
    admission.install();admission.install()
    assert tuple(checks.CHECKS)==before
    assert len([c for c in checks.CHECKS if c.id==candidate.CHECK])==1


