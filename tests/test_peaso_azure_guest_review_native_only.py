"""Native guest reviews must work through the unmodified automatic engine."""
import pytest
from peaso import engine
from peaso.checks.native_only import exclusions
from peaso.collectors import azure, collect_live
from tests.test_peaso_azure_access_reviews_native import API, CHECKS, SUB


def test_guest_review_controls_are_in_default_native_selection():
    assert not set(CHECKS) & set(exclusions())
    _, selected = engine._selection('azure', None, None, None)
    assert set(CHECKS) <= {check.id for check in selected}


@pytest.mark.parametrize('mode, expected', [
    ('complete', 'PASS'), ('deny_decision', 'PASS'),
    ('missing_decisions', 'UNKNOWN'), ('future_decision', 'UNKNOWN'),
    ('denied_users', 'DENIED'), ('no_guest', 'NOT_APPLICABLE'),
])
def test_automatic_guest_review_without_company_input(monkeypatch, mode, expected):
    api = API(mode)
    monkeypatch.setattr(azure, 'AzureTransportExposure', lambda auth: api)
    connector = {'provider': 'azure', 'scopes': [SUB], 'options': {'retries': 0}}
    required = engine.plan_collection({'connector': connector, 'checks': CHECKS})
    snapshot = collect_live(connector, required)
    assert not snapshot['metadata'].get('compliance_policy')
    report = engine.evaluate_snapshot(snapshot, checks=CHECKS, include_not_applicable=True)
    for cid in CHECKS:
        findings = [row for row in report['findings'] if row['check_id'] == cid]
        assert findings and {row['status'] for row in findings} == {expected}
    assert all(body is None for url, audience, body in api.calls)
