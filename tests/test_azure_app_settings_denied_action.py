"""A denied app settings read names the list action the identity is missing."""
from peaso.checks.automatic_workload_batch import _automatic_issue

KIND = 'app_service_selected_settings'
MARKER = 'SelectedAppSettingSecretIndicators'
SCOPE = '/subscriptions/00000000-0000-0000-0000-000000000000'
SITE = SCOPE + '/resourceGroups/rg/providers/Microsoft.Web/sites/app'


def _inputs(operation, http_status=403):
    meta = {KIND + '_capture': 'capture-1', KIND + '_selection': {SCOPE: [SITE]},
            KIND + '_receipts': [{'id': 'r1', 'identity': SITE, 'scope': SCOPE, 'http_status': http_status,
                                  'host': 'management.azure.com', 'operation': operation,
                                  'method': 'POST' if operation == 'settings' else 'GET',
                                  'route': 'exact_selected_' + operation, 'final_route_verified': True}]}
    item = {'id': SITE, '_provenance': {'source_requests': ['r1'], 'scope': SCOPE},
            MARKER: {'identity': SITE, 'scope': SCOPE, 'complete': False, 'capture': 'capture-1', 'source_requests': ['r1']}}
    expected = 'Microsoft.Web/sites' + ('/config/appsettings:POST' if operation == 'settings' else ':GET')
    batch = {'metadata': meta, 'issues': {SITE: {'status': 'denied', 'code': 'HTTP' + str(http_status), 'operation': expected}}}
    index = {'context': {'scope': SCOPE, 'provider': 'azure', 'metadata': {'context_binding': 'scan_local'}}}
    return item, index, batch


def test_denied_settings_list_names_the_missing_action():
    item, index, batch = _inputs('settings')
    status, evidence = _automatic_issue(item, index, KIND, batch, MARKER)
    assert status == 'DENIED'
    assert evidence['missing_action'] == 'Microsoft.Web/sites/config/list/action'
    assert 'app settings could not be read' in evidence['observed']
    assert 'Microsoft.Web/sites/config/list/action' in evidence['observed']


def test_denied_site_read_is_not_attributed_to_the_settings_action():
    item, index, batch = _inputs('identity')
    status, evidence = _automatic_issue(item, index, KIND, batch, MARKER)
    assert status == 'DENIED' and 'missing_action' not in evidence


def test_denied_settings_observation_names_the_action_first():
    from peaso.finding_observation import evidence_summary
    item, index, batch = _inputs('settings')
    status, evidence = _automatic_issue(item, index, KIND, batch, MARKER)
    lines = evidence_summary({'provider': 'azure', 'status': status, 'evidence': evidence,
                              'check_id': 'azure.review.app_service.selected_app_settings_secret_indicators'}).split('\n')
    assert 'Microsoft.Web/sites/config/list/action' in lines[0] and 3 <= len(lines) <= 5
